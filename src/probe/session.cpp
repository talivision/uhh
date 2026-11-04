// Public x64 breakpoint + inline backends. The debug API binds event consumption
// to the launching thread, so probe_run owns the event loop through exit.
#include "win_common.hpp"
#include "probe_agent_shared.hpp"
#include <cerrno>
#include <cctype>
#include <cstdarg>
#include <climits>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <Zydis/Zydis.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#include <unordered_set>

struct Probe {
    std::string location, module, callback_export;
    std::string export_name;   // "module!Export+0xOFF": resolved from the export table at load
    uint64_t sym_offset = 0;
    bool retired = false;      // PROBE_ONCE probe that already fired (kept for the report)
    bool internal = false;     // library-owned (not reported)
    bool runtime = false;      // added after launch: an install failure is reported, not fatal
    uint64_t rva = 0, base = 0, address = 0, hits = 0;
    uint32_t agent_index = UINT32_MAX;
    unsigned char original = 0;
    // Software-breakpoint displaced stepping: the full original instruction so it can
    // be executed out-of-line while the INT3 stays armed (no re-arm race, no thread
    // suspension). displaced_ok is false for control-flow instructions (handled by the
    // in-place fallback); riprel_disp_off marks a RIP-relative disp32 to retarget.
    std::vector<unsigned char> orig_insn;
    uint32_t insn_len = 0;
    bool displaced_ok = false;
    int riprel_disp_off = -1;
    probe_callback callback = nullptr;
    uint32_t flags = 0;
    std::vector<unsigned char> config;
    int dr_slot = -1;   // hardware-breakpoint DR register (0-3); -1 if not a HW probe
    bool active = false;
};

struct CallbackState {
    probe_session *session;
    Probe *probe;
};

// A thread mid-single-step over a software breakpoint. displaced == true means the
// INT3 was left armed and the instruction is running out-of-line (land at address +
// insn_len); false means the byte was lifted in place and must be re-armed.
struct StepState {
    Probe *probe = nullptr;
    bool displaced = false;
    // Captured at setup so single-step completion never dereferences the Probe*: a
    // mid-step UNLOAD_DLL zeroes probe->address, which would otherwise land RIP at
    // 0 + insn_len. site is the probe address (also the in-place re-arm target).
    uint64_t site = 0;
    uint32_t insn_len = 0;
};

// One log line, optionally with a raw stack snapshot (return addresses only). Frames
// are symbolized at report time -- never inside the breakpoint.
struct LogRecord {
    std::string text;
    uint32_t tid = 0, probe = 0;
    bool has_stack = false;
    std::vector<uint64_t> frames;
};

struct probe_session {
    std::vector<std::unique_ptr<Probe>> probes;
    std::vector<LogRecord> logs;
    bool sym_ready = false;    // dbghelp initialised on the target (stack walk + symbolize)
    std::unordered_map<std::string, uint64_t> module_bases;
    PROCESS_INFORMATION pi{};
    HANDLE stdin_write = nullptr;
    DWORD exit_code = 1;
    uint64_t overrides = 0;
    std::string error;
    HANDLE mapping = nullptr, remote_thread = nullptr;
    probe_agent_shared *shared = nullptr;
    HMODULE local_agent = nullptr;
    void *remote_path = nullptr;
    uint64_t remote_agent = 0;
    DWORD remote_tid = 0;
    enum RemoteWork { REMOTE_NONE, REMOTE_LOAD_AGENT, REMOTE_INIT_AGENT } remote_work = REMOTE_NONE;
    std::wstring agent_path;
    // One out-of-line step buffer per thread (lazily allocated in the target), so
    // concurrent threads can displaced-step independently without contending.
    std::unordered_map<DWORD, uint64_t> scratch;
    // Live target threads + hardware-breakpoint state. HW probes set a debug
    // register on EVERY thread (and each new one), so there is no code to modify
    // and no re-arm race: exact under threads for any instruction, up to 4 slots.
    std::unordered_set<DWORD> threads;
    uint8_t dr_used = 0;
    uint8_t dr_ever = 0;
    uint8_t dr_next = 0;                       // next DR slot to try (rotation)
    uint64_t entry_reapply = 0;                // image entry: re-apply DRs on first arrival                       // slots we have ever owned (stale-#DB filter)
    std::unordered_set<uint64_t> retired_bps;  // removed INT3 sites (stale-hit filter)
    int hw_active = 0;
    bool launched = false, ran = false, exited = false, gate_sent = false;
};

static bool register_runtime_inline(probe_session *s, Probe &p);
static bool kick_agent(probe_session *s);
static bool resolve_inline(probe_session *s, Probe &p, uint64_t base);
static Probe *probe_at(probe_session *s, uint64_t address);

static void set_error(probe_session *s, const std::string &message) {
    if (s && s->error.empty()) s->error = message;
    std::fprintf(stderr, "probe: error: %s\n", message.c_str());
}

static std::string win_error(const char *what) {
    return std::string(what) + " (Win32=" + std::to_string(GetLastError()) + ")";
}

static std::string basename_of(std::string path) {
    size_t p = path.find_last_of("\\/");
    return p == std::string::npos ? path : path.substr(p + 1);
}

static std::string module_name_from_handle(HANDLE file) {
    if (!file) return {};
    char path[MAX_PATH];
    DWORD n = GetFinalPathNameByHandleA(file, path, MAX_PATH, FILE_NAME_NORMALIZED);
    return n && n < MAX_PATH ? basename_of(path) : std::string{};
}

static std::string module_path_from_handle(HANDLE file) {
    if (!file) return {};
    char path[MAX_PATH];
    DWORD n = GetFinalPathNameByHandleA(file, path, MAX_PATH, FILE_NAME_NORMALIZED);
    if (!n || n >= MAX_PATH) return {};
    std::string r(path);
    if (r.rfind("\\\\?\\", 0) == 0) r = r.substr(4);
    return r;
}

// Register a mapped image with dbghelp (deferred: no symbol I/O until a frame is
// symbolized at report time). Keeps working after the target exits: it reads files.
static void sym_register(probe_session *s, HANDLE file, uint64_t base) {
    if (!s->sym_ready) return;
    std::string path = module_path_from_handle(file);
    if (path.empty()) return;
    // Pass the real SizeOfImage: with deferred loads dbghelp does not read the image yet,
    // so a size of 0 registers only the base address and no frame inside it resolves.
    DWORD size = 0; size_t got = 0;
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{};
    if (remote_read(s->pi.hProcess, base, &dos, sizeof(dos), &got) && got == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
        remote_read(s->pi.hProcess, base + (uint32_t)dos.e_lfanew, &nt, sizeof(nt), &got) && got == sizeof(nt) &&
        nt.Signature == IMAGE_NT_SIGNATURE)
        size = nt.OptionalHeader.SizeOfImage;
    SymLoadModuleEx(s->pi.hProcess, nullptr, path.c_str(), nullptr, (DWORD64)base, size, nullptr, 0);
}

static std::string module_name_from_module(HMODULE module) {
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(module, path, MAX_PATH);
    return n && n < MAX_PATH ? basename_of(path) : std::string{};
}

static bool iequals(const std::string &a, const std::string &b) {
    return a.size() == b.size() && !_stricmp(a.c_str(), b.c_str());
}

static bool has_inline(const probe_session *s) {
    for (const auto &p : s->probes) if (p->flags & PROBE_INLINE) return true;
    return false;
}

static std::wstring sibling_agent_path() {
    wchar_t path[MAX_PATH]; DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return L"probe_api_agent.dll";
    std::wstring result(path, n); size_t slash = result.find_last_of(L"\\/");
    result.resize(slash == std::wstring::npos ? 0 : slash + 1);
    return result + L"probe_api_agent.dll";
}

static bool patch(HANDLE process, uint64_t address, unsigned char byte) {
    DWORD old{}, ignored{}; SIZE_T done{};
    if (!VirtualProtectEx(process, (void *)(uintptr_t)address, 1, PAGE_EXECUTE_READWRITE, &old)) return false;
    BOOL wrote = WriteProcessMemory(process, (void *)(uintptr_t)address, &byte, 1, &done);
    BOOL flushed = FlushInstructionCache(process, (void *)(uintptr_t)address, 1);
    BOOL restored = VirtualProtectEx(process, (void *)(uintptr_t)address, 1, old, &ignored);
    return wrote && done == 1 && flushed && restored;
}

static bool parse_hex(const char *number, uint64_t &out) {
    if (!number || !*number) return false;
    for (const char *d = number; *d; ++d) if (!std::isxdigit((unsigned char)*d)) return false;
    errno = 0; char *end = nullptr;
    unsigned long long v = std::strtoull(number, &end, 16);
    if (errno == ERANGE || !end || *end) return false;
    out = (uint64_t)v; return true;
}

// "module+0xRVA" or "module!Export[+0xOFF]".
static bool parse_location(probe_session *s, const char *text, Probe &p) {
    if (!text || !*text) { set_error(s, "empty probe location"); return false; }
    p.location = text;
    size_t bang = p.location.find('!');
    if (bang != std::string::npos) {
        if (!bang) { set_error(s, "symbol location has an empty module"); return false; }
        p.module = basename_of(p.location.substr(0, bang));
        std::string rest = p.location.substr(bang + 1);
        size_t plus = rest.find('+');
        p.export_name = rest.substr(0, plus);
        if (p.export_name.empty()) { set_error(s, "symbol location has an empty export name"); return false; }
        if (plus != std::string::npos) {
            std::string off = rest.substr(plus + 1);
            if (off.size() < 3 || off[0] != '0' || (off[1] != 'x' && off[1] != 'X') ||
                !parse_hex(off.c_str() + 2, p.sym_offset)) {
                set_error(s, "symbol offset must be +0xHEX"); return false;
            }
        }
        return true;
    }
    size_t plus = p.location.rfind('+');
    if (!plus || plus == std::string::npos || plus + 3 > p.location.size() ||
        p.location[plus + 1] != '0' || (p.location[plus + 2] != 'x' && p.location[plus + 2] != 'X')) {
        set_error(s, "location must be module+0xRVA or module!Export[+0xOFF]"); return false;
    }
    p.module = basename_of(p.location.substr(0, plus));
    if (!parse_hex(p.location.c_str() + plus + 3, p.rva)) { set_error(s, "location has an invalid RVA"); return false; }
    return true;
}

// Resolve an export by name from the TARGET's image (read remotely; works before the
// module has run any code). Forwarded exports are rejected: hook the forward target.
static bool resolve_export(probe_session *s, uint64_t base, const std::string &name, uint64_t &rva) {
    HANDLE h = s->pi.hProcess; size_t got = 0;
    IMAGE_DOS_HEADER dos{};
    if (!remote_read(h, base, &dos, sizeof(dos), &got) || got != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        set_error(s, "export lookup: bad DOS header"); return false;
    }
    IMAGE_NT_HEADERS nt{};
    if (!remote_read(h, base + (uint32_t)dos.e_lfanew, &nt, sizeof(nt), &got) || got != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        set_error(s, "export lookup: bad NT headers"); return false;
    }
    auto dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) { set_error(s, "export lookup: module has no exports"); return false; }
    // Every size below comes from the (possibly hostile) target image: bound them all.
    if (dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY) || dir.Size > (64u << 20)) {
        set_error(s, "export lookup: implausible export directory size"); return false;
    }
    std::vector<unsigned char> blob(dir.Size);
    if (!remote_read(h, base + dir.VirtualAddress, blob.data(), blob.size(), &got) || got != blob.size()) {
        set_error(s, "export lookup: cannot read export directory"); return false;
    }
    auto in_dir = [&](uint32_t r, size_t n) { return r >= dir.VirtualAddress && r - dir.VirtualAddress + n <= dir.Size; };
    auto ex = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(blob.data());
    if (ex->NumberOfNames > (1u << 20) || ex->NumberOfFunctions > (1u << 20)) {
        set_error(s, "export lookup: implausible export counts"); return false;
    }
    // The name/function tables may live outside the directory range: read them separately.
    std::vector<DWORD> names(ex->NumberOfNames), funcs(ex->NumberOfFunctions);
    std::vector<WORD> ords(ex->NumberOfNames);
    if ((!names.empty() && (!remote_read(h, base + ex->AddressOfNames, names.data(), names.size() * 4, &got) || got != names.size() * 4)) ||
        (!ords.empty() && (!remote_read(h, base + ex->AddressOfNameOrdinals, ords.data(), ords.size() * 2, &got) || got != ords.size() * 2)) ||
        (!funcs.empty() && (!remote_read(h, base + ex->AddressOfFunctions, funcs.data(), funcs.size() * 4, &got) || got != funcs.size() * 4))) {
        set_error(s, "export lookup: cannot read export tables"); return false;
    }
    char buf[256];
    for (size_t i = 0; i < names.size(); ++i) {
        size_t n = 0;
        if (in_dir(names[i], 1)) {
            const char *str = reinterpret_cast<const char *>(blob.data() + (names[i] - dir.VirtualAddress));
            size_t lim = dir.Size - (names[i] - dir.VirtualAddress);
            n = strnlen(str, lim); if (n >= sizeof(buf)) continue; std::memcpy(buf, str, n);
        } else {
            if (!remote_read(h, base + names[i], buf, sizeof(buf) - 1, &got) || !got) continue;
            n = strnlen(buf, got);
        }
        buf[n] = 0;
        if (name != buf) continue;
        if (ords[i] >= funcs.size()) break;
        uint32_t f = funcs[ords[i]];
        if (in_dir(f, 0)) { set_error(s, "export '" + name + "' is forwarded; probe the forward target"); return false; }
        rva = f; return true;
    }
    set_error(s, "export '" + name + "' not found"); return false;
}

static std::string quote_arg(const char *arg) {
    std::string in = arg ? arg : "";
    if (!in.empty() && in.find_first_of(" \t\n\v\"") == std::string::npos) return in;
    std::string out = "\""; size_t slashes = 0;
    for (char ch : in) {
        if (ch == '\\') { ++slashes; continue; }
        if (ch == '\"') out.append(slashes * 2 + 1, '\\');
        else out.append(slashes, '\\');
        slashes = 0; out += ch;
    }
    out.append(slashes * 2, '\\'); out += '\"'; return out;
}

// Decode the site instruction to plan the single-step. Fills its length, whether it
// may be stepped out-of-line (not a relative branch / call / ret), and the offset of a
// RIP-relative disp32 to retarget in the out-of-line copy. Control-flow instructions
// return displaced_ok=false so the caller uses the in-place fallback.
static bool decode_site(const unsigned char *bytes, size_t n, uint32_t &len,
                        bool &displaced_ok, int &riprel_off) {
    ZydisDecoder dec;
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, bytes, n, &insn, ops))) return false;
    len = insn.length; riprel_off = -1; displaced_ok = true;
    if (insn.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE ||
        insn.meta.category == ZYDIS_CATEGORY_CALL || insn.meta.category == ZYDIS_CATEGORY_RET ||
        insn.meta.category == ZYDIS_CATEGORY_COND_BR || insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
        displaced_ok = false; return true;            // control flow -> in-place fallback
    }
    // Flags-image / trap / privileged instructions can clear or expose the trap flag,
    // or raise their own exception instead of the single-step, so out-of-line stepping
    // misbehaves; route them to the in-place fallback.
    switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_POPF:  case ZYDIS_MNEMONIC_POPFD:  case ZYDIS_MNEMONIC_POPFQ:
        case ZYDIS_MNEMONIC_PUSHF: case ZYDIS_MNEMONIC_PUSHFD: case ZYDIS_MNEMONIC_PUSHFQ:
        case ZYDIS_MNEMONIC_STI:   case ZYDIS_MNEMONIC_CLI:
        case ZYDIS_MNEMONIC_INT:   case ZYDIS_MNEMONIC_INT3:   case ZYDIS_MNEMONIC_INT1:
        case ZYDIS_MNEMONIC_SYSCALL: case ZYDIS_MNEMONIC_SYSENTER:
            displaced_ok = false; return true;
        default: break;
    }
    // REP/REPE/REPNE string ops single-step one iteration at a time; stepped out-of-line
    // we would force RIP past after a single pass and truncate the operation.
    if (insn.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE)) {
        displaced_ok = false; return true;
    }
    // RIP-relative memory operand (x64): record the disp32 so the copy can be retargeted.
    for (int i = 0; i < insn.operand_count; ++i) {
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.base == ZYDIS_REGISTER_RIP) {
            if (insn.raw.disp.size == 32 && insn.raw.disp.offset) riprel_off = insn.raw.disp.offset;
            else displaced_ok = false;                // RIP-relative but not a disp32 we can retarget
            break;
        }
    }
    return true;
}

// Program debug register `slot` for execute (rw=0,len=0) or a data watchpoint. rw:
// 0=execute, 1=write, 3=read/write. len: 0=1,1=2,3=4,2=8 bytes (Intel DR7 LEN encoding).
static bool set_dr_on_thread(HANDLE thread, int slot, uint64_t addr, bool enable,
                             uint32_t rw = 0, uint32_t len = 0) {
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &c)) return false;
    switch (slot) { case 0: c.Dr0 = addr; break; case 1: c.Dr1 = addr; break;
                    case 2: c.Dr2 = addr; break; case 3: c.Dr3 = addr; break; default: return false; }
    DWORD64 ln = (DWORD64)1 << (slot * 2);                       // local-enable Ln
    DWORD64 fieldmask = (DWORD64)0xF << (16 + slot * 4);         // this slot's RWn|LENn nibble
    DWORD64 field = (DWORD64)(((len & 3u) << 2) | (rw & 3u)) << (16 + slot * 4);
    DWORD64 dr7 = c.Dr7;
    if (enable) { dr7 &= ~fieldmask; dr7 |= ln | field; } else { dr7 &= ~ln; }
    c.Dr7 = dr7;
    return !!SetThreadContext(thread, &c);
}

// Hardware execute breakpoint: no code is modified, so there is no re-arm window and
// nothing to single-step. Set the DR on every current thread; new threads get it in
// the CREATE_THREAD handler. Exact under multithreading for ANY instruction (incl.
// control-flow/REP the displaced software path cannot handle), limited to 4 slots.
// Translate the probe flags into the DR7 RW/LEN encoding: execute breakpoint by
// default, or a data watchpoint (write / read+write) of one machine word.
static void hw_rw_len(uint32_t flags, uint32_t &rw, uint32_t &len) {
    if (flags & PROBE_WATCH_RW)          rw = 3;
    else if (flags & PROBE_WATCH_WRITE)  rw = 1;
    else { rw = 0; len = 0; return; }                 // execute breakpoint, 1 byte
    len = 3;   // LEN=11 -> 4-byte (dword) watchpoint; the address must be dword-aligned
}

static bool arm_hw(probe_session *s, Probe &p, uint64_t base) {
    if (p.rva > UINT64_MAX - base) { set_error(s, "probe address overflow"); return false; }
    uint64_t address = base + p.rva;
    int slot = -1;
    // Rotate through free slots so a just-released slot is reused last: a #DB already in
    // flight for the old probe is then far less likely to be blamed on a new one.
    for (int k = 0; k < 4; ++k) { int i = (s->dr_next + k) & 3; if (!(s->dr_used & (1u << i))) { slot = i; break; } }
    if (slot >= 0) s->dr_next = (uint8_t)((slot + 1) & 3);
    if (slot < 0) { set_error(s, "no free hardware breakpoint slot (max 4)"); return false; }
    uint32_t rw = 0, len = 0; hw_rw_len(p.flags, rw, len);
    size_t tried = 0, set_ok = 0;
    for (DWORD tid : s->threads) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
        if (!t) continue;
        ++tried;
        if (set_dr_on_thread(t, slot, address, true, rw, len)) ++set_ok;
        CloseHandle(t);
    }
    if (tried && !set_ok) {   // could not arm the DR on any thread -> the probe would never fire
        set_error(s, win_error("set hardware breakpoint on target threads")); return false;
    }
    s->dr_used |= (uint8_t)(1u << slot); s->dr_ever |= (uint8_t)(1u << slot); ++s->hw_active;
    p.dr_slot = slot; p.base = base; p.address = address; p.active = true;
    std::fprintf(stderr, "probe: active %s -> base=0x%llx addr=0x%llx (hw DR%d, %s)\n",
                 p.location.c_str(), (unsigned long long)base, (unsigned long long)address, slot,
                 rw == 3 ? "watch rw" : rw == 1 ? "watch write" : "execute");
    return true;
}

static bool arm_breakpoint(probe_session *s, Probe &p, uint64_t base) {
    if (p.rva > UINT64_MAX - base) { set_error(s, "probe address overflow"); return false; }
    uint64_t address = base + p.rva; size_t got{};
    unsigned char buf[16];
    if (!remote_read(s->pi.hProcess, address, buf, sizeof(buf), &got) || got != sizeof(buf)) {
        set_error(s, win_error("read original probe bytes")); return false;
    }
    if (buf[0] == 0xcc) {
        Probe *owner = probe_at(s, address);
        if (owner && owner->internal && !owner->orig_insn.empty()) {
            // Take over the library's own entry INT3: reuse its saved original bytes; the
            // re-apply still happens (entry_reapply) when this probe first fires.
            std::memcpy(buf, owner->orig_insn.data(), owner->orig_insn.size());
            owner->active = false; owner->retired = true;
            uint32_t len = 0; bool disp_ok = false; int riprel = -1;
            if (!decode_site(buf, sizeof(buf), len, disp_ok, riprel) || len == 0 || len > sizeof(buf)) {
                set_error(s, "could not decode probe site instruction"); return false;
            }
            p.original = buf[0]; p.orig_insn.assign(buf, buf + len);
            p.insn_len = len; p.displaced_ok = disp_ok; p.riprel_disp_off = riprel;
            p.base = base; p.address = address; p.active = true;
            s->retired_bps.erase(address);
            return true;
        }
        set_error(s, "pre-hooked INT3 sites are unsupported by this breakpoint backend"); return false;
    }
    uint32_t len = 0; bool disp_ok = false; int riprel = -1;
    if (!decode_site(buf, sizeof(buf), len, disp_ok, riprel) || len == 0 || len > sizeof(buf)) {
        set_error(s, "could not decode probe site instruction"); return false;
    }
    p.original = buf[0];
    p.orig_insn.assign(buf, buf + len);
    p.insn_len = len; p.displaced_ok = disp_ok; p.riprel_disp_off = riprel;
    if (!patch(s->pi.hProcess, address, 0xcc)) {
        set_error(s, win_error("arm software breakpoint")); return false;
    }
    p.base = base; p.address = address; p.active = true;
    s->retired_bps.erase(address);
    std::fprintf(stderr, "probe: active %s -> base=0x%llx addr=0x%llx (was 0x%02x, len=%u, %s)\n",
                 p.location.c_str(), (unsigned long long)base, (unsigned long long)address,
                 p.original, len, disp_ok ? "displaced" : "in-place");
    return true;
}

static bool resolve_inline(probe_session *s, Probe &p, uint64_t base) {
    if (p.rva > UINT64_MAX - base) { set_error(s, "probe address overflow"); return false; }
    if (!s->shared || p.agent_index >= s->shared->request_count) {
        set_error(s, "inline shared request is unavailable"); return false;
    }
    p.base = base; p.address = base + p.rva;
    auto &request = s->shared->requests[p.agent_index];
    request.site = p.address; MemoryBarrier();
    std::fprintf(stderr, "probe: resolved %s -> base=0x%llx addr=0x%llx (awaiting agent)\n",
                 p.location.c_str(), (unsigned long long)base, (unsigned long long)p.address);
    return true;
}

static bool arm_probe(probe_session *s, Probe &item, uint64_t base) {
    // A late-resolving inline probe (the gate is already released, so the target may
    // call the site before the async agent install lands) with PROBE_FALLBACK_HW set
    // becomes a hardware probe: that arms synchronously here (just debug registers —
    // no in-target code, no loader lock, no race) and is exact. The callback is
    // backend-agnostic, so it runs controller-side unchanged.
    if ((item.flags & PROBE_INLINE) && (item.flags & PROBE_FALLBACK_HW) && s->gate_sent) {
        item.flags = (item.flags & ~(uint32_t)PROBE_INLINE) | PROBE_HW;
        std::fprintf(stderr, "probe: %s -> hardware fallback (late inline would race the first call)\n",
                     item.location.c_str());
    }
    if (!item.export_name.empty()) {
        uint64_t exp = 0;
        if (!resolve_export(s, base, item.export_name, exp)) return false;
        item.rva = exp + item.sym_offset;
    }
    return item.flags & PROBE_BREAKPOINT ? arm_breakpoint(s, item, base)
         : item.flags & PROBE_HW          ? arm_hw(s, item, base)
                                          : resolve_inline(s, item, base);
}

// Launch-time probes that fail to arm fail the session (the user asked for them up
// front). A probe added at runtime -- possibly pending on a module that loads much
// later -- only reports its failure and retires; the run and other probes continue.
static bool arm_module(probe_session *s, const std::string &module, uint64_t base) {
    bool all_ok = true;
    for (size_t i = 0; i < s->probes.size(); ++i) {
        Probe &item = *s->probes[i];
        if (item.active || item.retired || item.address || !iequals(item.module, module)) continue;
        std::string saved = s->error;
        bool ok = false;
        try { ok = arm_probe(s, item, base); }
        catch (const std::exception &e) { set_error(s, std::string("arm ") + item.location + ": " + e.what()); }
        if (ok) continue;
        if (item.runtime) {
            std::fprintf(stderr, "probe: runtime probe %s failed to arm: %s\n", item.location.c_str(), s->error.c_str());
            s->error = saved; item.retired = true; continue;
        }
        all_ok = false;   // keep arming the module's other probes; the session still fails
    }
    return all_ok;
}

static Probe *probe_at(probe_session *s, uint64_t address) {
    for (auto &p : s->probes) if (p->active && p->address == address) return p.get();
    return nullptr;
}

static uint32_t probe_index(probe_session *s, const Probe *probe) {
    for (size_t i = 0; i < s->probes.size(); ++i)
        if (s->probes[i].get() == probe) return (uint32_t)i;
    return 0;
}

// The loader finishes process initialisation with NtContinue on the initial thread's
// start context, which carries the debug registers captured at thread creation. Any
// hardware probe armed later in loader init (a static import such as ucrtbase loading)
// is silently wiped there. A library-owned one-shot breakpoint at the image entry point
// re-applies every active hardware probe to every thread right after that point.
static void reapply_all_hw(probe_session *s) {
    s->entry_reapply = 0;
    for (auto &p : s->probes) {
        if (!p->active || !(p->flags & PROBE_HW)) continue;
        uint32_t rw = 0, len = 0; hw_rw_len(p->flags, rw, len);
        for (DWORD tid : s->threads) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
            if (t) { set_dr_on_thread(t, p->dr_slot, p->address, true, rw, len); CloseHandle(t); }
        }
    }
}

static void reapply_hw(probe_context *c) {
    if (probe_session *s = get_session(c)) reapply_all_hw(s);
}

static void arm_entry_fixup(probe_session *s, uint64_t entry) {
    if (!entry) return;
    s->entry_reapply = entry;
    if (probe_at(s, entry)) return;   // a user breakpoint is already there: it triggers the re-apply
    try {
        auto p = std::make_unique<Probe>();
        p->location = "<entry>"; p->flags = PROBE_BREAKPOINT | PROBE_ONCE; p->callback = reapply_hw;
        p->rva = entry; p->internal = true;
        Probe *raw = p.get(); s->probes.push_back(std::move(p));
        std::string saved = s->error;
        if (!arm_breakpoint(s, *raw, 0)) { raw->retired = true; s->error = saved; }
    } catch (...) {}
}

extern "C" probe_session *probe_session_create(void) {
    try { return new probe_session; }
    catch (...) { std::fprintf(stderr, "probe: error: session allocation failed\n"); return nullptr; }
}

// Dynamic (post-launch) control-plane calls come from a callback while the target is
// stopped. A failure there returns 0 to the callback but must not poison the session's
// end-of-run status, so the error is logged and the previous error state restored.
struct DynamicScope {
    probe_session *s; std::string saved; bool dynamic;
    explicit DynamicScope(probe_session *ss) : s(ss), saved(ss->error), dynamic(ss->launched) {}
    int done(int ok) {
        if (dynamic && !ok) {
            std::fprintf(stderr, "probe: dynamic add failed: %s\n", s->error.c_str());
            s->error = saved;
        }
        return ok;
    }
};

static uint32_t hw_in_use(const probe_session *s) {
    uint32_t n = 0;
    for (auto &pp : s->probes) if ((pp->flags & PROBE_HW) && !pp->retired) ++n;
    return n;
}

static bool check_flags(probe_session *s, uint32_t flags, bool allow_inline) {
    constexpr uint32_t types = PROBE_BREAKPOINT | PROBE_INLINE | PROBE_HW;
    constexpr uint32_t known = types | PROBE_AT_RETURN | PROBE_ALLOW_PREHOOKED | PROBE_FALLBACK_HW
                             | PROBE_WATCH_WRITE | PROBE_WATCH_RW | PROBE_ONCE;
    if (flags & ~known) { set_error(s, "unknown probe flags"); return false; }
    uint32_t type = flags & types;
    uint32_t watch = flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW);
    if ((type != PROBE_BREAKPOINT && type != PROBE_INLINE && type != PROBE_HW) || (flags & PROBE_AT_RETURN) ||
        (flags & PROBE_ALLOW_PREHOOKED) ||                           // chain-through not implemented yet
        ((flags & PROBE_FALLBACK_HW) && type != PROBE_INLINE) ||     // fallback only modifies an inline probe
        (watch && type != PROBE_HW) ||                               // a watchpoint uses the DR/HW backend
        watch == (PROBE_WATCH_WRITE | PROBE_WATCH_RW) ||             // pick one access mode, not both
        ((flags & PROBE_ONCE) && type == PROBE_INLINE)) {            // one-shot needs a controller backend
        set_error(s, "requested probe type/options are unsupported in this build");
        return false;
    }
    (void)allow_inline;
    if (type == PROBE_HW && hw_in_use(s) >= 4) {
        set_error(s, "too many hardware probes (max 4 DR slots)"); return false;
    }
    return true;
}

extern "C" int probe_add_symbol_cfg(probe_session *s, const char *location, probe_callback callback,
                                    uint32_t flags, const void *config, size_t config_len) {
    if (!s) return 0;
    DynamicScope scope(s);
    if (s->exited) { set_error(s, "session already exited"); return 0; }
    if (!callback) { set_error(s, "probe callback is null"); return scope.done(0); }
    if (!check_flags(s, flags, !s->launched)) return scope.done(0);
    uint32_t type = flags & (PROBE_BREAKPOINT | PROBE_INLINE | PROBE_HW);
    if (config_len && !config) { set_error(s, "non-empty probe config is null"); return scope.done(0); }
    if (type == PROBE_INLINE && config_len > PROBE_AGENT_CONFIG_CAP) {
        set_error(s, "inline probe config exceeds the agent limit"); return scope.done(0);
    }
    try {
        auto p = std::make_unique<Probe>();
        if (!parse_location(s, location, *p)) return scope.done(0);
        p->callback = callback; p->flags = flags; p->runtime = s->launched;
        if (type == PROBE_INLINE && !callback_export_name(callback, p->callback_export)) {
            set_error(s, "inline callback is not a named export"); return scope.done(0);
        }
        if (p->callback_export.size() >= PROBE_AGENT_EXPORT_CAP) {
            set_error(s, "inline callback export name is too long"); return scope.done(0);
        }
        if (config_len) {
            auto first = static_cast<const unsigned char *>(config);
            p->config.assign(first, first + config_len);
        }
        std::fprintf(stderr, "probe: pending %s\n", p->location.c_str());
        Probe *raw = p.get();
        s->probes.push_back(std::move(p));          // heap-stable: callbacks may add mid-iteration
        if (s->launched && type == PROBE_INLINE && !register_runtime_inline(s, *raw)) {
            raw->retired = true; return scope.done(0);
        }
        if (s->launched) {                          // runtime add: arm now if the module is mapped
            for (auto &kv : s->module_bases)
                if (iequals(kv.first, raw->module)) {
                    if (!arm_probe(s, *raw, kv.second)) { raw->retired = true; return scope.done(0); }
                    break;
                }
            if (type == PROBE_INLINE && raw->address && !kick_agent(s)) { raw->retired = true; return scope.done(0); }
        }
        return 1;
    } catch (const std::exception &e) { set_error(s, e.what()); return scope.done(0); }
}

extern "C" int probe_add_symbol(probe_session *s, const char *location, probe_callback callback, uint32_t flags) {
    return probe_add_symbol_cfg(s, location, callback, flags, nullptr, 0);
}

// Absolute-address probes only make sense once the process exists (ASLR), so they are a
// runtime operation: typically called from a callback with an address it just read.
static int add_absolute(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags) {
    if (!s) return 0;
    DynamicScope scope(s);
    if (!s->launched || s->exited) { set_error(s, "absolute-address probes need a running target"); return scope.done(0); }
    if (!cb) { set_error(s, "probe callback is null"); return scope.done(0); }
    if (!check_flags(s, flags, false)) return scope.done(0);
    try {
        auto p = std::make_unique<Probe>();
        char loc[40]; std::snprintf(loc, sizeof(loc), "0x%llx", (unsigned long long)address);
        p->location = loc; p->flags = flags; p->callback = cb; p->rva = address; p->runtime = true;
        if ((flags & PROBE_INLINE) && !callback_export_name(cb, p->callback_export)) {
            set_error(s, "inline callback is not a named export"); return scope.done(0);
        }
        Probe *raw = p.get();
        s->probes.push_back(std::move(p));
        bool ok = (flags & PROBE_INLINE) ? register_runtime_inline(s, *raw) && resolve_inline(s, *raw, 0) && kick_agent(s)
                : (flags & PROBE_HW)     ? arm_hw(s, *raw, 0) : arm_breakpoint(s, *raw, 0);
        if (!ok) raw->retired = true;
        return scope.done(ok ? 1 : 0);
    } catch (const std::exception &e) { set_error(s, e.what()); return scope.done(0); }
}

extern "C" int probe_add_address(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags) {
    if (s && (flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW))) {
        DynamicScope scope(s); set_error(s, "use probe_watch for data watchpoints"); return scope.done(0);
    }
    return add_absolute(s, address, cb, flags);
}

extern "C" int probe_watch(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags) {
    uint32_t mode = flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW);
    if (s && (flags & ~(uint32_t)(PROBE_WATCH_WRITE | PROBE_WATCH_RW | PROBE_ONCE | PROBE_HW))) {
        DynamicScope scope(s); set_error(s, "probe_watch takes PROBE_WATCH_WRITE/RW and PROBE_ONCE only"); return scope.done(0);
    }
    if (s && (address & 3)) {
        DynamicScope scope(s); set_error(s, "probe_watch address must be 4-byte aligned (watches one dword)"); return scope.done(0);
    }
    return add_absolute(s, address, cb, PROBE_HW | (mode ? mode : (uint32_t)PROBE_WATCH_WRITE) | (flags & PROBE_ONCE));
}

static bool open_agent_section(probe_session *s, uint32_t count) {
    wchar_t name[64]; probe_agent_mapping_name(s->pi.dwProcessId, name);
    s->mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                                    (DWORD)sizeof(probe_agent_shared), name);
    if (!s->mapping || GetLastError() == ERROR_ALREADY_EXISTS) {
        set_error(s, win_error("create inline shared section")); return false;
    }
    s->shared = static_cast<probe_agent_shared *>(MapViewOfFile(
        s->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(probe_agent_shared)));
    if (!s->shared) { set_error(s, win_error("map inline shared section")); return false; }
    std::memset(s->shared, 0, sizeof(*s->shared));
    s->shared->magic = PROBE_AGENT_MAGIC; s->shared->version = PROBE_AGENT_VERSION;
    s->shared->request_count = count;
    for (uint32_t i = 0; i < PROBE_AGENT_LOG_CAP; ++i) s->shared->logs[i].seq = i;   // ring: all free
    s->agent_path = sibling_agent_path();
    s->local_agent = LoadLibraryW(s->agent_path.c_str());
    if (!s->local_agent || !GetProcAddress(s->local_agent, "probe_agent_init")) {
        set_error(s, win_error("map probe_api_agent.dll exports")); return false;
    }
    return true;
}

static void fill_request(probe_session *s, const Probe &p) {
    auto &request = s->shared->requests[p.agent_index]; request.flags = p.flags;
    request.config_len = (uint32_t)p.config.size();
    std::memcpy(request.callback, p.callback_export.c_str(), p.callback_export.size() + 1);
    if (!p.config.empty()) std::memcpy(request.config, p.config.data(), p.config.size());
}

static bool create_agent_channel(probe_session *s) {
    uint32_t count = 0;
    for (auto &p : s->probes) if (p->flags & PROBE_INLINE) p->agent_index = count++;
    if (!count) return true;
    if (count > PROBE_AGENT_MAX_PROBES) { set_error(s, "too many inline probes"); return false; }
    if (!open_agent_section(s, count)) return false;
    for (const auto &p : s->probes) if (p->flags & PROBE_INLINE) fill_request(s, *p);
    return true;
}

static bool start_agent_load(probe_session *s);
static bool start_agent_init(probe_session *s);

// An inline probe added while the target runs (from a callback). It gets the next free
// request slot -- creating the channel on first use -- and is installed by the agent on
// a FRESH remote thread, never inside the calling callback: the installer freezes other
// threads, and the caller may hold locks (heap, loader) a frozen thread is waiting on.
// So it is asynchronous: the hook lands shortly after this returns. Use PROBE_BREAKPOINT
// or PROBE_HW when it must be live before the target's next instruction.
static bool register_runtime_inline(probe_session *s, Probe &p) {
    if (!s->shared && !open_agent_section(s, 0)) return false;
    uint32_t idx = s->shared->request_count;
    if (idx >= PROBE_AGENT_MAX_PROBES) { set_error(s, "too many inline probes"); return false; }
    p.agent_index = idx; p.runtime = true;
    fill_request(s, p);
    MemoryBarrier();
    s->shared->request_count = idx + 1;
    return true;
}

// Start (or queue) agent work for pending inline requests.
static bool kick_agent(probe_session *s) {
    if (s->remote_work != probe_session::REMOTE_NONE) return true;   // picked up when it finishes
    if (!s->remote_agent) return start_agent_load(s);
    return start_agent_init(s);
}

static bool release_gate(probe_session *s) {
    if (s->gate_sent) return true;
    DWORD wrote{}; char key = '\n';
    if (!WriteFile(s->stdin_write, &key, 1, &wrote, nullptr) || wrote != 1) {
        set_error(s, win_error("deliver gate keystroke")); return false;
    }
    s->gate_sent = true; return true;
}

extern "C" int probe_launch(probe_session *s, char *const argv[]) {
    if (!s || !argv || !argv[0]) { if (s) set_error(s, "launch argv is empty"); return 0; }
    if (s->launched) { set_error(s, "session already launched"); return 0; }
    try {
        std::string command;
        for (size_t i = 0; argv[i]; ++i) { if (i) command += ' '; command += quote_arg(argv[i]); }
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE}; HANDLE stdin_read{};
        if (!CreatePipe(&stdin_read, &s->stdin_write, &sa, 0)) { set_error(s, win_error("stdin pipe")); return 0; }
        if (!SetHandleInformation(s->stdin_write, HANDLE_FLAG_INHERIT, 0)) {
            CloseHandle(stdin_read); CloseHandle(s->stdin_write); s->stdin_write = nullptr;
            set_error(s, win_error("stdin pipe inheritance")); return 0;
        }
        STARTUPINFOA si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = stdin_read; si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        BOOL ok = CreateProcessA(argv[0], command.data(), nullptr, nullptr, TRUE,
                                 DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &s->pi);
        CloseHandle(stdin_read);
        if (!ok) {
            CloseHandle(s->stdin_write); s->stdin_write = nullptr;
            set_error(s, win_error("debug launch")); return 0;
        }
        s->launched = true;
        SymSetOptions(SymGetOptions() | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_NO_PROMPTS |
                      SYMOPT_FAIL_CRITICAL_ERRORS);
        s->sym_ready = !!SymInitialize(s->pi.hProcess, nullptr, FALSE);
        if (!create_agent_channel(s) || (!has_inline(s) && !release_gate(s))) {
            TerminateProcess(s->pi.hProcess, 3); return 0;
        }
        return 1;
    } catch (const std::exception &e) { set_error(s, e.what()); return 0; }
}

// Per-thread out-of-line step buffer in the target (executable), allocated on demand.
static bool trace_enabled() { static const bool on = std::getenv("PROBE_TRACE") != nullptr; return on; }

static uint64_t thread_scratch(probe_session *s, DWORD tid) {
    auto it = s->scratch.find(tid);
    if (it != s->scratch.end()) return it->second;
    void *mem = VirtualAllocEx(s->pi.hProcess, nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return 0;
    uint64_t addr = (uint64_t)(uintptr_t)mem; s->scratch[tid] = addr; return addr;
}

// Fully release a hardware probe: clear its DR on every thread and free the slot.
static void release_hw(probe_session *s, Probe &p) {
    if (p.dr_slot < 0) return;
    for (DWORD tid : s->threads) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
        if (t) { set_dr_on_thread(t, p.dr_slot, 0, false); CloseHandle(t); }
    }
    s->dr_used &= (uint8_t)~(1u << p.dr_slot);
    if (s->hw_active > 0) --s->hw_active;
    p.active = false; p.dr_slot = -1;
    if (p.flags & PROBE_ONCE) p.retired = true;
}

// Agent -> controller control-plane call (an inline callback used get_session(c)).
// The raising thread is stopped; service the request and write the result back.
// Trust boundary: the target is untrusted. A request is honoured only when an inline
// agent exists and it names a real inline probe as its origin, and the callback is
// resolved ONLY among the exports of that probe's controller-side callback module (so
// keep that module's exports to callbacks). Anything else is not ours: pass it through.
static bool handle_ipc(probe_session *s, const DEBUG_EVENT &event) {
    auto &ex = event.u.Exception.ExceptionRecord;
    if (!s->shared || ex.NumberParameters < 1) return false;
    uint64_t at = (uint64_t)ex.ExceptionInformation[0];
    probe_ipc_request req{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, at, &req, sizeof(req), &got) || got != sizeof(req)) return false;
    req.callback[sizeof(req.callback) - 1] = 0; req.symbol[sizeof(req.symbol) - 1] = 0;
    // The callback is named; find the controller's copy of the same source. Prefer the
    // module that holds the originating inline probe's callback, then the executable.
    probe_callback cb = nullptr; bool origin = false;
    for (auto &p : s->probes)
        if ((p->flags & PROBE_INLINE) && p->agent_index == req.origin_site && p->callback) {
            origin = true;
            HMODULE m{};
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   reinterpret_cast<LPCSTR>(p->callback), &m))
                cb = reinterpret_cast<probe_callback>(GetProcAddress(m, req.callback));
            break;
        }
    if (!origin) return false;
    int32_t result = 0;
    if (!cb) {
        std::fprintf(stderr, "probe: dynamic add from inline callback: no controller-side export '%s'\n", req.callback);
    } else if (req.op == PROBE_IPC_ADD_ADDRESS) result = probe_add_address(s, req.address, cb, req.flags);
    else if (req.op == PROBE_IPC_WATCH)       result = probe_watch(s, req.address, cb, req.flags);
    else if (req.op == PROBE_IPC_ADD_SYMBOL)  result = probe_add_symbol(s, req.symbol, cb, req.flags);
    std::fprintf(stderr, "probe: ipc op=%u from inline site %u cb=%s -> %d\n", req.op, req.origin_site, req.callback, result);
    size_t wrote = 0;
    remote_write(s->pi.hProcess, at + offsetof(probe_ipc_request, result), &result, sizeof(result), &wrote);
    return true;
}

// Service a hardware-breakpoint #DB (a single-step exception carrying a DR status
// bit, not one of our software single-steps). Returns false on error; sets handled
// when a DR we own fired. RF lets the flagged instruction run once without re-trapping.
static bool handle_hw(probe_session *s, const DEBUG_EVENT &event, bool &handled) {
    handled = false;
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
    if (!thread) { set_error(s, win_error("open hw event thread")); return false; }
    CONTEXT native{}; native.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(thread, &native)) { CloseHandle(thread); set_error(s, win_error("get hw context")); return false; }
    // Service EVERY debug-status bit that fired, not just the lowest: two probes can
    // share an address (both B-bits set), and clearing DR6 after handling only one
    // would silently drop the other. Callbacks compose on one context in slot order.
    bool any = false;
    for (int slot = 0; slot < 4; ++slot) {
        if (!(native.Dr6 & (1u << slot))) continue;
        Probe *probe = nullptr;
        for (auto &p : s->probes) if (p->active && (p->flags & PROBE_HW) && p->dr_slot == slot) { probe = p.get(); break; }
        if (!probe) {
            // A slot we owned but have since released (PROBE_ONCE / unload): a #DB that was
            // already in flight on another thread. Swallow it rather than crash the app.
            if (s->dr_ever & (1u << slot)) any = true;
            continue;
        }
        any = true;
        #if defined(_WIN64)
        uint64_t hit_pc = native.Rip;
#else
        uint64_t hit_pc = native.Eip;
#endif
        // Execute probes: pc == the probe address. Watchpoints trap AFTER the access, so
        // pc is the instruction following the store/load -- the real code location.
        if (!(probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) && hit_pc != probe->address) {
            any = true; continue;                                    // stale: slot was reassigned
        }
        probe_context context = from_context(native, probe_index(s, probe), hit_pc, &remote_ops, s->pi.hProcess);
        context.config = probe->config.empty() ? nullptr : probe->config.data();
        context.tid = event.dwThreadId;
        CallbackState state{s, probe}; context.controller = &state;
        try { probe->callback(&context); }
        catch (const std::exception &e) { CloseHandle(thread); set_error(s, std::string("probe callback: ") + e.what()); return false; }
        catch (...) { CloseHandle(thread); set_error(s, "probe callback threw an unknown exception"); return false; }
        ++probe->hits;
        if (probe->flags & PROBE_ONCE) release_hw(s, *probe);
        to_context(context, native);                                 // fold each callback's changes forward
#if defined(_WIN64)
        native.Rsp = context.regs.rsp;
#else
        native.Esp = (DWORD)context.regs.rsp;
#endif
    }
    if (!any) { CloseHandle(thread); return true; }                  // none of our DRs fired
    native.EFlags |= 0x10000u;   // RF: execute the flagged instruction once without re-trapping
    // Callbacks may have armed/released hardware probes (probe_watch, PROBE_ONCE), which
    // rewrote THIS thread's debug registers. Take the live DR image, not the stale one
    // captured before the callbacks, so the write-back below does not undo them.
    {
        CONTEXT dr{}; dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &dr)) {
            native.Dr0 = dr.Dr0; native.Dr1 = dr.Dr1; native.Dr2 = dr.Dr2; native.Dr3 = dr.Dr3; native.Dr7 = dr.Dr7;
        }
    }
    native.Dr6 = 0;              // clear all debug status bits we consumed
    if (!SetThreadContext(thread, &native)) { CloseHandle(thread); set_error(s, win_error("resume hw breakpoint")); return false; }
    CloseHandle(thread); handled = true; return true;
}

static bool handle_exception(probe_session *s, const DEBUG_EVENT &event,
                             std::unordered_map<DWORD, StepState> &stepping,
                             bool &initial_break, DWORD &disposition) {
    auto &ex = event.u.Exception.ExceptionRecord; DWORD code = ex.ExceptionCode;
    disposition = DBG_EXCEPTION_NOT_HANDLED;
    if (code == EXCEPTION_BREAKPOINT && !initial_break) {
        initial_break = true; disposition = DBG_CONTINUE; return true;
    }
    if (code == PROBE_IPC_CODE && handle_ipc(s, event)) { disposition = DBG_CONTINUE; return true; }
    auto step = stepping.find(event.dwThreadId);
    uint64_t address = (uint64_t)(uintptr_t)ex.ExceptionAddress;
    Probe *probe = code == EXCEPTION_BREAKPOINT ? probe_at(s, address) : nullptr;
    if (code == EXCEPTION_BREAKPOINT && !probe && s->retired_bps.count(address)) {
        // Another thread hit a one-shot INT3 that has since been removed: the original
        // byte is back, so rewind to it and continue as if the breakpoint never existed.
        unsigned char now = 0; size_t got = 0;
        if (remote_read(s->pi.hProcess, address, &now, 1, &got) && got == 1 && now != 0xcc) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
            bool ok = t && GetThreadContext(t, &w);
#if defined(_WIN64)
            w.Rip = address;
#else
            w.Eip = (DWORD)address;
#endif
            ok = ok && SetThreadContext(t, &w);
            if (t) CloseHandle(t);
            if (!ok) { set_error(s, win_error("rewind stale breakpoint")); return false; }
            disposition = DBG_CONTINUE; return true;
        }
    }
    if (trace_enabled())
        std::fprintf(stderr, "EV code=0x%lx tid=%lu addr=0x%llx step=%d probe=%d\n",
                     (unsigned long)code, (unsigned long)event.dwThreadId,
                     (unsigned long long)address, step != stepping.end(), probe != nullptr);
    if (code == EXCEPTION_SINGLE_STEP && step == stepping.end() && (s->hw_active || s->dr_ever)) {
        bool handled = false;
        if (!handle_hw(s, event, handled)) return false;
        if (handled) { disposition = DBG_CONTINUE; return true; }   // else fall through (not our DR)
    }
    if ((code != EXCEPTION_SINGLE_STEP || step == stepping.end()) && !probe) {
        // An unexpected exception (a fault in the out-of-line copy, or any app
        // exception) reached a thread still mid-step. Drop its stale StepState so a
        // later stray single-step can't teleport it to site+insn_len; re-arm the byte
        // if the step was in-place. Pass the exception through unchanged.
        if (step != stepping.end()) {
            if (!step->second.displaced) patch(s->pi.hProcess, step->second.site, 0xcc);
            stepping.erase(step);
        }
        return true;
    }
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
    if (!thread) { set_error(s, win_error("open event thread")); return false; }
    CONTEXT native{}; native.ContextFlags = CONTEXT_ALL;
    if (code == EXCEPTION_SINGLE_STEP && step != stepping.end()) {
        // The stepped instruction (displaced or in place) may itself have touched a
        // watched address: then this #DB carries B-bits as well as BS. Service those
        // hardware hits first (their callbacks run, DR6 is cleared), then finish the step.
        if (s->hw_active || s->dr_ever) {
            CONTEXT dr{}; dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(thread, &dr) && (dr.Dr6 & 0xF)) {
                bool handled = false;
                if (!handle_hw(s, event, handled)) { CloseHandle(thread); return false; }
            }
        }
        bool ok = !!GetThreadContext(thread, &native);
        if (step->second.displaced) {
            // The instruction ran out-of-line; the INT3 was never lifted, so there is
            // nothing to re-arm — just land on the instruction after the probe site.
            uint64_t next = step->second.site + step->second.insn_len;
#if defined(_WIN64)
            native.Rip = next;
#else
            native.Eip = (DWORD)next;
#endif
        } else if (ok) {
            ok = patch(s->pi.hProcess, step->second.site, 0xcc);   // in-place: re-arm the byte
        }
        native.EFlags &= ~0x100u;
        if (ok) ok = !!SetThreadContext(thread, &native);
        CloseHandle(thread);
        if (!ok) { set_error(s, win_error("complete breakpoint single-step")); return false; }
        if (trace_enabled())
            std::fprintf(stderr, "  step-done tid=%lu displaced=%d\n",
                         (unsigned long)event.dwThreadId, step->second.displaced);
        stepping.erase(step); disposition = DBG_CONTINUE; return true;
    }
    if (!GetThreadContext(thread, &native)) {
        CloseHandle(thread); set_error(s, win_error("get breakpoint context")); return false;
    }
    if (s->entry_reapply && address == s->entry_reapply && !probe->internal) reapply_all_hw(s);
    probe_context context = from_context(native, probe_index(s, probe),
                                         address, &remote_ops, s->pi.hProcess);
    context.config = probe->config.empty() ? nullptr : probe->config.data();
    context.tid = event.dwThreadId;
    CallbackState state{s, probe}; context.controller = &state;
    try { probe->callback(&context); }
    catch (const std::exception &e) {
        CloseHandle(thread); set_error(s, std::string("probe callback: ") + e.what()); return false;
    } catch (...) {
        CloseHandle(thread); set_error(s, "probe callback threw an unknown exception"); return false;
    }
    ++probe->hits;
    to_context(context, native);
#if defined(_WIN64)
    native.Rsp = context.regs.rsp;
#else
    native.Esp = (DWORD)context.regs.rsp;
#endif
    if (probe->flags & PROBE_ONCE) {
        // One-shot: put the original byte back for good and resume AT the site -- the
        // real instruction runs in place, no single-step needed. Stale hits from other
        // threads are rewound via retired_bps above.
        if (!patch(s->pi.hProcess, probe->address, probe->original)) {
            CloseHandle(thread); set_error(s, win_error("retire one-shot breakpoint")); return false;
        }
        probe->active = false; probe->retired = true; s->retired_bps.insert(probe->address);
#if defined(_WIN64)
        native.Rip = probe->address;
#else
        native.Eip = (DWORD)probe->address;
#endif
        native.ContextFlags = CONTEXT_FULL;   // keep any DRs the callback armed
        bool ok = !!SetThreadContext(thread, &native);
        CloseHandle(thread);
        if (!ok) { set_error(s, win_error("resume after one-shot")); return false; }
        disposition = DBG_CONTINUE; return true;
    }
    // Displaced stepping (default for ordinary instructions): run the original
    // instruction out-of-line with the INT3 left armed, so no other thread can cross
    // this site unobserved (no re-arm race) and no thread is suspended (no deadlock).
    bool displaced = probe->displaced_ok;
    uint64_t scratch_addr = displaced ? thread_scratch(s, event.dwThreadId) : 0;
    if (displaced && scratch_addr) {
        std::vector<unsigned char> code = probe->orig_insn;
        if (probe->riprel_disp_off >= 0) {
            int32_t disp; std::memcpy(&disp, code.data() + probe->riprel_disp_off, sizeof(disp));
            // Preserve the same absolute target when the copy runs from scratch.
            int64_t nd = (int64_t)disp + (int64_t)(probe->address - scratch_addr);
            if (nd < INT32_MIN || nd > INT32_MAX) displaced = false;
            else { int32_t v = (int32_t)nd; std::memcpy(code.data() + probe->riprel_disp_off, &v, sizeof(v)); }
        }
        size_t wrote = 0;
        if (displaced && (!remote_write(s->pi.hProcess, scratch_addr, code.data(), code.size(), &wrote) ||
                          wrote != code.size())) {
            CloseHandle(thread); set_error(s, win_error("stage displaced instruction")); return false;
        }
        if (displaced) FlushInstructionCache(s->pi.hProcess, (void *)(uintptr_t)scratch_addr, code.size());
    } else {
        displaced = false;   // no scratch available -> in-place fallback
    }
    if (displaced) {
#if defined(_WIN64)
        native.Rip = scratch_addr;
#else
        native.Eip = (DWORD)scratch_addr;
#endif
    } else {
        // In-place fallback (control-flow sites, or scratch/reach failure): lift the
        // byte, step over it at the real address, re-arm on the single-step (this is
        // the only path with a brief unarmed window, so it is kept for the rare cases).
        if (!patch(s->pi.hProcess, probe->address, probe->original)) {
            CloseHandle(thread); set_error(s, win_error("restore probed instruction")); return false;
        }
#if defined(_WIN64)
        native.Rip = probe->address;
#else
        native.Eip = (DWORD)probe->address;
#endif
    }
    native.EFlags |= 0x100u;
    // Preserve debug registers: the callback may have armed a hardware probe/watchpoint on
    // THIS thread (probe_watch/probe_add_at); writing CONTEXT_ALL with the pre-callback DR
    // image would clobber it. CONTEXT_FULL writes control/integer/segment only.
    native.ContextFlags = CONTEXT_FULL;
    if (!SetThreadContext(thread, &native)) {
        CloseHandle(thread); set_error(s, win_error("apply callback context")); return false;
    }
    CloseHandle(thread);
    if (trace_enabled())
        std::fprintf(stderr, "  setup tid=%lu displaced=%d scratch=0x%llx rip=0x%llx\n",
                     (unsigned long)event.dwThreadId, displaced,
                     (unsigned long long)scratch_addr, (unsigned long long)(displaced ? scratch_addr : probe->address));
    stepping[event.dwThreadId] = StepState{probe, displaced, probe->address, probe->insn_len};
    disposition = DBG_CONTINUE; return true;
}

static bool start_remote(probe_session *s, LPTHREAD_START_ROUTINE entry,
                         void *argument, probe_session::RemoteWork work) {
    s->remote_thread = CreateRemoteThread(s->pi.hProcess, nullptr, 0, entry, argument, 0, &s->remote_tid);
    if (!s->remote_thread) { set_error(s, win_error("create agent thread")); return false; }
    s->remote_work = work; return true;
}

static bool start_agent_load(probe_session *s) {
    if (s->remote_work != probe_session::REMOTE_NONE || s->remote_agent) return true;
    HMODULE local_kernel = GetModuleHandleW(L"kernel32.dll");
    auto local_load = reinterpret_cast<uintptr_t>(GetProcAddress(local_kernel, "LoadLibraryW"));
    if (!local_kernel || !local_load) { set_error(s, win_error("resolve LoadLibraryW")); return false; }
    HMODULE load_owner{};
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(local_load), &load_owner)) {
        set_error(s, win_error("resolve LoadLibraryW owner")); return false;
    }
    std::string owner_name = module_name_from_module(load_owner); uint64_t remote_owner = 0;
    for (const auto &module : s->module_bases)
        if (iequals(module.first, owner_name)) { remote_owner = module.second; break; }
    if (!remote_owner) {
        set_error(s, "target module owning LoadLibraryW was not observed"); return false;
    }
    size_t bytes = (s->agent_path.size() + 1) * sizeof(wchar_t);
    s->remote_path = VirtualAllocEx(s->pi.hProcess, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!s->remote_path) { set_error(s, win_error("allocate remote agent path")); return false; }
    SIZE_T written{};
    if (!WriteProcessMemory(s->pi.hProcess, s->remote_path, s->agent_path.c_str(), bytes, &written) ||
        written != bytes) {
        set_error(s, win_error("write remote agent path")); return false;
    }
    uint64_t remote_load = remote_owner + local_load - reinterpret_cast<uintptr_t>(load_owner);
    return start_remote(s, reinterpret_cast<LPTHREAD_START_ROUTINE>((uintptr_t)remote_load),
                        s->remote_path, probe_session::REMOTE_LOAD_AGENT);
}

static bool start_agent_init(probe_session *s) {
    if (s->remote_work != probe_session::REMOTE_NONE || !s->remote_agent || !s->local_agent) {
        set_error(s, "inline agent is not ready for initialization"); return false;
    }
    auto local_init = reinterpret_cast<uintptr_t>(GetProcAddress(s->local_agent, "probe_agent_init"));
    uint64_t remote_init = s->remote_agent + local_init - reinterpret_cast<uintptr_t>(s->local_agent);
    return start_remote(s, reinterpret_cast<LPTHREAD_START_ROUTINE>((uintptr_t)remote_init), nullptr,
                        probe_session::REMOTE_INIT_AGENT);
}

static bool agent_has_pending(const probe_session *s) {
    if (!s->shared) return false;
    for (const auto &p : s->probes) if ((p->flags & PROBE_INLINE) && p->address &&
        s->shared->requests[p->agent_index].status == PROBE_AGENT_PENDING) return true;
    return false;
}

static bool accept_agent_install(probe_session *s) {
    MemoryBarrier();
    for (auto &p : s->probes) if ((p->flags & PROBE_INLINE) && p->address && !p->active && !p->retired) {
        LONG status = s->shared->requests[p->agent_index].status;
        if (status == PROBE_AGENT_PENDING || status == PROBE_AGENT_INSTALLING) continue;   // next round
        if (status != PROBE_AGENT_INSTALLED) {
            std::string why = "inline agent failed to install " + p->location +
                              " (status=" + std::to_string(status) + ")";
            if (p->runtime) { std::fprintf(stderr, "probe: %s\n", why.c_str()); p->retired = true; continue; }
            set_error(s, why);
            return false;
        }
        p->active = true;
        std::fprintf(stderr, "probe: active %s -> addr=0x%llx (inline)\n",
                     p->location.c_str(), (unsigned long long)p->address);
    }
    return release_gate(s);
}

static bool complete_remote_thread(probe_session *s, DWORD result) {
    // The exit code comes from EXIT_THREAD_DEBUG_EVENT, not GetExitCodeThread: at
    // the instant that event is delivered the thread handle can still report
    // STILL_ACTIVE, which is the race that made agent init look like it failed.
    CloseHandle(s->remote_thread); s->remote_thread = nullptr;
    auto work = s->remote_work; s->remote_work = probe_session::REMOTE_NONE; s->remote_tid = 0;
    if (work == probe_session::REMOTE_LOAD_AGENT) {
        if (s->remote_path) {
            VirtualFreeEx(s->pi.hProcess, s->remote_path, 0, MEM_RELEASE); s->remote_path = nullptr;
        }
        if (result == 0 || !s->remote_agent) { set_error(s, "LoadLibraryW failed for probe_api_agent.dll"); return false; }
        return start_agent_init(s);
    }
    if (work == probe_session::REMOTE_INIT_AGENT) {
        if (result != 0) { set_error(s, "probe_agent_init failed (code=" + std::to_string(result) + ")"); return false; }
        if (!accept_agent_install(s)) return false;
        // Requests registered while that round ran (runtime inline adds) go next.
        if (agent_has_pending(s)) return start_agent_init(s);
        return true;
    }
    return true;
}

// Move published inline-log records out of the shared ring (single consumer). Called
// every debug-loop turn, on idle timeouts, and at report, so the ring never fills
// just because the run is long.
static void drain_agent_logs(probe_session *s) {
    if (!s->shared) return;
    auto *sh = s->shared;
    for (;;) {
        LONG64 tail = sh->log_tail;
        auto &rec = sh->logs[(uint64_t)tail % PROBE_AGENT_LOG_CAP];
        if (rec.seq != tail + 1) break;
        MemoryBarrier();
        LogRecord r;
        rec.text[PROBE_AGENT_LOG_TEXT_CAP - 1] = 0;
        r.text = rec.text; r.tid = rec.tid; r.has_stack = rec.has_stack != 0;
        r.probe = rec.probe;
        for (size_t i = 0; i < s->probes.size(); ++i)
            if ((s->probes[i]->flags & PROBE_INLINE) && s->probes[i]->agent_index == rec.probe) { r.probe = (uint32_t)i; break; }
        uint32_t n = rec.frame_count > PROBE_STACK_MAX_FRAMES ? PROBE_STACK_MAX_FRAMES : rec.frame_count;
        r.frames.assign(rec.frames, rec.frames + n);
        s->logs.push_back(std::move(r));
        MemoryBarrier();
        InterlockedExchange64(&rec.seq, tail + PROBE_AGENT_LOG_CAP);    // slot free again
        sh->log_tail = tail + 1;
    }
}

extern "C" int probe_run(probe_session *s) {
    if (!s || !s->launched) { if (s) set_error(s, "session is not launched"); return 0; }
    if (s->ran) { set_error(s, "session already ran"); return 0; }
    s->ran = true; bool initial_break = false; std::unordered_map<DWORD, StepState> stepping;
    DEBUG_EVENT event{};
    while (!s->exited) {
        drain_agent_logs(s);
        if (!WaitForDebugEvent(&event, s->shared ? 20 : INFINITE)) {
            if (GetLastError() == ERROR_SEM_TIMEOUT) continue;            // idle: drain and wait again
            set_error(s, win_error("wait for debug event")); break;
        }
        DWORD disposition = DBG_CONTINUE; bool ok = true;
        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            s->threads.insert(event.dwThreadId);                 // initial thread (for HW DRs)
            std::string name = module_name_from_handle(event.u.CreateProcessInfo.hFile);
            uint64_t base = (uint64_t)(uintptr_t)event.u.CreateProcessInfo.lpBaseOfImage;
            if (!name.empty()) s->module_bases[name] = base;
            sym_register(s, event.u.CreateProcessInfo.hFile, base);
            ok = arm_module(s, name, base);
            if (ok) arm_entry_fixup(s, (uint64_t)(uintptr_t)event.u.CreateProcessInfo.lpStartAddress);
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT:
            s->threads.insert(event.dwThreadId);
            if (s->hw_active && event.u.CreateThread.hThread)     // new thread inherits the DRs
                for (auto &p : s->probes)
                    if (p->active && (p->flags & PROBE_HW)) {
                        uint32_t rw = 0, len = 0; hw_rw_len(p->flags, rw, len);
                        set_dr_on_thread(event.u.CreateThread.hThread, p->dr_slot, p->address, true, rw, len);
                    }
            if (event.u.CreateThread.hThread) CloseHandle(event.u.CreateThread.hThread);
            break;
        case EXIT_THREAD_DEBUG_EVENT: {
            if (event.dwThreadId == s->remote_tid) ok = complete_remote_thread(s, event.u.ExitThread.dwExitCode);
            s->threads.erase(event.dwThreadId);
            auto it = stepping.find(event.dwThreadId);
            if (ok && it != stepping.end()) {
                // Only the in-place path lifted the byte; a displaced step left it armed.
                if (!it->second.displaced) ok = patch(s->pi.hProcess, it->second.site, 0xcc);
                stepping.erase(it);
                if (!ok) set_error(s, win_error("re-arm probe after thread exit"));
            }
            auto sc = s->scratch.find(event.dwThreadId);    // reclaim the thread's step buffer
            if (sc != s->scratch.end()) {
                VirtualFreeEx(s->pi.hProcess, (void *)(uintptr_t)sc->second, 0, MEM_RELEASE);
                s->scratch.erase(sc);
            }
            break;
        }
        case LOAD_DLL_DEBUG_EVENT: {
            std::string name = module_name_from_handle(event.u.LoadDll.hFile);
            uint64_t base = (uint64_t)(uintptr_t)event.u.LoadDll.lpBaseOfDll;
            if (!name.empty()) s->module_bases[name] = base;
            sym_register(s, event.u.LoadDll.hFile, base);
            ok = arm_module(s, name, base);
            if (iequals(name, "probe_api_agent.dll")) {
                s->remote_agent = base;
            }
            if (ok && s->remote_agent && s->remote_work == probe_session::REMOTE_NONE && agent_has_pending(s))
                ok = start_agent_init(s);
            if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
            break;
        }
        case UNLOAD_DLL_DEBUG_EVENT: {
            uint64_t base = (uint64_t)(uintptr_t)event.u.UnloadDll.lpBaseOfDll;
            for (auto it = s->module_bases.begin(); it != s->module_bases.end(); )
                if (it->second == base) it = s->module_bases.erase(it); else ++it;
            for (auto &p : s->probes) if (p->active && p->base == base) {
                if (p->flags & PROBE_INLINE) {
                    set_error(s, "unloading a module with an active inline probe is unsupported"); ok = false;
                } else if (p->flags & PROBE_HW) {
                    // Fully release the hardware breakpoint: clear its DR on every thread,
                    // free the slot, and drop the active count. A half-disarm (just
                    // clearing active/address) leaks the DR slot and strands the physical
                    // breakpoint on the unloaded address -> later slot exhaustion / crash.
                    release_hw(s, *p);
                    p->base = p->address = 0;
                } else { p->active = false; p->base = p->address = 0; }
            }
            break;
        }
        case EXCEPTION_DEBUG_EVENT:
            ok = handle_exception(s, event, stepping, initial_break, disposition);
            if (ok && initial_break && has_inline(s) && !s->remote_agent &&
                s->remote_work == probe_session::REMOTE_NONE)
                ok = start_agent_load(s);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            s->exit_code = event.u.ExitProcess.dwExitCode; s->exited = true; break;
        default: break;
        }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition)) {
            set_error(s, win_error("continue debug event")); ok = false;
        }
        if (!ok) break;
    }
    if (!s->exited && s->pi.hProcess) TerminateProcess(s->pi.hProcess, 3);
    if (s->exited && has_inline(s) && !s->gate_sent) set_error(s, "target exited before inline probes were ready");
    return s->exited && s->error.empty();
}

extern "C" int probe_wait_for_exit(probe_session *s) {
    if (!s || !s->ran) { if (s) set_error(s, "session has not been run"); return 0; }
    return s->exited && s->error.empty() && s->exit_code == 0;
}

static void json_string(FILE *out, const std::string &value) {
    std::fputc('\"', out);
    for (unsigned char ch : value) {
        if (ch == '\"' || ch == '\\') { std::fputc('\\', out); std::fputc(ch, out); }
        else if (ch == '\n') std::fputs("\\n", out);
        else if (ch >= 0x20) std::fputc(ch, out);
    }
    std::fputc('\"', out);
}

static std::string symbolize(probe_session *s, uint64_t addr);

extern "C" void probe_report(probe_session *s, FILE *out) {
    if (!s || !out) return;
    if (s->shared) {
        MemoryBarrier();
        for (auto &p : s->probes) if (p->flags & PROBE_INLINE)
            p->hits = (uint64_t)s->shared->requests[p->agent_index].hits;
    }
    drain_agent_logs(s);
    for (const auto &r : s->logs) {
        std::fprintf(out, "{\"kind\":\"probe_log\",\"probe\":%u,\"tid\":%u,\"message\":", r.probe, r.tid);
        json_string(out, r.text);
        if (r.has_stack) {                       // symbolized here, long after the hit
            std::fputs(",\"stack\":[", out);
            for (size_t i = 0; i < r.frames.size(); ++i) {
                if (i) std::fputc(',', out);
                json_string(out, symbolize(s, r.frames[i]));
            }
            std::fputc(']', out);
        }
        std::fputs("}\n", out);
    }
    for (const auto &p : s->probes) {
        if (p->internal) continue;
        std::fputs("{\"kind\":\"probe\",\"location\":", out); json_string(out, p->location);
        std::fprintf(out, ",\"backend\":\"%s\",\"active\":%s,\"hits\":%llu}\n",
                     p->flags & PROBE_INLINE ? "inline" : p->flags & PROBE_HW ? "hw" : "breakpoint",
                     p->active ? "true" : "false", (unsigned long long)p->hits);
    }
    uint64_t hits = 0, active = 0;
    size_t visible = 0;
    for (const auto &p : s->probes) if (!p->internal) { hits += p->hits; active += p->active; ++visible; }
    std::fprintf(out, "{\"kind\":\"probe_report\",\"probes\":%llu,\"active\":%llu,"
                 "\"hits\":%llu,\"overrides\":%llu,\"log_dropped\":%ld,\"app_exit\":%lu,\"error\":",
                 (unsigned long long)visible, (unsigned long long)active,
                 (unsigned long long)hits, (unsigned long long)s->overrides,
                 s->shared ? s->shared->log_dropped : 0, s->exit_code);
    if (s->error.empty()) std::fputs("null", out); else json_string(out, s->error);
    std::fputs("}\n", out); std::fflush(out);
}

extern "C" void probe_close(probe_session *s) {
    if (!s) return;
    if (s->launched && !s->exited && s->pi.hProcess) {
        for (auto &p : s->probes)
            if (p->active && (p->flags & PROBE_BREAKPOINT)) patch(s->pi.hProcess, p->address, p->original);
        TerminateProcess(s->pi.hProcess, 3);
    }
    if (s->pi.hProcess)
        for (auto &kv : s->scratch) VirtualFreeEx(s->pi.hProcess, (void *)(uintptr_t)kv.second, 0, MEM_RELEASE);
    if (s->sym_ready) SymCleanup(s->pi.hProcess);
    if (s->remote_thread) CloseHandle(s->remote_thread);
    if (s->remote_path && s->pi.hProcess) VirtualFreeEx(s->pi.hProcess, s->remote_path, 0, MEM_RELEASE);
    if (s->shared) UnmapViewOfFile(s->shared);
    if (s->mapping) CloseHandle(s->mapping);
    if (s->local_agent) FreeLibrary(s->local_agent);
    if (s->stdin_write) CloseHandle(s->stdin_write);
    if (s->pi.hThread) CloseHandle(s->pi.hThread);
    if (s->pi.hProcess) CloseHandle(s->pi.hProcess);
    delete s;
}

static uint64_t *register_slot(probe_context *c, enum probe_register reg) {
    if (!c) return nullptr;
    switch (reg) {
    case PROBE_REG_AX: return &c->regs.rax; case PROBE_REG_BX: return &c->regs.rbx;
    case PROBE_REG_CX: return &c->regs.rcx; case PROBE_REG_DX: return &c->regs.rdx;
    case PROBE_REG_SI: return &c->regs.rsi; case PROBE_REG_DI: return &c->regs.rdi;
    case PROBE_REG_BP: return &c->regs.rbp; case PROBE_REG_SP: return &c->regs.rsp;
#if defined(_WIN64)
    case PROBE_REG_R8: return &c->regs.r8; case PROBE_REG_R9: return &c->regs.r9;
    case PROBE_REG_R10: return &c->regs.r10; case PROBE_REG_R11: return &c->regs.r11;
    case PROBE_REG_R12: return &c->regs.r12; case PROBE_REG_R13: return &c->regs.r13;
    case PROBE_REG_R14: return &c->regs.r14; case PROBE_REG_R15: return &c->regs.r15;
#endif
    default: return nullptr;  /* x86: R8..R15 are unsupported -> null slot */
    }
}

extern "C" uint64_t get_reg(probe_context *c, enum probe_register reg) {
    uint64_t *slot = register_slot(c, reg);
    if (!slot) return 0;
    return *slot;
}

extern "C" int set_reg(probe_context *c, enum probe_register reg, uint64_t value) {
    uint64_t *slot = register_slot(c, reg); if (!slot) return 0;
    uint64_t next = value;
    if (*slot != next) {
        *slot = next;
        auto *state = static_cast<CallbackState *>(c->controller);
        if (state && state->session) ++state->session->overrides;
    }
    return 1;
}

extern "C" int get_mem(probe_context *c, uint64_t address, void *buffer, size_t size) {
    if (!c || !c->ops || !c->ops->read || (!buffer && size)) return 0;
    size_t done = 0; return c->ops->read(c->backend, address, buffer, size, &done) && done == size;
}

extern "C" int set_mem(probe_context *c, uint64_t address, const void *buffer, size_t size) {
    if (!c || !c->ops || !c->ops->write || (!buffer && size)) return 0;
    size_t done = 0; return c->ops->write(c->backend, address, buffer, size, &done) && done == size;
}

extern "C" uint64_t get_func_arg(probe_context *c, size_t index) {
    if (!c) return 0;
#if defined(_WIN64)
    /* x64 __fastcall: first four args in registers, rest above the shadow space. */
    switch (index) {
    case 0: return c->regs.rcx; case 1: return c->regs.rdx;
    case 2: return c->regs.r8; case 3: return c->regs.r9;
    default: {
        if (c->regs.rsp > UINT64_MAX - 8 || index > (UINT64_MAX - c->regs.rsp - 8) / 8) return 0;
        uint64_t value = 0, address = c->regs.rsp + 8 + 8 * index;
        return get_mem(c, address, &value, sizeof(value)) ? value : 0;
    }
    }
#else
    /* x86 __stdcall: every arg on the stack at [esp+4+4*i], read exactly 4 bytes. */
    if (c->regs.rsp > UINT64_MAX - 4 || index > (UINT64_MAX - c->regs.rsp - 4) / 4) return 0;
    uint32_t value = 0; uint64_t address = c->regs.rsp + 4 + 4 * index;
    return get_mem(c, address, &value, sizeof(value)) ? value : 0;
#endif
}

extern "C" const void *get_config(probe_context *c) { return c ? c->config : nullptr; }

extern "C" probe_session *get_session(probe_context *c) {
    auto *state = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    return state ? state->session : nullptr;
}

// Raw stack snapshot at the hit: return addresses only (StackWalk64 over the stopped
// target with the hit's register image). No symbol lookup here -- deferred to report.
static void capture_stack(probe_session *s, probe_context *c, std::vector<uint64_t> &frames) {
    frames.clear();
    frames.push_back(c->regs.pc);
    if (!s->sym_ready) return;
    CONTEXT w{}; w.ContextFlags = CONTEXT_FULL;
    to_context(*c, w);
    STACKFRAME64 f{};
#if defined(_WIN64)
    DWORD machine = IMAGE_FILE_MACHINE_AMD64;
    w.Rip = c->regs.pc; w.Rsp = c->regs.rsp; w.Rbp = c->regs.rbp;
#else
    DWORD machine = IMAGE_FILE_MACHINE_I386;
    w.Eip = (DWORD)c->regs.pc; w.Esp = (DWORD)c->regs.rsp; w.Ebp = (DWORD)c->regs.rbp;
#endif
    f.AddrPC.Offset = c->regs.pc;     f.AddrPC.Mode = AddrModeFlat;
    f.AddrStack.Offset = c->regs.rsp; f.AddrStack.Mode = AddrModeFlat;
    f.AddrFrame.Offset = c->regs.rbp; f.AddrFrame.Mode = AddrModeFlat;
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, c->tid);
    for (int i = 0; i < PROBE_STACK_MAX_FRAMES; ++i) {
        if (!StackWalk64(machine, s->pi.hProcess, thread, &f, &w, nullptr,
                         SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) break;
        if (!f.AddrPC.Offset) break;
        if (i == 0) continue;                          // frame 0 is the site itself (already pushed)
        frames.push_back(f.AddrPC.Offset);
    }
    if (thread) CloseHandle(thread);
}

static std::string symbolize(probe_session *s, uint64_t addr) {
    char buf[64]; std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)addr);
    if (!s->sym_ready) return buf;
    std::string out;
    IMAGEHLP_MODULE64 mod{}; mod.SizeOfStruct = sizeof(mod);
    if (SymGetModuleInfo64(s->pi.hProcess, addr, &mod)) out = mod.ModuleName;
    alignas(SYMBOL_INFO) char sb[sizeof(SYMBOL_INFO) + 256]{};
    auto *sym = reinterpret_cast<SYMBOL_INFO *>(sb); sym->SizeOfStruct = sizeof(SYMBOL_INFO); sym->MaxNameLen = 255;
    DWORD64 disp = 0;
    if (SymFromAddr(s->pi.hProcess, addr, &disp, sym)) {
        char tmp[300]; std::snprintf(tmp, sizeof(tmp), "!%s+0x%llx", sym->Name, (unsigned long long)disp);
        out += tmp;
    } else if (!out.empty()) {
        char tmp[40]; std::snprintf(tmp, sizeof(tmp), "+0x%llx", (unsigned long long)(addr - mod.BaseOfImage));
        out += tmp;
    }
    IMAGEHLP_LINE64 line{}; line.SizeOfStruct = sizeof(line); DWORD ld = 0;
    if (SymGetLineFromAddr64(s->pi.hProcess, addr, &ld, &line) && line.FileName) {
        char tmp[300]; std::snprintf(tmp, sizeof(tmp), " (%s:%lu)", basename_of(line.FileName).c_str(), line.LineNumber);
        out += tmp;
    }
    return out.empty() ? std::string(buf) : out + " [" + buf + "]";
}

static void log_common(probe_context *c, bool stack, const char *format, va_list ap) {
    if (!format) return;
    char line[2048];
    int n = std::vsnprintf(line, sizeof(line), format, ap);
    if (n < 0) return; line[sizeof(line) - 1] = 0;
    auto *state = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    if (!state || !state->session) { std::fprintf(stderr, "probe: %s\n", line); return; }
    LogRecord r; r.text = line; r.tid = c->tid; r.probe = c->site; r.has_stack = stack;
    if (stack) capture_stack(state->session, c, r.frames);
    std::fprintf(stderr, stack ? "probe: %s [+stack %zu frames]\n" : "probe: %s\n", line, r.frames.size());
    state->session->logs.push_back(std::move(r));
}

extern "C" void send_log(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format); log_common(c, false, format, ap); va_end(ap);
}

extern "C" void send_log_stack(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format); log_common(c, true, format, ap); va_end(ap);
}
