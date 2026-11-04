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
#include <map>
#include <vector>
#include <Zydis/Zydis.h>
#include "symbols.hpp"   // dbghelp+symsrv loaded dynamically; honours _NT_SYMBOL_PATH
#include <tlhelp32.h>
#include <timeapi.h>
#pragma comment(lib, "winmm.lib")
#include <unordered_set>
#include <atomic>
#include <mutex>
#include <thread>

struct Probe {
    std::string location, module, callback_export;
    std::string export_name;   // "module!Export+0xOFF": resolved from the export table at load
    uint64_t sym_offset = 0;
    bool retired = false;      // PROBE_ONCE probe that already fired (kept for the report)
    bool internal = false;     // library-owned (not reported)
    bool runtime = false;      // added after launch: an install failure is reported, not fatal
    bool vetted = false;       // pre-hook check done for this inline install
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
    DWORD pid = 0, tid = 0;   // the stopped event's thread (call_func runs code on it)
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
    uint64_t scratch = 0;   // the out-of-line copy's slot (displaced steps)
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
    std::mutex log_mu;                         // logs + agent_map: debug-loop thread + drainer thread
    uint32_t agent_map[PROBE_AGENT_MAX_PROBES] = {};   // agent request index -> probes[] index (under log_mu)
    std::thread drainer;                       // empties the agent's log ring continuously
    uint64_t controller_dropped = 0;           // controller-side logs lost to allocation failure
    std::atomic<bool> drain_stop{false};
    bool sym_ready = false;    // dbghelp initialised on the target (stack walk + symbolize)
    std::unordered_map<std::string, uint64_t> module_bases;
    std::unordered_map<std::string, std::string> module_paths;   // name -> on-disk image (prehook diff)
    std::vector<std::string> prehooks;                           // JSON lines for the report
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
    // Out-of-line step slots, 64 bytes each, carved from 64 KiB blocks allocated within
    // +-2 GiB of the probed code (so x64 RIP-relative operands can be retargeted and every
    // site takes the exact displaced path). Keyed by (thread, 1 GiB region of the site).
    std::map<std::pair<DWORD, uint64_t>, uint64_t> scratch;
    std::map<uint64_t, std::vector<uint64_t>> scratch_free;   // region -> free slots
    std::vector<uint64_t> scratch_blocks;
    // Live target threads + hardware-breakpoint state. HW probes set a debug
    // register on EVERY thread (and each new one), so there is no code to modify
    // and no re-arm race: exact under threads for any instruction, up to 4 slots.
    std::unordered_set<DWORD> threads;
    uint8_t dr_used = 0;
    uint8_t dr_ever = 0;
    uint8_t dr_next = 0;                       // next DR slot to try (rotation)
    uint64_t entry_reapply = 0;                // image entry: re-apply DRs on first arrival
    uint64_t entry_addr = 0;                   // image entry point (hold-for-install point)
    bool entry_seen = false;
    HANDLE svc_event = nullptr;                // agent service: "install pending requests"
    std::vector<HANDLE> held;                  // threads held until inline installs confirm
    ULONGLONG held_since = 0;                       // slots we have ever owned (stale-#DB filter)
    std::unordered_set<uint64_t> retired_bps;  // removed INT3 sites (stale-hit filter)
    int hw_active = 0;
    bool launched = false, ran = false, exited = false, gate_sent = false;
    bool attached = false;                     // probe_attach: detach (not kill) on close
    std::atomic<bool> stop_requested{false};   // probe_close from another thread while probe_run runs
    std::atomic<bool> running{false};          // probe_run is executing (on some thread)
    bool detached = false;
    DWORD in_call_tid = 0;                     // thread currently running a call_func callee
    bool skip_continue = false;                // call_func already continued the current event
    uint64_t call_trap = 0;                    // INT3 the callee returns into
    bool initial_break = false;
    std::unordered_map<DWORD, StepState> stepping;   // threads mid single-step
};

static bool register_runtime_inline(probe_session *s, Probe &p);
static bool kick_agent(probe_session *s);
static bool resolve_inline(probe_session *s, Probe &p, uint64_t base);
static Probe *probe_at(probe_session *s, uint64_t address);
static bool trace_enabled() { static const bool on = std::getenv("PROBE_TRACE") != nullptr; return on; }
static void start_drainer(probe_session *s);
static void stop_drainer(probe_session *s);
static void release_hw(probe_session *s, Probe &p);
static bool dispatch_event(probe_session *s, DEBUG_EVENT &event, DWORD &disposition);
static void release_held(probe_session *s, const char *why);

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
    std::string path = module_path_from_handle(file);
    if (path.empty()) return;
    s->module_paths[basename_of(path)] = path;
    if (!s->sym_ready) return;
    // Pass the real SizeOfImage: with deferred loads dbghelp does not read the image yet,
    // so a size of 0 registers only the base address and no frame inside it resolves.
    DWORD size = 0; size_t got = 0;
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{};
    if (remote_read(s->pi.hProcess, base, &dos, sizeof(dos), &got) && got == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
        remote_read(s->pi.hProcess, base + (uint32_t)dos.e_lfanew, &nt, sizeof(nt), &got) && got == sizeof(nt) &&
        nt.Signature == IMAGE_NT_SIGNATURE)
        size = nt.OptionalHeader.SizeOfImage;
    // dbghelp gets the exact (wide) path, so non-ASCII directories work.
    std::wstring wpath;
    {
        wchar_t w[1024];
        DWORD n = GetFinalPathNameByHandleW(file, w, 1024, FILE_NAME_NORMALIZED);
        if (n && n < 1024) {
            wpath.assign(w, n);
            if (wpath.size() > 4 && wpath.compare(0, 4, L"\\\\?\\") == 0) wpath = wpath.substr(4);
        }
    }
    if (!wpath.empty()) uhh_sym::register_module(s->pi.hProcess, wpath, base, size);
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
    if (enable) { dr7 &= ~fieldmask; dr7 |= ln | field; } else { dr7 &= ~(ln | fieldmask); }   // full release
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
    // Slots the TARGET itself has enabled (its own debug registers) are not ours to take.
    uint8_t foreign = 0;
    if (!s->threads.empty()) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT, FALSE, *s->threads.begin());
        CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (t && GetThreadContext(t, &c))
            for (int i = 0; i < 4; ++i) if ((c.Dr7 >> (i * 2)) & 3) foreign |= (uint8_t)(1u << i);
        if (t) CloseHandle(t);
        foreign &= (uint8_t)~s->dr_used;
    }
    for (int k = 0; k < 4; ++k) {
        int i = (s->dr_next + k) & 3;
        if (!(s->dr_used & (1u << i)) && !(foreign & (1u << i))) { slot = i; break; }
    }
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
    // A probe re-armed after its module was unloaded and loaded again: a new install.
    if (request.status != PROBE_AGENT_PENDING) InterlockedExchange(&request.status, PROBE_AGENT_PENDING);
    std::fprintf(stderr, "probe: resolved %s -> base=0x%llx addr=0x%llx (awaiting agent)\n",
                 p.location.c_str(), (unsigned long long)base, (unsigned long long)p.address);
    return true;
}

// ---- Foreign-hook ("pre-hooked site") detection -------------------------------------
// Compare the live bytes at a probe site with the same RVA in the module's file on disk
// (bytes covered by base relocations are ignored: they legitimately differ). If they
// differ, someone patched the site: report both byte strings disassembled, the hook
// pattern and where it leads, and weakly suggest alternative probe points.
static std::string hex_bytes(const unsigned char *b, size_t n) {
    std::string r; char t[4];
    for (size_t i = 0; i < n; ++i) { std::snprintf(t, sizeof(t), i ? " %02x" : "%02x", b[i]); r += t; }
    return r;
}

static void zydis_init(ZydisDecoder &dec) {
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
}

static std::vector<std::string> disasm(const unsigned char *b, size_t n, uint64_t at, size_t max_insns) {
    std::vector<std::string> out;
    ZydisDecoder dec; zydis_init(dec);
    ZydisFormatter fmt; ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    size_t off = 0;
    while (off < n && out.size() < max_insns) {
        ZydisDecodedInstruction insn; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, b + off, n - off, &insn, ops))) { out.push_back("(undecodable)"); break; }
        char text[96];
        if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&fmt, &insn, ops, insn.operand_count_visible, text,
                                                          sizeof(text), at + off, nullptr))) std::snprintf(text, sizeof(text), "?");
        char line[160];
        std::snprintf(line, sizeof(line), "+%zu: %-24s %s", off, hex_bytes(b + off, insn.length).c_str(), text);
        out.emplace_back(line);
        off += insn.length;
    }
    return out;
}

struct DiskImage {          // just enough of the PE file to map RVAs and find relocations
    std::vector<IMAGE_SECTION_HEADER> sections;
    IMAGE_DATA_DIRECTORY reloc{};
    HANDLE file = INVALID_HANDLE_VALUE;
    ~DiskImage() { if (file != INVALID_HANDLE_VALUE) CloseHandle(file); }
    bool read_at(uint64_t off, void *buf, size_t n) const {
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)off; DWORD got = 0;
        return SetFilePointerEx(file, li, nullptr, FILE_BEGIN) && ReadFile(file, buf, (DWORD)n, &got, nullptr) && got == n;
    }
    bool rva_to_off(uint32_t rva, size_t n, uint64_t &off) const {
        for (auto &sec : sections) {
            uint32_t size = sec.SizeOfRawData;
            if (rva >= sec.VirtualAddress && (uint64_t)rva + n <= (uint64_t)sec.VirtualAddress + size) {
                off = (uint64_t)sec.PointerToRawData + (rva - sec.VirtualAddress); return true;
            }
        }
        return false;
    }
    bool open(const std::string &path) {
        file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{};
        if (!read_at(0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
        if (!read_at((uint32_t)dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) return false;
        uint32_t count = nt.FileHeader.NumberOfSections;
        if (count > 96) return false;
        sections.resize(count);
        uint64_t sec_off = (uint32_t)dos.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
        if (count && !read_at(sec_off, sections.data(), count * sizeof(IMAGE_SECTION_HEADER))) return false;
        reloc = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        return true;
    }
    // Mark bytes of [rva, rva+n) that a base relocation rewrites at load time.
    void reloc_mask(uint32_t rva, size_t n, std::vector<bool> &mask) const {
        mask.assign(n, false);
        if (!reloc.VirtualAddress || !reloc.Size || reloc.Size > (16u << 20)) return;
        uint64_t off = 0;
        if (!rva_to_off(reloc.VirtualAddress, reloc.Size, off)) return;
        std::vector<unsigned char> blob(reloc.Size);
        if (!read_at(off, blob.data(), blob.size())) return;
        size_t at = 0;
        while (at + sizeof(IMAGE_BASE_RELOCATION) <= blob.size()) {
            auto *blk = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(blob.data() + at);
            if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || at + blk->SizeOfBlock > blob.size()) break;
            size_t entries = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            auto *e = reinterpret_cast<const WORD *>(blk + 1);
            for (size_t i = 0; i < entries; ++i) {
                int type = e[i] >> 12; uint32_t where = blk->VirtualAddress + (e[i] & 0xfff);
                size_t width = type == IMAGE_REL_BASED_DIR64 ? 8 : type == IMAGE_REL_BASED_HIGHLOW ? 4 : 0;
                for (size_t k = 0; k < width; ++k) {
                    uint64_t b = (uint64_t)where + k;
                    if (b >= rva && b < (uint64_t)rva + n) mask[(size_t)(b - rva)] = true;
                }
            }
            at += blk->SizeOfBlock;
        }
    }
};

static std::string symbolize(probe_session *s, uint64_t addr);

// Returns true when the site is modified relative to disk; fills a JSON report and
// prints a readable one. Sites in modules we have no file for are not judged.
static bool detect_prehook(probe_session *s, const Probe &p, std::string &json) {
    if (p.module.empty() || !p.address || p.address < p.base) return false;
    std::string path;
    for (auto &kv : s->module_paths) if (iequals(kv.first, p.module)) { path = kv.second; break; }
    if (trace_enabled()) std::fprintf(stderr, "  prehook-check %s path=%s\n", p.location.c_str(), path.c_str());
    if (path.empty()) return false;
    constexpr size_t N = 24;
    unsigned char live[N]{}, disk[N]{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, p.address, live, N, &got) || got != N) return false;
    DiskImage img; uint64_t off = 0;
    uint32_t rva = (uint32_t)(p.address - p.base);
    if (!img.open(path) || !img.rva_to_off(rva, N, off) || !img.read_at(off, disk, N)) return false;
    std::vector<bool> mask; img.reloc_mask(rva, N, mask);
    // Our own INT3 (a breakpoint probe on the same site) is not a foreign hook.
    size_t first = N, last = 0;
    for (size_t i = 0; i < 16; ++i) {
        if (mask[i] || live[i] == disk[i]) continue;
        if (i == 0 && live[0] == 0xcc) { Probe *own = probe_at(s, p.address); if (own && own != &p && !(own->flags & PROBE_INLINE)) continue; }
        if (first == N) first = i;
        last = i;
    }
    if (first == N) return false;
    size_t patched = last + 1;
    // Pattern + destination from the live bytes.
    ZydisDecoder dec; zydis_init(dec);
    ZydisDecodedInstruction insn; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    std::string pattern = "unknown modification"; uint64_t dest = 0;
    if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, live, N, &insn, ops))) {
        if (insn.mnemonic == ZYDIS_MNEMONIC_JMP && insn.operand_count_visible >= 1) {
            ZyanU64 target = 0;
            if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], p.address, &target))) {
                pattern = insn.length == 2 ? "jmp rel8" : "jmp rel32 (5-byte detour)"; dest = target;
            } else if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], p.address, &target))) {
                uint64_t ptr = 0; size_t w = sizeof(void *);
                if (remote_read(s->pi.hProcess, target, &ptr, w, &got) && got == w) dest = ptr;
                pattern = "jmp [mem] (indirect detour)";
            }
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_INT3) {
            pattern = "int3 (another debugger/instrumenter's breakpoint)";
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_PUSH && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                   live[insn.length] == 0xc3) {
            pattern = "push imm; ret (detour)"; dest = (uint32_t)ops[0].imm.value.u;
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_MOV && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            ZydisDecodedInstruction j; ZydisDecodedOperand jo[ZYDIS_MAX_OPERAND_COUNT];
            if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, live + insn.length, N - insn.length, &j, jo)) &&
                j.mnemonic == ZYDIS_MNEMONIC_JMP && jo[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                pattern = "mov reg, imm; jmp reg (absolute detour)"; dest = ops[1].imm.value.u;
                patched = (std::max)(patched, (size_t)insn.length + j.length);
            }
        }
    }
    // Follow the jump chain (hooking libraries usually jump to a small relay stub that
    // jumps on to the replacement): up to 4 hops through jmp rel/[mem]/reg-imm, stopping
    // at the first address inside a loaded module, which is what the user can act on.
    std::vector<uint64_t> hops;
    for (int hop = 0; dest && hop < 4; ++hop) {
        bool in_module = false;
        for (auto &kv : s->module_bases) {
            IMAGE_DOS_HEADER d{}; IMAGE_NT_HEADERS n{}; size_t g = 0;
            if (dest < kv.second) continue;
            if (remote_read(s->pi.hProcess, kv.second, &d, sizeof(d), &g) && g == sizeof(d) &&
                remote_read(s->pi.hProcess, kv.second + (uint32_t)d.e_lfanew, &n, sizeof(n), &g) && g == sizeof(n) &&
                dest < kv.second + n.OptionalHeader.SizeOfImage) { in_module = true; break; }
        }
        if (in_module) break;
        unsigned char code[24]{};
        if (!remote_read(s->pi.hProcess, dest, code, sizeof(code), &got) || got != sizeof(code)) break;
        ZydisDecodedInstruction ji; ZydisDecodedOperand jo[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code, sizeof(code), &ji, jo))) break;
        uint64_t next = 0; ZyanU64 t = 0;
        if (ji.mnemonic == ZYDIS_MNEMONIC_JMP && jo[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ji, &jo[0], dest, &t))) next = t;
        else if (ji.mnemonic == ZYDIS_MNEMONIC_JMP && jo[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ji, &jo[0], dest, &t))) {
            uint64_t ptr = 0;
            if (remote_read(s->pi.hProcess, t, &ptr, sizeof(void *), &got) && got == sizeof(void *)) next = ptr;
        } else if (ji.mnemonic == ZYDIS_MNEMONIC_MOV && jo[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   jo[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            ZydisDecodedInstruction j2; ZydisDecodedOperand o2[ZYDIS_MAX_OPERAND_COUNT];
            if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + ji.length, sizeof(code) - ji.length, &j2, o2)) &&
                j2.mnemonic == ZYDIS_MNEMONIC_JMP && o2[0].type == ZYDIS_OPERAND_TYPE_REGISTER) next = jo[1].imm.value.u;
        }
        if (!next || next == dest) break;
        hops.push_back(dest);
        dest = next;
    }
    // First unmodified instruction boundary in the ORIGINAL code at/after the patch.
    size_t resume = 0;
    while (resume < patched && resume < N) {
        ZydisDecodedInstruction d; ZydisDecodedOperand dops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, disk + resume, N - resume, &d, dops))) { resume = 0; break; }
        resume += d.length;
    }
    auto live_d = disasm(live, (std::max)(patched, (size_t)8), p.address, 4);
    auto disk_d = disasm(disk, resume ? resume : 8, p.address, 4);
    std::string dest_s = dest ? symbolize(s, dest) : std::string();
    std::string via;
    for (uint64_t h : hops) { char b[32]; std::snprintf(b, sizeof(b), "%s0x%llx", via.empty() ? "" : " -> ", (unsigned long long)h); via += b; }
    std::vector<std::string> suggest;
    char line[256];
    std::snprintf(line, sizeof(line), "PROBE_HW at %s (debug register; modifies no code, coexists with the existing hook)", p.location.c_str());
    suggest.emplace_back(line);
    if (dest) {
        std::snprintf(line, sizeof(line), "probe the detour target %s (runs before the other hook's logic)", dest_s.c_str());
        suggest.emplace_back(line);
    }
    if (resume && resume < N) {
        std::snprintf(line, sizeof(line), "%s+0x%x: first unmodified original instruction; usually reached when the existing hook resumes the original code",
                      p.module.c_str(), rva + (uint32_t)resume);
        suggest.emplace_back(line);
    }
    // Human-readable report.
    std::fprintf(stderr, "probe: PRE-HOOKED SITE %s (0x%llx): %zu byte(s) differ from %s\n",
                 p.location.c_str(), (unsigned long long)p.address, patched, path.c_str());
    std::fprintf(stderr, "probe:   pattern: %s%s%s%s%s\n", pattern.c_str(), dest ? " -> " : "", dest_s.c_str(),
                 via.empty() ? "" : "  (via ", via.empty() ? "" : (via + ")").c_str());
    std::fprintf(stderr, "probe:   live (in memory):\n");
    for (auto &l : live_d) std::fprintf(stderr, "probe:     %s\n", l.c_str());
    std::fprintf(stderr, "probe:   original (on disk):\n");
    for (auto &l : disk_d) std::fprintf(stderr, "probe:     %s\n", l.c_str());
    std::fprintf(stderr, "probe:   you could instead (suggestions, not verified):\n");
    for (auto &l : suggest) std::fprintf(stderr, "probe:     - %s\n", l.c_str());
    // JSON for the report.
    auto q = [](const std::string &v) {
        std::string r = "\"";
        for (char ch : v) { if (ch == '"' || ch == '\\') r += '\\'; if ((unsigned char)ch >= 0x20) r += ch; }
        return r + "\"";
    };
    auto arr = [&](const std::vector<std::string> &v) {
        std::string r = "["; for (size_t i = 0; i < v.size(); ++i) { if (i) r += ","; r += q(v[i]); } return r + "]";
    };
    char addr[32]; std::snprintf(addr, sizeof(addr), "0x%llx", (unsigned long long)p.address);
    json = std::string("{\"kind\":\"prehook\",\"location\":") + q(p.location) + ",\"address\":" + q(addr) +
           ",\"patched_bytes\":" + std::to_string(patched) + ",\"pattern\":" + q(pattern) +
           ",\"destination\":" + (dest ? q(dest_s) : std::string("null")) +
           ",\"via\":" + q(via) +
           ",\"live\":" + q(hex_bytes(live, (std::max)(patched, (size_t)8))) + ",\"original\":" + q(hex_bytes(disk, (std::max)(patched, (size_t)8))) +
           ",\"live_disasm\":" + arr(live_d) + ",\"original_disasm\":" + arr(disk_d) + ",\"suggest\":" + arr(suggest) + "}";
    return true;
}

// Decide what to do with a pre-hooked site for a code-modifying probe. Inline probes are
// refused by default (installing over an unknown detour chains through code we did not
// inspect); PROBE_ALLOW_PREHOOKED chains anyway, PROBE_FALLBACK_HW moves the probe to a
// debug register. Breakpoint probes still work (the jmp is stepped in place): report only.
// Returns false when the probe must not be armed; sets moved_to_hw when converted.
// An inline hook is installed by making the site's page non-executable for a moment
// (SafetyHook's thread-safe patching) while the installer calls back into ntdll. If the
// site shares a page with the very routines that sequence needs, the installer faults on
// itself. Those pages are off-limits to inline hooks: use the hardware backend there.
static bool inline_page_hazard(probe_session *s, const Probe &p, std::string &which) {
    uint64_t ntdll = 0;
    for (auto &kv : s->module_bases) if (iequals(kv.first, "ntdll.dll")) { ntdll = kv.second; break; }
    if (!ntdll || !p.address) return false;
    static const char *const needed[] = {"NtProtectVirtualMemory", "NtQueryVirtualMemory",
                                         "NtFlushInstructionCache", "KiUserExceptionDispatcher",
                                         "NtContinue", "RtlAddVectoredExceptionHandler",
                                         "RtlAcquireSRWLockExclusive", "RtlReleaseSRWLockExclusive",
                                         "RtlEnterCriticalSection", "RtlLeaveCriticalSection",
                                         "RtlAllocateHeap", "RtlFreeHeap", "NtAllocateVirtualMemory",
                                         "NtFreeVirtualMemory"};
    uint64_t lo = p.address & ~(uint64_t)0xFFF, hi = (p.address + 32 + 0xFFF) & ~(uint64_t)0xFFF;
    std::string saved = s->error;
    for (const char *name : needed) {
        uint64_t rva = 0;
        if (!resolve_export(s, ntdll, name, rva)) continue;
        uint64_t a = ntdll + rva;
        if (a + 32 > lo && a < hi) { which = std::string("ntdll!") + name; s->error = saved; return true; }
    }
    // KernelBase wrappers the installer calls (VirtualProtect, VirtualQuery, ...).
    uint64_t kb = 0;
    for (auto &kv : s->module_bases) if (iequals(kv.first, "KernelBase.dll")) { kb = kv.second; break; }
    static const char *const kbneeded[] = {"VirtualProtect", "VirtualQuery", "VirtualAlloc", "VirtualFree",
                                           "FlushInstructionCache"};
    for (const char *name : kbneeded) {
        if (!kb) break;
        uint64_t rva = 0;
        if (!resolve_export(s, kb, name, rva)) continue;
        uint64_t a = kb + rva;
        if (a + 32 > lo && a < hi) { which = std::string("KernelBase!") + name; s->error = saved; return true; }
    }
    s->error = saved;
    return false;
}

static bool vet_site(probe_session *s, Probe &p, bool &moved_to_hw) {
    moved_to_hw = false;
    if (p.flags & PROBE_HW) return true;
    std::string hazard;
    if ((p.flags & PROBE_INLINE) && inline_page_hazard(s, p, hazard)) {
        if (p.flags & PROBE_FALLBACK_HW) {
            p.flags = (p.flags & ~(uint32_t)PROBE_INLINE) | PROBE_HW; moved_to_hw = true;
            std::fprintf(stderr, "probe: %s -> hardware fallback (shares a page with %s, which the inline installer needs)\n",
                         p.location.c_str(), hazard.c_str());
            return true;
        }
        set_error(s, "inline probe " + p.location + " shares a page with " + hazard +
                     " (the inline installer needs it); use PROBE_HW or PROBE_FALLBACK_HW");
        return false;
    }
    std::string json;
    if (!detect_prehook(s, p, json)) return true;
    s->prehooks.push_back(json);
    if (!(p.flags & PROBE_INLINE) || (p.flags & PROBE_ALLOW_PREHOOKED)) return true;
    if (p.flags & PROBE_FALLBACK_HW) {
        p.flags = (p.flags & ~(uint32_t)PROBE_INLINE) | PROBE_HW; moved_to_hw = true;
        std::fprintf(stderr, "probe: %s -> hardware fallback (pre-hooked site)\n", p.location.c_str());
        return true;
    }
    set_error(s, "inline probe " + p.location + " is on a pre-hooked site (see the prehook report; "
                 "use PROBE_ALLOW_PREHOOKED to chain, PROBE_FALLBACK_HW or PROBE_HW to avoid)");
    return false;
}

static bool arm_probe(probe_session *s, Probe &item, uint64_t base) {
    // A late-resolving inline probe (the gate is already released, so the target may
    // call the site before the async agent install lands) with PROBE_FALLBACK_HW set
    // becomes a hardware probe: that arms synchronously here (just debug registers —
    // no in-target code, no loader lock, no race) and is exact. The callback is
    // backend-agnostic, so it runs controller-side unchanged.
    // With the agent's service thread running, a late inline site is installed while the
    // loading thread is held (synchronous), so the fallback is only needed without it.
    // Judge an inline site BEFORE any backend decision, so a foreign hook is always
    // reported (and handled per PROBE_ALLOW_PREHOOKED / PROBE_FALLBACK_HW) -- including
    // when the late-install rule below would move the probe anyway.
    if (item.flags & PROBE_INLINE) {
        Probe view = item; view.base = base;
        if (!item.export_name.empty()) {
            uint64_t exp = 0; std::string saved = s->error;
            if (resolve_export(s, base, item.export_name, exp)) view.rva = exp + item.sym_offset;
            s->error = saved;
        }
        view.address = base + view.rva;
        bool moved = false;
        if (!vet_site(s, view, moved)) { item.retired = true; return false; }
        if (moved) item.flags = view.flags;                // pre-hooked / hazard page -> hw
    }
    if ((item.flags & PROBE_INLINE) && (item.flags & PROBE_FALLBACK_HW) && s->gate_sent &&
        !(s->shared && s->shared->service_ready && s->svc_event)) {
        item.flags = (item.flags & ~(uint32_t)PROBE_INLINE) | PROBE_HW;
        std::fprintf(stderr, "probe: %s -> hardware fallback (late inline would race the first call)\n",
                     item.location.c_str());
    }
    if (!item.export_name.empty()) {
        uint64_t exp = 0;
        if (!resolve_export(s, base, item.export_name, exp)) {
            // Not exported: try the module's symbols (PDB beside the image, or a symbol
            // server via _NT_SYMBOL_PATH) -- internal functions by name.
            uint64_t addr = 0; std::string saved = s->error;
            uint32_t image = 0;
            {
                IMAGE_DOS_HEADER d{}; IMAGE_NT_HEADERS n{}; size_t g = 0;
                if (remote_read(s->pi.hProcess, base, &d, sizeof(d), &g) && g == sizeof(d) &&
                    remote_read(s->pi.hProcess, base + (uint32_t)d.e_lfanew, &n, sizeof(n), &g) && g == sizeof(n))
                    image = n.OptionalHeader.SizeOfImage;
            }
            // The symbol must lie inside THIS module's image (not a stale or same-named one).
            if (!s->sym_ready || !uhh_sym::resolve(s->pi.hProcess, item.module, item.export_name, addr) ||
                addr < base || addr >= base + image)
                return false;
            s->error.clear();
            exp = addr - base;
            std::fprintf(stderr, "probe: %s resolved from symbols -> %s+0x%llx\n", item.location.c_str(),
                         item.module.c_str(), (unsigned long long)exp);
            (void)saved;
        }
        item.rva = exp + item.sym_offset;
    }
    if (item.flags & PROBE_BREAKPOINT) {
        // Judge the site BEFORE planting our INT3 (address is known: base + rva).
        Probe probe_view = item; probe_view.base = base; probe_view.address = base + item.rva;
        bool moved = false; (void)vet_site(s, probe_view, moved);
        return arm_breakpoint(s, item, base);
    }
    return item.flags & PROBE_HW ? arm_hw(s, item, base) : resolve_inline(s, item, base);
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

// A lifted (in-place) breakpoint byte may only be re-armed while a breakpoint probe is
// still active at exactly that site: after detach, PROBE_ONCE retirement or an unload
// (where another module may now live at the address) the original byte must stay.
static Probe *probe_at(probe_session *s, uint64_t address);
static bool still_armed(probe_session *s, uint64_t site) {
    Probe *p = probe_at(s, site);
    return p && (p->flags & PROBE_BREAKPOINT);
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
    s->entry_reapply = entry; s->entry_addr = entry;
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
        ((flags & PROBE_ALLOW_PREHOOKED) && type != PROBE_INLINE) || // only meaningful for inline
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
    // Benchmark-only knob (not API): compare inline extended-state handling strategies.
    if (const char *m = std::getenv("UHH_BENCH_XSTATE"))
        s->shared->xstate_mode = !std::strcmp(m, "none") ? 1 : !std::strcmp(m, "full") ? 2 : 0;
    start_drainer(s);
    wchar_t svc[64]; probe_agent_service_name(s->pi.dwProcessId, svc);
    s->svc_event = CreateEventW(nullptr, FALSE, FALSE, svc);
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
    {
        std::lock_guard<std::mutex> lock(s->log_mu);
        for (auto &m : s->agent_map) m = UINT32_MAX;
        for (size_t i = 0; i < s->probes.size(); ++i)
            if (s->probes[i]->flags & PROBE_INLINE) {
                if (count < PROBE_AGENT_MAX_PROBES) s->agent_map[count] = (uint32_t)i;
                s->probes[i]->agent_index = count++;
            }
    }
    if (!count) return true;
    if (count > PROBE_AGENT_MAX_PROBES) { set_error(s, "too many inline probes"); return false; }
    if (!open_agent_section(s, count)) return false;
    for (const auto &p : s->probes) if (p->flags & PROBE_INLINE) fill_request(s, *p);
    return true;
}

static bool start_agent_load(probe_session *s);
static bool start_agent_init(probe_session *s);
static bool agent_has_pending(const probe_session *s);
static bool accept_agent_install(probe_session *s);

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
    {
        std::lock_guard<std::mutex> lock(s->log_mu);
        if (idx == 0) for (auto &m : s->agent_map) m = UINT32_MAX;
        s->agent_map[idx] = probe_index(s, &p);
    }
    fill_request(s, p);
    MemoryBarrier();
    s->shared->request_count = idx + 1;
    return true;
}

// ---- Synchronous inline install -----------------------------------------------------
// An inline hook installed asynchronously races the target's first calls unless the
// target happens to wait. So threads that could reach an uninstalled site are HELD
// (suspended) until the agent confirms the install round: the main thread at the image
// entry point (the loader lock is free there, so the agent can still be loaded), and a
// thread that is loading a DLL with inline sites (it holds the loader lock, so the
// install is done by the agent's already-running service thread, never a new thread).
static bool inline_unconfirmed(const probe_session *s) {
    for (const auto &p : s->probes)
        if ((p->flags & PROBE_INLINE) && p->address && !p->active && !p->retired) return true;
    return false;
}

static void hold_thread(probe_session *s, DWORD tid) {
    HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!t) return;
    DWORD prev = SuspendThread(t);
    if (prev == (DWORD)-1) { CloseHandle(t); return; }
    if (trace_enabled()) std::fprintf(stderr, "  hold tid=%lu prev_suspend=%lu\n", (unsigned long)tid, (unsigned long)prev);
    if (s->held.empty()) s->held_since = GetTickCount64();
    s->held.push_back(t);
    std::fprintf(stderr, "probe: holding thread %lu until inline installs confirm\n", (unsigned long)tid);
}

static void release_held(probe_session *s, const char *why) {
    if (s->held.empty()) return;
    for (HANDLE t : s->held) {
        DWORD prev = ResumeThread(t);
        if (trace_enabled()) std::fprintf(stderr, "  release tid=%lu prev_suspend=%lu\n", (unsigned long)GetThreadId(t), (unsigned long)prev);
        CloseHandle(t);
    }
    std::fprintf(stderr, "probe: released %zu held thread(s) (%s)\n", s->held.size(), why);
    s->held.clear();
}

static bool vet_pending_inline(probe_session *s);

// Start (or queue) agent work for pending inline requests.
static bool kick_agent(probe_session *s) {
    if (s->shared && s->shared->service_ready && s->svc_event) {     // persistent service thread
        if (!vet_pending_inline(s)) return false;
        SetEvent(s->svc_event); return true;
    }
    if (s->remote_work != probe_session::REMOTE_NONE) return true;   // picked up when it finishes
    if (!s->remote_agent) return start_agent_load(s);
    return start_agent_init(s);
}

static bool release_gate(probe_session *s) {
    if (s->gate_sent) return true;
    if (s->attached || !s->stdin_write) { s->gate_sent = true; return true; }   // nothing to release
    DWORD wrote{}; char key = '\n';
    if (!WriteFile(s->stdin_write, &key, 1, &wrote, nullptr) || wrote != 1) {
        set_error(s, win_error("deliver gate keystroke")); return false;
    }
    s->gate_sent = true; return true;
}

static bool same_bitness(probe_session *s, HANDLE process);
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
        // A process created under a debugger gets the NT debug heap (fill patterns,
        // different layout): the target must run exactly as it would without UHH.
        char prev_ndh[16] = {0};
        DWORD had_ndh = GetEnvironmentVariableA("_NO_DEBUG_HEAP", prev_ndh, sizeof(prev_ndh));
        SetEnvironmentVariableA("_NO_DEBUG_HEAP", "1");
        BOOL ok = CreateProcessA(argv[0], command.data(), nullptr, nullptr, TRUE,
                                 DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &s->pi);
        SetEnvironmentVariableA("_NO_DEBUG_HEAP", had_ndh && had_ndh < sizeof(prev_ndh) ? prev_ndh : nullptr);
        CloseHandle(stdin_read);
        if (!ok) {
            CloseHandle(s->stdin_write); s->stdin_write = nullptr;
            set_error(s, win_error("debug launch")); return 0;
        }
        if (!same_bitness(s, s->pi.hProcess)) {
            TerminateProcess(s->pi.hProcess, 3);
            CloseHandle(s->pi.hThread); CloseHandle(s->pi.hProcess); s->pi = {};
            CloseHandle(s->stdin_write); s->stdin_write = nullptr;
            return 0;
        }
        s->launched = true;
        { std::string which; s->sym_ready = uhh_sym::init(s->pi.hProcess, which);
          std::fprintf(stderr, "probe: symbols via %s%s\n", which.c_str(), uhh_sym::has_symbol_server() ? " (symbol server capable)" : ""); }
        if (!create_agent_channel(s) || (!has_inline(s) && !release_gate(s))) {
            TerminateProcess(s->pi.hProcess, 3); return 0;
        }
        return 1;
    } catch (const std::exception &e) { set_error(s, e.what()); return 0; }
}

// The controller and target must be the same bitness: callbacks run with the controller's
// view of registers, argument slots and pointer width. A mismatch would silently produce
// garbage, so refuse it up front.
static bool same_bitness(probe_session *s, HANDLE process) {
    BOOL me = FALSE, it = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &me) || !IsWow64Process(process, &it)) return true;   // cannot tell
    if (me == it) return true;
    set_error(s, it ? "target is a 32-bit (WOW64) process: use the x86 build of UHH"
                    : "target is a 64-bit process: use the x64 build of UHH");
    return false;
}

extern "C" int probe_attach(probe_session *s, uint32_t pid) {
    if (!s) return 0;
    if (s->launched) { set_error(s, "session already launched"); return 0; }
    s->pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!s->pi.hProcess) { set_error(s, win_error("open target process")); return 0; }
    if (!same_bitness(s, s->pi.hProcess)) { CloseHandle(s->pi.hProcess); s->pi.hProcess = nullptr; return 0; }
    if (!DebugActiveProcess(pid)) {
        set_error(s, win_error("attach debugger")); CloseHandle(s->pi.hProcess); s->pi.hProcess = nullptr; return 0;
    }
    DebugSetProcessKillOnExit(FALSE);              // our exit must never take the target down
    s->pi.dwProcessId = pid;
    s->attached = true; s->launched = true; s->gate_sent = true;
    { std::string which; s->sym_ready = uhh_sym::init(s->pi.hProcess, which); }
    if (!create_agent_channel(s)) { DebugActiveProcessStop(pid); return 0; }
    return 1;
}

static void snapshot_pids(const char *name, std::unordered_set<DWORD> &out, DWORD *newest_new,
                          const std::unordered_set<DWORD> *exclude) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    wchar_t wname[MAX_PATH]{};
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, MAX_PATH);
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    for (BOOL more = Process32FirstW(snap, &pe); more; more = Process32NextW(snap, &pe)) {
        if (_wcsicmp(pe.szExeFile, wname)) continue;
        out.insert(pe.th32ProcessID);
        if (newest_new && exclude && !exclude->count(pe.th32ProcessID)) *newest_new = pe.th32ProcessID;
    }
    CloseHandle(snap);
}

extern "C" int probe_attach_new(probe_session *s, const char *image_name, uint32_t timeout_ms) {
    if (!s) return 0;
    if (!image_name || !*image_name) { set_error(s, "attach_new needs an image name"); return 0; }
    std::unordered_set<DWORD> existing; snapshot_pids(image_name, existing, nullptr, nullptr);
    std::fprintf(stderr, "probe: waiting for a new %s (%zu already running, ignored)\n", image_name, existing.size());
    timeBeginPeriod(1);                               // ~1 ms polling granularity
    ULONGLONG start = GetTickCount64();
    DWORD pid = 0;
    while (!pid) {
        std::unordered_set<DWORD> now; snapshot_pids(image_name, now, &pid, &existing);
        if (pid) break;
        if (timeout_ms && GetTickCount64() - start > timeout_ms) break;
        Sleep(1);
    }
    timeEndPeriod(1);
    if (!pid) { set_error(s, std::string("no new ") + image_name + " appeared"); return 0; }
    std::fprintf(stderr, "probe: new %s pid %lu -> attaching\n", image_name, (unsigned long)pid);
    return probe_attach(s, pid);
}

// Detach from an attached, still-running target leaving it exactly as it ran before:
// inline hooks removed by the agent, every INT3 restored, every debug register cleared,
// and no thread left mid single-step. Events keep being dispatched while that happens
// (a thread may hit a breakpoint or finish a step in the meantime).
static void pump(probe_session *s, DWORD ms) {
    DEBUG_EVENT event{};
    ULONGLONG until = GetTickCount64() + ms;
    while (!s->exited && GetTickCount64() < until) {
        if (!WaitForDebugEvent(&event, 20)) continue;
        DWORD disposition = DBG_CONTINUE;
        dispatch_event(s, event, disposition);
        if (s->skip_continue) { s->skip_continue = false; continue; }
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition);
        if (s->remote_work == probe_session::REMOTE_NONE && s->stepping.empty() && ms == 0) break;
    }
}

static void detach(probe_session *s) {
    s->error.clear();
    release_held(s, "detach");
    if (s->remote_agent && s->local_agent && s->remote_work == probe_session::REMOTE_NONE) {
        auto local_stop = reinterpret_cast<uintptr_t>(GetProcAddress(s->local_agent, "probe_agent_stop"));
        if (local_stop) {
            uint64_t remote_stop = s->remote_agent + local_stop - reinterpret_cast<uintptr_t>(s->local_agent);
            HANDLE t = CreateRemoteThread(s->pi.hProcess, nullptr, 0,
                                          reinterpret_cast<LPTHREAD_START_ROUTINE>((uintptr_t)remote_stop), nullptr, 0, nullptr);
            if (t) {                                   // keep dispatching until it has run
                ULONGLONG until = GetTickCount64() + 5000;
                while (!s->exited && WaitForSingleObject(t, 0) == WAIT_TIMEOUT && GetTickCount64() < until) pump(s, 20);
                CloseHandle(t);
            }
        }
    }
    for (auto &p : s->probes) {
        if (!p->active) continue;
        if (p->flags & PROBE_BREAKPOINT) {
            patch(s->pi.hProcess, p->address, p->original);
            s->retired_bps.insert(p->address); p->active = false;
        } else if (p->flags & PROBE_HW) {
            release_hw(s, *p);
        }
    }
    // Let in-flight breakpoint hits rewind and mid-step threads land before letting go.
    ULONGLONG until = GetTickCount64() + 2000;
    do { pump(s, 50); } while (!s->exited && !s->stepping.empty() && GetTickCount64() < until);
    stop_drainer(s);
    if (!s->exited) DebugActiveProcessStop(s->pi.dwProcessId);
    std::fprintf(stderr, "probe: detached from pid %lu\n", (unsigned long)s->pi.dwProcessId);
}

// Per-thread out-of-line step buffer in the target (executable), allocated on demand.

// Reserve+commit one 64 KiB block as close as possible to `site` (within +-2 GiB on x64).
static uint64_t alloc_block_near(probe_session *s, uint64_t site) {
#if defined(_WIN64)
    const uint64_t gran = 0x10000, span = 0x7FF00000ull;
    uint64_t lo = site > span ? site - span : gran, hi = site + span;
    for (int dir = 0; dir < 2; ++dir) {                  // search down from the site, then up
        uint64_t a = (site & ~(gran - 1));
        for (int steps = 0; steps < 4096; ++steps) {
            a = dir == 0 ? a - gran : a + gran;
            if (a < lo || a > hi) break;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQueryEx(s->pi.hProcess, (void *)(uintptr_t)a, &mbi, sizeof(mbi))) continue;
            if (mbi.State != MEM_FREE) {                   // skip the whole occupied region
                uint64_t rb = (uint64_t)(uintptr_t)mbi.BaseAddress, rs = mbi.RegionSize;
                a = dir == 0 ? (rb & ~(gran - 1)) : ((rb + rs + gran - 1) & ~(gran - 1)) - gran;
                continue;
            }
            void *m = VirtualAllocEx(s->pi.hProcess, (void *)(uintptr_t)a, gran, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (m) return (uint64_t)(uintptr_t)m;
        }
    }
#endif
    (void)site;
    void *m = VirtualAllocEx(s->pi.hProcess, nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return m ? (uint64_t)(uintptr_t)m : 0;
}

static uint64_t thread_scratch(probe_session *s, DWORD tid, uint64_t site) {
    uint64_t region = site >> 30;
    auto key = std::make_pair(tid, region);
    auto it = s->scratch.find(key);
    if (it != s->scratch.end()) return it->second;
    auto &pool = s->scratch_free[region];
    if (pool.empty()) {
        uint64_t block = alloc_block_near(s, site);
        if (!block) return 0;
        s->scratch_blocks.push_back(block);
        for (uint64_t off = 0x10000; off >= 64; off -= 64) pool.push_back(block + off - 64);
    }
    uint64_t slot = pool.back(); pool.pop_back();
    s->scratch[key] = slot;
    return slot;
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
    {
        probe_ipc_request head{}; size_t n = 0;
        if (remote_read(s->pi.hProcess, (uint64_t)ex.ExceptionInformation[0], &head, offsetof(probe_ipc_request, address), &n) &&
            n == offsetof(probe_ipc_request, address) && head.op == PROBE_IPC_INSTALL_DONE) {
            // Harmless if forged: acceptance re-checks every request status itself.
            if (!accept_agent_install(s)) { std::fprintf(stderr, "probe: %s\n", s->error.c_str()); }
            if (agent_has_pending(s)) kick_agent(s);
            else if (!inline_unconfirmed(s)) release_held(s, "inline installs confirmed");
            return true;
        }
    }
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
    else if (req.op == PROBE_IPC_ADD_SYMBOL)
        result = probe_add_symbol_cfg(s, req.symbol, cb, req.flags, req.config_len ? req.config : nullptr,
                                      req.config_len <= sizeof(req.config) ? req.config_len : 0);
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
    bool any = false, exec_hit = false;
    DWORD64 consumed = 0;
    for (int slot = 0; slot < 4; ++slot) {
        if (!(native.Dr6 & (1u << slot))) continue;
        Probe *probe = nullptr;
        for (auto &p : s->probes) if (p->active && (p->flags & PROBE_HW) && p->dr_slot == slot) { probe = p.get(); break; }
        if (!probe) {
            // A slot we owned but have since released (PROBE_ONCE / unload): a #DB that was
            // already in flight on another thread. Swallow it rather than crash the app.
            if (s->dr_ever & (1u << slot)) { any = true; consumed |= (1u << slot); }
            continue;
        }
        consumed |= (1u << slot);
        any = true;
        #if defined(_WIN64)
        uint64_t hit_pc = native.Rip;
#else
        uint64_t hit_pc = native.Eip;
#endif
        // A watch hit while this thread runs a displaced copy: report the real code address.
        auto st = s->stepping.find(event.dwThreadId);
        if (st != s->stepping.end() && st->second.displaced && st->second.scratch &&
            hit_pc >= st->second.scratch && hit_pc <= st->second.scratch + st->second.insn_len)
            hit_pc = st->second.site + (hit_pc - st->second.scratch);
        if (!(probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW))) exec_hit = true;
        // Execute probes: pc == the probe address. Watchpoints trap AFTER the access, so
        // pc is the instruction following the store/load -- the real code location.
        if (!(probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) && hit_pc != probe->address) {
            any = true; continue;                                    // stale: slot was reassigned
        }
        probe_context context = from_context(native, probe_index(s, probe), hit_pc, &remote_ops, s->pi.hProcess);
        context.config = probe->config.empty() ? nullptr : probe->config.data();
        context.tid = event.dwThreadId;
        CallbackState state{s, probe, event.dwProcessId, event.dwThreadId}; context.controller = &state;
        if (event.dwThreadId == s->in_call_tid) { ++probe->hits; continue; }   // inside call_func: no re-entry
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
    // RF only for EXECUTE breakpoints (fault-type: the instruction has not run yet). Data
    // watchpoints are trap-type -- the access already happened -- and RF would wrongly
    // suppress an execute breakpoint on the very next instruction.
    if (exec_hit) native.EFlags |= 0x10000u;
    // Callbacks may have armed/released hardware probes (probe_watch, PROBE_ONCE), which
    // rewrote THIS thread's debug registers. Take the live DR image, not the stale one
    // captured before the callbacks, so the write-back below does not undo them.
    {
        CONTEXT dr{}; dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &dr)) {
            native.Dr0 = dr.Dr0; native.Dr1 = dr.Dr1; native.Dr2 = dr.Dr2; native.Dr3 = dr.Dr3; native.Dr7 = dr.Dr7;
        }
    }
    native.Dr6 &= ~consumed;     // clear only the status bits of slots we own
    if (!SetThreadContext(thread, &native)) { CloseHandle(thread); set_error(s, win_error("resume hw breakpoint")); return false; }
    CloseHandle(thread); handled = true; return true;
}

static bool handle_exception(probe_session *s, const DEBUG_EVENT &event,
                             std::unordered_map<DWORD, StepState> &stepping,
                             bool &initial_break, DWORD &disposition) {
    auto &ex = event.u.Exception.ExceptionRecord; DWORD code = ex.ExceptionCode;
    disposition = DBG_EXCEPTION_NOT_HANDLED;
    // The loader's initial breakpoint -- but only if it is not one of OUR INT3s: a probe
    // can fire during loader initialisation (e.g. ntdll!NtCreateFile from the shim engine),
    // before the loader breakpoint, and must be handled as a probe hit, not swallowed.
    if (code == EXCEPTION_BREAKPOINT && !initial_break &&
        !probe_at(s, (uint64_t)(uintptr_t)ex.ExceptionAddress) && !s->retired_bps.count((uint64_t)(uintptr_t)ex.ExceptionAddress)) {
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
    if (trace_enabled() && code == EXCEPTION_ACCESS_VIOLATION && ex.NumberParameters >= 2) {
        unsigned char around[24] = {0}; size_t got = 0;
        remote_read(s->pi.hProcess, address - 8, around, sizeof(around), &got);
        std::fprintf(stderr, "  AV %s 0x%llx first=%lu bytes[-8..+16]=%s\n",
                     ex.ExceptionInformation[0] == 8 ? "execute" : ex.ExceptionInformation[0] ? "write" : "read",
                     (unsigned long long)ex.ExceptionInformation[1], (unsigned long)event.u.Exception.dwFirstChance,
                     hex_bytes(around, got).c_str());
    }
    if (code != EXCEPTION_SINGLE_STEP && !probe && step != stepping.end() && step->second.displaced &&
        event.u.Exception.dwFirstChance) {
        // The displaced copy faulted. The target must see that fault at the REAL
        // instruction (its own SEH/C++ handlers and unwind data are keyed to it), so
        // swallow this one and re-run the instruction in place: lift our byte, step it
        // there; it faults again at the right address and is passed through below.
        uint64_t scratch = step->second.scratch;
        if (scratch && address >= scratch && address < scratch + step->second.insn_len + 16) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
            bool ok = t && GetThreadContext(t, &w);
            bool armed = still_armed(s, step->second.site);
            Probe *owner = armed ? probe_at(s, step->second.site) : nullptr;
            if (ok && owner) ok = patch(s->pi.hProcess, step->second.site, owner->original);
#if defined(_WIN64)
            w.Rip = step->second.site;
#else
            w.Eip = (DWORD)step->second.site;
#endif
            if (owner) w.EFlags |= 0x100u; else w.EFlags &= ~0x100u;
            ok = ok && SetThreadContext(t, &w);
            if (t) CloseHandle(t);
            if (!ok) { set_error(s, win_error("re-run faulting displaced instruction")); return false; }
            if (owner) step->second.displaced = false; else stepping.erase(step);
            disposition = DBG_CONTINUE; return true;
        }
    }
    // Exceptions Windows raises ONLY because a debugger is attached (closing an invalid or
    // protected handle): without UHH the call just returns an error, so continue them.
    if ((code == 0xC0000008u /*STATUS_INVALID_HANDLE*/ || code == 0xC0000235u /*HANDLE_NOT_CLOSABLE*/) &&
        event.u.Exception.dwFirstChance && !probe) {
        disposition = DBG_CONTINUE; return true;
    }
    if ((code != EXCEPTION_SINGLE_STEP || step == stepping.end()) && !probe) {
        // An unexpected exception (a fault in the out-of-line copy, or any app
        // exception) reached a thread still mid-step. Drop its stale StepState so a
        // later stray single-step can't teleport it to site+insn_len; re-arm the byte
        // if the step was in-place. Pass the exception through unchanged.
        if (step != stepping.end()) {
            if (!step->second.displaced && still_armed(s, step->second.site)) patch(s->pi.hProcess, step->second.site, 0xcc);
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
            if (still_armed(s, step->second.site)) ok = patch(s->pi.hProcess, step->second.site, 0xcc);   // in-place: re-arm
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
    bool at_entry = s->entry_addr && address == s->entry_addr && !s->entry_seen;
    if (at_entry) s->entry_seen = true;
    probe_context context = from_context(native, probe_index(s, probe),
                                         address, &remote_ops, s->pi.hProcess);
    context.config = probe->config.empty() ? nullptr : probe->config.data();
    context.tid = event.dwThreadId;
    CallbackState state{s, probe, event.dwProcessId, event.dwThreadId}; context.controller = &state;
    if (event.dwThreadId != s->in_call_tid)          // a probe hit INSIDE call_func's callee: step over it
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
        if (at_entry && inline_unconfirmed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
        disposition = DBG_CONTINUE; return true;
    }
    // Displaced stepping (default for ordinary instructions): run the original
    // instruction out-of-line with the INT3 left armed, so no other thread can cross
    // this site unobserved (no re-arm race) and no thread is suspended (no deadlock).
    bool displaced = probe->displaced_ok;
    uint64_t scratch_addr = displaced ? thread_scratch(s, event.dwThreadId, probe->address) : 0;
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
    stepping[event.dwThreadId] = StepState{probe, displaced, probe->address, probe->insn_len, displaced ? scratch_addr : 0};
    if (at_entry && inline_unconfirmed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
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

static bool vet_pending_inline(probe_session *s) {
    // Vet every inline site about to be installed: the bytes may have changed since the
    // site was resolved (a TLS callback or another tool can patch during loader init).
    for (size_t i = 0; i < s->probes.size(); ++i) {
        Probe &p = *s->probes[i];
        if (!(p.flags & PROBE_INLINE) || !p.address || p.active || p.retired || p.vetted) continue;
        // (Re-judged here even if judged at resolve time: a foreign hook may have been
        //  placed in between, e.g. by a TLS callback during loader initialisation.)
        auto &request = s->shared->requests[p.agent_index];
        if (request.status != PROBE_AGENT_PENDING) continue;
        p.vetted = true;
        bool moved = false;
        if (!vet_site(s, p, moved)) {
            if (p.runtime) { std::fprintf(stderr, "probe: %s\n", s->error.c_str()); s->error.clear(); }
            InterlockedExchange(&request.status, PROBE_AGENT_BAD_REQUEST); p.retired = true;
            if (!p.runtime) return false;
            continue;
        }
        if (moved) {
            InterlockedExchange(&request.status, PROBE_AGENT_BAD_REQUEST);   // agent must not install it
            uint64_t base = p.base; p.address = 0;
            if (!arm_hw(s, p, base)) return false;
        }
    }
    return true;
}

static bool start_agent_init(probe_session *s) {
    if (s->remote_work != probe_session::REMOTE_NONE || !s->remote_agent || !s->local_agent) {
        set_error(s, "inline agent is not ready for initialization"); return false;
    }
    if (!vet_pending_inline(s)) return false;
    if (!agent_has_pending(s)) return accept_agent_install(s);
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
        if (agent_has_pending(s)) return kick_agent(s);
        if (!inline_unconfirmed(s)) release_held(s, "inline installs confirmed");
        return true;
    }
    return true;
}

// Move published inline-log records out of the shared ring (single consumer). Called
// every debug-loop turn, on idle timeouts, and at report, so the ring never fills
// just because the run is long.
static size_t drain_agent_logs(probe_session *s) {
    if (!s->shared) return 0;
    auto *sh = s->shared;
    size_t moved = 0;
    std::lock_guard<std::mutex> lock(s->log_mu);   // also makes this the single consumer
    for (;;) {
        LONG64 tail = sh->log_tail;
        auto &rec = sh->logs[(uint64_t)tail % PROBE_AGENT_LOG_CAP];
        if (rec.seq != tail + 1) break;
        MemoryBarrier();
        LogRecord r;
        rec.text[PROBE_AGENT_LOG_TEXT_CAP - 1] = 0;
        r.text = rec.text; r.tid = rec.tid; r.has_stack = rec.has_stack != 0;
        // Never touch s->probes here (the debug loop may be growing it): agent_map is the
        // lock-protected agent-index -> probe-index translation.
        r.probe = rec.probe < PROBE_AGENT_MAX_PROBES && s->agent_map[rec.probe] != UINT32_MAX
                      ? s->agent_map[rec.probe] : rec.probe;
        uint32_t n = rec.frame_count > PROBE_STACK_MAX_FRAMES ? PROBE_STACK_MAX_FRAMES : rec.frame_count;
        try {
            r.frames.assign(rec.frames, rec.frames + n);
            s->logs.push_back(std::move(r));
        } catch (...) {
            InterlockedIncrement(&sh->log_dropped);       // out of memory: count it, keep going
        }
        MemoryBarrier();
        InterlockedExchange64(&rec.seq, tail + PROBE_AGENT_LOG_CAP);    // slot free again
        sh->log_tail = tail + 1;
        ++moved;
    }
    return moved;
}

// Producers in the target can log at ~1M records/s; the debug loop only gets to the
// ring between events. A dedicated consumer keeps the ring near empty so producers
// rarely see it full (and when they do they wait -- logs are never dropped by design).
static void start_drainer(probe_session *s) {
    if (s->drainer.joinable() || !s->shared) return;
    s->drain_stop = false;
    s->drainer = std::thread([s] {
        unsigned idle = 0;
        while (!s->drain_stop.load(std::memory_order_relaxed)) {
            InterlockedIncrement64(&s->shared->drain_beat);           // "controller alive"
            if (drain_agent_logs(s)) { idle = 0; continue; }
            if (++idle < 64) SwitchToThread(); else Sleep(1);
        }
    });
}

// After the target has exited no producer can still be mid-publish, so records published
// beyond a slot that was claimed but never published (its producer died at exit) are
// recovered, and each such slot is counted as dropped -- never lost silently.
static void drain_final(probe_session *s) {
    if (!s->shared) return;
    drain_agent_logs(s);
    if (!s->exited) return;
    auto *sh = s->shared;
    std::lock_guard<std::mutex> lock(s->log_mu);
    LONG64 head = sh->log_head;
    for (LONG64 pos = sh->log_tail; pos < head; ++pos) {
        auto &rec = sh->logs[(uint64_t)pos % PROBE_AGENT_LOG_CAP];
        if (rec.seq != pos + 1) { InterlockedIncrement(&sh->log_dropped); continue; }
        LogRecord r;
        rec.text[PROBE_AGENT_LOG_TEXT_CAP - 1] = 0;
        r.text = rec.text; r.tid = rec.tid; r.has_stack = rec.has_stack != 0;
        r.probe = rec.probe < PROBE_AGENT_MAX_PROBES && s->agent_map[rec.probe] != UINT32_MAX ? s->agent_map[rec.probe] : rec.probe;
        uint32_t n = rec.frame_count > PROBE_STACK_MAX_FRAMES ? PROBE_STACK_MAX_FRAMES : rec.frame_count;
        try { r.frames.assign(rec.frames, rec.frames + n); s->logs.push_back(std::move(r)); }
        catch (...) { InterlockedIncrement(&sh->log_dropped); }
    }
    sh->log_tail = head;
}

static void stop_drainer(probe_session *s) {
    if (s->shared) InterlockedExchange(&s->shared->controller_gone, 1);   // producers stop waiting
    if (!s->drainer.joinable()) { drain_final(s); return; }
    s->drain_stop = true; s->drainer.join();
    drain_final(s);
}

// One debug event -> library state changes. Shared by probe_run and the detach path.
static bool dispatch_event(probe_session *s, DEBUG_EVENT &event, DWORD &disposition) {
    disposition = DBG_CONTINUE; bool ok = true;
    switch (event.dwDebugEventCode) {
    case CREATE_PROCESS_DEBUG_EVENT: {
        s->threads.insert(event.dwThreadId);                 // initial thread (for HW DRs)
        std::string name = module_name_from_handle(event.u.CreateProcessInfo.hFile);
        uint64_t base = (uint64_t)(uintptr_t)event.u.CreateProcessInfo.lpBaseOfImage;
        if (!name.empty()) s->module_bases[name] = base;
        sym_register(s, event.u.CreateProcessInfo.hFile, base);
        ok = arm_module(s, name, base);
        if (ok && !s->attached) arm_entry_fixup(s, (uint64_t)(uintptr_t)event.u.CreateProcessInfo.lpStartAddress);
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
        // Do NOT close hThread: the debug subsystem owns it and closes it itself when the
        // thread's EXIT_THREAD event is continued. Closing it here made that later close hit
        // whatever handle had reused the value (e.g. a held thread's -> left suspended).
        break;
    case EXIT_THREAD_DEBUG_EVENT: {
        if (event.dwThreadId == s->remote_tid) ok = complete_remote_thread(s, event.u.ExitThread.dwExitCode);
        s->threads.erase(event.dwThreadId);
        auto it = s->stepping.find(event.dwThreadId);
        if (ok && it != s->stepping.end()) {
            // Only the in-place path lifted the byte; a displaced step left it armed.
            if (!it->second.displaced && still_armed(s, it->second.site)) ok = patch(s->pi.hProcess, it->second.site, 0xcc);
            s->stepping.erase(it);
            if (!ok) set_error(s, win_error("re-arm probe after thread exit"));
        }
        for (auto sc = s->scratch.begin(); sc != s->scratch.end(); ) {   // return its step slots
            if (sc->first.first == event.dwThreadId) {
                s->scratch_free[sc->first.second].push_back(sc->second);
                sc = s->scratch.erase(sc);
            } else ++sc;
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
        if (!s->held.empty()) s->held_since = GetTickCount64();   // symbol work above may have been slow
        if (ok && agent_has_pending(s)) {
            if (s->shared->service_ready && s->svc_event) {
                // This thread holds the loader lock: keep it (and so the new module's
                // code) parked until the agent's service thread confirms the hooks.
                hold_thread(s, event.dwThreadId);
                ok = kick_agent(s);
            } else if (s->remote_agent && s->remote_work == probe_session::REMOTE_NONE) {
                ok = start_agent_init(s);
            }
        }
        if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
        break;
    }
    case UNLOAD_DLL_DEBUG_EVENT: {
        uint64_t base = (uint64_t)(uintptr_t)event.u.UnloadDll.lpBaseOfDll;
        if (s->sym_ready) uhh_sym::unregister_module(s->pi.hProcess, base);
        for (auto it = s->module_bases.begin(); it != s->module_bases.end(); )
            if (it->second == base) it = s->module_bases.erase(it); else ++it;
        for (auto &p : s->probes) if (p->active && p->base == base) {
            if (p->flags & PROBE_INLINE) {
                // The hooked code went away with its module. The probe goes back to pending,
                // exactly like breakpoint/hw probes: if the module loads again (anywhere),
                // the agent installs a fresh hook at the new address.
                std::fprintf(stderr, "probe: %s unloaded with its module; pending until it loads again\n", p->location.c_str());
                p->active = false; p->vetted = false; p->base = p->address = 0;
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
        ok = handle_exception(s, event, s->stepping, s->initial_break, disposition);
        if (ok && s->initial_break && has_inline(s) && !s->remote_agent &&
            s->remote_work == probe_session::REMOTE_NONE)
            ok = start_agent_load(s);
        break;
    case EXIT_PROCESS_DEBUG_EVENT:
        s->exit_code = event.u.ExitProcess.dwExitCode; s->exited = true; break;
    default: break;
    }
    return ok;
}

extern "C" int probe_run(probe_session *s) {
    if (!s || !s->launched) { if (s) set_error(s, "session is not launched"); return 0; }
    if (s->ran) { set_error(s, "session already ran"); return 0; }
    s->ran = true;
    s->running = true;
    DEBUG_EVENT event{};
    while (!s->exited) {
        if (s->stop_requested) {
            // probe_close was called on another thread. The debug API binds the debug object
            // to THIS thread, so the detach (or termination) happens here.
            if (s->attached) { detach(s); s->detached = true; }
            else if (s->pi.hProcess) { TerminateProcess(s->pi.hProcess, 3); s->stop_requested = false; continue; }
            break;
        }
        drain_agent_logs(s);
        if (!s->held.empty() && GetTickCount64() - s->held_since > 5000) {
            // Never wedge the target: an install that does not confirm in 5 s is reported
            // and the threads run on (the affected probes simply stay inactive).
            std::fprintf(stderr, "probe: warning: inline install not confirmed within 5 s\n");
            release_held(s, "install timeout");
        }
        if (!WaitForDebugEvent(&event, 20)) {                         // short: also polls stop requests
            if (GetLastError() == ERROR_SEM_TIMEOUT) continue;            // idle: drain and wait again
            set_error(s, win_error("wait for debug event")); break;
        }
        DWORD disposition = DBG_CONTINUE;
        bool ok = dispatch_event(s, event, disposition);
        if (s->skip_continue) { s->skip_continue = false; if (!ok) break; continue; }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition)) {
            set_error(s, win_error("continue debug event")); ok = false;
        }
        if (!ok) break;
    }
    release_held(s, "session end");
    stop_drainer(s);
    if (!s->exited && s->pi.hProcess && !s->attached) TerminateProcess(s->pi.hProcess, 3);
    if (s->exited && has_inline(s) && !s->gate_sent) set_error(s, "target exited before inline probes were ready");
    int result = (s->exited || s->detached) && s->error.empty();
    s->running = false;                                   // last touch of s on this thread
    return result;
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
            p->hits = probe_agent_hits(s->shared, p->agent_index);
    }
    drain_agent_logs(s);
    for (const auto &j : s->prehooks) { std::fputs(j.c_str(), out); std::fputc('\n', out); }
    std::lock_guard<std::mutex> log_lock(s->log_mu);
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
                 (unsigned long long)hits, (unsigned long long)(s->overrides + (s->shared ? (uint64_t)s->shared->overrides : 0)),
                 (long)((s->shared ? s->shared->log_dropped : 0) + (long)s->controller_dropped), s->exit_code);
    if (s->error.empty()) std::fputs("null", out); else json_string(out, s->error);
    std::fputs("}\n", out); std::fflush(out);
}

extern "C" void probe_close(probe_session *s) {
    if (!s) return;
    if (s->running) {
        // probe_run is executing on another thread: ask it to detach/stop (it owns the
        // debug object) and wait for it to finish before tearing the session down.
        s->stop_requested = true;
        for (int i = 0; i < 1500 && s->running; ++i) Sleep(10);
    }
    if (s->detached) {
        // already detached by probe_run
    } else if (s->attached && !s->exited && s->pi.hProcess) {
        detach(s);
    } else if (s->launched && !s->exited && s->pi.hProcess) {
        for (auto &p : s->probes)
            if (p->active && (p->flags & PROBE_BREAKPOINT)) patch(s->pi.hProcess, p->address, p->original);
        TerminateProcess(s->pi.hProcess, 3);
    }
    if (s->pi.hProcess)
        for (uint64_t b : s->scratch_blocks) VirtualFreeEx(s->pi.hProcess, (void *)(uintptr_t)b, 0, MEM_RELEASE);
    if (s->sym_ready) uhh_sym::cleanup(s->pi.hProcess);
    if (s->remote_thread) CloseHandle(s->remote_thread);
    if (s->svc_event) CloseHandle(s->svc_event);
    if (s->remote_path && s->pi.hProcess) VirtualFreeEx(s->pi.hProcess, s->remote_path, 0, MEM_RELEASE);
    stop_drainer(s);
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

// ---- call_func: run a target function on the stopped thread -------------------------
// The debugger way (like gdb's `call`): save the thread's context, build an ABI-correct
// call frame below its stack whose return address is a library INT3, let it run, catch
// the INT3, read the return register and restore the context exactly. The original
// debug event is continued to start the call; the trap event on the same thread takes
// its place, so the caller's handler finishes and continues as if nothing happened.
static uint64_t resolve_symbol(probe_session *s, const char *symbol) {
    if (!symbol || !*symbol) return 0;
    if (symbol[0] == '0' && (symbol[1] == 'x' || symbol[1] == 'X')) return std::strtoull(symbol + 2, nullptr, 16);
    Probe tmp; std::string saved = s->error;
    if (!parse_location(s, symbol, tmp)) { s->error = saved; return 0; }
    for (auto &kv : s->module_bases)
        if (iequals(kv.first, tmp.module)) {
            uint64_t rva = tmp.rva;
            if (!tmp.export_name.empty()) {
                uint64_t exp = 0;
                if (!resolve_export(s, kv.second, tmp.export_name, exp)) { s->error = saved; return 0; }
                rva = exp + tmp.sym_offset;
            }
            s->error = saved; return kv.second + rva;
        }
    s->error = saved; return 0;
}

static int call_in_target(probe_session *s, CallbackState *st, uint64_t fn, uint64_t *ret, int nargs, const uint64_t *args) {
    if (s->in_call_tid || nargs < 0 || nargs > 8) return 0;           // no nesting
    if (!s->call_trap) {
        void *mem = VirtualAllocEx(s->pi.hProcess, nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        unsigned char cc = 0xcc; size_t w = 0;
        if (!mem || !remote_write(s->pi.hProcess, (uint64_t)(uintptr_t)mem, &cc, 1, &w)) return 0;
        s->call_trap = (uint64_t)(uintptr_t)mem;
    }
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, st->tid);
    if (!thread) return 0;
    CONTEXT saved{}; saved.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT;
    if (!GetThreadContext(thread, &saved)) { CloseHandle(thread); return 0; }
    CONTEXT w = saved; size_t wrote = 0; bool ok = true;
#if defined(_WIN64)
    uint64_t sp = ((saved.Rsp - 512) & ~(uint64_t)0xF) - 8;           // entry rsp == 8 mod 16
    uint64_t frame[13] = {s->call_trap};                               // ret, shadow x4, stack args
    for (int i = 4; i < nargs; ++i) frame[5 + (i - 4)] = args[i];
    ok = remote_write(s->pi.hProcess, sp, frame, sizeof(frame), &wrote) && wrote == sizeof(frame);
    w.Rsp = sp; w.Rip = fn;
    w.Rcx = nargs > 0 ? args[0] : 0; w.Rdx = nargs > 1 ? args[1] : 0;
    w.R8 = nargs > 2 ? args[2] : 0;  w.R9 = nargs > 3 ? args[3] : 0;
#else
    uint32_t sp = ((uint32_t)saved.Esp - 512) & ~0xFu;
    uint32_t frame[9] = {(uint32_t)s->call_trap};                      // ret, then args (stdcall/cdecl both
    for (int i = 0; i < nargs; ++i) frame[1 + i] = (uint32_t)args[i];  // fine: esp is restored after)
    ok = remote_write(s->pi.hProcess, sp, frame, sizeof(frame), &wrote) && wrote == sizeof(frame);
    w.Esp = sp; w.Eip = (DWORD)fn;
#endif
    w.EFlags &= ~0x100u;
    w.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!ok || !SetThreadContext(thread, &w)) { CloseHandle(thread); return 0; }
    s->in_call_tid = st->tid;
    if (!ContinueDebugEvent(st->pid, st->tid, DBG_CONTINUE)) { s->in_call_tid = 0; SetThreadContext(thread, &saved); CloseHandle(thread); return 0; }
    int result = 0; bool trapped = false;
    ULONGLONG until = GetTickCount64() + 5000;
    DEBUG_EVENT ev{};
    while (!s->exited) {
        if (!WaitForDebugEvent(&ev, 20)) {
            if (GetTickCount64() > until) break;
            continue;
        }
        if (ev.dwThreadId == st->tid && ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            auto &er = ev.u.Exception.ExceptionRecord;
            if (er.ExceptionCode == EXCEPTION_BREAKPOINT && (uint64_t)(uintptr_t)er.ExceptionAddress == s->call_trap) {
                CONTEXT r{}; r.ContextFlags = CONTEXT_INTEGER;
                if (GetThreadContext(thread, &r)) {
#if defined(_WIN64)
                    if (ret) *ret = r.Rax;
#else
                    if (ret) *ret = r.Eax;                     // pointer-sized return (EAX)
#endif
                    result = 1;
                }
                trapped = true; break;                             // leave this event pending
            }
            if (!(er.ExceptionCode == EXCEPTION_BREAKPOINT || er.ExceptionCode == EXCEPTION_SINGLE_STEP)) {
                trapped = true; break;                             // the callee faulted: abandon the call
            }
        }
        DWORD disposition = DBG_CONTINUE;
        dispatch_event(s, ev, disposition);                        // other threads keep working
        if (s->skip_continue) { s->skip_continue = false; continue; }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, disposition);
    }
    s->in_call_tid = 0;
    if (trapped) {
        SetThreadContext(thread, &saved);                          // exactly as it was at the hit
        // The pending trap/fault event on this thread now stands in for the original one.
    } else if (!s->exited) {
        // Timed out with the callee still running: stop it, put the context back, and tell
        // the loop the original event is already continued (there is nothing to continue).
        SuspendThread(thread); SetThreadContext(thread, &saved); ResumeThread(thread);
        s->skip_continue = true;
        std::fprintf(stderr, "probe: call_func timed out after 5 s; thread restored\n");
    } else {
        s->skip_continue = true;
    }
    CloseHandle(thread);
    return result;
}

extern "C" int call_func(probe_context *c, const char *symbol, uint64_t *ret, int nargs, ...) {
    auto *st = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    if (!st || !st->session || !st->tid) return 0;
    uint64_t fn = resolve_symbol(st->session, symbol);
    if (!fn) return 0;
    uint64_t args[8] = {0};
    if (nargs < 0 || nargs > 8) return 0;
    va_list ap; va_start(ap, nargs);
    for (int i = 0; i < nargs; ++i) args[i] = va_arg(ap, uint64_t);
    va_end(ap);
    return call_in_target(st->session, st, fn, ret, nargs, args);
}

extern "C" probe_session *get_session(probe_context *c) {
    auto *state = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    return state ? state->session : nullptr;
}

// Raw stack snapshot at the hit: return addresses only (StackWalk64 over the stopped
// target with the hit's register image). No symbol lookup here -- deferred to report.
static void capture_stack(probe_session *s, probe_context *c, std::vector<uint64_t> &frames) {
    frames.clear();
    if (!s->sym_ready) { frames.push_back(c->regs.pc); return; }
    CONTEXT w{}; w.ContextFlags = CONTEXT_FULL;
    to_context(*c, w);
#if defined(_WIN64)
    w.Rip = c->regs.pc; w.Rsp = c->regs.rsp; w.Rbp = c->regs.rbp;
#else
    w.Eip = (DWORD)c->regs.pc; w.Esp = (DWORD)c->regs.rsp; w.Ebp = (DWORD)c->regs.rbp;
#endif
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, c->tid);
    if (!uhh_sym::walk_stack(s->pi.hProcess, thread, w, c->regs.pc, c->regs.rsp, c->regs.rbp, frames,
                             PROBE_STACK_MAX_FRAMES) || frames.empty())
        frames.assign(1, c->regs.pc);
#if !defined(_WIN64)
    // x86 at a function's first instructions: EBP still frames the CALLER, so a walk can
    // skip the immediate caller. If [esp] is a genuine return address (the bytes before
    // it encode a call) and is not already frame 1, insert it -- same rule as the agent.
    uint32_t top = 0; size_t got = 0; unsigned char pre[8] = {0};
    if (remote_read(s->pi.hProcess, c->regs.rsp, &top, 4, &got) && got == 4 && top > 8 &&
        remote_read(s->pi.hProcess, top - 8, pre, 8, &got) && got == 8) {
        const unsigned char *p = pre + 8;
        bool call = p[-5] == 0xE8 ||
                    (p[-2] == 0xFF && ((p[-1] >> 3) & 7) == 2 && ((p[-1] >> 6) == 3 || ((p[-1] >> 6) == 0 && (p[-1] & 7) != 4 && (p[-1] & 7) != 5))) ||
                    (p[-3] == 0xFF && ((p[-2] >> 3) & 7) == 2 && (p[-2] >> 6) == 1) ||
                    (p[-6] == 0xFF && ((p[-5] >> 3) & 7) == 2 && ((p[-5] >> 6) == 2 || (p[-5] & 0xC7) == 5)) ||
                    (p[-7] == 0xFF && ((p[-6] >> 3) & 7) == 2 && (p[-6] >> 6) == 2 && (p[-6] & 7) == 4);
        if (call && (frames.size() < 2 || frames[1] != top)) frames.insert(frames.begin() + 1, top);
        if (frames.size() > PROBE_STACK_MAX_FRAMES) frames.resize(PROBE_STACK_MAX_FRAMES);
    }
#endif
    if (thread) CloseHandle(thread);
}

static std::string symbolize(probe_session *s, uint64_t addr) {
    if (!s->sym_ready) { char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)addr); return buf; }
    return uhh_sym::symbolize(s->pi.hProcess, addr);
}

static void log_common(probe_context *c, bool stack, const char *format, va_list ap) {
    if (!format) return;
    char line[PROBE_AGENT_LOG_TEXT_CAP];                      // the same limit inline uses
    int n = std::vsnprintf(line, sizeof(line), format, ap);
    if (n < 0) return; line[sizeof(line) - 1] = 0;
    if ((size_t)n >= sizeof(line)) {                          // truncated: say so, never silently
        static const char mark[] = "...[truncated]";
        std::memcpy(line + sizeof(line) - sizeof(mark), mark, sizeof(mark));
    }
    auto *state = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    if (!state || !state->session) { std::fprintf(stderr, "probe: %s\n", line); return; }
    LogRecord r; r.text = line; r.tid = c->tid; r.probe = c->site; r.has_stack = stack;
    if (stack) capture_stack(state->session, c, r.frames);
    std::fprintf(stderr, stack ? "probe: %s [+stack %zu frames]\n" : "probe: %s\n", line, r.frames.size());
    std::lock_guard<std::mutex> lock(state->session->log_mu);
    try { state->session->logs.push_back(std::move(r)); }
    catch (...) { ++state->session->controller_dropped; }      // out of memory: counted, not fatal
}

extern "C" void send_log(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format); log_common(c, false, format, ap); va_end(ap);
}

extern "C" void send_log_stack(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format); log_common(c, true, format, ap); va_end(ap);
}
