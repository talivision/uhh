// Module names, locations ("module!Export+0xOFF"), export / symbol resolution.
#include "session_internal.hpp"

namespace uhh_session {

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

// The image mapped at base, from the mapping itself: for a LOAD_DLL / CREATE_PROCESS event
// that came without a file handle. An ATTACH's synthesized events open each module's file
// in the TARGET's security context, and a sandboxed process (a Chromium/Edge renderer: a
// restricted token at untrusted integrity) cannot open them -- every DLL but ntdll then
// arrives with hFile == NULL, and probes on kernel32/KernelBase/... stayed pending forever
// (the inline agent: "target module owning LoadLibraryW was not observed"). DOS path when a
// drive letter maps the device, else the \Device\... path (its basename is still right).
static std::wstring mapped_image_path(HANDLE process, uint64_t base) {
    wchar_t dev[1024];
    DWORD n = GetMappedFileNameW(process, reinterpret_cast<LPVOID>(static_cast<uintptr_t>(base)), dev, 1024);
    if (!n || n >= 1024) return {};
    std::wstring path(dev, n);
    wchar_t drives[512];
    DWORD dn = GetLogicalDriveStringsW(512, drives);
    for (const wchar_t *d = drives; dn && dn < 512 && *d; d += std::wcslen(d) + 1) {
        wchar_t letter[3] = {d[0], L':', 0}, target[MAX_PATH];
        if (!QueryDosDeviceW(letter, target, MAX_PATH)) continue;
        size_t tl = std::wcslen(target);
        if (path.size() > tl && !_wcsnicmp(path.c_str(), target, tl) && path[tl] == L'\\')
            return std::wstring(letter) + path.substr(tl);
    }
    return path;
}

static std::string narrow_path(const std::wstring &w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string r(n > 0 ? (size_t)n : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_ACP, 0, w.c_str(), (int)w.size(), r.data(), n, nullptr, nullptr);
    return r;
}

// An event's module name: from its file handle, else from the mapping (see mapped_image_path).
std::string event_module_name(HANDLE process, HANDLE file, uint64_t base) {
    std::string name = module_name_from_handle(file);
    if (name.empty() && process) {
        name = basename_of(narrow_path(mapped_image_path(process, base)));
        if (trace_enabled()) std::fprintf(stderr, "  module without a file handle @0x%llx: name from the mapping '%s'\n",
                                          (unsigned long long)base, name.c_str());
    }
    return name;
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

// SizeOfImage of the image mapped at base in the target (0 if unreadable).
uint32_t remote_image_size(HANDLE process, uint64_t base) {
    size_t got = 0;
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{};
    if (remote_read(process, base, &dos, sizeof(dos), &got) && got == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
        remote_read(process, base + (uint32_t)dos.e_lfanew, &nt, sizeof(nt), &got) && got == sizeof(nt) &&
        nt.Signature == IMAGE_NT_SIGNATURE)
        return nt.OptionalHeader.SizeOfImage;
    return 0;
}
// Register a mapped image with dbghelp (deferred: no symbol I/O until the writer sees
// a stack frame). Keeps working after the target exits: it reads files.
void sym_register(probe_session *s, HANDLE file, uint64_t base) {
    const uint32_t size = remote_image_size(s->pi.hProcess, base);
    if (size) s->module_sizes[base] = size;
    std::string path = module_path_from_handle(file);
    std::wstring mapped;
    if (path.empty()) {                       // no file handle (sandboxed attach): the mapping's path
        mapped = mapped_image_path(s->pi.hProcess, base);
        if (mapped.size() < 3 || mapped[1] != L':') return;
        path = narrow_path(mapped);
    }
    if (path.empty()) return;
    s->module_paths[basename_of(path)] = path;
    if (!s->sym_ready) return;
    // Pass the real SizeOfImage: with deferred loads dbghelp does not read the image yet,
    // so a size of 0 registers only the base address and no frame inside it resolves.
    // A module that unloaded from this range may still be registered for log records
    // captured before its unload (see sym_unload): those are written first.
    wait_sym_unloads(s, base, size ? size : 1);
    // dbghelp gets the exact (wide) path, so non-ASCII directories work.
    std::wstring wpath = mapped;
    if (wpath.empty()) {
        wchar_t w[1024];
        DWORD n = GetFinalPathNameByHandleW(file, w, 1024, FILE_NAME_NORMALIZED);
        if (n && n < 1024) {
            wpath.assign(w, n);
            if (wpath.size() > 4 && wpath.compare(0, 4, L"\\\\?\\") == 0) wpath = wpath.substr(4);
        }
    }
    if (!wpath.empty()) uhh_sym::register_module(s->pi.hProcess, wpath, base, size);
}

std::string module_name_from_module(HMODULE module) {
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(module, path, MAX_PATH);
    return n && n < MAX_PATH ? basename_of(path) : std::string{};
}

bool iequals(const std::string &a, const std::string &b) {
    return a.size() == b.size() && !_stricmp(a.c_str(), b.c_str());
}

static bool parse_hex(const char *number, uint64_t &out) {
    if (!number || !*number) return false;
    for (const char *d = number; *d; ++d) if (!std::isxdigit((unsigned char)*d)) return false;
    errno = 0; char *end = nullptr;
    unsigned long long v = std::strtoull(number, &end, 16);
    if (errno == ERANGE || !end || *end) return false;
    out = (uint64_t)v; return true;
}

// THE module grammar, shared by probe locations (every backend, launch/attach/runtime adds,
// uhh_trace -p) and call_func (breakpoint/hw here; inline in agent.cpp agent_module, whose
// GetModuleHandleA reads names the same way): the module is matched by its FILE NAME, case-
// insensitively (a directory part is ignored), and a name without an extension means
// "<name>.dll", as LoadLibrary/GetModuleHandle read it: "kernel32" == "kernel32.dll", and
// "probe_app" names probe_app.dll -- never probe_app.exe (an EXE is named with its ".exe").
// A trailing dot means "no extension" ("foo." == the file "foo"). Empty = no module named.
static std::string module_of_location(const std::string &text, bool *bare = nullptr) {
    std::string m = basename_of(text);
    if (bare) *bare = false;
    if (m.empty() || m == ".") return {};
    if (m.back() == '.') { m.pop_back(); return m; }
    if (m.find('.') != std::string::npos) return m;
    if (bare) *bare = true;
    return m + ".dll";
}

// "module+0xRVA" or "module!Export[+0xOFF]" (module: see module_of_location).
bool parse_location(probe_session *s, const char *text, Probe &p) {
    if (!text || !*text) { set_error(s, "empty probe location"); return false; }
    p.location = text;
    size_t bang = p.location.find('!');
    if (bang != std::string::npos) {
        p.module = module_of_location(p.location.substr(0, bang), &p.bare_module);
        if (p.module.empty()) { set_error(s, "symbol location has an empty module"); return false; }
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
    p.module = module_of_location(p.location.substr(0, plus), &p.bare_module);
    if (p.module.empty()) { set_error(s, "location has an empty module"); return false; }
    if (!parse_hex(p.location.c_str() + plus + 3, p.rva)) { set_error(s, "location has an invalid RVA"); return false; }
    return true;
}

// Resolve an export by name from the TARGET's image (read remotely; works before the
// module has run any code). A forwarder is returned separately from a code RVA.
bool resolve_export(probe_session *s, uint64_t base, const std::string &name, uint64_t &rva, std::string *forward) {
    if (forward) forward->clear();
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
    auto result = [&](uint32_t f) {
        if (!f) return false;
        if (in_dir(f, 1)) {
            const char *str = reinterpret_cast<const char *>(blob.data() + (f - dir.VirtualAddress));
            const size_t lim = dir.Size - (f - dir.VirtualAddress);
            const size_t n = strnlen(str, lim);
            if (!n || n == lim) return false;
            if (forward) forward->assign(str, n);
            else set_error(s, "export '" + name + "' is forwarded; probe the forward target");
            return false;
        }
        rva = f; return true;
    };
    if (!name.empty() && name[0] == '#') {
        char *end = nullptr;
        const unsigned long ordinal = std::strtoul(name.c_str() + 1, &end, 10);
        if (end == name.c_str() + 1 || *end || ordinal < ex->Base || ordinal - ex->Base >= funcs.size()) return false;
        return result(funcs[ordinal - ex->Base]);
    }
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
        return result(f);
    }
    set_error(s, "export '" + name + "' not found"); return false;
}

// Follow the TARGET's forwarder strings and export tables. An absent destination remains
// a named pending probe, so its RVA is read from that image when it actually loads.
bool remote_export_owner(probe_session *s, std::string &module, std::string &name, uint64_t &base, uint64_t &rva) {
    for (unsigned depth = 0; depth < 32; ++depth) {
        base = 0;
        for (const auto &kv : s->module_bases) if (iequals(kv.first, module)) { base = kv.second; break; }
        if (!base) return true;
        std::string forward;
        if (resolve_export(s, base, name, rva, &forward)) return true;
        if (forward.empty()) return false;
        const size_t dot = forward.rfind('.');
        if (dot == std::string::npos || !dot || dot + 1 == forward.size()) return false;
        std::string next = forward.substr(0, dot);
        if (next.find('.') == std::string::npos) next += ".dll";
        // API contracts are aliases, not mapped images. Use the OS's contract mapping
        // only, then read the named export from the destination TARGET image.
        if (next.rfind("api-", 0) == 0 || next.rfind("ext-", 0) == 0) {
            HMODULE alias = LoadLibraryExA(next.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (!alias) return false;
            next = module_name_from_module(alias);
            FreeLibrary(alias);
            if (next.empty()) return false;
        }
        module = next; name = forward.substr(dot + 1);
    }
    return false; // cycles / implausibly deep chains
}

// ---- call_func: run a target function on the stopped thread -------------------------
// The debugger way (like gdb's `call`): save the thread's context, build an ABI-correct
// call frame below its stack whose return address is a library INT3, let it run, catch
// the INT3, read the return register and restore the context exactly. The original
// debug event is continued to start the call; the trap event on the same thread takes
// its place, so the caller's handler finishes and continues as if nothing happened.
uint64_t resolve_symbol(probe_session *s, const char *symbol) {
    if (!symbol || !*symbol) return 0;
    if (symbol[0] == '0' && (symbol[1] == 'x' || symbol[1] == 'X')) return std::strtoull(symbol + 2, nullptr, 16);
    Probe tmp; std::string saved = s->error;
    s->error.clear();
    uint64_t base = 0, rva = 0, result = 0;
    if (parse_location(s, symbol, tmp)) {
        if (!tmp.export_name.empty()) {
            if (remote_export_owner(s, tmp.module, tmp.export_name, base, rva) && base &&
                rva <= UINT64_MAX - base && tmp.sym_offset <= UINT64_MAX - base - rva)
                result = base + rva + tmp.sym_offset;
        } else {
            for (const auto &kv : s->module_bases) if (iequals(kv.first, tmp.module) && tmp.rva <= UINT64_MAX - kv.second)
                result = kv.second + tmp.rva;
        }
    }
    s->error = saved; return result;
}

} // namespace uhh_session
