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

struct Probe {
    std::string location, module, callback_export;
    uint64_t rva = 0, base = 0, address = 0, hits = 0;
    uint32_t agent_index = UINT32_MAX;
    unsigned char original = 0;
    probe_callback callback = nullptr;
    uint32_t flags = 0;
    std::vector<unsigned char> config;
    bool active = false;
};

struct CallbackState {
    probe_session *session;
    Probe *probe;
};

struct probe_session {
    std::vector<std::unique_ptr<Probe>> probes;
    std::vector<std::string> logs;
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
    bool launched = false, ran = false, exited = false, gate_sent = false;
};

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

static bool callback_export_name(probe_callback callback, std::string &name) {
    HMODULE module{};
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(callback), &module)) return false;
    auto base = reinterpret_cast<const unsigned char *>(module);
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        return false;
    auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return false;
    auto exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(base + dir.VirtualAddress);
    auto functions = reinterpret_cast<const DWORD *>(base + exports->AddressOfFunctions);
    auto names = reinterpret_cast<const DWORD *>(base + exports->AddressOfNames);
    auto ordinals = reinterpret_cast<const WORD *>(base + exports->AddressOfNameOrdinals);
    uint64_t callback_rva = reinterpret_cast<const unsigned char *>(callback) - base;
    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        WORD ordinal = ordinals[i];
        if (ordinal < exports->NumberOfFunctions && functions[ordinal] == callback_rva) {
            name = reinterpret_cast<const char *>(base + names[i]); return true;
        }
    }
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

static bool parse_location(probe_session *s, const char *text, Probe &p) {
    if (!text || !*text) { set_error(s, "empty probe location"); return false; }
    p.location = text;
    if (p.location.find('!') != std::string::npos) {
        set_error(s, "symbol locations are not yet supported in this build"); return false;
    }
    size_t plus = p.location.rfind('+');
    if (!plus || plus == std::string::npos || plus + 3 > p.location.size() ||
        p.location[plus + 1] != '0' || (p.location[plus + 2] != 'x' && p.location[plus + 2] != 'X')) {
        set_error(s, "location must be module+0xRVA"); return false;
    }
    p.module = basename_of(p.location.substr(0, plus));
    const char *number = p.location.c_str() + plus + 3;
    if (!*number) { set_error(s, "location has an empty RVA"); return false; }
    for (const char *digit = number; *digit; ++digit)
        if (!std::isxdigit((unsigned char)*digit)) {
            set_error(s, "location has an invalid RVA"); return false;
        }
    errno = 0; char *end = nullptr;
    unsigned long long value = std::strtoull(number, &end, 16);
    if (errno == ERANGE || !end || *end) { set_error(s, "location has an invalid RVA"); return false; }
    p.rva = (uint64_t)value;
    return true;
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

static bool arm_breakpoint(probe_session *s, Probe &p, uint64_t base) {
    if (p.rva > UINT64_MAX - base) { set_error(s, "probe address overflow"); return false; }
    uint64_t address = base + p.rva; size_t got{};
    if (!remote_read(s->pi.hProcess, address, &p.original, 1, &got) || got != 1) {
        set_error(s, win_error("read original probe byte")); return false;
    }
    if (p.original == 0xcc) {
        set_error(s, "pre-hooked INT3 sites are unsupported by this breakpoint backend"); return false;
    }
    if (!patch(s->pi.hProcess, address, 0xcc)) {
        set_error(s, win_error("arm software breakpoint")); return false;
    }
    p.base = base; p.address = address; p.active = true;
    std::fprintf(stderr, "probe: active %s -> base=0x%llx addr=0x%llx (was 0x%02x)\n",
                 p.location.c_str(), (unsigned long long)base,
                 (unsigned long long)address, p.original);
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

static bool arm_module(probe_session *s, const std::string &module, uint64_t base) {
    for (auto &item : s->probes) {
        if (item->active || item->address || !iequals(item->module, module)) continue;
        bool ok = item->flags & PROBE_BREAKPOINT ? arm_breakpoint(s, *item, base)
                                                 : resolve_inline(s, *item, base);
        if (!ok) return false;
    }
    return true;
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

extern "C" probe_session *probe_session_create(void) {
    try { return new probe_session; }
    catch (...) { std::fprintf(stderr, "probe: error: session allocation failed\n"); return nullptr; }
}

extern "C" int probe_add_cfg(probe_session *s, const char *location, probe_callback callback,
                               uint32_t flags, const void *config, size_t config_len) {
    if (!s) return 0;
    if (s->launched) { set_error(s, "probes must be added before launch"); return 0; }
    if (!callback) { set_error(s, "probe callback is null"); return 0; }
    constexpr uint32_t types = PROBE_BREAKPOINT | PROBE_INLINE | PROBE_HW;
    constexpr uint32_t known = types | PROBE_AT_RETURN | PROBE_ALLOW_PREHOOKED | PROBE_FALLBACK_HW;
    if (flags & ~known) { set_error(s, "unknown probe flags"); return 0; }
    uint32_t type = flags & types;
    if ((type != PROBE_BREAKPOINT && type != PROBE_INLINE) || (flags & PROBE_AT_RETURN) ||
        (flags & (PROBE_ALLOW_PREHOOKED | PROBE_FALLBACK_HW))) {
        set_error(s, "requested probe type/options are unsupported in this build");
        return 0;
    }
    if (config_len && !config) { set_error(s, "non-empty probe config is null"); return 0; }
    if (type == PROBE_INLINE && config_len > PROBE_AGENT_CONFIG_CAP) {
        set_error(s, "inline probe config exceeds the agent limit"); return 0;
    }
    try {
        auto p = std::make_unique<Probe>();
        if (!parse_location(s, location, *p)) return 0;
        p->callback = callback; p->flags = flags;
        if (type == PROBE_INLINE && !callback_export_name(callback, p->callback_export)) {
            set_error(s, "inline callback is not a named export"); return 0;
        }
        if (p->callback_export.size() >= PROBE_AGENT_EXPORT_CAP) {
            set_error(s, "inline callback export name is too long"); return 0;
        }
        if (config_len) {
            auto first = static_cast<const unsigned char *>(config);
            p->config.assign(first, first + config_len);
        }
        std::fprintf(stderr, "probe: pending %s\n", p->location.c_str());
        s->probes.push_back(std::move(p)); return 1;
    } catch (const std::exception &e) { set_error(s, e.what()); return 0; }
}

extern "C" int probe_add(probe_session *s, const char *location, probe_callback callback, uint32_t flags) {
    return probe_add_cfg(s, location, callback, flags, nullptr, 0);
}

static bool create_agent_channel(probe_session *s) {
    uint32_t count = 0;
    for (auto &p : s->probes) if (p->flags & PROBE_INLINE) p->agent_index = count++;
    if (!count) return true;
    if (count > PROBE_AGENT_MAX_PROBES) { set_error(s, "too many inline probes"); return false; }
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
    for (const auto &p : s->probes) if (p->flags & PROBE_INLINE) {
        auto &request = s->shared->requests[p->agent_index]; request.flags = p->flags;
        request.config_len = (uint32_t)p->config.size();
        std::memcpy(request.callback, p->callback_export.c_str(), p->callback_export.size() + 1);
        if (!p->config.empty()) std::memcpy(request.config, p->config.data(), p->config.size());
    }
    s->agent_path = sibling_agent_path();
    s->local_agent = LoadLibraryW(s->agent_path.c_str());
    if (!s->local_agent || !GetProcAddress(s->local_agent, "probe_agent_init")) {
        set_error(s, win_error("map probe_api_agent.dll exports")); return false;
    }
    return true;
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
        if (!create_agent_channel(s) || (!has_inline(s) && !release_gate(s))) {
            TerminateProcess(s->pi.hProcess, 3); return 0;
        }
        return 1;
    } catch (const std::exception &e) { set_error(s, e.what()); return 0; }
}

static bool handle_exception(probe_session *s, const DEBUG_EVENT &event,
                             std::unordered_map<DWORD, Probe *> &stepping,
                             bool &initial_break, DWORD &disposition) {
    auto &ex = event.u.Exception.ExceptionRecord; DWORD code = ex.ExceptionCode;
    disposition = DBG_EXCEPTION_NOT_HANDLED;
    if (code == EXCEPTION_BREAKPOINT && !initial_break) {
        initial_break = true; disposition = DBG_CONTINUE; return true;
    }
    auto step = stepping.find(event.dwThreadId);
    uint64_t address = (uint64_t)(uintptr_t)ex.ExceptionAddress;
    Probe *probe = code == EXCEPTION_BREAKPOINT ? probe_at(s, address) : nullptr;
    if ((code != EXCEPTION_SINGLE_STEP || step == stepping.end()) && !probe) return true;
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
    if (!thread) { set_error(s, win_error("open event thread")); return false; }
    CONTEXT native{}; native.ContextFlags = CONTEXT_ALL;
    if (code == EXCEPTION_SINGLE_STEP && step != stepping.end()) {
        bool ok = !!GetThreadContext(thread, &native);
        if (ok) ok = patch(s->pi.hProcess, step->second->address, 0xcc);
        native.EFlags &= ~0x100u;
        if (ok) ok = !!SetThreadContext(thread, &native);
        CloseHandle(thread);
        if (!ok) { set_error(s, win_error("complete breakpoint single-step")); return false; }
        stepping.erase(step); disposition = DBG_CONTINUE; return true;
    }
    if (!GetThreadContext(thread, &native)) {
        CloseHandle(thread); set_error(s, win_error("get breakpoint context")); return false;
    }
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
    if (!patch(s->pi.hProcess, probe->address, probe->original)) {
        CloseHandle(thread); set_error(s, win_error("restore probed instruction")); return false;
    }
#if defined(_WIN64)
    native.Rip = probe->address;
#else
    native.Eip = (DWORD)probe->address;
#endif
    native.EFlags |= 0x100u;
    if (!SetThreadContext(thread, &native)) {
        CloseHandle(thread); set_error(s, win_error("apply callback context")); return false;
    }
    CloseHandle(thread); stepping[event.dwThreadId] = probe; disposition = DBG_CONTINUE; return true;
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
    for (auto &p : s->probes) if ((p->flags & PROBE_INLINE) && p->address) {
        LONG status = s->shared->requests[p->agent_index].status;
        if (status != PROBE_AGENT_INSTALLED) {
            set_error(s, "inline agent failed to install " + p->location +
                         " (status=" + std::to_string(status) + ")");
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
        return accept_agent_install(s);
    }
    return true;
}

extern "C" int probe_run(probe_session *s) {
    if (!s || !s->launched) { if (s) set_error(s, "session is not launched"); return 0; }
    if (s->ran) { set_error(s, "session already ran"); return 0; }
    s->ran = true; bool initial_break = false; std::unordered_map<DWORD, Probe *> stepping;
    DEBUG_EVENT event{};
    while (!s->exited) {
        if (!WaitForDebugEvent(&event, INFINITE)) { set_error(s, win_error("wait for debug event")); break; }
        DWORD disposition = DBG_CONTINUE; bool ok = true;
        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            std::string name = module_name_from_handle(event.u.CreateProcessInfo.hFile);
            uint64_t base = (uint64_t)(uintptr_t)event.u.CreateProcessInfo.lpBaseOfImage;
            if (!name.empty()) s->module_bases[name] = base;
            ok = arm_module(s, name, base);
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT:
            if (event.u.CreateThread.hThread) CloseHandle(event.u.CreateThread.hThread);
            break;
        case EXIT_THREAD_DEBUG_EVENT: {
            if (event.dwThreadId == s->remote_tid) ok = complete_remote_thread(s, event.u.ExitThread.dwExitCode);
            auto it = stepping.find(event.dwThreadId);
            if (ok && it != stepping.end()) {
                ok = patch(s->pi.hProcess, it->second->address, 0xcc); stepping.erase(it);
                if (!ok) set_error(s, win_error("re-arm probe after thread exit"));
            }
            break;
        }
        case LOAD_DLL_DEBUG_EVENT: {
            std::string name = module_name_from_handle(event.u.LoadDll.hFile);
            uint64_t base = (uint64_t)(uintptr_t)event.u.LoadDll.lpBaseOfDll;
            if (!name.empty()) s->module_bases[name] = base;
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

extern "C" void probe_report(probe_session *s, FILE *out) {
    if (!s || !out) return;
    if (s->shared) {
        MemoryBarrier();
        for (auto &p : s->probes) if (p->flags & PROBE_INLINE)
            p->hits = (uint64_t)s->shared->requests[p->agent_index].hits;
        LONG count = s->shared->log_reserve;
        if (count > (LONG)PROBE_AGENT_LOG_CAP) count = PROBE_AGENT_LOG_CAP;
        for (LONG i = 0; i < count; ++i) {
            auto &record = s->shared->logs[i];
            if (!record.committed) continue;
            std::fputs("{\"kind\":\"probe_log\",\"probe\":", out);
            std::fprintf(out, "%u,\"tid\":%u,\"message\":", record.probe, record.tid);
            json_string(out, record.text); std::fputs("}\n", out);
        }
    }
    for (const auto &line : s->logs) {
        std::fputs("{\"kind\":\"probe_log\",\"message\":", out); json_string(out, line); std::fputs("}\n", out);
    }
    for (const auto &p : s->probes) {
        std::fputs("{\"kind\":\"probe\",\"location\":", out); json_string(out, p->location);
        std::fprintf(out, ",\"backend\":\"%s\",\"active\":%s,\"hits\":%llu}\n",
                     p->flags & PROBE_INLINE ? "inline" : "breakpoint",
                     p->active ? "true" : "false", (unsigned long long)p->hits);
    }
    uint64_t hits = 0, active = 0;
    for (const auto &p : s->probes) { hits += p->hits; active += p->active; }
    std::fprintf(out, "{\"kind\":\"probe_report\",\"probes\":%llu,\"active\":%llu,"
                 "\"hits\":%llu,\"overrides\":%llu,\"log_dropped\":%ld,\"app_exit\":%lu,\"error\":",
                 (unsigned long long)s->probes.size(), (unsigned long long)active,
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

extern "C" uint64_t probe_reg(probe_context *c, enum probe_register reg) {
    uint64_t *slot = register_slot(c, reg);
    if (!slot) return 0;
    return reg == PROBE_REG_AX ? (uint32_t)*slot : *slot;
}

extern "C" int probe_set_reg(probe_context *c, enum probe_register reg, uint64_t value) {
    uint64_t *slot = register_slot(c, reg); if (!slot) return 0;
    uint64_t next = reg == PROBE_REG_AX ? (uint32_t)value : value;
    if (*slot != next) {
        *slot = next;
        auto *state = static_cast<CallbackState *>(c->controller);
        if (state && state->session) ++state->session->overrides;
    }
    return 1;
}

extern "C" int probe_read(probe_context *c, uint64_t address, void *buffer, size_t size) {
    if (!c || !c->ops || !c->ops->read || (!buffer && size)) return 0;
    size_t done = 0; return c->ops->read(c->backend, address, buffer, size, &done) && done == size;
}

extern "C" int probe_write(probe_context *c, uint64_t address, const void *buffer, size_t size) {
    if (!c || !c->ops || !c->ops->write || (!buffer && size)) return 0;
    size_t done = 0; return c->ops->write(c->backend, address, buffer, size, &done) && done == size;
}

extern "C" uint64_t probe_arg(probe_context *c, size_t index) {
    if (!c) return 0;
#if defined(_WIN64)
    /* x64 __fastcall: first four args in registers, rest above the shadow space. */
    switch (index) {
    case 0: return c->regs.rcx; case 1: return c->regs.rdx;
    case 2: return c->regs.r8; case 3: return c->regs.r9;
    default: {
        if (c->regs.rsp > UINT64_MAX - 8 || index > (UINT64_MAX - c->regs.rsp - 8) / 8) return 0;
        uint64_t value = 0, address = c->regs.rsp + 8 + 8 * index;
        return probe_read(c, address, &value, sizeof(value)) ? value : 0;
    }
    }
#else
    /* x86 __stdcall: every arg on the stack at [esp+4+4*i], read exactly 4 bytes. */
    if (c->regs.rsp > UINT64_MAX - 4 || index > (UINT64_MAX - c->regs.rsp - 4) / 4) return 0;
    uint32_t value = 0; uint64_t address = c->regs.rsp + 4 + 4 * index;
    return probe_read(c, address, &value, sizeof(value)) ? value : 0;
#endif
}

extern "C" uint64_t probe_retval(probe_context *c) { return c ? c->regs.rax : 0; }

extern "C" void probe_log(probe_context *c, const char *format, ...) {
    if (!format) return;
    char line[2048]; va_list ap; va_start(ap, format);
    int n = std::vsnprintf(line, sizeof(line), format, ap); va_end(ap);
    if (n < 0) return; line[sizeof(line) - 1] = 0;
    std::fprintf(stderr, "probe: %s\n", line);
    auto *state = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    if (state && state->session) state->session->logs.emplace_back(line);
}
