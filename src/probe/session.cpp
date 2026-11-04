// Public PROBE_BREAKPOINT backend. The debug API binds event consumption to the
// launching thread, so probe_run owns the synchronous event loop through exit.
#define PROBE_PUBLIC_API
#include "win_common.hpp"
#include <cerrno>
#include <cctype>
#include <cstdarg>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

struct Probe {
    std::string location, module;
    uint64_t rva = 0, base = 0, address = 0, hits = 0;
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
    PROCESS_INFORMATION pi{};
    HANDLE stdin_write = nullptr;
    DWORD exit_code = 1;
    uint64_t overrides = 0;
    std::string error;
    bool launched = false, ran = false, exited = false;
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

static bool iequals(const std::string &a, const std::string &b) {
    return a.size() == b.size() && !_stricmp(a.c_str(), b.c_str());
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

static bool arm_probe(probe_session *s, Probe &p, uint64_t base) {
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

static bool arm_module(probe_session *s, const std::string &module, uint64_t base) {
    for (auto &item : s->probes)
        if (!item->active && iequals(item->module, module) && !arm_probe(s, *item, base)) return false;
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
    if ((flags & types) != PROBE_BREAKPOINT || (flags & PROBE_AT_RETURN)) {
        set_error(s, "requested probe type/options are unsupported in this build (breakpoint entry probes only)");
        return 0;
    }
    if (config_len && !config) { set_error(s, "non-empty probe config is null"); return 0; }
    try {
        auto p = std::make_unique<Probe>();
        if (!parse_location(s, location, *p)) return 0;
        p->callback = callback; p->flags = flags;
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
        DWORD wrote{}; char key = '\n';
        if (!WriteFile(s->stdin_write, &key, 1, &wrote, nullptr) || wrote != 1) {
            set_error(s, win_error("deliver gate keystroke")); TerminateProcess(s->pi.hProcess, 3); return 0;
        }
        s->launched = true; return 1;
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
    to_context(context, native); native.Rsp = context.regs.rsp;
    if (!patch(s->pi.hProcess, probe->address, probe->original)) {
        CloseHandle(thread); set_error(s, win_error("restore probed instruction")); return false;
    }
    native.Rip = probe->address; native.EFlags |= 0x100u;
    if (!SetThreadContext(thread, &native)) {
        CloseHandle(thread); set_error(s, win_error("apply callback context")); return false;
    }
    CloseHandle(thread); stepping[event.dwThreadId] = probe; disposition = DBG_CONTINUE; return true;
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
            ok = arm_module(s, name, base);
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT:
            if (event.u.CreateThread.hThread) CloseHandle(event.u.CreateThread.hThread);
            break;
        case EXIT_THREAD_DEBUG_EVENT: {
            auto it = stepping.find(event.dwThreadId);
            if (it != stepping.end()) {
                ok = patch(s->pi.hProcess, it->second->address, 0xcc); stepping.erase(it);
                if (!ok) set_error(s, win_error("re-arm probe after thread exit"));
            }
            break;
        }
        case LOAD_DLL_DEBUG_EVENT: {
            std::string name = module_name_from_handle(event.u.LoadDll.hFile);
            uint64_t base = (uint64_t)(uintptr_t)event.u.LoadDll.lpBaseOfDll;
            ok = arm_module(s, name, base);
            if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
            break;
        }
        case UNLOAD_DLL_DEBUG_EVENT: {
            uint64_t base = (uint64_t)(uintptr_t)event.u.UnloadDll.lpBaseOfDll;
            for (auto &p : s->probes)
                if (p->active && p->base == base) { p->active = false; p->base = p->address = 0; }
            break;
        }
        case EXCEPTION_DEBUG_EVENT:
            ok = handle_exception(s, event, stepping, initial_break, disposition); break;
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
    for (const auto &line : s->logs) {
        std::fputs("{\"kind\":\"probe_log\",\"message\":", out); json_string(out, line); std::fputs("}\n", out);
    }
    uint64_t hits = 0, active = 0;
    for (const auto &p : s->probes) { hits += p->hits; active += p->active; }
    std::fprintf(out, "{\"kind\":\"probe_report\",\"probes\":%llu,\"active\":%llu,"
                 "\"hits\":%llu,\"overrides\":%llu,\"app_exit\":%lu,\"error\":",
                 (unsigned long long)s->probes.size(), (unsigned long long)active,
                 (unsigned long long)hits, (unsigned long long)s->overrides, s->exit_code);
    if (s->error.empty()) std::fputs("null", out); else json_string(out, s->error);
    std::fputs("}\n", out); std::fflush(out);
}

extern "C" void probe_close(probe_session *s) {
    if (!s) return;
    if (s->launched && !s->exited && s->pi.hProcess) {
        for (auto &p : s->probes) if (p->active) patch(s->pi.hProcess, p->address, p->original);
        TerminateProcess(s->pi.hProcess, 3);
    }
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
    case PROBE_REG_R8: return &c->regs.r8; case PROBE_REG_R9: return &c->regs.r9;
    case PROBE_REG_R10: return &c->regs.r10; case PROBE_REG_R11: return &c->regs.r11;
    case PROBE_REG_R12: return &c->regs.r12; case PROBE_REG_R13: return &c->regs.r13;
    case PROBE_REG_R14: return &c->regs.r14; case PROBE_REG_R15: return &c->regs.r15;
    default: return nullptr;
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
    switch (index) {
    case 0: return c->regs.rcx; case 1: return c->regs.rdx;
    case 2: return c->regs.r8; case 3: return c->regs.r9;
    default: {
        if (c->regs.rsp > UINT64_MAX - 8 || index > (UINT64_MAX - c->regs.rsp - 8) / 8) return 0;
        uint64_t value = 0, address = c->regs.rsp + 8 + 8 * index;
        return probe_read(c, address, &value, sizeof(value)) ? value : 0;
    }
    }
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
