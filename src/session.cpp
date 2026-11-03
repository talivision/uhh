// probe_session: external-debugger controller demonstrating deferred activation.
//
//   probe_session <flag_rva> [probe_app args...]
//
// 1. Register a PENDING probe on configparse.dll+<flag_rva> before launching.
// 2. Launch probe_app under DEBUG_ONLY_THIS_PROCESS with a stdin pipe; the gate
//    keystroke is delivered through that pipe.
// 3. configparse.dll is absent at start. On the LOAD_DLL event for it (which
//    fires inside LoadLibraryA, before ParseConfig runs), resolve base+RVA and
//    arm a software breakpoint. Report the pending->active transition.
// 4. The site is `mov [rcx], eax` holding the parsed reads_enabled value (0).
//    At the breakpoint, override EAX 0->1 so the store writes 1, enabling the
//    workload. Exactly one override is expected.
//
// This is the "software breakpoint for the config modifier" demo: attach at
// start, probe fires later when the DLL becomes available. No symbols needed.
#include "win_common.hpp"
#include "detect.hpp"
#include <string>

struct PendingProbe {
    std::string module;      // basename, matched case-insensitively
    uint64_t rva = 0;
    uint64_t address = 0;    // resolved absolute address, 0 while pending
    unsigned char original = 0;
    bool active = false;
};

static bool iequals(const std::string &a, const std::string &b) {
    return a.size() == b.size() && _stricmp(a.c_str(), b.c_str()) == 0;
}

static std::string basename_of(std::string path) {
    size_t p = path.find_last_of("\\/");
    return p == std::string::npos ? path : path.substr(p + 1);
}

// Resolve a loaded module's file name from the debug-event file handle.
static std::string module_name_from_handle(HANDLE file) {
    if (!file) return {};
    char path[MAX_PATH]; DWORD n = GetFinalPathNameByHandleA(file, path, MAX_PATH, FILE_NAME_NORMALIZED);
    if (!n || n >= MAX_PATH) return {};
    return basename_of(path);
}

static bool patch(HANDLE process, uint64_t address, unsigned char byte) {
    DWORD old{}, ignored{}; SIZE_T done{};
    if (!VirtualProtectEx(process, (void *)(uintptr_t)address, 1, PAGE_EXECUTE_READWRITE, &old)) return false;
    BOOL ok = WriteProcessMemory(process, (void *)(uintptr_t)address, &byte, 1, &done);
    BOOL flush = FlushInstructionCache(process, (void *)(uintptr_t)address, 1);
    BOOL restore = VirtualProtectEx(process, (void *)(uintptr_t)address, 1, old, &ignored);
    return ok && done == 1 && flush && restore;
}

int main(int argc, char **argv) {
    PROCESS_INFORMATION pi{}; HANDLE thread{}; HANDLE stdin_wr{};
    try {
        require(argc >= 3, "usage: probe_session <flag_rva> <read_rva> [probe_app args...]");
        PendingProbe flag_probe;
        flag_probe.module = "configparse.dll";
        flag_probe.rva = _strtoui64(argv[1], nullptr, 0);
        uint32_t read_rva = (uint32_t)_strtoui64(argv[2], nullptr, 0);

        std::string exe = exe_directory() + "probe_app.exe";
        std::string command = "\"" + exe + "\"";
        for (int i = 3; i < argc; ++i) {
            require(std::strpbrk(argv[i], "\"") == nullptr, "quote in argument");
            command += " "; command += argv[i];
        }

        // stdin pipe to drive the gate keystroke; child inherits the read end.
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE}; HANDLE stdin_rd{};
        require(!!CreatePipe(&stdin_rd, &stdin_wr, &sa, 0), "stdin pipe");
        require(!!SetHandleInformation(stdin_wr, HANDLE_FLAG_INHERIT, 0), "stdin pipe inherit");
        STARTUPINFOA si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = stdin_rd;
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        require(!!CreateProcessA(exe.c_str(), command.data(), nullptr, nullptr, TRUE,
                                 DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi), "debug launch");
        CloseHandle(stdin_rd);
        // Deliver the gate keystroke now; the child buffers it until wait_for_key.
        DWORD wrote = 0; char key = '\n';
        require(!!WriteFile(stdin_wr, &key, 1, &wrote, nullptr) && wrote == 1, "write keystroke");

        std::fprintf(stderr, "probe: pending %s+0x%llx\n",
                     flag_probe.module.c_str(), (unsigned long long)flag_probe.rva);

        DWORD owner = 0, exit_code = 1; int stepping = -1; uint64_t overrides = 0;
        bool initial_break = false;
        uint64_t app_base = 0; bool read_site_checked = false, read_site_hooked = false;
        DEBUG_EVENT e{};
        for (;;) {
            require(!!WaitForDebugEvent(&e, INFINITE), "wait debug event");
            DWORD disposition = DBG_CONTINUE;
            switch (e.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                owner = e.dwThreadId;
                thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, owner);
                require(thread != nullptr, "open main thread");
                app_base = (uint64_t)(uintptr_t)e.u.CreateProcessInfo.lpBaseOfImage;
                if (e.u.CreateProcessInfo.hFile) CloseHandle(e.u.CreateProcessInfo.hFile);
                break;
            case OUTPUT_DEBUG_STRING_EVENT: {
                // App signals it has installed any pre-existing hook. Inspect the
                // read site now, against the clean on-disk image, as a real
                // attach to an already-hooked process would.
                char msg[32]{}; SIZE_T got{};
                if (!e.u.DebugString.fUnicode && e.u.DebugString.nDebugStringLength <= sizeof(msg) &&
                    ReadProcessMemory(pi.hProcess, e.u.DebugString.lpDebugStringData, msg, sizeof(msg) - 1, &got) &&
                    !std::strcmp(msg, "PROBE_APP_READY") && app_base && !read_site_checked) {
                    read_site_checked = compare_to_disk(&remote_ops, pi.hProcess, app_base + read_rva,
                                                        exe, read_rva, "ReadSite", read_site_hooked);
                }
                break;
            }
            case LOAD_DLL_DEBUG_EVENT: {
                std::string name = module_name_from_handle(e.u.LoadDll.hFile);
                if (e.u.LoadDll.hFile) CloseHandle(e.u.LoadDll.hFile);
                if (!flag_probe.active && iequals(name, flag_probe.module)) {
                    uint64_t base = (uint64_t)(uintptr_t)e.u.LoadDll.lpBaseOfDll;
                    uint64_t addr = base + flag_probe.rva;
                    size_t got{};
                    require(remote_read(pi.hProcess, addr, &flag_probe.original, 1, &got) && got == 1,
                            "read original byte");
                    require(flag_probe.original != 0xcc, "site already has INT3");
                    require(patch(pi.hProcess, addr, 0xcc), "arm software breakpoint");
                    flag_probe.address = addr; flag_probe.active = true;
                    std::fprintf(stderr,
                        "probe: active %s+0x%llx -> base=0x%llx addr=0x%llx (was 0x%02x)\n",
                        flag_probe.module.c_str(), (unsigned long long)flag_probe.rva,
                        (unsigned long long)base, (unsigned long long)addr, flag_probe.original);
                }
                break;
            }
            case EXCEPTION_DEBUG_EVENT: {
                auto &ex = e.u.Exception.ExceptionRecord; DWORD code = ex.ExceptionCode;
                disposition = DBG_EXCEPTION_NOT_HANDLED;
                if (code == EXCEPTION_BREAKPOINT && !initial_break) {
                    initial_break = true; disposition = DBG_CONTINUE; break;
                }
                CONTEXT c{}; c.ContextFlags = CONTEXT_ALL;
                if (code == EXCEPTION_SINGLE_STEP && stepping >= 0) {
                    require(!!GetThreadContext(thread, &c), "get step context");
                    require(patch(pi.hProcess, flag_probe.address, 0xcc), "re-arm breakpoint");
                    stepping = -1; c.EFlags &= ~0x100u;
                    require(!!SetThreadContext(thread, &c), "resume after step");
                    disposition = DBG_CONTINUE;
                } else if (code == EXCEPTION_BREAKPOINT && flag_probe.active &&
                           (uint64_t)(uintptr_t)ex.ExceptionAddress == flag_probe.address) {
                    require(!!GetThreadContext(thread, &c), "get breakpoint context");
                    // At `mov [rcx], eax`: EAX holds the parsed reads_enabled value.
                    uint32_t parsed = (uint32_t)c.Rax;
                    require(parsed == 0, "expected parsed flag 0 before override");
                    c.Rax = (c.Rax & ~0xffffffffull) | 1u;  // EAX = 1
                    ++overrides;
                    std::fprintf(stderr, "probe: flag override %u -> 1 at 0x%llx\n",
                                 parsed, (unsigned long long)flag_probe.address);
                    require(patch(pi.hProcess, flag_probe.address, flag_probe.original), "restore instruction");
                    c.Rip = flag_probe.address; stepping = 0; c.EFlags |= 0x100u;
                    require(!!SetThreadContext(thread, &c), "apply override");
                    disposition = DBG_CONTINUE;
                }
                break;
            }
            case EXIT_PROCESS_DEBUG_EVENT:
                exit_code = e.u.ExitProcess.dwExitCode;
                require(!!ContinueDebugEvent(e.dwProcessId, e.dwThreadId, DBG_CONTINUE), "continue exit");
                std::printf("{\"kind\":\"session\",\"flag_probe_active\":%s,\"overrides\":%llu,"
                            "\"read_site_checked\":%s,\"read_site_hooked\":%s,\"app_exit\":%lu}\n",
                            flag_probe.active ? "true" : "false", (unsigned long long)overrides,
                            read_site_checked ? "true" : "false",
                            read_site_hooked ? "true" : "false", exit_code);
                if (thread) CloseHandle(thread);
                CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(stdin_wr);
                require(flag_probe.active, "configparse.dll never loaded; probe stayed pending");
                require(overrides == 1, "expected exactly one flag override");
                return exit_code ? 1 : 0;
            }
            require(!!ContinueDebugEvent(e.dwProcessId, e.dwThreadId, disposition), "continue debug event");
        }
    } catch (const std::exception &ex) {
        std::fprintf(stderr, "session: %s\n", ex.what());
        if (pi.hProcess) { TerminateProcess(pi.hProcess, 3); CloseHandle(pi.hProcess); }
        if (pi.hThread) CloseHandle(pi.hThread);
        if (thread) CloseHandle(thread);
        if (stdin_wr) CloseHandle(stdin_wr);
        return 1;
    }
}
