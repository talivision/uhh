// mindbg -- the floor for an EXTERNAL hardware execute probe: the smallest debugger that can
// count hits of hitcost_target.exe!hit_site through a debug register.
//
//   mindbg --rva <hit_site RVA> [--full] -- hitcost_target.exe [args]
//
// Per hit: WaitForDebugEvent -> GetThreadContext (CONTEXT_CONTROL, or CONTEXT_ALL with --full,
// as UHH reads it) -> EFlags |= RF -> SetThreadContext -> ContinueDebugEvent. No callback, no
// bookkeeping: what UHH's hw path costs on top of this is UHH's.
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>

int main(int argc, char **argv) {
    uint64_t rva = 0; bool full = false; int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--rva") && i + 1 < argc) rva = std::strtoull(argv[++i], nullptr, 0);
        else if (!std::strcmp(argv[i], "--full")) full = true;
    }
    if (!rva || i + 1 >= argc) { std::fprintf(stderr, "usage: mindbg --rva R [--full] -- target [args]\n"); return 2; }
    std::string cmd;
    for (int k = i + 1; k < argc; ++k) { cmd += '"'; cmd += argv[k]; cmd += "\" "; }
    STARTUPINFOA si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE, DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi))
        return 1;
    uint64_t addr = 0; unsigned long long hits = 0;
    std::unordered_map<DWORD, HANDLE> threads;
    auto arm = [&](HANDLE t) {
        CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        c.Dr0 = (decltype(c.Dr0))addr; c.Dr7 = 1;
        SetThreadContext(t, &c);
    };
    DEBUG_EVENT ev{}; bool done = false;
    while (!done && WaitForDebugEvent(&ev, INFINITE)) {
        DWORD cont = DBG_CONTINUE;
        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            addr = (uint64_t)(uintptr_t)ev.u.CreateProcessInfo.lpBaseOfImage + rva;
            threads[ev.dwThreadId] = ev.u.CreateProcessInfo.hThread;
            arm(ev.u.CreateProcessInfo.hThread);
            if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            threads[ev.dwThreadId] = ev.u.CreateThread.hThread;
            arm(ev.u.CreateThread.hThread);
            break;
        case EXIT_THREAD_DEBUG_EVENT: threads.erase(ev.dwThreadId); break;
        case EXIT_PROCESS_DEBUG_EVENT: done = true; break;
        case LOAD_DLL_DEBUG_EVENT: if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile); break;
        case EXCEPTION_DEBUG_EVENT: {
            const DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            if (code == EXCEPTION_SINGLE_STEP || code == 0x4000001E /* WOW64 single step */) {
                ++hits;
                HANDLE t = threads[ev.dwThreadId];
                CONTEXT c{}; c.ContextFlags = full ? CONTEXT_ALL : CONTEXT_CONTROL;
                if (t && GetThreadContext(t, &c)) { c.EFlags |= 0x10000; SetThreadContext(t, &c); }
            } else if (code != EXCEPTION_BREAKPOINT && code != 0x4000001F) {
                cont = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }
        default: break;
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
    }
    std::printf("{\"kind\":\"mindbg\",\"hits\":%llu}\n", hits);
    return 0;
}
