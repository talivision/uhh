// lifecycle_bench -- control-plane timing for the main-vs-branch benchmark (bench/perfab).
//
//   lifecycle_bench --backend b --attach PID [--hold-ms N]     attach, run N ms, detach
//   lifecycle_bench --backend b -- target.exe [args]           launch, run to exit
//
// One probe (hitcost_target.exe!hit_site, empty callback -- the hitcost callback with the
// default config). Prints one {"kind":"lifecycle",...} line with the wall time of each
// control-plane call (QueryPerformanceCounter, ms):
//   attach:  create (session + probe_add), attach (probe_attach returns: probes armed),
//            detach (probe_close on the still-running target: hooks/INT3s/DRs removed),
//            join (the run thread returns after the detach)
//   launch:  create, launch (probe_launch returns), run (probe_run + probe_wait_for_exit:
//            the target ran and exited), close (probe_close after exit), total
// Attach and run happen on a worker thread (the debug object belongs to the attaching
// thread), the detach from the main thread, as examples/trace/uhh_trace.cpp does.
#include "probe_api.h"
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
extern "C" void hitcost_empty(probe_context *);

static double now_ms() {
    static LARGE_INTEGER f = [] { LARGE_INTEGER x; QueryPerformanceFrequency(&x); return x; }();
    LARGE_INTEGER t; QueryPerformanceCounter(&t);
    return (double)t.QuadPart * 1000.0 / (double)f.QuadPart;
}

int main(int argc, char **argv) {
    uint32_t backend = PROBE_INLINE; unsigned long pid = 0, hold_ms = 500; int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            backend = !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : PROBE_INLINE;
        } else if (!std::strcmp(argv[i], "--attach") && i + 1 < argc) pid = std::strtoul(argv[++i], nullptr, 0);
        else if (!std::strcmp(argv[i], "--hold-ms") && i + 1 < argc) hold_ms = std::strtoul(argv[++i], nullptr, 0);
    }
    struct { uint32_t method, pad; } cfg{0, 0};
    double t0 = now_ms();
    probe_session *s = probe_session_create();
    if (!s || !probe_add_symbol_cfg(s, "hitcost_target.exe!hit_site", hitcost_empty, backend, &cfg, sizeof(cfg))) return 1;
    double t1 = now_ms();
    if (pid) {
        HANDLE attached = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        int ok = 0; double ta = 0;
        std::thread runner([&] {
            ok = probe_attach(s, (uint32_t)pid);
            ta = now_ms();
            SetEvent(attached);
            if (ok) probe_run(s);
        });
        WaitForSingleObject(attached, INFINITE);
        CloseHandle(attached);
        if (!ok) { runner.join(); probe_close(s); std::printf("{\"kind\":\"lifecycle\",\"ok\":0}\n"); return 1; }
        Sleep(hold_ms);
        double td0 = now_ms();
        probe_close(s);
        double td1 = now_ms();
        runner.join();
        double tj = now_ms();
        std::printf("{\"kind\":\"lifecycle\",\"mode\":\"attach\",\"ok\":1,\"create_ms\":%.3f,\"attach_ms\":%.3f,"
                    "\"detach_ms\":%.3f,\"join_ms\":%.3f}\n", t1 - t0, ta - t1, td1 - td0, tj - td1);
        return 0;
    }
    if (i + 1 >= argc) return 2;
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    int ok = probe_launch(s, child.data());
    double tl = now_ms();
    ok = ok && probe_run(s) && probe_wait_for_exit(s);
    double tr = now_ms();
    probe_close(s);
    double tc = now_ms();
    std::printf("{\"kind\":\"lifecycle\",\"mode\":\"launch\",\"ok\":%d,\"create_ms\":%.3f,\"launch_ms\":%.3f,"
                "\"run_ms\":%.3f,\"close_ms\":%.3f,\"total_ms\":%.3f}\n", ok, t1 - t0, tl - t1, tr - tl, tc - tr, tc - t0);
    return ok ? 0 : 1;
}
