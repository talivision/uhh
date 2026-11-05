// detours_simple -- Microsoft Detours' "simple" sample (the SleepEx counter) on UHH.
//
//   detours_simple [--backend breakpoint|hw|inline] -- <program> [args...]
//
// Probes KernelBase!SleepEx (every Sleep/SleepEx of the process ends there) and the
// kernel32!Sleep import stub (what the program itself called), launches the program and
// prints the probe report. Every call is one probe_log line ("SleepEx(ms, alertable)" /
// "Sleep(ms)"): count them and sum the milliseconds -- see README.md.
#include "simple_callbacks.h"
#include <cstdio>
#include <cstring>

int main(int argc, char **argv) {
    uint32_t backend = PROBE_BREAKPOINT;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *name = argv[++i];
            backend = !std::strcmp(name, "inline") ? PROBE_INLINE : !std::strcmp(name, "hw") ? PROBE_HW
                    : !std::strcmp(name, "breakpoint") ? PROBE_BREAKPOINT : 0u;
        } else {
            backend = 0;
        }
    }
    if (!backend || i + 1 >= argc) {
        std::fprintf(stderr, "usage: detours_simple [--backend breakpoint|hw|inline] -- <program> [args]\n");
        return 2;
    }
    static const dsimple_config sleepex{DSIMPLE_SLEEPEX}, sleep{DSIMPLE_SLEEP};
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol_cfg(s, "KernelBase.dll!SleepEx", dsimple_on_sleep, backend, &sleepex, sizeof(sleepex)) &&
             probe_add_symbol_cfg(s, "kernel32.dll!Sleep", dsimple_on_sleep, backend, &sleep, sizeof(sleep)) &&
             probe_launch(s, argv + i + 1) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
