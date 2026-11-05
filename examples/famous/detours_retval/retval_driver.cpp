// detours_retval -- CreateFileW's return value and last error, the UHH way.
//
//   detours_retval [--backend breakpoint|hw|inline] [--fallback-hw] [--log-entry] -- <program> [args...]
//
// One entry probe on KernelBase!CreateFileW; its callback adds a probe at each new return
// address (same backend; --fallback-hw lets an inline return probe move to a debug
// register where an inline hook is not safe). Each return is logged as
//   CreateFileW("name") -> handle=0x... error=N
#include "retval_callbacks.h"
#include <cstdio>
#include <cstring>

int main(int argc, char **argv) {
    uint32_t backend = PROBE_BREAKPOINT; bool fallback = false, log_entry = false;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *name = argv[++i];
            backend = !std::strcmp(name, "inline") ? PROBE_INLINE : !std::strcmp(name, "hw") ? PROBE_HW
                    : !std::strcmp(name, "breakpoint") ? PROBE_BREAKPOINT : 0u;
        } else if (!std::strcmp(argv[i], "--fallback-hw")) {
            fallback = true;
        } else if (!std::strcmp(argv[i], "--log-entry")) {
            log_entry = true;
        } else {
            backend = 0;
        }
    }
    if (!backend || i + 1 >= argc) {
        std::fprintf(stderr, "usage: detours_retval [--backend breakpoint|hw|inline] [--fallback-hw] [--log-entry] -- <program> [args]\n");
        return 2;
    }
    static dretval_config cfg{};
    cfg.return_flags = backend | (fallback && backend == PROBE_INLINE ? (uint32_t)PROBE_FALLBACK_HW : 0u);
    cfg.log_entry = log_entry ? 1u : 0u;
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol_cfg(s, "KernelBase.dll!CreateFileW", dretval_on_entry, backend, &cfg, sizeof(cfg)) &&
             probe_launch(s, argv + i + 1) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
