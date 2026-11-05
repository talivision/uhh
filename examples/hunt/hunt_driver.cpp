// hunt_driver -- gated_config's instrumentation (NtOpenProcess -> handle/pid map, every
// NtReadVirtualMemory logged with its pid) on hunt_target, plus a stressor.
//
//   hunt_driver [--backend b] [--slow-ms N] [--tid] [--recurse] [--work-backend b]
//               -- hunt_target.exe <scenario> [--n N]
//
// --work-backend adds a probe on hunt_dll.dll!HuntWork (a module that keeps unloading).
#include "hunt_callbacks.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char **argv) {
    uint32_t backend = PROBE_INLINE, work_backend = 0;
    hunt_config cfg{};
    cfg.read = read_log_config{READ_LOG_COOKIE, 1, 0, 0, 0, 0};
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) backend = backend_flag(argv[++i]);
        else if (!std::strcmp(argv[i], "--work-backend") && i + 1 < argc) work_backend = backend_flag(argv[++i]);
        else if (!std::strcmp(argv[i], "--slow-ms") && i + 1 < argc) cfg.slow_ms = (uint32_t)std::strtoul(argv[++i], nullptr, 0);
        else if (!std::strcmp(argv[i], "--tid")) cfg.mode |= HUNT_MODE_TID;
        else if (!std::strcmp(argv[i], "--recurse")) cfg.mode |= HUNT_MODE_RECURSE;
        else { std::fprintf(stderr, "hunt_driver: unknown option %s\n", argv[i]); return 2; }
    }
    if (!backend || i + 1 >= argc) { std::fprintf(stderr, "usage: hunt_driver [opts] -- target args\n"); return 2; }
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol(s, "ntdll.dll!NtOpenProcess", track_open_process, backend) &&
             probe_add_symbol(s, "ntdll.dll!NtClose", forget_closed_handle, backend) &&
             probe_add_symbol_cfg(s, "ntdll.dll!NtReadVirtualMemory", hunt_read_cb, backend, &cfg, sizeof(cfg)) &&
             (!work_backend || probe_add_symbol(s, "hunt_dll.dll!HuntWork", hunt_work_cb, work_backend)) &&
             probe_launch(s, argv + i + 1) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
