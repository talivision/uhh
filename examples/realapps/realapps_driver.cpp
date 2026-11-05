// realapps_driver -- the gated_config callbacks, unchanged, on ANY program: launch a command
// or attach to a running pid, map every ntdll!NtOpenProcess handle to its pid and image
// name, and log every ntdll!NtReadVirtualMemory read (pid, name, address, size).
//
//   realapps_driver [--backend b] [--open-backend b] [--read-backend b] [--no-log]
//                   [--pid P] [--range BASE:SIZE ...] [--flag LOCATION [--flag-backend b]]
//                   (--attach PID | -- <program.exe> [args])
//
//   e.g. realapps_driver --backend inline -- C:\Windows\System32\tasklist.exe /m
//
// b = breakpoint | hw | inline (default breakpoint for every probe; --backend sets open and
// read together). Probes (callbacks from examples/gated_config/callbacks.cpp):
//   ntdll.dll!NtOpenProcess        <open-backend>  track_open_process (call_original -> handle -> pid -> name)
//   ntdll.dll!NtClose              <open-backend>  forget_closed_handle (handle values are reused)
//   ntdll.dll!NtReadVirtualMemory  <read-backend>  log_read (optionally only --pid P / --range)
//   LOCATION (optional)            <flag-backend>  enable_reads (the parsed flag in EAX: 0 -> 1)
// A read through a handle the program did not get from NtOpenProcess (CreateProcess's
// hProcess, DuplicateHandle, the -1 pseudo-handle, inheritance) is logged as pid=0 name=?.
// Prints the probe report (per-probe hits, logs_written, log_dropped, app_exit) at the end.
#include "callbacks.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int usage() {
    std::fprintf(stderr, "usage: realapps_driver [--backend b] [--open-backend b] [--read-backend b] [--no-log] "
                         "[--pid P] [--range BASE:SIZE ...] [--flag LOCATION [--flag-backend b]] "
                         "(--attach PID | -- <program.exe> [args])\n"
                         "       b = breakpoint | hw | inline\n");
    return 2;
}

int main(int argc, char **argv) {
    uint32_t open_backend = PROBE_BREAKPOINT, read_backend = PROBE_BREAKPOINT, flag_backend = PROBE_BREAKPOINT, attach = 0;
    const char *flag = nullptr;
    read_log_config cfg{};
    cfg.cookie = READ_LOG_COOKIE; cfg.log = 1;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        const bool more = i + 1 < argc;
        if (!std::strcmp(argv[i], "--no-log")) cfg.log = 0;
        else if (!std::strcmp(argv[i], "--backend") && more) open_backend = read_backend = backend_flag(argv[++i]);
        else if (!std::strcmp(argv[i], "--open-backend") && more) open_backend = backend_flag(argv[++i]);
        else if (!std::strcmp(argv[i], "--read-backend") && more) read_backend = backend_flag(argv[++i]);
        else if (!std::strcmp(argv[i], "--flag-backend") && more) flag_backend = backend_flag(argv[++i]);
        else if (!std::strcmp(argv[i], "--flag") && more) flag = argv[++i];
        else if (!std::strcmp(argv[i], "--attach") && more) attach = (uint32_t)std::strtoul(argv[++i], nullptr, 0);
        else if (!std::strcmp(argv[i], "--pid") && more) cfg.pid = std::strtoull(argv[++i], nullptr, 0);
        else if (!std::strcmp(argv[i], "--range") && more) { if (!add_read_range(&cfg, argv[++i])) return usage(); }
        else return usage();
    }
    char **target = i + 1 < argc ? argv + i + 1 : nullptr;   // argv is NULL-terminated
    if (!open_backend || !read_backend || !flag_backend || (!attach == !target)) return usage();

    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = (!flag || probe_add_symbol(s, flag, enable_reads, flag_backend)) &&
             probe_add_symbol(s, "ntdll.dll!NtOpenProcess", track_open_process, open_backend) &&
             probe_add_symbol(s, "ntdll.dll!NtClose", forget_closed_handle, open_backend) &&
             probe_add_symbol_cfg(s, "ntdll.dll!NtReadVirtualMemory", log_read, read_backend, &cfg, sizeof(cfg)) &&
             (attach ? probe_attach(s, attach) : probe_launch(s, target));
    if (ok && attach) {
        std::printf("{\"kind\":\"attached\",\"pid\":%lu}\n", (unsigned long)attach);
        std::fflush(stdout);
    }
    ok = ok && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
