// gated_config -- launch a target whose feature ships DISABLED, turn it on from
// outside, and log every read it then makes.
//
//   gated_config [--flag-backend b] [--read-backend b] [--open-backend b] [--no-log]
//                [--pid P] [--range BASE:SIZE ...] <flag_location> <read_location> -- <target.exe> [args]
//
//   e.g. gated_config configparse.dll!ParseConfig+0x16 ntdll.dll!NtReadVirtualMemory -- probe_app.exe
//
// b = breakpoint | hw | inline (flag default breakpoint, reads default inline, opens default
// = the read backend). The handle -> pid map is UHH_SHARED, so the open probe and the read
// probe may use different backends. Probing the ntdll syscall stubs catches every caller,
// whichever wrapper (or none) it went through. --pid logs only reads of that process;
// --range (repeatable, up to 8) only reads whose address is in one of the ranges.
#include "callbacks.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int usage() {
    std::fprintf(stderr, "usage: gated_config [--flag-backend b] [--read-backend b] [--open-backend b] [--no-log] "
                         "[--pid P] [--range BASE:SIZE ...] <flag_location> <read_location> -- <target.exe> [args]\n"
                         "       b = breakpoint | hw | inline\n");
    return 2;
}

int main(int argc, char **argv) {
    uint32_t flag_backend = PROBE_BREAKPOINT, read_backend = PROBE_INLINE, open_backend = 0, log = 1;
    read_log_config cfg{};
    const char *locations[2] = {}; int nloc = 0, i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--no-log")) log = 0;
        else if (!std::strcmp(argv[i], "--flag-backend") && i + 1 < argc) flag_backend = backend_flag(argv[++i]);
        else if (!std::strcmp(argv[i], "--read-backend") && i + 1 < argc) read_backend = backend_flag(argv[++i]);
        else if (!std::strcmp(argv[i], "--open-backend") && i + 1 < argc) open_backend = backend_flag(argv[++i]);
        else if (!std::strcmp(argv[i], "--pid") && i + 1 < argc) cfg.pid = std::strtoull(argv[++i], nullptr, 0);
        else if (!std::strcmp(argv[i], "--range") && i + 1 < argc) { if (!add_read_range(&cfg, argv[++i])) return usage(); }
        else if (nloc < 2) locations[nloc++] = argv[i];
        else return usage();
    }
    if (!flag_backend || !read_backend || nloc != 2 || i + 1 >= argc) return usage();
    if (!open_backend) open_backend = read_backend;
    char **target = argv + i + 1;   // argv is NULL-terminated

    cfg.cookie = READ_LOG_COOKIE; cfg.log = log;

    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol(s, locations[0], enable_reads, flag_backend) &&
             probe_add_symbol(s, "ntdll.dll!NtOpenProcess", track_open_process, open_backend) &&
             probe_add_symbol(s, "ntdll.dll!NtClose", forget_closed_handle, close_backend_for(open_backend)) &&
             probe_add_symbol_cfg(s, locations[1], log_read, read_backend, &cfg, sizeof(cfg)) &&
             probe_launch(s, target) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);   // "overrides" = how many times the flag was flipped
    probe_close(s);
    return ok ? 0 : 1;
}
