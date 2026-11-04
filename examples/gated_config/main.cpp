// gated_config -- launch a target whose feature ships DISABLED, turn it on from
// outside, and log every read it then makes.
//
//   gated_config [--flag-backend b] [--read-backend b] [--no-log]
//                <flag_location> <read_location> -- <target.exe> [target args]
//
//   e.g. gated_config configparse.dll!ParseConfig+0x16 ntdll.dll!NtReadVirtualMemory -- probe_app.exe
//
// b = breakpoint | hw | inline (flag default breakpoint, reads default inline). The
// ntdll!NtOpenProcess probe (handle -> pid for the read log) uses the read backend, so
// the map it builds lives in the same address space as log_read. Probing the ntdll
// syscall stubs catches every caller, whichever wrapper (or none) it went through.
#include "callbacks.h"
#include <cstdio>
#include <cstring>

static int usage() {
    std::fprintf(stderr, "usage: gated_config [--flag-backend b] [--read-backend b] [--no-log] "
                         "<flag_location> <read_location> -- <target.exe> [args]\n"
                         "       b = breakpoint | hw | inline\n");
    return 2;
}

int main(int argc, char **argv) {
    uint32_t flag_backend = PROBE_BREAKPOINT, read_backend = PROBE_INLINE, log = 1;
    const char *locations[2] = {}; int nloc = 0, i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--no-log")) log = 0;
        else if (!std::strcmp(argv[i], "--flag-backend") && i + 1 < argc) flag_backend = backend_flag(argv[++i]);
        else if (!std::strcmp(argv[i], "--read-backend") && i + 1 < argc) read_backend = backend_flag(argv[++i]);
        else if (nloc < 2) locations[nloc++] = argv[i];
        else return usage();
    }
    if (!flag_backend || !read_backend || nloc != 2 || i + 1 >= argc) return usage();
    char **target = argv + i + 1;   // argv is NULL-terminated

    read_log_config cfg{READ_LOG_COOKIE, log, 0, 0, 0, 0};

    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol(s, locations[0], enable_reads, flag_backend) &&
             probe_add_symbol(s, "ntdll.dll!NtOpenProcess", track_open_process, read_backend) &&
             probe_add_symbol_cfg(s, locations[1], log_read, read_backend, &cfg, sizeof(cfg)) &&
             probe_launch(s, target) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);   // "overrides" = how many times the flag was flipped
    probe_close(s);
    return ok ? 0 : 1;
}
