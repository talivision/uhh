// gated_config_mem -- gated_config, but the disabled flag is turned on by patching the
// target's MEMORY (set_mem on the stored config) instead of a register.
//
//   gated_config_mem [--flag-backend b] [--read-backend b] [--open-backend b] [--no-log]
//                <flag_location> <read_location> -- <target.exe> [target args]
//
//   e.g. gated_config_mem configparse.dll!ParseConfig+0x18 ntdll.dll!NtReadVirtualMemory -- probe_app.exe
//
// b = breakpoint | hw | inline (flag default breakpoint, reads default inline, opens default
// = the read backend). The handle -> pid map is UHH_SHARED, so the open probe and the read
// probe may use different backends. Probing the ntdll syscall stubs catches every caller,
// whichever wrapper (or none) it went through.
#include "callbacks.h"
#include <cstdio>
#include <cstring>

static int usage() {
    std::fprintf(stderr, "usage: gated_config_mem [--flag-backend b] [--read-backend b] [--open-backend b] [--no-log] "
                         "<flag_location> <read_location> -- <target.exe> [args]\n"
                         "       b = breakpoint | hw | inline\n");
    return 2;
}

int main(int argc, char **argv) {
    read_log_config cfg{};
    uint32_t flag_backend = PROBE_BREAKPOINT, read_backend = PROBE_INLINE, open_backend = 0, log = 1;
    const char *locations[2] = {}; int nloc = 0, i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--no-log")) log = 0;
        else if (!std::strcmp(argv[i], "--flag-backend") && i + 1 < argc) flag_backend = backend_flag(argv[++i]);
        else if (!std::strcmp(argv[i], "--read-backend") && i + 1 < argc) read_backend = backend_flag(argv[++i]);
        else if (!std::strcmp(argv[i], "--open-backend") && i + 1 < argc) open_backend = backend_flag(argv[++i]);
        else if (nloc < 2) locations[nloc++] = argv[i];
        else return usage();
    }
    if (!flag_backend || !read_backend || nloc != 2 || i + 1 >= argc) return usage();
    if (!open_backend) open_backend = read_backend;
    char **target = argv + i + 1;   // argv is NULL-terminated

    cfg.cookie = READ_LOG_COOKIE; cfg.log = log;

    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol(s, locations[0], enable_reads_mem, flag_backend) &&
             probe_add_symbol(s, "ntdll.dll!NtOpenProcess", track_open_process, open_backend) &&
             probe_add_symbol(s, "ntdll.dll!NtClose", forget_closed_handle, open_backend) &&
             probe_add_symbol_cfg(s, locations[1], log_read, read_backend, &cfg, sizeof(cfg)) &&
             probe_launch(s, target) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);   // the flip is logged ("flag flipped in memory at ...")
    probe_close(s);
    return ok ? 0 : 1;
}
