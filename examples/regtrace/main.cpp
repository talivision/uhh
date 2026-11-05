// regtrace -- log a program's registry reads and writes by key name.
//
//   regtrace [--backend b] [--open-backend b] [--value-backend b] [--close-backend b]
//            [--filter TEXT] -- <target.exe> [args]
//
// b = breakpoint | hw | inline (default inline; --backend sets all, the others one group):
//   open:  ntdll!NtOpenKey, NtOpenKeyEx, NtCreateKey  (call_original: handle -> key name)
//   value: ntdll!NtQueryValueKey, NtSetValueKey      (log key name + value name)
//   close: ntdll!NtClose                             (forget the handle)
// --filter logs only keys whose name contains TEXT (case-sensitive).
//   open key=\REGISTRY\USER\S-1-5-..\Software\X status=0x00000000 handle=0x8c
//   set key=\REGISTRY\USER\S-1-5-..\Software\X handle=0x8c value=count type=4
//
// Hardware: there are 4 debug registers, one probe each, and call_original on hw needs one
// free while it runs -- so hw fits the open group (3 + 1 free) OR value + close (3), not both.
#include "callbacks.h"
#include <cstdio>
#include <cstring>

static int usage() {
    std::fprintf(stderr, "usage: regtrace [--backend b] [--open-backend b] [--value-backend b] "
                         "[--close-backend b] [--filter TEXT] -- <target.exe> [args]\n"
                         "       b = breakpoint | hw | inline\n");
    return 2;
}

int main(int argc, char **argv) {
    uint32_t open = PROBE_INLINE, value = ~0u, close = ~0u;    // ~0u: same as open
    regtrace_config cfg{REGTRACE_COOKIE, {}};
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        const bool more = i + 1 < argc;
        if (!std::strcmp(argv[i], "--backend") && more) open = value = close = regtrace_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--open-backend") && more) open = regtrace_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--value-backend") && more) value = regtrace_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--close-backend") && more) close = regtrace_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--filter") && more) strncpy_s(cfg.filter, argv[++i], _TRUNCATE);
        else return usage();
    }
    if (value == ~0u) value = open;
    if (close == ~0u) close = open;
    if (!open || !value || !close || i + 1 >= argc) return usage();
    const int hw = 3 * (open == PROBE_HW) + 2 * (value == PROBE_HW) + (close == PROBE_HW);
    if (hw > 4 || (open == PROBE_HW && hw > 3)) {
        std::fprintf(stderr, "regtrace: %d hw probes do not fit the 4 debug registers%s\n", hw,
                     open == PROBE_HW ? " (the open group's call_original needs one free)" : "");
        return 2;
    }

    probe_session *s = probe_session_create();
    if (!s) return 1;
    const size_t n = sizeof(cfg);
    int ok = probe_add_symbol_cfg(s, "ntdll.dll!NtOpenKey", rt_on_open_key, open, &cfg, n) &&
             probe_add_symbol_cfg(s, "ntdll.dll!NtOpenKeyEx", rt_on_open_key_ex, open, &cfg, n) &&
             probe_add_symbol_cfg(s, "ntdll.dll!NtCreateKey", rt_on_create_key, open, &cfg, n) &&
             probe_add_symbol_cfg(s, "ntdll.dll!NtQueryValueKey", rt_on_query_value, value, &cfg, n) &&
             probe_add_symbol_cfg(s, "ntdll.dll!NtSetValueKey", rt_on_set_value, value, &cfg, n) &&
             probe_add_symbol(s, "ntdll.dll!NtClose", rt_on_close, close) &&
             probe_launch(s, argv + i + 1) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
