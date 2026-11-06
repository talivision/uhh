#include "my_callbacks.h"
#include <cstdio>

int main(int argc, char **argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: my_tool <target.exe> [args]\n");
        return 2;
    }
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol(s, "configparse.dll!ParseConfig+0x16", my_enable_reads, PROBE_BREAKPOINT) &&
             probe_add_symbol(s, "ntdll.dll!NtReadVirtualMemory", my_log_read, PROBE_INLINE) &&
             probe_launch(s, argv + 1) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);   // "overrides" = how many times the flag was flipped
    probe_close(s);
    return ok ? 0 : 1;
}
