// Hardware data-watchpoint demo driver. Sets a WRITE (or --rw: read/write) watchpoint
// on watch_target's global `g_watched` (passed as its module RVA) and counts callback
// invocations: one per access to that address. The callback runs controller-side (the
// hardware backend is an external debugger), so no injected agent is involved. This
// observes a plain memory write -- a capability inline/trampoline hooking lacks.
//
//   watch_driver [--rw] <g_watched_rva> -- <watch_target.exe> [target args]
//   watch_driver [--rw] <location> -- <target.exe> [target args]   (any "module+0xRVA" /
//                "module!symbol+0xOFF": regress boundary-watch-*)
#include "probe_api.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

static long g_hits = 0;
static void on_write(probe_context *c) { (void)c; ++g_hits; }

int main(int argc, char **argv) {
    uint32_t mode = PROBE_WATCH_WRITE; int i = 1;
    if (i < argc && !std::strcmp(argv[i], "--rw")) { mode = PROBE_WATCH_RW; ++i; }
    if (i + 2 >= argc || std::strcmp(argv[i + 1], "--")) {
        std::fprintf(stderr, "usage: watch_driver [--rw] <g_watched_rva | location> -- <target.exe> [args]\n");
        return 2;
    }
    char loc[96];
    if (std::strchr(argv[i], '!') || std::strchr(argv[i], '+')) std::snprintf(loc, sizeof(loc), "%s", argv[i]);
    else std::snprintf(loc, sizeof(loc), "watch_target.exe+0x%llx", std::strtoull(argv[i], nullptr, 0));
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol(s, loc, on_write, PROBE_HW | mode) &&
             probe_launch(s, argv + i + 2) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    std::printf("{\"kind\":\"watch_driver\",\"callback_hits\":%ld}\n", g_hits);
    probe_close(s);
    return ok ? 0 : 1;
}
