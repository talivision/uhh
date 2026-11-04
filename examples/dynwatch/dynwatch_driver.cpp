// Driver for the malloc -> watch chain (see dynwatch_callbacks.cpp).
//   dynwatch_driver [--entry breakpoint|hw|inline] -- <dynwatch_target.exe> [target args]
// --entry picks the backend for the malloc-entry probe only; the rest of the chain is
// registered at runtime from inside the callbacks.
#include "probe_api.h"
#include "dynwatch_callbacks.h"
#include <cstdio>
#include <cstring>

int main(int argc, char **argv) {
    const char *entry_name = "breakpoint"; int i = 1;
    if (i + 1 < argc && !std::strcmp(argv[i], "--entry")) { entry_name = argv[i + 1]; i += 2; }
    uint32_t entry = !std::strcmp(entry_name, "breakpoint") ? PROBE_BREAKPOINT
                   : !std::strcmp(entry_name, "hw") ? PROBE_HW
                   : !std::strcmp(entry_name, "inline") ? PROBE_INLINE : 0u;
    if (!entry || i + 1 >= argc || std::strcmp(argv[i], "--")) {
        std::fprintf(stderr, "usage: dynwatch_driver [--entry breakpoint|hw|inline] -- <dynwatch_target.exe> [args]\n");
        return 2;
    }
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol(s, "ucrtbase.dll!malloc", dynwatch_on_malloc, entry) &&
             probe_launch(s, argv + i + 1) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    std::printf("{\"kind\":\"dynwatch_result\",\"entry\":\"%s\",\"returns\":%ld,\"arms\":%ld,\"watch_hits\":%ld}\n",
                entry_name, dynwatch_returns(), dynwatch_arms(), dynwatch_watch_hits());
    probe_close(s);
    return ok ? 0 : 1;
}
