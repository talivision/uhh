// flagflip -- turn on a feature flag that is a C++ virtual method, from outside.
//
//   flagflip [--backend b] [--mode force|modify] [--feature NAME] <location> -- <target.exe> [args]
//
//   e.g. flagflip --feature beta flagfeature.dll!Feature::IsEnabled -- flagflip_target.exe
//
// b = breakpoint | hw | inline (default inline). force: the method returns true without
// running (return_from); modify: it runs (call_original) and its false becomes true.
// --feature limits it to the object whose name is NAME (read through `this`).
// The location may name a PDB symbol: the probe stays pending until the DLL loads.
#include "callbacks.h"
#include <cstdio>
#include <cstring>

static int usage() {
    std::fprintf(stderr, "usage: flagflip [--backend b] [--mode force|modify] [--feature NAME] <location> "
                         "-- <target.exe> [args]\n       b = breakpoint | hw | inline\n");
    return 2;
}

int main(int argc, char **argv) {
    uint32_t backend = PROBE_INLINE;
    flagflip_config cfg{FLAGFLIP_COOKIE, FLAGFLIP_FORCE, {}};
    const char *location = nullptr;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        const bool more = i + 1 < argc;
        if (!std::strcmp(argv[i], "--backend") && more) backend = flagflip_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--mode") && more) {
            const char *m = argv[++i];
            if (!std::strcmp(m, "force")) cfg.mode = FLAGFLIP_FORCE;
            else if (!std::strcmp(m, "modify")) cfg.mode = FLAGFLIP_MODIFY;
            else return usage();
        } else if (!std::strcmp(argv[i], "--feature") && more) strncpy_s(cfg.feature, argv[++i], _TRUNCATE);
        else if (!location && argv[i][0] != '-') location = argv[i];
        else return usage();
    }
    if (!backend || !location || i + 1 >= argc) return usage();

    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol_cfg(s, location, ff_force_enabled, backend, &cfg, sizeof(cfg)) &&
             probe_launch(s, argv + i + 1) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);   // "hits" = IsEnabled calls
    probe_close(s);
    return ok ? 0 : 1;
}
