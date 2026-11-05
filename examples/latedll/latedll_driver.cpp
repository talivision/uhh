// latedll_driver --backend breakpoint|hw|inline|mixed -- latedll_target.exe <main|worker|dllmain>
//
// Probes registered BEFORE launch on functions in DLLs the target LoadLibrary's later:
//   breakpoint/inline  latedll_fix.dll!LdSite0..7 (+ latedll_heavy.dll!HvSite for dllmain)
//   hw                 LdSite0, LdSite1 (+ HvSite): within the four debug registers
//   mixed              LdSite k: k%3 == 0 inline, 1 breakpoint, 2 hw; HvSite inline -- the
//                      hw probes take debug registers, so the inline sites outnumber the rest
// The regress check compares every probe's hits and "ld <id>" logs with the target's counts.
#include "probe_api.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" void latedll_hit(probe_context *);

int main(int argc, char **argv) {
    const char *backend = "inline"; int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i)
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) backend = argv[++i];
    if (i + 1 >= argc) { std::fprintf(stderr, "usage: latedll_driver --backend b -- latedll_target.exe <mode>\n"); return 2; }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    const bool heavy = argc > i + 2 && !std::strcmp(argv[i + 2], "dllmain");
    const bool mixed = !std::strcmp(backend, "mixed");
    const uint32_t one = !std::strcmp(backend, "hw") ? PROBE_HW : !std::strcmp(backend, "breakpoint") ? PROBE_BREAKPOINT : PROBE_INLINE;
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = 1;
    const int nsites = one == PROBE_HW ? 2 : 8;
    for (int k = 0; k < nsites && ok; ++k) {
        uint32_t f = mixed ? (k % 3 == 0 ? PROBE_INLINE : k % 3 == 1 ? PROBE_BREAKPOINT : PROBE_HW) : one;
        ok = probe_add_symbol(s, ("latedll_fix.dll!LdSite" + std::to_string(k)).c_str(), latedll_hit, f);
    }
    if (ok && heavy) ok = probe_add_symbol(s, "latedll_heavy.dll!HvSite", latedll_hit, mixed ? PROBE_INLINE : one);
    if (!ok) std::fprintf(stderr, "latedll_driver: setup failed\n");
    ok = ok && probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    std::printf("{\"kind\":\"latedll_driver\",\"backend\":\"%s\",\"run_ok\":%d}\n", backend, ok);
    std::fflush(stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
