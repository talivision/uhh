// ar_driver [--backend b] --probe <symbol>=<callback> ... -- ar_target.exe <case>
// Inline-agent review (regress `agent-*`): adds the given probes, runs the target, prints the
// report. Callbacks are named (see ar_callbacks.cpp).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "probe_api.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#define CB(n) extern "C" void n(probe_context *);
CB(ar_on_site) CB(ar_on_fault_ret) CB(ar_on_fault_noret) CB(ar_on_alloc) CB(ar_on_jump) CB(ar_on_after) CB(ar_on_prot) CB(ar_on_cf) CB(ar_on_cf_inner)
static const struct { const char *name; probe_callback fn; } k_callbacks[] = {
    {"ar_on_site", ar_on_site}, {"ar_on_fault_ret", ar_on_fault_ret}, {"ar_on_fault_noret", ar_on_fault_noret},
    {"ar_on_alloc", ar_on_alloc}, {"ar_on_jump", ar_on_jump}, {"ar_on_after", ar_on_after}, {"ar_on_prot", ar_on_prot},
    {"ar_on_cf", ar_on_cf}, {"ar_on_cf_inner", ar_on_cf_inner},
};

int main(int argc, char **argv) {
    uint32_t bk = PROBE_INLINE;
    std::vector<std::pair<std::string, probe_callback>> adds;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            bk = !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : PROBE_INLINE;
        } else if (!std::strcmp(argv[i], "--probe") && i + 1 < argc) {
            std::string spec = argv[++i];
            size_t eq = spec.rfind('=');
            probe_callback fn = nullptr;
            if (eq != std::string::npos)
                for (auto &cb : k_callbacks) if (spec.compare(eq + 1, std::string::npos, cb.name) == 0) fn = cb.fn;
            if (!fn) { std::fprintf(stderr, "ar_driver: bad --probe %s\n", spec.c_str()); return 2; }
            adds.emplace_back(spec.substr(0, eq), fn);
        }
    }
    if (adds.empty() || i + 1 >= argc) { std::fprintf(stderr, "usage: see ar_driver.cpp\n"); return 2; }
    probe_session *s = probe_session_create();
    if (!s) return 1;
    for (auto &a : adds)
        if (!probe_add_symbol(s, a.first.c_str(), a.second, bk)) {
            std::fprintf(stderr, "ar_driver: add %s failed\n", a.first.c_str());
            probe_report(s, stdout); probe_close(s); return 1;
        }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    int r = probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout); probe_close(s);
    return r ? 0 : 1;
}
