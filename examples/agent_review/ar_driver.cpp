// ar_driver [--backend b|cycle] [--repeat N] --probe <symbol>=<callback> ... -- ar_target.exe <case>
// Inline-agent review (regress `agent-*`): adds the given probes, runs the target, prints the
// report. Callbacks are named (see ar_callbacks.cpp). --repeat N runs N sessions one after
// the other in this process (--backend cycle: breakpoint, hw, inline in turn), each followed
// by a {"kind":"iter"} row with the controller's handle count (regress `sessions-repeat`).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "probe_api.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#define CB(n) extern "C" void n(probe_context *);
CB(ar_on_site) CB(ar_on_fault_ret) CB(ar_on_fault_noret) CB(ar_on_alloc) CB(ar_on_jump) CB(ar_on_after) CB(ar_on_prot) CB(ar_on_cf) CB(ar_on_cf_inner) CB(ar_on_dr_arm) CB(ar_on_d5_callee) CB(ar_on_d5_callee_fb) CB(ar_on_cfw_setup) CB(ar_on_cob) CB(ar_on_cfwl_setup) CB(ar_on_dr2_arm)
static const struct { const char *name; probe_callback fn; } k_callbacks[] = {
    {"ar_on_site", ar_on_site}, {"ar_on_fault_ret", ar_on_fault_ret}, {"ar_on_fault_noret", ar_on_fault_noret},
    {"ar_on_alloc", ar_on_alloc}, {"ar_on_jump", ar_on_jump}, {"ar_on_after", ar_on_after}, {"ar_on_prot", ar_on_prot},
    {"ar_on_cf", ar_on_cf}, {"ar_on_cf_inner", ar_on_cf_inner}, {"ar_on_dr_arm", ar_on_dr_arm},
    {"ar_on_d5_callee", ar_on_d5_callee}, {"ar_on_d5_callee_fb", ar_on_d5_callee_fb},
    {"ar_on_cfw_setup", ar_on_cfw_setup}, {"ar_on_cob", ar_on_cob},
    {"ar_on_cfwl_setup", ar_on_cfwl_setup}, {"ar_on_dr2_arm", ar_on_dr2_arm},
};

static uint32_t backend_of(const char *b) {
    return !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : PROBE_INLINE;
}

static int run_once(uint32_t bk, const std::vector<std::pair<std::string, probe_callback>> &adds, std::vector<char *> &child) {
    probe_session *s = probe_session_create();
    if (!s) return 0;
    for (auto &a : adds)
        if (!probe_add_symbol(s, a.first.c_str(), a.second, bk)) {
            std::fprintf(stderr, "ar_driver: add %s failed\n", a.first.c_str());
            probe_report(s, stdout); probe_close(s); return 0;
        }
    int r = probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout); probe_close(s);
    return r;
}

int main(int argc, char **argv) {
    const char *backend = "inline";
    int repeat = 1;
    std::vector<std::pair<std::string, probe_callback>> adds;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            backend = argv[++i];
        } else if (!std::strcmp(argv[i], "--repeat") && i + 1 < argc) {
            repeat = std::atoi(argv[++i]);
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
    if (adds.empty() || i + 1 >= argc || repeat < 1) { std::fprintf(stderr, "usage: see ar_driver.cpp\n"); return 2; }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    const bool cycle = !std::strcmp(backend, "cycle");
    static const char *const k_cycle[] = {"breakpoint", "hw", "inline"};
    int all = 1;
    for (int n = 0; n < repeat; ++n) {
        const char *b = cycle ? k_cycle[n % 3] : backend;
        const int ok = run_once(backend_of(b), adds, child);
        all &= ok;
        if (repeat > 1) {
            DWORD handles = 0; GetProcessHandleCount(GetCurrentProcess(), &handles);
            std::printf("{\"kind\":\"iter\",\"i\":%d,\"backend\":\"%s\",\"ok\":%d,\"handles\":%lu}\n", n, b, ok, handles);
            std::fflush(stdout);
        }
    }
    return all ? 0 : 1;
}
