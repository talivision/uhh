// Refusals must be clean: an unsupported or excess probe returns 0 with an error and
// leaves everything else working. Then 4 hardware probes on one function (the DR limit)
// must each count every call exactly.
//   refusal_driver -- hitcost_target.exe --calls N
#include "probe_api.h"
#include <cstdio>
#include <cstring>
#include <vector>

static volatile long g_hits[4];
extern "C" __declspec(dllexport) void refusal_noop(probe_context *c) { (void)c; }
#define HW_CB(n) extern "C" __declspec(dllexport) void refusal_hw##n(probe_context *c) { (void)c; ++g_hits[n]; }
HW_CB(0) HW_CB(1) HW_CB(2) HW_CB(3)

int main(int argc, char **argv) {
    int i = 1;
    while (i < argc && std::strcmp(argv[i], "--")) ++i;
    if (i + 1 >= argc) return 2;
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    const char *site = "hitcost_target.exe!hit_site";

    // Flag refusals (each on its own session so nothing leaks between them).
    probe_session *t = probe_session_create();
    int at_return = probe_add_symbol(t, site, refusal_noop, PROBE_BREAKPOINT | PROBE_AT_RETURN);
    int inline_once = probe_add_symbol(t, site, refusal_noop, PROBE_INLINE | PROBE_ONCE);
    int two_types = probe_add_symbol(t, site, refusal_noop, PROBE_INLINE | PROBE_HW);
    int watch_on_bp = probe_add_symbol(t, site, refusal_noop, PROBE_BREAKPOINT | PROBE_WATCH_WRITE);
    int inline33 = 1;
    for (int k = 0; k < 33; ++k) inline33 = probe_add_symbol(t, site, refusal_noop, PROBE_INLINE);
    probe_close(t);

    // 4 hw probes on one site, then a 5th that must be refused.
    probe_session *s = probe_session_create();
    int hw4 = probe_add_symbol(s, site, refusal_hw0, PROBE_HW) && probe_add_symbol(s, site, refusal_hw1, PROBE_HW) &&
              probe_add_symbol(s, site, refusal_hw2, PROBE_HW) && probe_add_symbol(s, site, refusal_hw3, PROBE_HW);
    int hw5 = probe_add_symbol(s, site, refusal_noop, PROBE_HW);
    int ok = hw4 && probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    probe_close(s);
    std::printf("{\"kind\":\"refusals\",\"at_return\":%d,\"inline_once\":%d,\"two_types\":%d,\"watch_on_bp\":%d,"
                "\"inline33\":%d,\"hw4\":%d,\"hw5\":%d,\"hits\":[%ld,%ld,%ld,%ld],\"run_ok\":%d}\n",
                at_return, inline_once, two_types, watch_on_bp, inline33, hw4, hw5,
                g_hits[0], g_hits[1], g_hits[2], g_hits[3], ok);
    return 0;
}
