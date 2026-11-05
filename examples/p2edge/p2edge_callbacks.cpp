// ONE callback source for the P2 edge checks, built into p2edge_driver (breakpoint/hw) and
// into probe_api_agent (inline). Results travel as logs, which every backend delivers.
#include "probe_api.h"

#define EDGE_EXPORT extern "C" __declspec(dllexport)

// Counting is done by the probe report's per-probe hit counts.
EDGE_EXPORT void edge_count(probe_context *c) { (void)c; }

// p2edge_late.dll!LateSite(i, LateNext): on the FIRST hit, add an inline probe on LateNext
// by address. The calling thread is held until the hook lands, so all its later calls
// (and every other thread's) are seen.
EDGE_EXPORT void edge_on_late(probe_context *c) {
    static volatile long first = 1;
    if (!first) return;
    first = 0;
    int r = probe_add_address(get_session(c), get_func_arg(c, 1), edge_count, PROBE_INLINE);
    send_log(c, "add_inline=%d", r);
}

// MarkA(HwSite3): all four debug-register slots are taken -> a runtime 5th is refused.
EDGE_EXPORT void edge_mark_a(probe_context *c) {
    int r = probe_add_address(get_session(c), get_func_arg(c, 0), edge_count, PROBE_HW);
    send_log(c, "markA fifth=%d", r);
}

// MarkB(HwSite2, &g_w2, HwSite3): both PROBE_ONCE probes have retired -> their two slots
// are free again (one execute, one watch), and a third add is refused again.
EDGE_EXPORT void edge_mark_b(probe_context *c) {
    probe_session *s = get_session(c);
    int hw = probe_add_address(s, get_func_arg(c, 0), edge_count, PROBE_HW);
    int watch = probe_watch(s, get_func_arg(c, 1), edge_count, PROBE_WATCH_WRITE);
    int fifth = probe_add_address(s, get_func_arg(c, 2), edge_count, PROBE_HW);
    send_log(c, "markB hw=%d watch=%d fifth=%d", hw, watch, fifth);
}
