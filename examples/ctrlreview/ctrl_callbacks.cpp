// Controller-review fixture callbacks: ONE source under breakpoint, hw and inline (also
// built into the agent DLL). The config carries the backend for runtime adds.
#include "probe_api.h"
#include <stdint.h>

#define CTRL_EXPORT extern "C" __declspec(dllexport)

struct ctrl_cfg { uint32_t backend; uint32_t pad; };

static uint32_t cfg_backend(probe_context *c) {
    const ctrl_cfg *k = (const ctrl_cfg *)get_config(c);
    return k ? k->backend : PROBE_BREAKPOINT;
}

CTRL_EXPORT void ctrl_on_load(probe_context *c) { send_log(c, "load"); }

CTRL_EXPORT void ctrl_on_loop(probe_context *c) {
    send_log(c, "tag=%llx", (unsigned long long)(get_reg(c, PROBE_REG_DX) & 0xFFFFFFFFu));
}

CTRL_EXPORT void ctrl_on_work(probe_context *c) { (void)c; }
CTRL_EXPORT void ctrl_on_watch(probe_context *c) { (void)c; }

// CtrlAnnounce(work, counter): probe the DLL function by address, watch the DLL global.
CTRL_EXPORT void ctrl_on_announce(probe_context *c) {
    const uint64_t work = get_func_arg(c, 0), counter = get_func_arg(c, 1);
    const int a = probe_add_address(get_session(c), work, ctrl_on_work, cfg_backend(c));
    const int w = probe_watch(get_session(c), counter, ctrl_on_watch, PROBE_WATCH_WRITE);
    send_log(c, "%s add=%d watch=%d", a == 1 && w == 1 ? "ok" : "FAIL", a, w);
}

CTRL_EXPORT void ctrl_on_leaf(probe_context *c) { send_log_stack(c, "leaf"); }

// CtrlTick(tock): arm a one-shot hardware probe on CtrlTock at runtime (once).
CTRL_EXPORT void ctrl_on_tock(probe_context *c) { send_log(c, "tock"); }
CTRL_EXPORT void ctrl_on_tick(probe_context *c) {
    const uint64_t tock = get_func_arg(c, 0);
    if (!tock) { send_log(c, "tick"); return; }
    const int r = probe_add_address(get_session(c), tock, ctrl_on_tock, PROBE_HW | PROBE_ONCE);
    send_log(c, "%s tick add=%d", r == 1 ? "ok" : "FAIL", r);
}
