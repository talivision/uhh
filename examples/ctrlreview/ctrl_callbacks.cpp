// Controller-review fixture callbacks: ONE source under breakpoint, hw and inline (also
// built into the agent DLL). The config carries the backend for runtime adds.
#include "probe_api.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

// inplace-* shapes: EDX holds the call's unique tag at every probed shape instruction.
CTRL_EXPORT void ctrl_on_shape(probe_context *c) {
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

// ---- Codex review fixtures (regress `cdx-*`) ----------------------------------------------
// CtrlOp(addr, n, mode): mode 0 arms a software breakpoint on each of the n bytes at addr
// (by address, from the callback); mode 1 reads them with get_mem and counts 0xCC bytes --
// the program's bytes must show, never our INT3s, on every backend.
CTRL_EXPORT void ctrl_on_op(probe_context *c) {
    const uint64_t addr = get_func_arg(c, 0), n = get_func_arg(c, 1), mode = get_func_arg(c, 2);
    if (mode == 0) {
        int ok = 0;
        for (uint64_t i = 0; i < n; ++i) ok += probe_add_address(get_session(c), addr + i, ctrl_on_work, PROBE_BREAKPOINT) == 1;
        send_log(c, "op arm ok=%d/%d", ok, (int)n);
        return;
    }
    static unsigned char buf[4096];
    const size_t len = n < sizeof(buf) ? (size_t)n : sizeof(buf);
    const int r = get_mem(c, addr, buf, len);
    int cc = 0;
    for (size_t i = 0; i < len; ++i) cc += buf[i] == 0xCC;
    send_log(c, "op peek r=%d cc=%d n=%d first=%02x", r, cc, (int)len, buf[0]);
}
// CtrlCall(phase): call_func of a function in a DLL that comes and goes under one name (cdx-cfreuse).
CTRL_EXPORT void ctrl_on_cfcall(probe_context *c) {
    uint64_t r = 0;
    const int ok = call_func(c, "cfr.dll!CfrValue", &r, 0);
    send_log(c, "cf phase=%d ok=%d r=%d", (int)get_func_arg(c, 0), ok, ok ? (int)r : -1);
}
// CtrlWatchOnce(var): a one-shot data watch on var (released when it fires).
CTRL_EXPORT void ctrl_on_wonce(probe_context *c) {
    const int r = probe_watch(get_session(c), get_func_arg(c, 0), ctrl_on_watch, PROBE_WATCH_WRITE | PROBE_ONCE);
    send_log(c, "%s wonce=%d", r == 1 ? "ok" : "FAIL", r);
}
// CtrlBigCfg(): a dynamic add with a config over 64 MiB (the old inline-only IPC bound).
CTRL_EXPORT void ctrl_on_bigcfg(probe_context *c) {
    const size_t n = ((size_t)64 << 20) + 4096;
    unsigned char *cfg = (unsigned char *)malloc(n);
    if (!cfg) { send_log(c, "FAIL bigcfg malloc"); return; }
    memset(cfg, 0x5A, n);
    const int r = probe_add_symbol_cfg(get_session(c), "ctrl_target.exe!CtrlTock", ctrl_on_tock, PROBE_BREAKPOINT, cfg, n);
    free(cfg);
    send_log(c, "%s bigcfg add=%d", r == 1 ? "ok" : "FAIL", r);
}

// Module-review callbacks, shared verbatim by every backend.
CTRL_EXPORT void ctrl_on_modcall(probe_context *c) {
    uint64_t r = 0;
    const int ok = call_func(c, "modrel_forward_low.dll!ForwardValue", &r, 1, (uint64_t)5);
    send_log(c, "modcall ok=%d r=%llu", ok, (unsigned long long)r);
}
CTRL_EXPORT void ctrl_on_modarm(probe_context *c) {
    const int ok = probe_add_address(get_session(c), get_func_arg(c, 0), ctrl_on_load, cfg_backend(c));
    send_log(c, "modarm ok=%d", ok);
}

CTRL_EXPORT void ctrl_on_modhistory(probe_context *c) {
    uint64_t r = 0;
    const int ok = call_func(c, "kernel32.dll!GetCurrentProcessId", &r, 0);
    send_log(c, "modhistory ok=%d match=%d", ok, ok && r == get_func_arg(c, 0));
}
