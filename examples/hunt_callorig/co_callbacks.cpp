// call_original / return_from edge-case hunt: ONE callback source for every backend (built
// into co_driver for breakpoint/hw and into the agent for inline). Every callback logs lines
// starting "co "; the regress check counts them against the probe hits.
#include "probe_api.h"
#include <stdint.h>
#include <atomic>

#define CO_CB extern "C" __declspec(dllexport)

struct co_cfg { uint32_t backend; };    // the backend flags this probe was added with

// Generic "Detours" wrapper: log, run the original, return its value (+ delta).
static void wrap(probe_context *c, const char *name, int nargs, uint64_t delta, int pop) {
    send_log(c, "co %s", name);
    uint64_t r = 0;
    if (!call_original(c, nargs, &r)) { send_log(c, "co %s refused", name); return; }
    send_log(c, "co %s-done", name);        // not reached when the original raised / longjmp'd
    return_from(c, r + delta, pop);
}

CO_CB void co_on_fact(probe_context *c) { wrap(c, "fact", 1, 0, 0); }
CO_CB void co_on_throw(probe_context *c) { wrap(c, "throw", 1, 0, 0); }
CO_CB void co_on_seh(probe_context *c) { wrap(c, "seh", 1, 0, 0); }
CO_CB void co_on_jump(probe_context *c) { wrap(c, "jump", 2, 0, 0); }
CO_CB void co_on_add(probe_context *c) { wrap(c, "add", 2, 0, 0); }
CO_CB void co_on_outer(probe_context *c) { wrap(c, "outer", 1, 0, 0); }
CO_CB void co_on_slow(probe_context *c) { wrap(c, "slow", 1, 0, 0); }
CO_CB void co_on_vslow(probe_context *c) { wrap(c, "vslow", 1, 0, 0); }
CO_CB void co_on_after(probe_context *c) { send_log(c, "co after"); }
CO_CB void co_on_inner(probe_context *c) { send_log(c, "co inner"); }
// nargs larger than the real count (co_add takes 2): harmless, and the delta shows return_from.
CO_CB void co_on_nargs(probe_context *c) { wrap(c, "nargs", 8, 1000, 0); }

// Calling conventions. x86 return_from's nargs = the STACK arguments the callee pops:
// __fastcall co_fast(a, b, c) has one (a, b in ECX/EDX), __thiscall CoThis(a, b) two.
CO_CB void co_on_fast(probe_context *c) { wrap(c, "fast", 3, 1, 1); }
CO_CB void co_on_this(probe_context *c) { wrap(c, "this", 2, 1, 2); }
// co_args8: the 8th argument (a stack argument on both arches) is rewritten to 100 first.
CO_CB void co_on_args8(probe_context *c) {
    const uint64_t sp = get_reg(c, PROBE_REG_SP);
#if defined(_WIN64)
    uint64_t h = 100; set_mem(c, sp + 8 + 8 * 7, &h, 8);
#else
    uint32_t h = 100; set_mem(c, sp + 4 + 4 * 7, &h, 4);
#endif
    wrap(c, "args8", 8, 0, 0);
}

// A mid-function probe (CoMidPush+1, after `push rbx`): both calls must refuse; the function
// returns its normal value.
CO_CB void co_on_mid(probe_context *c) {
    uint64_t r = 0;
    int ok = call_original(c, 1, &r);
    return_from(c, 999, 0);
    send_log(c, "co mid ok=%d", ok);
}

// A pure replacement at a function whose prologue saves callee-saved registers: the prologue
// never runs, the caller's registers are untouched.
CO_CB void co_on_prologue(probe_context *c) { send_log(c, "co prologue"); return_from(c, 77, 0); }

// A probe on the hit's return-to address, added from the first hit.
static std::atomic<int> g_ret_added{0};
CO_CB void co_on_retsite(probe_context *c) { send_log(c, "co retsite"); }
CO_CB void co_on_ret(probe_context *c) {
    if (!g_ret_added.exchange(1)) {
        uint64_t ret = 0;
        const co_cfg *k = (const co_cfg *)get_config(c);
        get_mem(c, get_reg(c, PROBE_REG_SP), &ret, sizeof(void *));
        if (!k || !probe_add_address(get_session(c), ret, co_on_retsite, k->backend))
            send_log(c, "co FAIL retsite add");
    }
    wrap(c, "ret", 1, 0, 0);
}
