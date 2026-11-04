// The malloc -> watch chain as three ordinary callbacks. This one source file is
// compiled into the driver (controller-side backends) AND into the agent DLL (inline
// backend); exports let either side find the other's copy by name.
//
//   on_malloc  (malloc entry)        size == 0x1337 ?  read the return address,
//                                    add a ONE-SHOT probe there
//   on_return  (malloc's caller)     AX = the new block: watch it for writes
//   on_write   (data watchpoint)     every store to the block: count + log with stack
//
// Every control call goes through get_session(c), so the chain is identical whether
// on_malloc runs as a breakpoint/hardware callback (in the controller) or as an inline
// hook (inside the target -- the calls are forwarded to the controller).
#include "probe_api.h"
#include "dynwatch_callbacks.h"

#define TRACKED_SIZE 0x1337

static long g_watch_hits, g_arms, g_returns;   // controller-side callbacks run on the debug-loop thread

extern "C" DYNWATCH_EXPORT void dynwatch_on_write(probe_context *c) {
    long n = ++g_watch_hits;
    if (n <= 2) send_log_stack(c, "write to tracked block");   // stack rides in the same record
}

extern "C" DYNWATCH_EXPORT void dynwatch_on_return(probe_context *c) {
    ++g_returns;
    uint64_t block = get_reg(c, PROBE_REG_AX);
    g_arms += probe_watch(get_session(c), block, dynwatch_on_write, PROBE_WATCH_WRITE);
    send_log(c, "malloc(0x1337) returned; watching");
}

// Runs as an INLINE hook added at runtime (counted via the probe's hit count).
extern "C" DYNWATCH_EXPORT void dynwatch_on_marker(probe_context *c) { (void)c; }

extern "C" DYNWATCH_EXPORT void dynwatch_on_malloc(probe_context *c) {
    if (get_func_arg(c, 0) != TRACKED_SIZE) return;           // ignore CRT/noise allocations
    // An inline hook added from inside a callback -- with --entry inline, from inside an
    // inline hook. Installed asynchronously on a fresh agent thread.
    probe_add_symbol(get_session(c), "dynwatch_target.exe!dynwatch_marker", dynwatch_on_marker, PROBE_INLINE);
    uint64_t ret = 0;
    if (!get_mem(c, get_reg(c, PROBE_REG_SP), &ret, sizeof(void *))) return;   // return address
    probe_add_address(get_session(c), ret, dynwatch_on_return, PROBE_BREAKPOINT | PROBE_ONCE);
}

extern "C" long dynwatch_watch_hits(void) { return g_watch_hits; }
extern "C" long dynwatch_arms(void) { return g_arms; }
extern "C" long dynwatch_returns(void) { return g_returns; }
