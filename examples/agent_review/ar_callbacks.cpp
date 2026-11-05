// Inline-agent review (regress `agent-*`): ONE callback source, built into ar_driver (for
// breakpoint/hw) and into the agent (inline). Every log starts "ar ".
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "probe_api.h"
#include <stdint.h>

#define AR_CB extern "C" __declspec(dllexport)

// unwind: a plain logging probe ON a call instruction / a faulting load.
AR_CB void ar_on_site(probe_context *c) { send_log(c, "ar site"); }

// faultafter: the original runs, its result is chosen as the return value, then the callback
// faults. The original must not run a second time.
static void fault_now() { *(volatile int *)(uintptr_t)8 = 1; }
AR_CB void ar_on_fault_ret(probe_context *c) {
    uint64_t r = 0;
    if (!call_original(c, 1, &r)) { send_log(c, "ar refused"); return; }
    return_from(c, r, 0);                               // ar_body is cdecl
    send_log(c, "ar fault-ret");
    fault_now();
}
AR_CB void ar_on_fault_noret(probe_context *c) {        // no return_from: the original's result
    uint64_t r = 0;
    if (!call_original(c, 1, &r)) { send_log(c, "ar refused"); return; }
    send_log(c, "ar fault-noret");
    fault_now();
}

// threadinit: an allocating callback on the allocator (it re-enters its own probe).
AR_CB void ar_on_alloc(probe_context *) {
    HANDLE h = GetProcessHeap();
    if (void *p = HeapAlloc(h, 0, 24)) HeapFree(h, 0, p);
}

// ljframe0
AR_CB void ar_on_jump(probe_context *c) {
    send_log(c, "ar jump");
    uint64_t r = 0;
    if (!call_original(c, 2, &r)) { send_log(c, "ar refused"); return; }
    send_log(c, "ar jump-done");                        // not reached when the original longjmp'd
    return_from(c, r, 0);
}
AR_CB void ar_on_after(probe_context *c) { send_log(c, "ar after"); }

// prot: the stack says who called NtProtectVirtualMemory.
AR_CB void ar_on_prot(probe_context *c) { send_log_stack(c, "ar prot"); }
