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

// prot: is this hit on one of the agent's own threads (started at an address inside this
// module: probe_agent_init/stop, the service thread)? No stack capture here: the loader calls
// NtProtectVirtualMemory while holding the function-table lock a stack walk needs.
extern "C" IMAGE_DOS_HEADER __ImageBase;
using nqit_fn = LONG (NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
static const nqit_fn g_nqit = reinterpret_cast<nqit_fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
AR_CB void ar_on_prot(probe_context *c) {
    void *start = nullptr;
    if (g_nqit) g_nqit(GetCurrentThread(), 9 /* ThreadQuerySetWin32StartAddress */, &start, sizeof(start), nullptr);
    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>((const char *)&__ImageBase + __ImageBase.e_lfanew);
    const uintptr_t lo = (uintptr_t)&__ImageBase, a = (uintptr_t)start;
    // Who called NtProtectVirtualMemory: ntdll itself (the loader starting/ending a thread)
    // or code outside it (VirtualProtect: the hook writes, the program).
    static const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto *nn = reinterpret_cast<const IMAGE_NT_HEADERS *>((const char *)ntdll + ((const IMAGE_DOS_HEADER *)ntdll)->e_lfanew);
    uint64_t ret = 0;
    get_mem(c, get_reg(c, PROBE_REG_SP), &ret, sizeof(void *));
    const bool via_ntdll = ret >= (uintptr_t)ntdll && ret < (uintptr_t)ntdll + nn->OptionalHeader.SizeOfImage;
    send_log(c, "ar prot agent=%d via=%s", a >= lo && a < lo + nt->OptionalHeader.SizeOfImage ? 1 : 0,
             via_ntdll ? "ntdll" : "other");
}

static SRWLOCK g_cfw_lock = SRWLOCK_INIT;               // cfwatchlock (one callback holds it across call_func)
// cfkill / cfmany / cflock (regress `callfunc-*`): call_func from a callback (cflock and
// cfmany also on breakpoint/hw: concurrent calls). A probe the
// callee hits is counted without a callback (no "ar cf-inner" from inside call_func).
AR_CB void ar_on_cf(probe_context *c) {
    const uint64_t x = get_func_arg(c, 0);
    uint64_t r = 0;
    if (x == 1) {                                       // the victim: killed inside the callee
        call_func(c, "ar_target.exe!ar_cf_block", &r, 0);
        send_log(c, "ar cf-unblocked");
    } else if (x == 5) {                                // cfwatch: a slow callee (a watch hit meanwhile)
        const int ok = call_func(c, "ar_target.exe!ar_cfw_slow", &r, 0);
        send_log(c, "ar cfw slow ok=%d r=%d", ok, (int)r);
    } else if (x == 6) {                                // cfwatchlock: a lock held across call_func
        AcquireSRWLockExclusive(&g_cfw_lock);
        const int ok = call_func(c, "ar_target.exe!ar_cfw_slow", &r, 0);
        ReleaseSRWLockExclusive(&g_cfw_lock);
        send_log(c, "ar cfw slow ok=%d r=%d", ok, (int)r);
    } else if (x == 2 || x == 4) {                      // cflock: the lock holder / the call waiting for it
        const int ok = x == 2 ? call_func(c, "ar_target.exe!ar_cf_inner", &r, 1, (uint64_t)2)
                              : call_func(c, "ar_target.exe!ar_cf_needlock", &r, 0);
        send_log(c, "ar cf-lock %s ok=%d r=%d", x == 2 ? "holder" : "waiter", ok, (int)r);
    } else if (x >= 1000) {
        const int ok = call_func(c, "ar_target.exe!ar_cf_gate", &r, 1, x);
        send_log(c, "ar cf-many ok=%d good=%d", ok, (uint32_t)r == (uint32_t)(x * 3) ? 1 : 0);
    } else {
        send_log(c, "ar cf");
    }
}
AR_CB void ar_on_cf_inner(probe_context *c) { send_log(c, "ar cf-inner"); }

// drrestore (regress `hw-dr-restore`): arms the probe on ar_dr_site at runtime, on every thread.
AR_CB void ar_on_dr_site(probe_context *c) { send_log(c, "ar dr x=%d", (int)get_func_arg(c, 0)); }
AR_CB void ar_on_dr_arm(probe_context *c) {
    if (!probe_add_symbol(get_session(c), "ar_target.exe!ar_dr_site", ar_on_dr_site, PROBE_HW)) send_log(c, "ar dr refused");
}

// absret (regress `inline-absolute-*`): the callee's entry probe adds an inline probe at its
// return site, BY ADDRESS (once); that site is followed by a loop head inside its 5 bytes.
AR_CB void ar_on_d5_ret(probe_context *c) { send_log(c, "ar d5 ret"); }
static void d5_add(probe_context *c, uint32_t flags) {
    static volatile long once = 0;
    uint64_t ret = 0;
    if (InterlockedExchange(&once, 1) || !get_mem(c, get_reg(c, PROBE_REG_SP), &ret, sizeof(void *))) return;
    send_log(c, "ar d5 add=%d", probe_add_address(get_session(c), ret, ar_on_d5_ret, flags));
}
AR_CB void ar_on_d5_callee(probe_context *c) { d5_add(c, PROBE_INLINE); }
AR_CB void ar_on_d5_callee_fb(probe_context *c) { d5_add(c, PROBE_INLINE | PROBE_FALLBACK_HW); }

// cfwatch (regress `callfunc-watch-*`): a write watch whose callback call_funcs.
AR_CB void ar_on_cfw_watch(probe_context *c) {
    uint64_t r = 0;
    const int ok = call_func(c, "ar_target.exe!ar_cf_inner", &r, 1, (uint64_t)3);
    send_log(c, "ar cfw watch ok=%d r=%d", ok, (int)r);
}
AR_CB void ar_on_cfw_setup(probe_context *c) {
    send_log(c, "ar cfw setup=%d", probe_watch(get_session(c), get_func_arg(c, 0), ar_on_cfw_watch, PROBE_WATCH_WRITE));
}

// coborrow (regress `hw-co-borrow-restore`): call_original + return_from.
AR_CB void ar_on_cob(probe_context *c) {
    uint64_t r = 0;
    const int ok = call_original(c, 1, &r);
    if (ok) return_from(c, r, 0);
    send_log(c, "ar cob ok=%d r=%d", ok, (int)r);
}
// cfwatchlock: the watch callback takes the lock another callback holds across call_func.
AR_CB void ar_on_cfwl_watch(probe_context *c) {
    AcquireSRWLockExclusive(&g_cfw_lock);
    uint64_t r = 0;
    const int ok = call_func(c, "ar_target.exe!ar_cf_inner", &r, 1, (uint64_t)3);
    ReleaseSRWLockExclusive(&g_cfw_lock);
    send_log(c, "ar cfw watch ok=%d r=%d", ok, (int)r);
}
AR_CB void ar_on_cfwl_setup(probe_context *c) {
    send_log(c, "ar cfw setup=%d", probe_watch(get_session(c), get_func_arg(c, 0), ar_on_cfwl_watch, PROBE_WATCH_WRITE));
}

// drresume (regress `hw-dr-restore-first`): a hw probe at the given address.
AR_CB void ar_on_dr2_site(probe_context *c) { send_log(c, "ar dr2 hit"); }
AR_CB void ar_on_dr2_arm(probe_context *c) {
    if (!probe_add_address(get_session(c), get_func_arg(c, 0), ar_on_dr2_site, PROBE_HW)) send_log(c, "ar dr2 refused");
}

// cdx-agent-*: callback effects deliberately left for the agent to restore.
#include "ar_review.hpp"
#include <initializer_list>
#include <intrin.h>
#include <immintrin.h>
AR_CB void ar_on_empty(probe_context *) {}
AR_CB void ar_on_cache(probe_context *c) {
    const uint64_t p = get_func_arg(c, 0);
    unsigned char byte = 0;
    const int first = get_mem(c, p, &byte, 1);
    uint64_t ret = 0;
    const int called = call_func(c, "ar_target.exe!ar_guard_buffer", &ret, 1, p);
    const int second = get_mem(c, p, &byte, 1);
    send_log(c, "ar cache first=%d called=%d guarded=%llu second=%d", first, called, (unsigned long long)ret, second);
}
AR_CB void ar_on_guarantee(probe_context *c) {
    send_log(c, "ar guarantee");
    ULONG want = 128 * 1024;
    SetThreadStackGuarantee(&want);
    uint64_t r = 0;
    call_original(c, 0, &r);                           // unwinds to the program's own handler
}
AR_CB void ar_on_epoch(probe_context *c) {
    auto *control = (ArEpochControl *)(uintptr_t)get_func_arg(c, 0);
    const auto *config = (const LONG *)get_config(c);
    SetEvent(control->entered);
    WaitForSingleObject(control->release, 30000);
    control->observed = config ? *config : -1;
    send_log(c, "ar epoch %ld", control->observed);
}
AR_CB void ar_on_vector(probe_context *c) {
    send_log(c, "ar vector");
    int cp[4]; __cpuid(cp, 1);
    if (!(cp[2] & (1 << 27))) return;
    const uint64_t enabled = _xgetbv(0);
    if ((enabled & 6) != 6) return;
    uint64_t mask = 6ull | ((enabled & 0xE0) == 0xE0 ? 0x20ull : 0);
    alignas(64) unsigned char area[4096] = {};
#if defined(_WIN64)
    _fxsave64(area);                                    // preserve ABI-nonvolatile XMM6..15
#else
    _fxsave(area);
    mask |= 1ull;
    *(unsigned short *)(area + 0) = 0x027F;
    *(unsigned short *)(area + 2) = 0;
    area[4] = 1;                                       // dirty ST0 as well as the control word
    *(uint64_t *)(area + 32) = 0x8000000000000000ull;
    *(unsigned short *)(area + 40) = 0x3FFF;
#endif
    *(unsigned int *)(area + 24) = _mm_getcsr() ^ 0x2000u;
#if defined(_WIN64)
    const int xmm_count = 6;
#else
    const int xmm_count = 8;
#endif
    for (int j = 0; j < xmm_count * 16; ++j) area[160 + j] = 0xA5;
    *(uint64_t *)(area + 512) = mask;
    for (int i : {2, 5}) {
        if (!(mask & (1ull << i))) continue;
        __cpuidex(cp, 0xD, i);
        if ((unsigned)cp[1] + (unsigned)cp[0] > sizeof(area)) return;
        for (int j = 0; j < cp[0]; ++j) area[cp[1] + j] = 0xFF;
    }
#if defined(_WIN64)
    _xrstor64(area, mask);
#else
    _xrstor(area, mask);
#endif
}

// Retained image sections must still be shared by mixed backends after reattach.
UHH_SHARED static volatile LONG ar_shared_value = 0;
AR_CB void ar_on_shared_write(probe_context *c) { ar_shared_value = (LONG)get_func_arg(c, 0); }
AR_CB void ar_on_shared_read(probe_context *c) { send_log(c, "ar shared %ld", ar_shared_value); }
AR_CB void ar_on_vector_call(probe_context *c) {
    uint64_t r = 0;
    const int ok = call_func(c, "ar_target.exe!ar_vector_clobber", &r, 0);
    send_log(c, "ar vector call %d", ok);
}
AR_CB void ar_on_config_late(probe_context *c) {
    const auto *cfg = (const unsigned char *)get_config(c);
    return_from(c, cfg ? cfg[4095] : 0, 0);
}
