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
