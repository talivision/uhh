// Transparency fixture: ONE callback source for every backend (built into tp_driver for
// breakpoint/hw and into the agent for inline). The probe's config picks what the callback
// does; none of it may be visible to the target (regress `transparency`). Problems the
// callback itself can see are logged as "tp FAIL ...".
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "probe_api.h"
#include <stdint.h>

#define TP_CB extern "C" __declspec(dllexport)

struct tp_cfg { uint32_t mode, nargs, pop, backend; };
enum { TP_NOOP, TP_LOG, TP_MEM, TP_SYS, TP_CALLFN, TP_CO };

// x86: a double comes back in ST0 -- the callback's own x87 traffic.
static __declspec(noinline) double tp_cb_math(double x) { return x * 1.5 + 0.125; }

typedef LONG(NTAPI *NtQSI_t)(ULONG, void *, ULONG, ULONG *);

TP_CB void tp_on_hit(probe_context *c) {
    const tp_cfg *k = (const tp_cfg *)get_config(c);
    if (!k) { send_log(c, "tp FAIL no config"); return; }
    switch (k->mode) {
    case TP_NOOP:
        return;
    case TP_LOG: {
        volatile double v = tp_cb_math((double)(get_reg(c, PROBE_REG_SP) & 0xFF));
        send_log(c, "tp log ax=%llx v=%.3f", (unsigned long long)get_reg(c, PROBE_REG_AX), (double)v);
        send_log_stack(c, "tp stack");
        return;
    }
    case TP_MEM: {
        unsigned char buf[64];
        if (!get_mem(c, get_reg(c, PROBE_REG_SP), buf, sizeof(buf))) send_log(c, "tp FAIL get_mem at SP");
        uint64_t sum = 0;
        for (size_t i = 0; i < 4; ++i) sum += get_func_arg(c, i);
        for (int r = PROBE_REG_AX; r <= PROBE_REG_R15; ++r) sum += get_reg(c, (enum probe_register)r);
        unsigned char probe16[16];        // whatever arg 0 points at (tp_peek: a page that changes)
        sum += get_mem(c, get_func_arg(c, 0), probe16, sizeof(probe16));
        send_log(c, "tp mem %llx", (unsigned long long)sum);
        return;
    }
    case TP_SYS: {
        // Win32/NT calls on the hit thread (inline): last error, last status, x87.
        SetLastError(0);
        (void)GetFileAttributesA("Z:\\uhh-transparency-no-such\\missing");
        static NtQSI_t qsi = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
        ULONG len = 0; unsigned char small[4];
        if (qsi) (void)qsi(0 /* SystemBasicInformation */, small, sizeof(small), &len);   // STATUS_INFO_LENGTH_MISMATCH
        volatile double acc = 0;
        for (int i = 0; i < 4; ++i) acc = acc + tp_cb_math(acc + i);
        send_log(c, "tp sys err=%lu len=%lu acc=%.3f", GetLastError(), len, (double)acc);
        return;
    }
    case TP_CALLFN: {
        // call_func of APIs that set the last error / status, and of a PROBED function (its
        // probe counts the hit but runs no callback).
        uint64_t r = 0;
        if (!call_func(c, "kernel32!GetThreadPriority", &r, 1, (uint64_t)0)) send_log(c, "tp FAIL call_func GetThreadPriority");
        if (!call_func(c, "kernel32!TlsGetValue", &r, 1, (uint64_t)1000)) send_log(c, "tp FAIL call_func TlsGetValue");
        if (!call_func(c, "tp_target.exe!tp_add", &r, 2, (uint64_t)5, (uint64_t)6) || r != 21)
            send_log(c, "tp FAIL call_func tp_add -> %llu", (unsigned long long)r);
        send_log(c, "tp callfn");
        return;
    }
    case TP_CO: {
        uint64_t r = 0;
        if (call_original(c, (int)k->nargs, &r)) return_from(c, r, (int)k->pop);
        return;                          // refused (the mid-function site): falls through
    }
    default:
        send_log(c, "tp FAIL mode %u", k->mode);
    }
}

// tp_spawn(fn, arg): create a thread in the target, during the hit, that runs fn(arg) (the
// probed tp_threadfn), then let the hit continue.
TP_CB void tp_on_spawn(probe_context *c) {
    uint64_t h = 0, ok = 0;
    if (!call_func(c, "kernel32!CreateThread", &h, 6, (uint64_t)0, (uint64_t)0, get_func_arg(c, 0), get_func_arg(c, 1),
                   (uint64_t)0, (uint64_t)0) || !h) {
        send_log(c, "tp FAIL CreateThread");
        return;
    }
    call_func(c, "kernel32!CloseHandle", &ok, 1, h);
    send_log(c, "tp spawned");
    tp_on_hit(c);
}

// tp_ovf: the callback overflows its stack (deep recursion), and is abandoned. The thread
// must keep its guard page: the program's own later overflow is still a catchable
// EXCEPTION_STACK_OVERFLOW.
static __declspec(noinline) int tp_cb_deep(int d) {
    volatile char pad[2048]; pad[0] = (char)d;
    return pad[0] + tp_cb_deep(d + 1) + pad[2047];
}
TP_CB void tp_on_ovf(probe_context *c) {
    send_log(c, "tp ovf");
    (void)tp_cb_deep(0);
}
