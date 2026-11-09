// ctrl_target -- fixtures for the controller review findings (regress `ctrl-*`).
//
//   ctrl_target fault [--n N]           probed load faults on a reserved / guard page; the VEH
//                                       commits it (or just continues) -> CONTINUE_EXECUTION
//   ctrl_target inplace [--threads T] [--n N]
//                                       T threads x N calls of CtrlLoop(tag), whose probed
//                                       instruction takes the in-place software-breakpoint path
//   ctrl_target absunload [--cycles C] [--n N]
//                                       load ctrl_dll, announce CtrlDllWork / CtrlDllCounter
//                                       (the callback probes / watches them by address), call
//                                       it N times, unload; C cycles
//   ctrl_target symunload [--cycles C] [--n N]
//                                       N stack-logged calls inside ctrl_dll, then unload at once
//   ctrl_target owndr [--n N]           the target's OWN hardware watchpoints (set with
//                                       SetThreadContext on itself, caught by its VEH) while
//                                       UHH arms / releases hardware probes
//   ctrl_target headcorrupt             write a huge log_head into the agent's shared section
//   ctrl_target faultreg [--n N]        the probed load faults; the VEH repairs it by pointing the
//                                       base register at valid memory and retries (cdx-faultreg)
//   ctrl_target faultmix [--n N]        the probed load faults; the handler retries it, skips it or
//                                       unwinds out of it (SEH), in turn (cx2-faultfresh)
//   ctrl_target owndrx [--n N]          the target's own watch on an address UHH watched once and
//                                       released, from a thread that existed then (cdx-owndrx)
//   ctrl_target absreuse                absolute INT3 in an unloaded DLL; its address reused (cdx-absreuse)
//   ctrl_target cfreuse                 call_func into a DLL that unloads and whose name and base
//                                       another DLL then takes (cdx-cfreuse)
//   ctrl_target cfrace | cfpin          call_func stalled (agent test knob UHH_TEST_CF_STALL) while
//                                       another thread unloads the callee's DLL (cfrace: and maps
//                                       another at its base) (cdx-cfrace / cdx-cfpin, inline)
//   ctrl_target cfnx                    call_func into module code whose execute rights the program
//                                       removes between calls: must refuse, not fault (cdx-cfnx)
//   ctrl_target codeprot                inline stack capture while the program guards / no-accesses
//                                       a code page of a loaded module (cdx-codeprot)
//   ctrl_target int3cap [--n N]         N armed INT3s read back with get_mem (cdx-int3cap)
//   ctrl_target bigcfg                  a dynamic add with a > 64 MiB config (cdx-bigcfg)
//   ctrl_target shape --shape S [--threads T] [--n N]
//                                       T threads x N calls of Shape_S_P (probed: a branch / call /
//                                       ret / loop / pushf / ... shape, ctrl_shapes_*.asm), each
//                                       followed by its never-probed twin Shape_S_R: the results
//                                       must match call by call (and a pushed flags image must not
//                                       carry a trap flag; a push into the stack guard page must
//                                       grow the stack as without UHH)
//
// Each prints one {"kind":"ctrl_result",...} line.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" int CtrlLoad(const int *p);
extern "C" uint32_t CtrlLoop(uint32_t tag);
extern "C" void CtrlSled(void);

// Codex-review sites (cdx-*): the probes' callbacks do the work (ctrl_callbacks.cpp).
extern "C" __declspec(dllexport) __declspec(noinline) void CtrlOp(const void *addr, uintptr_t n, uintptr_t mode) {
    static volatile uintptr_t sink[3];
    sink[0] = (uintptr_t)addr; sink[1] = n; sink[2] = mode;
}
// The probe's callback call_funcs "cfr.dll!CfrValue" and logs phase / result (cdx-cfreuse).
extern "C" __declspec(dllexport) __declspec(noinline) void CtrlCall(uintptr_t phase) {
    static volatile uintptr_t sink; sink = phase;
}
extern "C" __declspec(dllexport) __declspec(noinline) void CtrlWatchOnce(volatile LONG *var) {
    static volatile void *sink; sink = (void *)var;
}
extern "C" __declspec(dllexport) __declspec(noinline) void CtrlBigCfg(void) {
    static volatile int sink; sink = 1;
}

extern "C" __declspec(dllexport) __declspec(noinline) void CtrlAnnounce(void *work, void *counter) {
    static volatile void *sink[2];
    sink[0] = work; sink[1] = counter;
}
extern "C" __declspec(dllexport) __declspec(noinline) int CtrlTock(int x) {
    static volatile int sink; sink = x; return x + 1;
}
extern "C" __declspec(dllexport) __declspec(noinline) int CtrlTick(void *tock) {
    static volatile void *sink; sink = tock; return 1;
}

extern "C" __declspec(dllexport) __declspec(noinline) void CtrlApi(uintptr_t mode, void *addr, void *data) {
    static volatile uintptr_t sink[3];
    sink[0] = mode; sink[1] = (uintptr_t)addr; sink[2] = (uintptr_t)data;
}

static int arg_int(int argc, char **argv, const char *name, int def) {
    for (int i = 2; i + 1 < argc; ++i) if (!std::strcmp(argv[i], name)) return std::atoi(argv[i + 1]);
    return def;
}

// ---- fault -------------------------------------------------------------------------
static char *volatile g_page = nullptr;
static volatile LONG g_av = 0, g_guard = 0, g_tf = 0, g_stray = 0;

static LONG CALLBACK fault_veh(EXCEPTION_POINTERS *e) {
    const DWORD code = e->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_SINGLE_STEP) {                 // a trap flag the program never set
        InterlockedIncrement(&g_stray);
        e->ContextRecord->EFlags &= ~0x100u;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if ((code != EXCEPTION_ACCESS_VIOLATION && code != STATUS_GUARD_PAGE_VIOLATION) ||
        e->ExceptionRecord->NumberParameters < 2)
        return EXCEPTION_CONTINUE_SEARCH;
    char *a = (char *)e->ExceptionRecord->ExceptionInformation[1];
    if (!g_page || a < g_page || a >= g_page + 4096) return EXCEPTION_CONTINUE_SEARCH;
    if (e->ContextRecord->EFlags & 0x100u) InterlockedIncrement(&g_tf);
    if (code == EXCEPTION_ACCESS_VIOLATION) {            // lazy commit
        if (!VirtualAlloc(g_page, 4096, MEM_COMMIT, PAGE_READWRITE)) return EXCEPTION_CONTINUE_SEARCH;
        InterlockedIncrement(&g_av);
    } else {
        InterlockedIncrement(&g_guard);                  // the guard is already gone: retry
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

static int run_fault(int n) {
    PVOID h = AddVectoredExceptionHandler(1, fault_veh);
    long long sum = 0;
    for (int i = 0; i < n; ++i) {
        char *p;
        if (i % 2 == 0) {
            p = (char *)VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_NOACCESS);
        } else {
            p = (char *)VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (p) { p[0] = 7; DWORD old; VirtualProtect(p, 4096, PAGE_READWRITE | PAGE_GUARD, &old); }
        }
        if (!p) { std::printf("{\"kind\":\"ctrl_result\",\"error\":\"alloc\"}\n"); return 1; }
        g_page = p;
        sum += CtrlLoad((const int *)p);
        g_page = nullptr;
        VirtualFree(p, 0, MEM_RELEASE);
    }
    RemoveVectoredExceptionHandler(h);
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"fault\",\"n\":%d,\"av\":%ld,\"guard\":%ld,\"tf\":%ld,"
                "\"stray\":%ld,\"sum\":%lld}\n", n, g_av, g_guard, g_tf, g_stray, sum);
    return 0;
}

// ---- inplace -----------------------------------------------------------------------
struct LoopArg { uint32_t t, n; uint64_t bad; };
static DWORD WINAPI loop_thread(void *p) {
    LoopArg *a = (LoopArg *)p;
    for (uint32_t i = 0; i < a->n; ++i) {
        uint32_t tag = (a->t << 20) | i;
        if (CtrlLoop(tag) != tag) ++a->bad;
    }
    return 0;
}
static int run_inplace(int threads, int n) {
    std::vector<LoopArg> args(threads);
    std::vector<HANDLE> hs;
    int started = 0;
    for (int t = 0; t < threads; ++t) {
        args[t] = LoopArg{(uint32_t)t + 1, (uint32_t)n, 0};
        HANDLE h = CreateThread(nullptr, 0, loop_thread, &args[t], 0, nullptr);
        if (h) { hs.push_back(h); ++started; }
    }
    // Every thread must have started and finished: a failed CreateThread or wait is a
    // fixture failure (calls would be missing for a reason that is not the probe's).
    const DWORD w = hs.empty() ? WAIT_FAILED : WaitForMultipleObjects((DWORD)hs.size(), hs.data(), TRUE, 120000);
    uint64_t bad = 0, done = 0;
    for (auto &a : args) bad += a.bad;
    for (HANDLE h : hs) { DWORD code = 1; if (GetExitCodeThread(h, &code) && code == 0) ++done; CloseHandle(h); }
    const bool ok = started == threads && w == WAIT_OBJECT_0 && done == (uint64_t)threads;
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"inplace\",\"calls\":%d,\"bad\":%llu,\"started\":%d,"
                "\"finished\":%llu,\"wait_ok\":%d}\n", threads * n, (unsigned long long)bad, started,
                (unsigned long long)done, w == WAIT_OBJECT_0);
    return ok ? 0 : 4;
}

// ---- absunload / symunload ------------------------------------------------------------
typedef LONG (*work_fn)(LONG);
static int run_absunload(int cycles, int n) {
    long long sum = 0;
    std::string bases;
    for (int c = 0; c < cycles; ++c) {
        HMODULE m = LoadLibraryA("ctrl_dll.dll");
        if (!m) { std::printf("{\"kind\":\"ctrl_result\",\"error\":\"load\"}\n"); return 1; }
        work_fn work = (work_fn)GetProcAddress(m, "CtrlDllWork");
        void *counter = (void *)GetProcAddress(m, "CtrlDllCounter");
        char b[32]; std::snprintf(b, sizeof(b), "%s\"0x%llx\"", c ? "," : "", (unsigned long long)(uintptr_t)m);
        bases += b;
        CtrlAnnounce((void *)work, counter);
        for (int i = 0; i < n; ++i) sum += work(1);
        FreeLibrary(m);
    }
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"absunload\",\"cycles\":%d,\"n\":%d,\"sum\":%lld,\"bases\":[%s]}\n",
                cycles, n, sum, bases.c_str());
    return 0;
}
static int run_symunload(int cycles, int n) {
    long long sum = 0;
    for (int c = 0; c < cycles; ++c) {
        HMODULE m = LoadLibraryA("ctrl_dll.dll");
        if (!m) { std::printf("{\"kind\":\"ctrl_result\",\"error\":\"load\"}\n"); return 1; }
        work_fn rec = (work_fn)GetProcAddress(m, "CtrlDllRecurse");
        for (int i = 0; i < n; ++i) sum += rec(12);
        FreeLibrary(m);                                  // at once: the log writer is behind
    }
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"symunload\",\"cycles\":%d,\"n\":%d,\"sum\":%lld}\n",
                cycles, n, sum);
    return 0;
}

// ---- owndr ---------------------------------------------------------------------------
static __declspec(thread) LONG t_traps = 0;
static __declspec(thread) bool t_mine = false;
static LONG CALLBACK owndr_veh(EXCEPTION_POINTERS *e) {
    if (e->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP || !t_mine) return EXCEPTION_CONTINUE_SEARCH;
    ++t_traps;
    e->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}
static bool set_own_watch(int slot, volatile LONG *var, bool on) {
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &c)) return false;
    const uintptr_t a = on ? (uintptr_t)var : 0;
    switch (slot) { case 0: c.Dr0 = a; break; case 1: c.Dr1 = a; break; case 2: c.Dr2 = a; break; default: c.Dr3 = a; }
    const DWORD64 en = (DWORD64)1 << (slot * 2), field = (DWORD64)0xF << (16 + slot * 4);
    DWORD64 d7 = c.Dr7 & ~(en | field);
    if (on) d7 |= en | ((DWORD64)((3u << 2) | 1u) << (16 + slot * 4));   // write, 4 bytes
    c.Dr7 = (decltype(c.Dr7))d7;
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return !!SetThreadContext(GetCurrentThread(), &c);
}
static int free_slot_mask() {
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &c)) return 0;
    int m = 0;
    for (int k = 0; k < 4; ++k) if (!((c.Dr7 >> (k * 2)) & 3)) m |= 1 << k;
    return m;
}
static volatile LONG g_var1 = 0, g_var2 = 0;
static HANDLE g_ready, g_go;
static int g_n = 0, g_w1_slot = -1;
static LONG g_w1 = -1;
static DWORD WINAPI owndr_w1(void *) {
    t_mine = true;
    const int fm = free_slot_mask();
    for (int k = 0; k < 4; ++k) if (fm & (1 << k)) { g_w1_slot = k; break; }
    if (g_w1_slot >= 0 && !set_own_watch(g_w1_slot, &g_var1, true)) g_w1_slot = -2;
    SetEvent(g_ready);
    WaitForSingleObject(g_go, INFINITE);
    for (int i = 0; i < g_n; ++i) g_var1 = g_var1 + 1;
    if (g_w1_slot >= 0) set_own_watch(g_w1_slot, &g_var1, false);
    g_w1 = t_traps;
    return 0;
}
static LONG g_w2[4] = {-1, -1, -1, -1};
static DWORD WINAPI owndr_w2(void *) {
    t_mine = true;
    const int fm = free_slot_mask();
    for (int k = 0; k < 4; ++k) {
        if (!(fm & (1 << k))) continue;
        if (!set_own_watch(k, &g_var2, true)) { g_w2[k] = -2; continue; }
        const LONG before = t_traps;
        for (int i = 0; i < g_n; ++i) g_var2 = g_var2 + 1;
        set_own_watch(k, &g_var2, false);
        g_w2[k] = t_traps - before;
    }
    return 0;
}
static DWORD WINAPI idle_thread(void *ev) { WaitForSingleObject((HANDLE)ev, INFINITE); return 0; }
static int run_owndr(int n) {
    g_n = n;
    PVOID h = AddVectoredExceptionHandler(1, owndr_veh);
    g_ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::vector<HANDLE> idle;
    for (int i = 0; i < 4; ++i) idle.push_back(CreateThread(nullptr, 0, idle_thread, stop, 0, nullptr));
    HANDLE w1 = CreateThread(nullptr, 0, owndr_w1, nullptr, 0, nullptr);
    WaitForSingleObject(g_ready, INFINITE);
    // Phase A: UHH arms a hardware probe at runtime (from the CtrlTick callback) while w1
    // owns one debug register; CtrlTock then fires that one-shot probe, which is released.
    CtrlTick((void *)&CtrlTock);
    CtrlTock(1);
    SetEvent(g_go);
    WaitForSingleObject(w1, INFINITE);
    // Phase B: a fresh thread uses every debug register free on it, one after the other --
    // including the one UHH has just released.
    HANDLE w2 = CreateThread(nullptr, 0, owndr_w2, nullptr, 0, nullptr);
    WaitForSingleObject(w2, INFINITE);
    SetEvent(stop);
    WaitForMultipleObjects((DWORD)idle.size(), idle.data(), TRUE, INFINITE);
    RemoveVectoredExceptionHandler(h);
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"owndr\",\"n\":%d,\"w1_slot\":%d,\"w1\":%ld,"
                "\"w2\":[%ld,%ld,%ld,%ld]}\n", n, g_w1_slot, g_w1, g_w2[0], g_w2[1], g_w2[2], g_w2[3]);
    return 0;
}

// ---- cdx-faultreg: the VEH repairs the fault by changing a REGISTER and retries ----------
static int g_good = 42;
static volatile LONG g_fix = 0;
static LONG CALLBACK faultreg_veh(EXCEPTION_POINTERS *e) {
    const DWORD code = e->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_SINGLE_STEP) {
        InterlockedIncrement(&g_stray);
        e->ContextRecord->EFlags &= ~0x100u;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code != EXCEPTION_ACCESS_VIOLATION || e->ExceptionRecord->NumberParameters < 2) return EXCEPTION_CONTINUE_SEARCH;
    char *a = (char *)e->ExceptionRecord->ExceptionInformation[1];
    if (!g_page || a < g_page || a >= g_page + 4096) return EXCEPTION_CONTINUE_SEARCH;
    if (e->ContextRecord->EFlags & 0x100u) InterlockedIncrement(&g_tf);
#if defined(_WIN64)
    e->ContextRecord->Rcx = (DWORD64)(uintptr_t)&g_good;     // the faulting load's base register
#else
    e->ContextRecord->Ecx = (DWORD)(uintptr_t)&g_good;
#endif
    InterlockedIncrement(&g_fix);
    return EXCEPTION_CONTINUE_EXECUTION;                     // retry the load at the probe site
}
static int run_faultreg(int n) {
    PVOID h = AddVectoredExceptionHandler(1, faultreg_veh);
    char *p = (char *)VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_NOACCESS);
    if (!p) { std::printf("{\"kind\":\"ctrl_result\",\"error\":\"alloc\"}\n"); return 1; }
    long long sum = 0;
    g_page = p;
    for (int i = 0; i < n; ++i) sum += CtrlLoad((const int *)p);
    g_page = nullptr;
    VirtualFree(p, 0, MEM_RELEASE);
    RemoveVectoredExceptionHandler(h);
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"faultreg\",\"n\":%d,\"fix\":%ld,\"tf\":%ld,"
                "\"stray\":%ld,\"sum\":%lld}\n", n, g_fix, g_tf, g_stray, sum);
    return 0;
}

// ---- faultmix: after a faulting probed load the program's handler retries it, SKIPS it,
// or UNWINDS out of it (SEH __except); the next call is a fresh execution of the site on the
// same thread with no other event in between: every call must be one hit (cx2-faultfresh).
static volatile LONG g_mix_mode = 0;                   // 0 retry (commit), 1 skip, 2 unwind
static volatile LONG g_skip = 0, g_retry = 0, g_unwind = 0;
static LONG CALLBACK faultmix_veh(EXCEPTION_POINTERS *e) {
    const DWORD code = e->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_SINGLE_STEP) {
        InterlockedIncrement(&g_stray);
        e->ContextRecord->EFlags &= ~0x100u;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code != EXCEPTION_ACCESS_VIOLATION || e->ExceptionRecord->NumberParameters < 2) return EXCEPTION_CONTINUE_SEARCH;
    char *a = (char *)e->ExceptionRecord->ExceptionInformation[1];
    if (!g_page || a < g_page || a >= g_page + 4096) return EXCEPTION_CONTINUE_SEARCH;
    if (e->ContextRecord->EFlags & 0x100u) InterlockedIncrement(&g_tf);
    if (g_mix_mode == 0) {                                  // commit the page, retry the load
        if (!VirtualAlloc(g_page, 4096, MEM_COMMIT, PAGE_READWRITE)) return EXCEPTION_CONTINUE_SEARCH;
        InterlockedIncrement(&g_retry);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (g_mix_mode == 1) {                                  // emulate it: skip `mov eax, [rcx]` (8B 01)
#if defined(_WIN64)
        e->ContextRecord->Rip += 2; e->ContextRecord->Rax = 5;
#else
        e->ContextRecord->Eip += 2; e->ContextRecord->Eax = 5;
#endif
        InterlockedIncrement(&g_skip);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;                        // the frame's __except unwinds
}
static int faultmix_unwind(const int *p) {
    __try { return CtrlLoad(p); }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        InterlockedIncrement(&g_unwind);
        return 9;
    }
}
static int run_faultmix(int n) {
    PVOID h = AddVectoredExceptionHandler(1, faultmix_veh);
    long long sum = 0, want = 0;
    for (int i = 0; i < n; ++i) {
        char *p = (char *)VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_NOACCESS);
        if (!p) { std::printf("{\"kind\":\"ctrl_result\",\"error\":\"alloc\"}\n"); return 1; }
        g_mix_mode = i % 3;
        g_page = p;
        sum += g_mix_mode == 2 ? faultmix_unwind((const int *)p) : CtrlLoad((const int *)p);
        want += g_mix_mode == 0 ? 0 : g_mix_mode == 1 ? 5 : 9;
        g_page = nullptr;
        VirtualFree(p, 0, MEM_RELEASE);
    }
    RemoveVectoredExceptionHandler(h);
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"faultmix\",\"n\":%d,\"retry\":%ld,\"skip\":%ld,\"unwind\":%ld,"
                "\"tf\":%ld,\"stray\":%ld,\"sum\":%lld,\"want\":%lld}\n", n, g_retry, g_skip, g_unwind, g_tf, g_stray, sum, want);
    return 0;
}

// ---- cdx-owndrx: the target's own watch on an address UHH watched once and released -----
static volatile LONG g_var3 = 0;
static LONG g_wx[4] = {-1, -1, -1, -1};
static DWORD WINAPI owndrx_thread(void *) {           // exists BEFORE UHH's release
    t_mine = true;
    WaitForSingleObject(g_go, INFINITE);
    const int fm = free_slot_mask();
    for (int k = 3; k >= 0; --k) {
        if (!(fm & (1 << k))) continue;
        if (!set_own_watch(k, &g_var3, true)) { g_wx[k] = -2; continue; }
        const LONG before = t_traps;
        for (int i = 0; i < g_n; ++i) g_var3 = g_var3 + 1;
        set_own_watch(k, &g_var3, false);
        g_wx[k] = t_traps - before;
    }
    return 0;
}
static int run_owndrx(int n) {
    g_n = n;
    PVOID h = AddVectoredExceptionHandler(1, owndr_veh);
    g_go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE w = CreateThread(nullptr, 0, owndrx_thread, nullptr, 0, nullptr);
    CtrlWatchOnce(&g_var3);                            // UHH: one-shot watch on g_var3
    g_var3 = 1;                                        // fires (this thread), released
    SetEvent(g_go);
    WaitForSingleObject(w, INFINITE);
    RemoveVectoredExceptionHandler(h);
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"owndrx\",\"n\":%d,\"w\":[%ld,%ld,%ld,%ld]}\n",
                n, g_wx[0], g_wx[1], g_wx[2], g_wx[3]);
    return 0;
}

// ---- cdx-absreuse: an absolute INT3 in a DLL that unloads; its address is then reused -----
static int run_absreuse() {
    HMODULE m = LoadLibraryA("ctrl_dll.dll");
    if (!m) { std::printf("{\"kind\":\"ctrl_result\",\"error\":\"load\"}\n"); return 1; }
    work_fn work = (work_fn)GetProcAddress(m, "CtrlDllWork");
    const uintptr_t at = (uintptr_t)work;
    CtrlOp((const void *)at, 1, 0);                    // UHH: software breakpoint at CtrlDllWork
    long long sum = work(1);
    FreeLibrary(m);                                    // the breakpoint is retired with the DLL
    // Reuse the range: new memory at the same address holds a REAL 0xCC there.
    void *r = VirtualAlloc((void *)(at & ~(uintptr_t)0xFFFF), 0x20000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    const bool reused = r == (void *)(at & ~(uintptr_t)0xFFFF);
    if (reused) std::memset((void *)(at & ~(uintptr_t)0xFFF), 0xCC, 4096);
    if (reused) CtrlOp((const void *)at, 16, 1);       // get_mem must read the 16 0xCC bytes
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"absreuse\",\"reused\":%d,\"sum\":%lld}\n",
                reused ? 1 : 0, sum);
    return 0;
}

// ---- cdx-cfreuse: call_func into a DLL that unloads; another takes its name and base -------
// ctrl_cfr_a.dll and ctrl_cfr_b.dll are copied to <temp>\uhh-cfr-<pid>\{a,b}\cfr.dll (one
// name, one fixed base). Phase 1: A loaded (CfrValue = 1, three calls: the second and third
// may come from a cache); phase 2: nothing named cfr.dll loaded (call_func must fail, not call
// into the unmapped image); phase 3: B loaded at A's base (CfrValue = 2; A's address in B is
// CfrDecoy = 99).
static int run_cfreuse() {
    wchar_t self[MAX_PATH], tmp[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH) || !GetTempPathW(MAX_PATH, tmp)) return 1;
    std::wstring dir(self); dir.resize(dir.find_last_of(L'\\') + 1);
    const std::wstring root = std::wstring(tmp) + L"uhh-cfr-" + std::to_wstring(GetCurrentProcessId());
    const std::wstring a = root + L"\\a\\cfr.dll", b = root + L"\\b\\cfr.dll";
    CreateDirectoryW(root.c_str(), nullptr);
    CreateDirectoryW((root + L"\\a").c_str(), nullptr); CreateDirectoryW((root + L"\\b").c_str(), nullptr);
    if (!CopyFileW((dir + L"ctrl_cfr_a.dll").c_str(), a.c_str(), FALSE) ||
        !CopyFileW((dir + L"ctrl_cfr_b.dll").c_str(), b.c_str(), FALSE)) {
        std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"cfreuse\",\"error\":\"copy\"}\n"); return 1;
    }
    HMODULE ma = LoadLibraryW(a.c_str());
    const uintptr_t base_a = (uintptr_t)ma;
    for (int i = 0; i < 3 && ma; ++i) CtrlCall(1);
    if (ma) FreeLibrary(ma);
    const bool gone = GetModuleHandleW(L"cfr.dll") == nullptr;
    CtrlCall(2);
    HMODULE mb = LoadLibraryW(b.c_str());
    const uintptr_t base_b = (uintptr_t)mb;
    for (int i = 0; i < 3 && mb; ++i) CtrlCall(3);
    if (mb) FreeLibrary(mb);
    DeleteFileW(a.c_str()); DeleteFileW(b.c_str());
    RemoveDirectoryW((root + L"\\a").c_str()); RemoveDirectoryW((root + L"\\b").c_str()); RemoveDirectoryW(root.c_str());
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"cfreuse\",\"loaded\":%d,\"gone\":%d,\"same_base\":%d}\n",
                ma && mb ? 1 : 0, gone ? 1 : 0, ma && base_a == base_b ? 1 : 0);
    return 0;
}

// ---- cdx-cfrace / cdx-cfpin (codex5 #1): the unload lands INSIDE one call_func ------------
// The agent's test knob (UHH_TEST_CF_STALL=resolved|pinned) stops the phase-4 call_func once,
// right after it resolved cfr.dll!CfrValue (A's), before / after pinning the module, and
// signals Local\uhh_test_cf_<pid>; a second thread then frees A (cfrace: and loads B at A's
// base, CfrDecoy = 99 where A's CfrValue was) and releases it (Local\uhh_test_cf_go_<pid>).
// cfrace: the call must reach B's CfrValue (2: resolved again) or be refused -- never 99.
// cfpin: the pinned module stays mapped across the FreeLibrary (held), the call reaches A's
// CfrValue (1), and A is really unmapped once the call is done (gone_after); phase 5 (nothing
// named cfr.dll loaded) is refused.
static bool image_at(uintptr_t base) {
    MEMORY_BASIC_INFORMATION mbi{};
    return base && VirtualQuery((void *)base, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
           mbi.Type == MEM_IMAGE && (uintptr_t)mbi.AllocationBase == base;
}
struct CfRace { HANDLE at, go; HMODULE ma, mb; const wchar_t *b; bool pin; int stalled, held; };
static DWORD WINAPI cfrace_thread(void *p) {
    CfRace &x = *(CfRace *)p;
    x.stalled = WaitForSingleObject(x.at, 30000) == WAIT_OBJECT_0;   // the call_func is stopped
    FreeLibrary(x.ma);
    x.held = image_at((uintptr_t)x.ma);                  // still mapped: a reference outlived ours
    if (!x.pin) x.mb = LoadLibraryW(x.b);                // B at A's base (fixed base, A is gone)
    SetEvent(x.go);
    return 0;
}
static int run_cfrace(bool pin) {
    const char *sc = pin ? "cfpin" : "cfrace";
    wchar_t self[MAX_PATH], tmp[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH) || !GetTempPathW(MAX_PATH, tmp)) return 1;
    std::wstring dir(self); dir.resize(dir.find_last_of(L'\\') + 1);
    const std::wstring root = std::wstring(tmp) + L"uhh-" + std::wstring(pin ? L"cfpin-" : L"cfrace-") +
                              std::to_wstring(GetCurrentProcessId());
    const std::wstring a = root + L"\\a\\cfr.dll", b = root + L"\\b\\cfr.dll";
    CreateDirectoryW(root.c_str(), nullptr);
    CreateDirectoryW((root + L"\\a").c_str(), nullptr); CreateDirectoryW((root + L"\\b").c_str(), nullptr);
    if (!CopyFileW((dir + L"ctrl_cfr_a.dll").c_str(), a.c_str(), FALSE) ||
        !CopyFileW((dir + L"ctrl_cfr_b.dll").c_str(), b.c_str(), FALSE)) {
        std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"%s\",\"error\":\"copy\"}\n", sc); return 1;
    }
    const std::wstring pid = std::to_wstring(GetCurrentProcessId());
    HANDLE at = CreateEventW(nullptr, FALSE, FALSE, (L"Local\\uhh_test_cf_" + pid).c_str());
    HANDLE go = CreateEventW(nullptr, TRUE, FALSE, (L"Local\\uhh_test_cf_go_" + pid).c_str());
    CfRace r{};
    r.at = at; r.go = go; r.b = b.c_str(); r.pin = pin;
    r.ma = LoadLibraryW(a.c_str());
    const uintptr_t base_a = (uintptr_t)r.ma;
    if (!at || !go || !r.ma) {
        std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"%s\",\"error\":\"setup\"}\n", sc); return 1;
    }
    HANDLE t = CreateThread(nullptr, 0, cfrace_thread, &r, 0, nullptr);
    CtrlCall(4);
    WaitForSingleObject(t, INFINITE); CloseHandle(t);
    const int gone_after = !image_at(base_a) || (r.mb && (uintptr_t)r.mb == base_a);
    CtrlCall(5);
    if (r.mb) FreeLibrary(r.mb);
    CloseHandle(at); CloseHandle(go);
    DeleteFileW(a.c_str()); DeleteFileW(b.c_str());
    RemoveDirectoryW((root + L"\\a").c_str()); RemoveDirectoryW((root + L"\\b").c_str()); RemoveDirectoryW(root.c_str());
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"%s\",\"stalled\":%d,\"held\":%d,\"gone_after\":%d,"
                "\"same_base\":%d}\n", sc, r.stalled, r.held, gone_after, r.mb && (uintptr_t)r.mb == base_a ? 1 : 0);
    return 0;
}

// ---- cdx-cfnx: the program removes execute rights from a still-loaded module's code between
// call_func calls. call_func must refuse (return 0) the same as breakpoint/hw, WITHOUT calling
// into the page -- a call would raise a first-chance exception this program's handler would see.
static volatile LONG g_cfnx_fault = 0;
static unsigned char *volatile g_cfnx_page = nullptr;
static LONG CALLBACK cfnx_veh(EXCEPTION_POINTERS *e) {
    const DWORD code = e->ExceptionRecord->ExceptionCode;
    if ((code != EXCEPTION_ACCESS_VIOLATION && code != STATUS_GUARD_PAGE_VIOLATION) ||
        e->ExceptionRecord->NumberParameters < 2) return EXCEPTION_CONTINUE_SEARCH;
    unsigned char *a = (unsigned char *)e->ExceptionRecord->ExceptionInformation[1];
    if (!g_cfnx_page || a < g_cfnx_page || a >= g_cfnx_page + 4096) return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&g_cfnx_fault);                 // our capture/call touched the page: a side effect
    return EXCEPTION_CONTINUE_SEARCH;
}
static int run_cfnx() {
    wchar_t self[MAX_PATH], tmp[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH) || !GetTempPathW(MAX_PATH, tmp)) return 1;
    std::wstring dir(self); dir.resize(dir.find_last_of(L'\\') + 1);
    const std::wstring root = std::wstring(tmp) + L"uhh-cfnx-" + std::to_wstring(GetCurrentProcessId());
    const std::wstring f = root + L"\\cfr.dll";
    CreateDirectoryW(root.c_str(), nullptr);
    if (!CopyFileW((dir + L"ctrl_cfr_a.dll").c_str(), f.c_str(), FALSE)) {
        std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"cfnx\",\"error\":\"copy\"}\n"); return 1;
    }
    HMODULE m = LoadLibraryW(f.c_str());
    unsigned char *fn = m ? (unsigned char *)GetProcAddress(m, "CfrValue") : nullptr;
    if (!fn) { std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"cfnx\",\"error\":\"load\"}\n"); return 1; }
    g_cfnx_page = (unsigned char *)((uintptr_t)fn & ~(uintptr_t)0xFFF);
    PVOID h = AddVectoredExceptionHandler(1, cfnx_veh);
    CtrlCall(1);                                         // executable: call_func reaches CfrValue (primes the cache)
    DWORD old = 0;
    const int ro = VirtualProtect(g_cfnx_page, 4096, PAGE_READONLY, &old) ? 1 : 0;   // drop execute, keep read
    CtrlCall(2);                                         // not executable now: call_func must refuse, not fault
    VirtualProtect(g_cfnx_page, 4096, PAGE_EXECUTE_READ, &old);                       // restore execute
    CtrlCall(3);                                         // executable again
    const LONG faults = g_cfnx_fault;
    if (h) RemoveVectoredExceptionHandler(h);
    FreeLibrary(m);
    DeleteFileW(f.c_str()); RemoveDirectoryW(root.c_str());
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"cfnx\",\"ro\":%d,\"faults\":%ld}\n", ro, faults);
    return 0;
}

// ---- cdx-codeprot: the program toggles PAGE_GUARD / PAGE_NOACCESS on a code page of a
// loaded module (ctrl_dll) between hits while an inline stack-capturing probe runs. The x86
// capture scan re-queries protection each time (never trusts a cached "readable exec" verdict),
// so the guarded/no-access page is skipped UNTOUCHED: no crash, the guard page stays armed, no
// spurious fault reaches this program's handler, and the frames stay honest. A stack local
// holding (page + 0x40) is planted so the walk's return-address scan classifies the page every
// hit (its check reads the bytes just before 0x40, inside the page): the query must gate it.
static volatile LONG g_codeprot_fault = 0;
static unsigned char *volatile g_codeprot_page = nullptr;
static LONG CALLBACK codeprot_veh(EXCEPTION_POINTERS *e) {
    const DWORD code = e->ExceptionRecord->ExceptionCode;
    if ((code != EXCEPTION_ACCESS_VIOLATION && code != STATUS_GUARD_PAGE_VIOLATION) ||
        e->ExceptionRecord->NumberParameters < 2) return EXCEPTION_CONTINUE_SEARCH;
    unsigned char *a = (unsigned char *)e->ExceptionRecord->ExceptionInformation[1];
    if (!g_codeprot_page || a < g_codeprot_page || a >= g_codeprot_page + 4096) return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&g_codeprot_fault);             // our capture touched the page
    DWORD old = 0;                                        // re-arm so a buggy build does not hang / stay disarmed
    VirtualProtect(g_codeprot_page, 4096, PAGE_EXECUTE_READ | (code == STATUS_GUARD_PAGE_VIOLATION ? PAGE_GUARD : 0), &old);
    return EXCEPTION_CONTINUE_EXECUTION;
}
extern "C" __declspec(dllexport) __declspec(noinline) void CtrlCodeLeaf(void) {
    static volatile int sink; sink++;                    // the probed site (inline send_log_stack)
}
static volatile uintptr_t g_code_sink;
static __declspec(noinline) void CtrlCodeMid(uintptr_t planted) {
    volatile uintptr_t p = planted;                      // on the stack, inside the walk's scan window
    CtrlCodeLeaf();
    g_code_sink = p;                                     // keep it live across the call
}
static int run_codeprot() {
    HMODULE m = LoadLibraryA("ctrl_dll.dll");
    unsigned char *leaf = m ? (unsigned char *)GetProcAddress(m, "CtrlDllLeaf") : nullptr;
    if (!leaf) { std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"codeprot\",\"error\":\"load\"}\n"); return 1; }
    unsigned char *page = (unsigned char *)((uintptr_t)leaf & ~(uintptr_t)0xFFF);   // a code page we never execute here
    g_codeprot_page = page;
    const uintptr_t planted = (uintptr_t)page + 0x40;
    PVOID h = AddVectoredExceptionHandler(1, codeprot_veh);
    for (int i = 0; i < 50; ++i) CtrlCodeMid(planted);  // page executable/readable: prime any classification cache
    DWORD old = 0;
    const int guard_set = VirtualProtect(page, 4096, PAGE_EXECUTE_READ | PAGE_GUARD, &old) ? 1 : 0;
    for (int i = 0; i < 200; ++i) CtrlCodeMid(planted);
    MEMORY_BASIC_INFORMATION mbi{};
    const int guard_intact = (VirtualQuery(page, &mbi, sizeof(mbi)) && (mbi.Protect & PAGE_GUARD)) ? 1 : 0;
    VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old);
    const LONG guard_faults = g_codeprot_fault;
    g_codeprot_fault = 0;
    VirtualProtect(page, 4096, PAGE_NOACCESS, &old);
    for (int i = 0; i < 200; ++i) CtrlCodeMid(planted);
    VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old);
    const LONG na_faults = g_codeprot_fault;
    if (h) RemoveVectoredExceptionHandler(h);
    FreeLibrary(m);
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"codeprot\",\"guard_set\":%d,\"guard_intact\":%d,"
                "\"guard_faults\":%ld,\"na_faults\":%ld,\"hits\":%d}\n",
                guard_set, guard_intact, guard_faults, na_faults, 450);
    return 0;
}

// ---- cdx-int3cap: more armed software breakpoints than the agent's INT3 table used to hold --
static int run_int3cap(int n) {
    CtrlOp((const void *)&CtrlSled, (uintptr_t)n, 0);  // UHH: a breakpoint on each sled byte
    // ONE get_mem of the whole sled must read the program's bytes under every breakpoint (the
    // agent's table held 1024; then one inline read masked at most 64 of them).
    CtrlOp((const void *)&CtrlSled, (uintptr_t)n, 1);
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"int3cap\",\"n\":%d}\n", n);
    return 0;
}

// ---- cdx-bigcfg: a dynamic add with a config over 64 MiB ------------------------------------
static int run_bigcfg() {
    CtrlBigCfg();                                      // the callback adds CtrlTock with the big config
    const int r = CtrlTock(5);
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"bigcfg\",\"r\":%d}\n", r);
    return 0;
}

// ---- shape -------------------------------------------------------------------------
typedef uintptr_t (*ShapeFn)(uint32_t tag);
extern "C" uintptr_t g_tls_off = 0;   // segjmp: TEB offset of this run's TLS slot
extern "C" uint32_t g_ssn = 0;        // syscall: NtYieldExecution's service number (x64)
#define SHAPE(n) extern "C" uintptr_t Shape_##n##_P(uint32_t); extern "C" uintptr_t Shape_##n##_R(uint32_t);
#define SHAPES_COMMON(X) X(jmp8) X(jmp32) X(jcc8_taken) X(jcc8_not) X(jcc8_alt) X(jcc32_taken) X(call32) X(callmem) \
    X(ret) X(loop_taken) X(loop_not) X(loopz) X(loopnz) X(jrcxz) X(loop_a32) X(jecxz_a32) X(pushf) X(pushf_guard) X(segjmp)
SHAPES_COMMON(SHAPE)
#if defined(_WIN64)
SHAPE(syscall)
#endif
struct ShapeEntry { const char *name; ShapeFn p, r; };
#define SHAPE_ROW(n) {#n, Shape_##n##_P, Shape_##n##_R},
static const ShapeEntry g_shapes[] = {
    SHAPES_COMMON(SHAPE_ROW)
#if defined(_WIN64)
    SHAPE_ROW(syscall)
#endif
};
struct ShapeArg { const ShapeEntry *e; uint32_t t, n; uint64_t bad, tf, grow_bad; uintptr_t first_p, first_r; };
static DWORD WINAPI shape_thread(void *v) {
    ShapeArg *a = (ShapeArg *)v;
    const bool guard = !std::strcmp(a->e->name, "pushf_guard");
    const bool pushf = guard || !std::strcmp(a->e->name, "pushf");
    for (uint32_t i = 0; i < a->n; ++i) {
        const uint32_t tag = (a->t << 20) | i;
        NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
        void *lim0 = tib->StackLimit;
        const uintptr_t rp = a->e->p(tag);
        void *lim1 = tib->StackLimit;
        const uintptr_t rr = a->e->r(tag);
        if (guard && !(lim1 < lim0)) ++a->grow_bad;      // the push must have grown the stack
        if (rp != rr) { if (!a->bad) { a->first_p = rp; a->first_r = rr; } ++a->bad; }
        if (pushf && (rp & 0x100)) ++a->tf;
    }
    return 0;
}
static int run_shape(const char *name, int threads, int n) {
    const ShapeEntry *e = nullptr;
    for (auto &x : g_shapes) if (!std::strcmp(x.name, name)) e = &x;
    if (!e) { std::printf("{\"kind\":\"ctrl_result\",\"error\":\"unknown shape\"}\n"); return 1; }
    const DWORD tls = TlsAlloc();
    if (tls == TLS_OUT_OF_INDEXES || tls >= 64) { std::printf("{\"kind\":\"ctrl_result\",\"error\":\"tls\"}\n"); return 1; }
#if defined(_WIN64)
    g_tls_off = 0x1480 + 8 * tls;                       // TEB.TlsSlots
    const unsigned char *stub = (const unsigned char *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtYieldExecution");
    if (stub && stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8) std::memcpy(&g_ssn, stub + 4, 4);
#else
    g_tls_off = 0xE10 + 4 * tls;
#endif
    std::vector<ShapeArg> args(threads);
    std::vector<HANDLE> hs;
    for (int t = 0; t < threads; ++t) {
        args[t] = ShapeArg{e, (uint32_t)t + 1, (uint32_t)n, 0, 0, 0, 0, 0};
        // 32 MiB reserve: pushf_guard grows the stack by a page per call (P and R)
        hs.push_back(CreateThread(nullptr, 32u << 20, shape_thread, &args[t], STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr));
    }
    WaitForMultipleObjects((DWORD)hs.size(), hs.data(), TRUE, INFINITE);
    uint64_t bad = 0, tf = 0, grow_bad = 0; uintptr_t fp = 0, fr = 0;
    for (auto &a : args) {
        if (a.bad && !bad) { fp = a.first_p; fr = a.first_r; }
        bad += a.bad; tf += a.tf; grow_bad += a.grow_bad;
    }
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"shape\",\"shape\":\"%s\",\"calls\":%d,\"bad\":%llu,"
                "\"tf\":%llu,\"grow_bad\":%llu,\"first_p\":\"%llx\",\"first_r\":\"%llx\"}\n", name, threads * n,
                (unsigned long long)bad, (unsigned long long)tf, (unsigned long long)grow_bad,
                (unsigned long long)fp, (unsigned long long)fr);
    return 0;
}

static const char *arg_str(int argc, char **argv, const char *name, const char *def) {
    for (int i = 2; i + 1 < argc; ++i) if (!std::strcmp(argv[i], name)) return argv[i + 1];
    return def;
}

// ---- headcorrupt ---------------------------------------------------------------------
static int run_headcorrupt() {
    CtrlTick(nullptr);                                   // one probe hit (the agent is up)
    wchar_t name[64];
    _snwprintf_s(name, _countof(name), _TRUNCATE, L"Local\\probe_api_%lu", GetCurrentProcessId());
    HANDLE m = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name);
    void *v = m ? MapViewOfFile(m, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 192) : nullptr;
    if (v) {
        // probe_agent_shared (v27): log_head @64 (a cache line of its own), log_tail @128
        volatile LONG64 *head = (volatile LONG64 *)((char *)v + 64);
        volatile LONG64 *tail = (volatile LONG64 *)((char *)v + 128);
        *head = *tail + 0x7FFFFFFFFFFFll;
    }
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"headcorrupt\",\"mapped\":%d}\n", v != nullptr);
    std::fflush(stdout);
    return 0;
}

// ---- module reload / forwarding / address-size review --------------------------------
static int mod_failure(const char *stage, int code, DWORD error = 0, int cycle = -1,
                       HMODULE owner = nullptr, HMODULE fwd = nullptr) {
    std::printf("{\"kind\":\"ctrl_result\",\"error\":\"%s\",\"code\":%d,\"win32\":%lu,\"cycle\":%d,"
                "\"owner_base\":\"0x%llx\",\"forward_base\":\"0x%llx\"}\n", stage, code,
                (unsigned long)error, cycle, (unsigned long long)(uintptr_t)owner, (unsigned long long)(uintptr_t)fwd);
    std::fflush(stdout);
    return code;
}
static int run_modmodules(const std::string &sc, const char *which) {
    typedef int (*Value)(int);
    typedef int (*Sys)(unsigned long);
    std::vector<void *> reserved;
    int bad = 0, calls = 0;
    uintptr_t first_owner = 0, first_forward = 0;
    bool low_is_source = false;
    unsigned long ssn = 0;
#if defined(_WIN64)
    if (sc == "modreload") {
        const unsigned char *stub = (const unsigned char *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtYieldExecution");
        if (!stub || stub[0] != 0x4c || stub[3] != 0xb8) return mod_failure("syscall-stub", 5);
        std::memcpy(&ssn, stub + 4, 4);
    }
#endif
    for (int cycle = 0; cycle < 3; ++cycle) {
        HMODULE owner = nullptr, fwd = nullptr;
        if (sc == "modforward") {
            HMODULE low = LoadLibraryA("modrel_forward_low.dll");
            if (!low) return mod_failure("load-low-forwarder", 6, GetLastError(), cycle);
            HMODULE high = LoadLibraryA("modrel_forward_high.dll");
            if (!high) return mod_failure("load-high-forwarder", 6, GetLastError(), cycle, low);
            // File names do not promise placement. Select the source by the actual bases,
            // then keep those module identities for the unload/reload cycles.
            if (!cycle) low_is_source = ((uintptr_t)low < (uintptr_t)high) == !std::strcmp(which, "low");
            fwd = low_is_source ? low : high;
            owner = low_is_source ? high : low;
        } else {
            owner = LoadLibraryA(sc == "modreload" ? "modrel_owner.dll" : "modrel_forward_high.dll");
            if (!owner) return mod_failure("load-owner", 6, GetLastError(), cycle);
            fwd = LoadLibraryA("modrel_forward_low.dll");
            if (!fwd) return mod_failure("load-forwarder", 6, GetLastError(), cycle, owner);
        }
        if (!cycle) {
            first_owner = (uintptr_t)owner; first_forward = (uintptr_t)fwd;
            if (sc == "modforward") {
                const std::string symbol = std::string(low_is_source ? "modrel_forward_low.dll" : "modrel_forward_high.dll") + "!ForwardValue";
                CtrlAnnounce((void *)symbol.c_str(), (void *)(uintptr_t)(symbol.size() + 1));
            }
        }
        Value value = (Value)GetProcAddress(owner, "ModValue");
        if (!value) return mod_failure("resolve-ModValue", 7, GetLastError(), cycle, owner, fwd);
        if (sc == "modforward") {
            bad += value(5) != 12; ++calls;
            if (!FreeLibrary(fwd)) return mod_failure("unload-forwarder", 11, GetLastError(), cycle, owner, fwd);
            fwd = nullptr;
            bad += value(5) != 12; ++calls; // forwarding image gone, owner is still live
        } else if (sc == "modreload") {
            Sys sys = (Sys)GetProcAddress(owner, "ModSys");
            if (!sys) return mod_failure("resolve-ModSys", 7, GetLastError(), cycle, owner, fwd);
            bad += sys(ssn) != 0; ++calls;
        } else { CtrlCall(sc == "modhistory" ? GetCurrentProcessId() : (uintptr_t)cycle); ++calls; }
        auto dos = (const IMAGE_DOS_HEADER *)owner;
        auto nt = (const IMAGE_NT_HEADERS *)((const char *)owner + dos->e_lfanew);
        const SIZE_T size = nt->OptionalHeader.SizeOfImage;
        if (!FreeLibrary(owner)) return mod_failure("unload-owner", 11, GetLastError(), cycle, owner, fwd);
        if (fwd && !FreeLibrary(fwd)) return mod_failure("unload-forwarder", 11, GetLastError(), cycle, owner, fwd);
        // Only the reload test reserves old mappings; the forwarding pair is freely relocatable.
        if (sc == "modreload") {
            void *hold = VirtualAlloc(owner, size, MEM_RESERVE, PAGE_NOACCESS);
            if (!hold) return mod_failure("reserve-old-owner", 8, GetLastError(), cycle, owner);
            reserved.push_back(hold);
        }
    }
    for (void *hold : reserved) VirtualFree(hold, 0, MEM_RELEASE);
    std::printf("{\"kind\":\"ctrl_result\",\"calls\":%d,\"bad\":%d,"
                "\"owner_base\":\"0x%llx\",\"forward_base\":\"0x%llx\"}\n", calls, bad,
                (unsigned long long)first_owner, (unsigned long long)first_forward);
    return bad ? 9 : 0;
}
static int run_modreloc() {
    unsigned char *code = (unsigned char *)VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!code) return mod_failure("allocate-code", 5, GetLastError());
    int bad = 0, calls = 0;
#if defined(_WIN64)
    // LEA with EIP-relative addressing wraps the result at 32 bits. It never faults,
    // so a wrongly displaced copy cannot hide behind the fault-retry path.
    const unsigned char lea[] = {0x67, 0x8d, 0x05, 0, 0, 0, 0, 0xc3};
    std::memcpy(code, lea, sizeof(lea));
    FlushInstructionCache(GetCurrentProcess(), code, sizeof(lea));
    CtrlAnnounce(code, nullptr);
    typedef uintptr_t (*Fn)();
    for (int i = 0; i < 5; ++i) { bad += ((Fn)code)() != (uint32_t)(uintptr_t)(code + 7); ++calls; }
    // Use a second page: changing an already-probed instruction is another finding.
    code = (unsigned char *)VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!code) return mod_failure("allocate-branch-code", 6, GetLastError());
#endif
    void *low = VirtualAlloc((void *)(uintptr_t)0x20000, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!low) return mod_failure("allocate-low-pointer", 7, GetLastError());
#if defined(_WIN64)
    void *high = VirtualAlloc((void *)(uintptr_t)0x100020000ull, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!high) return mod_failure("allocate-high-pointer", 8, GetLastError());
#endif
    // mov eax,fffffff0; [addr32] jmp [eax+20020] -> pointer at 20010.
    const unsigned char branch[] = {0xb8, 0xf0, 0xff, 0xff, 0xff,
#if defined(_WIN64)
        0x67,
#endif
        0xff, 0xa0, 0x20, 0x00, 0x02, 0x00};
    std::memcpy(code, branch, sizeof(branch));
    const unsigned char good[] = {0xb8, 0x2a, 0, 0, 0, 0xc3};
    const unsigned char wrong[] = {0xb8, 0x63, 0, 0, 0, 0xc3};
    std::memcpy(code + 64, good, sizeof(good)); std::memcpy(code + 80, wrong, sizeof(wrong));
    *(uintptr_t *)((char *)low + 16) = (uintptr_t)(code + 64);
#if defined(_WIN64)
    *(uintptr_t *)((char *)high + 16) = (uintptr_t)(code + 80);
#endif
    FlushInstructionCache(GetCurrentProcess(), code, 96);
    CtrlAnnounce(code + 5, nullptr);
    typedef int (*Branch)();
    for (int i = 0; i < 5; ++i) { bad += ((Branch)code)() != 42; ++calls; }
    std::printf("{\"kind\":\"ctrl_result\",\"calls\":%d,\"bad\":%d}\n", calls, bad);
    return bad ? 9 : 0;
}

static int run_logsite_code(bool callpair, bool whole = false) {
    auto *code = (unsigned char *)VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!code) return 1;
    memset(code, 0x90, 4096);
    const unsigned char pair[] = {0xff, 0xd0, 0xe8, 0, 0, 0, 0, 0xc3};
    const unsigned char mov[] = {0xb8, 1, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0xc3};
    memcpy(code, callpair ? pair : mov, callpair ? sizeof(pair) : sizeof(mov));
    FlushInstructionCache(GetCurrentProcess(), code, 4096);
    CtrlAnnounce(code, nullptr);
    int bad = 0;
    if (!callpair) {
        // The entry callback reads these arguments before MOV changes EAX. Use the
        // same cdecl arguments on x86 and the native argument registers on x64.
        typedef int (__cdecl *fn)(const void *, uintptr_t);
        for (int i = 0; i < 12; ++i) bad += ((fn)code)(code, whole ? 1u : 0u) != i + 2;
    }
    // Keep the allocation mapped until process exit (it still owns an active probe).
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"logsite\",\"bad\":%d}\n", bad);
    return bad ? 1 : 0;
}

// Keep every thread alive after its hit so the recursion tables really exhaust on both arches.
static HANDLE api_go;
static volatile LONG api_called;
static DWORD WINAPI api_thread(void *) {
    CtrlTock(5);
    InterlockedIncrement(&api_called);
    WaitForSingleObject(api_go, INFINITE);
    return 0;
}
static int run_apithread() {
    api_go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!api_go) return 1;
    std::vector<HANDLE> threads;
    for (int i = 0; i < 4354; ++i) {
        HANDLE t = CreateThread(nullptr, 64 * 1024, api_thread, nullptr, STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
        if (!t) break;
        threads.push_back(t);
    }
    const ULONGLONG until = GetTickCount64() + 120000;
    while (api_called < (LONG)threads.size() && GetTickCount64() < until) Sleep(5);
    const LONG called = api_called;
    SetEvent(api_go);
    for (HANDLE t : threads) { WaitForSingleObject(t, 60000); CloseHandle(t); }
    CloseHandle(api_go);
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"apithread\",\"created\":%zu,\"called\":%ld}\n", threads.size(), called);
    return threads.size() == 4354 && called == 4354 ? 0 : 1;
}
static volatile LONG api_guards;
static LONG CALLBACK api_veh(EXCEPTION_POINTERS *e) {
    if (e->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) InterlockedIncrement(&api_guards);
    return EXCEPTION_CONTINUE_SEARCH;
}
static int run_apicontract(const std::string &sc, int mode) {
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) return 1;
    PVOID veh = AddVectoredExceptionHandler(1, api_veh);
    if (sc == "apiguard") {
        void *pid = (void *)(uintptr_t)GetCurrentProcessId();
        CtrlApi(0, page, pid);                       // warm this thread's private-region verdict
        DWORD old = 0, ignored = 0;
        if (!VirtualProtect(page, 4096, PAGE_READWRITE | PAGE_GUARD, &old)) return 1;
        CtrlApi(1, page, pid);                       // next callback must re-query and refuse
        VirtualProtect(page, 4096, old, &ignored);
    } else CtrlApi((uintptr_t)mode, (void *)&CtrlTock, page);
    const int value = CtrlTock(5);                    // the very next instruction path must see a successful add
    if (veh) RemoveVectoredExceptionHandler(veh);
    VirtualFree(page, 0, MEM_RELEASE);
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"%s\",\"guards\":%ld,\"value\":%d}\n", sc.c_str(), api_guards, value);
    return value == 6 && api_guards == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: ctrl_target <scenario> [opts]\n"); return 2; }
    const std::string sc = argv[1];
    int rc = 2;
    if (sc == "apiguard" || sc == "apiforeign" || sc == "apiinstall")
        rc = run_apicontract(sc, arg_int(argc, argv, "--mode", 0));
    else if (sc == "apithread") rc = run_apithread();
    else if (sc == "modforward" || sc == "modcall" || sc == "modhistory" || sc == "modreload")
        rc = run_modmodules(sc, arg_str(argc, argv, "--dll", "low"));
    else if (sc == "modreloc") rc = run_modreloc();
    else if (sc == "siteempty") rc = 0;
    else if (sc == "codewrite") rc = run_logsite_code(false, arg_int(argc, argv, "--whole", 0) != 0);
    else if (sc == "callpair") rc = run_logsite_code(true);
    else if (sc == "fault") rc = run_fault(arg_int(argc, argv, "--n", 200));
    else if (sc == "inplace") rc = run_inplace(arg_int(argc, argv, "--threads", 8), arg_int(argc, argv, "--n", 3000));
    else if (sc == "absunload") rc = run_absunload(arg_int(argc, argv, "--cycles", 5), arg_int(argc, argv, "--n", 100));
    else if (sc == "symunload") rc = run_symunload(arg_int(argc, argv, "--cycles", 4), arg_int(argc, argv, "--n", 1500));
    else if (sc == "owndr") rc = run_owndr(arg_int(argc, argv, "--n", 50));
    else if (sc == "headcorrupt") rc = run_headcorrupt();
    else if (sc == "faultreg") rc = run_faultreg(arg_int(argc, argv, "--n", 200));
    else if (sc == "faultmix") rc = run_faultmix(arg_int(argc, argv, "--n", 300));
    else if (sc == "owndrx") rc = run_owndrx(arg_int(argc, argv, "--n", 50));
    else if (sc == "absreuse") rc = run_absreuse();
    else if (sc == "cfreuse") rc = run_cfreuse();
    else if (sc == "cfnx") rc = run_cfnx();
    else if (sc == "cfrace") rc = run_cfrace(false);
    else if (sc == "cfpin") rc = run_cfrace(true);
    else if (sc == "codeprot") rc = run_codeprot();
    else if (sc == "int3cap") rc = run_int3cap(arg_int(argc, argv, "--n", 1200));
    else if (sc == "bigcfg") rc = run_bigcfg();
    else if (sc == "shape") rc = run_shape(arg_str(argc, argv, "--shape", ""), arg_int(argc, argv, "--threads", 8),
                                           arg_int(argc, argv, "--n", 1000));
    std::fflush(stdout);
    return rc;
}
