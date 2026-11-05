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
//   ctrl_target owndrx [--n N]          the target's own watch on an address UHH watched once and
//                                       released, from a thread that existed then (cdx-owndrx)
//   ctrl_target absreuse                absolute INT3 in an unloaded DLL; its address reused (cdx-absreuse)
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
    for (int t = 0; t < threads; ++t) {
        args[t] = LoopArg{(uint32_t)t + 1, (uint32_t)n, 0};
        hs.push_back(CreateThread(nullptr, 0, loop_thread, &args[t], 0, nullptr));
    }
    WaitForMultipleObjects((DWORD)hs.size(), hs.data(), TRUE, INFINITE);
    uint64_t bad = 0;
    for (auto &a : args) bad += a.bad;
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"inplace\",\"calls\":%d,\"bad\":%llu}\n", threads * n,
                (unsigned long long)bad);
    return 0;
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

// ---- cdx-int3cap: more armed software breakpoints than the agent's INT3 table used to hold --
static int run_int3cap(int n) {
    CtrlOp((const void *)&CtrlSled, (uintptr_t)n, 0);  // UHH: a breakpoint on each sled byte
    // get_mem of the LAST 16 (past the 1024th breakpoint) must read the program's bytes. (One
    // inline read overlays at most 64 INT3s -- an agent-side bound, reported separately.)
    CtrlOp((const char *)&CtrlSled + (n - 16), 16, 1);
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
    void *v = m ? MapViewOfFile(m, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 64) : nullptr;
    if (v) {
        // probe_agent_shared: magic, version, request_count, reserved, log_head @16, log_tail @24
        volatile LONG64 *head = (volatile LONG64 *)((char *)v + 16);
        volatile LONG64 *tail = (volatile LONG64 *)((char *)v + 24);
        *head = *tail + 0x7FFFFFFFFFFFll;
    }
    std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"headcorrupt\",\"mapped\":%d}\n", v != nullptr);
    std::fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: ctrl_target <scenario> [opts]\n"); return 2; }
    const std::string sc = argv[1];
    int rc = 2;
    if (sc == "fault") rc = run_fault(arg_int(argc, argv, "--n", 200));
    else if (sc == "inplace") rc = run_inplace(arg_int(argc, argv, "--threads", 8), arg_int(argc, argv, "--n", 3000));
    else if (sc == "absunload") rc = run_absunload(arg_int(argc, argv, "--cycles", 5), arg_int(argc, argv, "--n", 100));
    else if (sc == "symunload") rc = run_symunload(arg_int(argc, argv, "--cycles", 4), arg_int(argc, argv, "--n", 1500));
    else if (sc == "owndr") rc = run_owndr(arg_int(argc, argv, "--n", 50));
    else if (sc == "headcorrupt") rc = run_headcorrupt();
    else if (sc == "faultreg") rc = run_faultreg(arg_int(argc, argv, "--n", 200));
    else if (sc == "owndrx") rc = run_owndrx(arg_int(argc, argv, "--n", 50));
    else if (sc == "absreuse") rc = run_absreuse();
    else if (sc == "int3cap") rc = run_int3cap(arg_int(argc, argv, "--n", 1200));
    else if (sc == "bigcfg") rc = run_bigcfg();
    else if (sc == "shape") rc = run_shape(arg_str(argc, argv, "--shape", ""), arg_int(argc, argv, "--threads", 8),
                                           arg_int(argc, argv, "--n", 1000));
    std::fflush(stdout);
    return rc;
}
