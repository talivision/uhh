/* hunt_target -- concurrency / lifecycle stress for gated_config-style instrumentation.
 *
 *   hunt_target <scenario> [--n N]
 *
 * Every "read" is ntdll!NtReadVirtualMemory on a handle from OpenProcess(own pid) (so the
 * gated_config handle->pid map sees an NtOpenProcess first) of a known 64-byte pattern,
 * verified. The target counts its own reads; an instrumented run must see exactly that
 * many hits/logs, and the program result (reads, bad, checksum) must equal an
 * uninstrumented run. Scenarios:
 *   churn   8 spawner threads x N short-lived threads (2 reads each)
 *   pool    thread-pool work items, thread-pool timers, timer-queue timers
 *   fiber   4 threads x 8 fibers switching round-robin, reading between switches
 *   apc     user APCs queued to 4 alertable threads, each APC reads
 *   veh     own VEH + SEH filter + handler read on RaiseException; any single-step /
 *           breakpoint exception reaching the target's VEH is counted (must stay 0)
 *   dll     hunt_dll.dll load/unload churn (refcount reaches 0) from 4 threads; DllMain
 *           and HuntWork read; TLS callbacks read on every thread attach/detach
 *   ctx     two reader threads while main suspends one, GetThreadContext(CONTEXT_ALL),
 *           SetThreadContext with the same context, resumes -- N times
 *   exit-return / exit-process / exit-terminate   8 readers forever; main leaves after
 *           N ms by return 5 / ExitProcess(6) / TerminateProcess(self, 7)
 *   threads 32 threads x N reads (for slow / call_func callbacks)
 *   owndr   a worker runs with the target's OWN DR0 execute breakpoint on own_dr_site,
 *           handled by its VEH (RF set); N calls must give N own single-steps
 *   owndr-live  the same, but DR0 is armed on the worker while it RUNS (it waits on an event;
 *           main suspends it, GetThreadContext, sets DR0, SetThreadContext, resumes) -- over
 *           whatever DR0 held then (a debugger's hardware probe, if any)
 *   guard   N times, on a page touched through guard_touch (its first instruction is the
 *           access): twice from ONE call site, each a guard violation caught by __except (the
 *           second is a new call, not a retry); then once more with a filter that RETRIES
 *           (EXCEPTION_CONTINUE_EXECUTION: the guard is gone, the same execution completes);
 *           then a plain read. 4 calls (hits) and 3 guard violations per iteration (probe
 *           guard_touch, e.g. with uhh_trace)
 *   twin    N times: twin_a\twin.dll (TwinWork returns 0x101), unload, twin_b\twin.dll (0x202)
 *           -- the same base, different code at the same RVA (probe twin.dll!TwinWork)
 *   early   the handle is opened and one read made in a TLS callback at process attach
 *           (before the entry point); then N reads from main
 * Output: {"kind":"target","scenario":...,"reads":R,"bad":B,"foreign":F,...}
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef LONG(NTAPI *NtReadFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef struct { ULONG Length; HANDLE Root; PVOID Name; ULONG Attributes; PVOID Sd, Qos; } OBJATTR;
typedef struct { HANDLE UniqueProcess, UniqueThread; } CLIENTID;
typedef LONG(NTAPI *NtOpenFn)(HANDLE *, ACCESS_MASK, OBJATTR *, CLIENTID *);
static NtReadFn g_ntread;
static HANDLE g_proc;
static volatile LONG g_reads, g_bad, g_foreign, g_early, g_work, g_owndr, g_guards, g_twin;
static ULONG_PTR g_owndr_addr;
static unsigned char g_pattern[64];
static volatile LONG g_stop;

/* One verified read. Callable from anywhere (DllMain, TLS, APC, VEH, fiber). */
__declspec(dllexport) __declspec(noinline) void hunt_read(void) {
    unsigned char buf[64]; SIZE_T got = 0;
    if (!g_ntread || !g_proc) return;
    memset(buf, 0, sizeof(buf));
    if (g_ntread(g_proc, g_pattern, buf, sizeof(buf), &got) < 0 || got != sizeof(buf) ||
        memcmp(buf, g_pattern, sizeof(buf)) != 0)
        InterlockedIncrement(&g_bad);
    InterlockedIncrement(&g_reads);
}

static void init_reads(void) {
    if (g_proc) return;
    for (int i = 0; i < 64; ++i) g_pattern[i] = (unsigned char)(i * 7 + 3);
    g_ntread = (NtReadFn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
    /* ntdll!NtOpenProcess straight into the global (as probe_app does): gated_config's map
       dereferences the out-pointer lazily, which a kernelbase stack local would not survive. */
    NtOpenFn open = (NtOpenFn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
    OBJATTR oa; CLIENTID cid;
    memset(&oa, 0, sizeof(oa)); oa.Length = sizeof(oa);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId(); cid.UniqueThread = NULL;
    if (!open || open(&g_proc, PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid) < 0) g_proc = NULL;
}

/* ---- TLS callback: reads on every thread attach/detach (and process attach: early). ---- */
static volatile LONG g_tls_on;
static void NTAPI hunt_tls(PVOID mod, DWORD reason, PVOID r) {
    (void)mod; (void)r;
    if (reason == DLL_PROCESS_DETACH && getenv("HUNT_TRACE_EXIT")) {
        DWORD w; WriteFile(GetStdHandle(STD_ERROR_HANDLE), "[tls-process-detach]\n", 21, &w, NULL);
    }
    if (reason == DLL_PROCESS_ATTACH) {
        if (strstr(GetCommandLineA(), " early")) { init_reads(); hunt_read(); InterlockedIncrement(&g_early); }
    }
    else if (g_tls_on && (reason == DLL_THREAD_ATTACH || reason == DLL_THREAD_DETACH)) hunt_read();
}
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:hunt_tls_ptr")
#pragma const_seg(".CRT$XLB")
extern const PIMAGE_TLS_CALLBACK hunt_tls_ptr;
const PIMAGE_TLS_CALLBACK hunt_tls_ptr = hunt_tls;
#pragma const_seg()
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_hunt_tls_ptr")
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK hunt_tls_ptr = hunt_tls;
#pragma data_seg()
#endif

static DWORD g_n = 0;
static void trace_atexit(void) { DWORD w; WriteFile(GetStdHandle(STD_ERROR_HANDLE), "[atexit]\n", 9, &w, NULL); }
static HANDLE spawn(LPTHREAD_START_ROUTINE fn, void *arg) {
    HANDLE t = CreateThread(NULL, 0, fn, arg, 0, NULL);
    if (!t) { fprintf(stderr, "CreateThread failed %lu\n", GetLastError()); ExitProcess(90); }
    return t;
}
static void join(HANDLE *t, DWORD n) {
    for (DWORD i = 0; i < n; ++i) { WaitForSingleObject(t[i], INFINITE); CloseHandle(t[i]); }
}

/* ---- churn ---- */
static volatile LONG g_live;
static DWORD WINAPI short_life(void *p) { (void)p; hunt_read(); hunt_read(); InterlockedDecrement(&g_live); return 0; }
static DWORD WINAPI spawner(void *p) {
    (void)p;
    for (DWORD i = 0; i < g_n; ++i) {
        InterlockedIncrement(&g_live);
        HANDLE t = CreateThread(NULL, 0, short_life, NULL, 0, NULL);
        if (!t) { InterlockedDecrement(&g_live); InterlockedIncrement(&g_bad); continue; }
        if (i & 1) WaitForSingleObject(t, INFINITE);   /* half joined at once, half run free */
        CloseHandle(t);
    }
    return 0;
}

/* ---- pool ---- */
static volatile LONG g_pool_left;
static HANDLE g_pool_done;
static void pool_dec(void) { if (InterlockedDecrement(&g_pool_left) == 0) SetEvent(g_pool_done); }
static VOID CALLBACK work_cb(PTP_CALLBACK_INSTANCE i, PVOID c, PTP_WORK w) { (void)i; (void)c; (void)w; hunt_read(); pool_dec(); }
static VOID CALLBACK timer_cb(PTP_CALLBACK_INSTANCE i, PVOID c, PTP_TIMER t) { (void)i; (void)c; (void)t; hunt_read(); pool_dec(); }
static VOID CALLBACK tq_cb(PVOID c, BOOLEAN f) { (void)c; (void)f; hunt_read(); pool_dec(); }

/* ---- fiber ---- */
#define FIBERS 8
typedef struct { LPVOID self, next; DWORD left; } fib_t;
static VOID CALLBACK fiber_main(PVOID p) {
    fib_t *f = (fib_t *)p;
    for (;;) {
        if (f->left) { hunt_read(); --f->left; }
        SwitchToFiber(f->next);
    }
}
static DWORD WINAPI fiber_thread(void *p) {
    (void)p;
    fib_t fibs[FIBERS];
    LPVOID me = ConvertThreadToFiber(NULL);
    if (!me) { InterlockedIncrement(&g_bad); return 1; }
    for (int i = 0; i < FIBERS; ++i) { fibs[i].left = g_n; fibs[i].self = CreateFiber(0, fiber_main, &fibs[i]); }
    for (int i = 0; i < FIBERS; ++i) fibs[i].next = (i + 1 < FIBERS) ? fibs[i + 1].self : me;
    for (;;) {
        DWORD left = 0;
        for (int i = 0; i < FIBERS; ++i) left += fibs[i].left;
        if (!left) break;
        SwitchToFiber(fibs[0].self);
    }
    for (int i = 0; i < FIBERS; ++i) DeleteFiber(fibs[i].self);
    ConvertFiberToThread();
    return 0;
}

/* ---- apc ---- */
static volatile LONG g_apc_left;
static VOID CALLBACK apc_cb(ULONG_PTR a) { (void)a; hunt_read(); InterlockedDecrement(&g_apc_left); }
static DWORD WINAPI alertable(void *p) { (void)p; while (!g_stop) SleepEx(INFINITE, TRUE); return 0; }
static VOID CALLBACK apc_stop(ULONG_PTR a) { (void)a; }

/* ---- veh ---- */
#define HUNT_CODE 0xE0484E54u
static LONG CALLBACK hunt_veh(PEXCEPTION_POINTERS e) {
    DWORD code = e->ExceptionRecord->ExceptionCode;
    /* The target's OWN hardware breakpoint (owndr): count it, step past with RF. */
    if (code == EXCEPTION_SINGLE_STEP && g_owndr_addr && (ULONG_PTR)e->ExceptionRecord->ExceptionAddress == g_owndr_addr) {
        InterlockedIncrement(&g_owndr);
        e->ContextRecord->EFlags |= 0x10000;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code == EXCEPTION_SINGLE_STEP || code == EXCEPTION_BREAKPOINT || code == 0x4000001F || code == 0x4000001E)
        InterlockedIncrement(&g_foreign);
    if (code == HUNT_CODE) hunt_read();       /* then let the SEH filter handle it */
    return EXCEPTION_CONTINUE_SEARCH;
}
static int seh_filter(DWORD code) {
    if (code != HUNT_CODE) return EXCEPTION_CONTINUE_SEARCH;
    hunt_read();
    return EXCEPTION_EXECUTE_HANDLER;
}
static DWORD WINAPI raiser(void *p) {
    (void)p;
    for (DWORD i = 0; i < g_n; ++i) {
        __try { RaiseException(HUNT_CODE, 0, 0, NULL); }
        __except (seh_filter(GetExceptionCode())) { hunt_read(); }
    }
    return 0;
}

/* ---- dll churn ---- */
typedef void (*WorkFn)(void (*)(void), volatile LONG *);
static DWORD WINAPI dll_user(void *p) {
    (void)p;
    for (DWORD i = 0; i < g_n; ++i) {
        HMODULE h = LoadLibraryA("hunt_dll.dll");
        if (!h) { InterlockedIncrement(&g_bad); continue; }
        WorkFn w = (WorkFn)GetProcAddress(h, "HuntWork");
        if (w) w(hunt_read, &g_work); else InterlockedIncrement(&g_bad);
        if (i % 3 == 0) {
            InterlockedIncrement(&g_live);
            HANDLE t = CreateThread(NULL, 0, short_life, NULL, 0, NULL);
            if (t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); } else InterlockedDecrement(&g_live);
        }
        FreeLibrary(h);
    }
    return 0;
}

/* ---- owndr: the target arms DR0 on one of its own functions and handles it in its VEH ---- */
__declspec(dllexport) __declspec(noinline) int own_dr_site(int x) { return x * 3 + 1; }
static volatile int g_own_sink;
static HANDLE g_owndr_go, g_owndr_ready;
static DWORD WINAPI owndr_worker(void *p) {
    (void)p;
    /* live: running its own code (past its loader initialisation, whose closing NtContinue
       would restore the context it was created with -- the DR0 set meanwhile with it) */
    if (g_owndr_ready) SetEvent(g_owndr_ready);
    if (g_owndr_go) WaitForSingleObject(g_owndr_go, INFINITE);
    for (DWORD i = 0; i < g_n; ++i) { g_own_sink += own_dr_site((int)i); hunt_read(); }
    return 0;
}

/* ---- guard: an instruction displaced by a probe touches a guard page ---- */
/* __fastcall: on x86 too the pointer arrives in a register, so the access IS the first
   instruction (the probe site). Exported undecorated on x86 as well. */
__declspec(dllexport) __declspec(noinline) int __fastcall guard_touch(volatile char *p) { return *p; }
#ifndef _WIN64
#pragma comment(linker, "/EXPORT:guard_touch=@guard_touch@4")
#endif
static int guard_filter(DWORD code) {
    return code == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}
static int guard_retry(DWORD code) {
    if (code != STATUS_GUARD_PAGE_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&g_guards);
    return EXCEPTION_CONTINUE_EXECUTION;                     /* the guard is consumed: retry */
}

/* ---- twin: two builds of one DLL at the same base ---- */
typedef int (*TwinFn)(void);
static int twin_call(const char *dir, const char *sub) {
    char path[MAX_PATH];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\%s\\twin.dll", dir, sub);
    HMODULE h = LoadLibraryA(path);
    if (!h) return -1;
    TwinFn f = (TwinFn)GetProcAddress(h, "TwinWork");
    int v = f ? f() : -2;
    FreeLibrary(h);
    return v;
}

/* ---- ctx / exit ---- */
static DWORD WINAPI reader_until_stop(void *p) { (void)p; while (!g_stop) hunt_read(); return 0; }

/* ---- generic ---- */
static DWORD WINAPI reader_n(void *p) { (void)p; for (DWORD i = 0; i < g_n; ++i) hunt_read(); return 0; }

static unsigned long long checksum(void) {
    unsigned long long x = 1469598103934665603ull;
    for (int i = 0; i < 64; ++i) x = (x ^ g_pattern[i]) * 1099511628211ull;
    return x;
}

int main(int argc, char **argv) {
    const char *sc = argc > 1 ? argv[1] : "threads";
    g_n = 100;
    for (int i = 2; i + 1 < argc; i += 2) if (!strcmp(argv[i], "--n")) g_n = (DWORD)strtoul(argv[i + 1], NULL, 0);
    init_reads();
    g_tls_on = 1;
    PVOID veh = AddVectoredExceptionHandler(1, hunt_veh);

    if (!strcmp(sc, "churn")) {
        HANDLE t[8]; for (int i = 0; i < 8; ++i) t[i] = spawn(spawner, NULL); join(t, 8);
        while (g_live > 0) Sleep(1);   /* unjoined short-lived threads finish */
        Sleep(50);                     /* ... including their TLS detach read */
    } else if (!strcmp(sc, "pool")) {
        g_pool_done = CreateEventA(NULL, TRUE, FALSE, NULL);
        DWORD works = g_n * 4, timers = g_n, tqs = g_n;
        g_pool_left = (LONG)(works + timers + tqs);
        PTP_WORK w = CreateThreadpoolWork(work_cb, NULL, NULL);
        for (DWORD i = 0; i < works; ++i) SubmitThreadpoolWork(w);
        PTP_TIMER *tm = (PTP_TIMER *)calloc(timers, sizeof(PTP_TIMER));
        for (DWORD i = 0; i < timers; ++i) {
            FILETIME due; LARGE_INTEGER li; li.QuadPart = -(LONGLONG)(10000 * (1 + i % 20));
            due.dwLowDateTime = li.LowPart; due.dwHighDateTime = (DWORD)li.HighPart;
            tm[i] = CreateThreadpoolTimer(timer_cb, NULL, NULL); SetThreadpoolTimer(tm[i], &due, 0, 0);
        }
        HANDLE q = CreateTimerQueue();
        for (DWORD i = 0; i < tqs; ++i) { HANDLE h; CreateTimerQueueTimer(&h, q, tq_cb, NULL, 1 + i % 20, 0, WT_EXECUTEDEFAULT); }
        if (WaitForSingleObject(g_pool_done, 120000) != WAIT_OBJECT_0) InterlockedIncrement(&g_bad);
        WaitForThreadpoolWorkCallbacks(w, FALSE); CloseThreadpoolWork(w);
        for (DWORD i = 0; i < timers; ++i) { WaitForThreadpoolTimerCallbacks(tm[i], FALSE); CloseThreadpoolTimer(tm[i]); }
        DeleteTimerQueueEx(q, INVALID_HANDLE_VALUE);
        g_tls_on = 0;   /* pool threads retire whenever they like: stop counting their detach */
    } else if (!strcmp(sc, "fiber")) {
        HANDLE t[4]; for (int i = 0; i < 4; ++i) t[i] = spawn(fiber_thread, NULL); join(t, 4);
    } else if (!strcmp(sc, "apc")) {
        HANDLE t[4]; for (int i = 0; i < 4; ++i) t[i] = spawn(alertable, NULL);
        g_apc_left = (LONG)(g_n * 4 * 4);
        for (DWORD k = 0; k < g_n * 4; ++k) for (int i = 0; i < 4; ++i) QueueUserAPC(apc_cb, t[i], 0);
        while (g_apc_left > 0) Sleep(1);
        g_stop = 1; for (int i = 0; i < 4; ++i) QueueUserAPC(apc_stop, t[i], 0);
        join(t, 4);
    } else if (!strcmp(sc, "veh")) {
        HANDLE t[4]; for (int i = 0; i < 4; ++i) t[i] = spawn(raiser, NULL); join(t, 4);
    } else if (!strcmp(sc, "dll")) {
        HANDLE t[4]; for (int i = 0; i < 4; ++i) t[i] = spawn(dll_user, NULL); join(t, 4);
    } else if (!strcmp(sc, "ctx")) {
        HANDLE r[2]; for (int i = 0; i < 2; ++i) r[i] = spawn(reader_until_stop, NULL);
        for (DWORD k = 0; k < g_n; ++k) {
            HANDLE t = r[k & 1];
            CONTEXT c; memset(&c, 0, sizeof(c)); c.ContextFlags = CONTEXT_ALL;
            if (SuspendThread(t) == (DWORD)-1) { InterlockedIncrement(&g_bad); continue; }
            if (!GetThreadContext(t, &c) || !SetThreadContext(t, &c)) InterlockedIncrement(&g_bad);
            ResumeThread(t);
            if (k % 16 == 0) Sleep(0);
        }
        g_stop = 1; join(r, 2);
    } else if (!strncmp(sc, "exit-", 5)) {
        const char *rd = getenv("HUNT_READERS");
        int readers = rd ? atoi(rd) : 8;
        for (int i = 0; i < readers; ++i) CloseHandle(spawn(reader_until_stop, NULL));
        Sleep(g_n);
        printf("{\"kind\":\"target\",\"scenario\":\"%s\",\"reads_at_exit\":%ld,\"bad\":%ld}\n", sc, g_reads, g_bad);
        fflush(stdout);
        if (getenv("HUNT_TRACE_EXIT")) { atexit(trace_atexit); fprintf(stderr, "[main-leaving tid=%lu]\n", GetCurrentThreadId()); }
        if (!strcmp(sc, "exit-process")) ExitProcess(6);
        if (!strcmp(sc, "exit-terminate")) TerminateProcess(GetCurrentProcess(), 7);
        return 5;
    } else if (!strcmp(sc, "owndr") || !strcmp(sc, "owndr-live")) {
        const int live = !strcmp(sc, "owndr-live");
        if (live) { g_owndr_go = CreateEventA(NULL, TRUE, FALSE, NULL); g_owndr_ready = CreateEventA(NULL, TRUE, FALSE, NULL); }
        HANDLE t = CreateThread(NULL, 0, owndr_worker, NULL, live ? 0 : CREATE_SUSPENDED, NULL);
        CONTEXT c; memset(&c, 0, sizeof(c)); c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        g_owndr_addr = (ULONG_PTR)own_dr_site;
        if (live && t) {                                  /* it runs, then waits on the event */
            WaitForSingleObject(g_owndr_ready, INFINITE); Sleep(20);
            if (SuspendThread(t) == (DWORD)-1) InterlockedIncrement(&g_bad);
        }
        if (!t || !GetThreadContext(t, &c)) { InterlockedIncrement(&g_bad); }
        else {
            c.Dr0 = g_owndr_addr; c.Dr7 = (c.Dr7 & ~(ULONG_PTR)0xF0003) | 1;   /* L0, execute, len 1 */
            if (!SetThreadContext(t, &c)) InterlockedIncrement(&g_bad);
            ResumeThread(t);
            if (live) SetEvent(g_owndr_go);
            WaitForSingleObject(t, INFINITE); CloseHandle(t);
        }
        if ((DWORD)g_owndr != g_n) InterlockedIncrement(&g_bad);
    } else if (!strcmp(sc, "guard")) {
        for (DWORD i = 0; i < g_n; ++i) {
            char *page = (char *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            DWORD old = 0; int v = -1;
            if (!page) { InterlockedIncrement(&g_bad); continue; }
            page[0] = (char)(i & 0x7F);
            for (int k = 0; k < 2; ++k) {                        /* one call site, twice */
                v = -1;
                if (!VirtualProtect(page, 4096, PAGE_READWRITE | PAGE_GUARD, &old)) InterlockedIncrement(&g_bad);
                __try { v = guard_touch(page); }
                __except (guard_filter(GetExceptionCode())) { InterlockedIncrement(&g_guards); }
                if (v != -1) InterlockedIncrement(&g_bad);        /* the guard did not fire */
            }
            if (!VirtualProtect(page, 4096, PAGE_READWRITE | PAGE_GUARD, &old)) InterlockedIncrement(&g_bad);
            v = -1;
            __try { v = guard_touch(page); }
            __except (guard_retry(GetExceptionCode())) { InterlockedIncrement(&g_bad); }
            if (v != (int)(i & 0x7F)) InterlockedIncrement(&g_bad); /* the retry completed the read */
            if (guard_touch(page) != (int)(i & 0x7F)) InterlockedIncrement(&g_bad);
            VirtualFree(page, 0, MEM_RELEASE);
        }
        if ((DWORD)g_guards != 3 * g_n) InterlockedIncrement(&g_bad);
    } else if (!strcmp(sc, "twin")) {
        char dir[MAX_PATH]; DWORD n = GetModuleFileNameA(NULL, dir, MAX_PATH);
        while (n && dir[n - 1] != '\\') --n;
        dir[n ? n - 1 : 0] = 0;
        for (DWORD i = 0; i < g_n; ++i) {
            if (twin_call(dir, "twin_a") != 0x101) InterlockedIncrement(&g_bad); else InterlockedIncrement(&g_twin);
            if (twin_call(dir, "twin_b") != 0x202) InterlockedIncrement(&g_bad); else InterlockedIncrement(&g_twin);
        }
    } else if (!strcmp(sc, "early")) {
        for (DWORD i = 0; i < g_n; ++i) hunt_read();
    } else if (!strcmp(sc, "threads")) {
        HANDLE t[32]; for (int i = 0; i < 32; ++i) t[i] = spawn(reader_n, NULL); join(t, 32);
    } else {
        fprintf(stderr, "unknown scenario %s\n", sc); return 2;
    }
    g_tls_on = 0;
    if (veh) RemoveVectoredExceptionHandler(veh);
    printf("{\"kind\":\"target\",\"scenario\":\"%s\",\"n\":%lu,\"reads\":%ld,\"bad\":%ld,\"foreign\":%ld,"
           "\"early\":%ld,\"work\":%ld,\"owndr\":%ld,\"guards\":%ld,\"twin\":%ld,\"checksum\":\"%llx\",\"pid\":%lu}\n",
           sc, g_n, g_reads, g_bad, g_foreign, g_early, g_work, g_owndr, g_guards, g_twin, checksum(), GetCurrentProcessId());
    fflush(stdout);
    return 0;
}
