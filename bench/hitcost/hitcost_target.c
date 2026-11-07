// Per-hit cost microbenchmark target: calls an exported function N times in a tight loop
// and times the loop itself (QueryPerformanceCounter), so the number is the hook's cost
// per call. --avx keeps YMM upper halves live across the loop (the case where a full
// extended-state save has real work to do).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile intptr_t g_sink;
__declspec(dllexport) __declspec(noinline) intptr_t hit_site(intptr_t i);
static long long g_calls = 10000000; static int g_avx = 0;
static long long g_crash_after = 0;            /* >0: die with an unhandled access violation after N calls */
static volatile LONG g_go;
static volatile LONG g_done;
static volatile LONG64 g_spins;              /* --spin: iterations of a thread that hits nothing */
static int g_waiter_ms = 0, g_waiter_sleep = 0;  /* --waiter MS / --sleeper MS: a thread in timed waits */
static volatile LONG64 g_waits;              /* ... how many of them completed during the timed loop */
static int g_qpc_arg = 0;                      /* --qpc-arg: pass a QPC timestamp (microseconds, low 31 bits) instead of i */
static LARGE_INTEGER g_freq;
static intptr_t qpc_us(void) {                 /* same clock as Python's time.perf_counter_ns, in us, 31 bits (fits x86) */
    LARGE_INTEGER t; QueryPerformanceCounter(&t);
    long long us = (t.QuadPart / g_freq.QuadPart) * 1000000LL + (t.QuadPart % g_freq.QuadPart) * 1000000LL / g_freq.QuadPart;
    return (intptr_t)(us & 0x7fffffffLL);
}

/* --spin: a thread that never hits the probe and always wants the CPU -- the thread a
   debugger's fairness must not starve. Its iteration count over the timed loop is reported. */
static DWORD WINAPI spin(void *arg) {
    (void)arg;
    while (!g_go) YieldProcessor();
    LONG64 n = 0;
    while (!g_done) { ++n; if ((n & 1023) == 0) g_spins = n; }
    g_spins = n;
    return 0;
}

/* --waiter / --sleeper: a thread that never hits the probe and only waits with a timeout
   (WaitForSingleObject on an event nobody sets, or Sleep): how many timeouts complete during the
   timed loop vs its wall time / MS -- does a debugger freezing the process stall timeouts? */
static DWORD WINAPI waiter(void *arg) {
    HANDLE never = CreateEventA(NULL, TRUE, FALSE, NULL);
    (void)arg;
    while (!g_go) Sleep(1);
    while (!g_done) {
        if (g_waiter_sleep) Sleep((DWORD)g_waiter_ms); else WaitForSingleObject(never, (DWORD)g_waiter_ms);
        if (!g_done) InterlockedIncrement64(&g_waits);
    }
    CloseHandle(never);
    return 0;
}

static DWORD WINAPI loop(void *arg) {
    (void)arg;
    __m256 live = _mm256_set1_ps(1.0f), flip = _mm256_castsi256_ps(_mm256_set1_epi32(0x00800000));
    while (!g_go) YieldProcessor();
    for (long long i = 0; i < g_calls; ++i) {
        hit_site(g_qpc_arg ? qpc_us() : (intptr_t)i);
        if (g_crash_after && i + 1 == g_crash_after) *(volatile int *)(uintptr_t)8 = 1;   /* crash */
        if (g_avx) live = _mm256_xor_ps(live, flip);
    }
    float keep[8]; _mm256_storeu_ps(keep, live); return (DWORD)keep[0];
}

__declspec(dllexport) __declspec(noinline) intptr_t hit_site(intptr_t i) {
    g_sink += i;                 /* a few bytes of real work so the site is hookable */
    return g_sink ^ i;
}

int main(int argc, char **argv) {
    int no_wait = 0, threads = 1, spinner = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--calls") && i + 1 < argc) g_calls = atoll(argv[++i]);
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--avx")) g_avx = 1;
        else if (!strcmp(argv[i], "--crash-after") && i + 1 < argc) g_crash_after = atoll(argv[++i]);
        else if (!strcmp(argv[i], "--no-wait")) no_wait = 1;
        else if (!strcmp(argv[i], "--qpc-arg")) g_qpc_arg = 1;
        else if (!strcmp(argv[i], "--spin")) spinner = 1;
        else if (!strcmp(argv[i], "--waiter") && i + 1 < argc) g_waiter_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--sleeper") && i + 1 < argc) { g_waiter_ms = atoi(argv[++i]); g_waiter_sleep = 1; }
        else if (!strcmp(argv[i], "--print-rva")) {   /* g_sink's RVA: hit_site writes it on every call */
            printf("{\"kind\":\"rva\",\"sink\":%llu,\"hit_site\":%llu}\n",
                   (unsigned long long)((uintptr_t)&g_sink - (uintptr_t)GetModuleHandleA(NULL)),
                   (unsigned long long)((uintptr_t)&hit_site - (uintptr_t)GetModuleHandleA(NULL)));
            return 0;
        }
    }
    if (threads < 1 || threads > 64) threads = 1;
    QueryPerformanceFrequency(&g_freq);
    printf("{\"kind\":\"waiting\"}\n"); fflush(stdout);
    if (!no_wait) { char b; DWORD got = 0; ReadFile(GetStdHandle(STD_INPUT_HANDLE), &b, 1, &got, NULL); }
    HANDLE h[64];
    for (int t = 0; t < threads; ++t) h[t] = CreateThread(NULL, 0, loop, NULL, 0, NULL);
    HANDLE sp = spinner ? CreateThread(NULL, 0, spin, NULL, 0, NULL) : NULL;
    HANDLE wt = g_waiter_ms > 0 ? CreateThread(NULL, 0, waiter, NULL, 0, NULL) : NULL;
    Sleep(50);
    LARGE_INTEGER f, t0, t1; QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    InterlockedExchange(&g_go, 1);
    WaitForMultipleObjects((DWORD)threads, h, TRUE, INFINITE);
    QueryPerformanceCounter(&t1);
    InterlockedExchange(&g_done, 1);
    if (sp) { WaitForSingleObject(sp, INFINITE); CloseHandle(sp); }
    if (wt) { WaitForSingleObject(wt, INFINITE); CloseHandle(wt); }
    for (int t = 0; t < threads; ++t) CloseHandle(h[t]);
    double ns = (double)(t1.QuadPart - t0.QuadPart) * 1e9 / (double)f.QuadPart;
    /* wall time per call per thread: with T threads running in parallel, this is the
       per-hit cost each thread sees (contention shows up as growth with T). */
    /* spin_share: the spinner's iterations per ns of the timed window (--spin; 0 without) --
       compared with an uninstrumented run, the CPU share a thread that hits nothing got. */
    printf("{\"kind\":\"target\",\"name\":\"hitcost\",\"calls\":%lld,\"threads\":%d,\"avx\":%d,\"ns_per_call\":%.2f,"
           "\"spins\":%lld,\"spin_per_us\":%.3f,\"waits\":%lld,\"waits_due\":%.1f}\n",
           g_calls, threads, g_avx, ns / (double)g_calls, (long long)g_spins, (double)g_spins * 1000.0 / ns,
           (long long)g_waits, g_waiter_ms > 0 ? ns / 1e6 / g_waiter_ms : 0.0);
    fflush(stdout);
    return 0;
}
