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
static volatile LONG g_go;

static DWORD WINAPI loop(void *arg) {
    (void)arg;
    __m256 live = _mm256_set1_ps(1.0f), flip = _mm256_castsi256_ps(_mm256_set1_epi32(0x00800000));
    while (!g_go) YieldProcessor();
    for (long long i = 0; i < g_calls; ++i) {
        hit_site((intptr_t)i);
        if (g_avx) live = _mm256_xor_ps(live, flip);
    }
    float keep[8]; _mm256_storeu_ps(keep, live); return (DWORD)keep[0];
}

__declspec(dllexport) __declspec(noinline) intptr_t hit_site(intptr_t i) {
    g_sink += i;                 /* a few bytes of real work so the site is hookable */
    return g_sink ^ i;
}

int main(int argc, char **argv) {
    int no_wait = 0, threads = 1;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--calls") && i + 1 < argc) g_calls = atoll(argv[++i]);
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--avx")) g_avx = 1;
        else if (!strcmp(argv[i], "--no-wait")) no_wait = 1;
    }
    if (threads < 1 || threads > 64) threads = 1;
    printf("{\"kind\":\"waiting\"}\n"); fflush(stdout);
    if (!no_wait) { char b; DWORD got = 0; ReadFile(GetStdHandle(STD_INPUT_HANDLE), &b, 1, &got, NULL); }
    HANDLE h[64];
    for (int t = 0; t < threads; ++t) h[t] = CreateThread(NULL, 0, loop, NULL, 0, NULL);
    Sleep(50);
    LARGE_INTEGER f, t0, t1; QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    InterlockedExchange(&g_go, 1);
    WaitForMultipleObjects((DWORD)threads, h, TRUE, INFINITE);
    QueryPerformanceCounter(&t1);
    for (int t = 0; t < threads; ++t) CloseHandle(h[t]);
    double ns = (double)(t1.QuadPart - t0.QuadPart) * 1e9 / (double)f.QuadPart;
    /* wall time per call per thread: with T threads running in parallel, this is the
       per-hit cost each thread sees (contention shows up as growth with T). */
    printf("{\"kind\":\"target\",\"name\":\"hitcost\",\"calls\":%lld,\"threads\":%d,\"avx\":%d,\"ns_per_call\":%.2f}\n",
           g_calls, threads, g_avx, ns / (double)g_calls);
    fflush(stdout);
    return 0;
}
