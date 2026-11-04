// Dynamic-watchpoint demo target: the malloc -> watch case on the REAL CRT allocator.
// It makes some unrelated allocations (noise), then malloc(0x1337) -- the block the
// driver follows -- and writes it from the main thread and from a worker thread
// started AFTER the watchpoint exists (so the watch must reach new threads too).
// Unrelated blocks are written as well; those writes must NOT be reported.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRACKED_SIZE 0x1337

static long g_writes = 100;
static volatile long g_marker_calls;

// Hooked at RUNTIME with an inline probe that a callback adds. The install happens on
// a fresh agent thread (asynchronously), so main pauses briefly before calling it.
__declspec(dllexport) __declspec(noinline) void dynwatch_marker(long i) { (void)i; g_marker_calls += 1; }

// Called FROM a callback via call_func (never by the program itself): six arguments so
// x64 passes two on the stack. Returns 1*a + 2*b + ... + 6*f.
__declspec(dllexport) __declspec(noinline) long long dynwatch_sum6(long long a, long long b, long long c,
                                                                  long long d, long long e, long long f) {
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f;
}
static volatile long *g_block;

static int wait_gate(void) {
    char b; DWORD n = 0; HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    return in != INVALID_HANDLE_VALUE && ReadFile(in, &b, 1, &n, NULL) && n == 1;
}

static DWORD WINAPI worker(void *arg) {
    (void)arg;
    for (long i = 0; i < g_writes; ++i) g_block[0] = -i;   // watched: one hit per store
    return 0;
}

int main(int argc, char **argv) {
    int no_wait = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--writes") && i + 1 < argc) g_writes = atol(argv[++i]);
        else if (!strcmp(argv[i], "--no-wait")) no_wait = 1;
    }
    printf("{\"kind\":\"waiting\"}\n"); fflush(stdout);
    if (!no_wait && !wait_gate()) return 3;
    volatile long *noise[4];
    for (int i = 0; i < 4; ++i) noise[i] = (volatile long *)malloc(64 + 16 * i);   // not tracked
    g_block = (volatile long *)malloc(TRACKED_SIZE);                              // tracked
    if (!g_block) return 4;
    for (long i = 0; i < g_writes; ++i) {
        g_block[0] = i;                                    // watched
        for (int k = 0; k < 4; ++k) noise[k][0] = i;       // not watched
    }
    HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if (!t) return 5;
    WaitForSingleObject(t, INFINITE); CloseHandle(t);
    Sleep(300);
    for (long i = 0; i < 50; ++i) dynwatch_marker(i);
    printf("{\"kind\":\"target\",\"marker_calls\":%ld,\"writes_per_thread\":%ld,\"threads\":2,\"expected_watch_hits\":%ld}\n",
           g_marker_calls, g_writes, 2 * g_writes);
    fflush(stdout);
    for (int i = 0; i < 4; ++i) free((void *)noise[i]);
    // The tracked block is deliberately NOT freed: HeapFree writes free-list metadata
    // into the block's first bytes, and the watchpoint would (correctly) report those
    // allocator writes too -- which would make the expected count non-deterministic.
    return 0;
}
