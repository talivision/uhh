// tick_target [--threads T] [--calls N]
// Prints what GetTickCount returns. Two call sites: tick_worker (T threads x N calls) and
// tick_main (main: N calls plus a classic anti-debug timing check around Sleep(150) that
// "detects" a slow run when the elapsed ticks exceed 100). GetTickCount64 is the control:
// it is never overridden. Ground truth on stdout.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FORCED 0x1337BEEFu

static volatile DWORD g_sink, g_sink_main;   // distinct, so /OPT:ICF cannot fold the two sites
static volatile LONG g_calls, g_forced;
static int g_n = 25;

__declspec(noinline) static DWORD tick_worker(void) {
    DWORD t = GetTickCount();
    g_sink = t;                       // keeps the call from becoming a tail call
    return t;
}

__declspec(noinline) static DWORD tick_main(void) {
    DWORD t = GetTickCount();
    g_sink_main = t;
    return t;
}

static volatile LONG g_forced_by[33];     // per thread (index 32: main)

static void count(int who, DWORD t) {
    InterlockedIncrement(&g_calls);
    if (t == FORCED) { InterlockedIncrement(&g_forced); InterlockedIncrement(&g_forced_by[who]); }
}

static DWORD WINAPI worker(void *arg) {
    int k = (int)(INT_PTR)arg;
    for (int i = 0; i < g_n; ++i) { count(k, tick_worker()); Sleep(1); }
    return 0;
}

int main(int argc, char **argv) {
    int threads = 4;
    for (int i = 1; i + 1 < argc; ++i) {
        if (!strcmp(argv[i], "--threads")) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--calls")) g_n = atoi(argv[++i]);
    }
    if (threads < 1 || threads > 32 || g_n < 1) return 2;
    HANDLE h[32];
    for (int k = 0; k < threads; ++k) h[k] = CreateThread(NULL, 0, worker, (void *)(INT_PTR)k, 0, NULL);
    for (int i = 0; i < g_n; ++i) count(32, tick_main());
    DWORD start = tick_main();
    count(32, start);
    Sleep(150);
    DWORD end = tick_main();
    count(32, end);
    WaitForMultipleObjects((DWORD)threads, h, TRUE, INFINITE);
    for (int k = 0; k < threads; ++k) CloseHandle(h[k]);
    ULONGLONG t64 = GetTickCount64();
    printf("{\"kind\":\"app\",\"calls\":%ld,\"forced\":%ld,\"elapsed\":%lu,\"timing_check\":\"%s\",\"tick64_forced\":%d,"
           "\"forced_main\":%ld,\"forced_workers\":[", g_calls, g_forced, end - start,
           end - start > 100 ? "slow" : "fast", (DWORD)t64 == FORCED, g_forced_by[32]);
    for (int k = 0; k < threads; ++k) printf("%s%ld", k ? "," : "", g_forced_by[k]);
    printf("]}\n");
    fflush(stdout);
    return 0;
}
