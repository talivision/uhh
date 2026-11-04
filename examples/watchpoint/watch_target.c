// Watchpoint demo target. A single aligned global DWORD is written in a loop by W
// worker threads; a UHH hardware data watchpoint on its address should fire once per
// store. Observing DATA access like this is something inline/trampoline hooking
// cannot do at all — only a debug-register watchpoint sees a plain memory write.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 4-byte, dword-aligned, in the map by name so site_rvas.py can recover its RVA.
__declspec(align(4)) volatile long g_watched = 0;

static long g_threads = 1, g_writes = 100, g_reads = 0;
static volatile long g_sink;

static DWORD WINAPI worker(void *arg) {
    long id = (long)(intptr_t)arg;
    for (long i = 0; i < g_writes; ++i) g_watched = id * 100000 + i;   // store to the watched dword
    for (long i = 0; i < g_reads; ++i) g_sink = g_watched;              // load from it (RW mode only)
    return 0;
}

static int wait_gate(void) {
    char b; DWORD n = 0; HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    return in != INVALID_HANDLE_VALUE && ReadFile(in, &b, 1, &n, NULL) && n == 1;
}

int main(int argc, char **argv) {
    int no_wait = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--threads") && i + 1 < argc) g_threads = atol(argv[++i]);
        else if (!strcmp(argv[i], "--writes") && i + 1 < argc) g_writes = atol(argv[++i]);
        else if (!strcmp(argv[i], "--reads") && i + 1 < argc) g_reads = atol(argv[++i]);
        else if (!strcmp(argv[i], "--no-wait")) no_wait = 1;
    }
    if (g_threads < 1) g_threads = 1;
    printf("{\"kind\":\"waiting\"}\n"); fflush(stdout);
    if (!no_wait && !wait_gate()) return 3;
    HANDLE *h = (HANDLE *)malloc(sizeof(HANDLE) * g_threads);
    for (long t = 0; t < g_threads; ++t) h[t] = CreateThread(NULL, 0, worker, (void *)(intptr_t)t, 0, NULL);
    WaitForMultipleObjects((DWORD)g_threads, h, TRUE, INFINITE);
    for (long t = 0; t < g_threads; ++t) CloseHandle(h[t]);
    printf("{\"kind\":\"target\",\"threads\":%ld,\"writes\":%ld,\"reads\":%ld,\"total\":%ld,\"final\":%ld}\n",
           g_threads, g_writes, g_reads, g_threads * g_writes, g_watched);
    fflush(stdout);
    free(h);
    return 0;
}
