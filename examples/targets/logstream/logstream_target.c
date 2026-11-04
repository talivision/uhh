#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_count = 50;
static int g_delay_ms = 100;
static int g_ticks = 1;
static volatile LONG g_sink;

/* Kept as a real exported call site: the side effect prevents whole-program builds
   from proving the calls irrelevant, while each thread's argument remains its own
   simple 0..N-1 sequence. */
__declspec(noinline) void LogSite(int i) {
    InterlockedAdd(&g_sink, i);
}

static DWORD WINAPI run_sequence(void *unused) {
    int i;
    (void)unused;
    for (i = 0; i < g_count; ++i) {
        if (g_ticks) {
            printf("{\"kind\":\"tick\",\"i\":%d}\n", i);
            fflush(stdout);
        }
        LogSite(i);
        if (g_delay_ms) Sleep((DWORD)g_delay_ms);
    }
    return 0;
}

int main(int argc, char **argv) {
    int threads = 1;
    int i;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--count") && i + 1 < argc) g_count = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--delay") && i + 1 < argc) g_delay_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--no-ticks")) g_ticks = 0;
    }
    if (g_count < 0 || threads < 1 || threads > 64 || g_delay_ms < 0) return 2;

    if (threads == 1) return (int)run_sequence(NULL);
    {
        HANDLE workers[64];
        int made = 0;
        for (i = 0; i < threads; ++i) {
            workers[i] = CreateThread(NULL, 0, run_sequence, NULL, 0, NULL);
            if (!workers[i]) break;
            ++made;
        }
        if (made) WaitForMultipleObjects((DWORD)made, workers, TRUE, INFINITE);
        for (i = 0; i < made; ++i) CloseHandle(workers[i]);
        return made == threads ? 0 : 1;
    }
}
