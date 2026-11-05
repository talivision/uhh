/* p2edge_target: lifecycle edge cases for the P2 checks (driven by p2edge_driver).
 *
 *   p2edge_target --hold   a TLS callback and p2edge_early.dll's DllMain each start a thread
 *                        that calls its site (TlsSite / EarlySite) EDGE_CALLS times right
 *                        away -- during UHH's entry hold, before main() runs.
 *   p2edge_target --late   a WORKER thread LoadLibrary's p2edge_late.dll and calls
 *                        LateSite(i, LateNext) N times, then LateNext N times; a second
 *                        thread then calls LateNext N times.
 *   p2edge_target --hw     MarkA(HwSite3); T threads x N: HwSite(i) + InterlockedIncrement(g_w1);
 *                        MarkB(HwSite2, &g_w2, HwSite3); T threads x N: HwSite2(i) + ++g_w2.
 * Prints one {"kind":"edge",...} line with the target's own call counts. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EDGE_CALLS 2000
__declspec(dllimport) LONG EdgeEarlyJoin(void);

static volatile LONG_PTR g_tls_sink, g_hw_sink, g_hw2_sink, g_hw3_sink, g_mark_sink;
static volatile LONG g_tls_calls;
static HANDLE g_tls_thread;
__declspec(dllexport) volatile LONG g_w1, g_w2;    /* data watch targets (exported for module!symbol) */

__declspec(dllexport) __declspec(noinline) LONG_PTR TlsSite(LONG_PTR i) { g_tls_sink += i; return g_tls_sink ^ i; }
__declspec(dllexport) __declspec(noinline) LONG_PTR HwSite(LONG_PTR i) { g_hw_sink += i; return g_hw_sink ^ i; }
__declspec(dllexport) __declspec(noinline) LONG_PTR HwSite2(LONG_PTR i) { g_hw2_sink += i; return g_hw2_sink ^ i; }
__declspec(dllexport) __declspec(noinline) LONG_PTR HwSite3(LONG_PTR i) { g_hw3_sink += i; return g_hw3_sink ^ i; }
/* Phase markers: the driver's callbacks act on the pointers passed here. */
__declspec(dllexport) __declspec(noinline) LONG_PTR MarkA(void *a) { g_mark_sink += (LONG_PTR)a; return g_mark_sink; }
__declspec(dllexport) __declspec(noinline) LONG_PTR MarkB(void *a, void *b, void *c) {
    g_mark_sink += (LONG_PTR)a + (LONG_PTR)b + (LONG_PTR)c; return g_mark_sink;
}

/* ---- --hold: a thread started from a TLS callback ---------------------------------- */
static DWORD WINAPI tls_thread(void *arg) {
    (void)arg;
    for (LONG_PTR i = 0; i < EDGE_CALLS; ++i) { TlsSite(i); InterlockedIncrement(&g_tls_calls); }
    return 0;
}
static void NTAPI tls_callback(PVOID h, DWORD reason, PVOID reserved) {
    (void)h; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH && !g_tls_thread && strstr(GetCommandLineA(), "--hold"))
        g_tls_thread = CreateThread(NULL, 0, tls_thread, NULL, 0, NULL);
}
#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB")) const PIMAGE_TLS_CALLBACK edge_tls_ptr = tls_callback;
#if defined(_WIN64)
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:edge_tls_ptr")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_edge_tls_ptr")
#endif

/* ---- --late ------------------------------------------------------------------------ */
typedef LONG_PTR (*late_fn)(LONG_PTR, void *);
typedef LONG_PTR (*next_fn)(LONG_PTR);
static next_fn g_next;
static volatile LONG g_late_calls, g_next_calls;
static DWORD WINAPI next_thread(void *arg) {
    (void)arg;
    for (LONG_PTR i = 0; i < EDGE_CALLS; ++i) { g_next(i); InterlockedIncrement(&g_next_calls); }
    return 0;
}
static DWORD WINAPI late_worker(void *arg) {
    (void)arg;
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH);
    while (n && path[n - 1] != '\\') --n;
    strcpy(path + n, "p2edge_late.dll");
    HMODULE m = LoadLibraryA(path);
    if (!m) return 1;
    late_fn late = (late_fn)GetProcAddress(m, "LateSite");
    g_next = (next_fn)GetProcAddress(m, "LateNext");
    if (!late || !g_next) return 2;
    for (LONG_PTR i = 0; i < EDGE_CALLS; ++i) { late(i, (void *)g_next); InterlockedIncrement(&g_late_calls); }
    for (LONG_PTR i = 0; i < EDGE_CALLS; ++i) { g_next(i); InterlockedIncrement(&g_next_calls); }
    HANDLE t = CreateThread(NULL, 0, next_thread, NULL, 0, NULL);   /* another thread, after the add */
    if (!t) return 3;
    WaitForSingleObject(t, INFINITE); CloseHandle(t);
    return 0;
}

/* ---- --hw -------------------------------------------------------------------------- */
static int g_hw_threads = 4, g_hw_calls = 1000;
static DWORD WINAPI hw_phase1(void *arg) {
    (void)arg;
    for (int i = 0; i < g_hw_calls; ++i) { HwSite(i); InterlockedIncrement(&g_w1); }
    return 0;
}
static DWORD WINAPI hw_phase2(void *arg) {
    (void)arg;
    for (int i = 0; i < g_hw_calls; ++i) { HwSite2(i); InterlockedIncrement(&g_w2); }
    return 0;
}
static void run_threads(LPTHREAD_START_ROUTINE fn) {
    HANDLE h[64];
    for (int t = 0; t < g_hw_threads; ++t) h[t] = CreateThread(NULL, 0, fn, NULL, 0, NULL);
    WaitForMultipleObjects((DWORD)g_hw_threads, h, TRUE, INFINITE);
    for (int t = 0; t < g_hw_threads; ++t) CloseHandle(h[t]);
}

int main(int argc, char **argv) {
    const char *mode = "";
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--hold") || !strcmp(argv[i], "--late") || !strcmp(argv[i], "--hw")) mode = argv[i] + 2;
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) g_hw_threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--calls") && i + 1 < argc) g_hw_calls = atoi(argv[++i]);
    }
    if (g_hw_threads < 1 || g_hw_threads > 64) g_hw_threads = 4;
    if (!strcmp(mode, "hold")) {
        LONG early = EdgeEarlyJoin();
        if (g_tls_thread) { WaitForSingleObject(g_tls_thread, INFINITE); CloseHandle(g_tls_thread); }
        printf("{\"kind\":\"edge\",\"mode\":\"hold\",\"tls_calls\":%ld,\"early_calls\":%ld}\n", g_tls_calls, early);
    } else if (!strcmp(mode, "late")) {
        HANDLE t = CreateThread(NULL, 0, late_worker, NULL, 0, NULL);
        DWORD rc = 99;
        if (t) { WaitForSingleObject(t, INFINITE); GetExitCodeThread(t, &rc); CloseHandle(t); }
        printf("{\"kind\":\"edge\",\"mode\":\"late\",\"worker_rc\":%lu,\"late_calls\":%ld,\"next_calls\":%ld}\n",
               rc, g_late_calls, g_next_calls);
    } else if (!strcmp(mode, "hw")) {
        MarkA((void *)HwSite3);
        run_threads(hw_phase1);
        MarkB((void *)HwSite2, (void *)&g_w2, (void *)HwSite3);
        run_threads(hw_phase2);
        printf("{\"kind\":\"edge\",\"mode\":\"hw\",\"threads\":%d,\"calls\":%d,\"w1\":%ld,\"w2\":%ld}\n",
               g_hw_threads, g_hw_calls, g_w1, g_w2);
    } else {
        (void)EdgeEarlyJoin();
        printf("{\"kind\":\"edge\",\"mode\":\"none\"}\n");
    }
    fflush(stdout);
    return 0;
}
