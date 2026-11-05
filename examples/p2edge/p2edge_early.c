/* Statically imported by p2edge_target. With --hold on the command line, its
   DllMain(PROCESS_ATTACH) starts a thread that calls EarlySite EDGE_CALLS times at once --
   while the main thread has not reached main() (UHH holds it at the image entry point). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>

#define EDGE_CALLS 2000
static volatile LONG_PTR g_early_sink;
static volatile LONG g_early_calls;
static HANDLE g_thread;

__declspec(dllexport) __declspec(noinline) LONG_PTR EarlySite(LONG_PTR i) {
    g_early_sink += i;            /* a few bytes of real work: hookable by every backend */
    return g_early_sink ^ i;
}

static DWORD WINAPI early_thread(void *arg) {
    (void)arg;
    for (LONG_PTR i = 0; i < EDGE_CALLS; ++i) { EarlySite(i); InterlockedIncrement(&g_early_calls); }
    return 0;
}

/* Called by main: waits for the DllMain thread, returns how many calls it made. */
__declspec(dllexport) LONG EdgeEarlyJoin(void) {
    if (g_thread) { WaitForSingleObject(g_thread, INFINITE); CloseHandle(g_thread); g_thread = NULL; }
    return g_early_calls;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, void *reserved) {
    (void)h; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH && strstr(GetCommandLineA(), "--hold"))
        g_thread = CreateThread(NULL, 0, early_thread, NULL, 0, NULL);   /* runs once process init ends */
    return TRUE;
}
