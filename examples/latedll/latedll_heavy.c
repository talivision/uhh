/* latedll_heavy.dll: the loader-lock-heavy case. LoadLibrary'd by latedll_target's main
 * thread; its DllMain(PROCESS_ATTACH) -- running under the loader lock --
 *   1. LoadLibrary's latedll_fix.dll (a nested load: its LOAD_DLL event comes while this
 *      thread owns the loader lock),
 *   2. calls every LdSite and its own HvSite LD_CALLS times (probed calls under the lock),
 *   3. starts a thread that calls HvSite and LdSite0 LD_CALLS times (it can only start
 *      once the loader lock is free).
 * HvJoin() waits for that thread. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include "latedll_shared.h"

typedef LONG_PTR (*site_fn)(LONG_PTR, LONG_PTR);
static volatile LONG g_hv_calls;
static volatile LONG_PTR g_hv_sink;
static HANDLE g_thread;
static site_fn g_fix[LD_NSITES];
static LONG g_rc = -1;

__declspec(dllexport) __declspec(noinline) LONG_PTR HvSite(LONG_PTR id, LONG_PTR i) {
    InterlockedIncrement(&g_hv_calls); g_hv_sink += id + 7 * i; return g_hv_sink ^ i;
}
__declspec(dllexport) LONG HvCount(void) { return g_hv_calls; }

static DWORD WINAPI hv_thread(void *arg) {
    (void)arg;
    for (LONG_PTR i = 0; i < LD_CALLS; ++i) { HvSite(LD_HV_ID, i); g_fix[0](0, i); }
    return 0;
}

/* 0 = DllMain did everything; else what failed. Waits for the DllMain thread. */
__declspec(dllexport) LONG HvJoin(void) {
    if (g_thread) { WaitForSingleObject(g_thread, INFINITE); CloseHandle(g_thread); g_thread = NULL; }
    return g_rc;
}

static LONG attach(HINSTANCE self) {
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(self, path, MAX_PATH);
    while (n && path[n - 1] != '\\') --n;
    strcpy(path + n, "latedll_fix.dll");
    HMODULE fix = LoadLibraryA(path);
    if (!fix) return 1;
    for (int k = 0; k < LD_NSITES; ++k) {
        char name[16] = "LdSite0"; name[6] = (char)('0' + k);
        if (!(g_fix[k] = (site_fn)GetProcAddress(fix, name))) return 2;
    }
    for (LONG_PTR i = 0; i < LD_CALLS; ++i) {
        for (int k = 0; k < LD_NSITES; ++k) g_fix[k](k, i);
        HvSite(LD_HV_ID, i);
    }
    g_thread = CreateThread(NULL, 0, hv_thread, NULL, 0, NULL);
    return g_thread ? 0 : 3;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, void *reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) g_rc = attach(h);
    return TRUE;
}
