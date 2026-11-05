/* latedll_target <main|worker|dllmain>: probed functions in DLLs loaded at RUN time.
 *   main     the main thread LoadLibrary's latedll_fix.dll and at once calls LdSite0..7
 *            LD_CALLS times each.
 *   worker   the same from a worker thread.
 *   dllmain  the main thread LoadLibrary's latedll_heavy.dll, whose DllMain loads
 *            latedll_fix.dll, calls every site under the loader lock and starts a thread
 *            (latedll_heavy.c); then main calls every site LD_CALLS times more.
 * Prints {"kind":"latedll",...} with the bodies' own call counts (calls[k], hv) and the
 * counts the scenario must produce (want[k], want_hv). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "latedll_shared.h"

typedef LONG_PTR (*site_fn)(LONG_PTR, LONG_PTR);
typedef LONG (*count_fn)(int);
typedef LONG (*hvcount_fn)(void);

static HMODULE load(const char *dll) {
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH);
    while (n && path[n - 1] != '\\') --n;
    strcpy(path + n, dll);
    return LoadLibraryA(path);
}

static LONG call_all(HMODULE fix) {
    site_fn f[LD_NSITES];
    for (int k = 0; k < LD_NSITES; ++k) {
        char name[16] = "LdSite0"; name[6] = (char)('0' + k);
        if (!(f[k] = (site_fn)GetProcAddress(fix, name))) return 12;
    }
    for (LONG_PTR i = 0; i < LD_CALLS; ++i)
        for (int k = 0; k < LD_NSITES; ++k) f[k](k, i);
    return 0;
}

static DWORD WINAPI worker(void *arg) {
    (void)arg;
    HMODULE fix = load("latedll_fix.dll");
    return fix ? (DWORD)call_all(fix) : 11;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "main";
    LONG rc = 0, want[LD_NSITES], want_hv = 0, hv = 0;
    HMODULE heavy = NULL;
    for (int k = 0; k < LD_NSITES; ++k) want[k] = LD_CALLS;
    if (!strcmp(mode, "main")) {
        HMODULE fix = load("latedll_fix.dll");
        rc = fix ? call_all(fix) : 11;
    } else if (!strcmp(mode, "worker")) {
        HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        DWORD wrc = 99;
        if (t) { WaitForSingleObject(t, INFINITE); GetExitCodeThread(t, &wrc); CloseHandle(t); }
        rc = (LONG)wrc;
    } else if (!strcmp(mode, "dllmain")) {
        heavy = load("latedll_heavy.dll");
        LONG (*join)(void) = heavy ? (LONG (*)(void))GetProcAddress(heavy, "HvJoin") : NULL;
        rc = !heavy ? 21 : !join ? 22 : join();
        if (!rc) rc = call_all(GetModuleHandleA("latedll_fix.dll"));
        site_fn hvsite = heavy ? (site_fn)GetProcAddress(heavy, "HvSite") : NULL;
        if (!rc && hvsite) for (LONG_PTR i = 0; i < LD_CALLS; ++i) hvsite(LD_HV_ID, i);
        for (int k = 0; k < LD_NSITES; ++k) want[k] = 2 * LD_CALLS;   /* DllMain + main */
        want[0] += LD_CALLS;                                          /* + the DllMain thread */
        want_hv = 3 * LD_CALLS;                                       /* DllMain + its thread + main */
        hvcount_fn hc = heavy ? (hvcount_fn)GetProcAddress(heavy, "HvCount") : NULL;
        hv = hc ? hc() : -1;
    } else rc = 2;
    HMODULE fix = GetModuleHandleA("latedll_fix.dll");
    count_fn cnt = fix ? (count_fn)GetProcAddress(fix, "LdCount") : NULL;
    printf("{\"kind\":\"latedll\",\"mode\":\"%s\",\"rc\":%ld,\"calls\":[", mode, rc);
    for (int k = 0; k < LD_NSITES; ++k) printf("%s%ld", k ? "," : "", cnt ? cnt(k) : -1L);
    printf("],\"want\":[");
    for (int k = 0; k < LD_NSITES; ++k) printf("%s%ld", k ? "," : "", want[k]);
    printf("],\"hv\":%ld,\"want_hv\":%ld}\n", hv, want_hv);
    fflush(stdout);
    return (int)rc;
}
