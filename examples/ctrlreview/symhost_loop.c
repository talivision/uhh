/* symhost_loop <symhost.dll> <iterations> -- load symhost.dll, run symhost_run (create + close an
 * unlaunched UHH session), unload it at once; repeat. Then wait (10 s at most) until the DLL is
 * really gone (a background thread holding a reference must release it once done).
 * {"kind":"symhost","iterations":N,"ok":<runs that returned 1>,"held":<times the DLL was still mapped right
 * after its FreeLibrary: a thread's reference>,"gone":<1: unmapped at the end>}
 * An access violation in the unloaded image kills the process (exit code != 0). */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*run_fn)(void);

static LONG WINAPI crashed(EXCEPTION_POINTERS *ep) {
    printf("{\"kind\":\"unhandled\",\"code\":\"0x%08lx\",\"ip\":\"0x%p\"}\n", ep->ExceptionRecord->ExceptionCode,
           ep->ExceptionRecord->ExceptionAddress);
    fflush(stdout);
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: symhost_loop <dll> <iterations>\n"); return 2; }
    SetUnhandledExceptionFilter(crashed);
    const int n = atoi(argv[2]);
    int ok = 0, held = 0;
    const char *base = strrchr(argv[1], '\\');
    base = base ? base + 1 : argv[1];
    for (int i = 0; i < n; ++i) {
        HMODULE m = LoadLibraryA(argv[1]);
        if (!m) { fprintf(stderr, "load failed %lu\n", GetLastError()); return 3; }
        run_fn run = (run_fn)GetProcAddress(m, "symhost_run");
        if (run && run()) ++ok;
        FreeLibrary(m);
        if (GetModuleHandleA(base)) ++held;
    }
    int gone = 0;
    for (int t = 0; t < 1000 && !(gone = GetModuleHandleA(base) == NULL); ++t) Sleep(10);
    printf("{\"kind\":\"symhost\",\"iterations\":%d,\"ok\":%d,\"held\":%d,\"gone\":%d}\n", n, ok, held, gone);
    fflush(stdout);
    return 0;
}
