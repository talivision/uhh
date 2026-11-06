// susp_target (regress cx2-evsusp-*, cx2-cosusp-*; Codex review 2's X2 open note): the PROGRAM
// suspends a worker right after the controller let it run again, then the controller dies.
//   susp_target evsusp: the worker's probe hit (co_add) was handled and continued; it counts on.
//   susp_target cosusp: the worker is inside co_hold, run by its callback's call_original.
//   susp_target cosample: the worker is inside co_hold, run by call_original, and the controller
//     stays; the main thread samples the worker's suspend count for 1 s (SuspendThread +
//     ResumeThread in a loop): a suspension of the CONTROLLER in place at a sample shows as a
//     previous count of 1 ("foreign"), a side effect the program can see. No gate 2.
// Gate 1 (stdin): the controller is attached and its probe active -> the worker goes. The main
// thread suspends it once it runs on ("susp"). Gate 2: the controller is dead. Then the worker
// must still be suspended exactly once by the program (it did not run meanwhile, the program's
// ResumeThread reports 1) and it finishes normally. Driven by co_driver(_th) --module
// susp_target.exe; its own executable so co_target's code (callorig-hunt-*) is not perturbed.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CO_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)

static volatile LONG g_spun = 0, g_spin_stop = 0;
CO_EXPORT intptr_t co_add(intptr_t a, intptr_t b) { return a * 3 + b; }
CO_EXPORT intptr_t co_hold(intptr_t x) {                   // an original that runs ~3 s, counting
    for (int i = 0; i < 300; ++i) { InterlockedIncrement(&g_spun); Sleep(10); }
    return x * 19;
}

static HANDLE g_go;
static intptr_t g_worker_ret;
static DWORD WINAPI worker(void *p) {
    WaitForSingleObject(g_go, INFINITE);
    if (p) { g_worker_ret = co_hold(4); return 0; }
    g_worker_ret = co_add(1, 2);
    while (!g_spin_stop) { InterlockedIncrement(&g_spun); Sleep(1); }
    return 0;
}
static bool read_gate() {
    char b; DWORD n = 0;
    return ReadFile(GetStdHandle(STD_INPUT_HANDLE), &b, 1, &n, nullptr) && n == 1;
}

int main(int argc, char **argv) {
    const char *k = argc > 1 ? argv[1] : "";
    const bool sample = !strcmp(k, "cosample");
    const bool co = sample || !strcmp(k, "cosusp");
    if (!co && strcmp(k, "evsusp")) { fprintf(stderr, "susp_target: unknown case '%s'\n", k); return 2; }
    g_go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE w = CreateThread(nullptr, 0, worker, co ? (void *)1 : nullptr, 0, nullptr);
    if (!g_go || !w) return 4;
    printf("{\"kind\":\"waiting\",\"pid\":%lu,\"tid\":%lu}\n", GetCurrentProcessId(), GetCurrentThreadId()); fflush(stdout);
    if (!read_gate()) return 3;                                  // gate 1: the probe is active
    SetEvent(g_go);
    for (int i = 0; i < 60000 && g_spun == 0; ++i) Sleep(1);     // it runs on (after its hit / in the original)
    if (sample) {
        long n = 0, foreign = 0, in_original = 0;
        const ULONGLONG t0 = GetTickCount64();
        while (GetTickCount64() - t0 < 1000 && g_spun < 250) {      // well inside co_hold (300 x 10 ms)
            const DWORD prev = SuspendThread(w);
            if (prev == (DWORD)-1) break;
            ResumeThread(w);
            ++n; if (prev != 0) ++foreign;
        }
        in_original = g_spun < 300;
        const DWORD done = WaitForSingleObject(w, 30000);
        printf("{\"kind\":\"co\",\"case\":\"%s\",\"samples\":%ld,\"foreign\":%ld,\"in_original\":%ld,\"done\":%d,\"ret\":%lld}\n",
               k, n, foreign, in_original, done == WAIT_OBJECT_0, (long long)g_worker_ret);
        fflush(stdout);
        return 0;
    }
    const DWORD first = SuspendThread(w);
    printf("{\"kind\":\"susp\",\"tid\":%lu}\n", GetThreadId(w)); fflush(stdout);
    if (!read_gate()) return 3;                                  // gate 2: the controller is dead
    BOOL dbg = TRUE;
    for (int i = 0; i < 3000 && CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg) && dbg; ++i) Sleep(10);
    Sleep(1500);                                                 // the guard's cleanup
    const LONG c1 = g_spun;
    Sleep(300);
    const LONG c2 = g_spun;
    const DWORD prev = ResumeThread(w);
    InterlockedExchange(&g_spin_stop, 1);
    const DWORD done = WaitForSingleObject(w, 30000);
    printf("{\"kind\":\"co\",\"case\":\"%s\",\"first\":%lu,\"prev\":%lu,\"ran_while_suspended\":%ld,"
           "\"done\":%d,\"ret\":%lld,\"debugger\":%d}\n", k, first, prev, (long)(c2 - c1), done == WAIT_OBJECT_0,
           (long long)g_worker_ret, (int)dbg);
    fflush(stdout);
    return 0;
}
