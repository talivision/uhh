// susp_target (regress cx2-evsusp-*, cx2-cosusp-*; Codex review 2's X2 open note): the PROGRAM
// suspends a worker right after the controller let it run again, then the controller dies.
//   susp_target evsusp: the worker's probe hit (co_add) was handled and continued; it counts on.
//   susp_target cosusp: the worker is inside co_hold, run by its callback's call_original.
// Gate 1 (stdin): the controller is attached and its probe active -> the worker goes. The main
// thread suspends it once it runs on ("susp"). Gate 2: the controller is dead. Then the worker
// must still be suspended exactly once by the program (it did not run meanwhile, the program's
// ResumeThread reports 1) and it finishes normally. Driven by co_driver(_th) --module
// susp_target.exe; its own executable so co_target's code (callorig-hunt-*) is not perturbed.
//
// F5 (regress callorig-deep-*): a call_original whose original is LEFT -- a C++ throw (deepthrow),
// an SEH raise (deepseh) or a longjmp (deepjmp) -- caught / landed above it; then the program calls
// a probed function from a DEEPER frame than the left call's (deeper(): a real frame below the
// one that made the probed call). Every such later hit must run its callback (as inline does).
// catchhit: the probed call is made inside the catch block itself.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdexcept>

#define CO_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)

static volatile LONG g_spun = 0, g_spin_stop = 0;
CO_EXPORT intptr_t co_add(intptr_t a, intptr_t b) { return a * 3 + b; }
CO_EXPORT intptr_t co_hold(intptr_t x) {                   // an original that runs ~3 s, counting
    for (int i = 0; i < 300; ++i) { InterlockedIncrement(&g_spun); Sleep(10); }
    return x * 19;
}

static volatile intptr_t g_zero = 0;
CO_EXPORT intptr_t co_after(intptr_t x) { return x * 7 + g_zero; }
CO_EXPORT intptr_t co_throw(intptr_t x) {
    if (x & 1) throw std::runtime_error("odd");
    return x * 3 + g_zero;
}
CO_EXPORT intptr_t co_seh(intptr_t x) {
    if (x & 1) RaiseException(0xE0C0FFEEu, 0, 0, nullptr);
    return x + 100 + g_zero;
}
CO_EXPORT intptr_t co_jump(jmp_buf *env, intptr_t x) {
    if (x & 1) longjmp(*env, (int)x);
    return x * 5 + g_zero;
}
// A real frame below its caller's: the probed call it makes is deeper than the left one.
static __declspec(noinline) intptr_t deeper(intptr_t x) {
    volatile intptr_t pad[16];
    for (int i = 0; i < 16; ++i) pad[i] = x + i;
    return co_after(pad[x & 15]) + pad[0];
}
static __declspec(noinline) int seh_call(intptr_t x, intptr_t *r) {   // SEH and C++ objects: own frame
    __try { *r = co_seh(x); return 0; }
    __except (GetExceptionCode() == 0xE0C0FFEEu ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { return 1; }
}
static __declspec(noinline) intptr_t jump_call(intptr_t x, int *jumped) {
    jmp_buf env;
    const int v = setjmp(env);
    if (v) { *jumped += 1; return 1000 + v; }
    return co_jump(&env, x);
}
static int run_deep(const char *k) {
    intptr_t sum = 0, after = 0;
    int left = 0;
    for (intptr_t x = 0; x < 10; ++x) {
        if (!strcmp(k, "deepthrow") || !strcmp(k, "catchhit")) {
            try { sum += co_throw(x); }
            catch (const std::runtime_error &e) {
                if (!strcmp(e.what(), "odd")) ++left;
                if (k[0] == 'c') after += co_after(100 + x);       // catchhit: inside the catch block
            }
        } else if (!strcmp(k, "deepseh")) {
            intptr_t r = 0;
            if (seh_call(x, &r)) ++left; else sum += r;
        } else {
            sum += jump_call(x, &left);
        }
        if (k[0] == 'd') after += deeper(x);
    }
    printf("{\"kind\":\"co\",\"case\":\"%s\",\"sum\":%lld,\"left\":%d,\"after\":%lld}\n", k, (long long)sum, left,
           (long long)after);
    fflush(stdout);
    return 0;
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
    if (!strcmp(k, "deepthrow") || !strcmp(k, "deepseh") || !strcmp(k, "deepjmp") || !strcmp(k, "catchhit"))
        return run_deep(k);
    const bool co = !strcmp(k, "cosusp");
    if (!co && strcmp(k, "evsusp")) { fprintf(stderr, "susp_target: unknown case '%s'\n", k); return 2; }
    g_go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE w = CreateThread(nullptr, 0, worker, co ? (void *)1 : nullptr, 0, nullptr);
    if (!g_go || !w) return 4;
    printf("{\"kind\":\"waiting\",\"pid\":%lu,\"tid\":%lu}\n", GetCurrentProcessId(), GetCurrentThreadId()); fflush(stdout);
    if (!read_gate()) return 3;                                  // gate 1: the probe is active
    SetEvent(g_go);
    for (int i = 0; i < 60000 && g_spun == 0; ++i) Sleep(1);     // it runs on (after its hit / in the original)
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
