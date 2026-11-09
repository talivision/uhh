// susp_target (regress cx2-evsusp-*, cx2-cosusp-*; Codex review 2's X2 open note): the PROGRAM
// suspends a worker right after the controller let it run again, then the controller dies.
//   susp_target evsusp: the worker's probe hit (co_add) was handled and continued; it counts on.
//   susp_target cosusp: the worker is inside co_hold, run by its callback's call_original.
//   susp_target watchdeath: a killed guarded controller leaves a data DR; writes must succeed
//     without exposing its exception, while a foreign DR and an unrelated exception still work.
//   susp_target cosample: the worker is inside co_hold, run by call_original, and the controller
//     stays; the main thread samples the worker's suspend count for <= 1 s (SuspendThread +
//     ResumeThread in a loop): a suspension of the CONTROLLER in place at a sample shows as a
//     previous count of 1 ("foreign"), a side effect the program can see. No gate 2.
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
// catchhit: the probed call is made inside the catch block itself. catchinside: the control
// case -- the exception is caught INSIDE the original: every probed call is inside it.
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
CO_EXPORT intptr_t co_hold(intptr_t x) {                   // an original that runs ~x * 0.75 s, counting
    for (int i = 0; i < x * 75; ++i) { InterlockedIncrement(&g_spun); Sleep(10); }
    return x * 19;
}

static volatile intptr_t g_zero = 0;
CO_EXPORT intptr_t co_after(intptr_t x) { return x * 7 + g_zero; }
// Never called: co_driver --guard's inline probe (the agent and its guard in the session).
CO_EXPORT intptr_t co_idle(intptr_t x) { return (x ^ 0x1D1E) + g_zero * 3; }
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
// A real frame below its caller's, larger than any frame the left call was made from
// (jump_call's jmp_buf included): the probed call it makes is deeper than the left one.
static __declspec(noinline) intptr_t deeper(intptr_t x) {
    volatile intptr_t pad[64];
    for (int i = 0; i < 64; ++i) pad[i] = x + i;
    return co_after(pad[x & 15]) + pad[0];
}
// catchinside: the ORIGINAL (co_outer) throws and catches inside itself -- a probed call in
// the catch block -- then makes a deeper probed call: all of it is inside the original
// (counted, no callback, as inline's nested-call rule), the call returns normally.
static __declspec(noinline) intptr_t inner_try(intptr_t x) {
    try { return co_throw(x); } catch (const std::runtime_error &) { return co_after(200 + x) + 1; }
}
CO_EXPORT intptr_t co_outer(intptr_t x) { const intptr_t a = inner_try(x); return a + deeper(x); }
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
        if (!strcmp(k, "catchinside")) {
            sum += co_outer(x);
            left += (int)(x & 1);
            continue;
        }
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
    if (WaitForSingleObject(g_go, 60000) != WAIT_OBJECT_0) return 3;
    if (p) { g_worker_ret = co_hold((intptr_t)p); return 0; }   // cosusp: 4 (~3 s); cosample: 2
    g_worker_ret = co_add(1, 2);
    while (!g_spin_stop) { InterlockedIncrement(&g_spun); Sleep(1); }
    return 0;
}
static bool read_gate() {
    char b; DWORD n = 0;
    const HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    const ULONGLONG deadline = GetTickCount64() + 60000;
    while (GetTickCount64() < deadline) {
        DWORD available = 0;
        if (!PeekNamedPipe(in, nullptr, 0, nullptr, &available, nullptr)) return false;
        if (available) return ReadFile(in, &b, 1, &n, nullptr) && n == 1;
        Sleep(1);
    }
    fprintf(stderr, "susp_target: stdin gate timed out\n");
    return false;
}

// A data-watch trap reports the instruction AFTER this write, not the data address.
extern "C" { __declspec(dllexport) volatile LONG co_watch_value = 0; }
static volatile LONG g_watch_exceptions, g_own_hits, g_own_value;
static DWORD g_own_slot, g_stale_slots;
static DWORD WINAPI watchdeath_own_dr(void *main_thread) {
    HANDLE t = (HANDLE)main_thread;
    if (SuspendThread(t) == (DWORD)-1) return 1;
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    bool ok = GetThreadContext(t, &c) != 0;
    if (ok) {
        g_stale_slots = (DWORD)c.Dr7 & 0xFF;
        int slot = 0;
        while (slot < 4 && ((c.Dr7 >> (slot * 2)) & 3)) ++slot;
        ok = slot < 4;
        if (ok) {
            g_own_slot = 1u << slot;
            const DWORD_PTR address = (DWORD_PTR)&g_own_value;
            switch (slot) { case 0: c.Dr0 = address; break; case 1: c.Dr1 = address; break;
                            case 2: c.Dr2 = address; break; default: c.Dr3 = address; }
            c.Dr7 &= ~((decltype(c.Dr7))0xF << (16 + slot * 4));
            c.Dr7 |= ((decltype(c.Dr7))0xD << (16 + slot * 4)) | ((decltype(c.Dr7))1 << (slot * 2));
            ok = SetThreadContext(t, &c) != 0;
        }
    }
    ResumeThread(t);
    return ok ? 0 : 1;
}
static LONG CALLBACK watchdeath_veh(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ContextRecord->Dr6 & g_own_slot) InterlockedIncrement(&g_own_hits);
    else InterlockedIncrement(&g_watch_exceptions);
    // Let a failing guard finish too, so the regression reports the leaked exception.
    ep->ContextRecord->Dr7 &= ~(decltype(ep->ContextRecord->Dr7))0xFF;
    ep->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}
static int run_watchdeath() {
    if (!AddVectoredExceptionHandler(1, watchdeath_veh)) return 4;
    printf("{\"kind\":\"waiting\",\"pid\":%lu}\n", GetCurrentProcessId()); fflush(stdout);
    if (!read_gate()) return 3;                 // the controller died with the watch armed
    BOOL dbg = TRUE;
    for (int i = 0; i < 3000 && CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg) && dbg; ++i) Sleep(10);
    Sleep(1500);                               // exercise the lazy path AFTER guard cleanup
    // Inspect the still-armed stale UHH slot and add a foreign slot from another thread.
    HANDLE main_thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                                   FALSE, GetCurrentThreadId());
    if (!main_thread) return 4;
    HANDLE setup = CreateThread(nullptr, 0, watchdeath_own_dr, main_thread, 0, nullptr);
    if (!setup) { CloseHandle(main_thread); return 4; }
    const DWORD done = WaitForSingleObject(setup, 30000);
    DWORD setup_rc = 1;
    GetExitCodeThread(setup, &setup_rc);
    CloseHandle(setup); CloseHandle(main_thread);
    if (done != WAIT_OBJECT_0 || setup_rc != 0) return 4;
    co_watch_value = 41;
    co_watch_value += 1;                        // the UHH slot must now be disabled
    const LONG leaked = g_watch_exceptions;
    g_own_value = 7;                            // the guard must preserve the foreign DR slot
    RaiseException(EXCEPTION_SINGLE_STEP, 0, 0, nullptr); // unrelated target exception passes through
    printf("{\"kind\":\"co\",\"case\":\"watchdeath\",\"value\":%ld,\"exceptions\":%ld,"
           "\"target_exceptions\":%ld,\"own_hits\":%ld,\"stale_slots\":%lu,\"debugger\":%d}\n",
           co_watch_value, leaked, g_watch_exceptions - leaked, g_own_hits, g_stale_slots, (int)dbg);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    const char *k = argc > 1 ? argv[1] : "";
    if (!strcmp(k, "watchdeath")) return run_watchdeath();
    if (!strcmp(k, "deepthrow") || !strcmp(k, "deepseh") || !strcmp(k, "deepjmp") || !strcmp(k, "catchhit") ||
        !strcmp(k, "catchinside"))
        return run_deep(k);
    const bool sample = !strcmp(k, "cosample");
    const bool co = sample || !strcmp(k, "cosusp");
    if (!co && strcmp(k, "evsusp")) { fprintf(stderr, "susp_target: unknown case '%s'\n", k); return 2; }
    g_go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    // cosample: an original shorter than call_original's 5 s limit even at a 15.6 ms timer (150 x Sleep(10))
    HANDLE w = CreateThread(nullptr, 0, worker, co ? (void *)(intptr_t)(sample ? 2 : 4) : nullptr, 0, nullptr);
    if (!g_go || !w) return 4;
    printf("{\"kind\":\"waiting\",\"pid\":%lu,\"tid\":%lu}\n", GetCurrentProcessId(), GetCurrentThreadId()); fflush(stdout);
    if (!read_gate()) return 3;                                  // gate 1: the probe is active
    SetEvent(g_go);
    const ULONGLONG progress_deadline = GetTickCount64() + 60000;
    while (g_spun == 0 && GetTickCount64() < progress_deadline) Sleep(1);
    if (g_spun == 0) { fprintf(stderr, "susp_target: worker progress timed out\n"); return 5; }
    if (sample) {
        long n = 0, foreign = 0, in_original = 0;
        const ULONGLONG t0 = GetTickCount64();
        while (GetTickCount64() - t0 < 1000 && g_spun < 120) {      // well inside co_hold (150 x 10 ms)
            const DWORD prev = SuspendThread(w);
            if (prev == (DWORD)-1) break;
            ResumeThread(w);
            ++n; if (prev != 0) ++foreign;
        }
        in_original = g_spun < 150;
        const DWORD done = WaitForSingleObject(w, 30000);
        printf("{\"kind\":\"co\",\"case\":\"%s\",\"samples\":%ld,\"foreign\":%ld,\"in_original\":%ld,\"done\":%d,\"ret\":%lld}\n",
               k, n, foreign, in_original, done == WAIT_OBJECT_0, (long long)g_worker_ret);
        fflush(stdout);
        return 0;
    }
    const LONG spun_before = g_spun;
    BOOL debugger_before = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugger_before);
    const ULONGLONG first_tick = GetTickCount64();
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
           "\"done\":%d,\"ret\":%lld,\"debugger\":%d,\"spun_before\":%ld,\"debugger_before\":%d,\"first_tick\":%llu}\n",
           k, first, prev, (long)(c2 - c1), done == WAIT_OBJECT_0, (long long)g_worker_ret, (int)dbg,
           (long)spun_before, (int)debugger_before, (unsigned long long)first_tick);
    fflush(stdout);
    return 0;
}
