// call_original / return_from edge-case hunt: the TARGET. `co_target <case> [--wait]` runs one
// case and prints one JSON row of results; the same row from an uninstrumented run is the
// reference (regress `callorig-hunt`). See co_callbacks.cpp for what each probe does.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdexcept>
#include <thread>
#include <vector>
#include <atomic>
#include <algorithm>

#define CO_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)

static std::atomic<long> g_body{0};      // how many times an original body really ran
static volatile long g_sink;

extern "C" intptr_t CoMidPush(intptr_t a);
extern "C" intptr_t CoCallPrologue(intptr_t a, intptr_t *out);
extern "C" void CoRepFill(void *dst, size_t n, int v);
#if !defined(_WIN64)
extern "C" int CoThis(void);             // __thiscall, called from inline asm only
#endif

CO_EXPORT intptr_t co_fact(intptr_t n) { g_body++; return n <= 1 ? 1 : n * co_fact(n - 1); }
CO_EXPORT intptr_t co_after(intptr_t x) { g_body++; return x * 7; }
CO_EXPORT intptr_t co_throw(intptr_t x) {
    g_body++;
    if (x & 1) throw std::runtime_error("odd");
    return x * 3;
}
CO_EXPORT intptr_t co_seh(intptr_t x) {
    g_body++;
    if (x % 3 == 1) RaiseException(0xE0C0FFEEu, 0, 0, nullptr);
    if (x % 3 == 2) g_sink = *(volatile long *)(uintptr_t)0x10;        // access violation
    return x + 100;
}
CO_EXPORT intptr_t co_jump(jmp_buf *env, intptr_t x) {
    g_body++;
    if (x & 1) longjmp(*env, (int)x);
    return x * 5;
}
CO_EXPORT intptr_t co_add(intptr_t a, intptr_t b) { g_body++; return a * 3 + b; }
CO_EXPORT intptr_t co_ret(intptr_t a) { g_body++; return a + 11; }
CO_EXPORT intptr_t co_args8(intptr_t a, intptr_t b, intptr_t c, intptr_t d, intptr_t e, intptr_t f,
                            intptr_t g, intptr_t h) {
    g_body++;
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h;
}
CO_EXPORT int __fastcall co_fast(int a, int b, int c) { g_body++; return a * 100 + b * 10 + c; }
#if !defined(_WIN64)
#pragma comment(linker, "/EXPORT:co_fast=@co_fast@12")
#endif
CO_EXPORT intptr_t co_inner(intptr_t x) { g_body++; return x * 2; }
CO_EXPORT intptr_t co_outer(intptr_t x) { g_body++; return co_inner(x) + 1; }
CO_EXPORT intptr_t co_slow(intptr_t x) { g_body++; Sleep(250); return x * 13; }
CO_EXPORT intptr_t co_vslow(intptr_t x) { g_body++; Sleep(5600); return x * 17; }   // past the 5 s call limit
// Codex library review (regress `cxlib-*`): a callback that faults after call_original /
// return_from (cbfault), and one still running long after a detach started (late, cfgfree).
static volatile long g_cbf_runs[9];      // cbfault: body runs per call (by its first argument)
CO_EXPORT intptr_t co_cbf(intptr_t a, intptr_t b) {
    g_body++;
    if (a >= 0 && a < 9) g_cbf_runs[a]++;
    return a * 3 + b;
}
CO_EXPORT intptr_t co_late(volatile LONG *state, intptr_t x) { g_body++; (void)state; return x + 1; }
// cosusp (cx2-cosusp-*): an original that runs ~3 s, counting as it goes (g_spun).
static volatile LONG g_spun = 0, g_spin_stop = 0;
CO_EXPORT intptr_t co_hold(intptr_t x) {
    g_body++;
    for (int i = 0; i < 300; ++i) { InterlockedIncrement(&g_spun); Sleep(10); }
    return x * 19;
}

static void after3(intptr_t &after) { for (int i = 0; i < 3; ++i) after += co_after(i); }

// SEH and C++ objects cannot share a frame: the __try caller lives on its own.
static int seh_call(intptr_t x, intptr_t *r, DWORD *code) {
    __try { *r = co_seh(x); return 0; }
    __except (*code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) { return 1; }
}
static intptr_t jump_call(intptr_t x, int *jumped) {
    jmp_buf env;
    int v = setjmp(env);
    if (v) { *jumped += 1; return 1000 + v; }
    return co_jump(&env, x);
}

static int wait_gate() {
    printf("{\"kind\":\"waiting\",\"pid\":%lu,\"tid\":%lu}\n", GetCurrentProcessId(), GetCurrentThreadId()); fflush(stdout);
    char b; DWORD n = 0;
    return ReadFile(GetStdHandle(STD_INPUT_HANDLE), &b, 1, &n, nullptr) && n == 1;
}

// late / cfgfree: a thread calls co_late; its callback marks state 1 and waits until the
// target sets state 2. late: state 2 comes 19 s later (longer than the 2 s agent wait + the
// 15 s drain a detach used to allow). cfgfree: the thread is SUSPENDED by the program while in
// the callback, the test detaches, then sends one more byte: state 2, the thread resumed.
struct LateArg { volatile LONG state; intptr_t ret; };
static DWORD WINAPI late_thread(void *p) {
    auto *a = static_cast<LateArg *>(p);
    a->ret = co_late(&a->state, 7);
    return 0;
}
static int run_late(const char *k) {
    const bool suspend = !strcmp(k, "cfgfree");
    LateArg arg{0, 0};
    HANDLE th = CreateThread(nullptr, 0, late_thread, &arg, 0, nullptr);
    if (!th) return 4;
    for (int i = 0; i < 12000 && arg.state == 0; ++i) Sleep(5);          // the callback has started
    const LONG seen = arg.state;
    if (suspend && seen) SuspendThread(th);
    printf("{\"kind\":\"incb\",\"state\":%ld}\n", (long)seen); fflush(stdout);
    if (suspend) {
        char b; DWORD n = 0;
        ReadFile(GetStdHandle(STD_INPUT_HANDLE), &b, 1, &n, nullptr);    // after the detach
    } else if (seen) {
        Sleep(19000);
    }
    InterlockedExchange(&arg.state, 2);
    if (suspend && seen) ResumeThread(th);
    const DWORD w = WaitForSingleObject(th, 60000);
    printf("{\"kind\":\"co\",\"case\":\"%s\",\"ret\":%lld,\"body\":%ld,\"done\":%d}\n", k,
           (long long)arg.ret, g_body.load(), w == WAIT_OBJECT_0);
    fflush(stdout);
    return 0;
}

// many / manydead (cx2-manythreads): N threads (default 4200, more than the agent's 4096-entry
// thread table), all alive at once -- so N distinct thread ids -- each make one inline hit
// (co_add). Then co_late runs on yet another thread and its callback outlives a detach (as in
// `late`, state 2 comes 8 s later): many -- while the N threads are all still alive;
// manydead -- after they have all exited. Its log must be delivered.
struct ManyArg { HANDLE go; std::atomic<long> *called; DWORD *tid; };
static DWORD WINAPI many_thread(void *p) {
    auto *a = static_cast<ManyArg *>(p);
    *a->tid = GetCurrentThreadId();
    co_add(1, 2);
    a->called->fetch_add(1);
    WaitForSingleObject(a->go, INFINITE);
    return 0;
}
static void wait_all(std::vector<HANDLE> &ths) {
    for (size_t i = 0; i < ths.size(); i += MAXIMUM_WAIT_OBJECTS) {
        const DWORD n = (DWORD)(ths.size() - i < MAXIMUM_WAIT_OBJECTS ? ths.size() - i : MAXIMUM_WAIT_OBJECTS);
        WaitForMultipleObjects(n, &ths[i], TRUE, 120000);
    }
    for (HANDLE h : ths) CloseHandle(h);
    ths.clear();
}
static int run_many(const char *k, int n) {
    const bool dead = !strcmp(k, "manydead");
    HANDLE go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::atomic<long> called{0};
    std::vector<DWORD> tids((size_t)n, 0);
    std::vector<ManyArg> args((size_t)n);
    std::vector<HANDLE> ths;
    for (int i = 0; i < n; ++i) {
        args[i] = ManyArg{go, &called, &tids[i]};
        HANDLE h = CreateThread(nullptr, 64 * 1024, many_thread, &args[i], STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
        if (!h) break;
        ths.push_back(h);
    }
    const long created = (long)ths.size();
    for (int i = 0; i < 60000 && called.load() < created; ++i) Sleep(5);
    std::vector<DWORD> u(tids.begin(), tids.begin() + created);
    std::sort(u.begin(), u.end());
    const long distinct = (long)(std::unique(u.begin(), u.end()) - u.begin());
    if (dead) { SetEvent(go); wait_all(ths); }
    LateArg arg{0, 0};
    HANDLE th = CreateThread(nullptr, 0, late_thread, &arg, 0, nullptr);
    if (!th) return 4;
    for (int i = 0; i < 12000 && arg.state == 0; ++i) Sleep(5);          // the callback has started
    printf("{\"kind\":\"incb\",\"state\":%ld}\n", (long)arg.state); fflush(stdout);
    if (arg.state) Sleep(8000);                                           // the test detaches meanwhile
    InterlockedExchange(&arg.state, 2);
    const DWORD w = WaitForSingleObject(th, 60000);
    SetEvent(go); wait_all(ths);
    printf("{\"kind\":\"co\",\"case\":\"%s\",\"threads\":%ld,\"called\":%ld,\"distinct\":%ld,\"ret\":%lld,"
           "\"done\":%d}\n", k, created, called.load(), distinct, (long long)arg.ret, w == WAIT_OBJECT_0);
    fflush(stdout);
    return 0;
}

// susp (cx2-touchprog-hw): a worker the PROGRAM holds suspended while the controller attaches,
// arms a hw probe -- a context call on every thread -- and dies inside the call on the worker
// (test-hook build). Once the agent's guard has cleaned up after it, the worker must still be
// suspended exactly once by the program: it did not run, and the program's ResumeThread
// reports a previous count of 1.
static DWORD WINAPI susp_thread(void *) {
    while (!g_spin_stop) { InterlockedIncrement(&g_spun); Sleep(1); }
    return 0;
}
static int run_susp(bool gate) {
    HANDLE w = CreateThread(nullptr, 0, susp_thread, nullptr, 0, nullptr);
    if (!w) return 4;
    while (g_spun == 0) Sleep(1);
    const DWORD first = SuspendThread(w);
    printf("{\"kind\":\"susp\",\"tid\":%lu}\n", GetThreadId(w)); fflush(stdout);
    if (gate && !wait_gate()) return 3;
    BOOL dbg = TRUE;                                     // the controller is gone: wait for the debug port to go,
    for (int i = 0; i < 3000 && CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg) && dbg; ++i) Sleep(10);
    Sleep(1500);                                         // then for the guard's cleanup (it polls for that)
    const LONG c1 = g_spun;
    Sleep(300);
    const LONG c2 = g_spun;
    const DWORD prev = ResumeThread(w);
    InterlockedExchange(&g_spin_stop, 1);
    const DWORD r = prev > 1 ? ResumeThread(w) : 0;     // (never: a count the controller added)
    (void)r;
    const DWORD done = WaitForSingleObject(w, 30000);
    intptr_t sum = 0;
    for (int i = 0; i < 20; ++i) sum += co_add(i, 5);
    printf("{\"kind\":\"co\",\"case\":\"susp\",\"first\":%lu,\"prev\":%lu,\"ran_while_suspended\":%ld,"
           "\"done\":%d,\"sum\":%lld}\n", first, prev, (long)(c2 - c1), done == WAIT_OBJECT_0,
           (long long)sum);
    fflush(stdout);
    return 0;
}

// evsusp / cosusp (cx2-evsusp-*, cx2-cosusp-*; Codex review 2's X2 open note): the PROGRAM
// suspends a worker right after the controller let it run again, then the controller dies.
//   evsusp: the worker's probe hit (co_add) was handled and continued; it counts on (g_spun).
//   cosusp: the worker is inside co_hold, run by its callback's call_original.
// Gate 1 (stdin): the controller is attached and its probe active -> the worker goes. The main
// thread suspends it once it runs on ("susp"). Gate 2: the controller is dead. Then, as `susp`:
// the worker must still be suspended exactly once by the program (it did not run meanwhile, the
// program's ResumeThread reports 1) and it finishes normally.
static HANDLE g_go;
static intptr_t g_worker_ret;
static DWORD WINAPI ev_worker(void *p) {
    WaitForSingleObject(g_go, INFINITE);
    if (p) { g_worker_ret = co_hold(4); return 0; }
    g_worker_ret = co_add(1, 2);
    while (!g_spin_stop) { InterlockedIncrement(&g_spun); Sleep(1); }
    return 0;
}
static int run_susp_after(const char *k) {
    const bool co = !strcmp(k, "cosusp");
    g_go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE w = CreateThread(nullptr, 0, ev_worker, co ? (void *)1 : nullptr, 0, nullptr);
    if (!g_go || !w) return 4;
    if (!wait_gate()) return 3;
    SetEvent(g_go);
    for (int i = 0; i < 60000 && g_spun == 0; ++i) Sleep(1);      // it runs on (after its hit / in the original)
    const LONG spun_before = g_spun;
    const DWORD first = SuspendThread(w);
    printf("{\"kind\":\"susp\",\"tid\":%lu,\"spun\":%ld}\n", GetThreadId(w), (long)spun_before); fflush(stdout);
    char b; DWORD n = 0;
    if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), &b, 1, &n, nullptr) || n != 1) return 3;   // the controller is dead
    BOOL dbg = TRUE;
    for (int i = 0; i < 3000 && CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg) && dbg; ++i) Sleep(10);
    Sleep(1500);                                         // the guard's cleanup
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

int main(int argc, char **argv) {
    const char *k = argc > 1 ? argv[1] : "";
    if (!strcmp(k, "susp")) return run_susp(argc > 2 && !strcmp(argv[2], "--wait"));
    if (!strcmp(k, "evsusp") || !strcmp(k, "cosusp")) return run_susp_after(k);
    if (argc > 2 && !strcmp(argv[2], "--wait") && !wait_gate()) return 3;
    intptr_t sum = 0, after = 0;
    if (!strcmp(k, "recurse")) {
        for (int i = 0; i < 5; ++i) sum += co_fact(8);
        printf("{\"kind\":\"co\",\"case\":\"recurse\",\"sum\":%lld,\"body\":%ld}\n", (long long)sum, g_body.load());
    } else if (!strcmp(k, "cppthrow")) {
        int caught = 0;
        for (intptr_t x = 0; x < 10; ++x) {
            try { sum += co_throw(x); } catch (const std::runtime_error &e) { if (!strcmp(e.what(), "odd")) ++caught; }
        }
        after3(after);
        printf("{\"kind\":\"co\",\"case\":\"cppthrow\",\"sum\":%lld,\"caught\":%d,\"body\":%ld,\"after\":%lld}\n",
               (long long)sum, caught, g_body.load(), (long long)after);
    } else if (!strcmp(k, "seh")) {
        int raised = 0, av = 0;
        for (intptr_t x = 0; x < 9; ++x) {
            intptr_t r = 0; DWORD code = 0;
            if (!seh_call(x, &r, &code)) sum += r;
            else if (code == 0xE0C0FFEEu) ++raised;
            else if (code == EXCEPTION_ACCESS_VIOLATION) ++av;
        }
        after3(after);
        printf("{\"kind\":\"co\",\"case\":\"seh\",\"sum\":%lld,\"raised\":%d,\"av\":%d,\"body\":%ld,\"after\":%lld}\n",
               (long long)sum, raised, av, g_body.load(), (long long)after);
    } else if (!strcmp(k, "longjmp")) {
        int jumped = 0;
        for (intptr_t x = 0; x < 10; ++x) sum += jump_call(x, &jumped);
        after3(after);
        printf("{\"kind\":\"co\",\"case\":\"longjmp\",\"sum\":%lld,\"jumped\":%d,\"body\":%ld,\"after\":%lld}\n",
               (long long)sum, jumped, g_body.load(), (long long)after);
    } else if (!strcmp(k, "threads")) {
        const int T = 16, N = 300;
        std::atomic<long> good{0};
        std::vector<std::thread> ts;
        for (int t = 0; t < T; ++t)
            ts.emplace_back([t, &good] {
                long ok = 0;
                for (int i = 0; i < N; ++i) if (co_add(i, t) == (intptr_t)i * 3 + t) ++ok;
                good += ok;
            });
        for (auto &t : ts) t.join();
        printf("{\"kind\":\"co\",\"case\":\"threads\",\"good\":%ld,\"calls\":%d,\"body\":%ld}\n", good.load(), T * N, g_body.load());
    } else if (!strcmp(k, "mid")) {
        for (int i = 0; i < 5; ++i) sum += CoMidPush(i);
        printf("{\"kind\":\"co\",\"case\":\"mid\",\"sum\":%lld}\n", (long long)sum);
    } else if (!strcmp(k, "nargs")) {
        for (int i = 0; i < 20; ++i) sum += co_add(i, 5);
        printf("{\"kind\":\"co\",\"case\":\"nargs\",\"sum\":%lld,\"body\":%ld}\n", (long long)sum, g_body.load());
    } else if (!strcmp(k, "conv")) {
        intptr_t fast = 0, args8 = 0, thisv = -1; int this_sp = 0, fast_sp = 0;
        for (int i = 0; i < 5; ++i) {
#if !defined(_WIN64)
            uintptr_t b4, af; int r;
            __asm mov b4, esp
            r = co_fast(i, 2, 3);
            __asm mov af, esp
            fast += r; fast_sp += b4 == af;
            int obj = 4 + i, rv = 0;
            __asm {
                mov b4, esp
                lea ecx, obj
                push 3
                push 2
                call CoThis
                mov rv, eax
                mov af, esp
            }
            thisv += rv; this_sp += b4 == af;
#else
            fast += co_fast(i, 2, 3); ++fast_sp; ++this_sp;
#endif
            args8 += co_args8(1, 2, 3, 4, 5, 6, 7, 8 + i);
        }
        printf("{\"kind\":\"co\",\"case\":\"conv\",\"fast\":%lld,\"fast_sp\":%d,\"this\":%lld,\"this_sp\":%d,\"args8\":%lld,\"body\":%ld}\n",
               (long long)fast, fast_sp, (long long)thisv, this_sp, (long long)args8, g_body.load());
    } else if (!strcmp(k, "retaddr")) {
        for (int i = 0; i < 6; ++i) sum += co_ret(i);
        printf("{\"kind\":\"co\",\"case\":\"retaddr\",\"sum\":%lld,\"body\":%ld}\n", (long long)sum, g_body.load());
    } else if (!strcmp(k, "prologue")) {
        int intact = 0;
        for (int i = 0; i < 5; ++i) { intptr_t out = 0; intact += (int)CoCallPrologue(i + 1, &out); sum += out; }
        printf("{\"kind\":\"co\",\"case\":\"prologue\",\"sum\":%lld,\"intact\":%d}\n", (long long)sum, intact);
    } else if (!strcmp(k, "nested")) {
        for (int i = 0; i < 6; ++i) sum += co_outer(i);
        printf("{\"kind\":\"co\",\"case\":\"nested\",\"sum\":%lld,\"body\":%ld}\n", (long long)sum, g_body.load());
    } else if (!strcmp(k, "vslow")) {
        sum = co_vslow(3);
        after3(after);
        printf("{\"kind\":\"co\",\"case\":\"vslow\",\"sum\":%lld,\"body\":%ld,\"after\":%lld}\n",
               (long long)sum, g_body.load(), (long long)after);
    } else if (!strcmp(k, "cbfault")) {
        char rets[256] = "", runs[16] = "";
        for (int i = 0; i < 9; ++i) {
            const intptr_t r = co_cbf(i, 5);
            sum += r;
            snprintf(rets + strlen(rets), sizeof(rets) - strlen(rets), "%s%lld", i ? "," : "", (long long)r);
        }
        for (int i = 0; i < 9; ++i) runs[i] = (char)('0' + (g_cbf_runs[i] > 9 ? 9 : g_cbf_runs[i]));
        printf("{\"kind\":\"co\",\"case\":\"cbfault\",\"sum\":%lld,\"body\":%ld,\"rets\":[%s],\"runs\":\"%s\"}\n",
               (long long)sum, g_body.load(), rets, runs);
    } else if (!strcmp(k, "late") || !strcmp(k, "cfgfree")) {
        return run_late(k);
    } else if (!strcmp(k, "many") || !strcmp(k, "manydead")) {
        return run_many(k, 4200);
    } else if (!strcmp(k, "rep")) {                  // cxlib-reptail: big rep stosb fills, verified
        const size_t n = 64u << 20;
        unsigned char *b = (unsigned char *)VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!b) return 4;
        long good = 0;
        for (int i = 0; i < 8; ++i) {
            CoRepFill(b, n, 0x30 + i);
            good += b[0] == 0x30 + i && b[n / 2] == 0x30 + i && b[n - 1] == 0x30 + i;
        }
        printf("{\"kind\":\"co\",\"case\":\"rep\",\"good\":%ld}\n", good);
    } else if (!strcmp(k, "spin")) {                 // attached after its gate (cxlib-killarm)
        for (int i = 0; i < 200; ++i) { sum += co_add(i, 5); Sleep(1); }
        printf("{\"kind\":\"co\",\"case\":\"spin\",\"sum\":%lld,\"body\":%ld}\n", (long long)sum, g_body.load());
    } else if (!strcmp(k, "slow")) {
        for (int i = 0; i < 12; ++i) sum += co_slow(i);
        printf("{\"kind\":\"co\",\"case\":\"slow\",\"sum\":%lld,\"body\":%ld}\n", (long long)sum, g_body.load());
    } else {
        fprintf(stderr, "co_target: unknown case '%s'\n", k);
        return 2;
    }
    fflush(stdout);
    return 0;
}
