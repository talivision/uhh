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

#define CO_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)

static std::atomic<long> g_body{0};      // how many times an original body really ran
static volatile long g_sink;

extern "C" intptr_t CoMidPush(intptr_t a);
extern "C" intptr_t CoCallPrologue(intptr_t a, intptr_t *out);
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
    printf("{\"kind\":\"waiting\",\"pid\":%lu}\n", GetCurrentProcessId()); fflush(stdout);
    char b; DWORD n = 0;
    return ReadFile(GetStdHandle(STD_INPUT_HANDLE), &b, 1, &n, nullptr) && n == 1;
}

int main(int argc, char **argv) {
    const char *k = argc > 1 ? argv[1] : "";
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
