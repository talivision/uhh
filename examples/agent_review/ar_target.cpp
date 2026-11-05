// Inline-agent review (regress `agent-*`): the TARGET. `ar_target <case> [--wait]` runs one
// case and prints one JSON row; the same row from an uninstrumented run is the reference.
//   where       offsets of the probe sites below (found by scanning the code, so the
//               compiler's layout never has to be guessed): the call instructions and the
//               faulting load the `unwind` case probes
//   unwind      C++ throws and SEH exceptions raised by a callee whose CALL instruction is
//               inline-probed (the hook relocates that call), caught by the hooked function
//               itself and by its caller; and a faulting load relocated by the hook, inside
//               the hooked function's own __try
//   faultafter  bodies whose callback runs the original and then faults (the original must
//               run exactly once)
//   threadinit  threads started while RtlAllocateHeap is probed by an allocating callback
//               (hits in a thread's loader initialisation, before its TLS exists)
//   ljframe0    x64 longjmp WITHOUT unwinding (jmp_buf.Frame = 0) out of a call_original
//   prot        VirtualProtect calls while NtProtectVirtualMemory is probed (the agent's own
//               hook writes call it too -- those must not run the program's callback)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdexcept>
#include <atomic>
#include <thread>
#include <vector>

#define AR_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)

static std::atomic<long> g_body{0};      // how many times a probed body really ran
static volatile intptr_t g_zero = 0;

// ---- unwind -----------------------------------------------------------------------------
AR_EXPORT intptr_t ar_thrower(intptr_t x) {
    if (x & 1) throw std::runtime_error("odd");
    return x * 3 + (intptr_t)g_zero;
}
AR_EXPORT intptr_t ar_faulter(intptr_t x) {
    if (x % 3 == 1) RaiseException(0xE0A0BEEFu, 0, 0, nullptr);
    if (x % 3 == 2) return *(volatile intptr_t *)(uintptr_t)(0x10 + g_zero);     // access violation
    return x + 100;
}
// Mid-function call sites (the probe is ON the call): a callee exception caught by the caller...
AR_EXPORT intptr_t ar_mid_cpp(intptr_t x) {
    volatile intptr_t pre = x * 2;
    intptr_t r = ar_thrower(pre - x);
    return r + pre;
}
AR_EXPORT intptr_t ar_mid_seh(intptr_t x) {
    volatile intptr_t pre = x * 2;
    intptr_t r = ar_faulter(pre - x);
    return r + pre;
}
// ...and by the hooked function itself.
AR_EXPORT intptr_t ar_self_cpp(intptr_t x) {
    intptr_t r;
    try { r = ar_thrower(x); } catch (const std::runtime_error &) { r = -1; }
    return r;
}
AR_EXPORT intptr_t ar_self_seh(intptr_t x) {
    intptr_t r;
    __try { r = ar_faulter(x); }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION || GetExceptionCode() == 0xE0A0BEEFu
              ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { r = -1; }
    return r;
}
// A load the hook relocates into its trampoline, faulting there, inside this __try.
AR_EXPORT int ar_load_self(volatile int *p) {
    __try { return *p * 3 + 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return -7; }
}
static int seh_call(intptr_t x, intptr_t *r, DWORD *code) {
    __try { *r = ar_mid_seh(x); return 0; }
    __except (*code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) { return 1; }
}

// Offset of the first `call rel32` in fn that targets callee (-1: none in the first 256 bytes).
static long call_offset(const void *fn, const void *callee) {
    const unsigned char *p = (const unsigned char *)fn;
    for (long i = 0; i < 256; ++i)
        if (p[i] == 0xE8 && p + i + 5 + *(const int32_t *)(p + i + 1) == (const unsigned char *)callee) return i;
    return -1;
}
// The probe site for ar_load_self: the load of *p must lie inside the patch. x64: the first
// `mov eax,[rcx]` (8B 01); x86: `mov eax,[eax]`/`mov ecx,[ecx]`/... (8B /r, mod=0, same reg)
// after the argument load. The site is the function entry when the load starts within its
// first 5 bytes (a patch at the entry relocates it), else the load itself.
static long load_offset(const void *fn) {
    const unsigned char *p = (const unsigned char *)fn;
    for (long i = 0; i < 96; ++i) {
#if defined(_WIN64)
        if (p[i] == 0x8B && p[i + 1] == 0x01) return i;
#else
        if (p[i] == 0x8B && (p[i + 1] & 0xC0) == 0 && ((p[i + 1] >> 3) & 7) == (p[i + 1] & 7) && (p[i + 1] & 7) < 4 &&
            (p[i + 1] & 7) != 4) return i;
#endif
    }
    return -1;
}

// ---- faultafter -------------------------------------------------------------------------
AR_EXPORT intptr_t ar_body(intptr_t x) { g_body++; return x * 7 + 1; }
AR_EXPORT intptr_t __stdcall ar_body_std(intptr_t x) { g_body++; return x * 9 + 2; }
#if !defined(_WIN64)
#pragma comment(linker, "/EXPORT:ar_body_std=_ar_body_std@4")
#endif

// ---- ljframe0 ---------------------------------------------------------------------------
AR_EXPORT intptr_t ar_jump(jmp_buf *env, intptr_t x) {
    g_body++;
    if (x & 1) longjmp(*env, (int)x);
    return x * 5;
}
AR_EXPORT intptr_t ar_after(intptr_t x) { g_body++; return x * 11; }
static intptr_t jump_call(intptr_t x, int *jumped) {
    jmp_buf env;
    int v = setjmp(env);
    if (v) { *jumped += 1; return 1000 + v; }
#if defined(_WIN64)
    ((_JUMP_BUFFER *)&env)->Frame = 0;          // longjmp restores registers without unwinding
#endif
    return ar_jump(&env, x);
}

static int wait_gate() {
    printf("{\"kind\":\"waiting\",\"pid\":%lu}\n", GetCurrentProcessId()); fflush(stdout);
    char b; DWORD n = 0;
    return ReadFile(GetStdHandle(STD_INPUT_HANDLE), &b, 1, &n, nullptr) && n == 1;
}

int main(int argc, char **argv) {
    const char *k = argc > 1 ? argv[1] : "";
    if (argc > 2 && !strcmp(argv[2], "--wait") && !wait_gate()) return 3;
    if (!strcmp(k, "where")) {
        printf("{\"kind\":\"where\",\"mid_cpp\":%ld,\"mid_seh\":%ld,\"self_cpp\":%ld,\"self_seh\":%ld,\"load\":%ld}\n",
               call_offset((void *)ar_mid_cpp, (void *)ar_thrower), call_offset((void *)ar_mid_seh, (void *)ar_faulter),
               call_offset((void *)ar_self_cpp, (void *)ar_thrower), call_offset((void *)ar_self_seh, (void *)ar_faulter),
               load_offset((void *)ar_load_self));
    } else if (!strcmp(k, "unwind")) {
        intptr_t mid_cpp = 0, mid_seh = 0, self_cpp = 0, self_seh = 0, load = 0;
        int caught = 0, seh_raised = 0, seh_av = 0;
        for (intptr_t x = 0; x < 10; ++x) {
            try { mid_cpp += ar_mid_cpp(x); } catch (const std::runtime_error &e) { if (!strcmp(e.what(), "odd")) ++caught; }
            intptr_t r = 0; DWORD code = 0;
            if (!seh_call(x, &r, &code)) mid_seh += r;
            else if (code == 0xE0A0BEEFu) ++seh_raised;
            else if (code == EXCEPTION_ACCESS_VIOLATION) ++seh_av;
            self_cpp += ar_self_cpp(x);
            self_seh += ar_self_seh(x);
            volatile int v = (int)x;
            load += ar_load_self((x & 1) ? (volatile int *)(uintptr_t)(0x20 + g_zero) : &v);
        }
        printf("{\"kind\":\"ar\",\"case\":\"unwind\",\"mid_cpp\":%lld,\"caught\":%d,\"mid_seh\":%lld,\"raised\":%d,"
               "\"av\":%d,\"self_cpp\":%lld,\"self_seh\":%lld,\"load\":%lld}\n",
               (long long)mid_cpp, caught, (long long)mid_seh, seh_raised, seh_av, (long long)self_cpp,
               (long long)self_seh, (long long)load);
    } else if (!strcmp(k, "faultafter")) {
        intptr_t sum = 0, sum_std = 0;
        for (int i = 0; i < 5; ++i) { sum += ar_body(i); sum_std += ar_body_std(i); }
        printf("{\"kind\":\"ar\",\"case\":\"faultafter\",\"sum\":%lld,\"sum_std\":%lld,\"body\":%ld}\n",
               (long long)sum, (long long)sum_std, g_body.load());
    } else if (!strcmp(k, "threadinit")) {
        std::atomic<long> done{0};
        for (int round = 0; round < 4; ++round) {
            std::vector<std::thread> ts;
            for (int t = 0; t < 10; ++t) ts.emplace_back([&done] { std::vector<int> v(64, 1); done += v[3]; });
            for (auto &t : ts) t.join();
        }
        printf("{\"kind\":\"ar\",\"case\":\"threadinit\",\"done\":%ld}\n", done.load());
    } else if (!strcmp(k, "ljframe0")) {
        intptr_t sum = 0, after = 0; int jumped = 0;
        for (intptr_t x = 0; x < 10; ++x) sum += jump_call(x, &jumped);
        for (int i = 0; i < 3; ++i) after += ar_after(i);
        printf("{\"kind\":\"ar\",\"case\":\"ljframe0\",\"sum\":%lld,\"jumped\":%d,\"after\":%lld,\"body\":%ld}\n",
               (long long)sum, jumped, (long long)after, g_body.load());
    } else if (!strcmp(k, "prot")) {
        static __declspec(align(4096)) unsigned char page[4096];
        int ok = 0;
        for (int i = 0; i < 4; ++i) {
            DWORD old = 0;
            ok += VirtualProtect(page, sizeof(page), (i & 1) ? PAGE_READWRITE : PAGE_READONLY, &old) ? 1 : 0;
        }
        DWORD old = 0; VirtualProtect(page, sizeof(page), PAGE_READWRITE, &old);
        printf("{\"kind\":\"ar\",\"case\":\"prot\",\"ok\":%d}\n", ok);
    } else {
        fprintf(stderr, "ar_target: unknown case '%s'\n", k);
        return 2;
    }
    fflush(stdout);
    return 0;
}
