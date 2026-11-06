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
//   cfkill      a thread killed (TerminateThread) while its callback is inside call_func, then
//               thread ids taken (threads created suspended, ended unrun) until one is the dead
//               thread's id: that thread and 19 more run, each hitting the probe twice
//   cfmany      100 threads inside call_func at once, the callee hitting another probe
//   cflock      a call_func callee needing a lock another thread holds at its own probe hit
//   absret      a call whose return site is followed within 5 bytes by a loop head (machine
//               code placed in .text, no unwind data), probed BY ADDRESS from a callback
//   cfmanyq     cfmany without the barrier (the callee does not wait for the others)
//   cfwatch     a data-watch hit (whose callback call_funcs) while another thread's callback
//               is inside call_func
//   cfwatchlock cfwatch, the call_func'ing callback holding a lock the watch callback takes
//   drresume    a hw probe armed (from a callback) AT the instruction a thread inside a user APC
//               resumes at (after NtDelayExecution's syscall): the very first instruction after
//               the context restore must hit it
//   coborrow    breakpoint/hw call_original on a hw probe that has to lend its own DR (all 4
//               used), the original raising and continuing an exception (NtContinue)
//   drrestore   a hw probe armed (from a callback) while one thread is inside an exception
//               filter and another inside a user APC: both resume through NtContinue with a
//               context captured BEFORE the arm, then call the probed function
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

// ---- cfkill / cfmany: inline call_func's recursion guard (regress `callfunc-*`) ----------
static volatile intptr_t g_cf_seen;                     // (distinct body: no linker folding)
AR_EXPORT intptr_t ar_cf_site(intptr_t x) { g_cf_seen = x; return x; }        // probed: ar_on_cf
static HANDLE g_cf_in;                                  // set once the victim is inside call_func
AR_EXPORT intptr_t ar_cf_block() { SetEvent(g_cf_in); Sleep(INFINITE); return 0; }
AR_EXPORT intptr_t ar_cf_inner(intptr_t x) { return x * 3 + (intptr_t)g_zero; } // probed: ar_on_cf_inner
static std::atomic<long> g_cf_arrived{0}, g_cf_together{0};
static long g_cf_need;
// call_func's callee: wait until every thread is inside call_func, then hit ar_cf_inner.
AR_EXPORT intptr_t ar_cf_gate(intptr_t x) {
    g_cf_arrived++;
    for (int i = 0; i < 10000 && g_cf_arrived.load() < g_cf_need; ++i) Sleep(1);
    if (g_cf_arrived.load() >= g_cf_need) g_cf_together++;
    return ar_cf_inner(x);
}
// cflock: a callee that needs a lock another thread holds AT ITS OWN probe hit. It only
// completes if that thread's callback runs (and returns) while this call is in flight.
static CRITICAL_SECTION g_cf_cs;
static HANDLE g_cf_waiting;
AR_EXPORT intptr_t ar_cf_needlock() {
    SetEvent(g_cf_waiting);
    EnterCriticalSection(&g_cf_cs); LeaveCriticalSection(&g_cf_cs);
    return 7 + (intptr_t)g_zero;
}
static DWORD WINAPI cf_waiter(void *) { return (DWORD)ar_cf_site(4); }
// ---- cfwatch (regress `callfunc-watch-*`) ------------------------------------------------
static volatile LONG g_cfw_var;
static volatile intptr_t g_cfw_seen;
static HANDLE g_cfw_in;
AR_EXPORT intptr_t ar_cfw_setup(intptr_t addr) { g_cfw_seen = addr; return addr; }   // probed: watches addr
AR_EXPORT intptr_t ar_cfw_slow() { SetEvent(g_cfw_in); Sleep(500); return 11; }    // call_func'd
static intptr_t g_cfw_x = 5;                             // 6: cfwatchlock (the callback holds a lock)
static DWORD WINAPI cfw_caller(void *) { return (DWORD)ar_cf_site(g_cfw_x); }

// ---- drresume (regress `hw-dr-restore-first`) -------------------------------------------
static volatile intptr_t g_dr2_seen;
AR_EXPORT intptr_t ar_dr2_arm(intptr_t at) { g_dr2_seen = at; return at; }       // probed: arms a hw probe AT `at`
static DWORD g_dr2_tid;
static DWORD WINAPI dr2_apc_thread(void *) {
    g_dr2_tid = GetCurrentThreadId();
    SleepEx(15000, TRUE);                                // the APC ends with NtContinue back into the wait's return
    return 0;
}
// Where a thread interrupted in NtDelayExecution resumes: right after its kernel transition
// (x64: after `syscall`; x86 WOW64: after `call edx`).
static uintptr_t delay_resume_site() {
    const auto *p = (const unsigned char *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");
    for (int i = 0; p && i < 32; ++i) {
#if defined(_WIN64)
        if (p[i] == 0x0F && p[i + 1] == 0x05) return (uintptr_t)(p + i + 2);
#else
        if (p[i] == 0xFF && p[i + 1] == 0xD2) return (uintptr_t)(p + i + 2);
#endif
    }
    return 0;
}

// ---- coborrow (regress `hw-co-borrow-restore`) ------------------------------------------
static volatile intptr_t g_cob_seen;
static LONG cob_filter() { return EXCEPTION_CONTINUE_EXECUTION; }
AR_EXPORT intptr_t ar_cob_other(intptr_t x) { g_cob_seen = x; return x; }          // a third hw probe
AR_EXPORT intptr_t ar_cob_orig(intptr_t x) {                                       // call_original'd
    __try { RaiseException(0xE0C0B001u, 0, 0, nullptr); } __except (cob_filter()) {}
    return x * 2 + (intptr_t)g_zero;
}

// ---- absret (regress `inline-absolute-*`) -------------------------------------------------
// ar_d5_code(n): calls its callee (at the end: returns n), then a loop starting 3 bytes after
// that call's return site adds n more -> 2n. A 5-byte hook at the return site would cover
// the loop head. Code bytes in .text, so it is image code with no .pdata / PDB function.
#pragma section(".text")
#if defined(_WIN64)
extern "C" __declspec(dllexport) __declspec(allocate(".text")) const unsigned char ar_d5_code[] = {
    0x53,                               //  0 push rbx
    0x48, 0x83, 0xEC, 0x20,             //  1 sub rsp, 20h
    0x48, 0x89, 0xCB,                   //  5 mov rbx, rcx
    0xE8, 0x14, 0x00, 0x00, 0x00,       //  8 call callee (+33)
    0x48, 0x89, 0xC2,                   // 13 mov rdx, rax       <- return site
    0x48, 0xFF, 0xC2,                   // 16 inc rdx            <- loop head
    0x48, 0xFF, 0xCB,                   // 19 dec rbx
    0x75, 0xF8,                         // 22 jnz 16
    0x48, 0x89, 0xD0,                   // 24 mov rax, rdx
    0x48, 0x83, 0xC4, 0x20,             // 27 add rsp, 20h
    0x5B,                               // 31 pop rbx
    0xC3,                               // 32 ret
    0x48, 0x89, 0xC8,                   // 33 callee: mov rax, rcx
    0x48, 0x83, 0xC0, 0x00,             // 36 add rax, 0
    0xC3,                               // 40 ret
};
#else
extern "C" __declspec(dllexport) __declspec(allocate(".text")) const unsigned char ar_d5_code[] = {
    0x53,                               //  0 push ebx
    0x8B, 0x5C, 0x24, 0x08,             //  1 mov ebx, [esp+8]
    0x53,                               //  5 push ebx
    0xE8, 0x09, 0x00, 0x00, 0x00,       //  6 call callee (+20)
    0x83, 0xC4, 0x04,                   // 11 add esp, 4         <- return site
    0x40,                               // 14 inc eax            <- loop head
    0x4B,                               // 15 dec ebx
    0x75, 0xFC,                         // 16 jnz 14
    0x5B,                               // 18 pop ebx
    0xC3,                               // 19 ret
    0x8B, 0x44, 0x24, 0x04,             // 20 callee: mov eax, [esp+4]
    0x83, 0xC0, 0x00,                   // 24 add eax, 0
    0xC3,                               // 27 ret
};
#endif

// ---- drrestore (regress `hw-dr-restore`) ---------------------------------------------------
// (Distinct bodies: identical ones are folded into ONE function by the linker -- /OPT:ICF.)
static volatile intptr_t g_dr_seen_arm, g_dr_seen_site;
AR_EXPORT intptr_t ar_dr_arm(intptr_t x) { g_dr_seen_arm = x; return x; }     // probed: arms ar_dr_site (hw)
AR_EXPORT intptr_t ar_dr_site(intptr_t x) { g_dr_seen_site = x; return x; }   // the runtime-armed hw probe
static HANDLE g_dr_inside[2], g_dr_go;
static std::atomic<long> g_dr_calls[3];
static LONG dr_filter() {
    SetEvent(g_dr_inside[0]);
    WaitForSingleObject(g_dr_go, 15000);
    return EXCEPTION_CONTINUE_EXECUTION;                 // NtContinue with the context captured at the raise
}
static DWORD WINAPI dr_exception_thread(void *) {
    __try { RaiseException(0xE0D40001u, 0, 0, nullptr); } __except (dr_filter()) {}
    for (int i = 0; i < 10; ++i) { ar_dr_site(200 + i); g_dr_calls[1]++; }
    return 0;
}
static VOID CALLBACK dr_apc(ULONG_PTR) { SetEvent(g_dr_inside[1]); WaitForSingleObject(g_dr_go, 15000); }
static DWORD WINAPI dr_apc_thread(void *) {
    SleepEx(15000, TRUE);                                // the APC returns through NtContinue
    for (int i = 0; i < 10; ++i) { ar_dr_site(300 + i); g_dr_calls[2]++; }
    return 0;
}
struct CfReuse { DWORD victim; std::atomic<long> calls{0}, reused{0}; };
static DWORD WINAPI cf_short(void *p) {
    auto *r = (CfReuse *)p;
    for (int i = 0; i < 2; ++i) { ar_cf_site(0); r->calls++; }
    if (GetCurrentThreadId() == r->victim) r->reused++;
    return 0;
}
static DWORD WINAPI cf_victim(void *) { ar_cf_site(1); return 0; }
static DWORD WINAPI cf_many(void *p) { return (DWORD)ar_cf_site((intptr_t)p); }

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
    } else if (!strcmp(k, "cfkill")) {
        g_cf_in = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        DWORD vtid = 0;
        HANDLE v = CreateThread(nullptr, 0, cf_victim, nullptr, 0, &vtid);
        HANDLE w[2] = {g_cf_in, v};
        int killed = 0;
        if (WaitForMultipleObjects(2, w, FALSE, 10000) == WAIT_OBJECT_0 && TerminateThread(v, 0x1234)) {
            WaitForSingleObject(v, INFINITE);
            killed = 1;
        }
        CloseHandle(v);
        CfReuse r; r.victim = vtid;
        // Get the dead id back. Windows hands a freed thread id out again only once the id
        // table's free list it went to has run dry (freed ids queue behind it; one list per
        // CPU, the creating thread's CPU picks it) -- on a long-running machine that can take
        // far more threads than a test can run. So take ids fast: threads created suspended
        // and ended before they ever run (no callback, no hit), the creator moving across the
        // CPUs, until one is given the dead id -- that one runs cf_short; then 19 more do.
        int threads = 0;
        long consumed = 0;
        const ULONGLONG t0 = GetTickCount64();
        DWORD_PTR pm = 0, sm = 0;
        GetProcessAffinityMask(GetCurrentProcess(), &pm, &sm);
        int cpu = 0;
        while (killed && !r.reused.load() && consumed < 4000000 && GetTickCount64() - t0 < 150000) {
            if (pm && (consumed & 255) == 0) {
                do cpu = (cpu + 1) % (int)(8 * sizeof(DWORD_PTR)); while (!(pm & ((DWORD_PTR)1 << cpu)));
                SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << cpu);
            }
            DWORD tid = 0;
            HANDLE t = CreateThread(nullptr, 64 * 1024, cf_short, &r, CREATE_SUSPENDED | STACK_SIZE_PARAM_IS_A_RESERVATION, &tid);
            if (!t) break;
            ++consumed;
            if (tid == vtid) { ResumeThread(t); ++threads; }      // the dead id: this one runs
            else TerminateThread(t, 0);
            WaitForSingleObject(t, INFINITE); CloseHandle(t);
        }
        if (pm) SetThreadAffinityMask(GetCurrentThread(), pm);
        const ULONGLONG ms = GetTickCount64() - t0;
        for (int after = 1; r.reused.load() && after < 20; ++after, ++threads) {
            HANDLE t = CreateThread(nullptr, 0, cf_short, &r, 0, nullptr);
            if (!t) break;
            WaitForSingleObject(t, INFINITE); CloseHandle(t);
        }
        printf("{\"kind\":\"ar\",\"case\":\"cfkill\",\"killed\":%d,\"reused\":%ld,\"threads\":%d,\"calls\":%ld,"
               "\"consumed\":%ld,\"ms\":%llu}\n", killed, r.reused.load(), threads, r.calls.load(), consumed,
               (unsigned long long)ms);
    } else if (!strcmp(k, "cflock")) {
        InitializeCriticalSection(&g_cf_cs);
        g_cf_waiting = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        EnterCriticalSection(&g_cf_cs);
        HANDLE w = CreateThread(nullptr, 0, cf_waiter, nullptr, 0, nullptr);   // its callee waits for the lock
        const int inside = WaitForSingleObject(g_cf_waiting, 10000) == WAIT_OBJECT_0;
        const intptr_t held = ar_cf_site(2);              // a probe hit while holding it
        LeaveCriticalSection(&g_cf_cs);
        const int joined = WaitForSingleObject(w, 15000) == WAIT_OBJECT_0;
        DWORD e = 0; GetExitCodeThread(w, &e); CloseHandle(w);
        printf("{\"kind\":\"ar\",\"case\":\"cflock\",\"inside\":%d,\"joined\":%d,\"held\":%lld,\"waiter\":%lu}\n",
               inside, joined, (long long)held, e);
    } else if (!strcmp(k, "absret")) {
        auto f = reinterpret_cast<intptr_t (*)(intptr_t)>(reinterpret_cast<uintptr_t>(ar_d5_code));
        intptr_t sum = 0;
        for (int i = 0; i < 3; ++i) sum += f(5);
        printf("{\"kind\":\"ar\",\"case\":\"absret\",\"sum\":%lld}\n", (long long)sum);
    } else if (!strcmp(k, "drrestore")) {
        for (auto &e : g_dr_inside) e = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_dr_go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE te = CreateThread(nullptr, 0, dr_exception_thread, nullptr, 0, nullptr);
        HANDLE ta = CreateThread(nullptr, 0, dr_apc_thread, nullptr, 0, nullptr);
        Sleep(100);                                       // ta in its alertable wait
        QueueUserAPC(dr_apc, ta, 0);
        const int inside = WaitForMultipleObjects(2, g_dr_inside, TRUE, 15000) == WAIT_OBJECT_0;
        ar_dr_arm(1);                                     // its callback arms ar_dr_site now
        for (int i = 0; i < 10; ++i) { ar_dr_site(100 + i); g_dr_calls[0]++; }
        SetEvent(g_dr_go);
        WaitForSingleObject(te, 15000); WaitForSingleObject(ta, 15000);
        CloseHandle(te); CloseHandle(ta);
        printf("{\"kind\":\"ar\",\"case\":\"drrestore\",\"inside\":%d,\"main\":%ld,\"exception\":%ld,\"apc\":%ld}\n",
               inside, g_dr_calls[0].load(), g_dr_calls[1].load(), g_dr_calls[2].load());
    } else if (!strcmp(k, "cfwatch") || !strcmp(k, "cfwatchlock")) {
        if (!strcmp(k, "cfwatchlock")) g_cfw_x = 6;
        g_cfw_in = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ar_cfw_setup((intptr_t)&g_cfw_var);               // its callback watches g_cfw_var
        HANDLE a = CreateThread(nullptr, 0, cfw_caller, nullptr, 0, nullptr);
        const int inside = WaitForSingleObject(g_cfw_in, 10000) == WAIT_OBJECT_0;
        g_cfw_var = 1;                                    // the watch hit, while a's callee runs
        WaitForSingleObject(a, 15000);
        DWORD e = 0; GetExitCodeThread(a, &e); CloseHandle(a);
        printf("{\"kind\":\"ar\",\"case\":\"%s\",\"inside\":%d,\"caller\":%lu,\"var\":%ld}\n", k, inside, e, g_cfw_var);
    } else if (!strcmp(k, "drresume")) {
        for (auto &e : g_dr_inside) e = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_dr_go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE ta = CreateThread(nullptr, 0, dr2_apc_thread, nullptr, 0, nullptr);
        Sleep(100);                                       // ta in its alertable wait
        QueueUserAPC(dr_apc, ta, 0);
        const int inside = WaitForSingleObject(g_dr_inside[1], 15000) == WAIT_OBJECT_0;
        const uintptr_t site = delay_resume_site();
        if (site) ar_dr2_arm((intptr_t)site);             // its callback: a hw probe at the resume site
        SetEvent(g_dr_go);
        WaitForSingleObject(ta, 15000); CloseHandle(ta);
        printf("{\"kind\":\"ar\",\"case\":\"drresume\",\"inside\":%d,\"site\":%d,\"apc_tid\":%lu}\n",
               inside, site ? 1 : 0, g_dr2_tid);
    } else if (!strcmp(k, "coborrow")) {
        ar_dr_arm(1);                                     // arms ar_dr_site at runtime: 4 DRs in use
        intptr_t other = ar_cob_other(3), sum = 0;
        for (intptr_t i = 0; i < 5; ++i) sum += ar_cob_orig(i);
        printf("{\"kind\":\"ar\",\"case\":\"coborrow\",\"sum\":%lld,\"other\":%lld}\n", (long long)sum, (long long)other);
    } else if (!strcmp(k, "cfmany") || !strcmp(k, "cfmanyq")) {
        const int n = 100;
        g_cf_need = !strcmp(k, "cfmany") ? n : 1;
        std::vector<HANDLE> ts;
        for (int i = 0; i < n; ++i) ts.push_back(CreateThread(nullptr, 0, cf_many, (void *)(intptr_t)(1000 + i), 0, nullptr));
        long long sum = 0;
        for (HANDLE t : ts) { WaitForSingleObject(t, INFINITE); DWORD e = 0; GetExitCodeThread(t, &e); sum += e; CloseHandle(t); }
        printf("{\"kind\":\"ar\",\"case\":\"cfmany\",\"sum\":%lld,\"arrived\":%ld,\"together\":%ld}\n",
               sum, g_cf_arrived.load(), g_cf_together.load());
    } else {
        fprintf(stderr, "ar_target: unknown case '%s'\n", k);
        return 2;
    }
    fflush(stdout);
    return 0;
}
