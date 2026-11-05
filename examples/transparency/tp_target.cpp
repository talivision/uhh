// Transparency fixture: the TARGET (regress `transparency`). Every probed function has an
// unprobed twin with the same body; both are called through the same assembly harness
// (tp_sites_*.asm), which loads sentinels into every callee-saved register and captures,
// after the call, everything an ordinary caller can observe: the return registers (x64 RAX /
// XMM0; x86 EDX:EAX / ST0), callee-saved GPRs (+ XMM6-15 on x64), the stack-pointer delta
// (x86 `ret N`), DF, the x87 status/tag words. The C side adds GetLastError, the TEB's
// LastStatusValue and a byte diff of the whole TEB across the call. A probed call must be
// indistinguishable from its twin, whatever the callback does (tp_callbacks.cpp).
// A mid-function site (TpMidHit, between `cmp` and the flag snapshot, with a full x87 stack
// and a pending FCOM result) is compared the same way against TpMidRef.
//   tp_target [--iters N] [--spawn]
// --spawn: the probe on tp_spawn creates a thread (call_func CreateThread) that runs the
// probed tp_threadfn; the target waits for it.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TP_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)
#define TP_REF static __declspec(noinline)

struct TpIn { uint64_t a[8]; uint64_t x0, x1; uint32_t nargs, fpret; };
struct TpOut {
    uint64_t rax, rdx; uint8_t xmm0[16]; uint64_t nv[8]; uint8_t xmmnv[10][16];
    int64_t sp_delta; uint64_t flags; uint64_t st0; uint32_t fsw, ftw;
};
static_assert(offsetof(TpOut, sp_delta) == 0x100 && offsetof(TpOut, st0) == 0x110 && offsetof(TpOut, fsw) == 0x118,
              "harness layout");
struct TpMidOut { uint64_t gpr[15]; uint64_t flags; uint8_t xmm[16][16]; uint8_t fpu[108]; uint32_t pad; uint8_t ymmhi[16][16]; };
static_assert(offsetof(TpMidOut, xmm) == 0x80 && offsetof(TpMidOut, fpu) == 0x180 && offsetof(TpMidOut, ymmhi) == 0x1F0,
              "mid layout");

extern "C" void TpHarness(const void *fn, const TpIn *in, TpOut *out);
extern "C" void TpMid(TpMidOut *out);
extern "C" void TpMidRef(TpMidOut *out);

static volatile long g_calls;
typedef ULONG(NTAPI *RtlNtStatusToDosError_t)(LONG);
static RtlNtStatusToDosError_t p_status_to_dos;

// ---- the functions: probed (exported) and twin (TP_REF) with identical bodies -----------
#define BODY_ADD { g_calls++; return a * 3 + b; }
TP_EXPORT intptr_t tp_add(intptr_t a, intptr_t b) BODY_ADD
TP_REF intptr_t ref_add(intptr_t a, intptr_t b) BODY_ADD
#define BODY_I64 { g_calls++; return (((uint64_t)a << 32) | b) * 0x10001ull + 0x0123456789ull; }
TP_EXPORT uint64_t tp_i64(uint32_t a, uint32_t b) BODY_I64
TP_REF uint64_t ref_i64(uint32_t a, uint32_t b) BODY_I64
#define BODY_DBL { g_calls++; return (double)a / (double)b + 0.25; }
TP_EXPORT double tp_dbl(intptr_t a, intptr_t b) BODY_DBL
TP_REF double ref_dbl(intptr_t a, intptr_t b) BODY_DBL
#define BODY_DBLARG { g_calls++; return x * 2.5 + (double)k; }
TP_EXPORT double tp_dblarg(double x, intptr_t k) BODY_DBLARG
TP_REF double ref_dblarg(double x, intptr_t k) BODY_DBLARG
// Sets the thread's last error AND last NT status (RtlNtStatusToDosError records the status
// in the TEB): call_original must leave exactly these behind, as an un-hooked call does.
#define BODY_SETERR { g_calls++; p_status_to_dos((LONG)(0xC0000000u | (code & 0xFFFF))); SetLastError(code); return code ^ 0x55; }
TP_EXPORT DWORD tp_seterr(DWORD code) BODY_SETERR
TP_REF DWORD ref_seterr(DWORD code) BODY_SETERR
#define BODY_STD { g_calls++; return a - b * c; }
TP_EXPORT intptr_t __stdcall tp_std(intptr_t a, intptr_t b, intptr_t c) BODY_STD
TP_REF intptr_t __stdcall ref_std(intptr_t a, intptr_t b, intptr_t c) BODY_STD
// The stack alignment the body sees (x64: entry RSP == 8 mod 16; x86: 4-byte aligned).
#if defined(_WIN64)
#define ALIGNED() ((((uintptr_t)_AddressOfReturnAddress()) & 15) == 8)
#else
#define ALIGNED() ((((uintptr_t)_AddressOfReturnAddress()) & 3) == 0)
#endif
#define BODY_ALIGN { g_calls++; return (ALIGNED() ? 1000 : 0) + salt; }
TP_EXPORT intptr_t tp_align(intptr_t salt) BODY_ALIGN
TP_REF intptr_t ref_align(intptr_t salt) BODY_ALIGN
TP_EXPORT intptr_t tp_fact(intptr_t n) { g_calls++; return n <= 1 ? 1 : n * tp_fact(n - 1); }
TP_REF intptr_t ref_fact(intptr_t n) { g_calls++; return n <= 1 ? 1 : n * ref_fact(n - 1); }
TP_EXPORT intptr_t tp_spawn(void *fn, void *arg) { g_calls++; return (intptr_t)fn ^ (intptr_t)arg; }
TP_EXPORT DWORD WINAPI tp_threadfn(void *arg) { g_calls++; InterlockedExchange((volatile LONG *)arg, 1); return 5; }
// get_mem target: the callback (mode mem) reads 16 bytes at the argument.
TP_EXPORT intptr_t tp_peek(void *p) { g_calls++; return (intptr_t)p & 0xFF; }
// The probe on tp_ovf (tp_on_ovf) overflows its own stack (inline: the target thread's).
TP_EXPORT intptr_t tp_ovf(intptr_t x) { g_calls++; return x + 1; }
#if !defined(_WIN64)
#pragma comment(linker, "/EXPORT:tp_std=_tp_std@12")
#pragma comment(linker, "/EXPORT:tp_threadfn=_tp_threadfn@4")
#endif

// ---- TEB ----------------------------------------------------------------------------------
// TEB_HEAP_DATA: the heap's per-thread LFH affinity hint (HeapData, formerly
// HeapVirtualAffinity/LowFragHeapDataSlot), moved by any heap call an inline callback makes.
#if defined(_WIN64)
static const size_t TEB_SIZE = 0x1800, TEB_LAST_STATUS = 0x1250, TEB_STACK_LIMIT = 0x10, TEB_HEAP_DATA = 0x17B0;
#else
static const size_t TEB_SIZE = 0xFE0, TEB_LAST_STATUS = 0xBF4, TEB_STACK_LIMIT = 0x08, TEB_HEAP_DATA = 0xFA8;
#endif
static unsigned char *teb() { return (unsigned char *)NtCurrentTeb(); }
static void snap(unsigned char *dst) { const volatile unsigned char *t = teb(); for (size_t i = 0; i < TEB_SIZE; ++i) dst[i] = t[i]; }
static void set_le(DWORD err, DWORD status) { *(volatile DWORD *)(teb() + TEB_LAST_STATUS) = status; SetLastError(err); }

struct Result { long ok = 0, bad = 0, stack_moves = 0, heap_hint = 0; char first[256] = ""; };
static long g_bad_total;
static char g_first[512];
static void fail(Result &r, const char *name, int iter, const char *what) {
    if (!r.bad) snprintf(r.first, sizeof(r.first), "%s", what);
    if (!g_bad_total) snprintf(g_first, sizeof(g_first), "%s iter %d: %s", name, iter, what);
    r.bad++; g_bad_total++;
}

// Compare the TEB changes of the probed call (b1 -> a1) against the twin's (b2 -> a2).
// The stack limit moving down (a callback committing more of the thread's stack) and the
// heap's affinity hint (a callback's own heap calls) are counted, not failed: see
// docs/ROADMAP.md "Transparency findings".
static bool teb_same(const unsigned char *b1, const unsigned char *a1, const unsigned char *b2, const unsigned char *a2,
                     Result &r, char *why, size_t n) {
    for (size_t i = 0; i < TEB_SIZE; ++i) {
        const bool c1 = a1[i] != b1[i], c2 = a2[i] != b2[i];
        if (c1 == c2 && (!c1 || a1[i] == a2[i])) continue;
        if (i >= TEB_STACK_LIMIT && i < TEB_STACK_LIMIT + sizeof(void *)) { r.stack_moves++; i = TEB_STACK_LIMIT + sizeof(void *) - 1; continue; }
        if (i >= TEB_HEAP_DATA && i < TEB_HEAP_DATA + 4) { r.heap_hint++; i = TEB_HEAP_DATA + 3; continue; }
        snprintf(why, n, "TEB+0x%zx changed (probed %02x->%02x, twin %02x->%02x)", i, b1[i], a1[i], b2[i], a2[i]);
        return false;
    }
    return true;
}

enum RetKind { RET_INT, RET_I64, RET_DBL };
struct Fn { const char *name; const void *probed, *ref; RetKind kind; };

static void make_in(const char *name, int i, TpIn &in) {
    memset(&in, 0, sizeof(in));
    const intptr_t a = 1000 + i * 7, b = 3 + (i % 5);
    if (!strcmp(name, "add") || !strcmp(name, "i64") || !strcmp(name, "dbl")) { in.a[0] = (uint64_t)a; in.a[1] = (uint64_t)b; in.nargs = 2; }
    else if (!strcmp(name, "std")) { in.a[0] = (uint64_t)a; in.a[1] = (uint64_t)b; in.a[2] = 11; in.nargs = 3; }
    else if (!strcmp(name, "seterr")) { in.a[0] = 0x2000 + (uint64_t)i; in.nargs = 1; }
    else if (!strcmp(name, "align")) { in.a[0] = (uint64_t)i; in.nargs = 1; }
    else if (!strcmp(name, "fact")) { in.a[0] = 3 + (i % 6); in.nargs = 1; }
    else if (!strcmp(name, "dblarg")) {
        double x = 1.0 + i / 8.0; uint64_t bits; memcpy(&bits, &x, 8);
#if defined(_WIN64)
        in.x0 = bits; in.a[0] = 0x5151; in.a[1] = (uint64_t)b; in.nargs = 2;     // x in XMM0, k in RDX
#else
        in.a[0] = (uint32_t)bits; in.a[1] = bits >> 32; in.a[2] = (uint64_t)b; in.nargs = 3;
#endif
    }
#if !defined(_WIN64)
    if (!strcmp(name, "dbl") || !strcmp(name, "dblarg")) in.fpret = 1;
#endif
}

static void check_fn(const Fn &f, int i, Result &r) {
    static unsigned char b1[0x1800], a1[0x1800], b2[0x1800], a2[0x1800];
    TpIn in; make_in(f.name, i, in);
    TpOut o1{}, o2{};
    const DWORD le = 0x1234ABCD, ls = 0xC0DE0000u + (DWORD)i;
    set_le(le, ls); snap(b1);
    TpHarness(f.probed, &in, &o1);
    snap(a1);
    const DWORD le1 = GetLastError(), ls1 = *(DWORD *)(teb() + TEB_LAST_STATUS);
    set_le(le, ls); snap(b2);
    TpHarness(f.ref, &in, &o2);
    snap(a2);
    const DWORD le2 = GetLastError(), ls2 = *(DWORD *)(teb() + TEB_LAST_STATUS);
    char why[200] = "";
#if defined(_WIN64)
    const uint64_t eax1 = o1.rax, eax2 = o2.rax;
#else
    const uint64_t eax1 = (uint32_t)o1.rax, eax2 = (uint32_t)o2.rax;
#endif
    if (f.kind != RET_DBL && eax1 != eax2) snprintf(why, sizeof(why), "AX 0x%llx, twin 0x%llx", (unsigned long long)eax1, (unsigned long long)eax2);
#if !defined(_WIN64)
    else if (f.kind == RET_I64 && o1.rdx != o2.rdx) snprintf(why, sizeof(why), "EDX (high half) 0x%llx, twin 0x%llx", (unsigned long long)o1.rdx, (unsigned long long)o2.rdx);
    else if (f.kind == RET_DBL && o1.st0 != o2.st0) snprintf(why, sizeof(why), "ST0 0x%llx, twin 0x%llx", (unsigned long long)o1.st0, (unsigned long long)o2.st0);
#else
    else if (f.kind == RET_DBL && memcmp(o1.xmm0, o2.xmm0, 8)) snprintf(why, sizeof(why), "XMM0 0x%llx, twin 0x%llx", *(unsigned long long *)o1.xmm0, *(unsigned long long *)o2.xmm0);
    else if (memcmp(o1.xmmnv, o2.xmmnv, sizeof(o1.xmmnv))) snprintf(why, sizeof(why), "XMM6-15 differ");
#endif
    else if (memcmp(o1.nv, o2.nv, sizeof(o1.nv))) {
        static const char *nv[8] = {"BX", "BP", "SI", "DI", "R12", "R13", "R14", "R15"};
        for (int k = 0; k < 8; ++k) if (o1.nv[k] != o2.nv[k]) { snprintf(why, sizeof(why), "callee-saved %s 0x%llx, twin 0x%llx", nv[k], (unsigned long long)o1.nv[k], (unsigned long long)o2.nv[k]); break; }
    }
    else if (o1.sp_delta != o2.sp_delta) snprintf(why, sizeof(why), "SP after the call %+lld, twin %+lld", (long long)o1.sp_delta, (long long)o2.sp_delta);
    else if ((o1.flags ^ o2.flags) & 0x400) snprintf(why, sizeof(why), "DF %d, twin %d", (int)!!(o1.flags & 0x400), (int)!!(o2.flags & 0x400));
    else if (o1.fsw != o2.fsw || o1.ftw != o2.ftw) snprintf(why, sizeof(why), "x87 SW/TW %04x/%04x, twin %04x/%04x", o1.fsw, o1.ftw, o2.fsw, o2.ftw);
    else if (le1 != le2) snprintf(why, sizeof(why), "GetLastError 0x%lx, twin 0x%lx", le1, le2);
    else if (ls1 != ls2) snprintf(why, sizeof(why), "LastStatusValue 0x%lx, twin 0x%lx", ls1, ls2);
    else teb_same(b1, a1, b2, a2, r, why, sizeof(why));
    if (why[0]) fail(r, f.name, i, why); else r.ok++;
}

static void check_mid(int i, Result &r) {
    static unsigned char b1[0x1800], a1[0x1800], b2[0x1800], a2[0x1800];
    TpMidOut o1{}, o2{};
    const DWORD le = 0x0BADF00D, ls = 0xC0DE1000u + (DWORD)i;
    set_le(le, ls); snap(b1); TpMid(&o1); snap(a1);
    const DWORD le1 = GetLastError(), ls1 = *(DWORD *)(teb() + TEB_LAST_STATUS);
    set_le(le, ls); snap(b2); TpMidRef(&o2); snap(a2);
    const DWORD le2 = GetLastError(), ls2 = *(DWORD *)(teb() + TEB_LAST_STATUS);
    char why[200] = "";
    for (int k = 0; k < 15 && !why[0]; ++k)
        if (o1.gpr[k] != o2.gpr[k]) snprintf(why, sizeof(why), "GPR #%d 0x%llx, twin 0x%llx", k, (unsigned long long)o1.gpr[k], (unsigned long long)o2.gpr[k]);
    if (why[0]) {}
    else if ((o1.flags ^ o2.flags) & 0xCD5) snprintf(why, sizeof(why), "EFLAGS 0x%llx, twin 0x%llx", (unsigned long long)o1.flags, (unsigned long long)o2.flags);
    else if (memcmp(o1.xmm, o2.xmm, sizeof(o1.xmm))) snprintf(why, sizeof(why), "XMM differ");
    else if (memcmp(o1.ymmhi, o2.ymmhi, sizeof(o1.ymmhi))) {
        int k = 0; while (k < 15 && !memcmp(o1.ymmhi[k], o2.ymmhi[k], 16)) ++k;
        snprintf(why, sizeof(why), "YMM%d upper half 0x%llx, twin 0x%llx", k, *(unsigned long long *)o1.ymmhi[k], *(unsigned long long *)o2.ymmhi[k]);
    }
    // FNSAVE image: CW, SW, TW (bytes 0..11) and the 8 registers (28..107); not FIP/FDP/opcode.
    else if (memcmp(o1.fpu, o2.fpu, 12)) snprintf(why, sizeof(why), "x87 CW/SW/TW %04x/%04x/%04x, twin %04x/%04x/%04x",
                                                    *(uint16_t *)o1.fpu, *(uint16_t *)(o1.fpu + 4), *(uint16_t *)(o1.fpu + 8),
                                                    *(uint16_t *)o2.fpu, *(uint16_t *)(o2.fpu + 4), *(uint16_t *)(o2.fpu + 8));
    else if (memcmp(o1.fpu + 28, o2.fpu + 28, 80)) snprintf(why, sizeof(why), "x87 register stack differs");
    else if (le1 != le2) snprintf(why, sizeof(why), "GetLastError 0x%lx, twin 0x%lx", le1, le2);
    else if (ls1 != ls2) snprintf(why, sizeof(why), "LastStatusValue 0x%lx, twin 0x%lx", ls1, ls2);
    else teb_same(b1, a1, b2, a2, r, why, sizeof(why));
    if (why[0]) fail(r, "mid", i, why); else r.ok++;
}

// ---- get_mem never faults where the target can see it (and never eats its PAGE_GUARD) -------
static volatile LONG g_veh;
static LONG CALLBACK count_veh(EXCEPTION_POINTERS *) { InterlockedIncrement(&g_veh); return EXCEPTION_CONTINUE_SEARCH; }
// A page the probe has read (so the agent knows it), then guarded, then decommitted: each
// later probed call must neither raise an exception the target's vectored handler sees nor
// consume the guard. Returns "" or what went wrong.
static const char *check_peek(char *why, size_t n) {
    unsigned char *p = (unsigned char *)VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) return "VirtualAlloc";
    memset(p, 0x5A, 4096);
    for (int i = 0; i < 3; ++i) tp_peek(p + 64);
    PVOID veh = AddVectoredExceptionHandler(1, count_veh);
    DWORD old = 0;
    VirtualProtect(p, 4096, PAGE_READWRITE | PAGE_GUARD, &old);
    for (int i = 0; i < 3; ++i) tp_peek(p + 64);
    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(p, &mbi, sizeof(mbi));
    const bool guard_kept = (mbi.Protect & PAGE_GUARD) != 0;
    const LONG veh_guard = g_veh;
    VirtualProtect(p, 4096, PAGE_NOACCESS, &old);
    for (int i = 0; i < 3; ++i) tp_peek(p + 64);
    const LONG veh_noaccess = g_veh - veh_guard;
    VirtualFree(p, 4096, MEM_DECOMMIT);
    for (int i = 0; i < 3; ++i) tp_peek(p + 64);
    const LONG veh_decommit = g_veh - veh_guard - veh_noaccess;
    RemoveVectoredExceptionHandler(veh);
    VirtualFree(p, 0, MEM_RELEASE);
    if (!guard_kept || veh_guard || veh_noaccess || veh_decommit) {
        snprintf(why, n, "get_mem: guard kept=%d, exceptions seen by the target: guard=%ld noaccess=%ld decommit=%ld",
                 (int)guard_kept, veh_guard, veh_noaccess, veh_decommit);
        return why;
    }
    return "";
}

// ---- a callback's stack overflow must not cost the thread its guard page ------------------
static int own_overflow_depth(int d) { volatile char pad[4096]; pad[0] = (char)d; return pad[0] + own_overflow_depth(d + 1) + pad[4095]; }
static int overflow_caught() {
    __try { return own_overflow_depth(0); }
    __except (GetExceptionCode() == EXCEPTION_STACK_OVERFLOW ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {}
    return _resetstkoflw() ? 1 : 0;
}
static DWORD WINAPI ovf_thread(void *out) {
    tp_ovf(41);                                     // its probe overflows (inline: on THIS stack)
    *(int *)out = overflow_caught();                // the program's own overflow is still catchable
    return 0;
}
static int check_ovf() {
    int ok = 0;
    HANDLE h = CreateThread(nullptr, 0, ovf_thread, &ok, 0, nullptr);
    if (!h) return 0;
    DWORD w = WaitForSingleObject(h, 30000), code = 0;
    GetExitCodeThread(h, &code);
    CloseHandle(h);
    return w == WAIT_OBJECT_0 && code == 0 ? ok : 0;
}

int main(int argc, char **argv) {
    int iters = 50; bool spawn = false, peek = false, ovf = false;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--iters") && i + 1 < argc) iters = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--spawn")) spawn = true;
        else if (!strcmp(argv[i], "--peek")) peek = true;
        else if (!strcmp(argv[i], "--ovf")) ovf = true;
    }
    p_status_to_dos = (RtlNtStatusToDosError_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");
    static const Fn fns[] = {
        {"add", (const void *)tp_add, (const void *)ref_add, RET_INT},
        {"i64", (const void *)tp_i64, (const void *)ref_i64, RET_I64},
        {"dbl", (const void *)tp_dbl, (const void *)ref_dbl, RET_DBL},
        {"dblarg", (const void *)tp_dblarg, (const void *)ref_dblarg, RET_DBL},
        {"seterr", (const void *)tp_seterr, (const void *)ref_seterr, RET_INT},
        {"std", (const void *)tp_std, (const void *)ref_std, RET_INT},
        {"align", (const void *)tp_align, (const void *)ref_align, RET_INT},
        {"fact", (const void *)tp_fact, (const void *)ref_fact, RET_INT},
    };
    const size_t nf = sizeof(fns) / sizeof(fns[0]);
    Result res[sizeof(fns) / sizeof(fns[0]) + 1];
    for (int i = 0; i < iters; ++i) {
        for (size_t k = 0; k < nf; ++k) check_fn(fns[k], i, res[k]);
        check_mid(i, res[nf]);
    }
    int spawned = -1;
    if (spawn) {
        static volatile LONG flag;
        tp_spawn((void *)tp_threadfn, (void *)&flag);
        for (int t = 0; t < 500 && !flag; ++t) Sleep(10);
        spawned = flag ? 1 : 0;
        if (!flag) { g_bad_total++; snprintf(g_first, sizeof(g_first), "spawn: the thread created in the hit never ran tp_threadfn"); }
    }
    int peek_ok = -1, ovf_ok = -1;
    if (peek) {
        char why[200]; const char *w = check_peek(why, sizeof(why));
        peek_ok = !*w;
        if (*w) { g_bad_total++; if (!g_first[0]) snprintf(g_first, sizeof(g_first), "%s", w); }
    }
    if (ovf) {
        ovf_ok = check_ovf();
        if (!ovf_ok) { g_bad_total++; if (!g_first[0]) snprintf(g_first, sizeof(g_first), "ovf: after a hit, the thread's own stack overflow was not caught (guard page lost?)"); }
    }
    long moves = 0, hints = 0;
    printf("{\"kind\":\"target\",\"name\":\"transparency\",\"iters\":%d,\"spawn\":%d,\"peek\":%d,\"ovf\":%d", iters, spawned, peek_ok, ovf_ok);
    for (size_t k = 0; k <= nf; ++k) {
        const char *n = k < nf ? fns[k].name : "mid";
        printf(",\"%s_bad\":%ld", n, res[k].bad);
        moves += res[k].stack_moves; hints += res[k].heap_hint;
    }
    printf(",\"bad\":%ld,\"stack_limit_moves\":%ld,\"heap_hint_changes\":%ld,\"first\":\"", g_bad_total, moves, hints);
    for (const char *p = g_first; *p; ++p) if (*p != '"' && *p != '\\') putchar(*p);
    printf("\"}\n");
    fflush(stdout);
    return 0;
}
