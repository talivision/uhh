// cc_target <none|wrap|replace|wrongpop> [mask-hex]: calls every ccfix.dll function once (see
// cc_shared.h) and checks what the CALLER gets: the return value (EAX, EDX:EAX, ST0/XMM0, a
// hidden-pointer struct), whether the body ran, and on x86 the exact bytes the callee popped
// and that EBX/ESI/EDI/EBP survived (cc_invoke, cc_target_x86.asm). mask = the ids a probe
// sits on (default: all); the mode is what the probes' callback does (cc_callbacks.cpp), so
// each probed function's expected result follows from it. One JSON row per function, then a
// summary; exit code = failures.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cc_shared.h"

extern "C" void *g_pfn_std3t = nullptr;      // the "IAT slots" of CcImpThunk / CcImpNext
extern "C" void *g_pfn_jmp = nullptr;
extern "C" void CcImpThunk(void);
extern "C" __declspec(dllimport) volatile long cc_body;   // ccfix.dll: the bodies that ran

#if !defined(_WIN64)
struct cc_out { uint32_t eax, edx; int32_t popped; uint32_t nv_ok; double st0; uint32_t has_st0, pad; uint8_t xmm0[16]; };
extern "C" void cc_invoke(void *fn, const uint32_t *slots, int n, uint32_t ecx, uint32_t edx, const void *xmm, cc_out *out);
#endif

// What the caller must get from a replace-mode probe: literal constants, written out here
// independently of the callback's formula (cc_callbacks.cpp, cc_replacement). Integer-class
// results; CC_K_PTR results are checked through the struct (CC_REPLACED_STRUCT_BASE).
static int64_t cc_replaced(int id) {
    switch (id) {
    case CC_CDECL0: return 0x5EED0000; case CC_CDECL3: return 0x5EED0001; case CC_STD3: return 0x5EED0002;
    case CC_STD10: return 0x5EED0003; case CC_FAST4: return 0x5EED0004; case CC_THIS: return 0x5EED0005;
    case CC_VEC: return 0x5EED0006; case CC_I64: return 0x7766554433221107ll; case CC_STDI64: return 0x7766554433221108ll;
    case CC_S12: return 0x5EED0009; case CC_S8: return 0x5EED000A;
    case CC_RET8: return ((int64_t)152 << 32) | 151;       // {a = 151, b = 152}
    case CC_HOT: return 0x5EED0010; case CC_ILT: return 0x5EED0011; case CC_IMP: return 0x5EED0012;
    case CC_JMPDST: return 0x5EED0013;
    default: return -1;
    }
}
static int cc_replaced_struct_base(int id) { return id == CC_RETBIG ? 131 : id == CC_RETBIGSTD ? 141 : -1; }

static int g_fails;
static void row(const char *name, bool ok, const char *detail) {
    if (!ok) ++g_fails;
    printf("{\"kind\":\"cct\",\"name\":\"%s\",\"ok\":%s,\"detail\":\"%s\"}\n", name, ok ? "true" : "false", detail);
}

int main(int argc, char **argv) {
    const char *m = argc > 1 ? argv[1] : "none";
    const int mode = !strcmp(m, "wrap") ? CCM_WRAP : !strcmp(m, "replace") ? CCM_REPLACE : !strcmp(m, "wrongpop") ? CCM_WRONGPOP : CCM_NONE;
    const uint32_t mask = argc > 2 ? (uint32_t)strtoul(argv[2], nullptr, 16) : 0xFFFFFFFFu;
    // ccfix.dll is a STATIC import (cc_body), so it is mapped before the session's first
    // install round: a late LoadLibrary would test the LOAD_DLL install hold instead (see
    // docs/ROADMAP.md, "Calling-convention findings", CC8).
    HMODULE h = GetModuleHandleA("ccfix.dll");
    if (!h) { printf("{\"kind\":\"cct_sum\",\"fails\":1,\"error\":\"ccfix.dll not loaded\"}\n"); return 1; }
    volatile long *body = &cc_body;
    g_pfn_std3t = (void *)GetProcAddress(h, "CcStd3T");
    void *tail = (void *)GetProcAddress(h, "CcTail");
    g_pfn_jmp = (void *)GetProcAddress(h, "CcIltNext");
    for (int id = 0; id < CC_N; ++id) {
        const cc_fn &f = CC_FNS[id];
#if defined(_WIN64)
        if (f.x86_only) continue;
#endif
        void *fn = id == CC_IMP ? (void *)&CcImpThunk : id == CC_JMPDST ? tail : (void *)GetProcAddress(h, f.name);
        if (!fn || !body || !g_pfn_std3t || !g_pfn_jmp) { row(f.name, false, "GetProcAddress"); continue; }
        const bool probed = mode != CCM_NONE && ((mask >> id) & 1);
        const bool floaty = f.kind == CC_K_DBL || f.kind == CC_K_FLT;
        const bool replaced = probed && mode == CCM_REPLACE && !floaty;     // the body must not run
        const long before = *body;
        cc_s16 big{};                                                       // hidden return buffer
        int64_t got = 0; double gotd = 0; bool have_d = false;
        char detail[256] = "";
        bool ok = true;
#if !defined(_WIN64)
        uint32_t slots[16] = {0}; int n = 0; uint32_t ecx = 0, edx = 0;
        alignas(16) uint8_t xmm[6][16] = {};
        static uint32_t obj_v = 7;                                         // CcObj { int v; }
        auto put64 = [&](int64_t v) { slots[n++] = (uint32_t)v; slots[n++] = (uint32_t)((uint64_t)v >> 32); };
        auto putf = [&](float v) { memcpy(&slots[n++], &v, 4); };
        switch (id) {
        case CC_CDECL0: break;
        case CC_CDECL3: slots[0] = 1; slots[1] = 2; slots[2] = 3; n = 3; break;
        case CC_STD3: case CC_ILT: case CC_IMP: case CC_JMPDST: slots[0] = 4; slots[1] = 5; slots[2] = 6; n = 3; break;
        case CC_STD10: for (int i = 0; i < 10; ++i) slots[n++] = CC_STD10_ARG(i); break;
        case CC_FAST4: ecx = 11; edx = 12; slots[0] = 13; slots[1] = 14; n = 2; break;
        case CC_THIS: ecx = (uint32_t)(uintptr_t)&obj_v; slots[0] = 21; slots[1] = 22; n = 2; break;
        case CC_VEC: { ecx = 31; edx = 32; double d = 2.5; float fl = 0.25f; memcpy(xmm[0], &d, 8); memcpy(xmm[1], &fl, 4); break; }
        case CC_I64: put64(CC_I64_A); slots[n++] = 3; put64(CC_I64_C); break;
        case CC_STDI64: put64(CC_STDI64_A); slots[n++] = 2; break;
        case CC_S12: memcpy(slots, &CC_S12_ARG, 12); n = 3; slots[n++] = 44; break;
        case CC_S8: memcpy(slots, &CC_S8_ARG, 8); n = 2; break;
        case CC_DBL: { double a = 1.5; memcpy(slots, &a, 8); n = 2; putf(2.25f); slots[n++] = 3; break; }
        case CC_FLT: putf(0.5f); putf(4.0f); break;
        case CC_RETBIG: slots[0] = (uint32_t)(uintptr_t)&big; slots[1] = 61; n = 2; break;
        case CC_RETBIGSTD: slots[0] = (uint32_t)(uintptr_t)&big; slots[1] = 62; n = 2; break;
        case CC_RET8: slots[0] = 63; n = 1; break;
        case CC_HOT: slots[0] = 71; slots[1] = 72; n = 2; break;
        }
        cc_out o{};
        cc_invoke(fn, slots, n, ecx, edx, xmm, &o);
        got = (int64_t)(((uint64_t)o.edx << 32) | o.eax);
        if (f.kind == CC_K_INT) got = (int32_t)o.eax;
        if (floaty) { have_d = o.has_st0 != 0; gotd = o.st0; }
        if (o.popped != f.pop86 || !o.nv_ok) {
            ok = false;
            snprintf(detail, sizeof(detail), "popped=%d want=%d nv_ok=%u ", o.popped, f.pop86, o.nv_ok);
        }
        if (f.kind == CC_K_PTR && o.eax != (uint32_t)(uintptr_t)&big) { ok = false; strcat_s(detail, "eax!=hidden "); }
#else
        static cc_s16 *volatile sink;
        switch (id) {
        case CC_CDECL0: got = ((int (*)())fn)(); break;
        case CC_CDECL3: got = ((int (*)(int, int, int))fn)(1, 2, 3); break;
        case CC_STD3: case CC_ILT: case CC_IMP: case CC_JMPDST: got = ((int (*)(int, int, int))fn)(4, 5, 6); break;
        case CC_STD10: got = ((int (*)(int, int, int, int, int, int, int, int, int, int))fn)(
                           101, 102, 103, 104, 105, 106, 107, 108, 109, 110); break;
        case CC_FAST4: got = ((int (*)(int, int, int, int))fn)(11, 12, 13, 14); break;
        case CC_THIS: { static int obj_v = 7; got = ((int (*)(void *, int, int))fn)(&obj_v, 21, 22); break; }
        case CC_VEC: got = ((int(__vectorcall *)(int, double, int, float))fn)(31, 2.5, 32, 0.25f); break;
        case CC_I64: got = ((long long (*)(long long, int, long long))fn)(CC_I64_A, 3, CC_I64_C); break;
        case CC_STDI64: got = ((long long (*)(long long, int))fn)(CC_STDI64_A, 2); break;
        case CC_S12: got = ((int (*)(cc_s12, int))fn)(CC_S12_ARG, 44); break;
        case CC_S8: got = ((int (*)(cc_s8))fn)(CC_S8_ARG); break;
        case CC_DBL: gotd = ((double (*)(double, float, int))fn)(1.5, 2.25f, 3); have_d = true; break;
        case CC_FLT: gotd = ((float (*)(float, float))fn)(0.5f, 4.0f); have_d = true; break;
        case CC_RETBIG: big = ((cc_s16 (*)(int))fn)(61); break;
        case CC_RETBIGSTD: big = ((cc_s16 (*)(int))fn)(62); break;
        case CC_RET8: { cc_s8 r = ((cc_s8 (*)(int))fn)(63); got = ((int64_t)r.b << 32) | (uint32_t)r.a; break; }
        }
        sink = &big;
#endif
        const long ran = *body - before;
        char buf[160] = "";
        if (ran != (replaced ? 0 : 1)) { ok = false; snprintf(buf, sizeof(buf), "body_ran=%ld ", ran); strcat_s(detail, buf); }
        if (floaty) {
            const double want = f.kind == CC_K_DBL ? CC_DBL_RESULT : (double)CC_FLT_RESULT;
            if (!have_d || gotd != want) { ok = false; snprintf(buf, sizeof(buf), "fp=%g have=%d want=%g ", gotd, have_d, want); strcat_s(detail, buf); }
        } else if (f.kind == CC_K_PTR) {
            const int x = id == CC_RETBIG ? 61 : 62;
            const int base = replaced ? cc_replaced_struct_base(id) : x;
            if (big.a != base || big.b != base + 1 || big.c != base + 2 || big.d != base + 3) {
                ok = false; snprintf(buf, sizeof(buf), "struct={%d,%d,%d,%d} want_base=%d ", big.a, big.b, big.c, big.d, base); strcat_s(detail, buf);
            }
        } else {
            int64_t want = replaced ? cc_replaced(id) : cc_native_int(id);
            if (f.kind == CC_K_INT) want = (int32_t)want;
            if (got != want) { ok = false; snprintf(buf, sizeof(buf), "ret=0x%llx want=0x%llx ", (unsigned long long)got, (unsigned long long)want); strcat_s(detail, buf); }
        }
        row(f.name, ok, detail);
    }
    printf("{\"kind\":\"cct_sum\",\"fails\":%d}\n", g_fails);
    fflush(stdout);
    return g_fails;
}
