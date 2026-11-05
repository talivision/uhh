// Calling-convention fixture (regress `callconv-*`): what ccfix.dll exports, how cc_target
// calls each function, and what a probe at its entry must see. Shared by the fixture DLL,
// the target, the driver and the callbacks (one table, no drift).
#pragma once
#include <stdint.h>

struct cc_s8 { int32_t a, b; };              // x86: by value = 2 stack slots, returned in EDX:EAX
struct cc_s12 { int32_t a, b, c; };          // x86: 3 stack slots; x64: passed by reference to a copy
struct cc_s16 { int32_t a, b, c, d; };       // returned through a hidden pointer on both arches

enum cc_id {
    CC_CDECL0, CC_CDECL3, CC_STD3, CC_STD10, CC_FAST4, CC_THIS, CC_VEC, CC_I64, CC_STDI64,
    CC_S12, CC_S8, CC_DBL, CC_FLT, CC_RETBIG, CC_RETBIGSTD, CC_RET8, CC_HOT, CC_ILT, CC_IMP, CC_JMPDST,
    CC_N
};
enum cc_kind { CC_K_INT, CC_K_I64, CC_K_DBL, CC_K_FLT, CC_K_PTR, CC_K_S8 };
enum cc_mode { CCM_NONE = 0, CCM_WRAP = 1, CCM_REPLACE = 2, CCM_WRONGPOP = 3 };

struct cc_fn {
    const char *module, *name;
    int pop86;          // x86: bytes the callee pops (its `ret N`)
    int nslots;         // integer slots the function's arguments take: x86 stack slots, x64 arguments
    int kind;
    int x86_only;
};
static const cc_fn CC_FNS[CC_N] = {
    {"ccfix.dll", "CcCdecl0", 0, 0, CC_K_INT, 0},        // int __cdecl ()
    {"ccfix.dll", "CcCdecl3", 0, 3, CC_K_INT, 0},        // int __cdecl (int, int, int)
    {"ccfix.dll", "CcStd3", 12, 3, CC_K_INT, 0},         // int __stdcall (int, int, int)
    {"ccfix.dll", "CcStd10", 40, 10, CC_K_INT, 0},       // int __stdcall (10 x int): > 8 arguments
    {"ccfix.dll", "CcFast4", 8, 4, CC_K_INT, 0},         // int __fastcall (int, int, int, int)
    {"ccfix.dll", "CcThisGet", 8, 3, CC_K_INT, 0},       // int CcObj::Get(int, int): __thiscall
    {"ccfix.dll", "CcVec", 0, 4, CC_K_INT, 0},           // int __vectorcall (int, double, int, float)
    {"ccfix.dll", "CcI64", 0, 5, CC_K_I64, 0},           // int64 __cdecl (int64, int, int64)
    {"ccfix.dll", "CcStdI64", 12, 3, CC_K_I64, 0},       // int64 __stdcall (int64, int)
    {"ccfix.dll", "CcS12", 16, 4, CC_K_INT, 0},          // int __stdcall (CcS12 by value, int)
    {"ccfix.dll", "CcS8", 0, 2, CC_K_INT, 0},            // int __cdecl (CcS8 by value)
    {"ccfix.dll", "CcDbl", 0, 4, CC_K_DBL, 0},           // double __cdecl (double, float, int)
    {"ccfix.dll", "CcFlt", 8, 2, CC_K_FLT, 0},           // float __stdcall (float, float)
    {"ccfix.dll", "CcRetBig", 0, 2, CC_K_PTR, 0},        // cc_s16 __cdecl (int): hidden return pointer
    {"ccfix.dll", "CcRetBigStd", 8, 2, CC_K_PTR, 0},     // cc_s16 __stdcall (int): the callee pops it too
    {"ccfix.dll", "CcRet8", 0, 1, CC_K_S8, 0},           // CcS8 __cdecl (int): x86 EDX:EAX, x64 RAX
    {"ccfix.dll", "CcHot", 8, 2, CC_K_INT, 1},           // stdcall behind `mov edi,edi; push ebp; mov ebp,esp`
    {"ccfix.dll", "CcIlt", 12, 3, CC_K_INT, 0},          // incremental-link thunk: jmp rel32 -> CcStd3T
    {"cc_target.exe", "CcImpThunk", 12, 3, CC_K_INT, 0}, // import thunk: jmp [IAT slot] -> CcStd3T
    {"ccfix.dll", "CcJmpDst", 12, 3, CC_K_INT, 0},       // reached by a tail-call jmp (CcTail), not a call
};

// Arguments cc_target passes.
#define CC_STD10_ARG(i) (101 + (i))                              /* i = 0..9 */
#define CC_I64_A 0x1111111122222222ll
#define CC_I64_C 0x0444444455555555ll
#define CC_STDI64_A 0x0123456789ABCDEFll
static const struct cc_s12 CC_S12_ARG = {41, 42, 43};
static const struct cc_s8 CC_S8_ARG = {51, 52};

// Native results (what the uninstrumented function returns for those arguments).
static inline int64_t cc_native_int(int id) {
    switch (id) {
    case CC_CDECL0: return 256;
    case CC_CDECL3: return 123;
    case CC_STD3: case CC_ILT: case CC_IMP: case CC_JMPDST: return 456;
    case CC_STD10: { int64_t s = 0; for (int i = 0; i < 10; ++i) s += (i + 1) * CC_STD10_ARG(i); return s; }
    case CC_FAST4: return 11121314;
    case CC_THIS: return 72122;
    case CC_VEC: return 31307;
    case CC_I64: return CC_I64_A + 3 + CC_I64_C;
    case CC_STDI64: return CC_STDI64_A + 2;
    case CC_S12: return 41 + 2 * 42 + 3 * 43 + 4 * 44;
    case CC_S8: return 51 * 100 + 52;
    case CC_RET8: return ((int64_t)126 << 32) | 63;
    case CC_HOT: return 143;
    default: return 0;
    }
}
#define CC_DBL_RESULT 6.375          /* 1.5 * 2.25f + 3 */
#define CC_FLT_RESULT 2.125f         /* 0.5f * 4.0f + 0.125f */

// What the replace-mode callback returns instead (integer-class results only: return_from
// cannot set a floating-point return register).
static inline uint64_t cc_replacement(int id) {
    switch (CC_FNS[id].kind) {
    case CC_K_I64: return 0x7766554433221100ull + (uint64_t)id;
    case CC_K_S8: return ((uint64_t)(id * 10 + 2) << 32) | (uint64_t)(id * 10 + 1);
    default: return 0x5EED0000u + (uint32_t)id;
    }
}
