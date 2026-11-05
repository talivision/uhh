// ccfix.dll: one function per calling convention / argument and return shape (see
// cc_shared.h). Each export is named plainly ("CcStd3"), whatever its decoration: the
// pragma inside each body exports the decorated symbol (__FUNCDNAME__) under that name.
// Every body counts itself in cc_body so a test can tell whether the original ran.
#include <intrin.h>
#include "cc_shared.h"

#define CC_SELF(n) __pragma(comment(linker, "/EXPORT:" n "=" __FUNCDNAME__))

extern "C" __declspec(dllexport) volatile long cc_body = 0;
static __forceinline void body() { _InterlockedIncrement(&cc_body); }

extern "C" {
int __cdecl CcCdecl0(void) { CC_SELF("CcCdecl0"); body(); return 256; }
int __cdecl CcCdecl3(int a, int b, int c) { CC_SELF("CcCdecl3"); body(); return a * 100 + b * 10 + c; }
int __stdcall CcStd3(int a, int b, int c) { CC_SELF("CcStd3"); body(); return a * 100 + b * 10 + c; }
int __stdcall CcStd10(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10) {
    CC_SELF("CcStd10"); body();
    return a1 + 2 * a2 + 3 * a3 + 4 * a4 + 5 * a5 + 6 * a6 + 7 * a7 + 8 * a8 + 9 * a9 + 10 * a10;
}
int __fastcall CcFast4(int a, int b, int c, int d) { CC_SELF("CcFast4"); body(); return a * 1000000 + b * 10000 + c * 100 + d; }
int __vectorcall CcVec(int a, double d, int b, float f) {
    CC_SELF("CcVec"); body();
    return a * 1000 + b + (int)(d * 100) + (int)(f * 100);
}
long long __cdecl CcI64(long long a, int b, long long c) { CC_SELF("CcI64"); body(); return a + b + c; }
long long __stdcall CcStdI64(long long a, int b) { CC_SELF("CcStdI64"); body(); return a + b; }
int __stdcall CcS12(CcS12 s, int k) { CC_SELF("CcS12"); body(); return s.a + 2 * s.b + 3 * s.c + 4 * k; }
int __cdecl CcS8(CcS8 s) { CC_SELF("CcS8"); body(); return s.a * 100 + s.b; }
double __cdecl CcDbl(double a, float b, int c) { CC_SELF("CcDbl"); body(); return a * b + c; }
float __stdcall CcFlt(float a, float b) { CC_SELF("CcFlt"); body(); return a * b + 0.125f; }
CcS16 __cdecl CcRetBig(int x) { CC_SELF("CcRetBig"); body(); return CcS16{x, x + 1, x + 2, x + 3}; }
CcS16 __stdcall CcRetBigStd(int x) { CC_SELF("CcRetBigStd"); body(); return CcS16{x, x + 1, x + 2, x + 3}; }
CcS8 __cdecl CcRet8(int x) { CC_SELF("CcRet8"); body(); return CcS8{x, x * 2}; }
}

// __thiscall (x86: `this` in ECX, the callee pops the stack arguments).
struct CcObj { int v; int Get(int a, int b); };
int CcObj::Get(int a, int b) { CC_SELF("CcThisGet"); body(); return v * 10000 + a * 100 + b; }
