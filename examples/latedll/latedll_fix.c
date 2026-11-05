/* latedll_fix.dll: LoadLibrary'd at run time by latedll_target (main thread, a worker
 * thread, or latedll_heavy.dll's DllMain). Eight probed exports -- more than the four debug
 * registers, so the controller cannot gate all of them with hardware breakpoints. Each body
 * counts its own calls (the program's truth the probe hits are compared with). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "latedll_shared.h"

static volatile LONG g_calls[LD_NSITES];
static volatile LONG_PTR g_sink[LD_NSITES];

#define LD_SITE(k) \
    __declspec(dllexport) __declspec(noinline) LONG_PTR LdSite##k(LONG_PTR id, LONG_PTR i) { \
        InterlockedIncrement(&g_calls[k]); g_sink[k] += id * (k + 3) + i; return g_sink[k] ^ i; }
LD_SITE(0) LD_SITE(1) LD_SITE(2) LD_SITE(3) LD_SITE(4) LD_SITE(5) LD_SITE(6) LD_SITE(7)

__declspec(dllexport) LONG LdCount(int k) { return k >= 0 && k < LD_NSITES ? g_calls[k] : -1; }
