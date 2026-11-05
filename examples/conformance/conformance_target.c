// Conformance target: a function with six known arguments, a buffer it hands to the
// probe, and functions the probe calls or probes at runtime. After each call it checks
// the effects the callback is required to have had, and prints them.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

__declspec(align(16)) static volatile uint8_t g_buf[64];
static volatile long g_later_calls, g_watch_value;

// The probed site. Its return value depends on a0, which the callback rewrites.
// Pointer-sized arguments: the API's portable argument model (one slot per argument on
// both x64 and x86).
__declspec(dllexport) __declspec(noinline) intptr_t conf_site(intptr_t a0, intptr_t a1, intptr_t a2,
                                                              intptr_t a3, intptr_t a4, uint8_t *buf) {
    return a0 * 1000 + a1 + a2 + a3 + a4 + buf[0];
}
// Called by the callback via call_func.
__declspec(dllexport) __declspec(noinline) intptr_t conf_mul(intptr_t a, intptr_t b) { return a * b; }
// Probed only at runtime (added from inside the callback).
__declspec(dllexport) __declspec(noinline) void conf_later(int i) { g_later_calls += i ? 1 : 1; }
intptr_t SpSite(void);

/* call_original / return_from (conformance_driver --callorig). g_co_body counts how often a
   body really ran: once with call_original + return_from, never with a pure return_from. */
static volatile long g_co_body;
__declspec(dllexport) __declspec(noinline) intptr_t co_args6(intptr_t a0, intptr_t a1, intptr_t a2,
                                                             intptr_t a3, intptr_t a4, intptr_t a5) {
    g_co_body++;
    return a0 * 100000 + a1 * 10000 + a2 * 1000 + a3 * 100 + a4 * 10 + a5;
}
__declspec(dllexport) __declspec(noinline) intptr_t __stdcall co_std2(intptr_t a, intptr_t b) {
    g_co_body++;
    return a * 31 + b;
}
__declspec(dllexport) __declspec(noinline) intptr_t __cdecl co_cdecl2(intptr_t a, intptr_t b) {
    g_co_body++;
    return a * b + 1;
}
#if !defined(_WIN64)
#pragma comment(linker, "/EXPORT:co_std2=_co_std2@8")
#endif
static int callorig_main(void) {
    int args6 = 0, std2 = 0, std2_sp = 0, cdecl2 = 0, body_ok = 0;
    for (int k = 0; k < 10; ++k) {
        /* callback: a0 1 -> 7 and a5 6 -> 9 (a stack arg on both arches), call_original, then
           return_from(r + 1). Expect 7,2,3,4,5,9 -> 723459 + 1, body ran exactly once. */
        g_co_body = 0;
        intptr_t r = co_args6(1, 2, 3, 4, 5, 6);
        if (r == 723460) ++args6;
        int once = g_co_body == 1;
        /* pure replacement: return_from(99, 2) -- body never runs; x86 stdcall pops 8 bytes. */
        g_co_body = 0;
#if !defined(_WIN64)
        uintptr_t sp_before, sp_after;
        __asm mov sp_before, esp
        r = co_std2(3, 4);
        __asm mov sp_after, esp
        if (sp_before == sp_after) ++std2_sp;
#else
        r = co_std2(3, 4); ++std2_sp;
#endif
        if (r == 99) ++std2;
        int none = g_co_body == 0;
        /* cdecl: call_original (5*6+1 = 31) then return_from(r * 2, 0) -> 62, body once. */
        g_co_body = 0;
        r = co_cdecl2(5, 6);
        if (r == 62) ++cdecl2;
        if (once && none && g_co_body == 1) ++body_ok;
    }
    printf("{\"kind\":\"callorig\",\"args6\":%d,\"std2\":%d,\"std2_sp\":%d,\"cdecl2\":%d,\"body_ok\":%d}\n",
           args6, std2, std2_sp, cdecl2, body_ok);
    fflush(stdout);
    return 0;
}   /* asm: returns how far SP moved across the probe at SpSite+3 */

static int wait_gate(void) {
    char b; DWORD n = 0; HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    return in != INVALID_HANDLE_VALUE && ReadFile(in, &b, 1, &n, NULL) && n == 1;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--callorig")) return callorig_main();
    int no_wait = argc > 1 && !strcmp(argv[1], "--no-wait");
    printf("{\"kind\":\"waiting\"}\n"); fflush(stdout);
    if (!no_wait && !wait_gate()) return 3;
    for (int i = 0; i < 64; ++i) g_buf[i] = (uint8_t)(i + 1);
    const int calls = 10;
    int arg_rewritten = 0, mem_written = 0;
    for (int k = 0; k < calls; ++k) {
        g_buf[8] = 0;
        intptr_t r = conf_site(1, 2, 3, 4, 5, (uint8_t *)g_buf);
        // set_reg/set_mem must have rewritten a0 from 1 to 7: 7000 + 2+3+4+5 + buf[0]
        if (r == 7000 + 14 + g_buf[0]) ++arg_rewritten;
        if (g_buf[8] == 0xA5) ++mem_written;                // set_mem marker
    }
    // No wait: the callback that added conf_later's inline probe held this thread until it landed.
    for (int i = 0; i < 20; ++i) conf_later(i);
    int sp_moved = 0;
    for (int i = 0; i < 10; ++i) if (SpSite() == 32) ++sp_moved;
    g_watch_value = 1; g_watch_value = 2; g_watch_value = 3; // three stores to the watched address
    printf("{\"kind\":\"target\",\"sp_moved\":%d,\"calls\":%d,\"arg_rewritten\":%d,\"mem_written\":%d,\"later_calls\":%ld}\n", sp_moved,
           calls, arg_rewritten, mem_written, g_later_calls);
    fflush(stdout);
    return 0;
}

// Exposed so the callback can find the watched global by symbol.
__declspec(dllexport) volatile long *conf_watch_addr(void) { return &g_watch_value; }
