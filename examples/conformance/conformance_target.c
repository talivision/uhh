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
intptr_t SpSite(void);   /* asm: returns how far SP moved across the probe at SpSite+3 */

static int wait_gate(void) {
    char b; DWORD n = 0; HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    return in != INVALID_HANDLE_VALUE && ReadFile(in, &b, 1, &n, NULL) && n == 1;
}

int main(int argc, char **argv) {
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
