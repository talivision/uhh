// Stack-walk target: three known call chains, each ending in a probe site of a different
// frame shape (asm, one file per arch, so the shapes are exact):
//
//   main -> stk_outer_mid  -> StkMid   EBP/RBP-framed function, probe mid-function
//   main -> stk_outer_fpo  -> StkFpo   frame pointer OMITTED and EBP/RBP used as DATA
//   main -> stk_outer_leaf -> StkLeaf  leaf: no frame, no stack adjustment, mid-function
//
// The stk_outer_* callers are optimised C built with /Oy on x86 (frame-pointer omission;
// stk_outer_fpo also has locals), so every chain also crosses compiler FPO frames. A
// send_log_stack at each site must show <site>, stk_outer_<x>, main -- identically under
// breakpoint, hw and inline. The probes must not change results (checked and printed).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

int StkMid(int a);    /* a + 0x1000 */
int StkFpo(int a);    /* a + 0x2000 */
int StkLeaf(int a);   /* a + 0x3000 */

static volatile int g_sink;

__declspec(noinline) int stk_outer_mid(int a) { return StkMid(a) + g_sink; }
__declspec(noinline) int stk_outer_fpo(int a) {
    volatile int buf[8];
    for (int i = 0; i < 8; ++i) buf[i] = a + i;
    return StkFpo(a) + buf[a & 7] - (a & 7);           /* a + 0x2000 + a */
}
__declspec(noinline) int stk_outer_leaf(int a) { return StkLeaf(a) ^ g_sink; }

static int wait_gate(void) {
    char b; DWORD n = 0; HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    return in != INVALID_HANDLE_VALUE && ReadFile(in, &b, 1, &n, NULL) && n == 1;
}

int main(int argc, char **argv) {
    int no_wait = argc > 1 && !strcmp(argv[1], "--no-wait");
    printf("{\"kind\":\"waiting\"}\n"); fflush(stdout);
    if (!no_wait && !wait_gate()) return 3;
    const int calls = 3;
    int correct = 0;
    for (int k = 1; k <= calls; ++k) {
        if (stk_outer_mid(k) == k + 0x1000) ++correct;
        if (stk_outer_fpo(k) == 2 * k + 0x2000) ++correct;
        if (stk_outer_leaf(k) == k + 0x3000) ++correct;
    }
    printf("{\"kind\":\"target\",\"calls\":%d,\"correct\":%d}\n", calls, correct);
    fflush(stdout);
    return 0;
}
