/* cet_smash: the target for checking UHH against a shadow-stack checker (real CET hardware or
   Intel SDE's CET emulation, regress `cet-sde-*`). Built with /CETCOMPAT.

     cet_smash clean   two ordinary calls; exits 0. Must never be flagged.
     cet_smash smash   the positive control: the second call's return address is overwritten (on
                       the ordinary stack only) with the FIRST call's return address -- a valid
                       code address in the same frame, so without a shadow stack the program just
                       "returns" to site A a second time, prints "landed" and exits 3. With an
                       enforced shadow stack that `ret` does not match the shadow copy: #CP on
                       CET hardware, a "Control flow error" report under SDE.
     cet_smash calls N [--wait] [--smash]
                       the instrumented workload: N iterations of cet_leaf(i) and cet_caller(i)
                       (cet_caller CALLs cet_leaf; "call_off" is the offset of that call
                       instruction in cet_caller, where an inline hook has to relocate a call).
                       After each iteration RDSSP is read: "ssp_live" counts the iterations in
                       which this thread still had a shadow stack -- under SDE it drops to 0 the
                       moment the thread leaves the emulator. --wait: print the pid and wait for
                       one byte on stdin first (so a tool can attach). --smash: then the positive
                       control in the same thread, so the checker is shown to be still active
                       after the instrumented calls ("site_a"/"site_b" are the two return
                       addresses the checker must report).

   Every mode prints JSON lines; the first one carries RDSSP ("ssp"). */
#include <windows.h>
#include <intrin.h>
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CET_EXPORT __declspec(dllexport) __declspec(noinline)

static uintptr_t rdssp(void) {
#if defined(_WIN64)
    return (uintptr_t)_rdsspq();
#else
    return (uintptr_t)_rdsspd();
#endif
}

static void *volatile first_ret, *volatile second_ret;
static volatile int stage;

__declspec(noinline) static void victim(int smash) {
    void **slot = (void **)_AddressOfReturnAddress();
    if (!first_ret) first_ret = *slot;
    else if (smash) { second_ret = *slot; *slot = first_ret; }
}

__declspec(noinline) static int driver(int smash) {
    victim(0);                                     /* site A */
    if (stage++ > 0) {
        printf("{\"kind\":\"cet_smash\",\"result\":\"landed\",\"site_a\":\"0x%llx\",\"site_b\":\"0x%llx\"}\n",
               (unsigned long long)(uintptr_t)first_ret, (unsigned long long)(uintptr_t)second_ret);
        fflush(stdout);
        return 3;
    }
    victim(smash);                                 /* site B: smashed -> returns to site A */
    return 0;
}

static volatile intptr_t g_sink;
CET_EXPORT intptr_t cet_leaf(intptr_t x) { g_sink += x; return x * 3 + 1; }
CET_EXPORT intptr_t cet_caller(intptr_t x) { return cet_leaf(x) * 2 + (g_sink & 1); }

/* Offset of cet_caller's `call cet_leaf` (E8 rel32), -1 if the compiler did not emit one. */
static int call_offset(void) {
    const unsigned char *p = (const unsigned char *)cet_caller;
    for (int i = 0; i < 48; ++i) {
        if (p[i] != 0xE8) continue;
        int32_t rel; memcpy(&rel, p + i + 1, 4);
        if ((uintptr_t)(p + i + 5 + rel) == (uintptr_t)cet_leaf) return i;
    }
    return -1;
}

static int wait_gate(void) {
    printf("{\"kind\":\"waiting\",\"pid\":%lu}\n", GetCurrentProcessId());
    fflush(stdout);
    char b; DWORD n = 0;
    return ReadFile(GetStdHandle(STD_INPUT_HANDLE), &b, 1, &n, NULL) && n == 1;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "clean";
    printf("{\"kind\":\"cet_smash\",\"mode\":\"%s\",\"ssp\":%llu}\n", mode, (unsigned long long)rdssp());
    fflush(stdout);
    if (!strcmp(mode, "calls")) {
        const int n = argc > 2 ? atoi(argv[2]) : 10;
        int wait = 0, smash = 0;
        for (int i = 3; i < argc; ++i) {
            if (!strcmp(argv[i], "--wait")) wait = 1;
            else if (!strcmp(argv[i], "--smash")) smash = 1;
        }
        if (wait && !wait_gate()) return 4;
        intptr_t sum = 0;
        int live = 0;
        for (int i = 0; i < n; ++i) {
            sum += cet_leaf(i) + cet_caller(i);
            live += rdssp() != 0;
        }
        printf("{\"kind\":\"cet_calls\",\"n\":%d,\"sum\":%lld,\"ssp_live\":%d,\"call_off\":%d}\n", n, (long long)sum, live,
               call_offset());
        fflush(stdout);
        return smash ? driver(1) : 0;
    }
    const int rc = driver(!strcmp(mode, "smash"));
    printf("{\"kind\":\"cet_smash\",\"result\":\"%s\"}\n", rc ? "landed" : "clean");
    fflush(stdout);
    return rc;
}
