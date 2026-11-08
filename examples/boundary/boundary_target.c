// boundary target (regress `boundary-*`): code with a KNOWN instruction layout (the .asm next
// to it), so a probe can be aimed at an instruction boundary or into the middle of one.
//   BndFrame  a function with an extent (x64 .pdata via PROC FRAME, x86 PDB via ml /Zi) whose
//             body is reached only by a branch past an early `ret`;
//   BndLeaf   code with no extent at all (a bare exported label): only the symbol anchors it;
//   BndHidden a stray data byte after a `ret`, then code (BndHiddenReal) reached only by a
//             direct call from C: a linear sweep would decode the data byte over it.
//   BndNoret  `call BndDie` (never returns), a data byte, then a block that is one `ret`, reached
//             only by an indirect jump: the call's fall-through decodes the data over that ret;
//   BndSmc    returns the imm32 of its own `mov eax, imm32`, which --smc rewrites (a data
//             watchpoint on that operand, inside an instruction in .text, is a valid site).
// Prints ONE JSON row; the values never change under any probe (a refused probe included).
//   boundary_target [--iters K]
//   boundary_target --smc K      rewrite BndSmc's immediate to 1..K, calling it after each
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned BndFrame(unsigned x);
unsigned BndLeaf(void);
unsigned BndHidden(void);
unsigned BndHiddenReal(void);
unsigned BndNoret(unsigned x);
unsigned BndSmc(void);
__declspec(noreturn) void BndDie(void) { abort(); }

static int run_smc(int k) {
    unsigned char *f = (unsigned char *)BndSmc;
    DWORD old = 0;
    if (!VirtualProtect(f, 16, PAGE_EXECUTE_READWRITE, &old)) return 4;
    int good = 0;
    for (int i = 1; i <= k; ++i) {
        *(volatile unsigned *)(f + 4) = (unsigned)i;        // the watched store
        FlushInstructionCache(GetCurrentProcess(), f, 16);
        good += BndSmc() == (unsigned)i;
    }
    *(volatile unsigned *)(f + 4) = 0;                       // (one more store: k + 1 writes)
    VirtualProtect(f, 16, old, &old);
    FlushInstructionCache(GetCurrentProcess(), f, 16);
    const int ok = good == k && BndSmc() == 0;
    printf("{\"kind\":\"target\",\"name\":\"boundary-smc\",\"writes\":%d,\"good\":%d,\"ok\":%s}\n",
           k + 1, good, ok ? "true" : "false");
    fflush(stdout);
    return ok ? 0 : 3;
}

int main(int argc, char **argv) {
    int iters = 100;
    for (int i = 1; i + 1 < argc; ++i) {
        if (!strcmp(argv[i], "--iters")) iters = atoi(argv[i + 1]);
        if (!strcmp(argv[i], "--smc")) return run_smc(atoi(argv[i + 1]));
    }
    unsigned frame = 0, leaf = 0, hidden = 0, noret = 0;
    for (int i = 0; i < iters; ++i) {
        frame += BndFrame(0) + BndFrame((unsigned)i + 1);
        leaf += BndLeaf();
        hidden += BndHidden() + BndHiddenReal();
        noret += BndNoret(0);
    }
    // Expected: frame = sum((i+1)*0x12345678 + 0x9ABCDEF0), leaf = iters*0x11223344, hidden = iters*8,
    // noret = iters*5 (mod 2^32).
    unsigned want_frame = 0;
    for (int i = 0; i < iters; ++i) want_frame += ((unsigned)i + 1) * 0x12345678u + 0x9ABCDEF0u;
    const int ok = frame == want_frame && leaf == (unsigned)iters * 0x11223344u && hidden == (unsigned)iters * 8u &&
                   noret == (unsigned)iters * 5u;
    printf("{\"kind\":\"target\",\"name\":\"boundary\",\"iters\":%d,\"frame\":%u,\"leaf\":%u,\"hidden\":%u,"
           "\"noret\":%u,\"ok\":%s}\n", iters, frame, leaf, hidden, noret, ok ? "true" : "false");
    fflush(stdout);
    return ok ? 0 : 3;
}
