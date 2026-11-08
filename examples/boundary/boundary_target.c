// boundary target (regress `boundary-*`): code with a KNOWN instruction layout (the .asm next
// to it), so a probe can be aimed at an instruction boundary or into the middle of one.
//   BndFrame  a function with an extent (x64 .pdata via PROC FRAME, x86 PDB via ml /Zi) whose
//             body is reached only by a branch past an early `ret`;
//   BndLeaf   code with no extent at all (a bare exported label): only the symbol anchors it;
//   BndHidden a stray data byte after a `ret`, then code (BndHiddenReal) reached only by a
//             direct call from C: a linear sweep would decode the data byte over it.
// Prints ONE JSON row; the values never change under any probe (a refused probe included).
//   boundary_target [--iters K]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned BndFrame(unsigned x);
unsigned BndLeaf(void);
unsigned BndHidden(void);
unsigned BndHiddenReal(void);

int main(int argc, char **argv) {
    int iters = 100;
    for (int i = 1; i + 1 < argc; ++i)
        if (!strcmp(argv[i], "--iters")) iters = atoi(argv[i + 1]);
    unsigned frame = 0, leaf = 0, hidden = 0;
    for (int i = 0; i < iters; ++i) {
        frame += BndFrame(0) + BndFrame((unsigned)i + 1);
        leaf += BndLeaf();
        hidden += BndHidden() + BndHiddenReal();
    }
    // Expected: frame = sum((i+1)*0x12345678 + 0x9ABCDEF0), leaf = iters*0x11223344, hidden = iters*8 (mod 2^32).
    unsigned want_frame = 0;
    for (int i = 0; i < iters; ++i) want_frame += ((unsigned)i + 1) * 0x12345678u + 0x9ABCDEF0u;
    const int ok = frame == want_frame && leaf == (unsigned)iters * 0x11223344u && hidden == (unsigned)iters * 8u;
    printf("{\"kind\":\"target\",\"name\":\"boundary\",\"iters\":%d,\"frame\":%u,\"leaf\":%u,\"hidden\":%u,\"ok\":%s}\n",
           iters, frame, leaf, hidden, ok ? "true" : "false");
    fflush(stdout);
    return ok ? 0 : 3;
}
