/* ctrl_dll: a DLL the controller-review target loads and unloads repeatedly.
   CtrlDllWork / CtrlDllCounter: an absolute-address probe and a watchpoint land inside it
   (finding 5); CtrlDllRecurse -> CtrlDllLeaf: stack logs captured inside it (finding 6). */
#include <windows.h>

__declspec(dllexport) volatile LONG CtrlDllCounter = 0;

__declspec(dllexport) __declspec(noinline) LONG CtrlDllWork(LONG x) {
    CtrlDllCounter += x;
    return CtrlDllCounter;
}

__declspec(dllexport) __declspec(noinline) LONG CtrlDllLeaf(LONG x) {
    return x * 3 + (LONG)GetCurrentThreadId() * 0;
}

__declspec(dllexport) __declspec(noinline) LONG CtrlDllRecurse(LONG depth) {
    volatile LONG keep = depth;            /* a real frame per level */
    LONG r = depth > 0 ? CtrlDllRecurse(depth - 1) : CtrlDllLeaf(keep);
    return r + keep - depth;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) { (void)h; (void)reason; (void)r; return TRUE; }

/* A foreign-module export colliding with the callbacks module's name (api-foreign). */
__declspec(dllexport) void ctrl_on_tock(void *c) { (void)c; }

/* 36 KiB of executable padding in its own (r-x) section right after .text: the loader maps both as
   ONE run of equal protection, so a stack capture's code reads here are in a run of 8+ pages -- the
   size at which the x86 agent asks QueryWorkingSetEx instead of VirtualQuery (cdx-codeprot must hold
   on that path too: a guarded / no-access page is never "valid"). */
#pragma section(".uhhpad", read, execute)
__declspec(allocate(".uhhpad")) __declspec(dllexport) const unsigned char CtrlDllPad[0x9000] = {0xCC};
