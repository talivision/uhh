/* twin.dll -- built twice from this source (TWIN_VALUE 0x101 and 0x202) into twin_a\ and
   twin_b\, both at one fixed base (no ASLR): hunt_target's "twin" scenario loads one, unloads
   it and loads the other, which lands at the SAME base with DIFFERENT code at the same RVA. A
   probe on TwinWork re-arms in the new image and must run the NEW instruction, never a copy of
   the old one (regress hunt-twin-*). (Not 1: DllMain's `return TRUE` is the same code, and
   identical-code folding would merge the two -- linked /OPT:NOICF as well.) */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
__declspec(dllexport) __declspec(noinline) int TwinWork(void) { return TWIN_VALUE; }
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) { (void)h; (void)r; (void)p; return TRUE; }
