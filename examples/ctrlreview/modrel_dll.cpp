// Target-only exports: the controller must never resolve through its own DLL copy.
#include <windows.h>
extern "C" __declspec(dllexport) __declspec(noinline) int ModValue(int x) { volatile int value = x; return value + 7; }
extern "C" __declspec(dllexport) int (*ModRelocation)(int) = ModValue;
#if defined(_WIN64)
extern "C" int ModSys(unsigned long);
#else
extern "C" __declspec(dllexport) __declspec(noinline) int ModSys(unsigned long x) { return (int)x; }
#endif
