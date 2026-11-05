/* hunt_dll -- loaded/unloaded in a loop by hunt_target's "dll" scenario. DllMain reads
   (through the target's exported hunt_read) on process/thread attach/detach; HuntWork is
   a probe site of its own, so a probe lives in a module that keeps unloading. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static void (*g_read)(void);

__declspec(dllexport) __declspec(noinline) void HuntWork(void (*read)(void), volatile LONG *work) {
    InterlockedIncrement(work);
    read();
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r; (void)reason;
    if (!g_read) g_read = (void (*)(void))GetProcAddress(GetModuleHandleA(NULL), "hunt_read");
    if (g_read) g_read();
    return TRUE;
}
