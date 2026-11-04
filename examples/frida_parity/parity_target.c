#include <stdint.h>
#include <stddef.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* These assembly entry points keep the ABI pristine at each labelled probe site. */
int __stdcall ParityB1(uintptr_t handle, const char *name, size_t n);
int __stdcall ParityB2(uintptr_t handle, const char *name, size_t n);
int __stdcall ParityB4(uintptr_t handle, const char *name, size_t n);
int __stdcall ParityMidRegister(void);

static volatile uintptr_t seen_handle;
static volatile size_t seen_size;
static volatile char seen_name[64];

/* The entry sleds tail-jump here, so the original caller's return address and x86
   __stdcall arguments remain exactly where probe_arg expects them. */
__declspec(noinline) int __stdcall ParityObserve(uintptr_t handle, const char *name, size_t n) {
    size_t i, copy = n < sizeof(seen_name) - 1 ? n : sizeof(seen_name) - 1;
    seen_handle = handle;
    seen_size = n;
    for (i = 0; i < copy && name[i]; ++i) seen_name[i] = name[i];
    seen_name[i] = 0;
    return 1;
}

static int saw(uintptr_t handle, const char *name, size_t n) {
    size_t i = 0;
    if (seen_handle != handle || seen_size != n) return 0;
    while (name[i] && seen_name[i] == name[i]) ++i;
    return name[i] == 0 && seen_name[i] == 0;
}

int main(void) {
    static char original[sizeof("instrumented")] = "original";
    static char replacement[] = "instrumented";
    unsigned failures = 0;

    /* Wait for the controller's gate byte before calling the instrumented functions.
       The inline hooks are installed by an injected agent thread; the controller
       releases this gate only AFTER that install is confirmed, so without the wait the
       first calls would race the async install (the exact issue this would otherwise
       hit, and why the HW-backed B6 fired but the inline B1/B2/B4 did not). */
    { char gate; DWORD got = 0; HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
      if (in == INVALID_HANDLE_VALUE || !ReadFile(in, &gate, 1, &got, NULL) || got != 1) return 99; }

    ParityB1((uintptr_t)0x1234, "alpha", sizeof("alpha"));
    if (!saw((uintptr_t)0x1234, "alpha", sizeof("alpha"))) failures |= 1u;

    ParityB2((uintptr_t)0x2002, "hello-from-target", sizeof("hello-from-target"));
    if (!saw((uintptr_t)0x2002, "hello-from-target", sizeof("hello-from-target"))) failures |= 2u;

    /* B4 passes the replacement buffer as the handle. The probe redirects arg1 to
       it; this check proves the callee, not merely the callback, saw the new value. */
    ParityB4((uintptr_t)replacement, original, sizeof(replacement));
    if (!saw((uintptr_t)replacement, replacement, sizeof(replacement))) failures |= 4u;

    if (ParityMidRegister() != 42) failures |= 8u;
    return (int)failures;
}
