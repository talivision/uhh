/* Loaded LATE, by a worker thread of edge_target (never by the main thread). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static volatile LONG_PTR g_late_sink, g_next_sink;

/* next: the address of LateNext, so a callback can add a probe there by address. */
__declspec(dllexport) __declspec(noinline) LONG_PTR LateSite(LONG_PTR i, void *next) {
    g_late_sink += i + (LONG_PTR)next;
    return g_late_sink ^ i;
}

__declspec(dllexport) __declspec(noinline) LONG_PTR LateNext(LONG_PTR i) {
    g_next_sink += i;
    return g_next_sink ^ i;
}
