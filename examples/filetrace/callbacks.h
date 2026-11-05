#pragma once
// Callbacks of filetrace. One source, compiled into the driver (breakpoint / hw: callbacks
// run in the controller) AND into probe_api_agent.dll (inline: they run inside the target,
// found by export name). The handle -> path map is UHH_SHARED, so the probes may mix backends.
#include "probe_api.h"
#include <string.h>

/* Probe config (all probes): log only paths containing `filter` (empty = everything). */
struct filetrace_config {
    uint64_t cookie;          /* FILETRACE_COOKIE */
    char filter[128];
};
#define FILETRACE_COOKIE 0x6563617274656c69ULL

/* Drivers: "breakpoint" | "hw" | "inline" -> PROBE_* flag, 0 if unknown. */
inline uint32_t filetrace_backend(const char *name) {
    return !strcmp(name, "breakpoint") ? PROBE_BREAKPOINT : !strcmp(name, "hw") ? PROBE_HW
         : !strcmp(name, "inline") ? PROBE_INLINE : 0u;
}

extern "C" {
/* ntdll!NtCreateFile: runs the open (call_original), logs path/access/status/handle, maps
   handle -> path, returns the real status (return_from). */
__declspec(dllexport) void ft_on_create(probe_context *);
/* ntdll!NtWriteFile entry: logs path (from the map), handle, length, offset. */
__declspec(dllexport) void ft_on_write(probe_context *);
/* ntdll!NtClose entry: forget the handle (values are reused). */
__declspec(dllexport) void ft_on_close(probe_context *);
}
