#pragma once
// Callbacks of regtrace. One source, compiled into the driver (breakpoint / hw: callbacks
// run in the controller) AND into probe_api_agent.dll (inline: they run inside the target,
// found by export name). The key handle -> name map is UHH_SHARED: probes may mix backends.
#include "probe_api.h"
#include <string.h>

/* Probe config (all probes): log only keys whose name contains `filter` ("" = all). Keys
   the map does not know are always logged (as key=?), so a gap in the map is visible. */
struct regtrace_config {
    uint64_t cookie;          /* REGTRACE_COOKIE */
    char filter[128];
};
#define REGTRACE_COOKIE 0x6563617274676572ULL

/* Drivers: "breakpoint" | "hw" | "inline" -> PROBE_* flag, 0 if unknown. */
inline uint32_t regtrace_backend(const char *name) {
    return !strcmp(name, "breakpoint") ? PROBE_BREAKPOINT : !strcmp(name, "hw") ? PROBE_HW
         : !strcmp(name, "inline") ? PROBE_INLINE : 0u;
}

extern "C" {
/* ntdll!NtOpenKey / NtOpenKeyEx / NtCreateKey: run the open (call_original), map handle ->
   full key name, log it, return the real status (return_from). */
__declspec(dllexport) void rt_on_open_key(probe_context *);
__declspec(dllexport) void rt_on_open_key_ex(probe_context *);
__declspec(dllexport) void rt_on_create_key(probe_context *);
/* ntdll!NtQueryValueKey / NtSetValueKey entry: log key name and value name. */
__declspec(dllexport) void rt_on_query_value(probe_context *);
__declspec(dllexport) void rt_on_set_value(probe_context *);
/* ntdll!NtClose entry: forget the handle (values are reused). */
__declspec(dllexport) void rt_on_close(probe_context *);
}
