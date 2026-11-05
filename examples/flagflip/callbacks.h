#pragma once
// Callback of flagflip. One source, compiled into the driver (breakpoint / hw) AND into
// probe_api_agent.dll (inline: it runs inside the target, found by export name).
#include "probe_api.h"
#include <string.h>

/* How the forced value is produced. FORCE: return_from(1) without running the original.
   MODIFY: run the original (call_original), log what it said, return 1 instead. */
enum flagflip_mode { FLAGFLIP_FORCE = 0, FLAGFLIP_MODIFY = 1 };
struct flagflip_config {
    uint64_t cookie;          /* FLAGFLIP_COOKIE */
    uint32_t mode;            /* flagflip_mode */
    char feature[60];         /* only the object whose name is this ("" = every object) */
};
#define FLAGFLIP_COOKIE 0x70696c66676c6166ULL

/* Drivers: "breakpoint" | "hw" | "inline" -> PROBE_* flag, 0 if unknown. */
inline uint32_t flagflip_backend(const char *name) {
    return !strcmp(name, "breakpoint") ? PROBE_BREAKPOINT : !strcmp(name, "hw") ? PROBE_HW
         : !strcmp(name, "inline") ? PROBE_INLINE : 0u;
}

extern "C" {
/* Entry of a `bool IsEnabled() const` virtual method: make it return true. */
__declspec(dllexport) void ff_force_enabled(probe_context *);
}
