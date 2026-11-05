#pragma once
// Callbacks shared by gated_config (launch) and uhh_attach (attach). One source,
// compiled into the driver (breakpoint / hw: callbacks run in the controller) AND into
// probe_api_agent.dll (inline: callbacks run inside the target, found by export name).
#include "probe_api.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define PROBE_EXAMPLE_EXPORT __declspec(dllexport)
#else
#define PROBE_EXAMPLE_EXPORT
#endif

/* Config of the read probe. log=0: count hits only (no logs). Filters (all optional, a read
   must pass every one that is set): pid != 0 -- only reads through a handle opened
   (ntdll!NtOpenProcess) for that pid; nranges != 0 -- only reads whose address lies in one
   of the [base, base+size) ranges. */
#define READ_LOG_MAX_RANGES 8
struct read_range { uint64_t base, size; };
struct read_log_config {
    uint64_t cookie;          /* READ_LOG_COOKIE */
    uint32_t log, nranges;
    uint64_t pid;
    struct read_range ranges[READ_LOG_MAX_RANGES];
};
#define READ_LOG_COOKIE 0x7265616473697465ULL

/* Drivers: "BASE:SIZE" (decimal or 0x-hex) -> one more address range; 0 if malformed or full. */
inline int add_read_range(struct read_log_config *cfg, const char *text) {
    char *colon = NULL, *end = NULL;
    uint64_t base = strtoull(text, &colon, 0);
    if (!colon || *colon != ':' || cfg->nranges >= READ_LOG_MAX_RANGES) return 0;
    uint64_t size = strtoull(colon + 1, &end, 0);
    if (!size || *end) return 0;
    cfg->ranges[cfg->nranges].base = base; cfg->ranges[cfg->nranges].size = size; ++cfg->nranges;
    return 1;
}

/* Drivers: "breakpoint" | "hw" | "inline" -> PROBE_* flag, 0 if unknown. */
inline uint32_t backend_flag(const char *name) {
    return !strcmp(name, "breakpoint") ? PROBE_BREAKPOINT : !strcmp(name, "hw") ? PROBE_HW
         : !strcmp(name, "inline") ? PROBE_INLINE : 0u;
}

extern "C" {
/* configparse.dll!ParseConfig+0x16: the parsed flag is in EAX; 0 -> 1. */
PROBE_EXAMPLE_EXPORT void enable_reads(probe_context *);
/* configparse.dll!ParseConfig+0x18: the flag is already stored at [BX]; rewrite it 0 -> 1. */
PROBE_EXAMPLE_EXPORT void enable_reads_mem(probe_context *);
/* ntdll!NtOpenProcess entry: remember (pid, out-handle pointer). */
PROBE_EXAMPLE_EXPORT void track_open_process(probe_context *);
/* ntdll!NtOpenProcess entry, one callback: call_original, record handle -> pid -> name,
   return_from with the real status (gated_config --open-mode call). */
PROBE_EXAMPLE_EXPORT void track_open_process_call(probe_context *);
/* ntdll!NtReadVirtualMemory entry: log handle/pid/addr/size. */
PROBE_EXAMPLE_EXPORT void log_read(probe_context *);
}
