#pragma once
// Callbacks shared by gated_config (launch) and uhh_attach (attach). One source,
// compiled into the driver (breakpoint / hw: callbacks run in the controller) AND into
// probe_api_agent.dll (inline: callbacks run inside the target, found by export name).
#include "probe_api.h"
#include <string.h>

#ifdef _WIN32
#define PROBE_EXAMPLE_EXPORT __declspec(dllexport)
#else
#define PROBE_EXAMPLE_EXPORT
#endif

/* Config of the read probe. log=0: count hits only (no logs). filter=1: log only reads
   whose handle was opened (ntdll!NtOpenProcess) for `pid` and whose address is in
   [base, base+size). */
struct read_log_config {
    uint64_t cookie;          /* READ_LOG_COOKIE */
    uint32_t log, filter;
    uint64_t pid, base, size;
};
#define READ_LOG_COOKIE 0x7265616473697465ULL

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
/* ntdll!NtReadVirtualMemory entry: log handle/pid/addr/size. */
PROBE_EXAMPLE_EXPORT void log_read(probe_context *);
}
