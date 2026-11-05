#pragma once
// Callbacks of the edge-case hunter (examples/hunt). gated_config's own callbacks
// (track_open_process + log_read) do the work; these wrap log_read with the stressors.
// Compiled into hunt_driver (breakpoint/hw) and probe_api_agent.dll (inline).
#include "../gated_config/callbacks.h"

struct hunt_config {
    read_log_config read;     /* first: gated_config's log_read reads exactly this */
    uint32_t slow_ms;         /* sleep this long in every read callback */
    uint32_t mode;            /* HUNT_MODE_* bits */
};
enum {
    HUNT_MODE_TID     = 1u,   /* call_func(kernel32!GetCurrentThreadId) and log it */
    HUNT_MODE_RECURSE = 2u    /* call_func the probed NtReadVirtualMemory again with the same args */
};

extern "C" {
PROBE_EXAMPLE_EXPORT void hunt_read_cb(probe_context *);
PROBE_EXAMPLE_EXPORT void hunt_work_cb(probe_context *);
}
