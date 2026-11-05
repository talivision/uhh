#pragma once
// Lifecycle edge cases (examples/lifecycle, regress `lifecycle-*`): gated_config's callbacks
// (flag flip mid-function, NtOpenProcess map via call_original, NtClose, every read logged)
// plus one that blocks inside call_original. Compiled into lifecycle_driver (breakpoint/hw)
// and probe_api_agent.dll (inline).
#include "../gated_config/callbacks.h"

extern "C" {
/* lifecycle_target.exe!lc_slow(int ms): runs the original (it sleeps ms) through
   call_original, logs its result and returns it (return_from). */
PROBE_EXAMPLE_EXPORT void lc_slow_cb(probe_context *);
}
