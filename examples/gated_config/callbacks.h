#pragma once
#include "probe_api.h"

#ifdef _WIN32
#define PROBE_EXAMPLE_EXPORT __declspec(dllexport)
#else
#define PROBE_EXAMPLE_EXPORT
#endif

/* log=0: count hits only. filter=1: log only reads of the SELECTED child's handle inside
   the selected range -- values learned at runtime by learn_target (below). */
struct read_log_config { uint64_t cookie; uint32_t log; uint32_t filter; };

extern "C" {
PROBE_EXAMPLE_EXPORT void enable_reads(probe_context *);
PROBE_EXAMPLE_EXPORT void log_read(probe_context *);
PROBE_EXAMPLE_EXPORT void learn_target(probe_context *);
uint64_t gated_override_count(void);
}
