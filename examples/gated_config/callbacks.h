#pragma once
#include "probe_api.h"

#ifdef _WIN32
#define PROBE_EXAMPLE_EXPORT __declspec(dllexport)
#else
#define PROBE_EXAMPLE_EXPORT
#endif

struct read_log_config { uint64_t cookie; uint32_t log; uint32_t reserved; };   /* log=0: count only */

extern "C" {
PROBE_EXAMPLE_EXPORT void enable_reads(probe_context *);
PROBE_EXAMPLE_EXPORT void log_read(probe_context *);
uint64_t gated_override_count(void);
}
