#pragma once
#include "probe.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef int (*agent_start_fn)(const char *, void *, void *, const probe_config *);
typedef int (*agent_stop_fn)(probe_stats *);
#ifdef __cplusplus
}
#endif
