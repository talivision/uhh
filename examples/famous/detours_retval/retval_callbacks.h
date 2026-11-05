#pragma once
#include "probe_api.h"
#include <stdint.h>
#define DRETVAL_EXPORT __declspec(dllexport)

/* return_flags: the probe flags the entry callback uses for the return-site probes it adds
   (normally the entry probe's own backend). */
struct dretval_config { uint32_t return_flags; uint32_t log_entry; };   /* log_entry: also log each entry */

extern "C" DRETVAL_EXPORT void dretval_on_entry(probe_context *c);
extern "C" DRETVAL_EXPORT void dretval_on_return(probe_context *c);
