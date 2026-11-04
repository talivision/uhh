#pragma once
#include "probe_api.h"
#define DYNWATCH_EXPORT __declspec(dllexport)
extern "C" {
DYNWATCH_EXPORT void dynwatch_on_malloc(probe_context *c);
DYNWATCH_EXPORT void dynwatch_on_return(probe_context *c);
DYNWATCH_EXPORT void dynwatch_on_write(probe_context *c);
long dynwatch_watch_hits(void);
long dynwatch_arms(void);
long dynwatch_returns(void);
}
