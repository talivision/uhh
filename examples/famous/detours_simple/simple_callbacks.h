#pragma once
#include "probe_api.h"
#define DSIMPLE_EXPORT __declspec(dllexport)
enum { DSIMPLE_SLEEPEX = 0, DSIMPLE_SLEEP = 1 };
struct dsimple_config { int which; };
extern "C" DSIMPLE_EXPORT void dsimple_on_sleep(probe_context *c);
