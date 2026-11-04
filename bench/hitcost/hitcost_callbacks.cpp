// Empty callback: measures the hook machinery only.
#include "probe_api.h"
extern "C" __declspec(dllexport) void hitcost_empty(probe_context *c) { (void)c; }
