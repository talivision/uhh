// Same source in every backend (lifecycle_driver for breakpoint/hw, probe_api_agent.dll inline).
#include "lifecycle_callbacks.h"

extern "C" void lc_slow_cb(probe_context *c) {
    uint64_t ms = get_func_arg(c, 0) & 0xFFFFFFFFu, ret = 0;
    if (!call_original(c, 1, &ret)) { send_log(c, "slow ms=%llu call_original refused", (unsigned long long)ms); return; }
    send_log(c, "slow ms=%llu ret=%llu", (unsigned long long)ms, (unsigned long long)(ret & 0xFFFFFFFFu));
    return_from(c, ret, 0);           // __cdecl on x86: the caller pops
}
