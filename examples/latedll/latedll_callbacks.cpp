// ONE callback source for the latedll checks, built into latedll_driver (breakpoint/hw) and
// into probe_api_agent (inline). Every site is Site(id, i): one log per hit, naming the id.
#include "probe_api.h"

extern "C" __declspec(dllexport) void latedll_hit(probe_context *c) {
    send_log(c, "ld %llu", (unsigned long long)(get_func_arg(c, 0) & 0xFFFFFFFFu));
}
