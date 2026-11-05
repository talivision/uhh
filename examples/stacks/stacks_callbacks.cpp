// ONE callback for every site, backend and architecture: log the stack at the hit.
// Compiled into the driver (breakpoint/hw) and the agent DLL (inline).
#include "probe_api.h"

struct stk_config { char name[16]; };

extern "C" __declspec(dllexport) void stk_on_site(probe_context *c) {
    const stk_config *k = (const stk_config *)get_config(c);
    send_log_stack(c, "stack %s", k ? k->name : "?");
}
