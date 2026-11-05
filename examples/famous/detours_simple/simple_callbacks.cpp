// Detours "simple" sample, the UHH way: see every SleepEx and the time it asked for.
// This ONE source is compiled into the driver (breakpoint / hw callbacks run in the
// controller) and into probe_api_agent.dll (inline callbacks run inside the target).
//
// Detours keeps a global counter in the injected DLL and prints it at DLL_PROCESS_DETACH.
// A UHH callback's globals live wherever the callback runs (controller or target), so the
// per-call facts go into the log instead -- logs are never dropped, so the log IS the
// counter, identical under every backend. The config tells the two probes apart.
#include "simple_callbacks.h"

extern "C" DSIMPLE_EXPORT void dsimple_on_sleep(probe_context *c) {
    const dsimple_config *cfg = static_cast<const dsimple_config *>(get_config(c));
    const unsigned ms = static_cast<unsigned>(get_func_arg(c, 0));
    if (cfg && cfg->which == DSIMPLE_SLEEP) {
        send_log(c, "Sleep(%u)", ms);
    } else {
        const unsigned alertable = static_cast<unsigned>(get_func_arg(c, 1));
        send_log(c, "SleepEx(%u, %u)", ms, alertable);
    }
}
