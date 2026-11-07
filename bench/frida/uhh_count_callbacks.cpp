// The counting callback of bench/frida's count workload (uhh_count.cpp): exactly what the Frida
// count agents do -- read argument 0 (the handle) and argument 3 (the size), bump a counter.
// Built into uhh_count AND probe_api_agent (inline callbacks run from the agent DLL, by export
// name). The hit count the library reports is the number of callback runs.
#include "probe_api.h"
#include <atomic>

static std::atomic<uint64_t> g_calls{0};
static std::atomic<uint64_t> g_sink{0};

extern "C" __declspec(dllexport) void uhh_count_call(probe_context *c) {
    const uint64_t handle = get_func_arg(c, 0), size = get_func_arg(c, 3);
    g_sink.fetch_xor(handle ^ size, std::memory_order_relaxed);
    g_calls.fetch_add(1, std::memory_order_relaxed);
}
