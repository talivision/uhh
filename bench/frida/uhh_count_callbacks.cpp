// The counting callback of bench/frida's count workload (uhh_count.cpp): exactly what the Frida
// count agents do -- read argument 0 (the handle) and argument 3 (the size), bump a counter.
// Built into uhh_count AND probe_api_agent (inline callbacks run from the agent DLL, by export
// name). The hit count the library reports is the number of callback runs.
#include "probe_api.h"
#include <atomic>

// The same work as agents/count_cmodule.js's on_enter, operation for operation: a plain
// read-xor-write of a pointer-sized sink (`sink ^= handle ^ size`) and ONE 32-bit atomic add
// (g_atomic_int_add). This callback did two 64-bit atomic read-modify-writes per call -- on x86
// each a LOCK CMPXCHG8B retry loop, contended by the 8 workload threads -- which is more work
// than the Frida agent it is compared with, not a cost of the instrumentation.
static std::atomic<uint32_t> g_calls{0};
static std::atomic<uintptr_t> g_sink{0};

extern "C" __declspec(dllexport) void uhh_count_call(probe_context *c) {
    const uint64_t handle = get_func_arg(c, 0), size = get_func_arg(c, 3);
    g_sink.store(g_sink.load(std::memory_order_relaxed) ^ (uintptr_t)(handle ^ size), std::memory_order_relaxed);
    g_calls.fetch_add(1, std::memory_order_relaxed);
}
