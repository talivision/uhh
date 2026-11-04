// This source is compiled unchanged into the controller executable and the agent DLL.
// Its state consequently lives beside the callback: in the driver for breakpoint/HW
// probes, and in the target's agent for inline probes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#include "memstress_callbacks.h"

namespace {

alignas(8) volatile LONG64 g_calls;
alignas(8) volatile LONG64 g_reads_ok;
alignas(8) volatile LONG64 g_reads_bad;
alignas(8) volatile LONG64 g_writes;
alignas(8) volatile LONG64 g_cross_ok;
alignas(8) volatile LONG64 g_fault_reads_failed_closed;
alignas(8) volatile LONG64 g_ro_writes_failed_closed;

static uint8_t value_f(uint32_t thread, uint32_t iter, uint32_t index) {
    return static_cast<uint8_t>(thread * 37u + iter * 17u + index * 13u +
                                ((iter >> 8) ^ (index * 3u)));
}

static uint8_t value_g(uint32_t thread, uint32_t iter, uint32_t index) {
    return static_cast<uint8_t>(value_f(thread, iter, index) ^ 0xa5u);
}

static LONG64 atomic_load(volatile LONG64 *value) {
    return InterlockedCompareExchange64(value, 0, 0);
}

static void log_summary(probe_context *c) {
    send_log(c,
             "memstress reads_ok=%lld reads_bad=%lld writes=%lld cross_ok=%lld "
             "fault_reads_failed_closed=%lld ro_writes_failed_closed=%lld",
             static_cast<long long>(atomic_load(&g_reads_ok)),
             static_cast<long long>(atomic_load(&g_reads_bad)),
             static_cast<long long>(atomic_load(&g_writes)),
             static_cast<long long>(atomic_load(&g_cross_ok)),
             static_cast<long long>(atomic_load(&g_fault_reads_failed_closed)),
             static_cast<long long>(atomic_load(&g_ro_writes_failed_closed)));
}

static void run_throughput_reads(probe_context *c, uint64_t address, uint32_t repeats) {
    static thread_local uint8_t scratch[65536];
    static const size_t sizes[] = {1u, 8u, 64u, 4096u, 65536u};
    for (uint32_t repeat = 0; repeat < repeats; ++repeat) {
        for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
            (void)get_mem(c, address, scratch, sizes[i]);
        }
    }
}

} // namespace

extern "C" MEMSTRESS_EXPORT void ms_on_site(probe_context *c) {
    const uint32_t thread = static_cast<uint32_t>(get_func_arg(c, 0));
    const uint32_t iter = static_cast<uint32_t>(get_func_arg(c, 1));
    const uint64_t buffer_address = get_func_arg(c, 2);
    const uint64_t cross_address = get_func_arg(c, 3);
    const uint64_t noaccess_address = get_func_arg(c, 4);
    const uint64_t readonly_address = get_func_arg(c, 5);
    const uint32_t offset = (iter * 61u) % (65536u - 256u);
    const uint64_t window_address = buffer_address + offset;

    uint8_t window[256];
    bool read_ok = get_mem(c, window_address, window, sizeof(window)) != 0;
    for (uint32_t i = 0; read_ok && i < static_cast<uint32_t>(sizeof(window)); ++i) {
        read_ok = window[i] == value_f(thread, iter, i);
    }
    if (read_ok) {
        (void)InterlockedIncrement64(&g_reads_ok);
    } else {
        (void)InterlockedIncrement64(&g_reads_bad);
    }

    uint8_t marker[32];
    for (uint32_t i = 0; i < static_cast<uint32_t>(sizeof(marker)); ++i) {
        marker[i] = value_g(thread, iter, i + 64u);
    }
    if (set_mem(c, window_address + 64u, marker, sizeof(marker)) != 0) {
        (void)InterlockedIncrement64(&g_writes);
    }

    uint8_t cross[64];
    bool cross_succeeded = get_mem(c, cross_address, cross, sizeof(cross)) != 0;
    if (cross_succeeded) {
        for (size_t i = 0; i < sizeof(cross); ++i) cross[i] = static_cast<uint8_t>(~cross[i]);
        cross_succeeded = set_mem(c, cross_address, cross, sizeof(cross)) != 0;
    }
    if (cross_succeeded) (void)InterlockedIncrement64(&g_cross_ok);

    uint8_t guard_data[64] = {};
    if (get_mem(c, noaccess_address, guard_data, sizeof(guard_data)) == 0) {
        (void)InterlockedIncrement64(&g_fault_reads_failed_closed);
    }
    for (size_t i = 0; i < sizeof(guard_data); ++i) guard_data[i] = 0x3cu;
    if (set_mem(c, readonly_address, guard_data, sizeof(guard_data)) == 0) {
        (void)InterlockedIncrement64(&g_ro_writes_failed_closed);
    }

    const memstress_config *cfg = static_cast<const memstress_config *>(get_config(c));
    uint32_t throughput_repeats = 0;
    uint64_t expected_calls = 0;
    if (cfg != nullptr && cfg->version == MEMSTRESS_CONFIG_VERSION) {
        if ((cfg->flags & MEMSTRESS_CONFIG_THROUGHPUT) != 0) {
            throughput_repeats = cfg->throughput_repeats;
        }
        expected_calls = cfg->expected_calls;
    }
    if (throughput_repeats != 0) run_throughput_reads(c, buffer_address, throughput_repeats);

    const LONG64 calls = InterlockedIncrement64(&g_calls);
    const bool periodic = (calls & 4095) == 0;
    const bool final_call = expected_calls != 0 && static_cast<uint64_t>(calls) == expected_calls;
    if (periodic || final_call) log_summary(c);
}
