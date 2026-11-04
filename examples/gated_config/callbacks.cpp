#include "callbacks.h"
#include <cstring>

static uint64_t overrides;

extern "C" void enable_reads(probe_context *c) {
    if (get_reg(c, PROBE_REG_AX) == 0 && set_reg(c, PROBE_REG_AX, 1))
        ++overrides;
}

/* What learn_target discovers at runtime. Both probes use the same backend, so these
   live in the same address space (controller for breakpoint/hw, target for inline). */
static volatile uint64_t g_selected, g_range_start, g_range_size;
static volatile long g_learned;

/* probe_app announces its selected handle and range with one printf before the
   workload starts. Probe the CRT's formatter, recognise that line, and pull the values
   straight out of the call's va_list -- runtime state no static config could hold. */
extern "C" void learn_target(probe_context *c) {
#if defined(_WIN64)
    uint64_t fmt = get_func_arg(c, 2), va = get_func_arg(c, 4);   /* (options, stream, format, locale, va_list) */
#else
    uint64_t fmt = get_func_arg(c, 3), va = get_func_arg(c, 5);   /* 64-bit options takes two x86 slots */
#endif
    static const char want[] = "{\"kind\":\"waiting\",\"pid\"";
    char head[sizeof(want)] = {0};
    if (!fmt || !get_mem(c, fmt, head, sizeof(head) - 1) || std::memcmp(head, want, sizeof(want) - 1)) return;
    /* "%lu %llu %llu %llu %llu": pid, selected, decoy, range_start, range_size */
#if defined(_WIN64)
    uint64_t v[5] = {0};
    if (!get_mem(c, va, v, sizeof(v))) return;
    g_selected = v[1]; g_range_start = v[3]; g_range_size = v[4];
#else
    unsigned char b[36] = {0};
    if (!get_mem(c, va, b, sizeof(b))) return;
    uint64_t sel, start, size;
    std::memcpy(&sel, b + 4, 8); std::memcpy(&start, b + 20, 8); std::memcpy(&size, b + 28, 8);
    g_selected = sel; g_range_start = start; g_range_size = size;
#endif
    g_learned = 1;
    PROBE_LOG(c, "learned selected=%llu range=[%llu,+%llu)", (unsigned long long)g_selected,
              (unsigned long long)g_range_start, (unsigned long long)g_range_size);
}

extern "C" void log_read(probe_context *c) {
    auto *cfg = static_cast<const read_log_config *>(get_config(c));
    if (!cfg || cfg->cookie != 0x7265616473697465ULL) return;
    uint64_t handle = get_func_arg(c, 0), addr = get_func_arg(c, 1), size = get_func_arg(c, 3);
    if (cfg->filter) {
        if (!g_learned || handle != g_selected || addr < g_range_start || addr >= g_range_start + g_range_size) return;
    }
    if (cfg->log) PROBE_LOG(c, "read handle=%llu addr=0x%llx size=%llu", (unsigned long long)handle,
                            (unsigned long long)addr, (unsigned long long)size);
}

extern "C" uint64_t gated_override_count(void) { return overrides; }
