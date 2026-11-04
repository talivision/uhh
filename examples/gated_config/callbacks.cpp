#include "callbacks.h"

static uint64_t overrides;

extern "C" void enable_reads(probe_context *c) {
    if (probe_reg(c, PROBE_REG_AX) == 0 && probe_set_reg(c, PROBE_REG_AX, 1))
        ++overrides;
}

extern "C" void log_read(probe_context *c) {
    auto *cfg = static_cast<const read_log_config *>(c->config);
    if (!cfg || cfg->cookie != 0x7265616473697465ULL) return;
    (void)probe_arg(c, 0); (void)probe_arg(c, 3);
    PROBE_LOG(c, "read");
}

extern "C" uint64_t gated_override_count(void) { return overrides; }
