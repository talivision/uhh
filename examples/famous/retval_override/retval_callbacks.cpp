// Return-value override (Frida: Interceptor.attach(GetTickCount, { onLeave(r) {
// r.replace(ptr(0x1337beef)); } }) -- the anti-timing-check bypass).
//
//   kernel32!GetTickCount entry   called from the main module?  make sure that call site
//                                 has a return probe (armed before this call returns)
//   <call site> (return)          set_reg(AX, forced value)
//
// UHH has no onLeave flag on purpose: the return is an ordinary instruction in the
// caller, probed like any other. Scoped to the program's own call sites
// (Process.mainModule), so system DLLs that call GetTickCount are left alone.
#include "../common/famous_common.h"

UHH_SHARED famous_module g_tick_module{};
UHH_SHARED famous_site g_tick_sites[3]{};
UHH_SHARED std::atomic<uint64_t> g_tick_value{0};
UHH_SHARED std::atomic<int64_t> g_tick_overrides{0};

FAMOUS_EXPORT void famous_tick_on_return(probe_context *c) {
    uint64_t real = get_reg(c, PROBE_REG_AX);
    uint64_t forced = g_tick_value.load(std::memory_order_acquire);
    if (set_reg(c, PROBE_REG_AX, forced)) {
        int64_t n = g_tick_overrides.fetch_add(1, std::memory_order_relaxed) + 1;
        if (n <= 3) send_log(c, "tick-override real=%llu forced=0x%llx", (unsigned long long)(uint32_t)real,
                             (unsigned long long)forced);
    }
}

// GetTickCount(void)
FAMOUS_EXPORT void famous_tick_on_entry(probe_context *c) {
    uint64_t ret = famous_return_address(c);
    if (!famous_in_main(c, g_tick_module, ret)) return;
    if (const famous_config *cfg = famous_cfg(c)) g_tick_value.store(cfg->value, std::memory_order_release);
    famous_arm_return(c, g_tick_sites, 3, ret, famous_tick_on_return, famous_ret_flags(c));
}
