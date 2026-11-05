// Edge-case hunter callbacks: gated_config's log_read plus a stressor. Same source in
// every backend (driver for breakpoint/hw, probe_api_agent.dll for inline).
#include "hunt_callbacks.h"
#include <windows.h>

extern "C" void hunt_read_cb(probe_context *c) {
    auto *cfg = static_cast<const hunt_config *>(get_config(c));
    if (!cfg || cfg->read.cookie != READ_LOG_COOKIE) return;
    if (cfg->slow_ms) Sleep(cfg->slow_ms);
    if (cfg->mode & HUNT_MODE_TID) {
        uint64_t tid = 0;
        int ok = call_func(c, "kernel32.dll!GetCurrentThreadId", &tid, 0);
        send_log(c, "callfunc ok=%d tid=%llu", ok, (unsigned long long)tid);
    }
    if (cfg->mode & HUNT_MODE_RECURSE) {
        // Re-issue the very read this hit is about to make: the callee hits this same probe.
        uint64_t st = 0;
        int ok = call_func(c, "ntdll.dll!NtReadVirtualMemory", &st, 5, get_func_arg(c, 0), get_func_arg(c, 1),
                           get_func_arg(c, 2), get_func_arg(c, 3), (uint64_t)0);
        send_log(c, "recurse ok=%d status=0x%llx", ok, (unsigned long long)(uint32_t)st);
    }
    log_read(c);
}

extern "C" void hunt_work_cb(probe_context *c) {
    send_log(c, "work arg=0x%llx", (unsigned long long)get_func_arg(c, 1));
}
