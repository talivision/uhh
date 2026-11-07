// Per-method cost: the callback performs exactly one context operation (chosen by
// config), so ns/hit(method) - ns/hit(empty) is that operation's cost on that backend.
#include "probe_api.h"
#include <stdint.h>
#include <atomic>

struct hitcost_config { uint32_t method; uint32_t pad; };
enum { M_EMPTY, M_GET_REG, M_GET_ARG, M_GET_MEM, M_SET_MEM, M_SEND_LOG, M_SEND_LOG_STACK, M_CALL_FUNC,
       M_COUNTER_PLAIN, M_COUNTER_SHARED, M_CALL_ORIGINAL };

static volatile uint64_t g_sink;
// UHH_SHARED cost: the same atomic increment on a plain global and on a shared one. With
// HITCOST_SHARED the module opts in (breakpoint/hw callbacks then run from the controller's
// copy of the agent DLL); without it both methods hit the plain counter.
static std::atomic<uint64_t> g_plain_counter{0};
#if defined(HITCOST_SHARED)
UHH_SHARED std::atomic<uint64_t> g_shared_counter{0};
#else
static std::atomic<uint64_t> &g_shared_counter = g_plain_counter;
#endif

extern "C" __declspec(dllexport) void hitcost_empty(probe_context *c) {
    const hitcost_config *cfg = (const hitcost_config *)get_config(c);
    uint32_t m = cfg ? cfg->method : M_EMPTY;
    switch (m) {
    case M_GET_REG: g_sink += get_reg(c, PROBE_REG_CX); break;
    case M_GET_ARG: g_sink += get_func_arg(c, 0); break;
    case M_GET_MEM: { uint8_t b[64]; if (get_mem(c, get_reg(c, PROBE_REG_SP), b, sizeof(b))) g_sink += b[0]; break; }
    case M_SET_MEM: { uint64_t v = 0; uint64_t sp = get_reg(c, PROBE_REG_SP);
                      if (get_mem(c, sp, &v, sizeof(void *))) set_mem(c, sp, &v, sizeof(void *)); break; }
    case M_SEND_LOG: send_log(c, "hit %llu", (unsigned long long)get_func_arg(c, 0)); break;
    case M_SEND_LOG_STACK: send_log_stack(c, "hit"); break;
    case M_CALL_FUNC: { uint64_t r = 0; call_func(c, "kernel32.dll!GetCurrentProcessId", &r, 0); g_sink += r; break; }
    case M_COUNTER_PLAIN: g_plain_counter.fetch_add(1, std::memory_order_relaxed); break;
    case M_COUNTER_SHARED: g_shared_counter.fetch_add(1, std::memory_order_relaxed); break;
    // Detours-style replacement: run the original now and return its result (hit_site is
    // cdecl with one argument: x86 caller pops, so return_from nargs = 0).
    case M_CALL_ORIGINAL: { uint64_t r = 0; if (call_original(c, 1, &r)) return_from(c, r, 0); break; }
    default: break;
    }
}
