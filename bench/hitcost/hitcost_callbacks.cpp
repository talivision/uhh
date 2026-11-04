// Per-method cost: the callback performs exactly one context operation (chosen by
// config), so ns/hit(method) - ns/hit(empty) is that operation's cost on that backend.
#include "probe_api.h"
#include <stdint.h>

struct hitcost_config { uint32_t method; uint32_t pad; };
enum { M_EMPTY, M_GET_REG, M_GET_ARG, M_GET_MEM, M_SET_MEM, M_SEND_LOG, M_SEND_LOG_STACK, M_CALL_FUNC };

static volatile uint64_t g_sink;

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
    default: break;
    }
}
