// ONE callback source, run unchanged under every backend (breakpoint, hw, inline) and
// both architectures. Each check logs "ok <name>" or "FAIL <name> ...": the suite
// requires the full set of oks for every backend x arch.
#include "probe_api.h"
#include <stdint.h>

#define CONF_EXPORT extern "C" __declspec(dllexport)

struct conf_config { uint64_t cookie; };

static void check(probe_context *c, bool ok, const char *name) {
    if (ok) send_log(c, "ok %s", name); else send_log(c, "FAIL %s", name);
}

// set_reg(SP) at conformance_target!SpSite+3: move the stack pointer down 32 bytes; the
// site returns how far it moved (32 on every backend).
CONF_EXPORT void conf_move_sp(probe_context *c) {
    set_reg(c, PROBE_REG_SP, get_reg(c, PROBE_REG_SP) - 32);
}

struct later_config { uint64_t cookie; };
CONF_EXPORT void conf_on_later(probe_context *c) {
    const later_config *k = (const later_config *)get_config(c);
    if (k && k->cookie == 0x1A7E1A7E1A7E1A7Eull) send_log(c, "ok later-hit");      // config arrived with the add
    else send_log(c, "FAIL later-hit config");
}
CONF_EXPORT void conf_on_once_hw(probe_context *c) { send_log(c, "ok once-hw-hit"); }
CONF_EXPORT void conf_on_watch(probe_context *c) { send_log(c, "ok watch-hit"); }

CONF_EXPORT void conf_on_site(probe_context *c) {
    static volatile long first = 1;
    // get_config
    const conf_config *cfg = (const conf_config *)get_config(c);
    check(c, cfg && cfg->cookie == 0xC0F1C0F1C0F1C0F1ull, "get_config");
    // get_func_arg: 1..5 and a pointer
    bool args = get_func_arg(c, 0) == 1 && get_func_arg(c, 1) == 2 && get_func_arg(c, 2) == 3 &&
                get_func_arg(c, 3) == 4 && get_func_arg(c, 4) == 5 && get_func_arg(c, 5) != 0;
    check(c, args, "get_func_arg");
    // get_mem: the buffer holds 1..64
    uint8_t buf[16] = {0};
    uint64_t p = get_func_arg(c, 5);
    bool mem = get_mem(c, p, buf, sizeof(buf));
    for (int i = 0; mem && i < 16; ++i) mem = i == 8 || buf[i] == (uint8_t)(i + 1);   // [8] is reset per call
    check(c, mem, "get_mem");
    // set_mem: marker the target verifies after the call
    uint8_t marker = 0xA5;
    check(c, set_mem(c, p + 8, &marker, 1) != 0, "set_mem");
    // get_reg / set_reg: SP sane; rewrite arg 0 (1 -> 7) the portable way per ABI
    uint64_t sp = get_reg(c, PROBE_REG_SP);
    check(c, sp != 0 && (sp & 3) == 0, "get_reg");
#if defined(_WIN64)
    bool rewrote = set_reg(c, PROBE_REG_CX, 7) && get_reg(c, PROBE_REG_CX) == 7;
#else
    uint32_t seven = 7;              /* arg 0 is the pointer-sized slot at [esp+4] */
    bool rewrote = set_mem(c, sp + 4, &seven, 4) && get_func_arg(c, 0) == 7;
#endif
    check(c, rewrote, "set_reg/arg-rewrite");
    // call_func: a target function with two args
    uint64_t r = 0;
    check(c, call_func(c, "conformance_target.exe!conf_mul", &r, 2, (uint64_t)6, (uint64_t)7) && r == 42, "call_func");
    // ...and a FORWARDED export (kernel32 -> ntdll), resolved the same way on every backend.
    uint64_t cpu = ~0ull;
    check(c, call_func(c, "kernel32.dll!GetCurrentProcessorNumber", &cpu, 0) && cpu < 4096, "call_func-forwarded");
    // send_log_stack: frame 1 must exist (the caller)
    send_log_stack(c, "stack conf_site");
    // control plane from the callback, once
    if (first) {
        first = 0;
        probe_session *s = get_session(c);
        check(c, s != nullptr, "get_session");
        later_config k{0x1A7E1A7E1A7E1A7Eull};
        check(c, probe_add_symbol_cfg(s, "conformance_target.exe!conf_later", conf_on_later, PROBE_BREAKPOINT,
                                      &k, sizeof(k)) == 1, "probe_add_symbol");
        uint64_t watched = 0;
        bool got = call_func(c, "conformance_target.exe!conf_watch_addr", &watched, 0) && watched;
        check(c, got && probe_watch(s, watched, conf_on_watch, PROBE_WATCH_WRITE) == 1, "probe_watch");
        uint64_t ret = 0;
        get_mem(c, sp, &ret, sizeof(void *));               // our return address: a valid code address
        check(c, probe_add_address(s, ret, conf_on_once_hw, PROBE_HW | PROBE_ONCE) == 1, "probe_add_address");
    }
}
