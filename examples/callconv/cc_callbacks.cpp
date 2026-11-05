// Calling-convention probes (regress `callconv-*`): ONE callback for every ccfix.dll function
// and every backend (built into cc_driver for breakpoint/hw and into the agent for inline).
// At the function's entry it checks get_func_arg / get_reg against what cc_target passed
// (what index i means per convention: see probe_api.h, get_func_arg), then by mode:
//   wrap      call_original (its *ret checked for integer results) + return_from(r, pop)
//   replace   return_from(replacement, pop) without running the body (floating-point
//             results: no return_from -- it cannot set ST0/XMM0 -- the call falls through)
//   wrongpop  call_original + return_from(r, a WRONG x86 stack-argument count)
// Logs "cc hit NAME" once per hit and "cc FAIL NAME ..." for every mismatch.
#include "probe_api.h"
#include "cc_shared.h"
#include <string.h>

struct cc_cfg { uint32_t mode, id; };

#define CC_CB extern "C" __declspec(dllexport)

static bool arg_is(probe_context *c, const char *name, size_t i, uint64_t want) {
    const uint64_t got = get_func_arg(c, i);
    if (got == want) return true;
    send_log(c, "cc FAIL %s get_func_arg(%u)=0x%llx want 0x%llx", name, (unsigned)i,
             (unsigned long long)got, (unsigned long long)want);
    return false;
}
static bool reg_is(probe_context *c, const char *name, enum probe_register r, uint64_t want) {
    const uint64_t got = get_reg(c, r);
    if (got == want) return true;
    send_log(c, "cc FAIL %s reg%d=0x%llx want 0x%llx", name, (int)r, (unsigned long long)got, (unsigned long long)want);
    return false;
}
static uint32_t bits(float f) { uint32_t u; memcpy(&u, &f, 4); return u; }
static uint64_t bits(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }
static bool mem32_is(probe_context *c, const char *name, uint64_t addr, const int32_t *want, int n) {
    int32_t got[4] = {0};
    if (n > 4 || !get_mem(c, addr, got, 4 * (size_t)n) || memcmp(got, want, 4 * (size_t)n)) {
        send_log(c, "cc FAIL %s memory at 0x%llx", name, (unsigned long long)addr);
        return false;
    }
    return true;
}

// The arguments as the probe sees them at entry.
static void check_args(probe_context *c, int id) {
    const char *nm = CC_FNS[id].name;
#if defined(_WIN64)
    // x64: index i = the i-th argument (RCX, RDX, R8, R9, then [RSP+8+8i]); a float/double in
    // the first four lives in XMMi instead (not readable: get_func_arg(i) is then whatever
    // the integer register holds).
    switch (id) {
    case CC_CDECL3: for (int i = 0; i < 3; ++i) arg_is(c, nm, i, i + 1); break;
    case CC_STD3: case CC_ILT: case CC_IMP: case CC_JMPDST: for (int i = 0; i < 3; ++i) arg_is(c, nm, i, i + 4); break;
    case CC_STD10: for (int i = 0; i < 10; ++i) arg_is(c, nm, i, CC_STD10_ARG(i)); break;
    case CC_FAST4: for (int i = 0; i < 4; ++i) arg_is(c, nm, i, 11 + i); break;
    case CC_THIS: { const int32_t v = 7; mem32_is(c, nm, get_func_arg(c, 0), &v, 1); arg_is(c, nm, 1, 21); arg_is(c, nm, 2, 22); break; }
    case CC_VEC: arg_is(c, nm, 0, 31); arg_is(c, nm, 2, 32); break;
    case CC_I64: arg_is(c, nm, 0, (uint64_t)CC_I64_A); arg_is(c, nm, 1, 3); arg_is(c, nm, 2, (uint64_t)CC_I64_C); break;
    case CC_STDI64: arg_is(c, nm, 0, (uint64_t)CC_STDI64_A); arg_is(c, nm, 1, 2); break;
    case CC_S12: { const int32_t s[3] = {41, 42, 43}; mem32_is(c, nm, get_func_arg(c, 0), s, 3); arg_is(c, nm, 1, 44); break; }
    case CC_S8: arg_is(c, nm, 0, ((uint64_t)52 << 32) | 51); break;
    case CC_DBL: arg_is(c, nm, 2, 3); break;
    case CC_RETBIG: if (!get_func_arg(c, 0)) send_log(c, "cc FAIL %s no hidden pointer", nm); arg_is(c, nm, 1, 61); break;
    case CC_RETBIGSTD: if (!get_func_arg(c, 0)) send_log(c, "cc FAIL %s no hidden pointer", nm); arg_is(c, nm, 1, 62); break;
    case CC_RET8: arg_is(c, nm, 0, 63); break;
    default: break;
    }
#else
    // x86: index i = the i-th 4-byte STACK slot above the return address ([ESP+4+4i]).
    // Register arguments (fastcall/vectorcall ECX/EDX, thiscall ECX) are not counted: read
    // them with get_reg. A 64-bit argument or a double takes two slots (low, high), a struct
    // by value its size / 4, a hidden return pointer slot 0.
    switch (id) {
    case CC_CDECL3: for (int i = 0; i < 3; ++i) arg_is(c, nm, i, i + 1); break;
    case CC_STD3: case CC_ILT: case CC_IMP: case CC_JMPDST: for (int i = 0; i < 3; ++i) arg_is(c, nm, i, i + 4); break;
    case CC_STD10: for (int i = 0; i < 10; ++i) arg_is(c, nm, i, CC_STD10_ARG(i)); break;
    case CC_FAST4: reg_is(c, nm, PROBE_REG_CX, 11); reg_is(c, nm, PROBE_REG_DX, 12); arg_is(c, nm, 0, 13); arg_is(c, nm, 1, 14); break;
    case CC_THIS: { const int32_t v = 7; mem32_is(c, nm, get_reg(c, PROBE_REG_CX), &v, 1); arg_is(c, nm, 0, 21); arg_is(c, nm, 1, 22); break; }
    case CC_VEC: reg_is(c, nm, PROBE_REG_CX, 31); reg_is(c, nm, PROBE_REG_DX, 32); break;
    case CC_I64:
        arg_is(c, nm, 0, (uint32_t)CC_I64_A); arg_is(c, nm, 1, (uint32_t)((uint64_t)CC_I64_A >> 32)); arg_is(c, nm, 2, 3);
        arg_is(c, nm, 3, (uint32_t)CC_I64_C); arg_is(c, nm, 4, (uint32_t)((uint64_t)CC_I64_C >> 32)); break;
    case CC_STDI64:
        arg_is(c, nm, 0, (uint32_t)CC_STDI64_A); arg_is(c, nm, 1, (uint32_t)((uint64_t)CC_STDI64_A >> 32)); arg_is(c, nm, 2, 2); break;
    case CC_S12: for (int i = 0; i < 3; ++i) arg_is(c, nm, i, 41 + i); arg_is(c, nm, 3, 44); break;
    case CC_S8: arg_is(c, nm, 0, 51); arg_is(c, nm, 1, 52); break;
    case CC_DBL: arg_is(c, nm, 0, (uint32_t)bits(1.5)); arg_is(c, nm, 1, (uint32_t)(bits(1.5) >> 32));
                 arg_is(c, nm, 2, bits(2.25f)); arg_is(c, nm, 3, 3); break;
    case CC_FLT: arg_is(c, nm, 0, bits(0.5f)); arg_is(c, nm, 1, bits(4.0f)); break;
    case CC_RETBIG: if (!get_func_arg(c, 0)) send_log(c, "cc FAIL %s no hidden pointer", nm); arg_is(c, nm, 1, 61); break;
    case CC_RETBIGSTD: if (!get_func_arg(c, 0)) send_log(c, "cc FAIL %s no hidden pointer", nm); arg_is(c, nm, 1, 62); break;
    case CC_RET8: arg_is(c, nm, 0, 63); break;
    case CC_HOT: arg_is(c, nm, 0, 71); arg_is(c, nm, 1, 72); break;
    default: break;
    }
#endif
}

CC_CB void cc_on_entry(probe_context *c) {
    const cc_cfg *k = (const cc_cfg *)get_config(c);
    if (!k || k->id >= CC_N) { send_log(c, "cc FAIL bad config"); return; }
    const int id = (int)k->id;
    const cc_fn &f = CC_FNS[id];
    send_log(c, "cc hit %s", f.name);
    check_args(c, id);
    const bool floaty = f.kind == CC_K_DBL || f.kind == CC_K_FLT;
    const int pop_args = f.pop86 / 4;                     // return_from's nargs (x86 stack arguments popped)
    const int nargs = f.nslots < 8 ? f.nslots : 8;        // call_original's nargs (at most 8)
    if (k->mode == CCM_REPLACE) {
        if (floaty) return;                               // cannot set ST0/XMM0: let it run
        uint64_t v = cc_replacement(id);
        if (f.kind == CC_K_PTR) {                         // fill the caller's buffer, return its address
            const uint64_t hidden = get_func_arg(c, 0);
            const int32_t s[4] = {id * 10 + 1, id * 10 + 2, id * 10 + 3, id * 10 + 4};
            if (!set_mem(c, hidden, s, sizeof(s))) send_log(c, "cc FAIL %s set_mem hidden", f.name);
            v = hidden;
        }
        return_from(c, v, pop_args);
        return;
    }
    if (k->mode != CCM_WRAP && k->mode != CCM_WRONGPOP) return;
    uint64_t r = 0;
    if (!call_original(c, nargs, &r)) { send_log(c, "cc FAIL %s call_original refused", f.name); return; }
    // *ret is the integer return register: x64 RAX; x86 EAX zero-extended.
    if (f.kind == CC_K_INT && (uint32_t)r != (uint32_t)cc_native_int(id))
        send_log(c, "cc FAIL %s call_original ret=0x%llx want 0x%llx", f.name, (unsigned long long)r,
                 (unsigned long long)(uint32_t)cc_native_int(id));
#if defined(_WIN64)
    if (f.kind == CC_K_I64 && r != (uint64_t)cc_native_int(id))
        send_log(c, "cc FAIL %s call_original ret=0x%llx", f.name, (unsigned long long)r);
#endif
    int pop = pop_args;
    if (k->mode == CCM_WRONGPOP) pop = pop_args ? 0 : 2;  // the wrong x86 stack-argument count
    return_from(c, r, pop);
}
