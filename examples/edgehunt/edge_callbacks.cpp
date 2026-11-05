// edgehunt: ONE callback source, unchanged under breakpoint, hw and inline, x64 and x86.
// Every check logs "ok <name>" or "FAIL <name> <detail>"; the suite requires one "ok" per
// hit and no FAIL. The config carries the site id (and the backend for runtime adds).
#include "probe_api.h"
#include <stdint.h>
#include <string.h>

#define EDGE_EXPORT extern "C" __declspec(dllexport)

enum edge_id : uint32_t {
    E_REP = 1, E_STOS, E_RIPLOAD, E_RIPCMP, E_RIPVEC, E_RIPSTORE, E_CPUID, E_RDTSC, E_SYSCALL, E_INT2E,
    E_PUSHF, E_POPF, E_RETONLY, E_THUNK, E_JUMP, E_FAULTMID, E_X87, E_LOCK, E_DUAL1, E_DUAL2,
    E_READD_A, E_READD_B, E_ARGS, E_MEM, E_FMT, E_FMTPTR, E_LEAF, E_CBFAULT
};
struct edge_cfg { uint32_t id; uint32_t backend; uint64_t svc; };

static void check(probe_context *c, bool ok, const char *name, uint64_t v = 0) {
    if (ok) send_log(c, "ok %s", name);
    else send_log(c, "FAIL %s v=0x%llx", name, (unsigned long long)v);
}
static uint64_t ptr_at(probe_context *c, uint64_t a) {
    uint64_t v = 0;
    if (!get_mem(c, a, &v, sizeof(void *))) return ~0ull;
    return v;
}

EDGE_EXPORT void edge_on_readd_b(probe_context *c);

EDGE_EXPORT void edge_on_site(probe_context *c) {
    const edge_cfg *k = (const edge_cfg *)get_config(c);
    if (!k) { send_log(c, "FAIL no-config"); return; }
    const uint64_t ax = get_reg(c, PROBE_REG_AX), cx = get_reg(c, PROBE_REG_CX), sp = get_reg(c, PROBE_REG_SP);
    switch (k->id) {
    case E_REP:     check(c, cx == 100, "rep", cx); break;
    case E_STOS:    check(c, cx == 64 && (ax & 0xFF) == 0x3C, "stos", cx); break;
    case E_RIPLOAD: check(c, true, "ripload"); break;
    case E_RIPCMP:  check(c, ax == 0, "ripcmp", ax); break;
    case E_RIPVEC:  check(c, true, "ripvec"); break;
    case E_RIPSTORE: check(c, (cx & 0xFFFFFFFF) >= 1000 && (cx & 0xFFFFFFFF) < 2000, "ripstore", cx); break;
    case E_CPUID:   check(c, ax == 0 && cx == 0, "cpuid", ax); break;
    case E_RDTSC:   check(c, true, "rdtsc"); break;
    case E_SYSCALL: check(c, (ax & 0xFFFFFFFF) == k->svc && get_reg(c, PROBE_REG_R10) == k->svc, "syscall", ax); break;
    case E_INT2E:   check(c, (ax & 0xFFFFFFFF) == k->svc, "int2e", ax); break;
    case E_PUSHF:   check(c, true, "pushf"); break;
    case E_POPF: {  // the flags image about to be popped
        uint64_t v = ptr_at(c, sp);
        check(c, (v & 0xFFF) == (0x202 | 0x1 | 0x80 | 0x800), "popf", v);
        break;
    }
    case E_RETONLY: { uint64_t r = ptr_at(c, sp); check(c, r != ~0ull && r > 0x10000, "retonly", r); break; }
    case E_THUNK:   check(c, true, "thunk"); break;
    case E_JUMP:    check(c, ax <= 2, "jump", ax); break;
    case E_FAULTMID: check(c, true, "faultmid"); break;
    case E_X87:     check(c, true, "x87"); break;
    case E_LOCK:    check(c, ax == 5, "lock", ax); break;
    case E_DUAL1:   check(c, ax == 0, "dual1", ax); break;
    case E_DUAL2:   check(c, ax == 0, "dual2", ax); break;
    case E_READD_A: {
        // Add a one-shot probe on EdgeReaddB, which runs right after this function returns:
        // added and retired once per call, many times over the run.
        edge_cfg b{E_READD_B, k->backend, 0};
        int r = probe_add_symbol_cfg(get_session(c), "edge_target.exe!EdgeReaddB", edge_on_readd_b,
                                     k->backend | PROBE_ONCE, &b, sizeof(b));
        check(c, r == 1, "readd-a", (uint64_t)r);
        break;
    }
    case E_ARGS: {
        uint64_t bad = 0;
        for (size_t i = 0; i < 10; ++i) if ((get_func_arg(c, i) & 0xFFFFFFFF) != i + 1) bad |= 1ull << i;
        check(c, bad == 0, "args10", bad);
        break;
    }
    case E_MEM: {
        // struct edge_mem { guard, ro, code, freed, cross, rw, site } (u64 each)
        uint64_t m[7] = {0};
        if (!get_mem(c, get_func_arg(c, 0), m, sizeof(m))) { check(c, false, "mem-struct"); break; }
        unsigned char b[16];
        memset(b, 0xEE, sizeof(b));
        check(c, get_mem(c, m[0], b, 8) == 0, "mem-guard-read-fails");
        check(c, get_mem(c, m[1], b, 8) == 1 && b[0] == 0x11, "mem-ro-read", b[0]);
        unsigned char w[16]; memset(w, 0x77, sizeof(w));
        check(c, set_mem(c, m[1], w, 8) == 0, "mem-ro-write-fails");
        check(c, set_mem(c, m[2], w, 1) == 0, "mem-code-write-fails");
        check(c, get_mem(c, m[3], b, 8) == 0, "mem-freed-read-fails");
        memset(b, 0xEE, sizeof(b));
        int rc = get_mem(c, m[4], b, 16);
        bool untouched = true; for (int i = 0; i < 16; ++i) untouched &= b[i] == 0xEE;
        check(c, rc == 0, "mem-cross-read-fails", (uint64_t)rc);
        check(c, untouched, "mem-cross-read-no-partial", b[0]);
        check(c, set_mem(c, m[4], w, 16) == 0, "mem-cross-write-fails");
        check(c, get_mem(c, 0, b, 1) == 0, "mem-null-read-fails");
        const uint64_t top = sizeof(void *) == 8 ? 0xFFFFFFFFFFFFFFF8ull : 0xFFFFFFF8ull;
        check(c, get_mem(c, top, b, 16) == 0, "mem-wrap-read-fails");
        check(c, get_mem(c, m[5], b, 0) == 1, "mem-zero-size");
        unsigned char site[2] = {0};
        check(c, get_mem(c, m[6], site, 2) == 1 && site[0] == 0xF3 && site[1] == 0xA4, "mem-site-bytes",
              (uint64_t)site[0] << 8 | site[1]);
        break;
    }
    case E_FMT: {
        // Formats a callback might get wrong. None may kill the controller or the target, and
        // each send_log must still produce exactly one record.
        static const char *volatile bad1 = "fmt-invalid %k end";
        static const char *volatile bad2 = "fmt-percent-n %n end";
        static const char *volatile bad3 = "fmt-trailing %";
        int dummy = 0;
        send_log(c, "fmt-null-s %s end", (const char *)nullptr);
        send_log(c, "fmt-wide %5000d end", 7);
        send_log(c, bad1, 1);
        send_log(c, bad2, &dummy);
        send_log(c, bad3);
        send_log(c, "fmt-done");
        break;
    }
    case E_FMTPTR:
        // %s of a TARGET pointer: only meaningful where the callback runs inside the target.
        send_log(c, "fmtptr %s", (const char *)(uintptr_t)get_func_arg(c, 0));
        break;
    case E_LEAF:
        send_log_stack(c, "leaf depth=%d", (int)get_func_arg(c, 0));
        break;
    case E_CBFAULT: {
        // A callback that faults (a bad pointer dereference). Inline runs callbacks under SEH
        // in the target; every backend must survive it the same way: the hit counts, the log
        // before the fault is kept, the target is unaffected (no register write-back).
        send_log(c, "ok cbfault-before");
        set_reg(c, PROBE_REG_AX, 0xBAD);
        volatile int *volatile p = nullptr;
        *p = 1;
        send_log(c, "FAIL cbfault-after");
        break;
    }
    default: send_log(c, "FAIL unknown-id %u", k->id); break;
    }
}

EDGE_EXPORT void edge_on_readd_b(probe_context *c) {
    const edge_cfg *k = (const edge_cfg *)get_config(c);
    check(c, k && k->id == E_READD_B, "readd-b");
}
