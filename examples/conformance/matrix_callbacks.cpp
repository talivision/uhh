// Portability matrix: ONE callback source, run under PROBE_BREAKPOINT, PROBE_HW and
// PROBE_INLINE (conformance_driver --matrix, target conformance_target --matrix). Every
// callback records what each API call returned, as log lines:
//   "M key=value"  must be IDENTICAL on every backend (scripts/regress.py diffs them)
//   "D key=value"  a DOCUMENTED divergence (include/probe_api.h, docs/ROADMAP.md
//                  "Portability findings"); the suite checks each backend's documented value
//   "S name"       a send_log_stack record (frames compared by the suite)
#include "probe_api.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PM_EXPORT extern "C" __declspec(dllexport)

struct pm_env {                         // == conformance_target.c
    uint64_t rw, ro, guard, xo, reserved, pid, mul, hit, other, entry;
    uint64_t out[16];
    uint64_t cf;
};
struct pm_config { uint64_t cookie; };
struct pm_big_config { uint64_t cookie; unsigned char body[292]; uint64_t tail; };   // 308 bytes

static const bool x64 = sizeof(void *) == 8;

static void hex8(char *out, const unsigned char *b, int ok) {
    if (!ok) { strcpy(out, "-"); return; }
    for (int i = 0; i < 8; ++i) sprintf(out + 2 * i, "%02x", b[i]);
}

// Two IDENTICAL callbacks on purpose: the linker folds them into one address (/OPT:ICF), so
// each has several export names (an add from an inline callback named only the first one).
PM_EXPORT void pm_noop(probe_context *c) { (void)c; }
PM_EXPORT void pm_on_other(probe_context *c) { (void)c; }
// Deliberately NOT exported (and with a body of its own, so it is folded with nothing): a
// probe added from a callback with this callback.
static void pm_static_cb(probe_context *c) { send_log(c, "pm_static_cb %d", 0x57A71C); }

static void entry_memory(probe_context *c, const pm_env &e) {
    unsigned char b[32];
    send_log(c, "M mem.get.size0-null=%d", get_mem(c, 0, nullptr, 0));
    send_log(c, "M mem.get.addr0=%d", get_mem(c, 0, b, 1));
    memset(b, 0xEE, sizeof(b));
    int r = get_mem(c, e.rw, b, 16), content = 1;
    for (int i = 0; i < 16; ++i) content &= b[i] == (unsigned char)i;
    send_log(c, "M mem.get.rw=%d content=%d", r, content);
    memset(b, 0xEE, sizeof(b));
    r = get_mem(c, e.rw + 4096 - 8, b, 16);
    int untouched = 1; for (int i = 0; i < 16; ++i) untouched &= b[i] == 0xEE;
    send_log(c, "M mem.get.rw-into-noaccess=%d untouched=%d", r, untouched);
    r = get_mem(c, e.ro, b, 4);
    send_log(c, "M mem.get.ro=%d content=%d", r, r && b[0] == 0x5A && b[1] == 0x5B);
    send_log(c, "M mem.get.guard=%d", get_mem(c, e.guard, b, 4));
    send_log(c, "M mem.get.exec-only=%d", get_mem(c, e.xo, b, 4));
    send_log(c, "M mem.get.reserved=%d", get_mem(c, e.reserved, b, 4));
    send_log(c, "M mem.get.wrap=%d", get_mem(c, ~0ull - 7, b, 16));
    send_log(c, "M mem.get.huge=%d", get_mem(c, e.rw, b, (size_t)-1));
    send_log(c, "M mem.get.huge2=%d", get_mem(c, e.rw, b, (size_t)1 << (x64 ? 40 : 30)));
    // An address no pointer of this process can hold: above 4 GB on x86, kernel space on x64.
    const uint64_t high = x64 ? (e.rw | 0xFFFF800000000000ull) : e.rw + 0x100000000ull;
    memset(b, 0xEE, sizeof(b));
    r = get_mem(c, high, b, 4);
    send_log(c, "M mem.get.high=%d untouched=%d", r, b[0] == 0xEE && b[3] == 0xEE);
    send_log(c, "M mem.get.null-buf=%d", get_mem(c, e.rw, nullptr, 4));
    char h[20];
    r = get_mem(c, e.hit, b, 8); hex8(h, b, r);
    send_log(c, "M mem.get.code-mid-site=%s", h);            // probed by THIS backend (mid-function)
    r = get_mem(c, e.entry, b, 8); hex8(h, b, r);
    send_log(c, "M mem.get.code-own-site=%s", h);            // this very probe's site
    r = get_mem(c, e.other, b, 8); hex8(h, b, r);
    send_log(c, "M mem.get.code-other-backend=%s", h);       // probed by ANOTHER backend
    send_log(c, "M mem.set.size0=%d", set_mem(c, 0, nullptr, 0));
    const uint32_t v = 0xA5A5A5A5u, w = 0x11223344u;
    send_log(c, "M mem.set.rw=%d", set_mem(c, e.rw + 64, &v, 4));
    send_log(c, "M mem.set.ro=%d", set_mem(c, e.ro, &v, 4));
    const unsigned char eight[8] = {9, 9, 9, 9, 9, 9, 9, 9};
    send_log(c, "M mem.set.partial=%d", set_mem(c, e.rw + 4096 - 4, eight, 8));
    send_log(c, "M mem.set.guard=%d", set_mem(c, e.guard, &v, 4));
    const unsigned char nop = 0x90;
    send_log(c, "M mem.set.code=%d", set_mem(c, e.hit + 4, &nop, 1));
    send_log(c, "M mem.set.high=%d", set_mem(c, high, &w, 4));
    send_log(c, "M mem.set.null-buf=%d", set_mem(c, e.rw, nullptr, 4));
}

static void entry_call_func(probe_context *c, const pm_env &e) {
    struct { const char *key, *sym; } pid_forms[] = {
        {"plain", "kernel32.dll!GetCurrentProcessId"},
        {"upper", "KERNEL32.DLL!GetCurrentProcessId"},
        {"no-ext", "kernel32!GetCurrentProcessId"},
        {"path", "C:\\nowhere\\kernel32.dll!GetCurrentProcessId"},
        {"off-hex", "kernel32.dll!GetCurrentProcessId+0x0"},
        {"off-no-0x", "kernel32.dll!GetCurrentProcessId+0"},
        {"off-bad", "kernel32.dll!GetCurrentProcessId+0xZZ"},
        {"no-module", "nosuchmodule.dll!GetCurrentProcessId"},
        {"no-export", "kernel32.dll!NoSuchExportUhh"},
        {"empty-export", "kernel32.dll!"},
        {"empty-module", "!GetCurrentProcessId"},
    };
    for (auto &f : pid_forms) {
        uint64_t r = ~0ull;
        int ok = call_func(c, f.sym, &r, 0);
        send_log(c, "M call_func.%s=%d pid=%d", f.key, ok, ok && r == e.pid);
    }
    uint64_t r = 0;
    send_log(c, "M call_func.nargs9=%d", call_func(c, "kernel32.dll!GetCurrentProcessId", &r, 9, 1ull, 2ull, 3ull, 4ull,
                                                  5ull, 6ull, 7ull, 8ull, 9ull));
    send_log(c, "M call_func.nargs-neg=%d", call_func(c, "kernel32.dll!GetCurrentProcessId", &r, -1));
    send_log(c, "M call_func.ret-null=%d", call_func(c, "kernel32.dll!GetCurrentProcessId", nullptr, 0));
    send_log(c, "M call_func.null-symbol=%d", call_func(c, nullptr, &r, 0));
    send_log(c, "M call_func.empty-symbol=%d", call_func(c, "", &r, 0));
    char sym[64];
    snprintf(sym, sizeof(sym), "0x%llx", (unsigned long long)e.mul);
    r = 0; int ok = call_func(c, sym, &r, 2, 6ull, 7ull);
    send_log(c, "M call_func.address=%d r=%llu", ok, ok ? (unsigned long long)r : 0ull);
    uint64_t base = 0;
    ok = call_func(c, "kernel32.dll!GetModuleHandleA", &base, 1, 0ull);
    snprintf(sym, sizeof(sym), "conformance_target.exe+0x%llx", (unsigned long long)(e.mul - base));
    r = 0; ok = ok && call_func(c, sym, &r, 2, 6ull, 7ull);
    send_log(c, "M call_func.module-rva=%d r=%llu", ok, ok ? (unsigned long long)r : 0ull);
    r = 0; ok = call_func(c, "conformance_target.exe!conf_mul", &r, 2, (uint64_t)-3, 5ull);
    send_log(c, "M call_func.negative-arg=%d r=%lld", ok, ok ? (long long)(intptr_t)r : 0ll);
    send_log(c, "M call_func.bad-address=%d", call_func(c, "0x1", &r, 0));
    // A callee that faults and handles its own exception (lstrlenA guards its pointer).
    r = 7; ok = call_func(c, "kernel32.dll!lstrlenA", &r, 1, 1ull);
    send_log(c, "D call_func.callee-handles-fault=%d r=%llu", ok, (unsigned long long)r);
}

static void entry_control_plane(probe_context *c) {
    probe_session *s = get_session(c);
    send_log(c, "M session=%d", s != nullptr);
    send_log(c, "M session.null-ctx=%d", get_session(nullptr) != nullptr);
    send_log(c, "M add.ok=%d", probe_add_symbol(s, "conformance_target.exe!pm_dummy", pm_noop, PROBE_BREAKPOINT));
    send_log(c, "M add.no-export=%d", probe_add_symbol(s, "conformance_target.exe!NoSuchExportUhh", pm_noop, PROBE_BREAKPOINT));
    send_log(c, "M add.no-type=%d", probe_add_symbol(s, "conformance_target.exe!pm_dummy", pm_noop, 0));
    send_log(c, "M add.null-callback=%d", probe_add_symbol(s, "conformance_target.exe!pm_dummy", nullptr, PROBE_BREAKPOINT));
    send_log(c, "M add.inline-once=%d", probe_add_symbol(s, "conformance_target.exe!pm_dummy", pm_noop, PROBE_INLINE | PROBE_ONCE));
    send_log(c, "M add.static-callback=%d", probe_add_symbol(s, "conformance_target.exe!pm_dummy2", pm_static_cb, PROBE_BREAKPOINT));
    pm_big_config big{};
    big.cookie = 0xB16C0F16B16C0F16ull; memset(big.body, 0x11, sizeof(big.body)); big.tail = 0x7A117A117A117A11ull;
    send_log(c, "M add.config-308=%d", probe_add_symbol_cfg(s, "conformance_target.exe!pm_dummy3", pm_noop, PROBE_BREAKPOINT,
                                                           &big, sizeof(big)));
    char longsym[400];
    int n = snprintf(longsym, sizeof(longsym), "C:\\");
    for (int i = 0; i < 300; ++i) longsym[n++] = 'a';
    snprintf(longsym + n, sizeof(longsym) - n, "\\conformance_target.exe!pm_dummy4");
    send_log(c, "M add.long-symbol=%d", probe_add_symbol(s, longsym, pm_noop, PROBE_BREAKPOINT));
    send_log(c, "M add.null-session=%d", probe_add_symbol(nullptr, "conformance_target.exe!pm_dummy", pm_noop, PROBE_BREAKPOINT));
    send_log(c, "M add-address.zero=%d", probe_add_address(s, 0, pm_noop, PROBE_BREAKPOINT));
    send_log(c, "M watch.on-breakpoint=%d", probe_watch(s, 0x1000, pm_noop, PROBE_BREAKPOINT));
}

// Function entry: pm_entry(env, 11, 22, 33, 44, 55).
PM_EXPORT void pm_on_entry(probe_context *c) {
    pm_env e{};
    const uint64_t envp = get_func_arg(c, 0);
    send_log(c, "M args=%d %llu %llu %llu %llu %llu", get_mem(c, envp, &e, sizeof(e)),
             (unsigned long long)get_func_arg(c, 1), (unsigned long long)get_func_arg(c, 2),
             (unsigned long long)get_func_arg(c, 3), (unsigned long long)get_func_arg(c, 4),
             (unsigned long long)get_func_arg(c, 5));
    send_log(c, "M arg.huge-index=%llu", (unsigned long long)get_func_arg(c, (size_t)-1));
    send_log(c, "M arg.null-ctx=%llu", (unsigned long long)get_func_arg(nullptr, 0));
    const pm_config *k = (const pm_config *)get_config(c);
    send_log(c, "M config=%d aligned8=%d", k && k->cookie == 0xC0F1C0F1C0F1C0F1ull, ((uintptr_t)k & 7) == 0);
    send_log(c, "M config.null-ctx=%d", get_config(nullptr) != nullptr);
    send_log(c, "M reg.null-ctx=%llu set=%d", (unsigned long long)get_reg(nullptr, PROBE_REG_AX), set_reg(nullptr, PROBE_REG_AX, 1));
    send_log(c, "M mem.null-ctx=%d set=%d", get_mem(nullptr, e.rw, &e, 4), set_mem(nullptr, e.rw, &e, 4));
    entry_memory(c, e);
    entry_call_func(c, e);
    entry_control_plane(c);
    send_log(c, "M log.null-format-follows=1");
    send_log(c, nullptr);
    send_log(nullptr, "M log.null-ctx=1");
    char big[1500]; memset(big, 'x', sizeof(big) - 1); big[sizeof(big) - 1] = 0;
    send_log(c, "M log.long=%s", big);
    send_log(c, "M log.bad-format=%k");
    send_log_stack(c, "S entry");
    // Win32 calls in a callback run in the process the callback runs in.
    send_log(c, "D win32.pid-is-target=%d", GetCurrentProcessId() == (DWORD)e.pid);
}

// Mid-function (PmRegHit): every GPR holds a known constant, CF is set.
PM_EXPORT void pm_on_regs(probe_context *c) {
    for (int r = 0; r < 16; ++r) {
        if (r == PROBE_REG_SP) { send_log(c, "M reg.get.sp-aligned=%d", (get_reg(c, PROBE_REG_SP) & 7) == 0); continue; }
        send_log(c, "M reg.get.%d=%llx", r, (unsigned long long)get_reg(c, (probe_register)r));
    }
    send_log(c, "M reg.get.invalid=%llx %llx", (unsigned long long)get_reg(c, (probe_register)16),
             (unsigned long long)get_reg(c, (probe_register)-1));
    send_log(c, "M reg.set.invalid=%d %d", set_reg(c, (probe_register)16, 1), set_reg(c, (probe_register)-1, 1));
    send_log(c, "M reg.arg0=%llx", (unsigned long long)(x64 ? get_func_arg(c, 0) : 0));
    for (int r = 0; r < 16; ++r) {
        if (r == PROBE_REG_SP) continue;
        // Wider than the register on x86: the target sees the low 32 bits.
        const uint64_t v = (x64 ? 0x5E5E000000000000ull : 0x100000000ull) | (0x5E00u + (unsigned)r);
        const int ok = set_reg(c, (probe_register)r, v);
        send_log(c, "M reg.set.%d=%d now=%llx", r, ok, (unsigned long long)get_reg(c, (probe_register)r));
    }
    // Mid-function: [SP] is no return address, so both are refused (no effect).
    uint64_t r = 0x1234;
    send_log(c, "M call_original.mid=%d r=%llx", call_original(c, 0, &r), (unsigned long long)r);
    return_from(c, 0x77, 0);
    send_log(c, "M return_from.mid-ax=%llx", (unsigned long long)get_reg(c, PROBE_REG_AX));
    send_log_stack(c, "S mid");
}

// pm_fault_site(env, 5) / pm_throw_site(env, 5): change the argument (a register on x64,
// the stack slot on x86), write a marker, then fault / throw.
static void change_then(probe_context *c, uint32_t mark, uint64_t mark_off, bool do_throw) {
    pm_env e{};
    get_mem(c, get_func_arg(c, 0), &e, sizeof(e));
    set_mem(c, e.rw + mark_off, &mark, 4);
    if (x64) set_reg(c, PROBE_REG_DX, 100);
    else { uint32_t v = 100; set_mem(c, get_reg(c, PROBE_REG_SP) + 8, &v, 4); }
    send_log(c, "M %s.before=1", do_throw ? "throw" : "fault");
    if (do_throw) throw 7;
    *(volatile int *)(uintptr_t)16 = 1;
    send_log(c, "M fault.after=1");
}
PM_EXPORT void pm_on_fault(probe_context *c) { change_then(c, 0xFA017FA0u, 256, false); }
PM_EXPORT void pm_on_throw(probe_context *c) {
    change_then(c, 0x7E40E7E4u, 260, true);
    send_log(c, "M throw.after=1");
}

// Concurrency: 4 threads x 50 + main x 10 hits.
static volatile LONG g_inflight, g_max_inflight, g_total;
static thread_local LONG t_hits;
PM_EXPORT void pm_on_conc(probe_context *c) {
    (void)c;
    ++t_hits;
    InterlockedIncrement(&g_total);
    const LONG n = InterlockedIncrement(&g_inflight);
    for (LONG m = g_max_inflight; n > m; m = g_max_inflight) InterlockedCompareExchange(&g_max_inflight, n, m);
    Sleep(1);
    InterlockedDecrement(&g_inflight);
}
PM_EXPORT void pm_on_report(probe_context *c) {
    send_log(c, "M conc.total=%ld", g_total);
    send_log(c, "D conc.max-inflight=%ld", g_max_inflight);
    send_log(c, "D conc.thread-local-on-main=%ld", t_hits);
    send_log(c, "M report.config=%d", get_config(c) && ((const pm_config *)get_config(c))->cookie == 0x4E9041ull);
}
PM_EXPORT void pm_on_bigcfg(probe_context *c) {
    const pm_big_config *k = (const pm_big_config *)get_config(c);
    send_log(c, "M config.big=%d", k && k->cookie == 0xB16C0F16B16C0F16ull && k->tail == 0x7A117A117A117A11ull &&
                                      k->body[0] == 0x11 && k->body[291] == 0x11);
}
