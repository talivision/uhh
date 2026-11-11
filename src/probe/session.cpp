// Public x64 breakpoint + inline backends. The debug API binds event consumption
// to the launching thread, so probe_run owns the event loop through exit.
#include "session_internal.hpp"

namespace uhh_session {
bool trace_enabled() { static const bool on = std::getenv("PROBE_TRACE") != nullptr; return on; }
void bench_phase(const char *what, const char *arg) {
    static const bool on = std::getenv("UHH_BENCH_PHASES") != nullptr;
    if (!on) return;
    static const double f = [] { LARGE_INTEGER x; QueryPerformanceFrequency(&x); return (double)x.QuadPart; }();
    LARGE_INTEGER t; QueryPerformanceCounter(&t);
    std::fprintf(stderr, "  phase %.3f %s %s\n", (double)t.QuadPart * 1000.0 / f, what, arg ? arg : "");
}

void set_error(probe_session *s, const std::string &message) {
    if (s && s->error.empty()) s->error = message;
    std::fprintf(stderr, "probe: error: %s\n", message.c_str());
}

std::string win_error(const char *what) {
    return std::string(what) + " (Win32=" + std::to_string(GetLastError()) + ")";
}

bool has_inline(const probe_session *s) {
    for (const auto &p : s->probes) if (p->flags & PROBE_INLINE) return true;
    return false;
}

static bool arm_probe(probe_session *s, Probe &item, uint64_t base) {
    // A late-resolving inline probe (the gate is already released, so the target may
    // call the site before the async agent install lands) with PROBE_FALLBACK_HW set
    // becomes a hardware probe: that arms synchronously here (just debug registers —
    // no in-target code, no loader lock, no race) and is exact. The callback is
    // backend-agnostic, so it runs controller-side unchanged.
    // With the agent's service thread running, a late inline site is installed while the
    // loading thread is held (synchronous), so the fallback is only needed without it.
    // Judge an inline site BEFORE any backend decision, so a foreign hook is always
    // reported (and handled per PROBE_ALLOW_PREHOOKED / PROBE_FALLBACK_HW) -- including
    // when the late-install rule below would move the probe anyway.
    bool boundary_done = false;            // the instruction-boundary check ran (every backend)
    if (item.flags & PROBE_INLINE) {
        Probe view = item; view.base = base;
        bool known = true;
        if (!item.export_name.empty()) {
            uint64_t exp = 0; std::string saved = s->error;
            known = resolve_export(s, base, item.export_name, exp);
            if (known) view.rva = exp + item.sym_offset;
            s->error = saved;
        }
        // (A forwarded / symbol-only name has no RVA here yet: its real site is judged by
        //  vet_pending_inline before the hook is written -- never the module header.)
        view.address = base + view.rva;
        if (known && refuse_mid_instruction(s, item, view.address)) return false;
        boundary_done = known;
        bool moved = false;
        if (known && !vet_site(s, view, moved)) { item.retired = true; return false; }
        if (moved) item.flags = view.flags;                // pre-hooked -> hw (PROBE_FALLBACK_HW)
        item.patch_len = view.patch_len;                   // later inline probes must not overlap it
    }
    // (No "late inline -> hardware" rule: launch holds the main thread at the entry point
    // until the agent is ready, and a module loaded later is gated until its hooks are in.
    // Inline stays inline.)
    if (!item.export_name.empty()) {
        uint64_t exp = 0;
        std::string forward;
        const bool exported = resolve_export(s, base, item.export_name, exp, &forward);
        if (!exported && !forward.empty()) {
            std::string owner = item.module, symbol = item.export_name;
            uint64_t owner_base = 0;
            if (!remote_export_owner(s, owner, symbol, owner_base, exp)) return false;
            // Ownership follows the code mapping, not the forwarding image. Keep the
            // destination symbol so a reload re-reads its export table instead of an old RVA.
            item.module = owner; item.export_name = symbol;
            s->error.clear();
            if (!owner_base) return true;
            base = owner_base;
            boundary_done = false;
        } else if (!exported) {
            // Not exported: try the module's symbols (PDB beside the image, or a symbol
            // server via _NT_SYMBOL_PATH) -- internal functions by name.
            uint64_t addr = 0; std::string saved = s->error;
            uint32_t image = 0;
            {
                IMAGE_DOS_HEADER d{}; IMAGE_NT_HEADERS n{}; size_t g = 0;
                if (remote_read(s->pi.hProcess, base, &d, sizeof(d), &g) && g == sizeof(d) &&
                    remote_read(s->pi.hProcess, base + (uint32_t)d.e_lfanew, &n, sizeof(n), &g) && g == sizeof(n))
                    image = n.OptionalHeader.SizeOfImage;
            }
            // The symbol must lie inside THIS module's image (not a stale or same-named one).
            if (!s->sym_ready || !uhh_sym::resolve(s->pi.hProcess, item.module, item.export_name, addr) ||
                addr < base || addr >= base + image)
                return false;
            s->error.clear();
            exp = addr - base;
            std::fprintf(stderr, "probe: %s resolved from symbols -> %s+0x%llx\n", item.location.c_str(),
                         item.module.c_str(), (unsigned long long)exp);
            (void)saved;
        }
        item.rva = exp + item.sym_offset;
    }
    if (!boundary_done && refuse_mid_instruction(s, item, base + item.rva)) return false;
    if (item.flags & PROBE_BREAKPOINT) {
        // Judge the site BEFORE planting our INT3 (address is known: base + rva).
        Probe probe_view = item; probe_view.base = base; probe_view.address = base + item.rva;
        bool moved = false; (void)vet_site(s, probe_view, moved);
        return arm_breakpoint(s, item, base);
    }
    return item.flags & PROBE_HW ? arm_hw(s, item, base) : resolve_inline(s, item, base);
}

// "probe_app!X" names probe_app.dll (module_of_location), so it does not match the loaded
// probe_app.exe and would stay pending in silence: say so, once per probe, when a module of
// that name with another extension loads.
static void warn_bare_module(probe_session *s, const std::string &module) {
    const size_t dot = module.rfind('.');
    if (dot == std::string::npos || iequals(module.substr(dot), ".dll")) return;
    const std::string as_dll = module.substr(0, dot) + ".dll";
    for (size_t i = 0; i < s->probes.size(); ++i) {
        Probe &item = *s->probes[i];
        if (!item.bare_module || item.warned_bare || item.active || item.retired || item.address ||
            !iequals(item.module, as_dll)) continue;
        item.warned_bare = true;
        const size_t bang = item.location.find('!');
        const std::string rest = item.location.substr(bang != std::string::npos ? bang : item.location.rfind('+'));
        std::fprintf(stderr, "probe: warning: %s names %s (a module name without extension means .dll); "
                             "the loaded %s is not matched -- write %s%s to probe it\n",
                     item.location.c_str(), item.module.c_str(), module.c_str(), module.c_str(),
                     rest.c_str());
    }
}

// Launch-time probes that fail to arm fail the session (the user asked for them up
// front). A probe added at runtime -- possibly pending on a module that loads much
// later -- only reports its failure and retires; the run and other probes continue.
// fresh: the module has just been mapped (its LOAD_DLL, not the attach's replay of one already
// loaded) and none of its code has run yet.
bool arm_module(probe_session *s, const std::string &module, uint64_t base, bool fresh) {
    // Detaching: a module loading while the detach drains its last events must not get a
    // fresh INT3 / debug register / hook after everything was removed (seen: a DLL that
    // reloaded during the drain kept its new INT3 and the detached target died on it).
    if (s->detaching) return true;
    warn_bare_module(s, module);
    bool all_ok = true;
    // The agent's service thread runs: its init has put the guard in place (the vectored
    // handler goes in before the service thread starts), so the guard is up -- whether or not
    // that init has returned yet. Its INSTALL_DONE reports the inline probes active before
    // the init returns; a module loaded in between had its breakpoint/hw probes skipped here
    // and armed only when the init returned -- after the loading thread had run its code
    // (gated-e2e-attach-pre-fbp-oin-cin-rin, x86: no flag hit; regress gated-guardwin-stall-*).
    if (guard_pending(s) && s->shared->service_ready) all_ok = guard_set_ready(s, nullptr);
    for (size_t i = 0; i < s->probes.size(); ++i) {
        Probe &item = *s->probes[i];
        if (item.active || item.retired || item.address || !iequals(item.module, module)) continue;
        // Not up yet: a module already loaded at the attach waits for the guard (armed by
        // guard_set_ready; no unguarded trap). A FRESH mapping cannot wait: its loading
        // thread runs its code next, and a probe armed later misses those calls. It is armed
        // now; the guard covers it from the moment it is up (the INT3 table / DR mask are
        // mirrored already). regress gated-guardwin-early-*.
        if (!(item.flags & PROBE_INLINE) && guard_pending(s) && !fresh) continue;
        std::string saved = s->error;
        bool ok = false;
        try { ok = arm_probe(s, item, base); }
        catch (const std::exception &e) { set_error(s, std::string("arm ") + item.location + ": " + e.what()); }
        if (ok) continue;
        if (item.runtime) {
            std::fprintf(stderr, "probe: runtime probe %s failed to arm: %s\n", item.location.c_str(), s->error.c_str());
            s->error = saved; item.retired = true; continue;
        }
        all_ok = false;   // keep arming the module's other probes; the session still fails
    }
    return all_ok;
}

// The active SOFTWARE-BREAKPOINT probe at an address (the owner of an INT3 there). Other
// backends may probe the same address too (hw + breakpoint on one instruction): an INT3
// must never be attributed to them -- that ran the hw callback a second time and then
// "re-armed" the site with the hw probe's (zero) original byte, corrupting the code.
Probe *probe_at(probe_session *s, uint64_t address) {
    for (auto &p : s->probes)
        if (p->active && p->address == address && (p->flags & PROBE_BREAKPOINT)) return p.get();
    return nullptr;
}
static Probe *probe_any_at(probe_session *s, uint64_t address) {
    for (auto &p : s->probes) if (p->active && p->address == address) return p.get();
    return nullptr;
}

uint32_t probe_index(probe_session *s, const Probe *probe) {
    for (size_t i = 0; i < s->probes.size(); ++i)
        if (s->probes[i].get() == probe) return (uint32_t)i;
    return 0;
}

} // namespace uhh_session

using namespace uhh_session;

extern "C" probe_session *probe_session_create(void) {
    bench_phase("session_create");
    uhh_sym::preload();
    try { return new probe_session; }
    catch (...) { std::fprintf(stderr, "probe: error: session allocation failed\n"); return nullptr; }
}

namespace uhh_session {

// Dynamic (post-launch) control-plane calls come from a callback while the target is
// stopped. A failure there returns 0 to the callback but must not poison the session's
// end-of-run status, so the error is logged and the previous error state restored.
struct DynamicScope {
    probe_session *s; std::string saved; bool dynamic;
    explicit DynamicScope(probe_session *ss) : s(ss), saved(ss->error), dynamic(ss->launched) {}
    int done(int ok) {
        if (dynamic && !ok) {
            std::fprintf(stderr, "probe: dynamic add failed: %s\n", s->error.c_str());
            s->error = saved;
        }
        return ok;
    }
};

// A probe added from INSIDE a callback (any backend) must have a callback EXPORTED BY THE
// CALLING CALLBACK'S MODULE: an inline callback's control calls reach the controller by export
// name, resolved only among the exports of the module holding the origin probe's callback (the
// target is untrusted: it must not pick functions of other controller modules, handle_ipc).
// Requiring the same on every backend keeps one callback source portable (a static function,
// or an export of another module, used to work from a breakpoint/hw callback and return 0
// from an inline one).
static bool callback_ok_from_callback(probe_session *s, probe_callback cb) {
    if (!s->cb_tid || GetCurrentThreadId() != s->debug_tid || !cb) return true;
    std::string name;
    if (!callback_export_name(cb, name)) {
        set_error(s, "a probe added from a callback needs a callback exported by name (dllexport)");
        return false;
    }
    HMODULE mine{}, caller{};
    if (s->cb_probe && s->cb_probe->callback && module_of(reinterpret_cast<const void *>(cb), mine) &&
        module_of(reinterpret_cast<const void *>(s->cb_probe->callback), caller) && mine != caller) {
        set_error(s, kAddForeignCallback);
        return false;
    }
    return true;
}

// The export name(s) the agent resolves an inline probe's callback by (all names of a folded
// function that fit the request, see callback_export_names).
static bool inline_callback_names(probe_session *s, probe_callback cb, std::string &out) {
    std::string names;
    if (!callback_export_names(cb, names)) { set_error(s, "inline callback is not a named export"); return false; }
    out = export_names_fit(names, PROBE_AGENT_EXPORT_CAP);
    if (out.empty()) { set_error(s, "inline callback export name is too long"); return false; }
    return true;
}

static uint32_t hw_in_use(const probe_session *s) {
    uint32_t n = 0;
    for (auto &pp : s->probes) if ((pp->flags & PROBE_HW) && !pp->retired) ++n;
    return n;
}

static_assert(PROBE_AGENT_FLAG_UNSAFE_FAST_PATCH == PROBE_UNSAFE_FAST_PATCH, "agent flag mirror");
static bool check_flags(probe_session *s, uint32_t flags, bool allow_inline) {
    constexpr uint32_t types = PROBE_BREAKPOINT | PROBE_INLINE | PROBE_HW;
    constexpr uint32_t known = types | PROBE_AT_RETURN | PROBE_ALLOW_PREHOOKED | PROBE_FALLBACK_HW
                             | PROBE_WATCH_WRITE | PROBE_WATCH_RW | PROBE_ONCE | PROBE_UNSAFE_FAST_PATCH
                             | PROBE_ALLOW_UNSAFE_SITE;
    if (flags & ~known) { set_error(s, "unknown probe flags"); return false; }
    uint32_t type = flags & types;
    uint32_t watch = flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW);
    if ((type != PROBE_BREAKPOINT && type != PROBE_INLINE && type != PROBE_HW) || (flags & PROBE_AT_RETURN) ||
        ((flags & PROBE_ALLOW_PREHOOKED) && type != PROBE_INLINE) || // only meaningful for inline
        ((flags & PROBE_FALLBACK_HW) && type != PROBE_INLINE) ||     // fallback only modifies an inline probe
        ((flags & PROBE_UNSAFE_FAST_PATCH) && type != PROBE_INLINE) || // only inline hooks write code
        ((flags & PROBE_ALLOW_UNSAFE_SITE) && watch) || // any execute backend, never data watches
        (watch && type != PROBE_HW) ||                               // a watchpoint uses the DR/HW backend
        watch == (PROBE_WATCH_WRITE | PROBE_WATCH_RW) ||             // pick one access mode, not both
        ((flags & PROBE_ONCE) && type == PROBE_INLINE)) {            // one-shot needs a controller backend
        set_error(s, "requested probe type/options are unsupported in this build");
        return false;
    }
    (void)allow_inline;
    if (type == PROBE_HW && hw_in_use(s) >= 4) {
        set_error(s, "too many hardware probes (max 4 DR slots)"); return false;
    }
    if (type == PROBE_INLINE) {                            // the agent has a fixed number of hook slots
        size_t inl = 0; for (auto &pp : s->probes) if ((pp->flags & PROBE_INLINE) && !pp->retired) ++inl;
        if (inl >= PROBE_AGENT_MAX_PROBES) {
            set_error(s, "too many inline probes (max " + std::to_string(PROBE_AGENT_MAX_PROBES) + ")"); return false;
        }
    }
    return true;
}

} // namespace uhh_session

extern "C" int probe_add_symbol_cfg(probe_session *s, const char *location, probe_callback callback,
                                    uint32_t flags, const void *config, size_t config_len) {
    if (!s) return 0;
    DynamicScope scope(s);
    if (s->exited) { set_error(s, "session already exited"); return 0; }
    if (!callback) { set_error(s, "probe callback is null"); return scope.done(0); }
    if (!callback_ok_from_callback(s, callback)) return scope.done(0);
    if (!check_flags(s, flags, !s->launched)) return scope.done(0);
    uint32_t type = flags & (PROBE_BREAKPOINT | PROBE_INLINE | PROBE_HW);
    if (config_len && !config) { set_error(s, "non-empty probe config is null"); return scope.done(0); }
    if ((uint64_t)config_len > UINT32_MAX) { set_error(s, "probe config is larger than 4 GB"); return scope.done(0); }
    try {
        bench_phase("add_begin", location);
        auto p = std::make_unique<Probe>();
        if (!parse_location(s, location, *p)) return scope.done(0);
        bench_phase("add_parsed", location);
        p->callback = callback; p->flags = flags; p->runtime = s->launched;
        if (!bind_shared_callback(s, p->callback, flags, p->shared_export)) return scope.done(0);
        bench_phase("add_bound", location);
        if (type == PROBE_INLINE && !inline_callback_names(s, callback, p->callback_export)) return scope.done(0);
        if (type == PROBE_INLINE && !s->launched) start_agent_prep(s);   // the session will load the agent
        if (config_len) {
            auto first = static_cast<const unsigned char *>(config);
            p->config.assign(first, first + config_len);
        }
        std::fprintf(stderr, "probe: pending %s\n", p->location.c_str());
        Probe *raw = p.get();
        { std::lock_guard<std::mutex> lock(s->probes_mu); s->probes.push_back(std::move(p)); }          // heap-stable: callbacks may add mid-iteration
        if (s->launched && type == PROBE_INLINE && !register_runtime_inline(s, *raw)) {
            raw->retired = true; return scope.done(0);
        }
        if (s->launched) {                          // runtime add: arm now if the module is mapped
            if (raw->bare_module) for (auto &kv : s->module_bases) warn_bare_module(s, kv.first);
            for (auto &kv : s->module_bases)
                if (iequals(kv.first, raw->module)) {
                    if (!arm_probe(s, *raw, kv.second)) { raw->retired = true; return scope.done(0); }
                    break;
                }
            if (type == PROBE_INLINE && raw->address) {
                if (!kick_agent(s)) { raw->retired = true; return scope.done(0); }
                if (!confirm_runtime_inline(s, *raw)) return scope.done(0);
            }
        }
        return 1;
    } catch (const std::exception &e) { set_error(s, e.what()); return scope.done(0); }
}

extern "C" int probe_add_symbol(probe_session *s, const char *location, probe_callback callback, uint32_t flags) {
    return probe_add_symbol_cfg(s, location, callback, flags, nullptr, 0);
}

namespace uhh_session {

// Absolute-address probes only make sense once the process exists (ASLR), so they are a
// runtime operation: typically called from a callback with an address it just read.
static int add_absolute(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags) {
    if (!s) return 0;
    DynamicScope scope(s);
    if (!s->launched || s->exited) { set_error(s, "absolute-address probes need a running target"); return scope.done(0); }
    if (!cb) { set_error(s, "probe callback is null"); return scope.done(0); }
    if (!callback_ok_from_callback(s, cb)) return scope.done(0);
    if (!check_flags(s, flags, false)) return scope.done(0);
    try {
        auto p = std::make_unique<Probe>();
        char loc[40]; std::snprintf(loc, sizeof(loc), "0x%llx", (unsigned long long)address);
        p->location = loc; p->flags = flags; p->callback = cb; p->rva = address; p->runtime = true;
        std::string pending;                         // runtime add: bound at once (agent loaded)
        if (!bind_shared_callback(s, p->callback, flags, pending)) return scope.done(0);
        if ((flags & PROBE_INLINE) && !inline_callback_names(s, cb, p->callback_export)) return scope.done(0);
        Probe *raw = p.get();
        { std::lock_guard<std::mutex> lock(s->probes_mu); s->probes.push_back(std::move(p)); }
        if (refuse_mid_instruction(s, *raw, address)) return scope.done(0);   // (never a data watch)
        bool ok = (flags & PROBE_INLINE) ? register_runtime_inline(s, *raw) && resolve_inline(s, *raw, 0) && kick_agent(s)
                : (flags & PROBE_HW)     ? arm_hw(s, *raw, 0) : arm_breakpoint(s, *raw, 0);
        if (!ok) raw->retired = true;
        if (ok && (flags & PROBE_INLINE)) ok = confirm_runtime_inline(s, *raw);
        return scope.done(ok ? 1 : 0);
    } catch (const std::exception &e) { set_error(s, e.what()); return scope.done(0); }
}

} // namespace uhh_session

extern "C" int probe_add_address(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags) {
    if (s && (flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW))) {
        DynamicScope scope(s); set_error(s, "use probe_watch for data watchpoints"); return scope.done(0);
    }
    return add_absolute(s, address, cb, flags);
}

extern "C" int probe_watch(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags) {
    uint32_t mode = flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW);
    if (s && (flags & ~(uint32_t)(PROBE_WATCH_WRITE | PROBE_WATCH_RW | PROBE_ONCE | PROBE_HW))) {
        DynamicScope scope(s); set_error(s, "probe_watch takes PROBE_WATCH_WRITE/RW and PROBE_ONCE only"); return scope.done(0);
    }
    if (s && (address & 3)) {
        DynamicScope scope(s); set_error(s, "probe_watch address must be 4-byte aligned (watches one dword)"); return scope.done(0);
    }
    return add_absolute(s, address, cb, PROBE_HW | (mode ? mode : (uint32_t)PROBE_WATCH_WRITE) | (flags & PROBE_ONCE));
}

namespace uhh_session {

// ---- Callback memory access (breakpoint/hw callbacks) ---------------------------------
// The SAME policy as the inline agent's range check, so get_mem/set_mem answer the same on
// every backend: the whole range must be committed, not PAGE_GUARD / PAGE_NOACCESS, readable
// (and writable for set_mem) -- checked BEFORE any byte moves, so a failure has no partial
// effect. Plain Read/WriteProcessMemory differ: WriteProcessMemory silently makes code
// pages writable (a set_mem into .text succeeded under breakpoint/hw, failed inline), and a
// range running into an inaccessible page was half-copied. Reads also show the ORIGINAL
// byte where a software breakpoint is armed (the program's code, not UHH's INT3).
bool remote_range_ok(HANDLE h, uint64_t a, size_t n, bool write) {
    if (!n) return true;
    if (a + n < a) return false;
#if !defined(_WIN64)
    if (a + n > 0x100000000ull) return false;
#endif
    const uint64_t end = a + n;
    while (a < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(h, (const void *)(uintptr_t)a, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) return false;
        const DWORD prot = mbi.Protect & 0xFF;
        if ((mbi.Protect & PAGE_GUARD) || prot == PAGE_NOACCESS || prot == 0) return false;
        const bool w = prot == PAGE_READWRITE || prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READWRITE ||
                       prot == PAGE_EXECUTE_WRITECOPY;
        const bool r = w || prot == PAGE_READONLY || prot == PAGE_EXECUTE_READ;
        if (!r || (write && !w)) return false;
        a = (uint64_t)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return true;
}
static int callback_read(void *backend, uint64_t a, void *b, size_t n, size_t *done) {
    auto *s = static_cast<probe_session *>(backend);
    *done = 0;
    if (!n) return 1;
    if (!remote_range_ok(s->pi.hProcess, a, n, false)) return 0;
    if (!remote_read(s->pi.hProcess, a, b, n, done) || *done != n) return 0;
    for (auto &p : s->probes)                           // our INT3s read as the original bytes
        if (p->active && (p->flags & PROBE_BREAKPOINT) && !p->orig_insn.empty() && p->address >= a && p->address < a + n &&
            static_cast<unsigned char *>(b)[p->address - a] == 0xCC)
            static_cast<unsigned char *>(b)[p->address - a] = p->original;
    // ...and installed inline hooks as the bytes they overwrote (published by the agent), as
    // an inline callback reads them (it read the hook's jump here).
    if (s->shared) {
        const uint32_t count = s->shared->request_count < PROBE_AGENT_MAX_PROBES ? s->shared->request_count : PROBE_AGENT_MAX_PROBES;
        for (uint32_t i = 0; i < count; ++i) {
            const auto &r = s->shared->requests[i];
            const uint32_t len = r.original_len <= sizeof(r.original) ? r.original_len : 0;
            if (r.status != PROBE_AGENT_INSTALLED || !len || !r.site || r.site >= a + n || r.site + len <= a) continue;
            for (uint64_t x = r.site > a ? r.site : a; x < r.site + len && x < a + n; ++x)
                static_cast<unsigned char *>(b)[x - a] = r.original[x - r.site];
        }
    }
    return 1;
}
static int callback_write(void *backend, uint64_t a, const void *b, size_t n, size_t *done) {
    auto *s = static_cast<probe_session *>(backend);
    *done = 0;
    if (!n) return 1;
    if (!remote_range_ok(s->pi.hProcess, a, n, true)) return 0;
    // Keep our INT3s armed while changing the program bytes underneath them.
    std::vector<unsigned char> patched;
    try {
        for (auto &p : s->probes)
            if (p->active && (p->flags & PROBE_BREAKPOINT) && p->address < a + n &&
                (p->address >= a || a - p->address < 16)) {
                p->orig_insn.reserve(16); p->follow.reserve(15);
            }
        for (const auto &p : s->probes)
            if (p->active && (p->flags & PROBE_BREAKPOINT) && p->address >= a && p->address - a < n) {
                if (patched.empty()) patched.assign(static_cast<const unsigned char *>(b), static_cast<const unsigned char *>(b) + n);
                patched[p->address - a] = 0xcc;
            }
    } catch (...) { return 0; }
    const int ok = remote_write(s->pi.hProcess, a, patched.empty() ? b : patched.data(), n, done);
    for (auto &p : s->probes)
        if (p->active && (p->flags & PROBE_BREAKPOINT) && p->address >= a && p->address - a < *done)
            p->original = static_cast<const unsigned char *>(b)[p->address - a];
    for (auto &p : s->probes)
        if (p->active && (p->flags & PROBE_BREAKPOINT) && p->address < a + *done &&
            (p->address >= a || a - p->address < 16)) {
            if (!refresh_breakpoint(s, *p)) {
                // Undecodable code must execute at its real address, including its faults.
                p->orig_insn.assign(1, p->original); p->insn_len = 1;
                p->displaced_ok = false; p->rep_string = false; p->tramp = p->dtramp = 0;
            }
        }
    if (*done) {
        sync_int3_table(s);
        FlushInstructionCache(s->pi.hProcess, (void *)(uintptr_t)a, *done);
    }
    return ok;
}
const probe_ops callback_ops = {callback_read, callback_write};

// Ctrl+C / Ctrl+Break / console close while a session runs (probe_run through
// probe_wait_for_exit) ends the SESSION, not the tool: probe_run lets go of the target --
// an attached one is detached (probes removed, it keeps running), a launched one ended --
// and returns normally, so the caller still flushes the logs and writes its report. A
// second press, or one while no session runs, gets the default handling (the tool exits).
static std::atomic<int> g_ctrl_sessions{0};
static std::atomic<bool> g_ctrl_hit{false};

// probe_run loops still running (any session); g_runs_done is set when the last one has let
// go of its target (detached / ended) after a ctrl event.
static std::atomic<int> g_ctrl_runs{0};
static HANDLE g_runs_done = CreateEventW(nullptr, TRUE, FALSE, nullptr);

static BOOL WINAPI on_console_ctrl(DWORD type) {
    const bool mine = g_ctrl_sessions.load() > 0 && !g_ctrl_hit.exchange(true);
    if (trace_enabled()) std::fprintf(stderr, "  console ctrl %lu sessions=%d -> %s\n", (unsigned long)type,
                                      g_ctrl_sessions.load(), mine ? "session stop" : "default");
    // Console closed / logoff / shutdown: Windows ends this process as soon as the handler
    // returns, which would leave an attached target with live INT3s, debug registers and
    // hooks (it dies at its next hit). Hold the handler until probe_run has let go (the
    // system allows ~5 s for CTRL_CLOSE).
    if (mine && (type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT) &&
        g_ctrl_runs.load() > 0 && g_runs_done)
        WaitForSingleObject(g_runs_done, 4500);
    return mine;
}

static void ctrl_enter(probe_session *s) {
    static const BOOL installed = SetConsoleCtrlHandler(on_console_ctrl, TRUE);
    if (trace_enabled()) std::fprintf(stderr, "  console ctrl handler installed=%d err=%lu\n", installed, GetLastError());
    if (!s->ctrl_counted) { s->ctrl_counted = true; g_ctrl_sessions.fetch_add(1); }
}

static void ctrl_leave(probe_session *s) {
    if (!s->ctrl_counted) return;
    s->ctrl_counted = false;
    if (g_ctrl_sessions.fetch_sub(1) == 1) g_ctrl_hit = false;   // the next session starts clean
}

#if defined(UHH_TEST_HOOKS)
// UHH_TEST_STOP_LATE_MS=ms (test-only build): probe_run acts on a probe_close's detach request
// only ms after it first sees it, dispatching events meanwhile -- the debug loop busy when the
// request comes, forced: a target that dies right after the request ends the session on its
// EXIT_PROCESS first (regress lifecycle-target-dies-*, case "late").
static bool test_stop_late() {
    static const long ms = [] { const char *v = std::getenv("UHH_TEST_STOP_LATE_MS"); return v ? std::atol(v) : 0L; }();
    static ULONGLONG first = 0;
    if (ms <= 0) return false;
    if (!first) {
        first = GetTickCount64();
        std::fprintf(stderr, "probe: test: acting on the detach request %ld ms late\n", ms);
    }
    return GetTickCount64() - first < (ULONGLONG)ms;
}
// UHH_TEST_DIE_AFTER_HIT_MS=ms (test-only build): once a user probe has been hit, after the
// first exception event that was continued with its thread not mid-step (the hit's thread
// runs on), wait ms -- no event, no guard sync meanwhile -- and die (rc 96). The program
// suspends that thread meanwhile; the guard must leave that suspension alone (regress
// cx2-evsusp-*: the event thread used to stay on the guard's list until the next sync).
static void test_die_after_hit(probe_session *s, const DEBUG_EVENT &ev) {
    static const long ms = [] { const char *v = std::getenv("UHH_TEST_DIE_AFTER_HIT_MS"); return v ? std::atol(v) : 0L; }();
    if (ms <= 0 || ev.dwDebugEventCode != EXCEPTION_DEBUG_EVENT || s->stepping.count(ev.dwThreadId) ||
        s->cur_fiber || !s->calls.empty() || s->exited)
        return;
    uint64_t hits = 0;
    for (auto &p : s->probes) if (!p->internal) hits += p->hits;
    if (!hits) return;
    const ULONGLONG continued_tick = GetTickCount64();
    Sleep((DWORD)ms);
    const probe_agent_guard *g = s->shared ? &s->shared->guard : nullptr;
    std::string listed;
    for (LONG i = 0; g && i < g->held_count && i < (LONG)PROBE_AGENT_GUARD_TIDS; ++i)
        listed += (listed.empty() ? "" : ",") + std::to_string((unsigned long)g->held_tids[i]);
    // Diagnose a debug freeze during this deliberately unserviced delay. Dequeue only
    // immediately before death: continuing it would change the test's no-event window.
    DEBUG_EVENT pending{};
    const BOOL queued = WaitForDebugEvent(&pending, 0);
    std::fprintf(stderr, "probe: test: dying %ld ms after continuing thread %lu (guard enabled=%ld held=[%s]) continued_tick=%llu dying_tick=%llu "
                         "path=probe_run/test_die_after_hit/Sleep pending=%lu pending_tid=%lu exception=0x%lx at=0x%llx\n",
                 ms, (unsigned long)ev.dwThreadId, g ? (long)g->enabled : -1L, listed.c_str(),
                 (unsigned long long)continued_tick, (unsigned long long)GetTickCount64(),
                 queued ? (unsigned long)pending.dwDebugEventCode : 0UL, (unsigned long)pending.dwThreadId,
                 queued && pending.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? (unsigned long)pending.u.Exception.ExceptionRecord.ExceptionCode : 0UL,
                 queued && pending.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? (unsigned long long)(uintptr_t)pending.u.Exception.ExceptionRecord.ExceptionAddress : 0ULL);
    std::fflush(nullptr);
    TerminateProcess(GetCurrentProcess(), 96);
}
#endif

} // namespace uhh_session

extern "C" int probe_run(probe_session *s) {
    if (!s || !s->launched) { if (s) set_error(s, "session is not launched"); return 0; }
    if (s->ran) { set_error(s, "session already ran"); return 0; }
    if (s->debug_tid && s->debug_tid != GetCurrentThreadId()) {
        // Windows binds the debug object to the thread that created the process or attached.
        set_error(s, "probe_run must be called on the thread that called probe_launch/probe_attach");
        return 0;
    }
    bench_phase("run_begin");
    s->running = true;                     // before `ran`: probe_close waits on (ran && !running)
    s->ran = true;
    ctrl_enter(s);
    FiberHost fibers(s);
    if (g_ctrl_runs.fetch_add(1) == 0 && g_runs_done) ResetEvent(g_runs_done);
    DEBUG_EVENT event{};
    DWORD wait_ms = 20;
    while (!s->exited) {
        if (g_ctrl_hit && !s->interrupted) {
            s->interrupted = true; s->stop_requested = true;
            std::fprintf(stderr, "probe: interrupted: %s\n", s->attached
                         ? "detaching (probes removed, the target keeps running)" : "ending the target");
        }
#if defined(UHH_TEST_HOOKS)
        if (s->stop_requested && s->attached && test_stop_late()) {} else      // keeps dispatching meanwhile
#endif
        if (s->stop_requested) {
            // probe_close was called on another thread. The debug API binds the debug object
            // to THIS thread, so the detach (or termination) happens here.
            s->run_phase = "detaching";
            if (s->attached) { detach(s); s->detached = true; }
            else if (s->pi.hProcess) { TerminateProcess(s->pi.hProcess, 3); s->stop_requested = false; continue; }
            break;
        }
        s->run_phase = "draining the log ring";
        drain_agent_logs(s);
        if (!accept_agent_install(s, false)) break;
        s->run_phase = "in the debug loop";
        if (guard_pending(s) && s->guard_since && GetTickCount64() - s->guard_since > 5000 &&
            !guard_set_ready(s, "agent not ready within 5 s")) break;
        if (!s->held.empty() && GetTickCount64() - s->held_since > 5000) {
            // Never wedge the target: an install that does not confirm in 5 s is reported
            // and the threads run on (the affected probes simply stay inactive).
            std::fprintf(stderr, "probe: warning: inline install not confirmed within 5 s\n");
            if (trace_enabled()) trace_thread_stacks(s, "install timeout");
            release_held(s, "install timeout");
        }
        if (!poll_calls(s)) break;                          // call_func timeouts
        const auto wait_t0 = std::chrono::steady_clock::now();
        const BOOL got_event = WaitForDebugEvent(&event, wait_ms);   // short: also polls stop requests
        const DWORD wait_err = got_event ? 0 : GetLastError();
        wait_ms = fair_tick(s, std::chrono::steady_clock::now() - wait_t0, got_event);
        if (!s->ctx_watch.empty()) ctx_watch_poll(s);
        if (!got_event) {
            if (wait_err == ERROR_SEM_TIMEOUT) {            // idle: drain and wait again
                inplace_watchdog(s);
                if (!s->exited) guard_sync(s);              // holds released outside an event
                continue;
            }
            set_error(s, win_error("wait for debug event")); break;
        }
        if (continue_foreign_event(s, event)) continue;
        bool ok = service_event(s, event);
#if defined(UHH_TEST_HOOKS)
        if (g_test_die_on_continue) { std::fflush(nullptr); TerminateProcess(GetCurrentProcess(), 97); }
        test_die_after_hit(s, event);
#endif
        if (!ok) break;
    }
    std::unique_lock<std::mutex> report_lock(s->report_mu);
    bench_phase("run_loop_end");
    s->run_phase = "ending the session";
    finish_calls(s);                                      // callbacks still parked in call_func
    // An attached target is still running and the loop is leaving for some other reason
    // than a detach (an error: agent load/init failure, a failed context get/set or debug
    // wait): let go of it HERE, on the thread that owns the debug object -- INT3s restored,
    // debug registers cleared, inline hooks removed, logs drained -- instead of leaving live
    // traps behind a dead event loop (the target would freeze at its next debug event and die
    // when the controller exits) for a probe_close on a thread that cannot detach.
    if (s->attached && !s->exited && !s->detached && s->pi.hProcess) {
        const std::string why = s->error;
        std::fprintf(stderr, "probe: session failed (%s): detaching from the target\n", why.c_str());
        detach(s); s->detached = true;
        if (!why.empty()) s->error = why;
    }
    park_release(s);
    for (auto &kv : s->own_thread_handle) CloseHandle(kv.second);
    s->own_thread_handle.clear();
    if (trace_enabled())
        std::fprintf(stderr, "  fairness: %llu park rounds, %llu threads parked; rounds by demand: unknown %llu, none %llu, "
                             "some %llu; period %u ms\n", (unsigned long long)s->park_rounds, (unsigned long long)s->parked_total,
                     (unsigned long long)s->rounds_by_demand[0], (unsigned long long)s->rounds_by_demand[1],
                     (unsigned long long)s->rounds_by_demand[2], s->fair_period_ms);
    ctx_watch_poll(s, true);
    if (s->fine_timer) { timeEndPeriod(1); s->fine_timer = false; }
    release_held(s, "session end");
    stop_drainer(s);
    flush_log_writer(s);
    if (!s->exited && s->pi.hProcess && !s->attached) TerminateProcess(s->pi.hProcess, 3);
    if (s->exited && has_inline(s) && !s->inline_ready) set_error(s, "target exited before inline probes were ready");
    accept_agent_install(s, false);
    int result = (s->exited || s->detached) && s->error.empty();
    fibers.end();
    if (g_ctrl_runs.fetch_sub(1) == 1 && g_runs_done) SetEvent(g_runs_done);   // a closing console may go on
    report_lock.unlock();
    s->running = false;                                   // last touch of s on this thread
    return result;
}

extern "C" int probe_wait_for_exit(probe_session *s) {
    if (!s || !s->ran) { if (s) set_error(s, "session has not been run"); return 0; }
    bench_phase("wait_begin");
    if (s->exited) stop_drainer(s);             // includes recovery past a dead producer's ring slot
    flush_log_writer(s);
    ctrl_leave(s);
    bench_phase("wait_end");
    return s->error.empty() && (s->interrupted || (s->exited && s->exit_code == 0));
}

namespace uhh_session {

static void json_string(FILE *out, const std::string &value) {
    std::string text;
    append_json_string(text, value);
    std::fputs(text.c_str(), out);
}

} // namespace uhh_session

extern "C" void probe_report(probe_session *s, FILE *out) {
    if (!s || !out) return;
    std::lock_guard<std::mutex> report_lock(s->report_mu);
    bench_phase("report_begin");
    if (s->exited) stop_drainer(s); else drain_agent_logs(s);
    // All probe_log lines precede report records -- on a target still running (not exited,
    // not detached), the ones logged up to now: it may keep logging during the report.
    flush_log_writer(s, !s->exited && !s->detached);
    // Report lines and log batches never interleave mid-line on a shared stdout.
    std::unique_lock<std::mutex> out_lock(s->stdout_mu, std::defer_lock);
    if (out == stdout) out_lock.lock();
    // The forwarded target left its last line unfinished: report records start on their own line.
    if (out == stdout && s->fwd_out_active && s->out_midline) { std::fputc('\n', out); s->out_midline = false; }
    // The counts, in causal order: stdout_logs and logs_written (both frozen while stdout_mu is
    // held: the writer holds it across a batch's stdout AND file write), then the hits (a hit
    // is counted before its log exists). So stdout_logs <= logs_written <= hits even on a target that is
    // still running (except after a session-file failure: logs_written then counts the file only,
    // and stdout may hold more -- file_incomplete); once it exited or was detached they are exact. (The hits used to be read
    // BEFORE the flush: a report on a live target that flushed 5.3M records showed a probe's
    // hits far below its own logs_written.)
    bool live_closed, tail_on;
    uint64_t stdout_logs;
    std::string tail_error;
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        live_closed = s->live_output_closed;
        stdout_logs = s->stdout_logs;
        tail_on = s->tail_enabled;
        if (s->tail_failed && !s->live_output_closed) tail_error = s->tail_error;
    }
    const uint64_t written = s->logs_written.load();
    // Heap-stable pointers survive runtime additions; the vector itself does not. Copy only
    // under the growth lock, and use atomic counters/state without blocking the debug thread.
    std::vector<Probe *> probes;
    std::vector<std::string> prehooks;
    {
        std::lock_guard<std::mutex> lock(s->probes_mu);
        for (const auto &p : s->probes) probes.push_back(p.get());
        prehooks = s->prehooks;
    }
    for (const auto &j : prehooks) { std::fputs(j.c_str(), out); std::fputc('\n', out); }
    uint64_t hits = 0, active = 0;
    size_t visible = 0;
    for (const auto *p : probes) {
        if (p->internal) continue;
        const uint32_t flags = p->flags.load();
        const bool armed = p->active.load();
        const uint32_t index = p->agent_index.load();
        const uint64_t count = s->shared && (flags & PROBE_INLINE) && index < PROBE_AGENT_MAX_PROBES
            ? probe_agent_hits(s->shared, index) : p->hits.load();
        hits += count; active += armed; ++visible;
        std::fputs("{\"kind\":\"probe\",\"location\":", out); json_string(out, p->location);
        std::fprintf(out, ",\"backend\":\"%s\",\"active\":%s,\"hits\":%llu,\"retired\":%s}\n",
                     flags & PROBE_INLINE ? "inline" : flags & PROBE_HW ? "hw" : "breakpoint",
                     armed ? "true" : "false", (unsigned long long)count, p->retired.load() ? "true" : "false");
    }
    PROCESS_MEMORY_COUNTERS memory{}; memory.cb = (DWORD)sizeof(memory);
    uint64_t peak_mb = GetProcessMemoryInfo(GetCurrentProcess(), &memory, (DWORD)sizeof(memory))
                           ? ((uint64_t)memory.PeakWorkingSetSize + (1024 * 1024 - 1)) / (1024 * 1024) : 0;
    uint64_t dropped = (uint64_t)(s->shared ? s->shared->log_dropped : 0) +
                       s->controller_dropped.load(std::memory_order_relaxed);
    // Inline callbacks still in flight when the target died: ExitProcess/TerminateProcess
    // kill threads mid-callback (breakpoint/hw callbacks always complete -- the debugger
    // holds the thread). Their hits are counted; any log they would have sent never existed.
    uint64_t interrupted = 0;
    if (s->exited && s->shared)
        interrupted = probe_agent_inflight(s->shared);
    if (interrupted && !s->cut_off_said) {
        // Say which callbacks the target's end cut off (the thread died inside them) and
        // whether every interrupted hit is one of those (unexplained=0), once per session.
        s->cut_off_said = true;
        std::string where;
        uint64_t unexplained = 0;
        const uint64_t cut = probe_agent_cut_off(s->shared, unexplained, [&](uint32_t index, uint32_t tid, uint64_t n) {
            std::string loc = "probe #" + std::to_string(index);
            for (const auto *p : probes)
                if ((p->flags & PROBE_INLINE) && p->agent_index == index) { loc = p->location; break; }
            where += " " + loc + (tid ? " (tid " + std::to_string(tid) + ")" : "") + (n > 1 ? " x" + std::to_string(n) : "");
        });
        std::fprintf(stderr, "probe: callbacks interrupted by the target's end: %llu cut off while running:%s; "
                             "unexplained=%llu\n", (unsigned long long)cut, where.c_str(), (unsigned long long)unexplained);
    }
    std::fprintf(out, "{\"kind\":\"probe_report\",\"probes\":%llu,\"active\":%llu,"
                 "\"hits\":%llu,\"overrides\":%llu,\"log_dropped\":%llu,\"callbacks_interrupted\":%llu,"
                 "\"logs_written\":%llu,\"controller_peak_ws_mb\":%llu,\"app_exit\":%lu,"
                 "\"live_output_closed\":%s,",
                 (unsigned long long)visible, (unsigned long long)active,
                 (unsigned long long)hits, (unsigned long long)(s->overrides + (s->shared ? (uint64_t)s->shared->overrides : 0)),
                 (unsigned long long)dropped, (unsigned long long)interrupted,
                 (unsigned long long)written,
                 (unsigned long long)peak_mb, s->exit_code.load(), live_closed ? "true" : "false");
    // stdout_logs: probe_log records the live tail wrote to stdout -- equal to logs_written
    // unless stdout is NUL (no tail: null), its reader went away (live_output_closed), a
    // stdout write failed (live_output_error, also on stderr and in "error") or the session
    // file failed ("error": the file holds seq 0..logs_written-1; stdout may hold more). A capture is
    // complete when it holds stdout_logs probe_log lines with seq 0..stdout_logs-1.
    if (out == stdout) { s->reported_to_stdout = true; s->reported_stdout_logs = stdout_logs; }
    if (tail_on) std::fprintf(out, "\"stdout_logs\":%llu,", (unsigned long long)stdout_logs);
    else std::fputs("\"stdout_logs\":null,", out);
    std::fputs("\"live_output_error\":", out);
    if (tail_error.empty()) std::fputs("null", out); else json_string(out, tail_error);
    std::fputs(",\"error\":", out);
    if (s->error.empty()) std::fputs("null", out); else json_string(out, s->error);
    std::fputs("}\n", out); std::fflush(out);
    bench_phase("report_end");
}

extern "C" void probe_close(probe_session *s) {
    if (!s) return;
    bench_phase("close_begin");
    // probe_run is executing on another thread -- or is about to: the session was launched
    // or attached there and its probe_run has not started yet (e.g. Ctrl+C right after the
    // attach). Either way that thread owns the debug object: ask it to detach/stop and wait
    // for it to finish before tearing the session down.
    const bool owner_elsewhere = s->launched && !s->exited && s->debug_tid &&
                                 s->debug_tid != GetCurrentThreadId();
    const bool asked = s->running || (owner_elsewhere && !s->ran);   // this close stops a live session
    if (asked) {
        s->stop_requested = true;
        // Wait until probe_run has really returned: tearing the session down (or detaching
        // from this thread, which does not own the debug object) while it still runs would
        // be a use-after-free. A slow detach is reported, never cut short.
        for (ULONGLONG start = GetTickCount64(), warned = 0; s->running || !s->ran; Sleep(10)) {
            ULONGLONG waited = (GetTickCount64() - start) / 15000;
            if (waited > warned) {
                warned = waited;
                std::fprintf(stderr, "probe: close: still waiting for probe_run to stop (%llus; it is %s)\n",
                             waited * 15, s->run_phase.load());
            }
        }
    }
    ctrl_leave(s);                         // closed without probe_wait_for_exit
    if (s->detached) {
        // already detached by probe_run
    } else if (s->attached && !s->exited && s->pi.hProcess) {
        detach(s); s->detached = true;
    } else if (s->launched && !s->exited && s->pi.hProcess) {
        for (auto &p : s->probes)
            if (p->active && (p->flags & PROBE_BREAKPOINT)) restore_original(s->pi.hProcess, p->address, p->original);
        TerminateProcess(s->pi.hProcess, 3);
        if (WaitForSingleObject(s->pi.hProcess, 5000) == WAIT_OBJECT_0) s->exited = true;
        // On the debugger thread, consume the dead target's remaining events (through its
        // EXIT_PROCESS) so none is left queued for a later session on this thread.
        if (GetCurrentThreadId() == s->debug_tid) {
            for (ULONGLONG until = GetTickCount64() + 2000; GetTickCount64() < until; ) {
                DEBUG_EVENT ev{};
                if (!WaitForDebugEvent(&ev, 50)) continue;
                if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
                if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
                guard_continue(s, ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT && ev.dwProcessId == s->pi.dwProcessId) break;
            }
        }
    }
    stop_drainer(s);
    bench_phase("close_drainer");
    stop_log_output(s);                         // symbolization needs dbghelp and the process handle
    bench_phase("close_logout");
    // The close asked probe_run to detach, but the target ended first (killed or exited between
    // the request and the detach: probe_run left on its EXIT_PROCESS): the caller still gets
    // the final accounting, which it cannot take itself any more -- the session ended inside
    // this call (regress lifecycle-target-dies: once in ~20 runs no total was printed).
    const bool ended_first = asked && !s->detached && s->exited && s->attached;
    if (s->detached || ended_first) {
        // The final counts AFTER the detach (a report taken before probe_close races the
        // still-running target): every hit, and every log already written out.
        uint64_t hits = 0;
        for (auto &p : s->probes) {
            if (s->shared && (p->flags & PROBE_INLINE)) p->hits = probe_agent_hits(s->shared, p->agent_index);
            if (!p->internal) hits += p->hits;
        }
        // in_flight: inline callbacks still running (or killed/suspended mid-callback by the
        // program) at the detach that had not delivered a log yet -- hits == logs_written +
        // log_dropped + in_flight. running: inline callbacks still executing when the detach
        // stopped waiting (stop_drainer: at most 15 s), logged or not (not accounting: a callback
        // that logged is accounted by its log); any log they write later is lost.
        const uint64_t written = s->logs_written.load(std::memory_order_relaxed);
        const uint64_t dropped = (uint64_t)(s->shared ? s->shared->log_dropped : 0) +
                                 s->controller_dropped.load(std::memory_order_relaxed);
        const uint64_t in_flight = s->shared ? probe_agent_inflight(s->shared) : 0;
        const uint64_t running = s->shared && !ended_first ? probe_agent_running(s->shared) : 0;
        if (ended_first) {      // in_flight here: callbacks the target's end interrupted (probe_report's callbacks_interrupted)
            std::fprintf(stderr, "probe: ended: the target exited before the detach (exit code %lu): hits=%llu "
                                 "logs_written=%llu log_dropped=%llu in_flight=%llu\n", (unsigned long)s->exit_code.load(),
                         (unsigned long long)hits, (unsigned long long)written, (unsigned long long)dropped,
                         (unsigned long long)in_flight);
        } else {
            std::fprintf(stderr, "probe: detached: hits=%llu logs_written=%llu log_dropped=%llu in_flight=%llu running=%llu\n",
                         (unsigned long long)hits, (unsigned long long)written, (unsigned long long)dropped,
                         (unsigned long long)in_flight, (unsigned long long)running);
        }
        // The probe_report on stdout was taken before this detach (uhh_trace --detach-after-ms)
        // and records followed it: give stdout a last word too, so a capture that ends with
        // them still states its own total.
        uint64_t tailed;
        bool live;
        {
            std::lock_guard<std::mutex> lock(s->tail_mu);
            tailed = s->stdout_logs; live = s->tail_enabled && !s->tail_failed;
        }
        if (live && s->reported_to_stdout && tailed != s->reported_stdout_logs) {
            std::lock_guard<std::mutex> out_lock(s->stdout_mu);
            std::fprintf(stdout, "{\"kind\":\"probe_final\",\"hits\":%llu,\"logs_written\":%llu,\"log_dropped\":%llu,"
                                 "\"in_flight\":%llu,\"running\":%llu,\"stdout_logs\":%llu}\n",
                         (unsigned long long)hits, (unsigned long long)written, (unsigned long long)dropped,
                         (unsigned long long)in_flight, (unsigned long long)running, (unsigned long long)tailed);
            std::fflush(stdout);
        }
    }
    inplace_release_all(s);
    if (s->pi.hProcess) {
        for (uint64_t b : s->scratch_blocks) VirtualFreeEx(s->pi.hProcess, (void *)(uintptr_t)b, 0, MEM_RELEASE);
        // A config block stays in a detached target while any inline callback is still in flight
        // there (its thread suspended by the program, or past the drain): that callback's
        // get_config points into it. Freed, it read freed (or reused) memory.
        // A stop that never completed can also admit NEW callbacks.
        const uint64_t left = s->detached && !s->exited && s->shared ? probe_agent_running(s->shared) : 0;
        const bool hooks_live = s->detached && !s->exited && s->remote_agent && !s->detached_hooks;
        if ((left || hooks_live) && !s->config_blocks.empty())
            std::fprintf(stderr, "probe: detach: %zu config block(s) left in the target (running=%llu; hooks may still be live)\n",
                         s->config_blocks.size(), (unsigned long long)left);
        else
            for (uint64_t b : s->config_blocks) VirtualFreeEx(s->pi.hProcess, (void *)(uintptr_t)b, 0, MEM_RELEASE);
    }
    bench_phase("close_freed");
    if (s->agent_prep.joinable()) s->agent_prep.join();      // closed before the launch needed it
    if (!s->local_agent) s->local_agent = s->agent_prep_module;
    if (s->sym_ready) uhh_sym::cleanup(s->pi.hProcess);
    bench_phase("close_symcleanup");
    if (s->remote_thread) CloseHandle(s->remote_thread);
    if (s->svc_event) CloseHandle(s->svc_event);
    if (s->drain_event) CloseHandle(s->drain_event);
    if (s->remote_path && s->pi.hProcess) VirtualFreeEx(s->pi.hProcess, s->remote_path, 0, MEM_RELEASE);
    if (s->shared) UnmapViewOfFile(s->shared);
    if (s->mapping) CloseHandle(s->mapping);
    bench_phase("close_channel");
    if (s->local_agent) FreeLibrary(s->local_agent);
    bench_phase("close_local_agent");
    if (!s->agent_copy.empty()) {             // fails if the (detached) target still has it loaded
        DeleteFileW(s->agent_copy.c_str());
        RemoveDirectoryW(s->agent_copy.substr(0, s->agent_copy.find_last_of(L'\\')).c_str());
    }
    if (s->pi.hThread) CloseHandle(s->pi.hThread);
    if (s->pi.hProcess) CloseHandle(s->pi.hProcess);
    bench_phase("close_handles");
    delete s;
    bench_phase("close_end");
    if (std::getenv("UHH_BENCH_PHASES"))
        std::fprintf(stderr, "  diag file_writes=%llu file_bytes=%llu enqueues=%llu passes=%llu moved=%llu\n",
                     (unsigned long long)g_diag_file_writes.load(), (unsigned long long)g_diag_file_bytes.load(),
                     (unsigned long long)g_diag_enqueues.load(), (unsigned long long)g_diag_passes.load(),
                     (unsigned long long)g_diag_moved.load());
}

namespace uhh_session {

static uint64_t *register_slot(probe_context *c, enum probe_register reg) {
    if (!c) return nullptr;
    switch (reg) {
    case PROBE_REG_AX: return &c->regs.rax; case PROBE_REG_BX: return &c->regs.rbx;
    case PROBE_REG_CX: return &c->regs.rcx; case PROBE_REG_DX: return &c->regs.rdx;
    case PROBE_REG_SI: return &c->regs.rsi; case PROBE_REG_DI: return &c->regs.rdi;
    case PROBE_REG_BP: return &c->regs.rbp; case PROBE_REG_SP: return &c->regs.rsp;
#if defined(_WIN64)
    case PROBE_REG_R8: return &c->regs.r8; case PROBE_REG_R9: return &c->regs.r9;
    case PROBE_REG_R10: return &c->regs.r10; case PROBE_REG_R11: return &c->regs.r11;
    case PROBE_REG_R12: return &c->regs.r12; case PROBE_REG_R13: return &c->regs.r13;
    case PROBE_REG_R14: return &c->regs.r14; case PROBE_REG_R15: return &c->regs.r15;
#endif
    default: return nullptr;  /* x86: R8..R15 are unsupported -> null slot */
    }
}

} // namespace uhh_session

extern "C" uint64_t get_reg(probe_context *c, enum probe_register reg) {
    uint64_t *slot = register_slot(c, reg);
    if (!slot) return 0;
    return *slot;
}

extern "C" int set_reg(probe_context *c, enum probe_register reg, uint64_t value) {
    uint64_t *slot = register_slot(c, reg); if (!slot) return 0;
#if defined(_WIN64)
    uint64_t next = value;
#else
    uint64_t next = (uint32_t)value;   // x86: the register keeps the low 32 bits; get_reg says so (TH3)
#endif
    if (*slot != next) {
        *slot = next;
        auto *state = static_cast<CallbackState *>(c->controller);
        if (state && state->session) ++state->session->overrides;
    }
    return 1;
}

extern "C" int get_mem(probe_context *c, uint64_t address, void *buffer, size_t size) {
    if (!c || !c->ops || !c->ops->read || (!buffer && size)) return 0;
    size_t done = 0; return c->ops->read(c->backend, address, buffer, size, &done) && done == size;
}

extern "C" int set_mem(probe_context *c, uint64_t address, const void *buffer, size_t size) {
    if (!c || !c->ops || !c->ops->write || (!buffer && size)) return 0;
    size_t done = 0; return c->ops->write(c->backend, address, buffer, size, &done) && done == size;
}

extern "C" uint64_t get_func_arg(probe_context *c, size_t index) {
    if (!c) return 0;
#if defined(_WIN64)
    /* x64 __fastcall: first four args in registers, rest above the shadow space. */
    switch (index) {
    case 0: return c->regs.rcx; case 1: return c->regs.rdx;
    case 2: return c->regs.r8; case 3: return c->regs.r9;
    default: {
        if (c->regs.rsp > UINT64_MAX - 8 || index > (UINT64_MAX - c->regs.rsp - 8) / 8) return 0;
        uint64_t value = 0, address = c->regs.rsp + 8 + 8 * index;
        return get_mem(c, address, &value, sizeof(value)) ? value : 0;
    }
    }
#else
    /* x86 __stdcall: every arg on the stack at [esp+4+4*i], read exactly 4 bytes. */
    if (c->regs.rsp > UINT64_MAX - 4 || index > (UINT64_MAX - c->regs.rsp - 4) / 4) return 0;
    uint32_t value = 0; uint64_t address = c->regs.rsp + 4 + 4 * index;
    return get_mem(c, address, &value, sizeof(value)) ? value : 0;
#endif
}

extern "C" const void *get_config(probe_context *c) { return c ? c->config : nullptr; }

extern "C" probe_session *get_session(probe_context *c) {
    auto *state = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    return state ? state->session : nullptr;
}

namespace uhh_session {

static const probe_controller_api g_controller_api = {
    get_reg, set_reg, get_func_arg, get_mem, set_mem, vlog_entry, get_config, call_func_args, get_session,
    probe_add_address, probe_watch, probe_add_symbol, probe_add_symbol_cfg, call_original, return_from,
};
const probe_controller_api *controller_api_table() { return &g_controller_api; }

} // namespace uhh_session
