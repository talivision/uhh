// The hardware backend: debug-register slots, arming / migrating / releasing hw probes and
// watchpoints, library fixups at thread start, hw hit handling.
#include "session_internal.hpp"

namespace uhh_session {

// Hardware execute breakpoint: no code is modified, so there is no re-arm window and
// nothing to single-step. Set the DR on every current thread; new threads get it in
// the CREATE_THREAD handler. Exact under multithreading for ANY instruction (incl.
// control-flow/REP the displaced software path cannot handle), limited to 4 slots.
// Translate the probe flags into the DR7 RW/LEN encoding: execute breakpoint by
// default, or a data watchpoint (write / read+write) of one machine word.
void hw_rw_len(uint32_t flags, uint32_t &rw, uint32_t &len) {
    if (flags & PROBE_WATCH_RW)          rw = 3;
    else if (flags & PROBE_WATCH_WRITE)  rw = 1;
    else { rw = 0; len = 0; return; }                 // execute breakpoint, 1 byte
    len = 3;   // LEN=11 -> 4-byte (dword) watchpoint; the address must be dword-aligned
}

// The TARGET's own debug registers. A program may set hardware breakpoints/watchpoints on
// its own threads (SetThreadContext) and catch the #DB itself; those must keep working. A
// slot is the target's on a thread when it is enabled there, is not one we use, and does not
// hold an address we armed and released (a stale image of ours).
uint64_t dr_address(const CONTEXT &c, int slot) {
    switch (slot) { case 0: return c.Dr0; case 1: return c.Dr1; case 2: return c.Dr2; default: return c.Dr3; }
}
// A released address is still ours on `tid` only while that thread is unsettled (see
// probe_session::hw_unsettled); once it has run since the release, it is the target's.
bool hw_released_on(const probe_session *s, DWORD tid, uint64_t address) {
    if (tid == s->hw_stale_tid && s->hw_stale.count(address)) return true;
    const auto it = s->hw_unsettled.find(tid);
    return it != s->hw_unsettled.end() && it->second.addrs.count(address);
}
// An active hardware probe of ours at `address` (in whatever slot it lives now).
static bool hw_active_at(const probe_session *s, uint64_t address) {
    for (const auto &p : s->probes)
        if (p->active && (p->flags & PROBE_HW) && p->dr_slot >= 0 && p->address == address) return true;
    return false;
}
bool target_owns_slot(const probe_session *s, DWORD tid, const CONTEXT &c, int slot) {
    if (s->dr_used & (1u << slot)) return false;
    if (!((c.Dr7 >> (slot * 2)) & 3)) return false;
    const uint64_t a = dr_address(c, slot);
    // A probe moved to another slot (hw_yield_to_target) leaves its old image where our clear
    // was lost: still ours.
    return !hw_released_on(s, tid, a) && !hw_active_at(s, a);
}
static uint8_t target_slots(const probe_session *s, DWORD tid, const CONTEXT &c) {
    uint8_t m = 0;
    for (int k = 0; k < 4; ++k) if (target_owns_slot(s, tid, c, k)) m |= (uint8_t)(1u << k);
    return m;
}
// Slots the target owns on ANY of its threads (debug registers are per thread).
uint8_t target_slots_any(const probe_session *s) {
    uint8_t m = 0;
    for (DWORD tid : s->threads) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
        CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GuardTouch touch(s, tid);
        if (t && GetThreadContext(t, &c)) m |= target_slots(s, tid, c);
        if (t) CloseHandle(t);
    }
    return m;
}
// The integer registers, IP, SP and flags: equal -> the thread has not run in between.
// EFLAGS bit 1 is reserved (always 1 in the hardware register) and is not compared: a WOW64
// thread whose #DB is QUEUED reads EFlags with it set (0x206), the same thread at that event's
// report with it clear (0x204) -- nothing ran. Compared, "has not run" failed on every x86
// target, so the debug status our DR write zeroed was never carried into the queued #DB
// (dr6_lost) and a data-watch hit arrived with no status: passed to the target as an
// unhandled single step (hw-once-slots x86, ~1% of runs on CI runners).
static bool same_thread_regs(const CONTEXT &a, const CONTEXT &b) {
#if defined(_WIN64)
    return a.Rip == b.Rip && a.Rsp == b.Rsp && ((a.EFlags ^ b.EFlags) & ~0x2u) == 0 && a.Rax == b.Rax && a.Rbx == b.Rbx &&
           a.Rcx == b.Rcx && a.Rdx == b.Rdx && a.Rsi == b.Rsi && a.Rdi == b.Rdi && a.Rbp == b.Rbp && a.R8 == b.R8 &&
           a.R9 == b.R9 && a.R10 == b.R10 && a.R11 == b.R11 && a.R12 == b.R12 && a.R13 == b.R13 && a.R14 == b.R14 &&
           a.R15 == b.R15;
#else
    return a.Eip == b.Eip && a.Esp == b.Esp && ((a.EFlags ^ b.EFlags) & ~0x2u) == 0 && a.Eax == b.Eax && a.Ebx == b.Ebx &&
           a.Ecx == b.Ecx && a.Edx == b.Edx && a.Esi == b.Esi && a.Edi == b.Edi && a.Ebp == b.Ebp;
#endif
}
// Before writing ANOTHER thread's debug registers: keep the status of a #DB queued on it (see
// probe_session::dr6_lost). The event's own thread is handled from the context already read.
// The thread whose event is being handled right now (handlings on callback fibers
// interleave, so this is tracked across fiber switches, not taken from `handling`).
static DWORD handled_tid(const probe_session *s) { return s->event_tid; }
void keep_queued_dr6(probe_session *s, DWORD tid, HANDLE t) {
    if (tid == handled_tid(s)) return;
    CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(t, &c) || !(c.Dr6 & 0xF)) return;
    auto &l = s->dr6_lost[tid];
    if (l.bits && !same_thread_regs(l.regs, c)) l.bits = 0;
    l.regs = c; l.bits |= c.Dr6 & 0xF;
}
// The debug status lost by such a write, for the event of `tid` being handled (0 if none).
DWORD64 dr6_carried(const probe_session *s, DWORD tid) {
    return s->dr6_carry_tid == tid ? s->dr6_carry : 0;
}
// A hardware probe at `address` was just released (its DR cleared on every thread): until
// each thread reports an event, an image of it there may be our stale one. A thread that has
// run since an earlier release settled that one (our clear reached it): only the new counts.
void retire_hw_address(probe_session *s, uint64_t address) {
    for (DWORD tid : s->threads) {
        auto &u = s->hw_unsettled[tid];
        CONTEXT now{}; now.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        HANDLE t = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
        bool got;
        { GuardTouch touch(s, tid); got = t && GetThreadContext(t, &now); }
        if (t) CloseHandle(t);
        if (got && u.have_regs && !same_thread_regs(u.regs, now)) u.addrs.clear();
        if (got && (!u.have_regs || u.addrs.empty())) { u.regs = now; u.have_regs = true; }
        u.addrs.insert(address);
    }
    s->hw_released.insert(address);
    s->thread_start_due = true;
}
// Re-armed by us: no image of it is stale any more.
static void unretire_hw_address(probe_session *s, uint64_t address) {
    s->hw_stale.erase(address);
    s->hw_released.erase(address);
    for (auto it = s->hw_unsettled.begin(); it != s->hw_unsettled.end(); ) {
        it->second.addrs.erase(address);
        it = it->second.addrs.empty() ? s->hw_unsettled.erase(it) : std::next(it);
    }
}
// At each debug event of `tid`, before it is handled: settle it (see hw_unsettled).
void settle_hw_thread(probe_session *s, DWORD tid) {
    s->hw_stale_tid = 0; s->hw_stale.clear();
    s->dr6_carry_tid = 0; s->dr6_carry = 0;
    if (const auto l = s->dr6_lost.find(tid); l != s->dr6_lost.end()) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
        CONTEXT now{}; now.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (t && GetThreadContext(t, &now) && same_thread_regs(l->second.regs, now)) {
            s->dr6_carry_tid = tid; s->dr6_carry = l->second.bits;
        }
        if (t) CloseHandle(t);
        s->dr6_lost.erase(l);
    }
    const auto it = s->hw_unsettled.find(tid);
    if (it == s->hw_unsettled.end()) return;
    probe_session::HwUnsettled u = std::move(it->second);
    s->hw_unsettled.erase(it);
    HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (!t) return;
    CONTEXT now{}; now.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    // Without a register snapshot nothing tells "has run" apart: keep the address ours.
    if (GetThreadContext(t, &now) && (!u.have_regs || same_thread_regs(u.regs, now))) {
        // Not run since the release: this event was queued before it, and our clear may not
        // have landed. Its image of a released address is ours -- clear it now (a write at the
        // thread's own event sticks) and treat this event's #DB from it as stale.
        bool changed = false;
        for (int slot = 0; slot < 4; ++slot) {
            if ((s->dr_used & (1u << slot)) || !((now.Dr7 >> (slot * 2)) & 3) || !u.addrs.count(dr_address(now, slot))) continue;
            now.Dr7 &= ~((decltype(now.Dr7))3 << (slot * 2)) & ~((decltype(now.Dr7))0xF << (16 + slot * 4));
            changed = true;
        }
        if (changed) { now.ContextFlags = CONTEXT_DEBUG_REGISTERS; SetThreadContext(t, &now); }
        s->hw_stale_tid = tid; s->hw_stale = std::move(u.addrs);
    }
    CloseHandle(t);
}
#if defined(UHH_TEST_HOOKS)
// Test-only build (probe_api_testhooks, never shipped): UHH_TEST_DIE_AFTER_ARM=n kills the
// controller right after it writes its n-th user INT3 or arms its n-th hardware probe on the
// target's threads -- a controller death at the worst instant for the agent's guard
// (regress cxlib-killarm-*).
// UHH_TEST_DIE_IN_REPCOPY=1: die right after continuing a thread into a displaced REP string
// copy (it ends at an INT3 in our scratch; regress cxlib-reptail).
bool g_test_die_on_continue = false;
void test_note_repcopy() {
    static const bool on = std::getenv("UHH_TEST_DIE_IN_REPCOPY") != nullptr;
    if (on) g_test_die_on_continue = true;
}
void test_die_after_arm() {
    static const long n = [] { const char *v = std::getenv("UHH_TEST_DIE_AFTER_ARM"); return v ? std::atol(v) : 0L; }();
    static long seen = 0;
    if (n > 0 && ++seen == n) { std::fflush(nullptr); TerminateProcess(GetCurrentProcess(), 99); }
}
#endif
bool arm_hw(probe_session *s, Probe &p, uint64_t base) {
    if (p.rva > UINT64_MAX - base) { set_error(s, "probe address overflow"); return false; }
    uint64_t address = base + p.rva;
    int slot = -1;
    // Rotate through free slots so a just-released slot is reused last: a #DB already in
    // flight for the old probe is then far less likely to be blamed on a new one.
    // Slots the TARGET itself has enabled on any of its threads are not ours to take.
    const uint8_t foreign = target_slots_any(s);
    for (int k = 0; k < 4; ++k) {
        int i = (s->dr_next + k) & 3;
        if (!(s->dr_used & (1u << i)) && !(foreign & (1u << i))) { slot = i; break; }
    }
    if (slot >= 0) s->dr_next = (uint8_t)((slot + 1) & 3);
    if (slot < 0) { set_error(s, "no free hardware breakpoint slot (max 4)"); return false; }
    uint32_t rw = 0, len = 0; hw_rw_len(p.flags, rw, len);
    // The guard's DR mask gets the slot BEFORE any thread has it armed (as for an INT3, see
    // arm_breakpoint): a controller killed in between left an enabled DR the guard took for
    // the target's own -- never cleared, its #DB unhandled (0x80000004) at the next hit.
    const uint8_t ever_before = s->dr_ever;
    s->dr_ever |= (uint8_t)(1u << slot);
    s->hw_armed_ever.insert(address);
    guard_sync(s);
    size_t tried = 0, set_ok = 0;
#if defined(UHH_TEST_HOOKS)
    g_test_in_arm_hw = !p.internal;
#endif
    for (DWORD tid : s->threads) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
        if (!t) continue;
        ++tried;
        GuardTouch touch(s, tid);
        keep_queued_dr6(s, tid, t);
        if (set_dr_on_thread(t, slot, address, true, rw, len, s)) ++set_ok;
        CloseHandle(t);
    }
#if defined(UHH_TEST_HOOKS)
    g_test_in_arm_hw = false;
#endif
#if defined(UHH_TEST_HOOKS)
    if (set_ok && !p.internal) test_die_after_arm();
#endif
    if (tried && !set_ok) {   // could not arm the DR on any thread -> the probe would never fire
        s->dr_ever = ever_before; guard_sync(s);
        set_error(s, win_error("set hardware breakpoint on target threads")); return false;
    }
    s->dr_used |= (uint8_t)(1u << slot); s->dr_ever |= (uint8_t)(1u << slot); ++s->hw_active;
    s->hw_armed_ever.insert(address);
    unretire_hw_address(s, address);
    p.dr_slot = slot; p.base = base; p.address = address; p.active = true;
    std::fprintf(stderr, "probe: active %s -> base=0x%llx addr=0x%llx (hw DR%d, %s)\n",
                 p.location.c_str(), (unsigned long long)base, (unsigned long long)address, slot,
                 rw == 3 ? "watch rw" : rw == 1 ? "watch write" : "execute");
    arm_thread_start_fixup(s);
    return true;
}

// The target armed its OWN hardware breakpoint in a slot one of our probes uses (seen on a
// thread it created suspended and set DR0 on before it ran: our CREATE_THREAD write replaced it,
// so the program's own breakpoint never fired -- ROADMAP A7). Debug registers are the program's
// first: move our probe to a slot no thread of the target uses, on every thread (keeping the
// target's value where it has one). With no slot left, ours yields on that thread (its hits
// there are not seen; warned) -- never the program's breakpoint.
static bool hw_slot_is_ours(const probe_session *s, const CONTEXT &c, int slot) {
    if (!((c.Dr7 >> (slot * 2)) & 3)) return true;                       // disabled: nothing to keep
    return s->hw_armed_ever.count(dr_address(c, slot)) != 0;
}
static void migrate_hw(probe_session *s, Probe &p, DWORD tid) {
    const int old = p.dr_slot;
    const uint8_t foreign = target_slots_any(s);
    int slot = -1;
    for (int k = 0; k < 4 && slot < 0; ++k) {
        const int i = (s->dr_next + k) & 3;
        if (!(s->dr_used & (1u << i)) && !(foreign & (1u << i))) slot = i;
    }
    if (slot < 0) {
        if (!s->warned_dr_full) {
            s->warned_dr_full = true;
            std::fprintf(stderr, "probe: warning: %s: the program uses DR%d itself on thread %lu and no debug register is "
                                 "free: the probe yields there (its hits on such threads are not seen)\n",
                         p.location.c_str(), old, (unsigned long)tid);
        }
        return;
    }
    uint32_t rw = 0, len = 0; hw_rw_len(p.flags, rw, len);
    s->dr_ever |= (uint8_t)(1u << slot);
    s->dr_used |= (uint8_t)(1u << slot);
    guard_sync(s);                                   // the guard knows the new slot before any thread has it
    for (DWORD t_id : s->threads) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, t_id);
        if (!t) continue;
        GuardTouch touch(s, t_id);
        keep_queued_dr6(s, t_id, t);
        CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(t, &c)) {
            if (((c.Dr7 >> (old * 2)) & 3) && dr_address(c, old) == p.address)      // our old image: off
                c.Dr7 &= ~(((decltype(c.Dr7))3 << (old * 2)) | ((decltype(c.Dr7))0xF << (16 + old * 4)));
            switch (slot) { case 0: c.Dr0 = (decltype(c.Dr0))p.address; break; case 1: c.Dr1 = (decltype(c.Dr1))p.address; break;
                            case 2: c.Dr2 = (decltype(c.Dr2))p.address; break; default: c.Dr3 = (decltype(c.Dr3))p.address; }
            c.Dr7 = (c.Dr7 & ~((decltype(c.Dr7))0xF << (16 + slot * 4))) | ((decltype(c.Dr7))1 << (slot * 2)) |
                    ((decltype(c.Dr7))(((len & 3u) << 2) | (rw & 3u)) << (16 + slot * 4));
            c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            SetThreadContext(t, &c);
        }
        CloseHandle(t);
    }
    s->dr_used &= (uint8_t)~(1u << old);
    s->dr_next = (uint8_t)((slot + 1) & 3);
    p.dr_slot = slot;
    guard_sync(s);
    std::fprintf(stderr, "probe: %s moved from DR%d to DR%d: the program uses DR%d itself (thread %lu)\n",
                 p.location.c_str(), old, slot, old, (unsigned long)tid);
}
// Thread `tid` (handle t, GET_CONTEXT): any slot of ours the target has claimed there?
void hw_yield_to_target(probe_session *s, DWORD tid, HANDLE t) {
    if (!s->dr_used || !t) return;
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    { GuardTouch touch(s, tid); if (!GetThreadContext(t, &c)) return; }
    for (int slot = 0; slot < 4; ++slot) {
        if (!(s->dr_used & (1u << slot)) || hw_slot_is_ours(s, c, slot)) continue;
        for (auto &p : s->probes)
            if (p->active && (p->flags & PROBE_HW) && p->dr_slot == slot) { migrate_hw(s, *p, tid); break; }
    }
}
// A slot of ours the target claimed on this thread and that we could not move away from.
static bool hw_yielded(const probe_session *s, const CONTEXT &c, int slot) {
    return (s->dr_used & (1u << slot)) && !hw_slot_is_ours(s, c, slot);
}

// The loader finishes process initialisation with NtContinue on the initial thread's
// start context, which carries the debug registers captured at thread creation. Any
// hardware probe armed later in loader init (a static import such as ucrtbase loading)
// is silently wiped there. A library-owned one-shot breakpoint at the image entry point
// re-applies every active hardware probe to every thread right after that point.
void reapply_all_hw(probe_session *s) {
    s->entry_reapply = 0;
    for (DWORD tid : s->threads) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
        if (t) { hw_yield_to_target(s, tid, t); CloseHandle(t); }
    }
    for (auto &p : s->probes) {
        if (!p->active || !(p->flags & PROBE_HW)) continue;
        uint32_t rw = 0, len = 0; hw_rw_len(p->flags, rw, len);
        for (DWORD tid : s->threads) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
            GuardTouch touch(s, tid);
            if (t) { keep_queued_dr6(s, tid, t); set_dr_on_thread(t, p->dr_slot, p->address, true, rw, len, s); CloseHandle(t); }
        }
    }
}

static void reapply_hw(probe_context *c) {
    if (probe_session *s = get_session(c)) reapply_all_hw(s);
}

void arm_entry_fixup(probe_session *s, uint64_t entry) {
    if (!entry) return;
    s->entry_reapply = entry; s->entry_addr = entry;
    if (probe_at(s, entry)) return;   // a user breakpoint is already there: it triggers the re-apply
    try {
        auto p = std::make_unique<Probe>();
        p->location = "<entry>"; p->flags = PROBE_BREAKPOINT | PROBE_ONCE; p->callback = reapply_hw;
        p->rva = entry; p->internal = true;
        Probe *raw = p.get(); { std::lock_guard<std::mutex> lock(s->probes_mu); s->probes.push_back(std::move(p)); }
        std::string saved = s->error;
        if (!arm_breakpoint(s, *raw, 0)) { raw->retired = true; s->error = saved; }
    } catch (...) {}
}

// The same NtContinue wipe hits EVERY thread, not just the initial one: a thread still in
// its loader initialisation (LdrInitializeThunk: DLL_THREAD_ATTACH, TLS) when a hardware
// probe is armed at runtime -- from a callback, or at a later DLL load -- resumes at
// ntdll!RtlUserThreadStart with the DR image captured when it was created, and never sees
// that probe (found by examples/famous retval_override: whole worker threads missed a
// return-site probe added while they were starting). A library-owned breakpoint at
// RtlUserThreadStart re-applies the active hardware probes to each thread arriving there,
// i.e. right after its context was restored. Armed the first time a hardware probe is
// armed -- or released -- while the process is already running.
// The same restore brings back a hardware probe RELEASED while the thread was starting
// (see probe_session::hw_released): clear such slots before the program runs on it.
// Disable, in a restored DR image, our free slots that still point at a released address.
static bool clear_released_images(const probe_session *s, CONTEXT &c) {
    bool changed = false;
    for (int slot = 0; slot < 4; ++slot) {
        if (!(s->dr_ever & (1u << slot)) || (s->dr_used & (1u << slot)) || !((c.Dr7 >> (slot * 2)) & 3) ||
            !s->hw_released.count(dr_address(c, slot))) continue;
        c.Dr7 &= ~((decltype(c.Dr7))3 << (slot * 2)) & ~((decltype(c.Dr7))0xF << (16 + slot * 4));
        changed = true;
    }
    return changed;
}
void reapply_hw_thread(probe_session *s, DWORD tid) {
    if (!s->hw_active && s->hw_released.empty() && s->gates.empty()) return;
    HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (!t) return;
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!s->hw_released.empty() && GetThreadContext(t, &c)) {
        if (clear_released_images(s, c)) {
            if (trace_enabled()) std::fprintf(stderr, "  thread-start: released DR image cleared on %lu\n", (unsigned long)tid);
            SetThreadContext(t, &c);
        }
    }
    hw_yield_to_target(s, tid, t);
    for (auto &p : s->probes) {
        if (!p->active || !(p->flags & PROBE_HW)) continue;
        uint32_t rw = 0, len = 0; hw_rw_len(p->flags, rw, len);
        set_dr_on_thread(t, p->dr_slot, p->address, true, rw, len, s);
    }
    for (auto &g : s->gates) set_dr_on_thread(t, g.second, g.first, true, 0, 0, s);   // inline install gates too
    CloseHandle(t);
}

void thread_start_fixup(probe_context *c) {
    if (probe_session *s = get_session(c)) reapply_hw_thread(s, c->tid);
}
void arm_thread_start_fixup(probe_session *s) {
    arm_restore_fixup(s);
    if (s->thread_start_fixup || !(s->entry_seen || s->attached)) return;
    uint64_t at = resolve_symbol(s, "ntdll.dll!RtlUserThreadStart");
    if (!at) return;
    s->thread_start_fixup = true;
    if (Probe *owner = probe_at(s, at)) { (void)owner; return; }   // a user probe owns the site: rare, left as is
    try {
        auto p = std::make_unique<Probe>();
        p->location = "<thread-start>"; p->flags = PROBE_BREAKPOINT; p->callback = thread_start_fixup;
        p->rva = at; p->internal = true;
        Probe *raw = p.get(); { std::lock_guard<std::mutex> lock(s->probes_mu); s->probes.push_back(std::move(p)); }
        std::string saved = s->error;
        if (!arm_breakpoint(s, *raw, 0)) { raw->retired = true; s->error = saved; }
    } catch (...) {}
}

// Fully release a hardware probe: clear its DR on every thread and free the slot.
void release_hw(probe_session *s, Probe &p) {
    if (p.dr_slot < 0) return;
    for (DWORD tid : s->threads) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
        GuardTouch touch(s, tid);
        if (t) { keep_queued_dr6(s, tid, t); set_dr_on_thread(t, p.dr_slot, 0, false); CloseHandle(t); }
    }
    if (p.address) retire_hw_address(s, p.address);
    s->dr_used &= (uint8_t)~(1u << p.dr_slot);
    if (s->hw_active > 0) --s->hw_active;
    p.active = false; p.dr_slot = -1;
    if (p.flags & PROBE_ONCE) p.retired = true;
}

// Write the debug-register state the session wants into a thread's context: every slot
// this session has ever owned is set to its active probe (address + DR7 enable/RW/LEN)
// or cleared if released. Slots never owned (the target's own) are left alone.
// Why: a DR change made with SetThreadContext while that thread is blocked with its own
// debug event still QUEUED behind the one being handled (two threads hitting probes at
// once) can be lost -- seen as a hw probe added from a callback (e.g. a return-address
// probe) that never fires on that thread. Re-asserting our slots at the thread's own
// event repairs it before it runs on.
// clear_stale = false: only re-assert the active probes' slots (a context image the PROGRAM
// may have just edited -- an exception handler arming its own DR in the record -- keeps every
// other slot as it is).
void enforce_owned_drs(const probe_session *s, DWORD tid, CONTEXT &c, bool clear_stale) {
    for (int slot = 0; slot < 4; ++slot) {
        if (!(s->dr_ever & (1u << slot))) continue;
        // call_original borrowed its probe's slot on THIS thread for the return catch: on
        // that thread the slot is the return address until the call ends (an exception or
        // APC inside the original restores its context through NtContinue: see restore_fixup).
        if (slot == s->co_borrowed_slot && tid == s->in_call_tid) continue;
        const Probe *owner = nullptr;
        for (const auto &p : s->probes)
            if (p->active && (p->flags & PROBE_HW) && p->dr_slot == slot) { owner = p.get(); break; }
        // An inline install gate (arm_gates_for_pending) owns its slot like a probe: execute.
        uint64_t want = owner ? owner->address : 0;
        if (!owner) for (const auto &g : s->gates) if (g.second == slot) { want = g.first; break; }
        const DWORD64 ln = (DWORD64)1 << (slot * 2), fieldmask = (DWORD64)0xF << (16 + slot * 4);
        DWORD64 dr7 = c.Dr7;
        if (want && hw_yielded(s, c, slot)) continue;            // the program's own breakpoint: left alone
        if (want) {
            uint32_t rw = 0, len = 0;
            if (owner) hw_rw_len(owner->flags, rw, len);
            switch (slot) {
            case 0: c.Dr0 = (decltype(c.Dr0))want; break;
            case 1: c.Dr1 = (decltype(c.Dr1))want; break;
            case 2: c.Dr2 = (decltype(c.Dr2))want; break;
            default: c.Dr3 = (decltype(c.Dr3))want; break;
            }
            dr7 = (dr7 & ~fieldmask) | ln | ((DWORD64)(((len & 3u) << 2) | (rw & 3u)) << (16 + slot * 4));
        } else if (clear_stale && !(s->dr_used & (1u << slot)) && !target_owns_slot(s, tid, c, slot)) {
            dr7 &= ~(ln | fieldmask);                           // our stale slot (never the target's own)
        }
        c.Dr7 = (decltype(c.Dr7))dr7;
    }
}
bool handle_hw(probe_session *s, const DEBUG_EVENT &event, bool &handled) {
    handled = false;
    HANDLE thread = event_thread(s, event.dwThreadId);      // cached: see event_thread
    if (!thread) { set_error(s, win_error("open hw event thread")); return false; }
    CONTEXT native{}; native.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(thread, &native)) {                 // a stale cached handle (a missed EXIT_THREAD): reopen once
        forget_event_thread(s, event.dwThreadId);
        thread = event_thread(s, event.dwThreadId);
        if (!thread || !GetThreadContext(thread, &native)) { set_error(s, win_error("get hw context")); return false; }
    }
    const uint64_t dr_epoch_at_get = g_dr_epoch.load(std::memory_order_relaxed);
    native.Dr6 |= dr6_carried(s, event.dwThreadId);           // a status our own DR write zeroed
    // The program armed a slot of ours itself on this thread (its own hardware breakpoint): move
    // ours away first (hw_yield_to_target), so this #DB, if it is the program's, goes to it.
    // Then the live image again: the move rewrote this thread's debug registers (not DR6).
    if (s->dr_used & 0xF) {
        bool claimed = false;
        for (int slot = 0; slot < 4; ++slot) claimed = claimed || hw_yielded(s, native, slot);
        if (claimed) {
            hw_yield_to_target(s, event.dwThreadId, thread);
            CONTEXT dr{}; dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(thread, &dr)) {
                native.Dr0 = dr.Dr0; native.Dr1 = dr.Dr1; native.Dr2 = dr.Dr2; native.Dr3 = dr.Dr3; native.Dr7 = dr.Dr7;
            }
        }
    }
    uint8_t theirs = target_slots(s, event.dwThreadId, native);             // the target's own slots on this thread
    for (int slot = 0; slot < 4; ++slot)                                     // ... incl. ones ours yielded to it
        if (hw_yielded(s, native, slot)) theirs |= (uint8_t)(1u << slot);
    if (!(native.Dr6 & 0xF & s->dr_used) && !(native.Dr6 & 0xF & theirs) && !(native.Dr6 & 0x4000) &&
        !(native.EFlags & 0x100u)) {
        // A #DB that is neither a trap-flag step (BS clear, TF clear) nor flagged in DR6 for
        // one of our slots, AT the address of one of our execute probes: ours, but DR6 was
        // overwritten by the target writing a thread context it captured earlier (Suspend +
        // GetThreadContext / SetThreadContext round-trip racing this event). Passing it on
        // killed the target with an unhandled single step; recover the slot from the address.
#if defined(_WIN64)
        const uint64_t pc = native.Rip;
#else
        const uint64_t pc = native.Eip;
#endif
        for (auto &p : s->probes)
            if (p->active && (p->flags & PROBE_HW) && p->dr_slot >= 0 && !(p->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) &&
                p->address == pc)
                native.Dr6 |= (DWORD64)1 << p->dr_slot;
    }
    if (defer_hits_now(s, event.dwThreadId) && (native.Dr6 & 0xF)) {
        // Only pure execute hits can be replayed (a data watch has already happened).
        bool exec_only = true;
#if defined(_WIN64)
        const uint64_t pc = native.Rip;
#else
        const uint64_t pc = native.Eip;
#endif
        for (int slot = 0; slot < 4 && exec_only; ++slot) {
            if (!(native.Dr6 & (1u << slot))) continue;
            Probe *p = nullptr;
            for (auto &q : s->probes) if (q->active && (q->flags & PROBE_HW) && q->dr_slot == slot) { p = q.get(); break; }
            if (!p || p->internal || (p->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) || p->address != pc) exec_only = false;
        }
        if (exec_only && s->stepping.find(event.dwThreadId) == s->stepping.end() &&
            defer_hit_during_call(s, event.dwThreadId, pc, false)) {
            handled = true; return true;
        }
        if (!exec_only && s->stepping.find(event.dwThreadId) == s->stepping.end() &&
            hold_watch_hit(s, event, native, theirs)) {
            handled = true; return true;
        }
    }
    // Service EVERY debug-status bit that fired, not just the lowest: two probes can
    // share an address (both B-bits set), and clearing DR6 after handling only one
    // would silently drop the other. Callbacks compose on one context in slot order.
    bool any = false, exec_hit = false;
    DWORD64 consumed = 0;
    DWORD64 fired = native.Dr6 & 0xF;
    if (!fired) {
        // An execute breakpoint whose status was lost: a debug-register write from the
        // controller (arming another hardware probe on every thread) reached this thread
        // while its #DB was still waiting to be reported, and that write carries DR6 too,
        // so the B-bit reads 0 here. Found by examples/famous retval_override (the target
        // then died of an "unhandled" STATUS_SINGLE_STEP). An execute DR is unambiguous by
        // address: a trap exactly at an active hardware execute probe whose slot is
        // enabled on this thread is that probe's hit.
#if defined(_WIN64)
        const uint64_t pc = native.Rip;
#else
        const uint64_t pc = native.Eip;
#endif
        for (auto &p : s->probes)
            if (p->active && (p->flags & PROBE_HW) && !(p->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) &&
                p->address == pc && p->dr_slot >= 0 && p->dr_slot < 4 && ((native.Dr7 >> (p->dr_slot * 2)) & 1))
                fired |= (DWORD64)1 << p->dr_slot;
        if (fired && trace_enabled())
            std::fprintf(stderr, "  hw-dr6-lost tid=%lu pc=0x%llx inferred=0x%llx\n", (unsigned long)event.dwThreadId,
                         (unsigned long long)pc, (unsigned long long)fired);
    }
    std::vector<const Probe *> served;            // a probe fires once per #DB, even from two slots
    for (int slot = 0; slot < 4; ++slot) {
        if (!(fired & (1u << slot)) || (theirs & (1u << slot))) continue;
        Probe *probe = nullptr;
        for (auto &p : s->probes) if (p->active && (p->flags & PROBE_HW) && p->dr_slot == slot) { probe = p.get(); break; }
        if (!probe && (s->dr_ever & (1u << slot)) && !(theirs & (1u << slot))) {
            // Our image in a slot the probe has since left (moved off a slot the program uses,
            // see migrate_hw; the clear was lost on this thread): still that probe's hit.
#if defined(_WIN64)
            const uint64_t pc = native.Rip;
#else
            const uint64_t pc = native.Eip;
#endif
            for (auto &p : s->probes)
                if (p->active && (p->flags & PROBE_HW) && p->dr_slot >= 0 && !(p->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) &&
                    p->address == pc && dr_address(native, slot) == pc) { probe = p.get(); break; }
        }
        if (probe && std::find(served.begin(), served.end(), probe) != served.end()) {
            consumed |= (1u << slot); any = true; continue;
        }
        if (probe) served.push_back(probe);
        if (!probe) {
            // A slot we owned but have since released (PROBE_ONCE / unload): a #DB that was
            // already in flight on another thread. Swallow it rather than crash the app.
            if ((s->dr_ever & (1u << slot)) && !(theirs & (1u << slot))) { any = true; consumed |= (1u << slot); }
            continue;
        }
        consumed |= (1u << slot);
        any = true;
        #if defined(_WIN64)
        uint64_t hit_pc = native.Rip;
#else
        uint64_t hit_pc = native.Eip;
#endif
        // A watch hit while this thread runs a displaced copy: report the real code address.
        auto st = s->stepping.find(event.dwThreadId);
        if (st != s->stepping.end() && st->second.displaced && st->second.scratch &&
            hit_pc >= st->second.scratch && hit_pc <= st->second.scratch + st->second.insn_len)
            hit_pc = st->second.site + (hit_pc - st->second.scratch);
        else if (uint64_t tr = 0; const auto *d = dtramp_at(s, hit_pc, &tr)) hit_pc = d->site + (hit_pc - tr);
        if (!(probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW))) exec_hit = true;
        // Execute probes: pc == the probe address. Watchpoints trap AFTER the access, so
        // pc is the instruction following the store/load -- the real code location.
        if (!(probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) && hit_pc != probe->address) {
            any = true; continue;                                    // stale: slot was reassigned
        }
        probe_context context = from_context(native, probe_index(s, probe), hit_pc, &callback_ops, s);
        context.config = probe->config.empty() ? nullptr : probe->config.data();
        context.tid = event.dwThreadId;
        CallbackState state{s, probe, event.dwProcessId, event.dwThreadId}; context.controller = &state;
        if (thread_in_call(s, event.dwThreadId)) {                    // inside call_func/call_original: no re-entry
            if (s->co_addr && event.dwThreadId == s->in_call_tid && !(probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW))) {
#if defined(_WIN64)
                const uint64_t sp = native.Rsp;
#else
                const uint64_t sp = native.Esp;
#endif
                if ((sp >= s->co_sp || co_slot_gone(s, sp) || co_unwound(s, event.dwThreadId, native, hit_pc)) &&
                    defer_hit_during_call(s, event.dwThreadId, hit_pc, false)) {
                    s->co_left = true; handled = true; return true;   // left the call (see breakpoint)
                }
            }
            if (event.dwThreadId != s->quiet_tid) count_hit(probe);
            continue;
        }
        s->cb_tid = event.dwThreadId;
        try { run_callback(s, probe, &context); s->cb_tid = 0; }
        catch (const std::exception &e) { set_error(s, std::string("probe callback: ") + e.what()); return false; }
        catch (...) { set_error(s, "probe callback threw an unknown exception"); return false; }
        count_hit(probe);
        if (state.released) { s->skip_continue = true; handled = true; return true; }
        if (probe->flags & PROBE_ONCE) release_hw(s, *probe);
        to_context(context, native);                                 // fold each callback's changes forward
#if defined(_WIN64)
        native.Rsp = context.regs.rsp;
#else
        native.Esp = (DWORD)context.regs.rsp;
#endif
        apply_return_from(s, probe, context, native);               // Rip -> ret gadget, Rsp -> the hit's
    }
    if (!any) {                                                      // none of our DRs fired
        if (trace_enabled())
            std::fprintf(stderr, "  hw-not-ours tid=%lu dr6=0x%llx dr7=0x%llx dr0=0x%llx dr1=0x%llx dr2=0x%llx dr3=0x%llx "
                                 "used=0x%x ever=0x%x eflags=0x%lx\n", (unsigned long)event.dwThreadId,
                         (unsigned long long)native.Dr6, (unsigned long long)native.Dr7, (unsigned long long)native.Dr0,
                         (unsigned long long)native.Dr1, (unsigned long long)native.Dr2, (unsigned long long)native.Dr3,
                         s->dr_used, s->dr_ever, (unsigned long)native.EFlags);
        return true;
    }
    // RF only for EXECUTE breakpoints (fault-type: the instruction has not run yet). Data
    // watchpoints are trap-type -- the access already happened -- and RF would wrongly
    // suppress an execute breakpoint on the very next instruction.
    // Execute hits resume in the site's trampoline when the instruction can run there (no RF
    // to lose, see hw_trampoline) -- not for a #DB that is also the target's own (it sees this
    // context) nor if a callback moved the thread.
    if (exec_hit) {
        uint64_t tr = 0;
        if (!(native.Dr6 & 0xF & theirs) && !(native.EFlags & 0x100u) && !served.empty()) {
            Probe *first = const_cast<Probe *>(served.front());
            bool same = true;
            for (const Probe *q : served)
                same = same && !(q->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) && q->address == first->address;
            if (same && (uint64_t)EMU_IP(native) == first->address) tr = hw_trampoline(s, *first);
        }
        if (tr) EMU_IP(native) = (decltype(EMU_IP(native)))tr;
        else native.EFlags |= 0x10000u;
    }
    // Callbacks may have armed/released hardware probes (probe_watch, PROBE_ONCE), which
    // rewrote THIS thread's debug registers. Take the live DR image, not the stale one
    // captured before the callbacks, so the write-back below does not undo them.
    if (g_dr_epoch.load(std::memory_order_relaxed) != dr_epoch_at_get) {   // only if a DR write happened since
        CONTEXT dr{}; dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &dr)) {
            native.Dr0 = dr.Dr0; native.Dr1 = dr.Dr1; native.Dr2 = dr.Dr2; native.Dr3 = dr.Dr3; native.Dr7 = dr.Dr7;
        }
    }
    {                              // repair a DR write lost while this thread's event was queued
        const auto d7 = native.Dr7, d0 = native.Dr0, d1 = native.Dr1, d2 = native.Dr2, d3 = native.Dr3;
        enforce_owned_drs(s, event.dwThreadId, native, true);
        if (d7 != native.Dr7 || d0 != native.Dr0 || d1 != native.Dr1 || d2 != native.Dr2 || d3 != native.Dr3)
            std::fprintf(stderr, "probe: repaired hardware breakpoint state on thread %lu (dr7 0x%llx -> 0x%llx)\n",
                         (unsigned long)event.dwThreadId, (unsigned long long)d7, (unsigned long long)native.Dr7);
    }
    native.Dr6 &= ~consumed;     // clear only the status bits of slots we own
    if (!SetThreadContext(thread, &native)) { set_error(s, win_error("resume hw breakpoint")); return false; }
   
    // The same #DB also reports one of the target's OWN debug registers: it is the target's
    // exception too -- pass it on (our callbacks ran; their changes are applied above).
    handled = !(native.Dr6 & 0xF & theirs);
    return true;
}

} // namespace uhh_session
