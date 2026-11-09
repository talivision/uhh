// Callbacks and calls on breakpoint/hw: callback fibers, run_callback, call_func,
// call_original, return_from and their traps.
#include "session_internal.hpp"

namespace uhh_session {
#if defined(_WIN64)
#define UHH_POST_AX Rax
#else
#define UHH_POST_AX Eax
#endif

// ---- Callback fibers: concurrent call_func on breakpoint/hw ------------------------------
// A breakpoint/hw callback runs on the debug thread while its target thread is stopped at
// its event; call_func runs the callee ON that thread, so the callback has to wait while
// the loop keeps dispatching (the callee's own events, every other thread's hits). Each
// exception event is therefore handled on a fiber of the debug thread: call_func continues
// the event, parks the fiber and returns to whichever loop resumed it; the callee's return
// trap (or its fault, the 5 s timeout, the thread's or the process's end) resumes it.
// Other threads' code-probe hits are held back meanwhile (callbacks never overlap, see
// defer_hits_now); a hit that cannot be held back (a data watch, a thread mid-step) runs its
// callback during the call on its own fiber -- its call_func parks too, and the calls finish
// in any order. (The former single nested wait refused that call: it returned 0.)
// Only one event is outstanding per process at any time: a fiber parks only after
// continuing its own, and is resumed only at the event that ends its call.
static void WINAPI event_fiber_main(void *p) {
    auto *f = static_cast<EventFiber *>(p);
    for (;;) {
        f->disposition = DBG_CONTINUE;
        try { f->ok = dispatch_event(f->s, f->ev, f->disposition); }
        catch (const std::exception &e) { set_error(f->s, std::string("debug event: ") + e.what()); f->ok = false; }
        f->done = true;
        SwitchToFiber(f->return_to);
    }
}
EventFiber *fiber_get(probe_session *s) {
    if (!s->main_fiber) return nullptr;
    if (!s->fiber_pool.empty()) { EventFiber *f = s->fiber_pool.back(); s->fiber_pool.pop_back(); return f; }
    auto *f = new (std::nothrow) EventFiber;
    if (!f) return nullptr;
    f->s = s;
    f->fiber = CreateFiberEx(64 * 1024, 1024 * 1024, FIBER_FLAG_FLOAT_SWITCH, event_fiber_main, f);
    if (!f->fiber) { delete f; return nullptr; }
    return f;
}
// Run f until its handling finishes or parks in call_func. Finished: `ev` (the event f now
// stands at) is continued -- unless the handling did that itself, or its thread is held
// for it (resumed instead).
bool fiber_step(probe_session *s, EventFiber *f, const DEBUG_EVENT *ev) {
    const bool outer_skip = s->skip_continue;
    EventFiber *const outer = s->cur_fiber;
    const DWORD outer_cb = s->cb_tid, outer_event = s->event_tid;
    const Probe *const outer_probe = s->cb_probe;
    s->skip_continue = false;
    f->return_to = GetCurrentFiber();
    s->cur_fiber = f;
    SwitchToFiber(f->fiber);
    s->cur_fiber = outer; s->cb_tid = outer_cb; s->event_tid = outer_event; s->cb_probe = outer_probe;
    bool ok = true;
    if (f->done) {
        ok = f->ok;
        if (f->resume_after) {
            auto l = s->call_late.find(f->ev.dwThreadId);           // a timed-out call: where it was left
            CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
            if (l != s->call_late.end() && GetThreadContext(f->resume_after, &c)) l->second.ip = (uint64_t)UHH_PC(c);
            ResumeThread(f->resume_after); CloseHandle(f->resume_after); f->resume_after = nullptr;
            guard_resync(s);                         // our suspension is over: off the guard's list
        }
        else if (!s->skip_continue && ev) {
            guard_resync(s);                         // its handling is over: off the guard's list first
            if (!ContinueDebugEvent(ev->dwProcessId, ev->dwThreadId, f->disposition)) {
                set_error(s, win_error("continue debug event")); ok = false;
            }
        }
        f->done = false; f->stop_suspended = false;
        try { s->fiber_pool.push_back(f); } catch (...) { DeleteFiber(f->fiber); delete f; }
    }
    s->skip_continue = outer_skip;
    return ok;
}
// Called on a parked fiber by call_func: back to the loop that resumed it.
static void fiber_park(probe_session *s, EventFiber *f) {
    const DWORD cb = s->cb_tid, ev = s->event_tid;
    const Probe *const probe = s->cb_probe;
    SwitchToFiber(f->return_to);
    s->cb_tid = cb; s->event_tid = ev; s->cb_probe = probe;
}
bool call_resume(probe_session *s, DWORD tid, EventFiber::Outcome how, const DEBUG_EVENT *ev) {
    auto it = s->calls.find(tid);
    if (it == s->calls.end()) return true;
    EventFiber *f = it->second;
    s->calls.erase(it);
    f->call_outcome = how;
    if (ev || f->call_held) {                       // stopped at its trap/fault, or suspended by us
        handling_running(s, tid, false);
        guard_resync(s);                             // listed again before its context is touched
    }
    return fiber_step(s, f, ev);
}
// A thread running a call_func or call_original callee: its own probe hits are counted
// without a callback (no re-entry, as inline).
bool thread_in_call(const probe_session *s, DWORD tid) {
    return tid && (tid == s->in_call_tid || s->calls.count(tid) ||
                   (s->inline_add_wait_tid && (tid == s->remote_tid || agent_thread(s, tid))));
}
// Other threads' probe hits while a call_func or call_original is in flight are held back
// (defer_hit_during_call) and replayed when no call is left: breakpoint/hw callbacks never
// overlap (the documented contract), so a callback may hold a lock of its own across
// call_func. Only a hit that cannot be replayed (a data watch, a thread mid-step) runs its
// callback during the call -- on its own fiber, with its own call_func. The price, as
// before: a callee that waits for one of the held threads (a lock it holds at its probe
// hit) waits for the 5 s timeout (documented; owner decision: no hardening).
static void resume_deferred_hits(probe_session *s);
static void release_deferred(probe_session *s) {
    if (!s->in_call_tid && s->calls.empty() && !s->inline_add_wait_tid) resume_deferred_hits(s);
}
bool defer_hits_now(const probe_session *s, DWORD tid) {
    if (s->inline_add_wait_tid) return tid != s->inline_add_wait_tid && !thread_in_call(s, tid);
    if (s->in_call_tid) return tid != s->in_call_tid;                  // call_original
    return !s->calls.empty() && !s->calls.count(tid);                  // call_func (not the callee's own)
}
// The held data-watch hits (hold_watch_hit), once no call is in flight and no callback is
// running (only from a loop on the debug thread's own fiber): each event is handled again,
// on a fiber, with the thread stopped by our suspension instead of by the event.
static void drop_held_watch(probe_session *s, const probe_session::WatchHeld &h) {
    for (Probe *p : h.probes) if (p) { ++p->hits; s->controller_dropped.fetch_add(1, std::memory_order_relaxed); }
}
static void replay_held_watches(probe_session *s) {
    while (!s->watch_deferred.empty() && s->calls.empty() && !s->in_call_tid && !s->cur_fiber) {
        probe_session::WatchHeld h = s->watch_deferred.front();
        if (s->exited) { drop_held_watch(s, h); s->watch_deferred.erase(s->watch_deferred.begin()); CloseHandle(h.thread); continue; }
#if defined(UHH_TEST_HOOKS)
        static bool failed = false;
        const bool fail = !failed && std::getenv("UHH_TEST_WATCH_FIBER_FAIL");
        if (fail) { failed = true; std::fprintf(stderr, "probe: test: watch fiber denied\n"); }
        EventFiber *f = fail ? nullptr : fiber_get(s);
#else
        EventFiber *f = fiber_get(s);
#endif
        if (!f) break;                          // retain the hit and its suspension for the next poll
        s->watch_deferred.erase(s->watch_deferred.begin());
        f->ev = h.ev; f->resume_after = h.thread; f->stop_suspended = true;
        fiber_step(s, f, nullptr);
    }
}
// The 5 s call_func timeout; calls whose callee returned while a call_original ran
// (resumed once it is over: call_original allows no other one meanwhile).
bool poll_calls(probe_session *s) {
    bool ok = true;
    for (bool again = !s->calls.empty(); again; ) {
        again = false;
        const ULONGLONG now = GetTickCount64();
        for (auto &c : s->calls) {
            EventFiber *f = c.second;
            EventFiber::Outcome how = EventFiber::WAITING;
            if (f->call_held && !s->in_call_tid) how = f->call_outcome;
            else if (!f->call_held && now > f->call_deadline) how = EventFiber::TIMEOUT;
            if (how == EventFiber::WAITING) continue;
            ok = call_resume(s, c.first, how, nullptr) && ok;   // may add/remove calls: rescan
            again = true; break;
        }
    }
    if (!s->cur_fiber) release_deferred(s);      // runtime inline waits can also defer hits
    replay_held_watches(s);
    return ok;
}
// End every parked call (the process is gone, or the session stops dispatching).
void finish_calls(probe_session *s) {
    s->calls_closing = true;
    while (!s->calls.empty()) {
        auto it = s->calls.begin();
        EventFiber::Outcome how = s->exited ? EventFiber::EXITED : it->second->call_held ? it->second->call_outcome
                                                                                          : EventFiber::TIMEOUT;
        call_resume(s, it->first, how, nullptr);
    }
    s->calls_closing = false;
    if (!s->exited) release_deferred(s);
    replay_held_watches(s);
    for (auto &h : s->watch_deferred) { drop_held_watch(s, h); ResumeThread(h.thread); CloseHandle(h.thread); }   // (not on the main fiber)
    s->watch_deferred.clear();
}

// The same wipe through EVERY context restore: a thread inside exception dispatch (an
// exception filter, a vectored handler) or a user APC when a hardware probe is armed or
// released resumes through NtContinue with the context the kernel captured BEFORE that --
// debug registers included -- so the new probe never fires on it (or a released one comes
// back). Library-owned breakpoints at ntdll!NtContinue / NtContinueEx bring the debug-register
// image of the context about to be restored up to date first: our ACTIVE probes' slots only
// (a handler may have just armed the program's own DR in that record: regress cdx-owndrx). Armed
// with the thread-start fixup: once a hardware probe is armed or released at runtime.
static bool ensure_call_trap(probe_session *s);
void restore_fixup(probe_context *c) {
    probe_session *s = get_session(c);
    if (!s || !s->dr_ever) return;
    uint64_t rec = 0;
#if defined(_WIN64)
    rec = c->regs.rcx;                                       // NtContinue[Ex](PCONTEXT, ...)
#else
    uint32_t r32 = 0; size_t got = 0;                        // stdcall: [esp] = return, [esp+4] = PCONTEXT
    if (!remote_read(s->pi.hProcess, c->regs.rsp + 4, &r32, 4, &got) || got != 4) return;
    rec = r32;
#endif
    CONTEXT img{};
    const size_t at = offsetof(CONTEXT, ContextFlags), len = offsetof(CONTEXT, Dr7) + sizeof(img.Dr7) - at;
    size_t n = 0;
    if (!rec || !remote_read(s->pi.hProcess, rec + at, reinterpret_cast<char *>(&img) + at, len, &n) || n != len) return;
    if (trace_enabled())
        std::fprintf(stderr, "  restore-fixup tid=%lu flags=0x%lx dr7=0x%llx\n", (unsigned long)c->tid,
                     (unsigned long)img.ContextFlags, (unsigned long long)img.Dr7);
    if ((img.ContextFlags & CONTEXT_DEBUG_REGISTERS) != CONTEXT_DEBUG_REGISTERS) {
#if !defined(_WIN64)
        // WOW64: a 32-bit record WITHOUT debug registers (a user APC's: flags 0x10003) is
        // continued by the 64-bit layer from ITS copy of the context -- the DR image captured
        // before the arm, out of a 32-bit debugger's reach. Re-apply after the restore and
        // BEFORE the first instruction runs: the record resumes at our private INT3
        // (call_trap), where restore_resume_hit puts the DRs back and the thread at its real EIP.
        if ((!s->hw_active && s->gates.empty()) || !(img.ContextFlags & CONTEXT_CONTROL & ~CONTEXT_i386) || !ensure_call_trap(s)) return;
        DWORD eip = 0; size_t got = 0;
        const uint64_t at_eip = rec + offsetof(CONTEXT, Eip);
        if (!remote_read(s->pi.hProcess, at_eip, &eip, 4, &got) || got != 4 || eip == (DWORD)s->call_trap) return;
        const DWORD trap = (DWORD)s->call_trap;
        if (remote_write(s->pi.hProcess, at_eip, &trap, 4, &got) && got == 4) s->restore_resume[c->tid] = eip;
#endif
        return;                                              // DRs not restored from this record
    }
    const CONTEXT before = img;
    // Our ACTIVE probes only. Everything else stays as the record has it: a handler may have
    // armed the program's own DR there -- even at an address we watched once and released
    // (cdx-owndrx) -- and a stale image of a released probe of ours is recognised at the
    // thread's next #DB anyway (hw_unsettled).
    enforce_owned_drs(s, c->tid, img, false);
    if (img.Dr0 == before.Dr0 && img.Dr1 == before.Dr1 && img.Dr2 == before.Dr2 && img.Dr3 == before.Dr3 &&
        img.Dr7 == before.Dr7) return;
    if (trace_enabled())
        std::fprintf(stderr, "  restore-fixup tid=%lu rewritten dr7 0x%llx -> 0x%llx\n", (unsigned long)c->tid,
                     (unsigned long long)before.Dr7, (unsigned long long)img.Dr7);
    const size_t d0 = offsetof(CONTEXT, Dr0), dn = offsetof(CONTEXT, Dr6) - d0;     // Dr0..Dr3
    remote_write(s->pi.hProcess, rec + d0, reinterpret_cast<char *>(&img) + d0, dn, &n);
    remote_write(s->pi.hProcess, rec + offsetof(CONTEXT, Dr7), &img.Dr7, sizeof(img.Dr7), &n);
}
void arm_restore_fixup(probe_session *s) {
    if (s->restore_fixup || !(s->entry_seen || s->attached)) return;
    s->restore_fixup = true;
    static const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");   // same bitness and build as the target's
    for (const char *name : {"NtContinue", "NtContinueEx"}) {
        if (!GetProcAddress(ntdll, name)) continue;          // NtContinueEx: Windows 10 2004+
        const uint64_t at = resolve_symbol(s, (std::string("ntdll.dll!") + name).c_str());
        if (!at || probe_at(s, at)) continue;                // a user probe owns the site: rare, left as is
        try {
            auto p = std::make_unique<Probe>();
            p->location = "<context-restore>"; p->flags = PROBE_BREAKPOINT; p->callback = restore_fixup;
            p->rva = at; p->internal = true;
            Probe *raw = p.get(); { std::lock_guard<std::mutex> lock(s->probes_mu); s->probes.push_back(std::move(p)); }
            std::string saved = s->error;
            if (!arm_breakpoint(s, *raw, 0)) { raw->retired = true; s->error = saved; }
        } catch (...) {}
    }
}

// call_original (breakpoint/hw): the call's thread is DEEPER than the hit's frame (sp < co_sp),
// and yet the original has been left (ROADMAP F5). While the original runs, the return
// address the call pushed stays in its slot at co_sp (the original's frame is below it).
// Once an exception or longjmp left it, the program's next calls from the frame that caught
// it reuse that stack: the slot is overwritten (a return address into the catching frame,
// a local). So a slot no longer holding co_ret means the original's frame is gone -- unless
// co_ret lies in one of the few slots just below it (a thunk that moved its own return
// address down: still inside). A slot still holding co_ret proves nothing either way (a left
// frame whose slot was not reused yet): such a hit stays counted without a callback, as
// before, until the thread is seen above, the slot changes, or the 5 s release.
bool co_slot_gone(probe_session *s, uint64_t sp) {
    if (!s->co_addr || !s->co_ret || sp >= s->co_sp) return false;
    const size_t w = sizeof(void *);
    uint64_t v = 0; size_t n = 0;
    if (!remote_read(s->pi.hProcess, s->co_sp, &v, w, &n) || n != w || v == s->co_ret) return false;
    const uint64_t lo = std::max(sp, s->co_sp >= 64 ? s->co_sp - 64 : 0);
    unsigned char below[64];
    const size_t len = (size_t)(s->co_sp - lo);
    if (len && (!remote_read(s->pi.hProcess, lo, below, len, &n) || n != len)) return false;
    for (size_t o = len; o >= w; o -= w) {
        uint64_t x = 0;
        std::memcpy(&x, below + o - w, w);
        if (x == s->co_ret) return false;
    }
    return true;
}

// call_original (breakpoint/hw), a hit deeper than the hit's frame whose slot still holds
// co_ret (co_slot_gone has no answer): an exception was raised on the call's thread during
// the call (at SP co_exc_sp) and this thread is below that point -- in its dispatch (a VEH,
// a filter, a C++ catch block: those run on the dispatch's stack while the frames the
// exception passed are still physically there) or in deeper code since. The unwinder tells
// which frames are logically live: from here it walks up through the dispatch into the
// raise point and on through every live frame, the original's included -- unless the
// exception was already unwound past the original to a catching frame above it (a C++
// catch block: its frames unwind straight into the catching frame, x64 through the unwind
// consolidation frame, x86 through the catching frame's EBP). So the original is LEFT iff
// the walk reaches the frame above the hit's (sp >= co_sp + ptr) directly from below the
// raise point, never through a frame between the raise point and the hit's frame (the
// original's own, or a live callee's). x86 walks lean on frame pointers / FPO data, so a
// LEFT there also needs the SEH chain to agree: no registration left between the raise
// point and the hit's frame (an unwind to a frame above removed every one of them; a live
// original keeps its own). A walk that stops early decides nothing (inside, as before).
static uint64_t thread_teb(HANDLE thread, const CONTEXT &ctx);
bool co_unwound(probe_session *s, DWORD tid, const CONTEXT &at, uint64_t pc) {
    if (!s->co_addr || !s->co_ret || !s->co_exc_sp || !s->sym_ready) return false;
    CONTEXT w = at;
#if defined(_WIN64)
    w.Rip = pc;
    const uint64_t sp = w.Rsp;
#else
    w.Eip = (DWORD)pc;
    const uint64_t sp = w.Esp;
#endif
    if (sp >= s->co_exc_sp || sp >= s->co_sp) return false;
    HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!t) return false;
    std::vector<std::pair<uint64_t, uint64_t>> fr;
    uhh_sym::unwind_frames(s->pi.hProcess, t, w, fr, 512);
    const uint64_t above = s->co_sp + sizeof(void *);
    uint64_t prev = sp;
    bool left = false;
    for (const auto &f : fr) {
        if (f.second >= above) { left = prev < s->co_exc_sp; break; }
        prev = f.second;
    }
#if !defined(_WIN64)
    const uint64_t teb = left ? thread_teb(t, at) : 0;
    if (left && !teb) left = false;
    uint32_t rec = 0; size_t n = 0;
    if (left && (!remote_read(s->pi.hProcess, teb, &rec, 4, &n) || n != 4)) left = false;
    for (int i = 0; left && i < 256 && rec != 0xFFFFFFFFu && rec <= s->co_sp; ++i) {
        if (rec >= s->co_exc_sp) { left = false; break; }         // a registered frame still live in between
        if (!remote_read(s->pi.hProcess, rec, &rec, 4, &n) || n != 4) left = false;
    }
#endif
    CloseHandle(t);
    if (trace_enabled() && left)
        std::fprintf(stderr, "  call_original: tid=%lu left (unwound past the hit's frame at a hit below the raise point)\n",
                     (unsigned long)tid);
    return left;
}

// While one callback's call_original runs the original in place, another thread that hits
// a probe must not run ITS callback now: that callback may call call_original too, and only
// one can be in flight. Instead the hit is undone -- the thread is put back AT the probe
// address (an INT3 hit rewinds over the 0xCC; an execute #DB has not run the instruction)
// and suspended. When the call finishes it is resumed and hits the probe again, normally:
// counted once, its callback runs with call_original available. (call_func needs none of
// this: concurrent calls each park on their own fiber, see "Callback fibers".)
bool defer_hit_during_call(probe_session *s, DWORD tid, uint64_t address, bool rewind_ip) {
    HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                          FALSE, tid);                     // (QUERY_LIMITED: GetThreadId, guard_sync)
    if (!t) return false;
    CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    bool ok = !!GetThreadContext(t, &w);
    if (ok) {
        if (rewind_ip) {
#if defined(_WIN64)
            w.Rip = address;
#else
            w.Eip = (DWORD)address;
#endif
        }
        w.Dr6 = 0;
        w.EFlags &= ~0x10000u;                   // no RF: the probe must fire again
        ok = !!SetThreadContext(t, &w);
    }
    if (ok) guard_note_hold(s, tid);
    if (ok && SuspendThread(t) != (DWORD)-1) {
        try { s->call_deferred.push_back(t); return true; } catch (...) { ResumeThread(t); }
    }
    CloseHandle(t);
    return false;
}

static void resume_deferred_hits(probe_session *s) {
    const bool any = !s->call_deferred.empty();
    for (HANDLE t : s->call_deferred) { ResumeThread(t); CloseHandle(t); }
    s->call_deferred.clear();
    if (any) guard_resync(s);                                // our suspensions are over: off the list
}

// A data-watch hit while a call is in flight cannot be replayed by re-executing (the access
// has happened), but its callback can wait: the thread is held (suspended) right after the
// access, its status bits kept for its event (dr6_lost: it has not run since), and the event
// is handled again -- callback, call_func and all -- once no call is left (replay_held_watches).
// Only a hit that is ours alone: every status bit one of our data watches (none of the
// target's own slots, no execute probe sharing it).
bool hold_watch_hit(probe_session *s, const DEBUG_EVENT &event, const CONTEXT &native, uint8_t theirs) {
    const DWORD64 fired = native.Dr6 & 0xF;
    if (!fired || (fired & theirs) || (native.Dr6 & 0xE000u)) return false;
    probe_session::Dr6Lost saved{};
    saved.regs = native; saved.bits = fired;
    probe_session::WatchHeld held; held.ev = event;
    for (int slot = 0; slot < 4; ++slot) {
        if (!(fired & (1u << slot))) continue;
        Probe *p = nullptr;
        for (auto &q : s->probes) if (q->active && (q->flags & PROBE_HW) && q->dr_slot == slot) { p = q.get(); break; }
        if (!p || p->internal || !(p->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW))) return false;
        // Replayed watches use the same ownership check as queued #DBs. Preserve the
        // identity at the access, including an older identity already carried here.
        const bool carried = (dr6_carried(s, event.dwThreadId) & (1u << slot)) != 0;
        saved.address[slot] = carried ? s->dr6_carry_address[slot] : dr_address(native, slot);
        saved.generation[slot] = carried ? s->dr6_carry_generation[slot] : p->hw_generation;
        held.probes[slot] = p;
    }
    HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                          FALSE, event.dwThreadId);
    if (!t) return false;
    guard_note_hold(s, event.dwThreadId);
    if (SuspendThread(t) == (DWORD)-1) { CloseHandle(t); return false; }
    try {
        s->dr6_lost[event.dwThreadId] = saved;
        held.thread = t; s->watch_deferred.push_back(held);
    } catch (...) { ResumeThread(t); CloseHandle(t); return false; }
    if (trace_enabled()) std::fprintf(stderr, "  watch hit held during a call tid=%lu dr6=0x%llx\n",
                                      (unsigned long)event.dwThreadId, (unsigned long long)fired);
    return true;
}

// Raised by call_original (breakpoint/hw) to end a callback whose original left without
// returning (it raised, longjmp'd or ran past the call timeout): the thread runs on natively.
static const DWORD UHH_CALL_RELEASED = 0xE0554843u;
// Runs a breakpoint/hw callback in the controller under SEH, the way the inline agent runs
// it inside the target: a callback that faults (a bad pointer, a target address used as a
// controller pointer, ...) is abandoned -- the hit still counts, its register changes are
// discarded, the target continues -- instead of killing the controller (and with it the
// target). A C++ exception thrown out of the callback is treated the same way, exactly as
// the agent's SEH guard treats it inline (it used to end the whole session with "probe
// callback threw" on breakpoint/hw only). Caught by SEH on purpose: under /EHsc a C++
// try/catch around a call through an extern "C" callback pointer may be elided.
static bool seh_callback(probe_callback cb, probe_context *c, DWORD *code) {
    // Enough stack left for a callback's own stack overflow to reach the __except below
    // (probe_callback_stack_guarantee): set once per callback thread, raised only.
    static thread_local bool guaranteed = false;
    if (!guaranteed) {
        guaranteed = true;
        ULONG now = 0, want = probe_callback_stack_guarantee();
        if (SetThreadStackGuarantee(&now) && now < want) SetThreadStackGuarantee(&want);
    }
    __try { cb(c); return true; }
    __except (*code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {}
    if (*code == EXCEPTION_STACK_OVERFLOW) _resetstkoflw();      // the guard page, for the next overflow
    return false;
}
// Hardware shadow stacks (CET): after a completed in-place call_original the original's own
// `ret` has popped this frame's shadow-stack entry, and Windows refuses to move SSP back down
// (measured, windows-2025). The hooked function therefore cannot run a second time on
// fall-through: it returns to its caller with the original's result (as for a faulting
// callback), with one warning. Without shadow stacks nothing changes.
static void cet_after_original(probe_session *s, Probe *probe, probe_context *c) {
    auto *st = static_cast<CallbackState *>(c->controller);
    if (!c->called_original || c->returned || !st || !st->have_post || !target_has_shadow_stack(s)) return;
#if !defined(_WIN64)
    if (c->orig_pop < 0 || c->orig_pop > 1020 || (c->orig_pop & 3)) return;
    c->ret_pop = (uint32_t)c->orig_pop; c->regs.rdx = c->orig_edx;
#endif
    c->regs.rax = (uint64_t)st->post.UHH_POST_AX;
    c->returned = 1;
    if (!probe->warned_double_run) {
        probe->warned_double_run = true;
        std::fprintf(stderr, "probe: warning: %s: call_original without return_from under CET shadow stacks: the "
                     "original's result is returned (it cannot run twice). Further cases are not reported.\n",
                     probe->location.c_str());
    }
}
void run_callback(probe_session *s, Probe *probe, probe_context *c) {
    const probe_regs before = c->regs;
    DWORD code = 0;
    const Probe *const outer = s->cb_probe;          // a nested event's callback (call_func) restores it
    s->cb_probe = probe;
    const bool done = seh_callback(probe->callback, c, &code);
    s->cb_probe = outer;
    if (done) { cet_after_original(s, probe, c); return; }
    if (code == UHH_CALL_RELEASED) { c->regs = before; return; }   // call_original ended the callback (see there)
    // A faulting callback is a no-op: its register changes are discarded and a return_from it
    // asked for is dropped (the hit falls through into the original) -- exactly as inline
    // (agent.cpp call_mid). Unless call_original already RAN the original: falling through
    // would run it a second time (a double free / double close), so the hooked function
    // returns to its caller as with return_from -- return_from's value if one was set, else
    // the original's own result (x86: EDX:EAX and the bytes its `ret N` popped) -- with
    // everything else the original left (apply_return_from, CallbackState::faulted).
    auto *st = static_cast<CallbackState *>(c->controller);
    const bool ran = c->called_original && st && st->have_post;
    const bool was_returned = c->returned != 0;
    const uint64_t ax = was_returned ? c->regs.rax : ran ? (uint64_t)st->post.UHH_POST_AX : 0;
    const uint64_t dx = was_returned ? c->regs.rdx : c->orig_edx;
    c->regs = before;
    c->returned = 0;
    if (ran) {
        bool ok = true;
#if !defined(_WIN64)
        if (!was_returned) {
            if (c->orig_pop < 0 || c->orig_pop > 1020 || (c->orig_pop & 3)) ok = false;   // not measured: as inline
            else c->ret_pop = (uint32_t)c->orig_pop;
        }
        if (ok) c->regs.rdx = dx;
#else
        (void)dx;
#endif
        if (ok) { c->regs.rax = ax; c->returned = 1; st->faulted = true; }
    }
    if (!s->warned_cb_fault) {
        s->warned_cb_fault = true;
        std::fprintf(stderr, "probe: warning: callback for %s raised 0x%08lx; abandoned (hit counted, no register "
                     "changes applied). Further faults are not reported.\n", probe->location.c_str(), (unsigned long)code);
    }
}

// return_from resumes the hit thread at a real `ret` (x86 stdcall: `ret N`) with SP at the
// hit's return address, so the CPU pops the stack and any CET shadow stack together.
// One page in the target: offset 0 holds C3, offset 4k holds C2 imm16(4k) -- the gadget
// for `pop` bytes is at base + pop.
static uint64_t ret_gadget(probe_session *s, uint32_t pop) {
    if (pop % 4 || pop > 1020) return 0;
    if (!s->ret_gadgets) {
        unsigned char code[1024]; std::memset(code, 0xCC, sizeof(code));
        code[0] = 0xC3;
        for (uint32_t k = 4; k < sizeof(code); k += 4) { code[k] = 0xC2; code[k + 1] = (unsigned char)k; code[k + 2] = (unsigned char)(k >> 8); }
        void *mem = VirtualAllocEx(s->pi.hProcess, nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        size_t w = 0; DWORD old = 0;
        if (!mem) return 0;
        if (!remote_write(s->pi.hProcess, (uint64_t)(uintptr_t)mem, code, sizeof(code), &w) || w != sizeof(code) ||
            !VirtualProtectEx(s->pi.hProcess, mem, sizeof(code), PAGE_EXECUTE_READ, &old)) {
            VirtualFreeEx(s->pi.hProcess, mem, 0, MEM_RELEASE); return 0;
        }
        FlushInstructionCache(s->pi.hProcess, mem, sizeof(code));
        s->ret_gadgets = (uint64_t)(uintptr_t)mem;
        s->scratch_blocks.push_back(s->ret_gadgets);
    }
    return s->ret_gadgets + pop;
}
// The first call_original / return_from warning of a probe also goes to the LOG as one
// "uhh warning: <text>" record -- the record the inline agent emits (it has no stderr), so
// a log carries the same records on every backend.
void warn_record(probe_context *c, Probe *probe, const char *text, bool *warned) {
    if (!c || !probe) return;
    bool &once = warned ? *warned : probe->warned_log;
    if (once) return;
    once = true;
    send_log(c, "uhh warning: %s", text);
}
// After a callback: apply return_from (resume at the gadget, SP = the hit's) and return
// true; or warn once when call_original ran but the hit will fall through into the body.
bool apply_return_from(probe_session *s, Probe *probe, const probe_context &c, CONTEXT &native) {
    if (!c.returned) {
        if (c.called_original) warn_record(const_cast<probe_context *>(&c), probe,
                                           "call_original without return_from -- the original runs again on fall-through");
        if (c.called_original && !probe->warned_double_run) {
            probe->warned_double_run = true;
            std::fprintf(stderr, "probe: warning: %s: call_original without return_from -- the original runs again "
                         "on fall-through. Further cases are not reported.\n", probe->location.c_str());
        }
        return false;
    }
    uint64_t g = ret_gadget(s, c.ret_pop);
    auto *st = static_cast<CallbackState *>(c.controller);
    if (g && c.called_original && st && st->have_post) {
        // The caller gets what the original left (see CallbackState::post): its whole FP state
        // as it returned (XMM0 / x87 ST0 results; the nonvolatile parts are the hit's anyway,
        // ABI) and the volatile GPRs the callback did not set_reg after the call. x86 EDX is
        // already the original's unless return_from set a high half (probe_x86_return_regs).
        const CONTEXT &a = st->post;
#define UHH_KEEP(f, r) if (st->faulted || c.regs.r == st->post_seen.r) native.f = a.f;
#if defined(_WIN64)
        UHH_KEEP(Rcx, rcx) UHH_KEEP(Rdx, rdx) UHH_KEEP(R8, r8) UHH_KEEP(R9, r9) UHH_KEEP(R10, r10) UHH_KEEP(R11, r11)
        native.FltSave = a.FltSave; native.MxCsr = a.MxCsr;
#else
        UHH_KEEP(Ecx, rcx)
        native.FloatSave = a.FloatSave;
        std::memcpy(native.ExtendedRegisters, a.ExtendedRegisters, sizeof(native.ExtendedRegisters));
#endif
#undef UHH_KEEP
        native.ContextFlags |= UHH_CONTEXT_FP;
    }
    if (!g) {
        warn_record(const_cast<probe_context *>(&c), probe, "return_from could not be applied (no return thunk); the original runs");
        if (!probe->warned_double_run) {
            probe->warned_double_run = true;
            std::fprintf(stderr, "probe: warning: %s: return_from could not be applied (no return gadget); falling through\n",
                         probe->location.c_str());
        }
        return false;
    }
    // CET: the original already returned for real (its `ret` popped the shadow stack), so the
    // gadget's `ret` would pop the CALLER's shadow entry -- a #CP the kernel fixes up only in
    // compatibility mode (non-image code), fatal in strict mode. Resume directly where that
    // `ret` goes instead: the return address at the hit's SP, the stack popped past it.
    if (c.called_original && st && st->have_post && target_has_shadow_stack(s)) {
        uint64_t ra = 0; size_t n = 0;
        if (remote_read(s->pi.hProcess, c.hit_sp, &ra, sizeof(void *), &n) && n == sizeof(void *)) {
#if defined(_WIN64)
            native.Rip = ra; native.Rsp = c.hit_sp + 8 + c.ret_pop;
#else
            native.Eip = (DWORD)ra; native.Esp = (DWORD)(c.hit_sp + 4 + c.ret_pop);
#endif
            return true;
        }
    }
#if defined(_WIN64)
    native.Rip = g; native.Rsp = c.hit_sp;
#else
    native.Eip = (DWORD)g; native.Esp = (DWORD)c.hit_sp;
#endif
    return true;
}

// The stopped thread's TEB in the target (0 if unknown): call_func restores the thread's
// last error / last status there, as the inline agent does around every callback -- the
// callee's Win32 calls must not leak into the program (GetLastError after the probed code).
static uint64_t thread_teb(HANDLE thread, const CONTEXT &ctx) {
#if defined(_WIN64)
    (void)ctx;
    struct { LONG status; PVOID teb; ULONG_PTR pid, tid, affinity; LONG prio, base; } tbi{};
    using QueryFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto query = reinterpret_cast<QueryFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    return query && query(thread, 0 /* ThreadBasicInformation */, &tbi, sizeof(tbi), nullptr) >= 0 ? (uint64_t)(uintptr_t)tbi.teb : 0;
#else
    LDT_ENTRY e{};                               // FS base = the 32-bit TEB (WOW64 too)
    if (!GetThreadSelectorEntry(thread, ctx.SegFs, &e)) return 0;
    return (uint64_t)((DWORD)e.BaseLow | ((DWORD)e.HighWord.Bytes.BaseMid << 16) | ((DWORD)e.HighWord.Bytes.BaseHi << 24));
#endif
}
#if defined(_WIN64)
static const uint64_t TEB_LAST_ERROR = 0x68, TEB_LAST_STATUS = 0x1250;
#else
static const uint64_t TEB_LAST_ERROR = 0x34, TEB_LAST_STATUS = 0xBF4;
#endif
struct TebErrors {
    uint64_t teb = 0; DWORD error = 0, status = 0; bool ok = false;
    void save(HANDLE process, HANDLE thread, const CONTEXT &ctx) {
        size_t n1 = 0, n2 = 0;
        teb = thread_teb(thread, ctx);
        ok = teb && remote_read(process, teb + TEB_LAST_ERROR, &error, 4, &n1) && n1 == 4 &&
             remote_read(process, teb + TEB_LAST_STATUS, &status, 4, &n2) && n2 == 4;
    }
    void restore(HANDLE process) const {
        size_t n = 0;
        if (!ok) return;
        remote_write(process, teb + TEB_LAST_ERROR, &error, 4, &n);
        remote_write(process, teb + TEB_LAST_STATUS, &status, 4, &n);
    }
};

// Hardware shadow stacks (CET, x64): the thread's user shadow-stack pointer, read or written
// through the CET_U XSTATE component ({IA32_U_CET, IA32_PL3_SSP}). false = not available
// (no CET state on this machine/thread, or the kernel refused the change).
static bool thread_ssp(HANDLE thread, uint64_t *get, const uint64_t *set) {
#if defined(_WIN64) && defined(XSTATE_MASK_CET_U)
    using InitFn = BOOL(WINAPI *)(PVOID, DWORD, PCONTEXT *, PDWORD);
    using MaskFn = BOOL(WINAPI *)(PCONTEXT, DWORD64);
    using LocateFn = PVOID(WINAPI *)(PCONTEXT, DWORD, PDWORD);
    using EnabledFn = DWORD64(WINAPI *)();
    static HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    static auto init = reinterpret_cast<InitFn>(GetProcAddress(k32, "InitializeContext"));
    static auto mask = reinterpret_cast<MaskFn>(GetProcAddress(k32, "SetXStateFeaturesMask"));
    static auto locate = reinterpret_cast<LocateFn>(GetProcAddress(k32, "LocateXStateFeature"));
    static auto enabled = reinterpret_cast<EnabledFn>(GetProcAddress(k32, "GetEnabledXStateFeatures"));
    if (!init || !mask || !locate || !enabled || !(enabled() & XSTATE_MASK_CET_U)) return false;
    DWORD len = 0;
    init(nullptr, CONTEXT_CONTROL | CONTEXT_XSTATE, nullptr, &len);
    if (!len) return false;
    std::vector<unsigned char> buf(len);
    PCONTEXT ctx = nullptr;
    if (!init(buf.data(), CONTEXT_CONTROL | CONTEXT_XSTATE, &ctx, &len) || !mask(ctx, XSTATE_MASK_CET_U) ||
        !GetThreadContext(thread, ctx))
        return false;
    DWORD n = 0;
    auto *cet = static_cast<uint64_t *>(locate(ctx, XSTATE_CET_U, &n));
    if (!cet || n < 2 * sizeof(uint64_t)) return false;
    if (get) *get = cet[1];
    if (!set) return true;
    cet[1] = *set;
    ctx->ContextFlags = CONTEXT_XSTATE;                    // only the CET_U component
    return SetThreadContext(thread, ctx) != FALSE;
#else
    (void)thread; (void)get; (void)set;                   // x86: Windows enforces no shadow stack for WoW64
    return false;
#endif
}

// One INT3 in the target, ours alone: call_func's callees return into it (and x86 context
// restores are sent through it, see restore_fixup). It is preceded by `call rax|eax`: call_func
// enters the callee THROUGH that call (thread at call_trap - 2, rax/eax = the function), so the
// CPU pushes the return address = call_trap -- on the CET shadow stack too: the callee's `ret`
// matches, comes back to the INT3, and SSP is where it was at the hit. (Entering the callee by
// SetThreadContext with a hand-written return address made its `ret` a #CP under CET.)
// After the INT3 (call_trap + 1): the stack probe (see call_in_target). Entered with SP = the
// hit's and R10 / ECX = the lowest address the call frame needs, it reads one byte per page
// from SP down to that address -- __chkstk's walk: the thread touches its own stack page after
// page, each touch of the guard page makes Windows commit it and move the guard (and the TEB's
// StackLimit) one page down -- then jumps to the INT3. No call, no ret: the shadow stack is
// untouched.
static bool ensure_call_trap(probe_session *s) {
    if (s->call_trap) return true;
#if defined(_WIN64)
    static const unsigned char kStub[] = {
        0xFF, 0xD0, 0xCC,                                   // call rax; int3 (call_trap)
        0x49, 0x89, 0xE3,                                   // mov r11, rsp
        0x41, 0x84, 0x03,                                   // 1: test [r11], al
        0x49, 0x81, 0xEB, 0x00, 0x10, 0x00, 0x00,           //    sub r11, 0x1000
        0x4D, 0x39, 0xD3,                                   //    cmp r11, r10
        0x77, 0xF1,                                         //    ja 1b
        0x41, 0x84, 0x02,                                   // test [r10], al
        0xEB, 0xE8};                                        // jmp call_trap
#else
    static const unsigned char kStub[] = {
        0xFF, 0xD0, 0xCC,                                   // call eax; int3 (call_trap)
        0x89, 0xE2,                                         // mov edx, esp
        0x84, 0x02,                                         // 1: test [edx], al
        0x81, 0xEA, 0x00, 0x10, 0x00, 0x00,                 //    sub edx, 0x1000
        0x39, 0xCA,                                         //    cmp edx, ecx
        0x77, 0xF4,                                         //    ja 1b
        0x84, 0x01,                                         // test [ecx], al
        0xEB, 0xED};                                        // jmp call_trap
#endif
    void *mem = VirtualAllocEx(s->pi.hProcess, nullptr, sizeof(kStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    size_t w = 0;
    if (!mem) return false;
#if defined(UHH_TEST_HOOKS)
    if (std::getenv("UHH_TEST_CALL_STUB_TRACE"))
        std::fprintf(stderr, "probe: test: call stub %llx\n", (unsigned long long)(uintptr_t)mem);
    static bool write_failed = false;
    const bool fail_write = !write_failed && std::getenv("UHH_TEST_CALL_STUB_FAIL");
    if (fail_write) write_failed = true;
#else
    const bool fail_write = false;
#endif
    if (fail_write || !remote_write(s->pi.hProcess, (uint64_t)(uintptr_t)mem, kStub, sizeof(kStub), &w) || w != sizeof(kStub)) {
        VirtualFreeEx(s->pi.hProcess, mem, 0, MEM_RELEASE); return false;
    }
    try { s->scratch_blocks.push_back((uint64_t)(uintptr_t)mem); }
    catch (...) { VirtualFreeEx(s->pi.hProcess, mem, 0, MEM_RELEASE); return false; }
    s->call_trap = (uint64_t)(uintptr_t)mem + 2;
    return true;
}

// The thread's stack as its TEB describes it: NT_TIB StackBase, DeallocationStack (the low end
// of the reservation) and GuaranteedStackBytes (SetThreadStackGuarantee). Fibers: the TEB holds
// the running fiber's stack.
#if defined(_WIN64)
static const uint64_t TEB_STACK_BASE = 0x08, TEB_DEALLOCATION_STACK = 0x1478, TEB_GUARANTEED_STACK = 0x1748;
#else
static const uint64_t TEB_STACK_BASE = 0x04, TEB_DEALLOCATION_STACK = 0xE0C, TEB_GUARANTEED_STACK = 0xF78;
#endif
// May the thread grow its own stack from sp down to `low` (call_func's frame)? Only inside its
// stack reservation, and short of its last pages: Windows raises STATUS_STACK_OVERFLOW when the
// guard page comes within the guarantee (at least a page) of the reservation's end, and that
// overflow is spent for good (the program's own next overflow would be an access violation).
// The bound, kept well clear of it: low >= DeallocationStack + max(guarantee, 1 page) + 4 pages
// (regress hunt-stackend positions a hit just past it the same way).
static bool stack_can_grow(HANDLE process, HANDLE thread, const CONTEXT &ctx, uint64_t sp, uint64_t low, std::string &why) {
    const uint64_t page = 0x1000, teb = thread_teb(thread, ctx);
    uintptr_t base = 0, dealloc = 0; ULONG guarantee = 0; size_t n1 = 0, n2 = 0, n3 = 0;
    if (!teb || !remote_read(process, teb + TEB_STACK_BASE, &base, sizeof(base), &n1) || n1 != sizeof(base) ||
        !remote_read(process, teb + TEB_DEALLOCATION_STACK, &dealloc, sizeof(dealloc), &n2) || n2 != sizeof(dealloc) ||
        !remote_read(process, teb + TEB_GUARANTEED_STACK, &guarantee, sizeof(guarantee), &n3) || n3 != sizeof(guarantee)) {
        why = "the call frame's stack memory is not committed and the thread's stack bounds (TEB) are unreadable";
        return false;
    }
    char text[256];
    if (!dealloc || sp >= base || low < dealloc || low >= sp) {
        std::snprintf(text, sizeof(text), "the call frame at 0x%llx is not committed memory of the thread's stack "
                      "(0x%llx..0x%llx, SP 0x%llx)", (unsigned long long)low, (unsigned long long)dealloc,
                      (unsigned long long)base, (unsigned long long)sp);
        why = text; return false;
    }
    const uint64_t floor = dealloc + std::max<uint64_t>((guarantee + page - 1) & ~(page - 1), page) + 4 * page;
    if (low < floor) {
        std::snprintf(text, sizeof(text), "the thread's stack is nearly exhausted (the call frame at 0x%llx would "
                      "come within %llu bytes of the end of its reservation at 0x%llx)", (unsigned long long)low,
                      (unsigned long long)(low - dealloc), (unsigned long long)dealloc);
        why = text; return false;
    }
    return true;
}
// A call_func the session cannot make: 0 for the callback, and one stderr line per probe.
void call_refused(Probe *probe, const std::string &why) {
    if (probe && probe->warned_call) return;
    if (probe) probe->warned_call = true;
    std::fprintf(stderr, "probe: warning: %s: call_func refused: %s.%s\n", probe ? probe->location.c_str() : "<agent load>",
                 why.c_str(), probe ? " Further cases are not reported." : "");
}

// call_func on breakpoint/hw (and the early agent load): the callee runs on the stopped thread
// (run_call). Its frame goes 512+ bytes below the hit's SP; where that memory is not committed
// yet (a fresh thread, a caller that reserved a big frame without touching it: the frame would
// land in the guard page or beyond), the thread first grows its own stack down to it -- the
// probe after call_trap, run on the thread like a callee -- exactly as the callee would on
// inline. Writing there from outside instead failed (call_func 0, nothing said), and a
// WriteProcessMemory into the guard page spends the guard (ROADMAP XH3).

// Runs fn (or, with probe_to, the stack probe down to probe_to) on the stopped thread and puts
// the thread back exactly as it was. -1 (grow_to set): the call frame's memory is not committed
// but the thread can grow its stack down to *grow_to; nothing was done.
int run_call(probe_session *s, CallbackState *st, uint64_t fn, uint64_t *ret, int nargs, const uint64_t *args,
                    DWORD timeout_ms, uint64_t probe_to, uint64_t *grow_to) {
    if (nargs < 0 || nargs > 8 || st->released || s->exited || s->calls_closing) return 0;
    park_release(s);                     // the callee may need a lock a parked thread owns
    // The callback must run on its own event's fiber, stopped at that event (see "Callback
    // fibers"): that is where it can wait for the callee. Otherwise (no fiber could be
    // made, or the thread is already held after a timed-out call) the call is refused.
    EventFiber *const f = s->cur_fiber;
    if (!f || f->ev.dwThreadId != st->tid || (f->resume_after && !f->stop_suspended) || s->calls.count(st->tid)) {
        if (!f && !s->call_fiber_warned) {
            s->call_fiber_warned = true;
            std::fprintf(stderr, "probe: call_func refused: no callback fiber available\n");
        }
        return 0;
    }
    if (!ensure_call_trap(s)) return 0;
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, st->tid);
    if (!thread) return 0;
    CONTEXT legacy{};
    PCONTEXT saved_context = &legacy;
    std::vector<unsigned char> state;
    const DWORD flags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT
#if !defined(_WIN64)
        | CONTEXT_EXTENDED_REGISTERS
#endif
        ;
    // System-enabled features also include supervisor state. Only XCR0 user
    // components represent registers a callee can change; CET_U/SSP is handled below.
    int cpu[4]; __cpuid(cpu, 1);
    const DWORD64 features = (cpu[2] & (1 << 27))
        ? GetEnabledXStateFeatures() & _xgetbv(0) & XSTATE_MASK_ALLOWED & ~XSTATE_MASK_LEGACY : 0;
    auto context_failed = [&](const char *stage) {
        const DWORD error = GetLastError();
        char why[192];
        std::snprintf(why, sizeof(why), "%s failed (error %lu, XSTATE mask 0x%llx)", stage,
                      (unsigned long)error, (unsigned long long)features);
        call_refused(st->probe, why);
        CloseHandle(thread);
        return 0;
    };
    if (features) {
        DWORD len = 0;
        if (InitializeContext(nullptr, flags | CONTEXT_XSTATE, nullptr, &len) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER || !len) return context_failed("size call context");
        try { state.resize(len); } catch (...) { CloseHandle(thread); return 0; }
        if (!InitializeContext(state.data(), flags | CONTEXT_XSTATE, &saved_context, &len))
            return context_failed("initialize call context");
        if ((saved_context->ContextFlags & CONTEXT_XSTATE) != CONTEXT_XSTATE) {
            SetLastError(ERROR_NOT_SUPPORTED); return context_failed("initialize call XSTATE");
        }
        if (!SetXStateFeaturesMask(saved_context, features | XSTATE_MASK_LEGACY))
            return context_failed("select call XSTATE");
    } else legacy.ContextFlags = flags;
    CONTEXT &saved = *saved_context;
    const DWORD saved_flags = saved.ContextFlags;
    if (!GetThreadContext(thread, &saved)) return context_failed("get call context");
    if (features) {
        DWORD64 present = 0;
        if (!GetXStateFeaturesMask(saved_context, &present)) return context_failed("read call XSTATE mask");
        // GetThreadContext may omit INIT components: their bytes are undefined.
        // Explicitly materialize their zero INIT image before requesting their restore,
        // so a callee that activates them cannot leak its values back into the target.
        saved.ContextFlags = saved_flags;
        for (DWORD bit = 2; bit < 64; ++bit) if ((features & ~present) & (1ull << bit)) {
            DWORD bytes = 0;
            void *component = LocateXStateFeature(saved_context, bit, &bytes);
            if (!component || !bytes) {
                SetLastError(ERROR_NOT_SUPPORTED); return context_failed("locate INIT call XSTATE");
            }
            std::memset(component, 0, bytes);
        }
        if (!SetXStateFeaturesMask(saved_context, features | XSTATE_MASK_LEGACY))
            return context_failed("restore call XSTATE mask");
    }
    // The call frame: [sp, sp + frame_size), its return-address slot at sp. Checked before
    // anything is written: a WriteProcessMemory into the stack's guard page would spend it.
#if defined(_WIN64)
    const uint64_t hit_sp = saved.Rsp, sp = ((hit_sp - 512) & ~(uint64_t)0xF) - 8;     // entry rsp == 8 mod 16
    const size_t frame_size = 13 * sizeof(uint64_t);
#else
    const uint64_t hit_sp = saved.Esp, sp = (uint32_t)(hit_sp - 512) & ~0xFu;
    const size_t frame_size = 9 * sizeof(uint32_t);
#endif
    if (!probe_to && !remote_range_ok(s->pi.hProcess, sp, frame_size, true)) {
        std::string why = "the call frame's stack memory is still not committed after the thread grew its stack";
        const bool grow = grow_to && stack_can_grow(s->pi.hProcess, thread, saved, hit_sp, sp, why);
        CloseHandle(thread);
        if (grow) { *grow_to = sp; return -1; }
        call_refused(st->probe, why);
        return 0;
    }
    TebErrors teb_errors; teb_errors.save(s->pi.hProcess, thread, saved);
    // CET: a callee abandoned midway (it faulted, or timed out) leaves its frames on the
    // shadow stack; the restore below puts SSP back too (a completed call leaves it as it was).
    uint64_t ssp0 = 0;
    const bool have_ssp = target_has_shadow_stack(s) && thread_ssp(thread, &ssp0, nullptr);
    auto restore_ssp = [&] {
        uint64_t now = 0;
        if (!have_ssp || !thread_ssp(thread, &now, nullptr) || now == ssp0) return;
        const bool set = thread_ssp(thread, nullptr, &ssp0);
        if (trace_enabled() || !set)
            std::fprintf(stderr, "probe: call_func: shadow-stack pointer 0x%llx -> 0x%llx %s\n", (unsigned long long)now,
                         (unsigned long long)ssp0, set ? "restored" : "NOT restored (the kernel refused)");
    };
    CONTEXT w = saved; size_t wrote = 0; bool ok = true;
#if defined(_WIN64)
    uint64_t frame[13] = {s->call_trap};                               // ret (the CALL writes it too), shadow x4, stack args
    static_assert(sizeof(frame) == 13 * sizeof(uint64_t));
    for (int i = 4; i < nargs; ++i) frame[5 + (i - 4)] = args[i];
    if (probe_to) {
        w.Rip = s->call_trap + 1; w.R10 = probe_to;                    // the stack probe, from the hit's SP
    } else {
        ok = remote_write(s->pi.hProcess, sp, frame, sizeof(frame), &wrote) && wrote == sizeof(frame);
        w.Rsp = sp + 8; w.Rip = s->call_trap - 2; w.Rax = fn;          // the stub's CALL pushes call_trap at sp
        w.Rcx = nargs > 0 ? args[0] : 0; w.Rdx = nargs > 1 ? args[1] : 0;
        w.R8 = nargs > 2 ? args[2] : 0;  w.R9 = nargs > 3 ? args[3] : 0;
    }
#else
    uint32_t frame[9] = {(uint32_t)s->call_trap};                      // ret, then args (stdcall/cdecl both
    static_assert(sizeof(frame) == 9 * sizeof(uint32_t));
    for (int i = 0; i < nargs; ++i) frame[1 + i] = (uint32_t)args[i];  // fine: esp is restored after)
    if (probe_to) {
        w.Eip = (DWORD)s->call_trap + 1; w.Ecx = (DWORD)probe_to;      // the stack probe, from the hit's SP
    } else {
        ok = remote_write(s->pi.hProcess, sp, frame, sizeof(frame), &wrote) && wrote == sizeof(frame);
        w.Esp = (DWORD)sp + 4; w.Eip = (DWORD)s->call_trap - 2; w.Eax = (DWORD)fn; // the stub's CALL pushes call_trap at sp
    }
#endif
    // The callee gets what the ABI promises at a call: TF and DF clear. A hit can stop the
    // thread anywhere (a mid-function site may sit inside a `std` ... `cld` span): entered with
    // DF set, string instructions run backwards -- on Server 2025 / Win11 24H2 the WoW64
    // syscall thunk of GetThreadPriority then smashed its own stack (x86 target died executing
    // 0x0, transparency-*-callfn at TpMidHit). The thread's own flags come back with the restore.
    w.EFlags &= ~0x500u;
    w.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!ok || !SetThreadContext(thread, &w)) {
        char why[128];
        std::snprintf(why, sizeof(why), "%s failed (error %lu)", ok ? "SetThreadContext" : "writing the call frame",
                      GetLastError());
        call_refused(st->probe, why);
        CloseHandle(thread); return 0;
    }
    try { s->calls.emplace(st->tid, f); } catch (...) { SetThreadContext(thread, &saved); CloseHandle(thread); return 0; }
    f->call_start = GetTickCount64(); f->call_deadline = f->call_start + timeout_ms;
    f->call_outcome = EventFiber::WAITING;
    f->call_held = nullptr;
    // Let it run: continue its event -- or, for a replayed data-watch hit, resume it (it
    // was held by suspension, see replay_held_watches); its trap is then a normal event.
    // The guard stops listing the thread as it runs (guard_sync): taken off before a continue,
    // right after the resume of our own suspension (which stays covered until it ends).
    bool running = false;
    handling_running(s, st->tid, true);
    if (f->stop_suspended) {
        running = ResumeThread(f->resume_after) != (DWORD)-1;
        if (running) { CloseHandle(f->resume_after); f->resume_after = nullptr; f->stop_suspended = false; }
        guard_resync(s);
    } else {
        guard_resync(s);
        running = !!ContinueDebugEvent(st->pid, st->tid, DBG_CONTINUE);
    }
    if (!running) {
        handling_running(s, st->tid, false); guard_resync(s);
        s->calls.erase(st->tid); SetThreadContext(thread, &saved); CloseHandle(thread); return 0;
    }
    // A watch callback can call us while completing a software step. The callee's
    // traps belong to the call, not that outer instruction. Keep its node off the
    // live map until the original context is restored below.
    auto outer_step = s->stepping.extract(st->tid);
    // inplace_sync may release the step's window while this fiber is parked.
    // Keep the site armed before allowing any of those other threads to run.
    if (!outer_step.empty() && !outer_step.mapped().displaced)
        end_inplace_step(s, st->tid, outer_step.mapped().site);
    fiber_park(s, f);                       // the loop runs on; resumed by service_event / poll_calls
    // The outcome. TRAPPED / FAULTED: the thread is stopped at that event -- or, if it came
    // while a call_original ran, suspended by us (call_held) -- and it now stands in for the
    // original hit: the thread is put back exactly as it was at the hit.
    int result = 0;
    const HANDLE held = f->call_held;
    f->call_held = nullptr;
    switch (f->call_outcome) {
    case EventFiber::TRAPPED: {
        CONTEXT r{}; r.ContextFlags = CONTEXT_INTEGER;
        if (GetThreadContext(thread, &r)) {
#if defined(_WIN64)
            if (ret) *ret = r.Rax;
#else
            if (ret) *ret = r.Eax;                                     // pointer-sized return (EAX)
#endif
            result = 1;
        }
    }
        [[fallthrough]];
    case EventFiber::FAULTED:
        if (f->call_outcome == EventFiber::FAULTED && trace_enabled())
            std::fprintf(stderr, "  call_func: callee raised an exception on thread %lu; abandoned\n", (unsigned long)st->tid);
        SetThreadContext(thread, &saved);                              // exactly as it was at the hit
        restore_ssp();                                                 // CET: an abandoned callee's shadow frames
        teb_errors.restore(s->pi.hProcess);                            // and its last error / status
        if (held) f->resume_after = held;                              // no event to continue: resume it
        break;
    case EventFiber::TIMEOUT:
        // The callee is still running: stop it and put the context back. It stays suspended
        // until this handling ends, so the callback's own register changes still land.
        guard_note_hold(s, st->tid);
        if (SuspendThread(thread) != (DWORD)-1) {
            handling_running(s, st->tid, false);                        // suspended by us: listed (guard_sync)
            SetThreadContext(thread, &saved); restore_ssp(); teb_errors.restore(s->pi.hProcess);
            f->resume_after = thread; thread = nullptr;
            s->call_late[st->tid] = {};                                // see service_event, fiber_step
        } else {
            st->released = true;                                       // cannot stop it: nothing to write back
        }
        std::fprintf(stderr, "probe: call_func timed out after 5 s; thread restored\n");
        break;
    default:                                                           // GONE / EXITED: nothing left to restore
        if (held) { ResumeThread(held); CloseHandle(held); }
        st->released = true;
        break;
    }
    if (thread) CloseHandle(thread);
    if (!outer_step.empty() && !st->released) s->stepping.insert(std::move(outer_step));
    release_deferred(s);                                               // held hits replay now
    return result;
}

int call_func_args(probe_context *c, const char *symbol, uint64_t *ret, int nargs, const uint64_t *in) {
    auto *st = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    if (!st || !st->session || !st->tid) return 0;
    if (nargs < 0 || nargs > 8) return 0;
    uint64_t fn = resolve_symbol(st->session, symbol);
    if (!fn) return 0;
    uint64_t args[8] = {0};
    for (int i = 0; i < nargs; ++i) args[i] = in[i];
    return call_in_target(st->session, st, fn, ret, nargs, args);
}

} // namespace uhh_session

using namespace uhh_session;

extern "C" int call_func(probe_context *c, const char *symbol, uint64_t *ret, int nargs, ...) {
    if (nargs < 0 || nargs > 8) return 0;
    uint64_t args[8] = {0};
    va_list ap; va_start(ap, nargs);
    for (int i = 0; i < nargs; ++i) args[i] = va_arg(ap, uint64_t);
    va_end(ap);
    return call_func_args(c, symbol, ret, nargs, args);
}

namespace uhh_session {

// call_original on breakpoint/hw: the original runs IN PLACE -- on the hit's own stack, from
// the probe address, with the callback's registers -- exactly as the program would have run
// it, returning to its real return address. A debug register set on THIS thread only, at
// that return address, stops it there (SP just above the hit's: the matching return); the
// thread is then put back at the hit, so the callback continues and return_from applies.
// Nothing on the stack is rewritten, so an exception or longjmp inside the original unwinds
// natively into the program's own handlers (and CET shadow stacks stay in sync). Such an
// exit -- the thread seen at or above the hit's frame without having returned -- RELEASES
// the call: the thread runs on, the program sees exactly what it would have seen, and the
// rest of the callback is abandoned (as on inline, where the exception propagates through
// the callback). The probe's own entry is passed through without counting a hit; probes
// hit inside the original are counted but run no callback; other threads' hits wait.
static bool hit_is_function_entry(probe_context *c, uint64_t *ret_addr) {
    uint64_t r = 0; unsigned char pre[8];
    if (!get_mem(c, c->hit_sp, &r, sizeof(void *)) || r < 8 || !get_mem(c, r - 8, pre, sizeof(pre))) return false;
    if (ret_addr) *ret_addr = r;
    return looks_like_return_site(pre);
}
static void co_warn(bool &flag, const Probe *probe, const char *text) {
    if (flag) return;
    flag = true;
    std::fprintf(stderr, "probe: warning: %s: %s. Further cases are not reported.\n", probe->location.c_str(), text);
}
static int call_original_in_place(probe_session *s, CallbackState *st, probe_context *c, uint64_t *out) {
    park_release(s);                     // the original may need a lock a parked thread owns
    Probe *probe = st->probe;
    const uint64_t ptr = sizeof(void *);
    uint64_t ret_addr = 0;
    if (!hit_is_function_entry(c, &ret_addr)) {
        warn_record(c, probe, "call_original refused: not at a function entry ([SP] is no return address)");
        co_warn(s->co_warned_entry, probe, "call_original refused: not at a function entry ([SP] is no return address)");
        return 0;
    }
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, st->tid);
    if (!thread) return 0;
    CONTEXT saved{}; saved.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | UHH_CONTEXT_FP | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &saved)) { CloseHandle(thread); return 0; }
    int slot = -1;
    for (int k = 0; k < 4 && slot < 0; ++k)
        if (!(s->dr_used & (1u << k)) && !((saved.Dr7 >> (k * 2)) & 3)) slot = k;
    // All four in use, but the hit is a hardware EXECUTE probe: borrow its own slot on THIS
    // thread only (re-pointed at the return address for the call, put back after). Other
    // threads keep the probe; this thread is inside the original meanwhile, so only a
    // recursive entry of the same function on it goes uncounted. (gated_config with every
    // probe on hw: flag + NtOpenProcess + NtClose + NtReadVirtualMemory = 4 DRs.)
    bool borrowed = false;
    if (slot < 0 && (probe->flags & PROBE_HW) && !(probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) &&
        probe->dr_slot >= 0 && probe->dr_slot < 4) {
        slot = probe->dr_slot; borrowed = true;
    }
    if (slot < 0) {
        CloseHandle(thread);
        warn_record(c, probe, "call_original refused: needs one free debug register (all 4 in use)");
        co_warn(s->co_warned_dr, probe, "call_original refused: needs one free debug register (all 4 in use)");
        return 0;
    }
    CONTEXT w = saved;
    to_context(*c, w);                                                 // the callback's registers
    s->hw_armed_ever.insert(ret_addr);
    auto *dr = slot == 0 ? &w.Dr0 : slot == 1 ? &w.Dr1 : slot == 2 ? &w.Dr2 : &w.Dr3;   // DWORD64 / DWORD
    *dr = (std::remove_reference_t<decltype(*dr)>)ret_addr;
    w.Dr7 = (decltype(w.Dr7))((w.Dr7 & ~((DWORD64)0xF << (16 + slot * 4))) | ((DWORD64)1 << (slot * 2)));   // execute, local
    w.Dr6 = 0;
#if defined(_WIN64)
    w.Rip = probe->address; w.Rsp = c->hit_sp;
#else
    w.Eip = (DWORD)probe->address; w.Esp = (DWORD)c->hit_sp;
#endif
    w.EFlags &= ~0x100u;
    if (probe->flags & PROBE_HW) w.EFlags |= 0x10000u;                 // RF: the entry's own DR stays quiet once
    w.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    if (!SetThreadContext(thread, &w)) { CloseHandle(thread); return 0; }
    s->dr_used |= (uint8_t)(1u << slot);                               // reserved: no probe arms it meanwhile
    s->dr_ever |= (uint8_t)(1u << slot);                               // ours: detach / the guard clear it too
    s->in_call_tid = st->tid; s->co_addr = probe->address; s->co_sp = c->hit_sp; s->co_ret = ret_addr; s->co_exc_sp = 0;
    s->co_borrowed_slot = borrowed ? slot : -1;
    s->co_entry_pending = !(probe->flags & PROBE_HW); s->co_left = false;
    // Mirrored BEFORE the thread runs with it (the slot) -- and the thread off the guard's list
    // while it runs the original: a suspension of ours (the polls below) or its stop at the
    // return catch lists it for exactly that long.
    handling_running(s, st->tid, true);
    guard_sync(s);
    auto clear_slot = [&](bool running) {
        if (running) guard_note_hold(s, st->tid);
        if (running && SuspendThread(thread) == (DWORD)-1) return;
        if (borrowed) {                                                // the probe's own DR, back at its site
            uint32_t rw = 0, len = 0; hw_rw_len(probe->flags, rw, len);
            set_dr_on_thread(thread, slot, probe->address, probe->active, rw, len);
        } else {
            set_dr_on_thread(thread, slot, 0, false);
        }
        if (running) { ResumeThread(thread); guard_resync(s); }
    };
    EventFiber *const f = s->cur_fiber;
    bool continued = false;
    if (f && f->stop_suspended) {
        continued = ResumeThread(f->resume_after) != (DWORD)-1;
        if (continued) { CloseHandle(f->resume_after); f->resume_after = nullptr; f->stop_suspended = false; }
        guard_resync(s);
    } else continued = !!ContinueDebugEvent(st->pid, st->tid, DBG_CONTINUE);
    if (!continued) {
        if (!borrowed) s->dr_used &= (uint8_t)~(1u << slot);
        s->in_call_tid = 0; s->co_addr = 0; s->co_borrowed_slot = -1;
        handling_running(s, st->tid, false); guard_sync(s);            // still at its event: listed again
        saved.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(thread, &saved);
        CloseHandle(thread); return 0;
    }
    bool done = false, thread_gone = false;
    const char *why = "the original left without returning (exception or longjmp)";
    uint64_t result = 0;
    ULONGLONG until = GetTickCount64() + 5000, next_poll = GetTickCount64() + 20;
    DEBUG_EVENT ev{};
    while (!s->exited && !s->co_left && !thread_gone) {
        if (!s->ctx_watch.empty()) ctx_watch_poll(s);
        if (WaitForDebugEvent(&ev, s->ctx_watch.empty() ? 20 : 1)) {
            if (continue_foreign_event(s, ev)) continue;
            if (ev.dwThreadId == st->tid && ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                ev.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP &&
                (uint64_t)(uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress == ret_addr) {
                guard_note_hold(s, st->tid);                               // stopped at its event: listed meanwhile
                CONTEXT &r = st->post; r.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | UHH_CONTEXT_FP;
                if (GetThreadContext(thread, &r)) {
#if defined(_WIN64)
                    const uint64_t sp = r.Rsp, rax = r.Rax;
#else
                    const uint64_t sp = r.Esp, rax = r.Eax;
#endif
                    if (sp > s->co_sp && sp <= s->co_sp + ptr + 1024) {   // x86 stdcall: ret N popped the args
                        result = rax; done = true;                         // this event now stands in for the hit
                        handling_running(s, st->tid, false);               // stopped there: listed (guard_sync)
                        st->have_post = true;
                        st->post_seen = c->regs;
#if !defined(_WIN64)
                        c->orig_edx = r.Edx;                               // an EDX:EAX result's high half
                        c->orig_pop = (int32_t)(sp - (s->co_sp + ptr));    // the bytes its `ret N` popped
#endif
                        break;
                    }
                    r.EFlags |= 0x10000u; SetThreadContext(thread, &r);    // some other return there: run on
                }
                guard_resync(s);                                           // runs on: off the guard's list
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                continue;
            }
            if (ev.dwThreadId == st->tid && ev.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
                thread_gone = true; why = "the thread exited inside the original";
            }
            if (ev.dwThreadId == st->tid && ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && ev.u.Exception.dwFirstChance) {
                // The program's own exception (not a probe trap or step): its dispatch starts
                // below this SP (co_unwound).
                const DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
                if (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP && code != 0x4000001Eu &&
                    code != 0x4000001Fu && code != PROBE_IPC_CODE) {
                    CONTEXT r{}; r.ContextFlags = CONTEXT_CONTROL;
                    if (GetThreadContext(thread, &r))
#if defined(_WIN64)
                        s->co_exc_sp = r.Rsp;
#else
                        s->co_exc_sp = r.Esp;
#endif
                }
            }
            service_event(s, ev);                                          // everything else as usual
        }
        poll_calls(s);
        const ULONGLONG now = GetTickCount64();
        if (now >= next_poll && !s->co_left && !thread_gone && !s->exited) {
            // Left without a probe hit to show it (e.g. an exception caught by the caller):
            // the thread is above the hit's frame and not at the return address.
            // The context is read WITHOUT suspending the thread: a suspension of ours, however
            // short, is visible to the program -- its own SuspendThread of that thread returns 1
            // instead of 0 if it lands inside (regress cx2-cosusp-*, seen on CI). An x64
            // controller's GetThreadContext on a running thread is a consistent snapshot (the
            // kernel takes it in an APC on that thread) and leaves the suspend count alone. A
            // 32-bit (WOW64) controller's call suspends the thread implicitly inside the call
            // (GuardTouch; a residual window of the call's own length, as for any WOW64 debugger).
            next_poll = now + 20;
            CONTEXT r{}; r.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
            bool got;
            { GuardTouch touch(s, st->tid); got = !!GetThreadContext(thread, &r); }
            if (got) {
#if defined(_WIN64)
                const uint64_t sp = r.Rsp, pc = r.Rip;
#else
                const uint64_t sp = r.Esp, pc = r.Eip;
#endif
                // co_slot_gone reads two stack words of the running thread: the slot at co_sp only
                // changes once the original's frame is gone (a thunk moving its return address down
                // writes the copy first, and the copy is read after the slot).
                if ((sp >= s->co_sp + ptr && pc != ret_addr) || co_slot_gone(s, sp)) {
                    s->co_left = true;
                } else if (s->co_exc_sp && sp < s->co_exc_sp && s->sym_ready) {
                    // co_unwound walks the thread's stack: only on a stopped thread (frames that do not
                    // change under the walk). Rare -- an exception was raised during this call and the
                    // thread is below its raise point -- so the suspension is taken for that case only.
                    guard_note_hold(s, st->tid);
                    if (SuspendThread(thread) != (DWORD)-1) {
                        CONTEXT q{}; q.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
                        if (GetThreadContext(thread, &q)) {
#if defined(_WIN64)
                            const uint64_t qsp = q.Rsp, qpc = q.Rip;
#else
                            const uint64_t qsp = q.Esp, qpc = q.Eip;
#endif
                            if ((qsp >= s->co_sp + ptr && qpc != ret_addr) || co_slot_gone(s, qsp) ||
                                co_unwound(s, st->tid, q, qpc))
                                s->co_left = true;
                        }
                        ResumeThread(thread);
                    }
                    guard_resync(s);
                }
            }
        }
        if (!done && now > until && !s->co_left) {
            s->co_left = true; why = "the original did not return within 5 s (released, it runs on)";
        }
    }
    s->in_call_tid = 0; s->co_addr = 0; s->co_ret = 0; s->co_exc_sp = 0; s->co_entry_pending = false; s->co_left = false; s->co_borrowed_slot = -1;
    if (done) {
        CONTEXT cur{}; cur.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &cur)) {          // keep any DR armed meanwhile, drop ours
            const DWORD64 mask = ((DWORD64)3 << (slot * 2)) | ((DWORD64)0xF << (16 + slot * 4));
            const auto keep = slot == 0 ? saved.Dr0 : slot == 1 ? saved.Dr1 : slot == 2 ? saved.Dr2 : saved.Dr3;
            cur.Dr7 = (decltype(cur.Dr7))(cur.Dr7 & ~mask);
            if (borrowed) {                            // the probe's own DR: as it was at the hit
                cur.Dr7 = (decltype(cur.Dr7))(cur.Dr7 | (saved.Dr7 & mask));
                (slot == 0 ? cur.Dr0 : slot == 1 ? cur.Dr1 : slot == 2 ? cur.Dr2 : cur.Dr3) = keep;
            }
            saved.Dr0 = cur.Dr0; saved.Dr1 = cur.Dr1; saved.Dr2 = cur.Dr2; saved.Dr3 = cur.Dr3; saved.Dr7 = cur.Dr7;
        }
        saved.Dr6 = 0;
        saved.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | UHH_CONTEXT_FP | CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(thread, &saved);              // exactly as it was at the hit (CET: SSP stays popped,
                                                       // see apply_return_from / cet_after_original)
    } else if (!s->exited && !thread_gone) {
        clear_slot(true);
    }
    if (!borrowed) s->dr_used &= (uint8_t)~(1u << slot);
    release_deferred(s);                               // they hit their probes again now
    CloseHandle(thread);
    if (done) {
        c->called_original = 1;
        if (out) *out = result;
        return 1;
    }
    // Released: the original ran (or runs on) natively, and the program sees exactly its
    // outcome. There is no stopped thread left to write back to; end the callback here.
    st->released = true;
    s->skip_continue = true;
    if (!s->exited) co_warn(s->co_warned_left, probe, why);
    RaiseException(UHH_CALL_RELEASED, 0, 0, nullptr);
    return 0;
}
} // namespace uhh_session

extern "C" int call_original(probe_context *c, int nargs, uint64_t *out) {
    auto *st = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    if (!st || !st->session || !st->tid || !st->probe || st->released) return 0;
    if (nargs < 0 || nargs > 16) {                                     // same contract as inline
        warn_record(c, st->probe, "call_original refused: nargs must be 0..16");
        co_warn(st->session->co_warned_nargs, st->probe, "call_original refused: nargs must be 0..16"); return 0;
    }
    if (st->probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) return 0;
    if (st->session->in_call_tid) return 0;                            // no nesting
    if (st->session->cur_fiber && st->session->cur_fiber->resume_after && !st->session->cur_fiber->stop_suspended) return 0;   // held after a call_func timeout
    return call_original_in_place(st->session, st, c, out);
}
extern "C" void return_from(probe_context *c, uint64_t value, int nargs) {
    if (!c || nargs < 0 || nargs > 255) return;
    auto *st = static_cast<CallbackState *>(c->controller);
    if (!st || st->released) return;
    if (!hit_is_function_entry(c, nullptr)) {
        warn_record(c, st->probe, "return_from refused: not at a function entry ([SP] is no return address)");
        if (st->session && st->probe)
            co_warn(st->session->co_warned_entry, st->probe,
                    "return_from refused: not at a function entry ([SP] is no return address)");
        return;
    }
#if defined(_WIN64)
    (void)nargs; c->regs.rax = value; c->ret_pop = 0;
#else
    uint32_t pop = (uint32_t)nargs * 4;
    if (probe_x86_return_regs(c, value, &pop) && st->probe && !st->probe->warned_pop) {
        st->probe->warned_pop = true;
        send_log(c, "uhh warning: return_from nargs=%d but the original popped %d bytes (ret %d); the original's "
                    "count is used", nargs, (int)c->orig_pop, (int)c->orig_pop);   // as inline logs it
        std::fprintf(stderr, "probe: warning: %s: return_from nargs=%d but the original popped %d bytes (ret %d); "
                     "the original's count is used. Further cases are not reported.\n",
                     st->probe->location.c_str(), nargs, (int)c->orig_pop, (int)c->orig_pop);
    }
    c->ret_pop = pop;
#endif
    c->returned = 1;
}
