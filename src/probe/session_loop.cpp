// The debug loop: event service and dispatch, exception handling (breakpoint hits, steps,
// faults), crash reports, suspensions of our own, fairness ticks, context round-trips.
#include "session_internal.hpp"

namespace uhh_session {
// Debug events are per DEBUGGER THREAD, not per session: a thread that ran an earlier
// session can still have that (terminated) target's last events queued. They belong to
// another process -- continue them untouched and never let them reach this session's state.
bool continue_foreign_event(const probe_session *s, const DEBUG_EVENT &ev) {
    if (ev.dwProcessId == s->pi.dwProcessId) return false;
    if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
    if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId,
                       ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE);
    return true;
}
// Dispatch one debug event of this session and continue it -- or hand it to the call_func
// it ends. Every loop that waits for debug events goes through here.
#if defined(UHH_TEST_HOOKS)
// UHH_TEST_LATE_TRAP: every call_func times out exactly as its return trap is dequeued -- the
// race where poll_calls runs first, forced (regress callfunc-late-trap-*).
static bool test_late_trap() { static const bool on = std::getenv("UHH_TEST_LATE_TRAP") != nullptr; return on; }
#endif
// Continue an event that belongs to nothing any more (see service_event).
static bool swallow_event(probe_session *s, const DEBUG_EVENT &ev, const char *why) {
    if (trace_enabled())
        std::fprintf(stderr, "  %s tid=%lu code=0x%08lx at 0x%llx: swallowed\n", why, (unsigned long)ev.dwThreadId,
                     (unsigned long)ev.u.Exception.ExceptionRecord.ExceptionCode,
                     (unsigned long long)(uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress);
    if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)) { set_error(s, win_error("continue debug event")); return false; }
    return true;
}
bool service_event(probe_session *s, DEBUG_EVENT &ev) {
    if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
        const auto &er = ev.u.Exception.ExceptionRecord;
        DWORD code = er.ExceptionCode;                       // a WOW64 trap in its WOW64 form: the same
        if (code == 0x4000001Eu /*STATUS_WX86_SINGLE_STEP*/) code = EXCEPTION_SINGLE_STEP;
        else if (code == 0x4000001Fu /*STATUS_WX86_BREAKPOINT*/) code = EXCEPTION_BREAKPOINT;
        const uint64_t at = (uint64_t)(uintptr_t)er.ExceptionAddress;
        const bool at_trap = s->call_trap && code == EXCEPTION_BREAKPOINT && at == s->call_trap;
        auto it = s->calls.find(ev.dwThreadId);
#if defined(UHH_TEST_HOOKS)
        if (it != s->calls.end() && at_trap && !it->second->call_held && test_late_trap()) {
            call_resume(s, ev.dwThreadId, EventFiber::TIMEOUT, nullptr);
            it = s->calls.find(ev.dwThreadId);
        }
#endif
        if (it != s->calls.end()) {
            // The library's own call (early_agent): the agent's control-plane requests during it
            // (its hook-write FREEZE / THAW) are serviced as usual, not taken for a callee fault.
            const bool own_ipc = code == PROBE_IPC_CODE && ev.dwThreadId == s->quiet_tid;
            if (!own_ipc && (at_trap || !(code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP))) {
                const EventFiber::Outcome how = at_trap ? EventFiber::TRAPPED : EventFiber::FAULTED;
                if (!s->in_call_tid || s->calls_closing) return call_resume(s, ev.dwThreadId, how, &ev);
                // A call_original is running: hold this thread at its trap/fault until it is
                // over (its callback could call_original as well).
                EventFiber *f = it->second;
                HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, ev.dwThreadId);
                guard_note_hold(s, ev.dwThreadId);
                if (t && SuspendThread(t) != (DWORD)-1) {
                    f->call_held = t; f->call_outcome = how;
                    if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)) {
                        set_error(s, win_error("continue debug event")); return false;
                    }
                    return true;
                }
                if (t) CloseHandle(t);
                return call_resume(s, ev.dwThreadId, how, &ev);
            }
            if (trace_enabled())
                std::fprintf(stderr, "  call_func: own-thread event 0x%08lx at 0x%llx\n", (unsigned long)er.ExceptionCode,
                             (unsigned long long)at);
        } else if (at_trap) {
            auto r = s->restore_resume.find(ev.dwThreadId);
            if (r != s->restore_resume.end()) {
                // x86: a context restore sent through our INT3 (restore_fixup): the DRs the
                // 64-bit layer just put back are stale -- ours again, then the real EIP, before
                // its first instruction runs.
                const uint64_t eip = r->second;
                s->restore_resume.erase(r);
                GuardTouch touch(s, ev.dwThreadId);         // (not dispatched: no handling lists it)
                reapply_hw_thread(s, ev.dwThreadId);
                HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, ev.dwThreadId);
                CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
                if (t && GetThreadContext(t, &c)) {
#if defined(_WIN64)
                    c.Rip = eip;
#else
                    c.Eip = (DWORD)eip;
#endif
                    SetThreadContext(t, &c);
                }
                if (t) CloseHandle(t);
                return swallow_event(s, ev, "restore-resume");
            }
            // The return trap of a call_func that already timed out (it was queued when the
            // timeout ran): the thread was restored meanwhile and continues from there.
            s->call_late.erase(ev.dwThreadId);
            return swallow_event(s, ev, "call_func: late return");
        } else if (!s->call_late.empty()) {
            // Likewise a callee FAULT queued before its call timed out: not the program's.
            auto l = s->call_late.find(ev.dwThreadId);
            if (l != s->call_late.end()) {
                // Raised before the restore: the thread has not run since it was left at l->ip
                // (a fault it raises after running from there is the program's own).
                bool stale = false;
                if (l->second.ip && code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP) {
                    HANDLE t = OpenThread(THREAD_GET_CONTEXT, FALSE, ev.dwThreadId);
                    CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
                    GuardTouch touch(s, ev.dwThreadId);
                    stale = t && GetThreadContext(t, &c) && (uint64_t)UHH_PC(c) == l->second.ip && at != l->second.ip;
                    if (t) CloseHandle(t);
                }
                s->call_late.erase(l);
                if (stale) return swallow_event(s, ev, "call_func: late callee fault");
            }
        }
        if (EventFiber *f = fiber_get(s)) { f->ev = ev; return fiber_step(s, f, &ev); }
    }
    const bool outer_skip = s->skip_continue;
    s->skip_continue = false;
    DWORD disposition = DBG_CONTINUE;
    bool ok = dispatch_event(s, ev, disposition);
    if (!s->skip_continue) guard_resync(s);          // its handling is over: off the guard's list first
    if (!s->skip_continue && !ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, disposition)) {
        set_error(s, win_error("continue debug event")); ok = false;
    }
    s->skip_continue = outer_skip;
    if (ev.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT && s->calls.count(ev.dwThreadId))
        ok = call_resume(s, ev.dwThreadId, EventFiber::GONE, nullptr) && ok;      // ended inside the callee
    return ok;
}

void pump(probe_session *s, DWORD ms) {
    DEBUG_EVENT event{};
    ULONGLONG until = GetTickCount64() + ms;
    while (!s->exited && GetTickCount64() < until) {
        poll_calls(s);
        if (!WaitForDebugEvent(&event, 20)) continue;
        if (continue_foreign_event(s, event)) continue;
        service_event(s, event);
        if (s->remote_work == probe_session::REMOTE_NONE && s->stepping.empty() && ms == 0) break;
    }
}

// ---- Suspensions of our own, fairness, context round-trips ----------------------------
// How many suspensions of thread `tid` are ours right now (every list we suspend into).
static int our_suspends(const probe_session *s, DWORD tid) {
    int n = s->inline_add_wait_tid == tid ? 1 : 0;
    for (const auto *list : {&s->held, &s->ipc_frozen, &s->call_deferred})
        for (HANDLE t : *list) n += GetThreadId(t) == tid;
    for (const auto &e : s->inplace_suspended) n += e.first == tid;
    for (const auto &e : s->parked) n += e.first == tid;
    for (DWORD d : s->detach_frozen) n += d == tid;
    for (const auto &w : s->ctx_watch) n += w->tid == tid;
    return n;
}
// The thread's suspend count (THREAD_SUSPEND_RESUME), -1 = unknown. (Not ThreadSuspendCount:
// it includes a debug freeze that can outlive ContinueDebugEvent on a held thread.
// An "event pending" boolean cannot reliably subtract that contribution.)
static long suspend_count(HANDLE t) {
    const DWORD prev = SuspendThread(t);
    if (prev == (DWORD)-1) return -1;
    ResumeThread(t);
    return (long)prev;
}

void park_release(probe_session *s) {
    if (!s->parked.empty()) { ++s->park_rounds; s->parked_total += s->parked.size(); }
    if (trace_enabled() && !s->parked.empty())
        std::fprintf(stderr, "  park-release n=%zu t=%lld\n", s->parked.size(),
                     (long long)std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    for (auto &e : s->parked) { ResumeThread(e.second); CloseHandle(e.second); }
    s->parked.clear();
    s->parking = false; s->fair_period_ms = 20; s->round_demand = -1; s->quiet_sampled = false; s->quiet_rounds = 0;
    s->fair_window = std::chrono::steady_clock::now(); s->fair_gaps = {};
}
// Park the thread whose hit is about to be continued (see probe_session::parked). Never a
// thread we must keep running: one in a step (an in-place window waits on it), a call_func /
// call_original thread, our agent's threads.
// Make the thread whose hit is about to be continued sleep ~2 ms right after it (yield_stub:
// registers, flags and XMM0-5 (x86 XMM0-7) saved, ntdll!NtDelayExecution, all restored, a jump to
// where it was going). NOT a suspension: a thread suspended while it is still inside its debug
// event resumes the frozen process only when it runs again -- suspending hot threads kept the
// whole target frozen (main's Sleep(10) took 1-2.5 s); a thread asleep in its own code leaves it
// running, so the threads that hit nothing get the CPU.
// KUSER_SHARED_DATA.InterruptTime (100 ns): the same page, the same value, in every process.
static uint64_t interrupt_time_now() {
    const volatile ULONG *k = reinterpret_cast<const volatile ULONG *>(0x7FFE0008);
    for (;;) {
        const ULONG hi = k[1], lo = k[0];
        if ((LONG)hi == (LONG)k[2]) return ((uint64_t)hi << 32) | lo;
    }
}
static uint64_t yield_stub(probe_session *s, DWORD tid) {
    if (auto it = s->yield_stubs.find(tid); it != s->yield_stubs.end()) return it->second;
    if (s->yield_unusable) return 0;
    if (s->yield_next + 256 > s->yield_end) {
        void *m = VirtualAllocEx(s->pi.hProcess, nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!m) { s->yield_unusable = true; return 0; }
        s->yield_next = (uint64_t)(uintptr_t)m; s->yield_end = s->yield_next + 0x10000;
    }
    const uint64_t at = s->yield_next;
    // [0]: resume address, [8]: deadline (interrupt time), [16]: mode (0 sleep, 1 spin),
    // [24]: deadline (system time, absolute, for NtDelayExecution); code at +32.
    std::vector<unsigned char> c(32, 0);
    auto put = [&](std::initializer_list<unsigned char> b) { c.insert(c.end(), b); };
    auto put_u = [&](uint64_t v, int n) { for (int i = 0; i < n; ++i) c.push_back((unsigned char)(v >> (8 * i))); };
#if defined(_WIN64)
    put({0x9C, 0x53, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});   // pushfq; rbx rax rcx rdx r8-r11
    put({0x48, 0x89, 0xE3});                                   // mov rbx, rsp
    put({0x48, 0x83, 0xE4, 0xF0});                             // and rsp, -16
    put({0x48, 0x81, 0xEC, 0x90, 0, 0, 0});                    // sub rsp, 0x90
    put({0xF3, 0x0F, 0x7F, 0x44, 0x24, 0x30, 0xF3, 0x0F, 0x7F, 0x4C, 0x24, 0x40, 0xF3, 0x0F, 0x7F, 0x54, 0x24, 0x50,
         0xF3, 0x0F, 0x7F, 0x5C, 0x24, 0x60, 0xF3, 0x0F, 0x7F, 0x64, 0x24, 0x70,
         0xF3, 0x0F, 0x7F, 0xAC, 0x24, 0x80, 0, 0, 0});        // movdqu [rsp+0x30..0x80], xmm0..xmm5
    // Mode 0 (the 1 ms timer is on: something may be starved): sleep until the deadline, off the
    // CPU. Mode 1 (rounds have backed off, the timer is off): NtYieldExecution in a loop until the
    // interrupt time (KUSER_SHARED_DATA) passes the deadline -- no timer: a sleep would need the
    // 1 ms timer, whose cost is what the back-off saves (a sleep begun under the 15.6 ms timer
    // lasted up to 15.6 ms).
    put({0x80, 0x3D});                                         // cmp byte [rip+rel32], 0 -> [16]: mode
    { const int32_t r = (int32_t)(16 - (int64_t)(c.size() + 5)); put_u((uint32_t)r, 4); }
    c.push_back(0);
    put({0x74, 0x00}); const size_t to_sleep = c.size() - 1;   // je sleep
    const size_t loop = c.size();
    put({0x48, 0xB8}); put_u(s->yield_spin_fn, 8);             // mov rax, NtYieldExecution
    put({0xFF, 0xD0});                                         // call rax
    put({0x48, 0xA1}); put_u(0x7FFE0008ull, 8);                // mov rax, [KUSER_SHARED_DATA.InterruptTime]
    put({0x48, 0x2B, 0x05});                                   // sub rax, [rip+rel32] -> [8]: the deadline
    { const int32_t r = (int32_t)(8 - (int64_t)(c.size() + 4)); put_u((uint32_t)r, 4); }
    put({0x78}); c.push_back((unsigned char)(int8_t)((int64_t)loop - (int64_t)(c.size() + 1)));   // js loop
    put({0xEB, 0x00}); const size_t to_done = c.size() - 1;    // jmp done
    c[to_sleep] = (unsigned char)(c.size() - (to_sleep + 1));
    put({0x31, 0xC9});                                         // sleep: xor ecx, ecx (not alertable)
    put({0x48, 0x8D, 0x15});                                   // lea rdx, [rip+rel32] -> [24]: the deadline
    { const int32_t r = (int32_t)(24 - (int64_t)(c.size() + 4)); put_u((uint32_t)r, 4); }
    put({0x48, 0xB8}); put_u(s->yield_fn, 8);                  // mov rax, NtDelayExecution
    put({0xFF, 0xD0});                                         // call rax
    c[to_done] = (unsigned char)(c.size() - (to_done + 1));    // done:
    put({0xF3, 0x0F, 0x6F, 0x44, 0x24, 0x30, 0xF3, 0x0F, 0x6F, 0x4C, 0x24, 0x40, 0xF3, 0x0F, 0x6F, 0x54, 0x24, 0x50,
         0xF3, 0x0F, 0x6F, 0x5C, 0x24, 0x60, 0xF3, 0x0F, 0x6F, 0x64, 0x24, 0x70,
         0xF3, 0x0F, 0x6F, 0xAC, 0x24, 0x80, 0, 0, 0});        // movdqu xmm0..xmm5, [...]
    put({0x48, 0x89, 0xDC});                                   // mov rsp, rbx
    put({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0x5B, 0x9D});   // pops; popfq
    put({0xFF, 0x25});                                         // jmp [rip+rel32] -> [0]
    const int32_t rel = (int32_t)(0 - (int64_t)(c.size() + 4)); put_u((uint32_t)rel, 4);
#else
    put({0x9C, 0x60});                                         // pushfd; pushad
    put({0x89, 0xE3});                                         // mov ebx, esp
    put({0x83, 0xE4, 0xF0});                                   // and esp, -16
    put({0x81, 0xEC, 0x90, 0, 0, 0});                          // sub esp, 0x90
    put({0xF3, 0x0F, 0x7F, 0x44, 0x24, 0x10, 0xF3, 0x0F, 0x7F, 0x4C, 0x24, 0x20, 0xF3, 0x0F, 0x7F, 0x54, 0x24, 0x30,
         0xF3, 0x0F, 0x7F, 0x5C, 0x24, 0x40, 0xF3, 0x0F, 0x7F, 0x64, 0x24, 0x50, 0xF3, 0x0F, 0x7F, 0x6C, 0x24, 0x60,
         0xF3, 0x0F, 0x7F, 0x74, 0x24, 0x70, 0xF3, 0x0F, 0x7F, 0xBC, 0x24, 0x80, 0, 0, 0});   // movdqu [esp+0x10..0x80], xmm0..7
    put({0x80, 0x3D}); put_u(at + 16, 4); c.push_back(0);      // cmp byte [mode], 0 (see x64)
    put({0x74, 0x00}); const size_t to_sleep = c.size() - 1;   // je sleep
    const size_t loop = c.size();
    put({0xB8}); put_u(s->yield_spin_fn, 4);                   // mov eax, NtYieldExecution
    put({0xFF, 0xD0});                                         // call eax (stdcall, no arguments)
    put({0xA1}); put_u(0x7FFE0008ull, 4);                      // mov eax, [InterruptTime.LowPart]
    put({0x2B, 0x05}); put_u(at + 8, 4);                       // sub eax, [deadline low part]
    put({0x78}); c.push_back((unsigned char)(int8_t)((int64_t)loop - (int64_t)(c.size() + 1)));   // js loop (signed: 214 s of range)
    put({0xEB, 0x00}); const size_t to_done = c.size() - 1;    // jmp done
    c[to_sleep] = (unsigned char)(c.size() - (to_sleep + 1));
    put({0xB8}); put_u(at + 24, 4);                            // sleep: mov eax, &[24]: the deadline
    put({0x50, 0x6A, 0x00});                                   // push eax; push FALSE
    put({0xB8}); put_u(s->yield_fn, 4);                        // mov eax, NtDelayExecution
    put({0xFF, 0xD0});                                         // call eax (stdcall: pops its 2 args)
    c[to_done] = (unsigned char)(c.size() - (to_done + 1));    // done:
    put({0xF3, 0x0F, 0x6F, 0x44, 0x24, 0x10, 0xF3, 0x0F, 0x6F, 0x4C, 0x24, 0x20, 0xF3, 0x0F, 0x6F, 0x54, 0x24, 0x30,
         0xF3, 0x0F, 0x6F, 0x5C, 0x24, 0x40, 0xF3, 0x0F, 0x6F, 0x64, 0x24, 0x50, 0xF3, 0x0F, 0x6F, 0x6C, 0x24, 0x60,
         0xF3, 0x0F, 0x6F, 0x74, 0x24, 0x70, 0xF3, 0x0F, 0x6F, 0xBC, 0x24, 0x80, 0, 0, 0});
    put({0x89, 0xDC, 0x61, 0x9D});                             // mov esp, ebx; popad; popfd
    put({0xFF, 0x25}); put_u(at, 4);                           // jmp [at] -> [0]
#endif
    if (c.size() > 256) { s->yield_unusable = true; return 0; }
    size_t wrote = 0;
    if (!remote_write(s->pi.hProcess, at, c.data(), c.size(), &wrote) || wrote != c.size()) { s->yield_unusable = true; return 0; }
    FlushInstructionCache(s->pi.hProcess, (void *)(uintptr_t)at, c.size());
    s->yield_next += 256;
    try { s->yield_stubs[tid] = at; } catch (...) { return 0; }
    return at;
}
static bool in_yield_stub(const probe_session *s, uint64_t ip) {
    for (const auto &kv : s->yield_stubs) if (ip >= kv.second && ip < kv.second + 256) return true;
    return false;
}
static void park_thread(probe_session *s, DWORD tid, DWORD disposition) {
    if (disposition != DBG_CONTINUE || s->detaching || s->exited || thread_in_call(s, tid) || tid == s->inplace_owner ||
        s->stepping.count(tid) || inplace_exempt(s, tid) || target_has_shadow_stack(s))
        return;
    // Not when the program probes NtDelayExecution / NtYieldExecution itself (the stub's call
    // would be its hit).
    if (s->yield_unusable) return;
    if (!s->yield_fn) {
        s->yield_fn = resolve_symbol(s, "ntdll.dll!NtDelayExecution");
        s->yield_spin_fn = resolve_symbol(s, "ntdll.dll!NtYieldExecution");
        if (!s->yield_fn || !s->yield_spin_fn) { s->yield_unusable = true; return; }
    }
    for (const auto &p : s->probes)
        if (p->active && (p->address == s->yield_fn || p->address == s->yield_spin_fn)) return;
    if (!s->yielded_round.insert(tid).second) return;          // once per round
    HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (!t) return;
    CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
    // Not a thread resuming with RF or TF (a hw hit re-run at its site, a step): the stub's
    // first instruction would consume the flag, and the site would trap again at the jump back.
    const uint64_t stub = GetThreadContext(t, &c) && !(c.EFlags & 0x10100u) && !in_yield_stub(s, (uint64_t)EMU_IP(c))
                          ? yield_stub(s, tid) : 0;
    if (stub) {
        // Every thread of a round yields until the SAME moment (absolute): they are off the CPU
        // (or yielding it) together from the last one's yield to then -- staggered 2 ms sleeps
        // barely overlapped (the yields come one event apart). Sleep while the 1 ms timer is on
        // (something may be starved: free the CPU), spin-yield once rounds backed off (see stub).
        // Sleep (the target's own timer: ~15.6 ms, off the CPU -- what a starved thread needs)
        // while rounds find demand or have not yet found 8 in a row without; spin-yield ~4 ms
        // once they backed off (nobody to give the CPU to: keep the round short).
        // Several hot threads: always sleep -- spinning yielders hold CPUs the debugger needs for the
        // events of those not yet parked (measured: t4 hw ~660 us/hit spinning vs ~560 sleeping).
        const bool sleep = s->quiet_rounds < 8 || s->hot_prev.size() > 1 || s->hot_now.size() > 1;
        // The sleep ends at the round's absolute system-time deadline -- in the target's own
        // timer resolution, so at the first clock tick after it (0-15.6 ms, as before phase 3;
        // a relative sleep always took the full 15.6 ms and starved the hot threads).
        uint64_t head[4] = {(uint64_t)EMU_IP(c), (uint64_t)s->round_wake, sleep ? 0u : 1u, (uint64_t)s->round_wake_ft};
        // (x86: the stub reads [0] and [8] as dwords -- the low halves; [16] as a byte.)
        size_t w = 0;
        if (remote_write(s->pi.hProcess, stub, head, sizeof(head), &w) && w == sizeof(head)) {
            EMU_IP(c) = (decltype(EMU_IP(c)))(stub + 32);
            c.ContextFlags = CONTEXT_CONTROL;
            if (SetThreadContext(t, &c)) ++s->parked_total;
        }
    }
    CloseHandle(t);
}
// Called by the event loop around every wait. `blocked`: how long the last wait for a debug
// event blocked (the target ran unfrozen meanwhile, give or take), `got`: an event came.
// Returns the next wait's timeout.
// The target's threads as the kernel schedules them (NtQuerySystemInformation,
// SystemProcessInformation): does any thread other than the round's yielders want the CPU
// (initialized, ready, running, standby, in transition, deferred ready)? Asked only in a round's
// quiet time -- no debug event pending, so no thread is frozen and states are real (during the
// freeze of an event every thread reads Waiting/Suspended, and a thread-pool worker blocked in
// its queue even gains cycles from each freeze and thaw: measured, bench/perfab/threadstates.py).
// A thread that ran in the quiet time and went back to a wait of its own got what it wanted.
namespace {
struct SysThread {                       // SYSTEM_THREAD_INFORMATION
    LARGE_INTEGER KernelTime, UserTime, CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    HANDLE UniqueProcess, UniqueThread;  // CLIENT_ID
    LONG Priority, BasePriority;
    ULONG ContextSwitches, ThreadState, WaitReason;
};
struct SysProc {                         // SYSTEM_PROCESS_INFORMATION; SysThread[NumberOfThreads] follow
    ULONG NextEntryOffset, NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount, NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime, UserTime, KernelTime;
    struct { USHORT Length, MaximumLength; PWSTR Buffer; } ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId, InheritedFromUniqueProcessId;
    ULONG HandleCount, SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize, VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage,
           QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage, PrivatePageCount;
    LARGE_INTEGER ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount,
                  WriteTransferCount, OtherTransferCount;
};
}
// 1 = another thread wants the CPU, 0 = none does, -1 = unknown (query failed). A thread in a
// Suspended wait cannot run now and is passed over (in quiet ticks the program's main thread
// often reads so -- measured, hitcost_target -- while a starved Sleep, below, still reads its
// own wait). Wanting it:
// - runnable at two idle ticks in a row (>= 1 ms apart) -- a starved thread still is; a thread
//   the last event's thaw made Ready for a moment (a thread-pool worker resuming only to wait
//   again on its queue: measured) is not; or
// - it RAN since the previous tick (its context-switch count moved) and is not now back in a
//   thread-pool queue wait: a thread that wakes now and then (a Sleep(10) loop, a timer) needs
//   the CPU every time it wakes, and with rounds 80 ms apart each wake would wait that long
//   (regress hunt-starve: main's Sleep steps). The thaw's own churn moves a queue-waiting
//   worker's count, hence the exception for those.
static int others_runnable(probe_session *s) {
    using QueryFn = LONG(NTAPI *)(ULONG, PVOID, ULONG, PULONG);
    static auto query = reinterpret_cast<QueryFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!query) return -1;
    auto &buf = s->sysproc_buf;
    if (buf.size() < (256u << 10)) buf.resize(256u << 10);
    LONG st;
    for (int k = 0; k < 4; ++k) {
        ULONG need = 0;
        st = query(5 /* SystemProcessInformation */, buf.data(), (ULONG)buf.size(), &need);
        if (st != (LONG)0xC0000004) break;                     // STATUS_INFO_LENGTH_MISMATCH
        buf.resize(std::max<size_t>(buf.size() * 2, (size_t)need + (64u << 10)));
    }
    if (st < 0) return -1;
    std::unordered_set<DWORD> now;
    std::unordered_map<DWORD, ULONG> cs_now;
    uint32_t others = 0, suspended = 0;
    int r = [&]() -> int {
    for (size_t off = 0;;) {
        if (off + sizeof(SysProc) > buf.size()) return -1;
        const auto *p = reinterpret_cast<const SysProc *>(buf.data() + off);
        if ((DWORD)(uintptr_t)p->UniqueProcessId == s->pi.dwProcessId) {
            const auto *t = reinterpret_cast<const SysThread *>(p + 1);
            for (ULONG i = 0; i < p->NumberOfThreads; ++i) {
                if ((const unsigned char *)(t + i + 1) > buf.data() + buf.size()) return -1;
                const DWORD tid = (DWORD)(uintptr_t)t[i].UniqueThread;
                const ULONG state = t[i].ThreadState;
                if (inplace_exempt(s, tid)) continue;              // our agent's own threads (cached)
                if (s->yielded_round.count(tid) || s->hot_now.count(tid) || s->hot_prev.count(tid)) continue;   // a hot thread
                ++others;
                if (state == 5 && t[i].WaitReason == 5) {
                    if (trace_enabled() && !suspended && s->rounds_by_demand[0] < 8) {
                        using QFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                        static auto qit2 = reinterpret_cast<QFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
                        PVOID start = nullptr;
                        if (HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)) { qit2(h, 9, &start, sizeof(start), nullptr); CloseHandle(h); }
                        std::string where = "?"; uint64_t best = 0;
                        for (const auto &m : s->module_bases)
                            if (m.second <= (uint64_t)(uintptr_t)start && m.second > best) { best = m.second; where = m.first; }
                        std::fprintf(stderr, "  fair-suspended tid=%lu start=%s+0x%llx ours=%d yielded=%zu\n", (unsigned long)tid,
                                     where.c_str(), (unsigned long long)((uint64_t)(uintptr_t)start - best), our_suspends(s, tid),
                                     s->yielded_round.size());
                    }
                    ++suspended;
                    continue;                                   // a suspended thread cannot run now
                }
                if (!s->yielded_round.count(tid) && state == 5 && (t[i].WaitReason == 4 || t[i].WaitReason == 11)) {
                    // In a Sleep (DelayExecution): its timeout elapses only while the process is
                    // not frozen (measured: hunt-starve's main slept 300 ms for 4 s of rounds that
                    // found nothing runnable) -- it needs the rounds as much as a runnable thread.
                    if (trace_enabled() && s->rounds_by_demand[2] < 12)
                        std::fprintf(stderr, "  fair-demand tid=%lu sleeping\n", (unsigned long)tid);
                    return 1;
                }
                if (!s->yielded_round.count(tid)) {
                    cs_now[tid] = t[i].ContextSwitches;
                    const auto was = s->cs_prev.find(tid);
                    if (was != s->cs_prev.end() && was->second != t[i].ContextSwitches &&
                        state == 5 && t[i].WaitReason != 15 /* WrQueue */) {
                        if (trace_enabled() && s->rounds_by_demand[2] < 12)
                            std::fprintf(stderr, "  fair-demand tid=%lu ran (cs %lu -> %lu) state=%lu wait=%lu\n", (unsigned long)tid,
                                         (unsigned long)was->second, (unsigned long)t[i].ContextSwitches,
                                         (unsigned long)state, (unsigned long)t[i].WaitReason);
                        return 1;
                    }
                }
                // 0 Initialized, 1 Ready, 2 Running, 3 Standby, 6 Transition, 7 DeferredReady
                if ((state <= 3 || state == 6 || state == 7) && !s->yielded_round.count(tid)) {
                    now.insert(tid);
                    if (!s->runnable_prev.count(tid)) continue;
                    if (trace_enabled() && s->rounds_by_demand[2] < 12) {
                        using QFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                        static auto qit = reinterpret_cast<QFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
                        PVOID start = nullptr;
                        if (HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)) { qit(h, 9, &start, sizeof(start), nullptr); CloseHandle(h); }
                        std::string where = "?"; uint64_t best = 0;
                        for (const auto &m : s->module_bases)
                            if (m.second <= (uint64_t)(uintptr_t)start && m.second > best) { best = m.second; where = m.first; }
                        std::fprintf(stderr, "  fair-demand tid=%lu state=%lu wait=%lu cs=%lu start=%s+0x%llx\n", (unsigned long)tid,
                                     (unsigned long)state, (unsigned long)t[i].WaitReason, (unsigned long)t[i].ContextSwitches,
                                     where.c_str(), (unsigned long long)((uint64_t)(uintptr_t)start - best));
                    }
                    return 1;
                }
            }
            return 0;
        }
        if (!p->NextEntryOffset) return -1;
        off += p->NextEntryOffset;
    }
    }();
    s->runnable_prev = std::move(now);
    s->cs_prev = std::move(cs_now);
    (void)others;
    return r;
}
// An idle tick inside a yield round (no debug event pending: the round's hot threads sleep):
// asks whether anything else wants the CPU. The round's verdict needs two ticks (see
// others_runnable); with fewer it stays unknown and the period is left as it is.
static void round_quiet_tick(probe_session *s) {
    // At most two queries a round, and only in its quiet time: a query takes milliseconds on a
    // busy machine, and a hot thread that wakes and hits meanwhile waits for it (measured: one
    // query per idle tick through the round made windows with a single event, hw ~180 us/hit).
    const auto now = std::chrono::steady_clock::now();
    if (!s->parking || s->yielded_round.empty() || s->round_demand >= 0 || now >= s->round_quiet_until ||
        now < s->next_quiet_sample || s->hot_prev.size() > 1 || s->hot_now.size() > 1)
        return;
    s->next_quiet_sample = now + std::chrono::microseconds(700);
    const int r = others_runnable(s);
    if (r == -1 || r > 0) { s->round_demand = 1; return; }         // runnable, or unknown: as before (20 ms rounds)
    if (s->quiet_sampled) s->round_demand = 0;                     // a second tick compared: nobody
    s->quiet_sampled = true;
}
DWORD fair_tick(probe_session *s, std::chrono::steady_clock::duration blocked, bool got) {
    using namespace std::chrono;
    const auto now = steady_clock::now();
    if (s->fair_window == steady_clock::time_point{}) s->fair_window = now;
    s->fair_gaps += blocked;
    if (got) s->last_event = now;
    if (got) ++s->fair_events;
    if (!got) round_quiet_tick(s);
    if (now - s->fair_window >= milliseconds(s->fair_period_ms)) {
        // The round that just ended: something else ran in its quiet time -> rounds every 20 ms
        // (it may be starved); nothing did -> twice the period, to 80 ms; no quiet tick
        // compared (the round never went quiet) -> unchanged.
        if (s->parking) ++s->rounds_by_demand[s->round_demand + 1];
        // Hysteresis: back off only after 8 rounds in a row found nobody (~200 ms). A thread in a
        // timed wait shows only when its timeout completes -- and the timeout elapses only while
        // the process is not frozen (measured: a 10 ms WaitForSingleObject loop beside a hot hw
        // probe completed 13 times in 1.75 s with no rounds, 9 in 2.1 s when one sighting reset
        // the period for a single round): one sighting keeps it served for the next ones.
        // A round that never went quiet (a yielder was not parked, or events kept coming: no
        // verdict) counts as one without demand too: it gave nobody anything either, and leaving
        // the period as it was made the back-off -- so a run's speed -- depend on luck (CI x86
        // log-throughput-hw: two identical gated runs 1.6 s apart).
        // Several hot threads: the rounds of before (20 ms, sleeping yielders, no probing) -- the
        // probing's queries and quiet-time polling slowed the hot threads' own events there
        // (t4 hw ~660 us/hit vs ~560 without), and with several hot threads a starved one is the
        // common case (hunt-starve).
        const bool multi_hot = s->hot_prev.size() > 1 || s->hot_now.size() > 1;
        if (s->parking && multi_hot) { s->fair_period_ms = 20; s->quiet_rounds = 0; }
        else if (s->parking) {
            if (s->round_demand > 0) { s->fair_period_ms = 20; s->quiet_rounds = 0; }
            else if (++s->quiet_rounds >= 8) s->fair_period_ms = std::min<uint32_t>(80, s->fair_period_ms * 2);
        }
        s->round_demand = -1; s->quiet_sampled = false; s->runnable_prev.clear();   // cs_prev carries over
        s->hot_prev.swap(s->hot_now); s->hot_now.clear();
        const bool was = s->parking;
        // Dense debug events (>= 2000/s: the target is mostly frozen) -- or little unfrozen
        // time -- start a yield round: every thread whose hit is continued in the next window
        // sleeps ~2 ms once (park_thread), so all of them are off the CPU together for a moment
        // and a thread that hits nothing runs. (Measured: with the unfrozen-time rule alone, a
        // fast session kept >10% unfrozen yet main's Sleep(300) returned 3-20 s late: whenever
        // unfrozen, the hot threads had the CPU and trapped again before main was scheduled.)
        // (A window holding a round of ~15.6 ms sleep has few events by construction: still dense
        // if the yielders kept hitting around it -- else the back-off never accumulated.)
        const bool dense = s->fair_events >= (s->parking ? 5u : 40u) || s->fair_gaps * 10 < now - s->fair_window;
        s->parking = got && dense;
        s->fair_events_last = s->fair_events;
        s->fair_events = 0;
        if (s->parking) {
            ++s->park_rounds; s->yielded_round.clear();
            // 4 ms -- 2 ms once backed off (spinning yielders, nobody seen wanting the CPU).
            const bool backed_off = s->quiet_rounds >= 8 && s->hot_prev.size() <= 1;
            s->round_wake = (LONGLONG)interrupt_time_now() + (backed_off ? 20000 : 40000);   // (the stubs' clock)
            FILETIME ft; GetSystemTimeAsFileTime(&ft);                // ... and as system time, for a sleep
            s->round_wake_ft = (LONGLONG)(((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime) + 40000;
            s->next_quiet_sample = now + microseconds(backed_off ? 400 : 800);
            s->round_quiet_until = now + microseconds(backed_off ? 2000 : 4000);
        }
        if (s->parking && !was) {
            if (trace_enabled())
                std::fprintf(stderr, "  park-start t=%lld\n",
                             (long long)duration_cast<microseconds>(now.time_since_epoch()).count());
        }
        // Dense events stopped: the next dense phase starts afresh (noticed within 20 ms). A window
        // that merely ended on an idle tick (a round's quiet time) keeps the back-off state.
        if (!dense) { s->fair_period_ms = 20; s->quiet_rounds = 0; }
        if (trace_enabled() && s->park_rounds < 40)
            std::fprintf(stderr, "  fair-window events=%u gaps_us=%lld window_us=%lld dense=%d got=%d parking=%d period=%u quiet_rounds=%u\n",
                         s->fair_events_last, (long long)duration_cast<microseconds>(s->fair_gaps).count(),
                         (long long)duration_cast<microseconds>(now - s->fair_window).count(), (int)dense, (int)got,
                         (int)s->parking, s->fair_period_ms, s->quiet_rounds);
        s->fair_window = now; s->fair_gaps = {};
    }
    // 1 ms timer resolution only while a parked thread or a context watch waits on this loop:
    // process-wide, it also makes every Sleep(1) of the controller's own threads (the log
    // drainer) wake 15x as often -- a writer that never sees its queue empty kept a mid-run
    // probe_report (flush) waiting for the target to finish.
    if (s->rekick_at && GetTickCount64() >= s->rekick_at) {
        s->rekick_at = 0;
        if (agent_has_pending(s)) retarget_pending(s);
        if (agent_has_pending(s) && !kick_agent(s)) std::fprintf(stderr, "probe: %s\n", s->error.c_str());
    }
    // Not for the yield rounds: since Windows 10 2004 a process's timeBeginPeriod sets the timer
    // resolution of THAT process only -- the controller's 1 ms never shortened a stub's sleep in
    // the target (a "4 ms" round slept ~15.6 ms: windows of 4-28 events and 15-17 ms idle,
    // measured), it only made this loop's own waits finer, and kept on through the dense events
    // it cost a lone hot thread ~30% on the VM (hw 144 -> 110 us/hit, breakpoint 90 -> 72). The
    // quiet time is sampled by polling (below); the stubs time themselves.
    const bool fine = !s->ctx_watch.empty() || s->rekick_at;
    if (fine != s->fine_timer) { if (fine) timeBeginPeriod(1); else timeEndPeriod(1); s->fine_timer = fine; }
    // A round's quiet time (its yielders spin until round_wake, no timer involved) is sampled
    // without the 1 ms timer: the loop polls (no wait) until it ends -- ~4 ms per round.
    if (s->parking && now < s->round_quiet_until && s->round_demand < 0 && s->hot_prev.size() <= 1 &&
        s->hot_now.size() <= 1)
        return 0;
    return fine ? 1 : 20;
}

// Re-apply OUR changes (after vs before) to a context the target wrote back: a field the target
// left at its value from the event (it wrote back what it captured then) gets ours; a field the
// target set to something else keeps the target's.
template <class T> static bool merge_field(T &cur, const T &before, const T &after) {
    if (!std::memcmp(&after, &before, sizeof(T)) || std::memcmp(&cur, &before, sizeof(T))) return false;
    std::memcpy(&cur, &after, sizeof(T));
    return true;
}
static bool merge_context(CONTEXT &cur, const CONTEXT &b, const CONTEXT &a) {
    bool m = false;
#define UHH_MERGE(f) m |= merge_field(cur.f, b.f, a.f)
#if defined(_WIN64)
    UHH_MERGE(Rip); UHH_MERGE(Rsp); UHH_MERGE(Rbp); UHH_MERGE(Rax); UHH_MERGE(Rbx); UHH_MERGE(Rcx); UHH_MERGE(Rdx);
    UHH_MERGE(Rsi); UHH_MERGE(Rdi); UHH_MERGE(R8); UHH_MERGE(R9); UHH_MERGE(R10); UHH_MERGE(R11); UHH_MERGE(R12);
    UHH_MERGE(R13); UHH_MERGE(R14); UHH_MERGE(R15); UHH_MERGE(FltSave);
#else
    UHH_MERGE(Eip); UHH_MERGE(Esp); UHH_MERGE(Ebp); UHH_MERGE(Eax); UHH_MERGE(Ebx); UHH_MERGE(Ecx); UHH_MERGE(Edx);
    UHH_MERGE(Esi); UHH_MERGE(Edi); UHH_MERGE(FloatSave); UHH_MERGE(ExtendedRegisters);
#endif
    // Debug registers: only the status (DR6). Our slots are put back by enforce_owned_drs from
    // the CURRENT probe state (a probe may have been armed, moved or released since the event):
    // the one place that re-applies debug registers, as at NtContinue (restore_fixup).
    UHH_MERGE(EFlags); UHH_MERGE(Dr6);
#undef UHH_MERGE
    return m;
}
static bool same_context(const CONTEXT &x, const CONTEXT &y) {
    CONTEXT t = x;
    return !merge_context(t, x, y);          // no field of y differs from x
}
// At an exception event, before it is handled: is the thread suspended by the TARGET (more
// suspensions than ours)? Then the target may be in the middle of a context round-trip on it.
static std::unique_ptr<probe_session::CtxWatch> ctx_watch_begin(probe_session *s, DWORD tid) {
    if (s->detaching || s->exited) return nullptr;
    // The common case, cheaply: the event's own thread handle (no OpenThread / CloseHandle per
    // event; ~4-8 us a breakpoint/hw hit before) says nobody but us has it suspended.
    if (auto h = s->thread_handle.find(tid); h != s->thread_handle.end()) {
        const long n = suspend_count(h->second);
        if (n >= 0 && n <= our_suspends(s, tid)) return nullptr;
    }
    HANDLE t = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                          THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!t) return nullptr;
    const long n = suspend_count(t);
    if (n <= our_suspends(s, tid)) { CloseHandle(t); return nullptr; }
    auto w = std::make_unique<probe_session::CtxWatch>();
    w->tid = tid; w->t = t;
    w->before.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(t, &w->before)) { CloseHandle(t); return nullptr; }
    return w;
}
// After the event was handled, before it is continued: if we changed the thread's context, hold
// it (one suspension of ours) until the target has resumed it, then repair (ctx_watch_poll).
static void ctx_watch_end(probe_session *s, std::unique_ptr<probe_session::CtxWatch> w) {
    if (!w) return;
    w->after.ContextFlags = CONTEXT_ALL;
    if (s->skip_continue || s->exited || s->detaching || !GetThreadContext(w->t, &w->after) || same_context(w->before, w->after)) {
        CloseHandle(w->t); return;
    }
    guard_note_hold(s, w->tid);
    if (SuspendThread(w->t) == (DWORD)-1) { CloseHandle(w->t); return; }
    w->deadline = GetTickCount64() + 2000;
    if (trace_enabled()) std::fprintf(stderr, "  ctx-watch tid=%lu\n", (unsigned long)w->tid);
    try { s->ctx_watch.push_back(std::move(w)); } catch (...) { ResumeThread(w->t); CloseHandle(w->t); }
}
void ctx_watch_poll(probe_session *s, bool all) {
    for (size_t i = 0; i < s->ctx_watch.size(); ) {
        auto &w = *s->ctx_watch[i];
        // The target may write its captured trap context back at ANY time during its
        // suspension. Keep the repair until it resumes; a timeout cannot make that
        // stale resume address safe. Detach drains the watch explicitly (all=true).
        if (!all && GetTickCount64() >= w.deadline) {
            std::fprintf(stderr, "probe: warning: context repair waiting for target suspension on thread %lu\n",
                         (unsigned long)w.tid);
            w.deadline = ~ULONGLONG{0};
        }
        const long n = suspend_count(w.t);
        if (!all && n > our_suspends(s, w.tid)) { ++i; continue; }    // the target still holds it
        CONTEXT cur{}; cur.ContextFlags = CONTEXT_ALL;
        if (n >= 0 && GetThreadContext(w.t, &cur) && merge_context(cur, w.before, w.after)) {
            // The target wrote back the context it captured during our event: ours again.
            if (s->dr_ever) enforce_owned_drs(s, w.tid, cur, false);
            cur.ContextFlags = CONTEXT_ALL;
            GuardTouch touch(s, w.tid);
            SetThreadContext(w.t, &cur);
            if (trace_enabled()) std::fprintf(stderr, "  ctx-repaired tid=%lu\n", (unsigned long)w.tid);
        }
        // Suspended again by the target meanwhile: it may have captured the context before our
        // repair, to write it back later -- keep holding, look again after its resume.
        if (!all && suspend_count(w.t) > our_suspends(s, w.tid)) { ++i; continue; }
        ResumeThread(w.t); CloseHandle(w.t);
        s->ctx_watch.erase(s->ctx_watch.begin() + (ptrdiff_t)i);
        guard_resync(s);
    }
}
static void forget_thread_holds(probe_session *s, DWORD tid) {
    for (auto it = s->parked.begin(); it != s->parked.end(); )
        if (it->first == tid) { CloseHandle(it->second); it = s->parked.erase(it); } else ++it;
    for (auto it = s->ctx_watch.begin(); it != s->ctx_watch.end(); )
        if ((*it)->tid == tid) { CloseHandle((*it)->t); it = s->ctx_watch.erase(it); } else ++it;
}

// Service a hardware-breakpoint #DB (a single-step exception carrying a DR status
// bit, not one of our software single-steps). Returns false on error; sets handled
// when a DR we own fired. RF lets the flagged instruction run once without re-trapping.
// The event thread's handle for a breakpoint / hw hit: opened once per thread (context, suspend,
// query rights) and kept until its EXIT_THREAD (refreshed at a CREATE_THREAD: a reused id), not
// an OpenThread + CloseHandle per hit.
HANDLE event_thread(probe_session *s, DWORD tid) {
    if (auto it = s->own_thread_handle.find(tid); it != s->own_thread_handle.end()) return it->second;
    HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                          FALSE, tid);
    if (h) {
        try { s->own_thread_handle[tid] = h; } catch (...) { CloseHandle(h); return nullptr; }
    }
    return h;
}
void forget_event_thread(probe_session *s, DWORD tid) {
    if (auto it = s->own_thread_handle.find(tid); it != s->own_thread_handle.end()) {
        CloseHandle(it->second); s->own_thread_handle.erase(it);
    }
}

// "exception 0xc0000005 at msvcp140.dll+0x1234 (read 0x0)" plus a hint for known causes.
// What an address in the target IS, from its memory map: "thing.dll+0x41a0" inside a loaded
// image; otherwise the raw address plus the kind of memory (unmapped, reserved, heap/stack
// /private, mapped file) and, for committed memory, its protection -- e.g. why a write
// faulted. `module` receives the image's name (empty if none).
// Local wall-clock time "2026-11-05 15:40:12.345", for crash reports.
static std::string wall_clock() {
    SYSTEMTIME st{}; GetLocalTime(&st);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u.%03u", st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static const char *protect_name(DWORD p) {
    switch (p & 0xFF) {
    case PAGE_NOACCESS: return "PAGE_NOACCESS"; case PAGE_READONLY: return "PAGE_READONLY";
    case PAGE_READWRITE: return "PAGE_READWRITE"; case PAGE_WRITECOPY: return "PAGE_WRITECOPY";
    case PAGE_EXECUTE: return "PAGE_EXECUTE"; case PAGE_EXECUTE_READ: return "PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE"; case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
    default: return "?";
    }
}

static std::string module_offset(probe_session *s, uint64_t address, std::string *module = nullptr,
                                 bool with_protect = false) {
    if (module) module->clear();
    char buf[200];
    MEMORY_BASIC_INFORMATION m{};
    if (!s->pi.hProcess || !VirtualQueryEx(s->pi.hProcess, (void *)(uintptr_t)address, &m, sizeof(m))) {
        std::snprintf(buf, sizeof(buf), "0x%llx (not a valid address)", (unsigned long long)address);
        return buf;
    }
    const uint64_t alloc = (uint64_t)(uintptr_t)m.AllocationBase;
    if (m.State == MEM_COMMIT && m.Type == MEM_IMAGE) {
        std::string name;
        for (const auto &kv : s->module_bases) if (kv.second == alloc) { name = kv.first; break; }
        if (name.empty()) { char b[32]; std::snprintf(b, sizeof(b), "image@0x%llx", (unsigned long long)alloc); name = b; }
        if (module) *module = name;
        std::snprintf(buf, sizeof(buf), "%s+0x%llx", name.c_str(), (unsigned long long)(address - alloc));
        if (with_protect && (m.Protect & (PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE | PAGE_NOACCESS))) {
            std::string out = buf;
            return out + " [" + protect_name(m.Protect) + "]";
        }
        return buf;
    }
    const char *kind = m.State == MEM_FREE ? "unmapped" : m.State == MEM_RESERVE ? "reserved, not committed"
                     : m.Type == MEM_MAPPED ? "mapped view" : "private memory (heap/stack/VirtualAlloc)";
    if (m.State == MEM_COMMIT)
        std::snprintf(buf, sizeof(buf), "0x%llx (%s, %s%s)", (unsigned long long)address, kind, protect_name(m.Protect),
                      (m.Protect & PAGE_GUARD) ? "|PAGE_GUARD" : "");
    else
        std::snprintf(buf, sizeof(buf), "0x%llx (%s%s)", (unsigned long long)address, kind,
                      address < 0x10000 ? ", null page" : "");
    return buf;
}

static std::string describe_fault(probe_session *s, const EXCEPTION_RECORD &ex, DWORD code, uint64_t address) {
    std::string where;
    char buf[256];
    std::snprintf(buf, sizeof(buf), "exception 0x%08lx at %s", (unsigned long)code, module_offset(s, address, &where).c_str());
    std::string out = buf;
    if (code == EXCEPTION_ACCESS_VIOLATION && ex.NumberParameters >= 2) {
        const ULONG_PTR kind = ex.ExceptionInformation[0];
        out += std::string(" (") + (kind == 8 ? "execute" : kind ? "write" : "read") + " of " +
               module_offset(s, (uint64_t)ex.ExceptionInformation[1], nullptr, true) + ")";
    }
    std::string lower = where;
    for (auto &ch : lower) ch = (char)std::tolower((unsigned char)ch);
    if (lower.rfind("msvcp140", 0) == 0 || lower.rfind("vcruntime140", 0) == 0)
        out += " -- the target's MSVC runtime is older than the one probe_api_agent.dll was built "
               "against; rebuild UHH with -DUHH_STATIC_CRT=ON (the default)";
    return out;
}

// The crashing thread's call stack, one frame per line as module+offset (raw return
// addresses, no symbol lookup on this thread), so a crash is diagnosable from stderr alone.
static void print_crash_stack(probe_session *s, DWORD tid) {
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
    CONTEXT w{}; w.ContextFlags = CONTEXT_FULL;
    if (!thread || !GetThreadContext(thread, &w)) { if (thread) CloseHandle(thread); return; }
#if defined(_WIN64)
    const uint64_t pc = w.Rip, sp = w.Rsp, fp = w.Rbp;
#else
    const uint64_t pc = w.Eip, sp = w.Esp, fp = w.Ebp;
#endif
    std::vector<uint64_t> frames;
    if (!s->sym_ready || !uhh_sym::walk_stack(s->pi.hProcess, thread, w, pc, sp, fp, frames, PROBE_STACK_MAX_FRAMES))
        frames.assign(1, pc);
    CloseHandle(thread);
    for (size_t i = 0; i < frames.size(); ++i)
        std::fprintf(stderr, "probe:   #%zu %s\n", i, module_offset(s, frames[i]).c_str());
}

// PROBE_TRACE diagnostics: every target thread's symbolized stack (each thread briefly
// suspended for its context), e.g. when an install hold does not confirm -- shows what the
// agent's service thread is waiting on and what the held threads own.
void trace_thread_stacks(probe_session *s, const char *why) {
    std::fprintf(stderr, "  thread stacks (%s) t=%llu:\n", why, (unsigned long long)GetTickCount64());
    for (DWORD tid : s->threads) {
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!thread) continue;
        const DWORD prev = SuspendThread(thread);
        CONTEXT w{}; w.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(thread, &w)) {
#if defined(_WIN64)
            const uint64_t pc = w.Rip, sp = w.Rsp, fp = w.Rbp;
#else
            const uint64_t pc = w.Eip, sp = w.Esp, fp = w.Ebp;
#endif
            std::vector<uint64_t> frames;
            if (!s->sym_ready || !uhh_sym::walk_stack(s->pi.hProcess, thread, w, pc, sp, fp, frames, 24))
                frames.assign(1, pc);
            std::fprintf(stderr, "  tid=%lu suspend=%lu%s\n", (unsigned long)tid, (unsigned long)prev,
                         agent_thread(s, tid) ? " (agent)" : "");
            for (size_t i = 0; i < frames.size(); ++i)
                std::fprintf(stderr, "    #%zu %s %s\n", i, module_offset(s, frames[i]).c_str(),
                             s->sym_ready ? uhh_sym::symbolize(s->pi.hProcess, frames[i]).c_str() : "");
        }
        if (prev != (DWORD)-1) ResumeThread(thread);
        CloseHandle(thread);
    }
}

// A thread whose in-place step at `site` faulted, the fault passed to the program (see
// probe_session::refault), is at the INT3 at that site again, with no event in between: is
// this its handler RETRYING the faulted execution (EXCEPTION_CONTINUE_EXECUTION at the site:
// no new hit), or a FRESH execution after the handler skipped the instruction or unwound out
// of it (a new hit)? The kernel built the exception's dispatcher frame -- the CONTEXT the
// handler got and returned, and the EXCEPTION_RECORD -- on the thread's stack just below the
// faulting SP, and a retry is the very first instruction after that CONTEXT was restored: it
// is still there, naming the site, and the thread's registers are exactly its registers
// (whatever the handler repaired). A skip left it naming another address; an unwind rewrote
// it (x64 RtlUnwindEx uses it as its working context) or left its record marked
// EXCEPTION_UNWINDING (x86 RtlUnwind) -- a fresh execution of the site then matches nothing
// (comparing the registers with the fault's took a repaired retry for a new hit). `now` is the
// thread's context at the INT3 (CONTEXT_INTEGER | CONTEXT_CONTROL).
static bool fault_retried(probe_session *s, const CONTEXT &now, uint64_t site, DWORD code) {
    const uint64_t sp = (uint64_t)EMU_SP(now);
    constexpr uint64_t span = 32 * 1024;            // the frame (CONTEXT, record, XSAVE area) lies within
    // Readable stack below SP, page by page (a query answers from the address's page UP).
    uint64_t lo = sp;
    while (lo > 0x10000 && sp - lo < span) {
        MEMORY_BASIC_INFORMATION m{};
        if (!VirtualQueryEx(s->pi.hProcess, (void *)(uintptr_t)(lo - 1), &m, sizeof(m)) || m.State != MEM_COMMIT ||
            (m.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
            break;
        lo = std::max<uint64_t>((uint64_t)(uintptr_t)m.BaseAddress, sp > span ? sp - span : 0);
    }
    std::vector<unsigned char> buf((size_t)(sp - lo));
    size_t got = 0;
    if (buf.size() < sizeof(CONTEXT) || !remote_read(s->pi.hProcess, lo, buf.data(), buf.size(), &got) || got != buf.size())
        return false;
#if defined(_WIN64)
    constexpr DWORD arch = CONTEXT_AMD64;
    constexpr size_t align = 16, ip_at = offsetof(CONTEXT, Rip);
    using ip_t = DWORD64;
#else
    constexpr DWORD arch = CONTEXT_i386;
    constexpr size_t align = 4, ip_at = offsetof(CONTEXT, Eip);
    using ip_t = DWORD;
#endif
    const DWORD need = (CONTEXT_CONTROL | CONTEXT_INTEGER) & ~arch;
    for (size_t o = (size_t)((align - lo % align) % align); o + sizeof(CONTEXT) <= buf.size(); o += align) {
        ip_t ip;
        std::memcpy(&ip, buf.data() + o + ip_at, sizeof(ip));
        if ((uint64_t)ip != site) continue;
        CONTEXT c;
        std::memcpy(&c, buf.data() + o, sizeof(c));
        if (!(c.ContextFlags & arch) || (c.ContextFlags & need) != need) continue;
#if defined(_WIN64)
        const bool regs = c.Rsp == now.Rsp && c.Rax == now.Rax && c.Rcx == now.Rcx && c.Rdx == now.Rdx &&
                          c.Rbx == now.Rbx && c.Rbp == now.Rbp && c.Rsi == now.Rsi && c.Rdi == now.Rdi &&
                          c.R8 == now.R8 && c.R9 == now.R9 && c.R10 == now.R10 && c.R11 == now.R11 &&
                          c.R12 == now.R12 && c.R13 == now.R13 && c.R14 == now.R14 && c.R15 == now.R15;
#else
        const bool regs = c.Esp == now.Esp && c.Eax == now.Eax && c.Ecx == now.Ecx && c.Edx == now.Edx &&
                          c.Ebx == now.Ebx && c.Ebp == now.Ebp && c.Esi == now.Esi && c.Edi == now.Edi;
#endif
        if (!regs) continue;
#if !defined(_WIN64)
        // x86: KiUserExceptionDispatcher is entered with [esp] = &record, [esp+4] = &context,
        // just below the two. An unwind (RtlUnwind) leaves this CONTEXT intact but marks its
        // record unwinding.
        const uint32_t at = (uint32_t)(lo + o);
        for (size_t q = o > 0x1000 ? o - 0x1000 : 0; q + 8 <= o; q += 4) {
            uint32_t pr = 0, pc = 0;
            std::memcpy(&pr, buf.data() + q, 4); std::memcpy(&pc, buf.data() + q + 4, 4);
            if (pc != at || pr < lo || (uint64_t)pr + sizeof(EXCEPTION_RECORD) > sp) continue;
            EXCEPTION_RECORD r;
            std::memcpy(&r, buf.data() + (pr - lo), sizeof(r));
            if (r.ExceptionCode == code && (uint64_t)(uintptr_t)r.ExceptionAddress == site &&
                (r.ExceptionFlags & 0x6 /* EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND */))
                return false;
        }
#else
        (void)code;
#endif
        return true;
    }
    return false;
}

#if defined(UHH_TEST_HOOKS)
bool test_fault_retried(probe_session *s, const CONTEXT &now, uint64_t site, DWORD code) {
    return fault_retried(s, now, site, code);
}
#endif

static bool handle_exception(probe_session *s, const DEBUG_EVENT &event,
                             std::unordered_map<DWORD, StepState> &stepping,
                             bool &initial_break, DWORD &disposition) {
    auto &ex = event.u.Exception.ExceptionRecord; DWORD code = ex.ExceptionCode;
    // A 32-bit (WOW64) target's traps can arrive in their WOW64 form; they are the same
    // events as far as the probes are concerned.
    if (code == 0x4000001Eu /*STATUS_WX86_SINGLE_STEP*/) code = EXCEPTION_SINGLE_STEP;
    else if (code == 0x4000001Fu /*STATUS_WX86_BREAKPOINT*/) code = EXCEPTION_BREAKPOINT;
    disposition = DBG_EXCEPTION_NOT_HANDLED;
    // Defer before completing a software step: replay must see both the watch
    // and its original StepState, and must not enter another callback meanwhile.
    if (code == EXCEPTION_SINGLE_STEP && (s->in_call_tid || !s->calls.empty()) &&
        defer_hits_now(s, event.dwThreadId)) {
        CONTEXT dr{}; dr.ContextFlags = CONTEXT_ALL;
        HANDLE t = event_thread(s, event.dwThreadId);
        if (t && GetThreadContext(t, &dr)) {
            dr.Dr6 |= dr6_carried(s, event.dwThreadId);
            uint8_t theirs = 0;
            for (int k = 0; k < 4; ++k)
                if (target_owns_slot(s, event.dwThreadId, dr, k)) theirs |= (uint8_t)(1u << k);
            if (hold_watch_hit(s, event, dr, theirs)) {
                disposition = s->watch_deferred.back().reply_later ? DBG_REPLY_LATER : DBG_CONTINUE;
                return true;
            }
        }
    }
    // A REP string instruction ran out-of-line to completion and reached the INT3 placed
    // after its copy: land on the instruction after the probe site (no trap flag was used).
    if (code == EXCEPTION_BREAKPOINT) {
        auto st = stepping.find(event.dwThreadId);
        const uint64_t at = (uint64_t)(uintptr_t)ex.ExceptionAddress;
        if (st != stepping.end() && st->second.tail_int3 && st->second.scratch &&
            at == st->second.scratch + st->second.insn_len) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
            bool ok = t && GetThreadContext(t, &w);
#if defined(_WIN64)
            w.Rip = st->second.site + st->second.insn_len;
#else
            w.Eip = (DWORD)(st->second.site + st->second.insn_len);
#endif
            ok = ok && SetThreadContext(t, &w);
            if (t) CloseHandle(t);
            if (!ok) { set_error(s, win_error("complete out-of-line string instruction")); return false; }
            stepping.erase(st);
            disposition = DBG_CONTINUE; return true;
        }
        // Another thread has an in-place window open (our INT3 lifted at its site): this hit
        // was raised before the window and queued. Rewind it onto the INT3 -- the thread is
        // held in the window and hits it again afterwards, counted then, exactly once.
        if (s->inplace_owner && event.dwThreadId != s->inplace_owner && probe_at(s, at)) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
            bool ok = t && GetThreadContext(t, &w);
            EMU_IP(w) = (decltype(EMU_IP(w)))at;
            ok = ok && SetThreadContext(t, &w);
            if (t) CloseHandle(t);
            if (!ok) { set_error(s, win_error("replay a hit after the in-place window")); return false; }
            disposition = DBG_CONTINUE; return true;
        }
    }
    // The loader's initial breakpoint -- but only if it is not one of OUR INT3s: a probe
    // can fire during loader initialisation (e.g. ntdll!NtCreateFile from the shim engine),
    // before the loader breakpoint, and must be handled as a probe hit, not swallowed.
    if (code == EXCEPTION_BREAKPOINT && !initial_break &&
        !probe_at(s, (uint64_t)(uintptr_t)ex.ExceptionAddress) && !s->retired_bps.count((uint64_t)(uintptr_t)ex.ExceptionAddress)) {
        initial_break = true; disposition = DBG_CONTINUE; return true;
    }
    if (code == PROBE_IPC_CODE && handle_ipc(s, event)) { disposition = DBG_CONTINUE; return true; }
    auto step = stepping.find(event.dwThreadId);
    uint64_t address = (uint64_t)(uintptr_t)ex.ExceptionAddress;
    if (step != stepping.end() && step->second.refire &&
        (address != step->second.site || code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP)) {
        // A faulted instruction re-run without our trap flag (see refire) that did NOT fault
        // again: the thread ran on with the byte lifted. Arm the site again; this event is new.
        end_inplace_step(s, event.dwThreadId, step->second.site);
        stepping.erase(step);
        step = stepping.end();
    }
    bool restart = false;            // this INT3 is a faulted in-place step restarting (see refault)
    if (auto rf = s->refault.find(event.dwThreadId); rf != s->refault.end() && step == stepping.end()) {
        const uint64_t site = rf->second.site;
        const DWORD fault_code = rf->second.code;
        s->refault.erase(rf);                              // one event decides
        if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
            const bool got = t && GetThreadContext(t, &w);
            const bool tf = got && (w.EFlags & 0x100u);
            // The fault reached the program WITHOUT our trap flag (the in-place step re-runs a
            // faulting instruction without it; WOW64 drops it anyway), and this is the thread's
            // next event. An INT3 at the site is either its handler retrying the same execution
            // (no new hit) or, after the handler skipped the instruction or unwound out of it,
            // a fresh execution of the site (a new hit): the exception's own dispatcher frame
            // tells (fault_retried).
            const bool same = got && code == EXCEPTION_BREAKPOINT && address == site && fault_retried(s, w, site, fault_code);
            if (trace_enabled() && code == EXCEPTION_BREAKPOINT && address == site)
                std::fprintf(stderr, "refault tid=%lu site=0x%llx: %s\n", (unsigned long)event.dwThreadId,
                             (unsigned long long)site, same ? "the handler's retry" : "a new execution");
            if ((tf || same) && code == EXCEPTION_BREAKPOINT && address == site) {
                restart = true;                            // same execution: no new hit
            } else if (tf && code == EXCEPTION_SINGLE_STEP) {
                // The handler continued elsewhere with our trap flag: one instruction ran,
                // this is its trap. Drop the flag and let the thread run on.
                w.EFlags &= ~0x100u;
                const bool ok = !!SetThreadContext(t, &w);
                CloseHandle(t);
                if (!ok) { set_error(s, win_error("clear stray trap flag")); return false; }
                disposition = DBG_CONTINUE; return true;
            }
            if (t) CloseHandle(t);
        }
    }
    Probe *probe = code == EXCEPTION_BREAKPOINT ? probe_at(s, address) : nullptr;
    if (code == EXCEPTION_BREAKPOINT && !probe && !s->retired_bps.count(address))
        probe = adopt_relocated_breakpoint(s, address);   // our INT3, copied by another hooking tool
    if (code == EXCEPTION_BREAKPOINT && !probe && s->retired_bps.count(address)) {
        // Another thread hit a one-shot INT3 that has since been removed: the original
        // byte is back, so rewind to it and continue as if the breakpoint never existed.
        unsigned char now = 0; size_t got = 0;
        if (remote_read(s->pi.hProcess, address, &now, 1, &got) && got == 1 && now != 0xcc) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
            bool ok = t && GetThreadContext(t, &w);
#if defined(_WIN64)
            w.Rip = address;
#else
            w.Eip = (DWORD)address;
#endif
            ok = ok && SetThreadContext(t, &w);
            if (t) CloseHandle(t);
            if (!ok) { set_error(s, win_error("rewind stale breakpoint")); return false; }
            disposition = DBG_CONTINUE; return true;
        }
    }
    if (trace_enabled())
        std::fprintf(stderr, "EV code=0x%lx tid=%lu addr=0x%llx step=%d probe=%d first=%lu\n",
                     (unsigned long)code, (unsigned long)event.dwThreadId,
                     (unsigned long long)address, step != stepping.end(), probe != nullptr,
                     (unsigned long)event.u.Exception.dwFirstChance);
    if (code == EXCEPTION_SINGLE_STEP && step == stepping.end() && !s->gates.empty()) {
        bool handled = false;
        bool failed = false;
        const bool gate = handle_gate(s, event, handled, &failed);
        if (failed) return false;
        if (gate) {
            if (handled) disposition = DBG_CONTINUE;
            return true;
        }
    }
    if (code == EXCEPTION_SINGLE_STEP && step == stepping.end() && (s->hw_active || s->dr_ever)) {
        bool handled = false;
        if (!handle_hw(s, event, handled)) return false;
        if (handled) { disposition = DBG_CONTINUE; return true; }   // else fall through (not our DR)
        // A trap at the address of a hardware probe we have RELEASED, raised before the
        // release reached this thread (its debug status no longer names the slot): ours,
        // stale. Clear our slots on the thread, step over with RF, and swallow it.
        // A stale image of an inline install GATE (the gate is cleared once the hook is in, but
        // a context record written while it was live -- the restore fixup -- can bring it back
        // on a thread that has run since): a #DB exactly at one of our inline sites from a slot
        // we no longer use is ours. Off on this thread; the site runs (its hook) with RF.
        bool stale_gate = false;
        for (const auto &p : s->probes)
            if ((p->flags & PROBE_INLINE) && p->address == address) { stale_gate = true; break; }
        for (const auto &g : s->gates) if (g.first == address) stale_gate = false;
        if (stale_gate) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
            bool ours = false;
            if (t && GetThreadContext(t, &w)) {
                for (int slot = 0; slot < 4; ++slot) {
                    if (!(s->dr_ever & (1u << slot)) || (s->dr_used & (1u << slot)) || !((w.Dr7 >> (slot * 2)) & 3) ||
                        dr_address(w, slot) != address || target_owns_slot(s, event.dwThreadId, w, slot)) continue;
                    w.Dr7 &= ~((DWORD64)3 << (slot * 2)) & ~((DWORD64)0xF << (16 + slot * 4));
                    ours = true;
                }
                if (ours) {
                    w.Dr6 = 0;
                    w.EFlags |= 0x10000u;
                    SetThreadContext(t, &w);
                    if (trace_enabled()) std::fprintf(stderr, "  stale gate tid=%lu at 0x%llx\n", (unsigned long)event.dwThreadId,
                                                      (unsigned long long)address);
                }
            }
            if (t) CloseHandle(t);
            if (ours) { disposition = DBG_CONTINUE; return true; }
        }
        // (An INLINE probe at that address does not count: a cleared install gate's #DB is ours.)
        bool hw_live_here = false;
        for (const auto &p : s->probes)
            if (p->active && (p->flags & PROBE_HW) && p->address == address) { hw_live_here = true; break; }
        // Detaching: every probe is released and nothing of ours gets armed again, so a #DB from a
        // slot we have used, holding an address we armed, is ours however the thread got it: its
        // #DB was in flight when the release cleared the slot (delivering it restores the debug
        // registers captured at the raise, all of ours still enabled) and the thread no longer
        // counts as unsettled. Passed on, it killed the target (lifecycle-{reattach,interrupt}-hw;
        // the agent's guard VEH used to swallow it). Off on this thread, the instruction runs.
        if (s->detaching && !hw_live_here) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
            bool ours = false;
            if (t && GetThreadContext(t, &w)) {
                for (int slot = 0; slot < 4; ++slot) {
                    if (!(s->dr_ever & (1u << slot)) || !((w.Dr7 >> (slot * 2)) & 3) ||
                        !s->hw_armed_ever.count(dr_address(w, slot)))
                        continue;
                    ours = ours || (w.Dr6 & (1u << slot)) || dr_address(w, slot) == address;
                    w.Dr7 &= ~((DWORD64)3 << (slot * 2)) & ~((DWORD64)0xF << (16 + slot * 4));
                }
                if (ours) {
                    if (!(w.Dr7 & 0xFF)) w.Dr7 &= ~(decltype(w.Dr7))0x300;
                    w.Dr6 = 0;
                    w.EFlags |= 0x10000u;                              // RF: run the instruction once
                    SetThreadContext(t, &w);
                    if (trace_enabled()) std::fprintf(stderr, "  detach-stale #DB tid=%lu at 0x%llx\n",
                                                      (unsigned long)event.dwThreadId, (unsigned long long)address);
                }
            }
            if (t) CloseHandle(t);
            if (ours) { disposition = DBG_CONTINUE; return true; }
        }
        if (hw_released_on(s, event.dwThreadId, address) && !hw_live_here) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
            if (t && GetThreadContext(t, &w)) {
                for (int slot = 0; slot < 4; ++slot) {
                    if (!(s->dr_ever & (1u << slot)) || (s->dr_used & (1u << slot))) continue;   // keep live probes
                    if (target_owns_slot(s, event.dwThreadId, w, slot)) continue;                                 // and the target's own
                    w.Dr7 &= ~((DWORD64)3 << (slot * 2)) & ~((DWORD64)0xF << (16 + slot * 4));
                }
                w.Dr6 = 0;
                w.EFlags |= 0x10000u;                                  // RF: run the instruction once
                SetThreadContext(t, &w);
            }
            if (t) CloseHandle(t);
            disposition = DBG_CONTINUE; return true;
        }
    }
    if (event.dwThreadId == s->remote_tid && s->remote_tid && event.u.Exception.dwFirstChance &&
        code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP && code != PROBE_IPC_CODE &&
        s->remote_fault.empty()) {
        // The agent's load/init thread faulted. If the target's own unhandled-exception
        // filter swallows it, all we would see is the thread's exit code: keep where it was.
        s->remote_fault = describe_fault(s, ex, code, address);
        std::fprintf(stderr, "probe: %s agent thread %s\n", wall_clock().c_str(), s->remote_fault.c_str());
    } else if (!event.u.Exception.dwFirstChance && code != PROBE_IPC_CODE) {
        // Unhandled: the target is about to die. Say where, whatever the cause.
        std::fprintf(stderr, "probe: %s target crashed: tid=%lu %s\n", wall_clock().c_str(), (unsigned long)event.dwThreadId,
                     describe_fault(s, ex, code, address).c_str());
        print_crash_stack(s, event.dwThreadId);
    }
    // A stray trap-flag step inside our scratch slots with no step in progress: the target
    // wrote back a context it captured mid-step (see the jump-back after each displaced
    // copy). Ours, not the target's: drop TF and let the thread run the jump back.
    if (code == EXCEPTION_SINGLE_STEP && step == stepping.end()) {
        bool in_scratch = false;
        for (uint64_t b : s->scratch_blocks) if (address >= b && address < b + 0x10000) { in_scratch = true; break; }
        if (in_scratch) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
            if (t && GetThreadContext(t, &w)) { w.EFlags &= ~0x100u; SetThreadContext(t, &w); }
            if (t) CloseHandle(t);
            disposition = DBG_CONTINUE; return true;
        }
    }
    if (trace_enabled() && code == EXCEPTION_ACCESS_VIOLATION && ex.NumberParameters >= 2) {
        unsigned char around[24] = {0}; size_t got = 0;
        remote_read(s->pi.hProcess, address - 8, around, sizeof(around), &got);
        std::fprintf(stderr, "  AV %s 0x%llx first=%lu bytes[-8..+16]=%s\n",
                     ex.ExceptionInformation[0] == 8 ? "execute" : ex.ExceptionInformation[0] ? "write" : "read",
                     (unsigned long long)ex.ExceptionInformation[1], (unsigned long)event.u.Exception.dwFirstChance,
                     hex_bytes(around, got).c_str());
    }
    if (code != EXCEPTION_SINGLE_STEP && code != EXCEPTION_BREAKPOINT && !probe && step == stepping.end() &&
        event.u.Exception.dwFirstChance) {
        // A fault raised by the instruction in a displaced trampoline (no step state: the copy
        // runs without a trap flag). Handled as a faulting displaced copy, below.
        uint64_t tr = 0;
        if (const auto *d = dtramp_at(s, address, &tr); d && address < tr + d->len && d->probe) {
            StepState st{d->probe, true, d->site, d->len, tr, false, d->probe->rep_string, false};
            stepping[event.dwThreadId] = st;
            step = stepping.find(event.dwThreadId);
        }
    }
    if (code != EXCEPTION_SINGLE_STEP && !probe && step != stepping.end() && step->second.displaced &&
        event.u.Exception.dwFirstChance) {
        // The displaced copy faulted. The target must see that fault at the REAL
        // instruction (its own SEH/C++ handlers and unwind data are keyed to it), so
        // swallow this one and re-run the instruction in place: lift our byte, step it
        // there; it faults again at the right address and is passed through below.
        uint64_t scratch = step->second.scratch;
        if (scratch && address >= scratch && address < scratch + step->second.insn_len + 16) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
            bool ok = t && GetThreadContext(t, &w);
            bool armed = still_armed(s, step->second.site);
            Probe *owner = armed ? probe_at(s, step->second.site) : nullptr;
            if (ok && owner) restore_original(s->pi.hProcess, step->second.site, owner->original);
            // (Whoever owns the copy -- a breakpoint, a hardware probe's trampoline, a probe gone
            //  since: the re-run at the real instruction must raise the guard fault itself.)
            if (ok && code == STATUS_GUARD_PAGE_VIOLATION && ex.NumberParameters >= 2) {
                // The copy's access consumed the page's one-shot guard: put it back, so the
                // re-run raises the guard violation the program expects at the real instruction.
                MEMORY_BASIC_INFORMATION m{};
                void *page = (void *)(uintptr_t)ex.ExceptionInformation[1];
                DWORD old = 0;
                if (VirtualQueryEx(s->pi.hProcess, page, &m, sizeof(m)) && m.State == MEM_COMMIT && !(m.Protect & PAGE_GUARD))
                    VirtualProtectEx(s->pi.hProcess, page, 1, m.Protect | PAGE_GUARD, &old);
            }
#if defined(_WIN64)
            w.Rip = step->second.site;
#else
            w.Eip = (DWORD)step->second.site;
#endif
            if (owner) w.EFlags |= 0x100u; else w.EFlags &= ~0x100u;
            // A hardware probe's trampoline: the re-run at the site must not hit its DR again.
            if (!owner && step->second.probe && (step->second.probe->flags & PROBE_HW)) w.EFlags |= 0x10000u;
            ok = ok && SetThreadContext(t, &w);
            if (t) CloseHandle(t);
            if (!ok) { set_error(s, win_error("re-run faulting displaced instruction")); return false; }
            if (owner) {
                step->second.displaced = false; step->second.tail_int3 = false;
                step->second.windowed = true; inplace_begin(s, event.dwThreadId);   // lifted: hold the others
            } else {
                stepping.erase(step);
            }
            disposition = DBG_CONTINUE; return true;
        }
    }
    // Exceptions Windows raises ONLY because a debugger is attached (closing an invalid or
    // protected handle): without UHH the call just returns an error, so continue them.
    if ((code == 0xC0000008u /*STATUS_INVALID_HANDLE*/ || code == 0xC0000235u /*HANDLE_NOT_CLOSABLE*/) &&
        event.u.Exception.dwFirstChance && !probe) {
        disposition = DBG_CONTINUE; return true;
    }
    if ((code != EXCEPTION_SINGLE_STEP || step == stepping.end()) && !probe) {
        // An unexpected exception (a fault in the out-of-line copy, or any app
        // exception) reached a thread still mid-step. Drop its stale StepState so a
        // later stray single-step can't teleport it to site+insn_len; re-arm the byte
        // if the step was in-place. Pass the exception through unchanged.
        if (step != stepping.end()) {
            if (!step->second.displaced && event.u.Exception.dwFirstChance && address == step->second.site &&
                code != EXCEPTION_BREAKPOINT && step->second.windowed && !step->second.refire && !step->second.prog_tf) {
                // The instruction faulted during its in-place step: the kernel hands the program's
                // handler the context AS IT FAULTED -- with OUR trap flag (x64; WOW64 drops it),
                // which the program must never see. Swallow this one and run the instruction once
                // more without the flag (byte still lifted, window still held): it faults again,
                // and THAT fault, with the program's own flags, is the one passed on (below). A
                // guard page the faulting access consumed is put back first. Should the re-run
                // not fault after all, the window's watchdog re-arms the site (inplace_watchdog).
                HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
                CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
                if (t && GetThreadContext(t, &w) && (w.EFlags & 0x100u) && (uint64_t)EMU_IP(w) == address) {
                    if (code == STATUS_GUARD_PAGE_VIOLATION && ex.NumberParameters >= 2) {
                        MEMORY_BASIC_INFORMATION m{};
                        void *page = (void *)(uintptr_t)ex.ExceptionInformation[1];
                        DWORD old = 0;
                        if (VirtualQueryEx(s->pi.hProcess, page, &m, sizeof(m)) && m.State == MEM_COMMIT && !(m.Protect & PAGE_GUARD))
                            VirtualProtectEx(s->pi.hProcess, page, 1, m.Protect | PAGE_GUARD, &old);
                    }
                    w.EFlags &= ~0x100u;
                    if (SetThreadContext(t, &w)) {
                        CloseHandle(t);
                        step->second.refire = true;
                        disposition = DBG_CONTINUE; return true;
                    }
                }
                if (t) CloseHandle(t);
            }
            if (!step->second.displaced) {
                end_inplace_step(s, event.dwThreadId, step->second.site);
                // The instruction itself raised during its in-place step (e.g. the re-run of a
                // faulting displaced copy; re-run once more without our trap flag, above).
                // Remember it, to tell a restart of this same execution (the handler continues
                // at the site: the INT3 again) from a new hit.
                if (event.u.Exception.dwFirstChance && address == step->second.site) {
                    probe_session::Refault rf; rf.site = step->second.site; rf.code = code;
                    s->refault[event.dwThreadId] = rf;
                }
            }
            stepping.erase(step);
        }
        return true;
    }
    if (code == EXCEPTION_BREAKPOINT && step != stepping.end() && !step->second.displaced &&
        step->second.site == address) {
        // This thread is mid in-place step AT this site: its own hit was queued while another
        // thread had the byte lifted, it was set up to run the original instruction, and that
        // other thread's step completion re-armed the INT3 first. It executed our INT3 instead
        // of the instruction: the same execution, not a new hit (it was a double callback).
        // Put it back on the site, lift the byte again, and let its step run.
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
        CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
        bool ok = t && GetThreadContext(t, &w);
#if defined(_WIN64)
        w.Rip = address;
#else
        w.Eip = (DWORD)address;
#endif
        w.EFlags |= 0x100u;
        ok = ok && patch(s->pi.hProcess, address, probe->original) && SetThreadContext(t, &w);
        if (t) CloseHandle(t);
        if (!ok) { set_error(s, win_error("re-lift in-place step")); return false; }
        if (step->second.windowed) inplace_begin(s, event.dwThreadId);
        disposition = DBG_CONTINUE; return true;
    }
    HANDLE thread = event_thread(s, event.dwThreadId);      // cached: see event_thread
    if (!thread) { set_error(s, win_error("open event thread")); return false; }
    CONTEXT native{}; native.ContextFlags = CONTEXT_ALL;
    if (code == EXCEPTION_SINGLE_STEP && step != stepping.end()) {
        // The stepped instruction (displaced or in place) may itself have touched a
        // watched address: then this #DB carries B-bits as well as BS. Service those
        // hardware hits first (their callbacks run, DR6 is cleared), then finish the step.
        bool hw_hit = false;
        bool target_hw = false;
        {
            CONTEXT dr{}; dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(thread, &dr) && ((dr.Dr6 | dr6_carried(s, event.dwThreadId)) & 0xF)) {
                bool handled = false;
                const bool hw_ok = handle_hw(s, event, handled);
                // call_func parks this fiber; other events can rehash the map.
                step = stepping.find(event.dwThreadId);
                if (!hw_ok) { return false; }
                if (step == stepping.end()) return true; // the thread exited during the call
                hw_hit = handled; target_hw = !handled;
            }
        }
        if (step->second.tail_int3) {
            // No trap flag is set for a string instruction running out-of-line: this #DB is a
            // watchpoint it touched (serviced above) -- the copy keeps running to its INT3.
           
            if (hw_hit) { disposition = DBG_CONTINUE; return true; }
            return true;                                   // not ours: pass it through
        }
        bool ok = !!GetThreadContext(thread, &native);
        if (ok && !step->second.displaced && step->second.rep_string &&
            (uint64_t)EMU_IP(native) == step->second.site) {
            // An in-place REP string step traps after each iteration: keep stepping (INT3
            // still lifted, trap flag kept) until the instruction completes, so the callback
            // runs once per execution, as on every other backend.
            native.EFlags |= 0x100u;
            ok = !!SetThreadContext(thread, &native);
           
            if (!ok) { set_error(s, win_error("continue string instruction step")); return false; }
            if (!target_hw && !step->second.prog_tf) disposition = DBG_CONTINUE;
            return true;
        }
        if (step->second.displaced) {
            // The instruction ran out-of-line; the INT3 was never lifted, so there is
            // nothing to re-arm — just land on the instruction after the probe site.
            uint64_t next = step->second.site + step->second.insn_len;
#if defined(_WIN64)
            native.Rip = next;
#else
            native.Eip = (DWORD)next;
#endif
        } else if (ok) {
            end_inplace_step(s, event.dwThreadId, step->second.site);                                   // in-place: re-arm
            if (step->second.pushf_insn && !step->second.prog_tf &&
                (uint64_t)EMU_IP(native) == step->second.site + step->second.insn_len) {
                // PUSHF ran with OUR trap flag: the program's flags image must not show it
                // (RtlCaptureContext starts with pushfq).
                uint64_t v = 0; size_t n = 0; const size_t w = sizeof(void *);
                const uint64_t sp = (uint64_t)EMU_SP(native);
                if (remote_read(s->pi.hProcess, sp, &v, w, &n) && n == w && (v & 0x100)) {
                    v &= ~(uint64_t)0x100;
                    remote_write(s->pi.hProcess, sp, &v, w, &n);
                }
            }
        }
        if (!step->second.prog_tf) {
            if (step->second.popf_insn && (uint64_t)EMU_IP(native) == step->second.site + step->second.insn_len)
                native.EFlags = (native.EFlags & ~0x100u) | (step->second.popf_tf ? 0x100u : 0u);
            else native.EFlags &= ~0x100u;
            native.Dr6 &= ~(decltype(native.Dr6))0x4000u; // BS came from our step, not the target
        }
#if defined(_WIN64)
        // SYSCALL saves RFLAGS in R11 -- with the trap flag WE set for the step. The program
        // can read R11 after the syscall; give it the flags image it would have had.
        if (!step->second.displaced && step->second.syscall_insn && !step->second.prog_tf) native.R11 &= ~(DWORD64)0x100;
#endif
        if (ok) ok = !!SetThreadContext(thread, &native);
       
        if (!ok) { set_error(s, win_error("complete breakpoint single-step")); return false; }
        if (trace_enabled())
            std::fprintf(stderr, "  step-done tid=%lu displaced=%d\n",
                         (unsigned long)event.dwThreadId, step->second.displaced);
        const bool pass = target_hw || step->second.prog_tf;
        if (pass && !step->second.prog_tf && event.u.Exception.dwFirstChance &&
            !queue_debug_delivery(s, event.dwThreadId, (uint64_t)EMU_IP(native), 0x4000u, native.Dr6 & 0xE00Fu)) return false;
        stepping.erase(step);
        if (!pass) disposition = DBG_CONTINUE;
        return true;
    }
    if (!GetThreadContext(thread, &native)) {                 // a stale cached handle (a missed EXIT_THREAD): reopen once
        forget_event_thread(s, event.dwThreadId);
        thread = event_thread(s, event.dwThreadId);
        if (!thread || !GetThreadContext(thread, &native)) { set_error(s, win_error("get breakpoint context")); return false; }
    }
    if (code == EXCEPTION_BREAKPOINT && address == s->debug_dispatch_addr &&
        !repair_debug_delivery(s, event.dwThreadId, native)) return false;
    if (defer_hits_now(s, event.dwThreadId) && !probe->internal &&
        defer_hit_during_call(s, event.dwThreadId, address, true)) {
        disposition = DBG_CONTINUE; return true;
    }
    bool co_pass = false;                            // call_original's own entry pass: not a hit
    if (s->co_addr && event.dwThreadId == s->in_call_tid && !probe->internal) {
#if defined(_WIN64)
        const uint64_t sp = native.Rsp;
#else
        const uint64_t sp = native.Esp;
#endif
        if (s->co_entry_pending && address == s->co_addr && sp == s->co_sp) {
            s->co_entry_pending = false; co_pass = true;
        } else if ((sp >= s->co_sp || co_slot_gone(s, sp) || co_unwound(s, event.dwThreadId, native, address)) &&
                   defer_hit_during_call(s, event.dwThreadId, address, true)) {
            // The call_original thread is back at (or above) the hit's frame without having
            // returned, or deeper with the original's frame gone (co_slot_gone): the original
            // was left by an exception or longjmp. This hit is a NEW one -- rewind it; it is
            // serviced normally once the call is released.
            s->co_left = true; disposition = DBG_CONTINUE; return true;
        }
    }
    if (s->entry_reapply && address == s->entry_reapply && !probe->internal) reapply_all_hw(s);
    bool at_entry = s->entry_addr && address == s->entry_addr && !s->entry_seen;
    if (at_entry) s->entry_seen = true;
    probe_context context = from_context(native, probe_index(s, probe),
                                         address, &callback_ops, s);
    context.config = probe->config.empty() ? nullptr : probe->config.data();
    context.tid = event.dwThreadId;
    CallbackState state{s, probe, event.dwProcessId, event.dwThreadId}; context.controller = &state;
    s->cb_tid = event.dwThreadId;
    // A probe hit INSIDE a call_func/call_original callee: step over it (the library's own
    // internal breakpoints still do their work there).
    if ((probe->internal || !thread_in_call(s, event.dwThreadId)) && !restart)
    try { run_callback(s, probe, &context); s->cb_tid = 0; }
    catch (const std::exception &e) {
        set_error(s, std::string("probe callback: ") + e.what()); return false;
    } catch (...) {
        set_error(s, "probe callback threw an unknown exception"); return false;
    }
    if (!co_pass && !restart && !(s->quiet_tid && event.dwThreadId == s->quiet_tid && !probe->internal)) count_hit(probe);
    if (state.released) {        // call_original released the thread: it runs on, nothing to write back
        s->skip_continue = true; return true;
    }
    to_context(context, native);
#if defined(_WIN64)
    native.Rsp = context.regs.rsp;
#else
    native.Esp = (DWORD)context.regs.rsp;
#endif
    if (apply_return_from(s, probe, context, native)) {
        // The body is skipped: resume at the `ret` gadget, the INT3 stays armed (a
        // one-shot is retired here instead).
        if ((probe->flags & PROBE_ONCE) && patch(s->pi.hProcess, probe->address, probe->original)) {
            probe->active = false; probe->retired = true; s->retired_bps.insert(probe->address); sync_int3_table(s);
        }
        native.ContextFlags = CONTEXT_FULL | UHH_CONTEXT_FP;      // FP: the original's result (see apply_return_from)
        bool ok = !!SetThreadContext(thread, &native);
       
        if (!ok) { set_error(s, win_error("resume at return_from")); return false; }
        if (at_entry && inline_hold_needed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
        disposition = DBG_CONTINUE; return true;
    }
    if (probe->flags & PROBE_ONCE) {
        // One-shot: put the original byte back for good and resume AT the site -- the
        // real instruction runs in place, no single-step needed. Stale hits from other
        // threads are rewound via retired_bps above.
        if (!patch(s->pi.hProcess, probe->address, probe->original)) {
            set_error(s, win_error("retire one-shot breakpoint")); return false;
        }
        probe->active = false; probe->retired = true; s->retired_bps.insert(probe->address); sync_int3_table(s);
#if defined(_WIN64)
        native.Rip = probe->address;
#else
        native.Eip = (DWORD)probe->address;
#endif
        native.ContextFlags = CONTEXT_FULL;   // keep any DRs the callback armed
        bool ok = !!SetThreadContext(thread, &native);
       
        if (!ok) { set_error(s, win_error("resume after one-shot")); return false; }
        if (at_entry && inline_hold_needed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
        disposition = DBG_CONTINUE; return true;
    }
    bool target_debug = (native.EFlags & 0x100u) != 0;
    for (int slot = 0; slot < 4; ++slot)
        if (((native.Dr7 >> (slot * 2)) & 3) &&
            (target_owns_slot(s, event.dwThreadId, native, slot) || !s->hw_armed_ever.count(dr_address(native, slot))))
            target_debug = true;
#if defined(_WIN64)
    // SYSCALL / INT 2E: run from the site's trampoline -- the INT3 stays armed, no trap flag
    // (R11 gets the program's flags), and a syscall that blocks or returns elsewhere (APC,
    // NtContinue, a user-mode callback that hits probes on this thread) needs nothing from us.
    if (uint64_t tr = target_debug ? 0 : syscall_trampoline(s, *probe)) {
        native.Rip = tr;
        native.ContextFlags = CONTEXT_FULL;
        bool ok = !!SetThreadContext(thread, &native);
       
        if (!ok) { set_error(s, win_error("enter syscall trampoline")); return false; }
        if (at_entry && inline_hold_needed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
        disposition = DBG_CONTINUE; return true;
    }
#endif
    // Branches, call/ret, loop, pushf/popf: executed here on the context -- the INT3 stays
    // armed (exact under threads) and no trap flag is ever set (nothing leaks).
    if (!target_debug && !probe->displaced_ok && emulate_site(s, *probe, native)) {
        native.ContextFlags = CONTEXT_FULL;               // keep any DRs the callback armed
        bool ok = !!SetThreadContext(thread, &native);
       
        if (!ok) { set_error(s, win_error("apply emulated instruction")); return false; }
        if (at_entry && inline_hold_needed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
        disposition = DBG_CONTINUE; return true;
    }
    // Displaced execution (default for ordinary instructions): run the original instruction
    // out-of-line with the INT3 left armed, so no other thread can cross this site unobserved
    // (no re-arm race) and no thread is suspended (no deadlock). Normally from the site's
    // trampoline, which jumps back by itself (one event per hit, see displaced_trampoline).
    // Target-owned debug exceptions must arise at the real instruction, so their exception
    // address as well as their context remains the program's own.
    if (probe->displaced_ok && !target_debug) {
        if (const uint64_t tr = displaced_trampoline(s, *probe)) {
            EMU_IP(native) = (decltype(EMU_IP(native)))tr;
            native.ContextFlags = CONTEXT_FULL;               // keep any DRs the callback armed
            const bool ok = !!SetThreadContext(thread, &native);
           
            if (!ok) { set_error(s, win_error("enter displaced trampoline")); return false; }
#if defined(UHH_TEST_HOOKS)
            if (probe->rep_string && !probe->internal) test_note_repcopy();   // a thread now in the string copy
#endif
            if (trace_enabled())
                std::fprintf(stderr, "  tramp tid=%lu site=0x%llx tramp=0x%llx\n", (unsigned long)event.dwThreadId,
                             (unsigned long long)probe->address, (unsigned long long)tr);
            if (at_entry && inline_hold_needed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
            disposition = DBG_CONTINUE; return true;
        }
    }
    bool displaced = probe->displaced_ok && !target_debug;
    uint64_t scratch_addr = displaced ? thread_scratch(s, event.dwThreadId, probe->address) : 0;
    if (displaced && scratch_addr) {
        std::vector<unsigned char> code = probe->orig_insn;
        if (probe->riprel_disp_off >= 0) {
            int32_t disp; std::memcpy(&disp, code.data() + probe->riprel_disp_off, sizeof(disp));
            // Preserve the same absolute target when the copy runs from scratch.
            int64_t nd = (int64_t)disp + (int64_t)(probe->address - scratch_addr);
            if (nd < INT32_MIN || nd > INT32_MAX) displaced = false;
            else { int32_t v = (int32_t)nd; std::memcpy(code.data() + probe->riprel_disp_off, &v, sizeof(v)); }
        }
        if (probe->rep_string) code.push_back(0xCC);       // the copy runs to completion, then traps here
        // Follow the copy with a jump back to the next real instruction. Normally never
        // executed (the single-step lands us there), but a target that captures a thread's
        // context while it reports the step (Suspend + GetThreadContext, e.g. a GC or its own
        // context round-trip) and writes it back after we moved it, resumes the thread HERE:
        // it must continue correctly instead of running whatever follows in the slot.
        if (displaced) {
            const uint64_t back = probe->address + probe->insn_len;
#if defined(_WIN64)
            const unsigned char jmp[6] = {0xFF, 0x25, 0, 0, 0, 0};   // jmp [rip+0]; dq back
            code.insert(code.end(), jmp, jmp + 6);
            for (int b = 0; b < 8; ++b) code.push_back((unsigned char)(back >> (8 * b)));
#else
            const uint32_t rel = (uint32_t)(back - (scratch_addr + code.size() + 5));
            code.push_back(0xE9);                                     // jmp rel32
            for (int b = 0; b < 4; ++b) code.push_back((unsigned char)(rel >> (8 * b)));
#endif
        }
        size_t wrote = 0;
        if (displaced && (!remote_write(s->pi.hProcess, scratch_addr, code.data(), code.size(), &wrote) ||
                          wrote != code.size())) {
            set_error(s, win_error("stage displaced instruction")); return false;
        }
        if (displaced) FlushInstructionCache(s->pi.hProcess, (void *)(uintptr_t)scratch_addr, code.size());
    } else {
        displaced = false;   // no scratch available -> in-place fallback
    }
    if (displaced) {
#if defined(_WIN64)
        native.Rip = scratch_addr;
#else
        native.Eip = (DWORD)scratch_addr;
#endif
    } else {
        // In-place fallback (sites neither displaced nor emulated, or scratch/reach failure):
        // lift the byte, step over it at the real address, re-arm on the single-step. Every
        // other thread is held meanwhile (in-place window, inplace_begin below).
        if (!patch(s->pi.hProcess, probe->address, probe->original)) {
            set_error(s, win_error("restore probed instruction")); return false;
        }
#if defined(_WIN64)
        native.Rip = probe->address;
#else
        native.Eip = (DWORD)probe->address;
#endif
    }
    const bool tail = displaced && probe->rep_string;
    const bool prog_tf = native.EFlags & 0x100u;
    if (!tail) native.EFlags |= 0x100u;
    // Preserve debug registers: the callback may have armed a hardware probe/watchpoint on
    // THIS thread (probe_watch/probe_add_at); writing CONTEXT_ALL with the pre-callback DR
    // image would clobber it. CONTEXT_FULL writes control/integer/segment only.
    native.ContextFlags = CONTEXT_FULL;
    if (!SetThreadContext(thread, &native)) {
        set_error(s, win_error("apply callback context")); return false;
    }
   
    if (trace_enabled())
        std::fprintf(stderr, "  setup tid=%lu displaced=%d scratch=0x%llx rip=0x%llx\n",
                     (unsigned long)event.dwThreadId, displaced,
                     (unsigned long long)scratch_addr, (unsigned long long)(displaced ? scratch_addr : probe->address));
    const bool is_syscall = probe->orig_insn.size() == 2 && probe->orig_insn[0] == 0x0F && probe->orig_insn[1] == 0x05;
    StepState st{probe, displaced, probe->address, probe->insn_len, displaced ? scratch_addr : 0,
                 tail, probe->rep_string, is_syscall};
    for (size_t i = 0; i < probe->orig_insn.size(); ++i) {
        const unsigned char b = probe->orig_insn[i];
        if (b == 0x66 || b == 0x67 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 ||
            b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) continue;
#if defined(_WIN64)
        if (b >= 0x40 && b <= 0x4F) continue;
#endif
        if (b == 0x9D) {
            uint16_t flags = 0; size_t got = 0;
            st.popf_insn = remote_read(s->pi.hProcess, (uint64_t)EMU_SP(native), &flags, sizeof(flags), &got) && got == sizeof(flags);
            st.popf_tf = (flags & 0x100u) != 0;
        }
        break;
    }
    st.prog_tf = prog_tf;          // (also kept for a displaced copy that faults and re-runs in place)
#if defined(UHH_TEST_HOOKS)
    if (tail && !probe->internal) test_note_repcopy();
#endif
    if (!displaced) {
        bool pushf = false, may_block = false;
        site_traits(*probe, pushf, may_block);
        st.pushf_insn = pushf;
        st.windowed = !may_block;
        if (st.windowed) inplace_begin(s, event.dwThreadId);    // the byte is lifted: hold every other thread
    }
    stepping[event.dwThreadId] = st;
    if (at_entry && inline_hold_needed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
    disposition = DBG_CONTINUE; return true;
}

// One debug event -> library state changes. Shared by probe_run and the detach path.
static bool dispatch_event_impl(probe_session *s, DEBUG_EVENT &event, DWORD &disposition);
bool dispatch_event(probe_session *s, DEBUG_EVENT &event, DWORD &disposition) {
    s->handling.push_back({event.dwThreadId, false});
    struct Handling {                                // handlings on fibers can end in any order
        probe_session *s; DWORD tid;
        ~Handling() {
            s->event_tid = prev;
            auto &h = s->handling;
            for (size_t i = h.size(); i--; ) if (h[i].tid == tid) { h.erase(h.begin() + (ptrdiff_t)i); break; }
        }
        DWORD prev;
    } handling{s, event.dwThreadId, s->event_tid};
    s->event_tid = event.dwThreadId;
    guard_note_hold(s, event.dwThreadId);            // see guard_sync: until the event is continued
    std::unique_ptr<probe_session::CtxWatch> watch;
    if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) watch = ctx_watch_begin(s, event.dwThreadId);
    const bool ok = dispatch_event_impl(s, event, disposition);
    ctx_watch_end(s, std::move(watch));
    // Threads that raise events are the HOT ones (fairness rounds are for the others; one not yet
    // parked in this round is running, not starved: others_runnable passes over them).
    if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && s->parking) s->hot_now.insert(event.dwThreadId);
    // Fairness (see probe_session::parked): the thread of an exception event about to be
    // continued is parked while the target is starved of unfrozen time.
    if (ok && s->parking && event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && !s->skip_continue)
        park_thread(s, event.dwThreadId, disposition);
    // A hardware probe was released while the process runs: threads still starting must meet
    // the thread-start fixup (see probe_session::hw_released). Armed here, outside the loops
    // over the probes that release them, and before any thread runs on.
    if (ok && s->thread_start_due && (s->entry_seen || s->attached) && !s->detaching && !s->exited) {
        s->thread_start_due = false;
        arm_thread_start_fixup(s);
    }
    inplace_sync(s, event);
    // The guard's mirror, after EVERYTHING this event changed (an in-place window's holds are
    // taken / handed over just above) and before the thread runs again. The event's thread
    // stays listed until its event is continued (service_event / fiber_step re-sync just
    // before; its context may still be touched until then, e.g. a resume_after thread's).
    if (!s->exited) guard_sync(s);
    return ok;
}
// A module instance at `base` is gone: its symbols, its recorded base, and its probes (absolute
// ones retired; module ones back to pending, re-armed when the module loads again).
static void module_unloaded(probe_session *s, uint64_t base) {
    // Gates on this instance's copies of other instances' probe sites: gone with it.
    for (auto it = s->extra_gates.begin(); it != s->extra_gates.end(); ) {
        if (it->base != base) { ++it; continue; }
        const uint64_t site = it->site;
        it = s->extra_gates.erase(it);
        for (auto g = s->gates.begin(); g != s->gates.end(); ) {
            if (g->first != site) { ++g; continue; }
            for (DWORD tid : s->threads) {
                HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
                GuardTouch touch(s, tid);
                if (t) { keep_queued_dr6(s, tid, t); clear_dr_on_thread(t, g->second, g->first); CloseHandle(t); }
            }
            s->dr_used &= (uint8_t)~(1u << g->second);
            retire_hw_address(s, g->first);
            g = s->gates.erase(g);
        }
    }
    s->module_instances.erase(std::remove_if(s->module_instances.begin(), s->module_instances.end(),
                                             [base](const auto &m) { return m.second == base; }), s->module_instances.end());
    sym_unload(s, base);
    uint64_t size = 0;
    if (auto sz = s->module_sizes.find(base); sz != s->module_sizes.end()) { size = sz->second; s->module_sizes.erase(sz); }
    for (auto it = s->module_bases.begin(); it != s->module_bases.end(); )
        if (it->second == base) it = s->module_bases.erase(it); else ++it;
    for (auto &p : s->probes) {
        // Absolute-address probes (probe_add_address / probe_watch: base 0) inside the
        // module go with it, for good: there is no module to re-resolve them against, and
        // a stale one would keep its debug register, shadow a new probe at a reused address
        // (its saved instruction bytes run instead) and mask the new code's bytes.
        if (!p->active || p->base || !size || p->address < base || p->address - base >= size) continue;
        std::fprintf(stderr, "probe: %s retired: its module unloaded\n", p->location.c_str());
        if (p->flags & PROBE_INLINE) {
            if (s->shared && p->agent_index < PROBE_AGENT_MAX_PROBES)
                InterlockedExchange(&s->shared->requests[p->agent_index].status, PROBE_AGENT_UNLOADED);
            p->active = false;
        } else if (p->flags & PROBE_HW) {
            release_hw(s, *p);
        } else {
            p->active = false;
            sync_int3_table(s);      // the agent's copy too: a stale entry masks reused memory
        }
        p->retired = true;
    }
    for (auto &p : s->probes) if (p->active && p->base == base) {
        if (p->flags & PROBE_INLINE) {
            // The hooked code went away with its module. The probe goes back to pending,
            // exactly like breakpoint/hw probes: if the module loads again (anywhere),
            // the agent installs a fresh hook at the new address.
            std::fprintf(stderr, "probe: %s unloaded with its module; pending until it loads again\n", p->location.c_str());
            p->active = false; p->vetted = false; p->base = p->address = 0;
            // Tell the agent: its hook there now points at unmapped (or reused) memory,
            // so detach must not write the original bytes back.
            if (s->shared && p->agent_index < PROBE_AGENT_MAX_PROBES)
                InterlockedExchange(&s->shared->requests[p->agent_index].status, PROBE_AGENT_UNLOADED);
        } else if (p->flags & PROBE_HW) {
            // Fully release the hardware breakpoint: clear its DR on every thread,
            // free the slot, and drop the active count. A half-disarm (just
            // clearing active/address) leaks the DR slot and strands the physical
            // breakpoint on the unloaded address -> later slot exhaustion / crash.
            release_hw(s, *p);
            p->base = p->address = 0;
        } else { p->active = false; p->base = p->address = 0; sync_int3_table(s); }
    }
}
// After an instance went away while a newer one of the same module is already mapped at
// `base`: arm the module's pending probes there, with the same install path as a LOAD.
// The other instance may itself be gone already (a mapping the loader discarded): then the probes
// stay pending for the next LOAD -- never a session error.
static bool image_at(probe_session *s, uint64_t base) {
    MEMORY_BASIC_INFORMATION mbi{};
    return VirtualQueryEx(s->pi.hProcess, (void *)(uintptr_t)base, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
           mbi.Type == MEM_IMAGE && (uint64_t)(uintptr_t)mbi.AllocationBase == base;
}
bool arm_quietly(probe_session *s, const std::string &name, uint64_t base) {
    if (!image_at(s, base)) return false;
    const std::string saved = s->error;
    std::vector<std::pair<Probe *, bool>> was;                 // the module's probes: retired before?
    for (auto &p : s->probes) if (iequals(p->module, name)) was.emplace_back(p.get(), p->retired);
    const bool ok = arm_module(s, name, base, false);
    if (!ok) {
        if (trace_enabled()) std::fprintf(stderr, "  re-arm %s at 0x%llx failed (%s): pending\n", name.c_str(),
                                          (unsigned long long)base, s->error.c_str());
        s->error = saved;
        for (auto &w : was)                                      // not armed there: pending again, not retired
            if (!w.first->active) { w.first->retired = w.second; w.first->address = w.first->base = 0; w.first->vetted = false; }
    }
    return ok;
}
static bool arm_after_reload(probe_session *s, const std::string &name, uint64_t base) {
    bool ok = arm_quietly(s, name, base) || true;
    if (trace_enabled()) std::fprintf(stderr, "  re-arm %s at 0x%llx after a late unload\n", name.c_str(), (unsigned long long)base);
    if (ok && agent_has_pending(s)) {
        if (s->shared->service_ready && s->svc_event) { arm_gates_for_pending(s); ok = kick_agent(s); }
        else if (s->remote_agent && s->remote_work == probe_session::REMOTE_NONE) ok = start_agent_init(s);
    }
    return ok;
}

static bool dispatch_event_impl(probe_session *s, DEBUG_EVENT &event, DWORD &disposition) {
    disposition = DBG_CONTINUE; bool ok = true;
    settle_hw_thread(s, event.dwThreadId);           // released hardware probes: still ours on it?
    switch (event.dwDebugEventCode) {
    case CREATE_PROCESS_DEBUG_EVENT: {
        bench_phase("ev_create_process");
        s->threads.insert(event.dwThreadId);                 // initial thread (for HW DRs)
        if (event.u.CreateProcessInfo.hThread) s->thread_handle[event.dwThreadId] = event.u.CreateProcessInfo.hThread;
        uint64_t base = (uint64_t)(uintptr_t)event.u.CreateProcessInfo.lpBaseOfImage;
        std::string name = event_module_name(s->pi.hProcess, event.u.CreateProcessInfo.hFile, base);
        if (!name.empty()) s->module_bases[name] = base;
        sym_register(s, event.u.CreateProcessInfo.hFile, base);
        ok = arm_module(s, name, base, false);
        if (ok && !s->attached) arm_entry_fixup(s, (uint64_t)(uintptr_t)event.u.CreateProcessInfo.lpStartAddress);
        if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
        break;
    }
    case CREATE_THREAD_DEBUG_EVENT:
        s->threads.insert(event.dwThreadId);
        if (event.u.CreateThread.hThread) s->thread_handle[event.dwThreadId] = event.u.CreateThread.hThread;
        forget_event_thread(s, event.dwThreadId);                // a reused id: the old handle is another thread's
        if (s->ipc_freezer) ipc_freeze_thread(s, event.dwThreadId);   // born during a hook write: hold it too
        // A debug register the program set on the thread before it ran (created suspended) is
        // its own: our probes move out of its way first (hw_yield_to_target).
        if (s->dr_used && event.u.CreateThread.hThread && !s->detaching)
            hw_yield_to_target(s, event.dwThreadId, event.u.CreateThread.hThread);
        if (event.u.CreateThread.hThread && !s->detaching)     // new thread inherits the gates
            for (auto &g : s->gates) set_dr_on_thread(event.u.CreateThread.hThread, g.second, g.first, true, 0, 0, s, event.dwThreadId);
        if (s->hw_active && event.u.CreateThread.hThread)     // new thread inherits the DRs
            for (auto &p : s->probes)
                if (p->active && (p->flags & PROBE_HW)) {
                    uint32_t rw = 0, len = 0; hw_rw_len(p->flags, rw, len);
                    set_dr_on_thread(event.u.CreateThread.hThread, p->dr_slot, p->address, true, rw, len, s, event.dwThreadId);
                }
        // A launched target's thread born while inline installs are outstanding (e.g. started
        // by a TLS callback or a static DLL's DllMain(PROCESS_ATTACH) during process init,
        // before the main thread reaches the entry hold) could reach a site before its hook
        // is in. Hold it from its first instruction (it owns no lock yet) until the same
        // confirmation releases the others. Attached targets: only while a hold is already in
        // progress (a callback's runtime add) and the agent is up -- attach holds nothing while
        // the agent is injected. Never our own agent threads (they do the install).
        if (s->initial_break && event.dwThreadId != s->remote_tid &&
            (!s->attached || (!s->held.empty() && s->shared && s->shared->service_ready)) &&
            inline_hold_needed(s) && !agent_thread(s, event.dwThreadId))
            hold_thread(s, event.dwThreadId);
        // Do NOT close hThread: the debug subsystem owns it and closes it itself when the
        // thread's EXIT_THREAD event is continued. Closing it here made that later close hit
        // whatever handle had reused the value (e.g. a held thread's -> left suspended).
        break;
    case EXIT_THREAD_DEBUG_EVENT: {
        s->debug_delivery.erase(event.dwThreadId);
        if (event.dwThreadId == s->remote_tid) ok = complete_remote_thread(s, event.u.ExitThread.dwExitCode);
        if (event.dwThreadId == s->ipc_freezer) ipc_thaw(s);       // agent thread died mid-write: never strand the rest
        s->threads.erase(event.dwThreadId);
        s->thread_handle.erase(event.dwThreadId);
        forget_event_thread(s, event.dwThreadId);
        s->refault.erase(event.dwThreadId);
        s->hw_unsettled.erase(event.dwThreadId);
        forget_thread_holds(s, event.dwThreadId);
        s->dr6_lost.erase(event.dwThreadId);
        s->restore_resume.erase(event.dwThreadId);
        s->call_late.erase(event.dwThreadId);
        auto it = s->stepping.find(event.dwThreadId);
        if (ok && it != s->stepping.end()) {
            // Only the in-place path lifted the byte; a displaced step left it armed.
            if (!it->second.displaced) end_inplace_step(s, event.dwThreadId, it->second.site);
            s->stepping.erase(it);
            if (!ok) set_error(s, win_error("re-arm probe after thread exit"));
        }
        for (auto sc = s->scratch.begin(); sc != s->scratch.end(); ) {   // return its step slots
            if (sc->first.first == event.dwThreadId) {
                s->scratch_free[sc->first.second].push_back(sc->second);
                sc = s->scratch.erase(sc);
            } else ++sc;
        }
        break;
    }
    case LOAD_DLL_DEBUG_EVENT: {
        uint64_t base = (uint64_t)(uintptr_t)event.u.LoadDll.lpBaseOfDll;
        // A NEW instance at the base of one whose UNLOAD has not been reported yet (the
        // unmapping thread reports after the view is gone; another thread mapped the DLL again
        // and reported first -- the late unload is then ignored, see UNLOAD_DLL). Probes still
        // active at this base belong to the OLD view: the fresh mapping has neither our INT3
        // nor our hook. Re-arm them in it (a hardware probe's debug register is per address:
        // it stays). ROADMAP A8.
        s->early_unloaded.erase(base);                      // a new instance here
        if (!s->detaching) {
            // ... and at ANOTHER base: an older instance of this module whose image is gone but
            // whose UNLOAD has not been reported yet keeps its probes marked active, so this
            // instance would not be armed until that late unload (calls to it missed: seen,
            // hunt-dll-work-backend-inline). Tear the old one down now; its late UNLOAD is then
            // skipped (early_unloaded).
            const std::string nm = event_module_name(s->pi.hProcess, event.u.LoadDll.hFile, base);
            std::vector<uint64_t> gone;
            for (auto &p : s->probes) {
                if (!p->active || !p->base || p->base == base || !iequals(p->module, nm)) continue;
                if (std::find(gone.begin(), gone.end(), p->base) != gone.end()) continue;
                MEMORY_BASIC_INFORMATION mbi{};
                const bool mapped = VirtualQueryEx(s->pi.hProcess, (void *)(uintptr_t)p->base, &mbi, sizeof(mbi)) &&
                                    mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE &&
                                    (uint64_t)(uintptr_t)mbi.AllocationBase == p->base;
                if (!mapped) gone.push_back(p->base);
            }
            for (uint64_t g : gone) {
                if (trace_enabled()) std::fprintf(stderr, "  load at 0x%llx: older instance at 0x%llx gone, torn down now\n",
                                                  (unsigned long long)base, (unsigned long long)g);
                module_unloaded(s, g);
                s->early_unloaded.insert(g);
            }
        }
        if (!s->detaching)
            for (auto &p : s->probes) {
                if (!p->active || p->base != base || !base || (p->flags & PROBE_HW)) continue;
                if (p->flags & PROBE_INLINE) {
                    if (s->shared && p->agent_index < PROBE_AGENT_MAX_PROBES)
                        InterlockedExchange(&s->shared->requests[p->agent_index].status, PROBE_AGENT_UNLOADED);
                    p->active = false; p->vetted = false; p->base = p->address = 0;
                } else {
                    unsigned char now = 0; size_t got = 0;
                    if (remote_read(s->pi.hProcess, p->address, &now, 1, &got) && got == 1 && now == 0xcc) continue;
                    p->active = false; p->base = p->address = 0; sync_int3_table(s);
                }
                if (trace_enabled()) std::fprintf(stderr, "  reload at 0x%llx: re-arm %s\n", (unsigned long long)base, p->location.c_str());
            }
        std::string name = event_module_name(s->pi.hProcess, event.u.LoadDll.hFile, base);
        if (!name.empty()) s->module_bases[name] = base;
        if (!name.empty()) s->module_instances.emplace_back(name, base);
        sym_register(s, event.u.LoadDll.hFile, base);
        ok = arm_module(s, name, base, !s->attached || s->initial_break ||
                                       (s->attach_modules_ok && !s->attach_modules.count(base)));
        // A pending inline probe of this module resolved in ANOTHER instance (two mappings of
        // one DLL, one of them discarded -- which one is not known yet): gate this copy of the
        // site as well until the hook is in; retarget_pending moves the probe if its own copy
        // never becomes installable.
        // The same for an ACTIVE probe whose instance is still mapped: an older instance that is
        // being unloaded (its DllMain detach runs) while this one is already in use by another
        // thread -- calls to this one would go unhooked until the late UNLOAD.
        bool extra = false;
        if (!s->detaching && s->shared && s->shared->service_ready && s->svc_event)
            for (auto &p : s->probes)
                if ((p->flags & PROBE_INLINE) && p->address && p->base && p->base != base && !p->retired &&
                    iequals(p->module, name)) {
                    probe_session::ExtraGate e; e.site = base + (p->address - p->base); e.base = base; e.probe = p.get();
                    s->extra_gates.push_back(e); extra = true;
                }
        if (extra && !agent_has_pending(s)) arm_gates_for_pending(s);   // (with pending ones: below)
        if (iequals(name, "probe_api_agent.dll")) {
            s->remote_agent = base;
        }
        if (!s->held.empty()) s->held_since = GetTickCount64();   // symbol work above may have been slow
        if (trace_enabled()) std::fprintf(stderr, "  load_dll %s tid=%lu pending=%d t=%llu\n", name.c_str(),
                                          (unsigned long)event.dwThreadId, (int)agent_has_pending(s), (unsigned long long)GetTickCount64());
        if (ok && agent_has_pending(s)) {
            if (s->shared->service_ready && s->svc_event) {
                // Gate the new sites with debug registers and let the loading thread run on
                // (it holds loader state the install may need). Only if no DR is free, park
                // the loading thread as before.
                if (!arm_gates_for_pending(s)) hold_thread(s, event.dwThreadId);
                ok = kick_agent(s);
            } else if (s->remote_agent && s->remote_work == probe_session::REMOTE_NONE) {
                ok = start_agent_init(s);
            }
        }
        if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
        break;
    }
    case UNLOAD_DLL_DEBUG_EVENT: {
        uint64_t base = (uint64_t)(uintptr_t)event.u.UnloadDll.lpBaseOfDll;
#if defined(UHH_TEST_HOOKS)
        // Test-only (probe_api_testhooks): UHH_TEST_DEFER_UNLOAD=<module name> leaves that
        // module's unload unprocessed, as if its event were still queued behind the detach
        // (regress lifecycle-unload-unseen-*: the agent's final unhook meets an unmapped site
        // whose request is not UNLOADED -- the early-detach race of lifecycle-detach-early-*).
        if (const char *defer = std::getenv("UHH_TEST_DEFER_UNLOAD")) {
            bool match = false;
            for (const auto &m : s->module_bases) match = match || (m.second == base && !_stricmp(m.first.c_str(), defer));
            if (match) { std::fprintf(stderr, "probe: test: unload of %s left unprocessed\n", defer); break; }
        }
#endif
        // The unmapping thread reports AFTER the view is gone, so another thread can map the
        // same DLL again at the same base and report ITS load first. Seen under load/unload
        // churn: the late unload then retired probes just armed in the NEW instance -- its
        // INT3 / hook stayed in live code, was never removed at detach, and the detached
        // target died on it (0x80000003). An image mapped at this base right now means this
        // unload is stale: keep the probes (and the module) as they are.
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(s->pi.hProcess, (void *)(uintptr_t)base, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
                mbi.Type == MEM_IMAGE && (uint64_t)(uintptr_t)mbi.AllocationBase == base) {
                if (trace_enabled()) std::fprintf(stderr, "  stale unload at 0x%llx ignored\n", (unsigned long long)base);
                break;
            }
        }
        if (s->early_unloaded.erase(base)) break;           // torn down already, at a newer instance's LOAD
        {
            std::vector<std::string> mods;
            for (auto &p : s->probes) if (p->active && p->base == base && !p->module.empty()) mods.push_back(p->module);
            module_unloaded(s, base);
            // A newer instance of the module mapped ELSEWHERE already reported its load (its
            // probes were still marked active here, so it was not armed): arm it now.
            for (const auto &m : mods)
                for (const auto &kv : s->module_bases)
                    if (iequals(kv.first, m)) { ok = arm_after_reload(s, kv.first, kv.second) && ok; break; }
        }
        break;
    }
    case EXCEPTION_DEBUG_EVENT: {
        const bool before_initial = !s->initial_break;
        ok = handle_exception(s, event, s->stepping, s->initial_break, disposition);
        const bool loader_break = before_initial && s->initial_break && ok;   // this event IS the loader breakpoint
        if (loader_break) bench_phase("ev_loader_break");
        s->cb_tid = 0;
        for (DWORD tid : s->pending_hold) hold_thread(s, tid);
        s->pending_hold.clear();
        // (Attach does NOT hold the target's threads while the agent is injected: the target
        //  was already running, so a call before the hook lands is no different from one
        //  before the attach -- a probe reports "active" only once its hook is confirmed --
        //  while a held thread that owns the loader lock blocked the agent's LoadLibrary and
        //  froze the target until the install timeout (seen attaching to PowerShell). The
        //  hook write itself is safe without it: FREEZE suspends every thread for the patch.)
        if (ok && s->initial_break && has_inline(s) && s->remote_work == probe_session::REMOTE_NONE &&
            (!s->remote_agent || (s->attached && !s->agent_init_started))) {
            // (Re-attach: the agent is still loaded from an earlier session -- just init it.)
            if (!(loader_break && early_agent(s, event, ok)))
                ok = !s->remote_agent ? start_agent_load(s) : start_agent_init(s);
        }
        break;
    }
    case EXIT_PROCESS_DEBUG_EVENT:
        bench_phase("ev_exit_process");
        // An agent init thread still pending when the target ends gets no EXIT_THREAD of its own
        // when it is the process's LAST thread to exit (the kernel reports that exit as this
        // event, from that thread: dwThreadId) -- or when it was killed before it first ran (no
        // CREATE/EXIT_THREAD at all). Seen on x86 with TerminateProcess(self): the other
        // threads were gone first. Reported like the EXIT_THREAD case (complete_remote_thread).
        if (trace_enabled())
            std::fprintf(stderr, "  exit-process reported by tid=%lu (remote work=%d tid=%lu)\n", (unsigned long)event.dwThreadId,
                         (int)s->remote_work, (unsigned long)s->remote_tid);
        if (s->remote_work == probe_session::REMOTE_INIT_AGENT && s->shared && s->shared->init_returns == s->init_returns_at)
            std::fprintf(stderr, "probe: agent init thread ended by the target before it returned (%s, exit code 0x%lx)\n",
                         event.dwThreadId == s->remote_tid ? "the process's last thread" : "with the process",
                         (unsigned long)event.u.ExitProcess.dwExitCode);
        ipc_thaw(s);
        s->exit_code = event.u.ExitProcess.dwExitCode; s->exited = true; break;
    default: break;
    }
    return ok;
}

} // namespace uhh_session
