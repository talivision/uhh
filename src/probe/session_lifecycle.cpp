// Lifecycle: launch / attach, the controller-death guard, detach.
#include "session_internal.hpp"

namespace uhh_session {
#if !defined(_WIN64)
// A thread's suspend count, read without changing it (NtQueryInformationThread
// ThreadSuspendCount, Windows 8.1+). False: unknown. NOTE: it includes the debug freeze (+1 for
// every thread while the target is stopped at a debug event) -- see guard_floor.
static bool thread_suspend_count(DWORD tid, ULONG &count) {
    using QueryFn = LONG (NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
    static auto query = reinterpret_cast<QueryFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    HANDLE t = query ? OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid) : nullptr;
    if (!t) return false;
    count = 0;
    const bool ok = query(t, 35 /* ThreadSuspendCount */, &count, sizeof(count), nullptr) >= 0;
    CloseHandle(t);
    return ok;
}
// The thread's suspend count WITHOUT the debug freeze, as the guard reads it once the controller
// is gone (probe_agent_guard::held_floor): the freeze is the agent's service thread's count, a
// thread nobody suspends. Unknown: PROBE_AGENT_HOLD_OURS (an unconditional entry, one resume).
static uint32_t guard_floor(const probe_session *s, DWORD tid) {
    const DWORD svc = (DWORD)s->shared->guard.service_tid;
    ULONG count = 0, freeze = 0;
    if (!svc || !thread_suspend_count(tid, count) || !thread_suspend_count(svc, freeze) || freeze > count ||
        count - freeze >= PROBE_AGENT_HOLD_OURS)
        return PROBE_AGENT_HOLD_OURS;
    return (uint32_t)(count - freeze);
}
GuardTouch::GuardTouch(const probe_session *s, DWORD tid) {
    if (!s->attached || !s->shared || s->detached || !tid) return;
    auto &gg = s->shared->guard;
    LONG count = gg.held_count;
    if (count >= 0 && count <= (LONG)PROBE_AGENT_GUARD_TIDS) {
        LONG hole = 0;
        while (hole < count && gg.held_tids[hole]) ++hole;
        count = hole;
    }
#if defined(UHH_TEST_HOOKS)
    // Test-only (probe_api_testhooks): UHH_TEST_NO_TOUCH_GUARD=1 leaves the touch unrecorded
    // (the control run of regress cxlib-touchkill-hw).
    static const bool off = std::getenv("UHH_TEST_NO_TOUCH_GUARD") != nullptr;
    if (off) {} else
#endif
    if (count >= 0 && count < (LONG)PROBE_AGENT_GUARD_TIDS) {
        gg.held_floor[count] = guard_floor(s, tid);      // the count before the call: what the guard must leave
        gg.held_tids[count] = tid;
        MemoryBarrier();
        if (gg.held_count == count) gg.held_count = count + 1;
        g = &gg; n = count;
    }
#if defined(UHH_TEST_HOOKS)
    // UHH_TEST_DIE_IN_TOUCH=<tid>: at the first such call on that thread while arming a user hw
    // probe (g_test_in_arm_hw), do what the kernel
    // does inside it (suspend the thread) and die there -- the WOW64 implicit-suspend window.
    // UHH_TEST_DIE_IN_TOUCH_MODE=before: die with the touch recorded but BEFORE the implicit
    // suspension (regress cx2-touchprog-hw: the guard must leave the program's own suspension).
    static const DWORD die_tid = [] { const char *v = std::getenv("UHH_TEST_DIE_IN_TOUCH"); return v ? (DWORD)std::strtoul(v, nullptr, 10) : 0u; }();
    static const bool die_before = [] { const char *v = std::getenv("UHH_TEST_DIE_IN_TOUCH_MODE"); return v && !std::strcmp(v, "before"); }();
    if (die_tid && tid == die_tid && g_test_in_arm_hw && (!die_before || gg.enabled)) {
        DWORD prev = (DWORD)-1;
        if (!die_before)
            if (HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid)) prev = SuspendThread(t);
        std::fprintf(stderr, "probe: test: dying in a context call on thread %lu (guard enabled=%ld held=%ld "
                             "floor=%lu suspended_before=%ld)\n", (unsigned long)tid, (long)gg.enabled,
                     (long)gg.held_count, (unsigned long)(g ? gg.held_floor[n] : 0xFFFFFFFFu), (long)prev);
        std::fflush(nullptr);
        TerminateProcess(GetCurrentProcess(), 98);
    }
#endif
}
#endif
// The agent goes into a target only for inline probes: at launch/attach if any are registered,
// else lazily when a callback or runtime add requests the first one. A breakpoint/hw-only
// session loads nothing into the target (owner decision 2026-11-07: an injected DLL is itself a
// side effect; a controller killed while such a session is attached leaves its INT3s/DRs in the
// target, which may fault at its next hit -- the analyst sees the controller died). Where the
// agent is loaded it is also the controller-death guard (probe_agent_shared.hpp): an attach
// with inline probes from the start arms its breakpoint/hw probes once the guard is up, so no
// unguarded trap exists there; a session that acquires the agent later is guarded from then on.
bool guard_pending(const probe_session *s) { return s->attached && s->shared && !s->guard_ready; }

static std::string quote_arg(const char *arg) {
    std::string in = arg ? arg : "";
    if (!in.empty() && in.find_first_of(" \t\n\v\"") == std::string::npos) return in;
    std::string out = "\""; size_t slashes = 0;
    for (char ch : in) {
        if (ch == '\\') { ++slashes; continue; }
        if (ch == '\"') out.append(slashes * 2 + 1, '\\');
        else out.append(slashes, '\\');
        slashes = 0; out += ch;
    }
    out.append(slashes * 2, '\\'); out += '\"'; return out;
}

// The guard is up (or will not come): arm the breakpoint/hw probes held back until now.
// Called BEFORE the controller suspends a thread it does not resume within the same few
// instructions: the guard's held list gets the thread first, so a controller killed between
// the suspension and the next guard_sync still has it resumed (an entry for a thread that was
// never suspended, or already resumed, costs a no-op ResumeThread). guard_sync rewrites the
// list from the session's own bookkeeping after every event.
void guard_note_hold(probe_session *s, DWORD tid) {
    if (!s->attached || !s->shared || s->detached || !tid) return;
    auto &g = s->shared->guard;
    const LONG count = g.held_count;
    if (count < 0 || count > (LONG)PROBE_AGENT_GUARD_TIDS) return;
    LONG n = 0;
    while (n < count && g.held_tids[n]) ++n;
    if (n >= (LONG)PROBE_AGENT_GUARD_TIDS) return;
    g.held_floor[n] = PROBE_AGENT_HOLD_OURS;
    MemoryBarrier();
    g.held_tids[n] = tid;
    MemoryBarrier();
    if (n == count) g.held_count = n + 1;
}
bool guard_set_ready(probe_session *s, const char *why) {
    if (s->guard_ready) return true;
    s->guard_ready = true;
    if (why) std::fprintf(stderr, "probe: warning: controller-death guard unavailable (%s): "
                                  "breakpoint/hw probes armed without it\n", why);
    bool ok = true;
    std::vector<std::pair<std::string, uint64_t>> mods(s->module_bases.begin(), s->module_bases.end());
    for (auto &m : mods) ok = arm_module(s, m.first, m.second, false) && ok;
    guard_sync(s);
    return ok;
}

void guard_sync(probe_session *s) {
    if (!s->attached || !s->shared || s->detached) return;
    // (Armed INT3s: the INT3 table, kept current by sync_int3_table.)
    auto &g = s->shared->guard;
    uint32_t n = 0;
    for (auto &kv : s->stepping)
        if (!kv.second.prog_tf && !kv.second.tail_int3 && !kv.second.refire && n < PROBE_AGENT_GUARD_TIDS)
            g.step_tids[n++] = kv.first;
    g.step_count = (LONG)n;
    n = 0;
    DWORD holds[PROBE_AGENT_GUARD_TIDS]{};
    auto hold = [&](DWORD tid) {                        // a hold of ours: resumed once, unconditionally
        if (!tid || n >= PROBE_AGENT_GUARD_TIDS) return;
        holds[n++] = tid;
    };
    for (const auto *list : {&s->held, &s->ipc_frozen, &s->call_deferred})
        for (HANDLE t : *list) hold(GetThreadId(t));
    for (const auto &e : s->inplace_suspended) hold(e.first);   // an in-place step window's suspensions
    for (DWORD tid : s->detach_frozen) hold(tid);
    for (const auto &e : s->parked) hold(e.first);          // fairness parking (suspended by us)
    for (const auto &w : s->ctx_watch) hold(w->tid);        // context round-trips (suspended by us)
    // The threads whose events are being handled: a 32-bit (WOW64) controller's
    // Get/SetThreadContext on another thread is an implicit suspend + resume inside the call,
    // so a controller killed in the middle of one leaves that thread suspended once with
    // nothing of ours recording it (seen on x86: a thread parked for good at its NtOpenProcess
    // hit). One resume for each covers it -- a no-op for a thread that is not suspended.
    // Listed ONLY while the thread is stopped (at its event, or suspended by us for the rest
    // of its handling): the entry is taken off BEFORE its event is continued (service_event /
    // fiber_step re-sync first) or right after our suspension of it ends, and
    // a thread running a call_func / call_original callee is not listed (its context is
    // touched only at its own trap or under a suspension of ours, each listed then). A stale
    // entry for a thread that runs again would release a suspension the PROGRAM makes of it
    // next if the controller died then (Codex review 2, X2 open note; regress cx2-evsusp-*, cx2-cosusp-*).
    for (const auto &h : s->handling) if (!h.running) hold(h.tid);
    for (const auto &c : s->calls) if (c.second->call_held) hold(c.first);   // suspended by us
    for (const auto &h : s->watch_deferred) hold(h.ev.dwThreadId);
    // Never compact live entries: [A,B] -> [B] must not expose [B,B]
    // if the controller dies during publication.
    LONG count = g.held_count;
    if (count < 0 || count > (LONG)PROBE_AGENT_GUARD_TIDS) count = 0;
    for (LONG i = 0; i < count; ++i) {
        bool keep = false;
        for (uint32_t j = 0; j < n; ++j) if (holds[j] && holds[j] == g.held_tids[i]) {
            holds[j] = 0; keep = true; break;
        }
        if (!keep) g.held_tids[i] = 0;
    }
    MemoryBarrier();
    for (uint32_t j = 0; j < n; ++j) if (holds[j]) {
        LONG i = 0;
        while (i < count && g.held_tids[i]) ++i;
        if (i >= (LONG)PROBE_AGENT_GUARD_TIDS) break;
        g.held_floor[i] = PROBE_AGENT_HOLD_OURS;
        MemoryBarrier();
        g.held_tids[i] = holds[j];
        if (i == count) { MemoryBarrier(); g.held_count = ++count; }
    }
    n = 0;
    for (uint64_t b : s->scratch_blocks) if (n < PROBE_AGENT_GUARD_BLOCKS) g.blocks[n++] = b;
    g.block_count = (LONG)n;
    // Append/publish each address before arming it. A controller killed during this
    // mirror must not invalidate addresses already installed on running threads.
    for (uint64_t address : s->hw_armed_ever) {
        const LONG site_count = g.dr_site_count;
        if (site_count < 0 || site_count > (LONG)PROBE_AGENT_GUARD_DR_SITES) continue;
        bool found = false;
        for (LONG i = 0; i < site_count; ++i) if (g.dr_sites[i] == address) found = true;
        if (!found && site_count < (LONG)PROBE_AGENT_GUARD_DR_SITES) {
            g.dr_sites[site_count] = address;
            MemoryBarrier();
            g.dr_site_count = site_count + 1;
        }
    }
    g.dr_mask = s->dr_ever | s->dr_used;          // incl. a call_original's return-catch slot
    MemoryBarrier();
    g.enabled = 1;
}
// The guard's list rewritten right after a thread of ours was let go outside an event (a
// suspension of ours ended): its entry goes now, not at the next event (a stale entry would
// release a suspension the program makes next). Nothing once the target is gone.
void guard_resync(probe_session *s) { if (!s->exited) guard_sync(s); }
// The current handling of `tid` lets its thread run (true) or has it stopped again (false):
// see probe_session::handling. Callers re-sync the guard before the thread runs.
void handling_running(probe_session *s, DWORD tid, bool running) {
    for (size_t i = s->handling.size(); i--; )
        if (s->handling[i].tid == tid) { s->handling[i].running = running; return; }
}

static bool same_bitness(probe_session *s, HANDLE process);
} // namespace uhh_session

using namespace uhh_session;

extern "C" int probe_launch(probe_session *s, char *const argv[]) {
    if (!s || !argv || !argv[0]) { if (s) set_error(s, "launch argv is empty"); return 0; }
    if (s->launched) { set_error(s, "session already launched"); return 0; }
    s->error.clear();          // a refused probe_add already reported itself (returned 0)
    try {
        std::string command;
        for (size_t i = 0; argv[i]; ++i) { if (i) command += ' '; command += quote_arg(argv[i]); }
        // The target gets the controller's own stdin, exactly as if it had been started
        // without UHH (a filter reading stdin to EOF must see the caller's stream). Its
        // stdout/stderr are the controller's too when those are a console (or NUL); when they
        // are a pipe or a file, the target writes into its own pipe and UHH forwards its bytes
        // line-wise, so the live log records never land inside one of its lines. A stdout and
        // stderr that are one stream (2>&1) share one pipe: their relative order is kept.
        STARTUPINFOA si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE); si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        HANDLE client_out = INVALID_HANDLE_VALUE, client_err = INVALID_HANDLE_VALUE;
        // From the target's inheritable pipe ends to their close below (see uhh_sym::inherit_lock).
        std::unique_lock<std::mutex> inherit(uhh_sym::inherit_lock());
        const bool fwd_out = forwardable(si.hStdOutput), fwd_err = forwardable(si.hStdError);
        const bool one_stream = fwd_out && fwd_err && same_object(si.hStdOutput, si.hStdError);
        if (fwd_out) {
            if (!make_forward_pipe(s->fwd_out.pipe, client_out)) { set_error(s, win_error("create target stdout pipe")); return 0; }
            s->fwd_out.dst = si.hStdOutput; s->fwd_out.to_stdout = true; s->fwd_out_active = true;
            si.hStdOutput = client_out;
            if (one_stream) si.hStdError = client_out;
        }
        if (fwd_err && !one_stream) {
            if (!make_forward_pipe(s->fwd_err.pipe, client_err)) {
                if (client_out != INVALID_HANDLE_VALUE) CloseHandle(client_out);
                forward_stop(s); s->fwd_out_active = false;
                set_error(s, win_error("create target stderr pipe")); return 0;
            }
            s->fwd_err.dst = si.hStdError;
            si.hStdError = client_err;
        }
        // A process created under a debugger gets the NT debug heap (fill patterns,
        // different layout): the target must run exactly as it would without UHH.
        char prev_ndh[16] = {0};
        DWORD had_ndh = GetEnvironmentVariableA("_NO_DEBUG_HEAP", prev_ndh, sizeof(prev_ndh));
        SetEnvironmentVariableA("_NO_DEBUG_HEAP", "1");
        bench_phase("launch_createprocess");
        BOOL ok = CreateProcessA(argv[0], command.data(), nullptr, nullptr, TRUE,
                                 DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &s->pi);
        bench_phase("launch_created");
        SetEnvironmentVariableA("_NO_DEBUG_HEAP", had_ndh && had_ndh < sizeof(prev_ndh) ? prev_ndh : nullptr);
        DWORD launch_error = GetLastError();
        // Only the target (and what it hands them to) holds the write ends: end of file
        // arrives when its tree closes them.
        if (client_out != INVALID_HANDLE_VALUE) CloseHandle(client_out);
        if (client_err != INVALID_HANDLE_VALUE) CloseHandle(client_err);
        inherit.unlock();
        if (!ok) {
            forward_stop(s); s->fwd_out_active = false;
            SetLastError(launch_error); set_error(s, win_error("debug launch")); return 0;
        }
        if (!same_bitness(s, s->pi.hProcess)) {
            TerminateProcess(s->pi.hProcess, 3);
            CloseHandle(s->pi.hThread); CloseHandle(s->pi.hProcess); s->pi = {};
            return 0;
        }
        s->launched = true;
        s->debug_tid = GetCurrentThreadId();
        if (!start_log_output(s)) { TerminateProcess(s->pi.hProcess, 3); return 0; }
        bench_phase("launch_logout");
        if (!forward_start(s, &s->fwd_out) || !forward_start(s, &s->fwd_err)) {
            set_error(s, "target output forwarder creation failed"); TerminateProcess(s->pi.hProcess, 3); return 0;
        }
        { std::string which; s->sym_ready = uhh_sym::init(s->pi.hProcess, which);
          std::fprintf(stderr, "probe: symbols via %s%s\n", which.c_str(), uhh_sym::has_symbol_server() ? " (symbol server capable)" : ""); }
        bench_phase("launch_syminit");
        if (!create_agent_channel(s) || !bind_pending_shared(s)) { TerminateProcess(s->pi.hProcess, 3); return 0; }
        bench_phase("launch_channel");
        if (!has_inline(s)) s->inline_ready = true;
        return 1;
    } catch (const std::exception &e) { set_error(s, e.what()); return 0; }
}

namespace uhh_session {

// The controller and target must be the same bitness: callbacks run with the controller's
// view of registers, argument slots and pointer width. A mismatch would silently produce
// garbage, so refuse it up front.
static bool same_bitness(probe_session *s, HANDLE process) {
    BOOL me = FALSE, it = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &me) || !IsWow64Process(process, &it)) return true;   // cannot tell
    if (me == it) return true;
    set_error(s, it ? "target is a 32-bit (WOW64) process: use the x86 build of UHH"
                    : "target is a 64-bit process: use the x64 build of UHH");
    return false;
}

} // namespace uhh_session

extern "C" int probe_attach(probe_session *s, uint32_t pid) {
    if (!s) return 0;
    if (s->launched) { set_error(s, "session already launched"); return 0; }
    s->error.clear();          // a refused probe_add already reported itself (returned 0)
    s->pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!s->pi.hProcess) { set_error(s, win_error("open target process")); return 0; }
    if (!same_bitness(s, s->pi.hProcess)) { CloseHandle(s->pi.hProcess); s->pi.hProcess = nullptr; return 0; }
    if (!reuse_target_agent(s)) { CloseHandle(s->pi.hProcess); s->pi.hProcess = nullptr; return 0; }
    // Kill-on-exit OFF before the attach exists: DebugActiveProcess creates the thread's debug
    // object with kill-on-close set, so a controller ended in between (Ctrl+C during the
    // attach) took the target down with it (exit 0xC0000354). Create the object first.
    {
        using ConnectFn = LONG(NTAPI *)();
        auto connect = reinterpret_cast<ConnectFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "DbgUiConnectToDbg"));
        if (connect && connect() >= 0) DebugSetProcessKillOnExit(FALSE);
    }
    if (!DebugActiveProcess(pid)) {
        set_error(s, win_error("attach debugger")); CloseHandle(s->pi.hProcess); s->pi.hProcess = nullptr; return 0;
    }
    DebugSetProcessKillOnExit(FALSE);              // our exit must never take the target down
    // The modules mapped now: the attach replays a LOAD_DLL for each (its threads are held
    // until their replayed events are continued); every other LOAD_DLL is a fresh mapping.
    {
        HMODULE mods[1024]; DWORD need = 0;
        for (int tries = 0; tries < 3 && !s->attach_modules_ok; ++tries)
            if (K32EnumProcessModulesEx(s->pi.hProcess, mods, sizeof(mods), &need, LIST_MODULES_ALL) && need <= sizeof(mods)) {
                for (DWORD i = 0; i < need / sizeof(HMODULE); ++i) s->attach_modules.insert((uint64_t)(uintptr_t)mods[i]);
                s->attach_modules_ok = true;
            }
    }
    s->debug_tid = GetCurrentThreadId();
    s->pi.dwProcessId = pid;
    s->attached = true; s->launched = true; s->inline_ready = true;
    // A failure below lets go of the target at once and leaves the session NOT attached: a
    // probe_close (from any thread) then has nothing to detach and no probe_run to wait for.
    auto fail = [&] {
        if (s->shared) {
            auto &g = s->shared->guard;
            if (HANDLE h = (HANDLE)(uintptr_t)InterlockedExchange64(&g.controller_process, 0))
                DuplicateHandle(s->pi.hProcess, h, nullptr, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
        }
        release_unclaimed_agent_mapping(s);
        DebugActiveProcessStop(pid);
        if (s->sym_ready) { uhh_sym::cleanup(s->pi.hProcess); s->sym_ready = false; }
        CloseHandle(s->pi.hProcess); s->pi.hProcess = nullptr;
        s->attached = s->launched = false; s->debug_tid = 0;
        return 0;
    };
#if defined(UHH_TEST_HOOKS)
    if (std::getenv("UHH_TEST_ATTACH_FAIL")) return fail();
#endif
    if (!start_log_output(s)) return fail();
    { std::string which; s->sym_ready = uhh_sym::init(s->pi.hProcess, which); }
    if (!create_agent_channel(s) || !bind_pending_shared(s)) return fail();
    if (!s->shared) s->guard_ready = true;     // breakpoint/hw only: arm at once, no agent to wait for
    return 1;
}

namespace uhh_session {

static void snapshot_pids(const char *name, std::unordered_set<DWORD> &out, DWORD *newest_new,
                          const std::unordered_set<DWORD> *exclude) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    wchar_t wname[MAX_PATH]{};
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, MAX_PATH);
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    for (BOOL more = Process32FirstW(snap, &pe); more; more = Process32NextW(snap, &pe)) {
        if (_wcsicmp(pe.szExeFile, wname)) continue;
        out.insert(pe.th32ProcessID);
        if (newest_new && exclude && !exclude->count(pe.th32ProcessID)) {
            // Several new instances can appear in one snapshot (e.g. the target and the
            // helpers it spawns with the same image name): take the EARLIEST created.
            auto created = [](DWORD pid) -> ULONGLONG {
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                FILETIME c{}, e{}, k{}, u{};
                ULONGLONG t = ~0ull;
                if (h && GetProcessTimes(h, &c, &e, &k, &u)) t = ((ULONGLONG)c.dwHighDateTime << 32) | c.dwLowDateTime;
                if (h) CloseHandle(h);
                return t;
            };
            if (!*newest_new || created(pe.th32ProcessID) < created(*newest_new)) *newest_new = pe.th32ProcessID;
        }
    }
    CloseHandle(snap);
}

} // namespace uhh_session

extern "C" int probe_attach_new(probe_session *s, const char *image_name, uint32_t timeout_ms) {
    if (!s) return 0;
    if (!image_name || !*image_name) { set_error(s, "attach_new needs an image name"); return 0; }
    std::unordered_set<DWORD> existing; snapshot_pids(image_name, existing, nullptr, nullptr);
    std::fprintf(stderr, "probe: waiting for a new %s (%zu already running, ignored)\n", image_name, existing.size());
    timeBeginPeriod(1);                               // ~1 ms polling granularity
    ULONGLONG start = GetTickCount64();
    DWORD pid = 0;
    while (!pid) {
        std::unordered_set<DWORD> now; snapshot_pids(image_name, now, &pid, &existing);
        if (pid) break;
        if (timeout_ms && GetTickCount64() - start > timeout_ms) break;
        Sleep(1);
    }
    timeEndPeriod(1);
    if (!pid) { set_error(s, std::string("no new ") + image_name + " appeared"); return 0; }
    std::fprintf(stderr, "probe: new %s pid %lu -> attaching\n", image_name, (unsigned long)pid);
    return probe_attach(s, pid);
}

namespace uhh_session {

// Detach from an attached, still-running target leaving it exactly as it ran before:
// inline hooks removed by the agent, every INT3 restored, every debug register cleared,
// and no thread left mid single-step. Events keep being dispatched while that happens
// (a thread may hit a breakpoint or finish a step in the meantime).
void detach(probe_session *s) {
    // Detaching must not erase an install/session failure already reported.
    accept_agent_install(s, false);
    FiberHost fibers(s);
    // Callbacks inside call_func: let their callees return first (bounded by their timeout).
    for (ULONGLONG until = GetTickCount64() + 6000; !s->calls.empty() && !s->exited && GetTickCount64() < until; )
        pump(s, 20);
    finish_calls(s);
    // From here on nothing may start new agent work, arm anything, gate or hold a thread: the
    // event pumping below dispatches events (an agent load completing, a DLL with pending
    // sites loading, the initial breakpoint) that would otherwise start an init AFTER the stop
    // -- hooks installed into the target we are detaching from (seen: Ctrl+C 50 ms into an
    // inline attach left every hook live) -- or re-hold threads the agent's work then waits on.
    park_release(s);
    ctx_watch_poll(s, true);
    s->detaching = true;
    release_held(s, "detach");
    // Agent work in flight (load/init on a remote thread): let it finish first, or its hooks
    // would land AFTER the agent was told to stop -- live hooks in a detached process.
    for (ULONGLONG until = GetTickCount64() + 5000;
         s->remote_work != probe_session::REMOTE_NONE && !s->exited && GetTickCount64() < until; )
        pump(s, 20);
    if (s->remote_work != probe_session::REMOTE_NONE && s->shared) {
        // Still not done (e.g. the target holds its loader lock, so the remote thread cannot
        // even start). It may run after we are gone: tell the agent the session is over, so a
        // late init installs nothing into the detached target.
        std::fprintf(stderr, "probe: detach: agent work still pending after 5 s; it will install nothing\n");
        InterlockedExchange(&s->shared->controller_gone, 1);
    }
    // The stop runs even then: an init that already wrote hooks but cannot finish (its thread
    // exit waits on the loader) would otherwise leave them live. If the stop cannot run within
    // the wait either, it runs whenever the target lets it -- then without us (the agent
    // freezes in-process for a session that is over).
    accept_agent_install(s, false); // a completed install may not have delivered INSTALL_DONE
    // Snapshot BEFORE stop changes the channel/hooks. A clean detach alone does not imply
    // this cycle ever installed anything (its timer can expire before init even starts).
    if (s->shared) {
        for (const auto &p : s->probes) {
            const uint32_t index = p->agent_index.load();
            if (!(p->flags & PROBE_INLINE) || index >= s->shared->request_count || index >= PROBE_AGENT_MAX_PROBES) continue;
            std::fprintf(stderr, "probe: inline detach state %s index=%u status=%ld active=%d hits=%llu "
                                 "epoch=%ld init_started=%d init_returns=%ld service_ready=%ld remote_work=%d controller_gone=%ld\n",
                         p->location.c_str(), index, s->shared->requests[index].status, (int)p->active.load(),
                         (unsigned long long)probe_agent_hits(s->shared, index), s->shared->session_epoch,
                         (int)s->agent_init_started, s->shared->init_returns, s->shared->service_ready,
                         (int)s->remote_work, s->shared->controller_gone);
        }
    }
    if (s->remote_agent && s->local_agent) {
        auto local_stop = reinterpret_cast<uintptr_t>(GetProcAddress(s->local_agent, "probe_agent_stop"));
        if (local_stop) {
            uint64_t remote_stop = s->remote_agent + local_stop - reinterpret_cast<uintptr_t>(s->local_agent);
            HANDLE t = nullptr;
#if defined(UHH_TEST_HOOKS)
            if (!std::getenv("UHH_TEST_STOP_FAIL"))
#endif
            t = create_remote_thread_boosted(s->pi.hProcess,
                                                    reinterpret_cast<LPTHREAD_START_ROUTINE>((uintptr_t)remote_stop), nullptr, nullptr);
            if (t) {                                   // keep dispatching until it has run
                ULONGLONG until = GetTickCount64() + 5000;
                while (!s->exited && WaitForSingleObject(t, 0) == WAIT_TIMEOUT && GetTickCount64() < until) pump(s, 20);
                s->detached_hooks = WaitForSingleObject(t, 0) == WAIT_OBJECT_0;
                CloseHandle(t);
            }
        }
    }
    ipc_thaw(s);                                      // never leave an agent hook-write freeze behind
    // From here no target thread may run until the debugger is gone: a thread could hit an
    // INT3 or debug register just before it is removed, and an event still queued at
    // DebugActiveProcessStop would reach the target as an unhandled exception.
    std::vector<HANDLE> frozen;
    for (DWORD tid : s->threads) {
        HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                              THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
        if (!t) continue;
        guard_note_hold(s, tid);
        if (SuspendThread(t) == (DWORD)-1) { CloseHandle(t); continue; }
        frozen.push_back(t);
        s->detach_frozen.push_back(tid);
    }
    for (auto &p : s->probes) {
        if (!p->active) continue;
        // A forwarded #DB still has to pass its repaired context to VEH/SEH. Keep the
        // temporary dispatcher catch through the drain, then restore it below as well.
        if (p.get() == s->debug_dispatch_probe && !s->debug_delivery.empty()) continue;
        if (p->flags & PROBE_BREAKPOINT) {
            restore_original(s->pi.hProcess, p->address, p->original);
            s->retired_bps.insert(p->address); p->active = false; sync_int3_table(s);
        } else if (p->flags & PROBE_HW) {
            release_hw(s, *p);
        }
    }
    // Drain everything already queued: stale INT3 hits are rewound onto the restored
    // instruction, stale #DBs are swallowed, finished steps land. (Continuing an event of
    // a suspended thread leaves it suspended.)
    // Let the threads RUN while draining: a thread can be caught (frozen) between raising
    // an exception and its delivery to the debugger -- on WOW64 the 32-bit exception is
    // first processed by the 64-bit layer in user mode -- and such an event would only
    // surface after we let go. With every probe already removed nothing new can trap, so
    // run until the queue has been quiet for 200 ms: everything in flight lands here.
    for (HANDLE t : frozen) ResumeThread(t);
    s->detach_frozen.clear(); guard_sync(s);
    // Only EXCEPTIONS are what this waits for: a target that keeps creating threads or
    // loading DLLs never goes quiet in thread/module events (that kept a detach busy for
    // minutes), so those are handled but do not extend the wait -- and the whole drain is
    // bounded in time as well (an exception-heavy target of its own).
    int drained_logged = 0;
    const ULONGLONG drain_until = GetTickCount64() + 5000;
    ULONGLONG last_exception = GetTickCount64();
    for (int guard = 0; guard < 100000 && !s->exited && GetTickCount64() < drain_until &&
                        GetTickCount64() - last_exception < 200; ++guard) {
        DEBUG_EVENT ev{};
        if (!WaitForDebugEvent(&ev, 50)) continue;
        if (continue_foreign_event(s, ev)) continue;
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) last_exception = GetTickCount64();
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && drained_logged < 24) {
            ++drained_logged;
            std::fprintf(stderr, "probe: detach-drain tid=%lu code=0x%lx addr=0x%llx first=%lu\n",
                         (unsigned long)ev.dwThreadId, (unsigned long)ev.u.Exception.ExceptionRecord.ExceptionCode,
                         (unsigned long long)(uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress,
                         (unsigned long)ev.u.Exception.dwFirstChance);
        }
        service_event(s, ev);
    }
    finish_calls(s);                                         // a call started while draining
    for (HANDLE t : frozen) {                                // freeze again for the fix-ups below
        const DWORD tid = GetThreadId(t);
        guard_note_hold(s, tid);
        SuspendThread(t);
        s->detach_frozen.push_back(tid);
    }
    // A thread still mid single-step: put it on the real instruction stream (the INT3 is
    // gone) with the trap flag clear.
    for (auto &kv : s->stepping) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, kv.first);
        CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
        GuardTouch touch(s, kv.first);
        if (t && GetThreadContext(t, &w)) {
#if defined(_WIN64)
            uint64_t ip = w.Rip;
#else
            uint64_t ip = w.Eip;
#endif
            if (kv.second.displaced && kv.second.scratch && ip >= kv.second.scratch &&
                ip <= kv.second.scratch + kv.second.insn_len)
                ip = kv.second.site + (ip - kv.second.scratch);     // not yet run -> site; run -> site+len
#if defined(_WIN64)
            w.Rip = ip;
#else
            w.Eip = (DWORD)ip;
#endif
            if (!kv.second.prog_tf) w.EFlags &= ~0x100u;
            SetThreadContext(t, &w);
        }
        if (t) CloseHandle(t);
    }
    s->stepping.clear();
    // A thread inside a displaced trampoline (not yet run: at its start; run: at the jump
    // back): onto the real code. The trampolines are freed at close.
    for (HANDLE t : frozen) {
        CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
        GuardTouch touch(s, GetThreadId(t));
        uint64_t tr = 0;
        if (!GetThreadContext(t, &w)) continue;
        if (const auto *d = dtramp_at(s, (uint64_t)EMU_IP(w), &tr)) {
            EMU_IP(w) = (decltype(EMU_IP(w)))(d->site + ((uint64_t)EMU_IP(w) - tr));
            SetThreadContext(t, &w);
        }
    }
    // A thread asleep in a yield stub resumes at the address in its slot: if that is in a
    // trampoline (freed at close), the real code instead.
    for (const auto &kv : s->yield_stubs) {
        uint64_t resume = 0, tr = 0; size_t n = 0;
        if (!remote_read(s->pi.hProcess, kv.second, &resume, sizeof(void *), &n) || n != sizeof(void *)) continue;
        if (const auto *d = dtramp_at(s, resume, &tr)) {
            const uint64_t real = d->site + (resume - tr);
            remote_write(s->pi.hProcess, kv.second, &real, sizeof(void *), &n);
        }
    }
    if (Probe *p = s->debug_dispatch_probe; p && p->active) {
        restore_original(s->pi.hProcess, p->address, p->original);
        s->retired_bps.insert(p->address); p->active = false; sync_int3_table(s);
    }
    inplace_release_all(s);                                 // every INT3 is gone: nothing to hold for
    // Final pass, after every queued event has been continued: continuing an event can
    // restore the debug registers captured when the exception was raised. Clear our DR
    // images on every frozen thread one last time, preserving the target's own DRs and TF.
    std::string report_tids;
    for (HANDLE t : frozen) {
        CONTEXT w{}; w.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
        GuardTouch touch(s, GetThreadId(t));                 // (frozen handles carry query rights)
        BOOL got = FALSE; DWORD why = 0;
        for (int attempt = 0; attempt < 200 && !(got = GetThreadContext(t, &w)); ++attempt) {
            why = GetLastError();
            DWORD code = 0;
            if (GetExitCodeThread(t, &code) && code != STILL_ACTIVE) break;   // exited: nothing to clear
            Sleep(1);                                                           // transient: retry
        }
        if (!got) {
            bool gone = thread_terminating(t);
            if (!gone) report_tids += " " + std::to_string(GetThreadId(t)) + ":getfail=" + std::to_string(why);
            continue;
        }
        for (int slot = 0; slot < 4; ++slot) {
            if (!(s->dr_ever & (1u << slot)) || !s->hw_armed_ever.count(dr_address(w, slot)) ||
                target_owns_slot(s, GetThreadId(t), w, slot)) continue;
            w.Dr7 &= ~((DWORD64)3 << (slot * 2)) & ~((DWORD64)0xF << (16 + slot * 4));
            w.Dr6 &= ~((decltype(w.Dr6))1 << slot);
            switch (slot) { case 0: w.Dr0 = 0; break; case 1: w.Dr1 = 0; break; case 2: w.Dr2 = 0; break; default: w.Dr3 = 0; }
        }
        // No slot left enabled: drop the exact-match bits too (WOW64 leaves LE set once a DR was
        // used, seen as dr7=0x100 on every thread of a detached 32-bit target).
        if (!(w.Dr7 & 0xFF)) w.Dr7 &= ~(decltype(w.Dr7))0x300;
        BOOL set_ok = SetThreadContext(t, &w);
        const DWORD set_err = set_ok ? 0 : GetLastError();
        if (!set_ok && thread_terminating(t)) continue;      // exiting (ERROR_ACCESS_DENIED): never runs user code again
        CONTEXT v{}; v.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(t, &v);
        if (!set_ok)
            report_tids += " " + std::to_string(GetThreadId(t)) + ":dr7=" + std::to_string((unsigned long long)v.Dr7) +
                           (set_ok ? "" : ":setfail=" + std::to_string(set_err));
    }
    {   // threads the debugger knows about but could not freeze
        std::unordered_set<DWORD> fz;
        for (HANDLE t : frozen) fz.insert(GetThreadId(t));
        for (DWORD tid : s->threads) if (!fz.count(tid)) report_tids += " " + std::to_string(tid) + ":notfrozen";
    }
    std::fprintf(stderr, "probe: detach: %zu thread(s) frozen;%s\n", frozen.size(),
                 report_tids.empty() ? " all clean" : report_tids.c_str());
    release_held(s, "detach (late)");                    // belt and braces: never leave a hold behind
    // No PROBE_IPC_LOG may be raised once the debugger is gone (it would reach the program).
    if (s->shared) { InterlockedExchange(&s->shared->log_ipc, 0); InterlockedExchange(&s->shared->ring_stalled, 0); }
    if (s->shared) {            // everything is restored: the guard has nothing left to protect
        auto &g = s->shared->guard;
        g.enabled = 0; g.step_count = g.held_count = g.block_count = 0;
        MemoryBarrier();
        // Its handle to us, if the agent never took it (no agent loaded): close it in the target.
        if (HANDLE h = (HANDLE)(uintptr_t)InterlockedExchange64(&g.controller_process, 0))
            DuplicateHandle(s->pi.hProcess, h, nullptr, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    }
    release_unclaimed_agent_mapping(s);            // still exclusive: no reattach can borrow this handle yet
    if (!s->exited) DebugActiveProcessStop(s->pi.dwProcessId);
    for (HANDLE t : frozen) { ResumeThread(t); CloseHandle(t); }
    s->detach_frozen.clear();
    // The final drain runs with the threads RUNNING: one the freeze caught between claiming a
    // ring slot and publishing it finishes the record first (frozen, it would be lost).
    stop_drainer(s);
    std::fprintf(stderr, "probe: detached from pid %lu\n", (unsigned long)s->pi.dwProcessId);
}

} // namespace uhh_session
