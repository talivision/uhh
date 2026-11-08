// Real #DB events for the controller's ownership/TF regressions. Windows sanitizes DR6
// (and a never-started thread's flags) on context writes: do not fabricate exception status.
#include "../../src/probe/session_internal.hpp"
#include <stdexcept>

namespace dr_review_fixture {
using namespace uhh_session;
static constexpr DWORD announce = 0xE055D071u;
struct ChildState {
    LONG seen; DWORD flags; DWORD64 dr6, dr7, dr0, dr1;
    ULONG_PTR ip, exception_address;
    DWORD exception_code, parameters;
    LONG data[8];
};
static ChildState child_state{};
static uint64_t child_done = 0;
static unsigned callbacks = 0;
static void hit(probe_context *) { ++callbacks; }
static void dr_require(bool ok, const char *stage) {
    if (!ok) {
        std::fprintf(stderr, "dr-review: %s failed (Win32=%lu)\n", stage, (unsigned long)GetLastError());
        throw std::runtime_error(stage);
    }
}
static LONG CALLBACK child_veh(EXCEPTION_POINTERS *e) {
    if (child_done && e->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT &&
        (uint64_t)(uintptr_t)e->ExceptionRecord->ExceptionAddress == child_done) {
        EMU_IP(*e->ContextRecord) = (decltype(EMU_IP(*e->ContextRecord)))(child_done + 1);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (e->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    ++child_state.seen;
    child_state.flags = e->ContextRecord->EFlags;
    child_state.dr6 = e->ContextRecord->Dr6;
    child_state.dr7 = e->ContextRecord->Dr7;
    child_state.dr0 = e->ContextRecord->Dr0; child_state.dr1 = e->ContextRecord->Dr1;
    child_state.ip = (ULONG_PTR)EMU_IP(*e->ContextRecord);
    child_state.exception_address = (ULONG_PTR)e->ExceptionRecord->ExceptionAddress;
    child_state.exception_code = e->ExceptionRecord->ExceptionCode;
    child_state.parameters = e->ExceptionRecord->NumberParameters;
    e->ContextRecord->EFlags &= ~0x100u;
    e->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}
static int child(bool linger) {
    // pcmpeqd xmm0,xmm0; int3 (ready); movq [CX],xmm0; nop; int3 (done); ret.
    // One eight-byte store can fire distinct dword watches on data[0] and data[1],
    // on x64 and x86. CX is the first __fastcall argument on both architectures.
    const unsigned char code[] = {0x66,0x0F,0x76,0xC0, 0xCC, 0x66,0x0F,0xD6,0x01, 0x90,0xCC,0xC3};
    void *mem = VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mem || !AddVectoredExceptionHandler(1, child_veh)) return 3;
    if (linger) child_done = (uint64_t)(uintptr_t)mem + 10;
    std::memcpy(mem, code, sizeof(code));
    FlushInstructionCache(GetCurrentProcess(), mem, sizeof(code));
    const ULONG_PTR info[] = {(ULONG_PTR)mem, (ULONG_PTR)&child_state};
    RaiseException(announce, 0, 2, info);
    reinterpret_cast<void (__fastcall *)(LONG *)>(mem)(child_state.data);
    if (linger) Sleep(INFINITE);
    return 0;
}
struct Debuggee {
    PROCESS_INFORMATION pi{};
    DEBUG_EVENT ev{};
    bool pending = false, attached = true;
    uint64_t code = 0, state = 0, ntdll = 0;
    probe_session *session = nullptr; // only the UHH run dispatches library-owned events
    explicit Debuggee(bool linger = false) {
        char path[MAX_PATH];
        const DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
        dr_require(n && n < MAX_PATH, "child executable path");
        std::string command = std::string("\"") + path + (linger ? "\" --dr-child-detach" : "\" --dr-child");
        STARTUPINFOA startup{}; startup.cb = sizeof(startup);
        dr_require(!!CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE, DEBUG_ONLY_THIS_PROCESS,
                                 nullptr, nullptr, &startup, &pi), "create debuggee");
    }
    ~Debuggee() {
        TerminateProcess(pi.hProcess, 0);
        if (attached) {
            if (pending) ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            for (int i = 0; i < 100; ++i) {
                DEBUG_EVENT e{};
                if (!WaitForDebugEvent(&e, 50)) break;
                close_file(e);
                ContinueDebugEvent(e.dwProcessId, e.dwThreadId, DBG_CONTINUE);
                if (e.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) break;
            }
            DebugActiveProcessStop(pi.dwProcessId);
        }
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    static void close_file(const DEBUG_EVENT &e) {
        if (e.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && e.u.CreateProcessInfo.hFile) CloseHandle(e.u.CreateProcessInfo.hFile);
        if (e.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && e.u.LoadDll.hFile) CloseHandle(e.u.LoadDll.hFile);
    }
    void resume(DWORD disposition = DBG_CONTINUE) {
        dr_require(pending && !!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, disposition), "continue event");
        pending = false;
    }
    void wait(DWORD wanted, uint64_t address = 0) {
        dr_require(!pending, "previous event continued");
        const ULONGLONG until = GetTickCount64() + 10000;
        while (GetTickCount64() < until) {
            if (!WaitForDebugEvent(&ev, 100)) continue;
            pending = true;
            if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
                const auto base = (uint64_t)(uintptr_t)ev.u.LoadDll.lpBaseOfDll;
                if (iequals(event_module_name(pi.hProcess, ev.u.LoadDll.hFile, base), "ntdll.dll")) ntdll = base;
            }
            close_file(ev);
            dr_require(ev.dwDebugEventCode != EXIT_PROCESS_DEBUG_EVENT, "child alive");
            if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                auto &ex = ev.u.Exception.ExceptionRecord;
                if (ex.ExceptionCode == announce) {
                    dr_require(ex.NumberParameters == 2, "announcement arguments");
                    code = ex.ExceptionInformation[0]; state = ex.ExceptionInformation[1];
                } else {
                    if (ex.ExceptionCode == 0x4000001Eu) ex.ExceptionCode = EXCEPTION_SINGLE_STEP;
                    if (ex.ExceptionCode == 0x4000001Fu) ex.ExceptionCode = EXCEPTION_BREAKPOINT;
                    const uint64_t at = (uint64_t)(uintptr_t)ex.ExceptionAddress;
                    if (ex.ExceptionCode == wanted && at == (address ? address : code + 4) && code) return;
                    if (session && ((ex.ExceptionCode == EXCEPTION_BREAKPOINT && probe_at(session, at)) ||
                        (ex.ExceptionCode == EXCEPTION_SINGLE_STEP && session->stepping.count(ev.dwThreadId)))) {
                        DWORD disposition = 0;
                        dr_require(dispatch_event(session, ev, disposition), "dispatch library exception-context repair");
                        resume(disposition); continue;
                    }
                    // The only unsolicited exception is the initial loader breakpoint.
                    if (code || ex.ExceptionCode != EXCEPTION_BREAKPOINT)
                        std::fprintf(stderr, "dr-review: unexpected code=0x%lx at=0x%llx wanted=0x%lx at=0x%llx\n",
                                     (unsigned long)ex.ExceptionCode, (unsigned long long)at, (unsigned long)wanted,
                                     (unsigned long long)(address ? address : code + 4));
                    dr_require(!code && ex.ExceptionCode == EXCEPTION_BREAKPOINT, "expected exception address/code");
                }
            }
            resume();
        }
        dr_require(false, "debug event timeout");
    }
    CONTEXT get() const {
        CONTEXT c{}; c.ContextFlags = CONTEXT_ALL;
        dr_require(!!GetThreadContext(pi.hThread, &c), "get event context");
        return c;
    }
    void put(const CONTEXT &c) const { dr_require(!!SetThreadContext(pi.hThread, &c), "set event context"); }
    ChildState result() const {
        ChildState out{}; SIZE_T n = 0;
        dr_require(!!ReadProcessMemory(pi.hProcess, (void *)(uintptr_t)state, &out, sizeof(out), &n) && n == sizeof(out), "read child result");
        return out;
    }
};

// Intel SDM Vol. 3B (253669-088), 19.2.3 and 19.3.1.4:
// https://cdrdv2-public.intel.com/858456/253669-088-sdm-vol-3b.pdf
// BS records the step even after TF is cleared. Bn for a disabled slot is unspecified;
// test Bn only for target-enabled slots, not all four raw bits. Windows also clears TF
// in the user exception context (observed in CI and covered by Wine's ntdll exception tests,
// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/tests/exception.c
// single_step_handler on x86/x64). Measure the uninstrumented Windows VEH result rather
// than confusing the TF requested BEFORE execution with the flags delivered AFTER #DB.
static void initial_flags(CONTEXT &c) {
    // Make arithmetic flags equal between independent reference/observed processes.
    // PCMPEQD and MOVQ leave EFLAGS unchanged. Bit 1 is reserved, not a program flag.
    c.EFlags &= ~(0x8D5u | 0x100u | 0x10000u);
}
static void passive_debug_register(CONTEXT &c, uint64_t data) {
    // With DR7=0 Windows can omit debug status from its captured CONTEXT even though
    // TF really raised #DB. Use the same debug-active context class as the UHH run:
    // a debugger-owned EXECUTE breakpoint in data, which no instruction can execute.
    c.Dr3 = (decltype(c.Dr3))(data + 16);
    c.Dr7 |= (decltype(c.Dr7))1 << 6;
}
static unsigned target_slots_for(const std::string &mode) {
    return (mode == "step-own" || mode == "step-own-detach") ? 1u : mode == "step-mixed" ? 2u : 0u;
}
static void print_veh(const char *label, const ChildState &r) {
    std::fprintf(stderr, "dr-review: %s VEH seen=%ld flags=0x%lx dr6=0x%llx dr7=0x%llx ip=0x%llx exception=0x%llx code=0x%lx\n",
                 label, (long)r.seen, (unsigned long)r.flags, (unsigned long long)r.dr6,
                 (unsigned long long)r.dr7, (unsigned long long)r.ip,
                 (unsigned long long)r.exception_address, (unsigned long)r.exception_code);
}
static ChildState reference_event(const std::string &mode) {
    Debuggee d; d.wait(EXCEPTION_BREAKPOINT);
    auto c = d.get(); initial_flags(c);
    const unsigned slots = target_slots_for(mode);
    const uint64_t data = d.state + offsetof(ChildState, data);
    c.Dr0 = (decltype(c.Dr0))data; c.Dr1 = (decltype(c.Dr1))(data + 4);
    c.Dr2 = c.Dr3 = c.Dr6 = c.Dr7 = 0;
    for (unsigned k = 0; k < 2; ++k)
        if (slots & (1u << k)) c.Dr7 |= ((decltype(c.Dr7))1 << (k * 2)) | ((decltype(c.Dr7))0xD << (16 + k * 4));
    if (!slots) {
        passive_debug_register(c, data);
        c.EFlags |= 0x100u; // the PROGRAM's step; the passive debugger register cannot fire
    }
    d.put(c);
    const auto armed = d.get();
    if (!slots) dr_require((armed.EFlags & 0x100u) && (armed.Dr7 & 0x40u) && armed.Dr3 == data + 16,
                           "reference TF and non-firing debugger register armed");
    d.resume(); d.wait(EXCEPTION_SINGLE_STEP, d.code + 9);
    const auto incoming = d.get();
    const DWORD64 mask = 0xE000u | slots;
    std::fprintf(stderr, "dr-review: reference #DB dr6=0x%llx dr7=0x%llx flags=0x%lx\n",
                 (unsigned long long)incoming.Dr6, (unsigned long long)incoming.Dr7, (unsigned long)incoming.EFlags);
    dr_require((incoming.Dr6 & mask) == (slots ? slots : 0x4000u), "reference exception cause");
    d.resume(DBG_EXCEPTION_NOT_HANDLED); d.wait(EXCEPTION_BREAKPOINT, d.code + 10);
    const auto result = d.result(); print_veh("reference", result);
    dr_require(result.seen == 1 && result.exception_code == EXCEPTION_SINGLE_STEP &&
               result.ip == d.code + 9 && result.exception_address == d.code + 9,
               "reference event delivered at original instruction stream");
    dr_require(!(result.flags & 0x100u), "Windows reference delivers cleared TF");
    dr_require((result.dr6 & mask) == (slots ? slots : 0x4000u), "reference VEH cause preserved");
    return result;
}
static void compare_event(const Debuggee &d, const ChildState &reference, const std::string &mode) {
    const auto result = d.result(); print_veh("instrumented", result);
    const unsigned slots = target_slots_for(mode);
    // Keep BS/BD/BT and EVERY target-enabled B-bit in the comparison. Only raw Bn of
    // non-target slots (not architecturally meaningful for the program) are excluded.
    const DWORD64 mask = 0xE000u | slots;
    dr_require(!d.session || d.session->debug_delivery.empty(), "saved debug exception context repaired");
    if (d.session && d.session->debug_dispatch_probe) {
        const Probe *p = d.session->debug_dispatch_probe;
        unsigned char byte = 0; SIZE_T n = 0;
        dr_require(!p->active && !!ReadProcessMemory(d.pi.hProcess, (void *)(uintptr_t)p->address, &byte, 1, &n) &&
                   n == 1 && byte == p->original, "temporary dispatcher breakpoint removed");
    }
    dr_require(result.seen == reference.seen && result.exception_code == reference.exception_code &&
               result.parameters == reference.parameters && result.ip == d.code + 9 &&
               result.exception_address == d.code + 9, "target event count/code/location unchanged");
    dr_require(((result.flags ^ reference.flags) & ~0x2u) == 0, "target VEH flags unchanged from Windows reference");
    dr_require((result.dr6 & mask) == (reference.dr6 & mask), "target VEH step/watch status unchanged from Windows reference");
    const uint64_t data = d.state + offsetof(ChildState, data);
    for (unsigned k = 0; k < 2; ++k) {
        if (!(slots & (1u << k))) continue;
        const DWORD64 field = ((DWORD64)3 << (k * 2)) | ((DWORD64)0xF << (16 + k * 4));
        dr_require((result.dr7 & field) == (reference.dr7 & field) &&
                   (k ? result.dr1 : result.dr0) == data + k * 4, "target VEH debug-register ownership unchanged");
    }
}

int run(int argc, char **argv) {
    if (argc == 2 && !std::strcmp(argv[1], "--dr-child")) return child(false);
    if (argc == 2 && !std::strcmp(argv[1], "--dr-child-detach")) return child(true);
    if (argc != 2) return 2;
    const std::string mode = argv[1];
    bool ok = false;
    std::string failed;
    try {
        ChildState reference{};
        if (mode == "watch-tf" || mode == "watch-tf-carried" || mode == "step-own" ||
            mode == "step-mixed" || mode == "step-tf" || mode == "step-own-detach") reference = reference_event(mode);
        Debuggee d(mode == "step-own-detach");
        d.wait(EXCEPTION_BREAKPOINT); // after the loader: the child's ready INT3
        auto session = std::make_unique<probe_session>();
        auto *s = session.get();
        s->pi = d.pi; s->threads.insert(d.pi.dwThreadId); s->thread_handle[d.pi.dwThreadId] = d.pi.hThread;
        s->event_tid = d.pi.dwThreadId; s->initial_break = true;
        dr_require(d.ntdll != 0, "observe target ntdll mapping");
        s->module_bases["ntdll.dll"] = d.ntdll; d.session = s;
        s->detaching = true; // no asynchronous library installs in this isolated dispatcher
        const uint64_t site = d.code + 5, done = d.code + 10;
        const uint64_t old_address = d.state + offsetof(ChildState, data), new_address = old_address + 4;
        const uint64_t target_address = old_address + 8;
        auto probe = std::make_unique<Probe>();
        probe->flags = PROBE_HW | PROBE_WATCH_WRITE; probe->active = true;
        probe->hw_generation = 1; probe->address = old_address; probe->dr_slot = 0; probe->callback = hit;
        Probe *p = probe.get(); s->probes.push_back(std::move(probe));
        s->dr_used = s->dr_ever = 1; s->hw_active = 1; s->hw_armed_ever.insert(old_address);
        auto c = d.get(); initial_flags(c);
        c.Dr0 = (decltype(c.Dr0))old_address; c.Dr1 = c.Dr2 = c.Dr3 = c.Dr6 = 0;
        c.Dr7 = 1 | ((decltype(c.Dr7))0xD << 16); c.EFlags &= ~0x100u;
        auto watch_event = [&](bool tf, bool mixed = false) {
            if (tf) c.EFlags |= 0x100u;
            if (mixed) {
                c.Dr1 = (decltype(c.Dr1))new_address;
                c.Dr7 |= 4 | ((decltype(c.Dr7))0xD << 20);
            }
            d.put(c);
            const auto armed = d.get();
            dr_require(armed.Dr0 == c.Dr0 && (armed.Dr7 & 1) && ((armed.Dr7 >> 16) & 0xF) == 0xD, "watch armed before execution");
            d.resume(); d.wait(EXCEPTION_SINGLE_STEP, site + 4);
            const auto raised = d.get();
            const DWORD64 expect = (tf ? 0x4000u : 0u) | (mixed ? 3u : 1u);
            std::fprintf(stderr, "dr-review: real #DB dr6=0x%llx flags=0x%lx\n",
                         (unsigned long long)raised.Dr6, (unsigned long)raised.EFlags);
            dr_require((raised.Dr6 & 0xE00Fu) == expect, "real hardware exception status");
        };
        auto positive_watch = [&] {
            // Every stale-hit rejection must still accept a subsequent REAL access.
            auto next = d.get();
            EMU_IP(next) = (decltype(EMU_IP(next)))site;
            next.EFlags &= ~0x100u; next.Dr6 = 0;
            next.Dr0 = (decltype(next.Dr0))p->address;
            next.Dr7 = 1 | ((decltype(next.Dr7))0xD << 16);
            d.put(next); d.resume(); d.wait(EXCEPTION_SINGLE_STEP, site + 4);
            settle_hw_thread(s, d.pi.dwThreadId); // a new event, not the previous hit's carry
            s->event_tid = d.pi.dwThreadId;
            dr_require((d.get().Dr6 & 0xE00Fu) == 1, "new access real B0");
            const unsigned before = callbacks; const uint64_t hits = p->hits;
            bool handled = false;
            dr_require(handle_hw(s, d.ev, handled) && handled, "new access handled");
            dr_require(callbacks == before + 1 && p->hits == hits + 1, "new access callback and hit");
        };
        if (mode == "release") {
            c.Dr0 = (decltype(c.Dr0))target_address; c.Dr1 = (decltype(c.Dr1))(target_address + 4);
            c.Dr2 = (decltype(c.Dr2))(target_address + 8); c.Dr3 = (decltype(c.Dr3))(target_address + 12);
            c.Dr7 = 0xDDDD0055; d.put(c);
            const auto before = d.get();
            hw_yield_to_target(s, d.pi.dwThreadId, d.pi.hThread); release_hw(s, *p);
            const auto after = d.get();
            dr_require(after.Dr0 == before.Dr0 && after.Dr7 == before.Dr7, "release preserves target slots");
        } else if (mode == "queued" || mode == "queued-same" || mode == "queued-rearm") {
            watch_event(false);
            s->event_tid = 0; keep_queued_dr6(s, d.pi.dwThreadId, d.pi.hThread);
            dr_require((s->dr6_lost.at(d.pi.dwThreadId).bits & 1) != 0, "queued B0 captured");
            if (mode != "queued-rearm") {
                auto replacement = std::make_unique<Probe>(*p);
                p->active = false; p->dr_slot = -1;
                p = replacement.get(); s->probes.push_back(std::move(replacement));
            }
            p->address = mode == "queued" ? new_address : old_address; p->hw_generation = 2;
            s->hw_armed_ever.insert(p->address);
            dr_require(set_dr_on_thread(d.pi.hThread, 0, p->address, true, 1, 3), "replace queued slot");
            settle_hw_thread(s, d.pi.dwThreadId);
            dr_require((dr6_carried(s, d.pi.dwThreadId) & 1) != 0, "queued B0 carried");
            bool handled = false;
            dr_require(handle_hw(s, d.ev, handled) && handled && callbacks == 0 && p->hits == 0, "stale access rejected");
            positive_watch();
        } else if (mode == "deferred" || mode == "deferred-reused" || mode == "deferred-carried-reused") {
            watch_event(false);
            if (mode == "deferred-carried-reused") {
                s->event_tid = 0; keep_queued_dr6(s, d.pi.dwThreadId, d.pi.hThread);
                p->address = new_address; p->hw_generation = 2; s->hw_armed_ever.insert(new_address);
                dr_require(set_dr_on_thread(d.pi.hThread, 0, new_address, true, 1, 3), "replace before holding carried watch");
                settle_hw_thread(s, d.pi.dwThreadId);
            }
            auto raised = d.get(); raised.Dr6 |= dr6_carried(s, d.pi.dwThreadId);
            dr_require(hold_watch_hit(s, d.ev, raised, 0), "watch held during call");
            const auto &saved = s->dr6_lost.at(d.pi.dwThreadId);
            dr_require(saved.address[0] == old_address && saved.generation[0] == 1, "held watch ownership captured");
            if (mode == "deferred-reused") {
                p->address = new_address; p->hw_generation = 2; s->hw_armed_ever.insert(new_address);
                dr_require(set_dr_on_thread(d.pi.hThread, 0, new_address, true, 1, 3), "replace held watch");
            }
            d.resume(); // thread remains suspended by hold_watch_hit, exactly as during a call
            {
                FiberHost fibers(s);
                dr_require(poll_calls(s), "replay held watch after call");
            }
            dr_require(s->watch_deferred.empty() && callbacks == (mode == "deferred" ? 1u : 0u), "held watch callback identity");
            d.wait(EXCEPTION_BREAKPOINT, done);
            positive_watch();
        } else if (mode == "watch-tf" || mode == "watch-tf-carried") {
            watch_event(true);
            if (mode == "watch-tf-carried") {
                s->event_tid = 0; keep_queued_dr6(s, d.pi.dwThreadId, d.pi.hThread);
                dr_require(set_dr_on_thread(d.pi.hThread, 0, old_address, true, 1, 3), "write DRs over queued BS+B0");
                settle_hw_thread(s, d.pi.dwThreadId);
                dr_require((dr6_carried(s, d.pi.dwThreadId) & 0x4001) == 0x4001, "BS+B0 carried");
            }
            bool handled = false;
            dr_require(handle_hw(s, d.ev, handled) && !handled && callbacks == 1 && p->hits == 1, "watch callback and target step forwarding");
            d.resume(DBG_EXCEPTION_NOT_HANDLED); d.wait(EXCEPTION_BREAKPOINT, done);
            compare_event(d, reference, mode);
        } else if (mode == "gate") {
            watch_event(false); // B0 belongs to the target, whose slot replaced the gate
            p->active = false; s->hw_active = 0; s->gates.emplace_back(target_address, 0);
            s->hw_armed_ever.insert(target_address); s->detaching = false;
            bool handled = false;
            dr_require(!handle_gate(s, d.ev, handled) && !handled && s->held.empty(), "foreign exception is not an install gate");
            const auto before = d.get(); release_held(s, "test"); const auto after = d.get();
            dr_require(after.Dr0 == before.Dr0 && after.Dr7 == before.Dr7, "gate cleanup preserves target slot");
        } else if (mode == "step-entry") {
            const unsigned char trap = 0xCC; SIZE_T n = 0;
            dr_require(!!WriteProcessMemory(d.pi.hProcess, (void *)(uintptr_t)site, &trap, 1, &n) && n == 1, "arm software site");
            FlushInstructionCache(d.pi.hProcess, (void *)(uintptr_t)site, 1);
            p->flags = PROBE_BREAKPOINT; p->dr_slot = -1; p->address = site;
            p->original = 0x66; p->orig_insn = {0x66,0x0F,0xD6,0x01}; p->insn_len = 4; p->displaced_ok = true;
            s->dr_used = s->dr_ever = 0; s->hw_active = 0;
            c.Dr7 = c.Dr6 = 0; c.EFlags |= 0x100; d.put(c);
            d.resume(); d.wait(EXCEPTION_BREAKPOINT, site);
            DWORD disposition = 0;
            dr_require(dispatch_event(s, d.ev, disposition) && disposition == DBG_CONTINUE, "software hit dispatched");
            const auto st = s->stepping.find(d.pi.dwThreadId);
            dr_require(st != s->stepping.end() && !st->second.displaced && st->second.prog_tf && callbacks == 1, "program TF steps at real site");
        } else if (mode == "step-own" || mode == "step-tf" || mode == "step-mixed" || mode == "step-own-detach") {
            const bool mixed = mode == "step-mixed", tf = mode == "step-tf";
            p->active = mixed; s->hw_active = mixed ? 1 : 0; s->dr_used = s->dr_ever = mixed ? 1 : 0;
            if (tf) { c.Dr7 = 0; passive_debug_register(c, old_address); }
            StepState st{}; st.site = site; st.insn_len = 4; st.prog_tf = tf;
            s->stepping.emplace(d.pi.dwThreadId, st);
            if (tf) {
                c.EFlags |= 0x100; d.put(c); d.resume(); d.wait(EXCEPTION_SINGLE_STEP, site + 4);
                const auto raised = d.get();
                std::fprintf(stderr, "dr-review: real TF-only #DB dr6=0x%llx flags=0x%lx\n",
                             (unsigned long long)raised.Dr6, (unsigned long)raised.EFlags);
                // No target slot is enabled; SDM 19.2.3 does not define the raw B0-B3.
                dr_require((raised.Dr6 & 0xE000u) == 0x4000, "real TF-only exception");
            } else watch_event(true, mixed);
            DWORD disposition = 0;
            dr_require(dispatch_event(s, d.ev, disposition) && disposition == DBG_EXCEPTION_NOT_HANDLED, "step forwards target exception");
            dr_require(s->stepping.empty() && callbacks == (mixed ? 1u : 0u) && p->hits == (mixed ? 1u : 0u), "step completion and mixed callback");
            d.resume(disposition);
            if (mode == "step-own-detach") {
                // Detach before the queued dispatcher catch is serviced. Its drain must
                // repair the target's context, then remove the temporary INT3 too.
                detach(s);
                BOOL debugged = TRUE;
                dr_require(!!CheckRemoteDebuggerPresent(d.pi.hProcess, &debugged) && !debugged, "detach with pending debug delivery");
                d.attached = false;
            } else d.wait(EXCEPTION_BREAKPOINT, done);
            compare_event(d, reference, mode);
        } else if (mode == "detach-dr" || mode == "detach-tf") {
            const bool tf = mode == "detach-tf";
            p->active = false; s->hw_active = 0; s->dr_used = 0;
            c.Dr0 = (decltype(c.Dr0))target_address;
            if (tf) { s->dr_ever = 0; c.Dr7 = 0; c.EFlags |= 0x100; }
            d.put(c);
            const auto before = d.get();
            dr_require(((before.EFlags & 0x100) != 0) == tf, "detach input TF");
            dr_require(SuspendThread(d.pi.hThread) != (DWORD)-1, "hold child across detach");
            d.resume(); detach(s);
            BOOL debugged = TRUE;
            dr_require(!!CheckRemoteDebuggerPresent(d.pi.hProcess, &debugged) && !debugged, "debugger detached");
            d.attached = false;
            const auto after = d.get();
            dr_require(after.Dr0 == before.Dr0 && after.Dr7 == before.Dr7 &&
                    ((after.EFlags ^ before.EFlags) & 0x100) == 0, "detach preserves target DRs/TF");
        } else dr_require(false, "known scenario");
        for (auto &kv : s->own_thread_handle) CloseHandle(kv.second);
        ok = true;
    } catch (const std::exception &e) {
        failed = e.what(); // stage names are fixed literals without JSON metacharacters
    }
    std::printf("{\"kind\":\"dr_review\",\"case\":\"%s\",\"ok\":%d,\"callbacks\":%u,\"failure\":\"%s\"}\n",
                mode.c_str(), ok ? 1 : 0, callbacks, failed.c_str());
    return ok ? 0 : 1;
}

} // namespace dr_review_fixture

int main(int argc, char **argv) {
    return dr_review_fixture::run(argc, argv);
}
