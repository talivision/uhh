// Deterministic controller debug-context regressions. The child never runs: contexts model
// queued Windows events, which are dispatched through the real controller helpers. In
// particular, no timing race is needed to reuse a slot before its queued #DB is delivered.
#include "../../src/probe/session_internal.hpp"

using namespace uhh_session;
static unsigned callbacks = 0;
static void hit(probe_context *) { ++callbacks; }

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    STARTUPINFOA startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION pi{};
    std::string command = std::string("\"") + argv[2] + "\" owndr";
    if (!CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED,
                        nullptr, nullptr, &startup, &pi)) return 3;
    // Heap allocation: the session contains large fixed buffers on both architectures.
    auto session = std::make_unique<probe_session>();
    auto *s = session.get();
    s->pi = pi; s->threads.insert(pi.dwThreadId); s->thread_handle[pi.dwThreadId] = pi.hThread;
    s->event_tid = pi.dwThreadId; s->initial_break = true;
    s->detaching = true; // suppress asynchronous installs/holds in the synthetic dispatcher
    CONTEXT c{}; c.ContextFlags = CONTEXT_ALL;
    bool ok = !!GetThreadContext(pi.hThread, &c);
    const uint64_t pc = (uint64_t)EMU_IP(c);
    const uint64_t old_address = 0x12340000, new_address = 0x12350000, target_address = 0x12360000;
    auto probe = std::make_unique<Probe>();
    probe->flags = PROBE_HW | PROBE_WATCH_WRITE; probe->active = true;
    probe->hw_generation = 1; probe->address = old_address; probe->dr_slot = 0; probe->callback = hit;
    Probe *p = probe.get(); s->probes.push_back(std::move(probe));
    s->dr_used = s->dr_ever = 1; s->hw_active = 1; s->hw_armed_ever.insert(old_address);
    c.Dr0 = (decltype(c.Dr0))old_address; c.Dr1 = c.Dr2 = c.Dr3 = 0;
    c.Dr7 = 1 | ((decltype(c.Dr7))0xD << 16); c.Dr6 = 1;
    c.EFlags &= ~0x100u;
    DEBUG_EVENT event{}; event.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
    event.dwProcessId = pi.dwProcessId; event.dwThreadId = pi.dwThreadId;
    event.u.Exception.dwFirstChance = 1;
    event.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_SINGLE_STEP;
    event.u.Exception.ExceptionRecord.ExceptionAddress = (void *)(uintptr_t)pc;
    const std::string mode = argv[1];
    if (mode == "release") {
        // The program claimed all slots; migration must yield. A later release cannot
        // clear the foreign image in the probe's former slot.
        c.Dr0 = (decltype(c.Dr0))target_address;
        c.Dr1 = (decltype(c.Dr1))(target_address + 4);
        c.Dr2 = (decltype(c.Dr2))(target_address + 8);
        c.Dr3 = (decltype(c.Dr3))(target_address + 12);
        c.Dr7 = 0xDDDD0055;
        ok = ok && !!SetThreadContext(pi.hThread, &c);
        hw_yield_to_target(s, pi.dwThreadId, pi.hThread);
        release_hw(s, *p);
        CONTEXT after{}; after.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        ok = ok && !!GetThreadContext(pi.hThread, &after) && after.Dr0 == c.Dr0 && ((after.Dr7 ^ c.Dr7) & 0xFFFF03FFu) == 0;
    } else if (mode == "queued" || mode == "queued-same" || mode == "queued-rearm") {
        ok = ok && !!SetThreadContext(pi.hThread, &c);
        s->event_tid = 0; keep_queued_dr6(s, pi.dwThreadId, pi.hThread);
        // Reuse the slot before delivering the saved status. The old and replacement
        // watches are distinct even though the B-bit has the same index.
        const uint64_t replacement_address = mode == "queued" ? new_address : old_address;
        if (mode != "queued-rearm") {
            auto replacement = std::make_unique<Probe>(*p);
            p->active = false; p->dr_slot = -1;
            p = replacement.get(); s->probes.push_back(std::move(replacement));
        }
        p->address = replacement_address; p->hw_generation = 2;
        s->hw_armed_ever.insert(replacement_address);
        c.Dr0 = (decltype(c.Dr0))replacement_address; c.Dr6 = 0;
        ok = ok && !!SetThreadContext(pi.hThread, &c);
        settle_hw_thread(s, pi.dwThreadId);
        bool handled = false;
        ok = ok && dr6_carried(s, pi.dwThreadId) == 1 && handle_hw(s, event, handled) && handled && callbacks == 0 && p->hits == 0;
    } else if (mode == "watch-tf" || mode == "watch-tf-carried") {
        c.Dr6 |= 0x4000; c.EFlags |= 0x100;
        ok = ok && !!SetThreadContext(pi.hThread, &c);
        if (mode == "watch-tf-carried") {
            s->event_tid = 0; keep_queued_dr6(s, pi.dwThreadId, pi.hThread);
            c.Dr6 = 0; ok = ok && !!SetThreadContext(pi.hThread, &c);
            settle_hw_thread(s, pi.dwThreadId);
        }
        bool handled = false;
        ok = ok && handle_hw(s, event, handled) && !handled && callbacks == 1 && p->hits == 1;
        CONTEXT after{}; after.ContextFlags = CONTEXT_ALL;
        ok = ok && !!GetThreadContext(pi.hThread, &after) && (after.EFlags & 0x100) &&
             (after.Dr6 & 0x4000) && !(after.Dr6 & 1);
    } else if (mode == "gate") {
        p->active = false; s->hw_active = 0;
        s->gates.emplace_back(old_address, 0);
        c.Dr0 = (decltype(c.Dr0))target_address;
        ok = ok && !!SetThreadContext(pi.hThread, &c);
        bool handled = false;
        s->detaching = false; // a false-positive gate must visibly try to hold this thread
        const bool gated = handle_gate(s, event, handled);
        ok = ok && !gated && !handled && s->held.empty();
        release_held(s, "test"); // also exercises clear_gates
        CONTEXT after{}; after.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        ok = ok && !!GetThreadContext(pi.hThread, &after) && after.Dr0 == c.Dr0 && ((after.Dr7 ^ c.Dr7) & 0xFFFF03FFu) == 0;
    } else if (mode == "step-entry") {
        // A target already single-stepping must execute at the real site: both the
        // context and the eventual exception address must be outside UHH scratch.
        void *site = VirtualAllocEx(pi.hProcess, nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        const unsigned char code[] = {0xCC, 0x90, 0xC3};
        SIZE_T written = 0;
        ok = ok && site && !!WriteProcessMemory(pi.hProcess, site, code, sizeof(code), &written) && written == sizeof(code);
        p->flags = PROBE_BREAKPOINT; p->dr_slot = -1; p->address = (uint64_t)(uintptr_t)site;
        p->original = 0x90; p->orig_insn = {0x90}; p->insn_len = 1; p->displaced_ok = true;
        s->dr_used = s->dr_ever = 0; s->hw_active = 0;
        c.Dr0 = 0; c.Dr7 = c.Dr6 = 0; c.EFlags |= 0x100;
        EMU_IP(c) = (decltype(EMU_IP(c)))(p->address + 1);
        ok = ok && !!SetThreadContext(pi.hThread, &c);
        event.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_BREAKPOINT;
        event.u.Exception.ExceptionRecord.ExceptionAddress = site;
        DWORD disposition = 0;
        ok = ok && dispatch_event(s, event, disposition) && disposition == DBG_CONTINUE;
        const auto st = s->stepping.find(pi.dwThreadId);
        ok = ok && st != s->stepping.end() && !st->second.displaced && st->second.prog_tf && callbacks == 1;
    } else if (mode == "step-own" || mode == "step-tf" || mode == "step-mixed") {
        // Model an ordinary software step at completion. In step-own there is no
        // active UHH hardware probe: a breakpoint-only session must still pass B0.
        const bool mixed = mode == "step-mixed";
        p->active = mixed; s->hw_active = mixed ? 1 : 0; s->dr_used = s->dr_ever = mixed ? 1 : 0;
        const bool tf = mode == "step-tf";
        c.Dr0 = (decltype(c.Dr0))target_address; c.Dr6 = 0x4000 | (tf ? 0 : 1);
        if (mixed) {
            c.Dr0 = (decltype(c.Dr0))old_address; c.Dr1 = (decltype(c.Dr1))target_address;
            c.Dr7 |= 4 | ((decltype(c.Dr7))0xD << 20); c.Dr6 |= 3;
        }
        c.EFlags |= 0x100;
        StepState st{}; st.site = pc - 1; st.insn_len = 1; st.prog_tf = tf;
        s->stepping.emplace(pi.dwThreadId, st);
        ok = ok && !!SetThreadContext(pi.hThread, &c);
        DWORD disposition = 0;
        ok = ok && dispatch_event(s, event, disposition) && disposition == DBG_EXCEPTION_NOT_HANDLED;
        CONTEXT after{}; after.ContextFlags = CONTEXT_ALL;
        ok = ok && !!GetThreadContext(pi.hThread, &after) && ((after.EFlags & 0x100) != 0) == tf &&
             ((after.Dr6 & 0x4000) != 0) == tf && (tf || (after.Dr6 & (mixed ? 2 : 1))) &&
             callbacks == (mixed ? 1u : 0u) && s->stepping.empty();
    } else if (mode == "detach-dr" || mode == "detach-tf") {
        // detach() gets a real process and a suspended thread, but no live debugger.
        // Its release/drain/final-context passes run unchanged; the initial suspension
        // ensures that even when detach thaws its own holds, the fixture never executes.
        p->active = false; s->hw_active = 0; s->dr_used = 0;
        const bool tf = mode == "detach-tf";
        c.Dr0 = (decltype(c.Dr0))target_address; c.Dr6 = 0;
        if (tf) { s->dr_ever = 0; c.Dr7 = 0; c.EFlags |= 0x100; }
        ok = ok && !!SetThreadContext(pi.hThread, &c);
        detach(s);
        CONTEXT after{}; after.ContextFlags = CONTEXT_ALL;
        ok = ok && !!GetThreadContext(pi.hThread, &after) && after.Dr0 == c.Dr0 && ((after.Dr7 ^ c.Dr7) & 0xFFFF03FFu) == 0 &&
             ((after.EFlags ^ c.EFlags) & 0x100) == 0;
    } else ok = false;
    std::printf("{\"kind\":\"dr_review\",\"case\":\"%s\",\"ok\":%d,\"callbacks\":%u}\n",
                mode.c_str(), ok ? 1 : 0, callbacks);
    // No target instruction is ever executed with a fabricated context.
    TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 5000);
    for (auto &kv : s->own_thread_handle) CloseHandle(kv.second);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return ok ? 0 : 1;
}
