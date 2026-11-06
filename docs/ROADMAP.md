# UHH roadmap (living tracker)

Status: ✅ done and verified on x64 + x86 · 🔧 in progress · ⬜ not started · 📄 documented limitation.
Rules: every fix gets a regression test; the full suite (`scripts/regress.py`) runs on
x64 and x86 after each step; an adversarial review after each large change; push to
github.com/talivision/uhh at each green milestone. **The public API is frozen** as
agreed: session `probe_*`, context `get_*`/`set_*`/`send_log`/`send_log_stack`/
`call_func`/`get_session`, plus `probe_attach`/`probe_attach_new`. Callbacks are
identical source under every backend.

## Core library
- ✅ Three backends, multithread-exact: software breakpoint (displaced stepping), hardware (DR0-3), inline (SafetyHook mid-hook agent)
- ✅ Hardware data watchpoints (`probe_watch`, write / read-write), `PROBE_ONCE`
- ✅ Runtime control from any callback via `get_session(c)`; inline callbacks forward over synchronous IPC
- ✅ Runtime inline hooks (installed on a fresh agent thread, never inside the caller)
- ✅ `module!Export[+0xOFF]` resolution from the target image
- ✅ `send_log_stack`: raw frames at the hit, symbolized on the controller writer thread (dbghelp)
- ✅ Synchronous inline install: hold at entry point / at LOAD_DLL until hooks confirm (agent service thread). Handle double-close bug found and fixed; re-verifying
- ✅ Zero-drop inline logs: lock-free ring + controller drainer thread + backpressure. Must pass the 2M-event inline volume tier with `log_dropped == 0`
- ✅ Pre-hooked site report (live vs disk bytes, disassembly, pattern, destination, suggestions); `PROBE_ALLOW_PREHOOKED` / `PROBE_FALLBACK_HW`
- ✅ `call_func`: call target functions from any callback (direct for inline; debugger-run call on the stopped thread for breakpoint/hw); pointer-sized args on both arches. Further hardening of the breakpoint/hw path was not pursued
- ✅ `probe_attach` (clean detach: hooks removed, INT3s restored, DRs cleared, no thread mid-step), `probe_attach_new`
- 🔧 Inline register overrides counted in the report (`overrides`) like controller-side ones
- ✅ x86 `send_log_stack` at a function's first instruction includes the caller frame (agent and controller)
- ✅ Stream logs through a per-session `%TEMP%\uhh\logs` JSONL file: one bounded producer
  queue/file-writer plus a live stdout tailer, lossless filesystem backpressure, raw-handle
  complete-line writes, <=10 ms/idle publication, report-time catch-up, NUL opt-out, and
  `logs_written`/controller peak-working-set metrics. Covered at 20M inline and 200k hw/breakpoint.
- ⬜ Performance pass on every hot path (per-hit cost per backend and per method; see Benchmarks)

## Examples and targets (subagent, own worktree)
- ✅ Move `probe_app` + `configparse` to `examples/targets/`; target spawns helpers, enumerates PIDs, opens and reads them **only when the config flag is on**
- ✅ `examples/gated_config`: config ships DISABLED; breakpoint flips the flag (the metrics technique); logs every read
- ✅ `examples/attach` (`uhh_attach <pid> --pid P --range BASE:SIZE`): attach, same flag flip, NtOpenProcess handle->pid map, filtered read logging; README steps
- ✅ Clean drivers: no env vars, no sibling-path helpers, target path on the command line

## Correctness matrix (attest every method under every callback type)
- ✅ Conformance test: each of `get_reg`, `set_reg`, `get_func_arg`, `get_mem`, `set_mem`, `get_config`, `send_log`, `send_log_stack`, `call_func`, and the control ops via `get_session` (`probe_add_symbol`, `probe_add_address`, `probe_watch`) asserted under breakpoint, hw and inline callbacks, x64 and x86
- ✅ Exact hit counts at 8 threads, all backends; ✅ 2M hits exact all backends
- ✅ Logs == hits, `log_dropped == 0` asserted (normal tier); ✅ volume tier for inline

## Program-correctness guarantees (probes must have no side effects)
- ✅ Side-effect audit + tests: after any callback, the target observes no change except deliberate `set_reg`/`set_mem`: `GetLastError()`, `errno`, x87/SSE/AVX state, EFLAGS, TEB fields, stack contents below SP — under breakpoint, hw and inline
- ✅ Loader-time probe hits (a probe firing before the loader breakpoint) handled as hits, not swallowed (was crashing findstr x86)
- 🔧 Inline hooks on ntdll syscall stubs (the page ban is REMOVED): hooks are written with the target frozen by the controller (FREEZE/THAW IPC), page kept executable, threads inside the overwritten bytes moved to the trampoline; SafetyHook patched at build time (`cmake/patch_safetyhook.cmake`). gated_config/attach now probe `ntdll!NtReadVirtualMemory` / `ntdll!NtOpenProcess` directly. Tests: `ntdll-churn-*` (attach/hook/detach cycles under load, all backends), `patch-race-{frozen,unsafe}` (`PROBE_UNSAFE_FAST_PATCH` must fail sometimes; frozen never)
- 🔧 Inline site safety check (refused with the reason, or hw with `PROBE_FALLBACK_HW`; `PROBE_ALLOW_UNSAFE_SITE` overrides with a warning): overwritten bytes contain a non-final CALL; another export starts inside them; a branch (x64 .pdata function) lands inside them; an exit (ret/jmp) followed by non-padding inside them. Inline at a `ret` works over padding; packed code (ntdll stub rets) is refused -- breakpoint/hw there. Test: `ret-probe-*`
- ✗ Handle->pid through `kernel32!OpenProcess`: example design, documented (not a library item)
- ✅ Memory reads/writes at scale: millions of `get_mem`/`set_mem` across threads and backends; exact values, writes visible to the target, page-crossing and large sizes, unmapped/protected addresses fail cleanly, throughput per backend
- 🔧 Continuous evaluators (two full rounds done; more to come): independent agents repeatedly hunting edge cases, regressions and gaps against the gated_config use case

## Gaps from the goal gap-analysis (evaluator, 2026-11-04) — each closes with a test
- ✅ P1 detach while running: probe_close from another thread stops probe_run, which detaches on its own thread (debug-API rule); target finishes correctly, bytes == disk, DR7 == 0, debugger gone
- ✅ P1 unload/reload of a probed DLL: inline must re-arm like breakpoint/hw (hits == 3N per backend)
- ✅ P1 probe_add_symbol_cfg forwarded from inline callbacks (config travels over IPC)
- ✅ P1 one log length limit for every backend, truncation marked (inline was 256 vs 2048)
- ✅ P1 log delivery when the target crashes / is killed (logs + log_dropped == hits)
- ✅ P1 controller-side log memory: bounded queue; peak working set measured and compared at 2M/20M
- ✅ P1 probe_attach_new exercised (second instance, timeout path)
- ✅ P1 target checksum asserted equal across every mix cell and vs a flag-only run
- ✅ P2 hw PROBE_ONCE and watch RW|ONCE proven distinctly (1 hit each under 4 threads); 5th hw probe refused cleanly (setup and runtime from a breakpoint/inline callback), both freed slots reused (exec + watch, exact). Test: `hw-once-slots-*` (examples/p2edge) -- x64 ✅, x86 ✅
- ✅ P2 runtime adds on a DLL loaded later by a non-main thread (all backends, exact from the first call); probe_add_address(PROBE_INLINE) from a callback (every backend's callback; 2 threads, exact). Found+fixed: an inline callback folded by the linker (/OPT:ICF) with another exported callback was forwarded under the twin's name and refused -- both sides now match all export aliases. Test: `late-dll-worker-*` -- x64 ✅, x86 ✅
- ✅ P2 threads started during the entry hold (TLS callback / DllMain(PROCESS_ATTACH) thread calling the probed function): fixed -- a thread created while inline installs are outstanding (launch: after the initial break, incl. a static DLL's DllMain thread before the entry hold; attach: only during a runtime-add hold, never while the agent is injected; not the agent's own) is held from its first instruction until the same confirmation. Test: `entry-hold-threads-*` -- x64 ✅ (5/5 after the launch-scope fix), x86 ✅
- ✅ P2 refusal tests: PROBE_AT_RETURN, inline ONCE, 129th inline probe ✅; ALLOW_PREHOOKED inline chaining (attach onto probe_app --prehook's SafetyHook detour; foreign hook calls == UHH hits == logs == reads, checksum unchanged; `uhh_trace --allow-prehooked`). Test: `prehook-chain-inline` -- x64 ✅, x86 ✅ (found: probe_app's own --prehook detour called the __stdcall trampoline as cdecl and hung x86 with no tool attached; fixed in the target)
- ✅ P2 sidefx: full arithmetic EFLAGS (probe between cmp and jcc), LastStatus; below-SP documented as exempt
- ✅ P2 x86 stacks mid-function / FPO frames identical across backends (examples/stacks; x86 inline: verified return-address scan; x64 inline: frame 0 unwound from the original bytes; remaining differences in docs/symbols.md)
- ⬜ P2 mixed backends for state-sharing probes: documented limitation (state lives where callbacks run)

## Evaluator round 3 (2026-11-05) — open
- ✅ (#3) detach after a hooked DLL unloaded wrote original bytes to unmapped/reused memory -> agent skips UNLOADED hooks
- ✅ (#4) call inside the stolen bytes -> refused / hw fallback
- ✅ (#1) in-place step of `pushf` leaked TF into the pushed flags (RtlCaptureContext). PUSHF is emulated (flags image
  without TF); where the CPU must run it (the push lands in the stack's guard page -- emulating it would consume the
  guard without growing the stack) the in-place step clears our TF in the pushed image at step completion.
  Baseline `inplace-pushf_guard`: 7360/8000 pushed images carried TF (x86: 6441); now 0, stack grown as without UHH
- ✅ (#2) in-place fallback not exact under threads. Baseline (8 threads, breakpoint): `ctrl-inplace` 709/24000 hits
  on x64, 971/24000 on x86; `inplace-loop_a32` 1330/8000 (x86 677), `inplace-jecxz_a32` x86 1242/8000,
  `inplace-segjmp` 1147/8000 (x86 1400), `inplace-pushf_guard` 7672/8000 (x86 7267), `inplace-syscall` 7968/8000.
  Now every one exact (hits == logs == distinct tags == calls, results equal to a never-probed twin):
  - more is emulated: address-size LOOP/LOOPE/LOOPNE (ecx on x64, cx on x86) and JECXZ/JCXZ; every emulated memory
    access is first checked like the CPU would see it (committed, no PAGE_GUARD, readable/writable) -- before, an
    emulated push into the stack guard page went through Read/WriteProcessMemory semantics (guard consumed, no growth)
  - x64 SYSCALL / INT 2E run from a per-site trampoline (`insn; mov rcx, site+2; jmp site+2`, SYSCALL's RCX/R11 as
    natively, no trap flag, no completion event): the INT3 stays armed for the whole syscall (a blocking syscall used
    to keep the byte lifted until it returned), nesting (APCs, user-mode callbacks that hit probes) needs nothing;
    trampolines are never freed (a thread can be blocked in one across a detach)
  - whatever still steps in place (segment-relative / 16-bit branches, an access that must fault, the displaced-fault
    re-run, CALL/RET under CET shadow stacks, a REP string op without scratch) runs in an **in-place window**: every
    other target thread is suspended by the controller while the byte is lifted, and a hit queued just before the
    window is rewound onto the INT3 and replays after it (counted once). No deadlock: the window covers one
    instruction (one REP iteration) of the stepping thread, which reports its trap or fault before any other target
    code runs; instructions that can block in the kernel or leave 32-bit code (SYSCALL/SYSENTER/INT 2E/2B without a
    trampoline, far transfers, IRET) get no window; a window open for 2 s (the target suspended the stepping thread
    itself) is released with a warning; our agent's threads are never held (an entry hold waits for them).
    📄 Under CET the CALL/RET in-place path keeps working as before (the CPU executes them; only the other threads
    are held meanwhile) -- still unexercised on the VM (`EnableUserShadowStack`=0)
  - Tests: `inplace-*` (`--only inplace`: jmp rel8/rel32, jcc rel8/rel32 taken / not / data-dependent, call rel32,
    call [mem], ret, loop taken/not, loopz, loopnz, jrcxz/jecxz, address-size loop and jecxz/jcxz, pushf, pushf into
    the guard page, gs:/fs:-relative jmp, x64 syscall), `ctrl-inplace` exact
- 🔧 (#5) inline stack walk bounded by the thread's TEB stack limits + code reads range-checked (never faults); writes always re-validated (read cache kept across hits) -- VM verify pending
- ✗ (#6) breakpoint/hw call_func hardening: deliberately not pursued (see call_func note above)
- 🔧 (#7) call_func follows forwarded exports on breakpoint/hw (via the controller's copy of the same system DLL); conformance `call_func-forwarded` -- VM verify pending
- ✅ (#8) inline set_reg(SP): honoured -- SafetyHook's resume stub patched to `pop rsp; jmp [trampoline]` (also the CET fix, see Production readiness), the context rsp is the resume SP; conformance `sp_moved` 10/10 on every backend, x64 + x86
- 🔧 (#9) detach waits for in-flight agent work; agent install/stop serialized (SRW lock), no install after stop -- VM verify pending
- 🔧 (#10) re-attach reuses the agent channel; agent re-arms on init -- VM verify pending (ntdll-churn-inline)
- 🔧 (#11) every inline probe is accepted/retired before a failure is reported; (5 s hold timeout still a warning)
- 🔧 (#12) uhh_attach --flag-backend, attach test flips the flag on every backend; ✅ detach/crash multi-thread log counts: `detach-*` (4 threads; probe_close prints `probe: detached: hits= logs_written= log_dropped=` AFTER the detach; logs == hits == written, 0 dropped -- found and fixed: inline counted hits that the unhooking agent passed straight through without a callback) and `crash-logs-*-4t` (4 threads logging when the target dies; logs == hits); (x87 status word: open)
- ✅ probe_close waits for probe_run to return (warns every 15 s), never tears down underneath it
- ✅ frida_coexist hangs (found again 2026-11-05): harness rewritten (leftovers merge) -- reader thread, file output, deadlines, watchdog, tree-kill, Frida count from the exit path, waits for UHH's `active` line; 8 cases incl. inline refused / --fallback-hw / --allow-prehooked. Relocated-INT3 adoption is the integration tree's own (is_relocated_copy). Detach never leaves a hold behind (`detaching`: no new holds during the drain, late release).

## Hunter B findings (2026-11-05) — edge-case code shapes x every backend
Test: `examples/edgehunt` (target + asm shapes + ONE callback source), suite `edgehunt-*` (x64 + x86).
Each finding below was reproduced on main (d197024) by the same suite before the fix.
- ✅ (B1) breakpoint: a probe on `rep movsb/stosb` fired the callback once per ITERATION (500 hits for 5 calls; RCX
  seen counting down 99, 98, ...): the in-place step re-armed the INT3 after every iteration's trap. REP string ops
  now run out-of-line to completion ended by a trailing INT3 (no trap flag); an in-place fallback keeps stepping
  until the instruction leaves the site
- ✅ (B2) breakpoint: a probe on `syscall` (stepped in place) left the step's trap flag in R11 (the flags image the CPU
  saves); R11 is corrected at step completion
- ✅ (B3) breakpoint/hw `set_mem` into code succeeded (WriteProcessMemory silently makes PAGE_EXECUTE_READ writable)
  and modified the target's .text, where inline refuses; a range running into a PAGE_NOACCESS page was half-written
  (target-visible) and half-read. Callback memory ops now share the agent's policy: whole range committed,
  readable / writable, no guard, checked before any byte moves
- ✅ (B4) `get_mem` of code under a live probe: breakpoint returned 0xCC, inline the hook's jump bytes, hw the real
  bytes. Every backend now returns the PROGRAM's bytes (INT3 / hook bytes overlaid with the originals)
- ✅ (B5) a breakpoint/hw callback that faults (bad pointer) KILLED the controller (0xC0000005) and with it the target;
  inline abandons it. The controller now runs callbacks under SEH like the agent: hit counted, register changes
  discarded, one stderr warning, run continues
- ✅ (B6) `send_log` with a format the UCRT rejects (`%n`) fast-failed the controller (0xC0000409) or, inline, the
  TARGET; an encoding error dropped the record silently. One formatter for both sides (`include/probe_log_format.hpp`):
  invalid format or a faulting argument -> `[unformattable] <format>`, truncation marked, never fatal, never dropped
- ✅ (B7) hw + breakpoint on the SAME instruction, hw registered first: the INT3 was attributed to the hw probe (its
  callback ran again, 7 hits for 5) and the in-place "re-arm" wrote the hw probe's zero original byte into the code
  (wrong program result). INT3 lookups now only consider breakpoint probes
- ✅ (B8) breakpoint + inline on one instruction is refused (an inline hook would relocate the live INT3); the reason was
  a misleading "ret/jmp at +0x0" (the INT3 decoded as code) -- now names the breakpoint probe; site checks decode the
  program's bytes under our INT3s
- ✅ (B9) breakpoint/hw `send_log_stack` in deep recursion returned 2 frames (identical return addresses collapsed),
  inline 32. Frames with the same address but a different stack pointer are kept
- 📄 (B10) `%s` of a TARGET pointer in `send_log`: inline prints the string; breakpoint/hw callbacks run in the controller
  where it is no valid pointer -> `[unformattable] fmt %s` (was: controller crash). Callbacks must `get_mem` target strings
  into a local buffer first (the portable way); a pointer valid in both processes (system DLL data) prints on all
- 📄 (B11) UHH's own allocations in the target (scratch blocks, agent) can take an address range the program has just
  RELEASED (seen on x86: a just-freed page readable at the next probe). Programs that re-reserve a fixed address they
  freed could collide; not addressed
- 📄 (B12) Out of scope / not testable here: probes inside WOW64 thunks (x86 syscalls go through them; edgehunt's
  syscall / int 2e shapes are x64 only); `int 2e` system calls fault on this Windows build even without UHH (target
  records `int2e_ok:0`, behaviour identical); TSX (`xbegin`) and AVX-512 shapes (the VM's i5-6600 has neither); large-
  address-aware x86 targets not covered
- Verified clean (no change needed): RIP-relative load/store/compare(disp+imm)/AVX load, cpuid, rdtsc, pushf/popf, a bare
  `ret`, `call [rip+x]`, jump tables (x64 refused inline: the 3-byte `jmp [reg*8]` precedes a case label; x86's 7-byte
  form is hooked), x87, `lock cmpxchg`, 10 args at entry, a faulting load in a framed function caught by the caller's
  `__except` (inline too: the trampoline fault is still handled), one-shot probes re-added from a callback on every call,
  guard/read-only/decommitted/null/wrapping addresses, zero-size reads, hw + inline on one instruction

## Hunter A findings (2026-11-05) — concurrency / lifecycle edge cases
Driver `hunt_driver` + target `hunt_target` (`examples/hunt`): gated_config's own callbacks
(NtOpenProcess handle->pid map, every NtReadVirtualMemory logged with its pid) under a stressor;
suite `check_hunt` (`hunt-<scenario>-<backend>`; `UHH_HUNT=substr` narrows it). Clean on every
backend: thread churn (1.6k short-lived threads), thread-pool work/timers/timer-queue, fibers,
APCs, VEH + SEH filter + handler, DLL load/unload churn with a probe inside the DLL, TLS/DllMain
reads, a slow (50 ms) callback under 32 threads.
- ✅ (A1) inline: a callback whose call_func reaches the probed function (or that calls a probed
  API directly) re-entered its own callback until the stack overflowed (target died 0xC0000005).
  Now a per-thread guard: the nested hit is counted, no callback -- the breakpoint/hw call_func
  rule. `hunt-threads-recurse-*` (hits == 2 x reads, every call_func ok)
- ✅ (A2) breakpoint/hw: call_func returned 0 whenever ANOTHER thread hit a probe while a call was
  running (its callback ran nested inside the call and was refused) -- ~10% of calls at 32
  threads; the same callback source worked under inline. Now that other thread's hit is undone
  (INT3: rewound to the site; execute #DB: not yet executed) and the thread held until the call
  returns, then it hits again normally. Data-watch hits are not replayable and still run nested.
  If the callee needs a lock a held thread owns, the call times out (5 s) as before.
  `hunt-threads-tid-*` (call_func(GetCurrentThreadId) == the hit's tid), `hunt-threads-recurse-*`
- ✅ (A3) inline: process exit (return from main / ExitProcess / TerminateProcess) kills threads
  mid-callback: their hits were counted but their logs never existed and nothing said so
  (logs < hits, log_dropped 0). The in-flight counter now lives in the shared block and the report
  carries `callbacks_interrupted`; logs + log_dropped + callbacks_interrupted == hits exactly.
  Breakpoint/hw always complete callbacks (0). `hunt-exit-{return,process,terminate}-*`
  Open residual (seen in the huntaudit runs, x64 and x86, ~1 run in 8, always +1): logs +
  interrupted == hits + 1 -- a thread killed AFTER its callback published its log but BEFORE the
  agent took the callback off the in-flight count (run_callback's return .. the stripe decrement
  in call_mid) is counted as delivered AND interrupted. Not fixable by reordering (the log's
  publication and the in-flight decrement are two stores); exactness needs the accounting
  carried in the log record itself (e.g. per-thread hit sequence numbers in the records and the
  in-flight word, reconciled by the controller at exit). hunt-exit-*-inline flake by one.
  runfix1 (protocol 23: the log carry per hit, a separate running count) is that design.
- ✅ (A4) breakpoint/hw + a target that round-trips its own threads' contexts (SuspendThread +
  GetThreadContext + SetThreadContext, as GCs/profilers do): a context captured while the thread
  sat in a UHH debug event and written back after UHH resumed it undid UHH's fix-up (breakpoint:
  the trap state pc = site+1 resumed one byte into the instruction; hw: RF clear, the same call
  reported twice). Earlier partial fixes stay (jump back after every displaced copy, stray TF in
  our scratch swallowed, a #DB at our execute address with DR6 overwritten recovered as ours).
  Fixed (huntaudit): (1) at every exception event UHH checks whether the TARGET has the thread
  suspended (its suspend count exceeds UHH's own suspensions; measured with SuspendThread --
  NtQueryInformationThread(ThreadSuspendCount) reads one higher at a debug event). If so it keeps
  the context of the event (before) and the one it resumes with (after), holds the thread with
  one suspension of its own until the target has resumed it, and then re-applies its changes to
  whatever the target wrote back, per register: a field still at its trap value gets UHH's, a
  field the target set itself keeps the target's (exact for a plain write-back); debug registers
  are not merged but rewritten from the CURRENT probe state by enforce_owned_drs -- the one place
  that re-applies DRs, as at NtContinue (cfnest's restore_fixup). Re-checked after
  the repair: a thread the target suspended again meanwhile stays held. (2) hw execute hits no
  longer resume at the site with RF (RF only lives until the instruction ran, and a round-trip in
  that window comes back without it): they resume in the site's displaced trampoline (A5), whose
  copy is checked against the live code at every hit; non-displaceable sites keep RF.
  `hunt-ctx-{breakpoint,hw,inline}` (3000 round-trips under 2 hammering readers: hits == reads)
- ✅ (A5) breakpoint/hw starvation: every debug event freezes the whole process, so with 8 threads
  hitting a probe back to back, a thread that hits nothing ran only in the gaps (main's
  Sleep(300)+exit took 4 s typically, >180 s in ~1 of 6 runs). Fixed (huntaudit): (1) one event per
  breakpoint hit instead of two: a displaceable site resumes in a per-site TRAMPOLINE (`insn;
  jmp site+len`, RIP-relative operand retargeted, shared by all threads, built once near the site)
  with no trap flag, so there is no single-step completion event; a fault in the copy is mapped
  back to the real instruction (re-run in place, as before), a watch hit in it reports the real
  pc, a thread inside one at a detach is moved to the real code. A program that single-steps
  itself (TF set at the hit) keeps the stepped copy. (2) fairness by YIELD rounds: when debug
  events are dense (>= 2000/s) or the target ran unfrozen for less than a tenth of the last
  20 ms, each thread whose hit is continued in the next window is sent once through a per-thread
  yield stub (registers, flags, XMM saved; ntdll!NtDelayExecution until a deadline common to the
  round, ~4 ms; everything restored; a jump to where it was going), so the hot threads are off
  the CPU together for a moment and the threads that hit nothing run. Not done: CET shadow
  stacks, a program that probes NtDelayExecution itself, a thread mid-step / in a call. A first
  version SUSPENDED the hot threads instead -- a thread suspended inside its debug event keeps
  the whole target frozen until it runs again, so main's Sleep(300) still returned 3-20 s late
  (measured once main's own progress was measured, below). Detach rewrites a sleeping thread's
  resume address out of a trampoline. `hunt-starve-*` (8 readers; judged in a unit machine load
  does not distort: the probe hits the session handled between main's Sleep(300) falling due and
  main running again, counted by the target -- yield rounds 1.5k-6.5k, suspension parking
  45k-234k; bar 20000; wall time reported; logs + dropped + interrupted
== hits); the exit checks now use 8 readers on every backend
- ✅ (A6) inline missed calls made BEFORE the image entry point (TLS callbacks at process attach,
  static-import DllMain): the agent was loaded by a new thread, which cannot start before process
  initialisation ends, so hooks went in at the entry hold. Fixed (huntaudit): a launched target's
  MAIN thread loads the agent itself at the loader breakpoint (static imports mapped, no
  initialiser run yet) and runs probe_agent_init there (call_in_target, as call_func does; 60 s
  bound): the hooks are in before the first TLS callback / DllMain. The agent's PROBE_IPC
  requests (its hook-write freeze) are serviced during that call, probes it hits are not
  counted (the library's own work), and init does not wait for its service thread (agent
  protocol v24 `early_init`: that thread starts once process init ends and reports ready then;
  the entry hold waits for it as before). Falls back to the old remote-thread load on CET shadow
  stacks or if the call fails before loading. In gated_config terms an NtOpenProcess in a TLS
  callback is now mapped. `hunt-early-{inline,hw,breakpoint}`
- ✅ (A7) hw: the target arming its OWN debug registers shared DR0-3 with UHH's hardware probes and
  lost its own breakpoint (UHH's CREATE_THREAD write replaced the DR0 the program set on a thread
  it created suspended). Fixed (huntaudit): UHH records every address it ever put in a DR; an
  enabled slot of UHH's holding any other address was written by the program. Checked at
  CREATE_THREAD, at the thread-start fixup, at the entry re-apply and at every #DB (before the
  #DB is attributed): the probe moves to a slot no thread of the target uses, on every thread
  (the program's value kept where it has one), and the #DB of the program's own slot goes to the
  program. With no free slot UHH's probe yields on that thread (a warning; its hits there are not
  seen) -- never the program's breakpoint. Writers never overwrite such a slot. A DR the program
  sets on a running thread is seen at that thread's next debug event (UHH does not intercept
  SetThreadContext). `hunt-owndr-*` (DR0 set on a suspended new thread), `hunt-owndr-live-*`
  (DR0 set over UHH's on a running thread)
- ✅ (A8) hw: a hardware probe inside a DLL that 4 threads keep LoadLibrary/FreeLibrary-ing missed
  hits (60-125 of 240, "whole threads"). Proven cause (huntaudit): NOT the late UNLOAD suspected
  here -- with the stale-unload guard of 6d0147a disabled, 24 runs (x64 + x86) saw no late unload
  at all and were exact. The probe is (re)armed at the DLL's LOAD while other threads of the
  target are still in their loader initialisation (DLL_THREAD_ATTACH, TLS callbacks); such a
  thread resumes at ntdll!RtlUserThreadStart through LdrInitializeThunk's NtContinue with the
  debug registers captured when it was created, i.e. WITHOUT the new probe, and misses it until
  the next re-arm -- the DLL really unloads only a few times per run (3-6 loads in 240 calls), so
  that is most of the thread's calls. Evidence, x86, hunt_driver --work-backend hw dll --n 60: the
  A8 commit 9b045a6 missed hits in 4 of 14 runs (134, 65, 182, 180 of 240); the same commit plus
  e2cbfc5 alone (re-apply the hardware probes at ntdll!RtlUserThreadStart -- merged into
  merge-frida before the hunt suite was) 10 of 10 exact; the current code exact in every run of
  this audit (hunt-dll-work-backend-hw 3 x86 + 3 x64 suite runs, plus 24 direct runs).
  Defensive completion (huntaudit): should a LOAD of a new instance ever arrive before the UNLOAD
  of the old one at the same base (the case the guard handles; never observed in this audit), a
  breakpoint/inline probe still marked active there is re-armed in the fresh mapping, which has
  neither the INT3 nor the hook (hw: the DR is per address and stays). `hunt-dll-work-backend-*`
  Follow-up (huntaudit, after the merge): the same loss hit the INLINE probe in the reloaded DLL
  (hunt-dll-work-backend-inline, x86, once in a suite run; under load with tracing 20 of 180
  runs, 1-5 of 240 calls): its install GATE (a debug register on the pending site until the hook
  is in, arm_gates_for_pending) was wiped on a thread still starting (or inside an NtContinue
  restore), which then ran the site unhooked and uncaught. Gates are now re-applied by the
  thread-start and context-restore fixups like hardware probes (armed when a gate is), and
  enforce_owned_drs treats a gate's slot as owned. Reproduced on demand (x86, 6 parallel loops
  x 30 runs, PROBE_TRACE on, CPU burners: 20/180 runs missed calls) and fixed layer by layer --
  (1) gates re-applied as above (and a gate image a context record brings back after the gate
  was cleared, or its #DB still queued, is recognised as ours: it crashed the target with an
  unhandled single step once gates were re-applied); (2) an install round that made no progress
  (a relocated DLL's code is not executable until the loader has relocated it) is retried in
  5 ms instead of at once -- the immediate re-kick spun the agent, each round an event freezing
  the target, and starved the relocating thread into the 5 s install timeout; (3) a LOAD of a
  new instance while the old one's UNLOAD is still unreported: an old instance whose image is
  gone is torn down at that LOAD (its late UNLOAD skipped), and a late UNLOAD re-arms the
  module's newest instance; (4) two instances mapped at once (the old one still unmapping, the
  new one already called by another thread; or a mapping the loader discards): every other
  instance's copy of an inline site is gated, and a thread hitting one moves the probe to that
  live instance; a probe whose own copy never becomes code moves to an instance where it is.
  After all four: 180/180 runs exact under the same load.
- ✅ (A9, found in this audit) breakpoint: an instruction at a probe site that faults (a guard
  page, an access violation the program catches) is re-run at the real address so the program
  sees its own fault there; the thread's next arrival at the site was then ALWAYS taken for the
  handler retrying that execution (no hit, no callback) -- so a NEW call after an `__except`
  (IsBadReadPtr-style probing, a second call from the same call site) lost its hit and its log
  (hunt-guard-breakpoint: 50 of 100 hits, both arches). huntaudit first fixed it by watching the
  thread's context restores with per-thread debug registers; the integration branch meanwhile
  fixed the same hole independently (codex2-fixes, `fault_retried`: the exception's dispatcher
  frame below the faulting SP tells a retry from a fresh execution, no debug register needed),
  so the merge keeps that one and drops the watch. `hunt-guard-*` (one call site twice, a
  retry, a plain call: 4 hits, 3 guard violations per round) checks it on every backend. Also
  found here (Codex review): a displaced trampoline is reused only for the same instruction
  bytes (a DLL rebuilt at the same base: `hunt-twin-*`, x86 bad=30 before); a faulting trampoline
  copy of a HARDWARE probe re-arms the consumed guard page before the re-run (the program never
  saw its guard violation: hunt-guard-hw bad=51 before)

## Codex workaround audit (2026-11-05) — triaged
- ✗ (C1) handle->pid through kernel32!OpenProcess: example-callback design, not a library issue (user, 2026-11-05); documented in the gated_config README
- ✅ (C11) example handle map: no silent 1024 cap -- direct UHH_SHARED table indexed by handle>>2 (collisions overwrite) + ring of pending opens resolved lazily; test `handle-map-*` (5000 decoy opens with reused handle values, then the helpers; unmapped == 0, all backends + mixed)
- 🔧 (C3) attach holds every thread until inline hooks are confirmed (implemented); attach test without the gate pending
- 🔧 (C12) runtime inline add holds the calling thread until the hook lands (implemented); drop the 300 ms sleeps in conformance/dynwatch pending
- 🔧 (C4) uhh_trace: exact backend unless --fallback-hw (done); realworld matrix asserts the effective backend (done); remaining tests audited as they are touched
- ✅ (C5/C8) docs: logging-plan.md marked superseded with the lossless contract; README/probe_app comments on the ntdll stubs
- 🔧 (C14/C15) suite: missing binaries FAIL, skips not counted as passes (done); release runs pass --volume-reads; streaming adds 20M-log tests
- 🔧 (C9) detach test on ntdll stub, synchronized on 'probe: active', no sleep -- VM verify pending
- ✅ (C13) PROBE_AT_RETURN: deliberately not a feature (user, 2026-11-05) -- return points are hooked naturally: read the return address at entry and probe_add_address it from the callback; documented in probe_api.h. (Optional: delete the flag -- API change, user's call)
- ✅ (C16) breakage inline rows: every row has one required outcome (`pass` = exact uninstrumented behaviour, or `refused` with a reason, no hit, target uncorrupted); the driver fails on any other; uninstrumented baselines asserted. Found and fixed: an inline hook over a rel8-only branch (jrcxz/jecxz/loop*) crashed the target -> refused (`[reloc]`); two inline probes whose patches overlap (same address included) -> refused (or hw with PROBE_FALLBACK_HW)
- ✅ (C20) attach_new: `attach-new-{breakpoint,hw,inline}` on ntdll!NtReadVirtualMemory; no sleeps (decoy's gate line, tracer's 'probe: waiting for a new' and 'probe: active' lines). The target gate stays: attach_new polls, so reads could otherwise precede the attach
- ✅ (C6) anti-tamper/anti-debug: targets take a different path on detection (probed function called with -1); asserted per backend vs an uninstrumented baseline (`antitamper-*`, `antidebug-*`); per-backend visibility documented in examples/realworld/README.md (INT3/inline: code bytes vs disk; hw: DR7 only; debugger visible under every backend -- not hidden)
- ⬜ (C7) Shared state across backends -- `UHH_SHARED` (user-approved 2026-11-05). Default stays "probes that share state use one backend". Opt-in: globals marked `UHH_SHARED` live in a shared PE section (`/SECTION:uhhshr,RWS`) of the callbacks DLL; the controller runs breakpoint/hw callbacks from ITS copy of that same DLL file and the target runs inline callbacks from its copy, so both see the same physical pages with plain native access. Per-session copy of the DLL (unique path) so separate sessions never share; deleted at close. Rules: no pointers in shared state (bases differ), constant/zero init only, lock-free atomics for sync. Only enabled when the DLL actually has the section (no behaviour change otherwise).
  - ✅ test: gated_config with MIXED backends builds one handle->pid map; all reads attributed -- `gated-e2e-*` (every flag/open/close/read backend assignment, launch + attach before/after the config parse, exact per-thread ground truth from the target; see "E2E gated_config evaluator findings"), plus `shared-mix-*`
  - ⬜ benchmark: per-hit cost with UHH_SHARED state vs plain globals, every backend -- must be equal
- ⬜ Log sink speed (simple): UHH logs/s to NUL vs a plain writer's rate into a file; one manual console run. Bar: UHH is never the bottleneck.
- ✗ (C10) helpers in probe_app: requested by the user; (C18) asm configparse: deliberate stable symbol+offset (add a PDB-local compiled variant later); (C19) _NT_SYMBOL_PATH is the requested symbol mechanism (tests may clear it)

## Frida-replica findings (examples/famous, 2026-11-05)
Classic Frida / API Monitor / Procmon recipes re-done on UHH (`examples/famous`: heap
tracker, file monitor incl. attach mid-run and real findstr/cmd, TLS plaintext from the real
curl.exe, loader/RWX watcher, return-value override), each one callback source under
breakpoint/hw/inline on x64+x86, compared with the uninstrumented run (`regress.py --only famous`).
- ✅ (F1) HW: a hardware probe armed at RUNTIME (from a callback, or at a later DLL load) was lost for whole threads still in loader initialisation: thread start ends in NtContinue with the creation-time context, debug registers included (the initial-thread entry fixup's mechanism, for every other thread). Found by `famous-retval-hw` (return-site probes added while workers start: whole workers 0/25 overridden). Fix: library-owned INT3 at `ntdll!RtlUserThreadStart` (armed the first time a hw probe is armed after entry/attach) re-applies the active DRs to each arriving thread. Test: `famous-retval-hw` x3 (+ 8/8 manual)
- ✅ (F2) HW: target killed by STATUS_SINGLE_STEP. Arming a hw probe writes every thread's debug registers -- DR6 included -- and on a thread whose #DB is still waiting to be reported that zeroes the B-bit, so the hit looked foreign and was passed to the target. Fix: a #DB with no B-bit exactly at an active, enabled hw EXECUTE probe is that probe's hit (`hw-dr6-lost` under PROBE_TRACE). Test: `famous-retval-hw`. The same lost bit on a data WATCHPOINT: fixed by H2 (status kept across our DR writes)
- ✅ (F3) Inline: target died (STATUS_STACK_OVERFLOW, "probe_agent_init failed 0xC000041D") in ~half of short runs of an inline `RtlAllocateHeap` probe whose callback calls `call_func`: (a) the agent's thread_local region cache was touched before a starting thread had TLS (LdrpInitializeThread allocates it through the probed allocator) -> AV; (b) allocations inside call_func's own resolution/callee hit the probe again -> unbounded recursion. Fix: TLS presence checked (no cache until then); inline call_func now suppresses callbacks on its own thread for its duration -- the documented contract the breakpoint/hw path already kept. Test: `famous-heap-inline-reentry` (12 runs)
- ✅ (F4) Same NtContinue/RtlRestoreContext wipe class: a thread inside exception dispatch (an exception filter, a vectored handler) or inside a user APC when a hw probe is armed resumed through NtContinue with the context the kernel captured BEFORE the arm -- debug registers included -- and missed that probe (reproduced: `hw-dr-restore` exception 9/10, APC 9/10 before the fix, x64). Fix (builds on hwonce's thread-start mechanism): library-owned INT3s at `ntdll!NtContinue` / `NtContinueEx` (armed with the thread-start fixup: once a hw probe is armed or released at runtime) bring the DR image of the context about to be restored up to date: our ACTIVE probes' slots re-asserted, nothing else touched (an exception handler may arm the program's own DR in that record, even at an address we watched once and released: `cdx-owndrx` caught a first version that cleared released images there; a stale image of a released probe is recognised at the thread's next #DB by hwonce's per-thread logic). x86: a WOW64 user APC's 32-bit record carries no debug registers (flags 0x10003) and the 64-bit layer restores its own copy, out of a 32-bit debugger's reach -- there the fixup points the record's EIP at the library's private INT3 (`call_trap`), re-applies the DRs there and resumes the thread at its real EIP, so even its first instruction sees them (Codex review 2: a first version re-applied them by trap flag AFTER that instruction; `hw-dr-restore-first` arms a hw probe exactly at the APC thread's resume site). A breakpoint/hw call_original that borrowed its hw probe's own slot for the return catch keeps it on its thread through such a restore (Codex review: an exception continued inside the original lost the return; `enforce_owned_drs` skips it). Cost while armed: one INT3 + step per NtContinue (exceptions, APCs, thread starts). Tests: `hw-dr-restore` (exception 0/10, APC 0/10 before; 30/30 after), `hw-co-borrow-restore`
- ✅ (F5) `call_func` from a breakpoint/hw callback returned 0 while another thread's callback was inside one. Fixed with D3 (callback fibers; see there). famous_common.h's PE-header fallback is no longer needed for this but kept (harmless)
- ✗ (F6) HW budget: a recipe needing one return probe per call site exceeds the 4 debug registers when unfiltered (NtCreateFile is called from several KernelBase sites, CreateDirectory among them) -> clean `too many hardware probes` refusal. By design; the recipe's Procmon-style `--filter` keeps it to one site. Documented in the recipe README
- ✗ (F7) Observer effect: with inline probes, writing a hook makes the patched bytes PAGE_EXECUTE_READWRITE through the target's own NtProtectVirtualMemory (seen by an RWX watcher installed earlier: `rwx-protect size=0x8` in KernelBase); breakpoint/hw patch from the controller and are invisible. Documented (loader_rwx README)
- ✅ (F8, fixed with D2: a launched target writing to a pipe/file gets its own pipe, forwarded line-wise; regress `stdout-*`) The live log tail shares the target's inherited stdout: a target writing partial lines (cmd `type`) interleaves with tail lines mid-line, corrupting both for a line-based reader. The session JSONL file is unaffected (the famous checks read logs from it). Options: document; or tail to stderr/another handle when the target inherits stdout

## Detours-replica findings (examples/famous/detours_*, 2026-11-05)
Replicas of Microsoft Detours' simple / traceapi / withdll / retval samples on real system
binaries (cmd, reg, sort), multi-threaded targets, launch vs attach, attach mid-run + detach,
9 probes at once and mixed backends. Everything else matched the uninstrumented runs exactly.
- ✅ (D1, fixed: the target now inherits the caller's stdin; regress feeds keystrokes at the harness) **probe_launch replaced the program's stdin.** The child gets a private pipe, UHH writes
  one "gate keystroke" (`\n`) into it and keeps the write end open until probe_close. A filter
  program (`sort`, `findstr`, `more`, anything reading stdin to EOF) **hangs forever** under every
  backend, and a program reading a line gets a `\n` it was never sent. Detours' withdll passes the
  caller's handles through. The keystroke exists for probe_app's gate, so changing it touches the
  gated_config flow (not a contained fix -- user's call: e.g. inherit stdin by default and make the
  gate keystroke opt-in, or forward the controller's stdin after the keystroke and close at EOF).
  Test: `detours-launch-stdin-*` (FAILS today: hang).
- ✅ (D2, fixed: when the controller's stdout/stderr is a pipe or a file, probe_launch gives the
  target its own pipe(s) and a forwarder thread copies the bytes out a complete line at a time;
  log records are written only at a line boundary -- while the target sits inside an unfinished
  line (partial flushed after ~50 ms idle) they stay in the log file and are replayed at its
  next newline, so the writer never blocks on the target. 2>&1 shares one pipe (order kept). A
  console stays inherited (interactive targets keep GetConsoleMode). Grandchildren holding the
  pipe: drained with a bounded wait at target exit. Only exception: a target that ENDS inside
  a line with records still to follow gets a "\n" before them. `dt_split` now splits whole
  lines only; regress `stdout-*`) **Live log tail splices records into the target's own stdout lines.** The child inherits
  the controller's stdout; records are written whole, but a target that writes partial lines
  (reg.exe writes `ProductName` and the padding separately; unbuffered UCRT stdout writes one
  character per WriteFile) gets `{"kind":"probe_log",...}` inserted mid-line, so its output as read
  from the controller's stdout is altered (and line-based consumers lose records). The log FILE is
  intact. No way to separate the two streams through the API today (stdout to NUL hides the
  target's output too). Workaround in the suite: `dt_split` cuts records back out of the line they
  landed in. Options: a separate tail handle/stream, or giving the child its own stdout pipe that
  the controller forwards line-wise.
- ✅ (D3) **call_func from a breakpoint/hw callback fails while another thread's call_func is in
  flight.** FIXED (cfnest). Two parts: (1) Hunter A's policy (other threads' code-probe hits are
  rewound + held during a call and replayed after it) already serialised most calls; kept as
  the documented contract -- breakpoint/hw callbacks never overlap, so a callback may hold its own
  lock across call_func (B3). (2) Hits that cannot be held back (a data watch, a thread mid-step)
  still ran their callback during the call, and its call_func returned 0 ("no nesting"). Now
  every exception event is handled on a fiber of the debug thread: a callback waiting in
  call_func parks its fiber (its event continued), the loop that resumed it dispatches on, and
  the callee's trap / fault / 5 s timeout / thread or process end resumes it (`service_event`,
  `poll_calls`); those calls overlap and finish in any order. Also: a timed-out callee's thread
  stays suspended until its callback's handling ends (its register changes used to be written
  into an already-resumed thread). Considered and REJECTED (Codex review): letting held hits run
  once a callee is seen blocked (it fixed "the callee needs a lock a held thread owns", but a
  callback holding a lock across that call_func and a second callback taking it deadlock the
  debug thread -- it broke the documented never-overlap contract). That case stays the
  documented 5 s timeout (limitations.md; owner: no hardening). Codex review 2 of the branch:
  (a) a data-watch hit, which cannot be rewound, still ran its callback while another one was
  parked in call_func -- a lock held across that call_func and taken by the watch callback hung
  the debug thread; now the watch's thread is held right after its access (status bits kept via
  hwonce's dr6_lost carry) and its callback replayed, call_func included, once no call is in
  flight (`hold_watch_hit`, `replay_held_watches`): callbacks are strictly serialised (one corner
  documented: a hit on a thread mid single-step); (b) a call that timed out while its return
  trap (or a callee fault) was already queued passed that late event to the target as an
  unknown breakpoint -- now recognised and swallowed (`call_late`; forced deterministically
  by the UHH_TEST_LATE_TRAP test hook); (c) WOW64-form trap codes are normalised before the
  call_func checks (not reachable in this setup: same-bitness only, native codes seen).
  Tests: `callfunc-watch-lock-{bp,hw}`, `callfunc-late-trap-{bp,hw}` (ar_driver_th), and `callfunc-many-{bp,hw}`
  (100 threads, every call ok), `callfunc-watch-{bp,hw,inline}` (a watch callback's call_func
  during another thread's call: returned 0 before), `callfunc-lock-inline` (the inline
  reference), `sessions-repeat`. Original finding: The "no nesting" guard (`in_call_tid`) is session-wide: during thread A's call the
  debug loop dispatches thread B's events, B's callback calls call_func -> returns 0. With
  return-value probes on 4 threads (GetLastError via call_func at every CreateFileW return) this
  happens in practice. Inline is unaffected. Clean failure (returns 0), but surprising: the doc
  says "other threads keep running" without saying their callbacks cannot call_func meanwhile.
  Test: `detours-retval-callfunc-{breakpoint,hw}` (intermittent: 0-2 of 36 refused per run, seen
  on x64 and x86, both backends). Relates to (#6) (hardening not pursued). A fix would need either
  a nested-call stack in `call_in_target` (an outer call's trap arriving inside the inner wait
  must be recorded, its thread restored and suspended, and the outer told not to continue it) or
  suspending the other threads during a call (changes the documented "other threads keep running").
- ✅ (D4) **A hw probe armed from a callback never fired on threads that were hitting a probe at
  the same moment.** hw entry probe on CreateFileW, return-address probe added (hw) from the
  first entry callback; 4 threads start together: 18/36 and 27/36 returns seen, every miss on
  the 1-2 threads whose own entry #DB was queued while the DR was written (their entries all
  trapped). The SetThreadContext from `arm_hw` to a thread whose debug event is still queued
  behind the one being handled does not stick. Fix: `handle_hw` re-asserts every slot the
  session owns (address + DR7 bits; released slots cleared) in the context it writes back at the
  thread's own event (`enforce_owned_drs`; logs "repaired hardware breakpoint state").
  `detours-retval-hw` 36/36 since. (Still open in principle for a thread whose queued event is
  not a hw hit, e.g. a software breakpoint in a mixed session: those paths write CONTEXT_FULL
  and do not re-assert DRs.)
- ✅ (D5) REPRODUCED and fixed: an inline probe added by address at a return site followed by a
  loop head (ar_target absret, hand-assembled in .text) was hooked and the target died
  (0xC000001D). The site check now analyses the image mapped around the address
  (`image_base_of`), and the no-bounds block walk runs for any site (also non-image code).
  Tests: `inline-absolute-refused` (refused, result unchanged), `inline-absolute-fallback`
  (PROBE_FALLBACK_HW -> hw). Original note: absolute-address inline probes (`probe_add_address(...,
  PROBE_INLINE)`, e.g. a return site) are vetted with `base == 0`, which skips the function-bounds /
  branch-target part of the inline site check (`analyse_site` and the block walk both need a base):
  only the exit and call-inside-patch rules apply. A return site followed within 5 bytes by a jump
  target (a loop head right after a call) would be hooked without a warning.
- ✅ No issue: launch vs attach traces are identical (minus pre-attach work), detach mid-run on 4
  busy threads leaves the target correct on every backend, 9 probes in one session (breakpoint/hw/
  inline mixed), `kernel32` import-stub sites (`jmp [imp]` + padding) inline-hooked fine, APC-
  interrupted alertable SleepEx unchanged, GetLastError via call_func exact on inline.
## Blog-replica findings (2026-11-05, `examples/blogs`, regress `blog-*`)
Well-known instrumentation scenarios (crypto-API monitor, registry Run-key monitor,
DNS/socket logger, process-creation tracker, COM CLSID logger, 1 kHz game loop, attach to
PowerShell + detach) under every backend, against an uninstrumented baseline.
- ✅ (B1) hw: a #DB queued on one thread while another thread's callback armed a new DR
  (a return probe added from a callback) arrived with DR6 == 0 and was passed to the
  target -> **target killed by STATUS_SINGLE_STEP**. A #DB with empty DR6 at the address
  of a live execute probe enabled on that thread is now treated as that probe's hit.
  Test: `blog-crypto-naive-hw` (6 rounds), `blog-crypto-hw`
- ✅ (B2) hw: a DR armed while a thread was between CREATE_THREAD and the end of its
  start-up (LdrInitializeThunk's NtContinue restores the creation-time DR image) was
  **silently lost on that thread for its lifetime** (crypto: one worker never hit the
  runtime return probe, 100/120). Library INT3 at ntdll!RtlUserThreadStart, armed only
  once a hw probe is armed after start-up while such threads exist, re-applies the DRs.
  Test: `blog-crypto-naive-hw` (asserts every return captured), `blog-crypto-hw`
- ✅ (B3) breakpoint/hw `call_func`: another thread's probe hit during the call ran its
  callback NESTED on the controller thread -> a callback holding a lock across
  `call_func` **deadlocked** (registry monitor: NtSetValueKey -> call_func NtQueryKey hung
  on breakpoint and hw), and a nested `call_func` was refused. Other threads' code-probe
  hits are now parked (rewound + suspended) until the call returns, then re-hit.
  Test: `blog-registry-breakpoint/hw`
- ✅ (B4) a forwarded export whose target module maps after the forwarding module
  (`ole32!CoCreateInstance` -> combase) **failed the launch**; it now stays pending on the
  target module. Also the inline pre-vet of such a name checked the module header
  (base+0). Test: `blog-com-*`
- ✅ (B5) attach + inline into a CLR process (PowerShell) / x86 `attach-inline`: holds that
  lasted until the 5 s install timeout (seen: hits=0, "released 19 held thread(s) (detach)";
  x86 attach-inline once 0/8000 reads after "inline install not confirmed within 5 s" on the
  configparse LOAD_DLL hold). The thread holds during injection were already gone (attach
  holds nothing while the agent loads); the remaining cause was the CC8 root cause below --
  the agent's service thread was reported ready before it had run, so a LOAD_DLL hold could
  wait on a thread still in its loader init. Fixed with CC8. Tests: `attach-*`,
  `blog-pwsh-attach-detach-*` (x64 + x86 green after the fix; `attach` 4/4 repeats on x86).
- (note) `attach-new` failed once because ANOTHER agent's probe_app.exe started in the
  same second on the shared VM and was attached instead (image-name matching is
  inherently racy on a shared box; not a library bug).
- ⬜ (B6) API reality the docs should mention: `bcrypt!BCryptGenRandom` re-enters itself
  (2 hits per call), so entry counts != API calls and a naive return-capture needs a 5th
  hw slot; probes report every caller of a system export (CoCreateInstance 25 hits for 24
  target calls). The examples filter; the per-backend limitations doc should say so.
- ⬜ (B7) docs: per-hit cost seen as frame time at 1 kHz (`blog-game-*`, x64 VM): inline
  p50 1 us / p99 10 us, 0 missed frames; hw p50 ~220 us / p99 ~520 us, breakpoint p50
  ~300 us / p99 ~660 us, a few frames over budget -- belongs in the backend table.

## Code review of the 2026-11-05 merges (fresh-eyes reviewer)
- ✅ Console close/logoff/shutdown during a session: the handler now holds until probe_run has let go
  of the target (was: tool killed with INT3s/DRs/hooks still live -> target died at its next hit)
- ✅ gated_config mapped a REUSED handle value (CreateProcess hProcess, DuplicateHandle, inherited)
  to the pid opened under it before: ntdll!NtClose now clears the slot (forget_closed_handle)
- ✅ In-place re-arm / displaced-fault restore wrote without checking the byte (could land on another
  tool's hook written meanwhile): compare-before-write now
- ✅ A relocated INT3 whose adoption failed was passed to the target as unhandled: now rewound
- ✅ (call_original hunter) breakpoint/hw counted the call_original pass-through as a second hit;
  inline call_original swallowed the original's exceptions -- see "call_original findings"
- ✅ Accounting edge (closed 2026-11-06, runfix1, agent v23): a callback killed by process exit AFTER
  publishing its log but BEFORE returning was reported both as a delivered log and in
  callbacks_interrupted (seen on CI runners: 3 of 36 crash-logs-inline-4t runs). Now the callback's
  first record carries the hit's unaccounted unit (one store: the ring's seq) and the controller retires
  it when it takes the record, so hits == logs + dropped + interrupted exactly (see "Runner findings").
## call_original findings (2026-11-05, `examples/hunt_callorig`, regress `callorig-hunt-*`)
Edge-case hunt on `call_original` / `return_from`, every backend x x64/x86, each run compared
with the uninstrumented target and with exact hits / "co" logs / `log_dropped == 0`.
- ✅ (CO1) **breakpoint/hw counted call_original's own entry as a hit** (N calls -> 2N hits, inline
  N; broke logs+dropped+interrupted == hits). The call now starts with RF set (hw) / passes the
  entry INT3 once without counting (breakpoint). Test: `callorig-hunt-recurse-*` (exact 40 hits).
- ✅ (CO2) **inline call_original swallowed the original's exceptions** (`__except(EXECUTE_HANDLER)`
  around the call): the C++ throw / SEH raise / AV never reached the program's handler, the
  callback got 0 and the hit fell through, running the original a SECOND time. Breakpoint/hw
  abandoned the call and re-ran it from the hit too, and a longjmp out of the original left the
  controller waiting 5 s and then RESET the thread to the hit (x64: the unwind through the
  fake call_trap return address could not even work). Now, on every backend, an exception or
  longjmp out of the original goes to the program's own handler exactly as without the probe,
  the body runs once, and the rest of the callback is abandoned (Detours semantics):
  inline x64 calls the trampoline from `uhh_orig_thunk` (agent_x64.asm) whose unwind data is a
  machine frame + the hit's nonvolatiles, so the unwinder steps straight to the hooked
  function's caller; inline x86 relinks the SEH chain past the callback for the call; both
  settle the hit's bookkeeping (in-flight count, re-entry flag) when the unwind passes.
  Breakpoint/hw run the original IN PLACE (hit's own stack, real return address) and catch its
  return with a debug register set on that thread only; a thread seen above the hit's frame
  without having returned (poll, or a probe hit there) releases the call. Tests:
  `callorig-hunt-{cppthrow,seh,longjmp}-*` (the same thread's later probes still fire).
- ✅ (CO3) **return_from / call_original from a non-entry probe** returned through a saved register
  (`push rbx` -> ret to rbx). Both are now refused (warned once) unless [SP] at the hit is a
  return address (the bytes before it encode a CALL). Test: `callorig-hunt-mid-*`.
- ✅ (CO4) **breakpoint/hw call_original past 5 s RESET the thread to the hit** while the original
  was still running (a blocked read, a long wait): its partial effects were then repeated. The
  call is now released instead (the original runs on to its real caller; the callback ends).
- ✅ (CO5) breakpoint/hw call_original is no longer refused under CET shadow stacks (nothing on the
  stack is rewritten any more).
- ✅ (CO6, leftovers merge) all 4 debug registers taken by hw probes refused EVERY call_original --
  gated_config with every probe on hw (flag, NtOpenProcess, NtClose, NtReadVirtualMemory) mapped no
  handle (`mix flag=hw read=hw` unmapped=8000, `attach-hw`, `interrupt-detach-hw`, `cet-gated-hw`).
  A hw execute probe now lends its own slot on the hit thread for the call (re-pointed at the
  return address, restored after); only a recursive entry on that thread goes uncounted.
- Limits (documented in probe_api.h): breakpoint/hw call_original needs one free debug register
  for the call (all 4 taken by hw probes -> refused, unless the hit is itself a hw execute probe,
  which lends its own slot, as probe_api.h now says); probes hit inside the original count but
  run no callback when they are of the same kind as the caller (inline in inline,
  breakpoint/hw in breakpoint/hw -- including this probe for a recursive function), and fire
  when of the other kind; inline needs nargs >= the real argument count (it builds a new frame;
  breakpoint/hw run in place and ignore it); x86 return_from nargs = the callee's STACK
  arguments (fastcall: after the first two, thiscall: after `this`); set_reg of nonvolatile
  registers before call_original reaches the original on breakpoint/hw only; the abandoned
  rest of a callback does not destroy its C++ locals; an exception the original handles
  INTERNALLY is invisible on every backend (call_original returns normally). Detach /
  Ctrl+Break while a call_original is in flight complete that call first (`callorig-hunt-
  {detach,ctrlbreak}-*`).

## Agent review findings (2026-11-05, static review of the inline agent; regress `agent-*`, `examples/agent_review`)
- [x] **(HIGH) Exceptions through a relocated `call` (x64).** A probe whose patch ends in a `call` copied that call verbatim into the trampoline, so the callee returned INTO the trampoline -- no unwind data there (and not the hooked function), so a C++ throw / SEH exception from the callee caught by the hooked function or its callers was never found (std::terminate / unhandled). Fix (SafetyHook patch step 5, `uhh_relocate_call_as_jmp`): such a call is relocated as `push <site+len>; jmp <callee>` (call rel32 and call r/m not addressing through rsp/esp), so the callee returns to the hooked function itself; correct unwind, the function's own handlers, `_ReturnAddress`, stack walks; x86 `call $+5; pop` PIC thunks now get the original address too. Under CET shadow stacks (a pushed return address is a #CP) the agent sets `uhh_safetyhook_keep_calls` and the call stays verbatim -- known limit there. Reproduced x64 (target died 0xE06D7363 at the first throw); x86 was already correct (frame-based SEH). `agent-unwind`.
- [x] **Faulting instruction relocated into the trampoline** (e.g. a load inside the hooked function's own `__try`, x64 scope tables are looked up by RIP). The agent's first vectored handler RE-RAISES such a fault (NtRaiseException) at the original instruction it stands for (registers are identical: the copy did not execute) -- editing the CONTEXT in place is not enough, the dispatcher's machine frame keeps the trampoline RIP and the unwind ended in STATUS_BAD_STACK (seen); a vectored continue handler moves a resumed fault back into the trampoline. Reproduced x64. `agent-unwind` (`load`).
- [x] **Callback faults after `call_original`** returned early, before the return_from handling: the original ran a SECOND time on fall-through (double free/close). Now the hooked function returns with return_from's value, else the original's own result (x86: the callee's `ret N` is measured by call_original). Reproduced x64 + x86 (body ran 20x for 10 calls). `agent-faultafter`.
- [x] **Re-entrancy guard needed TLS.** A hit during LdrpInitializeThread (no TLS yet) had no guard: an allocating callback on RtlAllocateHeap recursed until the stack overflowed. The guard is now a TLS-free per-thread table (thread id -> running hit). Reproduced x64 (0xC00000FD) + x86 (0xC0000005). `agent-threadinit`.
- [x] **x64 non-unwinding longjmp (jmp_buf.Frame == 0) out of call_original** left the thread marked "in a callback" (every later hit on it silently ran no callback, no log) and in-flight +1 (detach waited 2 s). The record is now recognised as stale on the thread's next hit (its frame is at/below the new hit's SP, off this stack, or overwritten -- canary) and settled. Residual: until that thread's next hit the in-flight count stays +1. Reproduced x64 (8 of 10 callbacks + all 3 later probes silently lost); x86 longjmp always unwinds. `agent-ljframe0`.
- [x] **Agent's own threads ran program callbacks**, including the install rounds that run while every other thread is FROZEN (the hook writes call NtProtectVirtualMemory/FlushInstructionCache): a callback taking a lock a frozen thread held stalled the target for the controller's 5 s freeze limit. The service thread and the init/stop threads now pass straight through (not counted) while they run agent code. Reproduced x64 + x86 (callbacks on agent threads; with a stack-capturing callback the x64 run hung). Residual (not confirmed): one post-fix x64 run showed a single callback on an agent thread, not seen again; the likely source is the loader's own start/exit of the injected init thread (ntdll calling NtProtectVirtualMemory before/after the agent's code, outside any freeze), which the guard does not cover. The check now reports such loader hits separately and fails only on hits from agent code. `agent-own-threads`.
- [x] **Stop race:** `g_stopping` was checked before the hit was counted in flight, so a thread between the check and the add ran its callback after detach (its IPC raised an unhandled 0xE0554848 the target's VEH could see). Now checked after the in-flight add (Dekker with probe_agent_stop). Fixed by reasoning (no deterministic reproduction).
- [x] **probe_agent_init re-run cleared `callbacks[]`** while hooks could be live (null callback -> AV visible to the target). Each slot is now overwritten in one store; a null callback passes through. Fixed by reasoning.
- [ ] **Remaining limits:** a thread that dies inside a callback and whose id is reused before the next hit is treated as a stale record (settled, not reported as interrupted); `call_func` left by a non-unwinding longjmp keeps its thread in the call_func table; the per-thread region cache (`t_region`; since the transparency merge valid for one hit only) still trusts `tls_ready()`, which at thread exit (LdrpFreeTls frees the block before clearing the pointer) may point at freed memory.

## Controller static review (2026-11-05) — known limits, not fixed by design
- [ ] **call_func under contention (breakpoint/hw).** While a callback's `call_func` runs in the target, other threads that hit probes are parked; if one of them holds a lock the callee needs, the call times out after 5 s and the callee is abandoned mid-wait (SRW/CS wait blocks on a reused stack, locks it took never released). A first-chance exception inside the callee (C++ throw/catch, SEH probing) also abandons it. `call_original` is not affected (the thread runs on). Owner decision: no call_func hijack hardening -- use call_func only on lock-free, non-throwing callees; prefer `call_original`.
- [ ] **Unhandled-exception filters under breakpoint/hw.** A process under the debug API never runs its `SetUnhandledExceptionFilter` filter (the kernel routes to the debugger; second chance then ends the process). Crash reporters/recovery filters behave differently than without UHH. Every session (inline too) is a debugger, so this is inherent. Owner decision: no debug-port masking.
- Other findings (TF leak on re-faulting site, in-place double-fire, absolute probes across unload, deferred symbolisation vs unload, target-owned DRs, drain_final bound, error-exit detach) are being fixed with `ctrl-*` / `lifecycle-*` checks.

## Real-app findings (2026-11-05, `examples/realapps`, regress `realapps-*`)
The flagship callbacks (`track_open_process` / `forget_closed_handle` / `log_read`, unchanged
from gated_config) applied by `realapps_driver` to real programs that open other processes
and read their memory, launched and attached, under breakpoint / hw / inline, x64 and x86
(System32 vs SysWOW64). Ground truth: uninstrumented runs right before and after each
instrumented one (rows identical in both, about processes alive for the whole run, must be
unchanged), a 20 ms Toolhelp poll (every logged pid/name must be a process that existed),
and a .NET P/Invoke script (`ps-truth`) that prints the real handle -> pid of every read.
- ✅ No library or example bug found: every run had read logs == read-probe hits,
  log_dropped 0, callbacks_interrupted 0, no wrong pid/name, output identical to the plain
  runs, no refused inline site (ntdll stubs on both arches). Scale: `Get-Process | % Modules`
  x64 = ~330k reads over ~100 pids per run (breakpoint ~60-80 s, hw ~40 s, inline ~6-10 s);
  `tasklist /m` x64 = ~20k reads over ~110 pids.
- ✅ Handles that never went through NtOpenProcess read as `pid=0 name=?`, never as another
  process: CreateProcess's `hProcess`, a DuplicateHandle copy, the -1 pseudo-handle -- also
  when the duplicate is reissued the value of a just-closed mapped handle (NtClose clears the
  slot), and a reopen that gets the same value maps to the new pid (`ps-truth*`, 3-6 reused
  values per run).
- (inherent) What a launched program reads is not always in that program: `tasklist /v`
  opens ~100-120 processes but reads none (token/session queries only); `wmic process`
  opens 4 and reads 0 -- the enumeration runs in WmiPrvSE.exe, a different process (attach
  to it to see those reads); `cmd /c tasklist` shows 0 opens: the debugger follows only the
  launched process (DEBUG_ONLY_THIS_PROCESS), not its children -- launch the child itself.
- (inherent, x86) A 32-bit program reading a 64-bit process does not go through the 32-bit
  `ntdll!NtReadVirtualMemory`: SysWOW64 `Get-Process | % Modules` opens ~190 processes but
  logs reads of only the ~5 32-bit ones (the rest fail inside WoW64 or use
  `NtWow64ReadVirtualMemory64`, which the example does not probe). SysWOW64 `tasklist /m`
  opens nothing at all and takes ~2 min even uninstrumented (x64: ~1 s), so the suite runs
  it on x86 under breakpoint only.
- ⬜ (open, 1 row in ~40 list runs) x64 `tasklist /m` under inline once printed `N/A` as the
  module list of another agent's `lifecycle_target.exe` (alive for the whole run; both plain
  runs listed its 6 modules). N/A = tasklist got no module list for that process; no read of
  that pid was logged, so the open or the first query failed. Not reproduced in 12 further
  runs (4 x every backend, identical opens/reads per backend). Likely that target was being
  attached/held by its own test at that instant; the check now prints, for a changed row,
  whether the instrumented program opened/read that pid, to settle it next time.
- (note, test-side) a helper read immediately after CreateProcess fails with
  ERROR_PARTIAL_COPY (299, kernel32 not mapped yet) -- the plain run raced, the slower
  instrumented run did not. `ps-truth` now waits for the helpers' loader first.
- (note) the shared VM froze during the first x86 pass (black screen, guest paging at
  ~3 MB/s, SSH dead for ~40 min). This suite was running 32-bit `tasklist /m` /
  `Get-Process | % Modules` then (under 1 GB of controller/target memory, x86) alongside
  other agents' builds/tests; free RAM was not sampled at the time, so the cause is unknown.
  The rerun with free RAM logged every 15 s never went below 13.9 GB free (16 GB VM).

## Real large apps findings (2026-11-06, regress `realbig-*`, `scripts/target_state.py`)
Beyond `bigapps-*` (PowerShell + the Edge BROWSER, launch/attach/detach): a sandboxed Edge 156
RENDERER (V8, CIG, win32k lockdown) and the browser while a page ticks (`examples/bigapps/
ticks.html`: a new `Function` + hot loop + 512 KB typed array per tick, every value re-computed
by the suite, ticks must stay contiguous), PowerShell 5.1 (`workload.ps1`, JIT) and heavily
multi-threaded native programs (`robocopy /MT:16` of a 10000-file tree, `findstr /s` over 800
files), x64 and x86 (SysWOW64 hosts), every backend, launched or attached and detached
mid-run. Every run: the program's own result (exact copy / byte-identical output / workload
`bad=0` / page values), hits == logs_written == delivered (after a detach: the final totals
hits == logs + in_flight, every probe logs), log_dropped 0, no second-chance exception, the
controller's private bytes/handles sampled every 0.5 s, and after every detach **no residue**:
the target compared with ITSELF before the attach (every executable byte of ntdll / KernelBase /
kernel32 and the probed modules, both bitnesses in WoW64; every thread's DR0-3/DR7/TF in its
64- and 32-bit contexts; the debug port). (A comparison with the file on disk or with another
process would differ anyway: Chromium's sandbox patches ntdll stubs in its renderers.)
- ✅ (RB1) **Attach to a sandboxed process: every DLL but ntdll unnamed.** The synthesized
  LOAD_DLL events of an attach open each module's file in the TARGET's security context; an Edge
  renderer's restricted token cannot, so they arrive with `hFile == NULL` (dumped with a plain
  debugger: only ntdll and the exe have a handle). UHH named modules only from that handle:
  probes on KernelBase/kernel32/ws2_32/... stayed `pending` for the whole session (silently, 0
  hits), symbols for them were never registered, and the agent load failed with the misleading
  `target module owning LoadLibraryW was not observed` (repeated per event). The name and the
  dbghelp path now come from `GetMappedFileNameW` (device path mapped to a drive letter) when the
  event has no handle. Test: `realbig-edge-renderer-{breakpoint,hw}` (`KernelBase!VirtualAlloc`
  must hit; 1400-1600 hits per run).
- ✅ (RB2) **Inline into a CIG process is refused cleanly.** The renderer admits only
  Microsoft-signed DLLs (`ProcessSignaturePolicy.MicrosoftSignedOnly`), so `LoadLibraryW` of the
  agent fails; the session already failed cleanly (L7: detached, no residue, page unaffected),
  the error now says why (`... (the target admits only Microsoft-signed DLLs -- ProcessSignature
  Policy, e.g. a Chromium/Edge renderer -- ...)`). Breakpoint/hw there run without the
  controller-death guard (warned; limitations.md). Test: `realbig-edge-renderer-inline`.
  Renderer mitigations seen: CIG, DisableWin32kSystemCalls, StrictHandle, CFG, no-remote/low-label
  images, no child processes; **no ACG** (BlockDynamicCode off, V8 JIT on), so no dynamic-code
  refusal to test there.
- ✅ No other library issue: 18 x64 + 12 x86 rows (`--bigapps`), every residue check clean (0
  code bytes, 0 dirty threads of 16-83 per process), 0 drops, exact totals, every program right;
  controller peak 1-7 MB private, growth <= 3 MB over a run.
- (test-side) `realbig-robocopy-detach-inline` once finished the copy before its detach (a warm
  copy is ~4 s under inline; the plain first copy of fresh files 15-55 s): it now attaches as the
  copy starts and detaches 1.5 s later. (Still too fast for a runner once: now gated, see Follow-ups F2.)
- (test-side, realapps) `realapps-ps-fileversion-*` failed twice on x64 with one `powershell.exe`
  / `conhost.exe` row "missing": a bare image path stands for every process of that image, and
  another agent's instance that ended between the plain runs and the instrumented one was counted
  as lost output. Such rows now count only as many instances as were alive for the whole run.
- (flake, not reproduced) x86 `blog-pwsh-attach-detach-breakpoint` once detached (2.5 s) before
  its probe went active on a loaded VM; 3/3 x 3 backends green on the rerun (the mapped-name
  fallback never triggers for a WoW64 attach: traced).
- (note) What is hot is not what one expects: robocopy and findstr move file data through
  sections, not NtReadFile/NtWriteFile (0 hits on both: probe NtCreateFile/NtMapViewOfSection/
  NtClose); Edge's renderer calls NtProtectVirtualMemory 0 times in 20 s of fresh `Function`s
  and PowerShell 5.1 0-2 times (neither flips JIT page protection per compile on this build);
  the renderer's hot exports are NtAllocateVirtualMemory/VirtualAlloc and NtWaitForSingleObject.
- (measure, x64 VM, shared) Cost while attached: PowerShell workload ticks (plain 1.0/s, 4
  probes): breakpoint 0.4-0.9/s, hw 0.6-0.75/s, inline 1.0/s at 5-10x the hits; one probe on
  CreateFileW: bp/hw 0.70/s at ~85 hits/s (the 4 runspace threads serialize on the debugger),
  inline 0.84/s at ~630 hits/s; attached with no hit: 0.85/s (bp) / 0.95/s (inline) -- the
  workload's 6 first-chance .NET exceptions per iteration are debug events. Edge renderer:
  15/s while attached (bp/hw, ~300 hits/s) vs 21/s after the detach; the browser shows none.
  robocopy/findstr launch: bp 2-5x, hw 1-3x, inline ~1-3x (seconds-long runs, noisy).
- Not covered: pwsh 7 (not installed on the test VM: rows SKIP), 7-Zip / node (absent),
  msbuild (not run: spawns long-lived nodes on a shared VM).

## Calling-convention findings (2026-11-06, `examples/callconv`, regress `callconv-*`)
`ccfix.dll` exports one function per x86/x64 convention and argument/return shape: cdecl,
stdcall, fastcall, thiscall (a real C++ member), vectorcall (int + double + float args), 0 and
10 arguments, 64-bit arguments (two x86 slots), structs by value (8 and 12 bytes), float/double
arguments with ST0/XMM0 results, EDX:EAX results (int64, 8-byte struct), hidden return
pointers (cdecl and stdcall), an x86 `mov edi,edi` hot-patch prologue, an incremental-link
thunk (E9 rel32 followed by the next thunk), an import thunk (FF 25 [IAT slot], in the exe)
and a function entered by a tail-call `jmp`. `cc_target` calls each once -- on x86 through
`cc_invoke`, which measures the bytes the callee popped and checks EBX/ESI/EDI/EBP -- and
every one is probed at entry on breakpoint, hw (groups of 3) and inline in three modes:
wrap (call_original + return_from(r, n)), replace (return_from(v, n), body skipped) and
wrongpop (call_original + return_from with a wrong x86 nargs). The callback checks
get_func_arg/get_reg against what the caller passed. Before the fixes, x86: 9 of 10 checks
failed (only the uninstrumented baseline passed); x64: hw wrap lost `CcDbl`'s XMM0 result (the
x64 breakpoint/inline baseline was masked by identical-code folding of the fixture, since fixed).
- ✅ (CC1) **x86: the high half of an EDX:EAX result was lost on every backend.** return_from
  set EAX only (EDX = the hit's), and call_original's in-place restore put the hit's EDX back:
  `CcI64` wrap returned 0x7777777a for 0x155555557777777a, replace 0x33221107 for
  0x7766554433221107, `CcRet8` (8-byte struct) 0x3f for 0x7e0000003f. Now x86 return_from
  sets EDX = value >> 32, and after call_original a value whose high half is 0 leaves EDX as
  the original returned it, so `return_from(c, r, n)` passes any integer result through
  (probe_x86_return_regs, shared by all backends). *ret stays EAX zero-extended (comparisons
  like `r == 0` keep working on x86).
- ✅ (CC2) **Floating-point results were lost by return_from after call_original.** bp/hw
  restored the hit's FP state after the in-place call (x86 `CcDbl`/`CcFlt`: the caller found
  an EMPTY x87 stack -> NaN/0; x64 `CcDbl` got XMM0 = its own first argument 1.5 instead of
  6.375). Inline x86 left the original's ST0 pushed on the callback's x87 stack (worked only by
  accident with return_from, leaked one x87 slot per call without it); inline x64 restored
  the hit's XMM0 (by code inspection). Now the original's FP state is stashed and applied with return_from (bp/hw:
  the post-call CONTEXT FP area; inline: XMM0 copied into the hook context, x86 x87 via an
  FNSAVE image reloaded after the extended-state restore; the callback itself always runs
  with the hit's x87 state). Without call_original a float result cannot be set (documented).
- ✅ (CC3) **x86 bp/hw call_original did not restore XMM0-7/MXCSR** (CONTEXT_EXTENDED_REGISTERS
  was not part of the saved context): a fall-through or second call ran with the original's
  XMM registers, i.e. corrupted __vectorcall arguments. Saved/restored now.
- ✅ (CC4) **Inline call_original passed only nargs (<= 8) stack arguments**: `CcStd10` (10
  args) ran with garbage in args 9-10 (x86 ret 0x6195130b for 0x16fd), and any function with
  more than 8 x86 slots (64-bit/double/struct arguments) or more than 8 x64 arguments was
  corrupted -- bp/hw ran them correctly in place. Inline now copies a window of the hit's stack
  (32 x64 stack arguments / 64 x86 slots, bounded by the thread's stack top) whatever nargs
  says; nargs is only a minimum.
- ✅ (CC5) **Inline call_original did not pass XMM0-5** (coordinator's static review too):
  x64 `double f(double)` (by inspection: XMM0-3 were the agent's scratch) and every x86
  __vectorcall float argument arrived as garbage (`CcVec` 0x7938 for 0x7a4b), bp/hw were right. uhh_orig_thunk / call_tramp_x86 load
  XMM0-5 from the hit's context; x86 also passes EAX (Delphi/Borland `register` convention).
- ✅ (CC6) **A wrong x86 return_from nargs silently corrupted the caller's ESP** (`wrongpop`:
  cdecl with nargs 2 popped 8 bytes, stdcall with 0 popped none -- on every backend). After
  call_original the bytes the original really popped are measured (bp/hw: ESP at the return
  trap; inline: ESP after the call) and used; a contradicting nargs is warned once per probe
  ("return_from nargs=N but the original popped M bytes"). Without call_original the API
  cannot know the convention: probe_api.h now spells out which nargs to pass per convention
  (a wrong one leaves ESP off by the difference -- inherent).
- 📄 (CC7) get_func_arg's index per convention is now documented in probe_api.h: x64 =
  argument position (RCX, RDX, R8, R9, stack; float args in XMM are not readable; int args
  have undefined upper 32 bits; structs other than 1/2/4/8 bytes by pointer; hidden return
  pointer first); x86 = 4-byte stack slot, register args (fastcall/vectorcall ECX/EDX,
  thiscall ECX) via get_reg, 64-bit/double = 2 slots, struct = size/4, hidden pointer = slot 0.
  XMM arguments (x64 floats, vectorcall) have no accessor: the frozen API has none (inherent).
- ✅ (CC8) **Inline probes in a DLL the target LoadLibrary's at run time were missed** (the
  hold for the new module ended "inline install not confirmed within 5 s" / "released 1 held
  thread(s) (install timeout)", every call ran unhooked, the hooks reported "active" only
  afterwards). **Root cause** (PROBE_TRACE: `load_dll` timestamps + every thread's symbolized
  stack at the timeout): `probe_agent_init` published `service_ready` right after
  `CreateThread`, while the new service thread was still in `LdrInitializeThunk` (loader
  thread-init: DLL_THREAD_ATTACH for every module, which waits while another thread is in a
  load). The controller released the entry hold, the main thread at once LoadLibrary'd the DLL,
  was held at its LOAD_DLL event as the loader's load owner (`NtMapViewOfSection` <-
  `LdrLoadDll`), and the service thread (`LdrInitializeThunk` -> `ZwWaitForSingleObject`) waited
  for that load: the SetEvent kick was never seen until the timeout released the hold, then the
  install ran 220 ms later. Pre-fix: `latedll` main-thread and DllMain scenarios timed out 8/8
  (x64 inline), the worker-thread one passed (its extra thread start gave the service thread
  time). The install itself never needed the loader (callbacks are pre-resolved; SafetyHook
  only allocates/VirtualProtects). **Fix**: the service thread sets `service_ready` itself from
  `service_main` and raises INSTALL_DONE; `probe_agent_init` waits (bounded, 5 s) for it, so
  nothing reports "active" before it can install; the controller releases holds only when
  `inline_hold_needed` is false (i.e. the service thread runs). Holding the loading thread at
  LOAD_DLL is then safe: no new thread, no loader call on the install path. Test:
  `latedll-<main|worker|dllmain>-<inline|breakpoint|hw|mixed>` (examples/latedll: 8 inline
  sites, more than the debug registers, so the DR gates fall back to the LOAD_DLL hold; the
  dllmain case loads the probed DLL from a DllMain, calls every site under the loader lock and
  starts a thread there), 10 runs each, exact hits == body counts == logs, x64 + x86.
  Not covered: a probed site reached by the service thread's own DLL_THREAD_ATTACH callouts
  before it runs (a target DLL calling its probed function from DLL_THREAD_ATTACH).
- ✅ Thunks and prologues need nothing special: a probe on an import thunk (FF 25), an
  incremental-link thunk (E9, next thunk directly after) and a tail-call target sees the
  caller's return address at [SP], so get_func_arg, call_original and return_from (`ret 12`)
  work as on the real function, on every backend; the x86 hot-patch prologue likewise.
## Portability findings (2026-11-05, `examples/conformance/matrix_callbacks.cpp`, regress `portability-*`)
Gospel check: ONE callback source records what every API call returns -- registers (all 16 ids,
invalid ids, CF across the hit), memory of every kind (RW, read-only, guard, execute-only,
reserved, a range running into PAGE_NOACCESS, wrap-around, huge sizes, addresses no pointer can
hold, null buffers, size 0, code under this / another backend's probe), arguments, config (incl.
> 256 bytes), `call_func` symbol forms and failures, the control plane from a callback, logging
edge cases, a faulting and a throwing callback, 5 threads hitting one probe -- under breakpoint,
hw and inline (`conformance_driver --matrix A|B|C`, phases keep hw within 4 DRs). The suite diffs
the "M" lines of the three runs line by line (plus every other log record and the target's own
observations); "D" lines are documented divergences checked against their per-backend value.
Before the fixes, x64 differed in 18 keys (A: 10, B: 2, C: every target row -- the session died).
- ✅ (P1) `call_func` symbol grammar differed: inline resolved `kernel32!X` (GetModuleHandle
  appends ".dll"), `X+0` and `X+0xZZ` (lenient `_strtoui64`) where breakpoint/hw refuse them, and
  refused `C:\any\dir\kernel32.dll!X` where breakpoint/hw match the file name. The agent now parses
  with the controller's grammar (`module` matched by file name; `+0xHEX` only). Since the
  transparency merge (TR5) that grammar takes a bare module name as `<name>.dll` on every
  backend (`kernel32!X` resolves everywhere, `portability-matrix-A` `call_func.no-ext`).
- ✅ (P2) **A probe added from an inline callback returned 0 when its callback had been folded by
  the linker** (`/OPT:ICF`: two identical -- e.g. empty -- callbacks share one address): the agent
  sent the first export name of that address, which the controller's copy need not export.
  breakpoint/hw: 1. All names of the address now travel (IPC and the inline install request);
  the receiver takes the first it exports.
- ✅ (P3) From an inline callback, `probe_add_symbol_cfg` refused a config > 256 bytes and a symbol
  > 255 chars (fixed IPC buffers); breakpoint/hw accepted them. The controller now reads the name,
  symbol and config from the stopped calling thread's memory.
- ✅ (P4) An inline probe refused a config > 256 bytes at add time (breakpoint/hw: any size). A
  larger config now goes to a block the controller allocates in the target.
- ✅ (P5) **A callback that throws a C++ exception ended the whole breakpoint/hw session** ("probe
  callback threw an unknown exception"; the target's remaining run was lost); inline abandons
  the callback. The controller now abandons it the same way (SEH: hit counted, register changes
  discarded, set_mem writes kept, one stderr warning).
- ✅ (P6) Adding a probe from a callback with a NON-exported (static) callback: breakpoint/hw 1,
  inline 0 (the controller resolves inline requests by export name). Now refused (0, error
  message) on every backend when called from inside a callback; top-level adds are unchanged.
- ✅ (P7) The `call_original` / `return_from` refusal warning ("not at a function entry") was a log
  record inline but stderr only on breakpoint/hw: the logs differed by one record. breakpoint/hw
  now also emit the same "uhh warning: ..." record, once per probe like the agent.
- ✅ (P8) `get_mem` of code under a probe of ANOTHER backend (mixed sessions): inline read the
  breakpoint's 0xCC, breakpoint/hw read the inline hook's `jmp` (`e9 ...`). The controller now
  publishes its armed INT3s to the agent (shared table, seqlock) and overlays the bytes each
  installed inline hook overwrote (published by the agent): every backend reads `90 90 ...`.
- ✅ (P9) `call_func(c, "0x1", ...)` inline called the address and caught the fault, but the
  target's vectored handler saw the first-chance AV (breakpoint/hw: silent 0). Inline now refuses
  an address that is not committed executable memory before calling.
- ✅ (P10) **x86 inline `get_mem`/`set_mem` truncated a 64-bit address to 32 bits**: `set_mem(rw +
  4 GB)` returned 1 and WROTE `rw` (the target's first bytes changed; breakpoint/hw: 0, untouched),
  `get_mem` of it read `rw`, and `get_func_arg(c, SIZE_MAX)` returned the stack word at `[esp]`
  (address wrapped past 4 GB; breakpoint/hw: 0). Refused now, as on the controller.
- Evidence: before the fixes x64 differed in 18 keys and x86 in 21 (P1-P10 above; plus
  `portability-matrix-C` lost every target row on breakpoint/hw because the session died on the
  throw); after them `portability-matrix-{A,B,C}` and `portability-documented` pass on x64 and x86.
- ✅ (seen on the x86 run of this branch, not caused by a portability change): `edgehunt-
  {breakpoint,hw}-fmtptr` expected `[unformattable] fmtptr %s` for a TARGET pointer printed with
  `%s` in a controller callback, but on x86 the same address can be mapped in the controller too
  and then prints the controller's bytes (`fmtptr W..}j`) -- the B10 behaviour itself. The check
  now accepts either outcome on breakpoint/hw (exactly one record, run unaffected).
- 📄 (D1) Win32 calls made directly by a callback act on the process the callback runs in
  (`GetCurrentProcessId() == target pid`: breakpoint/hw 0, inline 1). Portable: `call_func`
  `kernel32.dll!GetCurrentProcessId` / `GetCurrentThreadId`; target memory only via get/set_mem.
- 📄 (D2) Concurrency: breakpoint/hw callbacks never overlap (max in flight 1 over 210 hits on 5
  threads); inline ones do (5 measured). `thread_local` in a callback is per target thread inline
  (main thread: 10) but one controller thread for all target threads on breakpoint/hw (210).
- 📄 (D3) A faulting / throwing callback is abandoned identically, but inline the exception is
  raised IN the target: its vectored handlers see the first chance (`c0000005`, `e06d7363`);
  breakpoint/hw: never.
- 📄 (D4) `call_func` of a callee that raises and handles its own exception (`lstrlenA((char*)1)`):
  breakpoint/hw abandon the call at the first-chance exception (0, `*ret` untouched, the target
  never sees it); inline the callee's handler runs (1, `*ret` = 0) and the target's vectored
  handlers see it. Passing the exception to the target from the debugger is not safe: the
  callee's frame chain ends in a frame the debugger built (x64 unwind / x86 SEH chain would reach
  the HIT's handlers and could unwind the thread out of the call).
- 📄 (D5) `PROBE_ONCE` is breakpoint/hw only (refused inline, from any caller); now in the header.
- 📄 (D6) A probe added from an inline callback names its callback by export, resolved in the
  module of the calling callback only (breakpoint/hw take the pointer as is): keep a callback and
  the callbacks it adds in one module.
- Agree on every backend (verified, no change): get_reg of all 16 ids at a mid-function site,
  set_reg of each (x86: values wider than 32 bits read back whole in the callback, the target gets
  the low half; R8..R15 are 0 / refused), invalid ids, CF preserved, every memory case above incl.
  untouched buffers on failure and the program-visible effects (guard page still armed, read-only
  and partial ranges unmodified), get_func_arg (huge index 0), get_config (null for none, 8-byte
  aligned), every null-context call, send_log (null format: no record; 1500 chars truncated alike;
  `%k` -> `[unformattable]`), send_log_stack at a function entry (frames 0-1), call_original /
  return_from refused mid-function, the probe and target rows of the faulting / throwing callbacks.
## Controller review findings (static review of src/probe/session.cpp, 2026-11-05)
Fixture `examples/ctrlreview` (ctrl_target + ctrl_dll + ONE callback source), regress `ctrl-*`
(`--only ctrl-`). Every finding below was first reproduced by its check on the unfixed code (x64).
- ✅ (2) **Faulting probed instruction, target handler CONTINUEs** (lazy commit in a VEH, guard pages).
  Breakpoint: the displaced copy faults, the instruction re-runs in place with TF; its fault went to the
  program with the INT3 re-armed, so the handler's restart hit the INT3 again -> **two callbacks for one
  execution** (300 hits for 200 executions); and a PAGE_GUARD fault was consumed by the out-of-line copy,
  so **the program's handler never saw its guard violation** (guard=0 of 100). Now: the guard is put back
  before the in-place re-run; a faulted in-place step is remembered per thread -- the restart (INT3 at the
  site with our TF still in the restored context) runs no callback and counts no hit, and if the handler
  continues elsewhere the one stray trap of our TF is absorbed. A WOW64 (x86) handler's context comes back
  WITHOUT our TF (x86 had 400 hits for 200 with the TF test alone): there the restart is the next INT3 at
  the site with every integer register, SP and the arithmetic flags unchanged since the fault.
  ~~📄 x64: the handler's ContextRecord shows our TF (the restart marker; it was visible before too).~~
  Fixed 2026-11-06 (Codex library review, below): the handler never sees our TF on any backend.
  📄 x86: a NEW call that reaches the site with exactly the faulting registers right after the handler
  unwound would be taken for the restart (not seen; needs identical registers incl. SP). hw and inline were
  already exact. Test: `ctrl-fault-{breakpoint,hw,inline}`
- ✅ (3) **In-place stepping, several threads: double callback.** Thread B's INT3 hit is queued while A has
  the byte lifted; B is set up to run the original at the site, A's step completion re-arms first, B
  executes the INT3 -> its callback ran again (20 duplicates in 24000 calls). Now a thread that is mid
  in-place step and hits the INT3 at its own site is put back and the byte lifted again, no callback.
  ✅ Missed hits while the byte is lifted (round 3 #2): fixed -- address-size LOOP is emulated now and
  every remaining in-place step holds the other threads (in-place window, see round 3 #2); a hit queued
  before a window is replayed after it, so the duplicate path cannot arise there either.
  Test: `ctrl-inplace` (8 threads x 3000 calls through an address-size LOOP): exact, x64 709 -> 24000/24000,
  x86 971 -> 24000/24000 hits
- ✅ (5) **probe_add_address / probe_watch inside a DLL that unloads were never retired** (UNLOAD_DLL only
  matched module probes by base). Seen: hw slots exhausted after 2-4 load cycles (`probe_watch` -> 0), and
  on reload at the same base every new probe's hits went to the stale first one (hits 0,0,0,0,500).
  Now absolute probes whose address lies in the unloading image (SizeOfImage recorded at load) are retired
  for good: DR released, agent hook marked UNLOADED, INT3 forgotten. Test: `ctrl-absunload-*`
- ✅ (6) **Deferred stack symbolization raced UNLOAD_DLL**: frames captured before an unload were written
  as raw hex once dbghelp had dropped the module (3-12 of 6000 on breakpoint/hw, 5934 of 6000 inline --
  the ring is drained later). Now the unregister travels through the log queue behind every record
  captured before the unload (the agent ring is drained into the queue first); a module loading over a
  range still held waits for the writer to pass that point. Test: `ctrl-symunload-*`
- ✅ (7) **The target's own debug registers** (SetThreadContext on itself, caught by its VEH): arm_hw only
  looked at one thread's DR7 and took a slot another thread owned (the target's watch never fired again);
  a slot UHH had once used and released was swallowed by handle_hw (`dr_ever`) and cleared by
  enforce_owned_drs. Now a slot enabled on a thread that is not ours and does not hold an address we
  released is the target's: never taken (any thread, also for inline gates), never cleared, its #DB
  passed on (also when it shares the #DB with one of ours), and never inferred as ours. 📄 A target that
  overwrites DR7 wholesale over a slot UHH is using cannot keep both; detach still clears every
  `dr_ever` slot (detach path owned elsewhere). Test: `ctrl-owndr-*`
- ✅ (8) **drain_final trusted log_head from shared memory**: a target writing a huge value hung the
  controller at exit. The loop is clamped to one ring (tail + PROBE_AGENT_LOG_CAP). Test: `ctrl-headclamp`
## Codex controller review (library diff, 2026-11-06)
Fixture `examples/ctrlreview` (scenarios owndrx / faultreg / absreuse / int3cap / bigcfg), regress `cdx-*`
(`--only cdx-`), every check on breakpoint, hw and inline.
- 🔧 (1) **A target-owned hardware breakpoint at an address UHH once probed with hw and released was
  swallowed**: `retired_hw` kept the address "ours" forever, so the target's slot there was not its own,
  its #DB was taken for a stale UHH event (and its DR cleared). Now a released address is ours on a thread
  only until that thread's next debug event, and only if the thread has not run since the release
  (registers unchanged: its event was queued before the release, when our DR clear can be lost -- see
  enforce_owned_drs); then its image is cleared and the #DB swallowed as before. A thread that has run
  since got our clear, so whatever it arms there afterwards is the target's. 📄 A context captured before
  the release and restored after it by a handler already running then (NtContinue) brings our released
  DR back as the program's own (passed on). Test: `cdx-owndrx-*` (a thread alive at the release arms its
  own write watch on the address UHH watched once, in every free slot)
- 🔧 (2) **WOW64 in-place fault restart compared registers**: an x86 handler that repairs the fault by
  changing a register and retries at the probe site was a new hit (two callbacks for one execution; x64
  recognises the restart by our trap flag). Now on x86 the restart is the faulted thread's next event being
  the INT3 at the site, whatever its registers (the fault was dispatched to the program in between).
  📄 x86: a handler that continues elsewhere and whose thread's very next event is a NEW call reaching the
  same site is taken for the restart (no callback for that call). Test: `cdx-faultreg-*`
- 🔧 (3) **Absolute software breakpoint retired on unload left the agent's INT3 table stale** (the
  module-relative branch synced it): an inline get_mem at the reused address showed the old original byte
  over a real 0xCC. Now synced. Test: `cdx-absreuse-*`
- 🔧 (4) **Only the first 1024 software breakpoints entered the shared INT3 table**: past them inline
  get_mem read UHH's 0xCC where breakpoint/hw read the program's byte. The table now holds 65536 entries
  (PROBE_AGENT_VERSION 18, 1 MiB of the section, touched only as far as used) and, in a session with the
  inline channel, the 65537th armed breakpoint is refused (documented in probe_api.h) instead of silently
  missing from it. Test: `cdx-int3cap-*` (1200 breakpoints)
- 🔧 (5) **A dynamic add from an inline callback refused configs over 64 MiB** (PROBE_IPC_CONFIG_MAX) while
  breakpoint/hw accepted any size: the limit is now the API's 4 GB (UINT32_MAX bytes) on every backend,
  documented in probe_api.h. Test: `cdx-bigcfg-*` (64 MiB + 4 KiB)
## New-app evaluator findings (2026-11-06, `examples/{filetrace,flagflip,regtrace}`, regress `newapp-*`)
A new user wrote three tools in gated_config's style from README.md, probe_api.h and the
examples alone. Each tool has a per-probe `--backend` option and a fixture that prints its
own ground truth. Every tool ran on every backend and in mixes, on x64 and x86.
- ✅ (NA1) **call_original was capped at 8 arguments**, so `NtCreateFile` (11 args), the
  first function a file tracer hooks, could not be run. With nargs 11 it was refused
  **silently** on every backend (return 0 and no warning, unlike the other refusals). With
  nargs 8, inline built a frame with garbage for args 9-11. The cap is now 16 on every
  backend: the x64 `uhh_orig_thunk` frame copies stack args 5..16, and x86 copies up to 16.
  An out-of-range nargs is refused with a one-time warning. Test: `newapp-file-*`
  (NtCreateFile call_original + return_from(11)).
- ✅ (NA2) **Backend mismatch: x64 inline call_original passed only the first `nargs`
  register arguments, zeroing the rest.** A `bool IsEnabled() const` method has no stack
  arguments, and following the x86 `__thiscall` reading of the doc ("ECX passed as it is")
  a user passes nargs 0. Breakpoint/hw ran the original in place and worked. Inline called
  it with RCX = 0, so `this->enabled_` faulted and the TARGET died (the exception went to
  the program, as designed). Now the x64 register arguments (RCX/RDX/R8/R9) always go as the
  hit had them, like x86 ECX/EDX, and nargs only sizes the stack copy. The doc says so.
  Test: `newapp-flag-inline-modify`.
- ✅ (NA3) Docs: README said "PDB-only symbols are on the roadmap", but `module!Name`
  already falls back to the PDB (`flagfeature.dll!Feature::IsEnabled` works, pending until
  the DLL late-loads). Fixed.
- ✅ (NA4) Docs: nothing in README said that inline callbacks must be **compiled into
  `probe_api_agent.dll` and exported by name**; a user learned it only from a comment in
  gated_config/callbacks.h and the CMake list. README now has a "Writing your own tool"
  section covering that, UHH_SHARED, the x86 `__thiscall` `this` (in ECX, not
  `get_func_arg(c, 0)`), the 16-argument limit and the hw register budget.
- ✅ (NA5) Docs: **inline probes go live at the entry point**, and breakpoint/hw from the first
  instruction. A tool mixing an inline open probe with a hw value probe sees the loader's own
  registry queries (IFEO `RaiseExceptionOnPossibleDeadlock`, `LongPathsEnabled`, ...) on
  handles its map never saw (`key=?`). This is correct, but it was undocumented. README and
  the regtrace README now cover it.
- 📄 (NA6) **hw budget**: 4 debug registers in total, and call_original on hw needs one of them free
  while it runs. A 6-probe tool (regtrace: 3 open stubs, 2 value stubs, NtClose) therefore
  cannot be all-hw. hw takes either the open group (3 + 1 free) or the value and close
  probes (3). regtrace refuses `--backend hw` up front with that reason
  (`newapp-reg-hw-overcommit`). filetrace has 3 probes, so all-hw fits.
- Asymmetry to know (documented in probe_api.h, kept): call_original's nargs counts the arguments
  the function takes, and return_from's nargs is the x86 STACK arguments the callee pops
  (`__thiscall` with no other args: 0, `NtCreateFile`: 11). Fixture-side surprise: `CreateDirectoryW` on an
  existing dir is an `NtCreateFile` that fails with OBJECT_NAME_COLLISION, which a faithful
  tracer logs. The fixture's ground truth must include it, or the fixture must skip the call.
## Log delivery findings (2026-11-05, `examples/logs_eval`, regress `logs-*`)
Adversarial pass on "logs are never dropped and always delivered; hits == logs + log_dropped +
callbacks_interrupted; log_dropped != 0 only when the controller is gone". Every defect below was
reproduced on x64 before the fix (baseline numbers quoted) and has a `logs-*` check.
- ✅ **Ring wedge: a producer that stops between claiming a ring slot and publishing it stalled
  every later inline log** (also flagged by the static agent review). The consumer stops at the
  first unpublished slot, so a thread killed there (TerminateThread, or ExitProcess killing workers
  mid-send_log while the exiting thread keeps logging from DLL/TLS detach) or suspended there by the
  program froze the ring: every logging thread then waited, and the old 2-s escape -- which rarely
  fired, and dropped logs while the controller was alive when it did -- was the only way out.
  Baseline: `logs-wedge-kill` 4107/12000 calls in 25 s (deadline), `logs-wedge-suspend` 4103/12000
  in 42 s, `logs-wedge-exit` session hung > 180 s. Fix (`probe_agent_shared.hpp`, agent `agent_log`,
  session `check_ring_stall`/`drain_final`): a producer claims a slot by owning it (CAS of the slot's
  owner tid) BEFORE moving the head, so every claimed slot names its producer; the drainer skips a
  claimed slot whose owner thread is GONE (its callback stays counted in flight ->
  `callbacks_interrupted`: accounted, not dropped); behind a LIVE but stopped owner it delivers the
  published records past that slot (in ring order; marked delivered, freed when the tail passes),
  and after 200 ms it sets `ring_stalled` and producers hand records over synchronously (`PROBE_IPC_LOG`, the
  existing agent->debugger exception channel) instead of waiting or dropping. The producer-side
  2-s drop is gone: a producer drops only when the controller stopped consuming
  (`controller_gone`) or its process is dead (new: checked when the drainer heartbeat has not moved
  for 1 s -- a controller killed while attached used to leave every logging thread spinning
  forever; `logs-controller-killed`).
- ✅ **Per-thread order across mixed backends was not preserved.** A thread alternating an inline-probed
  and a breakpoint/hw-probed call saw its records reordered (inline records crossed the ring while
  the debugger queued its own directly). Baseline: 2923 (inline+breakpoint) / 1783 (inline+hw)
  inversions in 16000. Fix: a controller-side send_log first drains the ring (the hit thread is
  stopped, so its earlier inline records are all published). It also delivers past one unfinished slot
  of another thread (frozen mid-record by the debug event). After the fix: 0 inversions.
  Residual (documented): a record behind TWO unfinished slots of other threads at the same instant
  can still be overtaken.
- ✅ **Silent content loss in log text.** An embedded NUL (`%c` of 0) cut the message there; tab, CR
  and other control characters were deleted by the JSON writer; invalid UTF-8 bytes were written raw
  (the line was not valid UTF-8 JSON -- a strict reader rejects it); an `[unformattable]` copy of a
  long format was cut without the truncation marker. Fix: the formatter returns the length (NULs
  kept, carried in `probe_agent_log::text_len`), the JSON writer escapes every control character
  (`\t`, `\r`, `\u0000`, ...) and writes a byte that is not well-formed UTF-8 as `\u00XX`, and every
  truncation carries `...[truncated]`. Same text on every backend (`logs-format-*`). Note: the MSVC
  CRT prints an unknown conversion such as `%k` as its letter (`k`); `%n` is refused
  (`[unformattable] ...`).
- ✅ **A closed stdout reader (`uhh_trace ... | head`) stopped the JSONL FILE too**: the writer failed
  as a whole and counted every later log as dropped (baseline: 293/20000 records in the file).
  Fix: a failed stdout only ends the live tail (still reported as the session error); the file keeps
  every record (`logs-stdout-closed-*`).
- ✅ Detach: the final drain now runs after the target's threads are resumed (a producer the detach
  freeze caught mid-record finishes it instead of losing it), recovers published records behind a
  never-published slot, and the detach summary prints `in_flight=` (hits == logs_written +
  log_dropped + in_flight).
- After the fix (x64): `logs-wedge-kill` 12000/12000 in 109 ms, `logs-wedge-suspend` 12000/12000 in
  2.1 s with every record delivered live, `logs-wedge-exit` exits with hits == logs + 1 interrupted,
  `logs-controller-killed` target completes 80000 calls.
- Checked, no defect: ExitProcess / TerminateProcess(self) during a 4-thread flood on every backend
  (hits == logs + log_dropped + callbacks_interrupted exactly, dropped 0); maximum-size text (1023 bytes kept whole, 1024 marked), `%n`/huge widths/
  null `%s`, valid UTF-8, stack snapshots on truncated messages, a slow stdout pipe (backpressure,
  nothing dropped), ring-full while the debugger holds the target (waiting time is not counted while
  the target is frozen).
- Inherent (accounted, documented): a thread killed AFTER publishing its log but before its callback
  returns is counted both as logged and as interrupted (two separate words cannot change
  atomically) -- over-accounting by at most one per killed thread, never a lost hit. A producer that
  read `controller_gone == 0` and claims a slot after the final drain at detach/close (a window of a
  few instructions) loses that record uncounted.
## hw load / VM freeze (2026-11-06) — investigated: VM artefact, not a UHH leak

The shared Win10 VM (Proxmox VM 103, KVM, cpu=host i5-6600) froze twice 18-22 min into the
30-min all-hw soak phase (~12k hw hits/s). Investigated with short, sampled runs (10 s
samples of Available MB, standby/modified/free lists, paged/nonpaged pool, commit, system
cache, system handles/threads, per-process private/WS/handles for controller, target,
python, System, Registry, MsMpEng; pool tags via SystemPoolTagInformation before/after;
abort below 4000 MB available):

- ✅ **No growth with hw load.** hw 2.3 min (1.44M hw hits, 10.4k/s): Available 14089 -> 14177 MB,
  nonpaged 110 -> 109 MB, paged 292 -> 293 MB, commit 2370 -> 2172 MB. hw 8.2 min (5.04M hits,
  10.3k/s, past the t=300 s and t=471 s points): Available 14065 -> 13980 MB (noise +-150),
  nonpaged 122 -> 127, paged 341 -> 360 (largest pool-tag deltas FMfn/MmSt/Ntff/File: file-system
  tags from other agents' builds, all < 5 MB), commit 2391 -> 2373. Controller ~2-3 MB private
  and target ~1 MB flat, handle counts flat, MsMpEng 434 -> 498 MB (scanned the non-excluded
  log file and other agents' builds). Same 2-min run on inline at the same rate (12k/s): equally
  flat. Upper bound for any per-hit leak: < ~30 bytes/hit -- the freeze would have needed
  ~1 KB/hit (6-10 MB/s). Every run PASSed soak.py's exactness checks.
- ✅ **DR7 is clean.** Read live from the target's threads mid-run: 0x415 / 0x15 (L0-L2 +
  reserved bit 10). UHH never sets LE/GE (bits 8/9), GD or BTF (set_dr_on_thread,
  enforce_owned_drs, the agent's in-process path only touch Ln and RW/LEN).
- ✅ **`kvm: Unhandled WRMSR(0x1d9) = 0x1` is unrelated to hw hits.** The guest writes
  DEBUGCTL.LBR; KVM drops the bit and logs (rate-limited, so 132 lines/min = the cap). Zero such
  lines during the whole 2.3-min hw run, and the same sporadic rate during the 8-min hw run as
  while only builds/other agents ran (00:20, 00:25-00:31, 00:43-00:46 with no hw load).
  Harmless (no #GP, no state); ignore it.
- **What the freezes were:** silent guest hangs. Kernel-Power 41 with BugcheckCode=0 (no
  bugcheck, no dump), no Resource-Exhaustion-Detector (2004) event, pagefile peak usage 0 --
  the guest never ran out of commit. An identical silent freeze happened at 12:56 the same
  day under concurrent builds with no hw soak at all. The "guest memory full" figure (6.3/8,
  14.2/16 GB) is Proxmox's QEMU RSS (no balloon driver in the guest: device VEN_1AF4&DEV_1002 is
  in Error state, so no balloon stats): it only shows guest pages ever touched (file cache of
  the multi-GB soak logs) and never shrinks -- it reads 16.8 GB right now with 14 GB available
  in the guest. The working-set trim seen at t=1085 s of the first run (8 GB guest) was with
  several agents building/testing concurrently. The guest disk is a thin LV on a 5400 rpm HDD
  (WD10EZRX, host /dev/sdb). Conclusion: a hypervisor/VM-load artefact on this box, not a UHH
  defect; a real machine is not affected by anything UHH does under hw load.
- **How to recognise it:** guest unreachable, Kernel-Power 41 BugcheckCode=0 after reset, no
  2004 events, soak samples flat right up to the hang (Available, pools, commit), Proxmox memory
  graph near the VM's maximum. WRMSR(0x1d9) lines are background noise, not a signal.
- **Safe soak limit on this VM:** all-hw phase <= 10 min per run (8.2 min verified clean), only
  with no other VM jobs running (take every vmslot), samples every <= 15 s, and the soak's abort
  on low Available memory left on. Longer hw soaks belong on bare metal. (`scripts/soak.py --help`
  says the same.)
- No fix, so no `hwload-` regress check: there is nothing in UHH to regress.

## Transparency findings (2026-11-06, `examples/transparency`, regress `transparency-*`)
Adversarial check of "a hit is invisible to the program". Every probed function has an unprobed
twin with the same body; both are called through one assembly harness that loads sentinels into
every callee-saved register and captures what a caller can observe (return registers: x64
RAX/XMM0, x86 EDX:EAX/ST0; callee-saved GPRs and XMM6-15; SP after the call, so x86 `ret N`; DF;
x87 SW/TW), plus GetLastError, the TEB LastStatusValue and a byte diff of the WHOLE TEB. A
mid-function site sits between a `cmp` and the flag snapshot with every GPR, XMM0-15, YMM upper
halves, a full 8-deep x87 stack with a pending FCOM result, a non-default x87 CW and DF=1 live.
Callback kinds: no-op, send_log(+stack), get_mem/get_func_arg/get_reg, Win32+NT calls on the hit
thread, call_func (APIs that set the last error; a probed function), call_original+return_from
(int / int64 / double return, a double argument, __stdcall, stack alignment, recursion); plus a
thread created by call_func during a hit, get_mem on a page the target later guards /
NOACCESSes / decommits (with a vectored handler counting exceptions), and a callback that
overflows its stack. Every backend, x64 and x86.
- ✅ (TR1) **call_original + return_from lost the original's return registers** on every
  backend: return_from set only AX, and the resume restored the HIT's other registers -- a
  double (x64 XMM0, x86 ST0) or x86 int64 (EDX) came back as garbage. Breakpoint/hw now capture
  the original's integer + FP context at its return; inline x64 `uhh_orig_thunk` stores RCX RDX
  R8-R11 XMM0-5 after the call, inline x86 ECX EDX XMM0-7 and the x87 state (FNSAVE, installed
  after the hit's extended state is restored). With return_from the caller gets them -- except
  AX and any register the callback set_reg'd after call_original. (Merged with the
  calling-convention fixes CC1-CC3 and agent-faultafter: one record of the original's results,
  `OrigPost` in the agent / `CallbackState::post` in the controller, serves return_from and a
  callback that faults after call_original; x86 EDX goes through `probe_x86_return_regs`.)
- ✅ (TR2) **inline x64 call_original ran the original with garbage XMM0-3**: float/double
  arguments were not passed (breakpoint/hw run in place, so they were fine). The thunk now
  loads the hit's XMM0-5 (the calling-convention fix, which also covers vectorcall).
- ✅ (TR3) **inline call_original + return_from hid the original's GetLastError / last NT
  status**: the agent restores both after every callback, to the values from BEFORE the hit.
  When call_original ran they are now restored to what the original left.
- ✅ (TR4) **breakpoint/hw call_func leaked the callee's last error / status** into the program
  (inline hid them): call_func now saves and restores the stopped thread's TEB LastErrorValue
  and LastStatusValue around the call. x86 also restores the XMM registers there
  (CONTEXT_EXTENDED_REGISTERS): a callee's SSE use leaked into a mid-function site on breakpoint
  x86 (hw happened to rewrite the full context afterwards).
- ✅ (TR5) **breakpoint/hw call_func("kernel32!X")** (no `.dll`) did not resolve; inline did
  (GetModuleHandle semantics). A bare module name now also matches `<name>.dll`.
- ✅ (TR6, review a) **the inline XSAVE buffer was sized from CPUID(0xD,0).EBX** (every XCR0
  feature): with AMX (~11 KB) it exceeded the 4 KiB buffer and the hit saved nothing, not even
  MXCSR -- a callback's VZEROUPPER (CRT memcpy) wiped the target's live YMM upper halves. The
  size now comes from the saved components only; without XSAVE, MXCSR is still kept. Test:
  `transparency-inline-xsave-bigarea` (UHH_BENCH_XSTATE=amx simulates the AMX-sized area).
- ✅ (TR7, review b) **x86 inline: the x87 state was not saved** (default mask = AVX only). x86
  code returns floats in ST0, so any callback/CRT float call changes the x87 status/tag/stack a
  mid-function site may have live. The gated mask now includes x87 on x86 when it is in use.
  (x64: not included -- MSVC x64 code never touches x87 -- so x64 hits keep the cheap path.)
- ✅ (TR8, review c) **inline get_mem trusted a per-thread region cache ACROSS hits**: a page the
  target decommitted / NOACCESSed / guarded later faulted (a first-chance AV its vectored
  handler saw) or silently consumed its PAGE_GUARD. The cache now lives for one hit (reset at
  the hit and after call_original).
- ✅ (TR9, review d) **a callback stack overflow was caught without `_resetstkoflw`**: the thread
  (inline: the TARGET's thread) lost its guard page and the program's own next overflow killed
  the process with an access violation. Restored on both the agent and the controller side.
- 📄 Inherent to inline (documented, counted not failed by the check): (1) the callback runs on
  the target thread's stack -- the hook path uses roughly 8-10 KiB (stub context, 4 KiB XSAVE
  area, the callback's frames), so a thread close to its stack limit can overflow where it would
  not have, and committing deeper stack moves TEB StackLimit (`stack_limit_moves`); (2) a
  callback's own heap calls change heap state, including the TEB's per-thread LFH affinity hint
  (`HeapData`, x64 TEB+0x17B0, x86 TEB+0xFA8; `heap_hint_changes`). Neither can be avoided while running C code
  in the target; breakpoint/hw callbacks run in the controller and change neither.
- 📄 Inline call_original is a real call from the agent: the original sees the agent's return
  address (`_ReturnAddress()`, e.g. kernelbase!GetProcAddress's caller-based lookups) and a new
  stack frame for its stack arguments, and is entered with the hit's argument registers (x64
  RCX RDX R8 R9 XMM0-5; x86 EAX ECX EDX XMM0-5 + stack args) but NOT its other registers -- a function with a
  custom register convention (hand-written asm, x86 LTCG internal functions taking ESI/EDI)
  gets garbage there. Breakpoint/hw run the original in place with the full context and have
  none of these limits. Returning through the program's caller would break the CET shadow stack.

## Test-hardening findings (2026-11-06, Codex test review, `scripts/regress.py` / `scripts/soak.py`)
18 checks could pass without testing what they claim (each verified against the code; all 18
real). Each now asserts an independent oracle -- constants and counts computed in Python or
written out literally, return codes, hits == logs + dropped + interrupted, the target's own
result values, strict JSON, multisets -- and missing explicitly-selected prerequisites FAIL.
Checks that now fail are left failing (library code is not changed here):
- ✅ (TH1, resolved: accepted everywhere; header and oracle updated) **`call_func("kernel32!X")` resolves on every backend, but `include/probe_api.h`
  says it is refused** ("module is matched by its file name WITH extension ... "kernel32!X" is
  refused"). Portability P1 made every backend refuse it; transparency TR5 (516358d) then made
  every backend accept it (bare name = `<name>.dll`) without changing the header. The old
  diff-only `portability-matrix-A` could not see it (all three backends agree);
  the absolute oracle does: `portability-matrix-A` FAIL, x64 and x86, all three
  backends: `call_func.no-ext=1 pid=1`, want `0 pid=0`. Decide which is right and make the
  header and the code agree (then update `portability_expect`).
- ✅ (TH2, resolved: a closed live stdout is a warning -- `"live_output_closed":true` in `probe_report` plus a stderr note; `error` and the exit code reflect real failures only; the file stays complete) **A closed stdout makes the session fail**: `logs-stdout-closed-{inline,hw}` -- every
  log IS in the JSONL file (20000/20000, 2000/2000, per-thread order exact; the report written
  to a side file says hits == logs_written, dropped 0), but `probe_report.error` = "tail probe
  logs to stdout (Win32=109/232)" (broken pipe / no process at the other end) and the
  controller exits 1 (`probe_wait_for_exit` fails). A reader going away (`| head`) is normal
  use; the complete file means the session did its job. x64 and x86, same errors.
- ✅ (TH3, resolved: x86 `set_reg` stores `(uint32_t)v` on every backend -- controller and agent -- so `get_reg` returns what the program sees; `return_from` already split EDX:EAX) **x86 `get_reg` returns a value no 32-bit register can hold**: after
  `set_reg(c, r, 0x1_0000_5E0r)` (matrix_callbacks.cpp `pm_on_regs`, deliberately wider than
  the register) `get_reg(c, r)` = `0x100005e0r` for EAX..EBP on breakpoint, hw AND inline
  (`portability-matrix-A` x86: `reg.set.0..6`, `return_from.mid-ax` = `100005e00`), while the
  program sees `0x5e0r` (`target.out` correct). probe_api.h: "Every ID is the full native
  register: ... EAX..EBP/ESP on x86" -- a read-back must be the register's value (low 32 bits).
  All backends agree, so the old diff-only check passed.
- (resolved by the merge of merge-frida, f07e457) `ctrl-inplace` with the exact oracle failed
  before that merge: hits = logs = 1156 of 24000 calls (x64, breakpoint; round 3 #2: missed
  while lifted). After the merge: 24000/24000/24000 distinct.

## Agent scope and bounded detach (owner decisions 2026-11-07, branch `agentscope`)
Two decisions that reverse earlier work:
- **The agent is injected only when the session needs it (inline).** Since L1 every ATTACHED session
  injected `probe_api_agent.dll` -- breakpoint/hw-only ones too -- so its controller-death guard could undo
  INT3s/DRs; bp/hw probes waited (up to 5 s) for it before arming, and a missing agent DLL failed the attach.
  The owner rejected that: an injected DLL in a bp/hw-only target is itself a side effect (gospel), and
  "controller-crash self-unhook: not worth the cost; the analyst sees the controller died and restarts the
  target". Now (as on main f9f3436): the agent goes in at launch/attach if inline probes are registered, or
  lazily when a callback/runtime add requests the first inline probe. bp/hw-only sessions inject nothing,
  arm at the attach's break-in (no 5 s agent wait), and do not need the agent DLL.
  Found on the way (CI + VM PROBE_TRACE, `lifecycle-{reattach,detach-early,interrupt}-hw`): hw-only targets
  died of an unhandled single step at a probed address during the detach drain. A thread created by one of
  ours starts with its CREATE THREAD-time copy of its creator's debug registers; created around the release,
  it carried our released DR images (`dr7=0x415`, all three slots) without being in any release bookkeeping,
  so its #DB was taken for the program's own breakpoint and passed on. Masked since L1: the agent's guard VEH
  swallowed such traps. Now CREATE_THREAD clears, before the thread runs, every enabled slot of a register
  we have used that holds an address we armed (active probes and gates are set again right after). Inline sessions keep the guard (it covers their bp/hw probes
  too; one that acquires the agent later is guarded from then on). Controller death in a bp/hw-only attached
  session is main's behaviour: kill-on-exit is off, so the target is not killed, but it keeps our INT3s/DRs
  and dies at its next hit (0x80000003 / 0x80000004) -- documented in limitations.md.
  Checks: `lifecycle-controller-killed-{breakpoint,hw}` now assert the new rule (no agent module while
  attached; after the kill the target runs on or dies only with our trap code, never another fault or a
  hang; outcomes listed); `lifecycle-reattach-{breakpoint,hw}` assert no agent module after every cycle;
  `lifecycle-agent-refused-{breakpoint,hw}` (a target admitting only Microsoft-signed DLLs) assert a normal
  session with no agent attempt; new `attach-lazy-agent-{breakpoint,hw}` (no agent module until a callback adds
  the first inline probe, then it is injected and that very call is hooked) and `attach-no-agent-dll-*` (the
  agent DLL missing next to the controller: bp/hw work, inline refuses cleanly). Note: breakpoint/hw callbacks
  that use `UHH_SHARED` state still run from the controller's LOCAL copy of the agent DLL (nothing injected),
  so such a controller still needs the file beside it. The guard checks that ran bp/hw-only sessions
  (`cxlib-killarm-*`, `cxlib-reptail-breakpoint`, `cxlib-touchkill-hw`, `cx2-touchprog-hw`,
  `cx2-evsusp-*`, `cx2-cosusp-*`) now add a never-called inline probe (`co_driver --guard`, `co_idle`) so
  they keep testing the guard's coverage of bp/hw state in inline sessions.
- **Bounded detach wait.** Codex library review (4) made a live detach wait without a time limit for inline
  callbacks that can still finish. Now it waits at most 15 s (logs delivered meanwhile), then completes:
  stderr `probe: detach: N callback(s) still running after 15 s; not waiting longer`, the detach line and
  `probe_final` carry `running=` (still executing) and `in_flight=` (of those, not logged yet: hits ==
  logs_written + log_dropped + in_flight); any log they write later is lost. Their config blocks stay
  allocated (the cfgfree keep-alive), so the program is unaffected. `cxlib-late-inline` asserts it (detach
  ~17 s, late log not delivered, running=1, right program result).

## Lifecycle findings (2026-11-06, `examples/lifecycle`, regress `lifecycle-*`)
Target `lifecycle_target` checks ITSELF on command: the code bytes of every probe-able site
(ntdll!NtOpenProcess/NtReadVirtualMemory/NtClose, configparse!ParseConfig incl. the mid-function
flag site +0x16, its own lc_slow/hunt_read) against a snapshot taken before any tool came, the
debug registers and trap flag of EVERY thread (incl. threads born while attached: a churner keeps
creating them), IsDebuggerPresent, flips seen after a detach, and every read verified.
`lifecycle_driver` attaches gated_config's callbacks (flag flip, NtOpenProcess map via
call_original, NtClose, every read logged) plus a probe blocking inside call_original
(lc_slow) and one in a DLL that keeps loading/unloading (hunt_dll!HuntWork), under breakpoint,
hw, inline and mixed. Checks per config: `reattach` (20 attach/detach cycles to one busy
process), `detach-{midcb,longcb,early-N}`, `target-dies`, `two-controllers`, `interrupt`
(Ctrl+Break at 7 points from before the attach to mid-run), `controller-killed`, and (inline,
mixed) `agent-refused`, `install-stuck`. `UHH_LC=substr` narrows. The target is paced (1 ms per
iteration) so breakpoint/hw runs stay at a few hundred hits/s on the shared VM.
Clean from the start: `two-controllers` (the second attach fails with Win32 87 before touching
anything; the first session is undisturbed), `target-dies` (the target killed 0..600 ms into the
attach / agent load / install or right after a detach request: the controller ends its session
by itself, nothing dropped), detach while callbacks run / block in call_original.
- ✅ (L1) Controller killed while attached (TerminateProcess, crash, Ctrl+C before the console
  handler exists): the kernel detaches with kill-on-exit off, but UHH's state stayed in the
  target. breakpoint/hw: INT3s and debug registers live -> the target died at its next hit
  (0x80000003 / 0x80000004, every run); inline: hooks live and every producer spun forever on
  the full log ring (nobody drains it; the 2 s give-up counts only while the drainer heartbeat
  moves) -> the target HUNG. Fixed: a controller-death guard. The agent is now injected into
  every ATTACHED target (breakpoint/hw-only too; launch is unchanged -- a launched target dies
  with its controller by design). The controller mirrors its state into the shared section
  after every debug event (armed INT3s + original bytes, DR slots owned, threads mid-step,
  threads it holds suspended, step blocks) and hands the agent a SYNCHRONIZE handle to itself.
  A first-in-line VEH takes our traps once the process has no debug port (restore the byte /
  clear our DRs / end the step, continue); the agent's service thread, woken when the
  controller process ends, restores every INT3, clears our DR slots and steps on every thread
  (twice: a thread released from a dead debugger's event can come back with its old DRs; and its
  own), resumes threads the controller held, sets controller_gone (logs drop, counted) and removes
  the inline hooks with an in-process freeze (heap lock taken first, all other threads suspended:
  SafetyHook's own unfrozen path makes the ntdll stub page non-executable and faulted the
  installer, 0xC0000005). Breakpoint/hw probes of an attach arm only once the guard is up (agent
  init done, or given up after 5 s / on load failure, with a warning), so no unguarded trap ever
  exists. `lifecycle-controller-killed-*` **Narrowed by owner decision 2026-11-07: the agent (and the
  guard) is only in sessions with an inline probe; breakpoint/hw-only targets get nothing injected and
  are not guarded -- see "Agent scope and bounded detach".**
- ✅ (L2) Ctrl+C (or any controller death) between DebugActiveProcess and
  DebugSetProcessKillOnExit(FALSE): the debug object is created kill-on-close, so the target was
  killed with it (exit 0xC0000354, seen twice in 7 Ctrl+Break timings on hw). Now the thread's
  debug object is created first (DbgUiConnectToDbg) and kill-on-exit turned off before the
  attach. `lifecycle-interrupt-*`
- ✅ (L3) Detach never finished on a target that keeps creating threads or loading DLLs (36 s ..
  > 120 s, breakpoint/hw; also Ctrl+Break): the post-restore drain waited for 200 ms without ANY
  debug event. Now only exceptions extend it, and it is bounded (5 s). `lifecycle-detach-early-*`,
  `lifecycle-reattach-*`, `lifecycle-interrupt-*`
- ✅ (L4) Events dispatched DURING a detach armed things after they had been removed: a DLL
  reloading during the drain got a fresh INT3 (the detached target died 0x80000003 at
  hunt_dll!HuntWork), a new thread inherited inline-install gates (DRs left after detach), the
  initial breakpoint / an agent load completing started an agent init AFTER the stop (Ctrl+C
  50-150 ms into an inline attach left every hook live in the detached target), and a held-
  thread fallback re-held threads the in-flight agent work then waited on. A `detaching` flag
  set at the start of detach stops arming, gating, holding and any new agent work.
  `lifecycle-detach-early-*`, `lifecycle-interrupt-*`
- ✅ (L5) Inline install racing a module unload: create_mid read the site of a DLL another thread
  had just unloaded -> access violation on the agent's thread -> the TARGET died (0xC0000005,
  3 of 4 early detaches on inline/mixed with DLL churn). The agent now skips a site that is not
  mapped executable code (stays pending until its module loads again) and SEH-guards the build
  and the write: an unmap racing them fails that one hook (abandoned, never touched again).
  Pinning the module was tried and rejected: GetModuleHandleEx/FreeLibrary wait on the loader,
  which a thread held mid-load (no DR free for gates) blocks -- the install then stalled past the
  detach's 5 s wait. `lifecycle-detach-early-*-{inline,mixed}` (The same race on the REMOVE side -- the final unhook
  of a site its DLL had just left -- was fixed later: "CI residuals" R3, `lifecycle-unload-unseen-*`.)
- ✅ (L6) Stale UNLOAD_DLL (reported after the same DLL was mapped again at the same base and its
  LOAD handled) retired the probe just armed in the NEW instance: its INT3 was never removed at
  detach. An image mapped at that base when the unload is processed now means the event is stale
  and is ignored (also the A8 ordering). `lifecycle-detach-early-*-breakpoint`
- ✅ (L7, review A) probe_run leaving its loop on an error (agent load/init failure, a failed
  context get/set or debug wait) left the attached target with live INT3s/DRs and no event loop
  (it froze at its next debug event and died when the controller exited), and set controller_gone
  with hooks still live; a probe_close from another thread then "detached" from a thread that
  does not own the debug object. Now probe_run detaches on its own (debug) thread before leaving
  (the error is kept), and probe_attach failures leave the session un-attached (probe_close used to
  wait forever for a probe_run that never came). Reproduced with a target that admits only
  Microsoft-signed DLLs (the agent is refused mid-attach). `lifecycle-agent-refused-{inline,mixed}`
- ✅ (L8, review B) Detach with agent load/init still in flight after 5 s (the target holds its
  loader lock, so the remote thread cannot even start) skipped the agent stop; the stale init ran
  later and hooked the detached target (seen: it died 0xC0000005). Now the detach marks the
  session over first (controller_gone) and the agent installs nothing for a session that is over.
  `lifecycle-install-stuck-{inline,mixed}`
- ✅ (L9) Logs of inline callbacks still running at detach (longer than the agent's 2 s unhook
  wait) were dropped (controller_gone set at once). The controller now keeps draining until no
  callback is in flight (bounded 15 s) before telling producers nobody listens. (Since the Codex
  library review: unbounded while a callback can still finish -- see there, finding 4.)
  `lifecycle-detach-longcb-*`
- ✅ (L10) The debug register a breakpoint/hw call_original borrows to catch the return was not
  counted as ours: the detach's final pass and the guard did not clear it (x86: its address stayed
  on every worker after detach; controller killed mid-call: 0x80000004 at the return address).
  It now joins the owned slots; with no slot left enabled the DR7 exact bits (LE/GE, which WOW64
  leaves set) are cleared too. Note: on WOW64 a zeroed address in a DISABLED slot is not always
  propagated -- inert (never fires); the target reports it as `dr_stale`, not as a breakpoint.
- Verification (2026-11-06, VM): x86 `--only lifecycle` 48/48 PASS (all four configs; hw run in
  <2 min chunks via UHH_LC), x86 `--only interrupt` 3/3, `--only attach` 11/11, `--only gated` 17/17.
  x64: every lifecycle-* check PASSED on the final code in some run, `--only interrupt` 3/3,
  `--only gated` 17/17, `--only attach` 11/11 (attach-new-inline failed once "probe never became
  active", then passed 3 runs in a row -- looks like a load flake, not re-investigated).
- ✅ (L11, runner signature, runfix2) controller killed early in an inline/mixed attach -> target 0xC0000005 with no
  unhandled report: the agent wrote an install round UNFROZEN when its FREEZE raise came back unserviced (SafetyHook's
  trap path made the ntdll stub page non-executable). Fixed in the agent; `lifecycle-killed-in-freeze-*` (CI section,
  "Runner findings").
- 🔧 (L11, likely fixed) x64 `lifecycle-controller-killed-breakpoint` was intermittent (1 of 4 kill timings fails
  in ~1 of 3 runs): the target still dies after the controller is killed, 0x80000004 at
  lifecycle_target+0x194d (a return address -- call_original's in-place run / its return-catch
  DR) or once 0x80000003. Mitigations added in order (each reduced it): call_original's DR slot
  mirrored into the guard before the thread runs; addresses the cleanup cleared remembered for
  #DBs already in flight; a single-step on a thread with no DR of its own taken as ours once the
  debug port is gone; our INT3/DR traps acted on even before the kernel clears the debug port
  (last change: with it, x64 controller-killed-{breakpoint x4, hw, inline, mixed} + reattach/
  interrupt-{breakpoint,inline} all PASSED; the x86 suite was not re-run on this last guard change,
  and 4 clean runs do not prove the race gone -- keep watching). Next step if it recurs: log
  (OutputDebugString-free: a shared counter) which VEH branch rejects the trap, and check whether
  the dying debugger leaves TF set on a thread in the middle of the in-place call_original.
- Test infra notes: `UHH_LC=substr[,substr]` narrows lifecycle checks; lifecycle_driver links the
  STATIC probe_api, so rebuild lifecycle_driver (not only probe_api) after session.cpp changes;
  the target is paced (`--pace-ms 1`) except inline controller-killed (needs the ring to fill).
- Residual / by design: a breakpoint/hw call_func running in the target when the controller dies
  (the thread's context was redirected to the callee and is never restored); suspensions taken
  inside a single debug event and not yet mirrored when the controller dies (microseconds); the
  guard's VEH and the agent stay in the target after detach (as the inline agent always did);
  a target's own debugger-free INT3 at one of our sites while orphaned, and any single-step on a
  thread without debug registers of its own once the controller is gone, are taken as ours
  (a program single-stepping itself after its controller died would lose those steps).
- ✅ (L12, found at the merge) The guard never resumed a thread the controller held suspended:
  the held handles (install holds, hook-write freezes, call_original/call_func deferrals) were
  opened without THREAD_QUERY_LIMITED_INFORMATION, so GetThreadId returned 0 and the mirrored
  held list was all zeros. After a controller kill the target ran on with those threads parked
  for good (x64 breakpoint: 1-3 workers suspended at their NtReadVirtualMemory/NtClose hit, rewound
  by a call_original deferral, in 4 of 7 runs on eval-lifecycle itself; invisible to the check
  except as a 60 s quit). Now opened with query rights, mirrored after the in-place window's own
  bookkeeping (inplace_sync), and resumed once per hold. lifecycle_target's quit report now
  carries `late` (workers not ended 15 s after quit) and `stuck` (threads left suspended:
  tid:count:ip), and every lifecycle check fails on either. `lifecycle-controller-killed-*`
- ✅ (L13, found at the merge, x86) With L12 fixed, x86 controller-killed-{breakpoint,hw,mixed}
  still left ONE thread suspended in ~half the runs, parked at its NtOpenProcess hit (site or
  site+1: the thread whose event the controller was handling). A 32-bit controller runs under
  WOW64, where Get/SetThreadContext on another thread is an implicit suspend + resume inside the
  call: killed in between, it leaves that thread suspended once with nothing of ours recording
  it. The guard now also lists the threads whose events are being handled (nested ones too,
  call_original) and the call_original/call_func thread, each published before the controller
  touches it; one resume for each is a no-op on a thread that is not suspended. Every other hold
  is published to the guard BEFORE the suspension (guard_note_hold), incl. detach's own freeze.
  Defensive, same commit: after the controller process ends, the agent polls (10 ms, <= 30 s) for
  its debug port to go instead of waiting for a trap to wake it. x86 bp+hw 10/10 (was 8 of 16
  failing). Residual (closed by the Codex library review, see there): a WOW64 implicit suspend of a
  thread that is neither the event's nor the call's (e.g. arming a hardware probe on every thread) was not covered; the guard's extra
  resume can undo a suspension the PROGRAM made of one of those threads at that instant.
- Merge verification (2026-11-06, VM, after L12/L13): `--only lifecycle,interrupt,attach,gated,detach,
  transparency,callorig,callfunc` 151/151 on x64 and 151/151 on x86; L11
  (`lifecycle-controller-killed-breakpoint`, now also failing on a thread left suspended) 11/11 on x64
  and 6/6 on x86 on the final code, no unhandled #DB/INT3 seen in any run since the merge.
- Merged into merge-frida (agent protocol v19 = v18 + the guard): the guard takes the armed INT3s
  from merge-frida's INT3 table (every armed breakpoint, sorted; was its own 512-entry copy, so a
  session with more breakpoints left the rest unguarded), resumes the threads an in-place step
  window holds suspended (`inplace_suspended`) along with install holds / hook-write freezes /
  call_func deferrals, is re-mirrored when holds are released outside a debug event, and its VEH
  is registered after the trampoline-fault VEH (so it is first in line). The cleanup's unhook no
  longer raises the FREEZE IPC with no debugger attached (it went to the program's own VEHs as a
  stray 0xE0554848): it freezes in-process directly. The 65536-INT3 limit applies, as
  documented, only alongside inline probes (an attach's channel no longer implies it).

## Codex library review findings (2026-11-06, merge-frida vs main, regress `cxlib-*`)
A read-only Codex review of every library change since the last release reported 5 bugs (static
reading only, all "high confidence"). Each was checked against the code and reproduced by a check
that FAILED on the unfixed code (commit 6e06b7b: the checks + test hooks only) before the fix.
Fixtures: new `examples/hunt_callorig` cases (`cbfault`, `late`, `cfgfree`, `spin`, `rep`) and
`co_driver_th` = co_driver linked with `probe_api_testhooks`, a TEST-ONLY build of the controller
(`UHH_TEST_HOOKS`: fault-injection points such as "the controller dies right after writing an
INT3"); nothing shipped links it. `--only cxlib`.
- ✅ (1) **Real.** A breakpoint/hw callback that faulted after `call_original` was recovered by restoring
  the registers only: the hit fell through and ran the original a SECOND time (fault after call_original
  without return_from), or returned the hit's entry AX (fault after return_from); a faulting callback that
  had called return_from without call_original returned entry AX instead of being a no-op. Reproduced:
  `cxlib-cbfault-{breakpoint,hw}` rets=[5, 1, 2, 14, 3, 2, ...] body runs per call `210210210` (want every
  call's own result, +1000 after return_from, `111111111`); inline was already exact. Now identical to
  inline (run_callback): after call_original the hit returns to its caller with return_from's value if one
  was set, else the original's result (x86: EDX:EAX and its measured `ret N`), plus every volatile register
  and the FP state the original left; otherwise the fault drops the return_from and the original runs once.
  `cxlib-cbfault-*` 3/3 on x64 and x86.
- ✅ (2) **Real.** probe_close freed the target block of an oversized (> 256 B) inline config even with a
  callback still in flight (thread suspended by the program across the detach, or running past the drain):
  its get_config then read freed memory (the callback faulted and was abandoned; the hit fell through).
  Reproduced: `cxlib-cfgfree-inline` / `cxlib-late-inline` target ret=8 (the original's) instead of the
  config checksum. Config blocks now have their own list and stay in a detached target while any callback
  is in flight (stderr says so: a deliberate, bounded leak, one block per oversized inline config).
- ✅ (3) **Real.** arm_breakpoint wrote the INT3 and only then published it to the guard's INT3 table; arm_hw
  set the DR on every thread before the slot joined the guard's DR mask. Reproduced with the test-hook build
  killing the controller right after the write (`UHH_TEST_DIE_AFTER_ARM=1`): the target died at its next
  call, 0x80000003 (`cxlib-killarm-breakpoint`) / 0x80000004 (`cxlib-killarm-hw`), x64 and x86. Now both are
  published (and the guard enabled) BEFORE the write; a failed write is unpublished. Also found: the end of a
  displaced REP string copy is an INT3 in our scratch (no trap flag) the guard did not know -- a controller
  death with a thread inside such a copy killed the target; the guard's VEH now steps over an INT3 in our
  scratch blocks to the copy's jump back (`cxlib-reptail-breakpoint`, test hook `UHH_TEST_DIE_IN_REPCOPY`).
- ✅ (4) **Real**, and worse than reported. The drain after a live-controller detach gave up after 15 s
  with callbacks still running (their later logs dropped), and in practice even sooner: the agent's stop
  waited `2000 x Sleep(1)` -- ~31 s at the default timer, not 2 s -- so a callback running past the
  controller's 5 s wait for the stop thread made the detach skip the drain altogether. Reproduced:
  `cxlib-late-inline` (a callback logging 19 s into the detach): late log delivered=0, summary in_flight=1.
  Design that does not drop: the drain asks the agent (protocol v20: `live_query` / `live_callbacks`,
  answered by its service thread) how many in-flight callbacks can still finish -- thread alive, not
  suspended, still inside its callback (its record's frame on the stack, canary intact) -- and keeps
  delivering for as long as any can, with no time bound (progress on stderr every 15 s; a slow detach is
  reported, never cut short). The agent's stop waits 2 s of wall time. 📄 Not waited for, by design: a
  callback whose thread is dead, suspended by the program (`cxlib-cfgfree-inline`: the detach takes ~2 s,
  in_flight=1) or left through a non-unwinding longjmp; it stays counted in flight (detach summary
  `in_flight`), and a log it sends if the program resumes it after the detach is counted dropped in the
  target (nobody can receive it). Without an answer from the agent (no service thread) the old 15 s bound
  applies. A callback that never returns (deadlocked) now keeps the detach waiting.
  **Bounded again by owner decision 2026-11-07** (see "Agent scope"): the wait is not needed for the
  program's correctness and an unbounded detach is worse. The detach now waits at most 15 s for running
  callbacks (still delivering their logs), then completes and accounts them (`running=`, `in_flight=`; any
  later log is lost); `cxlib-late-inline` asserts that.
- ✅ (5) **Real** (x86 only: x64 callbacks use no x87). Without OSXSAVE the inline hit saved MXCSR only; a
  callback's float work (x86 returns floats in ST0) changed a live x87 stack / status word at a
  mid-function site. Reproduced on the VM's OSXSAVE CPU with the knob `UHH_BENCH_XSTATE=noxsave` (xstate_mode
  3: the no-XSAVE fallback; the AVX state this CPU has is still kept by XSAVE, since a CPU without OSXSAVE has
  none): x86 `cxlib-noxsave-inline` bad=30 `first='mid iter 0: x87 ...'` (transparency `mid` with a full x87
  stack, callbacks doing float math). The fallback now FXSAVEs/FXRSTORs (x87 + MXCSR) around the callback.
  The knob is an env var like the existing `none`/`full`/`amx` bench knobs (inert unless set).
- ✅ (TF, from the Codex test review) The breakpoint backend let the program's own handler see UHH's trap
  flag: an instruction faulting during its in-place step reached the program with the context as it
  faulted (x64; WOW64 drops TF). `ctrl-fault-*` / `cdx-faultreg-*` now require tf == 0 on every backend;
  x64 breakpoint failed (tf_in_handler=200 of 200). Now that fault is swallowed once and the instruction
  re-run without our flag (byte still lifted, window held, a consumed guard page re-armed): its second
  fault, with the program's own flags, is passed on. A re-run that does not fault again re-arms the site at
  the thread's next event or by the window watchdog. The restart is recognised as on x86 (the thread's next
  event is the INT3 at the site). 📄 x64 now shares x86's residual: a handler that continues ELSEWHERE and
  whose thread's very next event is a new call at the same site is taken for the restart (no callback).
- ✅ (L13 residual) x86 controller: a WOW64 Get/SetThreadContext on a thread that is neither the event's nor
  the call's (arming/releasing a hw probe on every thread, gates, the detach fix-ups, moving a frozen thread
  into a trampoline) is an implicit suspend; killed inside it, the controller left that thread suspended.
  Each such call now lists the thread in the guard's held list for its duration (GuardTouch).
  `cxlib-touchkill-hw` (x86; SKIP on x64) simulates it in the test-hook build (the controller suspends the
  target's main thread at its first touch and dies); a control run without the record leaves the target
  hung.
- Verification (2026-11-06, VM). Before (6e06b7b, checks only), x64 and x86: cbfault-{breakpoint,hw}, late,
  cfgfree, killarm-{breakpoint,hw}, noxsave FAIL (x64 noxsave failed on YMM: the knob's first version broke
  the AVX state itself; fixed in 4c0e61c, the x86 run failed on x87 as intended); ctrl-fault-breakpoint /
  cdx-faultreg-breakpoint FAIL on x64 only (tf_in_handler=200; WOW64 drops TF). A second snapshot with only
  the REP-tail rule and the FXSAVE fallback reverted: reptail FAIL (0x80000003) on both, x86 noxsave FAIL
  (x87 SW/TW 0041/c000 vs 0000/0000). After (9aef7c1): `--only cxlib,ctrl-review,cdx-review` 38/38 + 1 SKIP
  (touchkill: x86 only) on x64 (cxlib 9/9 on the final build), 39/39 on x86; `--only callorig,lifecycle,
  detach,interrupt,conformance,transparency,agent_review,gated` 146/146 on x64 and 146/146 on x86.

## hw ONCE / ntdll-churn findings (2026-11-06, regress `hw-once-slots-*`, `ntdll-churn-*`, `cdx-owndrx-*`, `ctrl-owndr-*`)
- ✅ (H1) hw: **target killed by STATUS_SINGLE_STEP after a PROBE_ONCE hw probe retired** (`hw-once-slots`
  failed on every run since the Codex controller review, x64 and x86: the ONCE probes fired once, then a
  worker died at HwSite / after the `lock inc` on g_w1). Cause: a thread still STARTING (in
  LdrInitializeThunk) at the release ran past our DR clear and then restored, by NtContinue, the DR image
  captured at its first entry to user mode -- the released slots enabled again (PROBE_TRACE: dr7 0x455 ->
  0x44 at the release, 0x455 at the thread's first hit). Per-thread hw retirement (c487aa2) took such a
  slot for the target's own once the thread "had run" since the release, so its #DB was passed to the
  program. Bisect (x64, `--only hw_once` x3): 358b98d 6/6 PASS, c487aa2 6/6 FAIL. The same stale image
  is what left a released one-shot slot looking taken in `ctrl-owndr` / `cdx-owndrx` (`[-1,50,50,50]`).
  Fix: released addresses are remembered until re-armed (`hw_released`); a release while the process
  runs arms the thread-start fixup (INT3 at RtlUserThreadStart, which already re-applied ACTIVE DRs after
  that restore), and the fixup now also clears an enabled image of a released address there (nothing
  of the program has set the thread's DRs yet: the restore wiped whatever start-up code set). The
  target's own later use of a released address stays its own (`cdx-owndrx`).
- ✅ (H2) hw: closes F2's open item. Writing another thread's debug registers zeroes its DR6, also the
  status of a #DB already QUEUED there (PROBE_TRACE: dr6 0xffff0ff3 -> 0 across our write); an execute hit
  was recovered by address, a WATCHPOINT hit arrived with no B-bit and was passed to the target. Every
  all-thread DR write (arm, release, gates, entry re-apply) now keeps the status read just before it with
  the thread's registers; at the thread's next event, unchanged registers mean that event is the queued
  #DB and the status is carried into its handling.
  Verification on hwonce with merge-frida 32d7d36 merged: `hw-once-slots` 5/5 x (breakpoint, inline) on x64
  and x86; strict `ctrl-owndr-*` / `cdx-owndrx-*` (`--only ctrl_review,cdx_review`, 29/29) 3/3 per arch,
  plus 6 more runs of each owndr fixture x every backend per arch, all exact (before: breakpoint 1/3,
  hw 2/3, inline 1/6 failing on 4d74322); `--only watchpoint,dynwatch,edge,entry_hold,callorig,lifecycle`
  149/149 x64, 143/144 x86 (`lifecycle-target-dies-breakpoint` kill@detach once without final
  accounting; 16/16 on 4 reruns of every target-dies config; breakpoint config: no hw code involved).
- ✅ (H3) `ntdll-churn-inline` fitted only 2-4 attach/hook/detach cycles (hw/breakpoint 10-12) before the
  target's fixed 4 x 4,000,000 reads ended. Measured per cycle (x64): attach incl. uhh_trace start 0.4-3.0 s
  on every backend, hook active 0.05-0.1 s later; then inline is dominated by its own logs -- callbacks run
  at full speed, every call is logged, none dropped, and the hook stays in while uhh_trace's report drains
  them: 0.3-5.4 M log lines per cycle, 2.9-16.8 s (hw/breakpoint ~2-3 k hits, 1.2-2.6 s); the
  uninstrumented run is ~6.8 s. Inherent to logging every call, no stray wait. The check now keeps the
  target reading until told to stop (probe_app `--until-key`: rounds of the same read pattern, "rounds" in
  its app line) and runs exactly 8 cycles on every backend: every cycle detached with hits (after the
  first), stdout logs == the detach line's hits == logs_written, none dropped; exit 0, reads and checksum
  exactly rounds x an uninstrumented round's. Log lines are counted as they stream (the old check held
  millions of parsed lines in Python memory). With the streaming reader, inline cycles took 1.0-2.9 s on
  x64 and 1.2-8.0 s on x86 (hw/breakpoint 0.9-3.3 s): 3/3 PASS per arch, 8 cycles each, rounds 2-5.

## E2E gated_config evaluator findings (2026-11-06, regress `gated-e2e-*`)
The flagship use case end to end against ground truth written by the TARGET itself.
`probe_app --churn --truth FILE` opens its helpers, reads them and closes them over and over:
first serially (a freed handle value is handed out again at once, for the next helper's pid),
then 8 threads x 16 rounds at once. Opens alternate ntdll!NtOpenProcess (OpenThunk) and
kernel32!OpenProcess, reads (1..256 bytes) alternate ReadThunk and kernel32!ReadProcessMemory,
and every third cycle reads once through a DUPLICATE of the helper's CreateProcess handle
(NtDuplicateObject: the open probe never sees it, and it nearly always gets the value just
closed). Each operation is recorded by the thread that made it (tid, handle, pid, address,
size, in order). Per run: 136 opens, 374 reads (46 through duplicates), 182 closes, handle
values reused for different pids (4-34 per run), and 42-46 of the 46 duplicates on a value the map knew.
`--parse-early` loads configparse.dll and parses the config once before the gate.
The drivers gained per-role backends: `gated_config --close-backend`, and
`uhh_attach --open/close/read-backend` with optional `--pid`/`--range`.
- Matrix: every assignment of flag / open / close / read to {breakpoint, hw, inline} (81) x
  {launch (gated_config); attach-pre (uhh_attach at the gate, configparse.dll not loaded: the flag
  probe is pending); attach-post (configparse.dll loaded and parsed once before the attach: the
  flag probe arms on a loaded module, the reload counts)} = 243 runs per arch, ~3.5 min x64 and
  ~5 min x86. Asserted exactly in each run:
  - one flag hit and one override;
  - per target thread, the delivered `open`/`map`/`read` logs equal the target's own record in
    order: the right pid for a reused handle, no unmapped read, and a duplicate-handle read logged
    pid=0;
  - read hits == read logs == truth reads, open hits == truth opens;
  - logs_written == probe_log lines on stdout == records in the session file, and log_dropped ==
    callbacks_interrupted == 0;
  - no warning or refusal on stderr, the checksum equal to an uninstrumented run, exit 0.
  **x64 244/244 PASS, x86 244/244 PASS** (243 combinations + baseline), twice per arch (the second time inside
  `--only gated,attach,callorig,quickstart`: 322/322 on x64 and on x86).
- No combination is refused. At most 4 probes are hw, and with all four on hw (fhw-ohw-chw-rhw),
  call_original on the hw open borrows that probe's own debug register (session.cpp
  call_original_in_place). The `close_backend_for` comment in callbacks.h said a 4th hw probe
  would leave call_original without a register. That is outdated; the comment is corrected.
  close_backend_for stays the default (a close is rare; bp costs nothing).
- Sensitivity control: with `forget_closed_handle` disabled (a VM-only mutation, reverted), every
  sampled combination FAILs: the duplicate-handle read is logged with the stale pid of the closed
  handle (e.g. `want ('read', 0x140, 0, '?') got ('read', 0x140, 8564, 'probe_app.exe')`). So the
  close probe is load-bearing and the evaluator sees it.
- No library discrepancy found: the UHH_SHARED handle map is exact across every backend mix and
  both attach timings, on both arches (C7's mixed-backend test item is closed by this).
- Open: these are functional sizes. A long mixed-backend churn soak (`scripts/soak.py` has no
  churn phase) and the UHH_SHARED per-hit benchmark (C7) are not done.
## Codex review 2 findings (2026-11-06, code merged that day, regress `cx2-*`)
A second read-only Codex review (merge-frida 6f0c533) reported 3 high-confidence bugs. Each was
reproduced by a check that FAILED on the unfixed library (commit 85fd858 + the fixtures only),
then fixed. Fixtures: `ctrl_target faultmix`, `co_target susp / many / manydead`. `--only cx2`.
- ✅ (X1) **Real.** breakpoint (647130f): after a faulting probed instruction was passed to the program,
  the thread's next INT3 at the site was always taken for the handler's RETRY -- also when the handler
  had SKIPPED the instruction or UNWOUND out of it (SEH `__except`) and the next call executed the site
  afresh: no callback, no hit (gospel: hits == logs, identical across backends). Reproduced:
  `cx2-faultfresh-breakpoint` hits=101 logs=101 of 300 calls (retry / skip / unwind in turn), x64 and
  x86; hw and inline 300/300. Fix (`fault_retried`): the exception's dispatcher frame, still on the
  thread's stack below the faulting SP, decides. A retry is the first instruction after the handler's
  CONTEXT was restored: that CONTEXT names the site and holds exactly the thread's registers (whatever
  the handler repaired); after a skip it names another address, after an unwind it no longer matches
  (x86: RtlUnwind marks the paired EXCEPTION_RECORD unwinding). The program never sees a trap flag
  (ctrl-fault-*, cdx-faultreg-* unchanged). After: 300/300 on every backend, x64 and x86.
  Residual: a hand-rolled x86 unwind (no RtlUnwind) whose next execution of the site has every
  register identical and the stack below untouched is still taken for a retry.
- ✅ (X2) **Real.** x86 controller (d7140db): GuardTouch listed a thread touched by a WOW64
  Get/SetThreadContext (an implicit suspend inside the call) as an unconditional guard hold. A
  controller killed while the entry was published but the implicit suspension was not in place
  (before the call, or after it returned) made the guard resume a suspension the PROGRAM held.
  Reproduced (test-hook build, `UHH_TEST_DIE_IN_TOUCH_MODE=before`): `cx2-touchprog-hw` the program's
  ResumeThread returned 0 (want 1), its suspended worker ran 20-21 iterations. Fix: guard entries carry
  a floor (`probe_agent_guard::held_floor`, protocol v21): GuardTouch records the thread's suspend
  count before the call and the guard resumes it only while the count is above that (conditional
  entries first, then our own holds once each). The count is NtQueryInformationThread
  ThreadSuspendCount, which INCLUDES the debug freeze (+1 on every thread while the target is stopped
  at an event; measured: a program-suspended thread read 2 inside an event, a running one 1 -- the
  first version of this fix therefore left `cxlib-touchkill-hw` hung); the freeze is read off the
  agent's service thread, which nobody suspends (`guard.service_tid`), and subtracted. Unknown
  (no agent service thread, Windows < 8.1): an unconditional entry, as before. The check runs both
  deaths -- before the implicit suspension and with it in place (on a program-suspended thread):
  the guard must leave exactly the program's one suspension. After: PASS; `cxlib-touchkill-hw` PASS.
  Open note (same class) -- ✅ closed by the follow-ups (F4 below): guard_sync's unconditional
  entries for the event threads and the call_func/call_original thread (`handling`, `in_call_tid`)
  stayed listed until the next sync, i.e. past ContinueDebugEvent; a program that suspended such a
  thread right then and a controller death before the next event released it.
- ✅ (X3) **Real.** inline agent: the thread table held 4096 thread ids and never freed a slot, so
  after 4096 distinct probe-hitting threads over the process's life every further thread ran its
  callbacks untracked (no active record): the detach drain counted 0 live callbacks, gave up after
  three answers and the callback's log was lost (in_flight=1); such threads also had no recursion
  guard (call_func refused). Reproduced: `cx2-manythreads-inline` / `cx2-manydead-inline` (4200 threads
  alive at once, one hit each, then a callback outliving a detach, while they live / after they
  exited): late log delivered=0, in_flight=1, x64 and x86. Fix: a full table takes over a dead
  thread's slot (marked moving while the owner is re-checked, one sweeper at a time, its own hits
  pass through); with more than 4096 such threads alive an overflow table (256) holds the rest; a
  thread with no slot at all is counted live by the drain (`g_untracked_running`). After: PASS both.
- Verification (e4efa5d): `--only cx2` 2 x 5/5 + 1 SKIP on x64, 2 x 6/6 on x86; `--only ctrl,cdx,cxlib,
  lifecycle,detach,callorig` 138/138 on x86, 136/137 + 1 SKIP on x64 -- `cxlib-killarm-hw` once:
  "controller-death guard unavailable (agent not ready within 5 s)" under VM load, so the hw probe was
  armed without the guard; `--only cxlib` 3 x 9/9 on reruns.

## Follow-ups (2026-11-07, branch `followups`, regress `stream-live-*`, `realbig-robocopy-detach-*`, `lifecycle-target-dies-*`, `cx2-evsusp-*` / `cx2-cosusp-*`)
- ✅ (F1, test-side) **`stream-live-*` absolute p99 bound vs a loaded machine.** Same build, VM under load:
  p99 0.7-253 ms over 18 runs with every log delivered; one FAIL at 253 ms (x86 breakpoint), earlier 1102 ms
  (x64 hw). Fix: the stream-latency calibration (citune) applied -- an uninstrumented writer (logstream_target,
  a QPC-stamped line every ~5 ms) runs alongside as the noise sampler; arrivals are stamped with
  QueryPerformanceCounter (the target's own clock, us). Quiet run (the sampler saw < 50 ms of stall): p99 < 250 ms
  absolute, as before; noisy: p99 of (lag - the stall the sampler saw in that log's own window [event, arrival])
  < 250 ms, so a real UHH latency regression on top of the machine's stalls still fails. TEMP = the build dir's
  `uhh-latency-tmp` (as stream-latency: the profile's AV scan of the session file is not UHH's pipeline). Also
  required as before: every log delivered, >= 90% before the target's final line. `_NoiseSampler.noise` is indexed
  (bisect; equal to the old scan on random data) for ~31k samples per inline run. Evidence: VM (shared, other
  agents' builds running) 3 runs x 3 backends per arch, 18/18 PASS: inline p99 11.6-74 ms, hw/breakpoint 0.9-144
  ms; one x86 hw run was noisy (sampler stall 114.7 ms: judged on p99 net of it, 2.0 ms). CI: 10 runs per arch
  (2 full-suite pushes + 2 x 4 repetitions, branch `followups-reps`), all PASS. Not discounted, reported:
  `disk_run_max` (the sampler's own 120-byte appends) -- one quiet x86 inline run had a 622 ms disk stall and a
  724 ms lag_max (p99 74 ms): a stall of the session file's disk still delays the writer's next batch (as in
  stream-latency, by design not discounted); it would fail only if it held > 1% of the samples. The earlier
  253 / 1102 ms failures could not be reproduced on demand (no before/after pair): they were single runs under load.
- ✅ (F2, test-side) **`realbig-robocopy-detach-*` "robocopy ended during the attach"** (CI 42213960508, x86
  breakpoint: a fast runner finished the whole copy during the attach; accounting exact). Fix: a gate -- the last
  file of the tree in robocopy's order is held open with no sharing until the detach and the residue check are
  done; robocopy (`/R:600 /W:1` in this scenario) retries it and finishes after the gate opens, exit 1, the copy
  exact. On any machine the detach now lands while robocopy runs; `files_at_detach` reports how far the copy had
  got. Before: merge-frida 921820c's CI (42225208495) failed this row on x64 AND x86. After: VM 2 runs per arch PASS
  (files_at_detach 347-4266 of 10000, exit 1, copy exact, residue clean); CI 10 runs per arch PASS.
- ✅ (F3) **No final accounting when the target dies right after a detach request** (x86
  `lifecycle-target-dies-breakpoint`, ~1 in 20). Cause: probe_close from another thread asks probe_run to detach;
  a target killed 0-5 ms later can end the session on its EXIT_PROCESS before probe_run acts on the request. Then
  probe_run returns with the target exited and NOT detached, so probe_close printed no `probe: detached:` line --
  and the caller had no way left to take the totals (lifecycle_driver's runner had yielded the report to the
  closing thread; the session is gone after probe_close). Fix: probe_close prints `probe: ended: the target exited
  before the detach (exit code N): hits= logs_written= log_dropped= in_flight=` (in_flight: callbacks the end
  interrupted, as probe_report's callbacks_interrupted) whenever it asked a live session to stop and the target
  ended first. Checks: `lifecycle-target-dies-*` gains `detach0` (killed at once after the request) and `late`
  (test-hook `lifecycle_driver_th`, `UHH_TEST_STOP_LATE_MS=400`: probe_run acts on the request 400 ms late while
  dispatching, the target dies 50 ms after it -- the race forced; must report via `probe: ended:`). Before (VM,
  test hooks on 921820c's library): `late` FAILED 16/16 (4 configs x 2 runs x 2 arches, "no final accounting"),
  and the natural race once more (x86 mixed `detach0`); 48 runs of `detach`/`detach0` without the hook passed
  otherwise. After: VM 6 runs x 4 configs per arch PASS; `late` reported via `probe: ended:` 48/48, the natural race
  hit once more (x86 `detach0`) and also reported `ended`; CI 10 runs per arch PASS (`late` in 5 of them).
- ✅ (F4) **Guard event/call-thread window (X2 open note).** The controller-death guard listed, unconditionally,
  each thread whose event was being handled until the NEXT guard sync (past its ContinueDebugEvent), the
  call_original thread and every call_func callee thread for the whole call, and call_original's 20 ms poll
  appended one entry per poll until the next event. A program that suspended such a thread after it ran on, then
  a controller death: the guard resumed it, releasing the PROGRAM's suspension (side effect). Reproduced (new
  `susp_target`, driven by `co_driver_th --module susp_target.exe`): `cx2-evsusp-<b>` -- the test-hook build
  (`UHH_TEST_DIE_AFTER_HIT_MS=1500`) dies 1.5 s after continuing a probe hit's last event while the program has
  suspended that thread (no event, no sync in between); `cx2-cosusp-<b>` -- the controller is killed while
  call_original runs the original on a thread the program suspended. Before (unfixed library, VM): all four FAIL
  on x64 and on x86, 2 of 2 runs per arch (the program's ResumeThread returned 0, want 1; the worker ran 17-21
  iterations while "suspended"; the dying controller's guard list held the worker). Fix (a list of exactly the
  suspensions in place, no new protocol): the handling of an event records whether its thread runs again
  (call_func / call_original continued it, or call_original released it); guard_sync lists only stopped ones (at
  the event, or suspended by us for the rest of the handling) plus call_func threads held by us (`call_held`);
  the list is rewritten right before every continue of a handled event and right after each of our own
  suspensions ends (call_original's poll and clear_slot, resume_after, release_held, ipc_thaw, the in-place
  window, deferred hits); call_original's return catch is listed while its context is touched; the two context
  calls on undispatched events (restore-resume, a late callee fault) are GuardTouch'd. Residual (microseconds):
  between our ResumeThread of an explicit suspension and the re-sync right after it; and an event thread the
  program suspended in the instant before its exception was reported (listed unconditionally while stopped).
  After: VM `--only cx2` x86 10/10, x64 9/9 + touchprog SKIP (x64 has no implicit suspend); the dying
  controller's guard list no longer held the worker; CI 10 runs per arch PASS; `--only cxlib` (the guard's
  controller-death checks) PASS on both arches, VM and CI. Agent protocol unchanged (controller-side only).
- ✅ (F5) **breakpoint/hw call_original left by an exception: later hits deeper on the stack got no callback.**
  (Found when two cases added to co_target changed its x86 layout: `callorig-hunt-cppthrow-{breakpoint,hw}` x86
  then failed deterministically, `co after` hits=3 logs=0 -- after3 no longer inlined.) Cause: the release of a
  call_original whose original was left (C++ throw, SEH raise, longjmp) needed the thread to be seen AT OR ABOVE
  the hit's frame (a probe hit there, or the 20 ms poll); a hit from a DEEPER frame was taken for a hit inside the
  original -- counted, no callback (hits without logs) -- until the next hit at that level or the 5 s release
  (other threads' hits held back meanwhile). Reproduced deterministically in `susp_target` (co_target untouched):
  `deepthrow` / `deepseh` / `deepjmp` -- the original is left and caught above it, then the program calls a probed
  function from a frame deeper than the left call's; `catchhit` -- the probed call is made inside the C++ catch
  block itself (runs on the dispatch's stack, below the raise point, with the original's frame physically intact
  -- its return address still in place). Fix (controller only, no protocol change), at a deeper hit of the call's
  thread and in the 20 ms poll: (1) `co_slot_gone` -- the original's return address slot at the hit's SP no longer
  holds the return address (the catching frame's later calls reused the stack; a copy within the 64 bytes just
  below -- a thunk that moved its own return address -- counts as inside); (2) `co_unwound` -- when an exception was
  raised on the call's thread during the call and the thread is below the raise point: a virtual unwind (dbghelp,
  new `uhh_sym::unwind_frames`) that reaches the frame above the hit's straight from below the raise point -- not
  through a frame between the raise point and the hit's frame (the original's, or a live callee's) -- means the
  exception was already unwound past the original (x64: the catch funclet's consolidation frame unwinds into the
  catching frame; x86: the catch block runs on the catching frame's EBP); on x86 the SEH chain must also hold no
  registration between the raise point and the hit's frame. Either way the hit is rewound and the call released
  (as for a hit above): the callback's call_original ends as before ("the original left without returning",
  UHH_CALL_RELEASED, `-done` not logged, nothing interrupted), and the hit replays with its callback. Control case
  `catchinside`: the exception is caught INSIDE the original (a probed call in that catch block, then a deeper
  one): those hits stay inside the call (counted, no callback -- as inline) and the call returns normally.
  Regress `callorig-deep-{deepthrow,deepseh,deepjmp,catchhit,catchinside}-{breakpoint,hw,inline}`: exact hits and
  `co` logs, the target's row as uninstrumented, nothing dropped/interrupted, no 5 s release. Before (VM, the
  unfixed library of 53490ed): x64 AND x86 4/12 -- every breakpoint/hw row of deepthrow/deepseh/deepjmp FAIL with
  `co after` 5 of 10 logs, catchhit 0 of 5; inline PASS. With (1) only: 10/12 on both (catchhit still 0 of 5).
  After: 15/15 on both arches; VM `--only callorig,callfunc,cx2,cxlib,hunt` (f08b9ff) x64 192/192 (+2 SKIP), x86
  188/189 (`hunt-starve-breakpoint` timeout, a documented known row); 3 more VM runs per arch 17/17
  (`callorig-deep,callfunc-registry`). CI: full suite on f08b9ff (run 42259248723) and cf25988 (run 42263598556) --
  the only FAILs `stdout-console-*` on both arches (runner console, failing on merge-frida too); `callorig`
  (callorig-hunt + callorig-deep) and `callfunc-registry` 5 repetitions per arch (temporary branch `f5-reps`, run
  42263590965, deleted since): all PASS. Residuals: a left original whose slot still holds the return address and no
  exception seen (longjmp, then a deeper call that leaves that slot alone) -- as before until the thread is seen
  above / the slot changes; x86 only: during a phase-1 filter of a frame ABOVE the original (an original with no
  SEH registration of its own) a hit in the filter releases the call early -- harmless unless the filter then
  resumes execution in the original (EXCEPTION_CONTINUE_EXECUTION), when the callback's tail after call_original
  does not run; x86 walks without FPO data (no PDB) are guarded by the SEH-chain condition only.
- ✅ **`callfunc-kill-reuse` proved nothing on the VM** ("no thread reused the dead id in 3000 threads", every
  run). Windows hands a freed thread id out again only once the id table's free list it went to has run dry (freed
  ids queue behind it; per-CPU lists, the creating thread's CPU picks one) -- on a long-running machine that takes
  more thread creations than 3000. The check now creates its precondition: after the kill, ar_target takes ids
  fast -- threads created suspended and ended before they ever run (no callback, no hit), the creator moving across
  the CPUs -- until one is given the dead id (budget 150 s / 4M ids); that thread and 19 more run cf_short. It
  fails unless the dead id came back (reused=1, 20 threads). VM: x64 PASS after 4745 ids (500 ms), x86 after 4751
  ids (563 ms); 3 more runs per arch 8256-8310 ids, <= 1.6 s; CI (fresh runners) PASS in both full-suite runs and
  all 5 x 2 repetitions above.
- Open, not caused here: x86 `lifecycle-controller-killed-inline` kill@early-0.05 target DEAD (0xC0000005 /
  0xC00000FD) on windows-2022 runners, 2 of 8 reps (the known runner finding in the CI section, 2 of ~7 before).
  Also failing on merge-frida 921820c's CI and unchanged here: `stdout-console-*` on both arches (runner console).
- Verification (VM, c19bbd9 = the final code): `--only stream,realbig,lifecycle,cxlib,cx2` x64 81/81 + 2 SKIP
  (x86-only touch checks), x86 81/81 + 2 SKIP (x64-only Edge rows); `--only callorig_hunt` 45/45 on both arches.
  CI: full suite on 79d71e7 and c19bbd9 plus 2 x 4 repetitions of stream-live/realbig/lifecycle/cx2
  (`followups-reps`): every row of the four items PASS on both arches.

## PowerShell capture findings (2026-11-06, owner: "high volume drops lines logged -- powershell logging"; the session file was complete, the PowerShell console showed fewer lines; regress `stdout-powershell-*`, `stdout-console-*`)

Reproduced on Windows PowerShell 5.1.19041 (no `pwsh` on the VM) with `uhh_trace` on
`logstream_target` (4 threads, delay 0) under every backend, with and without `--stack`, and on
a launched `powershell.exe` target. Every capture was compared with the session JSONL file and
the report (count, valid JSON per line, CRC multiset of the lines, `seq` coverage).

**The live tail itself loses nothing -- into pipes, files or a console:**
- Console handle at volume: `uhh_trace` attached to a pseudo console (ConPTY, the console
  Windows Terminal / OpenSSH / VS Code use; GetConsoleMode succeeds on its stdout, the
  WriteFile-to-console path), inside `powershell -Command`, the rendered VT stream decoded:
  inline `--stack` 2,000,000/2,000,000 `seq` rendered (371 s; 602 MB of VT), inline without
  stacks 2,000,000/2,000,000 (82 s); 100k inline and 10k breakpoint/hw, with and without
  stacks, all complete; every report `stdout_logs == logs_written == hits`, no live error.
  A classic console window (screen buffer read back with ReadConsoleOutputCharacter, 400
  columns x 32766 rows): 8000/8000 records + report, inline and breakpoint.
- Pipes/files through PowerShell: `| Out-File` (UTF-16 and `-Encoding utf8`), `>` (UTF-16),
  `| Set-Content`, `| Tee-Object`, `| ForEach-Object`, `2>&1 | Out-File`, `| Measure-Object -Line`,
  `| Select-String`, `Start-Process -RedirectStandardOutput`, `cmd /c ... >` (control), from a
  redirected host and from a console window: every capture held exactly logs_written == hits
  records, byte-identical to the file (inline 200k and 1.2M stack records; breakpoint/hw 20k with
  and without stacks; 40k with the target's own stdout forwarded in between; a launched
  PowerShell target). Records never contain raw newlines (the JSON writer escapes every control
  character), so a stack stays on its line. PowerShell is slow (1.2M stack records: `cmd /c >`
  19 s, `>` 46 s, `Tee-Object` 56 s, `Out-File` 110 s); UHH back-pressures, it does not drop.

**Where the console loses lines (outside UHH):**
- A pseudo console is a screen renderer, not a byte pipe: fed faster than it renders, it
  emits only the frames it draws. Non-UHH control (`control2.py`, 2M UHH-shaped 330-byte
  records) through ConPTY: written with WriteConsoleW (Python's console stream) only
  360,005/2,000,000 records were ever rendered (first missing: seq 37); the SAME bytes with
  WriteFile (`os.write`, like UHH) 2,000,000/2,000,000 (579 s). UHH writes with WriteFile,
  which conhost processes in step with rendering: no loss above, at any volume measured.
- PowerShell displaying the records itself (its host writes the console): `& uhh_trace ... |
  Tee-Object x.txt`, `| ForEach-Object { $_ }` and `2>&1` in a pseudo console, inline `--stack` 1M records:
  1,000,000/1,000,000 rendered each (Tee 1077 s, ForEach 889 s, merged 171 s; plain 158 s). PowerShell is slower than the
  renderer, so it does not hit the WriteConsoleW loss above.
- The one reproduced "console short, session file more complete": **Ctrl+C in a PowerShell
  pipeline** (below): the capture/console stops a few hundred records before the session file
  and has no report. With Ctrl+C at the end of a long run, that is "lines missing near the end".
- Every console keeps a finite history (conhost: the screen buffer, e.g. 9001 rows; Windows
  Terminal: 9001 lines by default). A `--stack` record wraps into several rows at 120 columns,
  so a million-record run leaves only the last few thousand records on screen while every
  write succeeded (`stdout_logs == logs_written`). The session file is the archive.
- **Ctrl+C inside a PowerShell pipeline** terminates the native command: PowerShell stops
  reading and kills it, so UHH's Ctrl+C path (end the session, flush, report) never runs.
  inline, 4x300k stack records, Ctrl+C at 6 s: `| Out-File` captured 55,560 records (file
  55,824), `>` 112,947 (file 113,165), `2> err | Out-File` 131,073 (file 131,275; stderr has no
  `probe: interrupted`), none with a report; `cmd /c ... >` 152,649 == file == logs_written,
  hits 152,653 (= + 4 callbacks_interrupted), report present. Non-UHH control (`control.py`: on
  Ctrl+C writes 1000 more lines, waits 1 s, writes a final line and a side-file "finished"):
  `| Out-File` and `>` never reach "finished" (killed); `cmd /c >` and the plain console do.

**What changed in UHH (each with its reproduction on the old code):**
- ✅ **A capture could not prove it was complete** (owner: "interpreting the END of the log
  wrong"; owner-requested): every `probe_log` record carries `"seq"` (0, 1, 2, ... in file
  order; the last field, so prefix matchers keep working); `probe_report` adds `stdout_logs`
  (records the live tail wrote to stdout) and `live_output_error` (a stdout failure other than
  a closed reader; also on stderr and in `error`); when records follow the report
  (`--detach-after-ms`), `probe_close` ends stdout with a `probe_final` line. Recipe:
  troubleshooting.md "Is my captured output complete?". Old code: all 14 `stdout-*` checks FAIL
  (no seq / stdout_logs) although delivery was complete.
- ✅ **A report on a still-running target contradicted itself** (hwonce: final `probe` hits
  97,694 vs `logs_written` 5.4M). Reproduced on 6f0c533 (`hwonce.py`: attach inline `--stack`,
  `--detach-after-ms 4000`, `| Out-File`, target ended after 60 s): probe hits 102,972 /
  123,116 vs logs_written 997,389 / 1,256,316 in the same report, and the report only after the
  target ended. Cause: `probe_report` read the inline hit counters, then `flush_log_writer`
  waited for an EMPTY queue, which never happens while the target logs faster than stdout
  drains. Fix: on a live target the report flushes the records queued when it started
  (`logs_enqueued` mark; the writer notifies per batch), then reads stdout_logs, logs_written
  and the hits in that causal order under the stdout lock, one hits snapshot per probe for its
  record and the total. After: consistent in every run (e.g. hits 163,364 >= logs_written
  157,215 == stdout_logs, then `probe_final` 540,542 == 540,542 == 540,542).
- ✅ **probe_close never finished while the attached target kept logging** (the debug loop
  starved). `drain_agent_logs` looped "until the ring is empty" under `drain_mu`; producers
  saturating a full ring refill every freed slot at once, so the debug loop (which drains on
  every iteration) never reached the stop request. Reproduced with the bounded drain reverted
  (`stdout-powershell-detach-inline`, 4 runs): 1 of 4 hung (`probe: close: still waiting for
  probe_run to stop (180s)`, 6,462,473 records streamed, ended only when the test killed the
  target); with the fix 0 of 4 runs. Fix: every drain is one bounded pass up to `log_head` at
  entry (the drainer thread loops).
- ✅ **A held-up session-file write held live stdout** (reproduced by the citune agent: CI with
  TEMP on C: holds up to 221 ms, on D: 0.5 ms p99; VM default TEMP 2 of 3 runs with 427/180 ms
  holds from real-time AV scanning of the growing file, a Defender-excluded dir 9/9 clean).
  The writer wrote each batch to the file, then to stdout. Fix: stdout first, then the file,
  `stdout_mu` held across both (a report sees a batch counted in both or in neither). The file
  is still written by the same thread right after (no second writer, no reordering); a target
  whose stdout is forwarded keeps file-then-replay (deferred records are replayed from the
  file). Before/after on the shared VM (3 interleaved rounds each, 6f0c533 vs pslog, x64; other agents kept
  the VM at 37-100% CPU, so run-to-run spread is wide): `stream-live` p99 breakpoint 14.4 -> 3.2 ms,
  hw 25.2 -> 2.0 ms, inline 15.7 -> 12.9 ms (medians); `stream-latency` p99 medians within the
  noise (both builds had runs over 30 ms). The `stream-latency-*` ordering flake (a record
  printed before the target's own tick line: the forwarder has not read the tick from the
  target's pipe yet) failed on both builds under that load (6f0c533: 1 of 9 records,
  pslog: 3 of 9, plus one more breakpoint p99 of 341 ms); `stream-latency` launches with the
  target's stdout forwarded, a path this change does not touch (file, then replay).
- Throughput (6f0c533 vs pslog, 3 interleaved rounds per arch on the shared VM, medians; full
  table in the pslog report): no regression beyond the run-to-run spread, which was large (other
  agents kept the VM at 10-100% CPU): x64 `uhh_trace --stack` 1M to a file 69.8k -> 81.7k rec/s,
  through `| Out-File` 12.1k -> 25.8k; x86 20.6k -> 40.1k and 6.5k -> 12.0k; log-throughput and
  stream-volume peaks unchanged. stream-latency ordering flake: 5/36 (6f0c533) vs 9/36 (pslog)
  in a 6x interleaved A/B, p99 medians equal; the forwarded path it measures is unchanged.
- Considered and NOT changed: the drainer's idle `Sleep(1)` (inline median latency ~15.6 ms =
  one timer tick, a latency, not a loss); and, with no failure reproduced: splitting/looping console writes or
  WriteConsoleW (2M records through a console handle were complete), a retry after a short
  WriteFile, code-page conversion (records are ASCII unless the logged text is not), the
  inherited console of a launched target (its own output can interleave with records on a
  console; the records still all reach it).
- Regress: `stdout-powershell-{outfile,redirect,setcontent,tee,merged}-inline`,
  `-{outfile,merged}-{breakpoint,hw}` (100k / 10k stack records through `powershell -Command`):
  captured == stdout_logs == logs_written == hits == logs + dropped + interrupted, every line
  valid JSON, seq contiguous, nothing after the report, session file equally complete;
  `stdout-powershell-detach-{inline,breakpoint}` (live report consistent, `probe_final` last,
  target alive); `stdout-console-{inline,breakpoint,hw}` (into a pseudo console: every seq
  rendered, report complete; `--console-records 2000000` adds the 2M tier).

## Benchmarks
- ✅ UHH vs Frida (Interceptor / CModule / Stalker / HW) — `bench/BENCHMARKS.md`
- ✅ Per-log overhead ceilings in the suite (`log-throughput-*`)
- ✅ Inline extended-state strategy measured (`bench/hitcost`): gated save = +1-5% vs +70% for a full save; gated is default
- 🔧 Inline hot path (striped counters implemented; measurement pending): ~75 ns/hit is high for a mid-hook — 3 shared atomics per hit (hit count + in-flight); stripe/per-thread them, keep exact
- ⬜ Per-method, per-backend benchmark table (hit, get_reg/set_reg, get_mem, send_log, send_log_stack, call_func, control ops)

## Real-world cases
- ✅ Microsoft Detours samples replicated (`examples/famous/detours_*`: simple, traceapi, withdll/attach, retval) -- findings above
- ✅ (1) Real binaries via `uhh_trace`: curl `CreateFileW` + `connect` (all backends); ✅ findstr via `ntdll!NtCreateFile`
- ✅ Targets written by Codex in `examples/realworld/`, in CMake + suite:
  - ✅ (4) Re-entrancy: inline malloc hook whose callback logs/allocates
  - ✅ (8) Thread stress: 128 threads, suspended-then-resumed, thread pool, thread churn mid-step
  - ✅ (6) Anti-tamper: `.text` / function-byte checksums and DR visibility, measured per backend
  - ✅ (7) Anti-debug: IsDebuggerPresent, debug port/object/flags, PEB, timing — measured and documented
  - ✅ (3) Exceptions (C++, SEH, through a callback) unwinding across hooked frames
- ✅ (9) Hot-patch `mov edi,edi` prologues (x86); 🔧 coexistence with Frida hooking the same function

## Production readiness (user decisions 2026-11-05)
- 🔧 [fan-out] Intel CET shadow stacks (user-mode "Hardware-enforced Stack Protection", /CETCOMPAT): static audit done, every path that broke the shadow stack fixed or refused; **measured on REAL CET hardware (CI windows-2025, shadow stacks enforced): every backend, incl. call_func / call_original + return_from, in compatibility AND strict mode; BlockNonCetBinaries works on breakpoint/hw, inline needs the /CETCOMPAT agent (branch cfnest)** -- details in "CET on real hardware (runfix2)" below; inline was also measured under Intel SDE's CET emulation (the test VM has no CET)
  - **The VM cannot test it:** its CPU is an Intel Core i5-6600 (Skylake, 2015 -- CET shipped with Tiger Lake / Zen 3), so `cet_probe` reports CPUID CET_SS=0, IBT=0, no OS CET_U state, RDSSP=0 and `EnableUserShadowStack=0` for a /CETCOMPAT process (Windows 10 19045, x64 and x86, under Proxmox/KVM). A newer host would also need a hypervisor that passes CET to the guest (KVM CET virtualization is recent). So every `cet-*` row on the VM proves only that /CETCOMPAT targets work under all backends, NOT that UHH survives an enforced shadow stack.
  - **Real CET hardware: GitHub-hosted `windows-2025` runners (2026-11-06, CI job `cet-hw` on every push).** AMD EPYC 7763 / 9V45 under Hyper-V, Windows Server 2025 build 26100: `cet_probe` reports `cpuid_cet_ss=1, os_cet_u=1, ssp!=0, enforced=true`, policy `EnableUserShadowStack=1, SetContextIpValidation=1` (strict mode 0, BlockNonCetBinaries 0) for a /CETCOMPAT process (windows-2022 runners: Xeon 8573C, no CET in the guest). With shadow stacks ENFORCED: `cet-gated-breakpoint`, `cet-gated-inline`, `cet-gated-hw` PASS (`cet_enforced=True target_ssp=True`, hits 4000/4000, logs exact, checksum = uninstrumented; breakpoint sites displaced-stepped), `cet-ret-breakpoint` PASS (4/4, the in-place CALL/RET branch keyed on `EnableUserShadowStack` finally ran), the whole `cet-sde-*` set PASS (SDE 9.48 still hosts targets there), and the rest of the x64 suite on that image shows no CET-related failure (run 42182687993; probe_app_cet/cet_probe are the only /CETCOMPAT targets, so only the `cet-*` rows run under a shadow stack). So: the breakpoint/hw CET branches work on real hardware, and a debugger's cross-process SetThreadContext into displaced-step scratch memory is NOT refused under `SetContextIpValidation=1` in compatibility mode. Strict mode, `BlockNonCetBinaries` and breakpoint/hw `call_func` were then settled on that image by runfix2 (next item).
  - **CET on real hardware (runfix2, 2026-11-06, CI windows-2025: AMD EPYC, Server 2025 build 26100, shadow stacks enforced; rows `cet-tp-*`, `cet-strict-*`, `cet-block-*`):**
    - ✅ **breakpoint/hw `call_func` now WORKS under shadow stacks** (the refusal is gone): the callee is entered through a real CALL -- the thread is pointed at a 3-byte stub in the target, `call rax`/`call eax` (rax/eax = the function) + `int3` -- so the CPU pushes the return address on both stacks, the callee's `ret` matches and comes back to the stub's INT3, and SSP is where it was at the hit (simpler than the planned DR trap at the shadow-stack top; no debug register needed; the same path on every target). A callee abandoned midway (it faulted, or timed out) leaves its frames on the shadow stack: SSP is put back through `CONTEXT_XSTATE` / `XSTATE_MASK_CET_U` (`thread_ssp`; measured: `0x..fc8 -> 0x..fd0 restored`, also in strict mode -- the kernel accepts moving SSP UP). New fixture `tp_target_cet` (the transparency target linked /CETCOMPAT; `tp_driver` derives the module from the target's name): `cet-tp-{breakpoint,hw,inline}-{callfn,co}` all PASS with `target_ssp=True` (callfn = GetThreadPriority / TlsGetValue / a probed function / a callee faulting at its first instruction, "0x1"; co = call_original + return_from, int/int64/double/stdcall/alignment/recursion).
    - ✅ **Found + fixed: call_original + return_from on breakpoint/hw #CP'd under STRICT mode** (0xC0000409 at the ret gadget). The original runs in place and its own `ret` pops the frame's shadow entry; return_from then resumed at the `ret` gadget with SP at the hit, which popped the CALLER's shadow entry -- tolerated by the kernel in compatibility mode only because the gadget is non-image code. Windows REFUSES to move SSP back down (measured: `NOT restored (the kernel refused)`), so under shadow stacks return_from now resumes directly at the return address with the stack popped past it (no `ret` executed); call_original WITHOUT return_from under CET returns the original's result (warned once: it cannot run twice -- its shadow entry is gone; without shadow stacks the fall-through re-run is unchanged).
    - ✅ **Strict mode** (Exploit protection "Hardware-enforced Stack Protection: strict", set per image through IFEO `MitigationOptions` on renamed copies -- `check_cet_policy`; byte 15 = 0x30, as `Set-ProcessMitigation -Enable UserShadowStack,UserShadowStackStrictMode` writes it; `cet_probe` confirms `EnableUserShadowStackStrictMode=1`): `cet-strict-tp-{breakpoint,hw,inline}-{callfn,co}` and `cet-strict-gated-{breakpoint,hw,inline}` (800/800 hits+logs, target_ssp=True) all PASS. Displaced stepping into private scratch memory, the call stub, the freeze moves and every SetThreadContext RIP change are NOT refused by `SetContextIpValidation` (on by default for /CETCOMPAT images, not relaxed) for a debugger, in strict mode either.
    - ✅ **BlockNonCetBinaries** (IFEO byte 16 = 0x10 -- Set-ProcessMitigation has no switch for it; `cet_probe` confirms `BlockNonCetBinaries=1`): breakpoint/hw work (`cet-block-tp-{breakpoint,hw}-log`); inline with today's non-CETCOMPAT agent is refused CLEANLY (`LoadLibraryW failed for probe_api_agent.dll`, session error, target unaffected) and works fully once the agent AND the callback module are /CETCOMPAT (measured with a diag build: the cfnest agent line + `tp_driver` /CETCOMPAT, which runfix2 now links). x86: Windows does not even start a WoW64 process under this policy (0xC0000022) -- skipped, moot (no CET for WoW64).
    - x86 under Server 2025: `cet_probe` reports `EnableUserShadowStack=0` for WoW64 even for a /CETCOMPAT image (no enforcement); the x86-only runner failures there were not CET (see "Runner findings").
  - **Measured under Intel SDE's CET emulation (`check_cet_sde`, rows `cet-sde-*`; SDE in `C:\tools\sde`, skipped when absent):**
    - Kit: **SDE 9.48.0 (2024-11-25) is the last Windows kit with the CET checker**: 9.53+ (9.58.0, 10.13.1 tried) print `SDE ERROR: CET is not supported on Windows` and the checker strings are gone from their `sde-mix-mt.dll`. Knobs: `-tgl -cet -cet_stderr -cet_call_stack -no-follow-child` (`-cet_abort` stops at the first report, `-cet_raise` kills the target with 0xC000008C). SDE prints one `Control flow error: IP: <ret> expected (shadow stack): A got (actual return address): B` per mismatching `ret`; the labels are swapped in 9.48 (A is the ordinary-stack address, B the shadow-stack entry -- proven by cet_smash's known addresses).
    - Positive control (`examples/cet/cet_smash.c`, /CETCOMPAT): `cet_smash smash` overwrites a return address with another valid one -- natively it just "lands" (exit 3); under SDE the first report is exactly that `ret` with the two addresses (`cet-sde-control-smash`), a clean run gives none (`cet-sde-control-clean`). `cet_smash calls N --wait --smash` is the witness workload: RDSSP after every iteration (`ssp_live`: non-zero only while the thread runs inside SDE) and the deliberate smash again at the end, so a run proves the checker was on to the last instruction.
    - What SDE gives the process: CPUID CET_SS=1/IBT=1 and a live RDSSP, but no OS CET_U state and **`ProcessUserShadowStackPolicy.EnableUserShadowStack=0`** -- the shadow stack exists only inside SDE's JIT (`cet-sde-probe`). So UHH's controller-side CET branches, keyed on that policy (breakpoint CALL/RET stepped in place, the breakpoint/hw `call_func` refusal), never run under SDE; SDE measures the paths that are the same with and without CET.
    - Hosting: `sde.exe -> pin.exe -> target` (Pin injects into the target process; the target's own pid is the debuggee). UHH cannot launch through SDE, so every row ATTACHES to the SDE-hosted target at its stdin gate (`uhh_attach`, `co_driver --attach`, new `examples/cet/cet_sde_driver.cpp`). Pin picks up the agent's code patches (its SMC handling re-translates), and the agent's thread runs under SDE too.
    - ✅ **Inline (x64): no shadow-stack violation from UHH anywhere.** Every inline hit runs the patched mid-hook stub (`pop rsp; jmp [trampoline]`); measured: gated_config on probe_app_cet with flag/open/close/read all inline (exact hits/logs, checksum = uninstrumented, target RDSSP live, 0 reports); `call_original` + `return_from` and pure `return_from` (cet_smash, 20 each: only the deliberate smash's 3 reports, as uninstrumented); the 11 callorig-hunt cases (recurse, C++ throw, SEH, longjmp, 16 threads x 300, mid-function refusal, nargs, x64 8 args, return-site probe, return_from over a callee-saved prologue, nested): rows exact and the SDE reports IDENTICAL to the uninstrumented run (throw/SEH/longjmp produce 6/13/6 reports even uninstrumented -- Windows' unwinder does not pop a shadow stack the OS says is off; UHH adds none); `set_reg(SP)` sp_moved 10/10, 0 reports. (The full conformance callback -- inline call_func, get/set_reg, set_mem, runtime adds -- also passed all 15 checks with 0 reports, but its runtime breakpoint/hw probes can take the thread out of SDE, see below, so it is not counted as CET evidence and has no row.)
    - ✅ **Found + fixed: the relocated call (`uhh_relocate_call_as_jmp`) under a shadow stack the policy does not report.** A probe ON a `call` (co_target!CoCallPrologue+0x2a) was relocated as `push; jmp` because the agent set `uhh_safetyhook_keep_calls` only from the policy: SDE reported the callee's `ret` on every hit (10 reports / 5 hits). The agent now also sets it when RDSSP is non-zero (a NOP returning 0 without a shadow stack, so nothing changes elsewhere; also covers a failed policy query on CET hardware): 0 reports. Regress `cet-sde-relcall-inline` (cet_smash!cet_caller+call_off, fails without the fix).
    - ✗ **Breakpoint: not measurable under SDE.** The first INT3 of a thread is reported to UHH as an unhandled 0x80000003 (`target crashed` line, the hit lost: 39/40), and from then on the thread runs NATIVELY outside SDE (cet_smash: `ssp_live` 0/20 and its deliberate smash no longer reported); a hit inside the loader (gated_config's NtClose during LoadLibrary) hangs the target. Single-thread call_original on breakpoint "worked" (co recurse: row exact, 40 hits) but unchecked, for the same reason.
    - ✗ **hw: not measurable under SDE.** Execute debug registers never match: the CPU fetches from SDE's code cache, not the original address (0 hits on cet_smash, co_target, conformance SpSite; program unaffected, thread stays in SDE). Data watchpoints do fire (conformance probe_watch 3/3).
    - ✗ **x86: not measurable.** SDE's checker runs on WoW64 but reports 530 mismatches on a CLEAN 32-bit cet_smash run (121 with `-cet_exclude_image ntdll.dll`, still inside the CRT): the WoW64 transitions desynchronise its shadow stack. Moot for production: Windows does not enforce user shadow stacks for WoW64.
  - **Audit (x64; Windows does not enforce user shadow stacks for WoW64/x86 processes):**
    - ✅ Inline, every hit: SafetyHook's mid-hook stub ended `lea rsp,[rsp+8]; pop rsp; ret`, returning to the trampoline through an address it had PUSHED -- a #CP on every inline hit (fatal in strict mode; in compatibility mode at best a kernel fix-up per hit, since stub and trampoline are non-image memory). Fixed: the stub now ends `pop rsp; jmp [trampoline]` (`cmake/patch_safetyhook.cmake` step 3, applied to `third_party/safetyhook`; x64 the same 7 bytes, x86 one byte longer with a relocated `jmp [abs32]`). No `ret` remains on the hook path (the stub's own `call [destination]` is a real call/ret pair).
    - ✅ Inline `set_reg(SP)` (#8): the same patch makes the context's rsp/esp the stack pointer the hooked code resumes with -- nothing is written below the new SP (the old `trampoline_rsp` slot clobbered the saved registers when SP moved down). Re-enabled in `src/probe/agent.cpp`; conformance `sp_moved` now 10/10 on every backend.
    - ✅ Breakpoint emulation of CALL/RET (`emulate_site`): moves RSP/RIP but not SSP, so the target would #CP at its NEXT real `ret` inside its own CETCOMPAT code (fatal even in compatibility mode). Since 226f131 the emulation is skipped when `ProcessUserShadowStackPolicy.EnableUserShadowStack` is set and the CPU steps CALL/RET in place (JMP/Jcc/LOOP/PUSHF/POPF emulation is unaffected). Regress `cet-ret-breakpoint` (probe on NtOpenProcess's `ret` in probe_app_cet). That in-place CALL/RET step now runs in the in-place window (Evaluator round 3 #2: the other threads are held while the byte is lifted), so it is exact under threads too; the CPU still does the push/pop, so SSP stays consistent. The x64 SYSCALL trampoline has no call/ret (a `jmp [rip]` back), so it does not touch the shadow stack either.
    - ✅ `call_func` on breakpoint/hw (`call_in_target`): the callee was entered by SetThreadContext, so its `ret` to `call_trap` did not match the shadow stack -> #CP inside the callee. Was refused under shadow stacks; since runfix2 entered through a real CALL from a stub and works (above).
    - ✅ SetThreadContext RIP changes (displaced stepping into scratch memory, moving frozen threads onto the trampoline, `call_func` entry/restore, `set_reg`): not refused by `SetContextIpValidation` for a debugger, compatibility and strict mode (measured, above). The controller sets `CONTEXT_XSTATE` (CET_U) only to drop an abandoned call_func callee's shadow frames.
    - ✅ `BlockNonCetBinaries` policy: the injected `probe_api_agent.dll` was not /CETCOMPAT and would be refused -> no inline backend in such a process. Now linked /CETCOMPAT (cfnest). The bit only declares that the image's OWN `ret`s are shadow-stack clean (in compatibility mode a violation inside a CETCOMPAT image becomes fatal). Audit of every agent path: agent C++ and callbacks built into it are plain call/ret (no `_AddressOfReturnAddress`, no setjmp/longjmp of its own, x86 `__asm` blocks are x86-only: WOW64 has no user shadow stacks); `uhh_orig_thunk` (agent_x64.asm) is a real call/ret (its fake machine frame only steers the unwinder's frame walk, not a `ret`); the hook stub (SafetyHook mid-hook, in allocated memory) `call`s the agent and ends `pop rsp; jmp [trampoline]`; return_from's thunk (`pop rsp; ret`, allocated memory) returns to the hit's own return address = the shadow-stack top at a function entry (entry-only, enforced); a relocated CALL stays a call when a shadow stack is active (c7755cf); the trampoline-fault VEH re-raises with NtRaiseException (no `ret`). Open, as before and unchanged by the bit (needs CET hardware): SSP after an exception unwinds out of an inline call_original through the fake machine frame, and the VEH re-raise's SSP. Tests: `cet-agent-image` (agent CETCOMPAT, FAILED before), `cet-agent-block-noncet` (SKIP on this VM: `SetProcessMitigationPolicy(ProcessUserShadowStackPolicy, BlockNonCetBinaries)` at runtime is refused with ERROR_ACCESS_DENIED here -- no CET hardware; on CET hardware it maps a non-CET DLL vs the agent under the policy). Under Intel SDE with the CETCOMPAT agent (`--only cet`, x64): every `cet-sde-*` inline row passes unchanged (e.g. `cet-sde-relcall-inline` 3 reports = uninstrumented 3; `cet-sde-gated-inline` checksum same, target SSP live); bp/hw rows stay SKIP (not measurable under SDE). **Measured end to end on CET hardware (runfix2, windows-2025):** with this agent and a /CETCOMPAT callback module, inline works under BlockNonCetBinaries (`cet-block-tp-inline-log`).
  - (Before the windows-2025 runners) Not exercised anywhere: the CET-only branches (CALL/RET in-place stepping and the `call_func` refusal) are keyed on `EnableUserShadowStack`, which the VM reports as 0 even for a /CETCOMPAT image -- correct (it reflects enforcement, not the image bit), but it means those branches never ran here, and SDE cannot run them either (policy 0 there too, and the breakpoint backend leaves SDE at the first INT3). The policy is queried once per session and a failed query is cached as "no shadow stack" (the agent's own relocation switch also reads RDSSP; the controller cannot run RDSSP in the target).
  - **Test plan on CET hardware** (Intel Tiger Lake+ / AMD Zen 3+, Windows 10 21H1+/11 x64, bare metal or a hypervisor that passes CET through; `cet_probe` must print `enforced=true`): run `regress.py --only check_cet,check_conformance` and expect all PASS with `cet_enforced=True target_ssp=True`; then repeat with the process forced into strict mode (Exploit protection -> Program settings -> probe_app_cet.exe -> Hardware-enforced Stack Protection: on, strict) and with `SetContextIpValidation` on, to settle the two open items; then a `call_func` breakpoint/hw run to confirm the refusal is clean (returns 0, target unaffected). Hardware positive control first: `cet_smash smash` must die with 0xC0000409 (#CP), `cet_smash clean` exit 0. What only hardware can settle: the breakpoint/hw paths under a real shadow stack (in-place CALL/RET, displaced stepping, `call_func` refusal, call_original), strict mode, `SetContextIpValidation` for a debugger's SetThreadContext, `BlockNonCetBinaries` vs the non-CETCOMPAT agent, and the CET_U XSTATE the controller never sets.
  - Tests: `cet-image` (probe_app_cet/cet_probe carry the CETCOMPAT bit, probe_app does not), `cet-probe` (what the machine enforces), `cet-gated-{breakpoint,inline,hw}` (gated_config with all probes on one backend against `probe_app_cet`, exact hits/logs, checksum equal to an uninstrumented CET run, target's own RDSSP == cet_probe), `cet-ret-breakpoint`; `conformance-inline` sp_moved 10; under SDE: `cet-sde-{probe,control-clean,control-smash,calls-base,calls-inline,relcall-inline,gated-inline,sp-inline}`, `cet-sde-co-<case>-inline` (11 cases), SKIP rows `cet-sde-breakpoint` / `cet-sde-hw` saying why.
- ⬜ [fan-out] Windows 11 VM on the Proxmox server, run the suite there too (later)
- ✅ [fan-out] Stability on real large apps (important): browsers / heavily multi-threaded / JIT processes under all backends -- Edge renderer + browser, PowerShell 5.1, robocopy /MT:16, findstr /s, x64 + x86, launch and attach/detach with a no-residue check; 1 library bug fixed (RB1, attach to sandboxed processes), CIG refusal clarified (RB2). See "Real large apps findings"; regress `realbig-*` (default subset; all rows with `--bigapps`)
- ⬜ [fan-out, Codex] Docs: quickstart, API reference, per-backend limitations table, troubleshooting
- 🔧 Inline cap raised to 128 per session (user: 128 is enough; error beyond) -- compile-time thunk table, per-request FREEZE flag; refusal test uses the 129th -- VM verify pending
- ⏸ Follow child processes: design written -- [docs/child-processes.md](child-processes.md) (strategies with VM measurements from `bench/child_follow`, API options A-D, recommendation: ProcessDebugFlags inheritance + `probe_follow_children` + `get_pid`); **deferred by the owner (2026-11-06)**: a session follows one process; a child it starts runs unprobed -- attach to it with its own session. Processes the target did not create are unaffected either way (attach separately)
- ✅ CI on GitHub Actions: the full suite sharded on hosted windows-2022 runners, x64 + x86, ~19 min, plus enforced-CET checks on windows-2025 (`.github/workflows/windows.yml`, `scripts/ci_shards.py`) -- see "CI on GitHub Actions" below (runner findings open there); ⬜ (maybe) CMake package + versioned release zip
- 🔧 (very last) Soak test: hours under load; handles/memory/threads flat -- `scripts/soak.py` (phases mixed / hw / breakpoint / attach-detach cycles, per-minute samples to CSV, exactness + checksum + growth verdict), opt-in `regress.py --soak-minutes N`; probe_app `--pace`. x64 mixed 30 min PASS (57.6M reads, all logged, controller/target flat); 1-min calibration of every phase PASS. **The VM froze twice during the 30-min all-hw phase** (at ~18 and ~22 min, ~12k hw hits/s; guest RAM exhausted while UHH's own processes stayed at ~2.5 MB private) -- suspected kernel-side memory growth per debug event / DR context switch (host logs a burst of `Unhandled WRMSR(0x1d9)` DEBUGCTL from the guest during hw runs). soak.py now samples available RAM, kernel paged/nonpaged pool and system handles and aborts below 1.5 GB. Next: a 3-minute hw run with 15 s samples to measure pool growth per hit before any long hw soak
- ✅ Controller-crash self-unhook -- **inline sessions only, by owner decision 2026-11-07.** Originally ✗ (user: the analyst sees the controller died and restarts the target; not worth the cost); Lifecycle L1 then injected the agent into every ATTACHED target to guard it; the owner reversed that (an injected DLL in a breakpoint/hw-only target is itself a side effect): the agent -- and with it the controller-death guard -- is in a session only when it has an inline probe. A breakpoint/hw-only attached target keeps our INT3s/DRs when the controller dies and may fault at its next hit (see "Agent scope"). A launched target still ends with its controller
- ✗ Named-object hardening (user: unlikely; a clash fails loudly)

## CI on GitHub Actions (2026-11-06, `.github/workflows/windows.yml`, `scripts/ci_shards.py`)
More Windows test capacity than the one VM: the repo is public, so GitHub-hosted runners are free (~20 concurrent
jobs). The full suite, both arches, takes ~18 min wall on them (VM: ~36 min x64 + ~58 min x86, serial).
They are NOT the VM: `windows-2022` = Windows Server 2022 (build 20348), 4 vCPU (2 cores) / 16 GB, Intel Xeon
Platinum 8573C under Hyper-V (no CET in the guest), Defender real-time protection off; `windows-2025` = Server 2025
(build 26100), AMD EPYC (7763 / 9V45), Visual Studio 2026 only (no VS 2022), **user-mode CET shadow stacks ENFORCED**.
- **Triggers:** every push to any branch (pushes touching only `*.md` / `measurements/` are skipped, except
  `docs/quickstart.md`), every pull request, and `workflow_dispatch` (Actions tab -> windows-regress -> Run workflow,
  or `gh workflow run`) with inputs `only` (regress.py `--only` selectors, comma-separated; empty = full suite),
  `arches` (`x64,x86` / `x64` / `x86`), `shards` (per arch; 0 = 7 x64 / 9 x86) and `image` (`windows-2022` default,
  `windows-2025` = the whole selection under enforced CET). A newer push to the same branch cancels the older run.
- **Jobs:** `plan` (ubuntu) packs the suite's check units into balanced shards from measured runtimes;
  `build (x64|x86)` configures + builds Release (~2 min; no cache needed), posts runner facts, toolchain and
  `cet_probe`, uploads `bin-<arch>`; `test <arch>-<NN>` downloads it and runs `ci_shards.py run`: ONE
  `regress.py --only <unit>` per unit, timed, the whole output teed to `ci-logs/<arch>-<NN>.log` (+ `.json`), uploaded
  as artifact `logs-<arch>-<NN>`; the job fails on any FAIL / non-zero exit / unit timeout (45 min) except the
  documented by-design failures in `KNOWN` (hunt-ctx/starve/early/owndr, patch-race-unsafe: posted as warnings).
  `cet-hw` (windows-2025, x64, on every push) builds, posts `cet_probe` and runs `check_cet,check_conformance` under
  enforced CET, posting every `cet-*`/`conformance*` row. `summary` tabulates shard x arch (+ cet-hw) and the
  measured unit times (artifact `unit-times`, feeds `EST` in ci_shards.py).
- **Units:** `--only` matches substrings of check function names, so a unit is a check name that contains no other
  one, plus every check containing it (`check_attach` = attach + attach_new, `check_cet` = cet + cet_sde,
  `check_realworld`, `check_symbols`, `check_callorig`). `ci_shards.py units` lists them; the units are re-parsed from
  regress.py main() on every run and must partition it exactly, so a new check is picked up automatically (60 s
  estimate + a warning annotation until `EST` is refreshed). Opt-in tiers (`--volume-reads`, `--bigapps`,
  `--soak-minutes`) are not run. A long unit is SPLIT into parts run as units of their own (`SPLIT` in
  ci_shards.py: `check_realapps:<part>` = regress `--only check_realapps` with `UHH_REALAPPS_ONLY` /
  `UHH_REALAPPS_BACKENDS`; parts tasklist-m, ps-modules-<backend>, ps-fileversion-<backend>, rest = every other
  scenario, parsed from `_realapps_scenarios()` so a new one is never lost). Critical path now: x86 `check_hunt`
  (~7 min; longest shard 443 s) instead of x86 `check_realapps` (~15 min as one unit).
- **External deps:** every check runs explicitly selected, so `skip_external()` is a FAIL in CI where a full
  unselected run would SKIP. The shards that need them install Frida 16.5.9 into `C:\work\fv16` (regress
  `FRIDA_PY`) and Intel SDE 9.48 into `C:\tools\sde` (Intel's mirror, sha256-pinned, cached). `check_oldcrt` needs a
  pre-14.40 msvcp140.dll: windows-2022 has one (VS 2022's bundled LLVM, the check's own lookup); on other images the
  shard fetches the 14.29.30133 DLL from the PyPI wheel `msvc-runtime` (sha256-pinned) into `UHH_OLD_MSVCP`. An OS
  component an image does not ship at all is listed per image in `ABSENT` (ci_shards.py; windows-2025:
  `realapps-wmic`): its `skip_external()` row is posted as a warning like `KNOWN`, only on that image and only with
  skip_external's "optional external dependency absent" text. Any other absent system program is a FAIL.
- **Reading results without a token** (public REST, 60 requests/h unauthenticated): runs
  `GET /repos/talivision/uhh/actions/runs?branch=<b>`, jobs `GET .../actions/runs/<id>/jobs` (with per-step
  conclusions), annotations `GET .../check-runs/<job id>/annotations`. Every test job posts a notice
  (`<shard> PASS|FAIL N/M ok ... <secs>s` + per-unit times), error annotations with every `] FAIL` line IN FULL
  (chunked at 3.4 KB, a longer line split across parts, max 10 per step; the step summary and the `summary` job's
  "Failures (full detail)" section always have every line whole), a warning with its known / absent failures; `summary` posts the whole table (chunked, ~3.5 KB per annotation); `build` posts
  runner facts, toolchain and the `cet_probe` JSON. Orchestrator helper:
  `~/work/uhh-tools/fan/work/ci/gh.py runs <branch> | jobs <run> | notes <run> [job-name regex]` (2-12 calls per run).
  Logs, artifacts and dispatch need auth: `~/work/tools/gh/bin/gh auth login` once, then
  `gh run list -R talivision/uhh -b <branch>`, `gh run view <id> -R talivision/uhh --log-failed`,
  `gh run download <id> -R talivision/uhh -p 'logs-*'`,
  `gh workflow run windows.yml -R talivision/uhh --ref <branch> -f only=lifecycle,hunt -f arches=x64 [-f image=windows-2025]`.
  Without auth: push the branch to the own repo (every push runs the full suite).

### CI results (2026-11-06)
Final run on `ci` (run 42187807241, commit 7b495fd, windows-2022 + cet-hw on windows-2025): **1333/1349 ok,
16 failed = 7 known by-design + 9 runner findings below**; ~19 min wall (build ~2 min, then the x86 realapps shard).
Shards are re-packed from `EST` (unit lists in each job's step summary).

| shard | x64 result | x64 s | x64 cpu | x86 result | x86 s | x86 cpu |
|---|---|---|---|---|---|---|
| 01 (realapps) | PASS 24/24 | 562 | EPYC 7763 | FAIL 19/22: realapps-ps-fileversion-{bp,hw,inline} (env) | 897 | EPYC 7763 |
| 02 (lifecycle / hunt) | PASS 48/48 | 371 | EPYC 9V74 | PASS 46/48 (2 known hunt) | 402 | EPYC 9V74 |
| 03 (cet+sde / lifecycle) | PASS 118/118 | 311 | EPYC 7763 | PASS 48/48 | 379 | EPYC 7763 |
| 04 | PASS 101/101 | 276 | Xeon 8573C | PASS 71/71 | 240 | EPYC 7763 |
| 05 | FAIL 158/160: patch-race-frozen (env), patch-race-unsafe (known) | 270 | EPYC 9V74 | FAIL 81/82: stream-latency-breakpoint (flaky) | 262 | Xeon 8573C |
| 06 | PASS 122/125 (3 known hunt) | 293 | EPYC 7763 | PASS 58/58 | 207 | EPYC 9V74 |
| 07 | FAIL 95/97: ntdll-churn-{hw,breakpoint} (zero-hit cycles) | 343 | Xeon 8370C | FAIL 110/112: patch-race-frozen (env), patch-race-unsafe (known) | 244 | EPYC 7763 |
| 08 | -- | | | PASS 92/92 | 262 | EPYC 7763 |
| 09 | -- | | | FAIL 114/115: crash-logs-inline-4t | 258 | EPYC 7763 |
| cet-hw (windows-2025) | PASS 28/28 (+2 SKIP: cet-sde-breakpoint/hw) | 242 | AMD EPYC | -- | | |

Earlier runs on `ci`: 42180029465 (windows-2022, first full run: 1307/1321), 42182687993 (`image=windows-2025`, the
whole suite under enforced CET: 1296/1315; x64 `cet-*` all PASS), 42185253728 (windows-2022: 1314/1349, incl. the
18 transparency rows below), and a one-off diagnostic workflow (repeats + patch-race timing, removed again).

### Runner findings (2026-11-06; each analysed: environment vs real bug)
CET hardware (answers the CET question): `cet_probe` on windows-2025 (AMD EPYC 7763 and 9V45, Hyper-V, build 26100):
`cpuid_cet_ss=1, os_cet_u=1, ssp!=0, enforced=true`, policy `EnableUserShadowStack=1, SetContextIpValidation=1`
(strict mode 0, BlockNonCetBinaries 0) for a /CETCOMPAT process. windows-2022 (Xeon Platinum 8573C, which has CET)
exposes no CET to the guest (`cpuid_cet_ss=0, enforced=false`). On windows-2025 the `cet-hw` job passes
`cet-gated-{breakpoint,inline,hw}` and `cet-ret-breakpoint` with `cet_enforced=True target_ssp=True` (details in
the CET item under "Production readiness").

Real-bug candidates (reproduce on runners, not on the VM so far):
- ✅ **crash-logs-inline-4t (both images; x86 8/8 runs, x64 6/8; never on the VM)** -- fixed (runfix1). The gap
  `logs = hits - 1..3` was never a lost log: the report already carried `callbacks_interrupted` and runner diag
  (runfix1-diag run 42191637133, 72 runs, 6 jobs) showed `hits == logs + interrupted` exactly in 69 -- the check
  compared logs with hits. The other 3 (x64) exposed a real accounting bug: `logs + interrupted = hits + 1`, a thread
  killed after publishing its log but before its callback returned was counted as a log AND as interrupted (the
  documented v20 edge). Fix (agent protocol v23): the callback's FIRST record carries its hit's unaccounted unit
  (`probe_agent_log::carry`, published by the ring's single seq store) and the controller retires it when it takes
  the record (ring or PROBE_IPC_LOG); a callback that returns without logging drops it itself; unhook / detach drain
  wait on a separate `running` count. So a kill at any instant leaves hits == logs + dropped + interrupted exactly.
  `check_crash_logs` now requires exactly that (dropped 0; inline interrupted <= threads-1; bp/hw 0; 1 thread: n
  logs, 0 interrupted). Evidence: runner diag 42192716058 84/84 exact (7 jobs, x64+x86), 42194976034 36 full-check
  runs PASS, VM x64+x86 PASS. The same v20 edge made `hunt-exit-process-inline` report `logs + interrupted == hits +
  1` in ~1 of 8 runner runs (huntaudit): 42212077320 ran every `hunt-exit-*` 12 times on 5 jobs (x64+x86): 540/540
  PASS, 180 inline runs exact with interrupted 0-8.
- ✅ **lifecycle-controller-killed-{mixed x64 (full run), inline x86 (diag 1 of 4)}** (runfix2): kill@early-0.05 ->
  target DEAD 0xC0000005 with NO unhandled report. Reproduced with a kill loop on runners (`lckill`: 3 of ~1130 kills
  at 0.05/0.08 s into an inline/mixed attach; 0 of ~1130 with 3 CPU burners -- contention does not help). Cause: the
  controller died while the agent's install round was raising its FREEZE request; the raise came back unserviced
  (no debugger any more) BEFORE the guard's cleanup had set `controller_gone`, and the agent then enabled the hooks
  UNFROZEN -- SafetyHook's own trap path makes the site page non-executable, and on an ntdll syscall-stub page every
  system call faults, the installer's and the program's alike (also the program's own unhandled-exception filter,
  hence no report). Fix (agent `frozen()`): an install whose FREEZE no controller serviced is not written (the
  requests end HOOK_FAILED); a removal freezes in-process. Deterministic regress `lifecycle-killed-in-freeze-{inline,
  mixed}` (test hook `UHH_TEST_FREEZE_STALL_MS` parks the controller with the FREEZE pending, the test kills it):
  old agent 40/40 cases DEAD 0xC0000005 on windows-2022 x64 and x86 (diag run 42197120854), fixed agent 40/40 PASS.
  **Second layer, exposed by that fix: the target HUNG** instead (kill loop: 0 deaths but 4 hangs in ~3100 kills; a
  thread dump of the hung target -- `lckill.py` H lines -- showed EVERY program thread suspended once and no agent
  thread). The controller froze all threads for the install round and died before answering; nobody resumed them:
  the agent's service thread did not exist yet (its named event is the controller's and went with it), and the
  init's own orphan check keyed on the controller process being signaled -- an agent-side probe (diag build) showed
  `enabled=1 dead=0 port_gone=1 held=11`: the debug port goes during the dying controller's handle rundown, BEFORE
  its process object is signaled. Fix (agent init/service): the init ends with the guard's orphan check on the debug
  port (waiting up to 5 s for it when no service thread could start), and the service thread polls the port while
  it has no controller handle. The regress check now stalls the controller AFTER the freeze (`UHH_TEST_FREEZE_STALL_MS`,
  every other thread suspended): x64 freeze-stall loop 14-24 hangs / 120 before, 0 / 120 after (diag runs
  42212013348 / 42214215294 vs 42217463236); `lifecycle-killed-in-freeze-*` x64 + x86 all PASS.
- ✅ **ret-probe-breakpoint (x64 + x86, 1 of 9 each)** -- not a double count: a real 5th NtOpenProcess by the
  target. Per-hit stacks (runner diag 42192716058): on the FIRST launch of probe_app on a fresh runner (7 of 7 jobs,
  x64 and x86; never on a later run, so hw -- which runs second -- never saw it) the shim engine opens a process
  during loader init: `ntdll!LdrInitializeThunk -> LdrInitShimEngineDynamic -> apphelp!SE_InitializeEngine ->
  apphelp!Sdb* -> KernelBase!OpenProcess -> NtOpenProcess`. The check now takes its ground truth per hit from the
  stack (`--stack`): hits with a probe_app frame must equal the target's `opened` count, every hit is logged, other
  hits must be system-only (reported as `system_opens`). Evidence: 42194976034 12/12 jobs `check_ret_probe` first on
  a fresh runner PASS (4/4) and 36/36 later runs PASS.
- ✅ **x86 transparency-{breakpoint,hw}-callfn on windows-2025 (build 26100)** (runfix2): not CET (x86
  `cet_probe` there: `EnableUserShadowStack=0`, so the old refusal never fired). The target died at the MID-function
  site (TpMidHit sits inside a `std` ... `cld` span): call_func entered the callee with the hit's EFLAGS, DF=1, and
  on build 26100 the WoW64 syscall thunk under GetThreadPriority uses string instructions, which ran backwards and
  smashed its stack (execute of 0x0, return address = the call trap). Fix: the callee gets the ABI's flags (DF and
  TF clear); the thread's own flags come back with the restore. x86 windows-2025 `--only transparency` 19/19.
- ✅ **x86 detach-inline on windows-2025** (runfix2): two causes. (1) The check's fixed 2.5 s detach came after
  the target had finished every read on the fast EPYC hosts (`hits=6000000/6000000`, x64 too), so the detach met the
  main thread EXITING: SetThreadContext fails ERROR_ACCESS_DENIED (STATUS_THREAD_IS_TERMINATING) -- `setfail=5`
  (the error code is now reported). (2) The final DR pass counted that as a failure. Fixes: a terminating thread is
  clean (ThreadIsTerminated); the check detaches on stdin (`uhh_trace --detach-on-stdin`) after the first 1000
  logs, with the inline target paced (200k reads/s per thread) so the detach is mid-run on any host. windows-2025
  `--only check_detach` 6/6 on x86 and x64.
- **attach-new-inline x64 windows-2025 (1 run)**: "probe never became active" -- the load flake also seen once on
  the VM (Lifecycle section).

- ✅ (explained and fixed in the test: see "CI residuals" R1 below) **transparency-* (x64, all 18 rows, once in 5 runs)** -- host found: it is the **Intel Xeon 6973P-C** runner
  (Granite Rapids; AMX enabled in XCR0 = 0x600e7, XSAVE area 11008 bytes; GetEnabledXStateFeatures 0x608e7),
  1 in ~15 x64 windows-2022 jobs (runfix1-diag 42192716058 x64-a, 42194976034 x64-g: every `ovf` row fails there,
  every other CPU passes: EPYC 7763 / 9V74 / 9V45, Xeon 8370C / 8573C -- AVX-512, no AMX). The `ovf` case (TR9) has
  a callback overflow its stack: on that host the overflow's exception frame (a CONTEXT with the XSAVE area of every
  XCR0 feature, ~12 KB) does not fit the stack Windows leaves after the guard page. Fixed for the controller: its
  callback thread runs under a stack guarantee of CONTEXT + XCR0 XSAVE + 16 KB (`probe_callback_stack_guarantee`,
  SetThreadStackGuarantee): breakpoint/hw callbacks' overflows are caught there now ("callback raised 0xc00000fd;
  abandoned"). Inline: the agent raises the program thread's TEB guarantee for the callback only and restores it
  (the first version never applied it -- a probe request below the effective default is a no-op; fixed in 16c87b3:
  the VM shows `tp ovf guarantee teb=20480` inside the inline callback, and every transparency row -- which compares
  every TEB byte with the unprobed twin -- passes on the VM and runners; not yet seen on the AMX host). Open: on the AMX host
  the TARGET's own later overflow (`overflow_caught`, no probe on it) dies under breakpoint/hw (AV in the unwind,
  `read of ... reserved, not committed`) although the same target without UHH survives it; a bare ctypes debugger
  (`ci-diag/dbgtest.py` on runfix1-diag) and a probe on another function only (`ovfx`) are queued to tell "any
  debugger on AMX" (environment) from UHH; the gated AMX-host jobs (25-30 per diag run, `cpu: 6973P`) have not
  landed on one since.
- ✅ **ntdll-churn-{hw,breakpoint} (x64, 2 of 5 runs, Xeon 8370C in the last)** -- the probes never became ACTIVE
  inside the 300 ms window (report `active:false`, no `probe: active` line, nothing lost). On attach, breakpoint/hw
  probes arm only once the agent's controller-death guard is up (agent init on a remote thread). With 4 target
  threads spinning on a 2-vCPU runner a new normal-priority thread waits a whole quantum (Server: ~190 ms) at its
  start and at every wake-up, so arming took 0.3-1.5 s, and the detach as long (its remote stop thread). Fix: the
  controller's remote threads (agent load / init / stop) and the agent's service thread run at
  THREAD_PRIORITY_HIGHEST (they never spin; the program loses nothing but those milliseconds). A/B on runners
  (runfix1-diag 42192716058, one build, `UHH_DIAG_NOBOOST` knob, 7 jobs x 4 runs x 7 cycles after the first):
  without the boost 11 zero-hit cycles of 196 (activations up to 0.41 s), with it 0 of 196; 42201061531 /
  42203401040 (`churnx`: inline + hw + breakpoint on fresh targets as the check does, PROBE_TRACE timelines): 0 of
  315. The check's other assumption -- only cycle 1 may set the agent up -- also failed: a detach between the
  agent's load and its first init (which starts its service thread) left that init and a zero-hit window to cycle 2
  (3 of ~58 runner check runs, always cycle 2 after a short cycle 1). Cycle 1 now gets 3 s; every later cycle keeps
  300 ms and must see hits.
- ✅ **logs-wedge-{kill,suspend,exit} `wedged=0`** (x86 and x64, several runs, e.g. 42190450176, 42194952645,
  42203177441) -- the check's precondition never formed: logs_target sampled a running producer with
  SuspendThread (200000 tries) for the few hundred instructions between claiming a ring slot and publishing it; on
  the 2-vCPU runners it gave up (on a fast EPYC it needed 5 k-120 k tries). The accounting was right every time
  (`hits == logs + interrupted`; `rc=1` in exit mode is the target's exit 7, not checked). Now deterministic: the
  producer's record `UHH_TEST_WEDGE o N` stops in the agent right after its claim (`test_wedge_point`, enabled only
  by `UHH_TEST_LOG_WEDGE=1`, which logs_target sets in itself; every other record pays one byte compare) and the
  target confirms the claimed, unpublished slot in the ring before it kills / suspends / exits around it -- the
  same condition, created instead of hunted. (The live-delivery half of logs-wedge-suspend, `undelivered_live`, is
  pslog's.)
- Seen once, undetermined: x64 `detach-inline` (`1 thread(s) frozen; all clean` yet FAIL, detail cut); x86
  `hw-once-slots-breakpoint` (run 42194952645: `HwSite[once,all]=[1, 75]`, the run ended after 75 of 4000 calls).
- v23 (runfix1) follow-ups found by the full suite (42194952645): `cxlib-cfgfree-inline` wanted `in_flight=1` for a callback the
  program suspends across the detach AFTER it logged -- now accounted by its log (`in_flight=0`); the detach line
  gained `running=` (callbacks still executing, not accounting) and the check wants `running=1 in_flight=0`.
  `logs-controller-killed` reads the orphaned ring itself: first records left in it carry their hits, so the target
  counts with `probe_agent_unlogged` (unaccounted minus carried records still in the ring).

runfix2 results (2026-11-06/07; diagnostics through a scratch branch `runfix2-diag` whose workflow pushes each job's
full logs to a `diaglogs/<run>-<job>` branch -- readable with git, no API token):
- Kill loop (`ci-diag/lckill.py`: lifecycle_target + lifecycle_driver, the driver killed 0.02-0.2 s into the attach):
  before 3 deaths / ~1130 kills (inline+mixed, windows-2022); with the install fix 0 deaths but 11 hangs / ~2900
  (inline, 0.04-0.06 s); with both fixes **0 failures / 2557** (x64+x86, windows-2022+2025, run 42217463236).
- After merging merge-frida b1888e3 (cfnest fibers, runfix1, codex2, pslog, realbig, gatede2e, citune, huntaudit)
  into runfix2 (91e766b): ONE call_func path -- cfnest's fiber parking / late-trap tombstones / serialization,
  entered through runfix2's CALL stub (`call rax|eax` at call_trap-2, returning into call_trap, the INT3 that
  restore_fixup also uses), DF/TF clear, SSP restored on FAULTED/TIMEOUT; the early agent load (A6) now also runs
  under CET. CI windows-2022 run 42235426997 1992/2001, windows-2025 run 42235435967 1987/1997, cet-hw 49/49 on
  windows-2025 (the windows-2022 run's cet-hw: 48/49, `cet-sde-sp-inline` a PowerShell process-query timeout);
  remaining failures are on merge-frida too (stdout-console-*, stacks-identical) or timing flakes of other checks
  (realbig-robocopy-detach-breakpoint: 2 of 3 FAIL on merge-frida itself, 3 of 3 PASS on runfix2, diag
  42240423313; attach-new-inline). VM clean build, `--only callfunc,transparency,cet,lifecycle,detach,cxlib,cx2,co`:
  x64 169/170, x86 148/149 (only `callfunc-kill-reuse`, the VM precondition above).
- Final CI on runfix2 before the merge (eb4d54d): windows-2022 run 42225278011 1885/1897, windows-2025 run 42225285343 (branch
  `runfix2-w25` = runfix2 + a default `image=windows-2025`, never to be merged) 1876/1891, cet-hw 48/48 (+2 SKIP) on
  both; none of the failures is a runfix2 row (crash-logs-inline-4t, realapps-ps-fileversion x86, patch-race-frozen,
  stream-latency, wmic/oldcrt absent, known hunt rows).
- Earlier windows-2025 full suite (run 42218924878): x86 transparency/detach rows PASS, cet-hw 48/48
  (+2 SKIP); remaining failures are other findings (crash-logs-inline-4t, realapps-ps-fileversion x86, wmic/oldcrt
  absent, known hunt rows), plus single occurrences: attach-new-inline (load flake, above) and
  `lifecycle-detach-early-120-inline` (target 0xC0000005 in an agent thread while hunt_dll unloads; PRE-EXISTING:
  the same signature in 1 of 128 rows on merge-frida's agent, 0 of 128 on runfix2, diag run 42224315607 -- L5
  family; root-caused and fixed: "CI residuals" R3). `prehook-attach` failed once on windows-2025 (OSError: the target was gone 3 s into the attach);
  14/14 PASS in reruns on both arches.
- VM (Windows 10, both arches): `--only transparency,check_detach,conformance,callfunc,check_cet_policy,callorig`
  x64 88/89, x86 84/85 (the one FAIL both times: `callfunc-kill-reuse` "no thread reused the dead id in 3000
  threads" -- the check's precondition on that host, unrelated); `UHH_LC=controller-killed,killed-in-freeze
  --only lifecycle` 3 x 6/6 on each arch.

Environment (runner) effects, and how the checks were made robust without proving less (branch `citune`; full
run 42203177441 at df3bddc, windows-2022 + cet-hw: 1830/1843 ok; every check below PASS on both arches; longest
shard 443 s, was ~900 s; the 13 FAILs are the KNOWN hunt rows and findings owned elsewhere: crash-logs-inline-4t
x64+x86, ret-probe-breakpoint x86, ntdll-churn-breakpoint x86, gated-e2e-attach-post-fbp-oin-cbp-rbp x64 (new check,
another branch), logs-wedge-{exit x64, kill + suspend x86} (`wedged=0`: the wedge never formed on the runner)):
- **patch-race-frozen (x64 + x86, deterministic)**: hook_cycles=[1,1,1,1], need >= 4 in the target's 12 s. Measured
  (diag): one attach -> install -> 400 ms -> detach cycle against 8 spinning threads takes 6-8.5 s on the 2-core
  runner (13 threads frozen, all clean, 20-78 M hits per cycle), so only one cycle fits; never crashed or torn.
  **Fix:** cycle-count based. patchrace_target `--until-stdin` runs until the check closes its stdin; each trial
  runs >= 4 cycles AND >= 12 s (whichever is later; <= 25 cycles; 300 s budget, else FAIL), so the VM keeps at
  least its old exposure (VM x64: 6 cycles/trial in 12-17 s) and a runner gets 4 (28-31 s/trial). A second runner
  effect surfaced then: the report taken 400 ms after the attach can still show `hits=0` (the install against 8
  spinning threads is not finished yet), although the same cycle's detach summary counts 20-78 M hits; "this cycle's
  hook ran" now uses the detach-time count (stderr `probe: detached: hits=N`). patch-race-unsafe unchanged (still
  KNOWN: fails when the race is not seen; with more cycles it now sees it more often: crashed=3/4 on a runner).
- **stream-latency-* (x64 + x86)**: NOT scheduler noise. Rewritten to measure the real latency: logstream_target
  stamps each LogSite call and each of its own lines with QueryPerformanceCounter, the reader stamps arrivals with
  the same counter, and an uninstrumented writer (the same target, a line every ~5 ms) runs alongside as a
  scheduler-noise sampler (cyclictest-style: late writes and late arrivals). Bar: p99 < 100 ms when the sampler saw
  < 50 ms of stall in the run (quiet: the original absolute bar), else p99 of (latency - the stall the sampler saw in
  that record's own window) < 100 ms; plus all 50 records once and in call order, never before their event. Diag
  runs (CI 42192197211, 42195891554, 42198334462: 10-24 runs per arch x {0,2,4 CPU burners} x {TEMP on C:, D:}):
  the sampler showed a QUIET machine (stalls 1-5 ms) while records were held 50 ms - 2.5 s, consecutive records
  released together while the target kept running on schedule (x64 hw: #24-#46 all at once, 2.5 s late). Watching
  the session log file located the hold BEFORE the file (event -> in file == event -> stdout; file -> stdout ~0):
  UHH writes each batch to `%TEMP%\uhh\logs\*.jsonl` first, and appends on the runner's C: (network-backed managed
  disk) block when the lazy writer flushes (worst near ~1 s after the first write: sample #8-#10 is the slowest in
  almost every run). Same job, same commit (run 42198334462, 10 runs per arch each): TEMP on the runner's D: (local
  temp disk) -> 60/60 PASS, breakpoint/hw p99 ~0.5 ms (one 10 ms), the #8-#10 bump gone, sampler appends <= 10 ms;
  TEMP on C: -> 1 FAIL (breakpoint 221 ms, #25+#26 released together), several 50-63 ms holds, sampler appends
  stalling up to 364 ms. Earlier C: runs: 2.5 s (x64 hw), 205 ms (x86 inline), 164 / 136 ms (hw).
  The VM shows the same holds, from Defender: A/B on the VM, same C: disk, x64, 3 runs each: TEMP =
  `C:\Users\admin\AppData\Local\Temp` (real-time scan on) -> 2/3 FAIL (inline 427 / 180 ms holds at #8-#10, near
  misses 91 / 79 ms); TEMP in the Defender-excluded `C:\work\...` -> 9/9 PASS (worst 30 ms).
  **Fix (check):** the controller's TEMP/TMP is `<build dir>/uhh-latency-tmp` (next to the binaries: the VM's
  `C:\work`, the CI workspace on D:, both local and AV-excluded), so the check measures UHH's pipeline, not the
  user profile's AV or the runner's OS disk. VM after the fix: 17/18 PASS over 3 runs x 2 arches x 3 backends; the
  one FAIL (x64 hw, #8-#10 held 366 ms before the file) came with the sampler's own appends stalling 243 ms in that
  run (the VM's disk is shared with the other agents' builds). **Finding for the owners (UHH design):** live stdout
  latency is bounded by the session file's write latency -- the writer thread writes each batch to the file, then
  to stdout, so an AV scan of the new file or a slow disk (the first lazy-writer flush, ~1 s after the first write,
  is the usual culprit) holds live records 0.1-2.5 s. Candidates: write stdout before / independently of the file
  (the file stays the complete record), or give the file its own thread. The check deliberately does NOT discount
  disk stalls (the sampler's file is not UHH's file; discounting would hide exactly this).
  The 3.3 ms breakpoint failure was the old per-line ordering condition: the target's own lines are FORWARDED by
  UHH (pipe + forwarder thread, since 2f2f8c1), so a record can reach stdout before the tick line the target wrote
  just before the event; measured `log_before_tick` = 4-12 of 50 per run with 4 CPU burners, 0 otherwise. No such
  cross-stream promise exists (docs/api.md promises whole lines only): now reported, not required. (Possible UHH
  improvement: the writer drains the forward pipe's pending bytes before a batch.) Perf note: inline p50 ~15.6 ms
  everywhere = one timer quantum of the drainer's idle `Sleep(1)`.
- **realapps-ps-fileversion-* x86 (deterministic)**: the plain 32-bit `Get-Process -FileVersionInfo` lists only
  itself and exits 1 on a runner -- no other WoW64 process exists there (the VM has some), so `stable_rows=0` fails.
  **Fix:** the check starts 3 helpers of its own bitness (`<sysdir>\findstr.exe` waiting on a pipe) for the whole
  scenario and REQUIRES each in both plain runs and the instrumented one, and each read by the instrumented program
  through a handle mapped to its pid and name (`helpers=3xfindstr.exe: stable=3 instrumented=3 read=3/3`) -- on
  every machine, both arches.
- **windows-2025 only**: `realapps-wmic` (WMIC is a Feature on Demand Server 2025 no longer installs) -> new scenario
  `realapps-ps-cim` (the same WMI process query through PowerShell `Get-CimInstance`, every image, all backends)
  and `realapps-wmic` absent = `skip_external()` with that reason, posted by CI as ABSENT on windows-2025 only.
  `oldcrt` (VS 2026's LLVM ships no pre-14.40 msvcp140) -> CI provides msvcp140 14.29.30133 via `UHH_OLD_MSVCP`
  (PyPI `msvc-runtime` wheel, sha256-pinned). Verified on windows-2025 (diag jobs of run 42192197211): x64 and x86
  `realapps-ps-cim-*`, `realapps-ps-fileversion-*`, `oldcrt-{inline,breakpoint}` (app_local=True, 2000/2000) PASS,
  wmic ABSENT. `realapps-ps-modules-breakpoint` once: an svchost loaded fwpuclnt.dll between the plain and the
  instrumented run (a live process list).
- New on runners with ps-cim: x86 `realapps-ps-cim-inline` `intr=1` once (a callback interrupted when PowerShell
  exited: the crash-logs-inline-4t class -- an inline hit whose callback never completed because the process ended).
- Passing on runners where the VM was suspect: x86 `hunt-ctx-breakpoint` (no 600 s timeout), x86
  `edgehunt-*-fmtptr` (B10), x64 `blog-pwsh-attach-detach-inline`, x86 `hunt-exit-*`.
- ✅ **stacks-identical (both arches, about 1 run in 5 on windows-2022; never on the VM)**: a real bug, fixed
  (cisym). One inline frame was named `kernel32+0x14f80` while breakpoint and hw named it
  `kernel32!BaseThreadInitThunk+0x10`. Same address, same DbgHelp (SDK, export-only kernel32). The run-time
  diagnostics (60 repetitions per arch, 12-14 failures) showed kernel32 loaded with `SymType` none and no exports.
  DbgHelp keyed by the target's process handle reads a deferred module's image from the target's MEMORY on first
  use. An experiment registered kernel32's file at the base where the live target maps ntdll. Windows 10's DbgHelp
  then named the frame with ntdll's exports (`kernel32!RtlDosPathNameToNtPathName_U+0x60`) and the SDK's DbgHelp
  gave none. Names therefore depended on when a module was first used: breakpoint/hw walks load kernel32 at the
  hit, while inline stacks are named later on the writer, as the short target exited. **Fix:**
  `src/probe/symbols.cpp` keeps names in a DbgHelp session keyed by an opaque value, so every module loads from its
  file and PDB on disk. `StackWalk64` runs in a second session keyed by the real handle and only returns
  addresses. The rule is in docs/symbols.md. Regress `symbols-file-backed` (`symfile_test`) covers it. CI: stacks
  repeated 60 times per arch, 0 failures.
- ✅ **stdout-console-* (both arches, every run on windows-2022)**: a check bug, not a UHH bug. Every record and the
  report reached the pseudo console. Server 2022's conhost renders a line that wraps at the console width as the
  row, CRLF, CUP to the previous row's last column, and that column's character again, which the terminal's
  autowrap then continues. The check stripped VT sequences and line breaks, so it saw one character twice per
  wrapped row: `"logs__written"` and `"live_output_error"":null`. As a result the report was unparsable or lacked
  `logs_written`. **Fix:** regress `VtScreen`, a small VT screen emulator (autowrap with deferred wrap, cursor
  addressing, erase/insert/delete, scroll regions). Rows are read as they leave the screen and the report is parsed
  whole. The assertions are unchanged.

## CI residuals (2026-11-07, branch `ciresid`, regress `cx2-cosample-*`, `lifecycle-unload-unseen-*`, `transparency-*`)
Three residuals of merge-frida's CI run 42256070700 (e186402). Diagnostics ran on a scratch branch `ciresid-diag`
(never merged; deleted after) whose jobs pushed their full logs plus linker maps of the agent and targets to
`diaglogs/cr-<run>-<job>` branches (git-readable, no API token), so crash stacks could be symbolized.
- ✅ (R3, L5 family) **lifecycle-detach-early-*-inline: the target died 0xC0000005 on an agent thread while
  hunt_dll unloads.** Reproduced on CI (diag run 42262469609, 17 x64 jobs -- 16 windows-2022, 1 windows-2025 -- x ~214
  iterations of every `lifecycle-detach-early-*` row, merge-frida's code): 65 failures in 58,240 rows, all in the
  29,120 inline/mixed ones (44 x early-120-inline, 19 x early-30-inline, 2 x early-120-mixed; 0 breakpoint/hw), on
  every CPU type, all with ONE signature (the windows-2025 job's own build at its own offsets): `exception 0xc0000005 at probe_api_agent.dll+0x371f7 (write of 0x7ff...1040 (unmapped))`, stack
  (symbolized with the job's linker map) `MoveSmall6` <- `safetyhook::trap_threads` <- `InlineHook::disable` <-
  `MidHook::disable` <- `frozen<probe_agent_stop lambda>` (+0x21ca) <- `probe_agent_stop` (+0x9e25, the thread's
  start) -- the frames of merge-frida's CI failure. The agent's STOP thread (the remote thread a detach starts at
  probe_agent_stop) restored HuntWork's original bytes into hunt_dll after the program had unloaded it (refcount 0:
  unmapped): the UNLOAD_DLL event (reported AFTER the view is gone) was still queued behind the detach's own
  events, so the request was not yet UNLOADED. L5 had guarded the install side only. Fix (agent.cpp
  `disable_hook`): the final unhook skips a site that is not mapped executable code (nothing to restore) or that
  already holds the original bytes (the DLL mapped again at the same base: a fresh copy), and the write is
  SEH-guarded (an unmap completing meanwhile -- a thread suspended inside its unmap system call still finishes
  it); a hook whose write faulted is abandoned in place, never touched again. Deterministic check
  `lifecycle-unload-unseen-<cfg>` (every config): the test-hook controller (`UHH_TEST_DEFER_UNLOAD=hunt_dll.dll`,
  probe_api_testhooks) leaves that unload unprocessed, as if still queued; lifecycle_target's new `dllonce`
  command loads hunt_dll, calls HuntWork (its probe goes active and hits) and unloads it; then the detach. Before
  (VM x64, the fix reverted): inline and mixed DEAD 0xC0000005 with the same frames (`#4 +0x21ca`, `#5` the stop
  thread's start); breakpoint/hw PASS (removing an INT3/DR at an unmapped address fails harmlessly in the
  controller). After: 4/4 on both arches (VM; CI diag 42264739119 3 x 4 per arch). Repetitions after the fix (diag 42264739119, every `lifecycle-detach-early-*` row in a loop, 17 jobs, both arches, windows-2022 + one windows-2025, on EPYC 7763 / 9V74, Xeon 8573C and one Xeon 6973P-C): x64 0 failures in 31,184 rows (7,796 inline + 7,796 mixed; before the fix 65 in 29,120 inline+mixed); x86 1 failure in 21,792 rows (5,448 inline + 5,448 mixed) -- a DIFFERENT signature, still open: x86 `lifecycle-detach-early-30-inline` on an EPYC 9V74 (x86-04), `target crashed: exception 0xc0000005 ... (execute of 0x16dfc38 (private memory, PAGE_READWRITE))`, a worker thread executing a non-executable private page, `in_flight=1 running=1` (a callback still running at the detach), x86 frames not walkable (`#2-#4 probe_api_agent.dll+0x1489` = local_read's tail, frame-pointer garbage). Not the stop thread's write; not reproduced elsewhere (first x86 loop run of these rows: no x86 baseline exists to compare).
- ✅ (R2) **cx2-cosusp-breakpoint (x64)**: the failing condition was the one the message did not print -- `first`,
  the program's own SuspendThread of its worker returned 1, not 0: a suspension of the CONTROLLER's was in place at
  that instant; prev/ran/ret were right (the guard left exactly the program's suspension). Cause: call_original's
  20 ms "left the original?" poll suspended the thread around its GetThreadContext (window ~tens of us per 20 ms);
  a program suspending that thread then sees it -- a side effect (gospel), not a guard bug. Fix: the poll reads
  the context without a suspension. On x64 GetThreadContext of a running thread is a consistent snapshot (taken
  in an APC on that thread) and leaves the suspend count alone. x86 residual: a 32-bit (WOW64) controller's
  GetThreadContext suspends the thread INSIDE the call -- measured with a standalone 32-bit program on the VM
  (another thread reads the worker's context once per ms while a sampler loops SuspendThread/ResumeThread on it:
  3,639 of 3.3 M samples saw prev=1; `none` 0); NtQueryInformationThread(ThreadWow64Context) is refused to 32-bit
  callers (STATUS_INVALID_INFO_CLASS) and Wow64GetThreadContext suspends the same way (5,240) -- inherent to a
  32-bit debugger short of switching to 64-bit code; the call stays GuardTouch'd. New check `cx2-cosample-<b>`
  (susp_target `cosample`): the program samples its worker's suspend count for up to 1 s while the worker is
  inside a call_original (co_hold(2), under the 5 s limit; the wrap must complete, ret 38): x64 wants 0 foreign
  suspensions, x86 <= 1% (the WOW64 residual, reported). Before (VM x64, the poll reverted): foreign=43,193 of
  1.25 M samples (breakpoint), 389 of 436 k (hw). After: 0 of 1.26 M / 277 k; x86 987 of 493 k / 138 of 190 k
  (0.2% / 0.07%: the residual). The cosusp/evsusp failure message now prints `first`. CI (diag 42264739119, 3 runs each): before (the poll reverted) x64 cosample foreign 2,137-2,549 of ~2.4 M (breakpoint) / 680-803 of ~0.73 M (hw), x86 4,194-4,824 of ~1.47 M / 1,090-1,179 of ~0.43 M, and once the original symptom itself (x86 `cx2-cosusp-hw` FAIL); after: x64 0 of ~2.06 M / 0 of ~0.41 M, x86 1,953-2,362 of ~2.27 M (0.09%, the WOW64 residual, 3.5x below before). Full CI on the merged branch (30c1b48, run 42278813404): x64 1017/1017, x86 987/987, cet-hw 49/49.
- ✅ (R1) **transparency-* on the Xeon 6973P-C (AMX) runner: the target's own stack overflow died on every
  backend** (merge-frida: 14 of 18 rows; inline's single run includes `ovf`, so all its modes failed with "no
  target row"). Environmental, not UHH: the overflow's exception frame is a CONTEXT plus the XSAVE area of every
  XCR0 feature in the STANDARD layout, whatever is in use -- measured with tp_target's diagnostics (the overflow
  filter records the frame, the dispatch's position and the stack's committed range): XSTATE length 328-376
  bytes / frame ~1.8 KB on AVX2 hosts (EPYC 7763, 9V74), 1,920-1,976 / ~3.4 KB with AVX-512 (Xeon 8370C, EPYC
  9V45), ~1.95 KB on the VM (Skylake, AVX), the same for control (no debugger), a bare ctypes debugger (with and without a
  Get/SetThreadContext per exception) and every UHH backend with the probe on tp_ovf or elsewhere. Windows leaves
  the faulting frame 16.4-20.4 KB above the never-committed bottom page (random: where in a page the overflow
  strikes), so with AMX's 11,008-byte area (frame ~12 KB) the dispatch, the filter and RtlUnwindEx land within
  0-4 KB of reserved memory -- the "AV in the unwind, read of ... reserved, not committed" seen before -- with or
  without a tool. Model on the VM (tp_target's diagnostic knob `TP_OVF_PAD=N`: the overflow filter touches N more bytes, standing in for a bigger frame; Windows' default guarantee; 12 runs per cell): every mode survives at N <= 10 KB and dies at N >= 12 KB; in the transition (10.5-11.5 KB -- about what AMX adds to the frame) control (no debugger) survived 19/36, a bare debugger 19/36, UHH breakpoint/hw/inline 54/108: the same margin. On the AMX runner itself (diag run 42287996531, a Xeon 6973P-C job found after ~130 CPU-gated x64 jobs; 15 runs per cell of tp_target `--ovf`): the frame is 11,656-11,704 bytes (XSTATE 10,184-10,232) and the faulting frame sits 18.5-20.5 KB above the stack's bottom; WITHOUT a guarantee control (no debugger) survived 5/15 (dying 0xC0000005), a bare debugger 4/15, UHH breakpoint 9/30, hw 2/15, inline 4/30 (probe on tp_ovf or only on tp_add) -- the same failure with or without any tool; `regress --only transparency` with `TP_OVF_NO_GUARANTEE=1` 5/19 (the 14 rows merge-frida lost). WITH the guarantee every cell 15/15 (control, bare debugger with and without a context round trip per exception, breakpoint, hw, inline, both probe placements) and `--only transparency` 19/19 twice. Fix (test): tp_target's ovf thread reserves the stack its own overflow's dispatch
  needs on this CPU (SetThreadStackGuarantee(CONTEXT + CPUID(0xD,0).EBX + 16 KB), as a program relying on catching
  its overflow must; `TP_OVF_NO_GUARANTEE=1` keeps Windows' default). The check still proves TR9 (a callback's
  overflow must not cost the thread its guard page: without the restore the program's next overflow has no guard
  page and dies) on every host. UHH needs no change; inline's callback-time lift (g_cb_guarantee) is a no-op
  under the program's equal guarantee.

## Later
- ✅ x86 cumulative-session flakiness (possibly the same handle double-close; recheck) -- CLOSED with evidence (cfnest). The note dates from the first checkpoint (c617de4); its suspected cause, review finding I6 (handles closed twice on the launch failure path), was fixed long since. Rechecked with `ar_driver --repeat`: 60 sessions in ONE controller process, backends in turn (breakpoint, hw, inline), each a call_func + runtime data watch whose callback call_funcs during another thread's call: every session exact, nothing dropped, the controller's handle count flat (x64 73 -> 73, x86 89 -> 89). Regress `sessions-repeat` keeps it covered (also exercises the per-run callback-fiber host). (Separately: `callfunc-kill-reuse` -- inline, needs the OS to hand a killed thread's id to a new thread of the same process within 3000 creations -- failed on the shared VM in Nov-06 evening runs on the cfnest build AND on an unmodified baseline build (2/2): system-wide thread-id reuse under other agents' load, not a UHH regression.)
- ✅ PDB-only symbols (`module!InternalFunc`), Microsoft symbol server via dbghelp+symsrv and `_NT_SYMBOL_PATH`, export/function enumeration (`uhh_trace --list`) — engine by Codex, wired into the library; suite checks added
- ⬜ Split `src/probe/session.cpp` (debug loop, backends, symbols, attach/call)
- 🔧 [fan-out] Faster builds (user, 2026-11-05): parallel MSBuild (/MP, MultiToolTask, Directory.Build.rsp -maxCpuCount; `-DUHH_PARALLEL_MSBUILD=OFF` to disable) and `scripts\build.ps1` (Ninja Multi-Config). VM (4 cores), same tree: clean x64 221 s -> 83 s (VS) / 73 s (Ninja), x86 220 s -> 85 s / 66 s; touch session.cpp x64 49 s -> 24 s / 23 s. Still open: PCH / unity for session.cpp, not relinking every example when the library changes
- ⬜ Final independent whole-codebase sanity review; README/API docs pass
