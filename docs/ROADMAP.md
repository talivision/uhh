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
- 🔧 (A4) breakpoint/hw + a target that round-trips its own threads' contexts (SuspendThread +
  GetThreadContext + SetThreadContext, as GCs/profilers do): a context captured while the thread
  sat in a UHH debug event and written back after UHH resumed it undoes UHH's fix-up.
  Fixed: displaced step (resumed into the scratch slot -> ran garbage -> AV): every displaced copy
  is now followed by a jump back to site+len and a stray TF step inside the scratch slots is
  swallowed; hw (DR6 overwritten -> unhandled single step killed the target 0x80000004): a #DB at
  one of our execute addresses with no DR6/BS/TF is recovered as ours.
  Open (no contained fix): breakpoint -- a context captured at the INT3 trap (pc = site+1) written
  back resumes the thread one byte into the original instruction (seen: 1-2 wrong reads in 3M);
  hw -- the stale context has RF clear, so the same call is reported twice (+5 hits in 2M).
  Inline unaffected. `hunt-ctx-{breakpoint,hw}` FAIL by design until fixed
- ⬜ (A5) breakpoint/hw starvation: every debug event freezes the whole process, so with 8 threads
  hitting a probe back to back, a thread that hits nothing runs only in the gaps. Seen: main's
  Sleep(300)+exit taking 4 s typically and >180 s in ~1 of 6 runs (main measured still inside one
  fprintf). Program results stay correct; wall-clock does not. Options: one event per hit instead
  of two (emulate simple displaced instructions such as `mov r10, rcx` instead of single-stepping
  them), or a fairness throttle that briefly holds a thread that hits continuously.
  `hunt-starve-*` (exit within 60 s; flaky-fails on breakpoint/hw until fixed); exit checks use 2
  readers on breakpoint/hw so they test exit correctness, not starvation
- ⬜ (A6) inline misses calls made BEFORE the image entry point (TLS callbacks at process attach,
  static-import DllMain): hooks are installed at the entry hold. Breakpoint/hw see them. In
  gated_config terms an NtOpenProcess in a TLS callback is never mapped, so every later read logs
  pid=0. Needs an earlier install point (e.g. load the agent from the loader breakpoint) -- design
  change. `hunt-early-inline` FAIL by design
- ⬜ (A7) hw: the target arming its OWN debug registers (SetThreadContext DR0/DR7 on its threads,
  handled in its VEH) shares DR0-3 with UHH's hardware probes: the target's own breakpoint stopped
  firing. Breakpoint/inline pass the target's #DB through untouched. Document per-backend, or pick
  slots the thread does not use. `hunt-owndr-hw` FAIL by design
- ⬜ (A8) hw: a hardware probe inside a DLL that 4 threads keep LoadLibrary/FreeLibrary-ing
  (refcount reaches 0, so it really unloads and re-arms on every reload) misses hits: probe hits
  60 / 62 / 120 / 125 of 240 calls, x86 and x64, whatever backend the read probe uses (inline
  too, so only LOAD/UNLOAD/CREATE_THREAD events are involved); breakpoint and inline on the same
  site are exact. Intermittent on x64 (passed twice, then failed 3 of 4), steady on x86.
  Not yet proven. Leading suspect: UNLOAD_DLL of the old instance is processed AFTER the LOAD_DLL
  of the new instance mapped at the SAME base (the unmapping thread reports after the VA is free;
  another thread maps and reports first). The UNLOAD handler matches by base only, so it
  release_hw()s the probe that the new instance just armed (and erases module_bases[name]); the
  probe then stays pending until the next load. A per-base load count (skip teardown while a newer
  instance at that base is live) fixes hw; breakpoint/inline would additionally need LOAD to
  re-arm a probe still marked active at the same base. `hunt-dll-work-backend-hw` FAIL until fixed

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
  - ⬜ test: gated_config with MIXED backends (opens on breakpoint, reads on inline and vice versa) builds one handle->pid map; all reads attributed
  - ⬜ benchmark: per-hit cost with UHH_SHARED state vs plain globals, every backend -- must be equal
- ⬜ Log sink speed (simple): UHH logs/s to NUL vs a plain writer's rate into a file; one manual console run. Bar: UHH is never the bottleneck.
- ✗ (C10) helpers in probe_app: requested by the user; (C18) asm configparse: deliberate stable symbol+offset (add a PDB-local compiled variant later); (C19) _NT_SYMBOL_PATH is the requested symbol mechanism (tests may clear it)

## Frida-replica findings (examples/famous, 2026-11-05)
Classic Frida / API Monitor / Procmon recipes re-done on UHH (`examples/famous`: heap
tracker, file monitor incl. attach mid-run and real findstr/cmd, TLS plaintext from the real
curl.exe, loader/RWX watcher, return-value override), each one callback source under
breakpoint/hw/inline on x64+x86, compared with the uninstrumented run (`regress.py --only famous`).
- ✅ (F1) HW: a hardware probe armed at RUNTIME (from a callback, or at a later DLL load) was lost for whole threads still in loader initialisation: thread start ends in NtContinue with the creation-time context, debug registers included (the initial-thread entry fixup's mechanism, for every other thread). Found by `famous-retval-hw` (return-site probes added while workers start: whole workers 0/25 overridden). Fix: library-owned INT3 at `ntdll!RtlUserThreadStart` (armed the first time a hw probe is armed after entry/attach) re-applies the active DRs to each arriving thread. Test: `famous-retval-hw` x3 (+ 8/8 manual)
- ✅ (F2) HW: target killed by STATUS_SINGLE_STEP. Arming a hw probe writes every thread's debug registers -- DR6 included -- and on a thread whose #DB is still waiting to be reported that zeroes the B-bit, so the hit looked foreign and was passed to the target. Fix: a #DB with no B-bit exactly at an active, enabled hw EXECUTE probe is that probe's hit (`hw-dr6-lost` under PROBE_TRACE). Test: `famous-retval-hw`. Open: the same lost bit on a data WATCHPOINT cannot be inferred by address
- ✅ (F3) Inline: target died (STATUS_STACK_OVERFLOW, "probe_agent_init failed 0xC000041D") in ~half of short runs of an inline `RtlAllocateHeap` probe whose callback calls `call_func`: (a) the agent's thread_local region cache was touched before a starting thread had TLS (LdrpInitializeThread allocates it through the probed allocator) -> AV; (b) allocations inside call_func's own resolution/callee hit the probe again -> unbounded recursion. Fix: TLS presence checked (no cache until then); inline call_func now suppresses callbacks on its own thread for its duration -- the documented contract the breakpoint/hw path already kept. Test: `famous-heap-inline-reentry` (12 runs)
- ⬜ (F4) Same NtContinue/RtlRestoreContext wipe class, not covered: a thread inside exception dispatch when a hw probe is armed resumes with the old DRs
- ⬜ (F5) `call_func` from a breakpoint/hw callback returns 0 while another thread's callback is inside one (no nesting: the other thread's event is dispatched inside the first call). A Process.mainModule lookup via call_func silently skips that racing call; famous_common.h falls back to walking to the PE header. Library options: document in probe_api.h, or defer (replay) other threads' probe hits during a call
- ✗ (F6) HW budget: a recipe needing one return probe per call site exceeds the 4 debug registers when unfiltered (NtCreateFile is called from several KernelBase sites, CreateDirectory among them) -> clean `too many hardware probes` refusal. By design; the recipe's Procmon-style `--filter` keeps it to one site. Documented in the recipe README
- ✗ (F7) Observer effect: with inline probes, writing a hook makes the patched bytes PAGE_EXECUTE_READWRITE through the target's own NtProtectVirtualMemory (seen by an RWX watcher installed earlier: `rwx-protect size=0x8` in KernelBase); breakpoint/hw patch from the controller and are invisible. Documented (loader_rwx README)
- ⬜ (F8) The live log tail shares the target's inherited stdout: a target writing partial lines (cmd `type`) interleaves with tail lines mid-line, corrupting both for a line-based reader. The session JSONL file is unaffected (the famous checks read logs from it). Options: document; or tail to stderr/another handle when the target inherits stdout

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
- ⬜ (D2) **Live log tail splices records into the target's own stdout lines.** The child inherits
  the controller's stdout; records are written whole, but a target that writes partial lines
  (reg.exe writes `ProductName` and the padding separately; unbuffered UCRT stdout writes one
  character per WriteFile) gets `{"kind":"probe_log",...}` inserted mid-line, so its output as read
  from the controller's stdout is altered (and line-based consumers lose records). The log FILE is
  intact. No way to separate the two streams through the API today (stdout to NUL hides the
  target's output too). Workaround in the suite: `dt_split` cuts records back out of the line they
  landed in. Options: a separate tail handle/stream, or giving the child its own stdout pipe that
  the controller forwards line-wise.
- ⬜ (D3) **call_func from a breakpoint/hw callback fails while another thread's call_func is in
  flight.** The "no nesting" guard (`in_call_tid`) is session-wide: during thread A's call the
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
- ⬜ (D5) (code reading, not reproduced) absolute-address inline probes (`probe_add_address(...,
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
- 📄 Accounting edge: a callback killed by process exit AFTER publishing its log but BEFORE returning
  is reported both as a delivered log and in callbacks_interrupted (logs + dropped + interrupted can
  exceed hits by the number of such threads). No log is lost; closing it exactly needs a per-callback
  serial carried in the log record and matched by the controller. (The reverse window -- a hit counted
  with no log and not interrupted -- is closed: hit and in-flight are one atomic add.)
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
  with the controller's grammar (`module` with extension, matched by file name; `+0xHEX` only).
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
- ⬜ Open (seen on the x86 run of this branch, not caused by a portability change): `edgehunt-
  {breakpoint,hw}-fmtptr` expects `[unformattable] fmtptr %s` for a TARGET pointer printed with
  `%s` in a controller callback, but on x86 the same address can be mapped in the controller too
  and then prints the controller's bytes (`fmtptr W..}j`) -- the B10 behaviour itself; the
  check's expectation is address-layout dependent.
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
  📄 x64: the handler's ContextRecord shows our TF (the restart marker; it was visible before too).
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
  (PROBE_AGENT_VERSION 17, 1 MiB of the section, touched only as far as used) and, in a session with the
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
- 🔧 [fan-out] Intel CET shadow stacks (user-mode "Hardware-enforced Stack Protection", /CETCOMPAT): static audit done, every path that broke the shadow stack fixed or refused; **behaviour on real CET hardware still to be measured** (the test VM has no CET -- see below)
  - **The VM cannot test it:** its CPU is an Intel Core i5-6600 (Skylake, 2015 -- CET shipped with Tiger Lake / Zen 3), so `cet_probe` reports CPUID CET_SS=0, IBT=0, no OS CET_U state, RDSSP=0 and `EnableUserShadowStack=0` for a /CETCOMPAT process (Windows 10 19045, x64 and x86, under Proxmox/KVM). A newer host would also need a hypervisor that passes CET to the guest (KVM CET virtualization is recent). So every `cet-*` row on the VM proves only that /CETCOMPAT targets work under all backends, NOT that UHH survives an enforced shadow stack.
  - **Audit (x64; Windows does not enforce user shadow stacks for WoW64/x86 processes):**
    - ✅ Inline, every hit: SafetyHook's mid-hook stub ended `lea rsp,[rsp+8]; pop rsp; ret`, returning to the trampoline through an address it had PUSHED -- a #CP on every inline hit (fatal in strict mode; in compatibility mode at best a kernel fix-up per hit, since stub and trampoline are non-image memory). Fixed: the stub now ends `pop rsp; jmp [trampoline]` (`cmake/patch_safetyhook.cmake` step 3, applied to `third_party/safetyhook`; x64 the same 7 bytes, x86 one byte longer with a relocated `jmp [abs32]`). No `ret` remains on the hook path (the stub's own `call [destination]` is a real call/ret pair).
    - ✅ Inline `set_reg(SP)` (#8): the same patch makes the context's rsp/esp the stack pointer the hooked code resumes with -- nothing is written below the new SP (the old `trampoline_rsp` slot clobbered the saved registers when SP moved down). Re-enabled in `src/probe/agent.cpp`; conformance `sp_moved` now 10/10 on every backend.
    - ✅ Breakpoint emulation of CALL/RET (`emulate_site`): moves RSP/RIP but not SSP, so the target would #CP at its NEXT real `ret` inside its own CETCOMPAT code (fatal even in compatibility mode). Since 226f131 the emulation is skipped when `ProcessUserShadowStackPolicy.EnableUserShadowStack` is set and the CPU steps CALL/RET in place (JMP/Jcc/LOOP/PUSHF/POPF emulation is unaffected). Regress `cet-ret-breakpoint` (probe on NtOpenProcess's `ret` in probe_app_cet). That in-place CALL/RET step now runs in the in-place window (Evaluator round 3 #2: the other threads are held while the byte is lifted), so it is exact under threads too; the CPU still does the push/pop, so SSP stays consistent. The x64 SYSCALL trampoline has no call/ret (a `jmp [rip]` back), so it does not touch the shadow stack either.
    - ✅ `call_func` on breakpoint/hw (`call_in_target`): the callee is entered by SetThreadContext, so its `ret` to `call_trap` does not match the shadow stack -> #CP inside the callee (a CETCOMPAT system DLL: fatal). Now REFUSED (returns 0, one stderr warning) when the target has shadow stacks; inline `call_func` is a real call and unaffected. A working design for CET (return to the real shadow-stack top under a per-thread DR trap, then restore SSP through `CONTEXT_XSTATE`/`XSTATE_MASK_CET_U`) needs CET hardware to develop.
    - ⬜ SetThreadContext RIP changes (displaced stepping into scratch memory, moving frozen threads onto the trampoline, `call_func` restore, `set_reg`): no `ret` is involved and SSP is never touched (the controller never sets `CONTEXT_XSTATE`), so the CPU check does not apply. Open: Windows' optional `SetContextIpValidation` policy validates a new RIP against the shadow stack / EH-continuation table; whether it applies to a DEBUGGER's cross-process SetThreadContext is unverified. If it does, displaced stepping and the freeze move would be refused under that policy (in-place stepping would still work).
    - ⬜ `BlockNonCetBinaries` policy: the injected `probe_api_agent.dll` is not /CETCOMPAT and would be refused -> no inline backend in such a process. Linking the agent /CETCOMPAT is now plausible (its hook path has no ret-to-pushed-address) but untested.
  - Not exercised anywhere yet: the CET-only branches (CALL/RET in-place stepping and the `call_func` refusal) are keyed on `EnableUserShadowStack`, which the VM reports as 0 even for a /CETCOMPAT image -- correct (it reflects enforcement, not the image bit), but it means those branches never ran here. The policy is queried once per session and a failed query is cached as "no shadow stack".
  - **Test plan on CET hardware** (Intel Tiger Lake+ / AMD Zen 3+, Windows 10 21H1+/11 x64, bare metal or a hypervisor that passes CET through; `cet_probe` must print `enforced=true`): run `regress.py --only check_cet,check_conformance` and expect all PASS with `cet_enforced=True target_ssp=True`; then repeat with the process forced into strict mode (Exploit protection -> Program settings -> probe_app_cet.exe -> Hardware-enforced Stack Protection: on, strict) and with `SetContextIpValidation` on, to settle the two open items; then a `call_func` breakpoint/hw run to confirm the refusal is clean (returns 0, target unaffected).
  - Tests: `cet-image` (probe_app_cet/cet_probe carry the CETCOMPAT bit, probe_app does not), `cet-probe` (what the machine enforces), `cet-gated-{breakpoint,inline,hw}` (gated_config with all probes on one backend against `probe_app_cet`, exact hits/logs, checksum equal to an uninstrumented CET run, target's own RDSSP == cet_probe), `cet-ret-breakpoint`; `conformance-inline` sp_moved 10.
- ⬜ [fan-out] Windows 11 VM on the Proxmox server, run the suite there too (later)
- ⬜ [fan-out] Stability on real large apps (important): browsers / heavily multi-threaded / JIT processes under all backends
- ⬜ [fan-out, Codex] Docs: quickstart, API reference, per-backend limitations table, troubleshooting
- 🔧 Inline cap raised to 128 per session (user: 128 is enough; error beyond) -- compile-time thunk table, per-request FREEZE flag; refusal test uses the 129th -- VM verify pending
- 🔧 Follow child processes: design written -- [docs/child-processes.md](child-processes.md) (strategies with VM measurements from `bench/child_follow`, API options A-D, recommendation: ProcessDebugFlags inheritance + `probe_follow_children` + `get_pid`); **user to choose the API**, then implement
- ⬜ (maybe) CI on GitHub Actions; (maybe) CMake package + versioned release zip
- 🔧 (very last) Soak test: hours under load; handles/memory/threads flat -- `scripts/soak.py` (phases mixed / hw / breakpoint / attach-detach cycles, per-minute samples to CSV, exactness + checksum + growth verdict), opt-in `regress.py --soak-minutes N`; probe_app `--pace`. x64 mixed 30 min PASS (57.6M reads, all logged, controller/target flat); 1-min calibration of every phase PASS. **The VM froze twice during the 30-min all-hw phase** (at ~18 and ~22 min, ~12k hw hits/s; guest RAM exhausted while UHH's own processes stayed at ~2.5 MB private) -- suspected kernel-side memory growth per debug event / DR context switch (host logs a burst of `Unhandled WRMSR(0x1d9)` DEBUGCTL from the guest during hw runs). soak.py now samples available RAM, kernel paged/nonpaged pool and system handles and aborts below 1.5 GB. Next: a 3-minute hw run with 15 s samples to measure pool growth per hit before any long hw soak
- ✗ Controller-crash self-unhook (user: the analyst sees the controller died and restarts the target; not worth the cost)
- ✗ Named-object hardening (user: unlikely; a clash fails loudly)

## Later
- ⬜ x86 cumulative-session flakiness (possibly the same handle double-close; recheck)
- ✅ PDB-only symbols (`module!InternalFunc`), Microsoft symbol server via dbghelp+symsrv and `_NT_SYMBOL_PATH`, export/function enumeration (`uhh_trace --list`) — engine by Codex, wired into the library; suite checks added
- ⬜ Split `src/probe/session.cpp` (debug loop, backends, symbols, attach/call)
- 🔧 [fan-out] Faster builds (user, 2026-11-05): parallel MSBuild (/MP, MultiToolTask, Directory.Build.rsp -maxCpuCount; `-DUHH_PARALLEL_MSBUILD=OFF` to disable) and `scripts\build.ps1` (Ninja Multi-Config). VM (4 cores), same tree: clean x64 221 s -> 83 s (VS) / 73 s (Ninja), x86 220 s -> 85 s / 66 s; touch session.cpp x64 49 s -> 24 s / 23 s. Still open: PCH / unity for session.cpp, not relinking every example when the library changes
- ⬜ Final independent whole-codebase sanity review; README/API docs pass
