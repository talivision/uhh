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
- ⬜ P2 hw PROBE_ONCE and watch RW|ONCE proven distinctly; 5th hw probe refused cleanly (setup and runtime), slot reuse after ONCE
- ⬜ P2 runtime adds on a DLL loaded later by a non-main thread (all backends); probe_add_address(PROBE_INLINE) from a callback
- ⬜ P2 threads started during the entry hold (TLS/DllMain thread calling the probed function)
- 🔧 P2 refusal tests: PROBE_AT_RETURN, inline ONCE, 129th inline probe ✅; ALLOW_PREHOOKED inline assertion ⬜
- ✅ P2 sidefx: full arithmetic EFLAGS (probe between cmp and jcc), LastStatus; below-SP documented as exempt
- ⬜ P2 x86 stacks mid-function / FPO frames identical across backends
- ⬜ P2 mixed backends for state-sharing probes: documented limitation (state lives where callbacks run)

## Evaluator round 3 (2026-11-05) — open
- ✅ (#3) detach after a hooked DLL unloaded wrote original bytes to unmapped/reused memory -> agent skips UNLOADED hooks
- ✅ (#4) call inside the stolen bytes -> refused / hw fallback
- ⬜ (#1) in-place step of `pushf` leaks TF into the pushed flags (RtlCaptureContext) -> clear TF in the pushed value
- ⬜ (#2) in-place fallback (branch/call/rep/pushf sites) not exact under threads: missed hits while lifted, double hit via queued INT3
- 🔧 (#5) inline stack walk bounded by the thread's TEB stack limits + code reads range-checked (never faults); writes always re-validated (read cache kept across hits) -- VM verify pending
- ✗ (#6) breakpoint/hw call_func hardening: deliberately not pursued (see call_func note above)
- 🔧 (#7) call_func follows forwarded exports on breakpoint/hw (via the controller's copy of the same system DLL); conformance `call_func-forwarded` -- VM verify pending
- ✅ (#8) inline set_reg(SP): honoured -- SafetyHook's resume stub patched to `pop rsp; jmp [trampoline]` (also the CET fix, see Production readiness), the context rsp is the resume SP; conformance `sp_moved` 10/10 on every backend, x64 + x86
- 🔧 (#9) detach waits for in-flight agent work; agent install/stop serialized (SRW lock), no install after stop -- VM verify pending
- 🔧 (#10) re-attach reuses the agent channel; agent re-arms on init -- VM verify pending (ntdll-churn-inline)
- 🔧 (#11) every inline probe is accepted/retired before a failure is reported; (5 s hold timeout still a warning)
- 🔧 (#12) uhh_attach --flag-backend, attach test flips the flag on every backend; ✅ detach/crash multi-thread log counts: `detach-*` (4 threads; probe_close prints `probe: detached: hits= logs_written= log_dropped=` AFTER the detach; logs == hits == written, 0 dropped -- found and fixed: inline counted hits that the unhooking agent passed straight through without a callback) and `crash-logs-*-4t` (4 threads logging when the target dies; logs == hits); (x87 status word: open)
- ✅ probe_close waits for probe_run to return (warns every 15 s), never tears down underneath it
- ⬜ frida_coexist hangs (found again 2026-11-05)

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
- ⬜ (B5) attach + inline into a CLR process (PowerShell): every thread is held while the
  agent is injected; intermittently (1 of ~8 runs) a held thread blocks the injection
  (loader/heap/CLR lock) and the hold lasts until the 5 s timeout or detach -- target
  frozen, inline probe not live in that window (seen: hits=0, "released 19 held
  thread(s) (detach)" at 2.5 s). Fix idea: hold only for the install itself (after the
  agent is loaded and its service thread is up), not across LoadLibrary / thread start.
  Test: `blog-pwsh-attach-detach-inline` (fails when it happens; 2 of ~10 x64 runs).
  Same family seen once on x86 `attach-inline` (1 of 4): the LOAD_DLL hold for
  configparse hit "inline install not confirmed within 5 s", the flag probe missed the
  parse, 0/8000 reads.
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
    - ✅ Breakpoint emulation of CALL/RET (`emulate_site`): moves RSP/RIP but not SSP, so the target would #CP at its NEXT real `ret` inside its own CETCOMPAT code (fatal even in compatibility mode). Since 226f131 the emulation is skipped when `ProcessUserShadowStackPolicy.EnableUserShadowStack` is set and the CPU steps CALL/RET in place (JMP/Jcc/LOOP/PUSHF/POPF emulation is unaffected). Regress `cet-ret-breakpoint` (probe on NtOpenProcess's `ret` in probe_app_cet).
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
- ⬜ [fan-out] Faster builds (user, 2026-11-05): incremental rebuilds should be seconds -- precompiled headers / unity build for session.cpp, avoid rebuilding every example when the library changes, Ninja instead of MSBuild, ccache-style caching
- ⬜ Final independent whole-codebase sanity review; README/API docs pass
