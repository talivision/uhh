# UHH roadmap (living tracker)

Status: ✅ done and verified on x64 + x86 · 🔧 in progress · ⬜ not started.
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
- ⬜ (#8) inline set_reg(SP): currently REFUSED (returns 0) -- the trampoline_rsp approach overwrote saved registers when SP moves down. Real fix: patch SafetyHook's resume stub to `pop rsp; jmp [trampoline]` (also needed for CET) and make the context rsp writable; conformance `sp_moved` expects 0 for inline until then
- 🔧 (#9) detach waits for in-flight agent work; agent install/stop serialized (SRW lock), no install after stop -- VM verify pending
- 🔧 (#10) re-attach reuses the agent channel; agent re-arms on init -- VM verify pending (ntdll-churn-inline)
- 🔧 (#11) every inline probe is accepted/retired before a failure is reported; (5 s hold timeout still a warning)
- 🔧 (#12) uhh_attach --flag-backend, attach test flips the flag on every backend; (detach/crash multi-thread log counts, x87 status word: open)
- ✅ probe_close waits for probe_run to return (warns every 15 s), never tears down underneath it
- ⬜ frida_coexist hangs (found again 2026-11-05)

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
- ⬜ (C11) example handle map: no silent 1024 cap
- 🔧 (C3) attach holds every thread until inline hooks are confirmed (implemented); attach test without the gate pending
- 🔧 (C12) runtime inline add holds the calling thread until the hook lands (implemented); drop the 300 ms sleeps in conformance/dynwatch pending
- 🔧 (C4) uhh_trace: exact backend unless --fallback-hw (done); realworld matrix asserts the effective backend (done); remaining tests audited as they are touched
- ✅ (C5/C8) docs: logging-plan.md marked superseded with the lossless contract; README/probe_app comments on the ntdll stubs
- 🔧 (C14/C15) suite: missing binaries FAIL, skips not counted as passes (done); release runs pass --volume-reads; streaming adds 20M-log tests
- 🔧 (C9) detach test on ntdll stub, synchronized on 'probe: active', no sleep -- VM verify pending
- ✅ (C13) PROBE_AT_RETURN: deliberately not a feature (user, 2026-11-05) -- return points are hooked naturally: read the return address at entry and probe_add_address it from the callback; documented in probe_api.h. (Optional: delete the flag -- API change, user's call)
- ⬜ (C16) breakage inline rows gating (preserve or clean refusal)
- ⬜ (C20) attach_new: all backends, ntdll site, no sleeps/gate
- ⬜ (C6) anti-tamper/anti-debug: document per-backend visibility; behaviour == baseline
- ⬜ (C7) Shared state across backends -- `UHH_SHARED` (user-approved 2026-11-05). Default stays "probes that share state use one backend". Opt-in: globals marked `UHH_SHARED` live in a shared PE section (`/SECTION:uhhshr,RWS`) of the callbacks DLL; the controller runs breakpoint/hw callbacks from ITS copy of that same DLL file and the target runs inline callbacks from its copy, so both see the same physical pages with plain native access. Per-session copy of the DLL (unique path) so separate sessions never share; deleted at close. Rules: no pointers in shared state (bases differ), constant/zero init only, lock-free atomics for sync. Only enabled when the DLL actually has the section (no behaviour change otherwise).
  - ⬜ test: gated_config with MIXED backends (opens on breakpoint, reads on inline and vice versa) builds one handle->pid map; all reads attributed
  - ⬜ benchmark: per-hit cost with UHH_SHARED state vs plain globals, every backend -- must be equal
- ⬜ Log sink speed (simple): UHH logs/s to NUL vs a plain writer's rate into a file; one manual console run. Bar: UHH is never the bottleneck.
- ✗ (C10) helpers in probe_app: requested by the user; (C18) asm configparse: deliberate stable symbol+offset (add a PDB-local compiled variant later); (C19) _NT_SYMBOL_PATH is the requested symbol mechanism (tests may clear it)

## Benchmarks
- ✅ UHH vs Frida (Interceptor / CModule / Stalker / HW) — `bench/BENCHMARKS.md`
- ✅ Per-log overhead ceilings in the suite (`log-throughput-*`)
- ✅ Inline extended-state strategy measured (`bench/hitcost`): gated save = +1-5% vs +70% for a full save; gated is default
- 🔧 Inline hot path (striped counters implemented; measurement pending): ~75 ns/hit is high for a mid-hook — 3 shared atomics per hit (hit count + in-flight); stripe/per-thread them, keep exact
- ⬜ Per-method, per-backend benchmark table (hit, get_reg/set_reg, get_mem, send_log, send_log_stack, call_func, control ops)

## Real-world cases
- ✅ (1) Real binaries via `uhh_trace`: curl `CreateFileW` + `connect` (all backends); ✅ findstr via `ntdll!NtCreateFile`
- ✅ Targets written by Codex in `examples/realworld/`, in CMake + suite:
  - ✅ (4) Re-entrancy: inline malloc hook whose callback logs/allocates
  - ✅ (8) Thread stress: 128 threads, suspended-then-resumed, thread pool, thread churn mid-step
  - ✅ (6) Anti-tamper: `.text` / function-byte checksums and DR visibility, measured per backend
  - ✅ (7) Anti-debug: IsDebuggerPresent, debug port/object/flags, PEB, timing — measured and documented
  - ✅ (3) Exceptions (C++, SEH, through a callback) unwinding across hooked frames
- ✅ (9) Hot-patch `mov edi,edi` prologues (x86); 🔧 coexistence with Frida hooking the same function

## Production readiness (user decisions 2026-11-05)
- ⬜ [fan-out] Intel CET shadow stacks: test /CETCOMPAT targets on CET hardware (SafetyHook's resume path, inline set_reg(SP), call_func all use ret-to-pushed-address)
- ⬜ [fan-out] Windows 11 VM on the Proxmox server, run the suite there too (later)
- ⬜ [fan-out] Stability on real large apps (important): browsers / heavily multi-threaded / JIT processes under all backends
- ⬜ [fan-out, Codex] Docs: quickstart, API reference, per-backend limitations table, troubleshooting
- 🔧 Inline cap raised to 128 per session (user: 128 is enough; error beyond) -- compile-time thunk table, per-request FREEZE flag; refusal test uses the 129th -- VM verify pending
- ⬜ Follow child processes: write docs/child-processes.md -- strategies + robust API options for the user to choose from (during the soak test)
- ⬜ (maybe) CI on GitHub Actions; (maybe) CMake package + versioned release zip
- ⬜ (very last) Soak test: hours under load; handles/memory/threads flat
- ✗ Controller-crash self-unhook (user: the analyst sees the controller died and restarts the target; not worth the cost)
- ✗ Named-object hardening (user: unlikely; a clash fails loudly)

## Later
- ⬜ x86 cumulative-session flakiness (possibly the same handle double-close; recheck)
- ✅ PDB-only symbols (`module!InternalFunc`), Microsoft symbol server via dbghelp+symsrv and `_NT_SYMBOL_PATH`, export/function enumeration (`uhh_trace --list`) — engine by Codex, wired into the library; suite checks added
- ⬜ Split `src/probe/session.cpp` (debug loop, backends, symbols, attach/call)
- ⬜ [fan-out] Faster builds (user, 2026-11-05): incremental rebuilds should be seconds -- precompiled headers / unity build for session.cpp, avoid rebuilding every example when the library changes, Ninja instead of MSBuild, ccache-style caching
- ⬜ Final independent whole-codebase sanity review; README/API docs pass
