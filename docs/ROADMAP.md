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
- ✅ `send_log_stack`: raw frames at the hit, symbolized at report (dbghelp)
- ✅ Synchronous inline install: hold at entry point / at LOAD_DLL until hooks confirm (agent service thread). Handle double-close bug found and fixed; re-verifying
- ✅ Zero-drop inline logs: lock-free ring + controller drainer thread + backpressure. Must pass the 2M-event inline volume tier with `log_dropped == 0`
- ✅ Pre-hooked site report (live vs disk bytes, disassembly, pattern, destination, suggestions); `PROBE_ALLOW_PREHOOKED` / `PROBE_FALLBACK_HW`
- ✅ `call_func`: call target functions from any callback (direct for inline; debugger-run call on the stopped thread for breakpoint/hw); pointer-sized args on both arches. Further hardening of the breakpoint/hw path was not pursued
- ✅ `probe_attach` (clean detach: hooks removed, INT3s restored, DRs cleared, no thread mid-step), `probe_attach_new`
- 🔧 Inline register overrides counted in the report (`overrides`) like controller-side ones
- ✅ x86 `send_log_stack` at a function's first instruction includes the caller frame (agent and controller)
- ⬜ Log sink: stream logs as they arrive (flat memory at millions of events)
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
- ✅ Inline sites whose overwritten bytes contain a non-final CALL (a thread in the callee would return mid-jump): refused, or hardware with `PROBE_FALLBACK_HW`
- ✗ Handle->pid through `kernel32!OpenProcess`: example design, documented (not a library item)
- ✅ Memory reads/writes at scale: millions of `get_mem`/`set_mem` across threads and backends; exact values, writes visible to the target, page-crossing and large sizes, unmapped/protected addresses fail cleanly, throughput per backend
- 🔧 Continuous evaluators (two full rounds done; more to come): independent agents repeatedly hunting edge cases, regressions and gaps against the gated_config use case

## Gaps from the goal gap-analysis (evaluator, 2026-11-04) — each closes with a test
- ✅ P1 detach while running: probe_close from another thread stops probe_run, which detaches on its own thread (debug-API rule); target finishes correctly, bytes == disk, DR7 == 0, debugger gone
- ✅ P1 unload/reload of a probed DLL: inline must re-arm like breakpoint/hw (hits == 3N per backend)
- ✅ P1 probe_add_symbol_cfg forwarded from inline callbacks (config travels over IPC)
- ✅ P1 one log length limit for every backend, truncation marked (inline was 256 vs 2048)
- ✅ P1 log delivery when the target crashes / is killed (logs + log_dropped == hits)
- ⬜ P1 controller-side log memory: no unhandled bad_alloc; memory measured at 2M/20M
- ✅ P1 probe_attach_new exercised (second instance, timeout path)
- ✅ P1 target checksum asserted equal across every mix cell and vs a flag-only run
- ⬜ P2 hw PROBE_ONCE and watch RW|ONCE proven distinctly; 5th hw probe refused cleanly (setup and runtime), slot reuse after ONCE
- ⬜ P2 runtime adds on a DLL loaded later by a non-main thread (all backends); probe_add_address(PROBE_INLINE) from a callback
- ⬜ P2 threads started during the entry hold (TLS/DllMain thread calling the probed function)
- 🔧 P2 refusal tests: PROBE_AT_RETURN, inline ONCE, 33rd inline probe ✅; ALLOW_PREHOOKED inline assertion ⬜
- ✅ P2 sidefx: full arithmetic EFLAGS (probe between cmp and jcc), LastStatus; below-SP documented as exempt
- ⬜ P2 x86 stacks mid-function / FPO frames identical across backends
- ⬜ P2 mixed backends for state-sharing probes: documented limitation (state lives where callbacks run)

## Evaluator round 3 (2026-11-05) — open
- ✅ (#3) detach after a hooked DLL unloaded wrote original bytes to unmapped/reused memory -> agent skips UNLOADED hooks
- ✅ (#4) call inside the stolen bytes -> refused / hw fallback
- ⬜ (#1) in-place step of `pushf` leaks TF into the pushed flags (RtlCaptureContext) -> clear TF in the pushed value
- ⬜ (#2) in-place fallback (branch/call/rep/pushf sites) not exact under threads: missed hits while lifted, double hit via queued INT3
- ⬜ (#5) x86 inline send_log_stack / set_mem can raise first-chance AVs the target's VEH sees; t_region cache never invalidated
- ⬜ (#6) breakpoint/hw call_func: last-error/status, x86 FP, YMM not restored; callee exceptions abort the call
- ⬜ (#7) call_func on forwarded exports works inline, fails breakpoint/hw
- ⬜ (#8) set_reg(SP) honoured by breakpoint/hw, silently dropped inline (but counted)
- ⬜ (#9) detach while agent work in flight leaves inline hooks live
- ⬜ (#10) inline re-attach to a previously detached process fails (mapping/g_stopping persist)
- ⬜ (#11) slow install releases holds after 5 s silently; HOOK_FAILED stops accepting later probes
- ⬜ (#12) tests: attach flag probe only breakpoint; detach/crash logs not counted multi-thread; x87 status word
- ⬜ probe_close 15 s timeout path: detach on the wrong thread while probe_run still detaching (use-after-free)
- ⬜ frida_coexist hangs (found again 2026-11-05)

## Codex workaround audit (2026-11-05) — triaged
- ✗ (C1) handle->pid through kernel32!OpenProcess: example-callback design, not a library issue (user, 2026-11-05); documented in the gated_config README
- ⬜ (C11) example handle map: no silent 1024 cap
- ⬜ (C3) attach holds threads until inline hooks are confirmed (like launch); attach test without the gate, target already busy
- ⬜ (C12) runtime inline add holds the calling thread until the hook lands; drop the 300 ms sleeps in conformance/dynwatch
- ⬜ (C4) uhh_trace: exact backend unless --fallback-hw; every test asserts the effective backend
- ⬜ (C5/C8) docs: logging-plan.md rewritten to the lossless contract; README/probe_app comments off ReadThunk/OpenThunk
- ⬜ (C14/C15) suite: missing binaries FAIL, skips not counted as passes, both-arch aggregate, volume tier in the release run
- ⬜ (C9) detach test on ntdll stub, synchronized on 'active', no sleep
- ⬜ (C13) PROBE_AT_RETURN: implement or document precisely
- ⬜ (C16) breakage inline rows gating (preserve or clean refusal)
- ⬜ (C20) attach_new: all backends, ntdll site, no sleeps/gate
- ⬜ (C6) anti-tamper/anti-debug: document per-backend visibility; behaviour == baseline
- ⬜ (C7) mixed-backend shared state: design question (documented)
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

## Later
- ⬜ x86 cumulative-session flakiness (possibly the same handle double-close; recheck)
- ✅ PDB-only symbols (`module!InternalFunc`), Microsoft symbol server via dbghelp+symsrv and `_NT_SYMBOL_PATH`, export/function enumeration (`uhh_trace --list`) — engine by Codex, wired into the library; suite checks added
- ⬜ Split `src/probe/session.cpp` (debug loop, backends, symbols, attach/call)
- ⬜ Final independent whole-codebase sanity review; README/API docs pass
