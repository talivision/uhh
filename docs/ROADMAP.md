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
- 🔧 Synchronous inline install: hold at entry point / at LOAD_DLL until hooks confirm (agent service thread). Handle double-close bug found and fixed; re-verifying
- 🔧 Zero-drop inline logs: lock-free ring + controller drainer thread + backpressure. Must pass the 2M-event inline volume tier with `log_dropped == 0`
- 🔧 Pre-hooked site report (live vs disk bytes, disassembly, pattern, destination, suggestions); `PROBE_ALLOW_PREHOOKED` / `PROBE_FALLBACK_HW`
- 🔧 `call_func`: call target functions from any callback (direct for inline; debugger-run call on the stopped thread for breakpoint/hw)
- 🔧 `probe_attach` (clean detach: hooks removed, INT3s restored, DRs cleared, no thread mid-step), `probe_attach_new`
- 🔧 Inline register overrides counted in the report (`overrides`) like controller-side ones
- ⬜ x86 inline `send_log_stack` at a function's first instruction: include the caller frame (`[esp]`)
- ⬜ Log sink: stream logs as they arrive (flat memory at millions of events)
- ⬜ Performance pass on every hot path (per-hit cost per backend and per method; see Benchmarks)

## Examples and targets (subagent, own worktree)
- 🔧 Move `probe_app` + `configparse` to `examples/targets/`; target spawns helpers, enumerates PIDs, opens and reads them **only when the config flag is on**
- 🔧 `examples/gated_config`: config ships DISABLED; breakpoint flips the flag (the metrics technique); logs every read
- 🔧 `examples/attach` (`uhh_attach <pid> --pid P --range BASE:SIZE`): attach, same flag flip, NtOpenProcess handle->pid map, filtered read logging; README steps
- 🔧 Clean drivers: no env vars, no sibling-path helpers, target path on the command line

## Correctness matrix (attest every method under every callback type)
- ⬜ Conformance test: each of `get_reg`, `set_reg`, `get_func_arg`, `get_mem`, `set_mem`, `get_config`, `send_log`, `send_log_stack`, `call_func`, and the control ops via `get_session` (`probe_add_symbol`, `probe_add_address`, `probe_watch`) asserted under breakpoint, hw and inline callbacks, x64 and x86
- ✅ Exact hit counts at 8 threads, all backends; ✅ 2M hits exact all backends
- ✅ Logs == hits, `log_dropped == 0` asserted (normal tier); 🔧 volume tier for inline

## Program-correctness guarantees (probes must have no side effects)
- ⬜ Side-effect audit + tests: after any callback, the target observes no change except deliberate `set_reg`/`set_mem`: `GetLastError()`, `errno`, x87/SSE/AVX state, EFLAGS, TEB fields, stack contents below SP — under breakpoint, hw and inline
- ✅ Loader-time probe hits (a probe firing before the loader breakpoint) handled as hits, not swallowed (was crashing findstr x86)
- 🔧 Inline sites sharing a page with ntdll routines the installer needs -> hardware fallback / clear refusal, never a crash
- ⬜ Memory reads/writes at scale: millions of `get_mem`/`set_mem` across threads and backends; exact values, writes visible to the target, page-crossing and large sizes, unmapped/protected addresses fail cleanly, throughput per backend
- ⬜ Continuous evaluators: independent agents repeatedly hunting edge cases, regressions and gaps against the gated_config use case

## Benchmarks
- ✅ UHH vs Frida (Interceptor / CModule / Stalker / HW) — `bench/BENCHMARKS.md`
- 🔧 Per-log overhead ceilings in the suite (`log-throughput-*`)
- ✅ Inline extended-state strategy measured (`bench/hitcost`): gated save = +1-5% vs +70% for a full save; gated is default
- ⬜ Inline hot path: ~75 ns/hit is high for a mid-hook — 3 shared atomics per hit (hit count + in-flight); stripe/per-thread them, keep exact
- ⬜ Per-method, per-backend benchmark table (hit, get_reg/set_reg, get_mem, send_log, send_log_stack, call_func, control ops)

## Real-world cases
- ✅ (1) Real binaries via `uhh_trace`: curl `CreateFileW` + `connect` (all backends); 🔧 findstr via `ntdll!NtCreateFile`
- 🔧 Targets written by Codex in `examples/realworld/`, to integrate into CMake + suite:
  - ⬜ (4) Re-entrancy: inline malloc hook whose callback logs/allocates
  - ⬜ (8) Thread stress: 128 threads, suspended-then-resumed, thread pool, thread churn mid-step
  - ⬜ (6) Anti-tamper: `.text` / function-byte checksums and DR visibility, measured per backend
  - ⬜ (7) Anti-debug: IsDebuggerPresent, debug port/object/flags, PEB, timing — measured and documented
  - ⬜ (3) Exceptions (C++, SEH, through a callback) unwinding across hooked frames
- ⬜ (9) Hot-patch `mov edi,edi` prologues (x86 system DLLs); coexistence with Frida hooking the same function

## Later
- ⬜ x86 cumulative-session flakiness (possibly the same handle double-close; recheck)
- 🔧 PDB-only symbols (`module!InternalFunc`), Microsoft symbol server via dbghelp+symsrv and `_NT_SYMBOL_PATH`, export/function enumeration (`uhh_trace --list`) — Codex, tmux `codex-sym`
- ⬜ Split `src/probe/session.cpp` (debug loop, backends, symbols, attach/call)
- ⬜ Final independent whole-codebase sanity review; README/API docs pass
