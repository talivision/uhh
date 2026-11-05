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
- ✅ (#8) inline set_reg(SP): honoured -- SafetyHook's resume stub patched to `pop rsp; jmp [trampoline]` (also the CET fix, see Production readiness), the context rsp is the resume SP; conformance `sp_moved` 10/10 on every backend, x64 + x86
- 🔧 (#9) detach waits for in-flight agent work; agent install/stop serialized (SRW lock), no install after stop -- VM verify pending
- 🔧 (#10) re-attach reuses the agent channel; agent re-arms on init -- VM verify pending (ntdll-churn-inline)
- 🔧 (#11) every inline probe is accepted/retired before a failure is reported; (5 s hold timeout still a warning)
- 🔧 (#12) uhh_attach --flag-backend, attach test flips the flag on every backend; (detach/crash multi-thread log counts, x87 status word: open)
- ✅ probe_close waits for probe_run to return (warns every 15 s), never tears down underneath it
- ⬜ frida_coexist hangs (found again 2026-11-05)

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
