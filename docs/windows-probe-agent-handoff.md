# Windows native probe library — design and agent handoff

Date: 4 November 2026

## Assignment

Continue the attached `probe-first-pass.zip` on a Windows machine. Build it, fix build/runtime failures, extend the controlled example to require new-process-by-name attachment and deferred module-load probes, prove it works across the implemented backends, and collect reproducible performance measurements. Preserve the shared callback design below. Work autonomously through the correctness gates before benchmarking; return the changed source, build/run instructions, raw results and a concise findings report.

The source archive is available at:
[probe-first-pass.zip](https://chatgpt.com/library?file_id=libfile_babd3bab3b14819186c06860b91e3800&account_id=personal).
If your environment cannot access that link, have the user attach the archive alongside this document. Extract it and work from its `probe-first-pass` directory. This handoff distinguishes the agreed destination from the smaller prototype; do not assume all intended features already exist.

## Agreed design

Build a Windows user-mode instrumentation library with a plain C API. The user writes an ordinary native command-line program, owns argument parsing and session setup, and supplies small compiled C callbacks. A callback can inspect/filter state, read/write target memory, change supported registers and emit structured logs at a selected execution point.

The same callback SOURCE and signature should work with either an external debugger breakpoint or an in-process inline trampoline. The backend is selectable per probe in the intended API. This means compiling the source into the appropriate artifacts, not transporting a function pointer or assuming identical machine code across architectures.

The intended user experience is illustrated below. This registration API is a design sketch, NOT an API implemented in the current archive:

```c
probe_session *s = probe_attach(pid);
/* inspect is the callback; &config points to user-defined settings. */
probe_add(s, "unknown.dll+0x134", inspect, &config, PROBE_BREAKPOINT);
/* unknown.dll is not loaded yet: registration succeeds in a pending state. */
/* Select PROBE_INLINE for a hot site, keeping inspect's source unchanged. */
probe_run(s);
```

Required properties of the eventual library:

- Shell-first operation through a standalone executable; no interactive WinDbg/CDB requirement.
- Probe locations include absolute addresses, module offsets and symbols; defer resolution until a referenced module loads.
- Support mid-function instruction boundaries. Do not infer function arguments or a function-entry stack layout at arbitrary sites.
- Present logical target state immediately before the selected instruction. For inline mode, normalize the reported PC to the original probe address, not the trampoline address.
- Apply supported register modifications before executing displaced/original instructions. Restore all other machine state that the backend promises to preserve.
- Make loading the agent, registering probes and transporting configuration/logs part of the tooling.
- Keep filtering native. In inline mode it executes inside the target, without controller round trips on every hit.

The engine choice is an implementation detail. We initially discussed DbgEng or TitanEngine for debugging and SafetyHook for mid-function trampolines. The first pass instead uses the native Win32 debug-event API directly, plus SafetyHook. Keeping that implementation is acceptable while validating the design.

## Callback, memory and state contract

Use a common context containing register state, site/thread identity, a backend handle and a table of helper operations. A target address is an integer address in the target's address space; a callback buffer is local to wherever that callback runs.

| Facility | External debugger backend | Inline backend |
|---|---|---|
| Callback executes in | Controller executable | Agent DLL inside target |
| Registers | Stopped-thread context | Captured trampoline context |
| Target memory access | External process-memory helpers | Local helpers with fault handling |
| Logs | Controller buffers records | Agent buffers records; controller collects them |
| Configuration | Controller-owned data | Copied/serialized agent-local data |

Callback code must use helpers for target memory. Do not dereference a target address directly in shared snippet code, pass controller heap pointers into the agent, or assume global variables are shared between the two compiled copies.

Memory helpers report failure and short transfers; writes are not transactional or necessarily atomic. Define protection handling explicitly. A failed write may have partially modified memory. Stack unwinding and memory reads should be requested only when needed, rather than fetched on every hit.

The portable callback contract covers inspection, filtering, supported state modification and structured logging. Whole-process pause, single-step, redirection of control flow and debugger-specific actions require explicit capabilities. Do not silently pretend these have identical semantics in inline mode.

Eventually inline callbacks must tolerate concurrent target threads. The debugger event loop and inline callbacks have different scheduling and concurrency semantics. The current fixture is single-threaded for probe execution and does not solve that yet.

Architecture support is intended to expand through explicit architecture-specific register layouts/adapters. The first pass is Windows x64 only; ARM64, WOW64 and extended CPU state are not implemented. Never treat a Windows CONTEXT as a literal complete CPU-switch image.

## Existing-hook requirement

Assume another hook can already be installed when our probe arrives. Our callback should run first and then execution should follow that existing redirect/handler and its original trampoline. Preserve the observed patched code; do not restore pristine DLL bytes, bypass the existing handler, or treat its behavior as unwanted.

The controlled example must install the pre-existing layer BEFORE our probe, at the SAME read-wrapper entry address. Verify the old handler runs exactly once per read and that original behavior still completes correctly. Remove our layer before removing the old layer.

Inspect and report the bytes found before installation. Recognize supported redirect patterns; classify unfamiliar bytes as unknown. A matching known clean fixture is a special case, not universal proof of an unhooked function. Safe failure for unsupported relocation is preferable to bypassing the old layer. Arbitrary compatibility with hooks independently installed/removed by other tools is not guaranteed.

## Contrived example to preserve

The original use case is a program whose flag controls whether it performs many `NtReadVirtualMemory` calls. We change that flag mid-execution, then observe/filter reads by selected process and address range.

The current supplied target makes this deterministic (it does NOT yet exercise deferred loading):

1. Launch two helper processes with known byte patterns in known buffers: one selected process and one decoy.
2. In mutation mode, reset the flag to zero each iteration.
3. Cross an assembly label inside `FlagCheck`. The memory variant changes the flag before its load. The register variant changes RAX after its load.
4. Branch on the resulting flag. A zero flag genuinely skips the read.
5. Issue one read through `ReadThunk`, an assembly wrapper with the `NtReadVirtualMemory` ABI that forwards to the actual ntdll export.
6. Rotate through four requests: selected/in-range; selected/out-of-range; decoy/in-range; selected/in-range at another offset.
7. Independently verify status, bytes transferred, contents and final checksums.

The read probe is currently on the fixture's wrapper, not a general interception of every direct call to the ntdll export. The process filter uses a known process HANDLE, not a general handle-to-PID resolver. Keep these limits explicit.

Probe records describe attempted reads. The target independently checks completion. Matching return probes, nested calls and completion-status logging are future extensions.

With prehook enabled, a SafetyHook entry detour on `ReadThunk` increments a separate counter and forwards through its original trampoline. Our probe is installed over that existing entry patch. The count must equal warmup + measured iterations. In disabled mode it must remain zero.

## Required extension: catch the next new process by name

Add a standalone mode that waits for a NEW instance of a named executable, then
attaches and installs the configured probes. Existing instances must be excluded.
Illustrative CLI only; this is not implemented in the current archive:

```text
myprobe --wait-name example.exe --new-only
```

Required behavior:

- Arm process-start discovery before announcing watcher-ready. Establish a
  consistent baseline/cutoff without a gap between enumerating old processes
  and subscribing. Eligibility depends on when the process started relative to
  that boundary, not when a notification was delivered.
- Ignore every instance that already existed at the boundary, including old
  instances discovered later. Do not attach to, pause or modify those processes.
- Use PID plus creation identity/time so PID reuse cannot confuse old and new
  instances. Reject stale notifications belonging to an old process identity.
- Match executable basename exactly and case-insensitively on Windows, not by
  substring. Support an optional full-image-path restriction for duplicate names.
- Default to one-shot selection of the first eligible matching start under the
  documented event ordering. Stop selecting after successful attachment. Define
  tie-breaking and retry behavior for simultaneous starts or attachment failure;
  never fall back silently to an old instance.
- Report readiness, selected PID/image/creation identity, attachment success or
  failure, and exit-before-attach. Support timeout and cancellation.
- Register deferred probes during session setup. Reconcile modules already
  loaded by attach time as well as subsequent load events; avoid duplicate probe
  installation if a load races with the initial module inventory.

An observer attaching after process creation has an unavoidable delivery and
scheduling window: the process may have executed and loaded DLLs before attach.
Do not claim this mode intercepts the first instruction, TLS callbacks, DllMain,
or probe sites already crossed before attachment. If strict start control is
needed, expose a separate launch-under-debugger/suspended-launch mode for a
process we create. Intercepting independently launched processes before they
execute requires a separately chosen debugger-launch/creation interception
facility; do not silently enable a machine-wide mechanism or describe polling
or ordinary process-start notifications as that guarantee.

Required fixture checks:

1. Keep an old matching target running before watcher startup.
2. Arm the watcher, wait for its ready signal, then launch a new matching target.
3. Prove only the new instance is attached/instrumented. The old instance must
   retain its original flag behavior and produce no probe callbacks.
4. Gate the new fixture's delayed DLL load until attachment/probe readiness, then
   run the deferred-probe and existing-hook checks. This proves first-call
   interception in the gated fixture, not arbitrary first-instruction capture.
5. Test nonmatching names, same-name/different-path filtering, early exit,
   timeout/cancellation and competing new starts. Test stale identity/PID-reuse
   classification deterministically if live PID reuse is impractical.

## Required extension: deferred activation on DLL load

The contrived example MUST require registering at least one probe while its DLL
is absent, then resolving and activating it when that DLL loads. This is part of
the first Windows acceptance milestone, not a future optional feature.

The requested debugger workflow is conceptually “set a pending module+offset
breakpoint, observe the module-load event, then continue.” Provide this through
the standalone library, without requiring interactive WinDbg commands. An
unresolved location must remain a pending registration, not an error or a
breakpoint at the numeric offset alone. `0x134` is an illustrative RVA, not an
instruction address that may be assumed valid in a newly built DLL.

A concrete fixture arrangement that preserves the existing-hook experiment:

1. Move the flag-checking function and its stable mid-function probe labels into
   a new DLL such as `unknown.dll`. Do not link it as a startup dependency or
   otherwise load it before registration. Keep `ReadThunk` and its pre-existing
   detour in the executable, so the old read hook can already be present before
   deferred activation. Both requirements then hold without relying on work
   performed inside DllMain.
2. Before the DLL is loaded, register the shared flag callback against a textual
   `unknown.dll+<RVA>` location. Build tooling may produce the correct site RVA
   from a map/export for this fixture; runtime registration must not depend on
   obtaining a live target address from the target after it loads. Keep this
   configuration identical across backends except for backend selection.
3. Assert/report the probe as pending with zero callback hits. The target does
   unrelated work before explicitly loading the DLL at a deterministic gate.
4. Detect the actual load, find its target-process image base under ASLR, and
   resolve `base + RVA`. Validate that the location belongs to the expected
   image and is an intended instruction boundary. Record the transition to
   active. Do not use a local DLL mapping's address as the remote address.
5. Ensure activation completes before the first call into the DLL's flag-check
   routine. The FIRST invocation must observe the mutation; do not silently miss
   an initial call and still pass the final test.
6. Run the same read/filter/checksum workload and existing-hook exactly-once
   checks. No caller-side re-registration is needed after loading the DLL.

For external debugging, use the DLL-load debug event to resolve and arm the
pending breakpoint before resuming the relevant execution. Route unrelated DLL
loads normally and match the intended module identity, not just any load event.
The fixture does not execute its probed function from DllMain.

For the agent backends, provide an explicit safe module-load discovery and
activation path. Loader notifications may trigger bookkeeping, but arbitrary
hook installation, thread suspension, loading other DLLs, or logging that takes
uncontrolled locks must not be performed under the loader lock. A cooperative
load-completion rendezvous is acceptable for this controlled first fixture if
clearly documented; the library still resolves the pre-registered textual probe
and installs it. It must not require the user to supply the new live address or
call `probe_add` again. Do not present that rendezvous as general race-free
instrumentation of arbitrary DLL initializers or arbitrary concurrent callers.

Required correctness evidence, in addition to the existing matrix:

- The DLL was absent when registration occurred; pending status and zero hits
  are observable. A missing DLL that never loads remains pending without an
  invented address or unexpected callback.
- Unrelated DLL loads do not activate the probe.
- Loading the intended DLL produces exactly one active installation for the
  registered site, with recorded image base, RVA and resolved address.
- The first and all subsequent expected calls are intercepted, in both memory
  and register mutation variants, across inline/VEH/external backends.
- Clean and already-hooked read-wrapper variants still pass. The old layer must
  remain intact while the deferred flag probe becomes active.
- Setup/load/activation time is recorded separately from steady-state timings;
  no module scanning or symbol resolution is added to the per-hit callback.

Track module lifetime in the design: unloading invalidates resolved addresses,
and a new mapping needs a fresh resolution. Reload/unload support should be
implemented and tested or explicitly rejected as unsupported in this first
version; never leave an old address advertised as active. Pending cancellation
and same-named modules at different paths also need defined behavior, with any
unsupported combinations stated explicitly.

## What is currently in the archive

| Area | First-pass implementation | Important limit |
|---|---|---|
| Shared C policy | `src/callback.c`, linked into controller and DLL | Fixture-specific configuration/signature |
| Context/helpers | `include/probe.h` | x64 integer registers; PC/SP/flags observational |
| External software breakpoint | `src/debugger.cpp`, mode `debug-sw` | Single-thread restore/step/re-arm |
| External hardware breakpoint | Same file, mode `debug-hw` | Fixture main thread; two hardware slots |
| Local software breakpoint | `src/agent.cpp`, mode `veh-sw` | VEH; single-thread restore/step/re-arm |
| Inline mid-hook | Same file, mode `inline` | SafetyHook v0.7.0; relocation unverified on Windows |
| Entry inspection | `include/detect.hpp` | Common jump patterns; no general hook ownership detection |
| Workload | `src/target.cpp`, `src/sites.asm` | Stable NOP regions, not a comprehensive relocation test |
| Logging | Fixed first-8192-record buffer | No live transport/streaming ring; overflow counted |
| Runner | `scripts/bench.py` | Correctness oracle and timing matrix |

The fixture cooperatively loads the agent DLL. Arbitrary PID attach/injection, generic registration, PDB resolution, module+offset lookup, deferred breakpoints, per-site mixed backends, concurrent callbacks, and stack helpers are NOT complete. The external controller resolves known fixture exports with ASLR accounted for.

## Validation already performed

On Linux, the shared C callback tests passed with GCC warnings treated as errors and AddressSanitizer/UndefinedBehaviorSanitizer. Leak detection was disabled because the host's tracing environment prevents LeakSanitizer from running. Four Python oracle tests and Python syntax checks passed.

No Windows build, Windows execution or performance measurement has been performed. Treat the Windows source as unverified. `VALIDATION.md` records that distinction. Passing portable policy tests does not prove exception handling, instruction relocation, DLL lifetime or register preservation.

## Windows agent execution plan

### 1. Establish a native build

Record Windows build, CPU model/architecture, whether execution is native or emulated, compiler/tool versions and dependency versions. Use an x64 Visual Studio 2022 Developer command prompt with C++ and MASM installed, Git, CMake >=3.28 and Python >=3.10.

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python -m unittest discover -s tests -p "test_*.py" -v
```

CMake fetches SafetyHook v0.7.0 and its dependencies. Fix build failures and retain the actual build output. Pay attention to exports, assembly labels, DLL runtime linkage and the SafetyHook context adapter.

### 2. Implement new-instance discovery and deferred loading, then pass correctness

```bat
python scripts\bench.py --bin build\Release --correctness-only
```

The archive runner gates memory/register mutation, implemented probe modes, and clean/already-hooked variants. Extend it to enforce new-instance discovery and deferred activation as specified above; the old runner alone does not test them. Fix failures without weakening the expected counts, record digest or old-hook preservation checks. Unsupported cases must be reported explicitly rather than silently excluded from results.

Also run the disabled path:

```bat
build\Release\probe_target.exe disabled reads 20 mutate memory 0 prehook
```

Expect zero enabled iterations, zero successful reads and zero existing-hook calls. Useful individual runs:

```bat
build\Release\probe_target.exe inline reads 1000 mutate memory 32 prehook
build\Release\probe_debugger.exe debug-sw reads 1000 mutate memory 32 prehook
build\Release\probe_debugger.exe debug-hw reads 1000 mutate register 32 prehook
build\Release\probe_target.exe veh-sw reads 1000 mutate register 32 prehook
```

Audit breakpoint ownership, forwarding of unrelated exceptions, instruction-pointer adjustment, trap/resume flags, re-arming, hardware-register ownership and cleanup on failure. Explicitly test register/flags preservation beyond the current flag-result checks before claiming broad state equivalence. The first pass does not prove SIMD/AVX preservation or multithread safety.

### 3. Run controlled performance comparisons

```bat
python scripts\bench.py --bin build\Release --out results
```

After that passes, lengthen the runs:

```bat
python scripts\bench.py --bin build\Release --iterations 100000 --reads-iterations 10000 --repeats 7 --out longer-results
```

Start small because external breakpoint modes may be slow. Diagnose timeouts rather than treating them as correctness passes. Report incomplete runs as incomplete.

| Comparison | Purpose |
|---|---|
| Baseline vs inline vs VEH INT3 vs external INT3 vs external hardware | Measure each implemented mechanism |
| `micro` + noop | One probe crossing per iteration; minimal policy work |
| `micro` + filter/mutate/log | Incremental cost of filtering, memory helpers, state changes and buffered records |
| `reads`, clean vs prehook | Real syscall workload, two probes per iteration, and preservation/cost of existing hook |

Keep startup, resolution, installation and teardown outside the target's timed loop. Exclude warmup from timings but include it in validation. Use identical downstream work in the baseline; its flag is supplied as enabled so it performs the same reads. Randomize mode order across repeated runs; retain all samples. No console output in the timed region. Keep log-drop counts explicit.

For the one-probe microbenchmark:

`added ns per hit = (instrumented elapsed ns - matching baseline elapsed ns) / measured iterations`

For the read workload, report ns per ITERATION: each iteration has two probes and one syscall. Do not label that result as the cost of a single breakpoint. Software breakpoint measurements include their re-arm single-step events. CPU-time scopes differ in the current runner: target CPU covers its measured region, controller CPU covers its lifetime. Do not combine them as though they cover the same interval.

Report median/min/max, baseline-subtracted elapsed time and slowdown with environment details. Do not invent a universal breakpoint latency or promise that native conditions eliminate debugger event overhead. Distinguish native x64 results from x64 emulation on an ARM machine.

## Completion and return package

Return:

- Fixed source with a concise change list and exact build commands.
- Correctness results, including exclusion of existing process instances, pending-to-active transitions, first-call interception, all prehook variants and any unsupported cases.
- Raw JSONL and summary CSV/JSON from actual Windows measurements.
- A short comparison explaining which backends are practical for hot probes and what was actually measured.
- Remaining limits and a prioritized next step toward the general library.

First milestone: a verified controlled Windows prototype INCLUDING new-process-by-name attachment that excludes existing instances, deferred module+RVA registration, and load-triggered activation. Once that is solid, broaden the session/probe interface, symbol resolution and automated agent lifecycle, then address threading and broader architecture/state support. Preserve one shared C callback source throughout.
