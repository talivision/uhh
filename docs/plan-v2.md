# Plan v2: gated config DLL, mixed backends, multithreaded reads

Agreed 4 November 2026. Supersedes the single-mode fixture as the main example;
`probe_target` stays as a regression fixture.

## Scenario (`probe_app`)

1. Starts, launches the selected/decoy helper processes, optionally installs the
   pre-existing hook on `ReadThunk`, prints `{"kind":"waiting"}` and waits for a
   keystroke (stdin byte; console raw mode when interactive).
2. On the keystroke it loads `configparse.dll` (never a static dependency) and
   calls `ParseConfig`. The parsed `reads_enabled` value passes through the
   mid-function site `ParsedFlagSite`, right after parsing, before it is stored.
3. The shipped config says `reads_enabled=0`. Unless a probe flips the value at
   `ParsedFlagSite`, the read workload does not run.
4. If enabled, W worker threads each issue R reads through `ReadThunk`
   (NtReadVirtualMemory ABI), rotating selected/in-range, selected/out-of-range,
   decoy/in-range, selected/in-range-other-offset. Every result is verified.

## Probe targets

- `module+0xRVA` always works without symbols. Build tooling derives fixture RVAs
  from the linker map; runtime never asks the target for live addresses.
- `module!symbol[+off]` via dbghelp, honouring `_NT_SYMBOL_PATH` syntax
  (`srv*cache*url`) with a `--symbol-path` override. Server downloads need
  symsrv.dll from Debugging Tools for Windows.
- Both stay pending until the module loads; resolve against the remote image base.

## Backends, mixed per probe

- External: hardware breakpoint (per thread: set on all threads, including new
  ones), INT3 with `.bpsync`-style step-over (suspend other threads during the
  step; reference: GDB windows-nat). Displaced stepping later.
- In-process: inline (SafetyHook mid-hook), hardware breakpoint via VEH. No
  in-process INT3 when a debugger is attached (every exception round-trips).
- Intended mix for this scenario: software breakpoint at `ParsedFlagSite`
  (fires once; flips the parsed value 0 -> 1), inline at `ReadSite` (millions of
  hits across threads).
- Existing-hook checks stay mandatory for every backend and mix.

## Pre-existing hook policy (finalized 4 Nov 2026)

Supersedes the README's plain "safe-fail". Detection stays two-layer: classify +
compare_to_disk (any diff from the clean image = modified). On an inline site that
is already hooked:
- DEFAULT: fail fast and clean up (remove our hooks; never leave patches behind so
  re-runs don't see our own as "pre-existing"). Print report_prehooked.
- Per-probe override flags on probe_add:
  - PROBE_ALLOW_PREHOOKED: proceed with inline (relocate/chain the foreign jump).
  - PROBE_FALLBACK_BREAKPOINT: use a breakpoint (HW, no code modified) instead of
    failing. (HW breakpoint = universal no-clobber fallback, limited to 4 slots.)

report_prehooked is a DISCOVERY tool, not a solver:
- "detected pre-existing hook at <site>" + Zydis disassembly (offset + mnemonic).
- For a jmp/call, show the resolved target (addr, and module!off if mappable -
  often names who hooked it). We do NOT follow the detour, so whether it returns
  into the original call or returns to the caller is UNANALYZED and stated so.
- Hedged hint only: "maybe rehook at +0xN?" (next clean boundary past the detour;
  not verified reachable). Never an automated decision.

## Two demo probes + handle resolution

- Demo A: software breakpoint on `ParsedFlagSite`, overrides the parsed flag 0->1.
- Demo B: inline hook on the NtReadVirtualMemory path, logs every call's args.
- NtOpenProcess hook builds a handle->PID map at open time (PID is in CLIENT_ID;
  opens are rare, so the inline store is cheap). NtClose noted; entries carry a
  timestamp so a logged read resolves to the identity the handle had then.
- Reads log only the raw handle (cheap). The reader resolves handle->PID from the
  map and PID->image name once (QueryFullProcessImageName), cached. Name lookup is
  a syscall and must never run in callback context.
- Join is reader-side and TIMESTAMPED: every record carries a timestamp; the reader
  replays open/close in ts order keeping handle->pid INTERVALS, so a read resolves
  to the identity the handle had at the read's ts (survives close+reuse). This is
  the same per-record timestamp the per-thread log streams merge on.
- FIXTURE REQUIREMENT: probe_app must obtain its read handle via OpenProcess(pid),
  not the CreateProcess PROCESS_INFORMATION handle, or NtOpenProcess never fires
  and the map is empty. The read filter's selected_handle is then that OpenProcess
  handle, which the map resolves to the selected pid.

## Logging

- `PROBE_LOG(ctx, "fmt", args...)` written inline in callbacks. The call site
  stores a format-string identity + raw 8-byte args (`%s` bytes copied, bounded);
  the controller formats later (WPP/Quill/defmt pattern). Text or JSON output.
- Per-thread single-producer queues (Quill design), allocated from a pool created
  in advance: no allocation or locks in callback context.
- Full-queue policy selectable: lossless (block, optional timeout then count) or
  count-and-drop.

## Decisions (4 Nov 2026)

- `--wait-name` uses a BUSY WAIT (poll the process list), not an event/WMI
  subscription. Arm discovery before announcing ready; eligibility by creation
  time relative to the cutoff; exclude pre-existing instances; PID+creation-time
  identity against reuse. Real attach via DebugActiveProcess (today only launch).
- The demo/scenario code moves OUT of src/ into an examples/ tree; src/ keeps the
  reusable library + backends. Done as part of the session-API consolidation.
- The scenario is a run-on-demand script (check_scenario.py), NOT a CTest/CI gate.
  CTest keeps only the fast deterministic policy unit tests.
- Checkpoint before new layers (logging queues, more backends): record Windows
  validation, refactor probe_session into reusable session/probe machinery, and
  build real attach. (Aligned with Codex review.)

## Win32 / WoW64 support (required, 4 Nov 2026)

Must work on BOTH 64-bit and 32-bit. Current blockers, all x64-only:
- CMakeLists.txt FATAL_ERROR rejects non-x64; needs an x86 (`-A Win32`) config.
- probe.h `probe_regs` is rax..r15 only; needs an arch-specific register layout
  (x86: eax..edi, no r8-r15). Fold into the session-API refactor so the ABI and
  the from_context/to_context adapters are arch-parameterized from the start.
- MASM fixtures (sites.asm, app_sites.asm, flag.asm) are 64-bit; need x86 variants
  (ml.exe, __cdecl/__stdcall decoration) selected by target arch.
- Backends: INT3 (1 byte) and DR hardware slots work on both; SafetyHook has an
  x86 mid-hook (Context32). External debugger needs the x86 CONTEXT.

Deliverable: build and pass the example as a 32-bit binary. Two cases to keep
distinct: (a) 32-bit-native (x86 controller + x86 target) first; (b) true WoW64
(x64 controller debugging a 32-bit target via Wow64Get/SetThreadContext and the
WOW64 debug events) second. Do not conflate a Windows CONTEXT with a full CPU
image across the boundary.

## Benchmarking baselines

- Compare our backends against FRIDA doing the same instrumentation (Interceptor
  for the inline read hook; its equivalent for the config site), same workload,
  same machine. Frida's Interceptor is the industry-standard inline hook, so it is
  the reference for per-hit overhead. (Install frida on the VM for the perf bot.)
- Also keep the internal baseline (uninstrumented) and cross-backend comparison.

## Build-out requirements (4 Nov 2026)

- api-sketch.md is GOSPEL. Implement to it exactly.
- Test the exact gated use case on BOTH x86 and x64 (verified, not assumed).
- The contrived scenario must ALSO be demonstrated with a `watch_new`-style attach:
  attach to a newly-launched instance by name, then modify (flag flip) and log the
  reads - not only the launch-under-debugger path.
- Fix the catalogued bugs (review-findings.md) and make the hot path performant.
- INLINE-OVER-EXISTING-HOOK: test cases where, after detecting a pre-existing
  hook, we install an INLINE hook (no breakpoint fallback) that chains through
  the original trampoline and both run correctly (PROBE_ALLOW_PREHOOKED). Prove
  the inline-on-inline coexistence, not just detect-and-fail or HW fallback.
- MIX MATRIX: test the gated scenario across ALL permutations of backend per probe
  (config-flag site and read site x {software breakpoint, inline hook}, HW where
  applicable), proving each combination works and gives correct results. This is
  the mix-and-match validation; both backends must interoperate in one session.
- Codex does bounded implementation chunks (it cannot build Windows; the VM does);
  Codex reviews at the end against this gospel API. Watch Codex token usage.
- Ship: push to GitHub as `talivision/uhh` (usermode-hook-helper, UHH), PUBLIC repo, short-and-sweet
  README, and several VERIFIED examples of the tool working. Confirm before the push.

## No backward compatibility (4 Nov 2026)

Nothing is public yet, so the final tree is ONE internally-consistent codebase
on the locked probe_api - no compat shims, no parallel precursor. Before the
public push, a consolidation pass: drop the PROBE_PUBLIC_API dual include and
the precursor src/session.cpp; fold its unique value (on-disk hook detection +
Zydis disasm surfacing) into the probe_api backend; remove or port any first-
pass code (probe_target/probe_debugger/old bench) that does not serve as a
verified example on the new API. Keep shims only while actively building.

## Order

1. `probe_app` + `configparse.dll` + RVA tooling + check script.
2. Controller session API: per-probe backend, pending module probes, symbols.
3. Logging queues + `PROBE_LOG`.
4. Thread-safe breakpoints (bpsync INT3, all-thread hardware breakpoints).
5. Existing-hook matrix over mixes; multithreaded correctness and benchmarks.
