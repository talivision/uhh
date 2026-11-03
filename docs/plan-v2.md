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

## Two demo probes + handle resolution

- Demo A: software breakpoint on `ParsedFlagSite`, overrides the parsed flag 0->1.
- Demo B: inline hook on the NtReadVirtualMemory path, logs every call's args.
- NtOpenProcess hook builds a handle->PID map at open time (PID is in CLIENT_ID;
  opens are rare, so the inline store is cheap). NtClose noted; entries carry a
  timestamp so a logged read resolves to the identity the handle had then.
- Reads log only the raw handle (cheap). The reader resolves handle->PID from the
  map and PID->image name once (QueryFullProcessImageName), cached. Name lookup is
  a syscall and must never run in callback context.

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

## Order

1. `probe_app` + `configparse.dll` + RVA tooling + check script.
2. Controller session API: per-probe backend, pending module probes, symbols.
3. Logging queues + `PROBE_LOG`.
4. Thread-safe breakpoints (bpsync INT3, all-thread hardware breakpoints).
5. Existing-hook matrix over mixes; multithreaded correctness and benchmarks.
