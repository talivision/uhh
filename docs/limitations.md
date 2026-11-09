# Limitations

What UHH does not do, or does differently per backend. Items name their source in
[ROADMAP.md](ROADMAP.md) as *section item* (e.g. "Hunter B10" = item B10 under "Hunter B
findings"). Status: 📄 documented behaviour, ⬜ open, ⏸ deferred by the owner, ✗ owner decision
(will not change).

Contents: [per-backend table](#per-backend-table) · [scope](#scope) ·
[resource limits](#resource-limits) · [backend differences](#backend-differences-in-callbacks) ·
[formatting target strings](#formatting-target-strings) · [coverage and timing](#coverage-and-timing) ·
[call_func and call_original](#call_func-and-call_original) · [hardware](#hardware-backend) ·
[software breakpoint](#software-breakpoint-backend) · [inline](#inline-backend) ·
[x86 / WOW64](#x86--wow64) · [logs and accounting](#logs-and-accounting) ·
[detach and close](#detach-and-close) · [CET](#cet-shadow-stacks) ·
[visibility](#visibility-to-the-target-anti-debug)

## Per-backend table

One callback source runs on every backend and both architectures; the data-plane functions
return the same values everywhere. What differs:

| | `PROBE_BREAKPOINT` | `PROBE_HW` | `PROBE_INLINE` |
|---|---|---|---|
| Mechanism | INT3 written by the controller (a debugger); the probed instruction runs from a per-site trampoline (displaced stepping) | execute debug register (DR0-DR3), or a data watchpoint | SafetyHook mid-function hook (a jump of >= 5 bytes) installed by `probe_api_agent.dll`, injected into the target |
| Callback runs | in the controller, on its debugger thread, one hit at a time; the whole target is stopped meanwhile | same as breakpoint | inside the target, on the thread that hit the probe, concurrently with other threads' callbacks |
| Added cost per hit, x64 / x86 (1 thread, test VM, `bench/BENCHMARKS.md`) | ~78 us / ~124 us | ~92 us / ~138 us | ~0.065 us / ~0.134 us; `send_log` adds ~0.18 / ~0.13 us |
| 1 kHz frame loop, x64 (Blog B7, 2026-11-05) | frame time p50 ~300 us, p99 ~660 us; a few frames over budget | p50 ~220 us, p99 ~520 us; a few frames over budget | p50 1 us, p99 10 us; no frame missed |
| How many | unlimited (65536 armed at once in a session that also has inline probes) | 4 in total: execute probes and watchpoints | 128 per session |
| Sites | any instruction start (a site inside an instruction is refused unless `PROBE_ALLOW_UNSAFE_SITE` is set, [scope](#scope)); a site that already holds a foreign INT3 is refused | any instruction start | a site check refuses sites where code could arrive inside the overwritten bytes ([inline](#inline-backend)) |
| Live from, launch | the target's first instruction | the target's first instruction | the loader breakpoint: static imports mapped, before any DLL initialiser or TLS callback runs |
| Live from, attach | each probe's `probe: active` line | same | same (once the agent confirms the hook) |
| `probe_watch` (data) | - | yes | - |
| `PROBE_ONCE` | yes | yes | refused |
| Other threads | every hit stops the whole process; UHH's yield rounds let threads that hit nothing run between dense hits (Hunter A5) | same as breakpoint | unaffected |
| Changes in the target | the INT3 byte; executable trampoline blocks | the threads' DR0-3/DR7; executable trampoline blocks; once a hw probe is armed or released while the program runs, library INT3s at `ntdll!RtlUserThreadStart`, `NtContinue` and `NtContinueEx` | the hook jump (written through the target's own `NtProtectVirtualMemory`); the agent DLL and its service thread (stays loaded after a detach); the callback uses the thread's stack (several KiB) and, for its own allocations, the target's heap |
| Controller killed (attach) | the target keeps the INT3s and dies at its next hit (`0x80000003`) -- unless the session has an inline probe | same, `0x80000004` | the agent's controller-death guard removes its hooks, INT3s and debug registers; the target runs on |
| CET shadow stacks (x64) | works; a CALL/RET at a probe site is stepped in place | works | works (the agent is linked /CETCOMPAT) |
| `call_func` | the debugger runs the call on the stopped thread: ~200 / ~290 us beyond the hit (x64 / x86); a callee exception abandons it; refused on a nearly exhausted stack | same as breakpoint | ~2.3 us including the hit; a temporary reference holds the callee module |
| `call_original` | runs the original in place on the hit's stack; needs a free debug register for the call | same; a hw execute probe lends its own register | a real call in a new frame with a copy of the stack arguments (up to 256 bytes) and the argument registers |
| x86 (WOW64) | ~1.6x the x64 cost per hit | ~1.5x the x64 cost per hit | the x87 state is saved per hit; stack snapshots are a verified return-address scan |

x64 against x86, on every backend: R8..R15 read 0 on x86; `get_func_arg` is a register or stack
slot on x64 but always a 4-byte stack slot on x86; `return_from`'s `nargs` matters on x86 only;
Windows enforces no CET shadow stack for WOW64 processes. Details in [x86 / WOW64](#x86--wow64).

## Scope

- **One process per session; children are not followed** (⏸ Production readiness, "Follow
  child processes"; design in [child-processes.md](child-processes.md)). A launched target
  is debugged alone (`DEBUG_ONLY_THIS_PROCESS`); a child it starts runs unprobed (e.g.
  `cmd /c tasklist` shows no opens: Real-app findings).
  *Workaround:* launch the child program directly, or attach to it with its own session
  (`probe_attach`, or `probe_attach_new` for the next new process of that name).
- **Windows user mode, x64 and x86 only.** ARM64 is rejected at configure time.
- **Controller and target must have the same bitness.** *Workaround:* the x86 build for
  32-bit targets, the x64 build for 64-bit ones.
- **No return probes** (`PROBE_AT_RETURN` is refused; Codex workaround audit C13).
  *Workaround:* read the return address at entry and `probe_add_address` it from the
  callback (see [api.md](api.md#control-from-a-callback)).
- **A site inside an instruction is refused on every backend** where UHH can decode the
  function (`.pdata`, PDB, or the named symbol): `site is inside an instruction ... nearest
  instruction boundaries A, B`. Where it cannot decode the code (no function extent and no
  symbol before the site, code reached only by indirect jumps, overlapping instructions)
  the site is taken as given: a breakpoint there corrupts the instruction, an inline hook
  crashes the target, hw never fires. *Workaround:* probe instruction starts (map, PDB,
  disassembly), or use `PROBE_ALLOW_UNSAFE_SITE` for known overlapping/obfuscated code (warning on stderr and in the per-probe log, every execute backend; never data watchpoints). Hardware fallback alone does not override this refusal; name the function (`module!Func+0xOFF`) so the offset can be checked.
- **No accessor for XMM/x87 registers, the instruction pointer or flags** (📄 Calling-convention
  CC7). Float/double arguments in XMM cannot be read; a float result cannot be set.
  *Workaround:* pass float results through with `call_original` + `return_from`.
- **Sandboxed processes that admit only Microsoft-signed DLLs (Code Integrity Guard: every
  Chromium/Edge renderer, most of their utility processes) cannot load the agent** (Real large
  apps RB2). An inline session fails cleanly (`LoadLibraryW failed for probe_api_agent.dll (the
  target admits only Microsoft-signed DLLs ...)`, target untouched); breakpoint/hw-only sessions
  work as anywhere else (they inject nothing).
- **The debugger is not hidden** (✗ Codex workaround audit C6). See
  [visibility](#visibility-to-the-target-anti-debug).

## Resource limits

| Limit | Value | Workaround |
|---|---|---|
| Hardware probes | 4 in total (execute + watch), one debug register each (New-app NA6, Frida F6) | breakpoint/inline for the rest; filter so one site suffices |
| `call_original` on hw / breakpoint | needs one of the 4 registers free for the call, unless the hit is itself a hw execute probe (call_original CO6) | at most 3 hw probes when other probes call `call_original`; `gated_config` puts NtClose on breakpoint when opens are hw |
| Inline probes | 128 per session (the 129th is refused) | breakpoint/hw for more sites |
| Software breakpoints in a session with inline probes | 65536 armed at once | - |
| Config block | 4 GB | - |
| Log message | 1023 bytes, then `...[truncated]` | log several records |
| Stack snapshot | 32 frames | - |
| `call_func` | 0..8 integer arguments | - |
| `call_original` | 0..16 arguments; inline copies 256 bytes of stack arguments (New-app NA1, Calling-convention CC4) | wrap functions with larger stack arguments on breakpoint/hw |

## Backend differences in callbacks

What differs follows from where the callback runs: breakpoint/hw in the controller, inline
inside the target (📄 Portability D1-D6).

- **D1: direct Win32 calls act on the process the callback runs in.**
  `GetCurrentProcessId()` in a breakpoint/hw callback is the controller's pid.
  *Workaround:* `call_func(c, "kernel32.dll!GetCurrentProcessId", &v, 0)` (or
  `GetCurrentThreadId`); target memory only through `get_mem`/`set_mem`.
- **D2: concurrency.** Breakpoint/hw callbacks never overlap; inline callbacks of
  different target threads run at the same time. `thread_local` is per target thread
  inline, but one controller thread for all target threads on breakpoint/hw.
  *Workaround:* make shared state atomic or locked; key per-thread state by the target tid.
- **D3: a faulting or throwing callback** is abandoned on every backend (hit counted,
  register changes discarded, `set_mem` writes kept). Inline, the exception is raised in the
  target, so the program's vectored handlers see the first chance; breakpoint/hw never.
  *Workaround:* check pointers with `get_mem` instead of dereferencing; do not throw out of
  callbacks.
- **D4: a `call_func` callee that raises an exception, even one it handles itself,** is
  abandoned on breakpoint/hw (returns 0, the target never sees it); inline the exception is
  dispatched in the target (returns 1 if the callee handled it).
  *Workaround:* `call_func` only callees that do not raise.
- **D5: `PROBE_ONCE` is breakpoint/hw only** (refused inline).
  *Workaround:* inline, keep an atomic flag in the callback and return early.
- **D6: a probe added from a callback** must name a callback exported by the calling
  callback's module, on every backend: an inline request is resolved by export name in that
  module only (the target is untrusted), and breakpoint/hw refuse the same requests (a static
  function or another module's export: 0).
  *Workaround:* keep a callback and the callbacks it adds in one module, all exported.
- **State shared between probes of different backends** exists twice unless marked
  `UHH_SHARED` (Gaps P2; Codex workaround audit C7). *Workaround:* `UHH_SHARED` (see
  [api.md](api.md#shared-state-uhh_shared)), or one backend for all probes that share state.

## Formatting target strings

📄 Hunter B10. `send_log(c, "%s", ptr)` with a **target** pointer prints the string inline,
but on breakpoint/hw the callback runs in the controller, where the pointer is not valid:
the record becomes `[unformattable] <format>` (or, on x86, the controller's own bytes when
the same address happens to be mapped there). A pointer valid in both processes (system DLL
data) prints on all backends.
*Workaround:* `get_mem` the string into a local buffer, then print the buffer (as
`examples/trace/trace_callback.cpp` does).

## Coverage and timing

- **On launch, inline probes go live at the loader breakpoint** (Hunter A6): the target's
  main thread loads the agent there, after the static imports are mapped and before any DLL
  initialiser or TLS callback runs, so DllMain and TLS-callback calls are seen. The loader's
  own work before that point (mapping the static imports, its registry queries such as IFEO)
  is seen only by breakpoint/hw probes, which are armed from the first instruction. A map
  built by an inline probe does not know handles opened before then (`key=?`, `pid=0`).
  If that early load cannot run, the agent is loaded by a thread of its own and the main
  thread is held at the entry point until the hooks are in.
  *Workaround:* breakpoint/hw for probes that must see the loader's own activity.
- **Attach counts from each probe's `probe: active` line.** The target keeps running while
  probes arm; calls before that are not seen. *Workaround:* gate the target, or wait for
  the `active` lines before driving it (as `examples/attach` does).
- **`probe_attach_new` polls about every millisecond**, so the target runs a few
  milliseconds before the attach, and any new process with that image name matches (on a
  shared machine, another program's instance can be attached instead).
  *Workaround:* for start-up code, launch the target with `probe_launch`.
- **Breakpoint/hw cost a debug event per hit** (table above). Every event stops the whole
  process; when events are dense, UHH sends the hot threads through short yield rounds so
  threads that hit nothing still run (Hunter A5: before, a thread that hit nothing could wait
  seconds). Results stay exact; wall-clock time does not. A 1 kHz frame loop shows it as frame
  time (Blog B7, table above).
  *Workaround:* inline for hot paths; breakpoint/hw for rare sites (a flag flip).
- **A probe sees every caller of the function, and re-entry counts too** (Blog B6). Entry
  counts are not API-call counts: `bcrypt!BCryptGenRandom` re-enters itself (2 hits per
  call); `ole32!CoCreateInstance` showed 25 hits for 24 target calls (other callers in the
  process). A naive "probe every return" recipe on hw therefore asks for more debug registers
  than the 4 there are: the 5th is refused (`too many hardware probes (max 4 DR slots)`).
  *Workaround:* filter in the callback (by argument, return address or config); recognise
  re-entry by the stack pointer (an outer call's SP is above the inner one's), as
  `examples/blogs` does.
- **What a program reads is not always in that program** (Real-app findings). `wmic`'s
  enumeration runs in `WmiPrvSE.exe`; a 32-bit program reading a 64-bit process does not go
  through 32-bit `ntdll!NtReadVirtualMemory` (it uses `NtWow64ReadVirtualMemory64` or fails).
  *Workaround:* attach to the process that does the work; probe the WOW64 variant too.

## call_func and call_original

- **`call_func` on breakpoint/hw is a debugger-driven call** (✗ Controller static review,
  "call_func under contention"). Other threads' hits wait during the call (callbacks never
  overlap, so a callback may hold its own lock across `call_func`): code probes are rewound
  and hit again afterwards, a data watch's thread is held right after its access. If a
  waiting thread holds a lock the callee needs, the call times out after 5 s and the callee
  is abandoned mid-wait (inline: both run). A first-chance exception inside the callee also
  abandons it. A hardware hit on a thread that is at that moment single-stepping over a
  breakpoint probe is handled at once. Owner decision: no further hardening.
  *Workaround:* call only non-blocking, non-throwing callees; cache results; prefer
  `call_original` for the probed function.
- **`call_func` on breakpoint/hw on a nearly exhausted stack** (XH3). The callee's frame
  goes 512+ bytes below the hit's SP; where that stack is not committed yet the thread first
  grows it itself (as the callee would inline). Within the last pages of the thread's stack
  reservation (DeallocationStack + max(guarantee, 1 page) + 4 pages), or on a stack the TEB
  does not describe, it is not grown: `call_func` returns 0 and one stderr line per probe says
  why (`call_func refused: the thread's stack is nearly exhausted ...`).
- **Inline `call_original` is a real call from the agent** (📄 Transparency findings). The
  original sees the agent's return address (`_ReturnAddress()`), a new frame for its stack
  arguments, and only the hit's argument registers (x64 RCX RDX R8 R9 XMM0-5; x86 EAX ECX
  EDX XMM0-5 + stack arguments). A function with a custom register convention (hand-written
  assembly, x86 LTCG internals taking ESI/EDI) gets garbage in the other registers; a
  `set_reg` of a nonvolatile register before `call_original` reaches the original on
  breakpoint/hw only.
  *Workaround:* breakpoint/hw for such functions (they run the original in place with the
  full context).
- **An exception the original handles internally is invisible** to the callback on every
  backend: `call_original` returns normally.
- **x86 `return_from` without `call_original` trusts `nargs`** (📄 Calling-convention CC6). A
  wrong count leaves the caller's ESP off by the difference.
  *Workaround:* follow the per-convention rule in [api.md](api.md#callback-functions); wrap
  with `call_original` when unsure (the popped count is then measured).
- **Float results cannot be set** (📄 Calling-convention CC2). *Workaround:* pass them
  through with `call_original`.

## Hardware backend

- **The target's own debug registers and trap flag are preserved.** UHH clears only
  its own DR6 status bits, forwards the target's debug exceptions, and restores the
  target's TF after its own stepping, including fault/restart paths.
  **Slot contention** (Hunter A7). UHH never takes a slot the target uses:
  a probe moves to a slot no thread of the target uses, and the target's own #DB goes to the
  target. With no free slot the probe yields on that thread (`probe: warning: <loc>: the
  program uses DRn itself on thread N and no debug register is free: the probe yields there`)
  and its hits there are not seen. A DR the program sets on a running thread is noticed at
  that thread's next debug event.
  *Workaround:* breakpoint or inline for targets that use all debug registers themselves.
- **Open corner** (⬜ Detours D4 residual): in a mixed session, a hw probe armed while another
  thread's software-breakpoint event is still queued is not re-asserted on that thread at that
  event (a queued hw event is), so that thread can miss the probe until its next re-arm.
  *Workaround:* arm hw probes before the target's threads are busy (before launch, or early
  in the run), or use breakpoint.

## Software breakpoint backend

- **The faulting-instruction restart corner case** (📄 Codex library review "TF"; x64 and
  x86). When the probed instruction faults during its step and the program's handler continues
  **elsewhere**, and that thread's very next debug event is a **new** call reaching the same
  site, UHH takes it for the restart of the faulted instruction: no callback for that call.
  Only sites whose instruction faults and is handled by the program are affected.
  *Workaround:* probe the next instruction, or use hw/inline on such sites.
- **In-place steps hold the other threads briefly** (Evaluator round 3 #2). Instructions that
  cannot run out of line (segment-relative or 16-bit branches, accesses that must fault,
  CALL/RET under CET) run in place while every other target thread is suspended for that one
  instruction. A step not done within 2 s (the program suspended the stepping thread) is
  released with a warning, and a call through that site meanwhile may be missed.
- **A site that already holds a foreign INT3 is refused** (`pre-hooked INT3 sites are
  unsupported by this breakpoint backend`). *Workaround:* hw.

## Inline backend

- **Some sites are refused.** An inline hook overwrites at least 5 bytes; the site is refused
  (with the reason) when code could arrive inside them: a branch target, a function start,
  a call's return point, a switch-table target, live code after a ret/jmp (e.g. packed ntdll
  stubs at their `ret`), an unresolvable indirect jump in the function, the end of the
  section, a relocated rel8-only branch, another inline hook's bytes, or a software
  breakpoint probe (Core library; Detours C16, D5; Hunter B8). The stderr line suggests
  `inline-safe nearby` offsets when it finds some.
  *Workaround:* `PROBE_FALLBACK_HW`, breakpoint/hw on that site, a suggested nearby offset, or
  `PROBE_ALLOW_UNSAFE_SITE` if you are sure nothing reaches those bytes.
- **The callback runs on the target thread's stack** (📄 Transparency findings): several KiB
  per hit, so a thread close to its stack limit can overflow where it would not have, and
  committing deeper stack moves the TEB's StackLimit. A callback's own heap calls change heap
  state (including the TEB's per-thread LFH hint).
  *Workaround:* keep inline callbacks small; breakpoint/hw callbacks change neither.
- **Writing a hook is visible** (✗ Frida F7). Each install/remove changes page protection
  through the target's own `NtProtectVirtualMemory`, which an RWX watcher in the target
  sees. Breakpoint/hw write from the controller.
- **Under CET, a relocated `call` stays verbatim** (Agent review). Outside CET, a `call`
  inside the overwritten bytes is relocated so the callee returns into the hooked function
  (correct unwinding). Under shadow stacks it is copied as is, so an exception thrown by
  that callee and caught in the hooked function or above may not unwind.
  *Workaround:* do not place inline probes directly on a `call` in CET processes.
- **UHH's threads in the target run the program's thread callouts** (XH1-XH3): the agent's
  service thread and the controller's agent load / init / stop threads are ordinary threads,
  so the loader runs every module's `DllMain(DLL_THREAD_ATTACH/DETACH)` and TLS callbacks on
  them. A launch starts them before the entry point is released; an attach or detach starts
  them while the program runs.
- **Remaining agent limits** (Agent review, ⬜): a thread that dies inside a callback and
  whose id is reused before the next hit is not reported as interrupted; a `call_func` left
  by a non-unwinding `longjmp` keeps its thread marked as in a call.
- **The agent stays loaded after a detach** (Lifecycle), quiescent: hooks removed, logging
  stopped. A later attach to the same process reuses it.
  Reattach maps the retained agent file in the controller to preserve `UHH_SHARED`
  across backends. A different build is refused; restart the target to use it.
  A callback surviving detach retains its old config and channel storage until process exit.
- **x86 inline stack walks** are a verified return-address scan, not PDB-based; a frameless
  function reached by an indirect call can lose its immediate caller
  ([symbols.md](symbols.md#stacks-per-backend-send_log_stack)).

## x86 / WOW64

- R8..R15 read 0 and cannot be set; `set_reg` keeps the low 32 bits.
- `get_func_arg` is a 4-byte stack slot whatever the convention; register arguments
  (`__fastcall`, `__thiscall` `this`, `__vectorcall`) are read with `get_reg`. A C++ `this` is
  `get_reg(c, PROBE_REG_CX)` on both architectures.
- `return_from`'s `nargs` matters on x86 (stack slots the callee pops), not on x64.
- Windows does not enforce user shadow stacks (CET) for WOW64 processes.
- Breakpoint/hw hits cost about twice as much as on x64 (table above).
- Out of scope / not tested (📄 Hunter B12): probes inside WOW64 thunks, x86 `int 2e`
  system calls, large-address-aware x86 targets.
- A 32-bit program's reads of 64-bit processes bypass the 32-bit
  `ntdll!NtReadVirtualMemory` (Real-app findings).

## Logs and accounting

- **hits = logs_written + `log_dropped` + `callbacks_interrupted`** exactly for a callback that
  logs once per hit, also when the process dies at any instant: a callback's first log carries
  its hit, so a thread killed after publishing it is a delivered log, not interrupted. One
  inherent edge (Log delivery findings): a producer that claims a slot in the few instructions
  after the final drain at detach/close loses that record uncounted.
- **Per-thread order** is kept across backends, except that a record behind two unfinished
  ring slots of other threads at the same instant can be overtaken (Log delivery findings).
- **Inline callbacks killed by process exit** (ExitProcess/TerminateProcess) before their
  first log are reported as `callbacks_interrupted`; their logs never existed (Hunter A3). A
  stderr line names the probe and thread of each callback cut off while running.
- **A failed session-file write ends the file** (Codex review 4): the error reports the successfully
  appended record count; the failed batch and every later record count in `log_dropped`, and those
  that still reached stdout number `stdout_logs - logs_written`.
- **Session log files are not deleted.** They accumulate in `%TEMP%\uhh\logs`.
  *Workaround:* delete old `uhh-*.jsonl` files yourself.
- **A console is a slow log sink.** *Workaround:* redirect stdout to a file or pipe, or to
  `NUL` (the file still gets every record).

## Detach and close

- **Detach waits at most 15 s for running inline callbacks** (owner decision 2026-11-07). It
  keeps delivering their logs while any in-flight callback can still finish (thread alive,
  not suspended, still inside its callback), for up to 15 s after the hooks are removed, then
  completes. Not waited for at all: a callback whose thread is dead, suspended by the program,
  or left through a non-unwinding `longjmp`. Callbacks still running when the detach completes
  are counted: `running=` in the detach line / `probe_final`, and `in_flight=` for those that
  had not logged yet (hits = logs_written + log_dropped + in_flight). **Any log they write
  after that is lost.** Their config blocks stay allocated, so the program is unaffected.
  *Workaround:* keep inline callbacks short and lock-free.
- **Config blocks can stay in a detached target** (📄 Codex library review (2)): a config
  block is left allocated while a callback that may read it is still in flight, or the
  agent stop did not complete and hooks may admit new callbacks; stderr says so.
- **Controller death:** an **attached** target in a session with **inline probes** is
  protected by the agent's controller-death guard (Lifecycle L1): the agent restores
  breakpoints, clears UHH-owned debug registers, resumes held threads and removes inline hooks. A
  **breakpoint/hw-only** attach injects nothing (owner decision 2026-11-07), so it has no
  guard: the target is not killed, but it keeps our INT3s / debug registers and dies at its
  next hit (`0x80000003` / `0x80000004`), or runs on if it never reaches one. A **launched**
  target dies with its controller by design. Residual (Lifecycle): a breakpoint/hw `call_func`
  running when the controller dies leaves that thread redirected; after the controller is gone,
  any single-step on a thread without its own debug registers is taken as UHH's.
  Breakpoint/hw probes on modules newly loaded during an inline attach arm before the
  guard if necessary; controller death in that window can leave those traps installed.
  *Workaround:* end sessions with `probe_close` or Ctrl+C, not by killing the controller.
- **`probe_close` must not run while `probe_attach` is still running on another thread.**
  *Workaround:* signal completion of the attach first, as `uhh_trace --detach-after-ms` does.

## CET shadow stacks

Measured on real CET hardware (CI `windows-2025` runners: AMD EPYC, Windows Server 2025, user
shadow stacks enforced for /CETCOMPAT images; regress `cet-*`). The test VM's CPU has no CET.

| Path | Status |
|---|---|
| Every backend, x64 | gated_config and the transparency fixture (`call_func`, `call_original` + `return_from`) on /CETCOMPAT targets: exact, the target's shadow stack live |
| Strict mode (Exploit protection) | the same rows pass: no shadow-stack violation is left for the kernel to fix up |
| breakpoint/hw `call_func` | works: the callee is entered through a real `call` from a 3-byte stub; an abandoned callee's shadow frames are dropped |
| breakpoint/hw `call_original` without `return_from` | the original cannot run a second time (its shadow entry is gone): the hooked function returns the original's result, with one warning |
| `SetContextIpValidation` policy | does not refuse a debugger's thread-context changes (displaced stepping, freeze moves, call stub), strict mode included |
| `BlockNonCetBinaries` policy | breakpoint/hw work; inline works because `probe_api_agent.dll` (which holds the callbacks) is linked /CETCOMPAT |
| x86 | Windows enforces no shadow stack for WOW64; a WOW64 process does not even start under `BlockNonCetBinaries` |

## Visibility to the target (anti-debug)

✗ Owner decision: UHH does not mask the debugger (no PEB / debug-port hiding). Under
**every** backend the target is debugged (Codex workaround audit C6;
`examples/realworld/README.md`):

| Indicator | breakpoint | hw | inline |
|---|---|---|---|
| `IsDebuggerPresent`, remote check, debug port / object / flags, PEB `BeingDebugged` | set | set | set |
| Code bytes differ from disk at the probe | yes (`0xCC`) | no | yes (hook jump) |
| DR7 set | no | yes | no |
| A UHH DLL in the module list | no | no | `probe_api_agent.dll` |

- An in-memory `.text` checksum taken by the program after launch does not see the INT3 or
  the hook (both are in place before its baseline); a comparison with the file on disk does.
- A debugged process never runs its `SetUnhandledExceptionFilter` filter (Controller static
  review): crash reporters behave differently than without UHH.
- UHH's own allocations in the target (trampoline blocks, the agent) can take an address range
  the program has just released (📄 Hunter B11); a program that re-reserves a fixed address
  it freed could collide.

*Workaround:* none inside UHH; anti-debug targets take their "debugger" path under UHH.
