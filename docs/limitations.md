# Limitations

What UHH does not do, or does differently per backend. Each item names its source in
[ROADMAP.md](ROADMAP.md) as *section item*: for example "Hunter B10" is item B10 under
"Hunter B findings", "Portability D1" is item D1 under "Portability findings". Status:
📄 documented behaviour, ⬜ open (may be fixed later), 🔧 in progress or being verified,
⏸ deferred by the owner, ✗ owner decision (will not change).

Contents: [scope](#scope) · [resource limits](#resource-limits) ·
[backend differences](#backend-differences-in-callbacks) ·
[formatting target strings](#formatting-target-strings) · [coverage and timing](#coverage-and-timing) ·
[call_func and call_original](#call_func-and-call_original) · [hardware](#hardware-backend) ·
[software breakpoint](#software-breakpoint-backend) · [inline](#inline-backend) ·
[x86 / WOW64](#x86--wow64) · [logs and accounting](#logs-and-accounting) ·
[detach and close](#detach-and-close) · [CET](#cet-shadow-stacks) ·
[visibility](#visibility-to-the-target-anti-debug)

## Scope

- **One process per session; children are not followed** (⏸ Production readiness, "Follow
  child processes"; design in [child-processes.md](child-processes.md)). A launched target
  is debugged alone (`DEBUG_ONLY_THIS_PROCESS`); a child it starts runs unprobed (e.g.
  `cmd /c tasklist` shows no opens: Real-app findings). Processes the target did not
  create are unaffected either way.
  *Workaround:* launch the child program directly, or attach to it with its own session
  (`probe_attach`, or `probe_attach_new` for the next new process of that name).
- **Windows user mode, x64 and x86 only.** ARM64 is rejected at configure time.
- **Controller and target must have the same bitness.** *Workaround:* use the x86 build for
  32-bit targets, the x64 build for 64-bit ones.
- **No return probes** (`PROBE_AT_RETURN` is refused; ✗ Codex workaround audit C13).
  *Workaround:* read the return address at entry and `probe_add_address` it from the
  callback (see [api.md](api.md#control-from-a-callback)).
- **No accessor for XMM/x87 registers, the instruction pointer or flags** (📄 Calling-convention
  CC7). Float/double arguments in XMM cannot be read; a float result cannot be set.
  *Workaround:* pass float results through with `call_original` + `return_from`.
- **Sandboxed processes that admit only Microsoft-signed DLLs (Code Integrity Guard: every
  Chromium/Edge renderer, most of their utility processes) cannot load the agent** (Real large
  apps RB2). An inline session attached to one fails cleanly (`LoadLibraryW failed for
  probe_api_agent.dll (the target admits only Microsoft-signed DLLs ...)`, detached, target
  untouched); breakpoint/hw-only sessions work as anywhere else (they inject nothing).
  *Workaround:* breakpoint or hw in such processes, and end the session with `probe_close`/Ctrl+C.
- **The debugger is not hidden** (✗ Codex workaround audit C6; Controller static review).
  See [visibility](#visibility-to-the-target-anti-debug).

## Resource limits

| Limit | Value | Source | Workaround |
|---|---|---|---|
| Hardware probes | 4 in total (execute + watch), one debug register each | New-app NA6, Frida F6 | use breakpoint/inline for the rest; filter so one site suffices |
| `call_original` on hw | needs one of the 4 registers free for the call, unless the hit is itself a hw execute probe (lends its own slot) | call_original CO6 | keep at most 3 hw probes when other probes call `call_original`; e.g. `gated_config` puts NtClose on breakpoint when opens are hw |
| Inline probes | 128 per session (the 129th is refused) | Production readiness | use breakpoint/hw for more sites |
| Software breakpoints with inline probes in the session | 65536 armed at once | Codex controller review (4) | none needed in practice |
| Config block | 4 GB | Codex controller review (5) | - |
| Log message | 1023 bytes, then `...[truncated]` | Log delivery findings | log several records |
| Stack snapshot | 32 frames | - | - |
| `call_func` | 0..8 integer arguments | probe_api.h | - |
| `call_original` | 0..16 arguments; inline copies 256 bytes of stack arguments | New-app NA1, Calling-convention CC4 | wrap functions with larger stack arguments on breakpoint/hw |

## Backend differences in callbacks

The data-plane functions return the same values on every backend. What differs follows
from where the callback runs: breakpoint/hw in the controller, inline inside the target
(📄 Portability D1-D6).

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
  *Workaround:* inline, keep a flag in the callback (atomically) and return early.
- **D6: a probe added from an inline callback** names its callback by export and is
  resolved in the module of the calling callback.
  *Workaround:* keep a callback and the callbacks it adds in one module, all exported.
- **State shared between probes of different backends** exists twice unless marked
  `UHH_SHARED` (⬜ Gaps P2 "mixed backends for state-sharing probes"; Codex workaround audit
  C7). *Workaround:* `UHH_SHARED` (see [api.md](api.md#shared-state-uhh_shared)), or one
  backend for all probes that share state.

## Formatting target strings

📄 Hunter B10. `send_log(c, "%s", ptr)` with a **target** pointer prints the string inline,
but on breakpoint/hw the callback runs in the controller, where the pointer is not valid:
the record becomes `[unformattable] <format>` (or, on x86, the controller's own bytes when
the same address happens to be mapped there). A pointer valid in both processes (system DLL
data) prints on all backends.
*Workaround:* `get_mem` the string into a local buffer, then print the buffer (as
`examples/trace/trace_callback.cpp` does).

## Coverage and timing

- **Inline probes go live at the entry point on launch** (📄 New-app NA5; ⬜ Hunter A6).
  Calls made before it (TLS callbacks at process attach, DllMain of static imports, the
  loader's own registry queries) are seen only by breakpoint/hw probes. A map built by an
  inline probe does not know handles opened before then (`key=?`, `pid=0`).
  *Workaround:* use breakpoint/hw for probes that must see loader-time activity.
- **Attach counts from each probe's `probe: active` line.** The target keeps running while
  probes arm; calls before that are not seen. *Workaround:* gate the target, or wait for
  the `active` lines before driving it (as `examples/attach` does).
- **`probe_attach_new` polls about every millisecond**, so the target runs a few
  milliseconds before the attach, and any new process with that image name matches (on a
  shared machine, another program's instance can be attached instead; Blog note).
  *Workaround:* for start-up code, launch the target with `probe_launch`.
- **Breakpoint/hw slow the target and can starve threads** (⬜ Hunter A5). Every debug event
  stops the whole process, so with several threads hitting a probe back to back, a thread
  that hits nothing runs only in the gaps. Results stay correct; wall-clock does not.
  Measured at 1 kHz (Blog B7, x64 VM): inline p50 1 us / p99 10 us per frame; hw p50
  ~220 us / p99 ~520 us; breakpoint p50 ~300 us / p99 ~660 us.
  *Workaround:* inline for hot paths; breakpoint/hw for rare sites (a flag flip).
- **A probe sees every caller of the function, and re-entry counts too** (⬜ Blog B6).
  `bcrypt!BCryptGenRandom` re-enters itself (2 hits per call); `CoCreateInstance` showed 25
  hits for 24 target calls. Entry counts are not API-call counts.
  *Workaround:* filter in the callback (by argument, return address or config).
- **What a program reads is not always in that program** (Real-app findings). `wmic`'s
  enumeration runs in `WmiPrvSE.exe`; a 32-bit program reading a 64-bit process does not go
  through 32-bit `ntdll!NtReadVirtualMemory` (it uses `NtWow64ReadVirtualMemory64` or fails).
  *Workaround:* attach to the process that does the work; probe the WOW64 variant too.

## call_func and call_original

- **`call_func` on breakpoint/hw is a debugger-driven call** (✗ Controller static review,
  "call_func under contention"; Evaluator round 3 #6). Other threads' code-probe hits wait
  during the call (callbacks never overlap, so a callback may hold its own lock across
  `call_func`); if one of them holds a lock the callee needs, the call times out after 5 s
  and the callee is abandoned mid-wait (inline: both run). A first-chance exception inside
  the callee also abandons it. Owner decision: no further hardening.
  *Workaround:* call only non-blocking, non-throwing callees; cache results; prefer
  `call_original` for the probed function.
- **Concurrent `call_func` on breakpoint/hw** (✅ Detours D3, Frida F5, Hunter A2): calls from
  several threads' callbacks all succeed, one after the other: other threads' hits wait while
  a call is in flight -- code probes are rewound and hit again, a data watch's thread is held
  right after its access and its callback runs once the call is over (it used to run during
  the call, where its own `call_func` returned 0). `call_original` likewise runs one at a time.
  One corner: a hardware hit on a thread that is at that moment single-stepping over a
  breakpoint probe is handled at once.
- **Inline `call_original` is a real call from the agent** (📄 Transparency findings). The
  original sees the agent's return address (`_ReturnAddress()`), a new frame for its stack
  arguments, and only the hit's argument registers (x64 RCX RDX R8 R9 XMM0-5; x86 EAX ECX
  EDX XMM0-5 + stack arguments). A function with a custom register convention (hand-written
  assembly, x86 LTCG internals taking ESI/EDI) gets garbage in the other registers; a
  `set_reg` of a nonvolatile register before `call_original` reaches the original on
  breakpoint/hw only (call_original findings).
  *Workaround:* breakpoint/hw for such functions (they run the original in place with the
  full context).
- **An exception the original handles internally is invisible** to the callback on every
  backend (call_original findings): `call_original` returns normally.
- **x86 `return_from` without `call_original` trusts `nargs`** (📄 Calling-convention CC6). A
  wrong count leaves the caller's ESP off by the difference.
  *Workaround:* follow the per-convention rule in [api.md](api.md#callback-functions) (`return_from`);
  wrap with `call_original` when unsure (the popped count is then measured).
- **Float results cannot be set** (📄 Calling-convention CC2). *Workaround:* pass them
  through with `call_original`.

## Hardware backend

- **The target's own debug registers** (⬜ Hunter A7; Controller review (7); Codex controller
  review (1)). UHH never takes a slot the target uses, and passes the target's #DB on. A
  target that overwrites DR7 wholesale over a slot UHH is using cannot keep both, and fewer
  than 4 slots may be free. A context the program captured before UHH released a slot and
  restores afterwards brings UHH's old DR back as the program's own.
  *Workaround:* breakpoint or inline for targets that use debug registers themselves.
- **Programs that round-trip their own threads' contexts** (GCs, profilers:
  SuspendThread + GetThreadContext + SetThreadContext) (⬜ Hunter A4). A context captured
  while a thread sat in a UHH debug event and written back later undoes UHH's fix-up: on hw
  the same call can be reported twice (+5 hits in 2M seen); on breakpoint the thread can
  resume one byte into the instruction (1-2 wrong reads in 3M seen).
  *Workaround:* inline is unaffected.
- **Open corner cases** (⬜ Frida F2, F4; Detours D4 residual): a lost DR6 status bit on a
  data watchpoint cannot be recovered; a thread inside exception dispatch when a hw probe is
  armed resumes with its old debug registers; in a mixed session, a thread whose queued event
  is a software breakpoint does not get a just-armed DR re-asserted.
  *Workaround:* arm hw probes before the target's threads are busy (before launch, or early
  in the run), or use breakpoint.

## Software breakpoint backend

- **The faulting-instruction restart corner case** (📄 Codex library review "TF";
  Controller review (2); Codex controller review (2); x64 and x86). When the probed
  instruction faults during its step and the program's handler continues **elsewhere**, and
  that thread's very next debug event is a **new** call reaching the same site, UHH takes
  it for the restart of the faulted instruction: no callback for that call. Only sites whose
  instruction faults and is handled by the program are affected.
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
  breakpoint probe (Core library; Detours C16; Hunter B8). The stderr line suggests
  `inline-safe nearby` offsets when it finds some.
  *Workaround:* `PROBE_FALLBACK_HW`, breakpoint/hw on that site, a suggested nearby offset, or
  `PROBE_ALLOW_UNSAFE_SITE` if you are sure nothing reaches those bytes.
- **Absolute-address inline probes get a weaker site check** (⬜ Detours D5, code reading).
  `probe_add_address(..., PROBE_INLINE)` skips the function-bounds / branch-target part:
  a return site followed within 5 bytes by a jump target could be hooked without a warning.
  *Workaround:* breakpoint or hw for return-site probes.
- **The callback runs on the target thread's stack** (📄 Transparency findings): about
  8-10 KiB per hit, so a thread close to its stack limit can overflow where it would not
  have, and committing deeper stack moves the TEB's StackLimit. A callback's own heap calls
  change heap state (including the TEB's per-thread LFH hint).
  *Workaround:* keep inline callbacks small; breakpoint/hw callbacks change neither.
- **Writing a hook is visible** (✗ Frida F7). Each install/remove changes page protection
  through the target's own `NtProtectVirtualMemory`, which an RWX watcher in the target
  sees. Breakpoint/hw write from the controller.
- **Under CET, a relocated `call` stays verbatim** (Agent review). Outside CET, a `call`
  inside the overwritten bytes is relocated so the callee returns into the hooked function
  (correct unwinding). Under shadow stacks it is copied as is, so an exception thrown by
  that callee and caught in the hooked function or above may not unwind.
  *Workaround:* do not place inline probes directly on a `call` in CET processes.
- **Remaining agent limits** (Agent review, ⬜): a thread that dies inside a callback and
  whose id is reused before the next hit is not reported as interrupted; a `call_func` left
  by a non-unwinding `longjmp` keeps its thread marked as in a call.
- **Not covered** (Calling-convention CC8): a probed site reached by the agent service
  thread's own `DLL_THREAD_ATTACH` callouts before it runs.
- **The agent stays loaded after a detach** (Lifecycle residual), quiescent: hooks removed,
  logging stopped. A later attach to the same process reuses it.
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
- Out of scope / not tested (📄 Hunter B12): probes inside WOW64 thunks, x86 `int 2e`
  system calls, large-address-aware x86 targets.
- A 32-bit program's reads of 64-bit processes bypass the 32-bit
  `ntdll!NtReadVirtualMemory` (Real-app findings).

## Logs and accounting

- **Hits = logs + `log_dropped` + `callbacks_interrupted`** exactly for a callback that logs
  once per hit, also when the process dies at any instant: a callback's first log carries its
  hit, so a thread killed after publishing it is a delivered log, not interrupted (agent v23;
  runfix1). One inherent edge (Log delivery findings): a producer that claims a slot in the
  few instructions after the final drain at detach/close loses that record uncounted.
- **Per-thread order** is kept across backends, except that a record behind two unfinished
  ring slots of other threads at the same instant can be overtaken (Log delivery findings).
- **Inline callbacks killed by process exit** (ExitProcess/TerminateProcess) before their
  first log are reported as `callbacks_interrupted`; their logs never existed (Hunter A3).
- **Session log files are not deleted.** They accumulate in `%TEMP%\uhh\logs`.
  *Workaround:* delete old `uhh-*.jsonl` files yourself.
- **A console is a slow log sink.** *Workaround:* redirect stdout to a file or pipe, or to
  `NUL` (the file still gets every record).

## Detach and close

- **Detach waits at most 15 s for running inline callbacks** (📄 Codex library review (4);
  Lifecycle L9; bounded by owner decision 2026-11-07). It keeps delivering their logs while
  any in-flight callback can still finish (thread alive, not suspended, still inside its
  callback), for up to 15 s after the hooks are removed (plus the agent's own 2 s unhook
  wait), then completes. Not waited for at all: a callback whose thread is dead, suspended by
  the program, or left through a non-unwinding `longjmp`. Callbacks still running when the
  detach completes are counted, never silent: `running=` in the detach line / `probe_final`,
  and `in_flight=` for those that had not logged yet (hits = logs_written + log_dropped +
  in_flight). **Any log they write after that is lost** (dropped in the target; nobody reads
  it). Their config blocks stay allocated, so the program itself is unaffected.
  *Workaround:* keep inline callbacks short and lock-free.
- **Config blocks can stay in a detached target** (📄 Codex library review (2)): an oversized
  inline config (over 256 bytes) is left allocated while a callback that may read it is
  still in flight. One block per such config; stderr says so.
- **Controller death:** an **attached** target with **inline probes** is protected by the
  agent's controller-death guard (Lifecycle L1): if the controller is killed, the agent
  restores breakpoints, clears debug registers, resumes held threads and removes inline hooks.
  A **breakpoint/hw-only** attach injects nothing (owner decision 2026-11-07: no side effect
  beyond deliberate writes; "controller-crash self-unhook is not worth the cost"), so it has no
  guard: the kernel detaches the dead debugger without killing the target, but the target
  keeps our INT3s / debug registers and dies at its next hit (`0x80000003` breakpoint /
  `0x80000004` single step), or runs on if it never reaches one; regress
  `lifecycle-controller-killed-{breakpoint,hw}`. A **launched** target dies with its
  controller by design. Residual (Lifecycle): a breakpoint/hw `call_func` running
  when the controller dies leaves that thread redirected; after the controller is gone, any
  single-step on a thread without its own debug registers is taken as UHH's (a program
  single-stepping itself would lose those steps). 🔧 Lifecycle L11: one x64 kill timing on
  breakpoint was intermittent; likely fixed, still watched.
  *Workaround:* end sessions with `probe_close` or Ctrl+C, not by killing the controller.
- **`probe_close` must not run while `probe_attach` is still running on another thread**
  (examples/trace). *Workaround:* signal completion of the attach first, as `uhh_trace
  --detach-after-ms` does.

## CET shadow stacks

✅ Measured on real CET hardware (CI `windows-2025` runners: AMD EPYC, Windows Server 2025, user
shadow stacks enforced for /CETCOMPAT images; regress `cet-*`). The test VM's CPU has no CET.

| Path | Status |
|---|---|
| Every backend, x64 | gated_config and the transparency fixture (`call_func`, `call_original` + `return_from`) on /CETCOMPAT targets: exact, target's shadow stack live |
| Strict mode (Exploit protection) | same rows pass: no shadow-stack violation is left for the kernel to fix up |
| breakpoint/hw `call_func` | works: the callee is entered through a real `call` from a 3-byte stub; an abandoned callee's shadow frames are dropped (SSP restored) |
| breakpoint/hw `call_original` without `return_from` | under shadow stacks the original cannot run a second time (its shadow entry is gone): the hooked function returns the original's result, with one warning |
| `SetContextIpValidation` policy | does not refuse a debugger's thread-context changes (displaced stepping, freeze moves, call stub), strict mode included |
| `BlockNonCetBinaries` policy | breakpoint/hw work; inline needs the agent and the callback module linked /CETCOMPAT, otherwise the session fails cleanly (`LoadLibraryW failed for probe_api_agent.dll`) |
| x86 | Windows enforces no shadow stack for WoW64; a WoW64 process does not even start under `BlockNonCetBinaries` |

## Visibility to the target (anti-debug)

✗ Owner decision: UHH does not mask the debugger (no PEB / debug-port hiding). Under
**every** backend the target is debugged (Codex workaround audit C6;
`examples/realworld/README.md`):

| Indicator | breakpoint | hw | inline |
|---|---|---|---|
| `IsDebuggerPresent`, remote check, debug port / object / flags, PEB `BeingDebugged` | set | set | set |
| Code bytes differ from disk at the probe | yes (`0xCC`) | no | yes (hook jump) |
| DR7 set | no | yes | no |

- An in-memory `.text` checksum taken by the program after launch does not see the INT3 or
  the hook (both are in place before its baseline); a comparison with the file on disk does.
- A debugged process never runs its `SetUnhandledExceptionFilter` filter (Controller static
  review): crash reporters behave differently than without UHH.
- UHH's own allocations in the target (scratch blocks, the agent) can take an address range
  the program has just released (📄 Hunter B11); a program that re-reserves a fixed address
  it freed could collide.

*Workaround:* none inside UHH; anti-debug targets take their "debugger" path under UHH.
