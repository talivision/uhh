# Adversarial correctness findings — UHH probe backends

Adversarial read of the breakpoint backend (`src/probe/session.cpp`), the inline
agent (`src/probe/agent.cpp`), the shared section, and the ABI adapters, with the
just-added `.bpsync` suspend/resume race fix as the primary target. I cannot build
or run (macOS host); every item below is reasoned from the code and expressed as a
repro to run on the VM. Line numbers are against the files as read on 2026-11-04.

**Scope note on the suspend fix.** The core invariant it relies on is sound: while
a debug event is being serviced the whole target is stopped, so lifting the INT3
(session.cpp:408) and `suspend_others` (session.cpp:421) both happen before any
thread runs again, and a newly-created thread cannot run until its
`CREATE_THREAD` event is continued (so it is already in `s->threads`). The holes
are all in the *exit paths* from the step window and in backend placement, not in
the happy path.

## 1. Ranked summary

| # | Severity | Title | One-line mechanism |
|---|----------|-------|--------------------|
| F1 | **hang + correctness** | Faulting / non-single-step exception on the stepping thread never re-arms or resumes | Only `EXCEPTION_SINGLE_STEP` completes a step (session.cpp:377); any other exception on a `stepping` thread returns at :373 with the INT3 still lifted and `resume_others` never called |
| F2 | **crash** | Inline backend on `ParsedFlagSite` (2-byte prologue) | `--flag-backend inline` asks SafetyHook to steal 5 bytes from a `mov [rcx],eax; ret` site the fixture declares too short; required by the plan's mix matrix |
| F3 | **hang-looking perf cliff** | Breakpoint backend on the hot read path does a suspend/single-step storm | `--read-backend breakpoint` runs `suspend_others`+step+`resume_others` for every read → O(reads × threads) `OpenThread/Suspend/Resume/Close` syscalls serialized on one thread |
| F4 | **correctness** | Deferred inline probe races the target's first call | Gate is released after only the *already-resolved* inline hooks install (session.cpp:488-492); an inline probe on a module that loads *after* the gate installs asynchronously while the target runs |
| F5 | **correctness / policy** | Breakpoint backend ignores a pre-existing non-INT3 hook | `arm_breakpoint` only rejects `0xcc` (session.cpp:178); it silently writes `0xcc` over a foreign `E9`/`FF25` detour and emits no "pre-hooked" report, violating the mandatory-detection policy |
| F6 | **correctness** | REP-prefixed probed instruction over-counts and re-enters | `TF` single-steps a `rep` string op *per iteration*; the step completes with RIP still on the instruction, re-arms `0xcc` under it (session.cpp:379), so it re-fires every iteration |
| F7 | **hang (WoW64)** | Only one initial breakpoint is swallowed | `initial_break` (session.cpp:367) eats a single INT3; a WoW64 x86 target delivers a second initial break that is passed to the app as `DBG_EXCEPTION_NOT_HANDLED` |
| F8 | **hang (situational)** | Single-stepped blocking instruction deadlocks on a suspended holder | Stepping a `syscall`/`lock` that waits on a process-wide resource held by a thread `suspend_others` froze |
| F9 | **correctness (silent)** | `suspend_others` swallows Open/Suspend failures | On `OpenThread`/`SuspendThread` failure the thread is skipped (session.cpp:351-354), so that thread runs during the lifted-byte window and the original C1 race reappears, unreported |
| F10 | **minor (leak)** | `step_suspended` handles leak on abnormal teardown | `probe_close` never calls `resume_others` (session.cpp:644-660); an `EXIT_PROCESS` mid-step (session.cpp:579) or F1 leaks every suspended thread handle |
| F11 | **minor (divergence)** | Register/memory writes behave differently per backend | `probe_set_reg(SP)` is applied by the breakpoint backend (session.cpp:404) but dropped by the inline agent (no `rsp`/`esp` write-back, agent.cpp:122-131); `probe_write` to a read-only page succeeds under breakpoint, fails under inline |
| F12 | **minor** | `log_reserve`/`log_dropped` overflow past 2.1B hits | 32-bit `LONG` counters (shared hdr) wrap under the plan's "millions of reads × many threads"; hit counts stay correct (LONG64) but `log_dropped` reporting goes negative/garbage |

---

## 2. Findings in detail

### F1 — Faulting or asynchronous exception on the stepping thread strands the step (hang + correctness). Both arches.

**Mechanism.** The step window is opened in `handle_exception` (session.cpp:408-421):
lift the INT3 (:408), set `RIP=probe->address` + `TF` (:414-416), `stepping[tid]=probe`
(:420), `suspend_others` (:421). It is closed *only* by the `EXCEPTION_SINGLE_STEP`
branch (:377-386), which re-arms the byte (:379) and calls `resume_others` (:380).

The guard at session.cpp:373 is:
```cpp
if ((code != EXCEPTION_SINGLE_STEP || step == stepping.end()) && !probe) return true;
```
If the stepped instruction raises **any other exception** — an access violation, a
guard-page/`STATUS_GUARD_PAGE_VIOLATION`, a `#DE`, etc. — then on that thread
`code != EXCEPTION_SINGLE_STEP` is true and `probe` is null (`probe` is only set for
`EXCEPTION_BREAKPOINT`, :372), so we `return true` with `disposition` left at
`DBG_EXCEPTION_NOT_HANDLED`. Consequences, all at once:
- the INT3 byte at `probe->address` stays **lifted** → every later crossing by any
  thread is unobserved (missed hits);
- `stepping[tid]` is **never erased**;
- `resume_others` is **never called** → all other threads stay suspended forever.

Outcome depends on the app: if it has an SEH `__except` that swallows the fault
(very common around memory-touching code), the app keeps running but its worker
threads are frozen forever and the probe is dead → **full hang** (the debugger then
blocks in `WaitForDebugEvent(INFINITE)` because the only runnable thread is the one
that faulted). If unhandled, it is a second-chance crash plus a suspend/handle leak
(F10).

This is reachable without a hostile callback: it fires whenever the probed
instruction can fault. It is also trivially reachable *through a normal callback*
that rewrites a pointer register feeding the probed instruction.

**Concrete repro (needs a tiny callback change — describe only, do not apply).**
In `examples/gated_config/callbacks.cpp`, change `enable_reads` so that besides
flipping EAX it corrupts the store destination:
```cpp
// adversarial variant of enable_reads
probe_set_reg(c, PROBE_REG_CX, 0);   // ParsedFlagSite is `mov [rcx],eax`
```
Then run the flag site under the breakpoint backend with workers present:
```
gated_config <flag_rva> <read_rva> --no-wait --threads 8 --reads 100000 --clean
```
The single-step of `mov [rcx],eax` with `rcx=0` raises an AV on the main thread
while 8 workers are suspended → debugger hangs. No new fixture *support* is needed,
only the one-line callback edit.

**Cleaner repro with no callback change** (needs new fixture support): add a probe
site whose instruction is inside an app `__try/__except` and touches a guarded
page, then arm a breakpoint there while other threads run. The app recovers from
the fault; the probe silently dies and the other threads never resume.

**Fix sketch.** At the top of `handle_exception`, before :373, detect "a thread in
`stepping` raised something other than the single-step" and abort the step cleanly:
re-arm `step->second->address`, `resume_others(s)`, `stepping.erase(step)`, then fall
through to pass the original exception to the app. That restores the pre-step
invariant on every exit, not just the expected one.

---

### F2 — Inline hook on the 2-byte `ParsedFlagSite` prologue (crash). Both arches. **Required by the mix matrix.**

**Mechanism.** `flag.asm` defines the site as `mov DWORD PTR [rcx],eax` (`89 01`,
2 bytes) immediately followed by `ret` (`C3`), and the comment says outright: "too
short to patch a 5-byte inline jump safely… Breakpoint backends do not modify code
here." SafetyHook's mid-hook needs a 5-byte `E9 rel32` landing (14 for an absolute
form), and it relocates whole instructions forward until it has enough room. Here
it reaches `ret` after only 3 bytes and would relocate *across the function end*
into trailing padding / the next function — relocating a `ret` into a trampoline is
meaningless. SafetyHook will either refuse (→ `PROBE_AGENT_HOOK_FAILED`, a clean
`probe_run` failure via `accept_agent_install`, session.cpp:483-487) or, worse,
succeed and corrupt the following bytes.

The plan **requires** this cell: "MIX MATRIX: test the gated scenario across ALL
permutations of backend per probe (config-flag site and read site × {software
breakpoint, inline hook})". `gated_config` exposes `--flag-backend inline` precisely
to drive it, so this will be run.

**Concrete repro.** (x86 identical — x86 mid-hook is also `E9 rel32`; `flag_x86.asm`
is the same `89 01 C3` shape.)
```
gated_config <flag_rva> <read_rva> --flag-backend inline --read-backend inline --no-wait --clean
```
Expect either `inline agent failed to install … (status=-3)` or a crash in
`configparse!ParseConfig`/`StoreParsedFlag` on the first parse.

**Fix sketch.** `probe_add_cfg` (or install time) should reject an inline request
whose relocatable prologue is shorter than the detour, with a clear error, rather
than deferring the discovery to SafetyHook at runtime — and `gated_config`/the mix
matrix should treat "inline @ ParsedFlagSite" as an expected-unsupported cell.

---

### F3 — Breakpoint backend on the hot read path is a suspend/single-step storm (perf cliff that reads as a hang). Both arches.

**Mechanism.** Every breakpoint hit runs: `OpenThread`+`GetThreadContext`, callback,
`patch` ×2 (lift + later re-arm), `SetThreadContext` ×2, and a full
`suspend_others`/`resume_others` pair that does `OpenThread`+`SuspendThread` for
*every other live thread* and `ResumeThread`+`CloseHandle` for each
(session.cpp:348-360). All of it is serialized on the single `probe_run` thread,
and the whole process is stop-the-world for the duration. On the intended scenario
the read site is inline (cheap) and the breakpoint is a once-only flag flip, so this
never bites. But the mix matrix drives `--read-backend breakpoint`, putting a
breakpoint on `ReadSite`, which the plan says takes *millions* of hits across *more
threads than cores*.

Cost is ~`O(reads × threads)` thread-suspend syscalls plus two cross-process code
patches and two context round-trips per read, all single-threaded. At, say,
8M reads × 64 threads that is on the order of a billion `Suspend/Resume` calls. The
run will not deadlock, but it can look indistinguishable from a hang and will blow
any reasonable timeout (`check_scenario.run` default `timeout=180`).

**Concrete repro.**
```
gated_config <flag_rva> <read_rva> --read-backend breakpoint --no-wait --threads 64 --reads 2000000 --clean
```
Compare wall-clock against `--read-backend inline` at the same volume. No new
fixture support needed.

**Note.** This is not a correctness bug — counts should stay exact (that is what the
suspend fix buys). It is a scalability property the high-volume/mix-matrix
requirements will surface; worth a documented guard (e.g. refuse or warn on a
breakpoint probe expected to be hot, or cap the matrix volume for breakpoint cells).

---

### F4 — Deferred inline probe races the target's first call (correctness: missed hits). Both arches.

**Mechanism.** The gate (the stdin keystroke that lets `probe_app` past
`wait_for_key`) is held for inline sessions and released by `accept_agent_install`
→ `release_gate` (session.cpp:488-492) after `probe_agent_init` returns. But
`accept_agent_install` only confirms probes whose module was *already resolved*
(`p->address` set, session.cpp:481). An inline probe on a module that loads **after**
the gate (e.g. `configparse.dll`) has `site==0` at install time, is skipped by the
agent (`if (!request.site) continue`, agent.cpp:157), and is (re-)installed later by
the `LOAD_DLL` path: `start_agent_init` is fired on load (session.cpp:557-558) — but
that spins up a *remote* init thread and then `ContinueDebugEvent` lets the target's
main thread run concurrently. The main thread calls into the just-loaded module
immediately (`ParseConfig` right after `LoadLibraryA`), racing the asynchronous hook
install. If the call wins, the inline hook misses it.

For `configparse`'s flag site this is a single call, so losing the race means the
flag is never flipped → `reads_enabled` stays 0 → the whole workload silently does
nothing (0 reads) while the report still shows the probe as "active".

**Concrete repro** (depends on F2 being fixed first, since the natural trigger is an
inline flag site):
```
gated_config <flag_rva> <read_rva> --flag-backend inline --read-backend inline --no-wait --threads 4 --reads 200 --clean
```
Intermittent: sometimes `overrides==0` / `successful_reads==0` even though the
inline probe reports active. Contrast with the breakpoint flag backend, which arms
synchronously inside the `LOAD_DLL` handler while the target is frozen and therefore
cannot lose this race. Needs no new fixture support; a sleep inserted between
`LoadLibraryA(configparse)` and `ParseConfig` in `app.cpp` would make it
deterministic (describe only).

**Fix sketch.** For deferred inline probes, either hold the loading thread (keep the
`LOAD_DLL` event un-continued until `probe_agent_init` reports the site installed),
or install the deferred hook synchronously from the controller rather than via a
racing remote thread.

---

### F5 — Breakpoint backend does not detect a pre-existing non-INT3 hook (correctness / policy). Both arches.

**Mechanism.** `arm_breakpoint` reads the original byte and rejects only a
pre-existing `0xcc` (session.cpp:178). If the site already carries a foreign inline
detour (SafetyHook's `--prehook` installs an `E9`/`FF25` jump on `ReadThunk`, which
is the same address as `ReadSite`), `arm_breakpoint` sees `0xE9` (not `0xcc`),
proceeds, and writes `0xcc` over the detour's **first byte** with no "pre-hooked"
report. plan-v2 states existing-hook detection is "mandatory for every backend" and
the default is fail-fast-and-report; the breakpoint path implements neither for the
inline-detour case. The step-over then restores the full original first byte each
hit, so it may even *appear* to work, but the mandatory discovery/`report_prehooked`
contract is violated and a genuinely foreign hook is silently clobbered during every
lift/re-arm window.

**Concrete repro.**
```
gated_config <flag_rva> <read_rva> --read-backend breakpoint --prehook --no-wait --threads 4 --reads 500
```
`probe_app --prehook` installs the SafetyHook inline on `ReadThunk`; the breakpoint
read backend arms over it. Expect no pre-hook detection in the report despite the
site being hooked. No new fixture support needed.

**Fix sketch.** Reuse the two-layer detector (classify + compare_to_disk, referenced
in review-findings) in `arm_breakpoint`, not just the `==0xcc` check; honor
`PROBE_ALLOW_PREHOOKED` / fail-fast consistently with the inline path.

---

### F6 — REP-prefixed probed instruction over-counts and re-enters the callback (correctness). Both arches.

**Mechanism.** With `TF` set, a `rep`-prefixed string instruction (`rep movs`,
`rep stos`, …) traps **once per iteration** on x86/x64: after each repeat, RIP is
still the address of the `rep` instruction (it re-executes until RCX hits 0). The
single-step handler re-arms `0xcc` at `step->second->address` (session.cpp:379),
which equals the current RIP, and clears `TF`. On continue the CPU executes the byte
at RIP — now `0xcc` — producing a fresh `EXCEPTION_BREAKPOINT` at the same site:
`probe_at` matches, the callback runs **again**, `++hits` again. Net: the callback
fires and the hit is counted once per REP iteration instead of once per instruction,
and the user callback is re-entered mid-string-op.

Not reachable with the NOP-sled/`mov` fixture sites, but any user RVA that lands on
an inlined `memcpy`/`memset`'s `rep movs`/`rep stos` triggers it.

**Concrete repro** (needs new fixture support): add an asm site that is a single
`rep movsb` over a small buffer, expose its RVA, arm a breakpoint there, and assert
`hits == 1`; observe `hits == buffer_len`.

**Fix sketch.** On the single-step completion, if RIP is still equal to the probe
address (REP not finished), keep `TF` set and do **not** re-arm until RIP has moved
past the instruction; or special-case REP by stepping to completion with the byte
left lifted and others kept suspended.

---

### F7 — Only one initial breakpoint is swallowed (hang). WoW64-only (x64 controller debugging an x86 target).

**Mechanism.** `initial_break` (session.cpp:367) swallows exactly one
`EXCEPTION_BREAKPOINT` as the loader break. A native x64→x64 or x86→x86 session gets
one, so this is fine for the "32-bit-native first" path. A true WoW64 session
(x64 debugger, x86 target, deferred to "second" in plan-v2) delivers **two** initial
breakpoints — one from the native ntdll, one from the WoW64 ntdll. The second is not
at a probe, so it falls to session.cpp:373 and is returned with
`DBG_EXCEPTION_NOT_HANDLED`, i.e. injected into the x86 target as an unexpected
breakpoint → likely abnormal termination before `main`.

**Concrete repro.** Build the controller x64 and the target x86 (the WoW64 case the
plan calls out) and launch under `probe_run`; the target dies at startup. Latent
until WoW64 work begins, but worth fixing in the same pass that adds
`Wow64Get/SetThreadContext`. x86-only in the sense that it needs an x86 target.

**Fix sketch.** Track initial breaks per the WoW64 convention (accept the first
*user* breakpoint after the WoW64 loader break), or key off
`event.u.Exception.dwFirstChance` + a known-ntdll address rather than a single bool.

---

### F8 — Single-stepping a blocking instruction deadlocks against a suspended holder (hang). Both arches. Situational.

**Mechanism.** The step window assumes "one instruction cannot block." That holds
for ordinary instructions, but a probe placed on a `syscall`/`int 2e` stub, or on a
`lock`-prefixed op that the kernel turns into a wait, can block in the kernel on a
process-wide resource (VAD lock, heap lock via a syscall, a critical section's
keyed event) that is currently held by a thread `suspend_others` froze
(session.cpp:348-356). The holder cannot release it (suspended), and the stepping
thread cannot complete its single instruction → deadlock, and `resume_others` is
never reached.

Not hit by the fixture (its breakpoint site is a plain `mov`), but any breakpoint on
a syscall entry/`NtReadVirtualMemory`-style stub under load is a candidate.

**Concrete repro** (needs new fixture support / unusual placement): arm a breakpoint
on an instruction that acquires a lock also taken by the worker threads, run many
workers, and observe a stall. Lower priority than F1–F5 but shares the same root
family (step window exit assumptions).

**Fix sketch.** Prefer a hardware single-step that does not require freezing peers
for syscall sites, or detect syscall/lock instructions and use a temporary
breakpoint at the next instruction instead of `TF`+global suspend.

---

### F9 — `suspend_others` silently swallows failures, reopening the C1 race (correctness, silent). Both arches.

**Mechanism.** In `suspend_others` (session.cpp:351-354), if `OpenThread` returns
null or `SuspendThread` returns `(DWORD)-1`, the thread is simply skipped. That
thread then **runs during the lifted-byte window** (ContinueDebugEvent resumes it),
which is exactly the C1 race the fix exists to close — it can cross the now-original
instruction unobserved (missed hit) or, if it reaches the site, see the original
byte rather than `0xcc`. The failure is not logged or surfaced, so the race
reappears intermittently with no signal. `SuspendThread` can fail transiently for a
terminating thread; `OpenThread` can fail for a tid still in `s->threads` whose
`EXIT_THREAD` is queued behind the current event.

**Concrete repro** (needs new fixture support / timing): churn threads (create+exit)
while a breakpoint on a hot site fires, so some tids are mid-teardown when
`suspend_others` runs; occasional count drift. Hard to make deterministic; flagged
as a robustness gap rather than a reliable repro.

**Fix sketch.** Treat a suspend failure as fatal-to-the-step (abort cleanly: re-arm,
resume what was suspended, surface an error) rather than best-effort, or retry; at
minimum count/report it.

---

### F10 — `step_suspended` handles leak on abnormal teardown (minor / resource leak). Both arches.

**Mechanism.** `resume_others` is the only place `step_suspended` handles are closed
(session.cpp:357-360). It is called on normal step completion (:380) and on
stepping-thread exit (:544). It is **not** called when `EXIT_PROCESS` arrives mid-step
(session.cpp:579-580 just sets `exited` and breaks) nor in `probe_close`
(session.cpp:644-660 closes session handles but never touches `step_suspended`). F1
also leaves the vector populated. Each stranded incident leaks every suspended
thread handle for the remaining session lifetime; combined with F1 on an
SEH-recovering target it leaks per incident while the target keeps running.

**Fix sketch.** Call `resume_others(s)` in `probe_close` (and on the `EXIT_PROCESS`
path) so the vector is always drained and closed.

---

### F11 — Register/memory writes diverge between backends (minor / correctness divergence). Both arches.

**Mechanism.** The "same callback under any backend" contract is broken for two
operations:
- **SP writes.** The breakpoint backend applies `probe_set_reg(PROBE_REG_SP)` —
  `native.Rsp = context.regs.rsp` (session.cpp:404, and `.Esp` on x86). The inline
  agent's write-back copies only the `PROBE_GPRS` set, which excludes `rsp`/`esp`
  (agent.cpp:122-131), so a callback that adjusts SP is honored under breakpoint and
  silently ignored under inline.
- **Writes to read-only pages.** The breakpoint backend's `probe_write` goes through
  `WriteProcessMemory` (handles protection), while the inline agent's `local_write`
  is a raw `memcpy` guarded by SEH (agent.cpp:22-26): a write to a `PAGE_READONLY`
  target succeeds under breakpoint and fails (returns 0) under inline.

Low impact for the current callbacks (they write EAX and read only), but it
undermines the mix-matrix claim that a probe behaves identically across backends.

**Fix sketch.** Either document SP/PC/flags as not-writable uniformly, or have the
inline agent write `esp`/`rsp` back too; make the two `probe_write` paths agree on
read-only-page policy.

---

### F12 — 32-bit log counters overflow at scale (minor). Both arches.

**Mechanism.** `log_reserve` and `log_dropped` are 32-bit `LONG`
(`probe_agent_shared`), bumped by `InterlockedIncrement` per `PROBE_LOG`
(agent.cpp:89-91). The example `log_read` logs on every read, so under the plan's
"millions of reads × more threads than cores" the reserve counter can exceed
`INT_MAX` (~2.1B). After wrap it goes negative, `slot < 0` drops the record
(agent.cpp:90), and `probe_report`'s clamp (`count > LOG_CAP`, session.cpp:614-615)
does not catch a *negative* count, so no logs are emitted and `log_dropped` is
reported as a wrapped/garbage value. Hit counts are unaffected (they use `LONG64`
via `InterlockedIncrement64`), so the "counts must not drop" contract holds; only
the drop *accounting* is wrong.

**Concrete repro.** A high-volume run exceeding ~2.1B total logged hits; inspect
`log_dropped` in the report. No new fixture support needed (just volume).

**Fix sketch.** Make `log_reserve`/`log_dropped` 64-bit, and guard the report loop
against a negative count.

---

## 3. Outright bugs I'm confident about (file:line + fix sketch)

1. **F1 — stranded step on a non-single-step exception.** `handle_exception`
   (session.cpp:373, 377-386, 421) only closes the step window on
   `EXCEPTION_SINGLE_STEP`. Any other exception on a `stepping` thread leaves the
   INT3 lifted, `stepping[tid]` set, and peers suspended forever. *Fix:* before
   session.cpp:373, if `step != stepping.end()` and the code is neither the expected
   single-step nor a probe breakpoint, re-arm `step->second->address`,
   `resume_others(s)`, `stepping.erase(step)`, then pass the exception through.

2. **F10 — suspended-handle leak on teardown.** `probe_close` (session.cpp:644-660)
   and the `EXIT_PROCESS` path (session.cpp:579-580) never drain `step_suspended`.
   *Fix:* call `resume_others(s)` in `probe_close` and on process-exit teardown.

3. **F5 — breakpoint backend misses non-INT3 pre-existing hooks.** `arm_breakpoint`
   checks only `p.original == 0xcc` (session.cpp:178). *Fix:* run the inline-hook
   detector before arming and honor the fail-fast / `PROBE_ALLOW_PREHOOKED` policy,
   matching the inline backend.

4. **F9 — silent suspend failure.** `suspend_others` (session.cpp:351-354) drops
   threads it cannot open/suspend, reopening the very race the function exists to
   close. *Fix:* make a suspend failure abort the step cleanly (or retry) and
   surface it, instead of best-effort silence.

5. **F11 — inline agent never writes `rsp`/`esp` back.** `call_mid`
   (agent.cpp:122-131) copies only `PROBE_GPRS`, so `probe_set_reg(PROBE_REG_SP)` is
   a no-op inline while the breakpoint backend honors it (session.cpp:404). *Fix:*
   either write SP back in the agent or declare SP read-only on both backends.

(F2, F3, F4, F6, F7, F8, F12 are design/placement/scale issues rather than
one-line code defects; their fix sketches are inline above.)
