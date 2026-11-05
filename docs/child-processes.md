# Following child processes

Status: **design, not implemented.** The public API (`include/probe_api.h`) is frozen; every
signature below is a proposal for the user to choose from. Measurements were taken on the
test VM (Windows 10 22H2, 4 cores, x64 and x86 builds) with
[`bench/child_follow/child_exp.cpp`](../bench/child_follow/child_exp.cpp) (raw Win32 debug
API, no UHH) and [`bench/child_follow/suspended_attach.py`](../bench/child_follow/suspended_attach.py)
(the real UHH controller through `uhh_trace --attach`).

## 1. Where UHH stands today

* `probe_launch` creates the target with `DEBUG_ONLY_THIS_PROCESS`
  (`src/probe/session.cpp`, `probe_launch`). The target's children are not debugged, the
  agent is injected only into the target (`start_agent_load` runs `LoadLibraryW` on a
  remote thread in `s->pi.hProcess`), and an event from any other process is continued
  untouched (`continue_foreign_event`).
* `probe_attach` uses `DebugActiveProcess`: also one process only.
* `probe_attach_new(image, timeout)` polls Toolhelp about every millisecond for a NEW process
  with that image name and then attaches. It is the only way to reach a child today
  (`examples/blogs`, scenario `spawn`), and the child runs for a few ms before the attach.
* A session is ONE process throughout: `probe_session::pi`, `threads`, `module_bases`,
  `scratch`, the DR bookkeeping, the agent section (named by the target's pid,
  `probe_agent_mapping_name`) and every `Probe`'s `address/base/original/active` belong to
  that process.

Two properties of the code matter for every option below:

1. **The debug object belongs to a thread.** Whatever thread called
   `CreateProcess(DEBUG_*)`/`DebugActiveProcess` is the only one that receives those
   events (`probe_run` refuses to run on another thread). Different threads of one
   controller therefore have independent debug objects and can debug different processes
   in parallel.
2. **The inline backend needs the debugger.** The agent's control plane and the freeze
   around every hook write are `RaiseException(PROBE_IPC_CODE)` serviced by the debugger
   (`raise_ipc` in `agent.cpp`; with no debugger it silently fails). Injecting the agent
   into a child that is not debugged would give hooks with no safe patching, no
   `get_session(c)` forwarding and no runtime adds. **Every followed child must be
   debugged by the controller, whatever the backend.**

## 2. What the experiments settled

| Question | Result (x64 / x86, 20 children or trials each) |
|---|---|
| Can a debugger attach to a `CREATE_SUSPENDED` child before its first instruction? | **Yes**, 20/20 on both arches. `DebugActiveProcess` takes 0.13 ms (median); the attach break-in arrives 3.5 ms (x64) / 7.6 ms (x86) after `CreateProcess` returned. The main thread is still suspended at the break-in (suspend count 1, 20/20), and an INT3 written at the image entry during the attach's CREATE_PROCESS event is hit by the main thread, before `main`, 20/20. The loader initialises the process on the *break-in* thread (event order `C L T L L ... B`), so every static import arrives as a real LOAD_DLL event first. |
| ...and through the real UHH controller, every backend? | **Yes.** probe_app created suspended, `uhh_trace --attach` with a probe on probe_app.exe's entry point and on `ntdll!NtReadVirtualMemory`, main thread resumed after both report `active`: entry hits = 1 and read hits = logs = successful_reads = 8000 for breakpoint, hw and inline, on x64 and x86, checksum unchanged. Attach-to-armed: breakpoint/hw 50-90 ms, inline 0.2-1.4 s; most of it is the session start-up (`uhh_sym::init` -- dbghelp -- took up to 0.95 s of an inline run's 1.33 s), not the attach. Attaching to a *running* target costs the same (50-470 ms). |
| The attach reports the start address? | **No**: `lpStartAddress` is 0 in the CREATE_PROCESS event of an attach to a thread that never ran. The entry has to come from the PE header (`child_exp` does that); UHH's `arm_entry_fixup` would get 0 today. |
| Does `CreateProcess` already create the child suspended? | **Yes.** Logging the arguments (`uhh_trace -p ntdll.dll!NtCreateUserProcess:xxxxxxxx`) while a program calls `CreateProcess` with no `CREATE_SUSPENDED`: `NtCreateUserProcess`'s ThreadFlags is `0x1` (THREAD_CREATE_FLAGS_CREATE_SUSPENDED) on both arches. kernelbase registers the process with CSR and resumes the thread itself afterwards. A hook at the *return* of `NtCreateUserProcess` therefore sees a child that has not run, without rewriting any flags. |
| Can following be switched on at run time, for an attached target? | **Yes.** `NtSetInformationProcess(target, ProcessDebugFlags (31), 1)` from the debugger (WinDbg's `.childdbg 1`) makes the debug object inherited: after it, 20/20 children of an ATTACHED spawner and 20/20 of a `DEBUG_ONLY_THIS_PROCESS` launch (probe_launch's mode) arrived as CREATE_PROCESS events before their `main`. The flag reads 0 before and 1 after. |
| ...and can a child be declined? | **Yes.** `DebugActiveProcessStop(child)` at its CREATE_PROCESS event: 20/20 children ran to completion and saw `IsDebuggerPresent() == 0` at `main`. |
| `DEBUG_PROCESS` cost | 20 children: 6.8 → 16.0 ms per child (x64), 8.6 → 11.8 ms (x86); ~14 debug events per child (create, DLL loads, threads, loader breakpoint, exit). `DEBUG_ONLY_THIS_PROCESS` costs nothing per child. |
| Job-object notification (`JOB_OBJECT_MSG_NEW_PROCESS`) → attach | 40/40 attached before the child's `main` (lead 5-77 ms), but *after* it started: the loader, static DLL initialisers and the CRT start-up already ran. Asynchronous, so a fast child can be missed. |
| Toolhelp polling every ~1 ms (`probe_attach_new`) → attach | 39/40 before `main` (lead 2-36 ms), 1 attach failed (the child had already gone). Same caveat as jobs, plus it sees any process with the name, not only descendants. |

The children in these runs are tiny static-CRT programs; a real application spends longer in
its loader, which makes the asynchronous methods look *better* than they are for code that
runs early (DllMain, TLS callbacks, CRT initialisers, `main` itself).

## 3. Strategies for catching a child

### 3.1 `DEBUG_PROCESS` at launch

The OS debugs every descendant from creation; the controller gets CREATE_PROCESS before the
child's first user-mode instruction.

* Pros: no race, no hook in the parent, catches every creation path (Win32, `NtCreateUserProcess`
  called directly, legacy `NtCreateProcessEx`, a parent that inlines the syscall).
* Cons: launch only (attach cannot use a creation flag); ALL descendants are debugged and pay
  ~14 events each even when nobody wants them (~9 ms per child on x64 here); one debug thread
  carries every process's breakpoint/hw traffic.
* Failure modes: a child that checks `IsDebuggerPresent`/`ProcessDebugPort` sees a debugger;
  if the controller dies, every debugged process dies with it (kill-on-exit is the default
  for created debuggees); a target that is itself a debugger (or uses `DebugActiveProcess` on
  its children) conflicts.

### 3.2 `ProcessDebugFlags = 1` (".childdbg") -- launch AND attach, switchable

Same OS mechanism as 3.1, but set on the already-debugged root, at any time. It works for
`probe_launch` (DEBUG_ONLY_THIS_PROCESS) and `probe_attach` alike (measured above), can be
switched off again, and a child can be declined at its CREATE_PROCESS (it then runs with no
debugger at all). This is 3.1 without its two drawbacks (launch-only, all-or-nothing).

* Failure modes: as 3.1. Plus: grandchildren -- whether a followed child's own children are
  inherited depends on that child's ProcessDebugFlags; the controller holds a handle at
  CREATE_PROCESS and can set it explicitly either way (deterministic, not left to defaults).
* Debug heap: a process initialised under a debugger gets the NT debug heap unless
  `_NO_DEBUG_HEAP=1` is in its environment. `probe_launch` sets it in the root's environment,
  so children inherit it -- unless the parent passes its own environment block, and never for
  an attached root. `child_exp` reports `children_with_debug_heap` (PEB NtGlobalFlag & 0x70)
  per mode; the fix (clear the flags at the child's CREATE_PROCESS, or inject the variable)
  is an open item.

### 3.3 Hook process creation in the parent, attach while the child is suspended

A probe at the return of `ntdll!NtCreateUserProcess` (or `kernelbase!CreateProcessInternalW`)
holds the parent thread; the child exists, suspended, nothing has run. The controller attaches
(`DebugActiveProcess` -- measured 0.13 ms; armed at the break-in 3.5-7.6 ms later), arms the
child's probes, and lets the parent go. kernelbase resumes the child as usual (or the caller
does, if it asked for `CREATE_SUSPENDED`), so no flag needs rewriting and no ResumeThread is
owed.

* Pros: the parent call itself is the trigger, with its arguments (image, command line,
  creation flags, the caller's stack) at hand; a declined child is never debugged at all; the
  attaching thread can be ANY controller thread, so each child can get its own debug object
  (parallel servicing, a crash in one process's handling does not stall the others).
* Cons: it needs a probe in every followed process (a DR on hw-only sessions, or an internal
  INT3); a process created through a path that does not go through the hooked stub (direct
  syscall, `NtCreateProcessEx`, `RtlCreateUserProcess` of an old runtime) is missed; the parent
  thread is held for the attach (~4-8 ms + arming).
* Failure modes: the parent passes `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` (the child's
  official parent is someone else -- still caught, the hook is in the creator); the creator
  closes the handles or terminates the child immediately (attach fails cleanly, report it);
  inline arming in the child takes 0.2-1.4 s (agent load at the break-in), during which the
  parent is held -- make that a choice (hold for inline, or let the child's main thread wait
  at its entry, see 5).
* Grounding: the child is held at the attach exactly like `suspended_attach.py` does it, and
  UHH needs only (a) the entry from the PE header when `lpStartAddress` is 0 and (b) launch
  semantics (hold at entry until inline confirms, `arm_entry_fixup`) instead of attach
  semantics for such a child.

### 3.4 An `attach_new`-style image-name watch

What exists today. Racy by construction (measured 2-36 ms lead over `main`, after the
loader), unrelated processes with the same name match (`snapshot_pids` takes the earliest
NEW one -- it cannot tell a descendant from a stranger; filtering by parent pid has the pid
reuse problem), and polling costs a core at 1 ms granularity. Keep it for "the next
instance of X, wherever it comes from" (a service, a COM server launched by svchost,
something started through WMI or the task scheduler) -- exactly the cases the descendant
mechanisms cannot see -- not for children.

### 3.5 Job objects

`JOB_OBJECT_MSG_NEW_PROCESS` on a completion port names every process created in the job
(descendants included, unless they break away), and `KILL_ON_JOB_CLOSE` gives a "kill the
tree" for Ctrl+C on a launched target. But the notification is asynchronous (measured
5-77 ms after creation; the child is already running), assigning an *attached* process to a
job changes its behaviour (its own job, nesting rules, breakaway), and a job is not a
debugger. Use it, if at all, as an accounting net ("these processes appeared in the tree and
were not followed") and for kill-tree, not as the follow mechanism.

### 3.6 Injecting the agent into children

Needed for inline probes in a child (each process maps its own hooks), and only possible
safely when the child is debugged (section 1, point 2). Mechanically it is what
`start_agent_load` already does after the initial breakpoint; for a child caught by 3.2/3.3
the "initial breakpoint" is the loader's or the attach break-in (one `B` either way in the
event sequence). Each child gets its own agent section (named by its pid) and ring; the
controller's drainer must then serve N rings.

## 4. One session or one per child

| | One session, many processes | Session per child |
|---|---|---|
| Debug object | one thread for the whole tree (3.1/3.2 force this: inherited children land on the root's debug object) | one per child thread (3.3 attaches from any thread) |
| Code changes | every per-process field of `probe_session` and `Probe` becomes per-pid; dispatch by `event.dwProcessId` instead of `continue_foreign_event` | small: a session already is one process; the parent session spawns a child session (+ thread) per accepted child |
| Throughput | breakpoint/hw hits of all processes serialised on one thread | parallel |
| Logs / report | naturally one stream, one report | separate unless the child sessions share the parent's writer |
| UHH_SHARED | one agent copy for the tree -> shared by every process | one copy per session -> nothing shared across processes |
| Ctrl+C / detach | one place | must fan out to child threads |

A hybrid keeps both properties: **one public session per tree** (one log stream, one report,
one Ctrl+C) whose processes are internal per-process sub-sessions. With 3.2 a child that
needs its own thread can be handed over: suspend its initial thread at its CREATE_PROCESS,
`DebugActiveProcessStop`, attach from a worker thread (the two halves -- decline at
CREATE_PROCESS and attach-to-suspended -- are measured above; the hand-over itself is not).

### UHH_SHARED and the log stream across processes

* **UHH_SHARED** lives in a shared section of the per-session copy of
  `probe_api_agent.dll` (`ensure_local_agent`). If every process of a tree loads the SAME copy
  (the controller injects `s->agent_path`, which is already the copy), the section is shared by
  the controller and every followed process: "per session" stays true, and the session now
  spans the tree. Anything keyed by a per-process value then collides across processes:
  gated_config's `g_by_handle` is keyed by HANDLE, and handle 0x1f4 in the parent is not
  0x1f4 in the child. Such state needs the pid in the key -- and a breakpoint/hw callback runs
  in the controller, where `GetCurrentProcessId()` is the controller's pid, so the callback
  source can only stay identical across backends with a data-plane accessor
  (`get_pid(c)`, proposal below).
* **Logs**: one JSONL file and one stdout tail per session, with a `"pid"` field on every
  `probe_log` record (a format addition; readers that ignore unknown fields are unaffected).
  The writer queue is already shared by every producer; each process's agent ring gets a
  drainer (or one drainer polling N rings). Per-thread order is preserved; there is no order
  between processes, as today between threads.
* **Report**: one `probe` record per (probe, process) with `"pid"`, one `process` record per
  process seen (`pid, parent, image, followed|declined|refused:<why>, exit`), and the summary
  totals over the tree. `logs + log_dropped + callbacks_interrupted == hits` holds per
  process and in total.

## 5. Backend by backend

| | Breakpoint | Hardware | Inline |
|---|---|---|---|
| Arming in a child | INT3 per process (image pages are copy-on-write, so the parent's INT3s are not in the child -- except a *cloned* process, `RtlCloneUserProcess`/process reflection, which inherits them: must be debugged or it dies on the first one) | DRs per thread per process: each process has its own 4 slots | agent injected per child; hooks per process |
| Before the first instruction | yes (armed at LOAD_DLL / CREATE_PROCESS) | yes (measured; the RtlUserThreadStart re-apply covers the initial thread's NtContinue) | only if the child's main thread waits for the agent: hold at the entry (launch semantics), not attach semantics |
| Arm latency per child (measured) | 50-90 ms incl. session start-up | same | 0.2-1.4 s (agent load after the break-in) |
| Cost of an unwanted child | none if declined at creation | none | none |
| Specific hazard | a hit in a child that was declined/detached must not exist: never leave INT3s in a process we let go (detach() already restores) | DRs are per thread: a child thread created before arming must get them (CREATE_THREAD handling exists) | agent copy per tree must stay loaded in every child (`agent_copy` is deleted at close only if no process still maps it) |

## 6. Public API options

All are additive. They share these rules unless stated:
*filter* = image name (case-insensitive, `*` wildcard) or NULL for every child;
*bitness*: a child whose bitness differs from the controller is refused (reported, left
running undebugged), as `same_bitness` does for the root.

### Option A -- a flag on launch/attach

```c
enum { PROBE_FOLLOW_CHILDREN = 1u << 0, PROBE_FOLLOW_DESCENDANTS = 1u << 1 };
int probe_launch_ex(probe_session *, char *const argv[], uint32_t follow_flags);
int probe_attach_ex(probe_session *, uint32_t pid, uint32_t follow_flags);
```
Every child gets every probe of the session (same location strings, callbacks, configs).
Simplest to use and to explain; no filter, no per-child decisions, and it needs two new entry
points anyway. Logs/report as in 4; detach/Ctrl+C act on the tree.

### Option B -- `probe_follow_children` control-plane call (recommended surface)

```c
typedef struct probe_child_info {
    uint32_t pid, parent_pid;
    const char *image_path;        /* UTF-8, full path */
    const char *command_line;      /* read from the child's PEB at creation */
    int same_bitness;
} probe_child_info;
/* Called on the controller BEFORE the child runs its first instruction. Return 1 to follow,
   0 to let it run undebugged. `child` is that process's view of the session: probe_add_*
   on it adds probes to that process only. */
typedef int (*probe_child_callback)(probe_session *child, const probe_child_info *, void *user);

enum { PROBE_FOLLOW_NO_INHERIT = 1u << 0,   /* child starts with no probes (callback adds) */
       PROBE_FOLLOW_DESCENDANTS = 1u << 1,  /* grandchildren too (default: direct children) */
       PROBE_FOLLOW_WAIT_ALL = 1u << 2 };   /* probe_run returns when the whole tree exited */
int probe_follow_children(probe_session *, const char *image_filter,
                          probe_child_callback decide /* NULL = follow every match */,
                          void *user, uint32_t flags);
uint32_t get_pid(probe_context *);          /* data plane: the process this hit is in */
```
Semantics:
* Valid before `probe_launch`/`probe_attach` and at run time (also from a callback through
  `get_session(c)`): switching it on later follows only children created from then on;
  calling it with filter "" switches following off.
* Inheritance: by default the child gets every probe registered by *location string* on the
  session at that moment (`probe_add_symbol[_cfg]`, `probe_watch` is not inherited --
  absolute addresses are per process); `PROBE_FOLLOW_NO_INHERIT` starts empty. Probes added
  later on the root view go to the root only; `get_session(c)` inside a child's callback is
  that child's view.
* Logs: one stream; every record carries `"pid"`. Report: per-process records as in 4.
* `probe_run`: returns when the root exits (default; still-followed children are detached
  and keep running) or when the last followed process exits (`PROBE_FOLLOW_WAIT_ALL`).
* `probe_close` / Ctrl+C: the root behaves as today (launched: ended, attached: detached);
  followed children are always DETACHED (UHH did not start them; killing a tree is a
  separate, explicit choice -- a job object with KILL_ON_JOB_CLOSE, `PROBE_FOLLOW_KILL_TREE`).
* Limits: a cap on followed processes per session (e.g. 64); beyond it a child is declined
  and reported, never silently dropped.

### Option C -- a per-child callback only (no filter string)

The same as B with `image_filter` removed: the callback is the filter. Smaller surface, but
every child costs a callback round trip (for an inline-heavy tree the decision can need the
image name only, which a string filter answers without user code).

### Option D -- session-per-child handles

```c
/* Blocks up to timeout_ms for the next child of a followed session; the child is held
   (not yet run) until probe_run is called on the returned session, on any thread. */
probe_session *probe_next_child(probe_session *parent, const char *image_filter, uint32_t timeout_ms);
```
Each child is a full, independent session (own thread, own log file, own report, own
UHH_SHARED). Maximum isolation and parallelism, reuses today's one-process session
unchanged, and suits "run a different tool on the child". But the caller must run a loop of
threads, a slow caller holds the child (and with 3.3 the parent) indefinitely, there is no
tree-wide log or report, and the same callback source can no longer share state across the
tree.

## 7. Recommendation

1. **Mechanism: ProcessDebugFlags inheritance (3.2)** for following -- it is OS-guaranteed
   (the CREATE_PROCESS event precedes the child's first instruction, every creation path),
   it works for `probe_launch` and `probe_attach` with the same code, it can be switched on and
   off at run time, and a declined child is detached at creation and never sees a debugger
   (all measured). Use the entry from the PE header (the attach reports none) and launch
   semantics per child (hold at the entry until inline hooks confirm). Keep the hook at
   `NtCreateUserProcess`'s return (3.3) as the documented alternative for "a child per
   thread" and for when the creation arguments matter; it is proven by the
   suspended-attach experiment on all three backends. Jobs and image-name polling stay
   what they are: an accounting net and "next instance of X".
2. **API: Option B** (`probe_follow_children` + `get_pid`): one session per tree, a filter and
   an optional per-child decision that can add probes to that process, inheritance by
   location string, one log stream with `"pid"`, a per-process report, children always
   detached at the end. Option A is B with `filter = NULL, decide = NULL`; D can be built on
   B later for users who want independent per-child sessions.
3. **Implementation order**: (a) make `Probe`/session state per pid inside one debug thread
   (the hybrid of section 4, no hand-over yet); (b) breakpoint/hw in children; (c) agent per
   child with the session's agent copy (UHH_SHARED tree-wide) and one drainer over N rings;
   (d) the debug-heap fix for children; (e) optional per-child debug threads by hand-over.
4. **Tests** to add with it: `child-follow-{breakpoint,hw,inline}` on probe_app's helpers
   (they are children of the target): with following on, a probe on a function every
   helper calls at start-up (e.g. `kernelbase!WriteFile`, their handshake) must log exactly
   one hit per helper carrying that helper's pid, while the root's reads are logged exactly
   as today (logs == hits == successful_reads); a declined child sees
   no debugger and has no debug heap; Ctrl+C with live children leaves them running and
   clean; a 32-bit child of a 64-bit root is refused and reported; a fork-bomb hits the cap.

## 8. Open questions

* Debug heap in followed children (section 3.2): measure with `child_exp`
  (`children_with_debug_heap`) under each mode and pick the fix.
* Grandchild inheritance defaults of ProcessDebugFlags (set explicitly in any case).
* Protected / PPL children and children in another session or integrity level: `DebugActiveProcess`
  and agent injection fail -> refused and reported.
* WoW64 children of an x64 root (and vice versa): refused today; a cross-arch helper controller is
  possible but is a separate project.
* The `RtlCloneUserProcess` case (the clone shares the parent's INT3-modified pages): debug it or
  restore its breakpoints at its CREATE_PROCESS.
