# API reference

The whole public API is `include/probe_api.h` (C, usable from C++). It is frozen; this page
explains it. When this page and the header disagree, the header wins. Limitations and
per-backend differences are collected in [limitations.md](limitations.md); messages and
fixes in [troubleshooting.md](troubleshooting.md).

Contents: [concepts](#concepts) · [types and macros](#types-and-macros) ·
[probe flags](#probe-flags) · [registers](#registers) · [session functions](#session-functions) ·
[callback functions](#callback-functions) · [control from a callback](#control-from-a-callback) ·
[shared state](#shared-state-uhh_shared) · [output](#output-logs-and-report) ·
[threading](#threading-and-concurrency) · [limits](#limits) ·
[per-backend differences](#per-backend-differences)

## Concepts

- A **session** (`probe_session *`) is one instrumentation run of one target process. The
  `probe_*` functions take a session (the control plane).
- A **context** (`probe_context *`, called `c`) is one probe hit: its registers and memory.
  The `get_*` / `set_*` / `send_log*` / `call_*` functions take a context (the data plane).
  Both types are opaque and distinct, so the compiler keeps them apart.
- A **probe** is a location plus a callback (`void cb(probe_context *c)`) plus a backend.
  Probes are added before the target starts or from inside any callback.
- A **backend** is chosen per probe:

| Backend | Mechanism | Code modified | Where the callback runs |
|---|---|---|---|
| `PROBE_BREAKPOINT` | INT3 written by the controller (a debugger); displaced stepping | 1 byte | in the controller, on its debugger thread |
| `PROBE_HW` | execute debug register (DR0-DR3) | watched site unchanged; internal ntdll INT3s possible | in the controller, on its debugger thread |
| `PROBE_INLINE` | SafetyHook mid-function hook installed by `probe_api_agent.dll`, injected into the target | >= 5 bytes | inside the target, on the thread that hit the probe |

  One callback source runs under every backend. The functions below return the same values
  on every backend for the same arguments, including the documented failure cases.
  What differs follows from *where* the callback runs; see
  [per-backend differences](#per-backend-differences).

- UHH is a **debugger** under every backend: the controller launches or attaches to the
  target with the Windows debug API (inline probes too: the agent's control channel and the
  hook writes go through the debugger).

### Locations

| Form | Example | Meaning |
|---|---|---|
| `module+0xRVA` | `myapp.exe+0x1052` | offset from the module's load base (an RVA from the map file or PDB) |
| `module!Name` | `ntdll.dll!NtReadVirtualMemory` | an export of the module; if not exported, a symbol from the module's PDB (beside the image, or via `_NT_SYMBOL_PATH`) |
| `module!Name+0xOFF` | `configparse.dll!ParseConfig+0x16` | an offset from that symbol |

- `module` is matched by **file name**, case-insensitively; a directory part is ignored.
  A name **without an extension means `<name>.dll`**, as `LoadLibrary`/`GetModuleHandle`
  read it: `kernel32!CreateFileW` == `kernel32.dll!CreateFileW`. This is one grammar for
  probe locations (every backend, launch, attach, adds from a callback, `uhh_trace -p`) and
  [`call_func`](#int-call_funcprobe_context-c-const-char-symbol-uint64_t-ret-int-nargs-).
- An EXE is named **with** its extension: `probe_app.exe!Func`. `probe_app!Func` names
  `probe_app.dll`, so it does not match the program; when `probe_app.exe` loads while such
  a probe is pending, stderr says `probe: warning: probe_app!Func names probe_app.dll (a
  module name without extension means .dll); the loaded probe_app.exe is not matched --
  write probe_app.exe!Func to probe it` and the probe stays pending.
- Offsets are `+0x` hexadecimal only.
- **The site must be an instruction start.** A site inside an instruction is refused on
  every backend (breakpoint would write its INT3 over an operand byte, inline would make the
  program execute the hook's jump bytes, hw would never fire): `probe <loc> refused: site is
  inside an instruction: 2 byte(s) into the 6-byte imul at app.exe!F+0xb (instruction stream
  decoded from .pdata); nearest instruction boundaries app.exe!F+0xb, app.exe!F+0x11`. UHH
  judges this where it can decode the function: by following its control flow (fall-through,
  direct branches, switch tables) from the function start (`.pdata` on x64, the PDB on both
  arches), another `.pdata`/PDB/CFG function start, or the symbol the location names --
  never a linear sweep. Where it cannot (no extent and no symbol before the site, code reached
  only through indirect jumps, overlapping code) the site is taken as given. `PROBE_ALLOW_UNSAFE_SITE` overrides this refusal on every execute backend, with one
  stderr warning and one per-probe `uhh warning` log record; use it for known overlapping
  instructions/obfuscated code. Refusals end with `Override with PROBE_ALLOW_UNSAFE_SITE.`
  `PROBE_FALLBACK_HW` alone never bypasses this refusal. The same
  applies to `probe_add_address`.
- A probe on a module that is not loaded yet stays **pending** and arms when the module
  loads (also a DLL loaded at run time). It goes back to pending when the module unloads
  and re-arms if it loads again.
- A forwarded export (e.g. `kernel32.dll!HeapAlloc`) is followed through the target
  process's export tables, including ordinal forwarders. If its destination is not loaded,
  the probe waits and resolves against that image when it loads. API-set contracts use
  the OS contract mapping; export RVAs come from the target image.
- PDB symbols: see [symbols.md](symbols.md). `uhh_trace --list <module> --mask <pattern>`
  lists what a module offers.

Inline installation failures print `probe: inline agent failed to install <loc>
(status=N): <stage>` once and retire the probe (`active:false` in the report).
Stages include trampoline build, freeze, site check, patch write and verification.
For probes added before the run, failure also sets the session error and fails the
run on launch or attach; runtime additions follow the refusal policy below.

### When probes go live

- **Launch:** breakpoint and hw probes are armed from the target's first instruction.
  Inline probes go live at the loader breakpoint: the main thread loads the agent there,
  after the static imports are mapped and before any DLL initialiser or TLS callback runs.
  Only the loader's own work before that point is seen by breakpoint/hw probes alone. (If that
  early load cannot run, a thread of the agent's loads it and the main thread is held at the
  entry point until the hooks are confirmed.) Probes on a module loaded later arm at its load.
- **Attach:** the target keeps running while probes arm. Each probe counts from its
  `probe: active ...` line on stderr. Breakpoint/hw-only sessions arm at once (nothing is
  injected). With inline probes, breakpoint/hw probes on already loaded modules wait
  for the agent's controller-death guard (up to 5 s, then arm with a warning). The guard
  is ready when the agent's service thread runs. Newly loaded modules arm their
  breakpoint/hw probes immediately, even before the guard: killing the controller in
  that window can leave those traps in the target.
- A probe added from a callback: breakpoint/hw arm before the target resumes; mapped
  inline additions wait up to 5 s. See [control from a callback](#control-from-a-callback)
  for installation failures, deferred refusals and pending modules.

## Types and macros

| Name | Meaning |
|---|---|
| `probe_session` | opaque session type |
| `probe_context` | opaque per-hit context |
| `probe_callback` | `void (*)(probe_context *)` |
| `enum probe_flags` | backend and option bits, see [probe flags](#probe-flags) |
| `enum probe_register` | register ids, see [registers](#registers) |
| `PROBE_LOG(c, ...)` | same as `send_log(c, ...)` |
| `UHH_SHARED` | (MSVC) places a global in the shared `uhhshr` section; see [shared state](#shared-state-uhh_shared) |

Callbacks of inline probes, and callbacks of probes added from a callback, must be exported
by name (`__declspec(dllexport)`): they are found by export name. The examples declare every
callback `extern "C" __declspec(dllexport)`; that simple rule covers all cases.

## Probe flags

Pass exactly one backend flag, optionally ORed with options. An unknown bit is refused
(`unknown probe flags`); an option used with the wrong backend is refused
(`requested probe type/options are unsupported in this build`).

| Flag | Backends | Meaning |
|---|---|---|
| `PROBE_BREAKPOINT` | - | software breakpoint (INT3) |
| `PROBE_HW` | - | hardware execute breakpoint (one of 4 debug registers) |
| `PROBE_INLINE` | - | inline hook in the target |
| `PROBE_AT_RETURN` | none | **refused by every backend.** To observe a return, read the return address at the function's entry (`get_mem` at SP) and add a probe there from the callback (`probe_add_address(get_session(c), ret, on_return, flags)`); it fires on every return to that site. |
| `PROBE_ONCE` | breakpoint, hw | remove the probe after its first hit. Refused with `PROBE_INLINE`. |
| `PROBE_WATCH_WRITE` | hw | data watchpoint: fire when the address is written. With `probe_watch` it is the default. |
| `PROBE_WATCH_RW` | hw | data watchpoint: fire when the address is read or written. Exactly one of WRITE / RW. |
| `PROBE_ALLOW_PREHOOKED` | inline | install over a site another tool already hooked, chaining through its hook. Without it such a site is refused for inline (breakpoint reports it but refuses an existing INT3; hw skips prehook detection). |
| `PROBE_FALLBACK_HW` | inline | when the inline site is refused (pre-hooked, unsafe, or overlapping another inline hook), use a hardware execute probe instead (`probe: X -> hardware fallback (...)`). Needs a free debug register. |
| `PROBE_UNSAFE_FAST_PATCH` | inline | write the hook **without** freezing the target. By default every other thread is suspended while a hook is written (only at install/remove, never per hit) and a thread caught inside the overwritten bytes is moved onto the trampoline. With this flag such a thread can crash. For measurement only. |
| `PROBE_ALLOW_UNSAFE_SITE` | all execute backends | override the instruction-boundary refusal with one stderr warning and one per-probe `uhh warning` log record (never valid for data watchpoints). Inline additionally: install even where the site check refuses (code could arrive inside the >= 5 overwritten bytes: a branch target, function start, return point, switch-table target, live code after a ret/jmp, an unresolvable indirect jump, the end of the section). The reason is printed as a warning. You assert nothing reaches those bytes. The other inline checks keep their existing meaning. |

## Registers

`enum probe_register`: `PROBE_REG_AX, BX, CX, DX, SI, DI, BP, SP, R8 ... R15`.

- Each id is the full native register: RAX..R15 on x64, EAX..EBP/ESP on x86.
- `PROBE_REG_AX` is the return-value register.
- On x86, R8..R15 read 0 and cannot be set (`set_reg` returns 0).
- On x86, `set_reg` keeps the low 32 bits (what the register holds); a later `get_reg`
  returns exactly that.
- There is no accessor for the instruction pointer, flags, or XMM/x87 registers.

## Session functions

All return `1` on success and `0` on failure unless stated otherwise. A failure prints
`probe: error: <reason>` on stderr; the first error of a session is also kept and appears
as `"error"` in the report.

### `probe_session *probe_session_create(void)`

Creates an empty session. Returns NULL only if allocation fails.

### `int probe_add_symbol(probe_session *s, const char *location, probe_callback cb, uint32_t flags)`
### `int probe_add_symbol_cfg(probe_session *s, const char *location, probe_callback cb, uint32_t flags, const void *config, size_t config_len)`

Adds a probe at a [location](#locations). The `_cfg` form attaches a configuration block:
it is **copied** at the call, so your buffer can go away afterwards; the callback reads the
copy with `get_config`. `config_len` may be 0 (no config); a non-zero length with a NULL
`config` is refused; the limit is 4 GB (`UINT32_MAX` bytes) on every backend.

- Before launch/attach the call validates the location syntax and flags, prints
  `probe: pending <location>`, and returns 1. Resolution happens when the module loads.
- A probe added **before** the target starts that cannot be armed when its module loads
  (unknown export, refused inline site, no free debug register, ...) **fails the session**:
  `probe_run` returns 0, a launched target is terminated, an attached one is detached.
- Refused at once: null callback, bad syntax (`location must be module+0xRVA or
  module!Export[+0xOFF]`, `symbol offset must be +0xHEX`, ...), bad flags, a fifth hw probe
  (`too many hardware probes (max 4 DR slots)`), a 129th inline probe
  (`too many inline probes (max 128)`), an inline callback that is not an export
  (`inline callback is not a named export`), a session whose target already exited.
- From a callback, see [control from a callback](#control-from-a-callback).

### `int probe_add_address(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags)`

A probe on an absolute address in the target, typically a return address read in a
callback. Needs a running target (`absolute-address probes need a running target`), so it
is normally called from a callback. Watch flags are refused here (`use probe_watch for data
watchpoints`). A probe whose address lies in a DLL that unloads is retired for good
(`probe: <address> retired: its module unloaded`). An address inside an instruction is
refused as for [locations](#locations) (`probe 0x... refused: site is inside an instruction: ...`).

### `int probe_watch(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags)`

A hardware **data** watchpoint on an absolute address: the callback fires when the
location is written (`PROBE_WATCH_WRITE`, the default when no mode is given) or read or
written (`PROBE_WATCH_RW`). Optional `| PROBE_ONCE`. The watched address is not patched.
Hardware sessions can install internal software breakpoints at `ntdll!NtContinue`,
`NtContinueEx` and `RtlUserThreadStart` to maintain debug registers across context restores
and thread creation.

- The watch covers one dword: the address must be 4-byte aligned
  (`probe_watch address must be 4-byte aligned (watches one dword)`).
- Counts against the 4 hardware slots, together with `PROBE_HW` execute probes.
- Needs a running target, like `probe_add_address`. A module variable can also be watched
  before launch with `probe_add_symbol(s, "module+0xRVA", cb, PROBE_HW | PROBE_WATCH_WRITE)`.

### `int probe_launch(probe_session *s, char *const argv[])`

Starts `argv[0]` (`argv` is NULL-terminated) under UHH and returns once it is created; the
target runs when `probe_run` runs. One launch or attach per session
(`session already launched`).

- `argv[0]` is passed to `CreateProcess` as the application name: it is not searched on
  `PATH` and needs its `.exe` extension; a relative path is relative to the current
  directory. Give a full path to be safe. The command line is built from all of `argv`,
  quoted where needed.

- The target must have the controller's bitness (`target is a 32-bit (WOW64) process: use
  the x86 build of UHH` / `target is a 64-bit process: use the x64 build of UHH`).
- Only this process is debugged; its children run unprobed.
- The target inherits the caller's **stdin**.
- **stdout/stderr**: when the caller's are a console (or NUL) the target writes to them
  directly. When they are a pipe or a file, the target gets its own pipe and UHH forwards
  its bytes unchanged, a complete line at a time, so a `probe_log` record is always a whole
  line of its own. An unfinished line (a prompt, binary output) goes out after ~50 ms
  without new bytes; records logged meanwhile follow at the target's next newline. A
  stdout and stderr that are one stream (`2>&1`) share one pipe and keep their order. Only
  when the target ends inside a line and records or the report still follow does UHH add
  a `"\n"` first. Output its children still write after it exits is forwarded until
  `probe_close`.
- The target is started with `_NO_DEBUG_HEAP=1`, so it gets its normal heap, not the
  debug heap a debugged process would get.
- Prints `probe: logs -> <file>` and `probe: symbols via <dbghelp>` on stderr.

### `int probe_attach(probe_session *s, uint32_t pid)`

Attaches to a running process instead of launching one.

- Opens the process with `PROCESS_ALL_ACCESS` and attaches as a debugger. A process that
  already has a debugger cannot be attached (the second controller fails with Win32 87).
- Same-bitness rule as `probe_launch`.
- The agent DLL is injected only when the session has an inline probe: at the attach if
  one is registered, otherwise when a callback or runtime add requests the first one
  (owner decision 2026-11-07). A breakpoint/hw-only session loads nothing into the target
  and does not need `probe_api_agent.dll` -- unless its callbacks use `UHH_SHARED` state:
  the controller then runs them from its own local copy of the agent DLL (still nothing is
  injected). Where the agent is loaded it is also the
  controller-death guard: if the controller dies, the agent restores breakpoints, clears
  UHH-owned debug registers and removes hooks. A breakpoint/hw-only target has no such guard (see
  [limitations.md](limitations.md#detach-and-close)).
- Probes resolve against the modules already loaded and any loaded later. Reattach
  reuses an identified retained agent only when its normalized file contents match
  this build, and maps that same file in the controller to reconnect `UHH_SHARED`.
  A different build is refused; restart the target to use it.
  Discovery identifies agents by mapped PE export names, independently of loader
  lists and filenames; unreadable/unrelated images are skipped. For an identified
  agent, in-memory PE build fields/checksum must also match. An unreadable agent
  identity or backing file refuses attach with `retained inline agent unknown-image`.
- `probe_run` returns when the target exits. `probe_close` on a still-running target
  **detaches**: requests inline unhooking, restores breakpoints and clears UHH-owned debug registers;
  the target keeps running. The agent stop wait is bounded to 5 s. If it cannot finish in
  time, hooks may remain until the target lets the stop thread run; cleanup is not confirmed
  at return (see [limitations.md](limitations.md#detach-and-close)).

### `int probe_attach_new(probe_session *s, const char *image_name, uint32_t timeout_ms)`

Waits up to `timeout_ms` (0 = forever) for a **new** process whose image name matches
(e.g. `"probe_app.exe"`; processes already running are ignored) and attaches to it. It
polls about every millisecond, so the target may run for a few milliseconds before the
attach lands: instrument what it does after start-up. Any process with that name
matches, not only children of a particular parent. On timeout:
`no new <image> appeared`.

### `int probe_run(probe_session *s)`

Runs the session: dispatches debug events, runs breakpoint/hw callbacks, drains inline
logs, until the target exits or the session is stopped.

- Must be called on the **same thread** that called `probe_launch`/`probe_attach` (Windows
  binds the debug object to that thread):
  `probe_run must be called on the thread that called probe_launch/probe_attach`.
- Once per session (`session already ran`).
- Returns 1 when the target exited, or the session detached, with no error.
- On an internal error with an attached target, it detaches on its own thread before
  returning (`probe: session failed (<reason>): detaching from the target`).
- **Ctrl+C / Ctrl+Break** while `probe_run` (through `probe_wait_for_exit`) runs ends the
  session, not the tool: an attached target is detached and keeps running, a launched one
  is ended, and `probe_run` returns normally so the caller still flushes logs and writes its
  report. A second press gets the default handling (the tool ends).

### `int probe_wait_for_exit(probe_session *s)`

Call after `probe_run`. Waits until every `probe_log` record is in the session log file and
the live stdout tail has caught up.

Returns 1 only if the session has no error **and** either the target exited with exit code
0 or the session was interrupted by Ctrl+C. A target exiting with a non-zero code makes it
return 0 (the report's `app_exit` shows the code). A stdout reader that went away
(`| head`) is not an error: the live tail stops with a warning, every record still reaches
the file, and the report says `"live_output_closed":true`.

### `void probe_report(probe_session *s, FILE *out)`

Catches the stdout tail up, then writes to `out` only the `prehook`, `probe` and
`probe_report` records (see [output](#output-logs-and-report)). File-backed logs are never
replayed, also on repeated calls. In an attach that is detached afterwards, counts taken
before `probe_close` race the running target; `probe_close` prints the final counts.

### `void probe_close(probe_session *s)`

Ends the session and frees it; `s` is invalid afterwards.

- May be called from another thread while `probe_run` runs: it asks `probe_run` to stop
  (detach an attached target, end a launched one), waits until `probe_run` has returned
  (`probe: close: still waiting for probe_run to stop (Ns; it is <phase>)` every 15 s), then
  tears down.
- A launched target that is still running is terminated (exit code 3).
- An attached target that is still running is detached. stderr then shows
  `probe: detached: hits=.. logs_written=.. log_dropped=.. in_flight=.. running=..`
  (hits = logs_written + log_dropped + in_flight).
- Inline unhooking has the bounded stop wait described at `probe_attach`; close does not
  guarantee that unconfirmed hook removal has finished.
- Detach waits at most 15 s for inline callbacks that are still running and can finish,
  delivering their logs meanwhile. After that it completes: `running=` counts the callbacks
  still running, `in_flight=` those of them that had not logged yet, and any log they write
  later is lost (see [limitations.md](limitations.md#detach-and-close)).
- Do not call it while `probe_attach` is still running on another thread.

## Callback functions

These take the hit's context `c`. With a NULL context they return 0 and log no record.

### `uint64_t get_reg(probe_context *c, enum probe_register r)`
### `int set_reg(probe_context *c, enum probe_register r, uint64_t value)`

Read or write a register of the hit thread. `get_reg` returns 0 for an invalid id (and for
R8..R15 on x86); `set_reg` returns 0 for those, 1 otherwise. Changes apply when the
callback returns. A `set_reg` that changes a value is counted in the report's `overrides`.
`set_reg(c, PROBE_REG_SP, ...)` is honoured on every backend.

### `uint64_t get_func_arg(probe_context *c, size_t index)`

Integer argument `index` at a function **entry** probe (`[SP]` is the return address). The
index is positional per architecture, because the API cannot know the callee's
convention:

- **x64** (every convention): 0..3 = RCX, RDX, R8, R9, then `[RSP+8+8*index]`. A
  float/double among the first four is in XMM (not readable: that index returns the
  unrelated integer register). A struct of 1/2/4/8 bytes comes by value, any other as a
  pointer to a caller copy. A hidden return pointer (struct results over 8 bytes) is index 0
  (member functions: `this` 0, hidden pointer 1) and shifts the rest by one.
- **x86**: the index-th 4-byte stack slot, `[ESP+4+4*index]`, whatever the convention.
  Register arguments are not slots; read them with `get_reg`: `__fastcall` ECX, EDX (index 0
  is the third argument), `__thiscall` ECX = `this` (index 0 is the first declared
  argument), `__vectorcall` ECX, EDX (XMM0-5 not readable). A 64-bit integer or double takes
  two slots (low, high), a float one, a struct by value size/4 slots; a hidden return
  pointer is slot 0.
- A C++ `this` is `get_reg(c, PROBE_REG_CX)` on both architectures.
- Mid-function the result is whatever lies at those stack positions. An index whose
  address cannot be read returns 0.

### `int get_mem(probe_context *c, uint64_t address, void *buffer, size_t size)`
### `int set_mem(probe_context *c, uint64_t address, const void *buffer, size_t size)`

Copy target memory into `buffer`, or `buffer` into target memory. Return 1 only if the
whole range was transferred.

- The whole range must be committed, readable / writable and free of guard pages. A
  failed check returns 0 without transferring bytes or consuming a guard; read-only pages
  (code included) are not made writable. Inline uses the calling thread's TEB committed
  stack bounds without a query, caches image-region protection verdicts until module unload,
  and queries other private/mapped regions once per region per callback. Stack capture uses
  the same policy, except x86 speculative return-address scanning re-queries image regions
  once per capture so a newly guarded candidate is skipped untouched.
  `call_func` / `call_original` invalidate protection verdicts on return.
  Protection changes by another thread during a callback are an accepted race with these
  checks. Keep cached image-section protections stable while probing; callbacks changing
  protection must use `call_func` before accessing that memory again.
- `get_mem` of code under a probe returns the **program's** bytes, not UHH's INT3 or hook
  jump (on every backend, also for another backend's probe).
- Target pointers are only meaningful through these functions: a breakpoint/hw callback
  runs in the controller, where a target address is not a valid pointer.

### `const void *get_config(probe_context *c)`

The probe's config block (the copy made by `probe_add_symbol_cfg`), or NULL if it has
none. The block is 8-byte aligned. Treat it as read-only. A common pattern (all examples)
is a struct with a cookie field checked before use.

### `void send_log(probe_context *c, const char *format, ...)`
### `void send_log_stack(probe_context *c, const char *format, ...)`
### `PROBE_LOG(c, ...)`

Append one `probe_log` record (printf-style formatting). `send_log_stack` adds a snapshot
of the call stack at the hit to the same record.

- The message is at most 1023 bytes; a longer one is cut and ends in `...[truncated]`.
- An invalid format or a faulting argument gives `[unformattable] <format>`; it is never
  fatal and never dropped. `%n` is refused that way. A NULL format sends nothing.
- Control characters are escaped in the JSON; bytes that are not valid UTF-8 are written
  as `\u00XX`; embedded NULs are kept.
- `%s` must point to memory of the process the callback runs in. For a target string,
  `get_mem` it into a local buffer first (see [B10](limitations.md#formatting-target-strings)).
- The stack holds up to 32 frames, frame 0 being the probe site. Only raw return addresses
  are captured at the hit; they are resolved to `module!function+0xoff` (plus `file:line`
  with PDBs) later on the controller's log-writer thread. Walkers differ per backend; see
  [symbols.md](symbols.md#stacks-per-backend-send_log_stack).
- Records are lossless: when the writer is behind, the logging thread waits. Per-thread
  order is kept, also across backends.

### `int call_func(probe_context *c, const char *symbol, uint64_t *ret, int nargs, ...)`

Calls a function **in the target**, on the thread that hit the probe. Returns 1 if the call
ran; `*ret` receives the return register.

- `symbol`: `"module!Export[+0xOFF]"`, `"module+0xRVA"` or `"0xADDRESS"`, with the module
  grammar of [probe locations](#locations): matched by file name (a directory part is
  ignored); a name without an extension means `<name>.dll` (`"kernel32!X"` ==
  `"kernel32.dll!X"`). Offsets are `+0x` hex only.
- Up to 8 integer/pointer arguments (Windows x64 ABI; x86 stack arguments, stdcall or
  cdecl). The implementation reads each variadic argument as a `uint64_t`, so pass every
  argument as `uint64_t` (cast constants: `(uint64_t)0`), as the examples do.
- Returns 0 without calling anything for: an unknown module or export, `nargs` outside
  0..8, an address that is not committed executable memory.
- The callee runs with whatever locks the hit thread holds: avoid functions that need them
  (e.g. the allocator from inside a `malloc` hook).
- Probes hit inside the callee on the same thread run no callback.
- The program does not see the callee's last-error value or last NT status: the hit
  thread's values are restored.
- For the target's pid/tid, call `kernel32.dll!GetCurrentProcessId` /
  `GetCurrentThreadId` this way: a direct Win32 call acts on the process the callback runs
  in.
- **Breakpoint/hw:** the debugger runs the call on the stopped thread and restores its
  context, including enabled extended register state. Context-setup failures return 0
  with a once-per-probe diagnostic. It adds roughly 200 µs on x64 / 290 µs on x86 on
  the test VM, so cache results. Other threads keep
  running; their hits wait until the call ends (a code probe's thread is rewound and hits
  again; a data watch's thread is held right after its access, and its callback runs once
  the call is over). Calls from several threads' callbacks all succeed, one after the other.
  A call that does not return within 5 s is abandoned (`probe: call_func timed out after 5 s;
  thread restored`). A callee that raises an exception, even one it handles itself, is
  abandoned at that exception (returns 0, `*ret` untouched, the target never sees it).
  The callee is entered through a real `call` (a 3-byte stub in the target), so it works
  under CET shadow stacks too (measured on enforced-CET hardware, CI windows-2025). The
  callee's frame goes 512+ bytes below the hit's SP: where that stack is not committed yet,
  the thread first grows it itself; within the last pages of the thread's stack reservation
  the call is refused (returns 0, one stderr line per probe:
  `call_func refused: the thread's stack is nearly exhausted ...`).
- **Inline:** a direct call (~2.3 µs including the hit on the test VM). Named resolutions
  are cached until a module unload; executability is checked on every call. Loaded-image
  callees, including absolute addresses, are held by a temporary module reference during the call; failure to acquire
  it refuses the call. A concurrent `FreeLibrary` may defer unload until the call returns. Repeated resolution/unload races
  return 0 after four attempts. An exception in the callee is dispatched in the target as usual
  (handled inside: returns 1; unhandled: 0), and the target's vectored handlers see it.
- Prefer `call_original` for the probed function itself, and keep `call_func` to callees
  that take no locks and do not throw.

### `int call_original(probe_context *c, int nargs, uint64_t *ret)`
### `void return_from(probe_context *c, uint64_t value, int nargs)`

Detours-style replacement from an **entry** probe (the function's first instruction; also
a jmp thunk, an import/incremental-link thunk, a tail-call target, an x86 `mov edi,edi`
prologue). Same source on every backend.

`call_original` runs the probed function now, on the hit thread, with the current argument
registers and stack (including the callback's `set_reg`/`set_mem` changes). Returns 1 if it
ran; `*ret` receives the integer return register (x64 RAX; x86 EAX zero-extended).

- `nargs` = the integer/pointer arguments the function takes, 0..16 (e.g. 11 for
  `NtCreateFile`). It matters to inline only, and only as a minimum: inline copies the
  first 32 x64 stack arguments / 64 x86 slots anyway (stack arguments beyond 256 bytes are
  cut off), plus the argument registers and XMM0-5 as at the hit. Register arguments always
  go as at the hit, so a method with no other arguments is called with `nargs` 0.
- This probe does not fire for that call. Probes of the same kind hit inside the original
  (inline in inline; breakpoint/hw in breakpoint/hw), this one included for a recursive
  function, count their hits but run no callback. Probes of the other kind fire.
- An exception or `longjmp` out of the original goes to the program's own handlers exactly
  as without the probe; the body ran once and the rest of the callback does not run (its
  C++ locals are not destroyed). On breakpoint/hw the same holds for an original that has
  not returned after 5 s (it is released and runs on) and for a thread that exits inside it.
- **Breakpoint/hw:** the original runs in place on the hit's own stack; a debug register on
  that thread catches its return. That needs one of the 4 debug registers for the call: a
  free one, or, when the hit is itself a hw execute probe, its own slot (a recursive entry
  on that thread during the call then goes uncounted). Otherwise it is refused (0, warned
  once per probe: `uhh warning: call_original refused: needs one free debug register (all 4
  in use)`). Other threads' hits wait until the call ends.
- Refused (returns 0, warned once per probe) when the hit is not at a function entry
  (`[SP]` is not a return address, e.g. a probe after a `push`). On 0 the original has
  **not** run: do not `return_from`; let the hit fall through.

`return_from` makes the probed function return to its caller when the callback ends,
without running the body (again). It resumes at a real `ret` with SP at the hit's return
address, so the normal and shadow stacks stay in sync.

- The caller gets: x64 RAX = `value`; x86 EAX = low half and EDX = high half of `value`.
  After `call_original`, a `value` whose high half is 0 leaves EDX as the original returned
  it, so `return_from(c, r, nargs)` passes any integer result through unchanged. (To return
  a 64-bit value with a zero high half there, `set_reg(c, PROBE_REG_DX, 0)` after
  `return_from`.)
- Floating-point results cannot be set. After `call_original` the caller gets the
  original's XMM0 / x87 ST0, so passing a float result through works; without it the
  caller gets whatever XMM0/ST0 hold. Do not `return_from` a float function without calling
  the original.
- A struct result over 8 bytes goes through the hidden pointer (`get_func_arg(c, 0)`, x64
  member functions 1): write it with `set_mem` and `return_from(c, pointer, nargs)`.
- `nargs` (counts on x86 only; on x64 any value 0..255 does the same; outside 0..255
  `return_from` does nothing, on every backend) = the **stack** argument slots the callee pops:
  `__stdcall` all of them (64-bit/double ones count 2), `__fastcall`/`__vectorcall` those
  after the register ones, `__thiscall` those after `this`; a hidden return pointer counts
  1. Pass 0 for `__cdecl` and varargs functions (the caller pops). After `call_original` the
  count the original really popped is used, and a different `nargs` is warned once per
  probe. Without `call_original` a wrong `nargs` is **not** caught and leaves the caller's
  ESP off by the difference.
- Other register changes (`set_reg`) are kept; SP is always the hit's.
- Refused (no effect, warned once) where `call_original` is refused.
- `call_original` without `return_from` lets the original run a **second** time on fall
  through (warned once per probe). Exception: on breakpoint/hw under a CET shadow stack it
  cannot run twice, so the caller gets the original's result (warned once).

Note the asymmetry: `call_original`'s `nargs` counts the arguments the function takes;
`return_from`'s counts the x86 stack slots the callee pops (`__thiscall` with no other
arguments: 0; `NtCreateFile`: 11).

Typical wrap (examples/filetrace):

```cpp
uint64_t status = 0;
if (!call_original(c, 11, &status)) return;   // refused: the call runs normally
/* ... inspect the results ... */
return_from(c, status, 11);                    // the caller sees the real status
```

Warnings about `call_original` / `return_from` go into the log as a `uhh warning: ...`
record, once per probe (the probe's first such warning), on every backend -- the
breakpoint/hw refusal for want of a debug register included; breakpoint/hw also print them on
stderr (`probe: warning: <location>: ...`, the first of each kind per session).

### `probe_session *get_session(probe_context *c)`

The session the callback belongs to, for control-plane calls from a callback; see below.

Inline recursion tracking uses 4096 primary and 256 overflow thread slots, then a TLS
fallback. `call_func` remains guarded with that fallback. Before static TLS is available,
a hit with both tables owned by live threads is counted but its callback is refused with
a warning; it cannot safely run unguarded.

## Control from a callback

`get_session(c)` works in every callback: breakpoint/hw get the real session; inline
callbacks get a proxy whose calls are forwarded to the controller synchronously. The same
source works in every backend.

- Only `probe_add_symbol`, `probe_add_symbol_cfg`, `probe_add_address` and `probe_watch` may
  be called from a callback.
- The new probe's callback must be **exported by the calling callback's module**, on every
  backend. An inline request names it by export and the controller resolves that name only
  in that module (the target is untrusted: it must not name functions of other controller
  modules); breakpoint/hw refuse the same requests. Not exported: `a probe added from a
  callback needs a callback exported by name (dllexport)`; another module's export: `a probe
  added from a callback needs a callback exported by the calling callback's module`. Keep a
  callback and the callbacks it adds in one module.
- A failure returns 0 to the callback and does not become the session's error. Refusals by
  the controller print `probe: dynamic add failed: <reason>`; an inline request that cannot be
  read prints `probe: dynamic add from inline callback: ...`; an inline add with a null or
  non-exported callback or a null config is refused in the target, without a message.
- A probe added for a module that is not loaded yet returns 1 and stays pending; if it
  cannot be armed when the module loads, stderr shows `probe: runtime probe <loc> failed to
  arm: <reason>` and the probe is dropped.
- A mapped inline addition waits until installed; an agent installation failure returns 0
  and retires the probe, with its status and failing stage printed on stderr.
  Exception: deferred site-safety vetting may retire an accepted submission with a diagnostic
  (return 1, inactive, no hits), preserving the submission semantics. The wait is bounded
  to 5 s; a timeout returns 0 and releases the caller. The pending hook may still install later.
- Configs have no extra size limit from a callback (4 GB everywhere); a symbol string sent
  from an inline callback is limited to 64 KiB.

Example (README): watch the block `malloc` returns.

```c
void on_write(probe_context *c) { send_log_stack(c, "write to watched block"); }

void on_return(probe_context *c) {                      /* one-shot, at malloc's return  */
    probe_watch(get_session(c), get_reg(c, PROBE_REG_AX), on_write, PROBE_WATCH_WRITE);
}
void on_malloc(probe_context *c) {                      /* malloc entry                  */
    uint64_t sp = get_reg(c, PROBE_REG_SP), ret = 0;
    if (get_func_arg(c, 0) != 0x1337) return;           /* only the block we care about  */
    get_mem(c, sp, &ret, sizeof(void *));               /* return address                */
    probe_add_address(get_session(c), ret, on_return, PROBE_BREAKPOINT | PROBE_ONCE);
}
probe_add_symbol(s, "ucrtbase.dll!malloc", on_malloc, PROBE_BREAKPOINT);
```

(Full, built version: `examples/dynwatch`.)

## Shared state (`UHH_SHARED`)

Breakpoint/hw callbacks run in the controller and inline callbacks run in the target, so a
plain global exists once in **each** process. Probes that share state (a handle map, a
counter) either use one backend, or mark the state `UHH_SHARED`:

```cpp
UHH_SHARED OpenRecord g_by_handle[kHandleSlots];   // examples/gated_config/callbacks.cpp
```

- A `UHH_SHARED` global lives in a shared section of the callbacks DLL
  (`probe_api_agent.dll`). The controller runs those callbacks from its own copy of the same
  DLL file the target loads, so both processes see the same memory with ordinary access.
- Rules: constant or zero initialisation only (C++: enforced by `constinit`); no pointers
  into either process (store values, handles, indices); lock-free atomics for
  synchronisation (`std::atomic_ref` in the examples).
- Per session: each session uses its own copy of the agent DLL
  (`%TEMP%\uhh\<pid>-<tick>-<n>\probe_api_agent.dll`, deleted at close -- after a detach the
  target still has it loaded, and a later session removes it), so separate
  sessions never share. To keep that copy off the launch's critical path, a controller
  prepares the next session's copy in `%TEMP%\uhh\warm`; one is used only while `%TEMP%\uhh`
  is writable by this user alone (plus SYSTEM / Administrators) and only if it is exactly
  this build's agent (version stamp, PE identity and checksum), else a fresh copy is made.
- A breakpoint/hw callback of a module with `UHH_SHARED` globals must be an export that the
  agent DLL also has (it is run from there): otherwise `callback uses UHH_SHARED state but
  is not a named export ...` or `UHH_SHARED callback '<name>' is not exported by the agent
  DLL`.
- Callbacks of a module without `UHH_SHARED` globals are unaffected.

## Output: logs and report

### Session log file and live tail

Every `send_log`/`send_log_stack` record is appended as one JSON line to a per-session file,
`%TEMP%\uhh\logs\uhh-<controller pid>-<n>.jsonl`; its path is printed once as
`probe: logs -> ...`. The file is not deleted at close. The controller's log writer writes
each batch of lines to its stdout first (the live tail), then hands it to the file's own
appender thread. The bounded file queue absorbs short disk stalls; when full it
back-pressures the writer and stdout; a batch goes out within about
10 ms, at once when the writer was idle. When the writer falls behind, the logging
thread waits instead of dropping records. A failed file append ends the file: its failed
batch, queued batches and subsequent records count in `log_dropped`, including records
already delivered to stdout. The session error reports the successfully appended count; stdout may still
be complete. An allocation failure before append has the same effect. Redirect stdout
to `NUL` to disable the tail and keep only the file. If a console tail falls behind for more than about a second, UHH prints a one-time
warning suggesting a redirect to a file or pipe. Every flush (`probe_wait_for_exit`,
`probe_report`, `probe_close`) waits for pending file writes or their failure.

```json
{"kind":"probe_log","probe":3,"tid":5124,"message":"read handle=0xa4 pid=7516 name=probe_app.exe addr=0x7ff7fb509690 size=16","seq":0}
{"kind":"probe_log","probe":0,"tid":5124,"message":"write to watched block","stack":["module!function+0x12 (file.c:87) [0x7ff6...]", "..."],"seq":1}
```

`probe` is the probe's index in the order the probes were added (0-based); `tid` is the
target thread that hit it; `seq` numbers the session's records 0, 1, 2, ... in file order
(the same in the file and on stdout), so a gap or a missing tail in a capture is visible
from the capture itself. Every record is exactly one line: newlines and other control
characters in the text or a stack frame are escaped.

### Report (`probe_report`)

```json
{"kind":"prehook","location":"...","address":"0x...","patched_bytes":5,"pattern":"...","destination":"0x...","via":"","live":"...","original":"...","live_disasm":[...],"original_disasm":[...],"suggest":[...]}
{"kind":"probe","location":"ntdll.dll!NtReadVirtualMemory","backend":"inline","active":true,"hits":8000}
{"kind":"probe_report","probes":4,"active":4,"hits":8012,"overrides":1,"log_dropped":0,"callbacks_interrupted":0,"logs_written":8010,"controller_peak_ws_mb":12,"app_exit":0,"live_output_closed":false,"stdout_logs":8010,"live_output_error":null,"error":null}
```

| Field | Meaning |
|---|---|
| `prehook` record | one per probe site that another tool had already modified (live bytes differ from the file on disk); details also on stderr as `probe: PRE-HOOKED SITE ...` |
| `probe.backend` | the effective backend (after `PROBE_FALLBACK_HW`) |
| `probe.active` | armed at report time; false = still pending, refused, or unloaded |
| `probes`, `active`, `hits` | totals over the user's probes |
| `overrides` | register changes made by callbacks (`set_reg` with a new value) |
| `log_dropped` | records not in the session file: non-zero only when the controller stopped consuming (it died), ran out of memory for a record, or the file failed (every record after the failure; some may still be on stdout, see `stdout_logs`) |
| `callbacks_interrupted` | inline callbacks cut off by the target process dying before their first log; their hits are counted, their logs never existed (one killed after its first log counts as that log) |
| `logs_written` | records in successfully appended file batches |
| `controller_peak_ws_mb` | the controller's peak working set |
| `app_exit` | the target's exit code (1 if it did not exit, e.g. after a detach) |
| `live_output_closed` | stdout's reader went away; file logging continues |
| `stdout_logs` | `probe_log` records the live tail wrote to stdout before this report (null when stdout is `NUL`: no tail). Equal to `logs_written` unless the tail stopped (`live_output_closed` / `live_output_error`: fewer) or the session file failed (`error` says so; stdout may hold `stdout_logs - logs_written` more) |
| `live_output_error` | a stdout write failed for another reason (also on stderr and in `error`); file logging continues |
| `error` | the session's first error, or null |

A capture of stdout is complete when it ends with the `probe_report`, holds exactly
`stdout_logs` `probe_log` lines and their `seq` runs 0..`stdout_logs`-1 without a gap (recipe:
[troubleshooting.md](troubleshooting.md#is-my-captured-output-complete)). When records follow
the report -- an attach detached by `probe_close` after `probe_report`, as in
`uhh_trace --detach-after-ms` -- `probe_close` ends stdout with
`{"kind":"probe_final","hits":..,"logs_written":..,"log_dropped":..,"in_flight":..,"running":..,"stdout_logs":..}`.

Accounting: hits = logs + `log_dropped` + `callbacks_interrupted` for a callback that logs
once per hit (see [limitations.md](limitations.md#logs-and-accounting) for the edge cases).

## Threading and concurrency

| Topic | Breakpoint / hw | Inline |
|---|---|---|
| Thread a callback runs on | the controller's debugger thread (the one in `probe_run`) | the target thread that hit the probe |
| Overlap | callbacks never overlap; the whole target is stopped during each debug event | callbacks of different target threads run at the same time |
| Static state | plain variables work | must be atomic or locked |
| `thread_local` | one controller thread for all target threads | per target thread |
| Per-thread state | key it by the target tid (`call_func(c, "kernel32.dll!GetCurrentThreadId", &tid, 0)`) | same, to stay portable |
| Re-entrancy | a callback's own Win32 calls run in the controller and hit nothing | a probe hit on the same thread while its callback runs (directly or through `call_func`) is counted, with no callback |

Session functions: call `probe_launch`/`probe_attach` and `probe_run` on one thread.
`probe_close` may come from another thread (it stops `probe_run` and waits for it). Use
`get_session(c)` for control calls from callbacks.

A callback that faults or throws is abandoned on every backend: the hit counts, its
register changes are discarded, `set_mem` writes already made stay, and the program runs
on (after `call_original`, the caller gets `return_from`'s value if one was set, else the
original's result). Breakpoint/hw print `probe: warning: callback for <loc> raised 0x...;
abandoned` once. Inline the exception is raised in the target, so the program's vectored
exception handlers see it first.

## Limits

| Limit | Value |
|---|---|
| Hardware probes (execute + watch) | 4 per session (DR0-DR3) |
| Inline probes | 128 per session |
| Software breakpoints armed at once, in a session that also has inline probes | 65536 |
| Config block | 4 GB (`UINT32_MAX` bytes) |
| Log message | 1023 bytes, then `...[truncated]` |
| Stack snapshot | 32 frames |
| `call_func` arguments | 0..8 |
| `call_original` arguments | 0..16 |
| Inline `call_original` stack copy | 32 x64 stack arguments / 64 x86 slots (256 bytes) |
| `probe_watch` | one aligned dword |

## Per-backend differences

Everything not listed here behaves the same on every backend (checked by the regression
suite's portability matrix).

| Topic | Breakpoint / hw | Inline |
|---|---|---|
| Direct Win32 calls in a callback (`GetCurrentProcessId`, file I/O, allocation...) | act on the controller | act on the target |
| `%s` of a target pointer in `send_log` | not a valid pointer: `[unformattable] ...` (or controller bytes if mapped there too) | prints the string |
| Callback that faults/throws | the target never sees the exception | the target's vectored handlers see the first chance |
| `call_func` callee that raises (even if handled) | abandoned: returns 0 | dispatched in the target: 1 if handled |
| `call_func` cost | ~200 µs x64 / ~290 µs x86 beyond the hit (test VM) | ~2.3 µs including the hit |
| `PROBE_ONCE` | supported | refused |
| Visible to the program | INT3 byte (breakpoint) or DR7 (hw) | hook jump in the code; page protection changes when hooks are written |
| Live from (launch) | the first instruction | the loader breakpoint (before any DLL initialiser) |
| Added cost per hit, x64 / x86 | breakpoint ~77 / ~142 us, hw ~91 / ~151 us | ~0.07 / ~0.14 us, plus ~0.1 / ~0.15 us per `send_log` |

The full per-backend table (threads, side effects, visibility, CET, x86) and the remaining
corner cases are in [limitations.md](limitations.md#per-backend-table).

Developer source navigation: the controller is split across `src/probe/session*.cpp`,
with shared internal declarations in `session_internal.hpp`. The public C API remains
in `include/probe_api.h`; the split does not change it.
