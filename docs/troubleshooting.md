# Troubleshooting

UHH reports on **stderr**, every line starting with `probe:`. Errors read
`probe: error: <reason>`; the first error of a session is also the report's `"error"`
field. Callback-level warnings about `call_original` / `return_from` additionally appear
once per probe in the log as a `uhh warning: ...` record. Below: symptom -> cause -> fix,
grouped by phase. Background for most items is in [limitations.md](limitations.md).

First steps for any problem:

1. Read stderr from the top: every probe should go `probe: pending <loc>` ->
   `probe: active <loc> ...`. A probe that never prints `active` never fired.
2. Check the report: `"active":false` on a probe, `"error"` not null, `log_dropped` > 0.
3. Run the same tool with another backend (`breakpoint`, `hw`, `inline`). The callbacks do
   not change, so a difference points at a backend limit.
4. For hangs and install problems set `PROBE_TRACE=1` in the controller's environment: it
   echoes every log record on stderr and prints internal events (DLL loads, holds, every
   target thread's stack at an install timeout). It is verbose; use it on a short run.

## Build

| Symptom | Cause | Fix |
|---|---|---|
| `UHH supports x64 and x86 only (ARM64 rejected)` / `UHH requires MSVC` at configure | wrong generator platform or compiler | `-G "Visual Studio 17 2022" -A x64` or `-A Win32` |
| `probe_agent_init failed (code=0x2)` at run time | the controller and `probe_api_agent.dll` come from builds with different agent protocol versions | rebuild everything (`cmake --build build-x64 --config Release`) and run the driver from the same output directory as the agent |
| A library fix "has no effect" | drivers link the static `probe_api` library; building only `probe_api` does not relink them | build the driver target (or everything), not just `probe_api` |
| `... exception 0x... at msvcp140...` with `-- the target's MSVC runtime is older than the one probe_api_agent.dll was built against; rebuild UHH with -DUHH_STATIC_CRT=ON (the default)` | the agent was built with the dynamic CRT and bound to the target's older runtime | configure without `-DUHH_STATIC_CRT=OFF` |
| Your inline callback is not found (`inline agent failed to install <loc> (status=-2)`) | the callback is compiled into your driver but not into `probe_api_agent.dll` | add your callbacks file to the `probe_api_agent` sources in `CMakeLists.txt` (see [quickstart.md](quickstart.md#4-your-own-tool)) |
| Link error: duplicate symbol in `probe_api_agent` | your callback has the same name as an example's (the agent contains every example's callbacks) | give your callbacks unique names |

## Starting a session

| Symptom | Cause | Fix |
|---|---|---|
| `debug launch (Win32=2)` | `argv[0]` not found: it is not searched on `PATH` and needs its extension | pass the full path, e.g. `C:\Windows\System32\findstr.exe` |
| `target is a 32-bit (WOW64) process: use the x86 build of UHH` (or the 64-bit variant) | controller and target bitness differ | use the matching build (`build-x86` / `build-x64`) |
| `open target process (Win32=5)` | access denied (elevated or protected target) | run the controller with at least the target's privileges |
| `attach debugger (Win32=87)` | the process already has a debugger (another UHH session, a debugger) | detach the other one first |
| `map probe_api_agent.dll exports (Win32=126)` | `probe_api_agent.dll` is not next to the controller executable. Every attach injects it (it is the controller-death guard), and so does every launch with inline probes | copy the agent DLL from the same build next to the controller |
| `LoadLibraryW failed for probe_api_agent.dll: ...` | the target refused to load the agent (e.g. a process that only admits signed DLLs) | inline probes are unavailable in that process: use breakpoint/hw |
| `probe: warning: controller-death guard unavailable (<reason>): breakpoint/hw probes armed without it` | attach: the agent could not be loaded or did not start within 5 s | the session works; if the controller dies the target may die at its next hit. Use `probe_close` / Ctrl+C to end it |
| `probe_agent_init failed (code=...)` | the agent could not initialise in the target (`0x2`: version mismatch, see Build) | rebuild; look on stderr for a `probe: <time> agent thread exception ...` line that says where it faulted |
| `no new <image> appeared` | `probe_attach_new` timed out; processes already running are ignored | start the target after the `probe: waiting for a new <image>` line |
| `probe_run must be called on the thread that called probe_launch/probe_attach` | Windows binds the debug object to that thread | call launch/attach and `probe_run` on the same thread; `probe_close` may come from another |
| `create temporary log directory (Win32=...)` / `create probe log file` | `%TEMP%` not writable | point `TEMP` at a writable directory |
| `probe: warning: could not make a per-session copy of the agent DLL; UHH_SHARED state is shared with other sessions using the same file` | the per-session copy under `%TEMP%\uhh` failed | free space / permissions in `%TEMP%`; until then do not run two sessions with `UHH_SHARED` callbacks at once |

## Adding probes

| Message | Cause | Fix |
|---|---|---|
| `location must be module+0xRVA or module!Export[+0xOFF]`, `symbol offset must be +0xHEX`, `location has an invalid RVA` | location syntax | see [api.md](api.md#locations) |
| `unknown probe flags` | a bit not in `enum probe_flags` | - |
| `requested probe type/options are unsupported in this build` | not exactly one backend flag, or an option on the wrong backend: `PROBE_ONCE` with inline, `PROBE_FALLBACK_HW` / `PROBE_ALLOW_*` / `PROBE_UNSAFE_FAST_PATCH` without inline, a watch flag without hw, both watch flags, `PROBE_AT_RETURN` | see the flag table in [api.md](api.md#probe-flags) |
| `too many hardware probes (max 4 DR slots)` | a 5th hw probe (execute and watch count together) | move probes to breakpoint/inline |
| `no free hardware breakpoint slot (max 4)` (at arm time) | the target uses debug registers itself, or slots are still taken | fewer hw probes, or breakpoint |
| `too many inline probes (max 128)` | the 129th inline probe | breakpoint/hw for the rest |
| `inline callback is not a named export` | an inline callback without `__declspec(dllexport)` | export it (`extern "C" __declspec(dllexport)`) |
| `a probe added from a callback needs a callback exported by name (dllexport)` | a static (non-exported) callback passed from inside a callback | export it, in the same module as the calling callback |
| `callback uses UHH_SHARED state but is not a named export ...` / `UHH_SHARED callback '<name>' is not exported by the agent DLL` | a breakpoint/hw callback in a module with `UHH_SHARED` globals runs from the agent DLL, so it must be an export the agent has | export it and add its file to the agent sources |
| `absolute-address probes need a running target` | `probe_add_address` / `probe_watch` before launch | call them from a callback (or after launch) |
| `probe_watch address must be 4-byte aligned (watches one dword)` | unaligned watch address | watch the aligned dword containing it |
| `use probe_watch for data watchpoints` | watch flags passed to `probe_add_address` | use `probe_watch` |
| `probe: dynamic add failed: <reason>` | an add from a callback was refused; the callback got 0 | fix the reason; the session continues |
| `probe: runtime probe <loc> failed to arm: <reason>` | a probe added from a callback could not be armed when its module loaded | same reasons as below; that probe is dropped |

## A probe does not fire

| Symptom | Cause | Fix |
|---|---|---|
| Probe stays `pending`, report `"active":false`, `hits` 0 | the module never loaded under that file name. A module name **without extension** (`kernel32!X`) never matches for probes | write the full file name (`kernel32.dll!CreateFileW`, `app.exe!Func`); check the module really loads (`probe: pending` but no `active`) |
| `export 'X' not found` (the session fails when the module loads) | not exported, and not found in the module's PDB | put the PDB beside the image or set `_NT_SYMBOL_PATH` ([symbols.md](symbols.md)); list names with `uhh_trace --list <module> --mask *X*`; or use `module+0xRVA` |
| `could not decode probe site instruction` | the RVA is not on an instruction boundary | take the RVA from the map/PDB/disassembly |
| `inline probe <loc> refused: N-byte hook would be written across <what> at +0x... Override with PROBE_ALLOW_UNSAFE_SITE.` | the inline site check: code could arrive inside the overwritten bytes | use a suggested offset from `probe: <loc>: inline-safe nearby: ...`, or `PROBE_FALLBACK_HW`, or breakpoint/hw on that site; `PROBE_ALLOW_UNSAFE_SITE` only if you are sure |
| `inline probe <loc> refused: its N-byte hook would overlap the hook of inline probe <other>` | two inline hooks too close (never overridable) | move one, or make one breakpoint/hw |
| `probe: PRE-HOOKED SITE <loc> ...` then `inline probe <loc> is on a pre-hooked site (...)` | another tool already patched the function (live bytes differ from disk) | `PROBE_ALLOW_PREHOOKED` to chain through the foreign hook, or `PROBE_FALLBACK_HW` / `PROBE_HW`; the stderr report lists the pattern and suggestions |
| `pre-hooked INT3 sites are unsupported by this breakpoint backend` | a foreign INT3 at the site | hw |
| `too many software breakpoints armed alongside inline probes (max 65536)` | over 65536 breakpoints in a session with inline probes | fewer breakpoints |
| `probe: warning: inline install not confirmed within 5 s` then `released N held thread(s) (install timeout)` | the agent could not install in time (loader lock held, a stuck thread) | the affected probes stay inactive; rerun with `PROBE_TRACE=1` to see the thread stacks; consider breakpoint/hw |
| `inline agent failed to install <loc> (status=N)` | `-2`: callback not in the agent DLL; `-3`: the hook could not be built; `-1`: bad request | see Build for `-2`; for `-3` try breakpoint/hw |
| `target exited before inline probes were ready` | the target ended before the agent confirmed the hooks | normal for very short programs; use breakpoint/hw |
| Inline probe misses early calls; maps show `pid=0` / `key=?` for early handles | inline goes live at the entry point (launch) or at its `active` line (attach) | breakpoint/hw for loader-time activity ([limitations.md](limitations.md#coverage-and-timing)) |
| hw probe never fires under Intel SDE | execute debug registers do not match SDE's code cache | expected; see [limitations.md](limitations.md#cet-shadow-stacks) |

## During the run

| Symptom | Cause | Fix |
|---|---|---|
| `probe: warning: callback for <loc> raised 0x...; abandoned (hit counted, no register changes applied)` | the callback faulted or threw (often: dereferencing a target pointer on breakpoint/hw) | read target memory with `get_mem`; inline the program's vectored handlers saw the exception too |
| Log text `[unformattable] <format>` | `%s` of a target pointer in a breakpoint/hw callback, `%n`, or a faulting argument | `get_mem` strings into a local buffer first ([limitations.md](limitations.md#formatting-target-strings)) |
| `uhh warning: call_original refused: not at a function entry ([SP] is no return address)` | the probe is not on the function's first instruction (or after a `push`) | probe the entry; the original has not run, let the hit fall through |
| `call_original refused: needs one free debug register (all 4 in use)` | breakpoint/hw `call_original` needs a debug register for the call | at most 3 hw probes, or put the probe itself on hw (it lends its own slot), or inline |
| `call_original refused: nargs must be 0..16` | `nargs` out of range | - |
| `call_original without return_from -- the original runs again on fall-through` | the callback called the original but did not `return_from` | add `return_from(c, ret, nargs)` |
| `return_from nargs=N but the original popped M bytes (ret M); the original's count is used` | wrong x86 `nargs` for the convention | pass the stack slots the callee pops ([api.md](api.md#callback-functions)) |
| `probe: warning: <loc>: the original did not return within 5 s (released, it runs on)` / `... left without returning (exception or longjmp)` / `... the thread exited inside the original` | breakpoint/hw `call_original` ended abnormally; the rest of the callback did not run | expected for blocking, throwing or exiting functions |
| `call_func` returns 0 | unknown module/export, `nargs` outside 0..8, address not executable code; on breakpoint/hw also: the callee raised an exception, another `call_func` was in flight, the 5 s timeout (`probe: call_func timed out after 5 s; thread restored`), or CET (`probe: call_func refused on breakpoint/hw: target has hardware shadow stacks (CET)`) | pass every argument as `uint64_t`; call only lock-free, non-throwing callees; cache results |
| `probe: logs are being written to a console, which is slowing the target; ...` | the live tail to a console is slow | redirect stdout to a file or pipe (or `NUL`: the file keeps everything) |
| `probe: warning: live output closed (Win32=...)` | stdout's reader went away (`| head`) | not an error; the session file has every record (`"live_output_closed":true`) |
| `probe: <time> target crashed: tid=N exception 0x... at module+0x...` plus a stack | the target died of an unhandled exception | compare with an uninstrumented run; check `set_reg`/`set_mem`/`return_from` in your callbacks; try another backend |
| `probe: warning: in-place step on thread N not done within 2 s: ...` | the program suspended a thread while UHH stepped it in place | a call through that site may have been missed |
| The target runs very slowly, threads starve | breakpoint/hw stop the whole process at every hit | inline for hot paths; filter |
| Hits higher than the calls you expected | every caller of a system export is seen, and some APIs re-enter themselves | filter in the callback ([limitations.md](limitations.md#coverage-and-timing)) |
| The target behaves differently under UHH | it is debugged under every backend (anti-debug checks, no unhandled-exception filter), or checks its code against disk | expected; see [limitations.md](limitations.md#visibility-to-the-target-anti-debug) |
| The tool exits 1 but `"error":null` | `probe_wait_for_exit` returns 0 when the target's exit code is not 0 | check `app_exit` in the report |
| `log_dropped` > 0 | the controller stopped consuming (it died, or the log file failed: `probe: error: write probe log file ...`) | check disk space in `%TEMP%\uhh\logs` |
| `callbacks_interrupted` > 0 | the target died (ExitProcess / TerminateProcess) while inline callbacks ran | expected at process exit; their hits are counted |

Informational lines (no action needed): `probe: <loc> -> hardware fallback (...)`,
`probe: <loc> is forwarded -> ...`, `probe: <loc> resolved from symbols -> ...`,
`probe: holding thread N until inline installs confirm`, `probe: released N held thread(s)
(...)`, `probe: <loc> unloaded with its module; pending until it loads again`,
`probe: <loc> retired: its module unloaded` (absolute-address probes),
`probe: <loc> was re-hooked by another tool that relocated our breakpoint to 0x...;
following it there`, `probe: repaired hardware breakpoint state on thread N`,
`probe: warning: thread N was killed while writing a log record; ...`.

## Detach, Ctrl+C and close

| Message | Meaning | Action |
|---|---|---|
| `probe: interrupted: detaching (probes removed, the target keeps running)` / `... ending the target` | Ctrl+C / Ctrl+Break ended the session | a second press ends the tool itself |
| `probe: detach: still waiting for N running callback(s) to finish (Ns)` | inline callbacks are still running; detach delivers their logs first, with no time limit | find what the callback is blocked on (a lock, a wait); a deadlocked callback keeps the detach waiting |
| `probe: detach: N callback(s) cannot finish now (thread gone or suspended); not waiting for them` | callbacks on dead or suspended threads | none; they appear as `in_flight=` |
| `probe: detached: hits=.. logs_written=.. log_dropped=.. in_flight=..` | final counts after the detach | hits = logs_written + log_dropped + in_flight |
| `probe: detach: agent work still pending after 5 s; it will install nothing` | the agent's thread could not start (the target holds its loader lock) | none; nothing is installed after the detach |
| `probe: detach: N config block(s) left in the target for M callback(s) still in flight` | a deliberate, bounded leak so in-flight callbacks never read freed config | none |
| `probe: close: still waiting for probe_run to stop (Ns)` | `probe_close` from another thread waits for `probe_run` to finish its detach | wait; see the detach lines |
| `probe: session failed (<reason>): detaching from the target` | an internal error ended an attached session; the target was released cleanly | fix `<reason>` |

## Environment

- **Symbols.** `probe: symbols via <path>` names the DbgHelp in use, with
  `(symbol server capable)` when a `symsrv.dll` was found beside it. The System32 DbgHelp
  cannot download symbols; install the Windows SDK's *Debugging Tools for Windows* and set
  `_NT_SYMBOL_PATH` (details in [symbols.md](symbols.md)).
- **Disk.** Session log files stay in `%TEMP%\uhh\logs` after the session; delete old ones.
- **Antivirus.** Real-time scanning (MsMpEng) scans the growing session log file; in a long
  hw run its memory grew from 434 to 498 MB (ROADMAP, "hw load / VM freeze"). On very
  log-heavy runs, consider excluding `%TEMP%\uhh\logs`, or send stdout to a file you can
  exclude.
- **Virtual machines.** On the test VM, an all-hw soak at ~12k hw hits/s froze the guest
  twice, 18-22 minutes into the run; this was traced to the hypervisor, not to UHH (ROADMAP,
  "hw load / VM freeze"). Run long hardware-heavy sessions on bare metal.
