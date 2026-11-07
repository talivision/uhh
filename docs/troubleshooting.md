# Troubleshooting

UHH reports on **stderr**, every line starting with `probe:`. Errors read
`probe: error: <reason>`; the first error of a session is also the report's `"error"`
field. Warnings about `call_original` / `return_from` appear once per probe in the log as a
`uhh warning: ...` record (inline: only there, the agent has no stderr). Below: symptom -> cause -> fix,
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
| `map probe_api_agent.dll exports (Win32=126)` | `probe_api_agent.dll` is not next to the controller executable. Only sessions with inline probes inject it; the controller also loads it itself for breakpoint/hw callbacks with `UHH_SHARED` state | copy the agent DLL from the same build next to the controller |
| `LoadLibraryW failed for probe_api_agent.dll: ...` | the target refused to load the agent (e.g. a process that only admits signed DLLs) | inline probes are unavailable in that process: use breakpoint/hw |
| `probe: warning: controller-death guard unavailable (<reason>): breakpoint/hw probes armed without it` | attach with inline probes: the agent did not start within 5 s, so the breakpoint/hw probes beside them armed without waiting longer | the session works; if the controller dies the target may die at its next hit. Use `probe_close` / Ctrl+C to end it |
| `probe_agent_init failed (code=...)` | the agent could not initialise in the target (`0x2`: version mismatch, see Build) | rebuild; look on stderr for a `probe: <time> agent thread exception ...` line that says where it faulted |
| `no new <image> appeared` | `probe_attach_new` timed out; processes already running are ignored | start the target after the `probe: waiting for a new <image>` line |
| `probe_run must be called on the thread that called probe_launch/probe_attach` | Windows binds the debug object to that thread | call launch/attach and `probe_run` on the same thread; `probe_close` may come from another |
| `create temporary log directory (Win32=...)` / `create probe log file` | `%TEMP%` not writable | point `TEMP` at a writable directory |
| `probe: warning: could not make a per-session copy of the agent DLL; UHH_SHARED state is shared with other sessions using the same file` | the per-session copy under `%TEMP%\uhh\<pid>-<tick>-<n>` could not be made | free space / permissions in `%TEMP%`; until then do not run two sessions with `UHH_SHARED` callbacks at once |
| `probe: agent init thread ended by the target before it returned (...)` | the target ended (ExitProcess / TerminateProcess) while the agent was initialising | none: not an error, the target's end is the outcome (`app_exit` in the report) |

## Adding probes

| Message | Cause | Fix |
|---|---|---|
| `location must be module+0xRVA or module!Export[+0xOFF]`, `symbol offset must be +0xHEX`, `location has an invalid RVA` | location syntax | see [api.md](api.md#locations) |
| `probe callback is null`, `non-empty probe config is null`, `probe config is larger than 4 GB` | bad arguments | - |
| `session already exited` | a probe added after the target exited | - |
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
| `probe_watch takes PROBE_WATCH_WRITE/RW and PROBE_ONCE only` | another flag (e.g. `PROBE_BREAKPOINT`) passed to `probe_watch` | pass only those (`PROBE_HW` is accepted and implied) |
| `probe: dynamic add failed: <reason>` / `probe: dynamic add from inline callback: ...` | an add from a callback was refused; the callback got 0 | fix the reason; the session continues |
| `probe: runtime probe <loc> failed to arm: <reason>` | a probe added from a callback could not be armed when its module loaded | same reasons as below; that probe is dropped |

## A probe does not fire

| Symptom | Cause | Fix |
|---|---|---|
| Probe stays `pending`, report `"active":false`, `hits` 0 | the module never loaded under that file name. A module name **without extension** means `<name>.dll` (`kernel32!X` == `kernel32.dll!X`), so `app!Func` does not match `app.exe` (stderr warns: `probe: warning: app!Func names app.dll ...`) | name an EXE with its extension (`app.exe!Func`); check the module really loads (`probe: pending` but no `active`) |
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
| Inline probe misses early calls; maps show `pid=0` / `key=?` for early handles | on launch inline goes live at the loader breakpoint (the loader's own work before it is not seen); on attach at its `active` line | breakpoint/hw for the loader's own activity ([limitations.md](limitations.md#coverage-and-timing)) |
| hw probe never fires under Intel SDE | execute debug registers do not match SDE's code cache | expected; see [limitations.md](limitations.md#cet-shadow-stacks) |

## During the run

| Symptom | Cause | Fix |
|---|---|---|
| `probe: warning: callback for <loc> raised 0x...; abandoned (hit counted, no register changes applied)` | the callback faulted or threw (often: dereferencing a target pointer on breakpoint/hw) | read target memory with `get_mem`; inline the program's vectored handlers saw the exception too |
| Log text `[unformattable] <format>` | `%s` of a target pointer in a breakpoint/hw callback, `%n`, or a faulting argument | `get_mem` strings into a local buffer first ([limitations.md](limitations.md#formatting-target-strings)) |
| `uhh warning: call_original refused: not at a function entry ([SP] is no return address)` | the probe is not on the function's first instruction (or after a `push`) | probe the entry; the original has not run, let the hit fall through |
| `uhh warning: call_original refused: needs one free debug register (all 4 in use)` | breakpoint/hw `call_original` needs a debug register for the call | at most 3 hw probes, or put the probe itself on hw (it lends its own slot), or inline |
| `call_original refused: nargs must be 0..16` | `nargs` out of range | - |
| `call_original without return_from -- the original runs again on fall-through` | the callback called the original but did not `return_from` | add `return_from(c, ret, nargs)` |
| `return_from nargs=N but the original popped M bytes (ret M); the original's count is used` | wrong x86 `nargs` for the convention | pass the stack slots the callee pops ([api.md](api.md#callback-functions)) |
| `probe: warning: <loc>: the original did not return within 5 s (released, it runs on)` / `... left without returning (exception or longjmp)` / `... the thread exited inside the original` | breakpoint/hw `call_original` ended abnormally; the rest of the callback did not run | expected for blocking, throwing or exiting functions |
| `call_func` returns 0 | unknown module/export, `nargs` outside 0..8, address not executable code; on breakpoint/hw also: the callee raised an exception, or the 5 s timeout (`probe: call_func timed out after 5 s; thread restored`) | pass every argument as `uint64_t`; call only non-blocking, non-throwing callees; cache results |
| `probe: warning: <loc>: call_func refused: the thread's stack is nearly exhausted (...)` | breakpoint/hw: the callee's frame would come within the last pages of the thread's stack reservation | none needed for the program (it is unaffected); call from a site with more stack left, or inline |
| `probe: warning: <loc>: call_original without return_from under CET shadow stacks: the original's result is returned (it cannot run twice)` | breakpoint/hw, CET target: the fall-through re-run cannot happen | add `return_from(c, ret, nargs)` |
| `probe: warning: <loc>: the program uses DRn itself on thread N and no debug register is free: the probe yields there ...` | the target uses debug registers itself; UHH never takes the target's slot | fewer hw probes, or breakpoint/inline for that site |
| `probe: logs are being written to a console, which is slowing the target; ...` | the live tail to a console is slow | redirect stdout to a file or pipe (or `NUL`: the file keeps everything) |
| `probe: warning: live output closed (Win32=...)` | stdout's reader went away (`| head`) | not an error; the session file has every record (`"live_output_closed":true`) |
| `probe: <time> target crashed: tid=N exception 0x... at module+0x...` plus a stack | the target died of an unhandled exception | compare with an uninstrumented run; check `set_reg`/`set_mem`/`return_from` in your callbacks; try another backend |
| `probe: warning: in-place step on thread N not done within 2 s: ...` | the program suspended a thread while UHH stepped it in place | a call through that site may have been missed |
| The target runs very slowly, threads starve | breakpoint/hw stop the whole process at every hit | inline for hot paths; filter |
| Hits higher than the calls you expected | every caller of a system export is seen, and some APIs re-enter themselves | filter in the callback ([limitations.md](limitations.md#coverage-and-timing)) |
| The target behaves differently under UHH | it is debugged under every backend (anti-debug checks, no unhandled-exception filter), or checks its code against disk | expected; see [limitations.md](limitations.md#visibility-to-the-target-anti-debug) |
| The tool exits 1 but `"error":null` | `probe_wait_for_exit` returns 0 when the target's exit code is not 0 | check `app_exit` in the report |
| `log_dropped` > 0 | the controller stopped consuming (it died), or the session file failed: `probe: error: write probe log file (Win32=N); the session log file is incomplete: it holds records seq 0..K (logs_written); every later record is counted in log_dropped, those that reached stdout too (stdout_logs - logs_written of them)` | check disk space in `%TEMP%\uhh\logs`; a stdout capture may still be complete (`stdout_logs` records, `seq` without gap) |
| `callbacks_interrupted` > 0 | the target died (ExitProcess / TerminateProcess) while inline callbacks ran | expected at process exit; their hits are counted. stderr names each one: `probe: callbacks interrupted by the target's end: N cut off while running: <probe> (tid T); unexplained=0` (`unexplained` > 0 would be an accounting fault: report it) |

Informational lines (no action needed): `probe: <loc> -> hardware fallback (...)`,
`probe: <loc> is forwarded -> ...`, `probe: <loc> resolved from symbols -> ...`,
`probe: holding thread N until inline installs confirm`, `probe: released N held thread(s)
(...)`, `probe: <loc> unloaded with its module; pending until it loads again`,
`probe: <loc> retired: its module unloaded` (absolute-address probes),
`probe: <loc> was re-hooked by another tool that relocated our breakpoint to 0x...;
following it there`, `probe: repaired hardware breakpoint state on thread N`,
`probe: warning: thread N was killed while writing a log record; ...`,
`probe: detach: N thread(s) frozen; all clean`, `probe: detached from pid N`.

## Detach, Ctrl+C and close

| Message | Meaning | Action |
|---|---|---|
| `probe: interrupted: detaching (probes removed, the target keeps running)` / `... ending the target` | Ctrl+C / Ctrl+Break ended the session | a second press ends the tool itself |
| `probe: detach: N callback(s) still running; delivering their logs (up to 15 s)` | inline callbacks are still running; detach delivers their logs first, for at most 15 s | none; see the next lines |
| `probe: detach: N callback(s) still running after 15 s; not waiting longer (...)` | callbacks did not finish within the bound; the detach completes without them | any log they write from now on is lost; they are counted as `running=` (and `in_flight=` if they had not logged yet). Find what they are blocked on (a lock, a wait) |
| `probe: detach: N callback(s) cannot finish now (thread gone or suspended); not waiting for them` | callbacks on dead or suspended threads | none; they appear as `running=` (and, if they had not logged yet, `in_flight=`) |
| `probe: detached: hits=.. logs_written=.. log_dropped=.. in_flight=.. running=..` | final counts after the detach | hits = logs_written + log_dropped + in_flight (in_flight: callbacks still running that had not logged yet; running: all still running -- any log they write after the detach is lost) |
| `probe: detach: agent work still pending after 5 s; it will install nothing` | the agent's thread could not start (the target holds its loader lock) | none; nothing is installed after the detach |
| `probe: detach: N config block(s) left in the target for M callback(s) still in flight` | a deliberate, bounded leak so in-flight callbacks never read freed config | none |
| `probe: close: still waiting for probe_run to stop (Ns; it is <phase>)` | `probe_close` from another thread waits for `probe_run` to finish (the phase: detaching, draining the log ring, in the debug loop, ending the session) | wait; see the detach lines |
| `probe: ended: the target exited before the detach (exit code N): hits=.. logs_written=.. log_dropped=.. in_flight=..` | `probe_close` asked for a detach, but the target ended first | none; these are the final counts (`in_flight`: callbacks the target's end interrupted) |
| `probe: session failed (<reason>): detaching from the target` | an internal error ended an attached session; the target was released cleanly | fix `<reason>` |

## Is my captured output complete?

A capture of stdout proves its own completeness; never judge it by how its end looks.

- Every `probe_log` record is exactly one line and carries `"seq"`: 0, 1, 2, ... in the
  order of the session file. A gap is a lost record, a repeat a duplicate.
- The `probe_report` line comes after the last record and states `stdout_logs` (records
  written to stdout), `logs_written` (records in the session file), `log_dropped`,
  `live_output_closed` and `live_output_error`. When records follow the report (an attach
  detached by `probe_close` after `probe_report`, e.g. `uhh_trace --detach-after-ms`), the
  capture ends with a `probe_final` line with the final counts instead.
- **No `probe_report` (or `probe_final`) line at the end = the capture is incomplete**,
  whatever the last records look like: the tool was killed, or the consumer stopped reading.
  The session file (`probe: logs -> ...` on stderr) has every record that was written.

Check a capture (streams the file; any encoding PowerShell wrote) with:

```powershell
$n = 0; $gap = $null; $last = $null
foreach ($l in [IO.File]::ReadLines((Resolve-Path out.txt))) {
  if ($l.StartsWith('{"kind":"probe_log"')) {
    if ($l -notmatch ',"seq":(\d+)\}$' -or [uint64]$Matches[1] -ne $n) { if ($gap -eq $null) { $gap = $n } }
    $n++
  } elseif ($l.StartsWith('{"kind":"probe_report"') -or $l.StartsWith('{"kind":"probe_final"')) { $last = $l | ConvertFrom-Json }
}
if ($last -and $gap -eq $null -and $last.stdout_logs -eq $n) { "complete: $n records" }
else { "INCOMPLETE: $n records, first gap at seq $gap, last report says stdout_logs=$($last.stdout_logs)" }
```

### Capturing from PowerShell

Measured with Windows PowerShell 5.1 (regress `stdout-powershell-*`, ROADMAP "PowerShell
capture findings"): `| Out-File`, `>`, `| Set-Content`, `| Tee-Object`, `| ForEach-Object`,
`2>&1 | Out-File`, `Start-Process -RedirectStandardOutput` and the console itself deliver every
record, byte for byte, at any volume (1.2M stack records tested). What does lose the end:

| Symptom | Cause | Fix |
|---|---|---|
| The capture stops short and has no `probe_report`; stderr has no `probe: interrupted` line | **Ctrl+C while UHH runs inside a PowerShell pipeline** (`... \| Out-File`, `> file`, `\| Tee-Object`, `Start-Process -Wait`): PowerShell stops reading and terminates the native command at once, so UHH's own Ctrl+C handling (end the session, flush, report) never runs. A non-UHH program shows the same: its last lines and its final line never reach the file. The session file keeps what UHH wrote until it was killed (measured: a few hundred records more than the capture) | stop with Ctrl+C only when stdout is the console or redirected by cmd: `cmd /c "uhh_trace ... > out.jsonl"`; or end the target instead (close it, `--detach-after-ms`) |
| Non-ASCII text (paths, symbols) garbled in a PowerShell capture | PowerShell decodes a native command's output with `[Console]::OutputEncoding` (the OEM code page), then re-encodes it (UTF-16 for `>` / `Out-File` in 5.1) | `[Console]::OutputEncoding = [Text.UTF8Encoding]::new()` first, or capture with `cmd /c ... > file` (bytes untouched) |
| The capture is much slower than the run without it | PowerShell handles every line as an object (1.2M stack records: `cmd /c >` 19 s, `>` 46 s, `Out-File` 110 s); UHH back-pressures the target instead of dropping | `cmd /c "... > file"`, or stdout to `NUL` and read the session file |
| The console shows fewer records than the session file (high volume), `stdout_logs == logs_written` | not lost by UHH: every record was written to the console. A console keeps only a finite history (9001 rows by default; a `--stack` record takes several rows), a pseudo console (Windows Terminal, ssh) renders frames: a program writing faster than it renders loses lines on screen (reproduced with WriteConsoleW; UHH writes with WriteFile and was complete at 2M records). A run stopped with Ctrl+C inside a PowerShell pipeline also ends short (row above) | the session file (`probe: logs -> ...`) is the archive: read it, or capture stdout to a file with `cmd /c "... > out.jsonl"`; never judge completeness from the screen |
| `2>&1` puts `uhh_trace.exe : probe: ...` blocks between the records | PowerShell 5.1 wraps each stderr line in an error record | do not merge stderr (`2> err.txt`), or ignore lines that do not start with `{` |

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
