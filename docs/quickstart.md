# Quickstart

This page builds UHH, runs the flagship example (`gated_config`) by launch and by attach,
and then walks through a minimal tool of your own. For the full API see [api.md](api.md);
for what UHH does not do, [limitations.md](limitations.md); when something fails,
[troubleshooting.md](troubleshooting.md).

## 1. Build

Requirements: Windows (x64), Visual Studio 2022 with the C++ workload (MSVC + MASM) and
CMake 3.28 or later. No network access is needed: SafetyHook and Zydis are vendored in
`third_party/`.

```bat
:: x64
cmake -S . -B build-x64 -G "Visual Studio 17 2022" -A x64
cmake --build build-x64 --config Release

:: x86 (32-bit)
cmake -S . -B build-x86 -G "Visual Studio 17 2022" -A Win32
cmake --build build-x86 --config Release
```

Every binary lands in `build-x64\Release` (or `build-x86\Release`): the drivers
(`gated_config.exe`, `uhh_attach.exe`, `uhh_trace.exe`, ...), the example targets
(`probe_app.exe`, `configparse.dll`, ...) and `probe_api_agent.dll`, the DLL UHH injects
into the target for inline probes.

Rules that follow from how UHH works:

- The controller (your driver) and the target must have the **same bitness**. Use the x64
  build for 64-bit targets and the x86 build for 32-bit (WOW64) targets.
- `probe_api_agent.dll` must sit **next to the controller executable**. It is needed (and
  injected into the target) only for inline probes, and loaded by the controller itself for
  breakpoint/hw callbacks that use `UHH_SHARED` state.
- Rebuild the agent DLL and the drivers together. A driver and an agent built from
  different versions of the agent protocol fail with `probe_agent_init failed (code=0x2)`.

`scripts\build.ps1` is a faster (Ninja) alternative; see the README.

## 2. The flagship example: `gated_config`

`probe_app` (in `examples/targets/probe_app`) ships a feature **disabled in its config**.
After its gate it late-loads `configparse.dll`, parses `reads_enabled=0`, and does nothing
more. Only when the parsed flag is 1 does it open its helper processes
(`ntdll!NtOpenProcess`) and read their memory from several threads
(`ntdll!NtReadVirtualMemory`).

`gated_config` turns the feature on **from outside**, without changing the target or its
config, and logs what the enabled path does:

| Probe | Default backend | Callback | Effect |
|---|---|---|---|
| `configparse.dll!ParseConfig+0x16` | breakpoint | `enable_reads` | the parsed flag is in EAX: 0 -> 1 |
| `ntdll.dll!NtOpenProcess` | = read backend | `track_open_process` | runs the open (`call_original`), maps handle -> pid -> name, returns the real status (`return_from`) |
| `ntdll.dll!NtClose` | = open backend (breakpoint if that is hw) | `forget_closed_handle` | forgets a closed handle |
| `ntdll.dll!NtReadVirtualMemory` | inline | `log_read` | logs every read with its handle, pid and name |

The config stays disabled. That is the point of the technique: it is how you get metrics
on a code path that normally never runs. Do not "simplify" it by enabling the feature in
the config.

### 2.1 Without UHH (baseline)

```bat
cd build-x64\Release
probe_app.exe --no-wait --threads 4 --reads 200
```

The last line reports `"reads_enabled":0,"opened":0,...,"successful_reads":0`: the
feature is off.

### 2.2 Launch under UHH

```bat
gated_config.exe configparse.dll!ParseConfig+0x16 ntdll.dll!NtReadVirtualMemory -- probe_app.exe --no-wait --threads 4 --reads 200 > run.jsonl
```

Without `--no-wait`, `probe_app` waits for a key press (UHH passes the console's stdin
through). Redirecting stdout to a file is optional but faster: logs written to a console
slow the target, and UHH warns about it once.

Options (from `examples/gated_config/main.cpp`): `--flag-backend b` (default breakpoint),
`--read-backend b` (default inline), `--open-backend b` (default: the read backend),
`--close-backend b` (default: the open backend, breakpoint if that is hw), with `b` =
`breakpoint`, `hw` or `inline`; `--no-log` (count hits only), `--pid P` (log only reads of
that process), `--range BASE:SIZE` (repeatable, up to 8).

**stderr** shows the session's progress (captured on x64; pids, tids and addresses vary):

```text
probe: pending configparse.dll!ParseConfig+0x16
probe: pending ntdll.dll!NtOpenProcess
probe: pending ntdll.dll!NtClose
probe: pending ntdll.dll!NtReadVirtualMemory
probe: logs -> C:\Users\admin\AppData\Local\Temp\uhh\logs\uhh-24300-0.jsonl
probe: symbols via C:\Windows\system32\dbghelp.dll
probe: resolved ntdll.dll!NtOpenProcess -> base=0x7ffce01f0000 addr=0x7ffce028da50 (awaiting agent)
probe: resolved ntdll.dll!NtClose -> base=0x7ffce01f0000 addr=0x7ffce028d770 (awaiting agent)
probe: resolved ntdll.dll!NtReadVirtualMemory -> base=0x7ffce01f0000 addr=0x7ffce028dd70 (awaiting agent)
probe: active ntdll.dll!NtOpenProcess -> addr=0x7ffce028da50 (inline)
probe: active ntdll.dll!NtClose -> addr=0x7ffce028d770 (inline)
probe: active ntdll.dll!NtReadVirtualMemory -> addr=0x7ffce028dd70 (inline)
probe: holding thread 21100 until inline installs confirm
probe: released 1 held thread(s) (inline installs confirmed)
probe: active configparse.dll!ParseConfig+0x16 -> base=0x7ffcd5990000 addr=0x7ffcd5991116 (was 0x89, len=2, displaced)
```

The flag probe stays `pending` until `probe_app` loads `configparse.dll`; it arms at that
load. Inline probes become `active` once the injected agent confirms each hook (on a launch
at the loader breakpoint, before any DLL initialiser runs); the main thread is then held at
the entry point until the agent's service thread is up.

**stdout** (`run.jsonl`) holds the target's own lines and the `probe_log` records,
interleaved as they reach UHH (inline records travel through a ring the controller drains,
so the target's `app` line can arrive before the last `read` logs), then the report written
by `probe_report` (captured on x64, 823 lines, trimmed):

```text
{"kind":"helper","index":0,"pid":18388,"base":140696029979200,"size":256}
...
{"kind":"waiting","pid":12124,"helpers":4}
...
{"kind":"probe_log","probe":1,"tid":21100,"message":"open pid=18388 name=probe_app.exe","seq":0}
{"kind":"probe_log","probe":1,"tid":21100,"message":"map handle=0xf0 -> pid=18388 name=probe_app.exe","seq":1}
...
{"kind":"probe_log","probe":3,"tid":3744,"message":"read handle=0xf0 pid=18388 name=probe_app.exe addr=0x7ff658e362c0 size=16","seq":8}
...
{"kind":"app","reads_enabled":1,"helpers":4,"opened":4,"threads":4,"reads_per_thread":200,"successful_reads":800,"checksum":76800,"elapsed_ns":2015200,"prehook":false,"prehook_calls":0,"configparse_base":140723892060160,"shadow_stack":false,"rounds":1}
...
{"kind":"probe","location":"configparse.dll!ParseConfig+0x16","backend":"breakpoint","active":true,"hits":1}
{"kind":"probe","location":"ntdll.dll!NtOpenProcess","backend":"inline","active":true,"hits":4}
{"kind":"probe","location":"ntdll.dll!NtClose","backend":"inline","active":true,"hits":77}
{"kind":"probe","location":"ntdll.dll!NtReadVirtualMemory","backend":"inline","active":true,"hits":800}
{"kind":"probe_report","probes":4,"active":4,"hits":882,"overrides":1,"log_dropped":0,"callbacks_interrupted":0,"logs_written":808,"controller_peak_ws_mb":23,"app_exit":0,"live_output_closed":false,"stdout_logs":808,"live_output_error":null,"error":null}
```

What to check:

- `"reads_enabled":1` in the target's `app` line: the flag was flipped.
- `"overrides":1`: one register change (the flag), counted by the library.
- `NtReadVirtualMemory` `hits` = threads x reads (here 4 x 200 = 800), one `read` log each
  (`logs_written` 808 = 800 reads + 4 `open` + 4 `map` logs; `NtClose` hits vary from run
  to run: every handle the process closes is seen).
- `"log_dropped":0` and `"error":null`.
- `"stdout_logs"` equal to `logs_written`, and `"seq"` running 0..807 without a gap: the capture
  is complete ([troubleshooting.md](troubleshooting.md#is-my-captured-output-complete)).
- The `"probe"` field of a log is the probe's index in the order it was added
  (0 = the flag probe, 1 = NtOpenProcess, 2 = NtClose, 3 = NtReadVirtualMemory).

Try other backends without touching the callbacks:

```bat
gated_config.exe --flag-backend hw --read-backend breakpoint configparse.dll!ParseConfig+0x16 ntdll.dll!NtReadVirtualMemory -- probe_app.exe --no-wait --threads 4 --reads 200
```

The same callback source runs under every backend. The handle -> pid map is `UHH_SHARED`,
so the open and read probes may use different backends.

The x86 build works the same way from `build-x86\Release` (`ParseConfig+0x16` is the same
offset on both architectures).

### 2.3 Attach to a running target: `uhh_attach`

Same target, same callbacks, but UHH attaches to a process that is already running.
Use two consoles in the build directory.

1. Console A: start the target. It prints its helpers and waits for a key.

   ```text
   > probe_app.exe --helpers 4 --threads 8 --reads 1000
   {"kind":"helper","index":0,"pid":18896,"base":140696029979200,"size":256}
   {"kind":"helper","index":1,"pid":8276,"base":140696029979200,"size":256}
   {"kind":"helper","index":2,"pid":23884,"base":140696029979200,"size":256}
   {"kind":"helper","index":3,"pid":7912,"base":140696029979200,"size":256}
   {"kind":"waiting","pid":10932,"helpers":4}
   ```

2. Console B: attach. This logs only the reads of helper 1 at offset 64 of its buffer
   (`base + 64`, 64 bytes long):

   ```text
   > uhh_attach.exe 10932 --pid 8276 --range 140696029979264:64 --backend inline
   {"kind":"attached","pid":10932}
   ```

   Wait for the `probe: active ntdll.dll!NtOpenProcess ...` and
   `probe: active ntdll.dll!NtReadVirtualMemory ...` lines on stderr. The flag probe stays
   pending: `configparse.dll` is not loaded yet.

3. Console A: press a key. `probe_app` loads `configparse.dll`, the breakpoint flips the
   flag, and the reads run.

4. Console B prints the `open`/`map` logs and the matching `read` logs, then the report,
   and exits when the target exits (captured on x64, trimmed):

   ```text
   {"kind":"probe_log","probe":1,"tid":17572,"message":"open pid=18896 name=probe_app.exe","seq":0}
   {"kind":"probe_log","probe":1,"tid":17572,"message":"map handle=0x11c -> pid=18896 name=probe_app.exe","seq":1}
   ...
   {"kind":"probe_log","probe":3,"tid":15936,"message":"read handle=0x110 pid=8276 name=probe_app.exe addr=0x7ff658e36280 size=16","seq":8}
   ...
   {"kind":"probe","location":"configparse.dll!ParseConfig+0x16","backend":"breakpoint","active":true,"hits":1}
   {"kind":"probe","location":"ntdll.dll!NtOpenProcess","backend":"inline","active":true,"hits":4}
   {"kind":"probe","location":"ntdll.dll!NtClose","backend":"inline","active":true,"hits":44}
   {"kind":"probe","location":"ntdll.dll!NtReadVirtualMemory","backend":"inline","active":true,"hits":8000}
   {"kind":"probe_report","probes":4,"active":4,"hits":8049,"overrides":1,"log_dropped":0,"callbacks_interrupted":0,"logs_written":508,"controller_peak_ws_mb":22,"app_exit":0,"live_output_closed":false,"stdout_logs":508,"live_output_error":null,"error":null}
   ```

   Expected: `"overrides":1`, `NtReadVirtualMemory` `hits` = 8 x 1000 = 8000 (every
   read is seen), and exactly 500 logged reads (helper 1 at offset 64 gets every 16th read;
   `logs_written` 508 = 500 reads + 4 `open` + 4 `map`).

Usage: `uhh_attach <target_pid> [--pid P] [--range BASE:SIZE] [--backend b] [--flag-backend b] [--open-backend b] [--close-backend b] [--read-backend b]`
(`--backend` sets open and read, default breakpoint; close defaults to the open backend,
breakpoint if that is hw; the flag probe defaults to breakpoint).
See [examples/attach/README.md](../examples/attach/README.md) for the derivation of the
500.

If the controller ends while the target still runs (Ctrl+C, or `probe_close` from another
thread), UHH **detaches**: hooks removed, breakpoints restored, debug registers cleared,
and the target keeps running.

## 3. Tracing any export: `uhh_trace`

`uhh_trace` (examples/trace) logs calls to any function without writing code. One format
character per argument: `x` hex, `d` signed, `s` ANSI string, `W` wide string,
`S` sockaddr, `O` OBJECT_ATTRIBUTES name, `-` skip; `:-` counts hits without logging.

```bat
uhh_trace --backend inline -p "KernelBase.dll!CreateFileW:Wxx" -- program.exe [args]
uhh_trace --backend hw --stack -p "ntdll.dll!NtCreateFile:xxO" --attach 1234
uhh_trace --list kernelbase.dll --mask *CreateFile*
```

The program after `--` is started as given: it is **not** searched on `PATH`, so name a
system program by its path (`-- C:\Windows\System32\cmd.exe /c ...`; plain `cmd.exe` fails
with `probe: error: debug launch (Win32=2)`). Module names in `-p` follow the
[location grammar](api.md#locations): `kernel32!X` is `kernel32.dll!X`, and the program
itself is named with its extension (`app.exe!Func`).

Other options: `--attach <pid> [--detach-after-ms N | --detach-on-stdin]` (detach after N ms
or a line on stdin; the target runs on), `--attach-new <image> [--timeout ms]`,
`--fallback-hw`, `--allow-unsafe-site`, `--allow-prehooked`, `--unsafe-fast-patch` (see the
flags in [api.md](api.md#probe-flags)). The default backend is `breakpoint`. `--list` takes
exactly `--list <module> [--mask <pattern>]`.

## 4. Your own tool

A tool has two parts, laid out like every example (`gated_config`, `filetrace`,
`flagflip`, `regtrace`):

- **callbacks**: `extern "C" __declspec(dllexport)` functions. They are compiled into your
  driver (breakpoint/hw callbacks run in the controller) **and** into
  `probe_api_agent.dll` (inline callbacks run inside the target, where the agent finds
  them by export name).
- **driver** (`main.cpp`): creates a session, adds probes, launches or attaches, runs,
  reports and closes.

The minimal tool below keeps the flagship technique: the config stays disabled, a probe
turns the feature on, and a second probe logs the reads. It is a real example, built with
the others: [`examples/quickstart/`](../examples/quickstart) (target `my_tool`; the regress
check `quickstart-my-tool` runs it). The code below is those files, verbatim.
The callback bodies are those of `examples/gated_config/callbacks.cpp` (`enable_reads`,
and `log_read` without the handle map and filters); the driver is
`examples/gated_config/main.cpp` without its option parsing. The names carry a `my_`
prefix because the agent DLL already exports `enable_reads` and `log_read` from
gated_config: export names must be unique in the agent.

`examples/quickstart/my_callbacks.h`:

```cpp
#pragma once
#include "probe_api.h"

extern "C" {
/* configparse.dll!ParseConfig+0x16: the parsed flag is in EAX; 0 -> 1. */
__declspec(dllexport) void my_enable_reads(probe_context *);
/* ntdll!NtReadVirtualMemory entry: log handle/address/size. */
__declspec(dllexport) void my_log_read(probe_context *);
}
```

`examples/quickstart/my_callbacks.cpp`:

```cpp
#include "my_callbacks.h"

// Turn the disabled feature on. The library counts the register change in the
// report's "overrides" field.
extern "C" void my_enable_reads(probe_context *c) {
    if (get_reg(c, PROBE_REG_AX) == 0) set_reg(c, PROBE_REG_AX, 1);
}

// NtReadVirtualMemory(handle, address, buffer, size, done): arguments 0, 1 and 3.
extern "C" void my_log_read(probe_context *c) {
    uint64_t handle = get_func_arg(c, 0), addr = get_func_arg(c, 1), size = get_func_arg(c, 3);
    send_log(c, "read handle=0x%llx addr=0x%llx size=%llu", (unsigned long long)handle,
             (unsigned long long)addr, (unsigned long long)size);
}
```

`examples/quickstart/main.cpp`:

```cpp
#include "my_callbacks.h"
#include <cstdio>

int main(int argc, char **argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: my_tool <target.exe> [args]\n");
        return 2;
    }
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol(s, "configparse.dll!ParseConfig+0x16", my_enable_reads, PROBE_BREAKPOINT) &&
             probe_add_symbol(s, "ntdll.dll!NtReadVirtualMemory", my_log_read, PROBE_INLINE) &&
             probe_launch(s, argv + 1) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);   // "overrides" = how many times the flag was flipped
    probe_close(s);
    return ok ? 0 : 1;
}
```

`argv + 1` works because `argv` is NULL-terminated, which is what `probe_launch` expects.

The tool in `CMakeLists.txt`, next to the other examples:

```cmake
add_executable(my_tool examples/quickstart/main.cpp examples/quickstart/my_callbacks.cpp)
target_include_directories(my_tool PRIVATE include)
target_link_libraries(my_tool PRIVATE probe_api)
add_dependencies(my_tool probe_api_agent probe_app configparse)
```

and `examples/quickstart/my_callbacks.cpp` is in the source list of
`add_library(probe_api_agent SHARED ...)` in the same file. Without that, the inline probe
fails to install (`inline agent failed to install ntdll.dll!NtReadVirtualMemory
(status=-2)`, and the session ends): the agent cannot find `my_log_read`. For a tool of
your own, copy the directory, rename the target and the exports, and add the same lines.

Build and run (from the repository root):

```bat
cmake --build build-x64 --config Release --target my_tool
build-x64\Release\my_tool.exe build-x64\Release\probe_app.exe --no-wait --threads 4 --reads 200
```

stderr (captured on x64):

```text
probe: pending configparse.dll!ParseConfig+0x16
probe: pending ntdll.dll!NtReadVirtualMemory
probe: logs -> C:\Users\admin\AppData\Local\Temp\uhh\logs\uhh-1108-0.jsonl
probe: symbols via C:\Windows\system32\dbghelp.dll
probe: resolved ntdll.dll!NtReadVirtualMemory -> base=0x7ffce01f0000 addr=0x7ffce028dd70 (awaiting agent)
probe: active ntdll.dll!NtReadVirtualMemory -> addr=0x7ffce028dd70 (inline)
probe: holding thread 23880 until inline installs confirm
probe: released 1 held thread(s) (inline installs confirmed)
probe: active configparse.dll!ParseConfig+0x16 -> base=0x7ffcd5990000 addr=0x7ffcd5991116 (was 0x89, len=2, displaced)
```

stdout (813 lines, trimmed):

```text
{"kind":"helper","index":0,"pid":9300,"base":140696029979200,"size":256}
...
{"kind":"waiting","pid":8944,"helpers":4}
...
{"kind":"probe_log","probe":1,"tid":21980,"message":"read handle=0xbc addr=0x7ff658e362c0 size=16","seq":0}
{"kind":"probe_log","probe":1,"tid":6752,"message":"read handle=0xbc addr=0x7ff658e362c0 size=16","seq":1}
...
{"kind":"app","reads_enabled":1,"helpers":4,"opened":4,"threads":4,"reads_per_thread":200,"successful_reads":800,"checksum":76800,"elapsed_ns":1609000,"prehook":false,"prehook_calls":0,"configparse_base":140723892060160,"shadow_stack":false,"rounds":1}
...
{"kind":"probe","location":"configparse.dll!ParseConfig+0x16","backend":"breakpoint","active":true,"hits":1}
{"kind":"probe","location":"ntdll.dll!NtReadVirtualMemory","backend":"inline","active":true,"hits":800}
{"kind":"probe_report","probes":2,"active":2,"hits":801,"overrides":1,"log_dropped":0,"callbacks_interrupted":0,"logs_written":800,"controller_peak_ws_mb":23,"app_exit":0,"live_output_closed":false,"stdout_logs":800,"live_output_error":null,"error":null}
```

Expected: `"reads_enabled":1` in the target's `app` line, one `read ...` log per read
(800 = `logs_written` = the read probe's `hits`), and `"overrides":1` in the report. The
x86 build gives the same counts (`build-x86\Release\...`).

To change a backend, change only the flag in `main.cpp` (`PROBE_BREAKPOINT`, `PROBE_HW` or
`PROBE_INLINE`). The callbacks stay the same.

### Next steps

- Share state between probes (a handle map, counters): see `UHH_SHARED` in
  [api.md](api.md#shared-state-uhh_shared) and `examples/gated_config/callbacks.cpp`.
- Replace or wrap a function: `call_original` / `return_from`, as in
  `examples/filetrace` (`NtCreateFile`, 11 arguments) and `examples/flagflip` (a C++
  virtual method found in its PDB).
- Pass parameters to a callback: `probe_add_symbol_cfg` + `get_config`, as in
  `gated_config`'s `read_log_config`.
- Read a C++ `this`: `get_reg(c, PROBE_REG_CX)` on both architectures, not
  `get_func_arg(c, 0)` (examples/flagflip).
