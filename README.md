# UHH — usermode-hook-helper

A Windows user-mode instrumentation library where **one C callback source runs
unchanged under multiple selectable backends, chosen per probe**. Write a probe
once; decide later whether it is delivered by a software breakpoint, a hardware
breakpoint or an inline mid-function hook. Every callback gets the full machine context
and full control — read and write registers and memory, change arguments, flip a return
value, call functions in the target, log.

```c
/* The same callback works on x64 and x86, under any backend. */
void enable_reads(probe_context *c) {            /* parsed flag is in EAX here    */
    if (get_reg(c, PROBE_REG_AX) == 0) set_reg(c, PROBE_REG_AX, 1);
}
void log_read(probe_context *c) {
    const struct read_filter *f = get_config(c);  /* your optional parameters     */
    uint64_t addr = get_func_arg(c, 1);           /* arg 1: reg on x64, stack x86 */
    uint64_t size = get_func_arg(c, 3);           /* arg 3                        */
    if (f && (addr < f->base || addr >= f->base + f->size)) return;
    PROBE_LOG(c, "read addr=0x%llx size=%llu", addr, size);
}

probe_add_symbol(s, "configparse.dll!ParseConfig+0x16", enable_reads, PROBE_BREAKPOINT);  /* software breakpoint */
probe_add_symbol_cfg(s, "ntdll.dll!NtReadVirtualMemory", log_read, PROBE_INLINE, &cfg, len); /* inline mid-hook  */
```

### The API in one screen

Two nouns, two prefixes, and the compiler keeps them apart (both are opaque types):

| Takes | Functions | Meaning |
|---|---|---|
| a **session** | `probe_session_create`, `probe_add_symbol`, `probe_add_symbol_cfg`, `probe_add_address`, `probe_watch`, `probe_launch` / `probe_attach` / `probe_attach_new`, `probe_run`, `probe_wait_for_exit`, `probe_report`, `probe_close` | the instrumentation run (control plane) |
| a **context** `c` | `get_reg`, `set_reg`, `get_func_arg`, `get_mem`, `set_mem`, `get_config`, `send_log`, `send_log_stack`, `call_func`, `call_original`, `return_from`, `get_session` | this one hit (data plane) |

`get_session(c)` is the bridge: **probes can be added from inside any callback** —
breakpoint, hardware or inline (`probe_add_symbol[_cfg]`, `probe_add_address`,
`probe_watch`; the new probe's callback must be exported by the calling callback's module). A breakpoint/hw probe added there
is armed before the target resumes; an inline one holds the calling thread until its hook
is in. From an inline callback (which runs inside the target) the call is forwarded to the
controller synchronously; the callback source does not change.

```c
/* malloc -> watch: probe the allocator, follow the pointer, watch the memory.
   (Callbacks are extern "C" __declspec(dllexport), as in examples/dynwatch.) */
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

**Logs.** `send_log` and `send_log_stack` append `probe_log` JSON lines to a per-session
file under `%TEMP%\uhh\logs` (its path is printed as `probe: logs -> ...`) and to the
controller's stdout. `logs_written` counts file records; `stdout_logs` counts stdout
records. A file-write failure ends the file and counts subsequent records in `log_dropped`,
even if stdout received them. Records are not dropped for speed: when the writer falls behind, the
logging thread waits. Every record carries `"seq"` (0, 1, 2, ...) and the final `probe_report` line
says how many records stdout got (`stdout_logs`), so a capture proves its own completeness.
`send_log_stack` captures raw return addresses at the hit and resolves them to
`module!function+0xoff` (plus `file:line` with PDBs) later, off the hit path. When stdout
is a pipe or a file, a launched target's own output is forwarded a whole line at a time, so
records never land inside one of its lines. Details: [api.md](docs/api.md#output-logs-and-report).

## Backends

| Backend | How | Added cost per hit, x64 / x86 | Modifies code? | Callback runs |
|---|---|---|---|---|
| `PROBE_INLINE` | SafetyHook mid-hook installed by the injected agent DLL | ~0.065 / ~0.134 µs | jump of ≥5 bytes | in the target, on the hit thread |
| `PROBE_HW` | execute debug register (DR0–3), or a data watchpoint | ~92 / ~138 µs | no (≤4 probes) | in the controller |
| `PROBE_BREAKPOINT` | external debugger, INT3 with displaced stepping | ~78 / ~124 µs | 1 byte | in the controller |

(Single thread on the test VM, [bench/BENCHMARKS.md](bench/BENCHMARKS.md); a 1 kHz frame loop measured inline
frames at 1 µs p50, hw ~220 µs and breakpoint ~300 µs: [limitations.md](docs/limitations.md#per-backend-table).)

Inline total costs on that VM: `send_log` ~0.25 / 0.27 µs, `send_log_stack`
~1.5 / 9.0 µs, `call_func` with module pinning ~2.3 / 2.3 µs, and
`call_original` + `return_from` ~0.94 / 1.55 µs (x64 / x86).

All three are **exact under multithreading** (no dropped hits). The software
breakpoint achieves this with **displaced (out-of-line) stepping**: the `INT3` stays armed
while the original instruction runs from a per-site trampoline, so no other thread can
cross the site unobserved and no thread is suspended (except around the few instructions
that must run in place). The hardware breakpoint modifies no probed code at all. Inline is the fastest where the site has room for its jump.

**When probes go live.** On launch, breakpoint and hw probes are armed from the target's
first instruction, inline probes at the loader breakpoint (static imports mapped, before any
DLL initialiser or TLS callback runs). On attach, each probe counts from its
`probe: active` line on stderr. Probes may name a module that is not loaded yet: they stay
pending and arm when it loads. During an inline attach, breakpoint/hw probes on
newly loaded modules arm immediately; those on already loaded modules wait for the agent
guard (up to 5 s). A newly armed trap is unguarded until that guard starts.

Backends are picked **per probe** and interoperate in one session — e.g. a breakpoint on a
config-flag site (fires once) mixed with an inline hook on a hot read path (millions of
hits). Probe locations are `module+0xRVA` or `module!Name[+0xOFF]` (an export, else a symbol
from the module's PDB — beside the image or via `_NT_SYMBOL_PATH` — e.g.
`flagfeature.dll!Feature::IsEnabled`).

## Writing your own tool

Copy an example ([`examples/quickstart`](examples/quickstart) is the smallest; then
[`filetrace`](examples/filetrace), [`flagflip`](examples/flagflip),
[`regtrace`](examples/regtrace), [`gated_config`](examples/gated_config)). The layout is
always the same:

- `callbacks.cpp`: the callbacks, each `extern "C" __declspec(dllexport)`. Build it into
  your driver **and** add it to `probe_api_agent`'s sources in `CMakeLists.txt`. Inline
  callbacks run inside the target from the injected `probe_api_agent.dll`, found by export
  name: a callback missing from the agent fails its install
  (`inline agent failed to install <loc> (status=-2)`).
- State that probes share (a handle -> name map, say) must be `UHH_SHARED` (see
  `probe_api.h`) when the probes may use different backends: breakpoint/hw callbacks run in
  the controller and inline ones in the target, so a plain global exists once in each.
- `main.cpp`: `probe_session_create`, `probe_add_symbol[_cfg]` per probe (a `--backend`
  option per probe is cheap), `probe_launch` (or `probe_attach`), `probe_run`,
  `probe_wait_for_exit`, `probe_report` and `probe_close`.
- Arguments: `get_func_arg(c, i)` is the i-th argument at a function entry. A C++ member
  function on x86 is `__thiscall`, with `this` in ECX and not on the stack;
  `get_reg(c, PROBE_REG_CX)` reads `this` on both arches.
- `call_original` takes up to 16 arguments (`NtCreateFile` has 11). On breakpoint/hw it needs
  a free debug register while it runs (a hw probe lends its own), so keep at most 3 hw probes
  when other probes use it.

## Documentation

- [docs/quickstart.md](docs/quickstart.md): build, run `gated_config` (launch and attach) and `uhh_trace`, write your own tool.
- [docs/api.md](docs/api.md): every function, flag and macro in `include/probe_api.h`, with its per-backend semantics.
- [docs/limitations.md](docs/limitations.md): the per-backend table, and what UHH does not do, with workarounds.
- [docs/troubleshooting.md](docs/troubleshooting.md): the messages UHH prints and common failures, with causes and fixes.
- [docs/symbols.md](docs/symbols.md): DbgHelp, symbol paths, stack snapshots per backend.

## Build

Requires Windows, Visual Studio 2022 (MSVC, with MASM) and CMake 3.28+ — nothing else, and
**no network**: SafetyHook and Zydis are vendored in `third_party/` (see
`third_party/README.md`). Pass `-DUHH_VENDORED_DEPS=OFF` to fetch the same tags from GitHub
instead.

```sh
# x64
cmake -S . -B build-x64 -G "Visual Studio 17 2022" -A x64
cmake --build build-x64 --config Release

# x86 (32-bit native)
cmake -S . -B build-x86 -G "Visual Studio 17 2022" -A Win32
cmake --build build-x86 --config Release
```

For fast (incremental) builds use `scripts\build.ps1` (PowerShell): it configures fresh
build directories with the **Ninja Multi-Config** generator (the Ninja that ships with
Visual Studio is used if none is on `PATH`) and the MSVC environment from
`vcvarsall.bat`, then builds; output stays in `build-x64\Release` / `build-x86\Release`.
A directory already configured with the Visual Studio generator keeps it. With the
Visual Studio generator the build is parallel too (`/MP`, MultiToolTask and a generated
`Directory.Build.rsp` with `-maxCpuCount`; `-DUHH_PARALLEL_MSBUILD=OFF` disables that).

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1               # both arches
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -Arch x64 -Target probe_api
```

## Examples: `gated_config` (launch) and `uhh_attach` (attach)

The target (`examples/targets/probe_app`) ships a feature **disabled in its config**:
after a keystroke it late-loads `configparse.dll`, parses `reads_enabled=0`, and does
nothing. Only when the flag is on does it open its helper processes by pid
(`ntdll!NtOpenProcess`) and read their memory from many threads (`ntdll!NtReadVirtualMemory`).
The probes sit on those ntdll syscall stubs, so every caller is seen whatever wrapper it
went through, under every backend. The examples turn the feature on **from outside, without
modifying the target or its config**: a breakpoint inside `configparse.dll` flips the
parsed flag `0 -> 1` just before it is stored, and further probes log (and filter)
every read — this is how you build metrics on a code path that normally never runs.

- [`examples/gated_config`](examples/gated_config): launch the target under UHH; the
  flag probe is pending until the DLL loads; every read is logged with its pid.
- [`examples/attach`](examples/attach): attach to an already-running target by pid; log
  only the reads of one helper process inside one address range.

```sh
build-x64\Release\gated_config.exe configparse.dll!ParseConfig+0x16 ntdll.dll!NtReadVirtualMemory -- build-x64\Release\probe_app.exe --no-wait
python scripts/regress.py --bin build-x64/Release      # the regression suite (long; --only <names> narrows it)
```

## Status

Verified on x64 **and** x86 by the regression suite (`scripts/regress.py`; on GitHub Actions
for every push, x64 + x86, plus enforced-CET checks on `windows-2025` runners): all three
backends and their mixes, launch and attach/detach, exact hits and logs under heavy
multithreading (e.g. 2,000,000 reads across 8 threads on software breakpoints, zero dropped),
real applications (PowerShell, Edge, robocopy, findstr) and CET shadow stacks. Open items and
findings: [`docs/ROADMAP.md`](docs/ROADMAP.md).
