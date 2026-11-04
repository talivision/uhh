# UHH — usermode-hook-helper

A Windows user-mode instrumentation library where **one C callback source runs
unchanged under multiple selectable backends, chosen per probe**. Write a probe
once; decide later whether it is delivered by a software breakpoint or an inline
mid-function hook. Every callback gets the full machine context and full control —
read and write registers and memory, change arguments, flip a return value, log.

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
| a **session** | `probe_add_symbol`, `probe_add_symbol_cfg`, `probe_add_address`, `probe_watch`, `probe_launch`, `probe_run`, `probe_report`, `probe_close` | the instrumentation run (control plane) |
| a **context** `c` | `get_reg`, `set_reg`, `get_func_arg`, `get_mem`, `set_mem`, `get_config`, `send_log`, `send_log_stack`, `get_session` | this one hit (data plane) |

`get_session(c)` is the bridge: **every control-plane call works from inside any
callback** — breakpoint, hardware, or inline. The target is stopped, so a probe added
there is armed before the target runs another instruction. From an inline callback (which
executes inside the target) the call is forwarded to the controller synchronously; the
callback source does not change.

```c
/* malloc -> watch: probe the allocator, follow the pointer, watch the memory. */
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

`send_log` and `send_log_stack` append `probe_log` JSON lines to a per-session file under
`%TEMP%\uhh\logs`; its path is printed once as `probe: logs -> ...`. Both the debugger
callbacks and inline agent feed one bounded controller queue, so filesystem backpressure
waits instead of dropping logs or growing memory. A background tailer copies new complete
lines to controller stdout with raw-handle writes (up to 64 KiB each), flushing the
driver's CRT stdout first. This keeps the target decoupled from a slow console while logs
remain live; redirecting stdout to `NUL` disables tailing and leaves the complete file.
If a console tail falls behind for more than about a second, UHH prints a one-time
redirect-to-file-or-pipe performance warning on stderr.
The writer flushes on idle or within about 10 ms. `send_log_stack` captures only raw
return addresses at the hit; the writer resolves them to `module!function+0xoff` (plus
`file:line` with PDBs), so symbol work never runs in the hit path. `probe_report` catches
the tail up, then emits only pre-hook/probe/summary records; its summary includes
`logs_written`, `log_dropped`, and `controller_peak_ws_mb`. See
[`examples/dynwatch`](examples/dynwatch).

## Backends

| Backend | How | Per-hit cost | Modifies code? | Multithread |
|---|---|---|---|---|
| `PROBE_INLINE` | injected SafetyHook mid-hook | ~tens of ns | trampoline (≥5 bytes) | exact |
| `PROBE_HW` | execute debug register (DR0–3) | ~tens of µs | none | exact (≤4 probes) |
| `PROBE_BREAKPOINT` | external debugger, native-bitness INT3 | ~hundreds of µs | 1 byte | exact |

All three are **exact under multithreading** (no dropped hits). The software
breakpoint achieves this with **displaced (out-of-line) stepping** — the `INT3`
stays armed while the original instruction runs from a per-thread scratch buffer, so
no other thread can cross the site unobserved and no thread is suspended (no race, no
deadlock). The hardware breakpoint modifies no code at all and handles any
instruction, including the control-flow sites displaced stepping routes to an
in-place fallback. Inline is the fastest where the site has room for a trampoline.

Backends are picked **per probe** and interoperate in one session — e.g. a
breakpoint on a config-flag site (fires once) mixed with an inline hook on a hot
read path (millions of hits). Probe locations are `module+0xRVA` or `module!Export[+0xOFF]`
(resolved from the target's export table; PDB-only symbols are on the roadmap), and
probes may be registered **before the target module is loaded** — they stay pending
and activate on load.

## Build

Requires Windows, Visual Studio 2022 (MSVC) and CMake. SafetyHook and Zydis are
fetched automatically.

```sh
# x64
cmake -S . -B build-x64 -G "Visual Studio 17 2022" -A x64
cmake --build build-x64 --config Release

# x86 (32-bit native)
cmake -S . -B build-x86 -G "Visual Studio 17 2022" -A Win32
cmake --build build-x86 --config Release
```

## Examples: `gated_config` (launch) and `uhh_attach` (attach)

The target (`examples/targets/probe_app`) ships a feature **disabled in its config**:
after a keystroke it late-loads `configparse.dll`, parses `reads_enabled=0`, and does
nothing. Only when the flag is on does it open its helper processes by pid
(`ntdll!NtOpenProcess`) and read their memory from many threads (`ntdll!NtReadVirtualMemory`).
The probes sit on those ntdll syscall stubs, so every caller is seen whatever wrapper it
went through -- under every backend, inline included. The examples turn the feature on **from outside, without
modifying the target or its config**: a breakpoint inside `configparse.dll` flips the
parsed flag `0 -> 1` just before it is stored, and further probes log (and filter)
every read — this is how you build metrics on a code path that normally never runs.

- [`examples/gated_config`](examples/gated_config): launch the target under UHH; the
  flag probe is pending until the DLL loads; every read is logged with its pid.
- [`examples/attach`](examples/attach): attach to an already-running target by pid; log
  only the reads of one helper process inside one address range.

```sh
build-x64\Release\gated_config.exe configparse.dll!ParseConfig+0x16 ntdll.dll!NtReadVirtualMemory -- build-x64\Release\probe_app.exe
python scripts/regress.py --bin build-x64/Release      # everything, incl. both examples
```

## Status

Verified on x64 **and** x86: all three backends (inline, hardware, software
breakpoint), deferred module+RVA probes, and the mixed `gated_config` scenario.
Software breakpoints are multithread-safe via displaced stepping and proven exact at
**2,000,000 reads across 8 threads (zero dropped hits)**; hardware and inline are
exact under multithreading too. The backend mix matrix passes for breakpoint-flag
combinations.

Roadmap (see [`docs/ROADMAP.md`](docs/ROADMAP.md)): further hot-path measurement,
inline-over-existing-hook chaining, and the remaining adversarial correctness cases.
