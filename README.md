# UHH — usermode-hook-helper

A Windows user-mode instrumentation library where **one C callback source runs
unchanged under multiple selectable backends, chosen per probe**. Write a probe
once; decide later whether it is delivered by a software breakpoint or an inline
mid-function hook. Every callback gets the full machine context and full control —
read and write registers and memory, change arguments, flip a return value, log.

```c
/* The same callback works on x64 and x86, under any backend. */
void log_read(probe_context *c) {
    struct read_filter *f = c->config;            /* your optional parameters   */
    uint64_t handle = probe_arg(c, 0);            /* arg 0: reg on x64, stack x86 */
    uint64_t size   = probe_arg(c, 3);            /* arg 3                       */
    if (f && handle != f->selected_handle) return;
    PROBE_LOG(c, "read handle=%llu size=%llu", handle, size);
}

probe_add(s, "configparse.dll+0x1102", enable_reads, PROBE_BREAKPOINT);        /* software breakpoint */
probe_add_cfg(s, "probe_app.exe+0x4690", log_read, PROBE_INLINE, &cfg, len);   /* inline mid-hook     */
```

The full, locked API is in [`docs/api-sketch.md`](docs/api-sketch.md).

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
read path (millions of hits). Probe locations are `module+0xRVA` today (symbol
resolution via dbghelp is on the roadmap), and probes may be registered **before
the target module is loaded** — they stay pending and activate on load.

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

## Example: `gated_config`

A contrived but realistic target (`probe_app`) that, on a keystroke, late-loads a
config DLL (`configparse.dll`), parses a flag, and — only if the flag is set — runs
a multithreaded `NtReadVirtualMemory` workload. The shipped config has the flag
**off**. Two probes turn it on and watch it:

- a **deferred software breakpoint** on the parsed-flag site, pending before the
  DLL loads, that flips the value `0 -> 1` exactly once, and
- an **inline** probe on the read site that logs every read.

Run the end-to-end check against either build (it derives the probe RVAs from the
linker maps, launches the target under the library, and verifies the result):

```sh
python scripts/check_scenario.py --bin build-x64/Release --threads 4 --reads 200
python scripts/check_scenario.py --bin build-x86/Release --threads 4 --reads 200
```

Expected on **both** x64 and x86: the workload is gated off under the shipped
config; with the probes installed the flag is overridden once and the inline
probe's hit count equals the number of reads.

## Status

Verified on x64 **and** x86: all three backends (inline, hardware, software
breakpoint), deferred module+RVA probes, and the mixed `gated_config` scenario.
Software breakpoints are multithread-safe via displaced stepping and proven exact at
**2,000,000 reads across 8 threads (zero dropped hits)**; hardware and inline are
exact under multithreading too. The backend mix matrix passes for breakpoint-flag
combinations.

Roadmap (see [`docs/plan-v2.md`](docs/plan-v2.md)): per-thread `PROBE_LOG` queues,
`module!symbol` resolution, attach-by-name (`watch_new`), inline-over-existing-hook
chaining, a general `read_logger` CLI, and Frida benchmarks.
