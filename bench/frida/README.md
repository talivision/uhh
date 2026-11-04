# Frida benchmark harness

Frida equivalents of this repo's gated instrumentation scenario, so Frida's
`Interceptor` (the industry-standard inline hook) can be timed head-to-head with
our native inline/breakpoint backends on the **same workload, same machine**
(the baseline requirement in `docs/plan-v2.md` -> "Benchmarking baselines").

Everything here runs on the **Windows VM** against the compiled `probe_app.exe` /
`configparse.dll`. Nothing in this directory is built by CMake; it is pure
JS + Python driven by the `frida` module.

```
bench/frida/
  read_logger.js    # analogue of callbacks.cpp log_read   (hot inline read probe)
  enable_reads.js   # analogue of callbacks.cpp enable_reads (deferred flag flip)
  bench_frida.py    # harness: baseline vs Frida, comparable JSON/CSV
  README.md
```

## What each piece maps to

| Ours (`examples/gated_config/callbacks.cpp`) | Frida here |
|---|---|
| `log_read`: inline hook at `ReadSite`, reads `get_func_arg(c,0)` / `get_func_arg(c,3)`, `PROBE_LOG` | `read_logger.js`: `Interceptor.attach(ntdll!NtReadVirtualMemory)`, `args[0]`/`args[3]` |
| `read_logger` CLI: filter by resolved PID + address range | `read_logger.js` `configure({ onlyPid, rangeStart, rangeSize, selectedHandle })` |
| `enable_reads`: deferred **breakpoint** at `configparse.dll+ParsedFlagSite`, sets `PROBE_REG_AX`=1 | `enable_reads.js`: hook `ParseConfig` (default) or the flag-site register (`flagsite`) |
| `note_open`: `NtOpenProcess` return probe building handle->PID map | `GetProcessId(handle)` cached in `read_logger.js` (see note below) |
| controller delivers the gate keystroke via a stdin pipe (`src/session.cpp`) | `device.input(pid, b"x")` after `{"kind":"waiting"}` |

---

## Install (on the Windows VM)

Requires a 64-bit Python 3.8+ for an x64 target, or a 32-bit Python for an
x86 / WoW64 target **matching the target's bitness is not required** (frida can
inject cross-bitness), but using the matching Python avoids surprises.

```bat
python -m pip install --upgrade pip
python -m pip install frida==16.5.9 frida-tools==12.6.1
```

Pinned versions this harness was written against: **frida 16.5.9 / frida-tools
12.6.1**. The scripts also run on **frida 17.x** (which removed the static
`Module.getExportByName`/`findBaseAddress` helpers) via the version shims at the
top of each `.js`. If you use 17.x, just `pip install frida frida-tools` and
expect identical behaviour. Verify:

```bat
frida --version
python -c "import frida; print(frida.__version__)"
```

Run **elevated** (Administrator) - injecting into a spawned child needs
`SeDebugPrivilege` on most setups. Disable Frida's own output buffering is not
needed; the harness reads probe_app's stdout through Frida's `pipe` stdio.

---

## Build inputs it expects

Point `--bin` at a build output dir that contains (from `cmake --build`):

```
probe_app.exe      configparse.dll
probe_app.map      configparse.map   (only needed for --flag-method flagsite)
```

Build as the main README describes, e.g.:

```bat
cmake -S . -B build-x64 -A x64
cmake --build build-x64 --config RelWithDebInfo
```

Then `--bin build-x64\RelWithDebInfo`. For x86: `-A Win32` -> `build-x86`.

---

## Run

Quick comparison (clean baseline; reads enabled via config so the baseline has no
instrumentation at all):

```bat
python bench_frida.py --bin build-x64\RelWithDebInfo
```

Full real gate (late DLL load + flag flip via Frida + stdin keystroke), matching
`scripts/check_scenario.py` end to end:

```bat
python bench_frida.py --bin build-x64\RelWithDebInfo --gated --threads 4 --reads 200
```

High-volume (millions of reads, more threads than cores - plan-v2 requirement):

```bat
python bench_frida.py --bin build-x64\RelWithDebInfo --high-volume
:: == --threads (2*ncores) --reads 2000000  -> tens of millions of reads
```

Isolate attach cost, add the pre-existing-hook axis, more repeats:

```bat
python bench_frida.py --bin build-x64\RelWithDebInfo --with-attach-baseline --prehook --repeats 9
```

Run the scripts standalone for a functional smoke test (no timing):

```bat
frida -f build-x64\RelWithDebInfo\probe_app.exe -l enable_reads.js -l read_logger.js ^
      --runtime=v8 -- --threads 2 --reads 20
:: at the frida> prompt: %resume   then press a key in probe_app's console
```

---

## Methodology ("overhead per read")

The number we care about is the **extra time Frida's Interceptor adds to each
`NtReadVirtualMemory` call**. We get it without trusting any external clock:

1. **In-target clock.** `probe_app` wraps its gated W-threads x R-reads loop in
   `QueryPerformanceCounter` and prints `elapsed_ns`. `scripts/bench.py` reads
   the same field, so Frida's rows line up against our inline/veh-sw/debug-sw/
   debug-hw rows column-for-column.
2. **Baseline = no Frida.** `probe_app --no-wait --config reads_enabled=1`: the
   workload runs with zero instrumentation. (Enabling via config, not via a
   flag-flip hook, keeps the baseline genuinely clean. The flag flip is a
   once-per-run cost, dwarfed by millions of reads, and is measured separately in
   `--gated` mode.)
3. **Instrumented = Frida attached, only `ntdll!NtReadVirtualMemory` hooked.** No
   other code is touched, so the delta is the hook's cost.
4. **Count mode, not log mode.** The read hook reads `args[0]`+`args[3]` and bumps
   a counter - it does **not** `send()` per call. Sending per call would measure
   Frida's message IPC, not the hook; it is the wrong comparison for our inline
   `log_read`, whose `PROBE_LOG` only enqueues to a per-thread queue. (Use
   `mode:'log'` for functional logging; never for high-volume timing.)
5. **Medians.** Each configuration runs `--repeats` times (default 5).
   `added = median(frida) - median(baseline)`; `slowdown = median(frida)/median(baseline)`.

Two normalizations are reported:
- `median_ns_per_iteration = elapsed_ns / reads_per_thread` - **bench.py's
  definition** (W threads run concurrently, so an "iteration" is one per-thread
  read round). Use this column to sit beside our results.
- `median_ns_per_read_total = elapsed_ns / (threads*reads)` and
  `added_ns_per_read_total` - the intuitive per-call overhead.

Correctness is gated like `check_scenario.py`: every run asserts
`reads_enabled == 1` and `successful_reads == threads*reads`, and the harness
prints Frida's own `hook_calls` count, which should be ~`threads*reads` (one per
gated read; the local buffer verification in `app.cpp` does not go through
`NtReadVirtualMemory`).

### Output

`--out` (default `bench/frida/results/`):
- `raw.jsonl` - one line per run (`elapsed_ns`, `successful_reads`, `checksum`,
  `frida_read_calls`, `frida_matched`, `frida_overrides`).
- `summary.json` / `summary.csv` - medians per mode. Columns match
  `scripts/bench.py`'s `summary.csv`
  (`workload,callback,mutation,prehook,mode,repeats,median_ns_per_iteration,
  min_/max_ns_per_iteration,added_ns_per_iteration,slowdown`) plus Frida extras
  (`threads,reads_per_thread,total_reads,median_ns_per_read_total,
  added_ns_per_read_total,flag_method,frida_version`). `mode` is `baseline`,
  `frida`, and optionally `frida-attach`, so you can paste these rows directly
  under the `reads,mutate,register,*` rows in `measurements/.../summary.csv`.

---

## Where Frida's model differs from ours (read before interpreting numbers)

- **No deferred/pending probe on a module-load debug event.** Our controller
  registers `configparse.dll+RVA` *before the DLL exists* and arms it from the
  external debugger's `LOAD_DLL_DEBUG_EVENT`. A Frida agent lives **inside** the
  target and has no debug-event loop, so `enable_reads.js` instead watches for the
  load from within: `Process.attachModuleObserver` (frida >= 16.2) or, as a
  fallback, `Interceptor.attach(ntdll!LdrLoadDll, { onLeave })`. `LdrLoadDll`
  returns before `LoadLibraryA` returns, which is before `ParseConfig` runs, so
  the flag is still caught in time - functionally equivalent, mechanically
  different.
- **The flag site is too short for an inline hook - on *both* tools.**
  `ParsedFlagSite` is a 2-byte `mov [rcx],eax` + `ret`; our tool deliberately uses
  a **software breakpoint** there, not an inline jump. Frida's `Interceptor` is
  *also* an inline trampoline and may not find enough relocatable bytes either.
  So `enable_reads.js` defaults to `--flag-method parseconfig`: hook the exported
  `ParseConfig` and overwrite `parsed_config.reads_enabled` in `onLeave`. The
  direct register-flip mirror (`--flag-method flagsite`, set `EAX`=1 via
  `this.context.eax/rax`) is provided and will attach where byte-count permits; it
  falls back with a clear message otherwise. Frida does not expose a simple
  hardware-breakpoint primitive from JS, so it has no clean no-code-modification
  option at that site the way our HW/breakpoint backends do.
- **Handle->PID resolution.** UHH's `track_open_process`
  (examples/gated_config/callbacks.cpp) builds a handle->PID map at `NtOpenProcess`
  (probe_app opens every helper by pid there). `read_logger.js` instead resolves with
  `GetProcessId(handle)`, **cached per handle** (one syscall per distinct handle,
  then a JS-map hit) - the same "resolve once, cache, never on the hot path
  uncached" rule.
- **In-target vs out-of-process.** `BaseAddress` in `NtReadVirtualMemory` names
  the **remote** (child) process. Frida runs in-target, so `ptr(base).read*()`
  would read the wrong process - we log the raw args only, exactly as `log_read`
  does. The address-range filter compares the pointer value; it needs no memory read.
- **`args[i]` is arch-neutral**, like our `get_func_arg`: registers on x64, stack on
  x86, handled by Frida. One script covers x64, x86-native and WoW64 targets (for
  WoW64, inject the matching-bitness agent; frida handles this).
- **Per-call `send()` is not free.** Frida's strength (scriptable JS, rich
  messaging) is also why logging *every* hit over the message channel is far
  heavier than our deferred binary `PROBE_LOG`. The benchmark's `count` mode
  removes that asymmetry so the comparison is hook-vs-hook; `log` mode shows the
  real cost of actually streaming records out.
```
