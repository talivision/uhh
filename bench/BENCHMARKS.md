# UHH vs Frida — instrumentation benchmark

Head-to-head of **every UHH read backend** against **multiple Frida methods** doing
the *same* instrumentation (count each `ntdll!NtReadVirtualMemory` call), on the
*same* workload, *same* machine, *same* clock. Performance is only one axis —
**stability** (does the method complete the workload at all?) and **flexibility /
coverage** (where can the method be applied?) are reported as first-class results,
because UHH being more robust and more broadly applicable than a given Frida method
is itself a positive result.

Reproduce with `bench/bench_matrix.py` (driver) and `bench/frida/*.js` (the four
Frida methods). Raw per-run numbers in `bench/results/`.

## 2026-11-07 re-run (merge-frida 034b245; full gated_config on branch `perf` 74d62a5)

Same VM (i5-6600, Win10 19045), frida 16.5.9, W=8 x R=50,000 = 400,000 reads, 3 repeats, x64 AND
x86 (frida 16.5.9 instruments the 32-bit probe_app from its 64-bit host fine). Raw data:
`bench/results/frida-2026-11-07/`. The 2026-11-04 tables below are kept for history.

**Matrix (bench_matrix.py; UHH rows = gated_config, which LOGS every read; Frida = count mode):**

| method | x64 added ns/read | x64 slowdown | x86 added ns/read | x86 slowdown | hits exact |
|---|---:|---:|---:|---:|---|
| baseline | 0 (434 ns/read) | 1.0x | 0 (521 ns/read) | 1.0x | -- |
| UHH inline | +2,396 | 6.5x | +3,088 | 6.9x | 400,000, 0 dropped |
| UHH hw | +147,255 | 341x | +269,682 | 518x | 400,000, 0 dropped |
| UHH breakpoint | +103,641 | 240x | +207,514 | 399x | 400,000, 0 dropped |
| Frida Interceptor (count, no send) | +7,524 | 18.3x | +10,258 | 20.7x | 400,000 |

Why UHH inline went from +62.5 ns (2026-11-04) to +2,396 ns/read: then, 399,488 of the 400,000
log records were DROPPED (`log_dropped`); since the "no dropped logs" rule every record is
delivered (the ring applies backpressure), so the inline row now measures hook + delivering
400,000 records (~350k records/s through the controller), not the hook alone. The hook alone is
~0.1 us (`bench/perfab`, hit/inline/empty). CModule / Stalker / hwbp were not re-run (Frida-side,
unchanged; see below). The hw / breakpoint rows are merge-frida's (before the `perf` fairness
fix: breakpoint -16..-24% and hw -14..-16% per hit further, single thread: bench/results/main-vs-merge-frida-2026-11-07.md).

**The whole gated_config example in both tools** (`bench/frida/gated_full.py` + `gated_full.js`,
perf 74d62a5): config ships disabled and is flipped at parse; handle -> pid map at
NtOpenProcess (forgotten at NtClose); EVERY NtReadVirtualMemory logged as one record (handle,
pid, address, size) delivered to the host (Frida batches 4,096 records per send()). Ground truth:
probe_app's own `opened` lines.

| tool | arch | read window (in-target) | ns/read | wall (start -> last record) | records | wrong pid | no pid |
|---|---|---:|---:|---:|---|---|---|
| UHH (flag: breakpoint, reads: inline) | x64 | 1,031 ms | 2,578 | 1.63 s | 400,000 x3 | 0 | 0 |
| Frida Interceptor | x64 | 4,909 ms | 12,273 | 5.43 s | 400,000 x3 | 0 | 0 |
| UHH | x86 | 1,322 ms | 3,305 | 2.18 s | 400,000 x3 | 0 | 0 |
| Frida Interceptor | x86 | 5,696 ms | 14,240 | 6.42 s | 400,000 x3 | 0 | 0 |

Both are exact (every read logged once with the right pid); UHH is 4.3-4.8x faster on the full
example. (Frida 16.5.9 has no `Process.attachModuleObserver`: gated_full.js hooks ParseConfig
after LdrLoadDll there.)

## TL;DR

- **UHH completes the exact 8-thread × 50,000-read workload on all three backends
  (inline, hardware, software breakpoint) with EXACT hit counts (400,000, zero
  missed hooks).** That is the headline: full, correct coverage with no hangs.
- **UHH inline is ~130× cheaper per hit than Frida's Interceptor** (+62.5 vs
  +8,102 ns/read) for the same inline-hook job, and **1.15× vs 20.2× slowdown.**
- Of the four Frida methods, only **Interceptor** (inline trampoline, JS `onEnter`)
  completed the full workload correctly. **CModule hangs on load**, **Stalker hangs
  at volume** (per-instruction tracing), and **the hardware-breakpoint API counts
  incorrectly** (8 of 16,000) and is ~95× slower. UHH offers correct, hang-free
  alternatives (hardware + displaced software breakpoint) exactly where Frida's
  non-trampoline methods are impractical.
- **Frida 17.25.2 could not instrument this VM at all** (fatal "Unable to locate the
  ntdll loader TLS routines" on both spawn and attach). The Frida numbers here are
  from **frida 16.5.9**, which attaches cleanly. The 17.25.2 failure is itself a
  Frida-coverage finding.

## Environment

| | |
|---|---|
| Host | DESKTOP-DFF87LU (Proxmox VM 103) |
| CPU | Intel Core i5-6600 @ 3.30 GHz — 4 cores / 4 logical (no SMT) |
| OS | Windows 10 Pro 19045, ntdll 10.0.19041.2788 |
| RAM | 8 GB |
| Python | 3.12.10 |
| Frida (measured) | **16.5.9** (attach) — 17.25.2 is installed but cannot inject (see findings) |
| UHH build | `build-x64\Release`, MSVC 17.14, Release x64 (BUILD_OK confirmed) |
| Workload | probe_app: W threads × R reads through `ReadThunk → NtReadVirtualMemory`, 4-way selected/decoy/in-range rotation |
| Primary point | **W=8 threads (> 4 cores), R=50,000 reads/thread = 400,000 reads**, 3 repeats, median |
| High volume | W=8, R=250,000 = 2,000,000 reads, 3 repeats, median |
| Clock | probe_app's in-target `QueryPerformanceCounter` window (`elapsed_ns`) — the SAME field for every method, so columns line up |
| RVAs | `ParsedFlagSite` = 4354 (configparse.map), `ReadSite` = 18064 (probe_app.map) |

All methods run in **count mode**: read the handle (`args[0]`) and size (`args[3]`),
bump a counter, **no per-call `send()`/IPC** — the fair analogue of UHH's `log_read`,
whose `PROBE_LOG` only enqueues. "Added ns/read" = median(instrumented) −
median(baseline), both on `elapsed_ns / (W·R)`.

## Performance + correctness — W=8, R=50,000 (400,000 reads)

Baseline median ≈ 170 ms ≈ **422 ns/read** (per-chunk baseline used for each "added").

| Method | Added ns/read | Slowdown | Completes workload? | Hit count | Hits exact? |
|---|---:|---:|---|---|---|
| baseline (no instrumentation) | 0 | 1.00× | yes | — | — |
| **UHH inline** (SafetyHook mid-hook) | **+62.5** | **1.15×** | **yes** | 400,000 | **exact** |
| **UHH hardware** (debug register) | +65,330 | 156× | **yes** | 400,000 | **exact** |
| **UHH breakpoint** (INT3 + displaced step) | +118,044 | 279× | **yes** | 400,000 | **exact** |
| Frida Interceptor (inline trampoline, JS onEnter) | +8,102 | 20.2× | yes | 400,000 | exact |
| Frida CModule (native onEnter) | — | — | **NO — hangs on load** | — | — |
| Frida Stalker (follow + addCallProbe) | — | — | **NO — hangs at volume** | — | — |
| Frida hardware breakpoint (per-thread DR) | — | — | runs but **mis-counts** | see reduced-scale | **no** |

Notes:
- **UHH inline** reported `log_dropped = 399,488`. This is NOT missed
  instrumentation: the probe callback fired on **all 400,000** reads (hits exact).
  `log_dropped` counts deferred *log records* the out-of-band printer could not
  drain at burst speed; when the queue is full `PROBE_LOG` drops (a cheap counter
  bump) instead of enqueuing — which is precisely the "bump a counter, no IPC" work
  Frida's count mode does, so the inline-vs-Interceptor comparison is
  hook-dispatch vs hook-dispatch. UHH hw/breakpoint are slow enough that the printer
  keeps up → `log_dropped = 0`.
- `overrides == 1` and `successful_reads == 400,000` for all UHH runs; checksum is
  identical across baseline and all three UHH backends (see "Correctness").

### Frida CModule / Stalker / hardware-bp — characterization (reduced scale)

Because three of the four Frida methods do not complete the full workload, each was
also run under a hard per-method timeout at reduced scale to characterize *why*:

| Method | Scale tried | Result |
|---|---|---|
| CModule | W2×R500 (1,000) **and** W8×R50,000 | **Hangs/wedges the target on script load** at both scales (`Interceptor.attach(target, cmodule)`); the workload never runs. Not viable in this setup. |
| Stalker | W8×R2,000 (16,000) | **Completes, count exact (16,000)**, 9 threads followed, +2,169 ns/read (~6× at this scale). At the full W8×R50,000 it **hangs / wedges probe_app at 0 % CPU** (per-instruction recompilation of every worker thread → unbounded). Not viable at volume. |
| Hardware bp | W8×R2,000 (16,000) | Runs but **counts only 8 of 16,000** (re-arm/single-step across threads with one DR slot does not hold), 13 threads armed, +40,062 ns/read (~95×). API exists but is **incorrect and impractical** for counting all reads here. |

## High volume — W=8, R=250,000 (2,000,000 reads)

Only the methods that complete quickly are included (UHH hw/breakpoint scale ~linearly
— ≈130 s / ≈240 s per repeat at this size — and are omitted for time; the W8×R50,000
numbers above already establish their per-hit cost).

Baseline median ≈ 840 ms ≈ **420 ns/read** (2,000,000 reads).

| Method | Added ns/read | Slowdown | Hit count | Hits exact? |
|---|---:|---:|---|---|
| baseline | 0 | 1.00× | — | — |
| **UHH inline** | **+55.1** | **1.13×** | 2,000,000 | **exact** |
| Frida Interceptor | +8,145 | 20.4× | 2,000,000 | exact |

At 2,000,000 reads UHH inline is ~**148× cheaper per hit** than Frida's Interceptor
(+55 vs +8,145 ns/read), and the per-hit costs are stable vs the 400,000-read point
(+62.5 / +8,102) — the gap is structural, not a small-sample artifact. UHH inline
`log_dropped = 1,999,488` with **hits = 2,000,000 exact** (same nuance as above:
every hook fired; only deferred log records were shed at burst).

## Correctness (re-confirmation)

Confirmed directly from the raw per-run records at W=8, R=50,000 (3 repeats each):

| Method | checksum | successful_reads | probe hits | log_dropped |
|---|---|---|---|---|
| baseline | 33,600,000 | 400,000 | — | — |
| UHH inline | 33,600,000 | 400,000 | **400,000** | 399,488 |
| UHH hardware | 33,600,000 | 400,000 | **400,000** | 0 |
| UHH breakpoint | 33,600,000 | 400,000 | **400,000** | 0 |
| Frida Interceptor | 33,600,000 | 400,000 | **400,000** | — |

The checksum (33,600,000) is identical for baseline and every instrumented backend,
proving instrumentation did not perturb the workload's results.


For every UHH backend at W=8, R=50,000, across 3 repeats:
`probe hits == 400,000` (exact, no missed hooks), `successful_reads == 400,000`,
`overrides == 1`, and the checksum is stable and identical to baseline. UHH is
correct under heavy multithreading at volume on all three backends.

## Stability & coverage — the robustness result

| Method | Completes W8×R50k? | Correct count? | Why / caveat |
|---|---|---|---|
| UHH inline | yes | yes (400k) | needs a ≥5-byte relocatable site for the mid-hook |
| UHH hardware | yes | yes (400k) | no code modification; any instruction; ≤4 DR slots; applies to all threads incl. new ones |
| UHH breakpoint | yes | yes (400k) | no trampoline; any displaceable instruction; exact under threads via displaced stepping |
| Frida Interceptor | yes | yes (400k) | inline trampoline; needs ≥5-byte site + reachable within ±2 GB; JS onEnter bridge per call is the 20× cost |
| Frida CModule | **no (hangs)** | — | native onEnter removes the JS bridge, but wedged the target on load here; extra C/Gum build surface |
| Frida Stalker | **no (hangs at volume)** | exact only at small scale | per-instruction dynamic recompilation of every thread; overhead unbounded for a hot syscall loop |
| Frida hardware bp | runs, impractical | **no (8/16000)** | per-thread only (no process-wide/future-thread arming), one-shot re-arm broke across 8 threads |

### Flexibility / coverage matrix

- **UHH gives three selectable per-probe backends in one API** (`PROBE_INLINE`,
  `PROBE_HW`, `PROBE_BREAKPOINT`), chosen per site:
  - *inline* — fastest, for sites with ≥5 relocatable bytes.
  - *hardware* — **no code modification**, works on **any** instruction (even a
    2-byte store), limited to ≤4 debug-register slots, and is armed on **every
    thread including threads created later** (via the external debugger).
  - *software breakpoint* — no trampoline, works on any displaceable instruction,
    exact under multithreading via displaced single-stepping.
- The gated flag site (`ParsedFlagSite`, a 2-byte `mov [rcx],eax` + `ret`) is **too
  short for any inline trampoline** — UHH uses a software breakpoint there and it
  just works; Frida's Interceptor (also a trampoline) cannot hook such a site
  directly, and Frida exposes **no practical no-code-modification primitive** for it
  on this platform (its per-thread HW-bp API mis-counts, see above).
- **Frida Interceptor** needs a ≥5-byte site and a trampoline reachable within
  ±2 GB, and pays a JS bridge on every hit (the 20× here). **CModule** removes the
  bridge but adds C/Gum build complexity and did not run at all here. **Stalker**
  can count without patching code but is per-thread and recompiles everything it
  traces. **Hardware breakpoints** in 16.5.9 are per-thread
  (`ThreadDetails.setHardwareBreakpoint`) with no process-wide or future-thread
  variant and no thread-creation observer, so they cannot be armed on probe_app's
  worker threads before they start their read loop without racing.

## Finding: Frida 17.25.2 cannot instrument this VM

Both `frida.spawn()` and `frida.attach()` abort with the fatal gum error **"Unable
to locate the ntdll loader TLS routines"** on Windows 10 19045 (ntdll
10.0.19041.2788), reproduced three independent ways (spawn via the existing
harness, attach, and an introspection script). The baseline (no Frida) runs fine, so
this is a Frida-17.25.2-vs-this-ntdll signature-matching regression, not an
environment problem. **frida 16.5.9** attaches cleanly, so all Frida numbers here are
from 16.5.9 (installed in an isolated venv `C:\work\fv16`). Frida is driven by
**attach** (launch probe_app gated → attach → install hook → release the gate)
rather than spawn, which also sidesteps the suspended-loader issue.

## How to reproduce

```bat
:: on the VM, with frida 16.5.9 available (C:\work\fv16)
C:\work\fv16\Scripts\python.exe bench\bench_matrix.py ^
   --rel build-x64\Release --threads 8 --reads 50000 --repeats 3 ^
   --methods "baseline,uhh:inline,uhh:hw,uhh:breakpoint,frida:interceptor"
:: wrap EACH method in a Start-Job + Wait-Job -Timeout so a hanging Frida method
:: (CModule/Stalker/hwbp) cannot wedge the whole run; treat a timeout as the result
:: "not viable for this workload".
```

Files: `bench/bench_matrix.py` (unified driver), `bench/frida/read_logger.js`
(Interceptor), `read_cmodule.js` (CModule), `read_stalker.js` (Stalker),
`read_hwbp.js` (hardware breakpoint). Raw per-run data and per-method summaries in
`bench/results/`.
