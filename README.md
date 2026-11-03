# Native probes: first pass

An executable-oriented Windows x64 prototype. One C callback source runs in an
external debugger or an in-process agent, with a shared register/memory API.
Includes the contrived flag + NtReadVirtualMemory example, a pre-existing hook
layer, correctness gates, and a benchmark runner. This is source code, not a
claim of measured Windows performance.

## Build on Windows

Requirements: Windows x64, Visual Studio 2022 with Desktop development with C++
(MSVC and MASM, sufficiently recent for C++23), Git, CMake >=3.28, Python >=3.10.
Open an x64 Native Tools / Developer command prompt in this directory:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python scripts\bench.py --bin build\Release --correctness-only
python scripts\bench.py --bin build\Release --out results
```

CMake fetches SafetyHook v0.7.0 and its dependencies; it needs network access.
No system driver, kernel debugger, PDB installation or elevation is intended for
these launch-owned fixture processes. Some process security policies can still
block debugging or executable-page writes.

## Run the requested example

```bat
build\Release\probe_target.exe inline reads 1000 mutate memory 32 prehook
build\Release\probe_debugger.exe debug-sw reads 1000 mutate memory 32 prehook
build\Release\probe_debugger.exe debug-hw reads 1000 mutate register 32 prehook
build\Release\probe_target.exe veh-sw reads 1000 mutate register 32 prehook
```

Arguments are MODE, WORKLOAD, measured iterations, CALLBACK, MUTATION,
warmup iterations, and `prehook` or `clean`. Modes are `baseline`, `inline`,
`veh-sw`, `debug-sw`, `debug-hw`; the last two use probe_debugger.exe.
Workloads are `micro` or `reads`. Callbacks are `noop`, `filter`, `mutate`, `log`.
Mutation is `register` or `memory` and only affects `mutate` callbacks.

To dump the buffered records as JSON lines, after timing has finished:

```bat
set PROBE_DUMP_LOGS=1
build\Release\probe_target.exe inline reads 20 mutate memory 0 prehook
set PROBE_DUMP_LOGS=
```

The target:

1. Starts two helper processes with known 256-byte buffers.
2. Resets a local flag to zero before each iteration in mutation modes.
3. Crosses a stable assembly instruction boundary, inside FlagCheck. The
   callback sets the flag in target memory, or changes RAX after the flag load.
4. Uses the resulting flag to decide whether to perform a memory read.
5. Calls NtReadVirtualMemory through an assembly wrapper with the same ABI.
   Calls rotate through: selected process/in-range, selected process/out-of-range,
   other process/in-range, selected process/in-range at another offset.
6. Independently checks return status, bytes transferred, returned contents and
   checksums. The shared callback filters by the selected process handle and
   complete containment in its configured address range, logging attempted reads.

The target branches on the flag, skipping reads while it is zero, and fails its
final independent count check if a callback fails to enable it. In
baseline mode the target supplies flag=1 itself, so the downstream work is equal.
For an uninstrumented demonstration of the disabled path:

```bat
build\Release\probe_target.exe disabled reads 20 mutate memory 0 prehook
```

It should report zero enabled iterations, zero reads and zero existing-hook calls.

No unsuccessful reads or completion-probe pairing are implemented yet: successful
completion is checked by the target, while probe records describe attempts.
The filter uses a known process HANDLE, not a general handle-to-PID resolver.

## Existing-hook test

With `prehook`, the target first installs a SafetyHook function-entry detour on
ReadThunk. Its handler increments an independent counter and calls through its
original trampoline. Only AFTER that does the agent/controller inspect the entry
and install a second probe at that SAME address. This exercises relocation of an
existing entry redirection, not simply two callbacks at different addresses.

The intended inline chain is:

```
new mid-hook callback -> displaced existing jump -> existing handler
                     -> existing original trampoline -> NtReadVirtualMemory
```

Before installation stderr reports the site, first 16 bytes, and a classification
of common relative/indirect jump forms. Recognized forms explicitly say
`pre-existing redirect detected`. `fixture-clean` means only that this known
fixture's NOP bytes match; `unknown` is not evidence of no hook. This is not a
universal hook detector and does not identify the owning module or chase chains.

Each backend must leave `prehook_calls == warmup + iterations` in the read
workload. Removal order is second probe first, existing hook second. Unsupported
SafetyHook relocation is a failed test, never permission to skip the old layer.
We do not test independent concurrent install/uninstall by other tools yet.

## Architecture and code map

- include/probe.h: plain C context, integer registers, memory operation table,
  configuration, bounded structured log records.
- src/callback.c: identical callback source linked into both agent and controller.
- src/agent.cpp: local memory helpers with SEH; SafetyHook mid-hooks; local INT3
  exception handling through VEH with restore/single-step/re-arm.
- src/debugger.cpp: Win32 debug-event loop; external INT3 or hardware execution
  breakpoints; external memory helpers; explicit exception ownership.
- src/sites.asm: stable flag sites and NtReadVirtualMemory forwarding site.
- src/target.cpp: target, helper processes, existing hook, independent verification.
- scripts/bench.py: independent expected record/count oracle, correctness matrix,
  randomized repeat order, raw JSONL, median/min/max and baseline-subtracted CSV.

The first debugger adapter uses the native Windows debug API directly, rather
than DbgEng/TitanEngine. That keeps dependencies and the first event loop small;
the shared callback ABI does not depend on that choice. The agent DLL is loaded
cooperatively by the fixture. Arbitrary-process attach/injection, PDB symbols,
generic module+offset registration and deferred module loading are not built yet.
The controller resolves exports in the fixture executable and accounts for ASLR.

All 16 integer registers are observable; general-purpose registers other than
RSP are writable. PC, SP and flags are observational in this first ABI. SIMD,
AVX/XSTATE access, control-flow changes, stack unwinding, arbitrary-page writes
and atomic memory access are not promised. Local writes may partially modify
memory before a caught fault; a false result does not mean nothing was written.
There is no automatic page-protection escalation for callback data writes.

## What the measurements mean

`micro` crosses one flag probe per iteration and does no syscall workload.
`reads` crosses two probes and performs one actual NtReadVirtualMemory call per
iteration. Results are PER ITERATION, not an inferred cost per breakpoint for
the two-probe workload. The software breakpoint implementations also handle a
single-step exception to re-arm; both exceptions are included in elapsed time.

The matrix compares baseline, inline, VEH software breakpoint, external software
breakpoint and external hardware breakpoint. It first verifies both register and
memory mutation, with and without the existing layer. Microbenchmarks exercise
noop, filtering, memory-read/register-mutation, and 1%-selected buffered logging.
The realistic workload benchmarks mutation plus filtered read logging, with and
without the pre-existing layer. Correctness includes counts AND an independent
ordered record digest so missing, duplicate or altered records fail the gate.

Warmup is excluded from the timed region but included in hit counts/record
validation. Each run uses a fresh process. The baseline is paired by workload,
callback, mutation and prehook configuration. No terminal output occurs in the
timed target region. At most 8192 records are retained; dropped counts are
explicitly checked, so high-rate logging does not silently pretend full delivery.
The log buffer is an append-only first-N buffer, not a streaming ring yet.

The raw results include target timed elapsed ns, coarse target CPU ns for the
measured region, controller TOTAL lifetime CPU ns, and subprocess wall time.
These CPU scopes differ: do not subtract one from the other or present controller
startup-inclusive CPU time as a per-hit metric. summary.csv reports median,
min/max ns per iteration, baseline-subtracted ns/iteration and elapsed slowdown.
Start with the defaults (2000 micro iterations, 200 reads, 3 repeats); external
breakpoints can make million-hit runs expensive. For longer runs:

```bat
python scripts\bench.py --bin build\Release --iterations 100000 --reads-iterations 10000 --repeats 7 --out longer-results
```

No affinity control or timing threshold is imposed. Windows scheduling, CPU
frequency, VM translation and background load affect results. Run natively on
x64 for x64 conclusions; Windows x64 emulation on ARM is a separate experiment.
Negative tiny baseline-subtracted values can be noise and are not clamped away.

## First-pass limits and verification status

This fixture is intentionally SINGLE-THREAD for probe execution. Helper processes
are separate. Software breakpoint re-arm windows are not made safe for multiple
target threads; hardware slots are set only on the stopped fixture main thread.
No claim about concurrent target workloads or preservation of all extended CPU
state has been verified. Software re-arming must not be reused as-is in a
production multithread debugger.

Portable C policy tests and Python oracle tests can run on Linux:

```sh
gcc -std=c11 -Wall -Wextra -Werror -Iinclude src/callback.c tests/policy_tests.c -o policy_tests
./policy_tests
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

See VALIDATION.md for the exact checks executed during creation. Windows binaries
were NOT built or run in the creation environment. The next acceptance gate is a
Release build and `--correctness-only` on Windows, especially the already-hooked
inline case. No performance numbers should be quoted until those gates pass.
