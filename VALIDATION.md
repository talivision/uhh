# Validation during creation

Creation host: Linux x86_64. No Windows execution environment, Windows SDK,
MSVC/MASM or Wine was available. No Windows build or end-to-end benchmark has
been performed. There are no fabricated benchmark results in this package.

Executed:

- GCC C11 compilation of src/callback.c and tests/policy_tests.c with
  -Wall -Wextra -Werror and AddressSanitizer/UndefinedBehaviorSanitizer.
- Policy executable passed register mutation, memory mutation, invalid access,
  process-handle/range selection, overflow rejection, bounded-log drops and noop.
- LeakSanitizer cannot run under this host's tracing environment; the test was
  rerun with ASAN_OPTIONS=detect_leaks=0. Address and undefined-behaviour checking
  remained enabled. The portable test uses no dynamic allocation.
- Four Python unittest checks passed: independently calculated read selection
  including warmup-index reset, failure rejection, log-capacity accounting,
  baseline subtraction.
- Python syntax compilation of runner and tests passed.
- SafetyHook v0.7.0 public headers and CMake options were inspected to check the
  adapter's context field names, create_mid/create_inline, reset and target names.

These checks validate the shared policy and benchmark oracle, not Windows APIs,
trampoline relocation, exception re-arming, register preservation, DLL lifetime,
or actual timing. The supplied Windows runner and manual-dispatch workflow are
provided to establish those results next. The first expected acceptance run is:

    python scripts/bench.py --bin build/Release --correctness-only

Do not treat the source as production instrumentation or reuse the single-thread
software breakpoint handler in an arbitrary multithreaded target.

# Windows validation, 4 November 2026

Host: Windows 10 Pro 22H2 (10.0.19045) guest on Proxmox VE 8.2 (KVM, `cpu: host`),
Intel Core i5-6600 @ 3.30 GHz, 4 vCPUs, 8 GB RAM. Native x64, not emulation.
Toolchain: VS 2022 Build Tools, MSVC 14.44.35207, Windows SDK 10.0.26100,
CMake 4.4.5 (Visual Studio 17 2022 generator), Python 3.12.10, SafetyHook v0.7.0.

Fix required to pass: CMake ignores `.def` sources on executables, so
`probe_target.exe` exported nothing and both external debugger modes failed with
`fixture export (Win32=127)`. The module definition is now passed with `/DEF:`.
Remaining build noise: MASM warning A4018 for `/wd4201`, which Zycore adds as a
PUBLIC compile option; harmless.

Executed, all passing:

- `ctest` (portable policy tests) and the four Python oracle tests.
- `probe_target.exe disabled reads 20 mutate memory 0 prehook`: zero enabled
  iterations, zero reads, zero existing-hook calls.
- `bench.py --correctness-only`: 20/20 cases (baseline, inline, veh-sw,
  debug-sw, debug-hw x register/memory mutation x clean/prehook), including the
  exactly-once existing-hook count and independent record digests. The prehook
  read site was classified `relative-jump` (`e9...`) before our probe installed.
- `bench.py` default run (2000 micro / 200 reads iterations, 3 repeats), all
  rows re-validated. Raw results: `measurements/2026-11-04-vm103-default/`.

Measured ns per iteration (median of 3, baseline-subtracted). This is a VM on a
desktop CPU with only 3 repeats: a first indication, not a reference figure.

| Mode | micro noop (1 probe) | reads mutate, clean (2 probes + syscall) | reads mutate, prehook |
|---|---|---|---|
| inline (SafetyHook mid-hook) | ~40 | ~260 | ~235 |
| veh-sw (in-process INT3) | ~9,300 | ~19,700 | ~19,400 |
| debug-hw (external DR0/DR1) | ~67,000 | ~137,000 | ~133,000 |
| debug-sw (external INT3 + step) | ~160,000 | ~333,000 | ~323,000 |

Not yet covered: new-process-by-name attach, deferred `module+RVA` probes and
load-triggered activation (handoff milestone), register/flags preservation
beyond the flag result, SIMD/AVX state, multithreaded targets, longer runs.

# Windows validation, 4 November 2026 (gated scenario)

Same host/toolchain as above. Built and run clean on Windows x64:

- Full CMake build of all targets including the new configparse.dll, probe_app,
  probe_session.
- ctest: policy unit test passes (the only CTest gate; the end-to-end scenario is
  run on demand, deliberately not a CTest/CI gate).
- scripts/check_scenario.py (threads 4 and 8): shipped config gates the workload
  off (0 reads); the deferred configparse.dll+RVA probe is pending pre-load,
  activates on LOAD_DLL before ParseConfig, overrides the parsed flag exactly once,
  and all reads then run and verify; the on-attach on-disk comparison reports
  PRE-EXISTING HOOK for --prehook and clean for --clean.

Scope/known gaps (see docs/review-findings.md): the scenario does not yet arm a
read-path probe, so read interception and the shared callback are not exercised
by it; record_digest is x64/single-thread only; several multithread and deferred-
identity cases are enumerated but unbuilt. No benchmarks were run for this commit.
