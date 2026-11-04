# Real-world instrumentation targets

These programs are test targets, not users of the UHH API. Each is a plain console
executable built only with the Windows SDK and CRT. Hook points are exported and
non-inlined so a harness can address them as `exe!FunctionName`.

All targets accept `--no-wait`. Without it, the target writes exactly

```json
{"kind":"waiting"}
```

to stdout, flushes, and reads one byte from stdin. The harness should install its
instrumentation before writing that byte. A successful target then writes exactly one
additional line: the target result described below. Diagnostics are written only to
stderr. Invalid arguments or an internal workload failure produce a nonzero exit code.

## `reentrancy_target.c`

Hook point: `reent_marker(int i)`. The workload also calls the UCRT `malloc` and `free`
once per iteration. Allocation sizes cycle through 16, 64, 256, and 4096 bytes.

CLI:

```text
reentrancy_target.exe [--iters N] [--threads T] [--no-wait]
```

`--iters` defaults to 10000 and `--threads` defaults to 4. The exact result shape and
field order are:

```json
{"kind":"target","name":"reentrancy","iters":N,"threads":T,"mallocs":N*T,"frees":N*T,"marker_calls":N*T}
```

Harness assertion: exit code is zero; `mallocs == frees == marker_calls == iters *
threads`; and a hook on `malloc` whose callback allocates or logs completes without
recursion, deadlock, or process failure.

## `thread_stress_target.c`

Hook point: `stress_work(int tag)`. Phase A releases `M` already-created threads
together, with `K` calls per thread. Phase B creates 32 suspended threads and resumes
them together, also with `K` calls each. Phase C submits 256 Windows thread-pool
callbacks. Phase D creates and joins 200 one-call threads sequentially.

CLI:

```text
thread_stress_target.exe [--many M] [--calls K] [--no-wait]
```

`--many` defaults to 128 and `--calls` defaults to 50. The exact result is:

```json
{"kind":"target","name":"thread_stress","phase_a":M*K,"phase_b":32*K,"phase_c":256,"phase_d":200,"total_calls":M*K+32*K+256+200}
```

The expressions above denote JSON integer values, not strings. Harness assertion: exit
code is zero; `phase_a == many * calls`, `phase_b == 32 * calls`, `phase_c == 256`,
`phase_d == 200`, and `total_calls` is their sum. The observed hook count should equal
`total_calls`, with no missed lifecycle events or crashes.

## `antitamper_target.c`

Hook point: `guarded_fn(int)`. Before the stdin gate, the target records FNV-1a
checksums of its mapped `.text` section and the first 32 bytes of `guarded_fn`. It checks
both again immediately after release, halfway through the calls, and after all calls.
A helper thread suspends the main thread halfway through and reads its debug-register
context; `debug_registers_seen` is true when `Dr7` is nonzero.

CLI:

```text
antitamper_target.exe [--calls N] [--no-wait]
```

`--calls` defaults to 100. The exact result is:

```json
{"kind":"target","name":"antitamper","calls":N,"text_ok":true|false,"fn_bytes_ok":true|false,"text_changed_at":"none|before|middle|after","debug_registers_seen":true|false}
```

Harness assertion depends on hook type. With no hook, require `text_ok` and
`fn_bytes_ok` true, `text_changed_at == "none"`, and `debug_registers_seen == false`.
For a persistent inline or `INT3` patch installed while waiting, require a code checksum
failure (normally `text_changed_at == "before"`). For a hardware breakpoint, require
the code checksums to remain true and `debug_registers_seen == true`. In all cases,
require exit code zero and `calls == N`.

## `antidebug_target.c`

Hook point: `timed_fn(int)`. This target reports common debugger indicators but never
changes behavior because of them. `NtQueryInformationProcess` is resolved dynamically
from `ntdll`; the PEB address comes from `ProcessBasicInformation`. The
`peb_nt_global_flag_heap_debug` field represents `(NtGlobalFlag & 0x70) != 0`.

CLI:

```text
antidebug_target.exe [--no-wait]
```

The exact result is:

```json
{"kind":"target","name":"antidebug","is_debugger_present":true|false,"remote_debugger_present":true|false,"debug_port":true|false,"debug_object_handle":true|false,"debug_flags_zero":true|false,"peb_being_debugged":true|false,"peb_nt_global_flag_heap_debug":true|false,"timed_fn_ns":N}
```

Harness assertion: exit code is zero, every named check is a JSON boolean, and
`timed_fn_ns` is a nonnegative JSON integer. A baseline no-debugger run should report
all seven booleans false. Instrumented runs should assert the expected visibility policy
for the particular backend rather than treating any one anti-debug signal as universally
required. A harness breakpointing `timed_fn` may additionally compare `timed_fn_ns`
against a separately measured baseline threshold.

## `exceptions_target.cpp`

Hook points: `throws_cpp(int depth)`, `throws_seh(int depth)`, and
`calls_through(int n)`. `throws_cpp` recurses eight times and then throws
`std::runtime_error` (nine invocations including the base case). `throws_seh` likewise
recurses eight times, raises `0xE0000001`, and is caught by a separate SEH-only helper.
`calls_through` invokes an indirect callback that throws a C++ exception through its
frame. C++ objects and `__try`/`__except` are kept in separate functions for MSVC.

CLI:

```text
exceptions_target.exe [--iters N] [--no-wait]
```

`--iters` defaults to 200. The exact result is:

```json
{"kind":"target","name":"exceptions","cpp_caught":N,"seh_caught":N,"through_caught":N,"iters":N}
```

Harness assertion: exit code is zero and `cpp_caught == seh_caught == through_caught ==
iters`. Run with each exported function hooked; a trampoline with incorrect x64 unwind
metadata or broken x86 frame behavior must not be accepted if the process crashes or any
count is short.
