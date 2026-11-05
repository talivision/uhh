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
checksums of its mapped `.text` section and the first 32 bytes of `guarded_fn`. Right
after release, and again halfway through the calls, it checks for instrumentation:
both checksums, the first 8 bytes of `guarded_fn` against the executable FILE on disk
(`fn_disk_ok`; catches a patch made before the in-memory baseline), and the main
thread's DR7 read by a helper thread through `GetThreadContext`
(`debug_registers_seen`).

**Tamper response:** from the first detection on, the target takes a different path:
`guarded_fn` is still called `N` times, but with `-1` instead of the loop index, and
the summary says `"path":"tampered"` with what detected it and when.

CLI:

```text
antitamper_target.exe [--calls N] [--no-wait]
```

```json
{"kind":"target","name":"antitamper","calls":N,"text_ok":B,"fn_bytes_ok":B,"text_changed_at":"none|before|middle|after","debug_registers_seen":B,"fn_disk_ok":B,"path":"clean|tampered","detected_by":"none|code|debug_registers|code+debug_registers","detected_at":"none|before|middle"}
```

What each backend makes visible (asserted by `regress.py`, `antitamper-*`):

| Run | Code bytes changed | DR7 set | Result |
|---|---|---|---|
| no UHH (baseline) | no | no | `clean`, `guarded_fn(i)` |
| breakpoint (INT3) | yes: `0xCC` at the probe, vs disk | no | `tampered`, `code` at `before`, every call `guarded_fn(-1)` |
| inline | yes: the hook's jump, vs disk | no | `tampered`, `code` at `before`, every call `guarded_fn(-1)` |
| hw | **no** | yes | `tampered`, `debug_registers` at `before`, every call `guarded_fn(-1)` |

The in-memory `.text` checksum alone does NOT see the INT3 or the inline hook: both are
in place before the target takes its baseline (launch arms them at process creation /
holds the entry point until the hooks are in). Only the disk comparison does.

## `antidebug_target.c`

Hook point: `timed_fn(int)`. The target reads common debugger indicators
(`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` debug
port / debug object / debug flags, PEB `BeingDebugged` and `NtGlobalFlag & 0x70`).

**Anti-debug response:** if any indicator is set it takes a different path: `timed_fn`
is called with `-1` instead of `17`, and the summary says `"path":"debugger"`.

CLI:

```text
antidebug_target.exe [--no-wait]
```

```json
{"kind":"target","name":"antidebug","is_debugger_present":B,"remote_debugger_present":B,"debug_port":B,"debug_object_handle":B,"debug_flags_zero":B,"peb_being_debugged":B,"peb_nt_global_flag_heap_debug":B,"timed_fn_ns":N,"path":"clean|debugger"}
```

What each backend makes visible (asserted by `regress.py`, `antidebug-*`): a baseline
run reports every indicator false and `clean`. UHH launches (and attaches to) every
target as a **debugger**, whatever the backend: breakpoint and hw need it for their
exceptions, and inline's controller is the same debugger. So under breakpoint, hw and
inline the debugger is visible: `IsDebuggerPresent`, the remote check, debug port,
debug object, debug flags and PEB `BeingDebugged` are all true, the target takes the
`debugger` path and the probe logs `timed_fn(-1)`. (`NtGlobalFlag`'s heap-debug bits
are reported, not asserted.) UHH deliberately does not hide the debugger.

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
