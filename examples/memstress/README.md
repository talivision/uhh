# Memory read/write stress test

`memstress` drives the same exported `ms_on_site` callback through UHH's software
breakpoint, hardware execute-breakpoint, and inline backends. The callback source is
compiled into both the driver and `probe_api_agent`; no backend-specific callback path
is used.

## CLI

```text
memstress_driver --backend breakpoint|hw|inline [--throughput] -- <memstress_target.exe> [target args]
```

Target arguments are `--threads T` (default `8`), `--iters N` (default `20000`), and
`--no-wait`. Without `--no-wait`, the target prints `{"kind":"waiting"}`, flushes
stdout, and waits for one byte on stdin before creating the workers. This is useful for
an interactive or harness-controlled start gate.

Examples from a build output directory:

```powershell
.\memstress_driver.exe --backend breakpoint -- .\memstress_target.exe --no-wait
.\memstress_driver.exe --backend hw         -- .\memstress_target.exe --threads 8 --iters 20000 --no-wait
.\memstress_driver.exe --backend inline     -- .\memstress_target.exe --threads 8 --iters 20000 --no-wait
```

`--throughput` sets a callback config flag that performs
`MEMSTRESS_THROUGHPUT_REPEATS` (currently `1`) additional `get_mem` call of each size
1, 8, 64, 4096, and 65536 bytes per hit. Use a deliberately smaller hit count for a
throughput run; the target's `elapsed_ns` covers the complete worker interval:

```powershell
.\memstress_driver.exe --backend inline --throughput -- .\memstress_target.exe --threads 1 --iters 1000 --no-wait
```

For inline, the driver passes exactly `PROBE_INLINE`; it does not request a hardware
fallback.

## JSON and callback logs

The target emits exactly one final JSON line (in addition to the optional waiting
line):

```json
{"kind":"target","name":"memstress","threads":8,"iters":20000,"calls":160000,"write_ok":160000,"untouched_ok":true,"cross_ok":160000,"readonly_intact":true,"elapsed_ns":123456789}
```

`probe_report` then emits the callback logs, the probe row, and its final report row.
The callback logs a cumulative summary every 4096 hits and once on the final hit:

```text
memstress reads_ok=160000 reads_bad=0 writes=160000 cross_ok=160000 fault_reads_failed_closed=160000 ro_writes_failed_closed=160000
```

The counters are intentionally not read from the driver. For breakpoint/HW they live
in the driver copy of the callback; for inline they live in the agent copy. A harness
must parse the last (largest cumulative) `probe_log` summary.

## Exact pass criteria

For each architecture (`x64` and `Win32`) and each backend (`breakpoint`, `hw`, and
`inline`), let `calls = T * N`. A run passes only when all of the following hold:

- the driver exits `0`;
- the target row has the requested `threads` and `iters`, `calls == T * N`,
  `write_ok == calls`, `cross_ok == calls`, `untouched_ok == true`, and
  `readonly_intact == true`;
- the final callback summary has `reads_ok == calls`, `reads_bad == 0`,
  `writes == calls`, `cross_ok == calls`, `fault_reads_failed_closed == calls`, and
  `ro_writes_failed_closed == calls`;
- the single visible probe row reports the requested backend and `hits == calls`;
- the `probe_report` row has `hits == calls`, `log_dropped == 0`, `app_exit == 0`,
  and `error == null`.

Thus every success/fail-closed count other than `reads_bad` must equal `calls`, and
`reads_bad` must be zero. `elapsed_ns` is informational and must be positive.

## CMake snippet

Paste the following after `probe_api_agent` has been declared. It adds the callback
source to the agent DLL as well as to the driver executable.

```cmake
target_sources(probe_api_agent PRIVATE
    examples/memstress/memstress_callbacks.cpp)
target_include_directories(probe_api_agent PRIVATE examples/memstress)

add_executable(memstress_target
    examples/memstress/memstress_target.c)
target_compile_features(memstress_target PRIVATE c_std_11)
target_compile_options(memstress_target PRIVATE /W4)

add_executable(memstress_driver
    examples/memstress/memstress_driver.cpp
    examples/memstress/memstress_callbacks.cpp)
target_include_directories(memstress_driver PRIVATE include examples/memstress)
target_link_libraries(memstress_driver PRIVATE probe_api)
set_target_properties(memstress_driver PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
target_compile_options(memstress_driver PRIVATE /W4)
target_compile_definitions(memstress_driver PRIVATE _CRT_SECURE_NO_WARNINGS)
add_dependencies(memstress_driver memstress_target probe_api_agent)
```
