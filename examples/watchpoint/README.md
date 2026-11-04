# Hardware data watchpoint

Fire a callback when a **memory address is written** — not when code executes. This is
something inline/trampoline hooking (Frida's `Interceptor`, Detours, MinHook) **cannot
do**: a trampoline intercepts code at a function, never a plain data store. UHH does it
with a debug register programmed as a *data* breakpoint, so **no code is modified** and
it is exact under multithreading, just like the execute breakpoints.

```c
/* Break whenever the dword at this address is written. */
probe_add(s, "watch_target.exe+0x40a0", on_write, PROBE_HW | PROBE_WATCH_WRITE);
/* or PROBE_HW | PROBE_WATCH_RW to also trap reads. */
```

- The location is a **data** address (a variable's `module+RVA`), dword-aligned.
- `PROBE_WATCH_WRITE` traps writes; `PROBE_WATCH_RW` traps reads and writes.
- Uses one of the 4 debug-register slots (shared with execute hardware breakpoints).
- The callback runs controller-side (the hardware backend is an external debugger), so
  no agent is injected.

## Target + driver

`watch_target` writes a single aligned global `g_watched` from W worker threads;
`watch_driver` sets a write-watchpoint on it and counts callbacks — one per store.

```powershell
cmake -S . -B build-x64 -G "Visual Studio 17 2022" -A x64
cmake --build build-x64 --config Release --target watch_driver watch_target
$rva = (python scripts\site_rvas.py build-x64\Release\watch_target.map g_watched | ConvertFrom-Json).g_watched
build-x64\Release\watch_driver.exe $rva --no-wait --threads 4 --writes 1000
```

Expected: the probe's hit count equals the number of writes (4 × 1000 = 4000), exactly.
Verified on the VM: 4 threads × 1000 writes → `hits: 4000`, `callback_hits: 4000`.
