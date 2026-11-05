# detours_withdll — Detours' `withdll` / `setdll` on UHH: launch vs attach

## The Detours originals

- [`samples/withdll`](https://github.com/microsoft/Detours/tree/main/samples/withdll):
  `withdll.exe /d:trace.dll prog.exe` starts the program suspended with
  `DetourCreateProcessWithDllEx`, which rewrites the import table in memory so the
  instrumentation DLL loads before any of the program's own code runs.
- [`samples/setdll`](https://github.com/microsoft/Detours/tree/main/samples/setdll):
  `setdll.exe /d:trace.dll prog.exe` makes the same import-table change **on disk**, so
  every later start of the program is instrumented.

Neither covers a process that is **already running**; for that, Detours users write their
own `CreateRemoteThread(LoadLibrary)` injector.

## The UHH version

There is no DLL to inject by hand and no binary to patch: the session does both modes.

| Detours | UHH |
|---|---|
| `withdll /d:x.dll prog` (instrumented from the first instruction) | `detours_traceapi -- prog` → `probe_launch` |
| `setdll` (instrument every future start) | `detours_traceapi --attach-new prog.exe` → `probe_attach_new` (the next start; nothing on disk changes) |
| hand-written remote-thread injector | `detours_traceapi --attach <pid>` → `probe_attach` |
| `FreeLibrary` the hook DLL / unhook | `--detach-after-ms N`: `probe_close` while the target runs (hooks removed, INT3s restored, debug registers cleared) |

It is the same driver and callback as `../detours_traceapi` (`traceapi_driver.cpp`,
`traceapi_callbacks.cpp`): one callback source, every backend, launch or attach.

One difference from `withdll` found here (docs/ROADMAP.md, D1): `probe_launch` does not
pass the caller's stdin to the program — it gets a private pipe holding one `\n` (the gate
keystroke for `probe_app`) that stays open, so a program that reads stdin to EOF (`sort`,
`findstr`, `more`) waits forever. `detours-launch-stdin-*` checks this. Attach is not
affected (the program keeps its own handles). Also (D2) the launched program shares the
controller's stdout with the live log tail: a program that writes partial lines gets
records spliced into them.

## The checks (`scripts/regress.py --only detours_withdll`)

- `detours-withdll-<backend>` (hw in groups of ≤4, plus `mix`): `detours_target api --gate`
  is traced twice — launched under the driver, and started on its own then attached by pid
  while it waits at its gate (released only once every probe reports active). The two
  traces of the workload (handle values masked) must be **identical**, except for exactly
  the one registry open + query the target makes before its gate, which only the launch can
  see. The attached target's self-checks pass.
- `detours-withdll-detach-<backend>`: attach mid-run (no gate) to the target busy on four
  threads (files, registry, `LoadLibrary`, a child process), trace for 2.5 s, then detach
  while it keeps running. The target must finish with every self-check passing (data read
  back == written, registry value == the pre-attach value, child exit code 7) and exit 0.

```
start build-x64\Release\detours_target.exe api --gate
build-x64\Release\detours_traceapi.exe --backend inline --attach <pid>
```
