# detours_traceapi — Detours' `traceapi` sample on UHH

## The Detours original

[`samples/traceapi`](https://github.com/microsoft/Detours/tree/main/samples/traceapi)
detours ~1400 Win32 APIs in one DLL. Each detour formats its arguments (strings
dereferenced), calls the trampoline, logs the return value, and sends the lines to the
`syelogd` log daemon over a named pipe. It is injected with `withdll.exe`.

## The UHH version

| Detours | UHH |
|---|---|
| one hand-written detour per API | one callback, `dtrace_on_call`; the probe's config says which API it is |
| `DetourAttach` ×N in a transaction | `probe_add_symbol_cfg(s, "KernelBase.dll!<Api>", dtrace_on_call, backend, &cfg, ...)` ×N |
| dereference `LPCWSTR` arguments | `get_func_arg` + `get_mem` (read in 64-byte chunks; element-wise across an unreadable page) |
| `syelog` pipe + `syelogd.exe` | `send_log`: JSONL file + live stdout tail, lossless |
| `withdll.exe /d:trcapi.dll prog` | `detours_traceapi -- prog` (`probe_launch`) |
| (inject into a running process: not in the samples) | `detours_traceapi --attach <pid>` (`probe_attach`), see `../detours_withdll` |

Traced: `CreateFileW` (path, access, disposition), `ReadFile` / `WriteFile` (handle, size,
and the first 16 bytes written), `CloseHandle`, `RegOpenKeyExW` (root key, subkey, access),
`RegQueryValueExW` (value name), `CreateProcessInternalW` (application, command line),
`LoadLibraryW`, `LoadLibraryExW`.

All probes sit in **KernelBase**: on Windows 10+ kernel32/advapi32 only forward or `jmp`
there, so a call is seen once whichever DLL or API set the program imported it from.
`CreateProcessW` is traced at `CreateProcessInternalW` because x64 `kernel32!CreateProcessW`
calls that directly and never reaches `KernelBase!CreateProcessW` (on x86 it jumps to
KernelBase): only the internal function sees every caller on both arches.

Backends: `--backend breakpoint|hw|inline` puts every probe on one backend; `--backend mix`
rotates breakpoint/hw/inline over the probes in one session. `hw` has four debug registers,
so with `--backend hw` choose at most four APIs with `--only`.

Return values are the subject of `../detours_retval`.

## The checks (`scripts/regress.py --only detours_traceapi`)

- `detours-traceapi-<backend>` (hw in three groups `-g1..g3`, plus `mix`): `detours_target api`
  on 4 threads × 5 iterations. The trace holds **exactly** the workload calls the target
  reports (creates by disposition, 1337-byte reads, writes whose preview is the payload,
  `CurrentVersion` opens, `ProductName` queries, `version.dll` loads, the `cmd /c exit 7`
  child) plus the single registry read the target makes before its workload; `CloseHandle`
  ≥ the target's closes; the target's own self-checks and counters equal an uninstrumented
  run; probe hits == log lines; nothing dropped.
- `detours-traceapi-{type,reg,spawn}-<backend>`: real system programs — `cmd /c type
  <file>`, `reg query HKLM\...\CurrentVersion /v ProductName`, `cmd /c "cmd /c exit 3"`.
  Their console output and exit code equal an uninstrumented run, and the trace contains
  the expected decoded call (the file path, the key and value name, the child command line).

```
build-x64\Release\detours_traceapi.exe --backend mix -- C:\Windows\System32\reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName
```
