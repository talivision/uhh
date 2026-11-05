# bigapps -- stability on real, large programs

Inputs for the opt-in suite tier `scripts/regress.py --bigapps` (slow: about 15-20 minutes on
x64). It runs real shipped Windows programs under `uhh_trace` on every backend:

| app | why | modes |
|---|---|---|
| `powershell.exe` + `workload.ps1` | .NET JIT, runspace-pool threads, dynamic script blocks, first-chance .NET exceptions, child job processes; the 32-bit SysWOW64 host on the x86 build | launch, attach (run to exit), attach + detach mid-run |
| `msedge.exe --headless --dump-dom` of `page.html` from a local server | multi-process browser, V8 JIT in the renderer, network/IPC in the browser process (`/slow` holds the load event open); x64 only | launch, attach (run to exit), attach + detach mid-run |

Probes (busy system exports, at most 4 so the hw backend fits):
`ntdll!NtCreateFile:xxO`, `KernelBase!CreateFileW:Wxx` (logged), `ntdll!NtAllocateVirtualMemory:-`,
`kernel32!HeapAlloc:-` (a forwarded export -> `ntdll!RtlAllocateHeap`, count only); Edge swaps
CreateFileW for `ws2_32!connect:xSd` (not required to hit: the network service may be out of process).

Each run asserts: the program's own self-check is right (`BIGAPPS_DONE ... bad=0`, or the JS result
and 40/40 fetches in the dumped DOM) and it exits 0; no `probe: ... target crashed` (second-chance)
line; every required probe hit; `log_dropped == 0`; `logs_written ==` the logged probes' hits
(runs to exit) and every written log reached stdout; after a detach the program keeps working
(PowerShell keeps ticking, Edge finishes its page) and exits 0.

```sh
python scripts/regress.py --bin build-x64/Release --only bigapps --bigapps            # all
python scripts/regress.py --bin build-x64/Release --only bigapps --bigapps ps-detach   # a subset
```

Only processes the check started are killed (matched by its own per-run directory).
