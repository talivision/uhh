# gated_config_mem: turn on a disabled feature by patching MEMORY

The same scenario as [`gated_config`](../gated_config/README.md) -- `probe_app`'s config
ships `reads_enabled=0`, and we turn the feature on from outside and log every read -- but
the flag is flipped by writing the target's memory instead of a register.

| | `gated_config` | `gated_config_mem` |
|---|---|---|
| site | `configparse.dll!ParseConfig+0x16` | `configparse.dll!ParseConfig+0x18` |
| state at the site | parsed flag in EAX, not yet stored | flag already stored to `*out`; BX (rbx/ebx) points at `out` |
| callback | `enable_reads`: `set_reg(AX, 1)` | `enable_reads_mem`: `get_mem(BX)` -> 0 ? `set_mem(BX, 1)` |
| visible in the report | `"overrides":1` | a `probe_log` "flag flipped in memory at 0x..." |

`+0x18` is one instruction (`mov dword ptr [rbx], eax`, 2 bytes) after `+0x16` on both x64
and x86, so the location string is the same on both. The rest -- the `ntdll!NtOpenProcess`
handle -> pid map (UHH_SHARED, any backend mix) and logging every `ntdll!NtReadVirtualMemory`
-- is shared with `gated_config` (`examples/gated_config/callbacks.cpp`).

```powershell
$bin = "build-x64\Release"     # or build-x86\Release
& "$bin\gated_config_mem.exe" configparse.dll!ParseConfig+0x18 ntdll.dll!NtReadVirtualMemory `
    -- "$bin\probe_app.exe" --no-wait --helpers 4 --threads 8 --reads 1000
```

Expected: one `flag flipped in memory` log, the app line shows `"reads_enabled":1` and
`successful_reads` = threads x reads, the `NtReadVirtualMemory` probe's `hits` and the read
logs equal that, and `"log_dropped":0`. Any `--flag-backend` works (breakpoint, hw, inline).

Tested by `scripts/regress.py` (`gated-mem-*`).
