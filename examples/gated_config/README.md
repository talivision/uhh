# gated_config: turn on a disabled feature from outside and log it

## The technique

`probe_app` (in `examples/targets/probe_app`) has a feature that ships **disabled in
its config**. After a keystroke it late-loads `configparse.dll`, calls `ParseConfig`
on `reads_enabled=0`, and stops there. Only when the parsed flag is 1 does it open its
helper processes and read their memory from many threads.

You want metrics on that code path (which processes it reads, where, how often)
without rebuilding the target, editing its config, or patching its files:

1. **Flip the flag at the point it is parsed.** A breakpoint at
   `configparse.dll!ParseConfig+0x16` lands on the instruction that stores the parsed
   value; EAX holds it. `enable_reads` changes EAX from 0 to 1 and the target goes on
   to store "enabled" as if its config had said so. The probe is registered before
   the DLL exists in the process; it stays pending and arms when the DLL loads.
2. **Observe the path you enabled.** `track_open_process` on `ntdll.dll!NtOpenProcess`
   learns which pid each new process handle belongs to, and `log_read` on
   `ntdll.dll!NtReadVirtualMemory` logs every read as
   `read handle=0x.. pid=.. addr=0x.. size=..`. Both are the ntdll syscall stubs, so every
   caller is seen whichever wrapper it used (ReadProcessMemory, a direct ntdll call, a
   wrapper you do not know about) -- under every backend, inline included.

Do not "simplify" this by putting `reads_enabled=1` in the config: the whole point is
enabling a normally-off path from outside, without touching the target.

### Why `ParseConfig+0x16`

`ParsedFlagSite` is not exported, so it would normally need an RVA from the linker map
(`configparse.dll+0xRVA`). `ParseConfig` is written in assembly
(`examples/targets/configparse/parse_*.asm`) so that every instruction before the
site has a fixed encoding and the site is at the same offset, `+0x16`, from the
exported `ParseConfig` on **both x64 and x86**. That gives a location string that is
stable across builds and needs no map. `scripts/regress.py` (`sites`) checks the
offset against the map on every run.

### Handle -> pid

At `NtOpenProcess(PHANDLE out, access, attributes, CLIENT_ID *cid)` entry the pid is
known (`cid->UniqueProcess`) but the handle is not: the kernel writes it to `*out`
during the call. `track_open_process` remembers `(pid, out)`; when `log_read` meets a
handle it has not seen, it dereferences the remembered `out` pointers with `get_mem`
to find which open produced it, and caches the answer. This relies on `*out` still
holding the handle when the read happens: `probe_app` calls `NtOpenProcess` directly
with `out` pointing at a long-lived variable. **Limitation:** through
`kernel32!OpenProcess` the out pointer is a stack local inside KernelBase that is reused
as soon as `OpenProcess` returns, so a lazily dereferenced pointer can read garbage; such
reads log `pid=0`. Capturing the handle at the stub's return instead is on the roadmap. The callbacks are lock-free, so the same source runs on the controller's
debug loop (breakpoint / hw) and on many target threads at once (inline).

## Usage

```
gated_config [--flag-backend b] [--read-backend b] [--no-log]
             <flag_location> <read_location> -- <target.exe> [target args]
```

- `b` = `breakpoint` | `hw` | `inline`. Defaults: flag `breakpoint`, reads `inline`.
  The NtOpenProcess probe uses the read backend, so its map lives in the same address
  space as `log_read` (the controller for breakpoint/hw, the target for inline).
- Locations are UHH location strings: `module!Export+0xOFF` or `module+0xRVA`.
- `--no-log`: count hits only (used to measure per-log overhead).

```powershell
$bin = "build-x64\Release"     # or build-x86\Release
& "$bin\gated_config.exe" configparse.dll!ParseConfig+0x16 ntdll.dll!NtReadVirtualMemory `
    -- "$bin\probe_app.exe" --no-wait --helpers 4 --threads 8 --reads 1000
```

Output (JSON lines): probe_app's `helper` / `waiting` / `app` lines, then one
`probe_log` per read, then the report. Expected: `"overrides":1` in `probe_report`
(the flag was flipped once), the `ntdll.dll!NtReadVirtualMemory` probe's `hits` equal to
`threads * reads`, the app's `successful_reads` the same, one log per read with a
non-zero `pid`, and `"log_dropped":0`. Without the flag probe (run `probe_app.exe
--no-wait` alone) the app line shows `"reads_enabled":0,"opened":0,"successful_reads":0`.

`--no-wait` only skips probe_app's own keystroke wait; UHH holds a launched target at
its entry point until inline probes are installed, so no read is missed either way.

## Tested by

`scripts/regress.py`: `sites`, `gated-off`, `mix flag=* read=*` (all 9 backend
pairs), `exact-*` (hits == logs == reads, no unmapped pid, no drops),
`log-throughput-*`, and the opt-in `volume-*`.

### Inline hooks on ntdll syscall stubs

A syscall stub shares its page with the very routines a hook installer calls
(`NtProtectVirtualMemory` sits next to `NtReadVirtualMemory`). UHH writes an inline hook
only while the controller -- a debugger -- holds every other thread of the target
suspended: the page stays executable, nothing runs while the bytes change, and a thread
caught inside the overwritten instructions is moved to the same instruction in the
hook's trampoline. The freeze lasts only for the write (install/remove), never per hit.
`ntdll-churn-*` and `patch-race-*` in `scripts/regress.py` test this.
