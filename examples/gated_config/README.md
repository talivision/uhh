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
2. **Observe the path you enabled.** One callback on `ntdll.dll!NtOpenProcess`
   (`track_open_process`) runs the real open with `call_original`, so the new handle
   (`*out`) and the pid (`CLIENT_ID`) are both in hand at once, records handle -> pid ->
   name (image name from the kernel by pid, without opening it), logs
   `open pid=.. name=..` and `map handle=0x.. -> pid=.. name=..`, and returns the real
   status with `return_from`. The pid cannot be recovered from the handle later (helpers
   are opened with only `PROCESS_VM_READ`), so it is captured at the open -- for any
   caller, including `kernel32!OpenProcess` whose output slot dies as it returns.
   `log_read` on `ntdll.dll!NtReadVirtualMemory` logs every read as
   `read handle=0x.. pid=.. name=.. addr=0x.. size=..`. Regress `gated-map` checks every
   map and read line against the handle the target's open really returned. Both are the
   ntdll syscall stubs, so every
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

A read carries only a handle, and a handle opened with just `PROCESS_VM_READ` cannot be
asked for its pid. The pid exists only at the open (`cid->UniqueProcess` of
`NtOpenProcess(PHANDLE out, access, attributes, CLIENT_ID *cid)`), the handle only after
it. `track_open_process` therefore runs the open itself with `call_original`, reads the
handle from `*out` right away, records handle -> pid -> name, and hands the caller the real
status with `return_from` (the open is not run again). This works for every caller,
including `kernel32!OpenProcess`, whose `out` is a short-lived local. If `call_original` is
ever refused, the open runs normally and is logged as `unmapped` (breakpoint/hw no longer
refuse it under CET shadow stacks: ROADMAP CO5).

### Inline hooks on ntdll syscall stubs

A syscall stub shares its page with the very routines a hook installer calls
(`NtProtectVirtualMemory` sits next to `NtReadVirtualMemory`). UHH writes an inline hook
only while the controller -- a debugger -- holds every other thread of the target
suspended: the page stays executable, nothing runs while the bytes change, and a thread
caught inside the overwritten instructions is moved to the same instruction in the
hook's trampoline. The freeze lasts only for the write (install/remove), never per hit.
`ntdll-churn-*` and `patch-race-*` in `scripts/regress.py` test this.
