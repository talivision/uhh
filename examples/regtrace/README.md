# regtrace: registry reads and writes by key name

```sh
regtrace [--backend b] [--open-backend b] [--value-backend b] [--close-backend b] \
         [--filter TEXT] -- <target.exe> [args]          # b = breakpoint | hw | inline
regtrace --filter UHHTest -- regtrace_target.exe
```

A value operation carries only a key handle. The name exists only at the open, so:

- **open group:** `ntdll!NtOpenKey`, `NtOpenKeyEx` and `NtCreateKey` share one callback
  body. It reads `OBJECT_ATTRIBUTES` and runs the real open with `call_original`, then maps
  handle -> full name and returns the real status with `return_from` (x86 `__stdcall`: 3, 4
  and 7 arguments). `RegOpenKeyEx(HKCU, "Software\\X")` opens a name *relative* to the real
  HKCU handle, so the root's mapped name (`\REGISTRY\USER\S-1-5-..`) is prefixed to it.
- **value group:** `NtQueryValueKey` and `NtSetValueKey` log `key=.. handle=.. value=..`.
- **close:** `NtClose` forgets the handle.

The map is `UHH_SHARED`, so the groups may use different backends. Hardware has only 4
debug registers, and `call_original` on hw needs one free while it runs. hw therefore
takes the open group (3 + 1 free) or the value and close probes (3), never all six.
`--backend hw` is refused with that reason. An inline open group goes live at the target's
entry point. Value operations on keys the loader opened before then therefore log
`key=?` (seen when the value group is breakpoint/hw).

`regtrace_target` is the fixture. Under `HKCU\Software\UHHTest`, each thread creates its own
subkey, sets values, reopens the subkey read-only and queries the values back. It also
queries a value that does not exist and opens a key that does not exist, and it deletes
the tree at exit. It prints its own ground truth (`rt_key`, `rt_value`, `rt_done`); regress
`newapp-reg-*` compares the tool's log with it.
