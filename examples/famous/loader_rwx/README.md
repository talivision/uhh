# Loader and unpacker signals (LoadLibrary tracker + RWX watcher)

## The original recipes

API Monitor's "Library loading" filter (`LoadLibraryExW`, `LdrLoadDll`) and the Frida
scripts malware analysts use to catch unpackers and shellcode loaders: alert on any
memory that becomes writable **and** executable.

```js
Interceptor.attach(Module.getExportByName('ntdll.dll', 'LdrLoadDll'), {
  onEnter(args) { const us = args[2];
                  console.log('load', us.add(Process.pointerSize).readPointer().readUtf16String(us.readU16() / 2)); }
});
Interceptor.attach(Module.getExportByName('ntdll.dll', 'NtProtectVirtualMemory'), {
  onEnter(args) { if (args[3].toInt32() === 0x40)            // PAGE_EXECUTE_READWRITE
                    console.log('RWX', args[1].readPointer(), args[2].readPointer()); }
});
// ... and the same on NtAllocateVirtualMemory's Protect (arg 5)
```

## UHH mapping (`loader_callbacks.cpp`)

| Probe | Callback | Log |
|---|---|---|
| `kernelbase.dll!LoadLibraryExW` | `famous_loader_on_loadlibrary`: `famous_read_wstr(arg 0)`, flags arg 2 | `loadlibraryexw name= flags=` |
| `ntdll.dll!LdrLoadDll` | `famous_loader_on_ldrloaddll`: `UNICODE_STRING*` arg 2 | `ldrloaddll name=` |
| `ntdll.dll!NtAllocateVirtualMemory` | Protect (arg 5) is `PAGE_EXECUTE_READWRITE`/`WRITECOPY`: `*BaseAddress`, `*RegionSize` | `rwx-alloc base= size= type= protect=` |
| `ntdll.dll!NtProtectVirtualMemory` | NewProtect (arg 3) executable+writable: `*BaseAddress`, `*RegionSize` | `rwx-protect base= size= protect=` |

Entry-only: four probes, so it fits the hardware backend's four debug registers.
`LoadLibraryW` and `LoadLibraryA` funnel into `KernelBase!LoadLibraryExW`, so one probe sees all three.

## Target and expected result

`famous_loader_target --threads 4`: main loads `version.dll` (`LoadLibraryW`),
`dbghelp.dll` (`LoadLibraryExW`, `LOAD_LIBRARY_SEARCH_SYSTEM32`) and a missing
`uhh_no_such_module.dll`; worker `k` allocates RWX memory of `0x13000 + k*0x1000` bytes,
XOR-"unpacks" a `mov eax, imm; ret` into it and calls it, then allocates RW memory of
`0x25000 + k*0x1000`, writes code, flips it to RWX (signal), calls it, flips to RX (W^X done
right: not a signal) and calls it again.

Expected on every backend: exactly one `rwx-alloc` per worker fingerprint size, exactly one
`rwx-protect` per worker fingerprint size, all three names in both the `loadlibraryexw` and
`ldrloaddll` logs, and the target's output (`jit_ok == 2*threads`) unchanged.

**Observer effect (inline backend):** writing an inline hook makes the patched bytes
`PAGE_EXECUTE_READWRITE` for a moment through the target's own `NtProtectVirtualMemory`, so
an RWX watcher that is already installed sees UHH's later hook writes (observed:
`rwx-protect size=0x8` inside KernelBase; the check prints it as `other_rwx_events`).
Breakpoint and hardware probes patch the target from the controller process
(`VirtualProtectEx`/`WriteProcessMemory`), which never passes through the target's own
`NtProtectVirtualMemory`, so they are invisible here.
