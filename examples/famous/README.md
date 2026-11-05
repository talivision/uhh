# Famous recipes: classic Frida / API Monitor / Process Monitor instrumentation on UHH

Five instrumentation recipes everyone has written at least once, re-done with UHH's frozen
API. Each recipe is **one callback source** (`<recipe>/*_callbacks.cpp`) compiled unchanged
into `famous_driver.exe` (breakpoint / hardware callbacks run in the controller) and into
`probe_api_agent.dll` (inline callbacks run inside the target). `--backend` picks how every
probe of the recipe is delivered -- including the return-site probes the callbacks add at
runtime -- on x64 and x86.

| Recipe | Classic original | UHH probes | Target (ground truth) |
|---|---|---|---|
| [heap_tracker](heap_tracker) | Frida leak hunter (`Interceptor.attach(RtlAllocateHeap)` + `onLeave`), API Monitor HeapAlloc | `RtlAllocateHeap` entry, its call site's return, `RtlFreeHeap`, `RtlExitUserProcess` | `famous_heap_target`: 4 threads, known leak pattern |
| [file_monitor](file_monitor) | Process Monitor File System view; Frida `NtCreateFile` tracer | `NtCreateFile` (+ return), `NtReadFile`, `NtWriteFile` | `famous_file_target`, `findstr.exe`, `cmd /c type` |
| [tls_capture](tls_capture) | Frida `SSL_read`/`SSL_write` sniffer, SSPI flavour | `sspicli!EncryptMessage`, `DecryptMessage` (+ return) | the real `curl.exe` (SChannel) against a local HTTPS server |
| [loader_rwx](loader_rwx) | API Monitor library-load filter; Frida RWX/unpacker hunters | `LoadLibraryExW`, `LdrLoadDll`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory` | `famous_loader_target` (loads DLLs, writes and runs code) |
| [retval_override](retval_override) | Frida `onLeave: retval.replace(...)` (GetTickCount anti-timing bypass) | `GetTickCount` entry, `set_reg(AX)` at the call site's return | `famous_tick_target` (timing check around `Sleep`) |

```powershell
famous_driver --recipe heap|files|tls|loader|tick --backend breakpoint|hw|inline `
              [--filter text] [--value 0xN] [--attach-new image.exe [--timeout ms]] -- program.exe args...
```

## The Frida idioms and their UHH mapping (`common/famous_common.h`)

| Frida | UHH |
|---|---|
| `onEnter(args)` | the probe's callback; `get_func_arg(c, i)` (registers on x64, stack on x86) |
| `onLeave(retval)` | **no flag**: read the return address at entry (`get_mem` at SP) and `probe_add_address` it from the callback, once per distinct call site. The site probe fires on every later return there, on any backend. `famous_arm_return` makes sure every thread that saw a not-yet-armed site waits until it is armed. |
| `this.x = ...` in onEnter, used in onLeave | keyed by the stack pointer the thread will have at the return site (`SP + ptr` on x64; `+ 4*args` more on x86 stdcall) -- `famous_pending_put/take` |
| JS closure state | `UHH_SHARED` globals (a shared section of the callbacks DLL): the same memory whichever backend runs a callback. Values only, no pointers. |
| `Process.mainModule` | `call_func(c, "ntdll.dll!RtlGetCurrentPeb")` once, then `PEB->ImageBaseAddress` + `SizeOfImage` via `get_mem` (cached) |
| `args[i].readUtf16String()`, `UNICODE_STRING`, `OBJECT_ATTRIBUTES` | `famous_read_wstr`, `famous_read_ustr`, `famous_read_object_name` (bitness-correct layouts) |
| `retval.replace(v)` | `set_reg(c, PROBE_REG_AX, v)` in the return-site callback |
| `hexdump(buf)` | `famous_escape` (printable ASCII + `\xNN`) into `send_log` |

## Regression checks (`scripts/regress.py --only famous`)

Every recipe first runs its target **uninstrumented** (the target prints its own ground
truth as JSON), then under each backend. A check passes only if the program's output is
unchanged (except the deliberate override), the callbacks' view equals the ground truth
exactly, nothing was dropped, every probe ran on exactly the requested backend, and no
return-site probe was refused:

`famous-heap-*`, `famous-files-*` (filtered, unfiltered, `attach-*` mid-run via
`--attach-new`, `findstr-*`, `type-*`), `famous-tls-*`, `famous-loader-*`, `famous-retval-*`
(3 runs per backend).

## What the replicas found in UHH

Details and status in "Frida-replica findings" in [docs/ROADMAP.md](../../docs/ROADMAP.md).
Fixed in the library (each with a regression check here):

- **hw**: probes armed at runtime were lost for whole threads still in their loader
  initialisation (thread start restores the creation-time debug registers) --
  `famous-retval-hw`.
- **hw**: arming a probe could zero a pending hit's DR6 status on another thread; the hit
  was then passed to the target as an unhandled STATUS_SINGLE_STEP -- `famous-retval-hw`.
- **inline**: an allocator probe whose callback uses `call_func` crashed the target (TLS
  used before a starting thread had it; `call_func`'s own allocations re-entered the probe
  until the stack overflowed) -- `famous-heap-inline-reentry`.

Documented limits: hardware recipes that need a return probe per call site run out of the
four debug registers unless filtered (file monitor); the inline backend's hook writes are
visible to an RWX watcher (loader_rwx); the live log tail shares the target's stdout, so
the checks read the logs from the session JSONL file.
