# Heap tracker (leak hunter)

## The original recipe

The Frida leak-hunter script every tutorial shows:

```js
const live = new Map();
Interceptor.attach(Module.getExportByName('ntdll.dll', 'RtlAllocateHeap'), {
  onEnter(args) { this.size = args[2].toInt32(); },
  onLeave(ret)  { if (!ret.isNull()) live.set(ret.toString(), this.size); }
});
Interceptor.attach(Module.getExportByName('ntdll.dll', 'RtlFreeHeap'), {
  onEnter(args) { live.delete(args[2].toString()); }
});
// at exit: whatever is still in `live` leaked
```

API Monitor does the same with its "Memory Management > Heap" filter on `HeapAlloc`
(`kernel32!HeapAlloc` is a forward to `ntdll!RtlAllocateHeap`).

## UHH mapping (`heap_callbacks.cpp`)

| Frida | UHH |
|---|---|
| `onEnter` of RtlAllocateHeap | `famous_heap_on_alloc` on `ntdll.dll!RtlAllocateHeap`: caller in the main module? store `Size` (arg 2) keyed by the return-site SP, arm a probe on the return address |
| `onLeave` | `famous_heap_on_return` at the call site: `AX` is the block -> insert into the live table |
| the JS `Map` | a `UHH_SHARED` open-addressing hash (8192 slots, lock-free CAS), the same memory for the controller-side and in-target callbacks |
| RtlFreeHeap `onEnter` | `famous_heap_on_free`: remove arg 2 (any caller: `HeapFree` and the CRT go through kernel32/ucrtbase first) |
| "at exit" | `famous_heap_on_exit` on `ntdll.dll!RtlExitUserProcess`: one `heap-leak ptr= size=` line per live block, then `heap-summary` |

Scoping to the main module (`Process.mainModule` -> PEB via `call_func`) keeps the CRT's and
the loader's own allocations out, and keeps the number of return-site probes at the
program's own call sites -- which is what lets the recipe fit the four debug registers of
the hardware backend (alloc + free + exit + one call site).

## Target and expected result

`famous_heap_target --threads 4 --iters 600`: every allocation goes through one `xalloc`
(one `HeapAlloc` call site). Worker `k` forgets one block when `i % 250 == 7`; main leaks
one 4096-byte config block. The target prints `allocs`, `frees`, `leaks`, `leaked_bytes`;
the tracker's `heap-summary` must match all four exactly, with one `heap-leak` line per leak.

```powershell
famous_driver --recipe heap --backend inline -- famous_heap_target.exe --threads 4 --iters 600
```

Notes: tens of thousands of allocator hits -- the breakpoint backend is the slow one
(seconds) but exact; inline costs tens of ns per call.
