# UHH vs Frida: the comparison harness (current Frida, 17.26+)

`vs_frida.py` runs the same workloads under UHH and under Frida on the same machine, with
the same clocks, and checks correctness exactly for every run. The agents in `agents/` are
written the way the current Frida documentation says to write them. Results and their
interpretation are in [`../BENCHMARKS.md`](../BENCHMARKS.md), in the section "UHH vs Frida
17.26.1 (2026-11-07, supersedes the earlier comparison)".

```
bench/frida/
  vs_frida.py            driver: every workload x every method, repeats, exact judges, summary
  agents/prelude.js      prepended to every agent (PARAMS, target resolution, exit handshake)
  agents/count_js.js     Interceptor.attach, JavaScript onEnter (run under QuickJS and under V8)
  agents/count_cmodule.js  Interceptor.attach, CModule (C) onEnter
  agents/count_hw.js     hardware breakpoint / write watchpoint on every thread + exception handler
  agents/gated_js.js     the whole examples/gated_config, JavaScript callbacks, batched send()
  agents/gated_cmodule.js  the same with C callbacks, a lock-free ring and binary send()
  uhh_count.cpp, uhh_count_callbacks.cpp   UHH side of the count/hit workloads (same callback on every backend)
  (legacy, superseded: bench_frida.py, gated_full.*, read_*.js, enable_reads.js -- frida 16.5.9, see below)
```

## Run it

On the Windows VM (frida 17.26.1 lives in its own venv, `C:\work\frida17`; `C:\work\fv16`
is the old 16.5.9 one and is untouched):

```bat
python -m venv C:\work\frida17
C:\work\frida17\Scripts\python -m pip install frida==17.26.1 frida-tools
cmake --build build-x64 --config Release --target probe_app configparse gated_config uhh_count hitcost_target probe_api_agent
C:\work\frida17\Scripts\python -u bench\frida\vs_frida.py --rel build-x64\Release --arch x64 --repeats 3 --out rows-x64.jsonl
:: x86: build-x86 (cmake -A Win32), --rel build-x86\Release --arch x86. The SAME 64-bit Python and
:: frida drive 32-bit targets (frida injects its 32-bit agent through its helper).
```

`--workloads count,gated,churn,hit` and `--methods <substrings>` select a subset. The GitHub
workflow `.github/workflows/bench-frida.yml` runs the same thing on fresh windows-2022 and
windows-2025 runners (results as `::notice::` annotations plus the raw rows as an artifact).

## Workloads and methods

| workload | target | what every method does |
|---|---|---|
| count | `probe_app` (reads enabled by config), 8 threads x 50,000 reads | one probe at `ntdll!NtReadVirtualMemory`; the callback reads argument 0 and argument 3 and bumps a counter; no logging |
| gated | `probe_app` with its shipped config (feature DISABLED) | the whole `examples/gated_config`: flip the parsed flag at `configparse.dll!ParseConfig+0x16` (a probe that is set before the DLL is loaded), handle -> pid -> name map at `NtOpenProcess` (from the real returned handle), forget at `NtClose`, log EVERY `NtReadVirtualMemory` as `read handle=.. pid=.. name=.. addr=.. size=..` with its thread id, deliver every record to the host |
| churn | `probe_app --churn --truth FILE` | the same tools; helpers opened, read, closed over and over from 8 threads (handle values reused for different pids, reads through duplicated handles the map never saw); judged per thread against the target's own record |
| hit | `hitcost_target`, one thread, N calls of `hit_site` | the bare per-hit cost of each mechanism (counting callback), and of a write watchpoint on the global `hit_site` updates |

| method | UHH | Frida |
|---|---|---|
| inline hook, native callback | `uhh-inline` | `frida-cmodule` (Interceptor + CModule C callback) |
| inline hook, script callback | -- | `frida-js` (QuickJS, the default runtime), `frida-js-v8` |
| hardware breakpoint | `uhh-hw` (debug registers, out-of-process debugger) | `frida-hw` (`Thread#setHardwareBreakpoint` + `Process.setExceptionHandler`, in-process) |
| hardware watchpoint | `uhh-watch` | `frida-watch` (`Thread#setHardwareWatchpoint`) |
| software breakpoint | `uhh-breakpoint` | none in Frida's local (in-process) backends: `Interceptor.breakpointKind` exists only in the Barebone backend |

Every Frida method SPAWNS the target (spawn suspended, attach, load the agent, resume): Frida's
equivalent of UHH's launch. UHH is driven through `gated_config.exe` / `uhh_count.exe`.

## What current Frida offers, and how the agents use it

Read from the 17.x documentation (frida.re/docs/javascript-api, best-practices, the 17.22-17.26
release notes) and checked against the frida-gum source where the docs are silent:

- **Interceptor.attach(target, callbacks)** with `onEnter(args)`/`onLeave(retval)`. Docs:
  "callbacks have a significant impact on performance ... omit the callback you don't need";
  for hot functions "use Interceptor in conjunction with CModule to implement the callbacks in
  C". `this` is a per-invocation, per-thread object (state from onEnter to onLeave). JavaScript
  callbacks run under the script's runtime lock, so callbacks of different threads are
  SERIALIZED; CModule callbacks are plain native calls and run concurrently.
- **Instruction probes**: `Interceptor.attach(address, function (args) {...})` hooks an
  arbitrary instruction; `this.context.rax/eax` can be assigned. This is the exact
  equivalent of UHH's `ParseConfig+0x16` probe that sets EAX=1; the 7 bytes at that site
  (`mov [rbx],eax; mov eax,1`) relocate fine. (The old comparison claimed the site was "a 2-byte
  `mov [rcx],eax` + ret, too short for any trampoline" -- wrong for the current
  `parse_x64.asm`/`parse_x86.asm`.) 17.26 adds instrumentation options (`relocation:
  'forced'`, `scenario: 'offline'`, `writeRedirect`) for even tighter sites.
- **Process.attachModuleObserver({onAdded})** (17.x): called "synchronously right after that
  module has been loaded but before the application has had a chance to use it ... a good
  time to apply your instrumentation". This is Frida's pending/deferred probe: `gated_*.js`
  installs the flag probe there, when `configparse.dll` maps.
- **Process.attachThreadObserver({onAdded})** (17.x): existing threads right away, each new
  thread "synchronously from that new thread". With it, per-thread hardware breakpoints cover
  every thread including future ones -- the old comparison said Frida had "no process-wide or
  future-thread arming", true of 16.5.9 only.
- **Thread#setHardwareBreakpoint(id, address) / setHardwareWatchpoint(id, address, size,
  'r'|'w'|'rw')** + **Process.setExceptionHandler(cb)**: the hit is an `EXCEPTION_SINGLE_STEP`
  in the target's own exception dispatch (`details.type === 'single-step'`); return `true` to
  continue. Frida's own test only shows a one-shot breakpoint (it unsets it in the handler).
  To keep an EXECUTE breakpoint armed, the handler must set the resume flag (EFLAGS.RF, bit 16)
  -- `details.context` has no EFLAGS, so it is written in `details.nativeContext` (the Windows
  CONTEXT: `EFlags` at +0x44 on x64, +0xC0 on x86). A watchpoint traps after the access and
  needs nothing. The old `read_hwbp.js` set TF through `ctx.rflags`, which does not exist, so
  each thread counted one hit and never re-armed: that was its "8 of 16,000".
- **CModule**: `new CModule(source, symbols)` compiles C with the built-in TinyCC (no
  optimizer) into memory; exported functions become NativePointers that Interceptor accepts as
  native `onEnter`/`onLeave` (`GumInvocationContext *`). "All data is read-only, so writable
  globals should be declared extern, allocated using e.g. Memory.alloc(), and passed in as
  symbols". The old `read_cmodule.js` wrote to a CModule global (`g_calls++`), i.e. to
  read-only memory, from the hook: the first call faulted inside the hook, which is the "CModule
  hangs on load" it reported. Available in C: a curated subset of GLib (`g_atomic_int_add`,
  `g_thread_yield`, ...) and Gum (`gum_invocation_context_get_nth_argument`,
  `GUM_IC_GET_INVOCATION_DATA`, `gum_invocation_context_get_thread_id`); no `snprintf`.
  External functions (e.g. `NtQuerySystemInformation`) are passed as symbols too.
- **send(message[, data])** is asynchronous, but "the total overhead of sending a single
  message is not optimized for high frequencies ... Frida leaves it up to you to batch".
  `data` is an ArrayBuffer of raw bytes: the binary path. `gated_js.js` batches text records
  (4,096 per send(), and a 20 ms timer flush); `gated_cmodule.js` batches binary records from
  a native ring (one send() per drained chunk, up to 65,536 records). `recv(type, cb).wait()`
  blocks the calling thread until the host posts: the agents use it at
  `RtlExitUserProcess` so the final records are delivered before the process is gone.
- **Runtimes**: QuickJS (default, interpreter) or V8 (`create_script(..., runtime='v8')`, JIT).
  Both are measured.
- **Stalker** (dynamic recompilation, per thread) is a code tracer: following every worker
  thread to count calls of one function re-translates all their code. Not used here: it is
  not how anyone counts or logs calls of one function, and 17.26's Stalker changes (register
  spills off the target stack) do not change that.

## The Frida 17 failure on the VM (root cause)

`frida 17.25.2` aborted with `Unable to locate the ntdll loader TLS routines` on this VM, for
spawn and for attach. Frida 17.25.0 (2026-10-30) introduced a cross-platform manual mapper
that maps the agent into the target without touching the filesystem, and the PE mapper has to
call the loader's `LdrpHandleTlsData`/`LdrpReleaseTlsEntry` to register the agent's static
TLS. Those are not exported; frida-gum found them by disassembling ntdll with heuristics that
"only matched recent Windows 11 builds, so mapping any image with static TLS aborted on older
systems" (frida-gum commit 4576833, 2026-11-03, issue #1203). The fix ("TLS routines are
located by behavior instead of by signature ... Vista through Windows 11") shipped in
**17.26.0** (2026-11-05). The error is raised by `g_error` in the HOST process (python.exe),
which maps the agent out-of-process. Nothing was wrong with the VM: `pip install
frida==17.26.1` works on it unchanged (reproduced side by side: 17.25.2 aborts, 17.26.1 and
16.5.9 attach).

## Legacy scripts (frida 16.5.9, superseded)

`bench_frida.py`, `gated_full.py/.js`, `read_logger.js`, `read_cmodule.js`, `read_stalker.js`,
`read_hwbp.js`, `enable_reads.js` and `../bench_matrix.py` produced the 2026-11-04/-07 numbers.
They are kept for the record; see BENCHMARKS.md for why they were superseded (Frida only
counted while UHH logged and delivered; the CModule and hardware-breakpoint agents were buggy;
UHH hooked `probe_app!ReadThunk` while Frida hooked `ntdll!NtReadVirtualMemory`).
