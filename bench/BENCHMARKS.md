# UHH vs Frida — instrumentation benchmark

The current comparison is the first section below ("UHH vs Frida 17.26.1"). Everything after it
is kept for history and is SUPERSEDED (see "Why the earlier comparison was superseded").
Reproduce with `bench/frida/vs_frida.py` (how: `bench/frida/README.md`); raw rows in
`bench/results/frida17-2026-11-07/`.

## Update: branch `perf` (2026-11-07 evening) against the same Frida 17.26.1 rows

Same VM, same `vs_frida.py`, lean sizes (8 x 12,500 reads = 100,000 events, hit 50,000 calls),
3 repeats, every run exact. UHH = `perf` (c086163 + f1d011f), Frida rows re-measured in the same
session. Raw rows: `bench/results/frida17-perf-2026-11-07/`. Added ns per event (median):

| workload | arch | uhh-inline | frida-cmodule | uhh-hw | frida-hw | uhh-breakpoint |
|---|---|---:|---:|---:|---:|---:|
| count | x64 | **+42** | +307 | +120,350 | +23,047 | +99,508 |
| gated (every read logged + delivered) | x64 | **+763** | +793 | +132,796 | -- | +110,064 |
| hit | x64 | **+100** | +252 | +93,479 | +23,027 | +77,745 |
| count | x86 | +300 | **+214** | +217,134 | +20,151 | +205,144 |
| gated | x86 | +1,179 | **+287** | +238,642 | -- | +220,769 |
| hit | x86 | **+225** | +301 | +154,223 | +47,641 | +142,139 |

- UHH inline now beats CModule on x64 in all three workloads (gated was +2,145 before: the
  controller's log writer, see bench/results/main-vs-merge-frida-2026-11-07.md "Phase 3") and on
  x86 in `hit`; x86 `count` and `gated` are still behind (open: the x86 log path and per-hit
  costs beyond the x87 save).
- hw: UHH's hardware breakpoints are EXTERNAL (a debugger; the owner kept them so) and cannot go
  below the debug-event round trip: the smallest debugger counting the same debug-register hit
  (`bench/perfab/mindbg`) costs 67 us (x64) / 113 us (x86) per hit on this VM; Frida's in-process
  exception handler is ~3x below that floor by construction. UHH hw single-thread is 93 us (x64).

## UHH vs Frida 17.26.1 (2026-11-07, branch frida-real; supersedes everything below)

### Why the earlier comparison was superseded

1. It ran frida **16.5.9** because 17.25.2 "could not instrument this VM". Root cause, now
   found: Frida 17.25.0 (2026-10-30) added a manual PE mapper that injects the agent without
   touching the filesystem. To register the agent's static TLS it calls the loader's
   unexported `LdrpHandleTlsData`/`LdrpReleaseTlsEntry`, which it locates by disassembling
   ntdll, and those heuristics "only matched recent Windows 11 builds, so mapping any image with
   static TLS aborted on older systems" (frida-gum commit 4576833, issue #1203). Fixed in
   **17.26.0** (2026-11-05: "TLS routines are located by behavior instead of by signature").
   Reproduced side by side on the VM: 17.25.2 aborts in the HOST process (python.exe,
   `Frida-ERROR **: Unable to locate the ntdll loader TLS routines`), 17.26.1 and 16.5.9
   attach. Nothing on the VM needed changing (no Windows Update): `pip install frida==17.26.1`
   in its own venv `C:\work\frida17`; `C:\work\fv16` (16.5.9, used by regress) is untouched. The
   VM's ntdll is 10.0.19041.6456 (the earlier "unpatched 10.0.19041.2788" was also wrong).
2. Apples to oranges: UHH logged and delivered every event while Frida only counted; and UHH
   hooked `probe_app!ReadThunk` while Frida hooked `ntdll!NtReadVirtualMemory`.
3. Two of its Frida agents were broken, and their failures were reported as Frida's:
   - "CModule hangs on load": `read_cmodule.js` incremented a CModule global. CModule data is
     read-only (the docs say writable globals must be `extern`, allocated by JS and passed as
     symbols), so the first hooked call faulted inside the hook. Re-run under 17.26.1, the target
     still never completes its reads. Written as documented, CModule is the fastest Frida method.
   - "Hardware breakpoints mis-count (8 of 16,000)": `read_hwbp.js` tried to step past the
     breakpoint by setting TF through `context.rflags`, which Frida's context does not have, so
     each thread counted one hit and never re-armed (8 threads, 8 hits). Done properly (set
     EFLAGS.RF in the native CONTEXT, below), Frida's hardware breakpoints count exactly and cost
     5-10x less than UHH's.
4. "The flag site is a 2-byte `mov [rcx],eax` + ret, too short for any trampoline" was wrong
   for the current `parse_x64.asm`/`parse_x86.asm` (`mov [rbx],eax; mov eax,1`, 7 bytes).
   Frida's instruction probe (`Interceptor.attach(address, function)`, assigning
   `this.context.rax`) hooks it directly. It is installed from `Process.attachModuleObserver`
   when `configparse.dll` maps, which is Frida 17's equivalent of UHH's pending probe.
5. "Frida hardware breakpoints are per-thread, with no future-thread arming" was true of 16.5.9
   only. Frida 17 has `Process.attachThreadObserver` (each new thread is reported synchronously
   on itself), so per-thread breakpoints cover every thread.

### What was measured

Same VM for both tools (Proxmox VM 103: i5-6600, 4 cores, Windows 10 19045, ntdll
10.0.19041.6456), Python 3.12.10, frida 17.26.1 / frida-tools 14.13.0, UHH Release build of
frida-real. 3 repeats per method, interleaved (alternating order), median [min..max]. Timing
ran only when no other VM job was running (slot log beside the raw rows). x64: 8 threads x
50,000 reads (400,000 events), churn 8 x 2,000 rounds, hit 200,000 calls. x86 was sized lean on
the owner's request: 8 x 12,500 reads (100,000 events), churn 8 x 1,000 rounds, 50,000 calls.
Per-event costs are ratios, so they compare across sizes; wall times do not.

Every Frida method SPAWNS the target (spawn suspended, load the agent, resume), Frida's
equivalent of UHH's launch. The same 64-bit Python and frida drive the 32-bit targets (frida
injects its 32-bit agent through its helper). The agents follow the 17.x documentation
(`bench/frida/README.md` has the details and what each API does):

| method | what it is |
|---|---|
| uhh-inline / uhh-hw / uhh-breakpoint | UHH, the same callback source on each backend (hw/breakpoint callbacks run in the controller process, out of the target) |
| uhh-watch | UHH hardware write watchpoint |
| frida-js | `Interceptor.attach` with a JavaScript `onEnter`, QuickJS (the default runtime) |
| frida-js-v8 | the same script under the V8 runtime |
| frida-cmodule | `Interceptor.attach` with C callbacks (`CModule`, TinyCC) |
| frida-hw / frida-watch | `Thread#setHardwareBreakpoint` / `setHardwareWatchpoint` on every thread (`Process.attachThreadObserver`) + `Process.setExceptionHandler`; an execute breakpoint is continued by setting EFLAGS.RF in `details.nativeContext` |
| (no Frida equivalent) | software breakpoints: `Interceptor.breakpointKind` exists only in Frida's Barebone backend |

Workloads (`vs_frida.py`):
- **count**: `probe_app` (reads enabled by config); one probe at `ntdll!NtReadVirtualMemory`
  whose callback reads argument 0 and argument 3 and bumps a counter. Exact = callback count ==
  reads.
- **gated**: the whole `examples/gated_config`, in each tool. The config ships disabled and the
  flag is flipped at `configparse.dll!ParseConfig+0x16` by a probe set before the DLL loads.
  `NtOpenProcess` maps handle -> pid -> name from the real returned handle (name by pid via
  `NtQuerySystemInformation(SystemProcessIdInformation)`, as UHH does), `NtClose` forgets it,
  and EVERY `NtReadVirtualMemory` is logged as `read handle=.. pid=.. name=.. addr=.. size=..`
  with its thread id and delivered to the host process. Frida-js batches text records (4,096
  per `send()`, plus a 20 ms timer flush). Frida-cmodule writes binary records into a lock-free
  ring with backpressure (producers wait, nothing is dropped), drained by JS into one binary
  `send(meta, ArrayBuffer)` per chunk. Both hold the process exit (`recv().wait()` at
  `RtlExitUserProcess`) until the host has every record. Exact = every workload read has
  exactly one record with the right pid and name (vs probe_app's own `opened` lines), one flag
  flip, nothing dropped, nothing extra.
- **churn**: the same tools on `probe_app --churn --truth` (regress gated-e2e's ground truth):
  helpers are opened, read and closed over and over from 8 threads, handle values are reused
  for different pids, and some reads go through duplicated handles the map never saw (these
  must log pid 0). Exact = per thread, the delivered open/map/read sequence equals the target's
  own record, in order. Timed by wall clock (the target has no in-process window in this mode).
- **hit**: `hitcost_target`, one thread calling `hit_site()` N times: the bare per-hit cost of
  each mechanism with the counting callback, plus write watchpoints on the global it updates.

"Added" = median minus the uninstrumented baseline of the same arch, per event, from the
target's own `QueryPerformanceCounter` window (the same field for every method).

### Results (VM)

**Correctness: every UHH run and every Frida run except frida-js-v8 was exact**: all
400,000 / 100,000 calls counted, every record delivered with the right pid and name, per-thread
churn sequences identical to the target's ground truth, checksums equal to the uninstrumented
run. Frida-js-v8 crashes the target in gated/churn (see "Frida findings" below; on x86 it was
left out of the timed gated/churn runs after crashing in the smoke run).

**count**: one probe on `NtReadVirtualMemory`, counting callback (per read)

| method | x64 ns/read | x64 added | x86 ns/read | x86 added | exact |
|---|---:|---:|---:|---:|---|
| baseline | 440 [435..442] | -- | 499 [496..541] | -- | 3/3, 3/3 |
| **uhh-inline** | 592 [554..601] | **+152** (x1.3) | 799 [747..888] | **+300** (x1.6) | 3/3, 3/3 |
| **frida-cmodule** | 666 [648..684] | **+226** (x1.5) | 856 [706..1,942] | **+357** (x1.7) | 3/3, 3/3 |
| frida-js (QuickJS) | 7,744 [7,657..8,021] | +7,304 (x17.6) | 7,449 [6,833..8,200] | +6,950 (x14.9) | 3/3, 3/3 |
| frida-js-v8 | 11,956 [11,143..12,030] | +11,516 (x27.2) | 13,252 [12,613..14,708] | +12,753 (x26.6) | 3/3, 3/3 |
| **frida-hw** | 23,426 [23,158..23,505] | **+22,986** (x53) | 20,060 [19,654..20,682] | **+19,561** (x40) | 3/3, 3/3 |
| uhh-hw | 117,861 [115,524..120,578] | +117,420 (x268) | 200,366 [198,912..201,378] | +199,867 (x401) | 3/3, 3/3 |
| uhh-breakpoint | 76,818 [75,675..79,434] | +76,378 (x175) | 156,342 [149,700..159,626] | +155,842 (x313) | 3/3, 3/3 |

**gated**: the whole example, every read logged and delivered (per read)

| method | x64 ns/read | x64 added | x86 ns/read | x86 added | exact |
|---|---:|---:|---:|---:|---|
| baseline | 438 [427..442] | -- | 511 [506..633] | -- | 3/3, 3/3 |
| **frida-cmodule** | 820 [767..972] | **+383** (x1.9) | 801 [784..966] | **+291** (x1.6) | 3/3, 3/3 |
| **uhh-inline** | 2,583 [2,406..2,676] | **+2,145** (x5.9) | 3,396 [3,175..3,439] | **+2,885** (x6.7) | 3/3, 3/3 |
| frida-js (QuickJS) | 15,622 [15,591..15,680] | +15,185 (x36) | 15,453 [15,395..16,055] | +14,942 (x30) | 3/3, 3/3 |
| frida-js-v8 | -- | -- | -- | -- | 0/3 x64: target crashes; x86 not run (crashed in the smoke run) |
| uhh-hw | 119,665 [117,644..121,295] | +119,228 (x273) | 216,836 [216,296..219,106] | +216,326 (x425) | 3/3, 3/3 |
| uhh-breakpoint | 83,891 [83,032..85,039] | +83,453 (x192) | 169,536 [167,466..172,143] | +169,026 (x332) | 3/3, 3/3 |

End-to-end wall time, launch -> last record in the host (median; x64 400,000 reads, x86 100,000):
frida-cmodule 1.45 s / 0.78 s, uhh-inline 1.79 s / 1.12 s, frida-js 7.04 s / 2.27 s, uhh-breakpoint
34.2 s / 18.1 s, uhh-hw 48.6 s / 22.4 s. Frida's spawn + inject + agent load took 0.18-0.19 s.

**churn**: exact against the target's own record (wall seconds, launch -> exit)

| method | x64 (8 x 2,000 rounds) | x86 (8 x 1,000 rounds) | exact |
|---|---:|---:|---|
| baseline | 0.61 [0.55..0.69] | 0.73 [0.46..0.77] | 3/3, 3/3 |
| frida-cmodule | 0.93 [0.87..1.00] | 0.88 [0.87..0.89] | 3/3, 3/3 |
| uhh-inline | 1.03 [1.02..1.10] | 0.86 [0.67..0.98] | 3/3, 3/3 |
| frida-js | 2.35 [2.17..3.13] | 1.69 [1.60..1.75] | 3/3, 3/3 |
| uhh-hw | 15.37 [15.33..15.58] | 13.93 [13.86..13.95] | 3/3, 3/3 |
| uhh-breakpoint | 15.95 [15.71..16.65] | 15.25 [15.19..15.30] | 3/3, 3/3 |
| frida-js-v8 | target crashes 3/3 | not run | 0/3 |

**hit**: one thread, bare per-hit cost (ns per call)

| method | x64 added | x86 added | exact |
|---|---:|---:|---|
| baseline (ns/call) | 3.3 | 6.2 | |
| **uhh-inline** | **+94** | +396 | 3/3, 3/3 |
| **frida-cmodule** | +250 | **+274** | 3/3, 3/3 |
| frida-js (QuickJS) | +1,136 | +1,354 | 3/3, 3/3 |
| frida-js-v8 | +1,791 | +2,427 | 3/3, 3/3 |
| **frida-hw** (execute breakpoint) | **+22,901** | **+47,244** | 3/3, 3/3 |
| uhh-hw | +143,772 | +216,645 | 3/3, 3/3 |
| uhh-breakpoint | +88,640 | +164,915 | 3/3, 3/3 |
| **frida-watch** (write watchpoint) | **+20,896** | **+43,090** | 3/3, 3/3 |
| uhh-watch | +136,964 | +214,103 | 3/3, 3/3 |

### Where each tool wins

- **Raw inline hook, native callback (count, hit): UHH is ahead.** On x64 it adds 152 ns
  per read vs 226 ns for Frida CModule, and 94 vs 250 ns per call in the single-thread loop.
  On x86 it adds 300 vs 357 ns per read, but the single-thread x86 loop is the exception: UHH
  adds 396 ns per call, Frida CModule 274 ns. Both are 30-80x cheaper than Frida's JavaScript
  callbacks.
- **The full gated example (log every read and deliver it): Frida CModule wins clearly.** It
  adds 383 ns/read vs UHH inline's 2,145 (x64), and 291 vs 2,885 (x86): 5.6x and 9.9x less. It
  is also faster end to end (1.45 s vs 1.79 s for 400,000 records). The difference is UHH's
  per-record cost: the same inline hook costs +152 ns when counting and +2,145 ns when it logs,
  so about 2 us per record goes into formatting the text record and delivering it through
  UHH's log pipeline. Frida CModule writes a fixed-size binary record into a ring (with
  backpressure: on x64 the producers waited 534-6,579 times per run, and nothing was dropped)
  and ships 65,536 records per `send()`. **This is the main thing UHH can learn from Frida
  here** (see "For UHH" below).
- **Frida JavaScript callbacks are 5-7x slower than UHH inline on the gated example** (+15.2 us
  vs +2.1 us per read) and 30-50x slower on raw hooks. All JS callbacks run under one runtime
  lock, so 8 threads' hooks are serialized. V8 (JIT) is SLOWER than QuickJS here (+11.5 vs
  +7.3 us): the cost is the native-to-JS transition, not the script's work.
- **Hardware breakpoints and watchpoints: Frida is 4.6-10x cheaper than UHH.** x64 hit: +22.9
  vs +143.8 us (execute) and +20.9 vs +137.0 us (write watch); count with 8 threads: +23.0 vs
  +117.4 us (x64) and +19.6 vs +199.9 us (x86). Frida handles the trap in-process, in the target's own exception dispatch, on the
  thread that hit it. UHH's hw and breakpoint callbacks run in the controller (an out-of-process
  debugger): every hit is a debug event, two context switches and a serialized debugger
  loop. That is UHH's design (the callback runs outside the target, sees the target stopped and
  never runs on the target's stack). It is also the reason those backends cost what they do.
- **Software breakpoints**: only UHH has them on a local Windows process (+76-88 us per hit on
  x64). UHH's breakpoint backend is also faster than its own hw backend.
- **Same callback, any backend**: UHH runs one callback source unchanged on inline / hw /
  breakpoint. In Frida each mechanism is a different programming model: JS `onEnter`, C with
  TinyCC's restrictions (read-only data, no `snprintf`, `extern` state passed in from JS), or a
  process-wide exception handler that decodes registers itself and must set EFLAGS.RF in the raw
  CONTEXT.

### Frida findings (things a Frida user must know; all reproduced on the VM)

1. **V8 + a JS hook on `ntdll!NtClose` crashes the target.** An EMPTY `onEnter` on `NtClose`
   under `runtime='v8'` kills probe_app with an access violation in Frida's (manually mapped,
   "unknown") module, 3/3 on the plain workload and 2/3 on churn. QuickJS is fine 3/3, and V8
   with a hook on `NtOpenProcess` is fine 3/3. Probable cause: V8's own threads close handles
   and re-enter the runtime through the hook. Bisected with `gated_js.js`: removing only the
   NtClose hook makes V8 survive 3/3.
2. **Frida's own memory reads show up in your hook.** Since 17.25 its module registry handles
   every DLL load on the loading thread and reads the process's own memory through
   `K32GetModuleInformation` / `GetModuleFileNameExW` -> `ReadProcessMemory(-1)` ->
   `NtReadVirtualMemory`: about 150 calls per DLL load (148 on x64, 152 on x86, at the
   `configparse.dll` load), all from cloaked (Frida) return addresses. A tracer that logs every
   `NtReadVirtualMemory` records them as the program's reads unless it filters them. The
   agents skip a self-read (handle -1) when a cloaked address (`Cloak.hasRangeContaining`) is
   among the nearest stack words. UHH's agent does not show up this way (0 foreign records in
   every run).
3. **A `NativeFunction` call releases the JS lock** (default `scheduling: 'cooperative'`), so
   another thread's JS callback can run during it. A first version of `gated_js.js` shared one
   buffer for the image-name query, and under churn some opens got the name `?` (caught by the
   exact judge, 0/3). Fixed with per-call buffers and re-run: 3/3. JS-callback state is not as
   "single-threaded" as the runtime lock suggests.
4. Defender blocks Frida 17's `idund` helper on the VM (`Unable to start idund: error 225`,
   ERROR_VIRUS_INFECTED). It is the Apple-device daemon and is harmless for local
   instrumentation.

### For UHH (from this comparison; no library code was changed)

- The log path costs about 2 us per record on top of a 0.15 us hook, and it dominates the
  flagship example. Frida's CModule design suggests what would help: fixed-size binary records
  written straight into a shared ring with backpressure, text formatting moved to the
  controller/host, and large batches per transfer.
- The hw/breakpoint per-hit cost (77-217 us) is the price of out-of-process callbacks. An
  in-process (VEH) fast path for hw probes would be about 5x cheaper, as Frida shows, but it
  would give up running the callback outside the target.

### CI (GitHub-hosted windows-2022 / windows-2025, fresh patched images)

`.github/workflows/bench-frida.yml` installs `frida==17.26.1` from PyPI and runs the same script
(lean sizes) on windows-2022 and windows-2025, x64 and x86. Shared runners are noisy, so read
those times as indicative only; the correctness columns are exact anywhere.

Run 42334193289 (commit f4a2348, x64 and x86 at the full VM sizes: 400,000 reads, 2,000 churn
rounds, 200,000 calls, 3 repeats). Runners have 2 cores / 4 logical processors (AMD EPYC):
windows-2022 is Server 2022 10.0.20348 (ntdll 10.0.20348.5756), windows-2025 is Server 2025
10.0.26100 (ntdll 10.0.26100.33648). frida 17.26.1 installed from PyPI and worked on all four.
Added cost per event, median of 3:

| | 2022 x64 | 2022 x86 | 2025 x64 | 2025 x86 |
|---|---:|---:|---:|---:|
| count uhh-inline | +55 | +250 | +114 | +263 |
| count frida-cmodule | +129 | +166 | +159 | +182 |
| count frida-js | +1,057 | +1,941 | +1,430 | +1,579 |
| count frida-js-v8 | +6,334 | +13,267 | +9,218 | +11,178 |
| count frida-hw | +22,113 | +46,903 | +22,721 | +36,132 |
| count uhh-hw | +109,165 | +241,064 | +118,887 | +168,236 |
| count uhh-breakpoint | +80,225 | +199,993 | +91,240 | +133,896 |
| gated frida-cmodule | +385 | +508 | +433 | +322 |
| gated uhh-inline | +786 | +3,139 | +984 | +2,563 |
| gated frida-js | +4,767 | +13,991 | +6,330 | +6,173 |
| hit uhh-inline (ns/call) | +57 | +552 | +68 | +493 |
| hit frida-cmodule | +215 | +334 | +241 | +266 |
| hit frida-hw / uhh-hw | +38,172 / +130,432 | +92,792 / +271,893 | +38,208 / +136,896 | +76,109 / +184,638 |
| hit frida-watch / uhh-watch | +38,598 / +123,751 | +89,461 / +271,483 | +36,887 / +136,327 | +74,371 / +184,503 |

Correctness on CI: every UHH run exact (count, gated, churn, hit; all four images/arches) and
every frida-cmodule / frida-hw / frida-watch run exact. Frida-js-v8 crashed the target in
gated and churn, 3/3 on all four, so the V8 + `NtClose` crash is not specific to the VM.
Frida-js churn was 0/3 there because of the shared-buffer bug in my first `gated_js.js`
(Frida finding 3; fixed in f7aa0ad). The follow-up run 42336882930 (f7aa0ad, lean sizes,
frida-js-v8 left out of gated/churn) was exact in every row on all four image/arch
combinations, frida-js churn included. The CI ranking agrees with the VM's, with two
differences. On these 2-core runners Frida's JS count is much cheaper (+1.1-1.9 us vs +7.3 us
on the 4-core VM), probably because 8 threads contend less for the one JS runtime lock. And UHH
inline's gated cost on x64 is lower (+0.8-1.0 us vs +2.1 us). Frida CModule still beats it
2-2.6x on x64 and 5-8x on x86.

### Files

`bench/frida/vs_frida.py` (driver and judges), `bench/frida/agents/*.js` (Frida agents),
`bench/frida/uhh_count.cpp` + `uhh_count_callbacks.cpp` (UHH count tool), `bench/frida/tables.py`
(tables from the rows), `bench/results/frida17-2026-11-07/vm-x64.jsonl`, `vm-x86.jsonl` (every
run), `vm-x64-superseded-churn-frida-js.jsonl` (the 3 churn runs of the buggy first gated_js,
kept for the record), `slots-*.occ` (proof the VM was quiet).

---

# Superseded: earlier comparisons (frida 16.5.9, count-only Frida agents)

The sections below are the earlier comparison, kept for history. Their Frida numbers come from
frida 16.5.9 with count-only Frida agents, two of which were broken. Read the section above
instead.

## 2026-11-07 re-run (merge-frida 034b245; full gated_config on branch `perf` 74d62a5)

Same VM (i5-6600, Win10 19045), frida 16.5.9, W=8 x R=50,000 = 400,000 reads, 3 repeats, x64 AND
x86 (frida 16.5.9 instruments the 32-bit probe_app from its 64-bit host fine). Raw data:
`bench/results/frida-2026-11-07/`. The 2026-11-04 tables below are kept for history.

**Matrix (bench_matrix.py; UHH rows = gated_config, which LOGS every read; Frida = count mode):**

| method | x64 added ns/read | x64 slowdown | x86 added ns/read | x86 slowdown | hits exact |
|---|---:|---:|---:|---:|---|
| baseline | 0 (434 ns/read) | 1.0x | 0 (521 ns/read) | 1.0x | -- |
| UHH inline | +2,396 | 6.5x | +3,088 | 6.9x | 400,000, 0 dropped |
| UHH hw | +147,255 | 341x | +269,682 | 518x | 400,000, 0 dropped |
| UHH breakpoint | +103,641 | 240x | +207,514 | 399x | 400,000, 0 dropped |
| Frida Interceptor (count, no send) | +7,524 | 18.3x | +10,258 | 20.7x | 400,000 |

Why UHH inline went from +62.5 ns (2026-11-04) to +2,396 ns/read: then, 399,488 of the 400,000
log records were DROPPED (`log_dropped`); since the "no dropped logs" rule every record is
delivered (the ring applies backpressure), so the inline row now measures hook + delivering
400,000 records (~350k records/s through the controller), not the hook alone. The hook alone is
~0.1 us (`bench/perfab`, hit/inline/empty). CModule / Stalker / hwbp were not re-run (Frida-side,
unchanged; see below). The hw / breakpoint rows are merge-frida's (before the `perf` fairness
fix: breakpoint -16..-24% and hw -14..-16% per hit further, single thread: bench/results/main-vs-merge-frida-2026-11-07.md).

**The whole gated_config example in both tools** (`bench/frida/gated_full.py` + `gated_full.js`,
perf 74d62a5): config ships disabled and is flipped at parse; handle -> pid map at
NtOpenProcess (forgotten at NtClose); EVERY NtReadVirtualMemory logged as one record (handle,
pid, address, size) delivered to the host (Frida batches 4,096 records per send()). Ground truth:
probe_app's own `opened` lines.

| tool | arch | read window (in-target) | ns/read | wall (start -> last record) | records | wrong pid | no pid |
|---|---|---:|---:|---:|---|---|---|
| UHH (flag: breakpoint, reads: inline) | x64 | 1,031 ms | 2,578 | 1.63 s | 400,000 x3 | 0 | 0 |
| Frida Interceptor | x64 | 4,909 ms | 12,273 | 5.43 s | 400,000 x3 | 0 | 0 |
| UHH | x86 | 1,322 ms | 3,305 | 2.18 s | 400,000 x3 | 0 | 0 |
| Frida Interceptor | x86 | 5,696 ms | 14,240 | 6.42 s | 400,000 x3 | 0 | 0 |

Both are exact (every read logged once with the right pid); UHH is 4.3-4.8x faster on the full
example. (Frida 16.5.9 has no `Process.attachModuleObserver`: gated_full.js hooks ParseConfig
after LdrLoadDll there.)

## TL;DR

- **UHH completes the exact 8-thread × 50,000-read workload on all three backends
  (inline, hardware, software breakpoint) with EXACT hit counts (400,000, zero
  missed hooks).** That is the headline: full, correct coverage with no hangs.
- **UHH inline is ~130× cheaper per hit than Frida's Interceptor** (+62.5 vs
  +8,102 ns/read) for the same inline-hook job, and **1.15× vs 20.2× slowdown.**
- Of the four Frida methods, only **Interceptor** (inline trampoline, JS `onEnter`)
  completed the full workload correctly. **CModule hangs on load**, **Stalker hangs
  at volume** (per-instruction tracing), and **the hardware-breakpoint API counts
  incorrectly** (8 of 16,000) and is ~95× slower. UHH offers correct, hang-free
  alternatives (hardware + displaced software breakpoint) exactly where Frida's
  non-trampoline methods are impractical.
- **Frida 17.25.2 could not instrument this VM at all** (fatal "Unable to locate the
  ntdll loader TLS routines" on both spawn and attach). The Frida numbers here are
  from **frida 16.5.9**, which attaches cleanly. The 17.25.2 failure is itself a
  Frida-coverage finding.

## Environment

| | |
|---|---|
| Host | DESKTOP-DFF87LU (Proxmox VM 103) |
| CPU | Intel Core i5-6600 @ 3.30 GHz — 4 cores / 4 logical (no SMT) |
| OS | Windows 10 Pro 19045, ntdll 10.0.19041.2788 |
| RAM | 8 GB |
| Python | 3.12.10 |
| Frida (measured) | **16.5.9** (attach) — 17.25.2 is installed but cannot inject (see findings) |
| UHH build | `build-x64\Release`, MSVC 17.14, Release x64 (BUILD_OK confirmed) |
| Workload | probe_app: W threads × R reads through `ReadThunk → NtReadVirtualMemory`, 4-way selected/decoy/in-range rotation |
| Primary point | **W=8 threads (> 4 cores), R=50,000 reads/thread = 400,000 reads**, 3 repeats, median |
| High volume | W=8, R=250,000 = 2,000,000 reads, 3 repeats, median |
| Clock | probe_app's in-target `QueryPerformanceCounter` window (`elapsed_ns`) — the SAME field for every method, so columns line up |
| RVAs | `ParsedFlagSite` = 4354 (configparse.map), `ReadSite` = 18064 (probe_app.map) |

All methods run in **count mode**: read the handle (`args[0]`) and size (`args[3]`),
bump a counter, **no per-call `send()`/IPC** — the fair analogue of UHH's `log_read`,
whose `PROBE_LOG` only enqueues. "Added ns/read" = median(instrumented) −
median(baseline), both on `elapsed_ns / (W·R)`.

## Performance + correctness — W=8, R=50,000 (400,000 reads)

Baseline median ≈ 170 ms ≈ **422 ns/read** (per-chunk baseline used for each "added").

| Method | Added ns/read | Slowdown | Completes workload? | Hit count | Hits exact? |
|---|---:|---:|---|---|---|
| baseline (no instrumentation) | 0 | 1.00× | yes | — | — |
| **UHH inline** (SafetyHook mid-hook) | **+62.5** | **1.15×** | **yes** | 400,000 | **exact** |
| **UHH hardware** (debug register) | +65,330 | 156× | **yes** | 400,000 | **exact** |
| **UHH breakpoint** (INT3 + displaced step) | +118,044 | 279× | **yes** | 400,000 | **exact** |
| Frida Interceptor (inline trampoline, JS onEnter) | +8,102 | 20.2× | yes | 400,000 | exact |
| Frida CModule (native onEnter) | — | — | **NO — hangs on load** | — | — |
| Frida Stalker (follow + addCallProbe) | — | — | **NO — hangs at volume** | — | — |
| Frida hardware breakpoint (per-thread DR) | — | — | runs but **mis-counts** | see reduced-scale | **no** |

Notes:
- **UHH inline** reported `log_dropped = 399,488`. This is NOT missed
  instrumentation: the probe callback fired on **all 400,000** reads (hits exact).
  `log_dropped` counts deferred *log records* the out-of-band printer could not
  drain at burst speed; when the queue is full `PROBE_LOG` drops (a cheap counter
  bump) instead of enqueuing — which is precisely the "bump a counter, no IPC" work
  Frida's count mode does, so the inline-vs-Interceptor comparison is
  hook-dispatch vs hook-dispatch. UHH hw/breakpoint are slow enough that the printer
  keeps up → `log_dropped = 0`.
- `overrides == 1` and `successful_reads == 400,000` for all UHH runs; checksum is
  identical across baseline and all three UHH backends (see "Correctness").

### Frida CModule / Stalker / hardware-bp — characterization (reduced scale)

Because three of the four Frida methods do not complete the full workload, each was
also run under a hard per-method timeout at reduced scale to characterize *why*:

| Method | Scale tried | Result |
|---|---|---|
| CModule | W2×R500 (1,000) **and** W8×R50,000 | **Hangs/wedges the target on script load** at both scales (`Interceptor.attach(target, cmodule)`); the workload never runs. Not viable in this setup. |
| Stalker | W8×R2,000 (16,000) | **Completes, count exact (16,000)**, 9 threads followed, +2,169 ns/read (~6× at this scale). At the full W8×R50,000 it **hangs / wedges probe_app at 0 % CPU** (per-instruction recompilation of every worker thread → unbounded). Not viable at volume. |
| Hardware bp | W8×R2,000 (16,000) | Runs but **counts only 8 of 16,000** (re-arm/single-step across threads with one DR slot does not hold), 13 threads armed, +40,062 ns/read (~95×). API exists but is **incorrect and impractical** for counting all reads here. |

## High volume — W=8, R=250,000 (2,000,000 reads)

Only the methods that complete quickly are included (UHH hw/breakpoint scale ~linearly
— ≈130 s / ≈240 s per repeat at this size — and are omitted for time; the W8×R50,000
numbers above already establish their per-hit cost).

Baseline median ≈ 840 ms ≈ **420 ns/read** (2,000,000 reads).

| Method | Added ns/read | Slowdown | Hit count | Hits exact? |
|---|---:|---:|---|---|
| baseline | 0 | 1.00× | — | — |
| **UHH inline** | **+55.1** | **1.13×** | 2,000,000 | **exact** |
| Frida Interceptor | +8,145 | 20.4× | 2,000,000 | exact |

At 2,000,000 reads UHH inline is ~**148× cheaper per hit** than Frida's Interceptor
(+55 vs +8,145 ns/read), and the per-hit costs are stable vs the 400,000-read point
(+62.5 / +8,102) — the gap is structural, not a small-sample artifact. UHH inline
`log_dropped = 1,999,488` with **hits = 2,000,000 exact** (same nuance as above:
every hook fired; only deferred log records were shed at burst).

## Correctness (re-confirmation)

Confirmed directly from the raw per-run records at W=8, R=50,000 (3 repeats each):

| Method | checksum | successful_reads | probe hits | log_dropped |
|---|---|---|---|---|
| baseline | 33,600,000 | 400,000 | — | — |
| UHH inline | 33,600,000 | 400,000 | **400,000** | 399,488 |
| UHH hardware | 33,600,000 | 400,000 | **400,000** | 0 |
| UHH breakpoint | 33,600,000 | 400,000 | **400,000** | 0 |
| Frida Interceptor | 33,600,000 | 400,000 | **400,000** | — |

The checksum (33,600,000) is identical for baseline and every instrumented backend,
proving instrumentation did not perturb the workload's results.


For every UHH backend at W=8, R=50,000, across 3 repeats:
`probe hits == 400,000` (exact, no missed hooks), `successful_reads == 400,000`,
`overrides == 1`, and the checksum is stable and identical to baseline. UHH is
correct under heavy multithreading at volume on all three backends.

## Stability & coverage — the robustness result

| Method | Completes W8×R50k? | Correct count? | Why / caveat |
|---|---|---|---|
| UHH inline | yes | yes (400k) | needs a ≥5-byte relocatable site for the mid-hook |
| UHH hardware | yes | yes (400k) | no code modification; any instruction; ≤4 DR slots; applies to all threads incl. new ones |
| UHH breakpoint | yes | yes (400k) | no trampoline; any displaceable instruction; exact under threads via displaced stepping |
| Frida Interceptor | yes | yes (400k) | inline trampoline; needs ≥5-byte site + reachable within ±2 GB; JS onEnter bridge per call is the 20× cost |
| Frida CModule | **no (hangs)** | — | native onEnter removes the JS bridge, but wedged the target on load here; extra C/Gum build surface |
| Frida Stalker | **no (hangs at volume)** | exact only at small scale | per-instruction dynamic recompilation of every thread; overhead unbounded for a hot syscall loop |
| Frida hardware bp | runs, impractical | **no (8/16000)** | per-thread only (no process-wide/future-thread arming), one-shot re-arm broke across 8 threads |

### Flexibility / coverage matrix

- **UHH gives three selectable per-probe backends in one API** (`PROBE_INLINE`,
  `PROBE_HW`, `PROBE_BREAKPOINT`), chosen per site:
  - *inline* — fastest, for sites with ≥5 relocatable bytes.
  - *hardware* — **no code modification**, works on **any** instruction (even a
    2-byte store), limited to ≤4 debug-register slots, and is armed on **every
    thread including threads created later** (via the external debugger).
  - *software breakpoint* — no trampoline, works on any displaceable instruction,
    exact under multithreading via displaced single-stepping.
- The gated flag site (`ParsedFlagSite`, a 2-byte `mov [rcx],eax` + `ret`) is **too
  short for any inline trampoline** — UHH uses a software breakpoint there and it
  just works; Frida's Interceptor (also a trampoline) cannot hook such a site
  directly, and Frida exposes **no practical no-code-modification primitive** for it
  on this platform (its per-thread HW-bp API mis-counts, see above).
- **Frida Interceptor** needs a ≥5-byte site and a trampoline reachable within
  ±2 GB, and pays a JS bridge on every hit (the 20× here). **CModule** removes the
  bridge but adds C/Gum build complexity and did not run at all here. **Stalker**
  can count without patching code but is per-thread and recompiles everything it
  traces. **Hardware breakpoints** in 16.5.9 are per-thread
  (`ThreadDetails.setHardwareBreakpoint`) with no process-wide or future-thread
  variant and no thread-creation observer, so they cannot be armed on probe_app's
  worker threads before they start their read loop without racing.

## Finding: Frida 17.25.2 cannot instrument this VM

(Superseded: root-caused in the section at the top. It was a Frida 17.25 bug, fixed in 17.26.0.)

Both `frida.spawn()` and `frida.attach()` abort with the fatal gum error **"Unable
to locate the ntdll loader TLS routines"** on Windows 10 19045 (ntdll
10.0.19041.2788), reproduced three independent ways (spawn via the existing
harness, attach, and an introspection script). The baseline (no Frida) runs fine, so
this is a Frida-17.25.2-vs-this-ntdll signature-matching regression, not an
environment problem. **frida 16.5.9** attaches cleanly, so all Frida numbers here are
from 16.5.9 (installed in an isolated venv `C:\work\fv16`). Frida is driven by
**attach** (launch probe_app gated → attach → install hook → release the gate)
rather than spawn, which also sidesteps the suspended-loader issue.

## How to reproduce

```bat
:: on the VM, with frida 16.5.9 available (C:\work\fv16)
C:\work\fv16\Scripts\python.exe bench\bench_matrix.py ^
   --rel build-x64\Release --threads 8 --reads 50000 --repeats 3 ^
   --methods "baseline,uhh:inline,uhh:hw,uhh:breakpoint,frida:interceptor"
:: wrap EACH method in a Start-Job + Wait-Job -Timeout so a hanging Frida method
:: (CModule/Stalker/hwbp) cannot wedge the whole run; treat a timeout as the result
:: "not viable for this workload".
```

Files: `bench/bench_matrix.py` (unified driver), `bench/frida/read_logger.js`
(Interceptor), `read_cmodule.js` (CModule), `read_stalker.js` (Stalker),
`read_hwbp.js` (hardware breakpoint). Raw per-run data and per-method summaries in
`bench/results/`.
