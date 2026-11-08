# UHH vs Frida — instrumentation benchmark

The current comparison is the first section below ("UHH vs Frida 17.26.1"). Everything after it
is kept for history and is SUPERSEDED (see "Why the earlier comparison was superseded").
Reproduce with `bench/frida/vs_frida.py` (how: `bench/frida/README.md`); raw rows in
`bench/results/frida17-2026-11-07/`.

## Per-method cost (branch `bench2`, 2026-11-08; send_log_stack / call_func rows updated by `perf6`)

What one callback operation costs on each backend. `hitcost_target` calls `hit_site` (exported, cdecl, one
argument) in a tight loop and times the loop in-process (QPC); `hitcost_driver --method m` probes it with a callback
doing exactly one operation, so **op = ns/hit(method) - ns/hit(empty)** on the same backend. Harness:
`perf_ab.py --group methods --rounds 3` (each run waits for a quiet VM, < 12% busy; every run also checked exact:
hits == calls, logs == calls for send_log*, nothing dropped, add_once's one-shot probes fired once each), tables by
`bench/perfab/methods_table.py`; raw rows `bench/results/methods-2026-11-08/`. Machine: the Win10 test VM (4 vCPU on an
i5-6600), quiet-VM placeholder held for the round, build 5f64c9b (merge-frida 607fe19 + the harness). 1 thread.
Sizes per run: inline 200,000 calls (send_log_stack 50,000, add_once 5,000); breakpoint/hw 20,000 (send_log_stack,
call_func, call_original 5,000; add_once 2,000). Cells: **median (spread = (max-min)/median over 3 rounds)**, then the
op cost. Breakpoint/hw in **us**, inline in **ns**. Uninstrumented call: 2.5 ns (x64 and x86).

| method (what the callback does) | breakpoint us | op us | hw us | op us | inline ns | op ns |
|---|---:|---:|---:|---:|---:|---:|
| **x64** empty = the hit itself | 77.8 (3%) | 77.8 | 91.5 (3%) | 91.5 | 67.5 (7%) | **65** |
| get_reg (CX) | 79.5 (4%) | ~0 | 92.8 (1%) | ~0 | 71.3 (9%) | 3.8 |
| set_reg (AX, a new value each hit) | 77.8 (5%) | ~0 | 91.7 (1%) | ~0 | 78.0 (5%) | 10.5 |
| get_func_arg(0) | 79.4 (2%) | ~0 | 89.4 (5%) | ~0 | 68.4 (3%) | 0.9 |
| get_mem 64 B at SP | 86.2 (2%) | 8.4 | 95.5 (3%) | 4.0 | 81.0 (3%) | 13.5 |
| set_mem 8 B at SP (after an 8 B get_mem) | 86.0 (3%) | 8.2 | 100.8 (4%) | 9.3 | 90.4 (6%) | 22.9 |
| send_log("hit %llu", arg0) | 81.3 (1%) | 3.5 | 91.2 (5%) | ~0 | 247 (34%) | 179 |
| send_log_stack (perf6) | 163.4 (2%) | **86** | 173.6 (4%) | **85** | 1,532 (33%) | **1,466** |
| call_func(kernel32!GetCurrentProcessId) (inline: perf6) | 279.5 (1%) | 202 | 290.6 (4%) | 199 | 2,159 (2%) | **2,093** |
| call_original + return_from | 300.4 (3%) | 223 | 250.2 (1%) | 159 | 935 (18%) | 867 |
| control op: add_once (see below) | 274.1 (7%) | 196 | 285.5 (8%) | 194 | 305,962 (3%) | 305,895 |
| **x86** empty = the hit itself | 124.4 (2%) | 124.4 | 138.2 (11%) | 138.2 | 136 (4%) | **134** |
| get_reg (CX) | 123.1 (3%) | ~0 | 137.7 (3%) | ~0 | 139 (6%) | 3.2 |
| set_reg (AX, a new value each hit) | 123.7 (2%) | ~0 | 138.7 (2%) | ~0 | 152 (3%) | 15.7 |
| get_func_arg(0) | 134.8 (1%) | 10.4 | 146.9 (5%) | 8.7 | 140 (3%) | 4.1 |
| get_mem 64 B at SP | 130.9 (2%) | 6.5 | 146.3 (9%) | 8.1 | 159 (2%) | 22.5 |
| set_mem 8 B at SP (after an 8 B get_mem) | 139.2 (1%) | 14.8 | 152.4 (2%) | 14.2 | 174 (6%) | 37.3 |
| send_log("hit %llu", arg0) | 135.0 (1%) | 10.6 | 148.7 (2%) | 10.5 | 269 (1%) | 133 |
| send_log_stack (perf6) | 325 (1%) | **200** | 371 (9%) | **233** | 9,019 (5%) | 8,883 |
| call_func(kernel32!GetCurrentProcessId) (inline: perf6) | 412 (9%) | 288 | 426 (3%) | 288 | 2,171 (1%) | **2,035** |
| call_original + return_from | 499 (5%) | 375 | 392 (4%) | 254 | 1,552 (3%) | 1,416 |
| control op: add_once (see below) | 428 (17%) | 303 | 448 (7%) | 310 | 419,491 (4%) | 419,354 |

Reading it:
- **Breakpoint/hw: the debug event is the cost.** A hit is 78-92 us (x64) / 124-138 us (x86) on this VM; a context op
  that touches no target memory (get_reg, set_reg, x64 get_func_arg, send_log's formatting and enqueue) is below the
  resolution of the run (~2-5 us at these spreads), "~0". Each target memory access is one ReadProcessMemory /
  WriteProcessMemory: +4..15 us. x86 get_func_arg and x86 send_log("%llu", arg0) are +9..11 us for that reason (x86
  arguments are on the stack). Operations that make the TARGET run while the thread is stopped (call_func,
  call_original) cost about two more debug-event round trips: +160..220 us x64, +250..375 us x86.
- **Inline: tens of ns.** The hit is 65 ns (x64) / 134 ns (x86). get_reg/get_func_arg are a load (1-4 ns); set_reg
  is ~10-16 ns because a changed value counts an override (one interlocked add on the shared header, the same metric
  breakpoint/hw keep); get_mem/set_mem validate the range (the per-thread region cache; writes are re-checked every
  time): 13-37 ns; send_log 133-179 ns (format + ring publish).
- **Control op** = add_once: the documented return-hook idiom -- read the return address at the entry and
  `probe_add_address(get_session(c), ret, cb, PROBE_BREAKPOINT | PROBE_ONCE)`; the one-shot probe fires on the return
  and retires. The row includes that one-shot breakpoint hit (~one breakpoint hit, 78 / 124 us), so the add itself
  is ~120 us from a breakpoint/hw callback (x64; x86 ~180 us) and ~228 us from an INLINE callback (x64; x86 ~295 us:
  the request is forwarded to the controller synchronously and the thread waits for the INT3 to be armed).

Surprises found by this table, and what `perf6` did about them (before/after: "Update: perf6" below):
- **x86 send_log_stack on breakpoint/hw was 0.77-1.1 ms per hit** (x64 155 us) for a 4-frame stack. Cause: StackWalk64
  read the target in ~170-280 ReadProcessMemory calls of ~14 bytes per walk, ~50 of them FAILING (the x86 walker probes
  the bytes before candidate return addresses byte by byte, unmapped ones included), 2-8 us each under WOW64. Fixed:
  reads served from per-walk page copies (an unreadable page answers "unreadable" without a call) -- 8 page reads per
  walk; frames identical. hw was slower than breakpoint on x86 because at a hw hit the walker sees the real prologue
  bytes (not our INT3) and walks one frame more (the caller the breakpoint path re-inserts from [esp]); it is ~35 us
  now. The writer's per-frame symbolization (dbghelp, same few addresses again and again) is cached by address
  (cleared at every module load/unload), which is what makes inline send_log_stack 4.6x cheaper on x64 (the log queue's
  backpressure had made the program wait on the writer).
- **Inline call_func was ~2.7 us** for a callee that takes ~1 ns: GetModuleHandleA + GetProcAddress + a VirtualQuery per
  call. Fixed partly: a lock-free per-symbol cache for the NAME->address resolution, valid while no module has
  unloaded since the entry was resolved (the loader's DLL notification, sent before an image is unmapped, bumps a
  generation); regress `cdx-cfreuse-*` (a DLL unloaded and another mapped at its base under the same name: never
  called through the stale entry). The VirtualQuery stays -- it is re-run on every call (regress `cdx-cfnx-*`) because
  the gospel requires inline to refuse a target the program has made non-executable WITHOUT calling into it (a call
  would raise a first-chance fault the program's own handlers would see; breakpoint/hw refuse silently). The
  VirtualQuery turns out to be most of the cost on this VM, so the net is ~2.7 -> ~2.1 us (1.3x), not the resolve-only
  figure.
- **Adding a probe from an inline callback costs ~100 us more than from breakpoint/hw** (x64 ~205 vs ~100 us, not in
  the table above -- it is the add_once rows minus the one-shot hit): the
  inline callback reaches the controller through one more debug event (a raised exception: the target stops, the
  debugger wakes, continues it) -- the same round trip as a breakpoint hit, and it is what makes the add synchronous
  (the probe is armed when the call returns, probe_api.h). The controller can only act inside a debug event (one
  debug thread owns the session), so that round trip stays. perf6 trimmed what was around it (one read of the
  request instead of two, no stderr line per successful add -- a console write each); within noise in the table.
- **Inline call_original + return_from is 0.9 us (x64) / 1.4 us (x86)**, ~13x an empty hit: the x64 thunk saves the
  hit's nonvolatile GPRs and XMM6-15 into an unwindable machine frame, x86 relinks the SEH chain (both needed so an
  exception in the original reaches the program's handlers).
- Inline send_log (34%) and send_log_stack (77% x64) have wide spreads at these sizes (3 rounds); the medians agree
  with the earlier perf_ab sessions (send_log 1 thread 163-317 ns).

### Update: perf6 (2026-11-08) -- the three outliers, before/after

`perf_ab.py --group methods --rounds 3`, interleaved, base = merge-frida 5aad1ad, perf6 = branch `perf6` (same
targets for both; quiet-VM placeholder held for the round). Median (spread) per hit; breakpoint/hw in us, inline in
ns. Raw rows `bench/results/perf6-2026-11-08/` (x86 inline send_log_stack: a second run, `ab-x86-inline-stack.jsonl`,
mid = perf6 without the x86 capture change, new = with it; the main run's x86 inline cell predates that change).

These are the final, gospel-safe numbers (the two in-target caches were made fault-safe after a first pass;
see the note under the table). base = merge-frida 5aad1ad. send_log_stack/call_func from `ab2_*`, add_once/empty from
`ab-*`; x86 inline send_log_stack also measured against the no-capture-opt build in `ab2_x86_stack.jsonl`.

| cell | x64 base | x64 perf6 | | x86 base | x86 perf6 | |
|---|---:|---:|---:|---:|---:|---:|
| breakpoint send_log_stack (us) | 236.0 (5%) | 163.4 (2%) | 1.4x | 895 (2%) | 325 (1%) | 2.8x |
| hw send_log_stack (us) | 249.5 (1%) | 173.6 (4%) | 1.4x | 1,267 (65%) | 371 (9%) | 3.4x |
| inline send_log_stack (ns) | 7,110 (16%) | 1,532 (33%) | 4.6x | 9,907 (10%) | 9,019 (5%) | 1.1x |
| inline call_func (ns) | 2,826 (8%) | 2,159 (2%) | 1.3x | 2,843 (1%) | 2,171 (1%) | 1.3x |
| breakpoint add_once (us) | 256.6 (1%) | 257.1 (5%) | = | 420 (8%) | 428 (9%) | = |
| hw add_once (us) | 286.5 (6%) | 279.5 (6%) | = | 442 (4%) | 441 (3%) | = |
| inline add_once (us) | 290.7 (2%) | 283.8 (3%) | = | 410 (3%) | 413 (9%) | = |
| empty (bp us / hw us / inline ns) | 77.0 / 89.8 / 67.7 | 77.7 / 88.8 / 69.3 | = | 123 / 136 / 140 | 125 / 138 / 135 | = |

Where the wins are (docs/ROADMAP.md "perf6 findings"): the big ones are **controller-side** and unconditionally safe --
the stack walk reads the target by page per walk (breakpoint/hw send_log_stack, up to 3.4x on x86) and the log writer's
per-frame symbolization is cached by address (inline send_log_stack x64 4.6x). The two **in-target** caches are more
modest after being made fault-safe for the gospel: inline call_func keeps the name->address resolution but re-checks
executability every call (1.3x, not resolve-only), and the x86 inline stack capture no longer caches module-code
regions across hits (so x86 inline send_log_stack is ~1.1x, from the writer symbol cache only, not the 3.x of the first
pass). A program that makes its own loaded code non-executable or a guard page between hits is refused / skipped without
a fault or a consumed guard (regress `cdx-cfnx-*`, `cdx-codeprot-*`). Frames reported are unchanged (`--only stack`,
x64 + x86).

### UHH_SHARED state vs plain globals (C7): equal on every backend

The same atomic increment (`fetch_add`, relaxed) on a plain global and on a `UHH_SHARED` one, in the same run as the
table above. "plain driver" = `hitcost_driver` (its callbacks module has no UHH_SHARED state: breakpoint/hw callbacks
run from the driver itself and counter_shared is the plain counter there); "shared driver" = `hitcost_driver_shared`
(opted in: breakpoint/hw callbacks run from the controller's per-session copy of the agent DLL, every API call through
its controller table). Inline callbacks run from the injected agent in both, where counter_shared IS the shared section.

| | breakpoint plain / shared driver (us) | hw plain / shared driver (us) | inline plain / shared driver (ns) |
|---|---:|---:|---:|
| x64 empty | 77.8 (3%) / 79.9 (3%) | 91.5 (3%) / 92.7 (4%) | 67.5 (7%) / 67.0 (7%) |
| x64 counter_plain | 77.4 (1%) / 77.7 (3%) | 91.9 (2%) / 90.8 (4%) | 79.0 (5%) / 76.0 (4%) |
| x64 counter_shared | 76.9 (3%) / 77.9 (4%) | 90.0 (3%) / 91.0 (2%) | 77.6 (12%) / 77.3 (3%) |
| x86 empty | 124.4 (2%) / 124.9 (1%) | 138.2 (11%) / 140.2 (5%) | 136 (4%) / 137 (7%) |
| x86 counter_plain | 125.2 (1%) / 125.4 (2%) | 137.6 (2%) / 138.5 (26%) | 148 (1%) / 146 (2%) |
| x86 counter_shared | 122.9 (1%) / 125.2 (1%) | 138.7 (3%) / 138.6 (22%) | 145 (6%) / 147 (2%) |

Every pair overlaps within its spread (largest median difference: x64 breakpoint empty +2.6% with 3% spreads); shared
vs plain counter in the same run differs by <= 2% (breakpoint/hw) and <= 3 ns (inline). The shared page is plain
memory to the code touching it, and the controller-copy indirection of a UHH_SHARED module (one predictable branch +
an indirect call per API call) is invisible next to a debug event. The inline counter rows are +10-12 ns over empty:
the lock-prefixed add itself, the same for both globals.

## Update: branch `perf5` (2026-11-07/08 night): UHH vs Frida 17.26.1, same sessions

UHH = `perf5` e01ba59 (agent protocol v27; on merge-frida 535ebec), Frida 17.26.1, same VM, same `vs_frida.py`, every
run exact. **Session G** (the final build; 8 threads x 50,000 reads, hit 200,000 calls, churn 8 x 2,000 (x64) /
8 x 1,000 (x86) rounds, 6 repeats, quiet-VM placeholder). Added ns per event (median [min..max], over the session's
baseline); churn: added wall seconds. The last column pools sessions A, B, C, D and G (32 runs per method and arch,
each against its own session's baseline median; A-D were earlier builds of this branch). Raw rows:
`bench/results/perf5-2026-11-07/` (`<session>-<arch>-vsf.jsonl`, perf_ab rows `-pab.jsonl`).

| workload | arch | **uhh-inline** (G) | frida-cmodule (G) | pooled A-G: uhh vs frida |
|---|---|---:|---:|---:|
| count | x64 | **+100** [92..124] | +246 [221..463] | |
| gated | x64 | **+281** [254..294] | +463 [287..539] | **+283** vs +446 |
| hit | x64 | **+78.0** [71.4..79.6] | +255 [235..268] | |
| churn (s) | x64 | **+0.17** [-0.12..0.22] | +0.36 [0.19..0.45] | **+0.165** vs +0.366 |
| count | x86 | **+112** [84..142] | +268 [193..438] | |
| gated | x86 | **+402** [342..1,271] | +454 [322..564] | **+344** vs +401 |
| hit | x86 | **+151** [149..152] | +286 [276..288] | |
| churn (s) | x86 | **-0.02** [-0.05..0.40] | +0.38 [0.10..0.49] | **+0.146** vs +0.311 |

- **Ahead of Frida CModule in every inline cell on both arches**, x86 gated and x86 churn included. Per session (median
  added, UHH/Frida): x86 gated +337/+395 (A), +419/+396 (B: two UHH runs at 1,140 and 1,433 ns/read), +329/+391 (C),
  +329/+341 (D), +402/+454 (G); x86 churn +0.38/+0.40, +0.22/+0.33, +0.04/+0.32, -0.02/+0.14, -0.02/+0.38 s. x86 gated
  is ahead in four of five sessions and pooled; UHH's x86 gated spread has rare slow runs (D 2,079, G 1,760 ns/read;
  one in six) that Frida's does not -- not explained yet.
- Churn is fixed cost, and that cost was the antivirus scan of each session's new agent copy plus dbghelp's lookup:
  now a trimmed copy, a pre-scanned warm copy taken by rename, both prepared off the critical path (ROADMAP
  "perf5 findings"). x86 1-round churn: probe_launch ~260 -> ~45 ms.

Before / after this branch (perf_ab, base = the branch point e3b1bea; 5 rounds; session D unless noted; ns per call
unless noted; spreads are wide on this VM -- the A-D range is given where it matters):

| | x64 base | x64 perf5 | x86 base | x86 perf5 |
|---|---:|---:|---:|---:|
| inline empty hit, 1 thread | 68.5 | 70.3 | 136 | 136 |
| send_log hit, 4 threads | 635 | 656 | 754 | 762 |
| send_log hit, 1 thread | 176 | 163 | 266 | 317 (before the drainer pause; with it, session F vs merge-frida: 265 -> 285) |
| gated_config inline 8 x 50,000 (ns/read) | 750 | **700** | 884 | **806** (A-D: -6.5..-8.9% each) |
| logs/s, 1 thread to a file | 3.75M | 2.91M (A: 3.19M -> 3.98M) | 2.77M | 2.86M (A: 2.42M -> 3.21M) |
| idle event -> stdout latency p50 (ms) | 0.27 | 0.27 | 0.26 | 0.28 |
| inline launch, lifecycle_bench launch_ms (A-D medians) | 112-221 | 54-157 | 110-236 | 52-142 |

Against the CURRENT merge-frida (535ebec, with psdetach's fair drain lock; session E, 6 rounds, `-pab` rows `E-*`):
x64 inline empty hit 68.2 -> 67.4, send_log 1 thread 211 -> 207, logs/s to a file 2.90M -> 2.99M, gated 787 -> **700**
ns/read, launch 110 -> 78 ms: no x64 regression. x86: empty hit 139 -> 136, gated 912 -> **817**, logs/s to a file
2.14M -> 2.51M, launch 220 -> 86 ms, but send_log 1 thread 264 -> 319 ns -- fixed after session E by the drainer pause
(ROADMAP "perf5 findings"); session F (6 rounds, vs merge-frida): x86 send_log/1 thread 265 -> 285 (spread 190%),
gated 879 -> 816, logs/s to a file 2.40M -> 2.72M; x64 209 -> 208, gated 788 -> 711, logs/s 2.41M -> 2.98M.

## Update: branch `perf4` (2026-11-07 night): UHH vs Frida 17.26.1, same sessions

UHH = `perf4` c2edf28 (on merge-frida 59f6d61; agent protocol v26), Frida 17.26.1, same VM, same
`vs_frida.py`, every run exact. **Session A** (the main table): 8 threads x 50,000 reads, hit 200,000
calls, churn 8 x 2,000 (x64) / 8 x 1,000 (x86) rounds, 6 repeats, quiet-VM placeholder in the other heavy
slot. hw/breakpoint columns: session C, lean sizes (8 x 12,500, hit 50,000), 3 repeats (hw stays external
by owner decision: out of scope). Added ns per event (median [min..max], over the session's pooled
baseline); churn: added wall seconds. Raw rows: `bench/results/perf4-2026-11-07/` (fin3 = A, fin1 = B, fin2 = C).

| workload | arch | **uhh-inline** | **frida-cmodule** | uhh-hw | frida-hw | uhh-breakpoint |
|---|---|---:|---:|---:|---:|---:|
| count | x64 | **+108** [99..184] | +331 [255..569] | +118,325 | +23,060 | +98,209 |
| gated (every read logged + delivered) | x64 | **+335** [294..369] | +423 [337..712] | +123,972 | -- | +105,487 |
| hit | x64 | **+73** [70..77] | +252 [241..255] | +91,128 | +23,146 | +76,905 |
| churn (s) | x64 | **+0.265** [0.186..0.487] | +0.290 [-0.008..0.409] | | | |
| count | x86 | **+133** [81..501] | +284 [241..314] | +214,959 | +19,865 | +200,466 |
| gated | x86 | +377 [372..413] | +376 [333..599] | +229,735 | -- | +211,557 |
| hit | x86 | **+141** [140..148] | +279 [272..299] | +151,435 | +47,170 | +142,157 |
| churn (s) | x86 | +0.311 [0.016..0.344] | **+0.261** [0.158..0.478] | | | |

- **Ahead of Frida CModule:** x64 in all four (count 3.1x less, gated 1.3x, hit 3.5x, churn marginally);
  x86 count (2.1x) and hit (2.0x).
- **Not won on x86: gated is a tie** (+377 vs +376 in session A; UHH's spread 372..413 is narrower than
  Frida's 333..599) and **churn is behind** (+0.31 vs +0.26 s; wall clock of a ~1 s run, both spreads
  wide). Session B (lean sizes 8 x 12,500, 5 repeats, the build BEFORE the x86 get_func_arg change) had x86
  count +232 vs +193 and gated +451 vs +357 -- behind; earlier sessions (perf_ab A/B rounds, same day)
  had x86 gated +403 vs +446 and +423 vs +580. Frida's x86 gated row moves +281..+599 between sessions;
  a 100,000-read run is ~50-90 ms of target time.
- Churn is mostly fixed cost (launch, agent injection, teardown, measured to process exit for UHH and to
  the last record for Frida): with 1 round per thread UHH added +0.17 s (x64) / +0.47 s (x86) and Frida
  +0.15 / +0.44 (`churn1-*` rows).

Before / after this branch (perf_ab, base = merge-frida 3f06c24, interleaved, 3 rounds, quiet gate; final
build; rows `fin1-*-pab`, `fin3-*-pab`, `j2-*`; ns per call unless noted):

| | x64 base | x64 perf4 | x86 base | x86 perf4 |
|---|---:|---:|---:|---:|
| inline empty hit, 1 thread | 90.9 | **65.2** | 151 | **134** (136 with x86 stack args: fin3) |
| inline empty hit, 4 threads | 148 | 149 | 193 | **185** |
| send_log hit, 1 thread | 360 | **177** | 421 | **261** (fin3) |
| send_log hit, 4 threads | 1,299 | **625** | 1,682 (j2, 6 rounds) | **749** |
| gated_config inline 8 x 50,000 (ns/read; uninstrumented 416-422 / 513-540) | 838 | **759** | 1,050 | **918** (fin3) |
| controller CPU per log, gated (GetProcessTimes; noisy) | 781 | **625** | 1,055 | **820** |
| logs/s, 1 thread to a file | 2.38M | **2.98M** | 2.09M | **2.36M** |
| controller CPU per log, 1 thread to a file | 461 | **242** | 586 | **438** |
| idle event -> stdout latency p50 / p99 (ms) | 15.8 / 16.6 | **0.28 / 8.9** | 15.8 / 16.7 | **0.28 / 13.3** |
| idle controller CPU (Mcycles/s, idle_cpu.py) | 3.6 | **2.3** | 3.8 | **2.4** |
| inline launch (lifecycle_bench launch_ms) | 207 | **111** | 259 | **129** |

What changed is in docs/ROADMAP.md, "perf4 findings". The count/hit callback (`uhh_count_call`) now does
exactly the CModule agent's work (a plain `sink ^=` and one 32-bit atomic add; it did two 64-bit atomic
RMWs, LOCK CMPXCHG8B loops on x86); the library rows above (perf_ab) use hitcost's own callbacks and are
unaffected by it.

## Update: branch `perf` (2026-11-07 evening) against the same Frida 17.26.1 rows

Same VM, same `vs_frida.py`, lean sizes (8 x 12,500 reads = 100,000 events, hit 50,000 calls),
3 repeats, every run exact. UHH = `perf` c086163 (x86 uhh-inline / frida-cmodule rows: f1d011f, the
hook-shadow fast path, re-run together), Frida rows re-measured in the same session. Raw rows: `bench/results/frida17-perf-2026-11-07/`. Added ns per event (median):

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

**Update (branch `binlog`, 2026-11-07): done, the gated example now costs UHH inline +397 ns/read on x64
and +729 on x86 (was +2,358 / +2,886 in the same A/B; Frida CModule +521 / +555 in those sessions).** The
2 us was not the text formatting in the target: the controller's log writer (two `snprintf` per JSON line,
a lock and a wake-up per record) was the bottleneck and the ring's backpressure made the target wait for it.
Records now move in chunks, the writer formats without printf, an idle drainer no longer sleeps a whole
15.6 ms timer tick, and send_log formats the common conversions without the CRT (byte-identical, checked).
Per-hit send_log: 1,312 -> 347 ns (x64), 3,357 -> 623 ns (x86). Profile, change and full table:
docs/ROADMAP.md "Inline log cost findings"; raw rows `bench/results/binlog-2026-11-07/`.
On top of merge-frida 5f13966 (perf phase 3, which took the same writer change), binlog still cuts the
per-hit send_log 508 -> 338 ns (x64) and 759 -> 425 ns (x86), and gated_config inline 1,053 -> 821 / 1,532 ->
1,048 ns/read (perf_ab); vs_frida gated in the same sessions: x64 uhh-inline 986 vs frida-cmodule 808-1,028,
x86 1,232 vs 983-1,089 ns/read (baselines 423-556).


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
