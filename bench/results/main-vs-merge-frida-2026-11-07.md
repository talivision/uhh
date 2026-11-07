# main vs merge-frida vs agentscope: per-probe-type hit time, attach/detach (2026-11-07)

Builds (clean Release, MSVC, same VM, same day): **main** = f9f3436 (2026-11-05), **mf** =
merge-frida 034b245, **agentscope** = 7f09697 (agent injected only for inline sessions + bounded
15 s detach wait). Each build's own controller and agent; every TARGET binary (hitcost_target)
is the mf build's, so all three instrument byte-identical programs. Harness: `bench/perfab`
(`perf_ab.py`, `lifecycle_bench.cpp`, `summarize.py`), the same source applied to every build.
Machine: Windows 10 VM, i5-6600 4 cores; both heavy VM slots held, each run started only once
the VM was < 12% busy for 1 s (`pre_busy` in the raw data, `bench/results/perfab/*.jsonl`).
Rounds interleaved: every case runs all builds back to back, order rotated each round.

Method: `hitcost_driver` probes `hitcost_target.exe!hit_site` (or, for **watch**, a hardware DATA
watchpoint, PROBE_HW | PROBE_WATCH_WRITE, on the global `hit_site` writes) and the target times
its own call loop (QPC). Per hit = loop wall / calls per thread. Calls per measurement: inline
200k per thread, hw / watch / breakpoint 20k total; t4 = 4 threads sharing the calls. **empty** =
callback does nothing; **send_log** = `send_log(c, "hit %llu", get_func_arg(c, 0))`, stdout to a
file, every log counted (all runs exact: hits == calls, logs == calls, 0 dropped). Attach/detach:
`lifecycle_bench --attach` to a running hitcost_target (idle = blocked on stdin, busy = hitting the
probe in a loop), hold 300 ms, `probe_close` (detach); the target must carry on afterwards (all did).

Verdict column: gain / REGRESSION only when the ranges do not overlap across rounds AND the
medians differ by >= 5%; otherwise "~". Spread = (max - min) / median over the rounds.

## Headline (median per hit; x64 = 3 rounds; x86 = 2 rounds, PRELIMINARY -- run2 below has 3 rounds of main vs mf and agrees)

| probe type | arch | threads | callback | main | mf | agentscope | mf vs main |
|---|---|---|---|---:|---:|---:|---|
| uninstrumented | x64 | 1 | - | 2.5 ns | 2.5 ns | 2.5 ns | ~ |
| inline | x64 | 1 | empty | 83 ns | 110 ns | 111 ns | **+33%** |
| inline | x64 | 1 | send_log | 1.24 us | 1.36 us | 1.32 us | **+9%** |
| inline | x64 | 4 | empty | 137 ns | 166 ns | 176 ns | **+22%** |
| hw (execute) | x64 | 1 | empty | 103 us | 170 us | 170 us | **+64%** |
| hw (execute) | x64 | 1 | send_log | 100 us | 169 us | 165 us | **+69%** |
| hw data watch (write) | x64 | 1 | empty | 102 us | 162 us | 161 us | **+60%** |
| hw data watch (write) | x64 | 1 | send_log | 100 us | 159 us | 160 us | **+60%** |
| breakpoint | x64 | 1 | empty | 148 us | 115 us | 111 us | **-22% (gain)** |
| breakpoint | x64 | 1 | send_log | 150 us | 116 us | 117 us | **-22% (gain)** |
| hw / watch / breakpoint | x64 | 4 | empty | 345 / 324 / 496 us | 573 / 561 / 399 us | 569 / 544 / 395 us | +66% / +73% / -20% |
| uninstrumented | x86 | 1 | - | 2.6 ns | 2.6 ns | 2.5 ns | ~ |
| inline | x86 | 1 | empty | 97 ns | 208 ns | 207 ns | **+116%** |
| inline | x86 | 1 | send_log | 2.14 us | 3.38 us | 3.16 us | **+58%** |
| hw (execute) | x86 | 1 | empty | 157 us | 237 us | 251 us | **+51%** |
| hw data watch (write) | x86 | 1 | empty | 156 us | 233 us | 234 us | **+50%** |
| breakpoint | x86 | 1 | empty | 248 us | 178 us | 175 us | **-28% (gain)** |
| hw / watch / breakpoint | x86 | 4 | empty | 576 / 577 / 940 us | 890 / 865 / 688 us | 893 / 875 / 680 us | +54% / +50% / -27% |

(t4 rows: per call as each of the 4 threads sees it, i.e. the wall per hit x 4 -- breakpoint/hw
hits are serialized by the debugger.)

| attach / detach (ms) | arch | main | mf | agentscope |
|---|---|---:|---:|---:|
| attach, breakpoint (idle / busy) | x64 | 45 / 46 | 227 / 210 | 45 / 46 |
| attach, hw (idle / busy) | x64 | 45 / 45 | 187 / 214 | 46 / 45 |
| attach, inline (idle / busy) | x64 | 185 / 110 | 107 / 191 | 205 / 174 (noisy: 74-118% spread on every build) |
| detach, breakpoint / hw / inline (idle) | x64 | 266 / 266 / 314 | 314 / 314 / 329 | 297 / 266 / 314 |
| attach, breakpoint (idle / busy) | x86 | 47 / 51 | 218 / 246 | 46 / 46 |
| attach, hw (idle / busy) | x86 | 136* / 47 | 242* / 214 | 46 / 47 |
| detach, breakpoint / hw / inline (idle) | x86 | 266 / 297 / 321 | 314 / 329 / 329 | 266 / 282 / 322 |

(* one slow round each; 2 rounds.) Detach times are quantized near multiples of the 15.6 ms
timer tick (266 = 17, 314 = 20 ticks): detach is dominated by waits, not work.

## What explains the differences (measured where marked)

- **breakpoint: 22-28% faster** on mf: one debug event per hit (the per-site trampoline replaced the
  INT3 + single-step pair).
- **hw / watch: 50-73% slower per hit** on mf -- **measured cause: the fairness yield rounds**
  (ROADMAP A5). With the yield rounds switched off (bench-only env toggle in a scratch build of mf,
  x64, 3 runs each, us/hit): hw 166 -> 113, watch 156 -> 106, breakpoint 110 -> 73. A yield round
  every 20 ms sends each hot thread to sleep ~4 ms; with ONE hot thread and every other thread
  blocked, nobody benefits, and it costs ~30% of the hit rate on breakpoint AND hw (breakpoint's
  net gain hides it: without the rounds breakpoint would be 2x faster than main). The rest of the
  hw gap: the per-exception context-round-trip watch (`ctx_watch_begin`: OpenThread + Suspend /
  Resume to read the suspend count) ~4-8 us/hit (hw 113 -> 105, bp 73 -> 69 with both off),
  leaving hw within ~5% of main. Sampling profile of the mf controller (bench/perfab/sampler.py):
  the debugger thread's own CPU is small; it is mostly waiting for the target (NtWaitForDebugEvent)
  and in Get/SetThreadContext.
- **inline: +27 ns (x64) / +111 ns (x86) per empty hit** -- the per-hit accounting added since main
  (controller-death guard / in-flight accounting): a thread-slot lookup, a second pair of
  interlocked operations on the shared stripe line (`running`), the hit-scope record, the per-hit
  region-cache reset. Profile (x64, sampler): call_mid, run_callback, mid_entry, forget_region,
  thread_slot. x86 not profiled yet. NOT root-caused to a single change.
- **send_log**: x64 +9%, x86 +58% (+1.2 us/log) -- not root-caused yet (per-hit log carry is the
  suspect).
- **attach on breakpoint/hw: 45 ms -> 190-250 ms** on mf = the agent injected into every attached
  target. **agentscope removes it entirely** (45-47 ms, = main) and brings detach back to main's
  level too. Inline attach is unchanged (it always needed the agent) and noisy on every build.

## Not done / open
- Fairness back-off, commit 4ac7ef6 on `perf` (rounds back off 20 -> 80 ms while no non-yielding
  thread runs in them): **UNMEASURED and NOT YET BUILT** -- the comparison was delivered first.
  It needs a build, the hitcost A/B, and `regress --only check_hunt,check_detach` (hunt-starve bar)
  on both arches before anyone relies on it.
- x86 run3 had 2 of 3 rounds when this table was written (run2's 3 rounds of main vs mf agree).
- UHH vs Frida re-run (bench_matrix W8xR50000 x64/x86 + the full gated_config in both tools,
  bench/frida/gated_full.{js,py}): queued on the VM after run3 at the time of writing; results go
  to C:\work\uhh-perf-results\matrix_{x64,x86}\ and gated_full_{x64,x86}.{log,jsonl}.
- Secondary items of the original list (throughput sweeps, sinks, latency, launch, gated
  end-to-end): harness exists (`perf_ab.py --group extra`), not run (owner: keep it lean).

## Full tables

### x64 (run3: 3 rounds)

| case | metric | main median (spread) | mf median (spread) | agentscope median (spread) | mf vs main | agentscope vs main | rounds |
|---|---|---:|---:|---:|---|---|---|
| hit/base/empty/t1 | ns_per_call (ns/call) | 2.52 (3%) | 2.53 (5%) | 2.47 (3%) | +0.4% ~ | -2.0% ~ | 3/3/3 |
| hit/base/empty/t1 | hits_per_s (hits/s) | 396,825,397 (3%) | 395,256,917 (5%) | 404,858,300 (3%) | -0.4% ~ | +2.0% ~ | 3/3/3 |
| hit/inline/empty/t1 | ns_per_call (ns/call) | 83.2 (4%) | 110 (3%) | 111 (6%) | +32.6% **REGRESSION** | +33.3% **REGRESSION** | 3/3/3 |
| hit/inline/empty/t1 | hits_per_s (hits/s) | 12,017,786 (4%) | 9,061,254 (3%) | 9,016,320 (6%) | -24.6% **REGRESSION** | -25.0% **REGRESSION** | 3/3/3 |
| hit/inline/send_log/t1 | ns_per_call (ns/call) | 1,241 (1%) | 1,355 (9%) | 1,317 (1%) | +9.1% **REGRESSION** | +6.1% **REGRESSION** | 3/3/3 |
| hit/inline/send_log/t1 | hits_per_s (hits/s) | 805,516 (1%) | 738,018 (9%) | 759,555 (1%) | -8.4% **REGRESSION** | -5.7% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t1 | ns_per_call (ns/call) | 103,263 (2%) | 169,561 (2%) | 169,880 (3%) | +64.2% **REGRESSION** | +64.5% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t1 | hits_per_s (hits/s) | 9,684 (2%) | 5,898 (2%) | 5,887 (3%) | -39.1% **REGRESSION** | -39.2% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t1 | ns_per_call (ns/call) | 100,196 (4%) | 169,309 (2%) | 164,810 (8%) | +69.0% **REGRESSION** | +64.5% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t1 | hits_per_s (hits/s) | 9,980 (4%) | 5,906 (2%) | 6,068 (8%) | -40.8% **REGRESSION** | -39.2% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t1 | ns_per_call (ns/call) | 101,627 (3%) | 162,351 (7%) | 161,014 (9%) | +59.8% **REGRESSION** | +58.4% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t1 | hits_per_s (hits/s) | 9,840 (3%) | 6,160 (7%) | 6,211 (10%) | -37.4% **REGRESSION** | -36.9% **REGRESSION** | 3/3/3 |
| hit/watch/send_log/t1 | ns_per_call (ns/call) | 99,527 (2%) | 158,746 (2%) | 160,086 (5%) | +59.5% **REGRESSION** | +60.8% **REGRESSION** | 3/3/3 |
| hit/watch/send_log/t1 | hits_per_s (hits/s) | 10,047 (2%) | 6,299 (2%) | 6,247 (5%) | -37.3% **REGRESSION** | -37.8% **REGRESSION** | 3/3/3 |
| hit/breakpoint/empty/t1 | ns_per_call (ns/call) | 148,225 (2%) | 115,063 (5%) | 110,966 (4%) | -22.4% **gain** | -25.1% **gain** | 3/3/3 |
| hit/breakpoint/empty/t1 | hits_per_s (hits/s) | 6,746 (2%) | 8,691 (5%) | 9,012 (4%) | +28.8% **gain** | +33.6% **gain** | 3/3/3 |
| hit/breakpoint/send_log/t1 | ns_per_call (ns/call) | 149,605 (2%) | 116,188 (2%) | 117,267 (4%) | -22.3% **gain** | -21.6% **gain** | 3/3/3 |
| hit/breakpoint/send_log/t1 | hits_per_s (hits/s) | 6,684 (2%) | 8,607 (2%) | 8,528 (4%) | +28.8% **gain** | +27.6% **gain** | 3/3/3 |
| hit/base/empty/t4 | ns_per_call (ns/call) | 36.5 (8%) | 34.0 (18%) | 33.7 (22%) | -6.9% ~ | -7.6% ~ | 3/3/3 |
| hit/base/empty/t4 | hits_per_s (hits/s) | 109,619,074 (9%) | 117,716,304 (20%) | 118,588,793 (22%) | +7.4% ~ | +8.2% ~ | 3/3/3 |
| hit/inline/empty/t4 | ns_per_call (ns/call) | 137 (2%) | 166 (8%) | 176 (26%) | +21.7% **REGRESSION** | +28.8% **REGRESSION** | 3/3/3 |
| hit/inline/empty/t4 | hits_per_s (hits/s) | 29,259,015 (2%) | 24,035,573 (8%) | 22,710,498 (22%) | -17.9% **REGRESSION** | -22.4% **REGRESSION** | 3/3/3 |
| hit/inline/send_log/t4 | ns_per_call (ns/call) | 6,612 (12%) | 7,909 (7%) | 7,835 (16%) | +19.6% **REGRESSION** | +18.5% **REGRESSION** | 3/3/3 |
| hit/inline/send_log/t4 | hits_per_s (hits/s) | 604,966 (12%) | 505,750 (7%) | 510,523 (14%) | -16.4% **REGRESSION** | -15.6% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t4 | ns_per_call (ns/call) | 344,582 (5%) | 573,400 (3%) | 569,449 (4%) | +66.4% **REGRESSION** | +65.3% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t4 | hits_per_s (hits/s) | 11,608 (6%) | 6,976 (3%) | 7,024 (4%) | -39.9% **REGRESSION** | -39.5% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t4 | ns_per_call (ns/call) | 334,954 (3%) | 578,544 (3%) | 570,663 (3%) | +72.7% **REGRESSION** | +70.4% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t4 | hits_per_s (hits/s) | 11,942 (3%) | 6,914 (4%) | 7,009 (3%) | -42.1% **REGRESSION** | -41.3% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t4 | ns_per_call (ns/call) | 324,109 (1%) | 560,870 (7%) | 544,495 (1%) | +73.0% **REGRESSION** | +68.0% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t4 | hits_per_s (hits/s) | 12,342 (1%) | 7,132 (8%) | 7,346 (1%) | -42.2% **REGRESSION** | -40.5% **REGRESSION** | 3/3/3 |
| hit/watch/send_log/t4 | ns_per_call (ns/call) | 331,723 (3%) | 524,851 (5%) | 532,361 (5%) | +58.2% **REGRESSION** | +60.5% **REGRESSION** | 3/3/3 |
| hit/watch/send_log/t4 | hits_per_s (hits/s) | 12,058 (3%) | 7,621 (5%) | 7,514 (5%) | -36.8% **REGRESSION** | -37.7% **REGRESSION** | 3/3/3 |
| hit/breakpoint/empty/t4 | ns_per_call (ns/call) | 496,298 (3%) | 399,157 (9%) | 395,311 (5%) | -19.6% **gain** | -20.3% **gain** | 3/3/3 |
| hit/breakpoint/empty/t4 | hits_per_s (hits/s) | 8,060 (3%) | 10,021 (9%) | 10,119 (5%) | +24.3% **gain** | +25.5% **gain** | 3/3/3 |
| hit/breakpoint/send_log/t4 | ns_per_call (ns/call) | 521,433 (1%) | 412,793 (1%) | 414,695 (9%) | -20.8% **gain** | -20.5% **gain** | 3/3/3 |
| hit/breakpoint/send_log/t4 | hits_per_s (hits/s) | 7,671 (1%) | 9,690 (1%) | 9,646 (9%) | +26.3% **gain** | +25.7% **gain** | 3/3/3 |
| attach/inline/idle | attach_ms (ms) | 185 (74%) | 107 (115%) | 205 (4%) | -42.1% ~ | +10.9% ~ | 3/3/3 |
| attach/inline/idle | detach_ms (ms) | 314 (10%) | 329 (10%) | 314 (5%) | +5.0% ~ | +0.0% ~ | 3/3/3 |
| attach/inline/busy | attach_ms (ms) | 110 (87%) | 191 (103%) | 174 (102%) | +73.5% ~ | +58.0% ~ | 3/3/3 |
| attach/inline/busy | detach_ms (ms) | 313 (5%) | 329 (5%) | 314 (5%) | +5.0% ~ | +0.1% ~ | 3/3/3 |
| attach/hw/idle | attach_ms (ms) | 45.1 (0%) | 187 (48%) | 45.8 (1%) | +315.2% **REGRESSION** | +1.4% ~ | 3/3/3 |
| attach/hw/idle | detach_ms (ms) | 266 (12%) | 314 (5%) | 266 (12%) | +17.9% **REGRESSION** | -0.0% ~ | 3/3/3 |
| attach/hw/busy | attach_ms (ms) | 45.1 (2%) | 214 (55%) | 45.4 (14%) | +375.0% **REGRESSION** | +0.6% ~ | 3/3/3 |
| attach/hw/busy | detach_ms (ms) | 266 (0%) | 301 (10%) | 266 (1%) | +13.2% **REGRESSION** | +0.0% ~ | 3/3/3 |
| attach/breakpoint/idle | attach_ms (ms) | 45.2 (17%) | 227 (19%) | 45.2 (2%) | +402.2% **REGRESSION** | -0.1% ~ | 3/3/3 |
| attach/breakpoint/idle | detach_ms (ms) | 266 (12%) | 314 (0%) | 297 (11%) | +17.8% **REGRESSION** | +11.7% ~ | 3/3/3 |
| attach/breakpoint/busy | attach_ms (ms) | 45.7 (6%) | 210 (19%) | 46.1 (4%) | +360.3% **REGRESSION** | +0.8% ~ | 3/3/3 |
| attach/breakpoint/busy | detach_ms (ms) | 266 (0%) | 293 (8%) | 220 (21%) | +10.1% **REGRESSION** | -17.3% **gain** | 3/3/3 |

### x86 (run3: 2 rounds for most rows -- PRELIMINARY, the third was still running)

| case | metric | main median (spread) | mf median (spread) | agentscope median (spread) | mf vs main | agentscope vs main | rounds |
|---|---|---:|---:|---:|---|---|---|
| hit/base/empty/t1 | ns_per_call (ns/call) | 2.57 (5%) | 2.63 (4%) | 2.54 (4%) | +2.3% ~ | -1.2% ~ | 3/3/3 |
| hit/base/empty/t1 | hits_per_s (hits/s) | 389,105,058 (5%) | 380,228,137 (4%) | 393,700,787 (4%) | -2.3% ~ | +1.2% ~ | 3/3/3 |
| hit/inline/empty/t1 | ns_per_call (ns/call) | 96.6 (16%) | 208 (5%) | 207 (2%) | +115.6% **REGRESSION** | +114.6% **REGRESSION** | 3/3/3 |
| hit/inline/empty/t1 | hits_per_s (hits/s) | 10,355,183 (15%) | 4,801,921 (5%) | 4,825,789 (2%) | -53.6% **REGRESSION** | -53.4% **REGRESSION** | 3/3/3 |
| hit/inline/send_log/t1 | ns_per_call (ns/call) | 2,142 (3%) | 3,375 (3%) | 3,155 (4%) | +57.5% **REGRESSION** | +47.3% **REGRESSION** | 3/3/3 |
| hit/inline/send_log/t1 | hits_per_s (hits/s) | 466,744 (3%) | 296,289 (3%) | 316,952 (4%) | -36.5% **REGRESSION** | -32.1% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t1 | ns_per_call (ns/call) | 157,482 (3%) | 237,334 (11%) | 250,721 (4%) | +50.7% **REGRESSION** | +59.2% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t1 | hits_per_s (hits/s) | 6,350 (3%) | 4,213 (10%) | 3,988 (4%) | -33.6% **REGRESSION** | -37.2% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t1 | ns_per_call (ns/call) | 170,917 (3%) | 258,840 (4%) | 258,705 (6%) | +51.4% **REGRESSION** | +51.4% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t1 | hits_per_s (hits/s) | 5,851 (3%) | 3,863 (4%) | 3,865 (6%) | -34.0% **REGRESSION** | -33.9% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t1 | ns_per_call (ns/call) | 156,140 (5%) | 233,493 (0%) | 233,902 (4%) | +49.5% **REGRESSION** | +49.8% **REGRESSION** | 3/2/3 |
| hit/watch/empty/t1 | hits_per_s (hits/s) | 6,405 (4%) | 4,283 (0%) | 4,275 (4%) | -33.1% **REGRESSION** | -33.2% **REGRESSION** | 3/2/3 |
| hit/watch/send_log/t1 | ns_per_call (ns/call) | 166,650 (1%) | 249,228 (1%) | 255,511 (0%) | +49.6% **REGRESSION** | +53.3% **REGRESSION** | 2/2/2 |
| hit/watch/send_log/t1 | hits_per_s (hits/s) | 6,001 (1%) | 4,012 (1%) | 3,914 (0%) | -33.1% **REGRESSION** | -34.8% **REGRESSION** | 2/2/2 |
| hit/breakpoint/empty/t1 | ns_per_call (ns/call) | 247,784 (2%) | 177,967 (1%) | 175,293 (0%) | -28.2% **gain** | -29.3% **gain** | 2/2/2 |
| hit/breakpoint/empty/t1 | hits_per_s (hits/s) | 4,036 (2%) | 5,619 (1%) | 5,705 (0%) | +39.2% **gain** | +41.3% **gain** | 2/2/2 |
| hit/breakpoint/send_log/t1 | ns_per_call (ns/call) | 258,188 (1%) | 197,343 (0%) | 196,747 (2%) | -23.6% **gain** | -23.8% **gain** | 2/2/2 |
| hit/breakpoint/send_log/t1 | hits_per_s (hits/s) | 3,873 (1%) | 5,067 (0%) | 5,083 (2%) | +30.8% **gain** | +31.2% **gain** | 2/2/2 |
| hit/base/empty/t4 | ns_per_call (ns/call) | 44.2 (19%) | 47.5 (21%) | 45.6 (17%) | +7.5% ~ | +3.2% ~ | 2/2/2 |
| hit/base/empty/t4 | hits_per_s (hits/s) | 91,236,481 (19%) | 85,107,651 (21%) | 88,300,477 (17%) | -6.7% ~ | -3.2% ~ | 2/2/2 |
| hit/inline/empty/t4 | ns_per_call (ns/call) | 186 (29%) | 289 (20%) | 293 (30%) | +55.2% **REGRESSION** | +57.8% **REGRESSION** | 2/2/2 |
| hit/inline/empty/t4 | hits_per_s (hits/s) | 21,958,769 (29%) | 14,004,265 (20%) | 13,938,503 (30%) | -36.2% **REGRESSION** | -36.5% **REGRESSION** | 2/2/2 |
| hit/inline/send_log/t4 | ns_per_call (ns/call) | 9,441 (6%) | 15,115 (45%) | 12,355 (0%) | +60.1% **REGRESSION** | +30.9% **REGRESSION** | 2/2/2 |
| hit/inline/send_log/t4 | hits_per_s (hits/s) | 424,045 (6%) | 278,422 (45%) | 323,753 (0%) | -34.3% **REGRESSION** | -23.7% **REGRESSION** | 2/2/2 |
| hit/hw/empty/t4 | ns_per_call (ns/call) | 576,364 (0%) | 890,005 (0%) | 892,662 (0%) | +54.4% **REGRESSION** | +54.9% **REGRESSION** | 2/2/2 |
| hit/hw/empty/t4 | hits_per_s (hits/s) | 6,940 (0%) | 4,494 (0%) | 4,481 (0%) | -35.2% **REGRESSION** | -35.4% **REGRESSION** | 2/2/2 |
| hit/hw/send_log/t4 | ns_per_call (ns/call) | 632,851 (4%) | 948,606 (1%) | 959,030 (0%) | +49.9% **REGRESSION** | +51.5% **REGRESSION** | 2/2/2 |
| hit/hw/send_log/t4 | hits_per_s (hits/s) | 6,323 (4%) | 4,217 (1%) | 4,171 (0%) | -33.3% **REGRESSION** | -34.0% **REGRESSION** | 2/2/2 |
| hit/watch/empty/t4 | ns_per_call (ns/call) | 577,160 (0%) | 865,216 (0%) | 874,679 (1%) | +49.9% **REGRESSION** | +51.5% **REGRESSION** | 2/2/2 |
| hit/watch/empty/t4 | hits_per_s (hits/s) | 6,931 (0%) | 4,623 (0%) | 4,573 (1%) | -33.3% **REGRESSION** | -34.0% **REGRESSION** | 2/2/2 |
| hit/watch/send_log/t4 | ns_per_call (ns/call) | 623,918 (1%) | 950,091 (1%) | 940,274 (2%) | +52.3% **REGRESSION** | +50.7% **REGRESSION** | 2/2/2 |
| hit/watch/send_log/t4 | hits_per_s (hits/s) | 6,411 (1%) | 4,210 (1%) | 4,254 (2%) | -34.3% **REGRESSION** | -33.6% **REGRESSION** | 2/2/2 |
| hit/breakpoint/empty/t4 | ns_per_call (ns/call) | 939,539 (0%) | 687,815 (0%) | 679,685 (1%) | -26.8% **gain** | -27.7% **gain** | 2/2/2 |
| hit/breakpoint/empty/t4 | hits_per_s (hits/s) | 4,257 (0%) | 5,816 (0%) | 5,885 (1%) | +36.6% **gain** | +38.2% **gain** | 2/2/2 |
| hit/breakpoint/send_log/t4 | ns_per_call (ns/call) | 973,337 (1%) | 749,721 (2%) | 738,630 (3%) | -23.0% **gain** | -24.1% **gain** | 2/2/2 |
| hit/breakpoint/send_log/t4 | hits_per_s (hits/s) | 4,110 (1%) | 5,336 (2%) | 5,417 (3%) | +29.8% **gain** | +31.8% **gain** | 2/2/2 |
| attach/inline/idle | attach_ms (ms) | 208 (8%) | 114 (1%) | 137 (46%) | -45.2% **gain** | -34.1% **gain** | 2/2/2 |
| attach/inline/idle | detach_ms (ms) | 321 (5%) | 329 (9%) | 322 (5%) | +2.4% ~ | +0.0% ~ | 2/2/2 |
| attach/inline/busy | attach_ms (ms) | 96.0 (9%) | 198 (4%) | 156 (54%) | +106.0% **REGRESSION** | +62.2% **REGRESSION** | 2/2/2 |
| attach/inline/busy | detach_ms (ms) | 314 (0%) | 337 (5%) | 314 (0%) | +7.5% **REGRESSION** | +0.1% ~ | 2/2/2 |
| attach/hw/idle | attach_ms (ms) | 136 (132%) | 242 (111%) | 46.4 (3%) | +78.4% ~ | -65.9% ~ | 2/2/2 |
| attach/hw/idle | detach_ms (ms) | 297 (0%) | 329 (0%) | 282 (11%) | +10.8% **REGRESSION** | -5.2% ~ | 2/2/2 |
| attach/hw/busy | attach_ms (ms) | 47.1 (0%) | 214 (15%) | 46.7 (2%) | +354.4% **REGRESSION** | -0.8% ~ | 2/2/2 |
| attach/hw/busy | detach_ms (ms) | 266 (0%) | 305 (5%) | 220 (1%) | +14.8% **REGRESSION** | -17.1% **gain** | 2/2/2 |
| attach/breakpoint/idle | attach_ms (ms) | 46.9 (0%) | 218 (14%) | 46.1 (2%) | +365.1% **REGRESSION** | -1.7% ~ | 2/2/2 |
| attach/breakpoint/idle | detach_ms (ms) | 266 (0%) | 314 (0%) | 266 (0%) | +17.9% **REGRESSION** | -0.0% ~ | 2/2/2 |
| attach/breakpoint/busy | attach_ms (ms) | 50.7 (17%) | 246 (26%) | 46.0 (3%) | +385.2% **REGRESSION** | -9.3% ~ | 2/2/2 |
| attach/breakpoint/busy | detach_ms (ms) | 266 (0%) | 297 (15%) | 266 (0%) | +11.6% **REGRESSION** | -0.0% ~ | 2/2/2 |

### x64 (run2: main vs mf, 3 rounds)

| case | metric | main median (spread) | mf median (spread) | mf vs main | rounds |
|---|---|---:|---:|---|---|
| hit/base/empty/t1 | ns_per_call (ns/call) | 2.49 (6%) | 2.55 (5%) | +2.4% ~ | 3/3 |
| hit/base/empty/t1 | hits_per_s (hits/s) | 401,606,426 (6%) | 392,156,863 (5%) | -2.4% ~ | 3/3 |
| hit/inline/empty/t1 | ns_per_call (ns/call) | 81.7 (4%) | 110 (2%) | +34.3% **REGRESSION** | 3/3 |
| hit/inline/empty/t1 | hits_per_s (hits/s) | 12,242,899 (4%) | 9,117,433 (2%) | -25.5% **REGRESSION** | 3/3 |
| hit/inline/send_log/t1 | ns_per_call (ns/call) | 1,338 (13%) | 1,298 (2%) | -3.0% ~ | 3/3 |
| hit/inline/send_log/t1 | hits_per_s (hits/s) | 747,490 (14%) | 770,291 (2%) | +3.1% ~ | 3/3 |
| hit/hw/empty/t1 | ns_per_call (ns/call) | 98,711 (7%) | 163,202 (1%) | +65.3% **REGRESSION** | 3/3 |
| hit/hw/empty/t1 | hits_per_s (hits/s) | 10,131 (7%) | 6,127 (1%) | -39.5% **REGRESSION** | 3/3 |
| hit/hw/send_log/t1 | ns_per_call (ns/call) | 97,563 (2%) | 165,894 (4%) | +70.0% **REGRESSION** | 3/3 |
| hit/hw/send_log/t1 | hits_per_s (hits/s) | 10,250 (2%) | 6,028 (4%) | -41.2% **REGRESSION** | 3/3 |
| hit/watch/empty/t1 | ns_per_call (ns/call) | 98,696 (7%) | 159,298 (1%) | +61.4% **REGRESSION** | 3/3 |
| hit/watch/empty/t1 | hits_per_s (hits/s) | 10,132 (7%) | 6,278 (1%) | -38.0% **REGRESSION** | 3/3 |
| hit/watch/send_log/t1 | ns_per_call (ns/call) | 98,016 (5%) | 155,318 (11%) | +58.5% **REGRESSION** | 3/3 |
| hit/watch/send_log/t1 | hits_per_s (hits/s) | 10,202 (5%) | 6,438 (10%) | -36.9% **REGRESSION** | 3/3 |
| hit/breakpoint/empty/t1 | ns_per_call (ns/call) | 145,066 (7%) | 109,097 (1%) | -24.8% **gain** | 3/3 |
| hit/breakpoint/empty/t1 | hits_per_s (hits/s) | 6,893 (6%) | 9,166 (1%) | +33.0% **gain** | 3/3 |
| hit/breakpoint/send_log/t1 | ns_per_call (ns/call) | 151,856 (5%) | 116,135 (7%) | -23.5% **gain** | 3/3 |
| hit/breakpoint/send_log/t1 | hits_per_s (hits/s) | 6,585 (5%) | 8,611 (7%) | +30.8% **gain** | 3/3 |
| hit/base/empty/t4 | ns_per_call (ns/call) | 36.2 (19%) | 37.1 (23%) | +2.5% ~ | 3/3 |
| hit/base/empty/t4 | hits_per_s (hits/s) | 110,344,828 (23%) | 107,671,602 (29%) | -2.4% ~ | 3/3 |
| hit/inline/empty/t4 | ns_per_call (ns/call) | 180 (40%) | 160 (34%) | -10.8% ~ | 3/3 |
| hit/inline/empty/t4 | hits_per_s (hits/s) | 22,266,756 (54%) | 24,971,907 (26%) | +12.1% ~ | 3/3 |
| hit/inline/send_log/t4 | ns_per_call (ns/call) | 7,043 (38%) | 7,836 (3%) | +11.3% ~ | 3/3 |
| hit/inline/send_log/t4 | hits_per_s (hits/s) | 567,908 (32%) | 510,456 (3%) | -10.1% ~ | 3/3 |
| hit/hw/empty/t4 | ns_per_call (ns/call) | 329,516 (2%) | 569,981 (2%) | +73.0% **REGRESSION** | 3/3 |
| hit/hw/empty/t4 | hits_per_s (hits/s) | 12,139 (2%) | 7,018 (2%) | -42.2% **REGRESSION** | 3/3 |
| hit/hw/send_log/t4 | ns_per_call (ns/call) | 322,703 (5%) | 557,404 (3%) | +72.7% **REGRESSION** | 3/3 |
| hit/hw/send_log/t4 | hits_per_s (hits/s) | 12,395 (4%) | 7,176 (3%) | -42.1% **REGRESSION** | 3/3 |
| hit/watch/empty/t4 | ns_per_call (ns/call) | 328,406 (1%) | 544,312 (5%) | +65.7% **REGRESSION** | 3/3 |
| hit/watch/empty/t4 | hits_per_s (hits/s) | 12,180 (1%) | 7,349 (5%) | -39.7% **REGRESSION** | 3/3 |
| hit/watch/send_log/t4 | ns_per_call (ns/call) | 319,554 (1%) | 567,266 (41%) | +77.5% **REGRESSION** | 3/3 |
| hit/watch/send_log/t4 | hits_per_s (hits/s) | 12,517 (1%) | 7,051 (32%) | -43.7% **REGRESSION** | 3/3 |
| hit/breakpoint/empty/t4 | ns_per_call (ns/call) | 503,462 (0%) | 397,598 (8%) | -21.0% **gain** | 3/3 |
| hit/breakpoint/empty/t4 | hits_per_s (hits/s) | 7,945 (0%) | 10,060 (8%) | +26.6% **gain** | 3/3 |
| hit/breakpoint/send_log/t4 | ns_per_call (ns/call) | 518,239 (1%) | 411,581 (3%) | -20.6% **gain** | 3/3 |
| hit/breakpoint/send_log/t4 | hits_per_s (hits/s) | 7,718 (1%) | 9,719 (3%) | +25.9% **gain** | 3/3 |
| attach/inline/idle | attach_ms (ms) | 188 (96%) | 114 (106%) | -39.4% ~ | 3/3 |
| attach/inline/idle | detach_ms (ms) | 345 (9%) | 329 (5%) | -4.5% ~ | 3/3 |
| attach/inline/busy | attach_ms (ms) | 96.3 (4%) | 113 (118%) | +16.8% **REGRESSION** | 3/3 |
| attach/inline/busy | detach_ms (ms) | 329 (10%) | 329 (9%) | -0.0% ~ | 3/3 |
| attach/hw/idle | attach_ms (ms) | 45.7 (3%) | 117 (95%) | +156.9% **REGRESSION** | 3/3 |
| attach/hw/idle | detach_ms (ms) | 266 (12%) | 314 (10%) | +18.0% **REGRESSION** | 3/3 |
| attach/hw/busy | attach_ms (ms) | 46.6 (5%) | 126 (83%) | +170.4% **REGRESSION** | 3/3 |
| attach/hw/busy | detach_ms (ms) | 266 (0%) | 293 (2%) | +10.1% **REGRESSION** | 3/3 |
| attach/breakpoint/idle | attach_ms (ms) | 45.4 (3%) | 195 (55%) | +330.5% **REGRESSION** | 3/3 |
| attach/breakpoint/idle | detach_ms (ms) | 297 (10%) | 314 (10%) | +5.6% **REGRESSION** | 3/3 |
| attach/breakpoint/busy | attach_ms (ms) | 45.7 (28%) | 202 (41%) | +342.0% **REGRESSION** | 3/3 |
| attach/breakpoint/busy | detach_ms (ms) | 266 (0%) | 314 (15%) | +17.8% **REGRESSION** | 3/3 |

### x86 (run2: main vs mf, 3 rounds)

| case | metric | main median (spread) | mf median (spread) | mf vs main | rounds |
|---|---|---:|---:|---|---|
| hit/base/empty/t1 | ns_per_call (ns/call) | 2.54 (3%) | 2.49 (6%) | -2.0% ~ | 3/3 |
| hit/base/empty/t1 | hits_per_s (hits/s) | 393,700,787 (3%) | 401,606,426 (5%) | +2.0% ~ | 3/3 |
| hit/inline/empty/t1 | ns_per_call (ns/call) | 96.2 (3%) | 210 (4%) | +118.7% **REGRESSION** | 3/3 |
| hit/inline/empty/t1 | hits_per_s (hits/s) | 10,391,770 (3%) | 4,750,594 (4%) | -54.3% **REGRESSION** | 3/3 |
| hit/inline/send_log/t1 | ns_per_call (ns/call) | 2,178 (4%) | 3,408 (26%) | +56.4% **REGRESSION** | 3/3 |
| hit/inline/send_log/t1 | hits_per_s (hits/s) | 459,059 (4%) | 293,467 (21%) | -36.1% **REGRESSION** | 3/3 |
| hit/hw/empty/t1 | ns_per_call (ns/call) | 157,593 (1%) | 244,563 (5%) | +55.2% **REGRESSION** | 3/3 |
| hit/hw/empty/t1 | hits_per_s (hits/s) | 6,345 (1%) | 4,089 (5%) | -35.6% **REGRESSION** | 3/3 |
| hit/hw/send_log/t1 | ns_per_call (ns/call) | 167,210 (1%) | 257,993 (3%) | +54.3% **REGRESSION** | 3/3 |
| hit/hw/send_log/t1 | hits_per_s (hits/s) | 5,980 (1%) | 3,876 (3%) | -35.2% **REGRESSION** | 3/3 |
| hit/watch/empty/t1 | ns_per_call (ns/call) | 156,088 (3%) | 238,537 (1%) | +52.8% **REGRESSION** | 3/3 |
| hit/watch/empty/t1 | hits_per_s (hits/s) | 6,407 (3%) | 4,192 (1%) | -34.6% **REGRESSION** | 3/3 |
| hit/watch/send_log/t1 | ns_per_call (ns/call) | 167,879 (1%) | 256,060 (19%) | +52.5% **REGRESSION** | 3/3 |
| hit/watch/send_log/t1 | hits_per_s (hits/s) | 5,957 (1%) | 3,905 (16%) | -34.4% **REGRESSION** | 3/3 |
| hit/breakpoint/empty/t1 | ns_per_call (ns/call) | 249,033 (1%) | 179,724 (2%) | -27.8% **gain** | 3/3 |
| hit/breakpoint/empty/t1 | hits_per_s (hits/s) | 4,016 (1%) | 5,564 (2%) | +38.6% **gain** | 3/3 |
| hit/breakpoint/send_log/t1 | ns_per_call (ns/call) | 259,100 (1%) | 200,176 (1%) | -22.7% **gain** | 3/3 |
| hit/breakpoint/send_log/t1 | hits_per_s (hits/s) | 3,860 (1%) | 4,996 (1%) | +29.4% **gain** | 3/3 |
| hit/base/empty/t4 | ns_per_call (ns/call) | 43.8 (29%) | 43.0 (33%) | -1.9% ~ | 3/3 |
| hit/base/empty/t4 | hits_per_s (hits/s) | 91,365,921 (25%) | 93,131,548 (30%) | +1.9% ~ | 3/3 |
| hit/inline/empty/t4 | ns_per_call (ns/call) | 171 (32%) | 317 (62%) | +84.9% **REGRESSION** | 3/3 |
| hit/inline/empty/t4 | hits_per_s (hits/s) | 23,337,223 (31%) | 12,621,084 (57%) | -45.9% **REGRESSION** | 3/3 |
| hit/inline/send_log/t4 | ns_per_call (ns/call) | 8,729 (4%) | 12,525 (5%) | +43.5% **REGRESSION** | 3/3 |
| hit/inline/send_log/t4 | hits_per_s (hits/s) | 458,262 (4%) | 319,351 (6%) | -30.3% **REGRESSION** | 3/3 |
| hit/hw/empty/t4 | ns_per_call (ns/call) | 577,678 (5%) | 899,640 (36%) | +55.7% **REGRESSION** | 3/3 |
| hit/hw/empty/t4 | hits_per_s (hits/s) | 6,924 (4%) | 4,446 (27%) | -35.8% **REGRESSION** | 3/3 |
| hit/hw/send_log/t4 | ns_per_call (ns/call) | 622,869 (1%) | 965,416 (0%) | +55.0% **REGRESSION** | 3/3 |
| hit/hw/send_log/t4 | hits_per_s (hits/s) | 6,422 (1%) | 4,143 (0%) | -35.5% **REGRESSION** | 3/3 |
| hit/watch/empty/t4 | ns_per_call (ns/call) | 577,557 (1%) | 881,047 (2%) | +52.5% **REGRESSION** | 3/3 |
| hit/watch/empty/t4 | hits_per_s (hits/s) | 6,926 (1%) | 4,540 (2%) | -34.4% **REGRESSION** | 3/3 |
| hit/watch/send_log/t4 | ns_per_call (ns/call) | 624,880 (1%) | 966,322 (30%) | +54.6% **REGRESSION** | 3/3 |
| hit/watch/send_log/t4 | hits_per_s (hits/s) | 6,401 (1%) | 4,139 (24%) | -35.3% **REGRESSION** | 3/3 |
| hit/breakpoint/empty/t4 | ns_per_call (ns/call) | 929,501 (0%) | 679,587 (2%) | -26.9% **gain** | 3/3 |
| hit/breakpoint/empty/t4 | hits_per_s (hits/s) | 4,303 (0%) | 5,886 (2%) | +36.8% **gain** | 3/3 |
| hit/breakpoint/send_log/t4 | ns_per_call (ns/call) | 989,671 (1%) | 756,532 (3%) | -23.6% **gain** | 3/3 |
| hit/breakpoint/send_log/t4 | hits_per_s (hits/s) | 4,042 (1%) | 5,287 (3%) | +30.8% **gain** | 3/3 |
| attach/inline/idle | attach_ms (ms) | 187 (61%) | 115 (168%) | -38.1% ~ | 3/3 |
| attach/inline/idle | detach_ms (ms) | 329 (9%) | 329 (10%) | +0.1% ~ | 3/3 |
| attach/inline/busy | attach_ms (ms) | 189 (58%) | 204 (46%) | +8.0% ~ | 3/3 |
| attach/inline/busy | detach_ms (ms) | 329 (10%) | 329 (5%) | +0.0% ~ | 3/3 |
| attach/hw/idle | attach_ms (ms) | 46.5 (3%) | 110 (100%) | +136.7% **REGRESSION** | 3/3 |
| attach/hw/idle | detach_ms (ms) | 266 (0%) | 314 (0%) | +17.8% **REGRESSION** | 3/3 |
| attach/hw/busy | attach_ms (ms) | 47.4 (4%) | 210 (89%) | +342.9% **REGRESSION** | 3/3 |
| attach/hw/busy | detach_ms (ms) | 266 (0%) | 291 (22%) | +9.3% ~ | 3/3 |
| attach/breakpoint/idle | attach_ms (ms) | 46.9 (0%) | 220 (5%) | +368.4% **REGRESSION** | 3/3 |
| attach/breakpoint/idle | detach_ms (ms) | 266 (0%) | 329 (10%) | +23.7% **REGRESSION** | 3/3 |
| attach/breakpoint/busy | attach_ms (ms) | 46.0 (3%) | 340 (130%) | +638.8% **REGRESSION** | 3/3 |
| attach/breakpoint/busy | detach_ms (ms) | 266 (0%) | 327 (11%) | +22.8% **REGRESSION** | 3/3 |

## Phase 2 (2026-11-07, branch `perf`): the two regressions fixed -- before/after

Commits on `perf` (on merge-frida 034b245): 5d0a573, 91d7df7, 67161f7, 74d62a5 (+ harness
e1b99e2, ea1f395, 22d7deb). Agentscope is not on merge-frida yet, so it is not in `perf`:
attach/detach below are unchanged by phase 2 (agentscope's own numbers are in the first table).

**Fairness yields (breakpoint / hw / hw watch).** Cause, measured: the A5 yield rounds (every
20 ms each hot thread sleeps ~4 ms) -- with a lone hot thread they buy nothing and cost ~30% of
the hit rate. Now demand-driven: a round is also a probe -- in its quiet time (no event pending)
the controller reads the target's thread states (NtQuerySystemInformation) and keeps 20 ms
rounds only while another thread is runnable (two idle ticks in a row), ran in between (not a
pool worker re-waiting on its queue), or sits in a Sleep (its timeout elapses only while the
process is not frozen: hunt-starve's main); otherwise the period doubles, to 80 ms. Findings on
the way (bench/perfab/threadstates.py): during the freeze of a debug event every thread reads
Waiting/Suspended and thread-pool workers gain cycles from each freeze and thaw, so states are
read only in the quiet time; a thread blocked with a TIMEOUT starves too (its timeout elapses
only while the process runs) and cannot be told from one blocked for good -- hence the 80 ms
cap (with 320 ms hunt-starve failed: main slept 300 ms for 3-11 s). Also: ctx_watch_begin reads
the suspend count through the debug event's own thread handle (no OpenThread/CloseHandle per
event). A spinner thread that never hits (hitcost_target --spin) keeps its CPU: ~500 spins/us
on perf and merge-frida vs 33-47 on main.

**Inline per-hit accounting.** Agent protocol v25: a thread owns a per-thread hit block in the
shared section and is its only writer (plain stores; 64-bit fields as one MOVQ on x86); the
controller alone writes the block's `retired`, named by the carried record. Same exact
accounting (hits == logs + dropped + unaccounted at any kill instant; running counts for
detach; the runfix1 log carry). The thread slot is cached in implicit TLS (a TlsAlloc slot
would write the TEB: regress transparency-* caught it); range_ok trusts the thread's own stack
above its frame (x86 get_func_arg read the stack arguments through a VirtualQuery every hit);
HitScope no longer zero-filled; 1 KiB XSAVE area when it fits. Remaining x86 gap: the x87
state save the transparency work added on x86 (every hit; main did not keep x87 -- see the
UHH_BENCH_XSTATE=none row).

**Regression families** (`hunt,check_detach,crash_logs,logs,cxlib,cx2,lifecycle,ret_probe,
transparency`) on 74d62a5, VM: **x64 262/262 ok, x86 259/259 ok** (hunt-starve late_reads
4-5k, bar 20000). Full CI pushed (branch `perf`).

### Before / after (median per hit, 3 interleaved rounds, same VM, main / merge-frida / perf)

| probe type | arch | thr | callback | main | merge-frida | **perf** | perf vs main | perf vs mf |
|---|---|---|---|---:|---:|---:|---|---|
| inline | x64 | 1 | empty | 83 ns | 110 ns | **96 ns** | +15% | -13% |
| inline | x64 | 1 | send_log | 1.48 us | 1.48 us | **1.29 us** | ~ (noisy) | ~ |
| hw (execute) | x64 | 1 | empty | 100 us | 163 us | **141 us** | +41% | -14% |
| hw data watch | x64 | 1 | empty | 100 us | 159 us | **137 us** | +37% | -14% |
| breakpoint | x64 | 1 | empty | 148 us | 110 us | **84 us** | **-43%** | -24% |
| hw / watch / bp | x64 | 4 | empty | 330 / 321 / 497 us | 561 / 541 / 393 us | **449 / 414 / 308 us** | +36% / +29% / **-38%** | -20% / -24% / -22% |
| inline | x86 | 1 | empty | 103 ns | 215 ns | **181 ns** (116 ns with the x87/xstate save off) | +75% | -16% |
| inline | x86 | 1 | send_log | 2.14 us | 3.23 us | **3.40 us** | +58% | ~ |
| hw (execute) | x86 | 1 | empty | 156 us | 238 us | **201 us** | +29% | -16% |
| hw data watch | x86 | 1 | empty | 154 us | 234 us | **197 us** | +28% | -16% |
| breakpoint | x86 | 1 | empty | 247 us | 179 us | **150 us** | **-39%** | -16% |
| hw / watch / bp | x86 | 4 | empty | 573 / 583 / 929 us | 893 / 873 / 690 us | **748 / 715 / 555 us** | +30% / +23% / **-40%** | -16% / -18% / -20% |
| spinner beside one hot hw thread (spins/us) | x64 / x86 | | | 47 / 29 | 541 / 363 | 492 / 353 | fairness kept | |

x86 inline with `UHH_BENCH_XSTATE=none` (benchmark knob: no x87/AVX save): 116 ns vs 184 ns
default (5 runs each) -- the accounting part of the x86 gap is closed (116 vs main's 103); the
remaining ~70 ns is the x87 state save the transparency work added on x86 (main did not keep a
mid-function site's live x87 stack / status word: a correctness fix, kept).

**Bars not met (honest):** hw / hw-watch per hit are still +23..+48% over main (bar: ~5%);
inline x86 +75% (x87 save) and x86 send_log +58% (not root-caused; the stack fast path did not
move it); inline x64 +15% (bar: a few ns). What remains on hw: with the period capped at 80 ms a
lone hot thread still pays a ~4 ms round per 84 ms plus the quiet-time probes, and the verdicts
are noisy (rounds whose quiet ticks see a thread mid-thaw keep 20 ms). Scratch measurements on
the way: hw ~106-113 us/hit (x64, +6..13%) with rounds off or backed off to 320 ms -- but 320 ms
starved timed waits (hunt-starve). Next steps: per-round cost (the 4 ms sleep could shrink once a
round finds no demand), a cheaper quiet-time probe, and the x86 send_log profile.

Attach/detach: unchanged by phase 2 (perf = merge-frida there: bp/hw attach ~100-230 ms); the
agentscope branch alone fixes it (45 ms, = main; first table).

### Full tables (phase 2 final run)

### x64 (final: main / merge-frida 034b245 / perf 74d62a5, 3 interleaved rounds)

| case | metric | main median (spread) | mf median (spread) | perf median (spread) | mf vs main | perf vs main | rounds |
|---|---|---:|---:|---:|---|---|---|
| hit/base/empty/t1 | ns_per_call (ns/call) | 2.49 (1%) | 2.49 (5%) | 2.50 (2%) | +0.0% ~ | +0.4% ~ | 3/3/3 |
| hit/base/empty/t1 | hits_per_s (hits/s) | 401,606,426 (1%) | 401,606,426 (5%) | 400,000,000 (2%) | +0.0% ~ | -0.4% ~ | 3/3/3 |
| hit/inline/empty/t1 | ns_per_call (ns/call) | 83.3 (2%) | 110 (6%) | 95.5 (9%) | +31.7% **REGRESSION** | +14.6% **REGRESSION** | 3/3/3 |
| hit/inline/empty/t1 | hits_per_s (hits/s) | 12,009,127 (2%) | 9,121,591 (6%) | 10,475,592 (10%) | -24.0% **REGRESSION** | -12.8% **REGRESSION** | 3/3/3 |
| hit/inline/send_log/t1 | ns_per_call (ns/call) | 1,476 (19%) | 1,483 (28%) | 1,286 (37%) | +0.5% ~ | -12.9% ~ | 3/3/3 |
| hit/inline/send_log/t1 | hits_per_s (hits/s) | 677,727 (23%) | 674,482 (27%) | 777,708 (28%) | -0.5% ~ | +14.8% ~ | 3/3/3 |
| hit/hw/empty/t1 | ns_per_call (ns/call) | 99,883 (3%) | 163,258 (10%) | 141,206 (3%) | +63.4% **REGRESSION** | +41.4% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t1 | hits_per_s (hits/s) | 10,012 (3%) | 6,125 (9%) | 7,082 (3%) | -38.8% **REGRESSION** | -29.3% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t1 | ns_per_call (ns/call) | 98,627 (3%) | 162,619 (3%) | 146,249 (9%) | +64.9% **REGRESSION** | +48.3% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t1 | hits_per_s (hits/s) | 10,139 (3%) | 6,149 (3%) | 6,838 (10%) | -39.4% **REGRESSION** | -32.6% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t1 | ns_per_call (ns/call) | 99,591 (3%) | 158,977 (3%) | 136,830 (7%) | +59.6% **REGRESSION** | +37.4% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t1 | hits_per_s (hits/s) | 10,041 (3%) | 6,290 (3%) | 7,308 (7%) | -37.4% **REGRESSION** | -27.2% **REGRESSION** | 3/3/3 |
| hit/watch/send_log/t1 | ns_per_call (ns/call) | 100,023 (6%) | 159,343 (6%) | 131,267 (6%) | +59.3% **REGRESSION** | +31.2% **REGRESSION** | 3/3/3 |
| hit/watch/send_log/t1 | hits_per_s (hits/s) | 9,998 (6%) | 6,276 (6%) | 7,618 (6%) | -37.2% **REGRESSION** | -23.8% **REGRESSION** | 3/3/3 |
| hit/breakpoint/empty/t1 | ns_per_call (ns/call) | 147,866 (1%) | 110,267 (6%) | 83,798 (9%) | -25.4% **gain** | -43.3% **gain** | 3/3/3 |
| hit/breakpoint/empty/t1 | hits_per_s (hits/s) | 6,763 (1%) | 9,069 (6%) | 11,933 (8%) | +34.1% **gain** | +76.5% **gain** | 3/3/3 |
| hit/breakpoint/send_log/t1 | ns_per_call (ns/call) | 153,366 (6%) | 118,084 (9%) | 95,190 (5%) | -23.0% **gain** | -37.9% **gain** | 3/3/3 |
| hit/breakpoint/send_log/t1 | hits_per_s (hits/s) | 6,520 (6%) | 8,469 (8%) | 10,505 (5%) | +29.9% **gain** | +61.1% **gain** | 3/3/3 |
| hit/base/empty/t4 | ns_per_call (ns/call) | 34.3 (4%) | 37.0 (8%) | 37.0 (8%) | +7.9% **REGRESSION** | +7.8% **REGRESSION** | 3/3/3 |
| hit/base/empty/t4 | hits_per_s (hits/s) | 116,720,163 (4%) | 108,137,334 (8%) | 108,225,108 (8%) | -7.4% **REGRESSION** | -7.3% **REGRESSION** | 3/3/3 |
| hit/inline/empty/t4 | ns_per_call (ns/call) | 167 (28%) | 207 (23%) | 146 (44%) | +24.0% ~ | -12.9% ~ | 3/3/3 |
| hit/inline/empty/t4 | hits_per_s (hits/s) | 23,913,433 (38%) | 19,280,825 (29%) | 27,451,788 (32%) | -19.4% ~ | +14.8% ~ | 3/3/3 |
| hit/inline/send_log/t4 | ns_per_call (ns/call) | 6,744 (12%) | 7,665 (11%) | 8,044 (4%) | +13.6% **REGRESSION** | +19.3% **REGRESSION** | 3/3/3 |
| hit/inline/send_log/t4 | hits_per_s (hits/s) | 593,093 (11%) | 521,876 (10%) | 497,259 (4%) | -12.0% **REGRESSION** | -16.2% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t4 | ns_per_call (ns/call) | 329,806 (4%) | 561,284 (4%) | 449,383 (11%) | +70.2% **REGRESSION** | +36.3% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t4 | hits_per_s (hits/s) | 12,128 (4%) | 7,127 (4%) | 8,901 (11%) | -41.2% **REGRESSION** | -26.6% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t4 | ns_per_call (ns/call) | 320,225 (6%) | 557,316 (2%) | 446,986 (6%) | +74.0% **REGRESSION** | +39.6% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t4 | hits_per_s (hits/s) | 12,491 (5%) | 7,177 (2%) | 8,949 (6%) | -42.5% **REGRESSION** | -28.4% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t4 | ns_per_call (ns/call) | 321,221 (3%) | 540,894 (2%) | 413,505 (5%) | +68.4% **REGRESSION** | +28.7% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t4 | hits_per_s (hits/s) | 12,452 (3%) | 7,395 (2%) | 9,673 (5%) | -40.6% **REGRESSION** | -22.3% **REGRESSION** | 3/3/3 |
| hit/watch/send_log/t4 | ns_per_call (ns/call) | 317,677 (5%) | 537,317 (4%) | 435,234 (6%) | +69.1% **REGRESSION** | +37.0% **REGRESSION** | 3/3/3 |
| hit/watch/send_log/t4 | hits_per_s (hits/s) | 12,591 (4%) | 7,444 (4%) | 9,190 (6%) | -40.9% **REGRESSION** | -27.0% **REGRESSION** | 3/3/3 |
| hit/breakpoint/empty/t4 | ns_per_call (ns/call) | 496,603 (1%) | 393,208 (1%) | 308,347 (8%) | -20.8% **gain** | -37.9% **gain** | 3/3/3 |
| hit/breakpoint/empty/t4 | hits_per_s (hits/s) | 8,055 (1%) | 10,173 (1%) | 12,972 (8%) | +26.3% **gain** | +61.1% **gain** | 3/3/3 |
| hit/breakpoint/send_log/t4 | ns_per_call (ns/call) | 512,691 (2%) | 415,396 (2%) | 323,450 (2%) | -19.0% **gain** | -36.9% **gain** | 3/3/3 |
| hit/breakpoint/send_log/t4 | hits_per_s (hits/s) | 7,802 (2%) | 9,629 (2%) | 12,367 (2%) | +23.4% **gain** | +58.5% **gain** | 3/3/3 |
| spin/base/t1 | ns_per_call (ns/call) | 7.04 (9%) | 7.51 (59%) | 6.77 (23%) | +6.7% ~ | -3.8% ~ | 3/3/3 |
| spin/base/t1 | spin_per_us (spins/us) | 235 (56%) | 237 (64%) | 227 (64%) | +0.9% ~ | -3.6% ~ | 3/3/3 |
| spin/inline/t1 | ns_per_call (ns/call) | 102 (9%) | 135 (4%) | 113 (3%) | +32.9% **REGRESSION** | +11.5% **REGRESSION** | 3/3/3 |
| spin/inline/t1 | spin_per_us (spins/us) | 1,114 (9%) | 1,241 (1%) | 1,188 (8%) | +11.4% **gain** | +6.7% ~ | 3/3/3 |
| spin/hw/t1 | ns_per_call (ns/call) | 100,833 (5%) | 169,743 (4%) | 162,659 (1%) | +68.3% **REGRESSION** | +61.3% **REGRESSION** | 3/3/3 |
| spin/hw/t1 | spin_per_us (spins/us) | 46.7 (12%) | 541 (7%) | 492 (11%) | +1059.8% **gain** | +954.5% **gain** | 3/3/3 |
| spin/watch/t1 | ns_per_call (ns/call) | 100,301 (4%) | 158,549 (3%) | 166,050 (7%) | +58.1% **REGRESSION** | +65.6% **REGRESSION** | 3/3/3 |
| spin/watch/t1 | spin_per_us (spins/us) | 40.0 (8%) | 523 (7%) | 525 (10%) | +1208.4% **gain** | +1213.0% **gain** | 3/3/3 |
| spin/breakpoint/t1 | ns_per_call (ns/call) | 150,081 (9%) | 117,131 (8%) | 114,092 (6%) | -22.0% **gain** | -24.0% **gain** | 3/3/3 |
| spin/breakpoint/t1 | spin_per_us (spins/us) | 33.3 (109%) | 539 (7%) | 538 (2%) | +1516.0% **gain** | +1512.5% **gain** | 3/3/3 |
| attach/inline/idle | attach_ms (ms) | 180 (23%) | 209 (21%) | 110 (103%) | +16.4% ~ | -38.9% ~ | 3/3/3 |
| attach/inline/idle | detach_ms (ms) | 345 (0%) | 314 (10%) | 314 (10%) | -9.1% ~ | -9.1% ~ | 3/3/3 |
| attach/inline/busy | attach_ms (ms) | 200 (47%) | 222 (56%) | 112 (107%) | +10.8% ~ | -44.0% ~ | 3/3/3 |
| attach/inline/busy | detach_ms (ms) | 329 (10%) | 329 (14%) | 314 (5%) | +0.0% ~ | -4.7% ~ | 3/3/3 |
| attach/hw/idle | attach_ms (ms) | 45.5 (3%) | 223 (86%) | 203 (47%) | +390.9% **REGRESSION** | +345.2% **REGRESSION** | 3/3/3 |
| attach/hw/idle | detach_ms (ms) | 266 (0%) | 329 (10%) | 314 (0%) | +23.8% **REGRESSION** | +17.9% **REGRESSION** | 3/3/3 |
| attach/hw/busy | attach_ms (ms) | 46.6 (7%) | 240 (57%) | 107 (101%) | +415.3% **REGRESSION** | +130.6% **REGRESSION** | 3/3/3 |
| attach/hw/busy | detach_ms (ms) | 266 (0%) | 295 (17%) | 300 (2%) | +10.9% ~ | +12.8% **REGRESSION** | 3/3/3 |
| attach/breakpoint/idle | attach_ms (ms) | 45.4 (1%) | 213 (39%) | 195 (83%) | +370.2% **REGRESSION** | +330.0% **REGRESSION** | 3/3/3 |
| attach/breakpoint/idle | detach_ms (ms) | 266 (12%) | 345 (9%) | 314 (10%) | +29.6% **REGRESSION** | +17.9% **REGRESSION** | 3/3/3 |
| attach/breakpoint/busy | attach_ms (ms) | 46.2 (80%) | 137 (70%) | 208 (32%) | +195.8% **REGRESSION** | +350.5% **REGRESSION** | 3/3/3 |
| attach/breakpoint/busy | detach_ms (ms) | 266 (0%) | 314 (4%) | 322 (11%) | +17.9% **REGRESSION** | +21.1% **REGRESSION** | 3/3/3 |

### x86 (final: main / merge-frida 034b245 / perf 74d62a5, 3 interleaved rounds)

| case | metric | main median (spread) | mf median (spread) | perf median (spread) | mf vs main | perf vs main | rounds |
|---|---|---:|---:|---:|---|---|---|
| hit/base/empty/t1 | ns_per_call (ns/call) | 2.51 (2%) | 2.54 (2%) | 2.51 (1%) | +1.2% ~ | +0.0% ~ | 3/3/3 |
| hit/base/empty/t1 | hits_per_s (hits/s) | 398,406,375 (2%) | 393,700,787 (2%) | 398,406,375 (1%) | -1.2% ~ | +0.0% ~ | 3/3/3 |
| hit/inline/empty/t1 | ns_per_call (ns/call) | 103 (9%) | 215 (5%) | 181 (5%) | +107.5% **REGRESSION** | +75.4% **REGRESSION** | 3/3/3 |
| hit/inline/empty/t1 | hits_per_s (hits/s) | 9,671,180 (10%) | 4,661,353 (5%) | 5,512,375 (4%) | -51.8% **REGRESSION** | -43.0% **REGRESSION** | 3/3/3 |
| hit/inline/send_log/t1 | ns_per_call (ns/call) | 2,142 (2%) | 3,230 (15%) | 3,396 (9%) | +50.8% **REGRESSION** | +58.5% **REGRESSION** | 3/3/3 |
| hit/inline/send_log/t1 | hits_per_s (hits/s) | 466,856 (2%) | 309,575 (14%) | 294,488 (9%) | -33.7% **REGRESSION** | -36.9% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t1 | ns_per_call (ns/call) | 155,671 (2%) | 237,924 (1%) | 200,998 (6%) | +52.8% **REGRESSION** | +29.1% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t1 | hits_per_s (hits/s) | 6,424 (2%) | 4,203 (1%) | 4,975 (6%) | -34.6% **REGRESSION** | -22.6% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t1 | ns_per_call (ns/call) | 164,124 (0%) | 251,195 (3%) | 212,235 (3%) | +53.1% **REGRESSION** | +29.3% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t1 | hits_per_s (hits/s) | 6,093 (0%) | 3,981 (3%) | 4,712 (3%) | -34.7% **REGRESSION** | -22.7% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t1 | ns_per_call (ns/call) | 154,019 (2%) | 233,982 (1%) | 196,614 (4%) | +51.9% **REGRESSION** | +27.7% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t1 | hits_per_s (hits/s) | 6,493 (2%) | 4,274 (1%) | 5,086 (4%) | -34.2% **REGRESSION** | -21.7% **REGRESSION** | 3/3/3 |
| hit/watch/send_log/t1 | ns_per_call (ns/call) | 165,059 (2%) | 249,513 (1%) | 203,072 (10%) | +51.2% **REGRESSION** | +23.0% **REGRESSION** | 3/3/3 |
| hit/watch/send_log/t1 | hits_per_s (hits/s) | 6,058 (2%) | 4,008 (1%) | 4,924 (10%) | -33.8% **REGRESSION** | -18.7% **REGRESSION** | 3/3/3 |
| hit/breakpoint/empty/t1 | ns_per_call (ns/call) | 247,233 (4%) | 178,987 (1%) | 149,875 (9%) | -27.6% **gain** | -39.4% **gain** | 3/3/3 |
| hit/breakpoint/empty/t1 | hits_per_s (hits/s) | 4,045 (4%) | 5,587 (1%) | 6,672 (9%) | +38.1% **gain** | +65.0% **gain** | 3/3/3 |
| hit/breakpoint/send_log/t1 | ns_per_call (ns/call) | 257,662 (3%) | 193,460 (4%) | 156,932 (3%) | -24.9% **gain** | -39.1% **gain** | 3/3/3 |
| hit/breakpoint/send_log/t1 | hits_per_s (hits/s) | 3,881 (3%) | 5,169 (4%) | 6,372 (3%) | +33.2% **gain** | +64.2% **gain** | 3/3/3 |
| hit/base/empty/t4 | ns_per_call (ns/call) | 60.5 (12%) | 55.2 (14%) | 57.4 (9%) | -8.9% ~ | -5.2% ~ | 3/3/3 |
| hit/base/empty/t4 | hits_per_s (hits/s) | 66,072,019 (12%) | 72,503,172 (13%) | 69,686,411 (9%) | +9.7% ~ | +5.5% ~ | 3/3/3 |
| hit/inline/empty/t4 | ns_per_call (ns/call) | 156 (43%) | 251 (5%) | 221 (2%) | +60.7% **REGRESSION** | +41.0% **REGRESSION** | 3/3/3 |
| hit/inline/empty/t4 | hits_per_s (hits/s) | 25,572,177 (34%) | 15,914,064 (5%) | 18,132,366 (2%) | -37.8% **REGRESSION** | -29.1% **REGRESSION** | 3/3/3 |
| hit/inline/send_log/t4 | ns_per_call (ns/call) | 9,086 (5%) | 11,475 (6%) | 11,298 (3%) | +26.3% **REGRESSION** | +24.3% **REGRESSION** | 3/3/3 |
| hit/inline/send_log/t4 | hits_per_s (hits/s) | 440,228 (6%) | 348,571 (6%) | 354,061 (3%) | -20.8% **REGRESSION** | -19.6% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t4 | ns_per_call (ns/call) | 573,489 (1%) | 893,439 (3%) | 748,095 (5%) | +55.8% **REGRESSION** | +30.4% **REGRESSION** | 3/3/3 |
| hit/hw/empty/t4 | hits_per_s (hits/s) | 6,975 (1%) | 4,477 (3%) | 5,347 (5%) | -35.8% **REGRESSION** | -23.3% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t4 | ns_per_call (ns/call) | 619,639 (1%) | 947,662 (2%) | 769,576 (1%) | +52.9% **REGRESSION** | +24.2% **REGRESSION** | 3/3/3 |
| hit/hw/send_log/t4 | hits_per_s (hits/s) | 6,455 (1%) | 4,221 (2%) | 5,198 (1%) | -34.6% **REGRESSION** | -19.5% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t4 | ns_per_call (ns/call) | 582,937 (2%) | 873,052 (2%) | 715,261 (5%) | +49.8% **REGRESSION** | +22.7% **REGRESSION** | 3/3/3 |
| hit/watch/empty/t4 | hits_per_s (hits/s) | 6,862 (2%) | 4,582 (2%) | 5,592 (5%) | -33.2% **REGRESSION** | -18.5% **REGRESSION** | 3/3/3 |
| hit/watch/send_log/t4 | ns_per_call (ns/call) | 623,293 (0%) | 947,956 (0%) | 775,650 (3%) | +52.1% **REGRESSION** | +24.4% **REGRESSION** | 3/3/3 |
| hit/watch/send_log/t4 | hits_per_s (hits/s) | 6,418 (0%) | 4,220 (0%) | 5,157 (3%) | -34.2% **REGRESSION** | -19.6% **REGRESSION** | 3/3/3 |
| hit/breakpoint/empty/t4 | ns_per_call (ns/call) | 928,957 (8%) | 690,260 (1%) | 555,257 (5%) | -25.7% **gain** | -40.2% **gain** | 3/3/3 |
| hit/breakpoint/empty/t4 | hits_per_s (hits/s) | 4,306 (8%) | 5,795 (1%) | 7,204 (5%) | +34.6% **gain** | +67.3% **gain** | 3/3/3 |
| hit/breakpoint/send_log/t4 | ns_per_call (ns/call) | 970,461 (3%) | 742,797 (3%) | 594,635 (7%) | -23.5% **gain** | -38.7% **gain** | 3/3/3 |
| hit/breakpoint/send_log/t4 | hits_per_s (hits/s) | 4,122 (3%) | 5,385 (3%) | 6,727 (7%) | +30.6% **gain** | +63.2% **gain** | 3/3/3 |
| spin/base/t1 | ns_per_call (ns/call) | 14.4 (16%) | 16.1 (17%) | 15.5 (42%) | +12.0% **REGRESSION** | +7.6% ~ | 3/3/3 |
| spin/base/t1 | spin_per_us (spins/us) | 249 (40%) | 223 (67%) | 228 (2%) | -10.3% ~ | -8.5% ~ | 3/3/3 |
| spin/inline/t1 | ns_per_call (ns/call) | 116 (7%) | 230 (8%) | 191 (4%) | +98.2% **REGRESSION** | +64.6% **REGRESSION** | 3/3/3 |
| spin/inline/t1 | spin_per_us (spins/us) | 1,239 (4%) | 1,419 (6%) | 1,454 (3%) | +14.5% **gain** | +17.3% **gain** | 3/3/3 |
| spin/hw/t1 | ns_per_call (ns/call) | 158,096 (2%) | 237,073 (2%) | 231,879 (1%) | +50.0% **REGRESSION** | +46.7% **REGRESSION** | 3/3/3 |
| spin/hw/t1 | spin_per_us (spins/us) | 29.2 (25%) | 363 (2%) | 353 (7%) | +1144.1% **gain** | +1107.7% **gain** | 3/3/3 |
| spin/watch/t1 | ns_per_call (ns/call) | 155,949 (0%) | 232,886 (1%) | 225,898 (1%) | +49.3% **REGRESSION** | +44.9% **REGRESSION** | 3/3/3 |
| spin/watch/t1 | spin_per_us (spins/us) | 29.1 (5%) | 368 (4%) | 345 (4%) | +1165.0% **gain** | +1084.3% **gain** | 3/3/3 |
| spin/breakpoint/t1 | ns_per_call (ns/call) | 248,406 (5%) | 181,768 (1%) | 174,958 (3%) | -26.8% **gain** | -29.6% **gain** | 3/3/3 |
| spin/breakpoint/t1 | spin_per_us (spins/us) | 30.2 (88%) | 425 (4%) | 396 (6%) | +1307.5% **gain** | +1211.9% **gain** | 3/3/3 |
| attach/inline/idle | attach_ms (ms) | 190 (18%) | 208 (82%) | 195 (47%) | +9.0% ~ | +2.4% ~ | 3/3/3 |
| attach/inline/idle | detach_ms (ms) | 329 (10%) | 314 (0%) | 314 (5%) | -4.8% ~ | -4.7% ~ | 3/3/3 |
| attach/inline/busy | attach_ms (ms) | 94.1 (115%) | 113 (82%) | 227 (77%) | +20.5% ~ | +141.0% ~ | 3/3/3 |
| attach/inline/busy | detach_ms (ms) | 314 (5%) | 314 (5%) | 329 (9%) | +0.0% ~ | +5.0% ~ | 3/3/3 |
| attach/hw/idle | attach_ms (ms) | 46.9 (2%) | 210 (14%) | 231 (185%) | +347.8% **REGRESSION** | +393.7% **REGRESSION** | 3/3/3 |
| attach/hw/idle | detach_ms (ms) | 297 (11%) | 314 (0%) | 345 (9%) | +5.5% **REGRESSION** | +16.0% **REGRESSION** | 3/3/3 |
| attach/hw/busy | attach_ms (ms) | 46.3 (113%) | 142 (78%) | 215 (56%) | +206.3% **REGRESSION** | +364.7% **REGRESSION** | 3/3/3 |
| attach/hw/busy | detach_ms (ms) | 266 (0%) | 304 (24%) | 274 (19%) | +14.3% ~ | +3.0% ~ | 3/3/3 |
| attach/breakpoint/idle | attach_ms (ms) | 46.6 (2%) | 198 (61%) | 217 (49%) | +325.2% **REGRESSION** | +365.7% **REGRESSION** | 3/3/3 |
| attach/breakpoint/idle | detach_ms (ms) | 297 (11%) | 314 (0%) | 314 (0%) | +5.5% **REGRESSION** | +5.6% **REGRESSION** | 3/3/3 |
| attach/breakpoint/busy | attach_ms (ms) | 47.2 (2%) | 214 (228%) | 116 (91%) | +353.3% **REGRESSION** | +146.6% **REGRESSION** | 3/3/3 |
| attach/breakpoint/busy | detach_ms (ms) | 266 (0%) | 321 (8%) | 320 (14%) | +20.6% **REGRESSION** | +20.3% **REGRESSION** | 3/3/3 |

## Phase 3 (2026-11-07, branch `perf`): hw rounds, x86 send_log, the carry-retire fix

**Urgent fix first (branch `perf-fix` on merge-frida 4aeef77, CI green on 4e0263e):** CI
42325381514 had one `gated-e2e-launch-fhw-oin-cin-rin` with every log delivered yet
`interrupted=1`. Cause: `probe_agent_retire_carry` checked the producer block's unaccounted count
before retiring a carried record -- it summed the block's 128 hit counters, then read `done`,
while the owner thread kept counting; a sum that read a probe's hits before one hit and `done`
after it came out one short (0 with the record's own unit pending) and the retire was skipped.
Fix: no bound check (the sums clamp a block at zero anyway). New regress `carry-exact-inline`
(4 threads, every other hit logs, 3 runs): on 4aeef77 it failed 2 of 3 invocations (intr=1, 2);
fixed 9/9; families crash_logs, carry_exact, hunt, logs, gated_e2e: x64 320/320, x86 320/320.
Merged into `perf` (which also brings agentscope).

**hw / hw-watch / breakpoint rounds -- what the measurements showed:**
- The rounds' sleep never was 4 ms: since Windows 10 2004 `timeBeginPeriod` is per process, so the
  controller's 1 ms timer never reached the target -- every "4 ms" yield slept ~15.6 ms, and the
  1 ms timer only cost the controller's own loop (~30% on the VM: hw 144 -> 110 us/hit with it off).
- A thread in a TIMED wait (Sleep, WaitFor... with a timeout) has its timeout elapse only while the
  process is not frozen (a 10 ms WaitForSingleObject loop beside a hot hw thread completed 7% of
  its due timeouts with no rounds) -- it starves like a runnable thread, and cannot be told from an
  unbounded wait until it completes.
- Thread states read during a debug event's freeze are useless (every thread Waiting/Suspended;
  pool workers gain cycles from each freeze/thaw); read in a round's quiet time they are real.

**Design now:** a round is also a probe. In its quiet time the controller polls (no timer) and
asks the kernel twice whether another thread is runnable, ran since the last sample (not a pool
worker back on its queue), or sits in a Sleep. Demand (or fewer than 8 demand-free rounds in a
row) -> rounds every 20 ms whose yielders SLEEP (~15.6 ms, off the CPU: what a starved thread
needs); otherwise the period doubles to 80 ms and the yielders spin ~4 ms on NtYieldExecution
against the interrupt time (no timer). No 1 ms timer for the rounds at all.
- Per hw hit beyond that floor (measured with bench-only toggles, x64, one hot thread, 120 us/hit
  at 72ffb73): the post-callback re-read of the thread's debug registers ~27 us (now only when a
  DR write happened since the hit's own read: an epoch bumped by every context write carrying
  debug registers), the yield rounds ~20 us, ctx_watch ~3 us; with all three off 75 us. The hit
  thread's handle is now opened once per thread, not per hit. Counted syscalls per hw hit:
  GetThreadContext 2 -> 1, OpenThread/CloseHandle 1/1 -> 0.
- **The floor**: `bench/perfab/mindbg` -- the smallest debugger counting the same debug-register
  hit (WaitForDebugEvent, Get/SetThreadContext with RF, ContinueDebugEvent) -- **66-68 us/hit x64,
  112-117 us/hit x86** on this VM. An external (debugger) hw probe cannot go below that;
  Frida's in-process hardware breakpoint (+23 us x64, merge-frida BENCHMARKS) is not external.

**x86 send_log** was bound by the controller's log writer (the ring applies backpressure): one
lock + wake-up and two snprintf per record. Records are now taken in chunks of 256 and formatted
without printf or temporaries: x86 3.2 -> 0.85 us/log, x64 1.3 -> 0.45 us/log (4 threads: 7.6 ->
1.9 us x64, 12.4 -> 2.2 us x86). **x86 inline**: the x87 save is kept (a correctness fix) but done
by FXSAVE when only the x87 state is live (measured: XSAVEC 174, FXSAVE 154, FNSAVE 218, none 107
ns); no per-hit zero-fill of the probe context / hit scope.

### Phase 3 numbers (9f44166, x64 / x86, us or ns per call; main and merge-frida from the same day's interleaved A/B)

| probe | arch | thr | main | merge-frida | **perf** | perf vs main |
|---|---|---|---:|---:|---:|---|
| hw | x64 | 1 | 100 us | 166 us | **93 us** | **-7%** |
| hw data watch | x64 | 1 | 95 us | 161 us | **90 us** | -5% |
| breakpoint | x64 | 1 | 150 us | 111 us | **78 us** | **-48%** |
| hw / watch / bp | x64 | 4 | 334 / 327 / 508 us | 567 / 554 / 402 us | **466 / 449 / 435 us** | +40% / +37% / -14% |
| inline empty | x64 | 1 | 82 ns | 108 ns | **93 ns** | +13% |
| inline send_log | x64 | 1 | 1.15 us | 1.48 us | **0.47 us** | **-60%** |
| hw | x86 | 1 | 154 us | 242 us | **145 us** | **-6%** |
| hw data watch | x86 | 1 | 154 us | 234 us | **140 us** | -9% |
| breakpoint | x86 | 1 | 246 us | 181 us | **130 us** | **-47%** |
| hw / watch / bp | x86 | 4 | 586 / 581 / 931 us | 887 / 887 / 683 us | **810 / 794 / 755 us** | +38% / +37% / -19% |
| inline empty | x86 | 1 | 96 ns | 209 ns | **162 ns** | +69% (x87 save; 107 without) |
| inline send_log | x86 | 1 | 2.12 us | 3.24 us | **0.85 us** | **-60%** |
| floor (mindbg, hw) | x64 / x86 | 1 | | | 67 / 113 us | |

perf rows: 3 back-to-back runs each on a quiet VM (hw/bp/watch) and 5 (inline), median; main /
merge-frida rows: the interleaved 2-round A/B of the same afternoon (p8). Fairness kept: a
thread that never hits gets ~500-680 spins/us beside one hot hw thread (main: 45-60), a 10 ms
timed-wait loop completes 50-60% of its due timeouts (main: 4-8%), hunt-starve late reads
60-8,300 (bar 20,000). Several hot threads keep merge-frida's 20 ms sleeping rounds (the probing
cost them ~15%), so t4 hw stays ~+40% over main (main never yields: it starves the others).

Regress (VM): families hunt, check_detach, crash_logs, carry_exact, log_throughput, lifecycle,
transparency, agent_scope (+ cxlib, cx2, watch, conformance, callorig, famous on 9f44166): see
the phase 3 report; one-off flakes seen once each and not reproduced in 64 reruns:
lifecycle-detach-early-5-mixed (a DR left after an early detach), lifecycle-interrupt-mixed
ctrl@0.0.
