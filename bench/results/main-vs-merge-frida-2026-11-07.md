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
