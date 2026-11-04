# Per-hit cost: inline extended-state handling

`hitcost_target` calls an exported function N times in a tight loop and times the loop
in-process (QueryPerformanceCounter); `hitcost_driver` probes it with an EMPTY callback,
so the figure is the hook machinery's cost per call. `--avx` keeps YMM upper halves dirty
across the loop. Benchmark-only knob (not API): `UHH_BENCH_XSTATE=none|gated|full`.

Why it matters: the SafetyHook mid-hook stub preserves GPRs, flags and XMM0-15. A
callback (and the CRT it calls) can disturb MXCSR flags and, via `vzeroupper` in AVX code
paths, the upper YMM/ZMM halves the target may have live at a MID-FUNCTION site.

| strategy | what is saved around the callback |
|---|---|
| none | nothing beyond the stub |
| gated (default) | MXCSR always (one instruction each way); full XSAVEC/XRSTOR only when `XGETBV(1)` says AVX/AVX-512 state is in use |
| full | XSAVEC/XRSTOR of x87+SSE+AVX+AVX-512 on every hit |

Results (ns per hit, median of 3, 5M calls, Win10 VM on i5-6600):

| | baseline | none | gated | full |
|---|---|---|---|---|
| x64, AVX idle | 1.4 | 75.3 | 76.1 (+1%) | 127.7 (+70%) |
| x64, AVX live | 2.6 | 73.8 | 76.6 (+4%) | 128.9 (+75%) |
| x86, AVX idle | 1.9 | 78.5 | 82.1 (+5%) | 135.2 (+72%) |
| x86, AVX live | 2.3 | 80.5 | 82.1 (+2%) | 135.5 (+68%) |

At a function entry the Windows ABI already treats YMM upper halves as volatile, so the
compiler never has them live across the call: `XGETBV(1)` reports AVX unused and gated
costs about the same as none. Gated pays the full save only at a mid-function site with
live AVX state -- exactly where skipping it would corrupt the target. Gated is the default.
