# Review findings (wave-1 bots, 4 Nov 2026)

Actionable items from the three analysis agents, to fold into the consolidation
refactor. Not yet applied. Ordered within each section by impact.

## Correctness gates (correctness-checks bot)

1. **Read path has no probe and no content oracle (highest).** check_scenario.py
   only asserts the app's own `successful_reads`; the shared `example_callback` is
   never invoked (the flag flip is a raw EAX patch in session.cpp). First-call read
   interception and the "same shared C callback" contract are untested. → When the
   read probe lands, assert its match/record totals and content, not just app totals.
2. **record_digest breaks under multithreading.** win_common.hpp:39 FNV-hashes
   records in array order; sequence = read_hits-1 (callback.c:37) over a single
   non-atomic probe_stats. Multithreaded reads → RMW races + schedule-dependent
   order → flaky/meaningless. → Per-thread buffers or atomics; compare order-
   independently as a multiset keyed by the stable request index (app.cpp already
   computes t*reads+k). Replace the ordered digest for the MT case.
3. **check_scenario echoes the app; no independent checksum.** → Recompute in
   Python: for total%4==0, checksum == (total/4)*(64+128+64+80). Cheap, do early.
4. **Existing-hook gate is aggregate-only and at the wrong site.** prehook_calls==
   total proves totals, not per-read exactly-once; and our probe is on the flag,
   not the read path, so coexistence on reads is unproven. → When the read probe
   exists, install it over the prehook on ReadThunk/ReadSite; assert both counts.
5. **Scenario is outside all automated runs.** (CTest exclusion is intentional.)
   Audit suggests a small CI *smoke* job (threads 2, reads 50), separate from the
   policy CTest. NOTE: user said "pray this is not a CI gate" — DECISION PENDING,
   do not add without confirming.
6. **Override site not validated as the expected instruction boundary.** → In
   session.cpp, after reading the original byte, require the 2 bytes == {0x89,0x01}
   (mov [rcx],eax) before arming. Cheap.

## Code simplicity (code-simplicity bot)

1. session.cpp: `int stepping` is a disguised bool (-1/0, tested >=0) → `bool
   single_stepping`.
2. session.cpp: magic `0x100` EFLAGS.TF repeated → name `constexpr DWORD TRAP_FLAG`.
3. session.cpp: usage banner stale (missing <read_rva>); line 140 packs a `break`;
   line 89 packs four vars of three types.
4. detect.hpp: `report_entry` uses cramped spacing unlike sibling compare_to_disk
   (AI-pass tell); calls classify_entry 3x on same bytes → compute `kind` once.
5. app.cpp: `Hello::pid`/`reserved` written but never read → slim the struct.
   helper_main return line packs cast+parse+timeout+ternary → split; 600000 = 10min.
6. configparse.c: `sizeof("reads_enabled")` as cursor offset is opaque → named length.

## Corner cases (corner-cases bot)

Structural facts: ReadSite == ReadThunk (same address), so prehook + probe coexist
at one address. session.cpp drives the multithreaded probe_app but only arms the
once-on-main-thread flag site; debugger.cpp/agent.cpp drive the single-thread
probe_target. So the MT criticals are LATENT until a probe is armed on ReadSite.

Critical (all triggered the moment a probe is armed on a site >1 thread crosses):
- C1. INT3 restore→step→re-arm removes the byte process-wide; other threads miss
  the site in the window, and a non-owner-thread hit becomes a 2nd-chance crash.
  Global `stepping`. Required by plan step 4 (bpsync) but unbuilt.
- C2. session.cpp uses the MAIN thread's CONTEXT for every breakpoint, ignoring
  e.dwThreadId (session.cpp:98-99,142-161). Breaks if a probe fires on a worker.
- C3. probe_stats mutated non-atomically (callback.c:4-6,27,35-37); inline fires on
  all threads → the one MT-capable backend corrupts counters/records. Needs
  per-thread accumulation (ties to correctness #2).

Important:
- I1. Deferred match is basename-only; no path restriction; no UNLOAD handling →
  stale active address after unload/reload; same-name/other-path wrongly arms.
- I2. compare_to_disk: no base-reloc handling (false positives), only 16 bytes,
  unhardened PE parser (no PE32+ check, no section-table bounds check).
- I3. Unknown redirect patterns are logged but still armed/stepped — no safe-fail
  (or HW-fallback) gate on "unknown".
- I4. SafetyHook inline untested at REAL sites (all sites are NOP sleds): RIP-rel
  fixup, branch-into-stolen-bytes, trampoline unwind/CET, see also I7.
- I5. New-process-by-name attach unbuilt; enumerated cases (PID reuse, cutoff,
  basename/path, one-shot tie-break, module reconciliation).
- **I6. BUG: session.cpp double-closes handles on the failure asserts** — closes
  thread/pi/stdin_wr (session.cpp:174-175) then require() can throw into the catch
  which closes again (session.cpp:184-187). Fix: assert before closing, null after.
- I7. AVX/YMM high state + direction flag not preserved across the inline callback
  (SafetyHook v0.7.0 doesn't save YMM high; DF not normalized before the C call).
- I8. local_read/local_write __except swallows GUARD_PAGE (disarms stack growth)
  and loses partial-write count.

Minor: M1 resolved RVA not validated in-section/on-boundary; M2 HW breakpoints
only on main thread, no CREATE_THREAD handling; M3 fault during single-step leaves
site un-rearmed; M4 removal-order invariant not exercised at the shared address;
M5 null hFile → false "stayed pending"; M6 forwarded exports/IAT not modeled.
