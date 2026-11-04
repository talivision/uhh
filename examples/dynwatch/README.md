# dynwatch — follow a pointer from malloc to every write

The instrumentation is built **at runtime, from inside callbacks**, on the real CRT
allocator. Nothing in the target is labelled or modified for the demo.

```
ucrtbase.dll!malloc  (entry probe: breakpoint | hw | inline)
   size == 0x1337 ?  read the return address from [SP]
   └─ probe_add_address(get_session(c), ret, on_return, PROBE_BREAKPOINT | PROBE_ONCE)
        AX = the new block
        └─ probe_watch(get_session(c), block, on_write, PROBE_WATCH_WRITE)
             every store to the block -> on_write -> send_log_stack(...)
```

```
dynwatch_driver --entry breakpoint|hw|inline -- <dynwatch_target.exe> [--writes N]
```

What it shows:

- **Every control-plane call works from every callback type.** With `--entry inline`
  `on_malloc` runs *inside the target*; its `probe_add_address` is forwarded to the
  controller (one synchronous exception, callback passed by export name) and the rest
  of the chain runs controller-side. The callback source is identical in all three.
- **Data watchpoints observe access, not code** — including from a thread created after
  the watch was armed. Unrelated allocations written in the same loop are not reported.
- **One-shot probes** (`PROBE_ONCE`) retire after their first hit; other threads already
  racing to the same INT3 are rewound transparently.
- **Stacks in the log**: `send_log_stack` records raw return addresses at the hit and
  symbolizes them when the log is reported, e.g.
  `dynwatch_target!main+0x193 (dynwatch_target.c:43)`. (The store is on line 42: a data
  watchpoint traps *after* the access, so frame 0 of a watch hit is the instruction
  following the store.) Without PDBs frames fall back to
  exports / `module+offset`; set `_NT_SYMBOL_PATH` (e.g. the Microsoft symbol server)
  for accurate system-DLL names.

Expected: `watch_hits == 2 * writes` (main thread + worker). The tracked block is not
freed, because `HeapFree` writes free-list metadata into it — which the watchpoint
would (correctly) also report. Covered by `scripts/regress.py` (`dynwatch-*`).
