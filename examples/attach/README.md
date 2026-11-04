# uhh_attach: attach to a running target, enable its disabled feature, filter its reads

## The technique

Same target and same idea as [`gated_config`](../gated_config/README.md), but the
target is already running: UHH attaches to it by pid instead of launching it.

`probe_app` ships its read feature **disabled in its config** (`reads_enabled=0`).
`uhh_attach` turns it on from outside and watches it, without modifying the target,
its files or its config:

| Probe | Backend | Callback | What it does |
|---|---|---|---|
| `configparse.dll!ParseConfig+0x16` | breakpoint | `enable_reads` | the parsed flag is in EAX just before it is stored: 0 -> 1, so the disabled path runs |
| `ntdll.dll!NtOpenProcess` | `--backend` | `track_open_process` | handle -> pid map: pid from `CLIENT_ID` (arg 3), remember the out-handle pointer (arg 0) |
| `probe_app.exe!ReadThunk` | `--backend` | `log_read` | log only reads whose handle maps to pid P and whose address is in `[BASE, BASE+SIZE)` |

`configparse.dll` is not loaded yet when `uhh_attach` attaches (the target loads it
after the keystroke), so the flag breakpoint stays pending and arms when the DLL
loads. `ntdll` and `probe_app.exe` are already loaded, so those probes arm right after
the attach.

**Handle -> pid.** A read only carries a handle. At `NtOpenProcess` entry the pid is
known but the handle is not yet written, so `track_open_process` records `(pid, out
pointer)`. The first time `log_read` sees a handle it does not know, it dereferences
the remembered out pointers (`get_mem`) to find the open that produced it, then
caches it. probe_app opens each helper with `NtOpenProcess` into a long-lived
variable, so the pointer still holds the handle when the reads start (see
gated_config's README for why `kernel32!OpenProcess` would not do here).

The open and read probes must use the **same backend**: the map lives with the
callbacks (in `uhh_attach` for breakpoint/hw, inside the target's injected
`probe_api_agent.dll` for inline). The callbacks are the same source in every
backend (shared with gated_config, `examples/gated_config/callbacks.cpp`).

The helpers all hold their buffer at the **same address** (same image, same ASLR
base), so the address range alone cannot tell them apart: only the pid filter does.

## Usage

```
uhh_attach <target_pid> --pid P --range BASE:SIZE [--backend breakpoint|hw|inline]
```

`BASE` and `SIZE` take decimal or `0x` hex. Default backend: `breakpoint`.

## Manual run

Two consoles in the build directory (`build-x64\Release` or `build-x86\Release`;
`uhh_attach.exe` and `probe_app.exe` must be the same architecture).

1. **Console A** - start the target. It spawns its helpers, prints one line per
   helper, then waits for a key:

   ```
   > probe_app.exe --helpers 4 --threads 8 --reads 1000
   {"kind":"helper","index":0,"pid":6936,"base":140703050012240,"size":256}
   {"kind":"helper","index":1,"pid":7516,"base":140703050012240,"size":256}
   {"kind":"helper","index":2,"pid":6884,"base":140703050012240,"size":256}
   {"kind":"helper","index":3,"pid":5120,"base":140703050012240,"size":256}
   {"kind":"waiting","pid":3964,"helpers":4}
   ```

   Note the target's `pid` (3964) and one helper's `pid` and `base` (helper 1: 7516,
   140703050012240).

2. **Console B** - attach, filtering helper 1's reads at offset 64 (each helper buffer
   is 256 bytes; probe_app reads 16 bytes at offsets 0, 64, 128, 192):

   ```
   > uhh_attach.exe 3964 --pid 7516 --range 140703050012304:64 --backend inline
   {"kind":"attached","pid":3964}
   ```

   (`140703050012304` = base + 64.) Wait until it has printed (stderr)
   `probe: active ntdll.dll!NtOpenProcess ...` and `probe: active
   probe_app.exe!ReadThunk ...` - for `inline` the hooks install a moment after the
   attach.

3. **Console A** - press any key. probe_app loads configparse.dll, the breakpoint flips
   the flag, it opens its helpers and runs the reads, prints its `app` line and exits.

4. **Console B** - `uhh_attach` prints one `probe_log` per matching read, then the
   report, and exits when the target does:

   ```
   {"kind":"probe_log","probe":2,"tid":...,"message":"read handle=0xa4 pid=7516 addr=0x7ff7fb509690 size=16"}
   ...
   {"kind":"probe","location":"configparse.dll!ParseConfig+0x16","backend":"breakpoint","active":true,"hits":1}
   {"kind":"probe","location":"ntdll.dll!NtOpenProcess","backend":"inline","active":true,"hits":4}
   {"kind":"probe","location":"probe_app.exe!ReadThunk","backend":"inline","active":true,"hits":8000}
   {"kind":"probe_report",...,"overrides":1,"log_dropped":0,...}
   ```

Expected: `"overrides":1`, ReadThunk `hits` = threads x reads (8000: every read is
seen), and exactly 500 logged reads. probe_app's read pattern is deterministic: read
`i` (thread `t`'s `k`-th read, `i = t*R + k`) goes to helper `i % N` at offset
`64 * ((i / N) % 4)`, so with N=4 helper 1 at offset 64 gets every 16th read:
8000 / 16 = 500.

Without `uhh_attach` the same key press makes probe_app print
`"reads_enabled":0,"opened":0,"successful_reads":0` and exit: the feature is off.

## Tested by

`scripts/regress.py` (`attach-breakpoint`, `attach-hw`, `attach-inline`) runs exactly
these steps: start probe_app, parse its helper lines, run uhh_attach with helper 1's
pid and `[base+64, base+128)`, wait for `attached` and both `probe: active` lines,
write one byte to probe_app's stdin, then assert one override, every read hit,
logged reads == the predicted count, every logged pid == P, and no dropped logs.

## Note on the helpers

probe_app spawns its helpers before the gate (they stay idle - never opened, never
read - unless the flag is turned on). They have to exist before the attach: the
filter needs a helper's pid on the command line, and the flag can only be flipped by
a tool that is already attached when the config is parsed.
