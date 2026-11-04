#!/usr/bin/env python3
"""Benchmark Frida's Interceptor against our native inline backend on the EXACT
gated multithreaded read workload (probe_app, from docs/plan-v2.md).

It measures the per-read overhead Frida's Interceptor adds to ntdll!
NtReadVirtualMemory, versus an uninstrumented baseline, using probe_app's own
in-target QueryPerformanceCounter window (the "elapsed_ns" field) - the same
clock scripts/bench.py reads, so the two result sets line up column-for-column.

Comparability with scripts/bench.py:
  - Workload shape is identical: W threads x R reads through ReadThunk ->
    NtReadVirtualMemory, 4-way rotation (selected/in-range, selected/out-of-range,
    decoy/in-range, selected/other-offset). probe_app implements it.
  - "ns per iteration" == elapsed_ns / reads_per_thread (bench.py's normalization,
    so Frida slots next to inline/veh-sw/debug-sw/debug-hw as another `mode`).
  - We ALSO emit ns-per-read-total and added-ns-per-read-total, the intuitive
    per-call overhead.
  - Medians over N repeats; "added" = median(instrumented) - median(baseline).

What "overhead per read" means here: the extra wall time inside probe_app's
gated read loop attributable to Frida's trampoline + onEnter dispatch + arg
marshalling, divided by the number of NtReadVirtualMemory calls. The read hook
runs in 'count' mode (reads args[0] and args[3], bumps a counter, no per-call
send) so we measure the hook, not Frida's message IPC - the fair analogue of our
inline log_read whose PROBE_LOG only enqueues.

Baseline: probe_app with no Frida attached, reads enabled via `--config
reads_enabled=1` (so the workload runs without any flag-flip instrumentation).
Only ntdll!NtReadVirtualMemory is hooked in the instrumented run, so an
"attach-but-no-read-hook" run would equal baseline on the in-target clock; the
--with-attach-baseline flag verifies that if you want it.

Usage (on the Windows VM, in the build dir's shadow):
    python bench_frida.py --bin ..\\..\\build-x64\\RelWithDebInfo
    python bench_frida.py --bin <dir> --high-volume
    python bench_frida.py --bin <dir> --threads 8 --reads 500000 --repeats 5
"""
import argparse
import csv
import json
import os
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

try:
    import frida
except ImportError:
    sys.exit("frida not installed: pip install frida frida-tools")

HERE = Path(__file__).resolve().parent
READ_JS = HERE / "read_logger.js"
ENABLE_JS = HERE / "enable_reads.js"


# ---------------------------------------------------------------------------
def exports(script):
    """script.exports_sync (frida >= 16.1) or script.exports (older)."""
    return getattr(script, "exports_sync", None) or script.exports


def parse_lines(text):
    objs = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "kind" in o:
                objs[o["kind"]] = o
    return objs


def rva_from_map(map_file, sym):
    """Reuse scripts/site_rvas.py so RVAs match check_scenario.py exactly."""
    tool = HERE.parent.parent / "scripts" / "site_rvas.py"
    out = subprocess.check_output([sys.executable, str(tool), str(map_file), sym], text=True)
    return json.loads(out)[sym]


# ---------------------------------------------------------------------------
def run_baseline(exe, threads, reads, prehook, timeout):
    """probe_app, no Frida, reads enabled via config. Returns the app JSON."""
    cmd = [str(exe), "--no-wait", "--config", "reads_enabled=1",
           "--threads", str(threads), "--reads", str(reads),
           "--prehook" if prehook else "--clean"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode:
        raise RuntimeError(f"baseline failed: {cmd}\n{r.stdout}\n{r.stderr}")
    objs = parse_lines(r.stdout)
    if "app" not in objs:
        raise RuntimeError(f"baseline: no app result\n{r.stdout}\n{r.stderr}")
    return objs["app"]


def run_frida(exe, threads, reads, prehook, timeout,
              read_cfg=None, enable_cfg=None, gated=False):
    """Spawn probe_app under Frida, load the requested script(s), run the gated
    workload, and return (app_json, read_stats, enable_stats).

    gated=False: enable reads via `--config reads_enabled=1` and `--no-wait`
                 (clean per-read overhead measurement; no keystroke needed).
    gated=True : default config (reads off); enable_cfg script flips the flag, and
                 we deliver the keystroke on stdin after {"kind":"waiting"} - the
                 full real scenario (late DLL load + flag flip + gate)."""
    device = frida.get_local_device()
    argv = [str(exe), "--threads", str(threads), "--reads", str(reads),
            "--prehook" if prehook else "--clean"]
    if not gated:
        argv += ["--no-wait", "--config", "reads_enabled=1"]

    buf = []
    lock = threading.Lock()

    def on_output(pid_, fd, data):
        if fd in (1, 2) and data:
            with lock:
                buf.append((fd, data.decode("utf-8", "replace")))

    device.on("output", on_output)
    read_script = enable_script = session = None
    pid = None
    succeeded = False
    try:
        pid = device.spawn(argv, stdio="pipe")
        session = device.attach(pid)

        # Load the enable script FIRST so its module-load watcher is armed before
        # resume (configparse.dll loads only after the gate).
        if enable_cfg is not None:
            enable_script = session.create_script(ENABLE_JS.read_text(encoding="utf-8"))
            enable_script.on("message", lambda m, d: None)
            enable_script.load()
            exports(enable_script).configure(enable_cfg)
        if read_cfg is not None:
            read_script = session.create_script(READ_JS.read_text(encoding="utf-8"))
            read_script.on("message", lambda m, d: None)
            read_script.load()
            exports(read_script).configure(read_cfg)

        device.resume(pid)

        # Gate + collect until the {"kind":"app"} result line appears.
        deadline = time.time() + timeout
        key_sent = False
        app = None
        while time.time() < deadline:
            with lock:
                text = "".join(t for fd, t in buf if fd == 1)
            objs = parse_lines(text)
            if gated and not key_sent and "waiting" in objs:
                device.input(pid, b"x")        # the gate keystroke (one byte)
                key_sent = True
            if "app" in objs:
                app = objs["app"]
                break
            time.sleep(0.005)

        read_stats = exports(read_script).stats() if read_script else {}
        enable_stats = exports(enable_script).stats() if enable_script else {}
        if app is None:
            with lock:
                dump = "".join(t for _, t in buf)
            raise RuntimeError(f"frida run: no app result within {timeout}s\n{dump}")
        succeeded = True
        return app, read_stats, enable_stats
    finally:
        device.off("output", on_output)
        for s in (read_script, enable_script):
            if s is not None:
                try:
                    s.unload()
                except Exception:
                    pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        # On success probe_app exits on its own right after the app line (and its
        # destructors signal the helper children to stop). Only kill on failure,
        # so a hung/timed-out run does not leave processes behind.
        if pid is not None and not succeeded:
            try:
                device.kill(pid)
            except Exception:
                pass


# ---------------------------------------------------------------------------
def summarize(mode, rows, baseline_median, threads, reads, prehook, extra=None):
    per_iter = [r["elapsed_ns"] / reads for r in rows]          # bench.py's normalization
    per_read = [r["elapsed_ns"] / (threads * reads) for r in rows]
    med_iter = statistics.median(per_iter)
    med_read = statistics.median(per_read)
    base_iter = baseline_median
    out = dict(
        workload="reads", callback="log", mutation="register", prehook=prehook,
        mode=mode, repeats=len(rows),
        median_ns_per_iteration=round(med_iter, 3),
        min_ns_per_iteration=round(min(per_iter), 3),
        max_ns_per_iteration=round(max(per_iter), 3),
        added_ns_per_iteration=round(med_iter - base_iter, 3),
        slowdown=round(med_iter / base_iter, 6) if base_iter else None,
        # extra, Frida-friendly columns:
        threads=threads, reads_per_thread=reads, total_reads=threads * reads,
        median_ns_per_read_total=round(med_read, 4),
        added_ns_per_read_total=round(med_read - (baseline_median_per_read or 0), 4),
    )
    if extra:
        out.update(extra)
    return out


# ---------------------------------------------------------------------------
baseline_median_per_read = None  # set in main() for the summarize() helper


def main():
    global baseline_median_per_read
    cpu = os.cpu_count() or 4
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bin", type=Path, required=True,
                   help="dir with probe_app.exe, configparse.dll, probe_app.map, configparse.map")
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--reads", type=int, default=50000, help="reads PER THREAD")
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--timeout", type=float, default=180)
    p.add_argument("--out", type=Path, default=HERE / "results")
    p.add_argument("--prehook", action="store_true",
                   help="also install probe_app's pre-existing ReadThunk hook (prehook axis)")
    p.add_argument("--gated", action="store_true",
                   help="exercise the real gate: flag-flip hook + stdin keystroke "
                        "(default enables reads via --config for a clean baseline)")
    p.add_argument("--flag-method", choices=["parseconfig", "flagsite"], default="parseconfig")
    p.add_argument("--with-attach-baseline", action="store_true",
                   help="also time Frida attached with NO read hook (isolates attach cost)")
    p.add_argument("--high-volume", action="store_true",
                   help=f"preset: threads=2*cores (={2*cpu}), reads=2,000,000/thread "
                        "unless overridden; count mode only")
    args = p.parse_args()

    if args.high_volume:
        if args.threads == 4:
            args.threads = 2 * cpu           # > cores, as plan-v2 requires
        if args.reads == 50000:
            args.reads = 2_000_000
    if not (1 <= args.threads <= 256 and 1 <= args.reads <= 1_000_000_000):
        p.error("threads 1..256, reads 1..1e9 (probe_app limits)")

    args.bin = args.bin.resolve()
    exe = args.bin / "probe_app.exe"
    if not exe.exists():
        p.error(f"not found: {exe}")
    args.out.mkdir(parents=True, exist_ok=True)
    total = args.threads * args.reads

    # RVAs (only needed for the 'flagsite' flag-flip method, from the linker maps).
    flag_rva = None
    if args.gated and args.flag_method == "flagsite":
        flag_rva = rva_from_map(args.bin / "configparse.map", "ParsedFlagSite")

    enable_cfg = None
    if args.gated:
        enable_cfg = {"method": args.flag_method}
        if flag_rva is not None:
            enable_cfg["flagRva"] = flag_rva
    # Read hook: count mode, no filter -> pure per-hit hook overhead.
    read_cfg = {"mode": "count"}

    print(f"workload: {args.threads} threads x {args.reads} reads = {total:,} reads, "
          f"repeats={args.repeats}, gated={args.gated}, prehook={args.prehook}", flush=True)

    raw = []

    def record(mode, app, rstats, estats):
        row = dict(mode=mode, elapsed_ns=app["elapsed_ns"],
                   successful_reads=app["successful_reads"], checksum=app["checksum"],
                   reads_enabled=app["reads_enabled"], prehook_calls=app.get("prehook_calls", 0),
                   frida_read_calls=rstats.get("calls", 0),
                   frida_matched=rstats.get("matched", 0),
                   frida_overrides=estats.get("overrides", 0))
        raw.append(row)
        # Correctness gates, mirroring check_scenario.py.
        assert app["reads_enabled"] == 1, app
        assert app["successful_reads"] == total, app
        return row

    # 1. Baseline (no Frida).
    base_rows = []
    for i in range(args.repeats):
        app = run_baseline(exe, args.threads, args.reads, args.prehook, args.timeout)
        base_rows.append(record("baseline", app, {}, {}))
        print(f"  baseline  repeat {i+1}/{args.repeats}: elapsed_ns={app['elapsed_ns']:.0f}", flush=True)
    baseline_median = statistics.median(r["elapsed_ns"] / args.reads for r in base_rows)
    baseline_median_per_read = statistics.median(r["elapsed_ns"] / total for r in base_rows)

    # 2. Optional: Frida attached, NO read hook (attach cost isolation).
    attach_rows = []
    if args.with_attach_baseline:
        for i in range(args.repeats):
            app, rs, es = run_frida(exe, args.threads, args.reads, args.prehook, args.timeout,
                                    read_cfg=None, enable_cfg=enable_cfg, gated=args.gated)
            attach_rows.append(record("frida-attach", app, rs, es))
            print(f"  attach    repeat {i+1}/{args.repeats}: elapsed_ns={app['elapsed_ns']:.0f}", flush=True)

    # 3. Frida with the NtReadVirtualMemory hook (the measurement).
    frida_rows = []
    for i in range(args.repeats):
        app, rs, es = run_frida(exe, args.threads, args.reads, args.prehook, args.timeout,
                                read_cfg=read_cfg, enable_cfg=enable_cfg, gated=args.gated)
        frida_rows.append(record("frida", app, rs, es))
        # The hook should see ~one call per gated read.
        hook_calls = rs.get("calls", 0)
        print(f"  frida     repeat {i+1}/{args.repeats}: elapsed_ns={app['elapsed_ns']:.0f} "
              f"hook_calls={hook_calls:,} (reads={total:,})", flush=True)

    # Summaries (same columns as scripts/bench.py summary + Frida extras).
    summary = [summarize("baseline", base_rows, baseline_median, args.threads, args.reads, args.prehook)]
    if attach_rows:
        summary.append(summarize("frida-attach", attach_rows, baseline_median,
                                 args.threads, args.reads, args.prehook))
    summary.append(summarize("frida", frida_rows, baseline_median, args.threads, args.reads, args.prehook,
                             extra={"flag_method": args.flag_method if args.gated else "config",
                                    "frida_version": frida.__version__}))

    (args.out / "raw.jsonl").write_text("\n".join(json.dumps(r) for r in raw) + "\n")
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2))
    with (args.out / "summary.csv").open("w", newline="") as f:
        cols = list(summary[-1].keys())
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(summary)

    fr = summary[-1]
    print("\n=== Frida vs baseline (reads workload) ===")
    print(f"  baseline : {baseline_median:10.2f} ns/iter   "
          f"{baseline_median_per_read*1e0:8.3f} ns/read")
    print(f"  frida    : {fr['median_ns_per_iteration']:10.2f} ns/iter   "
          f"added {fr['added_ns_per_read_total']:.3f} ns/read   slowdown x{fr['slowdown']}")
    print(f"\nresults: {args.out.resolve()}")


if __name__ == "__main__":
    main()
