#!/usr/bin/env python3
"""SUPERSEDED by bench/frida/vs_frida.py (frida 17.26+, idiomatic agents, exact judges; see
bench/BENCHMARKS.md). Kept for the record.

Unified UHH-vs-Frida benchmark matrix on the gated multithreaded read workload.

Measures per-read overhead for every backend on the SAME in-target clock
(probe_app's QueryPerformanceCounter window, the "elapsed_ns" field), so all rows
line up column-for-column:

  baseline            probe_app, no instrumentation (reads enabled via config)
  uhh:inline          UHH SafetyHook mid-hook at probe_app.exe!ReadThunk
  uhh:hw              UHH debug-register backend
  uhh:breakpoint      UHH external INT3 + displaced-step backend
  frida:interceptor   Frida Interceptor (inline trampoline), JS onEnter, count mode
  frida:cmodule       Frida Interceptor with a native C (CModule) onEnter
  frida:stalker       Frida Stalker follow + addCallProbe (per-thread recompilation)
  frida:hwbp          Frida per-thread hardware breakpoint + exception handler

UHH runs go through gated_config.exe (flag flip via breakpoint enables reads, then
the chosen read backend probes probe_app.exe!ReadThunk). Frida runs ATTACH to a gated probe_app
(reads enabled via --config), install the hook before releasing the gate, measure.

NOTE: Frida is driven via ATTACH, not spawn, because frida 17.25.2 aborts on this
VM with "Unable to locate the ntdll loader TLS routines" on both spawn and attach;
frida 16.5.9 attaches fine. Run this script with the 16.5.9 interpreter for the
frida rows (C:\\work\\fv16\\Scripts\\python.exe). UHH/baseline rows need no frida.

Count mode for every Frida method (read args, bump a counter, no send()) - the fair
analogue of UHH's log_read whose PROBE_LOG only enqueues.
"""
import argparse, csv, json, os, statistics, subprocess, sys, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parent          # bench/
FRIDADIR = HERE / "frida"
REPO = HERE.parent

UHH_BACKENDS = {"inline": "inline", "hw": "hw", "breakpoint": "breakpoint"}
FRIDA_JS = {
    "interceptor": "read_logger.js",
    "cmodule": "read_cmodule.js",
    "stalker": "read_stalker.js",
    "hwbp": "read_hwbp.js",
}


def parse_objs(text):
    """Pull app/probe/probe_report out of (possibly huge) stdout; skip probe_log."""
    app = report = None
    probes = []
    for line in text.splitlines():
        if "probe_log" in line:
            continue
        if not line.startswith('{'):
            continue
        if '"kind":"app"' in line:
            app = json.loads(line)
        elif '"kind":"probe_report"' in line:
            report = json.loads(line)
        elif '"kind":"probe"' in line:
            probes.append(json.loads(line))
    return app, probes, report


# --------------------------------------------------------------------------- UHH
def run_baseline(rel, threads, reads, timeout):
    cmd = [str(rel / "probe_app.exe"), "--no-wait", "--config", "reads_enabled=1",
           "--threads", str(threads), "--reads", str(reads)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    app, _, _ = parse_objs(r.stdout)
    if app is None:
        raise RuntimeError(f"baseline: no app line\nSTDERR {r.stderr[:500]}")
    return app


def run_uhh(rel, backend, threads, reads, timeout, tmp):
    outfile = tmp / f"uhh_{backend}_{threads}x{reads}.out"
    cmd = [str(rel / "gated_config.exe"), "--flag-backend", "breakpoint", "--read-backend", backend,
           "configparse.dll!ParseConfig+0x16", "probe_app.exe!ReadThunk",
           "--", str(rel / "probe_app.exe"), "--no-wait", "--threads", str(threads), "--reads", str(reads)]
    with open(outfile, "w") as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=timeout)
    text = outfile.read_text(errors="replace")
    app, probes, report = parse_objs(text)
    if app is None or report is None:
        raise RuntimeError(f"uhh {backend}: missing app/report rc={r.returncode}\nSTDERR {r.stderr[:500]}")
    read_probe = next((p for p in probes if p.get("location", "").startswith("probe_app.exe")), None)
    return app, read_probe, report, r.returncode


# ------------------------------------------------------------------------- Frida
def run_frida(rel, method, threads, reads, timeout):
    import frida
    src = (FRIDADIR / FRIDA_JS[method]).read_text(encoding="utf-8")
    cmd = [str(rel / "probe_app.exe"), "--config", "reads_enabled=1",
           "--threads", str(threads), "--reads", str(reads)]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, bufsize=0)
    errbuf = []
    threading.Thread(target=lambda: errbuf.append(proc.stderr.read()), daemon=True).start()
    t0 = time.time()
    sess = scr = None
    msgs = []
    try:
        waiting = None
        while time.time() - t0 < timeout:
            line = proc.stdout.readline()
            if not line:
                break
            if b'"kind":"waiting"' in line:
                waiting = json.loads(line.decode()); break
        if waiting is None:
            raise RuntimeError("frida: no waiting line")
        sess = frida.attach(proc.pid)
        scr = sess.create_script(src)
        scr.on("message", lambda m, d: msgs.append(m))
        scr.load()
        exp = getattr(scr, "exports_sync", None) or scr.exports
        exp.configure({"mode": "count"})
        proc.stdin.write(b"x"); proc.stdin.flush()
        app = None
        while time.time() - t0 < timeout:
            line = proc.stdout.readline()
            if not line:
                break
            if b'"kind":"app"' in line:
                app = json.loads(line.decode()); break
        if app is None:
            raise RuntimeError("frida: no app line")
        # probe_app exits immediately after the app line, which tears down the
        # script; the scripts emit a {'type':'done', ...} message on the target's
        # RtlExitUserProcess hook so we get an accurate final count in time.
        done = None
        last_err = None
        dl = time.time() + 6          # exit hook holds the process ~4s
        while time.time() < dl:
            for mm in msgs:
                pl = mm.get("payload") if mm.get("type") == "send" else None
                if isinstance(pl, dict) and pl.get("type") == "done":
                    done = pl; break
            if done is not None:
                break
            try:
                s = exp.stats()
                if s and s.get("calls", -1) >= 0:
                    done = s; break
            except Exception as e:
                last_err = e
            time.sleep(0.03)
        if done is None:
            done = {"calls": -1, "note": f"no count (last_err={last_err})"}
        return app, done, msgs
    finally:
        if scr is not None:
            try: scr.unload()
            except Exception: pass
        if sess is not None:
            try: sess.detach()
            except Exception: pass
        try: proc.wait(timeout=15)
        except Exception:
            try: proc.kill()
            except Exception: pass


# --------------------------------------------------------------------------- run
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rel", type=Path, default=Path(r"C:\work\probe-first-pass\build-x64\Release"))
    p.add_argument("--threads", type=int, default=8)
    p.add_argument("--reads", type=int, default=50000)
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--timeout", type=float, default=240)
    p.add_argument("--methods", default="baseline,uhh:inline,uhh:hw,uhh:breakpoint,"
                   "frida:interceptor,frida:cmodule,frida:stalker,frida:hwbp")
    p.add_argument("--out", type=Path, default=HERE / "results")
    p.add_argument("--tag", default="run")
    args = p.parse_args()

    rel = args.rel.resolve()
    tmp = args.out / "tmp"
    args.out.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    W, R, N = args.threads, args.reads, args.repeats
    total = W * R
    methods = [m.strip() for m in args.methods.split(",") if m.strip()]

    print(f"[{args.tag}] W={W} R={R} total={total:,} repeats={N} methods={methods}", flush=True)
    raw = []            # one row per run
    summary = []        # one row per method

    # Always need baseline first for the "added" column.
    base_elapsed = []
    for i in range(N):
        app = run_baseline(rel, W, R, args.timeout)
        assert app["successful_reads"] == total, app
        base_elapsed.append(app["elapsed_ns"])
        raw.append(dict(method="baseline", repeat=i, elapsed_ns=app["elapsed_ns"],
                        successful_reads=app["successful_reads"], checksum=app["checksum"]))
        print(f"  baseline {i+1}/{N}: {app['elapsed_ns']:.0f} ns  reads={app['successful_reads']}", flush=True)
    base_med = statistics.median(base_elapsed)
    base_per_read = base_med / total
    summary.append(dict(method="baseline", repeats=N,
                        median_elapsed_ns=base_med,
                        median_ns_per_read=round(base_per_read, 4),
                        added_ns_per_read=0.0, slowdown=1.0,
                        hits=total, hits_exact=True, checksum=app["checksum"], notes=""))

    for m in methods:
        if m == "baseline":
            continue
        elapsed, hits_list, extra = [], [], {}
        ok = True
        try:
            if m.startswith("uhh:"):
                backend = m.split(":", 1)[1]
                for i in range(N):
                    app, rp, rep, rc = run_uhh(rel, backend, W, R, args.timeout, tmp)
                    hit = rp["hits"] if rp else -1
                    elapsed.append(app["elapsed_ns"]); hits_list.append(hit)
                    raw.append(dict(method=m, repeat=i, elapsed_ns=app["elapsed_ns"],
                                    successful_reads=app["successful_reads"], checksum=app["checksum"],
                                    hits=hit, overrides=rep.get("overrides"),
                                    log_dropped=rep.get("log_dropped"), rc=rc))
                    print(f"  {m} {i+1}/{N}: {app['elapsed_ns']:.0f} ns  hits={hit} "
                          f"dropped={rep.get('log_dropped')} reads={app['successful_reads']}", flush=True)
                    extra = dict(overrides=rep.get("overrides"), log_dropped=rep.get("log_dropped"))
            elif m.startswith("frida:"):
                method = m.split(":", 1)[1]
                for i in range(N):
                    app, stats, msgs = run_frida(rel, method, W, R, args.timeout)
                    hit = stats.get("calls", -1)
                    elapsed.append(app["elapsed_ns"]); hits_list.append(hit)
                    raw.append(dict(method=m, repeat=i, elapsed_ns=app["elapsed_ns"],
                                    successful_reads=app["successful_reads"], checksum=app["checksum"],
                                    hits=hit, frida_stats=stats))
                    print(f"  {m} {i+1}/{N}: {app['elapsed_ns']:.0f} ns  calls={hit} "
                          f"reads={app['successful_reads']} extra={({k:v for k,v in stats.items() if k not in ('calls','matched','logged','resolveCalls')})}", flush=True)
                    extra = {k: v for k, v in stats.items() if k not in ("calls", "matched", "logged", "resolveCalls")}
            else:
                print(f"  ?? unknown method {m}", flush=True); continue
        except Exception as e:
            ok = False
            print(f"  {m}: FAILED {e!r}", flush=True)
            summary.append(dict(method=m, repeats=0, median_elapsed_ns=None,
                                median_ns_per_read=None, added_ns_per_read=None,
                                slowdown=None, hits=None, hits_exact=False,
                                checksum=None, notes=f"FAILED: {e}"))
            continue
        med = statistics.median(elapsed)
        per_read = med / total
        hits_exact = all(h == total for h in hits_list)
        summary.append(dict(method=m, repeats=len(elapsed),
                            median_elapsed_ns=med,
                            median_ns_per_read=round(per_read, 4),
                            added_ns_per_read=round(per_read - base_per_read, 4),
                            slowdown=round(med / base_med, 4),
                            hits=hits_list, hits_exact=hits_exact,
                            checksum=app["checksum"],
                            notes=json.dumps(extra) if extra else ""))

    stamp = f"{args.tag}_W{W}_R{R}"
    (args.out / f"raw_{stamp}.jsonl").write_text("\n".join(json.dumps(r) for r in raw) + "\n")
    (args.out / f"summary_{stamp}.json").write_text(json.dumps(summary, indent=2))
    with (args.out / f"summary_{stamp}.csv").open("w", newline="") as f:
        cols = ["method", "repeats", "median_elapsed_ns", "median_ns_per_read",
                "added_ns_per_read", "slowdown", "hits_exact", "hits", "checksum", "notes"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for s in summary:
            row = dict(s); row["hits"] = json.dumps(s["hits"])
            w.writerow(row)

    print(f"\n=== SUMMARY [{stamp}] (baseline median {base_med:.0f} ns, {base_per_read:.3f} ns/read) ===")
    for s in summary:
        print(f"  {s['method']:20s} added_ns/read={str(s['added_ns_per_read']):>10s} "
              f"slowdown={str(s['slowdown']):>8s} hits_exact={s['hits_exact']} notes={s['notes'][:60]}")
    print(f"\nresults in {args.out}")


if __name__ == "__main__":
    main()
