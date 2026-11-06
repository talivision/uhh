#!/usr/bin/env python3
"""A/B performance harness: several UHH builds, the same targets, interleaved rounds.

  python -u bench\\perfab\\perf_ab.py --side main=<Release dir> --side mf=<Release dir> [--side ...]
         --targets <Release dir whose TARGET binaries all use> --rounds 5 --out raw.jsonl
         [--group core|extra|all] [--only substr,...] [--skip substr,...]

The CONTROLLER side (hitcost_driver, lifecycle_bench, gated_config, uhh_trace, probe_api*.dll)
comes from each build; every TARGET (hitcost_target, probe_app + configparse, logstream_target)
comes from --targets, so all builds instrument byte-identical programs. Each case runs
the sides in a rotated order each round (reversed in odd rounds). Before each run the machine must be quiet
(GetSystemTimes: < QUIET_PCT busy over 1 s, waits up to 120 s, records what it saw). One JSON
line per (round, case, side) goes to --out; bench/perfab/summarize.py turns it into tables.

Cases (names are <family>/<backend>/<variant>):
  hit/<bk>/<method>/t<T> hitcost_driver --method m, T threads: target ns per call per thread
                         (in-target QPC loop), hits/s, probe hits (must equal calls). bk = inline,
                         hw (execute), watch (hw data watchpoint, write, on the global hit_site
                         writes), breakpoint; base = no instrumentation.
  sink/<bk>/<nul|file|pipe>  send_log, 1 thread: logs/s end to end (process wall), exact count
                         checked on file and pipe.
  latency/<bk>/idle      uhh_trace on logstream_target (50 LogSite calls 100 ms apart): event ->
                         stdout arrival p50/p99 (QPC, same clock).
  live/<bk>/load         send_log at full speed with a QPC stamp as the argument: lag p50/p99 of
                         every 64th record, and the fraction delivered before the target ended.
  attach/<bk>/idle|busy  lifecycle_bench --attach (target idle on stdin / hitting the probe in a
                         loop): attach_ms, detach_ms; the target must carry on afterwards.
  launch/<bk>/-          lifecycle_bench launch of a 1000-call target: launch_ms, run_ms, total.
  gated/<bk>/8xR         the flagship: gated_config (flag on a breakpoint, reads on <bk>) over
                         probe_app 8 threads x R reads, 4 helpers: elapsed_ns (in-target), wall,
                         exact reads/logs/hits. base = probe_app with reads enabled by config.
"""
import argparse, ctypes, json, os, re, shutil, subprocess, sys, threading, time
from pathlib import Path

QUIET_PCT = 12.0      # % of all CPUs busy (4 cores: half a core) before a run starts
FLAG = "configparse.dll!ParseConfig+0x16"
READ = "ntdll.dll!NtReadVirtualMemory"

k32 = ctypes.windll.kernel32


class FT(ctypes.Structure):
    _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]


def _systimes():
    i, k, u = FT(), FT(), FT()
    k32.GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u))
    v = lambda f: (f.hi << 32) | f.lo
    return v(i), v(k) + v(u)          # idle, total (kernel includes idle)


def busy_pct(seconds):
    i0, t0 = _systimes(); time.sleep(seconds); i1, t1 = _systimes()
    return 100.0 * (1 - (i1 - i0) / max(1, t1 - t0))


def wait_quiet():
    t0, seen = time.time(), []
    while True:
        b = busy_pct(1.0); seen.append(round(b, 1))
        if b < QUIET_PCT or time.time() - t0 > 120:
            return {"pre_busy": round(b, 1), "waited_s": round(time.time() - t0, 1), "quiet": b < QUIET_PCT}


def qpc():
    c = ctypes.c_int64(); k32.QueryPerformanceCounter(ctypes.byref(c)); return c.value


QPF = (lambda f: (k32.QueryPerformanceFrequency(ctypes.byref(f)), f.value)[1])(ctypes.c_int64())


class Side:
    def __init__(self, name, bindir, tmp):
        self.name, self.bin, self.tmp = name, Path(bindir), Path(tmp)
        self.tmp.mkdir(parents=True, exist_ok=True)
        # The controller's %TEMP% (session log files): a local dir per side, emptied after each run.
        self.env = dict(os.environ, TEMP=str(self.tmp), TMP=str(self.tmp))

    def exe(self, n):
        return str(self.bin / n)

    def clean(self):
        shutil.rmtree(self.tmp / "uhh", ignore_errors=True)


T = None   # targets dir (Path)


def tgt(n):
    return str(T / n)


def scan_file(path):
    """Count probe_log lines; return (logs, list of the other JSON objects)."""
    logs, objs = 0, []
    with open(path, "rb") as f:
        for line in f:
            if line.startswith(b'{"kind":"probe_log"'):
                logs += 1
            elif line.startswith(b"{"):
                try:
                    objs.append(json.loads(line))
                except ValueError:
                    pass
    return logs, objs


def kind(objs, k):
    return [o for o in objs if o.get("kind") == k]


def first(objs, k):
    x = kind(objs, k)
    return x[0] if x else {}


def run_to_file(side, cmd, timeout, out_name="out.jsonl", stdin=subprocess.DEVNULL):
    out = side.tmp / out_name
    t0 = time.perf_counter()
    with open(out, "wb") as f:
        p = subprocess.run([str(c) for c in cmd], stdout=f, stderr=subprocess.DEVNULL, stdin=stdin,
                           env=side.env, timeout=timeout)
    wall = time.perf_counter() - t0
    logs, objs = scan_file(out)
    out.unlink()
    return p.returncode, wall, logs, objs


# ---------------------------------------------------------------- cases
# Calls PER THREAD per (backend, method); default per backend. Sized for seconds a run.
HIT_CALLS = {
    ("base", None): 10_000_000,
    ("inline", None): 200_000, ("inline", "send_log_stack"): 50_000,
    ("hw", None): 20_000, ("watch", None): 20_000, ("breakpoint", None): 20_000,
    ("hw", "send_log_stack"): 5_000, ("breakpoint", "send_log_stack"): 5_000,
    ("hw", "call_func"): 5_000, ("breakpoint", "call_func"): 5_000,
    ("hw", "call_original"): 5_000, ("breakpoint", "call_original"): 5_000,
}
METHODS = ["empty", "send_log", "get_func_arg", "get_mem", "send_log_stack", "call_original", "call_func"]
BACKENDS = ["inline", "hw", "breakpoint"]
HIT_BACKENDS = ["inline", "hw", "watch", "breakpoint"]     # watch = hw data watchpoint (write) on g_sink
_RVA = {}


def sink_rva():
    if "sink" not in _RVA:
        out = subprocess.run([tgt("hitcost_target.exe"), "--print-rva"], capture_output=True, timeout=30).stdout
        _RVA["sink"] = json.loads(out.splitlines()[0])["sink"]
    return _RVA["sink"]


def calls_for(bk, m, threads=1):
    n = HIT_CALLS.get((bk, m), HIT_CALLS[(bk, None)])
    return n // threads if bk != "base" else n


def case_hit(side, bk, m, threads=1):
    """ns_per_call = in-target loop wall / calls per thread: what one call costs a thread
    (with T threads running at once). hits_per_s = all threads' calls / wall."""
    n = calls_for(bk, m, threads)
    if bk == "base":
        cmd = [tgt("hitcost_target.exe"), "--no-wait", "--calls", n, "--threads", threads]
    else:
        cmd = [side.exe("hitcost_driver.exe"), "--backend", bk, "--method", m,
               *(["--watch-rva", sink_rva()] if bk == "watch" else []), "--",
               tgt("hitcost_target.exe"), "--no-wait", "--calls", n, "--threads", threads]
    rc, wall, logs, objs = run_to_file(side, cmd, 900)
    ns = first(objs, "target").get("ns_per_call")
    res = {"rc": rc, "ns_per_call": ns, "calls": n, "threads": threads, "wall_s": round(wall, 3),
           "hits_per_s": (n * threads) / (ns * n / 1e9) if ns else None}
    if bk == "base":
        res["ok"] = rc == 0 and ns is not None
        return res
    rep, pr = first(objs, "probe_report"), first(objs, "probe")
    want_logs = n * threads if m in ("send_log", "send_log_stack") else 0
    res.update(hits=pr.get("hits"), logs=logs, dropped=rep.get("log_dropped"),
               ok=rc == 0 and ns is not None and pr.get("hits") == n * threads and logs == want_logs
               and rep.get("log_dropped", 0) == 0)
    return res


SINK_CALLS = {"inline": 2_000_000, "hw": 20_000, "breakpoint": 20_000}


def case_sink(side, bk, sink):
    n = SINK_CALLS[bk]
    cmd = [side.exe("hitcost_driver.exe"), "--backend", bk, "--method", "send_log", "--",
           tgt("hitcost_target.exe"), "--no-wait", "--calls", n, "--threads", 1]
    cmd = [str(c) for c in cmd]
    t0 = time.perf_counter()
    if sink == "nul":
        p = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=side.env, timeout=900)
        wall, logs, rc = time.perf_counter() - t0, None, p.returncode
    elif sink == "file":
        rc, wall, logs, objs = run_to_file(side, cmd, 900)
    else:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=side.env)
        logs, buf = 0, b""
        while True:
            chunk = p.stdout.read1(1 << 20)
            if not chunk:
                break
            buf += chunk
            logs += buf.count(b'{"kind":"probe_log"')
            buf = buf[buf.rfind(b"\n") + 1:]
        rc = p.wait(timeout=600)
        wall = time.perf_counter() - t0
    return {"rc": rc, "ok": rc == 0 and logs in (None, n), "logs": logs, "wall_s": round(wall, 3),
            "logs_per_s": n / wall}


def pct(vals, q):
    v = sorted(vals)
    return v[max(0, min(len(v) - 1, int(round(q * len(v) + 0.5)) - 1))] if v else None


def case_latency(side, bk):
    n = 50
    cmd = [side.exe("uhh_trace.exe"), "--backend", bk, "-p", "logstream_target.exe!LogSite:d", "--",
           tgt("logstream_target.exe")]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=side.env)
    ticks, logs, order = {}, {}, []
    rx = re.compile(rb'"message":"LogSite\((-?\d+)\)"')
    for line in p.stdout:
        now = qpc()
        if line.startswith(b'{"kind":"tick"'):
            o = json.loads(line); ticks[o["i"]] = o.get("t")
        elif line.startswith(b'{"kind":"probe_log"'):
            m = rx.search(line)
            if m:
                i = int(m.group(1)); order.append(i); logs.setdefault(i, now)
    rc = p.wait(timeout=120)
    lat = [(logs[i] - ticks[i + 1]) * 1000.0 / QPF for i in range(n) if i in logs and (ticks.get(i + 1) or 0) > 0]
    return {"rc": rc, "ok": rc == 0 and len(lat) == n and order == list(range(n)),
            "p50_ms": pct(lat, .5), "p99_ms": pct(lat, .99), "max_ms": max(lat) if lat else None, "n": len(lat)}


LIVE_CALLS = {"inline": 2_000_000, "hw": 50_000, "breakpoint": 50_000}


def case_live(side, bk):
    n = LIVE_CALLS[bk]
    p = subprocess.Popen([side.exe("hitcost_driver.exe"), "--backend", bk, "--method", "send_log", "--",
                          tgt("hitcost_target.exe"), "--calls", str(n), "--threads", "1", "--no-wait", "--qpc-arg"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=side.env)
    rx = re.compile(rb'"message":"hit (-?\d+)"')
    lags, logs, before, exited, buf = [], 0, 0, False, b""
    while True:
        chunk = p.stdout.read1(1 << 20)
        if not chunk:
            break
        now = qpc(); now_us = (now // QPF) * 1_000_000 + (now % QPF) * 1_000_000 // QPF
        buf += chunk
        lines = buf.split(b"\n"); buf = lines.pop()
        for line in lines:
            if line.startswith(b'{"kind":"probe_log"'):
                logs += 1
                if not exited:
                    before += 1
                if logs % 64 == 0:
                    m = rx.search(line)
                    if m:
                        lags.append(((now_us - int(m.group(1))) & 0x7FFFFFFF) / 1000.0)
            elif line.startswith(b'{"kind":"target"'):
                exited = True
    rc = p.wait(timeout=600)
    return {"rc": rc, "ok": rc == 0 and logs == n, "logs": logs, "lag_p50_ms": pct(lags, .5),
            "lag_p99_ms": pct(lags, .99), "lag_max_ms": max(lags) if lags else None,
            "before_exit": before / logs if logs else 0}


def _lifecycle(side, cmd):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, env=side.env, timeout=120)
    o = next((json.loads(l) for l in r.stdout.splitlines() if l.startswith(b'{"kind":"lifecycle"')), {})
    return r.returncode, o


def case_attach(side, bk, mode):
    busy = mode == "busy"
    args = [tgt("hitcost_target.exe"), "--calls", str(10**12 if busy else 1000)] + (["--no-wait"] if busy else [])
    tp = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        tp.stdout.readline()            # {"kind":"waiting"}: the process is up
        time.sleep(0.3)
        t0 = time.perf_counter()
        rc, o = _lifecycle(side, [side.exe("lifecycle_bench.exe"), "--backend", bk, "--attach", tp.pid,
                                  "--hold-ms", 300])
        wall = time.perf_counter() - t0
        if busy:
            time.sleep(0.3)
            alive = tp.poll() is None   # still looping on its own
            after_ok = alive
        else:
            tp.stdin.write(b"\n"); tp.stdin.flush()
            rest = tp.stdout.read()
            after_ok = tp.wait(timeout=60) == 0 and b'"kind":"target"' in rest
    finally:
        if tp.poll() is None:
            tp.kill(); tp.wait()
    o.update({"rc": rc, "ok": rc == 0 and o.get("ok") == 1 and after_ok, "wall_s": round(wall, 3)})
    return o


def case_launch(side, bk):
    if bk == "base":
        t0 = time.perf_counter()
        r = subprocess.run([tgt("hitcost_target.exe"), "--no-wait", "--calls", "1000"], capture_output=True, timeout=60)
        return {"rc": r.returncode, "ok": r.returncode == 0, "wall_s": time.perf_counter() - t0}
    t0 = time.perf_counter()
    rc, o = _lifecycle(side, [side.exe("lifecycle_bench.exe"), "--backend", bk, "--",
                              tgt("hitcost_target.exe"), "--no-wait", "--calls", 1000])
    o.update({"rc": rc, "ok": rc == 0 and o.get("ok") == 1, "wall_s": time.perf_counter() - t0})
    return o


GATED_READS = {"base": 50_000, "inline": 50_000, "hw": 4_000, "breakpoint": 4_000}


def case_gated(side, bk):
    r = GATED_READS[bk]; total = 8 * r
    if bk == "base":
        cmd = [tgt("probe_app.exe"), "--no-wait", "--config", "reads_enabled=1", "--helpers", 4,
               "--threads", 8, "--reads", r]
    else:
        cmd = [side.exe("gated_config.exe"), "--flag-backend", "breakpoint", "--read-backend", bk, FLAG, READ, "--",
               tgt("probe_app.exe"), "--no-wait", "--helpers", 4, "--threads", 8, "--reads", r]
    rc, wall, logs, objs = run_to_file(side, cmd, 900)
    a = first(objs, "app")
    rd = next((x for x in kind(objs, "probe") if x.get("location") == READ), {})
    dropped = first(objs, "probe_report").get("log_dropped")
    ok = rc == 0 and a.get("successful_reads") == total
    if bk != "base":
        ok = ok and rd.get("hits", 0) >= total and logs >= total and dropped == 0
    return {"rc": rc, "ok": ok, "elapsed_ns": a.get("elapsed_ns"), "wall_s": round(wall, 3),
            "reads": a.get("successful_reads"), "hits": rd.get("hits"), "logs": logs, "dropped": dropped,
            "ns_per_read": a.get("elapsed_ns") / total if a.get("elapsed_ns") else None}


def all_cases(group):
    """core: the owner's per-probe-type time table + attach/detach. extra: the rest."""
    c = []
    if group in ("core", "all"):
        for t in (1, 4):
            c += [(f"hit/base/empty/t{t}", (lambda t: lambda s: case_hit(s, "base", None, t))(t))]
            c += [(f"hit/{bk}/{m}/t{t}", (lambda bk, m, t: lambda s: case_hit(s, bk, m, t))(bk, m, t))
                  for bk in HIT_BACKENDS for m in ("empty", "send_log")]
        c += [(f"attach/{bk}/{m}", (lambda bk, m: lambda s: case_attach(s, bk, m))(bk, m))
              for bk in BACKENDS for m in ("idle", "busy")]
    if group in ("extra", "all"):
        c += [(f"hit/{bk}/{m}/t1", (lambda bk, m: lambda s: case_hit(s, bk, m, 1))(bk, m))
              for bk in BACKENDS for m in METHODS[2:]]
        c += [(f"hit/{bk}/empty/t8", (lambda bk: lambda s: case_hit(s, bk, "empty", 8))(bk))
              for bk in ["base"] + BACKENDS]
        c += [(f"sink/inline/{k}", (lambda k: lambda s: case_sink(s, "inline", k))(k)) for k in ("nul", "file", "pipe")]
        c += [(f"latency/{bk}/idle", (lambda bk: lambda s: case_latency(s, bk))(bk)) for bk in BACKENDS]
        c += [(f"live/{bk}/load", (lambda bk: lambda s: case_live(s, bk))(bk)) for bk in BACKENDS]
        c += [("launch/base/-", lambda s: case_launch(s, "base"))]
        c += [(f"launch/{bk}/-", (lambda bk: lambda s: case_launch(s, bk))(bk)) for bk in BACKENDS]
        c += [(f"gated/{bk}/8x{GATED_READS[bk]}", (lambda bk: lambda s: case_gated(s, bk))(bk))
              for bk in ["base"] + BACKENDS]
    return c


def main():
    global T
    ap = argparse.ArgumentParser()
    ap.add_argument("--side", action="append", required=True, metavar="NAME=RELEASE_DIR",
                    help="a build to measure (repeat; the first is the reference)")
    ap.add_argument("--targets", required=True)
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tmp", default=r"C:\work\uhh-perf-tmp")
    ap.add_argument("--only", default=""); ap.add_argument("--skip", default="")
    ap.add_argument("--tag", default="")
    ap.add_argument("--group", default="core", choices=("core", "extra", "all"))
    a = ap.parse_args()
    T = Path(a.targets)
    sides = {}
    for spec in a.side:
        n, d = spec.split("=", 1)
        sides[n] = Side(n, d, Path(a.tmp) / n)
    names = list(sides)
    cases = all_cases(a.group)
    if a.only:
        cases = [c for c in cases if any(x in c[0] for x in a.only.split(","))]
    if a.skip:
        cases = [c for c in cases if not any(x in c[0] for x in a.skip.split(","))]
    print(f"{len(cases)} cases x {a.rounds} rounds x {len(names)} sides {names}", flush=True)
    with open(a.out, "a") as out:
        for r in range(a.rounds):
            for name, fn in cases:
                # rotate the order every round (A,B,C / B,C,A / C,A,B ...) and reverse it in odd
                # rounds, so no side always runs first or right after the same other side
                k = r % len(names)
                order = names[k:] + names[:k]
                for sn in (order if r % 2 == 0 else order[::-1]):
                    side = sides[sn]
                    q = wait_quiet()
                    i0, t0 = _systimes()
                    try:
                        res = fn(side)
                    except Exception as e:
                        res = {"ok": False, "error": repr(e)}
                    i1, t1 = _systimes()
                    side.clean()
                    res.update(q, run_busy=round(100.0 * (1 - (i1 - i0) / max(1, t1 - t0)), 1))
                    rec = {"tag": a.tag, "round": r, "case": name, "side": sn, **res}
                    out.write(json.dumps(rec) + "\n"); out.flush()
                    short = {k: (round(v, 2) if isinstance(v, float) else v) for k, v in res.items()
                             if k in ("ok", "ns_per_call", "hits_per_s", "logs_per_s", "p50_ms", "p99_ms",
                                      "lag_p50_ms", "lag_p99_ms", "attach_ms", "detach_ms", "launch_ms",
                                      "total_ms", "elapsed_ns", "wall_s", "pre_busy", "error")}
                    print(f"r{r} {name} {sn} {short}", flush=True)


if __name__ == "__main__":
    main()
