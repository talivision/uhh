#!/usr/bin/env python3
"""The full gated_config example in UHH and in Frida, same probe_app workload: time AND correctness.

  <frida python> bench\\frida\\gated_full.py --rel build-x64\\Release [--threads 8 --reads 50000 --repeats 3]
                 [--tools uhh-inline,uhh-hw,uhh-breakpoint,frida] [--out results.jsonl]

Both do the whole example: the config ships reads_enabled=0 and is flipped when parsed; a
handle -> pid map is built at ntdll!NtOpenProcess (and forgotten at NtClose); EVERY
ntdll!NtReadVirtualMemory call is logged as one record with its handle, pid, address and size,
delivered to the host.
  UHH:   gated_config --flag-backend breakpoint --read-backend <bk> (the open/close probes on the
         read backend, as the example ships) launching probe_app; records = its probe_log lines.
  Frida: attach to probe_app at its gate (before the config is parsed and the helpers opened),
         load gated_full.js, release the gate; records arrive in batches over send().
Ground truth: probe_app's {"kind":"opened","pid","handle"} lines. A read is the workload's if
its handle is one of those; it is CORRECT if its record carries that handle's pid. Reported:
records of the workload's reads (must equal W x R), wrong pids, records with no pid, the
in-target read window (elapsed_ns, the same clock bench_matrix uses), and the wall time
(process start -> last record in the host).
"""
import argparse, json, re, statistics, subprocess, sys, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
FLAG = "configparse.dll!ParseConfig+0x16"
READ = "ntdll.dll!NtReadVirtualMemory"


def check(records, opened, total):
    """records: iterable of (handle:int, pid:int). opened: {handle: pid}."""
    work = wrong = nopid = other = 0
    for h, pid in records:
        want = opened.get(h)
        if want is None:
            other += 1
        else:
            work += 1
            if pid == 0:
                nopid += 1
            elif pid != want:
                wrong += 1
    return {"records": work, "wrong_pid": wrong, "no_pid": nopid, "other_reads": other,
            "exact": work == total and wrong == 0 and nopid == 0}


def run_uhh(rel, bk, W, R, tmp):
    out = tmp / f"gated_full_uhh_{bk}.out"
    cmd = [str(rel / "gated_config.exe"), "--flag-backend", "breakpoint", "--read-backend", bk, FLAG, READ, "--",
           str(rel / "probe_app.exe"), "--no-wait", "--helpers", "4", "--threads", str(W), "--reads", str(R)]
    t0 = time.perf_counter()
    with open(out, "wb") as f:
        p = subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, timeout=1800)
    wall = time.perf_counter() - t0
    rx = re.compile(rb'"message":"read handle=0x([0-9a-fA-F]+) pid=(\d+) ')
    opened, recs, app, rep = {}, [], {}, {}
    with open(out, "rb") as f:
        for line in f:
            if line.startswith(b'{"kind":"probe_log"'):
                m = rx.search(line)
                if m:
                    recs.append((int(m.group(1), 16), int(m.group(2))))
            elif line.startswith(b'{"kind":"opened"'):
                o = json.loads(line); opened[int(o["handle"])] = int(o["pid"])
            elif line.startswith(b'{"kind":"app"'):
                app = json.loads(line)
            elif line.startswith(b'{"kind":"probe_report"'):
                rep = json.loads(line)
    out.unlink()
    res = check(recs, opened, W * R)
    res.update(rc=p.returncode, wall_s=round(wall, 3), elapsed_ns=app.get("elapsed_ns"),
               reads=app.get("successful_reads"), checksum=app.get("checksum"), dropped=rep.get("log_dropped"))
    return res


def run_frida(rel, W, R, timeout=600):
    import frida
    src = (HERE / "gated_full.js").read_text(encoding="utf-8")
    t0 = time.perf_counter()
    proc = subprocess.Popen([str(rel / "probe_app.exe"), "--helpers", "4", "--threads", str(W), "--reads", str(R)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    recs, done, last = [], {}, [t0]
    got_done = threading.Event()
    sess = scr = None
    lines = []
    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                raise RuntimeError("frida: probe_app ended before its gate")
            if b'"kind":"waiting"' in line:
                break
        sess = frida.attach(proc.pid)
        scr = sess.create_script(src)

        def on_msg(m, data):
            if m.get("type") != "send":
                if m.get("type") == "error":
                    print("  frida script error:", m.get("description"), flush=True)
                return
            pl = m["payload"]
            if pl.get("type") == "recs":
                for l in pl["text"].split("\n"):
                    h, pid, _a, _s = l.split(" ")
                    recs.append((int(h, 16), int(pid)))
                last[0] = time.perf_counter()
            elif pl.get("type") == "done":
                done.update(pl); last[0] = time.perf_counter()
                scr.post({"type": "ack"})
                got_done.set()
        scr.on("message", on_msg)
        scr.load()
        proc.stdin.write(b"x"); proc.stdin.flush()
        rest = proc.stdout.read()                # until probe_app exits
        lines = rest.splitlines()
        proc.wait(timeout=timeout)
        got_done.wait(10)
    finally:
        for f in ((lambda: scr.unload()) if scr else None, (lambda: sess.detach()) if sess else None):
            if f:
                try: f()
                except Exception: pass
        if proc.poll() is None:
            proc.kill(); proc.wait()
    opened, app = {}, {}
    for line in lines:
        if line.startswith(b'{"kind":"opened"'):
            o = json.loads(line); opened[int(o["handle"])] = int(o["pid"])
        elif line.startswith(b'{"kind":"app"'):
            app = json.loads(line)
    res = check(recs, opened, W * R)
    res.update(rc=proc.returncode, wall_s=round(last[0] - t0, 3), elapsed_ns=app.get("elapsed_ns"),
               reads=app.get("successful_reads"), checksum=app.get("checksum"), frida_done=done)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rel", type=Path, required=True)
    ap.add_argument("--threads", type=int, default=8); ap.add_argument("--reads", type=int, default=50000)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--tools", default="uhh-inline,frida")
    ap.add_argument("--out", type=Path, default=None); ap.add_argument("--tag", default="")
    a = ap.parse_args()
    rel = a.rel.resolve(); tmp = rel / "gated_full_tmp"; tmp.mkdir(exist_ok=True)
    tools = a.tools.split(",")
    rows = []
    for i in range(a.repeats):
        for t in (tools if i % 2 == 0 else tools[::-1]):
            try:
                r = run_frida(rel, a.threads, a.reads) if t == "frida" else run_uhh(rel, t.split("-", 1)[1], a.threads, a.reads, tmp)
            except Exception as e:
                r = {"exact": False, "error": repr(e)}
            r.update(tool=t, repeat=i, tag=a.tag, threads=a.threads, reads_per_thread=a.reads)
            rows.append(r)
            print(json.dumps(r), flush=True)
            if a.out:
                with open(a.out, "a") as f:
                    f.write(json.dumps(r) + "\n")
    print("summary:")
    for t in tools:
        rs = [r for r in rows if r["tool"] == t and r.get("elapsed_ns")]
        if not rs:
            print(f"  {t}: no successful run"); continue
        med = lambda k: statistics.median(r[k] for r in rs)
        print(f"  {t}: elapsed {med('elapsed_ns') / 1e6:.1f} ms ({med('elapsed_ns') / (a.threads * a.reads):.0f} ns/read) "
              f"wall {med('wall_s'):.2f} s  exact {sum(r['exact'] for r in rs)}/{len(rs)}  "
              f"records {[r['records'] for r in rs]} wrong {[r['wrong_pid'] for r in rs]} nopid {[r['no_pid'] for r in rs]}",
              flush=True)


if __name__ == "__main__":
    main()
