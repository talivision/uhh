#!/usr/bin/env python3
"""UHH vs current Frida (17.26+), same workloads, same machine, same clocks, exact correctness.

  <python with frida 17.26+> bench\\frida\\vs_frida.py --rel build-x64\\Release --arch x64
        [--workloads count,gated,churn,hit] [--methods <substrings>] [--repeats 3]
        [--threads 8 --reads 50000 --rounds 2000 --calls 200000] [--out rows.jsonl]

Workloads (every method on the SAME target binary and arguments):
  count  probe_app (reads enabled by config), W threads x R reads through
         ntdll!NtReadVirtualMemory. One probe there; its callback reads argument 0 and argument 3
         and bumps a counter. No logging. Per-event cost.
           uhh-inline / uhh-hw / uhh-breakpoint   uhh_count.exe --backend <b>
           frida-js / frida-js-v8                 agents/count_js.js (Interceptor, JS onEnter; QuickJS / V8)
           frida-cmodule                          agents/count_cmodule.js (Interceptor, C onEnter)
           frida-hw                               agents/count_hw.js (hardware breakpoint on every thread)
  gated  the whole examples/gated_config on probe_app (config ships DISABLED): flag flipped at
         configparse.dll!ParseConfig+0x16, handle -> pid -> name map at NtOpenProcess (NtClose
         forgets), EVERY NtReadVirtualMemory logged with its pid and name and delivered to the host.
         Exact: every workload read has a record with the right pid and name (probe_app's own
         {"kind":"opened"} lines), exactly one flag flip, nothing dropped.
           uhh-inline / uhh-hw / uhh-breakpoint   gated_config.exe (flag: breakpoint; open/close/read: <b>)
           frida-js / frida-js-v8 / frida-cmodule agents/gated_js.js, agents/gated_cmodule.js
  churn  the same tools on probe_app --churn --truth (regress gated-e2e's ground truth): helpers
         opened / read / closed over and over from W threads, handle values reused for different
         pids, reads through duplicated handles the map never saw. Exact: per thread, the delivered
         open/map/read sequence equals the target's own record, in order.
  hit    hitcost_target: one thread calls hit_site() N times; empty-work counting probe there (or
         a write watchpoint on the global it updates). The bare per-hit cost of each mechanism.
           uhh-inline / uhh-hw / uhh-breakpoint / uhh-watch, frida-js / frida-js-v8 / frida-cmodule /
           frida-hw / frida-watch

Every Frida method SPAWNS the target (frida's equivalent of UHH's launch): spawn suspended, load
the agent, resume. Clocks: the target's own QueryPerformanceCounter window (probe_app elapsed_ns,
hitcost ns_per_call: the same field for every method) and the host's wall time from launch to
the last record delivered. Rows go to --out (JSON lines); a summary (median, min..max) is printed.
"""
import argparse, collections, json, os, re, statistics, struct, subprocess, sys, tempfile, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
AGENTS = HERE / "agents"
FLAG = "configparse.dll!ParseConfig+0x16"
READ = "ntdll.dll!NtReadVirtualMemory"
HELPERS = 4

COUNT_METHODS = ["baseline", "uhh-inline", "uhh-hw", "uhh-breakpoint", "frida-js", "frida-js-v8", "frida-cmodule", "frida-hw"]
GATED_METHODS = ["baseline", "uhh-inline", "uhh-hw", "uhh-breakpoint", "frida-js", "frida-js-v8", "frida-cmodule"]
CHURN_METHODS = ["baseline", "uhh-inline", "uhh-hw", "uhh-breakpoint", "frida-js", "frida-js-v8", "frida-cmodule"]
HIT_METHODS = ["baseline", "uhh-inline", "uhh-hw", "uhh-breakpoint", "uhh-watch",
               "frida-js", "frida-js-v8", "frida-cmodule", "frida-hw", "frida-watch"]


def json_lines(blob):
    for line in blob.splitlines():
        if line.startswith(b"{"):
            try:
                yield json.loads(line)
            except ValueError:
                pass


def kind(objs, k):
    return [o for o in objs if o.get("kind") == k]


def one(objs, k):
    xs = kind(objs, k)
    return xs[-1] if xs else {}


# ----------------------------------------------------------------------------------- Frida
def frida_run(argv, agent, params, runtime="qjs", timeout=900):
    """Spawn argv suspended, load prelude.js + agent with PARAMS, resume, collect every message
    until the agent's exit handshake ('done'), and the target's stdout. Returns a dict."""
    import frida
    src = ("const PARAMS = " + json.dumps(params) + ";\n" + (AGENTS / "prelude.js").read_text(encoding="utf-8") +
           "\n" + (AGENTS / agent).read_text(encoding="utf-8"))
    dev = frida.get_local_device()
    out, recs, errors, done = [], [], [], {}
    ready, got_done, detached = threading.Event(), threading.Event(), threading.Event()
    last = [0.0]
    pid_box = [None]
    script = [None]
    detach_reason = [None]

    def on_output(pid, fd, data):
        if pid == pid_box[0] and fd == 1 and data:
            out.append(data)

    def on_message(m, data):
        if m.get("type") == "error":
            errors.append((m.get("description") or "") + " " + (m.get("stack") or "")[:300])
            ready.set()
            return
        if m.get("type") != "send":
            return
        p = m["payload"]
        t = p.get("type") if isinstance(p, dict) else None
        if t in ("recs", "bin"):
            recs.append((p, data))
            last[0] = time.perf_counter()
        elif t == "ready":
            ready.set()
        elif t == "done":
            done.update(p)
            last[0] = time.perf_counter()
            got_done.set()
            script[0].post({"type": "ack"})

    dev.on("output", on_output)
    t0 = time.perf_counter()
    sess = None
    try:
        pid = dev.spawn([str(a) for a in argv], stdio="pipe")
        pid_box[0] = pid
        sess = dev.attach(pid)
        sess.on("detached", lambda reason, crash: (detach_reason.__setitem__(0, f"{reason} {crash}" if crash else reason),
                                                   detached.set()))
        script[0] = sess.create_script(src, runtime=runtime)
        script[0].on("message", on_message)
        script[0].load()
        if not ready.wait(60) or errors:
            raise RuntimeError(f"agent not ready: {errors[:2]}")
        t_resume = time.perf_counter()
        dev.resume(pid)
        deadline = time.perf_counter() + timeout
        while not got_done.wait(0.5):
            if detached.is_set():                  # the target is gone without the exit handshake
                time.sleep(2)
                if got_done.is_set():
                    break
                tail = b"".join(out)[-400:].decode("utf-8", "replace")
                raise RuntimeError(f"target ended without the exit handshake: detach={detach_reason[0]} "
                                   f"errors={errors[:2]} stdout tail={tail!r}")
            if time.perf_counter() > deadline:
                raise RuntimeError(f"no exit handshake within {timeout} s (errors={errors[:2]})")
        detached.wait(30)
        for _ in range(100):                       # the target's last stdout lines arrive asynchronously
            if any(b'"kind":"app"' in c or b'"kind":"target"' in c for c in out):
                break
            time.sleep(0.05)
        return {"recs": recs, "done": done, "stdout": b"".join(out), "errors": errors,
                "wall_s": last[0] - t0, "attach_s": t_resume - t0, "detach": detach_reason[0]}
    finally:
        try:
            dev.off("output", on_output)
        except Exception:
            pass
        if pid_box[0] is not None and not detached.is_set():
            try:
                dev.kill(pid_box[0])
            except Exception:
                pass


REC = struct.Struct("<IIII QQQQ 32s")


def frida_records(recs):
    """(tid, message) for every delivered record, in delivery order; the CModule's binary
    records are rendered as the same text UHH's callbacks log."""
    for p, data in recs:
        if p["type"] == "recs":
            for line in p["text"].split("\n"):
                tid, msg = line.split("\t", 1)
                yield int(tid), msg
        else:
            mv = memoryview(data)
            for k in range(p["n"]):
                _, tid, kd, _, h, pid, addr, size, name = REC.unpack_from(mv, k * REC.size)
                name = name.split(b"\0", 1)[0].decode("ascii", "replace")
                if kd == 1:
                    yield tid, f"read handle=0x{h:x} pid={pid} name={name} addr=0x{addr:x} size={size}"
                else:
                    yield tid, f"open pid={pid} name={name}"
                    yield tid, f"map handle=0x{h:x} -> pid={pid} name={name}"


def frida_method(m):
    """method -> (runtime, count agent, gated agent)."""
    return {"frida-js": ("qjs", "count_js.js", "gated_js.js"),
            "frida-js-v8": ("v8", "count_js.js", "gated_js.js"),
            "frida-cmodule": ("qjs", "count_cmodule.js", "gated_cmodule.js"),
            "frida-hw": ("qjs", "count_hw.js", None),
            "frida-watch": ("qjs", "count_hw.js", None)}[m]


# ----------------------------------------------------------------------------------- UHH
def uhh_run(cmd, tmp, timeout=1800):
    outp = tmp / "uhh.out"
    t0 = time.perf_counter()
    with open(outp, "wb") as f:
        r = subprocess.run([str(c) for c in cmd], stdout=f, stderr=subprocess.PIPE, timeout=timeout)
    wall = time.perf_counter() - t0
    blob = outp.read_bytes()
    outp.unlink()
    return r.returncode, blob, r.stderr.decode("utf-8", "replace"), wall


def uhh_records(objs):
    for o in objs:
        if o.get("kind") == "probe_log":
            yield o.get("tid"), str(o.get("message", ""))


# ----------------------------------------------------------------------------------- judges
RX_READ = re.compile(r"read handle=0x([0-9a-f]+) pid=(\d+) name=(\S+) addr=0x([0-9a-f]+) size=(\d+)$")
RX_OPEN = re.compile(r"open pid=(\d+) name=(\S+)$")
RX_MAP = re.compile(r"map handle=0x([0-9a-f]+) -> pid=(\d+) name=(\S+)$")


def judge_volume(records, t_objs, total):
    """Every workload read (its handle is one probe_app opened) logged once, right pid + name."""
    opened = {int(o["handle"]): int(o["pid"]) for o in kind(t_objs, "opened")}
    work = wrong = nopid = other = foreign = 0
    for _tid, msg in records:
        m = RX_READ.match(msg)
        if not m:
            if not (RX_OPEN.match(msg) or RX_MAP.match(msg)):
                foreign += 1
            continue
        want = opened.get(int(m[1], 16))
        if want is None:
            other += 1
        elif int(m[2]) == 0:
            work += 1; nopid += 1
        else:
            work += 1
            if int(m[2]) != want or m[3].lower() != "probe_app.exe":
                wrong += 1
    return {"records": work, "wrong_pid": wrong, "no_pid": nopid, "other_reads": other, "foreign": foreign,
            "exact": work == total and wrong == 0 and nopid == 0 and foreign == 0 and len(opened) == HELPERS}


def judge_churn(records, t_objs, truth):
    """Per thread, the delivered open/map/read sequence == the target's own record."""
    helper_pids = {int(o["pid"]) for o in kind(t_objs, "helper")}
    want = collections.defaultdict(list)
    for e in truth:
        if e["op"] == "open":
            want[e["tid"]] += [("open", e["pid"], "probe_app.exe"), ("map", e["handle"], e["pid"], "probe_app.exe")]
        elif e["op"] == "read":
            want[e["tid"]].append(("read", e["handle"], e["pid"], "probe_app.exe", e["addr"], e["size"]))
        elif e["op"] == "read-unmapped":
            want[e["tid"]].append(("read", e["handle"], 0, "?", e["addr"], e["size"]))
    got, foreign, extra = collections.defaultdict(list), 0, 0
    for tid, msg in records:
        if (x := RX_OPEN.match(msg)):
            t = ("open", int(x[1]), x[2].lower())
        elif (x := RX_MAP.match(msg)):
            t = ("map", int(x[1], 16), int(x[2]), x[3].lower())
        elif (x := RX_READ.match(msg)):
            t = ("read", int(x[1], 16), int(x[2]), x[3].lower(), int(x[4], 16), int(x[5]))
        else:
            foreign += 1; continue
        if t[0] in ("open", "map") and t[1 if t[0] == "open" else 2] not in helper_pids:
            extra += 1; continue                    # an open of something else (none expected)
        got[tid].append(t)
    reads_want = sum(1 for seq in want.values() for t in seq if t[0] == "read")
    reads_got = sum(1 for seq in got.values() for t in seq if t[0] == "read")
    diff = [tid for tid in set(want) | set(got) if want.get(tid, []) != got.get(tid, [])]
    first = ""
    if diff:
        tid = diff[0]; w, g = want.get(tid, []), got.get(tid, [])
        i = next((k for k, (p, q) in enumerate(zip(w, g)) if p != q), min(len(w), len(g)))
        first = f"tid {tid} @{i}/{len(w)}: want {w[i:i + 1]} got {g[i:i + 1]}"
    return {"reads": reads_got, "reads_truth": reads_want, "threads_differ": len(diff), "foreign": foreign,
            "extra_opens": extra, "first_diff": first,
            "exact": not diff and foreign == 0 and reads_want == reads_got and reads_want > 0}


# ----------------------------------------------------------------------------------- runs
class Bench:
    def __init__(self, a):
        self.a, self.rel, self.tmp = a, a.rel.resolve(), Path(tempfile.mkdtemp(prefix="vsfrida-"))
        self.base = {}

    def exe(self, n):
        return self.rel / n

    def probe_args(self, *extra, enabled=False):
        return [self.exe("probe_app.exe"), "--no-wait", "--helpers", HELPERS, "--threads", self.a.threads,
                *(["--config", "reads_enabled=1"] if enabled else []), *extra]

    # --- count ---------------------------------------------------------------------------
    def count(self, m):
        a = self.a
        argv = self.probe_args("--reads", a.reads, enabled=True)
        total = a.threads * a.reads
        if m == "baseline":
            r = subprocess.run([str(x) for x in argv], capture_output=True, timeout=600)
            app = one(list(json_lines(r.stdout)), "app")
            return {"elapsed_ns": app.get("elapsed_ns"), "reads": app.get("successful_reads"),
                    "checksum": app.get("checksum"), "exact": app.get("successful_reads") == total, "rc": r.returncode}
        if m.startswith("uhh-"):
            rc, blob, err, wall = uhh_run([self.exe("uhh_count.exe"), "--backend", m[4:], "--", *argv], self.tmp)
            objs = list(json_lines(blob))
            app, rep = one(objs, "app"), one(objs, "probe_report")
            return {"elapsed_ns": app.get("elapsed_ns"), "reads": app.get("successful_reads"), "checksum": app.get("checksum"),
                    "calls": rep.get("hits"), "wall_s": round(wall, 3), "rc": rc,
                    "exact": rc == 0 and rep.get("hits") == total and app.get("successful_reads") == total,
                    "error": rep.get("error") or (err.strip()[-200:] if rc else None)}
        rt, agent, _ = frida_method(m)
        params = {"target": {"module": "ntdll.dll", "export": "NtReadVirtualMemory"}}
        r = frida_run(argv, agent, params, rt)
        app = one(list(json_lines(r["stdout"])), "app")
        calls = r["done"].get("calls")
        return {"elapsed_ns": app.get("elapsed_ns"), "reads": app.get("successful_reads"), "checksum": app.get("checksum"),
                "calls": calls, "wall_s": round(r["wall_s"], 3), "attach_s": round(r["attach_s"], 3),
                "armed": r["done"].get("armed"), "frida_errors": r["errors"][:2] + (r["done"].get("errors") or [])[:2],
                "exact": calls == total and app.get("successful_reads") == total}

    # --- gated (volume) ------------------------------------------------------------------
    def gated(self, m):
        a = self.a
        total = a.threads * a.reads
        if m == "baseline":
            r = subprocess.run([str(x) for x in self.probe_args("--reads", a.reads, enabled=True)], capture_output=True, timeout=600)
            app = one(list(json_lines(r.stdout)), "app")
            return {"elapsed_ns": app.get("elapsed_ns"), "reads": app.get("successful_reads"), "checksum": app.get("checksum"),
                    "exact": app.get("successful_reads") == total, "rc": r.returncode}
        argv = self.probe_args("--reads", a.reads)
        if m.startswith("uhh-"):
            b = m[4:]
            rc, blob, err, wall = uhh_run([self.exe("gated_config.exe"), "--flag-backend", "breakpoint", "--read-backend", b,
                                           "--open-backend", b, "--close-backend", b, FLAG, READ, "--", *argv], self.tmp)
            objs = list(json_lines(blob))
            app, rep = one(objs, "app"), one(objs, "probe_report")
            res = judge_volume(uhh_records(objs), objs, total)
            res.update(elapsed_ns=app.get("elapsed_ns"), reads=app.get("successful_reads"), checksum=app.get("checksum"),
                       wall_s=round(wall, 3), rc=rc, overrides=rep.get("overrides"), dropped=rep.get("log_dropped"),
                       logs=rep.get("logs_written"), error=rep.get("error") or (err.strip()[-200:] if rc else None))
            res["exact"] = res["exact"] and rc == 0 and rep.get("overrides") == 1 and rep.get("log_dropped") == 0
            return res
        rt, _, agent = frida_method(m)
        r = frida_run(argv, agent, {"batch": a.batch, "flushMs": a.flush_ms}, rt)
        t_objs = list(json_lines(r["stdout"]))
        app, d = one(t_objs, "app"), r["done"]
        res = judge_volume(frida_records(r["recs"]), t_objs, total)
        res.update(elapsed_ns=app.get("elapsed_ns"), reads=app.get("successful_reads"), checksum=app.get("checksum"),
                   wall_s=round(r["wall_s"], 3), attach_s=round(r["attach_s"], 3), overrides=d.get("overrides"),
                   hooked_reads=d.get("reads"), sent=d.get("sent"), batches=d.get("batches"), ring_waits=d.get("waits"),
                   frida_errors=r["errors"][:2])
        res["exact"] = res["exact"] and d.get("overrides") == 1 and d.get("sent") is not None
        return res

    # --- churn (exact against the target's own record) ------------------------------------
    def churn(self, m):
        a = self.a
        truth_p = self.tmp / "truth.jsonl"
        truth_p.unlink(missing_ok=True)
        argv = self.probe_args("--reads", a.rounds, "--churn", "--truth", truth_p, enabled=(m == "baseline"))
        if m == "baseline":
            t0 = time.perf_counter()
            r = subprocess.run([str(x) for x in argv], capture_output=True, timeout=600)
            wall = time.perf_counter() - t0
            app = one(list(json_lines(r.stdout)), "app")
            self.base["churn"] = app
            return {"wall_s": round(wall, 3), "reads": app.get("successful_reads"), "opens": app.get("opened"),
                    "checksum": app.get("checksum"), "exact": r.returncode == 0 and app.get("reads_enabled") == 1}
        if m.startswith("uhh-"):
            b = m[4:]
            rc, blob, err, wall = uhh_run([self.exe("gated_config.exe"), "--flag-backend", "breakpoint", "--read-backend", b,
                                           "--open-backend", b, "--close-backend", b, FLAG, READ, "--", *argv], self.tmp)
            objs = list(json_lines(blob))
            truth = [json.loads(l) for l in truth_p.read_text().splitlines() if l.strip()] if truth_p.exists() else []
            app, rep = one(objs, "app"), one(objs, "probe_report")
            res = judge_churn(uhh_records(objs), objs, truth)
            res.update(wall_s=round(wall, 3), rc=rc, overrides=rep.get("overrides"), dropped=rep.get("log_dropped"),
                       checksum_same=app.get("checksum") == self.base.get("churn", {}).get("checksum"),
                       error=rep.get("error") or (err.strip()[-200:] if rc else None))
            res["exact"] = res["exact"] and rc == 0 and rep.get("overrides") == 1 and rep.get("log_dropped") == 0 and res["checksum_same"]
            return res
        rt, _, agent = frida_method(m)
        r = frida_run(argv, agent, {"batch": a.batch, "flushMs": a.flush_ms}, rt)
        t_objs = list(json_lines(r["stdout"]))
        truth = [json.loads(l) for l in truth_p.read_text().splitlines() if l.strip()] if truth_p.exists() else []
        app, d = one(t_objs, "app"), r["done"]
        res = judge_churn(frida_records(r["recs"]), t_objs, truth)
        res.update(wall_s=round(r["wall_s"], 3), overrides=d.get("overrides"),
                   checksum_same=app.get("checksum") == self.base.get("churn", {}).get("checksum"), frida_errors=r["errors"][:2])
        res["exact"] = res["exact"] and d.get("overrides") == 1 and res["checksum_same"]
        return res

    # --- hit (bare per-hit cost) ---------------------------------------------------------------
    def hit(self, m):
        a = self.a
        argv = [self.exe("hitcost_target.exe"), "--no-wait", "--calls", a.calls]
        if m == "baseline":
            r = subprocess.run([str(x) for x in argv], capture_output=True, timeout=600)
            t = one(list(json_lines(r.stdout)), "target")
            return {"ns_per_call": t.get("ns_per_call"), "exact": r.returncode == 0}
        if "watch" in m and "sink_rva" not in self.base:
            r = subprocess.run([str(self.exe("hitcost_target.exe")), "--print-rva"], capture_output=True, timeout=60)
            self.base["sink_rva"] = one(list(json_lines(r.stdout)), "rva")["sink"]
        if m.startswith("uhh-"):
            b = m[4:]
            loc = f"hitcost_target.exe+0x{self.base['sink_rva']:x}" if b == "watch" else "hitcost_target.exe!hit_site"
            rc, blob, err, wall = uhh_run([self.exe("uhh_count.exe"), "--backend", b, "--location", loc, "--", *argv], self.tmp)
            objs = list(json_lines(blob))
            t, rep = one(objs, "target"), one(objs, "probe_report")
            return {"ns_per_call": t.get("ns_per_call"), "calls": rep.get("hits"), "wall_s": round(wall, 3), "rc": rc,
                    "exact": rc == 0 and rep.get("hits") == a.calls, "error": rep.get("error") or (err.strip()[-200:] if rc else None)}
        rt, agent, _ = frida_method(m)
        if m == "frida-watch":
            params = {"target": {"module": "hitcost_target.exe", "rva": self.base["sink_rva"]}, "kind": "watch"}
        else:
            params = {"target": {"module": "hitcost_target.exe", "export": "hit_site"}}
        r = frida_run(argv, agent, params, rt)
        t = one(list(json_lines(r["stdout"])), "target")
        calls = r["done"].get("calls")
        return {"ns_per_call": t.get("ns_per_call"), "calls": calls, "wall_s": round(r["wall_s"], 3),
                "armed": r["done"].get("armed"), "frida_errors": r["errors"][:2] + (r["done"].get("errors") or [])[:2],
                "exact": calls == a.calls}


def summarize(rows, a):
    print("summary (median [min..max] over the repeats; exact = runs with exact correctness / runs):", flush=True)
    by = collections.defaultdict(list)
    for r in rows:
        by[(r["workload"], r["method"])].append(r)
    base = {}
    for (w, m), rs in by.items():
        if m == "baseline":
            k = "ns_per_call" if w == "hit" else ("wall_s" if w == "churn" else "elapsed_ns")
            vals = [r[k] for r in rs if r.get(k) is not None]
            if vals:
                base[w] = statistics.median(vals)
    for (w, m), rs in by.items():
        ok = sum(1 for r in rs if r.get("exact"))
        if w == "hit":
            k, unit, n = "ns_per_call", "ns/call", 1
        elif w == "churn":
            k, unit, n = "wall_s", "s wall", 1
        else:
            k, unit, n = "elapsed_ns", "ns/read", a.threads * a.reads
        vals = [r[k] / n for r in rs if r.get(k) is not None]
        line = f"  {w:6} {m:15} exact {ok}/{len(rs)}"
        if vals:
            med = statistics.median(vals)
            line += f"  {med:,.1f} {unit} [{min(vals):,.1f}..{max(vals):,.1f}]"
            if w in base and m != "baseline":
                b = base[w] / n
                line += f"  added {med - b:+,.1f}  x{med / b:.1f}"
            walls = [r["wall_s"] for r in rs if r.get("wall_s") is not None]
            if walls and w != "churn":
                line += f"  wall {statistics.median(walls):.2f} s"
        bad = [r for r in rs if not r.get("exact")]
        if bad:
            b = bad[0]
            line += "  FIRST-BAD " + json.dumps({k: b.get(k) for k in ("records", "wrong_pid", "no_pid", "calls", "reads",
                                                                        "threads_differ", "first_diff", "error", "frida_errors",
                                                                        "overrides", "rc") if b.get(k) not in (None, [], "")})[:400]
        print(line, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rel", type=Path, required=True)
    ap.add_argument("--arch", default="x64")
    ap.add_argument("--workloads", default="count,gated,churn,hit")
    ap.add_argument("--methods", default="", help="comma substrings of method names (empty = all)")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--reads", type=int, default=50000)
    ap.add_argument("--rounds", type=int, default=2000, help="churn rounds per thread")
    ap.add_argument("--calls", type=int, default=200000, help="hit: calls of hit_site")
    ap.add_argument("--batch", type=int, default=4096)
    ap.add_argument("--flush-ms", type=int, default=20)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--tag", default="")
    a = ap.parse_args()
    try:
        import frida
        fv = frida.__version__
    except ImportError:
        fv = None
    print(f"vs_frida: frida {fv} python {sys.version.split()[0]} arch {a.arch} W={a.threads} R={a.reads} "
          f"rounds={a.rounds} calls={a.calls} repeats={a.repeats}", flush=True)
    b = Bench(a)
    sel = [s for s in a.methods.split(",") if s]
    plan = {"count": COUNT_METHODS, "gated": GATED_METHODS, "churn": CHURN_METHODS, "hit": HIT_METHODS}
    rows = []
    for w in a.workloads.split(","):
        ms = [m for m in plan[w] if m == "baseline" or not sel or any(s in m for s in sel)]
        if fv is None:
            ms = [m for m in ms if not m.startswith("frida")]
        for i in range(a.repeats):
            order = ms if i % 2 == 0 else [ms[0]] + ms[:0:-1]      # baseline first (churn needs it), then alternate
            for m in order:
                t0 = time.perf_counter()
                try:
                    r = getattr(b, w)(m)
                except Exception as e:
                    r = {"exact": False, "error": repr(e)[:400]}
                r.update(workload=w, method=m, repeat=i, arch=a.arch, frida=fv, tag=a.tag, threads=a.threads,
                         reads_per_thread=a.reads, rounds=a.rounds, calls_n=a.calls, run_s=round(time.perf_counter() - t0, 2))
                rows.append(r)
                print(json.dumps(r), flush=True)
                if a.out:
                    with open(a.out, "a") as f:
                        f.write(json.dumps(r) + "\n")
    summarize(rows, a)


if __name__ == "__main__":
    main()
