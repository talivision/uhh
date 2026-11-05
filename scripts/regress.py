#!/usr/bin/env python3
"""UHH regression suite — one command, asserts every behaviour we rely on.

    regress.py --bin build-x64/Release [--threads 8] [--reads 2000]

Run it against each build directory (x64 and x86). Every check is independent, has a
timeout, and asserts a concrete expected result; the script prints PASS/FAIL per check
and exits non-zero if ANY check fails, so it catches regressions without re-deriving
the checks by hand. Store-and-run this instead of ad-hoc scripts.

Checks:
  - sites: the hard-coded flag location configparse.dll!ParseConfig+0x16 is exactly the
    ParsedFlagSite of the linker map (the offset is fixed by the asm, on both arches).
  - gated-off: probe_app alone runs 0 opens and 0 reads (feature off in the shipped config).
  - mix matrix: flag x read over {breakpoint, inline, hw}; exactly one override and the
    read probe's hit count equals the reads (flag=inline exercises the HW fallback).
  - multithread exact: each read backend at >cores threads -> hits == threads*reads,
    the no-dropped-events guarantee -- and one formatted log per hit, log_dropped == 0
    (the no-dropped-LOGS guarantee; inline logs cross a shared ring the controller drains),
    and every logged read carries the helper pid mapped at probe_app.exe!OpenThunk.
  - attach-<backend>: probe_app started on its own (waiting at its gate); uhh_attach
    attaches, flips the flag, and logs only one helper's reads in one range. Exactly the
    predicted number of reads is logged, every read is still counted, nothing dropped.
  - log-throughput-<backend>: per-log overhead (logging run vs --no-log run) under a
    ceiling, so logging getting slow fails like any other regression.
  - stream-volume/latency/order: logs are emitted promptly, losslessly and in per-thread
    order through a bounded-memory controller queue, including a 20M inline-log run.
  - stream-sink-speed: inline 2M logging rate with stdout at NUL and at a disk file.
  - breakage: the hostile fixtures produce their expected verdicts.
  - frida-parity: the four Interceptor-parity demos all pass.
  - watchpoint: a hardware write-watchpoint fires once per store.
  - dynwatch-<entry>: the malloc -> return -> watch chain registered at runtime from
    inside callbacks (entry probe as breakpoint / hw / inline; inline exercises the
    agent->controller IPC). Exact hit count across two threads (one created after the
    watch is armed), one-shot return probe retired, and a symbolized stack in the log.
Missing binaries (an example not built) are reported as SKIP, not FAIL.
"""
import argparse
import json
import math
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

BIN = None
RESULTS = []  # (name, status, detail)


def run(args, timeout=180, feed=None):
    r = subprocess.run([str(a) for a in args], capture_output=True, text=True,
                       timeout=timeout, input=feed)
    objs = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return r, objs


def stream_run(args, timeout, on_line):
    """Drain stdout incrementally so volume checks never retain probe_log records."""
    proc = subprocess.Popen([str(a) for a in args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
    timed_out = threading.Event()

    def drain_stderr():
        for line in proc.stderr:
            marker = "probe: logs -> "
            if line.startswith(marker):
                try:
                    Path(line[len(marker):].strip()).unlink()
                except OSError:
                    pass

    stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
    stderr_thread.start()

    def expire():
        timed_out.set()
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass

    timer = threading.Timer(timeout, expire)
    timer.daemon = True
    timer.start()
    try:
        for line in proc.stdout:
            on_line(line.rstrip("\r\n"), time.perf_counter())
        proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait()
        stderr_thread.join(timeout=30)
    return proc.returncode, timed_out.is_set()


def rvas(map_name, *syms):
    out = subprocess.check_output(
        [sys.executable, str(Path(__file__).with_name("site_rvas.py")),
         str(BIN / map_name), *syms], text=True)
    return json.loads(out)


def exe(name):
    p = BIN / name
    return p if p.exists() else None


def record(name, ok, detail=""):
    RESULTS.append((name, "PASS" if ok else "FAIL", detail))


def skip(name, why):
    """A check that could not run. A missing binary is a FAILURE (a partial build must never
    look green); only a check that does not apply to this build (e.g. x86-only) is a SKIP,
    and a SKIP is never counted as a pass."""
    status = "FAIL" if "missing" in why else "SKIP"
    RESULTS.append((name, status, why))


def probes(objs):
    return [o for o in objs if o.get("kind") == "probe"]


def report(objs):
    for o in objs:
        if o.get("kind") == "probe_report":
            return o
    return {}


def app(objs):
    for o in objs:
        if o.get("kind") == "app":
            return o
    return {}


FLAG_LOCATION = "configparse.dll!ParseConfig+0x16"
READ_LOCATION = "ntdll.dll!NtReadVirtualMemory"
OPEN_LOCATION = "ntdll.dll!NtOpenProcess"
HELPERS = 4


def check_sites():
    try:
        r = rvas("configparse.map", "ParseConfig", "ParsedFlagSite")
        off = r["ParsedFlagSite"] - r["ParseConfig"]
        record("sites", off == 0x16, f"ParsedFlagSite = ParseConfig+{off:#x} (hard-coded +0x16)")
    except Exception as e:
        record("sites", False, repr(e))


def check_gated_off():
    p = exe("probe_app.exe")
    if not p:
        return skip("gated-off", "probe_app.exe missing")
    try:
        r, o = run([p, "--no-wait", "--helpers", HELPERS, "--threads", "4", "--reads", "200"], timeout=60)
        a = app(o)
        ok = (r.returncode == 0 and a.get("reads_enabled") == 0 and a.get("opened") == 0
              and a.get("successful_reads") == 0)
        record("gated-off", ok, f"reads_enabled={a.get('reads_enabled')} opened={a.get('opened')} "
                                f"reads={a.get('successful_reads')}")
    except Exception as e:
        record("gated-off", False, repr(e))


def gated(flag_bk, read_bk, threads, reads, timeout=200, log=True, open_bk=None):
    return run([exe("gated_config.exe"), "--flag-backend", flag_bk, "--read-backend", read_bk,
                *(["--open-backend", open_bk] if open_bk else []),
                *([] if log else ["--no-log"]), FLAG_LOCATION, READ_LOCATION,
                "--", exe("probe_app.exe"), "--no-wait", "--helpers", HELPERS,
                "--threads", threads, "--reads", reads], timeout=timeout)


def read_log_lines(objs):
    return [str(o.get("message")) for o in objs
            if o.get("kind") == "probe_log" and str(o.get("message", "")).startswith("read handle=")]


def read_logs(objs):
    """Logs emitted by log_read (one per read hit) and the report's drop counter."""
    return len(read_log_lines(objs)), report(objs).get("log_dropped")


def unmapped(objs):
    """Logged reads whose handle the NtOpenProcess map could not attribute to a pid."""
    return sum(1 for m in read_log_lines(objs) if " pid=0 " in m)


def read_probe(objs):
    return next((x for x in probes(objs) if x.get("location", "") == READ_LOCATION), {})


def open_probe(objs):
    return next((x for x in probes(objs) if x.get("location", "") == OPEN_LOCATION), {})


def logged_pids(objs):
    pids = set()
    for o in objs:
        m = str(o.get("message", "")) if o.get("kind") == "probe_log" else ""
        if m.startswith("read handle=") and " pid=" in m:
            pids.add(int(m.split(" pid=")[1].split()[0]))
    return pids


def helper_pids(objs):
    return {o.get("pid") for o in objs if o.get("kind") == "helper"}


def check_mix_matrix(threads, reads):
    if not exe("gated_config.exe"):
        return skip("mix-matrix", "gated_config.exe missing")
    total = int(threads) * int(reads)
    # Program correctness: the target's own checksum over everything it read must be the
    # same as an UNINSTRUMENTED run with the feature enabled by config.
    base = {}
    try:
        _, bo = run([exe("probe_app.exe"), "--no-wait", "--threads", threads, "--reads", reads,
                     "--config", "reads_enabled=1"], timeout=120)
        base = app(bo)
    except Exception:
        pass
    for flag_bk in ("breakpoint", "inline", "hw"):
        for read_bk in ("breakpoint", "inline", "hw"):
            name = f"mix flag={flag_bk} read={read_bk}"
            try:
                r, o = gated(flag_bk, read_bk, threads, reads)
                rep = report(o)
                rd, op = read_probe(o), open_probe(o)
                logs, dropped = read_logs(o)
                nomap = unmapped(o)
                pids_ok = logged_pids(o) == helper_pids(o) and bool(helper_pids(o))
                same_backend = rd.get("backend") == read_bk and op.get("backend") == read_bk
                same_result = (base.get("checksum") is not None and app(o).get("checksum") == base.get("checksum")
                               and app(o).get("successful_reads") == base.get("successful_reads") == total)
                ok = (r.returncode == 0 and rep.get("overrides") == 1 and rd.get("hits") == total and
                      logs == total and dropped == 0 and nomap == 0 and pids_ok and same_backend and
                      rep.get("error") is None and same_result)
                record(name, ok, f"override={rep.get('overrides')} read_hits={rd.get('hits')} logs={logs} "
                                 f"dropped={dropped} unmapped={nomap} pids_ok={pids_ok} "
                                 f"backends={rd.get('backend')}/{op.get('backend')} checksum_same={same_result} want={total}")
            except Exception as e:
                record(name, False, repr(e))


def check_multithread_exact(threads, reads):
    if not exe("gated_config.exe"):
        return skip("multithread-exact", "gated_config.exe missing")
    total = int(threads) * int(reads)
    for read_bk in ("inline", "hw", "breakpoint"):
        name = f"exact-{read_bk} {threads}x{reads}"
        try:
            r, o = gated("breakpoint", read_bk, threads, reads, timeout=300)
            rd = read_probe(o)
            a = app(o)
            logs, dropped = read_logs(o)
            nomap = unmapped(o)
            ok = (rd.get("hits") == total and a.get("successful_reads") == total and
                  logs == total and dropped == 0 and nomap == 0 and
                  logged_pids(o) == helper_pids(o) and rd.get("backend") == read_bk and
                  open_probe(o).get("backend") == read_bk)
            record(name, ok, f"hits={rd.get('hits')} reads={a.get('successful_reads')} logs={logs} "
                             f"dropped={dropped} unmapped={nomap} want={total}")
        except Exception as e:
            record(name, False, repr(e))


def predicted_reads(threads, reads, helpers, helper, offset):
    """probe_app's read pattern: global read i (= t*R + k) goes to helper i % N at
    base + 64 * ((i // N) % 4). How many reads hit (helper, offset)."""
    return sum(1 for i in range(threads * reads)
               if i % helpers == helper and 64 * ((i // helpers) % 4) == offset)


class Lines:
    """Collect a pipe's lines on a thread; wait for one matching a predicate."""

    def __init__(self, pipe):
        self.lines, self.cv = [], threading.Condition()
        self.t = threading.Thread(target=self._pump, args=(pipe,), daemon=True)
        self.t.start()

    def _pump(self, pipe):
        for line in pipe:
            with self.cv:
                self.lines.append(line.rstrip("\r\n"))
                self.cv.notify_all()

    def wait_for(self, pred, timeout):
        with self.cv:
            ok = self.cv.wait_for(lambda: any(pred(l) for l in self.lines), timeout)
            return next((l for l in self.lines if pred(l)), None) if ok else None

    def objs(self):
        self.t.join(timeout=30)
        out = []
        for l in list(self.lines):
            if l.startswith("{"):
                try:
                    out.append(json.loads(l))
                except json.JSONDecodeError:
                    pass
        return out


def check_attach(threads, reads):
    """The attach scenario end to end: probe_app runs on its own and waits at its gate;
    uhh_attach attaches by pid, flips the flag and logs only helper #1's reads at
    offset 64 (range [base+64, base+128)). Release the gate and compare."""
    a, p = exe("uhh_attach.exe"), exe("probe_app.exe")
    if not a or not p:
        return skip("attach", "uhh_attach/probe_app missing")
    W, R, N, helper, offset = int(threads), int(reads), HELPERS, 1, 64
    want = predicted_reads(W, R, N, helper, offset)
    for bk in ("breakpoint", "hw", "inline"):
        name = f"attach-{bk}"
        procs = []
        try:
            tgt = subprocess.Popen([str(p), "--helpers", str(N), "--threads", str(W), "--reads", str(R)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   text=True)
            procs.append(tgt)
            tout = Lines(tgt.stdout)
            waiting = tout.wait_for(lambda l: '"kind":"waiting"' in l, 30)
            if not waiting:
                raise RuntimeError("target never reached its gate")
            helpers = [json.loads(l) for l in tout.lines if '"kind":"helper"' in l]
            h = next(x for x in helpers if x["index"] == helper)
            att = subprocess.Popen([str(a), str(json.loads(waiting)["pid"]), "--pid", str(h["pid"]),
                                    "--range", f"{h['base'] + offset}:64", "--backend", bk, "--flag-backend", bk],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            procs.append(att)
            aout, aerr = Lines(att.stdout), Lines(att.stderr)
            if not aout.wait_for(lambda l: '"kind":"attached"' in l, 30):
                raise RuntimeError("uhh_attach did not attach")
            # Probes on already-loaded modules arm after the attach (inline: asynchronously,
            # in the injected agent). Release the gate only once both are live.
            for loc in (OPEN_LOCATION, READ_LOCATION):
                if not aerr.wait_for(lambda l, loc=loc: l.startswith(f"probe: active {loc} "), 30):
                    raise RuntimeError(f"{loc} never became active")
            tgt.stdin.write("x"); tgt.stdin.flush()
            tgt.wait(timeout=300); att.wait(timeout=60)
            o, t_objs = aout.objs(), tout.objs()
            rep, appl = report(o), app(t_objs)
            rd = next((x for x in probes(o) if x.get("location") == READ_LOCATION), {})
            logs, dropped = read_logs(o)
            wrong = [m for m in read_log_lines(o) if f" pid={h['pid']} " not in m]
            ok = (att.returncode == 0 and rep.get("overrides") == 1 and rd.get("hits") == W * R and
                  appl.get("successful_reads") == W * R and logs == want and dropped == 0 and not wrong)
            record(name, ok, f"override={rep.get('overrides')} read_hits={rd.get('hits')}/{W * R} "
                             f"logged={logs} want_logged={want} dropped={dropped} wrong_pid={len(wrong)} "
                             f"rc={att.returncode}" + ("" if ok else
                             f" err={(rep.get('error') or '')[:120]} stderr_tail={[l[:160] for l in aerr.lines if 'remote' in l or 'ipc' in l or 'hold' in l or 'active' in l or 'release' in l or 'warn' in l or 'kick' in l or 'resolved' in l or 'vet ' in l or ' t=' in l][-40:]}"))
        except Exception as e:
            record(name, False, repr(e) + (f" stderr_tail={[l[:120] for l in aerr.lines[-6:]]}" if 'aerr' in locals() else ""))
        finally:
            for pr in procs:              # only the processes this check started
                if pr.poll() is None:
                    pr.kill()


# Per-log overhead floors (ns per logged hit, over the same run without logging). Loose
# on purpose -- they catch a regression of an order of magnitude (e.g. logging going
# synchronous or quadratic), not run-to-run noise on a VM.
LOG_OVERHEAD_CEIL_NS = {"inline": 20_000, "hw": 100_000, "breakpoint": 200_000}


def check_log_throughput(threads, reads):
    if not exe("gated_config.exe"):
        return skip("log-throughput", "gated_config.exe missing")
    total = int(threads) * int(reads)
    for read_bk in ("inline", "hw", "breakpoint"):
        name = f"log-throughput-{read_bk}"
        try:
            _, quiet = gated("breakpoint", read_bk, threads, reads, timeout=300, log=False)
            _, loud = gated("breakpoint", read_bk, threads, reads, timeout=300, log=True)
            tq, tl = app(quiet).get("elapsed_ns"), app(loud).get("elapsed_ns")
            logs, dropped = read_logs(loud)
            per = (tl - tq) / total if (tq is not None and tl is not None) else None
            ok = (per is not None and per < LOG_OVERHEAD_CEIL_NS[read_bk] and logs == total and dropped == 0
                  and read_logs(quiet)[0] == 0)
            rate = total / (tl / 1e9) if tl else 0
            record(name, ok, f"logs={logs}/{total} dropped={dropped} overhead={per and round(per)}ns/log "
                             f"(ceil {LOG_OVERHEAD_CEIL_NS[read_bk]}) logged_rate={rate:,.0f}/s")
        except Exception as e:
            record(name, False, repr(e))


def check_volume(volume_reads):
    """No-dropped-events at scale: W threads x volume_reads, hits must equal the total
    exactly. Opt-in (slow, esp. the software breakpoint) — gates the millions-no-drops
    guarantee instead of leaving it a one-off. Inline is fast at any size; the software
    breakpoint is ~hundreds of us/hit so keep its volume sane unless you have time."""
    if not exe("gated_config.exe"):
        return skip("volume", "gated_config.exe missing")
    threads = 8
    total = threads * int(volume_reads)
    for read_bk, timeout in (("inline", 180), ("hw", 900), ("breakpoint", 1800)):
        name = f"volume-{read_bk} 8x{volume_reads}"
        try:
            # Stream: millions of log lines are COUNTED as they arrive, never held in memory
            # (holding 16M parsed lines took 6 GB and starved the VM). Non-log lines are kept.
            p = subprocess.Popen([str(x) for x in [exe("gated_config.exe"), "--flag-backend", "breakpoint",
                                  "--read-backend", read_bk, FLAG_LOCATION, READ_LOCATION, "--", exe("probe_app.exe"),
                                  "--no-wait", "--helpers", HELPERS, "--threads", threads, "--reads", volume_reads]],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            logs, o, buf, t0 = 0, [], b"", time.time()
            while True:
                chunk = p.stdout.read1(1 << 20)
                if not chunk:
                    break
                buf += chunk
                lines = buf.split(b"\n"); buf = lines.pop()
                for line in lines:
                    if b'"kind":"probe_log"' in line:
                        if b'"message":"read handle=' in line:
                            logs += 1
                    elif line.startswith(b"{"):
                        try:
                            o.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
                if time.time() - t0 > timeout:
                    p.kill()
                    raise RuntimeError(f"timeout after {timeout}s")
            p.wait(timeout=60)
            rd = read_probe(o)
            a = app(o)
            dropped = report(o).get("log_dropped")
            ok = (p.returncode == 0 and rd.get("hits") == total and a.get("successful_reads") == total and
                  logs == total and dropped == 0)
            record(name, ok, f"hits={rd.get('hits')} reads={a.get('successful_reads')} logs={logs} "
                             f"dropped={dropped} want={total}")
        except Exception as e:
            record(name, False, repr(e))


def stream_volume_once(backend, calls, timeout):
    driver, target = exe("hitcost_driver.exe"), exe("hitcost_target.exe")
    state = {"logs": 0, "objects": []}

    def consume(line, _arrival):
        if line.startswith('{"kind":"probe_log",'):
            state["logs"] += 1
        elif line.startswith("{"):
            try:
                state["objects"].append(json.loads(line))
            except json.JSONDecodeError:
                pass

    rc, timed_out = stream_run(
        [driver, "--backend", backend, "--method", "send_log", "--",
         target, "--calls", calls, "--threads", 1], timeout, consume)
    rep = report(state["objects"])
    pr = next(iter(probes(state["objects"])), {})
    return {
        "rc": rc, "timeout": timed_out, "logs": state["logs"], "report": rep,
        "hits": pr.get("hits"), "peak": rep.get("controller_peak_ws_mb"),
    }


def check_stream_volume():
    """The controller's peak must be independent of total streamed-log volume."""
    if not exe("hitcost_driver.exe") or not exe("hitcost_target.exe"):
        return skip("stream-volume", "hitcost driver/target missing")
    for backend in ("inline", "hw", "breakpoint"):
        name = f"stream-volume-{backend}"
        try:
            sizes = (2_000_000, 20_000_000) if backend == "inline" else (200_000,)
            runs = [stream_volume_once(backend, n, 1800) for n in sizes]
            exact = all(not x["timeout"] and x["rc"] == 0 and x["logs"] == n and
                        x["hits"] == n and x["report"].get("logs_written") == n and
                        x["report"].get("log_dropped") == 0
                        for x, n in zip(runs, sizes))
            peaks = [x["peak"] for x in runs]
            small = all(isinstance(p, (int, float)) and 0 < p <= 256 for p in peaks)
            flat = (backend != "inline" or
                    (peaks[0] is not None and peaks[1] is not None and peaks[1] <= peaks[0] * 1.20))
            record(name, exact and small and flat,
                   " ".join(f"N={n:,} logs={x['logs']:,} hits={x['hits']} written={x['report'].get('logs_written')} "
                            f"drop={x['report'].get('log_dropped')} peak={x['peak']}MB rc={x['rc']}"
                            for x, n in zip(runs, sizes)) + f" flat={flat}")
        except Exception as e:
            record(name, False, repr(e))


def check_stream_live(calls=2_000_000):
    """Logs arrive LIVE under full load, not in a burst at the end. hitcost_target passes a
    QueryPerformanceCounter timestamp (ns) as the probed function's argument; send_log logs
    it; this reader timestamps each chunk of stdout as it arrives with the SAME clock
    (time.perf_counter_ns) and computes the lag of every 64th log, plus the gaps between
    arrivals and how many logs arrived before the target printed its final line."""
    driver, target = exe("hitcost_driver.exe"), exe("hitcost_target.exe")
    if not driver or not target:
        return skip("stream-live", "hitcost driver/target missing")
    import re as _re
    for backend, n in (("inline", calls), ("hw", 50_000), ("breakpoint", 50_000)):
        name = f"stream-live-{backend}"
        try:
            p = subprocess.Popen([str(driver), "--backend", backend, "--method", "send_log", "--",
                                  str(target), "--calls", str(n), "--threads", "1", "--no-wait", "--qpc-arg"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            lags, gaps, logs, before_exit, exited, last, buf = [], [], 0, 0, False, None, b""
            rx = _re.compile(rb'"message":"hit (-?\d+)"')
            while True:
                chunk = p.stdout.read1(1 << 20)
                if not chunk:
                    break
                now = time.perf_counter_ns()
                if last is not None:
                    gaps.append(now - last)
                last = now
                buf += chunk
                lines = buf.split(b"\n"); buf = lines.pop()
                for k, line in enumerate(lines):
                    if b'"kind":"probe_log"' in line:
                        logs += 1
                        if not exited:
                            before_exit += 1
                        if logs % 64 == 0:
                            m = rx.search(line)
                            if m:
                                lags.append((((now // 1000) - int(m.group(1))) & 0x7FFFFFFF) * 1000)   # us, 31-bit wrap
                    elif b'"kind":"target"' in line:
                        exited = True
            p.wait(timeout=600)
            lags.sort(); ms = lambda v: round(v / 1e6, 1)
            p50 = ms(lags[len(lags) // 2]) if lags else None
            p99 = ms(lags[int(len(lags) * 0.99)]) if lags else None
            gmax = ms(max(gaps)) if gaps else None
            frac = before_exit / logs if logs else 0
            ok = (p.returncode == 0 and logs == n and p99 is not None and p99 < 250 and frac >= 0.9)
            record(name, ok, f"logs={logs:,}/{n:,} lag_p50={p50}ms lag_p99={p99}ms max_gap={gmax}ms "
                             f"before_target_exit={frac:.1%} rc={p.returncode}")
        except Exception as e:
            record(name, False, repr(e))


def check_stream_sink_speed():
    """Measure the file-backed writer with tailing disabled (NUL) and to a disk file."""
    driver, target = exe("hitcost_driver.exe"), exe("hitcost_target.exe")
    if not driver or not target:
        return skip("stream-sink-speed", "hitcost driver/target missing")
    calls = 2_000_000
    command = [driver, "--backend", "inline", "--method", "send_log", "--",
               target, "--calls", calls, "--threads", 1]

    def measure(sink):
        started = time.perf_counter()
        result = subprocess.run([str(x) for x in command], stdout=sink, stderr=subprocess.PIPE,
                                text=True, timeout=600)
        elapsed = time.perf_counter() - started
        log_size = 0
        for line in result.stderr.splitlines():
            marker = "probe: logs -> "
            if line.startswith(marker):
                try:
                    log_path = Path(line[len(marker):])
                    log_size = log_path.stat().st_size
                    log_path.unlink()
                except OSError:
                    pass
        return result.returncode, calls / elapsed, log_size

    try:
        nul_rc, nul_rate, nul_log_size = measure(subprocess.DEVNULL)
        with tempfile.TemporaryDirectory(prefix="uhh-stream-") as directory:
            output = Path(directory) / "stdout.jsonl"
            with output.open("w", encoding="utf-8", newline="") as sink:
                file_rc, file_rate, file_log_size = measure(sink)
            output_size = output.stat().st_size
        ok = (nul_rc == file_rc == 0 and nul_rate > 0 and file_rate > 0 and
              nul_log_size > calls * 40 and file_log_size > calls * 40 and output_size > calls * 40)
        record("stream-sink-speed", ok, f"NUL={nul_rate:,.0f} logs/s file={file_rate:,.0f} logs/s "
                                          f"stdout_bytes={output_size:,} log_bytes={nul_log_size:,}/{file_log_size:,} "
                                          f"rc={nul_rc}/{file_rc}")
    except Exception as e:
        record("stream-sink-speed", False, repr(e))


def trace_logstream(backend, target_args, timeout, consume):
    tracer, target = exe("uhh_trace.exe"), exe("logstream_target.exe")
    return stream_run([tracer, "--backend", backend, "-p",
                       "logstream_target.exe!LogSite:d", "--", target, *target_args],
                      timeout, consume)


def check_stream_latency():
    tracer, target = exe("uhh_trace.exe"), exe("logstream_target.exe")
    if not tracer or not target:
        return skip("stream-latency", "uhh_trace/logstream_target missing")
    for backend in ("inline", "hw", "breakpoint"):
        name = f"stream-latency-{backend}"
        ticks, logs, objects = {}, {}, []
        try:
            def consume(line, arrival):
                if not line.startswith("{"):
                    return
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    return
                if obj.get("kind") == "tick":
                    ticks.setdefault(obj.get("i"), arrival)
                elif obj.get("kind") == "probe_log":
                    match = re.fullmatch(r"LogSite\((-?\d+)\)", str(obj.get("message", "")))
                    if match:
                        logs.setdefault(int(match.group(1)), arrival)
                else:
                    objects.append(obj)

            rc, timed_out = trace_logstream(backend, [], 120, consume)
            latencies = [logs[i] - ticks[i] for i in range(50) if i in ticks and i in logs]
            ordered = all(logs.get(i, 0) >= ticks.get(i, float("inf")) for i in range(50))
            p99 = sorted(latencies)[max(0, math.ceil(.99 * len(latencies)) - 1)] if latencies else float("inf")
            rep = report(objects)
            ok = (not timed_out and rc == 0 and len(ticks) == len(logs) == len(latencies) == 50 and
                  ordered and p99 < .100 and rep.get("logs_written") == 50 and rep.get("log_dropped") == 0)
            record(name, ok, f"pairs={len(latencies)}/50 p99={p99 * 1000:.1f}ms "
                             f"written={rep.get('logs_written')} dropped={rep.get('log_dropped')} rc={rc}")
        except Exception as e:
            record(name, False, repr(e))


def check_stream_order():
    tracer, target = exe("uhh_trace.exe"), exe("logstream_target.exe")
    if not tracer or not target:
        return skip("stream-order", "uhh_trace/logstream_target missing")
    count = 1000
    by_tid, objects = {}, []
    try:
        def consume(line, _arrival):
            if not line.startswith("{"):
                return
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                return
            if obj.get("kind") == "probe_log":
                match = re.fullmatch(r"LogSite\((-?\d+)\)", str(obj.get("message", "")))
                if match:
                    by_tid.setdefault(obj.get("tid"), []).append(int(match.group(1)))
            else:
                objects.append(obj)

        rc, timed_out = trace_logstream("inline", ["--threads", 8, "--count", count,
                                                     "--delay", 0, "--no-ticks"], 120, consume)
        complete = len(by_tid) == 8 and all(seq == list(range(count)) for seq in by_tid.values())
        rep = report(objects)
        ok = (not timed_out and rc == 0 and complete and rep.get("logs_written") == 8 * count and
              rep.get("log_dropped") == 0)
        record("stream-order", ok, f"threads={len(by_tid)}/8 logs={sum(map(len, by_tid.values()))}/{8 * count} "
                                   f"written={rep.get('logs_written')} dropped={rep.get('log_dropped')} rc={rc}")
    except Exception as e:
        record("stream-order", False, repr(e))


def check_breakage():
    d = exe("breakage_driver.exe")
    if not d or not exe("hook_edge.exe"):
        return skip("breakage", "breakage_driver/hook_edge missing")
    expected = {
        ("ShortSite", "breakpoint"): "pass", ("ShortSite", "hw"): "pass",
        ("PrehookSite", "breakpoint"): "pass", ("PrehookSite", "hw"): "pass",
        ("UnrelocSite", "breakpoint"): "pass", ("UnrelocSite", "hw"): "pass",
        ("StackSite", "breakpoint"): "pass", ("StackSite", "hw"): "pass",
        ("StackInsideSite", "breakpoint"): "pass", ("StackInsideSite", "hw"): "pass",
    }
    try:
        r = rvas("hook_edge.map", "ShortSite", "PrehookSite", "UnrelocSite", "StackSite", "StackInsideSite")
        _, o = run([d, exe("hook_edge.exe"), r["ShortSite"], r["PrehookSite"], r["UnrelocSite"], r["StackSite"], r["StackInsideSite"]],
                   timeout=180)
        bad = []
        for row in o:
            key = (row.get("site"), row.get("backend"))
            want = expected.get(key)
            if want and row.get("verdict") != want:
                bad.append(f"{key}={row.get('verdict')}!={want} row={json.dumps(row)[:400]}")
        # The 10 breakpoint/hw controls MUST all pass; inline rows are observational.
        controls = [row for row in o if row.get("backend") in ("breakpoint", "hw")]
        ok = len(controls) == 10 and all(row.get("verdict") == "pass" for row in controls) and not bad
        record("breakage-controls", ok, f"controls={len(controls)}/10 bad={bad}")
    except Exception as e:
        record("breakage-controls", False, repr(e))


def check_frida_parity():
    d = exe("frida_parity.exe")
    if not d or not exe("parity_target.exe"):
        return skip("frida-parity", "frida_parity/parity_target missing")
    try:
        r = rvas("parity_target.map", "ParityB1Site", "ParityB2Site", "ParityB4Site", "ParityB6Site")
        _, o = run([d, exe("parity_target.exe"), r["ParityB1Site"], r["ParityB2Site"], r["ParityB4Site"], r["ParityB6Site"]], timeout=90)
        # This legacy driver asks probe_report for a private FILE and used to parse logs
        # back out of it. Logs now deliberately stream only to controller stdout, so
        # validate the four observable callback results directly from that stream.
        got = [row.get("message") for row in o if row.get("kind") == "probe_log"]
        expected = ["B1:4660", "B2:hello-from-target", "B4:instrumented", "B6:7->42"]
        ok = sorted(got) == sorted(expected)
        record("frida-parity", ok, f"streamed={sorted(got)}")
    except Exception as e:
        record("frida-parity", False, repr(e))


def check_watchpoint():
    d = exe("watch_driver.exe")
    if not d or not exe("watch_target.exe"):
        return skip("watchpoint", "watch_driver/watch_target missing")
    # Same workload both times: 4 threads x 1000 stores, then 1000 loads each, then main
    # reads the value once more for its report line. WRITE must count only the 4000
    # stores; RW must count stores + loads + that final read = 8001.
    for name, extra, want in (("watchpoint-write", [], 4000), ("watchpoint-rw", ["--rw"], 8001)):
        try:
            rva = rvas("watch_target.map", "g_watched")["g_watched"]
            _, o = run([d, *extra, rva, "--", exe("watch_target.exe"),
                        "--no-wait", "--threads", "4", "--writes", "1000", "--reads", "1000"],
                       timeout=120)
            rd = next((x for x in probes(o) if x.get("backend") == "hw"), {})
            hits = next((x.get("callback_hits") for x in o if x.get("kind") == "watch_driver"), None)
            ok = rd.get("hits") == want and hits == want
            record(name, ok, f"probe_hits={rd.get('hits')} callback_hits={hits} want={want}")
        except Exception as e:
            record(name, False, repr(e))


def check_dynwatch(writes=100):
    d = exe("dynwatch_driver.exe")
    if not d or not exe("dynwatch_target.exe"):
        return skip("dynwatch", "dynwatch_driver/dynwatch_target missing")
    want = 2 * writes
    for entry in ("breakpoint", "hw", "inline"):
        name = f"dynwatch-{entry}"
        try:
            _, o = run([d, "--entry", entry, "--", exe("dynwatch_target.exe"), "--writes", writes], timeout=120)
            res = next((x for x in o if x.get("kind") == "dynwatch_result"), {})
            rep = report(o)
            once = [p for p in probes(o) if p.get("location", "").startswith("0x") and p.get("backend") == "breakpoint"]
            stacks = [x.get("stack") for x in o if x.get("kind") == "probe_log" and x.get("stack")
                      and x.get("message") == "write to tracked block"]
            sym_ok = bool(stacks) and len(stacks[0]) >= 3 and stacks[0][0].startswith("dynwatch_target!main")
            marker = next((p for p in probes(o) if p.get("location", "").endswith("!dynwatch_marker")), {})
            calls = [x.get("message") for x in o if x.get("kind") == "probe_log" and "call_func" in str(x.get("message"))]
            entry = next((x.get("stack") for x in o if x.get("kind") == "probe_log" and x.get("message") == "malloc(0x1337) entry"), None)
            entry_ok = bool(entry) and len(entry) >= 2 and entry[1].startswith("dynwatch_target!main")
            tgt = next((x for x in o if x.get("kind") == "target"), {})
            ok = (res.get("returns") == 1 and res.get("arms") == 1 and res.get("watch_hits") == want and
                  rep.get("error") is None and len(once) == 1 and once[0].get("active") is False and
                  once[0].get("hits") == 1 and sym_ok and
                  marker.get("backend") == "inline" and marker.get("hits") == 50 and tgt.get("marker_calls") == 50 and
                  calls == ["call_func sum6=91 ok=1"] and entry_ok)
            record(name, ok, f"returns={res.get('returns')} arms={res.get('arms')} watch_hits={res.get('watch_hits')} "
                             f"want={want} once_retired={bool(once) and once[0].get('active') is False} "
                             f"err={rep.get('error')} once={[(p.get('active'), p.get('hits')) for p in once]} marker_calls={tgt.get('marker_calls')} "
                             f"runtime_inline_hits={marker.get('hits')}/50 call_func={calls} entry_caller={(entry[1][:40] if entry and len(entry) > 1 else entry)} stack0={(stacks[0][0] if stacks else None)}")
        except Exception as e:
            record(name, False, repr(e))


SYS32 = Path(r"C:\Windows\System32")


CONFORMANCE_CHECKS = ["get_config", "get_func_arg", "get_mem", "set_mem", "get_reg", "set_reg/arg-rewrite",
                      "call_func", "call_func-forwarded", "get_session", "probe_add_symbol", "probe_watch", "probe_add_address",
                      "later-hit", "once-hw-hit", "watch-hit"]


def check_conformance():
    """Every context method + the control ops, one callback source, every backend."""
    d, t = exe("conformance_driver.exe"), exe("conformance_target.exe")
    if not d or not t:
        return skip("conformance", "conformance_driver/target missing")
    for bk in ("breakpoint", "hw", "inline"):
        name = f"conformance-{bk}"
        try:
            _, o = run([d, "--backend", bk, "--", t], timeout=120)
            msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
            fails = sorted({m for m in msgs if m.startswith("FAIL")})
            oks = {m[3:] for m in msgs if m.startswith("ok ")}
            missing = [c for c in CONFORMANCE_CHECKS if c not in oks]
            tgt = next((x for x in o if x.get("kind") == "target"), {})
            stacks = [x.get("stack") for x in o if x.get("kind") == "probe_log" and x.get("message") == "stack conf_site"]
            stack_ok = bool(stacks) and all(len(st) >= 2 and st[1].startswith("conformance_target!main") for st in stacks)
            later = sum(1 for m in msgs if m == "ok later-hit")          # conf_later runs 20 times
            once = sum(1 for m in msgs if m == "ok once-hw-hit")         # PROBE_HW|PROBE_ONCE: exactly once
            hw_rows = [p for p in probes(o) if p.get("backend") == "hw" and p.get("location", "").startswith("0x")]
            # Two runtime hw probes: the PROBE_ONCE one (retired after exactly 1 hit) and the
            # write watchpoint (3 stores, still active).
            once_row = next((p for p in hw_rows if p.get("active") is False), {})
            watch_row = next((p for p in hw_rows if p.get("active") is True), {})
            ok = (not fails and not missing and tgt.get("arg_rewritten") == 10 and tgt.get("mem_written") == 10 and
                  tgt.get("sp_moved") == (0 if bk == "inline" else 10) and   # inline: set_reg(SP) refused (roadmap)
                  stack_ok and report(o).get("error") is None and report(o).get("log_dropped") == 0 and
                  later == 20 and once == 1 and once_row.get("hits") == 1 and watch_row.get("hits") == 3 and
                  len(hw_rows) == 2)
            record(name, ok, f"fails={fails[:3]} missing={missing} sp_moved={tgt.get('sp_moved')}/10 arg_rewritten={tgt.get('arg_rewritten')} "
                             f"mem_written={tgt.get('mem_written')} stack_ok={stack_ok} later={later}/20 once={once}/1 "
                             f"once_row={once_row.get('hits')}/{once_row.get('active')} watch_row={watch_row.get('hits')}")
        except Exception as e:
            record(name, False, repr(e))


def check_memstress(threads=8, iters=20000):
    """get_mem/set_mem at scale, every backend: exact values, writes visible, page-crossing
    access, bad addresses failing closed, nothing else in the target's memory touched."""
    d, t = exe("memstress_driver.exe"), exe("memstress_target.exe")
    if not d or not t:
        return skip("memstress", "memstress_driver/target missing")
    calls = threads * iters
    for bk in ("inline", "hw", "breakpoint"):
        name = f"memstress-{bk} {threads}x{iters}"
        try:
            r, o = run([d, "--backend", bk, "--", t, "--threads", threads, "--iters", iters], timeout=900)
            tgt = next((x for x in o if x.get("kind") == "target"), {})
            rep = report(o)
            pr = next(iter(probes(o)), {})
            summ = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"
                    and str(x.get("message", "")).startswith("memstress ")]
            fields = {}
            if summ:
                last = max(summ, key=lambda m: int(m.split("reads_ok=")[1].split()[0]) if "reads_ok=" in m else -1)
                for kv in last.split()[1:]:
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        try: fields[k] = int(v)
                        except ValueError: pass
            ok = (tgt.get("calls") == calls and tgt.get("write_ok") == calls and tgt.get("cross_ok") == calls and
                  tgt.get("untouched_ok") is True and tgt.get("readonly_intact") is True and
                  fields.get("reads_ok") == calls and fields.get("reads_bad") == 0 and fields.get("writes") == calls and
                  fields.get("fault_reads_failed_closed") == calls and fields.get("ro_writes_failed_closed") == calls and
                  pr.get("hits") == calls and rep.get("log_dropped") == 0 and rep.get("error") is None and
                  pr.get("backend") == bk and len(probes(o)) == 1 and r.returncode == 0 and rep.get("app_exit") == 0)
            record(name, ok, f"calls={tgt.get('calls')} write_ok={tgt.get('write_ok')} untouched={tgt.get('untouched_ok')} "
                             f"reads_ok={fields.get('reads_ok')} bad={fields.get('reads_bad')} "
                             f"fault_closed={fields.get('fault_reads_failed_closed')} hits={pr.get('hits')} "
                             f"ns={tgt.get('elapsed_ns')}")
        except Exception as e:
            record(name, False, repr(e))


def check_symbols():
    """Hook by PDB-only name (a static, non-exported function) and enumerate a module's
    exports -- via the dynamically loaded dbghelp/symsrv (honours _NT_SYMBOL_PATH)."""
    t, d = exe("uhh_trace.exe"), exe("dynwatch_target.exe")
    if not t or not d:
        return skip("symbols", "uhh_trace/dynwatch_target missing")
    for bk in ("breakpoint", "hw", "inline"):
        try:
            r, o = run([t, "--backend", bk, "-p", "dynwatch_target.exe!worker:x", "--", d, "--no-wait", "--writes", "10"],
                       timeout=120)
            msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
            pr = next(iter(probes(o)), {})
            via_pdb = "resolved from symbols" in (r.stderr or "")      # not an export: the PDB path ran
            ok = (pr.get("hits") == 1 and any(m.startswith("worker(") for m in msgs) and
                  report(o).get("error") is None and via_pdb)
            record(f"symbols-pdb-name-{bk}", ok, f"hits={pr.get('hits')} logs={msgs[:1]} err={report(o).get('error')}")
        except Exception as e:
            record(f"symbols-pdb-name-{bk}", False, repr(e))
    try:
        _, o = run([t, "--list", "kernel32.dll", "--mask", "*CreateFile*"], timeout=60)
        names = {x.get("name") for x in o if x.get("kind") == "symbol"}
        record("symbols-list", "CreateFileW" in names, f"found={sorted(n for n in names if n)[:5]}")
    except Exception as e:
        record("symbols-list", False, repr(e))


def trace_run(target, probes_spec, backend, targs=(), timeout=300):
    t = exe("uhh_trace.exe")
    cmd = [t, "--backend", backend]
    for sp in probes_spec:
        cmd += ["-p", sp]
    r, o = run(cmd + ["--", target, "--no-wait", *targs], timeout=timeout)
    return r, o, next((x for x in o if x.get("kind") == "target"), {})


def check_realworld_targets():
    """Codex-written behaviour targets: exceptions through probed frames, thread
    lifecycle stress, allocator re-entrancy, and (measured) tamper/debugger visibility."""
    if not exe("uhh_trace.exe"):
        return skip("realworld-targets", "uhh_trace missing")
    for bk in ("breakpoint", "hw", "inline"):
        # Exceptions must still be caught by the target with every probe type in the frames.
        x = exe("exceptions_target.exe")
        if x:
            try:
                r, o, tg = trace_run(x, ["exceptions_target.exe!throws_cpp:d", "exceptions_target.exe!throws_seh:d",
                                         "exceptions_target.exe!calls_through:d"], bk, ("--iters", "200"))
                ok = (r.returncode == 0 and tg.get("cpp_caught") == 200 and tg.get("seh_caught") == 200 and
                      tg.get("through_caught") == 200 and report(o).get("app_exit") == 0)
                record(f"exceptions-{bk}", ok, f"cpp={tg.get('cpp_caught')} seh={tg.get('seh_caught')} "
                                               f"through={tg.get('through_caught')} exit={report(o).get('app_exit')}")
            except Exception as e:
                record(f"exceptions-{bk}", False, repr(e))
        # Thread lifecycle: 128 at once, suspended-then-resumed, thread pool, churn.
        x = exe("thread_stress_target.exe")
        if x:
            try:
                r, o, tg = trace_run(x, ["thread_stress_target.exe!stress_work:d"], bk, ("--many", "128", "--calls", "50"),
                                     timeout=900)
                pr = next(iter(probes(o)), {})
                total = tg.get("total_calls")
                ok = (r.returncode == 0 and total == 128 * 50 + 32 * 50 + 256 + 200 and pr.get("hits") == total and
                      report(o).get("log_dropped") == 0)
                record(f"thread-stress-{bk}", ok, f"total={total} hits={pr.get('hits')} dropped={report(o).get('log_dropped')}")
            except Exception as e:
                record(f"thread-stress-{bk}", False, repr(e))
    # Re-entrancy: an inline probe on the CRT allocator whose callback logs every call.
    x = exe("reentrancy_target.exe")
    if x:
        try:
            r, o, tg = trace_run(x, ["ucrtbase.dll!malloc:x"], "inline", ("--iters", "10000", "--threads", "4"), timeout=600)
            pr = next(iter(probes(o)), {})
            want = 10000 * 4
            ok = (r.returncode == 0 and tg.get("mallocs") == want and tg.get("frees") == want and
                  (pr.get("hits") or 0) >= want and report(o).get("log_dropped") == 0 and pr.get("backend") == "inline")
            record("reentrancy-inline-malloc", ok, f"mallocs={tg.get('mallocs')} hits={pr.get('hits')} "
                                                   f"backend={pr.get('backend')} dropped={report(o).get('log_dropped')}")
        except Exception as e:
            record("reentrancy-inline-malloc", False, repr(e))
    # Tamper/debugger visibility: measured and asserted to match the documented signature.
    x = exe("antitamper_target.exe")
    if x:
        for bk, code_changes, dr_seen in (("breakpoint", True, False), ("inline", True, False), ("hw", False, True)):
            try:
                r, o, tg = trace_run(x, ["antitamper_target.exe!guarded_fn:d"], bk, ("--calls", "100"))
                ok = (r.returncode == 0 and tg.get("calls") == 100 and
                      (tg.get("fn_disk_ok") is (not code_changes)) and (tg.get("debug_registers_seen") is dr_seen))
                record(f"antitamper-{bk}", ok, f"fn_disk_ok={tg.get('fn_disk_ok')} fn_bytes_ok={tg.get('fn_bytes_ok')} text_ok={tg.get('text_ok')} "
                                               f"dr_seen={tg.get('debug_registers_seen')} (expected code_changes={code_changes})")
            except Exception as e:
                record(f"antitamper-{bk}", False, repr(e))
    x = exe("antidebug_target.exe")
    if x:
        try:
            r, o, tg = trace_run(x, ["antidebug_target.exe!timed_fn:d"], "hw")
            keys = ("is_debugger_present", "remote_debugger_present", "debug_port", "debug_object_handle",
                    "debug_flags_zero", "peb_being_debugged", "peb_nt_global_flag_heap_debug")
            ok = r.returncode == 0 and all(isinstance(tg.get(k), bool) for k in keys)
            record("antidebug-measured", ok, " ".join(f"{k}={tg.get(k)}" for k in keys))
        except Exception as e:
            record("antidebug-measured", False, repr(e))


FRIDA_PY = Path(r"C:\work\fv16\Scripts\python.exe")


def check_frida_coexist():
    """Frida and UHH on the same function, in both orders and on every UHH backend: the
    target stays correct and BOTH tools see every call. (Needs an interpreter with frida;
    on the test VM a frida 16.5.9 venv.)"""
    if not FRIDA_PY.exists() or not exe("uhh_trace.exe") or not exe("probe_app.exe"):
        return skip("frida-coexist", "frida interpreter / uhh_trace / probe_app missing")
    script = Path(__file__).with_name("frida_coexist.py")
    for order in ("frida_first", "uhh_first"):
        for bk in ("inline", "hw", "breakpoint"):
            name = f"frida-coexist-{order}-{bk}"
            try:
                r = subprocess.run([str(FRIDA_PY), str(script), "--app", str(exe("probe_app.exe")),
                                    "--trace", str(exe("uhh_trace.exe")), "--order", order, "--backend", bk],
                                   capture_output=True, text=True, timeout=300)
                res = next((json.loads(l) for l in r.stdout.splitlines() if l.startswith('{"kind": "coexist"')), {})
                total = res.get("total")
                ok = (total and res.get("app_reads") == total and res.get("frida_hits") == total and
                      res.get("uhh_hits") == total and res.get("app_exit") == 0)
                record(name, ok, f"total={total} app={res.get('app_reads')} frida={res.get('frida_hits')} "
                                 f"uhh={res.get('uhh_hits')}/{res.get('uhh_backend')} prehook={res.get('prehook_reports')} "
                                 f"exit={res.get('app_exit')}" + ("" if ok else f" err={(r.stderr or '')[-300:]!r} tail={res.get('uhh_stderr_tail')}"))
            except Exception as e:
                record(name, False, repr(e))


def check_sidefx(iters=1000, threads=4):
    """A probe hit leaves no trace on the target thread: GPRs, XMM, YMM upper halves,
    MXCSR, DF, x87 control word and the TEB last-error are bit-identical after the hit,
    while the callback deliberately does disturbing work (float math, formatting, logs
    with stacks, memory reads, a Win32 call that sets last-error). Every backend."""
    d, t = exe("sidefx_driver.exe"), exe("sidefx_target.exe")
    if not d or not t:
        return skip("sidefx", "sidefx_driver/target missing")
    calls = iters * threads
    for bk in ("breakpoint", "hw", "inline"):
        name = f"sidefx-{bk}"
        try:
            r, o = run([d, "--backend", bk, "--", t, "--iters", iters, "--threads", threads], timeout=600)
            tg = next((x for x in o if x.get("kind") == "target"), {})
            rep, pr = report(o), next(iter(probes(o)), {})
            keys = ("gpr_ok", "xmm_ok", "ymm_upper_ok", "mxcsr_ok", "df_ok", "arith_flags_ok", "x87cw_ok", "lasterror_ok")
            ok = (r.returncode == 0 and all(tg.get(k) == calls for k in keys) and pr.get("backend") == bk and
                  pr.get("hits") == calls and rep.get("log_dropped") == 0 and rep.get("app_exit") == 0 and
                  rep.get("error") is None)
            record(name, ok, " ".join(f"{k.replace('_ok', '')}={tg.get(k)}" for k in keys) +
                   f" below_sp={tg.get('below_sp_ok')} hits={pr.get('hits')}/{calls} backend={pr.get('backend')}")
        except Exception as e:
            record(name, False, repr(e))


def lines_until(proc, marker, timeout):
    """Read a child's stdout lines until one contains marker (or timeout). Helper processes
    may inherit the pipe, so never wait for EOF."""
    import threading
    got, done = [], threading.Event()

    def reader():
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode(errors="replace")
            got.append(line)
            if marker in line:
                break
        done.set()
    threading.Thread(target=reader, daemon=True).start()
    done.wait(timeout)
    return got


def check_detach():
    """Detach while the target keeps running (probe_close from another thread while
    probe_run runs): the target must finish every read with the SAME checksum as an
    uninstrumented run -- a leftover INT3 or debug register would crash it once no
    debugger is attached, and a half-removed hook would corrupt results."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return skip("detach", "uhh_trace/probe_app missing")
    import time
    for bk, reads in (("inline", 1500000), ("hw", 40000), ("breakpoint", 40000)):
        name = f"detach-{bk}"
        target = None
        try:
            threads = 2
            total = threads * reads
            _, bo = run([a, "--no-wait", "--threads", threads, "--reads", reads, "--config", "reads_enabled=1"],
                        timeout=600)
            base = app(bo)
            target = subprocess.Popen([str(a), "--threads", str(threads), "--reads", str(reads),
                                       "--config", "reads_enabled=1"],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while True:                                          # wait until it is at its gate
                line = target.stdout.readline().decode(errors="replace")
                if not line or '"waiting"' in line:
                    break
            tracer = subprocess.Popen([str(t), "--backend", bk, "--attach", str(target.pid), "--detach-after-ms", "2500",
                                       "-p", "ntdll.dll!NtReadVirtualMemory:xxxx"],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            tout, terr = Lines(tracer.stdout), Lines(tracer.stderr)   # release the gate once the probe is LIVE
            if not terr.wait_for(lambda l: l.startswith("probe: active ntdll.dll!NtReadVirtualMemory"), 60):
                raise RuntimeError("probe never became active")
            target.stdin.write(b"\n"); target.stdin.flush()
            tracer.wait(timeout=120)
            tout.t.join(timeout=30); terr.t.join(timeout=30)
            out, err = "\n".join(tout.lines), "\n".join(terr.lines)
            rest = lines_until(target, '"kind":"app"', 600)
            target.wait(timeout=120)
            terr = target.stderr.read().decode(errors="replace") if target.returncode != 0 else ""
            unhandled = [l for l in terr.splitlines() if '"unhandled"' in l][:2]
            tobjs = [json.loads(l) for l in rest if l.strip().startswith("{")]
            res = next((o for o in tobjs if o.get("kind") == "app"), {})
            objs = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
            pr = next((o for o in objs if o.get("kind") == "probe"), {})
            detached = any(o.get("kind") == "detached" for o in objs)
            mid_run = 0 < (pr.get("hits") or 0) < total
            ok = (detached and mid_run and target.returncode == 0 and res.get("successful_reads") == total and
                  res.get("checksum") == base.get("checksum"))
            record(name, ok, f"hits_before_detach={pr.get('hits')}/{total} detached={detached} exit={target.returncode} "
                             f"reads={res.get('successful_reads')} checksum_same={res.get('checksum') == base.get('checksum')}"
                             + ("" if ok else f" target_unhandled={unhandled} detach_line=" +
                                " | ".join(l for l in err.strip().splitlines() if "detach" in l)[:1200]))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            if target and target.poll() is None:
                target.kill()


def check_ntdll_churn():
    """Hooks on ntdll's own syscall stub, installed and removed again and again while
    threads hammer it: probe_app reads in a tight loop on 4 threads through
    ntdll!NtReadVirtualMemory (which shares its page with NtProtectVirtualMemory & co.);
    uhh_trace attaches, hooks the stub, detaches -- repeatedly -- for every backend.
    Inline hooks are written with the target frozen and threads caught inside the
    overwritten bytes moved to the trampoline: the target must finish every read, exit 0
    and match the uninstrumented checksum, and every cycle must have seen hits."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return skip("ntdll-churn", "uhh_trace/probe_app missing")
    import time
    for bk, reads in (("inline", 4000000), ("hw", 4000000), ("breakpoint", 4000000)):
        name = f"ntdll-churn-{bk}"
        target = None
        try:
            threads = 4
            total = threads * reads
            _, bo = run([a, "--no-wait", "--threads", threads, "--reads", reads, "--config", "reads_enabled=1"],
                        timeout=600)
            base = app(bo)
            target = subprocess.Popen([str(a), "--threads", str(threads), "--reads", str(reads),
                                       "--config", "reads_enabled=1"],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while True:
                line = target.stdout.readline().decode(errors="replace")
                if not line or '"waiting"' in line:
                    break
            target.stdin.write(b"\n"); target.stdin.flush()
            cycles, bad = [], []
            while target.poll() is None and len(cycles) < 12:
                tr = subprocess.Popen([str(t), "--backend", bk, "--attach", str(target.pid), "--detach-after-ms", "300",
                                       "-p", "ntdll.dll!NtReadVirtualMemory:xxxx"],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = tr.communicate(timeout=120)
                objs = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
                pr = next((o for o in objs if o.get("kind") == "probe"), {})
                det = any(o.get("kind") == "detached" for o in objs)
                if target.poll() is not None and not det:
                    break                                    # target finished mid-cycle: not a failure
                cycles.append(pr.get("hits") or 0)
                # The first cycle includes loading the agent (inline) and may not finish installing
                # inside the 300 ms window; every later cycle must see hits.
                if not det or (not pr.get("hits") and len(cycles) > 1) or pr.get("backend") != bk:
                    bad.append(f"cycle{len(cycles)}: detached={det} hits={pr.get('hits')} backend={pr.get('backend')} "
                               f"err={' | '.join(err.strip().splitlines()[-3:])[:400]}")
            rest = lines_until(target, '"kind":"app"', 600)
            target.wait(timeout=120)
            terr = target.stderr.read().decode(errors="replace") if target.returncode != 0 else ""
            unhandled = [l for l in terr.splitlines() if '"unhandled"' in l][:2]
            res = next((json.loads(l) for l in rest if l.strip().startswith("{") and '"kind":"app"' in l), {})
            ok = (len(cycles) >= 5 and not bad and target.returncode == 0 and res.get("successful_reads") == total
                  and res.get("checksum") == base.get("checksum"))
            record(name, ok, f"cycles={len(cycles)} hits/cycle={cycles} exit={target.returncode} "
                             f"reads={res.get('successful_reads')}/{total} checksum_same={res.get('checksum') == base.get('checksum')}"
                             + ("" if ok else f" bad={bad[:3]} target_unhandled={unhandled}"))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            if target and target.poll() is None:
                target.kill()


def check_patch_race(trials=4):
    """Why inline hooks are written with the target frozen. patchrace_target runs 8
    threads calling RaceSite -- xor eax,eax + 16 x inc eax, returns 16 -- in a loop, so threads sit
    INSIDE the 5 bytes a hook overwrites. uhh_trace attaches, hooks it, detaches, over
    and over. Frozen (default): threads caught in those bytes are moved to the
    trampoline; every trial must exit 0 with every call returning 16. With
    PROBE_UNSAFE_FAST_PATCH the jump is written while they run: a thread resumes mid-jump
    and returns a wrong count or crashes -- this must happen in at least one trial,
    proof the test can see the race the freeze removes."""
    t, a = exe("uhh_trace.exe"), exe("patchrace_target.exe")
    if not t or not a:
        return skip("patch-race", "uhh_trace/patchrace_target missing")
    for mode in ("frozen", "unsafe"):
        name = f"patch-race-{mode}"
        exits, cycles_all, notes, torn = [], [], [], []
        try:
            for _ in range(trials):
                target = subprocess.Popen([str(a), "--threads", "8", "--seconds", "12"],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                ready = target.stdout.readline()
                if '"ready"' not in ready:
                    raise RuntimeError(f"target not ready: {ready!r}")
                cycles = 0
                while target.poll() is None and cycles < 25:
                    cmd = [str(t), "--backend", "inline", "--attach", str(target.pid), "--detach-after-ms", "400",
                           "-p", "patchrace_target.exe!RaceSite:-"]
                    if mode == "unsafe":
                        cmd.insert(1, "--unsafe-fast-patch")
                    tr = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    objs = [json.loads(l) for l in tr.stdout.splitlines() if l.startswith("{")]
                    pr = next((o for o in objs if o.get("kind") == "probe"), {})
                    if target.poll() is not None:
                        break
                    cycles += 1
                    if pr.get("backend") != "inline" or (not pr.get("hits") and cycles > 1):   # first cycle loads the agent
                        notes.append(f"backend={pr.get('backend')} hits={pr.get('hits')} "
                                     f"err={(report(objs).get('error') or '')[:80]}")
                try:
                    tout, _ = target.communicate(timeout=120)
                except subprocess.TimeoutExpired:
                    target.kill(); tout, _ = target.communicate()
                res = next((json.loads(l) for l in (tout or "").splitlines() if '"kind":"app"' in l), {})
                exits.append(target.returncode); cycles_all.append(cycles); torn.append(res.get("torn"))
            crashed = sum(1 for e in exits if e != 0)
            torn_total = sum(t or 0 for t in torn)
            if mode == "frozen":
                ok = crashed == 0 and torn_total == 0 and min(cycles_all) >= 5 and not notes
            else:
                ok = (crashed >= 1 or torn_total >= 1) and not any("hits=None" in n or "hits=0" in n for n in notes)
            record(name, ok, f"trials={trials} crashed={crashed} torn={torn} exits={[hex(e & 0xffffffff) for e in exits]} "
                             f"hook_cycles={cycles_all}" + (f" notes={notes[:3]}" if notes else "")
                             + ("" if ok or mode == "frozen" else " (unsafe never failed: test not sensitive)"))
        except Exception as e:
            record(name, False, repr(e))


def check_emulated_sites(threads=8, calls=20000):
    """Sites UHH cannot step out-of-line -- a jmp, a pushfq -- are executed by the
    controller (emulated) under PROBE_BREAKPOINT: the INT3 never leaves the site, so hits
    are EXACT with 8 threads racing through it, and no trap flag is ever set, so the
    flags image the code pushes itself never shows TF (it used to: pushf stepped in place
    pushed TF=1, the RtlCaptureContext case). hw is run as the reference."""
    t, a = exe("uhh_trace.exe"), exe("patchrace_target.exe")
    if not t or not a:
        return skip("emulated-sites", "uhh_trace/patchrace_target missing")
    for site, mode in (("BranchSite", "branch"), ("PushfSite", "pushf")):
        for bk in ("breakpoint", "hw"):
            name = f"emulated-{mode}-{bk}"
            try:
                r, objs = run([t, "--backend", bk, "-p", f"patchrace_target.exe!{site}:-", "--",
                               a, "--flags", mode, "--threads", threads, "--calls", calls], timeout=600)
                res = next((x for x in objs if x.get("kind") == "app"), {})
                pr = next((x for x in objs if x.get("kind") == "probe"), {})
                want = threads * calls
                ok = (r.returncode == 0 and res.get("calls") == want and pr.get("hits") == want
                      and res.get("tf_seen") == 0 and pr.get("backend") == bk)
                record(name, ok, f"hits={pr.get('hits')}/{want} calls={res.get('calls')} tf_seen={res.get('tf_seen')} "
                                 f"backend={pr.get('backend')} exit={r.returncode}")
            except Exception as e:
                record(name, False, repr(e))


def check_ret_probe(threads=2, reads=50):
    """A probe on a function's own `ret` -- the natural way to see a return (no special
    flag): ntdll!NtOpenProcess's ret, found by decoding the stub in the DLL file. probe_app
    opens each helper once. breakpoint and hw must fire once per open. inline must be REFUSED cleanly (the 5-byte jump would run past the ret
    into code only a jump reaches -- the int 2e tail on x64, the next stub on x86) or,
    with --fallback-hw, move to hw. The target must be unaffected either way."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return skip("ret-probe", "uhh_trace/probe_app missing")
    import struct
    data = Path(t).read_bytes()
    x86 = struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0] == 0x14C
    nt = Path(r"C:\Windows\SysWOW64\ntdll.dll") if x86 else SYS32 / "ntdll.dll"
    stub = pe_export_bytes(nt, "NtOpenProcess", 32) or b""
    anchor_bytes, ret_ops = (b"\xff\xd2", (0xC2, 0xC3)) if x86 else (b"\x0f\x05", (0xC3,))
    i = stub.find(anchor_bytes)
    off = next((k for k in range(i + len(anchor_bytes), len(stub)) if stub[k] in ret_ops), None) if i >= 0 else None
    if off is None:
        return record("ret-probe", False, f"no ret found in NtOpenProcess stub: {stub.hex()}")
    site = f"ntdll.dll!NtOpenProcess+0x{off:x}"
    helpers = 4
    for bk, extra in (("breakpoint", []), ("hw", []), ("inline", []), ("inline", ["--fallback-hw"])):
        name = f"ret-probe-{bk}{'-fallback' if extra else ''}"
        try:
            r, objs = run([t, "--backend", bk, *extra, "-p", f"{site}:x", "--", a, "--no-wait", "--helpers", helpers,
                           "--threads", threads, "--reads", reads, "--config", "reads_enabled=1"], timeout=300)
            res = next((x for x in objs if x.get("kind") == "app"), {})
            pr = next((x for x in objs if x.get("kind") == "probe"), {})
            rep = report(objs)
            app_ok = res.get("opened") == helpers and res.get("successful_reads") == threads * reads
            if bk == "inline" and not extra:
                ok = r.returncode != 0 and "would be written across" in (rep.get("error") or "") and "PROBE_ALLOW_UNSAFE_SITE" in (rep.get("error") or "") and not pr.get("hits")
            else:
                want_bk = "hw" if extra else bk
                ok = app_ok and pr.get("backend") == want_bk and pr.get("hits") == helpers
            record(name, ok, f"site={site} backend={pr.get('backend')} hits={pr.get('hits')} opened={res.get('opened')} "
                             f"reads={res.get('successful_reads')} rc={r.returncode} err={(rep.get('error') or '')[:120]}")
        except Exception as e:
            record(name, False, repr(e))


def check_shared_mix(threads=8, reads=1000):
    """UHH_SHARED: the open probe and the read probe on DIFFERENT backends -- one runs in
    the controller, the other inside the target -- still build and use ONE handle->pid
    map (a shared section of the callbacks DLL). Every read must be logged with the right
    helper pid (unmapped == 0), hits == logs == reads, nothing dropped."""
    if not exe("gated_config.exe"):
        return skip("shared-mix", "gated_config.exe missing")
    want = threads * reads
    for open_bk, read_bk in (("breakpoint", "inline"), ("inline", "breakpoint"), ("hw", "inline"), ("inline", "hw")):
        name = f"shared-mix open={open_bk} read={read_bk}"
        try:
            r, o = gated("breakpoint", read_bk, threads, reads, open_bk=open_bk)
            rd, op = read_probe(o), open_probe(o)
            logs, dropped = read_logs(o)
            ok = (r.returncode == 0 and rd.get("hits") == want and logs == want and dropped == 0 and
                  unmapped(o) == 0 and logged_pids(o) == helper_pids(o) and
                  rd.get("backend") == read_bk and op.get("backend") == open_bk)
            record(name, ok, f"read_hits={rd.get('hits')} logs={logs} dropped={dropped} unmapped={unmapped(o)} "
                             f"pids_ok={logged_pids(o) == helper_pids(o)} backends={op.get('backend')}/{rd.get('backend')} "
                             f"err={(report(o).get('error') or '')[:100]}")
        except Exception as e:
            record(name, False, repr(e))


def check_forwarded_probe():
    """A probe on a FORWARDED export (kernel32!HeapAlloc -> ntdll!RtlAllocateHeap) lands on
    the forward target, on every backend; the target is unaffected."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return skip("forwarded-probe", "uhh_trace/probe_app missing")
    for bk in ("breakpoint", "hw", "inline"):
        name = f"forwarded-probe-{bk}"
        try:
            r, objs = run([t, "--backend", bk, "-p", "kernel32.dll!HeapAlloc:-", "--",
                           a, "--no-wait", "--helpers", 2, "--threads", 2, "--reads", 50,
                           "--config", "reads_enabled=1"], timeout=300)
            pr = next((x for x in objs if x.get("kind") == "probe"), {})
            res = next((x for x in objs if x.get("kind") == "app"), {})
            ok = (r.returncode == 0 and (pr.get("hits") or 0) > 0 and pr.get("backend") == bk and
                  res.get("successful_reads") == 100 and report(objs).get("error") is None)
            record(name, ok, f"hits={pr.get('hits')} backend={pr.get('backend')} reads={res.get('successful_reads')} "
                             f"err={(report(objs).get('error') or '')[:100]}")
        except Exception as e:
            record(name, False, repr(e))


def check_gated_mem(threads=8, reads=1000):
    """gated_config_mem: the disabled flag is flipped in the target's MEMORY (set_mem on the
    stored config at ParseConfig+0x18) instead of a register. Every flag backend; exactly
    one flip; the feature then runs and every read is logged with its pid."""
    d = exe("gated_config_mem.exe")
    if not d:
        return skip("gated-mem", "gated_config_mem.exe missing")
    want = threads * reads
    for flag_bk, read_bk in (("breakpoint", "inline"), ("hw", "inline"), ("inline", "inline"), ("inline", "breakpoint")):
        name = f"gated-mem flag={flag_bk} read={read_bk}"
        try:
            r, o = run([d, "--flag-backend", flag_bk, "--read-backend", read_bk,
                        "configparse.dll!ParseConfig+0x18", READ_LOCATION, "--", exe("probe_app.exe"),
                        "--no-wait", "--helpers", HELPERS, "--threads", threads, "--reads", reads], timeout=200)
            flips = sum(1 for x in o if x.get("kind") == "probe_log" and
                        str(x.get("message", "")).startswith("flag flipped in memory"))
            a, rd = app(o), read_probe(o)
            logs, dropped = read_logs(o)
            ok = (r.returncode == 0 and flips == 1 and a.get("reads_enabled") == 1 and
                  a.get("successful_reads") == want and rd.get("hits") == want and logs == want and
                  dropped == 0 and unmapped(o) == 0 and report(o).get("overrides") == 0)
            record(name, ok, f"flips={flips} reads_enabled={a.get('reads_enabled')} reads={a.get('successful_reads')} "
                             f"hits={rd.get('hits')} logs={logs} dropped={dropped} unmapped={unmapped(o)} "
                             f"overrides={report(o).get('overrides')} err={(report(o).get('error') or '')[:100]}")
        except Exception as e:
            record(name, False, repr(e))


def check_crash_logs(n=5000):
    """Log delivery when the TARGET crashes: after n probed calls (one log each) it dies
    with an unhandled access violation. Every log must still arrive -- for inline they
    sit in the shared ring at the moment of death -- and none may be counted as dropped."""
    d, t = exe("hitcost_driver.exe"), exe("hitcost_target.exe")
    if not d or not t:
        return skip("crash-logs", "hitcost driver/target missing")
    for bk in ("inline", "hw", "breakpoint"):
        try:
            _, o = run([d, "--backend", bk, "--method", "send_log", "--", t, "--calls", n * 10, "--threads", 1,
                        "--crash-after", n], timeout=300)
            rep = report(o)
            logs = sum(1 for x in o if x.get("kind") == "probe_log" and str(x.get("message", "")).startswith("hit "))
            pr = next(iter(probes(o)), {})
            ok = (rep.get("app_exit") == 0xC0000005 and pr.get("hits") == n and logs == n and rep.get("log_dropped") == 0)
            record(f"crash-logs-{bk}", ok, f"exit=0x{(rep.get('app_exit') or 0):x} hits={pr.get('hits')} logs={logs}/{n} "
                                           f"dropped={rep.get('log_dropped')}")
        except Exception as e:
            record(f"crash-logs-{bk}", False, repr(e))


def check_attach_new():
    """probe_attach_new: ignore an already-running instance, attach to the NEXT one started,
    observe all of its reads; and fail cleanly (error, non-zero exit) on timeout."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return skip("attach-new", "uhh_trace/probe_app missing")
    import re, time
    decoy = target = None
    try:
        decoy = subprocess.Popen([str(a), "--config", "reads_enabled=1"], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.5)
        tracer = subprocess.Popen([str(t), "--backend", "hw", "--attach-new", "probe_app.exe", "--timeout", "20000",
                                   "-p", "probe_app.exe!ReadThunk:xxxx"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1.0)
        threads, reads = 2, 500
        target = subprocess.Popen([str(a), "--threads", str(threads), "--reads", str(reads), "--config", "reads_enabled=1"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2.0)                                          # attach lands while it waits at its gate
        target.stdin.write(b"\n"); target.stdin.flush()
        t_app = time.time()
        lines_until(target, '"kind":"app"', 120)                 # keep its pipe drained
        t_app = time.time() - t_app
        try:
            out, err = tracer.communicate(timeout=180)           # returns when the target exits
        except subprocess.TimeoutExpired:
            tracer.kill(); out, err = tracer.communicate()
        try:
            target.wait(timeout=60)
        except subprocess.TimeoutExpired:
            pass
        err = (err or "") + f" | secs_to_app_line={t_app:.1f}"
        m = re.search(r"new probe_app\.exe pid (\d+)", err or "")
        objs = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
        pr = next((o for o in objs if o.get("kind") == "probe"), {})
        ok = (m is not None and int(m.group(1)) == target.pid and pr.get("hits") == threads * reads and
              target.returncode == 0)
        if not ok:
            err = f"target_rc={target.returncode} | " + (err or "")
        record("attach-new", ok, f"attached_pid={m.group(1) if m else None} target_pid={target.pid} "
                                 f"decoy_pid={decoy.pid} hits={pr.get('hits')}/{threads * reads}"
                                 + ("" if ok else " stderr=" + " | ".join((err or "").strip().splitlines()[:8])))
    except Exception as e:
        record("attach-new", False, repr(e))
    finally:
        for p_ in (decoy, target):
            if p_ and p_.poll() is None:
                p_.kill()
    try:
        r, o = run([t, "--attach-new", "no_such_process_uhh.exe", "--timeout", "1500", "-p", "x.dll!y"], timeout=60)
        ok = r.returncode != 0 and "no new no_such_process_uhh.exe appeared" in (r.stderr or "")
        record("attach-new-timeout", ok, f"rc={r.returncode}")
    except Exception as e:
        record("attach-new-timeout", False, repr(e))


def check_refusals(calls=2000):
    """Unsupported/excess probes are refused cleanly (0 + error) and do not disturb the
    rest; 4 hardware probes on one function (the debug-register limit) each count every
    call exactly."""
    d, t = exe("refusal_driver.exe"), exe("hitcost_target.exe")
    if not d or not t:
        return skip("refusals", "refusal_driver/hitcost_target missing")
    try:
        _, o = run([d, "--", t, "--calls", calls, "--threads", 1], timeout=300)
        r = next((x for x in o if x.get("kind") == "refusals"), {})
        ok = (r.get("at_return") == 0 and r.get("inline_once") == 0 and r.get("two_types") == 0 and
              r.get("watch_on_bp") == 0 and r.get("inline33") == 0 and r.get("hw4") == 1 and r.get("hw5") == 0 and
              r.get("hits") == [calls] * 4 and r.get("run_ok") == 1)
        record("refusals", ok, json.dumps(r))
    except Exception as e:
        record("refusals", False, repr(e))


def pe_export_bytes(path, name, n=8):
    """First n bytes of an exported function, read from the DLL FILE (no loading)."""
    import struct
    data = Path(path).read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dd = opt + (96 if magic == 0x10B else 112)
    exp_rva = struct.unpack_from("<I", data, dd)[0]
    secs = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]

    def off(rva):
        for i in range(nsec):
            vs, va, raw_sz, raw = struct.unpack_from("<IIII", data, secs + 40 * i + 8)
            if va <= rva < va + raw_sz:                  # file-backed part of the section only
                return raw + (rva - va)
        return None
    e = off(exp_rva)
    nfun, nnames, afun, anames, aords = struct.unpack_from("<IIIII", data, e + 20)
    for i in range(nnames):
        nm_rva = struct.unpack_from("<I", data, off(anames) + 4 * i)[0]
        o = off(nm_rva)
        nm = data[o:data.index(b"\0", o)].decode()
        if nm == name:
            ordinal = struct.unpack_from("<H", data, off(aords) + 2 * i)[0]
            frva = struct.unpack_from("<I", data, off(afun) + 4 * ordinal)[0]
            return data[off(frva):off(frva) + n]
    return None


def check_hotpatch_prologue():
    """x86 system DLL functions begin with the 2-byte hot-patch prologue `mov edi,edi`
    (8B FF). An inline probe there must work: KernelBase!CreateFileW in the shipped 32-bit
    curl.exe, args logged correctly, curl unaffected. (x86 builds only.)"""
    t = exe("uhh_trace.exe")
    if not t:
        return skip("hotpatch", "uhh_trace missing")
    import struct
    data = Path(t).read_bytes()
    machine = struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0]
    if machine != 0x14C:
        return skip("hotpatch-prologue", "x86-only (32-bit system DLLs carry the hot-patch prologue)")
    kb = Path(r"C:\Windows\SysWOW64\KernelBase.dll")
    curl = Path(r"C:\Windows\SysWOW64\curl.exe")
    if not kb.exists() or not curl.exists():
        return skip("hotpatch-prologue", "SysWOW64 KernelBase/curl missing")
    try:
        head = pe_export_bytes(kb, "CreateFileW") or b""
        r, o = run([t, "--backend", "inline", "-p", "KernelBase.dll!CreateFileW:Wxx", "--",
                    curl, "-s", "-o", "NUL", "file:///C:/Windows/win.ini"], timeout=120)
        msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
        pr = next(iter(probes(o)), {})
        hit = any("win.ini" in m for m in msgs)
        ok = (head[:2] == b"\x8b\xff" and pr.get("backend") == "inline" and hit and
              report(o).get("app_exit") == 0 and report(o).get("error") is None)
        record("hotpatch-prologue-inline", ok, f"prologue={head[:5].hex(' ')} backend={pr.get('backend')} "
                                               f"logged_win_ini={hit} exit={report(o).get('app_exit')}")
    except Exception as e:
        record("hotpatch-prologue-inline", False, repr(e))


def check_prehook_attach():
    """The realistic 'already hooked' case: attach to a process that detoured one of its own
    functions at run time (probe_app --prehook puts a SafetyHook inline detour on ReadThunk
    before its gate). An inline probe there must produce the pre-hook report (live bytes
    differ from the image on disk: pattern, symbolized destination, suggestions) and, with
    PROBE_FALLBACK_HW (uhh_trace --fallback-hw), move to the hardware backend."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return skip("prehook-attach", "uhh_trace/probe_app missing")
    import time
    target = None
    try:
        target = subprocess.Popen([str(a), "--prehook", "--helpers", "1"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        line = target.stdout.readline().decode(errors="replace")       # {"kind":"waiting",...}: hook is in
        tracer = subprocess.Popen([str(t), "--backend", "inline", "--fallback-hw", "--attach", str(target.pid),
                                   "-p", "probe_app.exe!ReadThunk:xxxx"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(3.0)                                                  # attach + vet
        target.stdin.write(b"\n"); target.stdin.flush()
        target.wait(timeout=60)
        out, err = tracer.communicate(timeout=60)
        objs = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
        pre = [o for o in objs if o.get("kind") == "prehook"]
        pr = next((o for o in probes(objs) if o.get("location", "").endswith("!ReadThunk")), {})
        ok = (bool(pre) and "jmp" in pre[0].get("pattern", "") and bool(pre[0].get("destination")) and
              "probe_app" in str(pre[0].get("destination")) and
              len(pre[0].get("suggest", [])) >= 2 and pr.get("backend") == "hw")
        tail = "" if ok else " stderr=" + " | ".join(err.strip().splitlines()[:12])
        record("prehook-attach", ok, f"reports={len(pre)} pattern={pre[0].get('pattern') if pre else None} "
                                     f"dest={pre[0].get('destination') if pre else None} backend={pr.get('backend')}{tail}")
    except Exception as e:
        record("prehook-attach", False, repr(e))
    finally:
        if target and target.poll() is None:
            target.kill()


def check_realworld():
    """Real shipped Windows binaries, real system-DLL exports, via uhh_trace. Each case
    asserts the logged ARGUMENTS match what the program demonstrably did."""
    t = exe("uhh_trace.exe")
    if not t:
        return skip("realworld", "uhh_trace.exe missing")
    cases = [
        # (name, probes, argv, regex that must appear in some probe_log message)
        ("curl-file-open", ["KernelBase.dll!CreateFileW:Wxx"],
         [SYS32 / "curl.exe", "-s", "-o", "NUL", "file:///C:/Windows/win.ini"], r"CreateFileW\(\".*win\.ini\""),
        ("curl-connect", ["ws2_32.dll!connect:xSd"],
         [SYS32 / "curl.exe", "-s", "--connect-timeout", "3", "http://127.0.0.1:9/"], r"connect\(0x[0-9a-f]+, 127\.0\.0\.1:9,"),
        ("findstr-open", ["ntdll.dll!NtCreateFile:xxO"],
         [SYS32 / "findstr.exe", "/c:fonts", r"C:\Windows\win.ini"], r"NtCreateFile\(.*\"[^\"]*\\Windows\\win\.ini\""),
    ]
    import re
    for name, specs, argv, pattern in cases:
        if not Path(argv[0]).exists():
            skip(f"realworld-{name}", f"{argv[0]} missing"); continue
        for bk in ("breakpoint", "hw", "inline"):
            label = f"realworld-{name}-{bk}"
            try:
                cmd = [t, "--backend", bk]
                for sp in specs:
                    cmd += ["-p", sp]
                _, o = run(cmd + ["--", *argv], timeout=120)
                msgs = [x.get("message", "") for x in o if x.get("kind") == "probe_log"]
                hit = next((m for m in msgs if re.search(pattern, m)), None)
                rep = report(o)
                got = sorted({x.get("backend") for x in probes(o)})
                ok = hit is not None and rep.get("error") is None and got == [bk]   # exactly the backend asked for
                record(label, ok, f"logs={len(msgs)} backends={got} match={hit[:70] if hit else None} err={rep.get('error')}")
            except Exception as e:
                record(label, False, repr(e))


def main():
    global BIN
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", type=Path, default=Path("build-x64/Release"))
    ap.add_argument("--threads", default="8")
    ap.add_argument("--reads", default="1000")
    ap.add_argument("--volume-reads", default="0",
                    help="per-thread reads for the opt-in no-drop-at-scale tier (e.g. 250000 = 2M); 0 skips")
    ap.add_argument("--only", default="", help="comma-separated substrings of check names to run (default: all)")
    args = ap.parse_args()
    BIN = args.bin.resolve()
    only = [x for x in args.only.split(",") if x]

    import os as _os

    def sweep_logs():
        """Every UHH session keeps its log file (%TEMP%\\uhh\\logs\\uhh-*.jsonl) -- that is the
        product. The suite runs hundreds of sessions (some with 20M logs), so it deletes the
        files it produced after each check; a file still open by a live session is skipped."""
        d = Path(_os.environ.get("TEMP", ".")) / "uhh" / "logs"
        for f in d.glob("uhh-*.jsonl") if d.is_dir() else []:
            try:
                f.unlink()
            except OSError:
                pass

    def want(fn):
        sweep_logs()
        return not only or any(o in fn.__name__ for o in only)
    print(f"UHH regression suite — bin={BIN}")
    if want(check_sites): check_sites()
    if want(check_gated_off): check_gated_off()
    if want(check_mix_matrix): check_mix_matrix(args.threads, args.reads)
    if want(check_multithread_exact): check_multithread_exact(args.threads, args.reads)
    if want(check_log_throughput): check_log_throughput(args.threads, args.reads)
    if want(check_stream_volume): check_stream_volume()
    if want(check_stream_sink_speed): check_stream_sink_speed()
    if want(check_stream_live): check_stream_live()
    if want(check_stream_latency): check_stream_latency()
    if want(check_stream_order): check_stream_order()
    if want(check_attach): check_attach(args.threads, args.reads)
    if int(args.volume_reads) > 0:
        if want(check_volume): check_volume(args.volume_reads)
    if want(check_breakage): check_breakage()
    if want(check_frida_parity): check_frida_parity()
    if want(check_watchpoint): check_watchpoint()
    if want(check_dynwatch): check_dynwatch()
    if want(check_realworld): check_realworld()
    if want(check_conformance): check_conformance()
    if want(check_prehook_attach): check_prehook_attach()
    if want(check_memstress): check_memstress()
    if want(check_symbols): check_symbols()
    if want(check_realworld_targets): check_realworld_targets()
    if want(check_frida_coexist): check_frida_coexist()
    if want(check_sidefx): check_sidefx()
    if want(check_detach): check_detach()
    if want(check_ntdll_churn): check_ntdll_churn()
    if want(check_patch_race): check_patch_race()
    if want(check_emulated_sites): check_emulated_sites()
    if want(check_ret_probe): check_ret_probe()
    if want(check_shared_mix): check_shared_mix()
    if want(check_gated_mem): check_gated_mem()
    if want(check_forwarded_probe): check_forwarded_probe()
    if want(check_crash_logs): check_crash_logs()
    if want(check_attach_new): check_attach_new()
    if want(check_refusals): check_refusals()
    if want(check_hotpatch_prologue): check_hotpatch_prologue()
    print("-" * 72)
    failed = 0
    for name, status, detail in RESULTS:
        print(f"  {status:4}  {name:34} {detail}")
        if status == "FAIL":
            failed += 1
    print("-" * 72)
    skipped = sum(1 for _, st, _ in RESULTS if st == "SKIP")
    passed = sum(1 for _, st, _ in RESULTS if st == "PASS")
    print(f"{passed}/{passed + failed} ok, {failed} failed, {skipped} skipped (not applicable to this build)")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
