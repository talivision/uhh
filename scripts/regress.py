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
  - famous-<recipe>-<backend>: the examples/famous recipes (heap tracker, file monitor
    incl. attach mid-run and findstr, TLS plaintext via curl.exe, loader/RWX signals,
    return-value override), each compared with the uninstrumented run of its target.
  - detours-*: Microsoft Detours samples replicated (examples/famous): simple (SleepEx
    counter), traceapi (decoded file/registry/process/module APIs on detours_target and on
    cmd/reg), withdll (launch trace == attach trace; attach mid-run + detach), retval (return
    values via a return-address probe + call_func GetLastError), launch-stdin. Every one
    compares against the uninstrumented run.
Missing binaries (an example not built) are reported as SKIP, not FAIL.
"""
import argparse
import json
import math
import os
import re
import shutil
import struct
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


def live(result):
    """Each result as it is recorded (timestamped), so a run can be followed in flight;
    the full table is printed again at the end."""
    name, status, detail = result
    print(f"[{time.strftime('%H:%M:%S')}] {status:4}  {name:34} {detail}", flush=True)


def record(name, ok, detail=""):
    RESULTS.append((name, "PASS" if ok else "FAIL", detail))
    live(RESULTS[-1])


def skip(name, why):
    """A check that could not run. A missing binary is a FAILURE (a partial build must never
    look green); only a check that does not apply to this build (e.g. x86-only) is a SKIP,
    and a SKIP is never counted as a pass."""
    status = "FAIL" if "missing" in why else "SKIP"
    RESULTS.append((name, status, why))
    live(RESULTS[-1])


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


def gated(flag_bk, read_bk, threads, reads, timeout=200, log=True, open_bk=None, target_args=(), extra=()):
    return run([exe("gated_config.exe"), "--flag-backend", flag_bk, "--read-backend", read_bk,
                *(["--open-backend", open_bk] if open_bk else []),
                *([] if log else ["--no-log"]), *extra, FLAG_LOCATION, READ_LOCATION,
                "--", exe("probe_app.exe"), "--no-wait", "--helpers", HELPERS,
                "--threads", threads, "--reads", reads, *target_args], timeout=timeout)


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
    """(C16) Hostile inline sites: every row has ONE required outcome -- the target behaves
    exactly as uninstrumented (each probe hit once, the target's own result check passes:
    exit 0), or UHH refuses the probe cleanly with a reason (no hit, target not corrupted).
    Any other outcome (wrong return, fault, missed/double hit) fails. The uninstrumented
    baseline of every case must exit 0 too, so 'exit 0' really means 'same as without UHH'."""
    d, h = exe("breakage_driver.exe"), exe("hook_edge.exe")
    if not d or not h:
        return skip("breakage", "breakage_driver/hook_edge missing")
    required = {
        ("ShortSite", "breakpoint"): "pass", ("ShortSite", "hw"): "pass",
        ("PrehookSite", "breakpoint"): "pass", ("PrehookSite", "hw"): "pass",
        ("UnrelocSite", "breakpoint"): "pass", ("UnrelocSite", "hw"): "pass",
        ("StackSite", "breakpoint"): "pass", ("StackSite", "hw"): "pass",
        ("StackInsideSite", "breakpoint"): "pass", ("StackInsideSite", "hw"): "pass",
        ("ShortSite", "inline"): "refused",                    # 5 bytes would run past the ret
        ("PrehookSite", "inline"): "pass",                     # PROBE_ALLOW_PREHOOKED: chains (1017)
        ("PrehookSite", "inline-default"): "pass",             # E9 also on disk: chained like ALLOW_PREHOOKED
        ("PrehookSite", "inline-fallback"): "pass",            # -> hw
        ("UnrelocSite", "inline"): "refused",                  # jrcxz/jecxz: rel8-only, not relocatable
        ("StackSite+StackSite", "inline"): "refused",          # second hook at the same address
        ("StackSite+StackInsideSite", "inline"): "refused",    # inner site inside the outer patch
    }
    try:
        for case in ("short", "prehook", "unreloc", "stack"):
            b = subprocess.run([str(h), "--case", case], input=b"x", capture_output=True, timeout=60)
            record(f"breakage-baseline-{case}", b.returncode == 0, f"uninstrumented exit={b.returncode}")
        r = rvas("hook_edge.map", "ShortSite", "PrehookSite", "UnrelocSite", "StackSite", "StackInsideSite")
        res, o = run([d, h, r["ShortSite"], r["PrehookSite"], r["UnrelocSite"], r["StackSite"], r["StackInsideSite"]],
                     timeout=300)
        rows = {(row.get("site"), row.get("backend")): row for row in o if "verdict" in row}
        for key, want in required.items():
            row = rows.get(key, {})
            ok = row.get("verdict") == want and row.get("required") == want
            if want == "refused":
                ok = ok and "refused" in (row.get("error") or "")
            record(f"breakage {key[0]}/{key[1]}", ok,
                   f"verdict={row.get('verdict')} want={want} hits={row.get('hits')} exit={row.get('app_exit')} "
                   f"err={(row.get('error') or '')[:160]}")
        record("breakage-driver", res.returncode == 0 and len(rows) == len(required),
               f"rc={res.returncode} rows={len(rows)}/{len(required)}")
    except Exception as e:
        record("breakage-driver", False, repr(e))


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
                  tgt.get("sp_moved") == 10 and   # set_reg(SP) honoured on every backend
                  stack_ok and report(o).get("error") is None and report(o).get("log_dropped") == 0 and
                  later == 20 and once == 1 and once_row.get("hits") == 1 and watch_row.get("hits") == 3 and
                  len(hw_rows) == 2)
            record(name, ok, f"fails={fails[:3]} missing={missing} sp_moved={tgt.get('sp_moved')}/10 arg_rewritten={tgt.get('arg_rewritten')} "
                             f"mem_written={tgt.get('mem_written')} stack_ok={stack_ok} later={later}/20 once={once}/1 "
                             f"once_row={once_row.get('hits')}/{once_row.get('active')} watch_row={watch_row.get('hits')}")
        except Exception as e:
            record(name, False, repr(e))


def check_callorig():
    """call_original / return_from on every backend (conformance_driver --callorig): arguments
    changed before call_original (a register arg and a stack arg) are what the original sees;
    its return value comes back; return_from's value is what the caller gets; a pure
    return_from never runs the body and call_original + return_from runs it exactly once;
    x86 __stdcall return_from(.., 2) leaves the caller's ESP balanced, cdecl uses nargs=0."""
    d, t = exe("conformance_driver.exe"), exe("conformance_target.exe")
    if not d or not t:
        return skip("callorig", "conformance_driver/target missing")
    for bk in ("breakpoint", "hw", "inline"):
        name = f"callorig-{bk}"
        try:
            r, o = run([d, "--callorig", "--backend", bk, "--", t, "--callorig"], timeout=120)
            msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
            fails = sorted({m for m in msgs if m.startswith("FAIL") or "uhh warning" in m})
            tgt = next((x for x in o if x.get("kind") == "callorig"), {})
            ok = (r.returncode == 0 and not fails and all(tgt.get(k) == 10 for k in ("args6", "std2", "std2_sp", "cdecl2", "body_ok"))
                  and report(o).get("error") is None)
            record(name, ok, f"target={ {k: v for k, v in tgt.items() if k != 'kind'} } fails={fails[:3]} rc={r.returncode}")
        except Exception as e:
            record(name, False, repr(e))


CO_CASES = ("recurse", "cppthrow", "seh", "longjmp", "threads", "mid", "nargs", "conv", "retaddr",
            "prologue", "nested", "vslow")


def co_expect(case, base, x86):
    """The target row a callorig-hunt case must print under instrumentation (from the
    uninstrumented row), the exact probe hits and the exact "co ..." log counts."""
    row, hits, logs = dict(base), {}, {}
    if case == "recurse":
        hits = {"co_fact": 40}; logs = {"co fact": 5, "co fact-done": 5}
    elif case == "cppthrow":
        hits = {"co_throw": 10, "co_after": 3}; logs = {"co throw": 10, "co throw-done": 5, "co after": 3}
    elif case == "seh":
        hits = {"co_seh": 9, "co_after": 3}; logs = {"co seh": 9, "co seh-done": 3, "co after": 3}
    elif case == "longjmp":
        hits = {"co_jump": 10, "co_after": 3}; logs = {"co jump": 10, "co jump-done": 5, "co after": 3}
    elif case == "threads":
        hits = {"co_add": 4800}; logs = {"co add": 4800, "co add-done": 4800}
    elif case == "mid":
        hits = {"CoMidPush+0x1": 5}; logs = {"co mid ok=0": 5}
    elif case == "nargs":
        row["sum"] = base["sum"] + 20 * 1000
        hits = {"co_add": 20}; logs = {"co nargs": 20, "co nargs-done": 20}
    elif case == "conv":
        row["fast"] = base["fast"] + 5
        row["args8"] = base["args8"] + 8 * sum(100 - (8 + i) for i in range(5))
        hits = {"co_fast": 5, "co_args8": 5}
        logs = {"co fast": 5, "co fast-done": 5, "co args8": 5, "co args8-done": 5}
        if x86:
            row["this"] = base["this"] + 5
            hits["CoThis"] = 5; logs.update({"co this": 5, "co this-done": 5})
    elif case == "retaddr":
        hits = {"co_ret": 6}; logs = {"co ret": 6, "co ret-done": 6}
    elif case == "prologue":
        row["sum"] = 77 * 5
        hits = {"CoPrologue": 5}; logs = {"co prologue": 5}
    elif case == "nested":
        hits = {"co_outer": 6, "co_inner": 6}; logs = {"co outer": 6, "co outer-done": 6, "co inner": 0}
    elif case == "vslow":   # an original running past the 5 s call limit (breakpoint/hw: released)
        hits = {"co_vslow": 1, "co_after": 3}; logs = {"co vslow": 1, "co vslow-done": 1, "co after": 3}
    return row, hits, logs


def check_callorig_hunt():
    """call_original / return_from edge cases (examples/hunt_callorig), every backend: a
    recursive original; C++ throw, SEH raise/AV and longjmp out of the original (the target's
    own handler gets it, the body runs once, later probes on the same thread still fire);
    16 threads on one probe; mid-function refusal; nargs larger than real; x86 fastcall /
    thiscall and x64 8 args; a probe at the return-to address; return_from over a callee-
    saved prologue; a probe inside the original (same backend: counted, no callback; another
    backend: fires); detach and Ctrl+Break while call_original is in flight. Each run's target
    row is compared with the uninstrumented run; hits and "co" logs are exact; nothing dropped."""
    d, t = exe("co_driver.exe"), exe("co_target.exe")
    if not d or not t:
        return skip("callorig-hunt", "co_driver/co_target missing")
    x86 = "x86" in str(BIN).lower() or "win32" in str(BIN).lower()

    def co_row(objs):
        return next((x for x in objs if x.get("kind") == "co"), {})

    def co_logs(objs):
        cnt = {}
        for x in objs:
            m = str(x.get("message", ""))
            if x.get("kind") == "probe_log" and m.startswith("co "):
                cnt[m] = cnt.get(m, 0) + 1
        return cnt

    def hits_by(objs):
        out = {}
        for p in probes(objs):
            loc = str(p.get("location", ""))
            out[loc.split("!", 1)[-1] if "!" in loc else loc] = p.get("hits")
        return out

    bases = {}
    for case in CO_CASES + ("slow",):
        r, o = run([t, case], timeout=60)
        bases[case] = co_row(o)
    runs = [(c, bk, bk) for c in CO_CASES for bk in ("breakpoint", "hw", "inline")]
    runs += [("nested", a, b) for a, b in (("breakpoint", "inline"), ("inline", "breakpoint"), ("hw", "inline"))]
    for case, bk, inner in runs:
        name = f"callorig-hunt-{case}-{bk}" + (f"+{inner}" if inner != bk else "")
        try:
            r, o = run([d, "--backend", bk, "--inner-backend", inner, "--case", case, "--", t, case], timeout=300)
            base = bases[case]
            want_row, want_hits, want_logs = co_expect(case, base, x86)
            if case == "nested" and inner != bk:
                want_logs["co inner"] = 6
            if case == "vslow" and bk != "inline":
                want_logs["co vslow-done"] = 0      # released: the callback ends, the program is unaffected
            row, logs, hb, rep = co_row(o), co_logs(o), hits_by(o), report(o)
            row.pop("kind", None); want_row.pop("kind", None)
            got_logs = {k: logs.get(k, 0) for k in want_logs}
            extra = sorted(k for k in logs if k not in want_logs and not (case == "retaddr" and k == "co retsite"))
            ok = (bool(base) and row == want_row and all(hb.get(k) == v for k, v in want_hits.items()) and
                  got_logs == want_logs and not extra and rep.get("log_dropped") == 0 and
                  rep.get("callbacks_interrupted", 0) == 0 and rep.get("error") is None and
                  rep.get("app_exit") == 0 and r.returncode == 0)
            if case == "retaddr":   # the return-site probe: one log per hit, every return after it arms
                rs = next((v for k, v in hb.items() if k.startswith("0x") or k not in ("co_ret",)), None)
                ok = ok and rs is not None and rs == logs.get("co retsite", 0) and rs >= 5
            record(name, ok, f"row={row} want={want_row} hits={hb} logs={got_logs} extra={extra[:3]} "
                             f"dropped={rep.get('log_dropped')} intr={rep.get('callbacks_interrupted')} "
                             f"err={rep.get('error')} rc={r.returncode}")
        except Exception as e:
            record(name, False, repr(e))
    # Detach (probe_close from another thread) and Ctrl+Break while call_original is in flight:
    # the attached target finishes every call correctly, unhooked from then on.
    import signal
    for bk in ("breakpoint", "hw", "inline"):
        for how in ("detach", "ctrlbreak"):
            name = f"callorig-hunt-{how}-{bk}"
            procs = []
            try:
                tgt = subprocess.Popen([str(t), "slow", "--wait"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, text=True)
                procs.append(tgt)
                tout = Lines(tgt.stdout)
                w = tout.wait_for(lambda l: '"kind":"waiting"' in l, 30)
                if not w:
                    raise RuntimeError("target never reached its gate")
                args = [str(d), "--backend", bk, "--case", "slow", "--attach", str(json.loads(w)["pid"])]
                if how == "detach":
                    args += ["--detach-after", "1300"]
                att = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
                procs.append(att)
                aout, aerr = Lines(att.stdout), Lines(att.stderr)
                if not aerr.wait_for(lambda l: l.startswith("probe: active co_target.exe!co_slow"), 60):
                    raise RuntimeError("co_slow never became active")
                tgt.stdin.write("x"); tgt.stdin.flush()
                if how == "ctrlbreak":
                    if not aout.wait_for(lambda l: '"message":"co slow"' in l, 30):
                        raise RuntimeError("no call_original was logged")
                    time.sleep(0.1)                         # mid-way through a 250 ms original
                    att.send_signal(signal.CTRL_BREAK_EVENT)
                att.wait(timeout=120)
                tgt.wait(timeout=120)
                row = co_row(tout.objs()); row.pop("kind", None)
                want = dict(bases["slow"]); want.pop("kind", None)
                # The session must really have ended mid-run: some calls instrumented, not all 12.
                started = sum(1 for l in aout.lines if '"message":"co slow"' in l)
                ok = (att.returncode == 0 and tgt.returncode == 0 and row == want and bool(want) and
                      1 <= started < 12)
                record(name, ok, f"row={row} want={want} tool_rc={att.returncode} target_rc={tgt.returncode} "
                                 f"instrumented_calls={started}/12")
            except Exception as e:
                record(name, False, repr(e))
            finally:
                for q in procs:
                    if q.poll() is None:
                        q.kill()


CC_NAMES = ["CcCdecl0", "CcCdecl3", "CcStd3", "CcStd10", "CcFast4", "CcThisGet", "CcVec", "CcI64", "CcStdI64",
            "CcS12", "CcS8", "CcDbl", "CcFlt", "CcRetBig", "CcRetBigStd", "CcRet8", "CcHot", "CcIlt",
            "CcImpThunk", "CcJmpDst"]          # = cc_shared.h's CC_FNS, in id order
CC_X86_ONLY = {"CcHot"}


def check_callconv():
    """Calling conventions (examples/callconv): ccfix.dll exports one function per x86/x64
    convention and argument/return shape -- cdecl, stdcall, fastcall, thiscall, vectorcall, 0
    and 10 arguments, 64-bit arguments (two x86 slots), structs by value, float/double
    arguments and ST0/XMM0 results, EDX:EAX results, hidden return pointers (cdecl and
    stdcall), an x86 hot-patch prologue, an incremental-link thunk, an import thunk and a
    tail-call jmp target. Every one is probed at entry on breakpoint, hw and inline and:
      wrap      get_func_arg/get_reg are what the caller passed; call_original's *ret is
                right; return_from(r, n) gives the caller exactly the original's result
                (EAX, EDX:EAX, ST0, XMM0, struct) and the body ran once;
      replace   return_from(v, n) without the body: the caller gets v (or the struct the
                callback wrote through the hidden pointer); float results fall through;
      wrongpop  call_original + return_from with a WRONG x86 nargs: the stack is still
                right (the measured pop wins) and the mismatch is warned (x86).
    cc_target checks every result and, on x86, the bytes popped and EBX/ESI/EDI/EBP. hw
    probes go in groups of 3 (4 debug registers, one kept free for call_original)."""
    d, t = exe("cc_driver.exe"), exe("cc_target.exe")
    if not d or not t:
        return skip("callconv", "cc_driver/cc_target missing")
    data = Path(t).read_bytes()          # the arch from the PE header (a path can say anything)
    x86 = struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0] == 0x14C
    ids = [i for i, n in enumerate(CC_NAMES) if x86 or n not in CC_X86_ONLY]

    def rows(objs):
        return [x for x in objs if x.get("kind") == "cct"], next((x for x in objs if x.get("kind") == "cct_sum"), {})

    try:
        r, o = run([t, "none"], timeout=60)
        rs, sm = rows(o)
        bad = [f"{x['name']}: {x['detail']}" for x in rs if not x.get("ok")]
        record("callconv-baseline", r.returncode == 0 and sm.get("fails") == 0 and len(rs) == len(ids),
               f"rows={len(rs)}/{len(ids)} bad={bad[:4]} rc={r.returncode}")
    except Exception as e:
        record("callconv-baseline", False, repr(e))
    for bk in ("breakpoint", "hw", "inline"):
        groups = [ids[k:k + 3] for k in range(0, len(ids), 3)] if bk == "hw" else [ids]
        for mode in ("wrap", "replace", "wrongpop"):
            name = f"callconv-{mode}-{bk}"
            problems, warned = [], 0
            try:
                for g in groups:
                    mask = f"{sum(1 << i for i in g):x}"
                    r, o = run([d, "--backend", bk, "--mode", mode, "--mask", mask, "--", t, mode, mask], timeout=120)
                    rs, sm = rows(o)
                    msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
                    hits = {}
                    for m in msgs:
                        if m.startswith("cc hit "):
                            hits[m[7:]] = hits.get(m[7:], 0) + 1
                    fails = [m for m in msgs if m.startswith("cc FAIL")]
                    warned += sum(1 for l in (r.stderr.splitlines() + msgs) if "popped" in l and "return_from" in l)
                    others = [m for m in msgs if "uhh warning" in m and "popped" not in m]
                    rep = report(o)
                    want_hits = {CC_NAMES[i]: 1 for i in g}
                    bad = [f"{x['name']}: {x['detail']}" for x in rs if not x.get("ok")]
                    if (r.returncode != 0 or sm.get("fails") != 0 or len(rs) != len(ids) or hits != want_hits or fails or
                            others or rep.get("error") is not None or rep.get("log_dropped") != 0):
                        problems.append(f"mask={mask} rc={r.returncode} target_bad={bad[:3]} cb_fails={fails[:3]} "
                                        f"hits={ {k: v for k, v in hits.items() if want_hits.get(k) != v} } "
                                        f"missing={[k for k in want_hits if k not in hits]} warn={others[:2]} "
                                        f"err={rep.get('error')} dropped={rep.get('log_dropped')} "
                                        f"probe_hits={ {str(p.get('location', '')).split('!')[-1]: p.get('hits') for p in probes(o)} } "
                                        f"stderr={r.stderr.strip().splitlines()[-3:]}")
                # x86: the wrong nargs is caught (warned once per probe whose pop it contradicts).
                if mode == "wrongpop" and x86 and not warned:
                    problems.append("no 'return_from ... popped' warning for the wrong nargs")
                record(name, not problems, "; ".join(problems)[:1500] if problems else f"groups={len(groups)} warned={warned}")
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
    # (C6) Tamper/debugger visibility. Both targets take a DIFFERENT path when they detect
    # instrumentation (the probed function is then called with -1 instead of its normal
    # argument). Asserted per backend against an uninstrumented baseline run:
    #   anti-tamper: INT3 (breakpoint) and inline change code bytes (seen vs the file on
    #     disk); hw changes no code byte but sets DR7 (seen via GetThreadContext).
    #   anti-debug: UHH launches every session as a debugger, so breakpoint, hw AND inline
    #     (whose controller is the debugger) are all visible. UHH does not hide it.
    def path_logs(o, fn):
        return [str(x.get("message")) for x in o if x.get("kind") == "probe_log" and str(x.get("message", "")).startswith(fn + "(")]
    x = exe("antitamper_target.exe")
    if x:
        calls = 100
        try:
            br = subprocess.run([str(x), "--no-wait", "--calls", str(calls)], capture_output=True, text=True, timeout=60)
            base = next((json.loads(l) for l in br.stdout.splitlines() if l.startswith("{")), {})
            ok = (br.returncode == 0 and base.get("path") == "clean" and base.get("detected_by") == "none" and
                  base.get("fn_disk_ok") is True and base.get("debug_registers_seen") is False)
            record("antitamper-baseline", ok, f"path={base.get('path')} detected_by={base.get('detected_by')} "
                                              f"fn_disk_ok={base.get('fn_disk_ok')} dr_seen={base.get('debug_registers_seen')}")
        except Exception as e:
            record("antitamper-baseline", False, repr(e))
        for bk, by in (("breakpoint", "code"), ("inline", "code"), ("hw", "debug_registers")):
            try:
                r, o, tg = trace_run(x, ["antitamper_target.exe!guarded_fn:d"], bk, ("--calls", str(calls)))
                pr = next(iter(probes(o)), {})
                logs = path_logs(o, "guarded_fn")
                neg = sum(m in ("guarded_fn(-1)", "guarded_fn(4294967295)") for m in logs)   # int -1 (x64: ecx only)
                ok = (r.returncode == 0 and tg.get("calls") == calls and pr.get("backend") == bk and
                      tg.get("path") == "tampered" and tg.get("detected_by") == by and tg.get("detected_at") == "before" and
                      pr.get("hits") == calls and len(logs) == calls and neg == calls)
                record(f"antitamper-{bk}", ok, f"path={tg.get('path')} detected_by={tg.get('detected_by')}@{tg.get('detected_at')} "
                                               f"(want {by}@before) fn_disk_ok={tg.get('fn_disk_ok')} dr_seen={tg.get('debug_registers_seen')} "
                                               f"hits={pr.get('hits')}/{calls} logs_-1={neg}")
            except Exception as e:
                record(f"antitamper-{bk}", False, repr(e))
    x = exe("antidebug_target.exe")
    if x:
        keys = ("is_debugger_present", "remote_debugger_present", "debug_port", "debug_object_handle",
                "debug_flags_zero", "peb_being_debugged", "peb_nt_global_flag_heap_debug")
        try:
            br = subprocess.run([str(x), "--no-wait"], capture_output=True, text=True, timeout=60)
            base = next((json.loads(l) for l in br.stdout.splitlines() if l.startswith("{")), {})
            ok = br.returncode == 0 and base.get("path") == "clean" and all(base.get(k) is False for k in keys)
            record("antidebug-baseline", ok, f"path={base.get('path')} " + " ".join(f"{k}={base.get(k)}" for k in keys))
        except Exception as e:
            record("antidebug-baseline", False, repr(e))
        for bk in ("breakpoint", "hw", "inline"):
            try:
                r, o, tg = trace_run(x, ["antidebug_target.exe!timed_fn:d"], bk)
                pr = next(iter(probes(o)), {})
                logs = path_logs(o, "timed_fn")
                seen = ("is_debugger_present", "remote_debugger_present", "debug_port", "debug_object_handle",
                        "debug_flags_zero", "peb_being_debugged")
                ok = (r.returncode == 0 and pr.get("backend") == bk and tg.get("path") == "debugger" and
                      all(tg.get(k) is True for k in seen) and pr.get("hits") == 1 and logs in (["timed_fn(-1)"], ["timed_fn(4294967295)"]))
                record(f"antidebug-{bk}", ok, f"path={tg.get('path')} logs={logs} " +
                       " ".join(f"{k}={tg.get(k)}" for k in keys))
            except Exception as e:
                record(f"antidebug-{bk}", False, repr(e))


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


EDGE_ITERS = 5
# (site, location) -- see examples/edgehunt/edge_driver.cpp
EDGE_SHAPES = ["rep", "stos", "ripload", "ripcmp", "ripvec", "ripstore", "cpuid", "rdtsc", "syscall", "int2e",
               "pushf", "popf", "retonly", "thunk", "jump", "faultmid", "x87", "lock", "args"]
EDGE_X64_ONLY = {"ripload", "ripcmp", "ripvec", "ripstore", "syscall", "int2e"}
EDGE_LOC = {"rep": "EdgeRepSite", "stos": "EdgeStosSite", "ripload": "EdgeRipLoadSite", "ripcmp": "EdgeRipCmpSite",
            "ripvec": "EdgeRipVecSite", "ripstore": "EdgeRipStoreSite", "cpuid": "EdgeCpuidSite",
            "rdtsc": "EdgeRdtscSite", "syscall": "EdgeSyscallSite", "int2e": "EdgeInt2eSite",
            "pushf": "EdgePushfSite", "popf": "EdgePopfSite", "retonly": "EdgeRetOnlySite",
            "thunk": "EdgeThunkSite", "jump": "EdgeJumpSite", "faultmid": "EdgeFaultMidSite", "x87": "EdgeX87Site",
            "lock": "EdgeLockSite", "args": "edge_args10", "mem": "edge_mem_site", "readd": "EdgeReaddA",
            "leaf": "edge_leaf", "fmt": "edge_fmt_site", "fmtptr": "edge_fmt_site", "cbfault": "EdgeReaddB"}
# Shapes an inline hook cannot take (a 5-byte jump would run past a ret / into a jump-table
# target): a clean refusal is the correct inline answer there. (x86's jump-table jmp is 7
# bytes long, so its hook stays inside the instruction and is accepted.)
EDGE_INLINE_REFUSED_X64 = {"retonly", "jump"}
EDGE_INLINE_REFUSED_X86 = {"retonly"}


def check_edgehunt():
    """Edge-case code shapes and argument/memory/log edge cases (examples/edgehunt): ONE
    callback source under breakpoint, hw and inline. Every hit logs one 'ok' (never FAIL),
    hit counts are exact, and the target's result row equals the uninstrumented baseline:
    rep movsb/stosb, RIP-relative loads/stores/compares/AVX, cpuid, rdtsc, raw syscall and
    int 2e, pushf/popf, a bare ret, a call through a pointer, a jump table, a faulting load
    inside a framed function caught by the caller's __except, x87, lock cmpxchg, 10 args;
    get_mem/set_mem on guard/read-only/code/freed/page-crossing/null/wrapping addresses (no
    side effects, no partial copies, code reads show the program's bytes); invalid send_log
    formats (%k, %n) logged, never fatal; a faulting callback abandoned the same way on every
    backend; one-shot probes re-added from a callback every call; two backends on one site."""
    d, t = exe("edge_driver.exe"), exe("edge_target.exe")
    if not d or not t:
        return skip("edgehunt", "edge_driver/edge_target missing")
    import struct
    data = Path(t).read_bytes()
    x86 = struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0] == 0x14C
    _, bo = run([t, "--iters", EDGE_ITERS], timeout=60)
    base = next((x for x in bo if x.get("kind") == "target"), None)
    record("edgehunt-baseline", base is not None, str(base))
    if base is None:
        return
    K = EDGE_ITERS
    shapes = [s for s in EDGE_SHAPES if not (x86 and s in EDGE_X64_ONLY)]
    refused_inline = EDGE_INLINE_REFUSED_X86 if x86 else EDGE_INLINE_REFUSED_X64

    def expected_hits(site):
        if site in ("faultmid", "rdtsc"):
            return 2 * K
        if site == "int2e":
            return K if base.get("int2e_ok") else 1
        if site == "syscall":
            return K if base.get("svc") else 0
        return {"mem": 1, "fmt": 1, "fmtptr": 1, "leaf": 2}.get(site, K)

    def go(bk, sites, extra=()):
        r, o = run([d, "--backend", bk, "--sites", ",".join(sites), *extra, "--", t, "--iters", K], timeout=120)
        msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
        tg = next((x for x in o if x.get("kind") == "target"), {})
        return r, o, msgs, tg

    def common(r, o, msgs, tg):
        bad = []
        if r.returncode != 0: bad.append(f"exit={r.returncode}")
        if report(o).get("error") is not None: bad.append(f"error={report(o).get('error')}")
        if report(o).get("log_dropped") != 0: bad.append(f"log_dropped={report(o).get('log_dropped')}")
        diff = {k: (base.get(k), tg.get(k)) for k in set(base) | set(tg) if base.get(k) != tg.get(k)}
        if diff: bad.append(f"target-vs-baseline={diff}")
        fails = [m for m in msgs if m.startswith("FAIL")]
        if fails: bad.append(f"fails={fails[:3]}")
        return bad

    for bk in ("breakpoint", "hw", "inline"):
        # code shapes: batches of <= 4 (hw has 4 slots); inline refusals run on their own
        normal = [s for s in shapes if not (bk == "inline" and s in refused_inline)]
        for i in range(0, len(normal), 4):
            batch = normal[i:i + 4]
            name = f"edgehunt-{bk}-{'+'.join(batch)}"
            try:
                r, o, msgs, tg = go(bk, batch)
                bad = common(r, o, msgs, tg)
                rows = {p.get("location", "").split("!")[-1]: p for p in probes(o)}
                for s in batch:
                    row = rows.get(EDGE_LOC[s], {})
                    if row.get("hits") != expected_hits(s) or row.get("backend") != bk:
                        bad.append(f"{s}:hits={row.get('hits')}/{expected_hits(s)} backend={row.get('backend')}")
                oks = sum(1 for m in msgs if m.startswith("ok "))
                want = sum(expected_hits(s) for s in batch)
                if oks != want: bad.append(f"oks={oks}/{want}")
                record(name, not bad, "; ".join(bad) or f"hits exact, target == baseline")
            except Exception as e:
                record(name, False, repr(e))
        if bk == "inline":
            for s in sorted(refused_inline):
                name = f"edgehunt-inline-{s}-refused"
                try:
                    r, o = run([d, "--backend", "inline", "--sites", s, "--", t, "--iters", K], timeout=120)
                    text = r.stdout + r.stderr
                    tg = next((x for x in o if x.get("kind") == "target"), {})
                    row = next(iter(probes(o)), {})
                    refused = "refus" in text.lower() or "unsafe" in text.lower()
                    clean = refused and (not tg or tg == base) and not row.get("hits")
                    record(name, clean, f"refused={refused} hits={row.get('hits')} target_ok={not tg or tg == base} exit={r.returncode}")
                except Exception as e:
                    record(name, False, repr(e))
        # memory edge cases (+ the rep site probed, so code reads cross a live probe)
        name = f"edgehunt-{bk}-mem"
        try:
            r, o, msgs, tg = go(bk, ["mem", "rep"])
            bad = common(r, o, msgs, tg)
            oks = sorted({m[3:] for m in msgs if m.startswith("ok mem-")})
            if len(oks) != 12: bad.append(f"mem-oks={len(oks)}/12 {oks}")
            for k in ("guard_kept", "code_kept", "cross_kept", "ro_kept"):
                if tg.get(k) != 1: bad.append(f"{k}={tg.get(k)}")
            record(name, not bad, "; ".join(bad) or "12/12 memory edge cases, no side effects")
        except Exception as e:
            record(name, False, repr(e))
        # log formatting edge cases
        name = f"edgehunt-{bk}-fmt"
        try:
            r, o, msgs, tg = go(bk, ["fmt"])
            bad = common(r, o, msgs, tg)
            fm = [m for m in msgs if "fmt-" in m]
            # %k is not a conversion the UCRT rejects (it prints "k"); %n is (it used to fast-fail
            # the controller, or the TARGET for inline). Same text on every backend.
            need = ["fmt-null-s (null) end", "fmt-invalid k end", "[unformattable] fmt-percent-n %n end",
                    "fmt-trailing ", "fmt-done"]
            for n_ in need:
                if n_ not in fm: bad.append(f"missing {n_!r} in {[m[:60] for m in fm]}")
            wide = [m for m in fm if m.startswith("fmt-wide")]
            if len(wide) != 1 or not wide[0].endswith("...[truncated]"): bad.append(f"wide={[w[-20:] for w in wide]}")
            if len(fm) != 6: bad.append(f"records={len(fm)}/6 {fm}")
            record(name, not bad, "; ".join(bad) or "6 records, invalid formats logged, truncation marked")
        except Exception as e:
            record(name, False, repr(e))
        # %s of a TARGET pointer: inline prints the string; breakpoint/hw callbacks run in the
        # controller, where it is not a valid pointer -> "[unformattable]" (never a crash)
        name = f"edgehunt-{bk}-fmtptr"
        try:
            r, o, msgs, tg = go(bk, ["fmtptr"])
            bad = common(r, o, msgs, tg)
            fm = [m for m in msgs if "fmtptr" in m]
            ok_text = ["fmtptr hello-from-target"] if bk == "inline" else ["fmtptr hello-from-target", "[unformattable] fmtptr %s"]
            if len(fm) != 1 or fm[0] not in ok_text: bad.append(f"got={fm}")
            record(name, not bad, "; ".join(bad) or f"{fm[0]!r}")
        except Exception as e:
            record(name, False, repr(e))
        # a callback that faults: abandoned, hit counted, target unaffected, run continues
        name = f"edgehunt-{bk}-cbfault"
        try:
            r, o, msgs, tg = go(bk, ["cbfault"])
            bad = common(r, o, msgs, tg)
            before = sum(1 for m in msgs if m == "ok cbfault-before")
            row = next(iter(probes(o)), {})
            if before != K or row.get("hits") != K: bad.append(f"before={before}/{K} hits={row.get('hits')}/{K}")
            record(name, not bad, "; ".join(bad) or f"{K} faulting callbacks abandoned cleanly")
        except Exception as e:
            record(name, False, repr(e))
        # one-shot probe re-added from a callback on every call (added + retired K times)
        name = f"edgehunt-{bk}-readd"
        try:
            r, o, msgs, tg = go(bk, ["readd"])
            bad = common(r, o, msgs, tg)
            a = sum(1 for m in msgs if m == "ok readd-a"); b = sum(1 for m in msgs if m == "ok readd-b")
            if a != K or b != K: bad.append(f"readd-a={a}/{K} readd-b={b}/{K}")
            record(name, not bad, "; ".join(bad) or f"{K} adds, {K} one-shot hits")
        except Exception as e:
            record(name, False, repr(e))
        # stacks at depth 0 (a thread's first frame) and in deep recursion (capped)
        name = f"edgehunt-{bk}-leaf"
        try:
            r, o, msgs, tg = go(bk, ["leaf"])
            bad = common(r, o, msgs, tg)
            st = {x.get("message"): x.get("stack") or [] for x in o if x.get("kind") == "probe_log"}
            deep = st.get("leaf depth=0") or []
            if len([x for x in o if x.get("kind") == "probe_log"]) != 2: bad.append("records!=2")
            if len(deep) < 16 or not any("edge_recurse" in f for f in deep[1:3]):
                bad.append(f"deep={len(deep)} {deep[:3]}")
            record(name, not bad, "; ".join(bad) or f"deep stack {len(deep)} frames")
        except Exception as e:
            record(name, False, repr(e))

    # two backends on the same instruction (in both registration orders). An inline hook
    # cannot be written over a live INT3: breakpoint + inline is refused, with that reason.
    for pair in ("breakpoint,inline", "inline,breakpoint"):
        name = f"edgehunt-dual-{pair.replace(',', '+')}-refused"
        try:
            r, o = run([d, "--dual", pair, "--", t, "--iters", K], timeout=120)
            err = str(report(o).get("error") or "")
            ok = r.returncode != 0 and "software-breakpoint probe" in err
            record(name, ok, f"exit={r.returncode} error={err[:160]!r}")
        except Exception as e:
            record(name, False, repr(e))
    for pair in ("breakpoint,hw", "hw,breakpoint", "hw,inline", "inline,hw"):
        name = f"edgehunt-dual-{pair.replace(',', '+')}"
        try:
            r, o = run([d, "--dual", pair, "--", t, "--iters", K], timeout=120)
            msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
            tg = next((x for x in o if x.get("kind") == "target"), {})
            bad = common(r, o, msgs, tg)
            rows = probes(o)
            hits = sorted((p.get("backend"), p.get("hits")) for p in rows)
            want = sorted((b, K) for b in pair.split(","))
            if hits != want: bad.append(f"probes={hits} want={want}")
            if sum(1 for m in msgs if m.startswith("ok dual")) != 2 * K: bad.append("oks!=2K")
            record(name, not bad, "; ".join(bad) or f"both fire {K}x, target == baseline")
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
    debugger is attached, and a half-removed hook would corrupt results. Several threads log
    while the detach happens: every hit up to the detach has its log delivered (the logs on
    the tracer's stdout == the final hit count probe_close prints after the detach ==
    logs_written), and none is dropped."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return skip("detach", "uhh_trace/probe_app missing")
    import time
    for bk, reads in (("inline", 1500000), ("hw", 40000), ("breakpoint", 40000)):
        name = f"detach-{bk}"
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
            logs = sum(1 for l in tout.lines if l.startswith('{"kind":"probe_log"'))
            objs = [json.loads(l) for l in out.splitlines() if l.startswith("{") and not l.startswith('{"kind":"probe_log"')]
            detached = any(o.get("kind") == "detached" for o in objs)
            fin = re.search(r"probe: detached: hits=(\d+) logs_written=(\d+) log_dropped=(\d+)", err)
            hits, written, dropped = (int(x) for x in fin.groups()) if fin else (None, None, None)
            mid_run = 0 < (hits or 0) < total
            ok = (detached and mid_run and target.returncode == 0 and res.get("successful_reads") == total and
                  res.get("checksum") == base.get("checksum") and logs == hits == written and dropped == 0)
            record(name, ok, f"hits={hits}/{total} logs={logs} written={written} dropped={dropped} threads={threads} "
                             f"detached={detached} exit={target.returncode} "
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
                ok = crashed == 0 and torn_total == 0 and min(cycles_all) >= 4 and not notes
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


def ntopen_ret_site(t):
    """ntdll!NtOpenProcess+off of the stub's `ret` (decoded from the DLL file of t's arch)."""
    import struct
    data = Path(t).read_bytes()
    x86 = struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0] == 0x14C
    nt = Path(r"C:\Windows\SysWOW64\ntdll.dll") if x86 else SYS32 / "ntdll.dll"
    stub = pe_export_bytes(nt, "NtOpenProcess", 32) or b""
    anchor_bytes, ret_ops = (b"\xff\xd2", (0xC2, 0xC3)) if x86 else (b"\x0f\x05", (0xC3,))
    i = stub.find(anchor_bytes)
    off = next((k for k in range(i + len(anchor_bytes), len(stub)) if stub[k] in ret_ops), None) if i >= 0 else None
    return (None if off is None else f"ntdll.dll!NtOpenProcess+0x{off:x}"), stub


def pe_cetcompat(path):
    """True when the PE's extended DLL characteristics (debug directory entry type 20,
    IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS) carry CET_COMPAT (0x1) -- what /CETCOMPAT sets."""
    import struct
    d = Path(path).read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec, optsz = struct.unpack_from("<H", d, pe + 6)[0], struct.unpack_from("<H", d, pe + 20)[0]
    opt = pe + 24
    dd = opt + (112 if struct.unpack_from("<H", d, opt)[0] == 0x20B else 96)
    rva, size = struct.unpack_from("<II", d, dd + 6 * 8)
    secs = [struct.unpack_from("<IIII", d, opt + optsz + 40 * i + 8) for i in range(nsec)]  # vsize, va, rawsize, raw
    def off(r):
        return next((raw + r - va for vs, va, rs, raw in secs if va <= r < va + max(vs, rs)), None)
    o = off(rva) if rva else None
    for i in range(size // 28 if o is not None else 0):
        typ, dsz, _, raw = struct.unpack_from("<IIII", d, o + 28 * i + 12)
        if typ == 20 and dsz >= 4:
            return bool(struct.unpack_from("<I", d, raw)[0] & 1)
    return False


def find_old_msvcp():
    """A pre-14.40 msvcp140.dll of this build's bitness (before VS 17.10's constexpr std::mutex).
    UHH_OLD_MSVCP names one; otherwise VS's bundled LLVM ships 14.29. None if not found."""
    env = os.environ.get("UHH_OLD_MSVCP")
    if env and Path(env).exists():
        return Path(env)
    d = (BIN / "uhh_trace.exe").read_bytes()[:4096]
    pe = struct.unpack_from("<I", d, 0x3c)[0]
    is64 = struct.unpack_from("<H", d, pe + 4)[0] == 0x8664
    roots = [Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio",
             Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft Visual Studio"]
    pattern = "*/*/VC/Tools/Llvm/x64/bin/msvcp140.dll" if is64 else "*/*/VC/Tools/Llvm/bin/msvcp140.dll"
    return next((c for root in roots for c in sorted(root.glob(pattern))), None)


def check_oldcrt(calls=2000):
    """The target ships an OLDER msvcp140.dll next to its exe (app-local), as real software
    does. The injected agent binds to the target's already-loaded msvcp140 by name, so an
    agent built /MD against a newer runtime crashed in _Mtx_* (null read) during the inline
    install (field report: probe_agent_init failed 0xc0000005 / 0xffffffff). With the static
    CRT the agent is immune: every call is hit, the target finishes, no error."""
    tracer, target = exe("uhh_trace.exe"), exe("oldcrt_target.exe")
    if not tracer or not target:
        return skip("oldcrt", "uhh_trace/oldcrt_target missing")
    old = find_old_msvcp()
    if not old:
        return skip("oldcrt", "no pre-14.40 msvcp140.dll on this machine (set UHH_OLD_MSVCP)")
    tmp = Path(tempfile.mkdtemp(prefix="uhh-oldcrt-"))
    try:
        shutil.copy2(target, tmp / "oldcrt_target.exe")
        shutil.copy2(old, tmp / "msvcp140.dll")
        for backend in ("inline", "breakpoint"):
            name = f"oldcrt-{backend}"
            try:
                r, objs = run([tracer, "--backend", backend, "-p", "oldcrt_target.exe!Tick:-", "--",
                               tmp / "oldcrt_target.exe", str(calls)], timeout=120)
                info = next((o for o in objs if o.get("kind") == "oldcrt_target"), {})
                done = next((o for o in objs if o.get("kind") == "oldcrt_done"), {})
                rep = report(objs)
                app_local = (tmp / "msvcp140.dll").resolve().as_posix().lower() == \
                    Path(str(info.get("msvcp140", ""))).resolve().as_posix().lower()
                ok = (r.returncode == 0 and app_local and done.get("calls") == calls and
                      rep.get("hits") == calls and not rep.get("error"))
                crash = next((l for l in r.stderr.splitlines() if "crashed" in l or "agent thread" in l), "")
                record(name, ok, f"msvcp140={old.parent.name}/{old.name} app_local={app_local} "
                                 f"hits={rep.get('hits')}/{calls} rc={r.returncode} error={rep.get('error')} {crash}")
            except Exception as e:
                record(name, False, repr(e))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_interrupt(threads=4, reads=100_000):
    """Ctrl+C / Ctrl+Break on uhh_attach mid-run DETACHES instead of killing the tool: it
    prints the report and exits 0, and the target -- unhooked from that moment -- carries on
    and completes every read with no error (nothing of the instrumentation left behind)."""
    a, p = exe("uhh_attach.exe"), exe("probe_app.exe")
    if not a or not p:
        return skip("interrupt", "uhh_attach/probe_app missing")
    import signal
    W, R, N = int(threads), int(reads), HELPERS
    for bk in ("inline", "hw", "breakpoint"):
        name = f"interrupt-detach-{bk}"
        procs = []
        try:
            tgt = subprocess.Popen([str(p), "--helpers", str(N), "--threads", str(W), "--reads", str(R)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            procs.append(tgt)
            tout = Lines(tgt.stdout)
            waiting = tout.wait_for(lambda l: '"kind":"waiting"' in l, 30)
            if not waiting:
                raise RuntimeError("target never reached its gate")
            h = next(json.loads(l) for l in tout.lines if '"kind":"helper"' in l)
            att = subprocess.Popen([str(a), str(json.loads(waiting)["pid"]), "--pid", str(h["pid"]),
                                    "--range", f"{h['base']}:{h['size']}", "--backend", bk, "--flag-backend", bk],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            procs.append(att)
            aout, aerr = Lines(att.stdout), Lines(att.stderr)
            if not aout.wait_for(lambda l: '"kind":"attached"' in l, 30):
                raise RuntimeError("uhh_attach did not attach")
            for loc in (OPEN_LOCATION, READ_LOCATION):
                if not aerr.wait_for(lambda l, loc=loc: l.startswith(f"probe: active {loc} "), 30):
                    raise RuntimeError(f"{loc} never became active")
            tgt.stdin.write("x"); tgt.stdin.flush()
            if not aout.wait_for(lambda l: '"message":"read handle=' in l, 60):
                raise RuntimeError("no read was logged before the interrupt")
            att.send_signal(signal.CTRL_BREAK_EVENT)
            att.wait(timeout=60)
            tgt.wait(timeout=300)
            o, appl = aout.objs(), app(tout.objs())
            interrupted = any("interrupted" in l for l in aerr.lines)
            ok = (att.returncode == 0 and interrupted and bool(report(o)) and tgt.returncode == 0 and
                  appl.get("successful_reads") == W * R)
            record(name, ok, f"tool_rc={att.returncode} interrupted={interrupted} report={bool(report(o))} "
                             f"target_rc={tgt.returncode} reads={appl.get('successful_reads')}/{W * R} "
                             f"logged_before={len(read_log_lines(o))}")
        except Exception as e:
            record(name, False, repr(e))
        finally:
            for q in procs:
                if q.poll() is None:
                    q.kill()


def check_gated_filter(threads=4, reads=200):
    """gated_config --range: only reads whose address is in one of the ranges are logged, and
    exactly those. One unfiltered run learns the helpers' buffer base (the same address in
    every run: same image), then one range and two ranges are compared with the prediction
    from probe_app's deterministic read pattern (read i -> helper i % N, base + 64*((i//N)%4)).
    The --pid filter (helper pids are new on every launch) is covered by attach-*."""
    if not exe("gated_config.exe"):
        return skip("gated-filter", "gated_config.exe missing")
    W, R, N = int(threads), int(reads), HELPERS
    rx = re.compile(r"read handle=0x[0-9a-f]+ pid=(\d+) name=\S+ addr=0x([0-9a-f]+) ")
    for bk in ("inline", "breakpoint", "hw"):
        try:
            r, o = gated("breakpoint", bk, W, R)
            helpers = sorted((x for x in o if x.get("kind") == "helper"), key=lambda x: x["index"])
            h0 = helpers[0]
            b = h0["base"]   # helper buffers sit at the same address in every run (same image)
            cases = {
                "one-range": (["--range", f"{b + 64}:64"], lambda a: b + 64 <= a < b + 128),
                "two-ranges": (["--range", f"{b}:64", "--range", f"{hex(b + 192)}:0x40"],
                               lambda a: b <= a < b + 64 or b + 192 <= a < b + 256),
            }
            for label, (args, keep) in cases.items():
                name = f"gated-filter-{label}-{bk}"
                r, o = gated("breakpoint", bk, W, R, extra=args)
                hs = sorted((x for x in o if x.get("kind") == "helper"), key=lambda x: x["index"])
                want = 0
                for i in range(W * R):
                    h = hs[i % N]
                    want += keep(h["base"] + 64 * ((i // N) % 4))
                got = [m.groups() for m in map(rx.match, read_log_lines(o)) if m]
                rd = read_probe(o)
                ok = (r.returncode == 0 and want > 0 and len(got) == want and rd.get("hits") == W * R and
                      all(keep(int(a, 16)) for _, a in got))
                record(name, ok, f"logged={len(got)} want={want} read_hits={rd.get('hits')}/{W * R} rc={r.returncode}")
        except Exception as e:
            record(f"gated-filter-{bk}", False, repr(e))


def check_gated_map(threads=4, reads=50):
    """The NtOpenProcess probe logs every open with the pid and its image name, and the map
    it builds is handle -> pid -> name exactly as the target produced it: probe_app prints
    the real handle each open returned ({"kind":"opened"}), and every `map` and `read` line
    must agree with that ground truth (no handle-slot, stale or partial mapping). Each open
    backend is mixed with an inline read probe (the map is UHH_SHARED across backends)."""
    if not exe("gated_config.exe"):
        return skip("gated-map", "gated_config.exe missing")
    rx_open = re.compile(r"open pid=(\d+) name=(\S+)$")
    rx_map = re.compile(r"map handle=0x([0-9a-f]+) -> pid=(\d+) name=(\S+)$")
    rx_read = re.compile(r"read handle=0x([0-9a-f]+) pid=(\d+) name=(\S+) ")
    # track_open_process runs the open (call_original) and records handle -> pid -> name in
    # the open's own callback. "k32": probe_app opens through kernel32!OpenProcess, whose
    # out slot is a short-lived kernelbase local -- mapped all the same.
    for open_bk, via in [(b, v) for v in ("ntdll", "k32") for b in ("breakpoint", "hw", "inline")]:
        name = f"gated-map-open-{open_bk}" + ("-k32" if via == "k32" else "")
        try:
            r, o = gated("breakpoint", "inline", threads, reads, open_bk=open_bk,
                         target_args=("--open-via", "kernel32") if via == "k32" else ())
            truth = {x["handle"]: x["pid"] for x in o if x.get("kind") == "opened"}
            want_pids = helper_pids(o)
            msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
            opens = [m.groups() for m in map(rx_open.match, msgs) if m]
            maps = [m.groups() for m in map(rx_map.match, msgs) if m]
            rds = [m.groups() for m in map(rx_read.match, msgs) if m]
            bad = []
            # Every helper open must be seen. An extra open is tolerated (and reported): seen
            # once with a breakpoint probe (armed at load) on a freshly built probe_app's first
            # launch -- a start-up NtOpenProcess of its own. The map must equal the ground truth.
            target_pid = next((x.get("pid") for x in o if x.get("kind") == "waiting"), None)
            extra = [(p, n) for p, n in opens if int(p) not in want_pids]
            if not want_pids <= {int(p) for p, _ in opens} or len(opens) - len(extra) != len(want_pids):
                bad.append(f"opens={opens} target_pid={target_pid} helpers={sorted(want_pids)}")
            bad += [f"open-name {n}" for p, n in opens if int(p) in want_pids and n.lower() != "probe_app.exe"]
            # The extra (non-helper) open is mapped too, correctly; compare only the helpers'.
            helper_maps = [(h, p, n) for h, p, n in maps if int(p) in want_pids]
            if sorted(int(h, 16) for h, _, _ in helper_maps) != sorted(truth):
                bad.append(f"mapped={[h for h, _, _ in helper_maps]} truth={[hex(h) for h in truth]}")
            bad += [f"map {h}->{p}" for h, p, n in helper_maps
                    if truth.get(int(h, 16)) != int(p) or n.lower() != "probe_app.exe"]
            wrong_reads = sum(1 for h, p, n in rds if truth.get(int(h, 16)) != int(p) or n.lower() != "probe_app.exe")
            ok = (r.returncode == 0 and len(truth) == len(want_pids) and not bad and
                  len(rds) == threads * reads and wrong_reads == 0)
            record(name, ok, f"opens={len(opens)} maps={len(maps)}/{len(truth)} reads={len(rds)}/{threads * reads} "
                             f"wrong_reads={wrong_reads} rc={r.returncode}" +
                             (f" extra_opens={extra} target_pid={target_pid}" if extra else "") + ("" if ok else f" bad={bad[:4]}"))
        except Exception as e:
            record(name, False, repr(e))


def check_agent_crt():
    """probe_api_agent.dll is injected into the target, so it must not import the dynamic
    MSVC runtime: it would bind to whatever msvcp140/vcruntime140 the target already loaded,
    and an older app-local msvcp140 crashes SafetyHook's std::mutex (_Mtx_* null read)."""
    path = BIN / "probe_api_agent.dll"
    if not path.exists():
        return skip("agent-crt", "probe_api_agent.dll missing")
    d = path.read_bytes().lower()
    bad = [n for n in (b"msvcp140", b"vcruntime140", b"api-ms-win-crt-") if n in d]
    record("agent-crt", not bad, "imports " + ",".join(n.decode() for n in bad) if bad else "static CRT")


def check_cet(threads=8, reads=500):
    """Intel CET shadow stacks. cet_probe (linked /CETCOMPAT) reports what this machine
    gives such a process: CPUID CET_SS, the OS CET_U state, the process's
    ProcessUserShadowStackPolicy, and RDSSP (non-zero only when a shadow stack is ACTIVE).
    Then the gated_config scenario runs on probe_app_cet (the same target linked
    /CETCOMPAT) with flag, open and read probes all on ONE backend, for each backend:
    flag flipped once, every read hit and logged, nothing dropped, the target's checksum
    equal to an uninstrumented CET run, and the target's own RDSSP agreeing with
    cet_probe (so a pass on a CET machine is a pass WITH the shadow stack enforced).
    cet-ret-breakpoint probes NtOpenProcess's `ret` with a software breakpoint: emulating
    that ret would desync the shadow stack, so on a CET target UHH must step it for real.
    The detail of every row says whether CET was enforced; on a machine without CET these
    rows prove only that /CETCOMPAT targets work, not the CET behaviour."""
    pr_exe, tgt, gc, t = exe("cet_probe.exe"), exe("probe_app_cet.exe"), exe("gated_config.exe"), exe("uhh_trace.exe")
    if not pr_exe or not tgt or not gc or not t:
        return skip("cet", "cet_probe/probe_app_cet/gated_config/uhh_trace missing")
    try:
        flags = {n: pe_cetcompat(BIN / n) for n in ("probe_app_cet.exe", "cet_probe.exe", "probe_app.exe")}
        record("cet-image", flags["probe_app_cet.exe"] and flags["cet_probe.exe"] and not flags["probe_app.exe"],
               " ".join(f"{n}:CETCOMPAT={v}" for n, v in flags.items()))
    except Exception as e:
        record("cet-image", False, repr(e))
    enforced = None
    try:
        r, o = run([pr_exe], timeout=60)
        info = next((x for x in o if x.get("kind") == "cet_probe"), {})
        enforced = info.get("enforced")
        pol = info.get("policy", {})
        record("cet-probe", r.returncode == 0 and enforced is not None and info.get("policy_ok") == 1,
               f"arch={info.get('arch')} vendor={info.get('vendor')} hypervisor={info.get('hypervisor')} "
               f"build={info.get('windows_build')} cpuid_cet_ss={info.get('cpuid_cet_ss')} "
               f"cpuid_cet_ibt={info.get('cpuid_cet_ibt')} os_cet_u={info.get('os_cet_u')} "
               f"ENFORCED={enforced} policy={{{', '.join(f'{k}={v}' for k, v in pol.items() if v)}}}")
    except Exception as e:
        record("cet-probe", False, repr(e))
    total = int(threads) * int(reads)
    base = {}
    try:
        _, bo = run([tgt, "--no-wait", "--threads", threads, "--reads", reads, "--config", "reads_enabled=1"], timeout=120)
        base = app(bo)
    except Exception:
        pass
    for bk in ("breakpoint", "inline", "hw"):
        name = f"cet-gated-{bk}"
        try:
            r, o = run([gc, "--flag-backend", bk, "--read-backend", bk, "--open-backend", bk, FLAG_LOCATION, READ_LOCATION,
                        "--", tgt, "--no-wait", "--helpers", HELPERS, "--threads", threads, "--reads", reads], timeout=300)
            rep, rd, a = report(o), read_probe(o), app(o)
            logs, dropped = read_logs(o)
            same = (base.get("checksum") is not None and a.get("checksum") == base.get("checksum")
                    and a.get("successful_reads") == base.get("successful_reads") == total)
            ok = (r.returncode == 0 and rep.get("overrides") == 1 and rd.get("hits") == total and rd.get("backend") == bk
                  and logs == total and dropped == 0 and unmapped(o) == 0 and rep.get("error") is None and same
                  and a.get("shadow_stack") == enforced)
            record(name, ok, f"cet_enforced={enforced} target_ssp={a.get('shadow_stack')} override={rep.get('overrides')} "
                             f"hits={rd.get('hits')}/{total} logs={logs} dropped={dropped} checksum_same={same} "
                             f"rc={r.returncode} err={(rep.get('error') or '')[:120]} stderr={r.stderr.strip()[-160:]!r}")
        except Exception as e:
            record(name, False, repr(e))
    site, stub = ntopen_ret_site(t)
    if site is None:
        return record("cet-ret-breakpoint", False, f"no ret found in NtOpenProcess stub: {stub.hex()}")
    try:
        r, o = run([t, "--backend", "breakpoint", "-p", f"{site}:x", "--", tgt, "--no-wait", "--helpers", HELPERS,
                    "--threads", 2, "--reads", 50, "--config", "reads_enabled=1"], timeout=300)
        a, pr = app(o), next((x for x in o if x.get("kind") == "probe"), {})
        ok = (r.returncode == 0 and a.get("opened") == HELPERS and a.get("successful_reads") == 100
              and pr.get("backend") == "breakpoint" and pr.get("hits") == HELPERS and a.get("shadow_stack") == enforced)
        record("cet-ret-breakpoint", ok, f"cet_enforced={enforced} site={site} hits={pr.get('hits')}/{HELPERS} "
                                         f"opened={a.get('opened')} reads={a.get('successful_reads')} rc={r.returncode}")
    except Exception as e:
        record("cet-ret-breakpoint", False, repr(e))


def check_ret_probe(threads=2, reads=50):
    """A probe on a function's own `ret` -- the natural way to see a return (no special
    flag): ntdll!NtOpenProcess's ret, found by decoding the stub in the DLL file. probe_app
    opens each helper once. breakpoint and hw must fire once per open. inline must be REFUSED cleanly (the 5-byte jump would run past the ret
    into code only a jump reaches -- the int 2e tail on x64, the next stub on x86) or,
    with --fallback-hw, move to hw. The target must be unaffected either way."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return skip("ret-probe", "uhh_trace/probe_app missing")
    site, stub = ntopen_ret_site(t)
    if site is None:
        return record("ret-probe", False, f"no ret found in NtOpenProcess stub: {stub.hex()}")
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


def check_handle_map(threads=4, reads=500, decoys=5000):
    """(C11) The example handle->pid map has no silent cap: probe_app first opens and closes
    ITSELF `decoys` times (far more than the old 1024-record limit; the handle values are
    reused over and over), then opens the helpers. Every helper read must still be logged
    with its helper's pid (unmapped == 0) -- open and read probe on the same backend, and
    across backends through UHH_SHARED."""
    if not exe("gated_config.exe"):
        return skip("handle-map", "gated_config.exe missing")
    want = threads * reads
    for open_bk, read_bk in (("breakpoint", "breakpoint"), ("hw", "hw"), ("inline", "inline"),
                             ("breakpoint", "inline")):
        name = f"handle-map open={open_bk} read={read_bk}"
        try:
            r, o = gated("breakpoint", read_bk, threads, reads, timeout=400, open_bk=open_bk,
                         target_args=("--decoy-opens", decoys))
            rd, op = read_probe(o), open_probe(o)
            logs, dropped = read_logs(o)
            ok = (r.returncode == 0 and rd.get("hits") == want and logs == want and dropped == 0 and
                  (op.get("hits") or 0) >= decoys + HELPERS and unmapped(o) == 0 and logged_pids(o) == helper_pids(o))
            record(name, ok, f"open_hits={op.get('hits')}/{decoys + HELPERS} read_hits={rd.get('hits')}/{want} "
                             f"logs={logs} dropped={dropped} unmapped={unmapped(o)} "
                             f"pids_ok={logged_pids(o) == helper_pids(o)} extra={sorted(logged_pids(o) - helper_pids(o))} "
                             f"missing={sorted(helper_pids(o) - logged_pids(o))} err={(report(o).get('error') or '')[:100]}")
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


def check_crash_logs(n=5000, threads=4):
    """Log delivery when the TARGET crashes: several threads log on every probed call; the
    first to reach n calls dies with an unhandled access violation while the others are
    still logging. Every hit counted must have its log delivered (logs == hits, at least
    n) -- for inline they sit in the shared ring at the moment of death -- and none may be
    counted as dropped. Single-thread run too: exactly n."""
    d, t = exe("hitcost_driver.exe"), exe("hitcost_target.exe")
    if not d or not t:
        return skip("crash-logs", "hitcost driver/target missing")
    for bk in ("inline", "hw", "breakpoint"):
        for nt in (1, threads):
            name = f"crash-logs-{bk}" + ("" if nt == 1 else f"-{nt}t")
            try:
                _, o = run([d, "--backend", bk, "--method", "send_log", "--", t, "--calls", n * 10, "--threads", nt,
                            "--crash-after", n], timeout=300)
                rep = report(o)
                logs = sum(1 for x in o if x.get("kind") == "probe_log" and str(x.get("message", "")).startswith("hit "))
                tids = {x.get("tid") for x in o if x.get("kind") == "probe_log"}
                pr = next(iter(probes(o)), {})
                hits = pr.get("hits") or 0
                ok = (rep.get("app_exit") == 0xC0000005 and logs == hits and rep.get("log_dropped") == 0 and
                      (hits == n if nt == 1 else hits >= n and len(tids) == nt))
                record(name, ok, f"exit=0x{(rep.get('app_exit') or 0):x} hits={hits} logs={logs} (n={n}) "
                                 f"threads_logging={len(tids)}/{nt} dropped={rep.get('log_dropped')}")
            except Exception as e:
                record(name, False, repr(e))


def check_attach_new(threads=2, reads=500):
    """probe_attach_new, every backend, on ntdll!NtReadVirtualMemory: ignore an already-running
    instance (the decoy), attach to the NEXT one started, observe all of its reads; and fail
    cleanly (error, non-zero exit) on timeout. No fixed sleeps: the target is started once
    the tracer reports its snapshot of running instances ('probe: waiting for a new'), and
    its gate is released once the tracer reports the probe live ('probe: active'). The gate
    stays: attach_new polls, so without it some reads could run before the attach lands."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return skip("attach-new", "uhh_trace/probe_app missing")
    for bk in ("breakpoint", "hw", "inline"):
        name = f"attach-new-{bk}"
        decoy = target = tracer = None
        try:
            decoy = subprocess.Popen([str(a), "--config", "reads_enabled=1"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # The decoy (and the helper processes it starts, also probe_app.exe) must all exist
            # before the tracer's snapshot: wait for its gate line, printed after its helpers.
            if not any('"waiting"' in l for l in lines_until(decoy, '"waiting"', 60)):
                raise RuntimeError("decoy never reached its gate")
            tracer = subprocess.Popen([str(t), "--backend", bk, "--attach-new", "probe_app.exe", "--timeout", "60000",
                                       "-p", "ntdll.dll!NtReadVirtualMemory:-"],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            tout, terr = Lines(tracer.stdout), Lines(tracer.stderr)
            if not terr.wait_for(lambda l: l.startswith("probe: waiting for a new probe_app.exe"), 60):
                raise RuntimeError("tracer never took its snapshot")
            target = subprocess.Popen([str(a), "--threads", str(threads), "--reads", str(reads),
                                       "--config", "reads_enabled=1"],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if not terr.wait_for(lambda l: l.startswith("probe: active ntdll.dll!NtReadVirtualMemory"), 120):
                raise RuntimeError("probe never became active")
            target.stdin.write(b"\n"); target.stdin.flush()
            lines_until(target, '"kind":"app"', 120)                 # keep its pipe drained
            tracer.wait(timeout=180)                                 # returns when the target exits
            target.wait(timeout=60)
            err = "\n".join(terr.lines)
            m = re.search(r"new probe_app\.exe pid (\d+)", err)
            pr = next((o for o in tout.objs() if o.get("kind") == "probe"), {})
            ok = (m is not None and int(m.group(1)) == target.pid and pr.get("hits") == threads * reads and
                  pr.get("backend") == bk and target.returncode == 0 and tracer.returncode == 0)
            record(name, ok, f"attached_pid={m.group(1) if m else None} target_pid={target.pid} decoy_pid={decoy.pid} "
                             f"backend={pr.get('backend')} hits={pr.get('hits')}/{threads * reads} "
                             f"rc={tracer.returncode}/{target.returncode}"
                             + ("" if ok else " stderr=" + " | ".join(err.strip().splitlines()[-8:])))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            for p_ in (decoy, target, tracer):
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

# ---- Microsoft Detours samples replicated on UHH (examples/famous/detours_*) --------------
# Every check compares the instrumented run against the uninstrumented one (the target's own
# ground truth) and the trace against what the target says it did, under every backend.

DT_BACKENDS = ("breakpoint", "hw", "inline")
# hw has 4 debug registers: the traceapi set is traced in groups of at most 4.
DT_HW_GROUPS = ("CreateFileW,ReadFile,WriteFile,CloseHandle",
                "RegOpenKeyExW,RegQueryValueExW,LoadLibraryW,LoadLibraryExW",
                "CreateProcessInternalW")


def dt_split(stdout):
    """Split a driver's stdout into UHH records and the TARGET's own output. The target
    inherits the controller's stdout, and the live log tail writes whole records -- but a
    target that writes a partial line (reg.exe does; so does unbuffered UCRT stdout) gets a
    record spliced into the middle of its line. Rebuild the target's text by cutting every
    record out of the line it landed in."""
    objs, text = [], []
    for line in stdout.splitlines():
        cut = line.find('{"kind":')
        if cut < 0:
            text.append(line + "\n")
            continue
        text.append(line[:cut])
        try:
            objs.append(json.loads(line[cut:]))
        except json.JSONDecodeError:
            text.append(line[cut:] + "\n")
    return objs, "".join(text)


def dt_run(args, timeout=300, feed=None):
    r = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout, input=feed)
    objs, text = dt_split(r.stdout)
    return r, objs, text


def dt_logs(objs):
    return [o.get("message", "") for o in objs if o.get("kind") == "probe_log"]


def dt_target(objs):
    return next((o for o in objs if o.get("kind") == "target"), {})


def dt_dir():
    """detours_target's working files: one directory per regress run, so suites running in
    parallel (x64 and x86 at once) never read or overwrite each other's files."""
    d = Path(tempfile.gettempdir()) / f"uhhdt-{os.getpid()}"
    d.mkdir(exist_ok=True)
    return d


def dt_tail(r, n=6):
    return " stderr_tail=" + " | ".join(l[:200] for l in (r.stderr or "").strip().splitlines()[-n:])


def check_detours_simple(threads=4, rounds=25):
    """Detours 'simple' (SleepEx counter): every Sleep/SleepEx the target made is logged once,
    with the requested milliseconds; the target's own results equal an uninstrumented run."""
    d, tg_exe = exe("detours_simple.exe"), exe("detours_target.exe")
    if not d or not tg_exe:
        return skip("detours-simple", "detours_simple/detours_target missing")
    targs = ["sleep", "--threads", threads, "--rounds", rounds]
    try:
        _, bo, _ = dt_run([tg_exe, *targs], timeout=120)
        base = dt_target(bo)
    except Exception as e:
        return record("detours-simple-baseline", False, repr(e))
    keys = ("sleep_calls", "sleepex_calls", "total_requested_ms", "alertable_ret", "apc_runs", "errors")
    for bk in DT_BACKENDS:
        name = f"detours-simple-{bk}"
        try:
            r, o, _ = dt_run([d, "--backend", bk, "--", tg_exe, *targs], timeout=300)
            tg, rep, logs = dt_target(o), report(o), dt_logs(o)
            sx = [re.match(r"SleepEx\((\d+), (\d+)\)$", m) for m in logs if m.startswith("SleepEx(")]
            sl = [re.match(r"Sleep\((\d+)\)$", m) for m in logs if m.startswith("Sleep(")]
            sx_ms, sl_ms = sum(int(m.group(1)) for m in sx if m), sum(int(m.group(1)) for m in sl if m)
            alertable = sum(1 for m in sx if m and m.group(2) != "0")
            hits = {p.get("location"): p.get("hits") for p in probes(o)}
            same = all(tg.get(k) == base.get(k) for k in keys)
            ok = (r.returncode == 0 and same and base.get("errors") == 0 and base.get("alertable_ret") == 192 and
                  len(sl) == base.get("sleep_calls") and
                  len(sx) == base.get("sleep_calls", 0) + base.get("sleepex_calls", 0) and
                  sx_ms == base.get("total_requested_ms") and alertable == threads * rounds + 1 and
                  hits.get("KernelBase.dll!SleepEx") == len(sx) and hits.get("kernel32.dll!Sleep") == len(sl) and
                  rep.get("log_dropped") == 0 and rep.get("app_exit") == 0 and rep.get("error") is None)
            record(name, ok, f"Sleep logs={len(sl)}/{base.get('sleep_calls')} SleepEx logs={len(sx)}/"
                             f"{base.get('sleep_calls', 0) + base.get('sleepex_calls', 0)} ms={sx_ms}/{base.get('total_requested_ms')} "
                             f"(Sleep ms={sl_ms}) alertable={alertable}/{threads * rounds + 1} hits={hits} "
                             f"target_same={same} alert_ret={tg.get('alertable_ret')} dropped={rep.get('log_dropped')} "
                             f"exit={rep.get('app_exit')} err={(rep.get('error') or '')[:160]}" + ("" if ok else dt_tail(r)))
        except Exception as e:
            record(name, False, repr(e))


def dt_api_expect(tg):
    """Workload lines the traceapi trace must contain, from the target's own counts."""
    n = tg.get("threads", 0) * tg.get("iters", 0)
    return {
        "create_always": n, "open_existing": 2 * n, "writes": tg.get("writes"), "reads": tg.get("reads"),
        "regopen": tg.get("regopens"), "regquery": tg.get("regqueries"), "loadlib": tg.get("loads"), "process": 1,
    }


def dt_api_seen(logs):
    """Count the workload's calls in a traceapi trace (startup noise is not 'uhhdt-')."""
    c = {"create_always": 0, "open_existing": 0, "writes": 0, "reads": 0, "regopen": 0, "regquery": 0,
         "loadlib": 0, "loadlibex": 0, "process": 0, "close": 0}
    for m in logs:
        if m.startswith("CreateFileW(") and "uhhdt-" in m:
            c["create_always" if m.endswith("disp=2)") else "open_existing"] += 1
        elif m.startswith("WriteFile(") and ', 1337, "UHHDT-PAYLOAD-' in m:
            c["writes"] += 1
        elif m.startswith("ReadFile(") and m.endswith(", 1337)"):
            c["reads"] += 1
        elif m.startswith('RegOpenKeyExW(HKLM, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"'):
            c["regopen"] += 1
        elif m.startswith("RegQueryValueExW(") and m.endswith(', "ProductName")'):
            c["regquery"] += 1
        elif m == 'LoadLibraryW("version.dll")':
            c["loadlib"] += 1
        elif m.startswith('LoadLibraryExW("version.dll"'):
            c["loadlibex"] += 1
        elif m.startswith("CreateProcessInternalW(") and "/d /c exit 7" in m:
            c["process"] += 1
        elif m.startswith("CloseHandle("):
            c["close"] += 1
    return c


def dt_groups(bk):
    return DT_HW_GROUPS if bk == "hw" else (None,)


def dt_kinds(group):
    """Which dt_api_seen keys a probe group can see."""
    if group is None:
        return None
    g = group.split(",")
    keys = set()
    if "CreateFileW" in g: keys |= {"create_always", "open_existing"}
    if "WriteFile" in g: keys.add("writes")
    if "ReadFile" in g: keys.add("reads")
    if "RegOpenKeyExW" in g: keys.add("regopen")
    if "RegQueryValueExW" in g: keys.add("regquery")
    if "LoadLibraryW" in g: keys.add("loadlib")
    if "CreateProcessInternalW" in g: keys.add("process")
    return keys


def check_detours_traceapi(threads=4, iters=5):
    """Detours 'traceapi': file/registry/process/module APIs traced with decoded arguments,
    on detours_target (exact: the trace holds exactly the calls the target says it made, plus
    the one pre-workload registry read) and on real system programs (cmd type, reg query,
    cmd spawning cmd): their output and exit code equal an uninstrumented run."""
    d, tg_exe = exe("detours_traceapi.exe"), exe("detours_target.exe")
    if not d or not tg_exe:
        return skip("detours-traceapi", "detours_traceapi/detours_target missing")
    wd = dt_dir()
    targs = ["api", "--threads", threads, "--iters", iters, "--dir", wd]
    try:
        _, bo, _ = dt_run([tg_exe, *targs], timeout=120)
        base = dt_target(bo)
    except Exception as e:
        return record("detours-traceapi-baseline", False, repr(e))
    want = dt_api_expect(base)
    want["regopen"] += 1; want["regquery"] += 1            # the ground-truth read before the workload
    keys = ("creates", "writes", "reads", "closes", "regopens", "regqueries", "loads", "child_exit", "product", "errors")
    for bk in (*DT_BACKENDS, "mix"):
        for group in dt_groups(bk):
            name = f"detours-traceapi-{bk}" + (f"-g{DT_HW_GROUPS.index(group) + 1}" if group else "")
            try:
                cmd = [d, "--backend", bk] + (["--only", group] if group else []) + ["--", tg_exe, *targs]
                r, o, _ = dt_run(cmd, timeout=600)
                tg, rep, logs = dt_target(o), report(o), dt_logs(o)
                seen = dt_api_seen(logs)
                kinds = dt_kinds(group) or set(want)
                bad = {k: (seen[k], want[k]) for k in kinds if seen[k] != want[k]}
                hits = sum(p.get("hits") or 0 for p in probes(o))
                same = all(tg.get(k) == base.get(k) for k in keys)
                lle_ok = group is not None and "LoadLibraryExW" not in group or seen["loadlibex"] >= want["loadlib"]
                close_ok = group is not None and "CloseHandle" not in group or seen["close"] >= base.get("closes", 0)
                backends = sorted({p.get("backend") for p in probes(o)})
                ok = (r.returncode == 0 and same and base.get("errors") == 0 and not bad and lle_ok and close_ok and
                      hits == len(logs) and rep.get("log_dropped") == 0 and rep.get("app_exit") == 0 and
                      rep.get("error") is None and (bk != "mix" or backends == ["breakpoint", "hw", "inline"]))
                record(name, ok, f"mismatch(seen,want)={bad} closes={seen['close']}>={base.get('closes')} "
                                 f"loadlibex={seen['loadlibex']} logs={len(logs)} hits={hits} backends={backends} "
                                 f"target_same={same} dropped={rep.get('log_dropped')} exit={rep.get('app_exit')} "
                                 f"err={(rep.get('error') or '')[:160]}" + ("" if ok else dt_tail(r)))
            except Exception as e:
                record(name, False, repr(e))
    # Real programs. 32-bit drivers launch the SysWOW64 copies through System32 redirection.
    content = wd / "uhhdt-type.txt"
    content.write_text("UHHDT-TYPE-CONTENT line one\nline two\n")
    # The uninstrumented baseline must run the SAME bitness as the traced program: a 32-bit
    # driver gets the SysWOW64 copies, and 32-bit reg.exe reads the WOW64 registry view
    # (HKLM\SOFTWARE\WOW6432Node: a different ProductName on this VM).
    import struct
    raw = Path(d).read_bytes()
    sysdir = Path(r"C:\Windows\SysWOW64") if struct.unpack_from("<H", raw, struct.unpack_from("<I", raw, 0x3C)[0] + 4)[0] == 0x14C else SYS32
    cmd_exe, reg_exe = str(sysdir / "cmd.exe"), str(sysdir / "reg.exe")
    key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    programs = (
        ("type", [cmd_exe, "/d", "/c", "type", str(content)],
         lambda logs: any(m.startswith("CreateFileW(") and "uhhdt-type.txt" in m for m in logs) and
                      any(m.startswith("ReadFile(") for m in logs), "CreateFileW,ReadFile,WriteFile,CloseHandle"),
        ("reg", [reg_exe, "query", key, "/v", "ProductName"],
         lambda logs: any(m.startswith("RegOpenKeyExW(HKLM, \"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\"") for m in logs) and
                      any(m.startswith("RegQueryValueExW(") and "ProductName" in m for m in logs),
         "RegOpenKeyExW,RegQueryValueExW,LoadLibraryW,LoadLibraryExW"),
        ("spawn", [cmd_exe, "/d", "/c", f"{cmd_exe} /d /c exit 3"],
         lambda logs: any(m.startswith("CreateProcessInternalW(") and "exit 3" in m for m in logs),
         "CreateProcessInternalW"),
    )
    for label, argv, check, hw_group in programs:
        try:
            br = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            base_out = [l for l in br.stdout.splitlines() if l.strip()]
        except Exception as e:
            record(f"detours-traceapi-{label}-baseline", False, repr(e)); continue
        for bk in (*DT_BACKENDS, "mix"):
            name = f"detours-traceapi-{label}-{bk}"
            try:
                cmd = [d, "--backend", bk] + (["--only", hw_group] if bk == "hw" else []) + ["--", *argv]
                r, o, text = dt_run(cmd, timeout=300)
                rep, logs = report(o), dt_logs(o)
                out = [l for l in text.splitlines() if l.strip()]
                hits = sum(p.get("hits") or 0 for p in probes(o))
                ok = (out == base_out and rep.get("app_exit") == br.returncode and check(logs) and
                      hits == len(logs) and rep.get("log_dropped") == 0 and rep.get("error") is None)
                record(name, ok, f"output_same={out == base_out} exit={rep.get('app_exit')}/{br.returncode} "
                                 f"trace_ok={check(logs)} logs={len(logs)} hits={hits} dropped={rep.get('log_dropped')} "
                                 f"err={(rep.get('error') or '')[:160]}" +
                                 ("" if ok else f" out={out[:4]} base={base_out[:4]} logs={logs[:6]}" + dt_tail(r)))
            except Exception as e:
                record(name, False, repr(e))


def dt_norm(m):
    """A trace line with run-specific values (handles) removed."""
    return re.sub(r"0x[0-9a-f]+", "0x?", m)


def dt_workload(logs):
    from collections import Counter
    keep = []
    for m in logs:
        if ("uhhdt-" in m or "UHHDT-PAYLOAD" in m or m.endswith(", 1337)") or "version.dll" in m or
                "/d /c exit 7" in m or m.startswith("RegOpenKeyExW(HKLM, \"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\"") or
                (m.startswith("RegQueryValueExW(") and "ProductName" in m)):
            keep.append(dt_norm(m))
    return Counter(keep)


def dt_gated(tg_exe, targs):
    tgt = subprocess.Popen([str(tg_exe), *map(str, targs), "--gate"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True)
    tout = Lines(tgt.stdout)
    waiting = tout.wait_for(lambda l: '"kind":"waiting"' in l, 30)
    if not waiting:
        tgt.kill()
        raise RuntimeError("target never reached its gate")
    return tgt, tout


def check_detours_withdll(threads=2, iters=3):
    """Detours withdll (launch with the DLL) vs attaching to a running process: the launch
    trace and the attach trace of the same gated workload are identical, except for the one
    registry read the target makes before its gate (it happens before the attach). Then
    attach mid-run to a busy multi-threaded target and DETACH while it keeps running: it
    must finish with every self-check passing."""
    d, tg_exe = exe("detours_traceapi.exe"), exe("detours_target.exe")
    if not d or not tg_exe:
        return skip("detours-withdll", "detours_traceapi/detours_target missing")
    wd = dt_dir()
    targs = ["api", "--threads", threads, "--iters", iters, "--dir", wd]
    for bk in (*DT_BACKENDS, "mix"):
        for group in dt_groups(bk):
            name = f"detours-withdll-{bk}" + (f"-g{DT_HW_GROUPS.index(group) + 1}" if group else "")
            procs = []
            try:
                sel = ["--only", group] if group else []
                # withdll: launch under instrumentation (gate released at once).
                r, lo, _ = dt_run([d, "--backend", bk, *sel, "--", tg_exe, *targs, "--gate"], timeout=300, feed="\n")
                launch = dt_workload(dt_logs(lo))
                # attach: the target is already running, waiting at its gate.
                tgt, tout = dt_gated(tg_exe, targs)
                procs.append(tgt)
                pid = tgt.pid
                att = subprocess.Popen([str(d), "--backend", bk, *sel, "--attach", str(pid)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                procs.append(att)
                aout, aerr = Lines(att.stdout), Lines(att.stderr)
                nprobes = len(group.split(",")) if group else 9
                if not aout.wait_for(lambda l: '"kind":"attached"' in l, 60):
                    raise RuntimeError("did not attach: " + " | ".join(aerr.lines[-5:]))
                deadline = time.time() + 60
                while time.time() < deadline and sum(1 for l in list(aerr.lines) if l.startswith("probe: active ")) < nprobes:
                    time.sleep(0.05)
                active = sum(1 for l in list(aerr.lines) if l.startswith("probe: active "))
                tgt.stdin.write("\n"); tgt.stdin.flush()
                tgt.wait(timeout=300); att.wait(timeout=120)
                ao, to = aout.objs(), tout.objs()
                attach = dt_workload(dt_logs(ao))
                diff_launch, diff_attach = launch - attach, attach - launch
                pre_gate = {k: v for k, v in diff_launch.items()}
                expect_pre = {}
                if group is None or "RegOpenKeyExW" in group:
                    expect_pre['RegOpenKeyExW(HKLM, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0x?)'] = 1
                if group is None or "RegQueryValueExW" in group:
                    expect_pre['RegQueryValueExW(0x?, "ProductName")'] = 1
                tg, rep = dt_target(to), report(ao)
                ok = (r.returncode == 0 and att.returncode == 0 and tgt.returncode == 0 and tg.get("errors") == 0 and
                      active == nprobes and not diff_attach and pre_gate == expect_pre and sum(attach.values()) > 0 and
                      rep.get("log_dropped") == 0 and rep.get("error") is None)
                record(name, ok, f"workload lines launch={sum(launch.values())} attach={sum(attach.values())} "
                                 f"only_in_launch={dict(diff_launch)} only_in_attach={dict(diff_attach)} active={active}/{nprobes} "
                                 f"target_errors={tg.get('errors')} rc={r.returncode}/{att.returncode}/{tgt.returncode} "
                                 f"dropped={rep.get('log_dropped')} err={(rep.get('error') or '')[:160]}")
            except Exception as e:
                record(name, False, repr(e))
            finally:
                for p_ in procs:
                    if p_.poll() is None:
                        p_.kill()
    # Attach mid-run (no gate: the target is busy on 4 threads) and detach while it runs.
    for bk in (*DT_BACKENDS, "mix"):
        name = f"detours-withdll-detach-{bk}"
        procs = []
        try:
            sel = ["--only", DT_HW_GROUPS[0]] if bk == "hw" else []
            tgt = subprocess.Popen([str(tg_exe), "api", "--threads", "4", "--iters", "2", "--duration-ms", "8000",
                                    "--dir", str(wd)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
            procs.append(tgt)
            tout, terr = Lines(tgt.stdout), Lines(tgt.stderr)
            if not tout.wait_for(lambda l: '"kind":"open"' in l, 30):
                raise RuntimeError("target never started its workload")
            r, o, _ = dt_run([d, "--backend", bk, *sel, "--attach", tgt.pid, "--detach-after-ms", "2500"], timeout=120)
            tgt.wait(timeout=180)
            tg, rep, logs = dt_target(tout.objs()), report(o), dt_logs(o)
            detached = any(x.get("kind") == "detached" for x in o)
            ok = (r.returncode == 0 and detached and len(logs) > 0 and tgt.returncode == 0 and tg.get("errors") == 0 and
                  tg.get("child_exit") == 7 and rep.get("log_dropped") == 0)
            record(name, ok, f"logs_before_detach={len(logs)} detached={detached} target_exit={tgt.returncode} "
                             f"target_errors={tg.get('errors')} child_exit={tg.get('child_exit')} creates={tg.get('creates')} "
                             f"dropped={rep.get('log_dropped')}" +
                             ("" if ok else f" target_stderr={terr.lines[-4:]}" + dt_tail(r)))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            for p_ in procs:
                if p_.poll() is None:
                    p_.kill()


def check_detours_retval(threads=4, iters=3):
    """Return values the UHH way: CreateFileW's entry callback probes its return address
    (probe_add_address from the callback); the return callback logs AX and GetLastError
    (call_func on the hit thread). The logged (name, handle, error) of every workload
    CreateFileW equals what the target itself saw, on every backend, from 4 threads."""
    d, tg_exe = exe("detours_retval.exe"), exe("detours_target.exe")
    if not d or not tg_exe:
        return skip("detours-retval", "detours_retval/detours_target missing")
    from collections import Counter
    wd = dt_dir()
    for bk, extra in (("breakpoint", []), ("hw", []), ("inline", []), ("inline", ["--fallback-hw"])):
        name = f"detours-retval-{bk}{'-fallback' if extra else ''}"
        try:
            r, o, _ = dt_run([d, "--backend", bk, *extra, "--log-entry", "--", tg_exe, "api", "--threads", threads,
                              "--iters", iters, "--dir", wd], timeout=600)
            opens = [x for x in o if x.get("kind") == "open"]
            truth = Counter((x["name"], int(x["handle"], 16), x["error"]) for x in opens)
            tid_of = {}
            for x in opens:
                tid_of.setdefault((x["name"], int(x["handle"], 16)), set()).add(x.get("tid"))
            got, got_h, strays, cf_fail = Counter(), Counter(), [], 0
            entries = Counter()
            for x in o:
                if x.get("kind") != "probe_log":
                    continue
                m = x.get("message", "")
                mm = re.match(r'CreateFileW\("([^"]*)"\) -> handle=0x([0-9a-f]+) error=(-?\d+)', m)
                if mm and mm.group(1).startswith("uhhdt-"):
                    key = (mm.group(1), int(mm.group(2), 16))
                    got_h[key] += 1
                    if int(mm.group(3)) == -1:
                        cf_fail += 1                  # call_func refused: the error is unknown
                    else:
                        got[(*key, int(mm.group(3)))] += 1
                elif m.startswith('entry "') and "uhhdt-" in m:
                    entries[x.get("tid")] += 1
                elif not mm and not m.startswith("entry "):
                    strays.append(m)
            truth_h = Counter((n, h) for (n, h, _) in truth.elements())
            tg, rep = dt_target(o), report(o)
            ret_probes = [p for p in probes(o) if p.get("location", "").startswith("0x")]
            errs = Counter(e for (_, _, e) in truth.elements())
            missing = truth_h - got_h
            missing_tids = sorted({t for k in missing for t in tid_of.get(k, ())})
            ok = (r.returncode == 0 and tg.get("errors") == 0 and sum(truth.values()) == tg.get("creates") and
                  got_h == truth_h and not (got - truth) and not strays and len(ret_probes) >= 1 and
                  rep.get("log_dropped") == 0 and rep.get("error") is None)
            record(name, ok, f"returns logged={sum(got_h.values())}/{sum(truth.values())} handles_equal={got_h == truth_h} "
                             f"errors_equal={not (got - truth)} errors_seen={dict(errs)} "
                             f"return_probes={[(p.get('backend'), p.get('hits')) for p in ret_probes]} "
                             f"dr_repairs={(r.stderr or '').count('repaired hardware breakpoint state')} "
                             f"strays={strays[:3]} target_errors={tg.get('errors')} dropped={rep.get('log_dropped')} "
                             f"err={(rep.get('error') or '')[:160]}" +
                             ("" if ok else f" missing={list(missing.items())[:3]} missing_tids={missing_tids} "
                                            f"entries_by_tid={dict(entries)} extra={list((got - truth).items())[:3]}" + dt_tail(r)))
            if bk != "inline":
                # call_func from a breakpoint/hw callback while ANOTHER thread's call_func is in
                # flight is refused ("no nesting" is session-wide): GetLastError unknown.
                record(f"detours-retval-callfunc-{bk}", cf_fail == 0,
                       f"call_func failures={cf_fail}/{sum(got_h.values())} (concurrent returns on 4 threads)")
        except Exception as e:
            record(name, False, repr(e))
    # A real program: cmd.exe types one file that exists and one that does not.
    content = wd / "uhhdt-type.txt"
    content.write_text("UHHDT-TYPE-CONTENT\n")
    missing = wd / "uhhdt-nosuchfile.txt"
    for bk in DT_BACKENDS:
        name = f"detours-retval-cmd-{bk}"
        try:
            r, o, text = dt_run([d, "--backend", bk, "--", str(SYS32 / "cmd.exe"), "/d", "/c",
                        f"type {content} & type {missing}"], timeout=300)
            rets = [re.match(r'CreateFileW\("([^"]*)"\) -> handle=0x([0-9a-f]+) error=(-?\d+)', m) for m in dt_logs(o)]
            rets = [(m.group(1), int(m.group(2), 16), int(m.group(3))) for m in rets if m]
            good = [x for x in rets if x[0] == content.name]
            bad = [x for x in rets if x[0] == missing.name]
            rep = report(o)
            ok = (any(h not in (0, 0xffffffff, (1 << 64) - 1) and e == 0 for _, h, e in good) and
                  any(h in (0xffffffff, (1 << 64) - 1) and e == 2 for _, h, e in bad) and
                  "UHHDT-TYPE-CONTENT" in text and rep.get("log_dropped") == 0)
            record(name, ok, f"existing={good[:2]} missing={bad[:2]} returns={len(rets)} "
                             f"return_probes={[(p.get('backend'), p.get('hits')) for p in probes(o) if p.get('location', '').startswith('0x')]} "
                             f"err={(rep.get('error') or '')[:160]}" + ("" if ok else dt_tail(r)))
        except Exception as e:
            record(name, False, repr(e))


def check_detours_stdin():
    """withdll semantics: a launched program keeps its own stdin. Detours' withdll starts
    the child with the caller's handles; a filter like sort.exe must read the caller's input
    and see EOF. (UHH's probe_launch gives the child a private pipe instead, writes one
    gate keystroke into it and keeps it open -- see docs/ROADMAP.md, Detours-replica
    findings.)"""
    d = exe("detours_traceapi.exe")
    if not d:
        return skip("detours-launch-stdin", "detours_traceapi missing")
    sort_exe, feed = str(SYS32 / "sort.exe"), "banana\napple\ncherry\n"
    try:
        br = subprocess.run([sort_exe], capture_output=True, text=True, timeout=60, input=feed)
        base = [l for l in br.stdout.splitlines() if l.strip()]
    except Exception as e:
        return record("detours-launch-stdin", False, "baseline: " + repr(e))
    for bk in DT_BACKENDS:
        name = f"detours-launch-stdin-{bk}"
        try:
            r, o, text = dt_run([d, "--backend", bk, "--only", "ReadFile", "--", sort_exe], timeout=60, feed=feed)
            out = text.splitlines()
            ok = r.returncode == 0 and [l for l in out if l.strip()] == base and len(out) == len(br.stdout.splitlines())
            record(name, ok, f"output={out[:5]} expected={br.stdout.splitlines()[:5]} rc={r.returncode}")
        except subprocess.TimeoutExpired:
            record(name, False, "hung: the program never saw EOF on its stdin (killed after 60 s)")
        except Exception as e:
            record(name, False, repr(e))


# ---- examples/famous: classic Frida / API Monitor / Procmon recipes ------------------------
# Every recipe runs under each backend and is compared against the UNINSTRUMENTED run of the
# same target (its own ground-truth JSON line): the program must behave identically
# (except deliberate overrides), and the callbacks' view must equal the ground truth.
FAMOUS_BACKENDS = ("breakpoint", "hw", "inline")


def famous_x86():
    import struct
    data = Path(exe("famous_driver.exe")).read_bytes()[:4096]
    return struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0] == 0x14C


def famous_json_lines(text):
    out = []
    for line in text.splitlines():
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def famous_objs(r, objs):
    """The probe_log records from the session's JSONL file (the "probe: logs -> path" line on
    stderr) instead of the live stdout tail: the target inherits the same stdout, and a
    program writing partial lines (cmd's `type`) interleaves with the tail mid-line. The
    other records (app, probe, probe_report) come from stdout."""
    m = re.search(r"probe: logs -> (.+)", r.stderr or "")
    if not m:
        return objs
    path = Path(m.group(1).strip())
    logs = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("{"):
                    try:
                        o = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if o.get("kind") == "probe_log":
                        logs.append(o)
        path.unlink()
    except OSError:
        return objs
    return [o for o in objs if o.get("kind") != "probe_log"] + logs


def famous(recipe, bk, argv, timeout=600, extra=()):
    r, objs = run([exe("famous_driver.exe"), "--recipe", recipe, "--backend", bk, *extra, "--", *argv],
                  timeout=timeout)
    return r, famous_objs(r, objs)


def famous_msgs(objs, prefix=""):
    return [str(o.get("message", "")) for o in objs
            if o.get("kind") == "probe_log" and str(o.get("message", "")).startswith(prefix)]


def famous_health(rc, objs, bk):
    """Common to every recipe: clean exit, no error, nothing dropped, every probe (incl. the
    return-site probes added at runtime) on exactly the backend asked for, no refusals."""
    rep = report(objs)
    got = sorted({x.get("backend") for x in probes(objs)})
    refused = [m for m in famous_msgs(objs, "return-site") if "REFUSED" in m]
    ok = (rc == 0 and rep.get("error") is None and rep.get("log_dropped") == 0 and got == [bk]
          and not refused)
    return ok, (f"rc={rc} backends={got} dropped={rep.get('log_dropped')} refused={len(refused)} "
                f"err={(rep.get('error') or '')[:140]}")


def famous_kv(message):
    return dict(kv.split("=", 1) for kv in message.split() if "=" in kv)


def check_famous_heap(threads=4, iters=600):
    """Heap tracker: RtlAllocateHeap entry + per-call-site return probe + RtlFreeHeap +
    RtlExitUserProcess, live table in UHH_SHARED. The tracker's allocs/frees/leaks/leaked
    bytes must equal the target's own counts, one heap-leak line per leaked block, and the
    target's output must equal the uninstrumented run."""
    d, t = exe("famous_driver.exe"), exe("famous_heap_target.exe")
    if not d or not t:
        return skip("famous-heap", "famous_driver/famous_heap_target missing")
    argv = [t, "--threads", threads, "--iters", iters]
    try:
        _, base_objs = run(argv, timeout=120)
        base = app(base_objs)
    except Exception as e:
        return record("famous-heap-baseline", False, repr(e))
    record("famous-heap-baseline", base.get("leaks", 0) > 1, json.dumps(base))
    for bk in FAMOUS_BACKENDS:
        name = f"famous-heap-{bk}"
        try:
            r, o = famous("heap", bk, argv)
            a = app(o)
            summ = famous_msgs(o, "heap-summary")
            s = famous_kv(summ[-1]) if summ else {}
            leaks = famous_msgs(o, "heap-leak ")
            leak_bytes = sum(int(famous_kv(m).get("size", 0)) for m in leaks)
            h_ok, h = famous_health(r.returncode, o, bk)
            ok = (h_ok and a == base and len(summ) == 1 and
                  int(s.get("allocs", -1)) == base.get("allocs") and int(s.get("frees", -1)) == base.get("frees") and
                  int(s.get("leaks", -1)) == base.get("leaks") and
                  int(s.get("leaked_bytes", -1)) == base.get("leaked_bytes") and
                  s.get("unmatched") == "0" and s.get("overflow") == "0" and
                  len(leaks) == base.get("leaks") and leak_bytes == base.get("leaked_bytes"))
            record(name, ok, f"summary={summ[-1] if summ else None} leak_lines={len(leaks)} "
                             f"app_same={a == base} {h}")
        except Exception as e:
            record(name, False, repr(e))
    # Inline allocator probe whose callback calls call_func (Process.mainModule) while
    # threads start, the agent's own included. Two agent bugs killed the target here in
    # ~half of short runs: the callback ran before the thread had TLS (the agent's
    # per-thread cache faulted), and the allocations inside call_func's own callee hit the
    # probe again, recursing until STATUS_STACK_OVERFLOW.
    name = "famous-heap-inline-reentry"
    try:
        bad = []
        for i in range(12):
            r, o = famous("heap", "inline", [t, "--threads", 2, "--iters", 50])
            a, s = app(o), famous_kv((famous_msgs(o, "heap-summary") or [""])[-1])
            if r.returncode != 0 or not a or s.get("leaks") != str(a.get("leaks")):
                bad.append(f"run{i}: rc={r.returncode} app_exit={report(o).get('app_exit')} "
                           f"err={(report(o).get('error') or '')[:80]}")
        record(name, not bad, f"failed {len(bad)}/12 " + " | ".join(bad[:3]))
    except Exception as e:
        record(name, False, repr(e))


def famous_file_totals(objs, dirname):
    """Per file name under `dirname`: [writes, written, reads, read] from the probe logs,
    and the NTSTATUS of every logged open."""
    tot, opens = {}, {}
    pat = re.compile(r"^file-(open|read|write) path=(.*?) handle=0x[0-9a-f]+ (?:len=(\d+)|status=0x([0-9a-f]+))")
    marker = "\\" + dirname.lower() + "\\"
    for m in famous_msgs(objs, "file-"):
        g = pat.match(m)
        if not g or marker not in g.group(2).lower():
            continue
        fname = g.group(2).rsplit("\\", 1)[-1].lower()
        if g.group(1) == "open":
            opens.setdefault(fname, []).append(g.group(4))
            continue
        e = tot.setdefault(fname, [0, 0, 0, 0])
        i = 0 if g.group(1) == "write" else 2
        e[i] += 1
        e[i + 1] += int(g.group(3))
    return tot, opens


def famous_file_expect(a):
    return {f["name"].lower(): [f["writes"], f["written"], f["reads"], f["read"]] for f in a.get("files", [])}


def check_famous_files(threads=3, chunks=20):
    """File monitor (Procmon-lite): NtCreateFile (OBJECT_ATTRIBUTES -> path, return probe ->
    handle) + NtReadFile/NtWriteFile. Per file: call counts and byte totals from the logs
    equal the target's workload; launched, attached mid-run (attach-new), and on a real
    system binary (findstr reading a known file)."""
    import os
    import shutil
    d, t = exe("famous_driver.exe"), exe("famous_file_target.exe")
    if not d or not t:
        return skip("famous-files", "famous_driver/famous_file_target missing")
    root = Path(os.environ.get("TEMP", ".")) / "uhh_famous"
    root.mkdir(exist_ok=True)

    def fresh(tag):
        # Created here, so the target's own CreateDirectory is skipped: with the hardware
        # backend's single spare debug register only one NtCreateFile call site can be armed.
        p = root / f"files_{os.getpid()}_{tag}"
        shutil.rmtree(p, ignore_errors=True)
        p.mkdir(parents=True)
        return p

    try:
        bdir = fresh("baseline")
        _, bo = run([t, bdir, "--threads", threads, "--chunks", chunks], timeout=120)
        base = app(bo)
        record("famous-files-baseline", base.get("errors") == 0 and len(base.get("files", [])) == threads + 1,
               json.dumps(base)[:200])
    except Exception as e:
        return record("famous-files-baseline", False, repr(e))
    # Launched. Procmon-style "Path contains <dir>" filter on every backend; unfiltered
    # (capture everything) on breakpoint/inline only -- unfiltered, every NtCreateFile call
    # site in the process needs a return probe, more than the 4 debug registers hold.
    runs = [(bk, True) for bk in FAMOUS_BACKENDS] + [("breakpoint", False), ("inline", False)]
    for bk, filtered in runs:
        name = f"famous-files-{bk}" + ("" if filtered else "-unfiltered")
        try:
            wdir = fresh(bk + ("" if filtered else "_all"))
            r, o = famous("files", bk, [t, wdir, "--threads", threads, "--chunks", chunks],
                          extra=("--filter", wdir.name) if filtered else ())
            a = app(o)
            tot, opens = famous_file_totals(o, wdir.name)
            want = famous_file_expect(a)
            bad_opens = [f for f in want if not opens.get(f) or any(st != "00000000" for st in opens[f])]
            h_ok, h = famous_health(r.returncode, o, bk)
            ok = h_ok and a.get("errors") == 0 and famous_file_expect(base) == want and tot == want and not bad_opens
            record(name, ok, f"{h} files_ok={tot == want} opens_missing={bad_opens} logs={len(famous_msgs(o, 'file-'))}"
                             + ("" if tot == want else f" got={tot} want={want}"))
        except Exception as e:
            record(name, False, repr(e))
    # Attached mid-run: the driver waits for the NEXT famous_file_target.exe; the target
    # sleeps before its workload, so the attach lands first and every operation is seen.
    for bk in FAMOUS_BACKENDS:
        name = f"famous-files-attach-{bk}"
        drv = tgt = None
        try:
            wdir = fresh("attach_" + bk)
            drv = subprocess.Popen([str(d), "--recipe", "files", "--backend", bk, "--filter", wdir.name,
                                    "--attach-new", "famous_file_target.exe", "--timeout", "30000"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            first = drv.stdout.readline()          # {"kind":"waiting_for"} -- printed just before
            time.sleep(1.5)                        # the snapshot of already-running instances
            tgt = subprocess.Popen([str(t), str(wdir), "--threads", str(threads), "--chunks", str(chunks),
                                    "--delay-ms", "2500"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            tout, _ = tgt.communicate(timeout=300)
            out, err = drv.communicate(timeout=300)
            out = first + out

            class _R:
                stderr = err
            objs = famous_objs(_R, famous_json_lines(out))
            a = app([json.loads(line) for line in tout.splitlines() if line.startswith("{")])
            tot, _ = famous_file_totals(objs, wdir.name)
            want = famous_file_expect(a)
            h_ok, h = famous_health(drv.returncode, objs, bk)
            attached = any(x.get("kind") == "attached" for x in objs)
            ok = h_ok and attached and a.get("errors") == 0 and tgt.returncode == 0 and tot == want
            record(name, ok, f"attached={attached} target_rc={tgt.returncode} {h} files_ok={tot == want}"
                             + ("" if ok else f" got={tot} want={want} "
                                              f"stderr={' | '.join(err.strip().splitlines()[-4:])}"))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            for p_ in (tgt, drv):
                if p_ and p_.poll() is None:
                    p_.kill()
    # Real system binaries on a known file: findstr (opens it; observed to read it without
    # NtReadFile -- a file mapping -- so reads are not asserted) and cmd's built-in `type`
    # (NtReadFile: the requested lengths must cover the file).
    sysdir = Path(r"C:\Windows\SysWOW64") if famous_x86() else SYS32
    data_dir = fresh("sysbin")
    data = data_dir / "haystack.txt"
    data.write_text("".join(f"line {i} {'UHHNEEDLE' if i % 7 == 0 else 'hay'}\n" for i in range(400)))
    size = data.stat().st_size
    want_lines = sum(1 for i in range(400) if i % 7 == 0)
    typed = data_dir / "typed.txt"
    for tool, argv in (("findstr", [sysdir / "findstr.exe", "UHHNEEDLE", data]),
                       ("type", [sysdir / "cmd.exe", "/d", "/c", "type", data, ">", typed])):
        for bk in FAMOUS_BACKENDS:
            name = f"famous-files-{tool}-{bk}"
            try:
                if typed.exists():
                    typed.unlink()
                r, o = famous("files", bk, argv, extra=("--filter", "haystack.txt"))
                # The program's own output, compared with the input: findstr's matches are
                # counted in the shared stdout (lines may interleave with the log tail, the
                # needle never appears in a log line); type's goes to a file.
                if tool == "findstr":
                    out_ok, out = r.stdout.count("UHHNEEDLE") == want_lines, f"matches={r.stdout.count('UHHNEEDLE')}/{want_lines}"
                else:
                    same = typed.exists() and typed.read_bytes() == data.read_bytes()
                    out_ok, out = same, f"typed_same={same}"
                tot, opens = famous_file_totals(o, data_dir.name)
                ev = tot.get("haystack.txt", [0, 0, 0, 0])
                h_ok, h = famous_health(r.returncode, o, bk)
                reads_ok = tool == "findstr" or (ev[2] >= 1 and ev[3] >= size)
                ok = (h_ok and out_ok and bool(opens.get("haystack.txt")) and
                      all(st == "00000000" for st in opens["haystack.txt"]) and reads_ok)
                record(name, ok, f"{h} {out} opens={opens.get('haystack.txt')} reads={ev[2]} read_len={ev[3]} size={size}")
            except Exception as e:
                record(name, False, repr(e))


def check_famous_tls():
    """TLS plaintext capture: sspicli!EncryptMessage (plaintext at entry) and DecryptMessage
    (plaintext at the call site's return) inside the real curl.exe (SChannel) talking to a
    local HTTPS server. The request line/header and the response marker must appear in
    the logs, and curl must print the same body as uninstrumented."""
    d = exe("famous_driver.exe")
    if not d:
        return skip("famous-tls", "famous_driver missing")
    curl = (Path(r"C:\Windows\SysWOW64") if famous_x86() else SYS32) / "curl.exe"
    if not curl.exists():
        return record("famous-tls", False, f"{curl} not present (offline TLS client needed)")
    server_py = Path(__file__).resolve().parent.parent / "examples" / "famous" / "tls_capture" / "tls_server.py"
    srv = subprocess.Popen([sys.executable, "-u", str(server_py)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True)
    try:
        port = json.loads(srv.stdout.readline())["port"]
        marker_req, marker_resp = "request-marker-91c2", "UHH-TLS-RESPONSE-MARKER-7f3a"
        argv = [curl, "-s", "-k", "--ssl-no-revoke", "-H", f"X-UHH: {marker_req}",
                f"https://127.0.0.1:{port}/uhh-secret-path?token=s3cr3t"]
        b = subprocess.run([str(x) for x in argv], capture_output=True, text=True, timeout=60)
        body = [line for line in b.stdout.splitlines() if line.startswith(marker_resp)]
        record("famous-tls-baseline", b.returncode == 0 and len(body) == 1,
               f"rc={b.returncode} body={body} err={b.stderr.strip()[:120]}")
        for bk in FAMOUS_BACKENDS:
            name = f"famous-tls-{bk}"
            try:
                r, o = famous("tls", bk, argv, timeout=180)
                got_body = [line for line in r.stdout.splitlines() if line.startswith(marker_resp)]
                enc = famous_msgs(o, "tls-encrypt")
                dec = famous_msgs(o, "tls-decrypt")
                req_seen = any("GET /uhh-secret-path?token=s3cr3t HTTP/1.1" in m and marker_req in m for m in enc)
                resp_seen = any(marker_resp in m and "path=/uhh-secret-path?token=s3cr3t" in m for m in dec)
                h_ok, h = famous_health(r.returncode, o, bk)
                ok = h_ok and got_body == body and req_seen and resp_seen
                record(name, ok, f"{h} encrypt_logs={len(enc)} decrypt_logs={len(dec)} request_seen={req_seen} "
                                 f"response_seen={resp_seen} body_same={got_body == body}")
            except Exception as e:
                record(name, False, repr(e))
    except Exception as e:
        record("famous-tls", False, repr(e))
    finally:
        srv.kill()
        srv.wait()


def check_famous_loader(threads=4):
    """Loader / unpacker signals: LoadLibraryExW + LdrLoadDll names, and RWX transitions at
    NtAllocateVirtualMemory / NtProtectVirtualMemory. Every worker's RWX allocation and
    RW->RWX protect is logged exactly once (by its fingerprint size); the W^X-correct
    RX protect is not; all three loads are seen by both probes; the target's output equals
    the uninstrumented run (the generated code still runs)."""
    d, t = exe("famous_driver.exe"), exe("famous_loader_target.exe")
    if not d or not t:
        return skip("famous-loader", "famous_driver/famous_loader_target missing")
    argv = [t, "--threads", threads]
    try:
        _, bo = run(argv, timeout=120)
        base = app(bo)
        record("famous-loader-baseline", base.get("jit_ok") == 2 * threads and base.get("errors") == 0 and
               base.get("loads_ok") == 2 and base.get("loads_failed") == 1, json.dumps(base))
    except Exception as e:
        return record("famous-loader-baseline", False, repr(e))
    names = ("version.dll", "dbghelp.dll", "uhh_no_such_module.dll")
    for bk in FAMOUS_BACKENDS:
        name = f"famous-loader-{bk}"
        try:
            r, o = famous("loader", bk, argv)
            a = app(o)
            allocs = [famous_kv(m) for m in famous_msgs(o, "rwx-alloc ")]
            prots = [famous_kv(m) for m in famous_msgs(o, "rwx-protect ")]
            alloc_hits = [sum(1 for x in allocs if x.get("size") == f"0x{0x13000 + k * 0x1000:x}") for k in range(threads)]
            prot_hits = [sum(1 for x in prots if x.get("size") == f"0x{0x25000 + k * 0x1000:x}") for k in range(threads)]
            ll = " ".join(famous_msgs(o, "loadlibraryexw ")).lower()
            ldr = " ".join(famous_msgs(o, "ldrloaddll ")).lower()
            loads_ok = all(n in ll and n in ldr for n in names)
            fp = {f"0x{0x13000 + k * 0x1000:x}" for k in range(threads)} | {f"0x{0x25000 + k * 0x1000:x}" for k in range(threads)}
            other = [m for m in famous_msgs(o, "rwx-") if famous_kv(m).get("size") not in fp]
            h_ok, h = famous_health(r.returncode, o, bk)
            ok = h_ok and a == base and alloc_hits == [1] * threads and prot_hits == [1] * threads and loads_ok
            record(name, ok, f"{h} rwx_alloc={alloc_hits} rwx_protect={prot_hits} other_rwx_events={len(other)} {other[:3]} "
                             f"loads_seen={loads_ok} app_same={a == base}")
        except Exception as e:
            record(name, False, repr(e))


def check_famous_retval(threads=4, calls=25):
    """Return-value override: GetTickCount's entry arms a probe at each main-module call
    site's return address, which sets AX. Every call the program makes returns the forced
    value (baseline: none), so its Sleep(150) timing check reads 'fast'; GetTickCount64
    (the control) is untouched."""
    d, t = exe("famous_driver.exe"), exe("famous_tick_target.exe")
    if not d or not t:
        return skip("famous-retval", "famous_driver/famous_tick_target missing")
    argv = [t, "--threads", threads, "--calls", calls]
    total = threads * calls + calls + 2
    try:
        _, bo = run(argv, timeout=120)
        base = app(bo)
        record("famous-retval-baseline", base.get("calls") == total and base.get("forced") == 0 and
               base.get("timing_check") == "slow", json.dumps(base))
    except Exception as e:
        return record("famous-retval-baseline", False, repr(e))
    # Each backend 3x: the return-site probes are added while the workers may still be in
    # their loader initialisation -- the hardware path once lost them for whole threads
    # (NtContinue at thread start restored the creation-time debug registers).
    for bk in FAMOUS_BACKENDS:
        name = f"famous-retval-{bk}"
        try:
            ok, details = True, []
            for _ in range(3):
                r, o = famous("tick", bk, argv, extra=("--value", "0x1337BEEF"))
                a = app(o)
                armed = [m for m in famous_msgs(o, "return-site") if m.endswith("armed")]
                h_ok, h = famous_health(r.returncode, o, bk)
                run_ok = (h_ok and a.get("calls") == total and a.get("forced") == total and a.get("elapsed") == 0 and
                          a.get("timing_check") == "fast" and a.get("tick64_forced") == 0 and len(armed) >= 2)
                ok = ok and run_ok
                if not run_ok or not details:
                    details.append(f"{h} forced={a.get('forced')}/{total} main={a.get('forced_main')} "
                                   f"workers={a.get('forced_workers')} timing={a.get('timing_check')} "
                                   f"return_sites={len(armed)}")
            record(name, ok, " || ".join(details))
        except Exception as e:
            record(name, False, repr(e))

def feed_keystrokes():
    """Targets that wait for a keystroke (probe_app's gate and the other --no-wait-less
    fixtures) read it from the stdin they inherit -- through the tool, exactly as if a user
    pressed a key; UHH passes the caller's stdin through untouched. Give every child of this
    run a stdin of newlines (one shared file offset, so each reader takes its own), unless a
    check feeds one explicitly."""
    keys = tempfile.TemporaryFile()
    keys.write(b"\n" * (1 << 20)); keys.flush(); keys.seek(0)
    os.dup2(keys.fileno(), 0)        # also the process's STD_INPUT_HANDLE, inherited by children


HUNT_READ = "ntdll.dll!NtReadVirtualMemory"


def hunt_run(backend, scenario, n, extra=(), timeout=600, readers=None):
    """hunt_driver (gated_config instrumentation + a stressor) on hunt_target <scenario>.
    Logs are stream-counted, never retained. readers: exit scenarios' reader threads."""
    import os
    d, t = exe("hunt_driver.exe"), exe("hunt_target.exe")
    st = {"read": 0, "unmapped": 0, "pids": set(), "work": 0, "tid_ok": 0, "tid_bad": 0,
          "recurse_ok": 0, "other": 0}
    keep = []

    def on_line(line, _t):
        if not line.startswith("{"):
            return
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            return
        if o.get("kind") != "probe_log":
            keep.append(o)
            return
        m = str(o.get("message", ""))
        if m.startswith("read handle="):
            st["read"] += 1
            pid = int(m.split(" pid=")[1].split()[0])
            st["pids"].add(pid)
            if pid == 0:
                st["unmapped"] += 1
        elif m.startswith("work "):
            st["work"] += 1
        elif m.startswith("callfunc "):
            ok = m.startswith("callfunc ok=1 ") and int(m.split("tid=")[1]) == o.get("tid")
            st["tid_ok" if ok else "tid_bad"] += 1
        elif m.startswith("recurse ok=1 status=0x0"):
            st["recurse_ok"] += 1
        elif m.startswith("open pid=") or m.startswith("map handle="):
            pass                      # gated_config's open log / handle -> pid -> name map lines
        else:
            st["other"] += 1
    if readers:
        os.environ["HUNT_READERS"] = str(readers)
    try:
        rc, timed_out = stream_run([d, "--backend", backend, *extra, "--", t, scenario, "--n", n], timeout, on_line)
    finally:
        os.environ.pop("HUNT_READERS", None)
    tg = next((o for o in keep if o.get("kind") == "target"), {})
    rd = next((o for o in keep if o.get("kind") == "probe" and o.get("location") == HUNT_READ), {})
    wk = next((o for o in keep if o.get("kind") == "probe" and "HuntWork" in str(o.get("location"))), {})
    return rc, timed_out, tg, rd, wk, report(keep), st


def hunt_selected(name):
    """UHH_HUNT=sub1,sub2 narrows the hunt cases (debugging aid; default: all)."""
    import os
    flt = [x for x in os.environ.get("UHH_HUNT", "").split(",") if x]
    return not flt or any(x in name for x in flt)


HUNT_CASES = [  # (scenario, n, extra driver args ("@" = the backend under test), timeout)
    ("churn", 100, (), 900), ("pool", 100, (), 600), ("fiber", 50, (), 600), ("apc", 100, (), 600),
    ("veh", 150, (), 600), ("dll", 60, ("--work-backend", "@"), 900), ("ctx", 3000, (), 600),
    ("threads", 4, ("--slow-ms", "50"), 600), ("threads", 20, ("--tid",), 600),
    ("threads", 20, ("--recurse",), 600), ("early", 10, (), 300),
    ("owndr", 200, (), 300),
]


def check_hunt():
    """Edge-case hunter (examples/hunt): gated_config's NtOpenProcess map + per-read pid log
    under concurrency / lifecycle stress, every backend. Every read the target makes must be
    one hit and one log carrying the target's pid; nothing dropped; the program's own result
    (reads, verify failures, foreign debug exceptions, checksum) equals an uninstrumented run."""
    d, t = exe("hunt_driver.exe"), exe("hunt_target.exe")
    if not d or not t or not exe("hunt_dll.dll"):
        return skip("hunt", "hunt_driver / hunt_target / hunt_dll missing")
    _, o = run([t, "threads", "--n", 10], timeout=120)
    checksum = next((x for x in o if x.get("kind") == "target"), {}).get("checksum")
    for bk in ("inline", "hw", "breakpoint"):
        for sc, n, extra, to in HUNT_CASES:
            extra = tuple(bk if x == "@" else x for x in extra)
            tag = "-".join(x.lstrip("-") for x in extra if not x.isdigit() and x != bk)
            name = f"hunt-{sc}{'-' + tag if tag else ''}-{bk}"
            if not hunt_selected(name):
                continue
            try:
                rc, tmo, tg, rd, wk, rep, st = hunt_run(bk, sc, n, extra, timeout=to)
                reads = tg.get("reads")
                want_hits = reads * 2 if (reads and "--recurse" in extra) else reads
                ok = (not tmo and rc == 0 and reads and tg.get("bad") == 0 and tg.get("foreign") == 0 and
                      tg.get("checksum") == checksum and rd.get("hits") == want_hits and st["read"] == reads and
                      st["unmapped"] == 0 and st["pids"] == {tg.get("pid")} and rep.get("log_dropped") == 0 and
                      rep.get("app_exit") == 0 and st["other"] == 0)
                if "--work-backend" in extra:
                    ok = ok and wk.get("hits") == tg.get("work") == st["work"] and tg.get("work") == 4 * n
                if "--tid" in extra:
                    ok = ok and st["tid_ok"] == reads and st["tid_bad"] == 0
                if "--recurse" in extra:
                    ok = ok and st["recurse_ok"] == reads
                record(name, ok, f"reads={reads} hits={rd.get('hits')} logs={st['read']} unmapped={st['unmapped']} "
                                 f"bad={tg.get('bad')} foreign={tg.get('foreign')} early={tg.get('early')} "
                                 f"dropped={rep.get('log_dropped')} exit={rep.get('app_exit')} rc={rc} timeout={tmo}"
                                 + (f" work={tg.get('work')}/{wk.get('hits')}/{st['work']}" if wk or tg.get("work") else "")
                                 + (f" tid_ok={st['tid_ok']} tid_bad={st['tid_bad']}" if "--tid" in extra else "")
                                 + (f" recurse_ok={st['recurse_ok']}" if "--recurse" in extra else "")
                                 + (f" other={st['other']}" if st["other"] else "")
                                 + ("" if ok else f" err={(rep.get('error') or '')[:160]}"))
            except Exception as e:
                record(name, False, repr(e))
        # Process exit racing in-flight callbacks and logs: no hang, the exit code is the
        # target's, and every hit is a delivered log, an honestly counted drop, or (inline
        # only: the process killed the thread mid-callback) a reported interrupted callback.
        for sc, code in (("exit-return", 5), ("exit-process", 6), ("exit-terminate", 7)):
            name = f"hunt-{sc}-{bk}"
            if not hunt_selected(name):
                continue
            try:
                # 2 readers on the debug-event backends: 8 starve the exiting thread (below).
                rc, tmo, tg, rd, wk, rep, st = hunt_run(bk, sc, 300, (), timeout=180,
                                                        readers=8 if bk == "inline" else 2)
                hits = rd.get("hits") or 0
                cut = rep.get("callbacks_interrupted")
                ok = (not tmo and rep.get("app_exit") == code and hits > 0 and tg.get("bad") == 0 and cut is not None and
                      st["read"] + (rep.get("log_dropped") or 0) + cut == hits and st["unmapped"] == 0 and
                      (bk == "inline" or cut == 0))
                record(name, ok, f"exit={rep.get('app_exit')} hits={hits} logs={st['read']} dropped={rep.get('log_dropped')} "
                                 f"interrupted={cut} "
                                 f"reads_at_print={tg.get('reads_at_exit')} rc={rc} timeout={tmo}")
            except Exception as e:
                record(name, False, repr(e))
        # Starvation: 8 threads hitting the probe back to back while main sleeps 300 ms and
        # calls ExitProcess. Uninstrumented: ~0.3 s. Every debug event freezes the whole
        # process, so on breakpoint/hw a thread that hits no probe only runs in the gaps
        # between events (Hunter A finding; see ROADMAP). Bar: exits within 60 s.
        name = f"hunt-starve-{bk}"
        if hunt_selected(name):
            try:
                t0 = time.perf_counter()
                rc, tmo, tg, rd, wk, rep, st = hunt_run(bk, "exit-process", 300, (), timeout=60, readers=8)
                secs = time.perf_counter() - t0
                ok = not tmo and rep.get("app_exit") == 6
                record(name, ok, f"exit={rep.get('app_exit')} secs={secs:.1f} hits={(rd or {}).get('hits')} "
                                 f"reads_at_print={tg.get('reads_at_exit')} timeout={tmo}")
            except Exception as e:
                record(name, False, repr(e))


# ---------------------------------------------------------------------------------------
# Blog replicas (examples/blogs): API-monitor scenarios from well-known write-ups, each run
# uninstrumented (baseline) and under every backend. The target's deterministic results
# must equal the baseline; every logged argument must match what the target did.
BLOG_RUNS = {   # scenario -> (target args, fields that must equal the baseline)
    "crypto": (["--threads", 6, "--files", 20],
               ["threads", "files", "bcrypt_encrypt", "genrandom", "capi_encrypt", "roundtrip_ok", "written",
                "pt_checksum", "dir_removed"]),
    "registry": (["--threads", 4, "--values", 25], ["threads", "values", "created", "set", "readback_ok", "cleaned"]),
    "net": (["--threads", 4, "--per", 4], ["clients", "exchanges_ok", "dns_calls", "dns_ok", "connect_calls",
                                           "wsaconnect_calls"]),
    "spawn": (["--threads", 4, "--children", 6], ["threads", "children", "started", "exit_ok"]),
    "com": (["--threads", 3, "--objects", 8], ["threads", "objects", "created", "saved", "removed"]),
    "game": (["--frames", 2000], ["frames", "checksum"]),
}
SHELL_LINK_CLSID = "{00021401-0000-0000-C000-000000000046}"


def blog_run(args, timeout):
    """run() for the blog checks, safe against a HANG: on timeout the whole tree is killed
    (the target inherits the driver's pipes, so killing only the driver would leave
    communicate() waiting forever) and TimeoutExpired carries what was printed so far."""
    p = subprocess.Popen([str(a) for a in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         errors="replace")
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        subprocess.run(["taskkill", "/f", "/t", "/pid", str(p.pid)], capture_output=True)
        subprocess.run(["taskkill", "/f", "/im", "blog_target.exe"], capture_output=True)
        try:
            out, err = p.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        raise subprocess.TimeoutExpired(p.args, timeout, out, err)
    objs = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return subprocess.CompletedProcess(p.args, p.returncode, out, err), objs


def blog_target_json(objs):
    return next((o for o in objs if o.get("kind") == "target"), {})


def blog_hits(objs, suffix):
    return next((p.get("hits") for p in probes(objs) if str(p.get("location", "")).endswith(suffix)), None)


def blog_registry_gone(pid):
    """True if the target removed its test key; otherwise remove it here and return False."""
    try:
        import winreg
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"Software\UHHBlogTest_{pid}"))
    except OSError:
        return True
    subprocess.run(["reg", "delete", rf"HKCU\Software\UHHBlogTest_{pid}", "/f"], capture_output=True)
    return False


def blog_scenario_ok(scn, bk, tgt, msgs, objs):
    """Scenario-specific: the logged arguments are exactly what the target did. -> (ok, detail)"""
    import re
    if scn == "crypto":
        enc = [m for m in msgs if m.startswith("BCryptEncrypt ") and 'pt="UHHFILE t=' in m]
        capi = [m for m in msgs if m.startswith("CryptEncrypt ") and 'pt="UHHCAPI t=' in m]
        rets = [m for m in msgs if m.startswith("BCryptGenRandom ret ")]
        s = 0
        for m in rets:
            s = (s + int(m.rsplit("key_first8=", 1)[1].split()[0], 16)) % (1 << 64)
        refused = [m for m in msgs if "REFUSED" in m]
        want_sum = int(str(tgt.get("rng_first8_sum", "0")), 16)
        ok = (len(enc) == tgt.get("bcrypt_encrypt") and len(capi) == tgt.get("capi_encrypt") and
              len(rets) == tgt.get("genrandom") and s == want_sum and not refused and
              blog_hits(objs, "!CryptEncrypt") == tgt.get("capi_encrypt"))
        return ok, (f"enc_logs={len(enc)}/{tgt.get('bcrypt_encrypt')} capi_logs={len(capi)}/{tgt.get('capi_encrypt')} "
                    f"rng_ret_logs={len(rets)}/{tgt.get('genrandom')} rng_sum_match={s == want_sum} "
                    f"hits={[(p.get('location'), p.get('backend'), p.get('hits')) for p in probes(objs)]} refused={refused[:1]}")
    if scn == "registry":
        pid = tgt.get("pid")
        sets = [m for m in msgs if m.startswith("NtSetValueKey ") and f"UHHBlogTest_{pid}/T" in m and '/Run"' in m]
        good = 0
        for m in sets:
            mm = re.search(r'value="Updater_(\d+)_(\d+)" type=1 .*data="C:/Users/Public/uhh_(\d+)_(\d+)\.exe /silent"', m)
            t = re.search(rf"UHHBlogTest_{pid}/T(\d+)/", m)
            if mm and t and mm.group(1) == mm.group(3) == t.group(1) and mm.group(2) == mm.group(4):
                good += 1
        creates = [m for m in msgs if m.startswith("NtCreateKey ") and "/Run" in m and f"UHHBlogTest_{pid}" in m]
        gone = blog_registry_gone(pid)
        ok = len(sets) == tgt.get("set") and good == len(sets) and len(creates) >= (tgt.get("created") or 1) and gone
        return ok, f"set_logs={len(sets)}/{tgt.get('set')} decoded_ok={good} create_logs={len(creates)} key_removed={gone}" + \
            ("" if ok else f" sample={next((m for m in msgs if m.startswith('NtSetValueKey')), '')[:200]!r}")
    if scn == "net":
        port = tgt.get("port")
        conns = [m for m in msgs if m.startswith("connect ") and m.endswith(f"addr=127.0.0.1:{port}")]
        reqs = [m for m in msgs if m.startswith("send ") and 'data="UHHREQ id=' in m]
        rsps = [m for m in msgs if m.startswith("send ") and 'data="UHHRSP id=' in m]
        dns = [m for m in msgs if m.startswith('DnsQuery_W name="localhost"')]
        hits = {k: blog_hits(objs, k) for k in ("!connect", "!WSAConnect", "!send", "!recv", "!DnsQuery_W")}
        want_dns = None if bk == "hw" else tgt.get("dns_calls")
        ok = (len(conns) == tgt.get("clients") and len(reqs) == tgt.get("clients") and len(rsps) == tgt.get("clients") and
              hits["!send"] == tgt.get("send_calls") and hits["!recv"] == tgt.get("recv_calls") and
              hits["!connect"] == tgt.get("connect_calls") and hits["!WSAConnect"] == tgt.get("wsaconnect_calls") and
              (len(dns) if want_dns is not None else None) == want_dns and hits["!DnsQuery_W"] == want_dns)
        return ok, (f"connect_logs={len(conns)}/{tgt.get('clients')} req={len(reqs)} rsp={len(rsps)} dns_logs={len(dns)} "
                    f"hits={hits} target_send={tgt.get('send_calls')} target_recv={tgt.get('recv_calls')}")
    if scn == "spawn":
        n = tgt.get("children") or 0
        pat = r'cmd=".*blog_target\.exe.? child (\d+)"'
        ids_cp = sorted(int(x) for m in msgs if m.startswith("CreateProcessInternalW ") for x in re.findall(pat, m))
        ids_nt = sorted(int(x) for m in msgs if m.startswith("NtCreateUserProcess ") for x in re.findall(pat, m))
        ok = ids_cp == list(range(n)) and ids_nt == list(range(n))
        return ok, f"CreateProcessInternalW={len(ids_cp)}/{n} NtCreateUserProcess={len(ids_nt)}/{n}" + \
            ("" if ok else f" sample={next((m for m in msgs if m.startswith('NtCreateUserProcess')), '')[:200]!r}")
    if scn == "com":
        links = [m for m in msgs if m.startswith(f"CoCreateInstance clsid={SHELL_LINK_CLSID}")]
        ok = len(links) == tgt.get("created")
        return ok, f"shelllink_logs={len(links)}/{tgt.get('created')} all_cocreate_hits={blog_hits(objs, '!CoCreateInstance')}"
    if scn == "game":
        frames = [m for m in msgs if m.startswith("frame ")]
        seq = [int(m.split()[1]) for m in frames]
        ok = seq == list(range(tgt.get("frames") or 0)) and blog_hits(objs, "!blog_frame") == tgt.get("frames")
        return ok, (f"frame_logs={len(frames)} in_order={seq == sorted(seq)} missed={tgt.get('missed')} "
                    f"cost_us p50/p99/max={tgt.get('cost_us_p50')}/{tgt.get('cost_us_p99')}/{tgt.get('cost_us_max')} "
                    f"late_us p99/max={tgt.get('late_us_p99')}/{tgt.get('late_us_max')}")
    return False, "unknown scenario"


def blog_crypto_naive_hw(d, t, targs, base, fields, rounds=3):
    """The first-cut crypto monitor on hw: BCryptGenRandom re-enters itself, so the
    callback asks for a 5th debug register (a return probe inside bcrypt) from inside a
    callback while other threads are trapped on the entry. The request must be refused
    cleanly and the target must not notice -- it used to die with an unhandled
    STATUS_SINGLE_STEP (a queued #DB whose DR6 was lost when DR3 was armed)."""
    name = "blog-crypto-naive-hw"
    print(f"  .. {name}", file=sys.stderr, flush=True)
    for i in range(rounds):
        r, o = blog_run([d, "--scenario", "crypto", "--backend", "hw", "--naive", "--", t, "crypto", *targs], timeout=300)
        tgt, rep = blog_target_json(o), report(o)
        msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
        refused = sum("REFUSED" in m for m in msgs)
        rets = sum(m.startswith("BCryptGenRandom ret ") for m in msgs)
        diff = {f: (base.get(f), tgt.get(f)) for f in fields if base.get(f) != tgt.get(f)}
        ok = (r.returncode == 0 and rep.get("app_exit") == 0 and not diff and refused >= 1 and
              rets == tgt.get("genrandom") and rep.get("log_dropped") == 0 and rep.get("error") is None and
              "not ours passed to the target" not in (r.stderr or ""))
        if not ok or i == rounds - 1:
            return record(name, ok, f"round={i + 1}/{rounds} refused_logs={refused} rng_ret_logs={rets}/{tgt.get('genrandom')} "
                                    f"vs_baseline={'same' if not diff else diff} rc={r.returncode} exit={rep.get('app_exit')} "
                                    f"stray_db={[l for l in (r.stderr or '').splitlines() if 'not ours' in l][:1]}")


def check_blog_replicas():
    """Blog replicas: crypto-API monitor, registry Run-key monitor, DNS/socket logger,
    process-creation tracker, COM CLSID logger, game-loop frame probe -- each against an
    uninstrumented baseline of the same target, under breakpoint, hw and inline.
    UHH_BLOG_SCENARIOS=crypto,net limits the scenarios (default: all)."""
    d, t = exe("blog_driver.exe"), exe("blog_target.exe")
    if not d or not t:
        return skip("blog", "blog_driver/blog_target missing")
    import os as _os
    want_scn = [x for x in _os.environ.get("UHH_BLOG_SCENARIOS", "").split(",") if x] or list(BLOG_RUNS)
    want_bk = [x for x in _os.environ.get("UHH_BLOG_BACKENDS", "").split(",") if x] or ["breakpoint", "hw", "inline"]
    for scn in want_scn:
        targs, fields = BLOG_RUNS[scn]
        try:
            _, bo = blog_run([t, scn, *targs], timeout=120)
            base = blog_target_json(bo)
            if scn == "registry":
                blog_registry_gone(base.get("pid"))
            record(f"blog-{scn}-baseline", bool(base) and all(f in base for f in fields),
                   " ".join(f"{k}={v}" for k, v in base.items() if k not in ("kind", "scenario")))
        except Exception as e:
            record(f"blog-{scn}-baseline", False, repr(e)); continue
        for bk in want_bk:
            name = f"blog-{scn}-{bk}"
            print(f"  .. {name}", file=sys.stderr, flush=True)
            try:
                r, o = blog_run([d, "--scenario", scn, "--backend", bk, "--", t, scn, *targs], timeout=300)
                tgt, rep = blog_target_json(o), report(o)
                msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
                diff = {f: (base.get(f), tgt.get(f)) for f in fields if base.get(f) != tgt.get(f)}
                prs = probes(o)
                generic = (r.returncode == 0 and rep.get("error") is None and rep.get("log_dropped") == 0 and
                           rep.get("app_exit") == 0 and bool(tgt) and not diff and
                           rep.get("logs_written") == len(msgs) and
                           # inline return probes may fall back to hw (PROBE_FALLBACK_HW)
                           all(p.get("backend") == bk or (p.get("backend") == "hw" and bk == "inline") for p in prs) and
                           all(p.get("active") or p.get("hits") for p in prs))
                sok, sdet = blog_scenario_ok(scn, bk, tgt, msgs, o)
                record(name, generic and sok,
                       f"{sdet} vs_baseline={'same' if not diff else diff} rc={r.returncode} exit={rep.get('app_exit')} "
                       f"logs={len(msgs)}/{rep.get('logs_written')} dropped={rep.get('log_dropped')} "
                       f"err={(rep.get('error') or '')[:160]}" +
                       ("" if generic else f" probes={[(p.get('location'), p.get('backend'), p.get('active'), p.get('hits')) for p in prs]}"
                                           f" stderr={(r.stderr or '')[-300:]!r}"))
                if scn == "crypto" and bk == "hw":
                    blog_crypto_naive_hw(d, t, targs, base, fields)
            except subprocess.TimeoutExpired as e:
                # A hang is a bug: say where it stopped (last lines of the driver's output).
                out, err = e.stdout or "", e.stderr or ""
                record(name, False, f"HANG (>{e.timeout}s) stdout_tail={out.strip().splitlines()[-3:]} "
                                    f"stderr_tail={err.strip().splitlines()[-4:]}")
                if scn == "registry":
                    subprocess.run(["powershell", "-NoProfile", "-Command",
                                    "Get-ChildItem HKCU:\\Software | ?{ $_.PSChildName -like 'UHHBlogTest_*' } | "
                                    "Remove-Item -Recurse -Force"], capture_output=True)
            except Exception as e:
                record(name, False, repr(e))


def check_blog_pwsh_attach():
    """JIT/managed process (the 'hook a .NET host' write-ups): attach to a running
    powershell.exe, hook kernelbase!CreateFileW, which its script drives via [IO.File],
    detach mid-run. PowerShell must finish with the same output and exit code."""
    t = exe("uhh_trace.exe")
    if not t:
        return skip("blog-pwsh", "uhh_trace.exe missing")
    import os as _os
    import struct
    data = Path(t).read_bytes()
    x86 = struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0] == 0x14C
    ps = Path(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe") if x86 else \
        SYS32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not ps.exists():
        return skip("blog-pwsh", f"{ps} missing")
    iters = 400
    # Warm-up first: the first Start-Sleep autoloads Microsoft.PowerShell.Utility (1-2 s on
    # the VM), which would otherwise fill the whole attach window with no script activity.
    script = ("$n=0; Start-Sleep -Milliseconds 1; [IO.File]::WriteAllText(\"$env:TEMP\\uhhblog_ps_$($PID)_w.txt\", 'w'); "
              "[IO.File]::Delete(\"$env:TEMP\\uhhblog_ps_$($PID)_w.txt\"); [Console]::Out.WriteLine('PSREADY'); [Console]::Out.Flush(); [void][Console]::In.ReadLine(); "
              f"for($i=0;$i -lt {iters};$i++){{ $p=\"$env:TEMP\\uhhblog_ps_$($PID)_$i.txt\"; "
              "[IO.File]::WriteAllText($p, ('x'*($i%50+1))); $n += ([IO.File]::ReadAllText($p)).Length; "
              "[IO.File]::Delete($p); Start-Sleep -Milliseconds 10 }; [Console]::Out.WriteLine(\"PSDONE $n\")")
    want_n = sum(i % 50 + 1 for i in range(iters))
    want_bk = [x for x in _os.environ.get("UHH_BLOG_BACKENDS", "").split(",") if x] or ["breakpoint", "hw", "inline"]
    for bk in want_bk:
        name = f"blog-pwsh-attach-detach-{bk}"
        print(f"  .. {name}", file=sys.stderr, flush=True)
        target = None
        try:
            target = subprocess.Popen([str(ps), "-NoProfile", "-NonInteractive", "-Command", script],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            tl = Lines(target.stdout)
            if not tl.wait_for(lambda l: "PSREADY" in l, 60):
                raise RuntimeError("powershell never got ready")
            tracer = subprocess.Popen([str(t), "--backend", bk, "--attach", str(target.pid), "--detach-after-ms", "2500",
                                       "-p", "kernelbase.dll!CreateFileW:Wxxxx"],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            tout, terr = Lines(tracer.stdout), Lines(tracer.stderr)
            if not terr.wait_for(lambda l: l.startswith("probe: active kernelbase.dll!CreateFileW"), 60):
                raise RuntimeError("probe never became active: " + " | ".join(terr.lines[-5:]))
            target.stdin.write("\n"); target.stdin.flush()
            tracer.wait(timeout=180)
            tout.t.join(timeout=30); terr.t.join(timeout=30)
            target.wait(timeout=180)
            tl.t.join(timeout=30)
            done = next((l for l in tl.lines if "PSDONE" in l), "")
            objs = [json.loads(l) for l in tout.lines if l.startswith("{")]
            pr = next(iter(probes(objs)), {})
            msgs = [str(o.get("message", "")) for o in objs if o.get("kind") == "probe_log"]
            ours = [m for m in msgs if "uhhblog_ps_" in m]
            detached = any(o.get("kind") == "detached" for o in objs)
            rep = report(objs)
            ok = (done.strip() == f"PSDONE {want_n}" and target.returncode == 0 and detached and
                  rep.get("log_dropped") == 0 and rep.get("error") is None and pr.get("backend") == bk and
                  10 <= len(ours) < 2 * iters)               # 2 opens per iteration: seen, then detached mid-run
            record(name, ok, f"ps_out={done.strip()!r} want=PSDONE {want_n} ps_exit={target.returncode} hits={pr.get('hits')} "
                             f"our_opens_logged={len(ours)}/{2 * iters} detached={detached} dropped={rep.get('log_dropped')} "
                             f"err={(rep.get('error') or '')[:120]}" +
                             ("" if ok else f" tracer_stderr={' | '.join(terr.lines[-6:])[:600]}"))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            if target and target.poll() is None:
                target.kill()


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
    feed_keystrokes()

    import os as _os

    def sweep_logs():
        """Every UHH session keeps its log file (%TEMP%\\uhh\\logs\\uhh-*.jsonl) -- that is the
        product. The suite runs hundreds of sessions (some with 20M logs), so it deletes the
        files it produced after each check; a file still open by a live session is skipped."""
        d = Path(_os.environ.get("TEMP", ".")) / "uhh" / "logs"
        import time as _t
        for f in d.glob("uhh-*.jsonl") if d.is_dir() else []:
            try:
                if _t.time() - f.stat().st_mtime < 600:
                    continue          # recent: may belong to a suite running in parallel (other arch)
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
    if want(check_gated_map): check_gated_map()
    if want(check_gated_filter): check_gated_filter()
    if want(check_callorig): check_callorig()
    if want(check_callorig_hunt): check_callorig_hunt()
    if want(check_callconv): check_callconv()
    if want(check_interrupt): check_interrupt()
    if want(check_agent_crt): check_agent_crt()
    if want(check_oldcrt): check_oldcrt()
    if want(check_cet): check_cet()
    if want(check_shared_mix): check_shared_mix()
    if want(check_handle_map): check_handle_map()
    if want(check_gated_mem): check_gated_mem()
    if want(check_forwarded_probe): check_forwarded_probe()
    if want(check_crash_logs): check_crash_logs()
    if want(check_attach_new): check_attach_new()
    if want(check_refusals): check_refusals()
    if want(check_hotpatch_prologue): check_hotpatch_prologue()
    if want(check_famous_heap): check_famous_heap()
    if want(check_famous_files): check_famous_files()
    if want(check_famous_tls): check_famous_tls()
    if want(check_famous_loader): check_famous_loader()
    if want(check_famous_retval): check_famous_retval()
    if want(check_edgehunt): check_edgehunt()
    if want(check_detours_simple): check_detours_simple()
    if want(check_detours_traceapi): check_detours_traceapi()
    if want(check_detours_withdll): check_detours_withdll()
    if want(check_detours_retval): check_detours_retval()
    if want(check_detours_stdin): check_detours_stdin()
    if want(check_hunt): check_hunt()
    if want(check_blog_replicas): check_blog_replicas()
    if want(check_blog_pwsh_attach): check_blog_pwsh_attach()
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
