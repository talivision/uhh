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
  - bigapps-<app>-<mode>-<backend> (opt-in, --bigapps): powershell.exe and headless Edge
    under every backend, launched / attached to exit / detached mid-run, busy system
    exports probed; program result + exit 0, no unhandled exception, hits > 0,
    log_dropped == 0, logs == hits, still working after detach.
  - newapp-file/flag/reg-<backends>: the new-app examples (filetrace, flagflip, regtrace),
    every backend and mixes, each compared with the ground truth its fixture prints.
  - logs-*: adversarial log delivery (examples/logs_eval): exact text for hostile formats on
    every backend, per-thread order across mixed backends, a producer killed/suspended
    mid-record, the controller killed while attached, the stdout reader going away.
  - gated-e2e-<mode>-f<b>-o<b>-c<b>-r<b>: the flagship use case end to end, every backend for
    each of the flag/open/close/read probes, launch and attach (before/after the config parse),
    compared EXACTLY with the target's own per-thread record (probe_app --churn --truth).
A missing project-built binary (an example not built) is a FAIL, never a SKIP (missing_bin()).
SKIP is only for a check that does not apply to this build (x86-only / x64-only: skip()) or
an absent OPTIONAL EXTERNAL dependency -- Frida, Intel SDE, a system program this Windows
does not ship (skip_external(); a FAIL when --only named the check).
"""
import argparse
import collections
from collections import Counter
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
ONLY = []     # --only substrings (empty: the full suite)


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



def pe_is_x86(path):
    """True for a 32-bit (i386) PE image: the arch from the header, never from a path."""
    data = Path(path).read_bytes()
    return struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0] == 0x14C


def live(result):
    """Each result as it is recorded (timestamped), so a run can be followed in flight;
    the full table is printed again at the end."""
    name, status, detail = result
    print(f"[{time.strftime('%H:%M:%S')}] {status:4}  {name:34} {detail}", flush=True)


def record(name, ok, detail=""):
    RESULTS.append((name, "PASS" if ok else "FAIL", detail))
    live(RESULTS[-1])


def missing_bin(name, what):
    """A PROJECT-BUILT binary (anything this repo's build produces: drivers, targets, DLLs) is
    absent: a FAILURE, never a skip -- a partial build must never look green."""
    RESULTS.append((name, "FAIL", f"missing project-built binary: {what}"))
    live(RESULTS[-1])


def explicitly_selected(name):
    """True when --only names this check (a selector that is a substring of the record name,
    or of check_<name> / check-<name>)."""
    under = "check_" + name.replace("-", "_")
    return any(o in n for o in ONLY for n in (name, under, under.replace("_", "-")))


def skip_external(name, dep, why=""):
    """An OPTIONAL EXTERNAL dependency is absent: Frida, Intel SDE, or a system program this
    Windows does not ship. A SKIP in a general run; a FAILURE when --only named the check
    (it was asked for and could not run)."""
    status = "FAIL" if explicitly_selected(name) else "SKIP"
    RESULTS.append((name, status, f"optional external dependency absent: {dep}" + (f" ({why})" if why else "")
                    + (" -- explicitly selected" if status == "FAIL" else "")))
    live(RESULTS[-1])


def skip(name, why):
    """A check that does not APPLY to this build (e.g. x86-only, x64-only). A SKIP is never
    counted as a pass. Use missing_bin() for an absent project-built binary and skip_external()
    for an absent optional external dependency. (Safety net for callers that still route a
    missing binary here: a reason mentioning "missing" is a FAILURE.)"""
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
        return missing_bin("gated-off", "probe_app.exe")
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
        return missing_bin("mix-matrix", "gated_config.exe")
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
        return missing_bin("multithread-exact", "gated_config.exe")
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
        return missing_bin("attach", "uhh_attach/probe_app")
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
        return missing_bin("log-throughput", "gated_config.exe")
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
        return missing_bin("volume", "gated_config.exe")
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
        return missing_bin("stream-volume", "hitcost driver/target")
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
        return missing_bin("stream-live", "hitcost driver/target")
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
        return missing_bin("stream-sink-speed", "hitcost driver/target")
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
        return missing_bin("stream-latency", "uhh_trace/logstream_target")
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
        return missing_bin("stream-order", "uhh_trace/logstream_target")
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
        return missing_bin("breakage", "breakage_driver/hook_edge")
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
        return missing_bin("frida-parity", "frida_parity/parity_target")
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
        return missing_bin("watchpoint", "watch_driver/watch_target")
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
        return missing_bin("dynwatch", "dynwatch_driver/dynwatch_target")
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
        return missing_bin("conformance", "conformance_driver/target")
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
        return missing_bin("callorig", "conformance_driver/target")
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


# ---- Portability matrix (examples/conformance/matrix_callbacks.cpp) -------------------------
# Expected per-backend values of the DOCUMENTED divergences ("D key=value" lines and target
# observations); None = any value. Everything else must be identical on every backend.
PORTABILITY_DOCUMENTED = {
    "win32.pid-is-target": {"breakpoint": "0", "hw": "0", "inline": "1"},
    # inline callbacks run concurrently on the 5 hitting threads: any of 1..5 (checked below)
    "conc.max-inflight": {"breakpoint": "1", "hw": "1", "inline": None},
    "conc.thread-local-on-main": {"breakpoint": "210", "hw": "210", "inline": "10"},
    "call_func.callee-handles-fault": {"breakpoint": "0 r=7", "hw": "0 r=7", "inline": "1 r=0"},
    # exceptions the PROGRAM's vectored handler saw, as stage:code (4 = the faulting callback,
    # 6 = the throwing callback, stage 1 = lstrlenA's own fault inside call_func)
    "target.veh-A": {"breakpoint": "", "hw": "", "inline": "1:c0000005"},
    "target.veh-B": {"breakpoint": "", "hw": "", "inline": "4:c0000005"},
    "target.veh-C": {"breakpoint": "", "hw": "", "inline": "6:e06d7363"},
}
PORTABILITY_REQUIRED = {
    "A": ["adds.entry", "adds.regs", "adds.other", "args", "mem.get.rw", "mem.set.high", "call_func.plain",
          "add.ok", "add.static-callback", "add.config-308", "add.long-symbol", "log.long", "reg.get.0",
          "reg.set.1", "target.cf", "target.out", "stack.entry"],
    "B": ["adds.fault", "adds.conc", "adds.report", "adds.bigcfg", "fault.before", "conc.total", "config.big",
          "target.fault_r", "target.fault_mark"],
    "C": ["adds.throw", "throw.before", "target.throw_r", "target.throw_mark"],
}


def portability_expect(phase, x86):
    """ABSOLUTE expected values (independent of every backend): what the target and the
    callback source make each API call return. The cross-backend diff only proves the
    backends agree; this proves they agree on the right answer."""
    e = {}
    if phase == "A":
        e.update({"adds.entry": "1", "adds.regs": "1", "adds.other": "1",
                  "args": "1 11 22 33 44 55", "arg.huge-index": "0", "arg.null-ctx": "0",
                  "config": "1 aligned8=1", "config.null-ctx": "0", "reg.null-ctx": "0 set=0", "mem.null-ctx": "0 set=0",
                  "mem.get.addr0": "0", "mem.get.rw": "1 content=1", "mem.get.ro": "1 content=1",
                  "mem.get.reserved": "0", "mem.get.wrap": "0", "mem.get.huge": "0", "mem.get.huge2": "0",
                  "mem.get.high": "0 untouched=1", "mem.get.null-buf": "0",
                  "mem.get.code-mid-site": "9090909090909090",          # PmRegHit: 16 NOPs under this backend's probe
                  "mem.get.code-other-backend": "9090909090909090",     # PmOther: 16 NOPs under the other backend's
                  "mem.set.rw": "1", "mem.set.high": "0", "mem.set.null-buf": "0",
                  "target.w_rw": "a5a5a5a5", "target.head_intact": "1",
                  "call_func.plain": "1 pid=1", "call_func.upper": "1 pid=1", "call_func.path": "1 pid=1",
                  "call_func.off-hex": "1 pid=1", "call_func.no-ext": "1 pid=1", "call_func.off-no-0x": "0 pid=0",
                  "call_func.off-bad": "0 pid=0", "call_func.no-module": "0 pid=0", "call_func.no-export": "0 pid=0",
                  "call_func.empty-export": "0 pid=0", "call_func.empty-module": "0 pid=0",
                  "call_func.nargs9": "0", "call_func.nargs-neg": "0", "call_func.null-symbol": "0",
                  "call_func.empty-symbol": "0", "call_func.address": "1 r=42", "call_func.module-rva": "1 r=42",
                  "call_func.negative-arg": "1 r=-15", "call_func.bad-address": "0",
                  "session": "1", "session.null-ctx": "0", "add.ok": "1", "add.no-export": "0", "add.no-type": "0",
                  "add.null-callback": "0", "add.static-callback": "0", "add.config-308": "1", "add.long-symbol": "1",
                  "add.null-session": "0", "add-address.zero": "0", "watch.on-breakpoint": "0",
                  "log.null-format-follows": "1", "log.bad-format": "k",
                  "reg.get.invalid": "0 0", "reg.set.invalid": "0 0", "call_original.mid": "0 r=1234",
                  "target.cf": "1", "target.entry_r": "165", "target.other_r": "16"})
        # "M log.long=" + 1499 x: a 1024-byte record (1023 chars) with the truncation marker.
        mark = "...[truncated]"
        text = ("M log.long=" + "x" * 1499)[:1023 - len(mark)] + mark
        v = text[len("M log.long="):]
        e["log.long"] = f"len={len(v)} end={v[-16:]}"
        # PmRegSite's constants (conf_sp_x64.asm / conf_sp_x86.asm), probe_register order.
        x64_regs = [0xA0A0A0A0A0A0A000, 0xB1B1B1B1B1B1B101, 0xC2C2C2C2C2C2C202, 0xD3D3D3D3D3D3D303,
                    0x5454545454545404, 0x6565656565656505, 0x7676767676767606, None,
                    0x8888888888888808, 0x9999999999999909, 0xAAAAAAAAAAAAAA0A, 0xBBBBBBBBBBBBBB0B,
                    0xCCCCCCCCCCCCCC0C, 0xDDDDDDDDDDDDDD0D, 0xEEEEEEEEEEEEEE0E, 0xFFFFFFFFFFFFFF0F]
        out = []
        for r in range(16):
            if r == 7:
                out.append("0")
                continue
            if x86:
                got = (x64_regs[r] & 0xFFFFFFFF) if r < 7 else 0
                newv = 0x5E00 + r if r < 7 else None
            else:
                got, newv = x64_regs[r], 0x5E5E000000005E00 + r
            e[f"reg.get.{r}"] = f"{got:x}"
            e[f"reg.set.{r}"] = f"1 now={newv:x}" if newv is not None else "0 now=0"
            out.append(f"{newv:x}" if newv is not None else "0")
        e["target.out"] = ",".join(out)
        if not x86:
            e["reg.get.sp-aligned"] = "1"
        e["reg.arg0"] = "0" if x86 else f"{x64_regs[2]:x}"
        e["return_from.mid-ax"] = "5e00" if x86 else "5e5e000000005e00"
    elif phase == "B":
        # The faulting callback's register change is discarded, its set_mem writes stay: the
        # argument (x64 RDX, x86 a stack slot written with set_mem) is 5 -> 10 on x64, 100 -> 200 on x86.
        e.update({"adds.fault": "1", "adds.conc": "1", "adds.report": "1", "adds.bigcfg": "1",
                  "fault.before": "1", "conc.total": "210", "report.config": "1", "config.big": "1",
                  "target.fault_r": "200" if x86 else "10", "target.fault_mark": "fa017fa0"})
    else:
        e.update({"adds.throw": "1", "throw.before": "1",
                  "target.throw_r": "200" if x86 else "10", "target.throw_mark": "7e40e7e4"})
    return e


# Pairs whose values must AGREE with each other (the API's answer == what the target saw).
PORTABILITY_CONSISTENT = [
    ("mem.set.ro", "target.ro_intact"),            # a write that succeeded must have changed the page
    ("mem.set.partial", "target.partial_intact"),   # a refused partial write must leave every byte
]


def matrix_values(o, phase):
    """One backend's run -> ({key: value} that must match, {key: value} documented)."""
    vals, doc = {}, {}

    def put(d, k, v):
        d[k] = v if k not in d else d[k] + "|" + v
    for x in o:
        kind = x.get("kind")
        if kind == "probe_log":
            m = str(x.get("message", ""))
            tag = ""
            if m.startswith("[unformattable] "):
                tag, m = "[unformattable]", m[len("[unformattable] "):]
            if m.startswith("S "):
                frames = x.get("stack") or []
                put(vals if m == "S entry" else doc, "stack." + m[2:], " < ".join(str(f) for f in frames[:2]))
            elif not (m[:2] in ("M ", "D ") and "=" in m):
                put(vals, "logs.other", m)               # any other record (e.g. a library warning)
            else:
                k, v = m[2:].split("=", 1)
                if k == "log.long":
                    v = f"len={len(v)} end={v[-16:]}"
                put(vals if m[0] == "M" else doc, k, tag + v)
        elif kind == "matrix_adds":
            for k, v in x.items():
                if k not in ("kind", "phase"):
                    vals["adds." + k] = str(v)
        elif kind == "matrix":
            for k, v in x.items():
                if k in ("kind", "veh_n"):
                    continue
                if k == "veh":
                    doc["target.veh-" + phase] = ",".join(v)
                else:
                    vals["target." + k] = ",".join(v) if isinstance(v, list) else str(v)
        elif kind == "probe_report":
            vals["report.error"] = str(x.get("error"))
            vals["report.log_dropped"] = str(x.get("log_dropped"))
    return vals, doc


def check_portability():
    """The SAME callback source must observe and do the same under breakpoint, hw and inline:
    every API a callback can call (registers incl. CF and invalid ids, memory of every kind and
    bad ranges, args, config incl. > 256 bytes, call_func symbol forms and failures, the control
    plane from a callback, logging edge cases, a faulting / throwing callback, concurrency). Each
    phase runs the matrix under all three backends and diffs the M lines; documented
    divergences must have exactly their documented value per backend."""
    d, t = exe("conformance_driver.exe"), exe("conformance_target.exe")
    if not d or not t:
        return missing_bin("portability", "conformance_driver/target")
    x86 = pe_is_x86(t)
    docs_seen = {}
    for phase in ("A", "B", "C"):
        name = f"portability-matrix-{phase}"
        try:
            per, rcs = {}, {}
            for bk in ("breakpoint", "hw", "inline"):
                r, o = run([d, "--backend", bk, "--matrix", phase, "--", t, "--matrix"], timeout=120)
                vals, doc = matrix_values(o, phase)
                per[bk] = vals
                rcs[bk] = (r.returncode, report(o).get("app_exit"))
                docs_seen.setdefault(bk, {}).update(doc)
            keys = sorted(set().union(*[set(v) for v in per.values()]))
            diffs = [k for k in keys if len({per[bk].get(k) for bk in per}) > 1]
            missing = [k for k in PORTABILITY_REQUIRED[phase] for bk in per if k not in per[bk]]
            errors = [bk for bk in per if per[bk].get("report.error") != "None" or per[bk].get("report.log_dropped") != "0"]
            # Every controller and target must have exited 0 (three identically broken runs
            # would otherwise agree with each other).
            rc_bad = {bk: v for bk, v in rcs.items() if v != (0, 0)}
            exp = portability_expect(phase, x86)
            wrong = [f"{k}[{bk}]={per[bk].get(k)!r} want {v!r}" for k, v in exp.items() for bk in per
                     if per[bk].get(k) != v]
            for a, b in PORTABILITY_CONSISTENT:
                for bk in per:
                    if a in per[bk] and per[bk].get(a) == per[bk].get(b):   # set ok=1 <-> intact=0
                        wrong.append(f"{a}={per[bk].get(a)} but {b}={per[bk].get(b)} [{bk}]")
            gone = [f"{k}[{bk}]" for k in ("fault.after", "throw.after") for bk in per if k in per[bk]]
            for k in diffs:
                print(f"    {name} DIFF {k}: " + " | ".join(f"{bk}={per[bk].get(k)}" for bk in per), flush=True)
            for w in wrong:
                print(f"    {name} WRONG {w}", flush=True)
            record(name, not diffs and not missing and not errors and not rc_bad and not wrong and not gone,
                   f"keys={len(keys)} absolute={len(exp)} diffs={diffs[:6]} wrong={wrong[:4]} "
                   f"missing={sorted(set(missing))[:4]} report_errors={errors} rc(ctl,app)={rc_bad} after_fault={gone}")
        except Exception as e:
            record(name, False, repr(e))
    bad = []
    for k, want in PORTABILITY_DOCUMENTED.items():
        for bk, v in want.items():
            got = docs_seen.get(bk, {}).get(k)
            if got is None or (v is not None and got != v):
                bad.append(f"{k}[{bk}]={got!r}")
    # inline's max-inflight: concurrent callbacks on the 5 hitting threads, 1..5.
    mi = docs_seen.get("inline", {}).get("conc.max-inflight")
    if mi is None or not mi.isdigit() or not 1 <= int(mi) <= 5:
        bad.append(f"conc.max-inflight[inline]={mi!r} (want 1..5)")
    # The mid-function stack snapshot: frame 0 is in PmRegSite (the hit is at its PmRegHit label).
    for bk in ("breakpoint", "hw", "inline"):
        st = docs_seen.get(bk, {}).get("stack.mid")
        if not st or not st.split(" < ")[0].lower().startswith("conformance_target!pmreg"):
            bad.append(f"stack.mid[{bk}]={st!r}")
    for bk, doc in docs_seen.items():
        print(f"    portability-documented {bk}: " + " ".join(f"{k}={v!r}" for k, v in sorted(doc.items())), flush=True)
    record("portability-documented", not bad, f"unexpected={bad[:6]}")


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
        return missing_bin("callorig-hunt", "co_driver/co_target")
    x86 = pe_is_x86(t)

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
        return missing_bin("callconv", "cc_driver/cc_target")
    x86 = pe_is_x86(t)
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
        return missing_bin("memstress", "memstress_driver/target")
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
        return missing_bin("symbols", "uhh_trace/dynwatch_target")
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
        return missing_bin("realworld-targets", "uhh_trace")
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


def run_killable(args, timeout):
    """Run a command with its output in FILES (never a pipe some grandchild may inherit and
    hold open) and a hard timeout; on timeout the whole process tree is killed. Returns
    (returncode or None on timeout, stdout, stderr)."""
    import tempfile
    with tempfile.TemporaryFile() as fo, tempfile.TemporaryFile() as fe:
        p = subprocess.Popen([str(x) for x in args], stdin=subprocess.DEVNULL, stdout=fo, stderr=fe)
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True, timeout=30)
            try:
                p.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
            rc = None
        fo.seek(0); fe.seek(0)
        return rc, fo.read().decode(errors="replace"), fe.read().decode(errors="replace")


FRIDA_COEXIST_CASES = [
    # (order, UHH backend, uhh_trace flag, expected UHH backend or None = refused, expect a prehook report)
    ("frida_first", "inline", "fallback-hw", "hw", True),
    ("frida_first", "inline", "none", None, True),
    ("frida_first", "inline", "allow-prehooked", "inline", True),
    ("uhh_first", "inline", "fallback-hw", "inline", False),
    ("frida_first", "hw", "none", "hw", False),
    ("uhh_first", "hw", "none", "hw", False),
    ("frida_first", "breakpoint", "none", "breakpoint", True),     # reported; the INT3 over the jmp still works
    ("uhh_first", "breakpoint", "none", "breakpoint", False),
]


def check_frida_coexist():
    """Frida and UHH on the same function (probe_app.exe!ReadThunk), in both orders and on
    every UHH backend: the target stays correct and BOTH tools see every call. Inline over
    a Frida hook follows UHH's documented pre-hook rules: refused by default (UHH reports
    the foreign hook and exits; the target and Frida are unaffected), moved to a debug
    register with PROBE_FALLBACK_HW (uhh_trace --fallback-hw), chained through Frida's
    detour with PROBE_ALLOW_PREHOOKED. One case at a time, each with a hard deadline;
    frida_coexist.py kills its children on any failure. (Needs an interpreter with frida;
    on the test VM a frida 16.5.9 venv.)"""
    if not exe("uhh_trace.exe") or not exe("probe_app.exe"):
        return missing_bin("frida-coexist", "uhh_trace / probe_app")
    if not FRIDA_PY.exists():
        return skip_external("frida-coexist", f"frida interpreter {FRIDA_PY}")
    script = Path(__file__).with_name("frida_coexist.py")
    for order, bk, flag, want_bk, want_pre in FRIDA_COEXIST_CASES:
        name = f"frida-coexist-{order}-{bk}" + ("" if flag in ("none", "fallback-hw") and want_bk else f"-{flag}")
        try:
            rc, out, err = run_killable([FRIDA_PY, script, "--app", exe("probe_app.exe"),
                                         "--trace", exe("uhh_trace.exe"), "--order", order,
                                         "--backend", bk, "--uhh-flag", flag, "--timeout", "90"], timeout=150)
            res = next((json.loads(l) for l in out.splitlines() if l.startswith('{"kind": "coexist"')), {})
            total = res.get("total")
            target_ok = (bool(total) and res.get("app_reads") == total and res.get("frida_hits") == total and
                         res.get("app_exit") == 0 and res.get("error") is None)
            if want_bk is None:      # refused: UHH says why, exits non-zero, nothing else changes
                uhh_ok = (res.get("uhh_exit") not in (0, None) and "pre-hooked" in str(res.get("uhh_error")) and
                          not res.get("uhh_hits"))
            else:
                uhh_ok = (res.get("uhh_hits") == total and res.get("uhh_backend") == want_bk and
                          res.get("uhh_exit") == 0)
            pre_ok = (res.get("prehook_reports", 0) > 0) == want_pre
            ok = rc == 0 and target_ok and uhh_ok and pre_ok
            record(name, ok, f"total={total} app={res.get('app_reads')} frida={res.get('frida_hits')} "
                             f"uhh={res.get('uhh_hits')}/{res.get('uhh_backend')} prehook={res.get('prehook_reports')} "
                             f"uhh_exit={res.get('uhh_exit')} exit={res.get('app_exit')}" +
                             ("" if ok else f" rc={rc} error={res.get('error')!r} uhh_error={res.get('uhh_error')!r} "
                                            f"tail={res.get('uhh_stderr_tail')} app_tail={res.get('app_tail')} "
                                            f"stderr={err[-300:]!r}"))
        except Exception as e:
            record(name, False, repr(e))


def check_sidefx(iters=1000, threads=4):
    """A probe hit leaves no trace on the target thread: GPRs, XMM, YMM upper halves,
    MXCSR, DF, x87 control word and the TEB last-error are bit-identical after the hit,
    while the callback deliberately does disturbing work (float math, formatting, logs
    with stacks, memory reads, a Win32 call that sets last-error). Every backend."""
    d, t = exe("sidefx_driver.exe"), exe("sidefx_target.exe")
    if not d or not t:
        return missing_bin("sidefx", "sidefx_driver/target")
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


TP_MODES = ("noop", "log", "mem", "sys", "callfn", "co")
TP_PROBES = ("add", "i64", "dbl", "dblarg", "seterr", "std", "align", "fact", "mid", "spawn", "thread", "peek", "ovf")


def tp_co_expected(grp, iters):
    """Mode co: the successful call_original wraps ("tp co ok" logs) a run must show, from the
    calls tp_target makes (tp_target.cpp main): each of the 8 functions once per iteration
    (tp_fact's recursive calls run INSIDE call_original: counted, no callback), tp_spawn once
    and the thread it creates runs tp_threadfn once (--spawn), tp_peek 12 times (--peek). The
    mid-function site refuses call_original (no wrap); tp_ovf's callback does not wrap."""
    per = {p: int(iters) for p in ("add", "i64", "dbl", "dblarg", "seterr", "std", "align", "fact")}
    per.update({"spawn": 1, "thread": 1 if "spawn" in grp else 0, "peek": 12, "mid": 0, "ovf": 0})
    return sum(per[p] for p in grp)


TP_GROUPS = {"breakpoint": [TP_PROBES], "inline": [TP_PROBES],
             "hw": [TP_PROBES[i:i + 3] for i in range(0, len(TP_PROBES), 3)]}


def tp_runs(d, t, bk, mode, iters):
    """Runs tp_driver for every probe group of `bk` in `mode` against target `t` (tp_target or
    its /CETCOMPAT twin); returns (problems, target rows)."""
    bad, rows = [], []
    for grp in TP_GROUPS[bk]:
        targs = [t, "--iters", iters] + [f"--{x}" for x in ("spawn", "peek", "ovf") if x in grp]
        r, o = run([d, "--backend", bk, "--mode", mode, "--probes", ",".join(grp), "--"] + targs, timeout=300)
        tg = next((x for x in o if x.get("kind") == "target"), {})
        rows.append(tg)
        rep = report(o)
        fails = sorted({str(x.get("message", "")) for x in o
                        if x.get("kind") == "probe_log" and str(x.get("message", "")).startswith("tp FAIL")})
        cold = [p.get("location") for p in probes(o) if not p.get("hits")]
        why = []
        if r.returncode != 0: why.append(f"rc={r.returncode}")
        if not tg: why.append("no target row")
        elif tg.get("bad") != 0: why.append(f"bad={tg.get('bad')} first={tg.get('first')!r}")
        for x in ("spawn", "peek", "ovf"):
            if x in grp and tg.get(x) != 1: why.append(f"{x}={tg.get(x)}")
        if fails: why.append(f"cb={fails[:4]}")
        if cold: why.append(f"no hits: {cold}")
        if mode == "co":
            wraps = sum(1 for x in o if x.get("kind") == "probe_log" and x.get("message") == "tp co ok")
            if wraps != tp_co_expected(grp, iters):
                why.append(f"call_original wraps={wraps} want {tp_co_expected(grp, iters)}")
        if rep.get("error") is not None or rep.get("app_exit") != 0 or rep.get("log_dropped") != 0:
            why.append(f"report err={rep.get('error')} exit={rep.get('app_exit')} dropped={rep.get('log_dropped')}")
        if why:
            bad.append(f"[{','.join(grp)}] " + " ".join(why) +
                       ("" if r.returncode == 0 else f" stderr={(r.stderr or '')[-200:]!r}"))
    return bad, rows


def check_transparency(iters=30):
    """A hit is invisible to the program (examples/transparency): every probed function has an
    unprobed twin, both called through one assembly harness, and a probed call must leave
    exactly what the twin leaves -- return registers (x64 RAX/XMM0; x86 EDX:EAX/ST0), callee-
    saved GPRs and XMM6-15, the SP after the call (x86 `ret N`), DF, x87 SW/TW, GetLastError,
    the TEB's LastStatusValue and every other TEB byte -- and a mid-function site (between a
    `cmp` and the flag snapshot, with a full x87 stack and a pending FCOM result) leaves every
    GPR, EFLAGS, XMM and the x87 state as its twin does. Every backend, every callback kind:
    no-op, send_log(+stack), get_mem/get_func_arg/get_reg, Win32+NT calls on the hit thread,
    call_func (APIs that set the last error; a probed function: counted, no callback),
    call_original + return_from (int, int64, double return; a double argument; __stdcall;
    stack alignment; recursion). Plus a thread created by call_func DURING a hit, which runs
    a probed function. hw: at most 3 probes per run (call_original needs a free DR)."""
    d, t = exe("tp_driver.exe"), exe("tp_target.exe")
    if not d or not t:
        return missing_bin("transparency", "tp_driver/tp_target")
    for bk in ("breakpoint", "hw", "inline"):
        for mode in TP_MODES:
            name = f"transparency-{bk}-{mode}"
            try:
                bad, _ = tp_runs(d, t, bk, mode, iters)
                record(name, not bad, "; ".join(bad) if bad else f"{len(TP_GROUPS[bk])} run(s), iters={iters}, all calls identical to the twin")
            except Exception as e:
                record(name, False, repr(e))
    # Inline, a CPU whose full XSAVE area (every XCR0 feature, e.g. AMX tiles: ~11 KB) exceeds
    # the agent's save buffer: the live AVX state and MXCSR must still be kept (the agent sizes
    # the save from the components it saves). UHH_BENCH_XSTATE=amx makes the agent see such a
    # full-area size on any CPU.
    name = "transparency-inline-xsave-bigarea"
    try:
        env = dict(os.environ, UHH_BENCH_XSTATE="amx")
        r = subprocess.run([str(a) for a in [d, "--backend", "inline", "--mode", "log", "--probes", "mid", "--", t,
                                             "--iters", iters]], capture_output=True, text=True, timeout=300, env=env)
        o = [json.loads(l) for l in r.stdout.splitlines() if l.strip().startswith("{")]
        tg = next((x for x in o if x.get("kind") == "target"), {})
        rep = report(o)
        rows = probes(o)
        logs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
        n = int(iters)                                   # TpMid runs once per iteration
        n_log = sum(1 for m in logs if m.startswith("tp log ax="))
        n_stack = logs.count("tp stack")
        fails = [m for m in logs if m.startswith("tp FAIL")]
        bad = []
        if r.returncode != 0: bad.append(f"rc={r.returncode}")
        if not tg or tg.get("bad") != 0: bad.append(f"target bad={tg.get('bad')} first={tg.get('first')!r}")
        if (len(rows) != 1 or rows[0].get("location") != "tp_target.exe!TpMidHit" or rows[0].get("backend") != "inline"
                or not rows[0].get("active") or rows[0].get("hits") != n):
            bad.append(f"probe_rows={rows} (want one active inline TpMidHit row with {n} hits)")
        if n_log != n or n_stack != n or len(logs) != 2 * n or fails:
            bad.append(f"callback logs: log={n_log} stack={n_stack} total={len(logs)} want {n}/{n}/{2 * n} fails={fails[:2]}")
        if (rep.get("error") is not None or rep.get("app_exit") != 0 or rep.get("log_dropped") != 0
                or rep.get("callbacks_interrupted") != 0 or rep.get("logs_written") != 2 * n):
            bad.append(f"report err={rep.get('error')} exit={rep.get('app_exit')} dropped={rep.get('log_dropped')} "
                       f"interrupted={rep.get('callbacks_interrupted')} written={rep.get('logs_written')}")
        record(name, not bad, " ".join(bad) if bad else
               f"hits={rows[0].get('hits')} logs={len(logs)} bad=0 first={tg.get('first')!r} rc=0")
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
        return missing_bin("edgehunt", "edge_driver/edge_target")
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
        # %s of a TARGET pointer (ROADMAP B10): inline prints the string; breakpoint/hw callbacks
        # run in the controller, which formats whatever is at that address in ITS OWN memory:
        # "[unformattable]" when unmapped there, the controller's bytes when mapped (x86 layouts
        # often overlap). Either way exactly one record, never a crash, run unaffected.
        name = f"edgehunt-{bk}-fmtptr"
        try:
            r, o, msgs, tg = go(bk, ["fmtptr"])
            bad = common(r, o, msgs, tg)
            fm = [m for m in msgs if "fmtptr" in m]
            ok = (fm == ["fmtptr hello-from-target"] if bk == "inline" else
                  len(fm) == 1 and (fm[0] == "[unformattable] fmtptr %s" or fm[0].startswith("fmtptr ")))
            if not ok: bad.append(f"got={fm}")
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
        return missing_bin("detach", "uhh_trace/probe_app")
    import time
    for bk, reads in (("inline", 1500000), ("hw", 40000), ("breakpoint", 40000)):
        name = f"detach-{bk}"
        target = None
        try:
            threads = 4
            total = threads * reads
            # inline paced (200k reads/s per thread, >= 7.5 s): an unpaced inline target on a fast
            # host finished every read before the detach completed (not mid-run).
            pace = ["--pace", "200000"] if bk == "inline" else []
            _, bo = run([a, "--no-wait", "--threads", threads, "--reads", reads, "--config", "reads_enabled=1"] + pace,
                        timeout=600)
            base = app(bo)
            target = subprocess.Popen([str(a), "--threads", str(threads), "--reads", str(reads),
                                       "--config", "reads_enabled=1"] + pace,
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while True:                                          # wait until it is at its gate
                line = target.stdout.readline().decode(errors="replace")
                if not line or '"waiting"' in line:
                    break
            # Detach as soon as the first 1000 logs arrive (was: a fixed 2.5 s after the attach,
            # which a fast host -- windows-2025's EPYC, inline -- outran: the target had finished
            # every read, so the detach was not mid-run, and met its main thread exiting; a
            # twentieth of the reads was still too late there: inline hits outrun the log pipe).
            tracer = subprocess.Popen([str(t), "--backend", bk, "--attach", str(target.pid), "--detach-on-stdin",
                                       "-p", "ntdll.dll!NtReadVirtualMemory:xxxx"],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            tout, terr = Lines(tracer.stdout), Lines(tracer.stderr)   # release the gate once the probe is LIVE
            if not terr.wait_for(lambda l: l.startswith("probe: active ntdll.dll!NtReadVirtualMemory"), 60):
                raise RuntimeError("probe never became active")
            target.stdin.write(b"\n"); target.stdin.flush()
            with tout.cv:
                tout.cv.wait_for(lambda: len(tout.lines) >= 1000, 120)
            tracer.stdin.write("\n"); tracer.stdin.flush()
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


def check_ntdll_churn(cycles=8, round_reads=1000000):
    """Hooks on ntdll's own syscall stub, installed and removed again and again while
    threads hammer it: probe_app reads in a tight loop on 4 threads through
    ntdll!NtReadVirtualMemory (which shares its page with NtProtectVirtualMemory & co.);
    uhh_trace attaches, hooks the stub, logs every call, detaches -- `cycles` times -- for
    every backend. Inline hooks are written with the target frozen and threads caught inside
    the overwritten bytes moved to the trampoline. The target reads until told to stop
    (probe_app --until-key: rounds of 4 x round_reads, the same pattern each round), so every
    cycle runs while it reads, whatever the machine's speed. Every cycle must detach cleanly
    with hits (all but the first: it may load the agent) and deliver every hit as a log
    (stdout logs == the detach line's hits == logs_written, none dropped); the target must
    exit 0 with every read done and the checksum exactly rounds x an uninstrumented round's.

    Why the target no longer runs a fixed count (it used to: 4 x 4,000,000 reads, >= 5
    cycles required; inline fitted only 2-4). Measured on the x64 VM (2026-11-06, merge-frida
    2715fab): attach (uhh_trace start + debug attach + agent) 0.4-3.0 s on every backend, the
    hook active ~0.05-0.1 s later. Then the inline cycle is dominated by its own logs: inline
    callbacks run at full speed (~2.4 M reads/s uninstrumented), every call is logged and none
    may be dropped, and the hook stays in while uhh_trace's report drains them -- 0.3-5.4 M
    log lines per cycle through the stdout pipe, cycles of 2.9-16.8 s (hw/breakpoint: ~2-3 k
    hits, 1.2-2.6 s). The uninstrumented run takes ~6.8 s, so a fixed count fits too few
    inline cycles. Inherent to logging every call, not a wait: the check now sets the run
    length instead of the machine. Log lines are counted as they stream (never held); with that,
    inline cycles took 1.0-2.9 s on x64 and 1.2-8.0 s on x86."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return missing_bin("ntdll-churn", "uhh_trace/probe_app")
    threads = 4
    for bk in ("inline", "hw", "breakpoint"):
        name = f"ntdll-churn-{bk}"
        target = None
        try:
            args = ["--threads", str(threads), "--reads", str(round_reads), "--config", "reads_enabled=1"]
            _, bo = run([a, "--no-wait", *args], timeout=600)
            base = app(bo)
            target = subprocess.Popen([str(a), "--until-key", *args],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while True:
                line = target.stdout.readline().decode(errors="replace")
                if not line or '"waiting"' in line:
                    break
            target.stdin.write(b"\n"); target.stdin.flush()
            done, bad, secs = [], [], []
            for c in range(1, cycles + 1):
                if target.poll() is not None:
                    bad.append(f"target ended before cycle {c}")
                    break
                t0 = time.time()
                tr = subprocess.Popen([str(t), "--backend", bk, "--attach", str(target.pid), "--detach-after-ms", "300",
                                       "-p", "ntdll.dll!NtReadVirtualMemory:xxxx"],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                terr = Lines(tr.stderr)
                logs, objs = 0, []
                for l in tr.stdout:                          # millions of log lines: count, never keep
                    if l.startswith('{"kind":"probe_log"'):
                        logs += 1
                    elif l.startswith("{"):
                        objs.append(json.loads(l))
                tr.wait(timeout=120); terr.t.join(timeout=30)
                secs.append(time.time() - t0)
                pr = next((o for o in objs if o.get("kind") == "probe"), {})
                det = any(o.get("kind") == "detached" for o in objs)
                fin = next((re.search(r"probe: detached: hits=(\d+) logs_written=(\d+) log_dropped=(\d+)", l)
                            for l in terr.lines if "probe: detached: hits=" in l), None)
                hits, written, dropped = (int(x) for x in fin.groups()) if fin else (None, None, None)
                done.append(hits)
                if (not det or tr.returncode != 0 or pr.get("backend") != bk or (not hits and c > 1) or
                        not (logs == hits == written) or dropped != 0):
                    bad.append(f"cycle{c}: rc={tr.returncode} detached={det} backend={pr.get('backend')} hits={hits} "
                               f"logs={logs} written={written} dropped={dropped} "
                               f"err={' | '.join(terr.lines[-3:])[:400]}")
            if target.poll() is None:
                target.stdin.write(b"\n"); target.stdin.flush()   # stop reading
            rest = lines_until(target, '"kind":"app"', 600)
            target.wait(timeout=120)
            terr = target.stderr.read().decode(errors="replace") if target.returncode != 0 else ""
            unhandled = [l for l in terr.splitlines() if '"unhandled"' in l][:2]
            res = next((json.loads(l) for l in rest if l.strip().startswith("{") and '"kind":"app"' in l), {})
            rounds = res.get("rounds") or 0
            total = threads * round_reads
            ok = (len(done) == cycles and not bad and target.returncode == 0 and rounds >= 1 and
                  res.get("successful_reads") == rounds * total and base.get("checksum") is not None and
                  res.get("checksum") == rounds * base.get("checksum"))
            record(name, ok, f"cycles={len(done)} hits/cycle={done} secs/cycle={[round(x, 1) for x in secs]} "
                             f"exit={target.returncode} rounds={rounds} reads={res.get('successful_reads')}/{rounds * total} "
                             f"checksum_exact={res.get('checksum') == rounds * (base.get('checksum') or 0)}"
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
        return missing_bin("patch-race", "uhh_trace/patchrace_target")
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
        return missing_bin("emulated-sites", "uhh_trace/patchrace_target")
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
        return missing_bin("oldcrt", "uhh_trace/oldcrt_target")
    old = find_old_msvcp()
    if not old:
        return skip_external("oldcrt", "a pre-14.40 msvcp140.dll", "none on this machine; set UHH_OLD_MSVCP")
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
        return missing_bin("interrupt", "uhh_attach/probe_app")
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
        return missing_bin("gated-filter", "gated_config.exe")
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
        return missing_bin("gated-map", "gated_config.exe")
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


# --- newapp-*: the three new-app examples (examples/filetrace, flagflip, regtrace), each
# compared with the ground truth its fixture prints about itself. ------------------------
def newapp_health(r, objs):
    """Problems common to every newapp run: exit code, dropped logs, library warnings."""
    rep, bad = report(objs), []
    if r.returncode != 0:
        bad.append(f"rc={r.returncode}")
    if rep.get("log_dropped") != 0 or rep.get("callbacks_interrupted", 0) != 0:
        bad.append(f"dropped={rep.get('log_dropped')} interrupted={rep.get('callbacks_interrupted')}")
    warnings = [ln for ln in (r.stderr or "").splitlines() if "warning" in ln.lower()]
    warnings += [m for m in newapp_msgs(objs) if m.startswith("uhh warning")]
    if warnings:
        bad.append(f"warnings={warnings[:2]}")
    return bad


def newapp_msgs(objs):
    return [str(o.get("message", "")) for o in objs if o.get("kind") == "probe_log"]


def newapp_label(backends):
    return backends[0] if len(set(backends)) == 1 else "+".join(backends)


def check_newapp_files(threads=4, files=4, chunks=6):
    """filetrace (NtCreateFile call_original + return_from, NtWriteFile, NtClose) against
    filetrace_target: every successful open is logged with exactly the handle the program got,
    every failing open with exactly the NTSTATUS the program saw (and the program's own error
    checks pass), every write is attributed to its path with the right count and bytes --
    plain and overlapped -- and every file reads back intact. All-same and mixed backends."""
    from collections import Counter
    if not exe("filetrace.exe") or not exe("filetrace_target.exe"):
        return missing_bin("newapp-file", "filetrace.exe / filetrace_target.exe")
    rx_create = re.compile(r"create path=(.*) access=0x([0-9a-f]+) status=0x([0-9a-f]+) handle=0x([0-9a-f]+)$")
    rx_write = re.compile(r"write path=(.*) handle=0x([0-9a-f]+) len=(\d+) offset=(-?\d+)$")

    def norm(path):
        path = path[4:] if path.startswith("\\??\\") else path
        return path.lower()

    cells = [("breakpoint",) * 3, ("hw",) * 3, ("inline",) * 3, ("breakpoint", "inline", "hw"),
             ("inline", "hw", "breakpoint"), ("hw", "breakpoint", "inline")]
    for create, write, close in cells:
        name = "newapp-file-" + newapp_label((create, write, close))
        d = Path(tempfile.mkdtemp(prefix="uhhft-"))
        try:
            r, o = run([exe("filetrace.exe"), "--create-backend", create, "--write-backend", write,
                        "--close-backend", close, "--filter", d.name, "--", exe("filetrace_target.exe"),
                        "--dir", d, "--threads", threads, "--files", files, "--chunks", chunks], timeout=600)
            done = next((x for x in o if x.get("kind") == "ft_done"), {})
            truth_open = Counter((norm(x["path"]), x["handle"]) for x in o if x.get("kind") == "ft_open")
            truth_fail = Counter((norm(x["path"]), int(x["status"], 16)) for x in o if x.get("kind") == "ft_fail")
            truth_files = {norm(x["path"]): (x["writes"], x["bytes"]) for x in o if x.get("kind") == "ft_file"}
            msgs = newapp_msgs(o)
            creates = [m.groups() for m in map(rx_create.match, msgs) if m]
            seen_open = Counter((norm(p), int(h, 16)) for p, _, st, h in creates if int(st, 16) < 0x80000000)
            seen_fail = Counter((norm(p), int(st, 16)) for p, _, st, h in creates if int(st, 16) >= 0x80000000)
            seen_files = {}
            for p, _, ln, _ in (m.groups() for m in map(rx_write.match, msgs) if m):
                n, b = seen_files.get(norm(p), (0, 0))
                seen_files[norm(p)] = (n + 1, b + int(ln))
            bad = newapp_health(r, o)
            if done.get("bad") != 0 or done.get("fail_mismatch") != 0:
                bad.append(f"target={done}")
            if seen_open != truth_open:
                bad.append(f"opens missing={list((truth_open - seen_open).items())[:2]} "
                           f"extra={list((seen_open - truth_open).items())[:2]}")
            if seen_fail != truth_fail:
                bad.append(f"fails missing={list((truth_fail - seen_fail).items())[:2]} "
                           f"extra={list((seen_fail - truth_fail).items())[:2]}")
            bad += [f"handle on failure {p}" for p, _, st, h in creates if int(st, 16) >= 0x80000000 and int(h, 16)]
            if seen_files != truth_files:
                diff = [(p, truth_files.get(p), seen_files.get(p)) for p in set(truth_files) | set(seen_files)
                        if truth_files.get(p) != seen_files.get(p)]
                bad.append(f"writes (path, truth, seen)={diff[:2]}")
            bad += [m for m in msgs if "unmapped" in m][:2]
            ok = (not bad and len(truth_files) == threads * files and sum(truth_fail.values()) == threads * 4)
            record(name, ok, f"opens={sum(seen_open.values())}/{sum(truth_open.values())} "
                             f"fails={sum(seen_fail.values())}/{sum(truth_fail.values())} "
                             f"files={len(seen_files)}/{len(truth_files)} "
                             f"writes={sum(n for n, _ in seen_files.values())}" + ("" if ok else f" bad={bad[:4]}"))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            shutil.rmtree(d, ignore_errors=True)


def check_newapp_flag(threads=4, calls=200):
    """flagflip on flagfeature.dll!Feature::IsEnabled (a virtual `bool IsEnabled() const`
    found in the PDB, late-loaded; x86 __thiscall: `this` in ECX): "beta" is forced on, "alpha"
    is left alone. force = return_from(1) without the original; modify = call_original, then
    return_from(1). The target's own counters must show beta's gated path ran on EVERY call and
    alpha's never; the logs must name the right object (`this` == the target's pointer)."""
    if not exe("flagflip.exe") or not exe("flagflip_target.exe") or not exe("flagfeature.dll"):
        return missing_bin("newapp-flag", "flagflip.exe / flagflip_target.exe / flagfeature.dll")
    rx = re.compile(r"IsEnabled this=0x([0-9a-f]+) name=(\S+) original=(\S+) returned=(\d+)$")
    location = "flagfeature.dll!Feature::IsEnabled"
    total = threads * calls
    for bk in ("breakpoint", "hw", "inline"):
        for mode in ("force", "modify"):
            name = f"newapp-flag-{bk}-{mode}"
            try:
                r, o = run([exe("flagflip.exe"), "--backend", bk, "--mode", mode, "--feature", "beta", location,
                            "--", exe("flagflip_target.exe"), "--threads", threads, "--calls", calls], timeout=300)
                feat = {x["name"]: x for x in o if x.get("kind") == "ff_feature"}
                alpha, beta = feat.get("alpha", {}), feat.get("beta", {})
                logs = [m.groups() for m in map(rx.match, newapp_msgs(o)) if m]
                hits = next((x.get("hits") for x in probes(o) if x.get("location") == location), None)
                bad = newapp_health(r, o)
                if (beta.get("calls"), beta.get("enabled"), beta.get("gated_ran")) != (total, total, total):
                    bad.append(f"beta={beta}")
                if (alpha.get("calls"), alpha.get("enabled"), alpha.get("gated_ran")) != (total, 0, 0):
                    bad.append(f"alpha={alpha}")
                if hits != 2 * total:
                    bad.append(f"hits={hits}")
                this = {n: int(str(f.get("this", "0x0")), 16) for n, f in feat.items()}
                want = {("beta", "skipped" if mode == "force" else "0", "1"): total}
                if mode == "modify":
                    want[("alpha", "0", "0")] = total
                got = {}
                for ptr, who, orig, ret in logs:
                    if int(ptr, 16) != this.get(who):
                        bad.append(f"this=0x{ptr} for {who} (target says {hex(this.get(who) or 0)})")
                    got[(who, orig, ret)] = got.get((who, orig, ret), 0) + 1
                if got != want:
                    bad.append(f"logs={got} want={want}")
                ok = not bad
                record(name, ok, f"beta enabled={beta.get('enabled')}/{total} gated_ran={beta.get('gated_ran')} "
                                 f"alpha enabled={alpha.get('enabled')} hits={hits} logs={len(logs)}" +
                                 ("" if ok else f" bad={bad[:4]}"))
            except Exception as e:
                record(name, False, repr(e))


def check_newapp_reg(threads=4, iters=20):
    """regtrace (NtOpenKey/NtOpenKeyEx/NtCreateKey via call_original + return_from,
    NtQueryValueKey, NtSetValueKey, NtClose) against regtrace_target under HKCU\\Software\\
    UHHTest: every key handle the program got is logged with its FULL name (the HKCU root
    resolved too), every set/query is attributed to the right key and value name with the
    program's own counts, a missing value / key fails for the program exactly as without the
    tool, and the tree is gone afterwards. hw cannot take all six probes (4 debug registers,
    and call_original on hw needs one free), so hw runs the open group or the value group."""
    from collections import Counter
    if not exe("regtrace.exe") or not exe("regtrace_target.exe"):
        return missing_bin("newapp-reg", "regtrace.exe / regtrace_target.exe")
    rx_open = re.compile(r"(open|create) key=(.*) status=0x([0-9a-f]+) handle=0x([0-9a-f]+)$")
    rx_val = re.compile(r"(query|set) key=(.*) handle=0x([0-9a-f]+) value=(\S*) (class|type)=(\d+)$")

    def rel(key):   # "\REGISTRY\USER\S-1-..\Software\UHHTest\t0" -> "software\uhhtest\t0"
        i = key.lower().find("software\\uhhtest")
        return key[i:].lower() if i >= 0 else None

    cells = [("breakpoint",) * 3, ("inline",) * 3, ("hw", "breakpoint", "breakpoint"), ("inline", "hw", "hw"),
             ("breakpoint", "inline", "hw"), ("hw", "inline", "inline")]
    for op_bk, val_bk, close_bk in cells:
        name = "newapp-reg-" + newapp_label((op_bk, val_bk, close_bk))
        try:
            r, o = run([exe("regtrace.exe"), "--open-backend", op_bk, "--value-backend", val_bk,
                        "--close-backend", close_bk, "--filter", "UHHTest", "--", exe("regtrace_target.exe"),
                        "--threads", threads, "--iters", iters], timeout=600)
            done = next((x for x in o if x.get("kind") == "rt_done"), {})
            truth_keys = Counter((x["key"].lower(), x["handle"]) for x in o if x.get("kind") == "rt_key")
            truth_vals = {(x["key"].lower(), x["value"]): (x["sets"], x["queries"]) for x in o if x.get("kind") == "rt_value"}
            msgs = newapp_msgs(o)
            opens = [m.groups() for m in map(rx_open.match, msgs) if m]
            vals = [m.groups() for m in map(rx_val.match, msgs) if m]
            bad = newapp_health(r, o)
            if done.get("bad") != 0 or done.get("cleaned") != 1:
                bad.append(f"target={done}")
            # Every name must be complete: rooted at \REGISTRY\ (a relative open resolved
            # through its root handle), never "?".
            bad += [f"partial name {k}" for _, k, st, _ in opens if rel(k) and not k.upper().startswith("\\REGISTRY\\")][:2]
            # Exact multiset over the keys the program reports opening (its per-thread keys):
            # every open logged once with the handle the program got -- no missing, no duplicate,
            # no extra. (The root key's intermediate creates are not in the truth: filtered by name.)
            truth_names = {k for k, _ in truth_keys}
            seen_keys = Counter((rel(k), int(h, 16)) for _, k, st, h in opens
                                if rel(k) in truth_names and int(st, 16) == 0)
            if truth_keys - seen_keys:
                bad.append(f"keys missing={list((truth_keys - seen_keys).items())[:2]}")
            if seen_keys - truth_keys:
                bad.append(f"keys extra/duplicate={list((seen_keys - truth_keys).items())[:2]}")
            if sum(truth_keys.values()) != 2 * threads:      # create + read-only reopen per thread
                bad.append(f"truth keys={sum(truth_keys.values())} want {2 * threads}")
            missing_opens = [k for _, k, st, _ in opens if rel(k) and rel(k).endswith("\\missing") and int(st, 16) == 0xC0000034]
            if len(missing_opens) != threads:
                bad.append(f"missing-key opens={len(missing_opens)}")
            seen_vals = {}
            for op, k, _, v, _, _ in vals:
                if k == "?":
                    # Keys opened before an inline open probe was live (loader-time queries,
                    # e.g. IFEO) are unknown to the map; the fixture's own never may be.
                    if v in ("count", "name", "blob", "missing"):
                        bad.append(f"unmapped {op} value={v}")
                    continue
                key = (rel(k), v)
                if key[0] is None:
                    continue
                sets, queries = seen_vals.get(key, (0, 0))
                seen_vals[key] = (sets + (op == "set"), queries + (op == "query"))
            if seen_vals != truth_vals:
                diff = [(k, truth_vals.get(k), seen_vals.get(k)) for k in set(truth_vals) | set(seen_vals)
                        if truth_vals.get(k) != seen_vals.get(k)]
                bad.append(f"values (key, truth, seen)={diff[:3]}")
            bad += [m for m in msgs if "unmapped" in m][:2]
            ok = not bad and len(truth_vals) == threads * 4
            record(name, ok, f"keys={sum(truth_keys.values()) - sum((truth_keys - seen_keys).values())}/"
                             f"{sum(truth_keys.values())} sets={sum(s for s, _ in seen_vals.values())} "
                             f"queries={sum(q for _, q in seen_vals.values())}" + ("" if ok else f" bad={bad[:4]}"))
        except Exception as e:
            record(name, False, repr(e))
    # More hw probes than debug registers is refused up front, with the reason.
    try:
        r, _ = run([exe("regtrace.exe"), "--backend", "hw", "--", exe("regtrace_target.exe")], timeout=60)
        record("newapp-reg-hw-overcommit", r.returncode == 2 and "debug registers" in (r.stderr or ""),
               f"rc={r.returncode} stderr={(r.stderr or '').strip()[:120]!r}")
    except Exception as e:
        record("newapp-reg-hw-overcommit", False, repr(e))


def check_agent_crt():
    """probe_api_agent.dll is injected into the target, so it must not import the dynamic
    MSVC runtime: it would bind to whatever msvcp140/vcruntime140 the target already loaded,
    and an older app-local msvcp140 crashes SafetyHook's std::mutex (_Mtx_* null read)."""
    path = BIN / "probe_api_agent.dll"
    if not path.exists():
        return missing_bin("agent-crt", "probe_api_agent.dll")
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
        return missing_bin("cet", "cet_probe/probe_app_cet/gated_config/uhh_trace")
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
    # call_func and call_original under the shadow stack, every backend: the transparency
    # fixture on its /CETCOMPAT twin (call_func of Win32 APIs, of a probed function, of a callee
    # faulting at its first instruction / inside a system function; call_original+return_from).
    # breakpoint/hw call_func enters the callee through a real CALL (a stub in the target), so
    # its ret matches the shadow stack; an abandoned callee's shadow frames are dropped (SSP
    # restored through CONTEXT_XSTATE CET_U).
    tpd, tpc = exe("tp_driver.exe"), exe("tp_target_cet.exe")
    for bk in ("breakpoint", "hw", "inline"):
        for mode in ("callfn", "co"):
            name = f"cet-tp-{bk}-{mode}"
            if not tpd or not tpc:
                missing_bin(name, "tp_driver/tp_target_cet")
                continue
            try:
                bad, rows = tp_runs(tpd, tpc, bk, mode, 10)
                ssp = sorted({str(x.get("shadow_stack")) for x in rows})
                if enforced is not None and ssp != [str(bool(enforced))]:
                    bad.append(f"target shadow_stack={ssp} but cet_probe enforced={enforced}")
                record(name, not bad, f"cet_enforced={enforced} target_ssp={ssp} " +
                       ("; ".join(bad) if bad else f"{len(TP_GROUPS[bk])} run(s), all calls identical to the twin"))
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


# Exploit-protection policies per image name (Image File Execution Options MitigationOptions,
# 24 bytes, as Set-ProcessMitigation writes them): user shadow stacks byte 15 (0x10 on, 0x30
# strict mode); byte 16 continues the CET policy2 nibbles: SetContext IP validation 0x01
# (0x03 relaxed), BlockNonCetBinaries 0x10 (0x30 non-EHCONT). Measured on windows-2025: these
# bytes make cet_probe report EnableUserShadowStackStrictMode / BlockNonCetBinaries /
# SetContextIpValidationRelaxedMode = 1 (Set-ProcessMitigation has no BlockNonCetBinaries).
CET_POLICIES = {"strict": (0x30, 0x00), "block": (0x10, 0x10)}


def cet_policy_copy(name, policy):
    """BIN/<name>.exe copied to BIN/<name>_<policy>.exe with that IFEO policy set (admin);
    returns the copy's path, or raises. cet_policy_clear removes the IFEO keys again."""
    import winreg
    src = BIN / f"{name}.exe"
    dst = BIN / f"{name}_{policy}.exe"
    shutil.copyfile(src, dst)
    b = bytearray(24); b[15], b[16] = CET_POLICIES[policy]
    k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{dst.name}",
                           0, winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY)
    winreg.SetValueEx(k, "MitigationOptions", 0, winreg.REG_BINARY, bytes(b))
    winreg.CloseKey(k)
    return dst


def cet_policy_clear(paths):
    import winreg
    for p in paths:
        try:
            winreg.DeleteKeyEx(winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{Path(p).name}",
                               winreg.KEY_WOW64_64KEY, 0)
        except OSError:
            pass


def check_cet_policy(threads=4, reads=200):
    """CET under the strictest process policies (Exploit protection, per image; set through
    IFEO on renamed copies, removed afterwards). STRICT MODE (cet-strict-*): every shadow-stack
    mismatch is fatal, also in non-image code the kernel would fix up in compatibility mode --
    the transparency fixture (call_func, call_original + return_from) and gated_config on every
    backend. BlockNonCetBinaries (cet-block-*): only /CETCOMPAT images may load; breakpoint/hw
    need nothing in the target; inline needs the agent (and the callback module) loaded.
    The detail says whether the machine enforced the policy (cet_probe of the same policy);
    on a machine without CET the rows prove only that the policy copies run."""
    pr_exe, tpd, gc = exe("cet_probe.exe"), exe("tp_driver.exe"), exe("gated_config.exe")
    if not pr_exe or not tpd or not gc or not exe("tp_target_cet.exe") or not exe("probe_app_cet.exe"):
        return missing_bin("cet-policy", "cet_probe/tp_driver/tp_target_cet/probe_app_cet/gated_config")
    made = []
    try:
        for policy in CET_POLICIES:
            if policy == "block" and pe_is_x86(BIN / "cet_probe.exe"):
                # WoW64 refuses to create a process with this policy (0xC0000022, measured on
                # windows-2025); moot: Windows enforces no shadow stack for WoW64 processes.
                skip("cet-block", "x86: Windows does not start a WoW64 process under BlockNonCetBinaries (no CET on WoW64)")
                continue
            try:
                copies = {n: cet_policy_copy(n, policy) for n in ("cet_probe", "tp_target_cet", "probe_app_cet")}
                made += copies.values()
            except Exception as e:
                record(f"cet-{policy}-setup", False, f"cannot set the IFEO policy (admin needed): {e!r}")
                continue
            r, o = run([copies["cet_probe"]], timeout=60)
            info = next((x for x in o if x.get("kind") == "cet_probe"), {})
            pol = info.get("policy", {})
            key = {"strict": "EnableUserShadowStackStrictMode", "block": "BlockNonCetBinaries"}[policy]
            # BlockNonCetBinaries is enforced by the loader whether or not the CPU has CET (seen on the
            # VM, Windows 10 on a Skylake); strict mode only matters with an active shadow stack.
            on = pol.get(key) == 1 and (policy == "block" or bool(info.get("enforced")))
            record(f"cet-{policy}-probe", r.returncode == 0 and (pol.get(key) == 1 or not info.get("enforced")),
                   f"enforced={info.get('enforced')} {key}={pol.get(key)} (policy {'IN EFFECT' if on else 'not in effect'})")
            for bk in ("breakpoint", "hw", "inline"):
                for mode in (("callfn", "co") if policy == "strict" else ("log",)):
                    name = f"cet-{policy}-tp-{bk}-{mode}"
                    try:
                        bad, rows = tp_runs(tpd, copies["tp_target_cet"], bk, mode, 5)
                        if policy == "block" and bk == "inline" and on:
                            # The agent / callback module must be /CETCOMPAT to load; until then
                            # the refusal must be clean (the error names the agent load).
                            r2, o2 = run([tpd, "--backend", bk, "--mode", mode, "--probes", "add", "--",
                                          copies["tp_target_cet"], "--iters", 2], timeout=120)
                            err = (report(o2).get("error") or "")
                            # until the agent AND the callback module are /CETCOMPAT
                            if bad and "LoadLibrary" in err:
                                record(name, True, f"policy IN EFFECT: inline refused cleanly: {err[:100]}")
                                continue
                        record(name, not bad, f"policy {'IN EFFECT' if on else 'not in effect'} " +
                               ("; ".join(bad) if bad else f"{len(TP_GROUPS[bk])} run(s), all calls identical to the twin"))
                    except Exception as e:
                        record(name, False, repr(e))
                if policy == "strict":
                    name = f"cet-{policy}-gated-{bk}"
                    try:
                        total = threads * reads
                        r, o = run([gc, "--flag-backend", bk, "--read-backend", bk, "--open-backend", bk, FLAG_LOCATION,
                                    READ_LOCATION, "--", copies["probe_app_cet"], "--no-wait", "--helpers", HELPERS,
                                    "--threads", threads, "--reads", reads], timeout=300)
                        rep, rd, a = report(o), read_probe(o), app(o)
                        logs, dropped = read_logs(o)
                        ok = (r.returncode == 0 and rep.get("overrides") == 1 and rd.get("hits") == total and logs == total
                              and dropped == 0 and unmapped(o) == 0 and rep.get("error") is None
                              and a.get("successful_reads") == total)
                        record(name, ok, f"policy {'IN EFFECT' if on else 'not in effect'} target_ssp={a.get('shadow_stack')} "
                                         f"hits={rd.get('hits')}/{total} logs={logs} dropped={dropped} rc={r.returncode} "
                                         f"exit={rep.get('app_exit')} err={(rep.get('error') or '')[:100]}")
                    except Exception as e:
                        record(name, False, repr(e))
    finally:
        cet_policy_clear(made)


def check_ret_probe(threads=2, reads=50):
    """A probe on a function's own `ret` -- the natural way to see a return (no special
    flag): ntdll!NtOpenProcess's ret, found by decoding the stub in the DLL file. probe_app
    opens each helper once. breakpoint and hw must fire once per open. inline must be REFUSED cleanly (the 5-byte jump would run past the ret
    into code only a jump reaches -- the int 2e tail on x64, the next stub on x86) or,
    with --fallback-hw, move to hw. The target must be unaffected either way."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return missing_bin("ret-probe", "uhh_trace/probe_app")
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
        return missing_bin("handle-map", "gated_config.exe")
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
        return missing_bin("shared-mix", "gated_config.exe")
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
        return missing_bin("forwarded-probe", "uhh_trace/probe_app")
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
        return missing_bin("gated-mem", "gated_config_mem.exe")
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
        return missing_bin("crash-logs", "hitcost driver/target")
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
        return missing_bin("attach-new", "uhh_trace/probe_app")
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
        return missing_bin("refusals", "refusal_driver/hitcost_target")
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
        return missing_bin("hotpatch", "uhh_trace")
    import struct
    data = Path(t).read_bytes()
    machine = struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0]
    if machine != 0x14C:
        return skip("hotpatch-prologue", "x86-only (32-bit system DLLs carry the hot-patch prologue)")
    kb = Path(r"C:\Windows\SysWOW64\KernelBase.dll")
    curl = Path(r"C:\Windows\SysWOW64\curl.exe")
    if not kb.exists() or not curl.exists():
        return skip_external("hotpatch-prologue", "system SysWOW64 KernelBase.dll/curl.exe")
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
        return missing_bin("prehook-attach", "uhh_trace/probe_app")
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
        return missing_bin("realworld", "uhh_trace.exe")
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
            skip_external(f"realworld-{name}", f"system program {argv[0]}"); continue
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
    """Split a driver's stdout into JSON records (UHH's and the target's own) and the
    TARGET's text. UHH forwards a launched target's output line-wise, so every record is a
    whole line of its own -- a record spliced into one of the target's lines (reg.exe and
    unbuffered UCRT stdout write partial lines; ROADMAP D2) stays text and fails the check."""
    objs, text = [], []
    for line in stdout.splitlines():
        if line.startswith('{"kind":'):
            try:
                objs.append(json.loads(line))
                continue
            except json.JSONDecodeError:
                pass
        text.append(line + "\n")
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
        return missing_bin("detours-simple", "detours_simple/detours_target")
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
        return missing_bin("detours-traceapi", "detours_traceapi/detours_target")
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
        return missing_bin("detours-withdll", "detours_traceapi/detours_target")
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
        return missing_bin("detours-retval", "detours_retval/detours_target")
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
        return missing_bin("detours-launch-stdin", "detours_traceapi")
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
        return missing_bin("famous-heap", "famous_driver/famous_heap_target")
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
        return missing_bin("famous-files", "famous_driver/famous_file_target")
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
        return missing_bin("famous-tls", "famous_driver")
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
        return missing_bin("famous-loader", "famous_driver/famous_loader_target")
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
        return missing_bin("famous-retval", "famous_driver/famous_tick_target")
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
        return missing_bin("hunt", "hunt_driver / hunt_target / hunt_dll")
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


# ---- forwarded target stdout/stderr (ROADMAP D2/F8) ----------------------------------------
# A launched target writes into its own pipe and UHH forwards its bytes line-wise, so the live
# log records never land inside one of its lines -- whatever the target writes: one byte per
# WriteFile, unbuffered UCRT, 4 KiB CRT chunks, binary bytes, a prompt without a newline.

STDOUT_PROBES = ("KernelBase.dll!WriteFile:xxd", "KernelBase.dll!GetFileAttributesA:s")


def stdout_capture(args, answer=None, prompt=None, merge=False, timeout=300):
    """Run with binary pipes, pumped by threads. With `prompt`, `answer` goes to stdin only
    once stdout holds the prompt -- a target waiting for that answer hangs unless the prompt
    reached the reader without its newline. Returns (rc, out, err, prompt_seen, seconds)
    where seconds is how long the process itself ran (not until its pipes closed)."""
    p = subprocess.Popen([str(a) for a in args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT if merge else subprocess.PIPE)
    bufs = {"out": bytearray(), "err": bytearray()}

    def pump(stream, key):
        while True:
            b = stream.read1(65536)
            if not b:
                break
            bufs[key] += b

    pumps = [threading.Thread(target=pump, args=(p.stdout, "out"), daemon=True)]
    if not merge:
        pumps.append(threading.Thread(target=pump, args=(p.stderr, "err"), daemon=True))
    for t in pumps:
        t.start()
    t0 = time.time()
    seen = None
    if prompt is not None:
        seen = False
        while time.time() - t0 < 120 and p.poll() is None:
            if prompt in bufs["out"]:
                seen = True
                break
            time.sleep(0.01)
    try:
        if answer is not None:
            p.stdin.write(answer)
        p.stdin.close()
    except OSError:
        pass
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        subprocess.run(["taskkill", "/f", "/t", "/pid", str(p.pid)], capture_output=True)
        p.wait()
    secs = time.time() - t0
    for t in pumps:
        t.join(timeout=30)
    return p.returncode, bytes(bufs["out"]), bytes(bufs["err"]), seen, secs


def stdout_lines(data):
    parts = data.split(b"\n")
    return [x + b"\n" for x in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def stdout_split(data):
    """(records, target bytes, strays): every whole line that is a UHH record is taken out;
    what is left must be the target's exact bytes. strays: records found anywhere else."""
    recs, keep = [], []
    for line in stdout_lines(data):
        if line.startswith(b'{"kind":"probe') and line.endswith(b"\n"):
            try:
                recs.append(json.loads(line))
                continue
            except ValueError:
                pass
        keep.append(line)
    rest = b"".join(keep)
    return recs, rest, rest.count(b'{"kind":"probe')


def stdout_strip_diag(data):
    """The controller's own stderr lines (probe: ...) out of a stderr stream."""
    return b"".join(l for l in stdout_lines(data) if not l.startswith(b"probe: "))


def stdout_first_diff(a, b):
    i = next((k for k in range(min(len(a), len(b))) if a[k] != b[k]), min(len(a), len(b)))
    return f"len {len(a)} vs {len(b)}, first diff @{i}: {a[max(0, i - 30):i + 30]!r} vs {b[max(0, i - 30):i + 30]!r}"


def check_stdout_forward():
    """stdout-*: a launched target's stdout/stderr bytes reach the consumer exactly (compared
    with an uninstrumented run) while probes on its every WriteFile and on a busy worker
    thread log at a high rate; every record is intact on its own line; a prompt without a
    newline shows promptly; stdout+stderr as one stream (2>&1) keep their order; a grandchild
    holding the pipe does not keep the controller waiting."""
    tr, t = exe("uhh_trace.exe"), exe("stdout_target.exe")
    if not tr or not t:
        return missing_bin("stdout", "uhh_trace/stdout_target")
    probes_args = [a for p in STDOUT_PROBES for a in ("-p", p)]
    try:
        brc, bout, berr, bseen, _ = stdout_capture([t, "run", "--prompt"], answer=b"go\n", prompt=b"prompt> ")
        ok = brc == 0 and bseen and bout.endswith(b"END stdout_target\n") and b"answer=go," in bout
        record("stdout-baseline", ok, f"rc={brc} prompt_seen={bseen} stdout={len(bout)}B stderr={len(berr)}B")
        mrc, mout, _, _, _ = stdout_capture([t, "mixed"], merge=True)
        record("stdout-mixed-baseline", mrc == 0 and mout.endswith(b"END mixed\n"), f"rc={mrc} bytes={len(mout)}")
    except Exception as e:
        return record("stdout-baseline", False, repr(e))
    for bk in ("breakpoint", "hw", "inline"):
        name = f"stdout-{bk}"
        print(f"  .. {name}", file=sys.stderr, flush=True)
        try:
            rc, out, err, seen, secs = stdout_capture([tr, "--backend", bk, *probes_args, "--", t, "run", "--prompt"],
                                                      answer=b"go\n", prompt=b"prompt> ")
            recs, text, strays = stdout_split(out)
            logs = [r for r in recs if r.get("kind") == "probe_log"]
            rep = next((r for r in recs if r.get("kind") == "probe_report"), {})
            writes = sum(str(r.get("message", "")).startswith("WriteFile(") for r in logs)
            errtext = stdout_strip_diag(err)
            ok = (rc == 0 and rep.get("error") is None and rep.get("app_exit") == 0 and rep.get("log_dropped") == 0 and
                  len(logs) == rep.get("logs_written") and strays == 0 and seen and text == bout and errtext == berr and
                  writes >= 2000)
            record(name, ok, f"logs={len(logs)}/{rep.get('logs_written')} writefile_logs={writes} strays={strays} "
                             f"prompt_seen={seen} stdout_same={text == bout} stderr_same={errtext == berr} rc={rc} "
                             f"exit={rep.get('app_exit')} dropped={rep.get('log_dropped')} {secs:.1f}s err={rep.get('error')}" +
                             ("" if text == bout else " stdout: " + stdout_first_diff(text, bout)) +
                             ("" if errtext == berr else " stderr: " + stdout_first_diff(errtext, berr)))
        except Exception as e:
            record(name, False, repr(e))
        name = f"stdout-mixed-{bk}"
        try:
            rc, out, _, _, secs = stdout_capture([tr, "--backend", bk, "-p", STDOUT_PROBES[0], "--", t, "mixed"], merge=True)
            recs, text, strays = stdout_split(out)
            text = stdout_strip_diag(text)
            logs = [r for r in recs if r.get("kind") == "probe_log"]
            rep = next((r for r in recs if r.get("kind") == "probe_report"), {})
            ok = (rc == 0 and rep.get("error") is None and rep.get("log_dropped") == 0 and
                  len(logs) == rep.get("logs_written") and len(logs) > 500 and strays == 0 and text == mout)
            record(name, ok, f"logs={len(logs)}/{rep.get('logs_written')} strays={strays} same_order={text == mout} rc={rc} "
                             f"{secs:.1f}s" + ("" if text == mout else " " + stdout_first_diff(text, mout)))
        except Exception as e:
            record(name, False, repr(e))
    name = "stdout-grandchild"
    m = None
    try:
        rc, out, err, _, secs = stdout_capture([tr, "--backend", "breakpoint", "-p", STDOUT_PROBES[0], "--", t, "orphan"],
                                               timeout=120)
        m = re.search(rb"grandchild (\d+)\n", out)
        recs, _, strays = stdout_split(out)
        rep = next((r for r in recs if r.get("kind") == "probe_report"), {})
        ok = rc == 0 and bool(m) and secs < 8 and rep.get("app_exit") == 0 and strays == 0
        record(name, ok, f"controller_exit_after={secs:.1f}s (grandchild holds the pipe 10 s) rc={rc} "
                         f"grandchild={bool(m)} exit={rep.get('app_exit')}")
    except Exception as e:
        record(name, False, repr(e))
    finally:
        # never leave the grandchild behind: it holds inherited pipes (the harness's too)
        if m:
            subprocess.run(["taskkill", "/f", "/pid", m.group(1).decode()], capture_output=True)


def check_blog_replicas():
    """Blog replicas: crypto-API monitor, registry Run-key monitor, DNS/socket logger,
    process-creation tracker, COM CLSID logger, game-loop frame probe -- each against an
    uninstrumented baseline of the same target, under breakpoint, hw and inline.
    UHH_BLOG_SCENARIOS=crypto,net limits the scenarios (default: all)."""
    d, t = exe("blog_driver.exe"), exe("blog_target.exe")
    if not d or not t:
        return missing_bin("blog", "blog_driver/blog_target")
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


def check_soak(minutes):
    """Opt-in (--soak-minutes N): scripts/soak.py's phases, N minutes each -- gated_config
    against a paced probe_app (mixed breakpoint/inline, all-hw, all-breakpoint), then attach /
    detach cycles of uhh_trace on one long-running probe_app. Each phase: every read logged
    with the right pid/name (logs == hits == successful_reads, log_dropped 0, the log file
    holds logs_written lines), the checksum of an uninstrumented run, and no growth of the
    controller's or target's private bytes / handles / threads (or of agent copies loaded in
    the attached target) beyond steady state."""
    if not exe("gated_config.exe") or not exe("uhh_trace.exe") or not exe("probe_app.exe"):
        return missing_bin("soak", "gated_config/uhh_trace/probe_app")
    sys.path.insert(0, str(Path(__file__).parent))
    import soak
    out = Path(tempfile.gettempdir()) / "uhh" / "soak-regress"
    for phase in ("mixed", "hw", "breakpoint", "attach"):
        name = f"soak-{phase}"
        try:
            r = soak.run_phase(BIN, phase, minutes, out_dir=out, sample_s=max(10.0, minutes * 60 / 6))
            g = r.get("growth_2nd_half", {})
            if phase == "attach":
                detail = (f"cycles={r.get('cycles_ok')}/{r.get('cycles')} reads={r.get('successful_reads')}/{r.get('total')} "
                          f"checksum_same={r.get('checksum') == r.get('baseline_checksum')} exit={r.get('target_exit')} "
                          f"agents(first,last)={r.get('agent_modules_first_last')} growth={g}")
                if not r["ok"]:
                    detail += f" failed={json.dumps(r.get('failed_cycles'))[:600]} unhandled={r.get('unhandled')}"
            else:
                detail = (f"logged={r.get('logged_reads')} hits={r.get('read_hits')} reads={r.get('successful_reads')}/"
                          f"{r.get('total')} dropped={r.get('log_dropped')} file_lines={r.get('log_file_lines')}/"
                          f"{r.get('logs_written')} wrong={r.get('wrong_lines')} checksum_same="
                          f"{r.get('checksum') == r.get('baseline_checksum')} rate={r.get('rate_per_s')}/s growth={g}")
                if not r["ok"]:
                    detail += f" error={r.get('error')} stderr={r.get('stderr_tail', [])[-4:]}"
            record(name, r["ok"], detail)
        except Exception as e:
            record(name, False, repr(e))


def check_blog_pwsh_attach():
    """JIT/managed process (the 'hook a .NET host' write-ups): attach to a running
    powershell.exe, hook kernelbase!CreateFileW, which its script drives via [IO.File],
    detach mid-run. PowerShell must finish with the same output and exit code."""
    t = exe("uhh_trace.exe")
    if not t:
        return missing_bin("blog-pwsh", "uhh_trace.exe")
    import os as _os
    import struct
    data = Path(t).read_bytes()
    x86 = struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0] == 0x14C
    ps = Path(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe") if x86 else \
        SYS32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not ps.exists():
        return skip_external("blog-pwsh", f"system program {ps}")
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


EDGE_CALLS = 2000          # examples/p2edge: calls per site / thread in --hold and --late


def edge_run(mode, backend, targs=(), timeout=300):
    d, t = exe("p2edge_driver.exe"), exe("p2edge_target.exe")
    r, o = run([d, "--mode", mode, "--backend", backend, "--", t, f"--{mode}", *targs], timeout=timeout)
    edge = next((x for x in o if x.get("kind") == "edge"), {})
    drv = next((x for x in o if x.get("kind") == "p2edge_driver"), {})
    return r, o, edge, drv


def probe_hits(objs, suffix):
    return [p.get("hits") for p in probes(objs) if p.get("location", "").endswith(suffix)]


def tail(r, n=6):
    return " | ".join(r.stderr.strip().splitlines()[-n:])


def check_entry_hold_threads(trials=3):
    """Threads started during the entry hold: p2edge_target's TLS callback and p2edge_early.dll's
    DllMain(PROCESS_ATTACH) each start a thread that calls its site EDGE_CALLS times at once,
    before main() runs (UHH holds the main thread at the entry point until the inline hooks
    are in). Every call must be seen: hits == the target's own counts, on every backend.
    Inline repeats (the miss was a race: such threads ran unheld while the hooks went in)."""
    if not exe("p2edge_driver.exe") or not exe("p2edge_target.exe"):
        return missing_bin("entry-hold-threads", "p2edge_driver/p2edge_target")
    for bk in ("breakpoint", "hw", "inline"):
        name = f"entry-hold-threads-{bk}"
        try:
            details, ok = [], True
            for _ in range(trials if bk == "inline" else 1):
                r, o, edge, drv = edge_run("hold", bk)
                tls, early = probe_hits(o, "!TlsSite"), probe_hits(o, "!EarlySite")
                rep = report(o)
                good = (edge.get("tls_calls") == EDGE_CALLS and edge.get("early_calls") == EDGE_CALLS and
                        tls == [EDGE_CALLS] and early == [EDGE_CALLS] and drv.get("run_ok") == 1 and
                        rep.get("error") is None and rep.get("app_exit") == 0)
                ok = ok and good
                details.append(f"tls={tls}/{edge.get('tls_calls')} early={early}/{edge.get('early_calls')}"
                               + ("" if good else f" err={rep.get('error')} stderr={tail(r)}"))
            record(name, ok, "; ".join(details))
        except Exception as e:
            record(name, False, repr(e))


def check_late_dll_worker():
    """A DLL loaded LATER by a NON-main thread: p2edge_late.dll!LateSite, registered before
    launch on <backend>, hits exactly from its first call (EDGE_CALLS). Its callback issues
    probe_add_address(LateNext, PROBE_INLINE) at the first hit (forwarded over IPC from an
    inline callback); LateNext is then called EDGE_CALLS times by the same thread and
    EDGE_CALLS by a new thread: all 2*EDGE_CALLS seen. (edge_count is an empty callback that
    the linker folds with other empty exported callbacks of the agent DLL: the forwarded name
    is an alias, which the controller must still map to its own copy.)"""
    if not exe("p2edge_driver.exe") or not exe("p2edge_target.exe"):
        return missing_bin("late-dll-worker", "p2edge_driver/p2edge_target")
    for bk in ("breakpoint", "hw", "inline"):
        name = f"late-dll-worker-{bk}"
        try:
            r, o, edge, drv = edge_run("late", bk)
            late = probe_hits(o, "!LateSite")
            added = [p for p in probes(o) if p.get("location", "").startswith("0x")]
            msgs = [x.get("message") for x in o if x.get("kind") == "probe_log"]
            rep = report(o)
            ok = (edge.get("worker_rc") == 0 and edge.get("late_calls") == EDGE_CALLS and
                  edge.get("next_calls") == 2 * EDGE_CALLS and late == [EDGE_CALLS] and
                  msgs == ["add_inline=1"] and len(added) == 1 and added[0].get("backend") == "inline" and
                  added[0].get("hits") == 2 * EDGE_CALLS and drv.get("run_ok") == 1 and rep.get("error") is None)
            record(name, ok, f"LateSite={late}/{edge.get('late_calls')} "
                             f"added={[(a.get('backend'), a.get('hits')) for a in added]}/{edge.get('next_calls')} "
                             f"logs={msgs[:3]} rc={edge.get('worker_rc')}"
                             + ("" if ok else f" err={rep.get('error')} stderr={tail(r)}"))
        except Exception as e:
            record(name, False, repr(e))


LD_CALLS, LD_NSITES, LD_HV_ID = 300, 8, 100     # examples/latedll/latedll_shared.h


def check_latedll(reps=10):
    """Probes in DLLs the target LoadLibrary's at RUN time (examples/latedll): registered
    before launch, and the target calls every probed function LD_CALLS times the moment the
    load returns -- from the main thread (`main`), from a worker thread (`worker`), and from
    inside a DllMain that itself LoadLibrary's the probed DLL, calls every site and starts a
    thread under the loader lock (`dllmain`). Eight inline sites outnumber the debug
    registers. On breakpoint, hw, inline and mixed (inline + breakpoint + hw in one session),
    `reps` runs each: every call is counted (probe hits == the bodies' own counts == the
    scenario's), every hit logged once ("ld <id>"), nothing dropped, no install timeout, exit 0.
    (The miss this guards: the LOAD_DLL install was "not confirmed within 5 s", the thread was
    released and every call ran unhooked -- ROADMAP CC8 / B5.)"""
    d, t = exe("latedll_driver.exe"), exe("latedll_target.exe")
    if not d or not t:
        return record("latedll", False, "latedll_driver/latedll_target missing")
    for scen in ("main", "worker", "dllmain"):
        for bk in ("inline", "breakpoint", "hw", "mixed"):
            name = f"latedll-{scen}-{bk}"
            bad, secs = [], []
            try:
                for rep in range(reps):
                    t0 = time.time()
                    r, o = run([d, "--backend", bk, "--", t, scen], timeout=90)
                    secs.append(time.time() - t0)
                    tg = next((x for x in o if x.get("kind") == "latedll"), {})
                    drv = next((x for x in o if x.get("kind") == "latedll_driver"), {})
                    rep_ = report(o)
                    calls = tg.get("calls") or []
                    nsites = 2 if bk == "hw" else LD_NSITES
                    # The oracle, computed HERE (not the target's own "want"): main/worker call
                    # every site LD_CALLS times; dllmain = DllMain + main (2x every site), + the
                    # DllMain thread (site 0 and HvSite once more), HvSite = DllMain + thread + main.
                    if scen == "dllmain":
                        exp = {k: 2 * LD_CALLS for k in range(nsites)}
                        exp[0] = 3 * LD_CALLS
                        exp[LD_HV_ID] = 3 * LD_CALLS
                    else:
                        exp = {k: LD_CALLS for k in range(nsites)}
                    got_calls = {k: calls[k] for k in range(nsites)} if len(calls) == LD_NSITES else {}
                    if scen == "dllmain":
                        got_calls[LD_HV_ID] = tg.get("hv")
                    # The unprobed sites' bodies ran the same counts too (hw probes only 0 and 1).
                    for k in range(nsites, LD_NSITES):
                        want_k = (2 * LD_CALLS) if scen == "dllmain" else LD_CALLS
                        if len(calls) != LD_NSITES or calls[k] != want_k:
                            got_calls[k] = calls[k] if len(calls) == LD_NSITES else None
                    hits = {}
                    for p in probes(o):
                        loc = str(p.get("location", ""))
                        m = re.search(r"!(LdSite(\d)|HvSite)$", loc)
                        if m:
                            hits[int(m.group(2)) if m.group(2) else LD_HV_ID] = p.get("hits")
                    logs = {}
                    for x in o:
                        if x.get("kind") == "probe_log" and str(x.get("message", "")).startswith("ld "):
                            k = int(str(x["message"])[3:])
                            logs[k] = logs.get(k, 0) + 1
                    timeout = "not confirmed" in r.stderr or "install timeout" in r.stderr
                    good = (r.returncode == 0 and tg.get("rc") == 0 and exp and got_calls == exp and
                            hits == exp and logs == exp and drv.get("run_ok") == 1 and
                            rep_.get("error") is None and rep_.get("log_dropped") == 0 and not timeout)
                    if not good:
                        bad.append(f"rep{rep}: rc={r.returncode}/{tg.get('rc')} "
                                   f"hits={ {k: v for k, v in hits.items() if exp.get(k) != v} } "
                                   f"logs={ {k: v for k, v in logs.items() if exp.get(k) != v} } "
                                   f"missing={[k for k in exp if k not in hits or k not in logs]} "
                                   f"body={ {k: v for k, v in got_calls.items() if exp.get(k) != v} } "
                                   f"timeout={timeout} err={rep_.get('error')} dropped={rep_.get('log_dropped')} "
                                   f"stderr={tail(r, 4)}")
                record(name, not bad, ("; ".join(bad)[:1500] if bad else
                                       f"{reps}/{reps} exact, max {max(secs):.1f}s"))
            except Exception as e:
                record(name, False, repr(e))


def check_hw_once_slots(threads=4, calls=1000):
    """Hardware PROBE_ONCE, distinctly: HwSite exec HW|ONCE and g_w1 watch RW|ONCE each fire
    exactly once while 4 threads hammer them (an exec HW and a WRITE watch on the same sites
    count every call). With those 4 slots in use a 5th hw probe is refused at setup and, from
    a callback (marker probe on breakpoint / inline), at runtime. After both ONCE probes
    retired, the marker reuses their two slots (an exec probe and a write watch, both exact)
    and a further add is refused again."""
    if not exe("p2edge_driver.exe") or not exe("p2edge_target.exe"):
        return missing_bin("hw-once-slots", "p2edge_driver/p2edge_target")
    total = threads * calls
    for marker in ("breakpoint", "inline"):
        name = f"hw-once-slots-{marker}"
        try:
            r, o, edge, drv = edge_run("hw", marker, ("--threads", threads, "--calls", calls))
            by = [(p.get("location", ""), p.get("hits")) for p in probes(o)]
            site = [h for l, h in by if l.endswith("!HwSite")]
            w1 = [h for l, h in by if l.endswith("!g_w1")]
            added = [h for l, h in by if l.startswith("0x")]
            msgs = [x.get("message") for x in o if x.get("kind") == "probe_log"]
            rep = report(o)
            ok = (site == [1, total] and w1 == [1, total] and added == [total, total] and
                  drv.get("setup_fifth") == 0 and msgs == ["markA fifth=0", "markB hw=1 watch=1 fifth=0"] and
                  edge.get("w1") == total and edge.get("w2") == total and
                  drv.get("run_ok") == 1 and rep.get("error") is None)
            record(name, ok, f"HwSite[once,all]={site} g_w1[rw-once,write]={w1} reused={added}/{total} "
                             f"setup_fifth={drv.get('setup_fifth')} logs={msgs}"
                             + ("" if ok else f" err={rep.get('error')} stderr={tail(r)}"))
        except Exception as e:
            record(name, False, repr(e))


def check_prehook_chain(threads=4, reads=500):
    """PROBE_ALLOW_PREHOOKED with inline asserted: attach to probe_app --prehook (its own
    SafetyHook detour already sits on ReadThunk) and chain an INLINE probe on top. Both the
    foreign hook and the UHH callback see every call and nothing changes for the target:
    its prehook_calls == UHH hits == logs == reads, checksum == a run without UHH."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return missing_bin("prehook-chain", "uhh_trace/probe_app")
    target = None
    total = threads * reads
    common = ["--prehook", "--helpers", "1", "--threads", str(threads), "--reads", str(reads),
              "--config", "reads_enabled=1"]
    try:
        _, bo = run([a, "--no-wait", *common], timeout=300)
        base = app(bo)
        target = subprocess.Popen([str(a), *common], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        tl = Lines(target.stdout)
        if not tl.wait_for(lambda l: '"waiting"' in l, 60):
            raise RuntimeError("target never reached its gate")
        tracer = subprocess.Popen([str(t), "--backend", "inline", "--allow-prehooked", "--attach", str(target.pid),
                                   "-p", "probe_app.exe!ReadThunk:xxxx"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        tout, terr = Lines(tracer.stdout), Lines(tracer.stderr)
        if not terr.wait_for(lambda l: l.startswith("probe: active probe_app.exe!ReadThunk"), 60):
            raise RuntimeError("probe never became active: " + " | ".join(terr.lines[-6:]))
        target.stdin.write("\n"); target.stdin.flush()
        target.wait(timeout=300)
        tracer.wait(timeout=120)
        res = app(tl.objs())
        objs = tout.objs()
        terr.t.join(timeout=30)
        pre = [x for x in objs if x.get("kind") == "prehook"]
        pr = next((x for x in probes(objs) if x.get("location", "").endswith("!ReadThunk")), {})
        logs = sum(1 for x in objs if x.get("kind") == "probe_log")
        rep = report(objs)
        ok = (bool(pre) and pr.get("backend") == "inline" and pr.get("hits") == total and logs == total and
              res.get("prehook_calls") == total and res.get("successful_reads") == total and
              res.get("checksum") == base.get("checksum") and base.get("prehook_calls") == total and
              target.returncode == 0 and rep.get("log_dropped") == 0)
        record("prehook-chain-inline", ok,
               f"prehook_reports={len(pre)} backend={pr.get('backend')} uhh_hits={pr.get('hits')} logs={logs} "
               f"foreign_hook_calls={res.get('prehook_calls')} reads={res.get('successful_reads')}/{total} "
               f"checksum_same={res.get('checksum') == base.get('checksum')} exit={target.returncode}"
               + ("" if ok else " stderr=" + " | ".join(terr.lines[-8:])))
    except Exception as e:
        record("prehook-chain-inline", False, repr(e))
    finally:
        if target and target.poll() is None:
            target.kill()


STACK_SITES = {"mid": "StkMidSite", "fpo": "StkFpoSite", "leaf": "StkLeafSite"}


def frame_name(f):
    """'mod!func+0x12 (file:line) [0xADDR]' -> 'func' ('' when unsymbolized)."""
    head = f.split(" ")[0]
    if "!" not in head:
        return ""
    return head.split("!", 1)[1].rsplit("+", 1)[0]


def strip_addr(f):
    return f.rsplit(" [0x", 1)[0]


def check_stacks():
    """send_log_stack at a mid-function site, in a frame-pointer-omitted function that uses
    EBP/RBP as data, and in a leaf -- each reached through optimised (x86: /Oy) C callers.
    Every backend must show <site>, stk_outer_<x>, main, and the symbolized stacks (addresses
    stripped) must be IDENTICAL across breakpoint, hw and inline -- frame 0 included."""
    d, t = exe("stacks_driver.exe"), exe("stacks_target.exe")
    if not d or not t:
        return missing_bin("stacks", "stacks_driver/stacks_target")
    try:
        r = rvas("stacks_target.map", *STACK_SITES.values())
    except Exception as e:
        return record("stacks", False, f"map: {e!r}")
    specs = [f"{k}=stacks_target.exe+{r[v]:#x}" for k, v in STACK_SITES.items()]
    per_bk = {}
    for bk in ("breakpoint", "hw", "inline"):
        name = f"stacks-{bk}"
        try:
            _, o = run([d, "--backend", bk, *specs, "--", t], timeout=120)
            tgt = next((x for x in o if x.get("kind") == "target"), {})
            got, bad = {}, []
            for k, site in STACK_SITES.items():
                sts = [[strip_addr(f) for f in x.get("stack") or []] for x in o
                       if x.get("kind") == "probe_log" and x.get("message") == f"stack {k}"]
                want = [site, f"stk_outer_{k}", "main"]
                names = [[frame_name(f) for f in st] for st in sts]
                if len(sts) != 3:
                    bad.append(f"{k}: {len(sts)} logs")
                elif any(n[:3] != want for n in names):
                    bad.append(f"{k}: {names[0][:5]}")
                elif any(st != sts[0] for st in sts):
                    bad.append(f"{k}: hits differ")
                got[k] = sts[0] if sts else []
            per_bk[bk] = got
            ok = not bad and tgt.get("correct") == 9 and report(o).get("error") is None
            record(name, ok, f"correct={tgt.get('correct')}/9 err={report(o).get('error')} bad={bad} "
                             f"fpo={[frame_name(f) for f in got.get('fpo', [])]}")
        except Exception as e:
            record(name, False, repr(e))
    if len(per_bk) == 3:
        diffs = []
        for k in STACK_SITES:
            ref = per_bk["breakpoint"].get(k)
            for bk in ("hw", "inline"):
                other = per_bk[bk].get(k)
                if other != ref:
                    i = next((j for j in range(max(len(ref or []), len(other or [])))
                              if (ref or [None] * 99)[j:j + 1] != (other or [None] * 99)[j:j + 1]), -1)
                    diffs.append(f"{k}/{bk}@{i}: {(ref or [])[i:i + 1]} vs {(other or [])[i:i + 1]}")
        record("stacks-identical", not diffs and all(per_bk[b].get(k) for b in per_bk for k in STACK_SITES),
               f"diffs={diffs[:4]} frames={ {k: len(per_bk['breakpoint'].get(k) or []) for k in STACK_SITES} }")


BIGAPPS_DIR = Path(__file__).resolve().parent.parent / "examples" / "bigapps"
EDGE_EXE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
# Busy system exports. HeapAlloc is a forwarded export (-> ntdll!RtlAllocateHeap). ':-' =
# count only (millions of hits); the others log every call. At most 4: the hw backend has 4 DRs.
BIGAPPS_PS_PROBES = ["ntdll.dll!NtCreateFile:xxO", "KernelBase.dll!CreateFileW:Wxx",
                     "ntdll.dll!NtAllocateVirtualMemory:-", "kernel32.dll!HeapAlloc:-"]
BIGAPPS_EDGE_PROBES = ["ntdll.dll!NtCreateFile:xxO", "ntdll.dll!NtAllocateVirtualMemory:-",
                       "kernel32.dll!HeapAlloc:-", "ws2_32.dll!connect:xSd"]


def bin_machine():
    """'x64' or 'x86': the bitness of the build under test (uhh_trace.exe's PE header)."""
    import struct
    b = (BIN / "uhh_trace.exe").read_bytes()[:4096]
    off = struct.unpack_from("<I", b, 0x3c)[0]
    return "x64" if struct.unpack_from("<H", b, off + 4)[0] == 0x8664 else "x86"


def kill_matching(fragment):
    """Kill ONLY processes whose command line contains fragment -- a unique directory this
    run created (Edge passes its --user-data-dir to every child) -- never anything else."""
    ps = (f"Get-CimInstance Win32_Process | ?{{ $_.CommandLine -like '*{fragment}*' -and $_.ProcessId -ne $PID }}"
          " | %{ Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }")
    try:
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, timeout=120)
    except Exception:
        pass


def bigapps_judge(objs, out_text, err_text, bk, specs, required, exact):
    """The assertions every bigapps run shares. exact: the session ran until the target exited,
    so every logged probe's hits must equal the logs written (a detach reports a live snapshot)."""
    rep = report(objs)
    hits = {p.get("location"): p.get("hits") or 0 for p in probes(objs)}
    backends = sorted({p.get("backend") for p in probes(objs)})
    logged = [sp.rsplit(":", 1)[0] for sp in specs if not sp.endswith(":-")]
    want_logs = sum(hits.get(l, 0) for l in logged)
    written = rep.get("logs_written")
    # Delivered records: every probe_log line must parse (run() keeps the JSON lines) and their
    # number must EQUAL logs_written -- fewer is a lost log, more a duplicated one.
    logs_out = sum(1 for o in objs if o.get("kind") == "probe_log")
    logs_raw = out_text.count('"kind":"probe_log"')
    unhandled = [l for l in err_text.splitlines() if "target crashed" in l or "unhandled exception" in l][:2]
    bad = []
    if not rep: bad.append("no probe_report")
    if rep.get("error") is not None: bad.append(f"error={str(rep.get('error'))[:200]}")
    if rep.get("log_dropped") != 0: bad.append(f"log_dropped={rep.get('log_dropped')}")
    if backends != [bk]: bad.append(f"backends={backends}")
    missing = [r for r in required if not hits.get(r)]
    if missing: bad.append(f"no hits on {missing}")
    if not written: bad.append("no logs")
    if exact and written != want_logs: bad.append(f"logs_written={written} != logged hits={want_logs}")
    if logs_raw != logs_out: bad.append(f"malformed/unparsable probe_log lines={logs_raw - logs_out}")
    # A detach mid-run: the report is a live snapshot taken BEFORE probe_close; the session's
    # final count is probe_close's "probe: detached: ... logs_written=N" (stderr), and every
    # record up to it must be on stdout -- exactly.
    fin = re.findall(r"probe: detached: hits=\d+ logs_written=(\d+) log_dropped=(\d+)", err_text)
    final_written = int(fin[-1][0]) if fin else written
    if fin and int(fin[-1][1]) != 0: bad.append(f"final log_dropped={fin[-1][1]}")
    if '"kind":"detached"' in out_text and not fin: bad.append("detached but no final 'probe: detached:' accounting")
    if final_written is None or logs_out != final_written:
        bad.append(f"stdout probe_log records={logs_out} != logs_written={final_written}"
                   + (" (final, after the detach)" if fin else ""))
    if unhandled: bad.append(f"unhandled={unhandled}")
    short = {k.split("!")[-1]: v for k, v in hits.items()}
    detail = (f"hits={short} logs={written}" + (f" final_logs={final_written}" if fin else "")
              + f" delivered={logs_out} dropped={rep.get('log_dropped')}")
    return not bad, detail, bad


def bigapps_js_expected():
    """page.html's JS result, computed the same way (int32 arithmetic)."""
    def i32(v):
        return (v + 2 ** 31) % 2 ** 32 - 2 ** 31
    r = 0
    for k in range(20):
        h = 0
        for i in range(50000 + k):
            h = i32(h * 31 + (i ^ (i >> 3)))
        r = i32(r + h)
    return r


def bigapps_ps_expected_hash(files=48):
    """workload.ps1's file set hashed HERE (hashlib): file i is 4096 + 97i bytes, byte k =
    (31i + 7k) % 251 (BigAppsWork.Fill); SHA-256 over all of them in order, formatted like
    .NET's BitConverter.ToString."""
    import hashlib
    h = hashlib.sha256()
    for i in range(files):
        h.update(bytes((i * 31 + k * 7) % 251 for k in range(4096 + i * 97)))
    return "-".join(f"{b:02X}" for b in h.digest())


def bigapps_async_n(hold_secs):
    """page.html's async request count: one per 100 ms over the first half of the hold."""
    return max(10, int(hold_secs * 10 / 2))


def bigapps_server(slow_secs):
    """Local HTTP server for page.html. /slow is a parser-blocking script streamed over
    slow_secs (holds Edge's load event, so the browser stays busy until then; it ends by
    writing SLOW=done into the page); /data?i=N answers 'dataN'."""
    import http.server
    page = (BIGAPPS_DIR / "page.html").read_bytes().replace(b"__ASYNC_N__", str(bigapps_async_n(slow_secs)).encode())
    seen = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            try:
                if self.path == "/slow":
                    n = max(1, int(slow_secs * 10))
                    tail = b"\ndocument.getElementById('slow').textContent = 'SLOW=done';\n"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/javascript")
                    self.send_header("Content-Length", str(n * 512 + len(tail)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    for _ in range(n):
                        self.wfile.write(b" " * 511 + b"\n"); self.wfile.flush(); time.sleep(0.1)
                    self.wfile.write(tail); self.wfile.flush()
                    return
                if self.path == "/":
                    body, ctype = page, "text/html"; seen.set()
                elif self.path.startswith("/data?i="):
                    body, ctype = ("data" + self.path.split("=", 1)[1]).encode(), "text/plain"
                else:
                    self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen


def bigapps_tracer(bk, specs, tail):
    cmd = [str(exe("uhh_trace.exe")), "--backend", bk]
    for sp in specs:
        cmd += ["-p", sp]
    return cmd + [str(x) for x in tail]


def bigapps_powershell(bk, mode, secs, ps):
    """powershell.exe running examples/bigapps/workload.ps1 (self-checking: bad=0, exit 0)."""
    work = Path(tempfile.mkdtemp(prefix="uhh-bigapps-ps-", dir=Path.cwd()))
    wl = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", BIGAPPS_DIR / "workload.ps1",
          "-Seconds", secs, "-Work", work, "-ExpectedHash", bigapps_ps_expected_hash()]
    done_re = re.compile(r"BIGAPPS_DONE iters=(\d+) bad=(\d+) jobs=(\d+) exc=(\d+)")

    def workload_bad(m):
        """The workload's own result: bad 0, at least one background job, and exactly 6
        caught exceptions per iteration (5 throws + 1 FormatException) -- in every mode."""
        if not m:
            return ["workload=None (no BIGAPPS_DONE)"]
        it, bd, jobs, exc = (int(x) for x in m.groups())
        out = []
        if bd != 0 or it == 0: out.append(f"workload iters={it} bad={bd}")
        if jobs == 0: out.append("workload jobs=0")
        if exc != 6 * it: out.append(f"workload exc={exc} want {6 * it}")
        return out
    target = None
    try:
        if mode == "launch":
            r, objs = run(bigapps_tracer(bk, BIGAPPS_PS_PROBES, ["--", ps, *wl]), timeout=secs + 900)
            ok, detail, bad = bigapps_judge(objs, r.stdout, r.stderr, bk, BIGAPPS_PS_PROBES,
                                            [s.rsplit(":", 1)[0] for s in BIGAPPS_PS_PROBES], True)
            m = done_re.search(r.stdout)
            rep = report(objs)
            bad += workload_bad(m)
            if rep.get("app_exit") != 0 or r.returncode != 0: bad.append(f"app_exit={rep.get('app_exit')} rc={r.returncode}")
            return not bad, f"{detail} {m.group(0) if m else 'no DONE'} exit={rep.get('app_exit')}", bad, r.stderr
        target = subprocess.Popen([str(ps), *[str(x) for x in wl]], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, errors="replace")
        tl, te = Lines(target.stdout), Lines(target.stderr)
        if not tl.wait_for(lambda l: l.startswith("BIGAPPS_READY"), 180):
            return False, "workload never READY", ["no READY"], "\n".join(te.lines[-5:])
        extra = ["--detach-after-ms", secs * 1000 // 2] if mode == "detach" else []
        r, objs = run(bigapps_tracer(bk, BIGAPPS_PS_PROBES, ["--attach", target.pid, *extra]), timeout=secs + 900)
        at_detach = len(tl.lines)
        target.wait(timeout=secs + 600)
        tl.t.join(timeout=30)
        after = [l for l in tl.lines[at_detach:] if l.startswith("BIGAPPS_TICK")]
        text = "\n".join(tl.lines)
        ok, detail, bad = bigapps_judge(objs, r.stdout, r.stderr, bk, BIGAPPS_PS_PROBES,
                                        [s.rsplit(":", 1)[0] for s in BIGAPPS_PS_PROBES], mode == "exit")
        m = done_re.search(text)
        bad += workload_bad(m)
        if target.returncode != 0 or r.returncode != 0: bad.append(f"target_rc={target.returncode} tracer_rc={r.returncode}")
        if mode == "detach":
            if '"kind":"detached"' not in r.stdout: bad.append("not detached")
            if len(after) < 2: bad.append(f"ticks after detach={len(after)}")
            detail += f" ticks_after_detach={len(after)}"
        return not bad, f"{detail} {m.group(0) if m else 'no DONE'} rc={target.returncode}", bad, r.stderr
    finally:
        if target and target.poll() is None:
            target.kill()
        kill_matching(work.name)
        import shutil
        shutil.rmtree(work, ignore_errors=True)


def bigapps_edge(bk, mode, secs):
    """Headless Edge (multi-process, JIT) dumping a local page while /slow keeps it loading.
    The browser process is the one launched/attached; its children run uninstrumented."""
    udd = Path(tempfile.mkdtemp(prefix="uhh-bigapps-edge-", dir=Path.cwd()))
    hold = secs if mode != "launch" else max(5, secs // 2)
    srv, seen = bigapps_server(hold)
    async_marker = f"ASYNC ok={bigapps_async_n(hold)} fail=0 sent={bigapps_async_n(hold)}<"
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    argv = [EDGE_EXE, "--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
            "--disable-extensions", "--disable-component-update", "--disable-background-networking",
            "--disable-sync", "--no-proxy-server", "--enable-features=NetworkServiceInProcess2",
            f"--user-data-dir={udd}",
            "--dump-dom", url]
    marker = f"BIGAPPS_JS={bigapps_js_expected()} nodes=20000"
    browser = None
    try:
        if mode == "launch":
            r, objs = run(bigapps_tracer(bk, BIGAPPS_EDGE_PROBES, ["--", *argv]), timeout=secs + 900)
            ok, detail, bad = bigapps_judge(objs, r.stdout, r.stderr, bk, BIGAPPS_EDGE_PROBES,
                                            [s.rsplit(":", 1)[0] for s in BIGAPPS_EDGE_PROBES[:3]], True)
            rep = report(objs)
            if marker not in r.stdout: bad.append("JS result missing/wrong in the dumped DOM")
            if "FETCHED=40" not in r.stdout: bad.append("fetches incomplete")
            if "SLOW=done" not in r.stdout: bad.append("slow script incomplete")
            if async_marker not in r.stdout:
                bad.append(f"async fetches: want {async_marker[:-1]!r}, got {re.findall(r'ASYNC ok=[^<]*', r.stdout)[:1]}")
            if rep.get("app_exit") != 0 or r.returncode != 0: bad.append(f"app_exit={rep.get('app_exit')} rc={r.returncode}")
            return not bad, f"{detail} exit={rep.get('app_exit')}", bad, r.stderr
        browser = subprocess.Popen([str(a) for a in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, errors="replace")
        bl, be = Lines(browser.stdout), Lines(browser.stderr)
        if not seen.wait(120):
            return False, "Edge never requested the page", ["no request"], "\n".join(be.lines[-5:])
        time.sleep(1.0)                                      # renderer busy, fetches in flight
        extra = ["--detach-after-ms", secs * 1000 // 2] if mode == "detach" else []
        r, objs = run(bigapps_tracer(bk, BIGAPPS_EDGE_PROBES, ["--attach", browser.pid, *extra]), timeout=secs + 900)
        browser.wait(timeout=secs + 600)
        bl.t.join(timeout=30)
        dom = "\n".join(bl.lines)
        ok, detail, bad = bigapps_judge(objs, r.stdout, r.stderr, bk, BIGAPPS_EDGE_PROBES,
                                        [s.rsplit(":", 1)[0] for s in BIGAPPS_EDGE_PROBES[:3]], mode == "exit")
        if marker not in dom: bad.append("JS result missing/wrong in the dumped DOM")
        if "FETCHED=40" not in dom: bad.append("fetches incomplete")
        if "SLOW=done" not in dom: bad.append("slow script incomplete")
        if async_marker not in dom:
            bad.append(f"async fetches: want {async_marker[:-1]!r}, got {re.findall(r'ASYNC ok=[^<]*', dom)[:1]}")
        if browser.returncode != 0 or r.returncode != 0: bad.append(f"browser_rc={browser.returncode} tracer_rc={r.returncode}")
        if mode == "detach" and '"kind":"detached"' not in r.stdout: bad.append("not detached")
        return not bad, f"{detail} rc={browser.returncode}", bad, r.stderr
    finally:
        srv.shutdown()
        if browser and browser.poll() is None:
            browser.kill()
        kill_matching(udd.name)
        import shutil
        shutil.rmtree(udd, ignore_errors=True)


def check_bigapps(secs=40, select="all"):
    """Stability on real, large, multi-threaded, JIT-heavy programs (opt-in: --bigapps).
    powershell.exe (.NET JIT, runspace-pool threads, child jobs; the 32-bit host on x86) and
    headless Edge (multi-process browser, x64 only), each under every backend, launched AND
    attached (run to exit, and detach mid-run), with busy ntdll/KernelBase/kernel32/ws2_32
    exports probed. Asserts: the program's own result is right and it exits 0, no unhandled
    exception, every probe hit, log_dropped == 0, logs == hits (when run to exit), and after a
    detach the program keeps working (ticks continue, result right, exit 0)."""
    if not exe("uhh_trace.exe"):
        return missing_bin("bigapps", "uhh_trace.exe")
    arch = bin_machine()
    ps = Path(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe") if arch == "x86" else \
        SYS32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    sel = [x for x in select.split(",") if x and x != "all"]
    for app_name in ("ps", "edge"):
        for mode in ("launch", "exit", "detach"):
            for bk in ("breakpoint", "hw", "inline"):
                name = f"bigapps-{app_name}-{mode}-{bk}"
                if sel and not any(x in name for x in sel):
                    continue
                if app_name == "edge" and arch == "x86":
                    skip(name, "msedge.exe is a 64-bit program (x64 build only)"); continue
                if not (ps if app_name == "ps" else EDGE_EXE).exists():
                    # --bigapps is opt-in: a requested app that is absent is a FAILURE, never a skip.
                    record(name, False, f"{'powershell' if app_name == 'ps' else 'msedge'} missing (not installed)"); continue
                t0 = time.time()
                try:
                    ok, detail, bad, err = (bigapps_powershell(bk, mode, secs, ps) if app_name == "ps"
                                            else bigapps_edge(bk, mode, secs))
                    tail = " | ".join(l for l in (err or "").splitlines() if l.strip())[-600:]
                    record(name, ok, f"{detail} secs={time.time() - t0:.0f}" +
                           ("" if ok else f" BAD={bad} stderr_tail={tail}"))
                except Exception as e:
                    record(name, False, repr(e))
# ---- realapps: the gated_config callbacks on real Windows programs ------------------------

REALAPPS_PS_TRUTH = r'''
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class UhhR {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(int a, bool i, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, IntPtr n, out IntPtr r);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool DuplicateHandle(IntPtr sp, IntPtr sh, IntPtr tp, out IntPtr th, int acc, bool inh, int opt);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetModuleHandleW(string n);
  public static string Read(IntPtr h, IntPtr a) { byte[] b = new byte[2]; IntPtr n; return ReadProcessMemory(h, a, b, (IntPtr)2, out n) ? System.Text.Encoding.ASCII.GetString(b) : "ERR" + Marshal.GetLastWin32Error(); }
  public static string Hex(IntPtr h) { return h.ToInt64().ToString("x"); }
}
"@
[Console]::Out.WriteLine('PSREADY'); [Console]::Out.Flush(); [void][Console]::In.ReadLine()
$k32 = [UhhR]::GetModuleHandleW('kernel32.dll'); $cur = [UhhR]::GetCurrentProcess()
"T k32 addr=$([UhhR]::Hex($k32))"
$helpers = 1..3 | % { $psi = New-Object Diagnostics.ProcessStartInfo 'ping.exe', '-n 300 127.0.0.1'
  $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.CreateNoWindow = $true; [Diagnostics.Process]::Start($psi) }
# A just-started helper has no kernel32 yet (a read is a partial copy, ERROR 299): wait
# until its loader is done, without touching the k32 address the test reads.
foreach ($p in $helpers) { for ($t = 0; $t -lt 200; $t++) { try { if ([Diagnostics.Process]::GetProcessById($p.Id).Modules.Count -gt 3) { break } } catch {}; Start-Sleep -Milliseconds 50 } }
$i = 0
foreach ($p in $helpers) {
  $i++
  # NtOpenProcess -> mapped: the read must say this helper's pid and ping.exe.
  $h = [UhhR]::OpenProcess(0x10, $false, $p.Id); "O open$i $([UhhR]::Read($h, $k32))"; "T read handle=$([UhhR]::Hex($h)) pid=$($p.Id)"
  [void][UhhR]::CloseHandle($h)
  # The closed value is reissued to a handle that never went through NtOpenProcess (a
  # duplicate of CreateProcess's handle): it must read as unmapped, not as the closed open.
  $d = [IntPtr]::Zero; [void][UhhR]::DuplicateHandle($cur, $p.Handle, $cur, [ref]$d, 0, $false, 2)
  "O dup$i $([UhhR]::Read($d, $k32))"; "T read handle=$([UhhR]::Hex($d)) pid=0 reuse=$($d -eq $h)"
  [void][UhhR]::CloseHandle($d)
  "O cph$i $([UhhR]::Read($p.Handle, $k32))"; "T read handle=$([UhhR]::Hex($p.Handle)) pid=0"
  "O self$i $([UhhR]::Read($cur, $k32))"; "T read handle=$([UhhR]::Hex($cur)) pid=0"
  # Reuse between two opens: open helper 1, close, open this helper (same value back).
  $a = [UhhR]::OpenProcess(0x10, $false, $helpers[0].Id); [void][UhhR]::CloseHandle($a)
  $b = [UhhR]::OpenProcess(0x10, $false, $p.Id)
  "O reopen$i $([UhhR]::Read($b, $k32))"; "T read handle=$([UhhR]::Hex($b)) pid=$($p.Id) reuse=$($a -eq $b)"
  [void][UhhR]::CloseHandle($b)
  # .NET's own path: Process.Modules (OpenProcess + EnumProcessModules).
  $q = [Diagnostics.Process]::GetProcessById($p.Id)
  "O mods$i $($q.MainModule.ModuleName) $($q.Modules.Count -gt 3)"
}
$helpers | % { $_.Kill(); $_.WaitForExit() }
"O done"
'''

# name, argv after the program dir is chosen, row filter. Rows: the program's output lines
# that the test compares (see realapps_rows). "stable" rows are those identical in two
# uninstrumented runs (before and after); each must appear unchanged under instrumentation.
def _realapps_scenarios(sysdir):
    ps = sysdir / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    psargs = [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]
    return [
        ("tasklist-m", [sysdir / "tasklist.exe", "/m", "/fo", "csv", "/nh"], "csv", (None, 1)),
        ("tasklist-v", [sysdir / "tasklist.exe", "/v", "/fo", "csv", "/nh"], "csv", ((0, 1, 2, 3, 6), 1)),
        ("wmic", [sysdir / "wbem" / "WMIC.exe", "process", "get", "Name,ProcessId,ExecutablePath", "/format:csv"], "lines", (None, -1)),
        ("cmd-tasklist", [sysdir / "cmd.exe", "/c", "tasklist /fo csv /nh"], "csv", ((0, 1, 2, 3), 1)),
        ("ps-modules", psargs + ["Get-Process | sort Id | % { try { '{0},{1},{2}' -f $_.Id,$_.ProcessName,"
                                 "(($_.Modules | % ModuleName) -join ';') } catch {} }"], "lines", (None, 0)),
        ("ps-fileversion", psargs + ["Get-Process -FileVersionInfo -EA SilentlyContinue | % { $_.FileName } | sort"],
         "lines", (None, "path")),
        ("ps-truth", psargs + [REALAPPS_PS_TRUTH], "truth", None),
        ("ps-truth-attach", psargs + [REALAPPS_PS_TRUTH], "truth-attach", None),
    ]


def _snapshot_processes():
    """{pid: image name} via Toolhelp (independent of UHH and of the program under test)."""
    import ctypes
    from ctypes import wintypes

    class PE32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for fn in (k32.Process32FirstW, k32.Process32NextW):
        fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(PE32)]
        fn.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    INVALID_HANDLE_VALUE, ERROR_NO_MORE_FILES = ctypes.c_void_p(-1).value, 18
    snap = k32.CreateToolhelp32Snapshot(2, 0)                  # TH32CS_SNAPPROCESS
    if not snap or snap == INVALID_HANDLE_VALUE:
        raise RuntimeError(f"Toolhelp oracle: CreateToolhelp32Snapshot failed (error {ctypes.get_last_error()})")
    try:
        out, e = {}, PE32()
        e.dwSize = ctypes.sizeof(PE32)
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        if not ok:
            raise RuntimeError(f"Toolhelp oracle: Process32FirstW failed (error {ctypes.get_last_error()})")
        while ok:
            out[e.th32ProcessID] = e.szExeFile
            ok = k32.Process32NextW(snap, ctypes.byref(e))
        err = ctypes.get_last_error()
        if err != ERROR_NO_MORE_FILES:
            raise RuntimeError(f"Toolhelp oracle: Process32NextW stopped with error {err}, not ERROR_NO_MORE_FILES")
    finally:
        k32.CloseHandle(snap)
    if not out:
        raise RuntimeError("Toolhelp oracle: empty process list")
    return out


class _ProcPoller:
    """Every (pid, name) that existed while a run was going on, polled every 20 ms. A snapshot
    failure in the polling thread is re-raised by finish(): the oracle is never silently thin."""
    def __init__(self):
        self.seen, self.stop, self.error = {}, threading.Event(), None
        self._add(_snapshot_processes())
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _add(self, snap):
        cur = {(pid, name.lower()) for pid, name in snap.items()}
        self.always = cur if not hasattr(self, "always") else self.always & cur
        for pid, name in snap.items():
            self.seen.setdefault(pid, set()).add(name.lower())

    def _loop(self):
        try:
            while not self.stop.wait(0.02):
                self._add(_snapshot_processes())
        except Exception as e:                     # reported by finish()
            self.error = e

    def finish(self):
        self.stop.set(); self.t.join(timeout=10)
        if self.t.is_alive():
            raise RuntimeError("Toolhelp oracle: poller did not stop")
        if self.error is not None:
            raise RuntimeError(f"Toolhelp oracle failed while polling: {self.error!r}")
        self._add(_snapshot_processes())
        return self.seen


_JSON_LINE = re.compile(rb'\{"kind":"[a-z_]+"[^\n]*\n')


def _split_stdout(raw):
    """The driver and the program share one stdout file (the target inherits it): every UHH
    record is one complete JSON line written in one go, so cutting those out leaves the
    program's output byte-for-byte."""
    objs = []
    for m in _JSON_LINE.finditer(raw):
        try:
            objs.append(json.loads(m.group(0)))
        except json.JSONDecodeError:
            pass
    return _JSON_LINE.sub(b"", raw), objs


def _decode_out(raw):
    """wmic writes UTF-16LE (with a BOM); the rest the OEM/ANSI code page."""
    if raw.startswith(b"\xff\xfe") or raw[1:200:2].count(0) > 50:
        return raw.decode("utf-16-le", "replace").lstrip("\ufeff")
    return raw.decode("mbcs", "replace")


def _realapps_rows(text, kind, cols):
    rows = []
    for line in _decode_out(text).splitlines():
        line = line.strip()
        if not line:
            continue
        if kind == "csv" and cols and cols[0]:
            import csv as _csv
            f = next(_csv.reader([line]), [])
            line = ",".join(f[c] for c in cols[0] if c < len(f))
        rows.append(line)
    return rows


def _row_alive(row, cols, alive_pids, alive_names):
    """Only rows about processes that existed for the WHOLE instrumented run can be compared
    (other agents' build/test processes come and go): key = the row's pid (csv field) or,
    for a bare image path, its file name."""
    if not cols or cols[1] is None:
        return True
    if cols[1] == "path":
        return row.rsplit("\\", 1)[-1].lower() in alive_names
    f = row.split(",")
    try:
        return int(f[cols[1]].strip('"')) in alive_pids
    except (ValueError, IndexError):
        return False


def _run_plain(argv, outp, timeout=900, stdin=None):
    t0 = time.perf_counter()
    with open(outp, "wb") as fo, open(str(outp) + ".err", "wb") as fe:
        p = subprocess.run([str(a) for a in argv], stdout=fo, stderr=fe, stdin=stdin or subprocess.DEVNULL, timeout=timeout)
    return p.returncode, Path(outp).read_bytes(), time.perf_counter() - t0


_RX_OPEN = re.compile(r"open pid=(\d+) name=(\S+)$")
_RX_MAP = re.compile(r"map handle=0x([0-9a-f]+) -> pid=(\d+) name=(\S+)$")
_RX_READ = re.compile(r"read handle=0x([0-9a-f]+) pid=(\d+) name=(\S+) addr=0x([0-9a-f]+) size=(\d+)$")


def _realapps_verify_logs(objs, seen):
    """Every read's (pid, name) must be a process that existed (per Toolhelp); pid 0 must
    say name=?; a mapped read's handle must have been mapped to that pid by an open line."""
    msgs = [str(o.get("message", "")) for o in objs if o.get("kind") == "probe_log"]
    maps, reads, opens, other, bad, unverified = {}, [], [], [], [], set()
    for m in msgs:
        if (g := _RX_READ.match(m)):
            reads.append((int(g[1], 16), int(g[2]), g[3], int(g[4], 16), int(g[5])))
        elif (g := _RX_MAP.match(m)):
            maps.setdefault(int(g[1], 16), set()).add(int(g[2]))
        elif (g := _RX_OPEN.match(m)):
            opens.append(int(g[1]))
        else:
            other.append(m)
    pids = set()
    for h, pid, name, _, _ in reads:
        if pid == 0:
            if name != "?":
                bad.append(f"pid0 name={name}")
            continue
        pids.add(pid)
        if pid not in maps.get(h, ()):
            bad.append(f"read h={h:#x} pid={pid} never mapped to it")
        if pid not in seen:
            unverified.add((pid, name))
        elif name.lower() not in seen[pid]:
            bad.append(f"pid {pid} logged {name}, really {sorted(seen[pid])}")
    return msgs, reads, opens, other, bad, unverified, pids


def check_realapps():
    """Flagship use case on REAL programs: realapps_driver applies gated_config's callbacks
    (track_open_process / forget_closed_handle / log_read) to tasklist, wmic, cmd and
    powershell (Get-Process .Modules / -FileVersionInfo, and a .NET P/Invoke script with
    known handles), launched and attached, on every backend. Program output must equal the
    uninstrumented run (rows stable across two plain runs must be unchanged); every logged
    read's pid/name must be a real process (Toolhelp poll); reads through handles that did
    not come from NtOpenProcess must be unmapped; nothing dropped (read logs == read hits).
    UHH_REALAPPS_ONLY / UHH_REALAPPS_BACKENDS (comma lists) narrow it."""
    drv = exe("realapps_driver.exe")
    if not drv:
        return missing_bin("realapps", "realapps_driver.exe")
    data = Path(drv).read_bytes()
    x86 = struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0] == 0x14C
    sysdir = Path(r"C:\Windows\SysWOW64") if x86 else SYS32
    only = [x for x in os.environ.get("UHH_REALAPPS_ONLY", "").split(",") if x]
    env_bks = [x for x in os.environ.get("UHH_REALAPPS_BACKENDS", "").split(",") if x]
    work = Path(tempfile.mkdtemp(prefix="uhh_realapps_"))
    for scen, argv, kind, cols in _realapps_scenarios(sysdir):
        if only and scen not in only:
            continue
        if not Path(argv[0]).exists():
            # Explicitly requested (--only realapps..., UHH_REALAPPS_ONLY): a FAILURE. In the
            # full suite a program this Windows no longer ships (e.g. wmic) is a SKIP.
            explicit = scen in only or any(o in n for o in ONLY for n in (f"realapps-{scen}", "check_realapps", "check-realapps"))
            if explicit:
                record(f"realapps-{scen}", False, f"{argv[0]} missing on this system (explicitly selected)")
            else:
                skip_external(f"realapps-{scen}", f"system program {argv[0]} (not on this system)")
            continue
        base = None
        bks = env_bks or ["breakpoint", "hw", "inline"]
        if x86 and scen == "tasklist-m" and not env_bks:
            bks = ["breakpoint"]   # 32-bit tasklist /m takes ~2 min even uninstrumented (and opens nothing)
        for bk in bks:
            name = f"realapps-{scen}-{bk}"
            print(f"  .. {name}", file=sys.stderr, flush=True)
            try:
                # Plain (uninstrumented) runs right before and right after this one: a
                # process list changes all the time, so only rows identical in both count.
                if kind in ("csv", "lines") or (kind == "truth" and base is None):
                    base = [_run_plain(argv, work / f"{scen}-{bk}-plain0.txt")]
                _realapps_one(name, drv, argv, kind, cols, bk, base, work / f"{scen}-{bk}", x86,
                              after=(lambda: _run_plain(argv, work / f"{scen}-{bk}-plain1.txt"))
                              if kind in ("csv", "lines") else None)
            except Exception as e:
                record(name, False, repr(e))
    if os.environ.get("UHH_REALAPPS_KEEP"):
        print(f"  realapps work dir kept: {work}", file=sys.stderr)
    else:
        shutil.rmtree(work, ignore_errors=True)


def _realapps_one(name, drv, argv, kind, cols, bk, base, stem, x86, after=None):
    t0 = time.perf_counter()
    poll = _ProcPoller()
    target = None
    try:
        if kind == "truth-attach":
            target = subprocess.Popen([str(a) for a in argv], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True)
            tl = Lines(target.stdout)
            if not tl.wait_for(lambda l: "PSREADY" in l, 120):
                raise RuntimeError("powershell never got ready")
            with open(str(stem) + ".out", "wb") as fo, open(str(stem) + ".err", "wb") as fe:
                d = subprocess.Popen([str(drv), "--backend", bk, "--attach", str(target.pid)], stdout=fo, stderr=fe)
                deadline = time.time() + 120
                while time.time() < deadline:
                    err = Path(str(stem) + ".err").read_bytes().decode("utf-8", "replace")
                    if sum(1 for l in err.splitlines() if l.startswith("probe: active ntdll.dll!")) >= 3 or d.poll() is not None:
                        break
                    time.sleep(0.05)
                target.stdin.write("\n"); target.stdin.flush(); target.stdin.close()
                d.wait(timeout=600)
            target.wait(timeout=60)
            tl.t.join(timeout=30)
            prog_out = ("\n".join(tl.lines) + "\n").encode()
            drc = d.returncode
            raw = Path(str(stem) + ".out").read_bytes()
            _, objs = _split_stdout(raw)
            prc = target.returncode
            # Baseline for attach: the launched-plain truth run.
            base_out = None
        else:
            with open(str(stem) + ".out", "wb") as fo, open(str(stem) + ".err", "wb") as fe:
                d = subprocess.run([str(drv), "--backend", bk, "--"] + [str(a) for a in argv], stdout=fo, stderr=fe,
                                   stdin=subprocess.DEVNULL, timeout=900)
            drc = d.returncode
            raw = Path(str(stem) + ".out").read_bytes()
            prog_out, objs = _split_stdout(raw)
            prc = report(objs).get("app_exit")
    finally:
        seen = poll.finish()
        alive_pids = {p for p, _ in poll.always}
        alive_names = {n for _, n in poll.always}
        if target and target.poll() is None:
            target.kill()
    secs = time.perf_counter() - t0
    if after:
        base = base + [after()]
    rep = report(objs)
    pr = {p.get("location"): p for p in probes(objs)}
    read_hits = pr.get(READ_LOCATION, {}).get("hits")
    msgs, reads, opens, other, bad, unverified, pids = _realapps_verify_logs(objs, seen)
    unmapped = sum(1 for r in reads if r[1] == 0)
    errs = Path(str(stem) + ".err").read_bytes().decode("utf-8", "replace").splitlines()
    warn = [l for l in errs if "refus" in l.lower() or "warning" in l.lower() or "error" in l.lower()]
    # The driver exits 1 when the program does (probe_wait_for_exit): compare with the plain run.
    plain_rc = base[0][0] if base else 0
    ok = ((drc == 0 or (drc == 1 and prc == plain_rc != 0)) and rep.get("error") is None and rep.get("log_dropped") == 0 and rep.get("callbacks_interrupted") == 0
          and read_hits == len(reads) and len(other) == 0 and not bad
          and all(p.get("active") for p in pr.values()) and len(pr) == 3)
    plain_s = f"(plain {base[0][2]:.1f}s) " if base else ""
    detail = (f"{secs:.1f}s {plain_s}rc={drc} app_exit={prc} opens={len(opens)} reads={len(reads)}/{read_hits} unmapped={unmapped} "
              f"pids={len(pids)} unverified={sorted(unverified)[:4]} dropped={rep.get('log_dropped')} "
              f"intr={rep.get('callbacks_interrupted')}")
    if kind in ("csv", "lines"):
        # Multisets, not sets: identical rows (e.g. several processes with the same image path)
        # must all still be there -- losing one of two equal rows is lost output.
        stable = Counter({r: n for r, n in (Counter(_realapps_rows(base[0][1], kind, cols)) &
                                            Counter(_realapps_rows(base[1][1], kind, cols))).items()
                          if _row_alive(r, cols, alive_pids, alive_names)})
        mine = Counter(_realapps_rows(prog_out, kind, cols))
        missing = sorted((stable - mine).elements())
        # A 32-bit Get-Process -FileVersionInfo lists only the few 32-bit processes: >= 1 row.
        ok = ok and not missing and prc == plain_rc and sum(stable.values()) >= 1
        detail += f" stable_rows={sum(stable.values())} missing={len(missing)} exit={prc}/{base[0][0]}"
        if missing:
            m0 = missing[0]
            key = ",".join(m0.split(",")[:2])
            if cols and isinstance(cols[1], int):
                try:   # did the instrumented program even get a handle to that process?
                    kp = int(m0.split(",")[cols[1]].strip('"'))
                    detail += f" [pid {kp}: opened={kp in opens} reads={sum(1 for r in reads if r[1] == kp)}]"
                except (ValueError, IndexError):
                    pass
            twin = next((r for r in mine if r.startswith(key)), None)
            if twin:   # show only where the row differs
                ma, tb = m0.split(";"), twin.split(";")
                detail += f" e.g. {key}: only_plain={sorted(set(ma) - set(tb))[:5]} only_instr={sorted(set(tb) - set(ma))[:5]}"
            else:
                detail += f" e.g.={m0[:200]!r} (row absent)"
    else:
        lines = prog_out.decode("mbcs", "replace").splitlines()
        o_lines = [l.strip() for l in lines if l.startswith("O ")]
        t_lines = [l.strip() for l in lines if l.startswith("T ")]
        want_o = ["O open%d MZ", "O dup%d MZ", "O cph%d MZ", "O self%d MZ", "O reopen%d MZ", "O mods%d ping.exe True"]
        want = [w % i for i in (1, 2, 3) for w in want_o] + ["O done"]
        o_lines = [l.lower() for l in o_lines]; want = [w.lower() for w in want]
        if base:
            plain_o = [l.strip().lower() for l in base[0][1].decode("mbcs", "replace").splitlines() if l.startswith("O ")]
            want_ok = plain_o == want
        else:
            want_ok = True
        k32 = next((int(l.split("addr=")[1], 16) for l in t_lines if l.startswith("T k32")), None)
        mask = 0xFFFFFFFF if x86 else (1 << 64) - 1
        exp = [(int(re.search(r"handle=([0-9a-f]+)", l)[1], 16) & mask, int(re.search(r"pid=(\d+)", l)[1]))
               for l in t_lines if l.startswith("T read")]
        reuse = [l for l in t_lines if "reuse=True" in l]
        got = [(h, pid) for h, pid, n, a, sz in reads if a == k32 and sz == 2]
        names = {n.lower() for h, pid, n, a, sz in reads if a == k32 and sz == 2 and pid}
        ok = ok and o_lines == want and want_ok and got == exp and names <= {"ping.exe"} and prc == 0
        detail += (f" out_ok={o_lines == want} plain_ok={want_ok} k32_reads={len(got)}/{len(exp)} match={got == exp} "
                   f"reused_values={len(reuse)} names={sorted(names)}")
        if got != exp:
            detail += f" got={[(hex(h), p) for h, p in got][:6]} exp={[(hex(h), p) for h, p in exp][:6]}"
        if o_lines != want:
            detail += f" out={[x for x in o_lines if x not in want][:4]} n={len(o_lines)} err={errs[-3:]}"
    if bad:
        detail += f" bad={bad[:3]}"
    if other:
        detail += f" other_logs={other[:2]}"
    if warn:
        detail += f" stderr={warn[:2]}"
    record(name, ok, detail[:1500])
INPLACE_SHAPES = ["jmp8", "jmp32", "jcc8_taken", "jcc8_not", "jcc8_alt", "jcc32_taken", "call32", "callmem", "ret",
                  "loop_taken", "loop_not", "loopz", "loopnz", "jrcxz", "loop_a32", "jecxz_a32", "pushf",
                  "pushf_guard", "segjmp", "syscall"]


def check_inplace_shapes():
    """inplace-<shape> (docs/ROADMAP.md "Evaluator round 3" #1/#2): software breakpoint on every
    instruction shape that cannot be stepped out-of-line (relative jmp/jcc rel8/rel32 taken and
    not, call rel32 / call [mem], ret, loop/loopz/loopnz/jrcxz incl. address-size forms, pushf
    with a normal stack and into the stack guard page, a segment-relative indirect jmp, x64
    syscall). 8 threads x 1000 calls each (examples/ctrlreview ctrl_target `shape`): hits ==
    logs == calls and the logged tags are EXACTLY the (thread << 20) | i tags of the calls
    (each once), every result equal to the never-probed twin's, no trap flag in a pushed
    flags image, and the guard-page push grew the stack as without UHH."""
    d, t = exe("ctrl_driver.exe"), exe("ctrl_target.exe")
    if not d or not t:
        return missing_bin("inplace", "ctrl_driver/ctrl_target")
    x86 = pe_is_x86(t)
    T, n = 8, 1000
    for sh in INPLACE_SHAPES:
        if sh == "syscall" and x86:
            continue                                     # no 32-bit syscall instruction
        name = f"inplace-{sh}"
        try:
            r, o = run([d, "--scenario", "shape", "--shape", sh, "--backend", "breakpoint", "--",
                        t, "shape", "--shape", sh, "--threads", T, "--n", n], timeout=300)
            bad = []
            if r.returncode != 0: bad.append(f"exit={r.returncode}")
            rep = report(o)
            if rep.get("error") is not None: bad.append(f"error={rep.get('error')}")
            if rep.get("log_dropped", 0) != 0: bad.append(f"log_dropped={rep.get('log_dropped')}")
            if rep.get("app_exit") != 0: bad.append(f"app_exit={rep.get('app_exit')}")
            res = next((x for x in o if x.get("kind") == "ctrl_result"), {})
            rows = [x for x in o if x.get("kind") == "probe"]
            logs = [x for x in famous_objs(r, o) if x.get("kind") == "probe_log"]
            hits = sum(x.get("hits", 0) for x in rows)
            tags = collections.Counter(str(x.get("message", "")) for x in logs)
            calls = T * n
            # Oracle computed here: thread t (1..T) calls the shape with tag (t << 20) | i for
            # i < n, and the callback logs "tag=<hex>" of EDX -- every call exactly once.
            want = collections.Counter(f"tag={(t_ << 20) | i:x}" for t_ in range(1, T + 1) for i in range(n))
            dups, missed = sum((tags - want).values()), sum((want - tags).values())
            if res.get("calls") != calls: bad.append(f"target={res}")
            if hits != calls: bad.append(f"hits={hits}")
            if len(logs) != calls: bad.append(f"logs={len(logs)}")
            if dups: bad.append(f"duplicate_or_foreign_tags={dups} e.g. {sorted((tags - want).elements())[:2]}")
            if missed: bad.append(f"missed_tags={missed} e.g. {sorted((want - tags).elements())[:2]}")
            if res.get("bad"): bad.append(f"result_differs={res.get('bad')} (first probed={res.get('first_p')} "
                                          f"reference={res.get('first_r')})")
            if res.get("tf"): bad.append(f"tf_in_pushed_flags={res.get('tf')}")
            if res.get("grow_bad"): bad.append(f"stack_not_grown={res.get('grow_bad')}")
            record(name, not bad, (" ".join(bad) + " " if bad else "") +
                   f"calls={calls} hits={hits} logs={len(logs)} exact_tags={len(set(tags) & set(want))}/{calls}")
        except Exception as e:
            record(name, False, repr(e))


def own_watch_slots_bad(w, n, bk):
    """The target's own watch, armed in turn in every debug register FREE on its thread
    (ctrl_target owndr phase B / owndrx: -1 = slot not free, -2 = SetThreadContext failed,
    else the traps seen). The expected free set is computed HERE, not from what the fixture
    found: 4 debug registers minus the one UHH's hw-backend probe holds (hw only). Every other
    UHH register -- the one-shot probe / watch it released -- must be free again, so exactly
    that many slots must trap n times and the rest be -1. A released slot left enabled shrinks
    the free set and fails."""
    want_free = 4 - (1 if bk == "hw" else 0)
    got_free = sum(1 for v in w if v == n)
    if len(w) != 4 or got_free != want_free or any(v not in (-1, n) for v in w):
        return f"own_watch_per_slot={w} (want {want_free} free slot(s) with {n} traps each, the rest -1)"
    return ""


def check_ctrl_review():
    """Controller review findings (examples/ctrlreview, docs/ROADMAP.md "Controller review
    findings"), each reproduced by its own fixture:
      ctrl-fault-<b>: a probed load faults on a reserved page (VEH commits it) or a guard page
        (VEH just retries) and the target CONTINUEs execution: one hit per execution (as
        inline), the VEH sees every fault (the guard one too), never our trap flag, and no
        stray single-step.
      ctrl-inplace: 8 threads x 3000 calls through an address-size LOOP (once stepped in place):
        hits == logs == distinct tags == calls (none missed while a byte was lifted, none twice).
      ctrl-absunload-<b>: probe_add_address / probe_watch inside a DLL that unloads and
        reloads 5 times: every absolute probe is retired at its unload (exactly N hits each,
        none attributed to an old probe, no debug-register slot leak).
      ctrl-symunload-<b>: stack logs captured inside a DLL that unloads right after a burst
        still symbolize to that DLL (the writer runs behind the unload).
      ctrl-owndr-<b>: the target's OWN hardware watchpoints (SetThreadContext on itself + VEH)
        keep working while UHH arms a hardware probe at runtime and releases a one-shot one.
      ctrl-headclamp: a target that corrupts the agent ring's log_head cannot hang the
        controller at exit."""
    d, t, dll = exe("ctrl_driver.exe"), exe("ctrl_target.exe"), exe("ctrl_dll.dll")
    if not d or not t or not dll:
        return missing_bin("ctrl-review", "ctrl_driver/ctrl_target/ctrl_dll")

    def go(sc, bk, targs, timeout=180):
        r, o = run([d, "--scenario", sc, "--backend", bk, "--", t, sc, *targs], timeout=timeout)
        res = next((x for x in o if x.get("kind") == "ctrl_result"), {})
        logs = [x for x in o if x.get("kind") == "probe_log"]
        rows = [x for x in o if x.get("kind") == "probe"]
        return r, o, res, logs, rows

    def common(r, o):
        bad = []
        if r.returncode != 0: bad.append(f"exit={r.returncode}")
        rep = report(o)
        if rep.get("error") is not None: bad.append(f"error={rep.get('error')}")
        if rep.get("log_dropped", 0) != 0: bad.append(f"log_dropped={rep.get('log_dropped')}")
        if rep.get("app_exit") != 0: bad.append(f"app_exit={rep.get('app_exit')}")
        return bad

    # Finding 2: faulting probed instruction, target handler continues execution.
    N = 200
    for bk in ("breakpoint", "hw", "inline"):
        name = f"ctrl-fault-{bk}"
        try:
            r, o, res, logs, rows = go("fault", bk, ["--n", N])
            bad = common(r, o)
            hits = sum(x.get("hits", 0) for x in rows)
            if hits != N: bad.append(f"hits={hits}")
            if len(logs) != N: bad.append(f"logs={len(logs)}")
            if res.get("av") != N // 2 or res.get("guard") != N // 2:
                bad.append(f"veh av={res.get('av')} guard={res.get('guard')} (want {N // 2} each)")
            # The program's handler must never see UHH's trap flag, on any backend (the gospel).
            if res.get("tf") != 0: bad.append(f"tf_in_handler={res.get('tf')}")
            if res.get("stray") != 0: bad.append(f"stray_single_steps={res.get('stray')}")
            # The program's own result: even loads read a freshly committed (zero) page, odd
            # ones the guard page holding 7 -> N/2 * 7. A probe that changed the load fails it.
            if res.get("sum") != (N // 2) * 7: bad.append(f"target_sum={res.get('sum')} want {(N // 2) * 7}")
            record(name, not bad, " ".join(bad) or
                   f"hits={hits} av={res.get('av')} guard={res.get('guard')} tf_in_handler={res.get('tf')}")
        except Exception as e:
            record(name, False, repr(e))

    # Finding 3 / round 3 #2: 8 threads through a site the breakpoint once stepped in place
    # (address-size LOOP): every call counted once -- none missed while a byte was lifted,
    # none reported twice.
    try:
        T, n = 8, 3000
        r, o, res, logs, rows = go("inplace", "breakpoint", ["--threads", T, "--n", n], timeout=300)
        bad = common(r, o)
        logs = [x for x in famous_objs(r, o) if x.get("kind") == "probe_log"]
        # Oracle computed here: thread t (1..T) calls CtrlLoop((t << 20) | i) for i < n, and
        # the callback logs "tag=<hex>" -- every call exactly once.
        want = Counter(f"tag={(t << 20) | i:x}" for t in range(1, T + 1) for i in range(n))
        got = Counter(str(x.get("message", "")) for x in logs)
        dups = sum((got - want).values())
        missed = sum((want - got).values())
        hits = sum(x.get("hits", 0) for x in rows)
        if dups: bad.append(f"duplicate_or_foreign_callbacks={dups}")
        if missed: bad.append(f"missed_calls={missed} (ROADMAP round 3 #2)")
        if hits != T * n: bad.append(f"hits={hits} want {T * n}")
        if len(logs) != T * n: bad.append(f"logs={len(logs)} want {T * n}")
        if (res.get("bad") != 0 or res.get("calls") != T * n or res.get("started") != T or res.get("finished") != T
                or res.get("wait_ok") != 1):
            bad.append(f"target={ {k: res.get(k) for k in ('calls', 'bad', 'started', 'finished', 'wait_ok')} }")
        record("ctrl-inplace", not bad, (" ".join(bad) + " " if bad else "") +
               f"calls={T * n} hits={hits} logs={len(logs)} distinct={len(set(got) & set(want))}")
    except Exception as e:
        record("ctrl-inplace", False, repr(e))

    # Finding 5: absolute probes / watches inside a DLL that unloads.
    C, n = 5, 100
    for bk in ("breakpoint", "hw", "inline"):
        name = f"ctrl-absunload-{bk}"
        try:
            r, o, res, logs, rows = go("absunload", bk, ["--cycles", C, "--n", n])
            bad = common(r, o)
            fails = [str(x.get("message")) for x in logs if not str(x.get("message", "")).startswith("ok")]
            if fails: bad.append(f"callback_fail={fails[:2]}")
            # C absolute execute probes (this backend) + C watchpoints (hw), N hits each
            absrows = [x for x in rows if str(x.get("location", "")).startswith("0x")]
            hits = sorted(x.get("hits", 0) for x in absrows)
            if len(absrows) != 2 * C or any(h != n for h in hits):
                bad.append(f"abs_rows={len(absrows)} hits={hits}")
            if any(x.get("active") for x in absrows): bad.append("abs probe still active after unload")
            # Each load starts CtrlDllCounter at 0 and work(1) returns the running count:
            # sum = C * n(n+1)/2 exactly, with the probe and the watchpoint on it.
            if res.get("sum") != C * n * (n + 1) // 2 or res.get("cycles") != C or len(res.get("bases") or []) != C:
                bad.append(f"target sum={res.get('sum')} want {C * n * (n + 1) // 2} cycles={res.get('cycles')}")
            ok_logs = [x for x in logs if str(x.get("message", "")).startswith("ok")]
            if len(ok_logs) != C: bad.append(f"announce_logs={len(ok_logs)} want {C}")
            record(name, not bad, " ".join(bad) or f"{len(absrows)} absolute probes x {n} hits, all retired")
        except Exception as e:
            record(name, False, repr(e))

    # Finding 6: frames captured before an unload must symbolize to the unloaded DLL.
    C, n = 4, 1500
    for bk in ("breakpoint", "hw", "inline"):
        name = f"ctrl-symunload-{bk}"
        try:
            r, o, res, logs, rows = go("symunload", bk, ["--cycles", C, "--n", n], timeout=300)
            bad = common(r, o)
            if len(logs) != C * n: bad.append(f"logs={len(logs)} want {C * n}")
            unres = [x for x in logs if not any("ctrl_dll" in str(f).lower() for f in (x.get("stack") or [])[:1])]
            if unres: bad.append(f"frames_not_in_ctrl_dll={len(unres)} e.g. {(unres[0].get('stack') or [])[:2]}")
            # CtrlDllRecurse(12) returns CtrlDllLeaf(0) = 0 through every level: sum 0.
            if res.get("sum") != 0 or res.get("cycles") != C or res.get("n") != n:
                bad.append(f"target sum={res.get('sum')} want 0 cycles={res.get('cycles')} n={res.get('n')}")
            leafs = sum(x.get("hits", 0) for x in rows)
            if leafs != C * n: bad.append(f"hits={leafs} want {C * n}")
            record(name, not bad, " ".join(bad) or f"{len(logs)} stack logs, frame 0 in ctrl_dll for all")
        except Exception as e:
            record(name, False, repr(e))

    # Finding 7: the target's own debug registers keep working.
    N = 50
    for bk in ("breakpoint", "hw", "inline"):
        name = f"ctrl-owndr-{bk}"
        try:
            r, o, res, logs, rows = go("owndr", bk, ["--n", N])
            bad = common(r, o)
            if res.get("w1_slot", -1) < 0: bad.append(f"w1_slot={res.get('w1_slot')}")
            if res.get("w1") != N: bad.append(f"own_watch_w1={res.get('w1')} (slot {res.get('w1_slot')})")
            w2 = res.get("w2") or []
            slots_bad = own_watch_slots_bad(w2, N, bk)
            if slots_bad: bad.append("w2 " + slots_bad)
            fails = [str(x.get("message")) for x in logs if "FAIL" in str(x.get("message", ""))]
            if fails: bad.append(f"callback_fail={fails[:2]}")
            tock = [x for x in rows if str(x.get("location", "")).startswith("0x")]
            if len(tock) != 1 or tock[0].get("hits") != 1: bad.append(f"tock_rows={tock}")
            record(name, not bad, " ".join(bad) or f"w1(slot {res.get('w1_slot')})={res.get('w1')} w2={w2}")
        except Exception as e:
            record(name, False, repr(e))

    # Finding 8: corrupt log_head from the target must not hang drain_final.
    try:
        t0 = time.time()
        r, o, res, logs, rows = go("headcorrupt", "inline", [], timeout=60)
        bad = []
        if res.get("mapped") != 1: bad.append(f"mapped={res.get('mapped')}")
        if not report(o): bad.append("no report")
        record("ctrl-headclamp", not bad, " ".join(bad) or f"controller finished in {time.time() - t0:.1f}s")
    except subprocess.TimeoutExpired:
        record("ctrl-headclamp", False, "controller hung (timeout 60s) after the target corrupted log_head")
    except Exception as e:
        record("ctrl-headclamp", False, repr(e))

def check_cdx_review():
    """Codex review of the controller (docs/ROADMAP.md "Codex controller review"), fixture
    examples/ctrlreview, ONE callback source per check, every backend:
      cdx-owndrx-<b>: UHH watches an address once (PROBE_ONCE) and releases it; a thread that
        existed at the release then arms its OWN write watch there in every free slot: its
        handler must see every write (the released address was swallowed as stale for good).
      cdx-faultreg-<b>: the probed load faults; the program's handler repairs it by changing the
        base REGISTER and retries at the site: one callback per execution (x86 took the
        changed registers for a new hit).
      cdx-absreuse-<b>: an absolute software breakpoint in a DLL that unloads; the address is
        reused by new memory holding a real 0xCC: get_mem must read 0xCC (the agent's INT3
        table kept the stale entry and showed the old original byte inline).
      cdx-int3cap-<b>: 1200 armed software breakpoints, all read back with ONE get_mem: the
        program's bytes on every backend, no 0xCC (inline saw 0xCC past the 1024th, and one
        inline read masked at most 64).
      cdx-bigcfg-<b>: a dynamic add from a callback with a config over 64 MiB: accepted on every
        backend (inline refused it)."""
    d, t, dll = exe("ctrl_driver.exe"), exe("ctrl_target.exe"), exe("ctrl_dll.dll")
    if not d or not t or not dll:
        return missing_bin("cdx-review", "ctrl_driver/ctrl_target/ctrl_dll")

    def go(sc, bk, targs, timeout=180):
        r, o = run([d, "--scenario", sc, "--backend", bk, "--", t, sc, *targs], timeout=timeout)
        res = next((x for x in o if x.get("kind") == "ctrl_result"), {})
        logs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
        rows = [x for x in o if x.get("kind") == "probe"]
        bad = []
        if r.returncode != 0: bad.append(f"exit={r.returncode}")
        rep = report(o)
        if rep.get("error") is not None: bad.append(f"error={rep.get('error')}")
        if rep.get("log_dropped", 0) != 0: bad.append(f"log_dropped={rep.get('log_dropped')}")
        if rep.get("app_exit") != 0: bad.append(f"app_exit={rep.get('app_exit')}")
        if not res: bad.append("no ctrl_result")
        fails = [m for m in logs if "FAIL" in m]
        if fails: bad.append(f"callback_fail={fails[:2]}")
        return res, logs, rows, bad

    for bk in ("breakpoint", "hw", "inline"):
        name = f"cdx-owndrx-{bk}"
        try:
            N = 50
            res, logs, rows, bad = go("owndrx", bk, ["--n", N])
            w = res.get("w") or []
            slots_bad = own_watch_slots_bad(w, N, bk)
            if slots_bad: bad.append(slots_bad)
            if not any(m.startswith("ok wonce=1") for m in logs): bad.append(f"no one-shot watch: {logs[:2]}")
            record(name, not bad, " ".join(bad) or f"own watch per slot={w}")
        except Exception as e:
            record(name, False, repr(e))

    for bk in ("breakpoint", "hw", "inline"):
        name = f"cdx-faultreg-{bk}"
        try:
            N = 200
            res, logs, rows, bad = go("faultreg", bk, ["--n", N])
            hits = sum(x.get("hits", 0) for x in rows)
            if hits != N: bad.append(f"hits={hits}")
            if len(logs) != N: bad.append(f"logs={len(logs)}")
            if res.get("fix") != N: bad.append(f"veh_fixes={res.get('fix')} (want {N})")
            # The program's own result: every repaired load reads g_good (42), n loads.
            if res.get("sum") != N * 42 or res.get("n") != N:
                bad.append(f"target sum={res.get('sum')} n={res.get('n')} (want {N * 42}, {N})")
            if res.get("tf") != 0: bad.append(f"tf_in_handler={res.get('tf')}")   # never UHH's trap flag
            if res.get("stray") != 0: bad.append(f"stray_single_steps={res.get('stray')}")
            record(name, not bad, " ".join(bad) or f"hits={hits} logs={len(logs)} fixes={res.get('fix')}")
        except Exception as e:
            record(name, False, repr(e))

    for bk in ("breakpoint", "hw", "inline"):
        name = f"cdx-absreuse-{bk}"
        try:
            res, logs, rows, bad = go("absreuse", bk, [])
            if res.get("reused") != 1: bad.append(f"reused={res.get('reused')} (address not free after unload)")
            if "op arm ok=1/1" not in logs: bad.append(f"arm={[m for m in logs if 'arm' in m]}")
            peek = [m for m in logs if m.startswith("op peek")]
            if peek != ["op peek r=1 cc=16 n=16 first=cc"]: bad.append(f"peek={peek} (want 16 x 0xCC)")
            record(name, not bad, " ".join(bad) or peek[0])
        except Exception as e:
            record(name, False, repr(e))

    for bk in ("breakpoint", "hw", "inline"):
        name = f"cdx-int3cap-{bk}"
        try:
            n = 1200
            res, logs, rows, bad = go("int3cap", bk, ["--n", n], timeout=300)
            if f"op arm ok={n}/{n}" not in logs: bad.append(f"arm={[m for m in logs if 'arm' in m]}")
            peek = [m for m in logs if m.startswith("op peek")]
            if peek != [f"op peek r=1 cc=0 n={n} first=90"]: bad.append(f"peek={peek} (want no 0xCC in all {n})")
            record(name, not bad, " ".join(bad) or f"{n} breakpoints, {peek[0]}")
        except Exception as e:
            record(name, False, repr(e))

    for bk in ("breakpoint", "hw", "inline"):
        name = f"cdx-bigcfg-{bk}"
        try:
            res, logs, rows, bad = go("bigcfg", bk, [])
            if "ok bigcfg add=1" not in logs: bad.append(f"add={[m for m in logs if 'bigcfg' in m]}")
            if logs.count("tock") != 1: bad.append(f"tock_logs={logs.count('tock')} (want 1)")
            record(name, not bad, " ".join(bad) or "64 MiB + 4 KiB config accepted, new probe fired once")
        except Exception as e:
            record(name, False, repr(e))

# ---- logs-*: adversarial log delivery (examples/logs_eval) --------------------------------
# Gospel: logs are never dropped and always delivered; hits == logs + log_dropped +
# callbacks_interrupted, and log_dropped != 0 only when the controller itself is gone.

def logs_run(a, b, targs, timeout=300):
    """logs_driver on logs_target. stdout is parsed as STRICT UTF-8 JSON: a line that is not
    valid JSON / UTF-8 is itself a failure (returned in bad)."""
    r = subprocess.run([str(exe("logs_driver.exe")), "--a", a, "--b", b, "--", str(exe("logs_target.exe"))] +
                       [str(x) for x in targs], capture_output=True, timeout=timeout)
    objs, bad = [], []
    for ln in r.stdout.split(b"\n"):
        ln = ln.strip()
        if not ln.startswith(b"{"):
            continue
        try:
            objs.append(json.loads(ln.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            bad.append(ln[:120])
    return r, objs, bad


def logs_expected_formats():
    mark = "...[truncated]"
    cut = lambda text: text[:1023 - len(mark)] + mark       # 1024-byte record: 1023 chars + NUL
    return [
        "x" * 1023,                                          # exactly the cap: whole
        cut("x" * 1024),                                     # one over: marked, never silent
        "[unformattable] k2 %n",
        "k3 k",                                              # the CRT prints an unknown conversion's letter
        cut("k4 " + " " * 4999 + "7"),
        "k5 a\x00b",                                         # embedded NUL kept (escaped)
        "k6 t\tr\rx\x01e\x1bf\x7f",                          # control characters kept (escaped)
        "k7 é→\U0001F600",                         # valid UTF-8 passes through
        "k8 ÿþ ok Ã",                         # invalid UTF-8 bytes -> \u00XX
        "k9 (null)",
        cut("[unformattable] " + "y" * 1100 + " %n"),        # long AND invalid: still marked
        "k11 \"quoted\" back\\slash /",
        "",
        cut("k13 " + "x" * 1100),
        "k14 w\u00e9",                                       # %ls of L"w\u00e9": the same two characters
        "k15 abc|5   |+2.50|0xff|%",
    ]


def check_logs_format():
    """Every send_log text arrives exactly, identically on every backend: maximum size kept
    whole, one byte over truncated WITH a visible marker (also for an unformattable long
    format), %n / unknown conversions logged as [unformattable], embedded NULs, control
    characters and invalid UTF-8 escaped (nothing silently removed), valid UTF-8 untouched,
    every line strict UTF-8 JSON, a stack snapshot on a truncated send_log_stack."""
    if not exe("logs_driver.exe") or not exe("logs_target.exe"):
        return missing_bin("logs-format", "logs_driver/logs_target")
    want = logs_expected_formats()
    seen = {}
    for bk in ("inline", "hw", "breakpoint"):
        name = f"logs-format-{bk}"
        try:
            r, o, bad = logs_run(bk, "none", ["--mode", "format", "--cases", len(want)])
            logs = [x for x in o if x.get("kind") == "probe_log"]
            msgs = [x.get("message") for x in logs]
            seen[bk] = msgs
            wrong = [f"k{i}: got {msgs[i]!r:.80} want {w!r:.80}" for i, w in enumerate(want)
                     if w is not None and i < len(msgs) and msgs[i] != w]
            stack13 = len(logs) > 13 and bool(logs[13].get("stack"))
            rep = report(o)
            ok = (r.returncode == 0 and not bad and len(msgs) == len(want) and not wrong and stack13 and
                  rep.get("log_dropped") == 0)
            record(name, ok, f"logs={len(msgs)}/{len(want)} bad_json_lines={len(bad)} wrong={len(wrong)} "
                             f"stack_on_truncated={stack13} dropped={rep.get('log_dropped')}" +
                             ("" if ok else f" first_wrong={wrong[:2]} bad={bad[:1]}"))
        except Exception as e:
            record(name, False, repr(e))
    try:
        same = len(seen) == 3 and seen["inline"] == seen["hw"] == seen["breakpoint"]
        record("logs-format-same-everywhere", same,
               "identical text on inline/hw/breakpoint" if same else
               f"differ: {[(i, a, b) for i, (a, b) in enumerate(zip(seen.get('inline', []), seen.get('breakpoint', []))) if a != b][:2]}")
    except Exception as e:
        record("logs-format-same-everywhere", False, repr(e))


def check_logs_order(threads=4, count=2000):
    """Per-thread order across MIXED backends: each thread alternates an inline-probed call
    and a breakpoint/hw-probed call (seq 0,1,2,...; the second logs with a stack). Inline
    logs cross the shared ring, breakpoint/hw logs are queued by the debugger -- every
    thread's records must still arrive in its own order, all of them, nothing dropped: each
    thread's sequence is EXACTLY 0, 1, ..., 2*count-1, no other record, and the report accounts
    for every call (hits == logs_written == delivered, nothing dropped or interrupted)."""
    if not exe("logs_driver.exe") or not exe("logs_target.exe"):
        return missing_bin("logs-order", "logs_driver/logs_target")
    want_seq = list(range(2 * count))
    for a, b in (("inline", "breakpoint"), ("inline", "hw")):
        name = f"logs-order-{a}+{b}"
        try:
            r, o, bad = logs_run(a, b, ["--mode", "order", "--threads", threads, "--count", count], timeout=600)
            by, nostack, foreign, delivered = {}, 0, [], 0
            for x in o:
                if x.get("kind") != "probe_log":
                    continue
                delivered += 1
                m = re.fullmatch(r"o (\d+)", str(x.get("message", "")))
                if not m or not isinstance(x.get("tid"), int):
                    foreign.append(f"{x.get('tid')}:{str(x.get('message', ''))[:60]!r}")
                    continue
                v = int(m.group(1))
                by.setdefault(x.get("tid"), []).append(v)
                nostack += bool(v % 2) and not x.get("stack")
            wrong = {tid: seq for tid, seq in by.items() if seq != want_seq}
            first_wrong = ""
            for tid, seq in list(wrong.items())[:1]:
                i = next((j for j, (p, q) in enumerate(zip(seq, want_seq)) if p != q), min(len(seq), len(want_seq)))
                first_wrong = f" tid {tid}: len={len(seq)} first diff @{i}: got {seq[i:i + 3]} want {want_seq[i:i + 3]}"
            total = sum(map(len, by.values()))
            calls = 2 * threads * count
            rep = report(o)
            acct = {k: rep.get(k) for k in ("hits", "logs_written", "log_dropped", "callbacks_interrupted", "app_exit", "error")}
            acct_ok = (rep.get("hits") == calls and rep.get("logs_written") == calls == delivered and
                       rep.get("log_dropped") == 0 and rep.get("callbacks_interrupted") == 0 and
                       rep.get("app_exit") == 0 and rep.get("error") is None)
            ok = (r.returncode == 0 and not bad and len(by) == threads and total == calls and not wrong and
                  not foreign and nostack == 0 and acct_ok)
            record(name, ok, f"threads={len(by)}/{threads} logs={total}/{calls} wrong_seq_threads={len(wrong)} "
                             f"foreign={len(foreign)} stack_missing={nostack} report={acct}"
                             + (first_wrong if wrong else "") + (f" foreign_e.g.={foreign[:2]}" if foreign else "")
                             + (f" bad_json={bad[:1]}" if bad else ""))
        except Exception as e:
            record(name, False, repr(e))


def check_logs_wedge(threads=4, count=3000):
    """A producer stopped BETWEEN claiming a ring slot and publishing it (the target finds that
    instant through the shared ring and freezes the thread there):
      kill:    TerminateThread there. Its slot can never be published.
      suspend: the program's own SuspendThread, held while the other threads log.
      exit:    ExitProcess kills it there, and the exiting thread then logs more records than
               the ring holds from a TLS callback at DLL_PROCESS_DETACH (the hang case: every
               later log used to wait behind the dead slot forever).
    The others' logs must keep flowing live (no stalls, all delivered while the target runs),
    nothing may be dropped, and the killed callback is accounted as interrupted:
    hits == logs + callbacks_interrupted exactly."""
    if not exe("logs_driver.exe") or not exe("logs_target.exe"):
        return missing_bin("logs-wedge", "logs_driver/logs_target")
    for mode in ("kill", "suspend", "exit"):
        name = f"logs-wedge-{mode}"
        try:
            n = 6000 if mode == "exit" else count
            r, o, bad = logs_run("inline", "none", ["--mode", f"wedge-{mode}", "--threads", threads, "--count", n],
                                 timeout=180)
            a, rep = app(o), report(o)
            hits = next(iter(probes(o)), {}).get("hits")
            logs = sum(1 for x in o if x.get("kind") == "probe_log" and str(x.get("message", "")).startswith("o "))
            interrupted = rep.get("callbacks_interrupted")
            if mode == "exit":
                live_ok = rep.get("app_exit") == 7
                detail = f"exit={rep.get('app_exit')}"
            else:
                live_ok = (r.returncode == 0 and a.get("phase2_calls") == threads * count and
                           (a.get("phase2_ms") or 1e9) < 10000 and a.get("undelivered_after_phase2") == 0)
                detail = (f"phase2={a.get('phase2_calls')}/{threads * count} in {a.get('phase2_ms')}ms "
                          f"undelivered_live={a.get('undelivered_after_phase2')}")
            ok = (live_ok and a.get("wedged") == 1 and rep.get("log_dropped") == 0 and
                  interrupted == (0 if mode == "suspend" else 1) and hits is not None and hits == logs + interrupted)
            record(name, ok, f"wedged={a.get('wedged')} {detail} hits={hits} logs={logs} interrupted={interrupted} "
                             f"dropped={rep.get('log_dropped')} rc={r.returncode}")
        except subprocess.TimeoutExpired:
            record(name, False, "session HUNG (180 s): logging stalled behind the unpublished slot")
        except Exception as e:
            record(name, False, repr(e))


def check_logs_controller_killed(threads=4, count=20000):
    """The CONTROLLER dies while attached (inline hooks stay in the target, nobody drains the
    ring): the target must run to completion -- its log calls notice the controller is gone
    and return instead of waiting forever on a full ring -- and every call stays ACCOUNTED for
    in the shared ring (read by the target itself, the only survivor): hits == records put in
    the ring + log_dropped, nothing consumed after the death, nothing in flight, and the
    records the full ring could not take are counted as dropped (the one case where dropping
    is allowed). Order: attach -> target maps the ring -> controller killed -> calls."""
    t, tr = exe("logs_target.exe"), exe("uhh_trace.exe")
    if not t or not tr:
        return missing_bin("logs-controller-killed", "logs_target/uhh_trace")
    name = "logs-controller-killed"
    tg = trc = None
    cap = 4096                                                # PROBE_AGENT_LOG_CAP (probe_agent_shared.hpp)
    try:
        tg = subprocess.Popen([str(t), "--mode", "gate", "--threads", str(threads), "--count", str(count)],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        tout = Lines(tg.stdout)
        first = tout.wait_for(lambda l: '"waiting"' in l, 60)
        if not first:
            raise RuntimeError("target never printed waiting")
        pid = json.loads(first)["pid"]
        trc = subprocess.Popen([str(tr), "--backend", "inline", "--attach", str(pid), "-p", "logs_target.exe!LogSiteA:dd"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        terr = Lines(trc.stderr)
        if not terr.wait_for(lambda l: l.startswith("probe: active "), 60):
            raise RuntimeError("probe never became active: " + " | ".join(terr.lines[-5:])[:400])
        tg.stdin.write("\n"); tg.stdin.flush()
        mapped = tout.wait_for(lambda l: '"mapped"' in l, 30)
        trc.kill(); trc.wait(timeout=30)
        tg.stdin.write("\n"); tg.stdin.flush()
        try:
            tg.wait(timeout=90)
        except subprocess.TimeoutExpired:
            return record(name, False, "target HUNG after the controller was killed (90 s): its log calls wait forever")
        a = next((o for o in tout.objs() if o.get("kind") == "app"), {})
        calls = threads * count
        d = lambda k: (a.get(k + "1") or 0) - (a.get(k + "0") or 0)
        bad = []
        if tg.returncode != 0 or a.get("calls") != calls: bad.append(f"rc={tg.returncode} calls={a.get('calls')}/{calls}")
        if not mapped or a.get("mapped") != 1: bad.append(f"ring not mapped ({mapped})")
        if d("hits") != calls: bad.append(f"hits={d('hits')} want {calls}")
        if d("head") + d("dropped") != calls: bad.append(f"ring={d('head')} + dropped={d('dropped')} != calls {calls}")
        if d("tail") != 0: bad.append(f"consumed after the controller died: {d('tail')}")
        if a.get("inflight1") != 0: bad.append(f"in_flight={a.get('inflight1')}")
        if (a.get("head1") or 0) - (a.get("tail1") or 0) > cap: bad.append("ring holds more than its capacity")
        if d("dropped") < calls - cap: bad.append(f"dropped={d('dropped')} < {calls - cap}: the full ring's overflow is unaccounted")
        record(name, not bad, " ".join(bad) or
               f"target finished in {a.get('ms')}ms calls={calls} hits={d('hits')} ring={d('head')} dropped={d('dropped')}")
    except Exception as e:
        record(name, False, repr(e))
    finally:
        for p_ in (tg, trc):
            if p_ and p_.poll() is None:
                p_.kill()


def check_logs_stdout_closed(threads=4):
    """The reader of the controller's stdout goes away (`| head`): live output ends, but the
    session's JSONL file -- the complete record -- must still receive EVERY log, exactly:
    every line strict UTF-8 JSON, each of the T threads' records "o 0", "o 2", ... in order
    with no gap or duplicate, the controller exits 0, and the final accounting (written by
    logs_driver --report to a file, a side channel that survives the closed stdout) says
    hits == logs_written == T * count, nothing dropped or interrupted, no error. A reader
    going away is not a session error (TH2): the report says "live_output_closed":true and
    stderr carries the warning, never a "probe: error:" line."""
    if not exe("logs_driver.exe") or not exe("logs_target.exe"):
        return missing_bin("logs-stdout-closed", "logs_driver/logs_target")
    for bk, count in (("inline", 5000), ("hw", 500)):
        name = f"logs-stdout-closed-{bk}"
        rep_path = Path(tempfile.gettempdir()) / f"uhh-logs-report-{os.getpid()}-{bk}.jsonl"
        try:
            rep_path.unlink(missing_ok=True)
            p = subprocess.Popen([str(exe("logs_driver.exe")), "--a", bk, "--b", "none", "--report", str(rep_path),
                                  "--", str(exe("logs_target.exe")),
                                  "--mode", "order", "--threads", str(threads), "--count", str(count)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for _ in range(5):
                p.stdout.readline()
            p.stdout.close()                                  # the reader is gone
            err = p.stderr.read().decode(errors="replace")
            p.wait(timeout=300)
            m = re.search(r"probe: logs -> (.*)", err)
            bad, by, nlogs = [], {}, 0
            if not m:
                bad.append("no log file announced")
            else:
                path = Path(m.group(1).strip())
                with open(path, "rb") as f:
                    for ln in f:
                        ln = ln.strip()
                        if not ln:
                            continue
                        try:
                            o = json.loads(ln.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            bad.append(f"bad line {ln[:60]!r}")
                            continue
                        if o.get("kind") != "probe_log":
                            continue
                        nlogs += 1
                        mm = re.fullmatch(r"o (\d+)", str(o.get("message", "")))
                        if not mm:
                            bad.append(f"foreign log {str(o.get('message'))[:60]!r}")
                            continue
                        by.setdefault(o.get("tid"), []).append(int(mm.group(1)))
                try:
                    path.unlink()
                except OSError:
                    pass
            want_seq = [2 * i for i in range(count)]          # LogSiteA only: probe B is not set
            wrong_threads = [tid for tid, seq in by.items() if seq != want_seq]
            if len(by) != threads or wrong_threads:
                bad.append(f"threads={len(by)}/{threads} wrong_sequence_threads={len(wrong_threads)}")
            rep = {}
            try:
                rep = next((json.loads(l) for l in rep_path.read_text().splitlines()
                            if '"kind":"probe_report"' in l), {})
            except OSError as e:
                bad.append(f"no report file ({e})")
            want_n = threads * count
            if (rep.get("hits") != want_n or rep.get("logs_written") != want_n or rep.get("log_dropped") != 0 or
                    rep.get("callbacks_interrupted") != 0 or rep.get("error") is not None or rep.get("app_exit") != 0):
                bad.append(f"report={ {k: rep.get(k) for k in ('hits', 'logs_written', 'log_dropped', 'callbacks_interrupted', 'app_exit', 'error')} }")
            if p.returncode != 0: bad.append(f"rc={p.returncode}")
            if rep.get("live_output_closed") is not True:
                bad.append(f"live_output_closed={rep.get('live_output_closed')!r} want True")
            if "probe: warning: live output closed" not in err: bad.append("no live-output-closed warning on stderr")
            if "probe: error:" in err: bad.append("a probe: error: line on stderr")
            if nlogs != want_n: bad.append(f"file_logs={nlogs}/{want_n}")
            record(name, not bad, f"file_logs={nlogs}/{want_n} threads={len(by)} rc={p.returncode}" +
                   ("" if not bad else f" bad={bad[:4]} stderr=" + " | ".join(err.strip().splitlines()[-3:])[:300]))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            try:
                rep_path.unlink(missing_ok=True)
            except OSError:
                pass


def check_agent_review():
    """Inline-agent static review (examples/agent_review), one reproduction per finding:
    agent-unwind: a C++ throw / SEH raise / AV from a callee whose CALL instruction is inline-
    probed (the hook relocates that call), caught by the hooked function and by its caller,
    and a load relocated by the hook faulting inside the hooked function's own __try -- the
    program's handlers get every one (x64: no unwind data for the trampoline used to end in
    std::terminate / an unhandled exception). agent-faultafter: a callback that ran the
    original and then faults must not run the original again. agent-threadinit: an
    allocating callback on RtlAllocateHeap while threads start (hits before the thread's TLS
    exists) must not recurse. agent-ljframe0: x64 longjmp without unwinding out of
    call_original must not leave the thread "in a callback" (later hits silently lost).
    agent-own-threads: the agent's own hook writes (NtProtectVirtualMemory, run while every
    other thread is frozen) must not run the program's callback. Every row equals the
    uninstrumented run; hits and "ar" logs are exact; nothing dropped or interrupted."""
    d, t = exe("ar_driver.exe"), exe("ar_target.exe")
    if not d or not t:
        return missing_bin("agent-review", "ar_driver/ar_target")

    def row(objs, kind="ar"):
        r = dict(next((x for x in objs if x.get("kind") == kind), {}))
        r.pop("kind", None)
        return r

    def ar_logs(objs):
        cnt = {}
        for x in objs:
            m = str(x.get("message", ""))
            if x.get("kind") == "probe_log" and m.startswith("ar "):
                cnt[m] = cnt.get(m, 0) + 1
        return cnt

    def go(case, specs, timeout=180):
        args = [d]
        for sp in specs:
            args += ["--probe", sp]
        return run(args + ["--", t, case], timeout=timeout)

    def common(r, o, base, extra_ok=()):
        rep, bad = report(o), []
        if not base:
            bad.append("no baseline row")
        if row(o) != base:
            bad.append(f"row={row(o)} want={base}")
        if rep.get("log_dropped") != 0: bad.append(f"dropped={rep.get('log_dropped')}")
        if rep.get("callbacks_interrupted", 0) != 0: bad.append(f"intr={rep.get('callbacks_interrupted')}")
        if rep.get("error") is not None: bad.append(f"err={rep.get('error')}")
        if rep.get("app_exit") != 0 or r.returncode != 0: bad.append(f"app_exit={rep.get('app_exit')} rc={r.returncode}")
        return bad

    # agent-unwind
    try:
        _, wo = run([t, "where"], timeout=60)
        w = row(wo, "where")
        _, bo = run([t, "unwind"], timeout=60)
        base = row(bo)
        specs = []
        for key in ("mid_cpp", "mid_seh", "self_cpp", "self_seh"):
            specs.append(f"ar_target.exe!ar_{key}+0x{w.get(key, -1):x}=ar_on_site")
        lo = w.get("load", -1)
        specs.append(("ar_target.exe!ar_load_self" + (f"+0x{lo:x}" if lo >= 5 else "")) + "=ar_on_site")
        if any(w.get(k, -1) < 0 for k in ("mid_cpp", "mid_seh", "self_cpp", "self_seh", "load")):
            record("agent-unwind", False, f"site scan failed: {w}")
        else:
            r, o = go("unwind", specs)
            bad = common(r, o, base)
            hits = [p.get("hits") for p in probes(o)]
            if hits != [10] * 5: bad.append(f"hits={hits}")
            if ar_logs(o) != {"ar site": 50}: bad.append(f"logs={ar_logs(o)}")
            record("agent-unwind", not bad, "; ".join(bad) or f"row={row(o)} sites={w}")
    except Exception as e:
        record("agent-unwind", False, repr(e))

    # agent-faultafter
    try:
        _, bo = run([t, "faultafter"], timeout=60)
        base = row(bo)
        r, o = go("faultafter", ["ar_target.exe!ar_body=ar_on_fault_ret", "ar_target.exe!ar_body_std=ar_on_fault_noret"])
        bad = common(r, o, base)
        if ar_logs(o) != {"ar fault-ret": 5, "ar fault-noret": 5}: bad.append(f"logs={ar_logs(o)}")
        record("agent-faultafter", not bad, "; ".join(bad) or f"row={row(o)}")
    except Exception as e:
        record("agent-faultafter", False, repr(e))

    # agent-threadinit
    try:
        _, bo = run([t, "threadinit"], timeout=60)
        base = row(bo)
        r, o = go("threadinit", ["ntdll.dll!RtlAllocateHeap=ar_on_alloc"], timeout=300)
        bad = common(r, o, base)
        hits = sum(p.get("hits") or 0 for p in probes(o))
        if hits < 40: bad.append(f"hits={hits}")
        record("agent-threadinit", not bad, "; ".join(bad) or f"row={row(o)} hits={hits}")
    except Exception as e:
        record("agent-threadinit", False, repr(e))

    # agent-ljframe0
    try:
        _, bo = run([t, "ljframe0"], timeout=60)
        base = row(bo)
        r, o = go("ljframe0", ["ar_target.exe!ar_jump=ar_on_jump", "ar_target.exe!ar_after=ar_on_after"])
        bad = common(r, o, base)
        want = {"ar jump": 10, "ar jump-done": 5, "ar after": 3}
        if ar_logs(o) != want: bad.append(f"logs={ar_logs(o)} want={want}")
        record("agent-ljframe0", not bad, "; ".join(bad) or f"row={row(o)}")
    except Exception as e:
        record("agent-ljframe0", False, repr(e))

    # agent-own-threads
    try:
        _, bo = run([t, "prot"], timeout=60)
        base = row(bo)
        r, o = go("prot", ["ntdll.dll!NtProtectVirtualMemory=ar_on_prot"])
        bad = common(r, o, base)
        # The agent's own code (hook writes: VirtualProtect, run FROZEN) must never run the
        # callback. The loader's own start/exit of the injected init thread (ntdll calling
        # itself, outside the agent's code and outside any freeze) is reported, not failed.
        lg = ar_logs(o)
        agent = lg.get("ar prot agent=1 via=other", 0)
        loader = lg.get("ar prot agent=1 via=ntdll", 0)
        prog = lg.get("ar prot agent=0 via=other", 0) + lg.get("ar prot agent=0 via=ntdll", 0)
        if agent: bad.append(f"{agent} callback(s) ran in the agent's own code (logs={lg})")
        if prog < 5: bad.append(f"program calls seen={prog} (want >= 5)")
        record("agent-own-threads", not bad,
               "; ".join(bad) or f"row={row(o)} program={prog} agent={agent} agent-thread-loader={loader}")
    except Exception as e:
        record("agent-own-threads", False, repr(e))


def check_callfunc_registry():
    """Inline call_func's recursion guard (a probe its callee hits is counted, no callback).
    callfunc-kill-reuse: a thread is killed (TerminateThread) while its callback is inside
    call_func; short threads then run until one gets the dead thread's id. Every hit of every
    later thread -- the reused id included -- runs its callback and logs; the killed hit is
    accounted as interrupted: hits == logs + interrupted, nothing dropped. (The guard used to
    be a thread-id table that a killed thread never left: the reused id's callbacks were
    skipped silently, and its stale record was settled, losing the interrupted count.)
    callfunc-many: 100 threads inside call_func at once, the callee hitting another probe:
    no callback re-enters (that table had 64 entries), every call returns its value, exact
    hits and logs."""
    d, t = exe("ar_driver.exe"), exe("ar_target.exe")
    if not d or not t:
        return missing_bin("callfunc-registry", "ar_driver/ar_target")

    def go(case, specs, timeout=180):
        args = [d]
        for sp in specs:
            args += ["--probe", sp]
        return run(args + ["--", t, case], timeout=timeout)

    def logs(o):
        cnt = {}
        for x in o:
            m = str(x.get("message", ""))
            if x.get("kind") == "probe_log" and m.startswith(("ar ", "uhh warning")):
                cnt[m] = cnt.get(m, 0) + 1
        return cnt

    def hits_of(o, sym):
        return next((p.get("hits") for p in probes(o) if sym in str(p.get("location", ""))), None)

    def row(o):
        return next((x for x in o if x.get("kind") == "ar"), {})

    try:
        r, o = go("cfkill", ["ar_target.exe!ar_cf_site=ar_on_cf"])
        rw, rep, lg, bad = row(o), report(o), logs(o), []
        hits, calls = hits_of(o, "ar_cf_site"), rw.get("calls", -1)
        intr, logged = rep.get("callbacks_interrupted"), lg.get("ar cf", 0)
        if rw.get("killed") != 1: bad.append(f"victim not killed inside call_func: {rw}")
        if not rw.get("reused"): bad.append(f"no thread reused the dead id in {rw.get('threads')} threads")
        if hits != calls + 1: bad.append(f"hits={hits} want={calls + 1}")
        if logged != calls: bad.append(f"logged={logged} want={calls} (callbacks skipped)")
        if set(lg) - {"ar cf"}: bad.append(f"logs={lg}")
        if intr != 1: bad.append(f"interrupted={intr} want=1")
        if hits is None or intr is None or hits != logged + intr: bad.append(f"hits != logs + interrupted")
        if rep.get("log_dropped") != 0: bad.append(f"dropped={rep.get('log_dropped')}")
        if rep.get("app_exit") != 0 or r.returncode != 0: bad.append(f"app_exit={rep.get('app_exit')} rc={r.returncode}")
        record("callfunc-kill-reuse", not bad, "; ".join(bad) or
               f"threads={rw.get('threads')} reused={rw.get('reused')} hits={hits} logs={logged} interrupted={intr}")
    except Exception as e:
        record("callfunc-kill-reuse", False, repr(e))

    try:
        n = 100
        r, o = go("cfmany", ["ar_target.exe!ar_cf_site=ar_on_cf", "ar_target.exe!ar_cf_inner=ar_on_cf_inner"])
        rw, rep, lg, bad = row(o), report(o), logs(o), []
        hs, hi = hits_of(o, "ar_cf_site"), hits_of(o, "ar_cf_inner")
        if rw.get("sum") != sum(range(1000, 1000 + n)): bad.append(f"row={rw}")
        if rw.get("together") != n: bad.append(f"only {rw.get('together')}/{n} threads were inside call_func together")
        if hs != n or hi != n: bad.append(f"hits site={hs} inner={hi} want={n}")
        if lg != {"ar cf-many ok=1 good=1": n}: bad.append(f"logs={lg}")
        if rep.get("log_dropped") != 0: bad.append(f"dropped={rep.get('log_dropped')}")
        if rep.get("callbacks_interrupted", 0) != 0: bad.append(f"intr={rep.get('callbacks_interrupted')}")
        if rep.get("app_exit") != 0 or r.returncode != 0: bad.append(f"app_exit={rep.get('app_exit')} rc={r.returncode}")
        record("callfunc-many", not bad, "; ".join(bad) or f"row={rw} hits={hs}/{hi} logs={lg}")
    except Exception as e:
        record("callfunc-many", False, repr(e))


# ---- lifecycle (examples/lifecycle) -------------------------------------------------------
# One probe per gated_config role on the ntdll stubs + the mid-function flag site + a probe
# that blocks inside call_original, under each backend and mixed.
LC_CONFIGS = {
    "breakpoint": dict(open="breakpoint", close="breakpoint", read="breakpoint", flag="breakpoint", slow="breakpoint"),
    # hw: 3 debug registers; the 4th stays free for call_original's return catch
    "hw":         dict(open="hw", close="breakpoint", read="hw", flag="hw", slow="breakpoint"),
    "inline":     dict(open="inline", close="inline", read="inline", flag="inline", slow="inline"),
    "mixed":      dict(open="hw", close="breakpoint", read="inline", flag="breakpoint", slow="inline"),
}


def lc_selected(name):
    sel = os.environ.get("UHH_LC", "")
    return not sel or any(x in name for x in sel.split(","))


class LcTarget:
    """lifecycle_target with its stdin as a command channel and stdout collected."""

    def __init__(self, *args, pace=1):
        # Paced (1 ms sleep per iteration: ~64 iterations/s per thread at the default timer
        # resolution): a few thousand hits/s at most, so hw/breakpoint runs never load the VM.
        args = ("--pace-ms", pace) + tuple(args)
        self.p = subprocess.Popen([str(exe("lifecycle_target.exe")), *map(str, args)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.out = Lines(self.p.stdout)
        ready = self.out.wait_for(lambda l: '"kind":"ready"' in l, 30)
        if not ready:
            raise RuntimeError("lifecycle_target not ready")
        self.pid = json.loads(ready)["pid"]

    def _cmd(self, word, kind, timeout=60):
        n = sum(1 for l in self.out.lines if f'"kind":"{kind}"' in l)
        if self.p.poll() is not None:
            return {"dead": self.p.returncode, "unhandled": self.unhandled()}
        try:
            self.p.stdin.write(word + "\n"); self.p.stdin.flush()
        except OSError:
            return {"dead": self.p.poll(), "unhandled": self.unhandled()}
        deadline = time.time() + timeout
        while time.time() < deadline:
            got = [l for l in self.out.lines if f'"kind":"{kind}"' in l]
            if len(got) > n:
                return json.loads(got[n])
            if self.p.poll() is not None:
                return {"dead": self.p.returncode, "unhandled": self.unhandled()}
            time.sleep(0.05)
        return {"hung": True}

    def check(self):
        return self._cmd("check", "check")

    def reset(self):
        return self._cmd("reset", "reset")

    def quit(self):
        a = self._cmd("quit", "app", timeout=120)
        try:
            self.p.wait(timeout=60)
        except subprocess.TimeoutExpired:
            pass
        a["rc"] = self.p.poll()
        return a

    def unhandled(self):
        return [l for l in self.out.lines if '"unhandled' in l][:4]     # + "unhandled_where" lines

    def kill(self):
        if self.p.poll() is None:
            self.p.kill()


def lc_clean(c, attached_ok=False):
    """A check line that says the target is exactly as before any tool came."""
    # (late / stuck: the quit report -- worker threads that did not end, threads left suspended)
    return (not c.get("dead") and not c.get("hung") and c.get("code_diff") == 0 and c.get("dr_dirty") == 0 and
            c.get("dr_unknown") == 0 and
            c.get("errors") == 0 and not c.get("late") and not c.get("stuck") and (attached_ok or c.get("debugger") == 0))


def lc_brief(c):
    if c.get("dead") is not None or c.get("hung"):
        return f"DEAD/HUNG {c}"
    return (f"code_diff={c.get('code_diff')} {c.get('code_bad') or ''} dr_dirty={c.get('dr_dirty')} {c.get('dr_bad') or ''} "
            f"dr_unknown={c.get('dr_unknown')} {c.get('dr_unknown_info') or ''} "
            f"dr_stale={c.get('dr_stale')} dbg={c.get('debugger')} errors={c.get('errors')} {c.get('first_error') or ''} flips={c.get('flips')} "
            f"agent={c.get('agent_loaded')}" + (f" late={c.get('late')} stuck={c.get('stuck_info')} agent_thr={c.get('agent_thr')}" if c.get("late") or c.get("stuck") else "")
            + (f" susp={c.get('susp_info')}" if c.get("susp") else "")
            ).replace("  ", " ")


class LcDriver:
    """lifecycle_driver: stdout probe_log lines are only COUNTED (never kept)."""

    def __init__(self, pid, cfg, *extra, group=False):
        args = [str(exe("lifecycle_driver.exe")), str(pid)]
        for k in ("open", "close", "read", "flag", "slow", "work"):
            args += [f"--{k}", cfg.get(k, "none")]
        args += [str(x) for x in extra]
        self.probes = sum(1 for k in ("open", "close", "read", "flag", "slow", "work") if cfg.get(k, "none") != "none")
        self.p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if group else 0)
        self.logs, self.other, self.cv = 0, [], threading.Condition()
        self.t = threading.Thread(target=self._pump, daemon=True); self.t.start()
        self.err = Lines(self.p.stderr)

    def _pump(self):
        for line in self.p.stdout:
            with self.cv:
                if line.startswith('{"kind":"probe_log"'):
                    self.logs += 1
                else:
                    self.other.append(line.rstrip("\r\n"))
                self.cv.notify_all()

    def wait_attached(self, timeout=30):
        with self.cv:
            return self.cv.wait_for(lambda: any('"kind":"attached"' in l for l in self.other), timeout)

    def wait_active(self, n=None, timeout=60):
        n = self.probes if n is None else n
        return self.err.wait_for(lambda l: sum(1 for x in self.err.lines if x.startswith("probe: active ")) >= n, timeout) is not None

    def wait_logs(self, n, timeout=30):
        with self.cv:
            return self.cv.wait_for(lambda: self.logs >= n, timeout)

    def detach(self):
        self.p.stdin.write("\n"); self.p.stdin.flush()

    def finish(self, timeout=90):
        try:
            self.p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        self.t.join(timeout=30); self.err.t.join(timeout=30)
        return True

    def final(self):
        """(hits, logs_written, log_dropped) from probe_close's 'probe: detached:' line, or None."""
        m = next((re.search(r"probe: detached: hits=(\d+) logs_written=(\d+) log_dropped=(\d+)", l) for l in self.err.lines
                  if l.startswith("probe: detached:")), None)
        return tuple(int(x) for x in m.groups()) if m else None

    def accounting(self):
        """The session's final accounting {hits, logs_written, log_dropped, source}: probe_close's
        'probe: detached:' line (a detach) or the probe_report record (the session ended on its
        own -- the target exited/died -- or never attached). None if neither was printed."""
        f = self.final()
        if f is not None:
            return {"hits": f[0], "logs_written": f[1], "log_dropped": f[2], "source": "detached"}
        rep = report([json.loads(l) for l in self.other if l.startswith('{"kind":"probe_report"')])
        if rep:
            return {"hits": rep.get("hits"), "logs_written": rep.get("logs_written"), "log_dropped": rep.get("log_dropped"),
                    "source": "report"}
        return None

    def attached(self):
        return any('"kind":"attached"' in l for l in self.other)

    def errors(self):
        return [l[:160] for l in self.err.lines if "error" in l.lower() or "warning" in l.lower() or "failed" in l][:4]

    def kill(self):
        if self.p.poll() is None:
            self.p.kill()


def lc_logs_ok(d):
    """Every log the session wrote reached stdout, none was dropped."""
    f = d.final()
    return f is not None and f[1] == d.logs and f[2] == 0, f


def lc_reattach(cfgname, cfg, cycles=20):
    """attach -> detach -> re-attach, `cycles` times, to the same busy process (4 workers + a
    thread-churner: threads are born while attached). After EVERY detach: the code bytes of
    every probed site equal the pre-attach snapshot, no thread (incl. those created while
    attached) has a debug register or the trap flag set, no debugger, no flip after the detach,
    no program error; every log written reached stdout and none was dropped."""
    name = f"lifecycle-reattach-{cfgname}"
    tg, bad, logs_total = None, [], 0
    try:
        tg = LcTarget("--threads", 4, "--churn", "--slow-every", 50, "--slow-ms", 5)
        import random
        rnd = random.Random(1234)
        for k in range(cycles):
            d = LcDriver(tg.pid, cfg, "--detach-on-stdin")
            try:
                if not d.wait_attached() or not d.wait_active():
                    bad.append(f"c{k}: not active err={d.errors()}"); d.kill(); break
                time.sleep(rnd.uniform(0.05, 0.4))
                d.detach()
                if not d.finish():
                    bad.append(f"c{k}: driver did not finish detaching"); break
            finally:
                d.kill()
            ok_logs, fin = lc_logs_ok(d)
            logs_total += d.logs
            c = tg.check()
            tg.reset(); time.sleep(0.2); c2 = tg.check()
            if not ok_logs or not lc_clean(c) or c2.get("flips") != 0 or d.p.returncode != 0:
                bad.append(f"c{k}: rc={d.p.returncode} logs={d.logs} final={fin} {lc_brief(c)} flips_after={c2.get('flips')}")
                if c.get("dead") is not None or c.get("hung"):
                    break
        a = tg.quit()
        ok = not bad and lc_clean(a) and a.get("rc") == 0 and a.get("churned", 0) > 0
        record(name, ok, f"cycles={cycles} logs={logs_total} iterations={a.get('iterations')} churned={a.get('churned')} "
                         f"final_rc={a.get('rc')} {lc_brief(a)}" + ("" if ok else f" bad={bad[:3]}"))
    except Exception as e:
        record(name, False, repr(e) + f" bad={bad[:3]}")
    finally:
        if tg:
            tg.kill()


def lc_detach_cases(cfgname, cfg):
    """Detach at awkward moments, each on a fresh target, each followed by the cleanliness check:
       midcb   -- every read callback sleeps 300 ms and lc_slow blocks 1.5 s inside call_original
                  (breakpoint/hw: threads stopped at a hit / mid call; inline: in the callback and
                  inside the trampoline) when the detach comes;
       longcb  -- callbacks longer than the agent's in-flight wait (2.5 s);
       early-N -- probe_close N ms after the attach completed (agent load / install / FREEZE in
                  flight), with a module that keeps loading/unloading and a pending probe in it."""
    cases = [("midcb", ("--threads", 4, "--slow-every", 3, "--slow-ms", 1500), ("--read-sleep-ms", 300), 1.5, {}),
             ("longcb", ("--threads", 4, "--slow-every", 2, "--slow-ms", 2500), ("--read-sleep-ms", 2500), 1.0, {})]
    for ms in (0, 5, 30, 120):
        cases.append((f"early-{ms}", ("--threads", 4, "--dll", "--churn"), ("--detach-after-ms", ms), None,
                      {"work": "breakpoint" if cfg["read"] == "hw" else cfg["read"]}))   # hw: keep a DR free
    for case, targs, dargs, wait_s, more in cases:
        name = f"lifecycle-detach-{case}-{cfgname}"
        if not lc_selected(name):
            continue
        tg = d = None
        try:
            tg = LcTarget(*targs)
            dcfg = dict(cfg, **more)
            d = LcDriver(tg.pid, dcfg, *(dargs + (("--detach-on-stdin",) if wait_s is not None else ())))
            if wait_s is not None:
                if not d.wait_attached() or not d.wait_active():
                    raise RuntimeError(f"not active: {d.errors()}")
                time.sleep(wait_s)
                d.detach()
            t0 = time.time()
            fin_ok = d.finish(timeout=120)
            took = time.time() - t0
            ok_logs, fin = lc_logs_ok(d)
            c = tg.check()
            tg.reset(); time.sleep(0.3); c2 = tg.check()
            a = tg.quit()
            ok = fin_ok and d.p.returncode == 0 and ok_logs and lc_clean(c) and c2.get("flips") == 0 and lc_clean(a) and a.get("rc") == 0
            record(name, ok, f"detach_took={took:.1f}s logs={d.logs} final={fin} {lc_brief(c)} flips_after={c2.get('flips')} "
                             f"exit={a.get('rc')}" + ("" if ok else f" driver_rc={d.p.returncode} err={d.errors()} unhandled={tg.unhandled()} "
                                         f"stderr_tail={[l[:200] for l in d.err.lines if not l.startswith('probe: active') and 'detach-drain' not in l][-8:]}"))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            if d: d.kill()
            if tg: tg.kill()


def lc_target_dies(cfgname, cfg):
    """The target dies (TerminateProcess) N ms into the attach / agent injection / install, or
    right after a detach was requested: the controller must notice, end its session and exit on
    its own (no hang, no crash) with every log it wrote delivered and none dropped. A session
    that was established ("attached") must report its final accounting, logs_written == the
    probe_log records delivered on stdout, log_dropped == 0, driver exit 0; an attach that
    failed before the session existed must exit 1 with a report of zero logs."""
    bad, n, seen = [], 0, []
    for when in (0, 2, 10, 40, 150, 600, "detach"):
        n += 1
        tg = d = None
        try:
            tg = LcTarget("--threads", 4, "--churn")
            d = LcDriver(tg.pid, cfg, "--detach-on-stdin")
            if when == "detach":
                d.wait_attached(); d.wait_active(timeout=30)
                d.detach(); time.sleep(0.005)
            else:
                time.sleep(when / 1000.0)
            tg.kill()
            if not d.finish(timeout=10):
                d.detach()                                  # the session may still wait for its detach cue
            fin_ok = d.finish(timeout=60)
            rc = d.p.returncode
            acct, session = d.accounting(), d.attached()
            seen.append(f"{when}:{'S' if session else '-'}{d.logs}")
            why = []
            if not fin_ok: why.append("driver did not finish")
            if acct is None:
                why.append("no final accounting (neither 'probe: detached:' nor probe_report)")
            elif acct["logs_written"] != d.logs or acct["log_dropped"] != 0:
                why.append(f"logs_written={acct['logs_written']} delivered={d.logs} dropped={acct['log_dropped']} "
                           f"({acct['source']})")
            if session and rc != 0: why.append(f"rc={rc} after the session was established")
            if not session and (rc != 1 or (acct or {}).get("logs_written") not in (0, None) or d.logs):
                why.append(f"attach failed before the session existed but rc={rc} delivered={d.logs}")
            if why:
                bad.append(f"kill@{when}: session={session} " + " ".join(why) + f" err={d.errors()}")
        except Exception as e:
            bad.append(f"kill@{when}: {e!r}")
        finally:
            if d: d.kill()
            if tg: tg.kill()
    name = f"lifecycle-target-dies-{cfgname}"
    record(name, not bad, f"cases={n} [when:session?delivered]={' '.join(seen)}" + (f" bad={bad[:3]}" if bad else ""))


def lc_two_controllers(cfgname, cfg):
    """A second controller attaching to a target the first one holds must fail cleanly (fast,
    with an error) and leave the first session working; the first then detaches cleanly."""
    name = f"lifecycle-two-controllers-{cfgname}"
    tg = a = b = None
    try:
        tg = LcTarget("--threads", 4)
        a = LcDriver(tg.pid, cfg, "--detach-on-stdin")
        if not a.wait_attached() or not a.wait_active():
            raise RuntimeError(f"first not active: {a.errors()}")
        b = LcDriver(tg.pid, cfg)
        b_done = b.finish(timeout=30)
        b_err = [l for l in b.err.lines if "attach" in l.lower() or "error" in l.lower()][:2]
        before = a.logs; time.sleep(1.0); grew = a.logs > before
        mid = tg.check()
        a.detach(); a_done = a.finish()
        ok_logs, fin = lc_logs_ok(a)
        c = tg.check(); tg.reset(); time.sleep(0.2); fl = tg.check()
        q = tg.quit()
        ok = (b_done and b.p.returncode != 0 and grew and mid.get("debugger") == 1 and a_done and a.p.returncode == 0
              and ok_logs and lc_clean(c) and fl.get("flips") == 0 and lc_clean(q) and q.get("rc") == 0)
        record(name, ok, f"second_rc={b.p.returncode} second_err={[x[:100] for x in b_err]} "
                         f"first_kept_logging={grew} first_logs={a.logs} final={fin} {lc_brief(c)} exit={q.get('rc')}")
    except Exception as e:
        record(name, False, repr(e))
    finally:
        for x in (a, b, tg):
            if x: x.kill()


def lc_interrupt(cfgname, cfg):
    """Ctrl+Break at random points of an attach session (before/while attaching, while the
    agent loads and hooks install, mid-run): the tool exits by itself, and the target is left
    exactly as before (no leftover code change / debug register / debugger) and runs on."""
    import signal
    bad, n = [], 0
    for when in (0.0, 0.01, 0.05, 0.15, 0.4, 1.0, "active"):
        n += 1
        tg = d = None
        try:
            tg = LcTarget("--threads", 4, "--churn")
            d = LcDriver(tg.pid, cfg, group=True)
            if when == "active":
                d.wait_attached(); d.wait_active(timeout=30); time.sleep(0.3)
            else:
                time.sleep(when)
            d.p.send_signal(signal.CTRL_BREAK_EVENT)
            fin_ok = d.finish(timeout=60)
            time.sleep(0.3)
            c = tg.check()
            if not fin_ok or not lc_clean(c):
                bad.append(f"ctrl@{when}: finished={fin_ok} rc={d.p.returncode} {lc_brief(c)}")
        except Exception as e:
            bad.append(f"ctrl@{when}: {e!r}")
        finally:
            if d: d.kill()
            if tg:
                a = tg.quit() if tg.p.poll() is None else {"rc": tg.p.returncode}
                if a.get("rc") != 0 and not any(x.startswith(f"ctrl@{when}") for x in bad):
                    bad.append(f"ctrl@{when}: target exit={a.get('rc')} {lc_brief(a)}")
                tg.kill()
    record(f"lifecycle-interrupt-{cfgname}", not bad, f"cases={n}" + (f" bad={bad[:3]}" if bad else ""))


def lc_controller_killed(cfgname, cfg):
    """The controller is killed (TerminateProcess) while attached, mid-run with every probe live
    and logging: the TARGET must survive -- keep running, never fault, never hang, make no
    error -- and, once the controller is gone, be left with no live hook / INT3 / debug register
    (it would die or misbehave at its next hit otherwise)."""
    bad, n, took = [], 0, []
    for when in ("active", "active+0.5", "early-0.05", "early-0.3"):
        n += 1
        tg = d = None
        t0, steps = time.time(), []
        try:
            # Inline only (no debug events per hit): flat out, so the agent's 4096-slot log ring
            # fills within the wait below -- an orphaned producer spinning on it is a hang.
            tg = LcTarget("--threads", 4, "--churn", "--slow-every", 20, "--slow-ms", 20,
                          pace=0 if cfgname == "inline" else 1)
            d = LcDriver(tg.pid, cfg)
            if when.startswith("active"):
                d.wait_attached(); d.wait_active(timeout=30)
                d.wait_logs(200, timeout=10)
                time.sleep(float(when.split("+")[1]) if "+" in when else 0.0)
            else:
                time.sleep(float(when.split("-")[1]))
            d.kill(); d.finish(timeout=30)
            steps = [f"fin={time.time() - t0:.0f}"]
            time.sleep(3.0)                                    # the target runs on, alone
            c = tg.check()
            steps.append(f"chk={time.time() - t0:.0f}{'!' if c.get('hung') else ''}")
            time.sleep(1.0)
            c2 = tg.check()
            progressed = (c2.get("iterations") or 0) > (c.get("iterations") or 0)
            if not lc_clean(c2) or not progressed:
                bad.append(f"kill@{when}: progressed={progressed} {lc_brief(c2)} unhandled={tg.unhandled()}")
            first_susp = c.get("susp_info") if c.get("susp") else ""
            a = tg.quit()
            steps.append(f"quit={time.time() - t0:.0f}")
            if (a.get("rc") != 0 or a.get("late") or a.get("stuck")) and not any(x.startswith(f"kill@{when}") for x in bad):
                bad.append(f"kill@{when}: exit={a.get('rc')} {lc_brief(a)} unhandled={tg.unhandled()}"
                           + (f" susp@4s={first_susp}" if first_susp else ""))
        except Exception as e:
            bad.append(f"kill@{when}: {e!r}")
        finally:
            if d: d.kill()
            if tg: tg.kill()
            took.append(f"{when}={time.time() - t0:.0f}s" + (f"({','.join(steps)})" if steps else ""))
    record(f"lifecycle-controller-killed-{cfgname}", not bad,
           f"cases={n} took=[{' '.join(took)}]" + (f" bad={bad[:3]}" if bad else ""))


def lc_agent_refused(cfgname, cfg):
    """The session fails in the middle of an attach (here: the target only admits Microsoft-
    signed DLLs, so the inline agent cannot load) while other probes are already armed: the
    controller must let go of the target ON ITS DEBUG THREAD before it returns (INT3s restored,
    DRs cleared, debugger detached) -- not leave live traps behind a dead event loop -- and
    every log it wrote must be delivered. The target runs on, untouched, and exits cleanly."""
    if "inline" not in cfg.values():
        return
    name = f"lifecycle-agent-refused-{cfgname}"
    tg = d = None
    try:
        tg = LcTarget("--threads", 4, "--ms-signed-only")
        d = LcDriver(tg.pid, cfg)
        fin_ok = d.finish(timeout=60)
        refused = any("LoadLibraryW failed" in l or "agent" in l.lower() and "fail" in l.lower() for l in d.err.lines)
        time.sleep(2.0)
        c = tg.check()
        a = tg.quit()
        rep = report([json.loads(l) for l in d.other if l.startswith("{")])
        ok = (fin_ok and d.p.returncode == 1 and refused and lc_clean(c) and lc_clean(a) and a.get("rc") == 0
              and rep.get("log_dropped") == 0)
        record(name, ok, f"driver_rc={d.p.returncode} refused={refused} logs={d.logs} dropped={rep.get('log_dropped')} "
                         f"{lc_brief(c)} exit={a.get('rc')}" + ("" if ok else f" err={d.errors()} unhandled={tg.unhandled()}"))
    except Exception as e:
        record(name, False, repr(e))
    finally:
        if d: d.kill()
        if tg: tg.kill()


def lc_install_stuck(cfgname, cfg):
    """Detach while the agent's remote work cannot run: the target holds its loader lock, so the
    agent init thread a re-attach starts cannot even begin before the detach gives up waiting
    for it. When the lock is released later that stale init must NOT install hooks into the
    (by then detached) target: its code bytes stay original and it runs on correctly."""
    if "inline" not in cfg.values():
        return
    name = f"lifecycle-install-stuck-{cfgname}"
    tg = d0 = d = None
    try:
        tg = LcTarget("--threads", 4)
        d0 = LcDriver(tg.pid, cfg, "--detach-on-stdin")         # first session: the agent gets loaded
        if not d0.wait_attached() or not d0.wait_active():
            raise RuntimeError(f"first session not active: {d0.errors()}")
        d0.detach(); d0.finish()
        tg.p.stdin.write("lock 9000\n"); tg.p.stdin.flush()
        if not tg.out.wait_for(lambda l: '"kind":"locked"' in l, 10):
            raise RuntimeError("target did not take its loader lock")
        d = LcDriver(tg.pid, cfg, "--detach-after-ms", 1000)
        fin_ok = d.finish(timeout=60)
        unlocked = tg.out.wait_for(lambda l: '"kind":"unlocked"' in l, 30) is not None
        time.sleep(2.0)
        c = tg.check()
        a = tg.quit()
        ok = fin_ok and unlocked and lc_clean(c) and lc_clean(a) and a.get("rc") == 0
        record(name, ok, f"driver_rc={d.p.returncode} finished={fin_ok} {lc_brief(c)} exit={a.get('rc')}"
                         + ("" if ok else f" err={d.errors()} unhandled={tg.unhandled()} "
                                          f"detach_lines={[l[:120] for l in d.err.lines if 'detach' in l or 'remote' in l][:4]}"))
    except Exception as e:
        record(name, False, repr(e))
    finally:
        for x in (d0, d, tg):
            if x: x.kill()


def lc_killed_in_freeze(cfgname, cfg, repeats=5):
    """L11, runner signature (controller killed 0.05 s into an attach, target dead 0xC0000005
    with no unhandled report): the controller dies while the agent's install round waits on its
    FREEZE request (UHH_TEST_FREEZE_STALL_MS parks the controller exactly there). The raise then
    comes back unserviced; the agent must NOT write the hooks unfrozen (SafetyHook's own trap
    path made the ntdll stub page non-executable under the installer and every other thread).
    The target must run on, untouched and unhooked."""
    if "inline" not in cfg.values():
        return
    bad, n = [], 0
    for i in range(repeats):
        n += 1
        tg = d = None
        try:
            tg = LcTarget("--threads", 4, "--churn", pace=0 if cfgname == "inline" else 1)
            old = os.environ.get("UHH_TEST_FREEZE_STALL_MS")
            os.environ["UHH_TEST_FREEZE_STALL_MS"] = "3000"
            try:
                d = LcDriver(tg.pid, cfg)
            finally:
                if old is None: os.environ.pop("UHH_TEST_FREEZE_STALL_MS", None)
                else: os.environ["UHH_TEST_FREEZE_STALL_MS"] = old
            if not d.err.wait_for(lambda l: l.startswith("probe: test: install freeze stalled"), 30):
                raise RuntimeError(f"no install freeze seen: {d.err.lines[-3:]}")
            d.kill(); d.finish(timeout=30)
            time.sleep(3.0)
            c = tg.check()
            time.sleep(1.0)
            c2 = tg.check()
            progressed = (c2.get("iterations") or 0) > (c.get("iterations") or 0)
            if not lc_clean(c2) or not progressed:
                bad.append(f"#{i}: progressed={progressed} {lc_brief(c2)} unhandled={tg.unhandled()}")
            a = tg.quit()
            if (a.get("rc") != 0 or a.get("late") or a.get("stuck")) and not any(x.startswith(f"#{i}") for x in bad):
                bad.append(f"#{i}: exit={a.get('rc')} {lc_brief(a)} unhandled={tg.unhandled()}")
        except Exception as e:
            bad.append(f"#{i}: {e!r}")
        finally:
            if d: d.kill()
            if tg: tg.kill()
    record(f"lifecycle-killed-in-freeze-{cfgname}", not bad, f"cases={n}" + (f" bad={bad[:3]}" if bad else ""))


def check_lifecycle():
    """Lifecycle edge cases (examples/lifecycle) under every backend and mixed: repeated
    attach/detach/re-attach, detach at awkward moments, the target dying under the controller,
    two controllers, Ctrl+Break at random points, the controller being killed. UHH_LC=substr
    narrows it (e.g. UHH_LC=reattach,inline)."""
    if not exe("lifecycle_driver.exe") or not exe("lifecycle_target.exe") or not exe("hunt_dll.dll"):
        return missing_bin("lifecycle", "lifecycle_driver / lifecycle_target / hunt_dll")
    for cfgname, cfg in LC_CONFIGS.items():
        for fn in (lc_reattach, lc_detach_cases, lc_target_dies, lc_two_controllers, lc_interrupt, lc_controller_killed,
                   lc_killed_in_freeze, lc_agent_refused, lc_install_stuck):
            tag = fn.__name__[3:].replace("_", "-")
            if fn is lc_detach_cases or lc_selected(f"lifecycle-{tag}-{cfgname}"):
                fn(cfgname, cfg)


SDE_EXE = Path(r"C:\tools\sde\sde.exe")
# -cet: shadow-stack checks on every call/ret of the process (Pin JIT); -cet_stderr: one
# "Control flow error: IP: .. expected (shadow stack): .. got (actual return address): .."
# block per violation on the target's stderr. SDE 9.48 is the last Windows kit with it (9.53+
# print "CET is not supported on Windows"). Its labels are swapped: "expected" is the address
# on the ordinary stack, "got" the shadow-stack entry (shown by cet_smash's known addresses).
SDE_CET = ["-tgl", "-cet", "-cet_stderr", "-cet_call_stack", "-no-follow-child"]
SDE_CF = re.compile(r"^Control flow error:\s+IP: (0x[0-9a-fA-F]+) expected \(shadow stack\): (0x[0-9a-fA-F]+) "
                    r"got \(actual return address\): (0x[0-9a-fA-F]+)")


def check_cet_sde(n=20, threads=2, reads=50):
    r"""Intel CET shadow stacks EMULATED by Intel SDE (C:\tools\sde = the 9.48 kit; skipped when
    absent). The VM's CPU has no CET, but SDE runs the target in its JIT with a shadow stack per
    thread and reports every ret that does not match it. UHH attaches to the SDE-hosted target
    (SDE starts it; probe_launch cannot) and every row compares the target's CET reports with an
    uninstrumented run under SDE. cet-sde-probe: SDE's CPUID shows CET_SS and RDSSP is live
    while Windows' ProcessUserShadowStackPolicy still says 0 -- so UHH's policy-keyed branches
    (breakpoint CALL/RET in place, the breakpoint/hw call_func refusal) never run under SDE.
    cet-sde-control-*: positive control -- cet_smash's deliberate return-address overwrite is
    reported with exactly its two addresses, a clean run is not. Inline backend: cet_smash's
    workload with call_original+return_from and a pure return_from (cet-sde-calls-inline), a
    probe ON a call instruction (the hook relocates that call; cet-sde-relcall-inline: under a
    shadow stack it must be copied verbatim, a push+jmp return is a violation), gated_config
    on probe_app_cet (flag/open/read all inline), the callorig-hunt cases (call_original /
    return_from incl. C++ throw, SEH, longjmp, 16 threads), set_reg(SP) (conformance SpSite).
    Every inline row ends with the workload thread still under SDE (RDSSP live) and, for
    cet_smash, its deliberate smash still reported (the checker was on the whole time).
    breakpoint/hw are not measurable under SDE (SKIP rows say why). x86: SKIP (SDE's checker
    reports hundreds of WoW64-transition mismatches on a clean 32-bit run, and Windows does not
    enforce user shadow stacks for WoW64 anyway)."""
    sm, drv, tgt, att, cot, cop = (exe("cet_smash.exe"), exe("cet_sde_driver.exe"), exe("probe_app_cet.exe"),
                                   exe("uhh_attach.exe"), exe("co_target.exe"), exe("conformance_target.exe"))
    pr = exe("cet_probe.exe")
    if not all((sm, drv, tgt, att, cot, cop, pr)):     # project-built: checked before the optional SDE
        return missing_bin("cet-sde", "cet_smash/cet_sde_driver/probe_app_cet/uhh_attach/co_target/conformance_target/cet_probe")
    if not SDE_EXE.exists():
        return skip_external("cet-sde", f"Intel SDE {SDE_EXE}", "the CET emulation needs the 9.48 kit")
    if pe_is_x86(sm):
        return skip("cet-sde", "x86: SDE's CET checker is not usable on WoW64 (530 reports on a clean cet_smash run, "
                               "121 with ntdll excluded) and Windows does not enforce user shadow stacks for WoW64")

    def violations(lines):
        return [m.groups() for m in (SDE_CF.match(l) for l in lines) if m]

    def sde(args, gate):
        p = subprocess.Popen([str(SDE_EXE), *SDE_CET, "--", *[str(a) for a in args]],
                             stdin=subprocess.PIPE if gate else subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        return p, Lines(p.stdout), Lines(p.stderr)

    def plain(args, timeout=180):
        """An uninstrumented run under SDE: (returncode, stdout objects, violations, stderr lines)."""
        p, out, err = sde(args, False)
        try:
            p.wait(timeout=timeout)
        finally:
            if p.poll() is None:
                p.kill()
        o = out.objs(); err.t.join(timeout=30)
        return p.returncode, o, violations(err.lines), err.lines

    def child_pid(sde_pid, name):
        """The pid of `name` that SDE started (sde.exe -> pin.exe -> the target), for targets whose
        gate line carries no pid."""
        ps = (f"$all = Get-CimInstance Win32_Process; $pins = $all | ?{{ $_.ParentProcessId -eq {sde_pid} -and "
              f"$_.Name -eq 'pin.exe' }} | %{{ $_.ProcessId }}; $all | ?{{ $_.Name -eq '{name}' -and "
              f"$pins -contains $_.ParentProcessId }} | %{{ $_.ProcessId }}")
        o = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=60).stdout.split()
        return int(o[0]) if o else None

    def attached(target_args, tool_args, active, timeout=240):
        """Start target_args (gated on stdin) under SDE, attach the UHH tool (tool_args + pid),
        wait until every location in `active` is live, release the gate. Returns (target rc,
        target objs, violations, tool rc, tool objs, tool stderr lines)."""
        p, out, err = sde(target_args, True)
        procs = [p]
        try:
            w = out.wait_for(lambda l: '"kind":"waiting"' in l, 120)
            if not w:
                raise RuntimeError(f"target never reached its gate under SDE: {err.lines[-3:]}")
            pid = json.loads(w).get("pid") or child_pid(p.pid, Path(str(target_args[0])).name)
            if not pid:
                raise RuntimeError("no pid for the SDE-hosted target")
            a = subprocess.Popen([str(x) for x in tool_args(pid)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            procs.append(a)
            aout, aerr = Lines(a.stdout), Lines(a.stderr)
            if not aout.wait_for(lambda l: '"kind":"attached"' in l, 60):
                raise RuntimeError(f"attach failed: {aerr.lines[-3:]}")
            for loc in active:
                if not aerr.wait_for(lambda l, loc=loc: l.startswith(f"probe: active {loc} "), 60):
                    raise RuntimeError(f"{loc} never became active")
            p.stdin.write("x"); p.stdin.flush()
            p.wait(timeout=timeout); a.wait(timeout=60)
            o = out.objs(); err.t.join(timeout=30)
            return p.returncode, o, violations(err.lines), a.returncode, aout.objs(), aerr.lines
        finally:
            for x in procs:                    # only the processes this check started
                if x.poll() is None:
                    x.kill()

    def logs_of(objs, prefix=""):
        return dict(Counter(str(x.get("message")) for x in objs
                            if x.get("kind") == "probe_log" and str(x.get("message")).startswith(prefix)))

    def hits_of(objs):
        return {str(x.get("location", "")).split("!", 1)[-1]: x.get("hits") for x in probes(objs)}

    def row_of(objs, kind):
        r = dict(next((x for x in objs if x.get("kind") == kind), {}))
        r.pop("kind", None)
        return r

    # cet-sde-probe: what SDE emulates vs what Windows reports.
    try:
        rc, o, v, el = plain([pr], timeout=120)
        info = row_of(o, "cet_probe")
        pol = info.get("policy", {})
        if any("not supported on Windows" in l for l in el):
            record("cet-sde-probe", False, f"{SDE_EXE} refuses -cet on Windows (SDE 9.53+); install the 9.48 kit there")
        else:
            record("cet-sde-probe", rc == 0 and info.get("cpuid_cet_ss") == 1 and (info.get("ssp") or 0) != 0 and
                   pol.get("EnableUserShadowStack") == 0,
                   f"cpuid_cet_ss={info.get('cpuid_cet_ss')} ssp={info.get('ssp')} os_cet_u={info.get('os_cet_u')} "
                   f"policy.EnableUserShadowStack={pol.get('EnableUserShadowStack')} (emulated in SDE's JIT; the OS "
                   f"policy UHH keys its breakpoint CET branches on stays 0) rc={rc}")
    except Exception as e:
        record("cet-sde-probe", False, repr(e))

    # cet-sde-control-*: the checker sees a real violation and nothing in a clean run.
    try:
        rc, o, v, _ = plain([sm, "clean"], timeout=120)
        first = row_of(o, "cet_smash")
        record("cet-sde-control-clean", rc == 0 and not v and (first.get("ssp") or 0) != 0,
               f"violations={len(v)} ssp={first.get('ssp')} rc={rc}")
        rc, o, v, _ = plain([sm, "smash"], timeout=120)
        land = next((x for x in o if x.get("site_a")), {})
        pair = {land.get("site_a"), land.get("site_b")}
        hit = bool(v) and {int(v[0][1], 16), int(v[0][2], 16)} == {int(a, 16) for a in pair if a}
        record("cet-sde-control-smash", rc == 3 and hit,
               f"first={v[0] if v else None} smash=site_a {land.get('site_a')} / site_b {land.get('site_b')} "
               f"violations={len(v)} rc={rc}")
    except Exception as e:
        record("cet-sde-control-smash", False, repr(e))

    # cet_smash's workload, uninstrumented: the reference sum, RDSSP live in every iteration, and
    # the violations of its closing smash (the only ones an instrumented run may show).
    base_sum = base_v = None
    call_off = -1
    try:
        r = subprocess.run([str(sm), "calls", "0"], capture_output=True, text=True, timeout=60)
        call_off = next((json.loads(l)["call_off"] for l in r.stdout.splitlines() if '"cet_calls"' in l), -1)
        rc, o, v, _ = plain([sm, "calls", n, "--smash"], timeout=120)
        c = row_of(o, "cet_calls")
        base_sum, base_v = c.get("sum"), v
        record("cet-sde-calls-base", rc == 3 and c.get("ssp_live") == n and len(v) >= 1 and call_off > 0,
               f"sum={c.get('sum')} ssp_live={c.get('ssp_live')}/{n} smash_violations={len(v)} call_off={call_off} rc={rc}")
    except Exception as e:
        record("cet-sde-calls-base", False, repr(e))

    def smash_row(name, specs, want_sum, want_hits, want_logs):
        try:
            locs = [sp.split("=")[0] for sp in specs]
            args = []
            for sp in specs:
                args += ["--probe", sp]
            rc, o, v, arc, ao, ael = attached([sm, "calls", n, "--wait", "--smash"],
                                              lambda pid: [drv, "--backend", "inline", *args, "--attach", pid], locs)
            c, rep = row_of(o, "cet_calls"), report(ao)
            hb, lg = hits_of(ao), logs_of(ao)
            ok = (rc == 3 and c.get("sum") == want_sum and c.get("ssp_live") == n and base_v is not None and v == base_v and
                  hb == want_hits and lg == want_logs and rep.get("error") is None and rep.get("log_dropped") == 0)
            record(name, ok, f"sum={c.get('sum')}/{want_sum} ssp_live={c.get('ssp_live')}/{n} violations={len(v)} "
                             f"(uninstrumented {len(base_v or [])}, same={v == base_v}) extra={[x for x in v if x not in (base_v or [])][:2]} "
                             f"hits={hb} logs={lg} err={rep.get('error')} rc={rc}/{arc}")
        except Exception as e:
            record(name, False, repr(e))

    leaf_sum = sum(3 * i + 1 for i in range(n))
    smash_row("cet-sde-calls-inline", ["cet_smash.exe!cet_leaf=orig", "cet_smash.exe!cet_caller=replace"],
              leaf_sum + 77 * n, {"cet_leaf": n, "cet_caller": n}, {"co fact": n, "co fact-done": n, "co prologue": n})
    if call_off > 0:
        site = f"cet_smash.exe!cet_caller+0x{call_off:x}"
        smash_row("cet-sde-relcall-inline", [site + "=log"], base_sum, {site.split("!", 1)[1]: n}, {"ok watch-hit": n})
    else:
        record("cet-sde-relcall-inline", False, f"cet_caller has no call rel32 (call_off={call_off})")

    # gated_config on probe_app_cet, every probe inline (uhh_attach: flag, open, close, read).
    try:
        W, R, helper, offset = int(threads), int(reads), 1, 64
        _, bo, bv, _ = plain([tgt, "--no-wait", "--helpers", HELPERS, "--threads", W, "--reads", R,
                              "--config", "reads_enabled=1"], timeout=180)
        base = app(bo)
        p, out, err = sde([tgt, "--helpers", HELPERS, "--threads", W, "--reads", R], True)
        a = None
        try:
            w = out.wait_for(lambda l: '"kind":"waiting"' in l, 120)
            if not w:
                raise RuntimeError("probe_app_cet never reached its gate under SDE")
            h = next(x for x in (json.loads(l) for l in out.lines if '"kind":"helper"' in l) if x["index"] == helper)
            a = subprocess.Popen([str(att), str(json.loads(w)["pid"]), "--pid", str(h["pid"]), "--range",
                                  f"{h['base'] + offset}:64", "--backend", "inline", "--flag-backend", "inline"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            aout, aerr = Lines(a.stdout), Lines(a.stderr)
            if not aout.wait_for(lambda l: '"kind":"attached"' in l, 60):
                raise RuntimeError(f"uhh_attach did not attach: {aerr.lines[-3:]}")
            for loc in (OPEN_LOCATION, READ_LOCATION):
                if not aerr.wait_for(lambda l, loc=loc: l.startswith(f"probe: active {loc} "), 60):
                    raise RuntimeError(f"{loc} never became active")
            p.stdin.write("x"); p.stdin.flush()
            p.wait(timeout=300); a.wait(timeout=60)
            rc, o, arc, ao = p.returncode, out.objs(), a.returncode, aout.objs()
            err.t.join(timeout=30)
            v = violations(err.lines)
        finally:
            for x in (p, a):                   # only the processes this check started
                if x is not None and x.poll() is None:
                    x.kill()
        rep, a_row = report(ao), app(o)
        rd = next((x for x in probes(ao) if x.get("location") == READ_LOCATION), {})
        logs, dropped = read_logs(ao)
        want = predicted_reads(W, R, HELPERS, helper, offset)
        ok = (arc == 0 and rc == 0 and rep.get("overrides") == 1 and rd.get("hits") == W * R and rd.get("backend") == "inline"
              and a_row.get("successful_reads") == W * R and a_row.get("checksum") == base.get("checksum")
              and logs == want and dropped == 0 and a_row.get("shadow_stack") is True and not v and not bv)
        record("cet-sde-gated-inline", ok,
               f"override={rep.get('overrides')} read_hits={rd.get('hits')}/{W * R} logged={logs}/{want} dropped={dropped} "
               f"checksum_same={a_row.get('checksum') == base.get('checksum')} target_ssp={a_row.get('shadow_stack')} "
               f"violations={len(v)} (uninstrumented {len(bv)}) rc={rc}/{arc} err={(rep.get('error') or '')[:100]}")
    except Exception as e:
        record("cet-sde-gated-inline", False, repr(e))

    # The callorig-hunt cases (examples/hunt_callorig), inline, attached by co_driver. C++
    # throw / SEH / longjmp make SDE report mismatches even uninstrumented (Windows' unwinder
    # does not move a shadow stack the OS says is off): the instrumented run must show exactly
    # the same reports.
    for case in ("recurse", "cppthrow", "seh", "longjmp", "threads", "mid", "nargs", "conv", "retaddr", "prologue",
                 "nested"):
        name = f"cet-sde-co-{case}-inline"
        try:
            _, bo, bv, _ = plain([cot, case], timeout=180)
            base = row_of(bo, "co")
            want_row, want_hits, want_logs = co_expect(case, base, False)
            want_row.pop("kind", None)
            locs = [f"co_target.exe!{k}" for k in want_hits]
            rc, o, v, arc, ao, ael = attached([cot, case, "--wait"],
                                              lambda pid: [exe("co_driver.exe"), "--backend", "inline", "--case", case,
                                                           "--attach", pid], locs)
            row, rep, lg, hb = row_of(o, "co"), report(ao), logs_of(ao, "co "), hits_of(ao)
            got_logs = {k: lg.get(k, 0) for k in want_logs}
            extra = sorted(k for k in lg if k not in want_logs and not (case == "retaddr" and k == "co retsite"))
            ok = (bool(base) and row == want_row and all(hb.get(k) == x for k, x in want_hits.items()) and
                  got_logs == want_logs and not extra and rep.get("log_dropped") == 0 and rep.get("error") is None and
                  rc == 0 and arc == 0 and sorted(v) == sorted(bv))
            record(name, ok, f"row={row} want={want_row} hits={hb} logs={got_logs} extra={extra[:3]} violations={len(v)} "
                             f"(uninstrumented {len(bv)}, same={sorted(v) == sorted(bv)}) err={rep.get('error')} rc={rc}/{arc}")
        except Exception as e:
            record(name, False, repr(e))

    # set_reg(SP) inline (conformance_target!SpSite+3 moves SP down 32 bytes; SafetyHook's patched
    # resume stub `pop rsp; jmp [trampoline]` resumes there).
    try:
        rc, o, v, arc, ao, ael = attached([cop], lambda pid: [drv, "--backend", "inline", "--sp-only", "--attach", pid],
                                          ["conformance_target.exe!SpSite+0x3"])
        t_row, rep = row_of(o, "target"), report(ao)
        ok = rc == 0 and arc == 0 and t_row.get("sp_moved") == 10 and not v and rep.get("error") is None
        record("cet-sde-sp-inline", ok, f"sp_moved={t_row.get('sp_moved')}/10 violations={len(v)} "
                                        f"hits={hits_of(ao)} err={rep.get('error')} rc={rc}/{arc}")
    except Exception as e:
        record("cet-sde-sp-inline", False, repr(e))

    skip("cet-sde-breakpoint", "not measurable under SDE: the first INT3 is reported as an unhandled 0x80000003 and "
                               "lost, and the thread then runs NATIVELY (cet_smash: ssp_live 0/20, its smash no longer "
                               "reported); a hit in the loader (gated_config's NtClose) hangs the target")
    skip("cet-sde-hw", "not measurable under SDE: execute debug registers never match code run from SDE's code cache "
                       "(0 hits on cet_smash/co_target/conformance; the program is unaffected)")

CX_LATE_SUM = sum(((j * 7 + 3) & 0xFF) * (j + 1) for j in range(1000)) & 0x7FFFFFFF   # co_on_late's config sum


def cx_detach_summary(lines):
    """The 'probe: detached: hits=.. logs_written=.. log_dropped=.. in_flight=..' line as a dict."""
    for l in lines:
        if l.startswith("probe: detached:"):
            return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", l)}
    return {}


def cx_attached_run(case, bk, driver, t, detach_step, timeout=150, env=None):
    """co_target <case> --wait, attached by <driver> --detach-on-stdin. detach_step(tgt, att, tout)
    runs once the callback is in flight; returns (target row, driver stdout/stderr Lines, rcs)."""
    procs = []
    try:
        tgt = subprocess.Popen([str(t), case, "--wait"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
        procs.append(tgt)
        tout = Lines(tgt.stdout)
        w = tout.wait_for(lambda l: '"kind":"waiting"' in l, 30)
        if not w:
            raise RuntimeError("target never reached its gate")
        att = subprocess.Popen([str(driver), "--backend", bk, "--case", case, "--attach", str(json.loads(w)["pid"]),
                                "--detach-on-stdin"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, env=env)
        procs.append(att)
        aout, aerr = Lines(att.stdout), Lines(att.stderr)
        if not aerr.wait_for(lambda l: l.startswith("probe: active co_target.exe!co_late"), 60):
            raise RuntimeError("co_late never became active: " + " | ".join(aerr.lines[-4:])[:300])
        tgt.stdin.write("x"); tgt.stdin.flush()
        incb = tout.wait_for(lambda l: '"kind":"incb"' in l, 90)
        if not incb or json.loads(incb).get("state") != 1:
            raise RuntimeError(f"the callback never started: {incb}")
        took = detach_step(tgt, att, tout)
        att.wait(timeout=timeout); tgt.wait(timeout=timeout)
        row = next((x for x in tout.objs() if x.get("kind") == "co"), {})
        aout.objs(); aerr.t.join(timeout=30)
        return row, aout, aerr, att.returncode, tgt.returncode, took
    finally:
        for q in procs:
            if q.poll() is None:
                q.kill()


def check_cxlib():
    """Codex library review of merge-frida vs main (docs/ROADMAP.md "Codex library review
    findings"), one check per finding, each reproduced on the unfixed code first:
      cbfault-*   a breakpoint/hw/inline callback that FAULTS after call_original (the original
                  must not run twice; the caller gets its result), after call_original +
                  return_from (the caller gets return_from's value) and after a return_from
                  without call_original (dropped, the original runs once) -- every backend alike;
      late-inline an inline callback still running 19 s into a detach (past the agent's 2 s wait
                  and the drain's old 15 s allowance): its log after that is delivered, nothing
                  dropped, and its >256-byte config (a block in the target) is still readable;
      cfgfree-inline the program suspends a thread inside an inline callback across the whole
                  detach and resumes it afterwards: the detach does not wait for it (accounted as
                  in_flight=1), and the callback's config block is NOT freed under it;
      killarm-*   the controller dies right after writing an INT3 / arming a hw probe (test-hook
                  build, co_driver_th): the agent's guard must undo it -- the target finishes;
      noxsave-inline the x86 inline fallback without OSXSAVE (forced: UHH_BENCH_XSTATE=noxsave)
                  keeps the x87 state at a mid-function site with a full x87 stack (transparency
                  `mid`, a callback doing x87 float work)."""
    d, t, dth = exe("co_driver.exe"), exe("co_target.exe"), exe("co_driver_th.exe")
    if not d or not t or not dth:
        return missing_bin("cxlib", "co_driver/co_target/co_driver_th")

    # -- (1) a callback faulting after call_original / return_from -------------------------
    want_rets = [i * 3 + 5 + (1000 if i % 3 == 1 else 0) for i in range(9)]
    for bk in ("breakpoint", "hw", "inline"):
        name = f"cxlib-cbfault-{bk}"
        try:
            r, o = run([d, "--backend", bk, "--case", "cbfault", "--", t, "cbfault"], timeout=120)
            row, rep = next((x for x in o if x.get("kind") == "co"), {}), report(o)
            hits = sum(p.get("hits", 0) for p in probes(o))
            logs = sum(1 for x in o if x.get("kind") == "probe_log" and x.get("message") == "co cbfault")
            bad = []
            if row.get("rets") != want_rets: bad.append(f"rets={row.get('rets')} want {want_rets}")
            if row.get("runs") != "1" * 9: bad.append(f"body runs per call={row.get('runs')!r} (want 111111111)")
            if hits != 9 or logs != 9: bad.append(f"hits={hits} logs={logs} (want 9)")
            if r.returncode != 0 or rep.get("error") is not None or rep.get("app_exit") != 0 or rep.get("log_dropped") != 0:
                bad.append(f"rc={r.returncode} err={rep.get('error')} exit={rep.get('app_exit')} dropped={rep.get('log_dropped')}")
            record(name, not bad, " ".join(bad) or f"rets={row.get('rets')} runs={row.get('runs')} hits={hits}")
        except Exception as e:
            record(name, False, repr(e))

    # -- (4)+(2) an inline callback outliving the detach's old allowances ------------------
    name = "cxlib-late-inline"
    try:
        def detach_now(tgt, att, tout):
            t0 = time.time(); att.stdin.write("\n"); att.stdin.flush()
            att.wait(timeout=150)
            return time.time() - t0
        row, aout, aerr, arc, trc, took = cx_attached_run("late", "inline", d, t, detach_now)
        sm = cx_detach_summary(aerr.lines)
        done = [l for l in aout.lines if '"message":"co late-done' in l]
        bad = []
        if row.get("ret") != CX_LATE_SUM or row.get("body") != 0 or row.get("done") != 1:
            bad.append(f"target ret={row.get('ret')} want {CX_LATE_SUM} body={row.get('body')} done={row.get('done')}")
        if len(done) != 1 or f"sum={CX_LATE_SUM}" not in done[0]:
            bad.append(f"late log delivered={len(done)}")
        if sm.get("log_dropped") != 0 or sm.get("in_flight") != 0 or sm.get("hits") != 1 or sm.get("logs_written") != 2:
            bad.append(f"summary={sm}")
        if arc != 0 or trc != 0: bad.append(f"driver_rc={arc} target_rc={trc}")
        record(name, not bad, " ".join(bad) or f"detach_took={took:.1f}s summary={sm} ret={row.get('ret')}")
    except Exception as e:
        record(name, False, repr(e))

    # -- (2) config block under a callback the program holds suspended across the detach ----
    name = "cxlib-cfgfree-inline"
    try:
        def detach_then_resume(tgt, att, tout):
            t0 = time.time(); att.stdin.write("\n"); att.stdin.flush()
            att.wait(timeout=150)
            took = time.time() - t0
            tgt.stdin.write("g"); tgt.stdin.flush()
            return took
        row, aout, aerr, arc, trc, took = cx_attached_run("cfgfree", "inline", d, t, detach_then_resume)
        sm = cx_detach_summary(aerr.lines)
        bad = []
        if row.get("ret") != CX_LATE_SUM or row.get("body") != 0 or row.get("done") != 1:
            bad.append(f"target ret={row.get('ret')} want {CX_LATE_SUM} body={row.get('body')} done={row.get('done')} "
                       "(config freed under the callback?)")
        if sm.get("in_flight") != 1 or sm.get("log_dropped") != 0: bad.append(f"summary={sm} (want in_flight=1 dropped=0)")
        if took > 12: bad.append(f"detach waited {took:.1f}s for a callback the program holds suspended")
        if arc != 0 or trc != 0: bad.append(f"driver_rc={arc} target_rc={trc}")
        record(name, not bad, " ".join(bad) or f"detach_took={took:.1f}s summary={sm} ret={row.get('ret')}")
    except Exception as e:
        record(name, False, repr(e))

    # -- (3) the controller dies right after arming: the guard must cover it ---------------
    r0, o0 = run([t, "spin"], timeout=60)
    base = next((x for x in o0 if x.get("kind") == "co"), {})
    for bk in ("breakpoint", "hw"):
        name = f"cxlib-killarm-{bk}"
        procs = []
        try:
            tgt = subprocess.Popen([str(t), "spin", "--wait"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True)
            procs.append(tgt)
            tout = Lines(tgt.stdout)
            w = tout.wait_for(lambda l: '"kind":"waiting"' in l, 30)
            if not w:
                raise RuntimeError("target never reached its gate")
            env = dict(os.environ, UHH_TEST_DIE_AFTER_ARM="1")
            att = subprocess.Popen([str(dth), "--backend", bk, "--case", "spin", "--attach", str(json.loads(w)["pid"])],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
            procs.append(att)
            aout, aerr = Lines(att.stdout), Lines(att.stderr)
            att.wait(timeout=90)
            time.sleep(2.0)                                   # the guard notices the controller is gone
            tgt.stdin.write("x"); tgt.stdin.flush()
            try:
                tgt.wait(timeout=60)
            except subprocess.TimeoutExpired:
                raise RuntimeError("target hung after the controller died")
            row = next((x for x in tout.objs() if x.get("kind") == "co"), {})
            row.pop("kind", None); want = dict(base); want.pop("kind", None)
            rc = tgt.returncode & 0xFFFFFFFF
            ok = att.returncode == 99 and rc == 0 and row == want and bool(want)
            record(name, ok, f"controller_rc={att.returncode} (99: killed by the hook) target_rc=0x{rc:x} row={row} "
                             f"want={want}" + ("" if ok else f" ctl_err={[l[:160] for l in aerr.lines[-4:]]}"))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            for q in procs:
                if q.poll() is None:
                    q.kill()

    # -- (3, extra) the other INT3 of ours a thread can execute: the end of a displaced REP
    # string copy (in UHH's scratch, no trap flag). The controller dies right after sending a
    # thread into one (test-hook build): the guard must take that INT3 too.
    name = "cxlib-reptail-breakpoint"
    procs = []
    try:
        tgt = subprocess.Popen([str(t), "rep", "--wait"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
        procs.append(tgt)
        tout = Lines(tgt.stdout)
        w = tout.wait_for(lambda l: '"kind":"waiting"' in l, 30)
        if not w:
            raise RuntimeError("target never reached its gate")
        env = dict(os.environ, UHH_TEST_DIE_IN_REPCOPY="1")
        att = subprocess.Popen([str(dth), "--backend", "breakpoint", "--case", "rep", "--attach", str(json.loads(w)["pid"])],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        procs.append(att)
        aout, aerr = Lines(att.stdout), Lines(att.stderr)
        if not aerr.wait_for(lambda l: l.startswith("probe: active co_target.exe!CoRepSite"), 60):
            raise RuntimeError("CoRepSite never became active: " + " | ".join(aerr.lines[-4:])[:300])
        tgt.stdin.write("x"); tgt.stdin.flush()
        att.wait(timeout=90)
        try:
            tgt.wait(timeout=60)
        except subprocess.TimeoutExpired:
            raise RuntimeError("target hung after the controller died")
        row = next((x for x in tout.objs() if x.get("kind") == "co"), {})
        rc = tgt.returncode & 0xFFFFFFFF
        ok = att.returncode == 97 and rc == 0 and row.get("good") == 8
        record(name, ok, f"controller_rc={att.returncode} (97: died with a thread in the copy) target_rc=0x{rc:x} "
                         f"fills_ok={row.get('good')}/8")
    except Exception as e:
        record(name, False, repr(e))
    finally:
        for q in procs:
            if q.poll() is None:
                q.kill()

    # -- ROADMAP L13 residual (x86 controller): the WOW64 implicit suspend of a thread the
    # controller touches outside an event (arming a hw probe on every thread). Simulated in the
    # test-hook build: at its first touch of the target's main thread the controller suspends
    # it (what the kernel does inside the call) and dies. The guard must resume it. The control
    # run (UHH_TEST_NO_TOUCH_GUARD: the touch left unrecorded) shows the gap: the target hangs.
    name = "cxlib-touchkill-hw"
    if not pe_is_x86(t):
        skip(name, "x86 only (an x64 controller has no implicit suspend)")
    else:
        def touchkill(control):
            procs = []
            try:
                tgt = subprocess.Popen([str(t), "spin", "--wait"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, text=True)
                procs.append(tgt)
                tout = Lines(tgt.stdout)
                w = tout.wait_for(lambda l: '"kind":"waiting"' in l, 30)
                if not w:
                    raise RuntimeError("target never reached its gate")
                g = json.loads(w)
                env = dict(os.environ, UHH_TEST_DIE_IN_TOUCH=str(g["tid"]))
                if control:
                    env["UHH_TEST_NO_TOUCH_GUARD"] = "1"
                att = subprocess.Popen([str(dth), "--backend", "hw", "--case", "spin", "--attach", str(g["pid"])],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, env=env)
                procs.append(att)
                att.wait(timeout=90)
                time.sleep(2.0)
                tgt.stdin.write("x"); tgt.stdin.flush()
                try:
                    tgt.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    return att.returncode, None, "hung"
                row = next((x for x in tout.objs() if x.get("kind") == "co"), {})
                return att.returncode, tgt.returncode & 0xFFFFFFFF, row
            finally:
                for q in procs:
                    if q.poll() is None:
                        q.kill()
        try:
            want = dict(base); want.pop("kind", None)
            crc, trc, row = touchkill(False)
            if isinstance(row, dict): row.pop("kind", None)
            ccrc, ctrc, crow = touchkill(True)
            ok = crc == 98 and trc == 0 and row == want and bool(want)
            record(name, ok, f"controller_rc={crc} (98: died in the touch) target_rc={trc} row={row} want={want}; "
                             f"control without the touch record: controller_rc={ccrc} target={crow if crow == 'hung' else ctrc}")
        except Exception as e:
            record(name, False, repr(e))

    # -- (5) x86 inline without OSXSAVE: the x87 state around ordinary callbacks -----------
    name = "cxlib-noxsave-inline"
    tpd, tpt = exe("tp_driver.exe"), exe("tp_target.exe")
    if not tpd or not tpt:
        return missing_bin(name, "tp_driver/tp_target")
    try:
        env = dict(os.environ, UHH_BENCH_XSTATE="noxsave")
        bad = []
        for mode in ("log", "sys"):
            r = subprocess.run([str(a) for a in [tpd, "--backend", "inline", "--mode", mode, "--probes", "mid,dbl,add", "--",
                                                 tpt, "--iters", 30]], capture_output=True, text=True, timeout=300, env=env)
            o = [json.loads(l) for l in r.stdout.splitlines() if l.strip().startswith("{")]
            tg, rep = next((x for x in o if x.get("kind") == "target"), {}), report(o)
            if r.returncode != 0 or tg.get("bad") != 0 or rep.get("error") is not None or rep.get("log_dropped") != 0:
                bad.append(f"[{mode}] rc={r.returncode} bad={tg.get('bad')} first={tg.get('first')!r} err={rep.get('error')}")
        record(name, not bad, " ".join(bad) or "mid/dbl/add (log, sys) identical to the twin without XSAVE")
    except Exception as e:
        record(name, False, repr(e))


def check_symbols_grammar():
    """One module grammar for probe locations and call_func (include/probe_api.h): a module
    name without extension means "<name>.dll". "kernel32!OpenProcess" and
    "kernel32.dll!OpenProcess" must both arm and see exactly the same calls on every backend
    (probe_app --open-via kernel32 opens its helpers through kernel32!OpenProcess). An EXE is
    named with its extension: "probe_app!OpenThunk" names probe_app.dll, so it must NOT match
    probe_app.exe -- it stays pending with a warning on stderr -- while
    "probe_app.exe!OpenThunk" sees every open."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return missing_bin("symbols-grammar", "uhh_trace/probe_app")
    helpers = 2

    def trace(bk, loc, open_via, fmt="-"):
        args = [t, "--backend", bk, "-p", f"{loc}:{fmt}", "--", a, "--no-wait", "--helpers", helpers,
                "--threads", 1, "--reads", 4, "--config", "reads_enabled=1"]
        if open_via:
            args += ["--open-via", open_via]
        r, objs = run(args, timeout=300)
        pr = next((x for x in probes(objs) if x.get("location") == loc), {})
        return r, objs, pr

    # A freshly built exe's first run can make one extra in-process OpenProcess call (seen once
    # per arch on the first instrumented run after a build, never again): warm up uninstrumented,
    # and compare exactly the calls probe_app makes -- OpenProcess(PROCESS_VM_READ, FALSE, pid)
    # of each of its helpers, logged with their arguments.
    run([a, "--no-wait", "--helpers", helpers, "--threads", 1, "--reads", 4, "--config", "reads_enabled=1",
         "--open-via", "kernel32"], timeout=120)
    for bk in ("breakpoint", "hw", "inline"):
        name = f"symbols-grammar-{bk}"
        try:
            seen, ok, detail = {}, True, []
            for loc in ("kernel32!OpenProcess", "kernel32.dll!OpenProcess", "KERNEL32!OpenProcess"):
                r, objs, pr = trace(bk, loc, "kernel32", "xxd")
                res, err = app(objs), report(objs).get("error")
                pids = {x.get("pid") for x in objs if x.get("kind") == "opened"}
                opens = [m for m in (str(x.get("message", "")) for x in objs if x.get("kind") == "probe_log")
                         if m.startswith("OpenProcess(0x10, 0x0, ") and
                         m[len("OpenProcess(0x10, 0x0, "):].rstrip(")").lstrip("-").isdigit() and
                         int(m[len("OpenProcess(0x10, 0x0, "):].rstrip(")")) in pids]
                seen[loc] = len(opens)
                good = (r.returncode == 0 and pr.get("active") is True and pr.get("backend") == bk and
                        len(pids) == helpers and len(opens) == helpers and (pr.get("hits") or 0) >= helpers and
                        res.get("opened") == helpers and res.get("successful_reads") == 4 and err is None)
                ok = ok and good
                detail.append(f"{loc}: active={pr.get('active')} helper_opens={len(opens)} hits={pr.get('hits')} "
                              f"rc={r.returncode}" + ("" if good else f" err={(err or '')[:80]} "
                              f"stderr={[l[:120] for l in r.stderr.splitlines() if 'probe:' in l][-4:]}"))
            # Identical helper opens seen for every spelling: one per helper.
            ok = ok and set(seen.values()) == {helpers}
            record(name, ok, "; ".join(detail))
        except Exception as e:
            record(name, False, repr(e))
    # The EXE trap: "probe_app!X" is probe_app.dll -- pending + warning, never probe_app.exe.
    for bk in ("breakpoint", "inline"):
        name = f"symbols-grammar-exe-{bk}"
        try:
            r1, o1, bare = trace(bk, "probe_app!OpenThunk", None)
            r2, o2, full = trace(bk, "probe_app.exe!OpenThunk", None)
            warned = any(l.startswith("probe: warning: probe_app!OpenThunk names probe_app.dll") and
                         "write probe_app.exe!OpenThunk" in l for l in r1.stderr.splitlines())
            ok = (r1.returncode == 0 and bare.get("active") is False and bare.get("hits") == 0 and warned and
                  app(o1).get("opened") == helpers and
                  r2.returncode == 0 and full.get("active") is True and full.get("hits") == helpers and
                  report(o2).get("error") is None)
            record(name, ok, f"bare: active={bare.get('active')} hits={bare.get('hits')} warned={warned} "
                             f"rc={r1.returncode}; full: active={full.get('active')} hits={full.get('hits')} "
                             f"rc={r2.returncode} err={(report(o2).get('error') or '')[:80]}")
        except Exception as e:
            record(name, False, repr(e))


def check_quickstart():
    """docs/quickstart.md section 4, compiled and run: examples/quickstart (my_tool) launches
    probe_app with its config DISABLED; the breakpoint at configparse.dll!ParseConfig+0x16
    flips the flag (one override), and the inline NtReadVirtualMemory probe logs every read
    (one "read handle=..." log per hit), nothing dropped, exit 0."""
    m, a = exe("my_tool.exe"), exe("probe_app.exe")
    if not m or not a:
        return missing_bin("quickstart-my-tool", "my_tool/probe_app")
    threads, reads = 4, 200
    name = "quickstart-my-tool"
    try:
        r, objs = run([m, a, "--no-wait", "--threads", threads, "--reads", reads], timeout=300)
        res, rep = app(objs), report(objs)
        rd = next((x for x in probes(objs) if x.get("location") == READ_LOCATION), {})
        fl = next((x for x in probes(objs) if x.get("location") == "configparse.dll!ParseConfig+0x16"), {})
        logs = sum(1 for x in objs if x.get("kind") == "probe_log" and
                   str(x.get("message", "")).startswith("read handle=0x"))
        want = threads * reads
        ok = (r.returncode == 0 and res.get("reads_enabled") == 1 and res.get("successful_reads") == want and
              fl.get("hits") == 1 and fl.get("backend") == "breakpoint" and rep.get("overrides") == 1 and
              rd.get("backend") == "inline" and rd.get("hits") == want and logs == want and
              rep.get("log_dropped") == 0 and rep.get("error") is None)
        record(name, ok, f"reads_enabled={res.get('reads_enabled')} reads={res.get('successful_reads')}/{want} "
                         f"flag_hits={fl.get('hits')} overrides={rep.get('overrides')} read_hits={rd.get('hits')} "
                         f"logs={logs} dropped={rep.get('log_dropped')} rc={r.returncode} "
                         f"err={(rep.get('error') or '')[:100]}")
    except Exception as e:
        record(name, False, repr(e))
    # The doc shows the example's files verbatim: each must appear in it byte for byte.
    name = "quickstart-doc-sync"
    try:
        root = Path(__file__).resolve().parent.parent
        doc = (root / "docs" / "quickstart.md").read_text(encoding="utf-8")
        stale = [p for p in ("my_callbacks.h", "my_callbacks.cpp", "main.cpp")
                 if "```cpp\n" + (root / "examples" / "quickstart" / p).read_text(encoding="utf-8").rstrip("\n")
                 + "\n```" not in doc]
        record(name, not stale, f"files not shown verbatim in docs/quickstart.md: {stale}" if stale else
               "docs/quickstart.md shows examples/quickstart verbatim")
    except Exception as e:
        record(name, False, repr(e))


# --- gated-e2e-*: the flagship use case end to end, against the TARGET's own ground truth ------
E2E_BACKENDS = ("breakpoint", "hw", "inline")
E2E_SHORT = {"breakpoint": "bp", "hw": "hw", "inline": "in"}
E2E_CLOSE_LOCATION = "ntdll.dll!NtClose"
E2E_RX_OPEN = re.compile(r"open pid=(\d+) name=(\S+)$")
E2E_RX_MAP = re.compile(r"map handle=0x([0-9a-f]+) -> pid=(\d+) name=(\S+)$")
E2E_RX_READ = re.compile(r"read handle=0x([0-9a-f]+) pid=(\d+) name=(\S+) addr=0x([0-9a-f]+) size=(\d+)$")


def e2e_truth(path):
    """probe_app --churn's own record: every open/read/close in sequence order."""
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def e2e_expected(truth):
    """tid -> the exact log sequence the gated_config callbacks must produce for that thread:
    an open logs `open` + `map`, a read one `read` line, a close nothing."""
    by = collections.defaultdict(list)
    for e in truth:
        if e["op"] == "open":
            by[e["tid"]] += [("open", e["pid"], "probe_app.exe"), ("map", e["handle"], e["pid"], "probe_app.exe")]
        elif e["op"] == "read":
            by[e["tid"]].append(("read", e["handle"], e["pid"], "probe_app.exe", e["addr"], e["size"]))
        elif e["op"] == "read-unmapped":      # through a duplicated handle the map never saw
            by[e["tid"]].append(("read", e["handle"], 0, "?", e["addr"], e["size"]))
    return by


def e2e_got(objs, helper_pids):
    """tid -> the delivered log sequence (parsed), plus anything that is no expected shape.
    Opens of a process that is not a helper (a start-up open of the target's own, seen once on
    a freshly built binary's first launch -- see gated-map) are set aside: they must still be
    mapped correctly, and no read may use them."""
    by, foreign, extra = collections.defaultdict(list), [], []
    for o in objs:
        if o.get("kind") != "probe_log":
            continue
        m, tid = str(o.get("message", "")), o.get("tid")
        if (x := E2E_RX_OPEN.match(m)):
            t = ("open", int(x[1]), x[2].lower())
        elif (x := E2E_RX_MAP.match(m)):
            t = ("map", int(x[1], 16), int(x[2]), x[3].lower())
        elif (x := E2E_RX_READ.match(m)):
            t = ("read", int(x[1], 16), int(x[2]), x[3].lower(), int(x[4], 16), int(x[5]))
        else:
            foreign.append(m[:80]); continue
        if t[0] in ("open", "map") and t[1 if t[0] == "open" else 2] not in helper_pids:
            extra.append((tid,) + t); continue
        by[tid].append(t)
    return by, foreign, extra


def e2e_session_file_logs(stderr_text):
    """probe_log records in the session JSONL file (the path is on stderr); deletes the file."""
    m = re.search(r"^probe: logs -> (.+)$", stderr_text or "", re.M)
    if not m:
        return None
    p = Path(m.group(1).strip())
    try:
        with open(p, "rb") as f:
            n = sum(1 for l in f if l.startswith(b'{"kind":"probe_log"'))
    except OSError:
        return None
    try:
        p.unlink()
    except OSError:
        pass
    return n


def e2e_judge(combo, rc, target_rc, objs, t_objs, stderr_text, truth, base, flag_hits_want=1):
    """Exact comparison of one run with the target's ground truth. Returns (ok, detail)."""
    fb, ob, cb, rb = combo
    bad = []
    rep, a = report(objs), app(t_objs)
    hp = helper_pids(t_objs)
    pr = {x.get("location"): x for x in probes(objs)}
    fl, op, cl, rd = (pr.get(FLAG_LOCATION, {}), pr.get(OPEN_LOCATION, {}), pr.get(E2E_CLOSE_LOCATION, {}),
                      pr.get(READ_LOCATION, {}))
    t_opens = [e for e in truth if e["op"] == "open"]
    t_reads = [e for e in truth if e["op"] in ("read", "read-unmapped")]
    t_unmapped = [e for e in truth if e["op"] == "read-unmapped"]
    t_dups = [e for e in truth if e["op"] == "dup"]
    t_closes = [e for e in truth if e["op"] == "close"]
    # The workload really did reuse handle values for different pids (else this proves nothing).
    pids_of = collections.defaultdict(set)
    for e in t_opens:
        pids_of[e["handle"]].add(e["pid"])
    reused = sum(1 for v in pids_of.values() if len(v) > 1)
    # A duplicate that got a value the map once knew (so a stale entry would mislabel it).
    known = {e["handle"] for e in t_opens}
    stale_bait = sum(1 for e in t_dups if e["handle"] in known)
    if rc != 0 or target_rc != 0 or rep.get("app_exit") not in (0, None):
        bad.append(f"rc={rc}/{target_rc} app_exit={rep.get('app_exit')}")
    if rep.get("error") is not None:
        bad.append(f"error={str(rep.get('error'))[:100]}")
    if (a.get("reads_enabled") != 1 or a.get("checksum") != base.get("checksum") or
            a.get("successful_reads") != base.get("successful_reads") or a.get("opened") != base.get("opened")):
        bad.append(f"app reads_enabled={a.get('reads_enabled')} reads={a.get('successful_reads')}/{base.get('successful_reads')} "
                   f"opened={a.get('opened')}/{base.get('opened')} checksum_same={a.get('checksum') == base.get('checksum')}")
    if (len(t_reads) != base.get("successful_reads") or len(t_opens) != base.get("opened") or not reused or
            not stale_bait or len(t_unmapped) != len(t_dups)):
        bad.append(f"truth reads={len(t_reads)} opens={len(t_opens)} reused_handles={reused} "
                   f"dups={len(t_dups)} stale_bait={stale_bait} unmapped_reads={len(t_unmapped)}")
    want_bk = {"flag": (fl, fb), "open": (op, ob), "close": (cl, cb), "read": (rd, rb)}
    wrong_bk = {k: p.get("backend") for k, (p, b) in want_bk.items() if p.get("backend") != b or p.get("active") is not True}
    if wrong_bk:
        bad.append(f"backend/active {wrong_bk}")
    if fl.get("hits") != flag_hits_want or rep.get("overrides") != 1:
        bad.append(f"flag hits={fl.get('hits')} overrides={rep.get('overrides')}")
    want, (got, foreign, extra) = e2e_expected(truth), e2e_got(objs, hp)
    # Extra (non-helper) opens: per thread, in order, each `open pid=P name=N` is followed by
    # exactly one `map handle=H -> pid=P name=N` (H != 0) of its own -- nothing else, nothing missing.
    extra_bad, ex_by = [], collections.defaultdict(list)
    for x in extra:
        ex_by[x[0]].append(x[1:])
    for tid, seq in ex_by.items():
        if len(seq) % 2 or any(not (o[0] == "open" and m[0] == "map" and m[1] != 0 and m[2] == o[1] and m[3] == o[2])
                               for o, m in zip(seq[0::2], seq[1::2])):
            extra_bad.append((tid, seq[:4]))
    if foreign or extra_bad:
        bad.append(f"foreign={foreign[:2]} extra_unpaired={extra_bad[:2]}")
    if op.get("hits") != len(t_opens) + sum(1 for x in extra if x[1] == "open"):
        bad.append(f"open hits={op.get('hits')} want={len(t_opens)}+{sum(1 for x in extra if x[1] == 'open')} extra")
    n_read_logs = sum(1 for seq in got.values() for t in seq if t[0] == "read")
    if rd.get("hits") != len(t_reads) or n_read_logs != len(t_reads):
        bad.append(f"read hits={rd.get('hits')} logs={n_read_logs} truth={len(t_reads)}")
    if (cl.get("hits") or 0) < len(t_closes):        # the program closes other handles too
        bad.append(f"close hits={cl.get('hits')} < truth closes {len(t_closes)}")
    unmapped_n = sum(1 for seq in got.values() for t in seq if t[0] == "read" and t[2] == 0) - len(t_unmapped)
    wrong_tids = [tid for tid in set(want) | set(got) if want.get(tid, []) != got.get(tid, [])]
    if wrong_tids:
        tid = wrong_tids[0]
        w, g = want.get(tid, []), got.get(tid, [])
        i = next((k for k, (p, q) in enumerate(zip(w, g)) if p != q), min(len(w), len(g)))
        bad.append(f"{len(wrong_tids)} thread(s) differ (unmapped reads={unmapped_n}); tid {tid} @{i}/{len(w)}: "
                   f"want {w[i:i + 2]} got {g[i:i + 2]}")
    delivered = sum(1 for o in objs if o.get("kind") == "probe_log")
    in_file = e2e_session_file_logs(stderr_text)
    if not (rep.get("logs_written") == delivered == in_file) or rep.get("log_dropped") != 0 or rep.get("callbacks_interrupted") != 0:
        bad.append(f"logs_written={rep.get('logs_written')} delivered={delivered} file={in_file} "
                   f"dropped={rep.get('log_dropped')} interrupted={rep.get('callbacks_interrupted')}")
    warns = [l[:140] for l in (stderr_text or "").splitlines() if "warning" in l.lower() or "refused" in l.lower()]
    if warns:
        bad.append(f"warnings={warns[:2]}")
    detail = (f"reads={n_read_logs}/{len(t_reads)} opens={op.get('hits')}/{len(t_opens)} closes>={len(t_closes)}:"
              f"{cl.get('hits')} reused={reused} dup_unmapped={len(t_unmapped)} stale_bait={stale_bait} logs={rep.get('logs_written')}/{delivered}/{in_file} "
              f"flag={fl.get('hits')}/{rep.get('overrides')}" + (f" extra_opens={len(extra)}" if extra else ""))
    return not bad, detail + ("" if not bad else " BAD: " + " | ".join(bad))


def e2e_target_args(threads, rounds, truth, parse_early=False):
    return ["--helpers", HELPERS, "--threads", threads, "--reads", rounds, "--churn", "--truth", truth,
            *(["--parse-early"] if parse_early else [])]


def e2e_launch(combo, threads, rounds, truth):
    fb, ob, cb, rb = combo
    r, o = run([exe("gated_config.exe"), "--flag-backend", fb, "--open-backend", ob, "--close-backend", cb,
                "--read-backend", rb, FLAG_LOCATION, READ_LOCATION, "--", exe("probe_app.exe"), "--no-wait",
                *e2e_target_args(threads, rounds, truth)], timeout=240)
    return r.returncode, report(o).get("app_exit"), o, o, r.stderr


def e2e_attach(combo, threads, rounds, truth, post):
    """probe_app runs on its own and waits at its gate (post: with configparse.dll already
    loaded and the config parsed once); uhh_attach attaches by pid, every probe that can arm
    is confirmed active, then the gate is released."""
    fb, ob, cb, rb = combo
    procs = []
    try:
        tgt = subprocess.Popen([str(exe("probe_app.exe")), *map(str, e2e_target_args(threads, rounds, truth, post))],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        procs.append(tgt)
        tout = Lines(tgt.stdout)
        waiting = tout.wait_for(lambda l: '"kind":"waiting"' in l, 60)
        if not waiting:
            raise RuntimeError("target never reached its gate")
        if post and not any('"phase":"early","reads_enabled":0' in l for l in tout.lines):
            raise RuntimeError("no early parse before the gate")
        att = subprocess.Popen([str(exe("uhh_attach.exe")), str(json.loads(waiting)["pid"]), "--flag-backend", fb,
                                "--open-backend", ob, "--close-backend", cb, "--read-backend", rb],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        procs.append(att)
        aout, aerr = Lines(att.stdout), Lines(att.stderr)
        if not aout.wait_for(lambda l: '"kind":"attached"' in l, 60):
            raise RuntimeError(f"uhh_attach did not attach: {aerr.lines[-3:]}")
        for loc in (OPEN_LOCATION, E2E_CLOSE_LOCATION, READ_LOCATION) + ((FLAG_LOCATION,) if post else ()):
            if not aerr.wait_for(lambda l, loc=loc: l.startswith(f"probe: active {loc} "), 60):
                raise RuntimeError(f"{loc} never became active: {aerr.lines[-3:]}")
        tgt.stdin.write("x"); tgt.stdin.flush()
        tgt.wait(timeout=240); att.wait(timeout=60)
        o, t_objs = aout.objs(), tout.objs()
        aerr.t.join(timeout=30)
        return att.returncode, tgt.returncode, o, t_objs, "\n".join(aerr.lines)
    finally:
        for pr in procs:                    # only the processes this run started
            if pr.poll() is None:
                pr.kill()


def check_gated_e2e(threads=8, rounds=16):
    """The flagship use case (examples/gated_config + examples/attach) end to end with EXACT
    ground truth written by the target itself (probe_app --churn --truth): EVERY assignment of
    the four roles -- flag (configparse.dll!ParseConfig+0x16), open (ntdll!NtOpenProcess,
    call_original map), close (ntdll!NtClose, forget) and read (ntdll!NtReadVirtualMemory) --
    over {breakpoint, hw, inline} (81; at most 4 hw probes, so none exceeds the debug registers:
    an hw open's call_original borrows its own DR when all 4 are taken), in three modes:
      launch      gated_config launches probe_app;
      attach-pre  uhh_attach attaches at the gate, before configparse.dll is loaded (flag pending);
      attach-post probe_app --parse-early: configparse.dll loaded and the config parsed once
                  before the gate; the flag probe arms on the loaded module, the reload counts.
    The workload: helpers opened, read (1..256 bytes, through ReadThunk and ReadProcessMemory)
    and closed over and over from several threads (handle values reused for different pids;
    asserted). Exact: one flag hit and one override; per target thread the delivered `open`,
    `map` and `read` logs equal the target's own record in order (right pid and name for a
    reused handle, no unmapped read; a read through a DUPLICATED helper handle -- never seen by
    the open probe, usually holding a value the map knew -- logged unmapped, pid 0: the close
    probe forgot the old value); read hits == read logs == truth; open hits == truth;
    logs_written == delivered on stdout == records in the session file; nothing dropped or
    interrupted; no warning; checksum == an uninstrumented run; exit 0 everywhere.
    UHH_E2E=<comma substrings of the record name> runs a subset (debugging)."""
    g, a, p = exe("gated_config.exe"), exe("uhh_attach.exe"), exe("probe_app.exe")
    if not g or not a or not p:
        return missing_bin("gated-e2e", "gated_config/uhh_attach/probe_app")
    sel = [x for x in os.environ.get("UHH_E2E", "").split(",") if x]
    tmp = Path(tempfile.gettempdir()) / f"uhh-e2e-{os.getpid()}"
    tmp.mkdir(exist_ok=True)
    base = {}
    try:
        _, bo = run([p, "--no-wait", *e2e_target_args(threads, rounds, tmp / "base.jsonl"),
                     "--config", "reads_enabled=1"], timeout=120)
        base = app(bo)
        bt = e2e_truth(tmp / "base.jsonl")
        ok = (base.get("reads_enabled") == 1 and base.get("successful_reads") == sum(e["op"] in ("read", "read-unmapped") for e in bt) > 0
              and base.get("opened") + sum(e["op"] == "dup" for e in bt) == sum(e["op"] == "close" for e in bt)
              and base.get("opened") == sum(e["op"] == "open" for e in bt))
        record("gated-e2e-baseline", ok, f"uninstrumented: reads={base.get('successful_reads')} opens={base.get('opened')} "
                                         f"dups={sum(e['op'] == 'dup' for e in bt)} "
                                         f"checksum={base.get('checksum')}")
        if not ok:
            return
    except Exception as e:
        return record("gated-e2e-baseline", False, repr(e))
    combos = [(f, o, c, r) for f in E2E_BACKENDS for o in E2E_BACKENDS for c in E2E_BACKENDS for r in E2E_BACKENDS]
    for mode in ("launch", "attach-pre", "attach-post"):
        for combo in combos:
            name = f"gated-e2e-{mode}-" + "-".join(f"{k}{E2E_SHORT[b]}" for k, b in zip("focr", combo))
            if sel and not any(s in name for s in sel):
                continue
            truth_path = tmp / "truth.jsonl"
            try:
                truth_path.unlink(missing_ok=True)
                if mode == "launch":
                    rc, trc, o, t_objs, err = e2e_launch(combo, threads, rounds, truth_path)
                else:
                    rc, trc, o, t_objs, err = e2e_attach(combo, threads, rounds, truth_path, mode == "attach-post")
                truth = e2e_truth(truth_path) if truth_path.exists() else []
                ok, detail = e2e_judge(combo, rc, trc, o, t_objs, err, truth, base)
                record(name, ok, detail)
            except Exception as e:
                record(name, False, repr(e)[:300])
    shutil.rmtree(tmp, ignore_errors=True)


def main():
    global BIN
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", type=Path, default=Path("build-x64/Release"))
    ap.add_argument("--threads", default="8")
    ap.add_argument("--reads", default="1000")
    ap.add_argument("--volume-reads", default="0",
                    help="per-thread reads for the opt-in no-drop-at-scale tier (e.g. 250000 = 2M); 0 skips")
    ap.add_argument("--bigapps", nargs="?", const="all", default="",
                    help="opt-in slow tier: real large apps (powershell, headless Edge) under every backend, "
                         "launch/attach/detach; optional comma list of name substrings (e.g. ps-launch,edge-detach)")
    ap.add_argument("--bigapps-secs", type=int, default=40, help="workload length of each bigapps run")
    ap.add_argument("--soak-minutes", type=float, default=0,
                    help="opt-in soak tier (scripts/soak.py): every phase for this many minutes; 0 skips")
    ap.add_argument("--only", default="",
                    help="comma-separated substrings of check FUNCTION names (check_logs_order; '-' matches '_', "
                         "so logs-order and check-logs-order work too) to run (default: all). Record names such as "
                         "inplace-jmp8 are NOT matched (use inplace). A selector that matches no check function, or a "
                         "selection that runs no check, is an error (exit 2)")
    args = ap.parse_args()
    BIN = args.bin.resolve()
    only = [x for x in args.only.split(",") if x]
    ONLY[:] = only

    def fn_names(fn):
        return (fn.__name__, fn.__name__.replace("_", "-"))
    if only:
        check_fns = [v for k, v in globals().items() if k.startswith("check_") and callable(v)]
        unmatched = [o for o in only if not any(o in n for fn in check_fns for n in fn_names(fn))]
        if unmatched:
            print(f"regress.py: --only selector(s) {unmatched} match no check function (substrings of check_* "
                  f"function names; '-' for '_'). Nothing was run.", file=sys.stderr)
            sys.exit(2)
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
        # Also matches the hyphenated name (check_logs_order -> check-logs-order), so
        # --only logs- selects the logs-* family by its record-name prefix.
        return not only or any(o in n for o in only for n in fn_names(fn))
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
    if want(check_portability): check_portability()
    if want(check_callorig_hunt): check_callorig_hunt()
    if want(check_callconv): check_callconv()
    if want(check_agent_review): check_agent_review()
    if want(check_callfunc_registry): check_callfunc_registry()
    if want(check_transparency): check_transparency()
    if want(check_interrupt): check_interrupt()
    if want(check_agent_crt): check_agent_crt()
    if want(check_oldcrt): check_oldcrt()
    if want(check_cet): check_cet()
    if want(check_cet_policy): check_cet_policy()
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
    if want(check_stdout_forward): check_stdout_forward()
    if want(check_blog_replicas): check_blog_replicas()
    if want(check_blog_pwsh_attach): check_blog_pwsh_attach()
    if want(check_entry_hold_threads): check_entry_hold_threads()
    if want(check_late_dll_worker): check_late_dll_worker()
    if want(check_latedll): check_latedll()
    if want(check_hw_once_slots): check_hw_once_slots()
    if want(check_prehook_chain): check_prehook_chain()
    if want(check_stacks): check_stacks()
    if args.bigapps:
        if want(check_bigapps): check_bigapps(args.bigapps_secs, args.bigapps)
    if want(check_realapps): check_realapps()
    if args.soak_minutes > 0:
        if want(check_soak): check_soak(args.soak_minutes)
    if want(check_ctrl_review): check_ctrl_review()
    if want(check_cdx_review): check_cdx_review()
    if want(check_newapp_files): check_newapp_files()
    if want(check_newapp_flag): check_newapp_flag()
    if want(check_newapp_reg): check_newapp_reg()
    if want(check_logs_format): check_logs_format()
    if want(check_logs_order): check_logs_order()
    if want(check_logs_wedge): check_logs_wedge()
    if want(check_logs_controller_killed): check_logs_controller_killed()
    if want(check_logs_stdout_closed): check_logs_stdout_closed()
    if want(check_inplace_shapes): check_inplace_shapes()
    if want(check_lifecycle): check_lifecycle()
    if want(check_cet_sde): check_cet_sde()
    if want(check_cxlib): check_cxlib()
    if want(check_symbols_grammar): check_symbols_grammar()
    if want(check_quickstart): check_quickstart()
    if want(check_gated_e2e): check_gated_e2e()
    if only and not RESULTS:
        print(f"regress.py: --only {','.join(only)} selected only opt-in tiers that were not enabled "
              f"(--bigapps / --soak-minutes / --volume-reads): no check ran.", file=sys.stderr)
        sys.exit(2)
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
