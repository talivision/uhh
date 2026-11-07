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
  - realbig-<app>-<mode>-<backend>: robocopy /MT:16 and findstr /s on a generated tree,
    PowerShell 5.1 / pwsh 7 (JIT), and a sandboxed Edge renderer / the browser while a page
    ticks, attached and detached mid-run: the program's own result, hits == logs ==
    delivered, a flat controller, and NO residue after the detach (the target's code
    compared with itself before the attach, every thread's DRs/TF, the debug port). A
    default subset; every row with --bigapps.
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
import io
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


def stream_run(args, timeout, on_line, on_err=None):
    """Drain stdout incrementally so volume checks never retain probe_log records. on_err(line):
    every stderr line (else stderr is drained and dropped)."""
    proc = subprocess.Popen([str(a) for a in args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
    timed_out = threading.Event()

    def drain_stderr():
        for line in proc.stderr:
            if on_err:
                on_err(line.rstrip("\r\n"))
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
    """The controller's peak must be independent of total streamed-log volume. inline: two 2M runs
    and one 20M run; flat = the 20M peak <= max(1.2 x, +8 MB over) the larger 2M peak. (A single 2M
    run does not always reach the pipeline's plateau: 0fb6cee on the VM, x64, peaked 14 MB at 2M
    and 22 MB at 20M in one of four runs, 22 -> 22 in the others; CI x86 18 -> 24. A leak of half a
    byte per record still shows: +8 MB over the 18M extra records.)"""
    if not exe("hitcost_driver.exe") or not exe("hitcost_target.exe"):
        return missing_bin("stream-volume", "hitcost driver/target")
    for backend in ("inline", "hw", "breakpoint"):
        name = f"stream-volume-{backend}"
        try:
            sizes = (2_000_000, 2_000_000, 20_000_000) if backend == "inline" else (200_000,)
            runs = [stream_volume_once(backend, n, 1800) for n in sizes]
            exact = all(not x["timeout"] and x["rc"] == 0 and x["logs"] == n and
                        x["hits"] == n and x["report"].get("logs_written") == n and
                        x["report"].get("log_dropped") == 0
                        for x, n in zip(runs, sizes))
            peaks = [x["peak"] for x in runs]
            small = all(isinstance(p, (int, float)) and 0 < p <= 256 for p in peaks)
            flat = (backend != "inline" or
                    (small and peaks[2] <= max(max(peaks[:2]) * 1.20, max(peaks[:2]) + 8)))
            record(name, exact and small and flat,
                   " ".join(f"N={n:,} logs={x['logs']:,} hits={x['hits']} written={x['report'].get('logs_written')} "
                            f"drop={x['report'].get('log_dropped')} peak={x['peak']}MB rc={x['rc']}"
                            for x, n in zip(runs, sizes)) + f" flat={flat}")
        except Exception as e:
            record(name, False, repr(e))


def check_stream_live(calls=2_000_000):
    """Logs arrive LIVE under full load, not in a burst at the end. hitcost_target passes a
    QueryPerformanceCounter timestamp (us, low 31 bits) as the probed function's argument;
    send_log logs it; this reader stamps each chunk of stdout as it arrives with the SAME
    counter and computes the lag of every 64th log, plus the gaps between arrivals and how
    many logs arrived before the target printed its final line. Bar (as stream-latency, whose
    calibration this reuses): every log delivered, >= 90% of them before the target's final
    line, and the lag
      - quiet machine (the concurrent noise sampler -- an uninstrumented writer, a line every
        ~5 ms -- saw < 50 ms of stall in the whole run): p99 < 250 ms, absolute (the original bar);
      - noisy machine (a shared VM, a 2-core runner): p99 of (lag - the stall the sampler saw in
        that log's own window [event, arrival]) < 250 ms -- the machine's stalls are not UHH's
        (same build, VM under load: p99 0.7-253 ms over 18 runs, one 1102 ms), but latency UHH
        adds on top of them still fails.
    The controller's %TEMP% (its session file) is <build dir>/uhh-latency-tmp, as stream-latency's
    (a local, AV-excluded dir on the test machines: the check measures UHH, not the profile's AV)."""
    driver, target, sampler_exe = exe("hitcost_driver.exe"), exe("hitcost_target.exe"), exe("logstream_target.exe")
    if not driver or not target or not sampler_exe:
        return missing_bin("stream-live", "hitcost driver/target, logstream_target")
    import re as _re
    freq = _qpc_freq()
    tms = lambda ticks: ticks * 1000.0 / freq
    tmp = Path(BIN).resolve().parent / "uhh-latency-tmp"
    tmp.mkdir(exist_ok=True)
    env = dict(os.environ, TEMP=str(tmp), TMP=str(tmp))
    quiet_ms, bar_ms = 50.0, 250.0
    pct = lambda vals, q: sorted(vals)[max(0, math.ceil(q * len(vals)) - 1)] if vals else float("inf")
    for backend, n in (("inline", calls), ("hw", 50_000), ("breakpoint", 50_000)):
        name = f"stream-live-{backend}"
        sampler = None
        try:
            sampler = _NoiseSampler(sampler_exe, tmp)
            time.sleep(0.2)
            p = subprocess.Popen([str(driver), "--backend", backend, "--method", "send_log", "--",
                                  str(target), "--calls", str(n), "--threads", "1", "--no-wait", "--qpc-arg"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
            samples, gaps, logs, before_exit, exited, last, buf = [], [], 0, 0, False, None, b""
            rx = _re.compile(rb'"message":"hit (-?\d+)"')
            while True:
                chunk = p.stdout.read1(1 << 20)
                if not chunk:
                    break
                now = _qpc_now()
                now_us = (now // freq) * 1_000_000 + (now % freq) * 1_000_000 // freq   # the target's formula
                if last is not None:
                    gaps.append(now - last)
                last = now
                buf += chunk
                lines = buf.split(b"\n"); buf = lines.pop()
                for line in lines:
                    if b'"kind":"probe_log"' in line:
                        logs += 1
                        if not exited:
                            before_exit += 1
                        if logs % 64 == 0:
                            m = rx.search(line)
                            if m:
                                lag = ((now_us - int(m.group(1))) & 0x7FFFFFFF) * freq // 1_000_000   # ticks, 31-bit us wrap
                                samples.append((lag, now - lag, now))       # (lag, event, arrival)
                    elif b'"kind":"target"' in line:
                        exited = True
            p.wait(timeout=600)
            sampler.stop()
            lags = [x[0] for x in samples]
            excess = [lag - sampler.noise(ev, arr) for lag, ev, arr in samples]
            run_noise = max([0] + [late for _, _, late in sampler.late] + [arr - w for w, arr in sampler.samples])
            quiet = tms(run_noise) < quiet_ms and len(sampler.samples) >= 100
            p50, p99, p99x = pct(lags, .5), pct(lags, .99), pct(excess, .99)
            frac = before_exit / logs if logs else 0
            lat_ok = bool(samples) and tms(p99 if quiet else p99x) < bar_ms
            ok = p.returncode == 0 and logs == n and lat_ok and frac >= 0.9
            record(name, ok, f"logs={logs:,}/{n:,} {'quiet' if quiet else 'noisy'}: "
                             f"bar={'p99' if quiet else 'p99(lag-noise)'}<{bar_ms:.0f}ms lag_p50={tms(p50):.1f}ms "
                             f"lag_p99={tms(p99):.1f}ms p99_excess={tms(p99x):.1f}ms lag_max={tms(max(lags, default=0)):.1f}ms "
                             f"max_gap={tms(max(gaps, default=0)):.1f}ms noise_run_max={tms(run_noise):.1f}ms "
                             f"sampler={len(sampler.samples)}@{tms(sampler.period):.1f}ms "
                             f"disk_run_max={tms(max((e - b for b, e in sampler.disk), default=0)):.1f}ms "
                             f"before_target_exit={frac:.1%} rc={p.returncode}")
        except Exception as e:
            if sampler and sampler.p.poll() is None:
                sampler.p.kill()
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


def _qpc_now():
    """QueryPerformanceCounter ticks: the clock logstream_target stamps its lines with (one
    system-wide counter, so arrival - stamp is a real cross-process latency)."""
    import ctypes
    c = ctypes.c_int64()
    ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(c))
    return c.value


def _qpc_freq():
    import ctypes
    f = ctypes.c_int64()
    ctypes.windll.kernel32.QueryPerformanceFrequency(ctypes.byref(f))
    return f.value


class _NoiseSampler:
    """Scheduler noise on THIS machine, measured alongside the run it calibrates (a cyclictest):
    an uninstrumented logstream_target writes a QPC-stamped line every ~5 ms into a pipe read
    by a Python thread. A stall of the machine (or of a thread's CPU) shows as a late write
    (a gap between consecutive stamps beyond the writer's normal period) or a late arrival
    (arrival - stamp). noise(a, b) = the worst of both overlapping the window [a, b]."""
    def __init__(self, target, tmp):
        self.samples = []                     # (w, arrival) in QPC ticks
        self.p = subprocess.Popen([str(target), "--count", "1000000", "--delay", "5"],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.t = threading.Thread(target=self._read, daemon=True)
        self.t.start()
        # The disk side, as UHH writes its session log (GetTempPath()\uhh\logs, cached appends):
        # each ~5 ms a 120-byte append to a file there, timed: reported (disk_run_max), never
        # discounted -- a stall of UHH's own file is not coincident with this one's, and UHH
        # writing the file before stdout is its design (docs/ROADMAP.md, CI section).
        self.disk, self._stop = [], threading.Event()
        self.dt = threading.Thread(target=self._disk, args=(tmp,), daemon=True)
        self.dt.start()

    def _read(self):
        for line in self.p.stdout:
            arrival = _qpc_now()
            m = re.search(r'"w":(-?\d+)', line)
            if m and int(m.group(1)) > 0:
                self.samples.append((int(m.group(1)), arrival))

    def _disk(self, tmp):
        d = Path(tmp) / "uhh" / "logs"
        d.mkdir(parents=True, exist_ok=True)
        f = open(d / f"latency-sampler-{os.getpid()}-{threading.get_ident()}.tmp", "wb", buffering=0)
        try:
            line = b"x" * 119 + b"\n"
            while not self._stop.wait(0.005):
                a = _qpc_now()
                f.write(line)
                self.disk.append((a, _qpc_now()))
        finally:
            f.close()
            try:
                os.unlink(f.name)
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        self.dt.join(timeout=10)
        try:
            self.p.kill()
        except OSError:
            pass
        self.p.wait()
        self.t.join(timeout=10)
        s = self.samples
        gaps = sorted(b[0] - a[0] for a, b in zip(s, s[1:]))
        self.period = gaps[len(gaps) // 2] if gaps else 0         # the writer's normal period (median)
        # per interval between consecutive writes: (start, end, lateness) ; per write: delivery latency
        self.late = [(a[0], b[0], max(0, b[0] - a[0] - self.period)) for a, b in zip(s, s[1:])]
        # Indexes for noise(): the intervals are consecutive (starts and ends ascending), the
        # write stamps ascending (one writer); a write delivered at or after a was written at or
        # after a - the longest delivery.
        self._starts = [x[0] for x in self.late]
        self._ends = [x[1] for x in self.late]
        self._lates = [x[2] for x in self.late]
        self._ws = [w for w, _ in s]
        self._maxdel = max((arr - w for w, arr in s), default=0)
        return self

    def noise(self, a, b):
        """Worst write lateness / delivery latency (QPC ticks) overlapping [a, b]."""
        import bisect
        worst = 0
        i0, i1 = bisect.bisect_left(self._ends, a), bisect.bisect_right(self._starts, b)
        if i0 < i1:
            worst = max(self._lates[i0:i1])
        j = bisect.bisect_right(self._ws, b)
        floor = a - self._maxdel
        while j > 0 and self._ws[j - 1] >= floor:
            j -= 1
            w, arr = self.samples[j]
            if arr >= a:
                worst = max(worst, arr - w)
        return worst


def _trace_logstream_staged(backend, consume, file_seen, env=None, timeout=120, tracer_name="uhh_trace.exe"):
    """trace_logstream, plus the session log file watched as it grows: file_seen[i] = QPC when
    LogSite(i)'s record was in the FILE (UHH writes each batch to the file, then to stdout), so a
    late record shows which stage held it: before the file (queue / writer) or after (stdout)."""
    tracer, target = exe(tracer_name), exe("logstream_target.exe")
    proc = subprocess.Popen([str(tracer), "--backend", backend, "-p", "logstream_target.exe!LogSite:d", "--",
                             str(target)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
                            env=env)
    path, have_path, done, timed_out = [], threading.Event(), threading.Event(), threading.Event()

    def drain_stderr():
        for line in proc.stderr:
            if line.startswith("probe: logs -> ") and not path:
                path.append(line[len("probe: logs -> "):].strip()); have_path.set()

    def watch():
        if not have_path.wait(60):
            return
        try:
            f = open(path[0], "rb")
        except OSError:
            return
        with f:
            buf = b""
            while True:
                last = done.is_set()
                chunk = f.read()
                if chunk:
                    now = _qpc_now()
                    buf += chunk
                    *lines, buf = buf.split(b"\n")
                    for l in lines:
                        m = re.search(rb'"message":"LogSite\((-?\d+)\)"', l)
                        if m:
                            file_seen.setdefault(int(m.group(1)), now)
                elif last:
                    return
                else:
                    time.sleep(0.001)

    threads = [threading.Thread(target=drain_stderr, daemon=True), threading.Thread(target=watch, daemon=True)]
    for t in threads:
        t.start()
    timer = threading.Timer(timeout, lambda: (timed_out.set(), proc.kill()))
    timer.daemon = True
    timer.start()
    try:
        for line in proc.stdout:
            consume(line.rstrip("\r\n"), None)
        proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill(); proc.wait()
        done.set()
        for t in threads:
            t.join(timeout=30)
        if path:
            try:
                Path(path[0]).unlink()
            except OSError:
                pass
    return proc.returncode, timed_out.is_set()


def check_stream_latency():
    """Live log latency: a record reaches the controller's stdout reader promptly after the
    event that made it. logstream_target calls LogSite(i) every 100 ms (50 calls) and stamps,
    with QueryPerformanceCounter, each call (field "t" of the next tick line) and each of its
    own stdout lines (field "w"); the reader stamps arrivals with the same counter. Per
    backend: all 50 records arrive, each once and in call order, never before its event
    (clock sanity), nothing dropped, and the latency event -> arrival meets the bar:
      - quiet machine (the concurrent noise sampler, an uninstrumented writer, saw < 50 ms of
        stall in the whole run): p99 < 100 ms, absolute (the original bar);
      - noisy machine (a shared VM, a 2-core cloud runner): p99 of (latency - the stall the
        sampler saw in that same record's window) < 100 ms -- the machine's own stalls are not
        UHH's, but any latency UHH adds on top of them still fails.
    The target's own lines are forwarded by UHH separately from the records (a pipe and a
    forwarder thread), so a record can reach stdout before the tick line written just before
    its event: reported (log_before_tick), not required (no such cross-stream promise).
    Diagnosis of a late record: the session log file is watched too (UHH writes each batch to
    it, then to stdout): in_file / p99_to_file = event -> in the file, p99_file_to_out = file
    -> stdout; disk_run_max = the longest 120-byte append the sampler saw in that temp dir.
    The controller's %TEMP% (where UHH puts its session file) is <build dir>/uhh-latency-tmp,
    next to the binaries: a local, AV-excluded directory on the test machines (the VM's
    C:/work, the CI workspace). UHH wrote every batch to that file before (or beside) stdout on
    one thread, so a stalling file write held live records: a real-time AV scan of the new file
    in %TEMP% (VM: 180-430 ms at records #8-#10), a slow disk (CI runners' C:: 50 ms-2.5 s), the
    cache manager flushing the new file ~1 s in (VM: 16 ms-1.5 s at record #8; the 327 ms FAIL
    on 0fb6cee). Since codex3 #5 stdout comes first and the file has a thread of its own
    (regress stream-filestall-*; docs/ROADMAP.md "Codex review 3")."""
    tracer, target = exe("uhh_trace.exe"), exe("logstream_target.exe")
    if not tracer or not target:
        return missing_bin("stream-latency", "uhh_trace/logstream_target")
    freq = _qpc_freq()
    ms = lambda ticks: ticks * 1000.0 / freq
    tmp = Path(BIN).resolve().parent / "uhh-latency-tmp"          # the controller's %TEMP%: see the docstring
    tmp.mkdir(exist_ok=True)
    env = dict(os.environ, TEMP=str(tmp), TMP=str(tmp))
    quiet_ms, bar_ms, n = 50.0, 100.0, 50      # quiet: < ~3 timer quanta (15.6 ms) of stall
    for backend in ("inline", "hw", "breakpoint"):
        name = f"stream-latency-{backend}"
        ticks, logs, log_seq, objects, in_file = {}, {}, [], [], {}
        sampler = None
        try:
            def consume(line, _arrival):
                arrival = _qpc_now()
                if not line.startswith("{"):
                    return
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    return
                if obj.get("kind") == "tick":
                    ticks.setdefault(obj.get("i"), (arrival, obj.get("w"), obj.get("t")))
                elif obj.get("kind") == "probe_log":
                    match = re.fullmatch(r"LogSite\((-?\d+)\)", str(obj.get("message", "")))
                    if match:
                        i = int(match.group(1))
                        log_seq.append(i)
                        logs.setdefault(i, arrival)
                else:
                    objects.append(obj)

            sampler = _NoiseSampler(target, tmp)
            time.sleep(0.2)
            rc, timed_out = _trace_logstream_staged(backend, consume, in_file, env)
            sampler.stop()
            # event i's stamp travels in tick i+1 ("t"); a tick's own write stamp is "w"
            events = {i: ticks[i + 1][2] for i in range(n) if i + 1 in ticks and (ticks[i + 1][2] or 0) > 0}
            lat = {i: logs[i] - events[i] for i in range(n) if i in logs and i in events}
            fwd = [ticks[i][0] - ticks[i][1] for i in range(n) if i in ticks]
            noise = {i: sampler.noise(events[i], logs[i]) for i in lat}
            excess = {i: lat[i] - noise[i] for i in lat}
            pct = lambda vals, q: sorted(vals)[max(0, math.ceil(q * len(vals)) - 1)] if vals else float("inf")
            p50, p99 = pct(list(lat.values()), .5), pct(list(lat.values()), .99)
            p99_excess = pct(list(excess.values()), .99)
            run_noise = max((late for _, _, late in sampler.late), default=0)
            run_noise = max([run_noise] + [arr - w for w, arr in sampler.samples])
            quiet = ms(run_noise) < quiet_ms and len(sampler.samples) >= 100
            causal = all(v >= 0 for v in lat.values()) and all(v >= 0 for v in fwd)
            in_order = log_seq == list(range(n))
            before_tick = sum(1 for i in range(n) if i in logs and i in ticks and logs[i] < ticks[i][0])
            rep = report(objects)
            complete = len(lat) == n and len(ticks) == n + 1
            lat_ok = ms(p99 if quiet else p99_excess) < bar_ms
            ok = (not timed_out and rc == 0 and complete and in_order and causal and lat_ok and
                  rep.get("logs_written") == n and rep.get("log_dropped") == 0)
            worst = sorted(lat, key=lat.get)[-3:][::-1]
            record(name, ok,
                   f"pairs={len(lat)}/{n} ticks={len(ticks)}/{n + 1} in_order={in_order} causal={causal} "
                   f"{'quiet' if quiet else 'noisy'}: bar={'p99' if quiet else 'p99(latency-noise)'}<{bar_ms:.0f}ms "
                   f"p50={ms(p50):.1f}ms p99={ms(p99):.1f}ms p99_excess={ms(p99_excess):.1f}ms "
                   f"worst(#,ms,noise,in_file)={[(i, round(ms(lat[i]), 1), round(ms(noise[i]), 1), round(ms(in_file[i] - events[i]), 1) if i in in_file else None) for i in worst]} "
                   f"p99_to_file={ms(pct([in_file[i] - events[i] for i in lat if i in in_file], .99)):.1f}ms "
                   f"p99_file_to_out={ms(pct([logs[i] - in_file[i] for i in lat if i in in_file], .99)):.1f}ms "
                   f"disk_run_max={ms(max((e - b for b, e in sampler.disk), default=0)):.1f}ms "
                   f"tmp={tmp} "
                   f"noise_run_max={ms(run_noise):.1f}ms sampler={len(sampler.samples)}@{ms(sampler.period):.1f}ms "
                   f"fwd_p99={ms(pct(fwd, .99)):.1f}ms log_before_tick={before_tick} "
                   f"written={rep.get('logs_written')} dropped={rep.get('log_dropped')} rc={rc}"
                   + (" TIMEOUT" if timed_out else "")
                   + ("" if in_order else f" seq={log_seq[:8]}..."))
            if backend == "inline":
                # Inline after a quiet spell: the agent wakes the sleeping drainer (agent protocol
                # v26, probe_agent_drain_wait) -- a record 100 ms after the last one is not left
                # for the drainer's next timer tick (15.6 ms: the p50 here before the wake-up).
                # Median, so the machine's own stalls do not decide it (noisy: minus the noise).
                p50_wake = p50 if quiet else pct(list(excess.values()), .5)
                record("stream-latency-inline-wake", complete and ms(p50_wake) < 8.0,
                       f"p50={ms(p50):.2f}ms p50_excess={ms(pct(list(excess.values()), .5)):.2f}ms "
                       f"({'quiet' if quiet else 'noisy'}; bar p50 < 8 ms, half a 15.6 ms timer tick) pairs={len(lat)}/{n}")
        except Exception as e:
            if sampler and sampler.p.poll() is None:
                sampler.p.kill()
            record(name, False, repr(e))


def check_stream_filestall():
    """codex3 #5: a session-file write that stalls must not hold live records. The writer wrote
    every batch to the session file before (forwarded target stdout) or beside (stdout_mu held)
    stdout, on one thread: a WriteFile that blocked -- the cache manager flushing the new file
    ~1 s after its creation, 16 ms to 1.5 s on the VM; an AV scan -- held every record queued
    meanwhile, then released them together (stream-latency-breakpoint: records #8-#10 at
    327/216/107 ms). Forced deterministically: uhh_trace_th (test-hook controller library),
    UHH_TEST_FILE_STALL_MS=400 on the session file's 8th append, the logstream run of
    stream-latency (LogSite every 100 ms, 50 calls). Per backend (breakpoint, inline): all 50
    records, in order, nothing dropped; the stall is visible in the FILE (a record reached it
    >= 300 ms late) but no record reached stdout more than 150 ms after its event."""
    if not exe("uhh_trace_th.exe") or not exe("logstream_target.exe"):
        return missing_bin("stream-filestall", "uhh_trace_th/logstream_target")
    freq = _qpc_freq()
    ms = lambda ticks: ticks * 1000.0 / freq
    tmp = Path(BIN).resolve().parent / "uhh-latency-tmp"
    tmp.mkdir(exist_ok=True)
    env = dict(os.environ, TEMP=str(tmp), TMP=str(tmp), UHH_TEST_FILE_STALL_MS="400", UHH_TEST_FILE_STALL_AT="8")
    n = 50
    for backend in ("breakpoint", "inline"):
        name = f"stream-filestall-{backend}"
        ticks, logs, log_seq, objects, in_file = {}, {}, [], [], {}
        try:
            def consume(line, _arrival):
                arrival = _qpc_now()
                if not line.startswith("{"):
                    return
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    return
                if obj.get("kind") == "tick":
                    ticks.setdefault(obj.get("i"), (arrival, obj.get("w"), obj.get("t")))
                elif obj.get("kind") == "probe_log":
                    m = re.fullmatch(r"LogSite\((-?\d+)\)", str(obj.get("message", "")))
                    if m:
                        log_seq.append(int(m.group(1))); logs.setdefault(int(m.group(1)), arrival)
                else:
                    objects.append(obj)

            rc, timed_out = _trace_logstream_staged(backend, consume, in_file, env, tracer_name="uhh_trace_th.exe")
            events = {i: ticks[i + 1][2] for i in range(n) if i + 1 in ticks and (ticks[i + 1][2] or 0) > 0}
            lat = {i: ms(logs[i] - events[i]) for i in range(n) if i in logs and i in events}
            to_file = {i: ms(in_file[i] - events[i]) for i in lat if i in in_file}
            rep = report(objects)
            worst = max(lat, key=lat.get) if lat else None
            worst_file = max(to_file, key=to_file.get) if to_file else None
            bad = []
            if timed_out or rc != 0: bad.append(f"rc={rc} timeout={timed_out}")
            if len(lat) != n or log_seq != list(range(n)): bad.append(f"pairs={len(lat)}/{n} in_order={log_seq == list(range(n))}")
            if rep.get("logs_written") != n or rep.get("log_dropped") != 0:
                bad.append(f"written={rep.get('logs_written')} dropped={rep.get('log_dropped')}")
            if worst_file is None or to_file[worst_file] < 300: bad.append(f"stall not seen in the file (max to_file={to_file.get(worst_file)})")
            if worst is None or lat[worst] >= 150: bad.append(f"stdout held: #{worst} {lat.get(worst, 0):.1f} ms")
            record(name, not bad, " ".join(bad) or
                   f"file stalled (#{worst_file} reached the file {to_file[worst_file]:.0f} ms late), stdout not: "
                   f"worst #{worst} {lat[worst]:.1f} ms; 50/50 in order")
        except Exception as e:
            record(name, False, repr(e))


def _filefail_run(args, env, timeout):
    """A test-hook controller run with binary pipes: (rc, timed_out, stdout records, target text,
    report, session-file records, stderr). The session file (named on stderr) is read, then deleted."""
    p = subprocess.Popen([str(a) for a in args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env)
    timed_out = False
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        subprocess.run(["taskkill", "/f", "/t", "/pid", str(p.pid)], capture_output=True)
        out, err = p.communicate()
    recs, text, _ = stdout_split(out)
    errtext = err.decode("utf-8", "replace")
    m = re.search(r"^probe: logs -> (.+?)\r?$", errtext, re.M)
    file_recs = []
    if m:
        path = Path(m.group(1).strip())
        try:
            for line in path.read_bytes().split(b"\n"):
                if line.startswith(b'{"kind":"probe_log"'):
                    try:
                        file_recs.append(json.loads(line))
                    except ValueError:
                        file_recs.append({})
            path.unlink()
        except OSError:
            pass
    logs = [r for r in recs if r.get("kind") == "probe_log"]
    rep = next((r for r in recs if r.get("kind") == "probe_report"), {})
    return p.returncode, timed_out, logs, text, rep, file_recs, errtext


def check_stream_filefail():
    """codex4 #1-#3: the session file's appender thread (log_filer_main, a37911d) failing. The
    behaviour kept from 0fb6cee (the synchronous file write): a failed file write is an error
    (stderr, report "error"), logs_written counts the records IN THE FILE (the file holds seq
    0..logs_written-1, nothing missing in between), every later record is in log_dropped -- also
    the ones stdout already had: stdout holds seq 0..stdout_logs-1 (stdout_logs >= logs_written)
    -- the error says the file is incomplete, hits == logs_written + log_dropped + interrupted,
    and nothing hangs or crashes. Forced with uhh_trace_th (test-hook controller):
      - queued-<bk>: UHH_TEST_FILE_FAIL_AT=8 on the append stalled 400 ms (UHH_TEST_FILE_STALL_*),
        the logstream run (a record every 100 ms): records queue up behind the failing append.
        Before: the queued records were counted in logs_written but never reached the file.
      - deferred-<bk>: stdout_target deferred (5 probed calls while the target's stdout is inside
        an unfinished line: their records wait in the file for its newline), the first append
        fails. Before: probe_report / probe_wait_for_exit waited forever for those records.
      - throw-spare: the appender's recycling of its 3rd chunk throws bad_alloc (the
        file_spare.push_back). Before: std::terminate. Now: harmless (the chunk is not
        recycled): all 50 records, no error.
      - throw-append: the appender throws before its 3rd append: a failed append, as above."""
    tr, ls, so = exe("uhh_trace_th.exe"), exe("logstream_target.exe"), exe("stdout_target.exe")
    if not tr or not ls or not so:
        return missing_bin("stream-filefail", "uhh_trace_th/logstream_target/stdout_target")
    seq_ok = lambda recs: [r.get("seq") for r in recs] == list(range(len(recs)))

    def judge(name, res, expect_fail, need_more_on_stdout=False, extra=None):
        rc, timed_out, logs, text, rep, file_recs, errtext = res
        bad = []
        if timed_out: bad.append("controller HUNG (killed)")
        if not rep: bad.append(f"no probe_report (rc={rc:#x})")
        written, dropped, stdout_logs = rep.get("logs_written"), rep.get("log_dropped"), rep.get("stdout_logs")
        hits, intr = rep.get("hits"), rep.get("callbacks_interrupted") or 0
        err = rep.get("error") or ""
        if rep:
            if written != len(file_recs) or not seq_ok(file_recs):
                bad.append(f"file has {len(file_recs)} records (seq ok={seq_ok(file_recs)}), logs_written={written}")
            if stdout_logs != len(logs) or not seq_ok(logs):
                bad.append(f"stdout has {len(logs)} records (seq ok={seq_ok(logs)}), stdout_logs={stdout_logs}")
            if None in (hits, written, dropped) or hits != written + dropped + intr:
                bad.append(f"hits={hits} != logs_written={written} + log_dropped={dropped} + interrupted={intr}")
            if expect_fail:
                if not ("incomplete" in err and expect_fail in err): bad.append(f"error={err!r}")
                if not dropped: bad.append("nothing counted dropped")
                if "probe: error:" not in errtext: bad.append("no error on stderr")
                if isinstance(stdout_logs, int) and isinstance(written, int):
                    if stdout_logs < written: bad.append("stdout_logs < logs_written")
                    if need_more_on_stdout and stdout_logs <= written: bad.append("scenario not hit: no record on stdout beyond the file")
            else:
                if err or dropped: bad.append(f"error={err!r} dropped={dropped}")
        if extra: bad += extra(res)
        record(name, not bad, "; ".join(bad) or
               f"file={len(file_recs)}=logs_written stdout={len(logs)}=stdout_logs hits={hits}=written+dropped({dropped})+"
               f"interrupted({intr}) rc={rc} error={err[:160]!r}")

    base = dict(os.environ)
    for bk in ("breakpoint", "inline"):
        name = f"stream-filefail-queued-{bk}"
        try:
            env = dict(base, UHH_TEST_FILE_STALL_MS="400", UHH_TEST_FILE_STALL_AT="8", UHH_TEST_FILE_FAIL_AT="8")
            res = _filefail_run([tr, "--backend", bk, "-p", "logstream_target.exe!LogSite:d", "--", ls], env, 120)
            judge(name, res, "write probe log file", need_more_on_stdout=True)
        except Exception as e:
            record(name, False, repr(e))
    for bk in ("breakpoint", "inline"):
        name = f"stream-filefail-deferred-{bk}"
        try:
            env = dict(base, UHH_TEST_FILE_FAIL_AT="1")
            res = _filefail_run([tr, "--backend", bk, "-p", "KernelBase.dll!GetFileAttributesA:s", "--", so, "deferred"],
                                env, 60)
            judge(name, res, "write probe log file", extra=lambda r: (
                [] if r[3] == b"partial line continued\nEND deferred\n" else [f"target stdout {r[3]!r}"]) + (
                [] if (r[4].get("hits") or 0) >= 5 else [f"hits={r[4].get('hits')} < 5"]))
        except Exception as e:
            record(name, False, repr(e))
    for where, expect in (("spare", None), ("append", "probe log file appender failed")):
        name = f"stream-filefail-throw-{where}"
        try:
            env = dict(base, UHH_TEST_FILE_THROW_AT="3", UHH_TEST_FILE_THROW_IN=where)
            res = _filefail_run([tr, "--backend", "breakpoint", "-p", "logstream_target.exe!LogSite:d", "--", ls], env, 120)
            judge(name, res, expect, extra=None if expect else lambda r: (
                [] if r[4].get("logs_written") == 50 and r[0] == 0 else [f"logs_written={r[4].get('logs_written')}/50 rc={r[0]}"]))
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
    elif case == "mid":   # call_original and return_from both refused: ONE warning record per probe
        hits = {"CoMidPush+0x1": 5}
        logs = {"co mid ok=0": 5, "uhh warning: call_original refused: not at a function entry ([SP] is no return address)": 1}
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
    row is compared with the uninstrumented run; hits, "co" logs and "uhh warning" records are
    exact (a warning is one record per probe on every backend); nothing dropped.
    callorig-hunt-warn-dr-breakpoint: four hw probes take every debug register, so call_original
    from two breakpoint probes is refused ("needs one free debug register"): exactly one
    "uhh warning" record per probe, like every other call_original warning (it used to be one
    stderr line per session and no record)."""
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
            if x.get("kind") == "probe_log" and m.startswith(("co ", "uhh warning")):
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
    name = "callorig-hunt-warn-dr-breakpoint"
    try:
        r, o = run([d, "--backend", "breakpoint", "--case", "drfull", "--", t, "nested"], timeout=300)
        dr_warn = "uhh warning: call_original refused: needs one free debug register (all 4 in use)"
        want_logs = {"co outer": 6, "co outer refused": 6, "co innerco": 6, "co innerco refused": 6, dr_warn: 2}
        row, logs, hb, rep = co_row(o), co_logs(o), hits_by(o), report(o)
        want = dict(bases["nested"])                # refused: the hits fall through, the program as uninstrumented
        recs = [x for x in o if x.get("kind") == "probe_log" and x.get("message") == dr_warn]
        per_probe = sorted(str(x.get("probe", x.get("location", x.get("site", "?")))) for x in recs)
        ok = (bool(want) and row == want and logs == want_logs and hb.get("co_outer") == 6 and hb.get("co_inner") == 6
              and len(set(per_probe)) == 2 and rep.get("log_dropped") == 0 and rep.get("error") is None
              and rep.get("app_exit") == 0 and r.returncode == 0)
        record(name, ok, f"row={row} want={want} logs={logs} hits={hb} warn_probes={per_probe} "
                         f"dropped={rep.get('log_dropped')} err={rep.get('error')} rc={r.returncode}")
    except Exception as e:
        record(name, False, repr(e))
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


# F5: case -> (the probed function call_original runs, its callback's log name, how many of its
# calls are left (no "-done" log), "co after" hits, "co after" logs).
CO_DEEP = {"deepthrow": ("co_throw", "throw", 5, 10, 10), "deepseh": ("co_seh", "seh", 5, 10, 10),
           "deepjmp": ("co_jump", "jump", 5, 10, 10), "catchhit": ("co_throw", "throw", 5, 5, 5),
           "catchinside": ("co_outer", "outer", 0, 15, 0)}


def check_callorig_deep():
    """ROADMAP F5: a breakpoint/hw call_original whose original is LEFT (C++ throw, SEH raise,
    longjmp) and caught above it; the program then calls a probed function from a DEEPER frame
    than the left call's (susp_target deep*), or inside the catch block (catchhit). Every later
    hit must run its callback as on inline -- they used to be taken for hits inside the
    original (counted, no callback) until the next hit at the left frame's level or the 5 s
    release. Control (catchinside): the exception is caught INSIDE the original (a probed call
    in that catch block, then a deeper one): those hits are inside the call -- counted, no
    callback -- and the call returns normally. Exact hits and "co" logs (hits == logs), the target's row as uninstrumented,
    nothing dropped or interrupted, and the abandoned call_original never runs into the 5 s
    limit. Every backend."""
    d, t = exe("co_driver.exe"), exe("susp_target.exe")
    if not d or not t:
        return missing_bin("callorig-deep", "co_driver/susp_target")

    def co_row(objs):
        return next((x for x in objs if x.get("kind") == "co"), {})

    for case, (fn, nm, nleft, after, after_logs) in CO_DEEP.items():
        try:
            r0, o0 = run([t, case], timeout=60)
            base = co_row(o0)
        except Exception as e:
            base = {}
        for bk in ("breakpoint", "hw", "inline"):
            name = f"callorig-deep-{case}-{bk}"
            try:
                r, o = run([d, "--backend", bk, "--case", case, "--module", "susp_target.exe", "--", t, case],
                           timeout=180)
                row, rep = co_row(o), report(o)
                logs = {}
                for x in o:
                    m = str(x.get("message", ""))
                    if x.get("kind") == "probe_log" and m.startswith("co "):
                        logs[m] = logs.get(m, 0) + 1
                hb = {}
                for p in probes(o):
                    loc = str(p.get("location", ""))
                    hb[loc.split("!", 1)[-1]] = p.get("hits")
                want_logs = {f"co {nm}": 10, f"co {nm}-done": 10 - nleft, "co after": after_logs}
                want_hits = {fn: 10, "co_after": after}
                got_logs = {k: logs.get(k, 0) for k in want_logs}
                extra = sorted(k for k in logs if k not in want_logs)
                slow = "within 5 s" in (r.stderr or "")
                ok = (bool(base) and base.get("left") == 5 and row == base and
                      all(hb.get(k) == v for k, v in want_hits.items()) and got_logs == want_logs and not extra and
                      rep.get("log_dropped") == 0 and rep.get("callbacks_interrupted", 0) == 0 and
                      rep.get("error") is None and rep.get("app_exit") == 0 and r.returncode == 0 and not slow)
                record(name, ok, f"row={row} want={base} hits={hb} logs={got_logs} extra={extra[:3]} "
                                 f"dropped={rep.get('log_dropped')} intr={rep.get('callbacks_interrupted')} "
                                 f"err={rep.get('error')} rc={r.returncode} released_at_5s={slow}")
            except Exception as e:
                record(name, False, repr(e))


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
    # The rule behind identical stacks on every backend: names come from the image file on
    # disk, never from the target's memory. symfile_test registers kernel32.dll's file at the
    # base where the live target maps ntdll (DbgHelp keyed by the process handle read the
    # image there: ntdll's exports under kernel32's name, or none -- one inline frame showed
    # kernel32+0x14f80 where breakpoint/hw showed BaseThreadInitThunk+0x10), and looks
    # kernel32 up for the first time after its target exited.
    sf = exe("symfile_test.exe")
    if not sf:
        missing_bin("symbols-file-backed", "symfile_test")
    else:
        try:
            r, o = run([sf], timeout=120)
            cases = {x.get("case"): x for x in o if x.get("kind") == "symfile"}
            ok = (r.returncode == 0 and set(cases) == {"foreign-image", "after-exit"} and
                  all(c.get("ok") for c in cases.values()))
            record("symbols-file-backed", ok, "; ".join(f"{k}: {c.get('name')} resolved_rva={c.get('resolved_rva')}"
                                                        f"/{c.get('want_rva')}" for k, c in cases.items())
                   + f" rc={r.returncode}" + ("" if ok else f" out={r.stdout.strip()[-600:]!r}"))
        except Exception as e:
            record("symbols-file-backed", False, repr(e))


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


TP_MODES = ("noop", "log", "mem", "sys", "callfn", "co", "fpu")
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


# The CET rows leave out tp_ovf (a callback overflowing its stack: TR9, a host-dependent runner finding of its
# own -- one such crash took every later row of the run with it); it has nothing to do with shadow stacks.
TP_CET_SKIP = ("ovf",)
TP_GROUPS = {"breakpoint": [TP_PROBES], "inline": [TP_PROBES],
             "hw": [TP_PROBES[i:i + 3] for i in range(0, len(TP_PROBES), 3)]}


def tp_runs(d, t, bk, mode, iters, skip=()):
    """Runs tp_driver for every probe group of `bk` in `mode` against target `t` (tp_target or
    its /CETCOMPAT twin); returns (problems, target rows). `skip`: probes left out."""
    bad, rows = [], []
    for grp in TP_GROUPS[bk]:
        grp = [p for p in grp if p not in skip]
        if not grp:
            continue
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
    (probe_app --until-key: rounds of 4 x round_reads, the same pattern each round, read by the
    same 4 threads with a blocking barrier between rounds), so every cycle runs while it reads,
    whatever the machine's speed. Every cycle must detach cleanly
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
    inline cycles took 1.0-2.9 s on x64 and 1.2-8.0 s on x86.

    Cycle 1 runs 3 s (the others 300 ms). Inline: the first cycle loads the agent and runs its
    first init (which starts its service thread). (breakpoint/hw: since 2026-11-07 no agent is
    injected without an inline probe, so they arm at once; the 3 s cycle 1 stays, harmless.) On a 2-vCPU CI runner with 4 spinning threads that took longer than
    300 ms; a detach between the load and the init left the first init -- and a zero-hit window --
    to cycle 2 (runfix1: 3 of ~58 runner runs, always cycle 2 right after a short cycle 1). The
    remote agent threads now run above normal priority (0 zero-hit cycles in 511 runner cycles
    after the first), and cycle 1 gets the time to finish the setup, so every later cycle tests
    install/remove churn with the agent ready.

    Why the rounds keep their threads (ROADMAP H4). The target used to start 4 fresh threads per
    round, and they and main SPUN until all had started: with every CPU taken by spinners, a
    thread not yet started waited for a scheduling quantum (Windows Server: ~190 ms), so every
    round began with 200-600 ms without a single read (measured on runners), and a 300 ms cycle
    inside one saw zero hits that the tool had nothing to do with (x86 ntdll-churn-breakpoint,
    CI 42357172927; the probe is armed before the attach resumes any thread). Now some thread
    reads at every moment (longest idle stretch measured: 6 ms), and a zero-hit cycle is the
    tool's fault again."""
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
                # Cycle 1 sets the agent up in the target (load, first init, its service thread):
                # it gets 3 s, so every later cycle starts with the agent ready and must see hits
                # within 300 ms (see the docstring).
                tr = subprocess.Popen([str(t), "--backend", bk, "--attach", str(target.pid), "--detach-after-ms",
                                       "3000" if c == 1 else "300", "-p", "ntdll.dll!NtReadVirtualMemory:xxxx"],
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
    proof the test can see the race the freeze removes.
    Each trial runs at least MIN_CYCLES attach/hook/detach cycles AND at least MIN_SECONDS
    of them (whichever ends later; at most 25 cycles), however long a cycle takes on this
    machine: the target runs until its stdin is closed (--until-stdin). A cycle against 8
    spinning threads takes ~1 s on the 4-core VM but 6-8.5 s on a 2-core CI runner; a fixed
    12 s window fitted only one there. A trial that cannot finish MIN_CYCLES within
    TRIAL_BUDGET seconds fails (a hang or a pathological slowdown, not a pass). Every cycle
    after the first (which loads the agent) must have hit the hook: hits counted up to its
    removal (the detach summary), not only in the report taken 400 ms after the attach."""
    MIN_CYCLES, MIN_SECONDS, TRIAL_BUDGET = 4, 12, 300
    t, a = exe("uhh_trace.exe"), exe("patchrace_target.exe")
    if not t or not a:
        return missing_bin("patch-race", "uhh_trace/patchrace_target")
    for mode in ("frozen", "unsafe"):
        name = f"patch-race-{mode}"
        exits, cycles_all, notes, torn, secs = [], [], [], [], []
        try:
            for _ in range(trials):
                target = subprocess.Popen([str(a), "--threads", "8", "--seconds", str(TRIAL_BUDGET + 60),
                                           "--until-stdin"], stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                ready = target.stdout.readline()
                if '"ready"' not in ready:
                    raise RuntimeError(f"target not ready: {ready!r}")
                cycles, t0 = 0, time.monotonic()
                while (target.poll() is None and cycles < 25 and time.monotonic() - t0 < TRIAL_BUDGET and
                       (cycles < MIN_CYCLES or time.monotonic() - t0 < MIN_SECONDS)):
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
                    # This cycle's hook really ran: hits by the time it was removed (the detach
                    # summary). The report, taken 400 ms after the attach, can still say 0 on a
                    # 2-core runner where the install against 8 spinning threads takes longer.
                    m = re.search(r"probe: detached: hits=(\d+)", tr.stderr or "")
                    hits = max(pr.get("hits") or 0, int(m.group(1)) if m else 0)
                    if pr.get("backend") != "inline" or (not hits and cycles > 1):   # first cycle loads the agent
                        notes.append(f"backend={pr.get('backend')} hits={hits} at_report={pr.get('hits')} "
                                     f"err={(report(objs).get('error') or '')[:80]}")
                secs.append(round(time.monotonic() - t0))
                try:
                    tout, _ = target.communicate(timeout=120)        # closes stdin: the target stops
                except subprocess.TimeoutExpired:
                    target.kill(); tout, _ = target.communicate()
                res = next((json.loads(l) for l in (tout or "").splitlines() if '"kind":"app"' in l), {})
                exits.append(target.returncode); cycles_all.append(cycles); torn.append(res.get("torn"))
            crashed = sum(1 for e in exits if e != 0)
            torn_total = sum(t or 0 for t in torn)
            if mode == "frozen":
                ok = crashed == 0 and torn_total == 0 and min(cycles_all) >= MIN_CYCLES and not notes
            else:
                ok = (crashed >= 1 or torn_total >= 1) and not any("hits=None" in n or "hits=0" in n for n in notes)
            record(name, ok, f"trials={trials} crashed={crashed} torn={torn} exits={[hex(e & 0xffffffff) for e in exits]} "
                             f"hook_cycles={cycles_all} secs={secs} (>= {MIN_CYCLES} cycles and {MIN_SECONDS} s each)"
                             + (f" notes={notes[:3]}" if notes else "")
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
                bad, rows = tp_runs(tpd, tpc, bk, mode, 10, skip=TP_CET_SKIP)
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
    need nothing in the target; inline needs the agent (which holds the callbacks) loaded.
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
                        bad, rows = tp_runs(tpd, copies["tp_target_cet"], bk, mode, 5, skip=TP_CET_SKIP)
                        if policy == "block" and bk == "inline" and on:
                            # The agent (it holds the inline callbacks) must be /CETCOMPAT to load;
                            # until then the refusal must be clean (the error names the agent load).
                            r2, o2 = run([tpd, "--backend", bk, "--mode", mode, "--probes", "add", "--",
                                          copies["tp_target_cet"], "--iters", 2], timeout=120)
                            err = (report(o2).get("error") or "")
                            # until the agent is /CETCOMPAT
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
    with --fallback-hw, move to hw. The target must be unaffected either way.
    Ground truth is per hit, from its stack (--stack): the target's opens are the hits with a
    probe_app frame, and must be exactly its `opened` count; every hit is logged. Other hits are
    allowed only from system code alone: the first launch of probe_app on a fresh machine
    (every CI runner) runs the shim engine at process init (ntdll!LdrInitShimEngineDynamic ->
    apphelp!SE_InitializeEngine -> KernelBase!OpenProcess) -- a real 5th NtOpenProcess of the
    target, seen as hits=5 on the first breakpoint run only (runner diag: 7 of 7 jobs, never
    on a later run)."""
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
            r, objs = run([t, "--backend", bk, *extra, "--stack", "-p", f"{site}:x", "--", a, "--no-wait", "--helpers",
                           helpers, "--threads", threads, "--reads", reads, "--config", "reads_enabled=1"], timeout=300)
            res = next((x for x in objs if x.get("kind") == "app"), {})
            pr = next((x for x in objs if x.get("kind") == "probe"), {})
            rep = report(objs)
            app_ok = res.get("opened") == helpers and res.get("successful_reads") == threads * reads
            stacks = [x.get("stack") or [] for x in objs if x.get("kind") == "probe_log"]
            own = sum(1 for st in stacks if any(str(f).lower().startswith("probe_app") for f in st))
            other = [" < ".join(str(f).split(" [")[0] for f in st[1:4]) for st in stacks
                     if not any(str(f).lower().startswith("probe_app") for f in st)]
            if bk == "inline" and not extra:
                ok = r.returncode != 0 and "would be written across" in (rep.get("error") or "") and "PROBE_ALLOW_UNSAFE_SITE" in (rep.get("error") or "") and not pr.get("hits")
            else:
                want_bk = "hw" if extra else bk
                ok = (app_ok and pr.get("backend") == want_bk and own == helpers and pr.get("hits") == len(stacks)
                      and all(stacks))
            record(name, ok, f"site={site} backend={pr.get('backend')} hits={pr.get('hits')} target_opens={own} "
                             f"system_opens={len(other)}{other[:2] if other else ''} logs={len(stacks)} "
                             f"opened={res.get('opened')} reads={res.get('successful_reads')} rc={r.returncode} "
                             f"err={(rep.get('error') or '')[:120]}")
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
    still logging. Every hit is accounted EXACTLY (the gospel): hits == logs + log_dropped +
    callbacks_interrupted, with log_dropped == 0 and hits >= n. Inline: the process death
    kills the other threads wherever they are -- one killed inside its callback before its
    log was published is callbacks_interrupted (at most one per thread); one killed after
    publishing is a delivered log and NOT interrupted (its record carried the hit's unit,
    probe_agent_shared v23; v20 counted it twice -- 3 of 36 runner runs). breakpoint/hw run
    callbacks in the controller: interrupted == 0, logs == hits. Single-thread run too:
    exactly n logs, nothing interrupted (the thread crashes after its hit returned)."""
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
                intr = rep.get("callbacks_interrupted")
                exact = intr is not None and hits == logs + (rep.get("log_dropped") or 0) + intr
                ok = (rep.get("app_exit") == 0xC0000005 and exact and rep.get("log_dropped") == 0 and
                      (hits == n and logs == n and intr == 0 if nt == 1 else
                       hits >= n and len(tids) == nt and intr <= (nt - 1 if bk == "inline" else 0)))
                record(name, ok, f"exit=0x{(rep.get('app_exit') or 0):x} hits={hits} logs={logs} "
                                 f"interrupted={intr} (hits == logs + dropped + interrupted: {exact}; n={n}) "
                                 f"threads_logging={len(tids)}/{nt} dropped={rep.get('log_dropped')}")
            except Exception as e:
                record(name, False, repr(e))


def check_carry_exact(calls=400_000, threads=4, runs=3):
    """A clean exit accounts every hit with no callback "interrupted": inline, 4 threads, every
    other call logs (hitcost --method log_alt), so the controller retires carried first records
    while the same threads keep counting hits that end unlogged. Regression for CI 42325381514
    (gated-e2e-launch-fhw-oin-cin-rin: logs 646/646 delivered, interrupted=1): the retire summed a
    block's hits then read its `done` while the owner counted on, came out one short and skipped
    the retire. Bar, every run: hits == calls x threads, logs == half of them, dropped == 0,
    callbacks_interrupted == 0."""
    d, t = exe("hitcost_driver.exe"), exe("hitcost_target.exe")
    if not d or not t:
        return missing_bin("carry-exact", "hitcost driver/target")
    total = calls * threads
    results, ok = [], True
    for i in range(runs):
        state = {"logs": 0, "objects": []}

        def consume(line, _arrival):
            if line.startswith('{"kind":"probe_log",'):
                state["logs"] += 1
            elif line.startswith("{"):
                try:
                    state["objects"].append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        try:
            rc, timed_out = stream_run([d, "--backend", "inline", "--method", "log_alt", "--", t, "--no-wait",
                                        "--calls", calls, "--threads", threads], 600, consume)
            rep = report(state["objects"])
            hits = next(iter(probes(state["objects"])), {}).get("hits")
            good = (not timed_out and rc == 0 and hits == total and state["logs"] == total // 2 and
                    rep.get("log_dropped") == 0 and rep.get("callbacks_interrupted") == 0)
            ok = ok and good
            results.append(f"hits={hits} logs={state['logs']} intr={rep.get('callbacks_interrupted')} "
                           f"drop={rep.get('log_dropped')} rc={rc}")
        except Exception as e:
            ok = False; results.append(repr(e))
    record("carry-exact-inline", ok, f"want hits={total} logs={total // 2}: " + " | ".join(results))


def check_attach_agent_scope():
    """Owner decision 2026-11-07: the agent DLL is injected into the target only when the session
    needs it (an inline probe).
      attach-lazy-agent-<b>: an ATTACHED breakpoint/hw-only session (co_driver --case lazy: one
        probe on co_outer) has no probe_api_agent.dll in the target while it has no inline probe;
        the first hit's callback then adds the session's first inline probe (co_inner) -- the
        agent is injected lazily, the calling thread is held until the hook is in, so that very
        call's co_inner is seen: 6 outer hits, 6 inner logs, the program's result unchanged (sum
        36, both bodies run 12 times).
      attach-no-agent-dll-<b>: co_driver.exe copied ALONE into a temp dir (no probe_api_agent.dll
        beside it). breakpoint/hw: the attach works as usual (nested: sum 36, 6+6 hits, no agent
        module in the target); inline: the attach is refused with an error naming the agent DLL
        and the target is untouched (it then runs to its normal result). (A controller whose
        breakpoint/hw callbacks use UHH_SHARED state still loads the agent DLL LOCALLY -- the
        shared callbacks run from it in the controller -- so such a driver needs the file
        beside it; nothing is injected for that. co_callbacks use none.)"""
    import shutil, tempfile
    d, t = exe("co_driver.exe"), exe("co_target.exe")
    if not d or not t:
        return missing_bin("attach-agent-scope", "co_driver/co_target")
    ts = _target_state()

    def session(bk, case, driver, gate_check=None):
        """co_target nested --wait attached by `driver` (--case case); returns (driver rc, stdout
        objs, stderr lines, target row, target rc, agent-before-gate)."""
        procs = []
        try:
            tgt = subprocess.Popen([str(t), "nested", "--wait"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True)
            procs.append(tgt)
            tout = Lines(tgt.stdout)
            w = tout.wait_for(lambda l: '"kind":"waiting"' in l, 30)
            if not w:
                raise RuntimeError("target never reached its gate")
            pid = json.loads(w)["pid"]
            att = subprocess.Popen([str(driver), "--backend", bk, "--case", case, "--attach", str(pid)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            procs.append(att)
            aout, aerr = Lines(att.stdout), Lines(att.stderr)
            if bk == "inline" and gate_check == "refused":
                att.wait(timeout=60)
            elif not aerr.wait_for(lambda l: l.startswith("probe: active co_target.exe!co_outer"), 60):
                raise RuntimeError("co_outer never became active: " + " | ".join(aerr.lines[-4:])[:300])
            time.sleep(0.3)
            before = ts.module_loaded(pid, "probe_api_agent.dll")
            tgt.stdin.write("x"); tgt.stdin.flush()
            att.wait(timeout=120); tgt.wait(timeout=60)
            o = aout.objs(); aerr.t.join(timeout=30)
            row = next((x for x in tout.objs() if x.get("kind") == "co"), {})
            return att.returncode, o, aerr.lines, row, tgt.returncode, before
        finally:
            for q in procs:
                if q.poll() is None:
                    q.kill()

    for bk in ("breakpoint", "hw"):
        name = f"attach-lazy-agent-{bk}"
        try:
            rc, o, err, row, trc, before = session(bk, "lazy", d)
            msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
            inner = next((p for p in probes(o) if str(p.get("location", "")).endswith("!co_inner")), {})
            rep, bad = report(o), []
            if before is not False: bad.append(f"agent loaded before any inline probe: {before}")
            if msgs.count("co lazy add=1") != 1 or msgs.count("co lazy add=-1") != 5:
                bad.append(f"lazy logs={[m for m in msgs if 'lazy' in m]}")
            if msgs.count("co inner") != 6 or inner.get("backend") != "inline" or inner.get("hits") != 6:
                bad.append(f"inner logs={msgs.count('co inner')} probe={inner} (want 6 inline hits)")
            if row.get("sum") != 36 or row.get("body") != 12 or trc != 0: bad.append(f"target row={row} rc={trc}")
            if rc != 0 or rep.get("log_dropped") != 0 or rep.get("error") is not None:
                bad.append(f"rc={rc} dropped={rep.get('log_dropped')} err={rep.get('error')}")
            record(name, not bad, " ".join(bad) + ("" if not bad else f" stderr={[l[:140] for l in err[-6:]]}")
                   or f"agent_before_first_inline={before} lazy_add=1 inner=6/6 inline sum={row.get('sum')}")
        except Exception as e:
            record(name, False, repr(e))

    # The lone copy goes next to the build first: Windows Defender on the VM quarantined an x64
    # co_driver.exe copied into %TEMP% (OSError winerror 225, "contains a virus or potentially
    # unwanted software" -- a debugger binary in a temp dir), never the original.
    tmp, lone = None, None
    for root in (BIN.parent, None):
        tmp = Path(tempfile.mkdtemp(prefix="uhh-noagent-", dir=str(root) if root else None))
        try:
            shutil.copy2(d, tmp / "co_driver.exe")
            lone = tmp / "co_driver.exe"
            break
        except OSError as e:
            shutil.rmtree(tmp, ignore_errors=True)
            if getattr(e, "winerror", None) != 225:
                raise
    if lone is None:
        for bk in ("breakpoint", "hw", "inline"):
            skip(f"attach-no-agent-dll-{bk}", "the antivirus quarantines a copy of co_driver.exe on this machine")
        return
    try:
        for bk in ("breakpoint", "hw", "inline"):
            name = f"attach-no-agent-dll-{bk}"
            try:
                rc, o, err, row, trc, before = session(bk, "nested", lone, "refused" if bk == "inline" else None)
                hits = {str(p.get("location", "")).split("!")[-1]: p.get("hits") for p in probes(o)}
                rep, bad = report(o), []
                if row.get("sum") != 36 or trc != 0: bad.append(f"target row={row} rc={trc}")
                if bk == "inline":
                    named = any("probe_api_agent" in l for l in err) or "probe_api_agent" in str(rep.get("error"))
                    if rc != 1 or not named: bad.append(f"rc={rc} error_names_agent={named} err={rep.get('error')}")
                    if before is not False: bad.append(f"agent module in the target: {before}")
                    if row.get("body") != 12: bad.append(f"body={row.get('body')} (want 12: untouched)")
                else:
                    if before is not False: bad.append(f"agent module in a breakpoint/hw-only target: {before}")
                    if rc != 0 or rep.get("error") is not None or hits != {"co_outer": 6, "co_inner": 6}:
                        bad.append(f"rc={rc} err={rep.get('error')} hits={hits}")
                record(name, not bad, " ".join(bad) + ("" if not bad else f" stderr={[l[:140] for l in err[-6:]]}")
                       or f"no agent DLL beside the controller: rc={rc} hits={hits} agent_in_target={before} "
                          f"sum={row.get('sum')}" + (f" error={str(rep.get('error'))[:100]}" if bk == "inline" else ""))
            except Exception as e:
                record(name, False, repr(e))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


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
          "recurse_ok": 0, "other": 0, "refused": []}
    keep = []

    def on_err(line):
        if "call_func refused" in line and len(st["refused"]) < 20:
            st["refused"].append(line)

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
        rc, timed_out = stream_run([d, "--backend", backend, *extra, "--", t, scenario, "--n", n], timeout, on_line, on_err)
    finally:
        os.environ.pop("HUNT_READERS", None)
    tg = next((o for o in keep if o.get("kind") == "target"), {})
    mx = next((o for o in keep if o.get("kind") == "main_exit"), None)   # exit scenarios: main's print time
    if mx is not None:
        tg = dict(tg, print_ms=mx.get("print_ms"))
    rd = next((o for o in keep if o.get("kind") == "probe" and o.get("location") == HUNT_READ), {})
    wk = next((o for o in keep if o.get("kind") == "probe" and "HuntWork" in str(o.get("location"))), {})
    return rc, timed_out, tg, rd, wk, report(keep), st


def hunt_selected(name):
    """UHH_HUNT=sub1,sub2 narrows the hunt cases (debugging aid; default: all)."""
    import os
    flt = [x for x in os.environ.get("UHH_HUNT", "").split(",") if x]
    return not flt or any(x in name for x in flt)


def check_hunt_stack():
    """breakpoint/hw call_func on a hit with barely any committed stack below it (ROADMAP XH3).
    The controller runs the callee on the stopped thread with its frame 512+ bytes below the
    hit's SP. Was: where that memory was not committed yet (a fresh thread, a caller's big
    untouched frame) the frame write failed and call_func returned 0, nothing said.
    hunt-stackedge-*: every backend, fresh threads whose read hits with less than a page of
    committed stack below (hunt_target stackedge); every call_func must work as inline (--tid:
    the target's tid; --recurse: NtReadVirtualMemory again, x64 with a stack argument), the
    thread's guard page must still be in place after it (guard_lost=0) and the thread grows its
    stack 64 KB afterwards; no refusal on stderr.
    hunt-stackend-*: breakpoint/hw, threads whose read hits just above the last pages of their
    stack reservation: there the stack must not grow (UHH's bound: DeallocationStack +
    max(guarantee, 1 page) + 4 pages) -- each such call_func returns 0 (the TLS reads' calls work),
    ONE stderr line names the probe and the reason, the guard page stays, the program is
    unaffected."""
    d, t = exe("hunt_driver.exe"), exe("hunt_target.exe")
    if not d or not t:
        return missing_bin("hunt-stack", "hunt_driver / hunt_target")
    n = 20
    rows = [(sc, bk, extra) for sc, bks in (("stackedge", ("inline", "hw", "breakpoint")), ("stackend", ("hw", "breakpoint")))
            for bk in bks for extra in ((("--tid",), ("--recurse",)) if sc == "stackedge" else (("--tid",),))]
    for sc, bk, extra in rows:
        name = f"hunt-{sc}-{extra[0].lstrip('-')}-{bk}"
        try:
            rc, tmo, tg, rd, wk, rep, st = hunt_run(bk, sc, n, extra, timeout=600)
            reads = tg.get("reads") or 0
            calls = st["tid_ok"] + st["tid_bad"] if "--tid" in extra else st["recurse_ok"]
            want_hits = reads * 2 if "--recurse" in extra else reads
            ok = (not tmo and rc == 0 and reads and tg.get("bad") == 0 and tg.get("edge") == n and
                  tg.get("guard_lost") == 0 and rd.get("hits") == want_hits and st["read"] == reads and
                  st["unmapped"] == 0 and rep.get("log_dropped") == 0 and rep.get("app_exit") == 0 and st["other"] == 0)
            if sc == "stackedge":
                ok = ok and not st["refused"] and (st["tid_ok"] == reads and st["tid_bad"] == 0 if "--tid" in extra
                                                   else st["recurse_ok"] == reads)
            else:
                ok = (ok and st["tid_bad"] == n and st["tid_ok"] == reads - n and len(st["refused"]) == 1 and
                      "NtReadVirtualMemory" in st["refused"][0] and "nearly exhausted" in st["refused"][0])
            record(name, ok, f"reads={reads} edge={tg.get('edge')} hits={rd.get('hits')} logs={st['read']} bad={tg.get('bad')} "
                             f"guard_lost={tg.get('guard_lost')} tid_ok={st['tid_ok']} tid_bad={st['tid_bad']} "
                             f"recurse_ok={st['recurse_ok']} calls={calls} refused={len(st['refused'])} "
                             f"dropped={rep.get('log_dropped')} exit={rep.get('app_exit')} rc={rc} timeout={tmo}"
                             + (f" other={st['other']}" if st["other"] else "")
                             + (f" first_refusal={st['refused'][0][:200]!r}" if st["refused"] else "")
                             + ("" if ok else f" err={(rep.get('error') or '')[:160]}"))
        except Exception as e:
            record(name, False, repr(e))


def check_init_cutoff():
    """An agent init running on a thread of its own (attach) that the target's end kills before
    it returns is no init failure: the session reports the target's own exit code and no error.
    Was: the killed thread's exit code (the PROGRAM's, e.g. TerminateProcess(self, 7)) read as
    "probe_agent_init failed (code=0x7)", the debug loop abandoned, app_exit lost (seen on a
    launch: hunt-exit-terminate-inline, a redundant init thread still running at the exit).
    UHH_TEST_INIT_STALL_MS (agent test knob, the target's environment) keeps the init from
    returning; the target ends 8 s after its start, mid-init."""
    import os
    tr, t = exe("uhh_trace.exe"), exe("hunt_target.exe")
    if not tr or not t:
        return missing_bin("init-cutoff", "uhh_trace / hunt_target")
    for sc, code in (("exit-terminate", 7), ("exit-process", 6)):
        name = f"init-cutoff-{sc}-inline"
        target = None
        try:
            env = dict(os.environ, UHH_TEST_INIT_STALL_MS="30000", HUNT_READERS="2")
            target = subprocess.Popen([str(t), sc, "--n", "8000"], env=env, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True)
            r, o = run([tr, "--backend", "inline", "--attach", target.pid, "-p", "ntdll.dll!NtReadVirtualMemory:-"],
                       timeout=120)
            target.communicate(timeout=60)
            rep = report(o)
            cut_line = next((l for l in r.stderr.splitlines() if "agent init thread ended by the target" in l), "")
            cut = bool(cut_line)
            # The cut-off line is required on both. exit-terminate on x86 lacked it now and then: the
            # init thread was the process's LAST thread to exit, whose exit the kernel reports as
            # EXIT_PROCESS (from that thread) with no EXIT_THREAD of its own -- VM, PROBE_TRACE, 30
            # runs: 4 such. The session now reports a pending init at EXIT_PROCESS too (XH3 notes).
            ok = target.returncode == code and rep.get("app_exit") == code and not rep.get("error") and cut
            record(name, ok, f"app_exit={rep.get('app_exit')} target_rc={target.returncode} cut_said={cut} "
                             f"cut_line={cut_line[len('probe: '):][:120]!r} "
                             f"error={(rep.get('error') or '')[:160]}")
        except Exception as e:
            if target and target.poll() is None:
                target.kill()
            record(name, False, repr(e))


HUNT_CASES = [  # (scenario, n, extra driver args ("@" = the backend under test), timeout)
    ("churn", 100, (), 900), ("pool", 100, (), 600), ("fiber", 50, (), 600), ("apc", 100, (), 600),
    ("veh", 150, (), 600), ("dll", 60, ("--work-backend", "@"), 900), ("ctx", 3000, (), 600),
    ("threads", 4, ("--slow-ms", "50"), 600), ("threads", 20, ("--tid",), 600),
    ("threads", 20, ("--recurse",), 600), ("early", 10, (), 300),
    ("owndr", 200, (), 300), ("owndr-live", 200, (), 300),
]


def check_hunt():
    """Edge-case hunter (examples/hunt): gated_config's NtOpenProcess map + per-read pid log
    under concurrency / lifecycle stress, every backend. Every read the target makes must be
    one hit and one log carrying the target's pid; nothing dropped; the program's own result
    (reads, verify failures, foreign debug exceptions, checksum) equals an uninstrumented run.
    alien == 0: no thread the program did not make ran its TLS callback while the program ran
    (a launch starts UHH's threads in the target -- they run the loader's thread-attach callouts,
    like any thread -- before the entry point is released, never mid-run)."""
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
                      tg.get("alien") == 0 and tg.get("checksum") == checksum and rd.get("hits") == want_hits and st["read"] == reads and
                      st["unmapped"] == 0 and st["pids"] == {tg.get("pid")} and rep.get("log_dropped") == 0 and
                      rep.get("app_exit") == 0 and st["other"] == 0)
                if sc == "ctx":
                    # Exact whatever the machine: N round-trips or 90 s of them (target-side). Not
                    # starved: at least 100 rounds, no single round over 30 s.
                    ok = ok and (tg.get("ctx_rounds") or 0) >= min(n, 100) and (tg.get("ctx_max_round_ms") or 0) < 30000
                if "--work-backend" in extra:
                    ok = ok and wk.get("hits") == tg.get("work") == st["work"] and tg.get("work") == 4 * n
                if "--tid" in extra:
                    ok = ok and st["tid_ok"] == reads and st["tid_bad"] == 0
                if "--recurse" in extra:
                    ok = ok and st["recurse_ok"] == reads
                record(name, ok, f"reads={reads} hits={rd.get('hits')} logs={st['read']} unmapped={st['unmapped']} "
                                 f"bad={tg.get('bad')} foreign={tg.get('foreign')} alien={tg.get('alien')} early={tg.get('early')} "
                                 f"dropped={rep.get('log_dropped')} exit={rep.get('app_exit')} rc={rc} timeout={tmo}"
                                 + (f" work={tg.get('work')}/{wk.get('hits')}/{st['work']}" if wk or tg.get("work") else "")
                                 + (f" tid_ok={st['tid_ok']} tid_bad={st['tid_bad']}" if "--tid" in extra else "")
                                 + (f" rounds={tg.get('ctx_rounds')}/{n} in {tg.get('ctx_ms')}ms max_round={tg.get('ctx_max_round_ms')}ms"
                                    if sc == "ctx" else "")
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
                # 8 readers on every backend (the debug-event backends park threads that hit
                # back to back, so the exiting one is not starved: hunt-starve-*).
                rc, tmo, tg, rd, wk, rep, st = hunt_run(bk, sc, 300, (), timeout=180, readers=8)
                hits = rd.get("hits") or 0
                cut = rep.get("callbacks_interrupted")
                ok = (not tmo and rep.get("app_exit") == code and hits > 0 and tg.get("bad") == 0 and tg.get("alien") == 0 and
                      cut is not None and
                      st["read"] + (rep.get("log_dropped") or 0) + cut == hits and st["unmapped"] == 0 and
                      (bk == "inline" or cut == 0))
                record(name, ok, f"exit={rep.get('app_exit')} hits={hits} logs={st['read']} dropped={rep.get('log_dropped')} "
                                 f"interrupted={cut} alien={tg.get('alien')} "
                                 f"reads_at_print={tg.get('reads_at_exit')} rc={rc} timeout={tmo}"
                                 + ("" if ok else f" err={(rep.get('error') or '')[:160]}"))
            except Exception as e:
                record(name, False, repr(e))
        # A displaced copy that faults (guard page: the program must still see its guard
        # violation, once, at the real instruction -- every backend, incl. a hw probe's
        # trampoline; a NEW call after the handler is a new hit, a retry is not: ROADMAP A9) and a DLL rebuilt at the same base (twin: the probe re-armed in the new
        # image must run the NEW instruction, not a cached copy of the old one).
        for sc, loc, n in (("guard", "hunt_target.exe!guard_touch", 50), ("twin", "twin.dll!TwinWork", 30)):
            name = f"hunt-{sc}-{bk}"
            if not hunt_selected(name):
                continue
            tr = exe("uhh_trace.exe")
            if not tr or (sc == "twin" and not (BIN / "twin_a" / "twin.dll").exists()):
                missing_bin(name, "uhh_trace / twin_a,twin_b")
                continue
            try:
                _, o = run([tr, "--backend", bk, "-p", loc + ":-", "--", t, sc, "--n", n], timeout=180)
                tg = next((x for x in o if x.get("kind") == "target"), {})
                pr = next((x for x in o if x.get("kind") == "probe"), {})
                rep = report(o)
                want = 4 * n if sc == "guard" else 2 * n          # guard: 4 calls (a retry is no new call)
                ok = (tg.get("bad") == 0 and pr.get("hits") == want and rep.get("app_exit") == 0 and
                      rep.get("log_dropped") == 0 and
                      (tg.get("guards") == 3 * n if sc == "guard" else tg.get("twin") == 2 * n))
                record(name, ok, f"bad={tg.get('bad')} guards={tg.get('guards')} twin={tg.get('twin')} "
                                 f"hits={pr.get('hits')}/{want} exit={rep.get('app_exit')} err={(rep.get('error') or '')[:120]}")
            except Exception as e:
                record(name, False, repr(e))
        # Starvation: 8 threads hitting the probe back to back while main sleeps 300 ms, prints
        # one line and calls ExitProcess. Every debug event freezes the whole process, so on
        # breakpoint/hw a thread that hits no probe used to run only in the gaps between events
        # (ROADMAP A5: main's Sleep+print took 4 s typically, > 180 s at worst): now one event
        # per hit and fairness (hot threads yield). Measured where starvation shows and in a unit
        # machine load does not distort: the reads the 8 threads made (= probe hits the session
        # handled) between main's Sleep falling due and main running again -- counted by the
        # target. Measured: with yield rounds 1.5k-6.5k hits (main's Sleep(10) steps every ~80 ms);
        # without them (suspension parking) 45k-234k, and the original starvation was far
        # worse (> 180 s). Bar: <= 20000 hits (inline: not judged, it freezes nothing); exit within the 60 s
        # timeout; every hit a delivered log or an honestly counted drop / interruption. (Wall
        # time is reported, not judged: on a loaded machine the session itself is slowed.)
        name = f"hunt-starve-{bk}"
        if hunt_selected(name):
            try:
                t0 = time.perf_counter()
                rc, tmo, tg, rd, wk, rep, st = hunt_run(bk, "exit-process", 300, (), timeout=60, readers=8)
                secs = time.perf_counter() - t0
                hits = (rd or {}).get("hits") or 0
                cut = rep.get("callbacks_interrupted")
                late = (tg.get("sleep_ms") or 10**9) - 300
                late_reads = tg.get("late_reads") if tg.get("late_reads") is not None else 10**9
                pms = tg.get("print_ms")
                ok = (not tmo and rep.get("app_exit") == 6 and (bk == "inline" or late_reads <= 20000) and hits > 0 and
                      cut is not None and st["read"] + (rep.get("log_dropped") or 0) + cut == hits and
                      st["unmapped"] == 0 and tg.get("bad") == 0 and (bk == "inline" or cut == 0))
                record(name, ok, f"exit={rep.get('app_exit')} main: late_reads={late_reads} (max 20000) sleep_late={late}ms "
                                 f"print={pms}ms secs={secs:.1f} "
                                 f"hits={hits} logs={st['read']} dropped={rep.get('log_dropped')} interrupted={cut} "
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
    per_bk, raw_bk, sym_bk = {}, {}, {}
    for bk in ("breakpoint", "hw", "inline"):
        name = f"stacks-{bk}"
        try:
            rr, o = run([d, "--backend", bk, *specs, "--", t], timeout=120)
            sym_bk[bk] = [l for l in rr.stderr.splitlines() if "symbols via" in l][:1]
            raw_bk[bk] = {k: next((x.get("stack") or [] for x in o if x.get("kind") == "probe_log"
                                   and x.get("message") == f"stack {k}"), []) for k in STACK_SITES}
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
        diffs, first = [], None
        for k in STACK_SITES:
            ref = per_bk["breakpoint"].get(k)
            for bk in ("hw", "inline"):
                other = per_bk[bk].get(k)
                if other != ref:
                    i = next((j for j in range(max(len(ref or []), len(other or [])))
                              if (ref or [None] * 99)[j:j + 1] != (other or [None] * 99)[j:j + 1]), -1)
                    diffs.append(f"{k}/{bk}@{i}: {(ref or [])[i:i + 1]} vs {(other or [])[i:i + 1]}")
                    first = first or (k, i)
        diag = ""
        if first:   # the first differing frame with its address, per backend, and each run's dbghelp
            k, i = first
            diag = (f" raw={ {b: (raw_bk.get(b, {}).get(k) or [])[i:i + 1] for b in per_bk} }"
                    f" dbghelp={ {b: v[0][len('probe: symbols via '):] if v else None for b, v in sym_bk.items()} }")
        record("stacks-identical", not diffs and all(per_bk[b].get(k) for b in per_bk for k in STACK_SITES),
               f"diffs={diffs[:4]} frames={ {k: len(per_bk['breakpoint'].get(k) or []) for k in STACK_SITES} }" + diag)


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
        # The same WMI process query as wmic, through PowerShell's CIM client: runs where WMIC
        # is no longer shipped (Windows Server 2025, Windows 11 24H2).
        ("ps-cim", psargs + ["Get-CimInstance Win32_Process | sort ProcessId | % { '{0},{1},{2}' -f "
                             "$_.ProcessId,$_.Name,$_.ExecutablePath }"], "lines", (None, 0)),
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


class _ModPoller:
    """An independent observer of other processes' module lists while a run goes on: every
    0.5 s, each process's loaded modules (EnumProcessModulesEx, LIST_MODULES_ALL; the base
    addresses, in load order). A process whose module list changed between two samples (a
    service loading / unloading DLLs) can legitimately be listed differently by a program
    that enumerates modules at some instant of the run; `moved` names those pids. A process
    this observer cannot open is never `moved` (no evidence, no exclusion)."""
    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self.ct, self.wt = ctypes, wintypes
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self.k32.OpenProcess.restype = wintypes.HANDLE
        self.k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.k32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.psapi.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                                    ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
        self.psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
        self.lists, self.samples, self.stop = {}, 0, threading.Event()
        self.sample()
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def modules(self, pid, names=False):
        ct = self.ct
        h = self.k32.OpenProcess(0x1000 | 0x10, False, pid)      # QUERY_LIMITED_INFORMATION | VM_READ
        if not h:
            return None
        try:
            arr, need = (ct.c_void_p * 1024)(), self.wt.DWORD(0)
            if not self.psapi.EnumProcessModulesEx(h, arr, ct.sizeof(arr), ct.byref(need), 3):
                return None
            mods = tuple(arr[i] or 0 for i in range(min(need.value // ct.sizeof(ct.c_void_p), 1024)))
            if not names:
                return mods
            buf = ct.create_unicode_buffer(260)
            return tuple(buf.value.lower() if self.psapi.GetModuleBaseNameW(h, m, buf, 260) else hex(m) for m in mods)
        finally:
            self.k32.CloseHandle(h)

    def sample(self):
        for pid in _snapshot_processes():
            m = self.modules(pid) if pid > 4 else None
            if m is None:
                continue
            seen = self.lists.setdefault(pid, [])
            if not seen or set(seen[-1]) != set(m):
                seen.append(m)
        self.samples += 1

    def _loop(self):
        while not self.stop.wait(0.5):
            try:
                self.sample()
            except Exception:
                pass

    def finish(self):
        self.stop.set(); self.t.join(timeout=30)
        self.sample()
        return {pid for pid, v in self.lists.items() if len(v) > 1}


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


def _row_key(row, cols):
    return ",".join(row.split(",")[:2])[:60]


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


_RX_CUT = re.compile(r"^probe: callbacks interrupted by the target's end: (\d+) cut off while running:(.*); unexplained=(\d+)$")
_RX_CUT_ONE = re.compile(r" (\S+)(?: \(tid \d+\))?(?: x(\d+))?")


def _cut_off(err_lines):
    """The library's account of interrupted inline callbacks (probe_report, on stderr):
    (cut off while running, unexplained, [(location, n), ...]) or None if it printed none."""
    for l in err_lines:
        if (m := _RX_CUT.match(l.strip())):
            return int(m[1]), int(m[3]), [(g[0], int(g[1] or 1)) for g in _RX_CUT_ONE.findall(m[2])]
    return None


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
    powershell (Get-Process .Modules / -FileVersionInfo, Get-CimInstance, and a .NET P/Invoke script with
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
            # An OS component this Windows does not ship: skip_external (a SKIP in the full suite,
            # a FAILURE when explicitly selected: --only realapps..., or UHH_REALAPPS_ONLY).
            why = ("WMIC is a Feature on Demand that Windows Server 2025 / Windows 11 24H2 no longer install; "
                   "realapps-ps-cim runs the same WMI process query" if scen == "wmic" else "not on this system")
            if scen in only:
                record(f"realapps-{scen}", False, f"optional external dependency absent: system program {argv[0]} "
                                                  f"({why}) -- explicitly selected (UHH_REALAPPS_ONLY)")
            else:
                skip_external(f"realapps-{scen}", f"system program {argv[0]}", why)
            continue
        # ps-fileversion lists the processes of ITS bitness that it can open: on a machine with
        # no other 32-bit process (a CI runner) a 32-bit run lists nothing to compare. The check
        # starts its own helpers of that bitness (findstr waiting on a pipe) for the scenario's
        # whole duration: their rows and their reads are required, deterministically, on every
        # machine.
        helpers = []
        if scen == "ps-fileversion":
            helpers = [subprocess.Popen([str(sysdir / "findstr.exe"), "uhh-helper"], stdin=subprocess.PIPE,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for _ in range(3)]
        own = (sysdir / "findstr.exe", [h.pid for h in helpers]) if helpers else None
        try:
            _realapps_scenario(scen, argv, kind, cols, x86, env_bks, drv, work, own)
        finally:
            for h in helpers:
                h.kill(); h.wait()
    if os.environ.get("UHH_REALAPPS_KEEP"):
        print(f"  realapps work dir kept: {work}", file=sys.stderr)
    else:
        shutil.rmtree(work, ignore_errors=True)


def _realapps_scenario(scen, argv, kind, cols, x86, env_bks, drv, work, own):
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
                          modwatch=scen in ("tasklist-m", "ps-modules"),
                          after=(lambda: _run_plain(argv, work / f"{scen}-{bk}-plain1.txt"))
                          if kind in ("csv", "lines") else None, own=own)
        except Exception as e:
            record(name, False, repr(e))


def _realapps_one(name, drv, argv, kind, cols, bk, base, stem, x86, after=None, own=None, modwatch=False):
    t0 = time.perf_counter()
    poll = _ProcPoller()
    mpoll = _ModPoller() if modwatch else None
    moved = set()
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
        if mpoll:
            moved = mpoll.finish()
        alive_pids = {p for p, _ in poll.always}
        alive_names = {n for _, n in poll.always}
        alive_always = list(poll.always)
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
    # Inline callbacks run on the program's own threads: the program's exit (ExitProcess kills
    # every other thread wherever it is) can cut one off mid-callback -- the thread dies inside
    # it, its hit counted, its log never written (callbacks_interrupted; docs/limitations.md).
    # Accepted only for inline, only when the library names every interrupted hit as a callback
    # still RUNNING when its thread died (unexplained=0: no accounting leak), and a read probe's
    # hits must still equal its logs plus exactly its own cut-off callbacks.
    intr, cut = rep.get("callbacks_interrupted"), _cut_off(errs)
    intr_ok = intr == 0 or (bk == "inline" and cut is not None and cut[1] == 0 and cut[0] == intr)
    read_cut = sum(n for loc, n in (cut[2] if cut else []) if loc == READ_LOCATION)
    ok = ((drc == 0 or (drc == 1 and prc == plain_rc != 0)) and rep.get("error") is None and rep.get("log_dropped") == 0 and intr_ok
          and read_hits == len(reads) + read_cut and len(other) == 0 and not bad
          and all(p.get("active") for p in pr.values()) and len(pr) == 3)
    plain_s = f"(plain {base[0][2]:.1f}s) " if base else ""
    detail = (f"{secs:.1f}s {plain_s}rc={drc} app_exit={prc} opens={len(opens)} reads={len(reads)}/{read_hits} unmapped={unmapped} "
              f"pids={len(pids)} unverified={sorted(unverified)[:4]} dropped={rep.get('log_dropped')} "
              f"intr={rep.get('callbacks_interrupted')}" + (f" cut_off={cut[0]}{cut[2]} unexplained={cut[1]}" if cut else ""))
    if kind in ("csv", "lines"):
        # Multisets, not sets: identical rows (e.g. several processes with the same image path)
        # must all still be there -- losing one of two equal rows is lost output.
        stable = Counter({r: n for r, n in (Counter(_realapps_rows(base[0][1], kind, cols)) &
                                            Counter(_realapps_rows(base[1][1], kind, cols))).items()
                          if _row_alive(r, cols, alive_pids, alive_names)})
        # A process whose module list the independent observer saw change DURING the
        # instrumented run is listed as of whatever instant the program enumerated it: its row
        # is not comparable (like a process that did not live through the run). Reported.
        moved_rows = Counter({r: n for r, n in stable.items() if moved and _row_alive(r, cols, moved, set())})
        stable -= moved_rows
        if cols and cols[1] == "path":
            # A bare image path stands for every process of that image: only as many as were
            # alive for the WHOLE run must be listed (another agent's conhost/powershell that
            # ended between the plain runs and this one is not lost output).
            per_name = Counter(n for _, n in alive_always)
            stable = Counter({r: min(n, per_name[r.rsplit("\\", 1)[-1].lower()]) for r, n in stable.items()})
            stable = +stable
        mine = Counter(_realapps_rows(prog_out, kind, cols))
        missing = sorted((stable - mine).elements())
        # A 32-bit Get-Process -FileVersionInfo lists only the few 32-bit processes: >= 1 row.
        ok = ok and not missing and prc == plain_rc and sum(stable.values()) >= 1
        detail += f" stable_rows={sum(stable.values())} missing={len(missing)} exit={prc}/{base[0][0]}"
        if mpoll:
            detail += (f" modules_moved_during_run={sum(moved_rows.values())}"
                       + (f"{sorted(_row_key(r, cols) for r in moved_rows)[:4]}" if moved_rows else "")
                       + f" (observer samples={mpoll.samples})")
        if own:
            # The check's own helpers: each listed in both plain runs and the instrumented one,
            # and each read by the instrumented program through a handle mapped to its pid/name.
            img, own_pids = str(own[0]).lower(), own[1]
            own_stable = sum(n for r, n in stable.items() if r.lower() == img)
            own_mine = sum(n for r, n in mine.items() if r.lower() == img)
            own_read = sorted({r[1] for r in reads if r[1] in own_pids and r[2].lower() == own[0].name.lower()})
            ok = ok and own_stable >= len(own_pids) and own_mine >= len(own_pids) and len(own_read) == len(own_pids)
            detail += (f" helpers={len(own_pids)}x{own[0].name}: stable={own_stable} instrumented={own_mine} "
                       f"read={len(own_read)}/{len(own_pids)}")
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
            if twin:   # show only where the row differs (module lists: ';' ps-modules, ',' tasklist)
                ma, tb = re.split(r"[;,]", m0), re.split(r"[;,]", twin)
                same_set = sorted(ma) == sorted(tb)
                detail += (f" e.g. {key}: only_plain={sorted(set(ma) - set(tb))[:8]} only_instr={sorted(set(tb) - set(ma))[:8]}"
                           + (" (same entries, other order)" if same_set else ""))
                if mpoll:
                    try:
                        kp = int(m0.split(",")[cols[1]].strip('"'))
                        hist = mpoll.lists.get(kp)
                        detail += f" observer[{kp}]: " + ("not openable" if hist is None else
                                                          f"{len(hist)} distinct module list(s), {len(hist[0])} modules")
                    except (ValueError, IndexError):
                        pass
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
        controller at exit.
      ctrl-agentprep-<unlaunched|badlaunch>: the controller's agent DLL is prepared on a
        background thread from the first inline add (perf5); a session closed without a launch,
        or whose launch failed, ends cleanly (exit 0, no crash) and deletes its agent copy; the prep
        thread's sweep of dead sessions' copies leaves every other directory alone (it removed an empty
        logs\\ while the launch was about to create the session file in it: CI x86 "create probe log
        file (Win32=3)")."""
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

    for sc in ("unlaunched", "badlaunch"):
        name = f"ctrl-agentprep-{sc}"
        try:
            r, o, res, logs, rows = go(sc, "inline", [], timeout=60)
            bad = []
            if r.returncode != 0: bad.append(f"exit={r.returncode}")
            if res.get("launched") != 0: bad.append(f"launched={res.get('launched')}")
            if res.get("copies_left") != 0: bad.append(f"copies_left={res.get('copies_left')}")
            if res.get("kept") != 1: bad.append(f"kept={res.get('kept')} (an empty non-copy dir in %TEMP%\\uhh was swept)")
            record(name, not bad, " ".join(bad) or f"closed cleanly, copies_left={res.get('copies_left')}, other dirs kept")
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

def _agent_stamp(path):
    """The warm-copy name of an agent file, exactly as session.cpp's agent_signature computes it:
    volume serial, file index, size, write time, change time (hex)."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                wintypes.DWORD, wintypes.HANDLE]

    class BHFI(ctypes.Structure):
        _fields_ = [("attr", wintypes.DWORD), ("c", wintypes.FILETIME), ("a", wintypes.FILETIME), ("w", wintypes.FILETIME),
                    ("vol", wintypes.DWORD), ("sizeh", wintypes.DWORD), ("sizel", wintypes.DWORD), ("links", wintypes.DWORD),
                    ("idxh", wintypes.DWORD), ("idxl", wintypes.DWORD)]

    class FBI(ctypes.Structure):
        _fields_ = [("ct", ctypes.c_longlong), ("la", ctypes.c_longlong), ("lw", ctypes.c_longlong), ("chg", ctypes.c_longlong),
                    ("attr", wintypes.DWORD)]

    h = k32.CreateFileW(str(path), 0x80000000, 1 | 4, None, 3, 0, None)
    if h in (None, wintypes.HANDLE(-1).value):
        raise OSError(f"open {path}: {ctypes.get_last_error()}")
    try:
        bi, fb = BHFI(), FBI()
        if not k32.GetFileInformationByHandle(h, ctypes.byref(bi)) or \
           not k32.GetFileInformationByHandleEx(h, 0, ctypes.byref(fb), ctypes.sizeof(fb)):
            raise OSError(f"query {path}: {ctypes.get_last_error()}")
    finally:
        k32.CloseHandle(h)
    return (f"{bi.vol:08x}{bi.idxh:08x}{bi.idxl:08x}{bi.sizeh:08x}{bi.sizel:08x}{bi.w.dwHighDateTime:08x}"
            f"{bi.w.dwLowDateTime:08x}{fb.chg & 0xffffffffffffffff:016x}")


def check_ctrl_warm():
    """codex3 #2: perf5's warm agent copies (%TEMP%\\uhh\\warm\\<sig>-*) were taken on the name alone (sig =
    the agent file's size and write time) and loaded into controller and target.
      ctrl-warm-identity: (a) a copy named for this agent's size and write time but made from another
        build (the agent with one DOS-stub byte changed) must not be used; (b) a copy under this
        agent's full version stamp (volume, file id, size, write time, change time) that is not a
        complete trimmed image of it (here: the untrimmed agent with that byte changed) is rejected
        and deleted; the first session makes a new copy (agent_copy_kind new) and works; a later
        session takes the genuine warm copy the first one left (agent_copy_kind warm: perf5's gain).
      ctrl-warm-acl: under a %TEMP% whose ACL lets Everyone write, no warm copy is made or taken
        (three sessions: all new, no ready copy left), the sessions work.
    Each session: lifecycle_driver attaches to a lifecycle_target with an inline read probe for
    ~1.5 s (long enough for the warm copy it starts), then detaches; TMP/TEMP point at the check's
    own directory."""
    agent = exe("probe_api_agent.dll")
    if not exe("lifecycle_driver.exe") or not exe("lifecycle_target.exe") or not agent:
        return missing_bin("ctrl-warm", "lifecycle_driver / lifecycle_target / probe_api_agent")
    import tempfile
    st = os.stat(agent)
    ft = st.st_mtime_ns // 100 + 116444736000000000
    old_sig = f"{st.st_size >> 32:08x}{st.st_size & 0xffffffff:08x}{ft >> 32:08x}{ft & 0xffffffff:08x}"
    sig = _agent_stamp(agent)

    def session(tmp):
        tg = d = None
        bad = []
        try:
            tg = LcTarget("--threads", 1)
            d = LcDriver(tg.pid, dict(read="inline"), "--detach-on-stdin",
                         env={"TMP": str(tmp), "TEMP": str(tmp), "UHH_BENCH_PHASES": "1"})
            if not d.wait_attached() or not d.wait_active():
                bad.append(f"not active: {d.errors()}")
            time.sleep(1.5)
            try:
                d.detach()
            except OSError:
                pass
            fin_ok = d.finish(timeout=60)
            ok_logs, fin = lc_logs_ok(d)
            a = tg.quit()
            if not fin_ok or d.p.returncode != 0: bad.append(f"driver rc={d.p.returncode} finished={fin_ok}")
            if not ok_logs or not fin or not fin[1]: bad.append(f"logs={d.logs} final={fin}")
            if not lc_clean(a) or a.get("rc") != 0: bad.append(f"quit rc={a.get('rc')} {lc_brief(a)}")
            kinds = [l.split()[3] for l in d.err.lines if l.split()[2:3] == ["agent_copy_kind"] and len(l.split()) > 3]
            rejected = sum(1 for l in d.err.lines if " agent_warm_rejected" in l)
            return (kinds[0] if kinds else None), rejected, bad
        finally:
            if d: d.kill()
            if tg: tg.kill()

    def ready(warm):
        return [p for p in warm.glob(sig + "-*") if p.is_dir()] if warm.is_dir() else []

    base = Path(tempfile.mkdtemp(prefix="uhhwarm-"))
    try:
        try:
            tmp = base / "id"; warm = tmp / "uhh" / "warm"
            img = bytearray(Path(agent).read_bytes()); img[0x50] ^= 0x01
            stale, corrupt = warm / f"{old_sig}-1-1-1", warm / f"{sig}-1-1-2"
            for d in (stale, corrupt):
                d.mkdir(parents=True)
                (d / "probe_api_agent.dll").write_bytes(bytes(img))
            kind1, rej1, bad = session(tmp)
            if kind1 != "new": bad.append(f"first session took kind={kind1} (a planted copy)")
            if rej1 < 1: bad.append("the corrupt copy under this build's stamp was not rejected")
            if corrupt.exists(): bad.append("the rejected copy is still there")
            kinds = []
            for _ in range(3):                       # the genuine copy an earlier session left behind
                for _w in range(40):
                    if ready(warm): break
                    time.sleep(0.25)
                k, rej, b2 = session(tmp)
                bad += b2; kinds.append((k, rej))
                if k == "warm": break
            if not kinds or kinds[-1] != ("warm", 0): bad.append(f"later sessions={kinds} (want a verified warm take)")
            record("ctrl-warm-identity", not bad, " ".join(bad) or
                   f"stale-build copy not taken, corrupt copy rejected and deleted (first: {kind1}, rejected={rej1}); "
                   f"later sessions {kinds}")
        except Exception as e:
            record("ctrl-warm-identity", False, repr(e))
        try:
            tmp = base / "acl"; tmp.mkdir()
            g = subprocess.run(["icacls", str(tmp), "/grant", "*S-1-1-0:(OI)(CI)F"], capture_output=True, text=True)
            kinds, bad = [], []
            if g.returncode != 0: bad.append(f"icacls rc={g.returncode} {g.stdout.strip()[:120]}")
            for _ in range(3):
                k, rej, b2 = session(tmp)
                bad += b2; kinds.append(k)
            if kinds != ["new"] * 3: bad.append(f"kinds={kinds} (want new x3: no warm copies in a shared directory)")
            if ready(tmp / "uhh" / "warm"): bad.append("a warm copy was made in the shared directory")
            record("ctrl-warm-acl", not bad, " ".join(bad) or f"Everyone-writable %TEMP%: kinds={kinds}, no warm copy")
        except Exception as e:
            record("ctrl-warm-acl", False, repr(e))
    finally:
        shutil.rmtree(base, ignore_errors=True)


def check_ctrl_symload():
    """codex3 #4 (claim: not a bug, kept as a guard): probe_session_create starts a detached thread
    that locates and loads dbghelp (symbols.cpp preload); the review claimed a host DLL that links
    UHH statically, creates and closes an unlaunched session and is unloaded at once would unmap
    the code that thread runs. It does not: std::thread starts it through the CRT's
    _beginthreadex, which holds a reference to the module of the thread procedure until the thread
    exits. ctrl-symload-unload: symhost_loop loads symhost.dll (UHH linked in), runs create+close,
    unloads it -- 40 times as is, then 3 times with the preload held 300 ms (test hook
    UHH_TEST_PRELOAD_DELAY_MS: certainly still running at the unload): no crash, every run ok; with
    the delay the DLL is still mapped right after each FreeLibrary (held == runs: the thread's
    reference) and really unmapped once the thread is done (gone)."""
    name = "ctrl-symload-unload"
    loop, dll = exe("symhost_loop.exe"), exe("symhost.dll")
    if not loop or not dll:
        return missing_bin(name, "symhost_loop / symhost")
    bad, got = [], []
    try:
        for n, delay in ((40, None), (3, "300")):
            env = dict(os.environ)
            if delay: env["UHH_TEST_PRELOAD_DELAY_MS"] = delay
            r = subprocess.run([str(loop), str(dll), str(n)], capture_output=True, text=True, timeout=120, env=env)
            res = next((json.loads(l) for l in r.stdout.splitlines() if l.startswith('{"kind":"symhost"')), {})
            crash = next((l for l in r.stdout.splitlines() if '"unhandled"' in l), None)
            got.append((n, delay, r.returncode, res.get("ok"), res.get("held"), res.get("gone")))
            if r.returncode != 0 or crash: bad.append(f"n={n} delay={delay}: exit=0x{r.returncode & 0xffffffff:x} {crash or ''}")
            elif res.get("ok") != n or res.get("gone") != 1 or (delay and res.get("held") != n):
                bad.append(f"n={n} delay={delay}: {res}")
        record(name, not bad, " ".join(bad) or f"(n, delay, rc, ok, held, gone)={got}")
    except Exception as e:
        record(name, False, repr(e))


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


def check_logs_format_fast():
    """send_log's fast formatter (probe_log_format.hpp uhh_format_fast: the common conversions
    without the CRT's printf engine) produces exactly what the CRT's vsnprintf does on every
    format it accepts -- lengths, bytes, truncation -- and declines (hands to vsnprintf) every
    format it does not handle; the hot formats (gated's read line, %llu, %s, %p...) are taken."""
    if not exe("log_format_selftest.exe"):
        return missing_bin("logs-format-fast", "log_format_selftest")
    try:
        r, objs = run([exe("log_format_selftest.exe")], timeout=60)
        o = next((x for x in objs if x.get("kind") == "log_format_selftest"), {})
        ok = (r.returncode == 0 and o.get("mismatch") == 0 and o.get("unexpected_decline") == 0 and
              o.get("fast", 0) > 1000 and o.get("declined", 0) > 0)
        record("logs-format-fast", ok, f"bits={o.get('bits')} cases={o.get('cases')} fast={o.get('fast')} "
                                       f"declined={o.get('declined')} mismatch={o.get('mismatch')} "
                                       f"unexpected_decline={o.get('unexpected_decline')}" +
                                       ("" if ok else f" rc={r.returncode} first={o.get('first')!r} out={r.stdout[-300:]!r}"))
    except Exception as e:
        record("logs-format-fast", False, repr(e))


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
    """A producer stopped BETWEEN claiming a ring slot and publishing it -- deterministically: its
    record "UHH_TEST_WEDGE o N" stops in the agent's test stop right after the claim (enabled by
    UHH_TEST_LOG_WEDGE=1, which logs_target sets in itself; agent.cpp test_wedge_point) and the
    target confirms the claimed, unpublished slot in the shared ring. (It used to sample a running
    producer with SuspendThread for that instant: wedged=0 on slow CI runners.) Then:
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
            # the producer's stopped record ("UHH_TEST_WEDGE o N", agent test stop) is delivered
            # only in suspend mode (resumed): it counts as a log like any other
            logs = sum(1 for x in o if x.get("kind") == "probe_log" and
                       str(x.get("message", "")).startswith(("o ", "UHH_TEST_WEDGE o ")))
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
            # (exit: rc 1 is expected -- the target exits 7 -- and not checked; wedged=1 is the
            # precondition: the producer was caught between claiming and publishing its slot.)
            record(name, ok, f"wedged={a.get('wedged')} tries={a.get('tries')} {detail} hits={hits} logs={logs} "
                             f"interrupted={interrupted} dropped={rep.get('log_dropped')} rc={r.returncode}")
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
    call_func; thread ids are then taken (threads created suspended and ended unrun, the creator
    moving across the CPUs: Windows reuses a freed id only once its free list has run dry) until
    a thread gets the dead thread's id; it and 19 more run. Every hit of every
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
        r, o = go("cfkill", ["ar_target.exe!ar_cf_site=ar_on_cf"], timeout=300)
        rw, rep, lg, bad = row(o), report(o), logs(o), []
        hits, calls = hits_of(o, "ar_cf_site"), rw.get("calls", -1)
        intr, logged = rep.get("callbacks_interrupted"), lg.get("ar cf", 0)
        if rw.get("killed") != 1: bad.append(f"victim not killed inside call_func: {rw}")
        if rw.get("reused") != 1 or rw.get("threads") != 20:
            bad.append(f"the dead id was not given out again: reused={rw.get('reused')} threads={rw.get('threads')} "
                       f"after {rw.get('consumed')} ids in {rw.get('ms')} ms")
        if hits != calls + 1: bad.append(f"hits={hits} want={calls + 1}")
        if logged != calls: bad.append(f"logged={logged} want={calls} (callbacks skipped)")
        if set(lg) - {"ar cf"}: bad.append(f"logs={lg}")
        if intr != 1: bad.append(f"interrupted={intr} want=1")
        if hits is None or intr is None or hits != logged + intr: bad.append(f"hits != logs + interrupted")
        if rep.get("log_dropped") != 0: bad.append(f"dropped={rep.get('log_dropped')}")
        if rep.get("app_exit") != 0 or r.returncode != 0: bad.append(f"app_exit={rep.get('app_exit')} rc={r.returncode}")
        record("callfunc-kill-reuse", not bad, "; ".join(bad) or
               f"threads={rw.get('threads')} reused={rw.get('reused')} (after {rw.get('consumed')} ids, {rw.get('ms')} ms) "
               f"hits={hits} logs={logged} interrupted={intr}")
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
                # It exited: its last lines may still be in the pipe (the reader thread lags the exit;
                # seen once: quit's "app" line missed, rc=0) -- read them all before calling it dead.
                self.out.t.join(timeout=10)
                got = [l for l in self.out.lines if f'"kind":"{kind}"' in l]
                if len(got) > n:
                    return json.loads(got[n])
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

    def __init__(self, pid, cfg, *extra, group=False, driver="lifecycle_driver.exe", env=None, keep=False):
        args = [str(exe(driver)), str(pid)]
        for k in ("open", "close", "read", "flag", "slow", "work"):
            args += [f"--{k}", cfg.get(k, "none")]
        args += [str(x) for x in extra]
        self.probes = sum(1 for k in ("open", "close", "read", "flag", "slow", "work") if cfg.get(k, "none") != "none")
        self.p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if group else 0,
                                  env=dict(os.environ, **env) if env else None)
        self.logs, self.other, self.cv = 0, [], threading.Condition()
        self.keep, self.loglines = keep, []                 # keep: the probe_log lines too (short runs only)
        self.t = threading.Thread(target=self._pump, daemon=True); self.t.start()
        self.err = Lines(self.p.stderr)

    def _pump(self):
        for line in self.p.stdout:
            with self.cv:
                if line.startswith('{"kind":"probe_log"'):
                    self.logs += 1
                    if self.keep: self.loglines.append(line)
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
        """The session's final accounting {hits, logs_written, log_dropped, in_flight, source}:
        probe_close's 'probe: detached:' line (a detach), its 'probe: ended:' line (the close asked
        for a detach but the target ended first) or the probe_report record (the session ended on
        its own -- the target exited/died -- or never attached). in_flight: callbacks still running
        at the detach / interrupted by the target's end. None if none was printed."""
        for l in self.err.lines:
            m = re.search(r"probe: (detached|ended): .*?hits=(\d+) logs_written=(\d+) log_dropped=(\d+) in_flight=(\d+)", l)
            if m:
                return {"hits": int(m.group(2)), "logs_written": int(m.group(3)), "log_dropped": int(m.group(4)),
                        "in_flight": int(m.group(5)), "source": m.group(1)}
        rep = report([json.loads(l) for l in self.other if l.startswith('{"kind":"probe_report"')])
        if rep:
            return {"hits": rep.get("hits"), "logs_written": rep.get("logs_written"), "log_dropped": rep.get("log_dropped"),
                    "in_flight": rep.get("callbacks_interrupted") or 0, "source": "report"}
        return None

    def attached(self):
        return any('"kind":"attached"' in l for l in self.other)

    def errors(self):
        return [l[:200] for l in self.err.lines
                if "error" in l.lower() or "warning" in l.lower() or "failed" in l or "crashed" in l][:4]

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
    no program error; every log written reached stdout and none was dropped. breakpoint/hw-only
    (owner decision 2026-11-07: the agent goes only into sessions with an inline probe): no
    probe_api_agent.dll in the target after any cycle."""
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
            if not lc_has_inline(cfg) and c.get("dead") is None and c.get("agent_loaded") != 0:
                bad.append(f"c{k}: agent module in a breakpoint/hw-only target {lc_brief(c)}")
            if not ok_logs or not lc_clean(c) or c2.get("flips") != 0 or d.p.returncode != 0:
                bad.append(f"c{k}: rc={d.p.returncode} logs={d.logs} final={fin} {lc_brief(c)} flips_after={c2.get('flips')}"
                           + (f" err={d.errors()}" if d.errors() else ""))
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
    right after a detach was requested (5 ms after; "detach0": at once, so the death races the
    request; "late": the test-hook driver acts on the request 400 ms late, the target dies 50 ms
    after it -- forced, the session ends on the target's EXIT_PROCESS before probe_run acts on
    the request, as seen once in ~20 x86 runs: no final accounting was printed): the controller must notice, end its session and exit on its own (no hang, no
    crash) with every log it wrote delivered and none dropped. A session that was established
    ("attached") must report its final accounting (hits, logs_written, log_dropped, in_flight:
    probe_close's detached/ended line or the runner's probe_report), logs_written == the
    probe_log records delivered on stdout, log_dropped == 0, and exit 0; an attach that failed
    before the session existed must exit 1 with a report of zero logs. (Not every lifecycle
    probe logs every hit, so hits are not balanced against logs here; realbig/stdout do that.)"""
    bad, n, seen = [], 0, []
    if not exe("lifecycle_driver_th.exe"):
        bad.append("missing project-built binary lifecycle_driver_th.exe")
    for when in (0, 2, 10, 40, 150, 600, "detach", "detach0", "late"):
        n += 1
        tg = d = None
        if when == "late" and not exe("lifecycle_driver_th.exe"):
            continue
        try:
            tg = LcTarget("--threads", 4, "--churn")
            if when == "late":
                d = LcDriver(tg.pid, cfg, "--detach-on-stdin", driver="lifecycle_driver_th.exe",
                             env={"UHH_TEST_STOP_LATE_MS": "400"})
            else:
                d = LcDriver(tg.pid, cfg, "--detach-on-stdin")
            if when in ("detach", "detach0", "late"):
                d.wait_attached(); d.wait_active(timeout=30)
                d.detach()
                if when == "detach": time.sleep(0.005)
                if when == "late": time.sleep(0.05)
            else:
                time.sleep(when / 1000.0)
            tg.kill()
            if not d.finish(timeout=10):
                d.detach()                                  # the session may still wait for its detach cue
            fin_ok = d.finish(timeout=60)
            rc = d.p.returncode
            acct, session = d.accounting(), d.attached()
            seen.append(f"{when}:{'S' if session else '-'}{d.logs}" + (f"/{acct['source'][0]}" if acct else ""))
            why = []
            if not fin_ok: why.append("driver did not finish")
            if acct is None:
                why.append("no final accounting (neither 'probe: detached:'/'probe: ended:' nor probe_report)")
            elif acct["logs_written"] != d.logs or acct["log_dropped"] != 0:
                why.append(f"logs_written={acct['logs_written']} delivered={d.logs} dropped={acct['log_dropped']} "
                           f"({acct['source']})")

            if session and rc != 0: why.append(f"rc={rc} after the session was established")
            if when == "late" and session and (acct or {}).get("source") != "ended":
                why.append(f"forced late stop: accounting from {(acct or {}).get('source')} (want 'probe: ended:')")
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


# An INT3 / single step (DR or trap flag) of ours left in the target; a 32-bit (WOW64) target can
# also end with their WOW64 forms as its exit code, its unhandled-exception filter never called.
LC_TRAP_CODES = {"0x80000003", "0x80000004", "0x4000001f", "0x4000001e"}


def lc_has_inline(cfg):
    return "inline" in cfg.values()


def lc_controller_killed(cfgname, cfg):
    """The controller is killed (TerminateProcess) while attached, mid-run with every probe live
    and logging.
    Sessions with an inline probe (inline, mixed) carry the agent and its controller-death guard
    (Lifecycle L1): the TARGET must survive -- keep running, never fault, never hang, make no
    error -- and, once the controller is gone, be left with no live hook / INT3 / debug register
    (it would die or misbehave at its next hit otherwise).
    breakpoint/hw-only sessions (owner decision 2026-11-07: the agent is injected only for inline
    probes; "controller-crash self-unhook: not worth the cost") inject nothing: while attached the
    target must have NO probe_api_agent.dll loaded, and a killed controller leaves its INT3s/DRs
    behind (kill-on-exit off: the target is not killed with it). Asserted: the target either runs
    on or dies at its next hit with OUR trap -- 0x80000003 (INT3) / 0x80000004 (DR or trap
    flag) -- never another fault and never a hang. The outcomes are listed in the detail."""
    guarded = lc_has_inline(cfg)
    bad, n, took, outcomes = [], 0, [], []
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
                if not guarded:
                    c0 = tg.check()                            # attached, every probe live
                    if c0.get("agent_loaded") != 0:
                        bad.append(f"kill@{when}: agent module in a breakpoint/hw-only target: {lc_brief(c0)}")
            else:
                time.sleep(float(when.split("-")[1]))
            d.kill(); d.finish(timeout=30)
            steps = [f"fin={time.time() - t0:.0f}"]
            time.sleep(3.0)                                    # the target runs on, alone
            c = tg.check()
            steps.append(f"chk={time.time() - t0:.0f}{'!' if c.get('hung') else ''}")
            if not guarded:
                if c.get("hung"):
                    bad.append(f"kill@{when}: target hung {lc_brief(c)}")
                elif c.get("dead") is not None:
                    codes = {str(json.loads(l).get("code")).lower() for l in tg.unhandled() if '"kind":"unhandled"' in l}
                    if not codes and isinstance(c.get("dead"), int):
                        codes = {f"0x{c['dead'] & 0xFFFFFFFF:08x}"}         # exit code only (no filter report)
                    outcomes.append(f"{when}:died{'/'.join(sorted(x for x in codes if x))}")
                    if not codes or not codes <= LC_TRAP_CODES:
                        bad.append(f"kill@{when}: died rc={c.get('dead')} unhandled={tg.unhandled()} (want only our trap)")
                else:
                    outcomes.append(f"{when}:alive(code_diff={c.get('code_diff')},dr_dirty={c.get('dr_dirty')},"
                                    f"agent={c.get('agent_loaded')})")
                    if c.get("agent_loaded") != 0:
                        bad.append(f"kill@{when}: agent module in a breakpoint/hw-only target: {lc_brief(c)}")
                continue
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
           f"cases={n} took=[{' '.join(took)}]" + (f" unguarded_outcomes=[{' '.join(outcomes)}]" if outcomes else "")
           + (f" bad={bad[:3]}" if bad else ""))


def lc_agent_refused(cfgname, cfg):
    """The session fails in the middle of an attach (here: the target only admits Microsoft-
    signed DLLs, so the inline agent cannot load) while other probes are already armed: the
    controller must let go of the target ON ITS DEBUG THREAD before it returns (INT3s restored,
    DRs cleared, debugger detached) -- not leave live traps behind a dead event loop -- and
    every log it wrote must be delivered. The target runs on, untouched, and exits cleanly.
    breakpoint/hw-only (owner decision 2026-11-07: no agent without an inline probe): the policy
    is irrelevant -- the session attaches, logs and detaches normally, with no agent load
    attempted and no warning, and no agent module in the target."""
    name = f"lifecycle-agent-refused-{cfgname}"
    tg = d = None
    try:
        tg = LcTarget("--threads", 4, "--ms-signed-only")
        if not lc_has_inline(cfg):
            d = LcDriver(tg.pid, cfg, "--detach-on-stdin")
            active = d.wait_attached() and d.wait_active(timeout=30) and d.wait_logs(50, timeout=30)
            c0 = tg.check()
            d.detach()
            fin_ok = d.finish(timeout=60)
            ok_logs, fin = lc_logs_ok(d)
            c = tg.check()
            a = tg.quit()
            noise = [l[:120] for l in d.err.lines if "agent" in l.lower() or "guard" in l or "warning" in l]
            ok = (bool(active) and fin_ok and d.p.returncode == 0 and ok_logs and c0.get("agent_loaded") == 0
                  and not noise and lc_clean(c) and lc_clean(a) and a.get("rc") == 0)
            record(name, ok, f"active={bool(active)} driver_rc={d.p.returncode} logs={d.logs} final={fin} "
                             f"agent_while_attached={c0.get('agent_loaded')} {lc_brief(c)} exit={a.get('rc')}"
                             + ("" if ok else f" noise={noise[:3]} err={d.errors()} unhandled={tg.unhandled()}"))
            return
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


def lc_unload_unseen(cfgname, cfg):
    """A detach while a hooked DLL's unload has not been processed yet (ROADMAP L5 / ciresid: the
    early-detach race of lifecycle-detach-early-*-inline, ~1 in 128 rows on CI): the program
    unloaded hunt_dll (unmapped) and the controller has not handled its UNLOAD_DLL event when
    the agent's final unhook runs, so the request is still INSTALLED at an unmapped site. The
    restore wrote there -- an access violation on the agent's stop thread killed the target.
    Forced deterministically: the test-hook driver (UHH_TEST_DEFER_UNLOAD=hunt_dll.dll) leaves
    that unload unprocessed. The probe on hunt_dll!HuntWork must have gone active and hit
    (work logs), then after the detach the target must be alive and clean, every log
    delivered. Every config (breakpoint/hw: the INT3 / DR of an unmapped site at detach)."""
    name = f"lifecycle-unload-unseen-{cfgname}"
    if not exe("lifecycle_driver_th.exe"):
        return missing_bin(name, "lifecycle_driver_th")
    tg = d = None
    try:
        tg = LcTarget("--threads", 2)
        dcfg = dict(cfg, work="breakpoint" if cfg["read"] == "hw" else cfg["read"])   # hw: keep a DR free
        d = LcDriver(tg.pid, dcfg, "--detach-on-stdin", driver="lifecycle_driver_th.exe",
                     env={"UHH_TEST_DEFER_UNLOAD": "hunt_dll.dll"})
        if not d.wait_attached() or not d.wait_active(n=d.probes - 1):        # HuntWork: pending (not loaded)
            raise RuntimeError(f"not active: {d.errors()}")
        once = tg._cmd("dllonce", "dllonce")
        active = d.err.wait_for(lambda l: l.startswith("probe: active hunt_dll.dll!HuntWork"), 10)
        deferred = d.err.wait_for(lambda l: l.startswith("probe: test: unload of hunt_dll.dll left unprocessed"), 10)
        time.sleep(0.3)
        d.detach()
        fin_ok = d.finish(timeout=120)
        ok_logs, fin = lc_logs_ok(d)
        c = tg.check()
        a = tg.quit()
        work_logs = fin is not None and fin[0] > 0
        bad = []
        if once.get("mapped") != 0 or not once.get("work"): bad.append(f"dllonce={once}")
        if not active: bad.append("HuntWork never went active")
        if not deferred: bad.append("the unload was not deferred (test hook)")
        if not fin_ok or d.p.returncode != 0: bad.append(f"driver rc={d.p.returncode} finished={fin_ok}")
        if not ok_logs or not work_logs: bad.append(f"logs={d.logs} final={fin}")
        if not lc_clean(c): bad.append(lc_brief(c))
        if not lc_clean(a) or a.get("rc") != 0: bad.append(f"quit rc={a.get('rc')} {lc_brief(a)}")
        record(name, not bad, " ".join(bad) + ("" if not bad else f" unhandled={tg.unhandled()} stderr_tail="
                                               f"{[l[:200] for l in d.err.lines if not l.startswith('probe: active')][-10:]}")
               or f"HuntWork hooked, hit (work={once.get('work')}), unloaded unseen; detach clean: logs={d.logs} "
                  f"final={fin} target alive, exit 0")
    except Exception as e:
        record(name, False, repr(e))
    finally:
        if d: d.kill()
        if tg: tg.kill()


def lc_unload_reused(cfgname, cfg):
    """codex3 #1: a detach while a hooked DLL's unload has not been processed AND other
    executable code now occupies its old address (JIT-style memory committed over the freed
    range; equally a different image mapped at the same base). The agent's final unhook only
    checked "mapped executable and not the original bytes", so it wrote hunt_dll's original
    bytes over the NEW code -- program corruption. Forced deterministically as in
    lifecycle-unload-unseen (UHH_TEST_DEFER_UNLOAD=hunt_dll.dll) plus the target's dllreuse
    (0x90 code over the whole old range). After the detach every byte of that range must still
    be 0x90, the target alive and clean, every log delivered. Every config (breakpoint: the
    INT3 restore only writes over our own 0xCC; hw: nothing to write)."""
    name = f"lifecycle-unload-reused-{cfgname}"
    if not exe("lifecycle_driver_th.exe"):
        return missing_bin(name, "lifecycle_driver_th")
    tg = d = None
    try:
        tg = LcTarget("--threads", 2)
        dcfg = dict(cfg, work="breakpoint" if cfg["read"] == "hw" else cfg["read"])   # hw: keep a DR free
        d = LcDriver(tg.pid, dcfg, "--detach-on-stdin", driver="lifecycle_driver_th.exe",
                     env={"UHH_TEST_DEFER_UNLOAD": "hunt_dll.dll"})
        if not d.wait_attached() or not d.wait_active(n=d.probes - 1):        # HuntWork: pending (not loaded)
            raise RuntimeError(f"not active: {d.errors()}")
        once = tg._cmd("dllreuse", "dllreuse")
        active = d.err.wait_for(lambda l: l.startswith("probe: active hunt_dll.dll!HuntWork"), 10)
        deferred = d.err.wait_for(lambda l: l.startswith("probe: test: unload of hunt_dll.dll left unprocessed"), 10)
        before = tg._cmd("reusecheck", "reusecheck")
        time.sleep(0.3)
        d.detach()
        fin_ok = d.finish(timeout=120)
        ok_logs, fin = lc_logs_ok(d)
        after = tg._cmd("reusecheck", "reusecheck")
        c = tg.check()
        a = tg.quit()
        work_logs = fin is not None and fin[0] > 0
        bad = []
        if once.get("mapped") != 0 or not once.get("work") or not once.get("reused"): bad.append(f"dllreuse={once}")
        if before.get("diff") != 0 or not before.get("len"): bad.append(f"before detach={before}")
        if after.get("diff") != 0: bad.append(f"NEW CODE OVERWRITTEN at detach: {after}")
        if not active: bad.append("HuntWork never went active")
        if not deferred: bad.append("the unload was not deferred (test hook)")
        if not fin_ok or d.p.returncode != 0: bad.append(f"driver rc={d.p.returncode} finished={fin_ok}")
        if not ok_logs or not work_logs: bad.append(f"logs={d.logs} final={fin}")
        if not lc_clean(c): bad.append(lc_brief(c))
        if not lc_clean(a) or a.get("rc") != 0: bad.append(f"quit rc={a.get('rc')} {lc_brief(a)}")
        record(name, not bad, " ".join(bad) + ("" if not bad else f" unhandled={tg.unhandled()} stderr_tail="
                                               f"{[l[:200] for l in d.err.lines if not l.startswith('probe: active')][-10:]}")
               or f"HuntWork hooked, hit (work={once.get('work')}), unloaded unseen, {after.get('len')} bytes of new "
                  f"code over its range untouched by the detach; logs={d.logs} final={fin} target alive, exit 0")
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
    with no unhandled report; then, with that fixed, HUNG): the controller dies while the agent's
    first install round waits on its FREEZE request, every other thread already suspended
    (UHH_TEST_FREEZE_STALL_MS parks the controller exactly there). The raise then comes back
    unserviced; the agent must NOT write the hooks unfrozen (SafetyHook's own trap path made the
    ntdll stub page non-executable under the installer and every other thread), and must resume
    the threads the dead controller froze although no service thread watches it yet (its named
    event died with it). The target must run on, untouched and unhooked."""
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


def check_ctrl_pack_oom():
    """codex3 #3: an allocation failure while the drainer packs an agent-ring record (header
    appended, text/frames throw) left the partial record in the pack: every later entry of that
    pack misparsed (garbage / foreign text, lengths read past the pack). Test hook
    UHH_TEST_PACK_FAIL=n (probe_api_testhooks) throws std::bad_alloc after every n-th record's
    header. lifecycle_driver_th, inline open/close/read/flag on a 4-thread lifecycle_target,
    ~4 s: every log line must be valid JSON whose message is one this driver's callbacks write
    (printable, known prefix), log_dropped == the number of injected failures (> 0), logs written
    == lines received, the target clean."""
    name = "ctrl-pack-oom"
    if not exe("lifecycle_driver_th.exe") or not exe("lifecycle_target.exe"):
        return missing_bin(name, "lifecycle_driver_th / lifecycle_target")
    tg = d = None
    try:
        tg = LcTarget("--threads", 4)
        cfg = dict(open="inline", close="inline", read="inline", flag="inline")
        d = LcDriver(tg.pid, cfg, "--detach-on-stdin", driver="lifecycle_driver_th.exe",
                     env={"UHH_TEST_PACK_FAIL": "37"}, keep=True)
        if not d.wait_attached() or not d.wait_active():
            raise RuntimeError(f"not active: {d.errors()}")
        time.sleep(4.0)
        try:
            d.detach()
        except OSError:
            pass                                      # the driver died already (reported below)
        fin_ok = d.finish(timeout=120)
        acc = d.accounting() or {}
        c = tg.check()
        a = tg.quit()
        injected = sum(1 for l in d.err.lines if l.startswith("probe: test: pack append failed"))
        known = re.compile(r"^(flag flipped in memory at 0x[0-9a-f]+|open pid=\d+ |map handle=0x[0-9a-f]+ -> pid=\d+ |"
                           r"read handle=0x[0-9a-f]+ pid=\d+ |callfunc ok=|recurse ok=)[ -~]*$")
        badlines, msgs = [], 0
        for l in d.loglines:
            try:
                m = json.loads(l).get("message")
            except json.JSONDecodeError:
                badlines.append(l[:120]); continue
            msgs += 1
            if not isinstance(m, str) or not known.match(m): badlines.append(repr(m)[:120])
        bad = []
        if not fin_ok or d.p.returncode != 0:
            bad.append(f"driver rc=0x{(d.p.returncode or 0) & 0xffffffff:x} finished={fin_ok} "
                       f"stderr_tail={[l[:160] for l in d.err.lines if 'pack append' not in l][-4:]}")
        if injected < 3: bad.append(f"injected={injected} (want several)")
        if badlines: bad.append(f"malformed_logs={len(badlines)} e.g. {badlines[:3]}")
        if acc.get("log_dropped") != injected: bad.append(f"log_dropped={acc.get('log_dropped')} want {injected}")
        if acc.get("logs_written") != d.logs: bad.append(f"logs_written={acc.get('logs_written')} lines={d.logs}")
        if not lc_clean(c) or not lc_clean(a) or a.get("rc") != 0: bad.append(f"target {lc_brief(c)} quit={a.get('rc')}")
        record(name, not bad, " ".join(bad) or
               f"{d.logs} logs all well-formed, {injected} injected pack failures = log_dropped, target clean")
    except Exception as e:
        record(name, False, repr(e))
    finally:
        if d: d.kill()
        if tg: tg.kill()


def check_lifecycle():
    """Lifecycle edge cases (examples/lifecycle) under every backend and mixed: repeated
    attach/detach/re-attach, detach at awkward moments, the target dying under the controller,
    two controllers, Ctrl+Break at random points, the controller being killed. UHH_LC=substr
    narrows it (e.g. UHH_LC=reattach,inline)."""
    if not exe("lifecycle_driver.exe") or not exe("lifecycle_target.exe") or not exe("hunt_dll.dll"):
        return missing_bin("lifecycle", "lifecycle_driver / lifecycle_target / hunt_dll")
    for cfgname, cfg in LC_CONFIGS.items():
        for fn in (lc_reattach, lc_detach_cases, lc_target_dies, lc_two_controllers, lc_interrupt, lc_controller_killed,
                   lc_killed_in_freeze, lc_agent_refused, lc_install_stuck, lc_unload_unseen, lc_unload_reused):
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
                  and the drain's 15 s bound). Owner decision 2026-11-07 (it used to be waited
                  for without a time limit): the detach completes after ~15 s and accounts it --
                  "still running after 15 s" on stderr, running=1, in_flight=0 (it logged
                  before), hits == logs_written + log_dropped + in_flight, nothing dropped -- its
                  later log is lost (not delivered), and its >256-byte config (a block in the
                  target) is NOT freed under it: the program still gets the right result;
      cfgfree-inline the program suspends a thread inside an inline callback across the whole
                  detach and resumes it afterwards: the detach does not wait for it (running=1;
                  it logged before the suspension, so it is accounted by that log: in_flight=0,
                  agent v23), and the callback's config block is NOT freed under it;
      killarm-*   the controller dies right after writing an INT3 / arming a hw probe (test-hook
                  build, co_driver_th): the agent's guard must undo it -- the target finishes.
                  co_driver --guard adds a never-called inline probe: only a session with an
                  inline probe has the agent and its guard (owner decision 2026-11-07; a
                  breakpoint/hw-only session's controller death: lifecycle-controller-killed-*).
                  The same holds for reptail, touchkill, cx2-touchprog and cx2-evsusp/cosusp;
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

    # -- (4)+(2) an inline callback outliving the detach's 15 s bound ---------------------
    name = "cxlib-late-inline"
    try:
        def detach_now(tgt, att, tout):
            t0 = time.time(); att.stdin.write("\n"); att.stdin.flush()
            att.wait(timeout=150)
            return time.time() - t0
        row, aout, aerr, arc, trc, took = cx_attached_run("late", "inline", d, t, detach_now)
        sm = cx_detach_summary(aerr.lines)
        done = [l for l in aout.lines if '"message":"co late-done' in l]
        cut = [l for l in aerr.lines if "still running after 15 s; not waiting longer" in l]
        bad = []
        if row.get("ret") != CX_LATE_SUM or row.get("body") != 0 or row.get("done") != 1:
            bad.append(f"target ret={row.get('ret')} want {CX_LATE_SUM} body={row.get('body')} done={row.get('done')} "
                       "(config freed under the callback?)")
        if done: bad.append(f"late log delivered={len(done)} (the detach must not wait 19 s for it)")
        if not cut: bad.append("no 'still running after 15 s' line")
        if (sm.get("log_dropped") != 0 or sm.get("in_flight") != 0 or sm.get("running") != 1 or sm.get("hits") != 1
                or sm.get("logs_written") != 1):
            bad.append(f"summary={sm} (want hits=1 logs_written=1 log_dropped=0 in_flight=0 running=1)")
        if not 14 <= took <= 30: bad.append(f"detach took {took:.1f}s (want ~15 s + the agent's 2 s unhook wait)")
        if arc != 0 or trc != 0: bad.append(f"driver_rc={arc} target_rc={trc}")
        record(name, not bad, " ".join(bad) or f"detach_took={took:.1f}s summary={sm} ret={row.get('ret')} "
                                                "(late log lost, accounted running=1)")
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
        if (sm.get("in_flight") != 0 or sm.get("running") != 1 or sm.get("log_dropped") != 0 or
                sm.get("hits") != sm.get("logs_written")):
            bad.append(f"summary={sm} (want running=1 in_flight=0 dropped=0 hits=logs_written)")
        if took > 12: bad.append(f"detach waited {took:.1f}s for a callback the program holds suspended")
        if arc != 0 or trc != 0: bad.append(f"driver_rc={arc} target_rc={trc}")
        record(name, not bad, " ".join(bad) or f"detach_took={took:.1f}s summary={sm} ret={row.get('ret')}")
    except Exception as e:
        record(name, False, repr(e))

    # -- (3) the controller dies right after arming: the guard must cover it (--guard: an
    # inline probe in the session, so the agent and its guard are there -- 2026-11-07) -----
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
            att = subprocess.Popen([str(dth), "--backend", bk, "--guard", "--case", "spin", "--attach", str(json.loads(w)["pid"])],
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

    # -- (3, extra) a thread inside a displaced REP string copy when the controller dies (test-
    # hook build: right after sending a thread into one). The copy is the site's trampoline
    # (it jumps back by itself, ROADMAP A5); a program single-stepping itself still gets the
    # older copy ended by an INT3 of ours, which the guard takes. Either way: the target runs on.
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
        att = subprocess.Popen([str(dth), "--backend", "breakpoint", "--guard", "--case", "rep", "--attach", str(json.loads(w)["pid"])],
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
                att = subprocess.Popen([str(dth), "--backend", "hw", "--guard", "--case", "spin", "--attach", str(g["pid"])],
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


def check_callfunc_concurrent():
    """call_func from several threads' callbacks (ROADMAP F5/D3). Breakpoint/hw keep their
    documented contract -- callbacks never overlap: other threads' code-probe hits wait while a
    call is in flight -- and every call of every thread succeeds, none is lost.
    callfunc-many-<bp/hw>: 100 threads hit the probe at once, each callback call_funcs a callee
    that hits another probe on its own thread (counted, no callback): 100 calls ok, exact hits.
    callfunc-watch-<backend>: a data-watch hit -- which cannot be held back -- arrives while
    another thread's callback is inside call_func (a 500 ms callee); the watch callback's own
    call_func must work (it returned 0: "no nesting") and both calls return their values.
    callfunc-lock-inline: the inline reference for a callee needing a lock another thread
    holds at its own probe hit (breakpoint/hw: that thread waits until the call is over, so the
    call times out -- documented, limitations.md)."""
    d, t = exe("ar_driver.exe"), exe("ar_target.exe")
    if not d or not t:
        return missing_bin("callfunc-concurrent", "ar_driver/ar_target")

    def go(bk, case, specs, timeout):
        args = [d, "--backend", bk]
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

    def common(r, rep, bad):
        if rep.get("log_dropped") != 0: bad.append(f"dropped={rep.get('log_dropped')}")
        if rep.get("callbacks_interrupted", 0) != 0: bad.append(f"intr={rep.get('callbacks_interrupted')}")
        if rep.get("app_exit") != 0 or r.returncode != 0: bad.append(f"app_exit={rep.get('app_exit')} rc={r.returncode}")
        if "timed out" in (r.stderr or ""): bad.append("call_func timed out")

    def rec(name, bad, ok_detail, r):
        record(name, not bad, ("; ".join(bad) + f" stderr={(r.stderr or '')[-300:]!r}") if bad else ok_detail)

    n = 100
    for bk in ("breakpoint", "hw"):
        name = f"callfunc-many-{bk}"
        try:
            r, o = go(bk, "cfmanyq", ["ar_target.exe!ar_cf_site=ar_on_cf", "ar_target.exe!ar_cf_inner=ar_on_cf_inner"], 180)
            rw, rep, lg, bad = row(o), report(o), logs(o), []
            hs, hi = hits_of(o, "ar_cf_site"), hits_of(o, "ar_cf_inner")
            if rw.get("sum") != sum(range(1000, 1000 + n)) or rw.get("arrived") != n: bad.append(f"row={rw}")
            if hs != n or hi != n: bad.append(f"hits site={hs} inner={hi} want={n}")
            if lg != {"ar cf-many ok=1 good=1": n}: bad.append(f"logs={lg}")
            common(r, rep, bad)
            rec(name, bad, f"row={rw} hits={hs}/{hi} logs={lg}", r)
        except Exception as e:
            record(name, False, repr(e))
    for bk in ("breakpoint", "hw", "inline"):
        name = f"callfunc-watch-{bk}"
        try:
            r, o = go(bk, "cfwatch", ["ar_target.exe!ar_cf_site=ar_on_cf", "ar_target.exe!ar_cfw_setup=ar_on_cfw_setup"], 90)
            rw, rep, lg, bad = row(o), report(o), logs(o), []
            if (rw.get("inside"), rw.get("caller"), rw.get("var")) != (1, 5, 1): bad.append(f"row={rw}")
            want = {"ar cfw setup=1": 1, "ar cfw slow ok=1 r=11": 1, "ar cfw watch ok=1 r=9": 1}
            if lg != want: bad.append(f"logs={lg}")
            common(r, rep, bad)
            rec(name, bad, f"row={rw} logs={lg}", r)
        except Exception as e:
            record(name, False, repr(e))
    for bk in ("breakpoint", "hw"):
        # Codex review: the watch callback takes a lock the call_func'ing callback holds across
        # the call. A data-watch hit must wait like any other hit (callbacks never overlap);
        # run during the parked call it blocked the debug thread for good (timeout: hang).
        name = f"callfunc-watch-lock-{bk}"
        try:
            r, o = go(bk, "cfwatchlock", ["ar_target.exe!ar_cf_site=ar_on_cf", "ar_target.exe!ar_cfw_setup=ar_on_cfwl_setup"], 60)
            rw, rep, lg, bad = row(o), report(o), logs(o), []
            if (rw.get("inside"), rw.get("caller"), rw.get("var")) != (1, 6, 1): bad.append(f"row={rw}")
            want = {"ar cfw setup=1": 1, "ar cfw slow ok=1 r=11": 1, "ar cfw watch ok=1 r=9": 1}
            if lg != want: bad.append(f"logs={lg}")
            common(r, rep, bad)
            rec(name, bad, f"row={rw} logs={lg}", r)
        except Exception as e:
            record(name, False, repr(e))
    dth = exe("ar_driver_th.exe")
    for bk in ("breakpoint", "hw"):
        # Codex review: a call_func timing out while its callee's return trap is already queued
        # (the timeout ran first: forced by the UHH_TEST_LATE_TRAP hook, every call). The late
        # trap belongs to the abandoned call: swallowed -- it reached the target as an unknown
        # breakpoint (the target died). Every call returns 0, the program is unaffected.
        name = f"callfunc-late-trap-{bk}"
        if not dth:
            missing_bin(name, "ar_driver_th"); continue
        try:
            env = dict(os.environ, UHH_TEST_LATE_TRAP="1")
            r = subprocess.run([str(dth), "--backend", bk, "--probe", "ar_target.exe!ar_cf_site=ar_on_cf", "--", str(t), "cfmanyq"],
                               capture_output=True, text=True, timeout=300, env=env)
            o = [json.loads(x) for x in r.stdout.splitlines() if x.strip().startswith("{")]
            rw, rep, lg, bad = row(o), report(o), logs(o), []
            if rw.get("sum") != sum(range(1000, 1000 + n)) or rw.get("arrived") != n: bad.append(f"row={rw}")
            if lg != {"ar cf-many ok=0 good=0": n}: bad.append(f"logs={lg} (want every call timed out)")
            if hits_of(o, "ar_cf_site") != n: bad.append(f"hits={hits_of(o, 'ar_cf_site')} want={n}")
            if "target crashed" in (r.stderr or ""): bad.append("target crashed")
            if rep.get("app_exit") != 0 or r.returncode != 0: bad.append(f"app_exit={rep.get('app_exit')} rc={r.returncode}")
            rec(name, bad, f"{n} late return traps swallowed, row={rw}", r)
        except Exception as e:
            record(name, False, repr(e))
    name = "callfunc-lock-inline"
    try:
        r, o = go("inline", "cflock", ["ar_target.exe!ar_cf_site=ar_on_cf"], 90)
        rw, rep, lg, bad = row(o), report(o), logs(o), []
        if (rw.get("inside"), rw.get("joined"), rw.get("held"), rw.get("waiter")) != (1, 1, 2, 4): bad.append(f"row={rw}")
        if lg != {"ar cf-lock holder ok=1 r=6": 1, "ar cf-lock waiter ok=1 r=7": 1}: bad.append(f"logs={lg}")
        if hits_of(o, "ar_cf_site") != 2: bad.append(f"hits={hits_of(o, 'ar_cf_site')} want=2")
        common(r, rep, bad)
        rec(name, bad, f"row={rw} logs={lg}", r)
    except Exception as e:
        record(name, False, repr(e))


def check_hw_co_borrow():
    """Codex review of the NtContinue fixup (F4): breakpoint/hw call_original on a hw probe
    with all 4 DRs in use lends the probe's own slot to the return catch on that thread. The
    original raises an exception and continues it (filter -> NtContinue): the context-restore
    fixup must leave that thread's borrowed slot alone, or the return is missed and the
    callback abandoned. 5 calls, each call_original ok with the original's value."""
    d, t = exe("ar_driver.exe"), exe("ar_target.exe")
    if not d or not t:
        return missing_bin("hw-co-borrow-restore", "ar_driver/ar_target")
    try:
        r, o = run([d, "--backend", "hw", "--probe", "ar_target.exe!ar_dr_arm=ar_on_dr_arm",
                    "--probe", "ar_target.exe!ar_cob_other=ar_on_site", "--probe", "ar_target.exe!ar_cob_orig=ar_on_cob",
                    "--", t, "coborrow"], timeout=120)
        rw, rep, bad = next((x for x in o if x.get("kind") == "ar"), {}), report(o), []
        msgs = Counter(str(x.get("message", "")) for x in o if x.get("kind") == "probe_log")
        want = Counter({f"ar cob ok=1 r={2 * i}": 1 for i in range(5)})
        want["ar site"] = 1
        if (rw.get("sum"), rw.get("other")) != (20, 3): bad.append(f"row={rw}")
        if msgs != want: bad.append(f"logs={dict(msgs)}")
        if "hw DR3" not in (r.stderr or ""): bad.append("4th debug register not in use (no borrowing)")
        if "without returning" in (r.stderr or "") or "did not return" in (r.stderr or ""): bad.append("call_original released")
        if rep.get("app_exit") != 0 or r.returncode != 0: bad.append(f"app_exit={rep.get('app_exit')} rc={r.returncode}")
        record("hw-co-borrow-restore", not bad, ("; ".join(bad) + f" stderr={(r.stderr or '')[-300:]!r}") if bad
               else f"row={rw} logs exact")
    except Exception as e:
        record("hw-co-borrow-restore", False, repr(e))


def check_hw_dr_restore():
    """ROADMAP F4: a hw probe armed at runtime (from a callback) while one thread sits in an
    exception filter and another inside a user APC. Both later resume through NtContinue
    with a context the kernel captured BEFORE the arm -- debug registers included -- which
    put the old DRs back: that thread never hit the probe again. Every call of the probed
    function on all three threads must be seen (30 hits, one log each)."""
    d, t = exe("ar_driver.exe"), exe("ar_target.exe")
    if not d or not t:
        return missing_bin("hw-dr-restore", "ar_driver/ar_target")
    try:
        r, o = run([d, "--backend", "hw", "--probe", "ar_target.exe!ar_dr_arm=ar_on_dr_arm", "--", t, "drrestore"], timeout=120)
        rw = next((x for x in o if x.get("kind") == "ar"), {})
        rep, bad = report(o), []
        got = Counter(int(m.group(1)) for x in o if x.get("kind") == "probe_log"
                      for m in [re.match(r"ar dr x=(\d+)$", str(x.get("message", "")))] if m)
        want = Counter(list(range(100, 110)) + list(range(200, 210)) + list(range(300, 310)))
        hits = next((p.get("hits") for p in probes(o) if "ar_dr_site" in str(p.get("location", ""))), None)
        if (rw.get("inside"), rw.get("main"), rw.get("exception"), rw.get("apc")) != (1, 10, 10, 10): bad.append(f"row={rw}")
        if got != want:
            miss = want - got
            bad.append(f"logs missing={sorted(miss)[:5]}.. ({sum(miss.values())}: main={sum(1 for x in miss if x < 200)} "
                       f"exception={sum(1 for x in miss if 200 <= x < 300)} apc={sum(1 for x in miss if x >= 300)}) "
                       f"extra={sorted((got - want).elements())[:5]}")
        if hits != 30: bad.append(f"hits={hits} want=30")
        arm = next((p.get("hits") for p in probes(o) if "ar_dr_arm" in str(p.get("location", ""))), None)
        site_rows = sum(1 for p in probes(o) if "ar_dr_site" in str(p.get("location", "")))
        if arm != 1 or site_rows != 1: bad.append(f"arm hits={arm} site probes={site_rows} (want 1, 1)")
        if rep.get("log_dropped") != 0: bad.append(f"dropped={rep.get('log_dropped')}")
        if rep.get("app_exit") != 0 or r.returncode != 0: bad.append(f"app_exit={rep.get('app_exit')} rc={r.returncode}")
        record("hw-dr-restore", not bad, "; ".join(bad) or f"row={rw} hits={hits}")
    except Exception as e:
        record("hw-dr-restore", False, repr(e))
    # Codex review: the FIRST instruction after the restore. A hw probe is armed (from a
    # callback) exactly where a thread inside a user APC resumes -- right after its wait's
    # kernel transition in NtDelayExecution. That instruction must hit it: on x86 the old DRs
    # were re-applied only after it had run (trap flag) and the hit was lost.
    try:
        r, o = run([d, "--backend", "hw", "--probe", "ar_target.exe!ar_dr2_arm=ar_on_dr2_arm", "--", t, "drresume"], timeout=120)
        rw, rep, bad = next((x for x in o if x.get("kind") == "ar"), {}), report(o), []
        tid = rw.get("apc_tid")
        mine = [x for x in o if x.get("kind") == "probe_log" and x.get("message") == "ar dr2 hit" and x.get("tid") == tid]
        if (rw.get("inside"), rw.get("site")) != (1, 1): bad.append(f"row={rw}")
        if len(mine) != 1: bad.append(f"resume-site hits on the APC thread={len(mine)} (want 1)")
        if any(x.get("message") == "ar dr2 refused" for x in o if x.get("kind") == "probe_log"): bad.append("arm refused")
        if rep.get("app_exit") != 0 or r.returncode != 0: bad.append(f"app_exit={rep.get('app_exit')} rc={r.returncode}")
        record("hw-dr-restore-first", not bad, "; ".join(bad) or f"row={rw} hit at the first resumed instruction")
    except Exception as e:
        record("hw-dr-restore-first", False, repr(e))


def check_inline_absolute():
    """ROADMAP D5: an inline probe added BY ADDRESS (probe_add_address from a callback, here
    at a call's return site) gets the same site checks as one added by symbol. ar_d5_code's
    return site is followed by a loop head 3 bytes later: a 5-byte hook there would split
    the loop's target. inline-absolute-refused: refused (the program's result unchanged, no
    hit); inline-absolute-fallback: with PROBE_FALLBACK_HW it runs as a hw probe instead.
    (Address probes used to skip the function-bounds / branch-target part of the check.)"""
    d, t = exe("ar_driver.exe"), exe("ar_target.exe")
    if not d or not t:
        return missing_bin("inline-absolute", "ar_driver/ar_target")
    callee = "ar_target.exe!ar_d5_code+" + ("0x14" if pe_is_x86(t) else "0x21")
    for kind, cb in (("refused", "ar_on_d5_callee"), ("fallback", "ar_on_d5_callee_fb")):
        name = f"inline-absolute-{kind}"
        try:
            r, o = run([d, "--backend", "inline", "--probe", f"{callee}={cb}", "--", t, "absret"], timeout=120)
            rw, rep, bad = next((x for x in o if x.get("kind") == "ar"), {}), report(o), []
            msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
            ret = next((p for p in probes(o) if str(p.get("location", "")).startswith("0x")), {})
            if rw.get("sum") != 30: bad.append(f"row={rw} (want sum=30)")
            if msgs.count("ar d5 add=1") != 1: bad.append(f"add logs={[m for m in msgs if 'add=' in m]}")
            refused = "would be written across a jump" in (r.stderr or "")
            if kind == "refused":
                if not refused: bad.append("no refusal on stderr")
                if ret.get("hits") or msgs.count("ar d5 ret"): bad.append(f"return probe ran: {ret}")
            else:
                # (armed before or after the first call returns: 2 or 3 returns seen, each logged)
                if ret.get("backend") != "hw" or ret.get("hits") not in (2, 3) or msgs.count("ar d5 ret") != ret.get("hits"):
                    bad.append(f"return probe={ret} logs={msgs.count('ar d5 ret')} (want hw, 2-3)")
            if rep.get("app_exit") != 0 or r.returncode != 0: bad.append(f"app_exit={rep.get('app_exit')} rc={r.returncode}")
            record(name, not bad, "; ".join(bad) + ("" if not bad else f" stderr={(r.stderr or '')[-400:]!r}")
                   or f"sum={rw.get('sum')} return_probe={ret.get('backend')}/{ret.get('hits')}")
        except Exception as e:
            record(name, False, repr(e))


def check_cet_agent():
    """The injected inline agent (probe_api_agent.dll) must load into a process whose policy
    is BlockNonCetBinaries: it is linked /CETCOMPAT (every `ret` in its own code returns
    through a real call: audited, ROADMAP "BlockNonCetBinaries"). cet-agent-image: the bit
    is set. cet-agent-block-noncet: cet_probe turns the policy on for itself at runtime,
    then maps a non-CETCOMPAT DLL (configparse.dll: refused) and the agent (must map). SKIP
    when this Windows does not let a process set the policy at runtime."""
    agent, pr_exe, other = BIN / "probe_api_agent.dll", exe("cet_probe.exe"), BIN / "configparse.dll"
    if not agent.exists() or not pr_exe or not other.exists():
        return missing_bin("cet-agent", "probe_api_agent.dll/cet_probe/configparse.dll")
    try:
        record("cet-agent-image", pe_cetcompat(agent) and not pe_cetcompat(other),
               f"probe_api_agent.dll:CETCOMPAT={pe_cetcompat(agent)} configparse.dll:CETCOMPAT={pe_cetcompat(other)}")
    except Exception as e:
        record("cet-agent-image", False, repr(e))
    try:
        r, o = run([pr_exe, "--block-non-cet", str(other), str(agent)], timeout=60)
        blk = next((x for x in o if x.get("kind") == "cet_block"), {})
        loads = {x.get("dll"): x for x in o if x.get("kind") == "cet_block_load"}
        a, c = loads.get("probe_api_agent.dll", {}), loads.get("configparse.dll", {})
        detail = (f"set={blk.get('set')} set_error={blk.get('set_error')} policy={blk.get('BlockNonCetBinaries')} "
                  f"configparse={c.get('loaded')}/{c.get('error')} agent={a.get('loaded')}/{a.get('error')}")
        if blk.get("set") != 1 or blk.get("BlockNonCetBinaries") != 1:
            skip("cet-agent-block-noncet", f"BlockNonCetBinaries cannot be set at runtime here: {detail}")
        elif c.get("loaded") != 0:
            skip("cet-agent-block-noncet", f"the policy is set but not enforced (a non-CET DLL still maps): {detail}")
        else:
            record("cet-agent-block-noncet", a.get("loaded") == 1, detail)
    except Exception as e:
        record("cet-agent-block-noncet", False, repr(e))


def check_sessions_repeat(n=60):
    """Many sessions one after the other in ONE controller process (ROADMAP "x86 cumulative-
    session flakiness"): ar_driver --repeat, backends in turn (breakpoint, hw, inline), each
    session the cfwatch case (a callback inside call_func on one thread while a data watch
    added from a callback fires on another and call_funcs too). Every session exact (row,
    every log, nothing dropped), and the controller's handle count flat after warm-up (a
    leaked or double-closed handle shows here or as a failure)."""
    d, t = exe("ar_driver.exe"), exe("ar_target.exe")
    if not d or not t:
        return missing_bin("sessions-repeat", "ar_driver/ar_target")
    try:
        r, o = run([d, "--backend", "cycle", "--repeat", n, "--probe", "ar_target.exe!ar_cf_site=ar_on_cf",
                    "--probe", "ar_target.exe!ar_cfw_setup=ar_on_cfw_setup", "--", t, "cfwatch"], timeout=60 + 15 * n)
        iters = [x for x in o if x.get("kind") == "iter"]
        rows = [x for x in o if x.get("kind") == "ar"]
        reps = [x for x in o if x.get("kind") == "probe_report"]
        msgs = Counter(str(x.get("message", "")) for x in o if x.get("kind") == "probe_log")
        bad = []
        failed = [(x.get("i"), x.get("backend")) for x in iters if x.get("ok") != 1]
        if len(iters) != n or failed: bad.append(f"iters={len(iters)}/{n} failed={failed[:6]}")
        wrong = [i for i, x in enumerate(rows) if (x.get("inside"), x.get("caller"), x.get("var")) != (1, 5, 1)]
        if len(rows) != n or wrong: bad.append(f"rows={len(rows)}/{n} wrong={wrong[:6]}")
        want = {"ar cfw setup=1": n, "ar cfw slow ok=1 r=11": n, "ar cfw watch ok=1 r=9": n}
        if dict(msgs) != want: bad.append(f"logs={dict(msgs)}")
        drops = [i for i, x in enumerate(reps) if x.get("log_dropped") != 0 or x.get("error") is not None]
        if len(reps) != n or drops: bad.append(f"reports={len(reps)}/{n} bad={drops[:6]}")
        h = [x.get("handles", 0) for x in iters]
        growth = (h[-1] - h[2]) if len(h) > 3 else None
        if growth is None or growth > 24: bad.append(f"controller handles {h[:3]}..{h[-3:]} (growth {growth})")
        if r.returncode != 0: bad.append(f"rc={r.returncode}")
        record("sessions-repeat", not bad, ("; ".join(bad) + f" stderr={(r.stderr or '')[-300:]!r}") if bad
               else f"{n} sessions exact; controller handles {h[2]} -> {h[-1]}")
    except Exception as e:
        record("sessions-repeat", False, repr(e))


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


def check_cx2_review():
    """Second Codex review of the code merged on 2026-11-06 (docs/ROADMAP.md "Codex review 2
    findings"), each reproduced on the unfixed code first:
      cx2-faultfresh-<b>: a probed load faults and the program's handler, in turn, retries it
        (commits the page), SKIPS it (emulates the load) or UNWINDS out of it (SEH __except).
        The next call is a fresh execution of the site on the same thread with no other event
        in between: one hit, one log per call on every backend (breakpoint took it for a retry
        of the faulted execution: no callback, no hit), the handler never sees a trap flag.
      cx2-touchprog-hw (x86 controller): the PROGRAM holds a thread suspended; the controller
        arms a hw probe at attach (a context call on every thread) and dies inside the call on
        that thread, before the implicit WOW64 suspension and (second run) with it in place
        (test-hook build). The guard must leave exactly the program's suspension (it resumed
        every thread the call had listed, once: the program's suspension was released).
      cx2-manythreads-inline / cx2-manydead-inline: 4200 threads (all alive at once: distinct
        ids, more than the agent's 4096-entry thread table) make one inline hit each; then a
        callback on yet another thread outlives a detach -- while those threads still live, and
        after they have all exited. Its log must be delivered (it ran untracked: the detach
        drain counted 0 live callbacks and gave up, the log was dropped).
      cx2-evsusp-<b> / cx2-cosusp-<b> (X2 open note; breakpoint, hw): the program suspends a
        worker the controller has just let run again -- its probe hit continued (evsusp; the
        test-hook build dies 1.5 s later with no event or guard sync in between) or inside its
        callback's call_original (cosusp; the controller killed while the original runs). The
        guard listed that thread as held until the next sync (evsusp) / for the whole call and
        once per 20 ms poll (cosusp), so it released the PROGRAM's suspension: it must leave it.
      touchprog / evsusp / cosusp run co_driver --guard (a never-called inline probe beside the
        breakpoint/hw one): the agent and its guard exist only in sessions with an inline probe
        (owner decision 2026-11-07)."""
    cd, ct = exe("ctrl_driver.exe"), exe("ctrl_target.exe")
    d, t, dth = exe("co_driver.exe"), exe("co_target.exe"), exe("co_driver_th.exe")
    if not cd or not ct or not d or not t or not dth:
        return missing_bin("cx2-review", "ctrl_driver/ctrl_target/co_driver/co_target/co_driver_th")

    N = 300
    for bk in ("breakpoint", "hw", "inline"):
        name = f"cx2-faultfresh-{bk}"
        try:
            r, o = run([cd, "--scenario", "faultmix", "--backend", bk, "--", ct, "faultmix", "--n", N], timeout=180)
            res = next((x for x in o if x.get("kind") == "ctrl_result"), {})
            logs = [x for x in o if x.get("kind") == "probe_log"]
            hits = sum(x.get("hits", 0) for x in o if x.get("kind") == "probe")
            rep = report(o)
            bad = []
            if r.returncode != 0: bad.append(f"exit={r.returncode}")
            if rep.get("error") is not None: bad.append(f"error={rep.get('error')}")
            if rep.get("log_dropped", 0) != 0: bad.append(f"log_dropped={rep.get('log_dropped')}")
            if hits != N or len(logs) != N: bad.append(f"hits={hits} logs={len(logs)} (want {N} each)")
            third = N // 3
            if (res.get("retry"), res.get("skip"), res.get("unwind")) != (third, third, third):
                bad.append(f"handler retry={res.get('retry')} skip={res.get('skip')} unwind={res.get('unwind')} (want {third} each)")
            if res.get("sum") is None or res.get("sum") != res.get("want"):
                bad.append(f"target sum={res.get('sum')} want={res.get('want')}")
            if res.get("tf") != 0: bad.append(f"tf_in_handler={res.get('tf')}")
            if res.get("stray") != 0: bad.append(f"stray_single_steps={res.get('stray')}")
            record(name, not bad, " ".join(bad) or f"hits={hits} logs={len(logs)} retry/skip/unwind="
                                                   f"{res.get('retry')}/{res.get('skip')}/{res.get('unwind')}")
        except Exception as e:
            record(name, False, repr(e))

    name = "cx2-touchprog-hw"
    if not pe_is_x86(t):
        skip(name, "x86 only (an x64 controller has no implicit suspend)")
    else:
        def touchprog(mode):
            """co_target susp: the controller dies in its context call on the program-suspended
            worker, before (mode "before") or inside (default: suspended) the implicit suspension."""
            procs = []
            try:
                tgt = subprocess.Popen([str(t), "susp", "--wait"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, text=True)
                procs.append(tgt)
                tout = Lines(tgt.stdout)
                sl = tout.wait_for(lambda l: '"kind":"susp"' in l, 30)
                w = tout.wait_for(lambda l: '"kind":"waiting"' in l, 30)
                if not sl or not w:
                    raise RuntimeError("target never reached its gate")
                env = dict(os.environ, UHH_TEST_DIE_IN_TOUCH=str(json.loads(sl)["tid"]))
                if mode:
                    env["UHH_TEST_DIE_IN_TOUCH_MODE"] = mode
                att = subprocess.Popen([str(dth), "--backend", "hw", "--guard", "--case", "susp", "--attach", str(json.loads(w)["pid"])],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=env)
                procs.append(att)
                aerr = Lines(att.stderr)
                att.wait(timeout=90)                       # dies arming the hw probe on every thread
                aerr.t.join(timeout=30)
                tgt.stdin.write("x"); tgt.stdin.flush()
                tgt.wait(timeout=90)
                row = next((x for x in tout.objs() if x.get("kind") == "co"), {})
                rc = tgt.returncode & 0xFFFFFFFF
                bad = []
                if att.returncode != 98: bad.append(f"controller_rc={att.returncode} (98: died in the touch)")
                died = next((l for l in aerr.lines if l.startswith("probe: test: dying")), "")
                if "enabled=1" not in died: bad.append(f"not killed in a guarded touch: {died!r}")
                if rc != 0: bad.append(f"target_rc=0x{rc:x}")
                if row.get("first") != 0 or row.get("prev") != 1 or row.get("ran_while_suspended") != 0:
                    bad.append(f"ResumeThread prev={row.get('prev')} (want 1: the program's own suspension) "
                               f"ran_while_suspended={row.get('ran_while_suspended')} (want 0)")
                if row.get("done") != 1 or row.get("sum") != sum(i * 3 + 5 for i in range(20)):
                    bad.append(f"target row={row}")
                return bad + ([f"died={died[:200]!r}"] if bad else [])
            finally:
                for q in procs:
                    if q.poll() is None:
                        q.kill()
        try:
            bad = [f"[{m or 'suspended'}] {x}" for m in ("before", None) for x in touchprog(m)]
            record(name, not bad, " ".join(bad) or "died before / inside the implicit suspension: the program's "
                                                   "suspension kept (prev=1, worker never ran) both times")
        except Exception as e:
            record(name, False, repr(e))

    st = exe("susp_target.exe")

    def susp_after(case, bk):
        """susp_target evsusp / cosusp: the program suspends its worker right after the controller let
        it run again (its hit continued / inside its callback's call_original); the controller then
        dies (evsusp: the test-hook build dies 1.5 s after continuing the hit, no event or guard sync
        meanwhile; cosusp: killed while the original runs). The guard must leave exactly the
        program's suspension: the worker did not run, the program's ResumeThread reports 1."""
        procs, bad = [], []
        try:
            tgt = subprocess.Popen([str(st), case], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True)
            procs.append(tgt)
            tout = Lines(tgt.stdout)
            w = tout.wait_for(lambda l: '"kind":"waiting"' in l, 30)
            if not w:
                raise RuntimeError("target never reached its gate")
            env = dict(os.environ)
            if case == "evsusp":
                env["UHH_TEST_DIE_AFTER_HIT_MS"] = "1500"
            att = subprocess.Popen([str(dth), "--backend", bk, "--guard", "--case", case, "--module", "susp_target.exe",
                                    "--attach", str(json.loads(w)["pid"])],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=env)
            procs.append(att)
            aerr = Lines(att.stderr)
            if not aerr.wait_for(lambda l: l.startswith("probe: active ") and "co_idle" not in l, 60):
                raise RuntimeError(f"probe never active: {aerr.lines[-4:]}")
            if any("guard unavailable" in l for l in aerr.lines):
                bad.append("controller-death guard unavailable")
            tgt.stdin.write("x"); tgt.stdin.flush()                # gate 1: the worker goes
            sl = tout.wait_for(lambda l: '"kind":"susp"' in l, 60)
            if not sl:
                raise RuntimeError("the program never suspended its worker")
            wtid = json.loads(sl)["tid"]
            if case == "evsusp":
                att.wait(timeout=90)                                 # dies 1.5 s after continuing the hit
            else:
                time.sleep(0.5)                                      # ~25 of call_original's 20 ms polls
                if att.poll() is None:
                    att.kill()
                att.wait(timeout=60)
            aerr.t.join(timeout=30)
            died = next((l for l in aerr.lines if l.startswith("probe: test: dying")), "")
            tgt.stdin.write("x"); tgt.stdin.flush()                # gate 2: the controller is dead
            tgt.wait(timeout=90)
            row = next((x for x in tout.objs() if x.get("kind") == "co"), {})
            rc = tgt.returncode & 0xFFFFFFFF
            if case == "evsusp":
                if att.returncode != 96: bad.append(f"controller_rc={att.returncode} (96: died after the hit)")
                if "enabled=1" not in died: bad.append(f"guard not enabled at the death: {died!r}")
            elif att.returncode == 0:
                bad.append("controller ended before it was killed (the call_original was not in flight)")
            if rc != 0: bad.append(f"target_rc=0x{rc:x}")
            if row.get("first") != 0 or row.get("prev") != 1 or row.get("ran_while_suspended") != 0:
                bad.append(f"SuspendThread first={row.get('first')} (want 0: no suspension of the controller's in place "
                           f"when the program suspends) ResumeThread prev={row.get('prev')} (want 1: the program's own "
                           f"suspension) ran_while_suspended={row.get('ran_while_suspended')} (want 0)")
            want = 76 if case == "cosusp" else 5
            if row.get("done") != 1 or row.get("ret") != want: bad.append(f"target row={row} (ret want {want})")
            listed = re.search(r"held=\[([^\]]*)\]", died)
            return bad, (f"worker={wtid} prev={row.get('prev')} ran={row.get('ran_while_suspended')} ret={row.get('ret')}"
                         + (f" guard_listed_worker={str(wtid) in listed.group(1).split(',')}" if listed else ""))
        finally:
            for q in procs:
                if q.poll() is None:
                    q.kill()

    for case in ("evsusp", "cosusp"):
        for bk in ("breakpoint", "hw"):
            name = f"cx2-{case}-{bk}"
            if not st:
                missing_bin(name, "susp_target"); continue
            try:
                bad, detail = susp_after(case, bk)
                record(name, not bad, " ".join(bad + [detail]))
            except Exception as e:
                record(name, False, repr(e))

    # cx2-cosample-<b>: the same call_original (co_hold, ~1.5 s inside the original) with the controller
    # staying; the program samples its worker's suspend count for 1 s. Any suspension of the
    # controller's in place at a sample is visible to the program (SuspendThread returns 1, not 0):
    # call_original's 20 ms "left the original?" poll suspended the thread for its context read,
    # and a program suspending that thread at that moment got prev=1 (cx2-cosusp-breakpoint on CI,
    # run 42256070700). The poll now reads the context without a suspension: x64 must show none.
    # x86 (a 32-bit controller, WOW64): GetThreadContext on another thread suspends it INSIDE the
    # call (measured on Windows 10 19045, a standalone 32-bit program reading another thread's
    # context once per ms: ~0.1% of a sampler's SuspendThread calls return 1; ThreadWow64Context
    # is refused to 32-bit callers (STATUS_INVALID_INFO_CLASS) and Wow64GetThreadContext suspends
    # the same way). That residual is inherent to a 32-bit debugger and bounded here at 1%.
    x86 = pe_is_x86(st) if st else False
    for bk in ("breakpoint", "hw"):
        name = f"cx2-cosample-{bk}"
        if not st:
            missing_bin(name, "susp_target"); continue
        procs = []
        try:
            tgt = subprocess.Popen([str(st), "cosample"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True)
            procs.append(tgt)
            tout = Lines(tgt.stdout)
            w = tout.wait_for(lambda l: '"kind":"waiting"' in l, 30)
            if not w:
                raise RuntimeError("target never reached its gate")
            att = subprocess.Popen([str(d), "--backend", bk, "--case", "cosample", "--module", "susp_target.exe",
                                    "--attach", str(json.loads(w)["pid"])],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            procs.append(att)
            aout, aerr = Lines(att.stdout), Lines(att.stderr)
            if not aerr.wait_for(lambda l: l.startswith("probe: active "), 60):
                raise RuntimeError(f"probe never active: {aerr.lines[-4:]}")
            tgt.stdin.write("x"); tgt.stdin.flush()
            tgt.wait(timeout=90); att.wait(timeout=90)
            row = next((x for x in tout.objs() if x.get("kind") == "co"), {})
            wraps = sum(1 for x in aout.objs() if x.get("kind") == "probe_log" and x.get("message") == "co hold-done")
            bad = []
            if tgt.returncode != 0: bad.append(f"target_rc={tgt.returncode}")
            if att.returncode != 0: bad.append(f"controller_rc={att.returncode}")
            foreign, samples = row.get("foreign"), row.get("samples") or 0
            if foreign is None or (foreign != 0 if not x86 else foreign > samples // 100):
                bad.append(f"foreign={foreign} of {samples} samples (want {'<= 1% (WOW64 residual)' if x86 else 0})")
            if (row.get("samples") or 0) < 100 or row.get("in_original") != 1:
                bad.append(f"samples={row.get('samples')} in_original={row.get('in_original')} (want >= 100, 1)")
            if row.get("done") != 1 or row.get("ret") != 38 or wraps != 1:
                bad.append(f"target row={row} hold_logs={wraps}")
            record(name, not bad, " ".join(bad) or f"samples={samples} foreign={foreign}"
                   + (" (x86: WOW64 GetThreadContext's implicit suspension, residual)" if x86 and foreign else "")
                   + " ret=38 call_original completed")
        except Exception as e:
            record(name, False, repr(e))
        finally:
            for q in procs:
                if q.poll() is None:
                    q.kill()

    for case in ("many", "manydead"):
        name = f"cx2-{case}threads-inline" if case == "many" else "cx2-manydead-inline"
        try:
            def detach_now(tgt, att, tout):
                t0 = time.time(); att.stdin.write("\n"); att.stdin.flush()
                att.wait(timeout=200)
                return time.time() - t0
            row, aout, aerr, arc, trc, took = cx_attached_run(case, "inline", d, t, detach_now, timeout=200)
            sm = cx_detach_summary(aerr.lines)
            done = [l for l in aout.lines if '"message":"co late-done' in l]
            n = row.get("threads", 0)
            bad = []
            if n != 4200 or row.get("called") != n or row.get("distinct") != n:
                bad.append(f"threads={n} called={row.get('called')} distinct={row.get('distinct')} (want 4200 each)")
            if row.get("ret") != CX_LATE_SUM or row.get("done") != 1:
                bad.append(f"target ret={row.get('ret')} want {CX_LATE_SUM} done={row.get('done')}")
            if len(done) != 1 or f"sum={CX_LATE_SUM}" not in done[0]:
                bad.append(f"late log delivered={len(done)}")
            if sm.get("log_dropped") != 0 or sm.get("in_flight") != 0 or sm.get("hits") != n + 1 or sm.get("logs_written") != n + 2:
                bad.append(f"summary={sm} (want hits={n + 1} logs_written={n + 2} dropped=0 in_flight=0)")
            if arc != 0 or trc != 0: bad.append(f"driver_rc={arc} target_rc={trc}")
            record(name, not bad, " ".join(bad) or f"threads={n} detach_took={took:.1f}s summary={sm}")
        except Exception as e:
            record(name, False, repr(e))


# ---- realbig: real large apps -- detach residue, controller memory, overhead ----------------
# The bigapps tier (above) proves PowerShell and the Edge BROWSER process survive launch/attach/
# detach. realbig goes further on the same machine: a sandboxed Edge RENDERER (V8 JIT, CIG:
# Microsoft-signed DLLs only, so the inline agent cannot load) and the browser while a page
# ticks, PowerShell 5.1 / pwsh 7 with the JIT's NtProtectVirtualMemory probed, and heavily
# multi-threaded native programs (robocopy /MT:16, findstr /s) on both arches -- and after
# every detach it compares the target with ITSELF before the attach: every executable byte of
# the probed modules, every thread's DR0-3/DR7/TF, the debug port (scripts/target_state.py).
# Each run also samples the controller's private bytes (flat) and times the backend.
REALBIG_FILES = 800
REALBIG_MANY = 10000
# Every probe LOGS (one short field where the arguments do not matter): after a detach the
# session's final accounting is a total over all probes, so hits == logs_written + in_flight
# is exact only when every probe logs.
# (robocopy and findstr never call NtReadFile/NtWriteFile on these files: findstr maps them,
# and robocopy's copy engine moves the data with sections too -- 0 hits on both, measured.)
REALBIG_ROBO_PROBES = ["ntdll.dll!NtCreateFile:xxO", "ntdll.dll!NtMapViewOfSection:xx", "ntdll.dll!NtClose:x",
                       "KernelBase.dll!WaitForSingleObjectEx:xx"]
REALBIG_FIND_PROBES = ["ntdll.dll!NtCreateFile:xxO", "ntdll.dll!NtMapViewOfSection:xx",
                       "ntdll.dll!NtUnmapViewOfSection:xx", "ntdll.dll!NtClose:x"]
REALBIG_JIT_PROBES = ["ntdll.dll!NtProtectVirtualMemory:xxxx", "ntdll.dll!NtAllocateVirtualMemory:x",
                      "KernelBase.dll!CreateFileW:Wxx", "ntdll.dll!NtWaitForSingleObject:x"]
# KernelBase!VirtualAlloc (PartitionAlloc / V8 pages): a probe OUTSIDE ntdll, which in a
# sandboxed renderer only resolves with the mapped-name fallback (hFile-less LOAD_DLL events).
# (Edge's renderer barely calls NtProtectVirtualMemory: logged, not required.)
REALBIG_EDGE_PROBES = ["ntdll.dll!NtProtectVirtualMemory:xxxx", "ntdll.dll!NtAllocateVirtualMemory:x",
                       "ntdll.dll!NtWaitForSingleObject:x", "KernelBase.dll!VirtualAlloc:xxxx"]
PWSH_EXE = Path(r"C:\Program Files\PowerShell\7\pwsh.exe")
# The default suite runs these (~3 min x64); --bigapps runs every realbig row (~10 min x64).
REALBIG_DEFAULT = ("realbig-robocopy-detach-breakpoint,realbig-findstr-launch-inline,"
                   "realbig-edge-renderer-breakpoint,realbig-edge-renderer-inline")


def _target_state():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import target_state
    return target_state


def realbig_session(bk, specs, tail, timeout, cwd=None, on_attached=None):
    """uhh_trace (backend bk, probes specs, then tail) with its private bytes / handles sampled
    every 0.5 s. stdout goes to a file (no pipe backpressure); the UHH records are split from
    the target's own bytes (stdout_split's rule). on_attached() runs once the "attached" record
    is out (the attach, agent and probe installs are done). Returns a dict."""
    ts = _target_state()
    d = Path(tempfile.mkdtemp(prefix="uhh-realbig-s-", dir=Path.cwd()))
    t0 = time.time()
    timed_out, samples = False, []
    with open(d / "out", "wb") as fo, open(d / "err", "wb") as fe:
        p = subprocess.Popen([str(a) for a in bigapps_tracer(bk, specs, tail)], stdout=fo, stderr=fe,
                             stdin=subprocess.DEVNULL, cwd=cwd)
        while p.poll() is None:
            m = ts.mem(p.pid)
            if m:
                samples.append((time.time() - t0, m[0], m[2]))
            if on_attached:
                try:
                    if b'"kind":"attached"' in (d / "out").read_bytes()[:1 << 20]:
                        on_attached()
                        on_attached = None
                except OSError:
                    pass
            if time.time() - t0 > timeout:
                timed_out = True
                p.kill()
                break
            time.sleep(0.5)
        p.wait()
    secs = time.time() - t0
    out = (d / "out").read_bytes()
    err = (d / "err").read_bytes().decode(errors="replace")
    shutil.rmtree(d, ignore_errors=True)
    recs, keep = [], []
    for line in stdout_lines(out):
        if line.startswith(b'{"kind":') and line.endswith(b"\n"):
            try:
                recs.append(json.loads(line))
                continue
            except ValueError:
                pass
        keep.append(line)
    return {"rc": p.returncode, "out": out.decode(errors="replace"), "err": err, "recs": recs,
            "text": b"".join(keep), "samples": samples, "secs": secs, "timed_out": timed_out}


def realbig_mem(samples):
    """Controller growth: the peak of the last quarter of the run vs the peak of the second
    (the first quarter is attach + symbol loading). Flat = under 32 MB / 300 handles."""
    priv = [s[1] for s in samples]
    hnd = [s[2] for s in samples]
    if len(priv) < 8:
        return [], f"ctl_samples={len(priv)}" + (f" ctl_peak={max(priv) >> 20}MB" if priv else "")
    q = len(priv) // 4
    growth = max(priv[3 * q:]) - max(priv[q:2 * q])
    hgrowth = max(hnd[3 * q:]) - max(hnd[q:2 * q])
    bad = []
    if growth > 32 << 20: bad.append(f"controller private bytes grew {growth >> 20} MB")
    if hgrowth > 300: bad.append(f"controller handles grew by {hgrowth}")
    return bad, f"ctl_peak={max(priv) >> 20}MB growth={growth / 2 ** 20:+.1f}MB handles={max(hnd)}({hgrowth:+d})"


def realbig_snapshot(pid, specs):
    names = {"ntdll.dll", "kernelbase.dll", "kernel32.dll"} | {s.split("!")[0].lower() for s in specs}
    return _target_state().snapshot(pid, names)


def realbig_residue(pid, snap):
    """After a detach: the probed modules' code identical to before the attach, no DR/TF left
    on any thread, no debug port."""
    ts = _target_state()
    bad = []
    diff = ts.code_diff(pid, snap)
    if diff: bad.append(f"code changed after detach: {diff[:4]}")
    dirty, unread, n = ts.debug_regs(pid)
    if dirty: bad.append(f"debug registers/TF left: {dirty[:4]}")
    if ts.debugger_present(pid): bad.append("debug port still set after detach")
    agent = ts.module_loaded(pid, "probe_api_agent.dll")
    return bad, (f"residue[code={len(diff)} dr={len(dirty)}/{n} unreadable={unread} "
                 f"mods={len(snap)} agent_loaded={agent}]")


def realbig_judge(s, bk, specs, required, exact):
    """bigapps_judge on a realbig_session result, plus the controller-memory verdict."""
    ok, detail, bad = bigapps_judge(s["recs"], s["out"], s["err"], bk, specs, required, exact)
    # Run to exit: hits == logs + log_dropped + callbacks_interrupted (a callback still running
    # when ExitProcess killed its thread is counted, its log never written -- documented edge).
    rep = report(s["recs"])
    intr = rep.get("callbacks_interrupted") or 0
    if exact and intr:
        want = sum(p.get("hits") or 0 for p in probes(s["recs"]))
        bad = [b for b in bad if not (b.startswith("logs_written=") and rep.get("logs_written", 0) + intr == want)]
        detail += f" interrupted={intr}"
    mbad, mdetail = realbig_mem(s["samples"])
    if s["timed_out"]: bad.append("controller timed out (killed)")
    # After a detach: the final totals over every probe (all of them log) must balance.
    fin = re.findall(r"probe: detached: hits=(\d+) logs_written=(\d+) log_dropped=(\d+) in_flight=(\d+)", s["err"])
    if fin:
        h, w, d, f = (int(x) for x in fin[-1])
        if h != w + d + f: bad.append(f"detach totals: hits={h} != logs_written={w} + dropped={d} + in_flight={f}")
        detail += f" final_hits={h} in_flight={f}"
    return bad + mbad, f"{detail} {mdetail}"


def realbig_tree(root, files=REALBIG_FILES):
    """A deterministic tree: files spread over 16x3 directories, 2-120 KB of text each, every
    7th one with a UHHNEEDLE<i> line in the middle."""
    for i in range(files):
        d = root / f"d{i % 16:02d}" / f"s{i % 3}"
        d.mkdir(parents=True, exist_ok=True)
        n = 2048 + (i * 7919) % 120000
        line = f"{i:05d} the quick brown fox {i * 31 % 1000:03d}\r\n".encode()
        body = (line * (n // len(line) + 1))[:n]
        if i % 7 == 0:
            body = body[:n // 2] + f"\r\nUHHNEEDLE{i}\r\n".encode() + body[n // 2:]
        (d / f"f{i:05d}.txt").write_bytes(body)


def realbig_tree_digest(root):
    import hashlib
    h = hashlib.sha256()
    n = 0
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(str(p.relative_to(root)).lower().encode() + b"\0" + hashlib.sha256(p.read_bytes()).digest())
            n += 1
    return h.hexdigest(), n


def realbig_sysprog(name, arch):
    return (Path(r"C:\Windows\SysWOW64") if arch == "x86" else SYS32) / name


def _share_lock(path):
    """Open `path` with no sharing (a gate): every other open fails with a sharing violation
    until close_share_lock(handle)."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    h = k32.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80, None)   # GENERIC_READ, share 0, OPEN_EXISTING
    if not h or h == wintypes.HANDLE(-1).value:
        raise RuntimeError(f"cannot lock {path}: error {ctypes.get_last_error()}")
    return h


def _close_share_lock(h):
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32")
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle(h)


def realbig_robocopy(bk, mode, arch, work, base):
    """robocopy /MT:16 (launch: the 800-file tree under UHH; detach: attached while it copies the
    many-small-files tree, detached 1.5 s after the attach). The copy must be exact and exit 1
    (copied). (/IPG cannot pace it: with /MT robocopy rejects it, rc 16.)
    Detach: the copy cannot end before the detach on any machine -- the last file in robocopy's
    order is held open with no sharing (a gate) until the detach and the residue check are done;
    robocopy retries it (/R:600 /W:1: a sharing violation is retried, the file then copied,
    exit 1) and finishes after the gate opens. (Ungated, a fast runner finished the whole copy
    during the attach: CI 42213960508 x86, "robocopy ended during the attach".) How far the copy
    had got at the detach is reported (files_at_detach).
    A second gate (the next-to-last file, held until the attach is done) guarantees real copy
    work while attached: a runner copies the other 9998 files in ~1 s, often before the attach
    completes, and robocopy's only activity left was the 1 s retry of the gated file -- an
    NtCreateFile failing with a sharing violation, no handle, no NtClose (CI 42333666071 x86:
    files_at_detach=9999, NtClose 0 hits). Opened at the attach, that file is copied (opened,
    written, CLOSED) at robocopy's next retry, within 1 s, while the probes are live (a slower
    machine is still copying the rest then): the check requires files copied while attached
    (files_at_detach > files_at_attach)."""
    robo = realbig_sysprog("robocopy.exe", arch)
    src = work / ("src" if mode == "launch" else "many")
    dst = work / f"dst-{bk}-{mode}"
    shutil.rmtree(dst, ignore_errors=True)
    want, nfiles = base["src_digest" if mode == "launch" else "many_digest"]
    argv = [robo, src, dst, "/E", "/MT:16", "/R:0", "/W:0", "/NP", "/NFL", "/NDL", "/NJH", "/NJS"]
    bad, extra = [], ""
    if mode == "launch":
        s = realbig_session(bk, REALBIG_ROBO_PROBES, ["--", *argv], 900)
        bad, detail = realbig_judge(s, bk, REALBIG_ROBO_PROBES, [REALBIG_ROBO_PROBES[i].rsplit(":", 1)[0] for i in (0, 2, 3)], True)
        rep = report(s["recs"])
        if rep.get("app_exit") != 1: bad.append(f"robocopy exit={rep.get('app_exit')} (want 1: files copied)")
        extra = f"secs={s['secs']:.1f} base={base['robo_secs']:.1f} x{s['secs'] / max(base['robo_secs'], 0.1):.1f}"
    else:
        gate_file, mid_file = sorted(src.rglob("*.dat"))[-1], sorted(src.rglob("*.dat"))[-2]
        gate, mid = _share_lock(gate_file), _share_lock(mid_file)
        mid_opened = {}

        def open_mid():                                       # the attach is done: copy work while attached
            nonlocal mid
            mid_opened["files"] = sum(1 for _ in dst.rglob("*.dat")) if dst.exists() else 0
            _close_share_lock(mid); mid = None
        argv = [a if a != "/R:0" else "/R:600" for a in argv]
        argv = [a if a != "/W:0" else "/W:1" for a in argv]
        tgt = subprocess.Popen([str(a) for a in argv], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            t0 = time.time()
            while time.time() - t0 < 60 and not dst.exists():
                time.sleep(0.05)
            time.sleep(0.2)
            if tgt.poll() is not None:
                return False, f"robocopy ended before the attach (rc={tgt.returncode})", ["too fast"], ""
            snap = realbig_snapshot(tgt.pid, REALBIG_ROBO_PROBES)
            # Detach soon: a warm copy of many/ takes only ~4 s under inline (the plain base copy,
            # of freshly written files, 15-55 s: the first read of a new file is the slow one).
            # (The gates keep robocopy running past the detach whatever the machine's speed; the
            # window covers realbig_session's 0.5 s poll for "attached" plus robocopy's 1 s retry.)
            dms = 3000
            s = realbig_session(bk, REALBIG_ROBO_PROBES, ["--attach", tgt.pid, "--detach-after-ms", dms], 900,
                                on_attached=open_mid)
            alive = tgt.poll() is None
            at_detach = sum(1 for _ in dst.rglob("*.dat")) if dst.exists() else 0
            at_attach = mid_opened.get("files")
            bad, detail = realbig_judge(s, bk, REALBIG_ROBO_PROBES, [REALBIG_ROBO_PROBES[i].rsplit(":", 1)[0] for i in (0, 2, 3)], False)
            if not alive:
                bad.append(f"robocopy ended during the attach (rc={tgt.returncode}): detach not mid-run")
            else:
                rbad, rdet = realbig_residue(tgt.pid, snap)
                bad += rbad
                detail += " " + rdet
            if '"kind":"detached"' not in s["out"]: bad.append("not detached")
            if at_attach is None: bad.append("the attach never reported (second gate not opened)")
            elif at_detach <= at_attach: bad.append(f"no file copied while attached ({at_attach} -> {at_detach})")
            _close_share_lock(gate); gate = None                  # the gate opens: robocopy finishes
            rc = tgt.wait(timeout=900)
            if rc != 1: bad.append(f"robocopy exit={rc} (want 1)")
            extra = (f"files_at_attach={at_attach} files_at_detach={at_detach}/{nfiles} "
                     f"plain_first_copy={base['robo_many_secs']:.1f}s total={time.time() - t0:.1f}s")
        finally:
            if gate is not None:
                _close_share_lock(gate)
            if mid is not None:
                _close_share_lock(mid)
            if tgt.poll() is None:
                tgt.kill()
    got, n = realbig_tree_digest(dst) if dst.exists() else (None, 0)
    if got != want: bad.append(f"copy differs: files={n}/{nfiles}")
    shutil.rmtree(dst, ignore_errors=True)
    return not bad, f"{detail} files={n}/{nfiles} {extra}", bad, s["err"]


def realbig_findstr(bk, arch, work, base):
    """findstr /s /n over the tree, launched under UHH: output byte-identical to the plain run."""
    fs = realbig_sysprog("findstr.exe", arch)
    s = realbig_session(bk, REALBIG_FIND_PROBES, ["--", fs, "/s", "/n", "/c:UHHNEEDLE", "*.txt"], 900, cwd=work / "src")
    bad, detail = realbig_judge(s, bk, REALBIG_FIND_PROBES, [p.rsplit(":", 1)[0] for p in REALBIG_FIND_PROBES[:2]], True)
    rep = report(s["recs"])
    if rep.get("app_exit") != 0: bad.append(f"findstr exit={rep.get('app_exit')}")
    if s["text"] != base["find_out"]:
        bad.append(f"output differs: {stdout_first_diff(s['text'], base['find_out'])}")
    opened = {str(r.get("message", "")).lower() for r in s["recs"] if r.get("kind") == "probe_log"}
    nopen = sum(1 for m in opened if ".txt" in m)
    nlines = s["text"].count(b"\n")
    return not bad, (f"{detail} out={len(s['text'])}B lines={nlines} txt_opens={nopen} "
                     f"secs={s['secs']:.1f} base={base['find_secs']:.1f} x{s['secs'] / max(base['find_secs'], 0.1):.1f}"), bad, s["err"]


def realbig_native_base(arch, work):
    """Uninstrumented reference runs (best of 2) and the robocopy pacing: /IPG chosen so a paced
    copy lasts long enough to attach, run and detach in the middle."""
    robo, fs = realbig_sysprog("robocopy.exe", arch), realbig_sysprog("findstr.exe", arch)
    src = work / "src"
    base = {"src_digest": realbig_tree_digest(src)}
    times = []
    for k in range(2):
        dst = work / "dst-base"
        shutil.rmtree(dst, ignore_errors=True)
        t0 = time.time()
        r = subprocess.run([str(robo), str(src), str(dst), "/E", "/MT:16", "/R:0", "/W:0", "/NP", "/NFL", "/NDL",
                            "/NJH", "/NJS"], capture_output=True, timeout=600)
        times.append(time.time() - t0)
        if r.returncode != 1 or realbig_tree_digest(dst) != base["src_digest"]:
            raise RuntimeError(f"uninstrumented robocopy failed: rc={r.returncode}")
    base["robo_secs"] = min(times)
    times, outs = [], set()
    for k in range(2):
        t0 = time.time()
        r = subprocess.run([str(fs), "/s", "/n", "/c:UHHNEEDLE", "*.txt"], capture_output=True, timeout=600, cwd=src)
        times.append(time.time() - t0)
        outs.add(r.stdout)
        if r.returncode != 0:
            raise RuntimeError(f"uninstrumented findstr failed: rc={r.returncode}")
    if len(outs) != 1:
        raise RuntimeError("uninstrumented findstr output not deterministic")
    base["find_secs"], base["find_out"] = min(times), outs.pop()
    # The attach target: many small files (file creation dominates, so the plain copy lasts).
    many = work / "many"
    if not many.exists():
        for i in range(REALBIG_MANY):
            d = many / f"m{i % 32:02d}"
            d.mkdir(parents=True, exist_ok=True)
            (d / f"x{i:05d}.dat").write_bytes((bytes(range(256)) * 9)[i % 256:i % 256 + 512 + i % 1536])
    base["many_digest"] = realbig_tree_digest(many)
    dst = work / "dst-base"
    shutil.rmtree(dst, ignore_errors=True)
    t0 = time.time()
    r = subprocess.run([str(robo), str(many), str(dst), "/E", "/MT:16", "/R:0", "/W:0", "/NP", "/NFL", "/NDL", "/NJH",
                        "/NJS"], capture_output=True, timeout=900)
    base["robo_many_secs"] = time.time() - t0
    if r.returncode != 1 or realbig_tree_digest(dst) != base["many_digest"]:
        raise RuntimeError(f"uninstrumented robocopy (many) failed: rc={r.returncode}")
    shutil.rmtree(dst, ignore_errors=True)
    return base


def realbig_ps(bk, ps, secs, label):
    """PowerShell (5.1 or pwsh 7) running bigapps' workload.ps1; attached after READY with the
    JIT's NtProtectVirtualMemory logged, detached halfway; the workload must keep ticking and
    finish with bad=0, exit 0; the residue check runs right after the detach."""
    work = Path(tempfile.mkdtemp(prefix=f"uhh-realbig-{label}-", dir=Path.cwd()))
    wl = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", BIGAPPS_DIR / "workload.ps1",
          "-Seconds", secs, "-Work", work, "-ExpectedHash", bigapps_ps_expected_hash()]
    done_re = re.compile(r"BIGAPPS_DONE iters=(\d+) bad=(\d+) jobs=(\d+) exc=(\d+)")
    target = None
    try:
        target = subprocess.Popen([str(ps), *[str(x) for x in wl]], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, errors="replace")
        tl, te = Lines(target.stdout), Lines(target.stderr)
        if not tl.wait_for(lambda l: l.startswith("BIGAPPS_READY"), 180):
            return False, "workload never READY", ["no READY"], "\n".join(te.lines[-5:])

        def ticks():
            return sum(1 for l in list(tl.lines) if l.startswith("BIGAPPS_TICK"))
        p0 = ticks()
        time.sleep(4.0)
        plain = ticks() - p0                      # uninstrumented tick rate, for the overhead
        snap = realbig_snapshot(target.pid, REALBIG_JIT_PROBES)
        mark = {}
        n0, t_att = ticks(), time.time()
        s = realbig_session(bk, REALBIG_JIT_PROBES, ["--attach", target.pid, "--detach-after-ms", secs * 1000 // 2],
                            secs + 600, on_attached=lambda: mark.update(n=ticks(), t=time.time()))
        n_det, t_det = ticks(), time.time()
        # Ticks while attaching (attach + agent + installs) and while attached (probes live).
        attach_secs = mark.get("t", t_det) - t_att
        attached_ticks = f"attaching={mark.get('n', n_det) - n0}/{attach_secs:.1f}s " \
                         f"attached={n_det - mark.get('n', n_det)}/{t_det - mark.get('t', t_det):.1f}s"
        bad, detail = realbig_judge(s, bk, REALBIG_JIT_PROBES, [p.rsplit(":", 1)[0] for p in REALBIG_JIT_PROBES[2:]], False)
        if target.poll() is None:
            rbad, rdet = realbig_residue(target.pid, snap)
            bad += rbad
            detail += " " + rdet
        else:
            bad.append(f"workload ended during the attach (rc={target.returncode})")
        at_detach = len(tl.lines)
        target.wait(timeout=secs + 600)
        tl.t.join(timeout=30)
        after = sum(1 for l in tl.lines[at_detach:] if l.startswith("BIGAPPS_TICK"))
        m = done_re.search("\n".join(tl.lines))
        if not m:
            bad.append("no BIGAPPS_DONE")
        else:
            it, bd, jobs, exc = (int(x) for x in m.groups())
            if bd != 0 or it == 0 or jobs == 0 or exc != 6 * it: bad.append(f"workload {m.group(0)}")
        if target.returncode != 0: bad.append(f"rc={target.returncode}")
        if '"kind":"detached"' not in s["out"]: bad.append("not detached")
        if after < 2: bad.append(f"ticks after detach={after}")
        return not bad, (f"{detail} ticks plain={plain}/4s {attached_ticks} after={after} "
                         f"{m.group(0) if m else 'no DONE'}"), bad, s["err"]
    finally:
        if target and target.poll() is None:
            target.kill()
        kill_matching(work.name)
        shutil.rmtree(work, ignore_errors=True)


_REALBIG_WORK = {}


def realbig_tick_expected(i):
    """ticks.html's value for tick i (int32 arithmetic, Math.imul semantics)."""
    def i32(v):
        return (v + 2 ** 31) % 2 ** 32 - 2 ** 31
    n = 100000 + i % 50
    if n not in _REALBIG_WORK:
        h = 0
        for j in range(n):
            h = i32(h * 31 + (j ^ (j >> 3)))
        _REALBIG_WORK[n] = h
    c, s = i % 97 + 3, 0
    for j in range(1000):
        s = i32(s + i * c + j)
    return i32(_REALBIG_WORK[n] ^ s ^ i)


def realbig_tick_server():
    """Serves ticks.html and checks every /tick?i=&v= against realbig_tick_expected."""
    import http.server
    page = (BIGAPPS_DIR / "ticks.html").read_bytes()
    st = {"ticks": [], "lock": threading.Lock()}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            try:
                if self.path == "/":
                    body = page
                elif self.path.startswith("/tick?"):
                    q = dict(x.split("=", 1) for x in self.path.split("?", 1)[1].split("&"))
                    i, v = int(q["i"]), int(q["v"])
                    with st["lock"]:
                        st["ticks"].append((time.time(), i, v == realbig_tick_expected(i)))
                    body = b"ok"
                else:
                    self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            except (OSError, ValueError, KeyError):
                pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, st


def realbig_edge_children(udd):
    """{pid: command line} of the Edge processes using this run's user-data-dir."""
    ps = (f"Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | ?{{ $_.CommandLine -like '*{udd}*' }}"
          " | %{ \"$($_.ProcessId)`t$($_.CommandLine)\" }")
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True,
                       text=True, timeout=120)
    out = {}
    for line in r.stdout.splitlines():
        if "\t" in line:
            pid, cmd = line.split("\t", 1)
            out[int(pid)] = cmd
    return out


def realbig_edge(bk, which, secs):
    """Headless Edge on ticks.html; attach to the browser or to the (sandboxed, JIT) renderer,
    detach halfway; the page must keep ticking with right values before, during and after,
    and the target must carry no residue."""
    ts = _target_state()
    udd = Path(tempfile.mkdtemp(prefix="uhh-realbig-edge-", dir=Path.cwd()))
    srv, st = realbig_tick_server()
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    argv = [EDGE_EXE, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
            "--disable-extensions", "--disable-component-update", "--disable-background-networking",
            "--disable-sync", "--no-proxy-server", "--renderer-process-limit=1",
            "--disable-features=SpareRendererForSitePerProcess", f"--user-data-dir={udd}", url]
    browser = None
    try:
        realbig_tick_expected(0)
        browser = subprocess.Popen([str(a) for a in argv], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t0 = time.time()
        while time.time() - t0 < 120 and len(st["ticks"]) < 20:
            time.sleep(0.2)
        if len(st["ticks"]) < 20:
            return False, f"page never ticked ({len(st['ticks'])})", ["no ticks"], ""
        kids = realbig_edge_children(udd.name)
        rends = [p for p, c in kids.items() if "--type=renderer" in c and "--extension-process" not in c]
        if which == "renderer":
            if not rends:
                return False, f"no renderer among {len(kids)} processes", ["no renderer"], ""
            # The busiest renderer is the page's (a spare/extension renderer idles).
            pid = max(rends, key=lambda p: ts.cpu_time(p) or 0)
        else:
            pid = browser.pid
        snap = realbig_snapshot(pid, REALBIG_EDGE_PROBES)
        with st["lock"]:
            n0 = len(st["ticks"])
        t_att = time.time()
        rate0 = sum(1 for t, _, _ in st["ticks"] if t > t_att - 5) / 5.0
        s = realbig_session(bk, REALBIG_EDGE_PROBES, ["--attach", pid, "--detach-after-ms", secs * 1000 // 2], secs + 600)
        t_det = time.time()
        with st["lock"]:
            during = [x for x in st["ticks"][n0:] if x[0] <= t_det]
        att = [o for o in s["recs"] if o.get("kind") == "attached"]
        attached = bool(att)
        required = [p.rsplit(":", 1)[0] for p in REALBIG_EDGE_PROBES[1:]] if which == "renderer" else \
                   [REALBIG_EDGE_PROBES[2].rsplit(":", 1)[0]]
        refused = which == "renderer" and bk == "inline"
        if refused:
            # The renderer admits only Microsoft-signed DLLs (CIG): the agent cannot load, so an
            # inline session must fail CLEANLY -- a clear error, nothing hit, the debugger gone,
            # no residue, and the page never notices (checked below like every other run).
            rep = report(s["recs"])
            err = str(rep.get("error") or "")
            bad, detail = [], f"error={err[:160]!r} rc={s['rc']}"
            if "Microsoft-signed" not in err: bad.append(f"no clear refusal: error={err[:200]!r}")
            if any(p.get("hits") for p in probes(s["recs"])): bad.append("hits in a refused session")
            if s["timed_out"]: bad.append("controller timed out (killed)")
        else:
            bad, detail = realbig_judge(s, bk, REALBIG_EDGE_PROBES, required, False)
        alive = ts.mem(pid) is not None
        if alive:
            rbad, rdet = realbig_residue(pid, snap)
            bad += rbad
            detail += " " + rdet
        else:
            bad.append(f"{which} process gone after the session")
        time.sleep(6.0)
        with st["lock"]:
            ticks = list(st["ticks"])
        after = [x for x in ticks if x[0] > t_det]
        wrong = [i for _, i, ok in ticks if not ok]
        idx = sorted(i for _, i, _ in ticks)
        gaps = idx != list(range(len(idx)))
        if wrong: bad.append(f"wrong tick values at {wrong[:5]}")
        if gaps: bad.append(f"ticks not contiguous ({len(idx)} ticks, max {idx[-1] if idx else None})")
        if len(after) < 10: bad.append(f"ticks after detach={len(after)}")
        if '"kind":"detached"' not in s["out"] and not refused: bad.append("not detached")
        if browser.poll() is not None: bad.append(f"browser exited rc={browser.returncode}")
        dur = max(t_det - t_att, 0.1)
        return not bad, (f"{which} pid={pid} attached={attached} {detail} ticks: before={rate0:.1f}/s "
                         f"during={len(during) / dur:.1f}/s after={len(after) / 6:.1f}/s total={len(ticks)} "
                         f"procs={len(kids)} renderers={len(rends)}"), bad, s["err"]
    finally:
        srv.shutdown()
        if browser and browser.poll() is None:
            browser.kill()
        kill_matching(udd.name)
        shutil.rmtree(udd, ignore_errors=True)


def check_realbig(select="", secs=30):
    """realbig-<app>-<mode>-<backend>: real large programs under every backend, launch and
    attach + detach mid-run, asserting the program's own result, exact accounting
    (hits == logs == delivered, log_dropped 0), no crash, a flat controller, and after every
    detach no residue (code bytes / DRs / TF / debug port). See the section comment."""
    if not exe("uhh_trace.exe"):
        return missing_bin("realbig", "uhh_trace.exe")
    arch = bin_machine()
    sel = [x for x in (os.environ.get("UHH_REALBIG") or select).split(",") if x]

    def wanted(name):
        return not sel or any(x in name for x in sel)

    def one(name, fn, *a):
        if not wanted(name):
            return
        print(f"  .. {name}", file=sys.stderr, flush=True)
        t0 = time.time()
        try:
            ok, detail, bad, err = fn(*a)
            tail = " | ".join(l for l in (err or "").splitlines() if l.strip() and "probe: active" not in l)[-700:]
            record(name, ok, f"{detail} wall={time.time() - t0:.0f}s" + ("" if ok else f" BAD={bad} stderr_tail={tail}"))
        except Exception as e:
            import traceback
            record(name, False, repr(e) + " " + traceback.format_exc().splitlines()[-3][:200])
    native = [n for n in (f"realbig-{a}-{m}-{b}" for a, m in (("robocopy", "launch"), ("robocopy", "detach"),
                                                               ("findstr", "launch"))
                          for b in ("breakpoint", "hw", "inline")) if wanted(n)]
    if native:
        work = Path(tempfile.mkdtemp(prefix="uhh-realbig-tree-", dir=Path.cwd()))
        try:
            realbig_tree(work / "src")
            base = realbig_native_base(arch, work)
            print(f"  .. realbig base: robocopy {base['robo_secs']:.1f}s many {base['robo_many_secs']:.1f}s "
                  f"findstr {base['find_secs']:.1f}s ({len(base['find_out'])}B)", file=sys.stderr, flush=True)
            for bk in ("breakpoint", "hw", "inline"):
                one(f"realbig-robocopy-launch-{bk}", realbig_robocopy, bk, "launch", arch, work, base)
                one(f"realbig-robocopy-detach-{bk}", realbig_robocopy, bk, "detach", arch, work, base)
                one(f"realbig-findstr-launch-{bk}", realbig_findstr, bk, arch, work, base)
        except Exception as e:
            record("realbig-native-base", False, repr(e))
        finally:
            shutil.rmtree(work, ignore_errors=True)
    ps = realbig_sysprog(r"WindowsPowerShell\v1.0\powershell.exe", arch)
    for bk in ("breakpoint", "hw", "inline"):
        one(f"realbig-ps-detach-{bk}", realbig_ps, bk, ps, secs, "ps")
    for bk in ("breakpoint", "hw", "inline"):
        name = f"realbig-pwsh-detach-{bk}"
        if not wanted(name):
            continue
        if arch == "x86":
            skip(name, "pwsh 7 is installed 64-bit only (x64 build)")
        elif not PWSH_EXE.exists():
            # Windows ships only PowerShell 5.1; pwsh 7 is a separate install (not on the test VM).
            skip(name, f"pwsh 7 is not installed ({PWSH_EXE}); the 5.1 rows cover the .NET JIT host")
        else:
            one(name, realbig_ps, bk, PWSH_EXE, secs, "pwsh")
    for which in ("renderer", "browser"):
        for bk in ("breakpoint", "hw", "inline"):
            name = f"realbig-edge-{which}-{bk}"
            if not wanted(name):
                continue
            if arch == "x86":
                skip(name, "msedge.exe is a 64-bit program (x64 build only)")
            elif not EDGE_EXE.exists():
                skip_external(name, f"Edge ({EDGE_EXE})")
            else:
                one(name, realbig_edge, bk, which, secs)


def verify_capture(path):
    """Stream a captured stdout file (any encoding PowerShell writes: UTF-16 BOM, UTF-8 BOM,
    plain UTF-8) and check it is SELF-VERIFYINGLY complete: every probe_log line is valid
    JSON, the records carry seq 0, 1, 2, ... with no gap, and the probe_report (after the last
    record) states stdout_logs == the records present. Returns a dict (streamed: never holds
    the records in memory)."""
    import codecs
    head = b""
    if Path(path).exists():
        with open(path, "rb") as f:
            head = f.read(4)
    enc = ("utf-16" if head[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE) else
           "utf-8-sig" if head[:3] == codecs.BOM_UTF8 else "utf-8")
    st = {"lines": 0, "logs": 0, "bad": 0, "gaps": 0, "next": 0, "after_report": 0,
          "report": None, "probes": [], "sample": "", "encoding": enc}
    if not head:
        return st
    with open(path, encoding=enc, errors="replace", newline="") as f:
        for raw in f:
            st["lines"] += 1
            line = raw.rstrip("\r\n")
            if '"kind":"probe_log"' in line:
                st["logs"] += 1
                if st["report"] is not None:
                    st["after_report"] += 1
                try:
                    seq = json.loads(line).get("seq")
                except json.JSONDecodeError:
                    st["bad"] += 1
                    st["sample"] = st["sample"] or line[:120]
                    continue
                if seq != st["next"]:
                    st["gaps"] += 1
                    st["sample"] = st["sample"] or f"seq={seq} want={st['next']}"
                st["next"] = (seq if isinstance(seq, int) else st["next"]) + 1
            elif line.startswith("{"):
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    st["bad"] += 1
                    st["sample"] = st["sample"] or line[:120]
                    continue
                if o.get("kind") == "probe_report":
                    st["report"] = o
                elif o.get("kind") == "probe":
                    st["probes"].append(o)
    return st


def run_in_conpty(cmdline, out_path, timeout, cols=120, rows=30):
    """Run cmdline attached to a pseudo console (ConPTY: what Windows Terminal and OpenSSH
    use; the child's stdout is a real console handle, GetConsoleMode succeeds) and stream the
    rendered VT byte stream to out_path. Returns (exit code or None on timeout, seconds)."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    HANDLE = wintypes.HANDLE

    class COORD(ctypes.Structure):
        _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                    ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
                    ("hStdInput", HANDLE), ("hStdOutput", HANDLE), ("hStdError", HANDLE)]

    class STARTUPINFOEXW(ctypes.Structure):
        _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", HANDLE), ("hThread", HANDLE), ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    k32.CreatePseudoConsole.argtypes = [COORD, HANDLE, HANDLE, wintypes.DWORD, ctypes.POINTER(HANDLE)]
    k32.CreatePseudoConsole.restype = ctypes.c_long
    k32.ClosePseudoConsole.argtypes = [HANDLE]
    k32.CreatePipe.argtypes = [ctypes.POINTER(HANDLE), ctypes.POINTER(HANDLE), ctypes.c_void_p, wintypes.DWORD]
    k32.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
    k32.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p,
                                              ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
    k32.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
                                   wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOEXW),
                                   ctypes.POINTER(PROCESS_INFORMATION)]
    k32.ReadFile.argtypes = [HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k32.WaitForSingleObject.argtypes = [HANDLE, wintypes.DWORD]
    k32.GetExitCodeProcess.argtypes = [HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.TerminateProcess.argtypes = [HANDLE, wintypes.UINT]
    k32.CloseHandle.argtypes = [HANDLE]
    in_r, in_w, out_r, out_w, hpc = HANDLE(), HANDLE(), HANDLE(), HANDLE(), HANDLE()
    k32.CreatePipe(ctypes.byref(in_r), ctypes.byref(in_w), None, 0)
    k32.CreatePipe(ctypes.byref(out_r), ctypes.byref(out_w), None, 0)
    hr = k32.CreatePseudoConsole(COORD(cols, rows), in_r, out_w, 0, ctypes.byref(hpc))
    if hr != 0:
        raise OSError(f"CreatePseudoConsole hr={hr:#x}")
    k32.CloseHandle(in_r); k32.CloseHandle(out_w)
    sink = open(out_path, "wb")

    def pump():
        buf = ctypes.create_string_buffer(1 << 16)
        got = wintypes.DWORD()
        while k32.ReadFile(out_r, buf, len(buf), ctypes.byref(got), None) and got.value:
            sink.write(buf.raw[:got.value])
    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    size = ctypes.c_size_t()
    k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    attrs = ctypes.create_string_buffer(size.value)
    k32.InitializeProcThreadAttributeList(attrs, 1, 0, ctypes.byref(size))
    k32.UpdateProcThreadAttribute(attrs, 0, 0x00020016, hpc, ctypes.sizeof(HANDLE), None, None)   # PSEUDOCONSOLE
    si = STARTUPINFOEXW()
    si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
    si.StartupInfo.dwFlags = 0x100           # STARTF_USESTDHANDLES, null: never this process's redirected handles
    si.lpAttributeList = ctypes.cast(attrs, ctypes.c_void_p)
    pi = PROCESS_INFORMATION()
    started = time.perf_counter()
    if not k32.CreateProcessW(None, ctypes.create_unicode_buffer(cmdline), None, None, False, 0x00080000,
                              None, None, ctypes.byref(si), ctypes.byref(pi)):
        raise OSError(f"CreateProcessW error={ctypes.get_last_error()}")
    code = None
    if k32.WaitForSingleObject(pi.hProcess, int(timeout * 1000)) == 0:
        c = wintypes.DWORD()
        k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(c))
        code = c.value
    else:
        k32.TerminateProcess(pi.hProcess, 1)
    elapsed = time.perf_counter() - started
    time.sleep(1.5)                          # the pseudo console renders its last frame
    k32.ClosePseudoConsole(hpc)
    reader.join(timeout=30)
    sink.close()
    for h in (in_w, out_r, pi.hProcess, pi.hThread):
        k32.CloseHandle(h)
    return code, elapsed


class VtScreen:
    """A minimal VT terminal (what a ConPTY capture needs): a rows x cols grid with autowrap,
    cursor addressing, erase/insert/delete and scrolling. ConPTY renders the console as a
    screen, not as the bytes the program wrote: it repaints only cells that changed, moves the
    cursor over cells the screen already shows, and may repaint rows out of order -- so text
    is only reconstructible by emulating the screen. Every row that leaves the screen (scrolled
    off the top or erased) and, at the end, every row still on it is passed to emit(text) --
    a row that autowrapped keeps its full width and no line break; any other row is
    right-stripped and ends in '\\n'."""
    SEQ = re.compile(r"\x1b\[([0-?]*)([ -/]*)([@-~])|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[P^_][^\x1b]*\x1b\\"
                     r"|\x1b[ -/]*[0-~]|[\x00-\x1f\x7f]")
    MOVES = set("HfABeCaDEFG`dKJX@PLMSTbr")
    PARTIAL = re.compile(r"\x1b(?:\[[0-?]*[ -/]*|\][^\x07\x1b]*|[P^_][^\x1b]*|[ -/]*)?\Z")

    def __init__(self, cols, rows, emit):
        self.cols, self.rows, self.emit = cols, rows, emit
        self.grid = [[" "] * cols for _ in range(rows)]
        self.wrapped = [False] * rows
        self.dirty = [False] * rows          # anything written since the row was last blank
        self.x = self.y = 0
        self.pending = False                 # deferred autowrap: the last column was written
        self.top, self.bottom = 0, rows - 1
        self.last = " "
        self.carry = ""

    def _row_text(self, y):
        t = "".join(self.grid[y])
        return t if self.wrapped[y] else t.rstrip(" ") + "\n"

    def _blank(self, y):
        self.grid[y] = [" "] * self.cols
        self.wrapped[y] = self.dirty[y] = False

    def _flush_row(self, y):
        if self.dirty[y]:
            self.emit(self._row_text(y))
        self._blank(y)

    def _scroll_up(self, n=1):
        for _ in range(n):
            if self.top == 0:
                self._flush_row(self.top)
            del self.grid[self.top]; del self.wrapped[self.top]; del self.dirty[self.top]
            self.grid.insert(self.bottom, [" "] * self.cols)
            self.wrapped.insert(self.bottom, False); self.dirty.insert(self.bottom, False)

    def _scroll_down(self, n=1):
        for _ in range(n):
            del self.grid[self.bottom]; del self.wrapped[self.bottom]; del self.dirty[self.bottom]
            self.grid.insert(self.top, [" "] * self.cols)
            self.wrapped.insert(self.top, False); self.dirty.insert(self.top, False)

    def _linefeed(self):
        self.pending = False
        if self.y == self.bottom:
            self._scroll_up()
        elif self.y < self.rows - 1:
            self.y += 1

    def _text(self, s):
        i, n = 0, len(s)
        while i < n:
            if self.pending:
                self.wrapped[self.y] = True
                self.x = 0
                self._linefeed()
            take = min(n - i, self.cols - self.x)
            self.grid[self.y][self.x:self.x + take] = s[i:i + take]
            self.dirty[self.y] = True
            self.x += take
            i += take
            if self.x >= self.cols:
                self.x, self.pending = self.cols - 1, True
        self.last = s[-1]

    def _erase(self, y, a, b):
        self.grid[y][a:b] = [" "] * (b - a)
        if b >= self.cols:
            self.wrapped[y] = False

    def _csi(self, params, inter, final):
        private = params[:1] in ("?", ">", "<", "=")
        nums = [int(p) if p.isdigit() else 0 for p in (params[1:] if private else params).split(";")] if params else []
        def arg(i=0, d=1):
            return nums[i] if len(nums) > i and nums[i] else d
        if private or inter or final not in self.MOVES:
            return                 # SGR, modes (?25l cursor, ?1049h ...): no text, no cursor motion
        c, r = self.cols, self.rows
        if final in "Hf":
            self.y, self.x = min(arg(0) - 1, r - 1), min(arg(1) - 1, c - 1)
        elif final == "A":
            self.y = max(self.y - arg(), 0)
        elif final in "Be":
            self.y = min(self.y + arg(), r - 1)
        elif final in "Ca":
            self.x = min(self.x + arg(), c - 1)
        elif final == "D":
            self.x = max(self.x - arg(), 0)
        elif final == "E":
            self.y, self.x = min(self.y + arg(), r - 1), 0
        elif final == "F":
            self.y, self.x = max(self.y - arg(), 0), 0
        elif final in "G`":
            self.x = min(arg() - 1, c - 1)
        elif final == "d":
            self.y = min(arg() - 1, r - 1)
        elif final == "K":
            m = arg(0, 0)
            self._erase(self.y, *((self.x, c) if m == 0 else (0, self.x + 1) if m == 1 else (0, c)))
        elif final == "J":
            m = arg(0, 0)
            if m == 0:
                self._erase(self.y, self.x, c)
                for y in range(self.y + 1, r): self._blank(y)
            elif m == 1:
                self._erase(self.y, 0, self.x + 1)
                for y in range(0, self.y): self._blank(y)
            elif m == 2:                             # clear: what it held was shown -- pass it on
                for y in range(r): self._flush_row(y)
        elif final == "X":
            self._erase(self.y, self.x, min(self.x + arg(), c))
        elif final == "@":
            row = self.grid[self.y]; k = min(arg(), c - self.x)
            row[self.x:] = [" "] * k + row[self.x:c - k]
        elif final == "P":
            row = self.grid[self.y]; k = min(arg(), c - self.x)
            row[self.x:] = row[self.x + k:] + [" "] * k
        elif final in "LM" and self.top <= self.y <= self.bottom:
            top, self.top = self.top, self.y
            (self._scroll_down if final == "L" else self._scroll_up)(min(arg(), self.bottom - self.y + 1))
            self.top = top
        elif final == "S":
            self._scroll_up(arg())
        elif final == "T":
            self._scroll_down(arg())
        elif final == "b":
            self._text(self.last * arg())
            return
        elif final == "r":
            t, b = arg(0, 1) - 1, arg(1, r) - 1
            if 0 <= t < b < r:
                self.top, self.bottom = t, b
            self.x = self.y = 0
        self.pending = False

    def feed(self, data):
        data = self.carry + data
        m = self.PARTIAL.search(data)
        cut = m.start() if m else len(data)
        self.carry = data[cut:]
        pos = 0
        for m in self.SEQ.finditer(data, 0, cut):
            if m.start() > pos:
                self._text(data[pos:m.start()])
            pos = m.end()
            t = m.group(0)
            if m.group(3):
                self._csi(m.group(1), m.group(2), m.group(3))
            elif t == "\r":
                self.x, self.pending = 0, False
            elif t in "\n\x0b\x0c":
                self._linefeed()
            elif t == "\x08":
                self.x, self.pending = max(self.x - 1, 0), False
            elif t == "\t":
                self.x = min((self.x // 8 + 1) * 8, self.cols - 1)
            elif t == "\x1bM":                       # reverse index
                if self.y == self.top: self._scroll_down()
                else: self.y = max(self.y - 1, 0)
            elif t == "\x1bD":
                self._linefeed()
            elif t == "\x1bE":
                self.x = 0; self._linefeed()
            elif t == "\x1bc":
                for y in range(self.rows): self._flush_row(y)
                self.x = self.y = 0
        if cut > pos:
            self._text(data[pos:cut])

    def close(self):
        for y in range(self.rows):
            self._flush_row(y)


def count_vt_seq(path, cols=120, rows=30):
    """Stream a ConPTY capture (cols x rows, as run_in_conpty created it) through VtScreen and
    read the reconstructed text, line breaks removed: the unique probe_log seq values (bit
    set), the highest one, and the last probe_report seen (parsed whole, however the renderer
    wrapped or repainted it)."""
    import codecs
    token = re.compile(r'"seq":(\d+)\}')
    seen, count, top, report_text, carry = bytearray(1 << 16), 0, -1, None, ""
    pieces = []
    screen = VtScreen(cols, rows, pieces.append)

    def scan(flat):
        nonlocal seen, count, top, report_text
        for m in token.finditer(flat):
            v = int(m.group(1))
            if v >= len(seen):
                seen.extend(bytearray(max(v + 1 - len(seen), len(seen))))
            if not seen[v]:
                seen[v] = 1
                count += 1
            top = max(top, v)
        at = flat.rfind('{"kind":"probe_report"')
        if at >= 0:
            report_text = flat[at:at + 16384]

    def drain(final):
        nonlocal carry
        text = carry + "".join(pieces).replace("\n", "")
        pieces.clear()
        cut = len(text) if final else max(text.rfind('{"kind"', 0, max(0, len(text) - 16384)), 0)
        scan(text[:cut])
        carry = text[cut:]
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 22)
            if not chunk:
                break
            screen.feed(decoder.decode(chunk))
            drain(False)
    screen.feed(decoder.decode(b"", final=True))
    screen.close()
    drain(True)
    report_obj = None
    if report_text:
        try:
            report_obj, _ = json.JSONDecoder().raw_decode(report_text)
        except json.JSONDecodeError:
            report_obj = None
    return {"unique": count, "max": top, "missing": (top + 1 - count) if top >= 0 else 0, "report": report_obj}


def check_stdout_powershell():
    """Owner bug: "high volume drops lines logged -- powershell logging" (stack dumps). Logs are
    consumed through Windows PowerShell 5.1 the way a user does: `| Out-File`, `>` (UTF-16),
    `| Set-Content`, `| Tee-Object`, and `2>&1 | Out-File` (stderr merged). High volume, every
    record with a symbolized --stack, every backend. Each capture must be complete and prove it
    from its own lines: every probe_log line valid JSON, seq 0..N-1 contiguous, the probe_report
    last with stdout_logs == logs_written == hits == the records captured, nothing dropped --
    and the session's JSONL file equally complete."""
    tracer, target = exe("uhh_trace.exe"), exe("logstream_target.exe")
    if not tracer or not target:
        return missing_bin("stdout-powershell", "uhh_trace/logstream_target")
    ps = SYS32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not ps.exists():
        return skip_external("stdout-powershell", "Windows PowerShell 5.1 (powershell.exe)")
    modes = {
        "outfile": "& $tr @a | Out-File -FilePath $o",
        "redirect": "& $tr @a > $o",
        "setcontent": "& $tr @a | Set-Content -Path $o",
        "tee": "& $tr @a | Tee-Object -FilePath $o | Out-Null",
        "merged": "& $tr @a 2>&1 | Out-File -FilePath $o -Encoding utf8",
    }
    volume = {"inline": (4, 25000), "breakpoint": (4, 2500), "hw": (4, 2500)}
    for backend, (threads, count) in volume.items():
        for mode, pipeline in modes.items():
            if backend != "inline" and mode not in ("outfile", "merged"):
                continue                      # every mode once at the highest volume; the rest per backend
            name = f"stdout-powershell-{mode}-{backend}"
            work = Path(tempfile.mkdtemp(prefix="uhh-pslog-"))
            try:
                out = work / "out.txt"
                a = ["--backend", backend, "--stack", "-p", "logstream_target.exe!LogSite:d", "--",
                     str(target), "--count", str(count), "--threads", str(threads), "--delay", "0", "--no-ticks"]
                lit = ",".join("'" + x.replace("'", "''") + "'" for x in a)
                script = (f"$ErrorActionPreference='Continue'; $tr='{tracer}'; $o='{out}'; $a=@({lit}); "
                          + pipeline)
                env = dict(os.environ, TEMP=str(work), TMP=str(work))
                r = subprocess.run([str(ps), "-NoProfile", "-NonInteractive", "-Command", script],
                                   capture_output=True, text=True, errors="replace", timeout=900, env=env)
                cap = verify_capture(out)
                sessions = list((work / "uhh" / "logs").glob("*.jsonl"))
                sess = verify_capture(sessions[0]) if len(sessions) == 1 else {}
                rep = cap["report"] or {}
                hits = sum(p.get("hits") or 0 for p in cap["probes"])
                want = threads * count
                ok = (bool(rep) and hits == want and cap["logs"] == want and
                      rep.get("hits") == hits == (rep.get("logs_written") or 0) + (rep.get("log_dropped") or 0)
                      + (rep.get("callbacks_interrupted") or 0) and
                      cap["bad"] == 0 and cap["gaps"] == 0 and cap["after_report"] == 0 and
                      rep.get("logs_written") == want and rep.get("stdout_logs") == want and
                      rep.get("log_dropped") == 0 and rep.get("error") is None and
                      rep.get("live_output_error") is None and not rep.get("live_output_closed") and
                      sess.get("logs") == want and sess.get("gaps") == 0 and sess.get("bad") == 0)
                record(name, ok, f"captured={cap['logs']}/{want} bad={cap['bad']} seq_gaps={cap['gaps']} "
                                 f"after_report={cap['after_report']} hits={hits} written={rep.get('logs_written')} "
                                 f"stdout_logs={rep.get('stdout_logs')} dropped={rep.get('log_dropped')} "
                                 f"file={sess.get('logs')}/gaps={sess.get('gaps')} enc={cap['encoding']} rc={r.returncode}"
                                 + (f" sample={cap['sample']!r}" if cap["sample"] else "")
                                 + ("" if ok else f" stderr={r.stderr.strip().splitlines()[-2:]}"))
            except Exception as e:
                record(name, False, repr(e))
            finally:
                shutil.rmtree(work, ignore_errors=True)


def check_powershell_detach():
    """An attach reported BEFORE its detach (uhh_trace --detach-after-ms) on a target that keeps
    logging at full speed into a slow PowerShell pipeline (split from check_stdout_powershell).
    UHH_PSDETACH_REPS (default 1) repeats each backend; UHH_PSDETACH_BACKENDS narrows them.
    The whole run must also end within 120 s (attach, 4 s, report, a detach bounded to ~15 s
    for running callbacks, the backlog; the starved detach of check_slowreader_detach took
    37-203 s here, and once never ended)."""
    tracer, target = exe("uhh_trace.exe"), exe("logstream_target.exe")
    if not tracer or not target:
        return missing_bin("stdout-powershell-detach", "uhh_trace/logstream_target")
    ps = SYS32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not ps.exists():
        return skip_external("stdout-powershell-detach", "Windows PowerShell 5.1 (powershell.exe)")
    reps = int(os.environ.get("UHH_PSDETACH_REPS", "1"))
    backends = [x for x in os.environ.get("UHH_PSDETACH_BACKENDS", "").split(",") if x] or ["inline", "breakpoint"]
    # An attach reported BEFORE its detach (uhh_trace --detach-after-ms) on a target that keeps
    # logging at full speed into a slow PowerShell pipeline. The report's counts must be
    # causally consistent (stdout_logs <= logs_written <= hits: the hits were read before a
    # long flush and came out far BELOW logs_written), and the records after the report must
    # end in a probe_final whose counts close the books: hits == logs_written + log_dropped +
    # in_flight, and the capture holds exactly its stdout_logs records, seq without a gap.
    for k, backend in ((r, b) for r in range(reps) for b in backends):
        name = f"stdout-powershell-detach-{backend}"
        work = Path(tempfile.mkdtemp(prefix="uhh-pslog-"))
        tgt = None
        try:
            out = work / "out.txt"
            tgt = subprocess.Popen([str(target), "--count", "2000000000", "--threads", "4", "--delay", "0",
                                    "--no-ticks"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
            a = ["--backend", backend, "--stack", "-p", "logstream_target.exe!LogSite:d",
                 "--attach", str(tgt.pid), "--detach-after-ms", "4000"]
            lit = ",".join("'" + x.replace("'", "''") + "'" for x in a)
            script = (f"$ErrorActionPreference='Continue'; $tr='{tracer}'; $o='{out}'; $a=@({lit}); "
                      "& $tr @a | Out-File -FilePath $o -Encoding utf8")
            env = dict(os.environ, TEMP=str(work), TMP=str(work))
            t0 = time.time()
            p = subprocess.Popen([str(ps), "-NoProfile", "-NonInteractive", "-Command", script],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", env=env)
            try:
                _, err = p.communicate(timeout=240)
            except subprocess.TimeoutExpired:
                tgt.kill()                                   # ends the attached session too
                _, err = p.communicate(timeout=120)
                partial = verify_capture(out)
                lines = err.strip().splitlines()
                waits = [l for l in lines if "still waiting for probe_run" in l][:1]
                record(name, False, f"rep={k} no end within 240 s: captured so far={partial['logs']} "
                                    f"report={'yes' if partial['report'] else 'no'} stderr={waits + lines[-4:]}")
                continue
            took = time.time() - t0
            r = subprocess.CompletedProcess(p.args, p.returncode, "", err)
            alive = tgt.poll() is None
            cap = verify_capture(out)
            rep = cap["report"] or {}
            hits = sum(p.get("hits") or 0 for p in cap["probes"])
            # probe_final must be the LAST JSON line, exactly once, after every record.
            fin, finals, after_final = {}, 0, 0
            with open(out, encoding=cap["encoding"], errors="replace") as f:
                for line in f:
                    if '"kind":"probe_final"' in line:
                        fin = json.loads(line)
                        finals += 1
                    elif line.startswith("{") and finals and '"kind":"detached"' not in line:
                        after_final += 1              # uhh_trace's own {"kind":"detached"} may follow
            consistent = (rep.get("stdout_logs") is not None and rep.get("logs_written") is not None and
                          rep["stdout_logs"] <= rep["logs_written"] <= hits == rep.get("hits"))
            closed = bool(fin) and fin.get("hits") == (fin.get("logs_written") or 0) + (fin.get("log_dropped") or 0) \
                + (fin.get("in_flight") or 0) and fin.get("stdout_logs") == fin.get("logs_written") == cap["logs"]
            # No record after the report (the detach came before the next hit -- breakpoint, now
            # that a breakpoint-only attach has no agent to stop): no probe_final by design (api.md);
            # the report itself then closes the books, equal to the detach's own final line.
            det = re.search(r"probe: detached: hits=(\d+) logs_written=(\d+) log_dropped=(\d+) in_flight=(\d+)", r.stderr or "")
            if not finals and det and consistent:
                dh, dw, dd, di = (int(x) for x in det.groups())
                closed = (dh == rep.get("hits") and dw == rep.get("logs_written") == rep.get("stdout_logs") == cap["logs"]
                          and dh == dw + dd + di)
                fin = {"hits": dh, "logs_written": dw, "log_dropped": dd, "in_flight": di, "stdout_logs": cap["logs"]}
            ok = (took <= 120 and alive and finals <= 1 and after_final == 0 and consistent and closed and cap["bad"] == 0 and cap["gaps"] == 0 and
                  fin.get("log_dropped") == 0 and rep.get("error") is None and cap["logs"] > 0)
            record(name, ok, f"rep={k} took={took:.0f}s report: hits={hits} written={rep.get('logs_written')} stdout_logs={rep.get('stdout_logs')} "
                             f"consistent={consistent} final={ {k: fin.get(k) for k in ('hits', 'logs_written', 'log_dropped', 'in_flight', 'stdout_logs')} } "
                             f"captured={cap['logs']} bad={cap['bad']} seq_gaps={cap['gaps']} target_alive={alive} "
                             f"finals={finals} json_after_final={after_final}"
                             + ("" if ok else f" stderr={r.stderr.strip().splitlines()[-2:]}"))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            if tgt and tgt.poll() is None:
                tgt.kill()
                tgt.wait()
            shutil.rmtree(work, ignore_errors=True)


def check_slowreader_detach():
    """A live detach must END while the attached target keeps the log ring full (CI 42364458533:
    x86 stdout-powershell-detach-inline, probe_close "still waiting for probe_run to stop (180s)"
    with 8.7M records streamed; the detach ran only once the test killed the target). The
    drainer thread took drain_mu again nanoseconds after each pass; the debug loop, waiting for
    it in its per-turn drain, starved and never got back to the stop request. Every trigger of
    a live detach goes through that loop: --detach-after-ms (timed), --detach-on-stdin, and
    Ctrl+Break (a plain --attach). uhh_trace --attach of logstream_target (4 threads, full
    speed, inline + --stack) with its stdout read SLOWLY by this script (the ring stays full):
    the trigger at ~3 s; the tool must exit within DETACH_END_S of it (the detach waits at most
    15 s for running callbacks), the target alive, the detach line's books closed (hits ==
    logs_written + log_dropped + in_flight, nothing dropped), and every record written to
    stdout read here (stdout_logs of probe_final / the report == probe_log lines read)."""
    import signal
    tracer, target = exe("uhh_trace.exe"), exe("logstream_target.exe")
    if not tracer or not target:
        return missing_bin("detach-slowreader", "uhh_trace/logstream_target")
    DETACH_END_S = 45     # bounded detach: ~15 s callback wait + agent stop/drain; starved, it was 58 s to forever
    reps = int(os.environ.get("UHH_SLOWREADER_REPS", "1"))
    for rep, how in ((r, h) for r in range(reps) for h in ("timed", "stdin", "ctrlbreak")):
        name = f"detach-slowreader-{how}-inline"
        procs = []
        work = Path(tempfile.mkdtemp(prefix="uhh-slowrd-"))
        try:
            tgt = subprocess.Popen([str(target), "--count", "2000000000", "--threads", "4", "--delay", "0", "--no-ticks"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(tgt)
            time.sleep(1)
            a = [str(tracer), "--backend", "inline", "--stack", "-p", "logstream_target.exe!LogSite:d",
                 "--attach", str(tgt.pid)]
            a += {"timed": ["--detach-after-ms", "3000"], "stdin": ["--detach-on-stdin"], "ctrlbreak": []}[how]
            att = subprocess.Popen(a, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=dict(os.environ, TEMP=str(work), TMP=str(work)),
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            procs.append(att)
            aerr = Lines(io.TextIOWrapper(att.stderr, errors="replace"))
            st = {"logs": 0, "final": None, "report": None, "first": None}

            def slow_read():                          # ~1 MB/s: far below what 4 logging threads produce
                carry = b""
                while True:
                    chunk = att.stdout.read1(16384) if hasattr(att.stdout, "read1") else att.stdout.read(16384)
                    if not chunk:
                        break
                    lines = (carry + chunk).split(b"\n")
                    carry = lines.pop()
                    for l in lines:
                        if l.startswith(b'{"kind":"probe_log"'):
                            st["logs"] += 1
                            if st["first"] is None: st["first"] = time.time()
                        elif l.startswith(b'{"kind":"probe_final"'): st["final"] = json.loads(l)
                        elif l.startswith(b'{"kind":"probe_report"'): st["report"] = json.loads(l)
                    time.sleep(0.016)
            rd = threading.Thread(target=slow_read, daemon=True)
            rd.start()
            t_att = time.time()
            if not aerr.wait_for(lambda l: l.startswith("probe: active logstream_target.exe!LogSite"), 90):
                raise RuntimeError("LogSite never became active: " + " | ".join(aerr.lines[-3:])[:300])
            if how == "timed":
                trig = time.time() + 3.0              # --detach-after-ms 3000 counts from the attach
            else:
                time.sleep(3)
                trig = time.time()
                if how == "stdin":
                    att.stdin.write(b"\n"); att.stdin.flush()
                else:
                    att.send_signal(signal.CTRL_BREAK_EVENT)
            try:
                att.wait(timeout=trig - time.time() + DETACH_END_S + 30)
            except subprocess.TimeoutExpired:
                pass
            took = time.time() - trig
            if att.poll() is None:
                waits = [l for l in aerr.lines if "still waiting for probe_run" in l][:1]
                att.kill(); att.wait()
                record(name, False, f"rep={rep} no end {took:.0f} s after the {how} trigger: read={st['logs']} "
                                    f"stderr={waits + aerr.lines[-3:]}")
                continue
            rd.join(timeout=120)
            aerr.t.join(timeout=30)
            alive = tgt.poll() is None
            sm = cx_detach_summary(aerr.lines)
            last = st["final"] or st["report"] or {}
            bad = []
            if took > DETACH_END_S: bad.append(f"ended {took:.0f}s after the trigger (> {DETACH_END_S}s)")
            if not alive: bad.append("target died")
            if att.returncode != 0: bad.append(f"rc={att.returncode}")
            if not sm or sm.get("hits") != sm.get("logs_written", 0) + sm.get("log_dropped", 0) + sm.get("in_flight", 0) \
                    or sm.get("log_dropped") != 0:
                bad.append(f"summary={sm}")
            if st["logs"] == 0 or last.get("stdout_logs") != st["logs"]:
                bad.append(f"read={st['logs']} stdout_logs={last.get('stdout_logs')}")
            if how == "ctrlbreak" and not any("interrupted" in l for l in aerr.lines):
                bad.append("no 'interrupted' line")
            record(name, not bad, f"rep={rep} " + (" ".join(bad) or
                   f"ended {took:.1f}s after the {how} trigger; read={st['logs']} summary={sm}") +
                   ("" if not bad else f" stderr={aerr.lines[-3:]}"))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            for q in procs:
                if q.poll() is None:
                    q.kill()
                    q.wait()
            shutil.rmtree(work, ignore_errors=True)


def check_stdout_console(big=0):
    """The live tail into a CONSOLE handle (owner: lines missing in the PowerShell console while
    the session file was complete). uhh_trace --stack runs attached to a pseudo console
    (ConPTY: GetConsoleMode succeeds on its stdout, the WriteFile-to-console path; the same
    conhost renders it to VT as for Windows Terminal), inside powershell.exe as a user runs it.
    Every probe_log seq 0..N-1 must appear in the rendered stream and the probe_report must say
    stdout_logs == logs_written == hits, with no live-output error, the session file equally
    complete. big > 0 (--console-records): one more inline run of that many records."""
    tracer, target = exe("uhh_trace.exe"), exe("logstream_target.exe")
    if not tracer or not target:
        return missing_bin("stdout-console", "uhh_trace/logstream_target")
    ps = SYS32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    runs = [("inline", 4, 25000), ("breakpoint", 4, 2500), ("hw", 4, 2500)]
    if big:
        runs.append(("inline", 4, (big + 3) // 4))
    for backend, threads, count in runs:
        want = threads * count
        name = f"stdout-console-{backend}" + (f"-{want}" if want > 100000 else "")
        work = Path(tempfile.mkdtemp(prefix="uhh-pscon-"))
        old_temp = os.environ.get("TEMP"), os.environ.get("TMP")
        try:
            os.environ["TEMP"] = os.environ["TMP"] = str(work)        # the pseudo console child inherits it
            cmd = (f'"{ps}" -NoProfile -NonInteractive -Command "& \'{tracer}\' --backend {backend} --stack '
                   f'-p logstream_target.exe!LogSite:d -- \'{target}\' --count {count} --threads {threads} '
                   f'--delay 0 --no-ticks"')
            code, secs = run_in_conpty(cmd, work / "vt.bin", timeout=600 + want / 500)
            seen = count_vt_seq(work / "vt.bin")
            with open(work / "vt.bin", "rb") as f:          # the capture's end: the report's rendering
                f.seek(max(0, (work / "vt.bin").stat().st_size - 2600))
                vt_tail = f.read()
            (work / "vt.bin").unlink()
            rep = seen["report"] or {}
            sessions = list((work / "uhh" / "logs").glob("*.jsonl"))
            sess = verify_capture(sessions[0]) if len(sessions) == 1 else {}
            ok = (code is not None and seen["unique"] == want and seen["max"] == want - 1 and
                  rep.get("logs_written") == want and rep.get("stdout_logs") == want and rep.get("hits") == want and
                  rep.get("log_dropped") == 0 and rep.get("live_output_error") is None and
                  not rep.get("live_output_closed") and rep.get("error") is None and
                  sess.get("logs") == want and sess.get("gaps") == 0)
            record(name, ok, f"console_seq={seen['unique']}/{want} missing={seen['missing']} report={'yes' if rep else 'no'} "
                             f"hits={rep.get('hits')} written={rep.get('logs_written')} stdout_logs={rep.get('stdout_logs')} "
                             f"live_error={rep.get('live_output_error')} file={sess.get('logs')} rc={code} {secs:.0f}s"
                             + ("" if ok else f" vt_tail={vt_tail!r}"))
        except Exception as e:
            record(name, False, repr(e))
        finally:
            for k, v in zip(("TEMP", "TMP"), old_temp):
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            shutil.rmtree(work, ignore_errors=True)


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
    ap.add_argument("--console-records", type=int, default=0,
                    help="opt-in: stdout-console also runs one inline --stack session of this many records "
                         "(e.g. 2000000) into a pseudo console")
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
    if want(check_callorig_deep): check_callorig_deep()
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
    if want(check_carry_exact): check_carry_exact()
    if want(check_attach_new): check_attach_new()
    if want(check_attach_agent_scope): check_attach_agent_scope()
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
    if want(check_hunt_stack): check_hunt_stack()
    if want(check_init_cutoff): check_init_cutoff()
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
    if want(check_ctrl_warm): check_ctrl_warm()
    if want(check_stream_filestall): check_stream_filestall()
    if want(check_stream_filefail): check_stream_filefail()
    if want(check_ctrl_symload): check_ctrl_symload()
    if want(check_cdx_review): check_cdx_review()
    if want(check_newapp_files): check_newapp_files()
    if want(check_newapp_flag): check_newapp_flag()
    if want(check_newapp_reg): check_newapp_reg()
    if want(check_logs_format): check_logs_format()
    if want(check_logs_format_fast): check_logs_format_fast()
    if want(check_logs_order): check_logs_order()
    if want(check_logs_wedge): check_logs_wedge()
    if want(check_logs_controller_killed): check_logs_controller_killed()
    if want(check_logs_stdout_closed): check_logs_stdout_closed()
    if want(check_inplace_shapes): check_inplace_shapes()
    if want(check_lifecycle): check_lifecycle()
    if want(check_ctrl_pack_oom): check_ctrl_pack_oom()
    if want(check_cet_sde): check_cet_sde()
    if want(check_cxlib): check_cxlib()
    if want(check_cx2_review): check_cx2_review()
    if want(check_symbols_grammar): check_symbols_grammar()
    if want(check_quickstart): check_quickstart()
    if want(check_callfunc_concurrent): check_callfunc_concurrent()
    if want(check_hw_dr_restore): check_hw_dr_restore()
    if want(check_hw_co_borrow): check_hw_co_borrow()
    if want(check_inline_absolute): check_inline_absolute()
    if want(check_cet_agent): check_cet_agent()
    if want(check_sessions_repeat): check_sessions_repeat()
    if want(check_gated_e2e): check_gated_e2e()
    if want(check_realbig): check_realbig("" if args.bigapps else REALBIG_DEFAULT)
    if want(check_stdout_powershell): check_stdout_powershell()
    if want(check_powershell_detach): check_powershell_detach()
    if want(check_slowreader_detach): check_slowreader_detach()
    if want(check_stdout_console): check_stdout_console(args.console_records)
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
