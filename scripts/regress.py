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
import subprocess
import sys
import threading
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
    RESULTS.append((name, "SKIP", why))


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
READ_LOCATION = "probe_app.exe!ReadThunk"
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


def gated(flag_bk, read_bk, threads, reads, timeout=200, log=True):
    return run([exe("gated_config.exe"), "--flag-backend", flag_bk, "--read-backend", read_bk,
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
    return next((x for x in probes(objs) if x.get("location", "").endswith("!ReadThunk")), {})


def open_probe(objs):
    return next((x for x in probes(objs) if x.get("location", "").endswith("!OpenThunk")), {})


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
    # flag=inline uses the HW fallback (late-loaded site); flag=hw/breakpoint arm directly.
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
                ok = (r.returncode == 0 and rep.get("overrides") == 1 and rd.get("hits") == total and
                      logs == total and dropped == 0 and nomap == 0 and pids_ok and same_backend and
                      rep.get("error") is None)
                record(name, ok, f"override={rep.get('overrides')} read_hits={rd.get('hits')} logs={logs} "
                                 f"dropped={dropped} unmapped={nomap} pids_ok={pids_ok} "
                                 f"backends={rd.get('backend')}/{op.get('backend')} want={total}")
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
                                    "--range", f"{h['base'] + offset}:64", "--backend", bk],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            procs.append(att)
            aout, aerr = Lines(att.stdout), Lines(att.stderr)
            if not aout.wait_for(lambda l: '"kind":"attached"' in l, 30):
                raise RuntimeError("uhh_attach did not attach")
            # Probes on already-loaded modules arm after the attach (inline: asynchronously,
            # in the injected agent). Release the gate only once both are live.
            for loc in ("probe_app.exe!OpenThunk", READ_LOCATION):
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
                             f"rc={att.returncode}")
        except Exception as e:
            record(name, False, repr(e))
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
            r, o = gated("breakpoint", read_bk, str(threads), str(volume_reads), timeout=timeout)
            rd = read_probe(o)
            a = app(o)
            logs, dropped = read_logs(o)
            ok = (rd.get("hits") == total and a.get("successful_reads") == total and
                  logs == total and dropped == 0)
            record(name, ok, f"hits={rd.get('hits')} reads={a.get('successful_reads')} logs={logs} "
                             f"dropped={dropped} want={total}")
        except Exception as e:
            record(name, False, repr(e))


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
                bad.append(f"{key}={row.get('verdict')}!={want}")
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
        passed = [row for row in o if row.get("verdict") == "pass"]
        ok = len(passed) == 4
        record("frida-parity", ok, f"{len(passed)}/4 pass")
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
            sym_ok = bool(stacks) and len(stacks[0]) >= 3 and stacks[0][0].startswith("dynwatch_target")
            marker = next((p for p in probes(o) if p.get("location", "").endswith("!dynwatch_marker")), {})
            calls = [x.get("message") for x in o if x.get("kind") == "probe_log" and "call_func" in str(x.get("message"))]
            entry = next((x.get("stack") for x in o if x.get("kind") == "probe_log" and x.get("message") == "malloc(0x1337) entry"), None)
            entry_ok = bool(entry) and len(entry) >= 2 and entry[1].startswith("dynwatch_target")
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
                      "call_func", "get_session", "probe_add_symbol", "probe_watch", "probe_add_address",
                      "later-hit", "watch-hit"]


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
            stack_ok = bool(stacks) and all(len(st) >= 2 and st[1].startswith("conformance_target") for st in stacks)
            ok = (not fails and not missing and tgt.get("arg_rewritten") == 10 and tgt.get("mem_written") == 10 and
                  stack_ok and report(o).get("error") is None and report(o).get("log_dropped") == 0)
            record(name, ok, f"fails={fails[:3]} missing={missing} arg_rewritten={tgt.get('arg_rewritten')} "
                             f"mem_written={tgt.get('mem_written')} stack_ok={stack_ok}")
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
            _, o = run([d, "--backend", bk, "--", t, "--threads", threads, "--iters", iters], timeout=900)
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
                  pr.get("hits") == calls and rep.get("log_dropped") == 0 and rep.get("error") is None)
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
            _, o = run([t, "--backend", bk, "-p", "dynwatch_target.exe!worker:x", "--", d, "--no-wait", "--writes", "10"],
                       timeout=120)
            msgs = [str(x.get("message", "")) for x in o if x.get("kind") == "probe_log"]
            pr = next(iter(probes(o)), {})
            ok = pr.get("hits") == 1 and any(m.startswith("worker(") for m in msgs) and report(o).get("error") is None
            record(f"symbols-pdb-name-{bk}", ok, f"hits={pr.get('hits')} logs={msgs[:1]} err={report(o).get('error')}")
        except Exception as e:
            record(f"symbols-pdb-name-{bk}", False, repr(e))
    try:
        _, o = run([t, "--list", "kernel32.dll", "--mask", "*CreateFile*"], timeout=60)
        names = {x.get("name") for x in o if x.get("kind") == "symbol"}
        record("symbols-list", "CreateFileW" in names, f"found={sorted(n for n in names if n)[:5]}")
    except Exception as e:
        record("symbols-list", False, repr(e))


def check_prehook_attach():
    """The realistic 'already hooked' case: attach to a process that detoured one of its own
    functions at run time (probe_app --prehook puts a SafetyHook inline detour on ReadThunk
    before its gate). An inline probe there must produce the pre-hook report (live bytes
    differ from the image on disk: pattern, symbolized destination, suggestions) and, with
    PROBE_FALLBACK_HW (uhh_trace's inline default), move to the hardware backend."""
    t, a = exe("uhh_trace.exe"), exe("probe_app.exe")
    if not t or not a:
        return skip("prehook-attach", "uhh_trace/probe_app missing")
    import time
    target = None
    try:
        target = subprocess.Popen([str(a), "--prehook", "--helpers", "1"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        line = target.stdout.readline().decode(errors="replace")       # {"kind":"waiting",...}: hook is in
        tracer = subprocess.Popen([str(t), "--backend", "inline", "--attach", str(target.pid),
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
                ok = hit is not None and rep.get("error") is None
                record(label, ok, f"logs={len(msgs)} match={hit[:70] if hit else None} err={rep.get('error')}")
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

    def want(fn):
        return not only or any(o in fn.__name__ for o in only)
    print(f"UHH regression suite — bin={BIN}")
    if want(check_sites): check_sites()
    if want(check_gated_off): check_gated_off()
    if want(check_mix_matrix): check_mix_matrix(args.threads, args.reads)
    if want(check_multithread_exact): check_multithread_exact(args.threads, args.reads)
    if want(check_log_throughput): check_log_throughput(args.threads, args.reads)
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
    print("-" * 72)
    failed = 0
    for name, status, detail in RESULTS:
        print(f"  {status:4}  {name:34} {detail}")
        if status == "FAIL":
            failed += 1
    print("-" * 72)
    n = len(RESULTS)
    print(f"{n - failed}/{n} ok, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
