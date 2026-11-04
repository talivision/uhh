#!/usr/bin/env python3
"""UHH regression suite — one command, asserts every behaviour we rely on.

    regress.py --bin build-x64/Release [--threads 8] [--reads 2000]

Run it against each build directory (x64 and x86). Every check is independent, has a
timeout, and asserts a concrete expected result; the script prints PASS/FAIL per check
and exits non-zero if ANY check fails, so it catches regressions without re-deriving
the checks by hand. Store-and-run this instead of ad-hoc scripts.

Checks:
  - gated-off: probe_app alone runs 0 reads (workload gated by the shipped config).
  - mix matrix: flag x read over {breakpoint, inline, hw}; exactly one override and the
    read probe's hit count equals the reads (flag=inline exercises the HW fallback).
  - multithread exact: each read backend at >cores threads -> hits == threads*reads,
    the no-dropped-events guarantee -- and one formatted log per hit, log_dropped == 0
    (the no-dropped-LOGS guarantee; inline logs cross a shared ring the controller drains).
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


def check_gated_off():
    p = exe("probe_app.exe")
    if not p:
        return skip("gated-off", "probe_app.exe missing")
    try:
        r, o = run([p, "--no-wait", "--threads", "4", "--reads", "200", "--clean"], timeout=60)
        a = app(o)
        ok = r.returncode == 0 and a.get("reads_enabled") == 0 and a.get("successful_reads") == 0
        record("gated-off", ok, f"reads_enabled={a.get('reads_enabled')} reads={a.get('successful_reads')}")
    except Exception as e:
        record("gated-off", False, repr(e))


def gated(flag_bk, read_bk, threads, reads, timeout=200, log=True, extra=()):
    g = exe("gated_config.exe")
    flag = rvas("configparse.map", "ParsedFlagSite")["ParsedFlagSite"]
    read = rvas("probe_app.map", "ReadSite")["ReadSite"]
    return run([g, flag, read, "--flag-backend", flag_bk, "--read-backend", read_bk,
                *([] if log else ["--no-log"]), *extra,
                "--no-wait", "--threads", threads, "--reads", reads], timeout=timeout)


def read_logs(objs):
    """Logs emitted by log_read (one per read hit) and the report's drop counter."""
    n = sum(1 for o in objs if o.get("kind") == "probe_log" and str(o.get("message", "")).startswith("read handle="))
    return n, report(objs).get("log_dropped")


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
                rd = next((x for x in probes(o) if "probe_app.exe" in x.get("location", "")), {})
                ok = (r.returncode == 0 and rep.get("overrides") == 1 and rd.get("hits") == total)
                record(name, ok, f"override={rep.get('overrides')} read_hits={rd.get('hits')} want={total}")
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
            rd = next((x for x in probes(o) if "probe_app.exe" in x.get("location", "")), {})
            a = app(o)
            logs, dropped = read_logs(o)
            ok = (rd.get("hits") == total and a.get("successful_reads") == total and
                  logs == total and dropped == 0)
            record(name, ok, f"hits={rd.get('hits')} reads={a.get('successful_reads')} logs={logs} "
                             f"dropped={dropped} want={total}")
        except Exception as e:
            record(name, False, repr(e))


def check_filtered_logging(threads, reads):
    """The original scenario with a runtime-learned filter: log only reads of the
    SELECTED child's handle inside the selected range. probe_app's request rotation makes
    that exactly half the reads; every read is still counted."""
    if not exe("gated_config.exe"):
        return skip("filtered-log", "gated_config.exe missing")
    total = int(threads) * int(reads)
    for read_bk in ("breakpoint", "hw", "inline"):
        name = f"filtered-log-{read_bk}"
        try:
            _, o = gated("breakpoint", read_bk, threads, reads, timeout=300, extra=("--log-selected",))
            rd = next((x for x in probes(o) if "probe_app.exe" in x.get("location", "")), {})
            logs, dropped = read_logs(o)
            learned = [x for x in o if x.get("kind") == "probe_log" and str(x.get("message", "")).startswith("learned")]
            ok = rd.get("hits") == total and logs == total // 2 and dropped == 0 and len(learned) == 1
            record(name, ok, f"hits={rd.get('hits')} logged={logs} want_logged={total // 2} learned={len(learned)}")
        except Exception as e:
            record(name, False, repr(e))


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
            rd = next((x for x in probes(o) if "probe_app.exe" in x.get("location", "")), {})
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
        _, o = run([d, r["ShortSite"], r["PrehookSite"], r["UnrelocSite"], r["StackSite"], r["StackInsideSite"]],
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
        # Pre-hooked site handling (the fixture's TLS callback installs a real foreign E9):
        # default inline is refused WITH a report; fallback moves to hw and hits once.
        rows = {row.get("backend"): row for row in o if row.get("site") == "PrehookSite"}
        dflt, fb = rows.get("inline-default", {}), rows.get("inline-fallback", {})
        ok2 = (dflt.get("verdict") == "expected_breakage" and dflt.get("prehook_reports", 0) >= 1 and
               fb.get("verdict") == "pass" and fb.get("prehook_reports", 0) >= 1 and
               rows.get("breakpoint", {}).get("verdict") == "pass")
        record("prehook-detect", ok2, f"default={dflt.get('verdict')}/reports={dflt.get('prehook_reports')} "
                                      f"fallback={fb.get('verdict')}/reports={fb.get('prehook_reports')}")
    except Exception as e:
        record("breakage-controls", False, repr(e))


def check_frida_parity():
    d = exe("frida_parity.exe")
    if not d or not exe("parity_target.exe"):
        return skip("frida-parity", "frida_parity/parity_target missing")
    try:
        r = rvas("parity_target.map", "ParityB1Site", "ParityB2Site", "ParityB4Site", "ParityB6Site")
        _, o = run([d, r["ParityB1Site"], r["ParityB2Site"], r["ParityB4Site"], r["ParityB6Site"]], timeout=90)
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
            _, o = run([d, rva, *extra, "--no-wait", "--threads", "4", "--writes", "1000", "--reads", "1000"],
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
            _, o = run([d, "--entry", entry, "--writes", writes], timeout=120)
            res = next((x for x in o if x.get("kind") == "dynwatch_result"), {})
            rep = report(o)
            once = [p for p in probes(o) if p.get("location", "").startswith("0x") and p.get("backend") == "breakpoint"]
            stacks = [x.get("stack") for x in o if x.get("kind") == "probe_log" and x.get("stack")]
            sym_ok = bool(stacks) and len(stacks[0]) >= 3 and stacks[0][0].startswith("dynwatch_target")
            marker = next((p for p in probes(o) if p.get("location", "").endswith("!dynwatch_marker")), {})
            calls = [x.get("message") for x in o if x.get("kind") == "probe_log" and "call_func" in str(x.get("message"))]
            tgt = next((x for x in o if x.get("kind") == "target"), {})
            ok = (res.get("returns") == 1 and res.get("arms") == 1 and res.get("watch_hits") == want and
                  rep.get("error") is None and len(once) == 1 and once[0].get("active") is False and
                  once[0].get("hits") == 1 and sym_ok and
                  marker.get("backend") == "inline" and marker.get("hits") == 50 and tgt.get("marker_calls") == 50 and
                  calls == ["call_func sum6=91 ok=1"])
            record(name, ok, f"returns={res.get('returns')} arms={res.get('arms')} watch_hits={res.get('watch_hits')} "
                             f"want={want} once_retired={bool(once) and once[0].get('active') is False} "
                             f"runtime_inline_hits={marker.get('hits')}/50 call_func={calls} stack0={(stacks[0][0] if stacks else None)}")
        except Exception as e:
            record(name, False, repr(e))


SYS32 = Path(r"C:\Windows\System32")


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
        ("findstr-open", ["KernelBase.dll!CreateFileW:Wxx"],
         [SYS32 / "findstr.exe", "/c:fonts", r"C:\Windows\win.ini"], r"CreateFileW\(\"C:\\Windows\\win\.ini\""),
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
    args = ap.parse_args()
    BIN = args.bin.resolve()
    print(f"UHH regression suite — bin={BIN}")
    check_gated_off()
    check_mix_matrix(args.threads, args.reads)
    check_multithread_exact(args.threads, args.reads)
    check_log_throughput(args.threads, args.reads)
    check_filtered_logging(args.threads, args.reads)
    if int(args.volume_reads) > 0:
        check_volume(args.volume_reads)
    check_breakage()
    check_frida_parity()
    check_watchpoint()
    check_dynwatch()
    check_realworld()
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
