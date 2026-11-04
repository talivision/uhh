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
    the no-dropped-events guarantee.
  - breakage: the hostile fixtures produce their expected verdicts.
  - frida-parity: the four Interceptor-parity demos all pass.
  - watchpoint: a hardware write-watchpoint fires once per store.
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


def gated(flag_bk, read_bk, threads, reads, timeout=200):
    g = exe("gated_config.exe")
    flag = rvas("configparse.map", "ParsedFlagSite")["ParsedFlagSite"]
    read = rvas("probe_app.map", "ReadSite")["ReadSite"]
    return run([g, flag, read, "--flag-backend", flag_bk, "--read-backend", read_bk,
                "--no-wait", "--threads", threads, "--reads", reads], timeout=timeout)


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
            ok = (rd.get("hits") == total and a.get("successful_reads") == total)
            record(name, ok, f"hits={rd.get('hits')} reads={a.get('successful_reads')} want={total}")
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
    try:
        rva = rvas("watch_target.map", "g_watched")["g_watched"]
        _, o = run([d, rva, "--no-wait", "--threads", "4", "--writes", "1000"], timeout=120)
        rd = next((x for x in probes(o) if x.get("backend") == "hw"), {})
        hits = next((x.get("callback_hits") for x in o if x.get("kind") == "watch_driver"), None)
        ok = rd.get("hits") == 4000 and hits == 4000
        record("watchpoint", ok, f"probe_hits={rd.get('hits')} callback_hits={hits} want=4000")
    except Exception as e:
        record("watchpoint", False, repr(e))


def main():
    global BIN
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", type=Path, default=Path("build-x64/Release"))
    ap.add_argument("--threads", default="8")
    ap.add_argument("--reads", default="1000")
    args = ap.parse_args()
    BIN = args.bin.resolve()
    print(f"UHH regression suite — bin={BIN}")
    check_gated_off()
    check_mix_matrix(args.threads, args.reads)
    check_multithread_exact(args.threads, args.reads)
    check_breakage()
    check_frida_parity()
    check_watchpoint()
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
