#!/usr/bin/env python3
"""On-demand correctness gate for the gated scenario (plan v2) on the UHH probe_api.

    check_scenario.py --bin build-x64/Release [--threads W] [--reads R]

Checks, against a built tree (works for both the -A x64 and -A Win32 outputs):
- probe_app alone, shipped config: the read workload is gated off (0 reads), and the
  config DLL is late-loaded (never a static dependency).
- gated_config: the deferred configparse.dll+RVA flag probe (software breakpoint) is
  pending before the DLL loads, activates on load, and overrides the parsed flag
  exactly once; the inline probe on ReadSite then logs every read, so its hit count
  equals the total number of reads. Proves the breakpoint and inline backends mixed
  in one session, and is the same check on x86 and x64.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path


def run(cmd, timeout=180):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    objs, probes = {}, []
    for line in r.stdout.splitlines():
        if line.startswith("{"):
            o = json.loads(line)
            (probes.append(o) if o.get("kind") == "probe" else objs.__setitem__(o["kind"], o))
    return r, objs, probes


def rvas(map_file, *syms):
    out = subprocess.check_output([sys.executable, str(Path(__file__).with_name("site_rvas.py")),
                                   str(map_file), *syms], text=True)
    return json.loads(out)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bin", type=Path, default=Path("build-x64/Release"))
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--reads", type=int, default=200)
    args = p.parse_args()
    b = args.bin.resolve()
    total = args.threads * args.reads
    app, gated = str(b / "probe_app.exe"), str(b / "gated_config.exe")
    flag_rva = rvas(b / "configparse.map", "ParsedFlagSite")["ParsedFlagSite"]
    read_rva = rvas(b / "probe_app.map", "ReadSite")["ReadSite"]

    # 1. Gated off by the shipped config.
    r, o, _ = run([app, "--no-wait", "--threads", str(args.threads), "--reads", str(args.reads), "--clean"])
    assert r.returncode == 0, r.stderr
    assert o["app"]["reads_enabled"] == 0 and o["app"]["successful_reads"] == 0, o["app"]
    print("PASS gated-off: shipped config runs 0 reads")

    # 2. Deferred flag breakpoint + inline read log, mixed in one session.
    r, o, probes = run([gated, str(flag_rva), str(read_rva),
                        "--no-wait", "--threads", str(args.threads), "--reads", str(args.reads), "--clean"])
    assert r.returncode == 0, r.stderr + "\n" + r.stdout
    rep = o["probe_report"]
    assert rep["overrides"] == 1, rep
    bp = next(x for x in probes if x["backend"] == "breakpoint")
    inl = next(x for x in probes if x["backend"] == "inline")
    assert bp["hits"] == 1, bp
    assert inl["hits"] == total, inl
    print(f"PASS deferred-activation: 1 override, inline hits == {total} reads "
          f"(breakpoint + inline mixed)")
    print("All scenario checks passed.")


if __name__ == "__main__":
    main()
