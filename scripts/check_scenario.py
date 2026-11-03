#!/usr/bin/env python3
"""Correctness gate for the gated multithreaded scenario (plan v2).

    check_scenario.py --bin build/Release [--threads W] [--reads R]

Checks:
- probe_app alone, shipped config: workload gated off (0 reads), DLL late-loaded.
- probe_session: deferred configparse.dll+RVA probe is pending pre-load, activates
  on load, overrides the parsed flag exactly once, and every read then runs.
- existing-hook variant: the pre-existing ReadThunk hook runs exactly once per read.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path


def run(cmd, timeout=120):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    objs = {}
    for line in r.stdout.splitlines():
        if line.startswith("{"):
            o = json.loads(line)
            objs[o["kind"]] = o
    return r, objs


def rvas(map_file, *syms):
    out = subprocess.check_output([sys.executable, str(Path(__file__).with_name("site_rvas.py")),
                                   str(map_file), *syms], text=True)
    return json.loads(out)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bin", type=Path, default=Path("build/Release"))
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--reads", type=int, default=200)
    args = p.parse_args()
    b = args.bin.resolve()
    total = args.threads * args.reads
    app, session = str(b / "probe_app.exe"), str(b / "probe_session.exe")
    flag_rva = rvas(b / "configparse.map", "ParsedFlagSite")["ParsedFlagSite"]
    read_rva = rvas(b / "probe_app.map", "ReadSite")["ReadSite"]

    # 1. Gated off by the shipped config.
    r, o = run([app, "--no-wait", "--threads", str(args.threads), "--reads", str(args.reads), "--clean"])
    assert r.returncode == 0, r.stderr
    assert o["app"]["reads_enabled"] == 0 and o["app"]["successful_reads"] == 0, o["app"]
    print("PASS gated-off: shipped config runs 0 reads")

    # 2. Deferred probe enables the workload; exactly one override. On-attach
    #    comparison against the on-disk image detects the pre-existing hook.
    for prehook in ("--clean", "--prehook"):
        r, o = run([session, str(flag_rva), str(read_rva),
                    "--threads", str(args.threads), "--reads", str(args.reads), prehook])
        assert r.returncode == 0, r.stderr
        s, a = o["session"], o["app"]
        assert s["flag_probe_active"] and s["overrides"] == 1, s
        assert a["reads_enabled"] == 1 and a["successful_reads"] == total, a
        assert "probe: active configparse.dll" in r.stderr, r.stderr
        want_hooked = prehook == "--prehook"
        assert s["read_site_checked"] and s["read_site_hooked"] == want_hooked, s
        assert ("PRE-EXISTING HOOK" in r.stderr) == want_hooked, r.stderr
        if want_hooked:
            assert a["prehook_calls"] == total, a
        print(f"PASS deferred-activation {prehook}: 1 override, {total} reads, "
              f"read-site hooked={want_hooked} detected on attach")

    print("All scenario checks passed.")


if __name__ == "__main__":
    main()
