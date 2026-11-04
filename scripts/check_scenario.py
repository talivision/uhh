#!/usr/bin/env python3
"""Quick end-to-end check of the gated scenario (a subset of regress.py).

    check_scenario.py --bin build-x64/Release [--threads W] [--reads R]

- probe_app alone, shipped config: the feature is off (0 opens, 0 reads) and the config
  DLL is late-loaded (never a static dependency).
- gated_config: the deferred flag breakpoint at configparse.dll!ParseConfig+0x16 is
  pending before the DLL loads, activates on load, and overrides the parsed flag
  exactly once; the inline probe on probe_app.exe!ReadThunk then logs every read, so
  its hit count equals the total number of reads (breakpoint + inline in one session).
"""
import argparse
import json
import subprocess
from pathlib import Path


def run(cmd, timeout=180):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, timeout=timeout)
    objs, probes = {}, []
    for line in r.stdout.splitlines():
        if line.startswith("{"):
            o = json.loads(line)
            (probes.append(o) if o.get("kind") == "probe" else objs.__setitem__(o["kind"], o))
    return r, objs, probes


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bin", type=Path, default=Path("build-x64/Release"))
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--reads", type=int, default=200)
    args = p.parse_args()
    b = args.bin.resolve()
    total = args.threads * args.reads
    app = b / "probe_app.exe"
    workload = ["--no-wait", "--threads", args.threads, "--reads", args.reads]

    # 1. Gated off by the shipped config.
    r, o, _ = run([app, *workload])
    assert r.returncode == 0, r.stderr
    assert o["app"]["reads_enabled"] == 0 and o["app"]["opened"] == 0 and o["app"]["successful_reads"] == 0, o["app"]
    print("PASS gated-off: shipped config runs 0 opens, 0 reads")

    # 2. Deferred flag breakpoint + inline read log, mixed in one session.
    r, o, probes = run([b / "gated_config.exe", "configparse.dll!ParseConfig+0x16", "probe_app.exe!ReadThunk",
                        "--", app, *workload])
    assert r.returncode == 0, r.stderr + "\n" + r.stdout
    rep = o["probe_report"]
    assert rep["overrides"] == 1, rep
    flag = next(x for x in probes if x["location"].startswith("configparse.dll"))
    read = next(x for x in probes if x["location"] == "probe_app.exe!ReadThunk")
    assert flag["backend"] == "breakpoint" and flag["hits"] == 1, flag
    assert read["backend"] == "inline" and read["hits"] == total, read
    print(f"PASS deferred-activation: 1 override, inline hits == {total} reads "
          f"(breakpoint + inline mixed)")
    print("All scenario checks passed.")


if __name__ == "__main__":
    main()
