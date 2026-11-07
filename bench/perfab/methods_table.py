#!/usr/bin/env python3
"""Per-method tables from a `perf_ab.py --group methods` run (one side).

  python3 methods_table.py raw_x64.jsonl [raw_x86.jsonl ...]

Table 1, per backend: ns per hit with the callback doing one operation, median over rounds and
spread ((max - min) / median), and the operation's own cost = median(method) - median(empty).
"hit" is the empty callback minus the uninstrumented call. Table 2 (C7): the empty callback and
an atomic increment of a plain vs a UHH_SHARED global, with hitcost_driver (no UHH_SHARED) and
hitcost_driver_shared (bp/hw callbacks from the controller's copy of the agent DLL).
Runs with ok=false are counted and excluded.
"""
import json, statistics, sys
from collections import defaultdict

BACKENDS = ["breakpoint", "hw", "inline"]


def load(path):
    d, bad = defaultdict(list), defaultdict(int)
    for line in open(path):
        r = json.loads(line)
        if r.get("ok") and r.get("ns_per_call") is not None:
            d[r["case"]].append(r["ns_per_call"])
        else:
            bad[r["case"]] += 1
    return d, bad


def stat(v):
    if not v:
        return None, None
    m = statistics.median(v)
    return m, (max(v) - min(v)) / m * 100 if m else 0


def fmt(m, sp=None):
    if m is None:
        return "-"
    s = f"{m:,.0f}" if abs(m) >= 100 else f"{m:.1f}"
    return s + (f" ({sp:.0f}%)" if sp is not None else "")


def main():
    for path in sys.argv[1:]:
        d, bad = load(path)
        methods = []
        for c in d:
            f, bk, m, _ = c.split("/")
            if f == "hit" and bk != "base" and m not in methods:
                methods.append(m)
        base, _ = stat(d.get("hit/base/empty/t1"))
        print(f"\n### {path}\n")
        print("| method | " + " | ".join(f"{b} ns/hit (spread) | {b} op" for b in BACKENDS) + " |")
        print("|---|" + "---|---|" * len(BACKENDS))
        for m in methods:
            cells = []
            for b in BACKENDS:
                v, sp = stat(d.get(f"hit/{b}/{m}/t1"))
                e, _ = stat(d.get(f"hit/{b}/empty/t1"))
                op = (v - base if m == "empty" and base is not None else v - e) if v is not None and e is not None else None
                cells += [fmt(v, sp), fmt(op)]
            print(f"| {m} | " + " | ".join(cells) + " |")
        print(f"\nuninstrumented call: {fmt(base)} ns; empty row's op column = the hit itself (empty - uninstrumented)")
        print("\n| method | " + " | ".join(f"{b} plain driver | {b} shared driver" for b in BACKENDS) + " |")
        print("|---|" + "---|---|" * len(BACKENDS))
        for m in ("empty", "counter_plain", "counter_shared"):
            cells = []
            for b in BACKENDS:
                cells += [fmt(*stat(d.get(f"hit/{b}/{m}/t1"))), fmt(*stat(d.get(f"hitsh/{b}/{m}/t1")))]
            print(f"| {m} | " + " | ".join(cells) + " |")
        if bad:
            print("\nexcluded (ok=false): " + ", ".join(f"{c} x{n}" for c, n in bad.items()))


if __name__ == "__main__":
    main()
