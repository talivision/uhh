#!/usr/bin/env python3
"""Summarize perf_ab.py raw JSONL into a Markdown table.

  python3 summarize.py --label x64 raw_x64.jsonl [--label x86 raw_x86.jsonl ...]

Per (case, metric): the median of each side over rounds and its spread ((max - min) / median);
for every side after the first (the reference), the delta vs the reference and a verdict:
gain / REGRESSION only when the two sides' ranges do not overlap (every round of one beat every
round of the other) -- else "~" (within noise). Runs with ok=false are counted and excluded.
"""
import argparse, json, statistics
from collections import defaultdict

# metric, better ("lo" | "hi"), unit/format
METRICS = {
    "hit": [("ns_per_call", "lo", "ns/call"), ("hits_per_s", "hi", "hits/s")],
    "mt": [("hits_per_s", "hi", "hits/s")],
    "sink": [("logs_per_s", "hi", "logs/s")],
    "latency": [("p50_ms", "lo", "ms"), ("p99_ms", "lo", "ms")],
    "live": [("lag_p50_ms", "lo", "ms"), ("lag_p99_ms", "lo", "ms")],
    "attach": [("attach_ms", "lo", "ms"), ("detach_ms", "lo", "ms")],
    "launch": [("launch_ms", "lo", "ms"), ("total_ms", "lo", "ms"), ("wall_ms", "lo", "ms")],
    "gated": [("ns_per_read", "lo", "ns/read"), ("wall_ms", "lo", "ms")],
}


def fmt(v):
    if v is None:
        return "-"
    a = abs(v)
    return f"{v:,.0f}" if a >= 100 else f"{v:.1f}" if a >= 10 else f"{v:.2f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", action="append", nargs=2, metavar=("LABEL", "FILE"), required=True)
    a = ap.parse_args()
    for label, path in a.label:
        data, bad, order, sides = defaultdict(lambda: defaultdict(list)), defaultdict(int), [], []
        for line in open(path):
            r = json.loads(line)
            if r.get("wall_s") is not None:
                r["wall_ms"] = r["wall_s"] * 1000.0
            c, sd = r["case"], r["side"]
            if c not in order:
                order.append(c)
            if sd not in sides:
                sides.append(sd)
            if not r.get("ok"):
                bad[(c, sd)] += 1
                continue
            data[c][sd].append(r)
        ref = sides[0]
        print(f"\n### {label}\n")
        head = "| case | metric | " + " | ".join(f"{s} median (spread)" for s in sides) + " | " + \
               " | ".join(f"{s} vs {ref}" for s in sides[1:]) + " | rounds |"
        print(head)
        print("|---|---|" + "---:|" * len(sides) + "---|" * (len(sides) - 1) + "---|")
        for c in order:
            fam = c.split("/")[0]
            for m, better, unit in METRICS.get(fam, []):
                vals = {s: [x[m] for x in data[c][s] if x.get(m) is not None] for s in sides}
                if not any(vals.values()):
                    continue
                med = {s: statistics.median(v) if v else None for s, v in vals.items()}
                cells = []
                for s in sides:
                    v, md = vals[s], med[s]
                    sp = f" ({(max(v) - min(v)) / md * 100:.0f}%)" if v and md else ""
                    cells.append(fmt(md) + sp)
                deltas = []
                for s in sides[1:]:
                    va, vb, ma, mb = vals[ref], vals[s], med[ref], med[s]
                    if not va or not vb or not ma:
                        deltas.append("-"); continue
                    d = (mb - ma) / ma * 100
                    verdict = "~"
                    if max(vb) < min(va) or min(vb) > max(va):
                        good = (max(vb) < min(va)) == (better == "lo")
                        verdict = "**gain**" if good else "**REGRESSION**"
                    deltas.append(f"{d:+.1f}% {verdict}")
                nb = "/".join(str(len(vals[s])) for s in sides)
                fails = [bad.get((c, s), 0) for s in sides]
                if any(fails):
                    nb += " (failed " + "/".join(map(str, fails)) + ")"
                print(f"| {c} | {m} ({unit}) | " + " | ".join(cells) + " | " + " | ".join(deltas) + f" | {nb} |")


if __name__ == "__main__":
    main()
