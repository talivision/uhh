#!/usr/bin/env python3
"""Markdown tables from vs_frida.py rows (JSON lines), one table per workload, x64 and x86 side by side.

  python3 bench/frida/tables.py rows-x64.jsonl rows-x86.jsonl [--tag vm]

Per method and arch: median [min..max] over the repeats of the per-event figure, the added cost
vs the uninstrumented baseline of the same arch, and correctness as exact runs / runs plus the
first failure seen.
"""
import argparse, collections, json, statistics

ORDER = ["baseline", "uhh-inline", "uhh-hw", "uhh-breakpoint", "uhh-watch",
         "frida-js", "frida-js-v8", "frida-cmodule", "frida-hw", "frida-watch"]


def load(paths, tag):
    rows = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    r = json.loads(line)
                    if tag is None or r.get("tag") == tag:
                        rows.append(r)
    return rows


def metric(w, r):
    if w == "hit":
        return r.get("ns_per_call")
    if w == "churn":
        return r.get("wall_s")
    e = r.get("elapsed_ns")
    return e / (r["threads"] * r["reads_per_thread"]) if e is not None else None


def fmt(v, w):
    return f"{v:,.2f}" if w == "churn" else (f"{v:,.1f}" if v < 100 else f"{v:,.0f}")


def why(r):
    if r.get("error"):
        e = r["error"]
        if "without the exit handshake" in e:
            return "target crashed"
        return e[:60]
    for k in ("wrong_pid", "no_pid", "threads_differ"):
        if r.get(k):
            return f"{k}={r[k]}"
    if r.get("calls") is not None:
        return f"calls={r['calls']:,}"
    return "inexact"


def table(rows, w, arches):
    by = collections.defaultdict(list)
    for r in rows:
        if r["workload"] == w:
            by[(r["method"], r["arch"])].append(r)
    unit = {"hit": "ns/call", "churn": "s wall", "count": "ns/read", "gated": "ns/read"}[w]
    hdr = "| method | " + " | ".join(f"{a} {unit} (median [min..max]) | {a} added | {a} exact" for a in arches) + " |"
    out = [hdr, "|---|" + "---:|---:|---|" * len(arches)]
    base = {}
    for a in arches:
        vals = [metric(w, r) for r in by.get(("baseline", a), []) if metric(w, r) is not None]
        if vals:
            base[a] = statistics.median(vals)
    for m in ORDER:
        if not any((m, a) in by for a in arches):
            continue
        cells = []
        for a in arches:
            rs = by.get((m, a), [])
            ok = [r for r in rs if r.get("exact")]
            vals = [metric(w, r) for r in ok if metric(w, r) is not None]
            if vals:
                med = statistics.median(vals)
                c1 = f"{fmt(med, w)} [{fmt(min(vals), w)}..{fmt(max(vals), w)}]"
                c2 = "--" if m == "baseline" or a not in base else f"+{fmt(med - base[a], w)} (x{med / base[a]:.1f})"
            else:
                c1, c2 = "--", "--"
            bad = [r for r in rs if not r.get("exact")]
            c3 = f"{len(ok)}/{len(rs)}" + (f" ({why(bad[0])})" if bad else "")
            cells += [c1, c2, c3]
        out.append(f"| {m} | " + " | ".join(cells) + " |")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rows", nargs="+")
    ap.add_argument("--tag", default=None)
    a = ap.parse_args()
    rows = load(a.rows, a.tag)
    arches = sorted({r["arch"] for r in rows})
    for w in ("count", "gated", "churn", "hit"):
        if any(r["workload"] == w for r in rows):
            print(f"\n### {w}\n")
            print(table(rows, w, arches))
    walls = collections.defaultdict(list)
    for r in rows:
        if r["workload"] in ("count", "gated") and r.get("exact") and r.get("wall_s") is not None:
            walls[(r["workload"], r["method"], r["arch"])].append(r["wall_s"])
    if walls:
        print("\n### end-to-end wall time (s, launch -> last record delivered; median)\n")
        print("| workload | method | " + " | ".join(arches) + " |\n|---|---|" + "---:|" * len(arches))
        for w in ("count", "gated"):
            for m in ORDER:
                if any((w, m, x) in walls for x in arches):
                    print(f"| {w} | {m} | " + " | ".join(
                        f"{statistics.median(walls[(w, m, x)]):.2f}" if (w, m, x) in walls else "--" for x in arches) + " |")


if __name__ == "__main__":
    main()
