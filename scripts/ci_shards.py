#!/usr/bin/env python3
"""GitHub Actions sharding for scripts/regress.py (.github/workflows/windows.yml).

    ci_shards.py units                                  list the units (selector -> check functions)
    ci_shards.py matrix [--only a,b] [--arches x64,x86] [--shards N] [--github-output FILE]
    ci_shards.py run --arch x64 --units check_a,check_b --bin build-x64/Release --out ci-logs --name x64-3
    ci_shards.py summarize --dir all-logs [--matrix JSON]

A UNIT is one `regress.py --only <selector>` run. --only matches SUBSTRINGS of check function
names, so `--only check_attach` also runs check_attach_new: a unit's selector is a check name
that contains no other check name, and the unit is every check whose name contains it
(check_cet = check_cet + check_cet_sde). The units partition the suite exactly (verified on
every `matrix`). The check list is parsed from regress.py main(); the opt-in tiers (calls
nested under `if args.<tier>`: --volume-reads, --bigapps, --soak-minutes) are excluded.

Running one regress.py per unit times every unit; the times feed EST below (seconds on a
GitHub windows-2022 runner, x64 / x86), which `matrix` packs into balanced shards (longest
first). `summarize` prints an updated EST from a run's measured times. A check missing from
EST gets DEFAULT_EST.

Note the --only semantics this implies: skip_external() is a FAIL for an explicitly selected
check, so an optional external dependency absent on the runner (Frida, Intel SDE, a system
program) FAILS here where the unselected full suite would SKIP it. The workflow installs
Frida (check_frida_coexist) and Intel SDE 9.48 (check_cet_sde) for the shards that need them.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGRESS = ROOT / "scripts" / "regress.py"

# Seconds per check function on a windows-2022 runner (x64, x86). Seeded from the Windows 10 VM's
# full run (2026-11-06) and refreshed from CI runs (`summarize` prints the measured table).
EST = {
    "check_sites": (2, 2), "check_gated_off": (3, 4), "check_mix_matrix": (16, 18),
    "check_multithread_exact": (5, 8), "check_log_throughput": (55, 75), "check_stream_volume": (100, 150),
    "check_stream_sink_speed": (10, 15), "check_stream_live": (15, 26), "check_stream_latency": (17, 17),
    "check_stream_order": (5, 8), "check_attach": (4, 4), "check_attach_new": (4, 4), "check_breakage": (21, 22),
    "check_frida_parity": (2, 2), "check_watchpoint": (2, 2), "check_dynwatch": (2, 2), "check_realworld": (8, 8),
    "check_realworld_targets": (12, 22), "check_conformance": (4, 4), "check_prehook_attach": (2, 2),
    "check_memstress": (47, 80), "check_symbols": (3, 3), "check_symbols_grammar": (20, 20),
    "check_frida_coexist": (60, 60), "check_sidefx": (25, 37), "check_detach": (27, 35),
    "check_ntdll_churn": (120, 130), "check_patch_race": (60, 68), "check_emulated_sites": (38, 65),
    "check_ret_probe": (6, 6), "check_gated_map": (6, 7), "check_gated_filter": (5, 5), "check_gated_mem": (4, 5),
    "check_callorig": (2, 2), "check_callorig_hunt": (50, 58), "check_portability": (17, 18),
    "check_callconv": (3, 3), "check_agent_review": (2, 2), "check_agent_crt": (1, 1),
    "check_callfunc_registry": (1, 1), "check_transparency": (7, 10), "check_interrupt": (2, 2),
    "check_oldcrt": (2, 2), "check_cet": (6, 6), "check_cet_sde": (230, 2), "check_shared_mix": (8, 12),
    "check_handle_map": (7, 17), "check_forwarded_probe": (2, 2), "check_crash_logs": (16, 18),
    "check_refusals": (1, 1), "check_hotpatch_prologue": (2, 2), "check_famous_heap": (8, 16),
    "check_famous_files": (16, 16), "check_famous_tls": (5, 5), "check_famous_loader": (3, 3),
    "check_famous_retval": (3, 3), "check_edgehunt": (28, 22), "check_detours_simple": (2, 2),
    "check_detours_traceapi": (5, 5), "check_detours_withdll": (35, 36), "check_detours_retval": (2, 2),
    "check_detours_stdin": (2, 2), "check_hunt": (175, 725), "check_stdout_forward": (16, 18),
    "check_blog_replicas": (15, 15), "check_blog_pwsh_attach": (25, 25), "check_entry_hold_threads": (2, 3),
    "check_late_dll_worker": (3, 3), "check_latedll": (47, 68), "check_hw_once_slots": (5, 5),
    "check_prehook_chain": (5, 5), "check_stacks": (10, 30), "check_realapps": (455, 1240),
    "check_ctrl_review": (16, 60), "check_cdx_review": (3, 3), "check_newapp_files": (2, 3),
    "check_newapp_flag": (2, 3), "check_newapp_reg": (2, 3), "check_logs_format": (2, 4),
    "check_logs_order": (2, 4), "check_logs_wedge": (2, 4), "check_logs_controller_killed": (2, 3),
    "check_logs_stdout_closed": (2, 3), "check_inplace_shapes": (36, 45), "check_lifecycle": (355, 335),
    "check_cxlib": (60, 60), "check_quickstart": (1, 1),
}
DEFAULT_EST = 60
DEFAULT_SHARDS = {"x64": 9, "x86": 10}
# Units that need an external dependency the workflow installs on demand.
NEEDS = {"frida": {"check_frida_coexist"}, "sde": {"check_cet_sde"}}
ARCH_IDX = {"x64": 0, "x86": 1}


def checks():
    """(name, opt_in) for every `if want(check_x)` in regress.py main(), in order."""
    src = REGRESS.read_text(encoding="utf-8")
    body = src[src.index("\ndef main("):]
    out = []
    for m in re.finditer(r"^( +)if want\((check_\w+)\)", body, re.M):
        out.append((m.group(2), len(m.group(1)) > 4))
    if not out:
        sys.exit("ci_shards: no `if want(check_*)` calls found in regress.py main()")
    return out


def units():
    """[(selector, [members])] in suite order; opt-in tiers excluded."""
    names = [n for n, opt in checks() if not opt]
    sel = [n for n in names if not any(o != n and o in n for o in names)]
    res = [(s, [n for n in names if s in n]) for s in sel]
    seen = [m for _, ms in res for m in ms]
    if sorted(seen) != sorted(names) or len(seen) != len(set(seen)):
        sys.exit(f"ci_shards: units do not partition the suite: {res}")
    return res


def est(members, arch):
    return sum(EST.get(m, (DEFAULT_EST, DEFAULT_EST))[ARCH_IDX[arch]] for m in members)


def cmd_units(_a):
    for s, ms in units():
        print(f"{s:32} x64 {est(ms, 'x64'):5}s  x86 {est(ms, 'x86'):5}s  {' '.join(ms)}")
    unknown = sorted({m for _, ms in units() for m in ms} - set(EST))
    if unknown:
        print(f"no estimate (default {DEFAULT_EST}s): {unknown}")


def cmd_matrix(a):
    us = units()
    only = [x.strip() for x in (a.only or "").split(",") if x.strip()]
    if only:
        hy = lambda n: (n, n.replace("_", "-"))
        us = [(s, ms) for s, ms in us if any(o in v for o in only for m in ms for v in hy(m))]
        if not us:
            sys.exit(f"ci_shards: --only {only} selects no check")
    unknown = sorted({m for _, ms in us for m in ms} - set(EST))
    if unknown:
        print(f"::warning title=ci_shards::no runtime estimate for {', '.join(unknown)} (using {DEFAULT_EST}s)")
    include = []
    for arch in [x.strip() for x in a.arches.split(",") if x.strip()]:
        n = int(a.shards) or DEFAULT_SHARDS[arch]
        n = max(1, min(n, len(us)))
        bins = [[0, []] for _ in range(n)]
        for s, ms in sorted(us, key=lambda u: -est(u[1], arch)):
            b = min(bins, key=lambda b: b[0])
            b[0] += est(ms, arch)
            b[1].append(s)
        order = {s: i for i, (s, _) in enumerate(us)}
        members = dict(us)
        for i, (t, sels) in enumerate(sorted((b for b in bins if b[1]), key=lambda b: -b[0])):
            sels.sort(key=order.get)
            ms = {m for s in sels for m in members[s]}
            include.append({"arch": arch, "shard": i + 1, "name": f"{arch}-{i + 1:02d}",
                            "units": ",".join(sels), "est": t,
                            "frida": bool(ms & NEEDS["frida"]),
                            # x86 too: check_cet_sde looks for SDE before its x86 SKIP
                            "sde": bool(ms & NEEDS["sde"])})
    matrix = {"include": include}
    for e in include:
        print(f"{e['name']}: ~{e['est']}s  {e['units']}", file=sys.stderr)
    if a.github_output:
        with open(a.github_output, "a", encoding="utf-8") as f:
            f.write(f"matrix={json.dumps(matrix, separators=(',', ':'))}\n")
            f.write(f"arches={json.dumps(sorted({e['arch'] for e in include}))}\n")
    else:
        print(json.dumps(matrix, indent=1))


def esc(s):
    """GitHub workflow-command message escaping."""
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def kill_tree(p):
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
    else:
        p.kill()


def cmd_run(a):
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    log = out / f"{a.name}.log"
    sels = [x for x in a.units.split(",") if x]
    res = {"name": a.name, "arch": a.arch, "units": [], "runner": os.environ.get("RUNNER_NAME", ""),
           "sha": os.environ.get("GITHUB_SHA", "")}
    fail_re = re.compile(r"^\[\d\d:\d\d:\d\d\] FAIL ")
    ok_re = re.compile(r"^(\d+)/(\d+) ok, (\d+) failed, (\d+) skipped")
    t_all = time.time()
    with open(log, "w", encoding="utf-8", errors="replace") as lf:
        for sel in sels:
            hdr = f"===== {a.name} {sel} start {time.strftime('%H:%M:%S')}"
            print(hdr, flush=True); lf.write(hdr + "\n"); lf.flush()
            t0 = time.time()
            u = {"unit": sel, "fails": [], "ok_line": "", "rc": None, "timeout": False}
            p = subprocess.Popen([sys.executable, "-u", str(REGRESS), "--bin", a.bin, "--only", sel],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                 encoding="utf-8", errors="replace", bufsize=1, cwd=ROOT)
            timer = threading.Timer(a.unit_timeout, lambda: (u.update(timeout=True), kill_tree(p)))
            timer.daemon = True
            timer.start()
            for line in p.stdout:
                sys.stdout.write(line); lf.write(line)
                s = line.rstrip("\n")
                if fail_re.match(s):
                    u["fails"].append(s[11:].strip())
                elif ok_re.match(s):
                    u["ok_line"] = s
            u["rc"] = p.wait()
            timer.cancel()
            u["secs"] = round(time.time() - t0, 1)
            m = ok_re.match(u["ok_line"])
            u.update(passed=int(m.group(1)), failed=int(m.group(3)), skipped=int(m.group(4))) if m else \
                u.update(passed=0, failed=0, skipped=0)
            u["ok"] = u["rc"] == 0 and not u["fails"] and not u["timeout"]
            tail = f"===== {a.name} {sel} end rc={u['rc']} {u['secs']}s" + (" UNIT TIMEOUT" if u["timeout"] else "") \
                   + f" | {u['ok_line']}"
            print(tail, flush=True); lf.write(tail + "\n"); lf.flush()
            res["units"].append(u)
    res["secs"] = round(time.time() - t_all, 1)
    res["ok"] = all(u["ok"] for u in res["units"])
    P = sum(u["passed"] for u in res["units"]); F = sum(u["failed"] for u in res["units"])
    S = sum(u["skipped"] for u in res["units"])
    res["ok_line"] = f"{P}/{P + F} ok, {F} failed, {S} skipped"
    (out / f"{a.name}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")

    bad = [u for u in res["units"] if not u["ok"]]
    lines = [f"### {a.name}: {'PASS' if res['ok'] else 'FAIL'} -- {res['ok_line']} in {res['secs']:.0f}s", "",
             "| unit | result | secs | |", "|---|---|---|---|"]
    for u in res["units"]:
        why = "timeout" if u["timeout"] else ("" if u["ok"] else f"rc={u['rc']}")
        lines.append(f"| {u['unit']} | {'ok' if u['ok'] else 'FAIL'} | {u['secs']:.0f} | {u['ok_line'] or why} |")
    if bad:
        lines += ["", "```"] + [f for u in bad for f in (u["fails"] or [f"{u['unit']}: rc={u['rc']}"
                                                                        f"{' timeout' if u['timeout'] else ''}"])] + ["```"]
    md = "\n".join(lines) + "\n"
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(md)
    # Annotations are readable through the public REST API without auth (check-run annotations).
    timing = " ".join(f"{u['unit'][6:]}={u['secs']:.0f}" for u in res["units"])
    print(f"::notice title={a.name} {'PASS' if res['ok'] else 'FAIL'} {res['ok_line']} {res['secs']:.0f}s::"
          + esc(f"times: {timing}"))
    if bad:
        fl = [f for u in bad for f in (u["fails"] or [f"{u['unit']}: rc={u['rc']}{' timeout' if u['timeout'] else ''}"])]
        print(f"::error title={a.name} FAIL ({len(fl)})::" + esc("\n".join(x[:400] for x in fl)[:30000]))
    sys.exit(0 if res["ok"] else 1)


def cmd_summarize(a):
    results = {}
    for p in Path(a.dir).rglob("*.json"):
        try:
            r = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(r, dict) and "units" in r and "name" in r:
            results[r["name"]] = r
    expected = [e["name"] for e in json.loads(a.matrix)["include"]] if a.matrix else sorted(results)
    rows, measured = [], {}
    for n in expected:
        r = results.get(n)
        if not r:
            rows.append(f"| {n} | NO RESULT (job failed before/without results) | | |")
            continue
        fails = [f for u in r["units"] if not u["ok"]
                 for f in (u["fails"] or [f"{u['unit']}: rc={u['rc']}{' timeout' if u['timeout'] else ''}"])]
        rows.append(f"| {n} | {'PASS' if r['ok'] else 'FAIL'} | {r['secs']:.0f} | {r['ok_line']} |")
        for u in r["units"]:
            measured.setdefault(u["unit"], {})[r["arch"]] = u["secs"]
        for f in fails:
            rows.append(f"| | `{f[:300].replace('|', '/')}` | | |")
    md = ["## UHH regress on windows-2022", "", "| shard | result | secs | counts |", "|---|---|---|---|"] + rows
    md += ["", "### Measured unit times (s)", "", "| unit | x64 | x86 |", "|---|---|---|"]
    for unit in sorted(measured, key=lambda k: -max(measured[k].values())):
        md.append(f"| {unit} | {measured[unit].get('x64', '')} | {measured[unit].get('x86', '')} |")
    text = "\n".join(md) + "\n"
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)
    total = [results[n] for n in expected if n in results]
    P = sum(u["passed"] for r in total for u in r["units"]); F = sum(u["failed"] for r in total for u in r["units"])
    S = sum(u["skipped"] for r in total for u in r["units"])
    print(f"::notice title=regress total {P}/{P + F} ok, {F} failed, {S} skipped::"
          + esc("\n".join(r for r in rows)[:30000]))
    print("::notice title=unit times (s) unit=x64/x86::"
          + esc(" ".join(f"{u[6:]}={v.get('x64', '-')}/{v.get('x86', '-')}" for u, v in sorted(measured.items()))))
    if a.est_out:
        Path(a.est_out).write_text(json.dumps(measured, indent=1, sort_keys=True), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("units")
    m = sp.add_parser("matrix")
    m.add_argument("--only", default="")
    m.add_argument("--arches", default="x64,x86")
    m.add_argument("--shards", default="0", help="shards per arch; 0 = DEFAULT_SHARDS")
    m.add_argument("--github-output", default="")
    r = sp.add_parser("run")
    r.add_argument("--arch", required=True, choices=list(ARCH_IDX))
    r.add_argument("--units", required=True)
    r.add_argument("--bin", required=True)
    r.add_argument("--out", default="ci-logs")
    r.add_argument("--name", required=True)
    r.add_argument("--unit-timeout", type=int, default=45 * 60)
    s = sp.add_parser("summarize")
    s.add_argument("--dir", required=True)
    s.add_argument("--matrix", default="")
    s.add_argument("--est-out", default="")
    a = ap.parse_args()
    {"units": cmd_units, "matrix": cmd_matrix, "run": cmd_run, "summarize": cmd_summarize}[a.cmd](a)


if __name__ == "__main__":
    main()
