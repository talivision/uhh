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
Frida (check_frida_coexist), Intel SDE 9.48 (check_cet_sde) and, on images without one, a
pre-14.40 msvcp140.dll (check_oldcrt) for the shards that need them. An OS component an image
does not ship at all (ABSENT, per image) is reported like a KNOWN failure: a warning.

A long unit can be SPLIT into parts (`check_realapps:ps-modules`), each its own unit: the
check is run with an environment variable narrowing it to the part's items (SPLIT).
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

# Seconds per check function on a windows-2022 runner (x64, x86), measured by CI run 42180029465
# (2026-11-06; a grouped unit's time sits on its selector). Refresh from `summarize`'s measured table.
EST = {
    "check_agent_crt": (1, 1), "check_agent_review": (1, 1), "check_agent_unwind": (3, 3), "check_attach": (9, 13), "check_attach_new": (0, 0),
    "check_blog_pwsh_attach": (20, 25), "check_blog_replicas": (12, 13), "check_breakage": (21, 21),
    "check_callconv": (1, 1), "check_callfunc_registry": (1, 1), "check_callorig": (65, 71),
    "check_callorig_hunt": (0, 0), "check_callorig_deep": (5, 5), "check_cdx_review": (1, 2), "check_cet": (6, 6), "check_cet_sde": (194, 1),
    "check_conformance": (1, 1), "check_crash_logs": (7, 13), "check_ctrl_review": (12, 23), "check_ctrl_warm": (25, 25), "check_ctrl_symload": (3, 3), "check_ctrl_pack_oom": (10, 10),
    "check_cxlib": (36, 73), "check_detach": (23, 37), "check_detours_retval": (1, 1),
    "check_detours_simple": (4, 4), "check_detours_stdin": (1, 1), "check_detours_traceapi": (2, 2),
    "check_detours_withdll": (35, 35), "check_dynwatch": (1, 1), "check_edgehunt": (22, 17),
    "check_emulated_sites": (73, 138), "check_entry_hold_threads": (1, 3), "check_famous_files": (14, 14),
    "check_famous_heap": (11, 20), "check_famous_loader": (1, 1), "check_famous_retval": (5, 5),
    "check_famous_tls": (2, 2), "check_forwarded_probe": (1, 1), "check_frida_coexist": (4, 9),
    "check_frida_parity": (1, 1), "check_gated_e2e": (343, 364), "check_gated_guardwin": (30, 30), "check_gated_filter": (5, 6), "check_gated_map": (3, 3),
    "check_gated_mem": (8, 7), "check_gated_off": (1, 1), "check_handle_map": (20, 21),
    "check_hotpatch_prologue": (1, 1), "check_hunt": (85, 420), "check_init_cutoff": (18, 18), "check_hw_once_slots": (6, 6),
    "check_inplace_shapes": (30, 27), "check_interrupt": (2, 2), "check_late_dll_worker": (1, 1),
    "check_latedll": (70, 64), "check_lifecycle": (380, 372), "check_log_throughput": (18, 23),
    "check_logs_controller_killed": (1, 1), "check_logs_format": (1, 1), "check_logs_order": (4, 9),
    "check_logs_stdout_closed": (1, 1), "check_logs_wedge": (4, 5), "check_memstress": (50, 71),
    "check_mix_matrix": (23, 32), "check_multithread_exact": (10, 11), "check_newapp_files": (1, 2),
    "check_newapp_flag": (5, 4), "check_newapp_reg": (2, 2), "check_ntdll_churn": (75, 111),
    "check_oldcrt": (2, 3), "check_patch_race": (166, 204), "check_portability": (8, 8),
    "check_powershell_detach": (40, 40), "check_slowreader_detach": (50, 50), "check_prehook_attach": (3, 3), "check_prehook_chain": (1, 1), "check_quickstart": (1, 1),
    "check_realapps:tasklist-m": (14, 360), "check_realapps:ps-modules-breakpoint": (230, 8),
    "check_realapps:ps-modules-hw": (140, 7), "check_realapps:ps-modules-inline": (35, 6),
    "check_realapps:ps-fileversion-breakpoint": (25, 200), "check_realapps:ps-fileversion-hw": (20, 190),
    "check_realapps:ps-fileversion-inline": (15, 190), "check_realapps:rest": (30, 33), "check_realworld": (14, 14), "check_realworld_targets": (0, 0),
    "check_refusals": (1, 1), "check_ret_probe": (5, 6), "check_shared_mix": (13, 14), "check_sidefx": (3, 10),
    "check_sites": (1, 1), "check_stacks": (1, 1), "check_stdout_forward": (18, 20),
    "check_stream_latency": (17, 17), "check_stream_live": (21, 44), "check_stream_order": (1, 1), "check_stream_filestall": (12, 12), "check_stream_filefail": (45, 45),
    "check_stream_sink_speed": (3, 8), "check_stream_volume": (149, 196), "check_symbols": (1, 1),
    "check_symbols_grammar": (0, 0), "check_transparency": (6, 9), "check_watchpoint": (2, 3),
}
DEFAULT_EST = 60
DEFAULT_SHARDS = {"x64": 7, "x86": 9}   # the critical path is one unit (x86 check_realapps)
# Documented by-design failures (docs/ROADMAP.md Hunter A A4-A8; HANDOFF's allowed list): still reported (warning
# annotation, step summary) but they do not fail the job. Runner-only failures are NOT listed here: they stay red
# until analysed (docs/ROADMAP.md "CI on GitHub Actions").
KNOWN = {
    "hunt-ctx-breakpoint": "A4: stale context reports a call twice (by design until fixed)",
    "hunt-ctx-hw": "A4: stale context reports a call twice (by design until fixed)",
    "hunt-starve-breakpoint": "A5: exit within 60 s flaky on breakpoint/hw until fixed",
    "hunt-starve-hw": "A5: exit within 60 s flaky on breakpoint/hw until fixed",
    "hunt-early-inline": "A6: by design",
    "hunt-owndr-hw": "A7: by design",
    "patch-race-unsafe": "the unsafe-patch race is probabilistic (proves the test can see it)",
}
# OS components a runner image does not ship (by image, from the workflow's CI_IMAGE): the check's skip_external()
# row (a FAIL, every CI unit being explicitly selected) is reported as a warning like KNOWN -- only that record, only
# on that image, and only when its detail is skip_external's "optional external dependency absent".
ABSENT = {
    "windows-2025": {
        "realapps-wmic": "WMIC is not installed on Server 2025 (realapps-ps-cim runs the same WMI process query)",
    },
}
ABSENT_TEXT = "optional external dependency absent"
# Units that need an external dependency the workflow installs on demand.
NEEDS = {"frida": {"check_frida_coexist"}, "sde": {"check_cet_sde"}, "oldmsvcp": {"check_oldcrt"}}
# Units run as several parts (`<selector>:<part>`), each a unit of its own: ENV narrows the check to the part's items
# (comma list), BENV (if the part names one) to one backend; the items None = "every item no other part names". The
# items are parsed from regress.py (FROM: the function listing them, one `("<item>", ...` tuple per line), so a new
# item lands in that part automatically.
_BK = ("breakpoint", "hw", "inline")
SPLIT = {
    "check_realapps": {"env": "UHH_REALAPPS_ONLY", "benv": "UHH_REALAPPS_BACKENDS", "from": "_realapps_scenarios",
                       "parts": {"tasklist-m": (["tasklist-m"], None),
                                 **{f"ps-modules-{b}": (["ps-modules"], b) for b in _BK},
                                 **{f"ps-fileversion-{b}": (["ps-fileversion"], b) for b in _BK},
                                 "rest": (None, None)}},
}
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


def split_items(sel):
    """{part: (items, backend or None)} of a SPLIT selector; every item of regress.py's list is covered."""
    sp = SPLIT[sel]
    src = REGRESS.read_text(encoding="utf-8")
    body = src[src.index(f"\ndef {sp['from']}("):]
    body = body[:body.index("\ndef ", 1)]
    items = re.findall(r'^\s+\("([\w-]+)",', body, re.M)
    named = {i for part, _ in sp["parts"].values() if part for i in part}
    if not items or any(i not in items for i in named):
        sys.exit(f"ci_shards: SPLIT {sel}: parts {sorted(named)} not all in {sp['from']}() items {items}")
    for i in named:   # an item split by backend must have every backend
        bks = {b for part, b in sp["parts"].values() if part and i in part}
        if None not in bks and bks != set(_BK):
            sys.exit(f"ci_shards: SPLIT {sel}: {i} split into backends {sorted(bks)}, not all of {_BK}")
    return {p: (v or [i for i in items if i not in named], b) for p, (v, b) in sp["parts"].items()}


def units():
    """[(selector, [members])] in suite order; opt-in tiers excluded; SPLIT units as their parts."""
    names = [n for n, opt in checks() if not opt]
    sel = [n for n in names if not any(o != n and o in n for o in names)]
    res = [(s, [n for n in names if s in n]) for s in sel]
    seen = [m for _, ms in res for m in ms]
    if sorted(seen) != sorted(names) or len(seen) != len(set(seen)):
        sys.exit(f"ci_shards: units do not partition the suite: {res}")
    out = []
    for s, ms in res:
        if s in SPLIT and ms == [s]:
            out += [(f"{s}:{p}", [f"{s}:{p}"]) for p in split_items(s)]
        else:
            out.append((s, ms))
    return out


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
                            "sde": bool(ms & NEEDS["sde"]),
                            "oldmsvcp": bool(ms & NEEDS["oldmsvcp"])})
    matrix = {"include": include}
    for e in include:
        print(f"{e['name']}: ~{e['est']}s  {e['units']}", file=sys.stderr)
    if a.github_output:
        with open(a.github_output, "a", encoding="utf-8") as f:
            f.write(f"matrix={json.dumps(matrix, separators=(',', ':'))}\n")
            f.write(f"arches={json.dumps(sorted({e['arch'] for e in include}))}\n")
    else:
        print(json.dumps(matrix, indent=1))


def chunks(lines, size=3500):
    """Annotation messages are cut at ~4 KB: split a list of lines into <= size-char messages."""
    out, cur = [], ""
    for line in lines:
        if cur and len(cur) + len(line) + 1 > size:
            out.append(cur); cur = ""
        cur += ("\n" if cur else "") + line
    if cur:
        out.append(cur)
    return out


def esc(s):
    """GitHub workflow-command message escaping."""
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def kill_tree(p):
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
    else:
        p.kill()


def cmd_run(a):
    # The runner's console is cp1252; regress.py prints UTF-8-only text (em dashes, arrows).
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    log = out / f"{a.name}.log"
    sels = [x for x in a.units.split(",") if x]
    res = {"name": a.name, "arch": a.arch, "units": [], "runner": os.environ.get("RUNNER_NAME", ""),
           "cpu": os.environ.get("RUNNER_CPU", ""),
           "sha": os.environ.get("GITHUB_SHA", "")}
    fail_re = re.compile(r"^\[\d\d:\d\d:\d\d\] FAIL ")
    absent = ABSENT.get(os.environ.get("CI_IMAGE", ""), {})
    expected = {}                                   # record -> why it may fail here (KNOWN, ABSENT)
    # CI_NOTICE_RE: result lines to publish as a notice annotation too (e.g. the cet-* rows of cet-hw)
    notice_re = re.compile(os.environ["CI_NOTICE_RE"]) if os.environ.get("CI_NOTICE_RE") else None
    noticed = []
    ok_re = re.compile(r"^(\d+)/(\d+) ok, (\d+) failed, (\d+) skipped")
    t_all = time.time()
    with open(log, "w", encoding="utf-8", errors="replace") as lf:
        for sel in sels:
            hdr = f"===== {a.name} {sel} start {time.strftime('%H:%M:%S')}"
            print(hdr, flush=True); lf.write(hdr + "\n"); lf.flush()
            t0 = time.time()
            u = {"unit": sel, "fails": [], "known": [], "ok_line": "", "rc": None, "timeout": False}
            only, uenv = sel, env
            if ":" in sel:                              # a SPLIT part: the check, narrowed by its env variable
                only, part = sel.split(":", 1)
                its, bk = split_items(only)[part]
                uenv = dict(env, **{SPLIT[only]["env"]: ",".join(its)})
                if bk:
                    uenv[SPLIT[only]["benv"]] = bk
                hdr2 = f"===== {SPLIT[only]['env']}={uenv[SPLIT[only]['env']]}" + (f" {SPLIT[only]['benv']}={bk}" if bk else "")
                print(hdr2, flush=True); lf.write(hdr2 + "\n")
            p = subprocess.Popen([sys.executable, "-u", str(REGRESS), "--bin", a.bin, "--only", only],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                 encoding="utf-8", errors="replace", bufsize=1, cwd=ROOT, env=uenv)
            timer = threading.Timer(a.unit_timeout, lambda: (u.update(timeout=True), kill_tree(p)))
            timer.daemon = True
            timer.start()
            for line in p.stdout:
                sys.stdout.write(line); lf.write(line)
                s = line.rstrip("\n")
                if notice_re and notice_re.search(s):
                    noticed.append(s[11:].strip())
                if fail_re.match(s):
                    rec = s[11:].split()[1] if len(s[11:].split()) > 1 else ""
                    why = KNOWN.get(rec) or (absent.get(rec) if ABSENT_TEXT in s else None)
                    if why:
                        expected[rec] = why
                    (u["known"] if why else u["fails"]).append(s[11:].strip())
                elif ok_re.match(s):
                    u["ok_line"] = s
            u["rc"] = p.wait()
            timer.cancel()
            u["secs"] = round(time.time() - t0, 1)
            m = ok_re.match(u["ok_line"])
            u.update(passed=int(m.group(1)), failed=int(m.group(3)), skipped=int(m.group(4))) if m else \
                u.update(passed=0, failed=0, skipped=0)
            u["ok"] = (u["rc"] == 0 or (u["rc"] == 1 and u["known"])) and not u["fails"] and not u["timeout"]
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
    lines = [f"### {a.name}: {'PASS' if res['ok'] else 'FAIL'} -- {res['ok_line']} in {res['secs']:.0f}s ({res['cpu']})", "",
             "| unit | result | secs | |", "|---|---|---|---|"]
    for u in res["units"]:
        why = "timeout" if u["timeout"] else ("" if u["ok"] else f"rc={u['rc']}")
        lines.append(f"| {u['unit']} | {'ok' if u['ok'] else 'FAIL'} | {u['secs']:.0f} | {u['ok_line'] or why} |")
    fl = [f for u in bad for f in (u["fails"] or [f"{u['unit']}: rc={u['rc']}{' timeout' if u['timeout'] else ''}"])]
    if bad:   # every FAIL line in full (the regress.py detail is the diagnosis)
        lines += ["", "Failures (full detail):", "```"] + fl + ["```"]
    known = [f for u in res["units"] for f in u["known"]]
    if known:
        lines += ["", "Known / absent on this image (not failing the job):", "```"] + \
                 [f"{x}  [{expected.get(x.split()[1], '')}]" for x in known] + ["```"]
    md = "\n".join(lines) + "\n"
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(md)
    # Annotations are readable through the public REST API without auth (check-run annotations).
    timing = " ".join(f"{u['unit'][6:]}={u['secs']:.0f}" for u in res["units"])
    print(f"::notice title={a.name} {'PASS' if res['ok'] else 'FAIL'} {res['ok_line']} {res['secs']:.0f}s::"
          + esc(f"cpu: {res['cpu']}\ntimes: {timing}"))
    if known:
        print(f"::warning title={a.name} known failures ({len(known)})::"
              + esc("\n".join(f"{x[:300]}  [{expected.get(x.split()[1], '')}]" for x in known)))
    for k, chunk in enumerate(chunks([x[:600] for x in noticed])):
        print(f"::notice title={a.name} selected rows ({k + 1})::" + esc(chunk))
    if bad:
        # Every FAIL line in full: one annotation per <= 3.5 KB chunk (GitHub cuts a message at ~4 KB), a longer line
        # split across consecutive chunks; at most 10 error annotations per step (the step summary and the log artifact
        # always have everything).
        parts = [x[i:i + 3400] for x in fl for i in range(0, max(len(x), 1), 3400)]
        cs = chunks(parts)
        for k, chunk in enumerate(cs[:10]):
            print(f"::error title={a.name} FAIL ({len(fl)}) part {k + 1}/{len(cs)}::" + esc(chunk))
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
    expected = [e["name"] for e in json.loads(a.matrix)["include"]] if a.matrix else []
    expected += sorted(n for n in results if n not in expected)      # e.g. cet-hw-x64
    rows, measured = [], {}
    for n in expected:
        r = results.get(n)
        if not r:
            rows.append(f"| {n} | NO RESULT (job failed before/without results) | | |")
            continue
        fails = [f for u in r["units"] if not u["ok"]
                 for f in (u["fails"] or [f"{u['unit']}: rc={u['rc']}{' timeout' if u['timeout'] else ''}"])]
        rows.append(f"| {n} | {'PASS' if r['ok'] else 'FAIL'} | {r['secs']:.0f} | {r['ok_line']} | {r.get('cpu', '')} |")
        for u in r["units"]:
            measured.setdefault(u["unit"], {})[r["arch"]] = u["secs"]
        for f in fails:
            rows.append(f"| | `{f[:300].replace('|', '/')}` | | |")
        for f in (f for u in r["units"] for f in u.get("known", [])):
            rows.append(f"| | known: `{f[:200].replace('|', '/')}` | | |")
    md = [f"## UHH regress on {os.environ.get('IMAGE', 'windows')}", "", "| shard | result | secs | counts | cpu |",
          "|---|---|---|---|---|"] + rows
    details = [(n, f) for n in expected if n in results for u in results[n]["units"] if not u["ok"]
               for f in (u["fails"] or [f"{u['unit']}: rc={u['rc']}{' timeout' if u['timeout'] else ''}"])]
    if details:
        md += ["", "### Failures (full detail)", "", "```"] + [f"[{n}] {f}" for n, f in details] + ["```"]
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
    for k, chunk in enumerate(chunks(rows)):
        print(f"::notice title={os.environ.get('IMAGE', '')} regress total {P}/{P + F} ok, {F} failed, {S} skipped "
              f"({k + 1})::" + esc(chunk))
    times = [f"{u[6:]}={v.get('x64', '-')}/{v.get('x86', '-')}" for u, v in sorted(measured.items())]
    for k, chunk in enumerate(chunks([" ".join(times[i:i + 8]) for i in range(0, len(times), 8)])):
        print(f"::notice title=unit times (s) unit=x64/x86 ({k + 1})::" + esc(chunk))
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
