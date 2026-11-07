#!/usr/bin/env python3
"""Where an inline send_log's time goes: runs the per-hit send_log case (hitcost_driver) and the
gated example with stdout to a FILE (as perf_ab does), optionally with sampler.py / threadstates.py
on the controller or the target (found by parent pid), and prints the targets' own timing.

  python logprof.py --bin build-x64\\Release [--modes plain,smp-ctl,smp-tgt,ts-ctl] [--calls N] [--reads R]
"""
import argparse, ctypes, ctypes.wintypes as W, json, os, subprocess, sys, time
from pathlib import Path

k32 = ctypes.WinDLL("kernel32", use_last_error=True)


class PE(ctypes.Structure):
    _fields_ = [("dwSize", W.DWORD), ("cntUsage", W.DWORD), ("th32ProcessID", W.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", W.DWORD), ("cntThreads", W.DWORD),
                ("th32ParentProcessID", W.DWORD), ("pcPriClassBase", ctypes.c_long), ("dwFlags", W.DWORD),
                ("szExeFile", ctypes.c_wchar * 260)]


def child_of(ppid, name, timeout=30):
    k32.CreateToolhelp32Snapshot.restype = W.HANDLE
    t0 = time.time()
    while time.time() - t0 < timeout:
        snap = k32.CreateToolhelp32Snapshot(2, 0)
        e = PE(); e.dwSize = ctypes.sizeof(e)
        ok = k32.Process32FirstW(snap, ctypes.byref(e)); found = None
        while ok:
            if e.th32ParentProcessID == ppid and e.szExeFile.lower() == name.lower():
                found = e.th32ProcessID; break
            ok = k32.Process32NextW(snap, ctypes.byref(e))
        k32.CloseHandle(snap)
        if found:
            return found
        time.sleep(0.005)


def run(cmd, mode, tgt_name, tmp, here, bindir, secs, delay=0.5):
    out, err = tmp / "out.jsonl", tmp / "err.txt"
    env = dict(os.environ, UHH_LOGPROF="1", TEMP=str(tmp), TMP=str(tmp))
    with open(out, "wb") as fo, open(err, "wb") as fe:
        t0 = time.perf_counter()
        p = subprocess.Popen([str(c) for c in cmd], stdout=fo, stderr=fe, env=env)
        prof = None
        if mode != "plain":
            pid = p.pid if mode.endswith("ctl") else child_of(p.pid, tgt_name)
            tool = "sampler.py" if mode.startswith("smp") else "threadstates.py"
            extra = ["--maps", str(bindir), "--top", "12", "--per-thread", "14"] if tool == "sampler.py" else []
            prof = subprocess.run([sys.executable, str(here / tool), "--pid", str(pid), "--seconds", str(secs),
                                   "--delay", str(delay)] + extra, capture_output=True, text=True).stdout
        rc = p.wait(); wall = time.perf_counter() - t0
    lines = open(out, "rb").read().splitlines()
    logs = sum(1 for l in lines if l.startswith(b'{"kind":"probe_log"'))
    objs = [json.loads(l) for l in lines if l.startswith(b"{") and not l.startswith(b'{"kind":"probe_log"')]
    lp = [l for l in open(err, errors="replace").read().splitlines() if l.startswith("LOGPROF")]
    return rc, wall, logs, objs, lp, prof


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True); ap.add_argument("--targets")
    ap.add_argument("--modes", default="plain,smp-ctl,smp-tgt")
    ap.add_argument("--cases", default="hit1,hit4,gated")
    ap.add_argument("--calls", type=int, default=2_000_000); ap.add_argument("--reads", type=int, default=50_000)
    ap.add_argument("--secs", type=float, default=1.5); ap.add_argument("--delay", type=float, default=0.5)
    a = ap.parse_args()
    b = Path(a.bin).resolve(); t = Path(a.targets).resolve() if a.targets else b
    here = Path(__file__).resolve().parent
    tmp = Path(os.environ.get("TEMP", ".")) / f"logprof_{os.getpid()}"; tmp.mkdir(parents=True, exist_ok=True)
    cases = {
        "hit1": ([b / "hitcost_driver.exe", "--backend", "inline", "--method", "send_log", "--", t / "hitcost_target.exe",
                  "--calls", a.calls, "--threads", 1, "--no-wait"], "hitcost_target.exe"),
        "hit4": ([b / "hitcost_driver.exe", "--backend", "inline", "--method", "send_log", "--", t / "hitcost_target.exe",
                  "--calls", a.calls // 4, "--threads", 4, "--no-wait"], "hitcost_target.exe"),
        "gated": ([b / "gated_config.exe", "--flag-backend", "breakpoint", "--read-backend", "inline",
                   "configparse.dll!ParseConfig+0x16", "ntdll.dll!NtReadVirtualMemory", "--", t / "probe_app.exe",
                   "--no-wait", "--helpers", 4, "--threads", 8, "--reads", a.reads], "probe_app.exe"),
    }
    for c in a.cases.split(","):
        cmd, tn = cases[c]
        for m in a.modes.split(","):
            rc, wall, logs, objs, lp, prof = run(cmd, m, tn, tmp, here, b, a.secs, a.delay)
            tg = next((o for o in objs if o.get("kind") in ("target", "app")), {})
            rep = next((o for o in objs if o.get("kind") == "probe_report"), {})
            n = tg.get("calls") or tg.get("successful_reads") or 0
            ns = tg.get("ns_per_call") or (tg.get("elapsed_ns", 0) / n if n else None)
            print(f"== {c} {m}: rc={rc} wall={wall:.2f}s logs={logs} ns_per_event={ns} dropped={rep.get('log_dropped')} "
                  f"interrupted={rep.get('callbacks_interrupted')} hits={rep.get('hits')}", flush=True)
            for l in lp:
                print("   " + l)
            if prof:
                print(prof, flush=True)


if __name__ == "__main__":
    main()
