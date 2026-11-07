#!/usr/bin/env python3
"""Controller CPU while an instrumented target is IDLE (the log drainer's idle cost).

  python bench\\perfab\\idle_cpu.py --side NAME=<Release dir> [--side ...] --targets <Release dir>
         [--seconds 10] [--rounds 3]

hitcost_driver --backend inline --method send_log on hitcost_target, which blocks on stdin
before its calls: once the probe is active the target is idle, and the driver's CPU cycles
over --seconds is what the controller burns waiting. Then one
byte on stdin lets it run its calls (1000) and exit; every log must arrive. Reported in CPU cycles
(QueryProcessCycleTime) per second of idle.
"""
import argparse, ctypes, json, statistics, subprocess, time
from ctypes import wintypes

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = wintypes.HANDLE


def cycles(pid):
    """CPU cycles the process's threads ran (QueryProcessCycleTime: exact, unlike the
    tick-sampled GetProcessTimes, which charges a thread that runs microseconds per wake-up
    nothing at all)."""
    h = k32.OpenProcess(0x1000, False, pid)        # PROCESS_QUERY_LIMITED_INFORMATION
    c = ctypes.c_uint64()
    k32.QueryProcessCycleTime(h, ctypes.byref(c))
    k32.CloseHandle(h)
    return c.value


def one(rel, targets, seconds):
    p = subprocess.Popen([rel + r"\hitcost_driver.exe", "--backend", "inline", "--method", "send_log", "--",
                          targets + r"\hitcost_target.exe", "--calls", "1000"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.time() + 30
    while time.time() < deadline:                  # the probe line comes once the hook is live
        line = p.stderr.readline()
        if not line or b"active" in line:
            break
    time.sleep(1.0)
    c0 = cycles(p.pid); t0 = time.perf_counter()
    time.sleep(seconds)
    c1 = cycles(p.pid); t1 = time.perf_counter()
    p.stdin.write(b"x"); p.stdin.flush(); p.stdin.close()
    out, _ = p.communicate(timeout=60)
    logs = out.count(b'{"kind":"probe_log"')
    return {"mcycles_per_s": (c1 - c0) / 1e6 / (t1 - t0), "logs": logs, "ok": p.returncode == 0 and logs == 1000}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--side", action="append", required=True)
    ap.add_argument("--targets", required=True)
    ap.add_argument("--seconds", type=float, default=10)
    ap.add_argument("--rounds", type=int, default=3)
    a = ap.parse_args()
    sides = [s.split("=", 1) for s in a.side]
    res = {n: [] for n, _ in sides}
    for r in range(a.rounds):
        for n, d in (sides if r % 2 == 0 else sides[::-1]):
            o = one(d, a.targets, a.seconds)
            res[n].append(o)
            print(json.dumps({"round": r, "side": n, **o}), flush=True)
    for n, rows in res.items():
        v = [x["mcycles_per_s"] for x in rows]
        print(f"idle_cpu {n}: median {statistics.median(v):.3f} Mcycles per s [{min(v):.3f}..{max(v):.3f}] "
              f"ok {sum(x['ok'] for x in rows)}/{len(rows)}", flush=True)


if __name__ == "__main__":
    main()
