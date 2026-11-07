#!/usr/bin/env python3
"""Where a short UHH run spends its wall time (launch, run, teardown).

  python bench\\perfab\\phases.py [--repeat N] <cmd...>

Like stamp.py, but for runs that log a lot: probe_log lines on stdout are counted, not
printed (only the first and the last one's arrival), every other line is printed with the ms
since the command started. With UHH_BENCH_PHASES=1 in the environment the controller stamps
its lifecycle phases on stderr ("  phase <QPC ms> <name>"); those are printed as ms since the
command started too (the QPC of this process and of the controller are the same clock).
--repeat runs the command N times and prints, per phase, the median offset.
"""
import ctypes, statistics, subprocess, sys, threading, time

k32 = ctypes.windll.kernel32 if sys.platform == "win32" else None


def qpc_ms():
    c, f = ctypes.c_int64(), ctypes.c_int64()
    k32.QueryPerformanceCounter(ctypes.byref(c)); k32.QueryPerformanceFrequency(ctypes.byref(f))
    return c.value * 1000.0 / f.value


def run(cmd, quiet):
    t0 = time.perf_counter(); q0 = qpc_ms()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    marks, logs = [], {"n": 0, "first": None, "last": None}
    lock = threading.Lock()

    def pump(stream, tag):
        for raw in iter(stream.readline, b""):
            ms = (time.perf_counter() - t0) * 1000
            line = raw.decode("utf-8", "replace").rstrip()
            if line.startswith('{"kind":"probe_log"'):
                with lock:
                    logs["n"] += 1
                    logs["first"] = logs["first"] if logs["first"] is not None else ms
                    logs["last"] = ms
                continue
            name = None
            if line.startswith("  phase "):
                parts = line.split(None, 3)
                try:
                    ms = float(parts[1]) - q0; name = parts[2]
                except (IndexError, ValueError):
                    pass
            with lock:
                marks.append((ms, name or (tag + " " + line[:60])))
            if not quiet:
                print(f"{ms:9.1f} {tag} {line[:160]}", flush=True)

    ts = [threading.Thread(target=pump, args=(p.stdout, "o")), threading.Thread(target=pump, args=(p.stderr, "e"))]
    for t in ts: t.start()
    rc = p.wait()
    for t in ts: t.join()
    end = (time.perf_counter() - t0) * 1000
    if logs["n"]:
        marks += [(logs["first"], "first_probe_log"), (logs["last"], "last_probe_log")]
    marks.append((end, "process_exit"))
    if not quiet:
        print(f"{end:9.1f} exit rc={rc} probe_log={logs['n']} first={logs['first']} last={logs['last']}", flush=True)
    return sorted(marks), rc


def main():
    args = sys.argv[1:]
    n = 1
    if args[:1] == ["--repeat"]:
        n = int(args[1]); args = args[2:]
    runs = []
    for i in range(n):
        marks, rc = run(args, quiet=n > 1)
        runs.append(dict((name, ms) for ms, name in marks if not name.startswith(("o ", "e "))))
        if n > 1:
            print(f"run {i}: rc={rc} exit={runs[-1].get('process_exit', 0):.1f} ms", flush=True)
    if n > 1:
        names = sorted({k for r in runs for k in r}, key=lambda k: statistics.median([r[k] for r in runs if k in r]))
        for k in names:
            v = [r[k] for r in runs if k in r]
            print(f"{statistics.median(v):9.1f} [{min(v):.1f}..{max(v):.1f}] {k}", flush=True)


if __name__ == "__main__":
    main()
