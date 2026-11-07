#!/usr/bin/env python3
"""Run a command and print each of its stderr/stdout lines prefixed with ms since start
(where a launch spends its time: PROBE_TRACE=1 lines are timestamped as they arrive).

  python bench\\perfab\\stamp.py <cmd...>
"""
import subprocess, sys, threading, time

t0 = time.perf_counter()
p = subprocess.Popen(sys.argv[1:], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def pump(stream, tag):
    for line in iter(stream.readline, b""):
        print(f"{(time.perf_counter() - t0) * 1000:9.1f} {tag} {line.decode('utf-8', 'replace').rstrip()[:200]}", flush=True)


ts = [threading.Thread(target=pump, args=(p.stdout, "o")), threading.Thread(target=pump, args=(p.stderr, "e"))]
for t in ts: t.start()
rc = p.wait()
for t in ts: t.join()
print(f"{(time.perf_counter() - t0) * 1000:9.1f} exit rc={rc}")
