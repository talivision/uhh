"""Diagnostic for the pwsh blog replica: attach uhh_trace to a running PowerShell for a
window, and print when each of the script's file opens happened (PowerShell side) vs
which were logged. usage: blog_pwsh_probe.py <bin> <backend> [window_ms]"""
import subprocess
import sys
import threading
import time
from pathlib import Path

bin_dir, bk = Path(sys.argv[1]), sys.argv[2]
window = sys.argv[3] if len(sys.argv) > 3 else "2500"
ps = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
script = ("Start-Sleep -Milliseconds 1; [Console]::Out.WriteLine('PSREADY'); [Console]::Out.Flush(); [void][Console]::In.ReadLine(); "
          "$sw=[Diagnostics.Stopwatch]::StartNew(); "
          "for($i=0;$i -lt 400;$i++){ $p=\"$env:TEMP\\uhhblog_ps_$($PID)_$i.txt\"; "
          "[IO.File]::WriteAllText($p, 'x'); [void][IO.File]::ReadAllText($p); [IO.File]::Delete($p); "
          "if($i % 25 -eq 0){ [Console]::Out.WriteLine(\"T $i $($sw.ElapsedMilliseconds)\") }; Start-Sleep -Milliseconds 10 }; "
          "[Console]::Out.WriteLine(\"PSDONE $($sw.ElapsedMilliseconds)\")")
t0 = time.perf_counter()
target = subprocess.Popen([str(ps), "-NoProfile", "-NonInteractive", "-Command", script], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, text=True)
out = []
def pump(pipe, sink, tag):
    for line in pipe:
        sink.append(f"{time.perf_counter() - t0:7.3f} {tag} {line.rstrip()}")
threading.Thread(target=pump, args=(target.stdout, out, "PS"), daemon=True).start()
while not any("PSREADY" in l for l in out):
    time.sleep(0.05)
import os
env = dict(os.environ)
if len(sys.argv) > 4:
    env["PROBE_TRACE"] = "1"
tr = subprocess.Popen([str(bin_dir / "uhh_trace.exe"), "--backend", bk, "--attach", str(target.pid), "--detach-after-ms",
                       window, "-p", "kernelbase.dll!CreateFileW:Wxxxx"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      text=True, env=env)
tout, terr = [], []
threading.Thread(target=pump, args=(tr.stdout, tout, "TR"), daemon=True).start()
threading.Thread(target=pump, args=(tr.stderr, terr, "ERR"), daemon=True).start()
while not any("probe: active" in l for l in terr):
    time.sleep(0.01)
out.append(f"{time.perf_counter() - t0:7.3f} -- gate released")
target.stdin.write("\n"); target.stdin.flush()
tr.wait(); target.wait()
time.sleep(0.5)
keys = ("probe:", "hold", "release", "remote", "agent", "install", "kick", "vet ")
for l in sorted(out + [l for l in terr if any(k in l for k in keys)][:40] +
                [l for l in tout if "uhhblog" in l][:3] + [l for l in tout if '"kind":"probe"' in l or "detached" in l],
                key=lambda x: float(x.split()[0])):
    print(l[:220])
print("logged opens:", sum("uhhblog" in l for l in tout))
if len(sys.argv) > 4:                     # PROBE_TRACE run: event histogram + stalls in the event stream
    import collections
    ev = [l for l in terr if " EV " in l or "ERR EV" in l]
    print("EV events:", len(ev), collections.Counter(l.split("code=")[1].split()[0] for l in ev if "code=" in l).most_common(8))
    ts = [(float(l.split()[0]), l) for l in terr]
    for (a, la), (b, lb) in zip(ts, ts[1:]):
        if b - a > 0.2:
            print(f"GAP {b - a:.3f}s after: {la[:160]}\n          before: {lb[:160]}")
