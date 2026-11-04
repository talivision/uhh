#!/usr/bin/env python3
"""Frida and UHH instrumenting the SAME function at the same time.

    frida_coexist.py --app probe_app.exe --trace uhh_trace.exe --order frida_first|uhh_first
                     [--backend inline|breakpoint|hw] [--threads 2] [--reads 100]

Runs with an interpreter that has frida installed (16.5.9 on the test VM). probe_app is
started with reads enabled and waits at its gate; both tools attach (in the requested
order) and hook probe_app.exe!ReadThunk; the gate is released. Prints one JSON line:
  {"kind":"coexist","order":..,"total":..,"app_reads":..,"frida_hits":..,"uhh_hits":..,
   "uhh_backend":..,"prehook_reports":..,"app_exit":..}
Correct coexistence: app_reads == frida_hits == uhh_hits == total, app_exit == 0.
"""
import argparse
import json
import subprocess
import time

import frida

JS = """
let n = 0;
Interceptor.attach(Module.getExportByName('probe_app.exe', 'ReadThunk'), { onEnter() { n++; } });
rpc.exports = { count() { return n; } };
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True)
    ap.add_argument("--trace", required=True)
    ap.add_argument("--order", choices=("frida_first", "uhh_first"), required=True)
    ap.add_argument("--backend", default="inline")
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--reads", type=int, default=100)
    a = ap.parse_args()
    helpers = 2
    total = helpers and a.threads * a.reads
    app = subprocess.Popen([a.app, "--helpers", str(helpers), "--threads", str(a.threads), "--reads", str(a.reads),
                            "--config", "reads_enabled=1"],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    app_lines = []
    # wait until the target is at its gate
    while True:
        line = app.stdout.readline().decode(errors="replace")
        if not line:
            break
        app_lines.append(line)
        if '"waiting"' in line:
            break
    tracer = None
    session = script = None

    def start_frida():
        nonlocal session, script
        session = frida.attach(app.pid)
        script = session.create_script(JS)
        script.load()

    def start_uhh():
        nonlocal tracer
        tracer = subprocess.Popen([a.trace, "--backend", a.backend, "--attach", str(app.pid),
                                   "-p", "probe_app.exe!ReadThunk:xxxx"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(3.0)                       # attach + agent install (async after attach)

    if a.order == "frida_first":
        start_frida(); start_uhh()
    else:
        start_uhh(); start_frida()
    frida_hits = None
    app.stdin.write(b"\n"); app.stdin.flush()
    # read the app's remaining output while it runs; query Frida before it exits
    deadline = time.time() + 120
    while time.time() < deadline:
        line = app.stdout.readline().decode(errors="replace")
        if not line:
            break
        app_lines.append(line)
        if '"kind":"app"' in line:
            try:
                frida_hits = script.exports_sync.count()
            except Exception:
                pass
            break          # the helpers inherit this pipe: EOF only comes when they exit
    app.wait(timeout=60)
    try:
        out, err = tracer.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        tracer.kill()
        out, err = tracer.communicate()
    objs = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
    app_objs = [json.loads(l) for l in app_lines if l.strip().startswith("{")]
    app_res = next((o for o in app_objs if o.get("kind") == "app"), {})
    pr = next((o for o in objs if o.get("kind") == "probe" and o.get("location", "").endswith("!ReadThunk")), {})
    print(json.dumps({"kind": "coexist", "order": a.order, "total": total,
                      "app_reads": app_res.get("successful_reads"), "frida_hits": frida_hits,
                      "uhh_hits": pr.get("hits"), "uhh_backend": pr.get("backend"),
                      "prehook_reports": sum(1 for o in objs if o.get("kind") == "prehook"),
                      "app_exit": app.returncode, "uhh_stderr_tail": err.strip().splitlines()[-3:]}))


if __name__ == "__main__":
    main()
