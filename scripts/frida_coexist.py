#!/usr/bin/env python3
"""Frida and UHH instrumenting the SAME function at the same time.

    frida_coexist.py --app probe_app.exe --trace uhh_trace.exe --order frida_first|uhh_first
                     [--backend inline|breakpoint|hw] [--uhh-flag fallback-hw|allow-prehooked|none]
                     [--threads 2] [--reads 100] [--timeout 90]

Runs with an interpreter that has frida installed (16.5.9 on the test VM). probe_app is
started with reads enabled and waits at its gate; both tools attach (in the requested
order) and hook probe_app.exe!ReadThunk; the gate is released. Prints one JSON line:
  {"kind":"coexist","order":..,"total":..,"app_reads":..,"frida_hits":..,"uhh_hits":..,
   "uhh_backend":..,"prehook_reports":..,"uhh_exit":..,"app_exit":..,"error":..}
Correct coexistence: app_reads == frida_hits == uhh_hits == total, app_exit == 0.

Nothing here can hang:
  * probe_app's stdout is read by a thread (its helpers inherit the pipe, so EOF only comes
    when THEY exit -- never wait for it); every wait has a deadline;
  * uhh_trace writes to FILES, not pipes: a debugger blocked on a full, undrained pipe
    stops the target at its next debug event, which froze the whole test before;
  * the Frida count is delivered from the target's exit path (RtlExitUserProcess waits
    for our ack), not raced against the exit by an RPC;
  * a watchdog kills every child (probe_app tree, its helpers by pid, uhh_trace) and
    exits the interpreter if the overall deadline passes; children are killed on any
    failure path too.
"""
import argparse
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time

import frida

JS = """
let n = 0;
Interceptor.attach(Module.getExportByName('probe_app.exe', 'ReadThunk'), { onEnter() { n++; } });
// Deliver the final count from the exit path and hold the exit until the host has it.
Interceptor.attach(Module.getExportByName('ntdll.dll', 'RtlExitUserProcess'), {
  onEnter() { send({ final: n }); recv('ack', () => {}).wait(); }
});
rpc.exports = { count() { return n; } };
"""

CHILD_PIDS = set()        # everything we must kill on failure (probe_app, helpers, uhh_trace)


def kill_all():
    for pid in list(CHILD_PIDS):
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, timeout=30)


def emit(res):
    sys.stdout.write(json.dumps(res) + "\n")
    sys.stdout.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True)
    ap.add_argument("--trace", required=True)
    ap.add_argument("--order", choices=("frida_first", "uhh_first"), required=True)
    ap.add_argument("--backend", default="inline", choices=("inline", "breakpoint", "hw"))
    ap.add_argument("--uhh-flag", default="fallback-hw", choices=("fallback-hw", "allow-prehooked", "none"))
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--reads", type=int, default=100)
    ap.add_argument("--helpers", type=int, default=2)
    ap.add_argument("--timeout", type=float, default=90.0, help="overall deadline (s)")
    a = ap.parse_args()
    total = a.threads * a.reads
    res = {"kind": "coexist", "order": a.order, "backend": a.backend, "uhh_flag": a.uhh_flag, "total": total,
           "app_reads": None, "frida_hits": None, "uhh_hits": None, "uhh_backend": None, "prehook_reports": 0,
           "uhh_exit": None, "app_exit": None, "error": None, "uhh_stderr_tail": []}
    t0 = time.time()

    def left():
        return max(0.1, a.timeout - (time.time() - t0))

    def watchdog():
        res["error"] = (res["error"] or "") + f" watchdog: overall deadline {a.timeout}s passed"
        kill_all()
        emit(res)
        os._exit(3)
    dog = threading.Timer(a.timeout + 15, watchdog)
    dog.daemon = True
    dog.start()

    workdir = tempfile.mkdtemp(prefix="frida_coexist_")
    out_path, err_path = os.path.join(workdir, "uhh.out"), os.path.join(workdir, "uhh.err")
    res["uhh_err_path"] = err_path
    app = tracer = session = None
    lines = queue.Queue()
    app_lines = []
    final = {"n": None}
    final_evt = threading.Event()
    try:
        app = subprocess.Popen([a.app, "--helpers", str(a.helpers), "--threads", str(a.threads),
                                "--reads", str(a.reads), "--config", "reads_enabled=1"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        CHILD_PIDS.add(app.pid)

        def pump():
            for raw in iter(app.stdout.readline, b""):
                lines.put(raw.decode(errors="replace"))
        threading.Thread(target=pump, daemon=True).start()

        def until(marker, timeout):
            end = time.time() + timeout
            while time.time() < end:
                try:
                    line = lines.get(timeout=0.2)
                except queue.Empty:
                    if app.poll() is not None and lines.empty():
                        time.sleep(0.2)
                        if lines.empty():
                            return None
                    continue
                app_lines.append(line)
                if line.strip().startswith('{"kind":"helper"'):
                    try:
                        CHILD_PIDS.add(json.loads(line)["pid"])
                    except (ValueError, KeyError):
                        pass
                if marker in line:
                    return line
            return None

        if not until('"kind":"waiting"', min(30, left())):
            raise RuntimeError("probe_app never reached its gate")

        def start_frida():
            nonlocal session
            box = {}

            def go():
                try:
                    s = frida.attach(app.pid)
                    sc = s.create_script(JS)

                    def on_message(msg, _data):
                        if msg.get("type") == "send" and isinstance(msg.get("payload"), dict) \
                                and "final" in msg["payload"]:
                            final["n"] = msg["payload"]["final"]
                            final_evt.set()
                            try:
                                sc.post({"type": "ack"})
                            except Exception:
                                pass
                    sc.on("message", on_message)
                    sc.load()
                    box["s"], box["sc"] = s, sc
                except Exception as e:      # noqa: BLE001 -- reported in the result
                    box["e"] = repr(e)
            th = threading.Thread(target=go, daemon=True)
            th.start()
            th.join(min(30, left()))
            if th.is_alive():
                raise RuntimeError("frida attach/script load timed out")
            if "e" in box:
                raise RuntimeError("frida: " + box["e"])
            session = box["s"]
            res["_script"] = box["sc"]

        def start_uhh():
            nonlocal tracer
            cmd = [a.trace, "--backend", a.backend]
            if a.uhh_flag != "none":
                cmd.append("--" + a.uhh_flag)
            cmd += ["--attach", str(app.pid), "-p", "probe_app.exe!ReadThunk:xxxx"]
            with open(out_path, "wb") as fo, open(err_path, "wb") as fe:
                tracer = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=fo, stderr=fe)
            CHILD_PIDS.add(tracer.pid)
            # probe_attach returns only once every probe is in (attach holds the threads
            # until inline hooks are confirmed); a refused probe makes uhh_trace exit.
            end = time.time() + min(30, left())
            while time.time() < end:
                with open(out_path, "rb") as f:
                    if b'"kind":"attached"' in f.read():
                        return True
                if tracer.poll() is not None:
                    return False
                time.sleep(0.05)
            raise RuntimeError("uhh_trace did not attach in time")

        if a.order == "frida_first":
            start_frida()
            start_uhh()
        else:
            if not start_uhh():
                raise RuntimeError("uhh_trace exited before attaching")
            start_frida()

        app.stdin.write(b"\n")
        app.stdin.flush()
        if not until('"kind":"app"', left()):
            raise RuntimeError("probe_app did not finish its reads in time")
        if not final_evt.wait(min(20, left())):
            raise RuntimeError("frida final count never arrived")
        res["frida_hits"] = final["n"]
        try:
            res["app_exit"] = app.wait(timeout=min(30, left()))
        except subprocess.TimeoutExpired:
            raise RuntimeError("probe_app did not exit after its reads")
        try:
            res["uhh_exit"] = tracer.wait(timeout=min(30, left()))
        except subprocess.TimeoutExpired:
            raise RuntimeError("uhh_trace did not exit after the target did")
    except Exception as e:      # noqa: BLE001
        res["error"] = str(e)
        if app is not None:
            res["app_alive_at_error"] = app.poll() is None
        if tracer is not None:
            res["uhh_alive_at_error"] = tracer.poll() is None
    finally:
        res.pop("_script", None)
        if res["error"]:
            kill_all()
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
    app_objs = []
    for l in app_lines:
        try:
            app_objs.append(json.loads(l)) if l.strip().startswith("{") else None
        except ValueError:
            pass
    app_res = next((o for o in app_objs if o.get("kind") == "app"), {})
    res["app_reads"] = app_res.get("successful_reads")
    if not app_res:
        res["app_tail"] = [l.rstrip() for l in app_lines[-3:]]
    objs = []
    try:
        with open(out_path, encoding="utf-8", errors="replace") as f:
            for l in f:
                if l.startswith("{"):
                    try:
                        objs.append(json.loads(l))
                    except ValueError:
                        pass
        with open(err_path, encoding="utf-8", errors="replace") as f:
            res["uhh_stderr_tail"] = f.read().strip().splitlines()[-4:]
    except OSError:
        pass
    pr = next((o for o in objs if o.get("kind") == "probe" and o.get("location", "").endswith("!ReadThunk")), {})
    rep = next((o for o in objs if o.get("kind") == "probe_report"), {})
    res["uhh_hits"], res["uhh_backend"] = pr.get("hits"), pr.get("backend")
    res["uhh_error"] = rep.get("error")
    res["prehook_reports"] = sum(1 for o in objs if o.get("kind") == "prehook")
    emit(res)
    os._exit(0)     # never wait on frida's teardown


if __name__ == "__main__":
    main()
