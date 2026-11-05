#!/usr/bin/env python3
"""Can the UHH controller instrument a CREATE_SUSPENDED process before its first instruction?

    suspended_attach.py --bin build-x64/Release [--trials 3]

The building block of "intercept CreateProcess, add CREATE_SUSPENDED, probe_attach, resume"
(docs/child-processes.md), with the public API unchanged: this script creates probe_app
SUSPENDED (as a parent would, through a CreateProcess hook), runs `uhh_trace --attach <pid>`
with a probe on probe_app.exe's ENTRY POINT and one on ntdll!NtReadVirtualMemory, waits for
both "probe: active" lines, and only then resumes the main thread. Per backend it reports:
  - attach_to_active_ms: from starting uhh_trace to the last "probe: active" line,
  - entry_hits (must be 1: the very first instruction of the image's entry was caught),
  - read_hits == logs == probe_app's successful_reads (nothing before the probes was missed),
  - probe_app's exit code and checksum (unchanged).
"""
import argparse
import ctypes
import json
import msvcrt
import os
import struct
import subprocess
import sys
import tempfile
import threading
import time
from ctypes import wintypes
from pathlib import Path


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


K32 = ctypes.WinDLL("kernel32", use_last_error=True)
K32.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
                               wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
                               ctypes.POINTER(PROCESS_INFORMATION)]
K32.ResumeThread.argtypes = [wintypes.HANDLE]
K32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
K32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
K32.CloseHandle.argtypes = [wintypes.HANDLE]
K32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
CREATE_SUSPENDED = 0x4


def entry_rva(path):
    b = Path(path).read_bytes()
    nt = struct.unpack_from("<I", b, 0x3C)[0]
    return struct.unpack_from("<I", b, nt + 0x28)[0]


def create_suspended(exe, args, out_handle):
    si = STARTUPINFOW(); si.cb = ctypes.sizeof(si); si.dwFlags = 0x100   # STARTF_USESTDHANDLES
    si.hStdInput = None; si.hStdOutput = out_handle; si.hStdError = out_handle
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(exe)] + args))
    if not K32.CreateProcessW(str(exe), cmd, None, None, True, CREATE_SUSPENDED, None, None, ctypes.byref(si),
                              ctypes.byref(pi)):
        raise OSError(ctypes.get_last_error(), "CreateProcessW")
    return pi


def trial(bin_dir, backend, threads, reads, running=False):
    app_exe = bin_dir / "probe_app.exe"
    rva = entry_rva(app_exe)
    out = tempfile.NamedTemporaryFile(delete=False, suffix=".out"); out.close()
    args = ["--helpers", "4", "--threads", str(threads), "--reads", str(reads), "--config", "reads_enabled=1"]
    gated = None
    if running:      # the comparison: an ordinary attach to a process already waiting at its gate
        gated = subprocess.Popen([str(app_exe)] + args, stdin=subprocess.PIPE, stdout=open(out.name, "wb"),
                                 stderr=subprocess.STDOUT)
        for _ in range(3000):
            if '"waiting"' in Path(out.name).read_text(errors="replace"):
                break
            time.sleep(0.01)
        pid = gated.pid
    else:
        f = open(out.name, "wb")
        h = msvcrt.get_osfhandle(f.fileno()); os.set_handle_inheritable(h, True)
        pi = create_suspended(app_exe, ["--no-wait"] + args, h)
        f.close()
        pid = pi.dwProcessId
    t0 = time.perf_counter()
    tr = subprocess.Popen([str(bin_dir / "uhh_trace.exe"), "--backend", backend, "--attach", str(pid),
                           "-p", f"probe_app.exe+{rva:#x}:-", "-p", "ntdll.dll!NtReadVirtualMemory:xxxx"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    active, err, logs, objs, timeline = [], [], [0], [], []
    both = threading.Event()

    def pump_err():
        for raw in tr.stderr:
            l = raw.decode(errors="replace").rstrip()
            err.append(l)
            timeline.append(f"{(time.perf_counter() - t0) * 1000:8.1f} {l}")
            if l.startswith("probe: active"):
                active.append((time.perf_counter() - t0) * 1000)
                if len(active) == 2:
                    both.set()

    def pump_out():
        for raw in tr.stdout:
            if raw.startswith(b'{"kind":"probe_log"'):
                logs[0] += 1
            elif raw.startswith(b"{"):
                try:
                    objs.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass

    te, to = threading.Thread(target=pump_err, daemon=True), threading.Thread(target=pump_out, daemon=True)
    te.start(); to.start()
    armed = both.wait(30)
    if running:
        prev = None
        gated.stdin.write(b"\n"); gated.stdin.flush()      # release the gate
    else:
        prev = K32.ResumeThread(pi.hThread)        # 1: the main thread had not run a single instruction
    t_resume = (time.perf_counter() - t0) * 1000
    try:
        tr.wait(timeout=600)
    except subprocess.TimeoutExpired:
        tr.kill(); tr.wait()
    te.join(30); to.join(30)
    code = wintypes.DWORD()
    if running:
        code.value = gated.wait(60)
    else:
        K32.WaitForSingleObject(pi.hProcess, 60000)
        K32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
        K32.CloseHandle(pi.hThread); K32.CloseHandle(pi.hProcess)
    app = {}
    for l in Path(out.name).read_text(errors="replace").splitlines():
        if l.startswith('{"kind":"app"'):
            app = json.loads(l)
    os.unlink(out.name)
    for l in err:
        if l.startswith("probe: logs -> "):
            try:
                os.unlink(l[len("probe: logs -> "):].strip())
            except OSError:
                pass
    probes = [o for o in objs if o.get("kind") == "probe"]
    entry = next((p for p in probes if p.get("location", "").startswith("probe_app.exe+")), {})
    rd = next((p for p in probes if "NtReadVirtualMemory" in p.get("location", "")), {})
    ok = (armed and (prev == 1 or running) and entry.get("hits") == (0 if running else 1) and rd.get("hits") == logs[0] == app.get("successful_reads")
          == threads * reads and code.value == 0)
    return {"backend": backend, "target": "running (at its gate)" if running else "CREATE_SUSPENDED", "ok": ok, "armed_before_resume": armed, "main_suspend_count_before_resume": prev,
            "attach_to_active_ms": [round(a) for a in active], "resumed_at_ms": round(t_resume),
            "entry_hits": entry.get("hits"), "read_hits": rd.get("hits"), "logs": logs[0],
            "successful_reads": app.get("successful_reads"), "checksum": app.get("checksum"), "exit": code.value,
            "tracer_exit": tr.returncode, "timeline": timeline[:80] if os.environ.get("PROBE_TRACE") else [], "stderr": [l for l in err if "probe:" in l and "active" not in l][:6] if not ok else []}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", type=Path, default=Path("build-x64/Release"))
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--reads", type=int, default=2000)
    ap.add_argument("--backends", default="breakpoint,hw,inline")
    ap.add_argument("--running", action="store_true", help="also attach to a running target (comparison)")
    a = ap.parse_args()
    bad = 0
    for bk in a.backends.split(","):
        for running in ((False, True) if a.running else (False,)):
            for _ in range(a.trials):
                r = trial(a.bin.resolve(), bk, a.threads, a.reads, running)
                print(json.dumps(r), flush=True)
                bad += not r["ok"]
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
