#!/usr/bin/env python3
"""UHH soak test: the flagship use case (examples/gated_config) for a long time, sampled.

    soak.py --bin build-x64/Release --minutes 30 --phase mixed [--phase hw ...] [--out DIR]

Phases (each runs ONE target process tree at a time):
  mixed       flag on a breakpoint, NtOpenProcess/NtClose/NtReadVirtualMemory inline
  hw          every probe a hardware breakpoint
  breakpoint  every probe a software breakpoint (lower default rate)
  attach      probe_app runs on its own; uhh_trace attaches, logs every read, detaches after
              --attach-ms, waits --gap-s, and attaches again with the next backend
              (inline -> hw -> breakpoint ...) until the time is up

A launch phase runs gated_config against `probe_app --threads T --reads R --pace P` for about
--minutes (R = P * 60 * minutes: probe_app's --pace keeps each read thread at P reads/s, so
the run is long but its log file stays bounded). While it runs, every --sample-s seconds the
controller's and the target's private bytes, working set, handle and thread counts and the
size of the session log file are recorded (printed live and written to DIR/<phase>.csv).
probe_log lines are checked as they stream (the controller's stdout is a pipe): every read
line must carry a helper's pid, name=probe_app.exe and the handle probe_app really opened
for that pid.

At the end a phase passes only if:
  - every read was logged: logged reads == read-probe hits == probe_app's successful_reads
    == threads * reads, log_dropped == 0, callbacks_interrupted == 0, no error;
  - the session log file holds exactly logs_written lines;
  - probe_app's checksum equals an uninstrumented run of the same reads;
  - no growth beyond steady state: over the second half of the run the controller's and
    the target's private bytes grew by less than --max-growth-mb and their handle counts by
    less than --max-handle-growth (warm-up excluded).
The attach phase checks every cycle (logs == hits == logs_written, dropped 0, detached), the
target's checksum after all cycles, and that the target's private bytes, handles, threads
and loaded agent copies do not grow from cycle to cycle.

regress.py --soak-minutes N runs every phase for N minutes through run_phase() below.

Shared test VM (Proxmox VM 103, KVM, guest disk on a 5400 rpm HDD): keep the hw phase to
<= 10 minutes per run (8.2 min / 5M hw hits verified clean), with no other VM jobs running and
--sample-s <= 15. The VM hung silently twice 18-22 min into a 30-min hw soak; short sampled runs
showed no growth of available memory, kernel pools, commit or handles with hw load (nor inline),
so that is a VM artefact, not a UHH leak -- see docs/ROADMAP.md "hw load / VM freeze". Signs:
Kernel-Power 41 with BugcheckCode=0, no Resource-Exhaustion (2004) event, samples flat up to the
hang. The host's "kvm: Unhandled WRMSR(0x1d9)" lines are unrelated background noise, and the
Proxmox memory graph (QEMU RSS) reads near-full whatever the guest's real use. Long hw soaks
belong on bare metal.
"""
import argparse
import csv
import ctypes
import json
import os
import re
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

FLAG_LOCATION = "configparse.dll!ParseConfig+0x16"
READ_LOCATION = "ntdll.dll!NtReadVirtualMemory"
HELPERS = 4

PHASES = {
    # name: (flag, open, read backend, default pace per thread)
    "mixed": ("breakpoint", "inline", "inline", 4000),
    "hw": ("hw", "hw", "hw", 1500),
    "breakpoint": ("breakpoint", "breakpoint", "breakpoint", 400),
}


# ---- process metrics (ctypes, no psutil) --------------------------------------------
class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                ("PrivateUsage", ctypes.c_size_t)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260)]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD), ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", ctypes.c_void_p), ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE),
                ("szModule", wintypes.WCHAR * 256), ("szExePath", wintypes.WCHAR * 260)]


if os.name == "nt":
    K32 = ctypes.WinDLL("kernel32", use_last_error=True)
    K32.OpenProcess.restype = wintypes.HANDLE
    K32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    K32.CloseHandle.argtypes = [wintypes.HANDLE]
    K32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    K32.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    K32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    K32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    K32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    K32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    K32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    K32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    K32.K32GetPerformanceInfo.argtypes = [ctypes.c_void_p, wintypes.DWORD]
INVALID_HANDLE = ctypes.c_void_p(-1).value


class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("CommitTotal", ctypes.c_size_t), ("CommitLimit", ctypes.c_size_t),
                ("CommitPeak", ctypes.c_size_t), ("PhysicalTotal", ctypes.c_size_t),
                ("PhysicalAvailable", ctypes.c_size_t), ("SystemCache", ctypes.c_size_t),
                ("KernelTotal", ctypes.c_size_t), ("KernelPaged", ctypes.c_size_t),
                ("KernelNonpaged", ctypes.c_size_t), ("PageSize", ctypes.c_size_t),
                ("HandleCount", wintypes.DWORD), ("ProcessCount", wintypes.DWORD), ("ThreadCount", wintypes.DWORD)]


def system_memory():
    """Whole-machine numbers (MB): the VM froze twice during the hw phase with the system out of
    memory while UHH's own processes stayed flat -- so kernel pools and available RAM are
    sampled too, and a phase is aborted before the machine runs out."""
    pi = PERFORMANCE_INFORMATION(); pi.cb = ctypes.sizeof(pi)
    if not K32.K32GetPerformanceInfo(ctypes.byref(pi), pi.cb):
        return None
    mb = lambda pages: round(pages * pi.PageSize / 2**20)
    return {"avail_mb": mb(pi.PhysicalAvailable), "commit_mb": mb(pi.CommitTotal), "nonpaged_mb": mb(pi.KernelNonpaged),
            "paged_mb": mb(pi.KernelPaged), "sys_handles": pi.HandleCount}


MIN_AVAIL_MB = 1536     # abort a phase below this (the shared VM must never be starved)


def thread_counts():
    """pid -> thread count, one system snapshot."""
    out = {}
    snap = K32.CreateToolhelp32Snapshot(0x2, 0)
    if not snap or snap == INVALID_HANDLE:
        return out
    pe = PROCESSENTRY32W(); pe.dwSize = ctypes.sizeof(pe)
    ok = K32.Process32FirstW(snap, ctypes.byref(pe))
    while ok:
        out[pe.th32ProcessID] = pe.cntThreads
        ok = K32.Process32NextW(snap, ctypes.byref(pe))
    K32.CloseHandle(snap)
    return out


def agent_modules(pid):
    """How many probe_api_agent.dll images (the agent and its per-session copies) pid has loaded."""
    for _ in range(5):                                  # ERROR_BAD_LENGTH while modules change: retry
        snap = K32.CreateToolhelp32Snapshot(0x18, pid)  # SNAPMODULE | SNAPMODULE32 (WOW64 targets)
        if snap and snap != INVALID_HANDLE:
            break
        time.sleep(0.05)
    else:
        return None
    n = 0
    me = MODULEENTRY32W(); me.dwSize = ctypes.sizeof(me)
    ok = K32.Module32FirstW(snap, ctypes.byref(me))
    while ok:
        if me.szModule.lower() == "probe_api_agent.dll":
            n += 1
        ok = K32.Module32NextW(snap, ctypes.byref(me))
    K32.CloseHandle(snap)
    return n


class Proc:
    """A query handle on one process (kept open so a pid is never confused with a reused one)."""

    def __init__(self, pid):
        self.pid = pid
        self.h = K32.OpenProcess(0x1000 | 0x0010, False, pid)   # QUERY_LIMITED_INFORMATION | VM_READ

    def sample(self, threads):
        if not self.h:
            return None
        pmc = PROCESS_MEMORY_COUNTERS_EX(); pmc.cb = ctypes.sizeof(pmc)
        handles = wintypes.DWORD(0)
        if not K32.K32GetProcessMemoryInfo(self.h, ctypes.byref(pmc), pmc.cb):
            return None
        K32.GetProcessHandleCount(self.h, ctypes.byref(handles))
        return {"private_mb": round(pmc.PrivateUsage / 2**20, 2), "ws_mb": round(pmc.WorkingSetSize / 2**20, 2),
                "handles": handles.value, "threads": threads.get(self.pid, 0)}

    def close(self):
        if self.h:
            K32.CloseHandle(self.h); self.h = None


# ---- helpers ------------------------------------------------------------------------
def say(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


def json_objs(lines):
    out = []
    for l in lines:
        l = l.strip()
        if l.startswith("{"):
            try:
                out.append(json.loads(l))
            except json.JSONDecodeError:
                pass
    return out


def baseline(bin_dir, threads, reads):
    """probe_app alone with the feature on: the checksum every instrumented run must match."""
    r = subprocess.run([str(bin_dir / "probe_app.exe"), "--no-wait", "--helpers", str(HELPERS), "--threads", str(threads),
                        "--reads", str(reads), "--config", "reads_enabled=1"],
                       capture_output=True, text=True, timeout=3600, stdin=subprocess.DEVNULL)
    app = next((o for o in json_objs(r.stdout.splitlines()) if o.get("kind") == "app"), {})
    return app


def count_lines(path):
    n = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 22)
            if not b:
                return n
            n += b.count(b"\n")


def growth(samples, who, key):
    """Growth of samples[who][key] over the second half of the run (the first half is warm-up)."""
    vals = [s[who][key] for s in samples if s.get(who)]
    if len(vals) < 4:
        return 0.0, vals
    half = vals[len(vals) // 2:]
    return round(max(half[-1] - half[0], 0), 2), vals


READ_RE = re.compile(rb"read handle=0x([0-9a-f]+) pid=(\d+) name=([^ ]+) addr=0x([0-9a-f]+) size=(\d+)")


class Sampler:
    def __init__(self, out_csv, every, procs, log_path_fn, extra_fn=None, on_low_memory=None):
        self.samples, self.every, self.procs = [], every, procs
        self.on_low_memory, self.low_memory = on_low_memory, None
        self.log_path_fn, self.extra_fn = log_path_fn, extra_fn
        self.stop = threading.Event()
        self.f = open(out_csv, "w", newline="")
        self.w = csv.writer(self.f)
        self.w.writerow(["t_s"] + [f"{who}_{k}" for who in procs for k in ("private_mb", "ws_mb", "handles", "threads")]
                        + ["log_mb", "avail_mb", "commit_mb", "nonpaged_mb", "paged_mb", "sys_handles", "extra"])
        self.t0 = time.time()
        self.t = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.t.start()

    def take(self):
        th = thread_counts()
        s = {"t": round(time.time() - self.t0, 1)}
        for who, p in self.procs.items():
            s[who] = p().sample(th) if p() else None
        lp = self.log_path_fn()
        try:
            s["log_mb"] = round(os.path.getsize(lp) / 2**20, 1) if lp else None
        except OSError:
            s["log_mb"] = None
        s["extra"] = self.extra_fn() if self.extra_fn else ""
        s["sys"] = system_memory() or {}
        self.samples.append(s)
        if s["sys"].get("avail_mb", 1 << 30) < MIN_AVAIL_MB and not self.low_memory:
            self.low_memory = s["sys"]
            say(f"ABORT: system available memory {s['sys']} below {MIN_AVAIL_MB} MB")
            if self.on_low_memory:
                self.on_low_memory()
        row = [s["t"]]
        for who in self.procs:
            m = s[who] or {}
            row += [m.get("private_mb"), m.get("ws_mb"), m.get("handles"), m.get("threads")]
        sy = s["sys"]
        self.w.writerow(row + [s["log_mb"]] + [sy.get(k) for k in ("avail_mb", "commit_mb", "nonpaged_mb", "paged_mb",
                                                                   "sys_handles")] + [s["extra"]]); self.f.flush()
        say("sample t=%5.0fs " % s["t"] + " ".join(
            f"{who}[priv={m['private_mb']}MB ws={m['ws_mb']}MB h={m['handles']} thr={m['threads']}]"
            for who, m in ((w, s[w]) for w in self.procs) if m) + f" log={s['log_mb']}MB {s['extra']} sys={sy}")

    def _run(self):
        while not self.stop.wait(self.every):
            try:
                self.take()
            except Exception as e:      # a sample must never kill the soak
                say("sample failed:", repr(e))

    def finish(self):
        self.stop.set(); self.t.join(timeout=10); self.f.close()


# ---- launch phases (gated_config) ----------------------------------------------------
def launch_phase(bin_dir, phase, minutes, threads, pace, out_dir, sample_s, max_growth_mb, max_handle_growth):
    flag_bk, open_bk, read_bk, default_pace = PHASES[phase]
    pace = pace or default_pace
    reads = max(1, int(pace * 60 * minutes))
    total = threads * reads
    say(f"phase {phase}: flag={flag_bk} open={open_bk} read={read_bk} threads={threads} reads/thread={reads} "
        f"pace={pace}/s/thread (~{threads * pace}/s, ~{minutes} min) total={total}")
    base = baseline(bin_dir, threads, reads)
    say(f"baseline (uninstrumented): successful_reads={base.get('successful_reads')} checksum={base.get('checksum')}")

    args = [str(bin_dir / "gated_config.exe"), "--flag-backend", flag_bk, "--open-backend", open_bk,
            "--read-backend", read_bk, FLAG_LOCATION, READ_LOCATION, "--", str(bin_dir / "probe_app.exe"),
            "--helpers", str(HELPERS), "--threads", str(threads), "--reads", str(reads), "--pace", str(pace)]
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    state = {"target": None, "log": None, "reads": 0, "bad": 0, "bad_examples": [], "objs": [], "opened": {},
             "helpers": {}, "pairs": {}, "other_logs": 0, "stderr": []}
    target_proc = [None]
    ctl = Proc(proc.pid)
    gate = threading.Event()

    def pump_out():
        for raw in proc.stdout:
            if raw.startswith(b'{"kind":"probe_log"'):
                m = READ_RE.search(raw)
                if not m:
                    state["other_logs"] += 1
                    continue
                state["reads"] += 1
                key = (int(m.group(1), 16), int(m.group(2)), m.group(3))
                state["pairs"][key] = state["pairs"].get(key, 0) + 1
                continue
            line = raw.decode(errors="replace").strip()
            if not line.startswith("{"):
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            state["objs"].append(o)
            k = o.get("kind")
            if k == "helper":
                state["helpers"][o["pid"]] = o
            elif k == "opened":
                state["opened"][o["handle"]] = o["pid"]
            elif k == "waiting":
                state["target"] = o["pid"]; target_proc[0] = Proc(o["pid"]); gate.set()

    def pump_err():
        marker = b"probe: logs -> "
        with open(out_dir / f"{phase}.stderr.log", "wb") as f:
            for raw in proc.stderr:
                f.write(raw); f.flush()
                if raw.startswith(marker):
                    state["log"] = raw[len(marker):].decode(errors="replace").strip()
                if len(state["stderr"]) < 200:
                    state["stderr"].append(raw.decode(errors="replace").rstrip())

    to, te = threading.Thread(target=pump_out, daemon=True), threading.Thread(target=pump_err, daemon=True)
    to.start(); te.start()
    if not gate.wait(120):
        proc.kill()
        return {"phase": phase, "ok": False, "detail": "target never reached its gate", "stderr": state["stderr"][-20:]}
    sampler = Sampler(out_dir / f"{phase}.csv", sample_s, {"ctl": lambda: ctl, "tgt": lambda: target_proc[0]},
                      lambda: state["log"], lambda: f"reads_logged={state['reads']}", on_low_memory=proc.kill)
    sampler.take()                      # t=0: at the gate, before the flag flips
    sampler.start()
    t0 = time.time()
    proc.stdin.write(b"\n"); proc.stdin.flush()       # the keystroke: ParseConfig runs, the flag flips
    try:
        proc.wait(timeout=minutes * 60 * 4 + 600)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait()
    elapsed = time.time() - t0
    to.join(timeout=60); te.join(timeout=60)
    sampler.finish()
    ctl.close()
    if target_proc[0]:
        target_proc[0].close()

    objs = state["objs"]
    app = next((o for o in objs if o.get("kind") == "app"), {})
    rep = next((o for o in objs if o.get("kind") == "probe_report"), {})
    rprobe = next((o for o in objs if o.get("kind") == "probe" and o.get("location") == READ_LOCATION), {})
    oprobe = next((o for o in objs if o.get("kind") == "probe" and o.get("location") == "ntdll.dll!NtOpenProcess"), {})
    hits = rprobe.get("hits")
    helper_pids = set(state["helpers"])
    wrong = {k: v for k, v in state["pairs"].items()
             if k[1] not in helper_pids or k[2] != b"probe_app.exe" or state["opened"].get(k[0]) != k[1]}
    file_lines = None
    if state["log"] and os.path.exists(state["log"]):
        file_lines = count_lines(state["log"])
    gr = {}
    for who in ("ctl", "tgt"):
        gr[f"{who}_private_mb"], _ = growth(sampler.samples, who, "private_mb")
        gr[f"{who}_handles"], _ = growth(sampler.samples, who, "handles")
        gr[f"{who}_threads"], _ = growth(sampler.samples, who, "threads")
    steady = (gr["ctl_private_mb"] < max_growth_mb and gr["tgt_private_mb"] < max_growth_mb and
              gr["ctl_handles"] < max_handle_growth and gr["tgt_handles"] < max_handle_growth and
              gr["ctl_threads"] <= 2 and gr["tgt_threads"] <= 2)
    exact = (state["reads"] == hits == app.get("successful_reads") == total and rep.get("log_dropped") == 0 and
             rep.get("callbacks_interrupted") == 0 and rep.get("error") is None and rep.get("overrides", 0) >= 1)
    lines_ok = file_lines == rep.get("logs_written") and state["reads"] + state["other_logs"] == rep.get("logs_written")
    checksum_ok = app.get("checksum") == base.get("checksum") and base.get("successful_reads") == total
    sysg = {k: (round(sampler.samples[-1]["sys"].get(k, 0) - sampler.samples[len(sampler.samples) // 2]["sys"].get(k, 0))
                if len(sampler.samples) >= 4 and sampler.samples[-1].get("sys") else 0)
            for k in ("nonpaged_mb", "paged_mb", "commit_mb", "sys_handles")}
    ok = (proc.returncode == 0 and exact and not wrong and lines_ok and checksum_ok and steady and
          not sampler.low_memory)
    first = sampler.samples[1] if len(sampler.samples) > 1 else (sampler.samples[0] if sampler.samples else {})
    last = sampler.samples[-1] if sampler.samples else {}
    result = {
        "kind": "soak_result", "phase": phase, "ok": ok, "minutes": round(elapsed / 60, 1),
        "backends": {"flag": flag_bk, "open": open_bk, "read": read_bk}, "threads": threads, "pace": pace,
        "total": total, "logged_reads": state["reads"], "read_hits": hits, "open_hits": oprobe.get("hits"),
        "successful_reads": app.get("successful_reads"), "rate_per_s": round(total / elapsed) if elapsed else None,
        "log_dropped": rep.get("log_dropped"), "callbacks_interrupted": rep.get("callbacks_interrupted"),
        "logs_written": rep.get("logs_written"), "log_file_lines": file_lines,
        "log_file_mb": round(os.path.getsize(state["log"]) / 2**20) if state["log"] and os.path.exists(state["log"]) else None,
        "wrong_lines": sum(wrong.values()), "wrong_examples": [(hex(k[0]), k[1], k[2].decode()) for k in list(wrong)[:4]],
        "checksum": app.get("checksum"), "baseline_checksum": base.get("checksum"), "exit": proc.returncode,
        "overrides": rep.get("overrides"), "controller_peak_ws_mb": rep.get("controller_peak_ws_mb"),
        "error": rep.get("error"), "growth_2nd_half": gr, "system_growth_2nd_half": sysg,
        "aborted_low_memory": sampler.low_memory, "first_sample": first, "last_sample": last,
        "samples": len(sampler.samples),
    }
    if state["log"] and ok:
        try:
            os.unlink(state["log"])           # GBs; kept only when the phase failed
        except OSError:
            pass
    if not ok:
        result["stderr_tail"] = state["stderr"][-20:]
    return result


# ---- attach phase (uhh_trace attach / detach cycles) ----------------------------------
def attach_cycle(bin_dir, pid, backend, attach_ms, timeout=600):
    args = [str(bin_dir / "uhh_trace.exe"), "--backend", backend, "--attach", str(pid), "--detach-after-ms",
            str(attach_ms), "-p", READ_LOCATION + ":xxxx"]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    logs, objs, err = [0], [], []

    def pump_out():
        for raw in proc.stdout:
            if raw.startswith(b'{"kind":"probe_log"'):
                logs[0] += 1
            elif raw.startswith(b"{"):
                objs.extend(json_objs([raw.decode(errors="replace")]))

    def pump_err():
        for raw in proc.stderr:
            err.append(raw.decode(errors="replace").rstrip())

    to, te = threading.Thread(target=pump_out, daemon=True), threading.Thread(target=pump_err, daemon=True)
    to.start(); te.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait()
    to.join(timeout=60); te.join(timeout=60)
    text = "\n".join(err)
    fin = re.search(r"probe: detached: hits=(\d+) logs_written=(\d+) log_dropped=(\d+)", text)
    hits, written, dropped = (int(x) for x in fin.groups()) if fin else (None, None, None)
    for l in err:
        if l.startswith("probe: logs -> "):
            try:
                os.unlink(l[len("probe: logs -> "):].strip())
            except OSError:
                pass
    detached = any(o.get("kind") == "detached" for o in objs)
    ok = proc.returncode == 0 and detached and hits is not None and hits > 0 and logs[0] == hits == written and dropped == 0
    return {"backend": backend, "ok": ok, "hits": hits, "logs": logs[0], "written": written, "dropped": dropped,
            "exit": proc.returncode, "detached": detached,
            "stderr_tail": [] if ok else [l for l in err if "probe:" in l][-12:]}


def attach_phase(bin_dir, minutes, threads, pace, out_dir, sample_s, attach_ms, gap_s, max_growth_mb, max_handle_growth):
    pace = pace or 2000
    reads = max(1, int(pace * 60 * (minutes + 2)))       # the target outlives the last cycle
    total = threads * reads
    say(f"phase attach: threads={threads} reads/thread={reads} pace={pace}/s/thread; cycles of {attach_ms} ms "
        f"attached + {gap_s} s detached for {minutes} min")
    base = baseline(bin_dir, threads, reads)
    say(f"baseline (uninstrumented): successful_reads={base.get('successful_reads')} checksum={base.get('checksum')}")
    target = subprocess.Popen([str(bin_dir / "probe_app.exe"), "--helpers", str(HELPERS), "--threads", str(threads),
                               "--reads", str(reads), "--pace", str(pace), "--config", "reads_enabled=1"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    tout, terr = [], []
    gate = threading.Event()

    def pump_out():
        for raw in target.stdout:
            l = raw.decode(errors="replace").rstrip()
            tout.append(l)
            if '"waiting"' in l:
                gate.set()

    def pump_err():
        for raw in target.stderr:
            terr.append(raw.decode(errors="replace").rstrip())

    threading.Thread(target=pump_out, daemon=True).start()
    threading.Thread(target=pump_err, daemon=True).start()
    if not gate.wait(60):
        target.kill()
        return {"phase": "attach", "ok": False, "detail": "target never reached its gate"}
    tp = Proc(target.pid)
    cycles = []
    sampler = Sampler(out_dir / "attach.csv", sample_s, {"tgt": lambda: tp}, lambda: None,
                      lambda: f"cycles={len(cycles)} agents={agent_modules(target.pid)}", on_low_memory=target.kill)
    sampler.take()
    sampler.start()
    target.stdin.write(b"\n"); target.stdin.flush()       # reads start (no instrumentation yet)
    per_cycle = []                                         # target state after each detach
    order = ("inline", "hw", "breakpoint")
    deadline = time.time() + minutes * 60
    t0 = time.time()
    while time.time() < deadline and target.poll() is None and not sampler.low_memory:
        bk = order[len(cycles) % len(order)]
        c = attach_cycle(bin_dir, target.pid, bk, attach_ms)
        c["i"] = len(cycles)
        th = thread_counts()
        c["target"] = tp.sample(th)
        c["agents"] = agent_modules(target.pid)
        cycles.append(c)
        per_cycle.append(c["target"])
        say(f"cycle {c['i']:3} {bk:10} ok={c['ok']} hits={c['hits']} logs={c['logs']} written={c['written']} "
            f"dropped={c['dropped']} target={c['target']} agents={c['agents']}"
            + ("" if c["ok"] else f" stderr={c['stderr_tail']}"))
        if target.poll() is not None:
            break
        time.sleep(gap_s)
    cycling_s = time.time() - t0
    try:
        target.wait(timeout=minutes * 60 * 4 + 900)
    except subprocess.TimeoutExpired:
        target.kill(); target.wait()
    time.sleep(1)
    sampler.finish()
    tp.close()
    app = next((o for o in json_objs(tout) if o.get("kind") == "app"), {})
    unhandled = [l for l in terr if '"unhandled"' in l][:2]
    # Cycle-to-cycle growth of the target, per backend (an inline cycle loads the agent).
    def grow(key):
        vals = [c["target"][key] for c in cycles if c.get("target")]
        half = vals[len(vals) // 2:]
        return round(max(half[-1] - half[0], 0), 2) if len(half) >= 2 else 0
    gr = {"tgt_private_mb": grow("private_mb"), "tgt_handles": grow("handles"), "tgt_threads": grow("threads")}
    agents = [c["agents"] for c in cycles if c.get("agents") is not None]
    steady = (gr["tgt_private_mb"] < max_growth_mb and gr["tgt_handles"] < max_handle_growth and gr["tgt_threads"] <= 2
              and (not agents or max(agents) <= 1))
    all_cycles_ok = bool(cycles) and all(c["ok"] for c in cycles)
    checksum_ok = (app.get("checksum") == base.get("checksum") and app.get("successful_reads") == total ==
                   base.get("successful_reads"))
    ok = all_cycles_ok and checksum_ok and target.returncode == 0 and not unhandled and steady and not sampler.low_memory
    by_bk = {}
    for c in cycles:
        b = by_bk.setdefault(c["backend"], {"cycles": 0, "ok": 0, "hits": 0, "logs": 0})
        b["cycles"] += 1; b["ok"] += c["ok"]; b["hits"] += c["hits"] or 0; b["logs"] += c["logs"]
    return {"kind": "soak_result", "phase": "attach", "ok": ok, "minutes": round(cycling_s / 60, 1), "threads": threads,
            "pace": pace, "cycles": len(cycles), "cycles_ok": sum(c["ok"] for c in cycles), "by_backend": by_bk,
            "failed_cycles": [c for c in cycles if not c["ok"]][:3], "successful_reads": app.get("successful_reads"),
            "total": total, "checksum": app.get("checksum"), "baseline_checksum": base.get("checksum"),
            "target_exit": target.returncode, "unhandled": unhandled, "growth_2nd_half": gr,
            "aborted_low_memory": sampler.low_memory,
            "agent_modules_first_last": (agents[0], agents[-1]) if agents else None,
            "target_after_first_cycle": per_cycle[0] if per_cycle else None,
            "target_after_last_cycle": per_cycle[-1] if per_cycle else None}


def run_phase(bin_dir, phase, minutes, threads=8, pace=0, out_dir=None, sample_s=60, attach_ms=3000, gap_s=2.0,
              max_growth_mb=16.0, max_handle_growth=50):
    out_dir = Path(out_dir or Path(os.environ.get("TEMP", ".")) / "uhh" / "soak")
    out_dir.mkdir(parents=True, exist_ok=True)
    if phase == "attach":
        return attach_phase(Path(bin_dir), minutes, threads, pace, out_dir, sample_s, attach_ms, gap_s,
                            max_growth_mb, max_handle_growth)
    return launch_phase(Path(bin_dir), phase, minutes, threads, pace, out_dir, sample_s, max_growth_mb, max_handle_growth)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", type=Path, default=Path("build-x64/Release"))
    ap.add_argument("--minutes", type=float, default=30, help="per phase (--soak-minutes); on the shared test VM keep the hw phase <= 10 (see above)")
    ap.add_argument("--soak-minutes", type=float, dest="minutes")
    ap.add_argument("--phase", action="append", choices=list(PHASES) + ["attach"],
                    help="repeatable; default: mixed hw breakpoint attach")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--pace", type=int, default=0, help="reads/s per thread (default per phase)")
    ap.add_argument("--sample-s", type=float, default=60)
    ap.add_argument("--attach-ms", type=int, default=3000)
    ap.add_argument("--gap-s", type=float, default=2.0)
    ap.add_argument("--max-growth-mb", type=float, default=16.0)
    ap.add_argument("--max-handle-growth", type=int, default=50)
    ap.add_argument("--out", type=Path, default=None, help="CSV/JSON output dir (default %%TEMP%%\\uhh\\soak)")
    a = ap.parse_args()
    phases = a.phase or ["mixed", "hw", "breakpoint", "attach"]
    failed = 0
    for ph in phases:
        r = run_phase(a.bin.resolve(), ph, a.minutes, a.threads, a.pace, a.out, a.sample_s, a.attach_ms, a.gap_s,
                      a.max_growth_mb, a.max_handle_growth)
        print(json.dumps(r), flush=True)
        say(("PASS" if r["ok"] else "FAIL"), f"soak-{ph}")
        failed += not r["ok"]
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
