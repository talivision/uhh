#!/usr/bin/env python3
"""What a debugger can see of a target's threads while it handles dense debug events
(experiment behind the demand-driven fairness): every --ms, for each thread of the process,
the kernel's ThreadState / WaitReason (NtQuerySystemInformation SystemProcessInformation), the
cycle-time delta (QueryThreadCycleTime) and user / kernel time deltas (GetThreadTimes).

  python threadstates.py --exe-name hitcost_target.exe [--ms 20] [--seconds 3]
"""
import argparse, collections, ctypes, ctypes.wintypes as W, struct, time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
k32.OpenThread.restype = W.HANDLE
STATES = {0: "Init", 1: "Ready", 2: "Running", 3: "Standby", 4: "Term", 5: "Wait", 6: "Trans", 7: "DefReady"}


def sysproc():
    size = 1 << 20
    while True:
        buf = ctypes.create_string_buffer(size); ret = W.ULONG()
        st = ntdll.NtQuerySystemInformation(5, buf, size, ctypes.byref(ret)) & 0xFFFFFFFF
        if st == 0xC0000004:
            size *= 2; continue
        return buf.raw


def threads_of(raw, pid):
    off = 0
    while True:
        nxt, nthr = struct.unpack_from("<II", raw, off)
        upid = struct.unpack_from("<Q", raw, off + 0x50)[0]
        if upid == pid:
            out = {}
            for i in range(nthr):
                t = off + 0x100 + i * 0x50
                tid = struct.unpack_from("<Q", raw, t + 0x30)[0]
                state, reason = struct.unpack_from("<II", raw, t + 0x44)
                out[tid] = (state, reason)
            return out
        if not nxt:
            return {}
        off += nxt


def find_pid(name):
    import subprocess
    for _ in range(3000):
        out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"], capture_output=True,
                             text=True).stdout
        for line in out.splitlines():
            parts = [x.strip('"') for x in line.split('","')]
            if len(parts) > 1 and parts[0].lower() == name.lower():
                return int(parts[1])
        time.sleep(0.01)


def cycles(tid):
    h = k32.OpenThread(0x1000 | 0x0800, False, tid)       # QUERY_LIMITED | ...
    if not h:
        return None
    c = ctypes.c_uint64(); ct, et, kt, ut = (W.FILETIME() for _ in range(4))
    ok = k32.QueryThreadCycleTime(h, ctypes.byref(c))
    k32.GetThreadTimes(h, ctypes.byref(ct), ctypes.byref(et), ctypes.byref(kt), ctypes.byref(ut))
    k32.CloseHandle(h)
    f = lambda x: (x.dwHighDateTime << 32) | x.dwLowDateTime
    return (c.value if ok else None, f(kt), f(ut))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe-name"); ap.add_argument("--pid", type=int); ap.add_argument("--ms", type=float, default=20)
    ap.add_argument("--seconds", type=float, default=3); ap.add_argument("--delay", type=float, default=0.5)
    a = ap.parse_args()
    pid = a.pid or find_pid(a.exe_name)
    time.sleep(a.delay)
    states = collections.defaultdict(collections.Counter)
    grew = collections.Counter(); windows = collections.Counter(); dcyc = collections.Counter()
    dut = collections.Counter(); dkt = collections.Counter()
    prev = {}
    t_end = time.time() + a.seconds
    while time.time() < t_end:
        for tid, (st, wr) in threads_of(sysproc(), pid).items():
            states[tid][f"{STATES.get(st, st)}/{wr}"] += 1
            c = cycles(tid)
            if c and tid in prev and c[0] is not None and prev[tid][0] is not None:
                windows[tid] += 1
                d = c[0] - prev[tid][0]
                dcyc[tid] += d; dut[tid] += c[2] - prev[tid][2]; dkt[tid] += c[1] - prev[tid][1]
                if d > 0:
                    grew[tid] += 1
            if c:
                prev[tid] = c
        time.sleep(a.ms / 1000)
    print(f"threadstates pid={pid}")
    for tid in sorted(states):
        n = windows[tid] or 1
        print(f"tid {tid}: windows={windows[tid]} cycles/window={dcyc[tid] / n:,.0f} grew={grew[tid]}/{windows[tid]} "
              f"user_ms={dut[tid] / 1e4:.1f} kernel_ms={dkt[tid] / 1e4:.1f} states={dict(states[tid].most_common(4))}")


if __name__ == "__main__":
    main()
