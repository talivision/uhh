#!/usr/bin/env python3
"""Poor man's sampling profiler for Windows processes (no WPA/xperf needed).

  python sampler.py --exe-name hitcost_target.exe [--ms 1] [--seconds 3] [--top 40] [--maps DIR]
  python sampler.py --pid N ...

Waits for the process (by image name, or a pid), then every --ms suspends each of its threads,
reads the instruction pointer and the first stack words (GetThreadContext, or
Wow64GetThreadContext for a 32-bit process), resumes it. A thread waiting in the kernel shows
its ntdll syscall stub; those samples are kept (they are where the time goes) and
attributed to the stub's export name and its caller. Addresses are resolved to
module!symbol: exports of every loaded module (read from the process's own memory), and,
for modules with a linker map file (<module>.map in --maps), the map's publics.
Prints the hottest leaf symbols and the hottest (leaf <- first caller in a non-system module).
"""
import argparse, bisect, collections, ctypes, ctypes.wintypes as W, os, re, struct, sys, time
from pathlib import Path

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
PROCESS_ALL = 0x1F0FFF
THREAD_ALL = 0x1F03FF


# CONTEXT (x64, 1232 bytes, 16-byte aligned): ContextFlags 0x30, Rsp 0x98, Rip 0xF8.
# WOW64_CONTEXT (716 bytes): ContextFlags 0x0, Eip 0xB8, Esp 0xC4.
_ctxbuf = ctypes.create_string_buffer(1232 + 16)
_ctxaddr = (ctypes.addressof(_ctxbuf) + 15) & ~15


def get_ip_sp(th, wow):
    if wow:
        buf = ctypes.create_string_buffer(716)
        struct.pack_into("<I", buf, 0, 0x10003)               # WOW64_CONTEXT_CONTROL | INTEGER
        if not k32.Wow64GetThreadContext(th, buf):
            return None
        return struct.unpack_from("<I", buf, 0xB8)[0], struct.unpack_from("<I", buf, 0xC4)[0]
    ctypes.memset(_ctxaddr, 0, 1232)
    ctypes.c_uint32.from_address(_ctxaddr + 0x30).value = 0x100003    # CONTEXT_CONTROL | INTEGER
    if not k32.GetThreadContext(th, ctypes.c_void_p(_ctxaddr)):
        return None
    return ctypes.c_uint64.from_address(_ctxaddr + 0xF8).value, ctypes.c_uint64.from_address(_ctxaddr + 0x98).value


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", W.DWORD), ("cntUsage", W.DWORD), ("th32ThreadID", W.DWORD),
                ("th32OwnerProcessID", W.DWORD), ("tpBasePri", W.LONG), ("tpDeltaPri", W.LONG), ("dwFlags", W.DWORD)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", W.DWORD), ("cntUsage", W.DWORD), ("th32ProcessID", W.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", W.DWORD), ("cntThreads", W.DWORD),
                ("th32ParentProcessID", W.DWORD), ("pcPriClassBase", W.LONG), ("dwFlags", W.DWORD),
                ("szExeFile", W.WCHAR * 260)]


k32.CreateToolhelp32Snapshot.restype = W.HANDLE
k32.OpenProcess.restype = W.HANDLE
k32.OpenThread.restype = W.HANDLE


def find_pid(name, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        snap = k32.CreateToolhelp32Snapshot(2, 0)
        e = PROCESSENTRY32W(); e.dwSize = ctypes.sizeof(e)
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            if e.szExeFile.lower() == name.lower():
                k32.CloseHandle(snap); return e.th32ProcessID
            ok = k32.Process32NextW(snap, ctypes.byref(e))
        k32.CloseHandle(snap)
        time.sleep(0.005)
    return None


def threads_of(pid):
    snap = k32.CreateToolhelp32Snapshot(4, 0)
    e = THREADENTRY32(); e.dwSize = ctypes.sizeof(e)
    out = []
    ok = k32.Thread32First(snap, ctypes.byref(e))
    while ok:
        if e.th32OwnerProcessID == pid:
            out.append(e.th32ThreadID)
        ok = k32.Thread32Next(snap, ctypes.byref(e))
    k32.CloseHandle(snap)
    return out


def rpm(h, addr, n):
    buf = ctypes.create_string_buffer(n); got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)) or got.value != n:
        return None
    return buf.raw


def modules(h):
    arr = (ctypes.c_void_p * 1024)(); need = W.DWORD()
    psapi.EnumProcessModulesEx(h, arr, ctypes.sizeof(arr), ctypes.byref(need), 3)
    out = []
    for i in range(need.value // ctypes.sizeof(ctypes.c_void_p)):
        base = arr[i]
        if not base:
            continue
        name = ctypes.create_unicode_buffer(520)
        psapi.GetModuleFileNameExW(h, ctypes.c_void_p(base), name, 520)

        class MI(ctypes.Structure):
            _fields_ = [("base", ctypes.c_void_p), ("size", W.DWORD), ("entry", ctypes.c_void_p)]
        mi = MI()
        psapi.GetModuleInformation(h, ctypes.c_void_p(base), ctypes.byref(mi), ctypes.sizeof(mi))
        out.append((base, mi.size, name.value))
    return out


def exports(h, base):
    """[(rva, name)] from the module's export directory, read from the process."""
    hdr = rpm(h, base, 0x400)
    if not hdr or hdr[:2] != b"MZ":
        return []
    pe = struct.unpack_from("<I", hdr, 0x3C)[0]
    magic = struct.unpack_from("<H", hdr, pe + 24)[0]
    dd = pe + 24 + (96 if magic == 0x10B else 112)
    erva, esize = struct.unpack_from("<II", hdr, dd)
    if not erva:
        return []
    ed = rpm(h, base + erva, 40)
    if not ed:
        return []
    nfun, nnames, afun, anames, aords = struct.unpack_from("<IIIII", ed, 20)
    funs = rpm(h, base + afun, 4 * nfun) or b""
    names = rpm(h, base + anames, 4 * nnames) or b""
    ords = rpm(h, base + aords, 2 * nnames) or b""
    out = []
    for i in range(min(nnames, len(names) // 4, len(ords) // 2)):
        nrva = struct.unpack_from("<I", names, 4 * i)[0]
        o = struct.unpack_from("<H", ords, 2 * i)[0]
        if 4 * o + 4 > len(funs):
            continue
        frva = struct.unpack_from("<I", funs, 4 * o)[0]
        nm = rpm(h, base + nrva, 96) or b""
        out.append((frva, nm.split(b"\0")[0].decode(errors="replace")))
    return out


def map_publics(path):
    """MSVC linker map: '  0001:000004a0  ?name@@...  00000001400014a0 f   obj.obj' -> rva = address - preferred base."""
    out, base = [], None
    for line in open(path, errors="replace"):
        m = re.search(r"Preferred load address is ([0-9a-fA-F]+)", line)
        if m:
            base = int(m.group(1), 16)
        m = re.match(r"\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8,16})\s", line)
        if m and base is not None:
            va = int(m.group(2), 16)
            if va > base:
                out.append((va - base, m.group(1)))
    return out


class Resolver:
    def __init__(self, h, maps_dir):
        self.mods = sorted(modules(h))
        self.syms = {}
        for base, size, path in self.mods:
            name = os.path.basename(path)
            syms = exports(h, base)
            if maps_dir:
                mp = Path(maps_dir) / (Path(name).stem + ".map")
                if mp.exists():
                    syms += map_publics(mp)
            syms.sort()
            self.syms[base] = ([s[0] for s in syms], [s[1] for s in syms], name)
        self.bases = [m[0] for m in self.mods]

    def name(self, a):
        i = bisect.bisect_right(self.bases, a) - 1
        if i < 0 or a >= self.mods[i][0] + self.mods[i][1]:
            return None
        base = self.mods[i][0]
        rvas, names, mod = self.syms[base]
        rva = a - base
        j = bisect.bisect_right(rvas, rva) - 1
        return f"{mod}!{names[j]}" if j >= 0 else f"{mod}+0x{rva:x}"


SYSTEM = ("ntdll.dll", "kernel32.dll", "kernelbase.dll", "ucrtbase.dll", "vcruntime140.dll", "msvcp140.dll",
          "wow64.dll", "wow64win.dll", "wow64cpu.dll", "user32.dll", "win32u.dll")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe-name"); ap.add_argument("--pid", type=int)
    ap.add_argument("--ms", type=float, default=1.0); ap.add_argument("--seconds", type=float, default=3.0)
    ap.add_argument("--delay", type=float, default=0.3, help="seconds to wait after the process appears")
    ap.add_argument("--top", type=int, default=30); ap.add_argument("--maps")
    ap.add_argument("--per-thread", type=int, default=0, help="also print the top N leaves of each busy thread")
    a = ap.parse_args()
    pid = a.pid or find_pid(a.exe_name, 60)
    if not pid:
        print("sampler: no process"); return
    h = k32.OpenProcess(PROCESS_ALL, False, pid)
    wow = W.BOOL(); k32.IsWow64Process(h, ctypes.byref(wow)); wow = bool(wow.value)
    time.sleep(a.delay)
    res = Resolver(h, a.maps)
    leaf, pair, nsamp = collections.Counter(), collections.Counter(), 0
    per = collections.defaultdict(collections.Counter)
    psz = 4 if wow else 8
    t_end = time.time() + a.seconds
    while time.time() < t_end:
        for tid in threads_of(pid):
            th = k32.OpenThread(THREAD_ALL, False, tid)
            if not th:
                continue
            if (k32.Wow64SuspendThread(th) if wow else k32.SuspendThread(th)) == 0xFFFFFFFF:
                k32.CloseHandle(th); continue
            r = get_ip_sp(th, wow)
            ok = r is not None
            ip, sp = r if ok else (0, 0)
            stack = rpm(h, sp, 64 * psz) if ok else None
            k32.ResumeThread(th); k32.CloseHandle(th)
            if not ok:
                continue
            nsamp += 1
            if res.name(ip) is None:
                res = Resolver(h, a.maps)          # a module loaded since
            ln = res.name(ip) or f"?0x{ip:x}"
            leaf[ln] += 1
            per[tid][ln] += 1
            caller = None
            if stack:
                for k in range(len(stack) // psz):
                    v = struct.unpack_from("<Q" if psz == 8 else "<I", stack, k * psz)[0]
                    n = res.name(v)
                    if n and n.split("!")[0].split("+")[0].lower() not in SYSTEM:
                        caller = n; break
            pair[f"{ln}  <-  {caller}"] += 1
        time.sleep(a.ms / 1000.0)
    print(f"sampler: pid {pid} wow64={wow} samples={nsamp}")
    print("-- leaf")
    for k, v in leaf.most_common(a.top):
        print(f"{v * 100.0 / max(1, nsamp):6.1f}%  {k}")
    print("-- leaf <- first non-system caller on the stack (scan)")
    for k, v in pair.most_common(a.top):
        print(f"{v * 100.0 / max(1, nsamp):6.1f}%  {k}")
    if a.per_thread:
        idle = ("ZwWaitForWorkViaWorkerFactory", "ZwWaitForMultipleObjects", "ZwRemoveIoCompletion", "ZwDelayExecution")
        for tid, c in sorted(per.items(), key=lambda kv: -sum(kv[1].values())):
            tot = sum(c.values())
            if all(any(i in k for i in idle) for k in c):
                continue
            print(f"-- thread {tid}: {tot} samples")
            for k, v in c.most_common(a.per_thread):
                print(f"{v * 100.0 / tot:6.1f}%  {k}")


if __name__ == "__main__":
    main()
