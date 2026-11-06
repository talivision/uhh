"""Out-of-process view of a target, for the realbig checks (scripts/regress.py):

  snapshot(pid, names)  the executable sections of the named modules (both bitnesses in a
                        WoW64 process), read from the target -- take it BEFORE attaching
  code_diff(pid, snap)  every byte that differs now, as "module+rva (export+off) before->after"
                        runs -- after a detach there must be none (no INT3 / hook left behind)
  debug_regs(pid)       threads whose DR7/DR0-3 are non-zero, and threads with TF set
  debugger_present(pid) the target's debug port (CheckRemoteDebuggerPresent)
  mem(pid)              private bytes / working set / handle count (controller growth)

Comparing a target with ITSELF (before attach vs after detach) is the only sound oracle on a
real program: Chromium's sandbox patches ntdll stubs in its renderers, chrome_elf hooks the
browser, so a comparison with the file on disk or with another process would differ anyway.
Plain ctypes, no third-party module; the suite's Python is 64-bit and reads 32-bit (WoW64)
targets too (Toolhelp SNAPMODULE32, Wow64GetThreadContext)."""
import ctypes
import struct
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED = 0x10, 0x400, 0x1000
THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED = 0x8, 0x800
TH32CS_SNAPTHREAD, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32 = 0x4, 0x8, 0x10
INVALID = ctypes.c_void_p(-1).value


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD), ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wintypes.DWORD), ("hModule", ctypes.c_void_p), ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * 260)]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD), ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", wintypes.DWORD)]


class PMC_EX(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + \
               [(n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                                               "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                                               "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage",
                                               "PrivateUsage")]


k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
for _f, _t in (("Module32FirstW", MODULEENTRY32W), ("Module32NextW", MODULEENTRY32W),
               ("Thread32First", THREADENTRY32), ("Thread32Next", THREADENTRY32)):
    getattr(k32, _f).argtypes = [wintypes.HANDLE, ctypes.POINTER(_t)]
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenThread.restype = wintypes.HANDLE
k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
k32.Wow64GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
k32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
k32.CheckRemoteDebuggerPresent.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
k32.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC_EX), wintypes.DWORD]


def _open(pid, access=PROCESS_QUERY_INFORMATION | PROCESS_VM_READ):
    h = k32.OpenProcess(access, False, pid)
    if not h:
        raise OSError(f"OpenProcess({pid}) failed: error {ctypes.get_last_error()}")
    return h


def _read(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)) or got.value != n:
        raise OSError(f"ReadProcessMemory({addr:#x}, {n}) failed: error {ctypes.get_last_error()}")
    return buf.raw


def modules(pid, tries=20):
    """[(name_lower, path_lower, base, size)] of both bitnesses (a 64-bit caller sees a WoW64
    process's 32-bit modules only with SNAPMODULE32). Toolhelp fails transiently while the
    target's loader runs (ERROR_BAD_LENGTH / PARTIAL_COPY): retried."""
    for _ in range(tries):
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if snap and snap != INVALID:
            break
        time.sleep(0.05)
    else:
        raise OSError(f"module snapshot of {pid} failed: error {ctypes.get_last_error()}")
    out = []
    try:
        e = MODULEENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        ok = k32.Module32FirstW(snap, ctypes.byref(e))
        while ok:
            out.append((e.szModule.lower(), e.szExePath.lower(), e.modBaseAddr, e.modBaseSize))
            ok = k32.Module32NextW(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return out


def _sections_and_exports(h, base):
    hdr = _read(h, base, 0x1000)
    lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
    nsec = struct.unpack_from("<H", hdr, lfanew + 6)[0]
    optsz = struct.unpack_from("<H", hdr, lfanew + 20)[0]
    opt = lfanew + 24
    magic = struct.unpack_from("<H", hdr, opt)[0]
    ddir = opt + (112 if magic == 0x20B else 96)
    exp_rva, exp_size = struct.unpack_from("<II", hdr, ddir)
    secs = []
    for i in range(nsec):
        o = opt + optsz + 40 * i
        vsize, va = struct.unpack_from("<II", hdr, o + 8)
        chars = struct.unpack_from("<I", hdr, o + 36)[0]
        if chars & 0x20000000 and vsize:                       # IMAGE_SCN_MEM_EXECUTE
            secs.append((va, vsize))
    exports = []
    if exp_rva and exp_size:
        try:
            ed = _read(h, base + exp_rva, 40)
            nfun, nnames, afun, anames, aords = struct.unpack_from("<IIIII", ed, 20)
            funs = struct.unpack(f"<{nfun}I", _read(h, base + afun, 4 * nfun)) if nfun else ()
            names = struct.unpack(f"<{nnames}I", _read(h, base + anames, 4 * nnames)) if nnames else ()
            ords = struct.unpack(f"<{nnames}H", _read(h, base + aords, 2 * nnames)) if nnames else ()
            for nrva, ordv in zip(names, ords):
                try:
                    nm = _read(h, base + nrva, 64).split(b"\0", 1)[0].decode("ascii", "replace")
                except OSError:
                    continue
                if ordv < len(funs) and not (exp_rva <= funs[ordv] < exp_rva + exp_size):   # not a forwarder
                    exports.append((funs[ordv], nm))
        except OSError:
            pass
    exports.sort()
    return secs, exports


def snapshot(pid, names=("ntdll.dll", "kernelbase.dll", "kernel32.dll")):
    """{path: (name, base, [(rva, bytes)], exports)} for every loaded module whose name is in
    names (lower case), executable sections only."""
    want = {n.lower() for n in names}
    h = _open(pid)
    try:
        snap = {}
        for name, path, base, size in modules(pid):
            if name not in want:
                continue
            secs, exports = _sections_and_exports(h, base)
            snap[path] = (name, base, [(rva, _read(h, base + rva, n)) for rva, n in secs], exports)
        return snap
    finally:
        k32.CloseHandle(h)


def _where(exports, rva):
    lo, hi, best = 0, len(exports), None
    while lo < hi:
        mid = (lo + hi) // 2
        if exports[mid][0] <= rva:
            best, lo = exports[mid], mid + 1
        else:
            hi = mid
    return f"{best[1]}+{rva - best[0]:#x}" if best else "?"


def code_diff(pid, snap, limit=12):
    """Differences between the target's executable sections now and in snap: a list of
    "ntdll.dll@SysWOW64+0x1234 (NtReadFile+0x0) cc->4c" strings (runs of differing bytes,
    at most limit), [] when identical. A module unloaded since the snapshot is not a diff."""
    h = _open(pid)
    out = []
    try:
        now = {path: base for _, path, base, _ in modules(pid)}
        for path, (name, base, secs, exports) in snap.items():
            if now.get(path) != base:
                continue
            tag = name + ("@SysWOW64" if "syswow64" in path else "")
            for rva, before in secs:
                after = _read(h, base + rva, len(before))
                if after == before:
                    continue
                i = 0
                while i < len(before) and len(out) < limit:
                    if before[i] == after[i]:
                        i += 1
                        continue
                    j = i
                    while j < len(before) and j - i < 16 and before[j] != after[j]:
                        j += 1
                    out.append(f"{tag}+{rva + i:#x} ({_where(exports, rva + i)}) "
                               f"{before[i:j].hex()}->{after[i:j].hex()}")
                    i = j
    finally:
        k32.CloseHandle(h)
    return out


def threads(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if not snap or snap == INVALID:
        raise OSError(f"thread snapshot failed: error {ctypes.get_last_error()}")
    out = []
    try:
        e = THREADENTRY32()
        e.dwSize = ctypes.sizeof(e)
        ok = k32.Thread32First(snap, ctypes.byref(e))
        while ok:
            if e.th32OwnerProcessID == pid:
                out.append(e.th32ThreadID)
            ok = k32.Thread32Next(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return out


def is_wow64(pid):
    h = _open(pid, PROCESS_QUERY_LIMITED)
    try:
        w = wintypes.BOOL(0)
        k32.IsWow64Process(h, ctypes.byref(w))
        return bool(w.value)
    finally:
        k32.CloseHandle(h)


def debug_regs(pid):
    """(dirty, unreadable, n_threads): dirty lists "tid:ctx dr7=.. dr0=.." for every thread
    with a non-zero DR7/DR0-3 or the trap flag, in its 64-bit context and (WoW64) its
    32-bit one. unreadable counts threads that could not be opened/read (gone or denied)."""
    wow = is_wow64(pid)
    raw = ctypes.create_string_buffer(0x4D0 + 16)
    ctx = (ctypes.addressof(raw) + 15) & ~15                   # CONTEXT is 16-byte aligned
    w32 = ctypes.create_string_buffer(0x2CC)
    dirty, unreadable, tids = [], 0, threads(pid)
    for tid in tids:
        th = k32.OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED, False, tid)
        if not th:
            unreadable += 1
            continue
        try:
            ctypes.memset(ctx, 0, 0x4D0)
            struct.pack_into("<I", (ctypes.c_char * 0x4D0).from_address(ctx), 0x30, 0x100011)  # AMD64|CONTROL|DEBUG
            if k32.GetThreadContext(th, ctypes.c_void_p(ctx)):
                b = ctypes.string_at(ctx, 0x4D0)
                eflags = struct.unpack_from("<I", b, 0x44)[0]
                d0, d1, d2, d3, d6, d7 = struct.unpack_from("<6Q", b, 0x48)
                if d7 or d0 or d1 or d2 or d3 or eflags & 0x100:
                    dirty.append(f"{tid}:ctx64 dr7={d7:#x} dr0-3={d0:#x},{d1:#x},{d2:#x},{d3:#x} tf={eflags >> 8 & 1}")
            else:
                unreadable += 1
            if wow:
                ctypes.memset(w32, 0, len(w32))
                struct.pack_into("<I", w32, 0, 0x10011)                                       # i386|CONTROL|DEBUG
                if k32.Wow64GetThreadContext(th, w32):
                    d0, d1, d2, d3, d6, d7 = struct.unpack_from("<6I", w32.raw, 4)
                    eflags = struct.unpack_from("<I", w32.raw, 0xC0)[0]
                    if d7 or d0 or d1 or d2 or d3 or eflags & 0x100:
                        dirty.append(f"{tid}:ctx32 dr7={d7:#x} dr0-3={d0:#x},{d1:#x},{d2:#x},{d3:#x} tf={eflags >> 8 & 1}")
        finally:
            k32.CloseHandle(th)
    return dirty, unreadable, len(tids)


def debugger_present(pid):
    h = _open(pid, PROCESS_QUERY_INFORMATION)
    try:
        b = wintypes.BOOL(0)
        if not k32.CheckRemoteDebuggerPresent(h, ctypes.byref(b)):
            raise OSError(f"CheckRemoteDebuggerPresent failed: error {ctypes.get_last_error()}")
        return bool(b.value)
    finally:
        k32.CloseHandle(h)


def mem(pid):
    """(private_bytes, working_set, handles), or None when the process is gone."""
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED | PROCESS_VM_READ, False, pid)
    if not h:
        return None
    try:
        m = PMC_EX()
        m.cb = ctypes.sizeof(m)
        if not psapi.GetProcessMemoryInfo(h, ctypes.byref(m), m.cb):
            return None
        hc = wintypes.DWORD(0)
        k32.GetProcessHandleCount(h, ctypes.byref(hc))
        return m.PrivateUsage, m.WorkingSetSize, hc.value
    finally:
        k32.CloseHandle(h)


def module_loaded(pid, name):
    try:
        return any(n == name.lower() for n, *_ in modules(pid, tries=5))
    except OSError:
        return None


def cpu_time(pid):
    """Kernel + user CPU seconds of a process, or None."""
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED, False, pid)
    if not h:
        return None
    try:
        t = [wintypes.FILETIME() for _ in range(4)]
        if not k32.GetProcessTimes(h, *[ctypes.byref(x) for x in t]):
            return None
        return sum((x.dwHighDateTime << 32 | x.dwLowDateTime) for x in t[2:]) / 1e7
    finally:
        k32.CloseHandle(h)
