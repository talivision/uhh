// child_exp -- the measurements behind docs/child-processes.md. Raw Win32 debug API, no UHH:
// each mode answers one question about following a target's child processes.
//
//   child_exp child                 the child: print {"kind":"child","pid":..,"main_qpc":..} at main
//   child_exp spawner N             create N children one after another (each awaited), no flags
//   child_exp suspended N           CREATE_SUSPENDED child, then DebugActiveProcess: does the attach
//                                   land before the child's first instruction? INT3 at its entry
//                                   point (written at the attach's CREATE_PROCESS event) must hit
//                                   on the main thread once it is resumed; how long does it take?
//   child_exp debugproc N           the spawner under DEBUG_PROCESS vs DEBUG_ONLY_THIS_PROCESS vs no
//                                   debugger: cost per child, and every child seen before it runs
//   child_exp job N                 the spawner in a job with a completion port: NEW_PROCESS
//                                   notification -> DebugActiveProcess; caught before main?
//   child_exp inherit N             ATTACH to the spawner, then set ProcessDebugFlags=1 (WinDbg's
//                                   .childdbg 1): are its children now debugged from creation?
//   child_exp inherit-drop N        same, detaching each child at its CREATE_PROCESS (a filter)
//   child_exp launch-inherit N      same on a DEBUG_ONLY_THIS_PROCESS launch (probe_launch's mode)
//   child_exp poll N                Toolhelp polled every ~1 ms (what probe_attach_new does) ->
//                                   DebugActiveProcess; caught before main?
//
// Every result is one JSON line. QPC is system-wide, so the child's main_qpc and the
// controller's timestamps are directly comparable.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <timeapi.h>
#include <intrin.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>
#pragma comment(lib, "winmm.lib")

static double g_freq_us;
static uint64_t qpc() { LARGE_INTEGER t{}; QueryPerformanceCounter(&t); return (uint64_t)t.QuadPart; }
static double us(uint64_t a, uint64_t b) { return ((double)(int64_t)(b - a)) / g_freq_us; }   // b - a in µs

static std::wstring self_path() {
    wchar_t p[MAX_PATH]; GetModuleFileNameW(nullptr, p, MAX_PATH); return p;
}

// Create `self <args>` with stdout/stderr = `out` (inheritable) and the given flags.
static bool spawn(const std::wstring &args, DWORD flags, HANDLE out, PROCESS_INFORMATION &pi) {
    std::wstring cmd = L"\"" + self_path() + L"\" " + args;
    STARTUPINFOW si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE); si.hStdOutput = out; si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    return CreateProcessW(self_path().c_str(), cmd.data(), nullptr, nullptr, TRUE, flags, nullptr, nullptr, &si, &pi) != 0;
}

static bool make_pipe(HANDLE &rd, HANDLE &wr) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    if (!CreatePipe(&rd, &wr, &sa, 1 << 20)) return false;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    return true;
}

static std::map<DWORD, int> g_child_debugger;   // pid -> IsDebuggerPresent() at its main
static std::map<DWORD, unsigned long> g_child_gflag;   // pid -> PEB NtGlobalFlag at its main
static unsigned long debug_heap_children() {
    unsigned long n = 0;
    for (auto &g : g_child_gflag) n += (g.second & 0x70) != 0;
    return n;
}

// pid -> main_qpc from the children's lines on a pipe (read after they exited).
static std::map<DWORD, uint64_t> read_children(HANDLE rd) {
    std::string all; char buf[4096]; DWORD got = 0;
    while (ReadFile(rd, buf, sizeof(buf), &got, nullptr) && got) all.append(buf, got);
    std::map<DWORD, uint64_t> out;
    for (size_t p = 0; (p = all.find("\"pid\":", p)) != std::string::npos; ++p) {
        DWORD pid = (DWORD)std::strtoul(all.c_str() + p + 6, nullptr, 10);
        size_t q = all.find("\"main_qpc\":", p);
        if (q != std::string::npos) out[pid] = std::strtoull(all.c_str() + q + 11, nullptr, 10);
        size_t d = all.find("\"debugger\":", p);
        if (d != std::string::npos) g_child_debugger[pid] = std::atoi(all.c_str() + d + 11);
        size_t g = all.find("\"ntglobalflag\":", p);
        if (g != std::string::npos) g_child_gflag[pid] = std::strtoul(all.c_str() + g + 15, nullptr, 10);
    }
    return out;
}

static void set_ip_back(DWORD tid) {
    HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
    if (t && GetThreadContext(t, &c)) {
#if defined(_WIN64)
        c.Rip -= 1;
#else
        c.Eip -= 1;
#endif
        SetThreadContext(t, &c);
    }
    if (t) CloseHandle(t);
}

static void close_event_handles(const DEBUG_EVENT &ev) {
    if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
    if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
}

static int child_main() {
    uint64_t t = qpc();
    // PEB->NtGlobalFlag: the loader sets the debug-heap flags (0x70: tail/free checking,
    // parameter validation) when a debugger was attached during process initialisation and
    // _NO_DEBUG_HEAP is not set -- the heap then behaves differently than without UHH.
#if defined(_WIN64)
    const unsigned long gflag = *(const unsigned long *)((const char *)__readgsqword(0x60) + 0xBC);
#else
    const unsigned long gflag = *(const unsigned long *)((const char *)__readfsdword(0x30) + 0x68);
#endif
    char line[200];
    int n = std::snprintf(line, sizeof(line), "{\"kind\":\"child\",\"pid\":%lu,\"main_qpc\":%llu,\"debugger\":%d,\"ntglobalflag\":%lu}\n",
                          GetCurrentProcessId(), (unsigned long long)t, IsDebuggerPresent() ? 1 : 0, gflag);
    DWORD w = 0; WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, (DWORD)n, &w, nullptr);
    return 0;
}

static int spawner_main(int n) {
    for (int i = 0; i < n; ++i) {
        PROCESS_INFORMATION pi{};
        if (!spawn(L"child", 0, GetStdHandle(STD_OUTPUT_HANDLE), pi)) return 1;
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    return 0;
}

static uint64_t image_entry(HANDLE process, uint64_t base) {
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{}; SIZE_T n = 0;
    if (!base || !ReadProcessMemory(process, (void *)(uintptr_t)base, &dos, sizeof(dos), &n) ||
        !ReadProcessMemory(process, (void *)(uintptr_t)(base + dos.e_lfanew), &nt, sizeof(nt), &n)) return 0;
    return base + nt.OptionalHeader.AddressOfEntryPoint;
}

// ---- suspended: CREATE_SUSPENDED + DebugActiveProcess --------------------------------
static int suspended_main(int trials) {
    DebugSetProcessKillOnExit(FALSE);
    std::vector<double> attach_us, breakin_us, resume_to_entry_us;
    int entry_on_main = 0, entry_before_main = 0, still_suspended = 0, ok_trials = 0;
    std::string firsts;
    for (int t = 0; t < trials; ++t) {
        HANDLE rd{}, wr{}; if (!make_pipe(rd, wr)) return 1;
        PROCESS_INFORMATION pi{};
        uint64_t t0 = qpc();
        if (!spawn(L"child", CREATE_SUSPENDED, wr, pi)) return 1;
        CloseHandle(wr);
        uint64_t t1 = qpc();
        if (!DebugActiveProcess(pi.dwProcessId)) {
            std::printf("{\"kind\":\"error\",\"what\":\"DebugActiveProcess on a suspended child\",\"err\":%lu}\n", GetLastError());
            return 1;
        }
        uint64_t t2 = qpc(), t_break = 0, t_resume = 0, t_entry = 0;
        uint64_t entry = 0, start_addr = 0; unsigned char orig = 0;
        int dlls_before_break = 0, threads_before_break = 0, breakpoints = 0; DWORD entry_tid = 0, prev = 0;
        std::string seq;
        bool done = false;
        while (!done) {
            DEBUG_EVENT ev{};
            if (!WaitForDebugEvent(&ev, 10000)) break;
            DWORD cont = DBG_CONTINUE;
            switch (ev.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                // An attach reports no start address for a thread that never ran: take the
                // image's entry point from its PE header.
                start_addr = (uint64_t)(uintptr_t)ev.u.CreateProcessInfo.lpStartAddress;
                entry = image_entry(pi.hProcess, (uint64_t)(uintptr_t)ev.u.CreateProcessInfo.lpBaseOfImage);
                if (entry) {
                    SIZE_T n = 0; unsigned char cc = 0xCC;
                    ReadProcessMemory(pi.hProcess, (void *)(uintptr_t)entry, &orig, 1, &n);
                    WriteProcessMemory(pi.hProcess, (void *)(uintptr_t)entry, &cc, 1, &n);
                    FlushInstructionCache(pi.hProcess, (void *)(uintptr_t)entry, 1);
                }
                if (t == 0) seq += "C";
                break;
            case LOAD_DLL_DEBUG_EVENT: if (!t_break) ++dlls_before_break; if (t == 0) seq += "L"; break;
            case CREATE_THREAD_DEBUG_EVENT: if (!t_break) ++threads_before_break; if (t == 0) seq += "T"; break;
            case EXCEPTION_DEBUG_EVENT: {
                auto &er = ev.u.Exception.ExceptionRecord;
                uint64_t at = (uint64_t)(uintptr_t)er.ExceptionAddress;
                if ((er.ExceptionCode == EXCEPTION_BREAKPOINT || er.ExceptionCode == 0x4000001F /*WOW64 bp*/) && at == entry && entry) {
                    t_entry = qpc(); entry_tid = ev.dwThreadId;
                    SIZE_T n = 0;
                    WriteProcessMemory(pi.hProcess, (void *)(uintptr_t)entry, &orig, 1, &n);
                    FlushInstructionCache(pi.hProcess, (void *)(uintptr_t)entry, 1);
                    set_ip_back(ev.dwThreadId);
                    if (t == 0) seq += "E";
                } else if (er.ExceptionCode == EXCEPTION_BREAKPOINT || er.ExceptionCode == 0x4000001F) {
                    ++breakpoints;
                    if (t == 0) seq += "B";
                    if (!t_break) {           // the attach's break-in: probes would be armed by now
                        t_break = qpc();
                        prev = ResumeThread(pi.hThread);   // 1 = the main thread had never run
                        t_resume = qpc();
                    }
                } else {
                    cont = DBG_EXCEPTION_NOT_HANDLED;
                    if (t == 0) seq += "X";
                }
                break;
            }
            case EXIT_PROCESS_DEBUG_EVENT: done = true; if (t == 0) seq += "Z"; break;
            default: break;
            }
            close_event_handles(ev);
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
        }
        DebugActiveProcessStop(pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, 5000);
        auto kids = read_children(rd); CloseHandle(rd);
        uint64_t main_qpc = kids.count(pi.dwProcessId) ? kids[pi.dwProcessId] : 0;
        if (t == 0) { firsts = seq; char b[64]; std::snprintf(b, sizeof(b), " start_address=0x%llx", (unsigned long long)start_addr); firsts += b; }
        if (t_break) { ++ok_trials; attach_us.push_back(us(t1, t2)); breakin_us.push_back(us(t1, t_break)); }
        if (t_entry) resume_to_entry_us.push_back(us(t_resume, t_entry));
        entry_on_main += t_entry && entry_tid == pi.dwThreadId;
        entry_before_main += t_entry && main_qpc && t_entry < main_qpc;
        still_suspended += prev == 1;
        (void)t0;
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    auto med = [](std::vector<double> v) { if (v.empty()) return -1.0; std::sort(v.begin(), v.end()); return v[v.size() / 2]; };
    auto mx = [](const std::vector<double> &v) { return v.empty() ? -1.0 : *std::max_element(v.begin(), v.end()); };
    std::printf("{\"kind\":\"suspended\",\"trials\":%d,\"attached\":%d,\"main_still_suspended_at_breakin\":%d,"
                "\"entry_int3_hit_on_main_thread\":%d,\"entry_hit_before_main\":%d,"
                "\"DebugActiveProcess_us_median\":%.0f,\"DebugActiveProcess_us_max\":%.0f,"
                "\"create_to_breakin_us_median\":%.0f,\"create_to_breakin_us_max\":%.0f,"
                "\"resume_to_entry_us_median\":%.0f,\"children_with_debug_heap\":%lu,\"event_sequence_trial0\":\"%s\"}\n",
                trials, ok_trials, still_suspended, entry_on_main, entry_before_main,
                med(attach_us), mx(attach_us), med(breakin_us), mx(breakin_us), med(resume_to_entry_us), debug_heap_children(), firsts.c_str());
    return ok_trials == trials ? 0 : 1;
}

// ---- debugproc: DEBUG_PROCESS vs DEBUG_ONLY_THIS_PROCESS vs none ---------------------
static int debugproc_main(int n) {
    struct Mode { const char *name; DWORD flags; } modes[] = {
        {"none", 0}, {"DEBUG_ONLY_THIS_PROCESS", DEBUG_ONLY_THIS_PROCESS}, {"DEBUG_PROCESS", DEBUG_PROCESS}};
    for (auto &m : modes) {
        HANDLE rd{}, wr{}; if (!make_pipe(rd, wr)) return 1;
        PROCESS_INFORMATION pi{};
        uint64_t t0 = qpc();
        if (!spawn(L"spawner " + std::to_wstring(n), m.flags, wr, pi)) return 1;
        CloseHandle(wr);
        std::map<DWORD, uint64_t> created;        // pid -> CREATE_PROCESS event qpc
        int events = 0, exits = 0;
        if (m.flags) {
            for (bool done = false; !done; ) {
                DEBUG_EVENT ev{};
                if (!WaitForDebugEvent(&ev, 30000)) break;
                ++events;
                DWORD cont = DBG_CONTINUE;
                if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) created[ev.dwProcessId] = qpc();
                if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                    DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
                    if (code != EXCEPTION_BREAKPOINT && code != 0x4000001F) cont = DBG_EXCEPTION_NOT_HANDLED;
                }
                if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                    ++exits;
                    if (ev.dwProcessId == pi.dwProcessId) done = true;
                }
                close_event_handles(ev);
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
            }
        }
        WaitForSingleObject(pi.hProcess, 60000);
        uint64_t t1 = qpc();
        auto kids = read_children(rd); CloseHandle(rd);
        int seen_before_main = 0;
        for (auto &k : kids) if (created.count(k.first) && created[k.first] < k.second) ++seen_before_main;
        std::printf("{\"kind\":\"debugproc\",\"mode\":\"%s\",\"children\":%zu,\"processes_seen\":%zu,"
                    "\"children_seen_before_main\":%d,\"debug_events\":%d,\"exits_seen\":%d,\"total_ms\":%.1f,\"per_child_ms\":%.2f,\"children_with_debug_heap\":%lu}\n",
                    m.name, kids.size(), created.size(), seen_before_main, events, exits, us(t0, t1) / 1000.0,
                    us(t0, t1) / 1000.0 / (n ? n : 1), debug_heap_children());
        g_child_gflag.clear();
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    return 0;
}

// Attach to pid, consume its events through the attach break-in, detach. Returns the qpc at
// which the debugger had control (0 = attach failed).
static uint64_t attach_and_release(DWORD pid) {
    if (!DebugActiveProcess(pid)) return 0;
    uint64_t at = 0;
    for (int guard = 0; guard < 1000; ++guard) {
        DEBUG_EVENT ev{};
        if (!WaitForDebugEvent(&ev, 2000)) break;
        DWORD cont = DBG_CONTINUE; bool stop = false;
        if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && !at) at = qpc();   // process frozen from here
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            if (code == EXCEPTION_BREAKPOINT || code == 0x4000001F) stop = true; else cont = DBG_EXCEPTION_NOT_HANDLED;
        }
        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) stop = true;
        close_event_handles(ev);
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
        if (stop) break;
    }
    DebugActiveProcessStop(pid);
    return at;
}

static void report_race(const char *mode, int n, const std::vector<std::pair<DWORD, std::pair<uint64_t, uint64_t>>> &seen,
                        const std::map<DWORD, uint64_t> &kids) {
    int before = 0, after = 0, missed = 0, failed = 0; std::vector<double> lead;
    for (auto &k : kids) {
        auto it = std::find_if(seen.begin(), seen.end(), [&](auto &s) { return s.first == k.first; });
        if (it == seen.end()) { ++missed; continue; }
        uint64_t attached = it->second.second;
        if (!attached) { ++failed; continue; }
        double d = us(attached, k.second);     // > 0: the debugger had the child before its main
        lead.push_back(d);
        (d > 0 ? before : after)++;
    }
    std::sort(lead.begin(), lead.end());
    std::printf("{\"kind\":\"%s\",\"children\":%zu,\"attached_before_main\":%d,\"attached_after_main\":%d,"
                "\"not_detected\":%d,\"attach_failed\":%d,\"lead_us_min\":%.0f,\"lead_us_median\":%.0f,\"lead_us_max\":%.0f,\"n\":%d,\"children_with_debug_heap\":%lu}\n",
                mode, kids.size(), before, after, missed, failed, lead.empty() ? 0 : lead.front(),
                lead.empty() ? 0 : lead[lead.size() / 2], lead.empty() ? 0 : lead.back(), n, debug_heap_children());
}

// ---- job: completion-port NEW_PROCESS notification -> attach ------------------------
static int job_main(int n) {
    DebugSetProcessKillOnExit(FALSE);
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    HANDLE port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT acp{}; acp.CompletionKey = job; acp.CompletionPort = port;
    if (!job || !port || !SetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &acp, sizeof(acp))) return 1;
    HANDLE rd{}, wr{}; if (!make_pipe(rd, wr)) return 1;
    PROCESS_INFORMATION pi{};
    if (!spawn(L"spawner " + std::to_wstring(n), CREATE_SUSPENDED, wr, pi)) return 1;
    CloseHandle(wr);
    if (!AssignProcessToJobObject(job, pi.hProcess)) { std::printf("{\"kind\":\"error\",\"what\":\"assign job\",\"err\":%lu}\n", GetLastError()); return 1; }
    ResumeThread(pi.hThread);
    std::vector<std::pair<DWORD, std::pair<uint64_t, uint64_t>>> seen;   // pid -> (notified, attached)
    for (;;) {
        DWORD msg = 0; ULONG_PTR key = 0; LPOVERLAPPED ov = nullptr;
        if (!GetQueuedCompletionStatus(port, &msg, &key, &ov, 30000)) break;
        if (msg == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO) break;
        if (msg != JOB_OBJECT_MSG_NEW_PROCESS) continue;
        DWORD pid = (DWORD)(ULONG_PTR)ov;
        if (pid == pi.dwProcessId) continue;
        uint64_t notified = qpc();
        seen.push_back({pid, {notified, attach_and_release(pid)}});
    }
    WaitForSingleObject(pi.hProcess, 30000);
    report_race("job", n, seen, read_children(rd));
    CloseHandle(rd); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(port); CloseHandle(job);
    return 0;
}

// ---- poll: Toolhelp every ~1 ms (probe_attach_new) -> attach ------------------------
static int poll_main(int n) {
    DebugSetProcessKillOnExit(FALSE);
    timeBeginPeriod(1);
    HANDLE rd{}, wr{}; if (!make_pipe(rd, wr)) return 1;
    PROCESS_INFORMATION pi{};
    if (!spawn(L"spawner " + std::to_wstring(n), 0, wr, pi)) return 1;
    CloseHandle(wr);
    std::set<DWORD> known;
    std::vector<std::pair<DWORD, std::pair<uint64_t, uint64_t>>> seen;
    while (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        for (BOOL more = Process32FirstW(snap, &pe); more; more = Process32NextW(snap, &pe))
            if (pe.th32ParentProcessID == pi.dwProcessId && known.insert(pe.th32ProcessID).second) {
                uint64_t notified = qpc();
                seen.push_back({pe.th32ProcessID, {notified, attach_and_release(pe.th32ProcessID)}});
            }
        CloseHandle(snap);
        Sleep(1);
    }
    timeEndPeriod(1);
    report_race("poll", n, seen, read_children(rd));
    CloseHandle(rd); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}

// ---- inherit: turn child-following on for an ATTACHED (or DEBUG_ONLY_THIS_PROCESS) target -----
// ProcessDebugFlags (31) reads 0 when the debug port is NOT inherited by children (attach,
// DEBUG_ONLY_THIS_PROCESS) and 1 when it is (DEBUG_PROCESS). Setting it to 1 from the
// debugger is WinDbg's `.childdbg 1`. drop=1: detach every child at its CREATE_PROCESS event
// (a "do not follow this one" filter) and see what the child observes.
using NtQIP = LONG (NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using NtSIP = LONG (NTAPI *)(HANDLE, ULONG, void *, ULONG);
static int inherit_main(int n, bool launch, bool drop) {
    auto q = (NtQIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    auto set = (NtSIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess");
    DebugSetProcessKillOnExit(FALSE);
    HANDLE rd{}, wr{}; if (!make_pipe(rd, wr)) return 1;
    PROCESS_INFORMATION pi{};
    if (!spawn(L"spawner " + std::to_wstring(n), launch ? DEBUG_ONLY_THIS_PROCESS : CREATE_SUSPENDED, wr, pi)) return 1;
    CloseHandle(wr);
    if (!launch && !DebugActiveProcess(pi.dwProcessId)) return 1;
    ULONG before = 99, after = 99; LONG st_set = -1;
    q(pi.hProcess, 31, &before, sizeof(before), nullptr);
    ULONG one = 1; st_set = set(pi.hProcess, 31, &one, sizeof(one));
    q(pi.hProcess, 31, &after, sizeof(after), nullptr);
    if (!launch) ResumeThread(pi.hThread);
    std::map<DWORD, uint64_t> created; int exits = 0, dropped = 0; bool root_gone = false;
    std::set<DWORD> live;
    for (;;) {
        DEBUG_EVENT ev{};
        if (!WaitForDebugEvent(&ev, 30000)) break;
        DWORD cont = DBG_CONTINUE; bool detach_now = false;
        if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            created[ev.dwProcessId] = qpc(); live.insert(ev.dwProcessId);
            if (drop && ev.dwProcessId != pi.dwProcessId) detach_now = true;
        }
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            if (code != EXCEPTION_BREAKPOINT && code != 0x4000001F) cont = DBG_EXCEPTION_NOT_HANDLED;
        }
        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            ++exits; live.erase(ev.dwProcessId);
            if (ev.dwProcessId == pi.dwProcessId) root_gone = true;
        }
        close_event_handles(ev);
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
        if (detach_now) { if (DebugActiveProcessStop(ev.dwProcessId)) ++dropped; live.erase(ev.dwProcessId); }
        if (root_gone && live.empty()) break;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    auto kids = read_children(rd); CloseHandle(rd);
    int seen_before_main = 0, saw_debugger = 0;
    for (auto &k : kids) {
        if (created.count(k.first) && created[k.first] < k.second) ++seen_before_main;
        saw_debugger += g_child_debugger[k.first];
    }
    DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);
    std::printf("{\"kind\":\"inherit\",\"root\":\"%s\",\"drop_children\":%d,\"debug_flags_before\":%lu,\"set_status\":\"0x%lx\","
                "\"debug_flags_after\":%lu,\"children\":%zu,\"children_seen\":%zu,\"seen_before_main\":%d,"
                "\"children_detached\":%d,\"children_that_saw_a_debugger\":%d,\"children_with_debug_heap\":%lu,\"exits_seen\":%d,\"root_exit\":%lu}\n",
                launch ? "DEBUG_ONLY_THIS_PROCESS launch" : "attach", drop ? 1 : 0, before, (unsigned long)st_set, after,
                kids.size(), created.size() ? created.size() - 1 : 0, seen_before_main, dropped, saw_debugger, debug_heap_children(), exits, code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}

int main(int argc, char **argv) {
    LARGE_INTEGER f{}; QueryPerformanceFrequency(&f); g_freq_us = (double)f.QuadPart / 1e6;
    if (argc >= 2 && !std::strcmp(argv[1], "child")) return child_main();
    int n = argc >= 3 ? std::atoi(argv[2]) : 20;
    if (argc >= 2 && !std::strcmp(argv[1], "spawner")) return spawner_main(n);
    if (argc >= 2 && !std::strcmp(argv[1], "suspended")) return suspended_main(n);
    if (argc >= 2 && !std::strcmp(argv[1], "debugproc")) return debugproc_main(n);
    if (argc >= 2 && !std::strcmp(argv[1], "job")) return job_main(n);
    if (argc >= 2 && !std::strcmp(argv[1], "poll")) return poll_main(n);
    if (argc >= 2 && !std::strcmp(argv[1], "inherit")) return inherit_main(n, false, false);
    if (argc >= 2 && !std::strcmp(argv[1], "inherit-drop")) return inherit_main(n, false, true);
    if (argc >= 2 && !std::strcmp(argv[1], "launch-inherit")) return inherit_main(n, true, false);
    std::fprintf(stderr, "usage: child_exp child | spawner N | suspended N | debugproc N | job N | poll N | inherit N | inherit-drop N | launch-inherit N\n");
    return 2;
}
