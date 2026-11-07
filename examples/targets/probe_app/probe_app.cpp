// probe_app: the target the gated_config and attach examples instrument.
//
//   probe_app [--helpers N] [--threads W] [--reads R] [--pace P] [--prehook] [--config k=v;...] [--no-wait]
//             [--until-key]
//
// 1. Spawn N helper processes (probe_app --helper). Each holds the same known 256-byte
//    buffer (byte j == j) at the same address and prints nothing; probe_app prints one
//    {"kind":"helper","index":k,"pid":..,"base":..,"size":256} line per helper.
// 2. Print {"kind":"waiting","pid":<own pid>,...} and block until one byte/keystroke on
//    stdin (the gate). --no-wait skips it.
// 3. LoadLibrary configparse.dll (late; never a static import) and ParseConfig. The
//    shipped config is reads_enabled=0: the feature is OFF and the run ends here with
//    no opens and no reads. Only a probe at configparse.dll!ParseConfig+0x16 that flips
//    the parsed flag turns it on.
// 4. Flag on: enumerate every PID on the system (Toolhelp), pick out our helpers, open
//    each one BY PID with PROCESS_VM_READ via ntdll!NtOpenProcess -- so a probe there
//    sees every handle being created -- then W threads x R reads of the helpers' buffers via
//    NtReadVirtualMemory, through the hookable ReadThunk (exported, probe_app.exe!ReadThunk).
//    Every read is verified; totals are reported as one {"kind":"app",...} JSON line.
//
// --pace P caps each read thread at about P reads per second (it sleeps when ahead of
// schedule), so a long soak (scripts/soak.py) runs at a steady, sustainable rate for as long
// as R / P seconds. Pacing changes only the timing: the reads, and the checksum, are the same.
//
// --until-key repeats the read phase (W x R reads, the same pattern each round) until a second
// byte/keystroke arrives on stdin after the gate, so a test can keep the threads reading for
// as long as it needs regardless of machine speed. The app line reports "rounds"; the reads
// and the checksum are exactly rounds x one round's. The same W threads read every round (a
// blocking barrier between rounds): some thread is reading at every moment (run_read_rounds).
//
// Read pattern (deterministic, so a filter on one pid + one address range selects an
// exactly predictable count): global read i = t*R + k (thread t, its k-th read) reads
// 16 bytes from helper (i % N) at base + 64 * ((i / N) % 4).
//
// --churn (with --truth FILE): the end-to-end ground-truth workload (regress gated-e2e-*).
// Instead of long-lived handles, the helpers are opened, read and closed over and over --
// handle VALUES are reused for different pids -- first serially, then from W threads at
// once (R rounds each): open (alternately ntdll!NtOpenProcess through OpenThunk and
// kernel32!OpenProcess), 1-4 reads of varying sizes (1..256 bytes; alternately ReadThunk
// and kernel32!ReadProcessMemory: both end in ntdll!NtReadVirtualMemory), CloseHandle
// (ntdll!NtClose). Every operation is recorded by the thread that made it (tid, handle, pid,
// address, size; a global sequence number: an open after it returned, a close before it
// starts) and written to FILE as JSON lines in sequence order at the end. Every third cycle
// also reads once through a DUPLICATE of the helper's process handle (op "dup", then
// "read-unmapped"): a handle the open probe never saw, usually with the value just closed. The schedule and
// the checksum (sum of every byte read) are deterministic, so an uninstrumented run gives
// the same checksum.
// --parse-early: load configparse.dll and parse the config once BEFORE the gate too (its
// result is printed as {"kind":"parsed","phase":"early",...} and otherwise ignored), and
// again after it: a tool that attaches at the gate finds configparse.dll already loaded and
// already parsed once, and only the second parse decides the feature.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <immintrin.h>
#include <tlhelp32.h>
#include <algorithm>
#include <atomic>
#include <barrier>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <safetyhook.hpp>
#include "configparse.h"

using NtRead = LONG (NTAPI *)(HANDLE, const void *, void *, SIZE_T, SIZE_T *);
struct ObjectAttributes { ULONG Length; HANDLE RootDirectory; void *ObjectName; ULONG Attributes;
                          void *SecurityDescriptor; void *SecurityQualityOfService; };
struct ClientId { HANDLE UniqueProcess, UniqueThread; };
using NtOpen = LONG (NTAPI *)(HANDLE *, ACCESS_MASK, ObjectAttributes *, ClientId *);
extern "C" {
    NtRead g_ntread = nullptr;
    NtOpen g_ntopen = nullptr;
    LONG NTAPI ReadThunk(HANDLE, const void *, void *, SIZE_T, SIZE_T *);
    LONG NTAPI OpenThunk(HANDLE *, ACCESS_MASK, ObjectAttributes *, ClientId *);   // probe_app.exe!OpenThunk
}

static void require(bool ok, const std::string &what) {
    if (!ok) throw std::runtime_error(what + " (Win32=" + std::to_string(GetLastError()) + ")");
}

static std::string exe_path() {
    char p[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr, p, MAX_PATH);
    require(n && n < MAX_PATH, "executable path");
    return p;
}

static std::string exe_directory() {
    std::string s = exe_path(); return s.substr(0, s.find_last_of("\\/") + 1);
}

// --- Optional pre-existing hook on the read site (--prehook) ----------------------
static SafetyHookInline prehook;
static std::atomic<uint64_t> prehook_calls{0};
static LONG NTAPI pre_read(HANDLE h, const void *a, void *b, SIZE_T n, SIZE_T *done) {
    prehook_calls.fetch_add(1, std::memory_order_relaxed);
    // ReadThunk is NTAPI (__stdcall on x86): through call<> (cdecl) the callee pops its 20
    // bytes of arguments and the caller does too -- x86 --prehook hung/crashed with no tool at all.
    return prehook.stdcall<LONG>(h, a, b, n, done);
}

// --- Helpers ------------------------------------------------------------------------
constexpr unsigned kBufferSize = 256, kReadSize = 16, kStride = 64, kOffsets = 4;

struct Hello { uint64_t address; uint32_t pid; uint32_t reserved; };

// A child process holding the known buffer until probe_app signals it to exit.
struct Helper {
    PROCESS_INFORMATION pi{}; HANDLE finish{}; Hello hello{};
    HANDLE read_handle{};   // from OpenProcess(PROCESS_VM_READ, pid), used for every read
    ~Helper() {
        if (read_handle) CloseHandle(read_handle);
        if (finish) { SetEvent(finish); WaitForSingleObject(pi.hProcess, 5000); CloseHandle(finish); }
        if (pi.hThread) CloseHandle(pi.hThread);
        if (pi.hProcess) CloseHandle(pi.hProcess);
    }
    void start() {
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE}; HANDLE rd{}, wr{};
        require(!!CreatePipe(&rd, &wr, &sa, 0), "pipe"); SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
        finish = CreateEventA(&sa, TRUE, FALSE, nullptr); require(finish != nullptr, "event");
        STARTUPINFOA si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = wr; si.hStdError = GetStdHandle(STD_ERROR_HANDLE); si.hStdInput = nullptr;
        // The helper also watches this process: it exits with it (no fixed timeout, so a
        // soak may read it for hours) and never outlives a killed probe_app.
        HANDLE parent{};
        require(!!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &parent,
                                  SYNCHRONIZE, TRUE, 0), "parent handle");
        std::string exe = exe_path();
        std::string command = "\"" + exe + "\" --helper " + std::to_string((uintptr_t)finish) + " " +
                              std::to_string((uintptr_t)parent);
        // Only the pipe and event are inherited; no DEBUG_* flags, so a debugger on
        // probe_app does not follow the helpers.
        BOOL ok = CreateProcessA(exe.c_str(), command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi);
        CloseHandle(wr); CloseHandle(parent); if (!ok) { CloseHandle(rd); require(false, "helper launch"); }
        DWORD got = 0; BOOL read = ReadFile(rd, &hello, sizeof(hello), &got, nullptr); CloseHandle(rd);
        require(read && got == sizeof(hello) && hello.pid == pi.dwProcessId, "helper handshake");
        SetHandleInformation(finish, HANDLE_FLAG_INHERIT, 0);
    }
};

static int helper_main(const char *finish_handle, const char *parent_handle) {
    static unsigned char data[kBufferSize];
    for (unsigned i = 0; i < kBufferSize; ++i) data[i] = (unsigned char)i;
    Hello h{(uint64_t)(uintptr_t)data, GetCurrentProcessId(), 0}; DWORD n{};
    require(!!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &h, sizeof(h), &n, nullptr) && n == sizeof(h), "helper write");
    // Until probe_app says so (finish), or probe_app is gone. An old-style launch without the
    // parent handle keeps the former 10-minute safety timeout.
    HANDLE wait[2] = {(HANDLE)(uintptr_t)_strtoui64(finish_handle, nullptr, 10),
                      parent_handle ? (HANDLE)(uintptr_t)_strtoui64(parent_handle, nullptr, 10) : nullptr};
    DWORD r = WaitForMultipleObjects(parent_handle ? 2 : 1, wait, FALSE, parent_handle ? INFINITE : 600000);
    return r == WAIT_OBJECT_0 ? 0 : 2;
}

// Find our helpers among ALL processes on the system, then open each one by PID.
// The open calls ntdll!NtOpenProcess directly (OpenProcess(PROCESS_VM_READ, pid) is the
// same syscall) so that its out-handle pointer is a long-lived variable: a probe on
// NtOpenProcess remembers that pointer at entry and can dereference it any time later
// to learn which handle the open produced. Through kernel32!OpenProcess the pointer
// would be a stack local of kernelbase, reused as soon as OpenProcess returns.
// --open-via kernel32: open through kernel32!OpenProcess instead, whose out-handle slot is a
// short-lived stack local of kernelbase (the case a lazy out-pointer map cannot resolve).
static bool g_open_kernel32 = false;
static void open_helpers(std::vector<Helper> &helpers) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    require(snap != INVALID_HANDLE_VALUE, "process snapshot");
    std::vector<DWORD> found;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    for (BOOL more = Process32FirstW(snap, &pe); more; more = Process32NextW(snap, &pe))
        if (pe.th32ParentProcessID == GetCurrentProcessId()) found.push_back(pe.th32ProcessID);
    CloseHandle(snap);
    for (auto &h : helpers) {
        bool listed = false;
        for (DWORD pid : found) listed = listed || pid == h.hello.pid;
        require(listed, "helper " + std::to_string(h.hello.pid) + " not in the process list");
    }
    for (auto &h : helpers) {
        // ntdll!NtOpenProcess(PHANDLE out, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID):
        // what kernel32!OpenProcess(PROCESS_VM_READ, FALSE, pid) does, but with the
        // out-handle pointing at h.read_handle, which lives as long as the helper.
        if (g_open_kernel32) {
            h.read_handle = OpenProcess(PROCESS_VM_READ, FALSE, h.hello.pid);
            require(h.read_handle != nullptr, "OpenProcess helper");
            continue;
        }
        ObjectAttributes oa{sizeof(oa)};
        ClientId cid{(HANDLE)(uintptr_t)h.hello.pid, nullptr};
        require(OpenThunk(&h.read_handle, PROCESS_VM_READ, &oa, &cid) >= 0 && h.read_handle, "NtOpenProcess helper");
    }
}

// --- Gate -------------------------------------------------------------------------
// One keystroke. Interactive console: raw mode, any key. Pipe/file: one byte.
static bool wait_for_key() {
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(in, &mode)) {
        SetConsoleMode(in, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));
        for (;;) {
            INPUT_RECORD r{}; DWORD got = 0;
            if (!ReadConsoleInputA(in, &r, 1, &got)) return false;
            if (got && r.EventType == KEY_EVENT && r.Event.KeyEvent.bKeyDown) break;
        }
        SetConsoleMode(in, mode);
        return true;
    }
    char c; DWORD got = 0;
    return ReadFile(in, &c, 1, &got, nullptr) && got == 1;
}

// --- Reads ------------------------------------------------------------------------
struct ThreadResult { uint64_t success = 0, checksum = 0; std::string error; };

static uint64_t g_pace = 0;   // --pace: reads per second per thread (0 = as fast as possible)

static uint64_t qpc_now() { LARGE_INTEGER t{}; QueryPerformanceCounter(&t); return (uint64_t)t.QuadPart; }

static void read_worker(std::vector<Helper> &helpers, uint64_t t, uint64_t reads, ThreadResult &r) {
    const uint64_t n = helpers.size();
    LARGE_INTEGER freq{}; QueryPerformanceFrequency(&freq);
    const uint64_t start = qpc_now();
    for (uint64_t k = 0; k < reads; ++k) {
        if (g_pace && (k & 15) == 0) {          // ahead of schedule: sleep until read k is due
            const double due = (double)k / (double)g_pace;
            while ((double)(qpc_now() - start) / (double)freq.QuadPart < due) Sleep(1);
        }
        uint64_t i = t * reads + k;
        Helper &h = helpers[(size_t)(i % n)];
        unsigned offset = kStride * (unsigned)((i / n) % kOffsets);
        unsigned char buffer[kReadSize]{}; SIZE_T bytes = 0;
        LONG status = ReadThunk(h.read_handle, (const void *)(uintptr_t)(h.hello.address + offset),
                                buffer, sizeof(buffer), &bytes);
        bool ok = status >= 0 && bytes == sizeof(buffer);
        for (unsigned j = 0; ok && j < sizeof(buffer); ++j) ok = buffer[j] == (unsigned char)(offset + j);
        if (!ok) { r.error = "read " + std::to_string(i) + " failed"; return; }
        ++r.success; r.checksum += buffer[0];
    }
}

// --- Churn (--churn): open / read / close over and over, with the target's own record ---
struct TruthRec { uint64_t seq; char op; DWORD tid; uint64_t handle; DWORD pid; uint64_t addr; unsigned size; };
static std::atomic<uint64_t> g_seq{0};
constexpr unsigned kChurnSizes[] = {1, 3, 8, 16, 17, 64, 100, 128, 200, 255, 256};
constexpr unsigned kChurnSizeCount = sizeof(kChurnSizes) / sizeof(kChurnSizes[0]);

struct ChurnResult { uint64_t reads = 0, opens = 0, checksum = 0; std::vector<TruthRec> log; std::string error; };

static HANDLE churn_open(const Helper &h, bool via_kernel32, ChurnResult &r) {
    HANDLE out{};
    if (via_kernel32) out = OpenProcess(PROCESS_VM_READ, FALSE, h.hello.pid);
    else {
        ObjectAttributes oa{sizeof(oa)};
        ClientId cid{(HANDLE)(uintptr_t)h.hello.pid, nullptr};
        if (OpenThunk(&out, PROCESS_VM_READ, &oa, &cid) < 0) out = nullptr;
    }
    if (!out) { r.error = "open of helper " + std::to_string(h.hello.pid) + " failed"; return nullptr; }
    r.log.push_back({g_seq.fetch_add(1), 'O', GetCurrentThreadId(), (uint64_t)(uintptr_t)out, h.hello.pid, 0, 0});
    ++r.opens;
    return out;
}

static void churn_close(HANDLE handle, const Helper &h, ChurnResult &r) {
    // Recorded BEFORE the close: once it returns, another thread's open may get this value.
    r.log.push_back({g_seq.fetch_add(1), 'C', GetCurrentThreadId(), (uint64_t)(uintptr_t)handle, h.hello.pid, 0, 0});
    if (!CloseHandle(handle) && r.error.empty()) r.error = "close failed";
}

static bool churn_read(const Helper &h, HANDLE handle, unsigned size, unsigned off, bool via_kernel32, ChurnResult &r) {
    unsigned char buffer[kBufferSize]{}; SIZE_T got = 0;
    const uint64_t addr = h.hello.address + off;
    LONG status = via_kernel32 ? (ReadProcessMemory(handle, (const void *)(uintptr_t)addr, buffer, size, &got) ? 0 : -1)
                               : ReadThunk(handle, (const void *)(uintptr_t)addr, buffer, size, &got);
    bool ok = status >= 0 && got == size;
    for (unsigned j = 0; ok && j < size; ++j) ok = buffer[j] == (unsigned char)(off + j);
    if (!ok) { r.error = "churn read of " + std::to_string(size) + " at +" + std::to_string(off) + " failed"; return false; }
    for (unsigned j = 0; j < size; ++j) r.checksum += buffer[j];
    r.log.push_back({g_seq.fetch_add(1), 'R', GetCurrentThreadId(), (uint64_t)(uintptr_t)handle, h.hello.pid, addr, size});
    ++r.reads;
    return true;
}

// One open -> reads -> close cycle of helper `h`; the schedule depends only on (t, round).
static bool churn_cycle(const Helper &h, uint64_t t, uint64_t round, ChurnResult &r) {
    HANDLE handle = churn_open(h, ((t + round) & 1) != 0, r);
    if (!handle) return false;
    const unsigned nreads = 1 + (unsigned)((t * 5 + round * 3) % 4);
    bool ok = true;
    for (unsigned k = 0; ok && k < nreads; ++k) {
        const unsigned size = kChurnSizes[(t * 7 + round * 5 + k * 3) % kChurnSizeCount];
        const unsigned off = (unsigned)(((t * 29 + round * 13 + k * 7) * 37) % (kBufferSize - size + 1));
        ok = churn_read(h, handle, size, off, ((k + round) & 1) != 0, r);
    }
    churn_close(handle, h, r);
    // Every third cycle: a handle the open probe never sees -- a duplicate of the helper's
    // CreateProcess handle (ntdll!NtDuplicateObject, not NtOpenProcess) -- usually gets the
    // value just closed, which the map knew for some pid. One read through it must be logged
    // as UNMAPPED (pid 0): only the close probe forgetting the old value makes that so.
    if (ok && (t + round) % 3 == 0) {
        HANDLE dup{};
        if (!DuplicateHandle(GetCurrentProcess(), h.pi.hProcess, GetCurrentProcess(), &dup, PROCESS_VM_READ, FALSE, 0) || !dup) {
            r.error = "duplicate of a helper handle failed"; return false;
        }
        r.log.push_back({g_seq.fetch_add(1), 'D', GetCurrentThreadId(), (uint64_t)(uintptr_t)dup, h.hello.pid, 0, 0});
        const unsigned size = kChurnSizes[(t + round) % kChurnSizeCount];
        ok = churn_read(h, dup, size, (unsigned)((t * 11 + round) % (kBufferSize - size + 1)), (round & 1) != 0, r);
        if (ok) r.log.back().op = 'U';                       // a read through an unmapped handle
        churn_close(dup, h, r);
    }
    return ok && r.error.empty();
}

// Serial phase (this thread: open/read/close each helper twice -- a freed handle value is
// handed out again at once, so it is reused for the next helper's pid), then W threads x
// R rounds at once. Returns the merged result; the truth file is written in seq order.
static ChurnResult run_churn(std::vector<Helper> &helpers, size_t threads, uint64_t rounds, const std::string &truth) {
    const uint64_t n = helpers.size();
    ChurnResult serial;
    for (uint64_t k = 0; k < 2 * n && serial.error.empty(); ++k)
        churn_cycle(helpers[(size_t)(k % n)], 1000 + k, k, serial);
    std::vector<ChurnResult> results(threads);
    if (serial.error.empty()) {
        std::atomic<size_t> ready{0}; std::atomic<bool> go{false};
        std::vector<std::thread> pool;
        for (size_t t = 0; t < threads; ++t) pool.emplace_back([&, t] {
            ready.fetch_add(1); while (!go.load(std::memory_order_acquire)) YieldProcessor();
            for (uint64_t round = 0; round < rounds; ++round)
                if (!churn_cycle(helpers[(size_t)((t * 3 + round) % n)], t, round, results[t])) break;
        });
        while (ready.load() != threads) YieldProcessor();
        go.store(true, std::memory_order_release);
        for (auto &th : pool) th.join();
    }
    ChurnResult all = std::move(serial);
    for (auto &r : results) {
        if (all.error.empty() && !r.error.empty()) all.error = r.error;
        all.reads += r.reads; all.opens += r.opens; all.checksum += r.checksum;
        all.log.insert(all.log.end(), r.log.begin(), r.log.end());
    }
    std::sort(all.log.begin(), all.log.end(), [](const TruthRec &a, const TruthRec &b) { return a.seq < b.seq; });
    if (FILE *f = std::fopen(truth.c_str(), "wb")) {
        for (const auto &e : all.log)
            std::fprintf(f, "{\"seq\":%llu,\"op\":\"%s\",\"tid\":%lu,\"handle\":%llu,\"pid\":%lu,\"addr\":%llu,\"size\":%u}\n",
                         (unsigned long long)e.seq, e.op == 'O' ? "open" : e.op == 'R' ? "read" : e.op == 'U' ? "read-unmapped" : e.op == 'D' ? "dup" : "close",
                         (unsigned long)e.tid, (unsigned long long)e.handle, (unsigned long)e.pid,
                         (unsigned long long)e.addr, e.size);
        std::fclose(f);
    } else if (all.error.empty()) {
        all.error = "cannot write " + truth;
    }
    return all;
}

// W threads released together; returns the elapsed time of the read phase.
static double run_reads(std::vector<Helper> &helpers, size_t threads, uint64_t reads,
                        std::vector<ThreadResult> &results) {
    results.assign(threads, {});
    std::atomic<size_t> ready{0}; std::atomic<bool> go{false};
    std::vector<std::thread> pool;
    for (size_t t = 0; t < threads; ++t) pool.emplace_back([&, t] {
        ready.fetch_add(1); while (!go.load(std::memory_order_acquire)) YieldProcessor();
        read_worker(helpers, t, reads, results[t]);
    });
    while (ready.load() != threads) YieldProcessor();
    LARGE_INTEGER f{}, begin{}, end{}; QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&begin);
    go.store(true, std::memory_order_release);
    for (auto &th : pool) th.join();
    QueryPerformanceCounter(&end);
    return (double)(end.QuadPart - begin.QuadPart) * 1e9 / (double)f.QuadPart;
}

// --until-key: the SAME W threads read round after round until `stop` is set, with a blocking
// barrier between rounds (its last arriver decides, for all, whether another round follows),
// so every thread does the same number of whole rounds. No thread is created and nobody spins
// between rounds: while some threads wait at the barrier the last one is still reading, so the
// process calls NtReadVirtualMemory at every moment of the phase. (Running run_reads again per
// round did not: its 4 fresh threads and main SPIN until all of them have started, and with
// every CPU taken by spinners a thread that has not started waits for a scheduling quantum --
// Windows Server: ~190 ms -- so a round's start left the process without a single read for a
// few hundred ms now and then: a short attach (regress ntdll-churn, 300 ms) saw no call at
// all.) Returns the phase's elapsed time; `results` holds each thread's sums over all rounds.
static double run_read_rounds(std::vector<Helper> &helpers, size_t threads, uint64_t reads,
                              const std::atomic<bool> &stop, uint64_t &rounds, std::vector<ThreadResult> &results) {
    results.assign(threads, {});
    std::atomic<bool> failed{false};
    bool more = true;
    uint64_t done = 0;
    std::barrier sync((std::ptrdiff_t)threads, [&]() noexcept {
        ++done;
        more = !stop.load() && !failed.load();
    });
    const uint64_t begin = qpc_now();
    std::vector<std::thread> pool;
    for (size_t t = 0; t < threads; ++t) pool.emplace_back([&, t] {
        for (;;) {
            ThreadResult r;
            read_worker(helpers, t, reads, r);
            results[t].success += r.success; results[t].checksum += r.checksum;
            if (!r.error.empty()) { if (results[t].error.empty()) results[t].error = r.error; failed.store(true); }
            sync.arrive_and_wait();
            if (!more) break;
        }
    });
    for (auto &th : pool) th.join();
    LARGE_INTEGER f{}; QueryPerformanceFrequency(&f);
    rounds = done;
    return (double)(qpc_now() - begin) * 1e9 / (double)f.QuadPart;
}

// Diagnostics for instrumentation tests: if anything ever reaches this process as an
// unhandled exception (e.g. a debug trap left behind by a detaching tool), say exactly
// what and where before the process dies.
static LONG WINAPI report_unhandled(EXCEPTION_POINTERS *ep) {
    const CONTEXT *c = ep->ContextRecord;
#if defined(_WIN64)
    unsigned long long ip = c->Rip;
#else
    unsigned long long ip = c->Eip;
#endif
    char buf[512];
    int n = std::snprintf(buf, sizeof(buf), "{\"kind\":\"unhandled\",\"code\":\"0x%08lx\",\"address\":\"0x%llx\",\"ip\":\"0x%llx\","
                 "\"tid\":%lu,\"eflags\":\"0x%lx\",\"dr6\":\"0x%llx\",\"dr7\":\"0x%llx\",\"dr0\":\"0x%llx\"}\n",
                 (unsigned long)ep->ExceptionRecord->ExceptionCode,
                 (unsigned long long)(uintptr_t)ep->ExceptionRecord->ExceptionAddress, ip,
                 (unsigned long)GetCurrentThreadId(), (unsigned long)c->EFlags,
                 (unsigned long long)c->Dr6, (unsigned long long)c->Dr7, (unsigned long long)c->Dr0);
    DWORD w = 0;                                        // straight to the handle: no CRT buffering
    if (n > 0) WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD)n, &w, nullptr);
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char **argv) try {
    SetUnhandledExceptionFilter(report_unhandled);
    if ((argc == 3 || argc == 4) && !std::strcmp(argv[1], "--helper")) return helper_main(argv[2], argc == 4 ? argv[3] : nullptr);
    size_t helper_count = 4, threads = std::thread::hardware_concurrency();
    uint64_t reads = 1000;
    uint64_t decoy_opens = 0;
    bool existing_hook = false, wait = true, until_key = false, churn = false, parse_early = false;
    std::string truth;
    std::string config = "reads_enabled=0\n";   // shipped config: the feature is OFF
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> const char * { require(i + 1 < argc, "missing option value"); return argv[++i]; };
        if (a == "--helpers") helper_count = (size_t)_strtoui64(next(), nullptr, 10);
        else if (a == "--threads") threads = (size_t)_strtoui64(next(), nullptr, 10);
        else if (a == "--reads") reads = _strtoui64(next(), nullptr, 10);
        else if (a == "--pace") g_pace = _strtoui64(next(), nullptr, 10);
        else if (a == "--prehook") existing_hook = true;
        else if (a == "--config") { config = next(); for (auto &c : config) if (c == ';') c = '\n'; }
        else if (a == "--no-wait") wait = false;
        else if (a == "--until-key") until_key = true;
        else if (a == "--decoy-opens") decoy_opens = _strtoui64(next(), nullptr, 10);
        else if (a == "--open-via") g_open_kernel32 = std::string(next()) == "kernel32";
        else if (a == "--churn") churn = true;
        else if (a == "--truth") truth = next();
        else if (a == "--parse-early") parse_early = true;
        else throw std::runtime_error("usage: probe_app [--helpers N] [--threads W] [--reads R] [--pace P] [--prehook] "
                                      "[--config k=v;...] [--no-wait] [--until-key] [--decoy-opens N] [--churn --truth FILE] [--parse-early]");
    }
    require(helper_count >= 1 && helper_count <= 64 && threads >= 1 && threads <= 256 &&
            reads >= 1 && reads <= 1000000000ULL, "helper/thread/read counts");
    require(!churn || !truth.empty(), "--churn needs --truth FILE");

    g_ntread = (NtRead)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
    g_ntopen = (NtOpen)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
    require(g_ntread != nullptr && g_ntopen != nullptr, "ntdll exports");
    if (existing_hook) {
        prehook = safetyhook::create_inline((void *)&ReadThunk, (void *)&pre_read);
        require(!!prehook, "install existing hook");
    }

    // 1. Helpers exist before the gate so an attaching tool can be told which one to
    //    watch; they stay idle (never opened, never read) unless the flag gets turned on.
    std::vector<Helper> helpers(helper_count);
    for (size_t k = 0; k < helper_count; ++k) {
        helpers[k].start();
        std::printf("{\"kind\":\"helper\",\"index\":%llu,\"pid\":%lu,\"base\":%llu,\"size\":%u}\n",
                    (unsigned long long)k, helpers[k].hello.pid,
                    (unsigned long long)helpers[k].hello.address, kBufferSize);
    }

    // 1b. --parse-early: the config library is loaded and the config parsed once before the
    //     gate (a tool attaching at the gate finds both done); only the parse after it counts.
    if (parse_early) {
        HMODULE early = LoadLibraryA((exe_directory() + "configparse.dll").c_str());
        require(early != nullptr, "load configparse.dll (early)");
        auto parse = (parse_config_fn)GetProcAddress(early, "ParseConfig"); require(parse != nullptr, "ParseConfig");
        parsed_config first{};
        require(parse(config.c_str(), &first) == 1, "config parse (early)");
        std::printf("{\"kind\":\"parsed\",\"phase\":\"early\",\"reads_enabled\":%u}\n", first.reads_enabled);
    }

    // 2. Gate.
    std::printf("{\"kind\":\"waiting\",\"pid\":%lu,\"helpers\":%llu}\n", GetCurrentProcessId(),
                (unsigned long long)helper_count);
    std::fflush(stdout);
    if (wait) require(wait_for_key(), "keystroke");

    // 3. Late-load the config library and parse the shipped config.
    require(parse_early || GetModuleHandleA("configparse.dll") == nullptr, "configparse.dll loaded before the gate");
    HMODULE dll = LoadLibraryA((exe_directory() + "configparse.dll").c_str());
    require(dll != nullptr, "load configparse.dll");
    auto parse = (parse_config_fn)GetProcAddress(dll, "ParseConfig"); require(parse != nullptr, "ParseConfig");
    parsed_config parsed{};
    require(parse(config.c_str(), &parsed) == 1, "config parse");

    // 4. The gated feature: open the helpers by PID and read them.
    std::vector<ThreadResult> results;
    double elapsed_ns = 0;
    uint64_t success = 0, checksum = 0, rounds = 0;
    ChurnResult churned;
    if (parsed.reads_enabled && churn) {
        churned = run_churn(helpers, threads, reads, truth);
        require(churned.error.empty(), churned.error);
        success = churned.reads; checksum = churned.checksum; rounds = 1;
    } else if (parsed.reads_enabled) {
        // --decoy-opens: open (and close) ourselves N times first through the same stub, so
        // an open-tracking map sees many opens -- and reused handle values -- before the
        // helpers are opened. None of these handles is ever read.
        for (uint64_t k = 0; k < decoy_opens; ++k) {
            ObjectAttributes oa{sizeof(oa)}; HANDLE self{};
            ClientId cid{(HANDLE)(uintptr_t)GetCurrentProcessId(), nullptr};
            require(OpenThunk(&self, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid) >= 0 && self, "NtOpenProcess self");
            CloseHandle(self);
        }
        open_helpers(helpers);
        for (auto &h : helpers)      // ground truth for the handle -> pid map tools build
            std::printf("{\"kind\":\"opened\",\"pid\":%lu,\"handle\":%llu}\n", h.hello.pid,
                        (unsigned long long)(uintptr_t)h.read_handle);
        std::fflush(stdout);
        static std::atomic<bool> key_pressed{false};
        if (until_key) std::thread([] { wait_for_key(); key_pressed.store(true); }).detach();   // EOF stops too
        if (until_key) elapsed_ns = run_read_rounds(helpers, threads, reads, key_pressed, rounds, results);
        else { elapsed_ns = run_reads(helpers, threads, reads, results); rounds = 1; }
        for (auto &r : results) { require(r.error.empty(), r.error); success += r.success; checksum += r.checksum; }
    }
    uint64_t hook_calls = prehook_calls.load();
    prehook.reset();
    // CET: RDSSP reads the shadow-stack pointer, and is a NOP (leaves 0) when this thread
    // has no shadow stack -- the /CETCOMPAT build (probe_app_cet) reports whether the CPU
    // and OS actually enforced one for this run.
#if defined(_WIN64)
    const uint64_t ssp = _rdsspq();
#else
    const uint64_t ssp = _rdsspd();
#endif
    std::printf("{\"kind\":\"app\",\"reads_enabled\":%u,\"helpers\":%llu,\"opened\":%llu,\"threads\":%llu,"
                "\"reads_per_thread\":%llu,\"successful_reads\":%llu,\"checksum\":%llu,\"elapsed_ns\":%.0f,"
                "\"prehook\":%s,\"prehook_calls\":%llu,\"configparse_base\":%llu,\"shadow_stack\":%s,\"rounds\":%llu}\n",
                parsed.reads_enabled, (unsigned long long)helper_count,
                (unsigned long long)(!parsed.reads_enabled ? 0 : churn ? churned.opens : helper_count), (unsigned long long)threads,
                (unsigned long long)reads, (unsigned long long)success, (unsigned long long)checksum, elapsed_ns,
                existing_hook ? "true" : "false", (unsigned long long)hook_calls,
                (unsigned long long)(uintptr_t)dll, ssp ? "true" : "false", (unsigned long long)rounds);
    std::fflush(stdout);
    return 0;
} catch (const std::exception &e) { std::fprintf(stderr, "probe_app: %s\n", e.what()); return 1; }
