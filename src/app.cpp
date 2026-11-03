// probe_app: gated, multithreaded version of the contrived example.
//
//   probe_app [--threads W] [--reads R] [--prehook|--clean] [--config TEXT] [--no-wait]
//
// 1. Start selected/decoy helper processes and optionally the pre-existing hook.
// 2. Print {"kind":"waiting",...} and block until one byte/keystroke on stdin.
// 3. LoadLibrary configparse.dll (late; never a static import), ParseConfig.
//    The shipped config is reads_enabled=0; only a probe at ParsedFlagSite
//    turns the workload on.
// 4. If enabled, W threads each issue R reads through ReadThunk. Every read is
//    verified; totals and the existing-hook count are reported as JSON.
#include "win_common.hpp"
#include "configparse/configparse.h"
#include <atomic>
#include <thread>
#include <vector>
#include <safetyhook.hpp>

using NtRead = LONG (NTAPI *)(HANDLE, const void *, void *, SIZE_T, SIZE_T *);
extern "C" {
    NtRead g_ntread = nullptr;
    LONG NTAPI ReadThunk(HANDLE, const void *, void *, SIZE_T, SIZE_T *);
}

static SafetyHookInline prehook;
static std::atomic<uint64_t> prehook_calls{0};
static LONG NTAPI pre_read(HANDLE h, const void *a, void *b, SIZE_T n, SIZE_T *done) {
    prehook_calls.fetch_add(1, std::memory_order_relaxed);
    return prehook.call<LONG>(h, a, b, n, done);
}

struct Hello { uint64_t address; uint32_t pid; uint32_t reserved; };
struct Child {
    PROCESS_INFORMATION pi{}; HANDLE finish{}; Hello hello{};
    ~Child() {
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
        std::string exe = exe_directory() + "probe_app.exe";
        std::string command = "\"" + exe + "\" --helper " + std::to_string((uintptr_t)finish);
        // Only the pipe and event need inheriting; DEBUG_* flags are never set here,
        // so a debugger on probe_app does not follow the helpers.
        BOOL ok = CreateProcessA(exe.c_str(), command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi);
        CloseHandle(wr); if (!ok) { CloseHandle(rd); require(false, "helper launch"); }
        DWORD got = 0; BOOL read = ReadFile(rd, &hello, sizeof(hello), &got, nullptr); CloseHandle(rd);
        require(read && got == sizeof(hello), "helper handshake");
        SetHandleInformation(finish, HANDLE_FLAG_INHERIT, 0);
    }
};

static int helper_main(const char *finish_handle) {
    static unsigned char data[256];
    for (unsigned i = 0; i < 256; ++i) data[i] = (unsigned char)i;
    Hello h{(uint64_t)(uintptr_t)data, GetCurrentProcessId(), 0}; DWORD n{};
    require(!!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &h, sizeof(h), &n, nullptr) && n == sizeof(h), "helper write");
    return WaitForSingleObject((HANDLE)(uintptr_t)_strtoui64(finish_handle, nullptr, 10), 600000) == WAIT_OBJECT_0 ? 0 : 2;
}

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

struct Request { bool decoy; unsigned offset; };
// Rotation per global read index: selected/in-range, selected/out-of-range,
// decoy/in-range, selected/in-range at another offset. In range = [64, 96).
static Request request_for(uint64_t index) {
    switch (index % 4) {
    case 0: return {false, 64};
    case 1: return {false, 128};
    case 2: return {true, 64};
    default: return {false, 80};
    }
}

struct ThreadResult { uint64_t success = 0, checksum = 0; std::string error; };

int main(int argc, char **argv) try {
    if (argc == 3 && !std::strcmp(argv[1], "--helper")) return helper_main(argv[2]);
    uint64_t threads = std::thread::hardware_concurrency(), reads = 1000;
    bool existing_hook = false, wait = true;
    std::string config = "reads_enabled=0\n";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> const char * { require(i + 1 < argc, "missing option value"); return argv[++i]; };
        if (a == "--threads") threads = _strtoui64(next(), nullptr, 10);
        else if (a == "--reads") reads = _strtoui64(next(), nullptr, 10);
        else if (a == "--prehook") existing_hook = true;
        else if (a == "--clean") existing_hook = false;
        else if (a == "--config") { config = next(); for (auto &c : config) if (c == ';') c = '\n'; }
        else if (a == "--no-wait") wait = false;
        else throw std::runtime_error("usage: probe_app [--threads W] [--reads R] [--prehook|--clean] [--config k=v;...] [--no-wait]");
    }
    require(threads >= 1 && threads <= 256 && reads >= 1 && reads <= 1000000000ULL, "thread/read counts");

    Child selected, decoy;
    selected.start(); decoy.start();
    const uint64_t range_start = selected.hello.address + 64, range_size = 32;

    g_ntread = (NtRead)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
    require(g_ntread != nullptr, "NtReadVirtualMemory");
    if (existing_hook) {
        prehook = safetyhook::create_inline((void *)&ReadThunk, (void *)&pre_read);
        require(!!prehook, "install existing hook");
    }

    std::printf("{\"kind\":\"waiting\",\"pid\":%lu,\"selected_handle\":%llu,\"decoy_handle\":%llu,"
                "\"range_start\":%llu,\"range_size\":%llu}\n",
                GetCurrentProcessId(), (unsigned long long)(uintptr_t)selected.pi.hProcess,
                (unsigned long long)(uintptr_t)decoy.pi.hProcess,
                (unsigned long long)range_start, (unsigned long long)range_size);
    std::fflush(stdout);
    if (wait) require(wait_for_key(), "keystroke");

    std::string dll_path = exe_directory() + "configparse.dll";
    require(GetModuleHandleA("configparse.dll") == nullptr, "configparse.dll loaded before the gate");
    HMODULE dll = LoadLibraryA(dll_path.c_str()); require(dll != nullptr, "load configparse.dll");
    auto parse = (parse_config_fn)GetProcAddress(dll, "ParseConfig"); require(parse != nullptr, "ParseConfig");
    parsed_config parsed{};
    require(parse(config.c_str(), &parsed) == 1, "config parse");

    std::vector<ThreadResult> results(parsed.reads_enabled ? threads : 0);
    std::atomic<uint64_t> ready{0}; std::atomic<bool> go{false};
    LARGE_INTEGER f{}, begin{}, end{}; QueryPerformanceFrequency(&f);
    if (parsed.reads_enabled) {
        std::vector<std::thread> pool;
        for (uint64_t t = 0; t < threads; ++t) pool.emplace_back([&, t] {
            ThreadResult &r = results[t];
            ready.fetch_add(1); while (!go.load(std::memory_order_acquire)) YieldProcessor();
            for (uint64_t k = 0; k < reads; ++k) {
                Request q = request_for(t * reads + k);
                Child &ch = q.decoy ? decoy : selected;
                unsigned char buffer[16]{}; SIZE_T bytes = 0;
                LONG status = ReadThunk(ch.pi.hProcess, (const void *)(uintptr_t)(ch.hello.address + q.offset),
                                        buffer, sizeof(buffer), &bytes);
                bool ok = status >= 0 && bytes == sizeof(buffer);
                for (unsigned j = 0; ok && j < sizeof(buffer); ++j) ok = buffer[j] == (unsigned char)(q.offset + j);
                if (!ok) { r.error = "read " + std::to_string(t * reads + k) + " failed"; return; }
                ++r.success; r.checksum += buffer[0];
            }
        });
        while (ready.load() != threads) YieldProcessor();
        QueryPerformanceCounter(&begin);
        go.store(true, std::memory_order_release);
        for (auto &th : pool) th.join();
        QueryPerformanceCounter(&end);
    }
    uint64_t success = 0, checksum = 0;
    for (auto &r : results) { require(r.error.empty(), r.error.c_str()); success += r.success; checksum += r.checksum; }
    uint64_t hook_calls = prehook_calls.load();
    prehook.reset();
    std::printf("{\"kind\":\"app\",\"reads_enabled\":%u,\"threads\":%llu,\"reads_per_thread\":%llu,"
                "\"successful_reads\":%llu,\"checksum\":%llu,\"elapsed_ns\":%.0f,"
                "\"prehook\":%s,\"prehook_calls\":%llu,\"configparse_base\":%llu}\n",
                parsed.reads_enabled, (unsigned long long)threads, (unsigned long long)reads,
                (unsigned long long)success, (unsigned long long)checksum,
                parsed.reads_enabled ? (double)(end.QuadPart - begin.QuadPart) * 1e9 / (double)f.QuadPart : 0.0,
                existing_hook ? "true" : "false", (unsigned long long)hook_calls,
                (unsigned long long)(uintptr_t)dll);
    return 0;
} catch (const std::exception &e) { std::fprintf(stderr, "probe_app: %s\n", e.what()); return 1; }
