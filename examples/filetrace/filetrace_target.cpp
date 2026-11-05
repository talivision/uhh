// filetrace_target -- fixture for filetrace. Several threads each create, write and close
// files (odd files with overlapped I/O: every chunk in flight at once), make opens that must
// fail, then the main thread reads every file back. It prints its own ground truth:
//   {"kind":"ft_open","path":"C:\\d\\ft_t0_f0.bin","handle":420}     every successful open
//   {"kind":"ft_fail","path":"..","status":"0xc0000034","error":2,"expected":2}
//   {"kind":"ft_file","path":"..","writes":6,"bytes":9001,"overlapped":1}
//   {"kind":"ft_done","files":16,"bad":0,"fail_mismatch":0}
// usage: filetrace_target --dir D [--threads T] [--files F] [--chunks K]   (D must exist)
#include <windows.h>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {
std::wstring g_dir;
int g_threads = 4, g_files = 4, g_chunks = 6;
std::mutex g_out;
std::atomic<int> g_bad{0}, g_fail_mismatch{0};

std::string json_path(const std::wstring &w) {
    std::string s;
    for (wchar_t ch : w) { if (ch == L'\\') s += "\\\\"; else s += ch < 0x80 ? (char)ch : '?'; }
    return s;
}
void emit(const char *fmt, ...) {
    std::lock_guard<std::mutex> lock(g_out);
    va_list ap; va_start(ap, fmt); std::vfprintf(stdout, fmt, ap); va_end(ap);
    std::fflush(stdout);
}
std::wstring file_path(int t, int f) { return g_dir + L"\\ft_t" + std::to_wstring(t) + L"_f" + std::to_wstring(f) + L".bin"; }
uint32_t chunk_size(int t, int f, int k) { return 1 + (uint32_t)((t * 7 + f * 13 + k * 101) % 3000); }
char pattern(int t, int f, uint64_t i) { return (char)(t * 31 + f * 17 + i * 7 + (i >> 8)); }

HANDLE open_file(const std::wstring &path, DWORD access, DWORD share, DWORD disposition, DWORD flags) {
    HANDLE h = CreateFileW(path.c_str(), access, share, nullptr, disposition, FILE_ATTRIBUTE_NORMAL | flags, nullptr);
    if (h != INVALID_HANDLE_VALUE)
        emit("{\"kind\":\"ft_open\",\"path\":\"%s\",\"handle\":%llu}\n", json_path(path).c_str(),
             (unsigned long long)(uintptr_t)h);
    return h;
}

// An open that must fail with `expected`; the NTSTATUS the program saw is reported too.
void must_fail(const std::wstring &path, DWORD access, DWORD share, DWORD disposition, DWORD expected) {
    using last_status_fn = LONG(NTAPI *)();
    static auto last_status = (last_status_fn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetLastNtStatus");
    HANDLE h = CreateFileW(path.c_str(), access, share, nullptr, disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD err = GetLastError();
    const LONG status = last_status();
    if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); ++g_fail_mismatch; return; }
    if (err != expected) ++g_fail_mismatch;
    emit("{\"kind\":\"ft_fail\",\"path\":\"%s\",\"status\":\"0x%08lx\",\"error\":%lu,\"expected\":%lu}\n",
         json_path(path).c_str(), (unsigned long)status, err, expected);
}

void write_file(int t, int f) {
    const std::wstring path = file_path(t, f);
    const bool overlapped = f % 2 == 1;
    HANDLE h = open_file(path, GENERIC_WRITE, 0, CREATE_ALWAYS, overlapped ? FILE_FLAG_OVERLAPPED : 0);
    if (h == INVALID_HANDLE_VALUE) { ++g_bad; return; }
    std::vector<std::vector<char>> bufs(g_chunks);
    std::vector<OVERLAPPED> ovs(g_chunks);
    uint64_t offset = 0;
    for (int k = 0; k < g_chunks; ++k) {
        bufs[k].resize(chunk_size(t, f, k));
        for (size_t i = 0; i < bufs[k].size(); ++i) bufs[k][i] = pattern(t, f, offset + i);
        DWORD done = 0;
        if (!overlapped) {
            if (!WriteFile(h, bufs[k].data(), (DWORD)bufs[k].size(), &done, nullptr) || done != bufs[k].size()) ++g_bad;
        } else {
            OVERLAPPED &o = ovs[k];
            o.Offset = (DWORD)offset; o.OffsetHigh = (DWORD)(offset >> 32);
            o.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!WriteFile(h, bufs[k].data(), (DWORD)bufs[k].size(), nullptr, &o) && GetLastError() != ERROR_IO_PENDING) ++g_bad;
        }
        offset += bufs[k].size();
    }
    for (int k = 0; overlapped && k < g_chunks; ++k) {   // all chunks were in flight together
        DWORD done = 0;
        if (!GetOverlappedResult(h, &ovs[k], &done, TRUE) || done != bufs[k].size()) ++g_bad;
        CloseHandle(ovs[k].hEvent);
    }
    CloseHandle(h);
    emit("{\"kind\":\"ft_file\",\"path\":\"%s\",\"writes\":%d,\"bytes\":%llu,\"overlapped\":%d}\n",
         json_path(path).c_str(), g_chunks, (unsigned long long)offset, overlapped ? 1 : 0);
}

void worker(int t) {
    for (int f = 0; f < g_files; ++f) write_file(t, f);
    const std::wstring tag = std::to_wstring(t);
    must_fail(g_dir + L"\\ft_t" + tag + L"_missing.bin", GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, ERROR_FILE_NOT_FOUND);
    must_fail(g_dir + L"\\no_dir_" + tag + L"\\x.bin", GENERIC_WRITE, 0, CREATE_ALWAYS, ERROR_PATH_NOT_FOUND);
    must_fail(file_path(t, 0), GENERIC_WRITE, 0, CREATE_NEW, ERROR_FILE_EXISTS);
    HANDLE held = open_file(file_path(t, 0), GENERIC_READ, 0, OPEN_EXISTING, 0);   // exclusive
    must_fail(file_path(t, 0), GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, ERROR_SHARING_VIOLATION);
    if (held != INVALID_HANDLE_VALUE) CloseHandle(held); else ++g_bad;
}

// The program still works: every file holds exactly what was written.
bool verify(int t, int f) {
    HANDLE h = open_file(file_path(t, f), GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, 0);
    if (h == INVALID_HANDLE_VALUE) return false;
    uint64_t want = 0;
    for (int k = 0; k < g_chunks; ++k) want += chunk_size(t, f, k);
    std::vector<char> data((size_t)want + 1);
    DWORD got = 0;
    bool ok = ReadFile(h, data.data(), (DWORD)data.size(), &got, nullptr) && got == want;
    for (uint64_t i = 0; ok && i < want; ++i) ok = data[(size_t)i] == pattern(t, f, i);
    CloseHandle(h);
    return ok;
}
}  // namespace

int wmain(int argc, wchar_t **argv) {
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!wcscmp(argv[i], L"--dir")) g_dir = argv[i + 1];
        else if (!wcscmp(argv[i], L"--threads")) g_threads = _wtoi(argv[i + 1]);
        else if (!wcscmp(argv[i], L"--files")) g_files = _wtoi(argv[i + 1]);
        else if (!wcscmp(argv[i], L"--chunks")) g_chunks = _wtoi(argv[i + 1]);
    }
    if (g_dir.empty() || g_threads < 1 || g_files < 1 || g_chunks < 1) {
        std::fprintf(stderr, "usage: filetrace_target --dir D [--threads T] [--files F] [--chunks K]\n");
        return 2;
    }
    std::vector<std::thread> threads;
    for (int t = 0; t < g_threads; ++t) threads.emplace_back(worker, t);
    for (auto &th : threads) th.join();
    for (int t = 0; t < g_threads; ++t)
        for (int f = 0; f < g_files; ++f) if (!verify(t, f)) ++g_bad;
    emit("{\"kind\":\"ft_done\",\"files\":%d,\"bad\":%d,\"fail_mismatch\":%d}\n", g_threads * g_files,
         g_bad.load(), g_fail_mismatch.load());
    return g_bad || g_fail_mismatch ? 1 : 0;
}
