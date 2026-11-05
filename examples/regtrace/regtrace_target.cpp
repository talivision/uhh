// regtrace_target -- fixture for regtrace. Under HKCU\Software\UHHTest, each thread creates
// its own subkey, writes values, reopens it read-only and queries them, plus a query of a
// value and an open of a key that do not exist; every value read back must equal what was
// written (status, type, exact size and bytes, every query). The tree is deleted at start and
// at exit by a CHILD reg.exe (uninstrumented): RegDeleteTree in this process would open the
// keys again, which the tool would rightly log as opens this truth does not list. It prints its
// own ground truth (every key open it made, nothing else):
//   {"kind":"rt_key","key":"Software\\UHHTest\\t0","handle":172}      every key it opened
//   {"kind":"rt_value","key":"Software\\UHHTest\\t0","value":"count","sets":20,"queries":20}
//   {"kind":"rt_done","bad":0,"cleaned":1}
// usage: regtrace_target [--threads T] [--iters N]
#include <windows.h>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#pragma comment(lib, "advapi32.lib")

namespace {
const wchar_t kRoot[] = L"Software\\UHHTest";
std::mutex g_out;
std::atomic<int> g_bad{0};

void emit(const char *fmt, ...) {
    std::lock_guard<std::mutex> lock(g_out);
    va_list ap; va_start(ap, fmt); std::vfprintf(stdout, fmt, ap); va_end(ap);
    std::fflush(stdout);
}
std::string json(const std::wstring &w) {
    std::string s;
    for (wchar_t ch : w) { if (ch == L'\\') s += "\\\\"; else s += ch < 0x80 ? (char)ch : '?'; }
    return s;
}
void key_opened(const std::wstring &key, HKEY h) {
    emit("{\"kind\":\"rt_key\",\"key\":\"%s\",\"handle\":%llu}\n", json(key).c_str(), (unsigned long long)(uintptr_t)h);
}
void value_done(const std::wstring &key, const char *value, int sets, int queries) {
    emit("{\"kind\":\"rt_value\",\"key\":\"%s\",\"value\":\"%s\",\"sets\":%d,\"queries\":%d}\n", json(key).c_str(),
         value, sets, queries);
}
void check(bool ok) { if (!ok) ++g_bad; }

void worker(int t, int iters) {
    const std::wstring key = std::wstring(kRoot) + L"\\t" + std::to_wstring(t);
    HKEY h{};
    check(RegCreateKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &h, nullptr) == ERROR_SUCCESS);
    if (!h) return;
    key_opened(key, h);
    const std::wstring name = L"thread-" + std::to_wstring(t);
    const BYTE blob[16] = {1, 2, 3, 4, 5, 6, 7, 8, (BYTE)t, 10, 11, 12, 13, 14, 15, 16};
    for (int n = 0; n < iters; ++n) {
        const DWORD count = (DWORD)(t * 1000 + n);
        check(RegSetValueExW(h, L"count", 0, REG_DWORD, (const BYTE *)&count, sizeof(count)) == ERROR_SUCCESS);
    }
    check(RegSetValueExW(h, L"name", 0, REG_SZ, (const BYTE *)name.c_str(), DWORD((name.size() + 1) * 2)) == ERROR_SUCCESS);
    check(RegSetValueExW(h, L"blob", 0, REG_BINARY, blob, sizeof(blob)) == ERROR_SUCCESS);
    RegCloseKey(h);

    // Read it back through a fresh read-only handle: the values must be exactly what was set.
    HKEY r{};
    check(RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, KEY_READ, &r) == ERROR_SUCCESS);
    if (!r) return;
    key_opened(key, r);
    // Every output is reset to a poison value before each query, so a stale value cannot pass.
    for (int n = 0; n < iters; ++n) {
        BYTE vb[8]; memset(vb, 0xCD, sizeof(vb));
        DWORD size = sizeof(vb), type = 0x7777;            // room for more: the size must come back 4
        const LSTATUS st = RegQueryValueExW(r, L"count", nullptr, &type, vb, &size);
        DWORD v = 0; memcpy(&v, vb, sizeof(v));
        check(st == ERROR_SUCCESS && type == REG_DWORD && size == sizeof(DWORD) && v == (DWORD)(t * 1000 + iters - 1) &&
              vb[4] == 0xCD);
    }
    wchar_t text[64]; wmemset(text, 0xCDCD, 64); DWORD size = sizeof(text), type = 0x7777;
    const DWORD name_bytes = DWORD((name.size() + 1) * 2);
    check(RegQueryValueExW(r, L"name", nullptr, &type, (BYTE *)text, &size) == ERROR_SUCCESS && type == REG_SZ &&
          size == name_bytes && !memcmp(text, name.c_str(), name_bytes));
    BYTE got[32]; memset(got, 0xCD, sizeof(got)); size = sizeof(got); type = 0x7777;
    check(RegQueryValueExW(r, L"blob", nullptr, &type, got, &size) == ERROR_SUCCESS && type == REG_BINARY &&
          size == sizeof(blob) && !memcmp(got, blob, sizeof(blob)) && got[sizeof(blob)] == 0xCD);
    memset(got, 0xCD, sizeof(got)); size = sizeof(got); type = 0x7777;   // does not exist: the error must reach the program unchanged
    check(RegQueryValueExW(r, L"missing", nullptr, &type, got, &size) == ERROR_FILE_NOT_FOUND && got[0] == 0xCD);
    RegCloseKey(r);
    HKEY none{};
    check(RegOpenKeyExW(HKEY_CURRENT_USER, (key + L"\\missing").c_str(), 0, KEY_READ, &none) == ERROR_FILE_NOT_FOUND);
    value_done(key, "count", iters, iters);
    value_done(key, "name", 1, 1);
    value_done(key, "blob", 1, 1);
    value_done(key, "missing", 0, 1);
}
// HKCU\Software\UHHTest deleted by reg.exe (a child: not instrumented); its exit code.
DWORD delete_tree_in_child() {
    wchar_t sys[MAX_PATH];
    if (!GetSystemDirectoryW(sys, MAX_PATH)) return 1000;
    std::wstring cmd = L"\"" + std::wstring(sys) + L"\\reg.exe\" delete HKCU\\Software\\UHHTest /f";
    STARTUPINFOW si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
    HANDLE nul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    si.hStdOutput = si.hStdError = nul; si.hStdInput = nullptr;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmd.begin(), cmd.end()); buf.push_back(0);
    DWORD code = 1001;
    if (CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        if (WaitForSingleObject(pi.hProcess, 60000) == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    return code;
}
}  // namespace

int main(int argc, char **argv) {
    int threads = 4, iters = 20;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!std::strcmp(argv[i], "--threads")) threads = std::atoi(argv[i + 1]);
        else if (!std::strcmp(argv[i], "--iters")) iters = std::atoi(argv[i + 1]);
    }
    delete_tree_in_child();                              // a previous run that was killed (absent: rc 1)
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; ++t) pool.emplace_back(worker, t, iters);
    for (auto &th : pool) th.join();
    const DWORD deleted = delete_tree_in_child();
    HKEY gone{};
    const bool cleaned = deleted == 0 &&
                         RegOpenKeyExW(HKEY_CURRENT_USER, kRoot, 0, KEY_READ, &gone) == ERROR_FILE_NOT_FOUND;
    emit("{\"kind\":\"rt_done\",\"bad\":%d,\"cleaned\":%d}\n", g_bad.load(), cleaned ? 1 : 0);
    return g_bad || !cleaned ? 1 : 0;
}
