// regtrace_target -- fixture for regtrace. Under HKCU\Software\UHHTest, each thread creates
// its own subkey, writes values, reopens it read-only and queries them, plus a query of a
// value and an open of a key that do not exist; every value read back must equal what was
// written. The tree is deleted at start and at exit. It prints its own ground truth:
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
    for (int n = 0; n < iters; ++n) {
        DWORD v = 0, size = sizeof(v), type = 0;
        check(RegQueryValueExW(r, L"count", nullptr, &type, (BYTE *)&v, &size) == ERROR_SUCCESS &&
              type == REG_DWORD && v == (DWORD)(t * 1000 + iters - 1));
    }
    wchar_t text[64] = {}; DWORD size = sizeof(text), type = 0;
    check(RegQueryValueExW(r, L"name", nullptr, &type, (BYTE *)text, &size) == ERROR_SUCCESS && name == text);
    BYTE got[16] = {}; size = sizeof(got);
    check(RegQueryValueExW(r, L"blob", nullptr, &type, got, &size) == ERROR_SUCCESS && !memcmp(got, blob, sizeof(got)));
    size = sizeof(got);   // does not exist: the error must reach the program unchanged
    check(RegQueryValueExW(r, L"missing", nullptr, &type, got, &size) == ERROR_FILE_NOT_FOUND);
    RegCloseKey(r);
    HKEY none{};
    check(RegOpenKeyExW(HKEY_CURRENT_USER, (key + L"\\missing").c_str(), 0, KEY_READ, &none) == ERROR_FILE_NOT_FOUND);
    value_done(key, "count", iters, iters);
    value_done(key, "name", 1, 1);
    value_done(key, "blob", 1, 1);
    value_done(key, "missing", 0, 1);
}
}  // namespace

int main(int argc, char **argv) {
    int threads = 4, iters = 20;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!std::strcmp(argv[i], "--threads")) threads = std::atoi(argv[i + 1]);
        else if (!std::strcmp(argv[i], "--iters")) iters = std::atoi(argv[i + 1]);
    }
    RegDeleteTreeW(HKEY_CURRENT_USER, kRoot);            // a previous run that was killed
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; ++t) pool.emplace_back(worker, t, iters);
    for (auto &th : pool) th.join();
    const LSTATUS deleted = RegDeleteTreeW(HKEY_CURRENT_USER, kRoot);
    HKEY gone{};
    const bool cleaned = deleted == ERROR_SUCCESS &&
                         RegOpenKeyExW(HKEY_CURRENT_USER, kRoot, 0, KEY_READ, &gone) == ERROR_FILE_NOT_FOUND;
    emit("{\"kind\":\"rt_done\",\"bad\":%d,\"cleaned\":%d}\n", g_bad.load(), cleaned ? 1 : 0);
    return g_bad || !cleaned ? 1 : 0;
}
