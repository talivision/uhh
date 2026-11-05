// oldcrt_target -- an app that uses the DYNAMIC MSVC runtime (/MD) and may ship its own,
// older msvcp140.dll next to its exe (app-local deployment, common in real software).
// Whatever msvcp140 it loads is the one any DLL injected later binds to by name.
//
//   oldcrt_target [calls]      prints the msvcp140 it loaded, then calls Tick() `calls` times
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <mutex>

static std::mutex g_mu;            // forces a real msvcp140 import (_Mtx_*)
static volatile long g_total;

extern "C" __declspec(dllexport) __declspec(noinline) long Tick(long v) {
    std::lock_guard<std::mutex> lock(g_mu);
    long x = v;
    for (int i = 0; i < 8; ++i) x = x * 31 + i;
    g_total += x & 0xff;
    return x;
}

int main(int argc, char **argv) {
    long calls = argc > 1 ? std::atol(argv[1]) : 1000;
    wchar_t path[MAX_PATH] = L"?";
    HMODULE crt = GetModuleHandleW(L"msvcp140.dll");
    if (crt) GetModuleFileNameW(crt, path, MAX_PATH);
    for (wchar_t *c = path; *c; ++c) if (*c == L'\\') *c = L'/';   // keep the JSON valid
    std::printf("{\"kind\":\"oldcrt_target\",\"msvcp140\":\"%ls\"}\n", path);
    std::fflush(stdout);
    Sleep(200);                     // let an attaching/launching instrumenter settle
    for (long i = 0; i < calls; ++i) Tick(i);
    std::printf("{\"kind\":\"oldcrt_done\",\"calls\":%ld,\"total\":%ld}\n", calls, g_total);
    return 0;
}
