// symfile_test: the controller's symbol names come from image files on disk, never from the
// target's memory (regress `symbols-file-backed`, docs/symbols.md). Uses the controller's
// internal symbol layer (src/probe/symbols.hpp) directly.
//
//   foreign-image  kernel32.dll's FILE registered at the base where the live target maps
//                  ntdll.dll: names and resolve() must be kernel32's. (DbgHelp keyed by the
//                  process handle read the image from memory: ntdll's exports under kernel32's
//                  name, or no symbols at all.)
//   after-exit     kernel32 registered, first looked up only after the target has exited.
//
// Prints one JSON line per case: {"kind":"symfile","case":...,"name":...,"resolved":...,"want_rva":...}
#include "../../src/probe/symbols.hpp"
#include <cstdio>
#include <string>

static void json_str(const std::string &s) {
    std::putchar('"');
    for (char c : s) { if (c == '"' || c == '\\') std::putchar('\\'); std::putchar(c); }
    std::putchar('"');
}

int main() {
    HMODULE k = GetModuleHandleW(L"kernel32.dll");
    auto *nt = (IMAGE_NT_HEADERS *)((char *)k + ((IMAGE_DOS_HEADER *)k)->e_lfanew);
    const uint32_t size = nt->OptionalHeader.SizeOfImage;
    const uint64_t rva = (uint64_t)(uintptr_t)GetProcAddress(k, "BaseThreadInitThunk") - (uint64_t)(uintptr_t)k;
    wchar_t dir[MAX_PATH]; BOOL wow = FALSE; IsWow64Process(GetCurrentProcess(), &wow);
    if (wow) GetSystemWow64DirectoryW(dir, MAX_PATH); else GetSystemDirectoryW(dir, MAX_PATH);
    const std::wstring path = std::wstring(dir) + L"\\kernel32.dll";
    int failures = 0;
    for (int c = 0; c < 2; ++c) {
        STARTUPINFOW si{sizeof(si)}; PROCESS_INFORMATION pi{};
        wchar_t live[] = L"cmd.exe /c ping -n 30 127.0.0.1 >nul", quick[] = L"cmd.exe /c exit 0";
        if (!CreateProcessW(nullptr, c == 0 ? live : quick, nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW | (c == 1 ? CREATE_SUSPENDED : 0), nullptr, nullptr, &si, &pi)) {
            std::printf("{\"kind\":\"symfile\",\"case\":\"spawn\",\"error\":%lu}\n", GetLastError());
            return 1;
        }
        if (c == 0) Sleep(300);
        // Same bitness, same boot: system DLLs are at the same bases in the target.
        const uint64_t base = (uint64_t)(uintptr_t)(c == 0 ? GetModuleHandleW(L"ntdll.dll") : (HMODULE)k);
        std::string which;
        const bool init = uhh_sym::init(pi.hProcess, which);
        uhh_sym::register_module(pi.hProcess, path, base, size);
        if (c == 1) { ResumeThread(pi.hThread); WaitForSingleObject(pi.hProcess, 30000); }
        const std::string name = uhh_sym::symbolize(pi.hProcess, base + rva + 0x10);
        uint64_t at = 0;
        const bool resolved = uhh_sym::resolve(pi.hProcess, "kernel32.dll", "BaseThreadInitThunk", at);
        const bool ok = init && name.rfind("kernel32!BaseThreadInitThunk+0x10 ", 0) == 0 && resolved && at == base + rva;
        failures += !ok;
        std::printf("{\"kind\":\"symfile\",\"case\":\"%s\",\"ok\":%s,\"name\":", c == 0 ? "foreign-image" : "after-exit",
                    ok ? "true" : "false");
        json_str(name);
        std::printf(",\"resolved\":%s,\"resolved_rva\":%lld,\"want_rva\":%llu,\"dbghelp\":", resolved ? "true" : "false",
                    resolved ? (long long)(at - base) : -1LL, (unsigned long long)rva);
        json_str(which);
        std::printf("}\n");
        uhh_sym::cleanup(pi.hProcess);
        TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    return failures ? 1 : 0;
}
