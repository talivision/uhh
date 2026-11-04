// uhh_trace -- trace calls to any exported function of any program.
//
//   uhh_trace [--backend inline|breakpoint|hw] [--stack]
//             -p "KernelBase.dll!CreateFileW:Wxx" [-p ...] -- program.exe [args...]
//   uhh_trace ... --attach <pid>          (instrument an already-running process)
//
// After the ':' one format character per argument (see trace_callback.h). Inline probes
// fall back to a hardware breakpoint when the site cannot be hooked in time or is
// already hooked by someone else (PROBE_FALLBACK_HW). Output: the probe report (JSON
// lines); every call is a probe_log record, with a symbolized stack under --stack.
#include "trace_callback.h"
#include "../../src/probe/symbols.hpp"
#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

static std::wstring wide_arg(const char *text) {
    if (!text || !*text) return {};
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, nullptr, 0);
    UINT code_page = CP_UTF8; DWORD flags = MB_ERR_INVALID_CHARS;
    if (!count) { code_page = CP_ACP; flags = 0; count = MultiByteToWideChar(code_page, flags, text, -1, nullptr, 0); }
    if (!count) return {};
    std::vector<wchar_t> result(static_cast<size_t>(count));
    return MultiByteToWideChar(code_page, flags, text, -1, result.data(), count)
        ? std::wstring(result.data()) : std::wstring{};
}

static std::wstring join_path(const std::wstring &directory, const wchar_t *name) {
    if (directory.empty()) return name;
    wchar_t last = directory.back();
    return directory + ((last == L'\\' || last == L'/') ? L"" : L"\\") + name;
}

static bool is_plain_module_name(const std::wstring &path) {
    return path.find_first_of(L"\\/") == std::wstring::npos && path.find(L':') == std::wstring::npos;
}

static std::wstring list_image_path(const char *argument) {
    std::wstring path = wide_arg(argument);
    if (path.empty()) return {};
    if (is_plain_module_name(path)) {
        wchar_t windows[MAX_PATH];
        UINT length = GetWindowsDirectoryW(windows, MAX_PATH);
        if (!length || length >= static_cast<UINT>(MAX_PATH)) return {};
#if defined(_WIN64)
        path = join_path(join_path(std::wstring(windows, length), L"System32"), path.c_str());
#else
        BOOL wow64 = FALSE;
        IsWow64Process(GetCurrentProcess(), &wow64);
        path = join_path(join_path(std::wstring(windows, length), wow64 ? L"SysWOW64" : L"System32"), path.c_str());
#endif
    }
    DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (!needed) return {};
    std::vector<wchar_t> absolute(needed);
    DWORD written = GetFullPathNameW(path.c_str(), needed, absolute.data(), nullptr);
    return written && written < needed ? std::wstring(absolute.data(), written) : std::wstring{};
}

static bool read_image_size(const std::wstring &path, uint32_t &size) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    IMAGE_DOS_HEADER dos{}; DWORD done = 0;
    bool ok = ReadFile(file, &dos, static_cast<DWORD>(sizeof(dos)), &done, nullptr) &&
              done == static_cast<DWORD>(sizeof(dos)) &&
              dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0;
    LARGE_INTEGER offset{}; offset.QuadPart = dos.e_lfanew;
    IMAGE_NT_HEADERS headers{};
    if (ok) ok = SetFilePointerEx(file, offset, nullptr, FILE_BEGIN) &&
                 ReadFile(file, &headers, static_cast<DWORD>(sizeof(headers)), &done, nullptr) &&
                 done == static_cast<DWORD>(sizeof(headers)) &&
                 headers.Signature == IMAGE_NT_SIGNATURE &&
                 headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC;
    CloseHandle(file);
    if (!ok) return false;
#if defined(_WIN64)
    if (headers.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
#else
    if (headers.FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return false;
#endif
    size = headers.OptionalHeader.SizeOfImage;
    return size != 0;
}

static std::string json_text(const std::string &text) {
    std::string result = "\"";
    static const char hex[] = "0123456789abcdef";
    for (unsigned char ch : text) {
        switch (ch) {
            case '\"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (ch < 0x20) {
                    result += "\\u00";
                    result.push_back(hex[ch >> 4]);
                    result.push_back(hex[ch & 0x0f]);
                } else result.push_back(static_cast<char>(ch));
        }
    }
    result.push_back('\"');
    return result;
}

static int list_symbols(int argc, char **argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: uhh_trace --list <module.dll|path> [--mask *pattern*]\n");
        return 2;
    }
    std::string mask = "*";
    if (argc != 3) {
        if (argc != 5 || std::strcmp(argv[3], "--mask")) {
            std::fprintf(stderr, "usage: uhh_trace --list <module.dll|path> [--mask *pattern*]\n");
            return 2;
        }
        mask = argv[4];
    }
    std::wstring image = list_image_path(argv[2]);
    uint32_t image_size = 0;
    if (image.empty() || !read_image_size(image, image_size)) {
        std::fprintf(stderr, "uhh_trace: cannot open a matching-bitness image: %s\n", argv[2]);
        return 1;
    }

    // DbgHelp treats hProcess as an opaque session key when fInvadeProcess is FALSE.
    // A non-handle identifier avoids contaminating the controller's real process session.
    HANDLE symbol_session = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x1234));
    std::string diagnostic;
    if (!uhh_sym::init(symbol_session, diagnostic)) {
        std::fprintf(stderr, "uhh_trace: symbol initialization failed: %s\n", diagnostic.c_str());
        return 1;
    }
    constexpr uint64_t image_base = 0x10000000ULL;
    uhh_sym::register_module(symbol_session, image, image_base, image_size);
    std::vector<uhh_sym::symbol_entry> symbols;
    const std::string module = [&image]() {
        size_t slash = image.find_last_of(L"\\/");
        std::wstring name = slash == std::wstring::npos ? image : image.substr(slash + 1);
        int bytes = WideCharToMultiByte(CP_UTF8, 0, name.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::vector<char> output(bytes > 0 ? static_cast<size_t>(bytes) : static_cast<size_t>(1), '\0');
        if (bytes > 0) WideCharToMultiByte(CP_UTF8, 0, name.c_str(), -1, output.data(), bytes, nullptr, nullptr);
        return std::string(output.data());
    }();
    bool ok = uhh_sym::enumerate(symbol_session, module, mask, symbols);
    if (ok) {
        std::sort(symbols.begin(), symbols.end(), [](const uhh_sym::symbol_entry &a, const uhh_sym::symbol_entry &b) {
            return a.address < b.address || (a.address == b.address && a.name < b.name);
        });
        for (const auto &symbol : symbols) {
            unsigned long long rva = symbol.address >= image_base
                ? static_cast<unsigned long long>(symbol.address - image_base) : 0;
            std::printf("{\"kind\":\"symbol\",\"name\":%s,\"rva\":%llu,\"size\":%lu,\"export\":%s}\n",
                        json_text(symbol.name).c_str(), rva, static_cast<unsigned long>(symbol.size),
                        symbol.is_export ? "true" : "false");
        }
    } else {
        std::fprintf(stderr, "uhh_trace: symbol enumeration failed for %s\n", argv[2]);
    }
    uhh_sym::cleanup(symbol_session);
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc > 1 && !std::strcmp(argv[1], "--list")) return list_symbols(argc, argv);
    uint32_t backend = PROBE_BREAKPOINT; bool stack = false; unsigned long attach_pid = 0;
    std::vector<trace_config> cfgs; std::vector<std::string> locs;
    int i = 1;
    for (; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--")) { ++i; break; }
        if (!std::strcmp(argv[i], "--stack")) { stack = true; continue; }
        if (!std::strcmp(argv[i], "--attach") && i + 1 < argc) { attach_pid = std::strtoul(argv[++i], nullptr, 0); continue; }
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            backend = !std::strcmp(b, "inline") ? PROBE_INLINE : !std::strcmp(b, "hw") ? PROBE_HW : PROBE_BREAKPOINT;
            continue;
        }
        if (!std::strcmp(argv[i], "-p") && i + 1 < argc) {
            std::string spec = argv[++i]; size_t colon = spec.rfind(':');
            std::string where = colon == std::string::npos ? spec : spec.substr(0, colon);
            std::string fmt = colon == std::string::npos ? "xxxx" : spec.substr(colon + 1);
            trace_config c{};
            size_t bang = where.find('!');
            std::snprintf(c.name, sizeof(c.name), "%s", bang == std::string::npos ? where.c_str() : where.c_str() + bang + 1);
            std::snprintf(c.fmt, sizeof(c.fmt), "%s", fmt.c_str());
            cfgs.push_back(c); locs.push_back(where);
            continue;
        }
        std::fprintf(stderr, "uhh_trace: unknown option %s\n", argv[i]); return 2;
    }
    if (cfgs.empty() || (!attach_pid && i >= argc)) {
        std::fprintf(stderr, "usage: uhh_trace [--backend inline|breakpoint|hw] [--stack] -p mod!Export[:fmt] ... -- prog [args]\n"
                             "       uhh_trace --list <module.dll|path> [--mask *pattern*]\n");
        return 2;
    }
    probe_session *s = probe_session_create();
    if (!s) return 1;
    uint32_t flags = backend | (backend == PROBE_INLINE ? static_cast<uint32_t>(PROBE_FALLBACK_HW) : 0u);
    int ok = 1;
    for (size_t k = 0; k < cfgs.size(); ++k) {
        cfgs[k].stack = stack ? 1 : 0;
        ok = ok && probe_add_symbol_cfg(s, locs[k].c_str(), uhh_trace_call, flags, &cfgs[k], sizeof(cfgs[k]));
    }
    std::vector<char *> child(argv + (i < argc ? i : argc), argv + argc); child.push_back(nullptr);
    if (attach_pid) {
        ok = ok && probe_attach(s, (uint32_t)attach_pid);
        if (ok) { std::printf("{\"kind\":\"attached\",\"pid\":%lu}\n", attach_pid); std::fflush(stdout); }
        ok = ok && probe_run(s);
    } else {
        ok = ok && probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    }
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
