#include "symbols.hpp"

#include <dbghelp.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <mutex>
#include <utility>

namespace uhh_sym {
namespace {

struct dbghelp_api {
    decltype(&::SymSetOptions) set_options = nullptr;
    decltype(&::SymInitializeW) initialize = nullptr;
    decltype(&::SymCleanup) cleanup = nullptr;
    decltype(&::SymLoadModuleExW) load_module = nullptr;
    decltype(&::SymFromNameW) from_name = nullptr;
    decltype(&::SymFromAddrW) from_addr = nullptr;
    decltype(&::SymGetModuleInfoW64) get_module_info = nullptr;
    decltype(&::SymGetLineFromAddrW64) get_line = nullptr;
    decltype(&::SymEnumSymbolsW) enum_symbols = nullptr;
    decltype(&::SymGetSearchPathW) get_search_path = nullptr;
    decltype(&::SymSetSearchPathW) set_search_path = nullptr;
    decltype(&::StackWalk64) stack_walk = nullptr;
    decltype(&::SymFunctionTableAccess64) function_table_access = nullptr;
    decltype(&::SymGetModuleBase64) get_module_base = nullptr;
};

struct session_state {
    struct module_state {
        std::wstring image_path;
        std::uint64_t base = 0;
        std::uint32_t size = 0;
    };
    HANDLE process = nullptr;
    std::vector<std::wstring> image_directories;
    std::vector<module_state> modules;
};

std::mutex g_mutex;
dbghelp_api g_api;
HMODULE g_dbghelp = nullptr;
bool g_load_attempted = false;
bool g_has_symsrv = false;
std::wstring g_dbghelp_path;
std::string g_load_error;
std::vector<session_state> g_sessions;

template <typename T>
bool bind(T &target, const char *name) noexcept {
    FARPROC proc = GetProcAddress(g_dbghelp, name);
    if (!proc) return false;
    static_assert(sizeof(target) == sizeof(proc), "Windows function pointers must be pointer-sized");
    std::memcpy(&target, &proc, sizeof(target));
    return true;
}

std::wstring join_path(const std::wstring &directory, const wchar_t *leaf) {
    if (directory.empty()) return std::wstring(leaf);
    const wchar_t last = directory.back();
    return directory + ((last == L'\\' || last == L'/') ? L"" : L"\\") + leaf;
}

bool regular_file(const std::wstring &path) noexcept {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool read_exact(HANDLE file, void *buffer, DWORD size) noexcept {
    DWORD done = 0;
    return ReadFile(file, buffer, size, &done, nullptr) != FALSE && done == size;
}

bool seek_file(HANDLE file, LONGLONG offset) noexcept {
    LARGE_INTEGER position{};
    position.QuadPart = offset;
    return SetFilePointerEx(file, position, nullptr, FILE_BEGIN) != FALSE;
}

bool has_process_machine(const std::wstring &path) noexcept {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    IMAGE_DOS_HEADER dos{};
    bool ok = read_exact(file, &dos, static_cast<DWORD>(sizeof(dos))) &&
              dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0 &&
              seek_file(file, dos.e_lfanew);
    DWORD signature = 0;
    IMAGE_FILE_HEADER header{};
    if (ok) ok = read_exact(file, &signature, static_cast<DWORD>(sizeof(signature))) &&
                 read_exact(file, &header, static_cast<DWORD>(sizeof(header))) &&
                 signature == IMAGE_NT_SIGNATURE;
    CloseHandle(file);
#if defined(_WIN64)
    return ok && header.Machine == IMAGE_FILE_MACHINE_AMD64;
#else
    return ok && header.Machine == IMAGE_FILE_MACHINE_I386;
#endif
}

bool usable_dbghelp_directory(const std::wstring &directory, std::wstring &result) {
    const std::wstring dbghelp = join_path(directory, L"dbghelp.dll");
    const std::wstring symsrv = join_path(directory, L"symsrv.dll");
    if (!regular_file(dbghelp) || !regular_file(symsrv)) return false;
    if (!has_process_machine(dbghelp) || !has_process_machine(symsrv)) return false;
    result = dbghelp;
    return true;
}

bool query_registry_string(const wchar_t *subkey, REGSAM view, const wchar_t *value,
                           std::wstring &out) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_QUERY_VALUE | view, &key) != ERROR_SUCCESS)
        return false;
    DWORD type = 0;
    DWORD bytes = 0;
    LSTATUS status = RegQueryValueExW(key, value, nullptr, &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) ||
        bytes < static_cast<DWORD>(sizeof(wchar_t))) {
        RegCloseKey(key);
        return false;
    }
    std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1, L'\0');
    status = RegQueryValueExW(key, value, nullptr, &type,
                              reinterpret_cast<BYTE *>(buffer.data()), &bytes);
    RegCloseKey(key);
    if (status != ERROR_SUCCESS) return false;
    buffer.back() = L'\0';
    out.assign(buffer.data());
    if (type == REG_EXPAND_SZ) {
        const DWORD needed = ExpandEnvironmentStringsW(out.c_str(), nullptr, 0);
        if (needed != 0) {
            std::vector<wchar_t> expanded(needed);
            if (ExpandEnvironmentStringsW(out.c_str(), expanded.data(), needed) != 0)
                out.assign(expanded.data());
        }
    }
    return !out.empty();
}

bool find_sdk_dbghelp(std::wstring &result) {
    static const wchar_t *const keys[] = {
        L"SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows Kits\\Installed Roots"
    };
    static const REGSAM views[] = {KEY_WOW64_64KEY, KEY_WOW64_32KEY};
    for (const wchar_t *key : keys) {
        for (REGSAM view : views) {
            std::wstring root;
            if (!query_registry_string(key, view, L"KitsRoot10", root)) continue;
#if defined(_WIN64)
            const std::wstring directory = join_path(root, L"Debuggers\\x64");
#else
            const std::wstring directory = join_path(root, L"Debuggers\\x86");
#endif
            if (usable_dbghelp_directory(directory, result)) return true;
        }
    }
    return false;
}

std::wstring environment_variable(const wchar_t *name) {
    const DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0) return {};
    std::vector<wchar_t> value(needed);
    const DWORD written = GetEnvironmentVariableW(name, value.data(), needed);
    if (written == 0 || written >= needed) return {};
    return std::wstring(value.data(), written);
}

std::wstring trim_process_output(std::wstring text) {
    const wchar_t *space = L" \t\r\n";
    const std::wstring::size_type first = text.find_first_not_of(space);
    if (first == std::wstring::npos) return {};
    const std::wstring::size_type last = text.find_last_not_of(space);
    text = text.substr(first, last - first + 1);
    if (text.size() >= 2 && text.front() == L'\"' && text.back() == L'\"')
        text = text.substr(1, text.size() - 2);
    return text;
}

bool run_vswhere(const std::wstring &program, std::wstring &install_path) {
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &security, 0)) return false;
    if (!SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        return false;
    }

    std::wstring command = L"\"" + program + L"\" -latest -property installationPath";
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = static_cast<DWORD>(sizeof(startup));
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = write_pipe;
    startup.hStdError = write_pipe;
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(program.c_str(), mutable_command.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    CloseHandle(write_pipe);
    if (!created) {
        CloseHandle(read_pipe);
        return false;
    }

    std::string bytes;
    char buffer[1024];
    DWORD count = 0;
    while (ReadFile(read_pipe, buffer, static_cast<DWORD>(sizeof(buffer)), &count, nullptr) && count != 0)
        bytes.append(buffer, count);
    CloseHandle(read_pipe);
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (exit_code != 0 || bytes.empty()) return false;

    const int chars = MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (chars <= 0) return false;
    std::wstring output(static_cast<std::size_t>(chars), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()),
                            &output[0], chars) != chars)
        return false;
    install_path = trim_process_output(std::move(output));
    return !install_path.empty();
}

bool search_vs_directory(const std::wstring &directory, std::wstring &result) {
    if (usable_dbghelp_directory(directory, result)) return true;
    WIN32_FIND_DATAW item{};
    const std::wstring pattern = join_path(directory, L"*");
    HANDLE search = FindFirstFileW(pattern.c_str(), &item);
    if (search == INVALID_HANDLE_VALUE) return false;
    do {
        if ((item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (item.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            std::wcscmp(item.cFileName, L".") == 0 || std::wcscmp(item.cFileName, L"..") == 0)
            continue;
        if (search_vs_directory(join_path(directory, item.cFileName), result)) {
            FindClose(search);
            return true;
        }
    } while (FindNextFileW(search, &item));
    FindClose(search);
    return false;
}

bool find_vs_dbghelp(std::wstring &result) {
    std::wstring program_files = environment_variable(L"ProgramFiles(x86)");
    if (program_files.empty()) program_files = environment_variable(L"ProgramFiles");
    if (program_files.empty()) return false;
    const std::wstring vswhere = join_path(program_files,
        L"Microsoft Visual Studio\\Installer\\vswhere.exe");
    if (!regular_file(vswhere)) return false;
    std::wstring install_path;
    return run_vswhere(vswhere, install_path) && search_vs_directory(install_path, result);
}

std::wstring system_dbghelp_path() {
    std::vector<wchar_t> directory(MAX_PATH);
#if !defined(_WIN64)
    // A Win32 controller running under WOW64 needs the x86 system DLL. Naming
    // SysWOW64 explicitly also makes active_dbghelp_path report the file actually used.
    const UINT wow64_length = GetSystemWow64DirectoryW(directory.data(), static_cast<UINT>(directory.size()));
    if (wow64_length != 0 && static_cast<std::size_t>(wow64_length) < directory.size())
        return join_path(std::wstring(directory.data(), wow64_length), L"dbghelp.dll");
#endif
    UINT length = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
    if (length == 0) return {};
    if (static_cast<std::size_t>(length) >= directory.size()) {
        directory.resize(static_cast<std::size_t>(length) + 1);
        length = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
        if (length == 0 || static_cast<std::size_t>(length) >= directory.size()) return {};
    }
    return join_path(std::wstring(directory.data(), length), L"dbghelp.dll");
}

std::string narrow(const std::wstring &text) {
    if (text.empty()) return {};
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                          nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return {};
    std::string result(static_cast<std::size_t>(bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                            &result[0], bytes, nullptr, nullptr) != bytes)
        return {};
    // Callers sometimes pass a length that includes the terminator (dbghelp's NameLen).
    while (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

std::wstring widen(const std::string &text) {
    if (text.empty()) return {};
    int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                    static_cast<int>(text.size()), nullptr, 0);
    UINT code_page = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (chars <= 0) {
        code_page = CP_ACP;
        flags = 0;
        chars = MultiByteToWideChar(code_page, flags, text.data(),
                                    static_cast<int>(text.size()), nullptr, 0);
    }
    if (chars <= 0) return {};
    std::wstring result(static_cast<std::size_t>(chars), L'\0');
    if (MultiByteToWideChar(code_page, flags, text.data(), static_cast<int>(text.size()),
                            &result[0], chars) != chars)
        return {};
    return result;
}

std::string win32_error(const char *operation) {
    return std::string(operation) + " failed (Win32=" + std::to_string(GetLastError()) + ")";
}

bool bind_api(std::string &error) {
    if (bind(g_api.set_options, "SymSetOptions") &&
        bind(g_api.initialize, "SymInitializeW") &&
        bind(g_api.cleanup, "SymCleanup") &&
        bind(g_api.load_module, "SymLoadModuleExW") &&
        bind(g_api.from_name, "SymFromNameW") &&
        bind(g_api.from_addr, "SymFromAddrW") &&
        bind(g_api.get_module_info, "SymGetModuleInfoW64") &&
        bind(g_api.get_line, "SymGetLineFromAddrW64") &&
        bind(g_api.enum_symbols, "SymEnumSymbolsW") &&
        bind(g_api.get_search_path, "SymGetSearchPathW") &&
        bind(g_api.set_search_path, "SymSetSearchPathW") &&
        bind(g_api.stack_walk, "StackWalk64") &&
        bind(g_api.function_table_access, "SymFunctionTableAccess64") &&
        bind(g_api.get_module_base, "SymGetModuleBase64"))
        return true;
    error = win32_error("GetProcAddress for a required DbgHelp function");
    return false;
}

bool load_dbghelp() {
    if (g_load_attempted) return g_dbghelp != nullptr;
    g_load_attempted = true;
    try {
        auto try_path = [](const std::wstring &path, bool with_symsrv) {
            if (path.empty()) return false;
            // Symbol-server support is supplied by symsrv.dll beside the Debugging
            // Tools DbgHelp. This flag makes that directory the dependency search path.
            g_dbghelp = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
            if (!g_dbghelp) {
                g_load_error = win32_error("LoadLibraryExW(dbghelp.dll)");
                return false;
            }
            std::string error;
            if (!bind_api(error)) {
                FreeLibrary(g_dbghelp);
                g_dbghelp = nullptr;
                g_load_error = error;
                return false;
            }
            g_dbghelp_path = path;
            g_has_symsrv = with_symsrv;
            return true;
        };

        std::wstring path;
        if (find_sdk_dbghelp(path) && try_path(path, true)) return true;
        path.clear();
        if (find_vs_dbghelp(path) && try_path(path, true)) return true;
        path = system_dbghelp_path();
        if (try_path(path, false)) return true;
        if (path.empty()) g_load_error = "could not locate dbghelp.dll";
        return false;
    } catch (...) {
        if (g_dbghelp) {
            FreeLibrary(g_dbghelp);
            g_dbghelp = nullptr;
        }
        try { g_load_error = "out of memory while locating dbghelp.dll"; } catch (...) {}
        return false;
    }
}

std::vector<session_state>::iterator find_session(HANDLE process) {
    return std::find_if(g_sessions.begin(), g_sessions.end(),
                        [process](const session_state &state) { return state.process == process; });
}

std::wstring full_path(const std::wstring &path) {
    const DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (needed == 0) return path;
    std::vector<wchar_t> buffer(needed);
    const DWORD written = GetFullPathNameW(path.c_str(), needed, buffer.data(), nullptr);
    return written != 0 && written < needed ? std::wstring(buffer.data(), written) : path;
}

std::wstring parent_directory(const std::wstring &path) {
    const std::wstring absolute = full_path(path);
    const std::wstring::size_type slash = absolute.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return {};
    return absolute.substr(0, slash);
}

std::wstring base_name(const std::wstring &path) {
    const std::wstring::size_type slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

std::vector<std::wstring> module_queries(const std::string &module, const std::string &name) {
    const std::wstring wide_module = widen(module);
    const std::wstring wide_name = widen(name);
    if (wide_module.empty() || wide_name.empty()) return {};
    std::vector<std::wstring> module_names;
    module_names.push_back(wide_module);
    const std::wstring basename = base_name(wide_module);
    if (_wcsicmp(basename.c_str(), wide_module.c_str()) != 0) module_names.push_back(basename);
    const std::wstring::size_type dot = basename.find_last_of(L'.');
    if (dot != std::wstring::npos && dot != 0) module_names.push_back(basename.substr(0, dot));

    std::vector<std::wstring> result;
    for (const std::wstring &candidate : module_names) {
        const auto duplicate = std::find_if(result.begin(), result.end(), [&candidate](const std::wstring &query) {
            const std::wstring::size_type bang = query.find(L'!');
            return bang != std::wstring::npos && candidate.size() == bang &&
                   _wcsnicmp(query.c_str(), candidate.c_str(), bang) == 0;
        });
        if (duplicate == result.end()) result.push_back(candidate + L"!" + wide_name);
    }
    return result;
}

void append_image_directory(session_state &session, const std::wstring &image_path) {
    const std::wstring directory = parent_directory(image_path);
    if (directory.empty()) return;
    const auto already_present = std::find_if(session.image_directories.begin(), session.image_directories.end(),
        [&directory](const std::wstring &entry) { return _wcsicmp(entry.c_str(), directory.c_str()) == 0; });
    if (already_present != session.image_directories.end()) return;

    std::vector<wchar_t> current(32768, L'\0');
    if (!g_api.get_search_path(session.process, current.data(), static_cast<DWORD>(current.size())))
        return;
    std::wstring updated(current.data());
    if (!updated.empty() && updated.back() != L';') updated.push_back(L';');
    updated += directory;
    if (g_api.set_search_path(session.process, updated.c_str()))
        session.image_directories.push_back(directory);
}

std::string hex_address(std::uint64_t address) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(address));
    return buffer;
}

struct enum_context {
    std::vector<symbol_entry> *output = nullptr;
    bool allocation_failed = false;
};

BOOL CALLBACK collect_symbol(PSYMBOL_INFOW symbol, ULONG size, PVOID user) noexcept {
    enum_context *context = static_cast<enum_context *>(user);
    try {
        symbol_entry entry;
        entry.name = narrow(std::wstring(symbol->Name, symbol->NameLen));
        entry.address = static_cast<std::uint64_t>(symbol->Address);
        entry.size = static_cast<std::uint32_t>(size);
        entry.is_export = (symbol->Flags & SYMFLAG_EXPORT) != 0;
        context->output->push_back(std::move(entry));
        return TRUE;
    } catch (...) {
        context->allocation_failed = true;
        return FALSE;
    }
}

} // namespace

bool init(HANDLE process, std::string &which_dbghelp_or_error) {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!process) {
            which_dbghelp_or_error = "invalid symbol-session handle";
            return false;
        }
        if (!load_dbghelp()) {
            which_dbghelp_or_error = g_load_error;
            return false;
        }
        if (find_session(process) != g_sessions.end()) {
            try { which_dbghelp_or_error = narrow(g_dbghelp_path); } catch (...) {}
            return true;
        }
        g_api.set_options(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS |
                          SYMOPT_NO_PROMPTS | SYMOPT_LOAD_LINES);
        // A null search path asks DbgHelp to construct WinDbg's normal environment-based
        // path, including _NT_SYMBOL_PATH and _NT_ALT_SYMBOL_PATH.
        if (!g_api.initialize(process, nullptr, FALSE)) {
            which_dbghelp_or_error = win32_error("SymInitializeW");
            return false;
        }
        try {
            session_state state;
            state.process = process;
            g_sessions.push_back(std::move(state));
        } catch (...) {
            g_api.cleanup(process);
            throw;
        }
        try { which_dbghelp_or_error = narrow(g_dbghelp_path); } catch (...) {}
        return true;
    } catch (...) {
        try { which_dbghelp_or_error = "out of memory while initializing symbols"; } catch (...) {}
        return false;
    }
}

void register_module(HANDLE process, const std::wstring &image_path,
                     std::uint64_t base, std::uint32_t size_of_image) {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_dbghelp || image_path.empty()) return;
        const auto session = find_session(process);
        if (session == g_sessions.end()) return;
        append_image_directory(*session, image_path);
        const auto existing = std::find_if(session->modules.begin(), session->modules.end(),
            [base](const session_state::module_state &module) { return module.base == base; });
        if (existing == session->modules.end()) {
            session_state::module_state module;
            module.image_path = image_path;
            module.base = base;
            module.size = size_of_image;
            session->modules.push_back(std::move(module));
        } else {
            existing->image_path = image_path;
            existing->size = size_of_image;
        }
        g_api.load_module(process, nullptr, image_path.c_str(), nullptr,
                          static_cast<DWORD64>(base), static_cast<DWORD>(size_of_image), nullptr, 0);
    } catch (...) {
    }
}

bool resolve(HANDLE process, const std::string &module, const std::string &name,
             std::uint64_t &address) {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_dbghelp || find_session(process) == g_sessions.end() || module.empty() || name.empty())
            return false;
        constexpr ULONG max_name = 2048;
        std::vector<unsigned char> storage(sizeof(SYMBOL_INFOW) +
            (static_cast<std::size_t>(max_name) - 1) * sizeof(wchar_t), 0);
        PSYMBOL_INFOW symbol = reinterpret_cast<PSYMBOL_INFOW>(storage.data());
        for (const std::wstring &query : module_queries(module, name)) {
            std::memset(storage.data(), 0, storage.size());
            symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
            symbol->MaxNameLen = max_name;
            if (g_api.from_name(process, query.c_str(), symbol)) {
                address = static_cast<std::uint64_t>(symbol->Address);
                return true;
            }
        }
        return false;
    } catch (...) {
        return false;
    }
}

std::string symbolize(HANDLE process, std::uint64_t address) {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        const std::string numeric = hex_address(address);
        const auto session = find_session(process);
        if (!g_dbghelp || session == g_sessions.end()) return numeric;

        IMAGEHLP_MODULEW64 module{};
        module.SizeOfStruct = sizeof(module);
        const bool have_module = g_api.get_module_info(process, static_cast<DWORD64>(address), &module) != FALSE;
        std::wstring module_name;
        if (have_module) {
            module_name = module.ModuleName;
            if (module_name.empty()) module_name = module.ImageName;
            module_name = base_name(module_name);
        }
        std::uint64_t module_base = have_module ? static_cast<std::uint64_t>(module.BaseOfImage) : 0;
        if (module_name.empty() || module_base == 0) {
            const auto registered = std::find_if(session->modules.begin(), session->modules.end(),
                [address](const session_state::module_state &entry) {
                    return address >= entry.base && address - entry.base < entry.size;
                });
            if (registered != session->modules.end()) {
                if (module_name.empty()) module_name = base_name(registered->image_path);
                if (module_base == 0) module_base = registered->base;
            }
        }

        constexpr ULONG max_name = 2048;
        std::vector<unsigned char> storage(sizeof(SYMBOL_INFOW) +
            (static_cast<std::size_t>(max_name) - 1) * sizeof(wchar_t), 0);
        PSYMBOL_INFOW symbol = reinterpret_cast<PSYMBOL_INFOW>(storage.data());
        symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
        symbol->MaxNameLen = max_name;
        DWORD64 displacement = 0;
        if (g_api.from_addr(process, static_cast<DWORD64>(address), &displacement, symbol)) {
            std::string output = narrow(module_name);
            if (!output.empty()) output.push_back('!');
            output += narrow(std::wstring(symbol->Name, symbol->NameLen));
            output += "+" + hex_address(static_cast<std::uint64_t>(displacement));

            IMAGEHLP_LINEW64 line{};
            line.SizeOfStruct = sizeof(line);
            DWORD line_displacement = 0;
            if (g_api.get_line(process, static_cast<DWORD64>(address), &line_displacement, &line) &&
                line.FileName) {
                output += " (" + narrow(line.FileName) + ":" + std::to_string(line.LineNumber) + ")";
            }
            return output + " [" + numeric + "]";
        }
        if (module_base != 0 && !module_name.empty()) {
            const std::uint64_t offset = address - module_base;
            return narrow(module_name) + "+" + hex_address(offset) + " [" + numeric + "]";
        }
        return numeric;
    } catch (...) {
        try { return hex_address(address); } catch (...) { return {}; }
    }
}

bool walk_stack(HANDLE process, HANDLE thread, CONTEXT ctx,
                std::uint64_t pc, std::uint64_t sp, std::uint64_t fp,
                std::vector<std::uint64_t> &frames, std::size_t max_frames) {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        frames.clear();
        if (!g_dbghelp || find_session(process) == g_sessions.end() || !thread || max_frames == 0)
            return false;
        frames.push_back(pc);

        STACKFRAME64 frame{};
        frame.AddrPC.Offset = static_cast<DWORD64>(pc);
        frame.AddrPC.Mode = AddrModeFlat;
        frame.AddrStack.Offset = static_cast<DWORD64>(sp);
        frame.AddrStack.Mode = AddrModeFlat;
        frame.AddrFrame.Offset = static_cast<DWORD64>(fp);
        frame.AddrFrame.Mode = AddrModeFlat;
        ctx.ContextFlags |= CONTEXT_FULL;
#if defined(_WIN64)
        const DWORD machine = IMAGE_FILE_MACHINE_AMD64;
        ctx.Rip = static_cast<DWORD64>(pc);
        ctx.Rsp = static_cast<DWORD64>(sp);
        ctx.Rbp = static_cast<DWORD64>(fp);
#else
        const DWORD machine = IMAGE_FILE_MACHINE_I386;
        ctx.Eip = static_cast<DWORD>(pc);
        ctx.Esp = static_cast<DWORD>(sp);
        ctx.Ebp = static_cast<DWORD>(fp);
#endif
        std::size_t attempts = 0;
        bool first = true;
        while (frames.size() < max_frames && attempts++ < max_frames + 8) {
            const DWORD64 previous_pc = frame.AddrPC.Offset;
            const DWORD64 previous_sp = frame.AddrStack.Offset;
            if (!g_api.stack_walk(machine, process, thread, &frame, &ctx, nullptr,
                                  g_api.function_table_access, g_api.get_module_base, nullptr))
                break;
            const std::uint64_t next = static_cast<std::uint64_t>(frame.AddrPC.Offset);
            if (next == 0) break;
            // The first StackWalk64 call reports frame 0 itself (same pc and, on x64, the
            // same stack pointer): that is not "no progress", it is the frame we already have.
            if (first) { first = false; if (next == pc) continue; }
            if (frame.AddrPC.Offset == previous_pc && frame.AddrStack.Offset == previous_sp) break;
            if (next != frames.back()) frames.push_back(next);
        }
        return true;
    } catch (...) {
        frames.clear();
        return false;
    }
}

bool enumerate(HANDLE process, const std::string &module, const std::string &mask,
               std::vector<symbol_entry> &out) {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        out.clear();
        if (!g_dbghelp || find_session(process) == g_sessions.end() || module.empty()) return false;
        const std::vector<std::wstring> queries = module_queries(module, mask.empty() ? "*" : mask);
        bool succeeded = false;
        for (const std::wstring &query : queries) {
            out.clear();
            enum_context context{&out, false};
            const BOOL ok = g_api.enum_symbols(process, 0, query.c_str(), collect_symbol, &context);
            if (context.allocation_failed) {
                out.clear();
                return false;
            }
            succeeded = succeeded || ok != FALSE;
            if (ok && !out.empty()) return true;
        }
        // A successful enumeration with no matches is still a successful query.
        return succeeded;
    } catch (...) {
        out.clear();
        return false;
    }
}

void cleanup(HANDLE process) {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        const auto session = find_session(process);
        if (!g_dbghelp || session == g_sessions.end()) return;
        g_api.cleanup(process);
        g_sessions.erase(session);
    } catch (...) {
    }
}

std::string active_dbghelp_path() {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        return narrow(g_dbghelp_path);
    } catch (...) {
        return {};
    }
}

bool has_symbol_server() {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_dbghelp != nullptr && g_has_symsrv;
    } catch (...) {
        return false;
    }
}

} // namespace uhh_sym
