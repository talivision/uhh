#include "probe_api.h"
#include "callbacks.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

static std::string sibling_app() {
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return "probe_app.exe";
    std::string result(path); size_t slash = result.find_last_of("\\/");
    return result.substr(0, slash == std::string::npos ? 0 : slash + 1) + "probe_app.exe";
}

int main(int argc, char **argv) {
    const char *env_flag = std::getenv("PROBE_FLAG_RVA");
    const char *env_read = std::getenv("PROBE_READ_RVA");
    bool any_env = (env_flag && *env_flag) || (env_read && *env_read);
    bool use_env = env_flag && *env_flag && env_read && *env_read;
    const char *flag_rva = use_env ? env_flag : (argc > 1 ? argv[1] : nullptr);
    const char *read_rva = use_env ? env_read : (argc > 2 ? argv[2] : nullptr);
    int first_passthrough = use_env ? 1 : 3;
    if (any_env != use_env || !flag_rva || !*flag_rva || !read_rva || !*read_rva) {
        std::fprintf(stderr, "usage: gated_config <flag_rva> <read_rva> [probe_app args...]\n"
                             "       or set both PROBE_FLAG_RVA and PROBE_READ_RVA\n");
        return 2;
    }
    auto parse_rva = [](const char *text, const char *kind, unsigned long long &value) {
        errno = 0; char *end = nullptr; value = std::strtoull(text, &end, 0);
        if (*text == '-' || errno == ERANGE || !end || *end) {
            std::fprintf(stderr, "gated_config: invalid %s RVA: %s\n", kind, text); return false;
        }
        return true;
    };
    unsigned long long parsed_flag{}, parsed_read{};
    if (!parse_rva(flag_rva, "flag", parsed_flag) || !parse_rva(read_rva, "read", parsed_read)) return 2;
    char flag_text[96], read_text[96];
    std::snprintf(flag_text, sizeof(flag_text), "configparse.dll+0x%llx", parsed_flag);
    std::snprintf(read_text, sizeof(read_text), "probe_app.exe+0x%llx", parsed_read);
    std::string app = sibling_app();
    std::vector<char *> child_args; child_args.push_back(app.data());
    for (int i = first_passthrough; i < argc; ++i) child_args.push_back(argv[i]);
    child_args.push_back(nullptr);

    probe_session *s = probe_session_create();
    if (!s) return 1;
    read_log_config cfg{0x7265616473697465ULL};
    int ok = probe_add(s, flag_text, enable_reads, PROBE_BREAKPOINT) &&
             probe_add_cfg(s, read_text, log_read, PROBE_INLINE, &cfg, sizeof(cfg)) &&
             probe_launch(s, child_args.data()) && probe_run(s) && probe_wait_for_exit(s);
    ok = ok && gated_override_count() == 1;
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
