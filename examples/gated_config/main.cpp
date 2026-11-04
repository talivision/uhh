#include "probe_api.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

static uint64_t override_count;

static void enable_reads(probe_context *c) {
    if (probe_reg(c, PROBE_REG_AX) == 0) {
        if (probe_set_reg(c, PROBE_REG_AX, 1)) ++override_count;
    }
}

static std::string sibling_app() {
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return "probe_app.exe";
    std::string result(path); size_t slash = result.find_last_of("\\/");
    return result.substr(0, slash == std::string::npos ? 0 : slash + 1) + "probe_app.exe";
}

int main(int argc, char **argv) {
    const char *env_rva = std::getenv("PROBE_FLAG_RVA");
    bool use_env = env_rva && *env_rva;
    const char *rva = use_env ? env_rva : (argc > 1 ? argv[1] : nullptr);
    int first_passthrough = use_env ? 1 : 2;
    if (!rva || !*rva) {
        std::fprintf(stderr, "usage: gated_config <flag_rva> [probe_app args...]\n"
                             "       or set PROBE_FLAG_RVA\n");
        return 2;
    }
    errno = 0; char *end = nullptr;
    unsigned long long parsed_rva = std::strtoull(rva, &end, 0);
    if (*rva == '-' || errno == ERANGE || !end || *end) {
        std::fprintf(stderr, "gated_config: invalid flag RVA: %s\n", rva);
        return 2;
    }
    char location_text[96];
    std::snprintf(location_text, sizeof(location_text), "configparse.dll+0x%llx", parsed_rva);
    std::string location = location_text;
    std::string app = sibling_app();
    std::vector<char *> child_args; child_args.push_back(app.data());
    for (int i = first_passthrough; i < argc; ++i) child_args.push_back(argv[i]);
    child_args.push_back(nullptr);

    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add(s, location.c_str(), enable_reads, PROBE_BREAKPOINT) &&
             probe_launch(s, child_args.data()) && probe_run(s) && probe_wait_for_exit(s);
    ok = ok && override_count == 1;
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
