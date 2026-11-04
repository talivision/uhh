// uhh_trace -- trace calls to any exported function of any program.
//
//   uhh_trace [--backend inline|breakpoint|hw] [--stack]
//             -p "KernelBase.dll!CreateFileW:Wxx" [-p ...] -- program.exe [args...]
//
// After the ':' one format character per argument (see trace_callback.h). Inline probes
// fall back to a hardware breakpoint when the site cannot be hooked in time or is
// already hooked by someone else (PROBE_FALLBACK_HW). Output: the probe report (JSON
// lines); every call is a probe_log record, with a symbolized stack under --stack.
#include "trace_callback.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

int main(int argc, char **argv) {
    uint32_t backend = PROBE_BREAKPOINT; bool stack = false;
    std::vector<trace_config> cfgs; std::vector<std::string> locs;
    int i = 1;
    for (; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--")) { ++i; break; }
        if (!std::strcmp(argv[i], "--stack")) { stack = true; continue; }
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
    if (cfgs.empty() || i >= argc) {
        std::fprintf(stderr, "usage: uhh_trace [--backend inline|breakpoint|hw] [--stack] -p mod!Export[:fmt] ... -- prog [args]\n");
        return 2;
    }
    probe_session *s = probe_session_create();
    if (!s) return 1;
    uint32_t flags = backend | (backend == PROBE_INLINE ? PROBE_FALLBACK_HW : 0u);
    int ok = 1;
    for (size_t k = 0; k < cfgs.size(); ++k) {
        cfgs[k].stack = stack ? 1 : 0;
        ok = ok && probe_add_symbol_cfg(s, locs[k].c_str(), uhh_trace_call, flags, &cfgs[k], sizeof(cfgs[k]));
    }
    std::vector<char *> child(argv + i, argv + argc); child.push_back(nullptr);
    ok = ok && probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
