// stacks_driver --backend breakpoint|hw|inline NAME=LOCATION... -- <stacks_target.exe>
// Probes each LOCATION with the same callback (stk_on_site: send_log_stack "stack NAME").
#include "probe_api.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" void stk_on_site(probe_context *);
struct stk_config { char name[16]; };

int main(int argc, char **argv) {
    uint32_t backend = PROBE_BREAKPOINT; int i = 1;
    std::vector<std::pair<stk_config, std::string>> sites;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            backend = !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "inline") ? PROBE_INLINE : PROBE_BREAKPOINT;
            continue;
        }
        const char *eq = std::strchr(argv[i], '=');
        if (!eq || eq - argv[i] >= 16) { std::fprintf(stderr, "bad site '%s' (NAME=LOCATION)\n", argv[i]); return 2; }
        stk_config cfg{}; std::memcpy(cfg.name, argv[i], eq - argv[i]);
        sites.push_back({cfg, eq + 1});
    }
    if (i + 1 >= argc || sites.empty()) {
        std::fprintf(stderr, "usage: stacks_driver --backend b NAME=LOCATION... -- target.exe\n"); return 2;
    }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    probe_session *s = probe_session_create();
    int ok = s != nullptr;
    for (auto &st : sites)
        ok = ok && probe_add_symbol_cfg(s, st.second.c_str(), stk_on_site, backend, &st.first, sizeof(st.first));
    ok = ok && probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    if (s) { probe_report(s, stdout); probe_close(s); }
    return ok ? 0 : 1;
}
