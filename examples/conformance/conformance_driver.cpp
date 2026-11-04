// conformance_driver --backend breakpoint|hw|inline -- <conformance_target.exe>
#include "probe_api.h"
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" void conf_on_site(probe_context *);
extern "C" void conf_move_sp(probe_context *);
struct conf_config { uint64_t cookie; };

int main(int argc, char **argv) {
    uint32_t backend = PROBE_BREAKPOINT; int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i)
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            backend = !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "inline") ? PROBE_INLINE : PROBE_BREAKPOINT;
        }
    if (i + 1 >= argc) { std::fprintf(stderr, "usage: conformance_driver --backend b -- target.exe\n"); return 2; }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    conf_config cfg{0xC0F1C0F1C0F1C0F1ull};
    probe_session *s = probe_session_create();
    int ok = s && probe_add_symbol_cfg(s, "conformance_target.exe!conf_site", conf_on_site, backend, &cfg, sizeof(cfg)) &&
             probe_add_symbol(s, "conformance_target.exe!SpSite+0x3", conf_move_sp, backend) &&
             probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    if (s) { probe_report(s, stdout); probe_close(s); }
    return ok ? 0 : 1;
}
