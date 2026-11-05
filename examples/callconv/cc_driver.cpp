// cc_driver --backend breakpoint|hw|inline --mode wrap|replace|wrongpop [--mask HEX] -- cc_target.exe ...
// Probes the entry of every ccfix.dll function in mask (cc_shared.h ids; default all) with
// cc_on_entry (cc_callbacks.cpp) and runs cc_target. Regress `callconv-*`.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "probe_api.h"
#include "cc_shared.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" void cc_on_entry(probe_context *);
struct cc_cfg { uint32_t mode, id; };

int main(int argc, char **argv) {
    uint32_t bk = 0, mode = 0, mask = 0xFFFFFFFFu;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            bk = !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "inline") ? PROBE_INLINE
               : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : 0;
        } else if (!std::strcmp(argv[i], "--mode") && i + 1 < argc) {
            const char *m = argv[++i];
            mode = !std::strcmp(m, "wrap") ? CC_WRAP : !std::strcmp(m, "replace") ? CC_REPLACE
                 : !std::strcmp(m, "wrongpop") ? CC_WRONGPOP : !std::strcmp(m, "none") ? CC_NONE : 99;
        } else if (!std::strcmp(argv[i], "--mask") && i + 1 < argc) {
            mask = (uint32_t)std::strtoul(argv[++i], nullptr, 16);
        }
    }
    if (!bk || mode == 99 || i + 1 >= argc) { std::fprintf(stderr, "usage: see cc_driver.cpp\n"); return 2; }
    probe_session *s = probe_session_create();
    if (!s) return 1;
    std::vector<cc_cfg> cfgs(CC_N);
    for (uint32_t id = 0; id < CC_N; ++id) {
        if (!((mask >> id) & 1)) continue;
#if defined(_WIN64)
        if (CC_FNS[id].x86_only) continue;
#endif
        cfgs[id] = {mode, id};
        std::string loc = std::string(CC_FNS[id].module) + "!" + CC_FNS[id].name;
        if (!probe_add_symbol_cfg(s, loc.c_str(), cc_on_entry, bk, &cfgs[id], sizeof(cc_cfg))) {
            std::fprintf(stderr, "cc_driver: add %s failed\n", loc.c_str()); probe_close(s); return 1;
        }
    }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    int r = probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout); probe_close(s);
    return r ? 0 : 1;
}
