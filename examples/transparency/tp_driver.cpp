// tp_driver --backend breakpoint|hw|inline --mode noop|log|mem|sys|callfn|co
//           [--probes add,i64,...] -- tp_target.exe [--iters N] [--spawn]
// Transparency fixture (regress `transparency`): probes tp_target's functions and its
// mid-function site with ONE callback (tp_callbacks.cpp) in the given mode, runs the target,
// prints the report. Default probes: all (hw takes at most 4; pass a subset).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "probe_api.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" void tp_on_hit(probe_context *);
extern "C" void tp_on_spawn(probe_context *);
extern "C" void tp_on_ovf(probe_context *);
struct tp_cfg { uint32_t mode, nargs, pop, backend, entry; char module[48]; };   // see tp_callbacks.cpp

struct Site { const char *name, *symbol; uint32_t nargs, pop; int special; };   // 1 spawn, 2 ovf
#if defined(_WIN64)
static const Site kSites[] = {
    {"add", "tp_add", 2, 0, 0}, {"i64", "tp_i64", 2, 0, 0}, {"dbl", "tp_dbl", 2, 0, 0},
    {"dblarg", "tp_dblarg", 2, 0, 0}, {"seterr", "tp_seterr", 1, 0, 0}, {"std", "tp_std", 3, 0, 0},
    {"align", "tp_align", 1, 0, 0}, {"fact", "tp_fact", 1, 0, 0}, {"mid", "TpMidHit", 0, 0, 0},
    {"spawn", "tp_spawn", 2, 0, 1}, {"thread", "tp_threadfn", 1, 0, 0}, {"peek", "tp_peek", 1, 0, 0}, {"ovf", "tp_ovf", 1, 0, 2}};
#else
static const Site kSites[] = {
    {"add", "tp_add", 2, 0, 0}, {"i64", "tp_i64", 2, 0, 0}, {"dbl", "tp_dbl", 2, 0, 0},
    {"dblarg", "tp_dblarg", 3, 0, 0}, {"seterr", "tp_seterr", 1, 0, 0}, {"std", "tp_std", 3, 3, 0},
    {"align", "tp_align", 1, 0, 0}, {"fact", "tp_fact", 1, 0, 0}, {"mid", "TpMidHit", 0, 0, 0},
    {"spawn", "tp_spawn", 2, 0, 1}, {"thread", "tp_threadfn", 1, 1, 0}, {"peek", "tp_peek", 1, 0, 0}, {"ovf", "tp_ovf", 1, 0, 2}};
#endif
static const char *kModes[] = {"noop", "log", "mem", "sys", "callfn", "co"};

int main(int argc, char **argv) {
    uint32_t bk = 0, mode = UINT32_MAX;
    std::string only;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            bk = !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "inline") ? PROBE_INLINE
               : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : 0;
        } else if (!std::strcmp(argv[i], "--mode") && i + 1 < argc) {
            const char *m = argv[++i];
            for (uint32_t k = 0; k < sizeof(kModes) / sizeof(kModes[0]); ++k) if (!std::strcmp(m, kModes[k])) mode = k;
        } else if (!std::strcmp(argv[i], "--probes") && i + 1 < argc) only = std::string(",") + argv[++i] + ",";
    }
    if (!bk || mode == UINT32_MAX || i + 1 >= argc) { std::fprintf(stderr, "usage: see tp_driver.cpp\n"); return 2; }
    probe_session *s = probe_session_create();
    if (!s) return 1;
    // The target's image name (tp_target.exe, or its /CETCOMPAT twin tp_target_cet.exe).
    std::string module = argv[i + 1];
    if (size_t slash = module.find_last_of("\\/"); slash != std::string::npos) module.erase(0, slash + 1);
    if (module.size() < 4 || _stricmp(module.c_str() + module.size() - 4, ".exe")) module += ".exe";
    if (module.size() >= sizeof(tp_cfg::module)) { std::fprintf(stderr, "tp_driver: target name too long\n"); return 2; }
    for (const Site &site : kSites) {
        if (!only.empty() && only.find(std::string(",") + site.name + ",") == std::string::npos) continue;
        tp_cfg cfg{mode, site.nargs, site.pop, bk, std::strcmp(site.name, "mid") ? 1u : 0u, {}};
        std::memcpy(cfg.module, module.c_str(), module.size() + 1);
        std::string loc = module + "!" + site.symbol;
        if (!probe_add_symbol_cfg(s, loc.c_str(), site.special == 1 ? tp_on_spawn : site.special == 2 ? tp_on_ovf : tp_on_hit, bk, &cfg, sizeof(cfg))) {
            std::fprintf(stderr, "tp_driver: add %s failed\n", loc.c_str());
            probe_close(s);
            return 1;
        }
    }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    int r = probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout); probe_close(s);
    return r ? 0 : 1;
}
