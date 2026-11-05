// edge_driver --backend breakpoint|hw|inline [--sites a,b,...] [--dual b1,b2] [--fallback-hw]
//             -- <edge_target.exe> [--iters K]
// Probes the named edgehunt sites (see edge_callbacks.cpp) with ONE backend (or, with
// --dual, EdgeDualSite with two backends at once), runs the target and prints its result
// row, the probe rows and the logs. Sites: rep stos ripload ripcmp ripvec ripstore cpuid
// rdtsc syscall int2e pushf popf retonly thunk jump faultmid x87 lock readd args mem fmt
// fmtptr leaf cbfault.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "probe_api.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" void edge_on_site(probe_context *);
struct edge_cfg { uint32_t id; uint32_t backend; uint64_t svc; };

struct SiteDef { const char *name; const char *location; uint32_t id; };
static const SiteDef kSites[] = {
    {"rep", "edge_target.exe!EdgeRepSite", 1},        {"stos", "edge_target.exe!EdgeStosSite", 2},
    {"ripload", "edge_target.exe!EdgeRipLoadSite", 3}, {"ripcmp", "edge_target.exe!EdgeRipCmpSite", 4},
    {"ripvec", "edge_target.exe!EdgeRipVecSite", 5},   {"ripstore", "edge_target.exe!EdgeRipStoreSite", 6},
    {"cpuid", "edge_target.exe!EdgeCpuidSite", 7},     {"rdtsc", "edge_target.exe!EdgeRdtscSite", 8},
    {"syscall", "edge_target.exe!EdgeSyscallSite", 9}, {"int2e", "edge_target.exe!EdgeInt2eSite", 10},
    {"pushf", "edge_target.exe!EdgePushfSite", 11},    {"popf", "edge_target.exe!EdgePopfSite", 12},
    {"retonly", "edge_target.exe!EdgeRetOnlySite", 13}, {"thunk", "edge_target.exe!EdgeThunkSite", 14},
    {"jump", "edge_target.exe!EdgeJumpSite", 15},      {"faultmid", "edge_target.exe!EdgeFaultMidSite", 16},
    {"x87", "edge_target.exe!EdgeX87Site", 17},        {"lock", "edge_target.exe!EdgeLockSite", 18},
    {"readd", "edge_target.exe!EdgeReaddA", 21},       {"args", "edge_target.exe!edge_args10", 23},
    {"mem", "edge_target.exe!edge_mem_site", 24},      {"fmt", "edge_target.exe!edge_fmt_site", 25},
    {"fmtptr", "edge_target.exe!edge_fmt_site", 26},   {"leaf", "edge_target.exe!edge_leaf", 27},
    {"cbfault", "edge_target.exe!EdgeReaddB", 28},
};

static uint32_t parse_backend(const char *b) {
    return !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "inline") ? PROBE_INLINE
         : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : 0;
}

static uint64_t yield_service() {
#if defined(_WIN64)
    const unsigned char *p = (const unsigned char *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtYieldExecution");
    if (p && p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) return *(const uint32_t *)(p + 4);
#endif
    return 0;
}

int main(int argc, char **argv) {
    uint32_t backend = 0, extra = 0, dual_a = 0, dual_b = 0;
    std::string sites;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) backend = parse_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--sites") && i + 1 < argc) sites = std::string(",") + argv[++i] + ",";
        else if (!std::strcmp(argv[i], "--fallback-hw")) extra |= PROBE_FALLBACK_HW;
        else if (!std::strcmp(argv[i], "--dual") && i + 1 < argc) {
            std::string d = argv[++i]; size_t comma = d.find(',');
            if (comma == std::string::npos) return 2;
            dual_a = parse_backend(d.substr(0, comma).c_str()); dual_b = parse_backend(d.substr(comma + 1).c_str());
        }
    }
    if (i + 1 >= argc || (!backend && !dual_a) || (dual_a && !dual_b)) {
        std::fprintf(stderr, "usage: edge_driver --backend b [--sites a,b] [--dual b1,b2] -- edge_target.exe\n");
        return 2;
    }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    probe_session *s = probe_session_create();
    bool ok = s != nullptr;
    static std::vector<edge_cfg> cfgs;
    const uint64_t svc = yield_service();
    if (ok && dual_a) {
        edge_cfg a{19, dual_a, 0}, b{20, dual_b, 0};
        ok = probe_add_symbol_cfg(s, "edge_target.exe!EdgeDualSite", edge_on_site, dual_a, &a, sizeof(a)) &&
             probe_add_symbol_cfg(s, "edge_target.exe!EdgeDualSite", edge_on_site, dual_b, &b, sizeof(b));
    }
    if (ok && backend) {
        for (const SiteDef &d : kSites) {
            if (!sites.empty() && sites.find(std::string(",") + d.name + ",") == std::string::npos) continue;
            // runtime one-shot adds: inline refuses PROBE_ONCE, so an inline run adds breakpoints
            uint32_t runtime = backend == PROBE_INLINE ? PROBE_BREAKPOINT : backend;
            edge_cfg k{d.id, runtime, svc};
            if (!probe_add_symbol_cfg(s, d.location, edge_on_site, backend | extra, &k, sizeof(k))) {
                std::fprintf(stderr, "edge_driver: add %s failed\n", d.name); ok = false; break;
            }
        }
    }
    ok = ok && probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    if (s) { probe_report(s, stdout); probe_close(s); }
    return ok ? 0 : 1;
}
