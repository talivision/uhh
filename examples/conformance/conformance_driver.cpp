// conformance_driver --backend breakpoint|hw|inline [--callorig | --matrix A|B|C] -- <conformance_target.exe> [...]
#include "probe_api.h"
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" void conf_on_site(probe_context *);
extern "C" void conf_move_sp(probe_context *);
extern "C" void co_on_args6(probe_context *);
extern "C" void co_on_std2(probe_context *);
extern "C" void co_on_cdecl2(probe_context *);
struct conf_config { uint64_t cookie; };
extern "C" void pm_on_entry(probe_context *);
extern "C" void pm_on_regs(probe_context *);
extern "C" void pm_on_other(probe_context *);
extern "C" void pm_on_fault(probe_context *);
extern "C" void pm_on_throw(probe_context *);
extern "C" void pm_on_conc(probe_context *);
extern "C" void pm_on_report(probe_context *);
extern "C" void pm_on_bigcfg(probe_context *);

// --matrix A|B|C: the portability matrix (matrix_callbacks.cpp). Phases keep each run
// within the 4 hardware debug registers. Every add's result is printed (an add one backend
// refuses is itself a portability finding).
static int run_matrix(probe_session *s, uint32_t backend, char phase, char **child) {
    struct { uint64_t cookie; } entry_cfg{0xC0F1C0F1C0F1C0F1ull}, report_cfg{0x4E9041ull};
    struct { uint64_t cookie; unsigned char body[292]; uint64_t tail; } big{};
    big.cookie = 0xB16C0F16B16C0F16ull; std::memset(big.body, 0x11, sizeof(big.body)); big.tail = 0x7A117A117A117A11ull;
    const uint32_t other = backend == PROBE_INLINE ? PROBE_BREAKPOINT : PROBE_INLINE;
    std::printf("{\"kind\":\"matrix_adds\",\"phase\":\"%c\"", phase);
    auto add = [&](const char *key, int ok) { std::printf(",\"%s\":%d", key, ok); };
    if (phase == 'A') {
        add("entry", probe_add_symbol_cfg(s, "conformance_target.exe!pm_entry", pm_on_entry, backend, &entry_cfg, sizeof(entry_cfg)));
        add("regs", probe_add_symbol(s, "conformance_target.exe!PmRegHit", pm_on_regs, backend));
        add("other", probe_add_symbol(s, "conformance_target.exe!PmOther", pm_on_other, other));
    } else if (phase == 'B') {
        add("fault", probe_add_symbol(s, "conformance_target.exe!pm_fault_site", pm_on_fault, backend));
        add("conc", probe_add_symbol(s, "conformance_target.exe!pm_conc", pm_on_conc, backend));
        add("report", probe_add_symbol_cfg(s, "conformance_target.exe!pm_report", pm_on_report, backend, &report_cfg, sizeof(report_cfg)));
        add("bigcfg", probe_add_symbol_cfg(s, "conformance_target.exe!pm_bigcfg", pm_on_bigcfg, backend, &big, sizeof(big)));
    } else {
        add("throw", probe_add_symbol(s, "conformance_target.exe!pm_throw_site", pm_on_throw, backend));
    }
    std::printf("}\n"); std::fflush(stdout);
    int ok = probe_launch(s, child) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout); probe_close(s);
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    uint32_t backend = PROBE_BREAKPOINT; int i = 1; bool callorig = false; char phase = 0;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i)
        if (!std::strcmp(argv[i], "--callorig")) callorig = true;
        else if (!std::strcmp(argv[i], "--matrix") && i + 1 < argc) phase = argv[++i][0];
        else if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            backend = !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "inline") ? PROBE_INLINE : PROBE_BREAKPOINT;
        }
    if (i + 1 >= argc) { std::fprintf(stderr, "usage: conformance_driver --backend b -- target.exe\n"); return 2; }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    conf_config cfg{0xC0F1C0F1C0F1C0F1ull};
    probe_session *s = probe_session_create();
    if (phase && s) return run_matrix(s, backend, phase, child.data());
    if (callorig) {   // call_original / return_from: target run as `conformance_target.exe --callorig`
        int ok = s && probe_add_symbol(s, "conformance_target.exe!co_args6", co_on_args6, backend) &&
                 probe_add_symbol(s, "conformance_target.exe!co_std2", co_on_std2, backend) &&
                 probe_add_symbol(s, "conformance_target.exe!co_cdecl2", co_on_cdecl2, backend) &&
                 probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
        if (s) { probe_report(s, stdout); probe_close(s); }
        return ok ? 0 : 1;
    }
    int ok = s && probe_add_symbol_cfg(s, "conformance_target.exe!conf_site", conf_on_site, backend, &cfg, sizeof(cfg)) &&
             probe_add_symbol(s, "conformance_target.exe!SpSite+0x3", conf_move_sp, backend) &&
             probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    if (s) { probe_report(s, stdout); probe_close(s); }
    return ok ? 0 : 1;
}
