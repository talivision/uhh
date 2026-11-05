// cet_sde_driver --backend breakpoint|hw|inline [--sp-only | --probe LOC[=log|orig|replace] ...] --attach <pid>
// The conformance probes (examples/conformance: conf_site's every-context-method callback and
// set_reg(SP) at SpSite+3), ATTACHED to a conformance_target that is already running -- for
// targets UHH cannot launch itself, such as one hosted by Intel SDE's CET emulation
// (`sde -tgl -cet -- conformance_target.exe`, regress `cet-sde-*`). --sp-only adds just the
// set_reg(SP) probe (conf_site's callback also adds runtime breakpoint/hw probes). --probe LOC
// (repeatable) instead probes any location of any target (examples/cet/cet_smash) with a callback
// the agent already exports: log = log only ("ok watch-hit"; e.g. on a CALL instruction, which
// the inline hook then has to relocate), orig = call_original(1 arg) + return_from of its result
// ("co fact" / "co fact-done"), replace = return_from(77) without running the body ("co prologue").
#include "probe_api.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" void conf_on_site(probe_context *);
extern "C" void conf_move_sp(probe_context *);
extern "C" void conf_on_watch(probe_context *);    // log only
extern "C" void co_on_fact(probe_context *);       // call_original + return_from (examples/hunt_callorig)
extern "C" void co_on_prologue(probe_context *);   // return_from(77)
struct conf_config { uint64_t cookie; };

int main(int argc, char **argv) {
    uint32_t backend = 0, pid = 0;
    bool sp_only = false;
    std::vector<const char *> sites;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--sp-only")) sp_only = true;
        else if (!std::strcmp(argv[i], "--probe") && i + 1 < argc) sites.push_back(argv[++i]);
        else if (!std::strcmp(argv[i], "--attach") && i + 1 < argc) pid = (uint32_t)std::strtoul(argv[++i], nullptr, 10);
        else if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            backend = !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "inline") ? PROBE_INLINE
                    : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : 0;
        }
    }
    if (!backend || !pid) { std::fprintf(stderr, "usage: cet_sde_driver --backend b [--sp-only | --probe LOC[=log|orig|replace] ...] --attach pid\n"); return 2; }
    conf_config cfg{0xC0F1C0F1C0F1C0F1ull};
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = 1;
    for (const char *spec : sites) {
        std::string loc = spec, cb = "log";
        if (const size_t eq = loc.find('='); eq != std::string::npos) { cb = loc.substr(eq + 1); loc.resize(eq); }
        probe_callback fn = cb == "orig" ? co_on_fact : cb == "replace" ? co_on_prologue : cb == "log" ? conf_on_watch : nullptr;
        ok = ok && fn && probe_add_symbol(s, loc.c_str(), fn, backend);
    }
    if (sites.empty())
        ok = (sp_only || probe_add_symbol_cfg(s, "conformance_target.exe!conf_site", conf_on_site, backend, &cfg, sizeof(cfg))) &&
             probe_add_symbol(s, "conformance_target.exe!SpSite+0x3", conf_move_sp, backend);
    ok = ok && probe_attach(s, pid);
    if (ok) {
        std::printf("{\"kind\":\"attached\",\"pid\":%u}\n", pid);
        std::fflush(stdout);
        ok = probe_run(s) && probe_wait_for_exit(s);
    }
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
