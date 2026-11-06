// co_driver --backend b [--inner-backend b2] --case name [--module m.exe] [--guard] [--attach pid [--detach-after ms | --detach-on-stdin]]
//           [-- co_target.exe name]
// --module: the probed functions' module (default co_target.exe; susp_target.exe for evsusp/cosusp
// and deepthrow/deepseh/deepjmp/catchhit/catchinside).
// --guard: also an inline probe on <module>!co_idle (never called), so a breakpoint/hw session has
// the agent and its controller-death guard: only sessions with an inline probe inject it
// (owner decision 2026-11-07).
// --detach-on-stdin: detach when a line arrives on stdin. co_driver_th is the same driver
// linked with the test-hook build of the library (probe_api_testhooks, regress cxlib-killarm).
// call_original / return_from edge-case hunt (regress `callorig-hunt`): probes co_target's
// functions for one case with one backend (nested: the inner probe may use another), runs
// it, prints the report. --attach: attach to a running co_target; --detach-after: close the
// session (detach) from another thread after ms while probe_run runs.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "probe_api.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#define CB(n) extern "C" void n(probe_context *);
CB(co_on_fact) CB(co_on_throw) CB(co_on_seh) CB(co_on_jump) CB(co_on_add) CB(co_on_outer) CB(co_on_slow)
CB(co_on_after) CB(co_on_inner) CB(co_on_nargs) CB(co_on_fast) CB(co_on_this) CB(co_on_args8) CB(co_on_mid)
CB(co_on_prologue) CB(co_on_ret) CB(co_on_vslow) CB(co_on_cbf) CB(co_on_late) CB(co_on_spin) CB(co_on_hold)
CB(co_on_idle) CB(co_on_lazy)
struct co_cfg { uint32_t backend; };
struct co_bigcfg { uint32_t backend, n; unsigned char pat[1000]; };   // see co_callbacks.cpp

static uint32_t parse_backend(const char *b) {
    return !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "inline") ? PROBE_INLINE
         : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : 0;
}

int main(int argc, char **argv) {
    uint32_t bk = 0, inner = 0, pid = 0, detach_ms = 0;
    bool detach_stdin = false, guard = false;
    std::string kase, module = "co_target.exe";
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) bk = parse_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--inner-backend") && i + 1 < argc) inner = parse_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--case") && i + 1 < argc) kase = argv[++i];
        else if (!std::strcmp(argv[i], "--module") && i + 1 < argc) module = argv[++i];
        else if (!std::strcmp(argv[i], "--attach") && i + 1 < argc) pid = (uint32_t)std::strtoul(argv[++i], nullptr, 10);
        else if (!std::strcmp(argv[i], "--detach-after") && i + 1 < argc) detach_ms = (uint32_t)std::strtoul(argv[++i], nullptr, 10);
        else if (!std::strcmp(argv[i], "--detach-on-stdin")) detach_stdin = true;
        else if (!std::strcmp(argv[i], "--guard")) guard = true;
    }
    if (!bk || kase.empty() || (!pid && i + 1 >= argc)) { std::fprintf(stderr, "usage: see co_driver.cpp\n"); return 2; }
    if (!inner) inner = bk;
    probe_session *s = probe_session_create();
    if (!s) return 1;
    co_cfg cfg{bk};
    auto add = [&](const char *fn, probe_callback cb, uint32_t flags) {
        std::string loc = module + "!" + fn;
        return probe_add_symbol_cfg(s, loc.c_str(), cb, flags, &cfg, sizeof(cfg)) != 0;
    };
    bool ok = true;
    const std::string &k = kase;
    if (k == "recurse") ok = add("co_fact", co_on_fact, bk);
    else if (k == "cppthrow") ok = add("co_throw", co_on_throw, bk) && add("co_after", co_on_after, bk);
    else if (k == "seh") ok = add("co_seh", co_on_seh, bk) && add("co_after", co_on_after, bk);
    else if (k == "longjmp") ok = add("co_jump", co_on_jump, bk) && add("co_after", co_on_after, bk);
    else if (k == "threads") ok = add("co_add", co_on_add, bk);
    else if (k == "mid") ok = add("CoMidPush+0x1", co_on_mid, bk);
    else if (k == "nargs") ok = add("co_add", co_on_nargs, bk);
    else if (k == "conv") {
        ok = add("co_fast", co_on_fast, bk) && add("co_args8", co_on_args8, bk);
#if !defined(_WIN64)
        ok = ok && add("CoThis", co_on_this, bk);
#endif
    }
    else if (k == "retaddr") ok = add("co_ret", co_on_ret, bk);
    else if (k == "prologue") ok = add("CoPrologue", co_on_prologue, bk);
    else if (k == "nested") ok = add("co_outer", co_on_outer, bk) && add("co_inner", co_on_inner, inner);
    else if (k == "lazy") ok = add("co_outer", co_on_lazy, bk);          // target case: nested
    else if (k == "slow") ok = add("co_slow", co_on_slow, bk);
    else if (k == "vslow") ok = add("co_vslow", co_on_vslow, bk) && add("co_after", co_on_after, bk);
    else if (k == "cbfault") ok = add("co_cbf", co_on_cbf, bk);
    else if (k == "spin") ok = add("co_add", co_on_spin, bk);
    else if (k == "rep") ok = add("CoRepSite", co_on_spin, bk);
    else if (k == "susp" || k == "evsusp") ok = add("co_add", co_on_spin, bk);
    else if (k == "cosusp" || k == "cosample") ok = add("co_hold", co_on_hold, bk);
    else if (k == "deepthrow" || k == "catchhit") ok = add("co_throw", co_on_throw, bk) && add("co_after", co_on_after, bk);
    else if (k == "deepseh") ok = add("co_seh", co_on_seh, bk) && add("co_after", co_on_after, bk);
    else if (k == "deepjmp") ok = add("co_jump", co_on_jump, bk) && add("co_after", co_on_after, bk);
    else if (k == "catchinside") ok = add("co_outer", co_on_outer, bk) && add("co_after", co_on_after, bk);
    else if (k == "late" || k == "cfgfree" || k == "many" || k == "manydead") {
        static co_bigcfg big{};                  // larger than PROBE_AGENT_CONFIG_CAP (256)
        big.backend = bk; big.n = (uint32_t)sizeof(big.pat);
        for (uint32_t j = 0; j < big.n; ++j) big.pat[j] = (unsigned char)((j * 7 + 3) & 0xFF);
        ok = probe_add_symbol_cfg(s, "co_target.exe!co_late", co_on_late, bk, &big, sizeof(big)) != 0;
        if (k == "many" || k == "manydead") ok = ok && add("co_add", co_on_spin, bk);
    }
    else { std::fprintf(stderr, "co_driver: unknown case %s\n", k.c_str()); return 2; }
    if (ok && guard) ok = add("co_idle", co_on_idle, PROBE_INLINE);
    if (!ok) { std::fprintf(stderr, "co_driver: add failed\n"); probe_close(s); return 1; }
    if (pid && (detach_ms || detach_stdin)) {
        // Detach from another thread while probe_run runs (and a call_original is in flight).
        // The debug object belongs to the attaching thread, so it attaches AND runs there.
        HANDLE attached = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        bool att_ok = false;
        std::thread runner([&] {
            att_ok = probe_attach(s, pid) != 0;
            SetEvent(attached);
            if (att_ok) probe_run(s);
        });
        WaitForSingleObject(attached, INFINITE);
        if (att_ok) {
            std::printf("{\"kind\":\"attached\",\"pid\":%u}\n", pid); std::fflush(stdout);
            if (detach_stdin) { char line[16]; if (!std::fgets(line, sizeof(line), stdin)) {} }
            else Sleep(detach_ms);
            std::fprintf(stderr, "co_driver: detaching\n");
        }
        probe_close(s);                         // waits for probe_run, then it has detached
        runner.join();
        std::printf("{\"kind\":\"detached\"}\n"); std::fflush(stdout);
        return att_ok ? 0 : 1;
    }
    if (pid) {
        if (!probe_attach(s, pid)) { probe_report(s, stdout); probe_close(s); return 1; }
        std::printf("{\"kind\":\"attached\",\"pid\":%u}\n", pid); std::fflush(stdout);
        int r = probe_run(s) && probe_wait_for_exit(s);
        probe_report(s, stdout); probe_close(s);
        return r ? 0 : 1;
    }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    int r = probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout); probe_close(s);
    return r ? 0 : 1;
}
