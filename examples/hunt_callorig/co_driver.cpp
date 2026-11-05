// co_driver --backend b [--inner-backend b2] --case name [--attach pid [--detach-after ms]]
//           [-- co_target.exe name]
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
CB(co_on_prologue) CB(co_on_ret) CB(co_on_vslow)
struct co_cfg { uint32_t backend; };

static uint32_t parse_backend(const char *b) {
    return !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "inline") ? PROBE_INLINE
         : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : 0;
}

int main(int argc, char **argv) {
    uint32_t bk = 0, inner = 0, pid = 0, detach_ms = 0;
    std::string kase;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) bk = parse_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--inner-backend") && i + 1 < argc) inner = parse_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--case") && i + 1 < argc) kase = argv[++i];
        else if (!std::strcmp(argv[i], "--attach") && i + 1 < argc) pid = (uint32_t)std::strtoul(argv[++i], nullptr, 10);
        else if (!std::strcmp(argv[i], "--detach-after") && i + 1 < argc) detach_ms = (uint32_t)std::strtoul(argv[++i], nullptr, 10);
    }
    if (!bk || kase.empty() || (!pid && i + 1 >= argc)) { std::fprintf(stderr, "usage: see co_driver.cpp\n"); return 2; }
    if (!inner) inner = bk;
    probe_session *s = probe_session_create();
    if (!s) return 1;
    co_cfg cfg{bk};
    auto add = [&](const char *fn, probe_callback cb, uint32_t flags) {
        std::string loc = std::string("co_target.exe!") + fn;
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
    else if (k == "slow") ok = add("co_slow", co_on_slow, bk);
    else if (k == "vslow") ok = add("co_vslow", co_on_vslow, bk) && add("co_after", co_on_after, bk);
    else { std::fprintf(stderr, "co_driver: unknown case %s\n", k.c_str()); return 2; }
    if (!ok) { std::fprintf(stderr, "co_driver: add failed\n"); probe_close(s); return 1; }
    if (pid && detach_ms) {
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
            Sleep(detach_ms);
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
