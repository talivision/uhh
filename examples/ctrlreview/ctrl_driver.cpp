// ctrl_driver --scenario fault|inplace|absunload|symunload|owndr|headcorrupt|shape [--shape S] --backend b
//             -- <ctrl_target.exe> <scenario> [opts]
// Instruments ctrl_target for one controller-review finding (see ctrl_target.cpp) with
// one backend, runs it and prints the target's result, the probe rows and the logs.
#include "probe_api.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
void ctrl_on_load(probe_context *);
void ctrl_on_loop(probe_context *);
void ctrl_on_announce(probe_context *);
void ctrl_on_leaf(probe_context *);
void ctrl_on_tick(probe_context *);
void ctrl_on_shape(probe_context *);
}
struct ctrl_cfg { uint32_t backend; uint32_t pad; };

static uint32_t parse_backend(const char *b) {
    return !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "inline") ? PROBE_INLINE
         : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : 0;
}

int main(int argc, char **argv) {
    uint32_t backend = 0;
    std::string sc, shape;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) backend = parse_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--scenario") && i + 1 < argc) sc = argv[++i];
        else if (!std::strcmp(argv[i], "--shape") && i + 1 < argc) shape = argv[++i];
    }
    if (i + 1 >= argc || !backend || sc.empty()) {
        std::fprintf(stderr, "usage: ctrl_driver --scenario s --backend b -- ctrl_target.exe s [opts]\n");
        return 2;
    }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    probe_session *s = probe_session_create();
    ctrl_cfg k{backend, 0};
    bool ok = s != nullptr;
    if (ok) {
        if (sc == "fault")
            ok = probe_add_symbol(s, "ctrl_target.exe!CtrlLoadInsn", ctrl_on_load, backend);
        else if (sc == "inplace")
            ok = probe_add_symbol(s, "ctrl_target.exe!CtrlLoopInsn", ctrl_on_loop, backend);
        else if (sc == "absunload")
            ok = probe_add_symbol_cfg(s, "ctrl_target.exe!CtrlAnnounce", ctrl_on_announce, backend, &k, sizeof(k));
        else if (sc == "symunload")
            ok = probe_add_symbol(s, "ctrl_dll.dll!CtrlDllLeaf", ctrl_on_leaf, backend);
        else if (sc == "owndr" || sc == "headcorrupt")
            ok = probe_add_symbol(s, "ctrl_target.exe!CtrlTick", ctrl_on_tick, backend);
        else if (sc == "shape")
            ok = probe_add_symbol(s, ("ctrl_target.exe!Shape_" + shape + "_P_Insn").c_str(), ctrl_on_shape, backend);
        else { std::fprintf(stderr, "ctrl_driver: unknown scenario %s\n", sc.c_str()); ok = false; }
    }
    ok = ok && probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    if (s) { probe_report(s, stdout); probe_close(s); }
    return ok ? 0 : 1;
}
