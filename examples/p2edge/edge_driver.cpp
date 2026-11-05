// edge_driver --mode hold|late|hw --backend breakpoint|hw|inline -- edge_target.exe --<mode> [...]
//
//   hold: TlsSite + edge_early.dll!EarlySite (threads started by a TLS callback / DllMain
//         during the entry hold) on <backend>: hits must equal the target's call counts.
//   late: edge_late.dll!LateSite on <backend> (DLL loaded later by a worker thread); its
//         callback adds an INLINE probe on LateNext by address at the first hit.
//   hw:   four hw probes (HwSite exec ONCE + exec, g_w1 watch RW|ONCE + WRITE), a 5th
//         refused at setup; phase markers on <backend> (breakpoint|inline) try a 5th at
//         runtime and reuse the two freed slots.
#include "probe_api.h"
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" void edge_count(probe_context *);
extern "C" void edge_on_late(probe_context *);
extern "C" void edge_mark_a(probe_context *);
extern "C" void edge_mark_b(probe_context *);

int main(int argc, char **argv) {
    uint32_t backend = PROBE_BREAKPOINT; const char *mode = "hold"; int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            backend = !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "inline") ? PROBE_INLINE : PROBE_BREAKPOINT;
        } else if (!std::strcmp(argv[i], "--mode") && i + 1 < argc) mode = argv[++i];
    }
    if (i + 1 >= argc) { std::fprintf(stderr, "usage: edge_driver --mode m --backend b -- edge_target.exe ...\n"); return 2; }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = 1, setup_fifth = -1;
    if (!std::strcmp(mode, "hold")) {
        ok = probe_add_symbol(s, "edge_target.exe!TlsSite", edge_count, backend) &&
             probe_add_symbol(s, "edge_early.dll!EarlySite", edge_count, backend);
    } else if (!std::strcmp(mode, "late")) {
        ok = probe_add_symbol(s, "edge_late.dll!LateSite", edge_on_late, backend);
    } else if (!std::strcmp(mode, "hw")) {
        ok = probe_add_symbol(s, "edge_target.exe!HwSite", edge_count, PROBE_HW | PROBE_ONCE) &&
             probe_add_symbol(s, "edge_target.exe!HwSite", edge_count, PROBE_HW) &&
             probe_add_symbol(s, "edge_target.exe!g_w1", edge_count, PROBE_HW | PROBE_WATCH_RW | PROBE_ONCE) &&
             probe_add_symbol(s, "edge_target.exe!g_w1", edge_count, PROBE_HW | PROBE_WATCH_WRITE);
        setup_fifth = probe_add_symbol(s, "edge_target.exe!HwSite3", edge_count, PROBE_HW);
        ok = ok && probe_add_symbol(s, "edge_target.exe!MarkA", edge_mark_a, backend) &&
             probe_add_symbol(s, "edge_target.exe!MarkB", edge_mark_b, backend);
    } else {
        std::fprintf(stderr, "edge_driver: unknown mode %s\n", mode); probe_close(s); return 2;
    }
    if (!ok) std::fprintf(stderr, "edge_driver: setup failed\n");
    ok = ok && probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    std::printf("{\"kind\":\"edge_driver\",\"mode\":\"%s\",\"setup_fifth\":%d,\"run_ok\":%d}\n", mode, setup_fifth, ok);
    std::fflush(stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
