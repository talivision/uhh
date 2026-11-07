// uhh_count -- the UHH side of the "count" workload in bench/frida (vs_frida.py): one probe,
// one counting callback, no log. The SAME callback source runs on every backend.
//
//   uhh_count [--backend inline|hw|breakpoint|watch] [--location module!export|module+0xRVA] -- <target.exe> [args]
//
// watch = a hardware data watchpoint on writes (PROBE_HW | PROBE_WATCH_WRITE) at the location.
//
// The callback does exactly what the Frida count agents do (count_js.js / count_cmodule.js /
// count_hw.js): read argument 0 (the handle) and argument 3 (the size) and bump a counter.
// The callback (uhh_count_callbacks.cpp) is also in probe_api_agent (inline callbacks run from
// the agent DLL). The count is the probe's "hits" in the report (one callback run per hit).
#include "probe_api.h"
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" void uhh_count_call(probe_context *);

int main(int argc, char **argv) {
    uint32_t backend = PROBE_INLINE;
    const char *location = "ntdll.dll!NtReadVirtualMemory";
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            backend = !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT
                    : !std::strcmp(b, "watch") ? (PROBE_HW | PROBE_WATCH_WRITE) : PROBE_INLINE;
        } else if (!std::strcmp(argv[i], "--location") && i + 1 < argc) {
            location = argv[++i];
        } else {
            std::fprintf(stderr, "usage: uhh_count [--backend inline|hw|breakpoint|watch] [--location m!f] -- target [args]\n");
            return 2;
        }
    }
    if (i + 1 >= argc) return 2;
    std::vector<char *> child(argv + i + 1, argv + argc);
    child.push_back(nullptr);
    probe_session *s = probe_session_create();
    int ok = s && probe_add_symbol(s, location, uhh_count_call, backend) && probe_launch(s, child.data()) &&
             probe_run(s) && probe_wait_for_exit(s);
    if (s) { probe_report(s, stdout); probe_close(s); }
    return ok ? 0 : 1;
}
