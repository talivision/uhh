// hitcost_driver --backend inline|breakpoint|hw [--method empty|get_reg|get_func_arg|get_mem|
//                set_mem|send_log|send_log_stack|call_func|counter_plain|counter_shared] -- hitcost_target.exe [args]
// hitcost_driver_shared: the same, with the callbacks module opted in to UHH_SHARED.
#include "probe_api.h"
#include <cstdio>
#include <cstring>
#include <vector>
extern "C" void hitcost_empty(probe_context *);
struct hitcost_config { uint32_t method; uint32_t pad; };
int main(int argc, char **argv) {
    static const char *const methods[] = {"empty", "get_reg", "get_func_arg", "get_mem", "set_mem",
                                          "send_log", "send_log_stack", "call_func", "counter_plain", "counter_shared"};
    uint32_t backend = PROBE_INLINE; hitcost_config cfg{0, 0}; int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            backend = !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : PROBE_INLINE;
        } else if (!std::strcmp(argv[i], "--method") && i + 1 < argc) {
            const char *m = argv[++i];
            for (uint32_t k = 0; k < sizeof(methods) / sizeof(*methods); ++k) if (!std::strcmp(m, methods[k])) cfg.method = k;
        }
    }
    if (i + 1 >= argc) return 2;
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    probe_session *s = probe_session_create();
    int ok = s && probe_add_symbol_cfg(s, "hitcost_target.exe!hit_site", hitcost_empty, backend, &cfg, sizeof(cfg)) &&
             probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    if (s) { probe_report(s, stdout); probe_close(s); }
    return ok ? 0 : 1;
}
