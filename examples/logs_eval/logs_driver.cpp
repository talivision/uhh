// logs_driver --a <backend> --b <backend> -- logs_target.exe [args]
// Probes logs_target.exe!LogSiteA and !LogSiteB (backend breakpoint|hw|inline|none) with
// logs_eval_cb, runs the target, and prints probe_report. regress `logs-*`.
#include "probe_api.h"
#include <cstdio>
#include <cstring>
#include <vector>
extern "C" void logs_eval_cb(probe_context *);
static uint32_t backend(const char *b) {
    return !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT
         : !std::strcmp(b, "inline") ? PROBE_INLINE : 0;
}
int main(int argc, char **argv) {
    uint32_t a = PROBE_INLINE, b = 0; int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--a") && i + 1 < argc) a = backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--b") && i + 1 < argc) b = backend(argv[++i]);
    }
    if (i + 1 >= argc) { std::fprintf(stderr, "usage: logs_driver --a bk --b bk -- target args\n"); return 2; }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    probe_session *s = probe_session_create();
    int ok = s != nullptr;
    if (ok && a) ok = probe_add_symbol(s, "logs_target.exe!LogSiteA", logs_eval_cb, a);
    if (ok && b) ok = probe_add_symbol(s, "logs_target.exe!LogSiteB", logs_eval_cb, b);
    ok = ok && probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    if (s) { probe_report(s, stdout); probe_close(s); }
    return ok ? 0 : 1;
}
