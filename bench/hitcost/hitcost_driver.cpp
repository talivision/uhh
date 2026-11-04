// hitcost_driver --backend inline|breakpoint|hw -- hitcost_target.exe [--calls N] [--avx]
#include "probe_api.h"
#include <cstdio>
#include <cstring>
#include <vector>
extern "C" void hitcost_empty(probe_context *);
int main(int argc, char **argv) {
    uint32_t backend = PROBE_INLINE; int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i)
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            backend = !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : PROBE_INLINE;
        }
    if (i + 1 >= argc) return 2;
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    probe_session *s = probe_session_create();
    int ok = s && probe_add_symbol(s, "hitcost_target.exe!hit_site", hitcost_empty, backend) &&
             probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    if (s) { probe_report(s, stdout); probe_close(s); }
    return ok ? 0 : 1;
}
