// sidefx_driver --backend breakpoint|hw|inline -- <sidefx_target.exe> [target args]
#include "probe_api.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" void sidefx_on_site(probe_context *);

namespace {

void usage() {
    std::fputs("usage: sidefx_driver --backend breakpoint|hw|inline -- "
               "<sidefx_target.exe> [--iters N] [--threads T] [--no-wait]\n",
               stderr);
}

} // namespace

int main(int argc, char **argv) {
    std::uint32_t backend = 0;
    int separator = -1;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--") == 0) {
            separator = i;
            break;
        }
        if (std::strcmp(argv[i], "--backend") != 0 || i + 1 >= argc) {
            usage();
            return 2;
        }
        const char *name = argv[++i];
        if (std::strcmp(name, "breakpoint") == 0) backend = PROBE_BREAKPOINT;
        else if (std::strcmp(name, "hw") == 0) backend = PROBE_HW;
        else if (std::strcmp(name, "inline") == 0) backend = PROBE_INLINE;
        else {
            usage();
            return 2;
        }
    }
    if (backend == 0 || separator < 0 || separator + 1 >= argc) {
        usage();
        return 2;
    }

    std::vector<char *> child(argv + separator + 1, argv + argc);
    child.push_back(nullptr);

    probe_session *session = probe_session_create();
    const int ok = session != nullptr &&
                   probe_add_symbol(session, "sidefx_target.exe!SideFxSite",
                                    sidefx_on_site, backend) != 0 &&
                   probe_launch(session, child.data()) != 0 &&
                   probe_run(session) != 0 &&
                   probe_wait_for_exit(session) != 0;
    if (session != nullptr) {
        probe_report(session, stdout);
        probe_close(session);
    }
    return ok ? 0 : 1;
}
