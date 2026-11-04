// memstress_driver --backend breakpoint|hw|inline [--throughput] --
//                  <memstress_target.exe> [target args]
#include "probe_api.h"
#include "memstress_callbacks.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

static void usage() {
    std::fprintf(stderr,
                 "usage: memstress_driver --backend breakpoint|hw|inline [--throughput] -- "
                 "<memstress_target.exe> [--threads T] [--iters N] [--no-wait]\n");
}

static bool parse_u32(const char *text, uint32_t &value) {
    if (text == nullptr || *text == '\0' || *text == '-') return false;
    char *end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::strtoull(text, &end, 10);
    if (errno == ERANGE || *end != '\0' || parsed == 0 || parsed > UINT32_MAX) return false;
    value = static_cast<uint32_t>(parsed);
    return true;
}

} // namespace

int main(int argc, char **argv) {
    uint32_t backend = 0;
    bool throughput = false;
    int separator = -1;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--") == 0) {
            separator = i;
            break;
        }
        if (std::strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
            const char *name = argv[++i];
            if (std::strcmp(name, "breakpoint") == 0) backend = PROBE_BREAKPOINT;
            else if (std::strcmp(name, "hw") == 0) backend = PROBE_HW;
            else if (std::strcmp(name, "inline") == 0) backend = PROBE_INLINE;
            else {
                usage();
                return 2;
            }
        } else if (std::strcmp(argv[i], "--throughput") == 0) {
            throughput = true;
        } else {
            usage();
            return 2;
        }
    }
    if (backend == 0 || separator < 0 || separator + 1 >= argc) {
        usage();
        return 2;
    }

    uint32_t threads = 8u;
    uint32_t iterations = 20000u;
    for (int i = separator + 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--no-wait") == 0) continue;
        if (std::strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], threads)) {
                usage();
                return 2;
            }
        } else if (std::strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], iterations)) {
                usage();
                return 2;
            }
        } else {
            usage();
            return 2;
        }
    }

    std::vector<char *> child(argv + separator + 1, argv + argc);
    child.push_back(nullptr);
    const memstress_config config{
        MEMSTRESS_CONFIG_VERSION,
        throughput ? MEMSTRESS_CONFIG_THROUGHPUT : 0u,
        throughput ? MEMSTRESS_THROUGHPUT_REPEATS : 0u,
        0u,
        static_cast<uint64_t>(threads) * static_cast<uint64_t>(iterations)};

    probe_session *session = probe_session_create();
    const int ok = session != nullptr &&
                   probe_add_symbol_cfg(session, "memstress_target.exe!ms_site", ms_on_site,
                                        backend, &config, sizeof(config)) != 0 &&
                   probe_launch(session, child.data()) != 0 &&
                   probe_run(session) != 0 &&
                   probe_wait_for_exit(session) != 0;
    if (session != nullptr) {
        probe_report(session, stdout);
        probe_close(session);
    }
    return ok ? 0 : 1;
}
