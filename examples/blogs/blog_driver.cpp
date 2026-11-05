// blog_driver -- instrument blog_target (or any program doing the same) the way a
// well-known instrumentation write-up does, on any backend:
//
//   blog_driver --scenario crypto|registry|net|spawn|com|game --backend breakpoint|hw|inline
//               [--no-log] [--naive] -- <program> [args...]
//
// --naive (crypto): also capture BCryptGenRandom's nested self-call, as a first-cut
// monitor would -- on hw that asks for a 5th debug register from inside a callback.
//
// Output: the target's own stdout, then probe_report (JSON lines). The callbacks
// (blog_callbacks.cpp) are the same source under every backend.
#include "blog_callbacks.h"

#include <cstdio>
#include <cstring>
#include <vector>

namespace {

struct site { const char *symbol; probe_callback cb; bool hw_ok; };

// hw has 4 debug registers in total; a scenario that needs more drops the entries marked
// hw_ok=false on hw (and says so) -- the documented hardware limit, not a silent loss.
const std::vector<site> *sites_for(const char *scenario) {
    static const std::vector<site> crypto = {
        {"bcrypt.dll!BCryptEncrypt", blog_on_bcrypt_encrypt, true},
        {"bcrypt.dll!BCryptGenRandom", blog_on_genrandom, true},       // + 1 dynamic return probe
        {"advapi32.dll!CryptEncrypt", blog_on_capi_encrypt, true},     // forwarded -> cryptsp.dll
    };
    static const std::vector<site> registry = {
        {"ntdll.dll!NtCreateKey", blog_on_ntcreatekey, true},
        {"ntdll.dll!NtSetValueKey", blog_on_ntsetvaluekey, true},
    };
    static const std::vector<site> net = {
        {"ws2_32.dll!connect", blog_on_connect, true},
        {"ws2_32.dll!WSAConnect", blog_on_connect, true},
        {"ws2_32.dll!send", blog_on_send, true},
        {"ws2_32.dll!recv", blog_on_recv, true},
        {"dnsapi.dll!DnsQuery_W", blog_on_dnsquery, false},           // 5th: no debug register left
    };
    static const std::vector<site> spawn = {
        {"kernelbase.dll!CreateProcessInternalW", blog_on_create_process_internal, true},
        {"ntdll.dll!NtCreateUserProcess", blog_on_nt_create_user_process, true},
    };
    static const std::vector<site> com = {
        {"ole32.dll!CoCreateInstance", blog_on_cocreateinstance, true}, // forwarded -> combase.dll
    };
    static const std::vector<site> game = {
        {"blog_target.exe!blog_frame", blog_on_frame, true},
    };
    if (!std::strcmp(scenario, "crypto")) return &crypto;
    if (!std::strcmp(scenario, "registry")) return &registry;
    if (!std::strcmp(scenario, "net")) return &net;
    if (!std::strcmp(scenario, "spawn")) return &spawn;
    if (!std::strcmp(scenario, "com")) return &com;
    if (!std::strcmp(scenario, "game")) return &game;
    return nullptr;
}

int usage() {
    std::fprintf(stderr, "usage: blog_driver --scenario crypto|registry|net|spawn|com|game "
                         "--backend breakpoint|hw|inline [--no-log] [--naive] -- <program> [args...]\n");
    return 2;
}

}  // namespace

int main(int argc, char **argv) {
    const char *scenario = nullptr;
    uint32_t backend = 0;
    bool log = true, naive = false;
    int i = 1;
    for (; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--")) { ++i; break; }
        if (!std::strcmp(argv[i], "--scenario") && i + 1 < argc) { scenario = argv[++i]; continue; }
        if (!std::strcmp(argv[i], "--no-log")) { log = false; continue; }
        if (!std::strcmp(argv[i], "--naive")) { naive = true; continue; }
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            backend = !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : !std::strcmp(b, "hw") ? PROBE_HW
                    : !std::strcmp(b, "inline") ? PROBE_INLINE : 0u;
            continue;
        }
        return usage();
    }
    const std::vector<site> *sites = scenario ? sites_for(scenario) : nullptr;
    if (!sites || !backend || i >= argc) return usage();

    const blog_config config{BLOG_COOKIE, backend, log ? 1u : 0u, naive ? BLOG_NAIVE : 0u};
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = 1;
    for (const site &p : *sites) {
        if (backend == PROBE_HW && !p.hw_ok) {
            std::fprintf(stderr, "blog_driver: %s skipped on hw (4 debug registers)\n", p.symbol);
            continue;
        }
        ok = ok && probe_add_symbol_cfg(s, p.symbol, p.cb, backend, &config, sizeof config);
    }
    std::vector<char *> child(argv + i, argv + argc);
    child.push_back(nullptr);
    ok = ok && probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
