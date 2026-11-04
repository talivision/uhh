// uhh_attach -- attach to a RUNNING probe_app, turn its disabled feature on, and log
// only the reads it makes of one process (P) inside one address range.
//
//   uhh_attach <target_pid> --pid P --range BASE:SIZE [--backend breakpoint|hw|inline]
//
// Three probes, the callbacks shared with gated_config (examples/gated_config):
//   configparse.dll!ParseConfig+0x16   breakpoint   enable_reads: parsed flag 0 -> 1
//   ntdll.dll!NtOpenProcess            <backend>    track_open_process: handle -> pid map
//   ntdll.dll!NtReadVirtualMemory      <backend>    log_read: only pid P, only [BASE, BASE+SIZE)
// The open and read probes share one backend because the map lives with the callbacks
// (in this process for breakpoint/hw, inside the target for inline).
#include "callbacks.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int usage() {
    std::fprintf(stderr, "usage: uhh_attach <target_pid> --pid P --range BASE:SIZE "
                         "[--backend breakpoint|hw|inline]\n");
    return 2;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    uint32_t target = (uint32_t)std::strtoul(argv[1], nullptr, 0), backend = PROBE_BREAKPOINT;
    read_log_config cfg{READ_LOG_COOKIE, 1, 1, 0, 0, 0};
    for (int i = 2; i + 1 < argc; i += 2) {
        if (!std::strcmp(argv[i], "--pid")) cfg.pid = std::strtoull(argv[i + 1], nullptr, 0);
        else if (!std::strcmp(argv[i], "--backend")) backend = backend_flag(argv[i + 1]);
        else if (!std::strcmp(argv[i], "--range")) {
            char *colon = nullptr;
            cfg.base = std::strtoull(argv[i + 1], &colon, 0);
            if (*colon == ':') cfg.size = std::strtoull(colon + 1, nullptr, 0);
        } else return usage();
    }
    if (!target || !cfg.pid || !cfg.size || !backend || argc % 2) return usage();

    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol(s, "configparse.dll!ParseConfig+0x16", enable_reads, PROBE_BREAKPOINT) &&
             probe_add_symbol(s, "ntdll.dll!NtOpenProcess", track_open_process, backend) &&
             probe_add_symbol_cfg(s, "ntdll.dll!NtReadVirtualMemory", log_read, backend, &cfg, sizeof(cfg)) &&
             probe_attach(s, target);
    if (ok) {
        std::printf("{\"kind\":\"attached\",\"pid\":%lu}\n", (unsigned long)target);
        std::fflush(stdout);
        ok = probe_run(s) && probe_wait_for_exit(s);   // returns when the target exits
    }
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
