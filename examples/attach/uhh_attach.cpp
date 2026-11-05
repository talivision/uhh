// uhh_attach -- attach to a RUNNING probe_app, turn its disabled feature on, and log
// only the reads it makes of one process (P) inside one address range.
//
//   uhh_attach <target_pid> --pid P --range BASE:SIZE [--backend breakpoint|hw|inline] [--flag-backend b]
//
// Three probes, the callbacks shared with gated_config (examples/gated_config):
//   configparse.dll!ParseConfig+0x16   <flag-backend>  enable_reads: parsed flag 0 -> 1
//   ntdll.dll!NtOpenProcess            <backend>       track_open_process: handle -> pid -> name map (call_original)
//   ntdll.dll!NtReadVirtualMemory      <backend>       log_read: only pid P, only [BASE, BASE+SIZE)
// The handle -> pid map is UHH_SHARED (see examples/gated_config/callbacks.cpp), so it is
// one map whichever process each callback runs in.
#include "callbacks.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int usage() {
    std::fprintf(stderr, "usage: uhh_attach <target_pid> --pid P --range BASE:SIZE "
                         "[--backend breakpoint|hw|inline] [--flag-backend b]\n");
    return 2;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    uint32_t target = (uint32_t)std::strtoul(argv[1], nullptr, 0), backend = PROBE_BREAKPOINT, flag_backend = PROBE_BREAKPOINT;
    read_log_config cfg{};
    cfg.cookie = READ_LOG_COOKIE; cfg.log = 1;
    for (int i = 2; i + 1 < argc; i += 2) {
        if (!std::strcmp(argv[i], "--pid")) cfg.pid = std::strtoull(argv[i + 1], nullptr, 0);
        else if (!std::strcmp(argv[i], "--backend")) backend = backend_flag(argv[i + 1]);
        else if (!std::strcmp(argv[i], "--flag-backend")) flag_backend = backend_flag(argv[i + 1]);
        else if (!std::strcmp(argv[i], "--range")) { if (!add_read_range(&cfg, argv[i + 1])) return usage(); }
        else return usage();
    }
    if (!target || !cfg.pid || !cfg.nranges || !backend || !flag_backend || argc % 2) return usage();

    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol(s, "configparse.dll!ParseConfig+0x16", enable_reads, flag_backend) &&
             probe_add_symbol(s, "ntdll.dll!NtOpenProcess", track_open_process, backend) &&
             probe_add_symbol(s, "ntdll.dll!NtClose", forget_closed_handle, backend) &&
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
