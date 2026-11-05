// lifecycle_driver -- attach gated_config's instrumentation to a RUNNING lifecycle_target,
// then let go of it in one of the ways a real tool does (regress `lifecycle-*`).
//
//   lifecycle_driver <pid> [--open b] [--close b] [--read b] [--flag b] [--slow b] [--work b]
//                    [--read-sleep-ms N] [--detach-after-ms N | --detach-on-stdin]
//
// b = breakpoint | hw | inline | none. Probes (callbacks shared with gated_config/hunt):
//   ntdll.dll!NtOpenProcess            track_open_process  (call_original + return_from)
//   ntdll.dll!NtClose                  forget_closed_handle
//   ntdll.dll!NtReadVirtualMemory      hunt_read_cb        (every read logged; optional sleep)
//   configparse.dll!ParseConfig+0x16   enable_reads        (mid-function: flag 0 -> 1)
//   lifecycle_target.exe!lc_slow       lc_slow_cb          (blocks inside call_original)
//   hunt_dll.dll!HuntWork              hunt_work_cb        (module that keeps unloading)
// Without a detach option the target runs until it exits or Ctrl+C/Ctrl+Break (which
// detaches). --detach-after-ms / --detach-on-stdin: attach + run on a worker thread and
// probe_close from the main thread after the delay / when a line arrives on stdin.
#include "lifecycle_callbacks.h"
#include "../hunt/hunt_callbacks.h"
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

static uint32_t parse_backend(const char *name) {
    return !std::strcmp(name, "none") ? 0u : backend_flag(name) ? backend_flag(name) : ~0u;
}

int main(int argc, char **argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: lifecycle_driver <pid> [options]\n"); return 2; }
    uint32_t pid = (uint32_t)std::strtoul(argv[1], nullptr, 0);
    uint32_t open_b = PROBE_INLINE, close_b = PROBE_INLINE, read_b = PROBE_INLINE, flag_b = PROBE_INLINE,
             slow_b = 0, work_b = 0;
    unsigned long detach_ms = 0; bool detach_stdin = false;
    hunt_config cfg{};
    cfg.read = read_log_config{READ_LOG_COOKIE, 1, 0, 0, {}};
    for (int i = 2; i < argc; ++i) {
        auto val = [&](uint32_t &b) { if (i + 1 < argc) b = parse_backend(argv[++i]); else b = ~0u; };
        if (!std::strcmp(argv[i], "--open")) val(open_b);
        else if (!std::strcmp(argv[i], "--close")) val(close_b);
        else if (!std::strcmp(argv[i], "--read")) val(read_b);
        else if (!std::strcmp(argv[i], "--flag")) val(flag_b);
        else if (!std::strcmp(argv[i], "--slow")) val(slow_b);
        else if (!std::strcmp(argv[i], "--work")) val(work_b);
        else if (!std::strcmp(argv[i], "--read-sleep-ms") && i + 1 < argc) cfg.slow_ms = (uint32_t)std::strtoul(argv[++i], nullptr, 0);
        else if (!std::strcmp(argv[i], "--detach-after-ms") && i + 1 < argc) detach_ms = std::strtoul(argv[++i], nullptr, 0);
        else if (!std::strcmp(argv[i], "--detach-on-stdin")) detach_stdin = true;
        else { std::fprintf(stderr, "lifecycle_driver: unknown option %s\n", argv[i]); return 2; }
    }
    for (uint32_t b : {open_b, close_b, read_b, flag_b, slow_b, work_b})
        if (b == ~0u) { std::fprintf(stderr, "lifecycle_driver: bad backend\n"); return 2; }
    if (!pid) return 2;
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = (!open_b || probe_add_symbol(s, "ntdll.dll!NtOpenProcess", track_open_process, open_b)) &&
             (!close_b || probe_add_symbol(s, "ntdll.dll!NtClose", forget_closed_handle, close_b)) &&
             (!read_b || probe_add_symbol_cfg(s, "ntdll.dll!NtReadVirtualMemory", hunt_read_cb, read_b, &cfg, sizeof(cfg))) &&
             (!flag_b || probe_add_symbol(s, "configparse.dll!ParseConfig+0x16", enable_reads, flag_b)) &&
             (!slow_b || probe_add_symbol(s, "lifecycle_target.exe!lc_slow", lc_slow_cb, slow_b)) &&
             (!work_b || probe_add_symbol(s, "hunt_dll.dll!HuntWork", hunt_work_cb, work_b));
    if (!ok) { probe_report(s, stdout); probe_close(s); return 1; }
    if (!detach_ms && !detach_stdin) {
        ok = probe_attach(s, pid);
        if (ok) { std::printf("{\"kind\":\"attached\",\"pid\":%lu}\n", (unsigned long)pid); std::fflush(stdout); }
        ok = ok && probe_run(s) && probe_wait_for_exit(s);
        probe_report(s, stdout);
        probe_close(s);
        return ok ? 0 : 1;
    }
    // The debug object belongs to the thread that attached: attach and run on a worker,
    // probe_close from here.
    HANDLE attached = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    bool attach_ok = false; int run_ok = 0;
    std::thread runner([&] {
        attach_ok = probe_attach(s, pid);
        SetEvent(attached);
        if (attach_ok) {
            std::printf("{\"kind\":\"attached\",\"pid\":%lu}\n", (unsigned long)pid); std::fflush(stdout);
            run_ok = probe_run(s);
        }
    });
    WaitForSingleObject(attached, INFINITE);
    CloseHandle(attached);
    if (!attach_ok) { runner.join(); probe_report(s, stdout); probe_close(s); return 1; }
    if (detach_stdin) { char line[64]; if (!std::fgets(line, sizeof(line), stdin)) {} }
    else Sleep(detach_ms);
    probe_close(s);                       // detach (or nothing, if the target already exited)
    runner.join();
    std::printf("{\"kind\":\"detached\",\"pid\":%lu,\"run_ok\":%d}\n", (unsigned long)pid, run_ok);
    return 0;
}
