// ar_driver [--backend b|cycle] [--repeat N] --probe <symbol>=<callback> ... -- ar_target.exe <case>
// Inline-agent review (regress `agent-*`): adds the given probes, runs the target, prints the
// report. Callbacks are named (see ar_callbacks.cpp). --repeat N runs N sessions one after
// the other in this process (--backend cycle: breakpoint, hw, inline in turn), each followed
// by a {"kind":"iter"} row with the controller's handle count (regress `sessions-repeat`).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "probe_api.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <atomic>

#define CB(n) extern "C" void n(probe_context *);
CB(ar_on_wrapresolve) CB(ar_on_stackcopy) CB(ar_on_install_saved)
CB(ar_on_image) CB(ar_on_shared_write) CB(ar_on_shared_read) CB(ar_on_vector_call) CB(ar_on_config_late)
CB(ar_on_logged) CB(ar_on_empty) CB(ar_on_cache) CB(ar_on_guarantee) CB(ar_on_epoch) CB(ar_on_vector)
CB(ar_on_site) CB(ar_on_fault_ret) CB(ar_on_fault_noret) CB(ar_on_alloc) CB(ar_on_jump) CB(ar_on_after) CB(ar_on_prot) CB(ar_on_cf) CB(ar_on_cf_inner) CB(ar_on_dr_arm) CB(ar_on_d5_callee) CB(ar_on_d5_callee_fb) CB(ar_on_cfw_setup) CB(ar_on_cob) CB(ar_on_cfwl_setup) CB(ar_on_dr2_arm)
static const struct { const char *name; probe_callback fn; } k_callbacks[] = {
    {"ar_on_wrapresolve", ar_on_wrapresolve}, {"ar_on_stackcopy", ar_on_stackcopy},
    {"ar_on_install_saved", ar_on_install_saved},
    {"ar_on_image", ar_on_image},
    {"ar_on_vector_call", ar_on_vector_call},
    {"ar_on_empty", ar_on_empty}, {"ar_on_cache", ar_on_cache}, {"ar_on_guarantee", ar_on_guarantee},
    {"ar_on_logged", ar_on_logged}, {"ar_on_epoch", ar_on_epoch}, {"ar_on_vector", ar_on_vector},
    {"ar_on_site", ar_on_site}, {"ar_on_fault_ret", ar_on_fault_ret}, {"ar_on_fault_noret", ar_on_fault_noret},
    {"ar_on_alloc", ar_on_alloc}, {"ar_on_jump", ar_on_jump}, {"ar_on_after", ar_on_after}, {"ar_on_prot", ar_on_prot},
    {"ar_on_cf", ar_on_cf}, {"ar_on_cf_inner", ar_on_cf_inner}, {"ar_on_dr_arm", ar_on_dr_arm},
    {"ar_on_d5_callee", ar_on_d5_callee}, {"ar_on_d5_callee_fb", ar_on_d5_callee_fb},
    {"ar_on_cfw_setup", ar_on_cfw_setup}, {"ar_on_cob", ar_on_cob},
    {"ar_on_cfwl_setup", ar_on_cfwl_setup}, {"ar_on_dr2_arm", ar_on_dr2_arm},
};

static uint32_t backend_of(const char *b) {
    return !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : PROBE_INLINE;
}

static int run_once(uint32_t bk, const std::vector<std::pair<std::string, probe_callback>> &adds, std::vector<char *> &child) {
    probe_session *s = probe_session_create();
    if (!s) return 0;
    for (auto &a : adds)
        if (!probe_add_symbol(s, a.first.c_str(), a.second, bk)) {
            std::fprintf(stderr, "ar_driver: add %s failed\n", a.first.c_str());
            probe_report(s, stdout); probe_close(s); return 0;
        }
    int r = probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout); probe_close(s);
    return r;
}

// Attach/run on one thread, close from another, like lifecycle_driver.
static int review_attach(DWORD pid, LONG config, const char *mode = nullptr) {
    probe_session *s = probe_session_create();
    if (!s) return 2;
    if (mode && !strcmp(mode, "--review-retry")) {
        DWORD before = 0, after = 0;
        // Debug-event handles belong to the attaching thread. End each debugger
        // thread before measuring: its OS-owned debug handles are not process-handle
        // leaks in probe_attach. The session (and any leaked OpenProcess handles)
        // survives all attempts. Warm up the CRT/thread machinery before the baseline.
        using GetDebugObject = HANDLE (NTAPI *)();
        using SetDebugObject = void (NTAPI *)(HANDLE);
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        const auto get_debug = reinterpret_cast<GetDebugObject>(GetProcAddress(ntdll, "DbgUiGetThreadDebugObject"));
        const auto set_debug = reinterpret_cast<SetDebugObject>(GetProcAddress(ntdll, "DbgUiSetThreadDebugObject"));
        if (!get_debug || !set_debug) { probe_close(s); return 5; }
        bool unexpected = false;
        for (int i = 0; i <= 20; ++i) {
            std::thread attempt([&] {
                unexpected = probe_attach(s, pid) != 0;
                if (unexpected) probe_close(s);       // close on its owning debugger thread
                // DbgUiConnectToDbg stores this handle in the thread's TEB. It is
                // process-owned; explicitly release this throwaway debugger's object.
                if (HANDLE debug = get_debug()) { set_debug(nullptr); CloseHandle(debug); }
            });
            attempt.join();
            if (unexpected) return 3;
            if (!i) GetProcessHandleCount(GetCurrentProcess(), &before);
        }
        GetProcessHandleCount(GetCurrentProcess(), &after);
        probe_close(s);
        printf("{\"kind\":\"retry\",\"growth\":%ld}\n", (LONG)after - (LONG)before);
        return after <= before + 2 ? 0 : 4;
    }
    bool added = false;
    const bool hookfail = mode && !strcmp(mode, "--review-hookfail");
    if (hookfail) {
        added = probe_add_symbol(s, "ar_target.exe!ar_shared_write_site", ar_on_shared_write, PROBE_INLINE) != 0;
    } else if (mode && !strcmp(mode, "--review-stub")) {
        added = probe_add_symbol(s, "ar_target.exe!ar_shared_read_site", ar_on_vector_call, PROBE_BREAKPOINT) != 0;
    } else if (mode && !strcmp(mode, "--review-shared")) {
        added = probe_add_symbol(s, "ar_target.exe!ar_shared_write_site", ar_on_shared_write, PROBE_INLINE) &&
                probe_add_symbol(s, "ar_target.exe!ar_shared_read_site", ar_on_shared_read, config == 1 ? PROBE_BREAKPOINT : PROBE_HW);
    } else if (mode && !strcmp(mode, "--review-config")) {
        unsigned char cfg[4096] = {}; cfg[4095] = 77;
        added = probe_add_symbol_cfg(s, "ar_target.exe!ar_config_site", ar_on_config_late, PROBE_INLINE, cfg, sizeof(cfg)) != 0;
    } else added = probe_add_symbol_cfg(s, "ar_target.exe!ar_epoch_site", ar_on_epoch, PROBE_INLINE, &config, sizeof(config)) != 0;
    if (!added) { probe_close(s); return 2; }
    HANDLE attached = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    bool ok = false;
    std::atomic<int> phase{0};
    int run_ok = 0;
    std::thread runner([&] {
        ok = probe_attach(s, pid);
        SetEvent(attached);
        if (ok) {
            printf("{\"kind\":\"attached\"}\n"); fflush(stdout);
            run_ok = probe_run(s);
            int idle = 0;
            if (phase.compare_exchange_strong(idle, 1)) { probe_report(s, stdout); phase = 2; }
        }
    });
    WaitForSingleObject(attached, INFINITE); CloseHandle(attached);
    if (hookfail) {
        runner.join();
        if (!ok) probe_report(s, stdout);
        probe_close(s);
        return ok && run_ok ? 0 : 3;
    }
    if (ok) { char line[8]; if (!fgets(line, sizeof(line), stdin)) {} }
    int idle = 0;
    if (!phase.compare_exchange_strong(idle, 3)) while (phase.load() != 2) Sleep(1);
    if (!ok) probe_report(s, stdout);
    probe_close(s); runner.join();
    return ok ? 0 : 3;
}
int main(int argc, char **argv) {
    if (argc == 4 && !strncmp(argv[1], "--review-", 9))
        return review_attach((DWORD)strtoul(argv[2], nullptr, 10), (LONG)strtol(argv[3], nullptr, 10), argv[1]);
    const char *backend = "inline";
    int repeat = 1;
    std::vector<std::pair<std::string, probe_callback>> adds;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            backend = argv[++i];
        } else if (!std::strcmp(argv[i], "--repeat") && i + 1 < argc) {
            repeat = std::atoi(argv[++i]);
        } else if (!std::strcmp(argv[i], "--probe") && i + 1 < argc) {
            std::string spec = argv[++i];
            size_t eq = spec.rfind('=');
            probe_callback fn = nullptr;
            if (eq != std::string::npos)
                for (auto &cb : k_callbacks) if (spec.compare(eq + 1, std::string::npos, cb.name) == 0) fn = cb.fn;
            if (!fn) { std::fprintf(stderr, "ar_driver: bad --probe %s\n", spec.c_str()); return 2; }
            adds.emplace_back(spec.substr(0, eq), fn);
        }
    }
    if (adds.empty() || i + 1 >= argc || repeat < 1) { std::fprintf(stderr, "usage: see ar_driver.cpp\n"); return 2; }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    const bool cycle = !std::strcmp(backend, "cycle");
    static const char *const k_cycle[] = {"breakpoint", "hw", "inline"};
    int all = 1;
    for (int n = 0; n < repeat; ++n) {
        const char *b = cycle ? k_cycle[n % 3] : backend;
        const int ok = run_once(backend_of(b), adds, child);
        all &= ok;
        if (repeat > 1) {
            DWORD handles = 0; GetProcessHandleCount(GetCurrentProcess(), &handles);
            std::printf("{\"kind\":\"iter\",\"i\":%d,\"backend\":\"%s\",\"ok\":%d,\"handles\":%lu}\n", n, b, ok, handles);
            std::fflush(stdout);
        }
    }
    return all ? 0 : 1;
}
