// detours_traceapi -- Microsoft Detours' "traceapi" sample on UHH: trace the classic file,
// registry, process and module APIs of a program, arguments decoded.
//
//   detours_traceapi [--backend breakpoint|hw|inline|mix] [--only Name,Name] [--stack]
//                    -- <program> [args...]                  launch under instrumentation
//                    --attach <pid> [--detach-after-ms N]    attach to a running process
//                    --attach-new <image> [--timeout ms]     attach to the next new instance
//
// The withdll/setdll equivalents (launch vs attach) are the same driver: see
// examples/famous/detours_withdll. --backend mix spreads the probes over all three
// backends in one session (breakpoint, hw, inline, breakpoint, ...). hw has 4 debug
// registers: with --backend hw, pick at most 4 APIs with --only.
#include "traceapi_callbacks.h"
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

static bool selected(const char *only, const char *name) {
    if (!only) return true;
    std::string list = std::string(",") + only + ",";
    return list.find(std::string(",") + name + ",") != std::string::npos;
}

int main(int argc, char **argv) {
    const char *backend = "breakpoint", *only = nullptr, *attach_new = nullptr;
    unsigned long attach_pid = 0, detach_ms = 0, attach_timeout = 0; bool stack = false;
    int i = 1;
    for (; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--")) { ++i; break; }
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) { backend = argv[++i]; continue; }
        if (!std::strcmp(argv[i], "--only") && i + 1 < argc) { only = argv[++i]; continue; }
        if (!std::strcmp(argv[i], "--stack")) { stack = true; continue; }
        if (!std::strcmp(argv[i], "--attach") && i + 1 < argc) { attach_pid = std::strtoul(argv[++i], nullptr, 0); continue; }
        if (!std::strcmp(argv[i], "--detach-after-ms") && i + 1 < argc) { detach_ms = std::strtoul(argv[++i], nullptr, 0); continue; }
        if (!std::strcmp(argv[i], "--attach-new") && i + 1 < argc) { attach_new = argv[++i]; continue; }
        if (!std::strcmp(argv[i], "--timeout") && i + 1 < argc) { attach_timeout = std::strtoul(argv[++i], nullptr, 0); continue; }
        std::fprintf(stderr, "detours_traceapi: unknown option %s\n", argv[i]); return 2;
    }
    const bool mix = !std::strcmp(backend, "mix");
    const uint32_t one = !std::strcmp(backend, "inline") ? PROBE_INLINE : !std::strcmp(backend, "hw") ? PROBE_HW
                       : !std::strcmp(backend, "breakpoint") ? PROBE_BREAKPOINT : 0u;
    if ((!one && !mix) || (!attach_pid && !attach_new && i >= argc)) {
        std::fprintf(stderr, "usage: detours_traceapi [--backend breakpoint|hw|inline|mix] [--only A,B] [--stack]\n"
                             "         (-- program [args] | --attach pid [--detach-after-ms N] | --attach-new image)\n");
        return 2;
    }
    probe_session *s = probe_session_create();
    if (!s) return 1;
    static dtrace_config cfgs[DTRACE_KIND_COUNT];
    static const uint32_t rotation[3] = {PROBE_BREAKPOINT, PROBE_HW, PROBE_INLINE};
    int ok = 1, n = 0;
    for (const auto &api : DTRACE_APIS) {
        if (!selected(only, api.name)) continue;
        cfgs[api.kind] = dtrace_config{api.kind, stack ? 1u : 0u};
        const uint32_t flags = mix ? rotation[n % 3] : one;
        ok = ok && probe_add_symbol_cfg(s, api.location, dtrace_on_call, flags, &cfgs[api.kind], sizeof(cfgs[api.kind]));
        ++n;
    }
    if (!n) { std::fprintf(stderr, "detours_traceapi: --only selected no API\n"); probe_close(s); return 2; }
    std::vector<char *> child(argv + (i < argc ? i : argc), argv + argc); child.push_back(nullptr);
    if (attach_new) {
        std::printf("{\"kind\":\"waiting_for\",\"image\":\"%s\"}\n", attach_new); std::fflush(stdout);
        ok = ok && probe_attach_new(s, attach_new, (uint32_t)attach_timeout);
        if (ok) { std::printf("{\"kind\":\"attached\"}\n"); std::fflush(stdout); }
        ok = ok && probe_run(s);
    } else if (attach_pid && detach_ms) {
        // Detach while the target keeps running: attach and run on a worker thread (the
        // debug object belongs to the attaching thread); probe_close from this one.
        HANDLE attached = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        bool attach_ok = false;
        std::thread runner([&] {
            attach_ok = ok && probe_attach(s, (uint32_t)attach_pid);
            SetEvent(attached);
            if (attach_ok) {
                std::printf("{\"kind\":\"attached\",\"pid\":%lu}\n", attach_pid); std::fflush(stdout);
                probe_run(s);
            }
        });
        WaitForSingleObject(attached, INFINITE);
        CloseHandle(attached);
        if (!attach_ok) { runner.join(); probe_report(s, stdout); probe_close(s); return 1; }
        Sleep(detach_ms);
        probe_report(s, stdout);
        probe_close(s);
        runner.join();
        std::printf("{\"kind\":\"detached\",\"pid\":%lu}\n", attach_pid);
        return 0;
    } else if (attach_pid) {
        ok = ok && probe_attach(s, (uint32_t)attach_pid);
        if (ok) { std::printf("{\"kind\":\"attached\",\"pid\":%lu}\n", attach_pid); std::fflush(stdout); }
        ok = ok && probe_run(s);
    } else {
        ok = ok && probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    }
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
