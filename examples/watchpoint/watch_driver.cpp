// Hardware data-watchpoint demo driver. Sets a WRITE watchpoint on watch_target's
// global `g_watched` (passed as its module RVA) and counts callback invocations: one
// per store to that address. The callback runs controller-side (the hardware backend
// is an external debugger), so no injected agent is involved. This observes a plain
// memory write — a capability inline/trampoline hooking fundamentally lacks.
#include "probe_api.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static long g_hits = 0;
static void on_write(probe_context *c) { (void)c; ++g_hits; }

static std::string sibling_target() {
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return "watch_target.exe";
    std::string r(path); size_t slash = r.find_last_of("\\/");
    return r.substr(0, slash == std::string::npos ? 0 : slash + 1) + "watch_target.exe";
}

int main(int argc, char **argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: watch_driver <g_watched_rva> [target args...]\n"); return 2; }
    char loc[96];
    std::snprintf(loc, sizeof(loc), "watch_target.exe+0x%llx",
                  (unsigned long long)std::strtoull(argv[1], nullptr, 0));
    probe_session *s = probe_session_create();
    if (!s) return 1;
    std::string target = sibling_target();
    std::vector<char *> child; child.push_back(target.data());
    for (int i = 2; i < argc; ++i) child.push_back(argv[i]);
    child.push_back(nullptr);
    int ok = probe_add_symbol(s, loc, on_write, PROBE_HW | PROBE_WATCH_WRITE) &&
             probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    std::printf("{\"kind\":\"watch_driver\",\"callback_hits\":%ld}\n", g_hits);
    probe_close(s);
    return ok ? 0 : 1;
}
