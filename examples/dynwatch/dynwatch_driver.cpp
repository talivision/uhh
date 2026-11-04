// Driver for the malloc -> watch chain (see dynwatch_callbacks.cpp).
//   dynwatch_driver [--entry breakpoint|hw|inline] [target args...]
// --entry picks the backend for the malloc-entry probe only; the rest of the chain is
// registered at runtime from inside the callbacks.
#include "probe_api.h"
#include "dynwatch_callbacks.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static std::string sibling(const char *exe) {
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return exe;
    std::string r(path); size_t slash = r.find_last_of("\\/");
    return r.substr(0, slash == std::string::npos ? 0 : slash + 1) + exe;
}

int main(int argc, char **argv) {
    uint32_t entry = PROBE_BREAKPOINT; const char *entry_name = "breakpoint";
    int i = 1;
    if (i + 1 < argc && !std::strcmp(argv[i], "--entry")) {
        entry_name = argv[i + 1];
        if (!std::strcmp(entry_name, "hw")) entry = PROBE_HW;
        else if (!std::strcmp(entry_name, "inline")) entry = PROBE_INLINE;
        else if (std::strcmp(entry_name, "breakpoint")) { std::fprintf(stderr, "bad --entry\n"); return 2; }
        i += 2;
    }
    probe_session *s = probe_session_create();
    if (!s) return 1;
    std::string t = sibling("dynwatch_target.exe");
    std::vector<char *> child; child.push_back(t.data());
    for (; i < argc; ++i) child.push_back(argv[i]);
    child.push_back(nullptr);
    int ok = probe_add_symbol(s, "ucrtbase.dll!malloc", dynwatch_on_malloc, entry) &&
             probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    std::printf("{\"kind\":\"dynwatch_result\",\"entry\":\"%s\",\"returns\":%ld,\"arms\":%ld,\"watch_hits\":%ld}\n",
                entry_name, dynwatch_returns(), dynwatch_arms(), dynwatch_watch_hits());
    probe_close(s);
    return ok ? 0 : 1;
}
