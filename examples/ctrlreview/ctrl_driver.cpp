// ctrl_driver --scenario fault|faultreg|faultmix|inplace|absunload|symunload|owndr|owndrx|absreuse|cfreuse|cfnx|cfrace|cfpin|codeprot|int3cap|
//                        bigcfg|headcorrupt|shape [--shape S] --backend b
//             -- <ctrl_target.exe> <scenario> [opts]
// Instruments ctrl_target for one controller-review finding (see ctrl_target.cpp) with
// one backend, runs it and prints the target's result, the probe rows and the logs.
#include "probe_api.h"
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
void ctrl_on_load(probe_context *);
void ctrl_on_loop(probe_context *);
void ctrl_on_announce(probe_context *);
void ctrl_on_leaf(probe_context *);
void ctrl_on_tick(probe_context *);
void ctrl_on_op(probe_context *);
void ctrl_on_wonce(probe_context *);
void ctrl_on_bigcfg(probe_context *);
void ctrl_on_shape(probe_context *);
void ctrl_on_cfcall(probe_context *);
void ctrl_on_modcall(probe_context *);
void ctrl_on_modhistory(probe_context *);
void ctrl_on_modarm(probe_context *);
}
struct ctrl_cfg { uint32_t backend; uint32_t pad; };

// The per-session agent copies this process left in %TEMP%\uhh (directories "<pid>-...").
static int agent_copies_left() {
    wchar_t tmp[MAX_PATH]; DWORD n = GetTempPathW(MAX_PATH, tmp);
    if (!n || n >= MAX_PATH - 16) return -1;
    std::wstring pattern = std::wstring(tmp) + L"uhh\\" + std::to_wstring(GetCurrentProcessId()) + L"-*";
    WIN32_FIND_DATAW fd{}; int left = 0;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do { if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ++left; } while (FindNextFileW(h, &fd));
    FindClose(h);
    return left;
}

static uint32_t parse_backend(const char *b) {
    return !std::strcmp(b, "hw") ? PROBE_HW : !std::strcmp(b, "inline") ? PROBE_INLINE
         : !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : 0;
}

int main(int argc, char **argv) {
    uint32_t backend = 0;
    std::string sc, shape;
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) backend = parse_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--scenario") && i + 1 < argc) sc = argv[++i];
        else if (!std::strcmp(argv[i], "--shape") && i + 1 < argc) shape = argv[++i];
    }
    if (i + 1 >= argc || !backend || sc.empty()) {
        std::fprintf(stderr, "usage: ctrl_driver --scenario s --backend b -- ctrl_target.exe s [opts]\n");
        return 2;
    }
    std::vector<char *> child(argv + i + 1, argv + argc); child.push_back(nullptr);
    // unlaunched/badlaunch: an empty directory in %TEMP%\uhh that is not an agent copy (like an
    // empty logs\) must survive the agent-prep thread's sweep of dead sessions' copies.
    std::wstring keep;
    if (sc == "unlaunched" || sc == "badlaunch") {
        wchar_t tmp[MAX_PATH]; DWORD n = GetTempPathW(MAX_PATH, tmp);
        if (n && n < MAX_PATH - 40) {
            CreateDirectoryW((std::wstring(tmp) + L"uhh").c_str(), nullptr);
            keep = std::wstring(tmp) + L"uhh\\keep-" + std::to_wstring(GetCurrentProcessId());
            CreateDirectoryW(keep.c_str(), nullptr);
        }
    }
    probe_session *s = probe_session_create();
    ctrl_cfg k{backend, 0};
    bool ok = s != nullptr;
    if (ok) {
        if (sc == "modforward")
            ok = probe_add_symbol(s, ("modrel_forward_" + shape + ".dll!ForwardValue").c_str(), ctrl_on_load, backend);
        else if (sc == "modcall" || sc == "modhistory") {
            ok = probe_add_symbol(s, "ctrl_target.exe!CtrlCall", sc == "modhistory" ? ctrl_on_modhistory : ctrl_on_modcall, backend);
        } else if (sc == "modreload") {
#if defined(_WIN64)
            ok = probe_add_symbol(s, "modrel_owner.dll!ModSysInsn", ctrl_on_load, backend);
#else
            ok = probe_add_symbol(s, "modrel_owner.dll!ModSys", ctrl_on_load, backend);
#endif
        } else if (sc == "modreloc")
            ok = probe_add_symbol_cfg(s, "ctrl_target.exe!CtrlAnnounce", ctrl_on_modarm, backend, &k, sizeof(k));
        else if (sc == "fault" || sc == "faultreg" || sc == "faultmix")
            ok = probe_add_symbol(s, "ctrl_target.exe!CtrlLoadInsn", ctrl_on_load, backend);
        else if (sc == "inplace")
            ok = probe_add_symbol(s, "ctrl_target.exe!CtrlLoopInsn", ctrl_on_loop, backend);
        else if (sc == "absunload")
            ok = probe_add_symbol_cfg(s, "ctrl_target.exe!CtrlAnnounce", ctrl_on_announce, backend, &k, sizeof(k));
        else if (sc == "symunload")
            ok = probe_add_symbol(s, "ctrl_dll.dll!CtrlDllLeaf", ctrl_on_leaf, backend);
        else if (sc == "owndr" || sc == "headcorrupt" || sc == "unlaunched" || sc == "badlaunch")
            ok = probe_add_symbol(s, "ctrl_target.exe!CtrlTick", ctrl_on_tick, backend);
        else if (sc == "absreuse" || sc == "int3cap")
            ok = probe_add_symbol(s, "ctrl_target.exe!CtrlOp", ctrl_on_op, backend);
        else if (sc == "cfreuse" || sc == "cfnx" || sc == "cfrace" || sc == "cfpin")
            ok = probe_add_symbol(s, "ctrl_target.exe!CtrlCall", ctrl_on_cfcall, backend);
        else if (sc == "codeprot")
            ok = probe_add_symbol(s, "ctrl_target.exe!CtrlCodeLeaf", ctrl_on_leaf, backend);
        else if (sc == "owndrx")
            ok = probe_add_symbol(s, "ctrl_target.exe!CtrlWatchOnce", ctrl_on_wonce, backend);
        else if (sc == "bigcfg")
            ok = probe_add_symbol(s, "ctrl_target.exe!CtrlBigCfg", ctrl_on_bigcfg, backend);
        else if (sc == "shape")
            ok = probe_add_symbol(s, ("ctrl_target.exe!Shape_" + shape + "_P_Insn").c_str(), ctrl_on_shape, backend);
        else { std::fprintf(stderr, "ctrl_driver: unknown scenario %s\n", sc.c_str()); ok = false; }
    }
    if (ok && (sc == "unlaunched" || sc == "badlaunch")) {
        // perf5: the agent is prepared on its own thread from the first inline add. A session
        // closed without a launch, or whose launch failed, must still end it cleanly: no crash
        // (a joinable thread at the session's end), the per-session agent copy deleted.
        char missing[] = "C:\\uhh-no-such-dir\\no_such_target.exe";
        char *bad[] = {missing, nullptr};
        const int launched = sc == "badlaunch" ? probe_launch(s, bad) : 0;
        probe_close(s);
        const int kept = !keep.empty() && GetFileAttributesW(keep.c_str()) != INVALID_FILE_ATTRIBUTES;
        if (!keep.empty()) RemoveDirectoryW(keep.c_str());
        std::printf("{\"kind\":\"ctrl_result\",\"scenario\":\"%s\",\"launched\":%d,\"copies_left\":%d,\"kept\":%d}\n",
                    sc.c_str(), launched, agent_copies_left(), kept);
        return launched == 0 ? 0 : 1;
    }
    ok = ok && probe_launch(s, child.data());
    // Launch clears pre-launch errors, and dynamic adds restore theirs. Leave a real
    // unrelated diagnostic AFTER launch, before the valid forwarded call_func.
    if (ok && sc == "modhistory") (void)probe_launch(s, nullptr);
    ok = ok && probe_run(s) && probe_wait_for_exit(s);
    if (s) { probe_report(s, stdout); probe_close(s); }
    return ok ? 0 : 1;
}
