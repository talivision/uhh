// logs_target -- adversarial log-delivery target (regress `logs-*`). Every mode calls two
// exported sites, LogSiteA(tag, seq) / LogSiteB(tag, seq); logs_callbacks.cpp logs from them.
//
//   --mode format        one thread, LogSiteA(0x100 + k, k) for every format case k
//   --mode order         T threads, each: LogSiteA(0xA, 2i), LogSiteB(0xB, 2i+1)   (per-thread order)
//   --mode wedge-kill    a lone producer is caught (suspended, via the shared ring) between
//                        claiming a ring slot and publishing it, and TerminateThread'ed there;
//                        then T threads log M records each (timed)
//   --mode wedge-suspend the same, but the producer is left SUSPENDED (the app's own
//                        SuspendThread) for the whole second phase, then resumed
//   --mode exit          T threads flood LogSiteA; main calls ExitProcess(7) after --ms
//   --mode selfterm      the same with TerminateProcess(self, 7)
//   --mode gate          print {"kind":"waiting","pid":N}, wait for a line on stdin, then T
//                        threads x M LogSiteA calls; prints the elapsed time (attach tests)
// Prints one {"kind":"app",...} line.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "probe_agent_shared.hpp"

static volatile LONG64 g_sink;
static volatile LONG g_stop, g_go;
static int g_threads = 4, g_count = 3000, g_ms = 200;
static unsigned g_cases = 16;

extern "C" __declspec(dllexport) __declspec(noinline) LONG64 LogSiteA(unsigned tag, unsigned seq) {
    g_sink += (LONG64)(tag ^ seq);
    return g_sink;
}
extern "C" __declspec(dllexport) __declspec(noinline) LONG64 LogSiteB(unsigned tag, unsigned seq) {
    g_sink -= (LONG64)(tag ^ seq);
    return g_sink;
}

static DWORD WINAPI order_thread(void *) {
    while (!g_go) YieldProcessor();
    for (unsigned i = 0; i < (unsigned)g_count; ++i) { LogSiteA(0xA, 2 * i); LogSiteB(0xB, 2 * i + 1); }
    return 0;
}
static DWORD WINAPI forever_thread(void *) {
    for (unsigned i = 0; !g_stop; ++i) LogSiteA(0xA, i);
    return 0;
}
static volatile LONG64 g_phase2_calls;
static DWORD WINAPI phase2_thread(void *) {
    ULONGLONG deadline = GetTickCount64() + 20000;          // bounded even when every log stalls
    for (unsigned i = 0; i < (unsigned)g_count && GetTickCount64() < deadline; ++i) {
        LogSiteA(0xA, i); InterlockedIncrement64(&g_phase2_calls);
    }
    return 0;
}

static probe_agent_shared *map_ring() {
    wchar_t name[64]; probe_agent_mapping_name(GetCurrentProcessId(), name);
    for (int i = 0; i < 500; ++i) {
        if (HANDLE m = OpenFileMappingW(FILE_MAP_READ, FALSE, name))
            return (probe_agent_shared *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, sizeof(probe_agent_shared));
        Sleep(10);
    }
    return nullptr;
}
// A slot in [tail, head) that is claimed but not published (seq == pos). With one producer
// running, it is that producer's.
static bool claimed_unpublished(const probe_agent_shared *sh) {
    LONG64 head = sh->log_head, tail = sh->log_tail;
    for (LONG64 pos = tail; pos < head; ++pos)
        if (sh->logs[(uint64_t)pos % PROBE_AGENT_LOG_CAP].seq == pos) return true;
    return false;
}

static int run_phase2() {
    HANDLE h[64]; int n = g_threads > 64 ? 64 : g_threads;
    ULONGLONG t0 = GetTickCount64();
    for (int t = 0; t < n; ++t) h[t] = CreateThread(nullptr, 0, phase2_thread, nullptr, 0, nullptr);
    WaitForMultipleObjects((DWORD)n, h, TRUE, INFINITE);
    for (int t = 0; t < n; ++t) CloseHandle(h[t]);
    return (int)(GetTickCount64() - t0);
}

static int wedge(bool kill) {
    probe_agent_shared *sh = map_ring();
    if (!sh) { printf("{\"kind\":\"app\",\"error\":\"no shared ring\"}\n"); return 3; }
    HANDLE w = CreateThread(nullptr, 0, forever_thread, nullptr, 0, nullptr);
    int wedged = 0, tries = 0;
    for (; tries < 200000 && !wedged; ++tries) {
        Sleep(0);
        if (SuspendThread(w) == (DWORD)-1) break;
        // A suspend is asynchronous: GetThreadContext waits until the thread really stopped.
        CONTEXT cx{}; cx.ContextFlags = CONTEXT_CONTROL; GetThreadContext(w, &cx);
        if (claimed_unpublished(sh)) { wedged = 1; break; }
        ResumeThread(w);
    }
    if (wedged && kill) { TerminateThread(w, 99); WaitForSingleObject(w, INFINITE); }
    int ms = run_phase2();
    // Live delivery: everything the second phase logged leaves the ring while the target runs.
    ULONGLONG until = GetTickCount64() + 3000;
    LONG64 published_behind = 0;
    while (GetTickCount64() < until) {
        published_behind = 0;
        for (LONG64 pos = sh->log_tail, head = sh->log_head; pos < head; ++pos)
            if (sh->logs[(uint64_t)pos % PROBE_AGENT_LOG_CAP].seq == pos + 1) ++published_behind;
        if (!published_behind) break;
        Sleep(10);
    }
    if (!kill) { InterlockedExchange(&g_stop, 1); if (wedged) ResumeThread(w); else ResumeThread(w); WaitForSingleObject(w, 10000); }
    else if (!wedged) { InterlockedExchange(&g_stop, 1); ResumeThread(w); WaitForSingleObject(w, 10000); }
    CloseHandle(w);
    printf("{\"kind\":\"app\",\"mode\":\"%s\",\"wedged\":%d,\"tries\":%d,\"phase2_calls\":%lld,\"phase2_want\":%d,"
           "\"phase2_ms\":%d,\"undelivered_after_phase2\":%lld}\n",
           kill ? "wedge-kill" : "wedge-suspend", wedged, tries, (long long)g_phase2_calls, g_threads * g_count, ms,
           (long long)published_behind);
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = "format";
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--mode") && i + 1 < argc) mode = argv[++i];
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) g_threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--count") && i + 1 < argc) g_count = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ms") && i + 1 < argc) g_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cases") && i + 1 < argc) g_cases = (unsigned)atoi(argv[++i]);
    }
    if (g_threads < 1 || g_threads > 64) g_threads = 4;
    if (!strcmp(mode, "format")) {
        for (unsigned k = 0; k < g_cases; ++k) LogSiteA(0x100 + k, k);
        printf("{\"kind\":\"app\",\"mode\":\"format\",\"cases\":%u}\n", g_cases);
        return 0;
    }
    if (!strcmp(mode, "order")) {
        HANDLE h[64];
        for (int t = 0; t < g_threads; ++t) h[t] = CreateThread(nullptr, 0, order_thread, nullptr, 0, nullptr);
        InterlockedExchange(&g_go, 1);
        WaitForMultipleObjects((DWORD)g_threads, h, TRUE, INFINITE);
        printf("{\"kind\":\"app\",\"mode\":\"order\",\"threads\":%d,\"count\":%d}\n", g_threads, g_count);
        return 0;
    }
    if (!strcmp(mode, "gate")) {
        printf("{\"kind\":\"waiting\",\"pid\":%lu}\n", GetCurrentProcessId()); fflush(stdout);
        char b; DWORD got = 0; ReadFile(GetStdHandle(STD_INPUT_HANDLE), &b, 1, &got, nullptr);
        int ms = run_phase2();
        printf("{\"kind\":\"app\",\"mode\":\"gate\",\"calls\":%lld,\"want\":%d,\"ms\":%d}\n",
               (long long)g_phase2_calls, g_threads * g_count, ms);
        return 0;
    }
    if (!strcmp(mode, "wedge-kill")) return wedge(true);
    if (!strcmp(mode, "wedge-suspend")) return wedge(false);
    if (!strcmp(mode, "exit") || !strcmp(mode, "selfterm")) {
        for (int t = 0; t < g_threads; ++t) CloseHandle(CreateThread(nullptr, 0, forever_thread, nullptr, 0, nullptr));
        Sleep(g_ms);
        printf("{\"kind\":\"app\",\"mode\":\"%s\"}\n", mode); fflush(stdout);
        if (!strcmp(mode, "exit")) ExitProcess(7);
        TerminateProcess(GetCurrentProcess(), 7);
    }
    return 2;
}
