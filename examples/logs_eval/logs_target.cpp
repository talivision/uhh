// logs_target -- adversarial log-delivery target (regress `logs-*`). Every mode calls two
// exported sites, LogSiteA(tag, seq) / LogSiteB(tag, seq); logs_callbacks.cpp logs from them.
//
//   --mode format        one thread, LogSiteA(0x100 + k, k) for every format case k
//   --mode order         T threads, each: LogSiteA(0xA, 2i), LogSiteB(0xB, 2i+1)   (per-thread order)
//   --mode wedge-kill    a lone producer is stopped between claiming a ring slot and publishing
//                        it (deterministically: its record "UHH_TEST_WEDGE o N" hits the agent's
//                        test stop, see agent.cpp test_wedge_point; the ring confirms the claimed,
//                        unpublished slot), and TerminateThread'ed there;
//                        then T threads log M records each (timed)
//   --mode wedge-suspend the same, but the producer is left SUSPENDED (the app's own
//                        SuspendThread) for the whole second phase, then resumed
//   --mode wedge-exit    the producer is caught the same way, then the process calls
//                        ExitProcess(7) -- which kills it there -- and the exiting thread
//                        logs --count more records from a TLS callback at DLL_PROCESS_DETACH
//                        (more than the ring holds: they must get past the dead slot)
//   --mode exit          T threads flood LogSiteA; main calls ExitProcess(7) after --ms
//   --mode selfterm      the same with TerminateProcess(self, 7)
//   --mode gate          print {"kind":"waiting","pid":N}, wait for a line on stdin, then T
//                        threads x M LogSiteA calls; prints the elapsed time (attach tests).
//                        After the line it maps the agent's shared ring (the session must be
//                        attached by then), prints {"kind":"mapped"}, waits for a SECOND line,
//                        runs the calls and prints the ring's accounting before/after them:
//                        hits, log_head, log_dropped, in-flight (the controller-death check)
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
struct ring_acct { unsigned long long hits, head, tail, dropped, inflight; };
static ring_acct acct(const probe_agent_shared *sh) {
    ring_acct a{};
    MemoryBarrier();
    for (uint32_t p = 0; p < PROBE_AGENT_MAX_PROBES; ++p) a.hits += probe_agent_hits(sh, p);
    a.inflight = probe_agent_unlogged(sh);     // records left in the ring carry their hits (v23)
    a.head = (unsigned long long)sh->log_head; a.tail = (unsigned long long)sh->log_tail;
    a.dropped = (unsigned long long)(ULONG)sh->log_dropped;
    return a;
}
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
static const unsigned WEDGE_SEQ = 1000;     // the producer's call that stops in its claimed slot
static DWORD WINAPI forever_thread(void *) {
    for (unsigned i = 0; !g_stop; ++i) LogSiteA(i == WEDGE_SEQ ? 0xE : 0xA, i);
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

// Process-detach logging (wedge-exit): runs on the exiting thread after ExitProcess has
// killed every other thread.
static volatile LONG g_detach_logs;
static void NTAPI logs_tls_callback(PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_DETACH && g_detach_logs)
        for (int i = 0; i < g_detach_logs; ++i) LogSiteA(0xA, (unsigned)i);
}
#if defined(_WIN64)
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:logs_tls_callback_ptr")
#pragma const_seg(".CRT$XLB")
extern "C" const PIMAGE_TLS_CALLBACK logs_tls_callback_ptr = logs_tls_callback;
#pragma const_seg()
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_logs_tls_callback_ptr")
#pragma data_seg(".CRT$XLB")
extern "C" PIMAGE_TLS_CALLBACK logs_tls_callback_ptr = logs_tls_callback;
#pragma data_seg()
#endif

static int run_phase2() {
    HANDLE h[64]; int n = g_threads > 64 ? 64 : g_threads;
    ULONGLONG t0 = GetTickCount64();
    for (int t = 0; t < n; ++t) h[t] = CreateThread(nullptr, 0, phase2_thread, nullptr, 0, nullptr);
    WaitForMultipleObjects((DWORD)n, h, TRUE, INFINITE);
    for (int t = 0; t < n; ++t) CloseHandle(h[t]);
    return (int)(GetTickCount64() - t0);
}

static int wedge(bool kill, bool exit_after = false) {
    probe_agent_shared *sh = map_ring();
    if (!sh) { printf("{\"kind\":\"app\",\"error\":\"no shared ring\"}\n"); return 3; }
    // The producer stops in its claimed slot at its WEDGE_SEQ-th call (the agent's test stop):
    // wait for that, then check the ring shows a claimed, unpublished slot. With it stopped there
    // the program's own SuspendThread (suspend mode) holds it exactly where sampling used to.
    wchar_t at_name[64], go_name[64];
    swprintf_s(at_name, L"Local\\uhh_test_wedge_%lu", GetCurrentProcessId());
    swprintf_s(go_name, L"Local\\uhh_test_wedge_go_%lu", GetCurrentProcessId());
    HANDLE at = CreateEventW(nullptr, FALSE, FALSE, at_name), go = CreateEventW(nullptr, TRUE, FALSE, go_name);
    SetEnvironmentVariableA("UHH_TEST_LOG_WEDGE", "1");
    HANDLE w = CreateThread(nullptr, 0, forever_thread, nullptr, 0, nullptr);
    int wedged = 0, tries = 0;
    if (at && go && WaitForSingleObject(at, 60000) == WAIT_OBJECT_0) {
        for (; tries < 1000 && !wedged; ++tries) { wedged = claimed_unpublished(sh) ? 1 : 0; if (!wedged) Sleep(1); }
        if (wedged && !kill && SuspendThread(w) == (DWORD)-1) wedged = 0;   // the program's own suspension
    }
    if (exit_after) {
        printf("{\"kind\":\"app\",\"mode\":\"wedge-exit\",\"wedged\":%d,\"tries\":%d,\"detach_logs\":%d}\n",
               wedged, tries, g_count);
        fflush(stdout);
        InterlockedExchange(&g_detach_logs, g_count);
        ExitProcess(7);                                       // kills w inside its claimed slot
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
    InterlockedExchange(&g_stop, 1);
    if (go) SetEvent(go);                                     // the stopped producer may finish its record
    if (!kill) { if (wedged) ResumeThread(w); WaitForSingleObject(w, 10000); }
    else if (!wedged) WaitForSingleObject(w, 10000);
    if (at) CloseHandle(at);
    if (go) CloseHandle(go);
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
        HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
        char b = 0; DWORD got = 0;
        while (ReadFile(in, &b, 1, &got, nullptr) && got == 1 && b != '\n') {}
        probe_agent_shared *sh = map_ring();
        printf("{\"kind\":\"mapped\",\"ok\":%d}\n", sh != nullptr); fflush(stdout);
        b = 0;
        while (ReadFile(in, &b, 1, &got, nullptr) && got == 1 && b != '\n') {}
        const ring_acct a0 = sh ? acct(sh) : ring_acct{};
        int ms = run_phase2();
        const ring_acct a1 = sh ? acct(sh) : ring_acct{};
        printf("{\"kind\":\"app\",\"mode\":\"gate\",\"calls\":%lld,\"want\":%d,\"ms\":%d,\"mapped\":%d,"
               "\"hits0\":%llu,\"hits1\":%llu,\"head0\":%llu,\"head1\":%llu,\"tail0\":%llu,\"tail1\":%llu,"
               "\"dropped0\":%llu,\"dropped1\":%llu,\"inflight1\":%llu}\n",
               (long long)g_phase2_calls, g_threads * g_count, ms, sh != nullptr, a0.hits, a1.hits, a0.head, a1.head,
               a0.tail, a1.tail, a0.dropped, a1.dropped, a1.inflight);
        return 0;
    }
    if (!strcmp(mode, "wedge-kill")) return wedge(true);
    if (!strcmp(mode, "wedge-exit")) return wedge(true, true);
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
