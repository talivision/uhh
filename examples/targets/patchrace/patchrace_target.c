/* patchrace_target -- threads call RaceSite (a NOP run, see the .asm) in a tight loop
   for --seconds, while a tool hooks and unhooks it from outside.
     patchrace_target [--threads N] [--seconds S] [--until-stdin]
       (--until-stdin: run until stdin reaches end of file, --seconds at most -- the caller
        decides how long, e.g. "until N hook cycles are done", on a machine of any speed)
     patchrace_target --flags branch|pushf [--threads N] --calls C
       (each thread calls BranchSite/PushfSite C times; prints calls and tf_seen, the
        number of calls whose own pushed flags showed TF -- must be 0)
   Prints {"kind":"ready","pid":P} once the threads run, then at the end
   {"kind":"app","threads":N,"calls":C,"torn":T} and exits 0. T counts calls that did not
   return 16: a thread resumed on torn hook bytes (or the process crashed: nonzero exit). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t RaceSite(void);        /* returns 16 unless it ran torn hook bytes */
size_t BranchSite(void);   /* returns the flags image the site itself pushed */
size_t PushfSite(void);
static size_t (*volatile flag_site)(void);
static long calls_per_thread;
static volatile LONG tf_seen;
static size_t (*volatile race_site)(void) = RaceSite;
static volatile LONG torn;
static volatile LONG stop;
static volatile LONG64 calls[64];

static DWORD WINAPI flags_worker(void *arg) {
    size_t i = (size_t)arg;
    for (long k = 0; k < calls_per_thread; ++k)
        if (flag_site() & 0x100) InterlockedIncrement(&tf_seen);   /* TF visible to the code */
    calls[i] = calls_per_thread;
    return 0;
}

static DWORD WINAPI worker(void *arg) {
    size_t i = (size_t)arg;
    LONG64 n = 0;
    while (!stop) {
        if (race_site() != 16) InterlockedIncrement(&torn);
        if (race_site() != 16) InterlockedIncrement(&torn);
        if (race_site() != 16) InterlockedIncrement(&torn);
        if (race_site() != 16) InterlockedIncrement(&torn);
        n += 4;
    }
    calls[i] = n;
    return 0;
}

static DWORD WINAPI drain_stdin(void *unused) {
    char buf[256];
    DWORD got;
    (void)unused;
    while (ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, sizeof buf, &got, NULL) && got) {}
    return 0;
}

int main(int argc, char **argv) {
    int threads = 8, seconds = 10;
    const char *flags_mode = NULL;
    int until_stdin = 0;
    for (int i = 1; i < argc; ++i) if (!strcmp(argv[i], "--until-stdin")) until_stdin = 1;
    for (int i = 1; i + 1 < argc; ++i) {
        if (!strcmp(argv[i], "--threads")) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--seconds")) seconds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--flags")) flags_mode = argv[++i];
        else if (!strcmp(argv[i], "--calls")) calls_per_thread = atol(argv[++i]);
    }
    if (threads < 1) threads = 1;
    if (threads > 64) threads = 64;
    HANDLE h[64];
    if (flags_mode) {
        flag_site = !strcmp(flags_mode, "pushf") ? PushfSite : BranchSite;
        for (int i = 0; i < threads; ++i) h[i] = CreateThread(NULL, 0, flags_worker, (void *)(size_t)i, 0, NULL);
        WaitForMultipleObjects((DWORD)threads, h, TRUE, INFINITE);
        LONG64 total = 0;
        for (int i = 0; i < threads; ++i) total += calls[i];
        printf("{\"kind\":\"app\",\"threads\":%d,\"calls\":%lld,\"tf_seen\":%ld}\n", threads, total, tf_seen);
        return 0;
    }
    for (int i = 0; i < threads; ++i) h[i] = CreateThread(NULL, 0, worker, (void *)(size_t)i, 0, NULL);
    printf("{\"kind\":\"ready\",\"pid\":%lu}\n", GetCurrentProcessId());
    fflush(stdout);
    if (until_stdin) {
        HANDLE reader = CreateThread(NULL, 0, drain_stdin, NULL, 0, NULL);
        if (reader) { WaitForSingleObject(reader, (DWORD)seconds * 1000u); CloseHandle(reader); }
    } else {
        Sleep((DWORD)seconds * 1000u);
    }
    InterlockedExchange(&stop, 1);
    WaitForMultipleObjects((DWORD)threads, h, TRUE, INFINITE);
    LONG64 total = 0;
    for (int i = 0; i < threads; ++i) total += calls[i];
    printf("{\"kind\":\"app\",\"threads\":%d,\"calls\":%lld,\"torn\":%ld}\n", threads, total, torn);
    return 0;
}
