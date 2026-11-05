/* detours_target -- the program the Detours-replica examples instrument.
 *
 *   detours_target sleep [--threads T] [--rounds R]
 *       The Detours "simple" workload: every thread sleeps a fixed pattern through
 *       kernel32!Sleep and kernel32!SleepEx, plus one alertable SleepEx that an APC
 *       interrupts (returns WAIT_IO_COMPLETION). Prints the ground truth it requested.
 *
 *   detours_target api [--threads T] [--iters N] [--dir D] [--gate] [--duration-ms MS]
 *       The "traceapi" workload: from T threads, N times each, the APIs Detours' traceapi
 *       sample is known for -- CreateFileW (create / reopen / missing), WriteFile, ReadFile,
 *       CloseHandle, RegOpenKeyExW + RegQueryValueExW, LoadLibraryW -- then one
 *       CreateProcessW (cmd.exe /c exit 7) from the main thread. Every result is checked by
 *       the target itself (data read back == data written, registry value == the value read
 *       before any instrumentation could exist, child exit code == 7): "errors" must be 0.
 *       --gate         print {"kind":"waiting"} and wait for a line on stdin first (attach)
 *       --duration-ms  repeat the per-thread loop until MS have elapsed (attach mid-run)
 *       Each CreateFileW result is printed as {"kind":"open",...} (name, handle,
 *       GetLastError right after the call) -- the ground truth for detours_retval.
 *
 * All file names contain "uhhdt-" so a trace can pick the workload out of startup noise.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define PAYLOAD_LEN 1337u           /* odd size: easy to spot in a trace (ReadFile/WriteFile) */

static volatile LONG g_errors, g_sleep_calls, g_sleepex_calls, g_apc_runs;
static volatile LONG64 g_total_ms;
static volatile LONG g_creates, g_writes, g_reads, g_closes, g_regopens, g_regqueries, g_loads, g_opens_logged;
static CRITICAL_SECTION g_print_lock;
static wchar_t g_dir[MAX_PATH];
static wchar_t g_product[256];
static DWORD g_product_len;
static unsigned g_threads = 4, g_iters = 10, g_rounds = 25, g_duration_ms;

static void fail(const char *what, unsigned t, unsigned i) {
    InterlockedIncrement(&g_errors);
    EnterCriticalSection(&g_print_lock);
    fprintf(stderr, "detours_target: FAILED %s (thread %u iter %u, err %lu)\n", what, t, i, GetLastError());
    LeaveCriticalSection(&g_print_lock);
}

/* ---- sleep ---------------------------------------------------------------------- */
static void my_sleep(DWORD ms) { InterlockedIncrement(&g_sleep_calls); InterlockedAdd64(&g_total_ms, ms); Sleep(ms); }
static DWORD my_sleepex(DWORD ms, BOOL alertable) {
    InterlockedIncrement(&g_sleepex_calls); InterlockedAdd64(&g_total_ms, ms); return SleepEx(ms, alertable);
}

static DWORD WINAPI sleep_thread(void *arg) {
    unsigned t = (unsigned)(uintptr_t)arg;
    for (unsigned r = 0; r < g_rounds; ++r) {
        my_sleep(1 + (t + r) % 3);                 /* 1..3 ms */
        my_sleepex(2, FALSE);
        if (my_sleepex(0, TRUE) != 0) fail("SleepEx(0,TRUE) without an APC", t, r);
        my_sleep(0);                               /* yield */
    }
    return 0;
}

static void CALLBACK apc_proc(ULONG_PTR p) { (void)p; InterlockedIncrement(&g_apc_runs); }

static DWORD WINAPI alertable_thread(void *ready) {
    SetEvent((HANDLE)ready);
    /* Interrupted by the APC the main thread queues: returns WAIT_IO_COMPLETION long
       before 60 s. (Queued before we sleep -> still delivered on entry: deterministic.) */
    DWORD r = my_sleepex(60000, TRUE);
    return r;
}

static int run_sleep(void) {
    LARGE_INTEGER f, a, b; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&a);
    HANDLE th[64]; unsigned n = g_threads > 64 ? 64 : g_threads;
    for (unsigned t = 0; t < n; ++t) th[t] = CreateThread(NULL, 0, sleep_thread, (void *)(uintptr_t)t, 0, NULL);
    HANDLE ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE alert = CreateThread(NULL, 0, alertable_thread, ready, 0, NULL);
    WaitForSingleObject(ready, INFINITE);
    QueueUserAPC(apc_proc, alert, 0);
    WaitForMultipleObjects(n, th, TRUE, INFINITE);
    WaitForSingleObject(alert, INFINITE);
    DWORD alert_ret = 0; GetExitCodeThread(alert, &alert_ret);
    if (alert_ret != WAIT_IO_COMPLETION) fail("alertable SleepEx did not return WAIT_IO_COMPLETION", 0, 0);
    for (unsigned t = 0; t < n; ++t) CloseHandle(th[t]);
    CloseHandle(alert); CloseHandle(ready);
    QueryPerformanceCounter(&b);
    printf("{\"kind\":\"target\",\"mode\":\"sleep\",\"threads\":%u,\"rounds\":%u,\"sleep_calls\":%ld,\"sleepex_calls\":%ld,"
           "\"total_requested_ms\":%lld,\"alertable_ret\":%lu,\"apc_runs\":%ld,\"errors\":%ld,\"elapsed_ms\":%.1f}\n",
           n, g_rounds, g_sleep_calls, g_sleepex_calls, (long long)g_total_ms, alert_ret, g_apc_runs, g_errors,
           (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)f.QuadPart);
    fflush(stdout);
    return g_errors ? 1 : 0;
}

/* ---- api ------------------------------------------------------------------------ */
static void json_name(char *out, size_t cap, const wchar_t *path) {
    const wchar_t *base = wcsrchr(path, L'\\'); base = base ? base + 1 : path;
    size_t n = 0;
    for (; *base && n + 1 < cap; ++base) out[n++] = (*base >= 0x20 && *base < 0x7f && *base != '"' && *base != '\\') ? (char)*base : '.';
    out[n] = 0;
}

/* Every CreateFileW of the workload goes through this one call site, so detours_retval
   needs exactly one return-address probe for all of them (hardware: one DR slot). */
static __declspec(noinline) HANDLE open_file(const wchar_t *path, DWORD access, DWORD disposition) {
    HANDLE h = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, disposition,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD err = GetLastError();
    char name[128]; json_name(name, sizeof(name), path);
    EnterCriticalSection(&g_print_lock);
    printf("{\"kind\":\"open\",\"name\":\"%s\",\"handle\":\"0x%llx\",\"error\":%lu,\"tid\":%lu}\n", name,
           (unsigned long long)(uintptr_t)h, err, GetCurrentThreadId());
    fflush(stdout);                        /* one write per line (see main) */
    LeaveCriticalSection(&g_print_lock);
    InterlockedIncrement(&g_opens_logged);
    SetLastError(err);
    return h;
}

static void fill_payload(unsigned char *p, unsigned t, unsigned i) {
    memcpy(p, "UHHDT-PAYLOAD-", 14);
    for (unsigned k = 14; k < PAYLOAD_LEN; ++k) p[k] = (unsigned char)(t * 31u + i * 7u + k * 13u);
}

static void api_iteration(unsigned t, unsigned i) {
    wchar_t path[MAX_PATH], missing[MAX_PATH];
    unsigned char out[PAYLOAD_LEN], in[PAYLOAD_LEN + 16];
    DWORD done = 0;
    swprintf(path, MAX_PATH, L"%s\\uhhdt-t%u-i%u.bin", g_dir, t, i % 4u);
    swprintf(missing, MAX_PATH, L"%s\\uhhdt-missing-t%u.bin", g_dir, t);
    fill_payload(out, t, i);

    HANDLE h = open_file(path, GENERIC_WRITE, CREATE_ALWAYS);       /* 0 or 183 (exists) */
    InterlockedIncrement(&g_creates);
    if (h == INVALID_HANDLE_VALUE) { fail("CreateFileW(CREATE_ALWAYS)", t, i); return; }
    if (!WriteFile(h, out, PAYLOAD_LEN, &done, NULL) || done != PAYLOAD_LEN) fail("WriteFile", t, i);
    InterlockedIncrement(&g_writes);
    CloseHandle(h); InterlockedIncrement(&g_closes);

    h = open_file(path, GENERIC_READ, OPEN_EXISTING);
    InterlockedIncrement(&g_creates);
    if (h == INVALID_HANDLE_VALUE) { fail("CreateFileW(OPEN_EXISTING)", t, i); return; }
    memset(in, 0, sizeof(in));
    if (!ReadFile(h, in, PAYLOAD_LEN, &done, NULL) || done != PAYLOAD_LEN || memcmp(in, out, PAYLOAD_LEN)) fail("ReadFile", t, i);
    InterlockedIncrement(&g_reads);
    CloseHandle(h); InterlockedIncrement(&g_closes);

    h = open_file(missing, GENERIC_READ, OPEN_EXISTING);            /* INVALID_HANDLE_VALUE, 2 */
    InterlockedIncrement(&g_creates);
    if (h != INVALID_HANDLE_VALUE || GetLastError() != ERROR_FILE_NOT_FOUND) fail("CreateFileW(missing)", t, i);

    HKEY key = NULL; wchar_t value[256]; DWORD type = 0, bytes = sizeof(value);
    LSTATUS st = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &key);
    InterlockedIncrement(&g_regopens);
    if (st != ERROR_SUCCESS) { fail("RegOpenKeyExW", t, i); return; }
    memset(value, 0, sizeof(value));
    st = RegQueryValueExW(key, L"ProductName", NULL, &type, (BYTE *)value, &bytes);
    InterlockedIncrement(&g_regqueries);
    if (st != ERROR_SUCCESS || type != REG_SZ || bytes != g_product_len || memcmp(value, g_product, bytes)) fail("RegQueryValueExW", t, i);
    RegCloseKey(key);

    HMODULE m = LoadLibraryW(L"version.dll");
    InterlockedIncrement(&g_loads);
    if (!m || !GetProcAddress(m, "GetFileVersionInfoSizeW")) fail("LoadLibraryW(version.dll)", t, i);
    if (m) FreeLibrary(m);
}

static DWORD WINAPI api_thread(void *arg) {
    unsigned t = (unsigned)(uintptr_t)arg;
    ULONGLONG until = GetTickCount64() + g_duration_ms;
    unsigned i = 0;
    do {
        for (unsigned k = 0; k < g_iters; ++k, ++i) api_iteration(t, i);
    } while (g_duration_ms && GetTickCount64() < until);
    return 0;
}

static int run_api(int gate) {
    /* Ground truth for the registry value, read before anything could be instrumented
       (with --gate: before the attach). */
    HKEY key; DWORD type = 0; g_product_len = sizeof(g_product);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &key) ||
        RegQueryValueExW(key, L"ProductName", NULL, &type, (BYTE *)g_product, &g_product_len)) {
        fprintf(stderr, "detours_target: cannot read ProductName\n"); return 2;
    }
    RegCloseKey(key);
    if (gate) {
        printf("{\"kind\":\"waiting\",\"pid\":%lu}\n", GetCurrentProcessId()); fflush(stdout);
        char line[64]; if (!fgets(line, sizeof(line), stdin)) { /* EOF: go anyway */ }
    }
    HANDLE th[64]; unsigned n = g_threads > 64 ? 64 : g_threads;
    for (unsigned t = 0; t < n; ++t) th[t] = CreateThread(NULL, 0, api_thread, (void *)(uintptr_t)t, 0, NULL);
    WaitForMultipleObjects(n, th, TRUE, INFINITE);
    for (unsigned t = 0; t < n; ++t) CloseHandle(th[t]);

    /* One child, from the main thread. */
    wchar_t sysdir[MAX_PATH], cmdline[MAX_PATH + 64];
    GetSystemDirectoryW(sysdir, MAX_PATH);
    swprintf(cmdline, MAX_PATH + 64, L"\"%s\\cmd.exe\" /d /c exit 7", sysdir);
    STARTUPINFOW si = {sizeof(si)}; PROCESS_INFORMATION pi = {0};
    DWORD child_exit = 0;
    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        fail("CreateProcessW", 0, 0);
    } else {
        WaitForSingleObject(pi.hProcess, 30000);
        GetExitCodeProcess(pi.hProcess, &child_exit);
        if (child_exit != 7) fail("child exit code", 0, 0);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    char product[256]; json_name(product, sizeof(product), g_product);
    printf("{\"kind\":\"target\",\"mode\":\"api\",\"threads\":%u,\"iters\":%u,\"creates\":%ld,\"writes\":%ld,\"reads\":%ld,"
           "\"closes\":%ld,\"regopens\":%ld,\"regqueries\":%ld,\"loads\":%ld,\"processes\":1,\"child_exit\":%lu,"
           "\"product\":\"%s\",\"opens_logged\":%ld,\"errors\":%ld}\n",
           n, g_iters, g_creates, g_writes, g_reads, g_closes, g_regopens, g_regqueries, g_loads, child_exit,
           product, g_opens_logged, g_errors);
    fflush(stdout);
    return g_errors ? 1 : 0;
}

int main(int argc, char **argv) {
    InitializeCriticalSection(&g_print_lock);
    /* Fully buffered + an explicit fflush per line: ONE WriteFile per line. (Unbuffered
       UCRT stdout writes character by character; a tracer sharing this stdout -- UHH's
       live log tail -- would then land in the middle of our lines.) */
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    if (argc < 2) { fprintf(stderr, "usage: detours_target sleep|api [options]\n"); return 2; }
    int gate = 0;
    GetTempPathW(MAX_PATH, g_dir);
    size_t dl = wcslen(g_dir); if (dl && g_dir[dl - 1] == L'\\') g_dir[dl - 1] = 0;
    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "--threads") && i + 1 < argc) g_threads = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rounds") && i + 1 < argc) g_rounds = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--iters") && i + 1 < argc) g_iters = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--duration-ms") && i + 1 < argc) g_duration_ms = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--dir") && i + 1 < argc) { MultiByteToWideChar(CP_ACP, 0, argv[++i], -1, g_dir, MAX_PATH); }
        else if (!strcmp(argv[i], "--gate")) gate = 1;
        else if (!strcmp(argv[i], "--no-wait")) {}
        else { fprintf(stderr, "detours_target: unknown option %s\n", argv[i]); return 2; }
    }
    if (g_threads == 0) g_threads = 1;
    if (!strcmp(argv[1], "sleep")) return run_sleep();
    if (!strcmp(argv[1], "api")) { CreateDirectoryW(g_dir, NULL); return run_api(gate); }
    fprintf(stderr, "detours_target: unknown mode %s\n", argv[1]);
    return 2;
}
