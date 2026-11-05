/* lifecycle_target -- a busy multithreaded process that tools attach to, detach from and
 * re-attach to (regress `lifecycle-*`). It checks ITSELF that every instrumentation left
 * it exactly as it was.
 *
 *   lifecycle_target [--threads N] [--churn] [--dll] [--slow-every K] [--slow-ms M]
 *
 * Workers loop until told to quit: NtOpenProcess(own pid) -> NtReadVirtualMemory of a known
 * 64-byte pattern (verified) -> NtClose -> configparse.dll!ParseConfig("reads_enabled=0")
 * (whose mid-function site +0x16 a tool may flip: counted as a "flip", never an error).
 * --slow-every K: every K-th iteration calls lc_slow(M) (Sleep M ms, returns M+1, verified):
 * a probe there can block in call_original. --churn: one thread keeps creating short-lived
 * threads that do one iteration each (threads born while a tool is attached). --dll: one
 * thread keeps loading/unloading hunt_dll.dll (refcount 0 -> really unmapped) and calls
 * HuntWork, so a probe there is pending/active/unloaded over and over.
 *
 * stdin commands (one per line):
 *   check  -> {"kind":"check",...}: the code bytes of every probe-able site against the
 *             snapshot taken at start-up (before any tool attached), the debug registers and
 *             trap flag of EVERY thread, IsDebuggerPresent, whether probe_api_agent.dll is
 *             loaded, iteration/error/flip counts.
 *   reset  -> zero the flip counter (after a detach, nothing may flip any more)
 *   lock N -> a thread holds the LOADER LOCK for N ms ({"kind":"locked"} once held): a tool's
 *             remote thread (agent load / init) cannot even start meanwhile
 *   quit   -> stop, join, final check, {"kind":"app",...}, exit 0 (1 on any error)
 * --ms-signed-only: from start-up on, only Microsoft-signed DLLs may load (process mitigation
 * policy): an injected agent is refused, so a tool's session fails mid-attach.
 * Any unhandled exception is printed as {"kind":"unhandled",...} before the process dies.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef LONG(NTAPI *NtReadFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef struct { ULONG Length; HANDLE Root; PVOID Name; ULONG Attributes; PVOID Sd, Qos; } OBJATTR;
typedef struct { HANDLE UniqueProcess, UniqueThread; } CLIENTID;
typedef LONG(NTAPI *NtOpenFn)(HANDLE *, ACCESS_MASK, OBJATTR *, CLIENTID *);
typedef LONG(NTAPI *NtCloseFn)(HANDLE);
typedef struct { unsigned reads_enabled, reserved; } parsed_config;
typedef int (*ParseFn)(const char *, parsed_config *);
typedef void (*HuntWorkFn)(void (*)(void), volatile LONG *);

static NtReadFn g_ntread; static NtOpenFn g_ntopen; static NtCloseFn g_ntclose; static ParseFn g_parse;
static unsigned char g_pattern[64];
static volatile LONG g_stop, g_errors, g_flips, g_slow_calls, g_churned, g_dll_cycles, g_work;
static volatile LONG64 g_iters;
static char g_first_error[160];
static LONG g_slow_every = 0, g_slow_ms = 50;

static void error(const char *what) {
    if (InterlockedIncrement(&g_errors) == 1) _snprintf_s(g_first_error, sizeof(g_first_error), _TRUNCATE, "%s", what);
}

__declspec(dllexport) __declspec(noinline) int lc_slow(int ms) {
    volatile int pad = ms;          /* a few instructions before the call: an inline-safe entry */
    Sleep((DWORD)pad);
    return pad + 1;
}

/* One verified read (also hunt_dll's DllMain/HuntWork callback). Uses its own handle. */
__declspec(dllexport) __declspec(noinline) void hunt_read(void) {
    OBJATTR oa; CLIENTID cid; HANDLE h = NULL; unsigned char buf[64]; SIZE_T got = 0;
    memset(&oa, 0, sizeof(oa)); oa.Length = sizeof(oa);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId(); cid.UniqueThread = NULL;
    if (g_ntopen(&h, PROCESS_VM_READ, &oa, &cid) < 0 || !h) { error("NtOpenProcess failed"); return; }
    memset(buf, 0, sizeof(buf));
    if (g_ntread(h, g_pattern, buf, sizeof(buf), &got) < 0 || got != sizeof(buf) || memcmp(buf, g_pattern, sizeof(buf)))
        error("read returned wrong data");
    if (g_ntclose(h) < 0) error("NtClose failed");
}

static void iteration(LONG64 k) {
    parsed_config pc = {7, 7};
    hunt_read();
    if (g_parse("reads_enabled=0\n", &pc) != 1) error("ParseConfig failed");
    else if (pc.reads_enabled == 1) InterlockedIncrement(&g_flips);
    else if (pc.reads_enabled != 0) error("ParseConfig wrong flag");
    if (g_slow_every && k % g_slow_every == 0) {
        if (lc_slow((int)g_slow_ms) != g_slow_ms + 1) error("lc_slow wrong result");
        InterlockedIncrement(&g_slow_calls);
    }
    InterlockedIncrement64(&g_iters);
}

static DWORD WINAPI worker(void *arg) {
    LONG64 k = 0; (void)arg;
    while (!g_stop) iteration(++k);
    return 0;
}

static DWORD WINAPI one_shot(void *arg) { iteration(1); (void)arg; return 0; }

static DWORD WINAPI churner(void *arg) {
    (void)arg;
    while (!g_stop) {
        HANDLE t = CreateThread(NULL, 0, one_shot, NULL, 0, NULL);
        if (!t) { error("CreateThread failed"); Sleep(10); continue; }
        WaitForSingleObject(t, INFINITE); CloseHandle(t);
        InterlockedIncrement(&g_churned);
    }
    return 0;
}

static char g_dir[MAX_PATH];
static DWORD WINAPI dll_churner(void *arg) {
    char path[MAX_PATH]; (void)arg;
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%shunt_dll.dll", g_dir);
    while (!g_stop) {
        HMODULE m = LoadLibraryA(path);
        if (!m) { error("load hunt_dll failed"); Sleep(50); continue; }
        HuntWorkFn work = (HuntWorkFn)GetProcAddress(m, "HuntWork");
        if (work) work(hunt_read, &g_work); else error("HuntWork missing");
        FreeLibrary(m);
        InterlockedIncrement(&g_dll_cycles);
        Sleep(2);
    }
    return 0;
}

/* ---- self check ------------------------------------------------------------------- */
#define NSITES 6
static const char *g_site_name[NSITES] = {"NtOpenProcess", "NtReadVirtualMemory", "NtClose", "ParseConfig",
                                          "lc_slow", "hunt_read"};
static unsigned char *g_site[NSITES];
static unsigned char g_snap[NSITES][48];

static void snapshot(void) {
    for (int i = 0; i < NSITES; ++i) if (g_site[i]) memcpy(g_snap[i], g_site[i], sizeof(g_snap[i]));
}

static int thread_dirty(HANDLE t, char *why, size_t cap) {
    CONTEXT c; memset(&c, 0, sizeof(c));
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
    if (!GetThreadContext(t, &c)) return 0;
    if ((c.Dr7 & 0xFF) || c.Dr0 || c.Dr1 || c.Dr2 || c.Dr3 || (c.EFlags & 0x100)) {
        _snprintf_s(why, cap, _TRUNCATE, "dr7=0x%llx dr0=0x%llx tf=%d", (unsigned long long)c.Dr7,
                    (unsigned long long)c.Dr0, (int)((c.EFlags >> 8) & 1));
        return 1;
    }
    return 0;
}

static void check(const char *kind) {
    char code_bad[256] = "", dr_bad[256] = "", why[96];
    int code_diff = 0, dr_dirty = 0, threads = 0;
    for (int i = 0; i < NSITES; ++i)
        if (g_site[i] && memcmp(g_snap[i], g_site[i], sizeof(g_snap[i]))) {
            ++code_diff;
            size_t n = strlen(code_bad);
            int at = 0; while (at < 48 && g_snap[i][at] == g_site[i][at]) ++at;
            _snprintf_s(code_bad + n, sizeof(code_bad) - n, _TRUNCATE, "%s%s+%d:%02x->%02x", n ? "," : "",
                        g_site_name[i], at, g_snap[i][at], g_site[i][at]);
        }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD self = GetCurrentThreadId(), pid = GetCurrentProcessId();
    for (BOOL more = Thread32First(snap, &te); more; more = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid) continue;
        ++threads;
        if (te.th32ThreadID == self) {
            if (thread_dirty(GetCurrentThread(), why, sizeof(why))) goto dirty;
            continue;
        }
        HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
        if (!t) continue;
        if (SuspendThread(t) != (DWORD)-1) {
            int d = thread_dirty(t, why, sizeof(why));
            ResumeThread(t);
            CloseHandle(t);
            if (d) goto dirty;
        } else CloseHandle(t);
        continue;
    dirty:
        ++dr_dirty;
        { size_t n = strlen(dr_bad);
          _snprintf_s(dr_bad + n, sizeof(dr_bad) - n, _TRUNCATE, "%s%lu:%s", n ? "," : "", te.th32ThreadID, why); }
    }
    CloseHandle(snap);
    printf("{\"kind\":\"%s\",\"code_diff\":%d,\"code_bad\":\"%s\",\"dr_dirty\":%d,\"dr_bad\":\"%s\",\"threads\":%d,"
           "\"debugger\":%d,\"agent_loaded\":%d,\"iterations\":%lld,\"errors\":%ld,\"first_error\":\"%s\","
           "\"flips\":%ld,\"slow_calls\":%ld,\"churned\":%ld,\"dll_cycles\":%ld}\n",
           kind, code_diff, code_bad, dr_dirty, dr_bad, threads, IsDebuggerPresent() ? 1 : 0,
           GetModuleHandleA("probe_api_agent.dll") != NULL, (long long)g_iters, g_errors, g_first_error,
           g_flips, g_slow_calls, g_churned, g_dll_cycles);
    fflush(stdout);
}

typedef LONG(NTAPI *LdrLockFn)(ULONG, ULONG *, ULONG_PTR *);
typedef LONG(NTAPI *LdrUnlockFn)(ULONG, ULONG_PTR);
static DWORD WINAPI hold_loader_lock(void *arg) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    LdrLockFn lock = (LdrLockFn)GetProcAddress(ntdll, "LdrLockLoaderLock");
    LdrUnlockFn unlock = (LdrUnlockFn)GetProcAddress(ntdll, "LdrUnlockLoaderLock");
    ULONG_PTR cookie = 0;
    if (!lock || !unlock || lock(0, NULL, &cookie) < 0) { error("LdrLockLoaderLock failed"); return 1; }
    printf("{\"kind\":\"locked\"}\n"); fflush(stdout);
    Sleep((DWORD)(ULONG_PTR)arg);
    unlock(0, cookie);
    printf("{\"kind\":\"unlocked\"}\n"); fflush(stdout);
    return 0;
}

static LONG WINAPI report_unhandled(EXCEPTION_POINTERS *ep) {
    char buf[256]; DWORD w = 0;
#if defined(_WIN64)
    unsigned long long ip = ep->ContextRecord->Rip;
#else
    unsigned long long ip = ep->ContextRecord->Eip;
#endif
    int n = _snprintf_s(buf, sizeof(buf), _TRUNCATE, "{\"kind\":\"unhandled\",\"code\":\"0x%08lx\",\"ip\":\"0x%llx\",\"tid\":%lu}\n",
                        (unsigned long)ep->ExceptionRecord->ExceptionCode, ip, GetCurrentThreadId());
    if (n > 0) WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, (DWORD)n, &w, NULL);
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char **argv) {
    int threads = 4, churn = 0, dll = 0, ms_only = 0;
    SetUnhandledExceptionFilter(report_unhandled);
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--churn")) churn = 1;
        else if (!strcmp(argv[i], "--dll")) dll = 1;
        else if (!strcmp(argv[i], "--ms-signed-only")) ms_only = 1;
        else if (!strcmp(argv[i], "--slow-every") && i + 1 < argc) g_slow_every = atol(argv[++i]);
        else if (!strcmp(argv[i], "--slow-ms") && i + 1 < argc) g_slow_ms = atol(argv[++i]);
        else { fprintf(stderr, "usage: lifecycle_target [--threads N] [--churn] [--dll] [--slow-every K] [--slow-ms M]\n"); return 2; }
    }
    if (threads < 1 || threads > 64) threads = 4;
    for (int i = 0; i < 64; ++i) g_pattern[i] = (unsigned char)(i * 7 + 3);
    GetModuleFileNameA(NULL, g_dir, sizeof(g_dir));
    { char *slash = strrchr(g_dir, '\\'); if (slash) slash[1] = 0; }
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    g_ntread = (NtReadFn)GetProcAddress(ntdll, "NtReadVirtualMemory");
    g_ntopen = (NtOpenFn)GetProcAddress(ntdll, "NtOpenProcess");
    g_ntclose = (NtCloseFn)GetProcAddress(ntdll, "NtClose");
    char path[MAX_PATH]; _snprintf_s(path, sizeof(path), _TRUNCATE, "%sconfigparse.dll", g_dir);
    HMODULE cp = LoadLibraryA(path);
    g_parse = cp ? (ParseFn)GetProcAddress(cp, "ParseConfig") : NULL;
    if (!g_ntread || !g_ntopen || !g_ntclose || !g_parse) { fprintf(stderr, "lifecycle_target: imports\n"); return 1; }
    g_site[0] = (unsigned char *)g_ntopen; g_site[1] = (unsigned char *)g_ntread; g_site[2] = (unsigned char *)g_ntclose;
    g_site[3] = (unsigned char *)g_parse; g_site[4] = (unsigned char *)lc_slow; g_site[5] = (unsigned char *)hunt_read;
    snapshot();
    if (ms_only) {
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig; memset(&sig, 0, sizeof(sig));
        sig.MicrosoftSignedOnly = 1;
        if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &sig, sizeof(sig))) {
            fprintf(stderr, "lifecycle_target: signature policy %lu\n", GetLastError()); return 1;
        }
    }

    HANDLE pool[70]; int n = 0;
    for (int i = 0; i < threads; ++i) pool[n++] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if (churn) pool[n++] = CreateThread(NULL, 0, churner, NULL, 0, NULL);
    if (dll) pool[n++] = CreateThread(NULL, 0, dll_churner, NULL, 0, NULL);
    printf("{\"kind\":\"ready\",\"pid\":%lu,\"threads\":%d,\"churn\":%d,\"dll\":%d}\n", GetCurrentProcessId(), threads, churn, dll);
    fflush(stdout);

    char line[64];
    while (fgets(line, sizeof(line), stdin)) {
        if (!strncmp(line, "check", 5)) check("check");
        else if (!strncmp(line, "reset", 5)) { InterlockedExchange(&g_flips, 0); printf("{\"kind\":\"reset\"}\n"); fflush(stdout); }
        else if (!strncmp(line, "lock ", 5)) {
            HANDLE t = CreateThread(NULL, 0, hold_loader_lock, (void *)(ULONG_PTR)atol(line + 5), 0, NULL);
            if (t) CloseHandle(t);
        }
        else if (!strncmp(line, "quit", 4)) break;
    }
    InterlockedExchange(&g_stop, 1);
    WaitForMultipleObjects(n, pool, TRUE, 60000);
    check("app");
    return g_errors ? 1 : 0;
}
