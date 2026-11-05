// edgehunt target: runs every edge-case code shape K times and prints ONE JSON row of
// results. Run alone it is the uninstrumented baseline; under edge_driver the same row
// must come out unchanged on every backend (a probe never changes program results).
//   edge_target [--iters K]
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long long u64;
#define EXPORT __declspec(dllexport) __declspec(noinline)

// Register-width results (EAX on x86, RAX on x64).
uintptr_t EdgeRep(void *dst, const void *src);
uintptr_t EdgeStos(void *dst);
uintptr_t EdgeCpuid(void);
uintptr_t EdgeRdtsc(void);
uintptr_t EdgePushf(void);
uintptr_t EdgePopf(uintptr_t flags);
void EdgeRetOnly(void);
int EdgeThunk(void);
int EdgeJump(int idx);
int EdgeFaultMid(volatile int *p);
int EdgeX87(int n);
intptr_t EdgeLock(intptr_t v);
int EdgeDual(void);
int EdgeReaddA(void);
int EdgeReaddB(void);
void EdgeCodePad(void);
void EdgeRepSite(void);
#if defined(_WIN64)
u64 EdgeRipLoad(void);
int EdgeRipCmp(void);
int EdgeRipVec(void);
void EdgeRipStore(int v);
int EdgeRipStoreRead(void);
u64 EdgeSyscall(u64 service);
u64 EdgeInt2e(u64 service);
#endif

// Every C-level site writes a volatile sink so the compiler can neither drop nor hoist the
// calls (they would otherwise be pure functions with unused results).
static volatile intptr_t g_sink;

// ---- C-level sites: arguments, memory edge cases, log formatting, deep stacks ----------
EXPORT intptr_t edge_args10(intptr_t a0, intptr_t a1, intptr_t a2, intptr_t a3, intptr_t a4,
                            intptr_t a5, intptr_t a6, intptr_t a7, intptr_t a8, intptr_t a9) {
    g_sink = a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9;
    return g_sink;
}

// Addresses the memory callback probes (all filled by the target, read via get_func_arg(0)).
struct edge_mem {
    u64 guard;      // PAGE_READWRITE | PAGE_GUARD
    u64 ro;         // PAGE_READONLY, bytes 0x11
    u64 code;       // EdgeCodePad: PAGE_EXECUTE_READ, never executed
    u64 freed;      // decommitted (the reservation is kept, so nothing else can be mapped there)
    u64 cross;      // 8 bytes before a PAGE_NOACCESS page (RW page then no access)
    u64 rw;         // ordinary RW buffer
    u64 site;       // EdgeRepSite: code a probe sits on (F3 A4 originally)
};
EXPORT int edge_mem_site(struct edge_mem *m) { g_sink = (intptr_t)m->rw; return g_sink != 0; }

EXPORT int edge_fmt_site(const char *s) { g_sink = s[0]; return (int)g_sink; }

static volatile LONG g_leaf_calls;
EXPORT int edge_leaf(int depth) { InterlockedIncrement(&g_leaf_calls); g_sink = depth; return depth; }
EXPORT int edge_recurse(int n) {
    volatile int pad[4] = {n, n, n, n};
    if (n == 0) return edge_leaf(pad[0]);
    return edge_recurse(n - 1) + pad[1] - n;
}
static DWORD WINAPI leaf_thread(void *p) { (void)p; return (DWORD)edge_leaf(-1); }

static int fault_call(volatile int *p) {
    int r;
    __try { r = EdgeFaultMid(p); }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { r = -1; }
    return r;
}

#if defined(_WIN64)
// int 2e is not accepted for system calls on every Windows build: a fault means "not
// supported here" (the same in the baseline and under every backend), never a crash.
static int g_int2e_ok = 1;
static u64 try_int2e(u64 svc) {
    __try { return EdgeInt2e(svc); }
    __except (EXCEPTION_EXECUTE_HANDLER) { g_int2e_ok = 0; return 0; }
}
static u64 yield_service(void) {           // NtYieldExecution's service number from its stub
    const unsigned char *p = (const unsigned char *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtYieldExecution");
    if (p && p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) return *(const uint32_t *)(p + 4);
    return 0;
}
#endif

int main(int argc, char **argv) {
    int iters = 5, trace = 0;
    for (int i = 1; i < argc; ++i) if (!strcmp(argv[i], "--trace")) trace = 1;
#define T(x) do { if (trace) { fprintf(stderr, "T %d %d %s\n", k, __LINE__, x); fflush(stderr); } } while (0)
    for (int i = 1; i + 1 < argc; ++i) if (!strcmp(argv[i], "--iters")) iters = atoi(argv[++i]);
    SYSTEM_INFO si; GetSystemInfo(&si);
    const size_t page = si.dwPageSize;

    // memory fixtures
    struct edge_mem m = {0};
    unsigned char *g = (unsigned char *)VirtualAlloc(NULL, page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE | PAGE_GUARD);
    unsigned char *ro = (unsigned char *)VirtualAlloc(NULL, page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    unsigned char *fr = (unsigned char *)VirtualAlloc(NULL, page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    // (A RELEASED region can be handed out again before the probe reads it -- UHH's own
    // allocations in the target are an example -- so the test keeps it reserved.)
    unsigned char *two = (unsigned char *)VirtualAlloc(NULL, 2 * page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    static unsigned char rwbuf[64];
    DWORD old = 0;
    if (!g || !ro || !fr || !two) return 10;
    memset(ro, 0x11, page); VirtualProtect(ro, page, PAGE_READONLY, &old);
    VirtualFree(fr, page, MEM_DECOMMIT);
    memset(two, 0x22, page); VirtualProtect(two + page, page, PAGE_NOACCESS, &old);
    m.guard = (u64)(uintptr_t)g; m.ro = (u64)(uintptr_t)ro; m.code = (u64)(uintptr_t)EdgeCodePad;
    m.freed = (u64)(uintptr_t)fr; m.cross = (u64)(uintptr_t)(two + page - 8); m.rw = (u64)(uintptr_t)rwbuf;
    m.site = (u64)(uintptr_t)EdgeRepSite;

    u64 rep_sum = 0, stos_sum = 0, cpuid_ebx = 0, pushf_bad = 0, popf_x = 0, thunk_sum = 0, jump_sum = 0,
        x87_sum = 0, lock_sum = 0, dual_sum = 0, readd_sum = 0, args_sum = 0, retonly = 0, rdtsc_ok = 0;
    int fault_ok = 0, fault_caught = 0;
#if defined(_WIN64)
    u64 riprel_sum = 0, sys_bad = 0, int2e_bad = 0;
    const u64 svc = yield_service();
#endif
    for (int k = 0; k < iters; ++k) {
        unsigned char src[100], dst[128];
        for (int i = 0; i < 100; ++i) src[i] = (unsigned char)(i * 7 + k);
        memset(dst, 0, sizeof(dst));
        T("EdgeRep");
        u64 left = (u64)EdgeRep(dst, src);
        rep_sum += left + (memcmp(dst, src, 100) == 0 ? 1 : 1000) + dst[100];
        memset(dst, 0, sizeof(dst));
        T("EdgeStos");
        left = EdgeStos(dst);
        int stos_good = 1; for (int i = 0; i < 64; ++i) stos_good &= dst[i] == 0x3C;
        stos_sum += left + (stos_good ? 1 : 1000) + dst[64];
        T("EdgeCpuid");
        cpuid_ebx = EdgeCpuid();
        T("EdgeRdtsc");
        u64 t1 = EdgeRdtsc(), t2 = EdgeRdtsc(); rdtsc_ok += t2 >= t1 && t1;
        T("");
        pushf_bad += (EdgePushf() & 0x10100) != 0;
        T("");
        popf_x |= EdgePopf(0x202 | 0x1 | 0x80 | 0x800) & 0xFFF;
        T("EdgeRetOnly");
        EdgeRetOnly(); ++retonly;
        T("");
        thunk_sum += (u64)EdgeThunk();
        T("");
        jump_sum += (u64)EdgeJump(k % 3);
        volatile int good = 7;
        T("");
        fault_ok += fault_call(&good) == 7;
        T("");
        fault_caught += fault_call(NULL) == -1;
        T("");
        x87_sum += (u64)EdgeX87(k + 2);
        T("");
        lock_sum += (u64)EdgeLock(9);
        T("");
        dual_sum += (u64)EdgeDual();
        T("");
        readd_sum += (u64)EdgeReaddA(); readd_sum += (u64)EdgeReaddB();
        T("");
        args_sum += (u64)edge_args10(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
#if defined(_WIN64)
        T("");
        riprel_sum += (EdgeRipLoad() == 0x1122334455667788ull) + EdgeRipCmp() + (EdgeRipVec() == (int)0xA5A5A5A5);
        T("EdgeRipStore");
        EdgeRipStore(1000 + k); riprel_sum += EdgeRipStoreRead() == 1000 + k;
        if (svc) {
            T("EdgeSyscall");
            u64 r = EdgeSyscall(svc);  sys_bad += ((uint32_t)r != 0 && (uint32_t)r != 0x40000024u) || (r >> 32);
            T("EdgeInt2e");
            if (g_int2e_ok) r = try_int2e(svc); if (g_int2e_ok) int2e_bad += (uint32_t)r != 0 && (uint32_t)r != 0x40000024u;
        }
#endif
    }
    // memory edge cases (once), then check the target saw no side effect
    g_sink = edge_mem_site(&m);
    MEMORY_BASIC_INFORMATION mbi = {0};
    VirtualQuery(g, &mbi, sizeof(mbi));
    int guard_kept = (mbi.Protect & PAGE_GUARD) != 0;
    int code_kept = 1; for (int i = 0; i < 8; ++i) code_kept &= ((unsigned char *)EdgeCodePad)[i] == 0xCC;
    int cross_kept = 1; for (int i = 0; i < 8; ++i) cross_kept &= two[page - 8 + i] == 0x22;
    int ro_kept = ro[0] == 0x11;
    // log formatting edge cases (once)
    g_sink = edge_fmt_site("hello-from-target");
    // deep recursion and a thread whose first frame is the probed function
    g_leaf_calls = 0;
    g_sink = edge_recurse(200);
    HANDLE th = CreateThread(NULL, 0, leaf_thread, NULL, 0, NULL);
    if (th) { WaitForSingleObject(th, INFINITE); CloseHandle(th); }

    printf("{\"kind\":\"target\",\"iters\":%d,\"rep\":%llu,\"stos\":%llu,\"cpuid_ebx\":%llu,\"rdtsc_ok\":%llu,"
           "\"pushf_bad\":%llu,\"popf\":%llu,\"retonly\":%llu,\"thunk\":%llu,\"jump\":%llu,\"fault_ok\":%d,"
           "\"fault_caught\":%d,\"x87\":%llu,\"lock\":%llu,\"dual\":%llu,\"readd\":%llu,\"args\":%llu,"
           "\"guard_kept\":%d,\"code_kept\":%d,\"cross_kept\":%d,\"ro_kept\":%d,\"leaf_calls\":%ld"
#if defined(_WIN64)
           ",\"riprel\":%llu,\"sys_bad\":%llu,\"int2e_bad\":%llu,\"svc\":%llu,\"int2e_ok\":%d"
#endif
           "}\n",
           iters, rep_sum, stos_sum, cpuid_ebx, rdtsc_ok, pushf_bad, popf_x, retonly, thunk_sum, jump_sum, fault_ok,
           fault_caught, x87_sum, lock_sum, dual_sum, readd_sum, args_sum, guard_kept, code_kept, cross_kept, ro_kept,
           g_leaf_calls
#if defined(_WIN64)
           , riprel_sum, sys_bad, int2e_bad, svc, g_int2e_ok
#endif
    );
    fflush(stdout);
    return 0;
}
