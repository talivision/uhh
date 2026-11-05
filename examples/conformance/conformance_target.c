// Conformance target: a function with six known arguments, a buffer it hands to the
// probe, and functions the probe calls or probes at runtime. After each call it checks
// the effects the callback is required to have had, and prints them.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

__declspec(align(16)) static volatile uint8_t g_buf[64];
static volatile long g_later_calls, g_watch_value;

// The probed site. Its return value depends on a0, which the callback rewrites.
// Pointer-sized arguments: the API's portable argument model (one slot per argument on
// both x64 and x86).
__declspec(dllexport) __declspec(noinline) intptr_t conf_site(intptr_t a0, intptr_t a1, intptr_t a2,
                                                              intptr_t a3, intptr_t a4, uint8_t *buf) {
    return a0 * 1000 + a1 + a2 + a3 + a4 + buf[0];
}
// Called by the callback via call_func.
__declspec(dllexport) __declspec(noinline) intptr_t conf_mul(intptr_t a, intptr_t b) { return a * b; }
// Probed only at runtime (added from inside the callback).
__declspec(dllexport) __declspec(noinline) void conf_later(int i) { g_later_calls += i ? 1 : 1; }
intptr_t SpSite(void);

/* call_original / return_from (conformance_driver --callorig). g_co_body counts how often a
   body really ran: once with call_original + return_from, never with a pure return_from. */
static volatile long g_co_body;
__declspec(dllexport) __declspec(noinline) intptr_t co_args6(intptr_t a0, intptr_t a1, intptr_t a2,
                                                             intptr_t a3, intptr_t a4, intptr_t a5) {
    g_co_body++;
    return a0 * 100000 + a1 * 10000 + a2 * 1000 + a3 * 100 + a4 * 10 + a5;
}
__declspec(dllexport) __declspec(noinline) intptr_t __stdcall co_std2(intptr_t a, intptr_t b) {
    g_co_body++;
    return a * 31 + b;
}
__declspec(dllexport) __declspec(noinline) intptr_t __cdecl co_cdecl2(intptr_t a, intptr_t b) {
    g_co_body++;
    return a * b + 1;
}
#if !defined(_WIN64)
#pragma comment(linker, "/EXPORT:co_std2=_co_std2@8")
#endif
static int callorig_main(void) {
    int args6 = 0, std2 = 0, std2_sp = 0, cdecl2 = 0, body_ok = 0;
    for (int k = 0; k < 10; ++k) {
        /* callback: a0 1 -> 7 and a5 6 -> 9 (a stack arg on both arches), call_original, then
           return_from(r + 1). Expect 7,2,3,4,5,9 -> 723459 + 1, body ran exactly once. */
        g_co_body = 0;
        intptr_t r = co_args6(1, 2, 3, 4, 5, 6);
        if (r == 723460) ++args6;
        int once = g_co_body == 1;
        /* pure replacement: return_from(99, 2) -- body never runs; x86 stdcall pops 8 bytes. */
        g_co_body = 0;
#if !defined(_WIN64)
        uintptr_t sp_before, sp_after;
        __asm mov sp_before, esp
        r = co_std2(3, 4);
        __asm mov sp_after, esp
        if (sp_before == sp_after) ++std2_sp;
#else
        r = co_std2(3, 4); ++std2_sp;
#endif
        if (r == 99) ++std2;
        int none = g_co_body == 0;
        /* cdecl: call_original (5*6+1 = 31) then return_from(r * 2, 0) -> 62, body once. */
        g_co_body = 0;
        r = co_cdecl2(5, 6);
        if (r == 62) ++cdecl2;
        if (once && none && g_co_body == 1) ++body_ok;
    }
    printf("{\"kind\":\"callorig\",\"args6\":%d,\"std2\":%d,\"std2_sp\":%d,\"cdecl2\":%d,\"body_ok\":%d}\n",
           args6, std2, std2_sp, cdecl2, body_ok);
    fflush(stdout);
    return 0;
}   /* asm: returns how far SP moved across the probe at SpSite+3 */


/* ---- Portability matrix (conformance_target --matrix; conformance_driver --matrix) ----------
   One run per backend; every callback logs "M key=value" lines that must be IDENTICAL on every
   backend (scripts/regress.py diffs them), "D ..." lines whose difference is documented. This
   side prepares memory of every kind, runs each probed site and afterwards checks the effects
   the callbacks may or may not have had; a vectored handler records every exception the
   PROGRAM could observe (stage:code). Layout shared with matrix_callbacks.cpp (pm_env). */
typedef struct pm_env {
    uint64_t rw, ro, guard, xo, reserved, pid, mul, hit, other, entry;
    uint64_t out[16];          /* +80: registers after PmRegHit (probe_register order) */
    uint64_t cf;               /* +208: carry flag after PmRegHit */
} pm_env;
void PmRegSite(pm_env *env);
intptr_t PmOther(intptr_t x);
extern char PmRegHit[];
static volatile long g_pm_sink, g_pm_stage, g_pm_veh_n;
static volatile long g_pm_veh_stage[16];
static volatile DWORD g_pm_veh_code[16];
static LONG CALLBACK pm_veh(EXCEPTION_POINTERS *e) {
    long i = InterlockedIncrement(&g_pm_veh_n) - 1;
    if (i < 16) { g_pm_veh_stage[i] = g_pm_stage; g_pm_veh_code[i] = e->ExceptionRecord->ExceptionCode; }
    return EXCEPTION_CONTINUE_SEARCH;
}
__declspec(dllexport) __declspec(noinline) intptr_t pm_entry(pm_env *env, intptr_t a1, intptr_t a2, intptr_t a3,
                                                             intptr_t a4, intptr_t a5) {
    g_pm_sink += (long)(a1 + a2 + a3 + a4 + a5);
    return (intptr_t)env->pid + g_pm_sink;
}
__declspec(dllexport) __declspec(noinline) intptr_t pm_fault_site(pm_env *env, intptr_t v) {
    g_pm_sink += (long)v;
    return v * 2 + (env ? 0 : 1);
}
__declspec(dllexport) __declspec(noinline) intptr_t pm_throw_site(pm_env *env, intptr_t v) {
    g_pm_sink += (long)v;
    return v * 2 + (env ? 0 : 1);
}
__declspec(dllexport) __declspec(noinline) intptr_t pm_conc(intptr_t i) {
    g_pm_sink += (long)i;
    return g_pm_sink;
}
__declspec(dllexport) __declspec(noinline) intptr_t pm_report(pm_env *env) {
    g_pm_sink += 1;
    return env ? g_pm_sink : 0;
}
__declspec(dllexport) __declspec(noinline) intptr_t pm_bigcfg(pm_env *env) {
    g_pm_sink += 2;
    return env ? g_pm_sink : 0;
}
/* Probed only at runtime, from a callback (never called). */
__declspec(dllexport) __declspec(noinline) intptr_t pm_dummy(intptr_t v) { g_pm_sink += (long)v; return g_pm_sink; }
__declspec(dllexport) __declspec(noinline) intptr_t pm_dummy2(intptr_t v) { g_pm_sink += (long)v * 3; return g_pm_sink; }
__declspec(dllexport) __declspec(noinline) intptr_t pm_dummy3(intptr_t v) { g_pm_sink += (long)v * 5; return g_pm_sink; }
__declspec(dllexport) __declspec(noinline) intptr_t pm_dummy4(intptr_t v) { g_pm_sink += (long)v * 7; return g_pm_sink; }

static DWORD WINAPI pm_conc_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < 50; ++i) pm_conc(i);
    return 0;
}
static int matrix_main(void) {
    AddVectoredExceptionHandler(1, pm_veh);
    pm_env env; memset(&env, 0, sizeof(env));
    uint8_t *rw = (uint8_t *)VirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    uint8_t *ro = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    uint8_t *guard = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    uint8_t *xo = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    uint8_t *reserved = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_RESERVE, PAGE_READWRITE);
    if (!rw || !ro || !guard || !xo || !reserved) return 4;
    DWORD old = 0;
    for (int i = 0; i < 4096; ++i) { rw[i] = (uint8_t)i; ro[i] = (uint8_t)(i ^ 0x5A); guard[i] = 1; xo[i] = 0xC3; }
    if (!VirtualProtect(rw + 4096, 4096, PAGE_NOACCESS, &old) || !VirtualProtect(ro, 4096, PAGE_READONLY, &old) ||
        !VirtualProtect(guard, 4096, PAGE_READWRITE | PAGE_GUARD, &old) || !VirtualProtect(xo, 4096, PAGE_EXECUTE, &old))
        return 5;
    env.rw = (uintptr_t)rw; env.ro = (uintptr_t)ro; env.guard = (uintptr_t)guard; env.xo = (uintptr_t)xo;
    env.reserved = (uintptr_t)reserved; env.pid = GetCurrentProcessId(); env.mul = (uintptr_t)conf_mul;
    env.hit = (uintptr_t)PmRegHit; env.other = (uintptr_t)PmOther; env.entry = (uintptr_t)pm_entry;
    g_pm_stage = 1; intptr_t entry_r = pm_entry(&env, 11, 22, 33, 44, 55);
    g_pm_stage = 2; PmRegSite(&env);
    g_pm_stage = 3; intptr_t other_r = PmOther(5);
    g_pm_stage = 4; intptr_t fault_r = pm_fault_site(&env, 5);
    g_pm_stage = 5;
    HANDLE th[4];
    for (int i = 0; i < 4; ++i) th[i] = CreateThread(NULL, 0, pm_conc_thread, NULL, 0, NULL);
    for (int i = 0; i < 10; ++i) pm_conc(i);
    for (int i = 0; i < 4; ++i) if (th[i]) { WaitForSingleObject(th[i], INFINITE); CloseHandle(th[i]); }
    g_pm_stage = 6; intptr_t throw_r = pm_throw_site(&env, 5);
    g_pm_stage = 7; pm_report(&env);
    g_pm_stage = 8; pm_bigcfg(&env);
    g_pm_stage = 9;
    MEMORY_BASIC_INFORMATION mbi; memset(&mbi, 0, sizeof(mbi));
    int guard_intact = VirtualQuery(guard, &mbi, sizeof(mbi)) && (mbi.Protect & PAGE_GUARD);
    int ro_intact = 1, partial_intact = 1, head_intact = 1;
    for (int i = 0; i < 4096; ++i) if (ro[i] != (uint8_t)(i ^ 0x5A)) ro_intact = 0;
    for (int i = 4092; i < 4096; ++i) if (rw[i] != (uint8_t)i) partial_intact = 0;
    for (int i = 0; i < 4; ++i) if (rw[i] != (uint8_t)i) head_intact = 0;
    uint32_t w_rw = 0, fault_mark = 0, throw_mark = 0;
    memcpy(&w_rw, rw + 64, 4); memcpy(&fault_mark, rw + 256, 4); memcpy(&throw_mark, rw + 260, 4);
    printf("{\"kind\":\"matrix\",\"entry_r\":%d,\"other_r\":%d,\"fault_r\":%d,\"throw_r\":%d,\"guard_intact\":%d,"
           "\"ro_intact\":%d,\"partial_intact\":%d,\"head_intact\":%d,\"w_rw\":\"%08x\",\"fault_mark\":\"%08x\","
           "\"throw_mark\":\"%08x\",\"cf\":%d,\"out\":[",
           (int)(entry_r - (intptr_t)env.pid), (int)other_r, (int)fault_r, (int)throw_r, guard_intact,
           ro_intact, partial_intact, head_intact, w_rw, fault_mark, throw_mark, (int)(env.cf & 0xFF));
    for (int i = 0; i < 16; ++i) printf("%s\"%llx\"", i ? "," : "", (unsigned long long)env.out[i]);
    printf("],\"veh\":[");
    long n = g_pm_veh_n < 16 ? g_pm_veh_n : 16;
    for (long i = 0; i < n; ++i) printf("%s\"%ld:%08lx\"", i ? "," : "", g_pm_veh_stage[i], (unsigned long)g_pm_veh_code[i]);
    printf("],\"veh_n\":%ld}\n", g_pm_veh_n);
    fflush(stdout);
    return 0;
}

static int wait_gate(void) {
    char b; DWORD n = 0; HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    return in != INVALID_HANDLE_VALUE && ReadFile(in, &b, 1, &n, NULL) && n == 1;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--callorig")) return callorig_main();
    if (argc > 1 && !strcmp(argv[1], "--matrix")) return matrix_main();
    int no_wait = argc > 1 && !strcmp(argv[1], "--no-wait");
    printf("{\"kind\":\"waiting\"}\n"); fflush(stdout);
    if (!no_wait && !wait_gate()) return 3;
    for (int i = 0; i < 64; ++i) g_buf[i] = (uint8_t)(i + 1);
    const int calls = 10;
    int arg_rewritten = 0, mem_written = 0;
    for (int k = 0; k < calls; ++k) {
        g_buf[8] = 0;
        intptr_t r = conf_site(1, 2, 3, 4, 5, (uint8_t *)g_buf);
        // set_reg/set_mem must have rewritten a0 from 1 to 7: 7000 + 2+3+4+5 + buf[0]
        if (r == 7000 + 14 + g_buf[0]) ++arg_rewritten;
        if (g_buf[8] == 0xA5) ++mem_written;                // set_mem marker
    }
    // No wait: the callback that added conf_later's inline probe held this thread until it landed.
    for (int i = 0; i < 20; ++i) conf_later(i);
    int sp_moved = 0;
    for (int i = 0; i < 10; ++i) if (SpSite() == 32) ++sp_moved;
    g_watch_value = 1; g_watch_value = 2; g_watch_value = 3; // three stores to the watched address
    printf("{\"kind\":\"target\",\"sp_moved\":%d,\"calls\":%d,\"arg_rewritten\":%d,\"mem_written\":%d,\"later_calls\":%ld}\n", sp_moved,
           calls, arg_rewritten, mem_written, g_later_calls);
    fflush(stdout);
    return 0;
}

// Exposed so the callback can find the watched global by symbol.
__declspec(dllexport) volatile long *conf_watch_addr(void) { return &g_watch_value; }
