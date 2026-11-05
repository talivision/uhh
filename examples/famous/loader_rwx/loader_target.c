// loader_target [--threads T]
// Behaves like a (benign) unpacker: loads libraries at runtime and generates code.
//   main      LoadLibraryW("version.dll"), LoadLibraryExW("dbghelp.dll", SEARCH_SYSTEM32),
//             LoadLibraryW("uhh_no_such_module.dll") (fails)
//   worker k  (1) VirtualAlloc RWX of 0x13000 + k*0x1000 bytes, "unpack" (XOR-decode) a
//                 tiny function into it, call it;
//             (2) VirtualAlloc RW of 0x25000 + k*0x1000, write code, VirtualProtect it to
//                 PAGE_EXECUTE_READWRITE, call it, then VirtualProtect to PAGE_EXECUTE_READ
//                 (W^X done right: NOT an RWX signal), call again.
// The sizes are the fingerprints the regression test looks for. Ground truth on stdout.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile LONG g_jit_ok, g_errors;

typedef int(__cdecl *fn_t)(void);

// mov eax, imm32 ; ret -- valid on x86 and x64. XOR-"packed" with 0x5c.
static void unpack(unsigned char *dst, unsigned value) {
    unsigned char packed[6] = {0xB8 ^ 0x5c, 0, 0, 0, 0, 0xC3 ^ 0x5c};
    for (int i = 0; i < 4; ++i) packed[1 + i] = (unsigned char)((value >> (8 * i)) ^ 0x5c);
    for (int i = 0; i < 6; ++i) dst[i] = packed[i] ^ 0x5c;
}

static DWORD WINAPI worker(void *arg) {
    int k = (int)(INT_PTR)arg;
    SIZE_T rwx_size = 0x13000 + (SIZE_T)k * 0x1000, rw_size = 0x25000 + (SIZE_T)k * 0x1000;
    unsigned char *a = VirtualAlloc(NULL, rwx_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!a) { InterlockedIncrement(&g_errors); return 1; }
    unpack(a + 0x40, 0x1000u + (unsigned)k);
    FlushInstructionCache(GetCurrentProcess(), a, rwx_size);
    if (((fn_t)(a + 0x40))() == 0x1000 + k) InterlockedIncrement(&g_jit_ok); else InterlockedIncrement(&g_errors);
    VirtualFree(a, 0, MEM_RELEASE);

    unsigned char *b = VirtualAlloc(NULL, rw_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD old = 0;
    if (!b) { InterlockedIncrement(&g_errors); return 1; }
    unpack(b + 0x80, 0x2000u + (unsigned)k);
    if (!VirtualProtect(b, rw_size, PAGE_EXECUTE_READWRITE, &old)) InterlockedIncrement(&g_errors);
    FlushInstructionCache(GetCurrentProcess(), b, rw_size);
    if (((fn_t)(b + 0x80))() == 0x2000 + k) InterlockedIncrement(&g_jit_ok); else InterlockedIncrement(&g_errors);
    if (!VirtualProtect(b, rw_size, PAGE_EXECUTE_READ, &old)) InterlockedIncrement(&g_errors);
    if (((fn_t)(b + 0x80))() != 0x2000 + k) InterlockedIncrement(&g_errors);
    VirtualFree(b, 0, MEM_RELEASE);
    return 0;
}

int main(int argc, char **argv) {
    int threads = 4;
    for (int i = 1; i + 1 < argc; ++i)
        if (!strcmp(argv[i], "--threads")) threads = atoi(argv[++i]);
    if (threads < 1 || threads > 32) return 2;
    int loads_ok = 0, loads_failed = 0;
    HMODULE m = LoadLibraryW(L"version.dll");
    m ? ++loads_ok : ++loads_failed;
    m = LoadLibraryExW(L"dbghelp.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    m ? ++loads_ok : ++loads_failed;
    m = LoadLibraryW(L"uhh_no_such_module.dll");
    m ? ++loads_ok : ++loads_failed;

    HANDLE h[32];
    for (int k = 0; k < threads; ++k) h[k] = CreateThread(NULL, 0, worker, (void *)(INT_PTR)k, 0, NULL);
    WaitForMultipleObjects((DWORD)threads, h, TRUE, INFINITE);
    for (int k = 0; k < threads; ++k) CloseHandle(h[k]);
    printf("{\"kind\":\"app\",\"threads\":%d,\"jit_ok\":%ld,\"errors\":%ld,\"loads_ok\":%d,\"loads_failed\":%d}\n",
           threads, g_jit_ok, g_errors, loads_ok, loads_failed);
    fflush(stdout);
    return 0;
}
