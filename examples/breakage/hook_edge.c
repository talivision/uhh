#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int __cdecl ShortSite(int value);
int __cdecl PrehookSite(int value);
extern const unsigned char PrehookOriginal[];
int __cdecl UnrelocFunction(int value);
int __cdecl StackSite(int value);

typedef int (__cdecl *edge_fn)(int);
static edge_fn foreign_original;
static volatile LONG foreign_calls;
static volatile LONG foreign_state;

int __cdecl ForeignReplacement(int value) {
    InterlockedIncrement(&foreign_calls);
    return foreign_original(value) + 1000;
}

static int install_foreign_hook(void) {
    unsigned char *site = (unsigned char *)(uintptr_t)&PrehookSite;
    unsigned char *trampoline;
    unsigned char patch[5] = {0xe9, 0, 0, 0, 0};
    intptr_t to_replacement = (intptr_t)(uintptr_t)&ForeignReplacement -
                              (intptr_t)(uintptr_t)(site + 5);
    DWORD old, ignored;
    int32_t rel;

    if (InterlockedCompareExchange(&foreign_state, 1, 0) != 0)
        return foreign_state == 2;
    if (to_replacement < INT32_MIN || to_replacement > INT32_MAX) {
        foreign_state = -1;
        return 0;
    }
    trampoline = (unsigned char *)VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE,
                                                PAGE_EXECUTE_READWRITE);
    if (!trampoline) {
        foreign_state = -1;
        return 0;
    }
    /* The pristine bytes live out of line because the mapped entry is already E9. */
    memcpy(trampoline, PrehookOriginal, 5);
#if defined(_WIN64)
    trampoline[5] = 0xff; trampoline[6] = 0x25;
    memset(trampoline + 7, 0, 4);
    *(uint64_t *)(void *)(trampoline + 11) = (uint64_t)(uintptr_t)(site + 5);
#else
    trampoline[5] = 0xe9;
    rel = (int32_t)((site + 5) - (trampoline + 10));
    memcpy(trampoline + 6, &rel, sizeof(rel));
#endif
    foreign_original = (edge_fn)(uintptr_t)trampoline;
    rel = (int32_t)to_replacement;
    memcpy(patch + 1, &rel, sizeof(rel));
    if (!VirtualProtect(site, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        foreign_original = NULL; foreign_state = -1;
        return 0;
    }
    if (site[0] == 0xcc) {
        /* A controller armed INT3 before TLS. Keep it armed; its saved byte is E9. */
        memcpy(site + 1, patch + 1, sizeof(patch) - 1);
    } else if (site[0] == 0xe9 && !memcmp(site, patch, sizeof(patch))) {
        /* Perform the startup write without replacing an inline detour installed first. */
        memcpy(site, patch, sizeof(patch));
    }
    FlushInstructionCache(GetCurrentProcess(), site, sizeof(patch));
    VirtualProtect(site, sizeof(patch), old, &ignored);
    InterlockedExchange(&foreign_state, 2);
    return 1;
}

/* A TLS callback runs during loader initialization, before the program's gate.
   This makes the E9 visible when the controller inspects the entry. */
static void NTAPI install_at_startup(PVOID module, DWORD reason, PVOID reserved) {
    (void)module; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) (void)install_foreign_hook();
}

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:breakage_tls_callback")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_breakage_tls_callback")
#endif
#pragma const_seg(".CRT$XLB")
const PIMAGE_TLS_CALLBACK breakage_tls_callback = install_at_startup;
#pragma const_seg()

static int wait_for_driver(void) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    char byte;
    DWORD got = 0;
    return input != INVALID_HANDLE_VALUE && ReadFile(input, &byte, 1, &got, NULL) && got == 1;
}

int main(int argc, char **argv) {
    const char *which;
    int value;
    if (argc != 3 || strcmp(argv[1], "--case") != 0) {
        fputs("usage: hook_edge --case short|prehook|unreloc|stack\n", stderr);
        return 2;
    }
    which = argv[2];
    if (foreign_state != 2 || !wait_for_driver()) return 3;
    if (!strcmp(which, "short")) return ShortSite(7) == 0 ? 0 : 4;
    if (!strcmp(which, "prehook")) {
        value = PrehookSite(7);
        return value == 1017 && foreign_calls == 1 ? 0 : 5;
    }
    if (!strcmp(which, "unreloc")) return UnrelocFunction(0) == 77 ? 0 : 6;
    if (!strcmp(which, "stack")) return StackSite(7) == 8 ? 0 : 7;
    return 2;
}
