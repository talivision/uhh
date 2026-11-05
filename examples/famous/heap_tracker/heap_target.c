// heap_target [--threads T] [--iters N]
// A small multi-threaded program with a KNOWN leak pattern. All of its own heap traffic
// goes through xalloc/xfree (HeapAlloc/HeapFree on the process heap -- HeapAlloc is a
// forward to ntdll!RtlAllocateHeap). Every 250th iteration (i % 250 == 7) of every worker
// forgets to free one block, and main leaks one 4096-byte "config" block. The program
// prints its own ground truth as one JSON line.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HANDLE g_heap;
static volatile LONG g_allocs, g_frees, g_leaks;
static volatile LONG64 g_leaked_bytes, g_checksum;
static int g_iters = 2000;

__declspec(noinline) static void *xalloc(size_t n) {
    void *p = HeapAlloc(g_heap, 0, n);
    if (!p) ExitProcess(3);
    InterlockedIncrement(&g_allocs);   // also keeps the HeapAlloc call from becoming a tail call
    return p;
}

__declspec(noinline) static void xfree(void *p) {
    if (!HeapFree(g_heap, 0, p)) ExitProcess(4);
    InterlockedIncrement(&g_frees);
}

static void leak(size_t n) {
    InterlockedIncrement(&g_leaks);
    InterlockedAdd64(&g_leaked_bytes, (LONG64)n);
}

static DWORD WINAPI worker(void *arg) {
    int k = (int)(INT_PTR)arg;
    void *keep[8] = {0};               // a few long-lived blocks, recycled round-robin
    LONG64 sum = 0;
    for (int i = 0; i < g_iters; ++i) {
        size_t a = 16 + (size_t)((i * 7 + k) % 97), b = 32 + (size_t)((i * 13 + k) % 211), d = 24 + (size_t)(i % 61);
        unsigned char *pa = xalloc(a), *pb = xalloc(b), *pd = xalloc(d);
        memset(pa, (int)(i & 0xff), a); memset(pb, k, b); memset(pd, 0x5a, d);
        sum += pa[a - 1] + pb[b - 1] + pd[0];
        void **slot = &keep[i % 8];
        if (*slot) xfree(*slot);
        *slot = xalloc(64 + (size_t)(i % 31));
        xfree(pd);
        xfree(pa);
        if (i % 250 == 7) leak(b); else xfree(pb);   // the leak: pb forgotten
    }
    for (int i = 0; i < 8; ++i) if (keep[i]) xfree(keep[i]);
    InterlockedAdd64(&g_checksum, sum);
    return 0;
}

int main(int argc, char **argv) {
    int threads = 4;
    for (int i = 1; i + 1 < argc; ++i) {
        if (!strcmp(argv[i], "--threads")) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--iters")) g_iters = atoi(argv[++i]);
    }
    if (threads < 1 || threads > 64 || g_iters < 1) return 2;
    g_heap = GetProcessHeap();
    char *config = xalloc(4096);       // leaked on purpose
    strcpy(config, "mode=leaky");
    leak(4096);
    HANDLE h[64];
    for (int k = 0; k < threads; ++k) h[k] = CreateThread(NULL, 0, worker, (void *)(INT_PTR)k, 0, NULL);
    WaitForMultipleObjects((DWORD)threads, h, TRUE, INFINITE);
    for (int k = 0; k < threads; ++k) CloseHandle(h[k]);
    printf("{\"kind\":\"app\",\"allocs\":%ld,\"frees\":%ld,\"leaks\":%ld,\"leaked_bytes\":%lld,\"checksum\":%lld}\n",
           g_allocs, g_frees, g_leaks, g_leaked_bytes, g_checksum);
    fflush(stdout);
    return 0;
}
