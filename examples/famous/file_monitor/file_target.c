// file_target <dir> [--threads T] [--chunks N] [--delay-ms D]
// A known file workload. Each of T threads writes <dir>\t<k>.dat in N WriteFile calls of
// (4096 + 100*k) bytes, closes it, reopens it and reads it back in N ReadFile calls of the
// same size, verifying the content. Main then writes <dir>\summary.txt through the CRT
// (fopen/fputs/fclose: one buffered write at close). The ground truth is printed as JSON:
// per file, the number of read/write calls and their byte totals.
// --delay-ms waits before any file activity (attach tests attach during the wait).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *g_dir;
static int g_chunks = 20;
static volatile LONG g_errors;

static DWORD WINAPI worker(void *arg) {
    int k = (int)(INT_PTR)arg;
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\t%d.dat", g_dir, k);
    DWORD chunk = 4096 + 100u * (DWORD)k, done = 0;
    unsigned char *buf = (unsigned char *)malloc(chunk), *back = (unsigned char *)malloc(chunk);
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { InterlockedIncrement(&g_errors); return 1; }
    for (int i = 0; i < g_chunks; ++i) {
        memset(buf, (k * 31 + i) & 0xff, chunk);
        if (!WriteFile(f, buf, chunk, &done, NULL) || done != chunk) InterlockedIncrement(&g_errors);
    }
    CloseHandle(f);
    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { InterlockedIncrement(&g_errors); return 1; }
    for (int i = 0; i < g_chunks; ++i) {
        memset(buf, (k * 31 + i) & 0xff, chunk);
        if (!ReadFile(f, back, chunk, &done, NULL) || done != chunk || memcmp(buf, back, chunk))
            InterlockedIncrement(&g_errors);
    }
    CloseHandle(f);
    free(buf); free(back);
    return 0;
}

int main(int argc, char **argv) {
    int threads = 3, delay = 0;
    if (argc < 2) { fprintf(stderr, "usage: file_target <dir> [--threads T] [--chunks N] [--delay-ms D]\n"); return 2; }
    g_dir = argv[1];
    for (int i = 2; i + 1 < argc; ++i) {
        if (!strcmp(argv[i], "--threads")) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--chunks")) g_chunks = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--delay-ms")) delay = atoi(argv[++i]);
    }
    if (threads < 1 || threads > 32 || g_chunks < 1) return 2;
    if (delay) Sleep((DWORD)delay);
    CreateDirectoryA(g_dir, NULL);
    HANDLE h[32];
    for (int k = 0; k < threads; ++k) h[k] = CreateThread(NULL, 0, worker, (void *)(INT_PTR)k, 0, NULL);
    WaitForMultipleObjects((DWORD)threads, h, TRUE, INFINITE);
    for (int k = 0; k < threads; ++k) CloseHandle(h[k]);

    char summary[MAX_PATH], text[128];
    snprintf(summary, sizeof(summary), "%s\\summary.txt", g_dir);
    int len = snprintf(text, sizeof(text), "threads=%d chunks=%d errors=%ld\n", threads, g_chunks, g_errors);
    FILE *s = fopen(summary, "wb");
    if (!s || fputs(text, s) < 0 || fclose(s)) InterlockedIncrement(&g_errors);

    printf("{\"kind\":\"app\",\"errors\":%ld,\"files\":[", g_errors);
    for (int k = 0; k < threads; ++k) {
        long bytes = (long)(4096 + 100 * k) * g_chunks;
        printf("%s{\"name\":\"t%d.dat\",\"writes\":%d,\"written\":%ld,\"reads\":%d,\"read\":%ld}",
               k ? "," : "", k, g_chunks, bytes, g_chunks, bytes);
    }
    printf(",{\"name\":\"summary.txt\",\"writes\":1,\"written\":%d,\"reads\":0,\"read\":0}]}\n", len);
    fflush(stdout);
    return 0;
}
