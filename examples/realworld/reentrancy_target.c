#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct worker_context {
    DWORD worker_id;
    DWORD iterations;
    unsigned long long mallocs;
    unsigned long long frees;
    BOOL failed;
} worker_context;

DECLSPEC_ALIGN(8) static volatile LONG64 g_marker_calls = 0;
static volatile LONG g_marker_sink = 0;

__declspec(dllexport) __declspec(noinline) void __cdecl reent_marker(int i)
{
    LONG mixed = (LONG)(((unsigned int)i * 33U) ^ 0x5a5a5a5aU);
    (void)InterlockedIncrement64(&g_marker_calls);
    (void)InterlockedExchangeAdd(&g_marker_sink, mixed | 1L);
}

static DWORD WINAPI worker_main(void *parameter)
{
    static const SIZE_T allocation_sizes[4] = { 16U, 64U, 256U, 4096U };
    worker_context *context = (worker_context *)parameter;
    DWORD i;

    for (i = 0; i < context->iterations; ++i) {
        SIZE_T size = allocation_sizes[(i + context->worker_id) & 3U];
        unsigned char *memory = (unsigned char *)malloc(size);
        if (memory == NULL) {
            context->failed = TRUE;
            return 1U;
        }

        ++context->mallocs;
        memory[0] = (unsigned char)i;
        memory[size - 1U] = (unsigned char)(i >> 8);
        reent_marker((int)i);
        free(memory);
        ++context->frees;
    }

    return 0U;
}

static BOOL parse_dword(const char *text, DWORD minimum, DWORD maximum,
                        DWORD *result)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        value < (unsigned long)minimum || value > (unsigned long)maximum) {
        return FALSE;
    }
    *result = (DWORD)value;
    return TRUE;
}

static BOOL wait_for_release(BOOL no_wait)
{
    int byte_read;

    if (no_wait) {
        return TRUE;
    }
    (void)printf("{\"kind\":\"waiting\"}\n");
    (void)fflush(stdout);
    byte_read = getchar();
    if (byte_read == EOF) {
        (void)fprintf(stderr, "stdin closed before release\n");
        return FALSE;
    }
    return TRUE;
}

int main(int argc, char **argv)
{
    DWORD iterations = 10000U;
    DWORD thread_count = 4U;
    BOOL no_wait = FALSE;
    HANDLE *threads = NULL;
    worker_context *contexts = NULL;
    DWORD created = 0U;
    DWORD i;
    unsigned long long mallocs = 0U;
    unsigned long long frees = 0U;
    unsigned long long marker_calls;
    BOOL failed = FALSE;

    for (i = 1U; i < (DWORD)argc; ++i) {
        if (strcmp(argv[i], "--no-wait") == 0) {
            no_wait = TRUE;
        } else if (strcmp(argv[i], "--iters") == 0 && i + 1U < (DWORD)argc) {
            ++i;
            if (!parse_dword(argv[i], 1U, 10000000U, &iterations)) {
                (void)fprintf(stderr, "invalid --iters value\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1U < (DWORD)argc) {
            ++i;
            if (!parse_dword(argv[i], 1U, 4096U, &thread_count)) {
                (void)fprintf(stderr, "invalid --threads value\n");
                return 2;
            }
        } else {
            (void)fprintf(stderr, "unknown or incomplete argument: %s\n", argv[i]);
            return 2;
        }
    }

    if (!wait_for_release(no_wait)) {
        return 3;
    }

    threads = (HANDLE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                  (SIZE_T)thread_count * sizeof(*threads));
    contexts = (worker_context *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                           (SIZE_T)thread_count * sizeof(*contexts));
    if (threads == NULL || contexts == NULL) {
        (void)fprintf(stderr, "unable to allocate worker state\n");
        failed = TRUE;
        goto cleanup;
    }

    for (i = 0U; i < thread_count; ++i) {
        contexts[i].worker_id = i;
        contexts[i].iterations = iterations;
        threads[i] = CreateThread(NULL, 0U, worker_main, &contexts[i], 0U, NULL);
        if (threads[i] == NULL) {
            (void)fprintf(stderr, "CreateThread failed: %lu\n",
                          (unsigned long)GetLastError());
            failed = TRUE;
            break;
        }
        ++created;
    }

    for (i = 0U; i < created; ++i) {
        if (WaitForSingleObject(threads[i], INFINITE) != WAIT_OBJECT_0) {
            failed = TRUE;
        }
        (void)CloseHandle(threads[i]);
        threads[i] = NULL;
        mallocs += contexts[i].mallocs;
        frees += contexts[i].frees;
        if (contexts[i].failed) {
            failed = TRUE;
        }
    }

cleanup:
    if (threads != NULL) {
        for (i = 0U; i < created; ++i) {
            if (threads[i] != NULL) {
                (void)CloseHandle(threads[i]);
            }
        }
        (void)HeapFree(GetProcessHeap(), 0U, threads);
    }
    if (contexts != NULL) {
        (void)HeapFree(GetProcessHeap(), 0U, contexts);
    }

    marker_calls = (unsigned long long)InterlockedCompareExchange64(&g_marker_calls, 0, 0);
    if (failed || created != thread_count ||
        mallocs != (unsigned long long)iterations * thread_count ||
        frees != mallocs || marker_calls != mallocs) {
        (void)fprintf(stderr, "reentrancy workload did not complete\n");
        return 4;
    }

    (void)printf("{\"kind\":\"target\",\"name\":\"reentrancy\","
                 "\"iters\":%lu,\"threads\":%lu,\"mallocs\":%llu,"
                 "\"frees\":%llu,\"marker_calls\":%llu}\n",
                 (unsigned long)iterations, (unsigned long)thread_count,
                 mallocs, frees, marker_calls);
    (void)fflush(stdout);
    return 0;
}
