#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct stress_thread_context {
    HANDLE start_event;
    DWORD calls;
    int tag;
} stress_thread_context;

typedef struct pool_context {
    HANDLE done_event;
    volatile LONG remaining;
} pool_context;

DECLSPEC_ALIGN(8) static volatile LONG64 g_total_calls = 0;
static volatile LONG g_stress_sink = 0;

__declspec(dllexport) __declspec(noinline) void __cdecl stress_work(int tag)
{
    LONG value = (LONG)(((unsigned int)tag * 16777619U) ^ 0x45d9f3bU);
    (void)InterlockedIncrement64(&g_total_calls);
    (void)InterlockedExchangeAdd(&g_stress_sink, value | 1L);
}

static LONG64 read_total_calls(void)
{
    return InterlockedCompareExchange64(&g_total_calls, 0, 0);
}

static DWORD WINAPI stress_thread_main(void *parameter)
{
    stress_thread_context *context = (stress_thread_context *)parameter;
    DWORD i;

    if (context->start_event != NULL &&
        WaitForSingleObject(context->start_event, INFINITE) != WAIT_OBJECT_0) {
        return 1U;
    }
    for (i = 0U; i < context->calls; ++i) {
        stress_work(context->tag + (int)(i & 7U));
    }
    return 0U;
}

static VOID CALLBACK pool_callback(PTP_CALLBACK_INSTANCE instance, void *parameter)
{
    pool_context *context = (pool_context *)parameter;
    UNREFERENCED_PARAMETER(instance);

    stress_work(0x300);
    if (InterlockedDecrement(&context->remaining) == 0) {
        (void)SetEvent(context->done_event);
    }
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
    if (no_wait) {
        return TRUE;
    }
    (void)printf("{\"kind\":\"waiting\"}\n");
    (void)fflush(stdout);
    if (getchar() == EOF) {
        (void)fprintf(stderr, "stdin closed before release\n");
        return FALSE;
    }
    return TRUE;
}

static BOOL join_threads(HANDLE *threads, DWORD count)
{
    DWORD i;
    BOOL ok = TRUE;

    for (i = 0U; i < count; ++i) {
        DWORD exit_code = 1U;
        if (WaitForSingleObject(threads[i], INFINITE) != WAIT_OBJECT_0 ||
            !GetExitCodeThread(threads[i], &exit_code) || exit_code != 0U) {
            ok = FALSE;
        }
        (void)CloseHandle(threads[i]);
        threads[i] = NULL;
    }
    return ok;
}

static BOOL run_phase_a(DWORD many, DWORD calls)
{
    HANDLE gate = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE *threads = NULL;
    stress_thread_context *contexts = NULL;
    DWORD created = 0U;
    DWORD i;
    BOOL ok = TRUE;

    if (gate == NULL) {
        return FALSE;
    }
    threads = (HANDLE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                  (SIZE_T)many * sizeof(*threads));
    contexts = (stress_thread_context *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                  (SIZE_T)many * sizeof(*contexts));
    if (threads == NULL || contexts == NULL) {
        ok = FALSE;
        goto cleanup;
    }

    for (i = 0U; i < many; ++i) {
        contexts[i].start_event = gate;
        contexts[i].calls = calls;
        contexts[i].tag = (int)i;
        threads[i] = CreateThread(NULL, 0U, stress_thread_main, &contexts[i], 0U, NULL);
        if (threads[i] == NULL) {
            ok = FALSE;
            break;
        }
        ++created;
    }
    if (!SetEvent(gate)) {
        ok = FALSE;
    }
    if (!join_threads(threads, created)) {
        ok = FALSE;
    }
    if (created != many) {
        ok = FALSE;
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
    (void)CloseHandle(gate);
    return ok;
}

static BOOL run_phase_b(DWORD calls)
{
    enum { suspended_count = 32 };
    HANDLE threads[suspended_count] = { 0 };
    stress_thread_context contexts[suspended_count];
    DWORD created = 0U;
    DWORD i;
    BOOL ok = TRUE;

    ZeroMemory(contexts, sizeof(contexts));
    for (i = 0U; i < (DWORD)suspended_count; ++i) {
        contexts[i].calls = calls;
        contexts[i].tag = 0x100 + (int)i;
        threads[i] = CreateThread(NULL, 0U, stress_thread_main, &contexts[i],
                                  CREATE_SUSPENDED, NULL);
        if (threads[i] == NULL) {
            ok = FALSE;
            break;
        }
        ++created;
    }
    for (i = 0U; i < created; ++i) {
        if (ResumeThread(threads[i]) == (DWORD)-1) {
            ok = FALSE;
        }
    }
    if (!join_threads(threads, created)) {
        ok = FALSE;
    }
    if (created != (DWORD)suspended_count) {
        ok = FALSE;
    }
    return ok;
}

static BOOL run_phase_c(void)
{
    enum { work_item_count = 256 };
    pool_context context;
    DWORD i;
    BOOL submitted_all = TRUE;

    context.done_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    context.remaining = work_item_count;
    if (context.done_event == NULL) {
        return FALSE;
    }

    for (i = 0U; i < (DWORD)work_item_count; ++i) {
        if (!TrySubmitThreadpoolCallback(pool_callback, &context, NULL)) {
            submitted_all = FALSE;
            if (InterlockedDecrement(&context.remaining) == 0) {
                (void)SetEvent(context.done_event);
            }
        }
    }
    if (WaitForSingleObject(context.done_event, INFINITE) != WAIT_OBJECT_0) {
        submitted_all = FALSE;
    }
    (void)CloseHandle(context.done_event);
    return submitted_all;
}

static BOOL run_phase_d(void)
{
    enum { churn_count = 200 };
    stress_thread_context context;
    DWORD i;

    ZeroMemory(&context, sizeof(context));
    context.calls = 1U;
    for (i = 0U; i < churn_count; ++i) {
        HANDLE thread;
        context.tag = 0x400 + (int)i;
        thread = CreateThread(NULL, 0U, stress_thread_main, &context, 0U, NULL);
        if (thread == NULL) {
            return FALSE;
        }
        if (!join_threads(&thread, 1U)) {
            return FALSE;
        }
    }
    return TRUE;
}

int main(int argc, char **argv)
{
    DWORD many = 128U;
    DWORD calls = 50U;
    BOOL no_wait = FALSE;
    DWORD i;
    LONG64 before;
    unsigned long long phase_a;
    unsigned long long phase_b;
    unsigned long long phase_c;
    unsigned long long phase_d;
    unsigned long long total;

    for (i = 1U; i < (DWORD)argc; ++i) {
        if (strcmp(argv[i], "--no-wait") == 0) {
            no_wait = TRUE;
        } else if (strcmp(argv[i], "--many") == 0 && i + 1U < (DWORD)argc) {
            ++i;
            if (!parse_dword(argv[i], 1U, 4096U, &many)) {
                (void)fprintf(stderr, "invalid --many value\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--calls") == 0 && i + 1U < (DWORD)argc) {
            ++i;
            if (!parse_dword(argv[i], 1U, 1000000U, &calls)) {
                (void)fprintf(stderr, "invalid --calls value\n");
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

    before = read_total_calls();
    if (!run_phase_a(many, calls)) {
        (void)fprintf(stderr, "phase A failed\n");
        return 4;
    }
    phase_a = (unsigned long long)(read_total_calls() - before);

    before = read_total_calls();
    if (!run_phase_b(calls)) {
        (void)fprintf(stderr, "phase B failed\n");
        return 5;
    }
    phase_b = (unsigned long long)(read_total_calls() - before);

    before = read_total_calls();
    if (!run_phase_c()) {
        (void)fprintf(stderr, "phase C failed\n");
        return 6;
    }
    phase_c = (unsigned long long)(read_total_calls() - before);

    before = read_total_calls();
    if (!run_phase_d()) {
        (void)fprintf(stderr, "phase D failed\n");
        return 7;
    }
    phase_d = (unsigned long long)(read_total_calls() - before);
    total = (unsigned long long)read_total_calls();

    if (phase_a != (unsigned long long)many * calls ||
        phase_b != 32ULL * calls || phase_c != 256ULL || phase_d != 200ULL ||
        total != phase_a + phase_b + phase_c + phase_d) {
        (void)fprintf(stderr, "stress call counts were inconsistent\n");
        return 8;
    }

    (void)printf("{\"kind\":\"target\",\"name\":\"thread_stress\","
                 "\"phase_a\":%llu,\"phase_b\":%llu,\"phase_c\":%llu,"
                 "\"phase_d\":%llu,\"total_calls\":%llu}\n",
                 phase_a, phase_b, phase_c, phase_d, total);
    (void)fflush(stdout);
    return 0;
}
