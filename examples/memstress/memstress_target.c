#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MS_BUFFER_SIZE 65536u
#define MS_WINDOW_SIZE 256u
#define MS_MARKER_OFFSET 64u
#define MS_MARKER_SIZE 32u
#define MS_CROSS_SIZE 64u

/* MSVC x86 decorates C exports with a leading underscore.  The public probe
   location is deliberately architecture-independent: memstress_target.exe!ms_site. */
#if defined(_MSC_VER) && defined(_M_IX86)
#pragma comment(linker, "/EXPORT:ms_site=_ms_site")
#endif

typedef struct worker_state {
    uint32_t thread_index;
    uint32_t iterations;
    DWORD page_size;
    HANDLE start_event;
    HANDLE handle;
    uint8_t *buffer;
    uint8_t *shadow;
    uint8_t *cross_allocation;
    uint8_t *cross;
    uint8_t *noaccess;
    uint8_t *readonly_page;
    uint8_t *readonly_expected;
    uint64_t calls;
    uint64_t write_ok;
    uint64_t cross_ok;
    int untouched_ok;
    int readonly_intact;
} worker_state;

static volatile LONG g_site_barrier;

__declspec(dllexport) __declspec(noinline)
void ms_site(uint32_t thread, uint32_t iter, uint8_t *buffer, uint8_t *cross,
             uint8_t *noaccess, uint8_t *readonly_page) {
    (void)thread;
    (void)iter;
    (void)buffer;
    (void)cross;
    (void)noaccess;
    (void)readonly_page;
    (void)g_site_barrier;
}

static uint8_t value_f(uint32_t thread, uint32_t iter, uint32_t index) {
    return (uint8_t)(thread * 37u + iter * 17u + index * 13u +
                     ((iter >> 8) ^ (index * 3u)));
}

static uint8_t value_g(uint32_t thread, uint32_t iter, uint32_t index) {
    return (uint8_t)(value_f(thread, iter, index) ^ 0xa5u);
}

static uint8_t cross_value(uint32_t thread, uint32_t iter, uint32_t index) {
    return (uint8_t)(0x31u + thread * 29u + iter * 43u + index * 7u);
}

static uint8_t readonly_value(uint32_t thread, uint32_t index) {
    return (uint8_t)(0x69u + thread * 11u + index * 5u);
}

static int parse_u32(const char *text, uint32_t *value) {
    char *end = NULL;
    unsigned long long parsed;
    if (text == NULL || *text == '\0' || *text == '-') return 0;
    parsed = strtoull(text, &end, 10);
    if (*end != '\0' || parsed == 0 || parsed > UINT32_MAX) return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int wait_gate(void) {
    char byte;
    DWORD count = 0;
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    return input != INVALID_HANDLE_VALUE &&
           ReadFile(input, &byte, 1, &count, NULL) != 0 && count == 1;
}

static void release_worker(worker_state *state) {
    if (state->handle != NULL) CloseHandle(state->handle);
    if (state->buffer != NULL) VirtualFree(state->buffer, 0, MEM_RELEASE);
    free(state->shadow);
    if (state->cross_allocation != NULL) VirtualFree(state->cross_allocation, 0, MEM_RELEASE);
    if (state->noaccess != NULL) VirtualFree(state->noaccess, 0, MEM_RELEASE);
    if (state->readonly_page != NULL) VirtualFree(state->readonly_page, 0, MEM_RELEASE);
    free(state->readonly_expected);
}

static int initialize_worker(worker_state *state, uint32_t thread_index, uint32_t iterations,
                             DWORD page_size, HANDLE start_event) {
    DWORD old_protection = 0;
    size_t i;
    const SIZE_T two_pages = (SIZE_T)page_size * 2u;
    memset(state, 0, sizeof(*state));
    state->thread_index = thread_index;
    state->iterations = iterations;
    state->page_size = page_size;
    state->start_event = start_event;
    state->untouched_ok = 1;
    state->readonly_intact = 1;
    state->buffer = (uint8_t *)VirtualAlloc(NULL, MS_BUFFER_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    state->shadow = (uint8_t *)calloc(MS_BUFFER_SIZE, 1u);
    state->cross_allocation = (uint8_t *)VirtualAlloc(NULL, two_pages, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    state->noaccess = (uint8_t *)VirtualAlloc(NULL, page_size, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
    state->readonly_page = (uint8_t *)VirtualAlloc(NULL, page_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    state->readonly_expected = (uint8_t *)malloc(page_size);
    if (state->buffer == NULL || state->shadow == NULL || state->cross_allocation == NULL ||
        state->noaccess == NULL || state->readonly_page == NULL || state->readonly_expected == NULL) {
        return 0;
    }
    state->cross = state->cross_allocation + page_size - (MS_CROSS_SIZE / 2u);
    for (i = 0; i < page_size; ++i) {
        const uint8_t value = readonly_value(thread_index, (uint32_t)i);
        state->readonly_page[i] = value;
        state->readonly_expected[i] = value;
    }
    if (VirtualProtect(state->readonly_page, page_size, PAGE_READONLY, &old_protection) == 0) return 0;
    return 1;
}

static DWORD WINAPI worker_main(void *argument) {
    worker_state *state = (worker_state *)argument;
    uint32_t iter;
    (void)WaitForSingleObject(state->start_event, INFINITE);
    for (iter = 0; iter < state->iterations; ++iter) {
        const uint32_t offset = (iter * 61u) % (MS_BUFFER_SIZE - MS_WINDOW_SIZE);
        uint32_t i;
        int marker_ok = 1;
        int cross_ok = 1;

        for (i = 0; i < MS_WINDOW_SIZE; ++i) {
            const uint8_t value = value_f(state->thread_index, iter, i);
            state->buffer[offset + i] = value;
            state->shadow[offset + i] = value;
        }
        for (i = 0; i < MS_CROSS_SIZE; ++i) {
            state->cross[i] = cross_value(state->thread_index, iter, i);
        }

        ms_site(state->thread_index, iter, state->buffer, state->cross,
                state->noaccess, state->readonly_page);
        ++state->calls;

        for (i = 0; i < MS_MARKER_SIZE; ++i) {
            const uint8_t expected = value_g(state->thread_index, iter, i + MS_MARKER_OFFSET);
            if (state->buffer[offset + MS_MARKER_OFFSET + i] != expected) marker_ok = 0;
            state->shadow[offset + MS_MARKER_OFFSET + i] = expected;
        }
        if (marker_ok) ++state->write_ok;
        if (memcmp(state->buffer + offset, state->shadow + offset, MS_WINDOW_SIZE) != 0) {
            state->untouched_ok = 0;
        }

        for (i = 0; i < MS_CROSS_SIZE; ++i) {
            const uint8_t expected = (uint8_t)~cross_value(state->thread_index, iter, i);
            if (state->cross[i] != expected) cross_ok = 0;
        }
        if (cross_ok) ++state->cross_ok;

        if (((iter + 1u) & 1023u) == 0u &&
            memcmp(state->buffer, state->shadow, MS_BUFFER_SIZE) != 0) {
            state->untouched_ok = 0;
        }
    }
    if (memcmp(state->buffer, state->shadow, MS_BUFFER_SIZE) != 0) state->untouched_ok = 0;
    if (memcmp(state->readonly_page, state->readonly_expected, state->page_size) != 0) {
        state->readonly_intact = 0;
    }
    return 0;
}

static uint64_t elapsed_nanoseconds(LARGE_INTEGER start, LARGE_INTEGER end, LARGE_INTEGER frequency) {
    const uint64_t ticks = (uint64_t)(end.QuadPart - start.QuadPart);
    const uint64_t hz = (uint64_t)frequency.QuadPart;
    return (ticks / hz) * 1000000000ull + ((ticks % hz) * 1000000000ull) / hz;
}

int main(int argc, char **argv) {
    uint32_t thread_count = 8u;
    uint32_t iterations = 20000u;
    int no_wait = 0;
    int arg;
    SYSTEM_INFO system_info;
    HANDLE start_event = NULL;
    worker_state *workers = NULL;
    uint32_t initialized = 0;
    uint32_t created = 0;
    uint32_t i;
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    uint64_t calls = 0;
    uint64_t write_ok = 0;
    uint64_t cross_ok = 0;
    int untouched_ok = 1;
    int readonly_intact = 1;
    int exit_code = 0;

    for (arg = 1; arg < argc; ++arg) {
        if (strcmp(argv[arg], "--no-wait") == 0) {
            no_wait = 1;
        } else if (strcmp(argv[arg], "--threads") == 0 && arg + 1 < argc) {
            if (!parse_u32(argv[++arg], &thread_count)) {
                fprintf(stderr, "memstress_target: invalid --threads\n");
                return 2;
            }
        } else if (strcmp(argv[arg], "--iters") == 0 && arg + 1 < argc) {
            if (!parse_u32(argv[++arg], &iterations)) {
                fprintf(stderr, "memstress_target: invalid --iters\n");
                return 2;
            }
        } else {
            fprintf(stderr, "usage: memstress_target [--threads T] [--iters N] [--no-wait]\n");
            return 2;
        }
    }

    if (!no_wait) {
        printf("{\"kind\":\"waiting\"}\n");
        fflush(stdout);
        if (!wait_gate()) return 3;
    }

    GetSystemInfo(&system_info);
    if (system_info.dwPageSize < MS_CROSS_SIZE ||
        !QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) {
        fprintf(stderr, "memstress_target: unsupported system configuration\n");
        return 4;
    }
    workers = (worker_state *)calloc(thread_count, sizeof(*workers));
    start_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (workers == NULL || start_event == NULL) {
        fprintf(stderr, "memstress_target: setup allocation failed\n");
        exit_code = 4;
        goto cleanup;
    }
    for (i = 0; i < thread_count; ++i) {
        if (!initialize_worker(&workers[i], i, iterations, system_info.dwPageSize, start_event)) {
            fprintf(stderr, "memstress_target: worker allocation failed\n");
            exit_code = 4;
            initialized = i + 1u;
            goto cleanup;
        }
        ++initialized;
    }
    for (i = 0; i < thread_count; ++i) {
        workers[i].handle = CreateThread(NULL, 0, worker_main, &workers[i], 0, NULL);
        if (workers[i].handle == NULL) {
            fprintf(stderr, "memstress_target: thread creation failed\n");
            exit_code = 5;
            goto cleanup;
        }
        ++created;
    }

    (void)QueryPerformanceCounter(&start);
    (void)SetEvent(start_event);
    for (i = 0; i < created; ++i) (void)WaitForSingleObject(workers[i].handle, INFINITE);
    (void)QueryPerformanceCounter(&end);

    for (i = 0; i < thread_count; ++i) {
        calls += workers[i].calls;
        write_ok += workers[i].write_ok;
        cross_ok += workers[i].cross_ok;
        if (!workers[i].untouched_ok) untouched_ok = 0;
        if (!workers[i].readonly_intact) readonly_intact = 0;
    }
    printf("{\"kind\":\"target\",\"name\":\"memstress\",\"threads\":%u,\"iters\":%u,"
           "\"calls\":%llu,\"write_ok\":%llu,\"untouched_ok\":%s,\"cross_ok\":%llu,"
           "\"readonly_intact\":%s,\"elapsed_ns\":%llu}\n",
           thread_count, iterations, (unsigned long long)calls, (unsigned long long)write_ok,
           untouched_ok ? "true" : "false", (unsigned long long)cross_ok,
           readonly_intact ? "true" : "false",
           (unsigned long long)elapsed_nanoseconds(start, end, frequency));
    fflush(stdout);

cleanup:
    if (exit_code != 0 && created != 0) {
        (void)SetEvent(start_event);
        for (i = 0; i < created; ++i) (void)WaitForSingleObject(workers[i].handle, INFINITE);
    }
    for (i = 0; i < initialized; ++i) release_worker(&workers[i]);
    if (start_event != NULL) CloseHandle(start_event);
    free(workers);
    return exit_code;
}
