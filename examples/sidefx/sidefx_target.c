#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN64)
#define SIDEFX_GPR_COUNT 14u
#define SIDEFX_VECTOR_COUNT 16u
#else
#define SIDEFX_GPR_COUNT 6u
#define SIDEFX_VECTOR_COUNT 8u
#endif

#define SIDEFX_BELOW_SIZE 512u
#define SIDEFX_MXCSR 0x00007f80u
#define SIDEFX_X87CW 0x0e7fu
#define SIDEFX_DF 0x00000400u
#define SIDEFX_LAST_ERROR ((DWORD)0x1234abcdu)
#define SIDEFX_VECTOR_BASE 0xa5a50000u
#define SIDEFX_BELOW_BYTE 0xd3u

typedef struct sidefx_capture {
#if defined(_WIN64)
    uint64_t gpr[SIDEFX_GPR_COUNT];
#else
    uint32_t gpr[SIDEFX_GPR_COUNT];
#endif
    uint8_t xmm[SIDEFX_VECTOR_COUNT][16];
    uint8_t ymm_upper[SIDEFX_VECTOR_COUNT][16];
    uint32_t mxcsr;
    uint32_t eflags;
    uint16_t x87cw;
    uint16_t reserved;
    uint8_t below_sp[SIDEFX_BELOW_SIZE];
} sidefx_capture;

#if defined(_WIN64)
_Static_assert(offsetof(sidefx_capture, xmm) == 112, "x64 xmm offset");
_Static_assert(offsetof(sidefx_capture, ymm_upper) == 368, "x64 ymm offset");
_Static_assert(offsetof(sidefx_capture, mxcsr) == 624, "x64 mxcsr offset");
_Static_assert(offsetof(sidefx_capture, eflags) == 628, "x64 eflags offset");
_Static_assert(offsetof(sidefx_capture, x87cw) == 632, "x64 x87 offset");
_Static_assert(offsetof(sidefx_capture, below_sp) == 636, "x64 below-sp offset");
#else
_Static_assert(offsetof(sidefx_capture, xmm) == 24, "x86 xmm offset");
_Static_assert(offsetof(sidefx_capture, ymm_upper) == 152, "x86 ymm offset");
_Static_assert(offsetof(sidefx_capture, mxcsr) == 280, "x86 mxcsr offset");
_Static_assert(offsetof(sidefx_capture, eflags) == 284, "x86 eflags offset");
_Static_assert(offsetof(sidefx_capture, x87cw) == 288, "x86 x87 offset");
_Static_assert(offsetof(sidefx_capture, below_sp) == 292, "x86 below-sp offset");
#endif

void sidefx_probe_point(sidefx_capture *capture);

typedef struct sidefx_counts {
    uint64_t gpr_ok;
    uint64_t xmm_ok;
    uint64_t ymm_upper_ok;
    uint64_t mxcsr_ok;
    uint64_t df_ok;
    uint64_t x87cw_ok;
    uint64_t lasterror_ok;
    uint64_t below_sp_ok;
} sidefx_counts;

typedef struct worker_args {
    uint32_t iterations;
    sidefx_counts counts;
} worker_args;

static int parse_u32(const char *text, uint32_t *value) {
    char *end = NULL;
    unsigned long long parsed;
    if (text == NULL || *text == '\0' || *text == '-') return 0;
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno == ERANGE || *end != '\0' || parsed == 0 || parsed > UINT32_MAX) return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int check_gprs(const sidefx_capture *capture) {
#if defined(_WIN64)
    static const uint64_t expected[SIDEFX_GPR_COUNT] = {
        UINT64_C(0x1111111111111111), UINT64_C(0x2222222222222222),
        UINT64_C(0x3333333333333333), UINT64_C(0x4444444444444444),
        UINT64_C(0x5555555555555555), UINT64_C(0x6666666666666666),
        UINT64_C(0x8888888888888888), UINT64_C(0x9999999999999999),
        UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_C(0xbbbbbbbbbbbbbbbb),
        UINT64_C(0xcccccccccccccccc), UINT64_C(0xdddddddddddddddd),
        UINT64_C(0xeeeeeeeeeeeeeeee), UINT64_C(0xffffffffffffffff)
    };
#else
    static const uint32_t expected[SIDEFX_GPR_COUNT] = {
        UINT32_C(0x11111111), UINT32_C(0x22222222), UINT32_C(0x33333333),
        UINT32_C(0x44444444), UINT32_C(0x55555555), UINT32_C(0x66666666)
    };
#endif
    return memcmp(capture->gpr, expected, sizeof(expected)) == 0;
}

static int check_vectors(const uint8_t vectors[SIDEFX_VECTOR_COUNT][16]) {
    uint32_t reg;
    for (reg = 0; reg < SIDEFX_VECTOR_COUNT; ++reg) {
        const uint32_t value = SIDEFX_VECTOR_BASE + reg;
        uint32_t byte;
        for (byte = 0; byte < 16u; ++byte) {
            const uint8_t expected = (uint8_t)(value >> ((byte & 3u) * 8u));
            if (vectors[reg][byte] != expected) return 0;
        }
    }
    return 1;
}

static int check_below_sp(const sidefx_capture *capture) {
    uint32_t i;
    for (i = 0; i < SIDEFX_BELOW_SIZE; ++i) {
        if (capture->below_sp[i] != SIDEFX_BELOW_BYTE) return 0;
    }
    return 1;
}

static DWORD WINAPI worker_main(void *opaque) {
    worker_args *args = (worker_args *)opaque;
    uint32_t iteration;
    for (iteration = 0; iteration < args->iterations; ++iteration) {
        sidefx_capture capture;
        DWORD last_error;

        SetLastError(SIDEFX_LAST_ERROR);
        sidefx_probe_point(&capture);
        last_error = GetLastError();

        args->counts.gpr_ok += (uint64_t)check_gprs(&capture);
        args->counts.xmm_ok += (uint64_t)check_vectors(capture.xmm);
        args->counts.ymm_upper_ok += (uint64_t)check_vectors(capture.ymm_upper);
        args->counts.mxcsr_ok += (uint64_t)(capture.mxcsr == SIDEFX_MXCSR);
        args->counts.df_ok += (uint64_t)((capture.eflags & SIDEFX_DF) != 0u);
        args->counts.x87cw_ok += (uint64_t)(capture.x87cw == SIDEFX_X87CW);
        args->counts.lasterror_ok += (uint64_t)(last_error == SIDEFX_LAST_ERROR);
        args->counts.below_sp_ok += (uint64_t)check_below_sp(&capture);
    }
    return 0;
}

static int wait_gate(void) {
    char byte;
    DWORD read = 0;
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    return input != INVALID_HANDLE_VALUE &&
           ReadFile(input, &byte, 1, &read, NULL) != 0 && read == 1;
}

static void usage(void) {
    fputs("usage: sidefx_target [--iters N] [--threads T] [--no-wait]\n", stderr);
}

int main(int argc, char **argv) {
    uint32_t iterations = 1000u;
    uint32_t threads = 4u;
    int no_wait = 0;
    worker_args *workers;
    HANDLE *handles;
    uint32_t created = 0;
    uint32_t i;
    sidefx_counts total = {0};
    uint64_t calls;
    int pass;

    for (i = 1; i < (uint32_t)argc; ++i) {
        if (strcmp(argv[i], "--no-wait") == 0) {
            no_wait = 1;
        } else if (strcmp(argv[i], "--iters") == 0 && i + 1u < (uint32_t)argc) {
            if (!parse_u32(argv[++i], &iterations)) { usage(); return 2; }
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1u < (uint32_t)argc) {
            if (!parse_u32(argv[++i], &threads) || threads > MAXIMUM_WAIT_OBJECTS) {
                usage();
                return 2;
            }
        } else {
            usage();
            return 2;
        }
    }

    puts("{\"kind\":\"waiting\"}");
    fflush(stdout);
    if (!no_wait && !wait_gate()) return 3;

    workers = (worker_args *)calloc(threads, sizeof(*workers));
    handles = (HANDLE *)calloc(threads, sizeof(*handles));
    if (workers == NULL || handles == NULL) {
        free(handles);
        free(workers);
        return 4;
    }

    for (i = 0; i < threads; ++i) {
        workers[i].iterations = iterations;
        handles[i] = CreateThread(NULL, 0, worker_main, &workers[i], 0, NULL);
        if (handles[i] == NULL) break;
        ++created;
    }
    if (created != threads ||
        WaitForMultipleObjects(created, handles, TRUE, INFINITE) == WAIT_FAILED) {
        for (i = 0; i < created; ++i) (void)WaitForSingleObject(handles[i], INFINITE);
        for (i = 0; i < created; ++i) CloseHandle(handles[i]);
        free(handles);
        free(workers);
        return 5;
    }

    for (i = 0; i < threads; ++i) {
        total.gpr_ok += workers[i].counts.gpr_ok;
        total.xmm_ok += workers[i].counts.xmm_ok;
        total.ymm_upper_ok += workers[i].counts.ymm_upper_ok;
        total.mxcsr_ok += workers[i].counts.mxcsr_ok;
        total.df_ok += workers[i].counts.df_ok;
        total.x87cw_ok += workers[i].counts.x87cw_ok;
        total.lasterror_ok += workers[i].counts.lasterror_ok;
        total.below_sp_ok += workers[i].counts.below_sp_ok;
        CloseHandle(handles[i]);
    }
    free(handles);
    free(workers);

    calls = (uint64_t)iterations * (uint64_t)threads;
    printf("{\"kind\":\"target\",\"name\":\"sidefx\",\"iters\":%u,\"threads\":%u,"
           "\"gpr_ok\":%" PRIu64 ",\"xmm_ok\":%" PRIu64
           ",\"ymm_upper_ok\":%" PRIu64 ",\"mxcsr_ok\":%" PRIu64
           ",\"df_ok\":%" PRIu64 ",\"x87cw_ok\":%" PRIu64
           ",\"lasterror_ok\":%" PRIu64 ",\"below_sp_ok\":%" PRIu64
           ",\"calls\":%" PRIu64 "}\n",
           iterations, threads, total.gpr_ok, total.xmm_ok, total.ymm_upper_ok,
           total.mxcsr_ok, total.df_ok, total.x87cw_ok, total.lasterror_ok,
           total.below_sp_ok, calls);
    fflush(stdout);

    pass = total.gpr_ok == calls && total.xmm_ok == calls &&
           total.ymm_upper_ok == calls && total.mxcsr_ok == calls &&
           total.df_ok == calls && total.x87cw_ok == calls &&
           total.lasterror_ok == calls;
    return pass ? 0 : 1;
}
