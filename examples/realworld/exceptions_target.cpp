#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#define TARGET_SEH_CODE ((DWORD)0xE0000001UL)

static volatile LONG g_unwind_sink = 0;

class UnwindMarker {
public:
    explicit UnwindMarker(int value) noexcept : value_(value) {}
    ~UnwindMarker() noexcept
    {
        (void)InterlockedExchangeAdd(&g_unwind_sink, (LONG)(value_ | 1));
    }

    UnwindMarker(const UnwindMarker &) = delete;
    UnwindMarker &operator=(const UnwindMarker &) = delete;

private:
    int value_;
};

extern "C" __declspec(dllexport) __declspec(noinline) void __cdecl throws_cpp(int depth)
{
    UnwindMarker marker(depth + 1);
    if (depth > 0) {
        throws_cpp(depth - 1);
        return;
    }
    throw std::runtime_error("expected target exception");
}

extern "C" __declspec(dllexport) __declspec(noinline) void __cdecl throws_seh(int depth)
{
    volatile LONG frame_touch = (LONG)depth;
    if (depth > 0) {
        throws_seh(depth - 1);
        (void)InterlockedExchangeAdd(&g_unwind_sink, frame_touch | 1L);
        return;
    }
    (void)InterlockedExchangeAdd(&g_unwind_sink, frame_touch | 1L);
    RaiseException(TARGET_SEH_CODE, 0U, 0U, nullptr);
}

typedef void (__cdecl *throwing_callback_type)(int);

static __declspec(noinline) void __cdecl throwing_callback(int value)
{
    (void)InterlockedExchangeAdd(&g_unwind_sink, (LONG)(value | 1));
    throw std::runtime_error("expected callback exception");
}

static throwing_callback_type volatile g_throwing_callback = throwing_callback;

extern "C" __declspec(dllexport) __declspec(noinline) void __cdecl calls_through(int n)
{
    UnwindMarker marker(n + 3);
    throwing_callback_type callback = g_throwing_callback;
    (void)InterlockedExchangeAdd(&g_unwind_sink, (LONG)((unsigned int)n ^ 0x13579bdfU));
    callback(n);
}

static __declspec(noinline) BOOL run_seh_once(int depth)
{
    BOOL caught = FALSE;

    __try {
        throws_seh(depth);
    }
    __except (GetExceptionCode() == TARGET_SEH_CODE
                  ? EXCEPTION_EXECUTE_HANDLER
                  : EXCEPTION_CONTINUE_SEARCH) {
        caught = TRUE;
    }
    return caught;
}

static bool parse_dword(const char *text, DWORD minimum, DWORD maximum,
                        DWORD &result)
{
    char *end = nullptr;
    unsigned long value;

    errno = 0;
    value = std::strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        value < static_cast<unsigned long>(minimum) ||
        value > static_cast<unsigned long>(maximum)) {
        return false;
    }
    result = static_cast<DWORD>(value);
    return true;
}

static bool wait_for_release(bool no_wait)
{
    if (no_wait) {
        return true;
    }
    (void)std::printf("{\"kind\":\"waiting\"}\n");
    (void)std::fflush(stdout);
    if (std::getchar() == EOF) {
        (void)std::fprintf(stderr, "stdin closed before release\n");
        return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    DWORD iterations = 200U;
    bool no_wait = false;
    int argument;
    DWORD i;
    DWORD cpp_caught = 0U;
    DWORD seh_caught = 0U;
    DWORD through_caught = 0U;
    const int recursion_depth = 8;

    for (argument = 1; argument < argc; ++argument) {
        if (std::strcmp(argv[argument], "--no-wait") == 0) {
            no_wait = true;
        } else if (std::strcmp(argv[argument], "--iters") == 0 && argument + 1 < argc) {
            ++argument;
            if (!parse_dword(argv[argument], 1U, 1000000U, iterations)) {
                (void)std::fprintf(stderr, "invalid --iters value\n");
                return 2;
            }
        } else {
            (void)std::fprintf(stderr, "unknown or incomplete argument: %s\n",
                               argv[argument]);
            return 2;
        }
    }
    if (!wait_for_release(no_wait)) {
        return 3;
    }

    for (i = 0U; i < iterations; ++i) {
        try {
            throws_cpp(recursion_depth);
        } catch (const std::runtime_error &) {
            ++cpp_caught;
        } catch (...) {
            (void)std::fprintf(stderr, "unexpected C++ exception type\n");
            return 4;
        }

        if (run_seh_once(recursion_depth)) {
            ++seh_caught;
        } else {
            (void)std::fprintf(stderr, "expected SEH exception was not caught\n");
            return 5;
        }

        try {
            calls_through(static_cast<int>(i));
        } catch (const std::runtime_error &) {
            ++through_caught;
        } catch (...) {
            (void)std::fprintf(stderr, "unexpected callback exception type\n");
            return 6;
        }
    }

    if (cpp_caught != iterations || seh_caught != iterations ||
        through_caught != iterations) {
        (void)std::fprintf(stderr, "exception catch counts were inconsistent\n");
        return 7;
    }

    (void)std::printf("{\"kind\":\"target\",\"name\":\"exceptions\","
                      "\"cpp_caught\":%lu,\"seh_caught\":%lu,"
                      "\"through_caught\":%lu,\"iters\":%lu}\n",
                      static_cast<unsigned long>(cpp_caught),
                      static_cast<unsigned long>(seh_caught),
                      static_cast<unsigned long>(through_caught),
                      static_cast<unsigned long>(iterations));
    (void)std::fflush(stdout);
    return 0;
}
