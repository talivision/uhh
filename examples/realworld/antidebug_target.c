#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef LONG (NTAPI *nt_query_information_process_fn)(
    HANDLE process, ULONG information_class, void *information,
    ULONG information_length, ULONG *return_length);

typedef struct process_basic_information_local {
    void *reserved1;
    void *peb_base_address;
    void *reserved2[2];
    ULONG_PTR unique_process_id;
    void *reserved3;
} process_basic_information_local;

static volatile LONG g_timed_sink = 0;

__declspec(dllexport) __declspec(noinline) int __cdecl timed_fn(int value)
{
    unsigned int mixed = ((unsigned int)value ^ 0x9e3779b9U) * 33U;
    (void)InterlockedExchangeAdd(&g_timed_sink, (LONG)(mixed | 1U));
    mixed ^= mixed >> 11;
    mixed *= 0x7feb352dU;
    return (int)(mixed ^ (mixed >> 15));
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

static const char *json_bool(BOOL value)
{
    return value ? "true" : "false";
}

int main(int argc, char **argv)
{
    BOOL no_wait = FALSE;
    int argument;
    HMODULE ntdll;
    union query_resolver {
        FARPROC raw;
        nt_query_information_process_fn typed;
    } resolver;
    ULONG_PTR debug_port = 0U;
    HANDLE debug_object = NULL;
    ULONG debug_flags = 1U;
    process_basic_information_local basic_information;
    ULONG returned = 0U;
    LONG status_port;
    LONG status_object;
    LONG status_flags;
    LONG status_basic;
    BOOL remote_debugger = FALSE;
    BOOL remote_check_ok;
    BOOL peb_being_debugged;
    BOOL peb_nt_global_flag;
    DWORD nt_global_flag = 0U;
    SIZE_T nt_global_flag_offset;
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    uint64_t elapsed_ticks;
    uint64_t frequency_ticks;
    uint64_t timed_fn_ns;

    for (argument = 1; argument < argc; ++argument) {
        if (strcmp(argv[argument], "--no-wait") == 0) {
            no_wait = TRUE;
        } else {
            (void)fprintf(stderr, "unknown argument: %s\n", argv[argument]);
            return 2;
        }
    }
    if (!wait_for_release(no_wait)) {
        return 3;
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        (void)fprintf(stderr, "ntdll is not loaded\n");
        return 4;
    }
    resolver.raw = GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (resolver.raw == NULL) {
        (void)fprintf(stderr, "NtQueryInformationProcess is unavailable\n");
        return 4;
    }

    status_port = resolver.typed(GetCurrentProcess(), 7U, &debug_port,
                                 (ULONG)sizeof(debug_port), &returned);
    status_object = resolver.typed(GetCurrentProcess(), 30U, &debug_object,
                                   (ULONG)sizeof(debug_object), &returned);
    status_flags = resolver.typed(GetCurrentProcess(), 31U, &debug_flags,
                                  (ULONG)sizeof(debug_flags), &returned);
    ZeroMemory(&basic_information, sizeof(basic_information));
    status_basic = resolver.typed(GetCurrentProcess(), 0U, &basic_information,
                                  (ULONG)sizeof(basic_information), &returned);
    if (status_basic < 0 || basic_information.peb_base_address == NULL) {
        (void)fprintf(stderr, "ProcessBasicInformation query failed: 0x%08lx\n",
                      (unsigned long)status_basic);
        return 5;
    }

    remote_check_ok = CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger);
    if (!remote_check_ok) {
        (void)fprintf(stderr, "CheckRemoteDebuggerPresent failed: %lu\n",
                      (unsigned long)GetLastError());
        return 6;
    }

    peb_being_debugged = *((const unsigned char *)basic_information.peb_base_address + 2U) != 0U;
#if defined(_WIN64)
    nt_global_flag_offset = 0xbcU;
#else
    nt_global_flag_offset = 0x68U;
#endif
    memcpy(&nt_global_flag,
           (const unsigned char *)basic_information.peb_base_address + nt_global_flag_offset,
           sizeof(nt_global_flag));
    peb_nt_global_flag = (nt_global_flag & 0x70U) != 0U;

    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0 ||
        !QueryPerformanceCounter(&start)) {
        (void)fprintf(stderr, "performance counter initialization failed\n");
        return 7;
    }
    (void)timed_fn(17);
    if (!QueryPerformanceCounter(&end) || end.QuadPart < start.QuadPart) {
        (void)fprintf(stderr, "performance counter measurement failed\n");
        return 7;
    }
    elapsed_ticks = (uint64_t)(end.QuadPart - start.QuadPart);
    frequency_ticks = (uint64_t)frequency.QuadPart;
    timed_fn_ns = (elapsed_ticks / frequency_ticks) * UINT64_C(1000000000) +
                  ((elapsed_ticks % frequency_ticks) * UINT64_C(1000000000)) /
                      frequency_ticks;

    (void)printf("{\"kind\":\"target\",\"name\":\"antidebug\","
                 "\"is_debugger_present\":%s,\"remote_debugger_present\":%s,"
                 "\"debug_port\":%s,\"debug_object_handle\":%s,"
                 "\"debug_flags_zero\":%s,\"peb_being_debugged\":%s,"
                 "\"peb_nt_global_flag_heap_debug\":%s,\"timed_fn_ns\":%llu}\n",
                 json_bool(IsDebuggerPresent()), json_bool(remote_debugger),
                 json_bool(status_port >= 0 && debug_port != 0U),
                 json_bool(status_object >= 0 && debug_object != NULL),
                 json_bool(status_flags >= 0 && debug_flags == 0U),
                 json_bool(peb_being_debugged), json_bool(peb_nt_global_flag),
                 (unsigned long long)timed_fn_ns);
    (void)fflush(stdout);
    return 0;
}
