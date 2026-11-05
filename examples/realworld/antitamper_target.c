#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (__cdecl *guarded_fn_pointer)(int);

typedef struct integrity_baseline {
    const unsigned char *text;
    SIZE_T text_size;
    const unsigned char *function_bytes;
    uint64_t text_checksum;
    uint64_t function_checksum;
} integrity_baseline;

typedef struct integrity_result {
    BOOL text_ok;
    BOOL function_ok;
    const char *text_changed_at;
} integrity_result;

typedef struct debug_context_request {
    HANDLE target_thread;
    BOOL succeeded;
    BOOL debug_registers_seen;
} debug_context_request;

static volatile LONG g_guarded_sink = 0;

__declspec(dllexport) __declspec(noinline) int __cdecl guarded_fn(int value)
{
    unsigned int mixed = ((unsigned int)value * 33U) ^ 0xa5a55a5aU;
    (void)InterlockedExchangeAdd(&g_guarded_sink, (LONG)(mixed | 1U));
    mixed ^= mixed >> 13;
    mixed *= 0x85ebca6bU;
    return (int)(mixed ^ (mixed >> 16));
}

static uint64_t fnv1a(const unsigned char *bytes, SIZE_T size)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    SIZE_T i;

    for (i = 0U; i < size; ++i) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static BOOL locate_text_section(const unsigned char **text, SIZE_T *text_size)
{
    const unsigned char *module = (const unsigned char *)GetModuleHandleW(NULL);
    const IMAGE_DOS_HEADER *dos_header;
    const IMAGE_NT_HEADERS *nt_headers;
    const IMAGE_SECTION_HEADER *section;
    WORD i;

    if (module == NULL) {
        return FALSE;
    }
    dos_header = (const IMAGE_DOS_HEADER *)module;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew <= 0) {
        return FALSE;
    }
    nt_headers = (const IMAGE_NT_HEADERS *)(module + (SIZE_T)dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    section = IMAGE_FIRST_SECTION(nt_headers);
    for (i = 0U; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        DWORD size;
        DWORD virtual_address;
        if (memcmp(section[i].Name, ".text", 5U) != 0) {
            continue;
        }
        size = section[i].Misc.VirtualSize;
        if (size == 0U) {
            size = section[i].SizeOfRawData;
        }
        virtual_address = section[i].VirtualAddress;
        if (size == 0U || virtual_address >= nt_headers->OptionalHeader.SizeOfImage ||
            size > nt_headers->OptionalHeader.SizeOfImage - virtual_address) {
            return FALSE;
        }
        *text = module + virtual_address;
        *text_size = (SIZE_T)size;
        return TRUE;
    }
    return FALSE;
}

/* Compare the first 8 bytes of guarded_fn in memory with the same bytes in this
   executable's FILE on disk -- what a real integrity check does, independent of when
   the in-memory baseline was taken. (8 bytes: the prologue carries no relocations.) */
static BOOL function_matches_disk(void)
{
    union { guarded_fn_pointer function; const unsigned char *bytes; } address;
    unsigned char *base = (unsigned char *)GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    wchar_t path[MAX_PATH];
    unsigned char disk[8];
    DWORD rva, got = 0;
    WORD i;
    HANDLE file;
    LARGE_INTEGER off;
    BOOL ok = FALSE;

    address.function = guarded_fn;
    rva = (DWORD)(address.bytes - base);
    if (!GetModuleFileNameW(NULL, path, MAX_PATH)) return FALSE;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                       OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (rva >= sec->VirtualAddress && rva + 8U <= sec->VirtualAddress + sec->SizeOfRawData) {
            off.QuadPart = (LONGLONG)sec->PointerToRawData + (rva - sec->VirtualAddress);
            if (SetFilePointerEx(file, off, NULL, FILE_BEGIN) && ReadFile(file, disk, 8, &got, NULL) && got == 8)
                ok = memcmp(disk, address.bytes, 8) == 0;
            break;
        }
    }
    CloseHandle(file);
    return ok;
}

static BOOL initialize_baseline(integrity_baseline *baseline)
{
    union function_address {
        guarded_fn_pointer function;
        const unsigned char *bytes;
    } address;

    if (!locate_text_section(&baseline->text, &baseline->text_size)) {
        return FALSE;
    }
    address.function = guarded_fn;
    baseline->function_bytes = address.bytes;
    baseline->text_checksum = fnv1a(baseline->text, baseline->text_size);
    baseline->function_checksum = fnv1a(baseline->function_bytes, 32U);
    return TRUE;
}

static void check_integrity(const integrity_baseline *baseline,
                            integrity_result *result, const char *stage)
{
    uint64_t text_checksum = fnv1a(baseline->text, baseline->text_size);
    uint64_t function_checksum = fnv1a(baseline->function_bytes, 32U);

    if (text_checksum != baseline->text_checksum) {
        result->text_ok = FALSE;
        if (strcmp(result->text_changed_at, "none") == 0) {
            result->text_changed_at = stage;
        }
    }
    if (function_checksum != baseline->function_checksum) {
        result->function_ok = FALSE;
    }
}

static DWORD WINAPI read_debug_context(void *parameter)
{
    debug_context_request *request = (debug_context_request *)parameter;
    CONTEXT context;
    DWORD suspend_count;

    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    suspend_count = SuspendThread(request->target_thread);
    if (suspend_count == (DWORD)-1) {
        return 1U;
    }
    if (GetThreadContext(request->target_thread, &context)) {
        request->debug_registers_seen = context.Dr7 != 0U;
        request->succeeded = TRUE;
    }
    if (ResumeThread(request->target_thread) == (DWORD)-1) {
        request->succeeded = FALSE;
    }
    return request->succeeded ? 0U : 1U;
}

static BOOL inspect_debug_registers(HANDLE main_thread, BOOL *seen)
{
    debug_context_request request;
    HANDLE helper;
    DWORD exit_code = 1U;

    ZeroMemory(&request, sizeof(request));
    request.target_thread = main_thread;
    helper = CreateThread(NULL, 0U, read_debug_context, &request, 0U, NULL);
    if (helper == NULL) {
        return FALSE;
    }
    if (WaitForSingleObject(helper, INFINITE) != WAIT_OBJECT_0 ||
        !GetExitCodeThread(helper, &exit_code)) {
        (void)CloseHandle(helper);
        return FALSE;
    }
    (void)CloseHandle(helper);
    if (exit_code != 0U || !request.succeeded) {
        return FALSE;
    }
    *seen = request.debug_registers_seen;
    return TRUE;
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

static const char *json_bool(BOOL value)
{
    return value ? "true" : "false";
}

int main(int argc, char **argv)
{
    DWORD calls = 100U;
    BOOL no_wait = FALSE;
    DWORD i;
    integrity_baseline baseline;
    integrity_result result;
    HANDLE main_thread = NULL;
    BOOL debug_registers_seen = FALSE;
    BOOL fn_disk_ok = TRUE;
    const char *detected_by = "none", *detected_at = "none";

    for (i = 1U; i < (DWORD)argc; ++i) {
        if (strcmp(argv[i], "--no-wait") == 0) {
            no_wait = TRUE;
        } else if (strcmp(argv[i], "--calls") == 0 && i + 1U < (DWORD)argc) {
            ++i;
            if (!parse_dword(argv[i], 1U, 10000000U, &calls)) {
                (void)fprintf(stderr, "invalid --calls value\n");
                return 2;
            }
        } else {
            (void)fprintf(stderr, "unknown or incomplete argument: %s\n", argv[i]);
            return 2;
        }
    }

    ZeroMemory(&baseline, sizeof(baseline));
    if (!initialize_baseline(&baseline)) {
        (void)fprintf(stderr, "unable to locate or checksum .text\n");
        return 3;
    }

    if (!wait_for_release(no_wait)) {
        return 4;
    }
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                         &main_thread,
                         THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                             THREAD_QUERY_INFORMATION,
                         FALSE, 0U)) {
        (void)fprintf(stderr, "unable to duplicate main thread handle: %lu\n",
                      (unsigned long)GetLastError());
        return 5;
    }

    result.text_ok = TRUE;
    result.function_ok = TRUE;
    result.text_changed_at = "none";

    /* The tamper response: once instrumentation is detected, the target takes a DIFFERENT
       path -- guarded_fn is still called, but with -1 (a "protected feature disabled"
       marker) instead of the loop index, so the change is visible to the probe's own log
       as well as in the summary line. Checked right after release and again halfway. */
    for (i = 0U; i <= calls; ++i) {
        if (i == 0U || i == calls / 2U) {
            const char *stage = i == 0U ? "before" : "middle";
            BOOL code_changed, dr = FALSE;
            check_integrity(&baseline, &result, stage);
            fn_disk_ok = function_matches_disk();
            if (!inspect_debug_registers(main_thread, &dr)) {
                (void)fprintf(stderr, "unable to inspect main-thread debug registers\n");
                (void)CloseHandle(main_thread);
                return 6;
            }
            debug_registers_seen = debug_registers_seen || dr;
            code_changed = !fn_disk_ok || !result.text_ok || !result.function_ok;
            if (strcmp(detected_at, "none") == 0 && (code_changed || dr)) {
                detected_by = code_changed ? (dr ? "code+debug_registers" : "code") : "debug_registers";
                detected_at = stage;
            }
        }
        if (i == calls) break;
        (void)guarded_fn(strcmp(detected_at, "none") == 0 ? (int)i : -1);
    }
    check_integrity(&baseline, &result, "after");
    (void)CloseHandle(main_thread);

    (void)printf("{\"kind\":\"target\",\"name\":\"antitamper\","
                 "\"calls\":%lu,\"text_ok\":%s,\"fn_bytes_ok\":%s,"
                 "\"text_changed_at\":\"%s\",\"debug_registers_seen\":%s,\"fn_disk_ok\":%s,"
                 "\"path\":\"%s\",\"detected_by\":\"%s\",\"detected_at\":\"%s\"}\n",
                 (unsigned long)calls, json_bool(result.text_ok),
                 json_bool(result.function_ok), result.text_changed_at,
                 json_bool(debug_registers_seen), json_bool(fn_disk_ok),
                 strcmp(detected_at, "none") == 0 ? "clean" : "tampered", detected_by, detected_at);
    (void)fflush(stdout);
    return 0;
}
