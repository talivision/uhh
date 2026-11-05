// Loader / unpacker signals (the API Monitor "Library loading" + "Memory" filters, and
// the Frida RWX-hunting scripts used to catch unpackers and shellcode loaders).
//
//   kernelbase!LoadLibraryExW entry       lpLibFileName (PCWSTR), dwFlags
//   ntdll!LdrLoadDll entry                UNICODE_STRING *DllName (every load, whatever API)
//   ntdll!NtAllocateVirtualMemory entry   Protect is executable+writable: log *BaseAddress,
//                                         *RegionSize, AllocationType
//   ntdll!NtProtectVirtualMemory entry    NewProtect executable+writable: log the range
//
// Entry-only (no return probes): four probes, so the recipe fits the four debug
// registers of the hardware backend too.
#include "../common/famous_common.h"

static bool exec_writable(uint32_t protect) {
    return (protect & 0xff) == PAGE_EXECUTE_READWRITE || (protect & 0xff) == PAGE_EXECUTE_WRITECOPY;
}

// LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
FAMOUS_EXPORT void famous_loader_on_loadlibrary(probe_context *c) {
    char name[260];
    if (!famous_read_wstr(c, get_func_arg(c, 0), name, sizeof(name))) strncpy_s(name, sizeof(name), "?", _TRUNCATE);
    send_log(c, "loadlibraryexw name=%s flags=0x%x", name, (uint32_t)get_func_arg(c, 2));
}

// LdrLoadDll(PWSTR SearchPath, PULONG Flags, PUNICODE_STRING DllName, PVOID *BaseAddress)
FAMOUS_EXPORT void famous_loader_on_ldrloaddll(probe_context *c) {
    char name[260];
    if (!famous_read_ustr(c, get_func_arg(c, 2), name, sizeof(name))) strncpy_s(name, sizeof(name), "?", _TRUNCATE);
    send_log(c, "ldrloaddll name=%s", name);
}

// NtAllocateVirtualMemory(HANDLE, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize,
//                         ULONG AllocationType, ULONG Protect)
FAMOUS_EXPORT void famous_loader_on_alloc(probe_context *c) {
    uint32_t protect = (uint32_t)get_func_arg(c, 5);
    if (!exec_writable(protect)) return;
    uint64_t base = famous_read_ptr(c, get_func_arg(c, 1));
    uint64_t size = famous_read_ptr(c, get_func_arg(c, 3));
    send_log(c, "rwx-alloc process=0x%llx base=0x%llx size=0x%llx type=0x%x protect=0x%x",
             (unsigned long long)get_func_arg(c, 0), (unsigned long long)base, (unsigned long long)size,
             (uint32_t)get_func_arg(c, 4), protect);
}

// NtProtectVirtualMemory(HANDLE, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect,
//                        PULONG OldProtect)
FAMOUS_EXPORT void famous_loader_on_protect(probe_context *c) {
    uint32_t protect = (uint32_t)get_func_arg(c, 3);
    if (!exec_writable(protect)) return;
    uint64_t base = famous_read_ptr(c, get_func_arg(c, 1));
    uint64_t size = famous_read_ptr(c, get_func_arg(c, 2));
    send_log(c, "rwx-protect process=0x%llx base=0x%llx size=0x%llx protect=0x%x",
             (unsigned long long)get_func_arg(c, 0), (unsigned long long)base, (unsigned long long)size, protect);
}
