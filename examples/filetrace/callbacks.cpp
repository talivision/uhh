// filetrace callbacks: the file-access tracer every hooking tutorial starts with, on the
// ntdll syscall stubs (every caller is seen, whatever wrapper it used). Identical source
// under every backend; the handle -> path map is plain lock-free shared memory.
#include "callbacks.h"
#include <atomic>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>

namespace {
// handle -> path, one slot per handle value (handle >> 2). A slot is published by its
// handle (release) after the path is written; readers re-check it after copying. A handle
// landing on an occupied slot overwrites it, so only two handle values 16 Ki apart that
// are BOTH open could hide one another (the reader then sees "?", never a wrong path).
struct PathSlot { uint64_t handle; char path[248]; };
constexpr uint32_t kSlots = 4096;
UHH_SHARED PathSlot g_paths[kSlots];

std::atomic_ref<uint64_t> at(uint64_t &v) { return std::atomic_ref<uint64_t>(v); }
PathSlot &slot_of(uint64_t h) { return g_paths[(h >> 2) % kSlots]; }

void remember(uint64_t h, const char *path) {
    PathSlot &s = slot_of(h);
    at(s.handle).store(0, std::memory_order_release);              // unpublish while rewriting
    strncpy_s(s.path, sizeof(s.path), path, _TRUNCATE);
    at(s.handle).store(h, std::memory_order_release);
}
void forget(uint64_t h) {
    uint64_t expected = h;
    if (h) at(slot_of(h).handle).compare_exchange_strong(expected, 0, std::memory_order_acq_rel);
}
bool lookup(uint64_t h, char *out, size_t cap) {
    PathSlot &s = slot_of(h);
    if (h && at(s.handle).load(std::memory_order_acquire) == h) {
        strncpy_s(out, cap, s.path, _TRUNCATE);
        if (at(s.handle).load(std::memory_order_acquire) == h) return true;
    }
    strncpy_s(out, cap, "?", _TRUNCATE);
    return false;
}

uint64_t read_pointer(probe_context *c, uint64_t address) {
    uintptr_t v = 0;                                               // target pointer width == ours
    return address && get_mem(c, address, &v, sizeof(v)) ? (uint64_t)v : 0;
}

// OBJECT_ATTRIBUTES -> "\??\C:\dir\file" (ASCII; other characters as '?'). A name relative
// to RootDirectory is prefixed with the root's mapped path.
void object_name(probe_context *c, uint64_t oa_addr, char *out, size_t cap) {
    OBJECT_ATTRIBUTES oa{}; UNICODE_STRING us{}; wchar_t name[260];
    size_t n = 0;
    out[0] = 0;
    if (!oa_addr || !get_mem(c, oa_addr, &oa, sizeof(oa))) return;
    if (oa.RootDirectory) {
        lookup((uint64_t)(uintptr_t)oa.RootDirectory, out, cap);
        n = strlen(out);
        if (n + 1 < cap) { out[n++] = '\\'; out[n] = 0; }
    }
    if (!oa.ObjectName || !get_mem(c, (uint64_t)(uintptr_t)oa.ObjectName, &us, sizeof(us))) return;
    size_t len = us.Length / sizeof(wchar_t);
    if (len > _countof(name)) len = _countof(name);
    if (!len || !get_mem(c, (uint64_t)(uintptr_t)us.Buffer, name, len * sizeof(wchar_t))) return;
    for (size_t i = 0; i < len && n + 1 < cap; ++i) out[n++] = name[i] < 0x80 ? (char)name[i] : '?';
    out[n] = 0;
}

bool wanted(probe_context *c, const char *path) {
    auto *cfg = static_cast<const filetrace_config *>(get_config(c));
    return !cfg || cfg->cookie != FILETRACE_COOKIE || !cfg->filter[0] || strstr(path, cfg->filter);
}
}  // namespace

// NtCreateFile(PHANDLE out, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER,
//              ULONG attrs, ULONG share, ULONG disposition, ULONG options, PVOID ea, ULONG ealen)
// The handle exists only after the call and the path only in the arguments: run the real
// call here (call_original), then hand its status back unchanged (return_from, 11 args).
extern "C" void ft_on_create(probe_context *c) {
    const uint64_t out = get_func_arg(c, 0), access = get_func_arg(c, 1);
    char path[248];
    object_name(c, get_func_arg(c, 2), path, sizeof(path));       // before the call
    uint64_t status = 0;
    if (!call_original(c, 11, &status)) {                          // refused: the open runs normally
        if (wanted(c, path)) send_log(c, "create path=%s unmapped: call_original refused", path);
        return;
    }
    const uint64_t handle = (int32_t)status >= 0 ? read_pointer(c, out) : 0;
    if (handle) remember(handle, path);
    if (wanted(c, path))
        send_log(c, "create path=%s access=0x%08llx status=0x%08x handle=0x%llx", path,
                 (unsigned long long)access, (uint32_t)status, (unsigned long long)handle);
    return_from(c, status, 11);                                    // the caller sees the real status
}

// NtWriteFile(HANDLE, HANDLE event, PIO_APC_ROUTINE, PVOID apc_ctx, PIO_STATUS_BLOCK,
//             PVOID buffer, ULONG length, PLARGE_INTEGER offset, PULONG key)
extern "C" void ft_on_write(probe_context *c) {
    const uint64_t handle = get_func_arg(c, 0), length = (uint32_t)get_func_arg(c, 6);
    const uint64_t offset_ptr = get_func_arg(c, 7);
    char path[248];
    lookup(handle, path, sizeof(path));
    if (!wanted(c, path)) return;
    long long offset = -1;                                         // -1: the file pointer
    if (offset_ptr) get_mem(c, offset_ptr, &offset, sizeof(offset));
    send_log(c, "write path=%s handle=0x%llx len=%llu offset=%lld", path, (unsigned long long)handle,
             (unsigned long long)length, offset);
}

// NtClose(HANDLE): a value cannot be reissued before its close completes, so clearing at the
// close's entry never removes a newer mapping.
extern "C" void ft_on_close(probe_context *c) { forget(get_func_arg(c, 0)); }
