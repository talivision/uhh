// regtrace callbacks: a registry tracer on the ntdll syscall stubs (every caller is seen,
// advapi32 / kernelbase / direct). Identical source under every backend; the key handle ->
// name map is plain lock-free shared memory.
#include "callbacks.h"
#include <atomic>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>

namespace {
// handle -> key name, one slot per handle value (handle >> 2), published by its handle
// (release) after the name is written; readers re-check it after copying. A colliding
// handle overwrites the slot: the older one then reads as "?", never as a wrong name.
struct NameSlot { uint64_t handle; char name[248]; };
constexpr uint32_t kSlots = 4096;
UHH_SHARED NameSlot g_keys[kSlots];

std::atomic_ref<uint64_t> at(uint64_t &v) { return std::atomic_ref<uint64_t>(v); }
NameSlot &slot_of(uint64_t h) { return g_keys[(h >> 2) % kSlots]; }

void remember(uint64_t h, const char *name) {
    NameSlot &s = slot_of(h);
    at(s.handle).store(0, std::memory_order_release);
    strncpy_s(s.name, sizeof(s.name), name, _TRUNCATE);
    at(s.handle).store(h, std::memory_order_release);
}
void forget(uint64_t h) {
    uint64_t expected = h;
    if (h) at(slot_of(h).handle).compare_exchange_strong(expected, 0, std::memory_order_acq_rel);
}
bool lookup(uint64_t h, char *out, size_t cap) {
    NameSlot &s = slot_of(h);
    if (h && at(s.handle).load(std::memory_order_acquire) == h) {
        strncpy_s(out, cap, s.name, _TRUNCATE);
        if (at(s.handle).load(std::memory_order_acquire) == h) return true;
    }
    strncpy_s(out, cap, "?", _TRUNCATE);
    return false;
}

uint64_t read_pointer(probe_context *c, uint64_t address) {
    uintptr_t v = 0;                                           // target pointer width == ours
    return address && get_mem(c, address, &v, sizeof(v)) ? (uint64_t)v : 0;
}

// A UNICODE_STRING in the target, appended as ASCII (other characters as '?').
size_t append_ustring(probe_context *c, uint64_t us_addr, char *out, size_t n, size_t cap) {
    UNICODE_STRING us{}; wchar_t text[256];
    if (!us_addr || !get_mem(c, us_addr, &us, sizeof(us))) return n;
    size_t len = us.Length / sizeof(wchar_t);
    if (len > _countof(text)) len = _countof(text);
    if (!len || !get_mem(c, (uint64_t)(uintptr_t)us.Buffer, text, len * sizeof(wchar_t))) return n;
    for (size_t i = 0; i < len && n + 1 < cap; ++i) out[n++] = text[i] < 0x80 ? (char)text[i] : '?';
    out[n] = 0;
    return n;
}

// OBJECT_ATTRIBUTES -> full key name: a name relative to RootDirectory (RegOpenKeyEx(HKCU,
// "Software\\X") opens "Software\\X" under the real HKCU handle) gets the root's mapped name.
void key_name(probe_context *c, uint64_t oa_addr, char *out, size_t cap) {
    OBJECT_ATTRIBUTES oa{};
    size_t n = 0;
    out[0] = 0;
    if (!oa_addr || !get_mem(c, oa_addr, &oa, sizeof(oa))) return;
    if (oa.RootDirectory) {
        lookup((uint64_t)(uintptr_t)oa.RootDirectory, out, cap);
        n = strlen(out);
        if (n + 1 < cap) { out[n++] = '\\'; out[n] = 0; }
    }
    append_ustring(c, (uint64_t)(uintptr_t)oa.ObjectName, out, n, cap);
}

bool wanted(probe_context *c, const char *name) {
    auto *cfg = static_cast<const regtrace_config *>(get_config(c));
    return !cfg || cfg->cookie != REGTRACE_COOKIE || !cfg->filter[0] || !strcmp(name, "?") ||
           strstr(name, cfg->filter);
}

// Shared by the three open stubs: arg 0 is the PHANDLE out, arg 2 the OBJECT_ATTRIBUTES.
void on_open(probe_context *c, const char *op, int nargs) {
    const uint64_t out = get_func_arg(c, 0);
    char name[248];
    key_name(c, get_func_arg(c, 2), name, sizeof(name));          // before the call
    uint64_t status = 0;
    if (!call_original(c, nargs, &status)) {                       // refused: the open runs normally
        if (wanted(c, name)) send_log(c, "%s key=%s unmapped: call_original refused", op, name);
        return;
    }
    const uint64_t handle = (int32_t)status >= 0 ? read_pointer(c, out) : 0;
    if (handle) remember(handle, name);
    if (wanted(c, name))
        send_log(c, "%s key=%s status=0x%08x handle=0x%llx", op, name, (uint32_t)status, (unsigned long long)handle);
    return_from(c, status, nargs);                                 // x86: stdcall pops nargs*4
}

void on_value(probe_context *c, const char *op, const char *what, uint32_t detail) {
    char key[248], value[128];
    lookup(get_func_arg(c, 0), key, sizeof(key));
    if (!wanted(c, key)) return;
    value[0] = 0;
    append_ustring(c, get_func_arg(c, 1), value, 0, sizeof(value));
    send_log(c, "%s key=%s handle=0x%llx value=%s %s=%u", op, key, (unsigned long long)get_func_arg(c, 0), value,
             what, detail);
}
}  // namespace

// NtOpenKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
extern "C" void rt_on_open_key(probe_context *c) { on_open(c, "open", 3); }
// NtOpenKeyEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG options)
extern "C" void rt_on_open_key_ex(probe_context *c) { on_open(c, "open", 4); }
// NtCreateKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG)
extern "C" void rt_on_create_key(probe_context *c) { on_open(c, "create", 7); }
// NtQueryValueKey(HANDLE, PUNICODE_STRING name, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG)
extern "C" void rt_on_query_value(probe_context *c) { on_value(c, "query", "class", (uint32_t)get_func_arg(c, 2)); }
// NtSetValueKey(HANDLE, PUNICODE_STRING name, ULONG title, ULONG type, PVOID data, ULONG size)
extern "C" void rt_on_set_value(probe_context *c) { on_value(c, "set", "type", (uint32_t)get_func_arg(c, 3)); }
// NtClose(HANDLE)
extern "C" void rt_on_close(probe_context *c) { forget(get_func_arg(c, 0)); }
