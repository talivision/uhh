// The three callbacks behind gated_config and uhh_attach. Identical in every backend:
// state is plain lock-free memory, so it works on the controller's debug-loop thread
// (breakpoint / hw) and on many target threads at once (inline, inside the target).
#include "callbacks.h"
#include <atomic>
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// 1. Turn the disabled feature on. At configparse.dll!ParseConfig+0x16 the freshly
//    parsed reads_enabled is in EAX and is about to be stored: make it 1. The library
//    counts the register change in the report's "overrides" field.
extern "C" void enable_reads(probe_context *c) {
    if (get_reg(c, PROBE_REG_AX) == 0) set_reg(c, PROBE_REG_AX, 1);
}

// 1b. The same flip done in MEMORY (examples/gated_config_mem). One instruction later, at
//     configparse.dll!ParseConfig+0x18, the parsed value has been stored to *out, and BX
//     (rbx/ebx) still points at out on both arches: read the stored flag and, if it is 0,
//     write 1 over it. No register changes -- the target simply reads enabled config.
extern "C" void enable_reads_mem(probe_context *c) {
    const uint64_t out = get_reg(c, PROBE_REG_BX);
    uint32_t reads_enabled = 1;
    if (out && get_mem(c, out, &reads_enabled, sizeof(reads_enabled)) && reads_enabled == 0) {
        reads_enabled = 1;
        set_mem(c, out, &reads_enabled, sizeof(reads_enabled));
        send_log(c, "flag flipped in memory at 0x%llx", (unsigned long long)out);
    }
}

// 2. Handle -> pid -> name map, built at ntdll!NtOpenProcess (PHANDLE out, ACCESS_MASK,
//    POBJECT_ATTRIBUTES, PCLIENT_ID): the syscall stub every OpenProcess path ends in.
//    The pid exists only here (cid->UniqueProcess) -- a PROCESS_VM_READ-only handle can
//    never be asked for it later -- and the handle only after the call. So the callback
//    runs the real open itself (call_original), reads the handle it just wrote to *out
//    (however short-lived that slot is, e.g. kernel32!OpenProcess's local), records
//    handle -> pid -> name, and returns the real status (return_from: not run again).
namespace {
struct OpenRecord {                     // plain data: zero-initialised, no constructors
    uint64_t pid;                       // 0 = empty
    uint64_t handle;
    char name[64];                      // image name of pid
};
// A direct table, one slot per handle value (handle >> 2): a lookup costs the same after a
// million opens as after one, and there is no cap on how many opens are tracked. A handle
// landing on an occupied slot overwrites it (handles are compared on lookup), so only two
// handle values 256 Ki apart that are BOTH still in use could hide one another.
constexpr uint32_t kHandleSlots = 0x10000;   // ~5 MiB shared, zero-initialised
// UHH_SHARED: the map is ONE piece of memory for every backend -- the open probe and the
// read probe may run in different processes (breakpoint/hw in the controller, inline in
// the target) and still see each other's records. Plain values only (pids, handles),
// zero-initialised; a slot is published by its pid (release) after the rest is written.
UHH_SHARED OpenRecord g_by_handle[kHandleSlots];

std::atomic_ref<uint64_t> at(uint64_t &field) { return std::atomic_ref<uint64_t>(field); }

uint64_t read_pointer(probe_context *c, uint64_t address) {
    uintptr_t value = 0;                 // target pointer width == ours (same arch)
    return get_mem(c, address, &value, sizeof(value)) ? (uint64_t)value : 0;
}

// Image name of a pid ("probe_app.exe"), without opening the process: an open here would
// re-enter the very NtOpenProcess probe this runs in. SystemProcessIdInformation (88) asks
// the kernel by pid; it works the same in the controller (breakpoint/hw) and in the target
// (inline). "?" if the process is gone or the query fails.
constexpr auto SystemProcessIdInformation = (SYSTEM_INFORMATION_CLASS)88;
struct SYSTEM_PROCESS_ID_INFORMATION { HANDLE ProcessId; UNICODE_STRING ImageName; };

void image_name_of(uint64_t pid, char *out, size_t cap) {
    wchar_t path[512];
    SYSTEM_PROCESS_ID_INFORMATION info{(HANDLE)(uintptr_t)pid, {0, sizeof(path), path}};
    size_t n = 0;
    if (NtQuerySystemInformation(SystemProcessIdInformation, &info, sizeof(info), nullptr) >= 0) {
        size_t len = info.ImageName.Length / sizeof(wchar_t), start = 0;
        for (size_t i = 0; i < len; ++i) if (path[i] == L'\\') start = i + 1;
        for (size_t i = start; i < len && n + 1 < cap; ++i)
            out[n++] = path[i] < 0x80 ? (char)path[i] : '?';
    }
    if (!n && cap > 1) out[n++] = '?';
    out[n] = 0;
}

OpenRecord &slot_of(uint64_t handle) { return g_by_handle[(handle >> 2) % kHandleSlots]; }

// Copy of what the table knows about `handle` (pid 0 if nothing). Re-read until the slot
// did not change underneath (a concurrent open of a colliding handle).
OpenRecord open_of(uint64_t handle) {
    OpenRecord r{};
    if (!handle) return r;
    OpenRecord &slot = slot_of(handle);
    for (int tries = 0; tries < 4; ++tries) {
        const uint64_t pid = at(slot.pid).load(std::memory_order_acquire);
        r.handle = at(slot.handle).load(std::memory_order_acquire);
        std::memcpy(r.name, slot.name, sizeof(r.name));
        if (at(slot.pid).load(std::memory_order_acquire) == pid) { r.pid = r.handle == handle ? pid : 0; break; }
    }
    r.name[sizeof(r.name) - 1] = 0;
    return r;
}

void remember_open(uint64_t handle, uint64_t pid, const char *name) {
    OpenRecord &slot = slot_of(handle);
    at(slot.pid).store(0, std::memory_order_release);                 // unpublish while rewriting
    std::memcpy(slot.name, name, sizeof(slot.name));
    at(slot.handle).store(handle, std::memory_order_relaxed);
    at(slot.pid).store(pid, std::memory_order_release);
}
}  // namespace

extern "C" void track_open_process(probe_context *c) {
    uint64_t out = get_func_arg(c, 0), cid = get_func_arg(c, 3);
    uint64_t pid = cid ? read_pointer(c, cid) : 0;     // CLIENT_ID.UniqueProcess (read before the call)
    uint64_t status = 0;
    if (!call_original(c, 4, &status)) {                // refused (no free debug register on hw): the open
        send_log(c, "open pid=%llu unmapped: call_original refused", (unsigned long long)pid);
        return;                                         // runs normally, but its handle stays unknown
    }
    uint64_t handle = (int32_t)status >= 0 && out ? read_pointer(c, out) : 0;
    if (pid && handle) {
        char name[sizeof(OpenRecord::name)];
        image_name_of(pid, name, sizeof(name));
        send_log(c, "open pid=%llu name=%s", (unsigned long long)pid, name);
        remember_open(handle, pid, name);
        send_log(c, "map handle=0x%llx -> pid=%llu name=%s", (unsigned long long)handle,
                 (unsigned long long)pid, name);
    }
    return_from(c, status, 4);                          // the caller sees exactly what it would have
}

// 2b. ntdll!NtClose(handle): forget a mapped handle when it is closed. Windows reuses handle
//     values, and process handles also come from places this map never sees (CreateProcess's
//     hProcess, DuplicateHandle, inheritance): a stale slot would label such a handle with
//     the pid of whatever was opened under that value before. A value cannot be reissued
//     before its close completes, so clearing at the close's entry never hits a newer record.
extern "C" void forget_closed_handle(probe_context *c) {
    const uint64_t handle = get_func_arg(c, 0);
    if (!handle) return;
    OpenRecord &slot = slot_of(handle);
    if (at(slot.handle).load(std::memory_order_acquire) == handle) at(slot.pid).store(0, std::memory_order_release);
}

// 3. Every read through ntdll!NtReadVirtualMemory(handle,
//    address, buffer, size, done). Optionally filtered by pid and/or address ranges.
extern "C" void log_read(probe_context *c) {
    auto *cfg = static_cast<const read_log_config *>(get_config(c));
    if (!cfg || cfg->cookie != READ_LOG_COOKIE || !cfg->log) return;
    uint64_t handle = get_func_arg(c, 0), addr = get_func_arg(c, 1), size = get_func_arg(c, 3);
    const OpenRecord r = open_of(handle);
    const uint64_t pid = r.pid;
    if (cfg->pid && pid != cfg->pid) return;
    if (cfg->nranges) {
        bool in = false;
        for (uint32_t k = 0; k < cfg->nranges && k < READ_LOG_MAX_RANGES && !in; ++k)
            in = addr - cfg->ranges[k].base < cfg->ranges[k].size;   // unsigned: also addr < base
        if (!in) return;
    }
    send_log(c, "read handle=0x%llx pid=%llu name=%s addr=0x%llx size=%llu", (unsigned long long)handle,
             (unsigned long long)pid, r.pid ? r.name : "?", (unsigned long long)addr, (unsigned long long)size);
}
