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

// 2. Handle -> pid -> name map, built from ntdll!NtOpenProcess (PHANDLE out, ACCESS_MASK,
//    POBJECT_ATTRIBUTES, PCLIENT_ID): the syscall stub every OpenProcess path ends in.
//    At ENTRY the pid is known (cid->UniqueProcess) but the handle is not yet: it is
//    written to *out by the kernel. So remember the out pointer and dereference it
//    LAZILY, the first time a read uses a handle we have not resolved -- by then the
//    open has long returned. Resolved handles go into a direct table: no cap on how many
//    opens are tracked, and a lookup costs the same after a million opens as after one.
namespace {
// UHH_SHARED: the map is ONE piece of memory for every backend -- the open probe and the
// read probe may run in different processes (breakpoint/hw in the controller, inline in
// the target) and still see each other's records. Plain values only (pids, target
// addresses, handles), zero-initialised; every shared word is accessed atomically.
struct OpenRecord {                     // plain data: zero-initialised, no constructors
    uint64_t pid;                       // 0 = empty / resolved (pending ring), see below
    uint64_t out;                       // where the open writes the handle
    uint64_t handle;                    // table: the handle this slot holds
    char name[64];                      // image name of pid, written before pid is published
};
// Resolved: a direct table, one slot per handle value (handle >> 2), holding the handle,
// its pid and name, and the number of the open that produced it ("seq", in .out). A
// different handle landing on the same slot simply overwrites it (compared on lookup).
constexpr uint32_t kHandleSlots = 0x10000;
UHH_SHARED OpenRecord g_by_handle[kHandleSlots];
// Pending: opens whose handle has not been used yet, a ring of the newest ones. A slot is
// overwritten only after kPending newer opens none of whose handles was used in between
// (e.g. a process-list scan); an open leaves the ring as soon as a read resolves it.
constexpr uint32_t kPending = 4096;
UHH_SHARED OpenRecord g_pending[kPending];
UHH_SHARED std::atomic<uint32_t> g_open_count{0};

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

// Copy of the table entry for `handle` (pid 0 if none): seq in .out, a consistent pair.
OpenRecord table_lookup(uint64_t handle) {
    OpenRecord &slot = g_by_handle[(handle >> 2) % kHandleSlots];
    OpenRecord r{};
    for (int tries = 0; tries < 4; ++tries) {
        const uint64_t pid = at(slot.pid).load(std::memory_order_acquire);
        r.out = at(slot.out).load(std::memory_order_acquire);
        r.handle = at(slot.handle).load(std::memory_order_acquire);
        std::memcpy(r.name, slot.name, sizeof(r.name));
        if (at(slot.pid).load(std::memory_order_acquire) == pid) { r.pid = r.handle == handle ? pid : 0; break; }
    }
    r.name[sizeof(r.name) - 1] = 0;
    return r;
}

void table_store(uint64_t handle, uint64_t pid, uint64_t seq, const char *name) {
    OpenRecord &slot = g_by_handle[(handle >> 2) % kHandleSlots];
    std::memcpy(slot.name, name, sizeof(slot.name));
    at(slot.handle).store(handle, std::memory_order_relaxed);
    at(slot.out).store(seq, std::memory_order_relaxed);
    at(slot.pid).store(pid, std::memory_order_release);
}

// The open that produced `handle` (pid 0 if no open we saw produced it). The table answers
// directly, unless an open NEWER than the one it remembers is still pending: those are
// checked newest first (each costs one read of its out-pointer), so a handle value reused
// after a close maps to the open that produced it most recently. A match goes into the
// table (logged once) and leaves the pending ring.
OpenRecord open_of(probe_context *c, uint64_t handle) {
    if (!handle) return {};
    const OpenRecord known = table_lookup(handle);
    const uint64_t since = known.pid ? known.out : 0;                 // opens below this are older
    const uint32_t n = g_open_count.load(std::memory_order_acquire);
    for (uint32_t k = n; k-- > since && n - k <= kPending;) {
        OpenRecord &r = g_pending[k % kPending];
        const uint64_t pid = at(r.pid).load(std::memory_order_acquire);
        if (!pid) continue;                                            // empty, or already resolved
        if (read_pointer(c, at(r.out).load(std::memory_order_relaxed)) != handle) continue;
        char name[sizeof(r.name)];
        std::memcpy(name, r.name, sizeof(name)); name[sizeof(name) - 1] = 0;
        table_store(handle, pid, k + 1, name);                         // BEFORE leaving the ring
        uint64_t expected = pid;
        if (at(r.pid).compare_exchange_strong(expected, 0))            // the one resolver logs it
            send_log(c, "map handle=0x%llx -> pid=%llu name=%s", (unsigned long long)handle,
                     (unsigned long long)pid, name);
        return table_lookup(handle);
    }
    // Look again: another thread may have resolved this handle meanwhile (it fills the
    // table before clearing the pending entry we then skipped).
    return table_lookup(handle);
}
}  // namespace

extern "C" void track_open_process(probe_context *c) {
    uint64_t out = get_func_arg(c, 0), cid = get_func_arg(c, 3);
    uint64_t pid = cid ? read_pointer(c, cid) : 0;     // CLIENT_ID.UniqueProcess
    if (!out || !pid) return;
    char name[sizeof(OpenRecord::name)];
    image_name_of(pid, name, sizeof(name));
    send_log(c, "open pid=%llu name=%s", (unsigned long long)pid, name);
    OpenRecord &r = g_pending[g_open_count.fetch_add(1, std::memory_order_relaxed) % kPending];
    at(r.pid).store(0, std::memory_order_relaxed);     // a wrapped slot: retire the old open first
    std::memcpy(r.name, name, sizeof(name));
    at(r.out).store(out, std::memory_order_relaxed);
    at(r.pid).store(pid, std::memory_order_release);   // publish (name before pid)
}

// 2b. The same map in ONE callback, with nothing left for later (gated_config --open-mode
//     call): run the real NtOpenProcess now (call_original), read the handle it just wrote
//     to *out -- however short-lived that slot is (kernel32!OpenProcess's local) -- record
//     handle -> pid -> name, and make the caller see exactly the status it would have
//     (return_from: the open is not run again). Works for any caller and needs no access
//     right on the handle (a PROCESS_VM_READ-only handle cannot be asked for its pid later).
extern "C" void track_open_process_call(probe_context *c) {
    uint64_t out = get_func_arg(c, 0), cid = get_func_arg(c, 3);
    uint64_t pid = cid ? read_pointer(c, cid) : 0;     // CLIENT_ID.UniqueProcess (read before the call)
    uint64_t status = 0;
    if (!call_original(c, 4, &status)) return;         // could not run it here: fall through (it runs normally)
    uint64_t handle = (int32_t)status >= 0 && out ? read_pointer(c, out) : 0;
    if (pid && handle) {
        char name[sizeof(OpenRecord::name)];
        image_name_of(pid, name, sizeof(name));
        send_log(c, "open pid=%llu name=%s", (unsigned long long)pid, name);
        const uint32_t seq = g_open_count.fetch_add(1, std::memory_order_relaxed);
        at(g_pending[seq % kPending].pid).store(0, std::memory_order_relaxed);   // its ring slot: nothing pending
        table_store(handle, pid, seq + 1, name);
        send_log(c, "map handle=0x%llx -> pid=%llu name=%s", (unsigned long long)handle,
                 (unsigned long long)pid, name);
    }
    return_from(c, status, 4);                          // the caller sees exactly what it would have
}

// 3. Every read through ntdll!NtReadVirtualMemory(handle,
//    address, buffer, size, done). Optionally filtered by pid and/or address ranges.
extern "C" void log_read(probe_context *c) {
    auto *cfg = static_cast<const read_log_config *>(get_config(c));
    if (!cfg || cfg->cookie != READ_LOG_COOKIE || !cfg->log) return;
    uint64_t handle = get_func_arg(c, 0), addr = get_func_arg(c, 1), size = get_func_arg(c, 3);
    const OpenRecord r = open_of(c, handle);
    const uint64_t pid = r.pid;
    if (cfg->pid && pid != cfg->pid) return;
    if (cfg->nranges) {
        bool in = false;
        for (uint32_t k = 0; k < cfg->nranges && k < READ_LOG_MAX_RANGES && !in; ++k)
            in = addr - cfg->ranges[k].base < cfg->ranges[k].size;   // unsigned: also addr < base
        if (!in) return;
    }
    send_log(c, "read handle=0x%llx pid=%llu name=%s addr=0x%llx size=%llu", (unsigned long long)handle,
             (unsigned long long)pid, pid ? r.name : "?", (unsigned long long)addr, (unsigned long long)size);
}
