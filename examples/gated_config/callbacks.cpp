// The three callbacks behind gated_config and uhh_attach. Identical in every backend:
// state is plain lock-free memory, so it works on the controller's debug-loop thread
// (breakpoint / hw) and on many target threads at once (inline, inside the target).
#include "callbacks.h"
#include <atomic>

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

// 2. Handle -> pid map, built from ntdll!NtOpenProcess (PHANDLE out, ACCESS_MASK,
//    POBJECT_ATTRIBUTES, PCLIENT_ID): the syscall stub every OpenProcess path ends in.
//    At ENTRY the pid is known (cid->UniqueProcess) but the handle is not yet: it is
//    written to *out by the kernel. So remember the out pointer and dereference it
//    LAZILY, the first time a read uses a handle we have not resolved -- by then the
//    open has long returned. Resolved handles go into a direct table, so there is no
//    cap on how many opens are tracked.
namespace {
// UHH_SHARED: the map is ONE piece of memory for every backend -- the open probe and the
// read probe may run in different processes (breakpoint/hw in the controller, inline in
// the target) and still see each other's records. Plain values only (pids, target
// addresses, handles), constant-initialised, lock-free atomics.
//
// Resolved: a direct table, one slot per handle value (handle >> 2): the handle, and
// (open number << 32 | pid) of the open that produced it. A different handle landing on
// the same slot simply overwrites it (the full handle is compared on lookup).
constexpr uint32_t kHandleSlots = 0x10000;
struct Resolved {
    std::atomic<uint64_t> handle{0};
    std::atomic<uint64_t> open_pid{0};  // (open number + 1) << 32 | pid; 0 = empty
};
UHH_SHARED Resolved g_by_handle[kHandleSlots] = {};
// Pending: opens whose handle has not been read back yet, a ring of the newest ones.
// A slot is overwritten only after kPending newer opens none of whose handles was used
// in between (e.g. a process-list scan); resolved opens leave the ring at once.
constexpr uint32_t kPending = 4096;
struct PendingOpen {
    std::atomic<uint64_t> pid{0};       // 0 = empty / resolved
    std::atomic<uint64_t> out{0};       // where the open writes the handle
};
UHH_SHARED PendingOpen g_pending[kPending] = {};
UHH_SHARED std::atomic<uint32_t> g_open_count{0};

uint64_t read_pointer(probe_context *c, uint64_t address) {
    uintptr_t value = 0;                 // target pointer width == ours (same arch)
    return get_mem(c, address, &value, sizeof(value)) ? (uint64_t)value : 0;
}

// pid the handle was opened for, or 0 if no open we saw produced it. The table answers
// directly, unless an open NEWER than the one it remembers is still pending: those are
// checked newest first (each costs one read of its out-pointer), so a handle value reused
// after a close maps to the open that produced it most recently. A match goes into the table.
uint64_t pid_of(probe_context *c, uint64_t handle) {
    if (!handle) return 0;
    Resolved &slot = g_by_handle[(handle >> 2) % kHandleSlots];
    uint64_t known = 0;
    for (int tries = 0; tries < 4; ++tries) {                  // a consistent (handle, open_pid) pair
        const uint64_t v = slot.open_pid.load(std::memory_order_acquire);
        const bool same = slot.handle.load(std::memory_order_acquire) == handle;
        if (slot.open_pid.load(std::memory_order_acquire) == v) { known = same ? v : 0; break; }
    }
    const uint32_t since = (uint32_t)(known >> 32);           // opens below this are older
    const uint32_t n = g_open_count.load(std::memory_order_acquire);
    for (uint32_t k = n; k-- > since && n - k <= kPending;) {
        PendingOpen &r = g_pending[k % kPending];
        const uint64_t pid = r.pid.load(std::memory_order_acquire);
        if (!pid) continue;                                    // empty, or already resolved
        if (read_pointer(c, r.out.load(std::memory_order_relaxed)) != handle) continue;
        slot.handle.store(handle, std::memory_order_relaxed);
        slot.open_pid.store((uint64_t)(k + 1) << 32 | (pid & 0xffffffffu), std::memory_order_release);
        uint64_t expected = pid;
        r.pid.compare_exchange_strong(expected, 0);            // resolved: leave the ring
        return pid;
    }
    return known & 0xffffffffu;
}
}  // namespace

extern "C" void track_open_process(probe_context *c) {
    uint64_t out = get_func_arg(c, 0), cid = get_func_arg(c, 3);
    uint64_t pid = cid ? read_pointer(c, cid) : 0;     // CLIENT_ID.UniqueProcess
    if (!out || !pid) return;
    PendingOpen &r = g_pending[g_open_count.fetch_add(1, std::memory_order_relaxed) % kPending];
    r.pid.store(0, std::memory_order_relaxed);         // a wrapped slot: retire the old open first
    r.out.store(out, std::memory_order_relaxed);
    r.pid.store(pid, std::memory_order_release);       // publish
}

// 3. Every read through ntdll!NtReadVirtualMemory(handle,
//    address, buffer, size, done). Optionally filtered to one pid + one address range.
extern "C" void log_read(probe_context *c) {
    auto *cfg = static_cast<const read_log_config *>(get_config(c));
    if (!cfg || cfg->cookie != READ_LOG_COOKIE || !cfg->log) return;
    uint64_t handle = get_func_arg(c, 0), addr = get_func_arg(c, 1), size = get_func_arg(c, 3);
    uint64_t pid = pid_of(c, handle);
    if (cfg->filter && (pid != cfg->pid || addr < cfg->base || addr - cfg->base >= cfg->size)) return;
    send_log(c, "read handle=0x%llx pid=%llu addr=0x%llx size=%llu", (unsigned long long)handle,
             (unsigned long long)pid, (unsigned long long)addr, (unsigned long long)size);
}
