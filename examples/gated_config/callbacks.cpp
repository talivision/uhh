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
//    It uses the same backend as the read probe: the map must live where the read
//    callback runs. At ENTRY the pid is known (cid->UniqueProcess)
//    but the handle is not yet: it is written to *out by the kernel. So remember the
//    out pointer and dereference it LAZILY, the first time a read uses a handle we have
//    not seen -- by then the open has long returned.
namespace {
struct OpenRecord {
    std::atomic<uint64_t> pid{0};       // 0 = slot not published yet
    std::atomic<uint64_t> out{0};       // where the open writes the handle
    std::atomic<uint64_t> handle{0};    // 0 = not resolved yet
};
constexpr uint32_t kMaxOpens = 1024;
// UHH_SHARED: the map is ONE piece of memory for every backend -- the open probe and the
// read probe may run in different processes (breakpoint/hw in the controller, inline in
// the target) and still see each other's records. Plain values only (pids, target
// addresses, handles), constant-initialised, lock-free atomics.
UHH_SHARED OpenRecord g_opens[kMaxOpens] = {};
UHH_SHARED std::atomic<uint32_t> g_open_count{0};

uint64_t read_pointer(probe_context *c, uint64_t address) {
    uintptr_t value = 0;                 // target pointer width == ours (same arch)
    return get_mem(c, address, &value, sizeof(value)) ? (uint64_t)value : 0;
}

// pid the handle was opened for, or 0 if no open we saw produced it. One pass, NEWEST
// open first: a resolved record is compared directly; an unresolved one is resolved by
// dereferencing its out-pointer. Newest-first means a handle value reused after a close
// maps to the open that produced it most recently. A record resolved concurrently by
// another thread is still matched (re-read after a lost CAS).
uint64_t pid_of(probe_context *c, uint64_t handle) {
    if (!handle) return 0;
    uint32_t n = g_open_count.load(std::memory_order_acquire);
    if (n > kMaxOpens) n = kMaxOpens;
    for (uint32_t k = n; k-- > 0;) {
        OpenRecord &r = g_opens[k];
        uint64_t pid = r.pid.load(std::memory_order_acquire);
        if (!pid) continue;                                    // claimed, not yet published
        uint64_t h = r.handle.load(std::memory_order_acquire);
        if (h) { if (h == handle) return pid; continue; }
        if (read_pointer(c, r.out.load(std::memory_order_relaxed)) != handle) continue;
        uint64_t expected = 0;
        if (r.handle.compare_exchange_strong(expected, handle) || expected == handle) return pid;
    }
    return 0;
}
}  // namespace

extern "C" void track_open_process(probe_context *c) {
    uint64_t out = get_func_arg(c, 0), cid = get_func_arg(c, 3);
    uint64_t pid = cid ? read_pointer(c, cid) : 0;     // CLIENT_ID.UniqueProcess
    if (!out || !pid) return;
    uint32_t slot = g_open_count.fetch_add(1, std::memory_order_relaxed);
    if (slot >= kMaxOpens) return;
    g_opens[slot].out.store(out, std::memory_order_relaxed);
    g_opens[slot].pid.store(pid, std::memory_order_release);   // publish
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
