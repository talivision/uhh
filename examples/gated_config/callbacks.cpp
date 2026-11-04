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

// 2. Handle -> pid map, built from ntdll!NtOpenProcess(PHANDLE out, ACCESS_MASK,
//    POBJECT_ATTRIBUTES, PCLIENT_ID cid). At ENTRY the pid is known (cid->UniqueProcess)
//    but the handle is not yet: it is written to *out by the kernel. So remember the
//    out pointer and dereference it LAZILY, the first time a read uses a handle we have
//    not seen -- by then the open has long returned.
namespace {
struct OpenRecord {
    std::atomic<uint64_t> pid{0};       // 0 = slot not published yet
    std::atomic<uint64_t> out{0};       // where NtOpenProcess writes the handle
    std::atomic<uint64_t> handle{0};    // 0 = not resolved yet
};
constexpr uint32_t kMaxOpens = 1024;
OpenRecord g_opens[kMaxOpens];
std::atomic<uint32_t> g_open_count{0};

uint64_t read_pointer(probe_context *c, uint64_t address) {
    uintptr_t value = 0;                 // target pointer width == ours (same arch)
    return get_mem(c, address, &value, sizeof(value)) ? (uint64_t)value : 0;
}

// pid the handle was opened for, or 0 if no NtOpenProcess we saw produced it.
uint64_t pid_of(probe_context *c, uint64_t handle) {
    uint32_t n = g_open_count.load(std::memory_order_acquire);
    if (n > kMaxOpens) n = kMaxOpens;
    for (uint32_t i = 0; i < n; ++i)
        if (g_opens[i].handle.load(std::memory_order_relaxed) == handle) return g_opens[i].pid.load();
    for (uint32_t i = 0; i < n; ++i) {   // unknown: resolve pending opens by dereferencing
        OpenRecord &r = g_opens[i];
        uint64_t pid = r.pid.load(std::memory_order_acquire);
        if (!pid || r.handle.load(std::memory_order_relaxed)) continue;
        if (read_pointer(c, r.out.load()) != handle) continue;
        uint64_t expected = 0;
        r.handle.compare_exchange_strong(expected, handle);
        return pid;
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

// 3. Every read through probe_app.exe!ReadThunk, i.e. NtReadVirtualMemory(handle,
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
