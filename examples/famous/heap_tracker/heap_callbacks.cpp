// Heap tracker (the classic Frida "leak hunter" / API Monitor HeapAlloc recipe).
//
//   ntdll!RtlAllocateHeap entry   caller in the main module?  remember the size (keyed by
//                                 the return-site SP) and make sure the call site has a
//                                 return probe
//   <call site> (return)          AX = the new block: insert {ptr,size} in the live table
//   ntdll!RtlFreeHeap entry       remove the block from the live table (any caller)
//   ntdll!RtlExitUserProcess      every block still live is a leak: one log each + summary
//
// The live table is a UHH_SHARED open-addressing hash, so the alloc probe, the return
// probe and the free probe agree on it whatever backend runs each of them.
#include "../common/famous_common.h"

namespace {

constexpr size_t kLive = 8192;          // power of two
constexpr uint64_t kTomb = ~0ull;

struct live_slot {
    std::atomic<uint64_t> ptr{0};       // 0 empty, kTomb removed, else a live block
    std::atomic<uint64_t> size{0};
};

} // namespace

UHH_SHARED famous_module g_heap_module{};
UHH_SHARED famous_site g_heap_sites[4]{};
UHH_SHARED famous_pending g_heap_pending[64]{};
UHH_SHARED live_slot g_heap_live[kLive]{};
UHH_SHARED std::atomic<int64_t> g_heap_allocs{0};
UHH_SHARED std::atomic<int64_t> g_heap_frees{0};
UHH_SHARED std::atomic<int64_t> g_heap_unmatched{0};    // return seen without its entry
UHH_SHARED std::atomic<int64_t> g_heap_overflow{0};     // table/pending full: a tracking loss
UHH_SHARED std::atomic<int64_t> g_heap_reported{0};

static size_t heap_hash(uint64_t p) {
    return (size_t)((p >> 4) * 0x9E3779B97F4A7C15ull >> 40) & (kLive - 1);
}

static bool live_insert(uint64_t p, uint64_t size) {
    for (size_t n = 0, i = heap_hash(p); n < kLive; ++n, i = (i + 1) & (kLive - 1)) {
        uint64_t cur = g_heap_live[i].ptr.load(std::memory_order_acquire);
        if (cur != 0 && cur != kTomb) continue;
        if (g_heap_live[i].ptr.compare_exchange_strong(cur, p, std::memory_order_acq_rel)) {
            g_heap_live[i].size.store(size, std::memory_order_release);   // read only at exit
            return true;
        }
    }
    return false;
}

static bool live_remove(uint64_t p) {
    for (size_t n = 0, i = heap_hash(p); n < kLive; ++n, i = (i + 1) & (kLive - 1)) {
        uint64_t cur = g_heap_live[i].ptr.load(std::memory_order_acquire);
        if (cur == 0) return false;                      // end of the probe chain: not tracked
        if (cur != p) continue;
        if (g_heap_live[i].ptr.compare_exchange_strong(cur, kTomb, std::memory_order_acq_rel)) return true;
    }
    return false;
}

FAMOUS_EXPORT void famous_heap_on_return(probe_context *c) {
    uint64_t size = 0, unused = 0;
    if (!famous_pending_take(g_heap_pending, 64, get_reg(c, PROBE_REG_SP), size, unused)) {
        g_heap_unmatched.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    uint64_t block = get_reg(c, PROBE_REG_AX);
    if (!block) return;                                  // allocation failed: nothing to track
    if (!live_insert(block, size)) { g_heap_overflow.fetch_add(1, std::memory_order_relaxed); return; }
    g_heap_allocs.fetch_add(1, std::memory_order_relaxed);
}

// RtlAllocateHeap(HeapHandle, Flags, Size)
FAMOUS_EXPORT void famous_heap_on_alloc(probe_context *c) {
    uint64_t ret = famous_return_address(c);
    if (!famous_in_main(c, g_heap_module, ret)) return;  // only the program's own call sites
    if (!famous_pending_put(g_heap_pending, 64, famous_return_sp(c, 3), get_func_arg(c, 2), 0)) {
        g_heap_overflow.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    famous_arm_return(c, g_heap_sites, 4, ret, famous_heap_on_return, famous_ret_flags(c));
}

// RtlFreeHeap(HeapHandle, Flags, BaseAddress) -- frees arrive from anywhere (kernel32's
// HeapFree wrapper, the CRT): untracked blocks simply miss.
FAMOUS_EXPORT void famous_heap_on_free(probe_context *c) {
    uint64_t block = get_func_arg(c, 2);
    if (block && live_remove(block)) g_heap_frees.fetch_add(1, std::memory_order_relaxed);
}

// RtlExitUserProcess(ExitStatus): the process is going away -- report what is still live.
FAMOUS_EXPORT void famous_heap_on_exit(probe_context *c) {
    if (g_heap_reported.exchange(1) != 0) return;
    int64_t leaks = 0;
    uint64_t bytes = 0;
    for (size_t i = 0; i < kLive; ++i) {
        uint64_t p = g_heap_live[i].ptr.load(std::memory_order_acquire);
        if (p == 0 || p == kTomb) continue;
        uint64_t size = g_heap_live[i].size.load(std::memory_order_relaxed);
        ++leaks; bytes += size;
        send_log(c, "heap-leak ptr=0x%llx size=%llu", (unsigned long long)p, (unsigned long long)size);
    }
    send_log(c, "heap-summary allocs=%lld frees=%lld leaks=%lld leaked_bytes=%llu unmatched=%lld overflow=%lld",
             (long long)g_heap_allocs.load(), (long long)g_heap_frees.load(), (long long)leaks,
             (unsigned long long)bytes, (long long)g_heap_unmatched.load(), (long long)g_heap_overflow.load());
}
