#include "win_common.hpp"
#include "probe_log_format.hpp"
#include "probe_agent_shared.hpp"
#include <safetyhook.hpp>
#include <Zydis/Zydis.h>
#include <tlhelp32.h>
#include <array>
#include <algorithm>
#include <bitset>
#include <vector>
#include <utility>
#include <cstdarg>
#include <intrin.h>
#include <immintrin.h>
#include <new>
#include <type_traits>

static HMODULE self_module;
static HANDLE mapping;
static probe_agent_shared *volatile shared;  // MSVC volatile: whole pointer publication on x64/x86
// Never destroyed: at process exit a static array's destructors would unhook through
// SafetyHook's stock path (page made non-executable while other threads may still run,
// and on ntdll stub pages the installer then faults on itself). The process is going
// away; its code is never restored. Explicit removal (probe_agent_stop) runs frozen.
static SafetyHookMid *const hooks = new SafetyHookMid[PROBE_AGENT_MAX_PROBES];
static uint64_t sites[PROBE_AGENT_MAX_PROBES];
static probe_callback callbacks[PROBE_AGENT_MAX_PROBES];

struct probe_session { uint32_t site; };
struct AgentState { probe_agent_shared *shared; uint32_t index; probe_session proxy; };
static_assert(sizeof(AgentState) == (sizeof(void *) == 8 ? 16 : 12), "keep proxy in the x64 state padding");
static AgentState *states;                             // immutable per-channel objects, retained with its view
static __forceinline LONG load_epoch(const probe_agent_shared *sh) {
    return __iso_volatile_load32(reinterpret_cast<const volatile __int32 *>(&sh->session_epoch));
}

/* Callback memory helpers fail closed on bad target addresses. They never change
   page protections: executable writes belong to the hook installer, not hits. */
/* Own committed stack needs no query. All other protection verdicts last only one
   callback, including image regions. Protection changes racing
   those verdicts are outside the guarantee (see limitations.md). Target calls invalidate
   protection verdicts too, so a callback can change protection through call_func safely. */
struct RegionCache {
    uintptr_t lo = 0, hi = 0;
    LONG gen = 0;
    bool writable = false, readable = false, executable = false, image = false;
};
// constinit is required on every hit-path TLS object: MSVC must not emit an
// on-demand TLS initializer (and its calls) before the recursion guard is established.
static constinit thread_local RegionCache t_region{};
// Loader unload notifications invalidate region and symbol-resolution caches.
static volatile LONG g_unload_gen;
static void *g_dll_cookie;
// K32QueryWorkingSetEx (resolved with the unload notification): the x86 stack capture's
// one-page protection probe (see X86Mem::fast_image).
using qwsex_fn = BOOL(WINAPI *)(HANDLE, PVOID, DWORD);
static qwsex_fn g_qwsex;
struct ImageRegions { RegionCache r[16]; LONG gen = 0; uint32_t used = 0, next = 0; };
static constinit thread_local ImageRegions t_images{};

// The per-thread cache is implicit TLS -- which does not exist yet on a thread that is
// still in its loader initialisation: LdrpInitializeThread allocates the thread's TLS
// block with RtlAllocateHeap, so an inline probe on the allocator (a heap tracker) runs
// its callback there with TEB->ThreadLocalStoragePointer (or this module's slot in it)
// still NULL, and touching t_region faults -- recursively, through the exception
// dispatcher's own allocations, until the stack overflows and the target dies. Found by
// examples/famous heap_tracker (inline). No TLS yet = no cache: validate every time.
extern "C" unsigned long _tls_index;
static bool tls_ready() {             // this module's implicit TLS exists on this thread
#if defined(_WIN64)
    void **array = *reinterpret_cast<void ***>(reinterpret_cast<unsigned char *>(NtCurrentTeb()) + 0x58);
#else
    void **array = *reinterpret_cast<void ***>(reinterpret_cast<unsigned char *>(NtCurrentTeb()) + 0x2C);
#endif
    return array && array[_tls_index];
}
static RegionCache *region_cache() { return tls_ready() ? &t_region : nullptr; }

// Shared by get_mem/set_mem and stack capture: no loader calls or allocations on a hit.
static bool query_region(uintptr_t a, RegionCache &out, bool cached_image = true) {
    ImageRegions *images = cached_image && tls_ready() && g_dll_cookie ? &t_images : nullptr;
    const LONG gen = g_unload_gen;
    if (images) {
        // forget_region clears t_region at callback entry. Clear lazily here so hits
        // that never query memory pay no extra cost. Unload notifications precede
        // unmapping, so their generation alone cannot validate later callbacks.
        if (!t_region.lo || images->gen != gen) { images->used = images->next = 0; images->gen = gen; }
        for (uint32_t i = 0; i < images->used; ++i)
            if (a >= images->r[i].lo && a < images->r[i].hi) { out = images->r[i]; return true; }
    }
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((void *)a, &mbi, sizeof(mbi))) return false;
    out.lo = (uintptr_t)mbi.BaseAddress; out.hi = out.lo + mbi.RegionSize; out.gen = gen;
    if (out.hi <= out.lo) out.hi = ~(uintptr_t)0;
    const DWORD prot = mbi.Protect & 0xFF;
    const bool committed = mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD);
    out.writable = committed && (prot == PAGE_READWRITE || prot == PAGE_WRITECOPY ||
                                prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
    out.readable = out.writable || (committed && (prot == PAGE_READONLY || prot == PAGE_EXECUTE_READ));
    out.image = mbi.Type == MEM_IMAGE;
    out.executable = out.readable && out.image && (prot == PAGE_EXECUTE_READ ||
                     prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
    if (images && out.image && out.readable && g_unload_gen == gen) {
        const uint32_t slot = images->used < 16 ? images->used++ : (images->next++ & 15);
        images->r[slot] = out;
    }
    return true;
}
static bool range_ok(uintptr_t a, size_t n, bool write) {
    if (!n) return true;
    if (a + n < a) return false;
    const NT_TIB *tib = reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
    if (a >= (uintptr_t)tib->StackLimit && a + n <= (uintptr_t)tib->StackBase) return true;
    RegionCache scratch, *cache = region_cache();
    if (!cache) cache = &scratch;
    const uintptr_t end = a + n;
    while (a < end) {
        if (a >= cache->lo && a < cache->hi &&
            (!cache->image || (g_dll_cookie && cache->gen == g_unload_gen))) {
            if (!cache->readable || (write && !cache->writable)) return false;
            a = cache->hi; continue;
        }
        if (!query_region(a, *cache) || !cache->readable || (write && !cache->writable)) return false;
        a = cache->hi;
    }
    return true;
}
static void forget_region(bool images = false) {
    if (RegionCache *cache = region_cache()) {
        *cache = {};
        if (images) t_images.used = t_images.next = 0;
    }
}
// The bytes each installed hook overwrote, so a callback reading code sees the PROGRAM's
// bytes (as the breakpoint backend shows the original byte under its INT3 and hw changes
// nothing), not the hook's jump. Published after the jump is written, withdrawn before it
// is removed; a reader checks the request is still INSTALLED (not unloaded/reused).
struct PatchShadow { volatile uintptr_t lo; uint32_t len; uint8_t bytes[32]; };
static PatchShadow g_shadow[PROBE_AGENT_MAX_PROBES];
static volatile LONG g_shadow_count;
// Every shadow published lies in [g_shadow_min, g_shadow_max) (it only widens): a read outside
// it -- the hit's own stack, a heap buffer: get_func_arg on x86 on every hit -- skips the scan of
// the 128 slots (x86 hit with two stack arguments read: measured ~360 ns, most of it here).
static volatile uintptr_t g_shadow_min = ~(uintptr_t)0, g_shadow_max = 0;
static void overlay_original(uintptr_t a, void *buffer, size_t n) {
    if (a >= g_shadow_max || a + n <= g_shadow_min) return;
    for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i) {
        const uintptr_t lo = g_shadow[i].lo;
        if (!lo || !shared || shared->requests[i].status != PROBE_AGENT_INSTALLED) continue;
        const uintptr_t hi = lo + g_shadow[i].len;
        if (hi <= a || lo >= a + n) continue;
        for (uintptr_t x = lo > a ? lo : a; x < hi && x < a + n; ++x)
            static_cast<uint8_t *>(buffer)[x - a] = g_shadow[i].bytes[x - lo];
    }
}
// A target address this process cannot hold (x86: at or above 4 GB, or a range ending past
// it) is refused -- as the controller refuses it -- instead of being truncated to 32 bits,
// which read or WROTE a different, valid address (rw + 4 GB landed on rw).
static bool addressable(uint64_t a, size_t n) {
#if defined(_WIN64)
    (void)a; (void)n; return true;
#else
    return a <= 0xFFFFFFFFull && (uint64_t)n <= 0x100000000ull - a;
#endif
}
// The program's byte under each armed breakpoint-backend INT3 (shared->int3, see there):
// EVERY one in [a, a + n), as breakpoint/hw show them. The table is sorted by address, so the
// entries in range are one run found by binary search: O(log count + hits in range). They
// are applied in batches, each read under the seqlock and applied only once validated; a
// rewrite in between restarts the scan (a byte already restored is no longer 0xCC, so
// redoing a batch is harmless).
static void overlay_int3(uint64_t a, void *buffer, size_t n) {
    auto *out = static_cast<uint8_t *>(buffer);
    for (int attempt = 0; attempt < 64; ++attempt) {
        const LONG seq = shared->int3_seq;
        if (seq & 1) { YieldProcessor(); continue; }
        MemoryBarrier();
        LONG count = shared->int3_count;
        if (count > (LONG)PROBE_AGENT_INT3_CAP) count = PROBE_AGENT_INT3_CAP;
        LONG lo = 0, hi = count;                           // first entry at or above a
        while (lo < hi) {
            const LONG mid = lo + (hi - lo) / 2;
            if (shared->int3[mid].address < a) lo = mid + 1; else hi = mid;
        }
        bool torn = false;
        while (!torn) {
            struct { uint64_t at; uint8_t b; } fix[64]; int nfix = 0;
            for (; lo < count && nfix < 64; ++lo) {
                const uint64_t x = shared->int3[lo].address;
                if (x < a || x - a >= n) break;
                fix[nfix++] = {x, shared->int3[lo].original};
            }
            MemoryBarrier();
            if (shared->int3_seq != seq) { torn = true; break; }
            for (int k = 0; k < nfix; ++k)
                if (out[fix[k].at - a] == 0xCC) out[fix[k].at - a] = fix[k].b;
            if (nfix < 64) return;                         // the run ended
        }
    }
}
static int local_read(void *, uint64_t address, void *buffer, size_t size, size_t *done) {
    *done = 0;
    if (size && !addressable(address, size)) return 0;
    if (!range_ok((uintptr_t)address, size, false)) return 0;
    __try { std::memcpy(buffer, (const void *)(uintptr_t)address, size); *done = size; }
    __except (EXCEPTION_EXECUTE_HANDLER) { forget_region(true); return 0; }
    if (g_shadow_count) overlay_original((uintptr_t)address, buffer, size);
    if (shared && shared->int3_count) overlay_int3(address, buffer, size);
    return 1;
}
static int local_write(void *, uint64_t address, const void *buffer, size_t size, size_t *done) {
    *done = 0;
    if (size && !addressable(address, size)) return 0;
    if (!range_ok((uintptr_t)address, size, true)) return 0;
    __try { std::memcpy((void *)(uintptr_t)address, buffer, size); *done = size; return 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { forget_region(true); return 0; }
}
static const probe_ops local_ops{local_read, local_write};

static uint64_t *register_slot(probe_context *c, enum probe_register reg) {
    if (!c) return nullptr;
    switch (reg) {
    case PROBE_REG_AX: return &c->regs.rax; case PROBE_REG_BX: return &c->regs.rbx;
    case PROBE_REG_CX: return &c->regs.rcx; case PROBE_REG_DX: return &c->regs.rdx;
    case PROBE_REG_SI: return &c->regs.rsi; case PROBE_REG_DI: return &c->regs.rdi;
    case PROBE_REG_BP: return &c->regs.rbp; case PROBE_REG_SP: return &c->regs.rsp;
#if defined(_WIN64)
    case PROBE_REG_R8: return &c->regs.r8; case PROBE_REG_R9: return &c->regs.r9;
    case PROBE_REG_R10: return &c->regs.r10; case PROBE_REG_R11: return &c->regs.r11;
    case PROBE_REG_R12: return &c->regs.r12; case PROBE_REG_R13: return &c->regs.r13;
    case PROBE_REG_R14: return &c->regs.r14; case PROBE_REG_R15: return &c->regs.r15;
#endif
    default: return nullptr;  /* x86: R8..R15 are unsupported -> null slot */
    }
}

// Non-null only in the CONTROLLER's copy of this DLL (UHH_SHARED callbacks run there for
// breakpoint/hw probes): every API entry point then forwards to the controller library.
// In the target it stays null -- one predictable branch per call.
static const probe_controller_api *g_ctrl;
extern "C" __declspec(dllexport) void probe_agent_bind_controller(const probe_controller_api *api) { g_ctrl = api; }

extern "C" uint64_t get_reg(probe_context *c, enum probe_register reg) {
    if (g_ctrl) return g_ctrl->get_reg(c, reg);
    uint64_t *slot = register_slot(c, reg);
    return slot ? *slot : 0;
}
extern "C" int set_reg(probe_context *c, enum probe_register reg, uint64_t value) {
    if (g_ctrl) return g_ctrl->set_reg(c, reg, value);
    // Inline set_reg(SP) is honoured: the (patched) SafetyHook stub resumes with
    // `pop rsp; jmp [trampoline]`, loading the context's rsp -- see call_mid.
    uint64_t *slot = register_slot(c, reg); if (!slot) return 0;
#if !defined(_WIN64)
    value = (uint32_t)value;   // x86: the register keeps the low 32 bits; get_reg says so (TH3)
#endif
    if (*slot != value) {
        *slot = value;
        auto *state = static_cast<AgentState *>(c->controller);
        if (state && state->shared) InterlockedIncrement64(&state->shared->overrides);   // same metric as controller
    }
    return 1;
}
extern "C" int get_mem(probe_context *c, uint64_t address, void *buffer, size_t size) {
    if (g_ctrl) return g_ctrl->get_mem(c, address, buffer, size);
    if (!c || !c->ops || !c->ops->read || (!buffer && size)) return 0;
    size_t done{}; return c->ops->read(c->backend, address, buffer, size, &done) && done == size;
}
extern "C" int set_mem(probe_context *c, uint64_t address, const void *buffer, size_t size) {
    if (g_ctrl) return g_ctrl->set_mem(c, address, buffer, size);
    if (!c || !c->ops || !c->ops->write || (!buffer && size)) return 0;
    size_t done{}; return c->ops->write(c->backend, address, buffer, size, &done) && done == size;
}
#if !defined(_WIN64)
// x86 get_func_arg, every hit (the arguments are on the stack): what local_read does for the hit
// thread's own stack -- range_ok trusts it above this frame -- without the indirect call, the
// SEH frame and the overlay passes, which find nothing there: hook shadows and breakpoint INT3
// bytes are code. Checked, not assumed: the address must lie outside every published shadow and
// outside the INT3 table's address span (read under its seqlock); else the full path runs.
static bool stack_arg(uint64_t address, uint32_t &value) {
    if (address > 0xFFFFFFFBull) return false;
    const uintptr_t a = (uintptr_t)address;
    const NT_TIB *tib = reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
    const uintptr_t here = (uintptr_t)_AddressOfReturnAddress();
    if (here < (uintptr_t)tib->StackLimit || here >= (uintptr_t)tib->StackBase || a < here ||
        a + 4 > (uintptr_t)tib->StackBase)
        return false;
    if (g_shadow_count && a < g_shadow_max && a + 4 > g_shadow_min) return false;
    if (shared && shared->int3_count) {
        const LONG seq = shared->int3_seq;
        if (seq & 1) return false;
        MemoryBarrier();
        LONG count = shared->int3_count;
        if (count > (LONG)PROBE_AGENT_INT3_CAP) count = PROBE_AGENT_INT3_CAP;
        const bool clear = count <= 0 || a + 4 <= shared->int3[0].address || a > shared->int3[count - 1].address;
        MemoryBarrier();
        if (!clear || shared->int3_seq != seq) return false;
    }
    value = *reinterpret_cast<const volatile uint32_t *>(a);
    return true;
}
#endif
extern "C" uint64_t get_func_arg(probe_context *c, size_t index) {
    if (g_ctrl) return g_ctrl->get_func_arg(c, index);
    if (!c) return 0;
#if defined(_WIN64)
    /* x64 __fastcall: first four args in registers, rest above the shadow space. */
    switch (index) {
    case 0: return c->regs.rcx; case 1: return c->regs.rdx;
    case 2: return c->regs.r8; case 3: return c->regs.r9;
    default: {
        if (c->regs.rsp > UINT64_MAX - 8 || index > (UINT64_MAX - c->regs.rsp - 8) / 8) return 0;
        uint64_t value{}, address = c->regs.rsp + 8 + 8 * index;
        return get_mem(c, address, &value, sizeof(value)) ? value : 0;
    }
    }
#else
    /* x86 __stdcall: every arg on the stack at [esp+4+4*i], read exactly 4 bytes. */
    if (c->regs.rsp > UINT64_MAX - 4 || index > (UINT64_MAX - c->regs.rsp - 4) / 4) return 0;
    uint32_t value{}; uint64_t address = c->regs.rsp + 4 + 4 * index;
    if (c->ops == &local_ops && stack_arg(address, value)) return value;
    return get_mem(c, address, &value, sizeof(value)) ? value : 0;
#endif
}

#if !defined(_WIN64)
// True when addr follows a call instruction: E8 rel32, or FF /2 (call r/m32) in its
// 2/3/6/7-byte forms. Caller holds an SEH guard (addr may be unmapped).
static bool looks_like_return(uint32_t addr) {
    const unsigned char *p = (const unsigned char *)(uintptr_t)addr;
    if (p[-5] == 0xE8) return true;
    if (p[-2] == 0xFF && ((p[-1] >> 3) & 7) == 2 && (p[-1] >> 6) == 3) return true;           // call reg
    if (p[-2] == 0xFF && ((p[-1] >> 3) & 7) == 2 && (p[-1] >> 6) == 0 && (p[-1] & 7) != 4 && (p[-1] & 7) != 5) return true;
    if (p[-3] == 0xFF && ((p[-2] >> 3) & 7) == 2 && (p[-2] >> 6) == 1) return true;            // call [reg+disp8]
    if (p[-6] == 0xFF && ((p[-5] >> 3) & 7) == 2 && ((p[-5] >> 6) == 2 || (p[-5] & 0xC7) == 5)) return true; // disp32 / [abs]
    if (p[-7] == 0xFF && ((p[-6] >> 3) & 7) == 2 && (p[-6] >> 6) == 2 && (p[-6] & 7) == 4) return true;      // SIB+disp32
    return false;
}

// ---- x86 stack walk without unwind data -------------------------------------------------
// x86 images carry no .pdata, and the frame-pointer chain alone skips (or stops at) frames
// of frame-pointer-omitted (/Oy, FPO) code: mid-function in an FPO function EBP still
// frames an ANCESTOR, or holds data when EBP is used as a general register. The
// controller's dbghelp walk reads the PDB's FPO data; the agent cannot (no PDB I/O at a
// hit), so it scans the stack for the return address and VERIFIES each candidate by the
// call instruction that precedes it:
//   EXACT    a direct call (E8, or FF 15 through the IAT; E9 / FF 25 thunks followed)
//            whose target starts the function holding the pc: target <= pc, within
//            256 KiB, and no int3 padding (CC CC: MSVC's inter-function fill) between
//   UNKNOWN  an indirect call (call reg / [reg+disp]): the target cannot be known
//   OTHER    a direct call to some other function (a stale value, or a tail-jumped callee)
// Per frame: the lowest EXACT slot wins, then (frame 0 only) a call-encoding [esp], then
// [ebp+4] while EBP still frames something above the stack pointer, then the lowest
// UNKNOWN, then the lowest OTHER. EBP is kept or
// recovered (an EBP-framed or EBP-saving callee leaves the caller's EBP just below its
// return slot) as a bound and tie-break only.
// Stack reads use TEB committed-stack bounds. Speculative code/data reads re-query each
// region once per capture, including images (cdx-codeprot). Scans are bounded
// (16 KiB per frame, 128 region lookups); the same protection-race policy as get_mem applies.

// Large image runs seen by this thread's stack captures (VirtualQuery answers), valid until a DLL
// unloads. VirtualQuery's cost grows with the pages from the queried address to the END of its run
// (WOW64 measured: 3.8 us at the start of ntdll's 176-page .text, 0.45 us for one page), so for an
// address in such a run the capture asks QueryWorkingSetEx about just the page(s) it will read:
// a page it reports VALID is hardware-accessible (PAGE_GUARD / PAGE_NOACCESS pages are never valid:
// measured, and that is how the OS traps them) with its exact protection. Any other answer (not
// resident, guarded, no access) takes the VirtualQuery path, so the verdicts are the same. Only the
// "this range is an image" part is remembered; a section unmapped outside the loader (no
// notification) could keep an image verdict for non-image code until the next unload.
struct ImageRuns { uintptr_t lo[8], hi[8]; LONG gen = 0; uint32_t used = 0, next = 0; };
static constinit thread_local ImageRuns t_image_runs{};
struct X86Mem {
    struct Region { uint32_t lo, hi; bool read, exec; };
    // Retain every query in this capture: scanning stack data can encounter more than
    // 16 regions, and evicting code/IAT regions paid for the same WOW64 query again.
    Region r[128]; uint32_t used = 0, last = 0; int budget = 128;
    Region stack;
    X86Mem() {
        const NT_TIB *tib = reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
        stack = Region{(uint32_t)(uintptr_t)tib->StackLimit,
                       (uint32_t)(uintptr_t)tib->StackBase, true, false};
    }
    const Region *keep(const Region &g) {
        // At most one entry per query, so the query budget also bounds this array.
        last = used++;
        r[last] = g;
        return &r[last];
    }
    // [a, a+n) within one remembered image run, every page valid and readable (and executable when
    // exec): one QueryWorkingSetEx call. False = ask VirtualQuery.
    static bool fast_image(uint32_t a, uint32_t n, bool exec, Region &g) {
        if (!g_qwsex || !g_dll_cookie || !tls_ready() || !n) return false;
        const ImageRuns &runs = t_image_runs;
        const uint32_t first = a & ~0xFFFu, last = (a + n - 1) & ~0xFFFu;
        if (a + n < a || last < first || (last - first) / 0x1000 >= 8 || runs.gen != g_unload_gen) return false;
        uint32_t i = 0;
        while (i < runs.used && !(first >= runs.lo[i] && (uintptr_t)last + 0x1000 <= runs.hi[i])) ++i;
        if (i == runs.used) return false;
        const uint32_t pages = (last - first) / 0x1000 + 1;
        struct { PVOID va; ULONG_PTR flags; } w[8];
        for (uint32_t k = 0; k < pages; ++k) { w[k].va = (PVOID)(uintptr_t)(first + k * 0x1000); w[k].flags = 0; }
        if (!g_qwsex(GetCurrentProcess(), w, pages * sizeof(w[0]))) return false;
        bool all_exec = true;
        for (uint32_t k = 0; k < pages; ++k) {
            if (!(w[k].flags & 1)) return false;                                  // not valid: VirtualQuery decides
            const DWORD prot = (DWORD)(w[k].flags >> 4) & 0xFF;   // Valid:1, ShareCount:3, Win32Protection:11
            const bool x = prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
            if (!x && prot != PAGE_READONLY && prot != PAGE_READWRITE && prot != PAGE_WRITECOPY) return false;
            all_exec = all_exec && x;
        }
        if (exec && !all_exec) return false;
        g.lo = first; g.hi = last + 0x1000; g.read = true; g.exec = all_exec;
        return true;
    }
    const Region *find(uint32_t a, uint32_t n, bool exec) {
        if (a >= stack.lo && a < stack.hi) return &stack;
        if (used && a >= r[last].lo && a < r[last].hi) return &r[last];
        for (uint32_t i = 0; i < used; ++i) {
            if (a >= r[i].lo && a < r[i].hi) { last = i; return &r[i]; }
        }
        if (budget <= 0) return nullptr;
        --budget;
        { Region f{}; if (fast_image(a, n, exec, f)) return keep(f); }
        RegionCache region{};
        const LONG ugen = g_unload_gen;
        // These are speculative stack values, not known module frames. A still-loaded
        // image can be guarded between captures: use this capture's own cache here.
        if (!query_region((uintptr_t)a, region, false)) return nullptr;
        if (region.image && region.readable && region.hi - region.lo >= 0x8000 && g_dll_cookie && tls_ready() &&
            ugen == g_unload_gen) {
            ImageRuns &runs = t_image_runs;
            if (runs.gen != ugen) { runs.gen = ugen; runs.used = runs.next = 0; }
            uint32_t at = 0;                                   // a run seen again (from a lower address) is widened
            while (at < runs.used && runs.hi[at] != region.hi) ++at;
            const uintptr_t lo = at < runs.used && runs.lo[at] < region.lo ? runs.lo[at] : region.lo;
            if (at == runs.used) at = runs.used < 8 ? runs.used++ : (runs.next++ & 7);
            runs.lo[at] = lo; runs.hi[at] = region.hi;
        }
        Region g{};
        g.lo = (uint32_t)region.lo;
        g.hi = (uint32_t)region.hi;
        g.read = region.readable; g.exec = region.executable;
        return keep(g);
    }
    // [a, a+n) lies in ONE readable region (and in executable image code when exec).
    bool ok(uint32_t a, uint32_t n, bool exec) {
        if (!n || a + n < a) return false;
        const Region *g = find(a, n, exec);
        return g && g->read && (!exec || g->exec) && a + n <= g->hi;
    }
};

enum class X86Ret { NO, OTHER, UNKNOWN, EXACT };
constexpr uint32_t X86_FN_MAX = 0x40000;

static bool return_checked(X86Mem &m, uint32_t ret) {
    return ret >= 0x10000 && m.ok(ret - 7, 8, true) && looks_like_return(ret);
}

// Does the function starting at t hold pc? (t <= pc, close, no int3 padding between.)
static bool x86_contains(X86Mem &m, uint32_t t, uint32_t pc) {
    if (t > pc || pc - t > X86_FN_MAX) return false;
    if (pc == t) return true;
    if (!m.ok(t, pc - t, true)) return false;
    const unsigned char *q = (const unsigned char *)(uintptr_t)t;
    for (uint32_t i = 0; i + 1 < pc - t; ++i)
        if (q[i] == 0xCC && q[i + 1] == 0xCC) return false;                      // a function boundary
    return true;
}

// The call target, then each thunk hop (E9 ILT jmp, FF 25 jmp [IAT]); EXACT if any of them
// starts the function holding pc. Every hop is checked -- the first one too, because the
// target may itself be an inline-hooked entry whose first bytes are now OUR jmp.
static bool x86_target_holds(X86Mem &m, uint32_t t, uint32_t pc) {
    for (int hop = 0; hop < 4; ++hop) {
        if (x86_contains(m, t, pc)) return true;
        if (hop == 3 || !m.ok(t, 6, true)) return false;
        const unsigned char *p = (const unsigned char *)(uintptr_t)t;
        if (p[0] == 0xE9) t = t + 5 + *(const int32_t *)(p + 1);
        else if (p[0] == 0xFF && p[1] == 0x25) {
            const uint32_t slot = *(const uint32_t *)(p + 2);
            if (!m.ok(slot, 4, false)) return false;
            t = *(const uint32_t *)(uintptr_t)slot;
        } else return false;
    }
    return false;
}

static X86Ret x86_classify(X86Mem &m, uint32_t ret, uint32_t pc) {
    if (ret < 0x10000 || !m.ok(ret - 7, 8, true)) return X86Ret::NO;
    const unsigned char *p = (const unsigned char *)(uintptr_t)ret;
    uint32_t target = 0;
    if (p[-5] == 0xE8) target = ret + *(const int32_t *)(p - 4);
    else if (p[-6] == 0xFF && p[-5] == 0x15) {                                   // call [abs]
        const uint32_t slot = *(const uint32_t *)(p - 4);
        if (!m.ok(slot, 4, false)) return X86Ret::UNKNOWN;
        target = *(const uint32_t *)(uintptr_t)slot;
    } else return looks_like_return(ret) ? X86Ret::UNKNOWN : X86Ret::NO;
    return x86_target_holds(m, target, pc) ? X86Ret::EXACT : X86Ret::OTHER;
}

static uint32_t walk_x86(const probe_context *c, uint64_t *frames, uint32_t n, uint32_t cap) {
    const NT_TIB *tib = reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
    const uint32_t lo = (uint32_t)(uintptr_t)tib->StackLimit, hi = (uint32_t)(uintptr_t)tib->StackBase;
    auto on_stack = [&](uint32_t a, uint32_t len) { return hi >= len && a >= lo && a <= hi - len; };
    auto rd = [](uint32_t a) { return *(const uint32_t *)(uintptr_t)a; };      // only after on_stack
    X86Mem m;
    constexpr uint32_t WINDOW = 0x4000;
    uint32_t pc = (uint32_t)c->regs.pc, sp = (uint32_t)c->regs.rsp, bp = (uint32_t)c->regs.rbp;
    // EBP frames something at or above `floor`: [bp] a saved frame, [bp+4] a return address.
    auto framed = [&](uint32_t b, uint32_t floor) {
        return b >= floor && on_stack(b, 8) && return_checked(m, rd(b + 4));
    };
    while (n < cap && on_stack(sp, 4)) {
        const bool anchored = framed(bp, sp);
        const uint32_t limit = hi - 4;
        uint32_t end = (limit - sp < WINDOW) ? limit : sp + WINDOW;
        if (anchored && bp + 4 < end) end = bp + 4;
        uint32_t exact = 0, unknown = 0, other = 0;
        // A stack often repeats a return address (saved registers, stale slots).
        // Classification includes scanning target bytes for padding; reuse it only
        // for this pc, within this capture. Collisions simply replace an entry.
        struct Candidate { uint32_t ret; X86Ret kind; };
        Candidate candidates[32]{};
        for (uint32_t a = sp; a <= end; a += 4) {
            const uint32_t ret = rd(a);
            if (ret < 0x10000) continue;
            Candidate &cached = candidates[((ret >> 2) ^ (ret >> 9)) & 31];
            const X86Ret k = cached.ret == ret ? cached.kind : x86_classify(m, ret, pc);
            cached = Candidate{ret, k};
            if (k == X86Ret::EXACT) { exact = a; break; }
            if (k == X86Ret::UNKNOWN && !unknown) unknown = a;
            if (k == X86Ret::OTHER && !other) other = a;
        }
        // Frame 0 only: a call-encoding [esp] is the return address (the site is a function's
        // first instruction, e.g. reached by call reg) -- the controller applies the same rule.
        const bool top = n == 1 && return_checked(m, rd(sp));
        const uint32_t slot = exact ? exact : top ? sp : anchored ? bp + 4 : unknown ? unknown : other;
        if (!slot) break;
        const uint32_t ret = rd(slot);
        if (!ret) break;
        frames[n++] = ret;
        if (anchored && slot == bp + 4) {
            bp = rd(bp);                                  // the plain EBP-chain step
        } else if (!framed(bp, slot + 4)) {
            const uint32_t saved = on_stack(slot - 4, 4) ? rd(slot - 4) : 0;
            bp = framed(saved, slot + 4) ? saved : 0;
        }
        pc = ret; sp = slot + 4;
    }
    return n;
}
#endif

#if defined(_WIN64)
// ---- x64 frame 0 at an INLINE site ------------------------------------------------------
// RtlVirtualUnwind decides "is pc in an epilogue?" by decoding the code AT pc. At a hooked
// site that code is our jmp to the hook stub -- a jmp leaving the function, i.e. a tail-call
// epilogue to the unwinder -- so it would take [rsp] as the return address and report
// garbage for any site past a prolog that moved rsp. Frame 0 is therefore unwound here,
// from the hook's ORIGINAL bytes: the epilogue check on them, else the function's unwind
// codes (UNWIND_INFO), exactly as the OS unwinder interprets them. Later frames are return
// addresses (not hooked code) and use RtlVirtualUnwind. Every read is range-checked.
struct X64Stack { uint64_t lo, hi; bool ok(uint64_t a, uint64_t n) const { return a >= lo && a <= hi - n && hi >= n; } };

static bool rd64(const X64Stack &st, uint64_t a, uint64_t &v) {
    if (!st.ok(a, 8)) return false;
    v = *(const uint64_t *)(uintptr_t)a; return true;
}

// The function's code as it was before the hook: original bytes over the patch, live after.
static size_t original_code(uint64_t pc, uint64_t site, const std::vector<uint8_t> &orig,
                            unsigned char *out, size_t cap) {
    size_t n = 0;
    for (uint64_t a = pc; n < cap; ++a, ++n) {
        if (a >= site && a < site + orig.size()) { out[n] = orig[(size_t)(a - site)]; continue; }
        if (!range_ok((uintptr_t)a, 1, false)) break;
        out[n] = *(const unsigned char *)(uintptr_t)a;
    }
    return n;
}

// The canonical x64 epilogue: [add rsp,imm | lea rsp,[fp+d]] pop* (ret | jmp out). True
// (and w unwound to the caller) when the code at w.Rip is one.
static bool x64_epilogue(CONTEXT &w, const unsigned char *b, size_t n, uint64_t fn_lo, uint64_t fn_hi,
                         const X64Stack &st) {
    size_t k = 0; uint64_t *regs = &w.Rax;
    uint64_t rsp = w.Rsp;
    auto have = [&](size_t m) { return k + m <= n; };
    if (have(4) && b[k] == 0x48 && b[k + 1] == 0x83 && b[k + 2] == 0xC4) { rsp += (int8_t)b[k + 3]; k += 4; }
    else if (have(7) && b[k] == 0x48 && b[k + 1] == 0x81 && b[k + 2] == 0xC4) { rsp += *(const int32_t *)(b + k + 3); k += 7; }
    else if (have(4) && (b[k] & 0xFE) == 0x48 && b[k + 1] == 0x8D && ((b[k + 2] >> 3) & 7) == 4 &&
             (b[k + 2] >> 6) != 0 && (b[k + 2] >> 6) != 3 && (b[k + 2] & 7) != 4) {
        const unsigned mod = b[k + 2] >> 6, reg = (b[k + 2] & 7) | ((b[k] & 1) << 3);
        const size_t len = mod == 1 ? 4 : 7;
        if (!have(len)) return false;
        rsp = regs[reg] + (mod == 1 ? (int64_t)(int8_t)b[k + 3] : (int64_t)*(const int32_t *)(b + k + 3));
        k += len;
    }
    uint64_t popped[16]; int preg[16]; int np = 0;
    for (;;) {
        if (have(1) && (b[k] & 0xF8) == 0x58) { if (np == 16) return false; preg[np++] = b[k] & 7; k += 1; continue; }
        if (have(2) && b[k] == 0x41 && (b[k + 1] & 0xF8) == 0x58) { if (np == 16) return false; preg[np++] = 8 + (b[k + 1] & 7); k += 2; continue; }
        break;
    }
    bool term = false;
    if (have(1) && b[k] == 0xC3) term = true;
    else if (have(2) && b[k] == 0xF3 && b[k + 1] == 0xC3) term = true;
    else if (have(3) && b[k] == 0xC2) term = true;
    else if (have(5) && b[k] == 0xE9) {
        const uint64_t t = w.Rip + k + 5 + *(const int32_t *)(b + k + 1);
        term = t < fn_lo || t >= fn_hi;                                      // tail call out
    } else if ((have(6) && b[k] == 0xFF && b[k + 1] == 0x25) || (have(7) && b[k] == 0x48 && b[k + 1] == 0xFF && b[k + 2] == 0x25))
        term = true;
    if (!term) return false;
    for (int i = 0; i < np; ++i) { if (!rd64(st, rsp, popped[i])) return false; rsp += 8; }
    uint64_t ret = 0;
    if (!rd64(st, rsp, ret)) return false;
    for (int i = 0; i < np; ++i) regs[preg[i]] = popped[i];
    w.Rip = ret; w.Rsp = rsp + 8;
    return true;
}

// Apply a function's unwind codes (and its chain) to w; off = pc - function start.
static bool x64_unwind_codes(CONTEXT &w, uint64_t image, const RUNTIME_FUNCTION *fn, uint64_t off,
                             const X64Stack &st) {
    uint64_t *regs = &w.Rax;
    for (int depth = 0; depth < 8; ++depth) {
        const uint64_t ui = image + fn->UnwindData;
        if (!range_ok((uintptr_t)ui, 4, false)) return false;
        const unsigned char *h = (const unsigned char *)(uintptr_t)ui;
        const unsigned flags = h[0] >> 3, prolog = h[1], count = h[2], fp = h[3] & 15, fpoff = h[3] >> 4;
        if (!range_ok((uintptr_t)ui + 4, count * 2 + 12, false)) return false;
        const uint16_t *codes = (const uint16_t *)(uintptr_t)(ui + 4);
        const bool in_prolog = depth == 0 && off < prolog;
        for (unsigned i = 0; i < count;) {
            const unsigned at = codes[i] & 0xFF, op = (codes[i] >> 8) & 15, info = codes[i] >> 12;
            unsigned slots = op == 1 ? (info ? 3 : 2) : (op == 4 || op == 8 || op == 6) ? 2 : (op == 5 || op == 9) ? 3 : 1;
            if (i + slots > count) return false;
            if (in_prolog && at > off) { i += slots; continue; }            // not executed yet
            uint64_t v = 0;
            switch (op) {
            case 0: if (!rd64(st, w.Rsp, v)) return false; regs[info] = v; w.Rsp += 8; break;   // PUSH_NONVOL
            case 1: w.Rsp += info ? *(const uint32_t *)&codes[i + 1] : codes[i + 1] * 8ull; break; // ALLOC_LARGE
            case 2: w.Rsp += info * 8ull + 8; break;                                                // ALLOC_SMALL
            case 3: w.Rsp = regs[fp] - 16ull * fpoff; break;                                        // SET_FPREG
            case 4: if (!rd64(st, w.Rsp + codes[i + 1] * 8ull, v)) return false; regs[info] = v; break;
            case 5: if (!rd64(st, w.Rsp + *(const uint32_t *)&codes[i + 1], v)) return false; regs[info] = v; break;
            case 6: case 8: case 9: break;                                    // EPILOG (v2), SAVE_XMM128[_FAR]
            case 10: {                                                        // PUSH_MACHFRAME
                const uint64_t base = w.Rsp + (info ? 8 : 0);
                uint64_t rip = 0, rsp = 0;
                if (!rd64(st, base, rip) || !rd64(st, base + 24, rsp)) return false;
                w.Rip = rip; w.Rsp = rsp; return true;
            }
            default: return false;
            }
            i += slots;
        }
        if (!(flags & UNW_FLAG_CHAININFO)) break;
        fn = (const RUNTIME_FUNCTION *)(uintptr_t)(ui + 4 + ((count + 1) & ~1u) * 2);
        if (!range_ok((uintptr_t)fn, sizeof(*fn), false)) return false;
    }
    uint64_t ret = 0;
    if (!rd64(st, w.Rsp, ret)) return false;
    w.Rip = ret; w.Rsp += 8;
    return true;
}

static bool x64_unwind_hooked(CONTEXT &w, uint64_t site, const std::vector<uint8_t> &orig, const X64Stack &st) {
    DWORD64 image = 0;
    PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry(w.Rip, &image, nullptr);
    unsigned char b[32];
    const size_t n = original_code(w.Rip, site, orig, b, sizeof(b));
    if (!fn) {                                                                // leaf: [rsp]
        uint64_t ret = 0;
        if (!rd64(st, w.Rsp, ret)) return false;
        w.Rip = ret; w.Rsp += 8; return true;
    }
    const uint64_t lo = image + fn->BeginAddress, hi = image + fn->EndAddress;
    if (x64_epilogue(w, b, n, lo, hi, st)) return true;
    return x64_unwind_codes(w, image, fn, w.Rip - lo, st);
}
#endif

// In-process stack snapshot from the HOOKED register image (not the agent's own frames):
// x64 unwinds with the image's .pdata (RtlVirtualUnwind); x86 scans with call-site
// verification (walk_x86 above).
static uint32_t capture_stack(probe_context *c, uint64_t *frames, uint32_t cap) {
    uint32_t n = 0;
    if (!cap) return 0;
    frames[n++] = c->regs.pc;
#if defined(_WIN64)
    CONTEXT w{};
    w.Rip = c->regs.pc; w.Rsp = c->regs.rsp; w.Rbp = c->regs.rbp; w.Rax = c->regs.rax;
    w.Rbx = c->regs.rbx; w.Rcx = c->regs.rcx; w.Rdx = c->regs.rdx; w.Rsi = c->regs.rsi; w.Rdi = c->regs.rdi;
    w.R8 = c->regs.r8; w.R9 = c->regs.r9; w.R10 = c->regs.r10; w.R11 = c->regs.r11;
    w.R12 = c->regs.r12; w.R13 = c->regs.r13; w.R14 = c->regs.r14; w.R15 = c->regs.r15;
    const NT_TIB *tib = reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
    const DWORD64 stack_lo = (DWORD64)tib->StackLimit, stack_hi = (DWORD64)tib->StackBase;
    const X64Stack st{stack_lo, stack_hi};
    const auto *state = static_cast<const AgentState *>(c->controller);
    const std::vector<uint8_t> *orig = state && state->index < PROBE_AGENT_MAX_PROBES && hooks[state->index]
                                       ? &hooks[state->index].original_bytes() : nullptr;
    __try {
        // Frame 0 sits ON the hook's patched bytes: unwind it from the original code.
        bool walk = true;
        if (orig && n < cap && c->regs.pc == sites[state->index]) {
            walk = w.Rsp >= stack_lo && w.Rsp < stack_hi && x64_unwind_hooked(w, c->regs.pc, *orig, st) && w.Rip;
            if (walk) frames[n++] = w.Rip;
        }
        while (walk && n < cap) {
            if (w.Rsp < stack_lo || w.Rsp >= stack_hi) break;   // unwound off this thread's stack
            DWORD64 image = 0;
            PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry(w.Rip, &image, nullptr);
            if (!fn) {                                   // leaf: return address is at [rsp]
                if (w.Rsp < stack_lo || w.Rsp + 8 > stack_hi) break;   // never fault (visible to the target)
                w.Rip = *(DWORD64 *)w.Rsp; w.Rsp += 8;
            } else {
                void *handler_data = nullptr; DWORD64 establisher = 0;
                RtlVirtualUnwind(UNW_FLAG_NHANDLER, image, w.Rip, fn, &w, &handler_data, &establisher, nullptr);
            }
            if (!w.Rip) break;
            frames[n++] = w.Rip;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#else
    // Every read is range-checked before it is made (see walk_x86); the __try only covers a
    // region freed concurrently by another thread (a race the target would also have).
    // At a function's first instruction [esp] is the return address and verifies EXACT,
    // so the immediate caller is never skipped.
    __try { n = walk_x86(c, frames, n, cap); } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
    return n;
}

static bool raise_ipc(probe_ipc_request *req);

// The ring is stalled behind a live producer (see probe_agent_shared.hpp): hand the record
// to the controller synchronously. False = not delivered (no debugger is servicing it).
static bool deliver_by_ipc(const probe_agent_log *rec, uint32_t site) {
    probe_ipc_request req{};
    req.op = PROBE_IPC_LOG; req.origin_site = site; req.address = (uint64_t)(uintptr_t)rec;
    return raise_ipc(&req) && req.result == 1;
}

// A drainer heartbeat that stopped means a BUSY controller (its writer is applying
// backpressure) or a DEAD one (killed while attached: the hooks stay, nobody consumes).
// Only the second may drop -- and must, or every logging thread would wait forever.
static bool controller_dead(const probe_agent_shared *sh) {
    if (!sh->controller_pid) return false;
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, sh->controller_pid);
    if (!h) return GetLastError() == ERROR_INVALID_PARAMETER;          // no such process
    bool dead = WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
    CloseHandle(h);
    return dead;
}

// Test stop (regress logs-wedge): "a producer stopped between claiming its ring slot and
// publishing it" made deterministic -- sampling a running producer for that instant failed on
// slow CI runners (wedged=0). Only a record whose text starts with "UHH_TEST_WEDGE " in a
// process whose environment has UHH_TEST_LOG_WEDGE=1 (set by the test target itself) stops
// here, after its claim: it signals Local\uhh_test_wedge_<pid> and waits for
// Local\uhh_test_wedge_go_<pid> (the target then kills, suspends or exits around it). Any other
// record pays one byte compare.
static void test_wedge_point(const probe_agent_log &rec) {
    static const char tag[] = "UHH_TEST_WEDGE ";
    if (rec.text_len < sizeof(tag) - 1 || rec.text[0] != 'U' || std::memcmp(rec.text, tag, sizeof(tag) - 1)) return;
    char on[4] = {};
    if (!GetEnvironmentVariableA("UHH_TEST_LOG_WEDGE", on, sizeof(on)) || on[0] != '1') return;
    wchar_t at[64], go[64];
    _snwprintf_s(at, _countof(at), _TRUNCATE, L"Local\\uhh_test_wedge_%lu", GetCurrentProcessId());
    _snwprintf_s(go, _countof(go), _TRUNCATE, L"Local\\uhh_test_wedge_go_%lu", GetCurrentProcessId());
    HANDLE a = OpenEventW(EVENT_MODIFY_STATE, FALSE, at), g = OpenEventW(SYNCHRONIZE, FALSE, go);
    if (a && g) { SetEvent(a); WaitForSingleObject(g, INFINITE); }
    if (a) CloseHandle(a);
    if (g) CloseHandle(g);
}

// The drainer sleeps (probe_agent_drain_wait): the first producer to take `waiting` wakes it.
// A probe on the APIs SetEvent runs (NtSetEvent) passes straight through on this thread (busy,
// as for thread_born): the agent's own call is not a program hit.
static HANDLE g_drain_event;             // the controller's drain event (opened at init)
struct ThreadSlot;
static ThreadSlot *agent_call_begin();
static void agent_call_end(ThreadSlot *ts);
static void wake_drainer(probe_agent_shared *sh) {
    if (!g_drain_event || !InterlockedExchange(&sh->drain_wait.waiting, 0)) return;
    ThreadSlot *const ts = agent_call_begin();
    SetEvent(g_drain_event);
    agent_call_end(ts);
}

struct HitScope;
static __forceinline DWORD current_tid();
static __forceinline bool log_epoch_current(probe_context *c, const probe_agent_shared *sh);
static __forceinline HitScope *log_carrier(probe_context *c);
static __forceinline void log_carried(HitScope *h, bool dropped);
static __forceinline uint32_t log_carry_block(const HitScope *h, const probe_agent_shared *sh);

// Format and stack are produced BEFORE claiming a ring slot so a slot is held only
// for a copy. A full ring makes the producer wait (backpressure); see the ring's comment in
// probe_agent_shared.hpp for the only cases that do not end in the ring.
static void agent_log(probe_context *c, bool stack, const char *format, va_list ap) {
    auto *state = c ? static_cast<AgentState *>(c->controller) : nullptr;
    if (!state || !state->shared || !format) return;
    auto *sh = state->shared;
    if (!log_epoch_current(c, sh)) return;              // once per record; running pins this channel until publication
    if (sh->controller_gone) {
        InterlockedIncrement(&sh->log_dropped); log_carried(log_carrier(c), true); return;
    }
    probe_agent_log local;                     // the record, built on this stack
    // The controller's formatter: an invalid format (%k, %n) used to fast-fail the TARGET
    // through the CRT's invalid-parameter handler; now logged as "[unformattable] <format>".
    int len = uhh_format_log(local.text, sizeof(local.text), format, ap);
    if (len < 0) return;
    local.text_len = (uint32_t)len;
    local.frame_count = stack ? capture_stack(c, local.frames, PROBE_STACK_MAX_FRAMES) : 0;
    local.has_stack = stack ? 1 : 0;
    local.probe = state->index; local.tid = c->tid;
    // The callback's first record carries its hit's unaccounted unit (probe_agent_stripe):
    // from the publish on, the hit is accounted by this record, not as interrupted.
    HitScope *const carrier = log_carrier(c);
    local.carry = carrier ? 1 : 0;
    local.reserved = log_carry_block(carrier, sh);
    LONG64 pos = sh->log_head;
    probe_agent_log *rec = nullptr;
    // Heartbeat watch: time is accumulated in small steps so a debugger freezing the whole
    // process (when nothing here runs) never counts as the controller being idle.
    ULONGLONG last_tick = 0, idle = 0; LONG64 seen_beat = -1; bool ipc_failed = false;
    const DWORD me = current_tid();
    for (;;) {
        rec = &sh->logs[(uint64_t)pos % PROBE_AGENT_LOG_CAP];
        LONG64 diff = rec->seq - pos;
        if (diff == 0) {
            // Claim = own the slot FIRST (owner 0 -> this thread), then move the head. Only the
            // owner can move the head past pos, so a claimed slot always names its producer --
            // the controller can tell when that producer died. A stale view (the head moved on)
            // gives the slot back.
            if (rec->owner == 0 && InterlockedCompareExchange(&rec->owner, (LONG)me, 0) == 0) {
                if (InterlockedCompareExchange64(&sh->log_head, pos + 1, pos) == pos) break;
                InterlockedExchange(&rec->owner, 0);
            }
            pos = sh->log_head;
        } else if (diff < 0) {
            // Full: wait for a slot rather than lose the record.
            if (sh->controller_gone) { InterlockedIncrement(&sh->log_dropped); log_carried(carrier, true); return; }
            if (sh->ring_stalled && sh->log_ipc && !ipc_failed) {
                if (deliver_by_ipc(&local, state->index)) { log_carried(carrier, false); return; }
                ipc_failed = true;
            }
            ULONGLONG now = GetTickCount64();
            LONG64 beat = probe_agent_load64(&sh->drain_beat);
            if (beat != seen_beat) { seen_beat = beat; idle = 0; }
            else if (last_tick) idle += (now - last_tick) < 50 ? (now - last_tick) : 50;
            last_tick = now;
            if (idle > 1000) {
                idle = 0;
                if (controller_dead(sh)) {
                    InterlockedExchange(&sh->controller_gone, 1);
                    InterlockedIncrement(&sh->log_dropped); log_carried(carrier, true); return;
                }
            }
            SwitchToThread();
            pos = sh->log_head;
        } else {
            pos = sh->log_head;
        }
    }
    test_wedge_point(local);                                      // (test only: see there)
    rec->probe = local.probe; rec->tid = local.tid;
    rec->text_len = local.text_len;
    std::memcpy(rec->text, local.text, local.text_len + 1);
    rec->has_stack = local.has_stack; rec->frame_count = local.frame_count;
    rec->carry = local.carry; rec->reserved = local.reserved;
    if (local.frame_count) std::memcpy(rec->frames, local.frames, local.frame_count * sizeof(uint64_t));
    // Publish (with carry: the unit goes with it). x86/x64 keep stores in program order (TSO), so
    // one plain store of seq after the record's own stores is a release: no fence and no LOCKed
    // exchange (on x86 a CMPXCHG8B loop) per record. The compiler barrier keeps MSVC from moving
    // the record's stores past it; the 64-bit store is whole (one MOVQ on x86).
    _ReadWriteBarrier();
    probe_agent_store64(&rec->seq, pos + 1);
    log_carried(carrier, false);
    if (sh->drain_wait.waiting) wake_drainer(sh);
}

// One warning per probe, delivered as a log record (the callback runs inside the target).
static volatile LONG g_warned[PROBE_AGENT_MAX_PROBES];
static volatile LONG g_warned_pop[PROBE_AGENT_MAX_PROBES];   // return_from's nargs contradicted call_original (x86)
static void warn_log(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format); agent_log(c, false, format, ap); va_end(ap);
}
static void warn_once(probe_context *c, const char *text) {
    if (!c || c->site >= PROBE_AGENT_MAX_PROBES || InterlockedExchange(&g_warned[c->site], 1)) return;
    warn_log(c, "uhh warning: %s", text);
}

extern "C" void send_log(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format);
    if (g_ctrl) g_ctrl->vlog(c, 0, format, ap); else agent_log(c, false, format, ap);
    va_end(ap);
}
extern "C" void send_log_stack(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format);
    if (g_ctrl) g_ctrl->vlog(c, 1, format, ap); else agent_log(c, true, format, ap);
    va_end(ap);
}
extern "C" const void *get_config(probe_context *c) {
    if (g_ctrl) return g_ctrl->get_config(c);
    return c ? c->config : nullptr;
}

// call_func inside the target: resolve and call directly on this (the hit) thread.
// The controller's grammar exactly (session_symbols.cpp parse_location / resolve_symbol), so a
// call_func symbol resolves -- or is refused -- the same on every backend: "0xADDRESS",
// "module+0xRVA", "module!Export[+0xOFF]"; offsets need "0x" and hex digits only; the module
// is matched by its file name (a directory part is ignored), and a name without extension
// means "<name>.dll" -- GetModuleHandleA's own reading, which the controller's
// module_of_location (session_symbols.cpp, also used for every probe location) mirrors exactly.
// (GetModuleHandleA alone searched a full path as given; _strtoui64 accepted "+0", "+0xZZ"
// and "+10"; the controller refuses all of those.)
static bool agent_parse_hex(const char *p, const char *end, uint64_t *out) {
    if (end - p < 3 || p[0] != '0' || (p[1] != 'x' && p[1] != 'X')) return false;
    uint64_t v = 0;
    for (p += 2; p < end; ++p) {
        const char ch = *p;
        const int d = ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10
                    : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
        if (d < 0 || v >> 60) return false;
        v = v << 4 | (uint64_t)d;
    }
    *out = v; return true;
}
static HMODULE agent_module(const char *begin, const char *end) {
    for (const char *p = begin; p < end; ++p) if (*p == '\\' || *p == '/') begin = p + 1;
    char mod[MAX_PATH];
    if (begin == end || (size_t)(end - begin) + 2 > sizeof(mod)) return nullptr;
    memcpy(mod, begin, end - begin); mod[end - begin] = 0;
    return GetModuleHandleA(mod);       // a bare name means <name>.dll, as in the controller's grammar
}
static uint64_t agent_resolve(const char *symbol) {
    if (!symbol || !*symbol) return 0;
    if (symbol[0] == '0' && (symbol[1] == 'x' || symbol[1] == 'X')) return _strtoui64(symbol + 2, nullptr, 16);
    const char *bang = strchr(symbol, '!'), *stop = symbol + strlen(symbol);
    if (!bang) {
        const char *plus = strrchr(symbol, '+');
        uint64_t rva = 0;
        if (!plus || plus == symbol || !agent_parse_hex(plus + 1, stop, &rva)) return 0;
        HMODULE m = agent_module(symbol, plus);
        return m ? (uint64_t)(uintptr_t)m + rva : 0;
    }
    if (bang == symbol) return 0;
    const char *plus = strchr(bang + 1, '+'), *name_end = plus ? plus : stop;
    uint64_t off = 0;
    char name[256];
    if (name_end == bang + 1 || (size_t)(name_end - bang - 1) >= sizeof(name)) return 0;
    if (plus && !agent_parse_hex(plus + 1, stop, &off)) return 0;
    HMODULE m = agent_module(symbol, bang);
    if (!m) return 0;
    memcpy(name, bang + 1, name_end - bang - 1); name[name_end - bang - 1] = 0;
    FARPROC f = GetProcAddress(m, name);
    return f ? (uint64_t)(uintptr_t)f + off : 0;
}

#if defined(_WIN64)
using fn8 = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static bool call_raw(uint64_t fn, const uint64_t *a, uint64_t *ret) {
    __try { uint64_t r = reinterpret_cast<fn8>(fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]); if (ret) *ret = r; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    return true;
}
#else
// Push the args, call, and restore ESP ourselves: correct for stdcall AND cdecl callees.
static bool call_raw(uint64_t fn, const uint64_t *a, uint64_t *ret, int nargs) {
    uint32_t args32[8]; for (int i = 0; i < 8; ++i) args32[i] = (uint32_t)a[i];
    uint32_t target = (uint32_t)fn, lo = 0, hi = 0;
    __try {
        __asm {
            mov ebx, esp
            mov ecx, nargs
            lea esi, args32
        push_loop:
            test ecx, ecx
            jz do_call
            dec ecx
            push dword ptr [esi + ecx*4]
            jmp push_loop
        do_call:
            call dword ptr [target]
            mov esp, ebx
            mov lo, eax
            mov hi, edx
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    (void)hi;
    if (ret) *ret = lo;                                    // pointer-sized return (EAX)
    return true;
}
#endif

// call_func resolution cache (inline): symbol string -> callee, for names that resolve through
// a module ("module!Export[+0xOFF]", "module+0xRVA"). Resolving every call (GetModuleHandleA +
// GetProcAddress + a VirtualQuery for the executable check) was ~2.7 us for a ~1 ns callee.
// Correctness rests on invalidation: a module unload -- the loader's DLL notification,
// sent BEFORE the image is unmapped -- bumps g_unload_gen, and an entry is used only while
// the generation it was resolved in is current. So a DLL unloaded and another (or nothing)
// mapped at its address is never called through a stale entry (regress cdx-cfreuse-*). The
// generation is sampled BEFORE resolving: an unload racing the resolution leaves the entry
// stale at once. Without the notification (registration failed) nothing is cached.
// Only the RESOLUTION (name -> address) is cached; executability is re-checked on every call
// (a VirtualQuery that reads protection and never touches the page), because the program can
// VirtualProtect still-loaded module code to NO_ACCESS/NX/GUARD between calls: calling it
// would raise a first-chance exception the target's vectored handlers would see (breakpoint/hw
// refuse such a call silently).
// Entries are per-slot seqlocks (odd = being written): lock-free, any thread, no allocation.
struct CfEntry { volatile LONG seq; volatile LONG gen; volatile uint64_t fn; volatile uint32_t len; char sym[116]; };
static CfEntry g_cf_cache[64];
static uint32_t cf_hash(const char *s, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; ++i) h = (h ^ (uint8_t)s[i]) * 16777619u;
    return h;
}
// An entry resolved in generation `gen` (the caller's sample of g_unload_gen), else 0.
static uint64_t cf_lookup(const char *sym, size_t len, uint32_t h, LONG gen) {
    CfEntry &e = g_cf_cache[h & 63];
    const LONG s1 = e.seq;
    if ((s1 & 1) || e.len != len || e.gen != gen) return 0;
    _ReadWriteBarrier();
    const bool same = memcmp(e.sym, sym, len) == 0;
    const uint64_t fn = e.fn;
    _ReadWriteBarrier();
    return same && e.seq == s1 ? fn : 0;
}
static void cf_store(const char *sym, size_t len, uint32_t h, uint64_t fn, LONG gen) {
    CfEntry &e = g_cf_cache[h & 63];
    const LONG s1 = e.seq;
    if ((s1 & 1) || InterlockedCompareExchange(&e.seq, s1 + 1, s1) != s1) return;   // another writer: skip
    e.len = (uint32_t)len; memcpy(e.sym, sym, len); e.fn = fn; e.gen = gen;
    InterlockedExchange(&e.seq, s1 + 2);
}
using ldr_notify_fn = VOID(CALLBACK *)(ULONG reason, const void *data, void *context);
static VOID CALLBACK on_dll_notification(ULONG reason, const void *, void *) {
    if (reason == 2) InterlockedIncrement(&g_unload_gen);    // LDR_DLL_NOTIFICATION_REASON_UNLOADED
}
using ldr_ref_fn = LONG(NTAPI *)(ULONG flags, PVOID base);
using ldr_unload_fn = LONG(NTAPI *)(PVOID base);
static ldr_ref_fn g_ldr_addref;          // ntdll!LdrAddRefDll / LdrUnloadDll: call_func's module pin
static ldr_unload_fn g_ldr_unload;
// Test knob (regress cdx-cfrace-inline, cdx-cfpin-inline): UHH_TEST_CF_STALL=resolved|pinned in
// the TARGET's environment (read once at init) stops ONE inline call_func right after it
// resolved its callee (before the module pin) or right after the pin: it signals
// Local\uhh_test_cf_<pid> and waits for Local\uhh_test_cf_go_<pid> while the target unloads
// (and replaces) the callee's DLL. Off: one load and compare per call.
static bool g_test_cf_pin_fail;       // UHH_TEST_CF_PIN_FAIL: refuse absolute image pins
static volatile LONG g_test_cf_stall;    // 0 off, 1 resolved, 2 pinned
static void test_cf_point(LONG where) {
    if (g_test_cf_stall != where || InterlockedCompareExchange(&g_test_cf_stall, 0, where) != where) return;
    wchar_t at[64], go[64];
    _snwprintf_s(at, _countof(at), _TRUNCATE, L"Local\\uhh_test_cf_%lu", GetCurrentProcessId());
    _snwprintf_s(go, _countof(go), _TRUNCATE, L"Local\\uhh_test_cf_go_%lu", GetCurrentProcessId());
    HANDLE a = OpenEventW(EVENT_MODIFY_STATE, FALSE, at), g = OpenEventW(SYNCHRONIZE, FALSE, go);
    if (a && g) { SetEvent(a); WaitForSingleObject(g, INFINITE); }
    if (a) CloseHandle(a);
    if (g) CloseHandle(g);
}
static void watch_unloads() {
    if (g_dll_cookie) return;
    const HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    g_ldr_addref = reinterpret_cast<ldr_ref_fn>(GetProcAddress(nt, "LdrAddRefDll"));
    g_ldr_unload = reinterpret_cast<ldr_unload_fn>(GetProcAddress(nt, "LdrUnloadDll"));
    g_qwsex = reinterpret_cast<qwsex_fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "K32QueryWorkingSetEx"));
    char knob[16] = {};
    if (GetEnvironmentVariableA("UHH_TEST_CF_STALL", knob, sizeof(knob)))
        g_test_cf_stall = !strcmp(knob, "resolved") ? 1 : !strcmp(knob, "pinned") ? 2 : 0;
    g_test_cf_pin_fail = GetEnvironmentVariableA("UHH_TEST_CF_PIN_FAIL", knob, sizeof(knob)) != 0;
    using reg_fn = LONG(NTAPI *)(ULONG, ldr_notify_fn, void *, void **);
    auto reg = reinterpret_cast<reg_fn>(GetProcAddress(nt, "LdrRegisterDllNotification"));
    void *cookie = nullptr;
    if (reg && reg(0, on_dll_notification, nullptr, &cookie) >= 0) g_dll_cookie = cookie;
}
static void unwatch_unloads() {
    if (!g_dll_cookie) return;
    using unreg_fn = LONG(NTAPI *)(void *);
    if (auto unreg = reinterpret_cast<unreg_fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrUnregisterDllNotification")))
        unreg(g_dll_cookie);
    g_dll_cookie = nullptr;
}

/* The callee's module lives until the call returns (codex5 #1). Resolving a name and calling
   the address are two steps: a DLL unloaded by another thread in between -- and another image
   mapped where it was -- would make call_func run unrelated code (or fault in a hole). So the
   module holding the callee is PINNED for the call: a loader reference (LdrAddRefDll) taken
   after the resolution and dropped (LdrUnloadDll) right after the call; and the unload
   generation is re-checked AFTER pinning: unchanged since before the resolution, no unload
   notification -- which the loader sends BEFORE unmapping -- came in between, so the pinned
   module is the one resolved and stays mapped until we release it. Changed: release and
   resolve again (bounded; then refuse).
   The cost of the alternative decides it: without a pin call_func can execute whatever now
   occupies the address. With it, one observable difference remains, and only in that race:
   a FreeLibrary of the callee's DLL on another thread DURING the call returns as always, but
   the unmap (and DllMain(DETACH), unload notifications) is deferred to our release at the
   end of the call -- on the calling thread, as if the program had called FreeLibrary there
   last. The program's own reference counting is untouched otherwise (our reference is ours,
   balanced on every path). The ntdll entry points take the loader's module-table lock only
   (not the loader lock, as GetModuleHandleEx would), unless the release is the last
   reference. Residual: an unload already past its last reference but not yet notified (if
   LdrAddRefDll refuses that module -- load count zero -- we resolve again).
   Absolute addresses ("0x...") are pinned the same way when they lie in a loaded image; code
   outside any image is called as before (nothing to pin). */
struct CalleePin {
    void *module = nullptr;
    ~CalleePin() { if (module) g_ldr_unload(module); }
};
static uint64_t resolve_callee(const char *symbol, CalleePin &pin) {
    if (!symbol || !*symbol) return 0;
    const bool absolute = symbol[0] == '0' && (symbol[1] == 'x' || symbol[1] == 'X');
    const size_t len = absolute || !g_dll_cookie ? 0 : strnlen(symbol, sizeof(CfEntry::sym) + 1);
    const bool cacheable = len && len <= sizeof(CfEntry::sym);
    const uint32_t h = cacheable ? cf_hash(symbol, len) : 0;
    const bool can_pin = g_ldr_addref && g_ldr_unload && g_dll_cookie;   // (the generation needs the notification)
    for (int attempt = 0; attempt < 4; ++attempt) {
        const LONG gen = g_unload_gen;                      // before resolving (see above)
        uint64_t fn = cacheable ? cf_lookup(symbol, len, h, gen) : 0;
        if (!fn) {
            fn = agent_resolve(symbol);
            if (!fn) return 0;
            if (cacheable) cf_store(symbol, len, h, fn, gen);   // cache the resolution only
        }
        test_cf_point(1);
        // Checked on EVERY call, never cached (see above): an address that is no committed
        // executable memory now (e.g. "0x1") returns 0 without being called -- the call would
        // fault, and inline that first-chance fault is seen by the target's vectored handlers
        // (breakpoint/hw, where the debugger sees it first, return 0 silently).
        if (!addressable(fn, 1)) return 0;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((const void *)(uintptr_t)fn, &mbi, sizeof(mbi))) return 0;
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE) {
            if (!can_pin) return 0;
            if (!(absolute && g_test_cf_pin_fail) && g_ldr_addref(0, mbi.AllocationBase) >= 0) pin.module = mbi.AllocationBase;
            else continue;                   // resolved through a module now going away
        }
        // Private memory replacing an unloaded image must not bypass generation validation.
        if (can_pin && g_unload_gen != gen) {   // an unload since the resolution: again
            if (pin.module) { g_ldr_unload(pin.module); pin.module = nullptr; }
            continue;
        }
        test_cf_point(2);
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD)) return 0;
        const DWORD p = mbi.Protect & 0xFF;
        if (p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY)
            return fn;
        return 0;
    }
    return 0;                                              // unloads kept racing the resolution
}

// A fixed set of thread ids (not TLS: it must work on a thread that is still in its loader
// initialisation). A scope registers the current thread for its lifetime.
template <size_t N> struct TidSet {
    volatile LONG count;
    volatile LONG tids[N];
    bool has(DWORD tid) const {
        if (!count) return false;
        for (auto &slot : tids) if ((DWORD)slot == tid) return true;
        return false;
    }
};
template <size_t N> struct TidScope {
    TidSet<N> &set;
    volatile LONG *slot = nullptr;
    explicit TidScope(TidSet<N> &s) : set(s) {
        const LONG tid = (LONG)GetCurrentThreadId();
        for (auto &t : set.tids)
            if (InterlockedCompareExchange(&t, tid, 0) == 0) { slot = &t; InterlockedIncrement(&set.count); break; }
    }
    ~TidScope() { if (slot) { InterlockedExchange(slot, 0); InterlockedDecrement(&set.count); } }
    TidScope(const TidScope &) = delete;
    TidScope &operator=(const TidScope &) = delete;
};

// The agent's OWN threads (the install service thread; the remote threads running init and
// stop). A probe they hit -- the hook writes call NtProtectVirtualMemory/FlushInstructionCache,
// trampolines are allocated, ... -- is not program activity: it passes straight through (not
// counted, no callback). Running the program's callback there was worse than noise: install
// rounds run while every other thread is FROZEN, so a callback taking a lock a frozen thread
// holds (heap, loader) stalled the target until the controller's 5 s freeze limit.
static TidSet<8> g_agent_threads;

static bool call_func_guarded(probe_context *c);
extern "C" int call_func(probe_context *c, const char *symbol, uint64_t *ret, int nargs, ...) {
    if (nargs < 0 || nargs > 8) return 0;
    uint64_t a[8] = {0};
    va_list ap; va_start(ap, nargs);
    for (int i = 0; i < nargs; ++i) a[i] = va_arg(ap, uint64_t);
    va_end(ap);
    if (g_ctrl) return g_ctrl->call_func_args(c, symbol, ret, nargs, a);
    if (!call_func_guarded(c)) return 0;
    CalleePin pin;                                         // the callee's module, until the call returns
    const uint64_t fn = resolve_callee(symbol, pin);
    if (!fn) return 0;
#if defined(_WIN64)
    const int ok = call_raw(fn, a, ret) ? 1 : 0;
#else
    const int ok = call_raw(fn, a, ret, nargs) ? 1 : 0;
#endif
    forget_region(true);                               // the callee may have changed protections
    return ok;
}

/* ---- call_original / return_from (inline). ----
   call_original: a real call to the hook's trampoline (the overwritten instructions, then a
   jump back past the hook), so this probe does not fire for it, with the context's argument
   registers and the hit's stack arguments. return_from: the patched mid-hook stub resumes at
   Context::rip with rsp at Context::rsp (cmake/patch_safetyhook.cmake, uhh_resume_slot); a
   return thunk there does `pop rsp; ret` (x86 `pop esp; ret N`) with Context::rsp = the hit's
   SP, so the hooked function returns to its caller through a REAL ret (CET shadow stacks
   stay in sync). The thunks live in one executable page allocated at init: slot k (4 bytes,
   at offset 4k) is `pop esp; ret 4k` (k = 0: `pop esp; ret`), i.e. the thunk for N popped
   bytes is at base + N. */
static uint8_t *g_ret_thunks;
static void make_ret_thunks() {
    if (g_ret_thunks) return;
    auto *p = static_cast<uint8_t *>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!p) return;
    for (uint32_t k = 0; k < 1024; k += 4) {
        p[k] = 0x5C;                                       // pop rsp / pop esp
        if (!k) { p[k + 1] = 0xC3; p[k + 2] = p[k + 3] = 0xCC; }
        else { p[k + 1] = 0xC2; p[k + 2] = (uint8_t)k; p[k + 3] = (uint8_t)(k >> 8); }
    }
    DWORD old = 0;
    if (!VirtualProtect(p, 4096, PAGE_EXECUTE_READ, &old)) { VirtualFree(p, 0, MEM_RELEASE); return; }
    FlushInstructionCache(GetCurrentProcess(), p, 4096);
    g_ret_thunks = p;
}

/* An exception (or longjmp) inside the original must reach the PROGRAM's handlers, exactly
   as without the probe, and must not run the original a second time. So call_original
   swallows nothing: the unwind goes from the original straight to the hooked function's
   caller, skipping the callback, the agent and the hook stub, which have no unwind data of
   their own (the rest of the callback does not run -- the same on every backend).
   x64: uhh_orig_thunk (agent_x64.asm) calls the trampoline from a frame whose unwind data is
   a MACHINE FRAME holding the hit's return address and caller SP, plus the hit's nonvolatile
   GPRs and XMM6-15: the unwinder steps from the thunk directly to the caller, as if the
   hooked function had returned. Its language handler (uhh_orig_unwind) settles this hit's
   bookkeeping when the unwind passes it.
   x86: the frame-based SEH chain is relinked for the call -- the record of the __try below
   points straight at the hit's first record -- so dispatch and unwind skip the callback's
   frames; its __finally settles the bookkeeping. */
struct HitScope;
/* Per-thread agent state WITHOUT implicit TLS. A hit can come on a thread whose TLS does not
   exist yet (LdrpInitializeThread allocates it: an allocator probe fires there) or is being
   freed (thread exit), so "this thread is running a callback" -- the re-entrancy guard --
   cannot live in a thread_local: with no TLS there was no guard, and an allocating callback
   on the allocator recursed until the stack overflowed. A fixed table keyed by thread id:
   a thread claims its slot on its first hit and keeps it (a reused id reuses the slot);
   after the claim only the owning thread touches its slot -- until it is gone and a new
   thread takes the slot over (the table is full: see take_dead_slot).
   The slot is also the call_func guard: call_func runs only inside a callback, i.e. while
   `active` marks this thread, so a probe its callee hits is counted without a callback (see
   call_func_guarded). One mechanism, no separate "in call_func" registry.
   A reused id: a thread killed (TerminateThread, ExitThread) inside a callback leaves its
   record in the slot. The next thread with its id must not settle it (that hit stays in
   flight: callbacks_interrupted) and must run its own callbacks. A new owner is recognised
   without writing anything the program could see: by its TEB and stack base, compared on
   every hit, and -- when those are reused too -- by its creation time, read once per new
   identity and again only when a stale record turns up (a dead owner's, or this thread's
   own after a non-unwinding longjmp, see hit_scope_live). */
// Where a hit is counted: the owner's per-thread block (blk, the common path: plain stores,
// see probe_agent_tblock) or, for a thread without one, its hit_stripes line (interlocked).
struct HitAcct { probe_agent_tblock *blk; probe_agent_stripe *line; uint32_t probe; };
// One cache line per slot (alignas(64)): every hit writes its own slot (active, active_acct,
// active_logged), and threads created together get neighbouring ids, i.e. neighbouring slots --
// unaligned (x86 72 bytes, x64 120) two threads' hits wrote the same line and it moved between
// their cores on every hit.
struct alignas(64) ThreadSlot {
    volatile LONG tid;
    HitScope *active;                    // the hit whose callback this thread is running
    HitAcct active_acct;                 // where that hit is counted
    volatile LONG active_logged;         // ... and its unaccounted unit left with its first log
    uintptr_t moved_from, moved_to;      // a fault moved out of a trampoline (tramp_veh)
    const void *teb;                     // the owner's identity: TEB, stack base, creation time
    uintptr_t stack;
    uint64_t born;
    volatile LONG busy;                  // reading `born`: a probe hit meanwhile passes straight through
    // The slot's hit block in the CURRENT shared block (blk_gen == g_tblock_gen; null: none was
    // free -- the stripes). It stays with the slot when the slot passes to a new owner (the
    // dead one writes nothing more), and moves to another slot only from a dead owner's.
    probe_agent_tblock *blk;
    LONG blk_gen;
    ULONGLONG blk_retry;
};
static_assert(sizeof(ThreadSlot) == 128, "keep each thread slot within two cache lines");
constexpr uint32_t AGENT_THREAD_SLOTS = 4096;
static ThreadSlot g_threads[AGENT_THREAD_SLOTS];
// When every slot is owned (4096 distinct thread ids have hit a probe over the process's life),
// a dead thread's slot is taken over -- thread ids are reused, but a short-lived thread's own
// slot was never freed, and a thread without a slot ran untracked: its callback was invisible
// to the detach drain (count_live_callbacks), which stopped waiting and dropped its log. With
// more than 4096 probe-hitting threads ALIVE at once, the overflow table holds the rest.
constexpr uint32_t AGENT_OVERFLOW_SLOTS = 256;
static ThreadSlot g_overflow[AGENT_OVERFLOW_SLOTS];
constexpr LONG SLOT_MOVING = 1;          // being handed to a new owner (never a thread id: those are multiples of 4)
// Callbacks running on a thread with no slot at all (both tables owned by live threads):
// counted as live by the detach drain.
static volatile LONG g_untracked_running;
static ThreadSlot *slot_in(ThreadSlot *table, uint32_t size, DWORD tid, bool claim) {
    for (uint32_t n = 0; n < size; ++n) {
        ThreadSlot &s = table[((tid >> 2) + n) & (size - 1)];
        const LONG t = s.tid;
        if (t == (LONG)tid) return &s;
        if (t) continue;
        if (!claim) return nullptr;
        if (InterlockedCompareExchange(&s.tid, (LONG)tid, 0) == 0) return &s;
    }
    return nullptr;                      // full (or, without claim, not there)
}
// The slot owner `tid` no longer exists in this process (exited, or the id now names a thread
// of another process). Not certain (a transient failure to open it): not gone.
static bool slot_owner_gone(LONG tid) {
    HANDLE h = OpenThread(SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)tid);
    if (!h) {
        const DWORD e = GetLastError();
        return e == ERROR_INVALID_PARAMETER;
    }
    const DWORD pid = GetProcessIdOfThread(h);
    const bool gone = (pid && pid != GetCurrentProcessId()) || WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
    CloseHandle(h);
    return gone;
}
// A full table: take over a slot whose owner is gone, nearest this thread's own position
// first (its lookups probe from there). The slot is marked moving while the owner is checked
// a second time, so a new thread given the dead owner's id meanwhile cannot have picked it up
// (it no longer matches): only then is it reset and handed over. A dead owner killed inside a
// callback leaves that hit in flight (callbacks_interrupted), as with a reused id.
// One sweeper at a time (another thread meanwhile gets no slot for this hit); a probe its own
// calls hit (NtOpenThread, ...) passes straight through, as the agent's own work.
static volatile LONG64 g_sweep_after;    // no takeover sweep before this tick: the last found every owner alive
static volatile LONG g_sweeper;          // the thread sweeping
static ThreadSlot *take_dead_slot(ThreadSlot *table, uint32_t size, DWORD tid) {
    if (GetTickCount64() < (ULONGLONG)g_sweep_after) return nullptr;
    if (InterlockedCompareExchange(&g_sweeper, (LONG)tid, 0) != 0) return nullptr;
    struct Done { ~Done() { InterlockedExchange(&g_sweeper, 0); } } done;
    for (uint32_t n = 0; n < size; ++n) {
        ThreadSlot &s = table[((tid >> 2) + n) & (size - 1)];
        const LONG t = s.tid;
        if (!t || t == SLOT_MOVING || t == (LONG)tid || !slot_owner_gone(t)) continue;
        if (InterlockedCompareExchange(&s.tid, SLOT_MOVING, t) != t) continue;
        if (!slot_owner_gone(t)) { InterlockedExchange(&s.tid, t); continue; }   // the id lives again: leave it
        s.active = nullptr; s.active_acct = {}; s.active_logged = 0; s.moved_from = s.moved_to = 0;
        s.teb = nullptr; s.stack = 0; s.born = 0; s.busy = 0;
        InterlockedExchange(&s.tid, (LONG)tid);
        return &s;
    }
    InterlockedExchange64(&g_sweep_after, (LONG64)GetTickCount64() + 100);
    return nullptr;
}
static ThreadSlot *thread_slot(DWORD tid, bool claim) {
    if (ThreadSlot *s = slot_in(g_threads, AGENT_THREAD_SLOTS, tid, claim)) return s;
    // The table is full (or, without claim, tid has no slot there): the overflow table, or a
    // dead thread's slot in either.
    if (ThreadSlot *s = slot_in(g_overflow, AGENT_OVERFLOW_SLOTS, tid, false)) return s;
    if (!claim) return nullptr;
    if (ThreadSlot *s = take_dead_slot(g_threads, AGENT_THREAD_SLOTS, tid)) return s;
    if (ThreadSlot *s = slot_in(g_overflow, AGENT_OVERFLOW_SLOTS, tid, true)) return s;
    return take_dead_slot(g_overflow, AGENT_OVERFLOW_SLOTS, tid);   // null: g_untracked_running
}
// The current thread's creation time (0: unknown). Hits it causes (a probe on
// NtQueryInformationThread) pass straight through: see ThreadSlot::busy.
using nt_qit_fn = LONG (NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
static nt_qit_fn g_nt_qit;               // ntdll!NtQueryInformationThread, resolved at init
static uint64_t thread_born(ThreadSlot *ts) {
    LARGE_INTEGER times[4] = {};         // KERNEL_USER_TIMES: CreateTime first
    InterlockedExchange(&ts->busy, 1);
    const bool ok = g_nt_qit && g_nt_qit(GetCurrentThread(), 1 /* ThreadTimes */, times, sizeof(times), nullptr) >= 0;
    InterlockedExchange(&ts->busy, 0);
    return ok ? (uint64_t)times[0].QuadPart : 0;
}
// This thread's slot, claimed. A new owner (another TEB or stack: a reused id) drops the dead
// thread's record without settling it.
static ThreadSlot *own_thread_slot(DWORD tid) {
    ThreadSlot *ts = thread_slot(tid, true);
    if (!ts) return ts;
    const NT_TIB *tib = reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
    if (ts->teb != tib || ts->stack != (uintptr_t)tib->StackBase) {
        ts->teb = tib; ts->stack = (uintptr_t)tib->StackBase;
        ts->active = nullptr;            // the dead thread's hit: left in flight (interrupted)
        ts->moved_to = 0;
        ts->born = thread_born(ts);
    }
    return ts;
}

// This thread's slot, cached in the agent's own implicit TLS (not the TEB: a TlsAlloc'd slot
// lives in the TEB's TlsSlots, and a probe hit must leave the program's TEB untouched --
// regress transparency-*): the lookup and identity check run once per thread, not per hit.
// A thread still in its loader initialisation has no TLS block yet (tls_ready): it looks the
// slot up every time. A slot passes to another thread only from a dead owner, so a cached
// slot stays this thread's.
static constinit thread_local ThreadSlot *t_slot = nullptr;
static constinit thread_local ThreadSlot t_fallback{};
static bool private_slot(const ThreadSlot *ts) { return ts && ts->blk_gen == -1; }
static inline ThreadSlot *cached_slot() { return tls_ready() ? t_slot : nullptr; }
static inline void cache_slot(ThreadSlot *ts) { if (tls_ready()) t_slot = ts; }
static bool g_test_slotless, g_test_preaccount;
static ThreadSlot *my_slot(DWORD tid) {
    ThreadSlot *ts = cached_slot();
    if (g_test_slotless && !private_slot(ts)) ts = nullptr; // never borrow a shared accounting block in this test
    // The test exhausts the shared tables, not this thread's TLS. Keep a private guard
    // while using stripes, including codex9's first-log carry when the thread is killed.
    if (!ts && !g_test_slotless && (ts = own_thread_slot(tid)) != nullptr) cache_slot(ts);
    if (!ts && tls_ready()) {
        ts = &t_fallback;
        ts->tid = (LONG)tid; ts->blk_gen = -1;
        cache_slot(ts);
    }
    return ts;
}
// The agent calls an API on a program thread (inside a callback): a probe that call hits passes
// straight through (ThreadSlot::busy), neither counted nor run.
static ThreadSlot *agent_call_begin() {
    ThreadSlot *ts = cached_slot();
    if (!ts) ts = thread_slot(GetCurrentThreadId(), false);
    if (ts) InterlockedExchange(&ts->busy, 1);
    return ts;
}
static void agent_call_end(ThreadSlot *ts) { if (ts) InterlockedExchange(&ts->busy, 0); }

// Hit blocks (probe_agent_tblock). A new shared block (init) starts a generation: every slot
// claims a block again. Claim: a free block, else (at most every 100 ms) one held by a slot
// whose owner is gone -- its counts stay in the block (a hit its owner left in flight stays
// unaccounted, as with the stripes), the new owner adds to them.
static volatile LONG g_tblock_gen = 1;
static volatile LONG64 g_tsteal_after;
static probe_agent_tblock *steal_tblock(ThreadSlot *table, uint32_t size, DWORD tid) {
    for (uint32_t n = 0; n < size; ++n) {
        ThreadSlot &d = table[n];
        const LONG t = d.tid;
        if (!t || t == SLOT_MOVING || t == (LONG)tid || !d.blk || d.blk_gen != g_tblock_gen || !slot_owner_gone(t)) continue;
        if (InterlockedCompareExchange(&d.tid, SLOT_MOVING, t) != t) continue;
        probe_agent_tblock *b = nullptr;
        if (slot_owner_gone(t) && d.blk && d.blk_gen == g_tblock_gen) {
            b = d.blk; d.blk = nullptr; d.active = nullptr; d.active_acct = {};
        }
        InterlockedExchange(&d.tid, t);
        if (b) return b;
    }
    return nullptr;
}
static probe_agent_tblock *slot_block(ThreadSlot *ts, DWORD tid) {
    if (private_slot(ts)) return nullptr;    // TLS fallback uses stripes, and the untracked live count
    const LONG gen = g_tblock_gen;
    if (ts->blk_gen == gen && (ts->blk || GetTickCount64() < ts->blk_retry)) return ts->blk;
    probe_agent_tblock *b = nullptr;
    for (uint32_t i = 0; i < PROBE_AGENT_TBLOCKS && !b; ++i)
        if (!shared->tblocks[i].owner && InterlockedCompareExchange(&shared->tblocks[i].owner, (LONG)tid, 0) == 0)
            b = &shared->tblocks[i];
    if (!b && GetTickCount64() >= (ULONGLONG)g_tsteal_after &&
        InterlockedCompareExchange(&g_sweeper, (LONG)tid, 0) == 0) {          // one sweeper (see take_dead_slot)
        b = steal_tblock(g_threads, AGENT_THREAD_SLOTS, tid);
        if (!b) b = steal_tblock(g_overflow, AGENT_OVERFLOW_SLOTS, tid);
        if (!b) InterlockedExchange64(&g_tsteal_after, (LONG64)GetTickCount64() + 100);
        InterlockedExchange(&g_sweeper, 0);
        if (b) InterlockedExchange(&b->owner, (LONG)tid);
    }
    ts->blk = b; ts->blk_gen = gen;
    if (!b) ts->blk_retry = GetTickCount64() + 100;   // none free: the stripes; look again in 100 ms
    return b;
}

// The thread's last NT status (TEB LastStatusValue), beside GetLastError.
#if defined(_WIN64)
static inline volatile DWORD *teb_last_status() { return (volatile DWORD *)((unsigned char *)NtCurrentTeb() + 0x1250); }
static inline volatile DWORD *teb_last_error() { return (volatile DWORD *)((unsigned char *)NtCurrentTeb() + 0x68); }
static __forceinline DWORD current_tid() { return __readgsdword(0x48); }   // TEB ClientId.UniqueThread
#else
static inline volatile DWORD *teb_last_status() { return (volatile DWORD *)((unsigned char *)NtCurrentTeb() + 0xBF4); }
static inline volatile DWORD *teb_last_error() { return (volatile DWORD *)((unsigned char *)NtCurrentTeb() + 0x34); }
static __forceinline DWORD current_tid() { return __readfsdword(0x24); }
#endif

/* The volatile registers call_original's original left: with return_from the caller gets
   them except AX (return_from's value) and any the callback set_reg'd after the call
   (HitScope::seen), so its return registers above all -- x64 XMM0; x86 EDX:EAX (EDX through
   probe_x86_return_regs), XMM0, ST0 (HitScope::x87_post). */
struct OrigPost {                    // x64: written by uhh_orig_thunk (gpr +0x00, xmm +0x30)
    uint64_t gpr[6];                 // x64 RCX RDX R8 R9 R10 R11; x86 ECX EDX
    unsigned char xmm[8][16];        // x64 XMM0-5; x86 XMM0-7
};
static_assert(offsetof(OrigPost, xmm) == 0x30, "uhh_orig_thunk layout");
static __forceinline void hit_settle(const HitAcct &a, bool logged);
struct HitScope {
    // Not zero-filled per hit (post / seen are written before they are read: only after
    // call_original ran, see orig_ran) -- ~250 bytes of memset per hit showed on x86.
    HitScope(const HitAcct &a, ThreadSlot *s, LONG e) : acct(a), slot(s), epoch(e) {}
    HitAcct acct;                   // where it is counted: its unaccounted unit and running count
    ThreadSlot *slot;               // this thread's slot (null: none free, see thread_slot)
    volatile LONG abandoned = 0;
    LONG epoch;                        // one relaxed snapshot at callback entry; checked by log publication only
    const void *xmm6 = nullptr;     // x64: the hit's XMM6..XMM15 (safetyhook Context, contiguous)
    uintptr_t canary = 0;           // (uintptr_t)this ^ HIT_CANARY while the callback runs
    const void *xmm0 = nullptr;     // the hit's XMM0..XMM5 (vector/float arguments; safetyhook Context)
    // call_original ran: what the original left, for return_from (and for a callback that
    // faults after the call). The caller then gets it all, as from an un-hooked call -- see
    // OrigPost -- and the thread's last error / last status as the original left them (the
    // callback's own Win32 calls are undone back to these, not to the values before the hit).
    bool orig_ran = false;
    bool logged = false;            // its first log carried the unaccounted unit (see agent_log)
    bool guarantee_saved = false;
    ULONG program_guarantee;       // written before guarantee_saved; pack into the x64 flag padding
    uint64_t orig_ret = 0;          // RAX / EAX (x86 EDX: probe_context::orig_edx)
    DWORD orig_error = 0, orig_status = 0;
    OrigPost post;
    uint64_t seen[6];          // the context's registers matching post.gpr when the original returned
    unsigned char *x87_post = nullptr; // x86: FNSAVE image of the x87 state after the original (an ST0
                                       // result): mid_entry's 108-byte buffer, reloaded after the
                                       // extended-state restore
};
static_assert(std::is_trivially_destructible_v<HitScope>, "no per-hit destructor/EH cleanup");
constexpr uintptr_t HIT_CANARY = (uintptr_t)0x5A17C0DEA11CE5EDull;
static void hit_scope_abandon(HitScope *h);
// Is h -- this thread's recorded running hit -- still live? A hit nested in a callback runs
// BELOW the outer callback's frame, on the same stack, with the outer scope intact. A longjmp
// that does not unwind (x64 jmp_buf.Frame == 0) out of call_original skips every frame in
// between, so no handler settles the hit: its record outlives its frame. The next hit is
// then at or above that frame (the longjmp went up), or the memory no longer holds the scope.
static bool hit_scope_live(const HitScope *h, uint64_t sp) {
    const NT_TIB *tib = reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
    const uintptr_t a = (uintptr_t)h, lo = (uintptr_t)tib->StackLimit, hi = (uintptr_t)tib->StackBase;
    if (a <= sp || a < lo || a + sizeof(HitScope) > hi) return false;   // never read off this stack
    return h->canary == (a ^ HIT_CANARY);
}

// Inline call_func runs its callee only while this thread's slot marks it as running c's
// callback: a probe the callee hits (resolution included: GetModuleHandle/GetProcAddress
// allocate) is then counted without re-entering a callback -- the documented contract, which
// breakpoint/hw keep too. Unguarded, an allocator probe whose callback calls call_func
// recursed until STATUS_STACK_OVERFLOW (examples/famous heap_tracker). A thread without a
// registry slot uses its private TLS slot when available. A context without either guard
// is refused with a warning, never run unguarded.
static volatile LONG g_warned_call[PROBE_AGENT_MAX_PROBES];
static bool call_func_guarded(probe_context *c) {
    const auto *h = c ? static_cast<const HitScope *>(c->hit_scope) : nullptr;
    if (h && h->slot && h->slot->active == h && (DWORD)h->slot->tid == GetCurrentThreadId()) return true;
    if (c && c->site < PROBE_AGENT_MAX_PROBES && !InterlockedExchange(&g_warned_call[c->site], 1))
        warn_log(c, "uhh warning: call_func refused: no recursion guard for this thread (agent thread table full)");
    return false;
}

constexpr int kOrigMaxArgs = 16;              // call_original's argument limit (probe_api.h)

#if defined(_WIN64)
struct OrigFrame {                   // layout read by uhh_orig_thunk
    uint64_t rip, rsp;               // the hit's return address, and the caller's SP after it
    uint64_t nv[8];                  // rbx rbp rsi rdi r12 r13 r14 r15 at the hit
    HitScope *scope;                 // +0x50
    const void *xmm6;                // +0x58
    const void *xmm0;                // +0x60 the hit's XMM0..XMM5 (loaded for the call; may be null)
    OrigPost *post;                  // +0x68 receives what the original left
};
static_assert(offsetof(OrigFrame, scope) == 0x50 && offsetof(OrigFrame, xmm6) == 0x58 &&
              offsetof(OrigFrame, xmm0) == 0x60 && offsetof(OrigFrame, post) == 0x68, "uhh_orig_thunk layout");
// args: the 4 register arguments, then UHH_ORIG_STACK_ARGS stack arguments (5th onwards).
#define UHH_ORIG_STACK_ARGS 32
extern "C" uint64_t uhh_orig_thunk(uint64_t fn, const uint64_t *args, OrigFrame *frame);
extern "C" EXCEPTION_DISPOSITION uhh_orig_unwind(EXCEPTION_RECORD *rec, void *frame, CONTEXT *, void *) {
    if (rec && (rec->ExceptionFlags & 0x66) && frame) {           // EXCEPTION_UNWIND: leaving through us
        auto *h = *reinterpret_cast<HitScope **>(static_cast<unsigned char *>(frame) + 0x148);   // uhh_orig_thunk
        if (h) hit_scope_abandon(h);
    }
    return ExceptionContinueSearch;
}
#else
struct SehRecord { SehRecord *next; void *handler; };
// FNSAVE/FRSTOR image of the x87 state (108 bytes in 32-bit protected mode).
static void x87_restore(const unsigned char *img) { __asm { mov eax, img
                                                            frstor [eax] } }
// Push the stack slots, load EAX/ECX/EDX (fastcall/thiscall/vectorcall/register conventions)
// and XMM0-5 (vectorcall), call, and record what the original left: EDX:EAX, the bytes it
// popped (its `ret N`), ECX, XMM0-7, and the x87 state holding an ST0 result. The x87 state
// the callback continues with is the hit's own (nothing pushed): return_from reloads x87_out.
static void call_tramp_x86(uint32_t target, const uint32_t *args32, int nargs, uint32_t eax_v, uint32_t ecx_v,
                           uint32_t edx_v, const void *vec_args, uint32_t *ret_lo, int32_t *popped, OrigPost *post,
                           unsigned char *x87_out, uint32_t hit_sp, HitScope *scope) {
    uint32_t lo = 0, hi = 0, ecx_post = 0, pb = 0;
    unsigned char *vec_out = post->xmm[0];
    unsigned char x87_pre[108];
    volatile int normal = 0;
    __try {
        // This function's own record heads the chain here; link it straight to the first
        // record that belongs to the program (above the hit's SP) for the call.
        SehRecord *self = (SehRecord *)(uintptr_t)__readfsdword(0);
        SehRecord *saved = self->next, *head = saved;
        while (head && head != (SehRecord *)(uintptr_t)0xFFFFFFFF && (uint32_t)(uintptr_t)head <= hit_sp) head = head->next;
        self->next = head;
        __asm {
            lea eax, x87_pre
            fnsave [eax]
            frstor [eax]
            mov eax, vec_args
            test eax, eax
            jz no_xmm
            movups xmm0, [eax]
            movups xmm1, [eax+16]
            movups xmm2, [eax+32]
            movups xmm3, [eax+48]
            movups xmm4, [eax+64]
            movups xmm5, [eax+80]
        no_xmm:
            mov ebx, esp
            mov ecx, nargs
            mov esi, args32
        push_loop:
            test ecx, ecx
            jz do_call
            dec ecx
            push dword ptr [esi + ecx*4]
            jmp push_loop
        do_call:
            mov edi, esp
            mov eax, eax_v
            mov ecx, ecx_v
            mov edx, edx_v
            call dword ptr [target]
            mov lo, eax
            mov hi, edx
            mov ecx_post, ecx
            mov eax, esp
            sub eax, edi
            mov pb, eax
            mov esp, ebx
            mov eax, vec_out
            movups [eax], xmm0
            movups [eax+16], xmm1
            movups [eax+32], xmm2
            movups [eax+48], xmm3
            movups [eax+64], xmm4
            movups [eax+80], xmm5
            movups [eax+96], xmm6
            movups [eax+112], xmm7
            mov eax, x87_out
            fnsave [eax]
            lea eax, x87_pre
            frstor [eax]
        }
        self->next = saved;
        normal = 1;
    } __finally {
        if (!normal && scope) hit_scope_abandon(scope);              // unwound past us
    }
    *ret_lo = lo; *popped = (int32_t)pb;
    post->gpr[0] = ecx_post; post->gpr[1] = hi;
}
#endif

// The hit is at a function entry: [SP] is a return address (see looks_like_return_site).
static bool hit_is_function_entry(probe_context *c, uint64_t *ret_addr) {
    uint64_t r = 0; unsigned char pre[8];
    if (!get_mem(c, c->hit_sp, &r, sizeof(void *)) || r < 8 || !get_mem(c, r - 8, pre, sizeof(pre))) return false;
    if (ret_addr) *ret_addr = r;
    return looks_like_return_site(pre);
}

static void warn_once(probe_context *c, const char *text);
extern "C" int call_original(probe_context *c, int nargs, uint64_t *out) {
    if (g_ctrl) return g_ctrl->call_original(c, nargs, out);
    auto *state = c ? static_cast<AgentState *>(c->controller) : nullptr;
    if (!state || !state->shared || state->index >= PROBE_AGENT_MAX_PROBES) return 0;
    if (nargs < 0 || nargs > kOrigMaxArgs) { warn_once(c, "call_original refused: nargs must be 0..16"); return 0; }
    auto *scope = static_cast<HitScope *>(c->hit_scope);
    const uint64_t tramp = state->shared->requests[state->index].trampoline;
    if (!tramp || !scope) return 0;
    uint64_t ret_addr = 0;
    if (!hit_is_function_entry(c, &ret_addr)) {
        warn_once(c, "call_original refused: not at a function entry ([SP] is no return address)");
        return 0;
    }
    // The original gets the hit's stack arguments as a COPY in a new frame: not just the nargs
    // the callback named but a window of the hit's stack (up to 32 x64 stack arguments / 64
    // x86 slots, never past the top of this thread's stack), so a function with more than 8
    // arguments, 64-bit or struct arguments (several x86 slots) or a hidden return pointer
    // runs with all of them -- as it does in place on breakpoint/hw.
    const NT_TIB *tib = reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
    const uint64_t stack_top = (uint64_t)(uintptr_t)tib->StackBase, stack_low = (uint64_t)(uintptr_t)tib->StackLimit;
    auto window = [&](uint64_t first, uint64_t slot, int cap) -> int {   // slots readable from first
        if (first < stack_low || first >= stack_top) return 0;
        const uint64_t n = (stack_top - first) / slot;
        return n < (uint64_t)cap ? (int)n : cap;
    };
    uint64_t r = 0;
#if defined(_WIN64)
    uint64_t a[4 + UHH_ORIG_STACK_ARGS] = {0};
    // The register arguments always go as the hit had them (as on breakpoint/hw, which run the
    // original in place): a method called with nargs 0 still gets `this` (RCX).
    for (int i = 0; i < (nargs > 4 ? nargs : 4); ++i) a[i] = get_func_arg(c, (size_t)i);
    const int extra = window(c->hit_sp + 0x28, 8, UHH_ORIG_STACK_ARGS);
    for (int i = 0; i < extra; ++i)
        if (4 + i >= nargs) a[4 + i] = reinterpret_cast<const uint64_t *>((uintptr_t)(c->hit_sp + 0x28))[i];
    OrigFrame f{};
    f.rip = ret_addr; f.rsp = c->hit_sp + 8;
    f.nv[0] = c->regs.rbx; f.nv[1] = c->regs.rbp; f.nv[2] = c->regs.rsi; f.nv[3] = c->regs.rdi;
    f.nv[4] = c->regs.r12; f.nv[5] = c->regs.r13; f.nv[6] = c->regs.r14; f.nv[7] = c->regs.r15;
    f.scope = scope; f.xmm6 = scope->xmm6; f.xmm0 = scope->xmm0; f.post = &scope->post;
    r = uhh_orig_thunk(tramp, a, &f);
    const uint64_t seen[6] = {c->regs.rcx, c->regs.rdx, c->regs.r8, c->regs.r9, c->regs.r10, c->regs.r11};
#else
    uint32_t a32[64] = {0}, lo = 0;
    int32_t popped = -1;
    for (int i = 0; i < nargs; ++i) a32[i] = (uint32_t)get_func_arg(c, (size_t)i);
    int n = window(c->hit_sp + 4, 4, 64);
    for (int i = nargs; i < n; ++i) a32[i] = reinterpret_cast<const uint32_t *>((uintptr_t)(c->hit_sp + 4))[i];
    if (n < nargs) n = nargs;
    call_tramp_x86((uint32_t)tramp, a32, n, (uint32_t)c->regs.rax, (uint32_t)c->regs.rcx, (uint32_t)c->regs.rdx,
                   scope->xmm0, &lo, &popped, &scope->post, scope->x87_post, (uint32_t)c->hit_sp, scope);
    r = lo;
    c->orig_edx = (uint32_t)scope->post.gpr[1];
    c->orig_pop = popped;
    const uint64_t seen[6] = {c->regs.rcx, c->regs.rdx};
#endif
    scope->orig_error = GetLastError(); scope->orig_status = *teb_last_status();
    scope->orig_ret = r;
    std::memcpy(scope->seen, seen, sizeof(seen));
    scope->orig_ran = true;
    forget_region(true);                               // the original may have changed protections
    c->called_original = 1;
    if (out) *out = r;
    return 1;
}
extern "C" void return_from(probe_context *c, uint64_t value, int nargs) {
    if (g_ctrl) { g_ctrl->return_from(c, value, nargs); return; }
    if (!c || nargs < 0 || nargs > 255) return;
    if (!hit_is_function_entry(c, nullptr)) {
        warn_once(c, "return_from refused: not at a function entry ([SP] is no return address)");
        return;
    }
#if defined(_WIN64)
    (void)nargs; c->regs.rax = value; c->ret_pop = 0;
#else
    uint32_t pop = (uint32_t)nargs * 4;
    if (probe_x86_return_regs(c, value, &pop) && c->site < PROBE_AGENT_MAX_PROBES &&
        !InterlockedExchange(&g_warned_pop[c->site], 1))
        warn_log(c, "uhh warning: return_from nargs=%d but the original popped %d bytes (ret %d); the original's "
                    "count is used", nargs, (int)c->orig_pop, (int)c->orig_pop);
    c->ret_pop = pop;
#endif
    c->returned = 1;
}

/* ---- Control plane from an inline callback: forwarded to the controller. ----
   get_session(c) returns a per-site proxy (so the controller knows which probe's
   callback module to resolve names in). Each call is one synchronous exception to the
   debugger; the callback itself is passed by EXPORT NAME and the controller runs its
   own copy of the same source (breakpoint/HW probes execute controller-side). */
struct AgentChannel {
    HANDLE handle;
    probe_agent_shared *view;
    AgentState *states;
    AgentChannel *next;
};
static AgentChannel *g_channels;                       // extra entries only for surviving-callback fallback

extern "C" probe_session *get_session(probe_context *c) {
    if (g_ctrl) return g_ctrl->get_session(c);
    auto *state = c ? static_cast<AgentState *>(c->controller) : nullptr;
    return state && state->index < PROBE_AGENT_MAX_PROBES ? &state->proxy : nullptr;
}

// SEH cannot share a frame with C++ objects; keep the raise in its own function.
static bool raise_ipc(probe_ipc_request *req) {
    ULONG_PTR arg = (ULONG_PTR)req;
    __try { RaiseException(PROBE_IPC_CODE, 0, 1, &arg); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }   // no controller listening
    return true;
}

static int forward(probe_session *s, uint32_t op, uint64_t address, const char *symbol,
                   probe_callback cb, uint32_t flags, const void *config = nullptr, size_t config_len = 0) {
    if (!s || !states || !cb) return 0;
    const uintptr_t offset = (uintptr_t)s - (uintptr_t)&states[0].proxy;
    if (offset >= sizeof(AgentState) * PROBE_AGENT_MAX_PROBES || offset % sizeof(AgentState)) return 0;
    if (config_len && !config) return 0;
    HMODULE owner{}, caller{};
    const probe_callback origin = callbacks[offset / sizeof(AgentState)];
    if (!origin || !GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                     reinterpret_cast<LPCSTR>(cb), &owner) ||
        !GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(origin), &caller) || owner != caller) return 0;
    probe_ipc_request req{};
    req.op = op; req.flags = flags; req.origin_site = s->site; req.address = address;
    std::string name;
    if (!callback_export_names(cb, name)) return 0;           // all names of a folded function
    req.callback = (uintptr_t)name.data(); req.callback_len = name.size();
    if (symbol) { req.symbol = (uintptr_t)symbol; req.symbol_len = strlen(symbol); }
    if (config_len) { req.config = (uintptr_t)config; req.config_len = config_len; }
    return raise_ipc(&req) ? req.result : 0;
}

extern "C" int probe_add_address(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags) {
    if (g_ctrl) return g_ctrl->add_address(s, address, cb, flags);
    return forward(s, PROBE_IPC_ADD_ADDRESS, address, nullptr, cb, flags);
}
extern "C" int probe_watch(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags) {
    if (g_ctrl) return g_ctrl->watch(s, address, cb, flags);
    return forward(s, PROBE_IPC_WATCH, address, nullptr, cb, flags);
}
extern "C" int probe_add_symbol(probe_session *s, const char *symbol, probe_callback cb, uint32_t flags) {
    if (g_ctrl) return g_ctrl->add_symbol(s, symbol, cb, flags);
    return forward(s, PROBE_IPC_ADD_SYMBOL, 0, symbol, cb, flags);
}
extern "C" int probe_add_symbol_cfg(probe_session *s, const char *symbol, probe_callback cb, uint32_t flags,
                                    const void *config, size_t config_len) {
    if (g_ctrl) return g_ctrl->add_symbol_cfg(s, symbol, cb, flags, config, config_len);
    return forward(s, PROBE_IPC_ADD_SYMBOL, 0, symbol, cb, flags, config, config_len);
}

static volatile LONG g_stopping;
// Every hit is counted with an unaccounted unit in the SHARED block (hit_stripes' high bits)
// that leaves with the callback's first log or when it returns: what is left when the process
// dies (ExitProcess kills threads mid-callback) is reported by the controller as
// callbacks_interrupted (probe_agent_stripe).
// A callback ended (returned, or was unwound past): it no longer runs, and its unaccounted
// unit goes -- unless its first log already carried it (probe_agent_stripe).
static __forceinline void restore_hit_guarantee(HitScope *h);
static __forceinline void hit_settle(const HitAcct &a, bool logged) {
    // The controller reuses a channel only after running==0; live callbacks get a separate
    // channel on reattach. No epoch read is needed here, and running is the LAST store.
    if (probe_agent_tblock *b = a.blk) {                 // the owner's block: plain stores
        if (!logged) probe_agent_store64(&b->done, probe_agent_load64(&b->done) + 1);
        b->running = b->running - 1;
        return;
    }
    if (!a.line) return;
    if (!logged) InterlockedExchangeAdd64(&a.line->value, -PROBE_AGENT_INFLIGHT_ONE);
    InterlockedDecrement64(&a.line->running);
}
// Explicit finalisation avoids destructor/EH work on every hit while retaining the channel
// through late warnings. Original-function unwinds settle separately in hit_scope_abandon.
static __forceinline bool finish_hit(bool result, DWORD error, DWORD status, const HitScope *scope = nullptr) {
    if (scope && !scope->abandoned) hit_settle(scope->acct, scope->logged);
    *teb_last_status() = status;
    *teb_last_error() = error;
    return result;
}
// An exception or longjmp left the original (call_original) and is unwinding past this
// hit's callback: settle what call_mid would have on return (once).
static void hit_scope_abandon(HitScope *h) {
    if (InterlockedExchange(&h->abandoned, 1)) return;
    if (h->slot && h->slot->active == h) h->slot->active = nullptr;
    if (!h->slot || private_slot(h->slot)) InterlockedDecrement(&g_untracked_running);   // call_mid's own decrement never runs now
    restore_hit_guarantee(h);
    hit_settle(h->acct, h->logged);
}
// The hit a record from c may carry: c's own, on its own thread while its callback runs (the
// slot names it), and only for its first record. Slotless hits carry their striped unit too.
static __forceinline bool log_epoch_current(probe_context *c, const probe_agent_shared *sh) {
    const auto *h = static_cast<const HitScope *>(c->hit_scope);
    return h && h->epoch == load_epoch(sh);
}
static __forceinline HitScope *log_carrier(probe_context *c) {
    if (!c || !c->hit_scope) return nullptr;
    auto *h = static_cast<HitScope *>(c->hit_scope);
    ThreadSlot *const ts = h->slot;
    if (c->tid != current_tid() || (ts && ((DWORD)ts->tid != c->tid || ts->active != h))) return nullptr;
    return h->logged ? nullptr : h;
}
// The block a carried record names (probe_agent_log::reserved): index + 1, 0 = the stripes.
static __forceinline uint32_t log_carry_block(const HitScope *h, const probe_agent_shared *sh) {
    return h && h->acct.blk ? (uint32_t)(h->acct.blk - sh->tblocks) + 1 : 0;
}
// The carrier's record was published / handed over (the controller retires the unit), or
// dropped (counted in log_dropped: the unit goes here).
static __forceinline void log_carried(HitScope *h, bool dropped) {
    if (!h) return;
    if (dropped) {
        if (probe_agent_tblock *b = h->acct.blk) probe_agent_store64(&b->done, probe_agent_load64(&b->done) + 1);
        else if (h->acct.line) InterlockedExchangeAdd64(&h->acct.line->value, -PROBE_AGENT_INFLIGHT_ONE);
    }
    h->logged = true;
    if (h->slot) h->slot->active_logged = 1;     // the owner's own slot: a plain (volatile) store, in program order
}
// Callbacks still executing (an unhook waits for them).
static bool any_inflight() {
    if (!shared) return false;
    return probe_agent_running(shared) != 0;
}

// XSAVE support, probed once: mask = XCR0 restricted to x87|SSE|AVX|AVX-512 components.
// size = the save area THOSE components need (standard or compacted layout), not CPUID(0xD,0)
// .EBX, which covers every XCR0 feature -- with AMX tiles (~11 KB) that exceeded the buffer,
// and the hit then saved nothing at all (a callback's VZEROUPPER wiped the live YMM state).
// x86: the gated mask also keeps live x87/MMX. 32-bit C code returns
// floating-point values in ST0, so any callback (or CRT) float call pushes/pops the x87 stack
// and changes its status word, which a mid-function site may have live.
static struct XState { bool ok = false, compact = false, xinuse = false; uint64_t mask = 0, avx_mask = 0; uint32_t size = 0, full = 0; } g_xs = [] {
    XState x;
    int r[4];
    __cpuid(r, 1);
    if (!(r[2] & (1 << 27))) return x;                     // OSXSAVE
    __cpuidex(r, 0xD, 0);
    const uint64_t supported = (uint32_t)r[0] | ((uint64_t)(uint32_t)r[3] << 32);
    x.full = (uint32_t)r[1];                               // full XCR0 area; this buffer is mask-specific
    x.mask = _xgetbv(0) & supported & 0xE7ull;              // CPUID and XGETBV can differ under emulation
    x.avx_mask = x.mask & 0xE4ull;                         // AVX upper + AVX-512 (opmask, ZMM) only
#if !defined(_WIN64)
    x.avx_mask |= x.mask & 1ull;                           // x86 callbacks use x87; x64 contract: probe_api.h
#endif
    char knob[8] = {};                                     // regress: a CPU with AMX tiles in XCR0
    if (GetEnvironmentVariableA("UHH_BENCH_XSTATE", knob, sizeof(knob)) && !strcmp(knob, "amx")) x.full += 8192;
    __cpuidex(r, 0xD, 1); x.compact = (r[0] & 2) != 0; x.xinuse = (r[0] & 4) != 0;   // XGETBV(1)
    uint32_t size = 576;                                   // legacy region + XSAVE header
    for (int i = 2; i < 8; ++i) {
        if (!(x.mask & (1ull << i))) continue;
        __cpuidex(r, 0xD, i);                              // EAX size, EBX offset, ECX bit 1: 64-aligned
        const uint64_t end = x.compact
            ? (uint64_t)((r[2] & 2) ? (size + 63) & ~63u : size) + (uint32_t)r[0]
            : (uint64_t)(uint32_t)r[1] + (uint32_t)r[0];
        const uint64_t standard_end = (uint64_t)(uint32_t)r[1] + (uint32_t)r[0];
        if (!r[0] || end > 4096 || standard_end > 4096 || (uint32_t)r[1] < 576) return x;
        if (end > size) size = (uint32_t)end;
    }
    x.size = size;
    x.ok = x.size <= 4096;
    return x;
}();



// A callback's stack overflow must reach run_callback's __except: on a CPU with a large XSAVE
// area (AMX) the overflow's exception frame does not fit the stack Windows leaves by default
// and the TARGET died (probe_callback_stack_guarantee). The callback runs on the program's
// thread, so its guarantee (TEB GuaranteedStackBytes, what SetThreadStackGuarantee sets and
// the kernel reads at a guard-page fault) is raised for the callback only and put back after:
// the program's own TEB and overflow behaviour are unchanged. The offset is checked once (on
// the agent's own thread, against SetThreadStackGuarantee) before it is ever written.
#if defined(_WIN64)
static inline volatile ULONG *teb_stack_guarantee() { return (volatile ULONG *)((unsigned char *)NtCurrentTeb() + 0x1748); }
#else
static inline volatile ULONG *teb_stack_guarantee() { return (volatile ULONG *)((unsigned char *)NtCurrentTeb() + 0xF78); }
#endif
static __forceinline void restore_hit_guarantee(HitScope *h) {
    if (h->guarantee_saved) {
        *teb_stack_guarantee() = h->program_guarantee;
        h->guarantee_saved = false;
    }
}
static ULONG g_cb_guarantee;             // 0: unknown offset / not needed -- left alone
static void probe_stack_guarantee_offset() {   // on an agent thread (its guarantee is ours to change)
    // (A request below the system's effective default is a no-op that leaves the field alone:
    // probe with the real value, which is above it.)
    const ULONG need = probe_callback_stack_guarantee();
    ULONG prev = 0;
    if (!SetThreadStackGuarantee(&prev) || *teb_stack_guarantee() != prev) return;
    ULONG want = need > prev ? need : prev + 4096;
    if (!SetThreadStackGuarantee(&want) || *teb_stack_guarantee() != (need > prev ? need : prev + 4096)) return;
    g_cb_guarantee = need;
}

// DF=0 for C code. POPF is microcoded (~20 cycles), PUSHF is not: written only when DF is set.
static __forceinline void clear_df() {
    const uintptr_t f = __readeflags();
    if (f & 0x400) __writeeflags(f & ~(uintptr_t)0x400);
}

// The callback runs on the target's own thread: any Win32 call it (or the library) makes
// can change the thread's last-error / last-status, which the target may read right
// after the probed instruction. Save and restore both (plain TEB fields: ~free) -- to what
// the original left if call_original ran (see HitScope).
static bool run_callback(probe_callback cb, probe_context *c, DWORD &last_error, DWORD &last_status) {
    // The entry scope saved these before bookkeeping and restored them at callback entry.
    // Update that snapshot only for call_original; finish_hit restores it on every exit.
    bool ok = true;
    DWORD code = 0;
    volatile ULONG *const guarantee = teb_stack_guarantee();
    const ULONG program_guarantee = g_cb_guarantee ? *guarantee : 0;
    auto *scope = static_cast<HitScope *>(c->hit_scope);
    if (g_cb_guarantee && scope) {
        scope->program_guarantee = program_guarantee;
        scope->guarantee_saved = true;
    }
    const bool lift = g_cb_guarantee > program_guarantee;
    if (lift) *guarantee = g_cb_guarantee;
    __try { cb(c); }
    __except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    // A callback that overflowed the stack used up the thread's guard page (the target's
    // stack): restore it, or the program's own next overflow is no longer catchable.
    if (code == EXCEPTION_STACK_OVERFLOW) _resetstkoflw();
    if (scope) restore_hit_guarantee(scope);
    if (const auto *h = static_cast<const HitScope *>(c->hit_scope); h && h->orig_ran) {
        last_error = h->orig_error; last_status = h->orig_status;
    }
    return ok;
}
/* SafetyHook's Context is Context64 on x64 and Context32 on x86; fill the same gospel
   probe_regs from whichever register image this build captured. */
static void load_regs(probe_regs &r, const safetyhook::Context &native) {
#if defined(_WIN64)
#define COPY(a,b) r.a = native.a;
    PROBE_GPRS(COPY)
#undef COPY
    r.rsp = native.rsp; r.flags = native.rflags;
#else
    r.rax = native.eax; r.rbx = native.ebx; r.rcx = native.ecx;
    r.rdx = native.edx; r.rsi = native.esi; r.rdi = native.edi;
    r.rbp = native.ebp; r.rsp = native.esp; r.flags = native.eflags;
#endif
}
// Kept out of line so the 4 KiB save area (and its stack probe) costs nothing on the
// common path.
// x87_post (x86): a 108-byte buffer owned by the caller; returns true when it holds the x87
// state return_from must leave (an ST0 result of call_original), to reload after any
// extended-state restore.
// Every field set below, none zero-filled first (a memset of the whole context per hit showed
// on x86): orig_pop must stay the last field, or a new one would be left uninitialised here.
static_assert(sizeof(probe_context) - (offsetof(probe_context, orig_pop) + sizeof(int32_t)) < 8,
              "call_mid initialises probe_context field by field: add the new field there");
static bool call_mid(safetyhook::Context &native, uint32_t index, unsigned char *x87_post) {
    struct TebScope {
        DWORD error = *teb_last_error(), status = *teb_last_status();
        __forceinline void restore() const { *teb_last_status() = status; *teb_last_error() = error; }
    } teb;
    AgentState *const state = &states[index];
    const LONG epoch = load_epoch(state->shared);         // before capturing session-owned data
    probe_context c;
    load_regs(c.regs, native);
#if !defined(_WIN64)
    c.regs.r8 = c.regs.r9 = c.regs.r10 = c.regs.r11 = c.regs.r12 = c.regs.r13 = c.regs.r14 = c.regs.r15 = 0;
#endif
    c.regs.pc = sites[index]; c.hit_sp = c.regs.rsp;
    c.backend = nullptr; c.ret_pop = 0; c.called_original = 0; c.returned = 0; c.hit_scope = nullptr;
    c.orig_edx = 0; c.orig_pop = 0;
    const auto &request = state->shared->requests[index];
    c.config = !request.config_len ? nullptr
             : request.config_len > PROBE_AGENT_CONFIG_CAP ? (void *)(uintptr_t)request.config_remote : (void *)request.config;
    c.ops = &local_ops; c.tid = current_tid(); c.site = index; c.controller = state;
    // Count the hit before the call so a faulting callback is still accounted, and run
    // the callback under SEH so an access violation (or any exception) inside user code
    // cannot take down the target. On a fault we skip register write-back, leaving the
    // target's registers untouched (the callback behaves as a no-op mutation).
    // Live detach passes straight through without counting a callback. Orphan cleanup
    // instead counts/drops each still-hooked call, since nobody can receive its callback.
    if (g_agent_threads.has(c.tid) || g_sweeper == (LONG)c.tid) return finish_hit(false, teb.error, teb.status);   // the agent's own work: see g_agent_threads, take_dead_slot
    const probe_callback cb = callbacks[index];
    if (!cb) return finish_hit(false, teb.error, teb.status);
    if (g_test_preaccount) {
        g_test_preaccount = false;
        const LONG stall = g_test_cf_stall;
        g_test_cf_stall = 1;
        test_cf_point(1);                                 // regress: paused before running is visible
        g_test_cf_stall = stall;
        g_test_preaccount = false;
    }
    ThreadSlot *const ts = my_slot(c.tid);
    if (ts && ts->busy) return finish_hit(false, teb.error, teb.status);                      // the agent's own query: see ThreadSlot
    // Count the hit and its unaccounted unit FIRST (a thread killed at any later instant leaves
    // it counted: probe_agent_tblock), then mark a callback running.
    HitAcct acct{ts ? slot_block(ts, c.tid) : nullptr, nullptr, index};
    if (probe_agent_tblock *b = acct.blk) {
        probe_agent_store64(&b->hits[index], probe_agent_load64(&b->hits[index]) + 1);
        b->running = b->running + 1;
    } else {
        // ONE atomic add counts the hit and its unaccounted unit (see probe_agent_stripe): a
        // thread killed between two separate counters left a hit that was neither logged nor
        // interrupted. `running` is separate: it is not accounting.
        acct.line = &state->shared->hit_stripes[index][(c.tid >> 2) & (PROBE_AGENT_STRIPES - 1)];
        InterlockedExchangeAdd64(&acct.line->value, 1 + PROBE_AGENT_INFLIGHT_ONE);
        InterlockedIncrement64(&acct.line->running);
    }
    _ReadWriteBarrier();
    // g_stopping is checked only once this hit is running: probe_agent_stop sets it, then
    // FlushProcessWriteBuffers (every processor's pending stores land: an asymmetric fence --
    // the block's plain stores need no LOCK here), then waits for running callbacks. So a hit is
    // either seen by that wait or sees the flag. The entry epoch also rejects a hit paused
    // before accounting across detach AND reattach (which clears g_stopping).
    // Checked first, a thread between the check and
    // the count ran its callback after the detach (its IPC then raised an exception nobody
    // handled, visible to the target).
    if (g_stopping || state->shared != shared || epoch != load_epoch(state->shared)) {
        // A dead controller cannot receive callbacks, but a hook still installed during
        // orphan cleanup must account its calls until the bytes are actually restored.
        // Normal detach / an old channel still use the rollback below.
        if (g_stopping && state->shared == shared && epoch == load_epoch(state->shared) &&
            state->shared->controller_gone) {
            InterlockedIncrement(&state->shared->log_dropped);
            hit_settle(acct, false);                        // keep the hit, settle its unit/running
            return finish_hit(false, teb.error, teb.status);
        }
        if (probe_agent_tblock *b = acct.blk) {
            probe_agent_store64(&b->hits[index], probe_agent_load64(&b->hits[index]) - 1);
            b->running = b->running - 1;
        } else {
            InterlockedExchangeAdd64(&acct.line->value, -(1 + PROBE_AGENT_INFLIGHT_ONE)); InterlockedDecrement64(&acct.line->running);
        }
        return finish_hit(false, teb.error, teb.status);
    }
    // A probe hit by code the callback itself runs (call_func of a probed function, or a
    // probed API called directly) is counted but does not re-enter a callback -- exactly
    // what breakpoint/hw do inside call_func. Re-entering recursed until the stack overflowed.
    // The guard is the thread's slot (no TLS: see ThreadSlot); a record left behind by a
    // non-unwinding longjmp is recognised as stale (hit_scope_live) and settled here.
    if (ts && ts->active && !hit_scope_live(ts->active, c.hit_sp)) {
        // This thread's own record (a longjmp skipped its settling) -- or, when the TEB and
        // stack were reused too, a dead thread's: another creation time. That hit stays in
        // flight (interrupted).
        const uint64_t now = thread_born(ts);
        if (!ts->born || !now || now == ts->born) hit_settle(ts->active_acct, ts->active_logged != 0);
        if (private_slot(ts)) InterlockedDecrement(&g_untracked_running);
        ts->born = now;
        ts->active = nullptr;
    }
    if (ts && ts->active) {
        hit_settle(acct, false); return finish_hit(false, teb.error, teb.status);
    }
    if (!ts) {
        // No static TLS yet AND both tables full: never run an unguarded callback. Direct
        // calls of a probed API could otherwise recurse until the target's stack overflows.
        warn_once(&c, "callback refused: agent thread table full before TLS initialisation");
        hit_settle(acct, false);
        return finish_hit(false, teb.error, teb.status);
    }
    // The mid-hook stub preserves GPRs, flags and XMM0-15 only. The callback (and the CRT
    // it calls) may touch x87/MXCSR/YMM/ZMM state -- e.g. vzeroupper -- which the target
    // could be relying on at a mid-function site. Save and restore the full extended state
    // and give C code the ABI-required DF=0.
    // Extended state (MXCSR, AVX/AVX-512) and DF are handled in mid_entry, BEFORE any of
    // this C code runs -- see there.
    forget_region();
    HitScope scope{acct, ts, epoch};                       // retain the admission epoch for logging
    scope.canary = (uintptr_t)&scope ^ HIT_CANARY;
#if defined(_WIN64)
    scope.xmm6 = &native.xmm6;
#endif
    scope.xmm0 = &native.xmm0;
    scope.x87_post = x87_post;
    if (acct.blk) acct.blk->probe = (LONG)index;          // diagnostics: probe_agent_cut_off
    if (ts) { ts->active_acct = acct; ts->active_logged = 0; ts->active = &scope; }
    if (!ts || private_slot(ts)) InterlockedIncrement(&g_untracked_running);
    c.hit_scope = &scope;
    teb.restore();                                      // bookkeeping must not reach the callback/target
    bool callback_ok = run_callback(cb, &c, teb.error, teb.status);
    if (ts) ts->active = nullptr;
    if (!ts || private_slot(ts)) InterlockedDecrement(&g_untracked_running);
    scope.canary = 0;
    if (!callback_ok) {
        // A faulting callback is a no-op: its register changes are discarded -- unless it had
        // already run the original (call_original). Falling through would run the original a
        // SECOND time (a double free / double close), so the hooked function returns to its
        // caller as with return_from: with return_from's value if one was set, else the
        // original's own result (x86: EDX:EAX and the bytes it popped), and everything else
        // the original left, like any return_from after call_original (below).
        if (!c.called_original || !scope.orig_ran) return finish_hit(false, teb.error, teb.status, &scope);
        const uint64_t ax = c.returned ? c.regs.rax : scope.orig_ret, dx = c.returned ? c.regs.rdx : c.orig_edx;
#if !defined(_WIN64)
        if (!c.returned) {
            if (c.orig_pop < 0 || c.orig_pop > 1020 || (c.orig_pop & 3)) return finish_hit(false, teb.error, teb.status, &scope);   // not measured
            c.ret_pop = (uint32_t)c.orig_pop;
        }
#endif
        load_regs(c.regs, native);
        c.regs.rax = ax;
#if !defined(_WIN64)
        c.regs.rdx = dx;
#else
        (void)dx;
#endif
        c.returned = 1;
    }
#if defined(_WIN64)
#define COPY(a,b) native.a = c.regs.a;
    PROBE_GPRS(COPY)
#undef COPY
#else
    native.eax = (uint32_t)c.regs.rax; native.ebx = (uint32_t)c.regs.rbx;
    native.ecx = (uint32_t)c.regs.rcx; native.edx = (uint32_t)c.regs.rdx;
    native.esi = (uint32_t)c.regs.rsi; native.edi = (uint32_t)c.regs.rdi;
    native.ebp = (uint32_t)c.regs.rbp;
#endif
    // set_reg(SP): the patched resume stub (cmake/patch_safetyhook.cmake, uhh_resume_jmp)
    // ends `pop rsp; jmp [trampoline]`, so the context's rsp IS the stack pointer the
    // hooked code resumes with -- nothing is written to the stack (moving SP down cannot
    // clobber the saved registers) and there is no `ret` to a pushed address (CET shadow
    // stacks never see the hook).
#if defined(_WIN64)
    native.rsp = c.regs.rsp;
#else
    native.esp = (uint32_t)c.regs.rsp;
#endif
    if (c.returned && g_ret_thunks) {
        // return_from: the stub ends `jmp [Context::rip]` with rsp at Context::rsp; the thunk
        // pops the hit's SP and returns (x86: ret N) to the caller.
#if defined(_WIN64)
        native.rsp = c.hit_sp; native.rip = (uintptr_t)(g_ret_thunks + c.ret_pop);
#else
        native.esp = (uint32_t)c.hit_sp; native.eip = (uintptr_t)(g_ret_thunks + c.ret_pop);
#endif
        // After call_original the caller gets what the original left (see OrigPost): its
        // volatile registers -- unless the callback set_reg'd them after the call (all of
        // them after a fault: its changes are discarded) -- XMM0-5 (x86 XMM0-7), and on x86
        // ST0 through the x87 image the hook entry reloads.
        if (c.called_original && scope.orig_ran) {
#if defined(_WIN64)
            uintptr_t *const regs[] = {&native.rcx, &native.rdx, &native.r8, &native.r9, &native.r10, &native.r11};
            const uint64_t now[] = {c.regs.rcx, c.regs.rdx, c.regs.r8, c.regs.r9, c.regs.r10, c.regs.r11};
            constexpr size_t xmm_n = 6;
#else
            uintptr_t *const regs[] = {&native.ecx};      // EDX: return_from (probe_x86_return_regs)
            const uint64_t now[] = {c.regs.rcx};
            constexpr size_t xmm_n = 8;
#endif
            for (size_t k = 0; k < std::size(regs); ++k)
                if (!callback_ok || now[k] == scope.seen[k]) *regs[k] = (uintptr_t)scope.post.gpr[k];
            std::memcpy(&native.xmm0, scope.post.xmm, xmm_n * 16);
            return finish_hit(scope.x87_post != nullptr, teb.error, teb.status, &scope);
        }
        return finish_hit(false, teb.error, teb.status, &scope);
    } else if (c.returned || c.called_original) {
        warn_once(&c, c.returned ? "return_from could not be applied (no return thunk); the original runs"
                                 : "call_original without return_from -- the original runs again on fall-through");
    }
    return finish_hit(false, teb.error, teb.status, &scope);
}

// All-zero STANDARD image for components whose architectural initial state is requested.
// It is immutable and shared by hits; no per-hit frame/header clear or XCOMP_BV modification.
// AVX's MXCSR dependency is avoided by handling YMM/ZMM0..15 uppers with VZEROUPPER first.
// SSE is deliberately absent from avx_mask: the hook stub restores every XMM register.
// XINUSE[1] is not a portable test for MXCSR's value (SDM Vol. 1, 13.6/13.8);
// MXCSR is saved/restored separately even when SSE reports INIT, never forced to 1F80.
alignas(64) static const unsigned char g_init_xstate[4096] = {};
static __declspec(noinline) void init_new_uppers() {
    // Isolate AVX code from callers that must also run on CPUs without AVX.
    _mm256_zeroupper();
}
#if !defined(_WIN64)
static __declspec(noinline) void init_new_x87() {
    // SDM Vol. 1, 13.6: INIT includes zero data registers, not just empty tags.
    // FNINIT alone leaves their physical contents intact. Clear all eight, then
    // reset TOP/tags/pointers and FCW=037F (not the Windows default of 027F).
    __asm {
        fninit
        fldz
        fldz
        fldz
        fldz
        fldz
        fldz
        fldz
        fldz
        fninit
    }
}
#endif
static __forceinline void restore_new_xstate(uint64_t saved) {
    const uint64_t missing = g_xs.avx_mask & ~saved;
    if (!missing || !g_xs.xinuse) return;
    uint64_t added = _xgetbv(1) & missing;
    if (!added) return;
#if !defined(_WIN64)
    if (added & 1ull) {
        init_new_x87();
        added &= ~1ull;
    }
#endif
    if (added & 0x44ull) {
        // Collateral zeroing of an originally live ZMM upper is undone by the saved-image
        // restore immediately afterwards. An unsaved upper was INIT and must stay zero.
        init_new_uppers();
        added &= ~0x44ull;
    }
    if (!added) return;
#if defined(_WIN64)
    _xrstor64(g_init_xstate, added);
#else
    _xrstor(g_init_xstate, added);
#endif
}

// Entry point of every inline hit. It runs FIRST, before any C code that might call the
// CRT: the CRT's memset/memcpy pick AVX paths ending in VZEROUPPER (wiping every YMM upper
// half the target may have live at a mid-function site), and its x86 rep-stos/movs paths
// run BACKWARDS if the site executes with DF=1. So: clear DF, then save what the stub
// does not (only live components), using intrinsics only -- then run the hit and initialise
// any newly activated components. The stub restores RFLAGS
// (so the target's DF) on the way out.
// N: the save area, sized to the CPU's need (g_xs.size): 1 KiB covers x87 + SSE + AVX (832
// bytes) -- no stack probe per hit (an x86 frame over 4 KiB calls __chkstk); 4 KiB otherwise.
template <uint32_t N>
static __declspec(noinline) bool mid_entry_saved(safetyhook::Context &native, uint32_t index, uint64_t mask,
                                                  unsigned char *x87_post) {
    alignas(64) unsigned char area[N];
    __stosb(area + 512, 0, 64);                            // XSAVE header must start clean (no CRT call)
#if defined(_WIN64)
    if (g_xs.compact) _xsavec64(area, mask); else _xsave64(area, mask);
#else
    if (g_xs.compact) _xsavec(area, mask); else _xsave(area, mask);
#endif
    unsigned int mxcsr = _mm_getcsr();
    const bool x87 = call_mid(native, index, x87_post);
    restore_new_xstate(mask);
#if defined(_WIN64)
    _xrstor64(area, mask);
#else
    _xrstor(area, mask);
#endif
    _mm_setcsr(mxcsr);
    return x87;
}

// No usable XSAVE (no OSXSAVE, or a save area past the buffer): x64 keeps MXCSR only
// (see the callback contract in probe_api.h). On x86, FXSAVE keeps the x87 state
// (ST0-7, control/status/tag words) and MXCSR around the callback, as XSAVE's x87 component
// does on the gated path. MXCSR alone let a callback's (or the CRT's) float code change a live
// x87 stack / status word at a mid-function site (x86 returns floats in ST0, so any float call
// pushes and pops it). The XMM registers the image also holds are put back by the hook stub
// afterwards anyway; without OSXSAVE there is no AVX state to keep.
static __declspec(noinline) bool mid_entry_fx(safetyhook::Context &native, uint32_t index, unsigned char *x87_post,
                                              uint64_t saved = ~0ull) {
#if defined(_WIN64)
    const unsigned int mxcsr = _mm_getcsr();             // x87/MMX is the callback's responsibility on x64
    const bool x87 = call_mid(native, index, x87_post);
    restore_new_xstate(saved);
    _mm_setcsr(mxcsr);
#else
    alignas(16) unsigned char fx[512];
    _fxsave(fx);
    const bool x87 = call_mid(native, index, x87_post);
    restore_new_xstate(saved);
    _fxrstor(fx);
#endif
    return x87;
}

#if !defined(_WIN64)
// x86 bench knob (xstate_mode 5, UHH_BENCH_XSTATE=fnsave): the x87 state by FNSAVE / FRSTOR
// (108 bytes, x87 only; FNSAVE leaves the FPU initialised, so the program's control word is put
// back for the callback), MXCSR by hand; AVX state, when live, by XSAVE as usual.
static __declspec(noinline) bool mid_entry_fnsave(safetyhook::Context &native, uint32_t index, unsigned char *x87_post, uint64_t saved) {
    unsigned char st[108]; unsigned char *p = st;
    __asm { mov eax, p
            fnsave [eax]
            fldcw word ptr [eax] }                          // the program's CW (first word of the image)
    unsigned int mxcsr = _mm_getcsr();
    const bool x87 = call_mid(native, index, x87_post);
    restore_new_xstate(saved);
    _mm_setcsr(mxcsr);
    __asm { mov eax, p
            frstor [eax] }
    return x87;
}
#endif

// Regress knob (xstate_mode 3, UHH_BENCH_XSTATE=noxsave): the no-XSAVE fallback on a CPU that
// HAS AVX. A CPU without OSXSAVE has no AVX state at all; this one does, so the AVX components
// alone are kept by XSAVE around the fallback, which is then tested for what it is responsible
// for -- x87, MXCSR -- exactly as without OSXSAVE.
static __declspec(noinline) bool mid_entry_noxsave_sim(safetyhook::Context &native, uint32_t index, uint64_t avx,
                                                       unsigned char *x87_post) {
    alignas(64) unsigned char area[4096];
    __stosb(area + 512, 0, 64);
#if defined(_WIN64)
    if (g_xs.compact) _xsavec64(area, avx); else _xsave64(area, avx);
    const bool x87 = mid_entry_fx(native, index, x87_post);
    _xrstor64(area, avx);
#else
    if (g_xs.compact) _xsavec(area, avx); else _xsave(area, avx);
    const bool x87 = mid_entry_fx(native, index, x87_post);
    _xrstor(area, avx);
#endif
    return x87;
}

// shared->xstate_mode, copied at init (set by the controller before it): the hit path does not
// read the shared header's cache line, which the ring's producers and the drainer write.
static LONG g_xmode;
static inline void mid_entry(safetyhook::Context &native, uint32_t index) {
    clear_df();                                            // DF=0 before ANY C code
#if defined(_WIN64)
    unsigned char *x87_post = nullptr;                     // x64 returns floating point in XMM0 only
#else
    unsigned char x87_buf[108], *x87_post = x87_buf;       // call_original's x87 state (ST0 result)
#endif
    bool x87 = false;
    // 0 gated (default), 1 none, 2 full (bench knobs), 3 as on a CPU without OSXSAVE (regress)
    const LONG xmode = g_xmode;
    const bool xs_ok = g_xs.ok && xmode != 3;
    uint64_t mask = 0;
    if (xmode != 1 && xs_ok) {
        if (xmode == 2) mask = g_xs.mask;
        else mask = g_xs.xinuse ? _xgetbv(1) & g_xs.avx_mask : g_xs.avx_mask;
    }
#if !defined(_WIN64)
    // Bench knobs, x86: 4 = x87 + MXCSR by FXSAVE, 5 = by FNSAVE (when no AVX state is live).
    if ((xmode == 4 || xmode == 5) && !(mask & ~1ull)) {
        x87 = xmode == 4 ? mid_entry_fx(native, index, x87_post, mask) : mid_entry_fnsave(native, index, x87_post, mask);
        if (x87) x87_restore(x87_post);
        return;
    }
#endif
#if !defined(_WIN64)
    // x86, only x87/MMX live: FXSAVE / FXRSTOR avoids the larger XSAVE frame.
    if (xmode == 0 && mask == 1) {
        x87 = mid_entry_fx(native, index, x87_post, mask);
        if (x87) x87_restore(x87_post);
        return;
    }
#endif
    if (xmode == 1) x87 = call_mid(native, index, x87_post);
    else if (xmode == 3 && g_xs.ok && (g_xs.mask & 0xE4ull))
        x87 = mid_entry_noxsave_sim(native, index, g_xs.mask & 0xE4ull, x87_post);
    else if (mask) x87 = g_xs.size <= 1024 ? mid_entry_saved<1024>(native, index, mask, x87_post)
                                           : mid_entry_saved<4096>(native, index, mask, x87_post);
    else if (!xs_ok) x87 = mid_entry_fx(native, index, x87_post);   // no XSAVE: x86 x87 + MXCSR; x64 MXCSR only
    else {
        unsigned int mxcsr = _mm_getcsr();                 // the common case: nothing live but MXCSR
        x87 = call_mid(native, index, x87_post);
        restore_new_xstate(0);
        _mm_setcsr(mxcsr);
    }
#if !defined(_WIN64)
    if (x87) x87_restore(x87_post);                        // return_from after call_original: ST0 = its result
#else
    (void)x87;
#endif
}

/* A fault in an instruction the hook RELOCATED into its trampoline (the hooked function's
   first bytes at the site, e.g. a load inside its own __try) is raised at the trampoline
   address. x64 dispatch looks handlers up by that address: there is no unwind data for it
   and the hooked function's own scope tables do not cover it, so the program's handler was
   never found (unhandled exception / std::terminate). The agent's vectored handler -- the
   first to run, it only rewrites -- moves such a fault to the original instruction it stands
   for (same registers: the relocated copy did not execute), so dispatch, unwind and crash
   reports see the program's own code. If a handler resumes it (EXCEPTION_CONTINUE_EXECUTION),
   the continue handler moves it back into the trampoline: the site itself holds the hook's
   jump. Each map is published (tramp != 0) before its hook is enabled. */
struct TrampMap { volatile uintptr_t tramp; uintptr_t site; uint32_t n; uint8_t t_off[16], o_off[16]; };
static TrampMap g_tmap[PROBE_AGENT_MAX_PROBES];
static void map_trampoline(uint32_t i, uintptr_t site, uintptr_t tramp, const std::vector<uint8_t> &orig) {
    TrampMap &m = g_tmap[i];
    m.tramp = 0;
    MemoryBarrier();
    if (!tramp || orig.empty() || orig.size() > 32) return;
    ZydisDecoder dec;
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
    const auto *t = reinterpret_cast<const uint8_t *>(tramp);
    MEMORY_BASIC_INFORMATION mbi{};        // decode only inside the trampoline's committed block
    if (!VirtualQuery(t, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) return;
    const uintptr_t tend = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    uint32_t o = 0, q = 0, n = 0;
    while (n < 16) {
        m.t_off[n] = (uint8_t)q; m.o_off[n] = (uint8_t)o; ++n;     // o == size: the jump back = site+len
        if (o >= orig.size()) break;
        ZydisDecodedInstruction a{}, b{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, orig.data() + o, orig.size() - o, &a)) ||
            tramp + q >= tend ||
            !ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, t + q, (size_t)std::min<uintptr_t>(32, tend - tramp - q), &b))) {
            --n; break;
        }
        // A CALL relocated as push + jmp (SafetyHook, uhh_relocate_call_as_jmp) is the last
        // instruction; its push stands for the call, nothing after it is reached.
        if (a.mnemonic == ZYDIS_MNEMONIC_CALL && b.mnemonic == ZYDIS_MNEMONIC_PUSH) break;
        o += a.length; q += b.length;
        if (q > 200) { --n; break; }
    }
    m.site = site; m.n = n;
    MemoryBarrier();
    m.tramp = tramp;
}
static bool tramp_to_site(uintptr_t ip, uintptr_t *site) {
    for (auto &m : g_tmap) {
        const uintptr_t t = m.tramp;
        if (!t || ip < t || ip - t > 255) continue;
        for (uint32_t k = 0; k < m.n; ++k)
            if (t + m.t_off[k] == ip) { *site = m.site + m.o_off[k]; return true; }
    }
    return false;
}
#if defined(_WIN64)
#define UHH_IP(ctx) (ctx)->Rip
#else
#define UHH_IP(ctx) (ctx)->Eip
#endif
using nt_raise_fn = LONG (NTAPI *)(EXCEPTION_RECORD *, CONTEXT *, BOOLEAN);
static nt_raise_fn g_nt_raise;           // ntdll!NtRaiseException, resolved at init
static LONG CALLBACK tramp_veh(EXCEPTION_POINTERS *ep) {
    const DWORD tid = GetCurrentThreadId();
    const uintptr_t ip = (uintptr_t)UHH_IP(ep->ContextRecord);
    if (ThreadSlot *ts = cached_slot() ? cached_slot() : thread_slot(tid, false)) // a new exception (not our re-raise)
        if (ts->moved_to && (uintptr_t)ep->ExceptionRecord->ExceptionAddress != ts->moved_to) ts->moved_to = 0;
    uintptr_t site = 0;
    if ((uintptr_t)ep->ExceptionRecord->ExceptionAddress != ip || !tramp_to_site(ip, &site)) return EXCEPTION_CONTINUE_SEARCH;
    if (ThreadSlot *ts = my_slot(tid)) { ts->moved_from = ip; ts->moved_to = site; }
    // RE-RAISE at the original address rather than edit this dispatch: the dispatcher's own
    // frame keeps a separate copy of the faulting RIP/RSP (its machine frame), which the
    // unwind to a handler walks through -- edited only in the CONTEXT, the unwind no longer
    // matched the dispatch and ended in STATUS_BAD_STACK. NtRaiseException starts a fresh
    // dispatch from the given context (the abandoned one is below its SP, never returned to).
    EXCEPTION_RECORD rec = *ep->ExceptionRecord;
    rec.ExceptionAddress = (void *)site;
    alignas(16) CONTEXT ctx = *ep->ContextRecord;
    ctx.ContextFlags &= ~(DWORD)0x40;                                   // CONTEXT_XSTATE: no CONTEXT_EX copied
    UHH_IP(&ctx) = site;
    if (g_nt_raise) g_nt_raise(&rec, &ctx, TRUE);                       // does not return
    return EXCEPTION_CONTINUE_SEARCH;
}
static LONG CALLBACK tramp_vch(EXCEPTION_POINTERS *ep) {
    ThreadSlot *ts = cached_slot();
    if (!ts) ts = thread_slot(GetCurrentThreadId(), false);
    if (!ts || !ts->moved_to) return EXCEPTION_CONTINUE_SEARCH;
    if ((uintptr_t)UHH_IP(ep->ContextRecord) == ts->moved_to) UHH_IP(ep->ContextRecord) = ts->moved_from;
    ts->moved_to = 0;
    return EXCEPTION_CONTINUE_SEARCH;
}

// One entry thunk per request slot (the slot index is baked in), generated at compile time.
using mid_callback = void (*)(safetyhook::Context &);
template <uint32_t N> static void mid_thunk(safetyhook::Context &c) { mid_entry(c, N); }
template <size_t... I> static constexpr std::array<mid_callback, sizeof...(I)> make_mid_thunks(std::index_sequence<I...>) {
    return {{ &mid_thunk<(uint32_t)I>... }};
}
static constexpr auto mid_callbacks = make_mid_thunks(std::make_index_sequence<PROBE_AGENT_MAX_PROBES>{});
struct HookOp { uint32_t index; uint64_t site; bool ok; };
static void build_hook(void *p) {
    auto *op = static_cast<HookOp *>(p);
    hooks[op->index] = safetyhook::create_mid((void *)(uintptr_t)op->site, mid_callbacks[op->index],
                                              safetyhook::MidHook::StartDisabled);
}
// The exact bytes each enabled hook wrote at its site (the jump SafetyHook emitted, padded with
// NOPs over the instructions it displaced): the final unhook restores a site only while it
// still holds THESE bytes (see disable_hook). Longest patch: a 14-byte FF jump over a
// displaced instruction of up to 15 bytes.
struct PatchBytes { uint8_t b[32]; uint32_t len; };
static PatchBytes g_patch[PROBE_AGENT_MAX_PROBES];
static void enable_hook(void *p) {
    auto *op = static_cast<HookOp *>(p);
    auto &h = hooks[op->index];
    auto &pb = g_patch[op->index];
    pb.len = 0;
    shared->requests[op->index].install_failure = PROBE_INSTALL_WRITE;
    op->ok = h.enable().has_value();
    if (op->ok) shared->requests[op->index].install_failure = PROBE_INSTALL_VERIFY;
    const size_t n = h.original_bytes().size();
    if (op->ok && n && n <= sizeof(pb.b)) {
        std::memcpy(pb.b, (const void *)h.target_address(), n);    // read back what was written (SEH-guarded by seh_run)
        pb.len = (uint32_t)n;
    }
}
// The final unhook (probe_agent_stop) of a site whose DLL another thread unloaded before the
// controller processed that unload (its status is not UNLOADED yet -- e.g. during an early
// detach while the program churns the DLL): the restore wrote to the unmapped site, an
// access violation on the agent's stop thread killed the target (regress
// lifecycle-detach-early-*-inline, ~1 in 128 on CI; ROADMAP L5). Not mapped executable code:
// nothing to restore. The bytes already the original ones (the DLL was mapped again, a fresh
// copy, at the same base): nothing to restore either. The write itself is SEH-guarded
// (seh_run) against an unmap completing meanwhile (a thread suspended inside its unmap
// system call still finishes it).
// More generally the site is restored ONLY while it still holds exactly the patch this hook
// wrote (g_patch). Anything else there is not ours: a different image or JIT/executable
// allocation mapped at the old DLL's address before its unload was processed (the old DLL's
// original bytes written over it corrupted the program: regress lifecycle-unload-reused-*),
// a fresh copy of the DLL (its original bytes), or another hooking tool's jump written over
// ours. Such a hook is abandoned in place (its trampoline and stub leak, never reached).
static bool site_mapped(uint64_t site);
static bool bytes_equal(const void *a, const uint8_t *b, size_t n) {
    uintptr_t at = (uintptr_t)a, end = at + n;
    if (end < at) return false;
    while (at < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((void *)at, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
            (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) || !(mbi.Protect & 0xFE)) return false;
        const uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= at) return false;
        at = next;
    }
    __try { return std::memcmp(a, b, n) == 0; }
    __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION || GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { return false; }
}
static void disable_hook(void *p) {
    auto *op = static_cast<HookOp *>(p);
    auto &h = hooks[op->index];
    const auto &pb = g_patch[op->index];
    if (!site_mapped(h.target_address())) return;
    if (!pb.len || pb.len != h.original_bytes().size() || !bytes_equal((const void *)h.target_address(), pb.b, pb.len)) return;
    op->ok = h.disable().has_value();
}

// Run fn with every other thread of the target suspended by the controller (FREEZE/THAW
// IPC; the controller is a debugger, so the raise is serviced synchronously). While frozen,
// SafetyHook patches with the page left executable and no thread trap (patch in
// cmake/patch_safetyhook.cmake), so a site may share a page with anything -- including
// the ntdll routines the patching itself calls. Inside fn: no heap, no locks another
// thread could hold. Without a controller (never in UHH) SafetyHook's own trap is used.
extern "C" volatile long uhh_safetyhook_frozen;
using slot_set = std::bitset<PROBE_AGENT_MAX_PROBES>;
// Controller gone (guard cleanup): nobody can freeze the target for us, and SafetyHook's own
// trap path makes the site page non-executable -- on an ntdll stub page that faults the
// installer itself (the target died 0xC0000005). Freeze in-process instead: take the process
// heap lock FIRST (so no thread we suspend can be holding it while SafetyHook allocates),
// suspend every other thread, write, resume. Only ever used to REMOVE hooks: no thread can be
// strictly inside a 5-byte jmp, so none needs moving.
static volatile LONG g_self_freeze;
struct SelfFreeze {
    static constexpr size_t CAP = 4096;
    HANDLE t[CAP]; size_t n = 0; bool active = false;
    void freeze() {
        HeapLock(GetProcessHeap());
        active = true;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return;
        THREADENTRY32 te{}; te.dwSize = sizeof(te);
        const DWORD self = GetCurrentThreadId(), pid = GetCurrentProcessId();
        for (BOOL more = Thread32First(snap, &te); more && n < CAP; more = Thread32Next(snap, &te)) {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
            if (!h) continue;
            if (SuspendThread(h) == (DWORD)-1) { CloseHandle(h); continue; }
            CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(h, &c);                       // waits until it is really stopped
            t[n++] = h;
        }
        CloseHandle(snap);
    }
    ~SelfFreeze() {
        for (size_t i = 0; i < n; ++i) { ResumeThread(t[i]); CloseHandle(t[i]); }
        if (active) HeapUnlock(GetProcessHeap());
    }
};
// Returns false (fn not run) for an install no controller froze the target for.
template <class F> static bool frozen(const slot_set &enabling, F &&fn) {
    for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i)          // tell the controller which ranges change
        InterlockedExchange(&shared->requests[i].enabling, enabling[i] ? 1 : 0);
    probe_ipc_request req{};
    req.op = PROBE_IPC_FREEZE; req.origin_site = UINT32_MAX; req.address = enabling.any() ? 1 : 0;
    // The guard's cleanup runs with no debugger attached: the raise would only reach the
    // program's own handlers, so it goes straight to the in-process freeze.
    const bool held = !g_self_freeze && raise_ipc(&req) && req.result == 1;
    // Not held = no debugger serviced the raise: the controller died (or let go) during this
    // round, before the guard's cleanup has run (it sets controller_gone). An INSTALL is then
    // not written at all: unfrozen, SafetyHook's own trap path makes the site page
    // non-executable, and on an ntdll stub page the installer's own system calls fault on it
    // (the target died 0xC0000005 when the controller was killed early in an attach, L11's
    // runner signature). A removal freezes in-process instead (the cleanup's path).
    if (!held && enabling.any()) return false;
    SelfFreeze self;
    if (!held) self.freeze();
    if (held || self.active) InterlockedExchange(&uhh_safetyhook_frozen, 1);
    fn();
    if (self.active) InterlockedExchange(&uhh_safetyhook_frozen, 0);
    if (held) {
        InterlockedExchange(&uhh_safetyhook_frozen, 0);
        probe_ipc_request thaw{};
        thaw.op = PROBE_IPC_THAW; thaw.origin_site = UINT32_MAX;
        raise_ipc(&thaw);
    }
    return true;
}

// Install rounds and the final unhook never overlap: a round that started before a detach
// finishes before probe_agent_stop removes hooks, and none starts after it.
static SRWLOCK g_install_lock = SRWLOCK_INIT;
static void install_pending_locked();
static void install_pending() {
    AcquireSRWLockExclusive(&g_install_lock);
    if (!g_stopping) install_pending_locked();
    ReleaseSRWLockExclusive(&g_install_lock);
}
// Resolve every requested callback by name NOW, while no DLL load is in progress, so later
// install rounds (e.g. for a module that is being loaded right now) never call the loader.
// request.callback holds one or more '\n'-separated export names of the same (folded)
// function: the first this DLL exports.
static probe_callback resolve_callback_names(const char *list) {
    char name[PROBE_AGENT_EXPORT_CAP];
    for (const char *p = list; *p && p < list + PROBE_AGENT_EXPORT_CAP; ) {
        size_t n = 0;
        while (p[n] && p[n] != '\n' && p + n < list + PROBE_AGENT_EXPORT_CAP - 1) ++n;
        std::memcpy(name, p, n); name[n] = 0;
        if (auto f = reinterpret_cast<probe_callback>(GetProcAddress(self_module, name))) return f;
        p += n; if (*p == '\n') ++p; else break;
    }
    return nullptr;
}
// Each slot is overwritten in one store (a new session may map it to another callback):
// clearing them all first left a window in which a hook still live from an earlier session
// called a null callback (an access violation the target's vectored handlers could see).
static void resolve_callbacks() {
    uint32_t count = shared->request_count;
    if (count > PROBE_AGENT_MAX_PROBES) count = PROBE_AGENT_MAX_PROBES;
    for (uint32_t i = 0; i < count; ++i) {
        const auto &request = shared->requests[i];
        if (!request.callback[0] || (request.config_len > PROBE_AGENT_CONFIG_CAP && !request.config_remote)) continue;
        callbacks[i] = resolve_callback_names(request.callback);
    }
}

// A DLL the target unloads (FreeLibrary on another thread) while its inline site is being
// hooked: create_mid read the unmapped site -- an access violation on the agent's thread that
// killed the target. (Pinning the module is not an option: the loader can be blocked by a
// thread the controller holds mid-load, and the install must never wait on the loader.) So
// a site that is not mapped executable code right now is skipped (stays pending), and the
// build and the write are SEH-guarded: an unmap racing them fails that one hook, nothing else.
// SafetyHook reads the site only outside its allocator lock; a hook whose write faulted is
// abandoned in place (never touched again).
static bool site_mapped(uint64_t site) {
    // Include the decoder's lookahead and a patch straddling two pages (max 14 + 15 bytes).
    if (!addressable(site, 32)) return false;
    uintptr_t at = (uintptr_t)site, end = at + 32;
    if (end < at) return false;
    while (at < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((void *)at, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
            (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
            !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) return false;
        const uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= at) return false;
        at = next;
    }
    return true;
}
static bool seh_run(void (*fn)(void *), void *ctx) {
    __try { fn(ctx); return true; }
    __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION || GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { return false; }
}

static void install_pending_locked() {
    // The controller already let go (detach while this round's remote thread could not run,
    // e.g. the loader lock was held): never hook a target nobody is attached to.
    if (shared->controller_gone) return;
    uint32_t count = shared->request_count;
    if (count > PROBE_AGENT_MAX_PROBES) count = PROBE_AGENT_MAX_PROBES;
    slot_set enabling;
    for (uint32_t i = 0; i < count; ++i) {
        auto &request = shared->requests[i];
        if (!request.site || request.status != PROBE_AGENT_PENDING) continue;
        if ((request.config_len > PROBE_AGENT_CONFIG_CAP && !request.config_remote) || !request.callback[0]) {
            InterlockedExchange(&request.status, PROBE_AGENT_BAD_REQUEST); continue;
        }
        // Normally already resolved by resolve_callbacks() at init: GetProcAddress can block on
        // loader state held by a thread that is parked at a LOAD_DLL event (the install that
        // event is waiting for would then never run).
        if (!callbacks[i])
            callbacks[i] = resolve_callback_names(request.callback);
        if (!callbacks[i]) {
            InterlockedExchange(&request.status, PROBE_AGENT_CALLBACK_MISSING); continue;
        }
        if (!site_mapped(request.site)) continue;          // its module is going away: stays pending
        if (InterlockedCompareExchange(&request.status, PROBE_AGENT_INSTALLING, PROBE_AGENT_PENDING) != PROBE_AGENT_PENDING)
            continue;
        request.install_failure = PROBE_INSTALL_BUILD;
        char fail_install[8]{};
        if (GetEnvironmentVariableA("UHH_TEST_HOOK_FAIL", fail_install, sizeof(fail_install)) && fail_install[0] == '1') {
            request.install_failure = PROBE_INSTALL_FREEZE;
            InterlockedExchange(&request.status, PROBE_AGENT_HOOK_FAILED); continue;
        }
        sites[i] = request.site;
        if (g_shadow[i].lo) { g_shadow[i].lo = 0; InterlockedDecrement(&g_shadow_count); }
        if (hooks[i]) {
            // A re-install after the module was unloaded: the old hook's code and target are
            // gone, so it must NOT be destroyed (its destructor would write to unmapped
            // memory). Leak it deliberately.
            new SafetyHookMid(std::move(hooks[i]));
        }
        // Build the trampoline now (allocates); write the jump later, frozen.
        HookOp build{i, request.site, false};
        if (!seh_run(build_hook, &build)) {              // unmapped under us: retry when it loads again
            new (&hooks[i]) SafetyHookMid();
            InterlockedExchange(&request.status, PROBE_AGENT_PENDING); continue;
        }
        if (!hooks[i]) { InterlockedExchange(&request.status, PROBE_AGENT_HOOK_FAILED); continue; }
        request.patch_len = (uint32_t)hooks[i].original_bytes().size();
        request.trampoline = (uint64_t)hooks[i].uhh_trampoline();
        map_trampoline(i, (uintptr_t)request.site, hooks[i].uhh_trampoline(), hooks[i].original_bytes());
        enabling.set(i);
    }
    if (enabling.none()) return;
    auto enable = [&](const slot_set &which) {
        for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i) {
            if (!which[i]) continue;
            if (shared->controller_gone) { shared->requests[i].install_failure = PROBE_INSTALL_CONTROLLER_GONE; InterlockedExchange(&shared->requests[i].status, PROBE_AGENT_HOOK_FAILED); continue; }
            shared->requests[i].install_failure = PROBE_INSTALL_SITE;
            HookOp op{i, 0, false};
            if (!site_mapped(sites[i])) { InterlockedExchange(&shared->requests[i].status, PROBE_AGENT_PENDING); continue; }
            if (!seh_run(enable_hook, &op)) {            // unmapped mid-write: abandon that hook object
                new (&hooks[i]) SafetyHookMid();
                InterlockedExchange(&shared->requests[i].status, PROBE_AGENT_PENDING); continue;
            }
            const bool ok = op.ok;
            const auto &orig = hooks[i].original_bytes();
            if (ok && orig.size() <= sizeof(shared->requests[i].original)) {
                std::memcpy(shared->requests[i].original, orig.data(), orig.size());
                shared->requests[i].original_len = (uint32_t)orig.size();
            }
            if (ok && !g_shadow[i].lo && orig.size() <= sizeof(g_shadow[i].bytes)) {
                std::memcpy(g_shadow[i].bytes, orig.data(), orig.size());
                g_shadow[i].len = (uint32_t)orig.size();
                {                                            // widen the bounds BEFORE the shadow is visible
                    const uintptr_t lo = hooks[i].target_address(), hi = lo + orig.size();
                    if (lo < g_shadow_min) g_shadow_min = lo;
                    if (hi > g_shadow_max) g_shadow_max = hi;
                }
                MemoryBarrier();
                g_shadow[i].lo = hooks[i].target_address();
                InterlockedIncrement(&g_shadow_count);
            }
            InterlockedExchange(&shared->requests[i].status, ok ? PROBE_AGENT_INSTALLED : PROBE_AGENT_HOOK_FAILED);
        }
    };
    // PROBE_UNSAFE_FAST_PATCH: write while the other threads keep running (page kept
    // executable, no freeze, no trap) -- the race the freeze exists to prevent.
    slot_set unsafe;
    for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i)
        if (enabling[i] && (shared->requests[i].flags & PROBE_AGENT_FLAG_UNSAFE_FAST_PATCH)) unsafe.set(i);
    if (unsafe.any()) {
        InterlockedExchange(&uhh_safetyhook_frozen, 1);
        enable(unsafe);
        InterlockedExchange(&uhh_safetyhook_frozen, 0);
    }
    const slot_set safe = enabling & ~unsafe;
    if (safe.any() && !frozen(safe, [&] { enable(safe); }))
        for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i)      // built, never written: nobody to install for
            if (safe[i]) {
                shared->requests[i].install_failure = PROBE_INSTALL_FREEZE;
                InterlockedExchange(&shared->requests[i].status, PROBE_AGENT_HOOK_FAILED);
            }
}

// Tell the controller an install round finished (synchronous: the controller services
// it while this thread is stopped, then releases any threads it held for the install).
static bool notify_installed() {
    probe_ipc_request req{};
    req.op = PROBE_IPC_INSTALL_DONE; req.origin_site = UINT32_MAX;
    return raise_ipc(&req);
}

// ---- Controller-death guard (see probe_agent_guard) ----------------------------------------
using NtQipFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NtQipFn g_ntqip;
static HANDLE g_guard_wake;           // auto-reset: re-check (new session / a trap was taken)
static HANDLE g_ctl;                  // the controller process (owned here once taken)
static volatile LONG g_orphan_cleaned;
static volatile LONG g_lazy_dr;        // orphaned DRs are cleared by their own thread's VEH
static bool no_debug_port() {         // nobody is debugging us (any more)
    ULONG_PTR port = 1;
    return g_ntqip && g_ntqip(GetCurrentProcess(), 7 /*ProcessDebugPort*/, &port, sizeof(port), nullptr) >= 0 && port == 0;
}
static bool guard_orphaned() { return shared && shared->guard.enabled && no_debug_port(); }
static void set_ip(CONTEXT *c, uint64_t ip) {
#if defined(_WIN64)
    c->Rip = ip;
#else
    c->Eip = (DWORD)ip;
#endif
}
static void restore_byte(uint64_t at, unsigned char original) {
    __try {
        volatile unsigned char *p = (volatile unsigned char *)(uintptr_t)at;
        if (*p != 0xCC || original == 0xCC) return;
        DWORD old = 0;
        if (!VirtualProtect((void *)p, 1, PAGE_EXECUTE_READWRITE, &old)) return;
        *p = original;
        VirtualProtect((void *)p, 1, old, &old);
        FlushInstructionCache(GetCurrentProcess(), (void *)p, 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}
// Inspect the saved exception context: never overwrite a running thread's DR edits.
static DWORD orphan_dr_mask(const CONTEXT &c) {
    const uint64_t address[4] = {c.Dr0, c.Dr1, c.Dr2, c.Dr3};
    const auto &g = shared->guard;
    DWORD mask = 0;
    const LONG n = g.dr_site_count;
    if (n < 0 || n > (LONG)PROBE_AGENT_GUARD_DR_SITES) return 0;
    for (int slot = 0; slot < 4; ++slot) {
        if (!(g.dr_mask & (1u << slot)) || !((c.Dr7 >> (slot * 2)) & 3)) continue;
        for (LONG i = 0; i < n; ++i)
            if (g.dr_sites[i] == address[slot]) { mask |= 1u << slot; break; }
    }
    return mask;
}
// Change only our slots in the saved exception context. The VEH separately consumes
// our exception status; foreign slots and all other state are preserved.
static void clear_orphan_dr(CONTEXT &c, DWORD mask) {
    for (int slot = 0; slot < 4; ++slot) {
        if (!(mask & (1u << slot))) continue;
        c.Dr7 &= ~(((decltype(c.Dr7))3 << (slot * 2)) | ((decltype(c.Dr7))0xF << (16 + slot * 4)));
        switch (slot) { case 0: c.Dr0 = 0; break; case 1: c.Dr1 = 0; break;
                        case 2: c.Dr2 = 0; break; default: c.Dr3 = 0; }
    }
}
#if defined(_WIN64)
// Native x64 only: Get/SetThreadContext(DEBUG_REGISTERS) are kernel APCs that do not suspend
// the thread (WOW64 calls do, so x86 keeps the lazy VEH clearing). Clears only slots that still
// hold what UHH armed; a thread that changed its own DRs meanwhile has them written back.
static DWORD64 dr7_slot_bits(DWORD mask) {
    DWORD64 bits = 0;
    for (int slot = 0; slot < 4; ++slot)
        if (mask & (1u << slot)) bits |= ((DWORD64)3 << (slot * 2)) | ((DWORD64)0xF << (16 + slot * 4));
    return bits;
}
static void clear_thread_dr(HANDLE t) {
    CONTEXT before{}; before.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(t, &before)) return;
    const DWORD mask = orphan_dr_mask(before);
    if (!mask) return;
    CONTEXT w = before; clear_orphan_dr(w, mask);
    if (!SetThreadContext(t, &w)) return;                       // failure: lazy VEH backstop
    CONTEXT after{}; after.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(t, &after)) return;
    const DWORD64 ours = dr7_slot_bits(mask);
    const uint64_t a0[4] = {before.Dr0, before.Dr1, before.Dr2, before.Dr3};
    const uint64_t a1[4] = {after.Dr0, after.Dr1, after.Dr2, after.Dr3};
    bool changed = (before.Dr7 & ~ours) != (after.Dr7 & ~ours);
    for (int slot = 0; slot < 4; ++slot) if (!(mask & (1u << slot)) && a0[slot] != a1[slot]) changed = true;
    if (!changed) return;
    // The thread edited its own DRs concurrently: write its current values back, ours cleared.
    clear_orphan_dr(after, orphan_dr_mask(after) & mask);
    SetThreadContext(t, &after);
}
#endif
// The program's byte under one of our armed INT3s (the INT3 table, sorted by address). The
// controller may have died in the middle of a rewrite (int3_seq left odd): then a plain scan.
static bool int3_original(uint64_t at, unsigned char &original) {
    for (int attempt = 0; attempt < 4; ++attempt) {
        const LONG seq = shared->int3_seq;
        if (seq & 1) break;
        MemoryBarrier();
        LONG count = shared->int3_count;
        if (count < 0) count = 0;
        if (count > (LONG)PROBE_AGENT_INT3_CAP) count = PROBE_AGENT_INT3_CAP;
        LONG lo = 0, hi = count;
        while (lo < hi) {
            const LONG mid = lo + (hi - lo) / 2;
            if (shared->int3[mid].address < at) lo = mid + 1; else hi = mid;
        }
        const bool found = lo < count && shared->int3[lo].address == at;
        const unsigned char b = found ? shared->int3[lo].original : 0;
        MemoryBarrier();
        if (shared->int3_seq != seq) continue;
        if (found) original = b;
        return found;
    }
    LONG count = shared->int3_count;
    if (count < 0) count = 0;
    if (count > (LONG)PROBE_AGENT_INT3_CAP) count = PROBE_AGENT_INT3_CAP;
    for (LONG i = 0; i < count; ++i)
        if (shared->int3[i].address == at) { original = shared->int3[i].original; return true; }
    return false;
}
static LONG tid_count(const uint32_t *list, LONG count, DWORD tid) {
    if (count > (LONG)PROBE_AGENT_GUARD_TIDS) count = PROBE_AGENT_GUARD_TIDS;
    LONG n = 0;
    for (LONG i = 0; i < count; ++i) n += list[i] == tid;
    return n;
}
static bool tid_listed(const uint32_t *list, LONG count, DWORD tid) { return tid_count(list, count, tid) != 0; }
// First in line for every exception, but acts only on OUR traps once no debugger is attached
// (a live controller handles them before any handler in the target sees them).
static LONG CALLBACK guard_veh(EXCEPTION_POINTERS *ep) {
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    // A live controller handles every trap of its own before any handler here runs, so one of
    // OURS reaching this handler means the controller is gone -- even if the kernel has not yet
    // cleared the debug port (a thread released from a dying debugger's event can get here
    // first). Only the broad single-step rule below waits for the port to be gone.
    if (!shared || !shared->guard.enabled) return EXCEPTION_CONTINUE_SEARCH;
    auto &g = shared->guard;
    CONTEXT *cx = ep->ContextRecord;
    const uint64_t at = (uint64_t)(uintptr_t)ep->ExceptionRecord->ExceptionAddress;
    if (code == EXCEPTION_BREAKPOINT) {
        unsigned char original = 0;
        if (!int3_original(at, original)) {
            // The other INT3 of ours a thread can execute: the end of a displaced REP string
            // copy in one of our scratch blocks (session_bp.cpp: the copy, an INT3 instead of a
            // trap flag, then a jump back to the code after the site). Skip to the jump back.
            LONG n = g.block_count; if (n > (LONG)PROBE_AGENT_GUARD_BLOCKS) n = PROBE_AGENT_GUARD_BLOCKS;
            bool in_block = false;
            for (LONG i = 0; i < n && !in_block; ++i) in_block = g.blocks[i] && at - g.blocks[i] < 0x10000;
            if (!in_block) return EXCEPTION_CONTINUE_SEARCH;
            set_ip(cx, at + 1);
            if (g_guard_wake) SetEvent(g_guard_wake);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        restore_byte(at, original);
        set_ip(cx, at);                                           // run the original instruction
        if (g_guard_wake) SetEvent(g_guard_wake);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    const DWORD mask = orphan_dr_mask(*cx);
    const DWORD hits = (DWORD)cx->Dr6 & 0xF;
    // Never consume the target's own DR hit, even when one of ours fired too. Likewise a
    // target single-step / debug-register-access exception must reach its own handlers.
    const bool step = (cx->Dr6 & (1u << 14)) && tid_listed(g.step_tids, g.step_count, GetCurrentThreadId());
    if ((hits & ~mask) || (cx->Dr6 & (1u << 13)) || ((cx->Dr6 & (1u << 14)) && !step))
        return EXCEPTION_CONTINUE_SEARCH;
    if (!(hits & mask) && !step) return EXCEPTION_CONTINUE_SEARCH;
    // A live controller consumes our traps before the VEH. This orphaned hit can precede
    // the service thread's death notification, even while the debug port is being torn down.
    if (!g_lazy_dr) InterlockedExchange(&g_lazy_dr, 1);
    // Use the exception's saved status rather than querying the current thread again.
    // Data watchpoints report the address AFTER the access, so ownership comes from DR6,
    // not the exception IP. Leave foreign slots intact.
    clear_orphan_dr(*cx, mask);
    cx->Dr6 &= ~(decltype(cx->Dr6))mask;
    if (step) { cx->Dr6 &= ~(decltype(cx->Dr6))(1u << 14); cx->EFlags &= ~0x100u; }
    if (g_guard_wake) SetEvent(g_guard_wake);
    return EXCEPTION_CONTINUE_EXECUTION;
}
// A dead controller's suspensions of thread t (probe_agent_guard::held_tids). Conditional
// entries first, each against the suspend count it recorded (a call that may suspend the thread
// implicitly, see held_floor): resumed only while the count is above it -- the implicit
// suspension is in place; a suspension the PROGRAM made is never released. (Before the
// unconditional ones: a hold of ours under the call is part of the recorded count.) Then the
// holds of ours, once each. A count that cannot be read (before Windows 8.1): resumed, as a hold.
static void resume_holds(const probe_agent_guard &g, HANDLE t, DWORD tid) {
    LONG count = g.held_count;
    if (count > (LONG)PROBE_AGENT_GUARD_TIDS) count = PROBE_AGENT_GUARD_TIDS;
    LONG ours = 0;
    for (LONG i = 0; i < count; ++i) {
        if (g.held_tids[i] != tid) continue;
        const uint32_t before = g.held_floor[i];
        if (before == PROBE_AGENT_HOLD_OURS) { ++ours; continue; }
        ULONG now = 0;
        if (!g_nt_qit || g_nt_qit(t, 35 /* ThreadSuspendCount */, &now, sizeof(now), nullptr) < 0 || now > before)
            ResumeThread(t);
    }
    for (; ours > 0; --ours) ResumeThread(t);
}
extern "C" __declspec(dllexport) DWORD WINAPI probe_agent_stop(void *);
// The controller is gone and left its state behind: undo all of it, once.
static void guard_cleanup() {
    if (InterlockedExchange(&g_orphan_cleaned, 1)) return;
    auto &g = shared->guard;
    InterlockedExchange(&shared->controller_gone, 1);          // logs: nobody will read them
    LONG n = shared->int3_count;                                // every INT3 of ours: original byte back
    if (n < 0) n = 0;
    if (n > (LONG)PROBE_AGENT_INT3_CAP) n = PROBE_AGENT_INT3_CAP;
    for (LONG i = 0; i < n; ++i) if (shared->int3[i].address) restore_byte(shared->int3[i].address, shared->int3[i].original);
    InterlockedExchange(&g_lazy_dr, 1);                         // fallback if an update fails
    const DWORD self = GetCurrentThreadId(), pid = GetCurrentProcessId();
#if defined(_WIN64)
    const DWORD mask = (DWORD)g.dr_mask & 0xF;
#endif
    // Preserve the original two 200 ms grace intervals on EVERY backend. Inline hooks
    // keep counting/dropping orphaned calls until removal; a no-DR session needs this too.
    for (int pass = 0; pass < 2; ++pass, Sleep(200)) {
#if defined(_WIN64)
        if (pass && !mask) continue;          // only DR cleanup needs another scan
#else
        if (pass) continue;                   // WOW64: context calls suspend; lazy VEH only
#endif
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        THREADENTRY32 te{}; te.dwSize = sizeof(te);
        for (BOOL more = Thread32First(snap, &te); more; more = Thread32Next(snap, &te)) {
            if (te.th32OwnerProcessID != pid) continue;
            DWORD access = THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION;
#if defined(_WIN64)
            access |= THREAD_GET_CONTEXT | THREAD_SET_CONTEXT;
#endif
            HANDLE t = OpenThread(access, FALSE, te.th32ThreadID);
            if (!t) continue;
#if defined(_WIN64)
            if (mask) clear_thread_dr(t);       // the guard's own thread too: the controller armed it like any other
#endif
            // Only release recorded controller holds, once per entry.
            if (!pass && te.th32ThreadID != self) resume_holds(g, t, te.th32ThreadID);
            CloseHandle(t);
        }
        CloseHandle(snap);
    }
    InterlockedExchange(&g_self_freeze, 1);                     // no controller to freeze for us
    probe_agent_stop(nullptr);                                  // inline hooks out (no-op without any)
    InterlockedExchange(&g_self_freeze, 0);
}
// Detach drain (probe_agent_shared::live_query): the in-flight callbacks that can still finish
// and send a log -- on a thread that exists, is not suspended and is still inside the callback
// its slot records (the record's frame is on the thread's stack, above its SP, canary intact).
// Dead / suspended threads and records a non-unwinding longjmp left behind are not counted.
static bool callback_live(const ThreadSlot &ts, DWORD self, DWORD pid) {
    const DWORD tid = (DWORD)ts.tid;
    const HitScope *h = ts.active;
    if (!tid || tid == (DWORD)SLOT_MOVING || !h || tid == self) return false;
    HANDLE t = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_GET_CONTEXT | SYNCHRONIZE, FALSE, tid);
    if (!t) return false;                                          // gone
    bool live = WaitForSingleObject(t, 0) == WAIT_TIMEOUT && GetProcessIdOfThread(t) == pid;
    if (live && g_nt_qit) {                                        // suspended (by the program): cannot finish now
        ULONG suspended = 0;
        if (g_nt_qit(t, 35 /* ThreadSuspendCount */, &suspended, sizeof(suspended), nullptr) >= 0 && suspended)
            live = false;
    }
    if (live) {
        CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(t, &c)) {
#if defined(_WIN64)
            const uintptr_t sp = (uintptr_t)c.Rsp;
#else
            const uintptr_t sp = (uintptr_t)c.Esp;
#endif
            const uintptr_t a = (uintptr_t)h;
            live = a > sp && (!ts.stack || a + sizeof(HitScope) <= ts.stack);
            if (live) {
                __try { live = h->canary == (a ^ HIT_CANARY); }
                __except (EXCEPTION_EXECUTE_HANDLER) { live = false; }
            }
        }
    }
    CloseHandle(t);
    return live;
}
static LONG count_live_callbacks() {
    // Private TLS fallback slots (more than 4096 + 256 live probe-hitting threads) cannot
    // be enumerated here: their callbacks are conservatively counted as live.
    LONG n = g_untracked_running;
    const DWORD self = GetCurrentThreadId(), pid = GetCurrentProcessId();
    for (const ThreadSlot &ts : g_threads) n += callback_live(ts, self, pid);
    for (const ThreadSlot &ts : g_overflow) n += callback_live(ts, self, pid);
    return n;
}
static void answer_live_query() {
    shared->live_callbacks = count_live_callbacks();
    MemoryBarrier();
    InterlockedIncrement(&shared->live_seq);
}

static HANDLE service_event;
static volatile LONG service_running;   // service_main has started (past its loader init)
static HANDLE service_up;               // set by service_main once it runs (init waits for it)
// The service thread reports itself ready only from HERE, i.e. once it runs its own code:
// a new thread first goes through the loader's thread initialisation (LdrInitializeThunk ->
// DLL_THREAD_ATTACH for every module), which waits while another thread is in the middle of
// a DLL load. Published as ready at CreateThread, it was not: the controller released the
// entry hold, the main thread at once LoadLibrary'd a DLL with inline sites and was held at
// its LOAD_DLL event (as the load owner) -- and the service thread, still in its loader init,
// waited for that load to finish: deadlock until the 5 s install timeout, every call missed
// (ROADMAP CC8/B5). The INSTALL_DONE raised here tells the controller it may release.
static DWORD WINAPI service_main(void *) {
    TidScope<8> own(g_agent_threads);
    InterlockedExchange(&shared->guard.service_tid, (LONG)GetCurrentThreadId());   // see held_floor
    InterlockedExchange(&service_running, 1);
    InterlockedExchange(&shared->service_ready, 1);
    if (service_up) SetEvent(service_up);
    notify_installed();
    // The controller process can be gone while the kernel still shows our debug port (its
    // debug object is torn down after the process is signaled). The traps that would wake us
    // again may all have been taken by then -- the VEH acts on ours before the port clears --
    // so after the controller ends, poll for the port to go (bounded) instead of waiting for
    // a trap that never comes: threads it held would stay suspended for good.
    ULONGLONG ctl_gone_at = 0;
    for (;;) {
        InterlockedExchange(&shared->guard.service_tid, (LONG)GetCurrentThreadId());   // see held_floor
        // Take a new session's controller handle (the old one, if any, is no longer ours to watch).
        if (HANDLE h = (HANDLE)(uintptr_t)InterlockedExchange64(&shared->guard.controller_process, 0)) {
            if (g_ctl) CloseHandle(g_ctl);
            g_ctl = h; ctl_gone_at = 0;
        }
        const bool polling = ctl_gone_at && !g_orphan_cleaned && shared->guard.enabled &&
                             GetTickCount64() - ctl_gone_at < 30000;
        // A guarded session whose controller never handed over its process handle (it died
        // first): poll for the debug port to go instead (the check below).
        const bool watch_port = !g_ctl && !ctl_gone_at && !g_orphan_cleaned && shared->guard.enabled;
        HANDLE waits[3] = {service_event, g_guard_wake, g_ctl};
        DWORD w = WaitForMultipleObjects(g_ctl ? 3 : 2, waits, FALSE, polling ? 10 : watch_port ? 100 : INFINITE);
        if (w == WAIT_OBJECT_0) {
            // A detach drain asking how many callbacks can still finish: answer only -- the
            // session is over, so no install round (and no INSTALL_DONE raised to nobody).
            if (InterlockedExchange(&shared->live_query, 0)) { answer_live_query(); continue; }
            install_pending(); notify_installed(); continue;
        }
        if (w == WAIT_OBJECT_0 + 2) {
            InterlockedExchange(&g_lazy_dr, 1);
            CloseHandle(g_ctl); g_ctl = nullptr; ctl_gone_at = GetTickCount64();
        }
        else if (w == WAIT_FAILED) {
            if (!g_ctl) return 1;
            CloseHandle(g_ctl); g_ctl = nullptr; ctl_gone_at = GetTickCount64();
        }
        if (guard_orphaned()) guard_cleanup();
    }
}

// Test knob (regress init-cutoff-*): UHH_TEST_INIT_STALL_MS=N in the TARGET's environment keeps
// an init on a thread of its own (not the early one) from returning for N ms, so the target's
// end kills it mid-init.
static void test_init_stall() {
    char v[16];
    if (shared->early_init || !GetEnvironmentVariableA("UHH_TEST_INIT_STALL_MS", v, sizeof(v))) return;
    Sleep(strtoul(v, nullptr, 10));
}

extern "C" volatile long uhh_safetyhook_keep_calls;
extern "C" __declspec(dllexport) DWORD WINAPI probe_agent_init(void *channel) {
    TidScope<8> own(g_agent_threads);
    // Counted on every return through a usable channel (see init_returns): the controller tells
    // a returned init from one cut off by the target's end.
    struct Returned {
        ~Returned() {
            if (shared && shared->magic == PROBE_AGENT_MAGIC && shared->version == PROBE_AGENT_VERSION)
                InterlockedIncrement(&shared->init_returns);
        }
    } returned;
    if (channel && channel != mapping) {
        AgentChannel *entry = g_channels;
        while (entry && entry->handle != (HANDLE)channel) entry = entry->next;
        if (!entry) {
            auto *view = static_cast<probe_agent_shared *>(MapViewOfFile((HANDLE)channel, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*shared)));
            if (!view || view->magic != PROBE_AGENT_MAGIC || view->version != PROBE_AGENT_VERSION) return 2;
            auto *next_states = new (std::nothrow) AgentState[PROBE_AGENT_MAX_PROBES];
            if (!next_states) { UnmapViewOfFile(view); return 4; }
            for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i) next_states[i] = {view, i, {i}};
            entry = new (std::nothrow) AgentChannel{(HANDLE)channel, view, next_states, g_channels};
            if (!entry) { delete[] next_states; UnmapViewOfFile(view); return 4; }
            g_channels = entry;
        }
        states = entry->states;
        mapping = entry->handle;
        shared = entry->view;                           // only fallback channels add retained views/handles
    }
    if (!shared) return 1;
    if (shared->request_count > PROBE_AGENT_MAX_PROBES) return 3;
    g_xmode = shared->xstate_mode;
    char review_knob[8] = {};
    g_test_slotless = GetEnvironmentVariableA("UHH_TEST_SLOTLESS", review_knob, sizeof(review_knob)) != 0;
    g_test_preaccount = GetEnvironmentVariableA("UHH_TEST_PREACCOUNT", review_knob, sizeof(review_knob)) != 0;
    // The drain event, opened once and never closed (a producer may be signalling it): the handle
    // keeps the named object alive, so a later controller (attach after a detach) creating the
    // same name gets this same event.
    if (!g_drain_event) {
        wchar_t name[64]; probe_agent_drain_name(GetCurrentProcessId(), name);
        g_drain_event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
    }
    if (g_drain_event) InterlockedExchange(&shared->drain_wait.agent_ready, 1);
    if (!g_cb_guarantee) probe_stack_guarantee_offset();   // this remote thread is ours (see run_callback)
    make_ret_thunks();
    watch_unloads();                       // call_func's resolution cache (once per process)
    static PVOID veh = nullptr;
    if (!veh) {
        // Under CET shadow stacks a call in a hook's range is relocated verbatim (a return
        // through a pushed address would be a #CP): see uhh_relocate_call_as_jmp. The policy
        // says so on CET hardware; RDSSP (a NOP leaving 0 without an active shadow stack) also
        // sees one the policy does not report: Intel SDE's emulated shadow stack (regress
        // `cet-sde-relcall-inline`), or a failed policy query.
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY pol{};
#if defined(_WIN64)
        const bool ssp = _rdsspq() != 0;
#else
        const bool ssp = _rdsspd() != 0;
#endif
        if (ssp || (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &pol, sizeof(pol)) &&
                    pol.EnableUserShadowStack))
            InterlockedExchange(&uhh_safetyhook_keep_calls, 1);
        g_nt_raise = reinterpret_cast<nt_raise_fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtRaiseException"));
        g_nt_qit = reinterpret_cast<nt_qit_fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
        veh = AddVectoredExceptionHandler(1, tramp_veh);
        AddVectoredContinueHandler(1, tramp_vch);
    }
    // Controller-death guard, once per process. Registered after tramp_veh, so it is first in
    // line: one of our traps orphaned inside a trampoline is ended where it happened, not
    // re-raised at its site first.
    if (!g_guard_wake) {
        g_ntqip = reinterpret_cast<NtQipFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        g_guard_wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        AddVectoredExceptionHandler(1, guard_veh);
    }
    InterlockedExchange(&g_orphan_cleaned, 0);   // a new session: guard it afresh
    InterlockedExchange(&g_lazy_dr, 0);
    if (g_guard_wake) SetEvent(g_guard_wake);    // the service thread takes the new controller handle
    InterlockedIncrement(&g_tblock_gen);   // a new (zeroed) channel: every thread claims a hit block again
    InterlockedExchange(&g_stopping, 0);   // a new session after a detach: callbacks run again
    resolve_callbacks();
    install_pending();
    // A thread from an earlier session (or a repeated init) -- ready only if it already runs;
    // one still in its loader init reports itself when it gets there.
    if (service_event && service_running) InterlockedExchange(&shared->service_ready, 1);
    if (!service_event) {   // first init: start the persistent install thread
        wchar_t name[64]; probe_agent_service_name(GetCurrentProcessId(), name);
        service_event = OpenEventW(SYNCHRONIZE, FALSE, name);
        if (service_event) {
            service_up = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            // Above normal priority, like the controller's threads in the target (see session_agent.cpp
            // create_remote_thread_boosted): a busy program must not delay installs and arming.
            HANDLE t = CreateThread(nullptr, 0, service_main, nullptr, CREATE_SUSPENDED, nullptr);
            if (t) { SetThreadPriority(t, THREAD_PRIORITY_HIGHEST); ResumeThread(t); }
            // service_ready is set by the thread itself, once running. Init does not finish
            // (so the controller reports nothing "active" and releases nothing) before then:
            // a DLL with inline sites loaded right after -- e.g. at once after an attach --
            // would otherwise find no service thread to install it. Nothing the controller
            // holds can own the loader here (launch: the entry hold; attach: no hold), so the
            // wait is short; bounded anyway (the thread then reports ready when it gets there).
            if (t) {
                CloseHandle(t);
                if (service_up && !shared->early_init) WaitForSingleObject(service_up, 5000);
            }
        }
    }
    // The controller died DURING this init (killed early in an attach), before anything could
    // watch it: its named service event went with it (no service thread) or it never handed
    // over its process handle. Nobody else would then undo what it left -- the threads it had
    // frozen for this install round stayed suspended and the target hung (runner kill loop).
    // The debug port is the signal: it goes as the dying controller's handles are closed,
    // BEFORE its process object is signaled (measured: port gone, process not yet "dead").
    // No service thread could start (its named event is the controller's: gone means the
    // controller is dying), so wait here for the port to go -- the handle rundown order is not
    // ours to rely on.
    if (!service_event && shared->guard.enabled)
        for (const ULONGLONG t0 = GetTickCount64(); !no_debug_port() && GetTickCount64() - t0 < 5000; ) Sleep(10);
    if (!g_orphan_cleaned && guard_orphaned()) guard_cleanup();
    test_init_stall();
    return 0;
}

// Unhook without pulling code out from under a thread: stop new callbacks, wait for the
// ones in flight to finish (bounded), then remove the hooks.
extern "C" __declspec(dllexport) DWORD WINAPI probe_agent_stop(void *) {
    TidScope<8> own(g_agent_threads);
    if (!shared) return 0;                               // loaded but never initialised: nothing to undo
    AcquireSRWLockExclusive(&g_install_lock);            // after any install round in progress
    InterlockedExchange(&g_stopping, 1);
    FlushProcessWriteBuffers();                          // see call_mid: hits count with plain stores
    // 2 s of wall time: 2000 x Sleep(1) was up to ~31 s at the default 15.6 ms timer, past the
    // controller's 5 s wait for this thread -- the detach then skipped its log drain (dropped
    // the late logs of a callback still running) and reported the hooks as not removed.
    for (const ULONGLONG t0 = GetTickCount64(); any_inflight() && GetTickCount64() - t0 < 2000; ) Sleep(1);
    for (auto &sh : g_shadow) if (sh.lo) { sh.lo = 0; InterlockedDecrement(&g_shadow_count); }
    frozen(slot_set{}, [] {
        for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i)
            // Restore the original bytes -- unless the controller saw the module unload
            // (the address is unmapped or holds another image now), or the module went away
            // before the controller has processed its unload (see disable_hook). A module that
            // went away and is pending again (reloaded, not yet re-hooked when the detach came)
            // still has its OLD hook object here, for code that may be unmapped: disable_hook
            // checks the site is mapped and still holds our bytes before writing.
            if (hooks[i] && shared->requests[i].status != PROBE_AGENT_UNLOADED) {
                HookOp op{i, 0, false};
                if (!seh_run(disable_hook, &op)) new (&hooks[i]) SafetyHookMid();   // unmapped mid-write: abandoned in place
            }
    });
    // Keep the trampolines and stubs: a thread may still be on its way back through one
    // (it then jumps to the original code, which is intact). Deliberate leak, once.
    for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i)
        if (hooks[i]) new SafetyHookMid(std::move(hooks[i]));
    ReleaseSRWLockExclusive(&g_install_lock);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, void *) {
    if (reason == DLL_PROCESS_ATTACH) { self_module = module; DisableThreadLibraryCalls(module); }
    return TRUE;
}

// The agent's entry point (linked /ENTRY:uhh_agent_entry). The agent carries its own static
// CRT, which DLL_PROCESS_DETACH would tear down -- but at PROCESS EXIT the hooks are still
// installed and keep firing while later DLLs shut down (CloseHandle, RegCloseKey, ...): a
// callback would then run on a dead CRT and abort() the target (seen: cmd.exe 0xC0000409
// at exit under inline traceapi probes). The process is going away, so at termination the
// CRT is simply left alive and every late hit is still delivered. A real unload
// (FreeLibrary: reserved == nullptr) uninitialises normally.
extern "C" BOOL WINAPI _DllMainCRTStartup(HINSTANCE, DWORD, void *);
extern "C" BOOL WINAPI uhh_agent_entry(HINSTANCE module, DWORD reason, void *reserved) {
    if (reason == DLL_PROCESS_DETACH && reserved) return TRUE;
    if (reason == DLL_PROCESS_DETACH) unwatch_unloads();   // a real unload: the callback goes with us
    return _DllMainCRTStartup(module, reason, reserved);
}
