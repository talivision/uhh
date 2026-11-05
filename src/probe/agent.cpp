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

static HMODULE self_module;
static HANDLE mapping;
static probe_agent_shared *shared;
// Never destroyed: at process exit a static array's destructors would unhook through
// SafetyHook's stock path (page made non-executable while other threads may still run,
// and on ntdll stub pages the installer then faults on itself). The process is going
// away; its code is never restored. Explicit removal (probe_agent_stop) runs frozen.
static SafetyHookMid *const hooks = new SafetyHookMid[PROBE_AGENT_MAX_PROBES];
static uint64_t sites[PROBE_AGENT_MAX_PROBES];
static probe_callback callbacks[PROBE_AGENT_MAX_PROBES];

struct AgentState { probe_agent_shared *shared; uint32_t index; };
static AgentState states[PROBE_AGENT_MAX_PROBES];

/* Callback memory helpers fail closed on bad target addresses. They never change
   page protections: executable writes belong to the hook installer, not hits. */
/* A bad pointer must fail cleanly WITHOUT raising an exception the target could observe
   (its vectored handlers see first-chance faults before our __except). So the range is
   validated first. The last validated region is cached per thread FOR THE CURRENT HIT
   (call_mid and call_original reset it), so repeated access to the same buffer/stack/image
   within a callback costs a bounds check, not a syscall -- while a page the target
   decommits, guards or protects between hits is validated afresh (a stale entry faulted,
   and a read of a PAGE_GUARD page consumed the target's guard). The __try stays only for a
   region freed concurrently (a race the target would also have). */
struct RegionCache { uintptr_t lo = 0, hi = 0; bool writable = false; };
static thread_local RegionCache t_region;

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

static bool range_ok(uintptr_t a, size_t n, bool write) {
    if (!n) return true;
    if (a + n < a) return false;
    RegionCache scratch, *cache = region_cache();
    if (!cache) cache = &scratch;
    uintptr_t end = a + n;
    while (a < end) {
        // Reads trust the per-thread cache across hits; WRITES re-check every time: the
        // target may have made the region read-only since (a write fault would be visible).
        if (!write && a >= cache->lo && a < cache->hi) {
            a = cache->hi; continue;
        }
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((void *)a, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) return false;
        DWORD prot = mbi.Protect & 0xFF;
        if ((mbi.Protect & PAGE_GUARD) || prot == PAGE_NOACCESS || prot == 0) return false;
        bool w = prot == PAGE_READWRITE || prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READWRITE ||
                 prot == PAGE_EXECUTE_WRITECOPY;
        bool r = w || prot == PAGE_READONLY || prot == PAGE_EXECUTE_READ;
        if (!r || (write && !w)) return false;
        cache->lo = (uintptr_t)mbi.BaseAddress;
        cache->hi = cache->lo + mbi.RegionSize;
        cache->writable = w;
        a = cache->hi;
    }
    return true;
}
static void forget_region() { if (RegionCache *cache = region_cache()) *cache = {}; }
// The bytes each installed hook overwrote, so a callback reading code sees the PROGRAM's
// bytes (as the breakpoint backend shows the original byte under its INT3 and hw changes
// nothing), not the hook's jump. Published after the jump is written, withdrawn before it
// is removed; a reader checks the request is still INSTALLED (not unloaded/reused).
struct PatchShadow { volatile uintptr_t lo; uint32_t len; uint8_t bytes[32]; };
static PatchShadow g_shadow[PROBE_AGENT_MAX_PROBES];
static volatile LONG g_shadow_count;
static void overlay_original(uintptr_t a, void *buffer, size_t n) {
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
    __except (EXCEPTION_EXECUTE_HANDLER) { forget_region(); return 0; }
    if (g_shadow_count) overlay_original((uintptr_t)address, buffer, size);
    if (shared && shared->int3_count) overlay_int3(address, buffer, size);
    return 1;
}
static int local_write(void *, uint64_t address, const void *buffer, size_t size, size_t *done) {
    *done = 0;
    if (size && !addressable(address, size)) return 0;
    if (!range_ok((uintptr_t)address, size, true)) return 0;
    __try { std::memcpy((void *)(uintptr_t)address, buffer, size); *done = size; return 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { forget_region(); return 0; }
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
// No-fault rule: every stack read is inside the hit thread's TEB stack bounds, and every
// code/data read is inside a region VirtualQuery reported committed and readable -- a
// per-capture cache, never trusted across hits. Nothing here can raise an exception the
// target's vectored handlers would see. Scans are bounded (16 KiB per frame, 128 queries).
struct X86Mem {
    struct Region { uint32_t lo, hi; bool read, exec; };
    Region r[16]{}; uint32_t used = 0, next = 0; int budget = 128;
    const Region *find(uint32_t a) {
        for (uint32_t i = 0; i < used; ++i) if (a >= r[i].lo && a < r[i].hi) return &r[i];
        if (budget <= 0) return nullptr;
        --budget;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((void *)(uintptr_t)a, &mbi, sizeof(mbi))) return nullptr;
        Region g{};
        g.lo = (uint32_t)(uintptr_t)mbi.BaseAddress;
        const uint64_t end = (uint64_t)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        g.hi = end > 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t)end;
        const DWORD prot = mbi.Protect & 0xFF;
        g.read = mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) &&
                 (prot == PAGE_READONLY || prot == PAGE_READWRITE || prot == PAGE_WRITECOPY ||
                  prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
        g.exec = g.read && mbi.Type == MEM_IMAGE &&
                 (prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
        const uint32_t slot = used < 16 ? used++ : (next++ & 15);
        r[slot] = g;
        return &r[slot];
    }
    // [a, a+n) lies in ONE readable region (and in executable image code when exec).
    bool ok(uint32_t a, uint32_t n, bool exec) {
        if (!n || a + n < a) return false;
        const Region *g = find(a);
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
        for (uint32_t a = sp; a <= end; a += 4) {
            const X86Ret k = x86_classify(m, rd(a), pc);
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

// Format and stack are produced BEFORE claiming a ring slot so a slot is held only
// for a copy. A full ring makes the producer wait (backpressure); see the ring's comment in
// probe_agent_shared.hpp for the only cases that do not end in the ring.
static void agent_log(probe_context *c, bool stack, const char *format, va_list ap) {
    auto *state = c ? static_cast<AgentState *>(c->controller) : nullptr;
    if (!state || !state->shared || !format) return;
    probe_agent_log local;                     // the record, built on this stack
    // The controller's formatter: an invalid format (%k, %n) used to fast-fail the TARGET
    // through the CRT's invalid-parameter handler; now logged as "[unformattable] <format>".
    int len = uhh_format_log(local.text, sizeof(local.text), format, ap);
    if (len < 0) return;
    local.text_len = (uint32_t)len;
    local.frame_count = stack ? capture_stack(c, local.frames, PROBE_STACK_MAX_FRAMES) : 0;
    local.has_stack = stack ? 1 : 0;
    local.probe = state->index; local.tid = c->tid;
    auto *sh = state->shared;
    if (sh->controller_gone) { InterlockedIncrement(&sh->log_dropped); return; }   // nobody will read it
    LONG64 pos = sh->log_head;
    probe_agent_log *rec = nullptr;
    // Heartbeat watch: time is accumulated in small steps so a debugger freezing the whole
    // process (when nothing here runs) never counts as the controller being idle.
    ULONGLONG last_tick = 0, idle = 0; LONG64 seen_beat = -1; bool ipc_failed = false;
    const DWORD me = GetCurrentThreadId();
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
            if (sh->controller_gone) { InterlockedIncrement(&sh->log_dropped); return; }
            if (sh->ring_stalled && sh->log_ipc && !ipc_failed) {
                if (deliver_by_ipc(&local, state->index)) return;
                ipc_failed = true;
            }
            ULONGLONG now = GetTickCount64();
            LONG64 beat = sh->drain_beat;
            if (beat != seen_beat) { seen_beat = beat; idle = 0; }
            else if (last_tick) idle += (now - last_tick) < 50 ? (now - last_tick) : 50;
            last_tick = now;
            if (idle > 1000) {
                idle = 0;
                if (controller_dead(sh)) {
                    InterlockedExchange(&sh->controller_gone, 1);
                    InterlockedIncrement(&sh->log_dropped); return;
                }
            }
            SwitchToThread();
            pos = sh->log_head;
        } else {
            pos = sh->log_head;
        }
    }
    rec->probe = local.probe; rec->tid = local.tid;
    rec->text_len = local.text_len;
    std::memcpy(rec->text, local.text, local.text_len + 1);
    rec->has_stack = local.has_stack; rec->frame_count = local.frame_count;
    if (local.frame_count) std::memcpy(rec->frames, local.frames, local.frame_count * sizeof(uint64_t));
    MemoryBarrier();
    InterlockedExchange64(&rec->seq, pos + 1);                    // publish
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
// The controller's grammar exactly (session.cpp parse_location / resolve_symbol), so a
// call_func symbol resolves -- or is refused -- the same on every backend: "0xADDRESS",
// "module+0xRVA", "module!Export[+0xOFF]"; offsets need "0x" and hex digits only; the module
// is matched by its file name (a directory part is ignored) and must include the extension.
// (GetModuleHandleA alone appended ".dll" to "kernel32" and searched a full path as given;
// _strtoui64 accepted "+0", "+0xZZ" and "+10"; the controller refuses all of those.)
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

// call_func of an address that is no committed executable memory (e.g. "0x1") returns 0
// without calling it: the call would fault, and inline that first-chance fault is seen by the
// target's vectored handlers -- breakpoint/hw (the debugger sees it first) return 0 silently.
static bool executable(uint64_t a) {
    if (!addressable(a, 1)) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((const void *)(uintptr_t)a, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
        (mbi.Protect & PAGE_GUARD)) return false;
    const DWORD p = mbi.Protect & 0xFF;
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
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
    uint64_t fn = agent_resolve(symbol);
    if (!fn || !executable(fn)) return 0;
#if defined(_WIN64)
    return call_raw(fn, a, ret) ? 1 : 0;
#else
    return call_raw(fn, a, ret, nargs) ? 1 : 0;
#endif
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
   after the claim only the owning thread touches its slot.
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
struct ThreadSlot {
    volatile LONG tid;
    HitScope *active;                    // the hit whose callback this thread is running
    volatile LONG64 *active_cell;        // that hit's hit_stripes cell
    uintptr_t moved_from, moved_to;      // a fault moved out of a trampoline (tramp_veh)
    const void *teb;                     // the owner's identity: TEB, stack base, creation time
    uintptr_t stack;
    uint64_t born;
    volatile LONG busy;                  // reading `born`: a probe hit meanwhile passes straight through
};
constexpr uint32_t AGENT_THREAD_SLOTS = 4096;
static ThreadSlot g_threads[AGENT_THREAD_SLOTS];
static ThreadSlot *thread_slot(DWORD tid, bool claim) {
    for (uint32_t n = 0; n < AGENT_THREAD_SLOTS; ++n) {
        ThreadSlot &s = g_threads[((tid >> 2) + n) & (AGENT_THREAD_SLOTS - 1)];
        const LONG t = s.tid;
        if (t == (LONG)tid) return &s;
        if (t) continue;
        if (!claim) return nullptr;
        if (InterlockedCompareExchange(&s.tid, (LONG)tid, 0) == 0) return &s;
    }
    return nullptr;                      // 4096 distinct thread ids: this thread runs unguarded
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

// The thread's last NT status (TEB LastStatusValue), beside GetLastError.
#if defined(_WIN64)
static inline volatile DWORD *teb_last_status() { return (volatile DWORD *)((unsigned char *)NtCurrentTeb() + 0x1250); }
#else
static inline volatile DWORD *teb_last_status() { return (volatile DWORD *)((unsigned char *)NtCurrentTeb() + 0xBF4); }
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
struct HitScope {
    volatile LONG64 *cell;          // hit_stripes cell: its in-flight count
    ThreadSlot *slot;               // this thread's slot (null: table full)
    volatile LONG abandoned = 0;
    const void *xmm6 = nullptr;     // x64: the hit's XMM6..XMM15 (safetyhook Context, contiguous)
    uintptr_t canary = 0;           // (uintptr_t)this ^ HIT_CANARY while the callback runs
    const void *xmm0 = nullptr;     // the hit's XMM0..XMM5 (vector/float arguments; safetyhook Context)
    // call_original ran: what the original left, for return_from (and for a callback that
    // faults after the call). The caller then gets it all, as from an un-hooked call -- see
    // OrigPost -- and the thread's last error / last status as the original left them (the
    // callback's own Win32 calls are undone back to these, not to the values before the hit).
    bool orig_ran = false;
    uint64_t orig_ret = 0;          // RAX / EAX (x86 EDX: probe_context::orig_edx)
    DWORD orig_error = 0, orig_status = 0;
    OrigPost post{};
    uint64_t seen[6] = {};          // the context's registers matching post.gpr when the original returned
    unsigned char *x87_post = nullptr; // x86: FNSAVE image of the x87 state after the original (an ST0
                                       // result): mid_entry's 108-byte buffer, reloaded after the
                                       // extended-state restore
};
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
// slot (the table is full) has no guard: call_func is refused with a warning, never run
// unguarded.
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
    forget_region();                                   // the original may have changed protections
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
struct probe_session { uint32_t site; };
static probe_session proxies[PROBE_AGENT_MAX_PROBES];

extern "C" probe_session *get_session(probe_context *c) {
    if (g_ctrl) return g_ctrl->get_session(c);
    auto *state = c ? static_cast<AgentState *>(c->controller) : nullptr;
    return state && state->index < PROBE_AGENT_MAX_PROBES ? &proxies[state->index] : nullptr;
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
    if (!s || s < proxies || s >= proxies + PROBE_AGENT_MAX_PROBES || !cb) return 0;
    if (config_len && !config) return 0;
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
// Callbacks running right now are counted with their hits in the SHARED block (hit_stripes'
// high bits): what is still in flight when the process dies (ExitProcess kills threads
// mid-callback) is reported by the controller as callbacks_interrupted.
// An exception or longjmp left the original (call_original) and is unwinding past this
// hit's callback: settle what call_mid would have on return (once).
static void hit_scope_abandon(HitScope *h) {
    if (InterlockedExchange(&h->abandoned, 1)) return;
    if (h->slot && h->slot->active == h) h->slot->active = nullptr;
    InterlockedExchangeAdd64(h->cell, -PROBE_AGENT_INFLIGHT_ONE);
}
static bool any_inflight() {
    if (!shared) return false;
    return probe_agent_inflight(shared) != 0;
}

// XSAVE support, probed once: mask = XCR0 restricted to x87|SSE|AVX|AVX-512 components.
// size = the save area THOSE components need (standard or compacted layout), not CPUID(0xD,0)
// .EBX, which covers every XCR0 feature -- with AMX tiles (~11 KB) that exceeded the buffer,
// and the hit then saved nothing at all (a callback's VZEROUPPER wiped the live YMM state).
// x86: the gated mask also keeps the x87 state when it is live -- 32-bit C code returns
// floating-point values in ST0, so any callback (or CRT) float call pushes/pops the x87 stack
// and changes its status word, which a mid-function site may have live.
static struct XState { bool ok = false, compact = false, xinuse = false; uint64_t mask = 0, avx_mask = 0; uint32_t size = 0, full = 0; } g_xs = [] {
    XState x;
    int r[4];
    __cpuid(r, 1);
    if (!(r[2] & (1 << 27))) return x;                     // OSXSAVE
    x.mask = _xgetbv(0) & 0xE7ull;
    x.avx_mask = x.mask & 0xE4ull;                         // AVX upper + AVX-512 (opmask, ZMM) only
#if !defined(_WIN64)
    x.avx_mask |= x.mask & 1ull;                           // x87 (see above)
#endif
    __cpuidex(r, 0xD, 0); x.full = (uint32_t)r[1];
    char knob[8] = {};                                     // regress: a CPU with AMX tiles in XCR0
    if (GetEnvironmentVariableA("UHH_BENCH_XSTATE", knob, sizeof(knob)) && !strcmp(knob, "amx")) x.full += 8192;
    __cpuidex(r, 0xD, 1); x.compact = (r[0] & 2) != 0; x.xinuse = (r[0] & 4) != 0;   // XGETBV(1)
    uint32_t size = 576;                                   // legacy region + XSAVE header
    for (int i = 2; i < 8; ++i) {
        if (!(x.mask & (1ull << i))) continue;
        __cpuidex(r, 0xD, i);                              // EAX size, EBX offset, ECX bit 1: 64-aligned
        if (x.compact) size = ((r[2] & 2) ? (size + 63) & ~63u : size) + (uint32_t)r[0];
        else if ((uint32_t)(r[1] + r[0]) > size) size = (uint32_t)(r[1] + r[0]);
    }
    x.size = size;
    x.ok = x.size <= 4096;
    return x;
}();



// The callback runs on the target's own thread: any Win32 call it (or the library) makes
// can change the thread's last-error / last-status, which the target may read right
// after the probed instruction. Save and restore both (plain TEB fields: ~free) -- to what
// the original left if call_original ran (see HitScope).
static bool run_callback(probe_callback cb, probe_context *c) {
    DWORD last_error = GetLastError(), last_status = *teb_last_status();
    __writeeflags(__readeflags() & ~(uintptr_t)0x400);
    bool ok = true;
    DWORD code = 0;
    __try { cb(c); }
    __except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    // A callback that overflowed the stack used up the thread's guard page (the target's
    // stack): restore it, or the program's own next overflow is no longer catchable.
    if (code == EXCEPTION_STACK_OVERFLOW) _resetstkoflw();
    if (const auto *h = static_cast<const HitScope *>(c->hit_scope); h && h->orig_ran) {
        last_error = h->orig_error; last_status = h->orig_status;
    }
    *teb_last_status() = last_status;
    SetLastError(last_error);
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
static bool call_mid(safetyhook::Context &native, uint32_t index, unsigned char *x87_post) {
    probe_context c{};
    load_regs(c.regs, native);
    c.regs.pc = sites[index]; c.hit_sp = c.regs.rsp;
    const auto &request = shared->requests[index];
    c.config = !request.config_len ? nullptr
             : request.config_len > PROBE_AGENT_CONFIG_CAP ? (void *)(uintptr_t)request.config_remote : (void *)request.config;
    c.ops = &local_ops; c.tid = GetCurrentThreadId(); c.site = index; c.controller = &states[index];
    // Count the hit before the call so a faulting callback is still accounted, and run
    // the callback under SEH so an access violation (or any exception) inside user code
    // cannot take down the target. On a fault we skip register write-back, leaving the
    // target's registers untouched (the callback behaves as a no-op mutation).
    // A hit is a callback run: while being unhooked the hook passes straight through and
    // that pass is NOT counted (else a detach would report hits that have no callback/log).
    if (g_agent_threads.has(c.tid)) return false;          // the agent's own work: see g_agent_threads
    const probe_callback cb = callbacks[index];
    if (!cb) return false;
    ThreadSlot *const ts = own_thread_slot(c.tid);
    if (ts && ts->busy) return false;                      // the agent's own query: see ThreadSlot
    uint32_t stripe = (c.tid >> 2) & (PROBE_AGENT_STRIPES - 1);
    volatile LONG64 &cell = shared->hit_stripes[index][stripe].value;
    // ONE atomic add counts the hit and marks a callback in flight (see hit_stripes): a thread
    // killed between two separate counters left a hit that was neither logged nor interrupted.
    InterlockedExchangeAdd64(&cell, 1 + PROBE_AGENT_INFLIGHT_ONE);
    // g_stopping is checked only once this hit is in flight: probe_agent_stop sets it and then
    // waits for in-flight callbacks, so a hit is either seen by that wait or sees the flag
    // (both sides use full-barrier interlocked operations). Checked first, a thread between
    // the check and the add ran its callback after the detach (its IPC then raised an
    // exception nobody handled, visible to the target).
    if (g_stopping) { InterlockedExchangeAdd64(&cell, -(1 + PROBE_AGENT_INFLIGHT_ONE)); return false; }
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
        if (!ts->born || !now || now == ts->born) InterlockedExchangeAdd64(ts->active_cell, -PROBE_AGENT_INFLIGHT_ONE);
        ts->born = now;
        ts->active = nullptr;
    }
    if (ts && ts->active) {
        InterlockedExchangeAdd64(&cell, -PROBE_AGENT_INFLIGHT_ONE); return false;
    }
    // The mid-hook stub preserves GPRs, flags and XMM0-15 only. The callback (and the CRT
    // it calls) may touch x87/MXCSR/YMM/ZMM state -- e.g. vzeroupper -- which the target
    // could be relying on at a mid-function site. Save and restore the full extended state
    // and give C code the ABI-required DF=0.
    // Extended state (MXCSR, AVX/AVX-512) and DF are handled in mid_entry, BEFORE any of
    // this C code runs -- see there.
    forget_region();     // validated regions are trusted within ONE hit only (see RegionCache)
    HitScope scope{&cell, ts};
    scope.canary = (uintptr_t)&scope ^ HIT_CANARY;
#if defined(_WIN64)
    scope.xmm6 = &native.xmm6;
#endif
    scope.xmm0 = &native.xmm0;
    scope.x87_post = x87_post;
    if (ts) { ts->active_cell = &cell; ts->active = &scope; }
    c.hit_scope = &scope;
    bool callback_ok = run_callback(cb, &c);
    if (ts) ts->active = nullptr;
    scope.canary = 0;
    InterlockedExchangeAdd64(&cell, -PROBE_AGENT_INFLIGHT_ONE);
    if (!callback_ok) {
        // A faulting callback is a no-op: its register changes are discarded -- unless it had
        // already run the original (call_original). Falling through would run the original a
        // SECOND time (a double free / double close), so the hooked function returns to its
        // caller as with return_from: with return_from's value if one was set, else the
        // original's own result (x86: EDX:EAX and the bytes it popped), and everything else
        // the original left, like any return_from after call_original (below).
        if (!c.called_original || !scope.orig_ran) return false;
        const uint64_t ax = c.returned ? c.regs.rax : scope.orig_ret, dx = c.returned ? c.regs.rdx : c.orig_edx;
#if !defined(_WIN64)
        if (!c.returned) {
            if (c.orig_pop < 0 || c.orig_pop > 1020 || (c.orig_pop & 3)) return false;   // not measured
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
            return scope.x87_post != nullptr;
        }
        return false;
    } else if (c.returned || c.called_original) {
        warn_once(&c, c.returned ? "return_from could not be applied (no return thunk); the original runs"
                                 : "call_original without return_from -- the original runs again on fall-through");
    }
    return false;
}

// Entry point of every inline hit. It runs FIRST, before any C code that might call the
// CRT: the CRT's memset/memcpy pick AVX paths ending in VZEROUPPER (wiping every YMM upper
// half the target may have live at a mid-function site), and its x86 rep-stos/movs paths
// run BACKWARDS if the site executes with DF=1. So: clear DF, then save what the stub
// does not (MXCSR always; AVX/AVX-512 when live, or unconditionally when the CPU cannot
// report liveness), using intrinsics only -- then run the hit. The stub restores RFLAGS
// (so the target's DF) on the way out.
static __declspec(noinline) bool mid_entry_saved(safetyhook::Context &native, uint32_t index, uint64_t mask,
                                                  unsigned char *x87_post) {
    alignas(64) unsigned char area[4096];
    __stosb(area + 512, 0, 64);                            // XSAVE header must start clean (no CRT call)
#if defined(_WIN64)
    if (g_xs.compact) _xsavec64(area, mask); else _xsave64(area, mask);
#else
    if (g_xs.compact) _xsavec(area, mask); else _xsave(area, mask);
#endif
    unsigned int mxcsr = _mm_getcsr();
    const bool x87 = call_mid(native, index, x87_post);
    _mm_setcsr(mxcsr);
#if defined(_WIN64)
    _xrstor64(area, mask);
#else
    _xrstor(area, mask);
#endif
    return x87;
}

static inline void mid_entry(safetyhook::Context &native, uint32_t index) {
    __writeeflags(__readeflags() & ~(uintptr_t)0x400);    // DF=0 before ANY C code
#if defined(_WIN64)
    unsigned char *x87_post = nullptr;                     // x64 returns floating point in XMM0 only
#else
    unsigned char x87_buf[108], *x87_post = x87_buf;       // call_original's x87 state (ST0 result)
#endif
    bool x87 = false;
    LONG xmode = shared->xstate_mode;                      // 0 gated (default), 1 none, 2 full (bench knob)
    uint64_t mask = 0;
    if (xmode != 1 && g_xs.ok) {
        if (xmode == 2) mask = g_xs.mask;
        else if (g_xs.xinuse) mask = _xgetbv(1) & g_xs.avx_mask;  // only components actually live
        else mask = g_xs.avx_mask;                         // liveness unknown: keep AVX state
    }
    if (xmode == 1) x87 = call_mid(native, index, x87_post);
    else if (mask) x87 = mid_entry_saved(native, index, mask, x87_post);
    else {
        unsigned int mxcsr = _mm_getcsr();                 // the common case (and no XSAVE): just MXCSR
        x87 = call_mid(native, index, x87_post);
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
    if (ThreadSlot *ts = thread_slot(tid, false))                       // a new exception (not our re-raise)
        if (ts->moved_to && (uintptr_t)ep->ExceptionRecord->ExceptionAddress != ts->moved_to) ts->moved_to = 0;
    uintptr_t site = 0;
    if ((uintptr_t)ep->ExceptionRecord->ExceptionAddress != ip || !tramp_to_site(ip, &site)) return EXCEPTION_CONTINUE_SEARCH;
    if (ThreadSlot *ts = own_thread_slot(tid)) { ts->moved_from = ip; ts->moved_to = site; }
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
    ThreadSlot *ts = thread_slot(GetCurrentThreadId(), false);
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
static void enable_hook(void *p) {
    auto *op = static_cast<HookOp *>(p);
    op->ok = hooks[op->index].enable().has_value();
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
template <class F> static void frozen(const slot_set &enabling, F &&fn) {
    for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i)          // tell the controller which ranges change
        InterlockedExchange(&shared->requests[i].enabling, enabling[i] ? 1 : 0);
    probe_ipc_request req{};
    req.op = PROBE_IPC_FREEZE; req.origin_site = UINT32_MAX; req.address = enabling.any() ? 1 : 0;
    // The guard's cleanup runs with no debugger attached: the raise would only reach the
    // program's own handlers, so it goes straight to the in-process freeze.
    const bool held = !g_self_freeze && raise_ipc(&req) && req.result == 1;
    SelfFreeze self;
    if (!held && enabling.none() && (g_self_freeze || shared->controller_gone)) self.freeze();   // removal with no controller
    if (held || self.active) InterlockedExchange(&uhh_safetyhook_frozen, 1);
    fn();
    if (self.active) InterlockedExchange(&uhh_safetyhook_frozen, 0);
    if (held) {
        InterlockedExchange(&uhh_safetyhook_frozen, 0);
        probe_ipc_request thaw{};
        thaw.op = PROBE_IPC_THAW; thaw.origin_site = UINT32_MAX;
        raise_ipc(&thaw);
    }
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
    MEMORY_BASIC_INFORMATION mbi{};
    return VirtualQuery((void *)(uintptr_t)site, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
           (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
}
static bool seh_run(void (*fn)(void *), void *ctx) {
    __try { fn(ctx); return true; }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { return false; }
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
        sites[i] = request.site; states[i] = {shared, i}; proxies[i].site = i;
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
            if (shared->controller_gone) { InterlockedExchange(&shared->requests[i].status, PROBE_AGENT_HOOK_FAILED); continue; }
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
    if (safe.any()) frozen(safe, [&] { enable(safe); });
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
static uint64_t get_ip(const CONTEXT *c) {
#if defined(_WIN64)
    return c->Rip;
#else
    return c->Eip;
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
// Addresses our slots held when the cleanup cleared them: a #DB already raised for one of them
// (its thread was stopped at that event when the controller died) is delivered AFTER the clear,
// when neither DR7 nor the address says it was ours any more.
static volatile LONG64 g_cleared[64];
static volatile LONG g_cleared_n;
static void remember_cleared(uint64_t a) {
    if (!a) return;
    LONG n = g_cleared_n;
    for (LONG i = 0; i < n && i < 64; ++i) if ((uint64_t)g_cleared[i] == a) return;
    LONG i = InterlockedIncrement(&g_cleared_n) - 1;
    if (i < 64) g_cleared[i] = (LONG64)a;
}
static void clear_dr_slots(CONTEXT &c, DWORD mask) {
    for (int slot = 0; slot < 4; ++slot) {
        if (!(mask & (1u << slot))) continue;
        remember_cleared(slot == 0 ? (uint64_t)c.Dr0 : slot == 1 ? (uint64_t)c.Dr1 : slot == 2 ? (uint64_t)c.Dr2 : (uint64_t)c.Dr3);
        c.Dr7 &= ~((decltype(c.Dr7))3 << (slot * 2)) & ~((decltype(c.Dr7))0xF << (16 + slot * 4));
        switch (slot) { case 0: c.Dr0 = 0; break; case 1: c.Dr1 = 0; break; case 2: c.Dr2 = 0; break; default: c.Dr3 = 0; }
    }
    if (mask && !(c.Dr7 & 0xFF)) c.Dr7 &= ~(decltype(c.Dr7))0x300;   // no slot left: exact bits off too
    c.Dr6 = 0;
}
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
        if (!int3_original(at, original)) return EXCEPTION_CONTINUE_SEARCH;
        restore_byte(at, original);
        set_ip(cx, at);                                           // run the original instruction
        if (g_guard_wake) SetEvent(g_guard_wake);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    CONTEXT dr{}; dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &dr);
    const DWORD mask = (DWORD)g.dr_mask & 0xF;
    bool ours = (dr.Dr6 & mask) != 0 || tid_listed(g.step_tids, g.step_count, GetCurrentThreadId());
    if (!ours) {   // DR6 is not always reported: an enabled slot of ours at this very address
        const uint64_t ip = get_ip(cx);
        const uint64_t a[4] = {(uint64_t)dr.Dr0, (uint64_t)dr.Dr1, (uint64_t)dr.Dr2, (uint64_t)dr.Dr3};
        for (int slot = 0; slot < 4 && !ours; ++slot)
            ours = (mask & (1u << slot)) && ((dr.Dr7 >> (slot * 2)) & 3) && (a[slot] == ip || a[slot] == at);
        LONG n = g_cleared_n; if (n > 64) n = 64;
        for (LONG i = 0; i < n && !ours; ++i) ours = (uint64_t)g_cleared[i] == ip || (uint64_t)g_cleared[i] == at;
    }
    if (!ours && no_debug_port()) {
        // A trap-flag step or #DB the dying controller set up that left no trace we can match
        // (seen on x64: a call_original's in-place run returning after the cleanup). With no
        // enabled slot of the target's own on this thread nothing else of the program can have
        // raised it, short of the program single-stepping itself (taken as ours: residual).
        DWORD own = 0;
        for (int slot = 0; slot < 4; ++slot)
            if (!(mask & (1u << slot)) && ((dr.Dr7 >> (slot * 2)) & 3)) own |= 1u << slot;
        ours = own == 0 && (dr.Dr6 & 0xF & ~mask) == 0;
    }
    if (!ours) {
        const uint64_t ip = get_ip(cx);
        LONG n = g.block_count; if (n > (LONG)PROBE_AGENT_GUARD_BLOCKS) n = PROBE_AGENT_GUARD_BLOCKS;
        for (LONG i = 0; i < n && !ours; ++i) ours = g.blocks[i] && ip - g.blocks[i] < 0x10000;
    }
    if (!ours) return EXCEPTION_CONTINUE_SEARCH;
    // A DR hit (execute: not yet run; data: already done) or the end of a step we started:
    // drop our debug registers and the trap flag, and carry on from here. (A displaced step
    // continues in its out-of-line copy, which jumps back to the code after the site.)
    clear_dr_slots(dr, mask);
    dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(GetCurrentThread(), &dr);
    if ((cx->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) clear_dr_slots(*cx, mask);
    cx->EFlags &= ~0x100u;
    if (g_guard_wake) SetEvent(g_guard_wake);
    return EXCEPTION_CONTINUE_EXECUTION;
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
    const DWORD mask = (DWORD)g.dr_mask & 0xF, self = GetCurrentThreadId(), pid = GetCurrentProcessId();
    {   // this thread too (the controller armed its DRs like every other thread's)
        CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &c)) { clear_dr_slots(c, mask); SetThreadContext(GetCurrentThread(), &c); }
    }
    // Twice: a thread the dying debugger had stopped at an event can be released with the
    // debug registers it was stopped with, after the first pass.
    for (int pass = 0; pass < 2; ++pass, Sleep(200)) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{}; te.dwSize = sizeof(te);
        for (BOOL more = Thread32First(snap, &te); more; more = Thread32Next(snap, &te)) {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
            HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!t) continue;
            if (SuspendThread(t) != (DWORD)-1) {              // no heap / lock use while it is suspended
                CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
                if (GetThreadContext(t, &c)) {
                    clear_dr_slots(c, mask);
                    if (tid_listed(g.step_tids, g.step_count, te.th32ThreadID)) c.EFlags &= ~0x100u;
                    SetThreadContext(t, &c);
                }
                ResumeThread(t);
            }
            // The controller's holds: once per entry (a thread can be held twice, e.g. a deferred
            // call_original hit that an in-place step window then suspended again).
            if (!pass)
                for (LONG k = tid_count(g.held_tids, g.held_count, te.th32ThreadID); k > 0; --k) ResumeThread(t);
            CloseHandle(t);
        }
        CloseHandle(snap);
    }
    }
    InterlockedExchange(&g_self_freeze, 1);                     // no controller to freeze for us
    probe_agent_stop(nullptr);                                  // inline hooks out (no-op without any)
    InterlockedExchange(&g_self_freeze, 0);
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
    InterlockedExchange(&service_running, 1);
    InterlockedExchange(&shared->service_ready, 1);
    if (service_up) SetEvent(service_up);
    notify_installed();
    for (;;) {
        // Take a new session's controller handle (the old one, if any, is no longer ours to watch).
        if (HANDLE h = (HANDLE)(uintptr_t)InterlockedExchange64(&shared->guard.controller_process, 0)) {
            if (g_ctl) CloseHandle(g_ctl);
            g_ctl = h;
        }
        HANDLE waits[3] = {service_event, g_guard_wake, g_ctl};
        DWORD w = WaitForMultipleObjects(g_ctl ? 3 : 2, waits, FALSE, INFINITE);
        if (w == WAIT_OBJECT_0) { install_pending(); notify_installed(); continue; }
        if (w == WAIT_OBJECT_0 + 2) { CloseHandle(g_ctl); g_ctl = nullptr; }
        else if (w == WAIT_FAILED) { if (g_ctl) { CloseHandle(g_ctl); g_ctl = nullptr; } else return 1; }
        if (guard_orphaned()) guard_cleanup();
    }
}

extern "C" volatile long uhh_safetyhook_keep_calls;
extern "C" __declspec(dllexport) DWORD WINAPI probe_agent_init(void *) {
    TidScope<8> own(g_agent_threads);
    if (!shared) {
        wchar_t name[64]; probe_agent_mapping_name(GetCurrentProcessId(), name);
        mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (!mapping) return 1;
        shared = static_cast<probe_agent_shared *>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*shared)));
        if (!shared || shared->magic != PROBE_AGENT_MAGIC || shared->version != PROBE_AGENT_VERSION) return 2;
    }
    if (shared->request_count > PROBE_AGENT_MAX_PROBES) return 3;
    make_ret_thunks();
    static PVOID veh = nullptr;
    if (!veh) {
        // Under CET shadow stacks a call in a hook's range is relocated verbatim (a return
        // through a pushed address would be a #CP): see uhh_relocate_call_as_jmp.
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY pol{};
        if (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &pol, sizeof(pol)) &&
            pol.EnableUserShadowStack)
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
    InterlockedExchange(&g_cleared_n, 0);
    if (g_guard_wake) SetEvent(g_guard_wake);    // the service thread takes the new controller handle
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
            HANDLE t = CreateThread(nullptr, 0, service_main, nullptr, 0, nullptr);
            // service_ready is set by the thread itself, once running. Init does not finish
            // (so the controller reports nothing "active" and releases nothing) before then:
            // a DLL with inline sites loaded right after -- e.g. at once after an attach --
            // would otherwise find no service thread to install it. Nothing the controller
            // holds can own the loader here (launch: the entry hold; attach: no hold), so the
            // wait is short; bounded anyway (the thread then reports ready when it gets there).
            if (t) {
                CloseHandle(t);
                if (service_up) WaitForSingleObject(service_up, 5000);
            }
        }
    }
    return 0;
}

// Unhook without pulling code out from under a thread: stop new callbacks, wait for the
// ones in flight to finish (bounded), then remove the hooks.
extern "C" __declspec(dllexport) DWORD WINAPI probe_agent_stop(void *) {
    TidScope<8> own(g_agent_threads);
    if (!shared) return 0;                               // loaded but never initialised: nothing to undo
    AcquireSRWLockExclusive(&g_install_lock);            // after any install round in progress
    InterlockedExchange(&g_stopping, 1);
    for (int i = 0; i < 2000 && any_inflight(); ++i) Sleep(1);
    for (auto &sh : g_shadow) if (sh.lo) { sh.lo = 0; InterlockedDecrement(&g_shadow_count); }
    frozen(slot_set{}, [] {
        for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i)
            // Restore the original bytes -- unless the controller saw the module unload
            // (the address is unmapped or holds another image now).
            if (hooks[i] && shared->requests[i].status != PROBE_AGENT_UNLOADED) (void)hooks[i].disable();
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
    return _DllMainCRTStartup(module, reason, reserved);
}
