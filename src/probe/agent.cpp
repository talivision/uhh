#include "win_common.hpp"
#include "probe_log_format.hpp"
#include "probe_agent_shared.hpp"
#include <safetyhook.hpp>
#include <array>
#include <bitset>
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
   validated first. The last validated region is cached per thread, so the common case
   -- repeated access to the same buffer/stack/image -- costs a bounds check, not a
   syscall. The __try stays only for a region freed concurrently (a race the target
   would also have). */
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
static int local_read(void *, uint64_t address, void *buffer, size_t size, size_t *done) {
    *done = 0;
    if (!range_ok((uintptr_t)address, size, false)) return 0;
    __try { std::memcpy(buffer, (const void *)(uintptr_t)address, size); *done = size; }
    __except (EXCEPTION_EXECUTE_HANDLER) { forget_region(); return 0; }
    if (g_shadow_count) overlay_original((uintptr_t)address, buffer, size);
    return 1;
}
static int local_write(void *, uint64_t address, const void *buffer, size_t size, size_t *done) {
    *done = 0;
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
#endif

// In-process stack snapshot from the HOOKED register image (not the agent's own frames):
// x64 unwinds with the image's .pdata (RtlVirtualUnwind); x86 follows the EBP chain.
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
    __try {
        while (n < cap) {
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
    // Every read is checked BEFORE it is made (the hit thread's own stack bounds from its
    // TEB; code bytes via range_ok), so a bogus EBP (FPO code, EBP used as a register) or a
    // non-address at [esp] stops the walk instead of faulting -- a fault would be visible
    // to the target's vectored handlers before our __except.
    const NT_TIB *tib = reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
    const uint32_t lo = (uint32_t)(uintptr_t)tib->StackLimit, hi = (uint32_t)(uintptr_t)tib->StackBase;
    auto on_stack = [&](uint32_t a, uint32_t len) { return a >= lo && a <= hi - len && hi >= len; };
    __try {
        // At a function's first instructions EBP is still the CALLER's frame, so the EBP
        // chain would skip the immediate caller. If [esp] is a genuine return address
        // (the bytes before it encode a call), record it first. Mid-function, [esp] is
        // usually a local that fails this test, and a duplicate of [ebp+4] is skipped.
        const uint32_t esp = (uint32_t)c->regs.rsp;
        uint32_t top = on_stack(esp, 4) ? *(uint32_t *)(uintptr_t)esp : 0;
        uint32_t caller_ret = on_stack((uint32_t)c->regs.rbp, 8) ? *(uint32_t *)(uintptr_t)(c->regs.rbp + 4) : 0;
        if (n < cap && top > 8 && top != caller_ret && range_ok(top - 8, 8, false) && looks_like_return(top))
            frames[n++] = top;
        uint32_t ebp = (uint32_t)c->regs.rbp;
        while (n < cap && ebp && on_stack(ebp, 8)) {
            uint32_t next = *(uint32_t *)(uintptr_t)ebp, ret = *(uint32_t *)(uintptr_t)(ebp + 4);
            if (!ret) break;
            frames[n++] = ret;
            if (next <= ebp) break;                      // stack grows down: frames must ascend
            ebp = next;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
    return n;
}

// Format and stack are produced BEFORE claiming a ring slot so a slot is held only
// for a memcpy; a full ring drops the record (counted) rather than block the thread.
static void agent_log(probe_context *c, bool stack, const char *format, va_list ap) {
    auto *state = c ? static_cast<AgentState *>(c->controller) : nullptr;
    if (!state || !state->shared || !format) return;
    char text[PROBE_AGENT_LOG_TEXT_CAP];
    // The controller's formatter: an invalid format (%k, %n) used to fast-fail the TARGET
    // through the CRT's invalid-parameter handler; now logged as "[unformattable] <format>".
    if (!uhh_format_log(text, sizeof(text), format, ap)) return;
    uint64_t frames[PROBE_STACK_MAX_FRAMES]; uint32_t nframes = 0;
    if (stack) nframes = capture_stack(c, frames, PROBE_STACK_MAX_FRAMES);
    auto *sh = state->shared;
    if (sh->controller_gone) { InterlockedIncrement(&sh->log_dropped); return; }   // nobody will read it
    LONG64 pos = sh->log_head;
    probe_agent_log *rec = nullptr;
    ULONGLONG last_tick = 0, waited = 0; LONG64 seen_beat = 0, seen_tail = -1;
    for (;;) {
        rec = &sh->logs[(uint64_t)pos % PROBE_AGENT_LOG_CAP];
        LONG64 diff = rec->seq - pos;
        if (diff == 0) {
            if (InterlockedCompareExchange64(&sh->log_head, pos + 1, pos) == pos) break;
            pos = sh->log_head;
        } else if (diff < 0) {
            // Full: the controller's drainer is behind. Wait for a slot (backpressure)
            // rather than lose the record. Give up only after THIS thread has itself
            // waited 2 s while the drainer was alive (its heartbeat moving) but the ring did
            // not move (tail stuck behind a slot whose producer is gone or suspended).
            // Time is accumulated in small steps so a debugger freezing the whole process
            // (when nothing here runs) never counts as waiting.
            if (sh->controller_gone) { InterlockedIncrement(&sh->log_dropped); return; }
            ULONGLONG now = GetTickCount64();
            LONG64 beat = sh->drain_beat, tail = sh->log_tail;
            if (!last_tick || tail != seen_tail) { waited = 0; seen_tail = tail; }
            else if (beat != seen_beat) waited += (now - last_tick) < 50 ? (now - last_tick) : 50;
            last_tick = now; seen_beat = beat;
            if (waited > 2000) { InterlockedIncrement(&sh->log_dropped); return; }
            SwitchToThread();
            pos = sh->log_head;
        } else {
            pos = sh->log_head;
        }
    }
    rec->probe = state->index; rec->tid = c->tid;
    std::memcpy(rec->text, text, sizeof(text));
    rec->has_stack = stack ? 1 : 0; rec->frame_count = nframes;
    if (nframes) std::memcpy(rec->frames, frames, nframes * sizeof(uint64_t));
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
static uint64_t agent_resolve(const char *symbol) {
    if (!symbol || !*symbol) return 0;
    if (symbol[0] == '0' && (symbol[1] == 'x' || symbol[1] == 'X')) return _strtoui64(symbol + 2, nullptr, 16);
    char mod[MAX_PATH]; const char *bang = strchr(symbol, '!'), *plus = strrchr(symbol, '+');
    const char *split = bang ? bang : plus;
    if (!split || (size_t)(split - symbol) >= sizeof(mod)) return 0;
    memcpy(mod, symbol, split - symbol); mod[split - symbol] = 0;
    HMODULE m = GetModuleHandleA(mod);
    if (!m) return 0;
    if (!bang) return (uint64_t)(uintptr_t)m + _strtoui64(split + 1, nullptr, 16);
    char name[256]; const char *end = plus && plus > bang ? plus : bang + strlen(bang);
    if ((size_t)(end - bang - 1) >= sizeof(name)) return 0;
    memcpy(name, bang + 1, end - bang - 1); name[end - bang - 1] = 0;
    FARPROC f = GetProcAddress(m, name);
    if (!f) return 0;
    uint64_t off = (plus && plus > bang) ? _strtoui64(plus + 1, nullptr, 16) : 0;
    return (uint64_t)(uintptr_t)f + off;
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

// Threads currently inside call_func (resolution included). Probes they hit there do not
// run callbacks -- the documented call_func contract, which the breakpoint/hw path already
// kept. Without it an inline allocator probe whose callback calls call_func recursed
// forever: GetModuleHandle/GetProcAddress (and many callees) allocate, which hits the
// probe, whose callback calls call_func again... -> STATUS_STACK_OVERFLOW (found by
// examples/famous heap_tracker). A fixed table, not TLS: it must work on a thread that
// is still in its loader initialisation.
static volatile LONG g_in_call_count;
static volatile LONG g_in_call_tids[64];
static bool in_call_func(DWORD tid) {
    if (!g_in_call_count) return false;
    for (auto &slot : g_in_call_tids) if ((DWORD)slot == tid) return true;
    return false;
}
struct CallFuncScope {
    volatile LONG *slot = nullptr;
    CallFuncScope() {
        const LONG tid = (LONG)GetCurrentThreadId();
        for (auto &s : g_in_call_tids)
            if (InterlockedCompareExchange(&s, tid, 0) == 0) { slot = &s; InterlockedIncrement(&g_in_call_count); break; }
    }
    ~CallFuncScope() { if (slot) { InterlockedExchange(slot, 0); InterlockedDecrement(&g_in_call_count); } }
};

extern "C" int call_func(probe_context *c, const char *symbol, uint64_t *ret, int nargs, ...) {
    if (nargs < 0 || nargs > 8) return 0;
    uint64_t a[8] = {0};
    va_list ap; va_start(ap, nargs);
    for (int i = 0; i < nargs; ++i) a[i] = va_arg(ap, uint64_t);
    va_end(ap);
    if (g_ctrl) return g_ctrl->call_func_args(c, symbol, ret, nargs, a);
    CallFuncScope scope;
    uint64_t fn = agent_resolve(symbol);
    if (!fn) return 0;
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
struct HitScope {
    volatile LONG64 *cell;          // hit_stripes cell: its in-flight count
    bool tls;                       // t_in_callback was set for this hit
    volatile LONG abandoned;
    const void *xmm6;               // x64: the hit's XMM6..XMM15 (safetyhook Context, contiguous)
    const void *xmm0;               // the hit's XMM0..XMM5 (vector/float arguments; safetyhook Context)
    // call_original's floating-point result, applied by return_from: XMM0 as the original
    // left it, and (x86) the x87 state with its ST0 result (an FNSAVE image owned by the hook
    // entry, which reloads it after the extended-state restore).
    alignas(16) unsigned char xmm0_post[16] = {};
    bool have_post = false;
    unsigned char *x87_post = nullptr; // x86: 108-byte FNSAVE buffer (mid_entry's)
    bool have_x87 = false;
};
static void hit_scope_abandon(HitScope *h);

#if defined(_WIN64)
struct OrigFrame {                   // layout read by uhh_orig_thunk
    uint64_t rip, rsp;               // the hit's return address, and the caller's SP after it
    uint64_t nv[8];                  // rbx rbp rsi rdi r12 r13 r14 r15 at the hit
    HitScope *scope;                 // +0x50
    const void *xmm6;                // +0x58
    const void *xmm0;                // +0x60 the hit's XMM0..XMM5 (loaded for the call; may be null)
    unsigned char xmm0_out[16];      // +0x68 XMM0 as the original returned it
};
static_assert(offsetof(OrigFrame, scope) == 0x50 && offsetof(OrigFrame, xmm6) == 0x58 &&
              offsetof(OrigFrame, xmm0) == 0x60 && offsetof(OrigFrame, xmm0_out) == 0x68, "uhh_orig_thunk layout");
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
// and XMM0-5 (vectorcall), call, and record what the original returned: EDX:EAX, the bytes it
// popped (its `ret N`), XMM0, and the x87 state holding an ST0 result. The x87 state the
// callback continues with is the hit's own (nothing pushed): return_from reloads x87_post.
static void call_tramp_x86(uint32_t target, const uint32_t *args32, int nargs, uint32_t eax_v, uint32_t ecx_v,
                           uint32_t edx_v, const void *vec_args, uint32_t *ret_lo, uint32_t *ret_hi, int32_t *popped,
                           unsigned char *vec_out, unsigned char *x87_out, uint32_t hit_sp, HitScope *scope) {
    uint32_t lo = 0, hi = 0, pb = 0;
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
            mov eax, esp
            sub eax, edi
            mov pb, eax
            mov esp, ebx
            mov eax, vec_out
            movups [eax], xmm0
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
    *ret_lo = lo; *ret_hi = hi; *popped = (int32_t)pb;
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
    if (!state || !state->shared || state->index >= PROBE_AGENT_MAX_PROBES || nargs < 0 || nargs > 8) return 0;
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
    for (int i = 0; i < nargs; ++i) a[i] = get_func_arg(c, (size_t)i);
    const int extra = window(c->hit_sp + 0x28, 8, UHH_ORIG_STACK_ARGS);
    for (int i = 0; i < extra; ++i)
        if (4 + i >= nargs) a[4 + i] = reinterpret_cast<const uint64_t *>((uintptr_t)(c->hit_sp + 0x28))[i];
    OrigFrame f{};
    f.rip = ret_addr; f.rsp = c->hit_sp + 8;
    f.nv[0] = c->regs.rbx; f.nv[1] = c->regs.rbp; f.nv[2] = c->regs.rsi; f.nv[3] = c->regs.rdi;
    f.nv[4] = c->regs.r12; f.nv[5] = c->regs.r13; f.nv[6] = c->regs.r14; f.nv[7] = c->regs.r15;
    f.scope = scope; f.xmm6 = scope->xmm6; f.xmm0 = scope->xmm0;
    r = uhh_orig_thunk(tramp, a, &f);
    std::memcpy(scope->xmm0_post, f.xmm0_out, 16);
#else
    uint32_t a32[64] = {0}, lo = 0, hi = 0;
    int32_t popped = -1;
    for (int i = 0; i < nargs; ++i) a32[i] = (uint32_t)get_func_arg(c, (size_t)i);
    int n = window(c->hit_sp + 4, 4, 64);
    for (int i = nargs; i < n; ++i) a32[i] = reinterpret_cast<const uint32_t *>((uintptr_t)(c->hit_sp + 4))[i];
    if (n < nargs) n = nargs;
    call_tramp_x86((uint32_t)tramp, a32, n, (uint32_t)c->regs.rax, (uint32_t)c->regs.rcx, (uint32_t)c->regs.rdx,
                   scope->xmm0, &lo, &hi, &popped, scope->xmm0_post, scope->x87_post, (uint32_t)c->hit_sp, scope);
    r = lo;
    c->orig_edx = hi;
    c->orig_pop = popped;
    scope->have_x87 = scope->x87_post != nullptr;
#endif
    scope->have_post = true;
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
    probe_ipc_request req{};
    req.op = op; req.flags = flags; req.origin_site = s->site; req.address = address;
    std::string name;
    if (!callback_export_name(cb, name) || name.size() >= sizeof(req.callback)) return 0;
    std::memcpy(req.callback, name.c_str(), name.size() + 1);
    if (symbol) {
        size_t n = strnlen(symbol, sizeof(req.symbol));
        if (n >= sizeof(req.symbol)) return 0;
        std::memcpy(req.symbol, symbol, n + 1);
    }
    if (config_len) {
        if (!config || config_len > sizeof(req.config)) return 0;
        std::memcpy(req.config, config, config_len);
        req.config_len = (uint32_t)config_len;
    }
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
static thread_local int t_in_callback;
// An exception or longjmp left the original (call_original) and is unwinding past this
// hit's callback: settle what call_mid would have on return (once).
static void hit_scope_abandon(HitScope *h) {
    if (InterlockedExchange(&h->abandoned, 1)) return;
    if (h->tls && tls_ready()) t_in_callback = 0;
    InterlockedExchangeAdd64(h->cell, -PROBE_AGENT_INFLIGHT_ONE);
}
static bool any_inflight() {
    if (!shared) return false;
    return probe_agent_inflight(shared) != 0;
}

// XSAVE support, probed once: mask = XCR0 restricted to x87|SSE|AVX|AVX-512 components.
static struct XState { bool ok = false, compact = false, xinuse = false; uint64_t mask = 0, avx_mask = 0; uint32_t size = 0; } g_xs = [] {
    XState x;
    int r[4];
    __cpuid(r, 1);
    if (!(r[2] & (1 << 27))) return x;                     // OSXSAVE
    x.mask = _xgetbv(0) & 0xE7ull;
    x.avx_mask = x.mask & 0xE4ull;                         // AVX upper + AVX-512 (opmask, ZMM) only
    __cpuidex(r, 0xD, 0); x.size = (uint32_t)r[1];
    __cpuidex(r, 0xD, 1); x.compact = (r[0] & 2) != 0; x.xinuse = (r[0] & 4) != 0;   // XGETBV(1)
    x.ok = x.size && x.size <= 4096;
    return x;
}();



// The callback runs on the target's own thread: any Win32 call it (or the library) makes
// can change the thread's last-error / last-status, which the target may read right
// after the probed instruction. Save and restore both (plain TEB fields: ~free).
#if defined(_WIN64)
static inline volatile DWORD *teb_last_status() { return (volatile DWORD *)((unsigned char *)NtCurrentTeb() + 0x1250); }
#else
static inline volatile DWORD *teb_last_status() { return (volatile DWORD *)((unsigned char *)NtCurrentTeb() + 0xBF4); }
#endif
static bool run_callback(probe_callback cb, probe_context *c) {
    DWORD last_error = GetLastError(), last_status = *teb_last_status();
    __writeeflags(__readeflags() & ~(uintptr_t)0x400);
    bool ok = true;
    __try { cb(c); }
    __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    *teb_last_status() = last_status;
    SetLastError(last_error);
    return ok;
}
// Kept out of line so the 4 KiB save area (and its stack probe) costs nothing on the
// common path.
// x87_post (x86): a 108-byte buffer owned by the caller; returns true when it holds the x87
// state return_from must leave (an ST0 result of call_original), to reload after any
// extended-state restore.
static bool call_mid(safetyhook::Context &native, uint32_t index, unsigned char *x87_post) {
    probe_context c{};
    /* SafetyHook's Context is Context64 on x64 and Context32 on x86; fill the same
       gospel probe_regs from whichever register image this build captured. */
#if defined(_WIN64)
#define COPY(a,b) c.regs.a = native.a;
    PROBE_GPRS(COPY)
#undef COPY
    c.regs.rsp = native.rsp; c.regs.flags = native.rflags;
#else
    c.regs.rax = native.eax; c.regs.rbx = native.ebx; c.regs.rcx = native.ecx;
    c.regs.rdx = native.edx; c.regs.rsi = native.esi; c.regs.rdi = native.edi;
    c.regs.rbp = native.ebp; c.regs.rsp = native.esp; c.regs.flags = native.eflags;
#endif
    c.regs.pc = sites[index]; c.hit_sp = c.regs.rsp;
    c.config = shared->requests[index].config_len ? shared->requests[index].config : nullptr;
    c.ops = &local_ops; c.tid = GetCurrentThreadId(); c.site = index; c.controller = &states[index];
    // Count the hit before the call so a faulting callback is still accounted, and run
    // the callback under SEH so an access violation (or any exception) inside user code
    // cannot take down the target. On a fault we skip register write-back, leaving the
    // target's registers untouched (the callback behaves as a no-op mutation).
    // A hit is a callback run: while being unhooked the hook passes straight through and
    // that pass is NOT counted (else a detach would report hits that have no callback/log).
    if (g_stopping) return false;
    uint32_t stripe = (GetCurrentThreadId() >> 2) & (PROBE_AGENT_STRIPES - 1);
    volatile LONG64 &cell = shared->hit_stripes[index][stripe].value;
    // ONE atomic add counts the hit and marks a callback in flight (see hit_stripes): a thread
    // killed between two separate counters left a hit that was neither logged nor interrupted.
    InterlockedExchangeAdd64(&cell, 1 + PROBE_AGENT_INFLIGHT_ONE);
    // A probe hit by code the callback itself runs (call_func of a probed function, or a
    // probed API called directly) is counted but does not re-enter a callback -- exactly
    // what breakpoint/hw do inside call_func. Re-entering recursed until the stack overflowed.
    // (No TLS yet -- a thread in loader init, see region_cache -- means no callback is running
    // on it; in_call_func covers this thread's call_func whatever its TLS state.)
    if (in_call_func(GetCurrentThreadId()) || (tls_ready() && t_in_callback)) {
        InterlockedExchangeAdd64(&cell, -PROBE_AGENT_INFLIGHT_ONE); return false;
    }
    // The mid-hook stub preserves GPRs, flags and XMM0-15 only. The callback (and the CRT
    // it calls) may touch x87/MXCSR/YMM/ZMM state -- e.g. vzeroupper -- which the target
    // could be relying on at a mid-function site. Save and restore the full extended state
    // and give C code the ABI-required DF=0.
    // Extended state (MXCSR, AVX/AVX-512) and DF are handled in mid_entry, BEFORE any of
    // this C code runs -- see there.
    const bool tls = tls_ready();
    if (tls) t_in_callback = 1;
    HitScope scope{&cell, tls, 0, nullptr};
#if defined(_WIN64)
    scope.xmm6 = &native.xmm6;
#endif
    scope.xmm0 = &native.xmm0;
    scope.x87_post = x87_post;
    c.hit_scope = &scope;
    bool callback_ok = run_callback(callbacks[index], &c);
    if (tls) t_in_callback = 0;
    InterlockedExchangeAdd64(&cell, -PROBE_AGENT_INFLIGHT_ONE);
    if (!callback_ok) return false;
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
        // After call_original the caller gets the original's floating-point result too
        // (XMM0; x86 ST0 through the x87 image the hook entry reloads).
        if (c.called_original && scope.have_post) std::memcpy(&native.xmm0, scope.xmm0_post, 16);
        return c.called_original && scope.have_x87;
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
    if (xmode == 1 || !g_xs.ok) x87 = call_mid(native, index, x87_post);
    else {
        uint64_t mask = 0;
        if (xmode == 2) mask = g_xs.mask;
        else if (g_xs.xinuse) mask = _xgetbv(1) & g_xs.avx_mask;  // only components actually live
        else mask = g_xs.avx_mask;                         // liveness unknown: keep AVX state
        if (mask) x87 = mid_entry_saved(native, index, mask, x87_post);
        else {
            unsigned int mxcsr = _mm_getcsr();             // the common case: just MXCSR
            x87 = call_mid(native, index, x87_post);
            _mm_setcsr(mxcsr);
        }
    }
#if !defined(_WIN64)
    if (x87) x87_restore(x87_post);                        // return_from after call_original: ST0 = its result
#else
    (void)x87;
#endif
}

// One entry thunk per request slot (the slot index is baked in), generated at compile time.
using mid_callback = void (*)(safetyhook::Context &);
template <uint32_t N> static void mid_thunk(safetyhook::Context &c) { mid_entry(c, N); }
template <size_t... I> static constexpr std::array<mid_callback, sizeof...(I)> make_mid_thunks(std::index_sequence<I...>) {
    return {{ &mid_thunk<(uint32_t)I>... }};
}
static constexpr auto mid_callbacks = make_mid_thunks(std::make_index_sequence<PROBE_AGENT_MAX_PROBES>{});

// Run fn with every other thread of the target suspended by the controller (FREEZE/THAW
// IPC; the controller is a debugger, so the raise is serviced synchronously). While frozen,
// SafetyHook patches with the page left executable and no thread trap (patch in
// cmake/patch_safetyhook.cmake), so a site may share a page with anything -- including
// the ntdll routines the patching itself calls. Inside fn: no heap, no locks another
// thread could hold. Without a controller (never in UHH) SafetyHook's own trap is used.
extern "C" volatile long uhh_safetyhook_frozen;
using slot_set = std::bitset<PROBE_AGENT_MAX_PROBES>;
template <class F> static void frozen(const slot_set &enabling, F &&fn) {
    for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i)          // tell the controller which ranges change
        InterlockedExchange(&shared->requests[i].enabling, enabling[i] ? 1 : 0);
    probe_ipc_request req{};
    req.op = PROBE_IPC_FREEZE; req.origin_site = UINT32_MAX; req.address = enabling.any() ? 1 : 0;
    const bool held = raise_ipc(&req) && req.result == 1;
    if (held) InterlockedExchange(&uhh_safetyhook_frozen, 1);
    fn();
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
static void resolve_callbacks() {
    uint32_t count = shared->request_count;
    if (count > PROBE_AGENT_MAX_PROBES) count = PROBE_AGENT_MAX_PROBES;
    for (uint32_t i = 0; i < count; ++i) {
        const auto &request = shared->requests[i];
        if (callbacks[i] || !request.callback[0] || request.config_len > PROBE_AGENT_CONFIG_CAP) continue;
        char name[PROBE_AGENT_EXPORT_CAP];
        std::memcpy(name, request.callback, sizeof(name)); name[sizeof(name) - 1] = 0;
        callbacks[i] = reinterpret_cast<probe_callback>(GetProcAddress(self_module, name));
    }
}

static void install_pending_locked() {
    uint32_t count = shared->request_count;
    if (count > PROBE_AGENT_MAX_PROBES) count = PROBE_AGENT_MAX_PROBES;
    slot_set enabling;
    for (uint32_t i = 0; i < count; ++i) {
        auto &request = shared->requests[i];
        if (!request.site || request.status != PROBE_AGENT_PENDING) continue;
        if (request.config_len > PROBE_AGENT_CONFIG_CAP || !request.callback[0]) {
            InterlockedExchange(&request.status, PROBE_AGENT_BAD_REQUEST); continue;
        }
        // Normally already resolved by resolve_callbacks() at init: GetProcAddress can block on
        // loader state held by a thread that is parked at a LOAD_DLL event (the install that
        // event is waiting for would then never run).
        if (!callbacks[i])
            callbacks[i] = reinterpret_cast<probe_callback>(GetProcAddress(self_module, request.callback));
        if (!callbacks[i]) {
            InterlockedExchange(&request.status, PROBE_AGENT_CALLBACK_MISSING); continue;
        }
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
        hooks[i] = safetyhook::create_mid((void *)(uintptr_t)request.site, mid_callbacks[i],
                                          safetyhook::MidHook::StartDisabled);
        if (!hooks[i]) { InterlockedExchange(&request.status, PROBE_AGENT_HOOK_FAILED); continue; }
        request.patch_len = (uint32_t)hooks[i].original_bytes().size();
        request.trampoline = (uint64_t)hooks[i].uhh_trampoline();
        enabling.set(i);
    }
    if (enabling.none()) return;
    auto enable = [&](const slot_set &which) {
        for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i) {
            if (!which[i]) continue;
            const bool ok = hooks[i].enable().has_value();
            const auto &orig = hooks[i].original_bytes();
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

static HANDLE service_event;
static DWORD WINAPI service_main(void *) {
    for (;;) {
        if (WaitForSingleObject(service_event, INFINITE) != WAIT_OBJECT_0) return 1;
        install_pending();
        notify_installed();
    }
}

extern "C" __declspec(dllexport) DWORD WINAPI probe_agent_init(void *) {
    if (!shared) {
        wchar_t name[64]; probe_agent_mapping_name(GetCurrentProcessId(), name);
        mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (!mapping) return 1;
        shared = static_cast<probe_agent_shared *>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*shared)));
        if (!shared || shared->magic != PROBE_AGENT_MAGIC || shared->version != PROBE_AGENT_VERSION) return 2;
    }
    if (shared->request_count > PROBE_AGENT_MAX_PROBES) return 3;
    make_ret_thunks();
    InterlockedExchange(&g_stopping, 0);   // a new session after a detach: callbacks run again
    for (auto &cb : callbacks) cb = nullptr;  // a new session may map slots to other callbacks
    resolve_callbacks();
    install_pending();
    if (service_event) InterlockedExchange(&shared->service_ready, 1);   // thread from an earlier session
    if (!service_event) {   // first init: start the persistent install thread
        wchar_t name[64]; probe_agent_service_name(GetCurrentProcessId(), name);
        service_event = OpenEventW(SYNCHRONIZE, FALSE, name);
        if (service_event) {
            HANDLE t = CreateThread(nullptr, 0, service_main, nullptr, 0, nullptr);
            if (t) { CloseHandle(t); InterlockedExchange(&shared->service_ready, 1); }
        }
    }
    return 0;
}

// Unhook without pulling code out from under a thread: stop new callbacks, wait for the
// ones in flight to finish (bounded), then remove the hooks.
extern "C" __declspec(dllexport) DWORD WINAPI probe_agent_stop(void *) {
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
