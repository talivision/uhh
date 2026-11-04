#include "win_common.hpp"
#include "probe_agent_shared.hpp"
#include <safetyhook.hpp>
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

static bool range_ok(uintptr_t a, size_t n, bool write) {
    if (!n) return true;
    if (a + n < a) return false;
    uintptr_t end = a + n;
    while (a < end) {
        if (a >= t_region.lo && a < t_region.hi && (!write || t_region.writable)) {
            a = t_region.hi; continue;
        }
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((void *)a, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) return false;
        DWORD prot = mbi.Protect & 0xFF;
        if ((mbi.Protect & PAGE_GUARD) || prot == PAGE_NOACCESS || prot == 0) return false;
        bool w = prot == PAGE_READWRITE || prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READWRITE ||
                 prot == PAGE_EXECUTE_WRITECOPY;
        bool r = w || prot == PAGE_READONLY || prot == PAGE_EXECUTE_READ;
        if (!r || (write && !w)) return false;
        t_region.lo = (uintptr_t)mbi.BaseAddress;
        t_region.hi = t_region.lo + mbi.RegionSize;
        t_region.writable = w;
        a = t_region.hi;
    }
    return true;
}
static int local_read(void *, uint64_t address, void *buffer, size_t size, size_t *done) {
    *done = 0;
    if (!range_ok((uintptr_t)address, size, false)) return 0;
    __try { std::memcpy(buffer, (const void *)(uintptr_t)address, size); *done = size; return 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { t_region = {}; return 0; }
}
static int local_write(void *, uint64_t address, const void *buffer, size_t size, size_t *done) {
    *done = 0;
    if (!range_ok((uintptr_t)address, size, true)) return 0;
    __try { std::memcpy((void *)(uintptr_t)address, buffer, size); *done = size; return 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { t_region = {}; return 0; }
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

extern "C" uint64_t get_reg(probe_context *c, enum probe_register reg) {
    uint64_t *slot = register_slot(c, reg);
    return slot ? *slot : 0;
}
extern "C" int set_reg(probe_context *c, enum probe_register reg, uint64_t value) {
    uint64_t *slot = register_slot(c, reg); if (!slot) return 0;
    if (*slot != value) {
        *slot = value;
        auto *state = static_cast<AgentState *>(c->controller);
        if (state && state->shared) InterlockedIncrement64(&state->shared->overrides);   // same metric as controller
    }
    return 1;
}
extern "C" int get_mem(probe_context *c, uint64_t address, void *buffer, size_t size) {
    if (!c || !c->ops || !c->ops->read || (!buffer && size)) return 0;
    size_t done{}; return c->ops->read(c->backend, address, buffer, size, &done) && done == size;
}
extern "C" int set_mem(probe_context *c, uint64_t address, const void *buffer, size_t size) {
    if (!c || !c->ops || !c->ops->write || (!buffer && size)) return 0;
    size_t done{}; return c->ops->write(c->backend, address, buffer, size, &done) && done == size;
}
extern "C" uint64_t get_func_arg(probe_context *c, size_t index) {
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
    __try {
        while (n < cap) {
            DWORD64 image = 0;
            PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry(w.Rip, &image, nullptr);
            if (!fn) {                                   // leaf: return address is at [rsp]
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
    __try {
        // At a function's first instructions EBP is still the CALLER's frame, so the EBP
        // chain would skip the immediate caller. If [esp] is a genuine return address
        // (the bytes before it encode a call), record it first. Mid-function, [esp] is
        // usually a local that fails this test, and a duplicate of [ebp+4] is skipped.
        uint32_t top = *(uint32_t *)(uintptr_t)c->regs.rsp;
        uint32_t caller_ret = c->regs.rbp ? *(uint32_t *)(uintptr_t)(c->regs.rbp + 4) : 0;
        if (n < cap && top && top != caller_ret && looks_like_return(top)) frames[n++] = top;
        uint32_t ebp = (uint32_t)c->regs.rbp;
        while (n < cap && ebp) {
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
    int n = -1;
    text[0] = 0;
    __try { n = _vsnprintf_s(text, sizeof(text), _TRUNCATE, format, ap); }
    __except (EXCEPTION_EXECUTE_HANDLER) { n = -1; }
    text[sizeof(text) - 1] = 0;
    if (n < 0 && text[0]) {                                  // truncated: say so, never silently
        static const char mark[] = "...[truncated]";
        std::memcpy(text + sizeof(text) - sizeof(mark), mark, sizeof(mark));
    }
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

extern "C" void send_log(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format); agent_log(c, false, format, ap); va_end(ap);
}
extern "C" void send_log_stack(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format); agent_log(c, true, format, ap); va_end(ap);
}
extern "C" const void *get_config(probe_context *c) { return c ? c->config : nullptr; }

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

extern "C" int call_func(probe_context *c, const char *symbol, uint64_t *ret, int nargs, ...) {
    (void)c;
    if (nargs < 0 || nargs > 8) return 0;
    uint64_t fn = agent_resolve(symbol);
    if (!fn) return 0;
    uint64_t a[8] = {0};
    va_list ap; va_start(ap, nargs);
    for (int i = 0; i < nargs; ++i) a[i] = va_arg(ap, uint64_t);
    va_end(ap);
#if defined(_WIN64)
    return call_raw(fn, a, ret) ? 1 : 0;
#else
    return call_raw(fn, a, ret, nargs) ? 1 : 0;
#endif
}


/* ---- Control plane from an inline callback: forwarded to the controller. ----
   get_session(c) returns a per-site proxy (so the controller knows which probe's
   callback module to resolve names in). Each call is one synchronous exception to the
   debugger; the callback itself is passed by EXPORT NAME and the controller runs its
   own copy of the same source (breakpoint/HW probes execute controller-side). */
struct probe_session { uint32_t site; };
static probe_session proxies[PROBE_AGENT_MAX_PROBES];

extern "C" probe_session *get_session(probe_context *c) {
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
    return forward(s, PROBE_IPC_ADD_ADDRESS, address, nullptr, cb, flags);
}
extern "C" int probe_watch(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags) {
    return forward(s, PROBE_IPC_WATCH, address, nullptr, cb, flags);
}
extern "C" int probe_add_symbol(probe_session *s, const char *symbol, probe_callback cb, uint32_t flags) {
    return forward(s, PROBE_IPC_ADD_SYMBOL, 0, symbol, cb, flags);
}
extern "C" int probe_add_symbol_cfg(probe_session *s, const char *symbol, probe_callback cb, uint32_t flags,
                                    const void *config, size_t config_len) {
    return forward(s, PROBE_IPC_ADD_SYMBOL, 0, symbol, cb, flags, config, config_len);
}

static volatile LONG g_stopping;
static struct alignas(64) { volatile LONG value; } g_inflight[PROBE_AGENT_STRIPES];
static bool any_inflight() {
    for (auto &x : g_inflight) if (x.value) return true;
    return false;
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
static void call_mid(safetyhook::Context &native, uint32_t index) {
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
    c.regs.pc = sites[index];
    c.config = shared->requests[index].config_len ? shared->requests[index].config : nullptr;
    c.ops = &local_ops; c.tid = GetCurrentThreadId(); c.site = index; c.controller = &states[index];
    // Count the hit before the call so a faulting callback is still accounted, and run
    // the callback under SEH so an access violation (or any exception) inside user code
    // cannot take down the target. On a fault we skip register write-back, leaving the
    // target's registers untouched (the callback behaves as a no-op mutation).
    uint32_t stripe = (GetCurrentThreadId() >> 2) & (PROBE_AGENT_STRIPES - 1);
    InterlockedIncrement64(&shared->hit_stripes[index][stripe].value);
    if (g_stopping) return;                                // being unhooked: pass straight through
    InterlockedIncrement(&g_inflight[stripe].value);
    // The mid-hook stub preserves GPRs, flags and XMM0-15 only. The callback (and the CRT
    // it calls) may touch x87/MXCSR/YMM/ZMM state -- e.g. vzeroupper -- which the target
    // could be relying on at a mid-function site. Save and restore the full extended state
    // and give C code the ABI-required DF=0.
    // Extended state (MXCSR, AVX/AVX-512) and DF are handled in mid_entry, BEFORE any of
    // this C code runs -- see there.
    bool callback_ok = run_callback(callbacks[index], &c);
    InterlockedDecrement(&g_inflight[stripe].value);
    if (!callback_ok) return;
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
}

// Entry point of every inline hit. It runs FIRST, before any C code that might call the
// CRT: the CRT's memset/memcpy pick AVX paths ending in VZEROUPPER (wiping every YMM upper
// half the target may have live at a mid-function site), and its x86 rep-stos/movs paths
// run BACKWARDS if the site executes with DF=1. So: clear DF, then save what the stub
// does not (MXCSR always; AVX/AVX-512 when live, or unconditionally when the CPU cannot
// report liveness), using intrinsics only -- then run the hit. The stub restores RFLAGS
// (so the target's DF) on the way out.
static __declspec(noinline) void mid_entry_saved(safetyhook::Context &native, uint32_t index, uint64_t mask) {
    alignas(64) unsigned char area[4096];
    __stosb(area + 512, 0, 64);                            // XSAVE header must start clean (no CRT call)
#if defined(_WIN64)
    if (g_xs.compact) _xsavec64(area, mask); else _xsave64(area, mask);
#else
    if (g_xs.compact) _xsavec(area, mask); else _xsave(area, mask);
#endif
    unsigned int mxcsr = _mm_getcsr();
    call_mid(native, index);
    _mm_setcsr(mxcsr);
#if defined(_WIN64)
    _xrstor64(area, mask);
#else
    _xrstor(area, mask);
#endif
}

static inline void mid_entry(safetyhook::Context &native, uint32_t index) {
    __writeeflags(__readeflags() & ~(uintptr_t)0x400);    // DF=0 before ANY C code
    LONG xmode = shared->xstate_mode;                      // 0 gated (default), 1 none, 2 full (bench knob)
    if (xmode == 1 || !g_xs.ok) { call_mid(native, index); return; }
    uint64_t mask = 0;
    if (xmode == 2) mask = g_xs.mask;
    else if (g_xs.xinuse) mask = _xgetbv(1) & g_xs.avx_mask;  // only components actually live
    else mask = g_xs.avx_mask;                             // liveness unknown: keep AVX state
    if (mask) { mid_entry_saved(native, index, mask); return; }
    unsigned int mxcsr = _mm_getcsr();                     // the common case: just MXCSR
    call_mid(native, index);
    _mm_setcsr(mxcsr);
}

#define MID_THUNK(n) static void mid_##n(safetyhook::Context &c) { mid_entry(c, n); }
MID_THUNK(0) MID_THUNK(1) MID_THUNK(2) MID_THUNK(3) MID_THUNK(4) MID_THUNK(5) MID_THUNK(6) MID_THUNK(7)
MID_THUNK(8) MID_THUNK(9) MID_THUNK(10) MID_THUNK(11) MID_THUNK(12) MID_THUNK(13) MID_THUNK(14) MID_THUNK(15)
MID_THUNK(16) MID_THUNK(17) MID_THUNK(18) MID_THUNK(19) MID_THUNK(20) MID_THUNK(21) MID_THUNK(22) MID_THUNK(23)
MID_THUNK(24) MID_THUNK(25) MID_THUNK(26) MID_THUNK(27) MID_THUNK(28) MID_THUNK(29) MID_THUNK(30) MID_THUNK(31)
#undef MID_THUNK
using mid_callback = void (*)(safetyhook::Context &);
static mid_callback mid_callbacks[PROBE_AGENT_MAX_PROBES] = {
    mid_0,mid_1,mid_2,mid_3,mid_4,mid_5,mid_6,mid_7,mid_8,mid_9,mid_10,mid_11,mid_12,mid_13,mid_14,mid_15,
    mid_16,mid_17,mid_18,mid_19,mid_20,mid_21,mid_22,mid_23,mid_24,mid_25,mid_26,mid_27,mid_28,mid_29,mid_30,mid_31
};

// Run fn with every other thread of the target suspended by the controller (FREEZE/THAW
// IPC; the controller is a debugger, so the raise is serviced synchronously). While frozen,
// SafetyHook patches with the page left executable and no thread trap (patch in
// cmake/patch_safetyhook.cmake), so a site may share a page with anything -- including
// the ntdll routines the patching itself calls. Inside fn: no heap, no locks another
// thread could hold. Without a controller (never in UHH) SafetyHook's own trap is used.
extern "C" volatile long uhh_safetyhook_frozen;
template <class F> static void frozen(uint64_t enabling_mask, F &&fn) {
    probe_ipc_request req{};
    req.op = PROBE_IPC_FREEZE; req.origin_site = UINT32_MAX; req.address = enabling_mask;
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

static void install_pending() {
    uint32_t count = shared->request_count;
    if (count > PROBE_AGENT_MAX_PROBES) count = PROBE_AGENT_MAX_PROBES;
    uint64_t enabling = 0;
    for (uint32_t i = 0; i < count; ++i) {
        auto &request = shared->requests[i];
        if (!request.site || request.status != PROBE_AGENT_PENDING) continue;
        if (request.config_len > PROBE_AGENT_CONFIG_CAP || !request.callback[0]) {
            InterlockedExchange(&request.status, PROBE_AGENT_BAD_REQUEST); continue;
        }
        callbacks[i] = reinterpret_cast<probe_callback>(GetProcAddress(self_module, request.callback));
        if (!callbacks[i]) {
            InterlockedExchange(&request.status, PROBE_AGENT_CALLBACK_MISSING); continue;
        }
        if (InterlockedCompareExchange(&request.status, PROBE_AGENT_INSTALLING, PROBE_AGENT_PENDING) != PROBE_AGENT_PENDING)
            continue;
        sites[i] = request.site; states[i] = {shared, i}; proxies[i].site = i;
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
        enabling |= 1ull << i;
    }
    if (!enabling) return;
    auto enable = [&](uint64_t which) {
        for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i) {
            if (!(which & (1ull << i))) continue;
            const bool ok = hooks[i].enable().has_value();
            InterlockedExchange(&shared->requests[i].status, ok ? PROBE_AGENT_INSTALLED : PROBE_AGENT_HOOK_FAILED);
        }
    };
    // PROBE_UNSAFE_FAST_PATCH: write while the other threads keep running (page kept
    // executable, no freeze, no trap) -- the race the freeze exists to prevent.
    uint64_t unsafe = 0;
    for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i)
        if ((enabling & (1ull << i)) && (shared->requests[i].flags & PROBE_AGENT_FLAG_UNSAFE_FAST_PATCH)) unsafe |= 1ull << i;
    if (unsafe) {
        InterlockedExchange(&uhh_safetyhook_frozen, 1);
        enable(unsafe);
        InterlockedExchange(&uhh_safetyhook_frozen, 0);
    }
    if (enabling & ~unsafe) frozen(enabling & ~unsafe, [&] { enable(enabling & ~unsafe); });
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
    InterlockedExchange(&g_stopping, 0);   // a new session after a detach: callbacks run again
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
    InterlockedExchange(&g_stopping, 1);
    for (int i = 0; i < 2000 && any_inflight(); ++i) Sleep(1);
    frozen(0, [] {
        for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i)
            // Restore the original bytes -- unless the controller saw the module unload
            // (the address is unmapped or holds another image now).
            if (hooks[i] && shared->requests[i].status != PROBE_AGENT_UNLOADED) (void)hooks[i].disable();
    });
    // Keep the trampolines and stubs: a thread may still be on its way back through one
    // (it then jumps to the original code, which is intact). Deliberate leak, once.
    for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i)
        if (hooks[i]) new SafetyHookMid(std::move(hooks[i]));
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, void *) {
    if (reason == DLL_PROCESS_ATTACH) { self_module = module; DisableThreadLibraryCalls(module); }
    return TRUE;
}
