#include "win_common.hpp"
#include "probe_agent_shared.hpp"
#include <safetyhook.hpp>

static HMODULE self_module;
static HANDLE mapping;
static probe_agent_shared *shared;
static SafetyHookMid hooks[PROBE_AGENT_MAX_PROBES];
static uint64_t sites[PROBE_AGENT_MAX_PROBES];
static probe_callback callbacks[PROBE_AGENT_MAX_PROBES];

struct AgentState { probe_agent_shared *shared; uint32_t index; };
static AgentState states[PROBE_AGENT_MAX_PROBES];

/* Callback memory helpers fail closed on bad target addresses. They never change
   page protections: executable writes belong to the hook installer, not hits. */
static int local_read(void *, uint64_t address, void *buffer, size_t size, size_t *done) {
    *done = 0;
    __try { std::memcpy(buffer, (const void *)(uintptr_t)address, size); *done = size; return 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
static int local_write(void *, uint64_t address, const void *buffer, size_t size, size_t *done) {
    *done = 0;
    __try { std::memcpy((void *)(uintptr_t)address, buffer, size); *done = size; return 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
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

extern "C" uint64_t probe_reg(probe_context *c, enum probe_register reg) {
    uint64_t *slot = register_slot(c, reg);
    return !slot ? 0 : reg == PROBE_REG_AX ? (uint32_t)*slot : *slot;
}
extern "C" int probe_set_reg(probe_context *c, enum probe_register reg, uint64_t value) {
    uint64_t *slot = register_slot(c, reg); if (!slot) return 0;
    *slot = reg == PROBE_REG_AX ? (uint32_t)value : value; return 1;
}
extern "C" int probe_read(probe_context *c, uint64_t address, void *buffer, size_t size) {
    if (!c || !c->ops || !c->ops->read || (!buffer && size)) return 0;
    size_t done{}; return c->ops->read(c->backend, address, buffer, size, &done) && done == size;
}
extern "C" int probe_write(probe_context *c, uint64_t address, const void *buffer, size_t size) {
    if (!c || !c->ops || !c->ops->write || (!buffer && size)) return 0;
    size_t done{}; return c->ops->write(c->backend, address, buffer, size, &done) && done == size;
}
extern "C" uint64_t probe_arg(probe_context *c, size_t index) {
    if (!c) return 0;
#if defined(_WIN64)
    /* x64 __fastcall: first four args in registers, rest above the shadow space. */
    switch (index) {
    case 0: return c->regs.rcx; case 1: return c->regs.rdx;
    case 2: return c->regs.r8; case 3: return c->regs.r9;
    default: {
        if (c->regs.rsp > UINT64_MAX - 8 || index > (UINT64_MAX - c->regs.rsp - 8) / 8) return 0;
        uint64_t value{}, address = c->regs.rsp + 8 + 8 * index;
        return probe_read(c, address, &value, sizeof(value)) ? value : 0;
    }
    }
#else
    /* x86 __stdcall: every arg on the stack at [esp+4+4*i], read exactly 4 bytes. */
    if (c->regs.rsp > UINT64_MAX - 4 || index > (UINT64_MAX - c->regs.rsp - 4) / 4) return 0;
    uint32_t value{}; uint64_t address = c->regs.rsp + 4 + 4 * index;
    return probe_read(c, address, &value, sizeof(value)) ? value : 0;
#endif
}
extern "C" uint64_t probe_retval(probe_context *c) { return c ? c->regs.rax : 0; }

extern "C" void probe_log(probe_context *c, const char *format, ...) {
    /* Chunk 2 records the stable format text only. Typed argument capture and
       reader-side formatting arrive with the per-thread queues in chunk 3. */
    auto *state = c ? static_cast<AgentState *>(c->controller) : nullptr;
    if (!state || !state->shared || !format) return;
    LONG slot = InterlockedIncrement(&state->shared->log_reserve) - 1;
    if (slot < 0 || slot >= (LONG)PROBE_AGENT_LOG_CAP) {
        InterlockedIncrement(&state->shared->log_dropped); return;
    }
    auto &record = state->shared->logs[slot];
    record.probe = state->index; record.tid = c->tid;
    size_t i = 0;
    __try {
        for (; i + 1 < PROBE_AGENT_LOG_TEXT_CAP && format[i]; ++i) record.text[i] = format[i];
    } __except (EXCEPTION_EXECUTE_HANDLER) { i = 0; }
    record.text[i] = 0;
    MemoryBarrier(); InterlockedExchange(&record.committed, 1);
}

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
    callbacks[index](&c);
    InterlockedIncrement64(&shared->requests[index].hits);
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

#define MID_THUNK(n) static void mid_##n(safetyhook::Context &c) { call_mid(c, n); }
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

extern "C" __declspec(dllexport) DWORD WINAPI probe_agent_init(void *) {
    if (!shared) {
        wchar_t name[64]; probe_agent_mapping_name(GetCurrentProcessId(), name);
        mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (!mapping) return 1;
        shared = static_cast<probe_agent_shared *>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*shared)));
        if (!shared || shared->magic != PROBE_AGENT_MAGIC || shared->version != PROBE_AGENT_VERSION) return 2;
    }
    if (shared->request_count > PROBE_AGENT_MAX_PROBES) return 3;
    for (uint32_t i = 0; i < shared->request_count; ++i) {
        auto &request = shared->requests[i];
        if (!request.site || request.status == PROBE_AGENT_INSTALLED) continue;
        if (request.config_len > PROBE_AGENT_CONFIG_CAP || !request.callback[0]) {
            InterlockedExchange(&request.status, PROBE_AGENT_BAD_REQUEST); continue;
        }
        callbacks[i] = reinterpret_cast<probe_callback>(GetProcAddress(self_module, request.callback));
        if (!callbacks[i]) {
            InterlockedExchange(&request.status, PROBE_AGENT_CALLBACK_MISSING); continue;
        }
        if (InterlockedCompareExchange(&request.status, PROBE_AGENT_INSTALLING, PROBE_AGENT_PENDING) != PROBE_AGENT_PENDING)
            continue;
        sites[i] = request.site; states[i] = {shared, i};
        hooks[i] = safetyhook::create_mid((void *)(uintptr_t)request.site, mid_callbacks[i]);
        InterlockedExchange(&request.status, hooks[i] ? PROBE_AGENT_INSTALLED : PROBE_AGENT_HOOK_FAILED);
    }
    return 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI probe_agent_stop(void *) {
    for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i) hooks[i].reset();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, void *) {
    if (reason == DLL_PROCESS_ATTACH) { self_module = module; DisableThreadLibraryCalls(module); }
    return TRUE;
}
