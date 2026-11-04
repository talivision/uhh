#ifndef PROBE_API_H
#define PROBE_API_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Shared state across backends (opt-in). Breakpoint/hw callbacks run in the controller,
   inline callbacks inside the target: a plain global exists once in EACH process, so
   probes that share state normally use one backend. A global marked UHH_SHARED lives in
   a shared section of the callbacks DLL: the controller runs those callbacks from its
   own copy of the same DLL file that the target loads, so both processes see the SAME
   memory, with ordinary native access. Rules: constant/zero initialisation only (C++:
   enforced by constinit), no pointers into either process (store values, handles,
   indices), lock-free atomics for synchronisation. Per session: separate sessions never
   share. Callbacks of a module without UHH_SHARED globals are unaffected. */
#if defined(_MSC_VER)
#pragma section("uhhshr", read, write, shared)
#if defined(__cplusplus) && defined(__cpp_constinit)
#define UHH_SHARED __declspec(allocate("uhhshr")) constinit
#else
#define UHH_SHARED __declspec(allocate("uhhshr"))
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct probe_session probe_session;
typedef struct probe_context probe_context;
typedef void (*probe_callback)(probe_context *);

enum probe_flags {
    PROBE_BREAKPOINT      = 1u << 0,
    PROBE_INLINE          = 1u << 1,
    PROBE_HW              = 1u << 2,
    /* Not supported (refused by every backend). To observe a function's return, read the
       return address at its entry (get_mem at the stack pointer) and add a probe THERE
       from the callback: probe_add_address(get_session(c), ret, on_return, flags). It
       fires on every return to that site, on any backend, without touching the stack. */
    PROBE_AT_RETURN       = 1u << 3,
    PROBE_ALLOW_PREHOOKED = 1u << 4,
    PROBE_FALLBACK_HW     = 1u << 5,
    /* Hardware DATA watchpoints (PROBE_HW only): the callback fires when the probed
       ADDRESS is written (or read+written). No code is modified and no execution is
       hooked -- this observes DATA access, which inline/trampoline hooking cannot do.
       The address is a data location (module+RVA of a variable) aligned to the word
       size. Exactly one of WRITE/RW; absent = an ordinary execute breakpoint. */
    PROBE_WATCH_WRITE     = 1u << 6,
    PROBE_WATCH_RW        = 1u << 7,
    /* Remove the probe after its first hit — e.g. a one-shot return hook, or an
       alloc-site hook that arms a watchpoint once and retires. */
    PROBE_ONCE            = 1u << 8,
    /* PROBE_INLINE only. UNSAFE: write the hook's jump WITHOUT freezing the target. By
       default the controller suspends every other thread while an inline hook is
       written (microseconds, at install/remove only -- never per hit; attach also holds
       every thread until inline hooks are in) and moves any
       thread caught inside the overwritten bytes onto the trampoline. With this flag a
       thread executing those bytes at that moment resumes mid-jump and crashes or
       misbehaves. For measurement/testing; do not use on code other threads may run. */
    PROBE_UNSAFE_FAST_PATCH = 1u << 9,
    /* PROBE_INLINE only. Install even where the site check refuses: an inline hook
       overwrites >= 5 bytes, and it is refused (with the reason) when code could arrive
       inside them -- a branch target, function start, return point or switch-table target,
       a ret/jmp followed by live code, an unresolvable indirect jump in the function, or the
       end of the code section. With this flag the reason is printed as a warning and the
       hook is installed anyway: you assert that nothing reaches those bytes. */
    PROBE_ALLOW_UNSAFE_SITE = 1u << 10
};

/* Every ID is the full native register: RAX..R15 on x64, EAX..EBP/ESP on x86
   (R8..R15 read 0 and cannot be set on x86). PROBE_REG_AX is the return value. */
enum probe_register {
    PROBE_REG_AX,
    PROBE_REG_BX,
    PROBE_REG_CX,
    PROBE_REG_DX,
    PROBE_REG_SI,
    PROBE_REG_DI,
    PROBE_REG_BP,
    PROBE_REG_SP,
    PROBE_REG_R8,
    PROBE_REG_R9,
    PROBE_REG_R10,
    PROBE_REG_R11,
    PROBE_REG_R12,
    PROBE_REG_R13,
    PROBE_REG_R14,
    PROBE_REG_R15
};

/* probe_context is OPAQUE: callbacks reach everything through the accessors below,
   so a context can never be mistaken for a session (distinct incomplete types). */

/* ---- Control plane: take a SESSION. Valid before probe_launch, and from inside any
   callback via get_session(c). From a callback, breakpoint/hw probes arm before the
   target resumes; an inline probe holds the calling thread until its hook is in. */
probe_session *probe_session_create(void);
/* "module+0xRVA" or "module!Export[+0xOFF]" -- resolved when the module loads. */
int probe_add_symbol(probe_session *, const char *symbol, probe_callback, uint32_t flags);
int probe_add_symbol_cfg(probe_session *, const char *symbol, probe_callback, uint32_t flags,
                         const void *config, size_t config_len);
/* An absolute address in the target (e.g. a return address read in a callback). */
int probe_add_address(probe_session *, uint64_t address, probe_callback, uint32_t flags);
/* Hardware DATA watchpoint on an absolute address: flags = PROBE_WATCH_WRITE (default)
   or PROBE_WATCH_RW, optionally | PROBE_ONCE. Max 4 hardware probes in total. */
int probe_watch(probe_session *, uint64_t address, probe_callback, uint32_t flags);
int probe_launch(probe_session *, char *const argv[]);
/* Attach to an already-running process instead of launching one. Probes resolve against
   the modules already loaded (and any loaded later). probe_run returns when the target
   exits; probe_close on a still-running target DETACHES (restores breakpoints, clears
   debug registers, removes inline hooks) instead of terminating it. With inline probes,
   every thread is held at the attach until the hooks are confirmed (bounded: 5 s). */
int probe_attach(probe_session *, uint32_t pid);
/* Wait (up to timeout_ms, 0 = forever) for a NEW process whose image name matches
   (e.g. "probe_app.exe"; processes already running are ignored) and attach to it as
   early as possible. Polls about every millisecond, so the target may run for a few
   milliseconds before the attach lands: instrument what it does after start-up. */
int probe_attach_new(probe_session *, const char *image_name, uint32_t timeout_ms);
int probe_run(probe_session *);
int probe_wait_for_exit(probe_session *);
void probe_report(probe_session *, FILE *);
void probe_close(probe_session *);

/* ---- Data plane: take a CONTEXT (this hit's registers and memory). ---- */
uint64_t get_reg(probe_context *, enum probe_register);
int set_reg(probe_context *, enum probe_register, uint64_t value);
uint64_t get_func_arg(probe_context *, size_t index);
int get_mem(probe_context *, uint64_t address, void *buffer, size_t size);
int set_mem(probe_context *, uint64_t address, const void *buffer, size_t size);
void send_log(probe_context *, const char *format, ...);
/* Same as send_log, plus a snapshot of the call stack at the hit, emitted as ONE log
   record. Only raw return addresses are captured at the hit; module!symbol+off (and
   file:line when PDBs are present) is resolved later, when the log is reported. */
void send_log_stack(probe_context *, const char *format, ...);
const void *get_config(probe_context *);
/* Call a function IN THE TARGET from a callback, on the thread that hit the probe:
   symbol is "module!Export[+0xOFF]", "module+0xRVA" or "0xADDRESS"; up to 8 integer/
   pointer args (Windows x64 ABI / x86 stack args; stdcall or cdecl). *ret receives the
   return register. Returns 1 on success. Inline: a direct call. Breakpoint/hw: the
   debugger runs the call on the stopped thread and restores its context exactly (other
   threads keep running; probes hit inside the callee do not re-enter callbacks) -- tens
   of microseconds, so cache results. The callee runs with whatever locks the hit thread
   holds: avoid functions that need them (e.g. the allocator from inside a malloc hook). */
int call_func(probe_context *, const char *symbol, uint64_t *ret, int nargs, ...);
/* The session this callback belongs to, for control-plane calls from a callback. In a
   breakpoint/hardware callback it is the real session; in an inline callback (running
   inside the target) it is an agent-side proxy whose control calls are forwarded to the
   controller synchronously. Same callback source works in every backend. */
probe_session *get_session(probe_context *);

#define PROBE_LOG(c, ...) send_log((c), __VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif
