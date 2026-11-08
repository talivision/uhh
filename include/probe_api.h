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

/* Portability: what one callback source can rely on under every backend (checked by the
   regress portability-* matrix; details in docs/ROADMAP.md, "Portability findings").
   Every function below returns the same values on every backend, for the same arguments,
   including the failure cases documented with it. What DIFFERS follows from WHERE the
   callback runs -- breakpoint/hw: in the controller, one hit at a time on its debugger
   thread; inline: inside the target, on the thread that hit the probe, concurrently:
   - Win32 calls made directly by a callback act on the process the callback runs in:
     GetCurrentProcessId/ThreadId, Sleep, file I/O, allocations... For the TARGET's pid / tid
     use call_func(c, "kernel32.dll!GetCurrentProcessId" / "...!GetCurrentThreadId", &v, 0);
     for target memory get_mem/set_mem (a target pointer cannot be dereferenced on
     breakpoint/hw, nor printed with %s).
   - Concurrency: inline callbacks of any number of target threads run at the same time;
     breakpoint/hw callbacks never overlap. Plain static state must be atomic (or locked) to
     be correct inline. thread_local is per TARGET thread inline but per controller thread
     (one for all target threads) on breakpoint/hw: keep per-thread state keyed by the
     target tid instead.
   - A callback that faults or throws is abandoned on every backend (the hit counts, its
     register changes are discarded, set_mem writes already made stay, the program runs on).
     Inline the exception is raised in the target, so the program's vectored exception
     handlers see it first (first chance); on breakpoint/hw the program never sees it. */
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
       The address is a data location (module+RVA of a variable), 4-byte aligned; one
       dword is watched on both x64 and x86. Exactly one of WRITE/RW; absent = an
       ordinary execute breakpoint. */
    PROBE_WATCH_WRITE     = 1u << 6,
    PROBE_WATCH_RW        = 1u << 7,
    /* Remove the probe after its first hit — e.g. a one-shot return hook, or an
       alloc-site hook that arms a watchpoint once and retires. PROBE_BREAKPOINT / PROBE_HW
       only: refused (0) with PROBE_INLINE, from any caller. */
    PROBE_ONCE            = 1u << 8,
    /* PROBE_INLINE only. UNSAFE: write the hook's jump WITHOUT freezing the target. By
       default the controller suspends every other thread while an inline hook is
       written (microseconds, at install/remove only -- never per hit) and moves any
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
   (R8..R15 read 0 and cannot be set on x86). PROBE_REG_AX is the return value. On x86
   set_reg keeps the low 32 bits of the value -- what the register holds -- and a later
   get_reg returns exactly that. */
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
/* "module+0xRVA" or "module!Export[+0xOFF]" -- resolved when the module loads (an export,
   else a PDB symbol). The grammar is call_func's, on every backend: the module is matched by
   its file name, case-insensitively (a directory part is ignored), and a name without
   extension means "<name>.dll" ("kernel32!X" == "kernel32.dll!X"); an EXE is named with
   its extension ("probe_app.exe!X": "probe_app!X" names probe_app.dll, and a warning on
   stderr says so when probe_app.exe loads instead). Offsets are "+0x" hex only.
   Limits, the same on every backend and from a callback: a config is at most 4 GB
   (UINT32_MAX bytes); in a session that also has inline probes at most 65536 software-
   breakpoint probes are armed at once (the next one is refused: inline get_mem must see the
   program's byte under each of them). */
int probe_add_symbol(probe_session *, const char *symbol, probe_callback, uint32_t flags);
int probe_add_symbol_cfg(probe_session *, const char *symbol, probe_callback, uint32_t flags,
                         const void *config, size_t config_len);
/* An absolute address in the target (e.g. a return address read in a callback). */
int probe_add_address(probe_session *, uint64_t address, probe_callback, uint32_t flags);
/* Hardware DATA watchpoint on an absolute address: flags = PROBE_WATCH_WRITE (default)
   or PROBE_WATCH_RW, optionally | PROBE_ONCE. Max 4 hardware probes in total. */
int probe_watch(probe_session *, uint64_t address, probe_callback, uint32_t flags);
/* Start argv[0] (with argv) under UHH. The target inherits the caller's stdin. Its stdout
   and stderr are the caller's when those are a console (or NUL); when they are a pipe or a
   file, the target writes into its own pipe (GetFileType: FILE_TYPE_PIPE) and UHH forwards
   its bytes unchanged, a complete line at a time, so a live probe_log record is always a
   whole line of its own and never lands inside one of the target's lines. An unfinished
   line (a prompt, binary output) goes out after ~50 ms without new bytes; records logged
   meanwhile follow at the target's next newline. stdout and stderr that are one stream
   (2>&1) share one pipe, so their order is kept. Only when the target ends inside a line
   and records or the report still follow does UHH end that line ("\n") first. After the
   target exits, output its children still write is forwarded until probe_close. */
int probe_launch(probe_session *, char *const argv[]);
/* Attach to an already-running process instead of launching one. Probes resolve against
   the modules already loaded (and any loaded later). probe_run returns when the target
   exits; probe_close on a still-running target DETACHES (restores breakpoints, clears
   debug registers, removes inline hooks) instead of terminating it. The target keeps
   running while the probes arm: each one counts from its "probe: active" line on (an
   inline hook once the injected agent confirms it; every hook write briefly suspends
   all threads so none is ever mid-patch). */
int probe_attach(probe_session *, uint32_t pid);
/* Wait (up to timeout_ms, 0 = forever) for a NEW process whose image name matches
   (e.g. "probe_app.exe"; processes already running are ignored) and attach to it as
   early as possible. Polls about every millisecond, so the target may run for a few
   milliseconds before the attach lands: instrument what it does after start-up. */
int probe_attach_new(probe_session *, const char *image_name, uint32_t timeout_ms);
/* Ctrl+C / Ctrl+Break while probe_run (through probe_wait_for_exit) runs ends the SESSION,
   not the tool: an attached target is detached (probes removed, it keeps running), a
   launched one is ended, and probe_run returns normally -- so the caller still flushes the
   logs and writes its report. A second press gets the default handling. */
int probe_run(probe_session *);
/* Waits until all probe_log records are in the session JSONL file and its live stdout
   tail (unless stdout is NUL) has reached the same byte offset. A stdout whose reader went
   away (a closed pipe: `| head`) is not a failure: the live tail stops with a warning on
   stderr, every record still reaches the file, and probe_report says
   "live_output_closed":true; `error` and the return value reflect real failures only.
   Returns 1 when the session ended without error AND the target exited with code 0 (or the
   session was interrupted by Ctrl+C); a target exit code other than 0 returns 0 with no
   error set: read the exit code from the probe_report record. */
int probe_wait_for_exit(probe_session *);
/* Catches the stdout tail up first, then writes only prehook/probe/probe_report records
   to out. File-backed logs are never replayed, including on repeated calls. */
void probe_report(probe_session *, FILE *);
void probe_close(probe_session *);

/* ---- Data plane: take a CONTEXT (this hit's registers and memory). ---- */
uint64_t get_reg(probe_context *, enum probe_register);
int set_reg(probe_context *, enum probe_register, uint64_t value);
/* Integer argument `index` at a function ENTRY probe ([SP] = the return address). The API
   cannot know the callee's convention, so the index is positional per architecture:
   x64 (every convention, incl. __vectorcall): the index-th argument -- 0..3 = RCX, RDX, R8, R9,
     then [RSP+8+8*index]. A float/double among the first four is in XMM<index> (not
     readable: that index returns the unrelated integer register); a struct of 1/2/4/8 bytes
     comes by value, any other struct as a pointer to a caller copy; a hidden return pointer
     (struct results over 8 bytes) is index 0 (member functions: `this` 0, hidden pointer 1)
     and shifts the rest up by one.
   x86: the index-th 4-byte STACK slot, [ESP+4+4*index], whatever the convention. Register
     arguments are not slots -- read them with get_reg: __fastcall ECX, EDX (the first two
     integer args; index 0 is the third), __thiscall ECX = this (index 0 is the first
     declared argument), __vectorcall ECX, EDX and XMM0-5 (not readable). A 64-bit integer
     or double takes two slots (low, high), a float one, a struct by value size/4 slots,
     and a hidden return pointer (results over 8 bytes) is slot 0.
   Only meaningful at the entry; mid-function the slots are wherever SP happens to be. */
uint64_t get_func_arg(probe_context *, size_t index);
int get_mem(probe_context *, uint64_t address, void *buffer, size_t size);
int set_mem(probe_context *, uint64_t address, const void *buffer, size_t size);
void send_log(probe_context *, const char *format, ...);
/* Same as send_log, plus a snapshot of the call stack at the hit, emitted as ONE log
   record. Only raw return addresses are captured at the hit; module!symbol+off (and
   file:line when PDBs are present) is resolved later on the controller's log-writer
   thread. Both calls append complete JSON lines to the session log file, live-tailed
   to controller stdout by default. */
void send_log_stack(probe_context *, const char *format, ...);
const void *get_config(probe_context *);
/* Call a function IN THE TARGET from a callback, on the thread that hit the probe:
   symbol is "module!Export[+0xOFF]", "module+0xRVA" or "0xADDRESS"; up to 8 integer/
   pointer args, each read as a uint64_t (cast every argument: an int passed on x86 is
   misread) (Windows x64 ABI / x86 stack args; stdcall or cdecl). *ret receives the
   return register. Returns 1 on success. Inline: a direct call. Breakpoint/hw: the
   debugger runs the call on the stopped thread and restores its context exactly (other
   threads keep running; probes hit inside the callee do not re-enter callbacks) -- tens
   of microseconds, so cache results. The callee runs with whatever locks the hit thread
   holds: avoid functions that need them (e.g. the allocator from inside a malloc hook).
   The symbol grammar is the same on every backend: the module is matched by its file name
   (a directory part is ignored; a name without extension means "<name>.dll", so
   "kernel32!X" == "kernel32.dll!X"), offsets are "+0x"
   hex only; an unknown module/export, nargs outside 0..8 or an address that is no committed
   executable memory returns 0 without calling anything. Breakpoint/hw also refuse (0, one
   stderr line per probe) a call on a thread whose stack is within its last pages (the
   callee's frame is not grown into them; docs/limitations.md). One difference: a callee that raises
   an exception -- even one it handles itself -- is abandoned at that exception on
   breakpoint/hw (returns 0, *ret untouched, the target never sees it), while inline it is
   dispatched in the target as usual (handled inside: returns 1; unhandled: 0) and the
   target's vectored handlers see it. */
int call_func(probe_context *, const char *symbol, uint64_t *ret, int nargs, ...);
/* Detours-style replacement from an ENTRY probe (a probe on a function's first
   instruction -- also a jmp thunk: an import/incremental-link thunk or tail-call target, and
   an x86 `mov edi,edi` hot-patch prologue), same source on every backend.
   call_original runs the probed function NOW, on the hit thread, with the CURRENT
   argument registers and stack (including set_reg/set_mem changes the callback made); *ret
   receives its integer return register (x64 RAX; x86 EAX, zero-extended -- the high half of
   an EDX:EAX result is not in *ret, but return_from passes it on, see there). A float/double
   result (ST0/XMM0) is not in *ret either; return_from passes it on too. Returns 1 if it
   ran. This probe does not fire (and counts no hit) for that call. nargs = integer/pointer
   arguments the function takes (0..16, e.g. 11 for NtCreateFile); it matters to inline only, and
   only as a minimum (register arguments always go as at the hit: a method with no other
   arguments is called with nargs 0):
   inline runs the original in a NEW call frame holding a copy of the hit's stack arguments
   -- every one of the first 32 x64 stack arguments / 64 x86 stack slots (bounded by the top
   of the thread's stack), plus RCX/RDX/R8/R9 (x64), EAX/ECX/EDX (x86) and XMM0-5 as at the
   hit -- so >8 arguments, 64-bit/struct/double stack arguments, hidden return pointers and
   float arguments all arrive as they do on breakpoint/hw. Larger stack arguments
   (> 256 bytes of them) are cut off on inline. Inline: a real call to the hook's trampoline.
   Breakpoint/hw: the original runs in place on the hit's own stack, from the probe address,
   and a debug register set on that thread only catches its return (needs one of the 4
   debug registers for the duration of the call: a free one, or -- when the hit is itself a
   hw execute probe -- its own, lent on that thread (a recursive entry on that thread during
   the call then goes uncounted); refused -- 0, warned once per probe -- otherwise). Probes hit INSIDE the original: those of the same kind (inline inside an
   inline call; breakpoint/hw inside a breakpoint/hw call) -- this one included, for a
   recursive function -- count their hits but run no callback; probes of the other kind fire
   normally. On breakpoint/hw other threads' hits wait until the call ends.
   An exception or longjmp out of the original goes to the PROGRAM's own handlers exactly as
   without the probe: the body ran once, and the rest of the callback does not run (on every
   backend; the callback cannot catch it, and its C++ locals are not destroyed). The same
   holds on breakpoint/hw for an original that has not returned after 5 s (the call is
   released and runs on; the callback ends) and for a thread that exits inside it.
   Refused (0, warned once) when the hit is not at a function entry -- [SP] is not a return
   address (the bytes before it are no CALL); e.g. a probe after a `push`. On 0 the original
   has NOT run: don't return_from, just let the hit fall through.
   return_from makes the probed function return to its caller as soon as the callback
   ends: the original body is not run (again). Resumes at a real `ret` (x86: `ret nargs*4`)
   with SP at the hit's return address, so the CPU pops the normal and shadow stacks
   together (CET-safe on every backend; on breakpoint/hw after call_original under a CET
   shadow stack, whose entry the original's own ret already popped, the thread resumes at
   the return address directly). The caller gets: x64 RAX = value; x86 EAX = the low
   half of value and EDX = its high half (an __int64 or 8-byte struct result) -- except that
   after call_original, a value whose high half is 0 leaves EDX as the original returned it,
   so return_from(c, r, nargs) passes ANY integer result through unchanged (to return a
   64-bit value with a zero high half there, set_reg(c, PROBE_REG_DX, 0) after return_from).
   Floating-point results cannot be set: after call_original the caller gets the original's
   own XMM0 / x87 ST0 (so passing a float/double result through works); without it, it gets
   whatever XMM0/ST0 hold (garbage -- don't return_from a float function without calling the
   original). A struct result over 8 bytes is returned through the hidden pointer
   (get_func_arg(c, 0), x64 member functions 1): write it with set_mem and return_from(c,
   pointer, nargs). nargs: the x86 STACK argument slots the callee pops -- __stdcall,
   __thiscall, __fastcall and __vectorcall pop theirs, i.e. every slot get_func_arg can see
   (__stdcall: all of them, 64-bit/double ones counting 2; __fastcall/__vectorcall: those after
   the register ones; __thiscall: those after `this`; a hidden return pointer counts 1);
   pass 0 for an x86 __cdecl (or varargs) function (the caller pops); ignored on x64 (but a
   value outside 0..255 makes return_from do nothing, on every backend). The API
   cannot know the convention: after call_original the count the original REALLY popped
   (measured) is used and a different nargs is warned once per probe; without call_original
   a wrong nargs is NOT caught and leaves the caller's ESP off by the difference. Refused
   (no effect, warned once) where call_original is. Other register changes the callback made
   (set_reg) are kept; SP is always the hit's. Calling call_original without return_from lets
   the original run a second time on fall-through (warned once per probe) -- except on
   breakpoint/hw under a CET shadow stack, where it cannot run twice: the caller gets the
   original's result (warned once). See
   docs/ROADMAP.md, "call_original findings" and "Calling-convention findings". */
int call_original(probe_context *, int nargs, uint64_t *ret);
void return_from(probe_context *, uint64_t value, int nargs);
/* The session this callback belongs to, for control-plane calls from a callback. In a
   breakpoint/hardware callback it is the real session; in an inline callback (running
   inside the target) it is an agent-side proxy whose control calls are forwarded to the
   controller synchronously. Same callback source works in every backend. From a callback,
   only probe_add_symbol[_cfg] / probe_add_address / probe_watch may be used, and the new
   probe's callback must be EXPORTED (dllexport) by the module of the calling callback: an
   inline callback's request names it by export and the controller resolves that name only
   there (the target is untrusted), so a non-exported callback, or one of another module, is
   refused (0) on every backend. A config has no extra size
   limit from a callback (4 GB everywhere, see probe_add_symbol), an inline probe's included;
   a symbol string sent from an inline callback is limited to 64 KiB. */
probe_session *get_session(probe_context *);

#define PROBE_LOG(c, ...) send_log((c), __VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif
