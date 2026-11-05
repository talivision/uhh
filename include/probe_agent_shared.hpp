#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstdint>
#include <cstdio>

constexpr uint32_t PROBE_AGENT_MAGIC = 0x50424131; // "PBA1"
constexpr uint32_t PROBE_AGENT_VERSION = 17;
constexpr uint32_t PROBE_AGENT_FLAG_UNSAFE_FAST_PATCH = 1u << 9;   /* agent side only needs this one */   /* == PROBE_UNSAFE_FAST_PATCH (asserted in session.cpp) */
constexpr uint32_t PROBE_AGENT_MAX_PROBES = 128;   /* inline probes per session; the 129th is refused */
constexpr uint32_t PROBE_AGENT_EXPORT_CAP = 128;
constexpr uint32_t PROBE_AGENT_CONFIG_CAP = 256;
constexpr uint32_t PROBE_AGENT_LOG_CAP = 4096;      /* ring slots; the controller drains continuously */
constexpr uint32_t PROBE_AGENT_LOG_TEXT_CAP = 1024;   /* == the controller-side limit: one limit for every backend */

enum probe_agent_status : LONG {
    PROBE_AGENT_PENDING = 0,
    PROBE_AGENT_INSTALLING = 1,
    PROBE_AGENT_INSTALLED = 2,
    PROBE_AGENT_UNLOADED = 3,        /* controller: the hooked module went away -- never touch that hook again */
    PROBE_AGENT_BAD_REQUEST = -1,
    PROBE_AGENT_CALLBACK_MISSING = -2,
    PROBE_AGENT_HOOK_FAILED = -3
};

struct probe_agent_request {
    uint64_t site;
    uint32_t flags;
    uint32_t config_len;
    char callback[PROBE_AGENT_EXPORT_CAP];
    unsigned char config[PROBE_AGENT_CONFIG_CAP];
    volatile LONG status;
    uint32_t patch_len;            /* agent: bytes the hook overwrites at site (set before a freeze) */
    uint64_t config_remote;        /* config_len > PROBE_AGENT_CONFIG_CAP: the config lives in a block
                                      the controller allocated in the target (else in config[]) */
    uint64_t trampoline;           /* agent: relocated copies of the overwritten instructions */
    volatile LONG enabling;        /* agent: 1 while this hook is about to be written under a FREEZE */
    uint32_t original_len;         /* agent: the program's bytes the installed hook overwrote, so a */
    uint8_t original[32];          /* breakpoint/hw callback's get_mem shows them (set before INSTALLED) */
};

/* Armed software breakpoints (INT3) of the session, published by the controller so an INLINE
   callback's get_mem shows the program's byte under them, as breakpoint/hw callbacks do (a
   callback reading code another backend probes saw 0xCC inline). Seqlock: the controller
   makes int3_seq odd while it rewrites the table; a reader retries (bounded) or skips. */
constexpr uint32_t PROBE_AGENT_INT3_CAP = 1024;
struct probe_agent_int3 { uint64_t address; uint8_t original; uint8_t pad[7]; };

/* Bounded MPMC ring (Vyukov): slot i starts with seq == i. A producer owns position
   pos when logs[pos % CAP].seq == pos; it claims it by CAS of the slot's owner (0 -> its
   tid) and THEN CAS of log_head (pos -> pos + 1) -- so every claimed slot names its producer
   -- fills the slot, then publishes seq = pos + 1. The single consumer (the controller) reads
   while seq == tail + 1 and frees the slot (owner = 0, seq = tail + CAP). While the tail is
   stuck behind an unpublished slot, the controller also delivers the published records
   beyond it in order and marks them seq = -(pos + 1) (delivered, freed when the tail passes).
   A full ring makes the producer WAIT (backpressure). Nothing is dropped while the
   controller is there:
   - a slot whose owner thread DIED between claim and publish (TerminateThread) is skipped
     by the controller once that thread is gone -- its callback stays counted in flight
     (callbacks_interrupted), so it is accounted, and the ring moves on;
   - while the ring is stuck behind a slot whose owner is alive but not running (suspended
     by the program), the controller sets ring_stalled and producers hand their record to
     the controller synchronously (PROBE_IPC_LOG) instead of waiting or dropping.
   A record is dropped (counted in log_dropped) only when the controller is gone: it
   stopped consuming (controller_gone: detach/close) or its process died. */
struct probe_agent_log {
    volatile LONG64 seq;
    uint32_t probe;
    uint32_t tid;
    char text[PROBE_AGENT_LOG_TEXT_CAP];
    uint32_t frame_count;          /* 0 = plain log; else frames[] is a stack snapshot */
    uint32_t has_stack;
    uint32_t text_len;             /* text may contain NULs (%c of 0): this is its length */
    volatile LONG owner;           /* tid of the producer that claimed the slot; 0 = free/unknown */
    uint64_t frames[32];           /* == PROBE_STACK_MAX_FRAMES */
};

/* Agent -> controller control-plane call from an INLINE callback (which runs inside the
   target). The agent fills this on its stack and RaiseException(PROBE_IPC_CODE, ptr); the
   controller (the debugger) gets it first-chance, services it while the thread is stopped,
   writes result, and continues -- a synchronous call, no polling, no extra thread. */
constexpr DWORD PROBE_IPC_CODE = 0xE0554848u;   /* 'UHH' */
enum probe_ipc_op : uint32_t { PROBE_IPC_ADD_ADDRESS = 1, PROBE_IPC_WATCH = 2, PROBE_IPC_ADD_SYMBOL = 3,
                               PROBE_IPC_INSTALL_DONE = 4,     /* agent service: an install round finished */
                               PROBE_IPC_FREEZE = 5,           /* suspend every other thread; the requests about
                                                                  to be enabled carry enabling = 1 */
                               PROBE_IPC_THAW = 6,             /* resume the threads the last FREEZE suspended */
                               PROBE_IPC_LOG = 7 };            /* address = a probe_agent_log on the caller's
                                                                  stack: deliver it (the ring is stalled) */
/* Hooks are written ONLY with the rest of the target frozen by the controller (a debugger):
   the page stays executable, no thread can run the bytes mid-write, nothing faults. A thread
   the freeze caught inside a range about to be overwritten is moved by the controller to the
   same instruction in that hook's trampoline. */
/* The callback's export name, the symbol and the config stay in the calling thread's memory
   (it is stopped while the controller services the call) and are read from there, so a call
   from an inline callback has no size limits a breakpoint/hw callback's call does not have
   (it had: config <= 256 bytes, symbol <= 255 chars, refused only inline). */
constexpr uint64_t PROBE_IPC_TEXT_MAX = 64u << 10;      /* sanity bounds on what the target claims */
constexpr uint64_t PROBE_IPC_CONFIG_MAX = 64u << 20;
struct probe_ipc_request {
    uint32_t op, flags, origin_site;
    int32_t result;
    uint64_t address;
    uint64_t callback, callback_len;      /* export name (not NUL-terminated) */
    uint64_t symbol, symbol_len;          /* probe_add_symbol */
    uint64_t config, config_len;          /* probe_add_symbol_cfg */
};

/* Hit counting and in-flight tracking are striped over cache-line-separated counters
   (indexed by thread id) so threads hitting the same probe do not contend on one line.
   Exact: the controller sums the stripes. */
constexpr uint32_t PROBE_AGENT_STRIPES = 16;
struct alignas(64) probe_agent_stripe { volatile LONG64 value; char pad[56]; };

struct probe_agent_shared {
    uint32_t magic;
    uint32_t version;
    uint32_t request_count;
    uint32_t reserved;
    volatile LONG64 log_head;      /* next position producers claim */
    volatile LONG64 log_tail;      /* next position the controller consumes */
    volatile LONG log_dropped;
    volatile LONG service_ready;   /* agent's persistent install thread is waiting on the svc event */
    volatile LONG64 overrides;     /* set_reg calls that changed a register, inline side */
    volatile LONG64 drain_beat;    /* bumped by the controller's drainer every loop: liveness */
    volatile LONG xstate_mode;     /* benchmark knob: 0 = default (gated), 1 = none, 2 = full */
    volatile LONG controller_gone; /* set when the controller stops consuming (detach/close): log calls return at once */
    volatile LONG ring_stalled;    /* controller: the ring is stuck behind a live producer's slot -- use PROBE_IPC_LOG */
    volatile LONG log_ipc;         /* controller: 1 while it is the debugger and services PROBE_IPC_LOG */
    uint32_t controller_pid;       /* lets producers tell a dead controller from a busy one */
    /* Per probe, striped by thread: the low 48 bits count hits, the high 16 bits count
       callbacks running now. One atomic add does both, so a thread killed at ANY instant
       (process exit) leaves hits == logs + dropped + interrupted exactly. Non-zero in-flight
       after the target exited = callbacks cut off by the process dying. */
    probe_agent_stripe hit_stripes[PROBE_AGENT_MAX_PROBES][PROBE_AGENT_STRIPES];
    probe_agent_request requests[PROBE_AGENT_MAX_PROBES];
    probe_agent_log logs[PROBE_AGENT_LOG_CAP];
    volatile LONG int3_seq;
    volatile LONG int3_count;
    probe_agent_int3 int3[PROBE_AGENT_INT3_CAP];
};

constexpr LONG64 PROBE_AGENT_INFLIGHT_ONE = 1LL << 48;   /* one running callback in a hit_stripes cell */

inline uint64_t probe_agent_hits(const probe_agent_shared *sh, uint32_t index) {
    uint64_t n = 0;
    for (uint32_t i = 0; i < PROBE_AGENT_STRIPES; ++i)
        n += (uint64_t)sh->hit_stripes[index][i].value & ((1ULL << 48) - 1);
    return n;
}

inline uint64_t probe_agent_inflight(const probe_agent_shared *sh) {
    uint64_t n = 0;
    for (uint32_t p = 0; p < PROBE_AGENT_MAX_PROBES; ++p)
        for (uint32_t i = 0; i < PROBE_AGENT_STRIPES; ++i) n += (uint64_t)sh->hit_stripes[p][i].value >> 48;
    return n;
}

inline void probe_agent_mapping_name(DWORD pid, wchar_t (&name)[64]) {
    _snwprintf_s(name, _countof(name), _TRUNCATE, L"Local\\probe_api_%lu", pid);
}
/* Auto-reset event the controller signals to ask the agent's service thread for an
   install round. A persistent thread is used because a NEW thread cannot start while
   another thread holds the loader lock (e.g. one stopped at a LOAD_DLL event). */
inline void probe_agent_service_name(DWORD pid, wchar_t (&name)[64]) {
    _snwprintf_s(name, _countof(name), _TRUNCATE, L"Local\\probe_api_svc_%lu", pid);
}
