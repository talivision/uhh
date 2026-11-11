#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>   /* _countof */
#include <intrin.h>

constexpr uint32_t PROBE_AGENT_MAGIC = 0x50424131; // "PBA1"
constexpr uint32_t PROBE_AGENT_VERSION = 35;   /* 35: saved debug-register delivery repair; 34: explicit orphan event claims; 33: agent debug-delivery repair; 32: guard DR address ownership; 31: inline install failure stage; 30: reusable channel epoch and target mapping handle; 29: init receives a per-session mapping handle (layout unchanged); 28: init_returns (x86hunt); 27: ring record's header and text start on one cache line, log_head on a line of its own (perf5); 26: tblock retired on a line of its own, drain wake-up (drain_wait); 25: per-thread hit blocks (tblocks); 24: huntaudit early_init (on top of 23: runfix1 log carry + running count; 21: held_floor) */
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

enum probe_agent_install_failure : uint32_t {
    PROBE_INSTALL_NONE, PROBE_INSTALL_BUILD, PROBE_INSTALL_FREEZE,
    PROBE_INSTALL_SITE, PROBE_INSTALL_WRITE, PROBE_INSTALL_VERIFY, PROBE_INSTALL_CONTROLLER_GONE
};

struct probe_agent_request {
    uint64_t site;
    uint32_t flags;
    uint32_t config_len;
    char callback[PROBE_AGENT_EXPORT_CAP];
    unsigned char config[PROBE_AGENT_CONFIG_CAP];
    volatile LONG status;
    uint32_t install_failure;      /* published before terminal status */
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
   makes int3_seq odd while it rewrites the table; a reader retries (bounded) or skips.
   The table holds EVERY armed breakpoint: in a session with the inline channel the controller
   refuses to arm more than PROBE_AGENT_INT3_CAP (documented in probe_api.h). It was 1024 and
   silently truncated: past it an inline get_mem read 0xCC where breakpoint/hw read the
   program's byte (v18). Sorted by address (the agent binary-searches a read's range and
   masks every INT3 in it). 1 MiB of the section, touched only as far as it is used. */
constexpr uint32_t PROBE_AGENT_INT3_CAP = 65536;
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
/* Layout (v27): a slot is a whole number of cache lines (the ring starts on one) and every field a plain record uses -- seq, owner,
   the header and the text's start -- is on its first line; a typical ~90-byte line of text ends
   on the second. (The header used to sit after the 1 KB text: every record touched three lines on
   the producer's side and three again on the controller's, each a transfer between the two cores.) */
struct probe_agent_log {
    volatile LONG64 seq;
    volatile LONG owner;           /* tid of the producer that claimed the slot; 0 = free/unknown */
    uint32_t probe;
    uint32_t tid;
    uint32_t text_len;             /* text may contain NULs (%c of 0): this is its length */
    uint32_t carry;                /* 1: the FIRST record of a running callback -- it carries that hit's
                                      unaccounted unit (hit_stripes[probe][stripe of tid]); the controller
                                      retires the unit when it takes the record (v23, see hit_stripes) */
    uint32_t reserved;             /* v25: with carry, the producer's hit block + 1 (0: the stripes) */
    uint32_t frame_count;          /* 0 = plain log; else frames[] is a stack snapshot */
    uint32_t has_stack;
    char text[PROBE_AGENT_LOG_TEXT_CAP];
    uint64_t frames[32];           /* == PROBE_STACK_MAX_FRAMES */
    char pad[24];                  /* to a whole number of cache lines (no alignas: a producer builds a record
                                      on its stack, and an over-aligned local re-aligns the x86 frame) */
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
constexpr uint64_t PROBE_IPC_CONFIG_MAX = 0xFFFFFFFFu;   /* == every backend's config limit (probe_api.h) */
struct probe_ipc_request {
    uint32_t op, flags, origin_site;
    int32_t result;
    uint64_t address;
    uint64_t callback, callback_len;      /* export name (not NUL-terminated) */
    uint64_t symbol, symbol_len;          /* probe_add_symbol */
    uint64_t config, config_len;          /* probe_add_symbol_cfg */
};

/* Controller-death guard (ATTACH sessions with an agent, i.e. with inline probes: a breakpoint/
   hw-only session injects nothing -- owner decision 2026-11-07). A debugger killed while attached (TerminateProcess,
   crash) is detached by the kernel with its INT3s still in the code, its debug registers still
   armed and possibly threads it had suspended: the target would die at its next hit. The
   controller mirrors that state here after every debug event (the armed INT3s and their
   original bytes are the INT3 table, probe_agent_shared::int3, kept for every session with a
   channel); the agent owns a vectored handler that takes
   each such trap as ours -- restores the byte / clears the DR / ends the step -- and its service
   thread, woken when the controller process ends, cleans everything up: original bytes back,
   our DR slots and steps cleared on every thread, held threads resumed, inline hooks removed. */
constexpr uint32_t PROBE_AGENT_GUARD_TIDS = 256;
constexpr uint32_t PROBE_AGENT_GUARD_BLOCKS = 64;
constexpr uint32_t PROBE_AGENT_GUARD_DR_SITES = 256;
// Stable slots: payload, barrier, tid last; retire tid first. Never compact.
constexpr uint32_t PROBE_AGENT_ORPHAN_CLAIMS = 256;
enum : uint32_t {
    PROBE_ORPHAN_STEP = 1, PROBE_ORPHAN_EXECUTE = 2,
    PROBE_ORPHAN_SCRATCH = 3, PROBE_ORPHAN_WATCH = 4
};
struct probe_agent_orphan_claim {
    volatile LONG tid;
    uint32_t kind;
    uint64_t created, address, resume;
};
struct probe_agent_guard {
    volatile LONG64 controller_process; /* handle IN THE TARGET (SYNCHRONIZE) to the controller; the agent takes it (-> 0) */
    volatile LONG enabled;              /* tables are live: a session is attached (0 after a clean detach) */
    volatile LONG dr_mask;              /* DR slots the controller owns or has owned */
    volatile LONG step_count, held_count, block_count;
    uint32_t step_tids[PROBE_AGENT_GUARD_TIDS];        /* threads mid single-step (trap flag ours) */
    uint32_t held_tids[PROBE_AGENT_GUARD_TIDS];        /* threads the controller holds suspended, one entry
                                                          per suspension: install holds, hook-write freezes,
                                                          call_func/call_original deferrals, in-place windows */
    uint64_t blocks[PROBE_AGENT_GUARD_BLOCKS];         /* 64 KiB out-of-line step blocks */
    uint32_t held_floor[PROBE_AGENT_GUARD_TIDS];       /* per held_tids entry: PROBE_AGENT_HOLD_OURS (a hold
                                                          of ours: resume once), or a CONDITIONAL entry --
                                                          the thread's suspend count before a call that may
                                                          suspend it implicitly (x86 controller, GuardTouch):
                                                          resumed once only if its count is above that */
    probe_agent_orphan_claim claims[PROBE_AGENT_ORPHAN_CLAIMS];
    volatile LONG service_tid;                         /* the agent's service thread (no one suspends it): its
                                                          suspend count as read by NtQueryInformationThread is
                                                          the debug freeze alone (0 / 1), which that count
                                                          includes -- subtracted from a held_floor reading */
    volatile LONG dr_site_count;          /* published after addresses */
    uint64_t dr_sites[PROBE_AGENT_GUARD_DR_SITES]; /* addresses UHH actually armed */
};
constexpr uint32_t PROBE_AGENT_HOLD_OURS = 0xFFFFFFFFu;

// Controller publishes tid LAST while the debug event freezes the process. The owning
// thread's first VEH consumes it, even after controller death. No executable patch.
constexpr uint32_t PROBE_AGENT_DEBUG_DELIVERIES = 256;
struct probe_agent_debug_delivery {
    volatile LONG tid;
    uint32_t dr_mask;                 // slots owned by UHH in the original event
    uint64_t ip, clear_bits, set_bits;
    uint64_t dr_before[4], dr_after[4], dr7_before, dr7_after;
};
// Compare-and-restore only UHH's original slot images. A target-owned slot, or
// an image changed by another handler, is never overwritten. Dispatcher repair
// can use the latest live image; the first VEH uses the controller's snapshot.
inline void probe_agent_repair_delivery_drs(CONTEXT &c, const probe_agent_debug_delivery &d,
                                           const CONTEXT *live = nullptr) {
    for (int slot = 0; slot < 4; ++slot) {
        if (!(d.dr_mask & (1u << slot))) continue;
        auto &address = slot == 0 ? c.Dr0 : slot == 1 ? c.Dr1 : slot == 2 ? c.Dr2 : c.Dr3;
        const uint64_t mask = ((uint64_t)3 << (slot * 2)) | ((uint64_t)0xF << (16 + slot * 4));
        if (address != d.dr_before[slot] || ((c.Dr7 ^ d.dr7_before) & mask)) continue;
        const uint64_t after = live ? (slot == 0 ? live->Dr0 : slot == 1 ? live->Dr1 :
                                       slot == 2 ? live->Dr2 : live->Dr3) : d.dr_after[slot];
        switch (slot) {
        case 0: c.Dr0 = (decltype(c.Dr0))after; break;
        case 1: c.Dr1 = (decltype(c.Dr1))after; break;
        case 2: c.Dr2 = (decltype(c.Dr2))after; break;
        default: c.Dr3 = (decltype(c.Dr3))after; break;
        }
        c.Dr7 = (decltype(c.Dr7))((c.Dr7 & ~mask) | ((live ? live->Dr7 : d.dr7_after) & mask));
    }
}

/* Hit counting and in-flight tracking are striped over cache-line-separated counters
   (indexed by thread id: (tid >> 2) % PROBE_AGENT_STRIPES) so threads hitting the same probe
   do not contend on one line. Exact: the controller sums the stripes.
   value:   low 48 bits = hits; high 16 bits = UNACCOUNTED hits -- callbacks that have neither
            delivered a log nor returned. A hit adds 1 + one unit in ONE atomic add. The unit
            leaves exactly once: when the callback returns without having logged (the agent
            subtracts it), or, when it logs, with its FIRST record -- published with carry = 1
            (one store: the ring's seq), the controller subtracts it when it takes that record
            (ring or PROBE_IPC_LOG). So a thread killed at ANY instant (process exit) leaves
            hits == logs + dropped + unaccounted exactly: killed before its record is published,
            the unit stays (callbacks_interrupted); after, the record is delivered and the unit
            goes with it. (v20 dropped the unit only when the callback returned: a thread
            killed between publishing its log and returning was counted both as a log and as
            interrupted.)
   running: callbacks executing now (whether or not they logged): what an unhook / a detach
            drain waits for. Not used for accounting. */
constexpr uint32_t PROBE_AGENT_STRIPES = 16;
struct alignas(64) probe_agent_stripe { volatile LONG64 value; volatile LONG64 running; char pad[48]; };

/* Per-thread hit blocks (v25): the common path. A thread that hits inline probes owns one block
   and is its ONLY writer -- plain stores, no LOCKed instruction per hit (on x86 every 64-bit
   interlocked operation is a LOCK CMPXCHG8B loop; the shared stripes cost ~2x main's per-hit
   time there). The stripes above remain for threads without a block (more than
   PROBE_AGENT_TBLOCKS probe-hitting threads alive at once). In a block:
   hits[p]  every hit of probe p by the owner -- the FIRST store of a hit, so a thread killed at
            any later instant leaves its hit counted (and unaccounted, below);
   done     the owner's callbacks that ended WITHOUT a carried record: returned without logging,
            or their first record was dropped (one store, made when that happens);
   running  1 while the owner runs a callback (detach / unhook drains wait for 0);
   retired  written ONLY by the controller: carried first records it took (log_carry names
            the block, probe_agent_log::reserved = index + 1). On a cache line of its own (v26):
            beside `running` (two owner stores per hit) every carried record the controller took
            pulled the owner's hot line to the controller's core and back.
   probe    the probe whose callback the owner runs or last ran (diagnostics only: names the
            callback a thread was killed in -- probe_agent_cut_off). On the owner's line.
   Unaccounted hits of a block = sum(hits) - done - retired: a callback that has neither ended
   unlogged nor had its carried record taken -- exactly the stripes' high bits. A thread killed
   at any instant leaves hits == logs + dropped + unaccounted, as before. 64-bit fields are
   read and written whole (probe_agent_load64 / store64: one MOVQ on x86, never torn). */
constexpr uint32_t PROBE_AGENT_TBLOCKS = 256;
struct alignas(64) probe_agent_tblock {
    volatile LONG owner;           /* agent bookkeeping: the owner's tid (0 free) */
    volatile LONG running;
    volatile LONG64 done;
    volatile LONG probe;
    char pad[44];
    volatile LONG64 retired;
    char pad2[56];
    volatile LONG64 hits[PROBE_AGENT_MAX_PROBES];
};
/* Waking an idle drainer (v26). After a quiet spell the controller's drainer stops polling the
   ring and sleeps on an auto-reset event (probe_agent_drain_name): it sets `waiting`, looks at the
   ring once more, and waits. A producer that published a record and sees `waiting` takes it
   (exchange 1 -> 0: one wake-up per sleep, however many producers) and signals the event. Each
   side writes its flag with a LOCKed instruction before reading the other's (the producer's is the
   head CAS of its claim), so either the drainer sees the claimed record or the producer sees it
   waiting. `agent_ready`: the agent holds the event (else the drainer keeps polling). On a line of
   its own: producers read `waiting` with every record; it is written only around a sleep. */
struct alignas(64) probe_agent_drain_wait {
    volatile LONG waiting;
    volatile LONG agent_ready;
    char pad[56];
};
inline LONG64 probe_agent_load64(const volatile LONG64 *p) {
#if defined(_WIN64)
    return *p;
#else
    return __iso_volatile_load64((const volatile __int64 *)p);
#endif
}
inline void probe_agent_store64(volatile LONG64 *p, LONG64 v) {
#if defined(_WIN64)
    *p = v;
#else
    __iso_volatile_store64((volatile __int64 *)p, v);
#endif
}

/* The header's lines (v27). Producers CAS log_head with every record: it shares its line only with
   flags they read per record and that are written once or rarely. What the controller writes while
   draining (log_tail per pack, drain_beat every drainer loop) is on the next line: beside log_head
   every one of those writes took the line away from the producers between two claims. */
struct probe_agent_shared {
    uint32_t magic;
    uint32_t version;
    uint32_t request_count;
    volatile LONG session_epoch;  /* controller advances BEFORE reset; never zeroed during reuse */
    volatile LONG service_ready;   /* agent's persistent install thread is waiting on the svc event */
    volatile LONG xstate_mode;     /* bench/test knob: 0 = default (gated), 1 = none, 2 = full, 3 = as without OSXSAVE */
    uint32_t controller_pid;       /* lets producers tell a dead controller from a busy one */
    volatile LONG64 overrides;     /* set_reg calls that changed a register, inline side */
    uint64_t agent_mapping;        /* retained target handle: reuse the same view on ordinary reattach */
    alignas(64) volatile LONG64 log_head;   /* next position producers claim */
    volatile LONG controller_gone; /* set when the controller stops consuming (detach/close): log calls return at once */
    volatile LONG ring_stalled;    /* controller: the ring is stuck behind a live producer's slot -- use PROBE_IPC_LOG */
    volatile LONG log_ipc;         /* controller: 1 while it is the debugger and services PROBE_IPC_LOG */
    volatile LONG log_dropped;
    alignas(64) volatile LONG64 log_tail;   /* next position the controller consumes */
    volatile LONG64 drain_beat;    /* advanced by the controller's drainer every loop (its only writer): liveness */
    /* Per probe, striped by thread: hits + unaccounted units, and running callbacks (see
       probe_agent_stripe). Non-zero unaccounted after the target exited and the ring was
       drained = callbacks cut off by the process dying before their first log. */
    probe_agent_stripe hit_stripes[PROBE_AGENT_MAX_PROBES][PROBE_AGENT_STRIPES];
    probe_agent_request requests[PROBE_AGENT_MAX_PROBES];
    probe_agent_log logs[PROBE_AGENT_LOG_CAP];
    volatile LONG int3_seq;
    volatile LONG int3_count;
    probe_agent_int3 int3[PROBE_AGENT_INT3_CAP];
    probe_agent_guard guard;
    volatile LONG debug_delivery_ready; // first VEH installed (independent of attach guard)
    probe_agent_debug_delivery debug_delivery[PROBE_AGENT_DEBUG_DELIVERIES];
    /* Detach drain (v20). Logs are never dropped while a callback can still send one: after a
       detach the controller keeps delivering until no in-flight callback can still finish. It
       sets live_query and signals the service event; the agent's service thread answers in
       live_callbacks -- callbacks in flight on a thread that exists, is not suspended and is
       still inside that callback (its record's frame is on the stack, canary intact) -- and
       then bumps live_seq. A callback whose thread is dead, suspended (by the program) or left
       through a non-unwinding longjmp cannot finish now: it stays counted in flight. */
    volatile LONG live_query;
    volatile LONG live_seq;
    volatile LONG live_callbacks;
    /* Early init (v24): the controller runs probe_agent_init on the launched target's MAIN
       thread at the loader breakpoint (before TLS callbacks and static DllMains, ROADMAP A6).
       No new thread can start before process initialisation ends, so init must not wait for
       its service thread (it reports itself ready once it runs). */
    volatile LONG early_init;
    /* v28: probe_agent_init calls that RETURNED (any result). An init thread the target's end
       kills (ExitProcess / TerminateProcess while it runs) exits with the PROGRAM's exit code:
       without this count the controller read that as an init failure and abandoned the session
       (hunt-exit-terminate-inline: "probe_agent_init failed (code=0x7)", app_exit lost). */
    volatile LONG init_returns;
    probe_agent_tblock tblocks[PROBE_AGENT_TBLOCKS];   /* v25: per-thread hit accounting (see probe_agent_tblock) */
    probe_agent_drain_wait drain_wait;                 /* v26: wake an idle drainer (see probe_agent_drain_wait) */
};
static_assert(offsetof(probe_agent_shared, log_head) == 64 && offsetof(probe_agent_shared, log_tail) == 128,
              "examples/ctrlreview/ctrl_target.cpp (headcorrupt) writes these offsets");
static_assert(sizeof(probe_agent_log) % 64 == 0 && offsetof(probe_agent_shared, logs) % 64 == 0, "ring slots are line-aligned");

constexpr LONG64 PROBE_AGENT_INFLIGHT_ONE = 1LL << 48;   /* one unaccounted hit in a hit_stripes cell */

inline uint64_t probe_agent_hits(const probe_agent_shared *sh, uint32_t index) {
    uint64_t n = 0;
    for (uint32_t i = 0; i < PROBE_AGENT_STRIPES; ++i)
        n += (uint64_t)probe_agent_load64(&sh->hit_stripes[index][i].value) & ((1ULL << 48) - 1);
    for (uint32_t b = 0; b < PROBE_AGENT_TBLOCKS; ++b) n += (uint64_t)probe_agent_load64(&sh->tblocks[b].hits[index]);
    return n;
}
/* A block's unaccounted hits (never below zero: the block lives in memory the target can write). */
inline uint64_t probe_agent_tblock_unaccounted(const probe_agent_tblock &t) {
    uint64_t hits = 0;
    for (uint32_t p = 0; p < PROBE_AGENT_MAX_PROBES; ++p) hits += (uint64_t)probe_agent_load64(&t.hits[p]);
    const uint64_t out = (uint64_t)probe_agent_load64(&t.done) + (uint64_t)probe_agent_load64(&t.retired);
    return hits > out ? hits - out : 0;
}

/* Unaccounted hits (see probe_agent_stripe): callbacks without a delivered log that have not
   returned, plus first records published but not yet taken by the controller. After the
   final drain: callbacks_interrupted / the detach line's in_flight. */
inline uint64_t probe_agent_inflight(const probe_agent_shared *sh) {
    uint64_t n = 0;
    for (uint32_t p = 0; p < PROBE_AGENT_MAX_PROBES; ++p)
        for (uint32_t i = 0; i < PROBE_AGENT_STRIPES; ++i) n += (uint64_t)probe_agent_load64(&sh->hit_stripes[p][i].value) >> 48;
    for (uint32_t b = 0; b < PROBE_AGENT_TBLOCKS; ++b) n += probe_agent_tblock_unaccounted(sh->tblocks[b]);
    return n;
}
/* Unaccounted hits minus the first records sitting published in the ring (they carry their
   hit, delivered or not): callbacks that never published a log. Exact when the producers are
   stopped -- for a reader of the ring other than the controller (e.g. after the controller
   died); the controller's own counts come after its final drain, where both agree. */
inline uint64_t probe_agent_unlogged(const probe_agent_shared *sh) {
    uint64_t n = probe_agent_inflight(sh), carried = 0;
    const LONG64 tail = sh->log_tail;
    LONG64 head = sh->log_head;
    if ((uint64_t)head - (uint64_t)tail > PROBE_AGENT_LOG_CAP) head = (LONG64)((uint64_t)tail + PROBE_AGENT_LOG_CAP);
    for (LONG64 pos = tail; pos != head; pos = (LONG64)((uint64_t)pos + 1)) {
        const probe_agent_log &r = sh->logs[(uint64_t)pos % PROBE_AGENT_LOG_CAP];
        if (r.seq == (LONG64)((uint64_t)pos + 1) && r.carry == 1) ++carried;
    }
    return n > carried ? n - carried : 0;
}
/* After the target ended: the unaccounted hits (callbacks_interrupted) split into callbacks that
   were still RUNNING when their thread died -- cut off by the target's end (ExitProcess /
   TerminateProcess kill threads mid-callback) -- and the rest (`unexplained`: an unaccounted
   unit with no callback running behind it -- an accounting fault, never expected). each(probe,
   tid, n) is called per cut-off callback group (tid 0: a striped thread, unknown). */
template <class F> inline uint64_t probe_agent_cut_off(const probe_agent_shared *sh, uint64_t &unexplained, F each) {
    uint64_t cut = 0;
    unexplained = 0;
    for (uint32_t p = 0; p < PROBE_AGENT_MAX_PROBES; ++p)
        for (uint32_t i = 0; i < PROBE_AGENT_STRIPES; ++i) {
            const uint64_t un = (uint64_t)probe_agent_load64(&sh->hit_stripes[p][i].value) >> 48;
            const LONG64 r = probe_agent_load64(&sh->hit_stripes[p][i].running);
            const uint64_t c = r > 0 ? (un < (uint64_t)r ? un : (uint64_t)r) : 0;
            if (c) each(p, 0u, c);
            cut += c; unexplained += un - c;
        }
    for (uint32_t b = 0; b < PROBE_AGENT_TBLOCKS; ++b) {
        const probe_agent_tblock &t = sh->tblocks[b];
        const uint64_t un = probe_agent_tblock_unaccounted(t);
        const uint64_t c = un && t.running != 0 ? 1 : 0;   /* one callback at a time per thread */
        if (c) each((uint32_t)t.probe, (uint32_t)t.owner, c);
        cut += c; unexplained += un - c;
    }
    return cut;
}
/* Callbacks executing now (a dead thread's stays counted). */
inline uint64_t probe_agent_running(const probe_agent_shared *sh) {
    uint64_t n = 0;
    for (uint32_t p = 0; p < PROBE_AGENT_MAX_PROBES; ++p)
        for (uint32_t i = 0; i < PROBE_AGENT_STRIPES; ++i) n += (uint64_t)probe_agent_load64(&sh->hit_stripes[p][i].running);
    for (uint32_t b = 0; b < PROBE_AGENT_TBLOCKS; ++b) n += (uint64_t)(sh->tblocks[b].running != 0);
    return n;
}
/* The controller took a record with carry = 1: retire its hit's unaccounted unit. The record
   lives in memory the target can write: bounded, and never below zero (a CAS, so a bogus
   carry cannot borrow from the hit count). */
inline void probe_agent_retire_carry(probe_agent_shared *sh, const probe_agent_log &rec) {
    if (rec.carry != 1 || rec.probe >= PROBE_AGENT_MAX_PROBES) return;
    if (rec.reserved) {                         /* the owner's block (v25): the controller's own counter */
        if (rec.reserved > PROBE_AGENT_TBLOCKS) return;
        /* No bound check: it summed the block's hits, then read `done` -- while the owner kept
           counting (a hit = hits[p]++ ... done++ at its return), a sum that read hits[p] before
           one hit and `done` after it came out one short, read 0 with this record's unit still
           pending, and skipped the retire: one hit reported interrupted forever (CI 42325381514,
           gated-e2e-launch-fhw-oin-cin-rin: logs 646/646 delivered, interrupted=1). The sums
           clamp a block's unaccounted at zero, so a bogus carry cannot borrow anyway. */
        InterlockedIncrement64(&sh->tblocks[rec.reserved - 1].retired);
        return;
    }
    volatile LONG64 &cell = sh->hit_stripes[rec.probe][(rec.tid >> 2) & (PROBE_AGENT_STRIPES - 1)].value;
    for (LONG64 v = cell; ((uint64_t)v >> 48) != 0; v = cell)
        if (InterlockedCompareExchange64(&cell, v - PROBE_AGENT_INFLIGHT_ONE, v) == v) return;
}

/* The stack a thread needs left when a CALLBACK overflows its stack, so the overflow can be
   dispatched to the guard that abandons the callback: the exception frame holds a CONTEXT with
   the full extended state of every XCR0 feature -- with AMX tiles (Xeon 6973P-C CI runners,
   XCR0 0x600e7) an 11 KB XSAVE area, more than Windows leaves by default, and the process died
   (0xC00000FD / 0xC0000005) instead (transparency TR9 `ovf`, every row, on those runners only).
   CONTEXT + the XCR0 XSAVE size + 16 KB for the dispatcher and the vectored handlers, in pages.
   Callbacks run under at least this stack guarantee (controller: SetThreadStackGuarantee on
   the callback thread; inline agent: for the callback only, see agent.cpp run_callback). */
inline unsigned long probe_callback_stack_guarantee() {
    int r[4] = {};
    __cpuid(r, 1);
    unsigned long xsave = 0;
    if (r[2] & (1 << 27)) { __cpuidex(r, 0xD, 0); xsave = (unsigned long)r[1]; }   /* OSXSAVE: XCR0's area */
    const unsigned long need = (unsigned long)sizeof(CONTEXT) + xsave + 64 + 16384;
    return (need + 4095) & ~4095ul;
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
inline void probe_agent_drain_name(DWORD pid, wchar_t (&name)[64]) {
    _snwprintf_s(name, _countof(name), _TRUNCATE, L"Local\\probe_api_drain_%lu", pid);
}
