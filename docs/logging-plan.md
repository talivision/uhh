# Logging subsystem design (`PROBE_LOG`)

Status: design, not yet implemented. Agreed against `api-sketch.md` (GOSPEL),
`plan-v2.md` (§Logging), and `design-review-codex.md` point #8. This is the
concrete, implementable spec for order-of-work item 3 ("Logging queues +
`PROBE_LOG`") in `plan-v2.md`.

It supersedes nothing in the public API: `PROBE_LOG(c, fmt, ...)` and the
one-context callback stay exactly as `api-sketch.md` shows them. This document
specifies what happens *behind* that macro.

---

## 0. The hard constraint that shapes everything

`PROBE_LOG` runs **inside the callback**. For `PROBE_INLINE` probes the callback
executes in the **target process (agent DLL)**, concurrently on arbitrarily many
threads, at an arbitrary instruction boundary — the thread may hold the target's
heap lock, the loader lock, a CRT lock, or be mid-syscall. Therefore the hot path
must, with no exceptions:

- **not allocate** (no `malloc`/`new`/`HeapAlloc`, no implicit-TLS first-touch
  allocation, no queue-grow-on-full);
- **take no uncontrolled lock** (nothing another target thread can hold across an
  unbounded region; a single bounded CAS is fine, a `CRITICAL_SECTION` is not);
- **make no loader-sensitive call** (`LoadLibrary`, `GetModuleHandle`, anything
  that touches the loader lock, `GetProcAddress`, dbghelp, `QueryFullProcess*`);
- **not block arbitrarily** (default policy never waits on the controller).

Everything below is a consequence of this. The expensive, unsafe work —
formatting, symbol/name resolution, I/O — is moved to the **reader** (the
controller), off the target thread, exactly as Quill moves it to a backend
thread and defmt moves it to a host decoder.

---

## 1. Model in one paragraph

`PROBE_LOG` does **deferred formatting**. At the call site it captures a *format
identity* (a stable dictionary id, never a raw format pointer), the *raw typed
argument bytes* (types known at compile time, so no type tags on the wire), a
*timestamp*, the *tid*, and a *per-thread sequence number*, and appends that
fixed-schema record to **its thread's own SPSC ring**. Rings come from a
**preallocated pool** living in a **shared-memory section** mapped into both the
target (producer) and the controller (consumer). The controller's **reader
thread** drains the rings, merges them into timestamp order, looks each record's
id up in a **dictionary shipped from the producer at attach**, formats the text
(or emits JSON), and resolves `handle -> pid -> name` reader-side. The *same*
`PROBE_LOG` source compiles into both the agent DLL and the controller; for
external/breakpoint probes the producer and consumer are simply the same process,
but the record layout, dictionary mechanism, and reader loop are identical.

---

## 2. What informs this design (Quill, defmt) and where we diverge

**Quill** (ultra-low-latency C++ logging): per-thread lock-free **SPSC** queue;
the `LOG_*` hot path writes a pointer to static call-site metadata plus
binary-encoded argument copies and returns; **one background thread** drains all
queues into a transit buffer, sorts by timestamp with a configurable grace
window, then formats and writes. Default clock is **rdtsc** with lazy
calibration; system clock is the alternative.

**defmt** (Rust, embedded): **deferred formatting** done on a *second machine*.
Format strings are **interned at compile time** into a table (a `.defmt` ELF
section); the device sends only an **index + raw args**; the host `defmt-decoder`
parses the ELF to rebuild the table and decode. Types are known from the site, so
they are not sent. You need the *exact* matching ELF or you decode garbage.

We adopt from Quill: per-thread SPSC rings, reader-side ("background")
formatting, the timestamp merge with a grace/low-watermark window. We adopt from
defmt: interning the format + types at compile time and sending only an id and
the raw args; types never travel on the wire.

We **diverge** on four points that Codex #8 flags, each forced by §0 or by
cross-process operation:

1. **Consumer is in another process.** Quill's backend thread shares the
   producer's address space; ours does not. So the transport is a mapped section
   and **nothing stored in it may be a pointer** — only offsets and indices,
   because the section maps at different base addresses in the two processes
   (same discipline that bans sending the format pointer).
2. **No pointer-as-identity.** Quill pushes a pointer to static metadata; that is
   invalid across two builds and two processes (a format string's address in the
   agent DLL is meaningless to the controller, and ASLR moves it anyway). We use
   defmt-style **content-hashed dictionary ids**, with the dictionary shipped
   in-band at attach rather than recovered from a binary.
3. **No grow-on-full.** Quill allocates a fresh, larger queue when one fills.
   That is a heap allocation on the hot path — forbidden here (§0). We use a
   **fixed preallocated pool** and an explicit **full-queue policy**
   (count-and-drop by default; bounded-block opt-in).
4. **Stricter producer contract.** Quill's producer is ordinary user code; ours
   runs at arbitrary target state, so the hot path is additionally barred from
   the loader lock, from arbitrary blocking, and from implicit-TLS first-touch
   allocation (§6).

We also **avoid defmt's ELF dependency**: requiring the reader to parse the
agent DLL (stripped, ASLR'd, possibly a different build than the controller)
would reproduce defmt's "need the exact ELF" fragility across *two* binaries.
Instead the agent **serializes its own dictionary into the shared section** at
attach; the content hash provides the version check that defmt gets from ELF
identity.

---

## 3. The restricted typed schema (format identity, types, `%s`)

General C varargs cannot be deferred safely (Codex #8): the format pointer
differs per build, raw 8-byte slots lose signedness / float / width / `%ls` /
Windows 32-bit `long`, `%s` may fault, and hash ids can collide. We therefore
define a **restricted** schema.

### 3.1 Compile-time argument type tags (from the macro)

Each argument's type is captured at compile time with C11 `_Generic`, so the
*reader* knows how to read every slot without any runtime type byte:

```c
enum probe_argt {
    PROBE_T_I32 = 1, PROBE_T_U32,     /* int / unsigned            -> 4 bytes */
    PROBE_T_I64,     PROBE_T_U64,     /* long long / ull           -> 8 bytes */
    PROBE_T_LONG,    PROBE_T_ULONG,   /* Windows 'long' is 32-bit  -> 4 bytes, tagged distinctly */
    PROBE_T_PTR,                      /* void*                     -> 8 bytes (hex) */
    PROBE_T_F64,                      /* double (float promotes)   -> 8 bytes IEEE */
    PROBE_T_STR,                      /* char*  -> bounded byte copy (see 3.3) */
    PROBE_T_WSTR,                     /* wchar_t* / %ls -> bounded wide copy      */
    PROBE_T_CHAR                      /* char                      -> 1 byte      */
};

#define PROBE_ARGTAG(x) _Generic((x),                                   \
    int: PROBE_T_I32,            unsigned int: PROBE_T_U32,             \
    long: PROBE_T_LONG,          unsigned long: PROBE_T_ULONG,         \
    long long: PROBE_T_I64,      unsigned long long: PROBE_T_U64,      \
    double: PROBE_T_F64,         float: PROBE_T_F64,                   \
    char: PROBE_T_CHAR,                                                \
    char*: PROBE_T_STR,          const char*: PROBE_T_STR,            \
    wchar_t*: PROBE_T_WSTR,      const wchar_t*: PROBE_T_WSTR,        \
    void*: PROBE_T_PTR,          const void*: PROBE_T_PTR,            \
    default: PROBE_T_PTR)
```

Key fixes this encodes:

- **float/double:** captured *by value* and stored as 8 IEEE bytes. We never
  re-read a float through a varargs slot, so the classic "float in an integer
  register" bug cannot occur.
- **Windows 32-bit `long`:** tagged `PROBE_T_LONG`/`ULONG` distinctly from
  `int`/`long long`, so width is explicit regardless of ABI.
- **`%ls`/wide strings:** a first-class `PROBE_T_WSTR`.
- **No runtime `*` width/precision.** The restricted grammar (3.4) forbids `*`;
  a width is a literal in the format text and belongs to the dictionary, not the
  record.

The tag array is a compile-time constant per site. It is stored **in the
dictionary entry**, not in every record (defmt's trick): the wire record carries
only raw bytes laid out per the site's tag sequence.

### 3.2 Stable format identity: a shipped dictionary id, not a pointer

Each `PROBE_LOG` site gets a `probe_log_site` descriptor placed in a dedicated
section of whichever binary compiled it:

```c
typedef struct probe_log_site {
    uint64_t    fmt_hash;        /* constexpr FNV-1a over file|line|fmt|argsig  */
    const char *fmt;             /* literal; valid ONLY in this build's memory   */
    const uint8_t *arg_types;    /* -> compile-time tag array (this build only)  */
    const char *file;
    uint32_t    line;
    uint8_t     arg_count;
    uint8_t     grammar_ok;      /* set by the one-time validator (3.4)          */
    uint32_t    dict_id;         /* dense id assigned at module init; 0 = unset  */
} probe_log_site;
```

Two distinct identities, deliberately separated:

- **`fmt_hash`** — the *content* identity (defmt-style interning by content, not
  by address). Computed at compile time from `file|line|fmt|argsig`. Stable
  across builds and processes because it is derived from source text, never from
  an address.
- **`dict_id`** — a small dense **transport index** assigned at module init by
  walking the site section in order. Compact (32-bit) so records stay small.

The record on the wire carries **`dict_id`** only. It is resolved through a
**dictionary shipped from the producer**, so it is never a raw pointer:

- The **agent** serializes its dictionary (for every site: `dict_id`,
  `fmt_hash`, the format-string *bytes*, `arg_types`, `file`, `line`) into the
  shared section's dictionary region at attach. The `const char *fmt` pointer is
  **dereferenced in-process to copy its bytes**; the pointer itself never
  crosses.
- The **reader** decodes agent-produced records against *that* shipped
  dictionary. For external/controller-produced records it uses the controller's
  own in-process dictionary.

**Collision handling:** at module init the registrar hashes all sites; if two
sites share a `fmt_hash` but differ in `(file,line,fmt,argsig)` it is a genuine
collision — init aborts with a diagnostic (and, in debug, salts the hash with a
per-TU counter until unique). 64-bit FNV over small distinct keys makes this
effectively never fire, but we check rather than assume.

**Versioning:** the shared-section header (4.1) carries `abi_version`,
`schema_version`, and the agent's `build_id`. The reader refuses a mismatched
`abi_version`/`schema_version` outright. Per record it may cross-check
`dictionary[dict_id].fmt_hash` against the hash it expects for that id; a
mismatch poisons that id (render raw, flag it) instead of printing garbage.
This is the in-band equivalent of defmt's "exact ELF required," without needing
the ELF.

### 3.3 `%s` handled specially: bounded, fault-safe, copied at log time

A `%s`/`%ls` pointer is never stored and formatted later — the bytes are copied
**at log time**, bounded, and fault-tolerant, because the memory may be freed or
mutated before the reader runs, and may fault on read:

- **Bound:** copy at most `PROBE_STR_MAX` bytes (default 256), stop at NUL,
  record the actual copied length. Over-length sets a `TRUNC` flag.
- **Fault-safe:** the copy is wrapped so an access violation is caught and turns
  into an empty value with a `STRFAULT` flag, never a crash in the target.
- **Domain-correct source — this is why the *same source* works in both
  domains.** The pointer's meaning differs:
  - **Inline (agent):** the pointer addresses the target's own address space
    (= the agent's). Copy locally under SEH `__try/__except` (no allocation).
  - **External (controller):** the pointer addresses the *target* process. A
    local copy would read the wrong process. The controller build's capture
    helper instead copies via `probe_read(c, ptr, ...)` (`ReadProcessMemory`),
    reporting short transfers.

  The macro emits the same thing in both builds (the pointer + the tag); the
  **per-domain `probe_log_emit` implementation** (6.3) does the right copy. The
  callback author writes one `PROBE_LOG`; the runtime closes the gap.

### 3.4 Restricted grammar, validated once

Allowed conversions: `%d %i %u %x %X %p %s %ls %c %f %g %%`, plus literal
flags/width/precision in the text. **Forbidden:** `%n` (write primitive), `*`
(runtime width/precision), and `%@`/non-standard. At module init, a one-time
validator parses each site's format and checks the conversion count and kinds
against `arg_types`; on mismatch it clears `grammar_ok` and the reader renders
that site as `fmt` + raw hex args with a `BADFMT` flag. The hot path never
parses the format.

---

## 4. Shared-memory transport (the mapped section)

### 4.1 Section creation and layout

The controller creates the section (`CreateFileMapping(INVALID_HANDLE_VALUE,
PAGE_READWRITE, ...)`, page-file backed, unnamed). For inline probes the handle
is **duplicated into the target** at attach and the agent `MapViewOfFile`s it
once, outside any callback. For external probes the controller maps it into
itself; producer and consumer are the same process but use the identical layout.

```
offset 0  +--------------------------------------------------------------+
          | probe_shm_header                                              |
          +--------------------------------------------------------------+
          | dictionary region  (serialized sites + packed fmt/type bytes) |
          +--------------------------------------------------------------+
          | slot pool control  (lock-free freelist of ring indices)      |
          +--------------------------------------------------------------+
          | ring[0]   : probe_ring_hdr + byte buffer[ring_bytes]          |
          | ring[1]   : probe_ring_hdr + byte buffer[ring_bytes]          |
          | ...                                                           |
          | ring[P-1] : probe_ring_hdr + byte buffer[ring_bytes]          |
          +--------------------------------------------------------------+
```

```c
typedef struct probe_shm_header {
    uint32_t magic;            /* 'PLOG'                                    */
    uint16_t abi_version;      /* bump on struct change; reader rejects mismatch */
    uint16_t schema_version;   /* record/dictionary schema                  */
    uint64_t build_id;         /* agent build hash; must match dictionary   */
    uint32_t clock_mode;       /* 0 = QPC, 1 = raw TSC                       */
    uint64_t qpc_freq;         /* QueryPerformanceFrequency, for the reader  */
    uint32_t pool_count;       /* P: number of preallocated rings            */
    uint32_t ring_bytes;       /* bytes per ring buffer (power of two)        */
    uint64_t dict_off, dict_bytes;
    uint64_t pool_off, rings_off, ring_stride;
    uint32_t str_max;          /* PROBE_STR_MAX                              */
    uint32_t state;            /* RUNNING / DRAINING / CLOSED               */
    /* global accounting for conditions that have no ring to charge to:     */
    uint64_t drop_no_slot;     /* threads that could not claim a pool slot   */
    uint64_t records_no_slot;  /* records those threads tried to emit        */
    /* rdtsc calibration (clock_mode==1): paired samples written by agent    */
    uint64_t calib_tsc, calib_qpc;
} probe_shm_header;
```

**No pointers anywhere in the section** — only offsets (`*_off`) and indices.
The section maps at different base addresses in the two processes; a stored
pointer would be wrong in one of them. (Same reason the format pointer never
crosses, §3.2.)

### 4.2 Per-thread SPSC ring

Each pool entry is one SPSC byte-ring. Single producer = the one target thread
that owns the slot; single consumer = the controller reader thread.

```c
typedef struct probe_ring_hdr {
    /* producer writes head, reads tail; consumer writes tail, reads head.   */
    volatile uint64_t head;    /* total bytes ever written  (release-stored)  */
    volatile uint64_t tail;    /* total bytes ever read      (release-stored)  */
    volatile uint32_t state;   /* FREE / CLAIMED / RETIRING                   */
    uint32_t generation;       /* bumped on free; distinguishes TID reuse     */
    uint32_t owner_tid;        /* OS tid currently owning the slot             */
    uint64_t dropped;          /* records dropped on this ring (full-queue)    */
    /* byte buffer[ring_bytes] follows, indexed by head/tail mod ring_bytes   */
} probe_ring_hdr;
```

- `head`/`tail` are **monotonic 64-bit byte counters** (indexed `mod
  ring_bytes`, which is a power of two). Monotonic counters avoid ABA and avoid
  wasting a slot to distinguish full from empty: `used = head - tail`,
  `free = ring_bytes - used`.
- **Memory ordering:** producer writes the record bytes, then `release`-stores
  the new `head`. Consumer `acquire`-loads `head`, reads up to it, then
  `release`-stores `tail`. On x86/x64 these are plain loads/stores with a
  compiler fence, but we mark them `std::atomic` with explicit ordering so the
  intent is correct and portable to the x86 target too. Works unchanged across
  the process boundary because the section is coherent shared memory.
- **Variable-length records, no straddling:** records vary in size (because of
  `%s`). A record is never split across the wrap point. If the bytes to the end
  of the buffer are too few for the next record, the producer writes a one-byte
  `WRAP` filler consuming the remainder and starts the record at offset 0. The
  consumer skips `WRAP` fillers.

### 4.3 How a record crosses, by domain

- **Inline (producer in target, consumer in controller):** the producer writes
  straight into the ring in the shared section; the reader reads it from the same
  physical pages mapped into the controller. No copy, no IPC syscall per record —
  the record "crosses" simply by being written to shared pages. Publication is
  the `release`-store of `head`.
- **External / breakpoint (callback already in the controller):** identical code
  path; the section is mapped only into the controller. The record is written and
  consumed in one process. Using the same path (rather than a special in-process
  buffer) keeps one record layout, one dictionary mechanism, and one reader loop.

This is the concrete answer to "the same `PROBE_LOG` source must work in both":
the *macro* and the *record layout* are identical; only (a) where the section is
mapped and (b) the `%s` capture helper (local vs `probe_read`) differ, and both
differences live in the per-domain `probe_log_emit`, not in user code.

---

## 5. Preallocated pool: assignment, exhaustion, exit/reuse, retirement

- **Preallocation:** at attach the pool of `P` rings (default 64, configurable
  via `c->config`-level session settings) is carved out of the section. No ring
  is allocated when a new thread first logs — the thread is *assigned* an
  existing ring.
- **Assignment (lock-free, one CAS):** the pool control block is an array-based
  Treiber stack of free ring indices with a tagged head (index + ABA tag in one
  64-bit CAS). First `PROBE_LOG` on a thread pops a free index, stores it in the
  thread's TLS slot (6.2), sets `owner_tid`, `state=CLAIMED`. One CAS, no lock,
  no allocation.
- **Pool exhaustion:** if the stack is empty, the thread **does not block and
  does not allocate**. It increments `header.drop_no_slot` once (atomic) and
  thereafter `header.records_no_slot` per attempted record, then returns. The
  reader reports "N threads exceeded the ring pool, M records dropped." Raising
  `P` is the remedy; we never silently stall a target thread for a ring.
- **Thread exit / TID reuse:** the agent is a DLL and receives
  `DLL_THREAD_DETACH`. In it (minimal work only — one atomic store, no
  allocation, no further loader calls, which is safe under loader lock) the
  owner marks its ring `state=RETIRING`. The producer side is finished.
- **Queue retirement (consumer frees):** the **reader** is what returns a ring
  to the pool, never the producer. When the reader sees `state==RETIRING` *and*
  `head==tail` (fully drained), it bumps `generation`, sets `state=FREE`, and
  pushes the index back on the free stack. Because every record carries
  `(ring index implicit, generation, tid)` and the generation changes on reuse,
  the reader never conflates two thread lifetimes that reused the same ring —
  this is the queue-level analogue of the handle-reuse problem solved by
  timestamped intervals in `plan-v2.md`.
- **Abrupt exit (no `DLL_THREAD_DETACH`, e.g. `TerminateThread`):** the ring
  stays `CLAIMED` with a stale `owner_tid`. A reaper pass in the reader reclaims
  a `CLAIMED` ring whose `owner_tid` is no longer a live thread *and* which has
  been idle (`head` unchanged) beyond a grace period. Documented as best-effort.

---

## 6. The hot path: macro, TLS, emit

### 6.1 Macro expansion sketch

```c
#define PROBE_LOG(c, fmt, ...)                                                 \
  do {                                                                         \
    /* one static site descriptor per call site, in a dedicated section */     \
    static const uint8_t _tags[] = { PROBE_MAP_TAGS(__VA_ARGS__) }; /*_Generic*/\
    PROBE_SITE_SECTION static probe_log_site _site = {                         \
        .fmt_hash  = PROBE_FMT_HASH(__FILE__, __LINE__, fmt), /* constexpr */  \
        .fmt       = (fmt),                                                    \
        .arg_types = _tags,                                                    \
        .file = __FILE__, .line = __LINE__,                                    \
        .arg_count = PROBE_NARG(__VA_ARGS__), .dict_id = 0 };                  \
    /* pack each arg into a stack array of {tag, 8-byte value-or-ptr} */       \
    probe_arg_slot _slots[] = { PROBE_PACK(__VA_ARGS__) }; /* compound literal */\
    probe_log_emit(c, &_site, _slots, PROBE_NARG(__VA_ARGS__));                \
  } while (0)
```

- `_site` and `_tags` are `static const` — assembled once by the compiler, zero
  hot-path cost; `dict_id` is filled lazily on first emit (6.3).
- `_slots` is a **compound literal on the stack** — no heap. For `PROBE_T_STR`
  the slot holds the `char*`; `probe_log_emit` performs the bounded fault-safe
  copy (3.3). All other tags hold the value widened to 8 bytes (the double is
  bit-copied, not converted).
- `PROBE_SITE_SECTION` is `__declspec(allocate("plog$m"))` plus
  `#pragma section("plog$m", read, write)` (MSVC); sites land contiguously so
  the registrar can walk them.

### 6.2 TLS without allocation

Implicit TLS (`__declspec(thread)`) in a `LoadLibrary`-loaded DLL can **allocate
the per-thread TLS block on first touch** — forbidden in callback context.
Instead the agent calls `TlsAlloc()` **once at attach** (asserting the returned
index is < 64 so it lives in the TEB's inline `TlsSlots` array and never triggers
a TLS-expansion allocation). In the hot path:

```c
uintptr_t v = (uintptr_t)TlsGetValue(g_tls_slot);   /* TEB array read, no lock */
if (!v) { v = claim_ring_or_markdrop(); TlsSetValue(g_tls_slot, (void*)v); }
uint32_t ring_index = (uint32_t)(v >> 1) - 1;        /* 0 reserved for "unset" */
```

`TlsGetValue`/`TlsSetValue` are indexed TEB reads/writes — no loader lock, no
allocation. A second bit in `v` is the **reentrancy guard**: `probe_log_emit`
sets it on entry and clears it on exit; a `PROBE_LOG` reached recursively (the
logger's own code crossing an instrumented site) sees the bit and drops to a
counter rather than recursing.

### 6.3 `probe_log_emit` (per-domain) pseudocode

```
probe_log_emit(c, site, slots, n):
    if header.state != RUNNING: return            # detached/draining: no-op cheaply
    if reentrancy bit set: bump reentrant_drop; return
    set reentrancy bit
    ring = TLS ring, or claim from pool            # §5; on exhaustion: count + return
    if site->dict_id == 0: register_site_once(site)  # one CAS; assign dense id + validate grammar
    ts  = (clock_mode==QPC) ? QueryPerformanceCounter() : __rdtsc()
    seq = ++ring.local_seq                          # plain increment: single producer
    # measure size: fixed header + per-tag widths + bounded %s/%ls copies
    need = sizeof(probe_log_record) + packed_size(slots, n)   # strings capped at str_max
    if free(ring) < need + maybe_wrap:
        if policy == DROP:  ring.dropped++; clear reentrancy; return
        if policy == BLOCK: spin/backoff until free or timeout; on timeout ring.dropped++, return
    off = head mod ring_bytes
    if wrap needed: write WRAP filler to end; off = 0
    write probe_log_record{ ts, seq, dict_id, tid, arg_bytes, arg_count, flags }
    for each slot: copy value by its tag;
        STR/WSTR -> bounded fault-safe copy (local SEH in agent; probe_read in controller),
                    set TRUNC/STRFAULT flags as needed
    release-store head += need                       # publishes the record
    clear reentrancy bit
```

The agent build and controller build link **different** `probe_log_emit` objects
that differ only in the `%s` copy and in holding a section mapped at a different
base. Everything else — layout, ordering, policy — is shared code.

### 6.4 Clock choice and the merge key

- **Default: QPC.** `QueryPerformanceCounter` reads `KUSER_SHARED_DATA` in user
  mode (no syscall, no lock, no loader) and is **coherent machine-wide across
  processes**. That last property is decisive: an agent-produced record and a
  controller-produced record are directly comparable on one timeline, so the
  reader can merge them without conversion. QPC is also VM-safe — relevant, since
  the validation target is a Proxmox VM where raw TSC can be trapped or skewed.
- **Opt-in: raw TSC (`rdtsc`).** ~Tens of cycles vs QPC's ~20-30ns, for
  bare-metal perf runs. Requires invariant TSC (CPUID check at attach) and
  calibration: the agent writes `(calib_tsc, calib_qpc)` pairs into the header
  periodically; the reader converts TSC to the QPC timeline before merging. This
  mirrors Quill's rdtsc + lazy-calibration default; we make QPC the default
  instead because our consumer is cross-process and VM-hosted.
- **Per-thread sequence** (`seq`) gives exact intra-thread order and makes same
  thread, same-tick records deterministic.
- **Merge tie-break:** order by `(timestamp, tid, seq)`. Records from *different*
  threads at an identical tick have no true order; `(tid, seq)` makes the output
  deterministic and stable, and we document it as arbitrary-but-stable.

---

## 7. Full-queue policy, and why lossless is not the default

Selectable per session (and overridable per probe):

- **`DROP` (count-and-drop) — DEFAULT.** Ring full -> `ring.dropped++`, return.
  Never touches the controller, never waits.
- **`BLOCK` (lossless).** Spin/backoff until space; with an optional timeout,
  after which it falls back to counting a drop.

**Lossless must not be the default for arbitrary inline sites** because the
producer is a *target thread at an arbitrary point*. Blocking it waits on the
**controller, in another process**, to drain the ring. If the controller is
merely slow, descheduled, or itself stopped at a breakpoint in its own event
loop, the wait is unbounded. Worse, the blocked target thread may hold the
target's **heap lock or loader lock**; freezing it there can **deadlock the whole
target** — every other target thread that needs that lock stalls behind an
instrumentation detail. So lossless is opt-in, bounded by a timeout, and intended
only for low-rate sites the user knows are safe (e.g. a once-per-call
configuration probe), never for a millions-of-hits inline read path.

Drops are first-class: per-ring `dropped`, plus `drop_no_slot`/`records_no_slot`
for pool exhaustion and a `reentrant_drop` counter. The reader surfaces all of
them, preserving the "explicit drop accounting" that `plan-v2.md` and the review
require. These map onto the existing `probe_stats.dropped` field.

---

## 8. Record layout (wire struct)

```c
/* Fixed 32-byte header; packed typed args follow inline, total = arg_bytes.   */
typedef struct probe_log_record {
    uint64_t timestamp;    /* QPC ticks, or raw TSC if header.clock_mode==1     */
    uint64_t sequence;     /* per-ring, single-producer monotonic              */
    uint32_t dict_id;      /* -> dictionary; NOT a pointer                      */
    uint32_t tid;          /* producer OS thread id                            */
    uint16_t arg_bytes;    /* length of the packed arg payload that follows     */
    uint8_t  arg_count;
    uint8_t  flags;        /* bit0 TRUNC, bit1 STRFAULT, bit2 BADFMT, bit3 WRAP */
    /* payload: args laid out per dictionary[dict_id].arg_types:
         fixed-width tags -> their width (4 or 8 bytes, or 1 for CHAR)
         STR/WSTR         -> uint16 len followed by len bytes (already copied)  */
} probe_log_record;
```

No type tags in the record: types come from the dictionary (defmt-style). The
payload is the raw captured bytes only. A typical read-probe line (`"read pid=%u
(%s) handle=%#llx size=%llu"`) is header (32) + `u32` + (`u16` len + ~10 string
bytes) + `u64` + `u64` ~= 64 bytes.

---

## 9. Reader (controller) decode loop

Runs on a dedicated controller thread (the Quill "backend thread" role), off the
target thread.

```
reader_run():
    load + verify dictionary from section (abi/schema/build_id); build id->site table
    heap = min-heap keyed (timestamp, tid, seq)           # reorder buffer
    loop:
        # 1. pull newly published records from every live/retiring ring
        for ring in pool where state in {CLAIMED, RETIRING}:
            while ring has a published record not yet pulled:
                skip WRAP fillers
                copy record out (bounded), push to heap
                advance ring.tail (release-store)         # frees ring space
        # 2. low-watermark: smallest timestamp that could still arrive
        watermark = min over live rings of (last-pulled ts)   # Quill's grace idea
        # 3. emit everything safely ordered
        while heap not empty and heap.top.timestamp < watermark:
            rec  = heap.pop()
            site = dict[rec.dict_id]
            if site.fmt_hash mismatch or !grammar_ok:
                emit raw(rec); continue                   # poisoned id / bad fmt
            render(rec, site)                             # text and/or JSON (10)
        # 4. retire fully-drained rings
        for ring in pool where state==RETIRING and head==tail:
            reclaim(ring)                                 # bump generation, free (§5)
        if header.state==DRAINING and all rings empty: flush heap; break
        if idle: backoff
```

The low-watermark (step 2) is why a record is **not** emitted the instant it is
read: a smaller-timestamp record may still be sitting unread in a ring the loop
hasn't reached. Only records older than the watermark are safe to emit in order.
On `DRAINING` the watermark goes to infinity and the heap flushes. This is
Quill's timestamp-sort-with-grace-window, adapted to a fixed pool of
cross-process rings.

---

## 10. Reader output: text, JSON, and handle/pid/name resolution

- **Text:** feed `site.fmt` and the decoded typed args to a restricted-grammar
  formatter (our own, or `{fmt}`), producing the exact line the author wrote.
- **JSON / structured:** emit
  `{"ts":..., "tid":..., "seq":..., "site":"file:line", "fmt":"...",
    "args":[typed values], "text":"<rendered>", "flags":[...]}`.
  Because the format uses the `key=%fmt` idiom throughout the gospel examples
  (`read pid=%u (%s) handle=%#llx size=%llu`), the reader also parses leading
  `key=` tokens and exposes named fields (`pid`, `handle`, `size`) alongside the
  positional args — structured output without a separate schema language.

- **`handle -> pid -> name` resolution (reader-side only).** The hot path logs
  the **raw handle** (cheap; `api-sketch.md` and `plan-v2.md`). The reader owns
  resolution, because name lookup is a syscall and must never run in callback
  context:
  - It consumes the `NtOpenProcess`-return and `NtClose` records (carried on
    this same log path) to build the **timestamped `handle -> pid` interval map**
    from `plan-v2.md`, so a read logged at time *t* resolves to the identity the
    handle held *at t*, surviving close+reuse.
  - `pid -> name` via `QueryFullProcessImageName`, **cached** per pid (the
    pointer-array `name_by_pid` idea from `api-sketch.md`, but reader-side).
  - The gospel `log_read` example resolves inline against the agent-local flat
    `pid_by_handle` array and logs the name directly; we support that too (the
    `%s` name is just a bounded string arg). Where both are available we
    recommend logging the raw handle and resolving in the reader, per the Codex
    inconsistency note (d): interval replay is the only version that is
    historically correct across handle reuse.

---

## 11. Relationship to the existing fixed buffer

`include/probe.h` has a fixed `probe_record records[8192]` in `probe_stats`, with
`record_digest`/`dump_records` in `win_common.hpp` for deterministic tests. That
stays as the **regression-fixture** path: it is the simple, single-stream,
test-reproducible digest and should not change under this work. The ring
subsystem is the **general** `PROBE_LOG` path. The counters line up:
`probe_stats.recorded` <- sum of records the reader emitted;
`probe_stats.dropped` <- sum of `ring.dropped` + `records_no_slot` +
`reentrant_drop`. A later change can let the fixture's digest be computed from the
reader's merged stream so both paths validate the same numbers.

---

## 12. Callback-context safety audit (every hot-path call)

| Operation | Allocates? | Loader lock? | Blocks? | Verdict |
|---|---|---|---|---|
| `TlsGetValue`/`TlsSetValue` (slot < 64) | no | no | no | safe |
| pool claim (tagged CAS) | no | no | no (bounded) | safe |
| `QueryPerformanceCounter` | no | no | no | safe |
| `__rdtsc` | no | no | no | safe |
| ring write + release-store | no | no | no | safe |
| `%s` local copy under SEH (agent) | no | no | no | safe |
| `%s` via `probe_read`/`ReadProcessMemory` (controller) | no | no | bounded by OS | safe (external domain only) |
| `MapViewOfFile`, `TlsAlloc`, `DuplicateHandle` | — | — | — | **attach only, never in callback** |
| `DLL_THREAD_DETACH` ring mark (atomic store) | no | (already under it) | no | safe |

---

## 13. Ordered task list

1. **Schema + headers.** Add `probe_log_record`, `probe_log_site`,
   `probe_shm_header`, `probe_ring_hdr`, `probe_arg_slot`, `probe_argt`, and the
   `PROBE_LOG`/`PROBE_ARGTAG`/`PROBE_PACK`/`PROBE_FMT_HASH` macros to a new
   `include/probe_log.h`. (New file; does not touch existing headers.)
2. **Dictionary/registrar.** `PROBE_SITE_SECTION`, the init-time section walk,
   dense `dict_id` assignment, `fmt_hash` collision check, grammar validator.
3. **Pool + SPSC ring.** Section layout, tagged-CAS freelist, byte-ring with
   monotonic counters, WRAP handling, acquire/release ordering (x64 + x86).
4. **`probe_log_emit` (two builds).** Shared core; agent `%s` via SEH, controller
   `%s` via `probe_read`; TLS slot + reentrancy guard; policy (DROP/BLOCK);
   clock read; per-ring sequence.
5. **Attach wiring.** Create section; `TlsAlloc`; duplicate/map into the target;
   serialize the agent dictionary; write the header (abi/schema/build_id/clock).
6. **Thread lifecycle.** `DLL_THREAD_DETACH` retire; reader-side retirement +
   generation bump; stale-`CLAIMED` reaper.
7. **Reader.** Drain + k-way merge with low-watermark, `fmt_hash` verify, text +
   JSON rendering, restricted-grammar formatter; `DRAINING` flush.
8. **Resolution.** Timestamped `handle->pid` interval replay + cached
   `pid->name`; wire into rendering.
9. **Teardown.** `state` transitions RUNNING->DRAINING->CLOSED; late-callback
   no-op; drain-with-timeout then unmap.
10. **Tests.** Single-thread digest parity with the legacy 8192 buffer;
    multi-thread order + drop accounting; pool exhaustion; TID-reuse generation;
    `%s` fault + truncation; dictionary version/collision rejection; QPC vs TSC
    merge; external-domain (`probe_read` `%s`) path. Then benchmark the inline
    hot path against FRIDA per `plan-v2.md`.

---

## 14. Risks and open points

- **Cross-process atomics ordering.** Relies on the mapped section being coherent
  and on `acquire`/`release` compiling to correct fences on both x64 and x86.
  Low risk on x86/x64 (strong model) but must be explicit, not incidental.
- **`DLL_THREAD_DETACH` not guaranteed.** `TerminateThread` and some teardown
  paths skip it; the stale-`CLAIMED` reaper (§5) is best-effort and could reclaim
  a genuinely slow thread's ring if the grace period is too short. Make it
  generous and configurable.
- **Pool sizing.** `P` too small -> `drop_no_slot` on thread-heavy targets; too
  large -> wasted committed section. Needs a sane default (64) and a session
  override; consider committing ring pages lazily (reserve P, commit on claim) to
  bound RSS — but commit must happen at claim via a path that itself does not
  violate §0 (reserve+commit-on-claim uses `VirtualAlloc`, which is *not* callable
  in callback context), so lazy commit likely has to be pre-committed or
  commit-ahead by the reader. Open; default to fully committed.
- **QPC in exotic VMs.** Normally coherent cross-process; a misconfigured
  hypervisor could make QPC jumpy. The `(timestamp, tid, seq)` tie-break and the
  low-watermark tolerate small non-monotonicity, but large jumps would widen the
  reorder buffer. Validate on the actual Proxmox VM.
- **`%s` via `probe_read` cost (external domain).** Each string is a
  `ReadProcessMemory` on the *controller* thread (the callback runs there for
  external probes), so it is off the target but still per-record; bound `str_max`
  tightly and allow disabling string capture for high-rate external probes.
- **Reentrancy edge.** The guard drops reentrant logs; if the logger itself ever
  needs to log (it should not), that line is silently lost by design — documented.
- **Dictionary drift between builds.** If the agent DLL and controller are built
  from different source revisions, `build_id`/`fmt_hash` mismatch is detected and
  rejected rather than mis-decoded — but it is a hard failure the build system
  must avoid by shipping matched artifacts.
- **Format-string trust.** Formats are compile-time literals from the callback
  author's own source; the reader still treats decoded `%s`/`%ls` bytes as
  untrusted target data (escape in text, encode in JSON) to avoid a logged target
  string injecting control sequences into the controller's output.

---

### Sources

- [Quill — Ultra-Low-Latency C++ Logging (docs)](https://quillcpp.readthedocs.io/)
- [Quill — User's API](https://quillcpp.readthedocs.io/en/latest/users-api.html)
- [Quill — Overview](https://quillcpp.readthedocs.io/en/latest/overview.html)
- [defmt book (Ferrous Systems)](https://defmt.ferrous-systems.com/print)
- [Using defmt — Ferrous training](https://rust-training.ferrous-systems.com/latest/book/defmt)
- [`defmt-decoder` source (docs.rs)](https://docs.rs/defmt-decoder/latest/src/defmt_decoder/lib.rs.html)
