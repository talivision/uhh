# End-user API sketch (design, not yet implemented)

> CORRECTIONS PENDING from the design review (docs/design-review-codex.md), to
> apply before implementing. Not yet reflected below:
> - NtOpenProcess: at ENTRY, RCX is PHANDLE (the out pointer), not the handle; the
>   handle exists only on RETURN. The handle->pid map needs a RETURN probe (grab
>   pid from CLIENT_ID at entry, read *PHANDLE on NTSTATUS success). The entry-only
>   example below is WRONG as written.
> - Register access is NOT arch-neutral: x86 passes args on the stack, not in
>   RCX/RDX/R9. Entry probes need a calling-convention-aware probe_arg(c, index);
>   PROBE_RAX-style ids stay for true register access only.
> - probe_add should take a versioned descriptor (stable callback identity +
>   fixed-width config blob copied for ALL backends + declared capabilities +
>   ordered backend preference) and RETURN a probe handle with async status.
> - Handle map: reconcile the inline flat-array view here with plan-v2's reader-
>   side timestamped join (pick one; inline live-resolution is the chosen default).
> - PROBE_LOG needs a restricted typed schema, not general varargs.


What a user writes to instrument the gated scenario. One callback source runs
unchanged under any backend (inline in the agent, or a breakpoint in the
controller). This supersedes the hard-coded probe_session.cpp demo.

```c
#include "probe.h"

/* User config shared with a callback (by pointer; copied into the agent for
   inline probes, kept in the controller for breakpoint probes). */
typedef struct { uint64_t selected_handle, range_start, range_size; } read_filter;

/* Callback 1 - flip the parsed config flag 0 -> 1, right after it is read.
   Runs at configparse.dll!ParsedFlagSite, where EAX holds the parsed value. */
void enable_reads(probe_context *c, void *user) {
    (void)user;
    if (probe_reg(c, PROBE_RAX) == 0)
        probe_set_reg(c, PROBE_RAX, 1);        /* the store now writes 1 */
}

/* Callback 2 - log every NtReadVirtualMemory on the hot path. Filtering is
   native and in-process (no controller round trip per hit). */
void log_read(probe_context *c, void *user) {
    read_filter *f = user;
    uint64_t handle = probe_reg(c, PROBE_RCX), addr = probe_reg(c, PROBE_RDX);
    if (handle != f->selected_handle) return;
    PROBE_LOG(c, "read handle=%#llx addr=%#llx size=%llu", handle, addr,
              probe_reg(c, PROBE_R9));
}

/* Callback 3 - build a handle->pid map at open time (rare, cheap). The reader
   resolves pid->image name later; never do that syscall in the callback. */
void note_open(probe_context *c, void *user) {
    (void)user;
    PROBE_LOG(c, "open pid=%llu handle@%#llx", probe_client_pid(c),
              probe_reg(c, PROBE_RCX));
}

int main(int argc, char **argv) {
    read_filter filter = {0, 0, 32};

    /* Attach: launch a child, attach to a pid, or BUSY-WAIT for the next new
       process by name (excluding instances already running). */
    probe_session *s = probe_launch(argv + 1);
    /* probe_attach_pid(1234);
       probe_wait_for_new("probe_app.exe", PROBE_NEW_ONLY | PROBE_MATCH_BASENAME); */

    /* Deferred: configparse.dll isn't loaded yet. Registration is pending and
       activates automatically when the module loads, before its first call.
       module+offset needs no symbols; the symbol form needs _NT_SYMBOL_PATH. */
    probe_add(s, "configparse.dll+0x1102", enable_reads, NULL, PROBE_BREAKPOINT_SW, 0);
    /* probe_add(s, "configparse.dll!ParsedFlagSite", enable_reads, NULL,
                  PROBE_BREAKPOINT_SW, 0); */

    /* Hot path: inline for speed. If this site is already hooked, FAIL FAST by
       default. PROBE_FALLBACK_BREAKPOINT => use a HW breakpoint (no code touched)
       instead of failing; PROBE_ALLOW_PREHOOKED => relocate/chain over it. */
    probe_add(s, "probe_app.exe!ReadSite", log_read, &filter,
              PROBE_INLINE, PROBE_FALLBACK_BREAKPOINT);

    probe_add(s, "ntdll.dll!NtOpenProcess", note_open, NULL, PROBE_INLINE, 0);

    probe_run(s);               /* arms ready probes; installs pending on load */
    probe_wait_for_exit(s);
    probe_report(s, stdout);    /* merged formatted logs + per-probe counts */
    probe_close(s);             /* removes all our hooks, restores bytes */
    return 0;
}
```

## API surface implied

- Sessions: `probe_launch(argv)`, `probe_attach_pid(pid)`,
  `probe_wait_for_new(name, flags)` (busy wait); `probe_run`,
  `probe_wait_for_exit`, `probe_report`, `probe_close` (clean teardown).
- `probe_add(s, "location", cb, user, backend, flags)`:
  - location: `module+0xRVA` (no symbols) or `module!symbol[+off]` (dbghelp).
  - backend: `PROBE_INLINE`, `PROBE_BREAKPOINT_SW`, `PROBE_BREAKPOINT_HW`,
    `PROBE_EXTERNAL_SW`, `PROBE_EXTERNAL_HW`.
  - flags: `PROBE_ALLOW_PREHOOKED`, `PROBE_FALLBACK_BREAKPOINT`, ...
- Callback: `void cb(probe_context *c, void *user)` - identical source for every
  backend. Register access via `probe_reg/probe_set_reg` with arch-neutral ids
  (so x64 and Win32 share the source); target memory via `probe_read/probe_write`.
- `PROBE_LOG(c, fmt, ...)`: inline call, deferred formatting (stores a format id
  + raw args; the controller formats later). `%s` bytes copied, bounded.
- Capabilities are per backend: asking for a register write or RIP change on a
  backend that can't do it is an error at probe_add time, not a silent no-op.

## Handle -> PID map (inline flat array)

note_open writes handle->pid into a PREALLOCATED flat array indexed by the raw
handle value; log_read reads it. No lock, no allocation, no syscall on the hot
path. Name resolution (pid->name) is a syscall, so it stays in the reader - never
in a callback.

```c
static uint32_t    *pid_by_handle;   /* index: handle -> pid */
static const char **name_by_pid;     /* index: pid -> image name (cached once) */
static size_t handle_cap, pid_cap;   /* bounds, allocated at attach */

void note_open(probe_context *c, void *user) {          /* NtOpenProcess, rare */
    uint64_t h = probe_reg(c, PROBE_RCX);
    if (h < handle_cap) pid_by_handle[h] = (uint32_t)probe_client_pid(c);
}
void log_read(probe_context *c, void *user) {           /* NtReadVirtualMemory, hot */
    read_filter *f = user;
    uint64_t handle = probe_reg(c, PROBE_RCX);
    if (handle != f->selected_handle) return;
    uint32_t pid = handle < handle_cap ? pid_by_handle[handle] : 0;
    const char *name = pid < pid_cap ? name_by_pid[pid] : NULL;
    if (pid && !name)                                   /* first time only */
        name = name_by_pid[pid] = probe_image_name(c, pid);
    PROBE_LOG(c, "read pid=%u (%s) handle=%#llx size=%llu",
              pid, name ? name : "?", handle, probe_reg(c, PROBE_R9));
}
```

- pid_by_handle overwrites on handle reuse, so it always reflects the CURRENT
  mapping - right for live inline resolution.
- name_by_pid is an array of POINTERS (~32 MB over the pid range), not fixed name
  buffers (which would be gigabytes). Strings are interned once by probe_image_name.
- The first-sighting lookup is a syscall in callback context: safe at the read
  site, but probe_image_name must FAIL SOFT (return NULL -> "?"), never block.
  Fully risk-free naming is still available by leaving pid->name to the reader.
```
