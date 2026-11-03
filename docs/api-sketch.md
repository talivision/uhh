# End-user API (design, not yet implemented)

An introspection tool: every callback gets the full context and full control. No
capability declarations, no descriptors - you add a probe at a location, give it a
callback, and flags decide the type. Config is an optional struct you define,
needed only to parameterize a callback (e.g. filter to a PID).

```c
#include "probe.h"

/* ---- agent-local maps, preallocated at attach (live inside the target) ---- */
static uint32_t    *pid_by_handle;   /* handle -> pid */
static const char **name_by_pid;     /* pid -> image name, resolved once */
static size_t handle_cap, pid_cap;

/* ---- optional config: the obvious example is filtering to a PID ---- */
struct read_filter { uint32_t only_pid; };   /* 0 = log all */

/* ---- flip the parsed config flag 0 -> 1, mid-function ----
   At configparse.dll!ParsedFlagSite, EAX holds the freshly parsed value. A true
   register access, so probe_reg (not probe_arg). No config needed. */
void enable_reads(probe_context *c) {
    if (probe_reg(c, PROBE_REG_AX) == 0)
        probe_set_reg(c, PROBE_REG_AX, 1);
}

/* ---- record handle -> pid on NtOpenProcess RETURN ----
   At entry the handle doesn't exist yet (arg0 is PHANDLE, the out pointer), so
   this is a return probe: entry args are captured and readable, retval is the
   NTSTATUS. Read *PHANDLE only on success. No config needed. */
void note_open(probe_context *c) {
    if ((int32_t)probe_retval(c) < 0) return;          /* NTSTATUS failure */
    uint64_t phandle = probe_arg(c, 0);                /* PHANDLE    */
    uint64_t pclient = probe_arg(c, 3);                /* PCLIENT_ID */
    uint64_t handle = 0, pid = 0;
    if (!probe_read(c, phandle, &handle, sizeof handle)) return;
    if (!probe_read(c, pclient, &pid,   sizeof pid))    return;  /* CLIENT_ID.UniqueProcess */
    if (handle < handle_cap) pid_by_handle[handle] = (uint32_t)pid;
}

/* ---- log every NtReadVirtualMemory, resolve + filter by PID ----
   Hot path. Args via probe_arg so the same source works on x64 (registers) and
   x86 (stack). Filter comes from the optional config. */
void log_read(probe_context *c) {
    struct read_filter *f = c->config;                 /* NULL if none was passed */
    uint64_t handle = probe_arg(c, 0);                 /* HANDLE ProcessHandle  */
    uint64_t size   = probe_arg(c, 3);                 /* SIZE_T NumberOfBytes  */
    uint32_t pid    = handle < handle_cap ? pid_by_handle[handle] : 0;
    if (f && f->only_pid && pid != f->only_pid) return;   /* inline filter */
    const char *name = pid < pid_cap ? name_by_pid[pid] : NULL;
    if (pid && !name)                                  /* first sighting only */
        name = name_by_pid[pid] = probe_image_name(c, pid);  /* fails soft -> NULL */
    PROBE_LOG(c, "read pid=%u (%s) handle=%#llx size=%llu",
              pid, name ? name : "?", handle, size);
}

int main(int argc, char **argv) {
    probe_session *s = probe_session_create();

    /* Pending until configparse.dll loads; activates before its first call.
       module+offset needs no symbols; module!symbol also works. Flags = type. */
    probe_add(s, "configparse.dll+0x1102", enable_reads, PROBE_BREAKPOINT);

    /* Inline return probe builds the handle->pid map. */
    probe_add(s, "ntdll.dll!NtOpenProcess", note_open, PROBE_INLINE | PROBE_AT_RETURN);

    /* Hot read path, inline, filtered to one PID via optional config. If the site
       is already hooked, fail fast unless a flag says otherwise. */
    struct read_filter cfg = { .only_pid = 0 };        /* set before run if filtering */
    probe_add_cfg(s, "ntdll.dll!NtReadVirtualMemory", log_read,
                  PROBE_INLINE | PROBE_FALLBACK_HW, &cfg, sizeof cfg);

    /* Attach: launch a child, or busy-wait for the next new instance by name. */
    probe_launch(s, argv + 1);
    /* probe_watch_new(s, "probe_app.exe", PROBE_NEW_ONLY, &ready);
       probe_attach_wait(s, 5000, &cancel); */

    probe_run(s);               /* arms ready probes; installs pending on load */
    probe_wait_for_exit(s);     /* or probe_stop(s) for a long-lived target */
    probe_report(s, stdout);    /* merged logs; reader fills any pid->name it lacks */
    probe_close(s);             /* quiesce callbacks, restore bytes, free */
    return 0;
}
```

## The whole API

- `probe_add(s, "location", callback, flags)` - flags decide the TYPE and options:
  `PROBE_INLINE`, `PROBE_BREAKPOINT`, `PROBE_HW`; plus `PROBE_AT_RETURN`,
  `PROBE_ALLOW_PREHOOKED`, `PROBE_FALLBACK_HW`.
- `probe_add_cfg(s, "location", callback, flags, &cfg, len)` - same, with an
  optional config struct. The bytes are COPIED (into the agent for inline probes,
  so a controller global would not work - this is why config exists). Reachable as
  `c->config`; `NULL` when none was passed.
- location: `module+0xRVA` (no symbols) or `module!symbol[+off]` (dbghelp). Pending
  until the module loads.
- `void callback(probe_context *c)` - one context, full control. Everything hangs
  off it:
  - `probe_arg(c, i)` - the i-th call argument, arch-neutral (registers on x64,
    stack on x86). Use at call entry / return.
  - `probe_reg(c, PROBE_REG_*)` / `probe_set_reg` - a real machine register, for
    mid-function sites.
  - `probe_read(c, addr, buf, n)` / `probe_write` - target memory (report short
    transfers / failure).
  - `probe_retval(c)` - return value, for `PROBE_AT_RETURN` probes.
  - `PROBE_LOG(c, fmt, ...)` - deferred-format log line (typed args; formatted by
    the reader).
  - `c->config` - your optional parameters.
- Backend can't do an operation (e.g. a breakpoint backend asked to do something
  inline-only)? That one helper returns UNSUPPORTED at runtime. Nothing is scoped
  away in advance - full control, physical limits surface where they bite.
- Session: `probe_session_create`, `probe_launch` / `probe_watch_new` +
  `probe_attach_wait` (busy-wait, readiness/timeout/cancel), `probe_run`,
  `probe_wait_for_exit` / `probe_stop` / `probe_detach`, `probe_report`,
  `probe_close`.

## Handle -> PID map notes

- `pid_by_handle` is populated by the `NtOpenProcess` RETURN probe and read inline
  by `log_read` - a flat array indexed by the raw handle, no lock/alloc/syscall.
  It overwrites on handle reuse, so it reflects the CURRENT mapping (right for live
  resolution).
- `name_by_pid` is an array of POINTERS (~32 MB over the pid range), not fixed name
  buffers (gigabytes). The name syscall runs once per pid, cached; `probe_image_name`
  must FAIL SOFT (never block in callback context).
