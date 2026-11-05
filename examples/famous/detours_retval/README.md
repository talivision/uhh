# detours_retval — return values without an "on return" flag

## The Detours original

In Detours the detour function *calls* the original through the trampoline, so it gets the
return value for free — the pattern used throughout `traceapi`:

```c
HANDLE WINAPI Mine_CreateFileW(LPCWSTR a0, ...) {
    _PrintEnter("CreateFileW(%ls,...)\n", a0);
    HANDLE rv = 0;
    __try { rv = Real_CreateFileW(a0, ...); }
    __finally { _PrintExit("CreateFileW(,,,,,,) -> %p\n", rv); }
    return rv;
}
```

## The UHH version

A UHH probe observes; it does not wrap the call. There is deliberately no
`PROBE_AT_RETURN` (it is refused). Instead, the entry callback reads the return address
from `[SP]` and puts a probe **there**, from inside the callback:

```c
void dretval_on_entry(probe_context *c) {
    uint64_t sp = get_reg(c, PROBE_REG_SP), ret = 0;
    get_mem(c, sp, &ret, sizeof(void *));                       // return address
    remember(sp + RET_SP_DELTA, file_name_from(get_func_arg(c, 0)));
    if (first_time(ret))                                         // once per call site
        probe_add_address(get_session(c), ret, dretval_on_return, same_backend);
}
void dretval_on_return(probe_context *c) {
    uint64_t err = 0;
    call_func(c, "KernelBase.dll!GetLastError", &err, 0);       // on the hit thread
    send_log(c, "CreateFileW(\"%s\") -> handle=0x%llx error=%llu",
             recall(get_reg(c, PROBE_REG_SP)), get_reg(c, PROBE_REG_AX), err);
}
```

| Detours | UHH |
|---|---|
| `rv = Real_CreateFileW(...)` | probe at the return address; `get_reg(c, PROBE_REG_AX)` |
| `GetLastError()` inside the detour | `call_func(c, "KernelBase.dll!GetLastError", ...)` — runs on the thread that hit the probe, under every backend |
| locals of the detour frame link entry and exit | the stack pointer links them: after the return SP = entry SP + 8 (x64) or + 4 + 7×4 (x86 stdcall pops the 7 arguments); unique per live thread, no thread id needed |
| the detour stays installed | the return probe stays too and serves every later call from that site; added once (a lock-free site table; a second thread arriving while it is being added waits until it is armed, so its own return is not missed) |

The same callback source runs as breakpoint, hw or inline, x64 and x86. The return probe
uses the entry probe's backend; `--fallback-hw` lets an inline return probe move to a
debug register where the site check refuses an inline hook (a return site is in the middle
of the caller's code).

Caveat found with this example (docs/ROADMAP.md, "Detours-replica findings" D3): under
breakpoint/hw, a `call_func` made while ANOTHER thread's `call_func` is still running is
refused (returns 0) — the callback then logs `error=-1 (call_func failed)`. Inline callbacks
call directly and are not affected.

## The checks (`scripts/regress.py --only detours_retval`)

- `detours-retval-<backend>` (and `inline-fallback`): `detours_target api` on 4 threads.
  Every workload `CreateFileW` goes through one call site, and the target prints what it
  got (`{"kind":"open","name":..,"handle":..,"error":..}`, `GetLastError()` taken right
  after the call). The multiset of logged `(name, handle, error)` must **equal** the
  target's — including `ERROR_ALREADY_EXISTS` (183) on re-creates and
  `INVALID_HANDLE_VALUE` / `ERROR_FILE_NOT_FOUND` (2) for the missing file — with no
  unmatched return and nothing dropped. Run with `--log-entry` so a miss can be traced to a
  thread. `detours-retval-callfunc-{breakpoint,hw}` asserts no `call_func` was refused.
- `detours-retval-cmd-<backend>`: the real `cmd.exe /c type <file> & type <missing>`:
  a valid handle with error 0 for the file, `INVALID_HANDLE_VALUE` with error 2 for the
  missing one, and cmd's output unchanged.

```
build-x64\Release\detours_retval.exe --backend hw -- build-x64\Release\detours_target.exe api --threads 4
```
