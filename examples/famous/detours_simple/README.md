# detours_simple — Detours' `simple` sample on UHH

## The Detours original

[`samples/simple`](https://github.com/microsoft/Detours/tree/main/samples/simple) is the
"hello world" of Detours: `simple.dll` is injected into a program (with `withdll.exe`), and
in `DllMain` it detours `SleepEx` inside a `DetourTransactionBegin/Commit` pair. The detour
counts calls and the time asked for, then calls the trampoline (`TrueSleepEx`); the count
is printed at `DLL_PROCESS_DETACH`. `sleep5.exe` is the test target.

## The UHH version

| Detours | UHH |
|---|---|
| `DetourAttach(&TrueSleepEx, TimedSleepEx)` | `probe_add_symbol_cfg(s, "KernelBase.dll!SleepEx", dsimple_on_sleep, backend, ...)` |
| inject with `withdll.exe /d:simple.dll sleep5.exe` | `detours_simple --backend <b> -- detours_target.exe sleep` (`probe_launch`) |
| detour reads `dwMilliseconds` | `get_func_arg(c, 0)` (and `get_func_arg(c, 1)` for `bAlertable`) |
| global counter, printed at detach | one `send_log` per call; the log is the counter (never dropped) |
| call `TrueSleepEx` | nothing to do: a probe observes, the original code runs on |

The **one callback source** (`simple_callbacks.cpp`) runs under `breakpoint`, `hw` and
`inline`, x64 and x86. A second probe sits on the `kernel32!Sleep` import stub (a 6/7-byte
`jmp [__imp_Sleep]` followed by padding) to tell what the program itself called from what
KernelBase does on its behalf: `kernel32!Sleep` → `KernelBase!Sleep` → `KernelBase!SleepEx`.

Why the log rather than a counter: a UHH callback's globals live where the callback runs —
in the controller for breakpoint/hw, inside the target for inline. A log line is delivered
the same way from both, so the totals come out identical under every backend.

## The target and the check

`detours_target sleep --threads 4 --rounds 25` sleeps a fixed pattern on four threads
(`Sleep(1..3)`, `SleepEx(2,FALSE)`, `SleepEx(0,TRUE)`, `Sleep(0)`), plus one
`SleepEx(60000,TRUE)` that an APC interrupts (returns `WAIT_IO_COMPLETION`, 192). It prints
what it requested.

`scripts/regress.py --only detours_simple` (`detours-simple-<backend>`) asserts, per
backend: the target's own results equal an uninstrumented run; `Sleep(...)` logs == the
target's `Sleep` calls; `SleepEx(...)` logs == `Sleep` + `SleepEx` calls; the summed
milliseconds == the total requested; alertable calls == rounds×threads + 1; probe hits ==
logs; nothing dropped; exit code 0.

```
build-x64\Release\detours_simple.exe --backend inline -- build-x64\Release\detours_target.exe sleep
```
