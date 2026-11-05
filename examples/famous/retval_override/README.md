# Return-value override (GetTickCount anti-timing bypass)

## The original recipe

```js
Interceptor.attach(Module.getExportByName('kernel32.dll', 'GetTickCount'), {
  onLeave(retval) { retval.replace(0x1337beef); }
});
```

The standard way to defeat "elapsed time > N ms means a debugger is attached" checks
(API Monitor can do the same with a breakpoint "modify return value" action).

## UHH mapping (`retval_callbacks.cpp`)

UHH has no on-return flag on purpose (`PROBE_AT_RETURN` is refused): the return is an
ordinary instruction in the caller, so it is probed like any other address.

| Frida | UHH |
|---|---|
| `Interceptor.attach(GetTickCount)` | `famous_tick_on_entry` on `kernel32.dll!GetTickCount`: read the return address at SP; if it is in the main module, `famous_arm_return` adds a probe there (once per call site, from inside the callback -- armed before this very call returns) |
| `onLeave: retval.replace(v)` | `famous_tick_on_return` at the call site: `set_reg(c, PROBE_REG_AX, v)` |
| the value | `--value 0xN` (default `0x1337BEEF`) in the probe config, published to the return-site callback through `UHH_SHARED` |

The alternative -- a probe on GetTickCount's own `ret` -- needs the function's internal
layout and, for inline, a site with 5 relocatable bytes before the next jump target; the
call-site form works on every backend without disassembling the callee. Scoping to the
main module leaves system DLLs that call GetTickCount untouched (Frida's version changes
the value for every caller in the process).

## Target and expected result

`famous_tick_target --threads 4 --calls 25`: two call sites (`tick_worker` on 4 threads
x 25 calls; `tick_main` on main: 25 calls plus a timing check `start; Sleep(150); end`).
Uninstrumented: no call returns `0x1337BEEF` and the check says `slow`. Instrumented, on
every backend: all 127 calls (`forced_workers` per thread, `forced_main`) return the forced
value, `elapsed == 0`, the check says `fast`, and `GetTickCount64` (the control) is unchanged.

This recipe found a hardware-backend bug: return-site probes added at runtime while
worker threads were still in their loader initialisation were lost for those whole
threads (thread start restores the creation-time debug registers). Fixed in the library;
`famous-retval-hw` runs three times to keep it fixed.
