# Real-world cases: inline-hook robustness & Frida parity

Research notes for (A) hardening UHH's inline backend against the hard cases that
trampoline-hooking libraries document, and (B) demonstrating feature parity with
Frida by replicating Frida's own published introspection examples.

Scope is ordinary instrumentation-library engineering and testing: correctness and
robustness of a debugger/tracer on normal application code. Nothing here is about
evading detection or defeating protections — the self-check item (A6) is a
*correctness* argument for the no-code-modification backend, not an evasion recipe.

How this maps onto what UHH already has: the existing breakage fixtures
(`examples/breakage/`, see its README) already exercise four of the Part A cases —
a 2-byte function (`ShortSite`), a function already carrying an `E9` jmp at entry
(`PrehookSite`), a non-widenable short branch at entry (`UnrelocSite`), and
stacked/overlapping hook sites (`StackSite` / `StackInsideSite`). The cases below
note which are already covered and which are genuinely new fixtures.

All URLs were fetched and verified while writing this (2026-11-04). Where a claim
rests on inference rather than a direct quote, it is marked **(inference)**.

---

## Part A — documented robustness challenges of trampoline/inline hooking

Backend legend: **inline** = `PROBE_INLINE` (SafetyHook mid-hook, overwrites ≥5
bytes + trampoline); **HW** = `PROBE_HW` (debug registers DR0–3, modifies no code,
≤4 slots); **sw-bp** = `PROBE_BREAKPOINT` (1-byte INT3 + displaced stepping).

| # | Challenge | Minimal benign code shape | Why naive inline struggles | Best UHH backend | Primary source | Fixture status |
|---|---|---|---|---|---|---|
| A1 | **Patch length vs function length** — a 5-byte rel `E9 jmp` (or 14-byte abs jmp when out of ±2 GB) needs ≥5 contiguous bytes of ordinary code before any control-flow boundary. | `xor eax,eax; ret` (2 bytes of body). | There aren't 5 bytes to steal without clobbering `ret` / the next function. Detours **aborts** below 5 bytes; MinHook tries to place the jump in padding *above* the function, else fails. | **HW** (needs 0 bytes); **sw-bp** (INT3 fits on byte 0). Inline must reject. | Detours: "If the target function is fewer than 5 bytes, Detours aborts and returns an error code" ([OverviewInterception](https://github.com/microsoft/Detours/wiki/OverviewInterception)). MinHook: "If the target function is too small… MinHook tries to place the jump above the function… If that fails… `MH_ERROR_UNSUPPORTED_FUNCTION`" ([README](https://github.com/TsudaKageyu/minhook/blob/master/README.md)). | **Covered** — `ShortSite`. |
| A2 | **Relocating a relative branch/call in the stolen bytes** — a short/near `jmp`/`call`/`jcc` among the first ≥5 bytes. | `jmp short L; … L:` where the `jmp` is inside the patched region. | Copying the branch verbatim to a far-away trampoline preserves the *displacement* but changes the *base*, so it no longer reaches the original target; it must be re-encoded (and short→near widened). | **HW** / **sw-bp** (no relocation at all); inline only with a correct relocator. | SafetyHook: "Fixes relative offsets of relocated instructions (eg. `jmp 0x1234`)" and "Widens short branches into near branches" ([README](https://github.com/cursey/safetyhook/blob/main/README.md)). Detours uses a "simple table-driven disassembler" to move copied instructions ([OverviewInterception](https://github.com/microsoft/Detours/wiki/OverviewInterception)). | **Partly covered** — `UnrelocSite` is the *un-widenable* variant (`JRCXZ`/`JECXZ rel8`, no wider encoding). A *widenable* short-branch case is a new fixture. |
| A3 | **Relocating a RIP-relative memory operand in the stolen bytes** — an x64 `[rip+disp]` load/store among the first bytes. | `mov rax, [rip+0x1234]; …` at entry (x64). | The displacement is relative to the *original* address; moved to the trampoline it points 0x1234 bytes off the wrong base. Must recompute the disp32 for the new location (and guard the scratch register — a documented sharp edge). | **HW** / **sw-bp** (operand runs in place); inline only with disp fixup. | SafetyHook: "Fixes IP relative displacements of relocated instructions (eg. `lea rax, [rip + 0x1234]`)" ([README](https://github.com/cursey/safetyhook/blob/main/README.md)). Frida's relocator `checked` mode will "verify that the chosen scratch register is not used in the function's early prologue" ([Interceptor docs](https://frida.re/docs/javascript-api/#interceptor)). | **New fixture** (x64-only). |
| A4 | **A branch target that lands *inside* the moved region** — code later in the function jumps back to a byte now living in the trampoline (or an entry-interior label is itself a jump target). | `L: dec ecx; jnz L` where `L` is within the first 5 bytes. | After patching, that target address holds detour bytes, not the original instruction; a jump to it executes the wrong bytes unless the engine detects internal targets and redirects them. Also the `/hotpatch` invariant ("no jump within the function goes to the first instruction") exists precisely to avoid this at entry. | **HW** / **sw-bp** (code unmoved, targets still valid); inline only if it handles internal targets. | SafetyHook: "Handles short branches that land within the trampoline" ([README](https://github.com/cursey/safetyhook/blob/main/README.md)). MSVC `/hotpatch`: "no jump within the function goes to the first instruction" ([/hotpatch](https://learn.microsoft.com/en-us/cpp/build/reference/hotpatch-create-hotpatchable-image)). | **New fixture.** |
| A5 | **Thread executing the prologue mid-patch** — another thread's IP is inside the bytes being overwritten at the instant of the write. | Hot function called in a tight loop on N worker threads while the hook installs. | A torn multi-byte write, or a thread resuming on a now-half-overwritten instruction, corrupts execution. Libraries freeze threads and fix up any IP caught in the patched range. | All three are **exact** by construction, via *different* mechanisms — good differential fixture. Inline: freeze + IP fixup. sw-bp: displaced stepping (no suspend). HW: no code change at all. | SafetyHook: "Stops all other threads when creating or deleting hooks" + "Fixes the IP of threads that may be affected by the creation or deletion of hooks" ([README](https://github.com/cursey/safetyhook/blob/main/README.md)). MinHook batches enable/disable because each "suspends and resumes all threads"; also "Fixed a possible thread deadlock in x64 mode" ([README](https://github.com/TsudaKageyu/minhook/blob/master/README.md)). UHH sw-bp exactness via displaced stepping is already proven at 2M reads × 8 threads ([README](../README.md)). | **New fixture** (stress harness; UHH already has the 2M/8-thread rig for sw-bp to extend to inline). |
| A6 | **Hot-patch prologue present vs absent** — `mov edi,edi` (2 bytes) at entry + NOP/int3 padding before it (`/hotpatch` + `/functionpadmin`). | `/hotpatch` build: `mov edi,edi` at entry, 5 pad bytes before. vs. a tightly packed function with no padding. | The classic 2-byte hot-patch hook puts a short `jmp -5` over `mov edi,edi` into the padding, which holds the real 5-byte jump. With no padding (most non-system, non-`/hotpatch` code) that route is unavailable and the engine must fall back to stealing ≥5 bytes of real code (→ A1/A2/A3). | **inline** when the prologue+padding exist (cleanest, 2-byte atomic patch); **HW**/**sw-bp** when they don't and the body is short. | MSVC: `/hotpatch` "ensures that the first instruction of each function is at least 2 bytes long and that no jump within the function goes to the first instruction" ([/hotpatch](https://learn.microsoft.com/en-us/cpp/build/reference/hotpatch-create-hotpatchable-image)); padding via [/functionpadmin](https://learn.microsoft.com/en-us/cpp/build/reference/functionpadmin-create-hotpatchable-image). MinHook's "place the jump above the function" is exactly this padding route ([README](https://github.com/TsudaKageyu/minhook/blob/master/README.md)). | **New fixture** (build one target each way; map file landmarks). |
| A7 | **Timing — hooking a function in a later-loaded module** — register a probe before its module exists; arm it from the module-load event. | Target `LoadLibrary`s a DLL on a keystroke; probe named `later.dll+0xRVA` registered up front. | A hook installed too early finds no bytes; installed from `DllMain`/TLS under loader lock is constrained. The robust pattern is a deferred probe armed on the load notification. | **Session-level, backend-agnostic** — UHH pending `module+RVA` probes already do this (the `gated_config` example flips a flag in a DLL that loads later). | Frida: `Process.attachModuleObserver(callbacks)` "observe modules… as they are added or removed" ([docs](https://frida.re/docs/javascript-api/#process)). UHH deferred-probe behavior ([README](../README.md), [plan-v2](plan-v2.md)). | **Covered** — `gated_config` / deferred probes. Add a focused unit fixture. |
| A8 | **Code that verifies its own bytes (integrity self-check)** — a function that checksums its own prologue and behaves differently if changed. | `if (crc(entry, N) != EXPECTED) return -1; /* normal work */` | Any byte-modifying backend (inline trampoline jump, or a 1-byte INT3) changes the checked bytes, so the self-check reads modified code and the function takes the "tampered" path — a *correctness* problem for the tracer, not a security one. A debug-register breakpoint modifies **no** code, so the self-check sees pristine bytes. | **HW** (modifies zero bytes — the only backend that leaves the self-check reading true bytes). inline and sw-bp both alter the bytes **(inference** from how each patches — Detours/MinHook overwrite entry bytes; INT3 writes 1 byte; DR0–3 write no code**)**. | Detours overwrites "the first few instructions" ([OverviewInterception](https://github.com/microsoft/Detours/wiki/OverviewInterception)); INT3 is a 1-byte code write; HW DR breakpoints change no code ([README](../README.md) backend table). The HW-is-non-modifying property is the primary engineering fact; the self-check consequence is the **(inference)**. | **New fixture** (differential: inline/sw-bp observe the "tampered" branch, HW does not). |

### Ranking A — value as a UHH inline-robustness fixture

1. **A3 RIP-relative operand relocation (x64)** — highest-value *new* inline test; the single most error-prone relocator path (scratch-register clobber is a real, documented bug class) and not yet in the fixture set.
2. **A4 branch-target-into-moved-region** — classic relocator correctness bug; new; cheap to build with a labelled loop.
3. **A2 widenable short branch** — complements the existing non-widenable `UnrelocSite`; proves the relocator *widens* rather than just rejects.
4. **A5 mid-patch thread race (inline)** — extend the existing 2M/8-thread sw-bp rig to inline; proves the "freeze + IP-fixup" path, the subtlest multithread guarantee.
5. **A6 hot-patch prologue present/absent** — two build variants; proves the clean 2-byte path and the fallback.
6. **A8 self-check differential** — strong demonstration of *why three backends exist*; HW wins by construction.
7. **A1 short function** — already covered (`ShortSite`); keep.
8. **A7 late-module timing** — already covered (`gated_config`); add a narrow unit fixture.

---

## Part B — Frida's published introspection examples to replicate

UHH mapping legend: **arg read** = `get_func_arg`; **reg r/w** = `get_reg` /
`set_reg`; **mem r/w** = `get_mem` / `set_mem`; **log** = `PROBE_LOG`;
**ret** = `get_reg(AX)` (+ `PROBE_AT_RETURN`). Port status: **ready** = buildable
on today's API; **needs-feature** = requires a roadmap item (symbol resolution,
enumeration, verified return/onLeave probes).

| # | Frida example | Demonstrates | Frida API | Primary source | UHH mapping | Backend | Port status |
|---|---|---|---|---|---|---|---|
| B1 | **Attach + log an argument** — `Interceptor.attach(fn,{onEnter(args){ send(args[0].toInt32()); }})`. | Entry hook; read call arg; emit it. | `Interceptor.attach` / `onEnter(args)` | [frida.re/docs/functions](https://frida.re/docs/functions/) (`hook.py`); [JS API](https://frida.re/docs/javascript-api/#interceptor) (`read` example) | `probe_add_symbol(…, cb, PROBE_INLINE)`; `get_func_arg(c,0)`; `PROBE_LOG`. Direct analog of the README `log_read`. | inline (sw-bp/HW also work) | **ready** |
| B2 | **Read a string argument** — read `lpFileName` / path arg as text (e.g. CreateFileW wide string). | Dereference a pointer arg and read target memory. | `args[n].readUtf8String()` / `readUtf16String()` | [JS API Interceptor](https://frida.re/docs/javascript-api/#interceptor); [Windows example](https://frida.re/docs/examples/windows/) reads buffers via `readByteArray` | `get_func_arg(c,n)` → `get_mem(c, ptr, buf, n)` → `PROBE_LOG`. (UHH logs raw bytes; UTF-16 decode is reader-side.) | inline / sw-bp / HW | **ready** |
| B3 | **Hexdump a buffer in onLeave** — save `this.outptr`/size in `onEnter`, `hexdump(readByteArray(size))` in `onLeave`. | Entry→leave carry; read an output buffer after the call. | `this.x` thread-local, `readByteArray`, `hexdump` | [Windows example](https://frida.re/docs/examples/windows/) | `get_mem` + `PROBE_LOG`. **Buffer capture needs a return probe** to run after the call fills it. | inline (+ ret) | **needs-feature** (verified `PROBE_AT_RETURN`) |
| B4 | **Modify an argument** — `onEnter(args){ args[0] = ptr('1337'); }`. | Change behavior by rewriting an incoming arg. | `args[n] = ptr(...)` | [frida.re/docs/functions](https://frida.re/docs/functions/) (`modify.py`) | x64: `set_reg(c, PROBE_REG_CX, …)` for arg0, etc. x86: `set_mem` to the stack slot at `SP+off`. | inline / sw-bp / HW | **ready** |
| B5 | **Replace a return value** — `onLeave(retval){ retval.replace(0); }`. | Override what the function returns. | `onLeave(retval)` + `retval.replace()` | [frida.re/docs/functions](https://frida.re/docs/functions/) (commented in `modify.py`); [JS API](https://frida.re/docs/javascript-api/#interceptor) `retval.replace(1337)` | Return probe (`PROBE_AT_RETURN`) + set the return register: `set_reg(c, PROBE_REG_AX, v)`. (`get_reg(AX)` reads it today; no `probe_set_retval` yet — use `set_reg(AX)`.) | inline/sw-bp/HW (+ ret) | **needs-feature** (return/onLeave probes) |
| B6 | **Mid-function register read/write** — `this.context.rax = …` / read `pc`,`sp`. | True machine-register access at an arbitrary instruction (not just args). | `this.context.<reg>` (read/assign) | [JS API Interceptor](https://frida.re/docs/javascript-api/#interceptor) (`context` with `pc`/`sp`/`rax`); note "args will only give sensible values if the intercepted instruction is at the beginning of a function" | `get_reg` / `set_reg` at a `module+RVA` mid-site. Direct analog of README `enable_reads` (flips parsed flag in `EAX`). | inline (sw-bp/HW for arbitrary instrs) | **ready** |
| B7 | **Resolve an export then hook it** — `Interceptor.attach(Module.getGlobalExportByName('connect'), …)`. | Hook by symbol name, no hard-coded address. | `Module.getGlobalExportByName` / `Module.getExportByName` | [frida.re/docs/functions](https://frida.re/docs/functions/) (`struct_mod.py`); [JS API](https://frida.re/docs/javascript-api/#module) | `probe_add_symbol(s, "ws2_32.dll!connect", …)` — the `module!symbol` form. Export-table resolution (no PDB) is on the roadmap; `module+RVA` is the workaround today. | any | **needs-feature** (symbol/export resolution) |
| B8 | **Build a struct and pass it as an arg** — allocate a `sockaddr_in`, `args[1] = st`. | Construct target memory + redirect a pointer arg to it. | `Memory.alloc` + struct writes + `args[n] = ptr` | [frida.re/docs/functions](https://frida.re/docs/functions/) (`struct_mod.py`) | `set_mem` into a scratch buffer + `set_reg`/stack write. Needs a target-memory allocation helper (no `probe_alloc` today — could write into an existing writable buffer). | inline | **needs-feature** (target-memory alloc helper) |
| B9 | **Enumerate modules / exports / threads** — list loaded modules, a module's exports, running threads. | Process introspection / discovery. | `Process.enumerateModules`, `Module.enumerateExports`, `Process.enumerateThreads` | [JS API](https://frida.re/docs/javascript-api/#process) | No UHH equivalent yet — pure discovery surface. Natural companion to symbol resolution; would feed `read_logger`-style auto-targeting. | n/a (controller-side) | **needs-feature** (enumeration) |
| B10 | **frida-trace by glob** — `frida-trace -i "CreateFileW" -i "recv*" …` auto-generates onEnter/onLeave handlers per matched function. | Bulk tracing of many APIs by name pattern; auto-generated logging handlers. | `frida-trace` CLI (`-i`/`-x`/`-a` filters) | [frida.re/docs/frida-trace](https://frida.re/docs/frida-trace/) | Maps to the planned `read_logger` CLI pattern but generalized: needs enumeration + export resolution + glob matching + a default log handler. Partial precursor exists (read_logger resolves `NtReadVirtualMemory` via export table). | sw-bp (CLI/external) | **needs-feature** (enumeration + glob + symbol resolution) |
| B11 | **Full function replacement** — `Interceptor.replace(fn, NativeCallback(...))`. | Swap an implementation entirely (not observe+modify). | `Interceptor.replace` / `replaceFast` | [JS API](https://frida.re/docs/javascript-api/#interceptor) | Out of UHH's observe-and-modify model — UHH gives full context control at a site but does not substitute whole functions. Note as a deliberate non-goal / future. | — | **out-of-scope** |

### Feature backlog surfaced by Part B

- **Return / onLeave probes** (`PROBE_AT_RETURN` is declared in `probe_api.h` but not yet verified/built) — unlocks B3, B5. Highest-leverage single feature.
- **Symbol / export resolution** (`module!symbol`, dbghelp + export table) — unlocks B7, and is a prerequisite for B10. On the README/plan-v2 roadmap.
- **Enumeration** (modules/exports/threads) — unlocks B9, feeds B10. New surface.
- **Target-memory allocation helper** — unlocks B8.
- **Glob/pattern CLI tracer** generalizing `read_logger` — the frida-trace analog (B10).

### Port status at a glance

- **Ready today (API as-is):** B1, B2, B4, B6.
- **One roadmap feature away:** B3/B5 (return probes), B7 (symbols).
- **Larger surface:** B8 (alloc), B9 (enumeration), B10 (CLI tracer).
- **Non-goal:** B11 (whole-function replace).

---

## Top 10 fixtures / examples to build next (ranked)

Interleaves Part A robustness fixtures and Part B parity examples by engineering value.

| Rank | Item | Type | Why now | Needs |
|---|---|---|---|---|
| 1 | **A3 — RIP-relative operand in stolen bytes (x64)** | robustness | Most error-prone relocator path (scratch-reg clobber is a known bug class); not yet covered. | inline relocator |
| 2 | **B1 — attach + log arg** parity demo | parity | Proves the headline Frida use case on today's API; zero new features. | none (ready) |
| 3 | **A4 — branch target into moved region** | robustness | Classic relocator correctness bug; cheap labelled-loop fixture. | inline relocator |
| 4 | **B5/B3 — return value replace + onLeave buffer dump** | parity | Unlocks the two most-cited Frida demos; forces finishing `PROBE_AT_RETURN`. | return probes |
| 5 | **A2 — widenable short branch** | robustness | Complements `UnrelocSite`; proves *widen*, not just reject. | inline relocator |
| 6 | **B7 — hook by `module!symbol`** | parity | Removes hard-coded RVAs; prerequisite for a frida-trace analog. | symbol resolution |
| 7 | **A8 — self-check differential (inline/sw-bp vs HW)** | robustness | Demonstrates *why* the HW backend exists; strong 3-backend story. | fixture only |
| 8 | **A5 — mid-patch thread race for inline** | robustness | Extends the proven 2M/8-thread sw-bp rig to inline freeze+IP-fixup. | stress harness |
| 9 | **A6 — hot-patch prologue present vs absent** | robustness | Two build variants; proves clean 2-byte path + fallback. | build variants |
| 10 | **B9/B10 — enumeration + glob CLI tracer** | parity | The frida-trace analog; generalizes `read_logger`. | enumeration, symbols, glob |

---

## Sources (primary, all verified 2026-11-04)

- Microsoft Detours — *Interception of Binary Functions*: <https://github.com/microsoft/Detours/wiki/OverviewInterception>
- TsudaKageyu/MinHook — README (version history documents the small-function fallback, `MH_ERROR_UNSUPPORTED_FUNCTION`, thread-suspension and x64 deadlock fix): <https://github.com/TsudaKageyu/minhook/blob/master/README.md>
- cursey/SafetyHook — README (relocation/IP-fixup/short-branch/thread-stop feature list): <https://github.com/cursey/safetyhook/blob/main/README.md> · mid-hook example: <https://github.com/cursey/safetyhook/blob/main/example/midhook.cpp>
- Frida — JavaScript API (Interceptor, Module, Process/Thread enumeration, relocator modes, breakpointKind): <https://frida.re/docs/javascript-api/>
- Frida — Functions tutorial (`hook.py`, `modify.py`, `struct_mod.py`): <https://frida.re/docs/functions/>
- Frida — frida-trace: <https://frida.re/docs/frida-trace/>
- Frida — Windows example (buffer hexdump via `readByteArray`, module base resolution): <https://frida.re/docs/examples/windows/>
- MSVC `/hotpatch` (2-byte first instruction, no jump to first instruction): <https://learn.microsoft.com/en-us/cpp/build/reference/hotpatch-create-hotpatchable-image> · `/functionpadmin` (padding): <https://learn.microsoft.com/en-us/cpp/build/reference/functionpadmin-create-hotpatchable-image>

Internal references: [`README.md`](../README.md), [`docs/plan-v2.md`](plan-v2.md), [`docs/api-sketch.md`](api-sketch.md), [`examples/breakage/README.md`](../examples/breakage/README.md).

### Verification notes / caveats

- The MinHook README page is primarily install guidance + version history; the
  small-function and thread-suspension behavior is quoted from its changelog
  entries, not a dedicated limitations section. Treated as authoritative but noted.
- The SafetyHook README states behaviors as a feature list; it does not document the
  trampoline internals or name Zydis in that list (Zydis is named in the install
  section). No upstream prose on *how* relocation is implemented was found beyond the
  bullets quoted.
- A8 (self-check): the primary facts (Detours/INT3 modify code; DR breakpoints do
  not) are sourced; the consequence that a self-checking function diverges under the
  byte-modifying backends is marked **(inference)** — it should be *demonstrated* by
  the proposed differential fixture rather than asserted.
- Frida's `retval.replace` in `modify.py` appears only as a commented line; it is
  live API, quoted additionally from the JS API Interceptor section (`retval.replace(1337)`).
- `/hotpatch` is documented as x86-only; x64/Arm64 are "always treated as
  hotpatchable" but still require `/functionpadmin` for the padding — relevant to
  building the A6 fixture per-arch.
