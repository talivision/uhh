# Frida Interceptor parity on today's UHH API

This example is deliberately limited to introspection and mutation already exposed
by `probe_api.h`. `parity_target` calls three ABI-preserving entry sleds and one
mid-function register site. `frida_parity` registers their module+RVA locations,
launches the target, and prints one JSON verdict for each demo.

| Demo | Frida source pattern | UHH pattern | Backend |
|---|---|---|---|
| B1: log an argument | [`Interceptor.attach` / `onEnter(args)`](https://frida.re/docs/functions/) | `probe_arg(c, 0)` then `PROBE_LOG` | inline; the 16-NOP entry sled is safely relocatable |
| B2: read a string | [`args[n].readUtf8String()`](https://frida.re/docs/functions/) | `probe_arg` -> `probe_read` -> `PROBE_LOG` | inline; the same long entry shape |
| B4: modify an argument | [`args[n] = ptr(...)`](https://frida.re/docs/functions/) | x64: `probe_set_reg(RDX)`; x86: `probe_write(SP+8)` | inline; the callee validates the replacement string |
| B6: register read/write | [`this.context.rax`](https://frida.re/docs/javascript-api/#interceptor) | `probe_reg(AX)` / `probe_set_reg(AX)` at a mid-site | hardware; exact at the single-NOP site without an inline patch span |

The B4 fixture reuses a target buffer already passed in arg0. That demonstrates
Frida-style pointer redirection without pretending UHH has a target-memory allocator.
Callbacks build their complete text before `PROBE_LOG`; this is compatible with the
current inline agent, which records the supplied log string rather than formatting
typed varargs.

## Build and run (PowerShell)

From a Visual Studio 2022 developer shell at the repository root:

```powershell
cmake -S . -B build-frida-x64 -A x64
cmake --build build-frida-x64 --config Release --target frida_parity

$bin = Resolve-Path build-frida-x64\Release
$r = (python scripts\site_rvas.py "$bin\parity_target.map" `
  ParityB1Site ParityB2Site ParityB4Site ParityB6Site | Out-String | ConvertFrom-Json)
& "$bin\frida_parity.exe" $r.ParityB1Site $r.ParityB2Site $r.ParityB4Site $r.ParityB6Site
```

For x86, use the same commands with a Win32 build directory:

```powershell
cmake -S . -B build-frida-x86 -A Win32
cmake --build build-frida-x86 --config Release --target frida_parity

$bin = Resolve-Path build-frida-x86\Release
$r = (python scripts\site_rvas.py "$bin\parity_target.map" `
  ParityB1Site ParityB2Site ParityB4Site ParityB6Site | Out-String | ConvertFrom-Json)
& "$bin\frida_parity.exe" $r.ParityB1Site $r.ParityB2Site $r.ParityB4Site $r.ParityB6Site
```

The four RVAs may instead be supplied through `UHH_PARITY_B1_RVA`,
`UHH_PARITY_B2_RVA`, `UHH_PARITY_B4_RVA`, and `UHH_PARITY_B6_RVA`. All four must be
set together. A successful run emits four lines shaped like:

```json
{"name":"B4_modify_argument","frida_equivalent":"onEnter: args[1] = ptr(...)","arg_seen":"instrumented","verdict":"pass"}
```

## Assumptions

- The build uses MSVC/MASM through CMake 3.28 or newer, as required by the project.
- The driver, target, and `probe_api_agent.dll` are kept in the same configuration
  directory so sibling discovery works.
- Site RVAs come from the matching architecture/configuration's linker map; ASLR is
  handled by UHH's `module+RVA` resolution.
- Each fixture site executes once on the initial target thread, so one callback hit
  is the expected result for every row.
