# Side-effect transparency test

`sidefx` checks UHH's promise that a hit leaves no trace on the target thread unless
the callback deliberately uses `set_reg` or `set_mem`. This callback uses neither.
The same exported `sidefx_on_site` source is linked into the driver (breakpoint and
hardware callbacks) and `probe_api_agent` (inline callbacks).

At the exported mid-function `SideFxSite`, the assembly fixture has live known values
in every GPR except the stack and frame/base pointers, XMM0-15 on x64 or XMM0-7 on
x86, and every corresponding nonzero YMM upper half. It also sets MXCSR to `0x7f80`
(all exception flags clear, round toward zero), the x87 control word to `0x0e7f`, and
DF to one. The target sets last error to `0x1234abcd` before entering the fixture.
Immediately after the 16-byte hookable site, assembly snapshots the live state for C
to compare. ABI-nonvolatile state is restored before the fixture returns.

The callback deliberately performs divide-by-zero and inexact floating-point work,
formats a double in `send_log`, reads 256 bytes at the captured SP with `get_mem`,
reads several registers, emits `send_log_stack` every 64th hit, and calls
`GetFileAttributesA` on a nonexistent path after clearing last error. Those operations
try to disturb exactly the state being checked.

The fixture also fills and checks 512 bytes below the site SP. Windows has no red zone,
so `below_sp_ok` is diagnostic information only, not a pass criterion. It is useful for
showing whether an inline hook happens to scribble on below-SP data that this particular
mid-function sequence keeps live, but portable Windows code may not rely on that area.
The test requires an AVX2-capable machine.

## CLI

```text
sidefx_driver --backend breakpoint|hw|inline -- <sidefx_target.exe> [--iters N] [--threads T] [--no-wait]
```

The target defaults to 1,000 iterations on four threads. It always prints and flushes
`{"kind":"waiting"}`; unless `--no-wait` is present, it then reads one byte from
standard input before starting its workers. Inline is registered as exactly
`PROBE_INLINE`, with no fallback.

Example commands from a build directory:

```powershell
.\sidefx_driver.exe --backend breakpoint -- .\sidefx_target.exe --no-wait
.\sidefx_driver.exe --backend hw         -- .\sidefx_target.exe --no-wait
.\sidefx_driver.exe --backend inline     -- .\sidefx_target.exe --no-wait
```

## Output JSON

For `N` iterations and `T` threads, the target emits one final row:

```json
{"kind":"target","name":"sidefx","iters":1000,"threads":4,"gpr_ok":4000,"xmm_ok":4000,"ymm_upper_ok":4000,"mxcsr_ok":4000,"df_ok":4000,"x87cw_ok":4000,"lasterror_ok":4000,"below_sp_ok":4000,"calls":4000}
```

Each `*_ok` number is the count of complete iterations whose named state matched.
After the target row, `probe_report` prints callback log rows, one probe row, and the
final `probe_report` row in the library's normal JSON-lines format.

## Exact pass criteria

Run every combination of architecture (`x64` and `Win32`) and backend (`breakpoint`,
`hw`, and `inline`). Let `calls = N * T`. A combination passes only if:

- the driver exits zero (and therefore the target exit recorded by UHH is zero);
- `gpr_ok`, `xmm_ok`, `ymm_upper_ok`, `mxcsr_ok`, `df_ok`, `x87cw_ok`, and
  `lasterror_ok` all equal `calls`;
- the single probe row names the requested backend and has `hits == calls`;
- the final `probe_report` row has `hits == calls`, `log_dropped == 0`,
  `app_exit == 0`, and `error == null`.

`below_sp_ok` is reported but is never part of pass/fail.

## CMake snippet

Paste this after `probe_api_agent` has been declared. The pointer-width branch mirrors
the repository's existing selection of separate `*_x64.asm` and `*_x86.asm` files.

```cmake
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(SIDEFX_ASM examples/sidefx/sidefx_sites_x86.asm)
    set(SIDEFX_SITE_EXPORT "/EXPORT:SideFxSite=_SideFxSite")
else()
    set(SIDEFX_ASM examples/sidefx/sidefx_sites_x64.asm)
    set(SIDEFX_SITE_EXPORT "/EXPORT:SideFxSite")
endif()

target_sources(probe_api_agent PRIVATE
    examples/sidefx/sidefx_callbacks.cpp)

add_executable(sidefx_target
    examples/sidefx/sidefx_target.c
    ${SIDEFX_ASM})
target_compile_features(sidefx_target PRIVATE c_std_11)
target_compile_options(sidefx_target PRIVATE /W4 /arch:AVX2)
target_link_options(sidefx_target PRIVATE
    ${SIDEFX_SITE_EXPORT}
    "/MAP:$<TARGET_FILE_DIR:sidefx_target>/sidefx_target.map")

add_executable(sidefx_driver
    examples/sidefx/sidefx_driver.cpp
    examples/sidefx/sidefx_callbacks.cpp)
target_include_directories(sidefx_driver PRIVATE include)
target_link_libraries(sidefx_driver PRIVATE probe_api)
set_target_properties(sidefx_driver PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES)
target_compile_options(sidefx_driver PRIVATE /W4)
target_compile_definitions(sidefx_driver PRIVATE _CRT_SECURE_NO_WARNINGS)
add_dependencies(sidefx_driver sidefx_target probe_api_agent)
```
