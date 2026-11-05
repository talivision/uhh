# Inline-hook breakage fixtures

`hook_edge` is intentionally hostile code. Its public MASM
labels are map-file landmarks; the driver still addresses every probe as
`hook_edge.exe+0xRVA`. `breakage_driver` gives every row a fresh target/session so
an expected inline-install failure or target fault cannot hide later rows.

The driver calls `probe_report` into a temporary stream and emits one summary JSON
line per case. `install_ok` means every registration in that row became active;
`hits` is their sum; `app_exit` and `error` come from the report.

Every row has ONE required outcome (`required`), and the driver exits non-zero if any
row's `verdict` differs:

- `pass`: every probe installed, each hit exactly once, and the target's own result
  check passed (exit 0 -- the same as an uninstrumented run).
- `refused`: UHH refused the probe with a reason (the report's `error`), nothing was
  hit, and the target was not corrupted (it never ran its case).
- `broken`: anything else (wrong return value, fault, missed or extra hit). Never allowed.

| Row | Required |
|---|---|
| every breakpoint / hw control (10 rows) | `pass` |
| `ShortSite` inline | `refused` (5-byte patch would run past the `ret`) |
| `PrehookSite` inline + `PROBE_ALLOW_PREHOOKED` | `pass` (chains: 1017) |
| `PrehookSite` inline (default) | `pass`: the `E9` is in the image FILE too, so live == disk and it is not a pre-hook; relocated and chained (1017) |
| `PrehookSite` inline + `PROBE_FALLBACK_HW` | `pass` (moved to hw) |
| `UnrelocSite` inline | `refused` (`jrcxz`/`jecxz` is rel8-only: the hook engine cannot relocate it; it used to crash the target) |
| `StackSite` twice, inline | `refused` (second hook overlaps the first) |
| `StackSite` + `StackInsideSite`, inline | `refused` (inner site inside the outer hook) |

The descriptions below explain why each site is hostile.

## Cases

1. **Short site (`ShortSite`).** The label is `xor eax,eax; ret`: only two bytes of
   ordinary code exist before a control-flow boundary. A five-byte inline jump
   cannot be installed without stealing `ret` and bytes belonging to the next
   function. Inline: `refused` by the site check (the patch would run past the
   `ret`). An individual INT3 or DR execute breakpoint needs no five-byte region and
   must report one hit with exit code zero.

2. **Already hooked / over the top (`PrehookSite`).** The mapped entry begins with
   a real `E9 rel32` to `ForeignReplacement`, so even a probe armed at the early
   `CREATE_PROCESS` event sees the foreign detour. A loader TLS callback copies a
   saved five-byte pristine body into an executable trampoline and rewrites the
   same foreign `E9` when it still owns the entry. If an INT3 was armed first it
   preserves byte zero while refreshing the displacement; if an inline hook was
   installed first it leaves those bytes alone. The replacement counts calls, invokes that trampoline,
   and adds 1000 to the original result. UHH therefore sees `E9`, not the pristine
   prologue. If its inline relocator accepts a foreign detour, execution is:
   UHH detour -> UHH callback -> UHH trampoline's relocated foreign `E9` -> foreign
   replacement -> foreign trampoline -> `PrehookSite+5`. Exact expected result is
   one UHH hit, one foreign hit, and return value 1017 (`pass`). The `E9` is also in
   the image file, so live == disk: UHH does not see a pre-hook here and chains with
   or without `PROBE_ALLOW_PREHOOKED`. Breakpoint/HW controls stop on the foreign
   `E9` and must preserve the same result.

3. **Un-relocatable prologue (`UnrelocSite`).** The first instruction is
   `JRCXZ rel8` on x64 or `JECXZ rel8` on x86. Those instructions have no wider
   relative encoding. Copying their two bytes to a remote trampoline preserves the
   displacement but changes its base, so the taken edge no longer reaches
   `UnrelocZero`; the target then faults (observed: the hook engine copies it
   as is). Inline: `refused` by the site check (`[reloc]`). Breakpoint uses UHH's in-place control-flow step and HW uses RF, so each control
   must hit once and return 77.

4. **Stacked UHH (`StackSite`).** The driver submits two `PROBE_INLINE` requests at
   the identical address, in order, with distinct exported callbacks. There is no
   public stacking contract: the second would relocate the first one's jump, and
   removing either restores bytes under the other. Inline: the second is `refused`
   (overlapping patch).

5. **Probe inside stolen bytes (`StackSite` + `StackInsideSite`).** The inner label
   is two bytes after the outer label and therefore lies inside the outer detour's
   minimum five-byte stolen region. The outer hook is installed first. Installing
   at the inner RVA subsequently decodes patched jump payload rather than the
   original NOP stream, or the outer trampoline bypasses the original inner
   address. Inline: the inner probe is `refused` (overlapping patch). The controls
   probe each label
   separately—never stack INT3/DR state—and each must hit once.

The ten control rows cover all five labels once with `PROBE_BREAKPOINT` and once
with `PROBE_HW`; each must `pass`. UHH refuses an inline probe whose patch would
overlap another inline probe's patch (same address included) -- or moves it to a debug
register with `PROBE_FALLBACK_HW`. Usage/setup errors exit 2.

## Build and run

Run these commands from the repository root in a Visual Studio developer shell.
The map is emitted beside the selected configuration's executable.

### x64

```powershell
cmake -S . -B build-breakage-x64 -A x64
cmake --build build-breakage-x64 --config Release --target breakage_driver
$r = (python scripts/site_rvas.py build-breakage-x64\Release\hook_edge.map ShortSite PrehookSite UnrelocSite StackSite StackInsideSite | Out-String | ConvertFrom-Json)
build-breakage-x64\Release\breakage_driver.exe build-breakage-x64\Release\hook_edge.exe $r.ShortSite $r.PrehookSite $r.UnrelocSite $r.StackSite $r.StackInsideSite
```

### Win32

```powershell
cmake -S . -B build-breakage-x86 -A Win32
cmake --build build-breakage-x86 --config Release --target breakage_driver
$r = (python scripts/site_rvas.py build-breakage-x86\Release\hook_edge.map ShortSite PrehookSite UnrelocSite StackSite StackInsideSite | Out-String | ConvertFrom-Json)
build-breakage-x86\Release\breakage_driver.exe build-breakage-x86\Release\hook_edge.exe $r.ShortSite $r.PrehookSite $r.UnrelocSite $r.StackSite $r.StackInsideSite
```

The DLL containing inline callbacks is built as a dependency and must remain next
to the driver (`probe_api_agent.dll`). The target path is the first argument. No RVA is compiled into either binary.
