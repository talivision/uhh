# Inline-hook breakage fixtures

`hook_edge` is intentionally hostile code, not a correctness test. Its public MASM
labels are map-file landmarks; the driver still addresses every probe as
`hook_edge.exe+0xRVA`. `breakage_driver` gives every row a fresh target/session so
an expected inline-install failure or target fault cannot hide later rows.

The driver calls `probe_report` into a temporary stream and emits one summary JSON
line per case. `install_ok` means every registration in that row became active;
`hits` is their sum. A target exit mismatch is folded into `verdict` because that is
how relocation corruption is distinguished from a harmless install.

## Cases

1. **Short site (`ShortSite`).** The label is `xor eax,eax; ret`: only two bytes of
   ordinary code exist before a control-flow boundary. A five-byte inline jump
   cannot be installed without stealing `ret` and bytes belonging to the next
   function. Expected inline result: installer rejection, an inactive probe, or no
   hit (`expected_breakage`). A clean inline hit is deliberately reported as
   `unexpected_inline_success`. An individual INT3 or DR execute breakpoint needs
   no five-byte region and must report one hit with exit code zero.

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
   one UHH hit, one foreign hit, and return value 1017
   (`foreign_then_uhh_chain_ok`). Rejection, recursion, a missed callback, or a bad
   return is `prehook_chain_broken`. Breakpoint/HW controls stop on the foreign
   `E9` and must preserve the same result.

3. **Un-relocatable prologue (`UnrelocSite`).** The first instruction is
   `JRCXZ rel8` on x64 or `JECXZ rel8` on x86. Those instructions have no wider
   relative encoding. Copying their two bytes to a remote trampoline preserves the
   displacement but changes its base, so the taken edge no longer reaches
   `UnrelocZero`; the target then returns the wrong value or faults. Exact naive
   inline failure is zero hits/install rejection, a nonzero target exit, or a
   fault. A relocator that expands or otherwise retargets this branch may correctly
   produce one hit and return 77; that is labelled `relocated_safely`, not hidden.
   Breakpoint uses UHH's in-place control-flow step and HW uses RF, so each control
   must hit once and return 77.

4. **Stacked UHH (`StackSite`).** The driver submits two `PROBE_INLINE` requests at
   the identical address, in order, with distinct exported callbacks. There is no
   public stacking contract. Expected failure is rejection of the second install
   or fewer than two total hits (`expected_stack_breakage`). If both callbacks run
   exactly once and the target still returns 8, the row says
   `unexpected_clean_stack`; this is useful evidence that the current underlying
   hook engine happened to compose the detours.

5. **Probe inside stolen bytes (`StackSite` + `StackInsideSite`).** The inner label
   is two bytes after the outer label and therefore lies inside the outer detour's
   minimum five-byte stolen region. The outer hook is installed first. Installing
   at the inner RVA subsequently decodes patched jump payload rather than the
   original NOP stream, or the outer trampoline bypasses the original inner
   address. Expected result is a rejected/inactive inner probe, fewer than two
   hits, or a broken target (`expected_overlap_breakage`). A fully correct two-hit
   run is explicitly `unexpected_clean_overlap`. The controls probe each label
   separately—never stack INT3/DR state—and each must hit once.

The ten control rows cover all five labels once with `PROBE_BREAKPOINT` and once
with `PROBE_HW`. They should all have `install_ok:true`, `hits:1`, and verdict
`pass`. Inline rows are observations of intentionally unsupported edge cases; the
driver exits zero after emitting them even when their verdict contains “breakage.”
Usage/setup errors still exit nonzero.

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
