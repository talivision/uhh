# flagflip: turn on a feature flag that is a C++ virtual method

```sh
flagflip [--backend b] [--mode force|modify] [--feature NAME] <location> -- <target.exe> [args]
flagflip --mode modify --feature beta flagfeature.dll!Feature::IsEnabled -- flagflip_target.exe
```

`flagfeature.dll` ships `class Feature { virtual bool IsEnabled() const; ... }` and every
feature is off. `flagflip_target` creates "alpha" and "beta" and, from several threads, runs
a gated path only when `IsEnabled()` says so.

- **Location.** The method is not exported. `flagfeature.dll!Feature::IsEnabled` is found
  in `flagfeature.pdb` beside the DLL; the probe stays pending until the target late-loads
  the DLL.
- **`this`.** A member function receives `this` in CX: `ECX` on x86 (`__thiscall`), `RCX`
  on x64 (the first argument). Use `get_reg(c, PROBE_REG_CX)`, the same source on both. Do
  not use `get_func_arg(c, 0)`: on x86 it is the first stack argument. The callback reads
  the object's name through `this` and acts only on `--feature`.
- **force:** `return_from(c, 1, 0)`, so the original does not run (a `__thiscall` method
  with no arguments pops nothing).
  **modify:** `call_original(c, 0, &orig)` runs it, the log shows `original=0`, and
  `return_from(c, 1, 0)` returns true instead. Only `AL` is defined for a `bool`.

Regress `newapp-flag-<backend>-<mode>` checks the target's own counters: beta's gated path
ran on every call and alpha's never. It also checks that every log names the object the
target created (`this`).
