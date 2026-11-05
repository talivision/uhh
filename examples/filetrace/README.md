# filetrace: which files does a program open and write?

```sh
filetrace [--backend b] [--create-backend b] [--write-backend b] [--close-backend b] \
          [--filter TEXT] -- <target.exe> [args]          # b = breakpoint | hw | inline
filetrace --filter uhhft -- filetrace_target.exe --dir %TEMP%\uhhft
```

Three probes on ntdll syscall stubs, so every caller is seen (CreateFileW, fopen, a direct
`NtCreateFile`):

- `ft_on_create` on `ntdll!NtCreateFile`: the path is in the arguments, the handle exists
  only after the call. The callback reads the path, runs the real open with
  `call_original(c, 11, &status)`, reads the handle from `*FileHandle`, maps handle -> path
  and logs `create path=.. access=.. status=.. handle=..`, then hands the program the
  real status with `return_from(c, status, 11)` (x86: `NtCreateFile` is `__stdcall`, 11
  stack arguments). A failing open is logged with its status and no handle, and the
  program sees exactly that status.
- `ft_on_write` on `ntdll!NtWriteFile`: `write path=.. handle=.. len=.. offset=..`
  (`offset=-1`: at the file pointer; overlapped writes carry their offset).
- `ft_on_close` on `ntdll!NtClose`: forgets the handle (values are reused).

The map is `UHH_SHARED`, so the probes may use different backends. All three on `hw` fit:
3 debug registers, and the fourth stays free for `call_original`.

`filetrace_target` is the fixture: threads create/write/close files (odd files with
overlapped I/O), make four kinds of failing open, and read everything back. It prints its
own ground truth (`ft_open`, `ft_fail`, `ft_file`, `ft_done`); regress `newapp-file-*`
compares the tool's log with it under every backend and in mixes.
