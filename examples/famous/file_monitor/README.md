# File-activity monitor (Process Monitor lite)

## The original recipe

Process Monitor's File System view with a "Path contains" filter, or the Frida tracer:

```js
const paths = {};
Interceptor.attach(Module.getExportByName('ntdll.dll', 'NtCreateFile'), {
  onEnter(args) {
    const oa = args[2];
    const name = oa.add(Process.pointerSize * 2).readPointer();   // ObjectName
    this.path = name.add(Process.pointerSize).readPointer()       // Buffer
                    .readUtf16String(name.readU16() / 2);         // Length (bytes)
    this.ph = args[0];
  },
  onLeave(status) { if (status.toInt32() >= 0) paths[this.ph.readPointer()] = this.path; }
});
['NtReadFile', 'NtWriteFile'].forEach(f => Interceptor.attach(Module.getExportByName('ntdll.dll', f), {
  onEnter(args) { console.log(f, paths[args[0]], args[6].toInt32()); }
}));
```

## UHH mapping (`file_callbacks.cpp`)

| Frida | UHH |
|---|---|
| `OBJECT_ATTRIBUTES -> UNICODE_STRING` | `famous_read_object_name`: `get_mem` of `ObjectName` at `oa + 2*ptr`, then `{Length, Buffer}` at `+0` / `+ptr` (layout correct on x64 and x86) |
| `this.ph` / `this.path` | `famous_pending_put` keyed by the return-site SP (x86: `NtCreateFile` is stdcall with 11 args, so `SP + 4 + 44`) |
| `onLeave` | `famous_file_on_create_return` at the `NtCreateFile` call site (in KernelBase): NTSTATUS in `AX`; `*PHANDLE` via `get_mem` -> `UHH_SHARED` handle map |
| `NtReadFile`/`NtWriteFile` `onEnter` | `file-read` / `file-write path= handle= len=` (requested `Length`, arg 6) |
| Procmon "Path contains" filter | `--filter text`: only matching creates are tracked; reads/writes on unmatched handles are skipped |

Handles opened another way (`NtOpenFile`, inherited stdio) log `path=?` when unfiltered.

## Hardware backend and the four debug registers

Unfiltered, every distinct `NtCreateFile` call site in the process needs its own return
probe. With three entry probes that leaves one debug register: the second call site is
refused (`return-site ... REFUSED`, `too many hardware probes (max 4 DR slots)`) and the
opens through it are untracked. With `--filter` only the program's file opens arm a
return site (KernelBase `CreateFileInternal`), which fits. Breakpoint and inline have no
such limit (inline: 128 probes per session).

## Targets and expected results

- `famous_file_target <dir> --threads 3 --chunks 20`: thread k writes `t<k>.dat` in 20
  `WriteFile`s of `4096+100k` bytes, reads it back in 20 `ReadFile`s; main writes
  `summary.txt` through the CRT (one buffered write at `fclose`). Per file, the logged call
  counts and byte totals must equal the ground truth the target prints. Also run with
  `--delay-ms 2500` while `famous_driver --attach-new famous_file_target.exe` waits: the
  attach lands mid-run, before the workload, and the totals must still be exact.
- `findstr.exe UHHNEEDLE haystack.txt` (a real system binary): the open must be logged with
  status 0 and findstr's output unchanged (it reads the file without `NtReadFile`).
- `cmd.exe /d /c type haystack.txt`: open + `NtReadFile`s covering the file size.

```powershell
famous_driver --recipe files --backend hw --filter uhh_famous -- famous_file_target.exe $env:TEMP\uhh_famous\demo
```
