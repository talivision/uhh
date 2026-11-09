# Symbols

UHH performs symbol work in the controller. It registers each image with DbgHelp when
the image is observed, but uses deferred loading: the image, PDB, and any configured
symbol server are consulted only when a symbol is first resolved, displayed, or
enumerated. Probe callbacks do not run DbgHelp.

The implementation is in `src/probe/symbols.hpp` and `src/probe/symbols.cpp`. It uses
only Windows SDK declarations from `dbghelp.h`; it does **not** link `dbghelp.lib`.
Every DbgHelp entry point is obtained with `GetProcAddress`.

## Which DbgHelp is loaded

The copy of `dbghelp.dll` in System32 normally has no `symsrv.dll` beside it. It can
read images, exports, and local PDBs, but it cannot download from a symbol server. UHH
therefore searches in this order:

1. Windows 10 SDK Debugging Tools. UHH reads `KitsRoot10` from
   `HKLM\SOFTWARE\Microsoft\Windows Kits\Installed Roots` and its WOW6432Node form,
   then checks `Debuggers\x64` for an x64 controller or `Debuggers\x86` for a Win32
   controller.
2. The latest Visual Studio installation reported by
   `%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe -latest
   -property installationPath`. The installation is searched for a `dbghelp.dll`
   with `symsrv.dll` in the same directory. UHH does not assume that a TestPlatform
   extension directory is present or stable.
   The answer (a path, or none) is cached for a day in `%TEMP%\uhh\vs-dbghelp-<arch>.txt`
   (the lookup costs ~40 ms per controller); delete that file after installing Visual
   Studio to make UHH look again.
3. The system `dbghelp.dll` (System32 for x64, SysWOW64 for a Win32 controller on
   64-bit Windows), as a local-symbol-and-exports fallback.

For SDK and Visual Studio candidates, both DLLs' PE `Machine` fields must match the
controller: AMD64 for an x64 build and I386 for a Win32 build. DbgHelp must match the
controller process, not the target image. An x64 DbgHelp can still inspect a 32-bit
target when used by an x64 controller.

The selected DLL is loaded by absolute path with
`LoadLibraryExW(..., LOAD_WITH_ALTERED_SEARCH_PATH)`. This is important because
symbol-server support comes from the `symsrv.dll` beside that particular DbgHelp.
`active_dbghelp_path()` reports the selected DLL and `has_symbol_server()` says
whether the selected directory contained a matching `symsrv.dll`.

Installing the Windows SDK's **Debugging Tools for Windows** feature is the usual way
to obtain a symbol-server-capable pair. Falling back to System32 is not an error;
local PDB lookup, image symbols, and exports still work.

## Symbol path

Initialization calls:

```text
SymInitializeW(process, NULL, FALSE)
```

Passing a null search path deliberately leaves construction of the path to DbgHelp,
which honours the standard WinDbg environment variables:

- `_NT_ALT_SYMBOL_PATH`
- `_NT_SYMBOL_PATH`

UHH then appends the directory of every registered EXE or DLL. That makes a PDB next
to its image discoverable without replacing or reordering the path DbgHelp built from
the environment.

UHH never adds a network server. Downloads occur only when the user supplied an
`srv*...` element and a DbgHelp/symsrv pair was found. For example, in `cmd.exe`:

```bat
set _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
uhh_trace --list kernelbase.dll --mask *CreateFile*
```

For local symbols only:

```bat
set _NT_ALT_SYMBOL_PATH=D:\build\myapp;D:\private-symbols
set _NT_SYMBOL_PATH=C:\symbols
uhh_trace --list D:\build\myapp\myapp.exe --mask worker_*
```

The usual WinDbg syntax is passed through unchanged. For example,
`srv*C:\symbols*https://msdl.microsoft.com/download/symbols` uses `C:\symbols` as a
downstream cache, while `cache*C:\symbols;srv*https://...` is interpreted by DbgHelp
and symsrv according to their normal rules.

## Lookup and display

`register_module` calls `SymLoadModuleExW` with the image's real base and
`SizeOfImage`. Supplying the image size matters with deferred loading: it lets
DbgHelp associate every address in the mapping with the module before it opens the
image.

`resolve(process, module, name, address)` asks `SymFromNameW` for
`module!name`. It therefore resolves ordinary exports as well as functions that exist
only in a matching PDB. A failed lookup returns `false` and leaves `address`
unchanged.

`symbolize` tries progressively less specific forms:

```text
myapp!parse_config+0x12 (D:\src\config.cpp:87) [0x7ff612341052]
myapp+0x1052 [0x7ff612341052]
0x7ff612341052
```

`walk_stack` uses `StackWalk64`, `SymFunctionTableAccess64`, and
`SymGetModuleBase64`. Its first returned frame is always the supplied program counter;
later frames are callers recovered by DbgHelp. Target memory is cached by page for
one walk only. Formatted names are cached by address and cleared when modules are
registered or unregistered. The selected DbgHelp DLL stays loaded for the controller
process lifetime.

## Display names come from files

Probe export resolution separately reads the target's export tables and follows its
forwarders. DbgHelp supplies PDB lookup and display names from disk.

Each controller symbol session is two DbgHelp sessions:

- **Names** (`resolve`, `symbolize`, `containing_function`, `enumerate`): keyed by an
  opaque value that is not a process handle, so DbgHelp cannot read the target's address
  space. Every module is loaded, on first use, from its image file and its PDB on disk:
  PDB names when a PDB matches, otherwise the file's export table.
- **Walk** (`walk_stack` only): keyed by the real process handle, created on the first
  stack walk, holding the same modules and search path. `StackWalk64` unwinds the live,
  stopped target from its memory (on x64 it needs the `.pdata` there). It produces raw
  frame addresses only; they are named by the names session.

The rule exists because DbgHelp keyed by a process handle reads a deferred module's image
from the target's memory when the module is first used. If the memory there does not
match the file, the module ends up with the memory's exports under the file's name or with
no symbols at all (`SymNone`). Which happened depended on when a module was first used.
The `stacks` check, run on GitHub's Server 2022 runners, failed about one run in five
(x64 and x86): breakpoint and hw walks had loaded kernel32 at the hit and named a frame
`kernel32!BaseThreadInitThunk+0x10`. Inline stacks are named later, on the writer
thread, and the check's target exits right after its last hit. In those runs the same
frame came out as `kernel32+0x14f80`. DbgHelp reported the module loaded from
`C:\Windows\System32\kernel32.dll` with `SymType` none and no exports.

The rule is the same for every backend and does not depend on timing: a frame names
through the image file whenever it is symbolized. A module whose file is gone, for
example a DLL deleted after it loaded, gets no names and is shown as `module+offset`.
`regress.py symbols-file-backed` registers kernel32's file at the base where the target
maps ntdll and requires kernel32's names and `resolve` results. A memory-keyed session
gave ntdll's exports (Windows 10's DbgHelp) or none (the SDK's). The check also requires
kernel32's names on a first lookup after the target has exited.

## Stacks per backend (`send_log_stack`)

Every backend captures raw return addresses at the hit; the controller's log writer
symbolizes them as it writes the record, so the same callback logs the same stack. The walkers differ:

| Backend | x64 | x86 |
|---|---|---|
| breakpoint / hw | `StackWalk64` (controller, `.pdata`) | `StackWalk64` with the PDB's FPO / frame data, plus an `[esp]` return-address check at a function's first instruction |
| inline | `RtlVirtualUnwind` in the target; frame 0 is unwound by the agent from the hook's **original** bytes | verified return-address scan in the target (`walk_x86` in `src/probe/agent.cpp`) |

- **x64 inline, frame 0.** At a hooked site the code at `pc` is the hook's `jmp`.
  `RtlVirtualUnwind` reads that as a tail-call epilogue and takes `[rsp]` as the return
  address. The agent therefore unwinds the first frame itself: it runs the epilogue check
  on the original bytes and then interprets the function's `UNWIND_INFO` codes, chained
  entries included. Later frames are return addresses and go through `RtlVirtualUnwind`.
- **x86 inline.** The agent cannot read PDBs at a hit, so it scans the stack upward
  for return addresses. It ranks each candidate by the call instruction just before it:
  - **exact:** a direct `call` (`E8`, or `FF 15` through the IAT, with `E9` and `FF 25`
    thunks followed) whose target starts the function holding `pc`. "Starts the function"
    means the target is at most 256 KiB below `pc`, with no `CC CC` padding between them.
  - **unknown:** an indirect call.
  - **other:** a direct call to a different function.

  Within each frame it takes the lowest exact slot first. In frame 0 only, it next
  takes `[esp]` if the bytes before it encode a call; this is the rule the controller
  applies after dbghelp, and it covers a site at a function's first instruction reached
  by `call reg`. Failing that, it takes `[ebp+4]` if EBP still points to a frame above
  the stack pointer, then the lowest unknown slot, then the lowest other. This handles frames without a frame pointer
  (`/Oy`), functions that hold data in EBP, mid-function sites and leaves without any
  unwind data.

  Stack reads stay inside the thread's TEB stack bounds. Code and import-table reads stay inside regions that
  `VirtualQuery` reported committed and readable; that cache is built per capture and
  never reused across hits, so changed code protections are respected without touching
  guard or inaccessible pages. Stack bounds come from the TEB without a query. Each
  capture retains up to 128 queried regions and memoizes return-address classifications;
  each frame scans at most 16 KiB. Protection changes during a capture follow the
  [memory-check contract](api.md#int-get_memprobe_context-c-uint64_t-address-void-buffer-size_t-size).
- **Frame 0** is the probe site on every backend (`pc` of the hit), never the agent's
  own frames.

`regress.py`'s `stacks` check runs `examples/stacks` under all three backends. It probes
a site mid-function in a function with a frame pointer, a site in a function without a
frame pointer that stores data in EBP/RBP, and a leaf. Each chain is reached through
optimised C callers built with `/Oy` on x86. The check requires `<site>, stk_outer_<x>,
main` and identical symbolized stacks (addresses stripped) across backends on x64 and
x86, all the way to `ntdll`.

Remaining differences (x86 inline only; dbghelp uses the PDB and is unaffected):

- A function without a frame pointer that was reached by an **indirect call or a tail
  jump**, while EBP still points to an ancestor's frame, cannot be verified. The scan
  then trusts `[ebp+4]` and omits that function's immediate caller.
- Uninitialised locals holding stale return addresses can win over an unverifiable
  true slot. They never win over a slot that verifies as exact.
- A frame larger than 16 KiB without a frame pointer ends the walk.
- x64 inline: only frame 0 is unwound from the original bytes. A return address that
  lands inside ANOTHER inline hook's patched bytes would go through `RtlVirtualUnwind`
  over live code. The site check refuses hooks over a call's return point, so this needs
  a probe placed by `PROBE_ALLOW_UNSAFE_SITE`.

`enumerate` uses `SymEnumSymbolsW`. Its mask is a DbgHelp wildcard such as `*`,
`*Create*`, or `worker_*`. Each result contains its name, absolute address, size, and
whether DbgHelp set `SYMFLAG_EXPORT`. PDB-only symbols have `export` set to `false`.

## Listing a module without launching a target

`uhh_trace --list` creates an isolated DbgHelp session using an opaque fake handle,
registers the image at a synthetic base, and emits one JSON object per symbol. It does
not start, attach to, or invade a process.

```bat
uhh_trace --list kernelbase.dll --mask *CreateFile*
uhh_trace --list C:\work\bin\parser.dll --mask parse_*
```

Example output (the `rva` and `size` values are JSON numbers):

```json
{"kind":"symbol","name":"CreateFileW","rva":123456,"size":42,"export":true}
{"kind":"symbol","name":"parse_internal","rva":8192,"size":96,"export":false}
```

When the argument is only a filename, the x64 build searches System32 and the Win32
build searches SysWOW64 on 64-bit Windows (System32 on 32-bit Windows). A path is used
as given after conversion to an absolute path. The image's PE machine type must match
the `uhh_trace` build.

## API summary

- `init` loads DbgHelp once, configures non-interactive deferred symbol and line
  loading, and initializes a session without invading the process.
- `register_module` adds an image mapping and its directory to the symbol search path.
- `resolve` resolves `module!name` to an absolute address.
- `symbolize` formats an address with the best available module, symbol, and line data.
- `walk_stack` returns raw frame addresses beginning with the supplied PC.
- `enumerate` lists symbols matching a DbgHelp wildcard.
- `cleanup` releases one DbgHelp symbol session.
- `active_dbghelp_path` and `has_symbol_server` describe the process-wide DbgHelp
  selected by UHH.

All functions serialize access because DbgHelp itself is single-threaded. Failures
return `false`, an empty value, or the numeric address fallback; exceptions do not
cross the module boundary.
