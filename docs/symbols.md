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
later frames are callers recovered by DbgHelp.

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
