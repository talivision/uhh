#!/usr/bin/env python3
"""Extract symbol RVAs from an MSVC linker .map file.

Build tooling for deferred module+RVA probes: the controller registers
`configparse.dll+<rva>` before the DLL loads, so the RVA must come from the build,
not from the live target. Usage:

    site_rvas.py <file.map> SYM [SYM ...]      -> JSON {sym: rva}
"""
import json
import re
import sys


def _undecorate(name):
    # x86 MSVC decoration: __cdecl/data -> _Name, __stdcall -> _Name@N,
    # __fastcall -> @Name@N. Strip it to the bare C name. x64 names are already
    # bare, so this is a no-op there.
    base = name[1:] if name[:1] in ("_", "@") else name
    at = base.rfind("@")
    if at > 0 and base[at + 1:].isdigit():
        base = base[:at]
    return base


def parse_map(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    m = re.search(r"Preferred load address is ([0-9A-Fa-f]+)", text)
    if not m:
        raise SystemExit(f"{path}: no preferred load address")
    base = int(m.group(1), 16)
    rvas = {}       # exact map name -> rva
    undec = {}      # decoration-stripped name -> rva (x86 _Name / _Name@N)
    # Lines: " 0001:00000000  Symbol  0000000180001000 f  obj" (x64, 16-hex addr)
    #        " 0001:00000000  _Symbol        10001000 f  obj" (x86, 8-hex addr)
    row = re.compile(r"^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{8,16})\b")
    for line in text.splitlines():
        m = row.match(line)
        if m:
            rva = int(m.group(2), 16) - base
            rvas.setdefault(m.group(1), rva)
            undec.setdefault(_undecorate(m.group(1)), rva)
    return rvas, undec


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    rvas, undec = parse_map(sys.argv[1])
    out = {}
    for sym in sys.argv[2:]:
        # Prefer an exact hit (x64 bare name), then the common x86 forms, then any
        # map symbol whose stripped decoration matches (e.g. _ReadThunk@20).
        if sym in rvas:
            out[sym] = rvas[sym]
        elif "_" + sym in rvas:
            out[sym] = rvas["_" + sym]
        elif sym in undec:
            out[sym] = undec[sym]
        else:
            raise SystemExit(f"{sys.argv[1]}: symbol {sym} not found")
    json.dump(out, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
