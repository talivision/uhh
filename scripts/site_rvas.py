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


def parse_map(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    m = re.search(r"Preferred load address is ([0-9A-Fa-f]+)", text)
    if not m:
        raise SystemExit(f"{path}: no preferred load address")
    base = int(m.group(1), 16)
    rvas = {}
    # Lines: " 0001:00000000  Symbol  0000000180001000 f  obj"
    row = re.compile(r"^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\b")
    for line in text.splitlines():
        m = row.match(line)
        if m:
            rvas.setdefault(m.group(1), int(m.group(2), 16) - base)
    return rvas


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    rvas = parse_map(sys.argv[1])
    out = {}
    for sym in sys.argv[2:]:
        # MSVC decorates __cdecl C symbols with a leading underscore on x86 only;
        # x64 public names are undecorated, but accept either.
        name = sym if sym in rvas else "_" + sym
        if name not in rvas:
            raise SystemExit(f"{sys.argv[1]}: symbol {sym} not found")
        out[sym] = rvas[name]
    json.dump(out, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
