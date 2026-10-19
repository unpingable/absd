#!/usr/bin/env python3
"""Relocation types, TLS sections and undefined symbols of a static archive.

Relocations in .rela.debug_* sections are not counted: DWARF offsets use
R_X86_64_32 by design and debug sections are never loaded.
"""
import collections, re, subprocess, sys

archive = sys.argv[1]
relocs = subprocess.run(["readelf", "-rW", archive], capture_output=True, text=True, check=True).stdout
counts, debug = collections.Counter(), False
for line in relocs.splitlines():
    header = re.match(r"Relocation section '([^']+)'", line)
    if header:
        debug = header.group(1).startswith(".rela.debug_")
        continue
    m = re.search(r"\bR_X86_64_[A-Z0-9_]+", line)
    if m and not debug:
        counts[m.group(0)] += 1
sections = subprocess.run(["readelf", "-SW", archive], capture_output=True, text=True, check=True).stdout
tls = sorted(set(re.findall(r"\.t(?:data|bss)[.\w]*", sections)))
undefined = subprocess.run(["llvm-nm-18", "-u", "--no-sort", archive], capture_output=True, text=True, check=True).stdout
names = sorted({line.split()[-1] for line in undefined.splitlines() if line.strip() and not line.endswith(":")})
for kind, count in sorted(counts.items()):
    print(f"{kind}\t{count}")
print(f"TLS SECTIONS: {' '.join(tls) if tls else 'none'}")
print(f"UNDEFINED: {' '.join(names)}")
