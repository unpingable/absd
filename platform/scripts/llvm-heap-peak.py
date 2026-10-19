#!/usr/bin/env python3
"""Peak heap of one traced process, from `strace -f -e trace=brk,mmap,munmap,
mremap,openat,close` output (scripts/build-llvm-kit.sh, twin step).

Heap = the program break's growth since its first value plus every live
anonymous private mapping (glibc's large-block malloc), excluding thread
stacks (MAP_STACK) and PROT_NONE reservations. File mappings are not heap
and are counted apart (the ABSD port reads files into the heap instead, so
on the twin built with LLVM_ABSD_KIT there should be none).
Prints: heap_peak_bytes=N brk_growth_peak=N file_map_bytes=N openat_ok=N
peak_open_fds=N
"""
import re, sys

brk0 = None; cur = 0; brk_peak = 0; anon = {}; peak = 0; file_maps = 0
fds = set(); fd_peak = 0; ok_opens = 0
for line in open(sys.argv[1]):
    m = re.search(r'brk\((?:\w+)\)\s*=\s*(0x[0-9a-f]+)', line)
    if m:
        v = int(m.group(1), 16)
        if brk0 is None:
            brk0 = v
        cur = v
        brk_peak = max(brk_peak, cur - brk0)
    m = re.search(r'mmap\((?:NULL|0x[0-9a-f]+), (\d+), ([^,]+), ([^,]+), (-?\d+), [^)]*\)\s*=\s*(0x[0-9a-f]+)', line)
    if m:
        size, prot, flags, fd, addr = int(m.group(1)), m.group(2), m.group(3), int(m.group(4)), int(m.group(5), 16)
        if 'MAP_ANONYMOUS' in flags and 'MAP_STACK' not in flags and 'PROT_NONE' not in prot:
            anon[addr] = size
        elif fd >= 0:
            file_maps += size
    m = re.search(r'munmap\((0x[0-9a-f]+), (\d+)\)\s*=\s*0', line)
    if m:
        a, n = int(m.group(1), 16), int(m.group(2))
        for k in list(anon):
            if k <= a < k + anon[k]:
                if a == k:
                    anon[k] -= n
                else:
                    anon[k] = a - k
                if anon[k] <= 0:
                    del anon[k]
    peak = max(peak, (cur - brk0 if brk0 is not None else 0) + sum(anon.values()))
    m = re.search(r'openat\([^"]*"[^"]*"[^)]*\)\s*=\s*(\d+)', line)
    if m:
        ok_opens += 1; fds.add(int(m.group(1))); fd_peak = max(fd_peak, len(fds))
    m = re.search(r'close\((\d+)\)\s*=\s*0', line)
    if m:
        fds.discard(int(m.group(1)))
print(f"heap_peak_bytes={peak} brk_growth_peak={brk_peak} file_map_bytes={file_maps} openat_ok={ok_opens} peak_open_fds={fd_peak}")
