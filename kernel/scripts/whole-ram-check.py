#!/usr/bin/env python3
"""Host oracle for `make whole-ram-test` (docs/x86-whole-ram-20261015).

Recomputes, from the memory map and reservations the kernel printed, what
the allocator must track and hold free, independently of the kernel's
arithmetic, and checks every count the boot disclosed against it.
"""

import argparse
import re
import struct
import sys

PAGE = 4096
TWO_MIB = 2 << 20
ONE_GIB = 1 << 30
FOUR_GIB = 4 << 30
BUILT_IN_LIMIT = 256 << 20
BOUND = 64 << 30
BUILT_IN_FRAMES = BUILT_IN_LIMIT // PAGE
# main.rs's page-map round trips remap this window; the table avoids it.
PAGE_TEST_WINDOW = (0x2000_0000, 0x2040_0000)


def die(message):
    print(f"whole-ram-check: {message}", file=sys.stderr)
    sys.exit(1)


def need(condition, message):
    if not condition:
        die(message)


def down(value, unit):
    return value // unit * unit


def up(value, unit):
    return -(-value // unit) * unit


def merge(intervals):
    out = []
    for start, end in sorted(i for i in intervals if i[0] < i[1]):
        if out and start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return [tuple(i) for i in out]


def length(intervals):
    return sum(end - start for start, end in intervals)


def intersect(a, b):
    out = []
    for s1, e1 in a:
        for s2, e2 in b:
            if max(s1, s2) < min(e1, e2):
                out.append((max(s1, s2), min(e1, e2)))
    return merge(out)


def subtract(a, b):
    out = []
    for start, end in a:
        pieces = [(start, end)]
        for s2, e2 in b:
            pieces = [p for s, e in pieces for p in ((s, min(e, s2)), (max(s, e2), e)) if p[0] < p[1]]
        out += pieces
    return merge(out)


def count_aligned(intervals, unit):
    return sum(max(0, (end - 1) // unit - up(start, unit) // unit + 1) for start, end in intervals if end > start)


def kernel_image(path):
    """[__kernel_start, __kernel_end) from the ELF symbol table of the very
    kernel the ISO boots, and the PT_LOAD span it must cover."""
    data = open(path, "rb").read()
    need(data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1, f"{path}: not ELF64 LE")
    phoff, shoff = struct.unpack_from("<QQ", data, 0x20)
    phentsize, phnum, shentsize, shnum = struct.unpack_from("<HHHH", data, 0x36)
    loads = []
    for i in range(phnum):
        kind, _, _, _, paddr, _, memsz, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
        if kind == 1 and memsz:
            loads.append((paddr, paddr + memsz))
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    symbols = {}
    for _, kind, _, _, offset, size, link, _, _, entsize in sections:
        if kind != 2:  # SHT_SYMTAB
            continue
        strtab = sections[link]
        for j in range(size // entsize):
            name, _, _, _, value, _ = struct.unpack_from("<IBBHQQ", data, offset + j * entsize)
            start = strtab[4] + name
            symbols[data[start:data.index(b"\0", start)].decode()] = value
    need("__kernel_start" in symbols and "__kernel_end" in symbols, f"{path}: no __kernel_start/__kernel_end")
    image = (symbols["__kernel_start"], symbols["__kernel_end"])
    need(loads and image[0] <= min(l[0] for l in loads) and max(l[1] for l in loads) <= up(image[1], PAGE),
         f"kernel symbols {image} do not cover PT_LOAD {loads}")
    return image


def place(size, rows, exclusions):
    """Lowest page-aligned start of `size` bytes in one usable row below
    1 GiB, overlapping no exclusion (the kernel's placement rule)."""
    candidates = sorted({up(e, PAGE) for _, e in exclusions} | {up(s, PAGE) for s, _ in rows})
    for at in candidates:
        end = at + size
        if end <= ONE_GIB and any(s <= at and end <= e for s, e in rows) \
                and not any(s < end and at < e for s, e in exclusions):
            return at
    return None


def ram_bytes(text):
    match = re.fullmatch(r"(\d+)([MG])", text)
    need(match, f"bad --ram {text}")
    return int(match[1]) << (20 if match[2] == "M" else 30)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ram", required=True)
    parser.add_argument("--kernel", required=True, help="the ELF the ISO boots")
    parser.add_argument("--cut", action="append", default=[],
                        help="START-END removed from the map by GRUB cutmem (hex)")
    parser.add_argument("--fragmented", action="store_true",
                        help="require several usable rows above 4 GiB and an unaligned edge above 1 GiB")
    parser.add_argument("serial")
    args = parser.parse_args()
    ram = ram_bytes(args.ram)
    lines = open(args.serial, encoding="utf-8", errors="replace").read().splitlines()

    for marker in ["ABSD KERNEL BOOT", "HEAP OK", "WHOLE RAM TEST OK", "USER INIT STARTED",
                   "USERSPACE BOOTSTRAP OK", "ABSD BOOT OK"]:
        need(marker in lines, f"missing line {marker!r}")
    for line in lines:
        need("PANIC" not in line and "KERNEL FAULT" not in line, f"unexpected line {line!r}")

    rows = [(int(m[1], 16), int(m[2], 16)) for m in
            (re.fullmatch(r"WHOLE RAM MAP usable start=0x([0-9a-f]+) end=0x([0-9a-f]+)", l) for l in lines) if m]
    disclosed = [(m[3], int(m[1], 16), int(m[2], 16)) for m in
                 (re.fullmatch(r"WHOLE RAM RESERVED start=0x([0-9a-f]+) end=0x([0-9a-f]+) kind=(\w+)", l)
                  for l in lines) if m]
    need(rows and disclosed, "no map or reservation disclosure")

    def one(pattern):
        found = [m for m in (re.fullmatch(pattern, l) for l in lines) if m]
        need(len(found) == 1, f"expected exactly one line matching {pattern!r}, found {len(found)}")
        return found[0]

    tracked_line = one(r"FRAMES TRACKED usable=(\d+) limit=(\d+) clipped=(\d+) bound=(\d+) "
                       r"table=(\S+) direct_map_pages=(\d+)")
    free_line = one(r"free frames: (\d+)")
    alloc = one(r"WHOLE RAM ALLOC frames=(\d+) start_free=(\d+) above_256m=0x([0-9a-f]+) "
                r"above_4g=0x([0-9a-f]+) highest=0x([0-9a-f]+) written=(\d+) verified=(\d+)")
    freed = one(r"WHOLE RAM FREE free=(\d+) allocated=(\d+)")
    placement = one(r"WHOLE RAM USER PLACEMENT pinned=(\d+) next=0x([0-9a-f]+)")

    # The map itself: QEMU's -m, less firmware holes and the cutmem ranges,
    # some of it above 4 GiB.
    cuts = [tuple(int(x, 16) for x in c.split("-")) for c in args.cut]
    for s, e in cuts:
        need(not any(rs < e and s < re_ for rs, re_ in rows), f"usable row overlaps cutmem {s:#x}-{e:#x}")
        need(any(re_ == s for _, re_ in rows) and any(rs == e for rs, _ in rows),
             f"cutmem {s:#x}-{e:#x} is not a hole between two usable rows")
    cut_bytes = sum(e - s for s, e in cuts)
    usable_bytes = sum(max(0, down(e, PAGE) - up(s, PAGE)) for s, e in rows)
    need(ram - cut_bytes - (4 << 20) <= usable_bytes <= ram - cut_bytes,
         f"map has {usable_bytes} usable bytes for -m {args.ram} less {cut_bytes} cut")
    need(any(e > FOUR_GIB for _, e in rows), "no usable RAM above 4 GiB in the map")
    if args.fragmented:
        need(sum(1 for s, _ in rows if s >= FOUR_GIB) >= 3, "high map is not fragmented")
        need(any(x >= ONE_GIB and x % TWO_MIB for r in rows for x in r), "no unaligned row edge above 1 GiB")

    # What must be tracked: 4 KiB pages below 1 GiB, whole 2 MiB pages from
    # 1 GiB to the bound.
    parts = []
    for s, e in rows:
        parts.append((up(s, PAGE), min(down(e, PAGE), ONE_GIB)))
        parts.append((up(max(s, ONE_GIB), TWO_MIB), down(min(e, BOUND), TWO_MIB)))
    tracked = merge(parts)
    end = tracked[-1][1]
    need(end > BUILT_IN_LIMIT, "test map fits the built-in table")
    usable, limit, clipped, bound, table, mapped = tracked_line.groups()
    need(int(bound) == BOUND, f"bound {bound}")
    need(table == "boot", f"table={table}")
    need(int(limit) == end, f"limit {limit} != highest tracked end {end}")
    need(int(usable) * PAGE == length(tracked), f"usable {usable} != {length(tracked) // PAGE} tracked frames")
    need(int(clipped) == usable_bytes - length(tracked), f"clipped {clipped} != {usable_bytes - length(tracked)}")
    high = intersect(tracked, [(ONE_GIB, BOUND)])
    need(int(mapped) * TWO_MIB == length(high), f"direct_map_pages {mapped} != {length(high) // TWO_MIB}")

    # Reservations derived without the kernel's list: low memory; the kernel
    # image from the ELF the ISO boots; the Multiboot2 block GRUB passed (its
    # address and size are printed at entry, before any of this code runs);
    # no modules (the ISO loads none); the table block from this oracle's
    # own plan and placement. The kernel's RESERVED list must equal it.
    image = kernel_image(args.kernel)
    info = one(r"multiboot info: 0x([0-9a-f]+)")
    info_bytes = one(r"multiboot bytes: 0x([0-9a-f]+)")
    boot = (int(info[1], 16), int(info[1], 16) + int(info_bytes[1], 16))
    tag_frames = max(end // PAGE, BUILT_IN_FRAMES + 1)
    directories = len({g for s, e in high for g in range(s // ONE_GIB, (e - 1) // ONE_GIB + 1)})
    block_bytes = directories * PAGE + up(tag_frames * 4, PAGE)
    fixed = [("low", 0, 0x10_0000), ("kernel", *image), ("multiboot", *boot)]
    at = place(block_bytes, rows, [(s, e) for _, s, e in fixed] + [PAGE_TEST_WINDOW])
    need(at is not None, "oracle finds no placement for the table block")
    expected = fixed + [("table", at, at + block_bytes)]
    need(disclosed == expected, f"kernel reservations {disclosed} != derived {expected}")

    # Free after reservations: tracked minus every derived reservation.
    holes = merge((down(s, PAGE), up(e, PAGE)) for _, s, e in expected)
    free = subtract(tracked, holes)
    need(int(free_line[1]) * PAGE == length(free),
         f"free frames {free_line[1]} != {length(free) // PAGE} (tracked {usable} minus "
         f"{length(intersect(tracked, holes)) // PAGE} reserved)")

    # Every free frame was allocatable, the marks are where the map says.
    frames, start_free, above_256m, above_4g, highest, written, verified = alloc.groups()
    need(int(frames) == int(start_free) == int(free_line[1]), f"allocated {frames} of {start_free}")
    first = lambda floor: next(max(s, floor) for s, e in free if e > floor)
    need(int(above_256m, 16) == first(256 << 20), f"above_256m {above_256m}")
    need(int(above_4g, 16) == first(FOUR_GIB), f"above_4g {above_4g}")
    need(int(highest, 16) == free[-1][1] - PAGE, f"highest {highest}")
    marks = {int(above_256m, 16), int(above_4g, 16), int(highest, 16)}
    expected = count_aligned(free, TWO_MIB) + len({m for m in marks if m % TWO_MIB})
    need(int(written) == int(verified) == expected, f"written {written} verified {verified} expected {expected}")
    need(freed.groups() == (start_free, "0"), f"after free: {freed.groups()}")

    # The suite ran with every frame below 4 GiB held.
    pinned, nxt = placement.groups()
    need(int(pinned) * PAGE == length(intersect(free, [(0, FOUR_GIB)])), f"pinned {pinned}")
    need(int(nxt, 16) == first(FOUR_GIB), f"next {nxt}")

    print(f"whole-ram-check: -m {args.ram}: {usable} frames tracked to {end:#x}, {len(rows)} map rows "
          f"({sum(1 for s, _ in rows if s >= FOUR_GIB)} above 4 GiB), reservations match the ELF/plan, "
          f"{int(usable) - int(free_line[1])} reserved, clipped {clipped} B, {mapped} direct-map 2 MiB pages; "
          f"all {frames} free frames allocated and freed, {written} pages written through the map; "
          f"suite ran above 4 GiB (pinned {pinned})")


if __name__ == "__main__":
    main()
