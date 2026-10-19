#!/usr/bin/env python3
"""Host checks that an ELF has the form the ABSD loader accepts.

ET_EXEC, x86-64, only PT_LOAD program headers (at most 8), every segment
page-aligned, disjoint in pages, inside the image window, no TLS sections, no .rel*/.rela*, .plt, .got.plt, .dynamic, .interp or
.dynsym section, and no undefined symbol except Picolibc's weak `stdin` and
`stdout` references. Both are a named allowance, not a general one: the only
weak references to them are in Picolibc 1.8.12's src/libc/stdio/bufio.c
(declared weak at 162-163), whose one use, __bufio_get's flush of stdout
before a stdin read (191-193), first tests `&stdin != NULL && &stdout !=
NULL`, so an absent one resolves to 0 and the flush is skipped, never
dereferenced. stdin was admitted first (the kit's stdin is the `stdin`
macro's own FILE); stdout by the steward's R13 decision (2026-10-12), so a
program whose stdio never names stdout (perror or stderr only, or files
only) is accepted. Any other weak-undefined name is refused. `__bothinit_array_start/end` must be defined by
the linker script: undefined, they resolve to 0 and no constructor runs.
Prints `C ELF OK <path> loads=<n>` or the first violation.

With `--map FILE` (the ld.lld map absd-cc leaves beside the output) it also
refuses: pulled archive members bid*.o, generic-morestack*.o, _eprintf.o or anything
from libgcc.a; any Picolibc libm name whose definition the map attributes to
the Rust archives (libabs.a / libabs_builtins.a), the names being every
global defined by the libm_* members of the libc.a the map names; and any
pulled libc.a member that is a libos fallback (libos_*) or that defines a
symbol the kit's own C objects (crt0/malloc/fd/errno_map/clock/locale/strerror_hook in libabs.a)
define, or the runtime's memcpy/memmove/memset/memcmp; any `*_chk` (fortify)
symbol resolved from an archive; and Picolibc's atexit runner
(libc_stdlib_exitprocs.c.o) pulled without its `.fini_array_onexit` section,
which would leave atexit handlers unrun. Prints `C ELF OK <path> loads=<n> map=checked` then.
"""
import fnmatch, os, re, subprocess, sys

IMAGE_MIN, IMAGE_MAX, PAGE = 0x80_0040_0000, 0x80_0400_0000, 0x1000

def fail(msg):
    print(f"C ELF REFUSED {path}: {msg}"); sys.exit(1)

args = sys.argv[1:]
map_path = None
if "--map" in args:
    i = args.index("--map"); map_path = args[i + 1]; del args[i:i + 2]
if len(args) != 1:
    print("usage: check-c-elf.py ELF [--map FILE]", file=sys.stderr); sys.exit(2)
path = args[0]
header = subprocess.run(["readelf", "-hW", path], capture_output=True, text=True, check=True).stdout
if not re.search(r"Type:\s+EXEC", header): fail("not ET_EXEC")
if not re.search(r"Machine:\s+Advanced Micro Devices X86-64", header): fail("not x86-64")
phdrs = subprocess.run(["readelf", "-lW", path], capture_output=True, text=True, check=True).stdout
loads = []
for line in phdrs.splitlines():
    m = re.match(r"\s+(\w+)\s+0x([0-9a-f]+) 0x([0-9a-f]+) 0x([0-9a-f]+) 0x([0-9a-f]+) 0x([0-9a-f]+) ([RWE ]+)\s+0x([0-9a-f]+)", line)
    if not m: continue
    kind, off, vaddr, _, filesz, memsz, flags, align = m.groups()
    if kind == "NULL": continue
    if kind != "LOAD": fail(f"program header {kind} is not PT_LOAD")
    off, vaddr, filesz, memsz, align = (int(x, 16) for x in (off, vaddr, filesz, memsz, align))
    if memsz == 0: fail("PT_LOAD with memsz 0")
    if filesz > memsz: fail("filesz > memsz")
    if vaddr % PAGE: fail(f"segment at {vaddr:#x} not page-aligned")
    if (vaddr - off) % align: fail("vaddr and offset disagree modulo align")
    if vaddr < IMAGE_MIN or vaddr + memsz > IMAGE_MAX: fail(f"segment {vaddr:#x}+{memsz:#x} outside the image window")
    loads.append((vaddr, vaddr + memsz))
if not loads: fail("no PT_LOAD")
if len(loads) > 8: fail(f"{len(loads)} PT_LOAD headers, at most 8")
pages = set()
for lo, hi in loads:
    mine = set(range(lo // PAGE, (hi + PAGE - 1) // PAGE))
    if pages & mine: fail("two PT_LOAD segments share a page")
    pages |= mine
sections = subprocess.run(["readelf", "-SW", path], capture_output=True, text=True, check=True).stdout
if re.search(r"\.t(data|bss)", sections): fail("TLS section present")
if re.search(r"\.note", sections): fail(".note section present (discard it in the linker script)")
ALLOWED_WEAK_UNDEFINED = {"stdin", "stdout"}   # exactly these two: bufio.c:162-163, 191-193 (docstring)
for line in subprocess.run(["llvm-nm-18", "-u", path], capture_output=True, text=True, check=True).stdout.splitlines():
    fields = line.split()
    if not fields: continue
    kind, name = fields[0], fields[-1]
    if kind in ("w", "v") and name in ALLOWED_WEAK_UNDEFINED: continue
    fail(f"undefined symbol {name} ({'weak' if kind in ('w', 'v') else 'strong'})")
names = [m.group(1) for m in re.finditer(r"^\s*\[\s*\d+\]\s+(\S+)", sections, re.M)]
for name in names:
    if re.match(r"\.rela?(\.|$)", name) or name in (".plt", ".got.plt", ".dynamic", ".interp", ".dynsym"):
        fail(f"section {name} present")
entry = int(re.search(r"Entry point address:\s+0x([0-9a-f]+)", header).group(1), 16)
if not any(lo <= entry < hi for lo, hi in loads): fail("entry outside every segment")
if map_path is None:
    print(f"C ELF OK {path} loads={len(loads)}"); sys.exit(0)

def nm_members(archive):
    """{member: set(global defined names)} for one archive."""
    out = subprocess.run(["llvm-nm-18", "-A", "--defined-only", archive], capture_output=True, text=True).stdout
    members = {}
    for line in out.splitlines():
        head, _, rest = line.partition(": ")
        fields = rest.split()
        if len(fields) < 2 or fields[-2] not in "TWDBRVi": continue
        members.setdefault(head.rsplit(":", 1)[-1], set()).add(fields[-1])
    return members

# Map lines: VMA LMA Size Align, then the text indented 0 (output section),
# 8 (input section, `archive(member):(section)` for archive members) or 16
# (a symbol defined in the input section above).
pulled, defined_by, current, kept_sections = set(), {}, None, set()
row = re.compile(r"^\s*[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+\d+ (.*)$")
for line in open(map_path):
    m = row.match(line.rstrip("\n"))
    if not m: continue
    text = m.group(1); indent = len(text) - len(text.lstrip()); text = text.strip()
    if indent == 8:
        a = re.match(r"(.+\.a)\(([^)]+)\):", text)
        current = (a.group(1), a.group(2)) if a else None
        if a:
            pulled.add(current)
            sec = re.match(r".+\.a\([^)]+\):\((.+)\)$", text)
            if sec: kept_sections.add((current[1], sec.group(1)))
    elif indent == 16 and current:
        defined_by[text] = current
if not pulled: fail(f"map {map_path} names no archive members")

archives = {os.path.basename(a): a for a, _ in pulled}
for archive, member in sorted(pulled):
    base = os.path.basename(archive)
    if base == "libgcc.a": fail(f"member {member} pulled from libgcc.a")
    for pat in ("bid*.o", "generic-morestack*.o", "_eprintf.o"):
        if fnmatch.fnmatch(member, pat): fail(f"denied member {base}({member}) pulled")

libc = archives.get("libc.a") or os.path.join(os.path.dirname(archives.get("libabs.a", "")), "libc.a")
libc_members = nm_members(libc)
libm_names = set().union(*[v for k, v in libc_members.items() if k.startswith("libm_")] or [set()])
if len(libm_names) < 100: fail(f"could not derive Picolibc libm names from {libc} ({len(libm_names)})")
for sym, (archive, member) in sorted(defined_by.items()):
    if sym in libm_names and os.path.basename(archive) in ("libabs.a", "libabs_builtins.a", "libabsd_c.a"):
        fail(f"libm symbol {sym} supplied by {os.path.basename(archive)}({member}), not Picolibc")

kit_c = ("crt0.o", "malloc.o", "fd.o", "errno_map.o", "clock.o", "locale.o", "strerror_hook.o")
kit_defined = set()
if "libabs.a" in archives:
    for member, syms in nm_members(archives["libabs.a"]).items():
        if member in kit_c: kit_defined |= syms
if not kit_defined: fail("could not read the kit's C definitions from libabs.a")
kit_defined |= {"memcpy", "memmove", "memset", "memcmp"}   # the Rust runtime's
for archive, member in sorted(pulled):
    if os.path.basename(archive) != "libc.a": continue
    if member.startswith("libos_"): fail(f"Picolibc libos fallback {member} pulled")
    clash = libc_members.get(member, set()) & kit_defined
    if clash: fail(f"libc.a({member}) pulled for {sorted(clash)[0]}, which the kit defines")
for sym, (archive, member) in sorted(defined_by.items()):
    if sym.endswith("_chk"): fail(f"fortify symbol {sym} resolved from {os.path.basename(archive)}({member})")
exitprocs = "libc_stdlib_exitprocs.c.o"
if any(m == exitprocs for _, m in pulled) and (exitprocs, ".fini_array_onexit") not in kept_sections:
    fail(f"libc.a({exitprocs}) pulled but its .fini_array_onexit was dropped: atexit handlers would never run")
print(f"C ELF OK {path} loads={len(loads)} map=checked")
