#!/usr/bin/env python3
"""Kernel-exact ELF acceptance for ABSD images.

Mirrors kernel-run at 2b4abb4: the spawn_image size check (src/syscalls.rs),
the parser (src/elf.rs parse_source, 110-213) and the loader's placement
(src/sched.rs populate, 731-767, with src/vm.rs map_user_page). Advice only:
the guest spawn is the truth source (A14). Neither stricter nor looser than
the kernel. The kit's stricter rules (page-aligned vaddr, link map,
__bothinit_array_*) belong to check-c-elf.py and are NOT applied here.

Rules, in the order the kernel applies them (every parser rule, for every
program header, precedes every loader rule):

  syscalls.rs:395-396  image length 1..=MAX_SPAWN_IMAGE_BYTES (32 MiB,
                       abi/src/syscall.rs:57); spawn_image path only. On
                       the file path (the shell spawning a file) the
                       runtime refuses a file over 32 MiB first (c-kit
                       runtime/src/process.rs:40,276, MAX_IMAGE;
                       runtime/src/storage.rs:489, SPAWN_IMAGE_TOO_LARGE)
  elf.rs:112-114       length >= 64
  elf.rs:118-120       magic \\x7fELF
  elf.rs:121-123       EI_CLASS == 2 (ELF64)
  elf.rs:124-126       EI_DATA == 1 (little-endian)
  elf.rs:127-129       e_type == 2 (ET_EXEC)
  elf.rs:130-132       e_machine == 62 (arch/x86_64/mod.rs:131)
  elf.rs:133-135       e_version == 1
  elf.rs:139-143       e_phentsize == 56 and e_phnum != 0
  elf.rs:144-152       e_phoff + e_phnum*56 <= length
  elf.rs:164-166       PT_NULL skipped (its fields are never read)
  elf.rs:167-169       any other non-PT_LOAD type refused
  elf.rs:170-172       at most 8 PT_LOAD (MAX_LOAD_SEGMENTS, elf.rs:7)
  elf.rs:182           p_memsz != 0
  elf.rs:183           p_filesz <= p_memsz
  elf.rs:184           p_offset + p_filesz <= length
  elf.rs:185           p_vaddr + p_memsz does not overflow u64
  elf.rs:186           p_align != 0
  elf.rs:187           p_align a power of two
  elf.rs:188           p_vaddr % p_align == p_offset % p_align
  elf.rs:189           p_flags within R|W|X
  elf.rs:203-211       some PT_LOAD exists and e_entry lies in
                       [p_vaddr, p_vaddr + p_memsz) of a PF_X PT_LOAD
  sched.rs:743-745     USER_IMAGE_MIN <= p_vaddr and p_vaddr + p_memsz <=
                       USER_IMAGE_MAX (abi/src/layout.rs:14-15; the end is
                       compared with `>`, so ending exactly at MAX is accepted)
  vm.rs:173-175        pages [p_vaddr & ~0xfff, roundup(p_vaddr + p_memsz))
                       of a PT_LOAD may not include a page an earlier PT_LOAD
                       mapped (AlreadyMapped -> BadImage, sched.rs:765-766)

Not checked by the kernel, so not checked here: EI_VERSION (byte 6), page
alignment of p_vaddr, p_paddr, section headers, symbols."""

import struct
import sys

MAX_SPAWN_IMAGE_BYTES = 32 << 20   # abi/src/syscall.rs:57
MAX_LOADS = 8                      # elf.rs:7
USER_IMAGE_MIN = 0x80_0040_0000    # abi/src/layout.rs:14
USER_IMAGE_MAX = 0x80_0400_0000    # abi/src/layout.rs:15 (segment end may equal it)
PAGE = 0x1000
U64 = (1 << 64) - 1
PT_NULL, PT_LOAD = 0, 1
PF_X, PF_W, PF_R = 1, 2, 4

RULES = [
    ("syscalls.rs:395-396", "image length outside 1..=32 MiB (spawn_image; from a file, the runtime refuses over "
                            "32 MiB first: runtime/src/process.rs:40,276, storage.rs:489)"),
    ("elf.rs:112-114", "shorter than the 64-byte ELF header"),
    ("elf.rs:118-120", "bad ELF magic"),
    ("elf.rs:121-123", "not ELF64"),
    ("elf.rs:124-126", "not little-endian"),
    ("elf.rs:127-129", "e_type != ET_EXEC"),
    ("elf.rs:130-132", "e_machine != x86-64"),
    ("elf.rs:133-135", "e_version != 1"),
    ("elf.rs:139-143", "e_phentsize != 56 or e_phnum == 0"),
    ("elf.rs:144-152", "program header table beyond the file"),
    ("elf.rs:167-169", "program header type other than PT_NULL/PT_LOAD"),
    ("elf.rs:170-172", "more than 8 PT_LOAD"),
    ("elf.rs:182", "PT_LOAD memsz == 0"),
    ("elf.rs:183", "PT_LOAD filesz > memsz"),
    ("elf.rs:184", "PT_LOAD bytes beyond the file"),
    ("elf.rs:185", "PT_LOAD vaddr + memsz overflows"),
    ("elf.rs:186", "PT_LOAD align == 0"),
    ("elf.rs:187", "PT_LOAD align not a power of two"),
    ("elf.rs:188", "PT_LOAD vaddr % align != offset % align"),
    ("elf.rs:189", "PT_LOAD flags beyond R/W/X"),
    ("elf.rs:203-211", "no PT_LOAD, or entry outside every PF_X PT_LOAD"),
    ("sched.rs:743-745", "PT_LOAD outside the image window"),
    ("vm.rs:173-175", "two PT_LOADs touch one 4 KiB page"),
]
_TEXT = dict(RULES)


def _refuse(cite, detail=""):
    return False, f"{_TEXT[cite]}{detail} ({cite})", 0


def check(data):
    """(ok, reason, loads) for `data` as the kernel would spawn it."""
    length = len(data)
    if length == 0 or length > MAX_SPAWN_IMAGE_BYTES:
        return _refuse("syscalls.rs:395-396")
    if length < 64:
        return _refuse("elf.rs:112-114")
    if data[0:4] != b"\x7fELF":
        return _refuse("elf.rs:118-120")
    if data[4] != 2:
        return _refuse("elf.rs:121-123")
    if data[5] != 1:
        return _refuse("elf.rs:124-126")
    e_type, e_machine, e_version, e_entry, e_phoff = struct.unpack_from("<HHIQQ", data, 16)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    if e_type != 2:
        return _refuse("elf.rs:127-129", f" (e_type {e_type})")
    if e_machine != 62:
        return _refuse("elf.rs:130-132", f" (e_machine {e_machine})")
    if e_version != 1:
        return _refuse("elf.rs:133-135")
    if e_phentsize != 56 or e_phnum == 0:
        return _refuse("elf.rs:139-143")
    if e_phoff + e_phentsize * e_phnum > length:
        return _refuse("elf.rs:144-152")

    loads = []
    for index in range(e_phnum):
        at = e_phoff + index * 56
        p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_align = \
            struct.unpack_from("<IIQQQQQQ", data, at)
        if p_type == PT_NULL:                                    # elf.rs:164-166
            continue
        if p_type != PT_LOAD:
            return _refuse("elf.rs:167-169", f" (header {index} type {p_type:#x})")
        if len(loads) == MAX_LOADS:
            return _refuse("elf.rs:170-172")
        where = f" (header {index})"
        if p_memsz == 0:
            return _refuse("elf.rs:182", where)
        if p_filesz > p_memsz:
            return _refuse("elf.rs:183", where)
        if p_offset + p_filesz > length:
            return _refuse("elf.rs:184", where)
        if p_vaddr + p_memsz > U64:
            return _refuse("elf.rs:185", where)
        if p_align == 0:
            return _refuse("elf.rs:186", where)
        if p_align & (p_align - 1):
            return _refuse("elf.rs:187", where)
        if p_vaddr % p_align != p_offset % p_align:
            return _refuse("elf.rs:188", where)
        if p_flags & ~(PF_R | PF_W | PF_X):
            return _refuse("elf.rs:189", where)
        loads.append((p_vaddr, p_memsz, p_flags))
    if not any(flags & PF_X and vaddr <= e_entry < vaddr + memsz
               for vaddr, memsz, flags in loads):
        return _refuse("elf.rs:203-211", f" (entry {e_entry:#x})")

    mapped = set()
    for vaddr, memsz, _flags in loads:
        end = vaddr + memsz
        if vaddr < USER_IMAGE_MIN or end > USER_IMAGE_MAX:
            return _refuse("sched.rs:743-745", f" ({vaddr:#x}..{end:#x})")
        pages = range(vaddr // PAGE, (end + PAGE - 1) // PAGE)
        if any(page in mapped for page in pages):
            return _refuse("vm.rs:173-175", f" (segment at {vaddr:#x})")
        mapped.update(pages)
    return True, "", len(loads)


# --kernel mode: the facts above, and their other hand-made copies in this
# tree, against the kernel source they were copied from. Each kernel fact is
# read by one anchored pattern at its definition and must also appear at the
# site that enforces it; each copy is read by one anchored pattern. A pattern
# that does not match exactly one line is UNKNOWN (exit 2), never OK. The
# relation is the copy's own stated contract: "eq" for a copy that says it is
# the kernel's value (this file, :7; C-INTERFACE.md:124 "From the kernel"),
# "le" for a consumer that may be stricter (the kit's link form, its gate,
# the runtime). A stricter "le" copy is NARROWER: named, exit 0. Nothing is
# rewritten and no side is taken: the output names both places.

import os
import re
import subprocess

KERNEL_DEFS = [
    # (fact, kernel file, definition pattern, value expression group)
    ("MAX_LOAD_SEGMENTS", "src/elf.rs", r"pub const MAX_LOAD_SEGMENTS: usize = ([0-9a-fx_ <]+);"),
    ("USER_IMAGE_MIN", "abi/src/layout.rs", r"pub const USER_IMAGE_MIN: u64 = USER_REGION_BASE \+ ([0-9a-fx_ <]+);"),
    ("USER_IMAGE_MAX", "abi/src/layout.rs", r"pub const USER_IMAGE_MAX: u64 = USER_REGION_BASE \+ ([0-9a-fx_ <]+);"),
    ("MAX_SPAWN_IMAGE_BYTES", "abi/src/syscall.rs", r"pub const MAX_SPAWN_IMAGE_BYTES: u64 = ([0-9a-fx_ <]+);"),
    ("USER_HEAP_PAGES", "abi/src/layout.rs", r"pub const USER_HEAP_PAGES: u64 = ([0-9a-fx_ <]+);"),
    ("MAX_MAP_PAGES", "abi/src/syscall.rs", r"pub const MAX_MAP_PAGES: u64 = ([0-9a-fx_ <]+);"),
]
# The window's base, added to the two image offsets above.
KERNEL_BASE = ("USER_REGION_BASE", "abi/src/layout.rs", r"pub const USER_REGION_BASE: u64 = ([0-9a-fx_ <]+);")
# Where the kernel applies each fact (a whole line, leading space ignored).
KERNEL_SITES = [
    ("MAX_LOAD_SEGMENTS", "src/elf.rs", r"if image\.segment_count == MAX_LOAD_SEGMENTS \{"),
    ("USER_IMAGE_MIN", "src/sched.rs", r"if segment\.virtual_address < USER_IMAGE_MIN \|\| end > USER_IMAGE_MAX \{"),
    ("USER_IMAGE_MAX", "src/sched.rs", r"if segment\.virtual_address < USER_IMAGE_MIN \|\| end > USER_IMAGE_MAX \{"),
    ("MAX_SPAWN_IMAGE_BYTES", "src/syscalls.rs", r"\|\| request\.image_bytes > MAX_SPAWN_IMAGE_BYTES"),
    ("USER_HEAP_PAGES", "abi/src/layout.rs", r"pub const USER_HEAP_END: u64 = USER_HEAP_BASE \+ USER_HEAP_PAGES \* 4096;"),
    ("USER_HEAP_PAGES", "src/syscalls.rs",
     r"vm::find_unmapped_run\(&process\.address_space, USER_HEAP_BASE, USER_HEAP_END, pages\)"),
    ("MAX_MAP_PAGES", "src/syscalls.rs", r"if pages == 0 \|\| pages > MAX_MAP_PAGES \{"),
]

_MIB, _KIB = 1 << 20, 1 << 10
_LINKERS = ["c/absd-c.ld", "user-linker.ld", "ssh/user-linker.ld", "integration/user-linker.ld"]
_PHDR_LOAD = r"\s*\w+ PT_LOAD FLAGS\(\d+\);"
_DOC_HEAP = (r"\| heap window \| (\d+) MiB per process; map granularity 4 KiB; "
             r"at most (\d+) pages \((\d+) KiB\) per map call; .*")
_DOC_IMAGE = (r"\| image \| ELF64 ET_EXEC, x86-64, PT_LOAD only \(PT_NULL skipped\), at most (\d+), "
              r"input at most (\d+) MiB, every segment inside (0x[0-9a-f_]+)\.\.(0x[0-9a-f_]+), .*")
# The copies: (fact, relation, file, whole-line pattern or "count:"+pattern,
# group, scale into the kernel's unit). For "count:" the value is the number
# of matching lines (a PHDRS block's PT_LOAD entries).
BINDINGS = [
    ("MAX_LOAD_SEGMENTS", "eq", "scripts/check-abi-elf.py", r"MAX_LOADS = (\d+)\s+#.*", 1, 1),
    ("USER_IMAGE_MIN", "eq", "scripts/check-abi-elf.py", r"USER_IMAGE_MIN = (0x[0-9a-f_]+)\s+#.*", 1, 1),
    ("USER_IMAGE_MAX", "eq", "scripts/check-abi-elf.py", r"USER_IMAGE_MAX = (0x[0-9a-f_]+)\s+#.*", 1, 1),
    ("MAX_SPAWN_IMAGE_BYTES", "eq", "scripts/check-abi-elf.py", r"MAX_SPAWN_IMAGE_BYTES = (\d+ << \d+)\s+#.*", 1, 1),
    ("MAX_LOAD_SEGMENTS", "le", "scripts/check-c-elf.py",
     r'if len\(loads\) > (\d+): fail\(f"\{len\(loads\)\} PT_LOAD headers, at most \d+"\)', 1, 1),
    ("USER_IMAGE_MIN", "eq", "scripts/check-c-elf.py", r"IMAGE_MIN, IMAGE_MAX, PAGE = (0x[0-9a-f_]+), (0x[0-9a-f_]+), 0x1000", 1, 1),
    ("USER_IMAGE_MAX", "eq", "scripts/check-c-elf.py", r"IMAGE_MIN, IMAGE_MAX, PAGE = (0x[0-9a-f_]+), (0x[0-9a-f_]+), 0x1000", 2, 1),
    ("USER_IMAGE_MIN", "eq", "c/absd-c.ld", r"\s*(0x[0-9a-f_]+)\.\.(0x[0-9a-f_]+), no notes, no TLS, init/fini arrays kept\.", 1, 1),
    ("USER_IMAGE_MAX", "eq", "c/absd-c.ld", r"\s*(0x[0-9a-f_]+)\.\.(0x[0-9a-f_]+), no notes, no TLS, init/fini arrays kept\.", 2, 1),
] + [binding for linker in _LINKERS for binding in (
    ("MAX_LOAD_SEGMENTS", "le", linker, "count:" + _PHDR_LOAD, 0, 1),
    ("USER_IMAGE_MIN", "eq", linker, r"\s*\. = (0x[0-9a-f]+);", 1, 1),
)] + [
    ("MAX_SPAWN_IMAGE_BYTES", "le", "runtime/src/process.rs", r"const MAX_IMAGE: u64 = (\d+ << \d+);", 1, 1),
    ("MAX_MAP_PAGES", "le", "runtime/src/allocator.rs", r"const MAX_MAP_PAGES: usize = (\d+);", 1, 1),
    ("USER_HEAP_PAGES", "le", "runtime/src/allocator.rs", r"const MAX_GROW_PAGES: usize = (\d+);", 1, 1),
    ("USER_HEAP_PAGES", "eq", "docs/C-INTERFACE.md", _DOC_HEAP, 1, _MIB // PAGE),
    ("MAX_MAP_PAGES", "eq", "docs/C-INTERFACE.md", _DOC_HEAP, 2, 1),
    ("MAX_MAP_PAGES", "eq", "docs/C-INTERFACE.md", _DOC_HEAP, 3, ("div", PAGE // _KIB)),
    ("MAX_LOAD_SEGMENTS", "eq", "docs/C-INTERFACE.md", _DOC_IMAGE, 1, 1),
    ("MAX_SPAWN_IMAGE_BYTES", "eq", "docs/C-INTERFACE.md", _DOC_IMAGE, 2, _MIB),
    ("USER_IMAGE_MIN", "eq", "docs/C-INTERFACE.md", _DOC_IMAGE, 3, 1),
    ("USER_IMAGE_MAX", "eq", "docs/C-INTERFACE.md", _DOC_IMAGE, 4, 1),
]
NOT_CHECKED = ("W^X (the kernel has no policy); segment overlap and page sharing; ELF header, "
               "entry and per-segment rules (check() and its tests); this file's docstring and RULES "
               "citations; the kernel's own prose (PROCESS-STARTUP.md, USERSPACE.md, "
               "application-interface-v0 limits); other C-INTERFACE.md section 2 rows; POSIX "
               "mmap/brk absence (C-INTERFACE.md sections 3, 10); the syscall ABI generation "
               "(check-all's KERNEL_ABI step); whether the 32 MiB heap window is architectural; "
               "restatements outside C-INTERFACE section 2 (section 3 prose, CPA-060, SSH-HEAP.md, "
               "c-ecosystem SPEC.md, the exec_probe boundary, build-tcc.sh's -Ttext and tcc's config.h)")


def _literal(text):
    """An integer as the sources spell it: decimal, 0x hex, `_` separators,
    optionally `<< n`. Anything else is None (UNKNOWN), never a guess."""
    m = re.fullmatch(r"(0x[0-9a-fA-F_]+|[0-9][0-9_]*)(?:\s*<<\s*([0-9]+))?", text.strip())
    if not m:
        return None
    digits = m.group(1).replace("_", "")
    value = int(digits[2:], 16) if digits.startswith("0x") else int(digits, 10)
    return value << int(m.group(2)) if m.group(2) else value


def _lines(base, rel):
    try:
        with open(os.path.join(base, rel), encoding="utf-8") as handle:
            return handle.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return None


# Rust lexer-lite: which bytes of a .rs file are active code. Comments
# (line, doc, block, nested block) and string, byte-string, C-string, raw
# and char literals are blanked; what it cannot classify it refuses.
_BREAKS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"   # str.splitlines() boundaries
_IDENT = re.compile(r"[A-Za-z_\u0080-\U0010ffff][0-9A-Za-z_\u0080-\U0010ffff]*")
_RAW_OPEN = re.compile(r'(?:br|cr|r)(#*)"')
_CHAR_ESCAPE = re.compile(r"\\(?:u\{[0-9a-fA-F_]{1,8}\}|x[0-9a-fA-F]{2}|[nrt\\0'\"])")


def rust_active(text):
    """(lines, None): `text` as str.splitlines() would split it, with every
    comment (line, block, nested block, doc), string (plain, byte, C, raw)
    and char literal blanked to spaces; or (None, reason) when a region is
    unterminated at EOF or a quote is neither a char literal nor a
    lifetime. Comments and literals only: not a parser; cfg, macros and
    items are not interpreted."""
    out, i, n = list(text), 0, len(text)

    def blank(start, end):
        for k in range(start, end):
            if out[k] not in _BREAKS:
                out[k] = " "

    def line_of(at):
        return len((text[:at] + "x").splitlines())

    while i < n:
        two = text[i:i + 2]
        word_before = i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_")
        raw = None if word_before else _RAW_OPEN.match(text, i)
        lead = i                       # a literal's prefix (b, c, r, br, cr) is blanked with it
        if not word_before and two in ('b"', 'c"', "b'"):
            i += 1
        # `two` is not recomputed after this shift: when a prefix moved `i`,
        # `two` is 'b"', 'c"' or "b'", which is neither "//" nor "/*", and
        # the literal branches below key on `c`, the character after it.
        c = text[i]
        if two == "//":
            # A line comment ends only at "\n", as in Rust. After a lone "\r"
            # (or another splitlines() boundary) inside it, the rest of that
            # line is still comment: conservative, never invented code.
            end = text.find("\n", i)
            end = n if end < 0 else end
            blank(i, end)
            i = end
        elif two == "/*":
            depth, k = 1, i + 2
            while k < n and depth:
                if text.startswith("/*", k):
                    depth, k = depth + 1, k + 2
                elif text.startswith("*/", k):
                    depth, k = depth - 1, k + 2
                else:
                    k += 1
            if depth:
                return None, f"unterminated block comment from line {line_of(i)}"
            blank(i, k)
            i = k
        elif raw:
            close = '"' + raw.group(1)
            end = text.find(close, raw.end())
            if end < 0:
                return None, f"unterminated raw string from line {line_of(i)}"
            blank(lead, end + len(close))
            i = end + len(close)
        elif c == '"':
            k = i + 1
            while k < n and text[k] != '"':
                k += 2 if text[k] == "\\" else 1
            if k >= n:
                return None, f"unterminated string from line {line_of(i)}"
            blank(lead, k + 1)
            i = k + 1
        elif c == "'":
            escape = _CHAR_ESCAPE.match(text, i + 1)
            if escape and text.startswith("'", escape.end()):
                blank(lead, escape.end() + 1)
                i = escape.end() + 1
            elif i + 2 < n and text[i + 1] not in "\\'" + _BREAKS and text[i + 2] == "'":
                blank(lead, i + 3)
                i += 3
            else:
                label = _IDENT.match(text, i + 1)
                if not label or text.startswith("'", label.end()):
                    return None, f"unclassified quote at line {line_of(i)}"
                i = label.end()
        else:
            i += 1
    return "".join(out).splitlines(), None


# Rust sources (.rs) are matched as active code: a commented or quoted copy
# of an anchor is not evidence, a Rust file the lexer cannot decide is
# UNKNOWN, and an anchor under a cfg attribute is UNKNOWN (cfg is not
# evaluated). Linker scripts, Python and Markdown stay raw lines: the
# image-window binding in c/absd-c.ld lives inside a /* */ comment.
_CFG_ATTR = re.compile(r"#\s*!?\s*\[\s*cfg")
_CFG_INNER = re.compile(r"\s*#\s*!\s*\[\s*cfg")


def _cfg_gated(lines, number):
    """True when active line `number` (1-based) may be compiled out: the file
    has an inner #![cfg...], or a cfg/cfg_attr attribute stands between the
    line and the previous line ending in `;`, `{` or `}`. cfg is not
    evaluated; an enclosing gated block further up is not seen."""
    if any(_CFG_INNER.match(line) for line in lines):
        return True
    for above in reversed(lines[:number - 1]):
        above = above.strip()
        if _CFG_ATTR.search(above):
            return True
        if above.endswith((";", "{", "}")):
            return False
    return False


def _source(base, rel):
    """(lines, None) to match anchors against, or (None, reason): a .rs file
    as its active code, any other file as raw lines."""
    try:
        with open(os.path.join(base, rel), encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError):
        return None, f"{rel} unreadable"
    if not rel.endswith(".rs"):
        return text.splitlines(), None
    lines, why = rust_active(text)
    if lines is None:
        return None, f"{rel}: active Rust source undecidable: {why}"
    return lines, None


def _one(base, rel, pattern):
    """(line number, match) for the one line `pattern` matches whole, after
    leading space (Rust: after surrounding space, comments blanked); or
    (None, reason)."""
    lines, why = _source(base, rel)
    if lines is None:
        return None, why
    rust = rel.endswith(".rs")
    hits = [(n, m) for n, line in enumerate(lines, 1)
            for m in [re.fullmatch(pattern, line.strip() if rust else line.lstrip())] if m]
    if len(hits) != 1:
        return None, f"{rel}: {len(hits)} lines match the anchor (want 1)"
    if rust and _cfg_gated(lines, hits[0][0]):
        return None, f"{rel}:{hits[0][0]}: the anchor is under a cfg attribute (not evaluated)"
    return hits[0]


def _count(base, rel, pattern):
    lines, why = _source(base, rel)
    if lines is None:
        return None, why
    rust = rel.endswith(".rs")
    hits = [n for n, line in enumerate(lines, 1) if re.fullmatch(pattern, line.rstrip() if rust else line)]
    if not hits:
        return None, f"{rel}: no line matches the anchor"
    return f"{hits[0]}-{hits[-1]}" if len(hits) > 1 else f"{hits[0]}", len(hits)


def _show(fact, value):
    if value is None:
        return "UNKNOWN"
    return f"{value:#x}" if fact.startswith("USER_IMAGE") else str(value)


def kernel_facts(kdir):
    """{fact: (value or None, citation or reason)} from kernel source."""
    facts = {}
    line, base = _one(kdir, KERNEL_BASE[1], KERNEL_BASE[2])
    base_value = _literal(base.group(1)) if line else None
    base_cite = f"{KERNEL_BASE[1]}:{line}" if line else base
    for fact, rel, pattern in KERNEL_DEFS:
        line, m = _one(kdir, rel, pattern)
        if line is None:
            facts[fact] = (None, m)
            continue
        value = _literal(m.group(1))
        cite = f"{rel}:{line}"
        if value is not None and fact.startswith("USER_IMAGE"):
            if base_value is None:
                facts[fact] = (None, f"{cite} needs USER_REGION_BASE: {base_cite}")
                continue
            value += base_value
            cite += f"+{base_cite}"
        facts[fact] = (value, cite) if value is not None else (None, f"{cite}: value is not a literal")
    for fact, rel, pattern in KERNEL_SITES:
        value, cite = facts[fact]
        if value is None:
            continue
        line, m = _one(kdir, rel, pattern)
        if line is None:
            facts[fact] = (None, f"{cite} defined but its enforcing site is not found: {m}")
        else:
            facts[fact] = (value, f"{cite} enforced={rel}:{line}")
    return facts


def _kernel_identity(kdir):
    """The commit when KERNEL_DIR is the top of a checkout; else what a
    snapshot recorded (.absd-identity, scripts/inputs.sh); else unrecorded."""
    try:
        top = subprocess.run(["git", "-C", kdir, "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=30)
        if top.returncode == 0 and os.path.realpath(top.stdout.strip()) == os.path.realpath(kdir):
            head = subprocess.run(["git", "-C", kdir, "rev-parse", "--verify", "HEAD"],
                                  capture_output=True, text=True, timeout=30)
            if head.returncode == 0:
                return head.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    recorded = _lines(kdir, ".absd-identity")
    return recorded[0].strip() if recorded else "unrecorded"


def check_kernel(kdir, root, out=print):
    """Compare every copy in BINDINGS with the kernel. Returns the exit code:
    0 OK, 1 MISMATCH (a copy disagrees), 2 UNKNOWN (evidence incomplete)."""
    facts = kernel_facts(kdir)
    out(f"ABI FACTS KERNEL dir={kdir} identity={_kernel_identity(kdir)}")
    for fact, _rel, _pattern in KERNEL_DEFS:
        value, cite = facts[fact]
        out(f"ABI KERNEL {fact}={_show(fact, value)} {cite}")
    tally = {"OK": 0, "MISMATCH": 0, "NARROWER": 0, "UNKNOWN": 0}
    for fact, relation, rel, pattern, group, scale in BINDINGS:
        kernel_value = facts[fact][0]
        note = None
        if pattern.startswith("count:"):
            where, copy = _count(root, rel, pattern[len("count:"):])
            if where is None:
                copy, note = None, copy
        else:
            line, m = _one(root, rel, pattern)
            where, copy = line, None
            if line is None:
                note = m
            else:
                copy = _literal(m.group(group))
                if copy is not None:
                    if isinstance(scale, tuple):
                        copy = copy // scale[1] if copy % scale[1] == 0 else None
                    else:
                        copy *= scale
        if where is None or copy is None or kernel_value is None:
            verdict = "UNKNOWN"
        elif copy == kernel_value:
            verdict = "OK"
        elif relation == "le" and copy < kernel_value:
            verdict = "NARROWER"
        else:
            verdict = "MISMATCH"
        tally[verdict] += 1
        place = f"{rel}:{where}" if where is not None else rel
        if verdict == "UNKNOWN" and note is None:
            note = (f"kernel: {facts[fact][1]}" if kernel_value is None
                    else f"{rel}:{where}: value is not a literal")
        tail = f" ({note})" if verdict == "UNKNOWN" else ""
        rel_text = "" if relation == "eq" else " relation=le"
        out(f"ABI FACT {fact} kernel={_show(fact, kernel_value)} {place}={_show(fact, copy)} "
            f"{verdict}{rel_text}{tail}")
    out(f"ABI FACTS NOT_CHECKED {NOT_CHECKED}")
    checked = tally["OK"] + tally["NARROWER"] + tally["MISMATCH"]
    if tally["MISMATCH"]:
        out(f"ABI FACTS MISMATCH mismatch={tally['MISMATCH']} unknown={tally['UNKNOWN']} "
            f"checked={checked} narrower={tally['NARROWER']}")
        return 1
    if tally["UNKNOWN"]:
        out(f"ABI FACTS UNKNOWN unknown={tally['UNKNOWN']} checked={checked} narrower={tally['NARROWER']}")
        return 2
    out(f"ABI FACTS OK checked={checked} narrower={tally['NARROWER']}")
    return 0


def main(argv):
    if len(argv) >= 2 and argv[1] == "--kernel":
        if len(argv) == 3:
            root = os.path.dirname(os.path.dirname(os.path.abspath(argv[0])))
        elif len(argv) == 5 and argv[3] == "--root":
            root = argv[4]
        else:
            print("usage: check-abi-elf.py --kernel KERNEL_DIR [--root PLATFORM_DIR]", file=sys.stderr)
            return 2
        return check_kernel(argv[2], root)
    if len(argv) != 2:
        print("usage: check-abi-elf.py FILE | --kernel KERNEL_DIR [--root PLATFORM_DIR]", file=sys.stderr)
        return 2
    with open(argv[1], "rb") as handle:
        data = handle.read(MAX_SPAWN_IMAGE_BYTES + 1)
    ok, reason, loads = check(data)
    if ok:
        entry = struct.unpack_from("<Q", data, 24)[0]
        print(f"ABI ELF ACCEPTS {argv[1]} loads={loads} entry={entry:#x}")
        return 0
    print(f"ABI ELF REFUSES {argv[1]} :: {reason}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
