#!/usr/bin/env python3
"""Host tests of scripts/check-abi-elf.py: one synthetic ELF per kernel rule,
refusals and the boundary accepts that keep the gate from being stricter than
the kernel. Plain asserts: `python3 -I scripts/tests/test_check_abi_elf.py`."""

import importlib.util
import pathlib
import struct

GATE = pathlib.Path(__file__).resolve().parent.parent / "check-abi-elf.py"
spec = importlib.util.spec_from_file_location("check_abi_elf", GATE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

W = 0x80_0040_0000          # USER_IMAGE_MIN
W_END = 0x80_0400_0000      # USER_IMAGE_MAX
R, WR, X = 4, 2, 1


def ph(kind=1, flags=R | X, offset=0, vaddr=W, filesz=0x100, memsz=0x100, align=0x1000):
    return (kind, flags, offset, vaddr, filesz, memsz, align)


def elf(phdrs, entry=W + 0x10, size=0x3000, ident=None, e_type=2, machine=62,
        version=1, phoff=64, phentsize=56, phnum=None):
    """A minimal ELF64 of `size` bytes with `phdrs` at `phoff`."""
    out = bytearray(max(size, 64))
    out[0:16] = ident if ident is not None else b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", out, 16, e_type, machine, version, entry,
                     phoff, 0, 0, 64, phentsize, len(phdrs) if phnum is None else phnum,
                     0, 0, 0)
    for index, header in enumerate(phdrs):
        at = phoff + index * 56
        if at + 56 <= len(out):
            struct.pack_into("<IIQQQQQQ", out, at, header[0], header[1], header[2],
                             header[3], header[3], header[4], header[5], header[6])
    return bytes(out[:size])


TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


def accepts(data, loads=None):
    ok, reason, count = gate.check(data)
    assert ok, f"refused: {reason}"
    assert reason == ""
    if loads is not None:
        assert count == loads, (count, loads)


def refuses(data, cite):
    ok, reason, count = gate.check(data)
    assert not ok, "accepted"
    assert count == 0
    assert cite in reason, f"{reason!r} lacks {cite!r}"


# -- accepts ---------------------------------------------------------------

@test
def accept_one_rx_load_at_the_window():
    accepts(elf([ph()]), loads=1)


@test
def accept_text_and_data_on_adjacent_pages():
    accepts(elf([ph(), ph(flags=R | WR, offset=0x1000, vaddr=W + 0x1000, filesz=0x10, memsz=0x2000)]), loads=2)


@test
def accept_mid_page_vaddr_with_congruent_offset():
    # The kit gate (check-c-elf.py) refuses this; the kernel accepts it.
    accepts(elf([ph(offset=0x680, vaddr=W + 0x680, filesz=0x80, memsz=0x80)], entry=W + 0x690), loads=1)


@test
def accept_pt_null_is_skipped():
    accepts(elf([ph(kind=0, flags=0xff, offset=0, vaddr=0, filesz=9, memsz=0, align=3), ph()]), loads=1)


@test
def accept_eight_loads():
    loads = [ph()] + [ph(flags=R, vaddr=W + 0x1000 * i, filesz=0, memsz=0x1000) for i in range(1, 8)]
    accepts(elf(loads), loads=8)


@test
def accept_segment_ending_exactly_at_window_max():
    accepts(elf([ph(), ph(flags=R | WR, offset=0, vaddr=W_END - 0x1000, filesz=0, memsz=0x1000)]), loads=2)


@test
def accept_ei_version_and_unread_fields_ignored():
    # elf.rs never reads EI_VERSION (byte 6) or e_ehsize (bytes 52-53); kernel
    # test elf.rs:482-483 zeroes the one and sets the other to 0xffff, and
    # asserts the image is accepted. The same two changes here.
    data = bytearray(elf([ph()], ident=b"\x7fELF\x02\x01\x00" + bytes(9)))
    data[52:54] = b"\xff\xff"
    accepts(bytes(data))


@test
def accept_image_of_exactly_32_mib():
    accepts(elf([ph()], size=32 << 20))


# -- refusals, in kernel order -------------------------------------------

@test
def refuse_zero_length_image():
    refuses(b"", "syscalls.rs:395-396")


@test
def refuse_image_over_32_mib():
    refuses(elf([ph()], size=(32 << 20) + 1), "syscalls.rs:395-396")


@test
def refuse_header_too_small():
    refuses(elf([ph()])[:63], "elf.rs:112-114")


@test
def refuse_bad_magic():
    refuses(elf([ph()], ident=b"\x7fELG\x02\x01\x01" + bytes(9)), "elf.rs:118-120")


@test
def refuse_elf32():
    refuses(elf([ph()], ident=b"\x7fELF\x01\x01\x01" + bytes(9)), "elf.rs:121-123")


@test
def refuse_big_endian():
    refuses(elf([ph()], ident=b"\x7fELF\x02\x02\x01" + bytes(9)), "elf.rs:124-126")


@test
def refuse_et_dyn():
    refuses(elf([ph()], e_type=3), "elf.rs:127-129")


@test
def refuse_aarch64_machine():
    refuses(elf([ph()], machine=183), "elf.rs:130-132")


@test
def refuse_e_version_0():
    refuses(elf([ph()], version=0), "elf.rs:133-135")


@test
def refuse_phentsize_57():
    refuses(elf([ph()], phentsize=57), "elf.rs:139-143")


@test
def refuse_phnum_0():
    refuses(elf([], phnum=0), "elf.rs:139-143")


@test
def refuse_program_header_table_beyond_file():
    refuses(elf([ph()], phnum=0xffff), "elf.rs:144-152")
    refuses(elf([ph()], phoff=0x3000 - 55), "elf.rs:144-152")


@test
def refuse_pt_gnu_relro():
    refuses(elf([ph(), ph(kind=0x6474E552, flags=R, filesz=0x10, memsz=0x10, align=1)]), "elf.rs:167-169")


@test
def refuse_pt_gnu_stack():
    refuses(elf([ph(), ph(kind=0x6474E551, flags=R | WR, filesz=0, memsz=0, align=16)]), "elf.rs:167-169")


@test
def refuse_nine_loads():
    loads = [ph()] + [ph(flags=R, vaddr=W + 0x1000 * i, filesz=0, memsz=0x1000) for i in range(1, 9)]
    refuses(elf(loads), "elf.rs:170-172")


@test
def refuse_memsz_0():
    refuses(elf([ph(), ph(flags=R, vaddr=W + 0x1000, filesz=0, memsz=0)]), "elf.rs:182")


@test
def refuse_filesz_over_memsz():
    refuses(elf([ph(filesz=0x101, memsz=0x100)]), "elf.rs:183")


@test
def refuse_segment_bytes_beyond_file():
    refuses(elf([ph(offset=0x2000, vaddr=W, filesz=0x1001, memsz=0x1001)]), "elf.rs:184")


@test
def refuse_vaddr_plus_memsz_overflow():
    refuses(elf([ph(), ph(flags=R, vaddr=0xFFFF_FFFF_FFFF_F000, filesz=0, memsz=0x1001)]), "elf.rs:185")


@test
def refuse_align_0():
    refuses(elf([ph(align=0)]), "elf.rs:186")


@test
def refuse_align_3():
    refuses(elf([ph(align=3)]), "elf.rs:187")


@test
def refuse_vaddr_offset_incongruent():
    refuses(elf([ph(offset=0x10, vaddr=W)]), "elf.rs:188")


@test
def refuse_flag_bit_8():
    refuses(elf([ph(flags=R | X | 8)]), "elf.rs:189")


@test
def refuse_no_load_at_all():
    refuses(elf([ph(kind=0)]), "elf.rs:203-211")


@test
def refuse_entry_in_rw_segment():
    refuses(elf([ph(), ph(flags=R | WR, offset=0x1000, vaddr=W + 0x1000, filesz=0x10, memsz=0x1000)],
                entry=W + 0x1000), "elf.rs:203-211")


@test
def refuse_entry_at_segment_end():
    refuses(elf([ph()], entry=W + 0x100), "elf.rs:203-211")


@test
def refuse_segment_below_the_window():
    refuses(elf([ph(vaddr=W - 0x1000)], entry=W - 0x1000 + 0x10), "sched.rs:743-745")


@test
def refuse_segment_ending_past_the_window():
    refuses(elf([ph(), ph(flags=R | WR, vaddr=W_END - 0x1000, filesz=0, memsz=0x1001)]), "sched.rs:743-745")


@test
def refuse_end_at_u64_max_left_to_loader():
    # Parses (no add overflow, elf.rs:185) and is refused by the window.
    refuses(elf([ph(), ph(flags=R, vaddr=0xFFFF_FFFF_FFFF_F000, filesz=0, memsz=0xFFF)]), "sched.rs:743-745")


@test
def refuse_two_loads_on_one_page():
    refuses(elf([ph(filesz=0x800, memsz=0x800),
                 ph(flags=R | WR, offset=0xC00, vaddr=W + 0xC00, filesz=0x10, memsz=0x10)]), "vm.rs:173-175")


@test
def refuse_bss_tail_reaching_next_segment_page():
    refuses(elf([ph(flags=R | WR, offset=0x1000, vaddr=W + 0x1000, filesz=0, memsz=0x1001),
                 ph(offset=0x2000, vaddr=W + 0x2000)], entry=W + 0x2010), "vm.rs:173-175")


@test
def parse_rules_precede_loader_rules():
    # Outside the window AND entry not executable: the parser refuses first.
    refuses(elf([ph(vaddr=W - 0x1000)], entry=W), "elf.rs:203-211")


@test
def refusal_cites_come_from_the_rule_table():
    # Every refusal cites a rule from the module's table.
    cites = [rule[0] for rule in gate.RULES]
    assert len(set(cites)) == len(cites)
    ok, reason, _ = gate.check(elf([ph()], e_type=3))
    assert any(c in reason for c in cites)


# -- rust_active: comments and literals blanked, lines kept -----------------

def active(text):
    """Stripped active lines of `text`; the lexer must decide."""
    lines, why = gate.rust_active(text)
    assert why is None, why
    assert len(lines) == len(text.splitlines()), (lines, text)
    return [line.strip() for line in lines]


def undecidable(text, reason):
    lines, why = gate.rust_active(text)
    assert lines is None and reason in why, (lines, why)


@test
def lex_line_and_doc_line_comments():
    assert active("a // b\n/// c\n//! d\nx") == ["a", "", "", "x"]


@test
def lex_block_comment_opened_and_closed_mid_line():
    assert active("a /* b\nc */ d") == ["a", "d"]
    assert active("a /* b */ c") == ["a         c"]


@test
def lex_nested_block_comments():
    assert active("/* /* */ x */ y") == ["y"]
    assert active("/* a /* b */ c */ d\ne") == ["d", "e"]
    assert active("/* /* */\nhidden\n*/ shown") == ["", "", "shown"]


@test
def lex_doc_block_comments():
    assert active("/** x */ y\n/*! z */ w\n/**\nhidden\n*/") == ["y", "w", "", "", ""]


@test
def lex_delimiters_inside_comments_are_comment():
    assert active('/* " */ x\n/* // */ y\n// /* z\nw') == ["x", "y", "", "w"]


@test
def lex_strings_hold_comment_delimiters():
    assert active('"/*" a\n"//" b\n"*/" c') == ["a", "b", "c"]
    assert active('"\\" /*" d') == ["d"]                 # escaped quote stays inside
    assert active('"a\nb" e') == ["", "e"]               # multi-line string
    assert active('"\\\\" /* f */ g') == ["g"]           # escaped backslash ends cleanly


@test
def lex_raw_byte_and_c_strings():
    assert active('r"/*" a') == ["a"]
    assert active('r#"x " /* y"# b') == ["b"]
    assert active('r##"a "# b"## c') == ["c"]
    assert active('b"/*" d\nbr#"" /*"# e\nc"/*" f\ncr"/*" g') == ["d", "e", "f", "g"]
    assert active("r#type /* x */ y")[0].split() == ["r#type", "y"]   # raw identifier


@test
def lex_char_literals_and_lifetimes():
    assert active("'\"' a\n'/' b\n'\\'' c\n'\\\\' d\n'\\x7f' e\n'\\u{1F600}' f\n'é' g\n'_' h") == \
        ["a", "b", "c", "d", "e", "f", "g", "h"]
    line = active("fn f<'a>(x: &'a str) -> &'static str { \"/*\" }")[0]
    assert "<'a>" in line and "&'a str" in line and "&'static" in line and "/*" not in line, line
    assert active("'outer: loop { break 'outer; } // x") == ["'outer: loop { break 'outer; }"]
    assert active("&'_ T") == ["&'_ T"]


@test
def lex_line_numbers_follow_splitlines():
    text = "x /* \x0c */ y\nz /* \n */ w"
    assert len(text.splitlines()) == 4
    assert active(text) == ["x", "y", "z", "w"]


@test
def lex_undecidable_is_explicit():
    undecidable("/* a", "unterminated block comment from line 1")
    undecidable("x\n/* /* */ y", "unterminated block comment from line 2")
    undecidable('x\n"abc', "unterminated string from line 2")
    undecidable('r#"abc"', "unterminated raw string from line 1")
    undecidable("''", "unclassified quote at line 1")
    undecidable("'ab' x", "unclassified quote at line 1")
    undecidable("'\\q'", "unclassified quote at line 1")


@test
def lex_byte_char_literals():
    assert active("b'x' a\nb'\\n' b\nb'\"' c\nb'/' d") == ["a", "b", "c", "d"]


@test
def lex_empty_block_comment():
    assert active("/**/ a\nb /**/ c /**/") == ["a", "b" + " " * 6 + "c"]


@test
def lex_astral_char_literal():
    assert active("'\U0001F600' a\n'\U0001F600' /* b */ c") == ["a", "c"]


# --kernel mode (check_kernel): the hand-copied kernel facts against kernel
# source. The kernel is the tree in ABSD_KERNEL_RUN (check-all passes the
# exact revision it built); without it these tests are NOT_RUN, by name.
# Every negative control mutates scratch copies in a temporary directory
# (TMPDIR), never the kernel tree or this tree.

import contextlib
import io
import os
import shutil
import tempfile

KERNEL = os.environ.get("ABSD_KERNEL_RUN", "")
PLATFORM = GATE.parent.parent
KERNEL_FILES = sorted({rel for _f, rel, _p in gate.KERNEL_DEFS} | {gate.KERNEL_BASE[1]}
                      | {rel for _f, rel, _p in gate.KERNEL_SITES})
PLATFORM_FILES = sorted({binding[2] for binding in gate.BINDINGS})
KERNEL_TESTS = []
# Summary expectations come from the declared comparison inventory, never
# from the checker's output. Keep the exact expected narrower copies below.
EXPECTED_NARROWER = {
    "c/absd-c.ld:12-13": ["MAX_LOAD_SEGMENTS"],
    "user-linker.ld:7-8": ["MAX_LOAD_SEGMENTS"],
    "ssh/user-linker.ld:7-8": ["MAX_LOAD_SEGMENTS"],
    "integration/user-linker.ld:7-8": ["MAX_LOAD_SEGMENTS"],
}
CHECKED = len(gate.BINDINGS)
NARROWER = sum(map(len, EXPECTED_NARROWER.values()))
OK_SUMMARY = f"ABI FACTS OK checked={CHECKED} narrower={NARROWER}"


def kernel_test(fn):
    KERNEL_TESTS.append(fn)
    return fn


def scratch(tmp):
    """Copies of exactly the files the check reads: (kernel dir, platform dir)."""
    kdir, pdir = os.path.join(tmp, "kernel"), os.path.join(tmp, "platform")
    for src, dst, files in ((KERNEL, kdir, KERNEL_FILES), (str(PLATFORM), pdir, PLATFORM_FILES)):
        for rel in files:
            os.makedirs(os.path.dirname(os.path.join(dst, rel)), exist_ok=True)
            shutil.copyfile(os.path.join(src, rel), os.path.join(dst, rel))
    return kdir, pdir


def mutate(base, rel, old, new):
    path = os.path.join(base, rel)
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    assert text.count(old) == 1, f"control anchor {old!r} not unique in {rel}"
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text.replace(old, new))


def run_kernel(kdir, pdir):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = gate.check_kernel(kdir, pdir)
    return code, out.getvalue().splitlines()


def facts(lines, verdict):
    """{place: fact} of the comparison lines with `verdict`."""
    found = {}
    for line in lines:
        fields = line.split()
        if line.startswith("ABI FACT ") and fields[5] == verdict:
            found.setdefault(fields[4].rsplit("=", 1)[0], []).append(fields[2])
    return found


def control(mutations):
    """Apply `mutations` [(side, rel, old, new)] to scratch copies and run."""
    with tempfile.TemporaryDirectory(prefix="abi-facts-") as tmp:
        kdir, pdir = scratch(tmp)
        for side, rel, old, new in mutations:
            mutate(kdir if side == "kernel" else pdir, rel, old, new)
        return run_kernel(kdir, pdir)


@kernel_test
def kernel_reference_is_ok():
    code, lines = run_kernel(KERNEL, str(PLATFORM))
    assert code == 0, lines
    assert lines[-1] == OK_SUMMARY, lines[-1]
    assert any(line.startswith("ABI FACTS NOT_CHECKED ") for line in lines)
    # The kit's two-PT_LOAD link form is narrower than the loader, never equal to it.
    assert facts(lines, "NARROWER") == EXPECTED_NARROWER, lines


@kernel_test
def control_1_loader_lowered_to_two_segments():
    code, lines = control([("kernel", "src/elf.rs", "pub const MAX_LOAD_SEGMENTS: usize = 8;",
                            "pub const MAX_LOAD_SEGMENTS: usize = 2;")])
    assert code == 1, lines
    assert lines[-1].startswith("ABI FACTS MISMATCH mismatch=3 unknown=0 "), lines[-1]
    assert facts(lines, "MISMATCH") == {
        "scripts/check-abi-elf.py:56": ["MAX_LOAD_SEGMENTS"],
        "scripts/check-c-elf.py:64": ["MAX_LOAD_SEGMENTS"],
        "docs/C-INTERFACE.md:138": ["MAX_LOAD_SEGMENTS"]}, lines
    # The kit's two-segment form stays OK: kit contract, not kernel fact.
    ok = facts(lines, "OK")
    assert "MAX_LOAD_SEGMENTS" in ok["c/absd-c.ld:12-13"], lines
    assert "MAX_LOAD_SEGMENTS" in ok["user-linker.ld:7-8"], lines
    return lines


@kernel_test
def control_2_doc_only_edit():
    code, lines = control([("platform", "docs/C-INTERFACE.md", "PT_LOAD only (PT_NULL skipped), at most 8,",
                            "PT_LOAD only (PT_NULL skipped), at most 2,")])
    assert code == 1, lines
    assert facts(lines, "MISMATCH") == {"docs/C-INTERFACE.md:138": ["MAX_LOAD_SEGMENTS"]}, lines
    return lines


@kernel_test
def control_3_heap_window_pages_changed():
    code, lines = control([("kernel", "abi/src/layout.rs", "pub const USER_HEAP_PAGES: u64 = 8192;",
                            "pub const USER_HEAP_PAGES: u64 = 4096;")])
    assert code == 1, lines
    assert facts(lines, "MISMATCH") == {"runtime/src/allocator.rs:23": ["USER_HEAP_PAGES"],
                                        "docs/C-INTERFACE.md:130": ["USER_HEAP_PAGES"]}, lines
    return lines


@kernel_test
def control_4_renamed_kernel_constant_is_unknown():
    code, lines = control([("kernel", "abi/src/syscall.rs", "pub const MAX_MAP_PAGES: u64 = 64;",
                            "pub const MAX_MAP_PAGE_COUNT: u64 = 64;")])
    assert code == 2, lines
    assert lines[-1].startswith("ABI FACTS UNKNOWN unknown=3 "), lines[-1]
    assert not any(line.startswith("ABI FACTS OK") for line in lines)
    assert facts(lines, "UNKNOWN") == {"runtime/src/allocator.rs:20": ["MAX_MAP_PAGES"],
                                       "docs/C-INTERFACE.md:130": ["MAX_MAP_PAGES", "MAX_MAP_PAGES"]}, lines
    return lines


@kernel_test
def control_5_narrower_runtime_copy():
    code, lines = control([("platform", "runtime/src/allocator.rs", "const MAX_MAP_PAGES: usize = 64;",
                            "const MAX_MAP_PAGES: usize = 32;")])
    assert code == 0, lines
    assert lines[-1] == f"ABI FACTS OK checked={CHECKED} narrower={NARROWER + 1}", lines[-1]
    assert "MAX_MAP_PAGES" in facts(lines, "NARROWER")["runtime/src/allocator.rs:20"], lines
    return lines


@kernel_test
def missing_copy_is_unknown_not_ok():
    # A copy whose anchor no longer matches (here a removed doc row) is UNKNOWN.
    code, lines = control([("platform", "docs/C-INTERFACE.md", "| heap window | 32 MiB per process;",
                            "| heap window | about 32 MiB per process;")])
    assert code == 2, lines
    assert sorted(facts(lines, "UNKNOWN")) == ["docs/C-INTERFACE.md"], lines


@kernel_test
def kernel_site_without_the_constant_is_unknown():
    # The definition stays but the loader stops comparing against it.
    code, lines = control([("kernel", "src/elf.rs", "if image.segment_count == MAX_LOAD_SEGMENTS {",
                            "if image.segment_count == 16 {")])
    assert code == 2, lines
    assert any("enforcing site is not found" in line for line in lines), lines


# -- _source/_one/_count: Rust read as active code, other files raw ----------

def with_file(rel, text, fn):
    with tempfile.TemporaryDirectory(prefix="abi-src-") as tmp:
        with open(os.path.join(tmp, rel), "w", encoding="utf-8") as handle:
            handle.write(text)
        return fn(tmp)


@test
def rust_one_ignores_commented_copy_and_reads_trailing_comment_line():
    text = "/*\nconst N: u64 = 1;\n*/\nconst N: u64 = 2; // note\n"
    line, m = with_file("a.rs", text, lambda d: gate._one(d, "a.rs", r"const N: u64 = (\d+);"))
    assert (line, m.group(1)) == (4, "2"), (line, m)


@test
def non_rust_one_and_count_stay_raw():
    text = "/*\nconst N: u64 = 1;\n*/\nconst N: u64 = 2; // note\n"
    line, m = with_file("a.ld", text, lambda d: gate._one(d, "a.ld", r"const N: u64 = (\d+);"))
    assert (line, m.group(1)) == (2, "1"), (line, m)       # .ld: the comment is read, as before
    text = "/* never closed\n  a PT_LOAD FLAGS(5);\n"
    assert with_file("a.ld", text, lambda d: gate._count(d, "a.ld", gate._PHDR_LOAD)) == ("2", 1)


@test
def rust_count_ignores_commented_lines():
    text = "/*\n  a PT_LOAD FLAGS(5);\n*/\n  b PT_LOAD FLAGS(4); // c\n  d PT_LOAD FLAGS(6);\n"
    assert with_file("a.rs", text, lambda d: gate._count(d, "a.rs", gate._PHDR_LOAD)) == ("4-5", 2)


@test
def rust_undecidable_file_is_a_reason_not_a_hit():
    for fn in (lambda d: gate._one(d, "a.rs", r"const N: u64 = (\d+);"),
               lambda d: gate._count(d, "a.rs", r"const N: u64 = (\d+);")):
        none, why = with_file("a.rs", "const N: u64 = 1;\n/* never closed\n", fn)
        assert none is None and why == ("a.rs: active Rust source undecidable: "
                                        "unterminated block comment from line 2"), why


@test
def rust_duplicate_active_anchor_is_a_reason():
    text = "#[cfg(a)]\nconst N: u64 = 1;\n#[cfg(not(a))]\nconst N: u64 = 2;\n"
    none, why = with_file("a.rs", text, lambda d: gate._one(d, "a.rs", r"const N: u64 = (\d+);"))
    assert none is None and why == "a.rs: 2 lines match the anchor (want 1)", why


@test
def rust_cfg_gated_anchor_is_a_reason():
    pattern = r"if n > LIMIT \{"
    for text, gated in (("fn f() {\n    #[cfg(any())]\n    if n > LIMIT {\n", 3),
                        ("x();\n#[cfg_attr(test, inline)]\n// c\nif n > LIMIT {\n", 4),
                        ("#![cfg(test)]\nfn f() {\n    if n > LIMIT {\n", 3)):
        none, why = with_file("a.rs", text, lambda d: gate._one(d, "a.rs", pattern))
        assert none is None and why == f"a.rs:{gated}: the anchor is under a cfg attribute (not evaluated)", why
    line, _m = with_file("a.rs", "#[cfg(any())]\nfn g() {}\nfn f() {\n    if n > LIMIT {\n",
                         lambda d: gate._one(d, "a.rs", pattern))
    assert line == 4, line       # a cfg above the previous `{`/`}` does not gate


# -- Rust lexical negative controls (F1, handoff 6fc07eb8): commented or
# quoted kernel text is not evidence. D/G are the MAX_MAP_PAGES definition
# and its enforcing site in the same KERNEL tree used by check_kernel.

D = "pub const MAX_MAP_PAGES: u64 = 64;"
D128 = "pub const MAX_MAP_PAGES: u64 = 128; // revised bound"
G = "if pages == 0 || pages > MAX_MAP_PAGES {"
G128 = "    if pages == 0 || pages > 128 {"
MISMATCH_128 = (f"ABI FACTS MISMATCH mismatch=2 unknown=0 checked={CHECKED} "
                f"narrower={NARROWER + 1}")
UNKNOWN_MAP = f"ABI FACTS UNKNOWN unknown=3 checked={CHECKED - 3} narrower={NARROWER}"


def kernel_anchor_line(rel, anchor):
    """Locate a unique literal fixture anchor independently of the gate lexer."""
    text = (pathlib.Path(KERNEL) / rel).read_text(encoding="utf-8")
    assert text.count(anchor) == 1, f"control anchor {anchor!r} not unique in {rel}"
    return text[:text.index(anchor)].count("\n") + 1


def kernel_line(lines, fact):
    return next(line for line in lines if line.startswith(f"ABI KERNEL {fact}="))


def definition(new, code, kernel, last):
    """Replace D with `new`; expect exit `code`, the MAX_MAP_PAGES kernel line
    to equal `kernel` and the summary line to equal `last` (UNKNOWN
    definitions carry an additional diagnostic after the kernel prefix)."""
    got, lines = control([("kernel", "abi/src/syscall.rs", D, new)])
    assert got == code, lines
    found = kernel_line(lines, "MAX_MAP_PAGES")
    assert (found.startswith(kernel + " ") if code == 2 else found == kernel), found
    assert lines[-1] == last, lines[-1]
    assert not (code and any(line.startswith("ABI FACTS OK") for line in lines)), lines
    return lines


def mismatch_128(new, offset):
    line = kernel_anchor_line("abi/src/syscall.rs", D) + offset
    site = kernel_anchor_line("src/syscalls.rs", G)
    return definition(new, 1, f"ABI KERNEL MAX_MAP_PAGES=128 abi/src/syscall.rs:{line} "
                              f"enforced=src/syscalls.rs:{site}", MISMATCH_128)


def still_ok(new, offset):
    line = kernel_anchor_line("abi/src/syscall.rs", D) + offset
    site = kernel_anchor_line("src/syscalls.rs", G)
    return definition(new, 0, f"ABI KERNEL MAX_MAP_PAGES=64 abi/src/syscall.rs:{line} "
                              f"enforced=src/syscalls.rs:{site}", OK_SUMMARY)


def unknown_def(new, why):
    lines = definition(new, 2, "ABI KERNEL MAX_MAP_PAGES=UNKNOWN", UNKNOWN_MAP)
    assert why in kernel_line(lines, "MAX_MAP_PAGES"), kernel_line(lines, "MAX_MAP_PAGES")


def site_unknown(new, why="0 lines match the anchor"):
    code, lines = control([("kernel", "src/syscalls.rs", G, new)])
    assert code == 2, lines
    assert lines[-1] == UNKNOWN_MAP, lines[-1]
    found = kernel_line(lines, "MAX_MAP_PAGES")
    assert "enforcing site is not found" in found and why in found, found
    assert not any(line.startswith("ABI FACTS OK") for line in lines), lines


@kernel_test
def f1_commented_definition_is_not_evidence():
    # Handoff 6fc07eb8 substitution 1; the unrepaired checker said OK citing :458.
    mismatch_128("/*\n" + D + "\n*/\n" + D128, 3)


@kernel_test
def f1_commented_enforcing_site_is_not_evidence():
    # Handoff 6fc07eb8 substitution 2; the unrepaired checker said OK citing :1314.
    site_unknown("/*\n" + G + "\n*/\n" + G128)


@kernel_test
def nested_block_comment_hides_definition_and_site():
    mismatch_128("/* outer /* inner */\n" + D + "\n*/\n" + D128, 3)           # E1a
    site_unknown("/* outer /* inner */\n" + G + "\n*/\n" + G128)                # E1a
    still_ok("/* /* */ */\n" + D, 1)                                           # E1b
    mismatch_128("/* outer /* inner */\n" + D + "\n*/\n"
                 "pub const MAX_MAP_PAGES: u64 = 128;", 3)                     # E1c
    mismatch_128("/* /* */ " + D + " */\n" + D128, 1)                          # one-line nesting


@kernel_test
def line_and_doc_line_comments_are_not_evidence():
    mismatch_128("// " + D + "\n" + D128, 1)                                   # E2
    site_unknown("// " + G + "\n" + G128)                                        # E2
    mismatch_128("/// " + D + "\n" + D128, 1)                                  # E4a
    site_unknown("/// " + G + "\n" + G128)                                       # E4a
    mismatch_128("//! " + D + "\n" + D128, 1)                                  # E4b
    still_ok(D + " // the map bound", 0)                                       # trailing comment read


@kernel_test
def doc_block_comments_are_not_evidence():
    mismatch_128("/**\n" + D + "\n*/\n" + D128, 3)                             # E4c
    mismatch_128("/*!\n" + D + "\n*/\n" + D128, 3)
    mismatch_128("/** " + D + " */ pub const MAX_MAP_PAGES: u64 = 128;", 0)    # code after the doc block


@kernel_test
def block_comment_open_and_close_mid_line():
    mismatch_128("const _A: u8 = 0; /*\n" + D + "\n*/ pub const MAX_MAP_PAGES: u64 = 128;", 2)
    mismatch_128("/* " + D + " */ pub const MAX_MAP_PAGES: u64 = 128;", 0)


@kernel_test
def strings_and_chars_hold_delimiters_not_evidence():
    still_ok('const _OPEN: &str = "/*";\n' + D + '\nconst _CLOSE: &str = "*/";', 1)   # E3a
    still_ok('const _Q: &str = "\\" /*";\n' + D, 1)                                  # escaped quote
    still_ok('const _R: &str = r"/*";\nconst _RH: &str = r#"a " /* b"#;\n'
             'const _B: &[u8] = b"/*";\nconst _BR: &[u8] = br#"" /*"#;\n'
             "const _DQ: char = '\"';\nconst _SL: char = '/';\nconst _AP: char = '\\'';\n"
             "fn _l<'a>(x: &'a str) -> &'a str { x }\n" + D, 8)
    mismatch_128('const _DOC: &str = r#"\n' + D + '\n"#;\n' + D128, 3)                # E3b
    site_unknown('let _doc = r#"\n' + G + '\n"#;\n' + G128)                             # E3b
    mismatch_128('const _S: &str = "\n' + D + '\n";\n' + D128, 3)                    # plain multi-line


@kernel_test
def cfg_gated_duplicate_or_alternate_is_unknown():
    unknown_def("#[cfg(any())]\n" + D + "\n" + D128, "2 lines match the anchor")       # E5
    site_unknown("#[cfg(any())]\n    " + G + "\n        return -1;\n    }\n" + G128,
                 "under a cfg attribute")


@kernel_test
def undecidable_kernel_source_is_unknown():
    for tail, why in (("\n/* never closed", "unterminated block comment"),
                      ('\nconst _S: &str = "never closed;', "unterminated string"),
                      ("\nconst _Q: char = '';", "unclassified quote")):
        code, lines = control([("kernel", "abi/src/syscall.rs", D, D + tail)])
        assert code == 2, lines
        for fact in ("MAX_SPAWN_IMAGE_BYTES", "MAX_MAP_PAGES"):
            found = kernel_line(lines, fact)
            assert f"=UNKNOWN abi/src/syscall.rs: active Rust source undecidable: {why}" in found, found
        assert not any(line.startswith("ABI FACTS OK") for line in lines), lines


@kernel_test
def platform_rust_copy_in_a_comment_is_not_evidence():
    # P1: the runtime's map cap commented out and widened past the kernel.
    code, lines = control([("platform", "runtime/src/allocator.rs", "const MAX_MAP_PAGES: usize = 64;",
                            "/*\nconst MAX_MAP_PAGES: usize = 64;\n*/\nconst MAX_MAP_PAGES: usize = 128; // widened")])
    assert code == 1, lines
    assert facts(lines, "MISMATCH") == {"runtime/src/allocator.rs:23": ["MAX_MAP_PAGES"]}, lines


@kernel_test
def linker_binding_inside_a_comment_is_still_read():
    # R1: c/absd-c.ld states the window inside its /* */ header on purpose.
    with open(os.path.join(PLATFORM, "c/absd-c.ld"), encoding="utf-8") as handle:
        assert handle.readline().startswith("/*")
    code, lines = run_kernel(KERNEL, str(PLATFORM))
    assert code == 0 and facts(lines, "OK")["c/absd-c.ld:2"] == ["USER_IMAGE_MIN", "USER_IMAGE_MAX"], lines
    code, lines = control([("platform", "c/absd-c.ld", "   0x80_0040_0000..0x80_0400_0000,",
                            "   0x80_0050_0000..0x80_0400_0000,")])
    assert code == 1 and facts(lines, "MISMATCH") == {"c/absd-c.ld:2": ["USER_IMAGE_MIN"]}, lines


if __name__ == "__main__":
    for fn in TESTS:
        fn()
    if KERNEL:
        for fn in KERNEL_TESTS:
            fn()
        kernel_mode = f"{len(KERNEL_TESTS)} kernel={gate._kernel_identity(KERNEL)}"
    else:
        kernel_mode = "NOT_RUN (set ABSD_KERNEL_RUN)"
    print(f"ABI ELF GATE TESTS OK tests={len(TESTS)} kernel_mode={kernel_mode}")
