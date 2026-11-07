#!/usr/bin/env python3
"""Tests for scripts/picolibc-provenance.py: telling a dependency probe from consumed source, binding a
link map to its ELF, reading the archive, and the receipt. The probe controls
run the host clang when it is installed and are skipped otherwise.
The optional run-wiring control uses ABSD_TEST_PICOLIBC_BUILD and
ABSD_TEST_PICOLIBC_TARBALL with a matching ABSD_TEST_USERLAND_BUILD. Its
three output writes are captured in memory; it publishes no records.
Run: python3 scripts/test_picolibc_provenance.py"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import struct
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("picolibc_provenance", HERE / "picolibc-provenance.py")
pp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pp)

CLANG = shutil.which("clang-18") or shutil.which("clang")
# Assembled so that this file carries no licence wording of its own.
COPYLEFT_HEADER = "/* licensed under the GNU Lesser " + "General Public License */\n#define FROM_COPYLEFT 1\n"


def elf(sections):
    """A minimal ELF64 with the given allocated (name, address, size) sections."""
    names = b"\0" + b"".join(n.encode() + b"\0" for n, _, _ in sections) + b".shstrtab\0"
    header = bytearray(64)
    header[:5] = b"\x7fELF\x02"
    shoff = 64 + len(names)
    entries = [bytes(64)]
    offset = 1
    for name, addr, size in sections:
        entries.append(struct.pack("<IIQQQQIIQQ", offset, 1, 2, addr, 0, size, 0, 0, 1, 0))
        offset += len(name) + 1
    entries.append(struct.pack("<IIQQQQIIQQ", offset, 3, 0, 0, 64, len(names), 0, 0, 1, 0))
    struct.pack_into("<Q", header, 0x28, shoff)
    struct.pack_into("<HHH", header, 0x3A, 64, len(entries), len(entries) - 1)
    return bytes(header) + names + b"".join(entries)


class ProbeOrConsumed(unittest.TestCase):
    def test_a_consumed_file_missing_from_dependency_evidence_is_refused(self):
        text = '# 1 "a.c"\n# 1 "/unreviewed/header.h" 1\n#define X 1\n# 2 "a.c" 2\n'
        consumed = pp.consumed_files(text, '. /unreviewed/header.h\n', '/b', 'a.c')
        with self.assertRaisesRegex(pp.Refused, 'absent from the dependency record'):
            pp.classify(['a.c'], consumed, '/b')

    def test_consumed_files_come_from_the_trace_checked_against_the_markers(self):
        text = '# 1 "a.c"\n# 1 "<built-in>" 1\n# 1 "../src/inc/x.h" 1\nint x;\n# 2 "a.c" 2\n'
        consumed = pp.consumed_files(text, ". ../src/inc/x.h\n", "/b", "a.c")
        self.assertEqual(consumed, {"/b/a.c", "/src/inc/x.h"})
        rows = pp.classify(["a.c", "../src/inc/x.h", "/usr/include/limits.h"], consumed, "/b")
        self.assertEqual(rows, [("a.c", "consumed"), ("../src/inc/x.h", "consumed"), ("/usr/include/limits.h", "probe")])

    def test_a_marker_stream_that_disagrees_with_the_trace_is_refused(self):
        # Round 2: missing markers must not read as probes.
        with self.assertRaisesRegex(pp.Refused, "no line marker for its main file"):
            pp.consumed_files("int fegetround(void);\n", ". ../src/fenv.h\n", "/b", "a.c")
        with self.assertRaisesRegex(pp.Refused, "never enters it"):
            pp.consumed_files('# 1 "a.c"\nint x;\n', ". ../src/fenv.h\n", "/b", "a.c")

    def test_a_line_directive_name_does_not_authenticate_a_file(self):
        # Round 2: a #line logical name is not a physical file the trace saw.
        text = '# 1 "a.c"\n# 7 "../src/fenv.h"\nint fegetround(void);\n'
        self.assertEqual(pp.consumed_files(text, "", "/b", "a.c"), {"/b/a.c"})

    def test_marker_suppressing_options_are_refused(self):
        for option in ("-P", "-Wp,-P", "-fdirectives-only", "-C"):
            with self.subTest(option=option), self.assertRaisesRegex(pp.Refused, "suppresses or rewrites line markers"):
                pp.preprocess_command(f"clang {option} -c s.c -o s.o")

    def test_preprocessing_writes_nothing(self):
        args = pp.preprocess_command("clang -Ia -MD -MQ o.o -MF o.o.d -o o.o -c s.c")
        self.assertEqual(args, ["clang", "-Ia", "s.c", "-E", "-H", "-o", "-"])

    @unittest.skipUnless(CLANG, "no host clang")
    def test_a_probe_and_a_consumed_header_are_told_apart(self):
        # Negative controls with the real compiler. A freestanding include of
        # <limits.h> with the host search path probes the host's limits.h
        # (__has_include_next) without reading it; an included local header
        # whose text is the Lesser GPL's notice is consumed; with -P (round 2)
        # the command is refused instead of misreading the header as a probe.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "copyleft.h").write_text(COPYLEFT_HEADER)
            (tmp / "a.c").write_text('#include <limits.h>\n#include "copyleft.h"\nint x = FROM_COPYLEFT + CHAR_BIT;\n')
            base = f"{CLANG} --target=x86_64-unknown-none-elf -ffreestanding -c a.c -o a.o -MD -MF a.o.d"
            subprocess.run(base.split(), cwd=tmp, check=True, capture_output=True)
            deps = (tmp / "a.o.d").read_text().replace("\\\n", " ").split(":", 1)[1].split()
            pre = subprocess.run(pp.preprocess_command(base), cwd=tmp, check=True, capture_output=True, text=True)
            rows = dict(pp.classify(deps, pp.consumed_files(pre.stdout, pre.stderr, str(tmp), "a.c"), str(tmp)))
            self.assertEqual(rows["copyleft.h"], "consumed")
            self.assertEqual(rows["a.c"], "consumed")
            host = [d for d in rows if d.startswith("/usr/include/")]
            if Path("/usr/include/limits.h").exists():  # the host has a C library's headers
                self.assertTrue(host, "the freestanding compile no longer probes the host limits.h")
            self.assertEqual({rows[d] for d in host}, {"probe"} if host else set())
            with self.assertRaises(pp.Refused):
                pp.preprocess_command(base + " -P")
            # Hosted, the same include enters the host header: consumed.
            hosted = f"{CLANG} -c a.c -o b.o -MD -MF b.o.d"
            if subprocess.run(hosted.split(), cwd=tmp, capture_output=True).returncode == 0 and host:
                deps = (tmp / "b.o.d").read_text().replace("\\\n", " ").split(":", 1)[1].split()
                pre = subprocess.run(pp.preprocess_command(hosted), cwd=tmp, check=True, capture_output=True, text=True)
                rows = dict(pp.classify(deps, pp.consumed_files(pre.stdout, pre.stderr, str(tmp), "a.c"), str(tmp)))
                self.assertIn("consumed", {rows[d] for d in rows if d.startswith("/usr/include/")})


class HostInputRows(unittest.TestCase):
    @unittest.skipUnless(CLANG, 'no host clang')
    def test_real_host_probe_is_recorded_without_a_licence_assertion(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            header = tmp / 'unreviewed.h'
            header.write_text('#define PRIVATE_INPUT 1\n')
            (tmp / 'a.c').write_text('#include <limits.h>\n#include "' + str(header) +
                                    '"\nint x = CHAR_BIT + PRIVATE_INPUT;\n')
            command = f'{CLANG} --target=x86_64-unknown-none-elf -ffreestanding -c a.c -o a.o -MD -MF a.o.d'
            subprocess.run(command.split(), cwd=tmp, check=True, capture_output=True)
            deps = (tmp / 'a.o.d').read_text().replace('\\\n', ' ').split(':', 1)[1].split()
            pre = subprocess.run(pp.preprocess_command(command), cwd=tmp, check=True,
                                 capture_output=True, text=True)
            consumed = pp.consumed_files(pre.stdout, pre.stderr, str(tmp), 'a.c')
            rows = dict(pp.classify(deps, consumed, str(tmp)))
            probes = [dep for dep, use in rows.items() if dep.startswith('/usr/include/') and use == 'probe']
            self.assertTrue(probes, 'real compiler no longer records the host limits probe')
            for dep in probes:
                where, label, licence, digest = pp.host_input(dep, 'probe', {})
                self.assertEqual((where, label, licence), ('host:' + dep, '', ''))
                self.assertEqual(digest, hashlib.sha256(Path(dep).read_bytes()).hexdigest())
            self.assertEqual(rows[str(header)], 'consumed')
            with self.assertRaisesRegex(pp.Refused, 'without a reviewed identity'):
                pp.host_input(str(header), 'consumed', {})
            # A stale record must not drop a header the real compiler entered.
            with self.assertRaisesRegex(pp.Refused, 'absent from the dependency record'):
                pp.classify([dep for dep in deps if dep != str(header)], consumed, str(tmp))

    def test_consumed_host_inputs_keep_exact_reviewed_identity_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'reviewed.h'
            path.write_text('#define REVIEWED 1\n')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            reviewed = {'host:' + str(path): (digest, 'MIT', 'fixture')}
            self.assertEqual(pp.host_input(str(path), 'consumed', reviewed),
                             ('host:' + str(path), 'host:' + str(path), 'MIT', digest))
            path.write_text('#define REVIEWED 2\n')
            with self.assertRaisesRegex(pp.Refused, 'without a reviewed identity'):
                pp.host_input(str(path), 'consumed', reviewed)
            with self.assertRaises(pp.Refused):
                pp.host_input(str(path), 'unclassified', reviewed)

    def test_existing_table_reader_and_gate_accept_probe_not_consumed_without_terms(self):
        text = ('member\tlinked_by\tinput\tlabel\tlicence\tuse\tsha256\n'
                'a.o\ttool\thost:/usr/include/limits.h\t\t\tprobe\t' + '0' * 64 + '\n')
        rows = pp.pv.parse_tsv(text)
        self.assertEqual((rows[0]['label'], rows[0]['licence']), ('', ''))
        policy = tomllib.loads((pp.ROOT / 'provenance/config.toml').read_text())['licence_policy']
        table = {'path': 'c/picolibc/PROVENANCE.tsv'}
        gate = pp.pv.LicenceGate(False)
        self.assertEqual(pp.pv.licence_member_rows(table, {}, rows, policy, [], [], gate), 1)
        self.assertTrue(gate.ok(), gate.fails())
        self.assertEqual(gate.items[0][1], 'probe')
        rows[0]['use'] = 'consumed'
        refused = pp.pv.LicenceGate(False)
        pp.pv.licence_member_rows(table, {}, rows, policy, [], [], refused)
        self.assertFalse(refused.ok())
        self.assertIn('no licence recorded', str(refused.fails()))


# A retained userland build whose grep ELF is the one userland/PORTS.tsv
# records: $ABSD_TEST_USERLAND_BUILD, else the first known build that
# matches. A build is chosen by identity (the ELF's sha256), never because
# it exists: a build of another catalog would be refused by the collector.
GREP_ROW = next(l.split("\t") for l in (pp.ROOT / "userland/PORTS.tsv").read_text().splitlines()
                if l.startswith("grep\t"))
CANDIDATES = [Path(p) for p in os.environ.get("ABSD_TEST_USERLAND_BUILD", "").split(os.pathsep) if p]


def matching_build():
    for build in CANDIDATES:
        grep = build / "absd/grep"
        if grep.is_file() and hashlib.sha256(grep.read_bytes()).hexdigest() == GREP_ROW[4]:
            return build
    return None


USERLAND = matching_build()
PICOLIBC_BUILD = Path(os.environ['ABSD_TEST_PICOLIBC_BUILD']) if os.environ.get('ABSD_TEST_PICOLIBC_BUILD') else None
PICOLIBC_TARBALL = Path(os.environ['ABSD_TEST_PICOLIBC_TARBALL']) if os.environ.get('ABSD_TEST_PICOLIBC_TARBALL') else None


class RunWiring(unittest.TestCase):
    @unittest.skipUnless(USERLAND and PICOLIBC_BUILD and PICOLIBC_TARBALL,
                         'set ABSD_TEST_PICOLIBC_BUILD, ABSD_TEST_PICOLIBC_TARBALL and a matching userland build')
    def test_run_preserves_reviewed_resource_headers_as_consumed(self):
        # Exercise the real links, preprocessing, classification and host-row
        # callsite. Capture only the final publication boundary, not its inputs.
        paths = {pp.ROOT / name for name in (pp.TABLE, pp.NOTICE, pp.RECEIPT)}
        before = {path: path.read_bytes() for path in paths}
        old = pp.pv.parse_tsv(before[pp.ROOT / pp.TABLE].decode())
        expected = {(row['member'], row['input']): row['licence'] for row in old
                    if row['input'].startswith('host:') and row['use'] == 'consumed'}
        self.assertTrue(expected, 'fixture has no reviewed consumed resource headers')
        captured = {}

        def capture(path, text, *args, **kwargs):
            self.assertIn(path, paths, 'unexpected writer outside the three publication outputs')
            self.assertNotIn(path, captured, 'output written twice')
            captured[path] = text
            return len(text)

        with mock.patch.object(Path, 'write_text', autospec=True, side_effect=capture), \
                contextlib.redirect_stdout(io.StringIO()):
            pp.run(PICOLIBC_TARBALL, PICOLIBC_BUILD, USERLAND,
                   USERLAND.parent / 'ckit-build/kit', USERLAND.parent / 'cports-build/lib/libabsd-posix.a')
        self.assertEqual(set(captured), paths)
        self.assertEqual({path: path.read_bytes() for path in paths}, before)
        rows = {(row['member'], row['input']): row for row in pp.pv.parse_tsv(captured[pp.ROOT / pp.TABLE])}
        for identity, licence in expected.items():
            self.assertIn(identity, rows)
            self.assertEqual((rows[identity]['use'], rows[identity]['licence']), ('consumed', licence), identity)


class LinkedMembers(unittest.TestCase):
    @unittest.skipUnless(USERLAND, "no retained userland build whose grep is the ELF userland/PORTS.tsv records "
                         "(set ABSD_TEST_USERLAND_BUILD)")
    def test_membership_comes_from_the_link_not_a_recorded_map(self):
        # Round 2: deleting every libc.a line from the recorded grep.map
        # emptied the member list. The relink reproduces the gated ELF and its
        # own map gives the members; the recorded map is never read.
        row = GREP_ROW
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "userland"
            (fake / "absd").mkdir(parents=True)
            (fake / "obj").symlink_to(USERLAND / "obj")
            for suffix in ("", ".toolchain"):
                shutil.copyfile(USERLAND / f"absd/grep{suffix}", fake / f"absd/grep{suffix}")
            (fake / "absd/grep.map").write_text("")
            kit, posix = USERLAND.parent / "ckit-build/kit", USERLAND.parent / "cports-build/lib/libabsd-posix.a"
            retained, _, _ = pp.port_link("grep", row[1], row[3], row[4], fake, kit, posix, Path(tmp))
            self.assertEqual(len(retained), 50)
            (fake / "obj").unlink()
            (fake / "obj/absd").mkdir(parents=True)
            for f in (USERLAND / "obj/absd").iterdir():
                if f.is_file():
                    shutil.copyfile(f, fake / "obj/absd" / f.name)
            shutil.copyfile(USERLAND / "obj/absd/cmp.o", fake / "obj/absd/grep.o")   # other inputs, other ELF
            with self.assertRaises(pp.Refused):
                pp.port_link("grep", row[1], row[3], row[4], fake, kit, posix, Path(tmp))


class Bindings(unittest.TestCase):
    def test_a_map_must_describe_its_elf(self):
        data = elf([(".text", 0x8000400000, 0x100), (".data", 0x8000401000, 0x20)])
        self.assertEqual(pp.elf_sections(data), {".text": (0x8000400000, 0x100), ".data": (0x8000401000, 0x20)})
        good = ("             VMA              LMA     Size Align Out     In      Symbol\n"
                "      8000400000       8000400000      100  4096 .text\n"
                "      8000401000       8000401000       20  4096 .data\n"
                "               0                0      200     8 .symtab\n")
        listed = pp.map_sections(good)
        self.assertTrue(all(pp.elf_sections(data).get(k) == v for k, v in listed.items()))
        bad = pp.map_sections(good.replace("      100  4096 .text", "      180  4096 .text"))
        self.assertFalse(all(pp.elf_sections(data).get(k) == v for k, v in bad.items()))

    def test_archive_members(self):
        def member(name, body):
            return f"{name:<16}{0:<12}{0:<6}{0:<6}{644:<8}{len(body):<10}`\n".encode() + body + (b"\n" if len(body) % 2 else b"")
        long = b"a_very_long_member_name.c.o/\n"
        data = b"!<arch>\n" + member("/", b"\0\0\0\0") + member("//", long) + member("s.o/", b"abc") + member("/0", b"xy")
        self.assertEqual(pp.ar_members(data), {"s.o": [b"abc"], "a_very_long_member_name.c.o": [b"xy"]})

    def test_the_receipt_binds_the_table(self):
        rows = [("a.o", "t", "x.c", "L", "MIT", "consumed", "0"), ("a.o", "t", "y.h", "L", "MIT", "probe", "0")]
        with tempfile.TemporaryDirectory() as tmp:
            saved, pp.ROOT = pp.ROOT, Path(tmp)
            try:
                for p in pp.BOUND:
                    (pp.ROOT / p).parent.mkdir(parents=True, exist_ok=True)
                    (pp.ROOT / p).write_text(p)
                table, receipt = pp.receipt_for(rows, {"a.o": {"t"}}, {"inputs": {}})
            finally:
                pp.ROOT = saved
        r = json.loads(receipt)
        self.assertEqual((r["rows"], r["probe_rows"], r["consumed_rows"], r["members"], r["coverage"]),
                         (2, 1, 1, ["a.o"], {"a.o": 2}))
        self.assertEqual(r["table_sha256"], pp.sha256(table.encode()))
        self.assertEqual(r["bound_files"], {p: pp.sha256(p.encode()) for p in pp.BOUND})


if __name__ == "__main__":
    unittest.main()
