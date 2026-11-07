#!/usr/bin/env python3
"""Host coverage controls; fixtures never touch an image or canonical pages."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import operator_image as oi
import manual_coverage as coverage
ROOT = Path(__file__).resolve().parent.parent


class SourceCoverageTests(unittest.TestCase):
    def test_capture_and_delay_ports_are_shipped_with_manuals(self):
        names = oi.command_names()
        for name in ('tee', 'sleep'):
            with self.subTest(command=name):
                self.assertIn(name, names, f'/bin/{name} missing from operator image')
                coverage.check(ROOT, [name])

    def test_shipped_sbase_tools_have_implemented_demand_status(self):
        summary = {row[0]: row[10] for line in (ROOT / 'userland/DEMAND-SUMMARY.tsv').read_text().splitlines()
                   if line.strip() and not line.startswith('#') for row in [line.split('\t')]}
        for line in (ROOT / 'userland/PORTS.tsv').read_text().splitlines():
            if not line.strip() or line.startswith('#'):
                continue
            name, upstream, *_ = line.split('\t')
            if upstream.startswith('sbase-'):
                with self.subTest(command=name):
                    self.assertIn(summary.get(name), ('T2', 'T3', 'T6'),
                                  f'{name} is shipped but its demand summary is not implemented')

    def test_ordinary_text_and_path_ports_are_shipped_with_manuals(self):
        names = oi.command_names()
        for name in ('tr', 'dirname'):
            with self.subTest(command=name):
                self.assertIn(name, names, f'/bin/{name} missing from operator image')
                coverage.check(ROOT, [name])

    def test_shipped_sources_are_complete(self):
        names = oi.command_names()
        missing = [n for n in names if not any((ROOT / 'man' / f'{n}.{s}').is_file() for s in (1, 8))]
        self.assertEqual(missing, [], f'{len(missing)} missing default pages: {missing}')
        self.assertTrue((ROOT / 'man/https-document.1').is_file(), 'missing optional https-document')


class ManualTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='absd-manual-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'man').mkdir()
        (self.root / 'man/cat.1').write_text('.Dt CAT 1\n.Nd copy bytes\n')
        self.files = [('/bin/cat', b'program'), ('/share/man/cat1/cat.0', b'CAT(1) manual\n'),
                      ('/share/man/whatis', b'cat(1) - copy bytes\n')]

    def test_complete_actual_composition(self):
        coverage.check(self.root, ['cat'], self.files)

    def test_missing_source_and_optional_source(self):
        for name in ('cat', 'https-document'):
            with self.subTest(name=name):
                path = self.root / 'man' / f'{name}.1'
                original = f'.Dt {name.upper()} 1\n.Nd fixture\n'.encode()
                path.write_bytes(original)
                coverage.check(self.root, [name])
                path.unlink()
                with self.assertRaisesRegex(coverage.Refused, name):
                    coverage.check(self.root, [name])
                path.write_bytes(b' \n')
                with self.assertRaisesRegex(coverage.Refused, name):
                    coverage.check(self.root, [name])
                path.write_bytes(original)
                coverage.check(self.root, [name])

    def test_missing_empty_render_and_whatis(self):
        for files in (self.files[:1] + self.files[2:],
                      [self.files[0], (self.files[1][0], b''), self.files[2]],
                      self.files[:2], self.files[:2] + [('/share/man/whatis', b'other(1) - other\n')]):
            with self.subTest(files=files), self.assertRaisesRegex(coverage.Refused, 'cat|whatis'):
                coverage.check(self.root, ['cat'], files)

    def test_duplicate_binary_source_render_and_index(self):
        with self.assertRaisesRegex(coverage.Refused, 'duplicate'):
            coverage.check(self.root, ['cat', 'cat'])
        for extra in (self.files[0], self.files[1], self.files[2]):
            with self.subTest(extra=extra), self.assertRaisesRegex(coverage.Refused, 'duplicate'):
                coverage.check(self.root, ['cat'], self.files + [extra])
        with self.assertRaisesRegex(coverage.Refused, 'duplicate'):
            coverage.check(self.root, ['cat'], self.files[:2] + [('/share/man/whatis', b'cat(1) - copy\ncat(1) - again\n')])
        shutil.copyfile(self.root / 'man/cat.1', self.root / 'man/cat.8')
        with self.assertRaisesRegex(coverage.Refused, 'ambiguous|duplicate'):
            coverage.check(self.root, ['cat'])

    def test_actual_extra_binary_refused(self):
        with self.assertRaisesRegex(coverage.Refused, 'new-command'):
            coverage.check(self.root, ['cat'], self.files + [('/bin/new-command', b'new')])

    def test_empty_whatis_description_refused(self):
        with self.assertRaisesRegex(coverage.Refused, 'cat'):
            coverage.check(self.root, ['cat'], self.files[:2] + [('/share/man/whatis', b'cat(1) - \n')])

    def test_system_files_refuses_before_return_to_writer(self):
        (self.root / 'commands').mkdir()
        for name in ('cat', 'absd-sh', 'sh', 'new-command'):
            (self.root / 'commands' / name).write_bytes(b'program')
        (self.root / 'man/absd-sh.1').write_text('.Dt ABSD-SH 1\n.Nd shell\n')
        (self.root / 'man/sh.1').write_text('.Dt SH 1\n.Nd shell alias\n')
        rendered = self.root / 'manpages/cat1'
        rendered.mkdir(parents=True)
        for name in ('cat', 'absd-sh', 'sh'):
            (rendered / f'{name}.0').write_bytes(b'rendered manual\n')
        (rendered.parent / 'whatis').write_bytes(b'cat(1) - copy\nabsd-sh(1) - shell\nsh(1) - alias\n')
        # Substitute only receipt acquisition, which is independent of manual
        # coverage. Real composition, reads and installed-manual reader run.
        with patch.object(oi, 'NATIVE', ['cat']), patch.object(oi, 'RUST_PORTS', []), \
             patch.object(oi, 'PORTS', []), patch.object(oi, 'c_ports_installed', return_value={}), \
             patch.dict('os.environ', {'ABSD_HTTPS_DOCUMENT': '0'}):
            self.assertEqual([p for p, _ in oi.system_files(self.root) if p.startswith('/bin/')],
                             ['/bin/cat', '/bin/absd-sh', '/bin/sh'])
            oi.NATIVE.append('new-command')
            sentinel = self.root / 'image'
            sentinel.write_bytes(b'unchanged image')
            with self.assertRaisesRegex(oi.Failed, 'new-command'):
                # An image writer can only consume a successfully returned
                # composition. This actual extra binary must stop it first.
                oi.system_files(self.root)
                sentinel.write_bytes(b'image would be mutated')
            self.assertEqual(sentinel.read_bytes(), b'unchanged image')
            oi.NATIVE.remove('new-command')
            oi.system_files(self.root)
            # Exercise the same optional switch used by the real builder.
            (self.root / 'commands/https-document').write_bytes(b'optional program')
            with patch.dict('os.environ', {'ABSD_HTTPS_DOCUMENT': '1'}):
                with self.assertRaisesRegex(oi.Failed, 'https-document'):
                    oi.system_files(self.root)
                (self.root / 'man/https-document.1').write_text('.Dt HTTPS-DOCUMENT 1\n.Nd fetch\n')
                (rendered / 'https-document.0').write_bytes(b'optional rendered page\n')
                index = rendered.parent / 'whatis'
                index.write_bytes(index.read_bytes() + b'https-document(1) - fetch\n')
                self.assertIn('/bin/https-document', dict(oi.system_files(self.root)))


if __name__ == '__main__':
    unittest.main()
