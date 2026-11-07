#!/usr/bin/env python3
"""Host controls for boot source composition; optional retained real ISO replay."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
spec = importlib.util.find_spec('boot_corresponding_source')
b = importlib.util.module_from_spec(spec) if spec else None
if b is not None:
    spec.loader.exec_module(b)


class SourceBundle(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(b, 'boot corresponding source implementation missing')
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.sources = self.root / 'sources'
        self.sources.mkdir()
        self.data = {'grub.dsc': b'Version: 2.12-1ubuntu7.3\n',
                     'unifont/source.tar.gz': b'fixture source archive'}
        self.pins = {name: hashlib.sha256(data).hexdigest() for name, data in self.data.items()}
        for name, data in self.data.items():
            p = self.sources / name
            p.parent.mkdir(exist_ok=True)
            p.write_bytes(data)
        self.pin_patch = patch.object(b, 'SOURCE_HASHES', self.pins)
        self.pin_patch.start()
        self.addCleanup(self.pin_patch.stop)
        self.iso = self.root / 'operator.iso'
        self.iso.write_bytes(b'fixture iso')
        self.out = self.root / 'source.tar'

    def build(self):
        with patch.object(b, 'verify_iso', return_value={'modules': 565, 'font': 1}) as verify:
            result = b.build(self.sources, self.iso, self.out)
            verify.assert_called_once_with(self.iso, 'vm-operator')
            return result

    def test_archive_roundtrip_and_deterministic_bytes(self):
        self.build()
        first = self.out.read_bytes()
        b.verify_archive(self.out)
        with tarfile.open(self.out) as t:
            self.assertEqual(set(t.getnames()), {'grub-source/' + n for n in self.data} | {'grub-source/SHA256SUMS'})
            for name, data in self.data.items():
                self.assertEqual(t.extractfile('grub-source/' + name).read(), data)
        self.out.unlink()
        self.build()
        self.assertEqual(first, self.out.read_bytes())

    def test_changed_source_refused_before_iso_check_or_output(self):
        (self.sources / 'grub.dsc').write_bytes(b'wrong source')
        with patch.object(b, 'verify_iso') as verify:
            with self.assertRaisesRegex(ValueError, 'source hash mismatch'):
                b.build(self.sources, self.iso, self.out)
            verify.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_wrong_source_version_refused(self):
        (self.sources / 'grub.dsc').write_bytes(b'Version: 2.12-1ubuntu7.4\n')
        with self.assertRaisesRegex(ValueError, 'source hash mismatch'):
            self.build()
        self.assertFalse(self.out.exists())

    def test_missing_input_refused(self):
        (self.sources / 'grub.dsc').unlink()
        with self.assertRaises((OSError, ValueError)):
            self.build()
        self.assertFalse(self.out.exists())

    def test_existing_output_preserved(self):
        self.out.write_bytes(b'previous evidence')
        with self.assertRaises((FileExistsError, ValueError)):
            self.build()
        self.assertEqual(self.out.read_bytes(), b'previous evidence')

    def test_iso_mismatch_never_creates_asset(self):
        with patch.object(b, 'verify_iso', side_effect=ValueError('ISO GRUB mismatch')):
            with self.assertRaisesRegex(ValueError, 'ISO GRUB mismatch'):
                b.build(self.sources, self.iso, self.out)
        self.assertFalse(self.out.exists())

    def test_archive_corruption_refused_even_with_updated_internal_checksums(self):
        self.build()
        with tarfile.open(self.out, 'w') as t:
            for name in self.data:
                data = b'replaced'
                entry = tarfile.TarInfo('grub-source/' + name)
                entry.size = len(data)
                t.addfile(entry, io.BytesIO(data))
            data = ''.join(f'{hashlib.sha256(b"replaced").hexdigest()}  {name}\n' for name in sorted(self.data)).encode()
            entry = tarfile.TarInfo('grub-source/SHA256SUMS')
            entry.size = len(data)
            t.addfile(entry, io.BytesIO(data))
        with self.assertRaises(ValueError):
            b.verify_archive(self.out)

    def test_changed_source_after_preflight_refused_by_archive_readback(self):
        def change(*args):
            (self.sources / 'grub.dsc').write_bytes(b'changed after preflight')
            return {}
        with patch.object(b, 'verify_iso', side_effect=change):
            with self.assertRaisesRegex(ValueError, 'source archive hash mismatch'):
                b.build(self.sources, self.iso, self.out)
        self.assertFalse(self.out.exists())

    def test_wrong_profile_version_refused(self):
        import media_operator
        profile = media_operator.load_operator_profile('vm-operator')
        profile['pins']['packages']['grub-common'] = 'wrong-version'
        with patch.object(b.media_operator, 'load_operator_profile', return_value=profile):
            with self.assertRaisesRegex(ValueError, 'GRUB package version'):
                b.verify_iso(self.iso)

    def test_changed_host_modules_refused_despite_version_label(self):
        with patch.object(b.subprocess, 'check_output', return_value=b.PINS['grub_version']), \
             patch.object(b.media_operator, 'grub_inventory', return_value=({'sha256': 'changed'}, {})):
            with self.assertRaisesRegex(ValueError, 'module inventory'):
                b.verify_iso(self.iso)

    def test_wrong_installed_version_refused(self):
        with patch.object(b.subprocess, 'check_output', return_value='wrong-version\n'):
            with self.assertRaisesRegex(ValueError, 'GRUB package version'):
                b.verify_iso(self.iso)


@unittest.skipUnless(os.environ.get('ABSD_BOOT_SOURCE_FIXTURE') and os.environ.get('ABSD_BOOT_ISO_FIXTURE'),
                     'explicit retained source and ISO fixture paths not supplied')
class RetainedFixtures(unittest.TestCase):
    def test_real_iso_changed_grub_module_and_font_refused(self):
        self.assertIsNotNone(b)
        import media
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = root / 'tree'
            (tree / 'boot').mkdir(parents=True)
            b.subprocess.run(['xorriso', '-osirrox', 'on', '-indev',
                os.environ['ABSD_BOOT_ISO_FIXTURE'], '-extract', '/boot/grub',
                str(tree / 'boot/grub')], check=True, capture_output=True)
            # File-tree fixtures only: rebuilding avoids copying stale hybrid
            # boot metadata, which would fail before the GRUB comparison.
            for number, target in enumerate(('boot/grub/i386-pc/normal.mod', 'boot/grub/fonts/unicode.pf2')):
                member = tree / target
                original = member.read_bytes()
                member.chmod(0o600)
                member.write_bytes(b'different GRUB package version or font')
                output = root / f'changed-{number}.iso'
                b.subprocess.run(['xorriso', '-as', 'mkisofs', '-R', '-o', str(output), str(tree)],
                    check=True, capture_output=True)
                member.write_bytes(original)
                with self.assertRaisesRegex(media.Refused, 'iso_grub_mismatch'):
                    b.verify_iso(output)

    def test_real_standalone_cli(self):
        self.assertIsNotNone(b)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'sources.tar'
            result = b.subprocess.run([sys.executable, '-B', str(Path(b.__file__)),
                '--sources', os.environ['ABSD_BOOT_SOURCE_FIXTURE'],
                '--operator-iso', os.environ['ABSD_BOOT_ISO_FIXTURE'], '--out', str(out)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['source_files'], 13)
            b.verify_archive(out)

    def test_real_sources_and_iso_roundtrip(self):
        self.assertIsNotNone(b)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'sources.tar'
            result = b.build(Path(os.environ['ABSD_BOOT_SOURCE_FIXTURE']),
                             Path(os.environ['ABSD_BOOT_ISO_FIXTURE']), out)
            self.assertEqual(result['source_files'], 13)
            self.assertEqual(result['grub']['modules'], 565)
            b.verify_archive(out)


if __name__ == '__main__':
    unittest.main()
