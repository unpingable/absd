#!/usr/bin/env python3
"""Bounded controls for receipt publication, source mutation and stale outputs."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('receipt', Path(__file__).with_name('operator_build_receipt.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        (self.root / 'scripts').mkdir()
        (self.root / 'scripts/prepare-and-build.sh').write_text('build\n')
        (self.root / '.gitignore').write_text('*.elf\ncommands/\n')
        for args in [('init', '-q'), ('add', '.'), ('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')]:
            subprocess.run(['git', '-C', str(self.root), *args], check=True)
        self.receipt = self.base / 'receipt.json'
        self.tool = self.base / 'tool'
        self.tool.write_text('fixture tool')
        self.lookup = patch.object(m.shutil, 'which', return_value=str(self.tool))
        self.lookup.start()
        self.addCleanup(self.lookup.stop)
        self.env = patch.dict(os.environ, {'ABSD_INCREMENTAL': '0', 'ABSD_HTTPS_DOCUMENT': '0'})
        self.env.start()
        self.addCleanup(self.env.stop)

    def begin(self):
        m.begin(self.root, self.receipt, self.base)

    def outputs(self):
        for name in m.OUTPUTS:
            path = self.root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(b'new executable')

    def test_success_and_exclusive_receipt(self):
        self.begin()
        self.outputs()
        m.finish(self.root, self.receipt)
        result = json.loads(self.receipt.read_text())
        self.assertEqual(result['status'], 'success')
        self.assertEqual(set(result['outputs']), set(m.OUTPUTS))
        self.assertFalse(Path(str(self.receipt) + '.pending').exists())
        with self.assertRaises(ValueError):
            self.begin()

    def test_old_output_removed_and_incomplete_build_never_succeeds(self):
        self.outputs()
        self.begin()
        self.assertFalse((self.root / 'sshd.elf').exists())
        with self.assertRaises(ValueError):
            m.finish(self.root, self.receipt)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(json.loads(Path(str(self.receipt) + '.pending').read_text())['status'], 'started')

    def test_canonical_generated_outputs_are_ignored(self):
        # Use the real project's exact rules; the generic unit fixture's
        # *.elf rule otherwise masks missing generated-product declarations.
        rules = Path(__file__).resolve().parents[1] / '.gitignore'
        (self.root / '.gitignore').write_bytes(rules.read_bytes())
        outputs = set(m.required_outputs()) | set(m.required_outputs({'ABSD_HTTPS_DOCUMENT': '1'}))
        for name in sorted(outputs):
            with self.subTest(output=name):
                result = subprocess.run(['git', '-C', str(self.root), 'check-ignore',
                                         '--no-index', '-q', name])
                self.assertEqual(result.returncode, 0)

    def test_logger_stale_bytes_are_removed_and_fresh_hash_is_bound(self):
        logger = self.root / 'absd-logd.elf'
        logger.write_bytes(b'stale logger')
        self.begin()
        self.assertFalse(logger.exists())
        self.outputs()
        m.finish(self.root, self.receipt)
        result = json.loads(self.receipt.read_text())
        self.assertEqual(result['outputs']['absd-logd.elf']['sha256'], m.digest(logger))

    def test_missing_logger_cannot_publish_success(self):
        self.begin()
        self.outputs()
        (self.root / 'absd-logd.elf').unlink(missing_ok=True)
        with self.assertRaisesRegex(ValueError, 'absd-logd.elf'):
            m.finish(self.root, self.receipt)
        self.assertFalse(self.receipt.exists())

    def test_document_selection_requires_fresh_output(self):
        app = self.root / 'commands/https-document'
        app.parent.mkdir()
        app.write_bytes(b'stale')
        with patch.dict(os.environ, {'ABSD_HTTPS_DOCUMENT': '1'}):
            self.begin()
            self.assertFalse(app.exists())
            self.outputs()
            with self.assertRaisesRegex(ValueError, 'https-document'):
                m.finish(self.root, self.receipt)
            app.write_bytes(b'fresh app')
            m.finish(self.root, self.receipt)
        result = json.loads(self.receipt.read_text())
        self.assertEqual(result['outputs']['commands/https-document']['sha256'], m.digest(app))

    def test_selection_change_refused(self):
        self.begin()
        self.outputs()
        with patch.dict(os.environ, {'ABSD_HTTPS_DOCUMENT': '1'}):
            with self.assertRaisesRegex(ValueError, 'selection changed'):
                m.finish(self.root, self.receipt)

    def test_untracked_source_refused(self):
        (self.root / 'new.rs').write_text('new source')
        with self.assertRaises(ValueError):
            self.begin()
        self.assertFalse(Path(str(self.receipt) + '.pending').exists())

    def test_source_change_during_build_refused(self):
        self.begin()
        self.outputs()
        (self.root / 'scripts/prepare-and-build.sh').write_text('changed')
        with self.assertRaises(ValueError):
            m.finish(self.root, self.receipt)
        self.assertFalse(self.receipt.exists())

    def test_tool_mutation_refused(self):
        self.begin()
        self.outputs()
        self.tool.write_text('changed')
        with self.assertRaises(ValueError):
            m.finish(self.root, self.receipt)
        self.assertFalse(self.receipt.exists())

    def test_incremental_refused(self):
        with patch.dict(os.environ, {'ABSD_INCREMENTAL': '1'}):
            with self.assertRaises(ValueError):
                self.begin()


if __name__ == '__main__':
    unittest.main()
