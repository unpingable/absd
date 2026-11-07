#!/usr/bin/env python3
"""Check installed native binaries against their declared Cargo workspaces."""
from pathlib import Path
import sys
import tomllib
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
import provenance as pv


class OperatorUnits(unittest.TestCase):
    def setUp(self):
        config = tomllib.loads((ROOT / 'provenance/config.toml').read_text())
        artifact = next(a for a in config['artifact'] if a['name'] == 'operator-image')
        self.units = {unit['name']: unit for unit in artifact['unit']}
        self.native = set(pv.literal(ROOT, 'scripts/operator_image.py:NATIVE'))
        self.ssh = tomllib.loads((ROOT / 'ssh/Cargo.toml').read_text())

    def test_root_unit_names_only_its_installed_native_binaries(self):
        unit = self.units['commands']
        actual = list(unit.get('bins', []))
        if 'bins_from' in unit:
            actual += pv.literal(ROOT, unit['bins_from'])
        delegated = {entry['name'] for entry in self.ssh['bin']}
        expected = (self.native - delegated) | {'absd_sh'}
        self.assertEqual(len(actual), len(set(actual)), 'duplicate root binary declaration')
        self.assertEqual(set(actual), expected)
        manifest = pv.Manifest(ROOT / 'Cargo.toml')
        self.assertEqual(unit['package'], manifest.name)
        for name in actual:
            with self.subTest(binary=name):
                self.assertIsNotNone(pv.bin_sources(manifest, name))

    def test_ssh_unit_covers_its_installed_native_binaries(self):
        unit = self.units['sshd']
        self.assertEqual(unit['package'], self.ssh['package']['name'])
        self.assertEqual(unit['lock'], 'ssh/Cargo.lock')
        names = {entry['name'] for entry in self.ssh['bin']}
        installed = self.native & names
        self.assertIn('absd-sftp', installed)
        # An omitted bins selector covers the whole package; an explicit
        # selector must keep every installed member of this workspace.
        if 'bins' in unit:
            self.assertTrue(installed <= set(unit['bins']))
        manifest = pv.Manifest(ROOT / 'ssh/Cargo.toml')
        for name in installed:
            with self.subTest(binary=name):
                self.assertIsNotNone(pv.bin_sources(manifest, name))


if __name__ == '__main__':
    unittest.main()
