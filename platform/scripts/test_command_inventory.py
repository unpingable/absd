#!/usr/bin/env python3
"""Command-matrix inventory consumers against the canonical catalog; host only."""
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
import operator_image as oi


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CommandInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='absd-command-inventory-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'userland').mkdir()
        (self.root / 'ports').mkdir()
        (self.root / 'man').mkdir()
        (self.root / 'sh/src').mkdir(parents=True)
        shutil.copyfile(ROOT / 'sh/src/lib.rs', self.root / 'sh/src/lib.rs')
        environment = mock.patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def fixture(self, names=None):
        names = names if names is not None else [name for name in oi.PORTS if name not in oi.RUST_PORTS]
        rows = []
        for name in names:
            data = ('fixture C port ' + name).encode()
            (self.root / 'ports' / name).write_bytes(data)
            rows.append('\t'.join([name, 'sbase-0.1', name + '.c', 'absd/' + name,
                                   hashlib.sha256(data).hexdigest(), hashlib.sha256(data).hexdigest(), str(len(data))]))
            (self.root / 'man' / (name + '.1')).write_text('.Xr sbase 7\n')
        (self.root / 'userland/PORTS.tsv').write_text('\n'.join(rows) + '\n')
        for name in ('sbase', 'toybox'):
            (self.root / 'man' / (name + '.7')).write_text('fixture manual\n')

    def test_reproduction_hashes_detect_changes_to_every_native_command(self):
        source = (ROOT / 'scripts/check-all.sh').read_text()
        start = source.index('# Reproducibility artifact declaration\n')
        end = source.index('# End reproducibility helpers\n', start)
        function = source[start:end]
        command = 'root=$1\nABSD_PROFILE=core\n' + function
        paths = subprocess.check_output(['/bin/sh', '-ec', command + '\nartifact_paths',
                                         'fixture', str(self.root)], text=True).splitlines()
        commands = oi.NATIVE + ['absd-sh', 'sh', 'sh-probe']
        self.assertEqual({p for p in paths if p.startswith('commands/')},
                         {'commands/' + name for name in commands})
        (self.root / 'commands').mkdir()
        for name in paths:
            (self.root / name).write_bytes(b'original product bytes')

        def hashes():
            return subprocess.check_output(['/bin/sh', '-ec',
                command + '\nartifact_hashes', 'fixture', str(self.root)])

        original = hashes()
        self.assertEqual(len(original.splitlines()), len(paths))
        for name in commands:
            with self.subTest(command=name):
                path = self.root / 'commands' / name
                path.write_bytes(b'changed product bytes')
                self.assertNotEqual(hashes(), original)
                path.write_bytes(b'original product bytes')

    def test_current_canonical_inventory_passes_actual_host_check(self):
        self.fixture()
        matrix = load('cmds-matrix')
        with contextlib.redirect_stdout(io.StringIO()):
            matrix.host_check(self.root)
        self.assertEqual(matrix.NATIVE, oi.NATIVE)
        self.assertEqual(matrix.PORTS, oi.RUST_PORTS)
        self.assertEqual(matrix.SBASE, [name for name in oi.PORTS if name not in oi.RUST_PORTS])

    def test_late_catalog_additions_are_installed_and_shell_alias_uses_inherited_bytes(self):
        with mock.patch.object(oi, 'NATIVE', oi.NATIVE + ['late-native']), \
             mock.patch.object(oi, 'RUST_PORTS', oi.RUST_PORTS + ['late-rust']), \
             mock.patch.object(oi, 'PORTS', oi.PORTS + ['late-rust']):
            matrix = load('cmds-matrix')
            commands = self.root / 'commands'
            commands.mkdir()
            for name in oi.NATIVE:
                (commands / name).write_bytes(('native ' + name).encode())
            for name in oi.RUST_PORTS:
                (self.root / 'ports' / name).write_bytes(('Rust ' + name).encode())
            shell = self.root / 'matrix-shell.elf'
            shell.write_bytes(b'inherited shell selected by superclass')
            for name in ('sshtest.elf', 'fsd-probe.elf'):
                (self.root / name).write_bytes(b'unrelated fixture helper')
            cports = {name: ('verified ' + name).encode() for name in oi.PORTS if name not in oi.RUST_PORTS}
            target = object.__new__(matrix.CmdsTarget)
            target.root, target.shell = self.root, shell
            with mock.patch.object(oi, 'c_ports_installed', return_value=cports), \
                 mock.patch.object(matrix.ssh_absd, 'manual', return_value=[]):
                files = target.files('fixture authorized key')
            installed = dict(files)
            self.assertEqual(installed['/bin/late-native'], b'native late-native')
            self.assertEqual(installed['/bin/late-rust'], b'Rust late-rust')
            self.assertEqual(installed['/bin/sh'], shell.read_bytes())
            self.assertEqual(installed['/bin/sh'], installed['/bin/absd-sh'])
            self.assertEqual(len(files), len(installed), 'duplicate install path')

    def test_demand_classifies_late_native_and_rust_catalog_additions(self):
        with mock.patch.object(oi, 'NATIVE', oi.NATIVE + ['late-native']), \
             mock.patch.object(oi, 'RUST_PORTS', oi.RUST_PORTS + ['late-rust']):
            demand = load('userland-demand')
            for name in oi.NATIVE:
                self.assertEqual(demand.disposition(name, True), 'native-present')
            self.assertEqual(demand.disposition('late-rust', True), 'uutils-present')

    def test_native_collision_remains_refused(self):
        with mock.patch.object(oi, 'NATIVE', oi.NATIVE + ['printf']):
            self.fixture()
            matrix = load('cmds-matrix')
            with self.assertRaisesRegex(matrix.HostCheckFailed, 'printf: a native command has the name'):
                matrix.host_check(self.root)

    def test_shell_alias_collision_remains_refused(self):
        with mock.patch.object(oi, 'PORTS', oi.PORTS + ['sh']):
            self.fixture()
            matrix = load('cmds-matrix')
            with self.assertRaisesRegex(matrix.HostCheckFailed, 'sh: a native command has the name'):
                matrix.host_check(self.root)

    def test_pin_and_manual_refusals_remain_effective(self):
        self.fixture()
        matrix = load('cmds-matrix')
        (self.root / 'ports/printf').write_bytes(b'wrong bytes')
        with self.assertRaisesRegex(matrix.HostCheckFailed, "not userland/PORTS.tsv"):
            matrix.host_check(self.root)
        self.fixture()
        (self.root / 'man/printf.1').unlink()
        with self.assertRaisesRegex(matrix.HostCheckFailed, 'man/printf.1 missing'):
            matrix.host_check(self.root)


if __name__ == '__main__':
    unittest.main()
