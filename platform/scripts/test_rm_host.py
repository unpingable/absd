"""Compile the real rm source for Linux; fixture crates supply mount inventory only.

Argument parsing, refusal logic and filesystem operations are production code.
The host filesystem is real. These tests do not establish ABSD ABI behavior.
"""
from pathlib import Path
import os
import hashlib
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
FSD = 'pub mod proto { pub struct Mount { pub path: Vec<u8> } }'
RUNTIME = r'''
pub fn link_anchor() {}
pub mod fsd {
    pub fn active() -> bool {
        std::env::var_os("HOST_RM_MOUNT").is_some()
            || std::env::var_os("HOST_RM_QUERY_FAILURE").is_some()
    }
    pub fn mounts() -> Result<Vec<absd_fsd::proto::Mount>, ()> {
        if std::env::var_os("HOST_RM_QUERY_FAILURE").is_some() { return Err(()); }
        Ok(std::env::var_os("HOST_RM_MOUNT").into_iter().map(|p|
            absd_fsd::proto::Mount { path: p.into_encoded_bytes() }).collect())
    }
}
'''


class RealRm(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='absd-rm-host-build-')
        cls.addClassCleanup(cls.build.cleanup)
        build = Path(cls.build.name)
        (build / 'fsd.rs').write_text(FSD)
        (build / 'runtime.rs').write_text(RUNTIME)
        env = dict(os.environ, RUSTC_BOOTSTRAP='1')
        def rustc(*args):
            subprocess.run(['rustc', '+1.95.0', '--edition=2021', *map(str, args)],
                           env=env, check=True, capture_output=True)
        fsd = build / 'libabsd_fsd.rlib'
        runtime = build / 'libabsd_runtime.rlib'
        rustc('--crate-type=rlib', '--crate-name=absd_fsd', build / 'fsd.rs', '-o', fsd)
        rustc('--crate-type=rlib', '--crate-name=absd_runtime', build / 'runtime.rs',
              '--extern', f'absd_fsd={fsd}', '-o', runtime)
        cls.binary = build / 'rm'
        rustc(ROOT / 'src/bin/rm.rs', '--extern', f'absd_fsd={fsd}', '--extern',
              f'absd_runtime={runtime}', '-L', f'dependency={build}', '-o', cls.binary)
        print('HOST RM SOURCE sha256=' + hashlib.sha256((ROOT / 'src/bin/rm.rs').read_bytes()).hexdigest()
              + ' backend=fixture-mount-inventory filesystem=real-host', flush=True)

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='absd-rm-host-case-')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)

    def run_rm(self, *args, mount=None, query_failure=False, cwd=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith('HOST_RM_')}
        if mount is not None:
            env['HOST_RM_MOUNT'] = str(mount)
        if query_failure:
            env['HOST_RM_QUERY_FAILURE'] = '1'
        return subprocess.run([str(self.binary), *map(str, args)], cwd=cwd or self.root,
                              env=env, capture_output=True, timeout=10)

    def assert_silent(self, result):
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_force_missing_is_silent(self):
        self.assert_silent(self.run_rm('-f', 'missing'))

    def test_missing_without_force_remains_an_error(self):
        result = self.run_rm('missing')
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'rm: missing:', result.stderr)

    def test_force_without_operands_succeeds(self):
        for flags in [('-f',), ('-rf',), ('-fr',), ('-r', '-f', '--')]:
            with self.subTest(flags=flags):
                self.assert_silent(self.run_rm(*flags))

    def test_missing_operands_without_force_is_usage(self):
        for flags in [(), ('-r',), ('--',)]:
            self.assertEqual(self.run_rm(*flags).returncode, 2)

    def test_clustered_and_repeated_flags_remove_real_trees(self):
        for index, flags in enumerate([('-rf',), ('-fr',), ('-rfr',), ('-f', '-r'), ('-r', '-f')]):
            with self.subTest(flags=flags):
                directory = self.root / f'two words {index}'
                directory.mkdir()
                (directory / 'kept').write_bytes(b'payload')
                self.assert_silent(self.run_rm(*flags, directory, 'missing'))
                self.assertFalse(directory.exists())

    def test_force_does_not_hide_not_a_directory(self):
        file = self.root / 'file'
        file.write_bytes(b'keep')
        result = self.run_rm('-f', 'file/child')
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'file/child', result.stderr)
        self.assertEqual(file.read_bytes(), b'keep')

    def test_force_does_not_allow_nonrecursive_directory_removal(self):
        (self.root / 'dir').mkdir()
        result = self.run_rm('-f', 'dir')
        self.assertEqual(result.returncode, 1)
        self.assertTrue((self.root / 'dir').is_dir())
        self.assertIn(b'use -r', result.stderr)

    def test_other_error_does_not_skip_later_operands(self):
        (self.root / 'dir').mkdir()
        (self.root / 'file').write_bytes(b'delete')
        result = self.run_rm('-f', 'dir', 'file', 'missing')
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.root / 'file').exists())
        self.assertTrue((self.root / 'dir').exists())

    def test_double_dash_and_lone_dash_are_operands(self):
        for name in ['-f', '-rf', '-']:
            (self.root / name).write_bytes(b'delete')
            self.assert_silent(self.run_rm('-f', '--', name))
            self.assertFalse((self.root / name).exists())

    def test_option_after_operand_is_a_filename(self):
        (self.root / 'file').write_bytes(b'delete')
        (self.root / '-f').write_bytes(b'delete')
        self.assert_silent(self.run_rm('file', '-f'))
        self.assertFalse((self.root / '-f').exists())

    def test_unknown_cluster_is_usage_before_any_mutation(self):
        file = self.root / 'file'
        file.write_bytes(b'keep')
        result = self.run_rm('-rfz', 'file')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(file.read_bytes(), b'keep')

    def test_force_preserves_dot_and_dotdot_refusal(self):
        # Both operands remain inside this test's own tree even if a regression
        # removes the refusal. Never pass the real host root or temp parent.
        nested = self.root / 'nested'
        nested.mkdir()
        (self.root / 'keep').write_bytes(b'keep')
        for name in ['.', '..']:
            result = self.run_rm('-rf', name, cwd=nested)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b'refusing to remove', result.stderr)
            self.assertTrue((self.root / 'keep').exists())

    def test_force_preserves_mount_point_refusal(self):
        protected = self.root / 'protected'
        protected.mkdir()
        (protected / 'keep').write_bytes(b'keep')
        result = self.run_rm('-rf', protected, mount=protected)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'a mount point', result.stderr)
        self.assertEqual((protected / 'keep').read_bytes(), b'keep')

    def test_force_preserves_descendant_mount_refusal(self):
        protected = self.root / 'protected'
        (protected / 'mount').mkdir(parents=True)
        (protected / 'keep').write_bytes(b'keep')
        result = self.run_rm('-rf', protected, mount=protected / 'mount')
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'holds a mount point', result.stderr)
        self.assertEqual((protected / 'keep').read_bytes(), b'keep')

    def test_force_preserves_mount_query_failure_refusal(self):
        protected = self.root / 'protected'
        protected.mkdir()
        (protected / 'keep').write_bytes(b'keep')
        result = self.run_rm('-rf', protected, query_failure=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'cannot be told', result.stderr)
        self.assertEqual((protected / 'keep').read_bytes(), b'keep')


if __name__ == '__main__':
    unittest.main()
