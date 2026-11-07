#!/usr/bin/env python3
"""Real public-layout Git identities and strict kernel mapping admission; no build."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import operator_image as oi
import release_manifest as rm

spec = importlib.util.spec_from_file_location('public_identity_release', Path(__file__).with_name('release.py'))
rel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rel)


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), '-c', 'user.name=Fixture',
                                    '-c', 'user.email=fixture@example.invalid', *args], stderr=subprocess.PIPE).decode().strip()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)


class ReleaseInput:
    id = 'fixture'
    def __init__(self, snapshot=None, commit='a' * 40):
        self.snapshot, self.commit = snapshot, commit
    def kernel_commit(self): return self.commit
    def _manifest_doc(self):
        return {'source': {} if self.snapshot is None else {'kernel_snapshot': self.snapshot}}


class PublicSourceIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'public'
        self.kernel, self.platform = self.root / 'kernel', self.root / 'platform'
        write(self.kernel / 'Makefile', 'durable-iso:\n')
        write(self.kernel / '.gitignore', '/build/\n/target/\n')
        write(self.kernel / 'source.rs', '// curated kernel source\n')
        write(self.platform / '.cargo/config.toml', '[unstable]\nbuild-std = ["core"]\n')
        write(self.platform / '.gitignore', '/target/\n')
        for name in ('scripts/verify-inputs.sh', 'scripts/rustc-staged.sh', 'scripts/prepare-and-build.sh',
                     'user-linker.ld', 'patches/rust-1.95.0-absd-std.patch', 'pins/library.Cargo.lock', 'targets/x.json'):
            write(self.platform / name, 'fixture\n')
        source_inputs = Path(__file__).with_name('inputs.sh')
        shutil.copyfile(source_inputs, self.platform / 'scripts/inputs.sh')
        git(self.root, 'init', '-q')
        git(self.root, 'add', '.')
        index = git(self.root, 'write-tree')
        rows = []
        for name, commit, upstream in (('kernel', 'a' * 40, 'b' * 40), ('platform', 'c' * 40, 'd' * 40)):
            rows.append(f'[[component]]\nname = "{name}"\npath = "{name}"\ncommit = "{commit}"\n'
                        f'source_tree = "{upstream}"\ntree = "{git(self.root, "rev-parse", index + ":" + name)}"\n')
        write(self.root / 'SOURCE-MANIFEST.toml', '\n'.join(rows))
        git(self.root, 'add', '.'); git(self.root, 'commit', '-qm', 'curated public snapshot')
        self.head = git(self.root, 'rev-parse', 'HEAD')
        self.snapshot = oi.public_source_identity(self.kernel)
        self.run = self.base / 'kernel-run'
        subprocess.run(['git', 'clone', '-q', '--no-hardlinks', str(self.root), str(self.run)], check=True)
        self.addCleanup(patch.stopall)
        patch.object(rel.absd_inputs, 'ROOT', self.platform).start()
        patch.dict(os.environ, {'ABSD_KERNEL_SOURCE': str(self.kernel), 'ABSD_KERNEL_PROTECTED': str(self.kernel),
                                'ABSD_HTTPS_DOCUMENT': '0'}).start()
        rel.absd_inputs._resolved.cache_clear()
        self.addCleanup(rel.absd_inputs._resolved.cache_clear)

    def test_two_real_public_clones_match_with_actual_head_separate_from_upstream(self):
        self.assertEqual(self.snapshot, oi.public_source_identity(self.run / 'kernel'))
        self.assertEqual(self.snapshot['upstream_commit'], 'a' * 40)
        self.assertEqual(self.snapshot['repository_commit'], self.head)
        self.assertNotEqual(self.head, 'a' * 40)
        self.assertEqual(rel.check_kernel(self.run / 'kernel', ReleaseInput(self.snapshot)), self.run / 'kernel')
        with self.assertRaisesRegex(rel.Failed, 'canonical kernel'):
            rel.check_kernel(self.kernel, ReleaseInput(self.snapshot))

    def test_actual_manifest_generation_records_both_identities_and_checked_mapping(self):
        release = self.base / 'release'
        write(release / 'release', 'release=fixture\n')
        write(release / rm.ISO, 'ISO fixture; content extraction held outside identity test\n')
        with patch.object(rm, 'iso_contents', return_value={}), patch.object(rm, 'toolchain_tables', return_value={}):
            text = rm.build(release, self.platform, self.run / 'kernel', partial=True)
        doc = tomllib.loads(text)
        self.assertEqual(doc['source']['kernel_commit'], 'a' * 40)
        self.assertEqual(doc['source']['kernel_repository_commit'], self.head)
        self.assertEqual(doc['source']['kernel_snapshot'], self.snapshot)
        self.assertEqual(doc['source']['platform_commit'], self.head)
        self.assertEqual(doc['source']['platform_snapshot']['upstream_commit'], 'c' * 40)
        self.assertEqual(rel.check_kernel(self.run / 'kernel', ReleaseInput(doc['source']['kernel_snapshot'])), self.run / 'kernel')

    def test_wrong_manifest_component_or_component_tree_refuses(self):
        manifest = self.run / 'SOURCE-MANIFEST.toml'
        original = manifest.read_text()
        for changed in (original.replace('name = "kernel"', 'name = "wrong"'),
                        original.replace(self.snapshot['component_tree'], 'e' * 40),
                        original.replace('commit = "' + 'a' * 40, 'commit = "' + 'f' * 40)):
            manifest.write_text(changed)
            with self.assertRaises(oi.Failed):
                oi.public_source_identity(self.run / 'kernel')
        manifest.write_text(original)
        write(self.run / 'kernel/source.rs', '// changed bytes\n')
        with self.assertRaises(rel.Failed):
            rel.check_kernel(self.run / 'kernel', ReleaseInput(self.snapshot))

    def test_committed_alternate_mapping_cannot_satisfy_original_release(self):
        manifest = self.run / 'SOURCE-MANIFEST.toml'
        manifest.write_text(manifest.read_text().replace('commit = "' + 'a' * 40, 'commit = "' + 'f' * 40))
        git(self.run, 'add', '.'); git(self.run, 'commit', '-qm', 'different source mapping')
        with self.assertRaisesRegex(rel.Failed, 'differs from release mapping'):
            rel.check_kernel(self.run / 'kernel', ReleaseInput(self.snapshot))

    def test_missing_mapping_and_private_checkout_do_not_stand_for_public_snapshot(self):
        with self.assertRaisesRegex(rel.Failed, 'lacks corresponding release mapping'):
            rel.check_kernel(self.run / 'kernel', ReleaseInput())
        private = self.base / 'standalone'
        write(private / 'Makefile', 'fixture\n'); git(private, 'init', '-q')
        git(private, 'add', '.'); git(private, 'commit', '-qm', 'standalone kernel')
        self.assertIsNone(oi.public_source_identity(private))
        own = ReleaseInput(commit=git(private, 'rev-parse', 'HEAD'))
        self.assertEqual(rel.check_kernel(private, own), private)
        with self.assertRaisesRegex(rel.Failed, 'differs from release mapping'):
            rel.check_kernel(private, ReleaseInput(self.snapshot))

    def test_existing_manifest_verified_snapshot_copy_serves_private_release_admission(self):
        # This is the existing delivery adapter, not a public HEAD claimed as
        # private history. The committed public mapping was checked above.
        copied = self.base / 'legacy-snapshot-run'
        copied.mkdir()
        subprocess.run(['sh', '-c', 'root=$1; . "$root/scripts/inputs.sh"; absd_kernel_run "$2" unused "$3"',
                        'sh', str(self.platform), str(self.kernel), str(copied)],
                       check=True, capture_output=True)
        self.assertEqual((copied / '.absd-identity').read_text().strip(), 'a' * 40)
        self.assertEqual({p.name for p in copied.iterdir()}, {p.name for p in self.kernel.iterdir()} | {'.absd-identity'})
        for source in self.kernel.iterdir():
            self.assertEqual((copied / source.name).read_bytes(), source.read_bytes())
        self.assertIsNone(oi.public_source_identity(copied))
        self.assertEqual(rel.check_kernel(copied, ReleaseInput()), copied)
        # The same marker-only copy cannot represent a genuinely public-built
        # release whose manifest records a full public snapshot descriptor.
        with self.assertRaisesRegex(rel.Failed, 'differs from release mapping'):
            rel.check_kernel(copied, ReleaseInput(self.snapshot))

    def test_untracked_source_refused_ignored_generated_products_do_not_change_mapping(self):
        write(self.run / 'kernel/build/output', 'reproducible product\n')
        self.assertEqual(oi.public_source_identity(self.run / 'kernel'), self.snapshot)
        write(self.run / 'kernel/new.rs', '// undeclared source\n')
        with self.assertRaises(oi.Failed):
            oi.public_source_identity(self.run / 'kernel')


if __name__ == '__main__': unittest.main()
