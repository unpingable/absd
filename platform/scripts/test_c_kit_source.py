#!/usr/bin/env python3
"""Real source/receipt and direct-install boundary tests; no compiler or guest."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
# D4: every other builder of the shared kit refuses a kit from another commit.
KIT_CONSUMERS = ('build-posix.sh', 'build-cports.sh', 'build-cxx-runtime.sh', 'build-llvm-kit.sh',
                 'run-cports.sh')


class CKitSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='absd-ckit-source-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'platform'
        (self.root / 'scripts').mkdir(parents=True)
        (self.root / 'userland').mkdir()
        for name in ('c_kit_source.py', 'install-userland-ports.sh', 'build-ports.sh', *KIT_CONSUMERS):
            shutil.copyfile(ROOT / 'scripts' / name, self.root / 'scripts' / name)
        self.helper = self.root / 'scripts/c_kit_source.py'
        self.out = self.base / 'userland-build'
        (self.out / 'absd').mkdir(parents=True)
        self.binary = self.out / 'absd/printf'
        self.binary.write_bytes(b'prebuilt local C-port fixture')
        (self.root / 'userland/PORTS.tsv').write_text(
            'printf\tsbase-0.1\tprintf.c\tabsd/printf\t' +
            hashlib.sha256(self.binary.read_bytes()).hexdigest() + '\t' +
            hashlib.sha256(b'stripped printf fixture').hexdigest() + '\t' +
            str(len(b'stripped printf fixture')) + '\n')
        self.kit_build = self.base / 'isolated-kit'
        self.kit = self.kit_build / 'kit'
        (self.kit / 'lib').mkdir(parents=True)
        self.archive = self.kit / 'lib/libabs.a'
        self.archive.write_bytes(b'local kit archive fixture')
        (self.kit / 'bin').mkdir()
        (self.kit / 'bin/absd-cc').write_text('#!/bin/sh\nexit 99\n')
        (self.kit / 'bin/absd-cc').chmod(0o755)
        self.cports = self.base / 'isolated-cports'
        self.posix = self.cports / 'lib/libabsd-posix.a'
        self.posix.parent.mkdir(parents=True)
        self.posix.write_bytes(b'local POSIX adapter archive fixture')
        self.ports = self.base / 'installed'
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        self.env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1',
                        ABSD_CKIT_BUILD=str(self.kit_build),
                        ABSD_USERLAND_BUILD=str(self.out),
                        ABSD_CPORTS_BUILD=str(self.cports),
                        ABSD_PORTS_DIR=str(self.base / 'installed'))
        self.env.pop('ABSD_ALLOW_MODIFIED', None)
        self.write_repro()
        self.git('init', '--quiet')
        (self.root / '.gitignore').write_text('ports/\ncommands/\n')  # as the platform's
        # Source coverage is now an operator composition prerequisite. Put
        # these unrelated fixture pages in the initial clean source identity.
        (self.root / 'man').mkdir()
        for name in ('absd-sh', 'sh', 'printf'):
            shutil.copyfile(ROOT / 'man' / f'{name}.1', self.root / 'man' / f'{name}.1')
        self.head = self.commit('first')
        self.write_kit()
        self.run_helper('capture', check=True)
        self.run_helper('stamp', check=True)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args],
                                       env=self.env, text=True).strip()

    def commit(self, value):
        (self.root / 'source').write_text(value)
        self.git('add', '-A')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid',
                 'commit', '--quiet', '-m', value)
        return self.git('rev-parse', 'HEAD')

    def write_kit(self, commit=None, dirty='no'):
        (self.kit / 'BUILT-FROM').write_text(
            f'commit {commit or self.head}\ndirty {dirty}\n' +
            'lib/libabs.a ' + hashlib.sha256(self.archive.read_bytes()).hexdigest() + '\n')

    def write_repro(self):
        # Run build-userland.sh's own manifest line, not a hand-written
        # spelling of it, so linked_posix is checked against what it parses.
        line = [l for l in (ROOT / 'scripts/build-userland.sh').read_text().splitlines()
                if 'repro/round$round.sha256' in l and 'sha256sum' in l]
        self.assertEqual(len(line), 1)
        (self.out / 'repro').mkdir(exist_ok=True)
        for round in (1, 2):
            subprocess.run(['sh', '-euc', line[0].strip(), 'manifest'], check=True, env=self.env | {
                'out': str(self.out), 'cports': str(self.cports), 'utils': 'printf', 'round': str(round)})

    def run_helper(self, mode, check=False, extra=()):
        args = ['python3', '-B', '-I', str(self.helper), mode, str(self.root)]
        if mode not in ('source', 'installed'):
            args.append(str(self.kit))
        if mode not in ('source', 'kit', 'installed'):
            args.append(str(self.out))
        if mode in ('stamp', 'verify', 'seal'):
            args += ['--posix', str(self.posix)]
        if mode in ('seal', 'installed'):
            args += ['--ports', str(self.ports)]
        return subprocess.run(args + list(extra), env=self.env, text=True,
                              capture_output=True, check=check)

    def refused(self, mode='verify', message=None):
        result = self.run_helper(mode)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('C KIT SOURCE REFUSED', result.stderr)
        if message:
            self.assertIn(message, result.stderr)

    def test_matching_fresh_output_verifies(self):
        self.run_helper('verify', check=True)
        record = json.loads(self.binary.with_name('printf.built-from.json').read_text())
        self.assertEqual(record['platform_commit'], self.head)
        self.assertEqual(record['elf_sha256'], hashlib.sha256(self.binary.read_bytes()).hexdigest())

    def test_receipt_write_ignores_legacy_temporary_symlink(self):
        helper = self.helper_module()
        receipt = self.base / 'receipt.json'
        protected = self.base / 'unrelated'
        protected.write_bytes(b'keep these fixture bytes')
        legacy = receipt.with_name(receipt.name + '.new')
        legacy.symlink_to(protected)
        value = {'schema_version': 2, 'case': 'legacy-path'}
        helper.write(receipt, value)
        self.assertEqual(protected.read_bytes(), b'keep these fixture bytes')
        self.assertTrue(legacy.is_symlink())
        self.assertFalse(receipt.is_symlink())
        self.assertEqual(json.loads(receipt.read_text()), value)

    def test_receipt_creation_collision_is_exclusive_and_private(self):
        helper = self.helper_module()
        receipt = self.base / 'receipt.json'
        protected = self.base / 'unrelated'
        protected.write_bytes(b'keep these fixture bytes')
        real_open = os.open
        collisions = []
        created = []

        def concurrent_entry(path, flags, mode=0o777):
            self.assertEqual(Path(path).parent, receipt.parent)
            self.assertTrue(flags & os.O_EXCL)
            if not collisions:
                Path(path).symlink_to(protected)
                collisions.append(Path(path))
            fd = real_open(path, flags, mode)
            created.append(Path(path))
            self.assertEqual(os.fstat(fd).st_mode & 0o777, 0o600)
            return fd

        value = {'schema_version': 2, 'case': 'exclusive'}
        with mock.patch.object(helper.os, 'open', side_effect=concurrent_entry):
            helper.write(receipt, value)
        self.assertEqual(len(collisions), 1)
        self.assertEqual(len(created), 1)
        self.assertTrue(collisions[0].is_symlink())
        self.assertFalse(created[0].exists())
        self.assertEqual(protected.read_bytes(), b'keep these fixture bytes')
        self.assertEqual(json.loads(receipt.read_text()), value)

    def test_receipt_write_failure_keeps_previous_and_removes_temporary(self):
        import io
        helper = self.helper_module()
        receipt = self.base / 'receipt.json'
        receipt.write_bytes(b'previous receipt\n')
        before = set(self.base.iterdir())
        real_open = io.open

        class PartialWrite:
            def __init__(self, file, *args, **kwargs):
                self.stream = real_open(file, *args, **kwargs)

            def __enter__(self):
                return self

            def write(self, text):
                self.stream.write(text[:4])
                raise OSError('fixture partial write')

            def __exit__(self, *args):
                self.stream.close()

        with mock.patch.object(io, 'open', side_effect=PartialWrite):
            with self.assertRaisesRegex(OSError, 'fixture partial write'):
                helper.write(receipt, {'schema_version': 2})
        self.assertEqual(receipt.read_bytes(), b'previous receipt\n')
        self.assertEqual(set(self.base.iterdir()), before)

    def test_receipt_rename_failure_keeps_previous_and_removes_temporary(self):
        helper = self.helper_module()
        receipt = self.base / 'receipt.json'
        receipt.write_bytes(b'previous receipt\n')
        before = set(self.base.iterdir())
        with mock.patch.object(Path, 'replace', side_effect=OSError('fixture rename refusal')):
            with self.assertRaisesRegex(OSError, 'fixture rename refusal'):
                helper.write(receipt, {'schema_version': 2})
        self.assertEqual(receipt.read_bytes(), b'previous receipt\n')
        self.assertEqual(set(self.base.iterdir()), before)

    def test_stale_kit_commit_refuses(self):
        self.commit('second')
        self.refused(message='C kit was built from')

    def test_stale_kit_refuses_verify_and_seal_with_fresh_receipts(self):
        # Receipts and ports/ agree with each other and with the commit the
        # kit names; only the kit is behind HEAD. kit_identity refuses first.
        self.ports.mkdir()
        (self.ports / 'printf').write_bytes(b'stripped printf fixture')
        self.commit('second')
        self.refused('verify', 'C kit was built from')
        self.refused('seal', 'C kit was built from')
        self.assertFalse((self.ports / '.c-ports.built-from.json').exists())

    def test_stale_prebuilt_output_refuses_with_fresh_kit(self):
        self.head = self.commit('second')
        self.write_kit()
        self.refused(message='platform_commit differs')

    def test_same_commit_changed_kit_refuses_prebuilt_output(self):
        self.archive.write_bytes(b'changed archive')
        self.write_kit()
        self.refused(message='kit_libabs_sha256 differs')

    def test_mutated_archive_refuses_kit_receipt(self):
        self.archive.write_bytes(b'unrecorded archive change')
        self.refused(message='libabs.a differs')

    def test_mutated_binary_refuses_its_receipt(self):
        self.binary.write_bytes(b'changed prebuilt bytes')
        self.refused(message='bytes differ')

    def test_missing_binary_receipt_refuses(self):
        self.binary.with_name('printf.built-from.json').unlink()
        self.refused(message='missing or invalid')

    def test_invalid_binary_receipt_refuses(self):
        self.binary.with_name('printf.built-from.json').write_text('{}')
        self.refused(message='unsupported receipt schema')

    def test_missing_kit_stamp_refuses(self):
        (self.kit / 'BUILT-FROM').unlink()
        self.refused(message='missing or unreadable')

    def test_duplicate_commit_records_refuse(self):
        with (self.kit / 'BUILT-FROM').open('a') as out:
            out.write(f'commit {self.head}\n')
        self.refused(message='exactly one commit')

    def test_extra_commit_fields_refuse(self):
        p = self.kit / 'BUILT-FROM'
        p.write_text(p.read_text().replace(f'commit {self.head}', f'commit {self.head} extra'))
        self.refused(message='exactly one commit')

    def test_broken_git_file_refuses_instead_of_snapshot(self):
        shutil.rmtree(self.root / '.git')
        (self.root / '.git').write_text('gitdir: /nonexistent-absd-fixture-gitdir\n')
        self.write_kit(commit='none', dirty='unknown')
        self.refused('source', 'Git identity unavailable')
        self.refused('verify', 'Git identity unavailable')

    def test_leaked_git_dir_refuses_instead_of_snapshot(self):
        self.env['GIT_DIR'] = str(self.base / 'missing-gitdir')
        self.refused('source', 'Git source overrides')

    def test_leaked_git_ceiling_refuses(self):
        self.env['GIT_CEILING_DIRECTORIES'] = str(self.root)
        self.refused('source', 'Git source overrides')

    def test_none_kit_refuses_for_real_checkout(self):
        self.write_kit(commit='none', dirty='unknown')
        self.refused(message='C kit was built from')

    def test_snapshot_none_requires_absent_own_git(self):
        shutil.rmtree(self.root / '.git')
        self.write_kit(commit='none', dirty='unknown')
        self.run_helper('capture', check=True)
        self.run_helper('stamp', check=True)
        self.run_helper('verify', check=True)
        self.assertEqual(json.loads(self.run_helper('source', check=True).stdout)['commit'], 'none')

    def test_dirty_kit_refuses_by_default(self):
        self.write_kit(dirty='yes')
        self.refused(message='dirty C kit')

    def test_unknown_kit_cleanliness_refuses_for_checkout(self):
        self.write_kit(dirty='unknown')
        self.refused(message='dirty C kit')

    def test_current_dirty_source_refuses(self):
        (self.root / 'source').write_text('uncommitted change')
        self.refused(message='dirty C kit or platform')

    def test_development_opt_in_is_explicit_and_reported(self):
        self.write_kit(dirty='yes')
        self.env['ABSD_ALLOW_MODIFIED'] = '1'
        result = self.run_helper('capture', check=True)
        self.assertIn('DIRTY development_opt_in=1', result.stderr)
        self.run_helper('stamp', check=True)
        self.run_helper('verify', check=True)

    def test_development_opt_in_never_waives_commit_mismatch(self):
        self.env['ABSD_ALLOW_MODIFIED'] = '1'
        self.commit('second')
        self.refused(message='C kit was built from')

    def test_changed_kit_during_build_refuses_stamp_publication(self):
        self.archive.write_bytes(b'kit changed after capture')
        self.write_kit()
        self.binary.with_name('printf.built-from.json').unlink()
        self.refused('stamp', 'kit_libabs_sha256 differs')
        self.assertFalse(self.binary.with_name('printf.built-from.json').exists())

    def test_missing_output_is_allowed_only_in_early_preflight(self):
        self.binary.unlink()
        self.run_helper('verify', check=True, extra=('--existing',))
        self.refused('verify')

    def test_direct_installer_refuses_stale_prebuilt_before_writing(self):
        self.head = self.commit('second')
        self.write_kit()
        result = subprocess.run(['sh', str(self.root / 'scripts/install-userland-ports.sh')],
                                env=self.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('platform_commit differs', result.stderr)
        self.assertFalse((self.base / 'installed').exists())

    def test_direct_build_ports_refuses_stale_prebuilt_before_building(self):
        self.head = self.commit('second')
        self.write_kit()
        result = subprocess.run(['sh', str(self.root / 'scripts/build-ports.sh')],
                                env=self.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('platform_commit differs', result.stderr)
        self.assertFalse(Path(str(self.root) + '.staged-compat').exists())

    # D2: the POSIX adapter archive every port links.

    def test_receipt_records_the_linked_posix_archive(self):
        record = json.loads(self.binary.with_name('printf.built-from.json').read_text())
        self.assertEqual(record['schema_version'], 2)
        self.assertEqual(record['posix_sha256'], hashlib.sha256(self.posix.read_bytes()).hexdigest())

    def test_changed_posix_archive_refuses_prebuilt_output(self):
        self.posix.write_bytes(b'adapter from another checkout')
        self.refused(message='posix_sha256 differs')

    def test_missing_posix_archive_refuses(self):
        self.posix.unlink()
        self.refused(message='libabsd-posix.a missing')

    def test_posix_path_is_required(self):
        result = subprocess.run(['python3', '-I', str(self.helper), 'verify', str(self.root), str(self.kit),
                                 str(self.out)], env=self.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--posix is required', result.stderr)

    def test_posix_changed_after_linking_refuses_stamp_publication(self):
        self.binary.with_name('printf.built-from.json').unlink()
        self.posix.write_bytes(b'adapter swapped after the rounds')
        self.refused('stamp', 'linked POSIX adapter archive differs')
        self.assertFalse(self.binary.with_name('printf.built-from.json').exists())

    def test_schema_1_receipt_without_posix_refuses(self):
        stamp = self.binary.with_name('printf.built-from.json')
        record = json.loads(stamp.read_text())
        record['schema_version'] = 1
        del record['posix_sha256']
        stamp.write_text(json.dumps(record))
        self.refused(message='unsupported receipt schema')

    def test_direct_installer_refuses_changed_posix_before_writing(self):
        self.posix.write_bytes(b'adapter from another checkout')
        result = subprocess.run(['sh', str(self.root / 'scripts/install-userland-ports.sh')],
                                env=self.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('posix_sha256 differs', result.stderr)
        self.assertFalse(self.ports.exists())

    def test_direct_build_ports_refuses_changed_posix_before_building(self):
        self.posix.write_bytes(b'adapter from another checkout')
        result = subprocess.run(['sh', str(self.root / 'scripts/build-ports.sh')],
                                env=self.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('posix_sha256 differs', result.stderr)
        self.assertFalse(Path(str(self.root) + '.staged-compat').exists())

    # D3: ports/ is sealed at install and checked by every reader of it.

    def install(self):
        self.ports.mkdir(exist_ok=True)
        (self.ports / 'printf').write_bytes(b'stripped printf fixture')
        self.run_helper('seal', check=True)

    def test_sealed_ports_verify(self):
        self.install()
        result = self.run_helper('installed', check=True)
        self.assertIn('ABSD C PORTS INSTALLED OK', result.stdout)
        record = json.loads((self.ports / '.c-ports.built-from.json').read_text())
        self.assertEqual(record['platform_commit'], self.head)
        self.assertEqual(record['ports'], {'printf': hashlib.sha256(b'stripped printf fixture').hexdigest()})

    def test_unsealed_ports_refuse(self):
        self.ports.mkdir()
        (self.ports / 'printf').write_bytes(b'ports installed before receipts')
        self.refused('installed', 'missing or invalid')

    def test_seal_refuses_stale_build_output(self):
        self.ports.mkdir()
        (self.ports / 'printf').write_bytes(b'stripped printf fixture')
        self.posix.write_bytes(b'adapter from another checkout')
        self.refused('seal', 'posix_sha256 differs')
        self.assertFalse((self.ports / '.c-ports.built-from.json').exists())

    def test_sealed_ports_refuse_after_a_new_commit(self):
        self.install()
        self.commit('second')
        self.refused('installed', 'platform_commit is')

    def test_sealed_ports_refuse_changed_bytes(self):
        self.install()
        (self.ports / 'printf').write_bytes(b'stale printf copied in later')
        self.refused('installed', 'bytes differ from the installed C-port receipt')

    def test_sealed_ports_refuse_a_missing_port(self):
        self.install()
        (self.ports / 'printf').unlink()
        self.refused('installed', 'printf missing')

    def test_sealed_ports_must_name_the_table(self):
        self.install()
        seal = self.ports / '.c-ports.built-from.json'
        record = json.loads(seal.read_text())
        record['ports']['extra'] = '0' * 64
        seal.write_text(json.dumps(record))
        self.refused('installed', 'do not name exactly')

    def test_sealed_ports_refuse_a_dirty_checkout(self):
        self.install()
        (self.root / 'source').write_text('uncommitted change')
        self.refused('installed', 'dirty checkout')

    def test_installed_ports_from_a_dirty_build_refuse(self):
        self.install()
        seal = self.ports / '.c-ports.built-from.json'
        record = json.loads(seal.read_text())
        record['platform_dirty'] = 'yes'
        seal.write_text(json.dumps(record))
        self.refused('installed', 'dirty checkout')

    def test_image_builder_refuses_unsealed_ports(self):
        # The ABSD_SKIP_BUILD=1 path: operator_image.py's system_files is
        # what build-operator-image, release and media_operator read.
        self.ports = self.root / 'ports'
        self.ports.mkdir()
        (self.ports / 'printf').write_bytes(b'ports installed before receipts')
        sys.path.insert(0, str(ROOT / 'scripts'))
        self.addCleanup(sys.path.remove, str(ROOT / 'scripts'))
        import operator_image as oi
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        os.environ.clear(); os.environ.update(self.env)
        with self.assertRaises(oi.Failed) as refused:
            oi.system_files(self.root)
        self.assertIn('C KIT SOURCE REFUSED', str(refused.exception))
        self.install()
        oi.c_ports_installed(self.root)

    def test_cmds_matrix_target_refuses_unsealed_ports(self):
        # Executed through cmds-matrix's own CmdsTarget.files, before any
        # other file of the image is read.
        self.ports = self.root / 'ports'
        self.ports.mkdir()
        (self.ports / 'printf').write_bytes(b'ports installed before receipts')
        sys.path.insert(0, str(ROOT / 'scripts'))
        self.addCleanup(sys.path.remove, str(ROOT / 'scripts'))
        import importlib.util
        spec = importlib.util.spec_from_file_location('cmds_matrix_under_test', ROOT / 'scripts/cmds-matrix.py')
        cmds = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cmds)
        import operator_image as oi
        target = object.__new__(cmds.CmdsTarget)
        target.root = self.root
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        os.environ.clear(); os.environ.update(self.env)
        with self.assertRaises(oi.Failed) as refused:
            target.files(None)
        self.assertIn('C KIT SOURCE REFUSED', str(refused.exception))
        self.assertIn('missing or invalid', str(refused.exception))

    def test_snapshot_seal_verifies_without_git(self):
        # A Git-less source snapshot seals and reads back as commit none;
        # dirty=unknown refuses only for a checkout whose commit is known.
        shutil.rmtree(self.root / '.git')
        self.write_kit(commit='none', dirty='unknown')
        self.run_helper('capture', check=True)
        self.run_helper('stamp', check=True)
        self.install()
        self.assertIn('commit=none', self.run_helper('installed', check=True).stdout)

    def test_every_ports_reader_checks_the_seal(self):
        installer = (ROOT / 'scripts/install-userland-ports.sh').read_text()
        self.assertLess(installer.index('rm -f "$ports/.c-ports.built-from.json"'), installer.index('llvm-strip-18 -o "$ports/$name"'))
        self.assertLess(installer.index('cmds-matrix.py" --host-check'), installer.index('c_kit_source.py" seal'))
        image = (ROOT / 'scripts/operator_image.py').read_text()
        self.assertIn('cports = c_ports_installed(root)', image)
        # Actual returned verified C bytes are protected by the mutation and
        # replacement consumer control below, independent of loop spelling.
        cmds = (ROOT / 'scripts/cmds-matrix.py').read_text()
        self.assertIn('for name in PORTS]', cmds)
        self.assertIn('cports[name]) for name in SBASE', cmds)
        userland = (ROOT / 'scripts/userland-matrix.py').read_text()
        self.assertIn('def product_files(self):', userland)
        self.assertIn('buffers = oi.c_ports_installed(', userland)
        self.assertNotIn('path.read_bytes()', userland[userland.index('class UserlandTarget'):userland.index('class UserlandMatrix')])
        parent = (ROOT / 'scripts/cports-matrix.py').read_text()
        self.assertIn('files += self.product_files()', parent)

    def helper_module(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        self.addCleanup(sys.path.remove, str(ROOT / 'scripts'))
        import c_kit_source
        return c_kit_source

    def test_seal_refuses_bytes_changed_after_installer_checks(self):
        self.ports.mkdir()
        (self.ports / 'printf').write_bytes(b'changed after checks')
        self.refused('seal', 'canonical userland/PORTS.tsv')
        self.assertFalse((self.ports / '.c-ports.built-from.json').exists())

    def test_seal_refuses_wrong_canonical_length(self):
        self.ports.mkdir()
        (self.ports / 'printf').write_bytes(b'stripped printf fixture')
        table = self.root / 'userland/PORTS.tsv'
        table.write_text(table.read_text().rsplit('\t', 1)[0] + '\t1\n')
        self.head = self.commit('wrong fixture length')
        self.write_kit()
        self.run_helper('capture', check=True)
        self.run_helper('stamp', check=True)
        self.refused('seal', 'canonical userland/PORTS.tsv')

    def test_self_consistent_forged_seal_cannot_replace_canonical_pin(self):
        self.install()
        changed = b'different bytes with matching forged receipt'
        (self.ports / 'printf').write_bytes(changed)
        seal = self.ports / '.c-ports.built-from.json'
        record = json.loads(seal.read_text())
        record['ports']['printf'] = hashlib.sha256(changed).hexdigest()
        seal.write_text(json.dumps(record))
        self.refused('installed', 'canonical userland/PORTS.tsv')

    def test_partial_installed_receipt_refuses(self):
        self.install()
        seal = self.ports / '.c-ports.built-from.json'
        record = json.loads(seal.read_text())
        record['ports'] = {}
        seal.write_text(json.dumps(record))
        self.refused('installed', 'do not name exactly')

    def test_null_port_digest_does_not_disable_receipt_verification(self):
        self.install()
        seal = self.ports / '.c-ports.built-from.json'
        record = json.loads(seal.read_text())
        record['ports']['printf'] = None
        seal.write_text(json.dumps(record))
        self.refused('installed', 'bytes differ from the installed C-port receipt')

    def test_seal_publishes_the_validated_buffer_after_path_replacement(self):
        helper = self.helper_module()
        self.ports.mkdir()
        port = self.ports / 'printf'
        port.write_bytes(b'stripped printf fixture')
        read = helper.read_verified_cport

        def replace_after_read(*args, **kwargs):
            data = read(*args, **kwargs)
            replacement = self.ports / 'replacement'
            replacement.write_bytes(b'replacement after verification')
            replacement.replace(port)
            return data

        with mock.patch.dict(os.environ, self.env, clear=True), mock.patch.object(helper, 'read_verified_cport', replace_after_read):
            identity = helper.kit_identity(self.root, self.kit)
            helper.seal(self.root, identity, self.out, self.posix, self.ports)
        self.assertEqual(port.read_bytes(), b'stripped printf fixture')
        self.run_helper('installed', check=True)
        self.assertEqual(list(self.ports.glob('.c-ports-*')), [])

    def consumer_fixture(self, consumer):
        """Run the real files() method, isolating unrelated native/manual inputs."""
        self.ports = self.root / 'ports'
        self.install()
        helper = self.helper_module()
        import operator_image as oi
        import importlib.util
        spec = importlib.util.spec_from_file_location('consumer_under_test', ROOT / 'scripts' / (consumer + '.py'))
        if consumer == 'operator_image':
            module = oi
        else:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        patches = [mock.patch.dict(os.environ, self.env, clear=True),
                   mock.patch.object(oi.ssh_absd, 'manual', return_value=[]),
                   mock.patch.object(oi.ssh_absd.AbsdTarget, 'files', return_value=[])]
        if consumer == 'operator_image':
            # Use the production declaration for the small fixture composition,
            # including every required shell alias and its manual coverage.
            with mock.patch.object(oi, 'NATIVE', []), mock.patch.object(oi, 'RUST_PORTS', []), mock.patch.object(oi, 'PORTS', ['printf']):
                names = oi.command_names()
            manual = [(f'/share/man/cat1/{name}.0', b'fixture rendered manual\n') for name in names]
            whatis = ''.join(f'{name}(1) - fixture command\n' for name in names).encode()
            manual.append(('/share/man/whatis', whatis))
            patches[1] = mock.patch.object(oi.ssh_absd, 'manual', return_value=manual)
            patches += [mock.patch.object(oi, 'NATIVE', []), mock.patch.object(oi, 'RUST_PORTS', []),
                        mock.patch.object(oi, 'PORTS', ['printf'])]
            commands = self.root / 'commands'
            commands.mkdir()
            for name in names:
                if name != 'printf': (commands / name).write_bytes(b'unrelated shell')
            call = lambda: oi.system_files(self.root)
        elif consumer == 'cmds-matrix':
            patches += [mock.patch.object(module, 'NATIVE', []), mock.patch.object(module, 'PORTS', []),
                        mock.patch.object(module, 'SBASE', ['printf'])]
            target = object.__new__(module.CmdsTarget)
            target.root = self.root
            call = lambda: target.files('unused')
        else:
            patches += [mock.patch.object(module, 'EXTRA', []), mock.patch.object(module.cm, 'EXTRA', []),
                        mock.patch.object(module, 'REPO', self.root), mock.patch.object(module, 'utils', return_value=['printf'])]
            target = object.__new__(module.UserlandTarget)
            target.root, target.case_files = self.root, []
            # If the inherited reader reopens products it must be detected.
            target.products = [self.ports / 'printf']
            call = lambda: target.files('unused')
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return helper, call

    def test_all_consumers_keep_verified_bytes_after_mutation_or_replacement(self):
        # Each case gets an independent fixture and the actual consumer method.
        for consumer in ('operator_image', 'cmds-matrix', 'userland-matrix'):
            for replacement in (False, True):
                with self.subTest(consumer=consumer, replacement=replacement):
                    fixture = CKitSourceTests('test_matching_fresh_output_verifies')
                    fixture.setUp()
                    try:
                        helper, call = fixture.consumer_fixture(consumer)
                        port = fixture.ports / 'printf'
                        read = helper.read_verified_cport
                        reads = []

                        def change_after_verify(*args, **kwargs):
                            data = read(*args, **kwargs)
                            reads.append(args[0])
                            if replacement:
                                other = fixture.ports / 'replacement'
                                other.write_bytes(b'changed after verified read')
                                other.replace(port)
                            else:
                                port.write_bytes(b'changed after verified read')
                            return data

                        with mock.patch.object(helper, 'read_verified_cport', change_after_verify):
                            files = dict(call())
                        self.assertEqual(files['/bin/printf'], b'stripped printf fixture')
                        if consumer == 'operator_image':
                            self.assertEqual(files['/bin/sh'], files['/bin/absd-sh'])
                            self.assertEqual(files['/bin/sh'], b'unrelated shell')
                        self.assertEqual(reads, [port])
                        self.assertEqual(port.read_bytes(), b'changed after verified read')
                        # A later invocation must reject the new unverified bytes.
                        with self.assertRaises(Exception) as refused:
                            call()
                        self.assertIn('bytes differ from the installed C-port receipt', str(refused.exception))
                    finally:
                        fixture.doCleanups()

    # D4: the other kit consumers refuse a kit built from another commit.

    def test_kit_consumers_refuse_a_stale_kit(self):
        self.commit('second')
        kernel = self.base / 'kernel'
        kernel.mkdir()
        env = self.env | {'ABSD_CKIT': str(self.kit), 'ABSD_KERNEL_RUN': str(kernel), 'ABSD_SKIP_BUILD': '1',
                          'ABSD_LLVM_BUILD': str(self.base / 'llvm-build'), 'ABSD_CXX_BUILD': str(self.base / 'cxx-build')}
        load = float(Path('/proc/loadavg').read_text().split()[0])
        for name in KIT_CONSUMERS:
            with self.subTest(name):
                if name == 'run-cports.sh' and load > 10:
                    self.skipTest('run-cports refuses to start above load 10, before any check')
                result = subprocess.run(['sh', str(self.root / 'scripts' / name)], env=env, text=True,
                                        capture_output=True, timeout=120)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('C KIT SOURCE REFUSED: C kit was built from', result.stdout + result.stderr)
        for unbuilt in ('llvm-build', 'cxx-build'):
            self.assertFalse((self.base / unbuilt).exists(), unbuilt)
        self.assertFalse(self.posix.with_name('posix-obj').exists())

    def test_run_c_kit_uses_the_strict_shared_reader(self):
        gate = (ROOT / 'scripts/run-c-kit.sh').read_text()
        self.assertIn('python3 -I "$root/scripts/c_kit_source.py" kit "$root" "$kit"', gate)
        self.assertNotIn('rev-parse HEAD 2>/dev/null || echo none', gate)

    def test_canonical_builder_checks_then_publishes_receipts(self):
        builder = (ROOT / 'scripts/build-userland.sh').read_text()
        capture = builder.index('c_kit_source.py" capture')
        stamp = builder.index('c_kit_source.py" stamp')
        gate = builder.index('python3 -I \"$root/scripts/check-userland.py\"')
        rounds = builder.index('for round in 1 2; do')
        self.assertLess(capture, rounds)
        self.assertLess(rounds, gate)
        self.assertLess(gate, stamp)
        kit_builder = (ROOT / 'scripts/build-c-kit.sh').read_text()
        self.assertIn('c_kit_source.py" source "$root"', kit_builder)


if __name__ == '__main__':
    unittest.main()
