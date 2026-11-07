#!/usr/bin/env python3
"""SDK filesystem/CLI contracts; fixture archives are bytes, never compiler proof."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / 'scripts/package-sdk.py'
LIBS = ('libabs.a', 'libabs_builtins.a', 'crt0.o', 'libc.a', 'libm.a')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SDKTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sdk-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        (self.source / 'identity').write_text('clean source\n')
        self.git('init', '-q')
        self.kit = self.base / 'kit'
        for d in ('bin', 'lib', 'include/absd'):
            (self.kit / d).mkdir(parents=True)
        shutil.copyfile(ROOT / 'c/bin/absd-cc', self.kit / 'bin/absd-cc')
        (self.kit / 'bin/absd-cc').chmod(0o755)
        (self.kit / 'absd-c.ld').write_text('SECTIONS {}\n')
        (self.kit / 'include/absd/a.h').write_text('int a(void);\n')
        shutil.copyfile(ROOT / 'c/include/absd/syscall.h', self.kit / 'include/absd/syscall.h')
        for name in LIBS:
            (self.kit / 'lib' / name).write_bytes(name.encode())
        self.pico = self.base / 'pico'
        (self.pico / 'lib').mkdir(parents=True)
        for name in ('libc.a', 'libm.a'):
            (self.pico / 'lib' / name).write_bytes(('upstream ' + name).encode())
        (self.pico / 'include').mkdir()
        (self.pico / 'include/picolibc.h').write_text('// pinned header\n')
        shutil.copyfile(self.pico / 'include/picolibc.h', self.kit / 'include/picolibc.h')
        for source_name, target in [('bin/absd-cc', 'c/bin/absd-cc'),
                                    ('absd-c.ld', 'c/absd-c.ld'),
                                    ('include/absd/a.h', 'c/include/absd/a.h'),
                                    ('include/absd/syscall.h', 'c/include/absd/syscall.h')]:
            path = self.source / target
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.kit / source_name, path)
        (self.source / 'scripts').mkdir()
        shutil.copyfile(ROOT / 'scripts/check-c-elf.py', self.source / 'scripts/check-c-elf.py')
        (self.source / 'cxx/tests').mkdir(parents=True)
        (self.source / 'cxx/tests/cxx0.cpp').write_text('int main() { return 0; }\n')
        (self.source / 'cxx/tests/cxx0.expected').write_text('fixture output\n')
        (self.source / 'cxx/bin').mkdir(parents=True)
        shutil.copyfile(ROOT / 'cxx/bin/absd-c++', self.source / 'cxx/bin/absd-c++')
        (self.source / 'c/picolibc').mkdir()
        self.pin = ''.join(f'picolibc-{n}\t1.0\t{sha(self.pico / "lib" / n)}\n' for n in ('libc.a', 'libm.a'))
        (self.source / 'c/picolibc/PIN').write_text(self.pin)
        self.git('add', '.')
        self.git('-c', 'user.name=SDK Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture')
        self.commit = self.git('rev-parse', 'HEAD').stdout.strip()
        self.stamp = (f'commit {self.commit}\ndirty no\nsource {self.source}\n' +
                      ''.join(f'lib/{n} {sha(self.kit / "lib" / n)}\n' for n in LIBS) +
                      ''.join(f'picolibc-{n} {sha(self.pico / "lib" / n)}\n' for n in ('libc.a', 'libm.a')))
        (self.kit / 'BUILT-FROM').write_text(self.stamp)
        self.out = self.base / 'out'

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.source), *args], capture_output=True, text=True, check=True)

    def package(self, *extra, ok=True, out=None, timeout=5):
        result = subprocess.run([sys.executable, str(PACK), '--kit', str(self.kit),
            '--source-root', str(self.source), '--picolibc-install', str(self.pico),
            '--version', 'test-1', '--kernel-commit', 'a' * 40,
            '--platform-commit', 'b' * 40, '--out', str(out or self.out), *extra],
            capture_output=True, text=True, timeout=timeout)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def check(self, sdk, *args, ok=True, env=None):
        result = subprocess.run([str(sdk / 'bin/absd-sdk-check'), *args],
                                capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)
        return result

    def test_deterministic_archive_relocation_inventory_and_private_receipt(self):
        before = {str(p): sha(p) for p in self.kit.rglob('*') if p.is_file()}
        self.package()
        second = self.base / 'second'
        self.package(out=second)
        self.assertEqual(sha(self.out / 'absd-sdk-test-1.tar.gz'), sha(second / 'absd-sdk-test-1.tar.gz'))
        with tarfile.open(self.out / 'absd-sdk-test-1.tar.gz') as archive:
            archive.extractall(self.base / 'relocated', filter='data')
        sdk = self.base / 'relocated/absd-sdk-test-1'
        self.assertEqual((sdk / 'c/include/absd/syscall.h').read_bytes(),
                         (ROOT / 'c/include/absd/syscall.h').read_bytes())
        self.check(sdk, '--inventory-only')
        manifest = json.loads((sdk / 'metadata/manifest.json').read_text())
        self.assertEqual(manifest['schema_version'], 1)
        self.assertEqual(manifest['packaging_source'].get('tool_sha256', {}).get('package-sdk.py'), sha(PACK))
        self.assertEqual(manifest['build_source']['commit'], self.commit)
        self.assertEqual(manifest['compatibility']['platform_commit'], 'b' * 40)
        self.assertEqual(manifest['receipts']['c_original_sha256'], hashlib.sha256(self.stamp.encode()).hexdigest())
        self.assertEqual(manifest['licenses']['status'], 'pending-qualification')
        for p in sdk.rglob('*'):
            if p.is_file():
                self.assertNotIn(str(self.base).encode(), p.read_bytes(), str(p))
        self.assertEqual(before, {str(p): sha(p) for p in self.kit.rglob('*') if p.is_file()})
        (sdk / 'c/include/absd/a.h').write_text('changed')
        self.assertIn('inventory', self.check(sdk, '--inventory-only', ok=False).stderr)

    def test_c_receipt_refuses_experimental_and_unknown_fields(self):
        for marker in ('native-pcm-experiment 1', 'profile unsupported', 'future-runtime-mode 1'):
            with self.subTest(marker=marker):
                (self.kit / 'BUILT-FROM').write_text(self.stamp + marker + '\n')
                out = self.base / ('refused-' + marker.split()[0])
                self.assertIn('default C', self.package(ok=False, out=out).stderr)
                self.assertFalse(out.exists())

    def test_elf_checker_matches_distinct_clean_build_source(self):
        checker = self.source / 'scripts/check-c-elf.py'
        checker.write_text(checker.read_text() + '\n# different loader contract\n')
        self.git('add', '.')
        self.git('-c', 'user.name=SDK Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'checker revision')
        commit = self.git('rev-parse', 'HEAD').stdout.strip()
        (self.kit / 'BUILT-FROM').write_text(self.stamp.replace(self.commit, commit))
        self.assertIn('source mismatch', self.package(ok=False).stderr)
        self.assertFalse(self.out.exists())

    def test_source_snapshot_refused(self):
        (self.source / '.git').rename(self.base / 'retired-fixture-git')
        self.assertIn('clean Git checkout', self.package(ok=False).stderr)
        self.assertFalse(self.out.exists())

    def test_documented_extraction_preserves_modes_under_restrictive_umask(self):
        self.package()
        archive = self.out / 'absd-sdk-test-1.tar.gz'
        line = next(row for row in (ROOT / 'docs/HOST-SDK.md').read_text().splitlines() if row.startswith('tar '))
        command = shlex.split(line.replace('absd-sdk-VERSION.tar.gz', str(archive)))
        dest = self.base / 'documented-extraction'
        dest.mkdir()
        result = subprocess.run(command, cwd=dest, umask=0o077, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.check(dest / 'absd-sdk-test-1', '--inventory-only')

    def test_nonpreserving_extraction_reports_mode_remedy(self):
        self.package()
        dest = self.base / 'default-extraction'
        dest.mkdir()
        result = subprocess.run(['tar', '-xzf', str(self.out / 'absd-sdk-test-1.tar.gz')],
                                cwd=dest, umask=0o027, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        message = self.check(dest / 'absd-sdk-test-1', '--inventory-only', ok=False).stderr
        self.assertIn('mode mismatch', message)
        self.assertIn('tar -p', message)

    def test_immutable_output(self):
        self.package()
        self.assertIn('exists', self.package(ok=False).stderr)

    def test_nonempty_and_empty_existing_destinations_refused(self):
        self.out.mkdir()
        self.assertIn('exists', self.package(ok=False).stderr)
        (self.out / 'keep').write_text('keep')
        self.package(ok=False)
        self.assertEqual((self.out / 'keep').read_text(), 'keep')

    def test_all_archive_hashes_checked(self):
        for name in LIBS:
            with self.subTest(name=name):
                path = self.kit / 'lib' / name
                original = path.read_bytes()
                path.write_bytes(b'changed')
                self.assertIn('digest', self.package(ok=False).stderr)
                path.write_bytes(original)
        (self.pico / 'lib/libm.a').write_bytes(b'changed')
        self.assertIn('digest', self.package(ok=False).stderr)

    def test_source_driver_linker_and_header_bytes_bound(self):
        for name in ('bin/absd-cc', 'absd-c.ld', 'include/absd/a.h',
                     'include/absd/syscall.h', 'include/picolibc.h'):
            with self.subTest(name=name):
                path = self.kit / name
                original = path.read_bytes()
                path.write_bytes(b'changed')
                self.assertIn('source', self.package(ok=False, out=self.base / ('refused-' + name.replace('/', '-'))).stderr)
                path.write_bytes(original)

    def test_missing_and_additional_headers_refused(self):
        path = self.kit / 'include/picolibc.h'
        original = path.read_bytes()
        path.unlink()
        self.assertIn('header', self.package(ok=False).stderr)
        path.write_bytes(original)
        (self.kit / 'include/unpinned.h').write_text('extra')
        self.assertIn('header', self.package(ok=False, out=self.base / 'extra-header-out').stderr)

    def test_arbitrary_picolibc_archive_with_matching_stamp_refused(self):
        path = self.pico / 'lib/libm.a'
        original_digest = sha(path)
        path.write_bytes(b'arbitrary archive')
        (self.kit / 'BUILT-FROM').write_text(self.stamp.replace(original_digest, sha(path)))
        self.assertIn('PIN', self.package(ok=False).stderr)

    def test_dirty_source_and_bad_stamp_refused(self):
        (self.source / 'identity').write_text('changed')
        self.assertIn('clean', self.package(ok=False).stderr)
        self.git('checkout', '--', 'identity')
        (self.kit / 'BUILT-FROM').write_text(self.stamp + 'commit ' + self.commit + '\n')
        self.assertIn('exactly one', self.package(ok=False).stderr)

    def test_symlink_and_unexpected_installed_file_refused(self):
        (self.kit / 'include/link').symlink_to('/etc/passwd')
        self.assertIn('symlink', self.package(ok=False).stderr)
        (self.kit / 'include/link').unlink()
        (self.kit / 'private.log').write_text('not installed')
        self.assertIn('unexpected', self.package(ok=False).stderr)

    def test_inventory_refuses_extra_missing_modes_and_invalid_schema(self):
        self.package()
        sdk = self.out / 'absd-sdk-test-1'
        path = sdk / 'c/include/absd/a.h'
        path.chmod(0o755)
        self.check(sdk, '--inventory-only', ok=False)
        path.chmod(0o644)
        (sdk / 'extra').write_text('unexpected')
        self.check(sdk, '--inventory-only', ok=False)
        (sdk / 'extra').unlink()
        path.unlink()
        self.check(sdk, '--inventory-only', ok=False)
        manifest = sdk / 'metadata/manifest.json'
        manifest.write_text('{"schema_version":99}')
        (sdk / 'metadata/manifest.sha256').write_text(sha(manifest) + '  manifest.json\n')
        self.assertIn('schema', self.check(sdk, '--inventory-only', ok=False).stderr)

    def test_manifest_identity_edit_and_missing_checksum_refused(self):
        self.package()
        sdk = self.out / 'absd-sdk-test-1'
        path = sdk / 'metadata/manifest.json'
        original = path.read_text()
        record = json.loads(original)
        record['compatibility']['kernel_commit'] = 'c' * 40
        path.write_text(json.dumps(record))
        self.assertIn('checksum', self.check(sdk, '--inventory-only', ok=False).stderr)
        path.write_text(original)
        checksum = sdk / 'metadata/manifest.sha256'
        self.assertTrue(checksum.is_file())
        checksum.unlink()
        self.assertIn('checksum', self.check(sdk, '--inventory-only', ok=False).stderr)

    def test_nested_receipt_named_header_is_copied(self):
        (self.kit / 'include/BUILT-FROM').write_text('header content\n')
        (self.pico / 'include/BUILT-FROM').write_text('header content\n')
        self.package()
        path = self.out / 'absd-sdk-test-1/c/include/BUILT-FROM'
        self.assertTrue(path.is_file(), 'include/BUILT-FROM is an installed header and must be copied')
        self.assertEqual(path.read_text(), 'header content\n')

    def test_host_tools_and_compiler_override(self):
        self.package()
        sdk = self.out / 'absd-sdk-test-1'
        env = os.environ.copy()
        env.pop('ABSD_CLANG', None)
        self.check(sdk, env=env)
        env['ABSD_CLANG'] = '/missing-sdk-clang'
        self.assertIn('/missing-sdk-clang', self.check(sdk, env=env, ok=False).stderr)

    def test_missing_host_tools_actionable(self):
        self.package()
        env = os.environ.copy()
        env['PATH'] = str(self.base / 'empty-path')
        result = subprocess.run([sys.executable, str(self.out / 'absd-sdk-test-1/metadata/sdk_check.py')],
                                capture_output=True, text=True, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('clang-18', result.stderr)

    def make_cxx(self):
        cxx = self.base / 'cxx'
        include = cxx / 'include/c++/v1'
        include.mkdir(parents=True)
        (cxx / 'lib').mkdir()
        (cxx / 'bin').mkdir()
        for name in ('__config_site', 'vector', 'cxxabi.h'):
            (include / name).write_text('// fixture header\n')
        for name in ('libc++.a', 'libc++abi.a'):
            (cxx / 'lib' / name).write_bytes(name.encode())
        shutil.copyfile(ROOT / 'cxx/bin/absd-c++', cxx / 'bin/absd-c++')
        (cxx / 'bin/absd-c++').chmod(0o755)
        headers = ''.join(f'{sha(p)}  ./{p.name}\n' for p in sorted(include.iterdir()))
        rows = [f'commit {self.commit}', 'dirty no', f'kit {self.kit}',
                f'kit-commit {self.commit}', f'cflags -isystem {self.kit}/include',
                f'cxxflags -isystem {self.source}/private',
                'headers ' + hashlib.sha256(headers.encode()).hexdigest()]
        rows += [f'kit-lib/{n} {sha(self.kit / "lib" / n)}' for n in ('libc.a', 'libabs.a', 'crt0.o')]
        rows += [f'lib/{n} {sha(cxx / "lib" / n)} bytes={(cxx / "lib" / n).stat().st_size}' for n in ('libc++.a', 'libc++abi.a')]
        (cxx / 'BUILT-FROM').write_text('\n'.join(rows) + '\n')
        (cxx / 'private.log').write_text('not shipped')
        return cxx

    def test_cxx_relocated_unsupported_option_and_libc_mismatch(self):
        cxx = self.make_cxx()
        self.package('--cxx', str(cxx))
        sdk = self.out / 'absd-sdk-test-1'
        self.check(sdk, '--inventory-only')
        self.assertFalse((sdk / 'cxx/private.log').exists())
        self.assertNotIn(str(self.base), (sdk / 'cxx/BUILT-FROM').read_text())
        self.kit.rename(self.base / 'retired-kit')
        cxx.rename(self.base / 'retired-cxx')
        env = os.environ.copy()
        env.update(ABSD_CKIT='/does-not-exist', ABSD_CXX_BUILD='/does-not-exist')
        # Real driver and clang version probe; no compilation of fixture archives.
        result = subprocess.run([str(sdk / 'bin/absd-c++'), '-pthread', 'example.cpp'],
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unsupported option -pthread', result.stderr)
        (sdk / 'c/lib/libc.a').write_bytes(b'changed')
        result = subprocess.run([str(sdk / 'bin/absd-c++'), '-pthread', 'example.cpp'],
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('runtime was built against', result.stderr)

    def test_cxx_receipt_rejects_symlink_fifo_and_directory_promptly(self):
        cxx = self.make_cxx()
        path = cxx / 'BUILT-FROM'
        external = self.base / 'external-cxx-receipt'
        path.rename(external)
        for kind in ('symlink', 'fifo', 'directory'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    path.symlink_to(external)
                elif kind == 'fifo':
                    os.mkfifo(path)
                else:
                    path.mkdir()
                try:
                    try:
                        result = self.package('--cxx', str(cxx), ok=False,
                            out=self.base / ('bad-cxx-' + kind), timeout=5)
                    except subprocess.TimeoutExpired:
                        # subprocess.run kills and waits for its exact child.
                        self.fail('C++ receipt FIFO blocked instead of prompt regular-file refusal')
                    self.assertIn('regular file', result.stderr)
                    self.assertFalse((self.base / ('bad-cxx-' + kind)).exists())
                finally:
                    path.rmdir() if kind == 'directory' else path.unlink()

    def test_original_picolibc_archives_reject_symlinks_and_fifos_promptly(self):
        for name in ('libc.a', 'libm.a'):
            path = self.pico / 'lib' / name
            external = self.base / ('external-' + name)
            path.rename(external)
            try:
                for kind in ('symlink', 'fifo'):
                    with self.subTest(name=name, kind=kind):
                        path.symlink_to(external) if kind == 'symlink' else os.mkfifo(path)
                        out = self.base / ('bad-' + name + '-' + kind)
                        try:
                            try:
                                result = self.package(ok=False, out=out, timeout=5)
                            except subprocess.TimeoutExpired:
                                # subprocess.run kills and waits for its exact child.
                                self.fail('Picolibc archive FIFO blocked instead of prompt regular-file refusal')
                            self.assertIn('regular file', result.stderr)
                            self.assertFalse(out.exists())
                        finally:
                            path.unlink()
            finally:
                external.rename(path)

    def test_input_roots_and_picolibc_lib_must_be_real_directories(self):
        cxx = self.make_cxx()
        for root, flag in ((cxx, '--cxx'), (self.pico, '--picolibc-install'),
                           (self.source, '--source-root')):
            with self.subTest(root=root.name):
                alias = self.base / (root.name + '-alias')
                alias.symlink_to(root, target_is_directory=True)
                self.assertIn('directory', self.package(flag, str(alias), ok=False,
                    out=self.base / (root.name + '-out')).stderr)
        lib = self.pico / 'lib'
        external = self.base / 'external-pico-lib'
        lib.rename(external)
        lib.symlink_to(external, target_is_directory=True)
        self.assertIn('directory', self.package(ok=False, out=self.base / 'lib-out').stderr)

    def test_cxx_driver_bound_to_actual_source(self):
        cxx = self.make_cxx()
        (cxx / 'bin/absd-c++').write_text('#!/bin/sh\nexit 0\n')
        self.assertIn('source', self.package('--cxx', str(cxx), ok=False).stderr)

    def test_cxx_archive_and_header_receipts_refused(self):
        cxx = self.make_cxx()
        for name in ('lib/libc++.a', 'lib/libc++abi.a', 'include/c++/v1/vector'):
            with self.subTest(name=name):
                path = cxx / name
                original = path.read_bytes()
                path.write_bytes(b'changed')
                self.assertIn('digest', self.package('--cxx', str(cxx), ok=False).stderr)
                path.write_bytes(original)

    def test_malformed_duplicate_empty_stamp_field_refused(self):
        (self.kit / 'BUILT-FROM').write_text(self.stamp + 'commit\n')
        self.assertIn('exactly one', self.package(ok=False).stderr)

    def test_whitespace_paths_refused(self):
        self.assertIn('whitespace', self.package('--version', 'bad version', ok=False).stderr)


if __name__ == '__main__':
    unittest.main()
