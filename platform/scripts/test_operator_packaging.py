"""Real enrollment and composition bytes; kernel/import execution is replaced at its boundary."""
import contextlib
import hashlib
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import operator_image as oi

class Packaging(unittest.TestCase):
    def build_fixture(self, root, out, **kwargs):
        iso = root / 'source.iso'; iso.write_bytes(b'kernel ISO')
        imports = []
        with mock.patch.object(oi, 'IMAGE_BYTES', 4096), \
             mock.patch.object(oi, 'check_platform_release'), \
             mock.patch.object(oi, 'system_files', return_value=[('/bin/absd-sh', b'shell')]), \
             mock.patch.object(oi, 'etc_files', return_value=[]), \
             mock.patch.object(oi, 'authorized', return_value=b'ssh-ed25519 fixture\n'), \
             mock.patch.object(oi, 'import_boots', side_effect=lambda k,i,plan,*a,**kw: imports.extend(plan)), \
             mock.patch.object(oi, 'verify'), \
             mock.patch.object(oi, 'check_successor_headroom', return_value={'peak_extra_blocks':0,'free_blocks':1}), \
             mock.patch.object(oi, 'kernel_iso', return_value=iso):
            files = oi.build(root, out, root/'keys', root=root, release_id='test', log=lambda _:None, **kwargs)
        return files, imports

    def test_default_enrollment_is_private_external_and_only_verifier_is_imported(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);out=root/'image';capture=io.StringIO()
            with contextlib.redirect_stdout(capture): files, imports=self.build_fixture(root,out)
            imported=dict(item for _,entries in imports for item in entries)
            self.assertIn('/ssh/local-login', imported)
            token=root/'image.local-console-token';verifier=Path(str(token)+'.verifier')
            raw=token.read_bytes().strip()
            self.assertEqual(stat.S_IMODE(token.stat().st_mode),0o600)
            self.assertEqual(stat.S_IMODE(verifier.stat().st_mode),0o600)
            self.assertEqual(imported['/ssh/local-login'],b'ABSD-LOCAL-1 operator '+hashlib.sha256(raw).hexdigest().encode()+b'\n')
            self.assertNotIn(raw,capture.getvalue().encode())
            self.assertNotIn(raw,b'\n'.join(data for _,data in files))
            self.assertNotIn(raw,(out/'MANIFEST').read_bytes())
            self.assertFalse(any('token' in p.name for p in out.rglob('*')))

    def test_preview_producer_omits_local_enrollment_and_passes_blank_check(self):
        import absd_try
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files, imports = self.build_fixture(root, root / 'preview', no_local_login=True)
            tree = dict(item for _, entries in imports for item in entries)
            self.assertNotIn('/ssh/local-login', tree)
            self.assertNotIn('/ssh/local-login', dict(files))
            self.assertFalse((root / 'preview.local-console-token').exists())
            self.assertFalse((root / 'preview.local-console-token.verifier').exists())
            # The release producer clears its temporary SSH enrollment before packaging.
            tree['/ssh/authorized_keys'] = b''
            absd_try.check_blank(tree, 'test')
            tree['/ssh/local-login'] = b'ABSD-LOCAL-1 operator ' + b'0' * 64 + b'\n'
            with self.assertRaisesRegex(absd_try.Refused, 'disk_not_blank.*local-login'):
                absd_try.check_blank(tree, 'test')

    def test_disabled_local_login_refuses_conflicting_enrollment_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for option in ('local_token_file', 'local_login_verifier'):
                with self.subTest(option=option):
                    with self.assertRaisesRegex(oi.Failed, 'no-local-login'):
                        self.build_fixture(root, root / 'preview', no_local_login=True,
                                           **{option: root / 'unused'})
                    self.assertFalse((root / 'preview').exists())

    def test_final_served_console_and_importer_console_flags_override_environment(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ,{'ABSD_LOCAL_CONSOLE':'1'}):
            root = Path(directory)
            (root / 'Makefile').write_text(
                "durable-iso:\n"
                "\t@printf '%s\\n' '$(ABSD_LOCAL_CONSOLE)' > console-flag\n")
            oi.kernel_iso(directory,2,'import',work=directory)
            self.assertEqual((root / 'console-flag').read_text(), '0\n')
            oi.kernel_iso(directory,0,'sshd',options='net fsd served',server='fsd',work=directory)
            self.assertEqual((root / 'console-flag').read_text(), '1\n')

    def test_shell_alias_is_declared_and_has_canonical_manual(self):
        self.assertIn('sh',oi.command_names())
        self.assertEqual((oi.ROOT/'man/sh.1').is_file(),True)

    def test_token_path_inside_artifacts_and_existing_enrollment_refuse_before_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);out=root/'artifact';out.mkdir()
            with self.assertRaisesRegex(oi.Failed,'outside'):
                oi.local_login_files(out, token_file=out/'token')
            self.assertEqual(list(out.iterdir()),[])
            existing=root/'existing';existing.write_bytes(b'owned prior token')
            with self.assertRaisesRegex(oi.Failed,'already exists'):
                oi.local_login_files(out, token_file=existing)
            self.assertEqual(existing.read_bytes(),b'owned prior token')
            self.assertFalse(Path(str(existing)+'.verifier').exists())

    def test_existing_verifier_reuses_enrollment_and_raw_token_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);original=root/'first'
            files=oi.local_login_files(original)
            token=root/'first.local-console-token';before=token.read_bytes()
            verifier=Path(str(token)+'.verifier')
            self.assertEqual(oi.local_login_files(root/'rebuilt',verifier=verifier),files)
            self.assertEqual(token.read_bytes(),before)
            self.assertFalse((root/'rebuilt.local-console-token').exists())
            with self.assertRaisesRegex(oi.Failed,'SHA-256 descriptor'):
                oi.local_login_files(root/'bad',verifier=token)
            with self.assertRaisesRegex(oi.Failed,'choose'):
                oi.local_login_files(root/'bad',token_file=root/'other',verifier=verifier)

    def test_release_site_defaults_and_manifest_include_only_descriptor(self):
        import release as release_tool
        import release_manifest
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);out=root/'release';(out/'site-defaults/etc').mkdir(parents=True)
            descriptor=dict(oi.local_login_files(out))['/ssh/local-login']
            (out/'site-defaults/local-login').write_bytes(descriptor)
            release=object.__new__(release_tool.Release);release.path=out
            self.assertEqual(release.site_defaults(),[('/ssh/local-login',descriptor)])
            release.artifact_digests=lambda:{'site-defaults/local-login':hashlib.sha256(descriptor).hexdigest()}
            self.assertEqual(release.verified_site_defaults(),[('/ssh/local-login',descriptor)])
            token=(root/'release.local-console-token').read_bytes().strip()
            for file in release_manifest.release_files(out):
                self.assertNotIn(token,(out/file).read_bytes())
            (out/'site-defaults/local-login').write_bytes(b'ABSD-LOCAL-1 operator '+b'0'*64+b'\n')
            with self.assertRaisesRegex(release_tool.Failed,'digest'):
                release.verified_site_defaults()

    def test_composition_refuses_a_different_shell_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'commands').mkdir()
            (root/'commands/absd-sh').write_bytes(b'canonical shell')
            (root/'commands/sh').write_bytes(b'different shell')
            with mock.patch.object(oi,'NATIVE',[]),mock.patch.object(oi,'PORTS',[]),mock.patch.object(oi,'RUST_PORTS',[]),mock.patch.object(oi,'c_ports_installed',return_value={}):
                with self.assertRaisesRegex(oi.Failed,'byte-identical'):
                    oi.system_files(root)

if __name__=='__main__':unittest.main()
