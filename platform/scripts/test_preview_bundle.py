#!/usr/bin/env python3
"""Preview composition host controls; no real media tools or guest runs."""
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import absd_try
from served_ram import ram_bytes
from test_absd_try import ed25519_line
from test_operator_boot_binding import fixture, elf
from test_p2_boot_binding import iso, SERVED

spec = importlib.util.find_spec('preview_bundle')
preview = importlib.util.module_from_spec(spec) if spec else None
if preview is not None:
    spec.loader.exec_module(preview)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fake_disk(path, files):
    body = json.dumps({k: v.decode('latin1') for k, v in files.items()}).encode()
    path.write_bytes(body + b'\n' + bytes(8191 - len(body)))


def disk_files(path):
    return {k: v.encode('latin1') for k, v in json.loads(Path(path).read_bytes().split(b'\n', 1)[0]).items()}


class PreviewComposition(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(preview, 'release preview composition is not implemented')
        tmp = tempfile.TemporaryDirectory(prefix='preview-host-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.platform, self.kernel = self.root / 'platform', self.root / 'kernel'
        for root in [self.platform, self.kernel]:
            root.mkdir()
            (root / '.gitignore').write_text('ports/\n*.elf\nbuild/\n')
        (self.platform / 'userland').mkdir()
        cport = b'fixture C output'
        (self.platform / 'userland/PORTS.tsv').write_text(f'printf\tu\tl\tprintf\t{sha(cport)}\t{sha(cport)}\t{len(cport)}\n')
        (self.platform / 'scripts').mkdir()
        for name in ['absd_try.py', 'absd_fs.py', 'absd_image.py', 'served_ram.py']:
            shutil.copyfile(HERE / name, self.platform / 'scripts' / name)
        commits = []
        for root in [self.platform, self.kernel]:
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
            subprocess.run(['git', '-c', 'gc.auto=0', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                            '-C', str(root), 'commit', '-qm', 'fixture'], check=True)
            commits.append(subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip())
        ports = self.platform / 'ports'
        ports.mkdir()
        (ports / 'printf').write_bytes(cport)
        (ports / '.c-ports.built-from.json').write_text(json.dumps(dict(schema_version=2,
            platform_commit=commits[0], kit_commit=commits[0], platform_dirty='no', kit_dirty='no',
            ports={'printf': sha(cport)})))
        for name, payload in [('sshd.elf', b'external-workload'), ('absd-fsd.elf', b'file-server'),
                              ('absd-logd.elf', b'logd'), ('fixture-import.elf', b'importer'),
                              ('absd-enroll.elf', b'enroll')]:
            (self.platform / name).write_bytes(elf(payload))
        self.notices = self.root / 'notices.txt'
        self.notices.write_text('Supplied test notices.\n')
        self.key = self.root / 'operator.pub'
        self.key.write_text('public input only\n')
        self.args = SimpleNamespace(platform=str(self.platform), kernel=str(self.kernel),
            platform_commit=commits[0], kernel_commit=commits[1], id='preview-test', tag='preview-test',
            repository='https://example.invalid/project', authorized_keys=str(self.key),
            notices=str(self.notices), boot_sources=str(self.root / 'boot-sources'), work=str(self.root / 'work'), out=str(self.root / 'assets'),
            profile='vm-operator', qemu='qemu-system-x86_64 -accel tcg', limitation=[], quickstart=None)
        self.calls = []
        self.local_login = False
        self.fail_validation = False
        self.reads = 0
        self.inject_second_read = False

    def tool(self, command, log):
        self.calls.append(command)
        script = next((Path(x).name for x in command if str(x).endswith('.py')), '')
        if script == 'provenance.py':
            self.assertEqual(command[-3:], ['check', '--peer', str(self.kernel)])
            return
        if script == 'media.py':
            if 'operator-image' in command:
                self.assertIn('--no-local-login', command)
                out = Path(command[command.index('--out') + 1])
                out.mkdir()
                files = {'/absd/selected': b'preview-test\n', '/ssh/authorized_keys': b'build-key\n'}
                if self.local_login:
                    files['/ssh/local-login'] = b''
                fake_disk(out / 'absd-operator.img', files)
                kernel, _ = fixture()
                tree = self.kernel / 'build/durable/iso-0/boot'
                (tree / 'grub').mkdir(parents=True, exist_ok=True)
                (tree / 'absd-kernel').write_bytes(kernel)
                (tree / 'grub/grub.cfg').write_bytes(SERVED)
                (out / 'absd-operator.iso').write_bytes(iso(kernel, SERVED))
                (out / 'MANIFEST').write_text('fixture media manifest\n')
                return
            if 'operator-validate' in command:
                if self.fail_validation:
                    raise subprocess.CalledProcessError(2, command)
                return
        if script == 'enroll-matrix.py':
            out = Path(command[command.index('--work') + 1])
            out.mkdir()
            data = b'fake enrollment ISO'
            (out / 'enroll.iso').write_bytes(data)
            (out / 'result.json').write_text(json.dumps({'isos': {'enroll': sha(data)},
                'elfs': {k: sha((self.platform / f).read_bytes()) for k, f in
                         [('enroll', 'absd-enroll.elf'), ('importer', 'fixture-import.elf')]}}))
            return
        self.fail(f'unexpected external tool: {command}')

    def blank(self, kernel, image, plan, work, **kwargs):
        self.assertEqual(plan, [(4, [('/ssh/authorized_keys', b'')])])
        files = disk_files(image)
        files['/ssh/authorized_keys'] = b''
        fake_disk(Path(image), files)

    def read(self, path):
        self.reads += 1
        files = disk_files(path)
        if self.inject_second_read and self.reads == 2:
            files['/ssh/local-login'] = b'late verifier'
        return files

    def boot_sources(self, sources, iso, output, profile):
        self.assertEqual(sources, self.args.boot_sources)
        self.assertEqual(Path(iso), Path(self.args.work) / 'operator/absd-operator.iso')
        self.assertTrue(Path(iso).is_file())
        self.assertEqual(profile, 'vm-operator')
        Path(output).write_bytes(b'checked corresponding source')
        return {'source_files': 13}

    def compose(self):
        with patch.object(preview.boot_source, 'verify_sources'), \
             patch.object(preview.boot_source, 'build', side_effect=self.boot_sources), \
             patch.object(preview, 'run_tool', side_effect=self.tool), \
             patch.object(preview.oi, 'import_boots', side_effect=self.blank), \
             patch.object(preview.absd_try, 'read_tree', side_effect=self.read):
            return preview.compose(self.args)

    def test_fake_tools_produce_consistent_consumer_verified_assets(self):
        self.compose()
        assets = Path(self.args.out)
        doc = absd_try.verify_assets(assets)
        self.assertEqual(doc['release']['platform_commit'], self.args.platform_commit)
        self.assertEqual(doc['release']['kernel_commit'], self.args.kernel_commit)
        self.assertEqual(doc['release']['id'], 'preview-test')
        disk = doc['assets']['disk']
        raw = lzma.decompress((assets / disk['name']).read_bytes())
        self.assertEqual(disk['raw_bytes'], 8192)
        self.assertEqual(disk['raw_sha256'], sha(raw))
        sums = absd_try.parse_sums((assets / 'SHA256SUMS').read_text())
        self.assertEqual(set(sums), {p.name for p in assets.iterdir()} - {'SHA256SUMS'})
        self.assertNotIn('MANIFEST.toml', [a['name'] for a in doc['assets'].values()])
        self.assertIn('QUICKSTART-INPUT.json', sums)
        self.assertGreaterEqual(self.reads, 2)
        source = doc['assets']['boot_source']
        self.assertEqual(source['name'], 'boot-corresponding-source.tar')
        self.assertEqual(source['sha256'], sha(b'checked corresponding source'))
        self.assertIn(source['name'], sums)
        record = json.loads((assets / 'QUICKSTART-INPUT.json').read_text())['record']
        self.assertIn(source['name'], [a['name'] for a in record['binary_preview']['assets']])

    def test_missing_boot_sources_refused_before_media_work(self):
        with patch.object(preview, 'run_tool') as tool:
            with self.assertRaises(FileNotFoundError):
                preview.compose(self.args)
            tool.assert_not_called()
        self.assertFalse(Path(self.args.work).exists())
        self.assertFalse(Path(self.args.out).exists())

    def test_boot_source_iso_refusal_prevents_sealing(self):
        with patch.object(preview.boot_source, 'verify_sources'), \
             patch.object(preview.boot_source, 'build', side_effect=ValueError('ISO GRUB mismatch')), \
             patch.object(preview, 'run_tool', side_effect=self.tool):
            with self.assertRaisesRegex(ValueError, 'ISO GRUB mismatch'):
                preview.compose(self.args)
        self.assertFalse(Path(self.args.out).exists())
        self.assertFalse(any('enroll-matrix.py' in str(item) for call in self.calls for item in call))

    def test_local_login_verifier_even_empty_refuses_shipment(self):
        self.local_login = True
        with self.assertRaisesRegex(Exception, 'local-login'):
            self.compose()
        self.assertFalse((Path(self.args.out) / 'SHA256SUMS').exists())

    def test_quickstart_inputs_do_not_change_when_generated_guide_is_added(self):
        self.compose()
        first = json.loads((Path(self.args.out) / 'QUICKSTART-INPUT.json').read_text())['record']
        self.assertIn('QUICKSTART.md', [a['name'] for a in first['binary_preview']['assets']])
        guide = self.root / 'generated-guide.md'
        guide.write_text('Guide generated by the site from the proposed final asset list.\n')
        self.args.quickstart = str(guide)
        self.args.work = str(self.root / 'work-with-guide')
        self.args.out = str(self.root / 'assets-with-guide')
        self.compose()
        second = json.loads((Path(self.args.out) / 'QUICKSTART-INPUT.json').read_text())['record']
        self.assertEqual(first, second)

    def test_cpu_default_is_shared_by_producer_and_downloaded_helper(self):
        with patch.object(absd_try, 'CPU_TCG', 'shared-test-cpu', create=True):
            self.compose()
            doc = absd_try.load_manifest(Path(self.args.out) / 'MANIFEST.toml')
            self.assertEqual(doc['qemu']['cpu_tcg'], 'shared-test-cpu')
            self.assertEqual(absd_try.accel_args('tcg', {})[0],
                             ['-accel', 'tcg', '-cpu', 'shared-test-cpu'])

    def test_provenance_binds_kernel_peer_and_records_verified_environment(self):
        environment = {'ABSD_CARGO_REGISTRY': '/verified/source-registry',
                       'ABSD_CRATE_ARCHIVES': '/verified/crate-archives'}
        with patch.dict(os.environ, environment):
            self.compose()
        command = next(c for c in self.calls if any(str(x).endswith('/provenance.py') for x in c))
        self.assertIn('--peer', command)
        self.assertEqual(command[command.index('--peer') + 1], str(self.kernel))
        data = json.loads((Path(self.args.out) / 'BUILD-INPUTS.json').read_text())
        self.assertEqual(data['provenance_environment'], environment)

    def test_finalize_attaches_guide_without_touching_media_or_running_tools(self):
        self.compose()
        assets = Path(self.args.out)
        before = {n: sha((assets / n).read_bytes()) for n in ['operator.iso', 'enroll.iso', 'disk.img.xz']}
        guide = self.root / 'site-guide.md'
        guide.write_text('The site generated this guide.\n')
        self.assertTrue(hasattr(preview, 'finalize'), 'preview finalization is not implemented')
        with patch.object(preview, 'run_tool', side_effect=AssertionError('finalize starts no tools')):
            preview.finalize(assets, guide)
        doc = absd_try.verify_assets(assets)
        self.assertEqual((assets / 'QUICKSTART.md').read_bytes(), guide.read_bytes())
        self.assertIn('QUICKSTART.md', [a['name'] for a in doc['assets'].values()])
        self.assertEqual(before, {n: sha((assets / n).read_bytes()) for n in before})
        self.assertEqual(set(absd_try.parse_sums((assets / 'SHA256SUMS').read_text())),
                         {p.name for p in assets.iterdir()} - {'SHA256SUMS'})

    def test_finalize_refuses_invalid_bundle_before_adding_guide(self):
        self.compose()
        assets = Path(self.args.out)
        (assets / 'operator.iso').write_bytes(b'changed media')
        guide = self.root / 'site-guide.md'
        guide.write_text('guide')
        self.assertTrue(hasattr(preview, 'finalize'), 'preview finalization is not implemented')
        with self.assertRaisesRegex(Exception, 'asset_digest'):
            preview.finalize(assets, guide)
        self.assertFalse((assets / 'QUICKSTART.md').exists())

    def test_finalize_refuses_existing_guide_without_overwriting(self):
        self.compose()
        assets = Path(self.args.out)
        (assets / 'QUICKSTART.md').write_text('existing owner guide')
        guide = self.root / 'site-guide.md'
        guide.write_text('replacement')
        self.assertTrue(hasattr(preview, 'finalize'), 'preview finalization is not implemented')
        before = (assets / 'MANIFEST.toml').read_bytes(), (assets / 'SHA256SUMS').read_bytes()
        with self.assertRaisesRegex(Exception, 'already|exists|guide'):
            preview.finalize(assets, guide)
        self.assertEqual((assets / 'QUICKSTART.md').read_text(), 'existing owner guide')
        self.assertEqual(before, ((assets / 'MANIFEST.toml').read_bytes(), (assets / 'SHA256SUMS').read_bytes()))

    def test_finalize_cli_uses_the_same_verified_bundle_path(self):
        self.compose()
        guide = self.root / 'site-guide.md'
        guide.write_text('Generated guide for CLI finalization.\n')
        result = subprocess.run([sys.executable, '-B', '-I', '-X', f"pycache_prefix={sys.pycache_prefix or ''}", str(HERE / 'release.py'),
            'preview-finalize', '--out', self.args.out, '--quickstart', str(guide)],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((Path(self.args.out) / 'QUICKSTART.md').read_bytes(), guide.read_bytes())
        absd_try.verify_assets(self.args.out)

    def test_all_qemu_manifest_fields_match_the_actual_boot_argv(self):
        self.compose()
        assets = Path(self.args.out)
        doc = absd_try.load_manifest(assets / 'MANIFEST.toml')
        profile = doc['qemu']
        machine = self.root / 'argv-machine'
        machine.mkdir()
        shutil.copyfile(assets / 'MANIFEST.toml', machine / 'MANIFEST.toml')
        (machine / 'disk.img').write_bytes(b'host fixture only')
        files = {'/ssh/authorized_keys': ed25519_line(b'argv-parity')}
        commands = []
        class CapturedLaunch(Exception):
            pass
        def capture(command, **kwargs):
            commands.append(command)
            raise CapturedLaunch
        with patch.object(absd_try, 'read_tree', return_value=files), \
             patch.object(absd_try, 'free_port'), \
             patch.object(absd_try, 'qemu_binary', return_value='/fixture/qemu'), \
             patch.object(absd_try.subprocess, 'Popen', side_effect=capture), \
             patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(CapturedLaunch):
                absd_try.boot(machine, accel='tcg')
        self.assertEqual(len(commands), 1)
        command = commands[0]
        self.assertEqual(profile['cpu_tcg'], command[command.index('-cpu') + 1])
        self.assertEqual(profile['memory_mib'], ram_bytes(command[command.index('-m') + 1]) // (1024 * 1024))
        cpus = int(command[command.index('-smp') + 1]) if '-smp' in command else 1
        self.assertEqual(profile['smp'], cpus)
        devices = [command[i + 1] for i, value in enumerate(command[:-1]) if value == '-device']
        self.assertEqual([d.split(',')[0] for d in devices if ',netdev=' in d], [profile['nic']])
        drive = command[command.index('-drive') + 1].split(',')
        self.assertIn('if=' + profile['disk'], drive)
        # The default PC firmware is this profile's SeaBIOS. Explicit firmware
        # or machine selection must make this parity control fail for review.
        self.assertEqual(profile['firmware'], 'SeaBIOS')
        self.assertFalse({'-bios', '-pflash', '-machine', '-M'} & set(command))

    def test_second_blank_check_rejects_a_verifier_after_compression(self):
        self.inject_second_read = True
        with self.assertRaisesRegex(Exception, 'local-login'):
            self.compose()
        self.assertFalse((Path(self.args.out) / 'SHA256SUMS').exists())

    def test_missing_c_port_seal_refuses_before_external_tools(self):
        (self.platform / 'ports/.c-ports.built-from.json').unlink()
        with self.assertRaisesRegex(Exception, 'missing|C.port|seal'):
            self.compose()
        self.assertEqual(self.calls, [])
        self.assertFalse(Path(self.args.work).exists())

    def test_wrong_logger_input_cannot_pass_the_actual_catalog_reader(self):
        (self.platform / 'absd-logd.elf').write_bytes(elf(b'wrong logger'))
        with self.assertRaisesRegex(Exception, 'logd|logger'):
            self.compose()
        self.assertFalse((Path(self.args.out) / 'SHA256SUMS').exists())

    def test_child_validation_failure_never_seals_success(self):
        self.fail_validation = True
        with self.assertRaises(Exception):
            self.compose()
        self.assertFalse((Path(self.args.out) / 'SHA256SUMS').exists())

    def test_existing_output_and_wrong_pin_refuse_before_tools(self):
        Path(self.args.out).mkdir()
        (Path(self.args.out) / 'keep').write_text('owner data')
        with self.assertRaises(Exception):
            self.compose()
        self.assertEqual((Path(self.args.out) / 'keep').read_text(), 'owner data')
        self.assertEqual(self.calls, [])

    def test_dangling_output_link_is_not_followed(self):
        Path(self.args.out).symlink_to(self.root / 'elsewhere')
        with self.assertRaises(Exception):
            self.compose()
        self.assertFalse((self.root / 'elsewhere').exists())
        self.assertEqual(self.calls, [])

    def test_release_cli_reaches_the_same_source_pin_refusal(self):
        command = [sys.executable, '-B', '-I', '-X', f"pycache_prefix={sys.pycache_prefix or ''}", str(HERE / 'release.py'), 'preview']
        for name in ['platform', 'kernel', 'platform_commit', 'kernel_commit', 'id', 'tag',
                     'repository', 'authorized_keys', 'notices', 'boot_sources', 'work', 'out']:
            value = '0' * 40 if name == 'platform_commit' else getattr(self.args, name)
            command += ['--' + name.replace('_', '-'), value]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release: refused:', result.stderr)
        self.assertIn('platform', result.stderr)
        self.assertFalse(Path(self.args.work).exists())
        self.args.out = str(self.root / 'fresh')
        self.args.platform_commit = '0' * 40
        with self.assertRaises(Exception):
            self.compose()
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
