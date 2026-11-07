#!/usr/bin/env python3
import importlib.util
import pathlib
import ctypes
import hashlib
import json
import os
import signal
import subprocess
import time
import struct
import sys
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import install_disk as layout

class PayloadTests(unittest.TestCase):
    def module(self):
        path = pathlib.Path(__file__).with_name('native_installer.py')
        self.assertTrue(path.exists(), 'native installer builder is missing')
        spec = importlib.util.spec_from_file_location('native_installer', path)
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        return mod

    def test_sparse_payload_is_exact_and_reproducible(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as work:
            image = pathlib.Path(work)/'disk.img'
            with image.open('wb') as f: f.truncate(3 << 30)
            with image.open('r+b') as f:
                for at in (0, 33*512, 2048*512, (3<<30)-512):
                    f.seek(at); f.write(b'x'*512)
            first = mod.pack(image, 'test', 'QEMU HARDDISK')
            self.assertEqual(first, mod.pack(image, 'test', 'QEMU HARDDISK'))
            self.assertEqual(first[:8], b'ABSDINS1')
            self.assertLess(len(first), 20000)
            records = list(mod.records(first))
            self.assertGreater(len(records), 2)
            with image.open('rb') as f:
                for lba, data in records:
                    f.seek(lba*512); self.assertEqual(f.read(len(data)), data)
                    self.assertTrue(lba+len(data)//512 <= layout.ABSD_FIRST or lba >= (3<<30)//512-33)
                    self.assertFalse(lba < 34 < lba+len(data)//512)

    def test_shared_v1_golden_vector(self):
        mod = self.module()
        payload = bytes.fromhex((pathlib.Path(__file__).resolve().parent.parent/'tests/native-installer-v1.hex').read_text())
        self.assertEqual(list(mod.records(payload)), [(0, bytes([0x5a])*512), (layout.MIN_SECTORS-1, bytes([0x5a])*512)])

    def test_default_media_shows_source_identity_and_has_no_consent(self):
        mod = self.module()
        plan = {'kernel_source':'a'*40, 'platform_source':'b'*40, 'payload_sha256':'c'*64}
        text = mod.config('test', 123, plan=plan)
        self.assertNotIn('install-consent=', text)
        for value in plan.values(): self.assertIn(value, text)
        self.assertIn('ahci-disk=test', text)

    def test_builder_refuses_invalid_identity_sizes_and_nonregular_paths(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as work:
            image = pathlib.Path(work)/'disk.img'; image.write_bytes(b'')
            for serial in ('', 'a'*21, 'with space', 'a;boot'):
                with self.assertRaises(layout.Refused): mod.pack(image, serial, 'QEMU HARDDISK')
            with self.assertRaises(layout.Refused): mod.pack(image, 'test', 'QEMU HARDDISK')
            with image.open('wb') as f: f.truncate(3 << 30)
            link = pathlib.Path(work)/'link'; link.symlink_to(image)
            with self.assertRaises(layout.Refused): mod.pack(link, 'test', 'QEMU HARDDISK')
            with self.assertRaises(layout.Refused): mod.pack(image, 'test', 'other')


    def test_builder_requires_clean_source_trees(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as work:
            repo = pathlib.Path(work)
            subprocess.run(['git','init','-q',str(repo)], check=True)
            (repo/'source').write_text('original')
            subprocess.run(['git','-C',str(repo),'add','source'], check=True)
            subprocess.run(['git','-C',str(repo),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture'], check=True)
            mod.require_clean(repo)
            (repo/'source').write_text('modified')
            with self.assertRaises(layout.Refused): mod.require_clean(repo)
            subprocess.run(['git','-C',str(repo),'add','source'], check=True)
            with self.assertRaises(layout.Refused): mod.require_clean(repo)
            subprocess.run(['git','-C',str(repo),'reset','--hard','-q','HEAD'], check=True)
            (repo/'untracked').write_text('new')
            with self.assertRaises(layout.Refused): mod.require_clean(repo)

class ApparatusTests(unittest.TestCase):
    def test_qemu_command_uses_shared_ram_policy(self):
        mod = self.module()
        for requested, expected in ((None, '512'), ('256M', '512'), ('1G', '1G')):
            env = {} if requested is None else {'ABSD_GUEST_RAM': requested}
            with self.subTest(requested=requested), mock.patch.dict(os.environ, env, clear=True):
                argv = mod.command('qemu', 'code', 'vars', 'disk', 'test', log='serial', trace='trace')
                self.assertEqual(argv.count('-m'), 1)
                self.assertEqual(argv[argv.index('-m') + 1], expected)
        for invalid in ('128M', 'invalid'):
            with self.subTest(invalid=invalid), mock.patch.dict(os.environ, {'ABSD_GUEST_RAM': invalid}):
                with self.assertRaises(ValueError):
                    mod.command('qemu', 'code', 'vars', 'disk', 'test', log='serial', trace='trace')

    def test_cli_invalid_ram_uses_named_stop_without_qemu(self):
        import contextlib, io
        mod = self.module()
        for invalid in ('128M', 'invalid'):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                artifact = root / 'artifact'
                expected = self.artifact_fixture(artifact)
                firmware = root / 'firmware'; firmware.write_bytes(b'fixture')
                argv = ['e2e', '--artifact', str(artifact), '--work', str(root / 'work'),
                        '--expected-plan-sha256', expected, '--ovmf-code', str(firmware),
                        '--ovmf-vars', str(firmware), '--qemu', '/never-executed']
                stderr = io.StringIO()
                with mock.patch.dict(os.environ, {'ABSD_GUEST_RAM': invalid}), \
                     mock.patch.object(sys, 'argv', argv), \
                     mock.patch.object(mod.builder, 'iso'), \
                     mock.patch.object(mod, 'run_qemu') as run, \
                     mock.patch.object(mod, 'qemu_version') as version, \
                     contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as stopped:
                        mod.main()
                self.assertEqual(stopped.exception.code, 2)
                self.assertIn('E2E STOP:', stderr.getvalue())
                self.assertNotIn('Traceback', stderr.getvalue())
                run.assert_not_called()
                version.assert_not_called()

    def test_offline_preparation_records_selected_ram_without_fixed_limit_claim(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            artifact, work = root/'artifact', root/'work'
            expected = self.artifact_fixture(artifact)
            firmware = root/'firmware'; firmware.write_bytes(b'fixture')
            args = SimpleNamespace(artifact=str(artifact), work=str(work),
                expected_plan_sha256=expected, ovmf_code=str(firmware),
                ovmf_vars=str(firmware), execute=False, qemu='/never-executed')
            with mock.patch.dict(os.environ, {'ABSD_GUEST_RAM': '1G'}), \
                    mock.patch.object(mod.builder, 'iso'), \
                    mock.patch.object(mod, 'run_qemu') as run, \
                    mock.patch.object(mod, 'qemu_version') as version:
                mod.prepare(args)
            run.assert_not_called()
            version.assert_not_called()
            commands = json.loads((work/'COMMANDS.json').read_text())
            self.assertEqual(len(commands), 8)
            for case in commands:
                argv = case['argv']
                self.assertEqual(argv.count('-m'), 1)
                self.assertEqual(argv[argv.index('-m') + 1], '1G')
            apparatus = json.loads((work/'APPARATUS.json').read_text())
            self.assertNotIn('512MiB per guest', apparatus['limits'])
            self.assertIn('COMMANDS.json', apparatus['limits'])

    def module(self):
        spec = importlib.util.spec_from_file_location('e2e', pathlib.Path(__file__).with_name('native-installer-e2e.py'))
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        return mod

    def artifact_fixture(self, root):
        import hashlib, zlib
        root.mkdir()
        names = ('payload.bin', 'installed.elf', 'installer.elf', 'installer.iso')
        for name in names: (root/name).write_bytes(b'fixture')
        digest = hashlib.sha256(b'fixture').hexdigest()
        plan = {'schema':'absd-native-install-plan/1', 'model':'QEMU HARDDISK',
                'serial':'test', 'sectors':layout.MIN_SECTORS,
                'kernel_source':'a'*40, 'platform_source':'b'*40,
                'payload_sha256':digest, 'payload_crc32':f'{zlib.crc32(b"fixture"):08x}',
                'artifacts':{name:digest for name in names}}
        (root/'PLAN.json').write_text(json.dumps(plan))
        return hashlib.sha256((root/'PLAN.json').read_bytes()).hexdigest()

    def test_cli_requires_expected_plan_sha256(self):
        mod = self.module()
        with mock.patch.object(sys, 'argv', ['e2e', '--artifact', '/unused', '--work', '/unused']), \
                mock.patch.object(mod, 'prepare') as prepare, \
                mock.patch('sys.stderr'):
            with self.assertRaises(SystemExit) as stopped: mod.main()
            self.assertEqual(stopped.exception.code, 2)
            prepare.assert_not_called()

    def test_expected_plan_is_checked_before_work_creation(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); artifact = root/'artifact'
            expected = self.artifact_fixture(artifact)
            args = SimpleNamespace(artifact=str(artifact), work=str(root/'work'),
                                   expected_plan_sha256='0'*64,
                                   ovmf_code='/missing', ovmf_vars='/missing', execute=False)
            # Even a self-consistent replacement must not get as far as OVMF/work.
            with self.assertRaisesRegex(layout.Refused, 'expected plan sha256 mismatch'):
                mod.prepare(args)
            self.assertFalse((root/'work').exists())
            self.assertEqual(mod.verify_artifact(artifact, expected)['serial'], 'test')
            for bad in ('', '0'*63, 'z'*64):
                with self.subTest(digest=bad), self.assertRaises(layout.Refused):
                    mod.verify_artifact(artifact, bad)

    def test_receipt_retains_case_exits_and_host_verdicts_on_pass_and_failure(self):
        mod = self.module()
        for failure in (None, 'exit', 'esp', 'persisted-file', 'timeout'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp); artifact = root/'artifact'; work = root/'work'
                expected = self.artifact_fixture(artifact)
                code = root/'code'; code.write_bytes(b'firmware')
                args = SimpleNamespace(artifact=str(artifact), work=str(work),
                    expected_plan_sha256=expected, ovmf_code=str(code), ovmf_vars=str(code),
                    execute=True, qemu='/never-executed')
                def run(argv, log):
                    name = pathlib.Path(log.name).name.removesuffix('.qemu.log')
                    case = next(c for c in json.loads((work/'COMMANDS.json').read_text()) if c['case'] == name)
                    if failure == 'timeout' and name == 'inspect':
                        raise subprocess.TimeoutExpired(argv, 300)
                    data = (case['expected']+'\n').encode()
                    if name.startswith('cold-'):
                        digest = 0x811c9dc5
                        for byte in data: digest = ((digest ^ byte)*0x1000193) & 0xffffffff
                        data = (f'EXTERNAL OUTPUT BEGIN encoding=hex\n'
                                f'EXTERNAL OUTPUT CHUNK offset=0000000000000000 data={data.hex()}\n'
                                f'EXTERNAL OUTPUT END bytes={len(data)} digest={digest:08x}\n').encode()
                    (work/(name+'.serial.log')).write_bytes(data)
                    (work/(name+'.trace')).write_bytes(b'fixture trace')
                    return SimpleNamespace(returncode=42 if failure == 'exit' and name == 'wrong' else case['exit'])
                def inspect(image, plan, artifact, checks=None):
                    checks = {} if checks is None else checks
                    checks['gpt'] = {'status':'PASS'}
                    checks['boot_payload'] = {'status':'PASS'}
                    checks['esp'] = {'status':'FAIL' if failure == 'esp' else 'PASS',
                                     'result':{'files':{'EFI/BOOT/BOOTX64.EFI':'observed-digest'}}}
                    if failure == 'esp': raise layout.Refused('fixture ESP mismatch')
                def state(image):
                    if failure == 'persisted-file': raise layout.Refused('fixture persisted file mismatch')
                    return {'path':'/native-installer-143', 'sha256':'observed-file-digest'}
                with mock.patch.dict(os.environ, {'ABSD_PROTECTED_HOST': ''}), \
                     mock.patch.object(mod.socket, 'gethostname', return_value='execution_host'), \
                        mock.patch.object(mod, 'qemu_version', return_value='QEMU emulator version 8.2.2'), \
                        mock.patch.object(mod.shutil, 'disk_usage', return_value=SimpleNamespace(free=100<<30)), \
                        mock.patch.object(mod.builder, 'iso'), mock.patch.object(mod, 'run_qemu', side_effect=run), \
                        mock.patch.object(mod, 'layout_digest', return_value='unchanged'), \
                        mock.patch.object(mod, 'check_install_flushes', return_value=2), \
                        mock.patch.object(mod, 'inspect', side_effect=inspect), \
                        mock.patch.object(mod, 'inspect_state', side_effect=state), \
                        mock.patch.object(layout, 'first_nonzero', return_value=None):
                    if failure:
                        with self.assertRaises((layout.Refused, subprocess.TimeoutExpired)): mod.prepare(args)
                    else: mod.prepare(args)
                receipt = json.loads((work/'RECEIPT.json').read_text())
                self.assertEqual(receipt['plan_sha256'], expected)
                self.assertEqual(receipt['status'], 'FAIL' if failure else 'PASS')
                cases = {case['case']:case for case in receipt['cases']}
                self.assertEqual(len(cases), 8)
                if failure == 'exit':
                    self.assertEqual(cases['wrong']['actual_exit'], 42)
                    self.assertEqual(cases['wrong']['status'], 'FAIL')
                    self.assertEqual(cases['install']['status'], 'NOT_RUN')
                elif failure == 'timeout':
                    self.assertIsNone(cases['inspect']['actual_exit'])
                    self.assertEqual(cases['inspect']['status'], 'TIMEOUT')
                else:
                    self.assertEqual(cases['install']['actual_exit'], 3)
                    boot = cases['install']['host_checks']
                    self.assertEqual(boot['gpt']['status'], 'PASS')
                    self.assertEqual(boot['esp']['status'], 'FAIL' if failure == 'esp' else 'PASS')
                    if failure != 'esp':
                        state = cases['cold-first']['host_checks']['persisted_file']
                        self.assertEqual(state['status'], 'FAIL' if failure else 'PASS')
                        if not failure:
                            self.assertEqual(state['result']['path'], '/native-installer-143')
                            for case in receipt['cases']:
                                self.assertEqual(case['actual_exit'], case['expected_exit'])
                                self.assertEqual(case['status'], 'PASS')
                self.assertEqual((work/'PASS.json').exists(), failure is None)

    @unittest.skipUnless(os.environ.get('ABSD_INSTALLER_RETAINED_LOGS'), 'set ABSD_INSTALLER_RETAINED_LOGS to replay retained serial logs')
    def test_retained_cold_first_output(self):
        mod = self.module()
        root = pathlib.Path(os.environ['ABSD_INSTALLER_RETAINED_LOGS'])
        case = next(case for case in json.loads((root/'COMMANDS.json').read_text()) if case['case'] == 'cold-first')
        raw = (root/'cold-first.serial.log').read_bytes()
        self.assertNotIn(case['expected'].encode(), raw)
        self.assertEqual(mod.external_output(raw), b'INSTALL PERSIST CREATED SYNCED\n')
        mod.check_case_output(case, 3, raw)
        for changed in (raw.split(b'EXTERNAL OUTPUT END')[0],
                        raw.replace(b'digest=b6c115b0', b'digest=00000000'),
                        raw.replace(b'END bytes=31', b'END bytes=30'),
                        raw.replace(b'53594e4345440a\n', b'53594e434544\n')):
            with self.subTest(changed=changed), self.assertRaises(layout.Refused):
                mod.check_case_output(case, 3, changed)

    @unittest.skipUnless(os.environ.get('ABSD_INSTALLER_RETAINED_LOGS'), 'set ABSD_INSTALLER_RETAINED_LOGS to replay retained serial logs')
    def test_every_case_expectation_against_retained_logs(self):
        mod = self.module()
        root = pathlib.Path(os.environ['ABSD_INSTALLER_RETAINED_LOGS'])
        recorded = {case['case']:case for case in json.loads((root/'COMMANDS.json').read_text())}
        cases = mod.install_cases(pathlib.Path('artifact'), pathlib.Path('work'), 'test')
        self.assertEqual({case[0] for case in cases}, set(recorded))
        for name, _, _, _, _, expected, status in cases:
            with self.subTest(case=name):
                case = recorded[name]
                self.assertEqual((expected, status), (case['expected'], case['exit']))
                log = root/(name+'.serial.log')
                if name == 'cold-second' and not log.exists():
                    self.skipTest('cold-second was not observed: runtime-01 stopped at cold-first')
                mod.check_case_output(case, status, log.read_bytes())

    def output_fixture(self):
        # Exact stdout frames from runtime-01/cold-first.serial.log, also
        # exercised in the full retained log via ABSD_INSTALLER_RETAINED_LOGS.
        return (b'EXTERNAL OUTPUT BEGIN encoding=hex\n'
                b'EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=494e5354414c4c205045525349535420435245415445442053594e4345440a\n'
                b'EXTERNAL OUTPUT END bytes=31 digest=b6c115b0\n')

    def test_verified_output_can_span_chunks(self):
        mod = self.module()
        raw = self.output_fixture()
        case = {'case':'cold-first', 'expected':'INSTALL PERSIST CREATED SYNCED', 'exit':3}
        data = b'INSTALL PERSIST CREATED SYNCED\n'
        chunk = raw.splitlines(keepends=True)[1]
        chunks = b''.join(f'EXTERNAL OUTPUT CHUNK offset={at:016x} data={data[at:at+7].hex()}\n'.encode() for at in range(0, len(data), 7))
        raw = raw.replace(chunk, chunks)
        self.assertEqual(mod.external_output(raw), data)
        mod.check_case_output(case, 3, raw)
        mod.check_case_output(case, 3, raw.replace(b'\n', b'\r\n'))

    def test_incomplete_or_corrupt_stream_never_matches(self):
        mod = self.module()
        raw = self.output_fixture()
        begin, chunk, end = raw.splitlines(keepends=True)
        case = {'case':'cold-first', 'expected':'INSTALL PERSIST CREATED SYNCED', 'exit':3}
        changed = {
            'missing end': begin+chunk,
            'truncated end': raw[:-1],
            'wrong count': raw.replace(b'bytes=31', b'bytes=30'),
            'wrong digest': raw.replace(b'b6c115b0', b'00000000'),
            'truncated payload': raw.replace(b'5440a\n', b'544\n'),
            'wrong offset': raw.replace(b'offset=0000000000000000', b'offset=0000000000000001'),
            'odd hex': raw.replace(b'data=49', b'data=9'),
            'invalid hex': raw.replace(b'data=49', b'data=zz'),
            'missing begin': chunk+end,
            'duplicate begin': begin+raw,
            'duplicate end': raw+end,
            'duplicate chunk': begin+chunk+chunk+end,
            'unanchored chunk': raw.replace(chunk, b'prefix '+chunk),
            'chunk after end': raw+chunk,
            'end before chunk': begin+end+chunk,
            'plaintext only': case['expected'].encode()+b'\n',
        }
        for name, serial in changed.items():
            with self.subTest(corruption=name), self.assertRaises(layout.Refused):
                # A plaintext copy must not bypass a broken stdout stream.
                mod.check_case_output(case, 3, serial+case['expected'].encode()+b'\n')

    def test_output_check_preserves_exit_and_failure_checks(self):
        mod = self.module()
        raw = self.output_fixture()
        case = {'case':'cold-first', 'expected':'INSTALL PERSIST CREATED SYNCED', 'exit':3}
        with self.assertRaises(layout.Refused): mod.check_case_output(case, 11, raw)
        with self.assertRaises(layout.Refused): mod.check_case_output(case, 3, raw+b'PANIC\n')
        case['expected'] = 'INSTALL PERSIST VERIFIED'
        with self.assertRaises(layout.Refused): mod.check_case_output(case, 3, raw)
        for expected in ('INSTALL REFUSED consent', 'INSTALL INSTALLED '):
            case = {'case':'install', 'expected':expected, 'exit':3}
            mod.check_case_output(case, 3, expected.encode()+b'\n')


    def test_media_boot_is_explicit_with_installed_disk_attached(self):
        mod = self.module()
        argv = mod.command('qemu', 'code', 'vars', 'disk', 'test', 'install.iso', log='serial', trace='trace')
        cd = next(word for word in argv if word.startswith('ide-cd,'))
        cd_options = dict(option.split('=', 1) for option in cd.split(',')[1:])
        self.assertEqual(cd_options['drive'], 'install-media')
        self.assertEqual(cd_options.get('bus'), 'ide.0')
        self.assertEqual(cd_options['bootindex'], '0')
        self.assertIn('ide-hd,drive=target,bus=sata.0,serial=test,bootindex=1', argv)
        self.assertEqual(argv[argv.index('-smp')+1], '1')
        self.assertNotIn('-boot', argv)
        self.assertNotIn('-cdrom', argv)
        self.assertIn('ide_bus_exec_cmd', argv)
        self.assertIn('serial_write', argv)
        self.assertEqual(argv[argv.index('-D')+1], 'trace')
        cold = mod.command('qemu', 'code', 'vars', 'disk', 'test', log='serial', trace='trace')
        self.assertFalse(any('ide-cd' in word for word in cold))

    def test_install_flush_count_comes_from_native_qemu_trace(self):
        mod = self.module()
        # Real QEMU format retained in sata-ahci-census-20261015/run6.
        def command(op): return f'ide_bus_exec_cmd IDE exec cmd: bus 0x5ab04e615048; state 0x5ab04e6150d0; cmd 0x{op:02x}\n'
        marker = ''.join(f'serial_write write addr 0x00 val 0x{byte:02x}\n' for byte in b'INSTALL PLAN serial=test')
        with tempfile.TemporaryDirectory() as work:
            trace = pathlib.Path(work)/'install.trace'
            # Firmware flushes do not satisfy the native installation oracle.
            for ops in ([], [0xea], [0xea]*3, [0xe7, 0xea]):
                trace.write_text(command(0xea)*2+marker+''.join(command(op) for op in ops))
                with self.assertRaises(layout.Refused): mod.check_install_flushes(trace)
            trace.write_text(command(0xea)*3+marker+command(0x35)+command(0xea)*2)
            self.assertEqual(mod.check_install_flushes(trace), 2)
            trace.write_text(command(0xea)*2)
            with self.assertRaises(layout.Refused): mod.check_install_flushes(trace)

    def test_qemu_version_is_observed_and_pinned(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as work:
            binary = pathlib.Path(work)/'version-fixture'
            binary.write_text('#!/bin/sh\nprintf "QEMU emulator version 8.2.2 (fixture)\\n"\n')
            binary.chmod(0o700)
            self.assertEqual(mod.qemu_version(str(binary)), 'QEMU emulator version 8.2.2 (fixture)')
            binary.write_text('#!/bin/sh\nprintf "QEMU emulator version 10.2.1\\n"\n')
            with self.assertRaises(layout.Refused): mod.qemu_version(str(binary))

    def test_runner_death_kills_emulator_child(self):
        # Use a real Linux child and parent-death signals; never invoke QEMU.
        libc = ctypes.CDLL(None, use_errno=True)
        old = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(old), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)  # adopt/reap the orphan
        try:
            for death in (signal.SIGTERM, signal.SIGKILL):
                with self.subTest(signal=death), tempfile.TemporaryDirectory() as work:
                    root = pathlib.Path(work); pidfile = root/'pid'
                    module = pathlib.Path(__file__).with_name('native-installer-e2e.py')
                    child_code = f'import os,pathlib,time; pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())); time.sleep(30)'
                    parent_code = f'import importlib.util; s=importlib.util.spec_from_file_location("e2e",{str(module)!r}); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.run_qemu({[sys.executable, "-c", child_code]!r},open({str(root/"log")!r},"wb"))'
                    parent = subprocess.Popen([sys.executable, '-B', '-I', '-X', f"pycache_prefix={sys.pycache_prefix or ''}", '-c', parent_code])
                    child = None
                    try:
                        deadline = time.monotonic()+5
                        while not pidfile.exists() and parent.poll() is None and time.monotonic()<deadline: time.sleep(.01)
                        self.assertTrue(pidfile.exists(), 'child failed to start')
                        child = int(pidfile.read_text())
                        os.kill(parent.pid, death); parent.wait(timeout=5)
                        deadline = time.monotonic()+5
                        status = None
                        while time.monotonic()<deadline:
                            reaped, status = os.waitpid(child, os.WNOHANG)
                            if reaped: break
                            time.sleep(.01)
                        self.assertEqual(reaped, child, 'runner left its child alive')
                        child = None
                        self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL)
                    finally:
                        if parent.poll() is None: parent.kill(); parent.wait()
                        if child is not None:
                            try: os.kill(child, signal.SIGKILL)
                            except ProcessLookupError: pass
                            os.waitpid(child, 0)
        finally: libc.prctl(36, old.value, 0, 0, 0)

    def test_refuses_tampered_artifact_and_blank_filesystem(self):
        import hashlib, json, zlib
        spec = importlib.util.spec_from_file_location('e2e', pathlib.Path(__file__).with_name('native-installer-e2e.py'))
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as work:
            root = pathlib.Path(work)
            names = ('payload.bin','installed.elf','installer.elf','installer.iso')
            for name in names: (root/name).write_bytes(b'fixture')
            digest = hashlib.sha256(b'fixture').hexdigest()
            plan = {'schema':'absd-native-install-plan/1','model':'QEMU HARDDISK',
                    'payload_sha256':digest,'payload_crc32':f'{zlib.crc32(b"fixture"):08x}',
                    'artifacts':{name:digest for name in names}}
            (root/'PLAN.json').write_text(json.dumps(plan))
            self.assertEqual(mod.verify_artifact(root, mod.media.sha(root/'PLAN.json')), plan)
            (root/'installed.elf').write_bytes(b'changed')
            with self.assertRaises(layout.Refused): mod.verify_artifact(root, mod.media.sha(root/'PLAN.json'))
            disk = root/'disk.img'
            with disk.open('wb') as f: f.truncate(3 << 30)
            with self.assertRaises(layout.Refused): mod.inspect_state(disk)

    def test_exit_status_matches_kernel_debug_exit_encoding(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('e2e', pathlib.Path(__file__).with_name('native-installer-e2e.py'))
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        self.assertTrue(hasattr(mod, 'exit_status'), 'debug-exit status contract is missing')
        self.assertEqual(mod.exit_status(0), 3)
        self.assertEqual(mod.exit_status(2), 11)
        self.assertEqual(mod.exit_status(3), 15)


class DiskInspectionTests(unittest.TestCase):
    """Real host readers on disposable sparse images; no QEMU or inspector mocks.

    Keep production geometry, but allocate only GPT, FAT and tiny filesystem
    records. Each negative isolates one check: the payload agrees with a bad
    GPT or changed ESP, so those failures cannot be credited to the payload.
    """

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('disk_e2e', pathlib.Path(__file__).with_name('native-installer-e2e.py'))
        cls.mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.mod)
        cls.tmp = tempfile.TemporaryDirectory(prefix='native-installer-readback-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = pathlib.Path(cls.tmp.name)
        cls.golden = cls.root/'golden.img'
        with cls.golden.open('xb') as handle: handle.truncate(layout.MIN_SECTORS*512)
        cls.guids = {key:str(uuid.UUID(int=i)).upper()
                     for i, key in enumerate(('disk', 'esp', 'absd'), 1)}
        kernel = cls.root/'kernel.elf'
        magic, length = 0xe85250d6, 24
        kernel.write_bytes(struct.pack('<IIIIHHI', magic, 0, length,
                                       (-(magic+length)) & 0xffffffff, 0, 0, 8)+bytes(4096))
        env = cls.mod.media.clean_env(cls.mod.builder.EPOCH)
        profile = layout.load_profile()
        line = layout.kernel_line(['durable=0'], cls.guids['absd'], 'test')
        esp, files, _ = layout.build_esp(cls.root, profile, kernel, layout.grub_config(profile, line),
            '1430-0001', '14300001', '{}\n', cls.mod.builder.EPOCH, env)
        cls.plan = {'guids':cls.guids, 'esp_files':files}
        target = layout.Target(cls.golden, writable=True)
        try:
            layout.write_gpt(target, *(cls.guids[key] for key in ('disk', 'esp', 'absd')), env)
            layout.copy_esp(esp, target)
            layout.read_back(target.fd, target.size, cls.guids)
        finally: target.close()
        cls.write_state(cls.golden)
        cls.payload = cls.mod.builder.pack(cls.golden, 'test', cls.mod.builder.MODEL)

    @classmethod
    def write_state(cls, image):
        """Write one valid v3 layout and format-2 file, without a guest writer."""
        ai, fs = cls.mod.absd_image, cls.mod.absd_fs
        half = layout.ABSD_SECTORS//2
        slot, segment = half//4, half//16
        spans = [(1, ai.KIND_ACTIVATION, 1, 2), (2, ai.KIND_LEDGER, 16, slot-16),
                 (3, ai.KIND_GENERATION, half-2*slot, slot), (4, ai.KIND_GENERATION, half-slot, slot),
                 *[(5+i, ai.KIND_LOG, slot+i*segment, segment) for i in range(4)],
                 (9, ai.KIND_FS, half, layout.ABSD_SECTORS-half)]
        descriptor = bytearray(512); descriptor[:8] = ai.LAYOUT_MAGIC
        struct.pack_into('<IIQ', descriptor, 8, 3, len(spans), layout.ABSD_SECTORS)
        for i, span in enumerate(spans): struct.pack_into('<IIQQ', descriptor, 24+i*32, *span)
        struct.pack_into('<Q', descriptor, 504, ai.fnv1a(descriptor[:504]))
        geo = fs.geometry(layout.ABSD_SECTORS-half)
        fs_start = (layout.ABSD_FIRST+half)*512
        content = b'ABSD native installer 143 persistent file v1\n'
        name = b'native-installer-143'
        with image.open('r+b') as handle:
            handle.seek(layout.ABSD_FIRST*512); handle.write(descriptor)
            for seq in (0, 1):
                raw = (b'ABSDFSI2'+struct.pack('<IIQQQIIQQ', 2, 0, 7, seq, 3, geo['data_blocks'], 2,
                        geo['region_sectors'], geo['half_sectors'])
                       +struct.pack('<QQQBBHIQ', 1, 0, 0, 2, 0, 0, 0, 0)
                       +struct.pack('<QQQBBHIQ', 2, 1, len(content), 1, 0, len(name), 1, 0)+name
                       +struct.pack('<I', 0))
                sb = bytearray(512); sb[:8] = b'ABSDFSS2'
                struct.pack_into('<IIQQIIQQQQ', sb, 8, 2, seq, 7, seq, len(raw), 0,
                    geo['region_sectors'], geo['half_sectors'], geo['data_first'], geo['data_blocks'])
                sb[72:104] = hashlib.sha256(raw).digest()
                sb[480:] = hashlib.sha256(sb[:480]).digest()
                handle.seek(fs_start+seq*512); handle.write(sb)
                handle.seek(fs_start+(fs.META_FIRST+seq*geo['half_sectors'])*512); handle.write(raw)
            cls.content_offset = fs_start+geo['data_first']*512
            handle.seek(cls.content_offset); handle.write(content)

    def setUp(self):
        self.work = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(dir=self.root)))
        self.image = self.work/'disk.img'
        subprocess.run(['cp', '--reflink=auto', '--sparse=always', str(self.golden), str(self.image)], check=True)
        self.artifact = self.work/'artifact'; self.artifact.mkdir()
        (self.artifact/'payload.bin').write_bytes(self.payload)

    def inspect(self):
        checks = {}
        self.mod.inspect(self.image, self.plan, self.artifact, checks)
        self.assert_boot_checks(checks, self.plan)
        return checks

    def assert_boot_checks(self, checks, plan):
        self.assertTrue(plan['esp_files'], 'ESP inventory must not be empty')
        self.assertEqual({key:value['status'] for key, value in checks.items()},
                         {'gpt':'PASS', 'boot_payload':'PASS', 'esp':'PASS'})
        self.assertEqual(checks['esp']['result']['files'],
                         {name:item['sha256'] for name, item in plan['esp_files'].items()})

    def repack(self):
        (self.artifact/'payload.bin').write_bytes(self.mod.builder.pack(self.image, 'test', self.mod.builder.MODEL))

    def test_real_disk_checks_pass(self):
        self.inspect()
        state = self.mod.inspect_state(self.image)
        content = b'ABSD native installer 143 persistent file v1\n'
        self.assertEqual(state, {'path':'/native-installer-143', 'bytes':len(content),
                                 'sha256':hashlib.sha256(content).hexdigest()})

    def test_gpt_difference_is_refused_even_when_payload_matches(self):
        self.inspect()
        with self.image.open('r+b') as handle:
            handle.seek(512+16); crc = handle.read(1)
            handle.seek(512+16); handle.write(bytes([crc[0] ^ 1]))
        self.repack()  # Corrupt GPT bytes agree with the payload; only read_back can refuse.
        checks = {}
        with self.assertRaisesRegex(layout.Refused, 'gpt_primary header CRC mismatch'):
            self.mod.inspect(self.image, self.plan, self.artifact, checks)
        self.assertEqual(checks['gpt']['status'], 'FAIL')
        self.assertNotIn('boot_payload', checks)

    def test_payload_difference_is_refused_with_valid_gpt_and_esp(self):
        self.inspect()
        with self.image.open('r+b') as handle:
            handle.seek(0); handle.write(b'x')  # MBR bootstrap, outside GPT structural fields.
        checks = {}
        with self.assertRaisesRegex(layout.Refused, 'installed boot payload differs'):
            self.mod.inspect(self.image, self.plan, self.artifact, checks)
        self.assertEqual(checks['gpt']['status'], 'PASS')
        self.assertEqual(checks['boot_payload']['status'], 'FAIL')
        self.assertNotIn('esp', checks)

    def test_esp_difference_is_refused_even_when_payload_matches(self):
        self.inspect()
        changed = self.work/'changed.cfg'; changed.write_bytes(b'changed boot configuration\n')
        subprocess.run(['mcopy', '-o', '-i', f'{self.image}@@{layout.ESP_FIRST*512}',
                        str(changed), '::/BOOT/GRUB.CFG'], check=True, capture_output=True)
        self.repack()  # GPT and sparse payload still pass; expected ESP hashes stay fixed.
        checks = {}
        with self.assertRaisesRegex(layout.Refused, 'installed ESP file differs: BOOT/GRUB.CFG'):
            self.mod.inspect(self.image, self.plan, self.artifact, checks)
        self.assertEqual(checks['gpt']['status'], 'PASS')
        self.assertEqual(checks['boot_payload']['status'], 'PASS')
        self.assertEqual(checks['esp']['status'], 'FAIL')

    def test_persisted_file_difference_is_refused_in_valid_filesystem(self):
        self.assertEqual(self.mod.inspect_state(self.image)['path'], '/native-installer-143')
        with self.image.open('r+b') as handle:
            handle.seek(self.content_offset); handle.write(b'X')  # Data only; metadata remains valid.
        self.inspect()
        with self.assertRaisesRegex(layout.Refused, 'independent installed file check failed'):
            self.mod.inspect_state(self.image)

    def test_empty_esp_inventory_fails_test_oracle(self):
        plan = dict(self.plan, esp_files={})
        checks = {}
        self.mod.inspect(self.image, plan, self.artifact, checks)
        # Assert nonemptiness explicitly: equality of two empty inventories is vacuous.
        with self.assertRaisesRegex(AssertionError, 'ESP inventory must not be empty'):
            self.assert_boot_checks(checks, plan)

if __name__ == '__main__': unittest.main()
