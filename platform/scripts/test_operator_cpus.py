#!/usr/bin/env python3
import os
import contextlib
import io
import pathlib
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import operator_image
import test_operator_boot_binding as grub_tests
import operator_cpus
import served_kernel


class OperatorCpus(unittest.TestCase):
    def test_profiles_and_qemu_arguments(self):
        for value in (None, '1'):
            env = {} if value is None else {'ABSD_OPERATOR_CPUS': value}
            self.assertEqual(operator_cpus.profile(env), 1)
            self.assertEqual(operator_cpus.qemu(['qemu'], env), ['qemu'])
            self.assertEqual(operator_cpus.qemu(['qemu', '-smp', '8'], env), ['qemu', '-smp', '8'])
        for count, topology in (('2', '2,sockets=1,cores=2,threads=1'),
                                ('4', '4,sockets=1,cores=4,threads=1'),
                                ('6', '6,sockets=1,cores=6,threads=1')):
            env = {'ABSD_OPERATOR_CPUS': count}
            with self.subTest(count=count):
                self.assertEqual(operator_cpus.profile(env), int(count))
                expected = ['qemu', '-cpu', 'max', '-smp', topology]
                self.assertEqual(operator_cpus.qemu(['qemu', '-cpu', 'max'], env), expected)
                self.assertEqual(operator_cpus.qemu('qemu -cpu max', env), expected)
            for words in (['qemu', '-smp', '2'], ['qemu', '-smp=1'],
                          ['qemu', '-smp', '2', '-smp', '2'], ['qemu', '--smp', '2'],
                          ['qemu', '--smp=2'], ['qemu', '-smp2'], ['qemu', '--smp2'],
                          ['qemu', '-smp', '4,sockets=1,cores=4,threads=1']):
                with self.subTest(count=count, words=words), self.assertRaises(ValueError):
                    operator_cpus.qemu(words, env)
        for value in ('', '0', '3', '5', '7', '8', '-2', '02', '04', '06',
                      ' 2', '4 ', '6\n', '2,cores=2', '4 6', '2|4', '2.0'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                operator_cpus.profile({'ABSD_OPERATOR_CPUS': value})

    def test_launch_executes_qemu_with_matching_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = pathlib.Path(directory, 'qemu')
            fake.write_text('#!/usr/bin/env python3\nimport sys\nprint(repr(sys.argv[1:]))\n')
            fake.chmod(0o755)
            for count, expected in (('1', "['-cpu', 'max']"),
                                    ('2', "['-cpu', 'max', '-smp', '2,sockets=1,cores=2,threads=1']"),
                                    ('4', "['-cpu', 'max', '-smp', '4,sockets=1,cores=4,threads=1']"),
                                    ('6', "['-cpu', 'max', '-smp', '6,sockets=1,cores=6,threads=1']")):
                env = dict(os.environ, ABSD_OPERATOR_CPUS=count)
                run = subprocess.run([sys.executable, str(pathlib.Path(operator_cpus.__file__)), 'launch', str(fake), '-cpu', 'max'], env=env, capture_output=True, text=True)
                with self.subTest(count=count):
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertEqual(run.stdout.strip(), expected)

    @unittest.skipUnless(shutil.which('xorriso'), 'xorriso required')
    def test_check_reads_actual_iso_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'tree/boot/grub').mkdir(parents=True)
            (root / 'tree/boot/absd-kernel').write_bytes(b'unique test kernel')
            config = root / 'tree/boot/grub/grub.cfg'
            iso = root / 'operator.iso'
            boots = [(count, grub_tests.GrubTests.CONFIG.replace(b'served nvme', word)) for count, word in
                     ((1, b'served nvme'), (2, b'served smp-operator=2 nvme'),
                      (4, b'served smp-operator=4 nvme'), (6, b'served smp-operator=6 nvme'))]
            boots += [(None, grub_tests.GrubTests.CONFIG.replace(b'served nvme',
                       f'served smp-operator={first} smp-operator={second} nvme'.encode()))
                      for first in (2, 4, 6) for second in (2, 4, 6)]
            boots.append((None, grub_tests.GrubTests.CONFIG.replace(b'served nvme', b'served smp-operator=8 nvme')))
            out = root / 'out'
            out.mkdir()
            (out / operator_image.IMAGE).write_bytes(b'untouched disk')
            (out / 'console.log').write_bytes(b'previous console')
            fake = root / 'qemu'
            fake.write_text('#!/bin/sh\ntouch "' + str(root / 'launched') + '"\n')
            fake.chmod(0o755)
            for actual, boot in boots:
                config.write_bytes(boot)
                subprocess.run(['xorriso', '-as', 'mkisofs', '-quiet', '-o', str(iso), str(root / 'tree')], check=True, capture_output=True)
                for selected in (2, 4, 6):
                    env = dict(os.environ, ABSD_OPERATOR_CPUS=str(selected))
                    result = subprocess.run([sys.executable, operator_cpus.__file__, 'check', str(iso), 'qemu'], env=env, capture_output=True)
                    with self.subTest(actual=actual, selected=selected):
                        self.assertEqual(result.returncode == 0, actual == selected, result.stderr)
                        if actual != selected:
                            shutil.copyfile(iso, out / operator_image.ISO)
                            env['ABSD_QEMU'] = str(fake)
                            run = subprocess.run([str(pathlib.Path(__file__).with_name('boot-operator.sh')), str(out)],
                                                 env=env, capture_output=True)
                            self.assertEqual(run.returncode, 7, run.stderr)
                            self.assertFalse((root / 'launched').exists())
                            self.assertEqual((out / 'console.log').read_bytes(), b'previous console')
                            self.assertFalse((out / 'recovery').exists())
                            self.assertEqual((out / operator_image.IMAGE).read_bytes(), b'untouched disk')

    def test_build_binds_only_the_final_iso_and_keeps_importers_up(self):
        for count, options in (('1', 'net fsd served'), ('2', 'net fsd served smp-operator=2'),
                               ('4', 'net fsd served smp-operator=4'), ('6', 'net fsd served smp-operator=6')):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                commands = []

                def make(argv, **kwargs):
                    commands.append(argv)
                    step = next(word.split('=', 1)[1] for word in argv if word.startswith('DURABLE_STEP='))
                    target = root / 'kernel/build/durable' / f'absd-durable-{step}.iso'
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(('iso for step ' + step).encode())
                    process = mock.MagicMock()
                    process.__enter__.return_value = process
                    process.stdout = io.BytesIO()
                    process.wait.return_value = 0
                    return process

                keys = root / 'authorized_keys'
                keys.write_text('ssh-ed25519 AAAA fixture\n')
                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.dict(os.environ, {'ABSD_OPERATOR_CPUS': count}))
                    for owner, name, value in (
                            (operator_image, 'IMAGE_BYTES', 4096),
                            (operator_image, 'system_files', lambda root: [('/bin/example', b'example')]),
                            (operator_image, 'etc_files', lambda *args: []),
                            (operator_image, 'verify', lambda *args: None),
                            (operator_image, 'check_successor_headroom', lambda *args: {'peak_extra_blocks': 1, 'free_blocks': 2}),
                            (operator_image, 'identity', lambda path: 'fixture-revision'),
                            (operator_image, '_import_boots', lambda *args: None),
                            (operator_image.storage_fence_host, 'mutation', lambda *args, **kwargs: contextlib.nullcontext()),
                            (operator_image.em, 'inspect_import_plan', lambda image, plan: ([], {})),
                            (operator_image.subprocess, 'Popen', make)):
                        stack.enter_context(mock.patch.object(owner, name, value))
                    operator_image.build(root / 'kernel', root / 'out', keys, root=root,
                                         release_id='dev', log=lambda line: None)
                self.assertGreaterEqual(len(commands), 3)
                for command in commands[:-1]:
                    self.assertNotIn('--operator-smp', command)
                    self.assertIn('DURABLE_OPTIONS=', command)
                    self.assertNotIn('DURABLE_STEP=0', command)
                final = commands[-1]
                self.assertIn('DURABLE_STEP=0', final)
                self.assertIn('DURABLE_OPTIONS=' + options, final)
                self.assertEqual('--operator-smp' in final, count != '1')
                self.assertEqual((root / 'out' / operator_image.ISO).read_bytes(), b'iso for step 0')
                self.assertTrue((root / 'out/MANIFEST').is_file())

    def test_invalid_build_inputs_refuse_before_output_creation(self):
        for value in ('', '0', '3', '5', '7', '8', ' 4', '6 ', '4,cores=4'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                out = pathlib.Path(directory) / 'out'
                with mock.patch.dict(os.environ, {'ABSD_OPERATOR_CPUS': value}), self.assertRaises(ValueError):
                    operator_image.build(directory, out, 'missing-keys')
                self.assertFalse(out.exists())
        for count in ('2', '4', '6'):
            for words in ('qemu -smp 2', 'qemu -smp=4', 'qemu --smp 6', 'qemu --smp=2', 'qemu -smp4'):
                with self.subTest(count=count, words=words), tempfile.TemporaryDirectory() as directory:
                    out = pathlib.Path(directory) / 'out'
                    with mock.patch.dict(os.environ, {'ABSD_OPERATOR_CPUS': count}), self.assertRaises(ValueError):
                        operator_image.build(directory, out, 'missing-keys', qemu=words)
                    self.assertFalse(out.exists())

    def test_real_make_feature_selection_and_no_override(self):
        with tempfile.TemporaryDirectory() as directory:
            pathlib.Path(directory, 'Makefile').write_text('durable-iso:\n\t@echo "$(EXTERNAL_KERNEL_FEATURES)"\n')
            for flag, expected in (([], 'frame-admission-v0'), (['--operator-smp'], 'frame-admission-v0,smp-operator')):
                run = subprocess.run([*served_kernel.kernel_make(), *flag, '-e', '-C', directory, '--no-print-directory', 'durable-iso'], capture_output=True, text=True, env=dict(os.environ, EXTERNAL_KERNEL_FEATURES='other'))
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stdout.strip(), expected)
            run = subprocess.run([*served_kernel.kernel_make(), '--operator-smp', 'EXTERNAL_KERNEL_FEATURES=other'], capture_output=True)
            self.assertNotEqual(run.returncode, 0)

    def test_import_iso_remains_up_and_final_iso_has_profile(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(operator_image.subprocess, 'Popen') as run:
            process = run.return_value.__enter__.return_value
            process.stdout = io.BytesIO()
            process.wait.return_value = 0
            operator_image.kernel_iso(directory, 2, 'import', work=directory)
            self.assertNotIn('--operator-smp', run.call_args.args[0])
            operator_image.kernel_iso(directory, 0, 'sshd', options='net fsd served smp-operator=2', server='fsd', work=directory, operator_smp=True)
            args = run.call_args.args[0]
            self.assertIn('--operator-smp', args)
            self.assertIn('DURABLE_OPTIONS=net fsd served smp-operator=2', args)


if __name__ == '__main__':
    unittest.main()
