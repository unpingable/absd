"""Host-only boot admission controls. No QEMU process is launched."""
import importlib.util
import json
import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('boot_artifacts', Path(__file__).with_name('boot_artifacts.py'))
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)


class Admission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='absd-binding-controls-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.iso = self.root / 'operator.iso'
        self.disk = self.root / 'target.raw'
        self.exe = self.root / 'qemu'
        self.iso.write_bytes(b'actual ISO fixture\0' * 47)
        self.disk.write_bytes(b'actual disk fixture\0' * 53)
        self.exe.write_bytes(b'executable fixture')
        self.receipt = self.root / 'admission.json'
        self.command = [str(self.exe), '-cdrom', str(self.iso), '-drive',
                        f'file={self.disk},format=raw,if=ide,index=0', '-display', 'none']
        self.expected = dict(iso_sha256=binding.sha(self.iso), disk_sha256=binding.sha(self.disk),
                             qemu_sha256=binding.sha(self.exe), record_path=self.receipt)
        self.events = []
        self.process = None

    def launch(self, defect=None, command=None, **overrides):
        outer = self
        real_sha = binding.sha
        real_read = Path.read_bytes
        real_stat = Path.stat
        class Process:
            pid = os.getpid()
            killed = False
            def poll(self): return None
            def kill(self): self.killed = True; outer.events.append('kill')
            def wait(self): outer.events.append('wait'); return -9
        def popen(argv, **kwargs):
            outer.events.append('popen')
            outer.actual = argv
            outer.fds = kwargs['pass_fds']
            # Real descriptors must reference the sealed ISO copy and original disk inode.
            self.assertEqual(real_sha(f'/proc/self/fd/{outer.fds[0]}'), outer.expected['iso_sha256'])
            self.assertEqual(os.fstat(outer.fds[1]).st_ino, self.disk.stat().st_ino)
            with self.assertRaises(OSError) as sealed_error:
                os.write(outer.fds[0], b'change sealed ISO')
            self.assertEqual(sealed_error.exception.errno, errno.EPERM)
            if defect == 'disk-content': self.disk.write_bytes(b'changed after launch')
            if defect == 'pathname-replaced':
                self.disk.rename(self.root / 'original-disk')
                self.disk.write_bytes(b'different pathname replacement')
            outer.process = Process()
            return outer.process
        class QMP:
            def __init__(self, *args): pass
            def execute(self, name):
                outer.events.append(name)
                if name == 'query-status':
                    return {'running': defect == 'running', 'status': 'paused'}
                if name == 'query-block':
                    iso, disk = (f'/proc/self/fd/{fd}' for fd in outer.fds)
                    if defect == 'qmp-map': disk = str(outer.disk)
                    return [{'inserted': {'file': iso}}, {'inserted': {'file': disk}}]
                if name == 'cont':
                    record = json.loads(outer.receipt.read_text())
                    outer.assertTrue(record['admitted'])
                    outer.assertEqual(set(record['opened_inputs']), {'iso', 'disk'})
                    return {}
            def close(self): outer.events.append('close')
        def read(path):
            if path == Path(f'/proc/{os.getpid()}/cmdline'):
                argv = list(outer.actual)
                if defect == 'argv': argv[0] = '/different/executable'
                return b'\0'.join(os.fsencode(x) for x in argv) + b'\0'
            return real_read(path)
        def sha(path):
            if Path(path) == Path(f'/proc/{os.getpid()}/exe'):
                return 'wrong-executable-digest' if defect == 'exe' else real_sha(outer.exe)
            return real_sha(path)
        def stat(path, *args, **kwargs):
            if defect == 'opened-inode' and hasattr(outer, 'fds') and path == Path(f'/proc/{os.getpid()}/fd/{outer.fds[1]}'):
                return real_stat(outer.iso)
            return real_stat(path, *args, **kwargs)
        with patch.object(binding.subprocess, 'Popen', popen), patch.object(binding, 'QMP', QMP), \
                patch.object(binding, 'sha', sha), patch.object(Path, 'read_bytes', read), patch.object(Path, 'stat', stat):
            return binding.launch(command or self.command, **(self.expected | overrides))

    def refused(self, defect=None, **kwargs):
        with self.assertRaises(binding.Refused): self.launch(defect, **kwargs)
        self.assertNotIn('cont', self.events)
        if self.process:
            self.assertTrue(self.process.killed)
            self.assertIn('wait', self.events)
        if self.receipt.exists(): self.assertFalse(json.loads(self.receipt.read_text())['admitted'])

    def test_positive_admits_before_cont(self):
        process = self.launch()
        self.assertIs(process, self.process)
        self.assertEqual(self.events[:4], ['popen', 'query-status', 'query-block', 'cont'])
        record = json.loads(self.receipt.read_text())
        self.assertEqual(record['opened_inputs']['disk']['inode'], self.disk.stat().st_ino)
        self.assertEqual(record['opened_inputs']['iso']['sha256'], self.expected['iso_sha256'])
        for fd in self.fds:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_canonical_durable_pair_preserved(self):
        self.launch(command=self.command + ['-no-reboot','-no-shutdown'])
        self.assertIn('-no-reboot',self.actual)
        self.assertIn('-no-shutdown',self.actual)
        self.assertIn('cont',self.events)

    def test_incomplete_or_duplicate_durable_flags_refused(self):
        for flags in (['-no-shutdown'],['-no-reboot','-no-shutdown','-no-shutdown']):
            with self.subTest(flags=flags):
                self.refused(command=self.command+flags)
        self.assertNotIn('popen',self.events)

    def test_wrong_iso(self):
        self.iso.write_bytes(b'wrong ISO before launch')
        self.refused()
        self.assertNotIn('popen', self.events)

    def test_wrong_disk(self):
        self.disk.write_bytes(b'wrong disk before launch')
        self.refused()
        self.assertNotIn('popen', self.events)

    def test_wrong_qemu(self):
        self.exe.write_bytes(b'wrong QEMU executable')
        self.refused()
        self.assertNotIn('popen', self.events)

    def test_alternative_sources(self):
        for option in (['-kernel', '/kernel'], ['-readconfig', '/config'],
                       ['-drive', 'file=/other,format=raw,if=ide,index=0'], ['-cdrom', '/other.iso']):
            with self.subTest(option=option):
                self.refused(command=self.command + option)
        self.assertNotIn('popen', self.events)

    def test_actual_argv(self): self.refused('argv')
    def test_actual_executable(self): self.refused('exe')
    def test_qmp_mapping(self): self.refused('qmp-map')
    def test_opened_inode(self): self.refused('opened-inode')
    def test_disk_changed_before_cont(self): self.refused('disk-content')
    def test_running_before_admission(self): self.refused('running')

    def test_pathname_replacement_preserves_opened_disk(self):
        self.launch('pathname-replaced')
        record = json.loads(self.receipt.read_text())
        self.assertEqual(record['opened_inputs']['disk']['inode'], (self.root / 'original-disk').stat().st_ino)
        self.assertNotEqual(record['opened_inputs']['disk']['inode'], self.disk.stat().st_ino)
        self.assertIn('cont', self.events)

    def test_existing_receipt_is_preserved(self):
        self.receipt.write_text('existing evidence')
        with self.assertRaises(FileExistsError): self.launch()
        self.assertEqual(self.receipt.read_text(), 'existing evidence')
        self.assertNotIn('popen', self.events)


if __name__ == '__main__':
    unittest.main()
