"""Actual startup oracle, with guest launch mocked and optional real line publisher.

ABSD_TEST_WORKER_CONSOLE_FIXTURE points at the independently accepted kernel
host fixture. ABSD_TEST_OLD_SERVED_LOG supplies the retained failed matrix log.
Neither input is required for the ordinary source-only unit checks.
"""
from pathlib import Path
from unittest.mock import Mock, patch
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import ssh_absd

PUBLIC = 'ssh-ed25519 ' + 'A' * 68
KEY = f'SSH HOST KEY LOADED {PUBLIC} SHA256:fixture\n'
MOUNTS = '/ssh:ro,/bin:ro,/etc:ro,/var/log:rw,/var/log/journal:ro,/var/log/journal-health:ro,/var/state:ro,/var/state/facts:rw'
TAIL = 'SSH ENTROPY OK source=rdrand\nSSH LISTENING port=22\n'


def mount_line(mounts=MOUNTS, block='none'):
    return f'SSH STORAGE VIA FILE SERVER OK block={block} control={mounts} slots=18\n'


def frames(text):
    data = text.encode()
    return b''.join(f'EXTERNAL OUTPUT CHUNK offset={at:016x} data='.encode()
                    + data[at:at+96].hex().encode() + b'\n'
                    for at in range(0, len(data), 96))


class StorageOracle(unittest.TestCase):
    def start(self, serial):
        """Run start() through its real storage assertion, without a guest."""
        target = ssh_absd.AbsdTarget.__new__(ssh_absd.AbsdTarget)
        target.root = ROOT
        target.kernel = ROOT
        target.work = Path('/unused-startup-oracle')
        target.boots = 0
        target.qemu = ['qemu-system-x86_64']
        target.port = 12345
        target.image = Path('/unused-startup-oracle.img')
        target.boot_seconds = 1
        target.sshd_iso = Mock(return_value=Path('/unused-startup-oracle.iso'))
        target.system_objects = Mock(return_value=())
        target.output = lambda: ssh_absd.captured(serial)
        target.serial = lambda: 'FSD HOST KEY PRESENT \nFSD READY\n'
        target.host_public_from_image = lambda: PUBLIC
        with patch.object(ssh_absd.subprocess, 'Popen', return_value=Mock()), \
             patch.object(ssh_absd, 'end_boots_on_signal'), \
             patch.object(ssh_absd, 'wait_rx_setup'), \
             patch.object(ssh_absd, 'LIVE_BOOTS', set()):
            return target.start()

    def refuse(self, text):
        with self.assertRaisesRegex(ssh_absd.Failed, "^sshd storage is not the file server's:"):
            self.start(frames(KEY + text + TAIL))

    def test_exact_current_mounts(self):
        result = self.start(frames(KEY + mount_line() + TAIL))
        self.assertEqual(result['public'], PUBLIC)
        self.assertEqual(result['entropy'], 'ok')
        self.assertFalse(result['image_changed'])

    def test_inexact_storage_refused(self):
        stale = MOUNTS.replace('/var/log/journal:ro,/var/log/journal-health:ro,', '')
        for bad in [
            mount_line(stale),
            mount_line(block='present'),
            mount_line(MOUNTS.replace('/var/log/journal:ro', '/var/log/journal:rw')),
            mount_line(MOUNTS.replace('/var/log/journal-health:ro', '/var/log/journal-health:rw')),
            mount_line(MOUNTS.replace('/var/log/journal-health:ro,', '')),
            mount_line(MOUNTS + ',/extra:rw'),
            mount_line(MOUNTS + ',/var/log/journal:ro'),
            'diagnostic: ' + mount_line(),
            mount_line().rstrip('\n') + ' extra\n',
        ]:
            with self.subTest(record=bad):
                self.refuse(bad)

    def test_legacy_interleaving_remains_refused(self):
        line = mount_line()
        self.refuse(line[:96] + 'sshd: configuration defaults\n' + line[96:])

    def test_wrong_session_capacity_remains_refused(self):
        for slots in (0, 10, 17, 19, 118):
            with self.subTest(slots=slots):
                self.refuse(mount_line().replace('slots=18', f'slots={slots}'))

    def test_duplicate_or_conflicting_storage_records_remain_refused(self):
        self.refuse(mount_line() * 2)
        self.refuse(mount_line().replace('slots=18', 'slots=10') + mount_line())

    @unittest.skipUnless(os.environ.get('ABSD_TEST_OLD_SERVED_LOG'), 'retained historical log not supplied')
    def test_actual_old_merged_output_remains_refused(self):
        text = Path(os.environ['ABSD_TEST_OLD_SERVED_LOG']).read_text().split(
            "SERVED MATRIX FAILED: sshd storage is not the file server's:\n", 1)[1]
        # Keep the actual mount bytes and interleaving; use a fixture public
        # key because the image reader is outside this source-only test.
        text = re.sub(r'SSH HOST KEY LOADED ssh-ed25519 \S+ SHA256:\S+', KEY.rstrip('\n'), text)
        with self.assertRaisesRegex(ssh_absd.Failed, "^sshd storage is not the file server's:"):
            self.start(frames(text))

    @unittest.skipUnless(os.environ.get('ABSD_TEST_WORKER_CONSOLE_FIXTURE'), 'accepted kernel host fixture not supplied')
    def test_accepted_kernel_producer_preserves_current_record(self):
        with tempfile.TemporaryDirectory(prefix='absd-storage-line-') as directory:
            work = Path(directory)
            (work / 'key.input').write_text(KEY)
            (work / 'mount.input').write_text(mount_line() + TAIL)
            (work / 'cut.input').write_text('75\n')
            subprocess.run([os.environ['ABSD_TEST_WORKER_CONSOLE_FIXTURE'], 'observed', str(work)], check=True)
            serial = (work / 'serial.log').read_bytes()
            self.assertEqual(ssh_absd.captured(serial), KEY + mount_line() + TAIL)
            result = self.start(serial)
            self.assertEqual(result['public'], PUBLIC)
            self.assertEqual(result['entropy'], 'ok')


if __name__ == '__main__':
    unittest.main()
