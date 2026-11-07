#!/usr/bin/env python3
"""Exact writable profiles and real sparse geometry; no QEMU or resize tool."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import absd_fs
import storage_fence_resume as resume
import storage_fence_state as guard
import test_storage_fence_resume as fixture

DEFAULT = 128 << 20
LARGE = 2 << 30


class GeometryResume(unittest.TestCase):
    def sparse(self, path, size):
        with path.open('wb') as stream:
            stream.truncate(size)
        self.assertLessEqual(path.stat().st_blocks * 512, 512 << 20)

    def build(self, path, size):
        sectors = size // 512
        # Only the established sparse fixture's creation geometry is patched.
        # Reader/open/identity/classification code is always the real module.
        with patch.multiple(fixture, DEVICE_SECTORS=sectors, FS_FIRST=sectors//2,
                            FS_SECTORS=sectors-sectors//2), \
             patch.object(fixture.sfr, 'IMAGE_BYTES', size):
            fixture.build_image(path, fixture.machine_files())
        self.assertEqual(path.stat().st_size, size)
        self.assertLessEqual(path.stat().st_blocks * 512, 512 << 20)

    def test_supported_sizes_have_matching_open_and_path_identity(self):
        self.assertEqual(resume.IMAGE_BYTES, DEFAULT)
        self.assertEqual(resume.DEVICE_SECTORS * 512, DEFAULT)
        for size in (DEFAULT, LARGE):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / resume.IMAGE
                self.sparse(path, size)
                fd, identity = resume.open_image(path)
                try:
                    st = os.fstat(fd)
                    self.assertEqual(identity, (st.st_dev, st.st_ino, size))
                    self.assertEqual(resume.identity_of(path), identity)
                finally:
                    os.close(fd)

    def test_other_sizes_are_not_writable_or_classified_as_owned(self):
        for size in (0, 64 << 20, DEFAULT-512, DEFAULT+512, 1 << 30,
                     LARGE-512, LARGE+512):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / resume.IMAGE
                self.sparse(path, size)
                self.assertIsNone(resume.identity_of(path))
                with self.assertRaises(resume.Refused) as error:
                    resume.open_image(path)
                self.assertEqual(error.exception.reason, 'image_size')

    def test_large_actual_layout_filesystem_and_recovery_state_validate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / resume.IMAGE
            self.build(path, LARGE)
            region = absd_fs.fs_region(path, resume.image_sectors(path))
            self.assertEqual((region.first*512, region.sectors*512), (1 << 30, 1 << 30))
            base = region.first * 512
            del region  # Release the whole-image capture before the next read.
            disk = resume.read_disk(path)
            self.assertEqual((disk['fs_id'], disk['seq'], disk['selected']), (7, 11, 'rel-a'))
            self.assertEqual((disk['guard'], disk['slot']['parsed']), ('dirty', 'none'))
            state = resume.recovery_state(disk['files'], disk['guard'])
            self.assertEqual((state['previous'], state['ledger']['seq']), ('failed', 3))
            self.assertEqual(disk['files']['/home/operator/big'], bytes(5000))
            fd, identity = resume.open_image(path)
            os.close(fd)
            self.assertEqual(resume.identity_of(path), identity)
            # Admission by size must not bypass either superblock's validity.
            with path.open('r+b') as stream:
                for slot in (0, 1):
                    stream.seek(base + slot * 512)
                    stream.write(b'NOTABSD!')
            with self.assertRaises(resume.Refused) as error:
                resume.read_disk(path)
            self.assertEqual(error.exception.reason, 'host_reader_refused')

    def test_padded_default_descriptor_is_not_a_large_profile_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / resume.IMAGE
            self.build(path, DEFAULT)
            with path.open('r+b') as stream:
                stream.truncate(LARGE)
            fd, identity = resume.open_image(path)
            os.close(fd)
            self.assertEqual(resume.identity_of(path), identity)
            with self.assertRaisesRegex(ValueError, 'layout descriptor invalid'):
                resume.read_disk(path)

    def test_size_change_does_not_revive_old_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / resume.IMAGE
            self.sparse(path, DEFAULT)
            old = resume.identity_of(path)
            with path.open('r+b') as stream:
                stream.truncate(LARGE)
            current = resume.identity_of(path)
            self.assertIsNotNone(current)
            self.assertEqual(current[:2], old[:2])
            sector = guard.encode_resume({'id':'a'*32, 'fs':7, 'seq':11, 'image':'0'*64,
                'ledger_seq':3, 'ledger_boot':fixture.BOOT0, 'previous':'failed', 'time':1761100000})
            active = {'id':'a'*32, 'f':list(old), 'hm':'0'*64,
                      'planned':sector.hex(), 'state':'authorized'}
            # Isolate the size member of F in the existing decision table;
            # unchanged planned bytes and Hm cannot authorize another size.
            probe = {'f':current, 'slot':('record',sector,guard.parse_resume(sector)), 'hm':'0'*64,
                     'records':{'unparsable':[], 'active':active, 'intents':{}, 'archives':[]}}
            decision = resume.classify(probe)
            self.assertEqual(decision.row, 9)
            self.assertFalse(decision.launch)
            self.assertEqual(decision.reason, 'recovery_image_changed (F)')

    def test_large_profile_preserves_file_identity_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / resume.IMAGE
            self.sparse(path, LARGE)
            link = Path(directory) / 'symbolic.img'
            link.symlink_to(path)
            self.assertIsNone(resume.identity_of(link))
            with self.assertRaises(resume.Refused) as error:
                resume.open_image(link)
            self.assertEqual(error.exception.reason, 'image_not_regular')
            link.unlink()
            os.link(path, link)
            self.assertIsNone(resume.identity_of(path))
            with self.assertRaises(resume.Refused) as error:
                resume.open_image(path)
            self.assertEqual(error.exception.reason, 'image_linked')
            link.unlink()
            with patch.object(resume, 'fs_type', return_value=0x6969):
                with self.assertRaises(resume.Refused) as error:
                    resume.open_image(path)
            self.assertEqual(error.exception.reason, 'image_not_local')


if __name__ == '__main__':
    unittest.main()
