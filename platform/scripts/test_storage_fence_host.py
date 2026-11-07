#!/usr/bin/env python3
"""Real guard sectors and host syscalls; filesystem-only layout fixture."""
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import absd_fs
import storage_fence_host as host
import storage_fence_state as guard
import operator_image

spec = importlib.util.spec_from_file_location('fs_vectors', Path(__file__).with_name('test_absd_fs.py'))
vectors = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vectors)


def image(path, state='clean'):
    data = vectors.load('format2.sectors')
    raw = vectors.selected_raw(data)[:64]
    struct.pack_into('<Q', raw, 32, 4)
    struct.pack_into('<I', raw, 44, 3)
    for serial, parent, name, directory, blocks in ((1, 0, b'', True, []),
            (2, 1, b'var', True, []), (3, 2, b'recovery.guard', False, [0])):
        raw += struct.pack('<QQQBBHIQ', serial, parent, 0 if directory else 512,
                           2 if directory else 1, 0, len(name), len(blocks), 0)
        raw += name + b''.join(struct.pack('<I', b) for b in blocks)
    vectors.resign(data, raw)
    geo = absd_fs.geometry(len(data)//512)
    offset = geo['data_first'] * 512
    data[offset:offset+512] = guard.encode(state)
    path.write_bytes(data)
    return offset


class HostMutation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'disk.img'
        self.offset = image(self.path)
        # The fixture is a whole filesystem region. Only the unchanged
        # outer device-layout lookup is substituted; decode/select and
        # the marker's mapping/content checks are real.
        self.region = patch.object(absd_fs, 'fs_region',
            lambda path, _: absd_fs.Region(path, 0, Path(path).stat().st_size//512))
        self.region.start(); self.addCleanup(self.region.stop)

    def test_success_restores_original_marker_last_without_metadata_changes(self):
        for state in ('fresh', 'clean'):
            image(self.path, state)
            before = self.path.read_bytes()
            with host.mutation(self.path):
                self.assertEqual(host.marker(self.path)[1], guard.encode('dirty'))
            self.assertEqual(self.path.read_bytes(), before)

    def test_failed_writer_stays_dirty_and_retry_issues_no_write(self):
        with self.assertRaisesRegex(RuntimeError, 'import failed'):
            with host.mutation(self.path):
                with self.path.open('r+b') as handle:
                    handle.seek(self.offset+512); handle.write(b'update')
                raise RuntimeError('import failed')
        self.assertEqual(host.marker(self.path)[1], guard.encode('dirty'))
        with patch.object(os, 'pwrite') as write:
            with self.assertRaisesRegex(ValueError, 'unclean'):
                with host.mutation(self.path):self.fail('dirty image admitted')
            write.assert_not_called()

    def test_failed_arming_write_or_flush_never_enters_writer(self):
        for operation in ('pwrite', 'fsync'):
            image(self.path)
            with patch.object(os, operation, side_effect=OSError('failed '+operation)):
                with self.assertRaises(OSError):
                    with host.mutation(self.path):self.fail('failed arm admitted writer')

    def test_interruption_at_each_flush_or_restore_write_is_conservative(self):
        for operation, count in (('fsync', 3), ('pwrite', 2)):
            original = getattr(os, operation)
            for stop in range(1, count+1):
                image(self.path)
                calls = []
                def fail(*args):
                    calls.append(args)
                    if len(calls) == stop:raise OSError('interrupted')
                    return original(*args)
                with patch.object(os, operation, side_effect=fail):
                    with self.assertRaises(OSError):
                        with host.mutation(self.path):pass
                self.assertIn(guard.parse(host.marker(self.path)[1]), ('clean', 'dirty'))

    def test_marker_replacement_and_invalid_seed_refuse(self):
        with self.assertRaisesRegex(ValueError, 'pathname'):
            with host.mutation(self.path):
                other=self.path.with_name('other.img');image(other);other.replace(self.path)
        for bytes_ in (bytes(512), b'invalid'.ljust(512,b'\0')):
            image(self.path)
            with self.path.open('r+b') as f:f.seek(self.offset);f.write(bytes_)
            with self.assertRaises(ValueError):
                with host.mutation(self.path):self.fail('invalid seed admitted')

    def test_operator_import_failure_leaves_dirty_and_blocks_retry(self):
        def failing(*args):
            self.assertEqual(host.marker(self.path)[1], guard.encode('dirty'))
            raise operator_image.Failed('import failed')
        with patch.object(operator_image, '_import_boots', side_effect=failing) as importing:
            with self.assertRaisesRegex(operator_image.Failed, 'import failed'):
                operator_image.import_boots(self.path, self.path, [], self.temp.name)
            with self.assertRaisesRegex(operator_image.Failed, 'unclean'):
                operator_image.import_boots(self.path, self.path, [], self.temp.name)
            self.assertEqual(importing.call_count, 1)

    def test_release_importer_shared_by_stage_and_cached_rollback_stays_dirty(self):
        spec = importlib.util.spec_from_file_location('release_for_guard', Path(__file__).with_name('release.py'))
        release = importlib.util.module_from_spec(spec);spec.loader.exec_module(release)
        for step in (1, 3, 4, 5):
            image(self.path)
            def failed(*args):
                self.assertEqual(host.marker(self.path)[1], guard.encode('dirty'))
                raise OSError('import failed')
            with patch.object(release, 'run_boot', side_effect=failed) as importing:
                with self.assertRaisesRegex(release.ImportFailed, 'import failed'):
                    release.importer_boot(self.path, self.path, self.path, self.temp.name,
                                          1, 1, step, [], lambda _:None)
                with self.assertRaisesRegex(release.Failed, 'unclean'):
                    release.importer_boot(self.path, self.path, self.path, self.temp.name,
                                          1, 1, step, [], lambda _:None)
                self.assertEqual(importing.call_count, 1)


if __name__=='__main__':unittest.main()
