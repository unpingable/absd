"""A no-op rmdir must not satisfy the real host case consumer."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('check_userland', ROOT/'scripts/check-userland.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RmdirState(unittest.TestCase):
    def test_surviving_directories_cannot_match_success_pins(self):
        for cid, args in [('rmdir-empty', ['dir']), ('rmdir-parents', ['-p','empty-tree/child'])]:
            with self.subTest(case=cid), tempfile.TemporaryDirectory() as tmp:
                m.OUT = Path(tmp)
                (m.OUT/'linux').mkdir()
                binary = m.OUT/'linux/rmdir'
                binary.write_text('#!/bin/sh\nexit 0\n')
                binary.chmod(0o755)
                got = m.run_case(cid, 'rmdir', '-', args)
                pin = (ROOT/'userland/expected'/cid).read_bytes()
                self.assertNotEqual(got, pin, 'a no-op rmdir passed the owning case consumer')
                binary.unlink()
                binary.symlink_to(shutil.which('rmdir'))
                self.assertEqual(m.run_case(cid, 'rmdir', '-', args), pin)


if __name__ == '__main__':
    unittest.main()
