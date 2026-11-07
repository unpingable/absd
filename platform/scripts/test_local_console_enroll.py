#!/usr/bin/env python3
import hashlib
import os
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('local_console_enroll', Path(__file__).with_name('local-console-enroll.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Enrollment(unittest.TestCase):
    def test_unique_random_tokens_and_owner_only_files(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            tokens = []
            for i in range(2):
                verifier, token = root / f'v{i}', root / f't{i}'
                module.enroll(verifier, token)
                raw = token.read_bytes().strip()
                self.assertEqual(len(raw), 32)
                self.assertEqual(verifier.read_bytes(), b'ABSD-LOCAL-1 operator ' + hashlib.sha256(raw).hexdigest().encode() + b'\n')
                self.assertEqual(stat.S_IMODE(token.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(verifier.stat().st_mode), 0o600)
                tokens.append(raw)
            self.assertNotEqual(tokens[0], tokens[1])
            with self.assertRaises(FileExistsError):
                module.enroll(root / 'v0', root / 't0')
            self.assertEqual((root / 't0').read_bytes().strip(), tokens[0])

    def test_private_permissions_do_not_depend_on_the_callers_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);previous=os.umask(0o777)
            try:module.enroll(root/'verifier',root/'token')
            finally:os.umask(previous)
            self.assertEqual(stat.S_IMODE((root/'token').stat().st_mode),0o600)
            self.assertEqual(stat.S_IMODE((root/'verifier').stat().st_mode),0o600)

if __name__ == '__main__':
    unittest.main()
