#!/usr/bin/env python3
"""Recording-tool controls; no compiler, download, or Picolibc build."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]


class TmpdirControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='absd-picolibc-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'platform'
        for n in ['scripts/build-picolibc.sh', 'c/picolibc/cross-absd.txt',
                  'c/picolibc/options.txt']:
            p = self.root / n
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / n, p)
        self.prefix = Path(self.temp.name) / 'picolibc'
        (self.prefix / 'dl').mkdir(parents=True)
        archive = self.prefix / 'dl/source.tar.xz'
        with tarfile.open(archive, 'w:xz') as t:
            data = b"project('recording-only', 'c')\n"
            item = tarfile.TarInfo('fixture/meson.build')
            item.size = len(data)
            t.addfile(item, io.BytesIO(data))
        h = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.root / 'c/picolibc/PIN').write_text(
            'meson\t1.9.1\tunused\nninja\t1.13.0\tunused\n'
            f'picolibc\tfixture\t{h}\thttps://invalid.invalid/source.tar.xz\n')
        self.venv = Path(self.temp.name) / 'venv'
        (self.venv / 'bin').mkdir(parents=True)
        self.exe('python3', "import os,sys\n"
                 "if len(sys.argv)>2 and sys.argv[2]=='-c':\n"
                 " print('1.9.1' if \"'meson'\" in sys.argv[3] else '1.13.0')\n"
                 "else: os.execv(sys.executable,[sys.executable,*sys.argv[1:]])\n")
        self.exe('ninja', "raise SystemExit('unexpected Ninja execution')\n")
        self.exe('meson', "import json,sys,pathlib,os\n"
                 "if sys.argv[1]=='--version': print('1.9.1');sys.exit(0)\n"
                 "pathlib.Path(os.environ['RECORD']).write_text(json.dumps(sys.argv[1:]))\n"
                 "sys.exit(77) # stop after recording setup; never compile\n")
        self.tmp = Path(self.temp.name) / 'private-tmp'
        self.tmp.mkdir()
        self.record = Path(self.temp.name) / 'setup.json'

    def exe(self, name, body):
        p = self.venv / 'bin' / name
        p.write_text('#!' + sys.executable + '\n' + body)
        p.chmod(0o755)

    def run_builder(self, tmp=None, jobs='1'):
        env = dict(os.environ, ABSD_PICOLIBC_PREFIX=str(self.prefix),
                   ABSD_PICOLIBC_VENV=str(self.venv), TMPDIR=str(tmp or self.tmp),
                   ABSD_PICOLIBC_JOBS=jobs, RECORD=str(self.record))
        return subprocess.run(['sh', str(self.root / 'scripts/build-picolibc.sh')],
                              env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=10)

    def test_private_map_reaches_meson(self):
        p = self.run_builder()
        self.assertNotEqual(p.returncode, 0)  # deliberate setup stop, not build PASS
        args = json.loads(self.record.read_text())
        self.assertEqual([a for a in args if a.startswith('--cross-file=')],
                         ['--cross-file=' + str(self.root / 'c/picolibc/cross-absd.txt'),
                          '--cross-file=' + str(self.prefix / 'tmpdir-cross.txt')])
        self.assertEqual((self.prefix / 'tmpdir-cross.txt').read_text(),
                         f"[constants]\nabsd_tmpdir = '{self.tmp}'\n")
        self.assertIn('-Dthread-local-storage=false', args)
        self.assertIn('-Dsingle-thread=true', args)
        self.assertIn('meson setup failed', p.stderr)

    def test_unsupported_paths_refuse_before_staging(self):
        for suffix in ['with space', "quote'", 'equals=', 'back\\slash', '@DIRNAME@', 'line\nbreak']:
            with self.subTest(suffix=suffix):
                bad = Path(self.temp.name) / suffix
                bad.mkdir()
                p = self.run_builder(bad)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('TMPDIR must', p.stderr)
                self.assertFalse((self.prefix / 'src').exists())
                self.assertFalse(self.record.exists())

    def test_alias_refused(self):
        alias = Path(self.temp.name) / 'alias'
        alias.symlink_to(self.tmp)
        self.assertIn('TMPDIR must', self.run_builder(alias).stderr)
        self.assertFalse(self.record.exists())

    def test_missing_or_relative_refused(self):
        for bad in [Path(self.temp.name) / 'missing', 'relative']:
            self.assertIn('TMPDIR must', self.run_builder(bad).stderr)
        self.assertFalse(self.record.exists())

    def test_jobs_refusal_preserved(self):
        self.assertIn('must be 1, 2, 3 or 4', self.run_builder(jobs='5').stderr)
        self.assertFalse(self.record.exists())

    def test_source_digest_refusal_preserved(self):
        (self.prefix / 'dl/source.tar.xz').write_bytes(b'wrong bytes')
        self.assertIn('PIN says', self.run_builder().stderr)
        self.assertFalse(self.record.exists())


if __name__ == '__main__':
    unittest.main()
