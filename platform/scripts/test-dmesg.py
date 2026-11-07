#!/usr/bin/env python3
"""Compile the real dmesg against deterministic transport; never launch a VM."""
import os
import selectors
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parent.parent
class Dmesg(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='absd-dmesg-')
        out=Path(cls.temp.name)
        env=dict(os.environ,RUSTC_BOOTSTRAP='1')
        subprocess.run(['rustc','--edition=2024','--crate-name','absd_runtime','--crate-type','rlib',str(ROOT/'tests/fixtures/kernel_log_mock_runtime.rs'),'-o',str(out/'libabsd_runtime.rlib')],check=True,env=env)
        cls.exe=out/'dmesg'
        subprocess.run(['rustc','--edition=2024',str(ROOT/'src/bin/dmesg.rs'),'--extern',f'absd_runtime={out}/libabsd_runtime.rlib','-o',str(cls.exe)],check=True,env=env)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def run_cmd(self,*args,**env):return subprocess.run([str(self.exe),*args],capture_output=True,env=dict(os.environ,**env),timeout=5)
    def test_snapshot_and_hostile_text(self):
        r=self.run_cmd();self.assertEqual(r.returncode,0);self.assertIn(b'early marker',r.stdout)
        self.assertIn(b'bad\\x1b[2J\\x0atext',r.stdout);self.assertNotIn(b'\x1b',r.stdout)
        self.assertEqual(len(r.stdout.splitlines()),3)
    def test_filters_and_since(self):
        r=self.run_cmd('--level','warn');self.assertEqual(r.returncode,0);self.assertNotIn(b'early marker',r.stdout);self.assertIn(b'bad',r.stdout)
        r=self.run_cmd('--source','nic');self.assertIn(b'early marker',r.stdout);self.assertNotIn(b'bad',r.stdout)
        r=self.run_cmd('--since','2');self.assertNotIn(b'early marker',r.stdout);self.assertIn(b'bad',r.stdout)
    def test_denied_and_clear_options(self):
        self.assertEqual(self.run_cmd(LOG_MOCK_DENIED='1').returncode,1)
        self.assertEqual(self.run_cmd('--clear').returncode,2)
        self.assertEqual(self.run_cmd('--level','bogus').returncode,2)
    def test_snapshot_freezes_first_end_while_later_records_arrive(self):
        r=self.run_cmd(LOG_MOCK_SCENARIO='growth')
        self.assertEqual(r.returncode,0);self.assertIn(b'early marker',r.stdout);self.assertIn(b'bad',r.stdout)
        self.assertNotIn(b'later carrier up',r.stdout)
    def test_wrap_gap_producer_drops_and_inferred_flags_are_visible(self):
        r=self.run_cmd(LOG_MOCK_SCENARIO='loss')
        self.assertEqual(r.returncode,0)
        for notice in [b'history begins at sequence 20',b'lost 1 overwritten records',b'producer contention drops=1',b'producer contention drops=3',b'inferred damaged',b'after gap']:
            self.assertIn(notice,r.stdout)
        self.assertNotIn(b'later carrier up',r.stdout)
    def test_follow_observes_later_record(self):
        process=subprocess.Popen([str(self.exe),'--follow'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=dict(os.environ,LOG_MOCK_FOLLOW='1'))
        try:
            selector=selectors.DefaultSelector()
            selector.register(process.stdout,selectors.EVENT_READ)
            data=b''
            for _ in range(8):
                self.assertTrue(selector.select(2),'follow did not produce a later record')
                data+=os.read(process.stdout.fileno(),4096)
                if b'later carrier up' in data:break
            selector.close()
            self.assertIn(b'later carrier up',data)
        finally:
            process.terminate();process.communicate(timeout=5)
    def test_damaged_record_survives_severity_filter(self):
        r=self.run_cmd('--level','err',LOG_MOCK_SCENARIO='loss')
        self.assertEqual(r.returncode,0)
        self.assertIn(b'inferred damaged',r.stdout)
if __name__=='__main__':unittest.main()
