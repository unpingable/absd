#!/usr/bin/env python3
"""Host-only R23 state and C-kit shape controls; no guest or compiler."""
import copy
import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
import warm_baseline as w


def sample(n=0, frames=100, heap=10):
    a = dict.fromkeys(w.SSH_FIELDS, 0)
    a.update(boot='a'*32, accepted_reclaimed=n, frames=frames, heap_pages_peak=heap)
    b = dict.fromkeys(w.FSD_FIELDS, 0)
    b.update(boot='a'*32, settled_releases=n, fs_objects=10, rotated_logs=0, heap_pages_peak=10)
    return a,b


class Plateau(unittest.TestCase):
    def baseline(self, samples):
        events=[]
        b=w.WarmBaseline(sample(), ['a','b'], events.append)
        it=iter(samples)
        b.establish(lambda _: ['a','b'], lambda: next(it))
        return b,events

    def test_two_or_three(self):
        b,e=self.baseline([sample(1,102,12),sample(2,102,12)])
        self.assertEqual(e[-1]['groups'],2)
        b,e=self.baseline([sample(1,101,11),sample(2,102,12),sample(3,102,12)])
        self.assertEqual(e[-1]['groups'],3)
        self.assertEqual(e[-1]['cold_to_warm'],dict(ssh_heap=2,fsd_heap=0,rest=0))
        with self.assertRaises(w.BaselineError): b.establish(lambda _:[],lambda:sample())

    def test_third_unequal_no_fallback(self):
        with self.assertRaisesRegex(w.BaselineError,'three'):
            self.baseline([sample(1,101,11),sample(2,102,12),sample(3,103,13)])

    def test_every_field_and_boot_and_freshness(self):
        for side,keys in ((0,w.SSH_FIELDS),(1,w.FSD_FIELDS+('fs_objects',))):
            for key in keys:
                samples=[sample(1),sample(2),sample(3)]
                for n,s in enumerate(samples): s[side][key]+=n+1
                with self.subTest(side=side,key=key),self.assertRaises(w.BaselineError):
                    self.baseline(samples)
        for side,key,value in ((0,'boot','b'*32),(1,'boot','b'*32),(0,'accepted_reclaimed',0),(1,'settled_releases',0)):
            s=sample(1);s[side][key]=value
            with self.subTest(key=key),self.assertRaises(w.BaselineError): self.baseline([s,s])

    def test_missing_shape(self):
        b=w.WarmBaseline(sample(),['a','b'],lambda _:None)
        with self.assertRaisesRegex(w.BaselineError,'shape'):
            b.establish(lambda _:['a'],lambda:sample(1))

    def test_cumulative_and_exact_repeat(self):
        b,_=self.baseline([sample(1),sample(2)])
        b.measured_group(sample(3,105,15))
        with self.assertRaises(w.BaselineError): b.measured_group(sample(4,106,16))
        b,_=self.baseline([sample(1),sample(2)])
        b.measured_group(sample(3,101,11))
        with self.assertRaisesRegex(w.BaselineError,'flat'): b.measured_group(sample(4,102,12))
        b,_=self.baseline([sample(1),sample(2)])
        with self.assertRaisesRegex(w.BaselineError,'residual'): b.measured_group(sample(3,101,10))

    def test_latest_malformed_and_normalized_logs(self):
        self.assertIsNone(w.latest_capacity('SERVED CAPACITY boot=a\nSERVED CAPACITY invalid','SERVED CAPACITY'))
        self.assertIsNone(w.latest_capacity('SERVED CAPACITY x=1 x=2','SERVED CAPACITY'))
        a,b=sample(1),sample(2); b[1].update(fs_objects=12,rotated_logs=2)
        self.assertEqual(w.fingerprint(a),w.fingerprint(b))
        del b[0]['cells']
        with self.assertRaises(w.BaselineError): w.fingerprint(b)

    def test_large_cold_growth_is_reported(self):
        _,e=self.baseline([sample(1,107),sample(2,107)])
        self.assertTrue(e[-1]['owner_report_required'])


class Consumer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('ckit', pathlib.Path(__file__).with_name('c-kit-matrix.py'))
        cls.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.m)

    def test_real_ordered_group(self):
        import tempfile
        import types
        with tempfile.TemporaryDirectory() as tmp:
            cwd=pathlib.Path(tmp)
            x=self.m.KitMatrix.__new__(self.m.KitMatrix)
            x.cases=[('shell','stdio','-','write'),('native','cat','-','c-stdio.dat'),('shell','stdio','-','verify')]
            x.vectors=cwd
            x.t=types.SimpleNamespace(system_objects=lambda: [])
            calls=[]
            x.check=lambda name,ok,*args:self.assertTrue(ok,name)
            x.probe_shell=lambda: calls.append('probe') or {}
            def run(route,program,stdin,args,env,where):
                calls.append(program+':'+args[0])
                file=where/'c-stdio.dat'
                if args==['write']: file.write_bytes(b'fixture')
                if program=='cat': self.assertEqual(file.read_bytes(),b'fixture')
                if args==['verify']: file.unlink()
                return self.m.case_key(program,stdin,args),(0,b'',b''),(0,b'',b''),[1]
            x.run_case=run
            x.quiescent=lambda:None
            x.check_stdio_file=lambda *args:None
            x.judge=lambda *args:calls.append('judge')
            x.live_frames=lambda label,words,**kw:self.assertTrue(kw.get('rehearsal'))
            x.run_vectors=lambda env:[]
            x.alive=lambda label:calls.append('alive')
            for n in (1,2): self.assertEqual(x.rehearse(n,cwd),x.warm_shapes())
            self.assertEqual(calls.count('judge'),6)
            self.assertEqual(calls.count('alive'),2)
            # A semantic refusal remains a refusal, never a plateau sample.
            x.judge=lambda *args: (_ for _ in ()).throw(self.m.sm.Failed('semantic fixture'))
            with self.assertRaises(self.m.sm.Failed): x.rehearse(3,cwd)

    def test_pin_authoring_does_not_claim_warm_qualification(self):
        import tempfile
        import types
        with tempfile.TemporaryDirectory() as tmp:
            x=self.m.KitMatrix.__new__(self.m.KitMatrix)
            x.work=pathlib.Path(tmp); x.op=x.work/'key'; x.op.with_suffix('.pub').write_text('fixture')
            x.t=types.SimpleNamespace(setup=lambda *a:None,start=lambda **k:{'public':'fixture'},port=1,stop=lambda:None)
            x.pin=['hello'];x.cases=[]
            x.probe_shell=lambda:{};x.run_vectors=lambda e:[];x.alive=lambda _:None
            seen=[]
            x.live_frames=lambda label,words,**kw:seen.append((label,kw)) or (0,0)
            x.warm_capacity=lambda: self.fail('pin authoring must not establish warm baseline')
            with patch.object(self.m.sm,'Client',return_value=types.SimpleNamespace(trust=lambda _:None)):
                x.run()
            self.assertEqual(seen[0],('warmup',{'warmup':True}))

    def test_exact_resource_check_not_relaxed(self):
        x=self.m.KitMatrix.__new__(self.m.KitMatrix)
        x.check=lambda name,ok,*args:self.assertTrue(ok,name)
        a=dict(images=0,memory='frames=100',kernel='handles=0',objects=[])
        b=dict(a,memory='frames=101')
        with self.assertRaises(AssertionError): x.compare_census('hello',a,b)

if __name__=='__main__': unittest.main()
