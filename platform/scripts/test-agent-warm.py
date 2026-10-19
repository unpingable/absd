#!/usr/bin/env python3
"""Finite host fixtures; no guest or compiler. Actual fixed-case Runner reused."""
import ast
import hashlib
import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch
import agent_warm as aw

here = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location('agent_exec_test', here / 'agent-exec.py')
ae = importlib.util.module_from_spec(spec); sys.modules[spec.name] = ae; spec.loader.exec_module(ae)

class Guest(ae.FakeSshd):
    def __init__(self):
        super().__init__(scale=1/60000)
        self.target = self
        self.reset_count = 0
        self.fail_reset = False
    def physical(self, path): return path
    def all_images(self): return self.active
    def system_objects(self):
        return sorted([(p, True, False, 1, ae.sha256(b'')) for p in self.dirs] +
                      [(p, False, False, 1, ae.sha256(b)) for p, b in self.files.items()])
    def census(self):
        super().census()
        self.s.append(f'FSD CAPACITY boot={self.BOOT} settled_releases={self.reclaimed} '
            f'bound=0 opens=1 draining=0 heap_pages_peak=10 fs_objects={len(self.files)+len(self.dirs)} rotated_logs=0\n')
    def behave(self, text, stdin, sid):
        if text == 'rm -r ' + aw.ROOT:
            self.reset_count += 1
            if self.fail_reset: return 1, b'', b'refused', 0
            self.files = {p:b for p,b in self.files.items() if not p.startswith(aw.ROOT+'/')}
            self.dirs.remove(aw.ROOT)
            return 0, b'', b'', 0
        if text == 'mkdir ' + aw.ROOT and aw.ROOT in self.dirs:
            return 1, b'', b'already exists', 0
        return super().behave(text, stdin, sid)

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='agent-warm-fixture-')
        self.g = Guest()
        self.r = ae.Runner(self.g, ae.load_cases(ae.DEFAULT_CASES), pathlib.Path(self.temp.name)/'measured.jsonl',out=lambda x:None)
    def tearDown(self): self.temp.cleanup()
    def adapter(self): return aw.Rehearsal(ae, self.r)
    def effects(self, a):
        self.g.dirs.add(aw.ROOT)
        self.g.files[aw.ROOT+'/in.txt'] = next(c.stdin for c in self.r.calls if c.id == 'C3b')
        a.final = a.verify_end(a.state())
    def test_actual_complete_transition_and_original_outcomes(self):
        a = self.adapter(); result = a.run(); self.assertTrue(result[1])
        self.assertEqual(self.g.reset_count,2)
        self.assertEqual(a.state(),a.final)
        for path in [self.r.receipts] + sorted(pathlib.Path(self.temp.name).glob('*.rehearsal-*')):
            rows = [__import__('json').loads(x) for x in path.read_text().splitlines()]
            cases={x['id']:x for x in rows if 'id' in x}
            self.assertEqual(cases['C8']['status'],'cancelled')
            self.assertEqual(cases['C10']['status'],'refused-host')
            self.assertEqual(cases['C11']['sessions'],4)
            self.assertFalse(any(x.get('checks_failed') for x in cases.values()))
        self.assertNotIn('reboot',self.g.sent)
    def test_candidate_two_includes_real_compile_case_contract(self):
        self.r.candidate = 2
        a = self.adapter(); self.assertTrue(a.run()[1])
        self.assertIn('C12b', a.shapes)
        self.assertIn(aw.ROOT + '/t', self.g.files)
    def test_missing_cancel_evidence_fails_original_checks(self):
        c=next(c for c in self.r.calls if c.id=='C8')
        r=self.r.call(c);r['lines']['kernel_ended']=[]
        self.assertTrue(any('USER KILLED' in x for x in self.r.check(c,r)))
    def test_concurrency_missing_refusal_fails_original_checks(self):
        c=next(c for c in self.r.calls if c.id=='C11')
        r=self.r.call(c);r['lines']['conn_refused']=[]
        self.assertTrue(any('REFUSED' in x for x in self.r.check(c,r)))
    def test_rehearsal_content_change_cannot_establish_plateau(self):
        self.r.candidate=2
        a=self.adapter()
        self.g.dirs.add(aw.ROOT)
        self.g.files[aw.ROOT+'/in.txt']=next(c.stdin for c in self.r.calls if c.id=='C3b')
        # Complete canonical C12 inventory; controlled fake Runner changes only
        # the compiler output on the next group. Same object count is insufficient.
        self.g.files[aw.ROOT+'/t.c']=next(c.stdin for c in self.r.calls if c.id=='C12a')
        self.g.files[aw.ROOT+'/t']=b'old ELF'
        a.final=a.verify_end(a.state())
        old=dict(a.final)
        def run_changed(r):
            self.g.dirs.add(aw.ROOT)
            self.g.files[aw.ROOT+'/in.txt']=next(c.stdin for c in self.r.calls if c.id=='C3b')
            self.g.files[aw.ROOT+'/t.c']=next(c.stdin for c in self.r.calls if c.id=='C12a')
            self.g.files[aw.ROOT+'/t']=b'new ELF'
            return 'controlled',True
        with patch.object(ae.Runner,'run',run_changed):
            with self.assertRaisesRegex(aw.wb.BaselineError,'logical end state changed'):a.group(2)
        self.assertEqual(a.final,old)
    def test_subset_or_changed_case_refuses(self):
        self.r.calls=self.r.calls[:-1]
        with self.assertRaises(aw.wb.BaselineError):self.adapter()
    def test_initial_generated_tree_refuses(self):
        self.g.dirs.add(aw.ROOT)
        with self.assertRaises(aw.wb.BaselineError):self.adapter()
    def test_unrelated_effect_refuses_before_delete(self):
        a=self.adapter();self.effects(a);self.g.files['/etc/unrelated']=b'x'
        with self.assertRaises(aw.wb.BaselineError):a.reset()
        self.assertEqual(self.g.reset_count,0)
    def test_unknown_child_refuses_before_delete(self):
        a=self.adapter();self.effects(a);self.g.files[aw.ROOT+'/unknown']=b'x'
        with self.assertRaises(aw.wb.BaselineError):a.reset()
        self.assertEqual(self.g.reset_count,0)
    def test_input_content_mutation_refuses(self):
        a=self.adapter();self.effects(a);self.g.files[aw.ROOT+'/in.txt']=b'changed'
        with self.assertRaises(aw.wb.BaselineError):a.verify_end(a.state())
    def test_initial_file_mutation_refuses(self):
        a=self.adapter();self.effects(a);self.g.files['/share/man/whatis']=b'changed'
        with self.assertRaises(aw.wb.BaselineError):a.verify_end(a.state())
    def test_reset_failure_retains_old_state(self):
        a=self.adapter();self.effects(a);self.g.fail_reset=True
        with self.assertRaises(aw.wb.BaselineError):a.reset()
        self.assertIn(aw.ROOT,self.g.dirs)
    def test_reset_kind_substitution_refuses(self):
        a=self.adapter();self.effects(a);self.g.dirs.add(aw.ROOT+'/in.txt');del self.g.files[aw.ROOT+'/in.txt']
        with self.assertRaises(aw.wb.BaselineError):a.verify_end(a.state())
    def test_stale_or_new_boot_sample_refuses(self):
        a=self.adapter();a.expected_reclaimed+=1
        with patch.object(aw.time,'monotonic',side_effect=[0,0,61]),patch.object(aw.time,'sleep'):
            with self.assertRaises(aw.wb.BaselineError):a.sample()
        a.expected_reclaimed-=1
        self.g.BOOT='f'*32;self.g.census()
        with patch.object(aw.time,'monotonic',side_effect=[0,0,61]),patch.object(aw.time,'sleep'):
            with self.assertRaises(aw.wb.BaselineError):a.sample()
    def test_measured_frame_and_rest_drift_refuse(self):
        a=self.adapter(); cold=a.sample();a.warm.baseline=a.warm.last=cold
        import copy
        changed=copy.deepcopy(cold);changed[0]['accepted_reclaimed']+=1;changed[1]['settled_releases']+=1
        changed[0]['frames']+=6;changed[0]['heap_pages_peak']+=6
        with self.assertRaises(aw.wb.BaselineError):a.warm.measured_group(changed)
    def test_original_core_methods_are_pinned_unchanged(self):
        import subprocess
        old=subprocess.check_output(['git','show','aa70b94c3721ac97f202d157a3fb7e34d832812a:scripts/agent-exec.py'],cwd=here)
        def methods(data):
            klass=next(x for x in ast.parse(data).body if isinstance(x,ast.ClassDef) and x.name=='Runner')
            return {x.name:ast.dump(x,include_attributes=False) for x in klass.body if isinstance(x,ast.FunctionDef)}
        self.assertEqual(methods(old),methods((here/'agent-exec.py').read_bytes()))

if __name__=='__main__':unittest.main()
