#!/usr/bin/env python3
"""Bounded host-only replay-state controls; no guest, compiler or subprocess fixtures."""
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import shlex
import sys
import tempfile
import types
import unittest
sys.dont_write_bytecode=True
import cports_warm as cw
import warm_baseline as wb
spec=importlib.util.spec_from_file_location('cports_test',pathlib.Path(__file__).with_name('cports-matrix.py'))
cp=importlib.util.module_from_spec(spec);spec.loader.exec_module(cp)

class Fake:
    def __init__(self,path):
        self.work=path;self.repo=pathlib.Path(__file__).resolve().parent.parent
        (path/'linux/excl').mkdir(parents=True)
        self.files={};self.history=[];self.fail_remove=False
        self.t=types.SimpleNamespace(boots=1,all_images=lambda:0,system_objects=self.system_objects)
        self.cases=[c for c in cp.load_cases(self.repo/'cports/cases.tsv') if c.name in cw.EXCL[:3]]
        self.first={};self.a17={'denied':None};self.a17_printed=False;self.steps=0;self.speedtest_limit=False
        self.n=0;self.pin=set()
    def system_objects(self):return [(p,False,False,7,hashlib.sha256(v).hexdigest()) for p,v in sorted(self.files.items())]
    def objects(self):return {o[0]:o for o in self.system_objects()}
    def linux_dir(self,cwd):return self.work/'linux'/cwd
    def shell_ssh(self,text,**kwargs):
        _,path=shlex.split(text)
        if not self.fail_remove:self.files.pop(path,None)
        self.history.append('reset');self.n+=1
        return 0,b'',b'',0,[1]
    def check(self,label,ok,*args):
        if not ok:raise cp.sm.Failed(label)
    def session_probes(self):self.n+=1
    def frames_warmup(self, rehearsal=False):
        self.check("rehearsal explicitly selected",rehearsal);self.n+=2;self.warmed=True
    def warm_capacity(self):
        a=dict.fromkeys(wb.SSH_FIELDS,0);a.update(boot='a'*32,accepted_reclaimed=self.n,frames=100,heap_pages_peak=10)
        b=dict.fromkeys(wb.FSD_FIELDS,0);b.update(boot='a'*32,settled_releases=self.n,fs_objects=10+len(self.files),rotated_logs=0,heap_pages_peak=10)
        return a,b
    def put(self,rows):
        value=str(rows).encode();self.files['/home/operator/cports/excl/x.db']=value
        (self.linux_dir('excl')/'x.db').write_bytes(value)
    def run_shell_case(self,c):
        self.n+=1;self.history.append(c.name)
        if c.name=='sqlite.excl-setup':
            self.check('setup requires absent database','/home/operator/cports/excl/x.db' not in self.files)
            self.put(2)
        else:self.check('readonly observes two',self.files['/home/operator/cports/excl/x.db']==b'2')
        return (0,b'ok',b''),(0,b'ok',b'')
    def judge(self,c,got,ref):self.check('semantic output equal',got==ref);return 'agree'
    def check_outputs(self,c):pass
    def scenario_excl_contention(self,c):
        self.check('deny begins with two rows',self.files['/home/operator/cports/excl/x.db']==b'2')
        self.put(3);self.n+=3;self.history.append(c.name)
    def alive(self,why):self.n+=1

class Cases(unittest.TestCase):
    def fixture(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup)
        return Fake(pathlib.Path(td.name))
    def quiet(self):return contextlib.redirect_stdout(io.StringIO())
    def test_complete_boundary_and_stopping_prerequisite(self):
        m=self.fixture();r=cw.Rehearsal(m,cp)
        with self.quiet():r.establish()
        self.assertIsNotNone(r.baseline.baseline)
        self.assertFalse(m.files) # measured reset is explicit and restores setup prerequisite
        self.assertFalse((m.linux_dir('excl')/'x.db').exists())
        self.assertEqual(r.final_target['/home/operator/cports/excl/x.db'][-1],hashlib.sha256(b'3').hexdigest())
        for c in m.cases:
            if c.route=='scenario':m.scenario_excl_contention(c)
            else:m.run_shell_case(c)
        with self.quiet():r.finish()
        self.assertEqual(m.files['/home/operator/cports/excl/x.db'],b'3') # no final reset before crash
        self.assertEqual(r.events[-1]['state'],'ESTABLISHED')
        self.assertEqual(m.history.count('sqlite.excl-setup'),3)
        self.assertEqual(m.history.count('reset'),2) # cold reset empty, later + measured reset real
    def test_measured_boundary_precedes_repeat_warm_step(self):
        # Execute the actual run() boundary blocks without its boot/workloads.
        # Both the first stopping case and a non-stopping-only selection must
        # check the rehearsal baseline BEFORE D-24's independent warm repeat.
        import ast
        tree=ast.parse(pathlib.Path(cp.__file__).read_text())
        run=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='run')
        loop=next(n for n in run.body if isinstance(n,ast.For) and ast.unparse(n.iter)=='self.cases')
        stopping=[n for n in loop.body if isinstance(n,ast.If)
                  and ast.unparse(n.test).startswith('case.name in RESTART_ROUNDS and')]
        tail=run.body[run.body.index(loop)+1:]
        end=next(i for i,n in enumerate(tail) if ast.unparse(n)=='t.stop()')
        for boundary in (stopping,tail[:end]):
            for drift in (0,4):
                with self.subTest(stopping=boundary is stopping,measured_drift=drift):
                    m=self.fixture();r=cw.Rehearsal(m,cp)
                    with self.quiet():r.establish()
                    m.put(3);m.n+=10
                    sample=m.warm_capacity
                    def capacity():
                        a,b=sample();a['frames']+=drift;b['heap_pages_peak']+=drift
                        return a,b
                    m.warm_capacity=capacity
                    m.cports_warm=r;m.warm_finished=False;m.highwater=['fixture'];m.repeated=False
                    calls=[]
                    def repeat():
                        self.assertTrue(m.warm_finished)
                        self.assertEqual(r.events[-1]['state'],'ESTABLISHED')
                        calls.append('repeat')
                        # The accepted repeat warm step must not be charged to
                        # the completed measured group, nor excuse its drift.
                        a,b=sample();a['frames']+=4;b['heap_pages_peak']+=4
                        m.warm_capacity=lambda:(a,b)
                    m.repeat_round=repeat
                    code=compile(ast.Module(body=boundary,type_ignores=[]),'<run boundary>','exec')
                    scope={'self':m,'case':types.SimpleNamespace(name=next(iter(cp.RESTART_ROUNDS))),
                           'RESTART_ROUNDS':cp.RESTART_ROUNDS}
                    with self.quiet():
                        if drift:
                            with self.assertRaisesRegex(wb.BaselineError,'post-warm FSD drift: heap_pages_peak'):
                                exec(code,scope)
                            self.assertEqual(calls,[])
                        else:
                            exec(code,scope)
                            self.assertEqual(calls,['repeat'])
                            self.assertEqual(r.baseline.last[1]['heap_pages_peak'],10)

    def test_target_reset_failure_refuses(self):
        m=self.fixture();r=cw.Rehearsal(m,cp);m.put(3);m.fail_remove=True
        with self.assertRaisesRegex(wb.BaselineError,'target reset'):r.reset()
    def test_reference_reset_failure_refuses(self):
        m=self.fixture();r=cw.Rehearsal(m,cp)
        (m.linux_dir('excl')/'x.db').mkdir()
        with self.assertRaisesRegex(wb.BaselineError,'reference reset'):r.reset()
    def test_unknown_target_and_reference_effects_refuse(self):
        for side in ('target','reference'):
            with self.subTest(side=side):
                m=self.fixture();r=cw.Rehearsal(m,cp)
                if side=='target':m.files['/home/operator/cports/excl/unknown']=b'x'
                else:(m.linux_dir('excl')/'unknown').write_bytes(b'x')
                with self.assertRaisesRegex(wb.BaselineError,'not equivalent'):r.reset()
    def test_unrelated_target_effect_is_not_invisible(self):
        for path in ['/home/operator/unrelated', '/etc/unrelated']:
            m=self.fixture();r=cw.Rehearsal(m,cp);m.files[path]=b'new'
            with self.assertRaisesRegex(wb.BaselineError,'not equivalent'):r.reset()
    def test_actual_cold_concurrency_allows_growth_but_measured_refuses(self):
        def make(changed_kernel=False):
            m=cp.CportsMatrix.__new__(cp.CportsMatrix)
            m.steps=0
            before=dict(images=0,kernel='handles=0',objects=[],fsd=10,memory='(1 + 100 frames of 4096 bytes)')
            after=dict(before,memory='(1 + 120 frames of 4096 bytes)',kernel='handles=1' if changed_kernel else 'handles=0')
            reads=iter([before,after]);m.stable=lambda *args:next(reads)
            m.rest_kernel=lambda *args:None;m.rest_opens=lambda *args:None
            m.t=types.SimpleNamespace(spawn_count=lambda:0,await_spawns=lambda *a:None,all_images=lambda:0)
            m.hold=lambda text:types.SimpleNamespace(communicate=lambda *a,**kw:(b'',b''),returncode=0)
            m.ssh=lambda text:(0,b'memory: fixture',b'')
            def check(label,ok,*args):
                if not ok:raise cp.sm.Failed(label)
            m.check=check
            return m
        with self.quiet():
            m=make();m.frames_warmup(rehearsal=True);self.assertEqual(m.steps,0)
            with self.assertRaisesRegex(cp.sm.Failed,'within 5'):make().frames_warmup()
            with self.assertRaisesRegex(cp.sm.Failed,'unchanged'):make(True).frames_warmup(rehearsal=True)
    def test_large_cold_group_reports_rest_then_plateaus(self):
        m=self.fixture();sample=m.warm_capacity
        def capacity():
            a,b=sample()
            if m.n:a['frames']=120
            return a,b
        m.warm_capacity=capacity;r=cw.Rehearsal(m,cp)
        with self.quiet():r.establish()
        baseline=next(e for e in r.events if e['phase']=='baseline')
        self.assertEqual(baseline['groups'],2)
        self.assertEqual(baseline['cold_to_warm']['rest'],20)
        self.assertTrue(baseline['owner_report_required'])
        self.assertEqual(m.steps,0)
    def test_input_content_mutation_refuses(self):
        m=self.fixture();m.files['/home/operator/cports/excl/input']=b'old';r=cw.Rehearsal(m,cp)
        m.files['/home/operator/cports/excl/input']=b'new'
        with self.assertRaises(wb.BaselineError):r.reset()
    def test_missing_predecessor_and_pair(self):
        m=self.fixture();m.cases=m.cases[1:]
        with self.assertRaisesRegex(wb.BaselineError,'predecessor'):cw.selected(m,cp)
        m.cases=[c for c in cp.load_cases(m.repo/'cports/cases.tsv') if c.name=='zlib.gzip-1m']
        with self.assertRaisesRegex(wb.BaselineError,'pair'):cw.selected(m,cp)
    def test_stopping_cases_not_rehearsed(self):
        m=self.fixture();stops=[c for c in cp.load_cases(m.repo/'cports/cases.tsv') if c.name in cp.RESTART_ROUNDS]
        m.cases+=stops
        self.assertEqual([c.name for c in cw.selected(m,cp)],cw.EXCL[:3])
        m.cases=stops+[m.cases[0]]
        with self.assertRaises(wb.BaselineError):cw.selected(m,cp)
    def test_different_end_files_are_not_new_exemption(self):
        m=self.fixture();r=cw.Rehearsal(m,cp)
        with self.quiet():r.establish()
        m.put(4)
        with self.quiet():r.finish()
        self.assertEqual(r.events[-1]['state'],'NOT_ESTABLISHED');self.assertEqual(m.files['/home/operator/cports/excl/x.db'],b'4')
    def test_new_boot_refuses_reset_and_does_not_reuse_baseline(self):
        m=self.fixture();r=cw.Rehearsal(m,cp);m.t.boots=2
        with self.assertRaisesRegex(wb.BaselineError,'boot'):r.reset()
        with self.quiet():r.finish()
        self.assertEqual(r.events[-1]['state'],'NOT_ESTABLISHED')
    def test_held_sessions_count_with_and_without_warm_mode(self):
        from unittest.mock import patch
        m=cp.CportsMatrix.__new__(cp.CportsMatrix)
        m.client=types.SimpleNamespace(base=lambda op:['fixture']);m.op='fixture'
        m.connections=0;m.pin=set()
        with patch.object(cp.subprocess,'Popen',return_value=types.SimpleNamespace()):
            m.hold('x');self.assertEqual(m.connections,1)
            m.pin={'fixture'};m.hold('x');self.assertEqual(m.connections,2)
    def test_correctness_repeat_and_stop_methods_stay_unchanged(self):
        import ast,subprocess
        path=pathlib.Path(cp.__file__)
        old=ast.parse(subprocess.check_output(['git','-C',str(path.parent.parent),'show',
            '288d543229d830b416a37ece4acd56e4917de30a:scripts/cports-matrix.py'],text=True))
        new=ast.parse(path.read_text())
        def body(tree,name):return ast.dump(next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name==name),include_attributes=False)
        # stable/compare_census now bind judgments to their recorded rest
        # floors; test-census-rest-floor.py exercises that correction.
        # cports-matrix-selftest.py covers warm acceptance/refusal, the post-warm
        # judged baseline, strict round equality and diagnostic failure retention.
        # Correctness and exact restart/stop methods remain frozen.
        for name in ['restart_rounds','restart_repeat',
                     'run_shell_case','judge','judge_limit_prefix','limit_case','timed_out','check_outputs']:
            self.assertEqual(body(old,name),body(new,name),name)
        # Only restart-local session accounting changes in cut(); preserve
        # the original stop, replay and resource assertions byte-for-AST.
        cut = next(n for n in ast.walk(new) if isinstance(n, ast.FunctionDef) and n.name == 'cut')
        resets = [n for n in cut.body if isinstance(n, ast.Assign)
                  and isinstance(n.targets[0], ast.Attribute) and n.targets[0].attr == 'connections'
                  and isinstance(n.targets[0].value, ast.Name) and n.targets[0].value.id == 'self']
        self.assertEqual(len(resets), 1)
        self.assertEqual(ast.literal_eval(resets[0].value), 0)
        cut.body.remove(resets[0])
        self.assertEqual(body(old, 'cut'), body(new, 'cut'))
    def test_expected_timeout_is_attempted_kept_and_reset(self):
        m=self.fixture();m.cases=[c for c in cp.load_cases(m.repo/'cports/cases.tsv') if c.name=='sqlite.speedtest1-20']
        (m.work/'linux/speedtest').mkdir();attempts=[]
        def run(c):
            attempts.append((c.args,c.timeout));m.n+=1
            m.files['/home/operator/cports/speedtest/st.db']=b'partial'
            (m.linux_dir('speedtest')/'st.db').write_bytes(b'partial')
            raise cp.SessionTimeout('expected',b'progress',b'',c.timeout)
        m.run_shell_case=run
        m.keep_timeout=lambda c,e:(m.work/'partial').write_bytes(e.out)
        r=cw.Rehearsal(m,cp)
        with self.quiet():r.establish()
        self.assertEqual(len(attempts),2);self.assertFalse(m.files)
        for n in (1,2):
            self.assertEqual((m.work/f'warm-rehearsal-{n}/partial').read_bytes(),b'progress')
            self.assertEqual(json.loads((m.work/f'warm-rehearsal-{n}/outcomes.json').read_text())['sqlite.speedtest1-20'],'LIMIT_TIMEOUT')
    def test_unreclaimed_limit_refuses_without_measured_result(self):
        from unittest.mock import patch
        m=self.fixture();m.cases=[c for c in cp.load_cases(m.repo/'cports/cases.tsv') if c.name=='sqlite.speedtest1-20']
        (m.work/'linux/speedtest').mkdir()
        m.run_shell_case=lambda c:(_ for _ in ()).throw(cp.SessionTimeout('expected',b'partial',b'',c.timeout))
        m.keep_timeout=lambda c,e:(m.work/'partial').write_bytes(e.out)
        m.t.all_images=lambda:1
        r=cw.Rehearsal(m,cp)
        with self.quiet(),patch.object(cw.time,'monotonic',side_effect=[0,121]),self.assertRaisesRegex(wb.BaselineError,'not reclaimed'):
            r.establish()
        self.assertIsNone(r.baseline.baseline)
        self.assertEqual(r.events[-1]['state'],'NOT_ESTABLISHED')
        self.assertEqual((m.work/'warm-rehearsal-1/partial').read_bytes(),b'partial')
    def test_failed_establishment_records_distinct_coverage(self):
        m=self.fixture();r=cw.Rehearsal(m,cp);m.files['/home/operator/cports/excl/unknown']=b'x'
        with self.quiet(),self.assertRaises(wb.BaselineError):r.establish()
        self.assertEqual(r.events[-1]['state'],'NOT_ESTABLISHED')
        self.assertIn('No measured result inferred',r.events[-1]['correctness'])

if __name__=='__main__':unittest.main()
