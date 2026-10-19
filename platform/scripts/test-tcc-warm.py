"""No guest/compiler: exercise actual adapter with explicit state/telemetry fixture."""
import copy
import importlib.util
from pathlib import Path
import shlex
import types
import tempfile
import unittest
from unittest.mock import patch
import tcc_warm as tw
import warm_baseline as wb


def case(name='hello', cwd=None, keeps=None, drops=None):
    return types.SimpleNamespace(name=name, kind='compile-run', args=[], stdin=None,
        pipe=None, cwd=cwd, keeps=keeps or [], drops=drops or [], gate=None)

class Matrix:
    def __init__(self):
        self.cases=[case()];self.pin=set();self.tree={'/base':b'base'}
        self.t=types.SimpleNamespace(tree=lambda:dict(self.tree))
        self.connections=0;self.events=[];self.fail_reset=False;self.fail_case=False;self.frames=10;self.growth=0
        self.warm_quote=shlex.quote
    def shell_ssh(self, cmd):
        self.connections+=1;self.events.append(('reset',cmd))
        if self.fail_reset:return 1,b'',b'failure',None,None
        # An unquoted exec uses argv mode, where exit is not an executable.
        if cmd == 'exit 0':return 127,b'',b'no exit executable',None,None
        for n in shlex.split(cmd)[1:] if cmd.startswith('"/bin/rm"') else []:del self.tree[n]
        return 0,b'',b'',None,None
    def stable(self,*a):return dict(images=0,kernel='same',memory=self.frames,fsd=0,fsd_draining=0,objects=[])
    def allowed(self,c):return {'/out/'+c.name+'.elf'}
    def rest_handles(self,c):return True
    def permitted_rest_lowering(self,before,after):return False
    def comparison_kernels(self,before,after,lowered):return before['kernel'],after['kernel']
    def rest_opens(self,*a):pass
    def check(self,text,ok,detail):wb.require(ok,text+detail)
    def compare_census(self,*a):pass
    def run_compile_case(self,c):
        self.connections+=1
        self.frames+=self.growth;self.growth=0
        self.events.append(('compile',c.name,'/out/'+c.name+'.elf' in self.tree))
        self.tree['/out/'+c.name+'.elf']=b'ELF'
        return ('failed' if self.fail_case else 'agree'),0
    run_negative=run_compile_case

class Tests(unittest.TestCase):
    def adapter(self):
        m=Matrix();r=tw.Rehearsal(m,'/out');r.emit=lambda x:None
        def sample():
            ssh={x:0 for x in wb.SSH_FIELDS};ssh.update(boot='a'*32,accepted_reclaimed=m.connections,frames=m.frames)
            fsd={x:0 for x in wb.FSD_FIELDS};fsd.update(boot='a'*32,settled_releases=m.connections,fs_objects=len(m.tree),rotated_logs=0)
            return ssh,fsd
        r.capacity=sample
        return m,r
    def test_final_rehearsal_baseline_reset_measured(self):
        m,r=self.adapter();r.establish();self.assertEqual(m.connections,4)
        self.assertIn('/out/hello.elf',m.tree)
        r.reset();self.assertNotIn('/out/hello.elf',m.tree)
        m.run_compile_case(m.cases[0]);r.measured()
        self.assertEqual([e[2] for e in m.events if e[0]=='compile'],[False]*3)
    def test_empty_reset_explicitly_uses_the_shell(self):
        m,r=self.adapter();r.reset()
        self.assertEqual(m.events[-1],('reset','"exit" "0"'))
    def test_uncapped_first_growth_then_measured_bound(self):
        m,r=self.adapter();m.growth=100;r.establish()
        self.assertEqual(r.baseline.baseline[0]['frames'],110)
        r.reset();m.growth=6;m.run_compile_case(m.cases[0])
        with self.assertRaises(wb.BaselineError):r.measured()
    def test_rehearsal_kernel_change_refused(self):
        m,r=self.adapter();before=m.stable();after=dict(before,kernel='changed')
        with self.assertRaisesRegex(wb.BaselineError,'kernel objects'):
            r.rehearsal_census(m.cases[0],before,after)
    def test_reset_failure(self):
        m,r=self.adapter();m.fail_reset=True
        with self.assertRaisesRegex(wb.BaselineError,'reset command'):r.establish()
        self.assertFalse(any(x[0]=='compile' for x in m.events))
    def test_no_unrelated_mutation(self):
        m,r=self.adapter();orig=m.shell_ssh
        def bad(c):
            ret=orig(c);m.tree['/unrelated']=b'new';return ret
        m.shell_ssh=bad
        with self.assertRaisesRegex(wb.BaselineError,'undeclared'):r.reset()
    def test_semantic_failure(self):
        m,r=self.adapter();m.fail_case=True
        with self.assertRaisesRegex(wb.BaselineError,'semantic'):r.establish()
    def test_end_correspondence_not_normalized(self):
        m,r=self.adapter();r.establish();r.reset();m.run_compile_case(m.cases[0]);m.tree['/other']=b'x'
        with self.assertRaisesRegex(wb.BaselineError,'final files'):r.measured()
    def test_pin_and_partial_chain_refused(self):
        m=Matrix();m.pin={'hello'}
        with self.assertRaises(wb.BaselineError):tw.Rehearsal(m,'/out')
        m.pin=set();m.cases=[case('stdio.verify','/home/operator/tcc-work',drops=['c-stdio.dat'])]
        with self.assertRaisesRegex(wb.BaselineError,'incomplete'):tw.Rehearsal(m,'/out')
    def test_host_state_refused(self):
        m=Matrix();m.cases=[case('stdio.write','/home/operator/tcc-work',keeps=['c-stdio.dat']),case('stdio.verify','/home/operator/tcc-work',drops=['c-stdio.dat'])]
        r=tw.Rehearsal(m,'/out')
        with tempfile.TemporaryDirectory() as d:
            m.linux_dir=lambda cwd:Path(d)
            (Path(d)/'c-stdio.dat').write_bytes(b'leftover')
            with self.assertRaisesRegex(wb.BaselineError,'Linux reference'):r.reset()
    def test_existing_state_refused(self):
        m=Matrix();m.cases=[case('stdio.write','/home/operator/tcc-work',keeps=['c-stdio.dat']),case('stdio.verify','/home/operator/tcc-work',drops=['c-stdio.dat'])]
        r=tw.Rehearsal(m,'/out');m.tree['/home/operator/tcc-work/c-stdio.dat']=b'x'
        with self.assertRaisesRegex(wb.BaselineError,'initial files'):r.reset()

class WiringTests(unittest.TestCase):
    def rest_lowering_fixture(self):
        spec=importlib.util.spec_from_file_location('tcc_matrix',Path(__file__).with_name('tcc-matrix.py'))
        tm=importlib.util.module_from_spec(spec);spec.loader.exec_module(tm)
        m=tm.TccMatrix.__new__(tm.TccMatrix)
        m.cases=[case()];m.pin=set();m.t=types.SimpleNamespace(boots=14)
        m.allowed=lambda c:{'/out/hello.elf'}
        m.check=lambda text,ok,detail:wb.require(ok,text)
        before=dict(images=0,kernel='kernel: 4 process slots, 67 handles, 27 pipes, 1 cells',
                    memory='728 frames',fsd=28,fsd_opens=1,fsd_draining=0,objects=[],
                    rest_at_judgment=dict(boot=14,handles=67,opens=1))
        after=copy.deepcopy(before)
        after.update(kernel='kernel: 4 process slots, 66 handles, 27 pipes, 1 cells',memory='732 frames',fsd=32)
        after['rest_at_judgment']['handles']=66
        m.rest=dict(after['rest_at_judgment'])
        r=tw.Rehearsal(m,'/out');r.emit=lambda x:None
        return m,r,before,after

    def test_actual_stamped_lowering_during_establishment(self):
        m,r,before,after=self.rest_lowering_fixture()
        saved=copy.deepcopy((before,after));events=[];r.emit=events.append
        r.rehearsal_census(m.cases[0],before,after)
        self.assertEqual((before,after),saved)
        self.assertEqual(events[0]['phase'],'rehearsal-rest-lowered')
        self.assertEqual(events[0]['before']['handles'],67)
        self.assertEqual(events[0]['after']['handles'],66)

    def test_establishment_lowering_refuses_invalid_bindings_and_mutations(self):
        def mutate(kind,m,b,a):
            if kind=='cross-boot':b['rest_at_judgment']['boot']=13
            elif kind=='legacy':b.pop('rest_at_judgment')
            elif kind=='malformed':b['rest_at_judgment']['handles']=True
            elif kind=='images':a['images']=1
            elif kind=='draining':a['fsd_draining']=1
            elif kind=='opens':a['fsd_opens']=2
            elif kind=='other-kernel':a['kernel']=a['kernel'].replace('27 pipes','28 pipes')
            elif kind=='current-floor':m.rest['handles']=65
            elif kind=='unrelated-file':a['objects']=[('/unrelated',False,420,b'changed')]
            elif kind=='increase':
                b['kernel']=b['kernel'].replace('67 handles','65 handles');b['rest_at_judgment']['handles']=65
        for kind in ['cross-boot','legacy','malformed','images','draining','opens','other-kernel','current-floor','unrelated-file','increase']:
            with self.subTest(kind=kind):
                m,r,b,a=self.rest_lowering_fixture();mutate(kind,m,b,a)
                with self.assertRaises(wb.BaselineError):r.rehearsal_census(m.cases[0],b,a)

    def census_fixture(self, counts):
        spec = importlib.util.spec_from_file_location('tcc_matrix', Path(__file__).with_name('tcc-matrix.py'))
        tm = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tm)
        m = tm.TccMatrix.__new__(tm.TccMatrix)
        m.connections = 7
        events = []
        def output():
            n = next(counts)
            events.append(('reclaimed', n))
            return (f'SERVED CAPACITY boot={"a" * 32} accepted_reclaimed={n} '
                    'slots=0 pool=0 processes=3 handles=57 pipes=24 cells=1 frames=619 heap_pages_peak=222\n')
        m.t = types.SimpleNamespace(output=output, all_images=lambda: 0,
                                   system_objects=lambda: [], census_detail=lambda: 'fixture')
        def sysinfo():
            events.append(('sysinfo',))
            return 'memory: fixture', 'kernel: 4 process slots, 66 handles, 27 pipes, 1 cells'
        m.sysinfo = sysinfo
        m.fsd_capacity = lambda: (1, 0, 16)
        m.fsd_peak = lambda: 16
        return tm, m, events

    def test_census_waits_for_every_prior_session(self):
        tm, m, events = self.census_fixture(iter([6, 7]))
        with patch.object(tm.ck.time, 'sleep'):
            got = m.census()
        self.assertEqual(events, [('reclaimed', 6), ('reclaimed', 7), ('sysinfo',)])
        self.assertEqual(got['quiescent']['accepted_reclaimed'], 7)
        self.assertEqual(got['kernel'], 'kernel: 4 process slots, 66 handles, 27 pipes, 1 cells')

    def test_missing_reclamation_refuses_before_sysinfo(self):
        tm, m, events = self.census_fixture(iter([6, 6]))
        with patch.object(tm.ck.time, 'monotonic', side_effect=[0, 0, 61]), \
             patch.object(tm.ck.time, 'sleep'):
            with self.assertRaisesRegex(tm.ck.sm.Failed, 'no quiescent'):
                m.census()
        self.assertNotIn(('sysinfo',), events)

    def test_actual_held_counts_connection(self):
        spec=importlib.util.spec_from_file_location('tcc_matrix',Path(__file__).with_name('tcc-matrix.py'))
        tm=importlib.util.module_from_spec(spec);spec.loader.exec_module(tm)
        outputs=iter(['', 'SSH SESSION CHILD pid=7 spawn_right=true argv0=/bin/absd-sh extra=1 control=true\n'])
        m=types.SimpleNamespace(t=types.SimpleNamespace(output=lambda:next(outputs)),connections=4,
            reclaimed=lambda:0,client=types.SimpleNamespace(base=lambda *a:[]),op=None,
            check=lambda text,ok,detail:self.assertTrue(ok,detail))
        with patch.object(tm.subprocess,'Popen',return_value=object()):
            held=tm.Held(m)
        self.assertEqual(m.connections,5);self.assertEqual(held.shell,'7')
    def test_current_table_inventory(self):
        spec=importlib.util.spec_from_file_location('tcc_matrix',Path(__file__).with_name('tcc-matrix.py'))
        tm=importlib.util.module_from_spec(spec);spec.loader.exec_module(tm)
        m=Matrix();m.cases=tm.load_cases(Path(__file__).resolve().parents[1]/'tcc/cases.tsv')
        r=tw.Rehearsal(m,tm.OUT_DIR)
        self.assertEqual(len(r.outputs),22);self.assertEqual(len(r.shapes),24)
        self.assertEqual(m.cases[-1].kind,'spawn-refused')

if __name__=='__main__':unittest.main()
