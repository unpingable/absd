#!/usr/bin/env python3
"""Focused actual guard/trace controls. No guest, full SMP receipt or runner execution."""
import ast, argparse, hashlib, json, re, subprocess, tempfile
from types import SimpleNamespace
from pathlib import Path
from kernel_capacities import MAX_PROCESS_SLOTS, MAX_PROCESS_HANDLES, FILE_SERVER_SLOTS
ROOT=Path(__file__).resolve().parents[1]

def guard(file, message, env):
    tree=ast.parse((ROOT/'scripts'/file).read_text())
    found=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in ('need','require') and len(n.args)>1 and isinstance(n.args[1],ast.Constant) and n.args[1].value==message]
    assert len(found)==1,(file,message)
    return eval(compile(ast.Expression(found[0].args[0]),file,'eval'),env)

def main():
    p=argparse.ArgumentParser();p.add_argument('--work',type=Path);a=p.parse_args()
    if a.work is None:
        with tempfile.TemporaryDirectory(prefix='absd-capacity-oracles-') as d:subprocess.run(['python3',__file__,'--work',str(Path(d)/'proof')],check=True)
        return
    a.work.mkdir(parents=True,exist_ok=False)
    assert (MAX_PROCESS_SLOTS,MAX_PROCESS_HANDLES,FILE_SERVER_SLOTS)==(32,128,18), 'current profile changed: rederive boundary controls'
    # Actual table consumer compiled against actual current ABI/object/handle code.
    for name,dest in [('src/object.rs','object.rs'),('src/handle.rs','handle.rs'),('abi/src/syscall.rs','abi.rs')]: (a.work/dest).write_bytes((ROOT/name).read_bytes())
    trace=(ROOT/'scripts/authority-handle-pressure.rs').read_text()
    trace='\n'.join(x for x in trace.splitlines() if not x.startswith('//!'))
    (a.work/'trace.rs').write_text('extern crate self as absd_kernel;extern crate self as absd_abi;#[path="abi.rs"]pub mod syscall;#[path="object.rs"]pub mod object;#[path="handle.rs"]pub mod handle;\n'+trace)
    subprocess.run(['rustc','+1.95.0','--edition=2024','-Awarnings',str(a.work/'trace.rs'),'-o',str(a.work/'trace')],check=True)
    result=subprocess.run([str(a.work/'trace')],capture_output=True,text=True);(a.work/'trace.log').write_text(result.stdout+result.stderr)
    failures=[]
    if result.returncode:failures.append('actual pressure trace refused current ABI: '+result.stderr)
    tests=[('check-smp-bsp-pressure.py','first user-entry slot/epoch is outside the live task range',dict(epoch=1)),('check-smp-nway-startup.py','first user trap does not bind published AP actor',dict(actor_cpu=1,cpu=1,seq=1,epoch=1,actors_by_role={1:{'restricted_i':0}},role=1,actor_i=1,i=2)),('check-smp-app-scale.py','supervisor slot/generation mismatch',dict(gen=1,cpus=2)),('check-smp-app-scale.py','native publication identity/parent/placement mismatch',dict(job=0,natives={},pid=2,parent=3,supervisors={0:{'pid':3}},cpu=0,cpus=2))]
    for file,message,values in tests:
        for slot,expected in [(31,True),(32,False),(-1,False)]:
            env=dict(values,slot=slot,MAX_PROCESS_SLOTS=MAX_PROCESS_SLOTS)
            actual=guard(file,message,env)
            if bool(actual)!=expected:failures.append(f'{file} slot{slot}: expected{expected}, actual{actual}')
    # Actual frame-bound assignment must use all slots, including the upper half.
    tree=ast.parse((ROOT/'scripts/check-smp-bsp-pressure.py').read_text())
    assignments=[n for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ordinary_slots' for t in n.targets)]
    assert len(assignments)==2
    for node in assignments:
        for reserve in (0,2,10):
            actual=eval(compile(ast.Expression(node.value),'BSP actual frame bound','eval'),dict(MAX_PROCESS_SLOTS=MAX_PROCESS_SLOTS,reserved=reserve,cpus=1+reserve//2))
            if actual!=MAX_PROCESS_SLOTS-reserve:failures.append('BSP ordinary-slot frame bound stale')
    file='check-smp-bsp-pressure.py'
    for peak,expected in [(32,True),(16,False),(33,False)]:
        actual=guard(file,'suite process pressure did not reach the exact process-table peak',dict(peak=peak,MAX_PROCESS_SLOTS=MAX_PROCESS_SLOTS)) if 'exact process-table peak' in (ROOT/'scripts'/file).read_text() else guard(file,'suite process pressure did not reach the exact 16-slot peak',dict(peak=peak,MAX_PROCESS_SLOTS=MAX_PROCESS_SLOTS))
        if actual!=expected:failures.append(f'BSP peak{peak}: expected{expected}, actual{actual}')
    # Evaluate the actual matrix readiness/start predicates, not a permissive replacement regex.
    for channels, expected in [(19,True),(11,False),(20,False)]:
        lines=[f'FSD READY channels={channels} slots=18 fs_seq=1 formatted=false fs_objects=0']
        env=dict(lines=lines,re=re,FILE_SERVER_SLOTS=FILE_SERVER_SLOTS)
        actual=guard('smp-app-matrix.py','file server did not report its ready boundary',env)
        starts=[re.fullmatch(r'FILE SERVER START pid=(\d+) channels=(\d+)',f'FILE SERVER START pid=2 channels={channels}')]
        start=guard('smp-app-matrix.py','unexpected FSD channel count',dict(starts=starts,FILE_SERVER_SLOTS=FILE_SERVER_SLOTS))
        if actual!=expected or start!=expected:failures.append(f'FSD channels{channels}: ready={actual} start={start}, expected{expected}')
    matrix=ast.parse((ROOT/'scripts/smp-app-matrix.py').read_text())
    build=next(n for n in ast.walk(matrix) if isinstance(n,ast.FunctionDef) and n.name=='build')
    update=next(n for n in ast.walk(build) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='update')
    config=eval(compile(ast.Expression(update.args[0]),'actual matrix build env','eval'),dict(Path=Path,worker='worker',input_path=a.work/'input',file_server='fsd',self=SimpleNamespace(target=a.work/'target')))
    if config.get('ABSD_LOGD_ELF')!='':failures.append('actual matrix build does not pin no-logger input')
    print(result.stdout,end='')
    for failure in failures:print(failure)
    files=['abi/src/syscall.rs','abi/src/program.rs','src/object.rs','src/handle.rs','scripts/kernel_capacities.py','scripts/authority-handle-pressure.rs','scripts/check-smp-bsp-pressure.py','scripts/check-smp-nway-startup.py','scripts/check-smp-app-scale.py','scripts/smp-app-matrix.py','scripts/test-capacity-oracles.py']
    (a.work/'SOURCE.json').write_text(json.dumps({x:hashlib.sha256((ROOT/x).read_bytes()).hexdigest() for x in files},indent=2)+'\n')
    (a.work/'RESULTS.json').write_text(json.dumps({'failures':failures,'scope':'actual guard expressions + actual HandleTable trace; no full SMP oracle or guest outcome'},indent=2)+'\n')
    if failures:raise SystemExit(1)
    print('actual slot guards accept31/refuse32/negative; BSP exact32 accepts/refuses16,33')
    print('actual FSD predicates accept19/18, reject11 and wrong20; actual build env pins no logger')
if __name__=='__main__':main()
