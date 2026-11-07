#!/usr/bin/env python3
"""Replay actual suite expressions; missing private counters come from actual host consumers.

The fixture is a retained failed kernel-test summary, never a new guest verdict.
"""
from pathlib import Path
import argparse, hashlib, json, re, subprocess, sys, tempfile
ROOT = Path(__file__).resolve().parents[1]

def expression(source, name):
    source = re.sub(r'//[^\n]*', '', source)
    start = source.index('let ' + name + ' =')
    return source[start:source.index(';', start)+1]

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--work', type=Path)
    p.add_argument('--serial', type=Path, default=ROOT/'tests/fixtures/smoke-accounting.txt')
    a = p.parse_args()
    if a.work is None:
        with tempfile.TemporaryDirectory(prefix='absd-smoke-accounting-') as d:
            subprocess.run([sys.executable, __file__, '--work', str(Path(d)/'proof'), '--serial', str(a.serial)], check=True)
        return
    a.work.mkdir(parents=True, exist_ok=False)
    consumers=subprocess.run([sys.executable, str(ROOT/'scripts/test-capacity-selftests.py'), '--work', str(a.work/'consumers')], capture_output=True, text=True)
    (a.work/'consumers.log').write_text(consumers.stdout+consumers.stderr)
    if consumers.returncode:
        print(consumers.stdout+consumers.stderr,end='');raise SystemExit(consumers.returncode)
    rows = json.loads((a.work/'consumers/RESULTS.json').read_text())
    observed = next(x['output'] for x in rows if x['case']=='object-accounting')
    cell, handle, pipe = map(int, re.search(r'cell=(\d+) handle=(\d+) pipe=(\d+)', observed).groups())
    child = next(x['output'] for x in rows if x['case']=='cell-accounting')
    child_cell = int(re.search(r'cell=(\d+)',child).group(1))
    data = a.serial.read_text()
    def value(key): return int(re.search(r'(?: |^)'+key+r'=(\d+)', data, re.M).group(1))
    values = {x:value(x) for x in ['spawns','reaps','exits','faults','kills','writes','maps','preempts','sleeps','timeouts']}
    for field,key in [('unknown_refusals','unknown'),('pointer_refusals','pointer'),('handle_refusals','handle'),('wait_refusals','wait'),('spawn_refusals','spawn'),('map_refusals','map'),('idle_entries','idle')]: values[field]=value(key)
    for left,right,key in [('transitions','stale_transitions','transitions'),('cell_waits','cell_wakeups','cell_waits'),('pipe_writes','pipe_reads','pipe_io'),('pipe_waits','pipe_wakeups','pipe_waits')]:
        values[left],values[right]=map(int,re.search(key+r'=(\d+)/(\d+)',data).groups())
    values['cell_refusals']=cell+child_cell; values['pipe_refusals']=pipe
    source=(ROOT/'src/suite.rs').read_text()
    stats_source=(ROOT/'src/sched.rs').read_text()
    for field in values:
        assert re.search(r'pub '+field+r': u64,',stats_source), 'actual RuntimeStats field type changed: '+field
    declarations='\n'.join(f'{k}: u64,' for k in values)+'\ninit_status: Option<i32>,'
    entries=','.join(f'{k}:{v}' for k,v in values.items())+f',init_status:Some({value("init")})'
    # Helper extraction includes only functions actually used by these predicates.
    helpers=''
    if 'fn smoke_handle_refusals(' in source:
        start=source.index('fn smoke_handle_refusals('); end=source.index('\n/// Evaluates',start)
        helpers=source[start:end]
    abi=ROOT/'abi/src/syscall.rs'; obj=ROOT/'src/object.rs'
    minimum=re.search(r'const MIN_STRESS_SPAWNS: u64 = \d+;',source).group()
    constants='\n'.join(re.search(r'pub const '+n+r': usize = \d+;', f.read_text()).group() for n,f in [('MAX_PROCESS_HANDLES',abi),('MAX_PROCESS_SLOTS',abi),('MAX_SPAWN_HANDLES',abi),('MAX_PIPES',obj)])
    code=constants+'\nextern crate self as absd_kernel; mod syscall {pub use crate::{MAX_PROCESS_SLOTS,MAX_SPAWN_HANDLES,MAX_PROCESS_HANDLES};} mod object {pub use crate::MAX_PIPES;}\nmod smp_user {pub fn pressure_reservation()->u64{0}}\n'+minimum+'\n'+helpers+'\n#[derive(Clone)]struct Stats{'+declarations+'}\nfn predicates(stats:&Stats)->(bool,bool){'+expression(source,'lifecycle')+expression(source,'abi')+'(lifecycle,abi)}\nfn main(){let base=Stats{'+entries+'};println!("replayed lifecycle/ABI={:?}; non-emitted cell/pipe from actual table/syscall consumers",predicates(&base));assert_eq!(predicates(&base),(true,true));\n'
    for field in ['handle_refusals','unknown_refusals','pointer_refusals','wait_refusals','spawn_refusals','map_refusals','cell_refusals','pipe_refusals','timeouts']:
        code+='for delta in [-1isize,1] {let mut bad=base.clone(); if delta<0 && bad.'+field+'==0 {continue;} bad.'+field+'=(bad.'+field+' as isize+delta)as u64; assert_ne!(predicates(&bad),(true,true),"counter '+field+' mutation accepted");}\n'
    code+='let mut bad=base.clone();bad.init_status=Some(1);assert!(!predicates(&bad).0);let mut bad=base.clone();bad.reaps-=1;assert!(!predicates(&bad).0);println!("17 exact-counter neighbors and init/reap negative controls rejected");}\n'
    (a.work/'proof.rs').write_text(code)
    subprocess.run(['rustc','+1.95.0','--edition=2024',str(a.work/'proof.rs'),'-o',str(a.work/'proof')],check=True)
    result=subprocess.run([str(a.work/'proof')],capture_output=True,text=True)
    (a.work/'result.log').write_text(result.stdout+result.stderr)
    files=['src/sched.rs','src/suite.rs','abi/src/syscall.rs','src/object.rs','scripts/test-smoke-accounting.py','tests/fixtures/smoke-accounting.txt']
    (a.work/'SOURCE.json').write_text(json.dumps({x:hashlib.sha256((ROOT/x).read_bytes()).hexdigest() for x in files},indent=2)+'\n')
    print(result.stdout+result.stderr,end='');raise SystemExit(result.returncode)
if __name__=='__main__': main()
