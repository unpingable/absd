#!/usr/bin/env python3
"""Actual init/bootstrap/request composition. Substitute only kernel resource/I/O endpoints."""
import argparse,hashlib,json,subprocess,sys,tempfile
from pathlib import Path
from logd_callsite_test import check as check_callsite
ROOT=Path(__file__).resolve().parents[1]
def block(s,marker):
 a=s.index(marker);b=s.index('{',a);at=b+1;depth=1
 while depth:depth+=(s[at]=='{')-(s[at]=='}');at+=1
 return s[a:at]
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--work',type=Path);parser.add_argument('--callsite-mutants',action='store_true');parser.add_argument('--producer',type=Path,help='frozen actual platform READY call/macros/oplog emitter');args=parser.parse_args()
 if args.work is None:
  with tempfile.TemporaryDirectory(prefix='absd-logd-admission-')as temp:
   subprocess.run([sys.executable,__file__,'--work',str(Path(temp)/'proof'),*(['--producer',str(args.producer)]if args.producer else[]),*(['--callsite-mutants']if args.callsite_mutants else[])],check=True)
  return
 work=args.work.resolve();work.mkdir(exist_ok=False,parents=True)
 init=(ROOT/'user/src/bin/init.rs').read_text();gate=(ROOT/'src/frame_admission.rs').read_text();obj=(ROOT/'src/object.rs').read_text();lib=(ROOT/'user/src/lib.rs').read_text()
 for source,dest in [('abi/src/syscall.rs','abi.rs'),('abi/src/program.rs','program.rs'),('user/src/logd_policy.rs','policy.rs')]: (work/dest).write_bytes((ROOT/source).read_bytes())
 (work/'gate.rs').write_text('use crate::{object::PipeId,program::ServedReadyProbe};\n'+'\n'.join(block(gate,m)for m in ['pub struct BootstrapAdmission','impl BootstrapAdmission','pub fn read_request(']))
 (work/'object.rs').write_text('#[derive(Clone,Copy,Debug,Eq,PartialEq)]\n'+block(obj,'pub struct PipeId')+'\npub fn fixture(index:u16,generation:u32)->PipeId{PipeId{index,generation}}\n')
 names=['fn frame_admission_result(','fn spawn_served_reserved(','impl LogdHandles','impl Drop for LogdHandles','fn logd_spawn(','fn logd_step(','fn observe_served_ready(']
 if 'fn logd_bootstrap('in init:names+=['fn logd_bootstrap(','fn logd_problem(']
 a=init.index('struct LogdHandles');selected=init[a:init.index('\n',a)]+'\n'+'\n'.join(block(init,m)for m in names)
 (work/'init-functions.rs').write_text(selected)
 code=(ROOT/'tests/fixtures/logd_admission.rs.in').read_text().replace('COLLECT_GLOBALS','static mut LOGD_COLLECT_PROBE:logd_policy::Collected=logd_policy::Collected::new();static mut LOGD_UNKNOWN_REAP:logd_policy::ReapGuard=logd_policy::ReapGuard::new();').replace('ENDED_FUNCTION',block(init,'fn logd_ended(')).replace('ORDINARY_WRAPPER','use syscall::SYS_SPAWN_MANY_COPY;\n'+block(lib,'fn result(')+'\n'+block(lib,'pub fn spawn_many_copy('))
 code=code.replace('INITIAL_CALL','logd_bootstrap(Console);let initial:Result<(),&str>=if unsafe{LOGD_CHILD}!=0{Ok(())}else{Err("initial logger refused")};'if 'fn logd_bootstrap('in init else'logd_step(Console);let initial:Result<(),&str>=if unsafe{LOGD_CHILD}!=0{Ok(())}else{Err("old cold readiness guard")};')
 producer=args.producer.read_text()if args.producer else'fn emit_ready(){println!("SSH LISTENING port=22 authorized_keys=1 preauth_per_source=2");}'
 buffer=lib[lib.index('pub struct LineBuffer {'):lib.index('\nimpl Console {',lib.index('pub struct LineBuffer {'))]
 code=code.replace('EMITTER',producer).replace('ACTUAL_BUFFER',buffer)
 code = code.replace('use std::fmt::Write;', '#[path=' + json.dumps(str(ROOT/'user/src/console_lines.rs')) + '] mod console_lines;\nuse std::fmt::Write;', 1)
 (work/'main.rs').write_text(code)
 sources=['user/src/console_lines.rs','user/src/bin/init.rs','user/src/lib.rs','user/src/logd_policy.rs','user/src/worker_console.rs','src/frame_admission.rs','src/object.rs','abi/src/program.rs','abi/src/syscall.rs','tests/fixtures/logd_admission.rs.in', 'scripts/test-logd-admission.py','scripts/logd_callsite_test.py','tests/fixtures/logd_callsite.rs.in']
 (work/'SOURCE.json').write_text(json.dumps({'scope':__doc__,'source_revision':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),'producer_sha256':hashlib.sha256(producer.encode()).hexdigest(),'producer_path':str(args.producer),'files':{s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest()for s in sources}},indent=2)+'\n')
 subprocess.run(['rustc','+1.95.0','--edition=2024','-A','warnings','-C','debuginfo=0',str(work/'main.rs'),'-o',str(work/'proof')],check=True)
 for scenario in ['normal','fragmented','historical-stderr','initial-refusal','pressure','identity-unknown']:
  run=subprocess.run([str(work/'proof'),scenario],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  (work/(scenario+'.log')).write_bytes(run.stdout);print(run.stdout.decode(),end='');
  if run.returncode:raise SystemExit(run.returncode)
 check_callsite(init,work,ROOT,args.callsite_mutants)
if __name__=='__main__':main()
