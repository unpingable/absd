#!/usr/bin/env python3
"""Actual scheduler/table/self-test consumers; substitute loader/process/IPC endpoints only."""
from pathlib import Path
import argparse,subprocess,json,hashlib,tempfile,sys,re
ROOT=Path(__file__).resolve().parents[1]
def block(s,m):
 a=s.index(m);b=s.index('{',a);end=b+1;depth=1
 while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[a:end]
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--work',type=Path);a=parser.parse_args()
 if a.work is None:
  with tempfile.TemporaryDirectory(prefix='absd-capacity-selftests-')as temp:
   subprocess.run([sys.executable,__file__,'--work',str(Path(temp)/'proof')],check=True)
  return
 work=a.work;work.mkdir(exist_ok=False,parents=True)
 hashes={}
 def source(name):
  text=(ROOT/name).read_text()
  hashes[name]=hashlib.sha256(text.encode()).hexdigest();return text
 for name,dest in [('src/object.rs','object.rs'),('src/handle.rs','handle.rs'),('abi/src/syscall.rs','abi.rs'),('abi/src/program.rs','program.rs')]: (work/dest).write_text(source(name))
 sched=source('src/sched.rs');catalog=source('src/user_program.rs');calls=source('src/syscalls.rs');init=source('user/src/bin/init.rs');hostile=source('user/src/bin/hostile_probe.rs');multi=source('user/src/bin/multi_handle.rs');cell=source('user/src/bin/cell.rs')
 enum=block(sched,'pub enum SpawnError');transfer=block(sched,'pub struct Transfer')
 selected='#[derive(Clone,Copy,Debug)]\n'+enum+'\n#[derive(Clone,Copy)]\n'+transfer+'\n'+block(sched,'impl Transfer')+'\n'+block(sched,'impl SpawnError')+'\n'+block(catalog,'pub const fn uses_multi_start(')+'\n'+block(sched,'pub unsafe fn spawn_many_copy(')+'\n'+block(sched,'unsafe fn spawn_transferred(')
 (work/'sched.rs').write_text('use crate::{handle::Object,syscall::*,spawn_from,PROGRAMS};\n'+selected)
 method=block(init,'fn verify_multi_handle_spawn(');name='let maximum ='if 'let maximum ='in method else'let exhaust =';start=method.index(name);end=method.index('    let second',start)
 smoke='fn smoke_vector()->Result<(), &\'static str>{let cell=Cell::from_raw(unsafe{PARENT_CELL});\n'+method[start:end]+'\nOk(())}\n'
 selected=block(cell,'fn run(').replace('fn run(','fn cell_run(',1)+'\n'+re.search(r'const OBJECT_CAPACITY_CYCLES: usize = \d+;',init).group()+'\n'+block(calls,'unsafe fn handle_error(')+'\n'+'mod sys_cell {use crate::{table,cells,stats,count_handle_refusal,release_object,handle_error,Object};use crate::handle::{RIGHT_READ,RIGHT_WRITE};use crate::syscall::{ERROR_TOO_MANY_HANDLES,ERROR_NO_MEMORY};pub unsafe fn call(current:usize,value:u64)->i64{unsafe{syscall_cell_create(current,value)}}'+block(calls,'unsafe fn syscall_cell_create(')+'}'+'\n'+block(init,'fn verify_object_capacity(')+'\n'+block(calls,'unsafe fn count_handle_refusal(')+'\nmod sys_pipe {use crate::{table,pipes,stats,count_handle_refusal,release_object,handle_error,Object};use crate::handle::{RIGHT_READ,RIGHT_WRITE};use crate::syscall::{ERROR_TOO_MANY_HANDLES,ERROR_NO_MEMORY};pub unsafe fn call(current:usize)->i64{unsafe{syscall_pipe_create(current)}}'+block(calls,'unsafe fn syscall_pipe_create(')+'}\n'+block(hostile,'fn objects_exhausted(')+'\n'+block(multi,'fn main(').replace('fn main(','fn multi_main(',1)+'\n'+smoke
 (work/'consumers.rs').write_text(selected)
 code=(ROOT/'tests/fixtures/capacity_selftests.rs.in').read_text()
 hashes['tests/fixtures/capacity_selftests.rs.in']=hashlib.sha256(code.encode()).hexdigest()
 hashes['scripts/test-capacity-selftests.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
 (work/'main.rs').write_text(code)
 (work/'SOURCE.json').write_text(json.dumps({'revision':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),'files':hashes,'scope':'Actual scheduler entry classifier/copy path, HandleTable/PipeTable/pipe_create and probe consumers; loader/process/IPC endpoints substituted'},indent=2)+'\n')
 run=subprocess.run(['rustc','+1.95.0','--edition=2024','-A','warnings',str(work/'main.rs'),'-o',str(work/'proof')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(work/'compile.log').write_bytes(run.stdout)
 if run.returncode:print(run.stdout.decode());raise SystemExit(run.returncode)
 rows=[]
 for case in ['smoke','pipes','pipes-global','vector-negatives','object-accounting','vector-accounting','cell-accounting']:
  run=subprocess.run([str(work/'proof'),case],stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(work/(case+'.log')).write_bytes(run.stdout);rows.append({'case':case,'status':run.returncode,'output':run.stdout.decode()})
 (work/'RESULTS.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps(rows,indent=2))
 if any(row['status']for row in rows):raise SystemExit(1)
if __name__=='__main__':main()
