#!/usr/bin/env python3
"""Run the production ps and observation decoder against bounded native-call fixtures."""
from pathlib import Path
import os
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[2]
STUB=r'''
mod absd_runtime {
    pub fn link_anchor() {}
    #[path="OBSERVATION"] pub mod observation;
    pub unsafe fn syscall3(number:u64,_:u64,address:u64,query:u64)->i64 {
        assert_eq!(number,0x7fc1);
        let mode=std::env::var("CAPACITY_CASE").unwrap();
        if mode=="old" && query==257 {return -22;}
        let b=unsafe {&mut *(address as *mut [u8;256])};
        let mut put=|at:usize,value:u64|b[at*8..at*8+8].copy_from_slice(&value.to_le_bytes());
        put(0,1);
        if query==257 {
            put(1,4);put(3,if mode=="bad"{257}else{32});put(4,128);put(5,64);put(6,128);put(7,32);
        } else {
            assert!(query<32);put(1,1);put(3,query);
            if query==18 || query==31 {put(4,200+query);put(5,1);put(6,0xffff_ffff);put(7,4);put(8,3);put(9,7);put(12,u64::MAX);}
        }
        0
    }
}
'''.replace('OBSERVATION',str(ROOT/'runtime/src/observation.rs'))
actual='\n'.join(line for line in (ROOT/'src/bin/ps.rs').read_text().splitlines() if not line.startswith(('#!','//!')))
with tempfile.TemporaryDirectory(prefix='absd-process-capacity-') as temp:
    wire=Path(temp)/'capacity-wire-tests'
    subprocess.run(['rustc','--edition=2024','--test',str(ROOT/'runtime/src/capacity_wire.rs'),'-o',str(wire)],check=True)
    subprocess.run([str(wire)],check=True)
    source=Path(temp)/'ps.rs';binary=Path(temp)/'ps';source.write_text(STUB+actual)
    subprocess.run(['rustc','--edition=2024','-Adead_code',str(source),'-o',str(binary)],check=True)
    for mode in ('known','old','bad'):
        result=subprocess.run([str(binary)],env={**os.environ,'CAPACITY_CASE':mode},capture_output=True)
        if mode=='known':
            assert result.returncode==0,(result.stdout,result.stderr)
            assert b'218' in result.stdout and b'231' in result.stdout,result.stdout
        else:
            assert result.returncode==1 and not result.stdout and b'no partial census' in result.stderr,(result.stdout,result.stderr)
print('PROCESS CAPACITY: upper-half slots observed; older/invalid profiles explicitly unknown')
