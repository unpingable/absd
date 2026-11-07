#!/usr/bin/env python3
"""Run actual patch-derived std time PAL and runtime bridges on controlled clock inputs."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
ROOT = Path(__file__).resolve().parents[1]

def function(source, marker):
    start=source.index(marker);at=source.index('{',start);end=at+1;depth=1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--work',type=Path,required=True);args=parser.parse_args()
    work=args.work.resolve();work.mkdir(parents=True,exist_ok=True)
    patch=ROOT/'patches/rust-1.95.0-absd-std.patch';text=patch.read_text()
    at=text.index('+++ b/library/std/src/sys/time/absd.rs\n');part=text[at:].split('\ndiff --git ',1)[0]
    pal='\n'.join(line[1:] for line in part.splitlines() if line.startswith('+') and not line.startswith('+++'))+'\n'
    (work/'pal.rs').write_text(pal)
    runtime=ROOT/'runtime/src/lib.rs';rs=runtime.read_text()
    code='#![allow(dead_code)]\nmod time { pub use std::time::Duration; }\n#[path='+json.dumps(str(work/'pal.rs'))+'] mod pal;\n'
    for marker in ['pub extern "C" fn __absd_std_ticks()', 'pub extern "C" fn __absd_std_wall_clock_seconds()']:
        code+='#[unsafe(no_mangle)]\n'+function(rs,marker)+'\n'
    fixture=ROOT/'tests/fixtures/system_time.rs';code+='include!('+json.dumps(str(fixture))+');\n';(work/'proof.rs').write_text(code)
    (work/'SOURCE.json').write_text(json.dumps({'scope':'Actual std PAL and exported runtime bridges; controlled underlying clock inputs, not a native guest or host std claim','sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),patch,runtime,fixture]},'pal_sha256':hashlib.sha256(pal.encode()).hexdigest()},indent=2)+'\n')
    subprocess.run(['rustc','--edition=2024','--test',str(work/'proof.rs'),'-o',str(work/'proof')],check=True)
    subprocess.run([str(work/'proof'),'--test-threads=1','--nocapture'],check=True,timeout=15)
if __name__=='__main__':main()
