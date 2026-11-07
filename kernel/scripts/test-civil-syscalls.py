#!/usr/bin/env python3
"""Actual clock syscall wrappers with real tables/Clock and controlled host memory I/O."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
ROOT=Path(__file__).resolve().parents[1]
def item(source, marker):
    start=source.index(marker);at=source.index('{',start);end=at+1;depth=1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True);parser.add_argument('--target-dir',type=Path,required=True)
    args=parser.parse_args();work=args.work.resolve();(work/'src').mkdir(parents=True,exist_ok=True)
    source=ROOT/'src/syscalls.rs';fixture=ROOT/'scripts/fixtures/civil-syscalls.rs'
    text=fixture.read_text();actual=source.read_text()
    text+='\n'+''.join(item(actual,marker)+'\n' for marker in ['unsafe fn handle_error(', 'unsafe fn civil_update(', 'unsafe fn civil_mint('])
    (work/'src/lib.rs').write_text(text)
    (work/'Cargo.toml').write_text('[package]\nname="civil-syscall-proof"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\nabsd-kernel={path='+json.dumps(str(ROOT))+'}\n[profile.test]\ndebug=0\n')
    (work/'SOURCE.json').write_text(json.dumps({'scope':'Actual syscall wrappers and real kernel process/handle/Clock types; substituted current table, tick, copy boundary, initialization and notice sinks; no interrupt/BKL, user-memory validation or guest proof','sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [source,fixture,Path(__file__)]}},indent=2)+'\n')
    env=dict(os.environ,CARGO_TARGET_DIR=str(args.target_dir.resolve()),CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0')
    subprocess.run(['cargo','test','--manifest-path',str(work/'Cargo.toml'),'--target','x86_64-unknown-linux-gnu','--offline','--lib','--','--test-threads=1','--nocapture'],env=env,check=True)
if __name__=='__main__':main()
