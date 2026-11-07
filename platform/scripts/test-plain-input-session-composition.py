#!/usr/bin/env python3
"""Actual shell/native control/local-console composition over bounded host IPC.

No Cargo, shared-target writes, guest, network or modelled recovery producer.
The native syscall boundary alone uses host adapters. No SSH transport is tested.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]

def item(text,marker):
    start=text.index(marker);at=text.index('{',start);depth=1;end=at+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--deps',type=Path,required=True)
    parser.add_argument('--conch',type=Path,required=True)
    parser.add_argument('--glob',type=Path,required=True)
    parser.add_argument('--case',action='append',default=[])
    args=parser.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    source=out/'source'
    names=['sh/src/lib.rs','sh/src/language.rs','sh/src/streams.rs','src/sh_host.rs','src/sh_input.rs',
           'ssh/src/local_console.rs','ssh/src/conn.rs','ssh/src/tty.rs','ssh/src/paste.rs',
           'ssh/src/plain_input.rs','ssh/src/control.rs','ssh/src/input_record.rs','runtime/src/terminal_wire.rs','ssh/src/absd.rs']
    hashes={}
    for name in names:
        target=source/name;target.parent.mkdir(parents=True,exist_ok=True);data=(ROOT/name).read_bytes();target.write_bytes(data);hashes[name]=hashlib.sha256(data).hexdigest()
    host=(source/'src/sh_host.rs').read_text();conn=(source/'ssh/src/conn.rs').read_text()
    traits='\n'.join(item(conn,marker)for marker in ['pub enum Command','pub enum Exit','pub trait SessionChild','pub enum ControlRequest','pub enum MachineRequest','pub fn machine_request','pub trait Spawner'])
    native='\n'.join(item(host,marker)for marker in ['pub struct Absd','impl Absd','struct Control','enum Heard','impl Control','impl Drop for Control'])
    if 'fn wait_plain_cancel(' in host and 'fn wait_plain_cancel(' not in native:
        native+='\nimpl Absd{'+item(host,'fn wait_plain_cancel(')+'}'
    wanted=['prompt_cancelled','terminal_size','prompt_input','input_limit_notice','refuse_interactive_input','discard_pending_input','interrupted','read_interactive','session_request','line_read','ended']
    methods='\n'.join(item(host,'fn '+name+'(')for name in wanted if 'fn '+name+'(' in host)
    fixture=(ROOT/'scripts/fixtures/plain_input_session_composition.rs').read_text()
    for key,value in {'@SOURCE@':str(source),'@CONN_TRAITS@':traits,'@NATIVE_STRUCTS@':native,'@NATIVE_METHODS@':methods}.items():fixture=fixture.replace(key,value)
    file=out/'composition.rs';file.write_text(fixture)
    binding=dict(test_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ['scripts/test-plain-input-session-composition.py','scripts/fixtures/plain_input_session_composition.rs']},source_sha256=hashes,generated_sha256=hashlib.sha256(file.read_bytes()).hexdigest(),
                 dependencies={str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in [args.conch,args.glob]},
                 upstream_queue_binding='Local POSIX FIONREAD==0 acquired after bounded 128-byte ingress; failures nonempty. The adapter passes this observation to the actual Manager poll. Native local_step source is hashed but its kernel pipe_info syscall is not executed by this host test.',
                 scope='Actual shell.session/native control methods/one-byte input/local Manager/TTY; host syscall adapters only; no SSH transport or non-PTY recovery claim')
    (out/'SOURCE-BINDING.json').write_text(json.dumps(binding,indent=2)+'\n')
    (out/'compiler.txt').write_bytes(subprocess.run(['rustc','+1.95.0','-vV'],check=True,stdout=subprocess.PIPE).stdout)
    with (out/'compile.log').open('wb')as log:
        subprocess.run(['rustc','+1.95.0','--edition=2024',str(file),'--extern','conch_parser='+str(args.conch),'--extern','glob='+str(args.glob),'-L','dependency='+str(args.deps),'-o',str(out/'composition')],stdout=log,stderr=subprocess.STDOUT,check=True)
    cases=args.case or ['local-heredoc','local-quote','local-stale','local-end','local-disconnect','local-backlog']
    results=[]
    for case in cases:
        frontend,scenario=case.split('-',1)
        if frontend != 'local': raise ValueError('only the admitted local-console slice is in scope')
        with (out/(case+'.log')).open('wb')as log:
            child=subprocess.run([str(out/'composition'),frontend,scenario,str(out/(case+'.effects'))],stdout=log,stderr=subprocess.STDOUT,timeout=45)
        results.append(dict(case=case,exit_code=child.returncode))
        (out/'RESULTS.json').write_text(json.dumps(results,indent=2)+'\n')
        if child.returncode:raise RuntimeError('composition control failed: '+case)
    print(json.dumps(dict(scope=binding['scope'],cases=results,result='PASS')))

if __name__=='__main__':main()
