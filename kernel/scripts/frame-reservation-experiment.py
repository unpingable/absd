#!/usr/bin/env python3
"""Isolated foreground build/guest fixture. Guest use requires a steward slot."""
import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def run(cmd, **kw):
    print('+', *map(str,cmd), flush=True)
    subprocess.run(list(map(str,cmd)), cwd=ROOT, check=True, **kw)

def build(out):
    users = out / 'users'
    env = dict(os.environ, CARGO_BUILD_JOBS='1')
    env['RUSTFLAGS'] = ('-C relocation-model=static -C code-model=large -C link-arg=-nostdlib '
        '-C link-arg=-static -C link-arg=-no-pie -C link-arg=-Wl,-T,' + str(ROOT/'user/linker.ld'))
    common=['cargo','build','--release','--manifest-path',ROOT/'user/Cargo.toml',
            '--features','reservation-fixture','--target','x86_64-unknown-linux-gnu','--target-dir',users]
    run(common+['--bin','reservation_actor'],env=env)
    env['ABSD_RESERVATION_ACTOR_EMBED']=str(users/'x86_64-unknown-linux-gnu/release/reservation_actor')
    run(common+['--bin','reservation_supervisor'],env=env)
    env.pop('RUSTFLAGS')
    bad=out/'bad.elf'
    bad.write_bytes(b'\x7fELF\x02'+bytes(59))
    env['ABSD_OWNER_2_ELF']=str(bad)
    env.update(ABSD_EXTERNAL_USER_ELF=str(users/'x86_64-unknown-linux-gnu/release/reservation_supervisor'),
               ABSD_OWNER_1_ELF=str(users/'x86_64-unknown-linux-gnu/release/reservation_actor'))
    for mode in ['baseline','protected']:
        target = out/'target'
        env['CARGO_TARGET_DIR'] = str(target)
        cmd=['cargo','rustc','--bin','absd-kernel']
        if mode == 'protected': cmd += ['--features','frame-admission-qualification,spawn-image-rollback-test']
        run(cmd+['--','-C','relocation-model=static','-C','code-model=kernel','-C','no-redzone=yes',
                 '-C','link-arg=-Tlinker.ld','-C','link-arg=-nostdlib','-C','link-arg=-no-pie'],env=env)
        iso=out/mode/'iso/boot'
        (iso/'grub').mkdir(parents=True,exist_ok=True)
        (iso/'absd-kernel').write_bytes((target/'debug/absd-kernel').read_bytes())
        (iso/'grub/grub.cfg').write_text('set timeout=0\nmenuentry "frame experiment" {\n multiboot2 /boot/absd-kernel external\n boot\n}\n')
        run(['grub-mkrescue','-o',out/(mode+'.iso'),iso.parent])

def check(log, mode):
    raw=log.read_bytes()
    chunks=re.findall(rb'^EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)$',raw,re.M)
    output=bytearray()
    for offset,data in chunks:
        assert int(offset,16)==len(output), 'output offset'
        output.extend(bytes.fromhex(data.decode()))
    decoded=log.with_suffix('.decoded.txt')
    decoded.write_bytes(output)
    # Reuse the existing byte-count/digest oracle for the complete captured stream.
    run(['python3','scripts/check-external-output.py',log,decoded])
    for marker in [b'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0',b'EXTERNAL WORKLOAD OK',b'ABSD BOOT OK']:
        assert marker in raw, marker
    assert not re.search(rb'PANIC|KERNEL FAULT|EXTERNAL WORKLOAD FAILED',raw)
    for marker in [b'SLOT PRESSURE OK occupied=16', b'B EXHAUSTED', b'B REEXHAUSTED', b'refusal=-12 retries=3',b'exact_return=true']:
        assert marker in output, (marker,output)
    if mode=='protected':
        assert b'FRAME RESERVATION TERMINAL idle=0' in raw
        for marker in [b'MODE protected=true',b'INITIALIZATION REFUSALS OK',b'LIFECYCLE OK cycles=64',
                       b'IMAGE ABORT OK cycles=64',b'borrowed_image=true',b'NEGATIVE OK',b'PRESSURE OK',b'A CAPACITY OK total=640 used=640',b'SUPERVISOR HEADROOM OK',b'RESERVATION RESULT protected=true']:
            assert marker in output, (marker,output)
        assert b'A REFUSED' not in output
    else:
        assert b'A REFUSED -12' in output and b'RESERVATION RESULT protected=false' in output
    print(output.decode(),end='')

def guest(out, mode, accel, memory):
    log=out/(mode+'.serial.log')
    cmd=['nice','-n','10','taskset','-c','2-5,8-11','qemu-system-x86_64','-accel',accel,'-m',str(memory),'-smp','1',
         '-cdrom',str(out/(mode+'.iso')),'-display','none','-serial','file:'+str(log),
         '-no-reboot','-no-shutdown','-nic','none','-device','isa-debug-exit,iobase=0xf4,iosize=0x04']
    result=subprocess.run(cmd,cwd=ROOT,timeout=120,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (out/(mode+'.qemu.txt')).write_bytes(result.stdout)
    assert result.returncode==3, ('qemu status', result.returncode,result.stdout)
    check(log,mode)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['build','guest','check'])
    p.add_argument('--out',type=Path,default=ROOT/'build/frame-experiment')
    p.add_argument('--mode',choices=['baseline','protected'],default='protected')
    p.add_argument('--accel',choices=['kvm','tcg'],default='kvm')
    p.add_argument('--memory',type=int,default=32)
    a=p.parse_args(); out=a.out.resolve(); out.mkdir(parents=True,exist_ok=True)
    if a.action=='build': build(out)
    elif a.action=='guest': guest(out,a.mode,a.accel,a.memory)
    else: check(out/(a.mode+'.serial.log'),a.mode)
