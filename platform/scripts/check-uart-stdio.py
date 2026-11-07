#!/usr/bin/env python3
"""Opt-in UART transport fixture for boot-operator --local-only --console.

A 64 KiB readonly x86 ROM echoes a line and exits. It runs no ABSD kernel,
service, credentials or network stack. Its sole drive is readonly. The real
launcher, recovery precheck/exit classifier, stdio chardev, PTY and logfile
are exercised; a small adapter substitutes this ROM for the product ISO.
--prepare-only assembles and inventories inputs without starting an emulator.
The campaign owner must serialize --run under the existing guest-slot rule.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import pty
import runpy
import select
import signal
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'scripts'))
sys.dont_write_bytecode=True

ROM_SOURCE=r'''.code16
.section .text
.global _start
_start:
    cli
    cld
    movw $0xf000,%ax
    movw %ax,%ds
    movw $0x3f9,%dx
    xorb %al,%al
    outb %al,%dx
    movw $0x3fb,%dx
    movb $0x80,%al
    outb %al,%dx
    movw $0x3f8,%dx
    movb $1,%al
    outb %al,%dx
    movw $0x3f9,%dx
    xorb %al,%al
    outb %al,%dx
    movw $0x3fb,%dx
    movb $3,%al
    outb %al,%dx
    movw $0x3fc,%dx
    movb $3,%al
    outb %al,%dx
    movw $ready,%si
send_string:
    lodsb
    testb %al,%al
    jz string_end
    movb %al,%bl
send_wait:
    movw $0x3fd,%dx
    inb %dx,%al
    testb $0x20,%al
    jz send_wait
    movw $0x3f8,%dx
    movb %bl,%al
    outb %al,%dx
    jmp send_string
string_end:
    cmpw $after_ready,%si
    je send_prefix
    cmpw $after_prefix,%si
    je receive
    movw $0xf4,%dx
    movb $1,%al
    outb %al,%dx
halt:
    hlt
    jmp halt
send_prefix:
    movw $prefix,%si
    jmp send_string
receive:
    movw $0x3fd,%dx
    inb %dx,%al
    testb $1,%al
    jz receive
    movw $0x3f8,%dx
    inb %dx,%al
    movb %al,%bl
receive_tx:
    movw $0x3fd,%dx
    inb %dx,%al
    testb $0x20,%al
    jz receive_tx
    movw $0x3f8,%dx
    movb %bl,%al
    outb %al,%dx
    cmpb $10,%bl
    jne receive
    movw $done,%si
    jmp send_string
ready:
    .asciz "UART FIXTURE READY\n"
after_ready:
prefix:
    .asciz "UART FIXTURE GOT: "
after_prefix:
done:
    .asciz "UART FIXTURE DONE\n"
.org 0xfff0
    ljmp $0xf000,$_start
.org 0x10000
'''
PAYLOAD=b'uart-fixture-input-42\n'
EXPECTED=b'UART FIXTURE READY\nUART FIXTURE GOT: '+PAYLOAD+b'UART FIXTURE DONE\n'

def digest(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1<<20),b''):value.update(block)
    return value.hexdigest()

def launcher_sources():
    # Only the shell's Python entrypoints are named here. Follow their actual
    # local imports with the existing source-only cohort resolver.
    resolver=runpy.run_path(str(ROOT/'scripts/check-harness-cohort.py'))
    available={path.relative_to(ROOT).as_posix() for path in (ROOT/'scripts').rglob('*.py')}
    pending=['scripts/operator_cpus.py','scripts/boot_operator_supervisor.py',
             'scripts/storage_fence_resume.py']
    seen=set()
    while pending:
        path=pending.pop()
        if path in seen:continue
        seen.add(path)
        try:
            pending.extend(resolver['local_imports']((ROOT/path).read_bytes(),path,available)-seen)
        except (resolver['Refused'],SyntaxError) as error:
            raise ValueError('launcher dependency closure: '+str(error)) from error
    return sorted(path.removeprefix('scripts/') for path in seen)

def prepare(out,qemu):
    if out.exists():raise ValueError('fixture output must be a new owned directory')
    out.mkdir(parents=True)
    (out/'OWNER').write_text('config-recovery lane / parent operability-148 owner\npurpose: readonly UART transport proof; no ABSD guest claim\nretire: parent review and composed runtime no longer depend on this fixture\n')
    (out/'uart.S').write_text(ROM_SOURCE)
    subprocess.run(['as','--32','-o',str(out/'uart.o'),str(out/'uart.S')],check=True)
    subprocess.run(['objcopy','-O','binary','-j','.text',str(out/'uart.o'),str(out/'uart.bin')],check=True)
    rom=(out/'uart.bin').read_bytes()
    if len(rom)!=65536 or rom[0xfff0:0xfff5]!=b'\xea\x00\x00\x00\xf0':raise ValueError('ROM reset vector or bound changed')
    import test_storage_fence_resume as fixture
    target=out/'machine';target.mkdir()
    fixture.build_image(target/'absd-operator.img',fixture.machine_files(state=False,guard_state='fresh'))
    (target/'absd-operator.iso').write_bytes(b'not an ABSD ISO; UART transport substitution fixture\n')
    (target/'TARGET').write_text('readonly-uart-transport-fixture\n')
    scripts=out/'scripts';scripts.mkdir()
    (scripts/'boot-operator.sh').write_bytes((ROOT/'scripts/boot-operator.sh').read_bytes())
    # Keep the actual precheck/exit implementation and CPU wrapper. The fixture
    # is a ROM, so the served ABSD RAM profile is replaced by a 16 MiB adapter.
    sources=launcher_sources()
    for name in sources:
        (scripts/name).parent.mkdir(parents=True,exist_ok=True)
        (scripts/name).write_bytes((ROOT/'scripts'/name).read_bytes())
    (scripts/'served_ram.py').write_text('import os,sys\nos.execvp(sys.argv[2],sys.argv[2:])\n')
    (scripts/'operator_image.py').write_text('raise SystemExit("local-only must not inspect the endpoint")\n')
    adapter=out/'uart-qemu'
    adapter.write_text('''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
root=Path(__file__).resolve().parent
config=json.loads((root/'fixture.json').read_text())
source=sys.argv[1:];args=[];i=0
while i<len(source):
    value=source[i]
    if value=='-cdrom':i+=2;continue
    if value=='-drive':args += [value,source[i+1]+',media=cdrom,readonly=on'];i+=2;continue
    args.append(value);i+=1
args=['-machine','pc,accel=tcg','-m','16','-bios',str(root/'uart.bin'),*args]
(root/'actual-qemu-argv.json').write_text(json.dumps([config['qemu'],*args],indent=2)+'\\n')
os.execvp(config['qemu'],[config['qemu'],*args])
''');adapter.chmod(0o700)
    launch_inputs={name:digest(scripts/name) for name in ['boot-operator.sh',*sources]}
    metadata={'schema':1,'scope':'readonly UART transport; no ABSD execution','qemu':qemu,'root':str(ROOT),'launcher_sha256':digest(ROOT/'scripts/boot-operator.sh'),'launcher_inputs_sha256':launch_inputs,'rom_sha256':digest(out/'uart.bin'),'disk_sha256':digest(target/'absd-operator.img'),'payload_hex':PAYLOAD.hex(),'expected_log_hex':EXPECTED.hex(),'forecast_guest_ram_bytes':16<<20,'guest_drive':'readonly=on; no guest storage writes','prepared_without_emulator':True}
    (out/'fixture.json').write_text(json.dumps(metadata,indent=2)+'\n')
    return metadata

def run(out):
    meta=json.loads((out/'fixture.json').read_text());target=out/'machine'
    if digest(ROOT/'scripts/boot-operator.sh')!=meta['launcher_sha256']:raise ValueError('launcher changed after fixture preparation')
    if set(meta['launcher_inputs_sha256'])!={'boot-operator.sh',*launcher_sources()}:
        raise ValueError('launcher input identity closure changed after fixture preparation')
    for name, expected in meta['launcher_inputs_sha256'].items():
        if digest(ROOT/'scripts'/name)!=expected or digest(out/'scripts'/name)!=expected:
            raise ValueError('launcher input changed after fixture preparation: '+name)
    if digest(out/'uart.bin')!=meta['rom_sha256'] or digest(target/'absd-operator.img')!=meta['disk_sha256']:raise ValueError('fixture inputs changed')
    master,slave=pty.openpty();transcript=bytearray();sent=False;proc=None
    env=dict(os.environ,ABSD_QEMU=str(out/'uart-qemu'),ABSD_OPERATOR_CPUS='1')
    started=time.monotonic();error=None
    try:
        proc=subprocess.Popen(['sh',str(out/'scripts/boot-operator.sh'),'--local-only','--console',str(target)],stdin=slave,stdout=slave,stderr=slave,env=env,start_new_session=True)
        os.close(slave);slave=-1
        deadline=started+15
        while time.monotonic()<deadline:
            ready,_,_=select.select([master],[],[],0.1)
            if ready:
                try:block=os.read(master,65536)
                except OSError:break
                if not block:break
                transcript.extend(block)
                if not sent and b'UART FIXTURE READY' in transcript:
                    os.write(master,PAYLOAD);sent=True
            if proc.poll() is not None and not ready:break
        if proc.poll() is None:raise RuntimeError('UART fixture exceeded its 15-second deadline')
        if proc.returncode!=0:raise RuntimeError(f'launcher exited {proc.returncode}')
        if not sent:raise RuntimeError('ROM never reached UART readiness')
        if (target/'console.log').read_bytes()!=EXPECTED:raise RuntimeError('actual stdio UART logfile differs from the complete expected exchange')
        if digest(target/'absd-operator.img')!=meta['disk_sha256']:raise RuntimeError('readonly fixture drive changed')
    except Exception as failure:error=str(failure)
    finally:
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid,signal.SIGTERM)
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=3)
        if slave!=-1:os.close(slave)
        os.close(master)
        (out/'transcript.bin').write_bytes(transcript)
        receipt={'schema':1,'scope':meta['scope'],'launcher_sha256':meta['launcher_sha256'],'rom_sha256':meta['rom_sha256'],'qemu':meta['qemu'],'seconds':time.monotonic()-started,'outcome':'PASS' if error is None else 'FAIL','error':error,'input_sent':sent,'returncode':None if proc is None else proc.returncode,'disk_sha256_after':digest(target/'absd-operator.img'),'retirement':'parent owns fixture until review/composed runtime no longer depend on it'}
        (out/'RESULT.json').write_text(json.dumps(receipt,indent=2)+'\n')
    if error is not None:raise ValueError(error)
    print('UART STDIO READONLY FIXTURE PASS; no ABSD guest claim')

def main():
    parser=argparse.ArgumentParser(description=__doc__);mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare-only',action='store_true');mode.add_argument('--run',action='store_true')
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--qemu',default='qemu-system-x86_64')
    args=parser.parse_args();out=args.out.resolve()
    if args.prepare_only:prepare(out,args.qemu);print('UART STDIO FIXTURE PREPARED; emulator not started')
    else:run(out)

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError) as error:sys.exit('UART fixture refused: '+str(error))
