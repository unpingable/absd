#!/usr/bin/env python3
"""Deterministic enrollment failure after durable dirty arming, using F3 unchanged.

Timed process cuts may miss the dirty interval. This holds an ordinary write
after the one-sector guard, then checks that both enrollment and file-server
retries refuse before any mutation while the backend still owns that write.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import storage_fence_guest as guest
import storage_fence_host as host
import storage_fence_state as guard


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('platform', 'kernel', 'f3', 'work'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    root, kernel, f3 = (Path(getattr(args,n)).resolve() for n in ('platform','kernel','f3'))
    work = Path(args.work).resolve();work.mkdir(parents=True, exist_ok=False, mode=0o700)
    enroll = load(root/'scripts/enroll-matrix.py', 'enroll_for_fence')
    blk = load(f3/'run-blkstall.py', 'enroll_f3')
    fixture = enroll.Matrix(SimpleNamespace(work=work/'fixture', kernel=str(kernel),
        importer=str(root/'fixture-import.elf'), enroll=str(root/'absd-enroll.elf')))
    fixture.build()
    identity, initial = host.marker(fixture.blank)
    if initial != guard.FRESH:raise RuntimeError('enrollment fixture is not fresh')
    result = {'backend':'ata', 'fixture':fixture.result, 'guard_identity':identity}
    with tempfile.TemporaryDirectory(prefix='fence-enroll-') as sockets:
        export, control = Path(sockets)/'export.sock', Path(sockets)/'control.sock'
        device_log = work/'device.jsonl'
        nbd = subprocess.Popen([sys.executable, str(f3/'nbd-stall.py'), str(fixture.blank),
            str(export), str(control), str(device_log)], stdout=subprocess.PIPE, text=True)
        try:
            if nbd.stdout.readline().strip() != 'NBD STALL READY':raise RuntimeError('NBD not ready')
            os.environ.update(F3_DRIVE='nbd:'+str(export), F3_REAL_QEMU='qemu-system-x86_64')
            os.environ.pop('F3_QMP',None)
            original = enroll.qemu_argv
            def argv(*arguments):
                words = original(*arguments);words[0] = str(f3/'f3-qemu');return words
            enroll.qemu_argv = argv
            # This small enrollment writes isolated sectors, never F3's
            # four-sector sequential run. Its fresh fixture allocates the
            # key data after the fixed guard. Hold the first such data
            # write, leaving the guard write and flush untouched.
            rule = {'arm':'write', 'hold':blk.blk_classify.HOLD_BOUND['ata']+5.0,
                    'min_offset':identity[2]+512, 'ghost':True}
            blk.control(control, rule)
            payload = enroll.stream(enroll.record(enroll.KEYS, enroll.key_line(1)))
            status, raw, killed = enroll.boot_enroll(fixture.enroll_iso, fixture.blank,
                                                    work/'failed.serial.log', payload)
            text = enroll.worker_text(raw)
            if (status != 7 or killed or raw.count(b'ABSD KERNEL BOOT\n') != 1
                    or 'ENROLL REFUSED reason=storage ' not in text or 'ENROLL OK' in text):
                raise RuntimeError('enrollment did not fail on its ordinary write: '+text[-1200:])

            def events(partial=False):
                text = device_log.read_text()
                if partial:text = text[:text.rfind('\n')+1]
                elif not text.endswith('\n'):raise RuntimeError('incomplete terminal device event')
                return [json.loads(line) for line in text.splitlines()]
            end = time.monotonic()+rule['hold']+30
            while True:
                observed = events(partial=True)
                held = [event for event in observed if event.get('ghost')]
                if held:break
                if time.monotonic()>end:raise RuntimeError('no retained ordinary enrollment write')
                time.sleep(0.2)
            writes = [event for event in observed if event.get('event')=='arrive' and event.get('type')=='write']
            if len(held)!=1 or not writes or (writes[0]['offset'],writes[0]['length'])!=(identity[2],512):
                raise RuntimeError('dirty marker was not the first write before retained ordinary I/O')
            mark = next((event for event in observed if event.get('event')=='reply'
                         and event.get('seq')==writes[0]['seq']),None)
            flushed = any(event.get('event')=='reply' and event.get('type')=='flush'
                          and event.get('performed') and writes[0]['seq']<event['seq']<held[0]['seq']
                          for event in observed)
            if not mark or mark.get('error')!=0 or not mark.get('performed') or not flushed:
                raise RuntimeError('dirty write/flush did not complete before ordinary I/O')
            if host.marker(fixture.blank)!=(identity,guard.encode('dirty')):
                raise RuntimeError('failed enrollment did not retain dirty state')
            cursor = len(observed)
            before = hashlib.sha256(fixture.blank.read_bytes()).hexdigest()
            status, retry, killed = enroll.boot_enroll(fixture.enroll_iso, fixture.blank,
                                                      work/'retry.serial.log', payload)
            if (status!=7 or killed or retry.count(b'ABSD KERNEL BOOT\n')!=1
                    or 'ENROLL REFUSED reason=writable-guard ' not in enroll.worker_text(retry)
                    or guest.accounting(retry.decode(errors='replace'))!=(0,0,0)
                    or hashlib.sha256(fixture.blank.read_bytes()).hexdigest()!=before):
                raise RuntimeError('dirty enrollment retry was not an unchanged zero-I/O refusal')
            target = SimpleNamespace(kernel=kernel, root=root, work=work, image=fixture.blank,
                                     proc=None, qemu='qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand')
            wrapper = shlex.quote(str(f3/'f3-qemu'))+' -cpu max,vendor=GenuineIntel,+rdrand'
            result['served_retry'] = guest.refused_cold_boot(target,'ata','enrollment-served',
                                                            previous='none',qemu=wrapper)
            later = [event for event in events()[cursor:] if event.get('event')=='arrive']
            if any(event.get('type')!='read' for event in later):
                raise RuntimeError('a retry sent non-read requests to the retained-write backend')
            answer = blk.control(control, {'apply_ghost':True})
            if [event['seq'] for event in answer.get('applied',[])]!=[held[0]['seq']]:
                raise RuntimeError('late effect did not identify exactly the original retained command')
            if host.marker(fixture.blank)!=(identity,guard.encode('dirty')):
                raise RuntimeError('late ordinary write changed the fixed dirty marker')
            result.update(verdict='PASS', retained_request=held[0], late_effect=answer,
                          enrollment_retry_zero_io=True, successor_request_kinds=sorted({e['type'] for e in later}))
            print('STORAGE FENCE ENROLLMENT OK dirty_before_ordinary_write=true retries_mutating_requests=0',flush=True)
        except BaseException as error:
            result.update(verdict='FAIL_OR_INCOMPLETE',error=repr(error));raise
        finally:
            (work/'result.json').write_text(json.dumps(result,indent=2)+'\n')
            nbd.terminate()
            try:nbd.wait(timeout=10)
            except subprocess.TimeoutExpired:nbd.kill();nbd.wait(timeout=10)


if __name__=='__main__':main()
