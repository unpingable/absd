#!/usr/bin/env python3
"""One bounded follow-on Mac/HVF VM. No retry or accelerator fallback."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import socket
import threading
import time
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--image', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--source', required=True)
p.add_argument('--cpus', type=int, choices=(1, 2, 4), required=True)
p.add_argument('--control', choices=('none', 'early-publication', 'feature-guard', 'fp-restore', 'gic3'), default='none')
p.add_argument('--start-delay', type=float, default=3)
p.add_argument('--ram-mib', type=int, choices=(256, 512, 768), default=512)
p.add_argument('--gic', type=int, choices=(2, 3), default=2)
p.add_argument('--block-slot', type=int, choices=(0, 31))
p.add_argument('--reset', action='store_true')
p.add_argument('--reboot', action='store_true')
a = p.parse_args()
if a.reboot:
    assert a.cpus > 1 and a.control == 'none'
    a.reset = True
a.output.mkdir(parents=True, exist_ok=False)
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def save(name, value):
    (a.output / name).write_text(json.dumps(value, indent=2) + '\n')
qemu = '/opt/homebrew/bin/qemu-system-aarch64'
serial = a.output / 'serial.log'
assert (a.gic == 3) == (a.control == 'gic3'), 'GICv3 only admitted as explicit refusal control'
command = [qemu, '-machine', f'virt-8.2,gic-version={a.gic}', '-accel', 'hvf', '-cpu', 'host', '-smp', str(a.cpus), '-m', f'{a.ram_mib}M', '-kernel', str(a.image.resolve()), '-display', 'none', '-serial', 'file:' + str(serial.resolve()), '-nic', 'none', '-no-reboot']
fixture = None
if a.block_slot is not None:
    assert a.control == 'none' and not a.reboot and not a.reset
    fixture = a.output / 'readonly-block.img'
    with fixture.open('wb') as f:
        f.write(b'ABSDARM3'); f.truncate(2*1024*1024)
    command += ['-global', 'virtio-mmio.force-legacy=false', '-drive', 'if=none,id=blk,file='+str(fixture.resolve())+',format=raw,readonly=on', '-device', f'virtio-blk-device,drive=blk,bus=virtio-mmio-bus.{a.block_slot}']
if a.cpus > 1:
    bootargs = f'absd-arm-smp={a.cpus}'
    if a.control == 'early-publication':
        bootargs += ' absd-arm-control=early-publication'
    if a.reset:
        bootargs += ' absd-arm-reset=1'
    command += ['-append', bootargs]
qmp_path = a.output.parent / 'q.sock'
if a.reboot:
    command.remove('-no-reboot')
    command += ['-qmp', 'unix:' + str(qmp_path) + ',server=on,wait=off']
record = dict(source=a.source, image_sha256=sha(a.image), runner_sha256=sha(Path(__file__)), started=time.time(), supervisor_pid=os.getpid(), cpus=a.cpus, accelerator='hvf', machine=f'virt-8.2,gic-version={a.gic}', ram_bytes=a.ram_mib*1024*1024, ram_base=0x40000000, block_slot=a.block_slot, fixture_sha256=sha(fixture) if fixture else None, control=a.control, reset=a.reset, reboot=a.reboot, command=command)
save('start.json', record)
def validate_trace(text, detail):
    markers = ['ABSD ARM64 KERNEL BOOT', 'ARM MMU OK', 'ARM EXCEPTION OK', 'ARM TIMER OK', 'ARM EL0 ENTER', 'PORTABLE MEMORY VALIDATION OK', 'PORTABLE HANDLE ISOLATION RIGHTS TRANSITIONS OK', 'PORTABLE FAULT ISOLATION OK', 'PORTABLE FP SIMD PREEMPTION OK', 'PORTABLE CAPACITY REUSE 200 REAPS OK', 'PORTABLE MACHINE AUTHORITY REFUSAL OK', 'PORTABLE SEMANTICS OK', 'PORTABLE B3 FAULT RECLAMATION FP HEALTH OK', 'ARM A2 OK', 'ARM PSCI POWEROFF']
    if a.reset:
        assert a.cpus > 1 and 'ARM PSCI POWEROFF' not in text
        markers[-1] = 'ARM PSCI RESET'
    if a.cpus > 1:
        markers += [f'ARM SMP ONLINE cpus={a.cpus}', 'ARM SMP TIMER IPI OK', 'ARM WEAK MEMORY WITNESSES OK', 'PORTABLE CROSS CPU STOP OK', 'ARM SMP PARK RECLAIM OK', 'ARM B1 OK']
        rows = re.findall(r'ARM SMP CPU cpu=(\d+) dispatches=(\d+) timers=(\d+) ipis=(\d+)', text)
        assert len(rows) == a.cpus and {int(r[0]) for r in rows} == set(range(a.cpus)), 'CPU witness coverage'
        assert all(all(int(n) > 0 for n in row[1:]) for row in rows), 'CPU execution/timer/IPI missing'
        migration = re.search(r'ARM SMP MIGRATION fp3=(\d+) fp4=(\d+) stops=(\d+)', text)
        assert migration and all(int(n) > 0 for n in migration.groups()), 'FP migration/stop missing'
        stops = re.findall(r'ARM STOP (REQUEST|OBSERVE|DEPART|ACK|RECLAIM) cpu=(\d+) slot=(\d+) pid=(\d+) epoch=(\d+)', text)
        chains = {}
        for phase, *identity in stops:
            chains.setdefault(tuple(identity), []).append(phase)
        # A task already in a syscall can depart directly under the lock.
        # The dedicated non-syscalling child must observe a remote IRQ stop.
        direct = ['REQUEST', 'DEPART', 'ACK', 'RECLAIM']
        observed = ['REQUEST', 'OBSERVE', 'DEPART', 'ACK', 'RECLAIM']
        assert chains and all(chain in (direct, observed) for chain in chains.values()), 'exact stop/departure/reclaim chain'
        assert observed in chains.values(), 'no remote interrupt stop observation'
        spinning = re.findall(r'SPAWN OK pid=(\d+) parent=1 program=hello-a', text.split('PORTABLE CROSS CPU STOP OK')[0])
        assert spinning and any(k[2] == spinning[-1] and v == observed for k, v in chains.items()), 'dedicated non-syscalling child lacks exact remote stop chain'
        names = ['message-passing', 'store-load-publication', 'queue-handoff', 'ownership-token', 'generation-replacement', 'task-stop-observation', 'refcount-reclaim', 'wake-after-state', 'lock-handoff', 'object-visibility']
        markers += [f'ARM LITMUS case={name} peer={peer} witnesses=16 PASS' for peer in range(1, a.cpus) for name in names]
        detail.update(cpu_witnesses=rows, migration=migration.groups(), stop_chains=[dict(identity=k, phases=v) for k, v in chains.items()])
    if a.block_slot is not None:
        markers += ['ARM VIRTIO BLOCK READY', 'PORTABLE VIRTIO READONLY OK']
        mmio = re.findall(r'ARM BLOCK MMIO base=(0x[0-9a-f]+)', text)
        assert len(mmio) == 1 and int(mmio[0],16) in (0x0a000000,0x0a003e00), 'end transport MMIO not discovered'
        detail['block_mmio'] = mmio[0]
        assert sha(fixture) == record['fixture_sha256'], 'read-only fixture changed'
    region = re.findall(r'ARM RAM REGION base=(0x[0-9a-f]+) bytes=(0x[0-9a-f]+)',text)
    assert len(region) == 1 and tuple(int(v,16) for v in region[0]) == (0x40000000,a.ram_mib*1024*1024), 'FDT RAM does not match configuration'
    detail['ram_region'] = region[0]
    assert all(text.splitlines().count(marker) == 1 for marker in markers), 'missing/repeated semantic milestone'
    assert 'PANIC' not in text and 'ASSERTION FAILED' not in text, 'kernel/user refusal of qualification'
    detail['tests'] = markers

reboot_state = {'resets': [], 'events': []}
monitor = None

def observe_reboots():
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(48)
            deadline = time.monotonic() + 3
            while True:
                try:
                    connection.connect(str(qmp_path))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    assert time.monotonic() < deadline, 'QMP readiness timeout'
                    time.sleep(.01)
            stream = connection.makefile('rwb')
            reboot_state['greeting'] = json.loads(stream.readline())
            stream.write(b'{"execute":"qmp_capabilities","id":1}\n')
            stream.flush()
            while True:
                line = stream.readline()
                assert line, 'QMP ended before second guest reset'
                event = json.loads(line)
                reboot_state['events'].append(event)
                if event.get('event') == 'RESET':
                    assert event.get('data', {}).get('guest') is True, 'reset was not guest requested'
                    reboot_state['resets'].append(event)
                    if len(reboot_state['resets']) == 2:
                        # Both complete guest suites have already printed RESET.
                        # End this campaign VM; never leave an infinite reset loop.
                        stream.write(b'{"execute":"quit","id":2}\n')
                        stream.flush()
                        return
    except Exception as error:
        reboot_state['error'] = str(error)

process = None
try:
    inventory = ['uname -a', 'sw_vers', 'sysctl -n machdep.cpu.brand_string', 'sysctl -n hw.memsize', qemu + ' --version']
    record['host'] = {cmd: subprocess.check_output(cmd.split(), text=True).strip() for cmd in inventory}
    save('command.json', command)
    time.sleep(a.start_delay)
    with (a.output / 'runtime.log').open('w') as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        record['qemu_started'] = time.time()
        if a.reboot:
            monitor = threading.Thread(target=observe_reboots, daemon=True)
            monitor.start()
        (a.output / 'producer.pid').write_text(str(process.pid) + '\n')
        try:
            status = process.wait(timeout=45)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            status = 'timeout'
    if monitor is not None:
        monitor.join(timeout=2)
        assert not monitor.is_alive(), 'reboot observer did not finish'
        save('qmp.json', reboot_state)
    text = serial.read_text() if serial.exists() else ''
    record.update(qemu_status=status, serial_sha256=sha(serial) if serial.exists() else None)
    if a.control == 'gic3':
        runtime = (a.output / 'runtime.log').read_text()
        assert ('FDT unsupported GIC version' in text) or (status != 0 and 'HVF' in runtime and 'GIC' in runtime), 'GICv3 did not explicitly refuse at kernel or HVF boundary'
        assert 'ARM A2 OK' not in text and 'ARM B1 OK' not in text
        record['negative_oracle'] = 'GICv3 explicit kernel/HVF refusal'
    elif a.control != 'none':
        reasons = {'early-publication': 'deterministic early publication exposed stale value', 'feature-guard': 'ARM SMP feature absent', 'fp-restore': 'USER EXIT pid=1 status=101'}
        assert reasons[a.control] in text, 'negative control did not expose expected failure'
        assert 'ARM B1 OK' not in text and 'ARM A2 OK' not in text, 'negative reached acceptance'
        record['negative_oracle'] = reasons[a.control]
    else:
        assert status == 0, f'QEMU status {status}'
        traces = [text]
        if a.reboot:
            assert not reboot_state.get('error') and len(reboot_state['resets']) == 2, 'two guest reset events required'
            assert 'PANIC' not in text, 'panic across reboot boundary'
            chunks = text.split('ABSD ARM64 KERNEL BOOT\n')
            assert len(chunks) >= 3, 'same-VM second boot missing'
            traces = ['ABSD ARM64 KERNEL BOOT\n' + chunk for chunk in chunks[1:3]]
            record['partial_boot_after_second_reset'] = len(chunks) > 3
        boots = []
        for trace in traces:
            detail = {}
            validate_trace(trace, detail)
            boots.append(detail)
        record['boots'] = boots
        if not a.reboot:
            record.update(boots[0])
    record['disposition'] = 'PASS'
except Exception as error:
    record.update(disposition='FAIL', error=str(error))
finally:
    if process is not None and process.poll() is None:
        process.kill()
        process.wait()
    record.update(ended=time.time(), vm_remains=False if process is None else process.poll() is None)
    if a.reboot:
        save('qmp.json', reboot_state)
    save('result.json', record)
    (a.output / 'status').write_text('0\n' if record['disposition'] == 'PASS' else '1\n')
raise SystemExit(0 if record['disposition'] == 'PASS' else 1)
