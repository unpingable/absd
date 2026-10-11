#!/usr/bin/env python3
"""Bounded KVM producer child; pin each vCPU before releasing guest execution."""
import json
import os
import re
import resource
from pathlib import Path
import socket
import subprocess
import sys
import time

out = Path(sys.argv[1]).resolve()
allowed = sorted(os.sched_getaffinity(0))
topology = {}
for cpu in allowed:
    base = Path(f'/sys/devices/system/cpu/cpu{cpu}/topology')
    topology[cpu] = (int((base / 'physical_package_id').read_text()),
                     int((base / 'core_id').read_text()))
count = int(os.environ.get('SMP_BENCH_VCPUS', '2'))
assert count in (1, 2, 4, 6)
if not allowed:
    raise RuntimeError('empty host CPU affinity set')
study = os.environ.get('SMP_TOPOLOGY', 'separate')
assert study in ('separate', 'smt')
first = allowed[0]
placement = [first]
if count > 1:
    if study == 'smt':
        if count != 2:
            raise RuntimeError('SMT study currently requires two vCPUs')
        candidates = [c for c in allowed if c != first and topology[c] == topology[first]]
        if not candidates:
            raise RuntimeError('no host SMT sibling pair')
        placement.append(candidates[0])
    else:
        seen = {topology[first]}
        for candidate in allowed:
            if topology[candidate][0] == topology[first][0] and topology[candidate] not in seen:
                placement.append(candidate)
                seen.add(topology[candidate])
                if len(placement) == count:
                    break
        if len(placement) != count:
            raise RuntimeError(f'not enough distinct physical cores for {count} vCPUs')

# Only scheduler qualification opts into a declared guest topology. Historical
# replay boots keep QEMU's previous `-smp N` defaults.
grub_cfg = out / 'iso/boot/grub/grub.cfg'
boot_lines = []
if grub_cfg.is_file():
    boot_lines = [line.split('#', 1)[0] for line in
                  grub_cfg.read_text().splitlines()
                  if line.lstrip().startswith('multiboot2 ')]
scheduler_test = any(re.search(r'(?<!\S)smp-scheduler-test(?!\S)', line)
                     for line in boot_lines)
if scheduler_test:
    declared = 6 if any(re.search(r'(?<!\S)smp-cpus=6(?!\S)', line) for line in boot_lines) else (4 if any(re.search(r'(?<!\S)smp-cpus=4(?!\S)', line) for line in boot_lines) else 2)
    if count != declared:
        raise RuntimeError('guest admission count differs from QEMU vCPU count')
extra_args = sys.argv[2:]
if scheduler_test and any(arg == '-smp' or arg.startswith('-smp=') for arg in extra_args):
    raise RuntimeError('QEMU -smp override is not allowed for smp-scheduler-test')
guest_topology = None
if scheduler_test:
    guest_topology = {'sockets': 1,
                      'cores': count if study == 'separate' else 1,
                      'threads': 1 if study == 'separate' else 2}
    guest_smp = (f"{count},sockets={guest_topology['sockets']},"
                 f"cores={guest_topology['cores']},"
                 f"threads={guest_topology['threads']}")
else:
    guest_smp = str(count)

command = ['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-smp', guest_smp,
           '-m', '256M', '-cdrom', str(out / 'boot.iso'), '-display', 'none',
           '-serial', 'file:' + str(out / 'serial.log'), '-no-reboot', '-no-shutdown',
           '-nic', 'none', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
           '-S', '-qmp', f'unix:{out / "qmp.sock"},server=on,wait=off']
command.extend(extra_args)
with (out / 'qemu.log').open('w') as log:
    process = subprocess.Popen(command, stdout=log, stderr=log, stdin=subprocess.DEVNULL)
    try:
        connection = socket.socket(socket.AF_UNIX)
        connection.settimeout(5)
        for _ in range(100):
            try:
                connection.connect(str(out / 'qmp.sock'))
                break
            except FileNotFoundError:
                if process.poll() is not None:
                    raise RuntimeError('QEMU exited before QMP readiness')
                time.sleep(.05)
        stream = connection.makefile('rwb')
        greeting = json.loads(stream.readline())
        def request(name):
            stream.write((json.dumps({'execute': name}) + '\n').encode())
            stream.flush()
            while True:
                answer = json.loads(stream.readline())
                if 'return' in answer:
                    return answer['return']
                if 'error' in answer:
                    raise RuntimeError(answer)
        request('qmp_capabilities')
        kvm = request('query-kvm')
        assert kvm == {'enabled': True, 'present': True}, kvm
        vcpus = request('query-cpus-fast')
        assert len(vcpus) == count
        assert sorted(entry['cpu-index'] for entry in vcpus) == list(range(count))
        for entry in vcpus:
            assigned = placement[entry['cpu-index']]
            os.sched_setaffinity(entry['thread-id'], {assigned})
            entry['host-cpu'] = assigned
            entry['host-package'] = topology[assigned][0]
            entry['host-core'] = topology[assigned][1]
            entry['affinity'] = sorted(os.sched_getaffinity(entry['thread-id']))
            assert entry['affinity'] == [assigned]
        (out / 'vcpu-placement.json').write_text(json.dumps(
            {'qemu_pid': process.pid, 'qmp': greeting, 'kvm': kvm, 'vcpus': vcpus,
             'host_topology': study, 'guest_topology': guest_topology,
             'guest_topology_mode': 'explicit-smp-scheduler-test' if scheduler_test
             else 'legacy-qemu-default', 'command': command}, indent=2) + '\n')
        started = time.monotonic()
        request('cont')
        serial_events = {}
        serial_offset = 0
        partial = ''
        while True:
            serial = out / 'serial.log'
            if serial.exists():
                with serial.open() as capture:
                    capture.seek(serial_offset)
                    appended = capture.read()
                    serial_offset = capture.tell()
                complete = (partial + appended).split('\n')
                partial = complete.pop()
                for line in complete:
                    if line.startswith(('SMP BENCH START ', 'SMP BENCH DONE ',
                                        'SMP SCALE START ', 'SMP SCALE DONE ',
                                        'SMP APP SCALE START ', 'SMP APP SCALE DONE ')):
                        serial_events.setdefault(line, time.monotonic() - started)
            try:
                status = process.wait(timeout=.02)
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() - started > 120:
                    raise TimeoutError('bounded KVM run exceeded 120 seconds')
        # Drain the terminal tail after process.wait: exit may occur after the
        # last live read and before wait returns. Never invent a missing event.
        serial = out / 'serial.log'
        if serial.exists():
            with serial.open('r') as capture:
                capture.seek(serial_offset)
                complete = (partial + capture.read()).split('\n')
            for line in complete[:-1]:
                if line.startswith(('SMP BENCH START ', 'SMP BENCH DONE ',
                                    'SMP SCALE START ', 'SMP SCALE DONE ',
                                    'SMP APP SCALE START ', 'SMP APP SCALE DONE ')):
                    serial_events.setdefault(line, time.monotonic() - started)
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        (out / 'run-metrics.json').write_text(json.dumps({
            'wall_seconds': time.monotonic() - started,
            'qemu_user_seconds': usage.ru_utime, 'qemu_system_seconds': usage.ru_stime,
            'serial_observations_seconds': serial_events,
            'sampling_seconds': .02, 'topology': study, 'vcpus': count,
            'guest_topology': guest_topology,
            'guest_topology_mode': 'explicit-smp-scheduler-test' if scheduler_test
            else 'legacy-qemu-default',
        }, indent=2) + '\n')
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        (out / 'qemu.status').write_text(str(process.returncode) + '\n')
sys.exit(status)
