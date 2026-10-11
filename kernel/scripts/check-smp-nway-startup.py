#!/usr/bin/env python3
"""Closed receipt oracle for pre-INIT multicore device-startup pressure.

Usage: check-smp-nway-startup.py SERIAL_LOG --cpus 4|6 --site 1|2|3
       --placement VCPU_PLACEMENT_JSON [--self-test]

Site IDs are ATA=1, NVMe=2, and NIC probe=3.  This oracle proves progress
inside the bounded device-probe interval; it does not claim simultaneous
execution on the APs.
"""
import argparse
import json
import re
import sys
from pathlib import Path


def need(ok, message):
    if not ok:
        raise AssertionError(message)


def kv(line):
    return {k: v for k, v in re.findall(r'([a-z0-9_-]+)=([^\s]+)', line)}


def number(value, label):
    try:
        n = int(value, 10)
    except (TypeError, ValueError):
        raise AssertionError(f'{label} is not a decimal integer')
    need(n >= 0, f'{label} is negative')
    return n


def rows(lines, prefix):
    return [(i, line, kv(line)) for i, line in enumerate(lines)
            if line.startswith(prefix)]


def one(lines, exact, label):
    matches = [i for i, line in enumerate(lines) if line == exact]
    need(len(matches) == 1, f'{label} missing/duplicate')
    return matches[0]


def check_placement(path, cpus):
    doc = json.loads(Path(path).read_text())
    need(doc.get('kvm') == {'enabled': True, 'present': True},
         'QMP placement does not attest KVM')
    need(doc.get('host_topology') == 'separate'
         and doc.get('guest_topology_mode') == 'explicit-smp-scheduler-test'
         and doc.get('guest_topology') == {'sockets': 1, 'cores': cpus, 'threads': 1},
         'QMP placement topology mismatch')
    vcpus = doc.get('vcpus')
    need(isinstance(vcpus, list) and len(vcpus) == cpus,
         'QMP vCPU count mismatch')
    need({v.get('cpu-index') for v in vcpus} == set(range(cpus)),
         'QMP CPU indices incomplete/duplicated')
    host_cpus, host_cores = set(), set()
    for v in vcpus:
        host_cpu = v.get('host-cpu')
        host_core = (v.get('host-package'), v.get('host-core'))
        need(isinstance(host_cpu, int) and host_cpu not in host_cpus,
             'QMP host CPU reused')
        need(all(isinstance(x, int) for x in host_core) and host_core not in host_cores,
             'QMP host core reused')
        need(v.get('affinity') == [host_cpu], 'QMP vCPU is not pinned to one host CPU')
        host_cpus.add(host_cpu)
        host_cores.add(host_core)
    need(len(host_cpus) == len(host_cores) == cpus, 'QMP placement uniqueness incomplete')


def check_timer_start(records, cpus, calibrated_index):
    need(len(records) == cpus - 1, 'AP-local timer calibration row count')
    found = set()
    expected = {'cpu', 'vector', 'divide', 'initial', 'tsc-a-before', 'tsc-a-after',
                'count-a', 'tsc-b-before', 'tsc-b-after', 'count-b', 'quantum-tsc',
                'sample-tsc', 'max-jitter', 'reference', 'global-time', 'rt-time'}
    for index, _, f in records:
        need(set(f) == expected, 'AP timer calibration fields mismatch')
        cpu = number(f['cpu'], 'timer CPU')
        need(1 <= cpu < cpus and cpu not in found, 'AP timer CPU missing/duplicate')
        found.add(cpu)
        need(calibrated_index < index, 'timer started before all-AP calibration fence')
        a0, a1 = (number(f[k], k) for k in ('tsc-a-before', 'tsc-a-after'))
        b0, b1 = (number(f[k], k) for k in ('tsc-b-before', 'tsc-b-after'))
        ca, cb = (number(f[k], k) for k in ('count-a', 'count-b'))
        quantum = number(f['quantum-tsc'], 'timer quantum')
        sample = number(f['sample-tsc'], 'timer sample')
        jitter = number(f['max-jitter'], 'timer jitter')
        initial = number(f['initial'], 'timer initial count')
        need(0 <= a0 <= a1 < b0 <= b1 <= 0xffffffffffffffff
             and a1 - a0 <= jitter and b1 - b0 <= jitter
             and b0 - a1 >= sample and b1 - a0 < (1 << 34),
             'AP-local TSC sampling order/jitter/spacing mismatch')
        need(quantum == 1 << 24 and sample == 1 << 25 and jitter == 1 << 18
             and f['reference'] == 'ap-local-tsc'
             and f['vector'] == '224' and f['divide'] == '16'
             and f['global-time'] == f['rt-time'] == 'CPU0',
             'AP-local timer constants or BSP clock ownership mismatch')
        mid_a = a0 + (a1 - a0) // 2
        mid_b = b0 + (b1 - b0) // 2
        span = mid_b - mid_a
        need(span > 0 and 0 < cb < ca <= 0xffffffff
             and 1 <= initial <= 0xffffffff
             and initial == (ca - cb) * quantum // span,
             'AP-local timer calibration arithmetic mismatch')
    need(found == set(range(1, cpus)), 'AP-local timer calibration coverage incomplete')


def check_lines(lines, cpus, site):
    need(cpus in (4, 6), 'startup fixture only admits 4/6 CPUs')
    need(site in (1, 2, 3), 'startup site must be ATA=1, NVMe=2, or NIC=3')
    actor_count = 2 * (cpus - 1)
    reserved = actor_count
    need(not any(re.search(r'ABSD PANIC:|KERNEL FAULT|FAILED|NIC UNAVAILABLE', x)
                 for x in lines), 'failure/unavailable record in positive startup receipt')
    need(not any(x.startswith('SMP STARTUP INJECT ') for x in lines),
         'mutant injection record in positive receipt')

    topology = rows(lines, 'SMP TOPOLOGY ')
    need(len(topology) == cpus, 'guest topology row count')
    topology_by_cpu = {}
    host_keys = set()
    for _, _, f in topology:
        need(set(f) == {'cpu', 'apic', 'package', 'core', 'siblings', 'online', 'parked'},
             'guest topology fields mismatch')
        cpu = number(f['cpu'], 'topology CPU')
        need(cpu < cpus and cpu not in topology_by_cpu, 'topology CPU missing/duplicated')
        need(number(f['apic'], 'APIC ID') == cpu
             and number(f['siblings'], 'sibling mask') == 1 << cpu
             and f['online'] == '1' and f['parked'] == str(int(cpu > 0)),
             f'guest topology identity/state mismatch on CPU {cpu}')
        key = (number(f['package'], 'package'), number(f['core'], 'core'))
        need(key not in host_keys, 'guest package/core identity reused')
        host_keys.add(key)
        topology_by_cpu[cpu] = f
    need(set(topology_by_cpu) == set(range(cpus)), 'guest topology coverage incomplete')

    config = rows(lines, 'SMP STARTUP PRESSURE CONFIG ')
    need(len(config) == 1, 'startup pressure configuration missing/duplicate')
    config_i, _, cf = config[0]
    need(cf == {'cpus': str(cpus), 'reserved': str(reserved),
                'observer': 'device-probe', 'quantum-tsc': '16777216',
                'reference': 'ap-local-tsc'}, 'startup pressure configuration mismatch')

    calibrated = rows(lines, 'SMP APP PRESSURE CALIBRATED ')
    need(len(calibrated) == 1, 'AP calibration readiness fence missing/duplicate')
    cal_i, _, kf = calibrated[0]
    need(kf == {'cpus': str(cpus), 'ready-mask': str((1 << cpus) - 2),
                'owners': '0', 'actor-calls': '0', 'phase': 'before-user'},
         'AP calibration readiness fields mismatch')
    need(config_i < cal_i, 'startup config/calibration chronology')

    model_rows = rows(lines, 'SMP STARTUP MODEL ')
    need(len(model_rows) == 1, 'startup pre-SIPI model fence missing/duplicate')
    model_i, _, mf = model_rows[0]
    need(mf == {'exhaustion': 'passed', 'real-init': 'uncreated', 'phase': 'before-sipi'}
         and config_i < model_i, 'startup model/exhaustion fence mismatch')
    exhausted = rows(lines, 'SPAWN EXHAUSTION frames_per_process=')
    need(len(exhausted) == 1 and model_i > exhausted[0][0]
         and number(kv(exhausted[0][1]).get('frames_per_process'),
                    'exhaustion frames per process') > 0,
         'successful INIT exhaustion proof missing/duplicate or after startup gate')

    frame_rows = rows(lines, 'SMP STARTUP FRAME RESERVATION ')
    restricted = rows(lines, 'SMP STARTUP RESTRICTED ')
    spawn_rows = [(i, line, kv(line)) for i, line in enumerate(lines)
                  if line.startswith('SPAWN OK ') and kv(line).get('program') == 'smp-user']
    published = [(i, line, kv(line)) for i, line in enumerate(lines)
                 if line.startswith('SPAWN OK ')]
    exhausted_init = [(i, f) for i, _, f in published if i < model_i]
    all_after_model = [(i, f) for i, _, f in published if i > model_i]
    need(len(frame_rows) == len(restricted) == len(spawn_rows) == actor_count
         and len(exhausted_init) == 1
         and exhausted_init[0][1] == {'pid': '1', 'parent': '0', 'program': 'init'}
         and exhausted_init[0][0] < exhausted[0][0] < model_i
         and len(all_after_model) == actor_count
         and all(f.get('program') == 'smp-user' for _, f in all_after_model),
         'exhaustion/init and startup actor publication census mismatch')
    actors_by_role, actor_pid_set, actor_generations = {}, set(), set()
    for idx in range(actor_count):
        role, pid, cpu = 200 + idx, idx + 1, idx // 2 + 1
        fi, _, ff = frame_rows[idx]
        ri, _, rf = restricted[idx]
        si, _, sf = spawn_rows[idx]
        need(ff == {'role': str(role), 'pid': str(pid), 'frames': '33'},
             f'role {role} startup frame reservation mismatch')
        need(rf == {'pid': str(pid), 'role': str(role), 'handles': '0', 'spawn': '0',
                    'console': '0', 'phase': 'before-ap-command'},
             f'role {role} startup authority restriction mismatch')
        need(sf == {'pid': str(pid), 'parent': '0', 'program': 'smp-user'},
             f'role {role} startup spawn identity mismatch')
        need(model_i < fi < si < ri < cal_i,
             f'role {role} reservation/publication/restriction/calibration chronology')
        actors_by_role[role] = {'pid': pid, 'cpu': cpu, 'frame_i': fi,
                                'spawn_i': si, 'restricted_i': ri}
        actor_pid_set.add(pid)

    actors = rows(lines, 'SMP APP PRESSURE ACTOR ')
    need(len(actors) == actor_count, 'startup actor first-syscall witness count')
    actor_by_pid = {}
    for i, _, f in actors:
        need(set(f) == {'cpu', 'pid', 'generation', 'role', 'cpl', 'cr3'},
             'startup actor ownership witness fields mismatch')
        pid = number(f['pid'], 'actor PID')
        gen = number(f['generation'], 'actor generation')
        role = number(f['role'], 'actor role')
        cpu = number(f['cpu'], 'actor CPU')
        need(role in actors_by_role and pid == actors_by_role[role]['pid']
             and cpu == actors_by_role[role]['cpu'] and f['cpl'] == '3'
             and f['cr3'] == 'owned' and gen > 0,
             f'role {role} actor identity/ownership mismatch')
        need(pid not in actor_by_pid and gen not in actor_generations,
             'duplicate startup actor PID/generation')
        need(cal_i < i, f'role {role} entered before AP calibration readiness')
        actor_generations.add(gen)
        actor_by_pid[pid] = (role, cpu, gen, i)
    need(set(actor_by_pid) == actor_pid_set, 'startup actor PID census mismatch')
    timer_starts = rows(lines, 'SMP TIMER START ')
    check_timer_start(timer_starts, cpus, cal_i)
    timer_start_by_cpu = {number(f['cpu'], 'timer CPU'): i for i, _, f in timer_starts}
    for cpu in range(1, cpus):
        need(timer_start_by_cpu[cpu] < min(v[3] for v in actor_by_pid.values() if v[1] == cpu),
             f'CPU {cpu} timer did not start before its first fixture syscall')

    user_traps = rows(lines, 'SMP USER TRAP ')
    need(len(user_traps) == cpus - 1, 'per-AP first user claim witness count')
    trap_cpus = set()
    for i, _, f in user_traps:
        need(set(f) == {'seq', 'cpu', 'slot', 'pid', 'epoch'},
             'first user trap fields mismatch')
        cpu, pid = number(f['cpu'], 'trap CPU'), number(f['pid'], 'trap PID')
        seq, slot, epoch = (number(f[k], k) for k in ('seq', 'slot', 'epoch'))
        need(1 <= cpu < cpus and cpu not in trap_cpus and pid in actor_by_pid,
             'first user trap has missing/duplicate CPU or unknown actor')
        role, actor_cpu, _, actor_i = actor_by_pid[pid]
        need(actor_cpu == cpu and seq > 0 and epoch > 0 and slot < 16
             and actors_by_role[role]['restricted_i'] < actor_i < i,
             'first user trap does not bind published AP actor')
        trap_cpus.add(cpu)
    need(trap_cpus == set(range(1, cpus)), 'first user trap AP coverage incomplete')

    preempts = rows(lines, 'SMP APP PRESSURE PREEMPT ')
    resumes = rows(lines, 'SMP APP PRESSURE RESUME ')
    odd_roles = set(range(201, 200 + actor_count, 2))
    need(len(preempts) == len(resumes) == cpus - 1,
         'odd-role saved timer/resume witness count')
    for group, label in ((preempts, 'preempt'), (resumes, 'resume')):
        seen = set()
        for i, _, f in group:
            need(set(f) == {'cpu', 'pid', 'generation', 'role', 'saved', 'live'}
                 and f['saved'] == '1' and f['live'] == '1',
                 f'{label} saved/live fields mismatch')
            role, pid = number(f['role'], f'{label} role'), number(f['pid'], f'{label} PID')
            need(role in odd_roles and role not in seen and pid in actor_by_pid,
                 f'{label} duplicate/non-odd actor')
            ar, cpu, gen, actor_i = actor_by_pid[pid]
            need((ar, cpu, gen) == (role, number(f['cpu'], f'{label} CPU'),
                                    number(f['generation'], f'{label} generation'))
                 and actor_i < i,
                 f'{label} actor identity/chronology mismatch')
            seen.add(role)
        need(seen == odd_roles, f'{label} AP role coverage incomplete')
    pre_by_role = {number(f['role'], 'preempt role'): i for i, _, f in preempts}
    resume_by_role = {number(f['role'], 'resume role'): i for i, _, f in resumes}
    for role in odd_roles:
        need(pre_by_role[role] < resume_by_role[role],
             f'role {role} resume precedes saved timer frame')

    ap_ready = rows(lines, 'SMP STARTUP AP READY ')
    need(len(ap_ready) == cpus - 1, 'startup AP-ready witness count')
    ready_cpus = set()
    for i, _, f in ap_ready:
        need(set(f) == {'cpu', 'actors', 'saved', 'resumed'}, 'AP-ready fields mismatch')
        cpu = number(f['cpu'], 'AP-ready CPU')
        need(1 <= cpu < cpus and cpu not in ready_cpus and f == {
            'cpu': str(cpu), 'actors': '2', 'saved': '1', 'resumed': '1'},
            'AP-ready identity/readiness mismatch')
        roles = (200 + 2 * (cpu - 1), 201 + 2 * (cpu - 1))
        need(all(actors_by_role[r]['restricted_i'] < i for r in roles)
             and all(actor_by_pid[actors_by_role[r]['pid']][3] < i for r in roles)
             and pre_by_role[roles[1]] < i and resume_by_role[roles[1]] < i,
             f'CPU {cpu} readiness precedes its actor setup/preemption/resume')
        ready_cpus.add(cpu)
    need(ready_cpus == set(range(1, cpus)), 'AP-ready CPU coverage incomplete')

    begin = one(lines, 'SMP STARTUP INTERVAL BEGIN phase=device-probe real-init=uncreated',
                'device-probe interval begin')
    end = one(lines, 'SMP STARTUP INTERVAL END phase=device-probe',
              'device-probe interval end')
    need(max(i for i, _, _ in ap_ready) < begin < end,
         'AP readiness/device-probe interval chronology')

    first_polls = rows(lines, 'SMP STARTUP FIRST POLL ')
    need(all(set(f) == {'site', 'revalidated', 'completion'} and f['revalidated'] == '1'
             and f['completion'] == 'unchecked' for _, _, f in first_polls),
         'first-poll receipt fields mismatch')
    selected_polls = [(i, f) for i, _, f in first_polls if f['site'] == str(site)]
    need(len(selected_polls) == 1 and begin < selected_polls[0][0] < end,
         'selected device first-poll witness missing/duplicate/outside interval')
    need(all(begin < i < end for i, _, _ in first_polls),
         'device first-poll record outside startup interval')

    if site == 1:
        success = [i for i, x in enumerate(lines) if x.startswith('BLOCK DEVICE OK sectors=')]
        backend = [i for i, x in enumerate(lines) if x.startswith('BLOCK BACKEND ata access=')]
        need(len(success) == len(backend) == 1 and lines[success[0]] ==
             'BLOCK DEVICE OK sectors=4096'
             and lines[backend[0]] == 'BLOCK BACKEND ata access=read-write',
             'ATA selected backend/sector/write receipt mismatch')
        device_indices = success + backend
    elif site == 2:
        ctrl = [i for i, x in enumerate(lines) if x.startswith('NVME CONTROLLER ')]
        ns = [i for i, x in enumerate(lines) if x.startswith('NVME NAMESPACE ')]
        read = [i for i, x in enumerate(lines) if x.startswith('NVME READ OK lba=0 fnv1a=')]
        success = [i for i, x in enumerate(lines) if x.startswith('BLOCK DEVICE OK sectors=')]
        backend = [i for i, x in enumerate(lines) if x == 'BLOCK BACKEND nvme access=read-write']
        need(len(ctrl) == len(ns) == len(read) == len(success) == len(backend) == 1,
             'NVMe controller/namespace/read/backend record count')
        need(lines[ctrl[0]] == ('NVME CONTROLLER pci=00:03.0 vendor=1b36 device=0010 '
                                'version=00010400 vwc=1 serial=absd model=QEMU NVMe Ctrl')
             and lines[ns[0]] == ('NVME NAMESPACE nsid=1 lba_bytes=512 sectors=4096 '
                                 'access=read-write (selected by nvme-write)')
             and lines[success[0]] == 'BLOCK DEVICE OK sectors=4096',
             'NVMe selected backend/namespace/write identity mismatch')
        need(ctrl[0] < ns[0] < read[0] < success[0] < backend[0],
             'NVMe initialization/output chronology')
        device_indices = ctrl + ns + read + success + backend
    else:
        nic = [i for i, x in enumerate(lines) if x.startswith('NIC CONTROLLER pci=')]
        link = [i for i, x in enumerate(lines) if x.startswith('NETWORK LINK OK ')]
        need(len(nic) == len(link) == 1 and
             re.fullmatch(r'NIC CONTROLLER pci=[0-9a-f]{2}:[0-9a-f]{2}\.0 '
                          r'vendor=8086 device=100e mac=(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',
                          lines[nic[0]]) is not None
             and lines[link[0]] ==
             'NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048',
             'e1000 selected device/link identity or descriptor geometry mismatch')
        need(nic[0] < link[0], 'NIC link precedes controller identification')
        device_indices = nic + link
    need(all(begin < i < end for i in device_indices),
         'selected backend initialized outside device-probe interval')
    need(selected_polls[0][0] < min(device_indices),
         'selected device progress witness follows device initialization')

    windows = rows(lines, 'SMP STARTUP WINDOW site=')
    need(len(windows) == 4 * (cpus - 1), 'per-AP/per-site window row count')
    window_pairs = set()
    counts_by_site = {}
    for i, _, f in windows:
        need(set(f) == {'site', 'cpu', 'intervals', 'all-ap-progress'},
             'per-AP startup window fields mismatch')
        s, cpu = number(f['site'], 'window site'), number(f['cpu'], 'window CPU')
        count = number(f['intervals'], 'window count')
        need(1 <= s <= 4 and 1 <= cpu < cpus and (s, cpu) not in window_pairs
             and f['all-ap-progress'] == '1', 'duplicate/invalid AP window evidence')
        window_pairs.add((s, cpu))
        counts_by_site.setdefault(s, []).append(count)
    need(window_pairs == {(s, cpu) for s in range(1, 5) for cpu in range(1, cpus)},
         'AP/site window coverage incomplete')
    totals = rows(lines, 'SMP STARTUP WINDOW TOTAL ')
    need(len(totals) == 4, 'per-site startup window total count')
    total_by_site = {}
    for i, _, f in totals:
        need(set(f) == {'site', 'intervals'}, 'startup window total fields mismatch')
        s, count = number(f['site'], 'total site'), number(f['intervals'], 'total intervals')
        need(1 <= s <= 4 and s not in total_by_site, 'duplicate/invalid window total')
        total_by_site[s] = count
        need(counts_by_site[s] and all(n == count for n in counts_by_site[s]),
             f'site {s} AP windows disagree with aggregate')
        need(i < min(j for j, _, wf in windows if number(wf['site'], 'window site') == s),
             f'site {s} aggregate follows its CPU window evidence')
    need(set(total_by_site) == {1, 2, 3, 4} and total_by_site[site] > 0,
         'selected device site lacks every-AP wait progress')

    probe_rows = rows(lines, 'SMP STARTUP PRESSURE CPU ')
    need(len(probe_rows) == cpus - 1, 'per-AP probe progress row count')
    probe_by_cpu = {}
    for i, _, f in probe_rows:
        need(set(f) == {'cpu', 'actors', 'calls', 'probe-calls', 'exited', 'departed'},
             'per-AP probe progress fields mismatch')
        cpu = number(f['cpu'], 'probe CPU')
        calls = number(f['calls'], 'actor calls')
        probe_calls = number(f['probe-calls'], 'device-interval actor calls')
        need(1 <= cpu < cpus and cpu not in probe_by_cpu and f['actors'] == '2'
             and calls > 0 and 0 < probe_calls <= calls
             and f['exited'] == '2' and f['departed'] == '2',
             f'CPU {cpu} did not make bounded device-interval syscall progress')
        need(end < i, 'per-AP probe summary chronology')
        probe_by_cpu[cpu] = (i, calls, probe_calls)
    need(set(probe_by_cpu) == set(range(1, cpus)), 'per-AP probe progress coverage')

    exits = rows(lines, 'USER EXIT ')
    exit_by_pid = {}
    for i, _, f in exits:
        need(set(f) == {'pid', 'status'}, 'user exit fields mismatch')
        pid = number(f['pid'], 'exit PID')
        need(pid not in exit_by_pid and pid in actor_pid_set and f['status'] == '0',
             'unexpected/duplicate/nonzero startup actor exit')
        need(i > end and i > actor_by_pid[pid][3],
             'startup actor exited before device interval completion/first syscall')
        exit_by_pid[pid] = i
    need(set(exit_by_pid) == actor_pid_set, 'startup actor exit census incomplete')
    reclaims = rows(lines, 'SMP STARTUP RECLAIM ')
    need(len(reclaims) == actor_count, 'startup actor reclaim count')
    reclaimed = set()
    for i, _, f in reclaims:
        need(set(f) == {'pid', 'role', 'frames', 'departed', 'fence'}, 'actor reclaim fields mismatch')
        pid = number(f['pid'], 'reclaim PID')
        role = number(f['role'], 'reclaim role')
        need(pid in actor_by_pid and pid not in reclaimed and
             role == actor_by_pid[pid][0] and f['frames'] == '0'
             and f['departed'] == '1' and f['fence'] == 'all-ap-idle'
             and exit_by_pid[pid] < i,
             'startup actor exit/reclaim identity or chronology mismatch')
        reclaimed.add(pid)
    need(reclaimed == actor_pid_set, 'startup actor reclaim census incomplete')

    quiescent = one(lines, 'SMP QUEUE QUIESCENT registered=0 queued=0 running=0',
                    'queue quiescence')
    need(max(exit_by_pid.values()) < quiescent
         and max(i for i, _, _ in reclaims) < quiescent,
         'queue quiescence precedes actor exit/reclamation')

    timers = rows(lines, 'SMP TIMER SUMMARY ')
    need(len(timers) == cpus - 1, 'AP timer summary row count')
    timer_cpus = set()
    for i, _, f in timers:
        need(set(f) == {'cpu', 'irqs', 'user-irqs', 'switches0', 'switches1'},
             'AP timer summary fields mismatch')
        cpu = number(f['cpu'], 'timer summary CPU')
        irq, user_irq = number(f['irqs'], 'AP IRQs'), number(f['user-irqs'], 'AP user IRQs')
        need(1 <= cpu < cpus and cpu not in timer_cpus and 0 < user_irq <= irq
             and number(f['switches1'], 'AP user switches') > 0,
             f'CPU {cpu} lacks ring-3 timer/preemption evidence')
        need(quiescent < i, 'timer summary precedes AP departure fence')
        timer_cpus.add(cpu)
    need(timer_cpus == set(range(1, cpus)), 'AP timer summary coverage incomplete')

    frames = rows(lines, 'SMP STARTUP FRAMES ')
    need(len(frames) == 1, 'startup frame census missing/duplicate')
    frames_i, _, ff = frames[0]
    need(set(ff) == {'baseline', 'final', 'kernel-retained', 'actor-owned', 'devices'},
         'startup frame census fields mismatch')
    baseline, final, retained = (number(ff[k], k) for k in
                                 ('baseline', 'final', 'kernel-retained'))
    need(final >= baseline and final - baseline == retained and ff['actor-owned'] == '0'
         and ff['devices'] == 'initialized-not-quiesced',
         'startup frame ownership/retention mismatch')

    summary = rows(lines, 'SMP STARTUP SUMMARY ')
    need(len(summary) == 1, 'multicore startup terminal summary missing/duplicate')
    summary_i, _, sf = summary[0]
    need(sf == {'cpus': str(cpus), 'actors': str(actor_count), 'faults': '0', 'kills': '0',
                'mappings': 'unchanged', 'reclaimed': '1', 'pid-rewind': 'fenced',
                'real-init': 'uncreated'}, 'startup lifecycle/mapping/PID-rewind summary mismatch')
    need(max(i for i, _, _ in reclaims) < quiescent
         and quiescent < min(i for i, _, _ in timers)
         and max(i for i, _, _ in timers) < min(i for i, _, _ in probe_rows)
         and end < min(i for i, _, _ in probe_rows)
         and max(i for i, _, _ in probe_rows) < min(i for i, _, _ in windows)
         and max(i for i, _, _ in windows + totals) < frames_i < summary_i,
         'startup quiescence/report/frame/summary chronology')

    # The simple single-CPU startup mode and normal INIT were not selected.
    need(not rows(lines, 'SMP STARTUP SUMMARY cpu=')
         and not rows(lines, 'SMP BSP TRAP ')
         and not rows(lines, 'USER INIT STARTED')
         and not rows(lines, 'SMP APP PRESSURE CPU '),
         'mixed single-CPU/BSP/INIT records in multicore pre-INIT receipt')
    startup_ok = one(lines, 'SMP NWAY STARTUP OK', 'N-way startup success marker')
    boot_ok = one(lines, 'ABSD BOOT OK', 'successful boot marker')
    need(summary_i < startup_ok < boot_ok, 'terminal startup/boot marker chronology')


def self_test(base, cpus, site):
    check_lines(base, cpus, site)
    tests = []

    def rejects(name, edit, expected=None):
        changed = list(base)
        edit(changed)
        try:
            check_lines(changed, cpus, site)
        except (AssertionError, KeyError, ValueError):
            tests.append(name)
            return
        raise AssertionError(f'self-test control was accepted: {name}')

    rejects('missing-calibration', lambda x: x.__setitem__(slice(None),
            [line for line in x if not line.startswith('SMP APP PRESSURE CALIBRATED ')]))
    rejects('publication-before-reservation', lambda x: _move_after(x, 'SMP STARTUP FRAME RESERVATION ',
            'SPAWN OK pid=1 parent=0 program=smp-user'))
    rejects('wrong-frame-budget', lambda x: _replace_first(x, 'frames=33', 'frames=32'))
    rejects('wrong-role-cpu', lambda x: _replace_first(x, 'SMP APP PRESSURE ACTOR cpu=1',
            'SMP APP PRESSURE ACTOR cpu=2'))
    rejects('missing-preempt', lambda x: _remove_prefix(x, 'SMP APP PRESSURE PREEMPT '))
    rejects('resume-before-preempt', lambda x: _move_before(x, 'SMP APP PRESSURE RESUME ',
            'SMP APP PRESSURE PREEMPT '))
    rejects('ready-before-resume', lambda x: _move_before(x, 'SMP STARTUP AP READY cpu=1',
            'SMP APP PRESSURE RESUME '))
    rejects('probe-before-ready', lambda x: _move_before(x,
            'SMP STARTUP INTERVAL BEGIN phase=device-probe real-init=uncreated',
            'SMP STARTUP AP READY cpu=1'))
    rejects('missing-selected-first-poll', lambda x: _remove_prefix(x,
            f'SMP STARTUP FIRST POLL site={site} '))
    rejects('device-outside-interval', lambda x: _move_before(x,
            'BLOCK DEVICE OK sectors=4096' if site != 3 else 'NIC CONTROLLER ',
            'SMP STARTUP INTERVAL BEGIN '))
    rejects('wrong-backend', lambda x: _replace_first(x, 'BLOCK BACKEND ata',
            'BLOCK BACKEND nvme')) if site == 1 else None
    rejects('zero-probe-progress', lambda x: _replace_row_value(x,
            'SMP STARTUP PRESSURE CPU cpu=1 ', 'probe-calls', '0'))
    rejects('timer-initial-mismatch', lambda x: _increment_row_value(x,
            'SMP TIMER START cpu=1 ', 'initial'))
    rejects('timer-start-after-actor', lambda x: _move_after(x,
            'SMP TIMER START cpu=1 ', 'SMP APP PRESSURE ACTOR cpu=1 '))
    rejects('site-aggregate-mismatch', lambda x: _replace_row_value(x,
            f'SMP STARTUP WINDOW site={site} cpu=1 ', 'intervals', '0'))
    rejects('missing-last-ap-window', lambda x: _remove_prefix(x,
            f'SMP STARTUP WINDOW site=4 cpu={cpus-1} '))
    rejects('bad-frame-census', lambda x: _increment_row_value(x,
            'SMP STARTUP FRAMES ', 'kernel-retained'))
    rejects('changed-mapping', lambda x: _replace_first(x, 'mappings=unchanged',
            'mappings=changed'))
    rejects('missing-reclaim', lambda x: _remove_prefix(x, 'SMP STARTUP RECLAIM '))
    rejects('duplicate-topology', lambda x: x.append(next(y for y in x
            if y.startswith('SMP TOPOLOGY '))))
    rejects('boot-before-terminal', lambda x: _move_before(x, 'ABSD BOOT OK',
            'SMP STARTUP SUMMARY '))
    rejects('single-cpu-summary-mix', lambda x: x.append(
            'SMP STARTUP SUMMARY cpu=1 ata=1 nvme=0 nic-probe=0'))
    need(len(tests) == len(set(tests)), 'self-test control names duplicated')
    print(f'SMP N-way startup oracle self-test OK cpus={cpus} site={site} '
          f'negative-controls={len(tests)}')


def _replace_row_value(lines, prefix, key, value):
    i = next(i for i, line in enumerate(lines) if line.startswith(prefix))
    pattern = rf'\b{re.escape(key)}=[^\s]+'
    changed, count = re.subn(pattern, f'{key}={value}', lines[i], count=1)
    need(count == 1 and changed != lines[i], f'self-test field missing/unchanged: {key}')
    lines[i] = changed


def _increment_row_value(lines, prefix, key):
    i = next(i for i, line in enumerate(lines) if line.startswith(prefix))
    current = number(kv(lines[i]).get(key), f'self-test {key}')
    _replace_row_value(lines, prefix, key, str(current + 1))


def _remove_prefix(lines, prefix):
    first = next(i for i, line in enumerate(lines) if line.startswith(prefix))
    lines.pop(first)


def _remove_exact(lines, exact):
    lines.remove(exact)


def _replace_first(lines, before, after):
    i = next(i for i, line in enumerate(lines) if before in line)
    lines[i] = lines[i].replace(before, after, 1)


def _move_after(lines, moved_prefix, anchor_prefix):
    i = next(i for i, line in enumerate(lines) if line.startswith(moved_prefix))
    moved = lines.pop(i)
    j = next(i for i, line in enumerate(lines) if line.startswith(anchor_prefix))
    lines.insert(j + 1, moved)


def _move_before(lines, moved_prefix, anchor_prefix):
    i = next(i for i, line in enumerate(lines) if line.startswith(moved_prefix))
    moved = lines.pop(i)
    j = next(i for i, line in enumerate(lines) if line.startswith(anchor_prefix))
    lines.insert(j, moved)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--cpus', required=True, type=int, choices=(4, 6))
    parser.add_argument('--site', required=True, type=int, choices=(1, 2, 3),
                        help='required wait site: ATA=1, NVMe=2, NIC probe=3')
    parser.add_argument('--placement', required=True, type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    lines = args.log.read_text(errors='replace').splitlines()
    check_placement(args.placement, args.cpus)
    check_lines(lines, args.cpus, args.site)
    if args.self_test:
        self_test(lines, args.cpus, args.site)
    print(f'SMP N-way startup oracle OK cpus={args.cpus} site={args.site}')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, OSError, ValueError, KeyError, StopIteration,
            json.JSONDecodeError) as error:
        print(f'SMP N-way startup oracle rejected: {error}', file=sys.stderr)
        sys.exit(1)
