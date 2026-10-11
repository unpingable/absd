#!/usr/bin/env python3
"""Closed receipt oracle for six real text-stats jobs under SMP placement."""
import argparse
import json
import math
import re
from pathlib import Path

U64 = (1 << 64) - 1
PATHS = ('other', 'getpid', 'cell-read', 'cell-transition', 'cell-wait',
         'syscall', 'timer', 'fault', 'stop', 'idle', 'device-reacquire', 'total')
INPUT = 1_114_112
OUTPUT = 107
LEAF_REGIONS = ('transfer-status', 'ring-read', 'ring-write', 'copy-from',
                'copy-to', 'wake-bookkeeping')
LEAF_UNITS = {'transfer-status': 0, 'ring-read': 6_685_314,
              'ring-write': 6_685_314, 'copy-from': 6_685_314,
              'copy-to': 6_685_314, 'wake-bookkeeping': 0}


def need(ok, message):
    if not ok:
        raise AssertionError(message)


def fields(line):
    first_field = re.search(r'(?:^| )([a-z][a-z0-9_-]*=)', line)
    need(first_field is not None, f'no key/value fields in {line}')
    tail = line[first_field.start(1):]
    pairs = re.findall(r'([a-z][a-z0-9_-]*)=([^\s]+)', tail)
    result = {}
    for key, value in pairs:
        need(key not in result, f'duplicate field {key}: {line}')
        result[key] = value
    need(' '.join(f'{key}={value}' for key, value in result.items()) == tail,
         f'malformed/unrecognized fields: {line}')
    return result


def rows(lines, prefix):
    return [(i, line, fields(line)) for i, line in enumerate(lines)
            if line.startswith(prefix)]


def num(row, key):
    value = row.get(key)
    need(value is not None and re.fullmatch(r'[0-9]+', value) is not None,
         f'{key} must be canonical unsigned decimal')
    value_n = int(value)
    need(str(value_n) == value and value_n <= U64, f'{key} out of range/noncanonical')
    return value_n


def placement(path, cpus):
    p = json.loads(Path(path).read_text())
    need(p.get('kvm') == {'enabled': True, 'present': True}, 'KVM is not attested')
    vcpus = p.get('vcpus')
    need(isinstance(vcpus, list) and len(vcpus) == cpus
         and {v.get('cpu-index') for v in vcpus} == set(range(cpus)),
         'QMP vCPU identity/count mismatch')
    if cpus == 1:
        need(p.get('host_topology') == 'separate'
             and p.get('guest_topology_mode') == 'legacy-qemu-default'
             and p.get('guest_topology') is None,
             'UP must use the legacy one-vCPU topology')
    else:
        need(p.get('host_topology') == 'separate'
             and p.get('guest_topology_mode') == 'explicit-smp-scheduler-test'
             and p.get('guest_topology') == {'sockets': 1, 'cores': cpus, 'threads': 1},
             'SMP guest topology mismatch')
    seen = set()
    for v in vcpus:
        host_cpu = v.get('host-cpu')
        need(isinstance(host_cpu, int) and v.get('affinity') == [host_cpu],
             'QMP pin and affinity differ')
        if cpus > 1:
            key = (v.get('host-package'), v.get('host-core'))
            need(None not in key and key not in seen, 'vCPUs are not pinned to distinct host cores')
            seen.add(key)
    return p


def check_lines(lines, cpus, leaf=False):
    need(cpus in (1, 2, 4, 6), 'unsupported vCPU count')
    need(not any('ABSD PANIC:' in x or x.startswith(('KERNEL FAULT', 'FAILED')) for x in lines),
         'positive receipt contains failure')
    known = ('SMP APP SCALE ROOT ', 'SMP APP SCALE SUPERVISOR ',
             'SMP APP SCALE SUPKEY ', 'SMP APP SCALE SUPTRAP ',
             'SMP APP SCALE NATIVE ', 'SMP APP SCALE TRAP ',
             'SMP APP SCALE IDENTITY ', 'SMP APP SCALE PREEMPT ',
             'SMP APP SCALE DEPART ', 'SMP APP SCALE RECLAIM ',
             'SMP APP SCALE START ', 'SMP APP SCALE JOB ',
             'SMP APP SCALE DONE ', 'SMP APP SCALE FENCE ', 'SMP APP SCALE OK ',
             'SMP SCALE LOCK ')
    need(all(not x.startswith('SMP APP SCALE ') or x.startswith(known) for x in lines),
         'unknown app-scale receipt row')
    need(all(not x.startswith('SMP SCALE ') or x.startswith('SMP SCALE LOCK ')
             for x in lines), 'unexpected generic scale receipt row')
    leaf_config = rows(lines, 'SMP APP LEAF CONFIG ')
    leaf_rows = rows(lines, 'SMP APP LEAF phase=')
    need(all(not x.startswith('SMP APP LEAF ') or
             x.startswith('SMP APP LEAF CONFIG ') or x.startswith('SMP APP LEAF phase=')
             for x in lines), 'unknown app leaf receipt row')
    need(len(leaf_config) == (1 if leaf else 0)
         and len(leaf_rows) == (cpus * 7 if leaf else 0),
         'leaf measurement rows must exactly match requested mode/topology')
    if leaf:
        _, _, config = leaf_config[0]
        need(set(config) == {'regions', 'coverage', 'units'}
             and config == {'regions': '6', 'coverage': 'exclusive-completed',
                            'units': 'successful-bytes'},
             'leaf measurement configuration mismatch')

    root = rows(lines, 'SMP APP SCALE ROOT ')
    need(len(root) == 1, 'root identity missing/duplicate')
    ri, _, rf = root[0]
    need(set(rf) == {'slot', 'pid', 'generation', 'cpu'}
         and num(rf, 'slot') == 0 and num(rf, 'pid') == 1
         and num(rf, 'cpu') == 0
         and (num(rf, 'generation') == 0 if cpus == 1 else num(rf, 'generation') > 0),
         'root identity/placement mismatch')
    need(ri > next(i for i, line in enumerate(lines) if line == 'SPAWN EXHAUSTION OK'),
         'root activation precedes exhaustion boundary')
    family_generations = {num(rf, 'generation')}
    family_slots = {num(rf, 'slot')}

    timer_starts = rows(lines, 'SMP TIMER START ')
    need(len(timer_starts) == cpus - 1, 'AP timer calibration coverage missing/duplicate')
    timer_index = {}
    timer_keys = {'cpu', 'vector', 'divide', 'initial', 'tsc-a-before', 'tsc-a-after',
                  'count-a', 'tsc-b-before', 'tsc-b-after', 'count-b', 'quantum-tsc',
                  'sample-tsc', 'max-jitter', 'reference', 'global-time', 'rt-time'}
    for i, _, f in timer_starts:
        need(set(f) == timer_keys, 'timer calibration fields mismatch')
        cpu = num(f, 'cpu')
        need(1 <= cpu < cpus and cpu not in timer_index, 'timer calibration CPU duplicate/range')
        a0, a1, b0, b1 = (num(f, k) for k in
                          ('tsc-a-before', 'tsc-a-after', 'tsc-b-before', 'tsc-b-after'))
        q, sample, jitter = (num(f, k) for k in ('quantum-tsc', 'sample-tsc', 'max-jitter'))
        ca, cb, initial = (num(f, k) for k in ('count-a', 'count-b', 'initial'))
        span = (b0 + (b1 - b0) // 2) - (a0 + (a1 - a0) // 2)
        need(0 <= a0 <= a1 < b0 <= b1 <= U64 and a1 - a0 <= jitter
             and b1 - b0 <= jitter and b0 - a1 >= sample and b1 - a0 < (1 << 34),
             'AP-local TSC sample bounds')
        need(q == 16_777_216 and sample == 33_554_432 and jitter == 262_144
             and f['reference'] == 'ap-local-tsc', 'timer calibration constants/reference')
        need(span > 0 and 0 < cb < ca <= 0xffffffff and 1 <= initial <= 0xffffffff
             and initial == (ca - cb) * q // span and f['vector'] == '224'
             and f['divide'] == '16' and f['global-time'] == f['rt-time'] == 'CPU0',
             'timer calibration arithmetic/ownership')
        timer_index[cpu] = i
    need(set(timer_index) == set(range(1, cpus)), 'AP timer calibration CPU set mismatch')

    supervisors, supervisor_pids, supervisor_gens = {}, set(), set()
    for prefix, mapping, label in (('SMP APP SCALE SUPERVISOR ', supervisors, 'supervisor'),
                                   ('SMP APP SCALE SUPKEY ', supervisors, 'superkey')):
        rr = rows(lines, prefix)
        need(len(rr) == 6, f'{label} census must be six')
        for i, _, f in rr:
            need(set(f) == ({'job', 'pid', 'cpu'} if label == 'supervisor'
                            else {'job', 'slot', 'pid', 'generation', 'cpu'}),
                 f'{label} fields mismatch')
            job = num(f, 'job')
            need(job in range(6) and job not in mapping if label == 'supervisor' else job in range(6),
                 f'{label} job duplicate/range')
            expected_cpu = job % cpus
            need(num(f, 'cpu') == expected_cpu, f'{label} CPU assignment mismatch')
            pid = num(f, 'pid')
            need(pid > 1, f'{label} PID invalid')
            if label == 'supervisor':
                need(pid not in supervisor_pids, 'duplicate supervisor PID')
                supervisor_pids.add(pid)
                mapping[job] = {'pid': pid, 'prepare_i': i}
            else:
                need(job in mapping and mapping[job]['pid'] == pid,
                     'supervisor activation does not match publication')
                slot, gen = num(f, 'slot'), num(f, 'generation')
                need(slot < 16 and (gen == 0 if cpus == 1 else gen > 0),
                     'supervisor slot/generation mismatch')
                need(pid not in supervisor_gens and (cpus == 1 or gen not in family_generations)
                     and slot not in family_slots,
                     'duplicate supervisor activation identity/generation')
                supervisor_gens.add(pid)
                family_generations.add(gen)
                family_slots.add(slot)
                mapping[job].update(slot=slot, generation=gen, activate_i=i)
    need(set(supervisors) == set(range(6)), 'supervisor job set incomplete')

    natives = {}
    nr = rows(lines, 'SMP APP SCALE NATIVE ')
    need(len(nr) == 6, 'native child publication census must be six')
    for i, _, f in nr:
        need(set(f) == {'job', 'slot', 'pid', 'parent', 'cpu'}, 'native publication fields mismatch')
        job, slot, pid = (num(f, k) for k in ('job', 'slot', 'pid'))
        parent, cpu = num(f, 'parent'), num(f, 'cpu')
        need(job in range(6) and job not in natives and slot < 16 and pid > 1
             and parent == supervisors[job]['pid'] and cpu == job % cpus,
             'native publication identity/parent/placement mismatch')
        natives[job] = {'pid': pid, 'parent': parent, 'slot': slot, 'cpu': cpu, 'publish_i': i}
    need(len({x['pid'] for x in natives.values()}) == 6, 'duplicate native PID')
    native_slots = {x['slot'] for x in natives.values()}
    supervisor_slots = {x['slot'] for x in supervisors.values()}
    need(len(native_slots | supervisor_slots) == 12,
         'duplicate live-family process slot')
    need(native_slots.isdisjoint(family_slots), 'native slot overlaps root/supervisor slot')

    # Bind the complete spawn ledger to the six supervisors, six catalogued native
    # children, and real init root; unrelated fixture publications are refused.
    spawns = [(i, re.fullmatch(r'SPAWN OK pid=(\d+) parent=(\d+) program=([a-z0-9_-]+)', x))
              for i, x in enumerate(lines) if x.startswith('SPAWN OK ')]
    spawns = [(i, int(m[1]), int(m[2]), m[3]) for i, m in spawns if m]
    exhaustion_ok = [i for i, line in enumerate(lines) if line == 'SPAWN EXHAUSTION OK']
    exhaustion_details = [(i, int(m[1])) for i, line in enumerate(lines)
                          if (m := re.fullmatch(r'SPAWN EXHAUSTION frames_per_process=(\d+)', line))]
    temp_init = [(i, parent, program) for i, pid, parent, program in spawns
                 if pid == 1 and parent == 0 and program == 'init']
    need(len(spawns) == 14 and len(exhaustion_ok) == 1 and len(exhaustion_details) == 1
         and exhaustion_details[0][1] > 0 and len(temp_init) == 1,
         'spawn ledger must include temporary INIT plus thirteen fixture tasks')
    need(temp_init[0][0] < exhaustion_details[0][0] < exhaustion_ok[0]
         and sum(i < exhaustion_ok[0] for i, _, _, _ in spawns) == 1,
         'temporary INIT spawn outside exhaustion boundary')
    active_spawns = [(i, pid, parent, program) for i, pid, parent, program in spawns
                     if i > exhaustion_ok[0]]
    need(len(active_spawns) == 13, 'fixture spawn count after exhaustion boundary mismatch')
    spawn_map = {pid: (i, parent, program) for i, pid, parent, program in active_spawns}
    need(len(spawn_map) == 13 and spawn_map.get(1, (None, None, None))[1:] == (0, 'smp-user'),
         'root spawn identity mismatch')
    need(set(spawn_map) == {1} | supervisor_pids | {v['pid'] for v in natives.values()},
         'spawn ledger PID set mismatch')
    for job in range(6):
        sup, native = supervisors[job], natives[job]
        need(spawn_map[sup['pid']][1:] == (1, 'smp-user')
             and spawn_map[native['pid']][1:] == (sup['pid'], 'external-workload'),
             'spawn parent/program mismatch')
        need(sup['prepare_i'] < spawn_map[sup['pid']][0]
             and sup['activate_i'] < spawn_map[sup['pid']][0]
             and native['publish_i'] < spawn_map[native['pid']][0],
             'fixture prepare/activation identity does not precede publication')

    suptraps = {}
    for i, _, f in rows(lines, 'SMP APP SCALE SUPTRAP '):
        need(set(f) == {'job', 'pid', 'generation', 'cpu'}, 'supervisor trap fields mismatch')
        job = num(f, 'job')
        need(job in range(6) and job not in suptraps, 'supervisor trap duplicate/range')
        s = supervisors[job]
        need(num(f, 'pid') == s['pid'] and num(f, 'generation') == s['generation']
             and num(f, 'cpu') == job % cpus
             and s['activate_i'] < spawn_map[s['pid']][0] < i,
             'supervisor trap identity/order mismatch')
        cpu = job % cpus
        need(cpu == 0 or timer_index[cpu] < i,
             'AP supervisor trap preceded local timer calibration')
        suptraps[job] = i
    need(set(suptraps) == set(range(6)), 'supervisor trap coverage incomplete')

    traps = {}
    for i, _, f in rows(lines, 'SMP APP SCALE TRAP '):
        need(set(f) == {'job', 'slot', 'pid', 'generation', 'cpu'}, 'native trap fields mismatch')
        job = num(f, 'job')
        need(job in range(6) and job not in traps, 'native first-trap duplicate/range')
        n = natives[job]
        gen = num(f, 'generation')
        need(num(f, 'pid') == n['pid'] and num(f, 'slot') == n['slot']
             and num(f, 'cpu') == n['cpu'] and gen == (0 if cpus == 1 else gen)
             and (gen == 0 if cpus == 1 else gen > 0)
             and n['publish_i'] < spawn_map[n['pid']][0] < i,
             'native first-trap identity/order mismatch')
        cpu = num(f, 'cpu')
        need(cpu == 0 or timer_index[cpu] < i,
             'AP native trap preceded local timer calibration')
        n['generation'], n['trap_i'] = gen, i
        traps[job] = i
    need(set(traps) == set(range(6)), 'native first-trap coverage incomplete')
    all_gens = [num(rf, 'generation')] + [s['generation'] for s in supervisors.values()] + [n['generation'] for n in natives.values()]
    need((all(g == 0 for g in all_gens) if cpus == 1 else len(set(all_gens)) == 13),
         'live fixture generation census mismatch')
    identities = rows(lines, 'SMP APP SCALE IDENTITY ')
    need(len(identities) == 6, 'native CPL3/CR3 identity witness census mismatch')
    for job, trap_i in traps.items():
        need(trap_i + 1 < len(lines)
             and lines[trap_i + 1] == 'SMP APP SCALE IDENTITY cpl=3 cr3=owned',
             'native identity witness not adjacent to its first trap')

    preempts = {}
    for i, _, f in rows(lines, 'SMP APP SCALE PREEMPT '):
        need(set(f) == {'job', 'pid', 'generation', 'cpu', 'saved'}, 'preempt fields mismatch')
        job = num(f, 'job')
        need(job in range(6) and job not in preempts, 'preempt witness duplicate/range')
        n = natives[job]
        need(num(f, 'pid') == n['pid'] and num(f, 'generation') == n['generation']
             and num(f, 'cpu') == n['cpu'] and num(f, 'saved') == 1
             and traps[job] < i,
             'saved native preemption identity/order mismatch')
        preempts[job] = i
    if cpus > 1:
        need(set(preempts) == set(range(6)), 'all six native jobs need saved timer preemption')

    start = rows(lines, 'SMP APP SCALE START ')
    need(len(start) == 1, 'start barrier missing/duplicate')
    start_i, _, sf = start[0]
    need(set(sf) == {'jobs', 'cpus', 'bytes-per-job', 'blocked'}
         and num(sf, 'jobs') == 6 and num(sf, 'cpus') == cpus
         and num(sf, 'bytes-per-job') == INPUT and num(sf, 'blocked') == 6,
         'start barrier census/work mismatch')
    need(all(suptraps[j] < start_i and traps[j] < start_i for j in range(6)),
         'start released before all supervisors/jobs reached the barrier')
    if cpus > 1:
        need(all(start_i < preempts[j] for j in range(6)),
             'native saved preemption predates measured release')

    jobs = {}
    for i, _, f in rows(lines, 'SMP APP SCALE JOB '):
        need(set(f) == {'job', 'pid', 'parent', 'slot', 'generation', 'cpu', 'calls',
                        'preempts', 'resumed', 'input', 'output', 'exited', 'reclaimed'},
             'job completion fields mismatch')
        job = num(f, 'job')
        need(job in range(6) and job not in jobs, 'job completion duplicate/range')
        n = natives[job]
        expected = {'pid': n['pid'], 'parent': n['parent'], 'slot': n['slot'],
                    'generation': n['generation'], 'cpu': n['cpu']}
        need(all(num(f, k) == v for k, v in expected.items())
             and num(f, 'calls') > 0 and num(f, 'input') == INPUT
             and num(f, 'output') == OUTPUT and num(f, 'exited') == 1
             and num(f, 'reclaimed') == 1,
             'job identity, work, or terminal fence mismatch')
        if cpus > 1:
            need(num(f, 'preempts') > 0, 'SMP native job lacks saved preemption')
        else:
            num(f, 'preempts')
        need(num(f, 'resumed') == (1 if cpus > 1 or num(f, 'preempts') > 0 else 0),
             'job resume witness mismatch')
        if cpus > 1:
            need(preempts[job] < i, 'job completed before saved preemption witness')
        jobs[job] = i
    need(set(jobs) == set(range(6)), 'six completed job rows required')
    job_preempted = {job for job in range(6)
                     if num(next(f for _, _, f in rows(lines, 'SMP APP SCALE JOB ')
                                 if num(f, 'job') == job), 'preempts') > 0}
    need(job_preempted == set(preempts), 'saved-preemption rows disagree with job counters')

    departures = {}
    for i, _, f in rows(lines, 'SMP APP SCALE DEPART '):
        need(set(f) == {'job', 'slot', 'pid', 'generation', 'owner'}, 'departure fields mismatch')
        job = num(f, 'job')
        need(job in range(6) and job not in departures, 'duplicate/out-of-range departure')
        n = natives[job]
        need((num(f, 'slot'), num(f, 'pid'), num(f, 'generation'), num(f, 'owner')) ==
             (n['slot'], n['pid'], n['generation'], 0), 'departure ownership identity mismatch')
        departures[job] = i
    need(set(departures) == set(range(6)), 'native queue departure fence incomplete')
    reclaims = {}
    for i, _, f in rows(lines, 'SMP APP SCALE RECLAIM '):
        need(set(f) == {'job', 'pid', 'generation', 'frames', 'handles'}, 'reclaim fields mismatch')
        job = num(f, 'job')
        need(job in range(6) and job not in reclaims, 'duplicate/out-of-range reclaim')
        n = natives[job]
        need((num(f, 'pid'), num(f, 'generation'), num(f, 'frames'), num(f, 'handles')) ==
             (n['pid'], n['generation'], 0, 0), 'reclaim identity/resource fence mismatch')
        reclaims[job] = i
    need(set(reclaims) == set(range(6)), 'native post-reap reclaim fence incomplete')
    for job in range(6):
        need(start_i < departures[job] < reclaims[job] < jobs[job],
             'job departure/reclaim does not precede completion receipt')

    done = rows(lines, 'SMP APP SCALE DONE ')
    need(len(done) == 1, 'measurement completion missing/duplicate')
    done_i, _, df = done[0]
    need(set(df) == {'jobs', 'cpus', 'input', 'output', 'tsc'}
         and num(df, 'jobs') == 6 and num(df, 'cpus') == cpus
         and num(df, 'input') == 6 * INPUT and num(df, 'output') == 6 * OUTPUT
         and num(df, 'tsc') > 0,
         'measurement completion counters/time mismatch')
    need(start_i < min(jobs.values()) and max(jobs.values()) < done_i,
         'job completion outside measured interval')

    exits = []
    for i, line in enumerate(lines):
        m = re.fullmatch(r'USER EXIT pid=(\d+) status=(\d+)', line)
        if m:
            exits.append((i, int(m[1]), int(m[2])))
    need(len(exits) == 13 and {pid for _, pid, _ in exits} == set(spawn_map),
         'normal exit census mismatch')
    exit_map = {pid: (i, status) for i, pid, status in exits}
    need(exit_map[1][1] == 0, 'root exit status')
    for job in range(6):
        s, n = supervisors[job], natives[job]
        need(exit_map[s['pid']][1] == 0 and exit_map[n['pid']][1] == 0,
             'supervisor/native exit status mismatch')
        need(traps[job] < start_i < exit_map[n['pid']][0] < departures[job] < reclaims[job]
             < exit_map[s['pid']][0] < jobs[job] < done_i,
             'native lifecycle outside start/done fence')
        if job in preempts:
            need(start_i < preempts[job] < exit_map[n['pid']][0] < departures[job],
                 'saved preemption outside measured native execution')
        need(suptraps[job] < start_i < exit_map[s['pid']][0],
             'supervisor lifecycle outside fixture fence')
    need(done_i < exit_map[1][0], 'root exit precedes completed native work')

    fences = rows(lines, 'SMP APP SCALE FENCE ')
    need(len(fences) == 1, 'global resource fence missing/duplicate')
    fence_i, _, ff = fences[0]
    need(set(ff) == {'frames', 'processes', 'cells', 'pipes', 'aps-idle'}
         and all(num(ff, k) == 0 for k in ('frames', 'processes', 'cells', 'pipes'))
         and num(ff, 'aps-idle') == cpus - 1,
         'global process/object/frame/AP fence mismatch')
    if leaf:
        need(max(i for i, _, _ in leaf_rows) < fence_i,
             'leaf measurement report must precede terminal resource fence')
    queue_quiescent = [i for i, x in enumerate(lines)
                       if x == 'SMP QUEUE QUIESCENT registered=0 queued=0 running=0']
    if cpus > 1:
        need(len(queue_quiescent) == 1 and exit_map[1][0] < queue_quiescent[0] < fence_i,
             'SMP run lacks the queue quiescence fence')
    else:
        need(not queue_quiescent, 'UP run unexpectedly claims SMP queue quiescence')

    lock_rows = rows(lines, 'SMP SCALE LOCK ')
    need(len(lock_rows) == 12 * cpus, 'BKL interval path census mismatch')
    lockdata = {cpu: {} for cpu in range(cpus)}
    for i, _, f in lock_rows:
        need(set(f) == {'phase', 'cpu', 'spans', 'contended', 'retries', 'wait-tsc',
                        'hold-tsc', 'wait-max', 'hold-max', 'path'},
             'BKL interval fields mismatch')
        need(num(f, 'phase') == 1, 'unexpected BKL measurement epoch')
        cpu, path = num(f, 'cpu'), f['path']
        need(cpu in range(cpus) and path in PATHS and path not in lockdata[cpu],
             'BKL interval CPU/path duplicate or out of range')
        vals = {k: num(f, k) for k in ('spans', 'contended', 'retries', 'wait-tsc',
                                       'hold-tsc', 'wait-max', 'hold-max')}
        need(vals['spans'] > 0 or all(v == 0 for v in vals.values()),
             'BKL counters without completed interval')
        need(vals['contended'] <= vals['spans'] and vals['retries'] >= vals['contended']
             and vals['wait-max'] <= vals['wait-tsc'] and vals['hold-max'] <= vals['hold-tsc'],
             'BKL interval counter inequality')
        lockdata[cpu][path] = {'index': i, **vals}
    for cpu, d in lockdata.items():
        need(set(d) == set(PATHS), 'BKL path set incomplete')
        total = d['total']
        for key in ('spans', 'contended', 'retries', 'wait-tsc', 'hold-tsc'):
            need(sum(d[p][key] for p in PATHS[:-1]) == total[key], f'BKL {key} partition mismatch')
        for key in ('wait-max', 'hold-max'):
            need(max(d[p][key] for p in PATHS[:-1]) == total[key], f'BKL {key} maximum mismatch')
        if cpus == 1:
            need(all(d[p][k] == 0 for p in PATHS for k in
                     ('spans', 'contended', 'retries', 'wait-tsc', 'hold-tsc', 'wait-max', 'hold-max')),
                 'UP measurement should have zero BKL interval counters')
        else:
            need(total['spans'] > 0, 'SMP BKL interval total is empty')
    need(all(done_i < lockdata[c][path]['index'] < exit_map[1][0]
             for c in range(cpus) for path in PATHS),
         'BKL interval rows must follow disarm and precede root terminal exit')

    leaf_result = None
    if leaf:
        leaf_config_i = leaf_config[0][0]
        need(leaf_config_i < start_i, 'leaf configuration must precede measured release')
        leafdata = {cpu: {} for cpu in range(cpus)}
        for i, _, f in leaf_rows:
            need(set(f) == {'phase', 'cpu', 'calls', 'units', 'tsc', 'max',
                            'excluded-calls', 'region'},
                 'leaf measurement fields mismatch')
            cpu, region = num(f, 'cpu'), f['region']
            need(num(f, 'phase') == 1 and cpu in range(cpus)
                 and region in (*LEAF_REGIONS, 'total')
                 and region not in leafdata[cpu],
                 'leaf measurement CPU/region duplicate or out of range')
            vals = {k: num(f, k) for k in
                    ('calls', 'units', 'tsc', 'max', 'excluded-calls')}
            need(vals['max'] <= vals['tsc'], 'leaf maximum exceeds accumulated ticks')
            if region != 'total':
                need(vals['calls'] > 0, f'leaf region has no observations: {region} CPU {cpu}')
                need((vals['units'] > 0 if LEAF_UNITS[region] else vals['units'] == 0),
                     f'leaf successful-byte region census mismatch: {region} CPU {cpu}')
            leafdata[cpu][region] = {'index': i, **vals}
        for cpu, d in leafdata.items():
            need(set(d) == {*LEAF_REGIONS, 'total'}, 'leaf region set incomplete')
            total = d['total']
            for key in ('calls', 'units', 'tsc'):
                need(sum(d[r][key] for r in LEAF_REGIONS) == total[key],
                     f'leaf {key} total mismatch on CPU {cpu}')
            need(max(d[r]['max'] for r in LEAF_REGIONS) == total['max'],
                 f'leaf maximum total mismatch on CPU {cpu}')
            excluded = {d[r]['excluded-calls'] for r in (*LEAF_REGIONS, 'total')}
            need(len(excluded) == 1, f'leaf excluded-call census differs on CPU {cpu}')
            need(all(d[r]['excluded-calls'] == next(iter(excluded)) for r in LEAF_REGIONS),
                 f'leaf excluded-call census differs on CPU {cpu}')
            if cpus > 1:
                region_ticks = sum(d[r]['tsc'] for r in LEAF_REGIONS)
                need(region_ticks <= lockdata[cpu]['total']['hold-tsc'],
                     f'leaf exclusive ticks exceed completed BKL hold on CPU {cpu}')
        for region, expected in LEAF_UNITS.items():
            need(sum(leafdata[c][region]['units'] for c in range(cpus)) == expected,
                 f'global leaf transfer-byte census mismatch for {region}')
        leaf_indices = [r['index'] for d in leafdata.values()
                        for r in d.values()]
        need(done_i < min(leaf_indices)
             and max(lockdata[c][path]['index'] for c in range(cpus) for path in PATHS)
                 < min(leaf_indices)
             and max(leaf_indices) < exit_map[1][0],
             'leaf report must follow DONE/BKL report and precede root exit')
        leaf_result = {'config': leaf_config[0][1],
                       'rows': [x[1] for x in leaf_rows]}

    ok = rows(lines, 'SMP APP SCALE OK ')
    boots = [i for i, x in enumerate(lines) if x == 'ABSD BOOT OK']
    need(len(ok) == 1 and fields(ok[0][1]) == {
         'jobs': '6', 'tasks': '13', 'input': 'exact', 'output': 'exact', 'reclaimed': '1'},
         'terminal application-scale fence mismatch')
    need(len(boots) == 1 and done_i < exit_map[1][0] < fence_i < ok[0][0] < boots[0],
         'success/boot terminal chronology mismatch')
    return {'cpus': cpus, 'root': root[0][1], 'leaf': leaf_result,
            'supervisors': [x[1] for x in rows(lines, 'SMP APP SCALE SUPERVISOR ')],
            'supervisor_keys': [x[1] for x in rows(lines, 'SMP APP SCALE SUPKEY ')],
            'native': [x[1] for x in nr], 'traps': [x[1] for x in rows(lines, 'SMP APP SCALE TRAP ')],
            'preempts': [x[1] for x in rows(lines, 'SMP APP SCALE PREEMPT ')],
            'departures': [x[1] for x in rows(lines, 'SMP APP SCALE DEPART ')],
            'reclaims': [x[1] for x in rows(lines, 'SMP APP SCALE RECLAIM ')],
            'jobs': [x[1] for x in rows(lines, 'SMP APP SCALE JOB ')],
            'locks': [x[1] for x in lock_rows], 'done': done[0][1], 'success': ok[0][1],
            'fence': fences[0][1], 'queue_quiescent': queue_quiescent,
            'boot_index': boots[0]}


def metrics(path, cpus, lines):
    m = json.loads(Path(path).read_text())
    expected_mode = 'legacy-qemu-default' if cpus == 1 else 'explicit-smp-scheduler-test'
    expected_guest = None if cpus == 1 else {'sockets': 1, 'cores': cpus, 'threads': 1}
    need(m.get('vcpus') == cpus and m.get('topology') == 'separate'
         and m.get('guest_topology_mode') == expected_mode
         and m.get('guest_topology') == expected_guest,
         'QEMU runtime metrics topology mismatch')
    for key in ('wall_seconds', 'qemu_user_seconds', 'qemu_system_seconds'):
        val = m.get(key)
        need(isinstance(val, (int, float)) and math.isfinite(val) and val >= 0,
             f'invalid runtime metric: {key}')
    for key in ('qemu_status', 'run_status', 'status'):
        if key in m:
            need(m[key] == 3, f'QEMU status metric is not expected exit 3: {key}')
    starts = [x for x in lines if x.startswith('SMP APP SCALE START ')]
    dones = [x for x in lines if x.startswith('SMP APP SCALE DONE ')]
    need(len(starts) == len(dones) == 1, 'measured workload host-observation boundaries missing/duplicate')
    observed = m.get('serial_observations_seconds')
    need(isinstance(observed, dict) and set(observed) == {starts[0], dones[0]},
         'QEMU host observations do not exactly match measured workload boundaries')
    a, b = observed[starts[0]], observed[dones[0]]
    need(all(isinstance(v, (int, float)) and math.isfinite(v) and v >= 0 for v in (a, b))
         and a <= b <= m['wall_seconds'], 'host phase observation time invalid/order mismatch')
    return m


def self_test(lines, cpus, leaf=False):
    controls = []
    def reject(name, mutate):
        changed = list(lines)
        mutate(changed)
        need(changed != lines, f'mutant was a no-op: {name}')
        try:
            check_lines(changed, cpus, leaf)
        except (AssertionError, KeyError, StopIteration, ValueError):
            controls.append(name)
            return
        raise AssertionError(f'deterministic receipt mutation accepted: {name}')
    def first(prefix):
        return next(i for i, x in enumerate(lines) if x.startswith(prefix))
    def delete(prefix):
        return lambda r: r.pop(first(prefix))
    def duplicate(prefix):
        return lambda r: r.insert(first(prefix) + 1, r[first(prefix)])
    def replace(prefix, key, value):
        idx = first(prefix); f = fields(lines[idx]); old = f[key]
        new = str(value(old) if callable(value) else value)
        return lambda r: r.__setitem__(idx, re.sub(rf'\b{re.escape(key)}=[^\s]+', f'{key}={new}', r[idx], count=1))
    reject('missing-native-trap', delete('SMP APP SCALE TRAP '))
    reject('duplicate-native-job', duplicate('SMP APP SCALE JOB '))
    reject('duplicate-root-identity', duplicate('SMP APP SCALE ROOT '))
    reject('wrong-native-parent', replace('SMP APP SCALE NATIVE ', 'parent', lambda x: int(x) + 1))
    reject('stale-generation', replace('SMP APP SCALE TRAP ', 'generation', lambda x: int(x) + 1))
    reject('wrong-cpu-assignment', replace('SMP APP SCALE SUPERVISOR ', 'cpu', '99'))
    reject('missing-start-barrier', delete('SMP APP SCALE START '))
    def early_start(r):
        src = first('SMP APP SCALE START ')
        row = r.pop(src)
        dest = first('SMP APP SCALE TRAP ')
        r.insert(dest, row)
    reject('start-before-native-trap', early_start)
    reject('pipe-barrier-count', replace('SMP APP SCALE START ', 'blocked', '5'))
    if cpus > 1:
        reject('missing-saved-preemption', delete('SMP APP SCALE PREEMPT '))
        def spawn_after_trap(r):
            trap = next(fields(x) for x in lines if x.startswith('SMP APP SCALE SUPTRAP '))
            pid = trap['pid']
            publication = f"SPAWN OK pid={pid} parent=1 program=smp-user"
            src = r.index(publication); row = r.pop(src)
            r.insert(r.index(next(x for x in r if x.startswith('SMP APP SCALE SUPTRAP '))) + 1, row)
        reject('publication-after-first-trap', spawn_after_trap)
        def preempt_after_depart(r):
            preempt = next(x for x in lines if x.startswith('SMP APP SCALE PREEMPT '))
            f = fields(preempt); depart = next(x for x in lines if x.startswith('SMP APP SCALE DEPART ')
                                                and fields(x)['job'] == f['job'])
            src = r.index(preempt); row = r.pop(src)
            r.insert(r.index(depart) + 1, row)
        reject('preempt-after-departure', preempt_after_depart)
        def queue_before_root_exit(r):
            q = 'SMP QUEUE QUIESCENT registered=0 queued=0 running=0'
            row = r.pop(r.index(q)); root_exit = next(i for i, x in enumerate(r)
                                                       if x.startswith('USER EXIT pid=1 '))
            r.insert(root_exit, row)
        reject('quiescence-before-root-exit', queue_before_root_exit)
        def lock_after_root_exit(r):
            row = next(x for x in lines if x.startswith('SMP SCALE LOCK '))
            r.remove(row); root_exit = next(i for i, x in enumerate(r)
                                           if x.startswith('USER EXIT pid=1 '))
            r.insert(root_exit + 1, row)
        reject('lock-report-after-root-exit', lock_after_root_exit)
        reject('bad-timer-quantum', replace('SMP TIMER START ', 'quantum-tsc', '16777215'))
        def timer_after_actor(r):
            timer = next(x for x in lines if x.startswith('SMP TIMER START '))
            cpu = fields(timer)['cpu']
            actor = next(x for x in lines if x.startswith('SMP APP SCALE SUPTRAP ')
                         and fields(x)['cpu'] == cpu)
            r.remove(timer); r.insert(r.index(actor) + 1, timer)
        reject('timer-calibration-after-actor', timer_after_actor)
    reject('missing-job-completion', delete('SMP APP SCALE JOB '))
    reject('missing-departure-proof', delete('SMP APP SCALE DEPART '))
    reject('missing-reclaim-proof', delete('SMP APP SCALE RECLAIM '))
    reject('missing-global-fence', delete('SMP APP SCALE FENCE '))
    reject('wrong-input-census', replace('SMP APP SCALE JOB ', 'input', INPUT - 1))
    reject('wrong-output-census', replace('SMP APP SCALE JOB ', 'output', OUTPUT + 1))
    reject('wrong-done-work', replace('SMP APP SCALE DONE ', 'input', 1))
    reject('wrong-lock-total', replace('SMP SCALE LOCK ', 'spans', lambda x: int(x) + 1))
    reject('wrong-native-user-identity', lambda r: r.__setitem__(first('SMP APP SCALE IDENTITY '), 'SMP APP SCALE IDENTITY cpl=0 cr3=owned'))
    reject('nonzero-frame-remainder', replace('SMP APP SCALE FENCE ', 'frames', '1'))
    reject('ap-quiescence-census', replace('SMP APP SCALE FENCE ', 'aps-idle', cpus))
    if cpus > 1:
        reject('missing-queue-quiescence', lambda r: r.pop(next(i for i, x in enumerate(r)
               if x == 'SMP QUEUE QUIESCENT registered=0 queued=0 running=0')))
    reject('early-success', lambda r: r.insert(first('SMP APP SCALE DONE '), r.pop(first('SMP APP SCALE OK '))))
    reject('missing-boot', lambda r: r.__setitem__(slice(None), [x for x in r if x != 'ABSD BOOT OK']))
    if leaf:
        reject('missing-leaf-config', delete('SMP APP LEAF CONFIG '))
        reject('duplicate-leaf-row', duplicate('SMP APP LEAF phase='))
        reject('wrong-leaf-units', replace('SMP APP LEAF phase=', 'units',
               lambda x: int(x) + 1))
        reject('wrong-leaf-phase', replace('SMP APP LEAF phase=', 'phase', '2'))
        def leaf_max_exceeds_ticks(r):
            i = first('SMP APP LEAF phase=')
            f = fields(r[i])
            r[i] = re.sub(r'\bmax=[^\s]+', f"max={int(f['tsc']) + 1}", r[i], count=1)
        reject('wrong-leaf-maximum', leaf_max_exceeds_ticks)
        reject('wrong-leaf-excluded-calls', replace('SMP APP LEAF phase=', 'excluded-calls',
               lambda x: int(x) + 1))
        def late_leaf_config(r):
            row = r.pop(first('SMP APP LEAF CONFIG '))
            r.insert(first('SMP APP SCALE START '), row)
        reject('leaf-config-after-start', late_leaf_config)
        if cpus > 1:
            def overcredited_hold(r):
                cpu = 1
                rows_for_cpu = [(i, fields(x)) for i, x in enumerate(lines)
                                if x.startswith('SMP APP LEAF phase=') and fields(x).get('cpu') == str(cpu)]
                hold = num(next(fields(x) for x in lines
                                if x.startswith('SMP SCALE LOCK ')
                                and fields(x).get('cpu') == str(cpu)
                                and fields(x).get('path') == 'total'), 'hold-tsc')
                region_row = next((i, f) for i, f in rows_for_cpu if f['region'] == LEAF_REGIONS[0])
                row_i, f = region_row
                new_ticks = hold + 1
                r[row_i] = re.sub(r'\btsc=[^\s]+', f'tsc={new_ticks}', r[row_i], count=1)
                r[row_i] = re.sub(r'\bmax=[^\s]+', f'max={new_ticks}', r[row_i], count=1)
                total_i, _ = next((i, f) for i, f in rows_for_cpu if f['region'] == 'total')
                prior_sum = sum(num(f, 'tsc') for _, f in rows_for_cpu if f['region'] != 'total')
                prior = num(f, 'tsc')
                new_total = prior_sum - prior + new_ticks
                r[total_i] = re.sub(r'\btsc=[^\s]+', f'tsc={new_total}', r[total_i], count=1)
                r[total_i] = re.sub(r'\bmax=[^\s]+', f'max={new_ticks}', r[total_i], count=1)
            reject('leaf-exceeds-credited-hold', overcredited_hold)
    else:
        def unexpected_leaf(r):
            r.insert(first('SMP APP SCALE START '),
                     'SMP APP LEAF CONFIG regions=6 coverage=exclusive-completed units=successful-bytes')
        reject('unexpected-leaf-rows-in-baseline', unexpected_leaf)
    return controls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--serial', required=True)
    ap.add_argument('--placement', required=True)
    ap.add_argument('--metrics', required=True)
    ap.add_argument('--cpus', type=int, required=True)
    ap.add_argument('--results')
    ap.add_argument('--mutants', action='store_true')
    ap.add_argument('--qemu-status')
    ap.add_argument('--leaf', action='store_true',
                    help='require the closed application leaf-measurement receipt')
    args = ap.parse_args()
    lines = Path(args.serial).read_text(errors='replace').splitlines()
    place = placement(args.placement, args.cpus)
    result = check_lines(lines, args.cpus, args.leaf)
    result['placement'] = place
    result['qemu_metrics'] = metrics(args.metrics, args.cpus, lines)
    if args.qemu_status:
        status = int(Path(args.qemu_status).read_text().strip())
        need(status == 3, f'QEMU process status {status}, expected 3')
        result['qemu_status'] = status
    if args.mutants:
        result['mutation_controls'] = self_test(lines, args.cpus, args.leaf)
    if args.results:
        Path(args.results).write_text(json.dumps(result, indent=2) + '\n')
    print(f"SMP APP SCALE RECEIPT OK cpus={args.cpus}" +
          (" leaf=1" if args.leaf else " leaf=0") +
          (f" mutants={len(result['mutation_controls'])}" if args.mutants else ''))


if __name__ == '__main__':
    main()
