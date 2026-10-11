#!/usr/bin/env python3
"""Closed receipt oracle for AP-pinned native text-statistics pressure runs."""

import argparse
import re
from pathlib import Path


def need(ok, message):
    if not ok:
        raise AssertionError(message)


def kv(line):
    return {key: value for key, value in re.findall(r'([a-z0-9-]+)=([^\s]+)', line)}


def number(value, label):
    try:
        return int(value, 10)
    except (TypeError, ValueError):
        raise AssertionError(f'{label} is not a decimal integer')


def selected(lines, prefix):
    return [(index, line, kv(line)) for index, line in enumerate(lines)
            if line.startswith(prefix)]


def check_placement(path, cpus):
    import json

    placement = json.loads(Path(path).read_text())
    need(placement.get('kvm') == {'enabled': True, 'present': True},
         'QEMU placement does not attest KVM')
    need(placement.get('host_topology') == 'separate'
         and placement.get('guest_topology_mode') == 'explicit-smp-scheduler-test'
         and placement.get('guest_topology') == {
             'sockets': 1, 'cores': cpus, 'threads': 1},
         'QEMU placement topology differs from admitted separate-core guest')
    vcpus = placement.get('vcpus')
    need(isinstance(vcpus, list) and len(vcpus) == cpus,
         'QEMU placement vCPU count mismatch')
    need({cpu.get('cpu-index') for cpu in vcpus} == set(range(cpus)),
         'QEMU placement vCPU indexes are incomplete/duplicate')
    host_cores = set()
    for cpu in vcpus:
        key = (cpu.get('host-package'), cpu.get('host-core'))
        need(key[0] is not None and key[1] is not None and key not in host_cores,
             'QEMU vCPUs are not pinned to distinct host cores')
        host_cores.add(key)
        need(cpu.get('affinity') == [cpu.get('host-cpu')],
             'QEMU vCPU affinity does not match its recorded host CPU')


def check_lines(lines, cpus, app_cpu):
    need(cpus in (2, 4, 6), 'unsupported guest CPU count')
    need(1 <= app_cpu < cpus, 'native application CPU is outside admitted AP range')
    reserved = 2 * (cpus - 1)

    config = selected(lines, 'SMP APP PRESSURE CONFIG ')
    need(len(config) == 1, 'pressure configuration missing/duplicate')
    config_index, _, cf = config[0]
    need(cf == {'cpus': str(cpus), 'reserved': str(reserved),
                'app-cpu': str(app_cpu), 'quantum-tsc': '16777216',
                'reference': 'ap-local-tsc'},
         f'pressure configuration mismatch: {cf}')

    calibrated = selected(lines, 'SMP APP PRESSURE CALIBRATED ')
    need(len(calibrated) == 1, 'AP calibration readiness fence missing/duplicate')
    calibrated_index, _, kf = calibrated[0]
    need(kf == {'cpus': str(cpus), 'ready-mask': str((1 << cpus) - 2),
                'owners': '0', 'actor-calls': '0', 'phase': 'before-user'},
         f'AP calibration readiness fence mismatch: {kf}')

    reserve = selected(lines, 'SMP APP PRESSURE RESERVE ')
    need(len(reserve) == 1, 'pressure reservation census missing/duplicate')
    reserve_index, _, rf = reserve[0]
    need(rf == {'pid': '1', 'cpus': str(cpus), 'reserved': str(reserved),
                'census': str(1 + reserved)},
         f'pressure reservation census mismatch: {rf}')
    need(config_index < calibrated_index < reserve_index,
         'calibration readiness/configuration/reservation chronology')

    user_traps = selected(lines, 'SMP USER TRAP ')
    need(len(user_traps) == cpus,
         'first user-entry witness count does not match guest CPU count')
    need(all(calibrated_index < index for index, _, _ in user_traps),
         'user entered CPL3 before AP timer calibration fence')

    actors = selected(lines, 'SMP APP PRESSURE ACTOR ')
    need(len(actors) == reserved, 'pressure actor census count')
    need(all(calibrated_index < index for index, _, _ in actors),
         'pressure actor entered before AP timer calibration fence')
    actor_keys = set()
    actor_pids = set()
    actor_generations = set()
    roles = set()
    actors_by_pid = {}
    actor_counts = {cpu: 0 for cpu in range(cpus)}
    actor_lines_by_cpu = {cpu: [] for cpu in range(cpus)}
    for index, _, f in actors:
        cpu = number(f.get('cpu'), 'actor CPU')
        pid = number(f.get('pid'), 'actor PID')
        generation = number(f.get('generation'), 'actor generation')
        role = number(f.get('role'), 'actor role')
        need(0 < pid and generation > 0 and f.get('cpl') == '3'
             and f.get('cr3') == 'owned'
             and set(f) == {'cpu', 'pid', 'generation', 'role', 'cpl', 'cr3'},
             'invalid pressure actor ownership witness')
        need(1 <= cpu < cpus and 200 <= role < 200 + reserved
             and cpu == (role - 200) // 2 + 1,
             'pressure actor CPU/role outside reservation')
        identity = (pid, generation)
        need(identity not in actor_keys and pid not in actor_pids
             and generation not in actor_generations and role not in roles,
             'duplicate pressure actor PID/generation or role')
        actor_keys.add(identity)
        actor_pids.add(pid)
        actor_generations.add(generation)
        roles.add(role)
        actors_by_pid[pid] = (index, cpu, role, generation)
        actor_counts[cpu] += 1
        actor_lines_by_cpu[cpu].append(index)
    need(roles == set(range(200, 200 + reserved)), 'pressure actor roles are incomplete')
    need(all(actor_counts[cpu] == 2 for cpu in range(1, cpus)),
         'each AP must own exactly two pressure actors')

    user_trap_cpus = set()
    for index, _, f in user_traps:
        need(set(f) == {'seq', 'cpu', 'slot', 'pid', 'epoch'},
             'first user-entry witness fields mismatch')
        cpu = number(f.get('cpu'), 'first user-entry CPU')
        pid = number(f.get('pid'), 'first user-entry PID')
        number(f.get('seq'), 'first user-entry sequence')
        number(f.get('slot'), 'first user-entry slot')
        number(f.get('epoch'), 'first user-entry epoch')
        need(0 <= cpu < cpus and cpu not in user_trap_cpus,
             'first user-entry CPU missing/duplicated/out of range')
        user_trap_cpus.add(cpu)
        if cpu == 0:
            need(pid == 1 and f['slot'] == '0',
                 'BSP first user-entry witness is not PID-1 init')
        else:
            need(pid in actors_by_pid and actors_by_pid[pid][1] == cpu
                 and actors_by_pid[pid][0] < index,
                 'AP first user-entry witness is not its published pressure actor')
    need(user_trap_cpus == set(range(cpus)),
         'first user-entry CPU coverage is incomplete')

    expected_preempt_roles = set(range(201, 200 + reserved, 2))
    preempts = selected(lines, 'SMP APP PRESSURE PREEMPT ')
    resumes = selected(lines, 'SMP APP PRESSURE RESUME ')
    need(len(preempts) == len(resumes) == cpus - 1,
         'odd-role per-AP timer-preemption/resume witness count')
    preempt_by_role = {}
    resume_by_role = {}
    actor_pid_by_role = {role: pid for pid, (_, _, role, _) in actors_by_pid.items()}
    for rows, records, label in ((preempts, preempt_by_role, 'preemption'),
                                 (resumes, resume_by_role, 'resume')):
        for index, _, f in rows:
            need(set(f) == {'cpu', 'pid', 'generation', 'role', 'saved', 'live'}
                 and f.get('saved') == '1' and f.get('live') == '1',
                 f'{label} witness fields/live saved frame mismatch')
            cpu = number(f.get('cpu'), f'{label} CPU')
            pid = number(f.get('pid'), f'{label} PID')
            generation = number(f.get('generation'), f'{label} generation')
            role = number(f.get('role'), f'{label} role')
            need(role in expected_preempt_roles and role not in records,
                 f'{label} witness has duplicate or non-odd actor role')
            actor_pid = actor_pid_by_role[role]
            actor_index, actor_cpu, actor_role, actor_generation = actors_by_pid[actor_pid]
            need((cpu, pid, generation, role) ==
                 (actor_cpu, actor_pid, actor_generation, actor_role),
                 f'{label} witness identity differs from its actor first trap')
            records[role] = (index, actor_index, cpu, pid, generation)
    need(set(preempt_by_role) == set(resume_by_role) == expected_preempt_roles,
         'odd-role per-AP timer-preemption/resume coverage incomplete')
    for role in expected_preempt_roles:
        preempt_index, actor_index, _, _, _ = preempt_by_role[role]
        resume_index, resume_actor_index, _, _, _ = resume_by_role[role]
        need(actor_index == resume_actor_index
             and actor_index < preempt_index < resume_index,
             f'actor role {role} first-trap/preemption/resume order')

    spawns = selected(lines, 'SPAWN OK ')
    exhaustion = [i for i, line in enumerate(lines) if line == 'SPAWN EXHAUSTION OK']
    model = [i for i, line in enumerate(lines) if line == 'PROCESS MODEL OK']
    need(len(exhaustion) == len(model) == 1 and exhaustion[0] < model[0],
         'process bootstrap exhaustion/model boundary missing or reordered')
    init_spawns = [(i, f) for i, _, f in spawns
                   if f == {'pid': '1', 'parent': '0', 'program': 'init'}]
    need(len(init_spawns) == 2
         and init_spawns[0][0] < exhaustion[0] < init_spawns[1][0] < model[0],
         'PID-1 init spawn exhaustion boundary mismatch')
    spawn_fields = {}
    for index, _, f in spawns:
        if 'pid' in f:
            pid = number(f.get('pid'), 'spawn PID')
            if pid == 1:
                need(f == {'pid': '1', 'parent': '0', 'program': 'init'},
                     'unexpected PID-1 spawn identity')
                continue
            need(index > model[0], 'non-bootstrap process published before process model')
            need(pid not in spawn_fields, 'duplicate process spawn receipt')
            spawn_fields[pid] = (f, index)
    for pid, _ in actor_keys:
        need(spawn_fields.get(pid, (None,))[0] == {'pid': str(pid), 'parent': '0',
                                                   'program': 'smp-user'},
             f'pressure actor PID {pid} lacks exact kernel-parent spawn receipt')
        spawn_index = spawn_fields[pid][1]
        need(spawn_index < actors_by_pid[pid][0],
             f'pressure actor PID {pid} first trap precedes process publication')

    app_traps = selected(lines, 'SMP APP TRAP ')
    need(len(app_traps) == 1, 'native application trap missing/duplicate')
    trap_index, trap_line, tf = app_traps[0]
    need(tf.get('cpu') == str(app_cpu) and number(tf.get('pid'), 'native PID') > 1
         and set(tf) == {'cpu', 'pid', 'cpl', 'cr3', 'catalog'}
         and trap_line.endswith('cpl=3 cr3=owned catalog=external-workload'),
         'native application first-trap identity/ownership mismatch')
    need(number(tf['pid'], 'native PID') not in actor_pids,
         'native application PID overlaps a pressure actor')
    native_pid = number(tf['pid'], 'native PID')
    need(calibrated_index < trap_index,
         'native application entered before AP timer calibration fence')
    need(spawn_fields.get(native_pid, (None,))[0] == {'pid': str(native_pid), 'parent': '1',
                                                      'program': 'external-workload'},
         'native application lacks exact external-workload spawn receipt')
    native_spawn_index = spawn_fields[native_pid][1]
    need(reserve_index < native_spawn_index < trap_index,
         'native publication/reservation/first-trap chronology')
    need(reserve_index < trap_index, 'native application entered before reservation census')

    summaries = selected(lines, 'SMP APP SUMMARY ')
    need(len(summaries) == 1, 'native application terminal summary missing/duplicate')
    summary_index, _, sf = summaries[0]
    need(set(sf) == {'cpu', 'pid', 'calls', 'timer-irqs', 'exited', 'faults', 'departed'}
         and sf.get('cpu') == str(app_cpu) and sf.get('pid') == tf.get('pid')
         and number(sf.get('calls'), 'native syscall count') > 0
         and number(sf.get('timer-irqs'), 'native timer count') > 0
         and sf.get('exited') == '1' and sf.get('faults') == '0'
         and sf.get('departed') == '1',
         'native application terminal/timer summary mismatch')
    need(trap_index < summary_index, 'native summary precedes first trap')

    cpu_rows = selected(lines, 'SMP APP PRESSURE CPU ')
    need(len(cpu_rows) == cpus - 1, 'per-AP pressure summary count')
    cpu_records = {}
    for index, _, f in cpu_rows:
        cpu = number(f.get('cpu'), 'pressure summary CPU')
        need(cpu not in cpu_records and cpu < cpus, 'duplicate/out-of-range pressure summary CPU')
        need(set(f) == {'cpu', 'actors', 'calls', 'app-calls', 'exited', 'departed'},
             'pressure summary fields mismatch')
        need(f['actors'] == '2' and number(f['calls'], 'pressure syscall count') > 0
             and f['exited'] == '2' and f['departed'] == '2',
             f'pressure actor completion/call count mismatch on CPU {cpu}')
        app_calls = number(f['app-calls'], 'native-lifetime pressure calls')
        need(0 < app_calls <= number(f['calls'], 'pressure syscall count'),
             f'no pressure progress during native lifetime on AP {cpu}')
        need(cpu > 0 and len(actor_lines_by_cpu[cpu]) == 2
             and max(actor_lines_by_cpu[cpu]) < index,
             f'pressure summary precedes AP actor first-trap witnesses on CPU {cpu}')
        need(trap_index < index,
             f'pressure summary precedes native first trap on CPU {cpu}')
        cpu_records[cpu] = (index, f)
    need(set(cpu_records) == set(range(1, cpus)), 'per-AP pressure summary coverage')
    need(max(index for index, _, _ in cpu_rows) < summary_index,
         'native terminal summary precedes per-AP pressure terminal summaries')

    timers = selected(lines, 'SMP TIMER SUMMARY ')
    need(len(timers) == cpus - 1, 'per-AP timer summary count')
    timer_cpus = set()
    for timer_index, _, f in timers:
        cpu = number(f.get('cpu'), 'timer summary CPU')
        need(1 <= cpu < cpus and cpu not in timer_cpus,
             'duplicate/out-of-range AP timer summary')
        need(set(f) == {'cpu', 'irqs', 'user-irqs', 'switches0', 'switches1'},
             'AP timer summary fields mismatch')
        need(0 < number(f.get('user-irqs'), 'AP user timer IRQ count')
             <= number(f.get('irqs'), 'AP timer IRQ count')
             and number(f.get('switches1'), 'AP timer switch count') > 0,
             f'AP {cpu} lacks ring-3 timer/preemption evidence')
        need(trap_index < timer_index,
             f'AP {cpu} timer summary precedes native application entry')
        timer_cpus.add(cpu)
    need(timer_cpus == set(range(1, cpus)), 'AP timer summary coverage incomplete')

    starts = selected(lines, 'SMP TIMER START ')
    need(len(starts) == cpus - 1 and
         {number(f.get('cpu'), 'timer calibration CPU') for _, _, f in starts}
         == set(range(1, cpus)), 'AP timer calibration coverage missing/duplicate')
    for start_index, _, f in starts:
        need(calibrated_index < start_index,
             'AP timer start was reported before readiness release/calibration fence')
        need(set(f) == {'cpu', 'vector', 'divide', 'initial',
                        'tsc-a-before', 'tsc-a-after', 'count-a',
                        'tsc-b-before', 'tsc-b-after', 'count-b',
                        'quantum-tsc', 'sample-tsc', 'max-jitter', 'reference',
                        'global-time', 'rt-time'},
             'AP timer calibration fields mismatch')
        a_before = number(f['tsc-a-before'], 'calibration TSC A before')
        a_after = number(f['tsc-a-after'], 'calibration TSC A after')
        b_before = number(f['tsc-b-before'], 'calibration TSC B before')
        b_after = number(f['tsc-b-after'], 'calibration TSC B after')
        quantum = number(f['quantum-tsc'], 'calibration quantum TSC')
        sample = number(f['sample-tsc'], 'calibration sample TSC')
        max_jitter = number(f['max-jitter'], 'calibration maximum jitter')
        need(0 <= a_before <= a_after < b_before <= b_after <= 0xffffffffffffffff
             and a_after - a_before <= max_jitter
             and b_after - b_before <= max_jitter
             and b_before - a_after >= sample
             and b_after - a_before < (1 << 34),
             'AP-local TSC sampling order, jitter, or spacing mismatch')
        need(quantum == 16777216 and sample == 33554432
             and max_jitter == 262144 and f['reference'] == 'ap-local-tsc',
             'AP-local TSC calibration constants/reference mismatch')
        mid_a = a_before + (a_after - a_before) // 2
        mid_b = b_before + (b_after - b_before) // 2
        span = mid_b - mid_a
        count_a = number(f['count-a'], 'calibration count-a')
        count_b = number(f['count-b'], 'calibration count-b')
        initial = number(f['initial'], 'calibrated initial count')
        need(span > 0 and 0 < count_b < count_a <= 0xffffffff
             and 1 <= initial <= 0xffffffff
             and initial == (count_a - count_b) * quantum // span
             and f['vector'] == '224' and f['divide'] == '16'
             and f['global-time'] == f['rt-time'] == 'CPU0',
             'AP timer calibration/count or CPU0 clock ownership mismatch')

    exits = {}
    for _, line, f in selected(lines, 'USER EXIT '):
        need(set(f) == {'pid', 'status'}, 'USER EXIT fields mismatch')
        pid = number(f['pid'], 'user exit PID')
        exits.setdefault(pid, []).append((line, f))
    for pid in actor_pids | {native_pid}:
        matching = exits.get(pid, [])
        need(len(matching) == 1 and matching[0][1]['status'] == '0',
             f'process PID {pid} lacks exactly one successful USER EXIT')
        exit_index = next(i for i, line in enumerate(lines) if line == matching[0][0])
        first_trap_index = trap_index if pid == native_pid else actors_by_pid[pid][0]
        terminal_index = summary_index if pid == native_pid else cpu_records[actors_by_pid[pid][1]][0]
        if pid != native_pid and actors_by_pid[pid][2] in expected_preempt_roles:
            role = actors_by_pid[pid][2]
            preempt_index = preempt_by_role[role][0]
            resume_index = resume_by_role[role][0]
            need(first_trap_index < preempt_index < resume_index < exit_index < terminal_index,
                 f'actor role {role} trap/preemption/resume/exit/own-CPU-summary chronology')
        else:
            need(first_trap_index < exit_index < terminal_index,
                 f'process PID {pid} trap/exit/own-CPU-summary chronology')

    pressure = selected(lines, 'SMP USER PRESSURE ')
    need(len(pressure) == 1 and number(pressure[0][2].get('calls1'),
                                      'AP pressure syscall count') > 0,
         'existing AP ring-3 pressure summary missing/empty')

    census = [line for line in lines if line.startswith('EXTERNAL status=')]
    need(census == ['EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0'],
         'exact external resource census missing/duplicate/changed')
    workload = [i for i, line in enumerate(lines) if line == 'EXTERNAL WORKLOAD OK']
    boots = [i for i, line in enumerate(lines) if line == 'ABSD BOOT OK']
    output_begin = [i for i, line in enumerate(lines)
                    if line == 'EXTERNAL OUTPUT BEGIN encoding=hex']
    output_end = [i for i, line in enumerate(lines)
                  if line.startswith('EXTERNAL OUTPUT END bytes=')]
    quiescent = [i for i, line in enumerate(lines)
                 if line == 'SMP QUEUE QUIESCENT registered=0 queued=0 running=0']
    census_lines = [i for i, line in enumerate(lines)
                    if line.startswith('EXTERNAL status=')]
    need(len(workload) == len(boots) == len(output_begin) == len(output_end) == 1,
         'external output/workload/boot boundary count')
    need(len(quiescent) == 1, 'queue quiescence receipt missing/duplicate')
    need(len([line for line in lines if line.startswith('SPAWN OK ')]) == len(spawns),
         'spawn record accounting')
    need(len(census_lines) == 1
         and output_end[0] < quiescent[0] < pressure[0][0]
         < min(index for index, _, _ in timers)
         and max(index for index, _, _ in timers) < min(index for index, _, _ in cpu_rows)
         and max(index for index, _, _ in cpu_rows) < summary_index < census_lines[0]
         < workload[0],
         'quiescence/pressure/timer/terminal summary chronology')
    need(output_begin[0] < output_end[0] < quiescent[0] < census_lines[0]
         < workload[0] < boots[0],
         'external output/workload/boot ordering')
    need(max([summary_index, reserve_index, trap_index, quiescent[0], census_lines[0],
              *(index for index, _, _ in cpu_rows), *(index for index, _, _ in actors),
              *(index for index, _, _ in timers), output_end[0], workload[0]]) < boots[0],
         'boot completed before native/pressure terminal evidence')
    need(not any(re.search(r'ABSD PANIC:|KERNEL FAULT|FAILED', line) for line in lines),
         'failure record present')


def require_reject(name, lines, mutate, cpus, app_cpu):
    changed = mutate(lines[:])
    need(changed != lines, f'negative receipt fixture did not change: {name}')
    try:
        check_lines(changed, cpus, app_cpu)
    except (AssertionError, KeyError, ValueError, StopIteration):
        return
    raise AssertionError(f'accepted multicore-pressure negative receipt control: {name}')


def negatives(lines, cpus, app_cpu):
    def actor_rows(rows):
        return [i for i, line in enumerate(rows)
                if line.startswith('SMP APP PRESSURE ACTOR ')]

    def duplicate_actor(rows):
        i = actor_rows(rows)[0]
        rows.insert(i + 1, rows[i])
        return rows

    def missing_actor(rows):
        rows.pop(actor_rows(rows)[0])
        return rows

    def wrong_actor_cpu(rows):
        i = actor_rows(rows)[0]
        f = kv(rows[i])
        cpu = 0 if int(f['cpu']) != 0 else 1
        rows[i] = re.sub(r'cpu=\d+', f'cpu={cpu}', rows[i], count=1)
        return rows

    def wrong_actor_role(rows):
        i = actor_rows(rows)[0]
        rows[i] = re.sub(r'role=\d+', 'role=999', rows[i], count=1)
        return rows

    def reused_actor_pid_different_generation(rows):
        indices = actor_rows(rows)
        a, b = kv(rows[indices[0]]), kv(rows[indices[1]])
        rows[indices[1]] = re.sub(r'pid=\d+', f'pid={a["pid"]}', rows[indices[1]], count=1)
        return rows

    def reused_generation_different_pid(rows):
        indices = actor_rows(rows)
        a = kv(rows[indices[0]])
        rows[indices[1]] = re.sub(r'generation=\d+', f'generation={a["generation"]}',
                                  rows[indices[1]], count=1)
        return rows

    def valid_role_wrong_ap(rows):
        first = next(i for i in actor_rows(rows) if kv(rows[i])['cpu'] == '1')
        second = next(i for i in actor_rows(rows) if kv(rows[i])['cpu'] == '2')
        cpu_first, cpu_second = kv(rows[first])['cpu'], kv(rows[second])['cpu']
        rows[first] = re.sub(r'cpu=\d+', f'cpu={cpu_second}', rows[first], count=1)
        rows[second] = re.sub(r'cpu=\d+', f'cpu={cpu_first}', rows[second], count=1)
        return rows

    def missing_cpu_summary(rows):
        i = next(i for i, line in enumerate(rows)
                 if line.startswith('SMP APP PRESSURE CPU ')
                 and kv(line)['cpu'] == str(cpus - 1))
        rows.pop(i)
        return rows

    def actor_after_cpu_summary(rows):
        actor_i = actor_rows(rows)[0]
        actor = rows.pop(actor_i)
        cpu = kv(actor)['cpu']
        summary_i = next(i for i, line in enumerate(rows)
                         if line.startswith('SMP APP PRESSURE CPU ')
                         and kv(line)['cpu'] == cpu)
        rows.insert(summary_i + 1, actor)
        return rows

    def no_app_timer(rows):
        i = next(i for i, line in enumerate(rows) if line.startswith('SMP APP SUMMARY '))
        rows[i] = re.sub(r'timer-irqs=\d+', 'timer-irqs=0', rows[i], count=1)
        return rows

    def no_native_lifetime_pressure(rows):
        i = next(i for i, line in enumerate(rows)
                 if line.startswith('SMP APP PRESSURE CPU ') and int(kv(line)['cpu']) > 0)
        rows[i] = re.sub(r'app-calls=\d+', 'app-calls=0', rows[i], count=1)
        return rows

    def wrong_app_cpu(rows):
        i = next(i for i, line in enumerate(rows) if line.startswith('SMP APP TRAP '))
        cpu = 0 if app_cpu != 0 else 1
        rows[i] = re.sub(r'cpu=\d+', f'cpu={cpu}', rows[i], count=1)
        return rows

    def wrong_app_pid(rows):
        i = next(i for i, line in enumerate(rows) if line.startswith('SMP APP SUMMARY '))
        f = kv(rows[i])
        rows[i] = re.sub(r'pid=\d+', f'pid={int(f["pid"]) + 1}', rows[i], count=1)
        return rows

    def wrong_external_census(rows):
        i = next(i for i, line in enumerate(rows) if line.startswith('EXTERNAL status='))
        rows[i] = rows[i].replace('processes=0', 'processes=1', 1)
        return rows

    def reservation_after_app_trap(rows):
        reserve_i = next(i for i, line in enumerate(rows)
                         if line.startswith('SMP APP PRESSURE RESERVE '))
        reserve = rows.pop(reserve_i)
        app_i = next(i for i, line in enumerate(rows) if line.startswith('SMP APP TRAP '))
        rows.insert(app_i + 1, reserve)
        return rows

    def summary_before_app_trap(rows):
        summary_i = next(i for i, line in enumerate(rows) if line.startswith('SMP APP SUMMARY '))
        summary = rows.pop(summary_i)
        app_i = next(i for i, line in enumerate(rows) if line.startswith('SMP APP TRAP '))
        rows.insert(app_i, summary)
        return rows

    def boot_before_pressure_completion(rows):
        boot_i = next(i for i, line in enumerate(rows) if line == 'ABSD BOOT OK')
        boot = rows.pop(boot_i)
        cpu_i = next(i for i, line in enumerate(rows)
                     if line.startswith('SMP APP PRESSURE CPU '))
        rows.insert(cpu_i, boot)
        return rows

    def missing_ap_timer_summary(rows):
        i = next(i for i, line in enumerate(rows)
                 if line.startswith('SMP TIMER SUMMARY cpu='))
        rows.pop(i)
        return rows

    def timer_summary_before_app(rows):
        i = next(i for i, line in enumerate(rows)
                 if line.startswith('SMP TIMER SUMMARY cpu='))
        timer = rows.pop(i)
        app_i = next(i for i, line in enumerate(rows) if line.startswith('SMP APP TRAP '))
        rows.insert(app_i, timer)
        return rows

    def missing_quiescence(rows):
        rows.pop(next(i for i, line in enumerate(rows)
                      if line == 'SMP QUEUE QUIESCENT registered=0 queued=0 running=0'))
        return rows

    def native_pid_is_pressure_actor(rows):
        app_i = next(i for i, line in enumerate(rows) if line.startswith('SMP APP TRAP '))
        actor_pid = kv(next(line for line in rows
                            if line.startswith('SMP APP PRESSURE ACTOR ')))['pid']
        rows[app_i] = re.sub(r'pid=\d+', f'pid={actor_pid}', rows[app_i], count=1)
        return rows

    def actor_spawn_has_wrong_parent(rows):
        pid = kv(rows[actor_rows(rows)[0]])['pid']
        i = next(i for i, line in enumerate(rows)
                 if line.startswith(f'SPAWN OK pid={pid} '))
        rows[i] = rows[i].replace('parent=0', 'parent=1', 1)
        return rows

    def actor_exit_missing(rows):
        pid = kv(rows[actor_rows(rows)[0]])['pid']
        rows.pop(next(i for i, line in enumerate(rows)
                      if line.startswith(f'USER EXIT pid={pid} ')))
        return rows

    def native_spawn_wrong_program(rows):
        pid = kv(next(line for line in rows if line.startswith('SMP APP TRAP ')))['pid']
        i = next(i for i, line in enumerate(rows)
                 if line.startswith(f'SPAWN OK pid={pid} '))
        rows[i] = rows[i].replace('program=external-workload', 'program=smp-user', 1)
        return rows

    def pressure_delta_exceeds_total(rows):
        i = next(i for i, line in enumerate(rows)
                 if line.startswith('SMP APP PRESSURE CPU '))
        rows[i] = re.sub(r'app-calls=\d+', f'app-calls={int(kv(rows[i])["calls"]) + 1}',
                         rows[i], count=1)
        return rows

    def user_irqs_exceed_total_irqs(rows):
        i = next(i for i, line in enumerate(rows)
                 if line.startswith('SMP TIMER SUMMARY cpu='))
        total = int(kv(rows[i])['irqs'])
        rows[i] = re.sub(r'user-irqs=\d+', f'user-irqs={total + 1}', rows[i], count=1)
        return rows

    def missing_timer_start(rows):
        rows.pop(next(i for i, line in enumerate(rows)
                      if line.startswith('SMP TIMER START ')))
        return rows

    def invalid_timer_calibration(rows):
        i = next(i for i, line in enumerate(rows)
                 if line.startswith('SMP TIMER START '))
        initial = int(kv(rows[i])['initial'])
        rows[i] = re.sub(r'initial=\d+', f'initial={initial + 1}', rows[i], count=1)
        return rows

    def mutate_timer_start(rows, field, value):
        i = next(i for i, line in enumerate(rows)
                 if line.startswith('SMP TIMER START '))
        rows[i] = re.sub(rf'{re.escape(field)}=[^\s]+',
                         f'{field}={value}', rows[i], count=1)
        return rows

    def excessive_tsc_jitter(rows):
        f = kv(next(line for line in rows if line.startswith('SMP TIMER START ')))
        return mutate_timer_start(rows, 'tsc-a-after',
                                  int(f['tsc-a-before']) + int(f['max-jitter']) + 1)

    def backward_tsc_sample(rows):
        f = kv(next(line for line in rows if line.startswith('SMP TIMER START ')))
        return mutate_timer_start(rows, 'tsc-a-after', int(f['tsc-a-before']) - 1)

    def undersized_tsc_sample(rows):
        f = kv(next(line for line in rows if line.startswith('SMP TIMER START ')))
        return mutate_timer_start(rows, 'tsc-b-before',
                                  int(f['tsc-a-after']) + int(f['sample-tsc']) - 1)

    def wrapped_tsc_sample(rows):
        rows = mutate_timer_start(rows, 'tsc-a-before', 0xfffffffffffffff0)
        return mutate_timer_start(rows, 'tsc-a-after', 3)

    def overflowing_apic_sample(rows):
        return mutate_timer_start(rows, 'count-a', 0x100000000)

    def calibration_span_reaches_deadline(rows):
        rows = mutate_timer_start(rows, 'tsc-a-before', 100)
        rows = mutate_timer_start(rows, 'tsc-a-after', 100)
        rows = mutate_timer_start(rows, 'tsc-b-before', 100 + (1 << 34))
        rows = mutate_timer_start(rows, 'tsc-b-after', 100 + (1 << 34))
        rows = mutate_timer_start(rows, 'count-a', 100000)
        rows = mutate_timer_start(rows, 'count-b', 98976)
        return mutate_timer_start(rows, 'initial', 1)

    def wrong_timer_reference(rows):
        return mutate_timer_start(rows, 'reference', 'CPU0')

    def wrong_timer_quantum(rows):
        return mutate_timer_start(rows, 'quantum-tsc', 16777215)

    def wrong_config_reference(rows):
        i = next(i for i, line in enumerate(rows)
                 if line.startswith('SMP APP PRESSURE CONFIG '))
        rows[i] = rows[i].replace('reference=ap-local-tsc', 'reference=CPU0', 1)
        return rows

    def wrong_config_quantum(rows):
        i = next(i for i, line in enumerate(rows)
                 if line.startswith('SMP APP PRESSURE CONFIG '))
        rows[i] = rows[i].replace('quantum-tsc=16777216', 'quantum-tsc=16777215', 1)
        return rows

    def actor_exit_before_first_trap(rows):
        actor = kv(rows[actor_rows(rows)[0]])
        exit_i = next(i for i, line in enumerate(rows)
                      if line.startswith(f'USER EXIT pid={actor["pid"]} '))
        exit_line = rows.pop(exit_i)
        trap_i = next(i for i, line in enumerate(rows)
                      if line.startswith('SMP APP PRESSURE ACTOR ')
                      and kv(line)['pid'] == actor['pid'])
        rows.insert(trap_i, exit_line)
        return rows

    def actor_spawn_after_first_trap(rows):
        actor = kv(rows[actor_rows(rows)[0]])
        spawn_i = next(i for i, line in enumerate(rows)
                       if line.startswith(f'SPAWN OK pid={actor["pid"]} '))
        spawn_line = rows.pop(spawn_i)
        trap_i = next(i for i, line in enumerate(rows)
                      if line.startswith('SMP APP PRESSURE ACTOR ')
                      and kv(line)['pid'] == actor['pid'])
        rows.insert(trap_i + 1, spawn_line)
        return rows

    def native_spawn_after_first_trap(rows):
        trap = kv(next(line for line in rows if line.startswith('SMP APP TRAP ')))
        spawn_i = next(i for i, line in enumerate(rows)
                       if line.startswith(f'SPAWN OK pid={trap["pid"]} '))
        spawn_line = rows.pop(spawn_i)
        trap_i = next(i for i, line in enumerate(rows)
                      if line.startswith('SMP APP TRAP '))
        rows.insert(trap_i + 1, spawn_line)
        return rows

    def native_exit_before_first_trap(rows):
        trap = kv(next(line for line in rows if line.startswith('SMP APP TRAP ')))
        exit_i = next(i for i, line in enumerate(rows)
                      if line.startswith(f'USER EXIT pid={trap["pid"]} '))
        exit_line = rows.pop(exit_i)
        trap_i = next(i for i, line in enumerate(rows)
                      if line.startswith('SMP APP TRAP '))
        rows.insert(trap_i, exit_line)
        return rows

    def actor_exit_after_own_cpu_summary(rows):
        actor = kv(rows[actor_rows(rows)[0]])
        cpu = actor['cpu']
        exit_i = next(i for i, line in enumerate(rows)
                      if line.startswith(f'USER EXIT pid={actor["pid"]} '))
        exit_line = rows.pop(exit_i)
        own_summary_i = next(i for i, line in enumerate(rows)
                             if line.startswith('SMP APP PRESSURE CPU ')
                             and kv(line)['cpu'] == cpu)
        rows.insert(own_summary_i + 1, exit_line)
        return rows

    def actor_proof_rows(rows, kind):
        prefix = f'SMP APP PRESSURE {kind} '
        return [i for i, line in enumerate(rows) if line.startswith(prefix)]

    def first_odd_actor(rows):
        return next(line for line in rows
                    if line.startswith('SMP APP PRESSURE ACTOR ')
                    and int(kv(line)['role']) % 2 == 1)

    def missing_actor_preempt(rows):
        rows.pop(actor_proof_rows(rows, 'PREEMPT')[0])
        return rows

    def duplicate_actor_preempt(rows):
        i = actor_proof_rows(rows, 'PREEMPT')[0]
        rows.insert(i + 1, rows[i])
        return rows

    def missing_actor_resume(rows):
        rows.pop(actor_proof_rows(rows, 'RESUME')[0])
        return rows

    def duplicate_actor_resume(rows):
        i = actor_proof_rows(rows, 'RESUME')[0]
        rows.insert(i + 1, rows[i])
        return rows

    def wrong_actor_preempt_cpu(rows):
        i = actor_proof_rows(rows, 'PREEMPT')[0]
        rows[i] = re.sub(r'cpu=\d+', 'cpu=0', rows[i], count=1)
        return rows

    def wrong_actor_resume_cpu(rows):
        i = actor_proof_rows(rows, 'RESUME')[0]
        rows[i] = re.sub(r'cpu=\d+', 'cpu=0', rows[i], count=1)
        return rows

    def crosswired_actor_preempt_pid(rows):
        actor = kv(first_odd_actor(rows))
        i = next(i for i, row in enumerate(rows)
                 if row.startswith('SMP APP PRESSURE PREEMPT ')
                 and kv(row)['role'] == actor['role'])
        other = next(kv(row) for row in rows
                     if row.startswith('SMP APP PRESSURE ACTOR ')
                     and kv(row)['cpu'] == actor['cpu']
                     and kv(row)['role'] != actor['role'])
        rows[i] = re.sub(r'pid=\d+', f'pid={other["pid"]}', rows[i], count=1)
        return rows

    def crosswired_actor_resume_pid(rows):
        actor = kv(first_odd_actor(rows))
        i = next(i for i, row in enumerate(rows)
                 if row.startswith('SMP APP PRESSURE RESUME ')
                 and kv(row)['role'] == actor['role'])
        other = next(kv(row) for row in rows
                     if row.startswith('SMP APP PRESSURE ACTOR ')
                     and kv(row)['cpu'] == actor['cpu']
                     and kv(row)['role'] != actor['role'])
        rows[i] = re.sub(r'pid=\d+', f'pid={other["pid"]}', rows[i], count=1)
        return rows

    def crosswired_actor_preempt_generation(rows):
        actor = kv(first_odd_actor(rows))
        i = next(i for i, row in enumerate(rows)
                 if row.startswith('SMP APP PRESSURE PREEMPT ')
                 and kv(row)['role'] == actor['role'])
        other = next(kv(row) for row in rows
                     if row.startswith('SMP APP PRESSURE ACTOR ')
                     and kv(row)['cpu'] == actor['cpu']
                     and kv(row)['role'] != actor['role'])
        rows[i] = re.sub(r'generation=\d+', f'generation={other["generation"]}',
                         rows[i], count=1)
        return rows

    def invalid_saved_live_witness(rows):
        i = actor_proof_rows(rows, 'PREEMPT')[0]
        rows[i] = re.sub(r'live=1', 'live=0', rows[i], count=1)
        return rows

    def calibration_rows(rows):
        return [i for i, line in enumerate(rows)
                if line.startswith('SMP APP PRESSURE CALIBRATED ')]

    def missing_calibration_fence(rows):
        rows.pop(calibration_rows(rows)[0])
        return rows

    def duplicate_calibration_fence(rows):
        i = calibration_rows(rows)[0]
        rows.insert(i + 1, rows[i])
        return rows

    def missing_ready_mask(rows):
        i = calibration_rows(rows)[0]
        rows[i] = re.sub(r' ready-mask=\d+', '', rows[i], count=1)
        return rows

    def wrong_ready_mask(rows):
        i = calibration_rows(rows)[0]
        mask = int(kv(rows[i])['ready-mask'])
        rows[i] = re.sub(r'ready-mask=\d+', f'ready-mask={mask ^ 1}', rows[i], count=1)
        return rows

    def calibration_has_owner(rows):
        i = calibration_rows(rows)[0]
        rows[i] = re.sub(r'owners=\d+', 'owners=1', rows[i], count=1)
        return rows

    def calibration_has_actor_calls(rows):
        i = calibration_rows(rows)[0]
        rows[i] = re.sub(r'actor-calls=\d+', 'actor-calls=1', rows[i], count=1)
        return rows

    def calibration_wrong_phase(rows):
        i = calibration_rows(rows)[0]
        rows[i] = rows[i].replace('phase=before-user', 'phase=after-user', 1)
        return rows

    def calibration_after_actor(rows):
        i = calibration_rows(rows)[0]
        line = rows.pop(i)
        actor_i = next(i for i, row in enumerate(rows)
                       if row.startswith('SMP APP PRESSURE ACTOR '))
        rows.insert(actor_i + 1, line)
        return rows

    def calibration_after_timer_start(rows):
        i = calibration_rows(rows)[0]
        line = rows.pop(i)
        timer_i = next(i for i, row in enumerate(rows)
                       if row.startswith('SMP TIMER START '))
        rows.insert(timer_i + 1, line)
        return rows

    def calibration_after_user_trap(rows):
        i = calibration_rows(rows)[0]
        line = rows.pop(i)
        user_trap_i = next(i for i, row in enumerate(rows)
                           if row.startswith('SMP USER TRAP '))
        rows.insert(user_trap_i + 1, line)
        return rows

    def missing_bsp_user_trap(rows):
        i = next(i for i, row in enumerate(rows)
                 if row.startswith('SMP USER TRAP ') and kv(row)['cpu'] == '0')
        rows.pop(i)
        return rows

    def wrong_ap_user_trap_pid(rows):
        traps = [i for i, row in enumerate(rows)
                 if row.startswith('SMP USER TRAP ') and kv(row)['cpu'] != '0']
        i = traps[0]
        rows[i] = re.sub(r'pid=\d+', 'pid=99999', rows[i], count=1)
        return rows

    def ap_user_trap_uses_other_ap_actor(rows):
        traps = [(i, kv(row)) for i, row in enumerate(rows)
                 if row.startswith('SMP USER TRAP ') and kv(row)['cpu'] != '0']
        actors_on_other_cpu = [(kv(row)['cpu'], kv(row)['pid']) for row in rows
                               if row.startswith('SMP APP PRESSURE ACTOR ')]
        i, trap = traps[0]
        other = next(pid for cpu, pid in actors_on_other_cpu if cpu != trap['cpu'])
        rows[i] = re.sub(r'pid=\d+', f'pid={other}', rows[i], count=1)
        return rows

    def wrong_actor_preempt_role(rows):
        i = actor_proof_rows(rows, 'PREEMPT')[0]
        role = int(kv(rows[i])['role'])
        rows[i] = re.sub(r'role=\d+', f'role={role - 1}', rows[i], count=1)
        return rows

    def resume_precedes_preempt(rows):
        resume_i = actor_proof_rows(rows, 'RESUME')[0]
        resume = rows.pop(resume_i)
        preempt_i = actor_proof_rows(rows, 'PREEMPT')[0]
        rows.insert(preempt_i, resume)
        return rows

    def actor_exit_precedes_preempt(rows):
        actor = kv(first_odd_actor(rows))
        exit_i = next(i for i, row in enumerate(rows)
                      if row.startswith(f'USER EXIT pid={actor["pid"]} '))
        exit_record = rows.pop(exit_i)
        preempt_i = next(i for i, row in enumerate(rows)
                         if row.startswith('SMP APP PRESSURE PREEMPT ')
                         and kv(row)['role'] == actor['role'])
        rows.insert(preempt_i, exit_record)
        return rows

    def duplicate_actor_spawn(rows):
        pid = kv(rows[actor_rows(rows)[0]])['pid']
        i = next(i for i, line in enumerate(rows)
                 if line.startswith(f'SPAWN OK pid={pid} '))
        rows.insert(i + 1, rows[i])
        return rows

    def duplicate_native_spawn(rows):
        pid = kv(next(line for line in rows if line.startswith('SMP APP TRAP ')))['pid']
        i = next(i for i, line in enumerate(rows)
                 if line.startswith(f'SPAWN OK pid={pid} '))
        rows.insert(i + 1, rows[i])
        return rows

    def missing_exhaustion_boundary(rows):
        rows.remove('SPAWN EXHAUSTION OK')
        return rows

    def bootstrap_init_before_exhaustion(rows):
        init_i = next(i for i, line in enumerate(rows)
                      if line == 'SPAWN OK pid=1 parent=0 program=init'
                      and i > rows.index('SPAWN EXHAUSTION OK'))
        init_line = rows.pop(init_i)
        exhaustion_i = rows.index('SPAWN EXHAUSTION OK')
        rows.insert(exhaustion_i, init_line)
        return rows

    def actor_spawn_before_exhaustion(rows):
        actor = kv(rows[actor_rows(rows)[0]])
        spawn_i = next(i for i, line in enumerate(rows)
                       if line.startswith(f'SPAWN OK pid={actor["pid"]} '))
        spawn_line = rows.pop(spawn_i)
        rows.insert(rows.index('SPAWN EXHAUSTION OK'), spawn_line)
        return rows

    def native_spawn_before_reservation(rows):
        trap = kv(next(line for line in rows if line.startswith('SMP APP TRAP ')))
        spawn_i = next(i for i, line in enumerate(rows)
                       if line.startswith(f'SPAWN OK pid={trap["pid"]} '))
        spawn_line = rows.pop(spawn_i)
        reserve_i = next(i for i, line in enumerate(rows)
                         if line.startswith('SMP APP PRESSURE RESERVE '))
        rows.insert(reserve_i, spawn_line)
        return rows

    controls = {
        'duplicate actor receipt': duplicate_actor,
        'missing actor receipt': missing_actor,
        'actor assigned to wrong CPU': wrong_actor_cpu,
        'actor role outside reservation': wrong_actor_role,
        'actor PID reused under a different generation': reused_actor_pid_different_generation,
        'generation reused by a different actor PID': reused_generation_different_pid,
        'missing CPU summary': missing_cpu_summary,
        'actor first trap follows per-AP completion summary': actor_after_cpu_summary,
        'native application timer absent': no_app_timer,
        'pressure absent during native application lifetime': no_native_lifetime_pressure,
        'missing AP timer summary': missing_ap_timer_summary,
        'AP timer summary precedes native entry': timer_summary_before_app,
        'native application on wrong CPU': wrong_app_cpu,
        'native summary PID differs from trap': wrong_app_pid,
        'external resource census changed': wrong_external_census,
        'reservation follows native entry': reservation_after_app_trap,
        'native summary precedes first trap': summary_before_app_trap,
        'boot precedes pressure completion': boot_before_pressure_completion,
        'missing queue quiescence receipt': missing_quiescence,
        'native PID overlaps pressure actor': native_pid_is_pressure_actor,
        'actor lacks kernel-parent smp-user spawn receipt': actor_spawn_has_wrong_parent,
        'actor successful exit receipt missing': actor_exit_missing,
        'native spawn program identity changed': native_spawn_wrong_program,
        'native-lifetime pressure delta exceeds total': pressure_delta_exceeds_total,
        'user timer IRQ count exceeds total AP IRQs': user_irqs_exceed_total_irqs,
        'AP timer calibration receipt missing': missing_timer_start,
        'AP timer calibration arithmetic changed': invalid_timer_calibration,
        'AP timer TSC jitter exceeds bound': excessive_tsc_jitter,
        'AP timer TSC sample moves backward': backward_tsc_sample,
        'AP timer TSC sample spacing is too small': undersized_tsc_sample,
        'AP timer TSC sample wraps': wrapped_tsc_sample,
        'AP timer counter sample exceeds 32 bits': overflowing_apic_sample,
        'AP timer calibration span reaches timeout bound': calibration_span_reaches_deadline,
        'AP timer calibration uses wrong reference': wrong_timer_reference,
        'AP timer calibration uses wrong quantum': wrong_timer_quantum,
        'pressure configuration uses wrong TSC reference': wrong_config_reference,
        'pressure configuration uses wrong TSC quantum': wrong_config_quantum,
        'actor exit precedes its first trap': actor_exit_before_first_trap,
        'actor publication follows its first trap': actor_spawn_after_first_trap,
        'native publication follows its first trap': native_spawn_after_first_trap,
        'native exit precedes its first trap': native_exit_before_first_trap,
        'actor PID has duplicate actual spawn receipt': duplicate_actor_spawn,
        'native PID has duplicate actual spawn receipt': duplicate_native_spawn,
        'spawn exhaustion boundary missing': missing_exhaustion_boundary,
        'reinitialized PID-1 init spawn precedes exhaustion boundary': bootstrap_init_before_exhaustion,
        'actor published before spawn exhaustion boundary': actor_spawn_before_exhaustion,
        'native published before pressure census': native_spawn_before_reservation,
        'odd actor timer-preemption witness missing': missing_actor_preempt,
        'odd actor timer-preemption witness duplicated': duplicate_actor_preempt,
        'odd actor resume witness missing': missing_actor_resume,
        'odd actor resume witness duplicated': duplicate_actor_resume,
        'actor timer witness assigned to wrong CPU': wrong_actor_preempt_cpu,
        'actor resume witness assigned to wrong CPU': wrong_actor_resume_cpu,
        'actor timer witness PID crosswired': crosswired_actor_preempt_pid,
        'actor resume witness PID crosswired': crosswired_actor_resume_pid,
        'actor timer witness generation crosswired': crosswired_actor_preempt_generation,
        'actor timer witness lacks live saved-frame marker': invalid_saved_live_witness,
        'AP calibration readiness fence missing': missing_calibration_fence,
        'AP calibration readiness fence duplicated': duplicate_calibration_fence,
        'AP ready mask missing': missing_ready_mask,
        'AP ready mask incomplete': wrong_ready_mask,
        'AP calibration observed process owners': calibration_has_owner,
        'AP calibration observed actor syscalls': calibration_has_actor_calls,
        'AP calibration phase is not before-user': calibration_wrong_phase,
        'AP calibration fence follows first actor': calibration_after_actor,
        'AP calibration fence follows timer start': calibration_after_timer_start,
        'AP calibration fence follows first user entry': calibration_after_user_trap,
        'BSP first user-entry witness missing': missing_bsp_user_trap,
        'AP first user-entry PID is not a pressure actor': wrong_ap_user_trap_pid,
        'actor timer witness role changed': wrong_actor_preempt_role,
        'actor resume precedes saved timer frame': resume_precedes_preempt,
        'actor exit precedes saved timer frame': actor_exit_precedes_preempt,
    }
    if cpus >= 4:
        controls['valid actor role assigned to another AP'] = valid_role_wrong_ap
        controls['actor exit follows its own AP terminal row'] = actor_exit_after_own_cpu_summary
        controls['AP first user-entry witness uses another AP actor'] = ap_user_trap_uses_other_ap_actor
    for name, mutate in controls.items():
        require_reject(name, lines, mutate, cpus, app_cpu)
    return len(controls)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('serial', type=Path)
    parser.add_argument('--cpus', type=int, choices=(2, 4, 6), required=True)
    parser.add_argument('--app-cpu', type=int, choices=(1, 2, 3, 4, 5), required=True)
    parser.add_argument('--placement', type=Path,
                        help='optional QMP runner vCPU placement receipt')
    args = parser.parse_args()
    lines = args.serial.read_text(errors='replace').splitlines()
    check_lines(lines, args.cpus, args.app_cpu)
    if args.placement is not None:
        check_placement(args.placement, args.cpus)
    count = negatives(lines, args.cpus, args.app_cpu)
    print(f'SMP APP PRESSURE oracle OK cpus={args.cpus} app-cpu={args.app_cpu} actors={2*(args.cpus-1)}')
    print(f'SMP APP PRESSURE oracle rejected {count} deterministic receipt controls')


if __name__ == '__main__':
    main()
