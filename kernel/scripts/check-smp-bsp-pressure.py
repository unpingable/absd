#!/usr/bin/env python3
"""Closed receipt oracle for BSP init work under AP userspace pressure."""

import argparse
import importlib.util
import re
import sys
from pathlib import Path


sys.dont_write_bytecode = True
_app_path = Path(__file__).with_name('check-smp-app-pressure.py')
_spec = importlib.util.spec_from_file_location('smp_app_pressure_oracle', _app_path)
_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_app)
need = _app.need
kv = _app.kv
number = _app.number
selected = _app.selected
check_placement = _app.check_placement

MAX_OUTPUT_BYTES = 1 << 20
U64_MAX = (1 << 64) - 1


def check_timer_calibration(lines, cpus, calibrated_index):
    starts = selected(lines, 'SMP TIMER START ')
    need(len(starts) == cpus - 1, 'AP timer calibration coverage missing/duplicate')
    timer_cpus = set()
    for index, _, f in starts:
        need(set(f) == {'cpu', 'vector', 'divide', 'initial',
                        'tsc-a-before', 'tsc-a-after', 'count-a',
                        'tsc-b-before', 'tsc-b-after', 'count-b',
                        'quantum-tsc', 'sample-tsc', 'max-jitter', 'reference',
                        'global-time', 'rt-time'},
             'AP timer calibration fields mismatch')
        cpu = number(f.get('cpu'), 'calibration CPU')
        need(1 <= cpu < cpus and cpu not in timer_cpus,
             'AP timer calibration CPU missing/duplicated/out of range')
        timer_cpus.add(cpu)
        need(calibrated_index < index,
             'AP timer start precedes the calibration readiness fence')
        a_before = number(f['tsc-a-before'], 'calibration TSC A before')
        a_after = number(f['tsc-a-after'], 'calibration TSC A after')
        b_before = number(f['tsc-b-before'], 'calibration TSC B before')
        b_after = number(f['tsc-b-after'], 'calibration TSC B after')
        quantum = number(f['quantum-tsc'], 'calibrated quantum')
        sample = number(f['sample-tsc'], 'calibration sample span')
        jitter = number(f['max-jitter'], 'calibration maximum jitter')
        need(0 <= a_before <= a_after < b_before <= b_after <= U64_MAX
             and a_after - a_before <= jitter
             and b_after - b_before <= jitter
             and b_before - a_after >= sample
             and b_after - a_before < (1 << 34),
             'AP-local TSC sampling order, jitter, or readiness deadline mismatch')
        need(quantum == 16777216 and sample == 33554432
             and jitter == 262144 and f['reference'] == 'ap-local-tsc',
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
    need(timer_cpus == set(range(1, cpus)), 'AP timer calibration CPU coverage incomplete')


def check_output_frame(lines):
    begins = [i for i, line in enumerate(lines)
              if line == 'EXTERNAL OUTPUT BEGIN encoding=hex']
    end_lines = [(i, line) for i, line in enumerate(lines)
                 if line.startswith('EXTERNAL OUTPUT END ')]
    ends = [(i, re.fullmatch(r'EXTERNAL OUTPUT END bytes=(\d+) digest=([0-9a-f]{8})', line))
            for i, line in end_lines]
    need(all(match is not None for _, match in ends),
         'malformed external output end record')
    need(len(begins) == len(ends) == 1 and begins[0] < ends[0][0],
         'external output frame boundary missing/duplicate/misordered')
    offset = 0
    digest = 0x811c9dc5
    chunk_re = re.compile(r'EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)')
    for line in lines[begins[0] + 1:ends[0][0]]:
        match = chunk_re.fullmatch(line)
        if match is None:
            continue
        data_hex = match.group(2)
        need(len(data_hex) % 2 == 0, 'external output chunk has odd hex length')
        data = bytes.fromhex(data_hex)
        need(int(match.group(1), 16) == offset, 'external output chunks are not contiguous')
        offset += len(data)
        need(offset <= MAX_OUTPUT_BYTES, 'external output exceeds 1 MiB receipt bound')
        for byte in data:
            digest = ((digest ^ byte) * 0x01000193) & 0xffffffff
    end_fields = ends[0][1]
    need(int(end_fields.group(1)) == offset and int(end_fields.group(2), 16) == digest,
         'external output length/digest does not match its bounded chunks')
    return begins[0], ends[0][0], offset


def check_lines(lines, cpus, mode, expected_peak=None):
    need(cpus in (2, 4, 6), 'unsupported guest CPU count')
    need(mode in ('external', 'durable', 'suite'), 'unsupported BSP workload mode')
    reserved = 2 * (cpus - 1)

    config = selected(lines, 'SMP BSP PRESSURE CONFIG ')
    need(len(config) == 1, 'BSP pressure configuration missing/duplicate')
    config_index, _, cf = config[0]
    need(cf == {'cpus': str(cpus), 'reserved': str(reserved), 'app-cpu': '0',
                'quantum-tsc': '16777216', 'reference': 'ap-local-tsc',
                'observer': 'init'}, f'BSP pressure configuration mismatch: {cf}')

    calibrated = selected(lines, 'SMP APP PRESSURE CALIBRATED ')
    need(len(calibrated) == 1, 'AP calibration readiness fence missing/duplicate')
    calibrated_index, _, kf = calibrated[0]
    need(kf == {'cpus': str(cpus), 'ready-mask': str((1 << cpus) - 2),
                'owners': '0', 'actor-calls': '0', 'phase': 'before-user'},
         f'AP calibration readiness fence mismatch: {kf}')
    need(config_index < calibrated_index, 'BSP configuration follows calibration release')

    actors = selected(lines, 'SMP APP PRESSURE ACTOR ')
    need(len(actors) == reserved, 'pressure actor census count')
    actor_keys, actor_pids, actor_gens, roles = set(), set(), set(), set()
    actors_by_pid, actor_pid_by_role = {}, {}
    actor_counts = {cpu: 0 for cpu in range(1, cpus)}
    for index, _, f in actors:
        need(set(f) == {'cpu', 'pid', 'generation', 'role', 'cpl', 'cr3'}
             and f.get('cpl') == '3' and f.get('cr3') == 'owned',
             'invalid AP pressure actor ownership witness')
        cpu = number(f.get('cpu'), 'actor CPU')
        pid = number(f.get('pid'), 'actor PID')
        gen = number(f.get('generation'), 'actor generation')
        role = number(f.get('role'), 'actor role')
        need(calibrated_index < index and 1 <= cpu < cpus and pid > 1 and gen > 0
             and 200 <= role < 200 + reserved and cpu == (role - 200) // 2 + 1,
             'pressure actor CPU/role or calibration chronology mismatch')
        need((pid, gen) not in actor_keys and pid not in actor_pids
             and gen not in actor_gens and role not in roles,
             'duplicate pressure actor PID/generation/role')
        actor_keys.add((pid, gen)); actor_pids.add(pid); actor_gens.add(gen); roles.add(role)
        actors_by_pid[pid] = (index, cpu, role, gen)
        actor_pid_by_role[role] = pid
        actor_counts[cpu] += 1
    need(roles == set(range(200, 200 + reserved))
         and all(actor_counts[cpu] == 2 for cpu in range(1, cpus)),
         'AP pressure role/CPU census is incomplete')

    frame_reservations = selected(lines, 'SMP BSP FRAME RESERVATION ')
    need(len(frame_reservations) == reserved,
         'BSP per-actor frame reservation census count mismatch')
    frame_roles = set()
    for index, _, ff in frame_reservations:
        need(ff.keys() == {'role', 'pid', 'frames'} and ff.get('frames') == '33',
             'BSP per-actor frame reservation fields/bound mismatch')
        role = number(ff.get('role'), 'reserved actor role')
        pid = number(ff.get('pid'), 'reserved actor PID')
        spawn_index = next((spawn_i for spawn_i, spawn_line in enumerate(lines)
                            if spawn_line.startswith('SPAWN OK ')
                            and kv(spawn_line).get('pid') == str(pid)), None)
        need(role in actor_pid_by_role and role not in frame_roles
             and actor_pid_by_role[role] == pid
             and spawn_index is not None and index < spawn_index
             and index < calibrated_index
             and index < actors_by_pid[pid][0],
             'BSP frame reservation role/PID or publication chronology mismatch')
        frame_roles.add(role)
    need(frame_roles == roles, 'BSP frame reservation role coverage incomplete')

    preempts = selected(lines, 'SMP APP PRESSURE PREEMPT ')
    resumes = selected(lines, 'SMP APP PRESSURE RESUME ')
    odd_roles = set(range(201, 200 + reserved, 2))
    need(len(preempts) == len(resumes) == cpus - 1,
         'odd-role AP preemption/resume evidence count')
    pre_by_role, res_by_role = {}, {}
    for rows, record_map, label in ((preempts, pre_by_role, 'preemption'),
                                    (resumes, res_by_role, 'resume')):
        for index, _, f in rows:
            need(set(f) == {'cpu', 'pid', 'generation', 'role', 'saved', 'live'}
                 and f.get('saved') == f.get('live') == '1',
                 f'{label} lacks saved GPR/FPU image evidence')
            cpu, pid, gen, role = (number(f.get(k), f'{label} {k}')
                                   for k in ('cpu', 'pid', 'generation', 'role'))
            need(role in odd_roles and role not in record_map,
                 f'duplicate/non-odd actor {label} evidence')
            actor_pid = actor_pid_by_role[role]
            actor_index, actor_cpu, actor_role, actor_gen = actors_by_pid[actor_pid]
            need((cpu, pid, gen, role) == (actor_cpu, actor_pid, actor_gen, actor_role),
                 f'{label} identity does not match actor role {role}')
            record_map[role] = (index, actor_index, pid)
    need(set(pre_by_role) == set(res_by_role) == odd_roles,
         'odd-role AP preemption/resume coverage incomplete')

    spawns = selected(lines, 'SPAWN OK ')
    exhaustion = [i for i, line in enumerate(lines) if line == 'SPAWN EXHAUSTION OK']
    models = [i for i, line in enumerate(lines) if line == 'PROCESS MODEL OK']
    need(len(exhaustion) == len(models) == 1 and exhaustion[0] < models[0],
         'bootstrap exhaustion/process-model boundary missing or reordered')
    init_spawns = [(i, f) for i, _, f in spawns
                   if f == {'pid': '1', 'parent': '0', 'program': 'init'}]
    need(len(init_spawns) == 2 and init_spawns[0][0] < exhaustion[0]
         < init_spawns[1][0] < models[0],
         'PID-1 init spawn exhaustion chronology mismatch')
    spawn_by_pid = {}
    for index, _, f in spawns:
        need(set(f) == {'pid', 'parent', 'program'}, 'spawn record fields mismatch')
        pid = number(f.get('pid'), 'spawn PID')
        if pid == 1:
            need(f == {'pid': '1', 'parent': '0', 'program': 'init'},
                 'unexpected bootstrap PID-1 spawn identity')
            continue
        need(index > models[0] and pid not in spawn_by_pid,
             'duplicate spawn or child published before process model')
        spawn_by_pid[pid] = (index, f)
    for pid, (actor_index, _, role, _) in actors_by_pid.items():
        row = spawn_by_pid.get(pid)
        need(row is not None and row[1] == {'pid': str(pid), 'parent': '0',
                                           'program': 'smp-user'}
             and row[0] < actor_index,
             f'AP actor PID {pid} lacks exact kernel-parent spawn receipt')

    bsp_summaries = selected(lines, 'SMP BSP SUMMARY ')
    need(len(bsp_summaries) == 1, 'BSP init terminal summary missing/duplicate')
    bsp_summary_index, _, _ = bsp_summaries[0]

    refusal_prefix_rows = [line for line in lines if line.startswith('SMP BSP REFUSAL ')]
    need(not selected(lines, 'SMP BSP REFUSAL INJECT '),
         'refusal histogram omission-injection marker present')
    refusal_rows = selected(lines, 'SMP BSP REFUSAL pid=')
    refusal_summaries = selected(lines, 'SMP BSP REFUSAL SUMMARY ')
    need(len(refusal_summaries) == 1,
         'BSP refusal histogram summary missing/duplicate')
    need(len(refusal_prefix_rows) == len(refusal_rows) + len(refusal_summaries),
         'unrecognized BSP refusal record present')
    refusal_summary_index, _, refusal_summary = refusal_summaries[0]
    need(set(refusal_summary) == {'events', 'kinds', 'tracked'}
         and refusal_summary.get('tracked') == '1',
         'BSP refusal histogram summary fields/tracking mismatch')
    refusal_keys, refusal_total = set(), 0
    refusal_by_key = {}
    for index, _, hf in refusal_rows:
        need(set(hf) == {'pid', 'program', 'syscall', 'site', 'count'},
             'BSP refusal histogram row fields mismatch')
        pid = number(hf.get('pid'), 'refusal PID')
        program = number(hf.get('program'), 'refusal program')
        syscall = number(hf.get('syscall'), 'refusal syscall')
        site = number(hf.get('site'), 'refusal site')
        count = number(hf.get('count'), 'refusal count')
        key = (pid, program, syscall, site)
        need(pid > 0 and program >= 0 and syscall >= 0 and 0 <= site <= 7 and count > 0
             and (pid == 1 or pid in spawn_by_pid)
             and key not in refusal_keys and index > bsp_summary_index
             and index < refusal_summary_index,
             'BSP refusal histogram identity/range/declaration/uniqueness mismatch')
        refusal_keys.add(key)
        refusal_by_key[key] = (index, count)
        refusal_total += count
    need(len(refusal_rows) <= 256
         and number(refusal_summary.get('kinds'), 'refusal histogram kinds') == len(refusal_rows)
         and number(refusal_summary.get('events'), 'refusal histogram events') == refusal_total,
         'BSP refusal histogram bounded count/kinds/event sum mismatch')
    terminal_prefixes = ('FRAMES ', 'DURABLE status=', 'EXTERNAL status=')
    terminal_indices = [i for i, line in enumerate(lines)
                        if line.startswith(terminal_prefixes)]
    need(terminal_indices and bsp_summary_index < refusal_summary_index < min(terminal_indices)
         and all(index < refusal_summary_index for index, _ in refusal_by_key.values()),
         'BSP refusal histogram is outside terminal-summary chronology')
    if mode == 'suite':
        counters = selected(lines, 'COUNTERS ')
        need(len(counters) == 1
             and number(refusal_summary.get('events'), 'suite refusal event count')
             == number(counters[0][2].get('handle'), 'suite handle refusal counter')
             == 190 - 2 * reserved,
             'suite BSP refusal events differ from the exact handle-refusal census')
        ready_rows = selected(lines, 'SUPERVISOR STUCK READY ')
        need(len(ready_rows) == 1, 'supervisor STUCK readiness witness missing/duplicate')
        ready_index, _, ready = ready_rows[0]
        need(set(ready) == {'pid', 'state', 'after-rights-check'}
             and ready.get('state') == 'waiting' and ready.get('after-rights-check') == '1',
             'supervisor STUCK readiness fields/state mismatch')
        stuck_pid = number(ready.get('pid'), 'supervisor STUCK PID')
        stuck_instance_rows = [(i, f) for i, _, f in selected(lines, 'SUPERVISOR INSTANCE ')
                               if f.get('generation') == '4' and f.get('pid') == str(stuck_pid)]
        need(len(stuck_instance_rows) == 1 and stuck_instance_rows[0][0] < ready_index
             and spawn_by_pid.get(stuck_pid, (None, {}))[1].get('program') == 'supervised-worker',
             'supervisor STUCK readiness does not bind generation-4 supervisedworker instance')
        worker_starts = [(i, f) for i, _, f in selected(lines, 'WORKER START ')
                         if f.get('generation') == '4' and f.get('pid') == str(stuck_pid)]
        need(len(worker_starts) == 1 and worker_starts[0][0] < ready_index,
             'supervisor STUCK readiness precedes its generation-4 worker start')
        kills = [(i, f) for i, _, f in selected(lines, 'USER KILLED ')
                 if f.get('pid') == str(stuck_pid) and f.get('by') == '1']
        need(len(kills) == 1 and ready_index < kills[0][0],
             'supervisor STUCK readiness is missing or follows init kill')
        stuck_key = (stuck_pid, 23, 12, 0)
        need(refusal_by_key.get(stuck_key, (None, None))[1] == 1,
             'generation-4 STUCK worker lacks its mandatory single syscall-12 site-0 refusal')
    bsp_traps = selected(lines, 'SMP BSP TRAP ')
    need(len(bsp_traps) == 1, 'BSP init first-trap witness missing/duplicate')
    bsp_trap_index, bsp_trap_line, bf = bsp_traps[0]
    need(calibrated_index < bsp_trap_index,
         'BSP init first-trap witness precedes AP calibration readiness')
    need(set(bf) == {'cpu', 'slot', 'pid', 'generation', 'cpl', 'cr3', 'catalog'}
         and bf == {'cpu': '0', 'slot': '0', 'pid': '1',
                    'generation': bf.get('generation'), 'cpl': '3', 'cr3': 'owned',
                    'catalog': 'init'}
         and number(bf.get('generation'), 'BSP init generation') > 0
         and number(bf['generation'], 'BSP init generation') not in actor_gens
         and bsp_trap_line.endswith('cpl=3 cr3=owned catalog=init'),
         'BSP init first-trap identity/ownership mismatch')
    bsp_gen = number(bf['generation'], 'BSP init generation')

    reserve = selected(lines, 'SMP APP PRESSURE RESERVE ')
    need(len(reserve) == 1, 'pressure reservation census missing/duplicate')
    reserve_index, _, rf = reserve[0]
    need(rf == {'pid': '1', 'cpus': str(cpus), 'reserved': str(reserved),
                'census': str(1 + reserved)}, f'pressure reservation census mismatch: {rf}')
    need(models[0] < bsp_trap_index < reserve_index,
         'process model/BSP first trap/reservation chronology mismatch')

    user_traps = selected(lines, 'SMP USER TRAP ')
    need(len(user_traps) == cpus, 'first user-entry witness count differs from CPU count')
    trap_cpus = set()
    for index, _, f in user_traps:
        need(set(f) == {'seq', 'cpu', 'slot', 'pid', 'epoch'},
             'first user-entry witness fields mismatch')
        cpu = number(f.get('cpu'), 'first user-entry CPU')
        pid = number(f.get('pid'), 'first user-entry PID')
        number(f.get('seq'), 'first user-entry sequence')
        slot = number(f.get('slot'), 'first user-entry slot')
        epoch = number(f.get('epoch'), 'first user-entry epoch')
        need(0 <= slot < 16 and epoch > 0,
             'first user-entry slot/epoch is outside the live task range')
        need(calibrated_index < index and 0 <= cpu < cpus and cpu not in trap_cpus,
             'first user-entry CPU missing/duplicate or predates calibration')
        trap_cpus.add(cpu)
        if cpu == 0:
            need(pid == 1 and f['slot'] == '0' and index >= bsp_trap_index,
                 'BSP first user-entry is not observed init')
        else:
            need(pid in actors_by_pid and actors_by_pid[pid][1] == cpu
                 and actors_by_pid[pid][0] < index,
                 'AP first user-entry is not its published pressure actor')
    need(trap_cpus == set(range(cpus)), 'first user-entry CPU coverage incomplete')
    need(all(index > reserve_index for index, f in spawn_by_pid.values()
             if number(f['pid'], 'spawn PID') not in actor_pids),
         'non-pressure child spawn precedes the exact pressure reservation')

    check_timer_calibration(lines, cpus, calibrated_index)
    timers = selected(lines, 'SMP TIMER SUMMARY ')
    need(len(timers) == cpus - 1, 'per-AP timer summary count')
    timer_indices, timer_cpus = [], set()
    for index, _, f in timers:
        need(set(f) == {'cpu', 'irqs', 'user-irqs', 'switches0', 'switches1'},
             'AP timer summary fields mismatch')
        cpu = number(f.get('cpu'), 'timer summary CPU')
        need(1 <= cpu < cpus and cpu not in timer_cpus
             and 0 < number(f.get('user-irqs'), 'AP user timer IRQs')
             <= number(f.get('irqs'), 'AP timer IRQs')
             and number(f.get('switches1'), 'AP user switches') > 0,
             f'AP {cpu} lacks timer IRQ/preemption evidence')
        timer_cpus.add(cpu); timer_indices.append(index)
    need(timer_cpus == set(range(1, cpus)), 'AP timer summary coverage incomplete')

    cpu_rows = selected(lines, 'SMP APP PRESSURE CPU ')
    need(len(cpu_rows) == cpus - 1, 'per-AP pressure terminal summary count')
    cpu_indices, cpu_map = [], {}
    for index, _, f in cpu_rows:
        need(set(f) == {'cpu', 'actors', 'calls', 'app-calls', 'exited', 'departed'},
             'AP pressure terminal summary fields mismatch')
        cpu = number(f.get('cpu'), 'pressure terminal CPU')
        need(1 <= cpu < cpus and cpu not in cpu_map and f['actors'] == '2'
             and number(f.get('calls'), 'AP calls') > 0
             and number(f.get('app-calls'), 'AP calls during init lifetime') > 0
             and number(f.get('app-calls'), 'AP calls during init lifetime')
             <= number(f.get('calls'), 'AP calls')
             and f['exited'] == f['departed'] == '2',
             f'AP {cpu} lacks two completed actors or init-lifetime progress')
        cpu_map[cpu] = (index, f); cpu_indices.append(index)
    need(set(cpu_map) == set(range(1, cpus)), 'AP pressure terminal CPU coverage incomplete')

    bsp_summaries = selected(lines, 'SMP BSP SUMMARY ')
    need(len(bsp_summaries) == 1, 'BSP init terminal summary missing/duplicate')
    bsp_summary_index, _, sf = bsp_summaries[0]
    need(set(sf) == {'cpu', 'slot', 'pid', 'generation', 'calls', 'peak-slots',
                     'exited', 'faults', 'departed'}
         and sf.get('cpu') == '0' and sf.get('slot') == '0' and sf.get('pid') == '1'
         and sf.get('generation') == str(bsp_gen) and sf.get('exited') == '1'
         and sf.get('faults') == '0' and sf.get('departed') == '1'
         and number(sf.get('calls'), 'BSP init syscall count') > 0,
         'BSP init terminal summary identity/accounting mismatch')
    peak = number(sf.get('peak-slots'), 'BSP init peak process slots')
    need(reserved + 1 <= peak <= 16,
         'BSP init peak process occupancy falls outside the reserved process-table bound')
    if mode == 'suite':
        need(peak == 16, 'suite process pressure did not reach the exact 16-slot peak')
    if expected_peak is not None:
        need(peak == expected_peak,
             f'BSP workload peak process occupancy mismatch: expected {expected_peak}, got {peak}')

    frame_rows = selected(lines, 'FRAMES ')
    frame_bounds = selected(lines, 'SMP BSP FRAME BOUND ')
    if mode == 'suite':
        need(len(frame_rows) == len(frame_bounds) == 1,
             'suite frame allocation/bound receipt missing/duplicate')
        frame_index, frame_line, _ = frame_rows[0]
        # The shared APP helper's deliberately narrow token regex can see the
        # `peak=` suffix inside `kstack_peak=`. Parse this suite record by tokens.
        fr = dict(token.split('=', 1) for token in frame_line.split()[1:]
                  if '=' in token)
        bound_index, _, fb = frame_bounds[0]
        counters = selected(lines, 'COUNTERS ')
        need(len(counters) == 1 and frame_index < counters[0][0] < bound_index,
             'suite frame bound does not follow frame/counter terminal summaries')
        suite_success = [i for i, line in enumerate(lines)
                         if line in ('USER PROCESSES OK', 'USER SCHEDULER OK')]
        suite_boots = [i for i, line in enumerate(lines) if line == 'ABSD BOOT OK']
        need(len(suite_success) == 2 and len(suite_boots) == 1
             and bsp_summary_index < frame_index < counters[0][0] < bound_index
             < min(suite_success) < suite_boots[0],
             'suite BSP frame-bound evidence is outside terminal success chronology')
        need(set(fr).issuperset({'baseline', 'peak', 'final'}),
             'suite frame allocation summary lacks baseline/peak/final')
        for key in ('baseline', 'peak', 'final'):
            number(fr[key], f'FRAMES {key}')
        need(fr['baseline'] == '0' and fr['final'] == '0',
             'suite frame allocation did not return to zero baseline')
        need(number(fr['peak'], 'FRAMES peak') >= 0,
             'suite frame allocation peak is negative')
        ordinary_slots = 16 - reserved
        ordinary_bound = ordinary_slots * 24 + 8192
        total_bound = ordinary_bound + 33 * reserved
        need(fb == {'reserved': str(reserved), 'actor-frames': str(33 * reserved),
                    'ordinary-slots': str(ordinary_slots),
                    'ordinary-bound': str(ordinary_bound),
                    'total-bound': str(total_bound), 'peak': fr['peak'],
                    'ignored': '0'},
             'suite BSP frame bound derivation/peak/ignored accounting mismatch')
        need(number(fr['peak'], 'FRAMES peak') <= total_bound,
             'suite frame allocation peak exceeds derived BSP bound')
    else:
        need(not frame_bounds, 'non-suite BSP workload emitted suite frame-bound receipt')

    need(not selected(lines, 'SMP APP TRAP ') and not selected(lines, 'SMP APP SUMMARY '),
         'BSP workload was misidentified as AP-pinned native application')
    exits_by_pid = {}
    for index, _, f in selected(lines, 'USER EXIT '):
        need(set(f) == {'pid', 'status'}, 'USER EXIT fields mismatch')
        pid = number(f.get('pid'), 'USER EXIT PID')
        need(pid not in exits_by_pid, f'duplicate USER EXIT for PID {pid}')
        exits_by_pid[pid] = (index, f)
    need(exits_by_pid.get(1, (None, {}))[1].get('status') == '0',
         'init PID 1 lacks exactly one successful USER EXIT')
    for pid, (actor_index, cpu, role, gen) in actors_by_pid.items():
        exit_record = exits_by_pid.get(pid)
        need(exit_record is not None and exit_record[1]['status'] == '0',
             f'pressure actor PID {pid} lacks exactly one successful USER EXIT')
        exit_index = exit_record[0]
        if role in odd_roles:
            pre_i, pre_actor, _ = pre_by_role[role]
            res_i, res_actor, _ = res_by_role[role]
            need(pre_actor == res_actor == actor_index < pre_i < res_i < exit_index,
                 f'odd actor role {role} preemption/resume/exit chronology mismatch')
        else:
            need(actor_index < exit_index, f'even actor role {role} exit precedes first trap')
    bsp_exit_index = exits_by_pid[1][0]
    need(bsp_trap_index < bsp_exit_index,
         'init exit precedes its first-trap witness')

    quiescent = [i for i, line in enumerate(lines)
                 if line == 'SMP QUEUE QUIESCENT registered=0 queued=0 running=0']
    need(len(quiescent) == 1, 'exact queue quiescence receipt missing/duplicate')
    pressure = selected(lines, 'SMP USER PRESSURE ')
    need(len(pressure) == 1 and number(pressure[0][2].get('calls1'), 'AP pressure calls') > 0,
         'AP ring-3 pressure completion receipt missing/empty')
    need(max([bsp_exit_index, *(exits_by_pid[pid][0] for pid in actor_pids)]) < quiescent[0]
         < pressure[0][0] < min(timer_indices)
         and max(timer_indices) < min(cpu_indices)
         and max(cpu_indices) < bsp_summary_index,
         'exit/quiescence/pressure/timer/CPU/BSP-summary chronology mismatch')

    output_begin, output_end, output_bytes = None, None, None
    if mode in ('external', 'durable'):
        output_begin, output_end, output_bytes = check_output_frame(lines)
        need(output_end < quiescent[0], 'workload output continues beyond queue quiescence')

    boots = [i for i, line in enumerate(lines) if line == 'ABSD BOOT OK']
    need(len(boots) == 1, 'boot completion marker missing/duplicate')
    terminal_markers = []
    if mode == 'external':
        statuses = [i for i, line in enumerate(lines)
                    if line.startswith('EXTERNAL status=')]
        need(len(statuses) == 1 and lines[statuses[0]] ==
             'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0',
             'external resource census is not exactly zero')
        terminal_markers = [i for i, line in enumerate(lines)
                            if line == 'EXTERNAL WORKLOAD OK']
        need(len(terminal_markers) == 1 and bsp_summary_index < statuses[0]
             < terminal_markers[0] < boots[0],
             'external summary/census/workload/boot chronology mismatch')
    elif mode == 'durable':
        statuses = [(i, line, dict(re.findall(r'([a-z0-9_-]+)=([^ ]+)', line)))
                    for i, line in enumerate(lines)
                    if line.startswith('DURABLE status=')]
        need(len(statuses) == 1, 'durable resource census missing/duplicate')
        status_i, _, df = statuses[0]
        required = {'status', 'frames', 'processes', 'cells', 'pipes', 'block_reads',
                    'block_writes', 'block_flushes', 'block_errors', 'block_waits',
                    'block_irqs', 'ticks'}
        need(set(df) == required and all(df[k] == '0' for k in
             ('status', 'frames', 'processes', 'cells', 'pipes')),
             'durable resource census/status/suffix fields mismatch')
        for key in required - {'status'}:
            number(df[key], f'durable {key}')
        terminal_markers = [i for i, line in enumerate(lines) if line == 'DURABLE WORKLOAD OK']
        need(len(terminal_markers) == 1 and bsp_summary_index < status_i
             < terminal_markers[0] < boots[0],
             'durable summary/census/workload/boot chronology mismatch')
    else:
        terminal_markers = [i for i, line in enumerate(lines)
                            if line in ('USER PROCESSES OK', 'USER SCHEDULER OK')]
        need(sum(line == 'USER PROCESSES OK' for line in lines) == 1
             and sum(line == 'USER SCHEDULER OK' for line in lines) == 1,
             'suite terminal markers missing/duplicate')
        need(bsp_summary_index < min(terminal_markers) < boots[0],
             'suite BSP summary/terminal/boot chronology mismatch')

    need(not any(re.search(r'ABSD PANIC:|KERNEL FAULT|FAILED', line) for line in lines),
         'failure record present')
    need(max([calibrated_index, bsp_trap_index, reserve_index, bsp_summary_index,
              quiescent[0], pressure[0][0], *timer_indices, *cpu_indices,
              *terminal_markers, *(exits_by_pid[pid][0] for pid in actor_pids | {1}),
              *([output_end] if output_end is not None else [])]) < boots[0],
         'boot completed before terminal BSP/AP evidence')


def require_reject(name, lines, mutate, cpus, mode, expected_peak):
    changed = mutate(lines[:])
    need(changed != lines, f'negative receipt fixture did not change: {name}')
    try:
        check_lines(changed, cpus, mode, expected_peak)
    except (AssertionError, KeyError, ValueError, StopIteration, IndexError):
        return
    raise AssertionError(f'accepted BSP pressure negative receipt control: {name}')


def negative_controls(lines, cpus, mode, expected_peak):
    def first(rows, prefix):
        return next(i for i, line in enumerate(rows) if line.startswith(prefix))

    def duplicate_bsp_trap(rows):
        i = first(rows, 'SMP BSP TRAP '); rows.insert(i + 1, rows[i]); return rows

    def bsp_wrong_cpu(rows):
        i = first(rows, 'SMP BSP TRAP '); rows[i] = rows[i].replace('cpu=0', 'cpu=1', 1); return rows

    def bsp_reuses_actor_generation(rows):
        trap_i = first(rows, 'SMP BSP TRAP ')
        actor = kv(next(line for line in rows if line.startswith('SMP APP PRESSURE ACTOR ')))
        rows[trap_i] = re.sub(r'generation=\d+', f"generation={actor['generation']}",
                              rows[trap_i], count=1)
        return rows

    def wrong_reservation(rows):
        i = first(rows, 'SMP APP PRESSURE RESERVE ')
        rows[i] = re.sub(r'reserved=\d+', 'reserved=1', rows[i], count=1); return rows

    def duplicate_actor(rows):
        i = first(rows, 'SMP APP PRESSURE ACTOR '); rows.insert(i + 1, rows[i]); return rows

    def missing_odd_resume(rows):
        rows.pop(first(rows, 'SMP APP PRESSURE RESUME ')); return rows

    def preempt_after_exit(rows):
        i = first(rows, 'SMP APP PRESSURE RESUME '); line = rows.pop(i)
        pid = kv(line)['pid']
        exit_i = next(i for i, row in enumerate(rows) if row.startswith(f'USER EXIT pid={pid} '))
        rows.insert(exit_i + 1, line); return rows

    def nonquiescent_queue(rows):
        i = first(rows, 'SMP QUEUE QUIESCENT ')
        rows[i] = rows[i].replace('queued=0', 'queued=1', 1); return rows

    def premature_boot(rows):
        i = rows.index('ABSD BOOT OK'); line = rows.pop(i)
        j = first(rows, 'SMP BSP SUMMARY '); rows.insert(j, line); return rows

    def bad_calibration_quantum(rows):
        i = first(rows, 'SMP TIMER START ')
        rows[i] = rows[i].replace('quantum-tsc=16777216', 'quantum-tsc=16777215', 1)
        return rows

    def backwards_calibration(rows):
        i = first(rows, 'SMP TIMER START ')
        rows[i] = re.sub(r'tsc-b-before=(\d+)', 'tsc-b-before=1', rows[i], count=1)
        return rows

    def excessive_calibration_jitter(rows):
        i = first(rows, 'SMP TIMER START ')
        rows[i] = re.sub(r'tsc-a-after=(\d+)',
                         lambda m: f"tsc-a-after={int(m.group(1)) + 262145}",
                         rows[i], count=1)
        return rows

    def calibration_deadline(rows):
        i = first(rows, 'SMP TIMER START ')
        replacements = {
            'tsc-a-before': '100', 'tsc-a-after': '100',
            'count-a': '2000000', 'tsc-b-before': str(100 + (1 << 34)),
            'tsc-b-after': str(100 + (1 << 34)), 'count-b': '951424',
            'initial': '1024',
        }
        for key, value in replacements.items():
            rows[i] = re.sub(rf'{re.escape(key)}=\d+', f'{key}={value}', rows[i], count=1)
        return rows

    def bsp_trap_before_calibration(rows):
        trap_i = first(rows, 'SMP BSP TRAP ')
        calibration_i = first(rows, 'SMP APP PRESSURE CALIBRATED ')
        trap = rows.pop(trap_i)
        if trap_i < calibration_i:
            calibration_i -= 1
        rows.insert(calibration_i, trap)
        return rows

    def child_before_reserve(rows):
        reserve_i = first(rows, 'SMP APP PRESSURE RESERVE ')
        actor_pids = {kv(row)['pid'] for row in rows
                      if row.startswith('SMP APP PRESSURE ACTOR ')}
        row_i = next(i for i, row in enumerate(rows)
                     if row.startswith('SPAWN OK ')
                     and kv(row).get('pid') != '1'
                     and kv(row).get('pid') not in actor_pids)
        row = rows.pop(row_i); rows.insert(reserve_i, row); return rows

    def missing_cpu_trap(rows):
        i = next(i for i, row in enumerate(rows)
                 if row.startswith('SMP USER TRAP ') and kv(row)['cpu'] == str(cpus - 1))
        rows.pop(i); return rows

    def corrupt_bsp_summary(rows):
        i = first(rows, 'SMP BSP SUMMARY ')
        rows[i] = rows[i].replace('departed=1', 'departed=0', 1); return rows

    def corrupt_summary_identity(rows):
        i = first(rows, 'SMP BSP SUMMARY ')
        rows[i] = re.sub(r'generation=\d+', 'generation=999999', rows[i], count=1)
        return rows

    def duplicate_init_exit(rows):
        i = next(i for i, row in enumerate(rows) if row.startswith('USER EXIT pid=1 '))
        rows.insert(i + 1, rows[i]); return rows

    def missing_init_exit(rows):
        rows.pop(next(i for i, row in enumerate(rows) if row.startswith('USER EXIT pid=1 ')))
        return rows

    def impossible_app_delta(rows):
        i = first(rows, 'SMP APP PRESSURE CPU ')
        rows[i] = re.sub(r'app-calls=\d+', 'app-calls=999999999', rows[i], count=1)
        return rows

    def out_of_range_peak(rows):
        i = first(rows, 'SMP BSP SUMMARY ')
        rows[i] = re.sub(r'peak-slots=\d+', 'peak-slots=17', rows[i], count=1)
        return rows

    def refusal_hist_duplicate(rows):
        summary_i = first(rows, 'SMP BSP REFUSAL SUMMARY ')
        hist = [i for i, row in enumerate(rows) if row.startswith('SMP BSP REFUSAL pid=')]
        if hist:
            rows.insert(summary_i, rows[hist[0]])
        else:
            fake = 'SMP BSP REFUSAL pid=1 program=0 syscall=1 site=0 count=1'
            rows[summary_i:summary_i] = [fake, fake]
            summary_i += 2
            rows[summary_i] = 'SMP BSP REFUSAL SUMMARY events=2 kinds=2 tracked=1'
        return rows

    def refusal_hist_missing(rows):
        hist = [i for i, row in enumerate(rows) if row.startswith('SMP BSP REFUSAL pid=')]
        summary_i = first(rows, 'SMP BSP REFUSAL SUMMARY ')
        if hist:
            rows.pop(hist[0])
        else:
            rows[summary_i] = 'SMP BSP REFUSAL SUMMARY events=1 kinds=1 tracked=1'
        return rows

    def refusal_hist_wrong_sum(rows):
        hist = [i for i, row in enumerate(rows) if row.startswith('SMP BSP REFUSAL pid=')]
        summary_i = first(rows, 'SMP BSP REFUSAL SUMMARY ')
        if hist:
            rows[hist[0]] = re.sub(r'count=(\d+)',
                                   lambda m: f'count={int(m.group(1)) + 1}',
                                   rows[hist[0]], count=1)
        else:
            rows[summary_i] = 'SMP BSP REFUSAL SUMMARY events=1 kinds=0 tracked=1'
        return rows

    def refusal_omit_injection(rows):
        i = first(rows, 'SMP BSP REFUSAL SUMMARY ')
        rows.insert(i, 'SMP BSP REFUSAL INJECT pid=1 program=0 syscall=12 site=0 omitted=1 result=unchanged')
        return rows

    def missing_stuck_refusal(rows):
        ready = kv(next(row for row in rows if row.startswith('SUPERVISOR STUCK READY ')))
        stuck_pid = ready['pid']
        index = next(i for i, row in enumerate(rows)
                     if row.startswith(f'SMP BSP REFUSAL pid={stuck_pid} program=23 syscall=12 site=0 '))
        used = {(kv(row).get('pid'), kv(row).get('program'), kv(row).get('syscall'), kv(row).get('site'))
                for row in rows if row.startswith('SMP BSP REFUSAL pid=')}
        declared = {'1'} | {kv(row)['pid'] for row in rows if row.startswith('SPAWN OK ')}
        replacement = next(pid for pid in sorted(declared, key=int)
                           if pid != stuck_pid and (pid, '23', '12', '0') not in used)
        rows[index] = re.sub(r'pid=\d+', f'pid={replacement}', rows[index], count=1)
        return rows

    def missing_stuck_ready(rows):
        rows.pop(first(rows, 'SUPERVISOR STUCK READY ')); return rows

    def ready_after_kill(rows):
        ready_i = first(rows, 'SUPERVISOR STUCK READY ')
        ready = rows.pop(ready_i)
        pid = kv(ready)['pid']
        kill_i = next(i for i, row in enumerate(rows)
                      if row.startswith(f'USER KILLED pid={pid} by=1'))
        rows.insert(kill_i + 1, ready)
        return rows

    def missing_frame_reservation(rows):
        rows.pop(first(rows, 'SMP BSP FRAME RESERVATION ')); return rows

    def duplicate_frame_reservation(rows):
        i = first(rows, 'SMP BSP FRAME RESERVATION ')
        rows.insert(i + 1, rows[i]); return rows

    def mismatched_frame_reservation_identity(rows):
        i = first(rows, 'SMP BSP FRAME RESERVATION ')
        rows[i] = re.sub(r'pid=\d+', 'pid=999999', rows[i], count=1)
        return rows

    def underreserved_actor_frames(rows):
        i = first(rows, 'SMP BSP FRAME RESERVATION ')
        rows[i] = rows[i].replace('frames=33', 'frames=32', 1); return rows

    def wrong_derived_frame_bound(rows):
        i = first(rows, 'SMP BSP FRAME BOUND ')
        rows[i] = re.sub(r'ordinary-bound=\d+', 'ordinary-bound=1', rows[i], count=1)
        return rows

    def frame_peak_disagrees(rows):
        i = first(rows, 'SMP BSP FRAME BOUND ')
        rows[i] = re.sub(r'peak=\d+', 'peak=1', rows[i], count=1)
        return rows

    def negative_frame_peak(rows):
        i = first(rows, 'FRAMES ')
        rows[i] = re.sub(r'(?<![A-Za-z0-9_-])peak=\d+', 'peak=-1', rows[i], count=1)
        i = first(rows, 'SMP BSP FRAME BOUND ')
        rows[i] = re.sub(r'peak=\d+', 'peak=-1', rows[i], count=1)
        return rows

    def missing_frame_bound(rows):
        rows.pop(first(rows, 'SMP BSP FRAME BOUND ')); return rows

    def nonzero_final_frames(rows):
        i = first(rows, 'FRAMES ')
        rows[i] = re.sub(r'final=\d+', 'final=1', rows[i], count=1)
        return rows

    def bound_before_counters(rows):
        bound_i = first(rows, 'SMP BSP FRAME BOUND ')
        bound = rows.pop(bound_i)
        counters_i = first(rows, 'COUNTERS ')
        rows.insert(counters_i, bound)
        return rows

    def bound_after_boot(rows):
        bound_i = first(rows, 'SMP BSP FRAME BOUND ')
        bound = rows.pop(bound_i)
        boot_i = rows.index('ABSD BOOT OK')
        rows.insert(boot_i + 1, bound)
        return rows

    mutations = [
        ('duplicate BSP identity', duplicate_bsp_trap),
        ('wrong BSP CPU identity', bsp_wrong_cpu),
        ('BSP generation aliases AP actor', bsp_reuses_actor_generation),
        ('reservation count mismatch', wrong_reservation),
        ('duplicate AP actor', duplicate_actor),
        ('missing odd actor resume', missing_odd_resume),
        ('resume after actor exit', preempt_after_exit),
        ('non-quiescent run queue', nonquiescent_queue),
        ('boot before BSP terminal summary', premature_boot),
        ('invalid AP calibration quantum', bad_calibration_quantum),
        ('backwards AP calibration sample', backwards_calibration),
        ('excessive AP calibration jitter', excessive_calibration_jitter),
        ('AP calibration deadline overflow', calibration_deadline),
        ('BSP first trap before AP readiness fence', bsp_trap_before_calibration),
        ('child spawn before reservation', child_before_reserve),
        ('missing AP first-user witness', missing_cpu_trap),
        ('corrupt BSP terminal accounting', corrupt_bsp_summary),
        ('corrupt BSP terminal identity', corrupt_summary_identity),
        ('duplicate init exit', duplicate_init_exit),
        ('missing init exit', missing_init_exit),
        ('impossible AP application-call delta', impossible_app_delta),
        ('out-of-range process occupancy peak', out_of_range_peak),
        ('duplicate BSP refusal histogram key', refusal_hist_duplicate),
        ('missing BSP refusal histogram row', refusal_hist_missing),
        ('BSP refusal histogram sum mismatch', refusal_hist_wrong_sum),
        ('refusal omission injection marker', refusal_omit_injection),
        ('missing actor frame reservation', missing_frame_reservation),
        ('duplicate actor frame reservation', duplicate_frame_reservation),
        ('wrong actor frame reservation identity', mismatched_frame_reservation_identity),
        ('under-reserved actor frame bound', underreserved_actor_frames),
    ]
    if mode == 'suite':
        mutations.extend([
            ('incorrect derived ordinary frame bound', wrong_derived_frame_bound),
            ('frame peak disagrees with allocation summary', frame_peak_disagrees),
            ('missing suite frame bound', missing_frame_bound),
            ('nonzero final frame allocation', nonzero_final_frames),
            ('frame bound before counters', bound_before_counters),
            ('frame bound after boot success', bound_after_boot),
            ('negative FRAMES peak', negative_frame_peak),
            ('missing supervisor STUCK readiness', missing_stuck_ready),
            ('supervisor STUCK readiness after init kill', ready_after_kill),
            ('missing generation-4 STUCK refusal', missing_stuck_refusal),
        ])
    else:
        def unexpected_frame_bound(rows):
            actor_frames = 33 * (2 * (cpus - 1))
            ordinary_slots = 16 - 2 * (cpus - 1)
            ordinary_bound = ordinary_slots * 24 + 8192
            frame_row = (f'SMP BSP FRAME BOUND reserved={2 * (cpus - 1)} '
                         f'actor-frames={actor_frames} ordinary-slots={ordinary_slots} '
                         f'ordinary-bound={ordinary_bound} '
                         f'total-bound={ordinary_bound + actor_frames} peak=1 ignored=0')
            i = first(rows, 'SMP BSP SUMMARY ')
            rows.insert(i + 1, frame_row)
            return rows
        mutations.append(('unexpected suite frame bound in non-suite mode',
                          unexpected_frame_bound))
    for name, mutate in mutations:
        require_reject(name, lines, mutate, cpus, mode, expected_peak)
    return len(mutations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', type=Path, required=True)
    parser.add_argument('--placement', type=Path, required=True)
    parser.add_argument('--cpus', type=int, choices=(2, 4, 6), required=True)
    parser.add_argument('--mode', choices=('external', 'durable', 'suite'), required=True)
    parser.add_argument('--expected-peak', type=int, choices=range(1, 17),
                        help='optional exact peak-slot census from the selected platform fixture')
    args = parser.parse_args()
    lines = args.serial.read_text(errors='replace').splitlines()
    check_placement(args.placement, args.cpus)
    check_lines(lines, args.cpus, args.mode, args.expected_peak)
    count = negative_controls(lines, args.cpus, args.mode, args.expected_peak)
    print(f'SMP BSP PRESSURE oracle OK cpus={args.cpus} mode={args.mode} '
          f'actors={2 * (args.cpus - 1)} negative-controls={count}')


if __name__ == '__main__':
    main()
