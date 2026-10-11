#!/usr/bin/env python3
"""Closed receipt oracle for separate-core 2/4/6-vCPU SMP N-way boots.

Usage: check-smp-nway.py SERIAL_LOG VCPU_PLACEMENT_JSON
The placement JSON is written by scripts/smp-user-qemu.py before guest release.
"""
import json
import re
import sys
from pathlib import Path


def fields(line):
    return {k: int(v, 0) if v.lower().startswith('0x') else int(v)
            for k, v in re.findall(r'([\w-]+)=(0x[\da-fA-F]+|\d+)', line)}


def need(ok, message):
    if not ok:
        raise AssertionError(message)


def topology(path, cpus):
    doc = json.loads(Path(path).read_text())
    need(doc.get('kvm') == {'enabled': True, 'present': True}, 'QMP did not confirm KVM')
    need(doc.get('guest_topology_mode') == 'explicit-smp-scheduler-test', 'implicit QEMU topology')
    need(doc.get('host_topology') == 'separate', 'host placement is not separate-core mode')
    need(doc.get('guest_topology') == {'sockets': 1, 'cores': cpus, 'threads': 1},
         'guest topology does not match the selected N-way case')
    vcpus = doc.get('vcpus', [])
    need(len(vcpus) == cpus, 'QMP vCPU count mismatch')
    need(sorted(v.get('cpu-index', -1) for v in vcpus) == list(range(cpus)),
         'QMP CPU indices are missing/duplicated')
    host_cpus, host_cores, guest_cores, apic_ids = set(), set(), set(), set()
    for v in vcpus:
        index = v['cpu-index']
        host_cpu = v.get('host-cpu')
        host_core = (v.get('host-package'), v.get('host-core'))
        need(isinstance(host_cpu, int) and host_cpu not in host_cpus, 'host CPU reused')
        need(all(isinstance(x, int) for x in host_core) and host_core not in host_cores,
             'vCPUs are not placed on distinct host physical cores')
        need(v.get('affinity') == [host_cpu], 'vCPU affinity is not a single pinned host CPU')
        host_cpus.add(host_cpu)
        host_cores.add(host_core)
        props = v.get('props') or {}
        socket = props.get('socket-id', 0)
        core = props.get('core-id', index)
        thread = props.get('thread-id', 0)
        need(socket == 0 and thread == 0 and core not in guest_cores,
             'QMP guest cores are not unique single-thread cores')
        guest_cores.add(core)
        # QEMU versions differ on where query-cpus-fast exposes the APIC ID.
        # CPU-index is an explicit APIC-ID inference only if QMP omits it.
        apic = props.get('apic-id', v.get('apic-id', index))
        need(isinstance(apic, int) and apic not in apic_ids, 'APIC identity missing/duplicated')
        need(apic == index, 'QMP APIC differs from admitted contiguous CPU identity')
        apic_ids.add(apic)
    need(len(host_cpus) == len(host_cores) == len(guest_cores) == len(apic_ids) == cpus,
         'topology uniqueness incomplete')


def check_lines(lines, cpus, report=False):
    need(cpus in (2, 4, 6), 'unsupported closed N-way count')
    need(lines.count('SMP QUEUE QUIESCENT registered=0 queued=0 running=0') == 1,
         'queue quiescence missing/duplicate')
    need(lines.count(f'SMP NWAY SUMMARY terminal=0 cases=1 resources=0') == 1,
         'N-way terminal summary missing/duplicate')
    need(lines.count('ABSD BOOT OK') == 1, 'successful boot record missing/duplicate')
    need(not any(re.search(r'PANIC|KERNEL FAULT|FAILED', line) for line in lines),
         'failure record present')

    proof_lines = [line for line in lines if line.startswith('SMP NWAY PROOF ')]
    need(len(proof_lines) == 1, 'N-way proof missing/duplicate')
    proof = fields(proof_lines[0])
    need(proof == {'cpus': cpus, 'workers': 2 * cpus,
                   'users': 16 * (cpus + 1) + 48 + 9 * (cpus - 1),
                   'transfers': 16 * cpus + 32 + 4 * (cpus - 1), 'steals': 16},
         f'N-way proof mismatch: {proof}')

    # Kernel-decoded topology is the architectural authority and must report
    # every CPU with an isolated sibling mask and a distinct APIC/core.
    topology_lines = [line for line in lines if line.startswith('SMP TOPOLOGY ')]
    need(len(topology_lines) == cpus, 'guest topology record count')
    guest_cpus, apics, package_cores = {}, set(), set()
    for line in topology_lines:
        f = fields(line)
        cpu = f['cpu']
        need(cpu < cpus and cpu not in guest_cpus, 'duplicate/out-of-range guest topology CPU')
        need(f['online'] == 1 and f['parked'] == int(cpu > 0), 'guest CPU online/parked mismatch')
        need(f['siblings'] == (1 << cpu), 'guest CPU sibling mask is not isolated')
        need(f['apic'] == f['cpu'], 'kernel APIC differs from admitted CPU identity')
        need(f['apic'] not in apics and (f['package'], f['core']) not in package_cores,
             'guest APIC/package/core identity duplicated')
        apics.add(f['apic'])
        package_cores.add((f['package'], f['core']))
        guest_cpus[cpu] = f
    need(set(guest_cpus) == set(range(cpus)) and len(apics) == len(package_cores) == cpus,
         'guest topology coverage incomplete')

    # One complete closed stage history per witness identity. Roles are the
    # fixture's sealed role IDs, not arbitrary caller-provided CPU labels.
    user_lines = []
    users = {}
    for i, line in enumerate(lines):
        if not line.startswith('SMP NWAY USER '):
            continue
        f = fields(line)
        role, pid, gen = f['role'], f['pid'], f['generation']
        cpu, stage, epoch = f['cpu'], f['stage'], f['epoch']
        need(pid > 0 and gen > 0 and f['cpl'] == 3 and epoch > 0, 'bad N-way user witness')
        if 128 <= role <= 139:
            need(role < 128 + 2 * cpus and cpu == (role - 128) // 2
                 and stage == role - 128 and f['preempts'] > 0, 'fixed worker witness mismatch')
        elif role == 160:
            need(cpu == 0 if stage == 0 else cpu == stage % cpus,
                 'migrant stage has wrong CPU')
            need(0 <= stage <= cpus, 'migrant stage out of range')
        elif role == 161:
            need(stage in (0, 1, 2), 'stealer stage out of range')
            need((cpu == 0 if stage in (0, 2) else 0 < cpu < cpus), 'stealer CPU sequence')
        elif 162 <= role <= 165:
            need(stage in ((0, 1, 2) if role == 162 else (0, 1)),
                 'composition stage out of range')
            need((cpu == 0 if stage == 0 else 0 < cpu < cpus),
                 'composition CPU placement')
        elif 184 <= role <= 189:
            need(role < 184 + cpus and cpu == role - 184 and stage == 0,
                 'pipe reader placement mismatch')
        else:
            raise AssertionError(f'unexpected N-way userspace role {role}')
        key = (pid, gen, role)
        users.setdefault(key, []).append({**f, '_line': i})
        user_lines.append((i, f))

    worker_roles = set(range(128, 128 + 2 * cpus))
    expected_user_count = 2 * cpus + 16 * (cpus + 1) + 48 + cpus + 9 * (cpus - 1)
    need(len(user_lines) == expected_user_count, 'N-way USER event count')
    for role in worker_roles:
        matches = [(k, v) for k, v in users.items() if k[2] == role]
        need(len(matches) == 1 and len(matches[0][1]) == 1, f'worker role {role} missing/duplicate')
    migrants = [(k, v) for k, v in users.items() if k[2] == 160]
    stealers = [(k, v) for k, v in users.items() if k[2] == 161]
    readers = [(k, v) for k, v in users.items() if 184 <= k[2] <= 189]
    compositions = [(k, v) for k, v in users.items() if 162 <= k[2] <= 165]
    need(len(migrants) == len(stealers) == 16 and len(readers) == cpus,
         'migrant/stealer/reader role census')
    need(len(compositions) == 4 * (cpus - 1), 'composition role census')
    all_user_pids = [key[0] for key in users]
    need(len(set(all_user_pids)) == len(all_user_pids), 'PID reused across N-way witness identities')
    for (pid, gen, role), history in users.items():
        stages = [w['stage'] for w in history]
        if role == 160:
            need(stages == list(range(cpus + 1)), f'migrant stage ledger {pid}')
        elif role == 161:
            need(stages == [0, 1, 2], f'stealer stage ledger {pid}')
        elif role == 162:
            need(stages == [0, 1, 2] and history[0]['cpu'] == 0
                 and history[1]['cpu'] == history[2]['cpu'],
                 f'block/wake composition stage ledger {pid}')
        elif 163 <= role <= 165:
            need(stages == [0, 1] and history[0]['cpu'] == 0,
                 f'composition stage ledger {pid}')
            need(history[1]['cpu'] > 0, f'composition did not reach an AP {pid}')
        else:
            need(len(history) == 1, f'fixed role duplicated {role}/{pid}')

    # Role 128 emits a single contiguous sample block after it has observed
    # progress on every admitted CPU. Bind the samples to that observer's
    # registration identity and require the block before any worker witness.
    overlap_lines = [(i, line) for i, line in enumerate(lines)
                     if line.startswith('SMP NWAY OVERLAP ')]
    need(len(overlap_lines) == cpus, 'per-CPU overlap sample count')
    overlap = []
    expected_overlap_keys = {'observer', 'generation', 'cpu', 'mask', 'before',
                             'after', 'first', 'last', 'cpl'}
    for i, line in overlap_lines:
        m = re.fullmatch(
            r'SMP NWAY OVERLAP observer=(\d+) generation=(\d+) cpu=(\d+) '
            r'mask=(\d+) before=(\d+) after=(\d+) first=(\d+) last=(\d+) cpl=(\d+)',
            line)
        need(m is not None, 'overlap record fields/order malformed')
        f = fields(line)
        need(set(f) == expected_overlap_keys, 'overlap record has missing/extra fields')
        need(f['cpu'] < cpus and f['mask'] == (1 << cpus) - 1 and f['cpl'] == 3,
             'overlap CPU/mask/CPL mismatch')
        need(f['before'] == f['after'] and f['last'] > f['first'],
             'overlap sample crossed user entry or lacks per-CPU progress')
        overlap.append((i, f))
    need([f['cpu'] for _, f in overlap] == list(range(cpus)),
         'overlap CPU order/coverage mismatch')
    need([i for i, _ in overlap] == list(range(overlap[0][0], overlap[0][0] + cpus)),
         'overlap sample records are not contiguous')
    observer_records = [(key, history) for key, history in users.items() if key[2] == 128]
    need(len(observer_records) == 1, 'overlap observer role 128 missing/duplicate')
    observer_key, observer_history = observer_records[0]
    need(all((f['observer'], f['generation']) == observer_key[:2] for _, f in overlap),
         'overlap records disagree on observer registration identity')
    first_worker_line = min(i for i, f in user_lines if 128 <= f['role'] < 128 + 2 * cpus)
    proof_index = next(i for i, line in enumerate(lines) if line.startswith('SMP NWAY PROOF '))
    root_exit_index = next(i for i, line in enumerate(lines)
                           if line.startswith('USER EXIT ') and fields(line)['pid'] == 1)
    need(overlap[-1][0] < observer_history[0]['_line'] and overlap[-1][0] < first_worker_line,
         'overlap proof does not precede worker witnesses')
    need(overlap[-1][0] < proof_index and overlap[-1][0] < root_exit_index,
         'overlap proof occurs after terminal/root completion')

    # This hook records saved timer frames for every live role. Require the
    # exact worker pair coverage and one frame for every victim before REQUEST.
    preempt_keys = {}
    for line_index, line in enumerate(lines):
        if not line.startswith('SMP NWAY PREEMPT '):
            continue
        f = fields(line)
        key = (f['pid'], f['generation'], f['role'], f['cpu'])
        need(f['saved'] == 1 and f['pid'] > 0 and f['generation'] > 0 and f['cpu'] < cpus,
             'invalid saved-preemption record')
        need(key not in preempt_keys, 'duplicate saved-preemption record')
        role = f['role']
        if 128 <= role < 128 + 2 * cpus:
            need(f['cpu'] == (role - 128) // 2
                 and (f['pid'], f['generation'], role) in users,
                 'worker preemption identity/CPU differs from witness')
        elif 144 <= role < 144 + cpus:
            need(f['cpu'] == role - 144, 'victim preemption CPU/role mismatch')
        elif role in (120, 196):
            need(f['cpu'] == (0 if role == 120 else 1), 'root/helper preemption CPU mismatch')
        elif role in (160, 161):
            need((f['pid'], f['generation'], role) in users, 'migrant preemption identity mismatch')
        elif 162 <= role <= 165:
            need((f['pid'], f['generation'], role) in users and f['cpu'] == 0,
                 'composition initial timer identity/CPU mismatch')
        elif 176 <= role < 176 + cpus:
            need(f['cpu'] == role - 176, 'fault-role preemption CPU mismatch')
        elif 184 <= role < 184 + cpus:
            need(f['cpu'] == role - 184, 'pipe-role preemption CPU mismatch')
        else:
            raise AssertionError(f'unexpected preemption role {role}')
        preempt_keys[key] = {'line': line_index, 'fields': f}
    worker_preempts = {key for key in preempt_keys if 128 <= key[2] < 128 + 2 * cpus}
    need(len(worker_preempts) == 2 * cpus, 'fixed-worker preemption proof cardinality')
    expected_preempt_keys = set()
    for key, hist in users.items():
        if 128 <= key[2] < 128 + 2 * cpus:
            expected_preempt_keys.add((key[0], key[1], key[2], hist[0]['cpu']))
    need(worker_preempts == expected_preempt_keys, 'not exactly two timer-saved workers per CPU')

    for key, hist in users.items():
        if 128 <= key[2] < 128+2*cpus:
            evidence=preempt_keys[(key[0],key[1],key[2],hist[0]['cpu'])]
            need(evidence['line'] < hist[0]['_line'], 'worker preemption after user completion')
    generation_pids={}
    for pid,gen,role in users:
        need(gen not in generation_pids or generation_pids[gen]==pid,'registration generation reused across PIDs')
        generation_pids[gen]=pid
    for (pid,gen,role,cpu) in preempt_keys:
        need(gen not in generation_pids or generation_pids[gen]==pid,'preemption generation reused across PIDs')
        generation_pids[gen]=pid

    comp_by_identity = {(key[0], key[1], key[2]): hist
                        for key, hist in compositions}
    comp_initial_preempts = [key for key in preempt_keys if 162 <= key[2] <= 165]
    need(len(comp_initial_preempts) == 4 * (cpus - 1),
         'composition initial timer witness count')
    for pid, gen, role, cpu in comp_initial_preempts:
        need(cpu == 0 and (pid, gen, role) in comp_by_identity,
             'composition initial timer witness identity/CPU')
        initial = preempt_keys[(pid, gen, role, cpu)]
        hist = comp_by_identity[(pid, gen, role)]
        first_positive = next((w for w in hist if w['preempts'] > 0), None)
        transfer = next(((i, fields(line)) for i, line in enumerate(lines)
                         if line.startswith('SMP QUEUE TRANSFER ')
                         and fields(line)['pid'] == pid
                         and fields(line)['generation'] == gen), None)
        need(first_positive is not None and transfer is not None
             and initial['line'] < transfer[0]
             and initial['line'] < first_positive['_line'],
             'composition initial timer must precede admission transfer/first positive witness')

    # Composition-specific records separate migrated operations from the
    # fixed per-CPU block/fault/stop census above.
    def records(prefix):
        return [(i, fields(line)) for i, line in enumerate(lines)
                if line.startswith(prefix)]

    comp_blocks = records('SMP NWAY COMPOSE BLOCK ')
    comp_refusals = records('SMP NWAY COMPOSE REFUSE ')
    comp_departs = records('SMP NWAY COMPOSE DEPART ')
    comp_terminals = records('SMP NWAY COMPOSE TERMINAL ')
    comp_cpus = records('SMP NWAY COMPOSE CPU ')
    comp_proofs = records('SMP NWAY COMPOSE PROOF ')
    comp_timers = records('SMP NWAY COMPOSE TIMER ')
    need(len(comp_blocks) == len(comp_refusals) == cpus - 1
         and len(comp_departs) == len(comp_terminals) == 4 * (cpus - 1),
         'composition block/refusal/depart/terminal record count')
    need(len(comp_cpus) == cpus and len(comp_proofs) == 1,
         'composition CPU/proof record count')
    need(comp_proofs[0][1] == {'tasks': 4 * (cpus - 1)},
         'composition proof fields mismatch')

    composition_roles = {(key[0], key[1], key[2]): hist
                         for key, hist in compositions}
    for role in range(162, 166):
        role_histories = [(key, hist) for key, hist in compositions if key[2] == role]
        need(len(role_histories) == cpus - 1
             and {hist[1]['cpu'] for _, hist in role_histories} == set(range(1, cpus)),
             f'composition role {role} does not cover each AP exactly once')
    def composition_record(record, role, outcome=None):
        i, f = record
        key = (f['pid'], f['generation'], f['role'])
        need(key in composition_roles and f['role'] == role,
             f'composition role/identity mismatch for role {role}')
        hist = composition_roles[key]
        target = hist[1]['cpu']
        need(f['cpu'] == target and f['epoch'] > 0,
             f'composition terminal CPU/epoch mismatch for role {role}')
        if outcome is not None:
            need(f['outcome'] == outcome, f'composition terminal outcome mismatch for role {role}')
        return i, f, hist, target

    block_by_pid = {}
    for record in comp_blocks:
        i, f, hist, target = composition_record(record, 162)
        key = (f['pid'], f['generation'], f['role'])
        need(f['saved'] == 1 and key not in block_by_pid,
             'composition block lacks saved frame or duplicates')
        need(f['epoch'] >= hist[1]['epoch']
             and hist[1]['cpu'] == target and hist[2]['cpu'] == target
             and hist[1]['_line'] < i < hist[2]['_line']
             and hist[2]['epoch'] > f['epoch'],
             'composition block/wake chronology or epoch advance mismatch')
        block_by_pid[key] = (i, f)

    refuse_by_pid = {}
    for record in comp_refusals:
        i, f, hist, target = composition_record(record, 162)
        key = (f['pid'], f['generation'], f['role'])
        need(f['to'] == 0 and f['waiting'] == 1 and key not in refuse_by_pid,
             'composition blocked-transfer refusal mismatch/duplicate')
        need(f['epoch'] == block_by_pid[key][1]['epoch'],
             'composition refusal epoch differs from saved blocked frame')
        need(block_by_pid[key][0] < i < hist[2]['_line'],
             'composition refusal not after block and before wake witness')
        refuse_by_pid[key] = (i, f)

    depart_by_pid = {}
    for record in comp_departs:
        i, f = record
        key = (f['pid'], f['generation'], f['role'])
        expected_kind = {162: 0, 163: 1, 164: 0, 165: 2}.get(f['role'])
        need(key in composition_roles and f['kind'] == expected_kind
             and f['departed'] == 1 and f['epoch'] > 0,
             'composition departure identity/kind mismatch')
        hist = composition_roles[key]
        need(f['cpu'] == hist[1]['cpu'] and f['epoch'] >= hist[-1]['epoch'],
             'composition departure used reaper/wrong CPU or claim epoch')
        need(hist[-1]['_line'] < i, 'composition departure precedes final user witness')
        need(key not in depart_by_pid, 'duplicate composition departure')
        depart_by_pid[key] = (i, f)

    terminal_by_pid = {}
    expected_outcome = {162: 7, 163: 14, 164: 7, 165: 0}
    for record in comp_terminals:
        i, f = record
        key = (f['pid'], f['generation'], f['role'])
        need(key in composition_roles and f['kind'] == {162: 0, 163: 1, 164: 0, 165: 2}.get(f['role'])
             and f['outcome'] == expected_outcome.get(f['role']) and f['departed'] == 1,
             'composition terminal identity/kind/outcome mismatch')
        hist = composition_roles[key]
        need(f['cpu'] == hist[1]['cpu'] and f['epoch'] == depart_by_pid[key][1]['epoch'],
             'composition terminal CPU/epoch differs from actual departure claim')
        need(i > depart_by_pid[key][0], 'composition cleanup precedes departure latch')
        need(key not in terminal_by_pid, 'duplicate composition terminal record')
        terminal_by_pid[key] = (i, f)
    need(set(depart_by_pid) == set(composition_roles)
         and set(terminal_by_pid) == set(composition_roles),
         'composition terminal identity coverage')
    need(set(block_by_pid) == {(p, g, r) for p, g, r in composition_roles if r == 162}
         and set(refuse_by_pid) == set(block_by_pid),
         'composition block/refusal coverage')

    timer_by_cpu = {}
    for i, f in comp_timers:
        key = (f['pid'], f['generation'], f['role'])
        need(f['role'] == 165 and key in composition_roles and f['saved'] == 1,
             'composition timer identity mismatch')
        need(0 <= f['cpu'] < cpus, 'out-of-range composition timer CPU')
        hist = composition_roles[key]
        need(f['cpu'] in (0, hist[1]['cpu']),
             'composition timer CPU is outside observed ownership history')
        timer_key = (f['pid'], f['generation'], f['cpu'])
        need(timer_key not in timer_by_cpu, 'duplicate composition timer identity/CPU')
        timer_by_cpu[timer_key] = (i, f)
    expected_timer_keys = set()
    for key, hist in composition_roles.items():
        if key[2] == 165:
            expected_timer_keys.add((key[0], key[1], 0))
            expected_timer_keys.add((key[0], key[1], hist[1]['cpu']))
    need(set(timer_by_cpu) == expected_timer_keys,
         'composition per-role/per-CPU timer evidence incomplete')
    for key, hist in composition_roles.items():
        if key[2] != 165:
            continue
        source_timer_i, source_timer = timer_by_cpu[(key[0], key[1], 0)]
        target_timer_i, target_timer = timer_by_cpu[(key[0], key[1], hist[1]['cpu'])]
        transfer = [(i, fields(line)) for i, line in enumerate(lines)
                    if line.startswith('SMP QUEUE TRANSFER ')
                    and fields(line)['pid'] == key[0]
                    and fields(line)['generation'] == key[1]]
        need(len(transfer) == 1, 'composition stop transfer missing/duplicate')
        transfer_i, transfer_fields = transfer[0]
        defer = next((j for j, line in enumerate(lines)
                      if line.startswith('SMP QUEUE DEFER ')
                      and fields(line)['pid'] == key[0]
                      and fields(line)['to'] == 0), None)
        need(source_timer_i < transfer_i and source_timer['epoch'] <= transfer_fields['epoch']
             and target_timer_i > transfer_i and target_timer['epoch'] > transfer_fields['epoch'],
             'composition source/target timer evidence outside transfer interval')
        need(defer is not None and target_timer_i < defer
             and fields(lines[defer])['epoch'] >= target_timer['epoch'],
             'target saved timer does not precede migrated-stop defer')

    compose_cpu_by_id = {}
    for _, f in comp_cpus:
        cpu = f['cpu']
        expected = ({'cpu': 0, 'blocks': 0, 'refusals': 0, 'exits': 0, 'faults': 0, 'kills': 0}
                    if cpu == 0 else
                    {'cpu': cpu, 'blocks': 1, 'refusals': 1, 'exits': 2, 'faults': 1, 'kills': 1})
        need(f == expected and cpu not in compose_cpu_by_id,
             'composition per-CPU accounting mismatch/duplicate')
        compose_cpu_by_id[cpu] = f
    need(set(compose_cpu_by_id) == set(range(cpus)), 'composition per-CPU accounting coverage')

    # Block-then-wake pipe evidence and one page fault on each CPU.
    block_lines = [line for line in lines if line.startswith('SMP NWAY BLOCK ')]
    need(len(block_lines) == cpus, 'blocked pipe role count')
    blocks = {}
    for line in block_lines:
        f = fields(line)
        need(f['saved'] == 1 and f['cpu'] < cpus, 'pipe block lacks saved waiting-state proof')
        key = (f['pid'], f['generation'], f['cpu'])
        need(key not in blocks, 'duplicate pipe block record')
        blocks[key] = lines.index(line)
    for key, hist in readers:
        pid, gen, role = key
        cpu = role - 184
        bkey = (pid, gen, cpu)
        need(bkey in blocks and blocks[bkey] < hist[0]['_line'], 'pipe wake witness lacks preceding block')

    fault_lines = [line for line in lines if line.startswith('SMP NWAY FAULT ')]
    need(len(fault_lines) == cpus, 'per-CPU fault role count')
    fault_pids = set()
    fault_cpus = set()
    for line in fault_lines:
        f = fields(line)
        need(f['pid'] > 0 and f['cpu'] < cpus and f['vector'] == 14 and f['departed'] == 1,
             'fault role/vector/departure mismatch')
        need(f['cpu'] not in fault_cpus and f['pid'] not in fault_pids, 'duplicate fault role')
        fault_cpus.add(f['cpu'])
        fault_pids.add(f['pid'])
    need(fault_cpus == set(range(cpus)), 'fault CPU coverage incomplete')
    user_faults = [line for line in lines if line.startswith('USER FAULT ')]
    compose_fault_pids = {key[0] for key in composition_roles if key[2] == 163}
    need(len(user_faults) == 2 * cpus - 1, 'ordinary USER FAULT record count')
    user_fault_pids = set()
    for line in user_faults:
        f = fields(line)
        need(f['vector'] == 14 and f['pid'] in fault_pids | compose_fault_pids
             and f['pid'] not in user_fault_pids,
             'ordinary page-fault record differs from fixed/composition terminal faults')
        user_fault_pids.add(f['pid'])
    need(user_fault_pids == fault_pids | compose_fault_pids,
         'normal and N-way fault identities differ')

    # Chronological global queue ownership. USER stage witnesses bracket each
    # transfer; optional DEFER records, when present, bind exactly to its next
    # transfer. The one idle steal per stealer is the only steal transfer.
    task_history = {}
    task_key_by_pid = {}
    for key, hist in users.items():
        if key[2] in (160, 161, 162, 163, 164, 165):
            task_history[(key[0], key[1])] = {'role': key[2], 'witnesses': hist, 'transfers': []}
            task_key_by_pid[key[0]] = (key[0], key[1])
    transfers = []
    pending_defer = {}
    canceled_composition_defers = {}
    for i, line in enumerate(lines):
        if line.startswith('SMP QUEUE DEFER '):
            f = fields(line)
            pid = f['pid']
            need(pid in task_key_by_pid and pid not in pending_defer, 'defer for unknown/duplicate task')
            task = task_history[task_key_by_pid[pid]]
            prior = [w for w in task['witnesses'] if w['_line'] < i]
            latest = max(prior, key=lambda w: w['_line']) if prior else None
            need(latest is not None and f['epoch'] >= latest['epoch'] and f['to'] != latest['cpu'],
                 'stale defer/invalid destination')
            pending_defer[pid] = (f['epoch'], f['to'])
        elif line.startswith('SMP QUEUE TRANSFER '):
            f = fields(line)
            need(f['n'] == len(transfers) + 1, 'transfer sequence gap/reorder')
            key = (f['pid'], f['generation'])
            need(key in task_history, 'transfer before initial claim/witness or stale generation')
            task = task_history[key]
            ws = task['witnesses']
            prev_index = len(task['transfers'])
            need(prev_index < len(ws) - 1, 'extra transfer after final witness')
            source, dest, epoch = f['from'], f['to'], f['epoch']
            previous, following = ws[prev_index], ws[prev_index + 1]
            need(f['saved'] == f['departed'] == 1, 'transfer lacks saved/departed proof')
            need(source == previous['cpu'] and epoch >= previous['epoch'], 'transfer source/epoch stale')
            need(following['cpu'] == dest and epoch < following['epoch'], 'transfer does not precede destination witness')
            need(previous['_line'] < i < following['_line'], 'transfer line outside witness interval')
            request = pending_defer.pop(f['pid'], None)
            if request is not None:
                need(request == (epoch, dest), 'defer does not match next transfer')
            task['transfers'].append({**f, '_line': i})
            transfers.append(f)
        elif line.startswith('SMP QUEUE CANCEL '):
            f = fields(line)
            pid = f['pid']
            if pid in task_key_by_pid and task_history[task_key_by_pid[pid]]['role'] in range(162, 166):
                need(pid in pending_defer, 'composition cancel without a pending defer')
                request_epoch, request_to = pending_defer.pop(pid)
                task = task_history[task_key_by_pid[pid]]
                role = task['role']
                expected_stop = int(role == 165)
                need(f['epoch'] == request_epoch and f['stop'] == expected_stop
                     and f['departed'] == 1 and request_to == 0,
                     'composition canceled defer identity/stop/destination mismatch')
                latest = max((w for w in task['witnesses'] if w['_line'] < i),
                             key=lambda w: w['_line'])
                need(latest['cpu'] > 0 and request_to != latest['cpu'],
                     'composition cancellation source/destination mismatch')
                canceled_composition_defers.setdefault(pid, []).append(
                    {'epoch': request_epoch, 'to': request_to, 'stop': f['stop'], '_line': i})
    need(not pending_defer, 'unconsumed queue defer')
    need(len(transfers) == 16 * cpus + 32 + 4 * (cpus - 1), 'transfer total')
    need(sum(f['steal'] for f in transfers) == 16, 'idle steal total')
    for key, task in task_history.items():
        role, ws, ts = task['role'], task['witnesses'], task['transfers']
        if role == 160:
            need(len(ts) == cpus, f'migrant transfer count {key}')
            expected = [(stage - 1, stage % cpus, 0) for stage in range(1, cpus + 1)]
            actual = [(t['from'], t['to'], t['steal']) for t in ts]
            need(actual == expected, f'migrant directed ring route {key}')
            counts = [w['preempts'] for w in ws]
            need(all(b > a for a, b in zip(counts, counts[1:])),
                 f'migrant timer counts not increasing {key}')
            records = [proof for pkey, proof in preempt_keys.items()
                       if pkey[:3] == (key[0], key[1], role)]
            need(len(records) == 1 and records[0]['fields']['cpu'] == 0,
                 f'migrant first timer identity/CPU {key}')
            first_positive = next(w for w in ws if w['preempts'] > 0)
            need(records[0]['line'] < ts[0]['_line']
                 and records[0]['line'] < first_positive['_line'],
                 f'migrant first timer after transfer/witness {key}')
        elif role == 161:
            need(len(ts) == 2, f'stealer transfer count {key}')
            need(ts[0]['from'] == 0 and 0 < ts[0]['to'] < cpus and ts[0]['steal'] == 1,
                 f'stealer did not move once from BSP to an AP {key}')
            need((ts[1]['from'], ts[1]['to'], ts[1]['steal']) == (ts[0]['to'], 0, 0),
                 f'stealer return route {key}')
        else:
            need(len(ts) == 1 and ts[0]['from'] == 0 and ts[0]['to'] == ws[1]['cpu']
                 and ts[0]['steal'] == 0, f'composition admission route {key}')
            canceled = canceled_composition_defers.get(key[0], [])
            if role in (162, 165):
                need(len(canceled) == 1 and canceled[0]['to'] == 0
                     and canceled[0]['stop'] == int(role == 165),
                     f'composition pending return cancellation {key}')
            else:
                need(not canceled, f'unexpected composition cancellation {key}')
            if role == 162:
                rkey = (key[0], key[1], role)
                need(block_by_pid[rkey][0] < canceled[0]['_line']
                     < refuse_by_pid[rkey][0]
                     < ws[2]['_line'],
                     f'blocked-move refusal is not after cancellation/before wake {key}')
            elif role == 165:
                rkey = (key[0], key[1], role)
                depart = depart_by_pid[rkey]
                terminal = terminal_by_pid[rkey]
                need(canceled[0]['epoch'] == depart[1]['epoch']
                     and depart[0] < canceled[0]['_line'] < terminal[0],
                     f'migrated-stop cancellation does not bind stop departure token {key}')

    # One stop/reclaim history for each of the 16 victims assigned to each CPU.
    seq = 0
    lifecycles = {}
    for line_index, line in enumerate(lines):
        m = re.fullmatch(r'SMP USER (TRAP|REQUEST|OBSERVE|DEPART|ACK) seq=(\d+) cpu=(\d+) slot=(\d+) pid=(\d+) epoch=(\d+)', line)
        if m:
            label, raw_seq, cpu, slot, pid, epoch = m.groups()
            seq += 1
            need(int(raw_seq) == seq, 'global USER sequence gap/reorder, including TRAP')
            if label != 'TRAP':
                lifecycles.setdefault((int(cpu), int(slot), int(pid), int(epoch)), []).append(
                    {'label': label, 'line': line_index})
    reclaim_lines = [line for line in lines if line.startswith('SMP USER RECLAIM ')]
    reclaims = {}
    for line in reclaim_lines:
        f = fields(line)
        key = (f['cpu'], f['slot'], f['pid'], f['epoch'])
        need(key not in reclaims, 'duplicate stop reclaim')
        reclaims[key] = {'line': lines.index(line), 'fields': f}
    need(len(lifecycles) == 16 * cpus + cpus - 1
         and len(reclaims) == 16 * cpus + cpus - 1,
         'stop/reclaim history cardinality')
    stop_pids_by_cpu = {cpu: set() for cpu in range(cpus)}
    for key, history in lifecycles.items():
        cpu, slot, pid, epoch = key
        need(cpu < cpus and epoch > 0, 'stop CPU/epoch outside case')
        need([event['label'] for event in history] == ['REQUEST', 'OBSERVE', 'DEPART', 'ACK'],
             f'stop order {key}')
        need(key in reclaims, f'stop has no matching reclaim {key}')
        need(reclaims[key]['line'] > history[-1]['line'], f'reclaim precedes ACK {key}')
        need(pid not in stop_pids_by_cpu[cpu], f'victim stopped twice on CPU {cpu}')
        stop_pids_by_cpu[cpu].add(pid)
        comp_stop = next((r for r in comp_departs if r[1]['pid'] == pid
                          and r[1]['role'] == 165), None)
        if comp_stop is not None:
            f = comp_stop[1]
            depart_event = next(event for event in history if event['label'] == 'DEPART')
            ack_event = next(event for event in history if event['label'] == 'ACK')
            terminal_event = terminal_by_pid[(f['pid'], f['generation'], f['role'])]
            need(f['cpu'] == cpu and f['epoch'] == epoch
                 and depart_event['line'] < ack_event['line'] < comp_stop[0]
                 < terminal_event[0] < reclaims[key]['line'],
                 f'composition stop departure/lifecycle mismatch {key}')
        else:
            victim_role = 144 + cpu
            victim_preempts = [proof for pkey, proof in preempt_keys.items()
                               if pkey[0] == pid and pkey[2] == victim_role and pkey[3] == cpu]
            need(len(victim_preempts) == 1 and victim_preempts[0]['line'] < history[0]['line'],
                 f'victim lacks an earlier saved timer frame {key}')
    for cpu, pids in stop_pids_by_cpu.items():
        expected_count = 16 + int(cpu > 0)
        need(len(pids) == expected_count, f'fixed/composition victims missing on CPU {cpu}')

    stop_lines = [line for line in lines if line.startswith('SMP NWAY STOP CPU ')]
    need(len(stop_lines) == cpus, 'STOP CPU record count')
    stop_cpu_records = {}
    for line in stop_lines:
        f = fields(line)
        expected_stops = 16 + int(f['cpu'] > 0)
        need(f['stops'] == expected_stops and f['cpu'] not in stop_cpu_records,
             'STOP CPU count/duplicate')
        stop_cpu_records[f['cpu']] = f['stops']
    need(set(stop_cpu_records) == set(range(cpus)), 'STOP CPU coverage incomplete')

    # Role 120 is PID 1 in this standalone boot; victims/faults terminate by
    # kill/fault and all completed child actors/helper report status 7.
    exits = {}
    for line in lines:
        if line.startswith('USER EXIT '):
            f = fields(line)
            need(f['pid'] not in exits, 'duplicate USER EXIT')
            exits[f['pid']] = f['status']
    normal_actor_pids = {key[0] for key in users if key[2] not in (163, 165)}
    all_witness_pids = {key[0] for key in users}
    killed_actor_pids = {key[0] for key in users if key[2] == 165}
    need(all(exits.get(pid) == 7 for pid in normal_actor_pids), 'normal actor exit status mismatch')
    need(not any(pid in exits for pid in fault_pids | compose_fault_pids | killed_actor_pids),
         'fault/killed actor also exited normally')
    need({key[0] for key in users if key[2] == 163} == compose_fault_pids,
         'composition fault actor identity mismatch')
    victim_pids = {key[2] for key in lifecycles}
    need(len(victim_pids) == 16 * cpus + cpus - 1,
         'fixed/composition victim PID reused across CPU histories')
    helper_pids={pid for pid,status in exits.items() if status==7}-normal_actor_pids
    fixed_victim_pids = victim_pids - killed_actor_pids
    need((victim_pids & all_witness_pids) == killed_actor_pids,
         'only migrated-stop actors may also appear in witness identities')
    need(not (fixed_victim_pids & (fault_pids | all_witness_pids | helper_pids | {1}))
         and not (victim_pids & (fault_pids | helper_pids | {1})),
         'victim/outcome identity groups overlap')
    need(not(fault_pids & (normal_actor_pids | helper_pids | {1})), 'fault/outcome identity groups overlap')
    need(not any(pid in exits for pid in victim_pids), 'killed victim also exited normally')
    exit7_pids = {pid for pid, status in exits.items() if status == 7}
    need(len(exit7_pids) == 3 * cpus + 33 + 2 * (cpus - 1)
         and len(exit7_pids - normal_actor_pids) == 1,
         'helper/actor exit-7 total or unique helper identity')
    zeros = {pid for pid, status in exits.items() if status == 0}
    need(zeros == {1}, 'PID-1 root status-0 completion')

    cpu_lines = [line for line in lines if line.startswith('SMP NWAY CPU ')]
    need(len(cpu_lines) == cpus, 'per-CPU accounting record count')
    cpu_records = {}
    for line in cpu_lines:
        f = fields(line)
        need(f['cpu'] not in cpu_records and f['pipes'] == f['blocks'] == f['faults'] == 1,
             'per-CPU pipe/block/fault accounting mismatch')
        cpu_records[f['cpu']] = f
    need(set(cpu_records) == set(range(cpus)), 'per-CPU accounting coverage incomplete')
    quiescence=[fields(line) for line in lines if line.startswith('SMP NWAY QUIESCENCE ')]
    need(quiescence==[{'cpus':cpus,'idle-mask':((1<<cpus)-1)&~1,'pending':0,'contexts':0,'roots':0}], 'machine quiescence does not fence every admitted CPU')
    starts = [fields(line) for line in lines if line.startswith('SMP TIMER START ')]
    need(len(starts) == cpus - 1 and {t['cpu'] for t in starts} == set(range(1, cpus)),
         'AP timer calibration coverage missing/duplicate')
    for t in starts:
        span = t['tick-b'] - t['tick-a']
        elapsed = t['count-a'] - t['count-b']
        need(span >= 8 and 0 < t['count-b'] < t['count-a'] <= 0xffffffff,
             'invalid AP timer calibration endpoints')
        need(t['vector'] == 224 and t['divide'] == 16 and t['quantum-ticks'] == 8
             and 0 < t['initial'] == elapsed * 8 // span <= 0xffffffff,
             'AP timer count differs from paired calibration')
    timers=[fields(line) for line in lines if line.startswith('SMP TIMER SUMMARY ')]
    need(len(timers)==cpus-1 and {t['cpu'] for t in timers}==set(range(1,cpus)), 'per-AP timer summary missing/duplicate')
    need(all(t['irqs']>=t['user-irqs']>0 and t['switches1']>0 for t in timers), 'AP timer/scheduler progress missing')
    if report:
        print(f'SMP N-way oracle OK cpus={cpus} ring=16 steals=16 '
              f'composition={4*(cpus-1)} stops={16*cpus+cpus-1}')


def check(serial, placement, report=False):
    lines = Path(serial).read_text().splitlines()
    proofs = [line for line in lines if line.startswith('SMP NWAY PROOF ')]
    need(len(proofs) == 1, 'cannot determine selected CPU count')
    cpus = fields(proofs[0]).get('cpus')
    need(cpus in (2, 4, 6), 'unsupported N-way proof')
    topology(placement, cpus)
    check_lines(lines, cpus, report)


def require_reject(name, lines, mutate, cpus):
    changed = mutate(lines[:])
    need(changed != lines, f'negative fixture did not change: {name}')
    try:
        check_lines(changed, cpus)
    except (AssertionError, KeyError, ValueError, StopIteration):
        return
    raise AssertionError(f'accepted negative control: {name}')


def negatives(lines, cpus):
    def remove_cpu(rows):
        i = next(i for i, x in enumerate(rows)
                 if x.startswith('SMP NWAY CPU ') and fields(x)['cpu'] == cpus - 1)
        rows.pop(i)
        return rows

    def duplicate_cpu(rows):
        indices = [i for i, x in enumerate(rows) if x.startswith('SMP NWAY CPU ')]
        rows[indices[1]] = rows[indices[0]]
        return rows

    def duplicate_generation(rows):
        indices = [i for i, x in enumerate(rows) if x.startswith('SMP QUEUE TRANSFER ')]
        first = fields(rows[indices[0]])
        other = next(i for i in indices[1:]
                     if fields(rows[i])['pid'] != first['pid'])
        rows[other] = re.sub(r'generation=\d+', f'generation={first["generation"]}', rows[other], count=1)
        return rows

    def transfer_before_witness(rows):
        i = next(i for i, x in enumerate(rows) if x.startswith('SMP QUEUE TRANSFER '))
        f = fields(rows[i])
        u = next(j for j, x in enumerate(rows) if x.startswith('SMP NWAY USER ')
                 and fields(x)['pid'] == f['pid'] and fields(x)['generation'] == f['generation']
                 and fields(x)['stage'] == 0)
        line = rows.pop(i)
        rows.insert(u, line)
        return rows

    def stale_witness_epoch(rows):
        i = next(i for i, x in enumerate(rows) if x.startswith('SMP QUEUE TRANSFER '))
        t = fields(rows[i])
        j = next(j for j, x in enumerate(rows) if x.startswith('SMP NWAY USER ')
                 and fields(x)['pid'] == t['pid'] and fields(x)['generation'] == t['generation']
                 and fields(x)['stage'] == 1)
        rows[j] = re.sub(r'epoch=\d+', f'epoch={t["epoch"]}', rows[j], count=1)
        return rows

    def stop_reorder(rows):
        d = next(i for i, x in enumerate(rows) if x.startswith('SMP USER DEPART '))
        a = next(i for i, x in enumerate(rows) if x.startswith('SMP USER ACK '))
        rows[d], rows[a] = rows[a], rows[d]
        return rows

    def bad_fault(rows):
        i = next(i for i, x in enumerate(rows) if x.startswith('SMP NWAY FAULT '))
        rows[i] = re.sub(r'vector=14', 'vector=13', rows[i], count=1)
        return rows

    def no_quiescence(rows):
        i = next(i for i, x in enumerate(rows)
                 if x.startswith('SMP QUEUE QUIESCENT '))
        rows.pop(i)
        return rows

    def crosswired_worker_pid(rows):
        indices = [i for i, x in enumerate(rows)
                   if x.startswith('SMP NWAY PREEMPT ') and 128 <= fields(x)['role'] < 128 + 2 * cpus]
        first = fields(rows[indices[0]])
        other = next(fields(rows[i]) for i in indices[1:]
                     if fields(rows[i])['pid'] != first['pid'])
        rows[indices[0]] = re.sub(r'pid=\d+', f'pid={other["pid"]}', rows[indices[0]], count=1)
        return rows

    def stale_stop_epoch(rows):
        i = next(i for i, x in enumerate(rows) if x.startswith('SMP USER RECLAIM '))
        f = fields(rows[i])
        rows[i] = re.sub(r'epoch=\d+', f'epoch={f["epoch"] + 1}', rows[i], count=1)
        return rows

    def reclaim_before_ack(rows):
        ri = next(i for i, x in enumerate(rows) if x.startswith('SMP USER RECLAIM '))
        r = fields(rows[ri])
        ai = next(i for i, x in enumerate(rows)
                  if x.startswith('SMP USER ACK ') and
                  all(fields(x)[k] == r[k] for k in ('cpu', 'slot', 'pid', 'epoch')))
        rows[ri], rows[ai] = rows[ai], rows[ri]
        return rows

    def reused_victim(rows):
        victims=[fields(line) for line in rows if line.startswith('SMP NWAY PREEMPT ') and 144<=fields(line)['role']<144+cpus]
        first=victims[0]
        other=next(v for v in victims if v['cpu']!=first['cpu'])
        return [re.sub(r'(?<!\w)pid='+str(other['pid'])+r'(?!\d)', 'pid='+str(first['pid']),line) for line in rows]

    def noncontiguous_apic(rows):
        i=next(i for i,line in enumerate(rows) if line.startswith('SMP TOPOLOGY ') and fields(line)['cpu']==cpus-1)
        rows[i]=re.sub(r'apic=\d+','apic=99',rows[i],count=1)
        return rows

    def late_worker_preempt(rows):
        i=next(i for i,line in enumerate(rows) if line.startswith('SMP NWAY PREEMPT ') and 128<=fields(line)['role']<128+2*cpus)
        pid=fields(rows[i])['pid']
        event=rows.pop(i)
        witness=next(i for i,line in enumerate(rows) if line.startswith('SMP NWAY USER ') and fields(line)['pid']==pid)
        rows.insert(witness+1,event)
        return rows

    def ignore_last_idle(rows):
        i=next(i for i,line in enumerate(rows) if line.startswith('SMP NWAY QUIESCENCE '))
        mask=(((1<<cpus)-1)&~1)&~(1<<(cpus-1))
        rows[i]=re.sub(r'idle-mask=\d+','idle-mask='+str(mask),rows[i],count=1)
        return rows

    def missing_last_cpu_overlap(rows):
        i = next(i for i, line in enumerate(rows)
                 if line.startswith('SMP NWAY OVERLAP ') and fields(line)['cpu'] == cpus - 1)
        rows.pop(i)
        return rows

    def changed_overlap_epoch(rows):
        i = next(i for i, line in enumerate(rows) if line.startswith('SMP NWAY OVERLAP '))
        f = fields(rows[i])
        rows[i] = re.sub(r'after=\d+', f'after={f["after"] + 1}', rows[i], count=1)
        return rows

    def partial_overlap_mask(rows):
        i = next(i for i, line in enumerate(rows) if line.startswith('SMP NWAY OVERLAP '))
        rows[i] = re.sub(r'mask=\d+', f'mask={(1 << cpus) - 2}', rows[i], count=1)
        return rows

    def zero_cpu_overlap_progress(rows):
        i = next(i for i, line in enumerate(rows) if line.startswith('SMP NWAY OVERLAP '))
        f = fields(rows[i])
        rows[i] = re.sub(r'last=\d+', f'last={f["first"]}', rows[i], count=1)
        return rows

    def migrant_rows(rows):
        i = next(i for i, line in enumerate(rows)
                 if line.startswith('SMP NWAY USER ') and fields(line)['role'] == 160)
        f = fields(rows[i])
        return [j for j, line in enumerate(rows)
                if line.startswith('SMP NWAY USER ')
                and fields(line)['pid'] == f['pid'] and fields(line)['generation'] == f['generation']]

    def migrant_zero(rows):
        for i in migrant_rows(rows):
            rows[i] = re.sub(r'preempts=\d+', 'preempts=0', rows[i], count=1)
        return rows

    def migrant_equal(rows):
        indices = migrant_rows(rows)
        count = fields(rows[indices[0]])['preempts']
        rows[indices[1]] = re.sub(r'preempts=\d+', f'preempts={count}', rows[indices[1]], count=1)
        return rows

    def migrant_decrease(rows):
        indices = migrant_rows(rows)
        count = fields(rows[indices[1]])['preempts'] - 1
        rows[indices[2]] = re.sub(r'preempts=\d+', f'preempts={count}', rows[indices[2]], count=1)
        return rows

    def migrant_preempt_index(rows):
        f = fields(rows[migrant_rows(rows)[0]])
        return next(i for i, line in enumerate(rows)
                    if line.startswith('SMP NWAY PREEMPT ') and fields(line)['pid'] == f['pid']
                    and fields(line)['generation'] == f['generation'] and fields(line)['role'] == 160)

    def migrant_missing(rows):
        rows.pop(migrant_preempt_index(rows))
        return rows

    def migrant_late(rows):
        i = migrant_preempt_index(rows)
        line = rows.pop(i)
        f = fields(line)
        after = next(i for i, row in enumerate(rows)
                     if row.startswith('SMP QUEUE TRANSFER ') and fields(row)['pid'] == f['pid'])
        rows.insert(after + 1, line)
        return rows

    def migrant_wrong_cpu(rows):
        i = migrant_preempt_index(rows)
        rows[i] = re.sub(r'cpu=\d+', 'cpu=1', rows[i], count=1)
        return rows

    def migrant_wrong_generation(rows):
        i = migrant_preempt_index(rows)
        rows[i] = re.sub(r'generation=\d+', 'generation=999999', rows[i], count=1)
        return rows

    def migrant_duplicate(rows):
        i = migrant_preempt_index(rows)
        rows.insert(i + 1, re.sub(r'cpu=\d+', 'cpu=1', rows[i], count=1))
        return rows

    def missing_calibration(rows):
        rows.pop(next(i for i, row in enumerate(rows) if row.startswith('SMP TIMER START ')))
        return rows

    def changed_calibration(rows):
        i = next(i for i, row in enumerate(rows) if row.startswith('SMP TIMER START '))
        value = fields(rows[i])['initial'] + 1
        rows[i] = re.sub(r'initial=\d+', f'initial={value}', rows[i], count=1)
        return rows

    def wrong_quantum(rows):
        i = next(i for i, row in enumerate(rows) if row.startswith('SMP TIMER START '))
        rows[i] = re.sub(r'quantum-ticks=\d+', 'quantum-ticks=2', rows[i], count=1)
        return rows

    def reversed_calibration(rows):
        i = next(i for i, row in enumerate(rows) if row.startswith('SMP TIMER START '))
        value = fields(rows[i])['count-a']
        rows[i] = re.sub(r'count-b=\d+', f'count-b={value}', rows[i], count=1)
        return rows

    def wrong_composition_terminal_cpu(rows):
        i = next(i for i, row in enumerate(rows)
                 if row.startswith('SMP NWAY COMPOSE TERMINAL ')
                 and fields(row)['role'] == 165)
        f = fields(rows[i])
        rows[i] = re.sub(r'cpu=\d+', f'cpu={0 if f["cpu"] != 0 else 1}', rows[i], count=1)
        return rows

    def missing_composition_terminal(rows):
        i = next(i for i, row in enumerate(rows)
                 if row.startswith('SMP NWAY COMPOSE TERMINAL ')
                 and fields(row)['role'] == 163)
        rows.pop(i)
        return rows

    def wrong_composition_refusal_epoch(rows):
        i = next(i for i, row in enumerate(rows)
                 if row.startswith('SMP NWAY COMPOSE REFUSE '))
        f = fields(rows[i])
        rows[i] = re.sub(r'epoch=\d+', f'epoch={f["epoch"] + 1}', rows[i], count=1)
        return rows

    def wrong_composition_cancel_kind(rows):
        pid = fields(next(row for row in rows
                          if row.startswith('SMP NWAY COMPOSE REFUSE ')))['pid']
        i = next(i for i, row in enumerate(rows)
                 if row.startswith('SMP QUEUE CANCEL ') and fields(row)['pid'] == pid)
        rows[i] = re.sub(r'stop=0', 'stop=1', rows[i], count=1)
        return rows

    def composition_transfer_wrong_destination(rows):
        witness = next(fields(row) for row in rows
                       if row.startswith('SMP NWAY USER ') and fields(row)['role'] == 162
                       and fields(row)['stage'] == 0)
        i = next(i for i, row in enumerate(rows)
                 if row.startswith('SMP QUEUE TRANSFER ')
                 and fields(row)['pid'] == witness['pid'])
        rows[i] = re.sub(r'to=\d+', 'to=0', rows[i], count=1)
        return rows

    def composition_target_timer_after_defer(rows):
        timer_i = next(i for i, row in enumerate(rows)
                       if row.startswith('SMP NWAY COMPOSE TIMER ')
                       and fields(row)['role'] == 165 and fields(row)['cpu'] > 0)
        pid = fields(rows[timer_i])['pid']
        timer = rows.pop(timer_i)
        defer_i = next(i for i, row in enumerate(rows)
                       if row.startswith('SMP QUEUE DEFER ') and fields(row)['pid'] == pid
                       and fields(row)['to'] == 0)
        rows.insert(defer_i + 1, timer)
        return rows

    def composition_block_before_ap_witness(rows):
        block_i = next(i for i, row in enumerate(rows)
                       if row.startswith('SMP NWAY COMPOSE BLOCK '))
        pid = fields(rows[block_i])['pid']
        witness_i = next(i for i, row in enumerate(rows)
                         if row.startswith('SMP NWAY USER ')
                         and fields(row)['pid'] == pid and fields(row)['role'] == 162
                         and fields(row)['stage'] == 1)
        block = rows.pop(block_i)
        witness_i = next(i for i, row in enumerate(rows)
                         if row.startswith('SMP NWAY USER ')
                         and fields(row)['pid'] == pid and fields(row)['role'] == 162
                         and fields(row)['stage'] == 1)
        rows.insert(witness_i, block)
        return rows

    def composition_wake_epoch_not_advanced(rows):
        block = fields(next(row for row in rows
                            if row.startswith('SMP NWAY COMPOSE BLOCK ')))
        i = next(i for i, row in enumerate(rows)
                 if row.startswith('SMP NWAY USER ') and fields(row)['role'] == 162
                 and fields(row)['pid'] == block['pid'] and fields(row)['stage'] == 2)
        rows[i] = re.sub(r'epoch=\d+', f'epoch={block["epoch"]}', rows[i], count=1)
        return rows

    def composition_stop_cancel_epoch_differs_from_latch(rows):
        departure = fields(next(row for row in rows
                                if row.startswith('SMP NWAY COMPOSE DEPART ')
                                and fields(row)['role'] == 165))
        pid = departure['pid']
        changed_epoch = departure['epoch'] + 1
        for i, row in enumerate(rows):
            if ((row.startswith('SMP QUEUE DEFER ') or row.startswith('SMP QUEUE CANCEL '))
                    and fields(row)['pid'] == pid and fields(row).get('to', 0) == 0):
                rows[i] = re.sub(r'epoch=\d+', f'epoch={changed_epoch}', row, count=1)
        return rows

    def composition_stop_cancel_before_departure_latch(rows):
        pid = fields(next(row for row in rows
                          if row.startswith('SMP NWAY COMPOSE DEPART ')
                          and fields(row)['role'] == 165))['pid']
        cancel_i = next(i for i, row in enumerate(rows)
                        if row.startswith('SMP QUEUE CANCEL ') and fields(row)['pid'] == pid)
        cancel = rows.pop(cancel_i)
        depart_i = next(i for i, row in enumerate(rows)
                        if row.startswith('SMP NWAY COMPOSE DEPART ')
                        and fields(row)['pid'] == pid)
        rows.insert(depart_i, cancel)
        return rows

    controls = {
        'wrong N-way quantum': wrong_quantum,
        'missing AP calibration': missing_calibration,
        'changed AP calibrated count': changed_calibration,
        'empty AP calibration interval': reversed_calibration,
        'migrant zero timer counts': migrant_zero,
        'migrant repeated timer counts': migrant_equal,
        'migrant decreasing timer counts': migrant_decrease,
        'migrant missing first timer': migrant_missing,
        'migrant late first timer': migrant_late,
        'migrant wrong first timer CPU': migrant_wrong_cpu,
        'migrant wrong first timer generation': migrant_wrong_generation,
        'migrant duplicate first timer': migrant_duplicate,
        'victim PID reused across CPUs': reused_victim,
        'noncontiguous APIC': noncontiguous_apic,
        'worker preempt after witness': late_worker_preempt,
        'quiescence ignores last CPU': ignore_last_idle,
        'missing CPU record': remove_cpu,
        'duplicated CPU record': duplicate_cpu,
        'duplicate generation for another pid': duplicate_generation,
        'transfer before initial witness': transfer_before_witness,
        'stale destination witness epoch': stale_witness_epoch,
        'stop ACK before departure': stop_reorder,
        'wrong page-fault vector': bad_fault,
        'missing quiescence': no_quiescence,
        'crosswired worker pid': crosswired_worker_pid,
        'stale stop epoch at reclaim': stale_stop_epoch,
        'reclaim before acknowledgement': reclaim_before_ack,
        'missing last CPU overlap sample': missing_last_cpu_overlap,
        'changed overlap epoch': changed_overlap_epoch,
        'partial overlap CPU mask': partial_overlap_mask,
        'zero CPU overlap progress': zero_cpu_overlap_progress,
        'composition terminal record uses BSP reaper CPU': wrong_composition_terminal_cpu,
        'missing composition terminal latch receipt': missing_composition_terminal,
        'composition refusal epoch differs from blocked frame': wrong_composition_refusal_epoch,
        'composition pending cancellation has wrong stop class': wrong_composition_cancel_kind,
        'composition admission targets wrong CPU': composition_transfer_wrong_destination,
        'composition target timer follows stop defer': composition_target_timer_after_defer,
        'composition block precedes target execution witness': composition_block_before_ap_witness,
        'composition wake does not advance claim epoch': composition_wake_epoch_not_advanced,
        'composition stop cancel epoch differs from departure claim': composition_stop_cancel_epoch_differs_from_latch,
        'composition stop cancel precedes departure latch': composition_stop_cancel_before_departure_latch,
    }
    for name, mutate in controls.items():
        require_reject(name, lines, mutate, cpus)
    return len(controls)


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: check-smp-nway.py SERIAL_LOG VCPU_PLACEMENT_JSON')
    check(sys.argv[1], sys.argv[2], report=True)
    cpus = fields(next(line for line in Path(sys.argv[1]).read_text().splitlines()
                       if line.startswith('SMP NWAY PROOF ')))['cpus']
    count = negatives(Path(sys.argv[1]).read_text().splitlines(), cpus)
    print(f'SMP N-way oracle rejected {count} deterministic negative controls')


if __name__ == '__main__':
    main()
