#!/usr/bin/env python3
"""Check a closed SMP FPU migration qualification receipt.

Draft host oracle for the prospective `smp-fpu-migration-test` boot. The
receipt schema is intentionally closed: each line described below has one
record and each identity has a complete, ordered history.
"""
import re
import sys
import tempfile
from pathlib import Path


def attrs(line):
    return {k: v for k, v in re.findall(r'([\w-]+)=([^\s]+)', line)}


def number(value):
    if value.lower().startswith('0x'):
        return int(value, 16)
    if re.search(r'[a-f]', value, re.I):
        return int(value, 16)
    return int(value, 10)


def must(ok, message):
    if not ok:
        raise AssertionError(message)


def check_lines(lines, report=False):
    must(lines.count('SMP QUEUE PROOF transfers=32 steals=0 before=16 remote=16 returned=16') == 1,
         'queue proof/count mismatch')
    must(lines.count('SMP QUEUE QUIESCENT registered=0 queued=0 running=0') == 1,
         'queue quiescence missing/duplicate')
    must(lines.count('ABSD BOOT OK') == 1, 'successful boot record missing/duplicate')
    must(not any(re.search(r'PANIC|KERNEL FAULT|FAILED', line) for line in lines),
         'failure record present')

    # Queue USER witnesses are authoritative placement/epoch claims. A change
    # of CPU is legal only after the matching departed transfer, and the next
    # witness must be later than its transfer epoch.
    tasks = {}
    transfers = []
    defers = []
    pending_defer = {}
    for line_index, line in enumerate(lines):
        if line.startswith('SMP QUEUE USER '):
            f = attrs(line)
            pid, generation = number(f['pid']), number(f['generation'])
            cpu, stage, epoch = number(f['cpu']), number(f['stage']), number(f['epoch'])
            must(pid > 0 and generation > 0 and f.get('cpl') == '3', 'bad queue user identity/CPL')
            must(cpu in (0, 1) and stage in (0, 1, 2) and epoch > 0, 'bad queue witness')
            key = (pid, generation)
            task = tasks.setdefault(key, {'witnesses': [], 'transfers': [], 'cpu': None, 'pending': None})
            ws = task['witnesses']
            if not ws:
                must(stage == 0 and cpu == 0, 'initial witness must be CPU0 stage0')
                task['cpu'] = cpu
            else:
                prev = ws[-1]
                must(stage == prev['stage'] + 1 and epoch > prev['epoch'], 'witness stage/epoch order')
                tr = task['pending']
                must(tr is not None, 'placement changed without transfer')
                must(cpu == tr['to'] and epoch > tr['epoch'], 'destination witness does not follow transfer')
                task['pending'] = None
                task['cpu'] = cpu
            ws.append({'stage': stage, 'cpu': cpu, 'epoch': epoch, 'line_index': line_index})
        elif line.startswith('SMP QUEUE DEFER '):
            f = attrs(line)
            pid, epoch, to = number(f['pid']), number(f['epoch']), number(f['to'])
            key = next((k for k in tasks if k[0] == pid), None)
            must(key is not None and to in (0, 1), 'defer for unknown task/destination')
            task = tasks[key]
            must(pid not in pending_defer, 'duplicate outstanding defer')
            must(epoch >= task['witnesses'][-1]['epoch'] and to != task['cpu'], 'stale/invalid defer')
            pending_defer[pid] = {'epoch': epoch, 'to': to}
            defers.append((pid, epoch, to))
        elif line.startswith('SMP QUEUE TRANSFER '):
            f = attrs(line)
            must(number(f['n']) == len(transfers) + 1, 'transfer sequence gap/reorder')
            pid, generation = number(f['pid']), number(f['generation'])
            key = (pid, generation)
            must(key in tasks, 'transfer before initial witness or stale generation')
            task = tasks[key]
            source, dest, epoch = number(f['from']), number(f['to']), number(f['epoch'])
            must(f.get('saved') == '1' and f.get('departed') == '1', 'transfer lacks save/depart proof')
            must(source in (0, 1) and dest in (0, 1) and source != dest, 'invalid transfer direction')
            must(task['pending'] is None and task['cpu'] == source, 'transfer source/current placement mismatch')
            must(epoch >= task['witnesses'][-1]['epoch'], 'transfer predates latest witness')
            must(len(task['witnesses']) in (1, 2), 'transfer after final witness')
            # The initial source-side move is commonly ready at once because
            # its actor timer-departed while the controller ran. A return can
            # also be immediate. When a DEFER was emitted, however, it must
            # be consumed by the very next matching transfer.
            request = pending_defer.pop(pid, None)
            if request is not None:
                must(request == {'epoch': epoch, 'to': dest},
                     'transfer/defer epoch or destination mismatch')
            tr = {'from': source, 'to': dest, 'epoch': epoch, 'pid': pid,
                  'generation': generation, 'line_index': line_index}
            task['pending'] = tr
            task['transfers'].append(tr)
            transfers.append(tr)

    must(len(tasks) == 16 and len({pid for pid, _ in tasks}) == 16,
         'migrant task census / duplicate PID')
    must(not pending_defer and 0 <= len(defers) <= 32 and len(transfers) == 32,
         'defer/transfer cardinality or unconsumed defer')
    for (pid, gen), task in tasks.items():
        ws, ts = task['witnesses'], task['transfers']
        must([w['stage'] for w in ws] == [0, 1, 2], f'incomplete migrant witness history {(pid, gen)}')
        must([w['cpu'] for w in ws] == [0, 1, 0], f'migrant CPU sequence {(pid, gen)}')
        must([(t['from'], t['to']) for t in ts] == [(0, 1), (1, 0)], f'migrant transfer sequence {(pid, gen)}')
        must(ws[-1]['epoch'] > ts[-1]['epoch'], f'late/absent return witness {(pid, gen)}')

    # Exactly 16 actors retain their configured SSE state through both moves;
    # three fresh actors prove MXCSR/FCW defaults only; one peer verifies its
    # distinct state while the CPU0 migratables churn.
    fpurecs = []
    for line_index, line in enumerate(lines):
        if line.startswith('SMP FPU USER '):
            f = attrs(line)
            record = {k: number(v) for k, v in f.items()}
            record['_line_index'] = line_index
            fpurecs.append(record)
    must(len(fpurecs) == 36 and all(f.get('stage') in (1, 2, 3, 4) for f in fpurecs),
         'extra or invalid FPU actor record')
    stages = {s: [f for f in fpurecs if f.get('stage') == s] for s in (1, 2, 3, 4)}
    must([len(stages[s]) for s in (1, 2, 3, 4)] == [16, 16, 3, 1], 'FPU stage census')
    migrant_ids = set(tasks)
    for stage in (1, 2):
        stage_ids = [(f['pid'], f['generation']) for f in stages[stage]]
        must(len(set(stage_ids)) == 16 and set(stage_ids) == migrant_ids,
             f'FPU stage{stage} identity census differs from queue migrants')
        for f in stages[stage]:
            key = (f['pid'], f['generation'])
            task = tasks[key]
            transfer = task['transfers'][stage - 1]
            witness = task['witnesses'][stage]
            must(transfer['line_index'] < f['_line_index'] < witness['line_index'],
                 f'FPU stage{stage} record outside transfer→FPU→placement order for {key}')
    fresh_ids = [(f['pid'], f['generation']) for f in stages[3]]
    peer_ids = [(f['pid'], f['generation']) for f in stages[4]]
    must(len(set(fresh_ids)) == 3 and len({pid for pid, _ in fresh_ids}) == 3
         and all(key not in migrant_ids and key[0] not in {pid for pid, _ in migrant_ids}
                 for key in fresh_ids),
         'fresh-control identities duplicate or alias migrants')
    must(len(peer_ids) == 1 and peer_ids[0] not in migrant_ids
         and peer_ids[0][0] not in {pid for pid, _ in migrant_ids}
         and peer_ids[0] not in fresh_ids
         and peer_ids[0][0] not in {pid for pid, _ in fresh_ids},
         'peer identity aliases another FPU role')
    for stage, cpu in ((1, 1), (2, 0)):
        records = stages[stage]
        must(all(f['cpu'] == cpu and f['cpl'] == 3 for f in records), f'FPU stage{stage} CPU/CPL')
        must(all(f['mxcsr'] == 0x3fa0 and f['fcw'] == 0x077f
                 and f['xmm0'] == 1 and f['xmm7'] == 1 for f in records),
             f'FPU migrant state lost at stage{stage}')
    must(all(f['cpu'] == 1 and f['cpl'] == 3 and f['mxcsr'] == 0x1f80
             and f['fcw'] == 0x037f
             for f in stages[3]), 'fresh task MXCSR/FCW default witness mismatch')
    must(all(f['cpu'] == 1 and f['cpl'] == 3 and f['mxcsr'] == 0x5fa0
             and f['fcw'] == 0x0b7f and f['xmm0'] == 1 and f['xmm7'] == 1
             for f in stages[4]), 'peer FPU state mismatch')

    proof_lines = [line for line in lines if line.startswith('SMP FPU PROOF ')]
    must(len(proof_lines) == 1, 'FPU proof record missing/duplicate')
    proof = {k: number(v) for k, v in attrs(proof_lines[0]).items()}
    must(proof['roundtrips'] == 16 and proof['peers'] == 1 and proof['defaults'] == 3
         and proof['faults'] == 1 and proof['kills'] == 1, 'FPU role proof totals')
    must(proof['preempts0'] >= 16 and proof['preempts1'] >= 16 and proof['peer-preempts'] > 0,
         'FPU migration/peer preemption evidence missing')

    # Per-migrant evidence proves both CPUs interrupted its live assembly
    # sentinel interval; aggregate counts alone could come from one actor.
    preempt_lines = [line for line in lines if line.startswith('SMP FPU PREEMPT ')]
    must(len(preempt_lines) == 32, 'per-task/per-CPU preemption records missing/duplicate')
    seen_preempts = set()
    for line in preempt_lines:
        f = attrs(line)
        key = (number(f['pid']), number(f['generation']), number(f['cpu']))
        must(key[:2] in tasks and key[2] in (0, 1), 'preemption witness for unknown task/CPU')
        must(key not in seen_preempts, 'duplicate per-task preemption witness')
        seen_preempts.add(key)
        must(number(f['count']) >= 1 and f.get('interval') == 'nonvoluntary'
             and f.get('live-asm') == '1', 'preemption did not interrupt live assembly interval')
    must(seen_preempts == {(pid, gen, cpu) for pid, gen in tasks for cpu in (0, 1)},
         'not every migrant was preempted on both CPUs')

    # The #XM peer has one complete CPU1 stop/reclaim transaction. Sequence is
    # contiguous; matching pid/epoch records have the required stop order.
    lifecycle = []
    seq = 0
    for line in lines:
        m = re.fullmatch(r'SMP USER (TRAP|REQUEST|OBSERVE|DEPART|ACK) seq=(\d+) cpu=(\d+) slot=(\d+) pid=(\d+) epoch=(\d+)', line)
        if m:
            kind, n, cpu, slot, pid, epoch = m.groups()
            seq += 1
            must(int(n) == seq, 'stop lifecycle sequence gap/reorder')
            if kind != 'TRAP':
                lifecycle.append((kind, int(cpu), int(slot), int(pid), int(epoch)))
    fault_lines = [line for line in lines if line.startswith('USER FAULT ')]
    must(len(fault_lines) == 1, 'SIMD fault record missing/duplicate')
    fault = {k: number(v) for k, v in attrs(fault_lines[0]).items()}
    must(fault['vector'] == 19 and fault['pid'] > 0, 'wrong SIMD fault vector/identity')
    peer_pid = stages[4][0]['pid']
    fault_pid = fault['pid']
    must(fault_pid != peer_pid and all(fault_pid != pid for pid, _ in migrant_ids)
         and all(fault_pid != pid for pid, _ in fresh_ids),
         'fault role aliases peer/fresh/migrant FPU identity')
    exits = {}
    for line in lines:
        if line.startswith('USER EXIT '):
            f = attrs(line)
            pid, status = number(f['pid']), number(f['status'])
            must(pid not in exits, 'duplicate normal exit record')
            exits[pid] = status
    must(all(exits.get(pid) == 7 for pid, _ in migrant_ids), 'migrant did not exit normally')
    must(all(exits.get(pid) == 7 for pid, _ in fresh_ids), 'fresh control did not exit normally')
    must(peer_pid not in exits and fault_pid not in exits,
         'killed peer or faulted actor also reported normal exit')
    must(not any(e[3] == fault['pid'] for e in lifecycle),
         'ordinary #XM fault incorrectly has a request/ACK stop lifecycle')
    matching = [e for e in lifecycle if e[3] == peer_pid]
    must(len(lifecycle) == 4 and [e[0] for e in matching] ==
         ['REQUEST', 'OBSERVE', 'DEPART', 'ACK'], 'peer stop lifecycle order/cardinality')
    must(all(e[1] == 1 and e[4] > 0 for e in matching), 'fault stop not CPU1/epoch-qualified')
    must(len({e[2] for e in matching}) == 1 and len({e[4] for e in matching}) == 1,
         'fault stop lifecycle identity mismatch')
    key = (matching[0][1], matching[0][2], matching[0][3], matching[0][4])
    reclaim_lines = [line for line in lines if line.startswith('SMP USER RECLAIM ')]
    must(len(reclaim_lines) == 1, 'peer stop reclaim missing/duplicate')
    reclaim = {k: number(v) for k, v in attrs(reclaim_lines[0]).items()}
    must((reclaim['cpu'], reclaim['slot'], reclaim['pid'], reclaim['epoch']) == key,
         'reclaim identity does not match peer stop')
    lifecycle_idxs = []
    for kind in ('REQUEST', 'OBSERVE', 'DEPART', 'ACK'):
        target = next(line for line in lines
                      if line.startswith(f'SMP USER {kind} ')
                      and number(attrs(line)['pid']) == peer_pid
                      and number(attrs(line)['epoch']) == matching[0][4])
        lifecycle_idxs.append(lines.index(target))
    reclaim_idx = lines.index(reclaim_lines[0])
    must(lifecycle_idxs == sorted(lifecycle_idxs) and reclaim_idx > lifecycle_idxs[-1],
         'stop/reclaim record order')

    postfault = [line for line in lines if line.startswith('SMP FPU PEER POSTFAULT ')]
    must(len(postfault) == 1, 'post-fault peer progress witness missing/duplicate')
    post = {k: number(v) for k, v in attrs(postfault[0]).items()}
    must(post['progress'] > 0 and post['controls-checked'] == 1,
         'peer did not progress after #XM / control checks incomplete')
    fault_idx = lines.index(fault_lines[0])
    post_idx = lines.index(postfault[0])
    request_idx = lifecycle_idxs[0]
    must(fault_idx < post_idx < request_idx,
         'post-fault peer witness is not between #XM and peer kill')

    # One explicit terminal record closes workload accounting and process
    # outcomes; tolerate field-order changes but no missing/duplicate counts.
    terminal_lines = [line for line in lines if line.startswith('SMP FPU SUMMARY ')]
    must(len(terminal_lines) == 1, 'FPU terminal record missing/duplicate')
    terminal = {k: number(v) for k, v in attrs(terminal_lines[0]).items()}
    must(terminal.get('terminal') == 0 and terminal.get('cases') == 1
         and terminal.get('faults') == 1 and terminal.get('kills') == 1
         and terminal.get('resources') == 0, 'FPU terminal accounting')
    if report:
        print('SMP FPU migration oracle OK migrants=16 transfers=32 clean=3 peer=1 #XM=1')


def require_reject(name, source, mutate):
    changed = mutate(source)
    must(changed != source, f'negative mutation did not alter receipt: {name}')
    try:
        check_lines(changed.splitlines())
    except (AssertionError, KeyError, ValueError, StopIteration):
        return
    raise AssertionError(f'accepted negative control: {name}')


def first_sub(pattern, replacement, text):
    changed, count = re.subn(pattern, replacement, text, count=1, flags=re.M)
    must(count == 1, f'negative-control target missing: {pattern}')
    return changed


def test_negatives(source):
    controls = {
        'migrant MXCSR': lambda s: first_sub(r'(SMP FPU USER [^\n]*stage=1[^\n]*mxcsr=)([^\s]+)', r'\g<1>0x1f80', s),
        'migrant FCW': lambda s: first_sub(r'(SMP FPU USER [^\n]*stage=2[^\n]*fcw=)([^\s]+)', r'\g<1>0x037f', s),
        'fresh MXCSR default': lambda s: first_sub(r'(SMP FPU USER [^\n]*stage=3[^\n]*mxcsr=)([^\s]+)', r'\g<1>0x3fa0', s),
        'peer XMM flag': lambda s: first_sub(r'(SMP FPU USER [^\n]*stage=4[^\n]*xmm7=)1', r'\g<1>0', s),
        'transfer before departure evidence': lambda s: first_sub(r'(SMP QUEUE TRANSFER [^\n]*departed=)1', r'\g<1>0', s),
        'duplicate migrant witness': lambda s: first_sub(r'^(SMP QUEUE USER [^\n]*stage=1[^\n]*\n)', r'\g<1>\g<1>', s),
        'duplicate valid FPU actor with missing peer migrant': lambda s: duplicate_fpu_actor(s),
        'FPU witness wrong chronology': lambda s: reorder_fpu_and_queue_witness(s),
        'stale generation': lambda s: first_sub(r'(SMP QUEUE TRANSFER [^\n]*generation=)(\d+)',
                                                 lambda m: m.group(1) + str(int(m.group(2)) + 1), s),
        'stale destination witness epoch': lambda s: stale_destination_epoch(s),
        'peer absence': lambda s: remove_first_line(s, r'^SMP FPU USER [^\n]*stage=4'),
        'preemption absent': lambda s: first_sub(r'(SMP FPU PROOF [^\n]*preempts1=)\d+', r'\g<1>0', s),
        'per-task preemption absent': lambda s: remove_first_line(s, r'^SMP FPU PREEMPT '),
        'quiescence absent': lambda s: remove_first_line(s, r'^SMP QUEUE QUIESCENT '),
        'stop ACK before DEPART': lambda s: swap_stop_depart_ack(s),
        'reclaim before ACK': lambda s: swap_reclaim_ack(s),
    }
    with tempfile.TemporaryDirectory(prefix='smp-fpu-migration-oracle-'):
        for name, mutate in controls.items():
            require_reject(name, source, mutate)
    return len(controls)


def remove_first_line(text, pattern):
    changed, count = re.subn(pattern + r'\n?', '', text, count=1, flags=re.M)
    must(count == 1, f'negative-control target missing: {pattern}')
    return changed


def stale_destination_epoch(text):
    lines = text.splitlines()
    transfer = next(attrs(line) for line in lines if line.startswith('SMP QUEUE TRANSFER '))
    pid, generation, epoch = (number(transfer[k]) for k in ('pid', 'generation', 'epoch'))
    for i, line in enumerate(lines):
        if not line.startswith('SMP QUEUE USER '):
            continue
        f = attrs(line)
        if number(f['pid']) == pid and number(f['generation']) == generation and number(f['stage']) == 1:
            changed, count = re.subn(r'(\bepoch=)\d+', rf'\g<1>{epoch}', line, count=1)
            must(count == 1, 'destination witness epoch absent')
            lines[i] = changed
            return '\n'.join(lines) + '\n'
    raise AssertionError('no destination witness for stale-epoch control')


def duplicate_fpu_actor(text):
    lines = text.splitlines()
    indices = [i for i, line in enumerate(lines)
               if line.startswith('SMP FPU USER ') and 'stage=1' in line]
    must(len(indices) >= 2, 'not enough stage1 FPU actors to mutate')
    lines[indices[1]] = lines[indices[0]]
    return '\n'.join(lines) + '\n'


def reorder_fpu_and_queue_witness(text):
    lines = text.splitlines()
    fpu = next((i for i, line in enumerate(lines)
                if line.startswith('SMP FPU USER ') and 'stage=1' in line), None)
    must(fpu is not None, 'stage1 FPU record absent')
    f = attrs(lines[fpu])
    queue = next((i for i, line in enumerate(lines)
                  if line.startswith('SMP QUEUE USER ')
                  and number(attrs(line)['pid']) == number(f['pid'])
                  and number(attrs(line)['generation']) == number(f['generation'])
                  and number(attrs(line)['stage']) == 1), None)
    must(queue is not None, 'corresponding stage1 queue witness absent')
    lines[fpu], lines[queue] = lines[queue], lines[fpu]
    return '\n'.join(lines) + '\n'


def swap_stop_depart_ack(text):
    lines = text.splitlines()
    dep = next(i for i, line in enumerate(lines) if line.startswith('SMP USER DEPART '))
    ack = next(i for i, line in enumerate(lines) if line.startswith('SMP USER ACK '))
    lines[dep], lines[ack] = lines[ack], lines[dep]
    return '\n'.join(lines) + '\n'


def swap_reclaim_ack(text):
    lines = text.splitlines()
    ack = next(i for i, line in enumerate(lines) if line.startswith('SMP USER ACK '))
    reclaim = next(i for i, line in enumerate(lines) if line.startswith('SMP USER RECLAIM '))
    lines[ack], lines[reclaim] = lines[reclaim], lines[ack]
    return '\n'.join(lines) + '\n'


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: check-smp-fpu-migration.py SERIAL_LOG')
    source = Path(sys.argv[1]).read_text()
    check_lines(source.splitlines(), report=True)
    rejected = test_negatives(source)
    print(f'SMP FPU migration oracle: rejected {rejected} deterministic negative controls')


if __name__ == '__main__':
    main()
