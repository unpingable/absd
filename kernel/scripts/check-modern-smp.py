#!/usr/bin/env python3
"""Check chronological queue transfer and userspace placement evidence."""
import re
import sys
from pathlib import Path


def fields(line):
    return {name: int(value) for name, value in re.findall(r'([\w-]+)=(\d+)', line)}


def check(path, report=True):
    lines = Path(path).read_text().splitlines()
    assert lines.count('SMP QUEUE PROOF transfers=112 steals=16 before=80 remote=80 returned=32') == 1
    assert lines.count('SMP QUEUE QUIESCENT registered=0 queued=0 running=0') == 1
    assert lines.count('ABSD BOOT OK') == 1
    assert not any(re.search(r'PANIC|KERNEL FAULT|FAILED', line) for line in lines)

    # The fixture emits one closed identity for every migrated process. Track
    # placement and epoch in line order; a later destination witness must be
    # justified by the immediately preceding transfer for that identity.
    tasks = {}
    transfers = []
    cancels = []
    deferred = []
    pending_defer = {}
    for line in lines:
        if line.startswith('SMP QUEUE USER '):
            f = fields(line)
            identity = (f['pid'], f['generation'])
            assert f['pid'] > 0 and f['generation'] > 0
            assert f['cpl'] == 3 and f['cpu'] in (0, 1) and f['stage'] in (0, 1, 2)
            assert f['epoch'] > 0
            task = tasks.setdefault(identity, {
                'pid': f['pid'], 'generation': f['generation'], 'witnesses': [],
                'transfers': [], 'cpu': None, 'last_epoch': 0, 'pending': None,
            })
            witnesses = task['witnesses']
            if not witnesses:
                assert f['stage'] == 0 and f['cpu'] == 0
                assert task['pending'] is None
                task['cpu'] = f['cpu']
            else:
                previous = witnesses[-1]
                assert f['stage'] == previous['stage'] + 1
                assert f['epoch'] > previous['epoch']
                pending = task['pending']
                assert pending is not None, 'user placement changed without transfer'
                assert f['cpu'] == pending['to']
                assert f['epoch'] > pending['epoch'], 'destination witness predates transfer claim'
                task['pending'] = None
                task['cpu'] = f['cpu']
            witnesses.append(f)
            task['last_epoch'] = f['epoch']
        elif line.startswith('SMP QUEUE TRANSFER '):
            f = fields(line)
            assert f['n'] == len(transfers) + 1, 'transfer sequence gap or reorder'
            assert f['saved'] == f['departed'] == 1
            assert f['from'] in (0, 1) and f['to'] in (0, 1) and f['to'] != f['from']
            assert f['epoch'] > 0 and f['steal'] in (0, 1)
            identity = (f['pid'], f['generation'])
            assert identity in tasks, 'transfer before first userspace witness'
            task = tasks[identity]
            assert task['pending'] is None, 'second transfer before destination witness'
            assert task['cpu'] == f['from'], 'transfer source differs from current placement'
            assert f['epoch'] >= task['last_epoch'], 'transfer predates last userspace witness'
            assert len(task['witnesses']) in (1, 2), 'transfer after final userspace witness'
            request = pending_defer.pop(f['pid'], None)
            if request is not None:
                assert request['epoch'] == f['epoch'], 'transfer bypassed another pending epoch'
                assert request['to'] == f['to'], 'transfer destination differs from deferred request'
            task['pending'] = f
            task['transfers'].append(f)
            transfers.append(f)
        elif line.startswith('SMP QUEUE CANCEL PROOF '):
            continue
        elif line.startswith('SMP QUEUE CANCEL '):
            f = fields(line)
            assert f['pid'] > 0 and f['epoch'] > 0 and f['departed'] == 1
            assert f['stop'] in (0, 1)
            assert any(task['pid'] == f['pid'] for task in tasks.values()), 'cancel for unknown task'
            request = pending_defer.pop(f['pid'], None)
            assert request is not None and request['epoch'] == f['epoch'], 'cancel lacks matching defer'
            cancels.append(f)
        elif line.startswith('SMP QUEUE DEFER '):
            f = fields(line)
            assert f['pid'] > 0 and f['epoch'] > 0 and f['to'] in (0, 1)
            task = next((task for task in tasks.values() if task['pid'] == f['pid']), None)
            assert task is not None, 'defer for unknown task'
            assert f['epoch'] >= task['last_epoch'] and f['to'] != task['cpu']
            assert f['pid'] not in pending_defer, 'duplicate pending defer'
            pending_defer[f['pid']] = f
            deferred.append(f)

    # Every PID and registration generation is unique, and each history is a
    # complete stage sequence. The protocol emits 32 return migrations and 48
    # one-way migrations; of the latter, 16 are idle steals.
    identities = set(tasks)
    assert len(identities) == 80
    assert len({pid for pid, _ in identities}) == 80
    assert len({generation for _, generation in identities}) == 80
    two_transfer = [t for t in tasks.values() if [w['stage'] for w in t['witnesses']] == [0, 1, 2]]
    one_transfer = [t for t in tasks.values() if [w['stage'] for w in t['witnesses']] == [0, 1]]
    assert len(two_transfer) == 32 and len(one_transfer) == 48
    assert all(len(t['transfers']) == 2 and t['pending'] is None for t in two_transfer)
    assert all(len(t['transfers']) == 1 and t['pending'] is None for t in one_transfer)
    assert all(t['cpu'] == t['witnesses'][-1]['cpu'] for t in tasks.values())
    assert all(t['witnesses'][-1]['epoch'] > t['transfers'][-1]['epoch'] for t in tasks.values())
    assert len(transfers) == 112 and sum(f['steal'] for f in transfers) == 16
    assert sum(f['stop'] == 0 for f in cancels) == 32
    assert sum(f['stop'] == 1 for f in cancels) == 16
    assert len(cancels) == 48
    assert len(deferred) == 80 and not pending_defer
    cancel_proofs = [line for line in lines if line.startswith('SMP QUEUE CANCEL PROOF ')]
    assert len(cancel_proofs) == 1
    proof = fields(cancel_proofs[0])
    assert proof['blocks'] == 32 and proof['stops'] == 16 and proof['deferred'] == len(deferred)
    if report:
        print('Modern SMP chronological oracle OK tasks=80 two_transfer=32 one_transfer=48 '
              'transfers=112 steals=16 cancellations=48 deferred=' + str(proof['deferred']))
    return tasks, transfers, cancels


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: check-modern-smp.py SERIAL_LOG')
    check(sys.argv[1])
