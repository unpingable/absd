#!/usr/bin/env python3
"""Negative controls for the chronological modern-SMP receipt oracle."""
import re
import runpy
import sys
import tempfile
from pathlib import Path

check = runpy.run_path(str(Path(__file__).with_name('check-modern-smp.py')))['check']


def swap_same_task_transfers(text):
    lines = text.splitlines()
    groups = {}
    for index, line in enumerate(lines):
        if line.startswith('SMP QUEUE TRANSFER '):
            f = dict((k, int(v)) for k, v in re.findall(r'([\w-]+)=(\d+)', line))
            groups.setdefault((f['pid'], f['generation']), []).append(index)
    pair = next(indices[:2] for indices in groups.values() if len(indices) >= 2)
    lines[pair[0]], lines[pair[1]] = lines[pair[1]], lines[pair[0]]
    return '\n'.join(lines) + '\n'


def stale_transfer_epoch(text):
    lines = text.splitlines()
    transfers = {}
    witnesses = {}
    for index, line in enumerate(lines):
        if line.startswith('SMP QUEUE TRANSFER '):
            f = dict((k, int(v)) for k, v in re.findall(r'([\w-]+)=(\d+)', line))
            transfers.setdefault((f['pid'], f['generation']), []).append(index)
        elif line.startswith('SMP QUEUE USER '):
            f = dict((k, int(v)) for k, v in re.findall(r'([\w-]+)=(\d+)', line))
            witnesses[(f['pid'], f['generation'], f['stage'])] = f['epoch']
    identity, indexes = next((identity, indexes) for identity, indexes in transfers.items()
                             if len(indexes) == 2)
    index = indexes[1]
    middle_epoch = witnesses[(identity[0], identity[1], 1)]
    stale_epoch = middle_epoch - 1
    assert stale_epoch > 0
    lines[index] = re.sub(r'(\bepoch=)\d+', rf'\g<1>{stale_epoch}', lines[index], count=1)
    return '\n'.join(lines) + '\n'


def duplicate_user_witness(text):
    return re.sub(r'^(SMP QUEUE USER [^\n]*\n)', r'\g<1>\g<1>', text, count=1, flags=re.M)


def lose_transfer_membership(text):
    return re.sub(r'^SMP QUEUE TRANSFER [^\n]*\n', '', text, count=1, flags=re.M)


def retain_queued_membership(text):
    return text.replace(
        'SMP QUEUE QUIESCENT registered=0 queued=0 running=0',
        'SMP QUEUE QUIESCENT registered=0 queued=1 running=0',
        1,
    )


def inject_membership_failure(text):
    return text.replace('ABSD BOOT OK', 'ABSD PANIC: lost/extra runnable membership\nABSD BOOT OK', 1)


def stale_cancel_epoch(text):
    return re.sub(r'(SMP QUEUE CANCEL [^\n]*\bepoch=)(\d+)',
                  lambda m: m[1] + str(int(m[2]) + 1), text, count=1)


def duplicate_cancel(text):
    return re.sub(r'^(SMP QUEUE CANCEL [^\n]*\n)', r'\g<1>\g<1>', text, count=1, flags=re.M)


if len(sys.argv) != 2:
    raise SystemExit('usage: test-modern-smp-oracle.py SERIAL_LOG')
source = Path(sys.argv[1]).read_text()
check(sys.argv[1], report=False)
controls = {
    'reordered same-task transfers': swap_same_task_transfers,
    'stale transfer epoch': stale_transfer_epoch,
    'duplicate user witness': duplicate_user_witness,
    'lost transfer membership evidence': lose_transfer_membership,
    'queued membership at quiescence': retain_queued_membership,
    'lost membership failure text': inject_membership_failure,
    'stale cancellation epoch': stale_cancel_epoch,
    'duplicate cancellation': duplicate_cancel,
}
with tempfile.TemporaryDirectory(prefix='modern-smp-oracle-') as directory:
    path = Path(directory) / 'serial.log'
    for name, mutate in controls.items():
        changed = mutate(source)
        assert changed != source, name
        path.write_text(changed)
        try:
            check(path, report=False)
        except (AssertionError, KeyError, StopIteration, ValueError):
            continue
        raise AssertionError(f'accepted negative control: {name}')
print(f'Modern SMP oracle: accepted original, rejected {len(controls)} negative controls')
