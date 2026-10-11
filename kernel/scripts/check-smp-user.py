#!/usr/bin/env python3
"""Exact fresh-boot cooperative fixture oracle, including lifecycle tokens."""
import re
import sys
from pathlib import Path

def check(path, preemptive=False, modern=False):
    assert not modern or preemptive
    lines = Path(path).read_text().splitlines()
    assert lines.count('ABSD BOOT OK') == 1
    assert lines.count('SMP USER COOPERATIVE STRUCTURAL OK') == 1
    assert not any(re.search(r'PANIC|KERNEL FAULT|FAILED', line) for line in lines)
    cases = [int(m[1]) for line in lines if (m := re.fullmatch(r'SMP USER CASE id=(\d+) cpu=0', line))]
    assert cases == list(range(1, 26 if modern else 22 if preemptive else 18)), cases
    overlaps = [re.fullmatch(r'SMP USER OVERLAP cpu=([01]) peer_changes=(\d+)', line)
                for line in lines if line.startswith('SMP USER OVERLAP ')]
    assert len(overlaps) == 2 and all(overlaps)
    assert sorted(int(m[1]) for m in overlaps) == [0, 1]
    assert all(int(m[2]) >= 128 for m in overlaps)
    histories = {}
    sequence = 0
    for line in lines:
        m = re.fullmatch(r'SMP USER (TRAP|REQUEST|OBSERVE|DEPART|ACK) seq=(\d+) cpu=([01]) slot=(\d+) pid=(\d+) epoch=(\d+)', line)
        if m:
            label, seq, cpu, slot, pid, epoch = m.groups()
            assert int(seq) == sequence + 1
            sequence = int(seq)
            if label != 'TRAP':
                histories.setdefault((cpu, slot, pid, epoch), []).append(label)
        m = re.fullmatch(r'SMP USER RECLAIM cpu=([01]) slot=(\d+) pid=(\d+) epoch=(\d+)', line)
        if m:
            histories.setdefault(m.groups(), []).append('RECLAIM')
    assert len(histories) == (152 if modern else 136 if preemptive else 8)
    assert sum(key[0] == '0' for key in histories) == 1
    assert all(history == ['REQUEST', 'OBSERVE', 'DEPART', 'ACK', 'RECLAIM']
               for history in histories.values()), histories
    paths = {}
    for line in lines:
        m = re.fullmatch(r'SMP USER STOP PATH cpu=([01]) pid=(\d+) epoch=(\d+) path=(ring3-ipi|bounded-continuation|departure-guard|timer-stop)', line)
        if m:
            cpu, pid, epoch, path = m.groups()
            key = (cpu, pid, epoch)
            assert key not in paths
            paths[key] = path
    assert set(paths) == {(cpu, pid, epoch) for cpu, slot, pid, epoch in histories}
    if not preemptive:
        assert sum(cpu == '1' and path == 'ring3-ipi' for (cpu, pid, epoch), path in paths.items()) == 1
    else:
        assert sum(cpu == '1' and path in ('ring3-ipi', 'timer-stop', 'departure-guard') for (cpu, pid, epoch), path in paths.items()) == (145 if modern else 129)
    assert sum(cpu == '1' and path == 'bounded-continuation' for (cpu, pid, epoch), path in paths.items()) == 6
    summaries = [line for line in lines if line.startswith('SMP USER SUMMARY ')]
    assert len(summaries) == 1
    values = dict((key, int(value)) for key, value in re.findall(r'(\w+)=(\d+)', summaries[0]))
    assert values['cases'] == (25 if modern else 21 if preemptive else 17) and values['stops0'] == 1 and values['stops1'] == (151 if modern else 135 if preemptive else 7)
    assert values['calls0'] > 6000 and values['calls1'] > 6000
    assert values['contention1'] > 0 and values['idle1'] > 0
    if preemptive:
        proofs = [re.fullmatch(r'SMP TIMER PROOF cpu=1 tasks=2 registers=2 user-irqs=(\d+) switches=(\d+) voluntary-traps=0', line)
                  for line in lines if line.startswith('SMP TIMER PROOF ')]
        assert len(proofs) == 1 and proofs[0] and all(int(x) >= 3 for x in proofs[0].groups())
        assert sum(line.startswith('SMP TIMER START cpu=1 ') for line in lines) == 1
        assert sum(line.startswith('SMP TIMER SUMMARY cpu=1 ') for line in lines) == 1
        pairs = [re.fullmatch(r'SMP TIMER PAIR from=(\d+) to=(\d+) source-loop=1', line)
                 for line in lines if line.startswith('SMP TIMER PAIR ')]
        assert len(pairs) >= 3 and all(pairs)
        identities = {int(x) for pair in pairs for x in pair.groups()}
        assert len(identities) == 2
        assert all(pair[1] != pair[2] for pair in pairs)
        assert len({pair.groups() for pair in pairs}) == 2
        assert lines.count('SMP FAIRNESS tasks=8 cpu0=4 cpu1=4 progress=8 completed=8') == 1
        assert lines.count('SMP TIMER TERMINAL faults=16 exits=16 bsp-continued=16') == 1
    print('SMP user exact oracle OK', values)

if __name__ == '__main__':
    check(sys.argv[1], '--preemptive' in sys.argv[2:], '--modern' in sys.argv[2:])
