#!/usr/bin/env python3
"""Validate scheduler evidence, not just successful boot text."""
import re
import sys
from pathlib import Path


def check(path, normal_pid=2):
    lines = Path(path).read_text().splitlines()
    assert 'RT WORKLOAD OK' in lines and 'ABSD BOOT OK' in lines
    assert not any(re.search(r'PANIC|KERNEL FAULT|USER FAULT|FAILED', s) for s in lines)
    configs = {int(re.search(r'pid=(\d+)', s)[1]): int(re.search(r'mode=(\d+)', s)[1])
               for s in lines if s.startswith('RT CONFIG ')}
    scenarios = {1: [], 2: []} if configs else {}
    mode = None
    for line in lines:
        if line.startswith('RT SCENARIO '):
            mode = int(line.split('=')[1])
            if not configs:
                assert mode not in scenarios
                scenarios[mode] = []
        elif line.startswith(('RT RELEASE ', 'RT DISPATCH ', 'RT PERIOD ', 'RT EXHAUST ')):
            assert mode is not None
            fields = dict((k, int(v)) for k, v in re.findall(r'(\w+)=(\d+)', line))
            owner = configs[fields["pid"]] if configs else mode
            scenarios[owner].append((line.split()[1], fields))
    assert set(scenarios) == {1, 2}
    for mode, events in scenarios.items():
        releases = [f for kind, f in events if kind == 'RELEASE']
        dispatches = [f for kind, f in events if kind == 'DISPATCH']
        periods = [f for kind, f in events if kind == 'PERIOD']
        exhausts = [f for kind, f in events if kind == 'EXHAUST']
        assert len(periods) >= 12
        assert len(releases) == len(dispatches)
        assert len({f['pid'] for _, f in events}) == 1
        assert all(f.get('skipped', f['missed']) == 0 and 0 <= f['actual'] - f['requested'] <= 1 for f in releases)
        assert all(b['requested'] - a['requested'] == 20 for a, b in zip(releases, releases[1:]))
        for index, (release, dispatch) in enumerate(zip(releases, dispatches), 1):
            assert dispatch['seq'] == index
            assert dispatch['requested'] == release['requested']
            assert dispatch['latency'] == dispatch['actual'] - dispatch['requested'] <= 1
            # The named ordinary hog proves displacement at selection.
            assert dispatch['from'] == normal_pid
        for index, period in enumerate(periods, 1):
            assert period['seq'] == index
            assert period['release'] == releases[index - 1]['requested']
            assert period['dispatch'] == dispatches[index - 1]['actual']
            assert period['budget'] == 5 and period['normal'] >= 14
            assert (1 <= period['consumed'] <= 4) if mode == 1 else period['consumed'] == 5
            if mode == 2:
                assert exhausts[index - 1]['tick'] == period['dispatch'] + 5
        assert len(exhausts) == (0 if mode == 1 else len(dispatches))
        print(f"mode={mode} periods={len(periods)} dispatches={len(dispatches)} "
              f"max_latency_ticks={max(f['latency'] for f in dispatches)} "
              f"exhaustions={len(exhausts)} min_normal_ticks={min(f['normal'] for f in periods)}")


if __name__ == '__main__':
    check(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 2)
