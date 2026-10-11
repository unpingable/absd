#!/usr/bin/env python3
"""Replay bounded-class evidence and enforce the deterministic case obligations."""
import re
import sys
from pathlib import Path

WAITING, RUNNABLE, RUNNING, BLOCKED, EXHAUSTED = range(5)
NONE = (1 << 64) - 1


def check(path, report=True, structural_only=False):
    lines = Path(path).read_text().splitlines()
    assert 'RT CLASS CASES OK' in lines
    assert 'RTC status=0 frames=0 processes=0 cells=0 pipes=0' in lines
    assert 'RTC WORKLOAD OK' in lines and 'ABSD BOOT OK' in lines
    assert not any(re.search(r'PANIC|KERNEL FAULT|FAILED', s) for s in lines)
    owner, cases = {}, {}
    case = None
    for line in lines:
        if line.startswith('RT CASE '):
            case = int(line.split('=')[1])
            assert case not in cases
            cases[case] = dict(events=[], pids=[], idle=[], faults=[])
        elif line.startswith('SPAWN OK ') and line.endswith('program=rt-probe'):
            owner[int(re.search(r'pid=(\d+)', line)[1])] = case
        elif line.startswith('USER FAULT '):
            pid = int(re.search(r'pid=(\d+)', line)[1])
            assert owner[pid] == 12 and 'vector=6 ' in line
            cases[12]['faults'].append(pid)
    assert set(cases) == set(range(1, 13))
    active, history = {}, {}
    previous_tick = 0
    for line in lines:
        if not line.startswith(('RT CONFIG ', 'RT STATE ', 'RT CHARGE ', 'RT PERIOD ',
                                'RT RELEASE ', 'RT DISPATCH ', 'RT SELECT ', 'RT EXHAUST ',
                                'RT REMOVE ', 'RT IDLE ')):
            continue
        kind = line.split()[1]
        f = {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', line)}
        tick = f.get('tick', f.get('actual'))
        if tick is not None:
            assert tick >= previous_tick
            previous_tick = tick
        if kind == 'IDLE':
            assert all(r['state'] not in (RUNNABLE, RUNNING) for r in active.values())
            # No normal hog in case 7; assign idle observations by its active RT task.
            for r in active.values():
                cases[r['case']]['idle'].append(f['tick'])
            continue
        pid = f['pid']
        c = cases[owner[pid]]
        c['events'].append((kind, f, line))
        if kind == 'CONFIG':
            assert pid not in active and pid not in history
            assert f['state'] in (WAITING, BLOCKED) and f['priority'] in (1, 2)
            assert 0 < f['budget'] < f['period']
            r = dict(f, case=owner[pid], seq=0, consumed=0, state=f['state'],
                     release=f['first'], missed=0, firsts={}, periods=[], charges=[],
                     selects=[], states=[], exhausts=[], release_pending=None)
            active[pid] = history[pid] = r
            c['pids'].append(pid)
            continue
        assert pid in active, f'event for removed task: {line}'
        r = active[pid]
        if kind == 'CHARGE':
            assert r['state'] == RUNNING and f['seq'] == r['seq']
            assert f['consumed'] == r['consumed'] + 1 <= r['budget']
            assert f['remaining'] == r['budget'] - f['consumed']
            r['consumed'] = f['consumed']
            r['charges'].append(f)
        elif kind == 'EXHAUST':
            assert r['state'] == RUNNING and r['consumed'] == r['budget']
            assert r['charges'][-1]['tick'] == f['tick']
            r['exhausts'].append(f)
        elif kind == 'PERIOD':
            assert f['seq'] == r['seq'] and f['state'] == r['state']
            assert f['consumed'] == r['consumed'] <= f['budget'] == r['budget']
            assert f['release'] == r['release']
            assert f['dispatch'] == r['firsts'].get(r['seq'], NONE)
            r['periods'].append(f)
        elif kind == 'RELEASE':
            # One phase transition and one fresh budget, irrespective of blocked time.
            assert f['seq'] == r['seq'] + f['skipped'] + 1
            assert f['requested'] == r['first'] + (f['seq'] - 1) * r['period']
            assert f['actual'] >= f['requested'] and f['late'] == f['actual'] - f['requested']
            unfinished = int(r['seq'] > 0 and r['state'] != WAITING)
            assert f['missed'] == f['skipped'] + unfinished
            assert f['total_missed'] == r['missed'] + f['missed']
            r.update(seq=f['seq'], release=f['requested'], missed=f['total_missed'], consumed=0)
            r['release_pending'] = f
        elif kind == 'DISPATCH':
            assert r['state'] == RUNNABLE and r['seq'] == f['seq']
            assert r['seq'] not in r['firsts']
            assert f['requested'] == r['release']
            assert f['latency'] == f['actual'] - f['requested'] >= 0
            r['firsts'][r['seq']] = f['actual']
        elif kind == 'SELECT':
            assert r['state'] == RUNNABLE and r['consumed'] < r['budget']
            assert f['priority'] == r['priority'] and f['remaining'] == r['budget'] - r['consumed']
            ready = {p: q for p, q in active.items() if q['state'] == RUNNABLE}
            highest = max(q['priority'] for q in ready.values())
            assert r['priority'] == highest
            peers = [p for p, q in ready.items() if q['priority'] == highest]
            if len(peers) == 2 and f['from'] in peers:
                assert pid != f['from'], 'equal-priority runnable peer was bypassed'
            assert not any(q['state'] == RUNNING for q in active.values())
            r['selects'].append(f)
        elif kind == 'STATE':
            reason = re.search(r'event=(\w+)', line)[1]
            assert f['from'] == r['state'] and f['seq'] == r['seq']
            assert f['consumed'] == r['consumed'] and f['remaining'] == r['budget'] - r['consumed']
            old = r['state']
            if reason == 'release':
                assert r['release_pending'] is not None
                expected = BLOCKED if old == BLOCKED else RUNNABLE
                r['release_pending'] = None
            elif reason == 'dispatch':
                assert old == RUNNABLE and r['consumed'] < r['budget']
                assert r['selects'][-1]['tick'] == f['tick']
                expected = RUNNING
            elif reason == 'preempt':
                assert old == RUNNING and r['consumed'] < r['budget']
                expected = RUNNABLE
            elif reason == 'exhaust':
                assert old == RUNNING and r['consumed'] == r['budget']
                assert r['exhausts'][-1]['tick'] == f['tick']
                expected = EXHAUSTED
            elif reason == 'block':
                assert old == RUNNING and 0 < r['consumed'] < r['budget']
                expected = BLOCKED
            elif reason == 'complete':
                assert old == RUNNING
                expected = WAITING
            elif reason == 'wake':
                assert old == BLOCKED  # These real fixtures wake only existing blockers.
                expected = RUNNABLE
            else:
                raise AssertionError(line)
            assert f['to'] == expected
            r['state'] = expected
            r['states'].append((reason, f))
        elif kind == 'REMOVE':
            assert r['release_pending'] is None
            del active[pid]
    assert not active
    assert len(cases[12]['faults']) == 1
    for number, c in cases.items():
        expected = 2 if number in (9, 10) else 1
        assert len(c['pids']) == expected
        tasks = [history[p] for p in c['pids']]
        if number != 12:
            assert all(len(r['periods']) >= 8 for r in tasks)
            assert all(len(r['firsts']) >= 9 for r in tasks)
        if structural_only:
            # Preserve case identity, task cardinality, phase coverage and the
            # two priority/peer-selection controls. The strict mode below
            # continues to enforce the fixture's timing and workload claims.
            if number == 9:
                assert all(r['priority'] == 1 for r in tasks)
                assert any(s['from'] == c['pids'][1] for s in tasks[0]['selects'])
                assert any(s['from'] == c['pids'][0] for s in tasks[1]['selects'])
            if number == 10:
                low, high = tasks
                assert (low['priority'], high['priority']) == (1, 2)
                assert any(s['from'] == low['pid'] for s in high['selects'])
                assert any(s['from'] == high['pid'] for s in low['selects'])
            if number in (3, 4, 5, 6):
                for r in tasks:
                    blocks = [f for reason, f in r['states'] if reason == 'block']
                    wakes = [f for reason, f in r['states'] if reason == 'wake']
                    assert wakes and len(wakes) <= len(blocks) <= len(wakes) + 1
            if report:
                periods = sum(len(r['periods']) for r in tasks)
                dispatches = sum(len(r['firsts']) for r in tasks)
                print(f'case={number} tasks={len(tasks)} periods={periods} '
                      f'dispatches={dispatches} structural=ok')
            continue
        if number not in (7, 12):
            assert all(p['normal'] >= 8 for r in tasks for p in r['periods'])
        if number in (1, 7):
            assert all(0 < p['consumed'] < p['budget'] for p in tasks[0]['periods'])
            assert not tasks[0]['exhausts'] and tasks[0]['missed'] == 0
        if number == 2:
            r = tasks[0]
            assert all(p['consumed'] == 5 for p in r['periods'])
            assert len(r['exhausts']) == len(r['firsts'])
        if number in (3, 4, 5, 6):
            r = tasks[0]
            blocks = [f for reason, f in r['states'] if reason == 'block']
            wakes = [f for reason, f in r['states'] if reason == 'wake']
            assert wakes and len(wakes) <= len(blocks) <= len(wakes) + 1
            for block, wake in zip(blocks, wakes):
                next_selection = next(s for s in r['selects'] if s['tick'] >= wake['tick'])
                assert next_selection['tick'] == wake['tick']
                assert not any(block['tick'] < t['tick'] <= wake['tick'] for t in r['charges'])
                if number == 3:
                    assert wake['seq'] == block['seq'] and wake['consumed'] == block['consumed']
                    assert wake['remaining'] == block['remaining']
                    assert r['exhausts'][0]['tick'] - wake['tick'] == wake['remaining']
                else:
                    assert wake['seq'] > block['seq'] and wake['consumed'] == 0
                    assert wake['remaining'] == r['budget']
            if number == 5:
                assert r['missed'] == 1
            if number == 6:
                assert r['missed'] == 3
        if number == 7:
            assert len(c['idle']) >= 10
            assert all(p['normal'] == 0 for p in tasks[0]['periods'])
        if number == 8:
            r = tasks[0]
            ex = r['exhausts'][0]['tick']
            ordered = [(kind, f) for kind, f, _ in c['events'] if f.get('tick', f.get('actual')) == ex]
            names = [kind for kind, _ in ordered]
            assert names.index('EXHAUST') < names.index('RELEASE')
            assert r['periods'][0]['consumed'] == 5
            assert r['firsts'][1] + 5 == ex == r['first'] + r['period']
        if number == 9:
            assert all(r['priority'] == 1 and len(r['exhausts']) >= 10 for r in tasks)
            assert all(p['consumed'] == 5 for r in tasks for p in r['periods'])
            # Replay checked round-robin at every selection where both were runnable.
            assert any(s['from'] == c['pids'][1] for s in tasks[0]['selects'])
            assert any(s['from'] == c['pids'][0] for s in tasks[1]['selects'])
        if number == 10:
            low, high = tasks
            assert (low['priority'], high['priority']) == (1, 2)
            assert len(low['exhausts']) >= 8 and len(high['exhausts']) >= 8
            assert any(s['from'] == low['pid'] for s in high['selects'])
            assert any(s['from'] == high['pid'] for s in low['selects'])
        if number == 11:
            r = tasks[0]
            wake = next(f for reason, f in r['states'] if reason == 'wake')
            assert wake['tick'] == r['first'] + r['period'] and wake['consumed'] == 0
            same = [(kind, f) for kind, f, _ in c['events'] if f.get('tick', f.get('actual')) == wake['tick']]
            assert next(i for i, (kind, _) in enumerate(same) if kind == 'RELEASE') < next(
                i for i, (kind, f) in enumerate(same) if kind == 'STATE' and f['from'] == BLOCKED and f['to'] == RUNNABLE)
        latencies = [tick - (r['first'] + (seq - 1) * r['period'])
                     for r in tasks for seq, tick in r['firsts'].items()]
        maximum = max(latencies)
        # Bound deliberately accounts for blocking and equal/higher-priority contention.
        bound = 15 if number == 8 else 9 if number in (3, 4, 5, 6, 9, 10) else 1
        assert maximum <= bound, (number, maximum, bound)
        if report:
            periods = sum(len(r['periods']) for r in tasks)
            misses = sum(r['missed'] for r in tasks)
            print(f'case={number} tasks={len(tasks)} periods={periods} max_latency_ticks={maximum} '
                  f'bound_ticks={bound} misses={misses} exhaustions={sum(len(r["exhausts"]) for r in tasks)}')
    if structural_only and report:
        task_count = sum(len(c['pids']) for c in cases.values())
        print(f'RT CLASS STRUCTURAL OK cases={len(cases)} tasks={task_count}')
    return cases, history


if __name__ == '__main__':
    args = sys.argv[1:]
    structural_only = '--structural-only' in args
    args = [arg for arg in args if arg != '--structural-only']
    if len(args) != 1:
        raise SystemExit('usage: check-rt-class.py [--structural-only] SERIAL_LOG')
    check(args[0], structural_only=structural_only)
