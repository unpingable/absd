#!/usr/bin/env python3
"""Additional closed observer oracle; base workload oracle remains required."""
import json
import re
import sys
from pathlib import Path

OPS = 'other getpid write read yield exit wait spawn map unmap objects-handles cell info timer fault stop device'.split()
REGIONS = 'bsp-probe ap-id-probe lock-id-probe queue-audit select publish claim depart transfer steal remote-wake reschedule-ipi idle-enter idle-exit empty-select steal-attempt'.split()


def fields(line):
    values = re.findall(r'([a-z-]+)=([^ ]+)', line)
    assert len({k for k, _ in values}) == len(values), 'duplicate field'
    return dict(values)


def check(lines, cpus):
    configs = [fields(x) for x in lines if x.startswith('SMP COMMON CONFIG ')]
    phases = [int(x['phase']) for x in configs]
    app = any(x.startswith('SMP APP SCALE START ') for x in lines)
    required = [1] if app else [1, 2, 3]
    assert phases == required, 'observer phases missing/duplicated'
    boot = [i for i,x in enumerate(lines) if x == 'ABSD BOOT OK']
    assert len(boot) == 1
    all_common = [i for i,x in enumerate(lines) if x.startswith('SMP COMMON ')]
    assert len(all_common) == len(configs) + len(phases)*cpus*(len(REGIONS)+len(OPS))
    for phase in required:
        start = [i for i,x in enumerate(lines) if x.startswith('SMP APP SCALE START ')] if app else [i for i,x in enumerate(lines) if x.startswith(f'SMP SCALE START phase={phase} ')]
        done = [i for i,x in enumerate(lines) if x.startswith('SMP APP SCALE DONE ')] if app else [i for i,x in enumerate(lines) if x.startswith(f'SMP SCALE DONE phase={phase} ')]
        config = [i for i,x in enumerate(lines) if x.startswith(f'SMP COMMON CONFIG phase={phase} ')]
        rows = [i for i,x in enumerate(lines) if x.startswith(('SMP COMMON REGION ', 'SMP COMMON LOCK ')) and int(fields(x)['phase']) == phase]
        old = [i for i,x in enumerate(lines) if x.startswith(f'SMP SCALE LOCK phase={phase} ')]
        assert len(start) == len(done) == len(config) == 1 and rows and old
        assert start[0] < config[0] < min(rows) <= max(rows) < min(old) < boot[0]
        if app: assert done[0] < config[0]
        else: assert max(old) < done[0] < boot[0]
        assert rows == list(range(config[0]+1,config[0]+1+cpus*(len(REGIONS)+len(OPS))))

    for x in configs:
        assert set(x) == {'phase', 'cpus', 'coverage'}
        assert int(x['cpus']) == cpus
        assert x['coverage'] == ('serial-epoch' if cpus == 1 else 'completed-held') + ';probes-disjoint;scheduler-inclusive'
    region_rows = [fields(x) for x in lines if x.startswith('SMP COMMON REGION ')]
    lock_rows = [fields(x) for x in lines if x.startswith('SMP COMMON LOCK ')]
    assert len(region_rows) == len(phases) * cpus * len(REGIONS)
    assert len(lock_rows) == len(phases) * cpus * len(OPS)
    summary = []
    for phase in phases:
        for cpu in range(cpus):
            rs = [x for x in region_rows if int(x['phase']) == phase and int(x['cpu']) == cpu]
            ls = [x for x in lock_rows if int(x['phase']) == phase and int(x['cpu']) == cpu]
            assert sorted(x['region'] for x in rs) == sorted(REGIONS)
            assert sorted(x['op'] for x in ls) == sorted(OPS)
            for x in rs:
                assert set(x) == {'phase', 'cpu', 'calls', 'tsc', 'max', 'region'}
                vals = [int(x[k]) for k in ['calls', 'tsc', 'max']]
                assert all(v >= 0 for v in vals)
                assert vals[2] <= vals[1]
                if x['region'] in REGIONS[:8]: assert (vals[0] == 0) == (vals[1] == vals[2] == 0)
                else: assert vals[1] == vals[2] == 0
            for x in ls:
                assert set(x) == {'phase', 'cpu', 'spans', 'contended', 'wait-tsc', 'hold-tsc', 'wait-max', 'hold-max', 'op'}
                assert all(int(x[k]) >= 0 for k in x if k != 'op')
                assert int(x['contended']) <= int(x['spans'])
                for k in ['wait', 'hold']:
                    assert int(x[k + '-max']) <= int(x[k + '-tsc'])
            existing = [fields(x) for x in lines if x.startswith('SMP SCALE LOCK ') and ' path=total' in x]
            total = [x for x in existing if int(x['phase']) == phase and int(x['cpu']) == cpu]
            assert len(total) == 1
            for k in ['spans', 'contended', 'wait-tsc', 'hold-tsc']:
                assert sum(int(x[k]) for x in ls) == int(total[0][k]), f'common lock {k} mismatch'
            for k in ['wait-max', 'hold-max']:
                assert max(int(x[k]) for x in ls) == int(total[0][k])
            for kind in ['transfer', 'steal']:
                assert int(next(x['calls'] for x in rs if x['region'] == kind)) == 0, 'fixed workload moved'
            probes = sum(int(x['tsc']) for x in rs if x['region'] in REGIONS[:3])
            if cpus > 1:
                assert probes <= int(total[0]['hold-tsc'])
                for kind in ['bsp-probe', 'lock-id-probe'] + (['ap-id-probe'] if cpu else []):
                    assert int(next(x['calls'] for x in rs if x['region'] == kind)) > 0
                assert int(total[0]['spans']) > 0
            else:
                assert int(next(x['calls'] for x in rs if x['region'] == 'bsp-probe')) > 0
            if phase == 2 and cpus > 1:
                workers = len([i for i in range(6) if i % cpus == cpu])
                assert int(next(x['spans'] for x in ls if x['op'] == 'getpid')) == workers * 10000
            summary.append({'phase': phase, 'cpu': cpu, 'probe_tsc': probes, 'regions': rs, 'locks': ls})
    return summary


def main():
    lines = Path(sys.argv[1]).read_text().splitlines()
    cpus = int(sys.argv[2])
    assert cpus in (1, 2, 4, 6)
    result = check(lines, cpus)
    candidates = []
    region_i = next(i for i, x in enumerate(lines) if x.startswith('SMP COMMON REGION '))
    lock_i = next(i for i, x in enumerate(lines) if x.startswith('SMP COMMON LOCK '))
    changed = lines.copy(); changed.pop(region_i); candidates.append(changed)
    changed = lines.copy(); changed.insert(region_i, lines[region_i]); candidates.append(changed)
    changed = lines.copy(); changed[lock_i] = re.sub(r' spans=(\d+)', lambda m: ' spans=' + str(int(m[1]) + 1), changed[lock_i]); candidates.append(changed)
    changed = lines.copy(); changed[region_i] = re.sub(r' tsc=(\d+)', ' tsc=0', changed[region_i]); candidates.append(changed)
    changed = [x for x in lines if not x.startswith('SMP COMMON ')]; candidates.append(changed)
    changed = lines.copy(); value=changed.pop(region_i); changed.insert(0,value); candidates.append(changed)
    changed = lines.copy(); value=changed.pop(region_i); changed.append(value); candidates.append(changed)
    if any(x.startswith('SMP SCALE START phase=2 ') for x in lines):
        changed = [x for x in lines if not (x.startswith('SMP COMMON ') and int(fields(x)['phase']) != 1)]; candidates.append(changed)
    event_i = next(i for i,x in enumerate(lines) if x.startswith('SMP COMMON REGION ') and ' region=transfer' in x)
    changed = lines.copy(); changed[event_i] = changed[event_i].replace(' calls=0 ', ' calls=1 '); candidates.append(changed)
    for changed in candidates:
        try:
            check(changed, cpus)
        except (AssertionError, ValueError, KeyError, StopIteration):
            continue
        raise AssertionError('observer substitution accepted')
    print(json.dumps({'cpus': cpus, 'rows': result, 'receipt_controls': len(candidates)}, indent=2))


if __name__ == '__main__':
    main()
