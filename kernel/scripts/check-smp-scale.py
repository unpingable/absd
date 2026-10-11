#!/usr/bin/env python3
"""Closed receipt oracle for the fixed-work SMP scaling qualification."""
import argparse
import json
import math
import re
from pathlib import Path

U64 = (1 << 64) - 1
PATHS = ('other', 'getpid', 'cell-read', 'cell-transition', 'cell-wait',
         'syscall', 'timer', 'fault', 'stop', 'idle', 'device-reacquire', 'total')
WORK = {1: 1 << 26, 2: 10000, 3: 2000}


def need(ok, why):
    if not ok:
        raise AssertionError(why)


def fields(line):
    tail = line.split(' ', 3)[-1]
    pairs = re.findall(r'([a-z][a-z0-9_-]*)=([^\s]+)', tail)
    result = {}
    for key, value in pairs:
        need(key not in result, f'duplicate key {key} in {line}')
        result[key] = value
    need(' '.join(f'{k}={v}' for k, v in result.items()) == tail,
         f'unrecognized/malformed fields in {line}')
    return result


def rows(lines, prefix):
    return [(i, line, fields(line)) for i, line in enumerate(lines)
            if line.startswith(prefix)]


def num(f, key, label=None):
    value = f.get(key)
    need(value is not None and re.fullmatch(r'[0-9]+', value) is not None,
         f'{label or key} is not an unsigned decimal')
    n = int(value)
    need(value == str(n), f'{label or key} is not canonical decimal')
    need(n <= U64, f'{label or key} exceeds u64')
    return n


def check_placement(path, cpus):
    p = json.loads(Path(path).read_text())
    need(p.get('kvm') == {'enabled': True, 'present': True}, 'KVM is not attested')
    v = p.get('vcpus')
    need(isinstance(v, list) and len(v) == cpus
         and {x.get('cpu-index') for x in v} == set(range(cpus)),
         'QMP vCPU identity/count mismatch')
    if cpus == 1:
        need(p.get('host_topology') == 'separate'
             and p.get('guest_topology_mode') == 'legacy-qemu-default'
             and p.get('guest_topology') is None,
             'UP case must retain the one-vCPU legacy topology')
    else:
        need(p.get('host_topology') == 'separate'
             and p.get('guest_topology_mode') == 'explicit-smp-scheduler-test'
             and p.get('guest_topology') == {'sockets': 1, 'cores': cpus, 'threads': 1},
             'multicore topology is not the admitted explicit separate-core topology')
    seen = set()
    for x in v:
        cpu = x.get('host-cpu')
        need(isinstance(cpu, int) and x.get('affinity') == [cpu],
             'vCPU affinity does not match QMP pin')
        if cpus > 1:
            key = (x.get('host-package'), x.get('host-core'))
            need(None not in key and key not in seen,
                 'guest vCPUs are not pinned to distinct host cores')
            seen.add(key)


def check_lines(lines, cpus, expected_meter):
    need(cpus in (1, 2, 4, 6), 'unsupported vCPU count')
    need(not any('PANIC' in line or 'FAILED' in line for line in lines),
         'positive receipt contains panic/failure')
    known = ('SMP SCALE CONFIG ', 'SMP SCALE ACTOR ', 'SMP SCALE WORK ',
             'SMP SCALE START ', 'SMP SCALE DONE ', 'SMP SCALE CPU ',
             'SMP SCALE LOCK ', 'SMP SCALE OK ')
    need(all(not line.startswith('SMP SCALE ') or line.startswith(known) for line in lines),
         'unrecognized SMP SCALE receipt row')
    cfg = rows(lines, 'SMP SCALE CONFIG ')
    need(len(cfg) == 1, 'scale configuration missing/duplicate')
    ci, _, cf = cfg[0]
    expected_cfg = {'workers': '6', 'phases': '3', 'clock': 'guest-tsc',
                    'coverage': 'completed-spans',
                    'scheduling': 'up-scan' if cpus == 1 else 'per-cpu-queues',
                    'vcpus': str(cpus), 'meter': cf.get('meter'), 'control': cf.get('control')}
    need(set(cf) == set(expected_cfg) and all(cf[k] == v for k, v in expected_cfg.items()
                                              if v is not None),
         'scale configuration fields/value mismatch')
    need(cf['meter'] == str(expected_meter) and expected_meter in (0,1) and cf['control'] == '0',
         'scale receipt meter/control mode mismatch')
    meter = cf['meter'] == '1'

    starts = rows(lines, 'SMP TIMER START ')
    need(len(starts) == cpus - 1, 'AP timer calibration coverage missing/duplicate')
    timer_idx = {}
    for i, _, f in starts:
        need(set(f) == {'cpu','vector','divide','initial','tsc-a-before','tsc-a-after',
                        'count-a','tsc-b-before','tsc-b-after','count-b','quantum-tsc',
                        'sample-tsc','max-jitter','reference','global-time','rt-time'},
             'timer calibration fields mismatch')
        cpu = num(f, 'cpu')
        need(1 <= cpu < cpus and cpu not in timer_idx, 'timer CPU missing/duplicate/range')
        a0,a1,b0,b1 = (num(f,k) for k in ('tsc-a-before','tsc-a-after','tsc-b-before','tsc-b-after'))
        q, sample, jitter = num(f,'quantum-tsc'), num(f,'sample-tsc'), num(f,'max-jitter')
        ca, cb, initial = num(f,'count-a'), num(f,'count-b'), num(f,'initial')
        need(0 <= a0 <= a1 < b0 <= b1 <= U64 and a1-a0 <= jitter and b1-b0 <= jitter
             and b0-a1 >= sample and b1-a0 < (1 << 34), 'AP-local TSC sampling bounds')
        need(q == 16777216 and sample == 33554432 and jitter == 262144
             and f['reference'] == 'ap-local-tsc', 'timer calibration constants/reference')
        span = (b0 + (b1-b0)//2) - (a0 + (a1-a0)//2)
        need(span > 0 and 0 < cb < ca <= 0xffffffff and 1 <= initial <= 0xffffffff
             and initial == (ca-cb)*q//span and f['vector']=='224' and f['divide']=='16'
             and f['global-time']==f['rt-time']=='CPU0', 'timer calibration arithmetic/ownership')
        timer_idx[cpu] = i
    need(set(timer_idx) == set(range(1,cpus)), 'AP timer calibration CPU coverage')

    actors = rows(lines, 'SMP SCALE ACTOR ')
    need(len(actors) == 18, 'scale actor census must be exactly 18')
    identities, roles, pids, generations = set(), set(), set(), set()
    actor_idx = {p: {} for p in range(1,4)}
    for i, _, f in actors:
        need(set(f) == {'phase','index','role','cpu','pid','generation','cpl'},
             'actor fields mismatch')
        phase,index,role,cpu,pid,gen = (num(f,k) for k in ('phase','index','role','cpu','pid','generation'))
        need(phase in (1,2,3) and index in range(6) and role == 300+(phase-1)*6+index
             and cpu == index % cpus and pid > 1
             and (gen == 0 if cpus == 1 else gen > 0) and f['cpl']=='3',
             'actor role/placement/ownership mismatch')
        need((pid,gen) not in identities and role not in roles,
             'duplicate actor identity or role')
        need(pid not in pids and (cpus == 1 or gen not in generations), 'duplicate actor PID or generation')
        pids.add(pid); generations.add(gen)
        identities.add((pid,gen)); roles.add(role); actor_idx[phase][index] = i
        if cpu:
            need(cpu in timer_idx and timer_idx[cpu] < i,
                 'AP actor preceded its local timer start')
    need(roles == set(range(300,318)), 'actor role set incomplete')
    need(all(set(actor_idx[p]) == set(range(6)) for p in (1,2,3)), 'phase actor coverage')

    publications = [(i, re.fullmatch(r'SPAWN OK pid=(\d+) parent=(\d+) program=smp-user', line))
                    for i,line in enumerate(lines)]
    publications = [(i, int(m[1]), int(m[2])) for i,m in publications if m]
    need(len(publications) == 19 and publications[0][1:] == (1,0), 'nineteen exact fixture publications')
    need({pid for _,pid,_ in publications} == pids | {1}
         and all(parent == 1 for _,pid,parent in publications if pid != 1), 'fixture publication identity/parent census')
    pub = {pid:i for i,pid,_ in publications}
    outcomes = [(i, re.fullmatch(r'USER EXIT pid=(\d+) status=(\d+)', line))
                for i,line in enumerate(lines) if i > publications[0][0]]
    outcomes = [(i,int(m[1]),int(m[2])) for i,m in outcomes if m]
    need(len(outcomes) == 19 and {pid for _,pid,_ in outcomes} == pids | {1}
         and all(status == (0 if pid == 1 else 7) for _,pid,status in outcomes), 'nineteen normal terminal outcomes')
    exit_idx = {pid:i for i,pid,_ in outcomes}
    for i,_,f in actors:
        need(pub[int(f['pid'])] < i < exit_idx[int(f['pid'])], 'actor outside published lifetime')

    workrows = rows(lines, 'SMP SCALE WORK ')
    need(len(workrows) == 18, 'scale work rows must be exactly 18')
    work_indices = {p: {} for p in (1,2,3)}
    for i, _, f in workrows:
        need(set(f) == {'phase','index','units','checksum'}, 'work row fields mismatch')
        phase,index = num(f,'phase'),num(f,'index')
        need(phase in work_indices and index in range(6) and index not in work_indices[phase],
             'duplicate/out-of-range work row')
        units, checksum = num(f,'units'), num(f,'checksum')
        expected = WORK[phase]
        need(units == expected and checksum == (expected*(expected-1)//2+index if phase==1 else 0),
             'fixed work units/checksum mismatch')
        work_indices[phase][index] = i
    need(all(set(work_indices[p]) == set(range(6)) for p in (1,2,3)), 'work row coverage')

    starts_phase, dones_phase = {}, {}
    for prefix, dst, label in [('SMP SCALE START ', starts_phase, 'start'),
                               ('SMP SCALE DONE ', dones_phase, 'done')]:
        rr = rows(lines,prefix); need(len(rr)==3, f'{label} phase count')
        for i,_,f in rr:
            need(set(f)==({'phase','vcpus','workers'} if label=='start'
                 else {'phase','vcpus','units','tsc'}), f'{label} fields')
            phase=num(f,'phase'); need(phase in (1,2,3) and phase not in dst, f'duplicate {label}')
            need(num(f,'vcpus')==cpus and (label=='done' or num(f,'workers')==6), f'{label} config')
            if label=='done':
                need(num(f,'units')==WORK[phase]*6 and num(f,'tsc')>0, 'done work/time')
            dst[phase]=i
    for p in (1,2,3):
        phase_pids = [int(f['pid']) for _,_,f in actors if int(f['phase']) == p]
        need(all(starts_phase[p] < exit_idx[pid] < dones_phase[p] for pid in phase_pids), 'worker terminal outcome outside phase')
        need(max(actor_idx[p].values()) < starts_phase[p] < dones_phase[p],
             f'phase {p} actor/start/done chronology')
        if p > 1:
            need(dones_phase[p-1] < min(actor_idx[p].values()),
                 f'phase {p} actors precede prior phase completion')
        need(all(starts_phase[p] < work_indices[p][x] < dones_phase[p] for x in range(6)),
             f'phase {p} work outside measurement interval')
    need(max(actor_idx[1].values()) < ci < starts_phase[1],
         'phase-one actors/configuration/start chronology')

    cpur = rows(lines,'SMP SCALE CPU ')
    need(len(cpur)==3*cpus, 'per-phase CPU accounting cardinality')
    cpudata={p:{} for p in (1,2,3)}
    for i,_,f in cpur:
        need(set(f)=={'phase','cpu','calls','cas-retries','dispatch','preempt'}, 'CPU row fields')
        p,cpu=num(f,'phase'),num(f,'cpu')
        need(p in cpudata and cpu in range(cpus) and cpu not in cpudata[p], 'CPU row duplicate/range')
        calls,retries,dispatch,preempt=(num(f,k) for k in ('calls','cas-retries','dispatch','preempt'))
        need(calls>0 and dispatch>0 and (p!=1 or cpu==0 or preempt>0),
             'required calls/dispatch/preemption absent')
        cpudata[p][cpu]=(i,calls,retries,dispatch,preempt)
    need(all(set(cpudata[p])==set(range(cpus)) for p in cpudata), 'CPU coverage')
    for p in (1,2,3):
        need(all(starts_phase[p] < cpudata[p][c][0] < dones_phase[p] for c in range(cpus)),
             'CPU counters outside phase interval')

    locks=rows(lines,'SMP SCALE LOCK ')
    need(len(locks)==3*cpus*len(PATHS), 'lock path census cardinality')
    lockdata={p:{c:{} for c in range(cpus)} for p in (1,2,3)}
    for i,_,f in locks:
        need(set(f)=={'phase','cpu','spans','contended','retries','wait-tsc','hold-tsc',
                      'wait-max','hold-max','path'}, 'lock row fields')
        p,c=num(f,'phase'),num(f,'cpu'); path=f['path']
        need(p in lockdata and c in range(cpus) and path in PATHS and path not in lockdata[p][c],
             'lock row duplicate/range/path')
        values={k:num(f,k) for k in ('spans','contended','retries','wait-tsc','hold-tsc','wait-max','hold-max')}
        need(values['spans'] > 0 or all(v == 0 for v in values.values()), 'orphan lock counters without span')
        need(values['contended']<=values['spans'] and values['retries']>=values['contended']
             and values['wait-max']<=values['wait-tsc'] and values['hold-max']<=values['hold-tsc'],
             'lock counter inequality')
        lockdata[p][c][path]=(i,values)
    for p in (1,2,3):
        for c in range(cpus):
            d=lockdata[p][c]; need(set(d)==set(PATHS), 'lock path set incomplete')
            total=d['total'][1]
            for key in ('spans','contended','retries','wait-tsc','hold-tsc'):
                need(sum(d[x][1][key] for x in PATHS[:-1])==total[key], f'{key} path sum')
            for key in ('wait-max','hold-max'):
                need(max(d[x][1][key] for x in PATHS[:-1])==total[key], f'{key} path maximum')
            if cpus==1 or not meter:
                need(all(v[k]==0 for _,v in d.values() for k in v), 'UP/meter-off counters not zero')
            else:
                need(total['spans']>0, 'multicore meter has no completed spans')
            need(all(starts_phase[p] < d[path][0] < dones_phase[p] for path in PATHS),
                 'meter rows outside phase')

    if cpus > 1 and meter:
        for phase, path, units in ((2, 'getpid', 10000), (3, 'cell-transition', 2000)):
            for cpu in range(cpus):
                workers = sum(i % cpus == cpu for i in range(6))
                need(lockdata[phase][cpu][path][1]['spans'] == workers * units,
                     'meter path work count correspondence')

    ok=rows(lines,'SMP SCALE OK ')
    boot=[i for i,line in enumerate(lines) if line=='ABSD BOOT OK']
    need(len(ok)==1 and fields(ok[0][1])=={'phases':'3','workers':'6','tasks':'18',
         'work':'exact','table':'empty','objects':'empty','frames':'baseline','ap':'idle'},
         'scale terminal fence mismatch')
    need(dones_phase[3] < exit_idx[1] < ok[0][0], 'root terminal outcome precedes full work completion/fence')
    need(len(boot)==1 and ok[0][0] < boot[0], 'boot completion order/multiplicity')
    need(max(i for p in (1,2,3) for i in dones_phase.values()) < ok[0][0],
         'terminal success before phase completion')
    need(sum(line.startswith('SMP SCALE OK ') for line in lines)==1, 'duplicate success')
    done_rows=rows(lines,'SMP SCALE DONE ')
    return {'cpus':cpus,'meter':meter,'config':cfg[0][1], 'actors':[x[1] for x in actors],
            'work':[x[1] for x in workrows], 'cpu':[x[1] for x in cpur],
            'locks':[x[1] for x in locks], 'timer':[x[1] for x in starts],
            'start':[x[1] for x in rows(lines,'SMP SCALE START ')],
            'done':[x[1] for x in done_rows],
            'success':ok[0][1], 'boot_index':boot[0]}


def check_metrics(path, cpus, lines):
    m=json.loads(Path(path).read_text())
    expected_mode='legacy-qemu-default' if cpus==1 else 'explicit-smp-scheduler-test'
    expected_guest=None if cpus==1 else {'sockets':1,'cores':cpus,'threads':1}
    need(m.get('vcpus')==cpus and m.get('topology')=='separate'
         and m.get('guest_topology_mode')==expected_mode
         and m.get('guest_topology')==expected_guest,
         'QEMU run metrics topology/vCPU mismatch')
    for key in ('wall_seconds','qemu_user_seconds','qemu_system_seconds'):
        value=m.get(key)
        need(isinstance(value,(int,float)) and math.isfinite(value) and value>=0,
             f'invalid QEMU run metric {key}')
    observed=m.get('serial_observations_seconds')
    expected={line for line in lines if line.startswith(('SMP SCALE START ','SMP SCALE DONE '))}
    need(isinstance(observed,dict) and set(observed)==expected and len(expected)==6,
         'QEMU serial observation set differs from scale phase boundaries')
    need(all(isinstance(v,(int,float)) and math.isfinite(v) and v>=0 for v in observed.values()),
         'invalid serial observation time')
    for phase in (1,2,3):
        start=next(x for x in expected if x.startswith(f'SMP SCALE START phase={phase} '))
        done=next(x for x in expected if x.startswith(f'SMP SCALE DONE phase={phase} '))
        need(0 <= observed[start] <= observed[done] <= m['wall_seconds'], 'metric phase chronology')
        if phase > 1:
            prev=next(x for x in expected if x.startswith(f'SMP SCALE DONE phase={phase-1} '))
            need(observed[prev] <= observed[start], 'metric inter-phase chronology')
    return m


def self_test(lines, cpus, expected_meter):
    controls=[]
    def rejected(name, mutate):
        changed=list(lines); mutate(changed)
        need(changed != lines, f'mutation did not change receipt: {name}')
        try: check_lines(changed,cpus,expected_meter)
        except (AssertionError, StopIteration, KeyError, ValueError): controls.append(name); return
        raise AssertionError(f'mutation accepted: {name}')
    def index(prefix): return next(i for i,x in enumerate(lines) if x.startswith(prefix))
    def delete(prefix):
        i=next(i for i,x in enumerate(lines) if x.startswith(prefix)); return lambda r:r.pop(i)
    def duplicate(prefix):
        i=index(prefix); return lambda r:r.insert(i+1,r[i])
    def edit(prefix, old, new):
        i=index(prefix); return lambda r:r.__setitem__(i,r[i].replace(old,new,1))
    rejected('missing-last-actor',delete('SMP SCALE ACTOR '))
    rejected('leading-zero',edit('SMP SCALE CPU ', 'cpu=0', 'cpu=00'))
    rejected('malformed-actor-marker',edit('SMP SCALE ACTOR ', 'SMP SCALE ACTOR ', 'SMP SCALE ACTORjunk '))
    rejected('duplicate-actor',duplicate('SMP SCALE ACTOR '))
    wi=index('SMP SCALE WORK ')
    workf=fields(lines[wi]); old=workf['checksum']
    actor_rows=rows(lines, 'SMP SCALE ACTOR ')
    first, second=actor_rows[:2]
    rejected('duplicate-pid-new-generation',lambda r:r.__setitem__(second[0], r[second[0]].replace('pid='+second[2]['pid'], 'pid='+first[2]['pid'])))
    if cpus > 1:
        rejected('duplicate-generation-new-pid',lambda r:r.__setitem__(second[0], r[second[0]].replace('generation='+second[2]['generation'], 'generation='+first[2]['generation'])))
    rejected('missing-worker-terminal',lambda r:r.pop(next(i for i,x in enumerate(r) if x.startswith('USER EXIT pid='+first[2]['pid']+' '))))
    rejected('wrong-checksum',edit('SMP SCALE WORK ',f'checksum={old}',f'checksum={int(old)+1}'))
    rejected('wrong-units',edit('SMP SCALE WORK ','units=67108864','units=67108863'))
    rejected('wrong-cpu',edit('SMP SCALE CPU ','cpu=0','cpu=99'))
    cindex=index('SMP SCALE CPU '); cf=fields(lines[cindex]); old=cf['dispatch']
    rejected('zero-dispatch',edit('SMP SCALE CPU ',f'dispatch={old}',f'dispatch=0'))
    total_i=next(i for i,x in enumerate(lines) if x.startswith('SMP SCALE LOCK ') and 'path=total' in x)
    rejected('bad-path-total',lambda r:r.__setitem__(total_i,r[total_i].replace('path=total','path=other',1)))
    rejected('duplicate-lock-path',duplicate('SMP SCALE LOCK '))
    rejected('bad-counter-sum',edit('SMP SCALE LOCK ','spans=','spans=999999'))
    if any(x.startswith('SMP TIMER START ') for x in lines):
        rejected('wrong-timer-quantum',edit('SMP TIMER START ','quantum-tsc=16777216','quantum-tsc=16777215'))
    done_i=next(i for i,x in enumerate(lines) if x.startswith('SMP SCALE DONE '))
    done_fields=fields(lines[done_i]); tsc=done_fields['tsc']
    rejected('zero-duration',edit('SMP SCALE DONE ',f'tsc={tsc}','tsc=0'))
    rejected('duplicate-key',lambda r:r.__setitem__(index('SMP SCALE ACTOR '),
        r[index('SMP SCALE ACTOR ')]+' cpu=0'))
    rejected('late-actor',lambda r:r.insert(index('SMP SCALE START '),r.pop(index('SMP SCALE ACTOR '))))
    rejected('early-success',lambda r:r.insert(index('SMP SCALE START '),r.pop(index('SMP SCALE OK '))))
    rejected('missing-success',delete('SMP SCALE OK '))
    rejected('duplicate-success',duplicate('SMP SCALE OK '))
    if cpus > 1 and expected_meter:
        pair = [i for i,x in enumerate(lines) if x.startswith('SMP SCALE LOCK phase=2 cpu=0 ') and fields(x)['path'] in ('getpid', 'other')]
        need(len(pair)==2, 'attribution control pair missing')
        def crosswire(r):
            for i in pair:
                p=fields(r[i])['path']; r[i]=r[i].replace('path='+p, 'path='+('other' if p=='getpid' else 'getpid'))
        rejected('partition-preserving-wrong-path', crosswire)
    rejected('missing-boot',lambda r:r.__setitem__(slice(None),[x for x in r if x!='ABSD BOOT OK']))
    return controls


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('serial'); ap.add_argument('placement'); ap.add_argument('--metrics',required=True)
    ap.add_argument('--cpus',type=int,required=True)
    ap.add_argument('--results'); ap.add_argument('--mutants',action='store_true')
    ap.add_argument('--meter',type=int,choices=(0,1),required=True)
    a=ap.parse_args(); lines=Path(a.serial).read_text(errors='replace').splitlines()
    check_placement(a.placement,a.cpus)
    result=check_lines(lines,a.cpus,a.meter)
    result['qemu_metrics']=check_metrics(a.metrics,a.cpus,lines)
    if a.mutants:
        result['mutation_controls']=self_test(lines,a.cpus,a.meter)
    if a.results:
        Path(a.results).write_text(json.dumps(result,indent=2)+'\n')
    print(f"SMP SCALE RECEIPT OK cpus={a.cpus} meter={int(result['meter'])}" +
          (f" mutants={len(result['mutation_controls'])}" if a.mutants else ''))

if __name__=='__main__': main()
