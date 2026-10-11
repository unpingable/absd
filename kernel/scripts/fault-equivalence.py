#!/usr/bin/env python3
"""Native fault lineage + kernel-normalized evidence + shared terminal policy."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from arch_evidence import aarch64, x86_64

FL = re.compile(r'^FLT1 (\d+) (\d+) ([12]) ([0-9a-f]{16}) ([0-9a-f]{16}) ([0-9a-f]{16})$', re.M)
NF = re.compile(r'^FAULT1 pid=(\d+) kind=([a-z-]+) access=(read|write|execute|none) user=1 address=(0x[0-9a-f]+)$', re.M)
RAW = re.compile(r'^USER FAULT pid=(\d+) vector=(\d+) address=(0x[0-9a-f]+) error=(0x[0-9a-f]+)$', re.M)

def parse(text, isa):
    rows = FL.findall(text)
    assert [int(r[0]) for r in rows] == list(range(10, 18)), 'fault corpus missing/reordered'
    assert text.splitlines().count('PORTABLE B3 FAULT RECLAMATION FP HEALTH OK') == 1
    normalized = {int(pid): dict(kind=kind, access=access, from_user=True, address=int(address, 16)) for pid, kind, access, address in NF.findall(text)}
    raw = {int(pid): [int(v), int(a, 16), int(e, 16)] for pid, v, a, e in RAW.findall(text)}
    result = []
    for role, pid, terminal, vector, address, error in rows:
        role, pid, terminal = int(role), int(pid), int(terminal)
        native = [int(vector, 16), int(address, 16), int(error, 16)]
        if role == 17:
            assert terminal == 1 and native == [0, 0, 0] and pid not in normalized, 'permitted stack growth did not resume'
            result.append(dict(case=role, disposition='exited', native=native));continue
        assert terminal == 2 and raw.get(pid) == native, 'native wait/kernel lineage mismatch'
        v, a, e = native
        if (isa == 'x86_64' and v == 14) or (isa == 'aarch64' and v in (32, 36)):
            fault = {'x86_64': x86_64, 'aarch64': aarch64}[isa].memory_fault(v, a, e)
        else:
            fault = dict(kind='undefined' if (isa == 'x86_64' and v == 6) or (isa == 'aarch64' and v == 0) else 'other', access='none', from_user=True, address=a)
        assert normalized.get(pid) == fault, 'actual kernel normalization differs from architecture mapping'
        expected = {10: ('translation', 'read'), 11: ('permission', 'write'), 12: ('permission', 'execute'), 13: ('undefined', 'none'), 14: ('other', 'none') if isa == 'x86_64' else ('alignment', 'read'), 15: ('translation', 'write'), 16: ('permission', 'write')}[role]
        assert (fault['kind'], fault['access']) == expected, 'fault class/access differs from fixture'
        fixed = {10: 0x8011fff000, 12: 0x8010000000, 15: 0x8007fffff0, 16: 0x100000}
        if role in fixed:
            assert a == fixed[role], 'semantic fault address changed'
        result.append(dict(case=role, disposition='faulted/reclaimed', native=native, normalized=fault))
    # The same invalid-pointer and copyout cases must refuse without a task fault.
    for event in ('pointer_refused', 'copyout_readonly', 'unmapped_refused'):
        assert re.search(r'^SEM1 \d+ '+event+r' fffffffffffffff2 0000000000000000 0000000000000000$', text, re.M)
    return result

def compare(x, a):
    assert [(r['case'], r['disposition']) for r in x] == [(r['case'], r['disposition']) for r in a]
    for xr, ar in zip(x, a):
        if xr['case'] not in (14, 17):
            assert all(xr['normalized'][field] == ar['normalized'][field] for field in ('kind', 'access', 'from_user'))

def main():
    p = argparse.ArgumentParser();p.add_argument('--x86', type=Path, required=True);p.add_argument('--arm', type=Path, required=True);p.add_argument('--output', type=Path, required=True);args=p.parse_args()
    result = dict(schema_version=1, validator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), traces={isa: dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for isa,path in [('x86',args.x86),('arm',args.arm)]})
    try:
        x=parse(args.x86.read_text(),'x86_64');a=parse(args.arm.read_text(),'aarch64');compare(x,a)
        controls=[]
        text=args.arm.read_text()
        first_pid=int(FL.findall(text)[0][1])
        missing_native='\n'.join(line for line in text.splitlines() if not line.startswith(f'USER FAULT pid={first_pid} '))
        for name, candidate in [('wrong_nx_class',text.replace('kind=permission access=execute','kind=other access=execute')),('missing_native',missing_native),('missing_health',text.replace('PORTABLE B3 FAULT RECLAMATION FP HEALTH OK',''))]:
            try: parse(candidate,'aarch64')
            except (AssertionError,ValueError) as error:controls.append(dict(name=name,rejected=str(error)))
            else:raise AssertionError('negative control accepted '+name)
        result.update(disposition='PASS',x86=x,arm=a,negative_controls=controls,architecture_difference='MOVAPS #GP lacks data alignment cause/address; LDXR exposes Alignment/read/FAR. Both shared dispositions faulted/reclaimed.',not_earned=['ARM arithmetic FP trap enabling','All native exception classes','Cross-ISA live state transfer'])
    except Exception as error:result.update(disposition='FAIL',error=str(error))
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2)+'\n');print(result['disposition'],result.get('error','eight cases + pointer refusals + post-fault FP/resource health'))
    raise SystemExit(0 if result['disposition']=='PASS' else 1)
if __name__=='__main__':main()
