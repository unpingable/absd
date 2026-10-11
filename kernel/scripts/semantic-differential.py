#!/usr/bin/env python3
"""Strict SEM1 comparison. Only named native evidence is adapted; no wildcard drift."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from arch_evidence import aarch64, x86_64

LINE = re.compile(r'^(SEM1|NAT1) ([1-9][0-9]*) ([a-z_]+) ([0-9a-f]{16}) ([0-9a-f]{16}) ([0-9a-f]{16})$')
EVENTS = {'abi', 'unknown_syscall', 'pointer_refused', 'handle_refused', 'copyout_readonly', 'heap_cross_page', 'unmapped_refused', 'resource_accounts', 'resource_balance', 'cell_created', 'read_grant', 'rights_refused', 'handle_closed', 'revoked_refused', 'cell_transition', 'stale_refused', 'spawn_identity', 'wait_exit', 'transfer_children', 'cell_final', 'cell_closed', 'fault_wait', 'capacity_refused', 'kill_wait', 'machine_grant', 'machine_stop_rights', 'machine_recover_rights', 'machine_stop_invalid', 'machine_stop_handle', 'machine_recover_handle', 'machine_restart_handle', 'machine_wrong_kind', 'terminal'}
ERRORS = {'unknown_syscall': -38, 'pointer_refused': -14, 'handle_refused': -9, 'copyout_readonly': -14, 'unmapped_refused': -14, 'rights_refused': -1, 'revoked_refused': -9, 'stale_refused': -116, 'capacity_refused': -11, 'machine_stop_rights': -1, 'machine_recover_rights': -1, 'machine_stop_invalid': -22, 'machine_stop_handle': -9, 'machine_recover_handle': -9, 'machine_restart_handle': -9, 'machine_wrong_kind': -9}

def parse(text, architecture):
    semantic, native = [], []
    for line in text.splitlines():
        if not line.startswith(('SEM', 'NAT')):
            continue
        match = LINE.fullmatch(line)
        assert match, 'malformed or unknown-version semantic/native record'
        prefix, sequence, event, *words = match.groups()
        row = dict(sequence=int(sequence), event=event, words=[int(w, 16) for w in words])
        if prefix == 'SEM1':
            assert event in EVENTS, 'unknown semantic event'
            assert row['sequence'] == len(semantic) + 1, 'missing/repeated/reordered semantic record'
            semantic.append(row)
        else:
            assert semantic and row['sequence'] == semantic[-1]['sequence'], 'native record lost semantic parent'
            assert event in ('frame_geometry', 'fault_wait'), 'unqualified native evidence kind'
            native.append(row)
    assert len(semantic) == 481, 'logical corpus incomplete'
    assert semantic[0]['event'] == 'abi' and semantic[0]['words'] == [1, 40, 32], 'ABI/record contract drift'
    assert semantic[-1]['event'] == 'terminal' and semantic[-1]['words'] == [0, 1, 1], 'terminal state drift'
    for event, code in ERRORS.items():
        rows = [r for r in semantic if r['event'] == event]
        assert len(rows) == 1 and rows[0]['words'] == [code & ((1 << 64) - 1), 0, 0], 'refusal classification drift: ' + event
    cells = [r for r in semantic if r['event'] == 'cell_final']
    assert len(cells) == 1 and cells[0]['words'] == [201, 201, 0], 'Cell transition history drift'
    waits = [r for r in semantic if r['event'] == 'wait_exit']
    kills = [r for r in semantic if r['event'] == 'kill_wait']
    identities = [r for r in semantic if r['event'] == 'spawn_identity']
    assert len(waits) == 206 and len(kills) == 15 and len(identities) == 222, 'lifecycle corpus drift'
    assert sum(r['words'][2] == 7 for r in waits) == 201 and all(r['words'][1] == 1 for r in waits)
    assert all(r['words'][1:] == [3, 0] for r in kills)
    assert [r['words'][0] for r in identities] == list(range(2, 224)), 'spawn identity/order drift'
    assert all(r['words'][1] == 1 for r in identities), 'parent authority drift'
    balances = [r for r in semantic if r['event'] == 'resource_balance']
    assert [r['words'] for r in balances] == [[0, 0, phase] for phase in range(1, 6)], 'resource reclamation drift'
    accounts = [r for r in semantic if r['event'] == 'resource_accounts']
    assert len(accounts) == 5 and all(r['words'] == [1, 2, 0] for r in accounts), 'object/handle/process accounting drift'
    assert len(native) == 6, 'native evidence coverage drift'
    frames = [r for r in native if r['event'] == 'frame_geometry']
    assert len(frames) == 5 and all(r['words'][0] == r['words'][1] > 0 and r['words'][2] == 4096 for r in frames), 'native frame balance mismatch'
    assert {r['sequence'] for r in frames} == {r['sequence'] for r in balances}, 'frame evidence lost resource lineage'
    faults = [r for r in native if r['event'] == 'fault_wait']
    disposition = [r for r in semantic if r['event'] == 'fault_wait']
    assert len(faults) == len(disposition) == 1 and faults[0]['sequence'] == disposition[0]['sequence']
    assert disposition[0]['words'] == [5, 2, 0], 'fault disposition drift'
    adaptor = {'x86_64': x86_64, 'aarch64': aarch64}[architecture]
    fault = adaptor.memory_fault(*faults[0]['words'])
    assert fault == dict(kind='permission', access='write', from_user=True, address=0x100000), 'normalized fault semantics drift'
    return dict(semantic=semantic, native=native, normalized_fault=fault)

def compare(x86, arm):
    assert x86['semantic'] == arm['semantic'], 'semantic records differ; normalization cannot repair them'
    assert x86['normalized_fault'] == arm['normalized_fault'], 'normalized fault differs'

def controls(text, x86):
    rows = []
    cases = [('cell_final', 1, 200), ('rights_refused', 0, (-9) & ((1 << 64) - 1)), ('resource_balance', 0, 1), ('wait_exit', 2, 99), ('abi', 0, 2)]
    for name, word, value in cases:
        lines = text.splitlines();changed = False
        for i, line in enumerate(lines):
            m = LINE.fullmatch(line)
            if m and m[1] == 'SEM1' and m[3] == name:
                fields = line.split();fields[3+word] = f'{value:016x}';lines[i] = ' '.join(fields);changed = True;break
        assert changed
        try:
            compare(x86, parse('\n'.join(lines), 'aarch64'))
        except (AssertionError, ValueError) as error:
            rows.append(dict(control=name, rejected=str(error)))
        else:
            raise AssertionError('semantic mutation accepted: ' + name)
    # Remove a lineage record without renumbering: the next record must refuse.
    lines = text.splitlines();index = next(i for i, s in enumerate(lines) if s.startswith('SEM1 ') and ' handle_closed ' in s);del lines[index]
    try:
        compare(x86, parse('\n'.join(lines), 'aarch64'))
    except (AssertionError, ValueError) as error:
        rows.append(dict(control='missing_close_record', rejected=str(error)))
    else:
        raise AssertionError('missing semantic record accepted')
    return rows

def main():
    p = argparse.ArgumentParser();p.add_argument('--x86', type=Path, required=True);p.add_argument('--arm', type=Path, required=True);p.add_argument('--output', type=Path, required=True);a = p.parse_args()
    result = dict(schema_version=1, x86_serial_sha256=hashlib.sha256(a.x86.read_bytes()).hexdigest(), arm_serial_sha256=hashlib.sha256(a.arm.read_bytes()).hexdigest(), comparator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), adapter_sha256={name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() for name, module in [('x86_64', x86_64), ('aarch64', aarch64)]})
    try:
        x86 = parse(a.x86.read_text(), 'x86_64');arm = parse(a.arm.read_text(), 'aarch64');compare(x86, arm)
        result.update(disposition='PASS', semantic_records=len(arm['semantic']), x86=x86, arm=arm, negative_controls=controls(a.arm.read_text(), x86), differences=[dict(classification='required architecture-specific difference', field='native fault identity/syndrome', disposition='permission/write/from-user/address preserved'), dict(classification='required architecture-specific difference', field='root frame footprint', disposition='raw counts retained; exact per-ISA baseline return and every nonzero delta compared/refused')], not_earned=['SMP scheduler equivalence from this UP comparison','Kernel receipt/persistence lineage ABI, which has no live implementation in this kernel','B3 expanded exception paths','Full catalog or served boot'])
    except Exception as error:
        result.update(disposition='FAIL', error=str(error))
    a.output.parent.mkdir(parents=True, exist_ok=True);a.output.write_text(json.dumps(result, indent=2) + '\n');print(result['disposition'], result.get('error', '481 semantic records matched; six negative controls rejected'))
    raise SystemExit(0 if result['disposition'] == 'PASS' else 1)

if __name__ == '__main__':
    main()
