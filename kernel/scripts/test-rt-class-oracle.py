#!/usr/bin/env python3
"""Negative controls: reconstructing logs must reject broken scheduler evidence."""
import re
import runpy
import sys
import tempfile
from pathlib import Path

check = runpy.run_path(str(Path(__file__).with_name('check-rt-class.py')))['check']
args = sys.argv[1:]
structural_only = '--structural-only' in args
args = [arg for arg in args if arg != '--structural-only']
if len(args) != 1:
    raise SystemExit('usage: test-rt-class-oracle.py [--structural-only] SERIAL_LOG')
source = Path(args[0]).read_text()
controls = {
    'wake reset': lambda s: re.sub(r'(RT STATE event=wake[^\n]*remaining=)\d+', r'\g<1>99', s, count=1),
    'budget overrun': lambda s: re.sub(r'(RT CHARGE[^\n]*consumed=)\d+', r'\g<1>99', s, count=1),
    'exhaustion bypass': lambda s: re.sub(r'(RT STATE event=exhaust[^\n]*to=)4', r'\g<1>1', s, count=1),
    'queued instance': lambda s: re.sub(r'(RT RELEASE[^\n]*seq=)1', r'\g<1>2', s, count=1),
    'wrong priority': lambda s: re.sub(r'(RT SELECT[^\n]*priority=)2', r'\g<1>1', s, count=1),
    'missing miss': lambda s: re.sub(r'(RT RELEASE[^\n]*missed=)1 ', r'\g<1>0 ', s, count=1),
    'missing teardown': lambda s: re.sub(r'^RT REMOVE[^\n]*\n', '', s, count=1, flags=re.M),
    'missing exhaustion': lambda s: re.sub(r'^RT EXHAUST[^\n]*\n', '', s, count=1, flags=re.M),
    'missing case ledger': lambda s: re.sub(r'^RT CASE id=12\n', '', s, count=1, flags=re.M),
}

def remove_case_task_history(text, case_id):
    lines = text.splitlines()
    current_case = None
    task_pid = None
    for line in lines:
        if line.startswith('RT CASE '):
            current_case = int(re.search(r'id=(\d+)', line)[1])
        elif current_case == case_id and line.startswith('RT CONFIG '):
            task_pid = int(re.search(r'pid=(\d+)', line)[1])
            break
    assert task_pid is not None, f'case {case_id} configured task'
    return '\n'.join(
        line for line in lines
        if not (line.startswith('RT ') and re.search(rf'\bpid={task_pid}\b', line))
    ) + '\n'

controls['missing task records'] = lambda s: remove_case_task_history(s, 12)

def truncate_final_teardown(text):
    # Idle diagnostics are optional; remove the final task's teardown record
    # regardless of the following diagnostics or terminal census record.
    records = list(re.finditer(r'^RT REMOVE pid=\d+ tick=\d+\n', text, re.M))
    assert records, 'final task teardown record'
    final = records[-1]
    return text[:final.start()] + text[final.end():]


controls['truncated history'] = truncate_final_teardown
check(args[0], report=False, structural_only=structural_only)
check(args[0], report=False, structural_only=True)
with tempfile.TemporaryDirectory(prefix='absd-rtc-oracle-') as directory:
    path = Path(directory) / 'serial.log'
    for name, mutate in controls.items():
        changed = mutate(source)
        assert changed != source, name
        path.write_text(changed)
        for structural_only in (False, True):
            try:
                check(path, report=False, structural_only=structural_only)
            except (AssertionError, IndexError, KeyError):
                pass
            else:
                mode = 'structural' if structural_only else 'strict'
                raise AssertionError(f'accepted {mode} negative control: {name}')

    # Workload-progress minima are intentionally omitted in structural mode,
    # while strict mode continues to reject the same altered record.
    changed = re.sub(r'(RT PERIOD[^\n]* normal=)\d+', r'\g<1>0', source, count=1)
    assert changed != source, 'normal progress mutation'
    path.write_text(changed)
    try:
        check(path, report=False)
    except (AssertionError, IndexError, KeyError):
        pass
    else:
        raise AssertionError('strict mode accepted missing normal progress')
    check(path, report=False, structural_only=True)
print(f'RT class oracle: strict and structural modes rejected {len(controls)} structural negatives; '
      'structural mode skipped the normal-progress negative')
