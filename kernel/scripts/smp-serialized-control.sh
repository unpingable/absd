#!/bin/sh
# Closed all-CPU0 substitution; reject it through real fixture CPU identity.
set -eu
kernel=${1:?qualified ELF}; out=${2:?new directory}
mkdir "$out"
result=1
trap 'printf "%s\n" "$result" > "$out/status"' EXIT
if sh scripts/smp-user-run.sh "$kernel" "$out/case" 'smp-user-test smp-user-preempt smp-scheduler-test smp-user-serialized'; then exit 1; fi
test "$(cat "$out/case/qemu.status")" -eq 7
python3 - "$out/case/serial.log" <<'PY'
import re, sys
from pathlib import Path
lines = Path(sys.argv[1]).read_text().splitlines()
def check(rows):
    injection = 'SMP USER INJECT serialized-placement=1 cpu=0'
    assert rows.count(injection) == 1
    indices = [i for i, line in enumerate(rows) if line.startswith('SMP USER SERIALIZED CPU ')]
    assert len(indices) == 2
    matches = [re.fullmatch(r'SMP USER SERIALIZED CPU cpu=0 pid=(\d+) role=1 cpl=3', rows[i])
               for i in indices]
    assert all(matches) and len({m[1] for m in matches}) == 1
    pid = int(matches[0][1])
    spawn = f'SPAWN OK pid={pid} parent=1 program=smp-user'
    assert rows.count(spawn) == 1
    failure = 'SMP USER FIXTURE FAILED role=1 error=fixed actor placement'
    assert rows.count(failure) == 1
    panic = next(i for i, line in enumerate(rows) if line.startswith('ABSD PANIC:'))
    assert rows.index(injection) < rows.index(spawn) < indices[0] < indices[1] < rows.index(failure) < panic
    assert 'ABSD BOOT OK' not in rows
    return pid
pid = check(lines)
for change in ('late-witness', 'wrong-pid', 'late-spawn', 'missing-witness', 'missing-failure'):
    rows = lines[:]
    indices = [i for i, line in enumerate(rows) if line.startswith('SMP USER SERIALIZED CPU ')]
    if change == 'late-witness':
        record = rows.pop(indices[1])
        after = rows.index('SMP USER FIXTURE FAILED role=1 error=fixed actor placement')
        rows.insert(after + 1, record)
    elif change == 'wrong-pid':
        rows[indices[1]] = re.sub(r'pid=\d+', 'pid=999999', rows[indices[1]], count=1)
    elif change == 'late-spawn':
        record = f'SPAWN OK pid={pid} parent=1 program=smp-user'
        rows.remove(record)
        after = next(i for i, line in enumerate(rows) if line.startswith('SMP USER SERIALIZED CPU '))
        rows.insert(after + 1, record)
    elif change == 'missing-witness':
        rows.pop(indices[1])
    else:
        rows.remove('SMP USER FIXTURE FAILED role=1 error=fixed actor placement')
    assert rows != lines
    try:
        check(rows)
    except (AssertionError, ValueError, StopIteration):
        continue
    raise AssertionError(f'accepted placement receipt mutation: {change}')
print(f'SMP CPU0 placement control rejected pid={pid} role=1 receipt-controls=5')
PY
result=0
