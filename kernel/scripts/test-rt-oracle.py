#!/usr/bin/env python3
"""Deterministic negative controls for the RT serial evidence checker."""
import contextlib
import io
import re
import runpy
import sys
import tempfile
from pathlib import Path

checker = runpy.run_path(str(Path(__file__).with_name('check-rt.py')))['check']
source = Path(sys.argv[1]).read_text()
controls = {
    'late dispatch': lambda s: re.sub(r'latency=0', 'latency=2', s, count=1),
    'missed release': lambda s: re.sub(r'skipped=0', 'skipped=1', s, count=1) if 'skipped=' in s else re.sub(r'missed=0', 'missed=1', s, count=1),
    'no normal service': lambda s: re.sub(r'normal=\d+', 'normal=0', s, count=1),
    'budget exceeded': lambda s: re.sub(r'(RT PERIOD[^\n]*consumed=)\d+', r'\g<1>6', s, count=1),
    'no displacement': lambda s: re.sub(r'(RT DISPATCH[^\n]*from=)\d+', r'\g<1>1', s, count=1),
    'missing exhaustion': lambda s: re.sub(r'^RT EXHAUST.*\n', '', s, count=1, flags=re.M),
}
with tempfile.TemporaryDirectory(prefix='absd-rt-oracle-') as directory:
    path = Path(directory) / 'serial.log'
    with contextlib.redirect_stdout(io.StringIO()):
        normal_pid = int(sys.argv[2]) if len(sys.argv) > 2 else 2
        checker(sys.argv[1], normal_pid)
        for name, mutate in controls.items():
            mutated = mutate(source)
            assert mutated != source, name
            path.write_text(mutated)
            try:
                checker(path, normal_pid)
            except (AssertionError, IndexError):
                pass
            else:
                raise AssertionError(f'oracle accepted: {name}')
print(f'RT oracle: accepted original; rejected {len(controls)} negative controls')
