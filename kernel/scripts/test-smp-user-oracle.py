#!/usr/bin/env python3
"""Substitution vectors must fail the exact log oracle."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile

spec = importlib.util.spec_from_file_location('oracle', Path(__file__).with_name('check-smp-user.py'))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
source = Path(sys.argv[1]).read_text()
lines = source.splitlines()
vectors = {
    'missing-case': '\n'.join(x for x in lines if x != 'SMP USER CASE id=17 cpu=0') + '\n',
    'duplicate-terminal': source + 'ABSD BOOT OK\n',
    'missing-overlap': '\n'.join(x for x in lines if not x.startswith('SMP USER OVERLAP cpu=1')) + '\n',
    'missing-reclaim': '\n'.join(x for x in lines if not x.startswith('SMP USER RECLAIM')) + '\n',
    'early-ack': source.replace('SMP USER DEPART seq=5', 'SMP USER ACK seq=5', 1),
    'missing-ipi': '\n'.join(x for x in lines if 'path=ring3-ipi' not in x) + '\n',
}
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / 'vector.log'
    for name, text in vectors.items():
        assert text != source, name
        path.write_text(text)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                oracle.check(path)
        except AssertionError:
            print('ORACLE REJECT', name)
        else:
            raise AssertionError('accepted negative vector ' + name)
