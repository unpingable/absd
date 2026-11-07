#!/usr/bin/env python3
"""Bounded host controls: require the intended assertion failure, never a build failure."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=False)
variants = {
    'absd_mutant_wait_skip_recheck': 'register_rechecks_arrival_before_arming',
    'absd_mutant_wait_no_eof': 'writer_close_after_registration_completes_eof',
    'absd_mutant_handle_ignore_tag': 'close_and_replaced_handle_do_not_inherit_readiness',
    'absd_mutant_wait_ignore_revocation': 'registered_revocation_is_terminal_even_without_a_deadline',
    'absd_mutant_wait_ignore_timeout': 'deadline_and_arrival_races_complete_exactly_once_in_lock_order',
}
source = root / 'src/readable_wait.rs'
source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
results = []
for mutant, test in [('positive', None), *variants.items()]:
    # Caller admits storage/CPU and owns this isolated output directory.
    env = os.environ.copy()
    env['CARGO_BUILD_JOBS'] = '2'
    env['CARGO_TARGET_DIR'] = str(out / 'target')
    env['RUSTFLAGS'] = '' if mutant == 'positive' else f'--cfg {mutant}'
    command = ['cargo', 'test', '--offline', '--lib']
    if test:
        command += [f'readable_wait::tests::{test}', '--', '--exact']
    else:
        command += ['readable_wait::']
    with (out / f'{mutant}.log').open('w') as log:
        result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
    text = (out / f'{mutant}.log').read_text()
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash, 'source changed during controls'
    if mutant == 'positive':
        assert result.returncode == 0 and '26 passed; 0 failed' in text, text[-3000:]
    else:
        assert result.returncode == 101, (mutant, result.returncode)
        assert 'running 1 test' in text and '0 passed; 1 failed' in text, text[-3000:]
        assert f'test readable_wait::tests::{test} ... FAILED' in text, text[-3000:]
        assert 'assertion `left == right` failed' in text, text[-3000:]
        assert 'error[E' not in text and 'could not compile' not in text, text[-3000:]
    results.append({'variant': mutant, 'test': test, 'exit': result.returncode,
                    'log_sha256': hashlib.sha256((out / f'{mutant}.log').read_bytes()).hexdigest()})
    print(mutant, 'PASS' if mutant == 'positive' else 'REJECTED BY EXPECTED ASSERTION', flush=True)
(out / 'RESULT.json').write_text(json.dumps({'source_sha256': source_hash, 'results': results,
    'scope': 'Actual wait-set, HandleTable, PipeTable, Process and ownership model host checks; not a native guest race observation.'}, indent=2) + '\n')
