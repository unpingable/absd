#!/usr/bin/env python3
"""Actual init relay/publication through unchanged paired host consumers; no guest."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True

def item(source, marker):
    start = source.index(marker)
    at = source.index('{', start)
    depth, end = 1, at + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

parser = argparse.ArgumentParser()
parser.add_argument('--platform', type=Path, required=True)
args = parser.parse_args()
sys.path.insert(0, str(args.platform.resolve() / 'scripts'))
import storage_fence_resume as sfr
import ssh_absd
init = (ROOT / 'user/src/bin/init.rs').read_text()
user = (ROOT / 'user/src/lib.rs').read_text()
assert init.count('external_worker_chunk(') == 3, 'both actual stream call sites must use the tested publication function'
production = '\n'.join(item(user, marker) for marker in ('pub struct LineBuffer', 'impl LineBuffer', 'impl core::fmt::Write for LineBuffer'))
production += '\n' + '\n'.join(item(init, 'fn ' + name + '(') for name in ('external_line', 'external_chunk', 'external_split_notice', 'external_worker_chunk', 'external_worker_startup', 'external_output_end'))
production += '\n' + init[init.index('static mut FSD_LOG_READERS:'):init.index('fn finish_fsd_logs(')]
production += '\n' + item(init, 'fn finish_fsd_logs(')
fixture = (ROOT / 'scripts/fixtures/local-console-startup.rs').read_text().replace('@ROOT@', str(ROOT)).replace('@PRODUCTION@', production)
ident = '0123456789abcdef0123456789abcdef'
fsd = f'RECOVERY WRITABLE RESUMED id={ident} previous=failed fs_seq=1926 ledger_seq=2\nRELEASE OK release=fixture\n'.encode()
network = b'SSH HOST KEY LOADED ssh-ed25519 fixture-public SHA256:fixture\n' + b'x' * 300 + b'\nSSH RECOVERY streak=1\nSSH LISTENING port=22 authorized_keys=1 preauth_per_source=2\n'
with tempfile.TemporaryDirectory(prefix='absd-local-startup-') as temporary:
    out = Path(temporary)
    (out / 'fixture.rs').write_text(fixture)
    subprocess.run(['rustc', '--edition=2024', '--crate-name', 'absd_abi', '--crate-type=rlib', str(ROOT / 'abi/src/lib.rs'), '-o', str(out / 'libabsd_abi.rlib')], check=True)
    subprocess.run(['rustc', '--edition=2024', str(out / 'fixture.rs'), '--extern', 'absd_abi=' + str(out / 'libabsd_abi.rlib'), '-o', str(out / 'fixture')], check=True)
    (out / 'fsd.input').write_bytes(fsd)
    cases = [(mode, chunk, split) for mode in ('network-local', 'local-1', 'local-0', 'headless') for chunk, split in ((1, 1), (7, 17), (96, 256), (256, 3))]
    cases.append(('network-race', 256, 256))
    for mode, chunk, split in cases:
        work = network if mode in ('network-local', 'network-race', 'headless') else f'SSH RECOVERY streak=1\nLOCAL READY boot=0123456789abcdef0123456789abcdef enrolled={mode[-1]}\n'.encode()
        current_fsd = fsd if mode != 'network-race' else fsd.replace(b'RELEASE OK', (b'FSD queued startup padding ' + b'x' * 70 + b'\n') * 6 + b'RELEASE OK')
        (out / 'fsd.input').write_bytes(current_fsd)
        (out / 'worker.input').write_bytes(work)
        subprocess.run([str(out / 'fixture'), str(out), mode, str(chunk), str(split)], check=True)
        raw = (out / 'serial').read_bytes()
        segment = sfr.latest_boot(raw)
        assert sfr.witness_of(out / 'serial', ident) is not None
        expected = work + (b'worker-runtime\n' if mode == 'headless' else b'')
        assert sfr.captured(raw) == ssh_absd.captured(raw) == expected.decode()
        assert (sfr.readiness(segment, ident)[0] == 'ready') == (mode in ('network-local', 'network-race', 'headless'))
        assert (sfr.listener_position(segment) is not None) == (mode in ('network-local', 'network-race', 'headless'))
        assert sfr.readiness(segment, '0' * 32)[0] is None
        assert sfr.witness_of(out / 'serial', '0' * 32) is None
        if mode in ('network-local', 'network-race', 'headless'):
            lines = raw.splitlines(keepends=True)
            first = next(i for i, line in enumerate(lines) if line.startswith(b'EXTERNAL OUTPUT CHUNK'))
            for modified in (b''.join(lines[:first] + lines[first + 1:]), b''.join(lines[:first] + [lines[first]] + lines[first:])):
                assert sfr.readiness(sfr.latest_boot(modified), ident)[0] is None
            assert sfr.readiness(sfr.latest_boot(raw + sfr.BOOT_LINE + b'\n'), ident)[0] is None
        if mode == 'headless':
            (out / 'expected').write_bytes(expected)
            subprocess.run(['python3', str(ROOT / 'scripts/check-external-output.py'), str(out / 'serial'), str(out / 'expected')], check=True)
        else:
            assert b'EXTERNAL OUTPUT END' not in raw
            assert raw.index(b'LOCAL LOGIN FIXTURE') > raw.index(b'EXTERNAL OUTPUT CHUNK')
    for mode in ('partial', 'write-failure', 'no-marker'):
        (out / 'fsd.input').write_bytes(fsd.rstrip(b'\n') if mode == 'partial' else fsd)
        (out / 'worker.input').write_bytes(b'no readiness marker\n' if mode == 'no-marker' else network)
        subprocess.run([str(out / 'fixture'), str(out), mode, '256', '256'], check=True)
        assert b'LOCAL LOGIN FIXTURE' not in (out / 'serial').read_bytes()
    print(f'actual producer/relay and unchanged recovery/readiness readers: {len(cases)} positive + 3 refusal cases PASS')
