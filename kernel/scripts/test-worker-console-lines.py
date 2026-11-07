#!/usr/bin/env python3
"""Actual init line publisher, real capture consumers, finite host transports."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def item(source, marker):
    start = source.index(marker)
    at = source.index('{', start)
    depth, end = 1, at + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--platform', type=Path)
parser.add_argument('--work', type=Path)
args = parser.parse_args()
temporary = None
if args.work:
    out = args.work.resolve()
    out.mkdir(exist_ok=False)
else:
    temporary = tempfile.TemporaryDirectory(prefix='absd-worker-lines-')
    out = Path(temporary.name)
readers = []
platform_identity = None
if args.platform:
    platform = args.platform.resolve()
    sys.path.insert(0, str(platform / 'scripts'))
    import ssh_absd
    import storage_fence_resume
    readers = [ssh_absd.captured, storage_fence_resume.captured]
    platform_identity = {
        'revision': subprocess.check_output(['git', '-C', str(platform), 'rev-parse', 'HEAD'], text=True).strip(),
        'source_sha256': {name: hashlib.sha256((platform / 'scripts' / name).read_bytes()).hexdigest()
                          for name in ['ssh_absd.py', 'storage_fence_resume.py']},
    }
init = (ROOT / 'user/src/bin/init.rs').read_text()
user = (ROOT / 'user/src/lib.rs').read_text()
assert init.count('external_worker_chunk(') == 3
assert init.count('external_worker_startup(') == 2
production = '\n'.join(item(user, marker) for marker in
                       ('pub struct LineBuffer', 'impl LineBuffer', 'impl core::fmt::Write for LineBuffer'))
production += '\n' + '\n'.join(item(init, 'fn ' + name + '(') for name in
                               ('external_line', 'external_chunk', 'external_split_notice', 'external_worker_chunk', 'external_worker_startup', 'external_output_end'))
production += '\n' + init[init.index('static mut FSD_LOG_READERS:'):init.index('fn finish_fsd_logs(')]
production += '\n' + item(init, 'fn finish_fsd_logs(')
prefix = (ROOT / 'scripts/fixtures/local-console-startup.rs').read_text().split('fn main() {', 1)[0]
fixture = prefix.replace('@ROOT@', str(ROOT)).replace('@PRODUCTION@', production)
fixture += (ROOT / 'scripts/fixtures/worker-console-lines.rs').read_text()
stderr_block = item(init, 'if stderr_open {')
error_arm = item(stderr_block, 'Err(_) =>')
fixture = fixture.replace('@STDERR_READ_ERROR@', error_arm[error_arm.index('{') + 1:-1])
(out / 'fixture.rs').write_text(fixture)
subprocess.run(['rustc', '--edition=2024', '--crate-name', 'absd_abi', '--crate-type=rlib',
                str(ROOT / 'abi/src/lib.rs'), '-o', str(out / 'libabsd_abi.rlib')], check=True)
subprocess.run(['rustc', '--edition=2024', str(out / 'fixture.rs'), '--extern',
                'absd_abi=' + str(out / 'libabsd_abi.rlib'), '-o', str(out / 'fixture')], check=True)
results = []
try:
    for mode in ['observed', 'concurrent', 'binary', 'long', 'cap-newline', 'tail', 'abort', 'write-failure', 'read-error', 'partial-write', 'offset-overflow', 'pre-prompt', 'fsd-interleaved', 'fsd-boundary', 'fsd-eof', 'fsd-error', 'fsd-close', 'maintenance-boundary', 'maintenance-poisoned']:
        work = out / mode
        work.mkdir()
        # Public fixture data: same 96-byte scheduling shape as baseline03.
        (work / 'key.input').write_bytes(b'SSH HOST KEY LOADED ssh-ed25519 ' + b'A' * 68 + b' SHA256:fixture\n')
        (work / 'mount.input').write_bytes(b':ro,/bin:ro,/etc:ro,/var/log:rw,/var/log/journal:ro,/var/log/journal-health:ro,/var/state:ro,/va' + b'r/tmp:rw\n')
        (work / 'cut.input').write_text('75\n')
        subprocess.run([str(out / 'fixture'), mode, str(work)], check=True)
        serial = (work / 'serial.log').read_bytes()
        run = subprocess.run(['python3', str(ROOT / 'scripts/check-external-output.py'), '--print', str(work / 'serial.log')], capture_output=True)
        complete = mode not in ['abort', 'write-failure', 'partial-write', 'offset-overflow', 'pre-prompt', 'maintenance-poisoned']
        if complete:
            assert run.returncode == 0, run.stderr
            decoded = run.stdout
        else:
            assert run.returncode != 0, 'incomplete capture claimed a valid end'
            import re
            decoded = b''.join(bytes.fromhex(m.group(1).decode()) for m in re.finditer(rb'EXTERNAL OUTPUT CHUNK offset=[0-9a-f]+ data=([0-9a-f]*)\n', serial))
        if mode == 'concurrent':
            lines = decoded.splitlines(keepends=True)
            assert len(lines) == 32
            for stream in range(2):
                actual = [line for line in lines if line.startswith(f'stream={stream} '.encode())]
                assert actual == [f'stream={stream} line={n:02} '.encode() + b'x' * 600 + b'\n' for n in range(16)]
            assert b'EXTERNAL OUTPUT SPLIT' not in serial
        elif mode in ['write-failure', 'offset-overflow']:
            assert decoded == b''
        else:
            assert decoded == (work / 'expected.bin').read_bytes(), mode
        for reader in readers:
            assert reader(serial) == decoded.decode(errors='replace'), (mode, reader.__module__)
        if mode == 'long':
            assert [line for line in serial.splitlines(keepends=True) if line.startswith(b'EXTERNAL OUTPUT SPLIT')] == [
                b'EXTERNAL OUTPUT SPLIT stream=stdout reason=limit offset=0000000000000000 bytes=1024\n']
        if mode == 'cap-newline':
            assert b'EXTERNAL OUTPUT SPLIT' not in serial
        if mode == 'tail':
            assert b'EXTERNAL OUTPUT SPLIT stream=stdout reason=eof ' in serial
        if mode == 'read-error':
            assert b'EXTERNAL OUTPUT SPLIT stream=stderr reason=read-error ' in serial
            assert b'reason=eof ' not in serial
        if mode == 'abort':
            assert serial.count(b' reason=abort ') == 2
        if mode == 'pre-prompt':
            assert serial.index(b' reason=pre-prompt ') < serial.index(b'LOCAL LOGIN FIXTURE')
            if args.platform:
                assert storage_fence_resume.readiness(serial, '0123456789abcdef0123456789abcdef')[0] == 'ready'
        results.append({'mode': mode, 'pass': True, 'serial_sha256': hashlib.sha256(serial).hexdigest(), 'payload_bytes': len(decoded)})
    (out / 'RESULT.json').write_text(json.dumps({'scope': __doc__, 'platform_readers': len(readers), 'platform_identity': platform_identity, 'cases': results,
        'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in ['user/src/bin/init.rs', 'user/src/worker_console.rs', 'user/src/local_console.rs', 'user/src/console_startup.rs', 'user/src/console_lines.rs']},
        'fixture_sha256': hashlib.sha256(fixture.encode()).hexdigest()}, indent=2) + '\n')
    print(f'worker console actual-path host cases: {len(results)} PASS; unchanged platform readers={len(readers)}')
finally:
    if temporary:
        temporary.cleanup()
