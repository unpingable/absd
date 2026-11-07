#!/usr/bin/env python3
"""Opt-in receipt for one successful, nonincremental prepare-and-build occurrence.

The receipt binds source and produced bytes; it does not attest compiler correctness
or replace verify-inputs and the separate C-kit/ports provenance receipts.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone

COMMANDS = 'echo pwd ls cat printenv uname mkdir rm mv cp head tail wc sha256sum stat df sync man date uptime release sysinfo health net-status terminal-size ps interfaces dmesg logs absd-sh sh sh-probe absd-sftp'.split()
OUTPUTS = ['absd-logd.elf', 'sshd.elf', 'absd-sftp.elf', 'absd-fsd.elf', 'fixture-import.elf', 'exec-probe.elf', 'fsd-probe.elf', 'sshtest.elf', 'absd-enroll.elf'] + ['commands/' + name for name in COMMANDS]


def required_outputs(environment=None):
    environment = os.environ if environment is None else environment
    document = environment.get('ABSD_HTTPS_DOCUMENT', '0')
    if document not in ('0', '1'):
        raise ValueError('ABSD_HTTPS_DOCUMENT must be 0 or 1')
    return OUTPUTS + (['commands/https-document'] if document == '1' else [])


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


def source(root):
    if git(root, 'status', '--porcelain', '--untracked-files=all').strip():
        raise ValueError('source must be clean, including untracked source')
    revision = git(root, 'rev-parse', 'HEAD').decode().strip()
    return {'revision': revision, 'tree': git(root, 'rev-parse', 'HEAD^{tree}').decode().strip(),
            'git_archive_sha256': hashlib.sha256(git(root, 'archive', '--format=tar', 'HEAD')).hexdigest()}


def write_new(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def now():
    return datetime.now(timezone.utc).isoformat()


def begin(root, receipt, toolchain):
    pending = Path(str(receipt) + '.pending')
    if receipt.exists() or pending.exists():
        raise ValueError('receipt and pending path must be fresh')
    if os.environ.get('ABSD_INCREMENTAL', '0') == '1':
        raise ValueError('receipted builds must be nonincremental')
    required = required_outputs()
    identity = source(root)
    tools = {}
    for name, requested in [('rustc', str(Path(toolchain) / 'bin/rustc')), ('cargo_runner', 'cargo'), ('cargo_1_95', str(Path(os.environ.get('RUSTUP_HOME', str(Path.home() / '.rustup'))) / 'toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo')), ('clang', 'clang'), ('llvm-ar-18', 'llvm-ar-18'), ('llvm-strip-18', 'llvm-strip-18')]:
        resolved = shutil.which(requested)
        if not resolved:
            raise ValueError('missing producer tool: ' + name)
        path = Path(resolved).resolve()
        tools[name] = {'path': str(path), 'sha256': digest(path)}
    record = {'schema_version': 1, 'status': 'started', 'run': str(uuid.uuid4()), 'started': now(),
              'root': str(root), 'source': identity, 'producer': {'pid': os.getppid(), 'script': 'scripts/prepare-and-build.sh',
              'script_sha256': digest(root / 'scripts/prepare-and-build.sh'), 'tools': tools},
              'environment': {k: os.environ[k] for k in ('ABSD_PROFILE', 'ABSD_RELEASE_ID', 'ABSD_INCREMENTAL', 'ABSD_RUST_TOOLCHAIN', 'ABSD_CARGO_LOCKED', 'ABSD_HTTPS_DOCUMENT', 'CARGO_HOME', 'RUSTUP_HOME') if k in os.environ},
              'required_outputs': required,
              'scope': 'prepare-and-build outputs only; C kit and ports require their separate provenance receipts',
              'limits': ['Source cleanliness is sampled at begin and finish; transient concurrent mutations are not excluded.', 'Tool hashes identify selected executables, not their shared libraries or compiler correctness.', 'Pinned external inputs remain governed by canonical verify-inputs; this receipt is not a replacement.']}
    write_new(pending, record)
    # All named paths are build products of this script. Removing them prevents
    # a missing production step from admitting a previous occurrence's output.
    for name in required:
        path = root / name
        if path.is_symlink():
            raise ValueError('output symlink refused: ' + name)
        path.unlink(missing_ok=True)


def finish(root, receipt):
    pending = Path(str(receipt) + '.pending')
    record = json.loads(pending.read_text())
    if record['status'] != 'started' or record['root'] != str(root):
        raise ValueError('pending occurrence does not match root')
    if required_outputs(record['environment']) != required_outputs() or record['required_outputs'] != required_outputs(record['environment']):
        raise ValueError('build output selection changed')
    if source(root) != record['source']:
        raise ValueError('source changed during build')
    outputs = {}
    for name in record['required_outputs']:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('missing or substituted output: ' + name)
        outputs[name] = {'sha256': digest(path), 'bytes': path.stat().st_size}
    for tool in record['producer']['tools'].values():
        if digest(tool['path']) != tool['sha256']:
            raise ValueError('producer tool changed during build')
    record.update(status='success', finished=now(), outputs=outputs)
    write_new(receipt, record)
    pending.unlink()


def main():
    action, root, receipt, *rest = sys.argv[1:]
    root, receipt = Path(root).resolve(), Path(receipt).absolute()
    if action == 'begin' and len(rest) == 1:
        begin(root, receipt, rest[0])
    elif action == 'finish' and not rest:
        finish(root, receipt)
    else:
        raise ValueError('usage: operator_build_receipt.py begin ROOT RECEIPT TOOLCHAIN | finish ROOT RECEIPT')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print('operator-build-receipt: ' + str(error), file=sys.stderr)
        sys.exit(1)
