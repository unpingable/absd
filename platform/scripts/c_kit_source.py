#!/usr/bin/env python3
"""Bind base C-port outputs to their platform revision, C-kit archive and
POSIX adapter archive, and the installed ports/ to those receipts.

These are local build receipts, not authentication or a lock on shared output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


class Refused(Exception):
    pass


# 2: receipts also name the POSIX adapter archive every port links (D2), and
# install seals ports/ with INSTALLED (D3). Schema 1 receipts are refused.
SCHEMA = 2
INSTALLED = '.c-ports.built-from.json'
_NO_RECEIPT = object()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source(root):
    # Exported snapshots have no own .git; do not discover an enclosing repo.
    if not os.path.lexists(root / '.git'):
        return {'commit': 'none', 'dirty': 'unknown', 'dirty_paths': ''}
    overrides = ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE',
                 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
                 'GIT_NAMESPACE', 'GIT_CEILING_DIRECTORIES',
                 'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT')
    present = [key for key in overrides if key in os.environ]
    if present:
        raise Refused('Git source overrides are set: ' + ', '.join(present))
    def git(*args):
        result = subprocess.run(['git', '-C', str(root), *args], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise Refused('platform Git identity unavailable: ' + result.stderr.strip())
        return result.stdout.strip()
    commit = git('rev-parse', '--verify', 'HEAD')
    if len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
        raise Refused('platform Git revision is not a full commit')
    paths = git('status', '--porcelain')
    return {'commit': commit, 'dirty': 'yes' if paths else 'no',
            'dirty_paths': ' '.join(paths.splitlines()[:8])}


def kit_identity(root, kit):
    # Archive hashes describe the observed kit context, not the bytes an
    # earlier linker consumed. Full-output pins remain the acceptance check.
    current = source(root)
    stamp = kit / 'BUILT-FROM'
    try:
        lines = stamp.read_text().splitlines()
    except OSError as error:
        raise Refused(f'{stamp} missing or unreadable: rebuild the C kit') from error
    fields = {}
    for key in ('commit', 'dirty', 'lib/libabs.a'):
        rows = [line.split() for line in lines if line.split()[:1] == [key]]
        if len(rows) != 1 or len(rows[0]) != 2:
            raise Refused(f'{stamp} must name exactly one {key} value')
        fields[key] = rows[0][1]
    if fields['commit'] != current['commit']:
        raise Refused(f"C kit was built from {fields['commit']}, platform is {current['commit']}: rebuild the C kit")
    if fields['dirty'] not in ('no', 'yes', 'unknown'):
        raise Refused('C kit has an invalid dirty disposition')
    if current['commit'] != 'none' and (fields['dirty'] != 'no' or current['dirty'] != 'no'):
        if os.environ.get('ABSD_ALLOW_MODIFIED') != '1':
            raise Refused('dirty C kit or platform checkout: rebuild cleanly (ABSD_ALLOW_MODIFIED=1 is development only)')
        print('ABSD C KIT SOURCE DIRTY development_opt_in=1', file=sys.stderr)
    actual = digest(kit / 'lib/libabs.a')
    if fields['lib/libabs.a'] != actual:
        raise Refused('C kit libabs.a differs from its BUILT-FROM receipt')
    return {'schema_version': SCHEMA, 'platform_commit': current['commit'],
            'platform_dirty': current['dirty'],
            'kit_commit': fields['commit'], 'kit_dirty': fields['dirty'],
            'kit_libabs_sha256': actual}


def load(path):
    try:
        result = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise Refused(f'{path} missing or invalid: rebuild the C ports') from error
    if not isinstance(result, dict) or type(result.get('schema_version')) is not int or result['schema_version'] != SCHEMA:
        raise Refused(f'{path} has an unsupported receipt schema: rebuild the C ports')
    return result


def write(path, value):
    # mkstemp creates a private O_EXCL file beside the final receipt, so a
    # pre-existing temporary pathname cannot redirect the write elsewhere.
    fd, name = tempfile.mkstemp(prefix=path.name + '.', suffix='.new', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(json.dumps(value, sort_keys=True, indent=2) + '\n')
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def rows(root):
    for row in (root / 'userland/PORTS.tsv').read_text().splitlines():
        if row and not row.startswith('#'):
            fields = row.split('\t')
            if len(fields) != 7:
                raise Refused('C-port table row does not have seven fields')
            yield fields


def outputs(root, out):
    for fields in rows(root):
        yield out / fields[3]


def posix_digest(posix):
    if posix is None:
        raise Refused('the POSIX adapter archive path (--posix) is required')
    try:
        return digest(posix)
    except OSError as error:
        raise Refused(f'{posix} missing or unreadable: run scripts/build-posix.sh') from error


def linked_posix(out, actual):
    # Both rounds recorded the archive they linked (build-userland.sh); the
    # archive at publication must still be that one.
    for round in (1, 2):
        path = out / 'repro' / f'round{round}.sha256'
        try:
            lines = [line.split() for line in path.read_text().splitlines()]
        except OSError as error:
            raise Refused(f'{path} missing: rebuild the C ports') from error
        recorded = [line[0] for line in lines if line[1:] == ['lib/libabsd-posix.a']]
        if recorded != [actual]:
            raise Refused(f'{path}: the linked POSIX adapter archive differs from the current one: rebuild the C ports')


def verify(root, identity, out, posix, existing=False):
    actual = None
    for path in outputs(root, out):
        if existing and not path.exists():
            continue
        stamp = path.with_name(path.name + '.built-from.json')
        record = load(stamp)
        same_context(record, identity, stamp)
        if record.get('elf_sha256') != digest(path):
            raise Refused(f'{path}: bytes differ from the C-port build receipt: rebuild the C ports')
        actual = actual or posix_digest(posix)
        if record.get('posix_sha256') != actual:
            raise Refused(f'{stamp}: C-port build receipt posix_sha256 differs from {posix}: rebuild the C ports')
    return actual


def clean(record, current, what):
    if current['commit'] != 'none' and (current['dirty'] != 'no' or any(record[key] != 'no' for key in ('platform_dirty', 'kit_dirty'))):
        if os.environ.get('ABSD_ALLOW_MODIFIED') != '1':
            raise Refused(f'{what} came from or is used by a dirty checkout: rebuild cleanly (ABSD_ALLOW_MODIFIED=1 is development only)')
        print('ABSD C KIT SOURCE DIRTY development_opt_in=1', file=sys.stderr)


def read_verified_cport(path, pin, length, receipt=_NO_RECEIPT):
    """Return the very buffer checked against the canonical stripped pin.

    A receipt adds a consistency check; it cannot replace the canonical pin.
    Callers must consume this buffer, never reopen path after verification.
    """
    try:
        data = path.read_bytes()
    except OSError as error:
        raise Refused(f'{path} missing or unreadable: run scripts/build-ports.sh') from error
    actual = hashlib.sha256(data).hexdigest()
    if receipt is not _NO_RECEIPT and receipt != actual:
        raise Refused(f'{path}: bytes differ from the installed C-port receipt: run scripts/build-ports.sh')
    if actual != pin or len(data) != int(length):
        raise Refused(f'{path}: bytes or length differ from canonical userland/PORTS.tsv: rebuild the C ports')
    return data


def read_installed(root, ports):
    """Capture context/table/receipt once and return verified C-port buffers.

    Schema 2 remains observed build context plus output digests. This reader
    enforces canonical pins at consumption; the seal does not lock ports/ or
    promise that its paths will remain unchanged after this observation.
    """
    path = ports / INSTALLED
    record = load(path)
    current = source(root)
    for key in ('platform_commit', 'kit_commit'):
        if record.get(key) != current['commit']:
            raise Refused(f"{path}: installed C ports {key} is {record.get(key)}, platform is {current['commit']}: run scripts/build-ports.sh")
    for key in ('platform_dirty', 'kit_dirty'):
        if record.get(key) not in ('no', 'yes', 'unknown'):
            raise Refused(f'{path}: invalid {key}')
    clean(record, current, 'the installed C ports')
    table = list(rows(root))
    names = [fields[0] for fields in table]
    if not isinstance(record.get('ports'), dict) or sorted(record['ports']) != sorted(names):
        raise Refused(f'{path}: installed C ports do not name exactly userland/PORTS.tsv: run scripts/build-ports.sh')
    buffers = {f[0]: read_verified_cport(ports / f[0], f[5], f[6], record['ports'][f[0]])
               for f in table}
    return record, buffers


def installed(root, ports):
    return read_installed(root, ports)[0]


def seal(root, identity, out, posix, ports):
    """Validate canonical installed bytes, then publish those same buffers.

    Keep the raw-output/context checks. Publish every validated C port before
    the receipt; no later copy reopens the checked source. All consumers use
    retained bytes, not streaming paths. The private O_EXCL files below are
    for atomic publication only, not a claim of immutable shared output.
    """
    posix_hash = verify(root, identity, out, posix)
    table = list(rows(root))
    buffers = {f[0]: read_verified_cport(ports / f[0], f[5], f[6]) for f in table}
    with tempfile.TemporaryDirectory(prefix='.c-ports-', dir=ports) as private:
        for name, data in buffers.items():
            temporary = Path(private) / name
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                os.fchmod(stream.fileno(), 0o755)
            temporary.replace(ports / name)
    digests = {name: hashlib.sha256(data).hexdigest() for name, data in buffers.items()}
    write(ports / INSTALLED, identity | {'posix_sha256': posix_hash, 'ports': digests})


def same_context(record, expected, path):
    for key, value in expected.items():
        if record.get(key) != value:
            raise Refused(f'{path}: C-port build receipt {key} differs from the current kit/platform: rebuild the C ports')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('source', 'kit', 'capture', 'stamp', 'verify', 'seal', 'installed'))
    parser.add_argument('root', type=Path)
    parser.add_argument('kit', type=Path, nargs='?')
    parser.add_argument('out', type=Path, nargs='?')
    parser.add_argument('--existing', action='store_true', help='check existing outputs; missing ones are rebuilt by the installer')
    parser.add_argument('--posix', type=Path, help='the POSIX adapter archive the ports link (stamp, verify, seal)')
    parser.add_argument('--ports', type=Path, help='the installed ports directory (seal, installed)')
    args = parser.parse_args()
    if args.mode == 'source':
        print(json.dumps(source(args.root), sort_keys=True))
        return
    if args.mode == 'installed':
        if args.ports is None:
            parser.error('--ports is required for this mode')
        record = installed(args.root, args.ports)
        print(f"ABSD C PORTS INSTALLED OK commit={record['platform_commit']} n={len(record['ports'])}")
        return
    if args.kit is None or (args.mode not in ('kit',) and args.out is None):
        parser.error('kit and output paths are required for this mode')
    if args.mode in ('stamp', 'verify', 'seal') and args.posix is None:
        parser.error('--posix is required for this mode')
    if args.mode == 'seal' and args.ports is None:
        parser.error('--ports is required for this mode')
    identity = kit_identity(args.root, args.kit)
    if args.mode == 'kit':
        scope = 'git_identity=unavailable' if identity['platform_commit'] == 'none' else 'git_identity=known'
        print(f"ABSD C KIT SOURCE OK commit={identity['platform_commit']} {scope}")
    elif args.mode == 'capture':
        write(args.out / 'BUILT-FROM.json', identity)
    elif args.mode == 'stamp':
        same_context(load(args.out / 'BUILT-FROM.json'), identity, args.out)
        posix = posix_digest(args.posix)
        linked_posix(args.out, posix)
        for path in outputs(args.root, args.out):
            write(path.with_name(path.name + '.built-from.json'),
                  identity | {'elf_sha256': digest(path), 'posix_sha256': posix})
    elif args.mode == 'verify':
        verify(args.root, identity, args.out, args.posix, args.existing)
    else:
        seal(args.root, identity, args.out, args.posix, args.ports)


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError) as error:
        print('C KIT SOURCE REFUSED: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
