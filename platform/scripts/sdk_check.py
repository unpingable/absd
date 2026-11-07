#!/usr/bin/env python3
"""Verify an installed SDK's inventory and the host tools its drivers use."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys


class Refused(Exception):
    pass


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def files(root):
    result = {}
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise Refused(f'inventory: symlink or special file: {path.relative_to(root)}')
        if stat.S_ISREG(mode):
            result[path.relative_to(root).as_posix()] = {
                'sha256': digest(path), 'size': path.stat().st_size,
                'mode': stat.S_IMODE(mode)}
    return result


def inventory(root):
    manifest = root / 'metadata/manifest.json'
    try:
        checksum = (root / 'metadata/manifest.sha256').read_text()
    except OSError as error:
        raise Refused('manifest checksum missing: metadata/manifest.sha256') from error
    match = re.fullmatch(r'([0-9a-f]{64})  manifest\.json\n', checksum)
    if not match or digest(manifest) != match.group(1):
        raise Refused('manifest checksum mismatch; extract a fresh SDK and verify its archive checksum')
    try:
        record = json.loads((root / 'metadata/manifest.json').read_text())
    except (OSError, ValueError) as error:
        raise Refused('inventory: unreadable metadata/manifest.json') from error
    if not isinstance(record, dict) or type(record.get('schema_version')) is not int or record['schema_version'] != 1:
        raise Refused('unsupported SDK manifest schema (expected 1)')
    actual = files(root)
    # The containing archive checksum binds these two bootstrap records.
    del actual['metadata/manifest.json']
    del actual['metadata/manifest.sha256']
    expected = record.get('inventory')
    if not isinstance(expected, dict):
        raise Refused('inventory: manifest has no file inventory')
    for name in sorted(set(actual) | set(expected)):
        if actual.get(name) != expected.get(name):
            observed, wanted = actual.get(name), expected.get(name)
            if (observed and isinstance(wanted, dict) and
                    observed['sha256'] == wanted.get('sha256') and
                    observed['size'] == wanted.get('size') and
                    observed['mode'] != wanted.get('mode')):
                raise Refused(f'inventory mode mismatch: {name}; re-extract with tar -p (tar -xpzf ARCHIVE.tar.gz) to preserve the recorded file modes')
            raise Refused(f'inventory mismatch: {name}; extract a fresh SDK and verify its archive checksum')
    return record


def command(name, *args):
    if not shutil.which(name):
        raise Refused(f'{name} missing: install the documented Ubuntu host prerequisite')
    result = subprocess.run([name, *args], capture_output=True, text=True)
    if result.returncode:
        raise Refused(f'{name} failed: {result.stderr.strip()}')
    return result.stdout.strip()


def host():
    clang = os.environ.get('ABSD_CLANG') or 'clang-18'
    version = command(clang, '-dumpversion')
    if version.split('.')[0] != '18':
        raise Refused(f'{clang} is version {version}; LLVM clang major 18 is required')
    version = command('ld.lld-17', '--version')
    if not re.search(r'\bLLD 17\.', version):
        raise Refused(f'ld.lld-17 is {version}; LLD major 17 is required')
    version = command('llvm-nm-18', '--version')
    if not re.search(r'\bLLVM version 18\.', version):
        raise Refused(f'llvm-nm-18 is {version}; LLVM nm major 18 is required')
    version = command('readelf', '--version')
    if 'GNU readelf' not in version:
        raise Refused('readelf must be GNU binutils readelf')
    command('sha256sum', '--version')
    command('ssh', '-V')
    require('scp')
    resource = Path(command(clang, '-print-resource-dir'))
    for path in (resource / 'include', resource / 'lib/linux/libclang_rt.builtins-x86_64.a'):
        if not path.exists():
            raise Refused(f'clang-18 resource missing: {path}; install libclang-rt-18-dev')


def require(name):
    if not shutil.which(name):
        raise Refused(f'{name} missing: install openssh-client')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory-only', action='store_true', help='verify delivered files without probing host tools')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if any(c.isspace() for c in str(root)):
        raise Refused('SDK path contains whitespace; existing compiler drivers require paths without whitespace')
    record = inventory(root)
    if not args.inventory_only:
        host()
    print(f'ABSD SDK OK version={record["version"]} inventory=verified host={"not-checked" if args.inventory_only else "verified"} licenses=pending-qualification')


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, KeyError, TypeError, ValueError) as error:
        print('ABSD SDK REFUSED: ' + str(error), file=sys.stderr)
        sys.exit(1)
