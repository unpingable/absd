#!/usr/bin/env python3
"""Create a deterministic local engineering SDK; does not grant publication clearance."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
os.environ['GIT_OPTIONAL_LOCKS'] = '0'  # Git identity reads must not refresh the input index.

# Load only this checkout's helpers; packaged content is never executed here.
SCRIPTS = Path(__file__).resolve().parent

def helper(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

sdk = helper('sdk_check')
source_helper = helper('c_kit_source')
Refused = sdk.Refused
LIBS = ('libabs.a', 'libabs_builtins.a', 'crt0.o', 'libc.a', 'libm.a')
C_FIELDS = {'commit', 'dirty', 'source', 'rustc', 'cargo', 'clang', 'ld.lld',
            'llvm-ar', 'picolibc-libc.a', 'picolibc-libm.a',
            *('lib/' + name for name in LIBS)}


def field(rows, key):
    values = [r.split(maxsplit=1) for r in rows if r.split()[:1] == [key]]
    if len(values) != 1 or len(values[0]) != 2:
        raise Refused(f'BUILT-FROM must name exactly one {key}')
    return values[0][1]


def regular_file(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise Refused(f'expected a regular file (no symlink or special file): {path}')


def require_directory(path):
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise Refused(f'expected a real directory (no symlink): {path}')


def check_hash(path, want):
    regular_file(path)
    if not re.fullmatch('[0-9a-f]{64}', want) or sdk.digest(path) != want:
        raise Refused(f'digest mismatch: {path}; rebuild from clean pinned inputs')


def source_equal(delivered, source):
    regular_file(delivered)
    regular_file(source)
    if sdk.digest(delivered) != sdk.digest(source):
        raise Refused(f'source mismatch: {delivered} differs from {source}')


def c_headers(args):
    expected_root = args.picolibc_install / 'include'
    overlay = args.source_root / 'c/include/absd'
    tree(expected_root, lambda name, directory: True)
    tree(overlay, lambda name, directory: True)
    expected = {name: row['sha256'] for name, row in sdk.files(expected_root).items()}
    for path in sorted(overlay.glob('*.h')):
        expected['absd/' + path.name] = sdk.digest(path)
    actual = {name: row['sha256'] for name, row in sdk.files(args.kit / 'include').items()}
    for name in sorted(set(actual) | set(expected)):
        if actual.get(name) != expected.get(name):
            raise Refused(f'C header source mismatch: {name}; expected exact Picolibc headers with the clean-source ABSD overlay')


def receipt(root, commit):
    regular_file(root / 'BUILT-FROM')
    data = (root / 'BUILT-FROM').read_bytes()
    rows = data.decode().splitlines()
    if field(rows, 'commit') != commit or field(rows, 'dirty') != 'no':
        raise Refused(f'{root}/BUILT-FROM must name the clean source commit {commit}')
    return data, rows


def tree(root, allowed):
    """Reject unknown top-level content and symlinks even when not copied."""
    require_directory(root)
    for path in root.rglob('*'):
        relative = path.relative_to(root).as_posix()
        if any(c.isspace() for c in relative):
            raise Refused(f'whitespace in input path unsupported: {path}')
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise Refused(f'symlink refused: {path}')
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise Refused(f'special file refused: {path}')
        if not allowed(relative, path.is_dir()):
            raise Refused(f'unexpected installed file: {path}')


def c_allowed(name, directory):
    if directory:
        return name in ('bin', 'lib', 'include') or name.startswith('include/')
    return name in {'BUILT-FROM', 'absd-c.ld', 'bin/absd-cc', *('lib/' + n for n in LIBS)} or name.startswith('include/')


def cxx_allowed(name, directory):
    # Installed subsets may include ancillary files. Copy only the explicit
    # library/driver allowlist and v1 headers below.
    return True


def copy_file(source, target, executable=False):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755 if executable else 0o644)


def text_file(path, text, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755 if executable else 0o644)


def sanitized(rows):
    # Keep factual source/tool/archive identities. Paths and expanded flags
    # stay in the external original receipt, whose digest is in the manifest.
    private = {'source', 'kit', 'cflags', 'cxxflags', 'dirty-paths'}
    return '\n'.join(row for row in rows if row.split() and row.split()[0] not in private) + '\n'


def wrapper(target, cxx=False):
    return ('#!/bin/sh\nset -eu\nroot=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)\n'
            'case "$root" in *[[:space:]]*) echo "ABSD SDK: whitespace paths unsupported" >&2; exit 2;; esac\n' +
            ('export ABSD_CXX_BUILD="$root/cxx" ABSD_CKIT="$root/c"\n' if cxx else '') +
            f'exec {target} "$@"\n')


def build(args, stage):
    require_directory(args.source_root)
    require_directory(args.picolibc_install)
    require_directory(args.picolibc_install / 'lib')
    if args.cxx:
        require_directory(args.cxx)
    current = source_helper.source(args.source_root)
    if current['commit'] == 'none' or current['dirty'] != 'no':
        raise Refused('--source-root must be a clean Git checkout of the actual build source')
    source_equal(SCRIPTS / 'check-c-elf.py', args.source_root / 'scripts/check-c-elf.py')
    tree(args.kit, c_allowed)
    c_original, c_rows = receipt(args.kit, current['commit'])
    for row in c_rows:
        if row.split() and row.split()[0] not in C_FIELDS:
            raise Refused('only established default C kit receipts are supported; unsupported field: ' + row.split()[0])
    for name in LIBS:
        check_hash(args.kit / 'lib' / name, field(c_rows, 'lib/' + name))
    regular_file(args.source_root / 'c/picolibc/PIN')
    pins = (args.source_root / 'c/picolibc/PIN').read_text().splitlines()
    for name in ('libc.a', 'libm.a'):
        pin = field(pins, 'picolibc-' + name).split()
        if len(pin) != 2 or field(c_rows, 'picolibc-' + name) != pin[1]:
            raise Refused(f'Picolibc {name} stamp differs from clean-source c/picolibc/PIN')
        check_hash(args.picolibc_install / 'lib' / name, pin[1])
    source_equal(args.kit / 'bin/absd-cc', args.source_root / 'c/bin/absd-cc')
    source_equal(args.kit / 'absd-c.ld', args.source_root / 'c/absd-c.ld')
    c_headers(args)
    for name in ('absd-c.ld', 'bin/absd-cc'):
        if not (args.kit / name).is_file():
            raise Refused('missing C kit file: ' + name)
    if not (args.kit / 'bin/absd-cc').stat().st_mode & 0o111:
        raise Refused('C kit bin/absd-cc must be executable')
    for path in sorted(args.kit.rglob('*')):
        if path.is_file() and path != args.kit / 'BUILT-FROM':
            copy_file(path, stage / 'c' / path.relative_to(args.kit), path == args.kit / 'bin/absd-cc')
    text_file(stage / 'c/BUILT-FROM', sanitized(c_rows))
    receipts = {'c_original_sha256': hashlib.sha256(c_original).hexdigest()}
    if args.cxx:
        # Inspect only installed subsets: build logs/work can contain symlinks.
        for directory in ('lib', 'include', 'bin'):
            tree(args.cxx / directory, cxx_allowed)
        original, rows = receipt(args.cxx, current['commit'])
        source_equal(args.cxx / 'bin/absd-c++', args.source_root / 'cxx/bin/absd-c++')
        if any(row.startswith('profile ') for row in rows):
            raise Refused('only the established default C++0 runtime is supported; profile overrides refused')
        if field(rows, 'kit-commit') != current['commit']:
            raise Refused('C++ kit-commit differs from actual clean source')
        for name in ('libc.a', 'libabs.a', 'crt0.o'):
            check_hash(args.kit / 'lib' / name, field(rows, 'kit-lib/' + name))
        for name in ('libc++.a', 'libc++abi.a'):
            value = field(rows, 'lib/' + name).split()[0]
            check_hash(args.cxx / 'lib' / name, value)
            copy_file(args.cxx / 'lib' / name, stage / 'cxx/lib' / name)
        include = args.cxx / 'include/c++/v1'
        for name in ('__config_site', 'vector', 'cxxabi.h'):
            if not (include / name).is_file():
                raise Refused('missing C++0 header: ' + name)
        header_data = ''.join(f'{sdk.digest(p)}  ./{p.relative_to(include).as_posix()}\n' for p in sorted(include.rglob('*')) if p.is_file())
        if hashlib.sha256(header_data.encode()).hexdigest() != field(rows, 'headers'):
            raise Refused('C++ header aggregate digest mismatch')
        for path in sorted(include.rglob('*')):
            if path.is_file():
                copy_file(path, stage / 'cxx/include/c++/v1' / path.relative_to(include))
        copy_file(args.cxx / 'bin/absd-c++', stage / 'cxx/bin/absd-c++', True)
        text_file(stage / 'cxx/BUILT-FROM', sanitized(rows))
        text_file(stage / 'bin/absd-c++', wrapper('"$root/cxx/bin/absd-c++"', True), True)
        receipts['cxx_original_sha256'] = hashlib.sha256(original).hexdigest()
        for name in ('cxx0.cpp', 'cxx0.expected'):
            copy_file(args.source_root / 'cxx/tests' / name, stage / 'examples' / name)
    copy_file(SCRIPTS.parent / 'docs/HOST-SDK.md', stage / 'HOST-SDK.md')
    text_file(stage / 'bin/absd-cc', wrapper('"$root/c/bin/absd-cc"'), True)
    text_file(stage / 'bin/absd-sdk-check', wrapper('python3 -I "$root/metadata/sdk_check.py"'), True)
    text_file(stage / 'bin/absd-check-elf', wrapper('python3 -I "$root/metadata/check-c-elf.py"'), True)
    copy_file(SCRIPTS / 'sdk_check.py', stage / 'metadata/sdk_check.py')
    copy_file(SCRIPTS / 'check-c-elf.py', stage / 'metadata/check-c-elf.py')
    if args.licenses:
        tree(args.licenses, lambda name, directory: True)
        for path in sorted(args.licenses.rglob('*')):
            if path.is_file():
                copy_file(path, stage / 'licenses/evidence' / path.relative_to(args.licenses))
    text_file(stage / 'licenses/STATUS', 'Pending complete downloadable-content licence qualification. Local engineering only. Publication is not authorized. Supplied notices are evidence, not clearance.\n')
    text_file(stage / 'README', f'''ABSD host SDK {args.version} (local engineering candidate)
Ubuntu 24.04 x86-64 host prerequisites: Python 3, clang-18, ld.lld-17,
llvm-nm-18, GNU readelf (binutils), sha256sum (coreutils), openssh-client,
and clang 18 resource headers / builtins (libclang-rt-18-dev).
No source checkout or Rust/CMake/Ninja is needed to consume this SDK.
Start with HOST-SDK.md for the build/upload/run/change loop.
Run bin/absd-sdk-check before compiling; --inventory-only skips host probes.
Use bin/absd-cc and bin/absd-check-elf ELF --map ELF.map.
Existing drivers do not support whitespace in SDK, input or output paths.
Extract with tar -xpzf ARCHIVE.tar.gz to preserve the exact recorded file modes.
Only default C receipts and optional C++0 are supported; profile/unknown C fields are refused.
The compatibility pair is recorded in metadata/manifest.json; this is not an ABI freeze.
Original receipts remain in external build evidence; sanitized installed receipts
retain source and archive identities, and the manifest hashes the originals.
The archive checksum binds the manifest and its detached metadata/manifest.sha256.
The checker requires their ordinary checksum consistency (not authentication).
The embedded inventory binds every other delivered file.
Licence qualification is pending. Do not publish or distribute this candidate.
''')
    packaging = source_helper.source(SCRIPTS.parent)
    packaging_identity = {k: packaging[k] for k in ('commit', 'dirty')}
    packaging_identity['tool_sha256'] = {name: sdk.digest(SCRIPTS / name) for name in
        ('package-sdk.py', 'sdk_check.py', 'check-c-elf.py', 'c_kit_source.py')}
    record = {'schema_version': 1, 'version': args.version,
              'compatibility': {'kernel_commit': args.kernel_commit, 'platform_commit': args.platform_commit},
              'build_source': current, 'packaging_source': packaging_identity,
              'receipts': receipts, 'licenses': {'status': 'pending-qualification'},
              'inventory': sdk.files(stage)}
    text_file(stage / 'metadata/manifest.json', json.dumps(record, sort_keys=True, indent=2) + '\n')
    text_file(stage / 'metadata/manifest.sha256', sdk.digest(stage / 'metadata/manifest.json') + '  manifest.json\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog='Outputs in a NEW --out directory: absd-sdk-VERSION/ tree, absd-sdk-VERSION.tar.gz and .tar.gz.sha256. Existing destinations (even empty) are refused. Inputs are read only. No downloads. Consumption requires Python 3, clang-18/resource headers/builtins, LLD 17, LLVM nm 18, GNU readelf, sha256sum and OpenSSH. Existing compiler drivers require SDK/input/output paths without whitespace. Supplied licence evidence never implies clearance. Only established default C receipts and optional C++0 are supported. --source-root must be a clean Git checkout; snapshots are refused. Extract with tar -xpzf to preserve canonical modes.')
    parser.add_argument('--kit', required=True, type=Path, help='installed C kit with clean BUILT-FROM')
    parser.add_argument('--cxx', type=Path, help='optional established C++0 build output (only installed files copied)')
    parser.add_argument('--source-root', required=True, type=Path, help='clean actual build-source Git checkout, independently of packager HEAD')
    parser.add_argument('--picolibc-install', required=True, type=Path, help='original Picolibc install to verify unstripped receipt hashes')
    parser.add_argument('--version', required=True, help='safe version token used in tree and archive names')
    parser.add_argument('--kernel-commit', required=True, help='full compatibility-pair kernel Git commit')
    parser.add_argument('--platform-commit', required=True, help='full compatibility-pair platform Git commit (distinct from actual build source)')
    parser.add_argument('--out', required=True, type=Path, help='new output directory; existing paths refused')
    parser.add_argument('--licenses', type=Path, help='optional actual notices/coverage evidence directory; qualification remains pending')
    args = parser.parse_args()
    for name in ('kit', 'cxx', 'source_root', 'picolibc_install', 'out', 'licenses'):
        value = getattr(args, name)
        if value is not None:
            if any(c.isspace() for c in str(value)):
                raise Refused(f'whitespace in --{name.replace("_", "-")} path unsupported')
            setattr(args, name, value.absolute())
    if any(c.isspace() for c in args.version):
        raise Refused('whitespace in --version unsupported')
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+-]{0,79}', args.version):
        raise Refused('--version must be a safe 1-80 character version token')
    for name in ('kernel_commit', 'platform_commit'):
        if not re.fullmatch('[0-9a-f]{40}', getattr(args, name)):
            raise Refused(f'--{name.replace("_", "-")} must be a full Git commit')
    if os.path.lexists(args.out):
        raise Refused(f'output already exists: {args.out}; choose a new destination')
    inputs = [args.kit, args.cxx, args.source_root, args.picolibc_install, args.licenses]
    for path in inputs:
        if path and (args.out.resolve() == path.resolve() or path.resolve() in args.out.resolve().parents):
            raise Refused('--out must be outside every input tree')
    if not args.out.parent.is_dir():
        raise Refused('--out parent must already exist')
    with tempfile.TemporaryDirectory(prefix='.sdk-package-', dir=args.out.parent) as temporary:
        staging = Path(temporary) / 'result'
        name = 'absd-sdk-' + args.version
        tree_path = staging / name
        tree_path.mkdir(parents=True)
        build(args, tree_path)
        archive_path = staging / (name + '.tar.gz')
        with archive_path.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for path in [tree_path, *sorted(tree_path.rglob('*'))]:
                    info = archive.gettarinfo(str(path), arcname=path.relative_to(staging).as_posix())
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ''
                    if path.is_file():
                        with path.open('rb') as stream:
                            archive.addfile(info, stream)
                    else:
                        info.mode = 0o755
                        archive.addfile(info)
        text_file(staging / (name + '.tar.gz.sha256'), sdk.digest(archive_path) + '  ' + archive_path.name + '\n')
        # mkdir claims the final name exclusively; never replace an existing destination.
        args.out.mkdir()
        for path in staging.iterdir():
            path.rename(args.out / path.name)
    print('ABSD SDK PACKAGED ' + str(args.out / name) + ' licenses=pending-qualification')


if __name__ == '__main__':
    try:
        main()
    except (Refused, source_helper.Refused, OSError, ValueError, UnicodeError) as error:
        print('ABSD SDK PACKAGE REFUSED: ' + str(error), file=sys.stderr)
        sys.exit(1)
