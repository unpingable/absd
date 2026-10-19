#!/usr/bin/env python3
"""Exercise the actual build script with local source and substituted build tools."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

SCRIPT = Path(__file__).resolve().with_name('build-picolibc.sh').read_bytes()


def executable(path, text):
    path.write_text('#!/bin/sh\nset -eu\n' + text)
    path.chmod(0o755)


def case(value):
    with tempfile.TemporaryDirectory(prefix='absd-picolibc-jobs-') as temporary:
        base = Path(temporary)
        root = base / 'platform'
        (root / 'scripts').mkdir(parents=True)
        (root / 'scripts/build-picolibc.sh').write_bytes(SCRIPT)
        pins = root / 'c/picolibc'
        pins.mkdir(parents=True)
        prefix = base / 'picolibc'
        (prefix / 'dl').mkdir(parents=True)
        archive = prefix / 'dl/source.tar.xz'
        with tarfile.open(archive, 'w:xz') as tar:
            data = b'fixture only\n'
            info = tarfile.TarInfo('source/meson.build')
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (pins / 'PIN').write_text(
            'meson\t1\n' 'ninja\t2\n'
            f'picolibc\t1\t{digest}\thttps://invalid.example/source.tar.xz\n')
        (pins / 'options.txt').write_text('-Dfixture=true\n')
        (pins / 'cross-absd.txt').write_text('')
        venv = base / 'venv/bin'
        venv.mkdir(parents=True)
        executable(venv / 'python3', "case \"$*\" in *meson*) echo 1;; *ninja*) echo 2;; *) exit 90;; esac\n")
        executable(venv / 'meson', 'if [ "$1" = --version ]; then echo 1; else echo setup >> "$FIXTURE_LOG"; fi\n')
        executable(venv / 'ninja', 'printf "%s\\n" "$@" > "$FIXTURE_ARGS"\nexit 77\n')
        guard = base / 'guard'
        guard.mkdir()
        for name in ('curl', 'pip', 'ninja', 'meson'):
            executable(guard / name, 'echo unexpected-tool >> "$FIXTURE_LOG"\nexit 91\n')
        log = base / 'calls'
        args = base / 'args'
        env = dict(os.environ, PATH=str(guard) + os.pathsep + os.environ['PATH'],
                   ABSD_PICOLIBC_PREFIX=str(prefix), ABSD_PICOLIBC_VENV=str(base / 'venv'),
                   FIXTURE_LOG=str(log), FIXTURE_ARGS=str(args))
        env.pop('ABSD_PICOLIBC_JOBS', None)
        if value is not None:
            env['ABSD_PICOLIBC_JOBS'] = value
        # Existing staging must survive invalid configuration unchanged.
        for name in ('src', 'build', 'install'):
            (prefix / name).mkdir()
            (prefix / name / 'preserve').write_text(name)
        result = subprocess.run(['sh', str(root / 'scripts/build-picolibc.sh')],
                                env=env, capture_output=True, text=True, timeout=10)
        valid = value is None or value in ('1', '2', '3', '4')
        if valid:
            assert result.returncode != 0 and 'ninja failed' in result.stderr, result
            assert args.read_text().splitlines() == ['-j', value or '4', '-C', str(prefix / 'build')]
            assert log.read_text() == 'setup\n'
        else:
            assert result.returncode != 0 and 'ABSD_PICOLIBC_JOBS must be' in result.stderr, result
            assert not log.exists() and not args.exists()
            for name in ('src', 'build', 'install'):
                assert (prefix / name / 'preserve').read_text() == name
        return valid


if __name__ == '__main__':
    values = [None, '1', '2', '3', '4', '', '0', '-1', '5', '64', '1.5', '01', ' 1', '1 ', '1\n', '1;true']
    for value in values:
        case(value)
    # The pre-fix script must fail the fixture's default -j expectation.
    fixed = SCRIPT
    old_call = b'"$venv/bin/ninja" -j "$jobs" -C'
    assert old_call in SCRIPT
    SCRIPT = SCRIPT.replace(old_call, b'"$venv/bin/ninja" -C', 1)
    try:
        case(None)
    except AssertionError:
        pass
    else:
        raise AssertionError('negative control without job limit was not detected')
    SCRIPT = fixed
    print(f'PICOLIBC JOBS OK cases={len(values)} negative_control=unbounded-rejected')
