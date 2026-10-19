#!/usr/bin/env python3
"""Compile exact metadata decoder/std PAL items and the live C header on a host.

Usage: check-mtime.py ROOT [--self-test]
The static guard requires exactly the three V2 metadata hooks. Negative
controls revert each hook or substitute a wrong wire word/invented epoch in
extracted source; they never change product sources or historical verdicts.
Native end-to-end qualification is scripts/mtime-matrix.py, separately.
"""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys


def item(text, anchor, kinds):
    m = re.search(anchor, text, re.M)
    if not m:
        raise RuntimeError(f"metadata source item missing: {anchor}")
    body, _ = kinds.block(text, '(?m)' + anchor, 'mtime')
    first = text.rfind('\n', 0, m.start()) + 1
    while first > 0:
        previous = text.rfind('\n', 0, first - 1) + 1
        if not text[previous:first].startswith(('#[', '///')):
            break
        first = previous
    return text[first:text.index(body, m.start()) + len(body)] + '}\n'


def patch_file(root, path):
    text = (root / 'patches/rust-1.95.0-absd-std.patch').read_text()
    section = text.split('+++ b/' + path + '\n', 1)[1].split('\ndiff --git ', 1)[0]
    return '\n'.join(line[1:] for line in section.splitlines() if line.startswith('+')) + '\n'


def check_hooks(source):
    """V1 into a V2-sized buffer is safe but silently loses every timestamp."""
    expected = {'__absd_std_fs_' + name + '_v2' for name in ('stat', 'fstat', 'readdir')}
    found = set(re.findall(r'\b__absd_std_fs_(?:stat|fstat|readdir)\w*\b', source))
    if found != expected:
        raise RuntimeError(f'metadata hook versions: got {sorted(found)}, want {sorted(expected)}')
    for name in expected:
        if len(re.findall(r'\b' + name + r'\s*\(', source)) < 2:
            raise RuntimeError(f'metadata hook {name} must be declared and called')


def main():
    root = Path(sys.argv[1]).resolve()
    negative = sys.argv[2:] == ['--self-test']
    if sys.argv[2:] and not negative:
        raise RuntimeError(__doc__)
    spec = importlib.util.spec_from_file_location('kinds', root / 'scripts/check-fs-kinds.py')
    kinds = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kinds)
    out = root / '.host-target/mtime'
    out.mkdir(parents=True, exist_ok=True)
    source = (root / 'runtime/src/storage.rs').read_text()
    anchors = [r'^pub struct RawAttr \{', r'^pub struct RawAttrV2 \{',
               r'^impl From<RawAttrV2> for RawAttr \{',
               r'^fn ledger_attr<T: From<RawAttrV2>>\(',
               r'^fn remote_attr<T: From<RawAttrV2>>\(',
               r'^fn entry_attr<T: From<RawAttrV2>>\(',
               r'^fn write_attr<T: From<RawAttrV2>>\(']
    runtime = '\n'.join(item(source, a, kinds) for a in anchors)
    proto = (root / 'fsd/src/proto.rs').read_text()
    assert re.search(r'pub const ATTR_BYTES: usize = 48;', proto), 'wire fixture size changed'
    runtime = 'mod absd_fsd { pub mod proto { pub const ATTR_BYTES: usize = 48; } }\n' + runtime
    std = kinds.std_items(root)
    full_std = kinds.std_fs_source(root, 'mtime')
    check_hooks(full_std)
    if negative:
        for name in ('stat', 'fstat', 'readdir'):
            old = full_std.replace('__absd_std_fs_' + name + '_v2', '__absd_std_fs_' + name)
            try:
                check_hooks(old)
            except RuntimeError as error:
                print(f'old-{name}-hook: refused {error}', flush=True)
            else:
                raise RuntimeError(f'old-{name}-hook was accepted')
        print('MTIME HOOK CONTROLS OK cases=3', flush=True)
    std += 'impl FileAttr {\n' + item(full_std, r'^    pub fn modified\(&self\)', kinds) + '}\n'
    time = patch_file(root, 'library/std/src/sys/time/absd.rs')
    time = time.replace('use crate::time::Duration;', 'use std::time::Duration;')
    time = '\n'.join(line for line in time.splitlines() if not line.startswith('//!')) + '\n'
    (out / 'time_pal.rs').write_text(time)
    env = {k: v for k, v in os.environ.items() if k != 'RUSTFLAGS'}
    env.update(ABSD_RUNTIME_ATTR_ITEMS=str(out / 'runtime_items.rs'),
               ABSD_STD_FS_ITEMS=str(out / 'std_items.rs'), ABSD_TIME_PAL=str(out / 'time_pal.rs'))
    versions = [('current', runtime, std, 0)]
    if negative:
        assert runtime.count('mtime: word(40)') == 1
        wrong_word = runtime.replace('mtime: word(40)', 'mtime: word(32)')
        assert std.count('return unsupported();') == 1
        invented_epoch = std.replace('return unsupported();', 'return Ok(UNIX_EPOCH);')
        versions += [('wrong-wire-word', wrong_word, std, 1), ('invented-epoch', runtime, invented_epoch, 1)]
    for label, runtime_body, std_body, expected in versions:
        (out / 'runtime_items.rs').write_text(runtime_body)
        (out / 'std_items.rs').write_text(std_body)
        failed = 0
        for name in ['runtime_fs_attr', 'std_fs_mtime']:
            binary = out / (name + '-' + label)
            subprocess.run(['rustc', '+1.95.0', '--edition', '2024', '--target', 'x86_64-unknown-linux-gnu',
                            '--test', str(root / 'tests' / (name + '.rs')), '-o', str(binary)], env=env, check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            (out / (name + '-' + label + '.log')).write_text(result.stdout + result.stderr)
            failed += result.returncode != 0
            summary = next((x for x in result.stdout.splitlines() if x.startswith('test result:')), '')
            print(f'{label} {name}: rc={result.returncode} {summary}', flush=True)
        if (failed > 0) != bool(expected):
            raise RuntimeError(f'{label}: unexpected result failed_suites={failed}')
    # Restore the extracted current sources after negative controls.
    (out / 'runtime_items.rs').write_text(runtime)
    (out / 'std_items.rs').write_text(std)
    subprocess.run(['cc', '-std=c11', '-Werror', '-I', str(root / 'c/include'), '-c',
                    str(root / 'tests/runtime_fs_attr_layout.c'), '-o', str(out / 'layout.o')], check=True)
    print('MTIME HOST OK' + (' negative_controls=2' if negative else ''), flush=True)


if __name__ == '__main__':
    main()
