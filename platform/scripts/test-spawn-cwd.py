#!/usr/bin/env python3
"""Actual runtime cwd/plan code and FSD dispatcher, with finite host transport."""
import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def item(source, marker):
    start = source.index(marker)
    at = source.index('{', start)
    depth, end = 1, at + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--counterfactual-parent', action='store_true')
    parser.add_argument('--counterfactual-stale-policy', action='store_true')
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    process = (ROOT / 'runtime/src/process.rs').read_text()
    server = (ROOT / 'ssh/src/fsd_server.rs').read_text()
    storage = (ROOT / 'runtime/src/storage.rs').read_text()
    ssh = (ROOT / 'ssh/src/absd.rs').read_text()
    begin = process.index('    let plan = crate::fsd::plan_child()?;')
    end = process.index('    let channel_ends = plan.ends();', begin)
    cwd_begin = process.index('let child_cwd =')
    assert cwd_begin < begin < process.index('spawn_image_raw(spawn_request', begin)
    assert 'stat_kind' not in process[cwd_begin:process.index(
        '// SAFETY: single-threaded runtime', cwd_begin)]
    control_begin = server.index('    let control = vec![')
    control_end = server.index('];', control_begin) + 2
    fixture = (ROOT / 'scripts/fixtures/spawn-cwd.rs').read_text()
    replacements = {
        '@ROOT@': str(ROOT),
        '@NOTDIR@': re.search(r'(?:pub )?const SPAWN_NOT_A_DIRECTORY[^;]+;', process)[0],
        '@CONTROL@': server[control_begin:control_end],
        '@SESSION@': item(ssh, 'fn session_mounts('),
        '@STAT@': item(storage, 'pub(crate) fn stat_kind('),
        '@ERRNO@': item(storage, 'fn errno('),
        '@VALIDATE@': item(process, 'fn validate_child_cwd('),
        '@WRAPPER@': item(process, 'pub unsafe extern "C" fn __absd_std_process_spawn_image('),
        '@PREPARE@': process[begin:end],
    }
    for key, value in replacements.items():
        fixture = fixture.replace(key, value)
    if args.counterfactual_parent:
        original = ('let kind = crate::fsd::child_cwd_kind(plan, directory)\n'
                    '        .or_else(|| crate::storage::stat_kind(directory));')
        assert original in fixture
        fixture = fixture.replace(original, 'let kind = crate::storage::stat_kind(directory);')
    if args.counterfactual_stale_policy:
        original = 'crate::fsd::cancel_next_child();'
        assert original in fixture
        fixture = fixture.replace(original, '/* counterfactual: leave one-shot policy armed */')

    # Reuse the existing host dependency set/lock. Only our fixture and target
    # directory are mutable; there is no network or product staging.
    (work / 'main.rs').write_text(fixture)
    manifest = (ROOT / 'tests/Cargo.toml').read_text()
    manifest = manifest[:manifest.index('[[test]]')]
    manifest = manifest.replace('path = "../src/health_observation.rs"',
                                f'path = "{ROOT}/src/health_observation.rs"')
    for name in ['fs', 'fsd', 'release']:
        manifest = manifest.replace(f'path = "../{name}"', f'path = "{ROOT}/{name}"')
    manifest += '\n[[bin]]\nname="spawn-cwd"\npath="main.rs"\n'
    (work / 'Cargo.toml').write_text(manifest)
    (work / 'Cargo.lock').write_bytes((ROOT / 'tests/Cargo.lock').read_bytes())
    env = {**os.environ, 'CARGO_TARGET_DIR': str(work / 'target'),
           'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_INCREMENTAL': '0'}
    for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
                'RUSTC_WORKSPACE_WRAPPER']:
        env.pop(key, None)
    result = subprocess.run([
        'cargo', '+1.95.0', 'run', '--manifest-path', str(work / 'Cargo.toml'),
        '--target', 'x86_64-unknown-linux-gnu', '--offline', '--locked', '-j2',
        '--bin', 'spawn-cwd',
    ], cwd=ROOT, env=env)
    if result.returncode:
        raise SystemExit(result.returncode)
    print('SPAWN CWD PRODUCTION/FSD HOST CONTROLS PASS')


if __name__ == '__main__':
    main()
