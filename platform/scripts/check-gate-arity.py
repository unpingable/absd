#!/usr/bin/env python3
"""Validate the gate's single per-profile reproducibility artifact declaration."""
from pathlib import Path
import ast
import re
import shlex
import sys


class Refused(Exception):
    pass


def check(text):
    declarations = re.findall(r'(?ms)^artifact_paths\(\) \{\n    case "\$ABSD_PROFILE" in\n(.*?)^    esac\n\}', text)
    if len(declarations) != 1:
        raise Refused('canonical artifact declaration not found')
    if len(re.findall(r"\bartifact_paths\s*\(\)\s*\{", text)) != 1:
        raise Refused("shadow artifact declaration")
    profiles = {}
    for profile, body in re.findall(r"(?ms)^    (core|full)\) printf '%s\\n' \\\n(.*?) ;;", declarations[0]):
        paths = shlex.split(body.replace('\\\n', ''), comments=True)
        if profile in profiles or not paths or any(
                not re.fullmatch(r'[A-Za-z0-9_./-]+', p) or p.startswith('/') or '..' in p.split('/')
                for p in paths):
            raise Refused('unsupported or dynamic artifact declaration')
        if len(set(paths)) != len(paths):
            raise Refused('duplicate artifact path')
        profiles[profile] = paths
    if set(profiles) != {'core', 'full'}:
        raise Refused('canonical full/core artifact declarations not found')
    if not set(profiles['core']).issubset(profiles['full']):
        raise Refused('core artifact missing from full declaration')
    for name in ('first', 'second'):
        if re.findall(rf'(?m)^[ \t]*{name}_hashes=.*$', text) != [f'{name}_hashes=$(artifact_hashes)']:
            raise Refused(f'{name} stale or independent hash list')
    if not re.search(r'(?m)^artifact_summary\n\nrun=\$\(mktemp', text):
        raise Refused('canonical summary boundary not found')
    consumer = '        paths=$(artifact_paths) || return\n        set -- $paths\n        [ "$#" -gt 0 ] || { echo "empty artifact declaration" >&2; return 1; }\n        sha256sum "$@"'
    if consumer not in text:
        raise Refused('hash consumer does not use artifact declaration')
    if re.search(r'(?m)^.*(?:commands=\d|programs=\d|test "\$#" -eq \d)', text):
        raise Refused('stale literal artifact count')
    comparison = 'test "$first_hashes" = "$second_hashes" || { echo "ABSD RUST REPRODUCIBLE FAILED: program hashes differ between builds" >&2; exit 1; }'
    if text.splitlines().count(comparison) != 1:
        raise Refused('hash comparison boundary not found')
    # Cross-check against the live image owner using Python's standard AST;
    # this is a bounded declaration lint, not an interpreter for arbitrary shell.
    module = ast.parse((Path(__file__).parent / 'operator_image.py').read_text())
    native = next(ast.literal_eval(node.value) for node in module.body
                  if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'NATIVE' for t in node.targets))
    expected = {'commands/' + name for name in native} | {'commands/absd-sh', 'commands/sh', 'commands/sh-probe'}
    for profile, paths in profiles.items():
        if {p for p in paths if p.startswith('commands/')} != expected:
            raise Refused(f'{profile} commands differ from owning image declaration')
    return {profile: len(paths) for profile, paths in profiles.items()}


def main():
    if len(sys.argv) != 2:
        print('usage: check-gate-arity.py CHECK_ALL_SH', file=sys.stderr)
        return 2
    try:
        counts = check(Path(sys.argv[1]).read_text())
    except (Refused, OSError, ValueError) as error:
        print(f'ABSD HASH ARITY REFUSED {error}', file=sys.stderr)
        return 2
    print(f"ABSD HASH ARITY OK full={counts['full']} core={counts['core']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
