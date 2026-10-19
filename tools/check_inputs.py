#!/usr/bin/env python3
"""Discover literal documentation inputs of the retained Python/Rust checks.

This is a bounded source-curation check, not a build dependency solver. It
recognizes Rust literal include_str!/include_bytes! and Python Path joins
rooted at __file__, including module-level aliases, parent(s), and resolve,
and @relative-file fields in TSV fixtures.
Dynamic paths, generated inputs and external tools remain qualification work.
No component code is imported or executed.
"""
import argparse
import ast
import csv
import hashlib
import json
import posixpath
import re
import subprocess
from pathlib import Path, PurePosixPath


class Problem(Exception):
    pass


def doc_path(value):
    if isinstance(value, PurePosixPath):
        value = PurePosixPath(posixpath.normpath(str(value)))
        try:
            rel = value.relative_to('/component')
        except ValueError:
            return None
        if rel.parts[:1] == ('docs',) and rel.suffix:
            return str(rel)
    return None


def python_paths(name, source):
    tree = ast.parse(source, filename=name)
    env = {'__file__': PurePosixPath('/component') / name}

    def value(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
            return node.value
        if isinstance(node, ast.Name):
            return env.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left, right = value(node.left), value(node.right)
            if isinstance(left, PurePosixPath) and isinstance(right, str):
                return left / right
        if isinstance(node, ast.Attribute) and node.attr == 'parent':
            parent = value(node.value)
            if isinstance(parent, PurePosixPath):
                return parent.parent
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == 'parents':
            parent, index = value(node.value.value), value(node.slice)
            if isinstance(parent, PurePosixPath) and isinstance(index, int) and 0 <= index < len(parent.parents):
                return parent.parents[index]
        if isinstance(node, ast.Call):
            path_call = (isinstance(node.func, ast.Name) and node.func.id == 'Path') or (
                isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                and node.func.value.id == 'pathlib' and node.func.attr == 'Path')
            if path_call and len(node.args) == 1:
                arg = value(node.args[0])
                if isinstance(arg, PurePosixPath):
                    return arg
            if isinstance(node.func, ast.Attribute) and node.func.attr in ('resolve', 'absolute') and not node.args and not node.keywords:
                return value(node.func.value)
        return None

    found = set()
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            result = value(statement.value)
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    env[target.id] = result
        for node in ast.walk(statement):
            path = doc_path(value(node))
            if path and path != name:
                found.add((path, name, node.lineno))
    return found


def discover(files):
    """Return (input path, consumer, line) for supported literal expressions."""
    found = set()
    for name, data in sorted(files.items()):
        if name.endswith('.py'):
            found.update(python_paths(name, data.decode('utf-8')))
        elif name.endswith('.rs'):
            source = data.decode('utf-8')
            for match in re.finditer(r'\binclude_(?:str|bytes)!\s*\(\s*"([^"\\]+)"\s*\)', source):
                path = doc_path(PurePosixPath('/component') / PurePosixPath(name).parent / match[1])
                if path:
                    found.add((path, name, source.count('\n', 0, match.start()) + 1))
        elif name.endswith('.tsv'):
            # Fixture tables use @relative-file for stdin. Do not interpret
            # command text or regular expressions as dependency declarations.
            for line, fields in enumerate(csv.reader(data.decode('utf-8').splitlines(), delimiter='\t'), 1):
                if fields and not fields[0].startswith('#'):
                    for field in fields:
                        if re.fullmatch(r'@[A-Za-z0-9_./-]+', field):
                            path = doc_path(PurePosixPath('/component') / PurePosixPath(name).parent / field[1:])
                            if path:
                                found.add((path, name, line))
    return sorted(found)


def check_file_hashes(files):
    """Check retained literal $root/file pins used by the shell verifier.

    This recognizes expect_file_hash/expect_extended_file_hash calls with a
    literal digest and path. External, computed and excluded-profile inputs
    remain the actual verifier's job. It changes no pin and executes no shell.
    """
    pattern = re.compile(r'(?m)^[ \t]*(expect_(?:extended_)?file_hash)[ \t]+'
                         r'([0-9a-f]{64})[ \t]+"\$root/([^"\n]+)"[ \t]*$')
    checked = []
    for consumer, data in sorted(files.items()):
        if not consumer.endswith('.sh'):
            continue
        for helper, expected, path in pattern.findall(data.decode('utf-8').replace('\\\n', ' ')):
            if path not in files:
                continue
            actual = hashlib.sha256(files[path]).hexdigest()
            if actual != expected:
                raise Problem(f'{consumer}: retained file hash differs for {path}: expected {expected}, actual {actual}')
            checked.append(dict(consumer=consumer, input=path, expected=expected, actual=actual, helper=helper))
    return checked


def check(root):
    root = Path(root).resolve()
    names = subprocess.check_output(['git', '-C', str(root), 'ls-tree', '-r', '--name-only', '-z', 'HEAD'], text=True).split('\0')
    results = []
    for component in ('kernel', 'platform'):
        prefix = component + '/'
        tracked = {n[len(prefix):] for n in names if n.startswith(prefix)}
        files = {n: (root / component / n).read_bytes() for n in tracked
                 if (root / component / n).is_file()}
        check_file_hashes(files)
        for path, consumer, line in discover(files):
            target = root / component / path
            if path not in tracked or not target.is_file() or target.is_symlink():
                raise Problem(f'{component}/{consumer}:{line}: missing tracked check input {component}/{path}')
            results.append({'component': component, 'input': path, 'consumer': consumer, 'line': line})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    try:
        print(json.dumps({'result': 'PASS', 'scope': 'literal check inputs and retained literal shell file-hash pins',
                          'inputs': check(args.root)}, indent=2))
    except (Problem, OSError, subprocess.CalledProcessError, SyntaxError) as error:
        parser.exit(1, f'CHECK INPUTS REFUSED: {error}\n')


if __name__ == '__main__':
    main()
