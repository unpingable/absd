#!/usr/bin/env python3
"""Compare pinned local SSH-helper import closures before a runner starts.

Reads Git blobs, never imports or executes either source. The caller retains
its existing exact-HEAD and clean-worktree checks before invoking this check.
"""
import argparse
import ast
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT_HELPER = "scripts/ssh_absd.py"
# The same source-context overrides refused by c_kit_source.source().
GIT_OVERRIDES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                 "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                 "GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT")


class Refused(Exception):
    pass


class Source:
    def __init__(self, repository, revision):
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise Refused("helper source revision must be a full commit identity")
        present = [name for name in GIT_OVERRIDES if name in os.environ]
        if present:
            raise Refused("Git source overrides are set: " + ", ".join(present))
        self.repository, self.revision = repository.resolve(), revision
        top = Path(self.git("rev-parse", "--show-toplevel").decode().strip()).resolve()
        if top != self.repository:
            raise Refused("helper source must be the exact checkout root")
        resolved = self.git("rev-parse", revision + "^{commit}").decode().strip()
        if resolved != revision:
            raise Refused("helper source does not name the exact commit")
        self.files = {}
        for entry in self.git("ls-tree", "-rz", "--full-tree", revision, "--", "scripts").split(b"\0"):
            if not entry:
                continue
            metadata, name = entry.split(b"\t", 1)
            path = name.decode()
            if path.endswith(".py"):
                mode, kind, blob = metadata.decode().split()
                self.files[path] = (mode, kind, blob)

    def git(self, *args):
        try:
            # A pinned blob must be read literally, including while finding
            # its imports. Local replacement refs can otherwise hide a leaf.
            return subprocess.check_output(["git", "--no-replace-objects", "-C", str(self.repository), *args],
                                           stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as error:
            raise Refused(f"cannot read pinned helper source: {error.stderr.decode(errors='replace').strip()}") from None

    def blob(self, path):
        record = self.files.get(path)
        if record is None:
            return None
        mode, kind, blob = record
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise Refused(f"helper is not an ordinary source file: {path}")
        return blob

    def read(self, path):
        return self.git("cat-file", "blob", self.blob(path))


def local_imports(source, path, available):
    """The import forms used by the current SSH-helper cohort.

    Standard local modules/packages and script-relative literal importlib
    loads are followed. An unresolved importlib load refuses admission.
    """
    result = set()

    def module(name):
        parts = name.split(".")
        for count in range(1, len(parts) + 1):
            prefix = "scripts/" + "/".join(parts[:count])
            result.update(p for p in (prefix + ".py", prefix + "/__init__.py") if p in available)

    for node in ast.walk(ast.parse(source, filename=path)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise Refused(f"unresolved relative helper import: {path}:{node.lineno}")
            if node.module:
                module(node.module)
                for alias in node.names:
                    module(node.module + "." + alias.name)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "spec_from_file_location":
                value = node.args[1] if len(node.args) >= 2 else None
                if not (isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div)
                        and isinstance(value.left, ast.Name) and value.left.id in {"here", "HERE"}
                        and isinstance(value.right, ast.Constant) and isinstance(value.right.value, str)
                        and re.fullmatch(r"[A-Za-z0-9_.-]+\.py", value.right.value)):
                    raise Refused(f"unresolved importlib helper path: {path}:{node.lineno}")
                result.add(str(PurePosixPath(path).parent / value.right.value))
            elif node.func.attr == "import_module":
                if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                    raise Refused(f"unresolved importlib helper module: {path}:{node.lineno}")
                module(node.args[0].value)
    return result


def closure(source, available):
    pending, seen = [ROOT_HELPER], set()
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        if source.blob(path) is not None:
            pending.extend(local_imports(source.read(path), path, available) - seen)
    return seen


def compare(harness, candidate):
    available = set(harness.files) | set(candidate.files)
    paths = closure(harness, available) | closure(candidate, available)
    mismatches = []
    for path in sorted(paths):
        left, right = harness.blob(path), candidate.blob(path)
        if left is None or right is None or left != right:
            mismatches.append(f"{path} harness={left or 'missing'} candidate={right or 'missing'}")
    if mismatches:
        raise Refused("; ".join(mismatches))
    return sorted(paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--harness-rev", required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--candidate-rev", required=True)
    args = parser.parse_args()
    try:
        paths = compare(Source(args.harness, args.harness_rev), Source(args.candidate, args.candidate_rev))
    except (Refused, OSError, SyntaxError, ValueError) as error:
        print(f"ABSD HARNESS COHORT REFUSED {error}", file=sys.stderr)
        return 2
    print(f"ABSD HARNESS COHORT OK helpers={len(paths)} harness={args.harness_rev} candidate={args.candidate_rev}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
