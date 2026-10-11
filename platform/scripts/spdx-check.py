#!/usr/bin/env python3
"""File-level licensing metadata check. See docs/SOURCE-LICENSING.md.

Every tracked file must be classified by a `provenance.toml` rule. A file
whose rule states a licence must carry matching REUSE information (an SPDX
tag in the file, a `.license` sidecar, or a `REUSE.toml` annotation) and the
licence text under `LICENSES/`. A file whose rule says `pending` must carry
no licence declaration at all.

    scripts/spdx-check.py                  # development: pending is not a failure
    scripts/spdx-check.py --mode release   # pending and unresolved block
    scripts/spdx-check.py --base main      # also report what a change introduces
    scripts/spdx-check.py --json           # machine-readable report on stdout

Findings are one of: missing-metadata, unknown-licensing, conflict,
accepted-exception, new-obligation. Exit status: 0 pass, 1 findings that
fail in the selected mode, 2 unusable configuration.

This is not `reuse lint` and passing it is not REUSE compliance. It covers
tracked files (and, with --base, files not yet added); linked dependencies and their notices belong to the
release tooling.
"""

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

# Assembled so that this file does not itself carry the tags it looks for.
LICENSE_TAG = "SPDX" + "-License-Identifier"
IGNORE_START = "REUSE-Ignore" + "Start"
IGNORE_END = "REUSE-Ignore" + "End"

CLASSES = ("first-party", "adapted", "generated", "imported", "unresolved")
CATEGORIES = (
    "missing-metadata",
    "unknown-licensing",
    "conflict",
    "accepted-exception",
    "new-obligation",
)
PENDING = "pending"

TAG_RE = re.compile(LICENSE_TAG + r":[ \t]+(.+?)[ \t]*(?:\*/|-->)?[ \t]*$", re.M)
IGNORE_RE = re.compile(IGNORE_START + r".*?" + IGNORE_END, re.S)
CARGO_LICENSE_RE = re.compile(r'^license\s*=\s*"([^"]+)"', re.M)
LICENSE_TEXT_NAME_RE = re.compile(r"^(LICEN[CS]E|COPYING)([-.].*)?$")
LICENSE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
# Phrases that, on a line added to a pending file, usually mean someone
# else's work came with it.
# REUSE-IgnoreStart
MARKER_RE = re.compile(
    r"(?i:copyright\s*(\(c\)|©|\d{4})|licensed under|permission is hereby granted"
    r"|redistribution and use|all rights reserved|gnu (lesser |affero )?general public"
    r"|\b(adapted|ported|vendored) from"
    # "derived from the request" is ordinary prose; the same words followed
    # by a project name are not.
    r"|\b(derived|copied|taken) from\b[^.;]*\b(linux|\w*bsd|gnu|upstream|github|gitlab|kernel\.org)\b)"
    r"|SPDX-[A-Z]"
)
# REUSE-IgnoreEnd
# scripts/provenance.py's own records (docs/PROVENANCE.md); nothing else
# under provenance/ is exempt from anything.
READINESS_RECORD_RE = re.compile(
    r"^provenance/((config|obligations)\.toml|(inventory|baseline)/[^/]+\.tsv|upstream-notices/[^/]+)$"
)
LOCK_RE = re.compile(r"(^|/)(Cargo\.lock|[^/]*\.Cargo\.lock)$")


class ConfigError(Exception):
    pass


def git(root, *args):
    return subprocess.run(
        ("git", "-C", str(root)) + args, check=True, capture_output=True
    ).stdout


def glob_regex(pattern):
    """REUSE.toml globbing: `*` stops at `/`, `**` does not."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def as_list(value):
    return value if isinstance(value, list) else [value]


def normalize(expression):
    return " ".join(expression.split())


def license_ids(expression):
    return {
        word
        for word in LICENSE_ID_RE.findall(expression)
        if word not in ("AND", "OR", "WITH")
    }


class Rules:
    """Ordered path rules; the last rule that matches a path wins."""

    def __init__(self, entries, where):
        self.entries = []
        for index, entry in enumerate(entries):
            if "path" not in entry:
                raise ConfigError(f"{where} entry {index + 1} has no path")
            patterns = [glob_regex(p) for p in as_list(entry["path"])]
            self.entries.append((patterns, entry))
        self.used = [False] * len(self.entries)

    def match(self, path):
        for index in range(len(self.entries) - 1, -1, -1):
            patterns, entry = self.entries[index]
            if any(p.match(path) for p in patterns):
                self.used[index] = True
                return entry
        return None

    def unused(self):
        return [e for (_, e), used in zip(self.entries, self.used) if not used]


def load_toml(path):
    try:
        with open(path, "rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"{path}: {error}") from error


def load_inventory(root):
    path = root / "provenance.toml"
    if not path.exists():
        raise ConfigError("provenance.toml not found")
    data = load_toml(path)
    if data.get("version") != 1:
        raise ConfigError("provenance.toml: version must be 1")
    for index, rule in enumerate(data.get("files", [])):
        where = f"provenance.toml files entry {index + 1}"
        cls = rule.get("class")
        if cls not in CLASSES:
            raise ConfigError(f"{where}: class must be one of {', '.join(CLASSES)}")
        if "license" not in rule and cls != "unresolved":
            raise ConfigError(f"{where}: license is required ('pending' or an expression)")
        required = {
            "adapted": ("origin", "upstream-license"),
            "imported": ("origin",),
            "generated": ("generator",),
            "unresolved": ("reason",),
        }.get(cls, ())
        for key in required:
            if key not in rule:
                raise ConfigError(f"{where}: class {cls} requires {key}")
        if cls == "imported" and rule["license"] == PENDING:
            raise ConfigError(f"{where}: imported material cannot be pending; use unresolved")
    for index, entry in enumerate(data.get("exceptions", [])):
        where = f"provenance.toml exceptions entry {index + 1}"
        for key in ("path", "finding", "reason", "decided-by", "date"):
            if key not in entry:
                raise ConfigError(f"{where}: {key} is required")
        if entry["finding"] not in ("missing-metadata", "unknown-licensing", "conflict"):
            raise ConfigError(f"{where}: finding cannot be {entry['finding']}")
    return (
        Rules(data.get("files", []), "provenance.toml files"),
        Rules(data.get("exceptions", []), "provenance.toml exceptions"),
    )


def load_annotations(root):
    path = root / "REUSE.toml"
    if not path.exists():
        return Rules([], "REUSE.toml")
    data = load_toml(path)
    if data.get("version") != 1:
        raise ConfigError("REUSE.toml: version must be 1")
    return Rules(data.get("annotations", []), "REUSE.toml annotations")


def read_text(path):
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return IGNORE_RE.sub("", data.decode("utf-8", "replace"))


def declared_in_file(root, path):
    """The licence expression a file or its sidecar states, and where."""
    text = read_text(root / path)
    tags = sorted({normalize(t) for t in TAG_RE.findall(text)}) if text else []
    if tags:
        return " AND ".join(tags), "file"
    sidecar = root / (path + ".license")
    if sidecar.exists():
        text = read_text(sidecar) or ""
        tags = sorted({normalize(t) for t in TAG_RE.findall(text)})
        if tags:
            return " AND ".join(tags), "sidecar"
    return None, None


def effective_license(root, path, annotations):
    in_file, source = declared_in_file(root, path)
    annotation = annotations.match(path)
    annotated = None
    if annotation and LICENSE_TAG in annotation:
        annotated = " AND ".join(normalize(e) for e in as_list(annotation[LICENSE_TAG]))
        if annotation.get("precedence") == "override" or in_file is None:
            return annotated, "REUSE.toml"
    return in_file, source


def is_metadata(path):
    name = path.rsplit("/", 1)[-1]
    return (
        path.startswith("LICENSES/")
        or path == "REUSE.toml"
        or path.endswith(".license")
        or LICENSE_TEXT_NAME_RE.match(name) is not None
    )


def check_tree(root, files, inventory, exceptions, annotations):
    findings = []
    texts = {p.name[:-4] for p in (root / "LICENSES").glob("*.txt")}
    used_ids = set()

    def report(category, path, detail, rule=None):
        if category != "accepted-exception":
            exception = exceptions.match(path)
            if exception and exception["finding"] == category:
                detail = f"{detail}; accepted: {exception['reason']}"
                category = "accepted-exception"
        findings.append(
            {
                "category": category,
                "path": path,
                "detail": detail,
                "class": rule.get("class") if rule else None,
            }
        )

    for path in files:
        if is_metadata(path):
            continue
        rule = inventory.match(path)
        if rule is None:
            report("missing-metadata", path, "no provenance.toml rule classifies this file")
            continue
        cls = rule["class"]
        stated = rule.get("license", PENDING)
        effective, source = effective_license(root, path, annotations)

        if cls == "unresolved":
            report("unknown-licensing", path, f"unresolved: {rule['reason']}", rule)
            continue

        if stated == PENDING:
            if effective is not None:
                report(
                    "conflict",
                    path,
                    f"{source} declares {effective} but provenance.toml says pending",
                    rule,
                )
                continue
            if path.rsplit("/", 1)[-1] == "Cargo.toml":
                text = read_text(root / path) or ""
                field = CARGO_LICENSE_RE.search(text)
                if field and normalize(field.group(1)) != rule.get("upstream-license"):
                    report(
                        "conflict",
                        path,
                        f"manifest declares {field.group(1)} but provenance.toml says pending",
                        rule,
                    )
                    continue
            report("unknown-licensing", path, "licence pending owner decision", rule)
            continue

        stated = normalize(stated)
        used_ids |= license_ids(stated)
        if effective is None:
            report(
                "missing-metadata",
                path,
                f"provenance.toml states {stated} but no SPDX tag, sidecar, or "
                "REUSE.toml annotation carries it",
                rule,
            )
        elif effective != stated:
            report(
                "conflict",
                path,
                f"{source} declares {effective} but provenance.toml states {stated}",
                rule,
            )
        else:
            for missing in sorted(license_ids(stated) - texts):
                report("missing-metadata", path, f"no LICENSES/{missing}.txt", rule)
            if rule.get("first-party-portion") == PENDING:
                report(
                    "unknown-licensing",
                    path,
                    f"{stated} covers the upstream content; the ABSD changes are pending",
                    rule,
                )

    pending = any(e.get("class") == "first-party" and e.get("license") == PENDING for _, e in inventory.entries)
    for path in files:
        if "/" not in path and LICENSE_TEXT_NAME_RE.match(path) and pending:
            report(
                "conflict",
                path,
                "a licence file at the repository root reads as the project's licence, "
                "but provenance.toml records first-party files as pending",
            )

    notes = []
    for rule in inventory.unused():
        notes.append(f"provenance.toml rule matches no tracked file: {rule['path']}")
    for entry in exceptions.unused():
        notes.append(f"provenance.toml exception matches no finding's path: {entry['path']}")
    for annotation in annotations.unused():
        notes.append(f"REUSE.toml annotation matches no checked file: {annotation['path']}")
    for name in sorted(texts - used_ids):
        notes.append(f"LICENSES/{name}.txt is not used by any provenance.toml rule")
    return findings, notes


def check_change(root, base, inventory):
    """What the difference from `base` to the working tree brings with it."""
    findings = []

    def report(path, detail, kind):
        # `kind` is the stable name of the rule; `detail` is for people.
        findings.append(
            {"category": "new-obligation", "path": path, "detail": detail, "class": None, "kind": kind}
        )

    names = git(root, "diff", "--name-only", "-z", "--diff-filter=AM", base, "--")
    changed = [n for n in names.decode().split("\0") if n]
    untracked = git(root, "ls-files", "-z", "--others", "--exclude-standard")
    changed += [n for n in untracked.decode().split("\0") if n]
    before = git(root, "ls-tree", "-r", "--name-only", base, "--", "LICENSES").decode()
    before = {line.rsplit("/", 1)[-1] for line in before.splitlines()}
    for path in sorted(set(changed)):
        if path.startswith("LICENSES/"):
            if path.rsplit("/", 1)[-1] not in before:
                report(path, "licence text new to this repository", "licence-text-new")
            continue
        if LOCK_RE.search(path):
            report(path, "dependency set changed; regenerate the release notice set", "lock-changed")
            continue
        if is_metadata(path):
            continue
        rule = inventory.match(path)
        if rule is None:
            continue
        if rule["class"] in ("imported", "adapted"):
            report(
                path,
                f"{rule['class']} material added or changed "
                f"(upstream terms: {rule.get('upstream-license', rule.get('license'))})",
                "third-party-changed",
            )
            continue
        if rule.get("license", PENDING) != PENDING:
            continue
        # Prose about other projects (documents, manual pages) and the
        # release-readiness records, which quote upstream notices, use this
        # vocabulary freely; the wording rule is for source and build files.
        if path.endswith(".md") or path.startswith(("docs/", "man/")) or READINESS_RECORD_RE.match(path):
            continue
        diff = subprocess.run(
            ("git", "-C", str(root), "diff", "-U0", "--no-color", base, "--", path),
            capture_output=True,
        ).stdout.decode("utf-8", "replace")
        if not diff:
            diff = "\n".join("+" + l for l in (read_text(root / path) or "").splitlines())
        added = IGNORE_RE.sub("", diff)
        hits = [
            line[1:].strip()
            for line in added.splitlines()
            if line.startswith("+") and not line.startswith("+++") and MARKER_RE.search(line)
        ]
        if hits:
            report(path, f"attribution wording added to a pending file: {hits[0][:100]}", "attribution-wording")
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", help="repository root (default: this script's repository)")
    parser.add_argument("--mode", choices=("dev", "release"), default="dev")
    parser.add_argument("--base", help="revision to compare against for new obligations")
    parser.add_argument("--fail-on-new", action="store_true", help="new obligations fail")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    parser.add_argument("--list", action="store_true", help="list every finding as text")
    args = parser.parse_args()

    root = Path(args.root) if args.root else Path(__file__).resolve().parent.parent
    try:
        inventory, exceptions = load_inventory(root)
        annotations = load_annotations(root)
        tracked = git(root, "ls-files", "-z").decode().split("\0")
        if args.base:
            # Judging a change: files not yet added are part of it.
            others = git(root, "ls-files", "-z", "--others", "--exclude-standard").decode().split("\0")
            tracked = sorted(set(tracked) | set(others))
        files = sorted(p for p in tracked if p and (root / p).is_file())
        findings, notes = check_tree(root, files, inventory, exceptions, annotations)
        if args.base:
            findings += check_change(root, args.base, inventory)
    except ConfigError as error:
        print(f"spdx-check: {error}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as error:
        print(f"spdx-check: {error.stderr.decode().strip()}", file=sys.stderr)
        return 2

    failing = {"missing-metadata", "conflict"}
    if args.mode == "release":
        failing.add("unknown-licensing")
    if args.fail_on_new:
        failing.add("new-obligation")
    counts = {c: sum(1 for f in findings if f["category"] == c) for c in CATEGORIES}
    failed = sorted(c for c in failing if counts[c])
    flagged = {f["path"] for f in findings if f["category"] != "new-obligation"}
    report = {
        "schema": "absd-spdx-check/1",
        "mode": args.mode,
        "base": args.base,
        "files": len(files),
        "established": len([p for p in files if not is_metadata(p) and p not in flagged]),
        "counts": counts,
        "failing_categories": failed,
        "pass": not failed,
        "findings": findings,
        "notes": notes,
    }

    if args.json:
        json.dump(report, sys.stdout, indent=1)
        print()
    else:
        print(f"spdx-check ({args.mode}): {len(files)} tracked files, "
              f"{report['established']} with established licensing")
        for category in CATEGORIES:
            marker = "FAIL" if category in failed else "ok  "
            print(f"  {marker} {category}: {counts[category]}")
        shown = failing | {"accepted-exception", "new-obligation"}
        if not args.list:
            # Pending first-party files are the bulk of the tree; summarize them.
            shown.discard("unknown-licensing")
            by_class = {}
            for finding in findings:
                if finding["category"] == "unknown-licensing":
                    by_class[finding["class"]] = by_class.get(finding["class"], 0) + 1
            for cls, count in sorted(by_class.items()):
                print(f"unknown-licensing: {count} {cls} files (--list names them)")
        for finding in findings:
            if args.list or finding["category"] in shown:
                print(f"{finding['category']}: {finding['path']}: {finding['detail']}")
        for note in notes:
            print(f"note: {note}")
        print("PASS" if not failed else "FAIL: " + ", ".join(failed))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
