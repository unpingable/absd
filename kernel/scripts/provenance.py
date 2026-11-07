#!/usr/bin/env python3
"""Provenance, licensing and distribution-readiness checks (docs/PROVENANCE.md).

  provenance.py check [--base REF]   fast: what a change adds to the baseline
  provenance.py full [--out DIR]     whole tree, inventory, notices, readiness
  provenance.py update               regenerate provenance/inventory/*.tsv
  provenance.py notices ARTIFACT --out DIR   candidate third-party notice bundle
  provenance.py report [--require source|binary]   release readiness

check and full end with the licence-policy gate ([licence_policy] in
provenance/config.toml): LICENCE POLICY DISTRIBUTION (the shipped closure;
PASS or FAIL n, and the command fails with it), LICENCE INVENTORY (the rest
of the repository, reported) and LICENCE HOST TOOLS (recorded).

This tool owns the release-readiness decision. Per-file licensing
classification is provenance.toml at the repository root, and its validation
is scripts/spdx-check.py (docs/SOURCE-LICENSING.md): this tool runs that
check and reads that file; it does not restate either. Its own records are
under provenance/: config.toml (baseline identity, coverage, dependency
licence policy, artifacts), obligations.toml (known obligations and
decisions), inventory/ (generated dependency inventory), baseline/ (inventory
frozen at the reviewed baseline). Python standard library, plus the pinned license-expression library for the licence gate; no network;
nothing is built.

A passing check is a mechanical result. It is not legal clearance, and it
does not show that unchanged code is original: the baseline's coverage limits
are printed with every full report.
"""
import argparse
import copy
import ast
import fnmatch
import glob
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORDER = ["UNCHANGED", "UNKNOWN", "NEW_REVIEW_REQUIRED", "COMPLIANCE_ACTION_REQUIRED", "BLOCKED"]
DEP_TABLES = (("dependencies", "normal"), ("build-dependencies", "build"), ("dev-dependencies", "dev"))
LICENSE_NAMES = re.compile(r"^(licen[sc]e|copying|notice|unlicense|copyright)", re.I)
SECRETS = re.compile(
    r"BEGIN [A-Z ]*PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"
    r"|xox[abprs]-[A-Za-z0-9-]{20,}|hooks\.slack\.com/services/|AKIA[0-9A-Z]{16}|sk-ant-[A-Za-z0-9_-]{20,}"
)
# PKCS#8 / PKCS#1 / SEC1 private keys in DER: a SEQUENCE holding version 0 or 1.
DER_KEY = re.compile(rb"^\x30[\x2e-\x82].{0,3}\x02\x01[\x00\x01]", re.S)
KEY_NAMES = re.compile(r"(\.pk8|\.p12|\.pfx|\.key|id_(rsa|ed25519|ecdsa)|\.pem)$")
RECORDS = re.compile(r"^(provenance\.toml|REUSE\.toml|provenance/((config|obligations)\.toml|(inventory|baseline)/[^/]+\.tsv))$")
DEV_PATHS = re.compile(r"(/home/[a-z_][a-z0-9_-]*/|/Users/[A-Za-z0-9_.-]+/|/data/git/)")


class Problem(Exception):
    pass


def git(*args, root=None, check=True, text=True):
    r = subprocess.run(["git", "-C", str(root or ROOT), *args], capture_output=True,
                       **({"encoding": "utf-8", "errors": "surrogateescape"} if text else {}))
    if check and r.returncode:
        raise Problem(f"git {' '.join(args)}: {r.stderr.strip() if text else r.stderr!r}")
    return r.stdout


def match(path, globs):
    return any(fnmatch.fnmatchcase(path, g) for g in globs)


def load(root, name, required=True):
    p = root / "provenance" / name
    if not p.exists():
        if required:
            raise Problem(f"{p}: missing")
        return {}
    try:
        return tomllib.loads(p.read_text())
    except tomllib.TOMLDecodeError as error:
        raise Problem(f"{p}: not valid TOML: {error}") from None


THIRD_PARTY = ("vendored", "upstream-patch", "adapted")


def spdx_module(root):
    """scripts/spdx-check.py, loaded for its provenance.toml rule matching."""
    path = Path(root) / "scripts/spdx-check.py"
    if not path.exists():
        raise Problem(f"{path}: missing (it owns the file-level licensing rules)")
    spec = importlib.util.spec_from_file_location("spdx_check", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Records:
    def __init__(self, root=ROOT):
        # Resolved, as ROOT is: the manifest crawl follows symlinks and so
        # yields resolved paths, which are compared with this root.
        self.root = Path(root).resolve()
        self.config = load(self.root, "config.toml")
        self.obligations = load(self.root, "obligations.toml", required=False).get("obligation", [])
        self.policy = self.config.get("policy", {})
        self.scan = self.config.get("scan", {})
        self.spdx = spdx_module(self.root)
        try:
            self.rules, _ = self.spdx.load_inventory(self.root)
        except self.spdx.ConfigError as error:
            raise Problem(f"provenance.toml: {error}") from None
        self.declarations = [self.declaration(entry) for _, entry in self.rules.entries]
        self.declarations = [d for d in self.declarations if d]

    @staticmethod
    def declaration(rule):
        """A provenance.toml rule seen as declared material, or None for
        plain first-party and generated files. Third-party kinds: imported
        (vendored), adapted, and generated from an upstream source."""
        cls = rule.get("class")
        if cls == "imported":
            kind, terms = "vendored", rule.get("license", "")
        elif cls == "adapted" or (cls == "generated" and rule.get("upstream-license")):
            kind, terms = "adapted", rule.get("upstream-license", "")
        elif rule.get("kind"):
            kind, terms = rule["kind"], ""
        else:
            return None
        paths = rule["path"] if isinstance(rule["path"], list) else [rule["path"]]
        return {"id": rule.get("id", paths[0]), "kind": kind, "license": terms, "origin": rule.get("origin", ""),
                "notice": rule.get("upstream-notice", ""), "license_files": rule.get("notice-files", []),
                "binary_actions": rule.get("binary-actions", []), "in_artifacts": rule.get("in-artifacts"),
                "decision": rule.get("decision"), "rule": rule}

    def declared(self, path):
        """The provenance.toml rule that classifies PATH (the last match
        wins, as spdx-check decides), when it declares non-first-party material."""
        rule = self.rules.match(path)
        return [d for d in self.declarations if d["rule"] is rule] if rule else []


# ---------------------------------------------------------------- licences

def local_license_tree(expr):
    """SPDX expression -> nested ('or'|'and', [..]) / ('id', name). '/' is the legacy OR."""
    tokens = re.findall(r"\(|\)|[A-Za-z0-9.+-]+", expr.replace("/", " OR "))
    pos = 0

    def atom():
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError(expr)
        t = tokens[pos]
        pos += 1
        if t == "(":
            node = either()
            # A group must close where it ends: nothing is skipped over.
            if pos >= len(tokens) or tokens[pos] != ")":
                raise ValueError(expr)
            pos += 1
            return node
        if t == ")" or t.upper() in ("AND", "OR", "WITH"):
            raise ValueError(expr)
        if pos < len(tokens) and tokens[pos].upper() == "WITH":
            if pos + 1 >= len(tokens) or tokens[pos + 1] in ("(", ")") or tokens[pos + 1].upper() in ("AND", "OR", "WITH"):
                raise ValueError(expr)
            t = f"{t} WITH {tokens[pos + 1]}"
            pos += 2
        return ("id", t)

    def both():
        nonlocal pos
        parts = [atom()]
        while pos < len(tokens) and tokens[pos].upper() == "AND":
            pos += 1
            parts.append(atom())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def either():
        nonlocal pos
        parts = [both()]
        while pos < len(tokens) and tokens[pos].upper() == "OR":
            pos += 1
            parts.append(both())
        return parts[0] if len(parts) == 1 else ("or", parts)

    node = either()
    if pos != len(tokens):
        raise ValueError(expr)
    return node


def elect(expr, policy):
    """The licences taken from EXPR under the policy's preference order, or None
    when no alternative consists only of accepted licences."""
    prefer = policy.get("prefer", [])

    def walk(node):
        kind, value = node
        if kind == "id":
            return [value] if value in prefer else None
        options = [walk(part) for part in value]
        if kind == "and":
            return None if None in options else sorted({x for o in options for x in o})
        options = [o for o in options if o is not None]
        return min(options, key=lambda o: max(prefer.index(x) for x in o)) if options else None

    try:
        return walk(license_tree(expr))
    except ValueError:
        return None


# ---------------------------------------------------------------- cargo graph

class Cfg:
    def __init__(self, target):
        self.triple = target.get("triple", "")
        self.names = set(target.get("names", []))
        self.values = {k: set(v if isinstance(v, list) else [v]) for k, v in target.get("values", {}).items()}

    def holds(self, spec):
        spec = spec.strip()
        if not spec.startswith("cfg("):
            return spec == self.triple
        tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*|"[^"]*"|[(),=]', spec[3:])
        pos = 0

        def pred():
            nonlocal pos
            name = tokens[pos]
            pos += 1
            if pos < len(tokens) and tokens[pos] == "(":
                pos += 1
                parts = []
                while tokens[pos] != ")":
                    parts.append(pred())
                    if tokens[pos] == ",":
                        pos += 1
                pos += 1
                return {"all": all, "any": any}[name](parts) if name != "not" else not parts[0]
            if pos < len(tokens) and tokens[pos] == "=":
                value = tokens[pos + 1].strip('"')
                pos += 2
                return value in self.values.get(name, ())
            return name in self.names

        pos += 1  # the opening parenthesis of cfg(
        return pred()


class Manifest:
    def __init__(self, path):
        self.path = Path(path)
        doc = tomllib.loads(self.path.read_text())
        self.doc = doc
        pkg = doc.get("package", {})
        self.name = pkg.get("name")
        self.version = pkg.get("version") if isinstance(pkg.get("version"), str) else None
        self.license = pkg.get("license") if isinstance(pkg.get("license"), str) else None
        self.license_file = pkg.get("license-file") if isinstance(pkg.get("license-file"), str) else None
        self.proc_macro = bool(doc.get("lib", {}).get("proc-macro") or doc.get("lib", {}).get("proc_macro"))
        self.features = doc.get("features", {})
        self.deps = []
        tables = [(None, doc)] + [(spec, t) for spec, t in doc.get("target", {}).items()]
        for spec, table in tables:
            for key, kind in DEP_TABLES:
                for name, value in table.get(key, {}).items():
                    value = {"version": value} if isinstance(value, str) else dict(value)
                    if value.get("workspace"):
                        value = {**self.inherited(name), **{k: v for k, v in value.items() if k != "workspace"}}
                    self.deps.append({
                        "key": name, "package": value.get("package", name), "kind": kind, "cfg": spec,
                        "optional": bool(value.get("optional")), "features": value.get("features", []),
                        "default": value.get("default-features", value.get("default_features", True)),
                        "path": value.get("path"),
                    })

    def inherited(self, name):
        for parent in self.path.parent.parents:
            candidate = parent / "Cargo.toml"
            if candidate.exists():
                doc = tomllib.loads(candidate.read_text())
                if "workspace" in doc:
                    value = doc["workspace"].get("dependencies", {}).get(name, {})
                    value = {"version": value} if isinstance(value, str) else dict(value)
                    if "path" in value:
                        value["path"] = str(parent / value["path"])
                    return value
        return {}

    def local_paths(self):
        """Every path this manifest names: dependencies, patches, workspace members."""
        base = self.path.parent
        out = [base / d["path"] for d in self.deps if d["path"]]
        for table in self.doc.get("patch", {}).values():
            out += [base / v["path"] for v in table.values() if isinstance(v, dict) and "path" in v]
        for m in self.doc.get("workspace", {}).get("members", []):
            out += sorted(base.glob(m)) if "*" in m else [base / m]
        return out


class Graph:
    """One lock file resolved for one target: which packages are link inputs."""

    def __init__(self, root, lock, manifest_dir, cfg, registries, registry_pins=None):
        self.root, self.cfg, self.registries = Path(root), cfg, registries
        # The existing checksum table names registry roots/staged copies whose
        # locks omit source/checksum. Their identity does not change when the
        # stage moves inside the checkout. Missing upstream metadata stays
        # unknown instead of falling back to a locally patched manifest.
        self.registry_pins = registry_pins or {}
        self.lock_path = self.root / lock
        self.packages = {}
        for p in tomllib.loads(self.lock_path.read_text()).get("package", []):
            self.packages[(p["name"], p["version"])] = p
        self.by_name = {}
        for key in self.packages:
            self.by_name.setdefault(key[0], []).append(key)
        self.local = {}
        self.unresolved = set()
        seen = set()
        for directory in manifest_dir if isinstance(manifest_dir, list) else [manifest_dir]:
            self.crawl(Path(directory), seen)
        self.cache = {}

    def crawl(self, directory, seen):
        # Through symlinks: ssh/ reaches the tree's crates and the staged
        # sunset through ssh/tree/ links (scripts/stage-ssh.sh), which Cargo
        # does not resolve but which name the same crates.
        directory = Path(os.path.realpath(directory))
        if directory in seen:
            return
        seen.add(directory)
        path = directory / "Cargo.toml"
        if not path.exists():
            return
        try:
            m = Manifest(path)
        except (tomllib.TOMLDecodeError, OSError):
            return
        if m.name:
            self.local.setdefault(m.name, m)
        for p in m.local_paths():
            self.crawl(p, seen)

    def pinned_registry(self, key):
        return f"{key[0]} {key[1]}" in self.registry_pins

    def manifest(self, key):
        if key in self.cache:
            return self.cache[key]
        name, version = key
        m = None
        local = self.local.get(name) if not self.packages[key].get("source") else None
        if local is not None and self.root in local.path.parents and not self.pinned_registry(key):
            m = local
        else:
            # A crate the lock gives no source for and that is not in this
            # repository is a lock's own root or a staged, patched copy of a
            # registry crate: read the registry's manifest, so the result
            # does not depend on what happens to be staged beside the checkout.
            for registry in self.registries:
                path = Path(registry) / f"{name}-{version}" / "Cargo.toml"
                if path.exists():
                    m = Manifest(path)
                    break
            if m is None and not self.pinned_registry(key):
                m = local
        self.cache[key] = m
        return m

    def target(self, key, package):
        """The locked package a dependency of KEY named PACKAGE resolves to."""
        for entry in self.packages[key].get("dependencies", []):
            parts = entry.split()
            if parts[0] == package:
                if len(parts) > 1:
                    return (parts[0], parts[1])
                found = self.by_name.get(package, [])
                return found[0] if len(found) == 1 else None
        return None

    def resolve(self, roots):
        """ROOTS: [(key, features, only)], ONLY limiting a root to some of its
        direct dependencies. Returns {key: 'linked'|'build-only'|'not-built'}."""
        features, active, pending = {}, {}, {}
        only = {key: names for key, _, names in roots if names is not None}
        for key, feats, _ in roots:
            features.setdefault(key, set()).update(feats)
        linked, macros = set(features), set()
        changed = True
        while changed:
            changed = False
            for key in list(linked):
                m = self.manifest(key)
                if m is None:
                    self.unresolved.add(key)
                    for entry in self.packages[key].get("dependencies", []):
                        t = self.target(key, entry.split()[0])
                        if t and t not in linked:
                            linked.add(t)
                            features.setdefault(t, {"default"})
                            changed = True
                    continue
                on = active.setdefault(key, set())
                wants = pending.setdefault(key, {})
                optional = {d["key"] for d in m.deps if d["optional"]}
                stack, done = list(features[key]), set()
                while stack:
                    f = stack.pop()
                    if f in done:
                        continue
                    done.add(f)
                    if f not in m.features and f in optional:
                        on.add(f)
                    for item in m.features.get(f, []):
                        if item.startswith("dep:"):
                            on.add(item[4:])
                        elif "/" in item:
                            dep, feat = item.split("/", 1)
                            if dep.endswith("?"):
                                dep = dep[:-1]
                            else:
                                on.add(dep)
                            wants.setdefault(dep, set()).add(feat)
                        else:
                            stack.append(item)
                for d in m.deps:
                    if d["kind"] != "normal" or (d["cfg"] and not self.cfg.holds(d["cfg"])):
                        continue
                    if d["optional"] and d["key"] not in on:
                        continue
                    if key in only and d["key"] not in only[key]:
                        continue
                    t = self.target(key, d["package"])
                    if t is None:
                        continue
                    tm = self.manifest(t)
                    if tm is not None and tm.proc_macro:
                        macros.add(t)
                        continue
                    need = set(d["features"]) | wants.get(d["key"], set()) | ({"default"} if d["default"] else set())
                    have = features.setdefault(t, set())
                    if t not in linked or not need <= have:
                        linked.add(t)
                        have |= need
                        changed = True
        # Build-time only: build dependencies of linked packages, procedural
        # macros, and whatever those reach. No feature precision is attempted.
        build, stack = set(), list(macros)
        for key in linked:
            m = self.manifest(key)
            for d in (m.deps if m else []):
                if d["kind"] == "build":
                    t = self.target(key, d["package"])
                    if t:
                        stack.append(t)
        while stack:
            key = stack.pop()
            if key in build or key in linked:
                continue
            build.add(key)
            for entry in self.packages[key].get("dependencies", []):
                t = self.target(key, entry.split()[0])
                if t:
                    stack.append(t)
        return {key: "linked" if key in linked else "build-only" if key in build else "not-built"
                for key in self.packages}


def literal(root, spec):
    """'path.py:NAME' -> the list literal assigned to NAME in that file."""
    path, name = spec.split(":")
    for node in ast.parse((Path(root) / path).read_text()).body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise Problem(f"{path}: no list named {name}")


def c_port_rows(root, unit):
    """The rows of a C port table (userland/PORTS.tsv: NAME UPSTREAM SOURCE
    BUILD GATED_SHA256 SHA256 BYTES; '#' starts a comment)."""
    path = Path(root) / unit["c_ports"]
    if not path.exists():
        raise Problem(f"{unit['c_ports']}: missing")
    rows = [line.split("\t") for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]
    if any(len(r) != 7 for r in rows):
        raise Problem(f"{unit['c_ports']}: a row without seven tab-separated fields")
    return rows


def c_port_pins(root, unit):
    """NAME-VERSION -> (VERSION, URL, SHA256, LICENSE) from the pin file
    (userland/PIN: NAME VERSION URL SHA256 LICENSE)."""
    pins = {}
    for line in (Path(root) / unit["pin"]).read_text().splitlines():
        f = line.split("\t")
        if len(f) == 5 and not line.startswith("#"):
            pins[f"{f[0]}-{f[1]}"] = (f[1], f[2], f[3], f[4])
    return pins


def c_port_notice_files(unit, upstream):
    files = unit.get("notice_files", [])
    if isinstance(files, dict):
        if not files.get(upstream):
            raise Problem(f"{unit['name']}: no notices configured for {upstream}")
        files = files[upstream]
    if not isinstance(files, list) or any(not isinstance(path, str) for path in files):
        raise Problem(f"{unit['name']}: C-port notices must be a list of paths")
    return files


def toolchain_source_id(unit, name, use):
    source = unit.get("source_id", "")
    note = unit.get("linked_source_notes", {}).get(name) if use in ("linked", "compiler-input") else None
    return f"{source}; {note}" if note else source


def bin_sources(manifest, name):
    """The source files of one binary: its file and what it pulls in by path."""
    base = manifest.path.parent
    start = None
    for entry in manifest.doc.get("bin", []):
        if entry.get("name") == name and entry.get("path"):
            start = base / entry["path"]
    for candidate in (start, base / "src/bin" / f"{name}.rs", base / "src/bin" / f"{name.replace('-', '_')}.rs",
                      base / "src/bin" / name / "main.rs"):
        if candidate and candidate.exists():
            start = candidate
            break
    else:
        return None
    seen, stack = [], [start]
    while stack:
        path = Path(os.path.normpath(stack.pop()))
        if path in seen or not path.exists():
            continue
        seen.append(path)
        text = path.read_text(errors="replace")
        for ref in re.findall(r'#\[path\s*=\s*"([^"]+)"\]|include!\(\s*"([^"]+)"\s*\)', text):
            stack.append(path.parent / (ref[0] or ref[1]))
        for mod in re.findall(r"^\s*(?:pub\s+)?mod\s+([a-z_0-9]+)\s*;", text, re.M):
            stack += [path.parent / f"{mod}.rs", path.parent / mod / "mod.rs"]
    return seen


def registries(config):
    """Crate source directories: $ABSD_CARGO_REGISTRY's entries first, then
    Cargo's own registry sources. The variable adds to the list; it never
    hides the default one."""
    env = [p for p in os.environ.get("ABSD_CARGO_REGISTRY", "").split(os.pathsep) if p]
    base = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")) / "registry/src"
    default = sorted(str(p) for p in base.glob("*")) if base.exists() else []
    return env + [p for p in default if p not in env]


def expand(path, root=None):
    """A configured path: absolute, under the home directory, or (given
    ROOT) relative to the repository."""
    path = Path(os.path.expandvars(os.path.expanduser(path)))
    return path if path.is_absolute() or root is None else Path(root) / path


def license_files(directory):
    """Licence and notice files of a crate, as paths relative to it. Nested
    ones count: some crates keep the licence of embedded data beside the data."""
    if not directory or not Path(directory).is_dir():
        return []
    directory = Path(directory)
    return sorted(p.relative_to(directory).as_posix() for p in directory.rglob("*")
                  if p.is_file() and LICENSE_NAMES.match(p.name) and p.suffix not in (".rs", ".toml", ".py", ".json")
                  and "target" not in p.relative_to(directory).parts)


def inventory(rec, artifact):
    """Rows for one artifact: every component the configured units can reach."""
    cache = rec.__dict__.setdefault("_inventory", {})
    if artifact["name"] not in cache:
        cache[artifact["name"]] = compute_inventory(rec, artifact)
    return cache[artifact["name"]]


def compute_inventory(rec, artifact):
    root, cfg = rec.root, Cfg(rec.config.get("target", {}))
    regs = registries(rec.config)
    rows, notes = {}, []

    def add(unit, key, graph, use):
        pkg = graph.packages[key]
        m = graph.manifest(key)
        source = pkg.get("source", "")
        in_registry = m is not None and any(Path(r) in m.path.parents for r in regs)
        if source.startswith("registry") or in_registry or graph.pinned_registry(key):
            # A lock's own root package, and a crate patched from a staged
            # copy, carry no source line but are registry crates all the same.
            origin, ident = "registry", pkg.get("checksum", "")
        elif m is not None and unit.get("_sources") is not None and unit["_sources"] in m.path.parents:
            origin, ident = "toolchain", toolchain_source_id(unit, key[0], use)
        elif m is not None and root in m.path.parents:
            rel = m.path.parent.relative_to(root).as_posix()
            origin, ident = ("vendored" if any(d["kind"] == "vendored" for d in rec.declared(rel + "/Cargo.toml"))
                             else "first-party"), rel
        elif use == "not-built":
            # Named by a lock, outside this repository, and not part of the
            # artifact: recorded without reading it, so the inventory is the
            # same whether or not that checkout is present.
            origin, ident, m = "outside-repository", "", None
        elif m is not None:
            origin, ident = "sibling-checkout", ""
        else:
            origin, ident = "unresolved", ""
        declared = m.license if m and m.license else (f"file:{m.license_file}" if m and m.license_file else "")
        derived = unit.get("_compiler_declarations", {}).get(key[0]) if use == "compiler-input" else None
        if not declared and derived and origin == "toolchain":
            declared = derived["license"]
        # policy.decisions keys name one exact version: "crate VERSION".
        decision = rec.policy.get("decisions", {}).get(f"{key[0]} {key[1]}")
        if use not in ("linked", "compiler-input"):
            # Not part of the artifact: its terms are not read, so the
            # inventory does not depend on whether its source is cached here.
            declared, elected, m = "", "n/a", None
        elif origin in ("first-party", "outside-repository"):
            elected = "n/a"
        elif m is None:
            elected = "UNKNOWN"
        elif origin == "sibling-checkout":
            elected = "n/a" if match(key[0], rec.policy.get("owner_projects", [])) else "UNKNOWN"
        elif decision:
            elected = decision
        elif declared and not declared.startswith("file:"):
            taken = elect(declared, rec.policy)
            elected = " AND ".join(taken) if taken else "DECISION_REQUIRED"
        else:
            elected = "UNDECLARED"
        texts = license_files(m.path.parent) if m and origin in ("registry", "vendored", "toolchain") else []
        if m and origin == "toolchain" and not texts:
            texts = ["(toolchain notice set)"]
        row = rows.setdefault((key[0], key[1]), {
            "component": key[0], "version": key[1], "origin": origin, "source": ident, "license": declared,
            "elected": elected, "use": use, "units": set(),
            "texts": ",".join(texts) if texts else ("" if elected == "n/a" else "UNKNOWN" if m is None else "MISSING"),
        })
        rank = ["not-built", "build-only", "compiler-input", "linked"]
        if rank.index(use) > rank.index(row["use"]):
            # Linked by this unit though an earlier one only named it: take this reading.
            row.update(origin=origin, source=ident, license=declared, elected=elected, use=use,
                       texts=",".join(texts) if texts else ("" if elected == "n/a" else "UNKNOWN" if m is None else "MISSING"))
        if use != "not-built":
            row["units"].add(unit["name"])
        # Every lock identity the row was merged from (internal; the licence
        # gate verifies each one, so a merge never hides a differing checksum).
        lock = graph.lock_path.relative_to(root).as_posix() if root in graph.lock_path.parents else str(graph.lock_path)
        row.setdefault("_ids", set()).add((lock, pkg.get("source", ""), pkg.get("checksum", "")))

    # Programs built from a pinned upstream tarball rather than a Cargo lock
    # (the base userland's sbase ports): their names may share the image's
    # port list with the crates, and are not crate rows.
    c_names = set()
    for unit in artifact.get("unit", []):
        if "c_ports" in unit:
            c_names |= {r[0] for r in c_port_rows(root, unit)}

    for unit in artifact.get("unit", []):
        if unit.get("listed") is False:
            # Named so that its lock file is accounted for (`note` says why
            # nothing is listed from it); never resolved, so it needs no
            # sources on this machine.
            continue
        if "c_ports" in unit:
            pins = c_port_pins(root, unit)
            for name, upstream, source_file, *_ in c_port_rows(root, unit):
                if upstream not in pins:
                    notes.append(("UNKNOWN", unit["c_ports"], f"{name}: upstream {upstream} is not a row of {unit['pin']}"))
                    continue
                version, url, digest, declared = pins[upstream]
                notice_files = c_port_notice_files(unit, upstream)
                rows[(f"{upstream.rsplit('-', 1)[0]}-{name}", version)] = {
                    "component": f"{upstream.rsplit('-', 1)[0]}-{name}", "version": version,
                    "origin": "upstream-tarball", "source": f"{url} sha256:{digest} {source_file}",
                    "license": declared,
                    "elected": " AND ".join(elect(declared, rec.policy) or ["DECISION_REQUIRED"]) if declared
                    else "UNDECLARED",
                    "use": "linked", "units": {unit["name"]},
                    "texts": ",".join(Path(f).name for f in notice_files) or "MISSING",
                    "_notice_files": notice_files,  # internal only; inventory columns are unchanged
                }
            continue
        unit = dict(unit)
        manifest_dir = unit.get("manifest_dir", ".")
        manifest_dir = [root / d for d in manifest_dir] if isinstance(manifest_dir, list) else root / manifest_dir
        if "sources" in unit:
            # Match Graph.crawl's real paths, with directory containment rather
            # than a spelling prefix that also admits similarly named siblings.
            unit["_sources"] = Path(os.path.realpath(expand(unit["sources"])))
            manifest_dir = [unit["_sources"] / unit.get("manifest_dir", "."), unit["_sources"]]
        targets = []
        if "ports" in unit:
            table = {}
            for line in (root / unit["table"]).read_text().splitlines():
                f = line.split("\t")
                if len(f) >= 5 and not line.startswith("#"):
                    table[f[3]] = (f[0], f[1])
            for name in literal(root, unit["ports"]):
                if name in c_names:
                    continue
                if name not in table:
                    raise Problem(f"{unit['table']}: no row for port {name}")
                crate, version = table[name]
                targets.append((unit["lock"].format(crate=crate, version=version), crate, None, None, None))
        else:
            bins = list(unit.get("bins", []))
            if "bins_from" in unit:
                bins += literal(root, unit["bins_from"])
            targets.append((unit["lock"], unit["package"], bins or None, manifest_dir, unit.get("features")))
        for lock, package, bins, directory, feats in targets:
            if not (root / lock).exists():
                notes.append(("UNKNOWN", lock, "lock file missing"))
                continue
            graph = Graph(root, lock, directory or root, cfg, regs, rec.config.get("licence_policy", {}).get("crate_checksums", {}))
            keys = graph.by_name.get(package, [])
            if len(keys) != 1:
                notes.append(("UNKNOWN", lock, f"root package {package} not unique in lock"))
                continue
            m = graph.manifest(keys[0])
            only = None
            if bins and m is not None and not artifact.get("_wide"):
                # The notice inventory narrows a binary to the dependencies
                # its sources name. The licence gate resolves the same unit
                # without that narrowing (artifact["_wide"]): every normal
                # dependency of the package can be linked into each binary.
                text = ""
                for b in bins:
                    files = bin_sources(m, b)
                    if files is None:
                        notes.append(("UNKNOWN", lock, f"sources of binary {b} not found"))
                        continue
                    text += "".join(f.read_text(errors="replace") for f in files)
                only = {d["key"] for d in m.deps
                        if d["kind"] == "normal" and re.search(rf"\b{re.escape(d['key'].replace('-', '_'))}\b", text)}
            feats = set(feats) if feats is not None else {"default"}
            roots = [(keys[0], feats, only)]
            for extra in unit.get("roots", []):
                found = graph.by_name.get(extra, [])
                roots += [(found[0], set(), None)] if len(found) == 1 else []
            uses = graph.resolve(roots)
            for key, use in uses.items():
                add(unit, key, graph, "compiler-input" if use == "linked" and unit.get("_compiler_inputs") else use)
            missing = sorted(graph.unresolved)
            if missing:
                notes.append(("UNKNOWN", lock, f"{len(missing)} package manifest(s) not available on this machine "
                              f"(first: {missing[0][0]} {missing[0][1]}); their dependencies are assumed linked"))
    for extra in artifact.get("component", []):
        rows[(extra["name"], extra.get("version", ""))] = {
            "component": extra["name"], "version": extra.get("version", ""), "origin": extra.get("origin", "declared"),
            "source": extra.get("source", ""), "license": extra.get("license", ""),
            "elected": " AND ".join(elect(extra.get("license", ""), rec.policy) or [extra.get("license", "")]),
            "use": extra.get("use", "included"), "units": {"image"},
            # "texts" states that no text is required (public domain) and why.
            "texts": extra.get("texts") or ",".join(Path(p).name for p in extra.get("notice_files", [])) or "MISSING",
        }
    return [rows[k] for k in sorted(rows)], notes


COLUMNS = ["component", "version", "origin", "use", "license", "elected", "texts", "units", "source"]


def render(rows):
    lines = ["\t".join(COLUMNS)]
    for row in rows:
        row = {**row, "units": ",".join(sorted(row["units"])) if not isinstance(row["units"], str) else row["units"]}
        lines.append("\t".join(str(row[c]) for c in COLUMNS))
    return "\n".join(lines) + "\n"


def parse_tsv(text):
    lines = text.splitlines()
    return [dict(zip(lines[0].split("\t"), line.split("\t"))) for line in lines[1:] if line]


def shipped(row):
    """Third-party notice coverage, including explicitly identified compiler inputs.

    The compiler-input label does not assert final ELF code membership.
    """
    return row["use"] in ("linked", "included", "compiler-input") and row["elected"] != "n/a" and row["origin"] != "first-party"


# ---------------------------------------------------------------- findings

class Findings:
    def __init__(self):
        self.items, self.info = [], []

    def add(self, status, path, reason, fix=""):
        self.items.append((status, path, reason, fix))

    def note(self, text):
        self.info.append(text)

    def verdict(self):
        return max((i[0] for i in self.items), key=ORDER.index, default="UNCHANGED")

    def print(self, title):
        print(f"PROVENANCE {title}: {self.verdict()}")
        for status in reversed(ORDER):
            for item in [i for i in self.items if i[0] == status]:
                print(f"  {status}  {item[1]}: {item[2]}" + (f"\n      fix: {item[3]}" if item[3] else ""))
        for line in self.info:
            print(f"  note  {line}")


def is_binary(data):
    if b"\0" in data[:8192]:
        return True
    try:
        data[:8192].decode("utf-8")
        return False
    except UnicodeDecodeError as error:
        return error.start < len(data[:8192]) - 4


def scan_file(rec, path, data, lines, out, added=True):
    """One new or changed file: credentials and binaries of unstated origin.
    (Licence headers and attribution wording are spdx-check's to judge.)"""
    declared = rec.declared(path)
    kinds = {d.get("kind") for d in declared}
    text = None if is_binary(data) else data.decode("utf-8", "replace")
    if (SECRETS.search(text or "") or (DER_KEY.match(data) and KEY_NAMES.search(path))
            or (text is None and KEY_NAMES.search(path))):
        if "test-key" not in kinds:
            out.add("BLOCKED", path, "credential-shaped file with no declaration",
                    "remove it, or give its provenance.toml rule kind = \"test-key\" and a note saying "
                    "why it is not a live credential")
        return
    if text is None:
        if added and not declared and not match(path, rec.scan.get("binary_ok", [])):
            out.add("NEW_REVIEW_REQUIRED", path, "binary file with no declared origin",
                    "state its origin in a provenance.toml rule (imported, adapted or generated), or add its "
                    "directory to scan.binary_ok in provenance/config.toml if the project generates such files")
        return


def dev_paths(rec, path, lines, out):
    """Absolute development-machine paths. In build manifests they break the
    build elsewhere (definite); elsewhere they are reported, not failed."""
    hits = [l.strip()[:100] for l in lines if DEV_PATHS.search(l)]
    if not hits:
        return 0
    if Path(path).name in ("Cargo.toml", "config.toml") and not match(path, rec.scan.get("path_ok", [])):
        out.add("COMPLIANCE_ACTION_REQUIRED", path, f"absolute development-machine path in a build manifest: "
                f"\"{hits[0]}\"", "use a relative path or a staged copy, or record the dependency as a known "
                "portability obligation and add the file to scan.path_ok")
    return len(hits)


def private_patterns():
    path = expand(os.environ.get("ABSD_PRIVATE_PATTERNS", "~/.config/absd/private-patterns"))
    if not path.exists():
        return None
    out = []
    for line in path.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            out.append(re.compile(line.split("\t")[0]))
    return out


def tracked(rec, ref=None):
    if ref:
        return git("ls-tree", "-r", "--name-only", "-z", ref, root=rec.root).split("\0")[:-1]
    return git("ls-files", "-z", root=rec.root).split("\0")[:-1]


def declaration_checks(rec, files, out):
    """What this tool adds to spdx-check's validation of provenance.toml:
    required upstream notice files are present, and material under terms
    outside the accepted list carries a recorded decision."""
    for d in rec.declarations:
        ident = d["id"]
        for name in d["license_files"]:
            if name not in files:
                out.add("BLOCKED", name, f"notice file required by the provenance.toml rule for {ident} is missing",
                        "restore the upstream licence or notice file")
        if d["kind"] in THIRD_PARTY:
            terms = d["license"]
            public = terms == "public domain" or terms.startswith("LicenseRef-") and "public-domain" in terms
            if terms and not public and elect(terms, rec.policy) is None and not d["decision"]:
                out.add("NEW_REVIEW_REQUIRED", "provenance.toml",
                        f"{ident}: upstream terms \"{terms}\" have no alternative on the accepted list; "
                        "incorporating the material is an explicit decision",
                        "add decision = \"who decided, when, and why its terms fit the intended distribution\" "
                        "to the rule")


def spdx_run(rec, base, release=False):
    """scripts/spdx-check.py's own report (schema absd-spdx-check/1)."""
    cache = rec.__dict__.setdefault("_spdx", {})
    key = (base, release)
    if key not in cache:
        cmd = [sys.executable, str(rec.root / "scripts/spdx-check.py"), "--root", str(rec.root), "--json",
               "--mode", "release" if release else "dev"] + (["--base", base] if base else [])
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 2:
            raise Problem(f"spdx-check: {r.stderr.strip()}")
        try:
            cache[key] = json.loads(r.stdout)
        except json.JSONDecodeError:
            raise Problem(f"spdx-check: unreadable report ({r.stderr.strip()[:200]})") from None
        if cache[key].get("schema") != "absd-spdx-check/1":
            raise Problem(f"spdx-check: unexpected report schema {cache[key].get('schema')}")
    return cache[key]


def named_locks(rec):
    """Lock files some artifact unit in provenance/config.toml reads."""
    out = []
    for artifact in rec.config.get("artifact", []):
        for unit in artifact.get("unit", []):
            if "lock" in unit:
                out.append(re.sub(r"\\\{[a-z]+\\\}", "[^/]+", re.escape(unit["lock"])) + "$")
    return [re.compile(p) for p in out]


def spdx_checks(rec, out, base):
    """Fold spdx-check's findings into this run. Its categories and kinds
    keep their meaning; only the mapping to a verdict is decided here, and a
    kind this tool does not know is treated as needing review."""
    report = spdx_run(rec, base)
    old_rules = []
    if base:
        text = git("show", f"{base}:provenance.toml", root=rec.root, check=False)
        try:
            old_rules = tomllib.loads(text).get("files", []) if text else []
        except tomllib.TOMLDecodeError:
            old_rules = []
    locks = named_locks(rec)
    classify = "classify the file in provenance.toml or correct its licence metadata (docs/SOURCE-LICENSING.md)"
    for f in report["findings"]:
        category, path, detail = f["category"], f["path"], f["detail"]
        if category in ("missing-metadata", "conflict"):
            out.add("COMPLIANCE_ACTION_REQUIRED", path, f"spdx-check {category}: {detail}", classify)
        elif category == "unknown-licensing" and f.get("class") == "unresolved":
            out.add("NEW_REVIEW_REQUIRED", path, f"spdx-check: {detail}",
                    "establish where the file came from and under what terms, then classify it")
        elif category == "new-obligation":
            kind = f.get("kind")
            if kind == "lock-changed":
                # The dependency inventory says exactly what changed, for the locks it reads.
                if not any(rx.match(path) for rx in locks):
                    out.add("NEW_REVIEW_REQUIRED", path, "lock file that no artifact in provenance/config.toml "
                            "reads: its dependencies are not inventoried",
                            "add a unit for it to provenance/config.toml, or say there why it ships nothing")
            elif kind == "licence-text-new":
                out.note(f"spdx-check: {path}: {detail}")
            elif kind == "third-party-changed":
                rule = rec.rules.match(path)
                if rule is not None and rule not in old_rules:
                    out.note(f"spdx-check: {path}: {detail}; its provenance.toml rule is new or updated in this change")
                else:
                    out.add("NEW_REVIEW_REQUIRED", path, f"spdx-check: {detail}, and its provenance.toml rule "
                            "was not touched", "say in the rule what was added or changed and why (origin, a "
                            "note), keeping upstream notices; if the new content has other terms, give it its own rule")
            else:
                out.add("NEW_REVIEW_REQUIRED", path, f"spdx-check: {detail}",
                        "if the file now holds someone else's work, classify it in provenance.toml (adapted or "
                        "imported, with origin and upstream licence); if the line only mentions another project, reword it")
    for note in report.get("notes", []):
        out.note(f"spdx-check: {note}")
    exceptions = report["counts"].get("accepted-exception", 0)
    if exceptions:
        out.note(f"spdx-check: {exceptions} finding(s) accepted by recorded exception in provenance.toml")
    return report


def detect(rec, obligation, files):
    """(holds, why, grew): whether the condition an obligation tracks holds
    now, and whether it has grown past the accepted count. holds is None when
    the obligation has no mechanical detector or it cannot run here."""
    d = obligation.get("detect")
    if not d:
        return None, "", False
    kind, limit = d["kind"], d.get("max")
    if kind in ("exists", "missing"):
        found = [f for f in files if match(f, [d["path"]])]
        return (bool(found) if kind == "exists" else not found), f"{len(found)} file(s) match {d['path']}", False
    if kind in ("grep", "grep-absent", "private-names"):
        if kind == "private-names":
            patterns = private_patterns()
            if patterns is None:
                return None, "no private-name pattern file on this machine; not checked", False
        else:
            patterns = [re.compile(d["pattern"])]
        count = hit = 0
        for f in files:
            if match(f, d.get("files", ["*"])) and not match(f, d.get("exclude", [])):
                try:
                    data = (rec.root / f).read_bytes()
                except OSError:
                    continue
                if is_binary(data):
                    continue
                n = sum(1 for line in data.decode("utf-8", "replace").splitlines() if any(rx.search(line) for rx in patterns))
                count += n
                hit += bool(n)
        if kind == "grep-absent":
            return count == 0, f"{count} matching line(s)", False
        why = f"{count} line(s) in {hit} file(s)" + (f", accepted at {limit}" if limit is not None else "")
        return count > 0, why, limit is not None and count > limit
    if kind == "spdx":
        report = spdx_run(rec, None, release=True)
        count = report["counts"].get(d["category"], 0)
        why = f"spdx-check release mode: {count} file(s) {d['category']}"
        return count > 0, why, False
    if kind == "inventory":
        total = 0
        for artifact in rec.config.get("artifact", []):
            rows, _ = inventory(rec, artifact)
            total += sum(1 for r in rows if shipped(r) and r[d["column"]] in d["values"])
        why = f"{total} shipped component(s)" + (f", accepted at {limit}" if limit is not None else "")
        return total > 0, why, limit is not None and total > limit
    raise Problem(f"obligation {obligation.get('id')}: unknown detector {kind}")


def obligation_checks(rec, files, out, quick=False):
    """Each obligation with its detector's result. Statuses: open (known,
    unresolved), resolved (must stay clear), latent (applies once its
    condition appears, for example when a branch is merged)."""
    rows = []
    for o in rec.obligations:
        slow = (o.get("detect") or {}).get("kind") in ("inventory", "private-names", "spdx") or (
            (o.get("detect") or {}).get("files") in (None, ["*"]) and (o.get("detect") or {}).get("kind") == "grep")
        fires, why, grew = (None, "not run in the fast check", False) if quick and slow else detect(rec, o, files)
        status = o.get("status", "open")
        where = "provenance/obligations.toml"
        if status == "resolved" and not o.get("resolved"):
            out.add("COMPLIANCE_ACTION_REQUIRED", where, f"{o['id']} is marked resolved with no statement of how",
                    "add resolved = \"date, commit, and what was done or who decided\"")
        if status == "resolved" and fires:
            out.add("COMPLIANCE_ACTION_REQUIRED", where, f"{o['id']} is recorded resolved but its condition "
                    f"holds again ({why})", "fix the regression or reopen the obligation")
        elif status == "latent" and fires:
            out.add("NEW_REVIEW_REQUIRED", where, f"{o['id']} now applies ({why}): {o['title']}",
                    "do what the obligation says, then set its status to open or resolved")
        elif status == "open" and grew:
            out.add("COMPLIANCE_ACTION_REQUIRED", where, f"{o['id']} has grown past its accepted count ({why}): "
                    f"{o['title']}", "remove the new occurrences; raise the count only for a reason you record")
        elif status == "open" and fires is False:
            out.note(f"{o['id']} appears resolved ({why}); set status = \"resolved\" once confirmed")
        rows.append((o, fires, why))
    return rows


def build_evidence(rec, artifact, rows, out):
    """Where a build exists, compare the inventory with the compiler's own
    dep-info: the registry sources each compiled crate was read from."""
    name = artifact["name"]
    linked = {f"{r['component']}-{r['version']}" for r in rows if r["use"] in ("linked", "compiler-input") and r["origin"] == "registry"}
    for unit in artifact.get("unit", []):
        if "evidence" not in unit:
            continue
        # {root} identifies this checkout's sibling stage. A single path-level
        # wildcard reads the per-port target directories the producer creates;
        # legacy relative evidence paths retain their existing interpretation.
        if "{root}" in unit["evidence"]:
            pattern = rec.root / unit["evidence"].replace("{root}", glob.escape(str(rec.root)))
            files = sorted(Path(path) for path in glob.glob(str(pattern / "*.d")))
        else:
            directory = (rec.root / unit["evidence"]).resolve()
            files = sorted(directory.glob("*.d")) if directory.is_dir() else []
        if not files:
            out.note(f"{name}/{unit['name']}: no build output at {unit['evidence']}; inventory not compared with a build")
            continue
        compiled, text = set(), ""
        for f in files:
            text += f.read_text(errors="replace")
        compiled |= set(re.findall(r"/registry/src/[^/]+/([^/ ]+)/", text))
        mine = {f"{r['component']}-{r['version']}" for r in rows if r["use"] in ("linked", "compiler-input") and r["origin"] == "registry"
                and unit["name"] in r["units"]}
        missed = sorted(compiled - linked) if unit.get("evidence_exact") else []
        for ident in missed:
            out.add("COMPLIANCE_ACTION_REQUIRED", f"{name}/{unit['name']}: {ident}",
                    "compiled for the target but absent from the inventory: the inventory understates what ships",
                    "correct the unit's roots or features in provenance/config.toml")
        # Crates built from a staged copy (a lock's root, a patched crate) are
        # compiled from outside the registry path and cannot be matched here.
        mine -= {f"{r['component']}-{r['version']}" for r in rows if r["source"] in ("", "staged copy")}
        extra = sorted(mine - compiled)
        out.note(f"{name}/{unit['name']}: build output lists {len(compiled)} registry crate(s); "
                 f"{len(missed)} not in the inventory, {len(extra)} in the inventory but not compiled"
                 + (f" ({', '.join(extra[:6])}{'...' if len(extra) > 6 else ''})" if extra else ""))


def inventory_checks(rec, out, base=None, evidence=False):
    """Committed inventory against a fresh one; and against BASE's, as a delta."""
    for artifact in rec.config.get("artifact", []):
        name = artifact["name"]
        rel = f"provenance/inventory/{name}.tsv"
        try:
            rows, notes = inventory(rec, artifact)
        except Problem as error:
            out.add("UNKNOWN", rel, f"inventory cannot be computed: {error}")
            continue
        for status, where, why in notes:
            out.add(status, where, why, "stage or fetch the missing input, then rerun")
        if evidence:
            build_evidence(rec, artifact, rows, out)
        fresh = render(rows)
        committed = (rec.root / rel).read_text() if (rec.root / rel).exists() else ""
        unknown = [r for r in rows if "UNKNOWN" in (r["elected"], r["texts"])]
        if unknown:
            out.add("UNKNOWN", rel, f"{len(unknown)} component(s) could not be read on this machine (first: "
                    f"{unknown[0]['component']} {unknown[0]['version']}): the crate registry cache or the "
                    "toolchain sources are missing, so the inventory was not verified",
                    "fetch the dependencies (cargo fetch --locked) and install the toolchain's rust-src, then rerun")
            continue
        if fresh != committed:
            out.add("COMPLIANCE_ACTION_REQUIRED", rel, "the committed inventory does not match the dependency "
                    "graph and image composition", "run scripts/provenance.py update and commit the result")
        old = {}
        if base:
            text = git("show", f"{base}:{rel}", root=rec.root, check=False)
            if not text and (rec.root / f"provenance/baseline/{name}.tsv").exists() and base == rec.config["baseline"]["commit"]:
                text = (rec.root / f"provenance/baseline/{name}.tsv").read_text()
            old = {(r["component"], r["version"]): r for r in parse_tsv(text) if shipped(r)} if text else None
        new = {(r["component"], r["version"]): r for r in parse_tsv(fresh) if shipped(r)}
        for r in new.values():
            where = f"{name}: {r['component']} {r['version']}"
            if r["elected"] == "UNDECLARED":
                out.add("BLOCKED", where, "shipped component declares no licence",
                        "find the upstream licence and record it under policy.decisions, or drop the component")
            elif r["elected"] == "DECISION_REQUIRED":
                out.add("NEW_REVIEW_REQUIRED", where, f"licence \"{r['license']}\" has no alternative on the "
                        "accepted list; incorporating it is an explicit decision",
                        "record the decision under policy.decisions in provenance/config.toml, or drop the component")
        if old is None:
            out.note(f"{name}: no inventory at {base}; component delta not computed")
        elif base:
            added, removed = set(new) - set(old), set(old) - set(new)
            # One version of a name gone and one arrived: a version change.
            moved = {}
            for c in sorted(added):
                gone = [o for o in removed if o[0] == c[0]]
                if len(gone) == 1 and sum(1 for a in added if a[0] == c[0]) == 1:
                    moved[c] = gone[0]
            for c in sorted(added):
                r = new[c]
                if c in moved:
                    out.note(f"{name}: {c[0]} {moved[c][1]} -> {c[1]}")
                    # A licence_policy exception bound to exactly this
                    # component (name, version, artifact, source identity) and
                    # these terms is the confirmation the change needs.
                    declared = next((x for x in artifact.get("component", []) if x["name"] == c[0]
                                     and x.get("version", "") == c[1]), None)
                    accepted = [e["decision"] for e in exception_for(
                        rec.config.get("licence_policy", {}).get("exception", []), declared or {}, name)
                        if e.get("licence") == r["license"] and e.get("decision")] if declared else []
                    if r["license"] != old[moved[c]]["license"] and accepted:
                        out.note(f"{name}: {c[0]} licence declaration \"{old[moved[c]]['license']}\" -> "
                                 f"\"{r['license']}\", accepted by {accepted[0]}")
                    elif r["license"] != old[moved[c]]["license"]:
                        out.add("NEW_REVIEW_REQUIRED", f"{name}: {c[0]} {c[1]}", f"licence declaration changed: "
                                f"\"{old[moved[c]]['license']}\" -> \"{r['license']}\"",
                                "confirm the new terms are acceptable")
                else:
                    out.note(f"{name}: new shipped component {c[0]} {c[1]} ({r['license']}, taken as "
                             f"{r['elected']}); notices must be regenerated before distribution")
                if r["texts"] == "MISSING":
                    out.add("COMPLIANCE_ACTION_REQUIRED", f"{name}: {c[0]} {c[1]}",
                            "new shipped component carries no licence text in its source",
                            "obtain the text from upstream and record it as an obligation")
            for c in sorted(removed - set(moved.values())):
                out.note(f"{name}: shipped component removed: {c[0]} {c[1]}")


def changes(rec, base):
    """(status, path) for everything that differs from BASE, tracked or not."""
    out = []
    for line in git("diff", "--name-status", "--no-renames", "-z", base, root=rec.root).split("\0"):
        if line in ("A", "M", "D", "T"):
            status = line
        elif line:
            out.append((status, line))
    for path in git("ls-files", "-o", "--exclude-standard", "-z", root=rec.root).split("\0"):
        if path:
            out.append(("A", path))
    return out


def added_lines(rec, base, path):
    text = git("diff", "-U0", "--no-renames", base, "--", path, root=rec.root, check=False)
    return [l[1:] for l in text.splitlines() if l.startswith("+") and not l.startswith("+++")]


def default_base(rec):
    for ref in (rec.config.get("main", "main"), rec.config["baseline"]["commit"]):
        r = subprocess.run(["git", "-C", str(rec.root), "merge-base", "HEAD", ref], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    raise Problem("no base: neither the main branch nor the baseline commit is an ancestor")


def source_release(rec):
    """In a source release (docs/PROVENANCE.md) this directory is one component
    of an assembled tree: its history, and so any base to compare with, stayed
    behind. The release's manifest is beside it and names the tree it shipped."""
    manifest = rec.root.parent / "SOURCE-MANIFEST.toml"
    # A directory with its own .git is a development checkout whatever lies
    # beside it: only a component inside a release is judged this way.
    if (rec.root / ".git").exists() or not manifest.exists():
        return None
    data = tomllib.loads(manifest.read_text())
    entry = next((c for c in data.get("component", []) if c.get("path") == rec.root.name), None)
    if entry is None:
        return None
    ident = data.get("release", {}).get("id", "unnamed")
    tree = subprocess.run(["git", "-C", str(rec.root), "rev-parse", "HEAD:./"], capture_output=True, text=True)
    dirty = subprocess.run(["git", "-C", str(rec.root), "status", "--porcelain", "--", "."],
                           capture_output=True, text=True)
    if tree.returncode or dirty.returncode:
        return False, f"SOURCE RELEASE {ident}: {rec.root.name}/ not compared with the manifest (not a Git checkout)"
    if tree.stdout.strip() == entry.get("tree") and not dirty.stdout.strip():
        return True, f"SOURCE RELEASE {ident}: {rec.root.name}/ matches the manifest (tree {entry['tree']})"
    return False, (f"SOURCE RELEASE {ident}: {rec.root.name}/ differs from the manifest; "
                   "changes made here are not covered by the release's review")


def spdx_library_review(rec, out, base):
    """The SPDX library is a policy input: a change to its recorded version,
    wheels or SPDX licence list against BASE needs review until the policy's
    `decision` names the new license_expression wheel's sha256."""
    now = rec.config.get("licence_policy", {}).get("spdx_library", {})
    text = git("show", f"{base}:provenance/config.toml", root=rec.root, check=False) if base else ""
    try:
        old = tomllib.loads(text).get("licence_policy", {}).get("spdx_library", {}) if text else {}
    except tomllib.TOMLDecodeError:
        old = {}
    fields = ("license_expression_version", "boolean_py_version", "spdx_license_list_version", "license_index_sha256", "wheels")
    if all(now.get(k) == old.get(k) for k in fields):
        return
    wheel = next((v for k, v in now.get("wheels", {}).items() if k.startswith("license_expression-")), "")
    if wheel and wheel in now.get("decision", "") and now.get("decision") != old.get("decision"):
        out.note(f"SPDX library policy input changed against {base[:12]} (list {old.get('spdx_license_list_version')} -> "
                 f"{now.get('spdx_license_list_version')}), recorded by: {now['decision']}")
    else:
        out.add("NEW_REVIEW_REQUIRED", "provenance/config.toml", "the SPDX library policy input changed (version, "
                "wheels or SPDX licence list) without a new owner decision naming the license_expression wheel sha256",
                "record the owner's decision in [licence_policy.spdx_library] decision")


def check(rec, base=None, peer=None):
    out = Findings()
    base = base or default_base(rec)
    delta = changes(rec, base)
    first = third = 0
    records = sorted(p for s, p in delta if RECORDS.match(p))
    if records:
        out.note("licensing and provenance records changed in this change; read their diff, since classifications, "
                 "exemptions and accepted counts decide what this check reports: " + ", ".join(records))
    for status, path in delta:
        declared = rec.declared(path)
        if RECORDS.match(path):
            continue
        if status != "D" and (rec.root / path).is_dir():
            out.add("NEW_REVIEW_REQUIRED", path, "git submodule or nested repository: its content is not tracked "
                    "here and is not examined", "vendor the files with a provenance.toml rule, or remove it")
            continue
        if status == "D":
            was = rec.rules.match(path)
            if any(path in d["license_files"] for d in rec.declarations) or (
                    was and was.get("class") in ("imported", "adapted") and LICENSE_NAMES.match(Path(path).name)):
                out.add("BLOCKED", path, "licence or notice file of declared third-party material was removed",
                        "restore it")
            continue
        try:
            data = (rec.root / path).read_bytes()
        except OSError:
            continue
        lines = [] if is_binary(data) else (data.decode("utf-8", "replace").splitlines() if status == "A"
                                            else added_lines(rec, base, path))
        scan_file(rec, path, data, lines, out, added=status == "A")
        dev_paths(rec, path, lines, out)
        if any(d["kind"] in THIRD_PARTY for d in declared):
            third += 1
        else:
            first += 1
    spdx_checks(rec, out, base)
    shared_tool_checks(rec, out, peer)
    spdx_library_review(rec, out, base)
    declaration_checks(rec, tracked(rec) + [p for s, p in delta if s == "A"], out)
    obligation_checks(rec, tracked(rec), out, quick=True)
    inputs = {u.get("lock", "") for a in rec.config.get("artifact", []) for u in a.get("unit", [])}
    touched = [p for _, p in delta if p.endswith(("Cargo.lock", "Cargo.toml")) or p in inputs
               or p.startswith("pins/") or p in ("provenance/config.toml", "provenance.toml")
               or any(p == str(u.get(k, "")).split(":")[0] for a in rec.config.get("artifact", [])
                      for u in a.get("unit", []) for k in ("bins_from", "ports", "table"))]
    if not registries(rec.config) and not touched and all(
            (rec.root / f"provenance/inventory/{a['name']}.tsv").exists() for a in rec.config.get("artifact", [])):
        # A fresh checkout with no crate cache: nothing that feeds the
        # inventory changed, so the committed inventory still describes it.
        out.note("dependency inventory not recomputed: no crate registry cache on this machine and no "
                 "dependency or image input changed since the base")
    else:
        inventory_checks(rec, out, base)
    patterns = private_patterns()
    if patterns:
        for status, path in delta:
            if status != "D" and (rec.root / path).is_file() and not is_binary((rec.root / path).read_bytes()):
                lines = added_lines(rec, base, path) if status == "M" else (rec.root / path).read_text(errors="replace").splitlines()
                n = sum(1 for l in lines for rx in patterns if rx.search(l))
                if n:
                    out.note(f"{path}: {n} added line(s) match a private-name pattern (a disclosure matter "
                             "for source publication, tracked as an obligation)")
    out.note(f"compared with {base[:12]}: {first} first-party file(s) changed, {third} declared third-party "
             "file(s) changed. First-party changes are not reviewed for originality by this check.")
    return out


def full(rec, out_dir, peer=None):
    out = Findings()
    out.full = True
    files = tracked(rec)
    for path in files:
        if RECORDS.match(path):
            continue
        if (rec.root / path).is_dir():
            out.add("NEW_REVIEW_REQUIRED", path, "git submodule or nested repository: its content is not tracked "
                    "here and is not examined", "vendor the files with a provenance.toml rule, or remove it")
            continue
        try:
            data = (rec.root / path).read_bytes()
        except OSError:
            continue
        lines = [] if is_binary(data) else data.decode("utf-8", "replace").splitlines()
        scan_file(rec, path, data, lines, out, added=False)
    for path in files:
        if Path(path).name in ("Cargo.toml", "config.toml") and not path.startswith("provenance/"):
            dev_paths(rec, path, (rec.root / path).read_text(errors="replace").splitlines(), out)
    spdx_checks(rec, out, rec.config["baseline"]["commit"])
    shared_tool_checks(rec, out, peer)
    spdx_library_review(rec, out, rec.config["baseline"]["commit"])
    declaration_checks(rec, files, out)
    inventory_checks(rec, out, rec.config["baseline"]["commit"], evidence=True)
    rows = obligation_checks(rec, files, out)
    if private_patterns() is None:
        out.note("private-name scan skipped: no pattern file (~/.config/absd/private-patterns or "
                 "$ABSD_PRIVATE_PATTERNS). Host names and similar are NOT checked on this machine.")
    for artifact in rec.config.get("artifact", []):
        notices(rec, artifact["name"], Path(out_dir) / "notices" / artifact["name"], quiet=True)
    report, verdicts = readiness(rec, rows, out)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / "READINESS.md").write_text(report)
    return out, (report, verdicts)


# Exact upstream declaration used only for the observed Rust1.95 proc_macro
# manifest that has no Cargo license field. This is not a missing-license default.
DOCUMENT_PROC_MACRO_DECLARATION = {
    "manifest_sha256": "7aba4b48b58473181856588046a32222b420c17e257cfcb7813b218f2958f9ee",
    "std_sha256": "3961aa8abb13677871f3febc67b5d651da0cd195fd1711abccf288f0164f940c",
    "rustc_sha256": "bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6",
    "copyright_sha256": "90567e2718bf7fd65a71a3a43c5596488e80e5f51ed02bfea6fec54458b5f3d1",
}


def document_toolchain_notices(library, receipt):
    """Bind notice paths to the actual App compiler, never ambient HOME."""
    compiler = receipt.get("explicit_environment", {}).get("ABSD_REAL_RUSTC")
    if not isinstance(compiler, str) or not compiler:
        raise Problem("document native receipt requires actual compiler")
    rustc = Path(compiler)
    if (not rustc.is_absolute() or rustc.parent.name != "bin" or rustc.name != "rustc"
            or rustc.is_symlink() or not rustc.is_file()):
        raise Problem("document actual compiler path differs")
    toolchain = rustc.parent.parent
    docs = toolchain / "share/doc/rust"
    if any(p.is_symlink() for p in [rustc, *rustc.parents, docs, *docs.parents]):
        raise Problem("document actual toolchain path component is aliased")
    copyright = docs / "COPYRIGHT-library.html"
    licenses = docs / "licenses"
    if (not copyright.is_file() or copyright.is_symlink() or not licenses.is_dir() or licenses.is_symlink()
            or any(p.is_symlink() for p in licenses.rglob("*"))):
        raise Problem("document actual toolchain notice inputs missing or aliased")
    texts = [copyright] + sorted(p for p in licenses.rglob("*") if p.is_file())
    if len(texts) < 2 or any(not (licenses / name).is_file() for name in ("MIT.txt", "Apache-2.0.txt")):
        raise Problem("document actual toolchain license texts missing")
    proof = {"compiler": str(rustc), "compiler_sha256": hashlib.sha256(rustc.read_bytes()).hexdigest(),
             "notice_files": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in texts}}
    manifest = Path(library) / "proc_macro/Cargo.toml"
    if not manifest.is_file() or tomllib.loads(manifest.read_text()).get("package", {}).get("license"):
        return [str(copyright), str(licenses)], proof
    pins = DOCUMENT_PROC_MACRO_DECLARATION
    text = copyright.read_text()
    scopes = re.findall(r"<b>File/Directory:</b> <code>(.*?)</code>", text)
    scope = "library/proc_macro"
    if (toolchain.name != "1.95.0-x86_64-unknown-linux-gnu" or manifest.is_symlink()
            or hashlib.sha256(manifest.read_bytes()).hexdigest() != pins["manifest_sha256"]
            or receipt.get("staged_std_source_sha256") != pins["std_sha256"]
            or proof["compiler_sha256"] != pins["rustc_sha256"]
            or hashlib.sha256(copyright.read_bytes()).hexdigest() != pins["copyright_sha256"]
            or not scopes or scopes[0] != "."
            or any(scope == p or scope.startswith(p.rstrip("/") + "/") for p in scopes[1:])
            or "<p><b>License:</b> Apache-2.0 OR MIT</p>" not in text):
        raise Problem("document proc_macro upstream declaration identity or scope differs")
    proof["proc_macro"] = {"license": "Apache-2.0 OR MIT", "basis": "derived upstream root-scope declaration; not Cargo-declared",
                           "declaration_source": str(copyright), "sha256": pins["copyright_sha256"],
                           "scope": ". covers library/proc_macro with no applicable listed exception",
                           "manifest_sha256": pins["manifest_sha256"], "staged_std_source_sha256": pins["std_sha256"]}
    return [str(copyright), str(licenses)], proof


def document_artifact(rec, release_dir, build_receipt, deps_dir):
    """Select the opt-in artifact only after binding actual build inputs."""
    cfg = rec.config["document_application"]
    release_dir, build_receipt, deps_dir = map(Path, (release_dir, build_receipt, deps_dir))
    try:
        manifest_path = release_dir / "release-manifest.toml"
        manifest = tomllib.loads(manifest_path.read_text())
        receipt = json.loads(build_receipt.read_text())
        binary = (release_dir / cfg["binary"]).read_bytes()
        digest = hashlib.sha256(binary).hexdigest()
        document = manifest["build"]["https_document"]
        if (document["enabled"] is not True
                or document["build_receipt_sha256"] != hashlib.sha256(build_receipt.read_bytes()).hexdigest()
                or any(document[k] != receipt[k] for k in
                       ("cargo_lock_sha256", "target_sha256", "staged_std_source_sha256"))
                or document["ring_stage_sha256"] != hashlib.sha256(json.dumps(
                    receipt["ring_stage"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                or manifest["artifacts"]["files"][cfg["binary"]]["sha256"] != digest
                or not binary.startswith(b"\x7fELF")
                or receipt["outputs"]["https_document"]["sha256"] != digest
                or receipt["outputs"]["https_document"]["bytes"] != len(binary)
                or receipt["application"]["schema"] != "absd-https-document-build/1"
                or receipt["application"]["fixture_selectors"] is not False
                or receipt["source_revision"] != manifest["source"]["platform_commit"]
                or receipt["source_revision"] != git("rev-parse", "HEAD", root=rec.root).strip()
                or receipt["source_tree"] != git("rev-parse", "HEAD^{tree}", root=rec.root).strip()
                or bool(git("status", "--porcelain", root=rec.root).strip())
                or receipt["tracked_dirty"] is not False or receipt["untracked_source"] is not False
                or receipt["cargo_lock_sha256"] != hashlib.sha256((rec.root / "tls/Cargo.lock").read_bytes()).hexdigest()
                or receipt["target_sha256"] != hashlib.sha256((rec.root / "targets/x86_64-unknown-absd.json").read_bytes()).hexdigest()):
            raise Problem("document release, native build receipt, lock or target identity differs")
        stage = (rec.root / "tls/tree/ring").resolve().parent
        staged = json.loads((stage / "STAGE.json").read_text())
        files = (stage / "STAGED-FILES.json").read_bytes()
        expected_files = json.loads(files)
        actual_files = {}
        for path in (stage / "ring").rglob("*"):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise Problem("document ring stage contains a non-regular source object")
            if path.is_file():
                actual_files[path.relative_to(stage / "ring").as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        pins = json.loads((rec.root / "tls/PIN.json").read_text())
        ring_pin = next(p["checksum"] for p in pins["packages"] if p["name"] == "ring")
        patches = {p: hashlib.sha256((rec.root / "patches" / p).read_bytes()).hexdigest()
                   for p in ("ring-absd.patch", "ring-absd-tls-fixture-rng.patch")}
        if (staged != receipt["ring_stage"] or staged["ring_archive_sha256"] != ring_pin
                or staged["patches"] != patches
                or staged["source_manifest_sha256"] != hashlib.sha256(files).hexdigest()
                or expected_files != actual_files):
            raise Problem("document patched ring stage differs from its exact build receipt")
        library = rec.root / ".staged-sysroot/lib/rustlib/src/rust/library"
        library_files = sorted((p for p in library.rglob("*") if p.is_file()),
                               key=lambda p: p.relative_to(library).as_posix().encode())
        if not library_files or any(p.is_symlink() for p in library.rglob("*")):
            raise Problem("document staged standard library missing or contains symlinks")
        library_hash = hashlib.sha256("".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  library/{p.relative_to(library).as_posix()}\n"
            for p in library_files).encode()).hexdigest()
        if library_hash != receipt["staged_std_source_sha256"]:
            raise Problem("document staged standard library differs from native receipt")
        dep_files = sorted(deps_dir.glob("*.d"))
        if not dep_files or deps_dir.parts[-3:] != ("x86_64-unknown-absd", "release", "deps"):
            raise Problem("document notices require actual x86_64-unknown-absd/release/deps/*.d")
        dep_text = "\n".join(document_dep_sources(p.read_text()) for p in dep_files)
        if not re.search(r"(?:^|/)https_document-[^/ ]+\.d$", "\n".join(str(p) for p in dep_files), re.M):
            raise Problem("document target dep-info has no https_document binary")
        dep_identity = {p.name: {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                                "bytes": p.stat().st_size} for p in dep_files}
        if any(p.is_symlink() for p in dep_files) or receipt["application"]["target_dep_info"] != dep_identity:
            raise Problem("document target dep-info differs from native build receipt")
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        raise Problem(f"document notice inputs unavailable or malformed: {error}") from None
    base = next(a for a in rec.config["artifact"] if a["name"] == cfg["base"])
    artifact = copy.deepcopy(base)
    artifact["name"] = cfg["artifact"]
    artifact["_compiler_coverage"] = True
    notice_files, toolchain_proof = document_toolchain_notices(library, receipt)
    document_unit = copy.deepcopy(cfg["unit"])
    document_unit["_compiler_inputs"] = True
    artifact["unit"].append(document_unit)
    for unit in artifact["unit"]:
        if unit["name"] == "std":
            unit["sources"] = str(library)
            unit["_compiler_inputs"] = True
            if notice_files is not None:
                unit["notice_files"] = notice_files
            if "proc_macro" in toolchain_proof:
                unit["_compiler_declarations"] = {"proc_macro": toolchain_proof["proc_macro"]}
            # Cargo build-std emits these compiler units in the fresh target
            # corpus even though they are not roots of the static std graph.
            # Cover their exact sources/texts without claiming ELF membership.
            unit["roots"] = list(dict.fromkeys(unit.get("roots", []) + ["panic_unwind", "proc_macro"]))
    # -Z build-std emits its target dep-info beside the application crates.
    # Include that same existing standard-library unit in the comparison.
    app_only = {"name": "document-target-closure", "unit": [document_unit] +
                [u for u in artifact["unit"] if u["name"] == "std"]}
    app_rows, notes = compute_inventory(rec, app_only)
    if notes or any(r["elected"] in ("UNKNOWN", "UNDECLARED", "DECISION_REQUIRED")
                    or r["texts"] in ("UNKNOWN", "MISSING") for r in app_rows if shipped(r)):
        raise Problem("document target dependency sources, licence decisions or notice texts are incomplete")
    compiled = set(re.findall(r"/registry/src/[^/]+/([^/ \n]+)/", dep_text))
    # ring is compiled from the exact verified patched stage, not registry/src.
    if any(re.search(r"(?:^|[ \t\n])" + re.escape(marker), dep_text)
           for marker in document_ring_source_markers(rec.root, stage / "ring")):
        compiled.add("ring-0.17.14")
    expected = {f"{r['component']}-{r['version']}" for r in app_rows
                if r["use"] in ("linked", "compiler-input") and r["origin"] == "registry"}
    if compiled != expected:
        raise Problem(f"document target compiler closure differs: missing={sorted(expected - compiled)} extra={sorted(compiled - expected)}")
    toolchain_manifests = {}
    for unit in app_only["unit"]:
        if "sources" not in unit:
            continue
        source = Path(unit["sources"])
        graph = Graph(rec.root, unit["lock"], [source / unit.get("manifest_dir", "."), source],
                      Cfg(rec.config.get("target", {})), registries(rec.config),
                      rec.config.get("licence_policy", {}).get("crate_checksums", {}))
        for row in app_rows:
            key = (row["component"], row["version"])
            if row["use"] in ("linked", "compiler-input") and row["origin"] == "toolchain" and unit["name"] in row["units"]:
                source_manifest = graph.manifest(key)
                if source_manifest is None:
                    raise Problem("document toolchain manifest unresolved: " + key[0])
                toolchain_manifests[key] = source_manifest.path
    compiled_crates = document_path_closure(app_rows, dep_files, rec.root, library,
                                           registries(rec.config), stage / "ring", toolchain_manifests)
    fingerprints = {}
    missing_fingerprints = []
    for entry in compiled_crates:
        for name in entry["dep_info"]:
            target, suffix = name[:-2].rsplit("-", 1)
            kind = "bin" if target == "https_document" else "lib"
            path = deps_dir.parent / ".fingerprint" / (entry["component"] + "-" + suffix) / (kind + "-" + target + ".json")
            if path.is_symlink():
                raise Problem("document compiler fingerprint is a symlink")
            if not path.is_file():
                missing_fingerprints.append(name)
                continue
            raw = path.read_bytes()
            try:
                observed = json.loads(raw)
                if not isinstance(observed, dict) or not isinstance(observed.get("deps"), list) or type(observed.get("compile_kind")) is not int:
                    raise ValueError("not a Cargo unit fingerprint")
            except (ValueError, TypeError) as error:
                raise Problem("document compiler fingerprint malformed: " + path.name) from error
            fingerprints[name] = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                                  "unit_dependencies": observed.get("deps", []), "compile_kind": observed.get("compile_kind")}
    artifact.setdefault("component", []).append({"name": "https-document", "version": manifest["release"]["id"],
        "origin": "first-party", "use": "included", "source": f"{cfg['binary']} sha256:{digest}",
        "texts": "First-party command; exact native build receipt bound in DOCUMENT-COMPOSITION.json"})
    rec.config["artifact"].append(artifact)
    rec.__dict__.pop("_inventory", None)
    return {"schema": "absd-document-notice-composition/2", "binary": cfg["binary"], "sha256": digest,
            "bytes": len(binary), "platform_revision": receipt["source_revision"],
            "release_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "build_receipt_sha256": hashlib.sha256(build_receipt.read_bytes()).hexdigest(),
            "coverage": "exact target compiler inputs; not final ELF code membership",
            "configured_compiler_unit_roots": {u["name"]: [u["package"], *u.get("roots", [])] for u in app_only["unit"]},
            "toolchain_declaration_sources": toolchain_proof,
            "target_compiled_registry_packages": sorted(compiled),
            "target_compiled_crates": compiled_crates,
            "compiler_fingerprint_observations": fingerprints,
            "unavailable_fingerprint_observations": sorted(missing_fingerprints),
            "target_dep_info": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in dep_files},
            "ring_stage": staged}


def document_dep_sources(text):
    """Read dependency rule RHSs, never infer source identity from output LHSs.

    The existing source-only unit fixtures have no make-rule colon. Native
    rustc records do, and phony source targets do not supply dependencies.
    """
    lines = [line for line in text.replace("\\\n", " ").splitlines()
             if line and not line.startswith("#")]
    if any(":" in line for line in lines):
        return "\n".join(line.split(": ", 1)[1] for line in lines if ": " in line)
    return "\n".join(lines)


def document_tls_entry_marker(root, source, entry):
    """A Cargo-declared TLS target entry, relative to its manifest directory."""
    if not isinstance(entry, str):
        return None
    path = Path(entry)
    if path.is_absolute() or ".." in path.parts:
        return None
    try:
        tls = (Path(root) / "tls").resolve(strict=True)
        source = Path(source).resolve(strict=True)
        actual = (tls / path).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return path.as_posix() if source == tls and actual.is_relative_to(tls) and actual.is_file() else None


def document_ring_source_markers(root, ring):
    """Known absolute/remapped paths, plus the actual Cargo patch spelling.

    Native Cargo dep-info can retain `tree/ring/` from tls/Cargo.toml. Bind
    that relative spelling to the same already receipt-verified patched tree;
    never accept a basename or an unrelated checkout with the same suffix.
    """
    root, ring = Path(root), Path(ring)
    markers = [str(ring) + "/", "/tls-fixture-stage/ring/"]
    manifest = root / "tls/Cargo.toml"
    if manifest.is_file():
        doc = tomllib.loads(manifest.read_text())
        patch = doc.get("patch", {}).get("crates-io", {}).get("ring", {})
        if patch.get("path") == "tree/ring":
            alias = root / "tls/tree/ring"
            try:
                same = alias.resolve(strict=True) == ring.resolve(strict=True)
            except (OSError, RuntimeError):
                same = False
            if same:
                markers.append("tree/ring/")
    return markers


def document_path_closure(rows, dep_files, root, library, registry_roots=None, ring=None, toolchain_manifests=None):
    """Bind each target dep-info file to an actual selected Cargo target.

    Source roots are exact build paths or the builder's explicit remaps.
    Cargo target names come from manifests, including nested toolchain crates
    and [lib].name aliases. No package-name suffix or arbitrary library path
    is accepted. This checks compiler inputs, not linker reachability.
    """
    root, library = Path(root), Path(library)
    registry_roots = [Path(p) for p in (registry_roots if registry_roots is not None else registries({}))]
    toolchain = {}
    if toolchain_manifests is not None:
        toolchain = {key: [Path(path)] for key, path in toolchain_manifests.items()}
    else:
        for path in library.rglob("Cargo.toml"):
            if path.is_symlink():
                raise Problem("document toolchain manifest is a symlink")
            doc = tomllib.loads(path.read_text())
            package = doc.get("package", {})
            key = (package.get("name"), package.get("version"))
            if all(isinstance(value, str) for value in key):
                toolchain.setdefault(key, []).append(path)
    expected, targets = {}, {}
    for row in rows:
        if row["use"] not in ("linked", "compiler-input"):
            continue
        key = (row["component"], row["version"])
        origin = row["origin"]
        if origin == "toolchain":
            candidates = toolchain.get(key, [])
        elif origin in ("first-party", "vendored"):
            candidates = [root / row["source"] / "Cargo.toml"]
        elif origin == "registry":
            candidates = ([Path(ring) / "Cargo.toml"] if key[0] == "ring" and ring is not None else
                          [p / (key[0] + "-" + key[1]) / "Cargo.toml" for p in registry_roots
                           if (p / (key[0] + "-" + key[1]) / "Cargo.toml").is_file()][:1])
        else:
            raise Problem("document compiler-input crate has no exact source manifest: " + key[0])
        if len(candidates) != 1 or not candidates[0].is_file():
            raise Problem("document compiler-input crate manifest missing or ambiguous: " + key[0])
        manifest = candidates[0]
        doc = tomllib.loads(manifest.read_text())
        package = doc.get("package", {})
        if (package.get("name"), package.get("version")) != key:
            raise Problem("document compiler-input crate manifest identity differs: " + key[0])
        source = manifest.parent
        markers = [str(source) + "/"]
        if origin == "toolchain":
            markers.append("/absd/.staged-sysroot/lib/rustlib/src/rust/library/" +
                           source.relative_to(library).as_posix() + "/")
        elif origin in ("first-party", "vendored"):
            relative = source.relative_to(root).as_posix()
            markers.append("/absd/" + (relative + "/" if relative != "." else ""))
        elif key[0] == "ring" and ring is not None:
            markers = document_ring_source_markers(root, source)
        else:
            markers += ["/cargo/registry/src/" + p.name + "/" + key[0] + "-" + key[1] + "/"
                        for p in registry_roots if source == p / (key[0] + "-" + key[1])]
        alias = doc.get("lib", {}).get("name", key[0].replace("-", "_"))
        if not isinstance(alias, str) or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", alias) is None:
            raise Problem("document Cargo library target name differs: " + key[0])
        base_markers = list(markers)
        if origin == "first-party" and row["source"] == "tls":
            entry = document_tls_entry_marker(root, source, doc.get("lib", {}).get("path", "src/lib.rs"))
            if entry is not None:
                markers.append(entry)
        expected[key] = {"coverage": "compiler-input; final ELF membership not established", "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                         "source": str(source), "target": alias, "dep_info": []}
        targets.setdefault(alias, []).append((key, markers))
        if key[0] == "absd-native-tls-fixture" or (origin == "first-party" and row["source"] == "tls"):
            bins = [entry for entry in doc.get("bin", []) if entry.get("name") == "https_document"]
            if len(bins) != 1:
                raise Problem("document Cargo binary target missing or ambiguous")
            binary_markers = list(base_markers)
            entry = document_tls_entry_marker(root, source, bins[0].get("path", "src/bin/https_document.rs"))
            if entry is not None:
                binary_markers.append(entry)
            targets.setdefault("https_document", []).append((key, binary_markers))
    for path in dep_files:
        match = re.fullmatch(r"([A-Za-z_][A-Za-z_0-9]*)-([0-9a-f]{16})\.d", path.name)
        if match is None:
            raise Problem("document target dep-info filename is not a Cargo target identity: " + path.name)
        text = document_dep_sources(path.read_text())
        matched = [(key, markers) for key, markers in targets.get(match[1], [])
                   if any(re.search(r"(?:^|[ \t\n])" + re.escape(marker) +
                                    (r"(?=$|[ \t\n])" if not marker.endswith("/") else ""), text)
                          for marker in markers)]
        if len(matched) != 1:
            raise Problem("document target compiler closure unexpected target or source path differs: " + path.name)
        expected[matched[0][0]]["dep_info"].append(path.name)
    for key, entry in expected.items():
        # The library and selected binary each need their own compiler output.
        if not any(name.startswith(entry["target"] + "-") for name in entry["dep_info"]):
            raise Problem("document target compiler closure missing path crate: " + key[0])
    return [{"component": key[0], "version": key[1], **entry} for key, entry in sorted(expected.items())]


# ---------------------------------------------------------------- licence policy
#
# The standing licence-policy gate (docs/PROVENANCE.md, "Licence policy
# gate"). It judges every recorded licence against the owner's policy table
# ([licence_policy] in provenance/config.toml) in three scopes: the shipped
# closure (a distribution claim), the rest of the repository (reported, every
# entry), host tools (recorded).
#
# It makes a claim only under five proof obligations (OBLIGATIONS below),
# checked in "preconditions" before any licence is judged. An obligation in
# "gate" mode that is not met voids the claim (NO CLAIM); one switched to
# "report" mode ([licence_policy.obligations]) lists its subjects as
# UNVERIFIED and leaves them out of the claim instead.

OBLIGATIONS = {
    # Gating: what the claim rests on, demonstrated sound (review round 3).
    "O1": "every licence expression parses strictly with the pinned SPDX library, its wheels verified by sha256",
    "G3": "every exact byte comparison the tool makes holds (pinned file hashes, shared-tool identity)",
    # Report-only: listed UNVERIFIED on every run, whatever is detected; never part of a PASS.
    "O2": "evidence completeness and lock identity",
    "O3": "exact identities and incorporation",
    "O4": "notice fulfilment",
    "O5": "peer and composition comparisons",
    "C": "Picolibc collector completeness",
    "S": "SPDX database and boolean.py consistency with the recorded policy input",
}
GATING = ("O1", "G3")
# What each report-only obligation leaves unproven, printed on every run.
UNVERIFIED_SCOPE = {
    "O2": "that every lock identity (including several sources of one name and version inside one lock) and every "
          "closure input was verified; crate archive and manifest checks are reported, not claimed",
    "O3": "that exceptions, acceptances, elections and paired records match exactly the components shipped, and "
          "which kernel the operator image actually incorporates",
    "O4": "that notices and acknowledgements required by accepted terms are complete and distributed",
    "O5": "that the paired repository's audit covers the composed artifact (nested peer runs skip composition)",
    "C": "that the Picolibc member table lists every consumed input of every linked member",
    "S": "that the SPDX licence database digest, list version and boolean.py version are the recorded ones",
}

# Assembled from parts so that this file does not carry the markers it scans for.
_GNU = "GNU "
_GPL_WORDS = "General Public " + "License"
LICENCE_MARKERS = [
    ("lesser-gpl", re.compile(_GNU + "(Lesser|Library) " + _GPL_WORDS, re.I)),
    ("lesser-gpl", re.compile(r"\bL" + "GPL")),
    ("affero-gpl", re.compile(_GNU + "Aff" + "ero", re.I)),
    ("affero-gpl", re.compile(r"\bA" + "GPL")),
    ("gpl", re.compile(_GNU + _GPL_WORDS, re.I)),
    ("gpl", re.compile(r"(?<![A-Za-z])G" + r"PL-[0-9]")),
    ("weak-copyleft", re.compile(r"\b(MPL|EPL|CDDL|EUPL|SSPL|OSL|CPAL|RPL)" + r"-[0-9]")),
    ("weak-copyleft", re.compile("Sleepy" + "cat")),
]
# A licence tag is a line of its own after at most a comment leader of
# punctuation (//, //!, ///, #, /*, *, --, ;, <!--, .\"): a mention inside a
# string literal or a sentence is not one.
LICENCE_TAG = re.compile(r"^\s*(?:[^\w\s\"'`]{1,6}\s*)?" + "SPDX"
                         + r"-License-Identifier\s*[:=]\s*\"?(.+?)\"?\s*(?:\*/|-->)?\s*$")
LICENCE_REF = re.compile(r"LicenseRef-[A-Za-z0-9.-]+")
# The provenance tools are one implementation in the kernel and platform
# repositories; each present here must be pinned in [shared_tools].
SHARED_TOOLS = ("scripts/provenance.py", "scripts/spdx-check.py", "scripts/test_provenance.py",
                "scripts/provenance-counterexamples.toml")
DOCUMENT_SUFFIXES = (".md", ".txt", ".rst", ".adoc", ".html")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")


# ---------------------------------------------------------------- SPDX library (O1)

class SpdxUnavailable(Exception):
    pass


_SPDX = {}


def spdx_library(policy):
    """The pinned `license-expression` library (and its `boolean.py`
    dependency), loaded from wheels whose sha256 [licence_policy.spdx_library]
    records, with the SPDX licence list version it embeds checked against the
    recorded one. The wheels are host tooling, looked up in
    $ABSD_PROVENANCE_WHEELS or ~/.cache/absd/provenance-wheels. Anything
    missing or different raises SpdxUnavailable: no expression is judged."""
    lib = policy.get("spdx_library", {})
    wheels = lib.get("wheels", {})
    key = json.dumps(lib, sort_keys=True)
    if _SPDX.get("key") == key:
        return _SPDX["licensing"]
    if not wheels or not lib.get("spdx_license_list_version") or not lib.get("license_expression_version"):
        raise SpdxUnavailable("[licence_policy.spdx_library] must pin wheels, license_expression_version and "
                              "spdx_license_list_version")
    where = Path(os.environ.get("ABSD_PROVENANCE_WHEELS") or Path.home() / ".cache/absd/provenance-wheels")
    paths = []
    for name, digest in sorted(wheels.items()):
        path = where / name
        if not path.is_file():
            raise SpdxUnavailable(f"{path}: pinned wheel missing (set $ABSD_PROVENANCE_WHEELS)")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SpdxUnavailable(f"{path}: sha256 differs from the pinned one")
        paths.append(str(path))
    import zipfile
    main = next((p for p in paths if Path(p).name.startswith("license_expression-")), None)
    if main is None or f"license_expression-{lib['license_expression_version']}-" not in Path(main).name:
        raise SpdxUnavailable("the pinned license_expression wheel is not the recorded version")
    with zipfile.ZipFile(main) as z:
        about = z.read("license_expression/data/license_key_index.json.ABOUT").decode()
        index = z.read("license_expression/data/scancode-licensedb-index.json")
    embedded = re.search(r"^spdx_license_list_version:\s*(\S+)", about, re.M)
    # Reported, not gated (review round 3): the database's list version and
    # digest and the boolean.py version against the recorded policy input.
    _SPDX["consistency"] = [p for p in (
        None if embedded and embedded.group(1) == lib["spdx_license_list_version"] else
        f"the wheel embeds SPDX licence list {embedded.group(1) if embedded else '?'}, the policy records "
        f"{lib['spdx_license_list_version']}",
        None if hashlib.sha256(index).hexdigest() == lib.get("license_index_sha256") else
        "the licence database digest is not the recorded license_index_sha256",
        None if any(Path(p).name.startswith(f"boolean_py-{lib.get('boolean_py_version')}-") for p in paths) else
        "the boolean.py wheel is not the recorded boolean_py_version") if p]
    for p in paths:
        if p not in sys.path:
            sys.path.insert(0, p)
    tmp = tempfile.mkdtemp(prefix="absd-spdx-")
    (Path(tmp) / "index.json").write_bytes(index)
    try:
        import license_expression
        licensing = license_expression.get_spdx_licensing(str(Path(tmp) / "index.json"))
    except Exception as error:  # the library itself failed to load
        raise SpdxUnavailable(f"license-expression failed to load: {error}") from None
    _SPDX.update(key=key, licensing=licensing, checked=list(_SPDX.get("consistency", [])))
    return licensing


def spdx_tree(expr, policy, cargo=False):
    """(tree, None) or (None, problem). The whole expression is validated by
    the pinned library in strict mode: unknown identifiers fail, except
    LicenseRef- identifiers. CARGO accepts Cargo's legacy '/' for OR, for
    crate manifests only. The tree is ('id', key) / ('and'|'or', [...]),
    with library-normalised keys; WITH makes 'KEY WITH EXCEPTION'."""
    expr = " ".join(str(expr).split())
    if not expr:
        return None, "no licence recorded"
    if cargo:
        expr = expr.replace("/", " OR ")
    licensing = spdx_library(policy)
    try:
        info = licensing.validate(expr, strict=True)
        bad = [e for e in info.errors if not e.startswith("Unknown license key(s)")]
        unknown = [s for s in info.invalid_symbols if not LICENCE_REF.fullmatch(str(s))]
        if bad or unknown:
            return None, "; ".join(bad + [f"unknown identifier {s}" for s in unknown])
        parsed = licensing.parse(expr, validate=False, strict=True)
    except Exception as error:  # the library raises on some malformed input
        return None, f"not an SPDX licence expression ({type(error).__name__})"

    def walk(node):
        name = type(node).__name__
        if name == "AND":
            return ("and", [walk(a) for a in node.args])
        if name == "OR":
            return ("or", [walk(a) for a in node.args])
        if name == "LicenseWithExceptionSymbol":
            return ("id", f"{node.license_symbol.key} WITH {node.exception_symbol.key}")
        return ("id", node.key)
    return walk(parsed), None


def license_tree(expr):
    """The parse tree the inventory uses for licence election (crate
    manifests, so Cargo's '/' is OR). Raises ValueError on a malformed
    expression. Uses the pinned library when a policy loaded it; otherwise
    the strict local grammar below, which never skips a token."""
    if "licensing" in _SPDX:
        tree, problem = spdx_tree(expr, {"spdx_library": json.loads(_SPDX["key"])}, cargo=True)
        if tree is None:
            raise ValueError(problem)
        return tree
    return local_license_tree(expr)


def licence_leaves(node):
    kind, value = node
    return [value] if kind == "id" else [leaf for part in value for leaf in licence_leaves(part)]


def licence_denied(term, policy):
    """The denied family pattern TERM falls under (its WITH exception does
    not change the family), or None."""
    base = term.split(" WITH ")[0]
    return next((p for p in policy.get("denied", []) if fnmatch.fnmatchcase(base, p)), None)


def judge_licence(expr, policy, extra=(), cargo=False):
    """(ok, taken, why) for one recorded licence expression. An expression
    the pinned SPDX library does not accept gives why "O1: ...", which the
    gate treats as an unmet proof obligation, not as a licence finding. An
    OR passes when one alternative consists only of allowed terms; that
    alternative is the one taken, and WHY then names any denied alternative,
    which needs a recorded election. WITH never rescues a denied licence; AND
    needs every part allowed. A term on `pending` fails as awaiting the
    owner."""
    allowed = list(policy.get("allowed", [])) + [e for e in extra if e not in policy.get("allowed", [])]
    try:
        tree, problem = spdx_tree(expr, policy, cargo)
    except SpdxUnavailable as error:
        return False, None, f"O1: {error}"
    if tree is None:
        return False, None, ("no licence recorded" if problem == "no licence recorded" else f"O1: {problem}")

    def walk(node):
        kind, value = node
        if kind == "id":
            return [value] if value in allowed else None
        options = [walk(part) for part in value]
        if kind == "and":
            return None if None in options else sorted({x for o in options for x in o})
        options = [o for o in options if o is not None]
        return min(options, key=lambda o: max(allowed.index(x) for x in o)) if options else None

    leaves = licence_leaves(tree)
    taken = walk(tree)
    denied = sorted({f"{t} ({licence_denied(t, policy)})" for t in leaves if licence_denied(t, policy)})
    if taken is None:
        if denied:
            return False, None, "denied: " + ", ".join(denied)
        pending = {p["licence"]: p for p in policy.get("pending", [])}
        missing = sorted({t for t in leaves if t not in allowed})
        if all(t in pending for t in missing):
            return False, None, "pending owner acceptance: " + ", ".join(missing)
        return False, None, "not on the allowed list: " + ", ".join(missing)
    return True, taken, ("taken from an expression that also offers " + ", ".join(denied)) if denied else ""


class LicenceGate:
    """Findings of the licence-policy gate in its three scopes, and the proof
    obligations its claim rests on.

    distribution: the shipped closure. A denied, pending or unaccepted
        licence or an unrecorded election fails it.
    inventory: everything else the repository names, every entry listed with
        path and reason; never fails a distribution audit by itself.
    host: tools the build or the tests run on the host, with obligations.
    obligation: an unmet proof obligation. In gate mode the result is NO
        CLAIM; in report mode the subject is UNVERIFIED and left out.

    `items` holds every entry as (scope, status, where, component, licence,
    detail); `full` writes them to licence-report.tsv."""

    def __init__(self, full, modes=None, local=False):
        # Only the GATING obligations can void the claim; every other one is
        # report-only, whatever the configuration says.
        self.full, self.local = full, local
        self.items, self.closure, self.excluded = [], {}, set()
        self.artifacts, self.open, self.peer = [], [], None

    def add(self, scope, status, where, component, licence, detail=""):
        if detail.startswith("O1: ") and scope == "distribution":
            self.unmet("O1", where, component, f"{licence}: {detail[4:]}")
            return
        if detail.startswith("O1: "):
            status, detail = "unparseable", detail[4:]
        self.items.append((scope, status, where, component, licence, detail))

    def unmet(self, oid, where, subject, problem):
        status = "UNMET" if oid in GATING else "DETECTED"
        self.items.append(("obligation", f"{status} {oid}", where, subject, "", problem))

    def fail(self, where, component, licence, rule):
        self.add("distribution", "FAIL", where, component, licence, rule)

    def unknown_input(self, where, component, why):
        self.fail(where, component, "UNKNOWN", f"licence not read: {why}")

    def ok_entry(self, where, component, licence, detail=""):
        self.add("distribution", "allowed", where, component, licence, detail)

    def report(self, status, where, component, licence, why):
        self.add("inventory", status, where, component, licence, why)

    def blocking(self):
        return [i for i in self.items if i[0] == "obligation" and i[1].startswith("UNMET")]

    def fails(self):
        return [i for i in self.items if i[0] == "distribution" and i[1].startswith("FAIL")] + self.blocking()

    def count(self):
        return len(self.fails())

    def ok(self):
        return self.count() == 0

    def rows(self):
        always = [("obligation", f"UNVERIFIED {o}", "", OBLIGATIONS[o], "", UNVERIFIED_SCOPE[o])
                  for o in OBLIGATIONS if o not in GATING]
        opened = [("condition", "OPEN", "", c, "", d) for c, d in self.open]
        return [("scope", "status", "where", "component", "licence", "detail")] + always + opened + self.items

    def scope(self):
        short = {"O2": "O2 evidence completeness", "O3": "O3 identities", "O4": "O4 notices", "O5": "O5 composition",
                 "C": "collector completeness", "S": "SPDX database consistency"}
        unverified = ", ".join(short[o] for o in OBLIGATIONS if o not in GATING)
        text = f"scope: expression validity and declared-licence policy; UNVERIFIED: {unverified}"
        if self.open:
            text += f"; OPEN: {'; '.join(sorted(set(o for o, _ in self.open)))}"
        if not self.peer:
            text += "; no peer given"
        return text

    def verdict(self):
        if self.blocking():
            return f"NO CLAIM ({len(self.blocking())} unmet gating obligation(s); {self.scope()})"
        fails = [i for i in self.items if i[0] == "distribution" and i[1].startswith("FAIL")]
        if fails:
            return f"FAIL {len(fails)} ({self.scope()})"
        return f"PASS ({self.scope()})"

    def print(self):
        print(f"LICENCE POLICY DISTRIBUTION: {self.verdict()}")
        print("  closure: " + "; ".join(f"{k} {v}" for k, v in self.closure.items()))
        for scope, status, where, component, licence, detail in self.items:
            if scope == "obligation" and status.startswith("UNMET"):
                oid = status.split()[-1]
                print(f"  {status}  {where}\n      subject: {component}\n      obligation: {OBLIGATIONS[oid]}"
                      f"\n      problem: {detail}")
        affected = ", ".join(self.artifacts) or "none"
        for oid in OBLIGATIONS:
            if oid in GATING:
                continue
            detected = [i for i in self.items if i[0] == "obligation" and i[1] == f"DETECTED {oid}"]
            print(f"  UNVERIFIED {oid}  {OBLIGATIONS[oid]}: not part of this claim (artifacts: {affected}); "
                  f"unproven: {UNVERIFIED_SCOPE[oid]}; {len(detected)} problem(s) detected")
            for _, _, where, component, _, detail in detected:
                print(f"      detected  {where}: {component}: {detail}")
        for condition, detail in self.open:
            print(f"  OPEN  {condition}: {detail}")
        for scope, status, where, component, licence, detail in self.items:
            if scope == "distribution" and status.startswith("FAIL"):
                print(f"  {status}  {where}\n      component: {component}\n      licence: {licence}\n      rule: {detail}")
        self.print_groups("distribution", exclude=("FAIL",))
        inventory = [i for i in self.items if i[0] == "inventory"]
        kinds = {}
        for item in inventory:
            kinds[item[1]] = kinds.get(item[1], 0) + 1
        print(f"LICENCE INVENTORY: {len(inventory)} entr{'y' if len(inventory) == 1 else 'ies'} outside the shipped "
              "closure (" + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) + "); reported, not a "
              "distribution failure")
        self.print_groups("inventory")
        host = [i for i in self.items if i[0] == "host"]
        print(f"LICENCE HOST TOOLS: {len(host)} recorded; used on the build or test host, not distributed")
        for _, _, _, name, licence, detail in host:
            print(f"  host  {name}: {licence}; {detail}")
        print("  The gate identifies licences only; notice and source obligations are provenance/obligations.toml's.")

    def print_groups(self, scope, exclude=()):
        groups = {}
        for s, status, where, component, licence, detail in self.items:
            if s == scope and status not in exclude:
                groups.setdefault((status, licence, detail), []).append(f"{component} [{where}]" if where else component)
        for (status, licence, detail), entries in sorted(groups.items()):
            print(f"  {status}  {licence}{': ' + detail if detail else ''}: {len(entries)}: " + "; ".join(entries))


# ---------------------------------------------------------------- source notices (shared with generators)

def dep5(text, paragraphs=None):
    """A Debian copyright-format file: [(patterns, label, copyright)] in order,
    and {label: text with whitespace collapsed}. PARAGRAPHS, when given,
    receives {label: the licence text as written}."""
    files, texts = [], {}
    for para in re.split(r"\n\s*\n", text):
        fields, key = {}, None
        for line in para.splitlines():
            m = re.match(r"^([A-Za-z-]+):(.*)$", line)
            if m:
                key = m.group(1)
                fields[key] = m.group(2).strip()
            elif key:
                fields[key] += "\n" + line
        if "License" not in fields:
            continue
        name = fields["License"].split("\n")[0].strip()
        if "Files" in fields:
            files.append((fields["Files"].split(), name, " ".join(fields.get("Copyright", "").split())))
        else:
            texts[name] = " ".join(fields["License"].split()[1:])
            if paragraphs is not None:
                paragraphs[name] = "\n".join(l.strip() for l in fields["License"].split("\n")[1:])
    return files, texts


def dep5_label(files, path, holders=False):
    found = (None, "")
    for patterns, name, copyright in files:  # the last matching paragraph wins
        if any(fnmatch.fnmatchcase(path, p) for p in patterns):
            found = (name, copyright)
    return found if holders else found[0]


def source_header(text):
    """A source file's leading comments, verbatim: every block comment and
    line comment before its first line of code (preprocessor lines such as
    an include guard are passed over, not copied)."""
    out, pos = [], 0
    while pos < len(text):
        while pos < len(text) and text[pos] in " \t\r\n":
            pos += 1
        if text.startswith("/*", pos):
            end = text.find("*/", pos)
            if end < 0:
                break
            out.append(text[pos:end + 2])
            pos = end + 2
        elif text.startswith("//", pos):
            end = text.find("\n", pos)
            end = len(text) if end < 0 else end
            out.append(text[pos:end])
            pos = end
        elif re.match(r"#\s*(if|ifdef|ifndef|define|endif|include)\b", text[pos:pos + 20]):
            end = text.find("\n", pos)
            pos = len(text) if end < 0 else end
        else:
            break
    return "\n".join(out)


def no_header_note(record):
    return f"(no header in the file; COPYING.picolibc records: {record})"


def parse_notice(raw):
    """A member-table notice: {"ack": [lines], label: {"text": [lines],
    "terms": {name: [lines]}, "files": {path: [body lines]}}}."""
    out, label, part, ack = {}, None, None, []
    target = None
    for line in raw.splitlines():
        if line.startswith("== ACKNOWLEDGEMENTS"):
            part = "ack"
        elif line.startswith("== LABEL "):
            label, part = line[9:].strip(), "text"
            out[label] = {"text": [], "terms": {}, "files": {}}
        elif line.startswith("-- TERMS ") and label:
            target = out[label]["terms"].setdefault(line[9:].split()[0], [])
            part = "terms"
        elif line.startswith("-- FILE ") and label:
            target = out[label]["files"].setdefault(line[8:].strip(), [])
            part = "file"
        elif line.startswith("REUSE-"):
            continue
        elif part == "ack":
            if line.strip():
                ack.append(line.strip())
        elif part == "text":
            out[label]["text"].append(line)
        elif part in ("terms", "file"):
            target.append(line)
    out["ack"] = ack
    return out


# ---------------------------------------------------------------- preconditions: the proof obligations
#
# Everything here runs before any licence is judged. Each function checks one
# obligation and records what is unmet; nothing here makes a licence claim.

def pre_spdx(policy, gate):
    """O1: the pinned SPDX library is present, intact and the recorded
    version; every expression the policy itself states parses."""
    try:
        spdx_library(policy)
    except SpdxUnavailable as error:
        gate.unmet("O1", "provenance/config.toml", "[licence_policy.spdx_library]", str(error))
        return False
    for problem in _SPDX.get("checked", []):
        gate.unmet("S", "provenance/config.toml", "[licence_policy.spdx_library]", problem)
    for term in policy.get("allowed", []) + [p.get("licence", "") for p in policy.get("pending", [])]:
        tree, problem = spdx_tree(term, policy)
        if tree is None:
            gate.unmet("O1", "provenance/config.toml", f"licence_policy term {term}", problem)
    return True


def policy_entries(policy, gate, table, required):
    """Entries of one policy table with the fields an identity needs (O3)."""
    out = []
    for entry in policy.get(table, []):
        missing = [k for k in required if not entry.get(k)]
        if missing:
            gate.unmet("O3", "provenance/config.toml", f"licence_policy.{table} "
                       f"{entry.get('id', entry.get('name', entry.get('component', entry.get('licence', '?'))))}",
                       "missing " + ", ".join(missing))
            continue
        out.append(entry)
    return out


def pre_identities(rec, policy, gate):
    """O3: exceptions, acceptances, elections and decisions each name an exact
    identity, and their own expressions parse. Returns the usable entries."""
    exceptions = []
    for e in policy_entries(policy, gate, "exception", ("id", "licence", "scope", "decision")):
        if e.get("component") and not (e.get("version") and e.get("artifacts") and
                                       (e.get("source") or HEX64.fullmatch(e.get("sha256", "")))):
            gate.unmet("O3", "provenance/config.toml", f"exception {e['id']}",
                       "a component exception names version, artifacts and source or sha256")
        elif not (e.get("component") or e.get("paths")):
            gate.unmet("O3", "provenance/config.toml", f"exception {e['id']}", "names no component or paths")
        else:
            exceptions.append(e)
    elections = []
    for e in policy_entries(policy, gate, "election", ("component", "versions", "expression", "elected", "decision")):
        if not isinstance(e["versions"], list) or not all(isinstance(v, str) and v for v in e["versions"]):
            gate.unmet("O3", "provenance/config.toml", f"election {e['component']}", "versions must list exact versions")
            continue
        for field in ("expression", "elected"):
            if spdx_tree(e[field], policy)[0] is None:
                gate.unmet("O1", "provenance/config.toml", f"election {e['component']}", f"{field} does not parse")
        elections.append(e)
    accepted = []
    for a in policy_entries(policy, gate, "accepted", ("licence", "member_table", "name", "version", "source_sha256",
                                                       "conditions", "decision")):
        if not HEX64.fullmatch(a["source_sha256"]):
            gate.unmet("O3", "provenance/config.toml", f"accepted {a['licence']}", "source_sha256 is not a sha256")
            continue
        if "inputs" in a and not (isinstance(a.get("input_sha256"), dict) and a["inputs"]
                                  and all(HEX64.fullmatch(a["input_sha256"].get(i, "")) for i in a["inputs"])):
            gate.unmet("O3", "provenance/config.toml", f"accepted {a['licence']}",
                       "an acceptance scoped to inputs names each input's sha256 (input_sha256)")
            continue
        tables_here = {t.get("path") for t in policy.get("member_table", [])}
        if a.get("interpretation") and a["member_table"] in tables_here \
                and not (rec.root / f"LICENSES/{a['interpretation']}.txt").is_file():
            gate.unmet("O3", "provenance/config.toml", f"accepted {a['licence']}",
                       f"its interpretation's text LICENSES/{a['interpretation']}.txt is missing")
            continue
        accepted.append(a)
    policy_entries(policy, gate, "pending", ("licence", "users", "obligations", "decision"))
    for key in rec.policy.get("decisions", {}):
        if len(key.split()) != 2:
            gate.unmet("O3", "provenance/config.toml", f"policy.decisions {key}",
                       "a decision names one exact version: \"crate VERSION\"")
    return exceptions, elections, accepted


def closure_resolution(rec, policy, gate):
    """The distributed artifacts' closures, resolved but not judged:
    [(artifact, rows)], every row carrying the lock identities it was merged
    from. Inconsistent configuration is an O2 failure: the evidence the claim
    needs is incomplete."""
    out = []
    names = {t["name"] for t in policy.get("host_tool", []) + policy.get("held", []) if t.get("name")}
    for variant in policy_entries(policy, gate, "variant", ("name", "env", "reason")):
        on = [v for v in variant["env"] if os.environ.get(v)]
        if on:
            gate.unmet("O2", "environment", variant["name"], f"{', '.join(on)} selects a build variant whose closure "
                       f"the gate does not resolve: {variant['reason']}")
        else:
            gate.report("variant-not-covered", "provenance/config.toml", variant["name"], "",
                        f"selected by {', '.join(variant['env'])}; {variant['reason']}")
    for artifact in rec.config.get("artifact", []):
        where = f"provenance/config.toml [{artifact['name']}]"
        if "distributed" not in artifact:
            gate.unmet("O2", where, f"artifact {artifact['name']}", "every artifact states distributed = true or false")
            continue
        if not artifact["distributed"]:
            continue
        hidden = [u["name"] for u in artifact.get("unit", []) if u.get("listed") is False]
        if hidden:
            gate.unmet("O2", where, ", ".join(hidden), "listed = false units are never resolved, so they cannot be "
                       "part of a distributed artifact")
        for name in sorted({c["name"] for c in artifact.get("component", [])} & names):
            gate.unmet("O2", where, name, "a host tool or held artifact is declared part of a distributed artifact")
        wide = copy.deepcopy(artifact)
        wide["_wide"] = True
        try:
            rows, notes = compute_inventory(rec, wide)
        except Problem as error:
            gate.unmet("O2", where, artifact["name"], f"closure cannot be resolved: {error}")
            continue
        for _, path, why in notes:
            gate.unmet("O2", path, artifact["name"], why)
        out.append((artifact, rows))
    return out


def pre_crates(rec, policy, resolved, gate):
    """O2: every registry crate in a closure is verified for every distinct
    identity (lock, source, checksum) it was resolved from, before rows are
    trusted: the archive's sha256 must be that checksum (or, for a lock root
    or staged copy without one, the checksum its pin records), the source's
    manifest must equal the archive's, and one name and version may not
    carry two checksums."""
    verify = crate_archives(rec, policy)
    pinned = policy.get("crate_checksums", {})
    for artifact, rows in resolved:
        for row in rows:
            if row["use"] not in ("linked", "compiler-input") or row["origin"] != "registry":
                continue
            component = f"{row['component']} {row['version']}"
            ids = sorted(row.get("_ids", set()))
            sums = {c or pinned.get(component, "") for _, _, c in ids}
            if len(sums) != 1:
                gate.unmet("O2", ", ".join(l for l, _, _ in ids), component,
                           f"conflicting checksums across locks: {', '.join(sorted(s or '(none)' for s in sums))}")
                continue
            for lock, source, checksum in ids:
                if source and source not in policy.get("crate_registries", ["registry+https://github.com/rust-lang/crates.io-index"]):
                    gate.unmet("O2", lock, component, f"unsupported source {source}")
                problem = verify(row["component"], row["version"], checksum or pinned.get(component, ""))
                if problem:
                    gate.unmet("O2", lock, component, problem)


def pre_member_tables(rec, policy, accepted, gate):
    """O2: each member table is present and bound to its sealed receipt (the
    receipt's sha256 pinned in the policy; the table's sha256, rows, members
    and per-member counts, and every bound input, as the receipt states).
    Returns {path: (table, receipt, rows)} for bound tables."""
    out = {}
    for table in policy.get("member_table", []):
        component = table.get("component", table.get("path", "?"))
        path = rec.root / table.get("path", "")
        receipt_path = rec.root / table.get("receipt", "")
        if not table.get("path") or not path.is_file():
            gate.unmet("O2", table.get("path", "?"), component, "member table missing")
            continue
        if not table.get("receipt") or not table.get("receipt_sha256") or not receipt_path.is_file():
            gate.unmet("O2", table["path"], component, "member table without its sealed receipt (receipt, receipt_sha256)")
            continue
        raw = receipt_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != table["receipt_sha256"]:
            gate.unmet("G3", table["receipt"], component, "receipt differs from the sha256 the policy pins")
            continue
        receipt = json.loads(raw)
        text = path.read_bytes()
        rows = parse_tsv(text.decode())
        coverage = {}
        for row in rows:
            coverage[row.get("member")] = coverage.get(row.get("member"), 0) + 1
        problems, byte = [], []
        if hashlib.sha256(text).hexdigest() != receipt.get("table_sha256"):
            byte.append("table differs from the sha256 its receipt states")
        if not rows or len(rows) != receipt.get("rows") or len(coverage) != receipt.get("member_count"):
            problems.append(f"{len(rows)} row(s) and {len(coverage)} member(s); the receipt states "
                            f"{receipt.get('rows')} and {receipt.get('member_count')}")
        if sorted(coverage) != receipt.get("members") or coverage != receipt.get("coverage"):
            problems.append("members or per-member input counts differ from the receipt")
        if not receipt.get("bound_files"):
            problems.append("receipt binds no input files")
        for bound, digest in sorted(receipt.get("bound_files", {}).items()):
            now = hashlib.sha256((rec.root / bound).read_bytes()).hexdigest() if (rec.root / bound).is_file() else "missing"
            if now != digest:
                byte.append(f"{bound} changed since the table was generated: regenerate it")
        if not HEX64.fullmatch(receipt.get("source_sha256", "")):
            problems.append("receipt names no source sha256")
        for p in byte:
            gate.unmet("G3", table["path"], component, "member table not bound to its inputs: " + p)
        for p in problems:
            gate.unmet("O2", table["path"], component, "member table not consistent with its receipt: " + p)
        if not byte:
            out[table["path"]] = (table, receipt, rows)
    return out


def table_acceptances(table, receipt, accepted):
    """The acceptances that apply to a bound table: same table, name,
    version and source sha256."""
    return [a for a in accepted if a["member_table"] == table["path"] and a["name"] == table.get("name")
            and a["version"] == table.get("version") and a["source_sha256"] == receipt.get("source_sha256")]


def source_archive(rec, table, receipt):
    """The pinned source archive a table's notice is verified against:
    $ABSD_SOURCE_ARCHIVE_<NAME> or the table's `source_archives` (paths
    relative to the repository); its sha256 must be the receipt's source."""
    candidates = [os.environ.get(f"ABSD_SOURCE_ARCHIVE_{table.get('name', '').upper()}", "")]
    candidates += [str(expand(p, rec.root)) for p in table.get("source_archives", [])]
    for c in candidates:
        if c and Path(c).is_file() and hashlib.sha256(Path(c).read_bytes()).hexdigest() == receipt.get("source_sha256"):
            return Path(c)
    return None


def pre_notices(rec, policy, tables, accepted, gate):
    """O4: a table any acceptance applies to, or that names a notice, must
    have its notice, label map and source archive. The notice must be the one
    the receipt names; each label's text must be the reviewed text and the
    text COPYING writes; every consumed source input must have its entry,
    whose body must equal the header of that file in the pinned source (or
    the record COPYING gives when the file has none); an acceptance's
    interpretation must carry its terms verbatim and its acknowledgement
    must be present; and the table's artifact must be distributed, so that
    `notices` bundles the notice with it."""
    for path, (table, receipt, rows) in sorted(tables.items()):
        component = table.get("component", path)
        applies = table_acceptances(table, receipt, accepted)
        if not applies and not table.get("notice"):
            continue
        problems = []
        if not table.get("notice") or not table.get("labels"):
            problems.append("its accepted terms require a notice and a label map (notice, labels)")
        artifact = next((a for a in rec.config.get("artifact", []) if a["name"] == table.get("artifact")), None)
        if not artifact or not artifact.get("distributed"):
            problems.append("its artifact is not a distributed artifact, so no bundle carries the notice")
        archive = source_archive(rec, table, receipt)
        if archive is None:
            problems.append("the pinned source archive is not available to verify the notice "
                            f"(source_archives or $ABSD_SOURCE_ARCHIVE_{table.get('name', '').upper()})")
        notice = rec.root / table.get("notice", "")
        if table.get("notice") and not notice.is_file():
            problems.append(f"{table['notice']} missing")
        if problems:
            for p in problems:
                gate.unmet("O4", table.get("notice", path), component, p)
            continue
        raw = notice.read_bytes()
        if hashlib.sha256(raw).hexdigest() != receipt.get("notice_sha256"):
            gate.unmet("O4", table["notice"], component, "differs from the notice its receipt names")
            continue
        reviewed = {}
        if (rec.root / table["labels"]).is_file():
            for line in (rec.root / table["labels"]).read_text().splitlines():
                f = line.split("\t")
                if len(f) == 4 and not line.startswith("#"):
                    reviewed[f[0]] = f[1]
        parsed = parse_notice(raw.decode())
        with tarfile.open(archive) as t:
            members = {m.name.split("/", 1)[1]: m for m in t.getmembers() if m.isfile() and "/" in m.name}
            read = lambda rel: t.extractfile(members[rel]).read().decode("utf-8", "replace")
            paragraphs = {}
            files, _ = dep5(read("COPYING.picolibc") if "COPYING.picolibc" in members else "", paragraphs)
            problems = []
            for name, sec in sorted((k, v) for k, v in parsed.items() if k != "ack"):
                text = "\n".join(sec["text"]).strip("\n")
                if hashlib.sha256(" ".join(text.split()).encode()).hexdigest() != reviewed.get(name):
                    problems.append(f"the text under {name} is not the reviewed text for that label")
                if text != paragraphs.get(name, "").strip("\n"):
                    problems.append(f"the text under {name} is not the text COPYING writes for it")
                for rel, body in sorted(sec["files"].items()):
                    if rel not in members:
                        problems.append(f"{rel}: not in the pinned source")
                        continue
                    want = source_header(read(rel)) or no_header_note(dep5_label(files, rel, True)[1])
                    if "\n".join(body).strip("\n") != want.strip("\n"):
                        problems.append(f"{rel}: its notice body is not the file's header in the pinned source")
            for row in rows:
                source = row.get("input", "")
                if row.get("use") != "consumed" or source.startswith(("host:", "build:")):
                    continue
                if source not in parsed.get(row.get("label"), {}).get("files", {}):
                    problems.append(f"{row.get('member')} ships {source} ({row.get('label')}) without its notice entry")
            used = {r.get("licence") for r in rows if r.get("use") == "consumed"}
            for a in applies:
                if a["licence"] not in used:
                    continue
                label = next((r.get("label") for r in rows if r.get("licence") == a["licence"]), None)
                if a.get("acknowledgement") and a["acknowledgement"] not in parsed["ack"]:
                    problems.append(f"acknowledgement missing: \"{a['acknowledgement']}\" ({a['licence']})")
                if a.get("interpretation"):
                    terms = "\n".join(parsed.get(label, {}).get("terms", {}).get(a["interpretation"], [])).strip("\n")
                    want = (rec.root / f"LICENSES/{a['interpretation']}.txt").read_text().strip("\n")
                    if terms != want:
                        problems.append(f"{label}: the {a['interpretation']} terms of its interpretation are not "
                                        "in the notice verbatim")
        for p in sorted(set(problems)):
            gate.unmet("O4", table["notice"], component, p)


def git_head(root):
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True)
    dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True)
    return (head.stdout.strip() if head.returncode == 0 else None), bool(dirty.stdout.strip())


def pre_comparisons(rec, policy, gate, peer, release=None):
    """O5: a peer is another repository (its own root and repository name);
    each paired-audit record names the component's repository and artifact
    and its incorporated revision; with a peer, the peer is that repository
    at that revision, clean, its distribution gate passes now and its
    inventory is the recorded one; with a release manifest, the manifest's
    kernel commit is the incorporated revision. Without a peer the
    comparisons are not made: the result is local, not a distribution claim.
    Returns the paired records that held, by component name."""
    other = None
    if peer:
        try:
            other = Records(peer)
        except Problem as error:
            gate.unmet("O5", str(peer), "peer repository", f"unreadable: {error}")
        else:
            if Path(peer).resolve() == rec.root.resolve() or other.config.get("repository") == rec.config.get("repository"):
                gate.unmet("O5", str(peer), "peer repository", "the peer is this repository, not another one")
                other = None
    held = {}
    for artifact in rec.config.get("artifact", []):
        if not artifact.get("distributed"):
            continue
        for c in artifact.get("component", []):
            if not c.get("cross_repository") or c.get("use") == "variant":
                continue
            subject = f"{c['name']} {c.get('version', '')}".strip()
            for other_id in c.get("distinct_identities", []):
                gate.unmet("O3", "provenance/config.toml", subject, f"{other_id.get('commit')} ({other_id.get('role')}) is a "
                           f"different identity from the paired audit's {c.get('incorporated_commit')}; this audit says "
                           "nothing about it")
            path = rec.root / c.get("paired_audit", "")
            if not c.get("paired_audit") or not path.is_file():
                gate.unmet("O2", "provenance/config.toml", subject, "cross-repository component without a paired-audit "
                           "record (paired_audit)")
                continue
            try:
                record = tomllib.loads(path.read_text())
            except tomllib.TOMLDecodeError as error:
                gate.unmet("O2", c["paired_audit"], subject, f"paired-audit record unreadable: {error}")
                continue
            problems = []
            if record.get("repository") != c.get("cross_repository"):
                problems.append(f"the record is for {record.get('repository')}, the component is built in "
                                f"{c.get('cross_repository')}")
            if record.get("artifact") != c.get("paired_artifact"):
                problems.append(f"the record audits {record.get('artifact')}, the component is "
                                f"{c.get('paired_artifact')}")
            if not HEX40.fullmatch(record.get("commit", "")) or record.get("commit") != c.get("incorporated_commit"):
                problems.append("the record's commit is not the component's incorporated_commit")
            if record.get("gate") != "PASS":
                problems.append(f"the paired repository's gate recorded {record.get('gate')}")
            if record.get("shared_tools") != rec.config.get("shared_tools", {}).get("sha256", {}):
                problems.append("the paired audit ran under other provenance tools")
            if not HEX64.fullmatch(record.get("inventory_sha256", "")):
                problems.append("the record names no inventory sha256")
            if release:
                manifest = tomllib.loads(Path(release).read_text())
                kernel = manifest.get("source", {}).get("kernel_commit") or manifest.get("release", {}).get("kernel_commit")
                if kernel != c.get("incorporated_commit"):
                    problems.append(f"the release incorporates kernel {kernel}, not {c.get('incorporated_commit')}")
            # The record must identify exactly the component's repository,
            # artifact and incorporated revision: an identity question (O3),
            # decided before any comparison.
            for p in problems:
                gate.unmet("O3", c["paired_audit"], subject, p)
            if problems:
                continue
            if other is None:
                if not peer:
                    gate.unmet("O5", c["paired_audit"], subject, "not compared: no peer checkout given")
                continue
            head, dirty = git_head(other.root)
            if other.config.get("repository") != record["repository"]:
                gate.unmet("O5", str(peer), subject, f"the peer is {other.config.get('repository')}, not "
                           f"{record['repository']}")
                continue
            if head != record["commit"] or dirty:
                gate.unmet("O5", str(peer), subject, f"the peer is at {head}{' with changes' if dirty else ''}, the "
                           f"record names {record['commit']}")
                continue
            result = licence_gate(other, full=True, peer=None, nested=True)
            if not result.ok():
                gate.unmet("O5", str(peer), subject, f"the peer's distribution gate does not pass now: {result.verdict()}")
                continue
            inv = other.root / f"provenance/inventory/{record['artifact']}.tsv"
            if not inv.is_file() or hashlib.sha256(inv.read_bytes()).hexdigest() != record["inventory_sha256"]:
                gate.unmet("O5", str(peer), subject, "the peer's inventory differs from the paired-audit record")
                continue
            held[c["name"]] = record
    return held


def pre_expressions(rec, policy, resolved, tables, gate):
    """O1: every expression the claim rests on parses with the pinned SPDX
    library: provenance.toml rule fields, REUSE.toml annotations, licence
    tags in tracked files, distributed components and closure rows, member
    table rows, pin licences. Run before anything is judged."""
    def need(where, subject, expr, cargo=False):
        tree, problem = spdx_tree(expr, policy, cargo)
        if tree is None and problem != "no licence recorded":
            gate.unmet("O1", where, subject, f"{expr}: {problem}")
    text = (rec.root / "provenance.toml").read_text()
    lines = [n for n, line in enumerate(text.splitlines(), 1) if line.strip() == "[[files]]"]
    for index, (_, rule) in enumerate(rec.rules.entries):
        for field in ("license", "upstream-license", "first-party-portion"):
            if rule.get(field) not in (None, "pending"):
                need(f"provenance.toml:{lines[index] if index < len(lines) else '?'}", str(rule["path"])[:80], rule[field])
    reuse = rec.root / "REUSE.toml"
    if reuse.is_file():
        try:
            for a in tomllib.loads(reuse.read_text()).get("annotations", []):
                value = a.get("SPDX-License-Identifier")
                if value is not None:
                    need("REUSE.toml", f"annotation for {a.get('path')}",
                         " AND ".join(value if isinstance(value, list) else [value]))
        except tomllib.TOMLDecodeError as error:
            gate.unmet("O1", "REUSE.toml", "REUSE.toml", f"not valid TOML: {error}")
    for path in tracked(rec):
        if path == "REUSE.toml":
            continue
        try:
            data = (rec.root / path).read_bytes()
        except OSError:
            continue
        if is_binary(data):
            continue
        for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            tag = LICENCE_TAG.search(line)
            if tag:
                need(f"{path}:{n}", f"licence tag in {path}", tag.group(1))
    for artifact, rows in resolved:
        declared = {c["name"]: c for c in artifact.get("component", [])}
        for row in rows:
            if row["component"] in declared:
                if declared[row["component"]].get("license"):
                    need(f"provenance/config.toml [{artifact['name']}]", row["component"], declared[row["component"]]["license"])
            elif row["use"] in ("linked", "compiler-input") and row["elected"] != "n/a" and row["license"] \
                    and not row["license"].startswith("file:"):
                need(f"{artifact['name']} closure", f"{row['component']} {row['version']}", row["license"],
                     cargo=row["origin"] in ("registry", "toolchain"))
    for path, (table, receipt, rows) in sorted(tables.items()):
        for expr in sorted({r.get("licence", "") for r in rows if r.get("use") == "consumed"}):
            need(path, table.get("component", path), expr)


# ---------------------------------------------------------------- the gate

def licence_gate(rec, full=False, peer=None, release=None, nested=False):
    """Check the gating obligations (O1 strict expression parsing with the
    verified wheels; G3 exact byte comparisons) and, only if they hold, judge
    every licence the records name by scope: the shipped closure
    (distribution), the rest of the repository (inventory), host tools. The
    report-only obligations (O2-O5, collector completeness, SPDX database
    consistency) are run where the tool can, their detections are listed,
    and every one of them is printed UNVERIFIED on every run: no PASS
    implies them."""
    policy = rec.config.get("licence_policy") or {}
    gate = LicenceGate(full)
    gate.peer = peer
    gate.artifacts = [a["name"] for a in rec.config.get("artifact", []) if a.get("distributed")]
    # Owner requirements the gate does not verify stay OPEN on every run:
    # reporting an obligation never waives them.
    tables_here = {t.get("path"): t.get("artifact") for t in policy.get("member_table", [])}
    for a in (policy.get("accepted") or []):
        if a.get("acknowledgement") and tables_here.get(a.get("member_table")) in gate.artifacts:
            gate.open.append(("release-document acknowledgements",
                              f"release documentation must carry \"{a['acknowledgement']}\" ({a['licence']}; owner "
                              "decision, provenance/obligations.toml LIC-PICOLIBC-NOTICES); not verified by the gate"))
    if not policy.get("allowed") or not policy.get("denied"):
        gate.unmet("O1", "provenance/config.toml", "licence policy", "no [licence_policy] with allowed and denied lists")
        return gate
    # Preconditions: nothing below judges a licence.
    if not pre_spdx(policy, gate):
        return gate
    exceptions, elections, accepted = pre_identities(rec, policy, gate)
    resolved = closure_resolution(rec, policy, gate)
    pre_crates(rec, policy, resolved, gate)
    tables = pre_member_tables(rec, policy, accepted, gate)
    exempt = licence_exemptions(rec, policy, gate, tables)
    pre_notices(rec, policy, tables, accepted, gate)
    pre_expressions(rec, policy, resolved, tables, gate)
    held = pre_comparisons(rec, policy, gate, peer, release) if not nested else {}
    if gate.blocking():
        gate.closure["evaluation"] = "not made: a proof obligation is unmet"
        return gate
    # Evaluation.
    files = tracked(rec)
    closure = licence_closure(rec, policy, resolved, tables, exceptions, elections, accepted, gate, held)
    licence_gate_rules(rec, policy, exceptions, gate)
    licence_gate_reuse(rec, policy, exceptions, elections, gate)
    licence_gate_locks(rec, policy, elections, files, closure, gate)
    licence_gate_pins(rec, policy, gate)
    licence_gate_markers(rec, policy, exceptions, elections, files, gate, exempt)
    licence_gate_outside(rec, policy, gate)
    gate.closure["tracked files (published source tree)"] = len(files)
    return gate


def licence_closure(rec, policy, resolved, tables, exceptions, elections, accepted, gate, held):
    """Judge the shipped closure the preconditions resolved and verified:
    every package the distributed artifacts' units can link (every normal
    dependency of a package, not only those a binary's source names: this
    licence closure is wider than the notice inventory), every declared
    component, every row of a bound member table. Returns {(component,
    version)} of the closure's packages."""
    closure, counts = set(), {"rows": 0, "components": 0, "member rows": 0}
    for artifact in rec.config.get("artifact", []):
        if "distributed" in artifact and not artifact["distributed"]:
            where = f"provenance/config.toml [{artifact['name']}]"
            for c in artifact.get("component", []):
                ok, taken, why = judge_licence(c.get("license", ""), policy)
                gate.report("allowed" if ok else ("pending" if "pending" in why else "denied" if "denied" in why
                                                  else "not-allowed"),
                            where, f"{c['name']} {c.get('version', '')}".strip(), c.get("license", "") or "(none)",
                            "component of an artifact that is not distributed" + (f"; {why}" if why else ""))
    for artifact, rows in resolved:
        where = f"provenance/config.toml [{artifact['name']}]"
        declared = {c["name"]: c for c in artifact.get("component", [])}
        for row in rows:
            component = f"{row['component']} {row['version']}".strip()
            if row["component"] in declared:
                c = declared[row["component"]]
                if c.get("use") == "variant":
                    continue
                counts["components"] += 1
                licence_component(rec, c, artifact["name"], where, policy, exceptions, elections, gate, held, tables)
                continue
            if row["use"] not in ("linked", "compiler-input") or row["elected"] == "n/a":
                continue
            counts["rows"] += 1
            closure.add((row["component"], row["version"]))
            source = f"{artifact['name']} closure ({row['origin']}, {row['use']})"
            if row["elected"] in ("UNKNOWN", "UNDECLARED") or not row["license"] or row["license"].startswith("file:"):
                gate.unknown_input(source, component, "licence not read: " + (row["license"] or row["elected"]))
                continue
            ok, taken, why = judge_licence(row["license"], policy, cargo=row["origin"] in ("registry", "toolchain"))
            if not ok:
                gate.fail(source, component, row["license"], why)
            else:
                licence_election(row["component"], row["version"], row["license"], taken, why, elections, gate,
                                 source, True)
        for path, (table, receipt, rows) in sorted(tables.items()):
            if table.get("artifact") == artifact["name"]:
                counts["member rows"] += licence_member_rows(table, receipt, rows, policy, elections, accepted, gate)
    gate.closure.update({"distributed artifacts": ", ".join(a["name"] for a, _ in resolved) or "none",
                         "packages": counts["rows"], "declared components": counts["components"],
                         "member-table rows": counts["member rows"]})
    return closure


def licence_member_rows(table, receipt, rows, policy, elections, accepted, gate):
    """Judge a bound member table's rows. Consumed rows are judged; probe
    rows (a dependency the preprocessor never entered) are recorded, never
    judged as source. An acceptance applies to a row only for its table,
    version and source, and, when it names inputs, only to those inputs at
    their recorded sha256. Failures are grouped by licence."""
    component = table.get("component", table["path"])
    applies = table_acceptances(table, receipt, accepted)
    bad, allowed = {}, {}
    for row in rows:
        item = f"{row.get('member')}<-{row.get('input')}"
        if row.get("use") == "probe":
            gate.add("distribution", "probe", table["path"], item, row.get("licence", ""),
                     "named by the dependency output but never entered by the preprocessor; not source")
            continue
        if row.get("use") != "consumed":
            bad.setdefault((row.get("licence", ""), f"row use {row.get('use')!r} is neither consumed nor probe"), []).append(item)
            continue
        extra = [a["licence"] for a in applies if "inputs" not in a or
                 (row.get("input") in a["inputs"] and a["input_sha256"].get(row.get("input")) == row.get("sha256"))]
        ok, taken, why = judge_licence(row.get("licence", ""), policy, extra)
        if ok and why:
            recorded = [e for e in elections if e["component"] == table.get("name") and table.get("version") in e["versions"]
                        and " ".join(e["expression"].split()) == " ".join(row["licence"].split())
                        and " ".join(e["elected"].split()) == " AND ".join(taken)]
            if not recorded:
                ok, why = False, f"election not recorded: {why}"
        if not ok:
            bad.setdefault((row.get("licence", ""), why), []).append(item)
        elif row["licence"] in extra and row["licence"] not in policy["allowed"]:
            a = next(a for a in applies if a["licence"] == row["licence"])
            gate.add("distribution", "accepted", table["path"], item, row["licence"],
                     ("interpreted as " + a["interpretation"] + "; " if a.get("interpretation") else "")
                     + f"accepted for this table, version and source: {a['decision']}")
        else:
            allowed[row["licence"]] = allowed.get(row["licence"], 0) + 1
    for (licence, why), items in sorted(bad.items()):
        if why.startswith("O1: "):
            gate.unmet("O1", table["path"], component, f"{licence}: {why[4:]}")
            continue
        members = sorted({i.split("<-")[0] for i in items})
        gate.fail(table["path"], f"{component}: {len(members)} linked member(s), {len(items)} input(s): "
                  + ", ".join(items), licence, why)
    for licence, n in sorted(allowed.items()):
        gate.ok_entry(table["path"], f"{component}: {n} consumed input row(s)", licence)
    return len(rows)


def exception_for(exceptions, component, artifact):
    """The exceptions whose identity this declared component matches exactly."""
    source = component.get("source", "")
    return [e for e in exceptions if e.get("component") == component.get("name")
            and e.get("version") == component.get("version") and artifact in e.get("artifacts", [])
            and (e.get("source") == source if e.get("source") else e.get("sha256", "\0") in source)]



def licence_election(name, version, expression, taken, why, elections, gate, where, in_closure, licence=None):
    """Record one allowed licence. An OR that also offers a denied licence
    needs a recorded election of exactly this component, version, expression
    and alternative: in the closure it fails without one."""
    elected = " AND ".join(taken)
    component = f"{name} {version}".strip()
    if not why:
        if in_closure:
            gate.ok_entry(where, component, expression, f"taken as {elected}" if elected != expression else "")
        else:
            gate.report("allowed", where, component, expression, f"taken as {elected}" if elected != expression else "")
        return
    recorded = [e for e in elections if e["component"] == name and version in e["versions"]
                and " ".join(e["expression"].split()) == " ".join(expression.split())]
    if recorded and " ".join(recorded[0]["elected"].split()) == elected:
        detail = f"elected {elected}; {recorded[0]['decision']}"
        gate.ok_entry(where, component, expression, detail) if in_closure else gate.report("elected", where, component, expression, detail)
    elif in_closure:
        gate.fail(where, component, expression, f"election not recorded: {why}; record [[licence_policy.election]] "
                  f"with component, versions, expression and elected = \"{elected}\"")
    else:
        gate.report("unrecorded-election", where, component, expression, f"would be taken as {elected}; {why}")



def member_table_licence(rows):
    """The licence a member table's consumed rows state together: each
    distinct expression once, sorted, joined by AND (an OR parenthesised)."""
    exprs = sorted({r.get("licence", "") for r in rows if r.get("use") == "consumed"})
    return " AND ".join(f"({x})" if " OR " in x or " AND " in x else x for x in exprs) if len(exprs) > 1 \
        else "".join(exprs)


def licence_component(rec, c, artifact, where, policy, exceptions, elections, gate, held, tables=None):
    """One component a distributed artifact declares. A component backed by
    a member table (member_table = PATH) is judged by that table's rows, per
    member; its `license` must be exactly the licence those rows state."""
    component = f"{c['name']} {c.get('version', '')}".strip()
    if c.get("member_table"):
        configured = next((t for t in policy.get("member_table", []) if t.get("path") == c["member_table"]), None)
        bound = (tables or {}).get(c["member_table"])
        problems = []
        if configured is None:
            problems.append(f"{c['member_table']} is not a [[licence_policy.member_table]]")
        elif bound is None:
            problems.append(f"{c['member_table']} is not bound to its sealed receipt")
        else:
            table, _, rows = bound
            derived = member_table_licence(rows)
            if table.get("artifact") != artifact:
                problems.append(f"the table belongs to artifact {table.get('artifact')}, not {artifact}")
            if table.get("name", "").lower() != c["name"].lower() or table.get("version") != c.get("version"):
                problems.append(f"the table is {table.get('name')} {table.get('version')}, not {component}")
            if c.get("license") != derived:
                problems.append(f"the component and its member table disagree: the table's consumed rows state "
                                f"\"{derived}\"")
        if problems:
            gate.fail(where, component, c.get("license") or "(none)",
                      "component backed by a member table: " + "; ".join(problems))
        else:
            gate.ok_entry(where, component, c["license"], f"the licence of {c['member_table']}'s consumed rows, "
                          "each judged per linked member there")
        return
    if c.get("cross_repository"):
        record = held.get(c["name"])
        if record:
            gate.ok_entry(where, component, "(paired audit)", f"{record['repository']} {record['commit'][:12]} "
                          f"{record['artifact']}: distribution gate PASS, inventory {record['inventory_sha256'][:12]}")
        return
    if not c.get("license") and c.get("origin") == "first-party":
        gate.fail(where, component, "(none)", "a first-party component built in another repository needs "
                  "cross_repository and a paired audit; one built here needs no component entry")
        return
    named = exception_for(exceptions, c, artifact)
    ok, taken, why = judge_licence(c.get("license", ""), policy, [e["licence"] for e in named])
    if ok and c.get("license") in [e["licence"] for e in named] and c.get("license") not in policy["allowed"]:
        e = next(e for e in named if e["licence"] == c["license"])
        gate.ok_entry(where, component, c["license"], f"exception {e['id']}: {e['scope']} ({e['decision']})")
    elif not ok:
        others = [e for e in exceptions if e.get("component") == c["name"]]
        gate.fail(where, component, c.get("license") or "(none)", why + (
            "; an exception names this component, but not this version, artifact and source identity"
            if others and not named else ""))
    else:
        licence_election(c["name"], c.get("version", ""), c["license"], taken, why, elections, gate, where, True)



def licence_gate_rules(rec, policy, exceptions, gate):
    """(source tree) Every provenance.toml rule: its licence, its upstream's
    licence and any first-party portion, judged for each of its paths, so an
    exception naming one path never covers another. Adapted material keeps
    its upstream's terms: its own `license` must be exactly its
    `upstream-license`, and a denied upstream fails whatever the label says.
    A recorded `decision` does not waive either."""
    text = (rec.root / "provenance.toml").read_text()
    lines = [n for n, line in enumerate(text.splitlines(), 1) if line.strip() == "[[files]]"]
    for index, (_, rule) in enumerate(rec.rules.entries):
        paths = rule["path"] if isinstance(rule["path"], list) else [rule["path"]]
        where = f"provenance.toml:{lines[index] if index < len(lines) else '?'}"
        origin = f" [{rule['origin'][:90]}]" if rule.get("origin") else ""
        for path in paths:
            component = path + origin
            extra = [e["licence"] for e in exceptions if path in e.get("paths", [])]
            for field in ("license", "upstream-license", "first-party-portion"):
                value = rule.get(field)
                if value is None or value == "pending":
                    continue
                ok, _, why = judge_licence(value, policy, extra)
                if ok and value in extra and value not in policy["allowed"]:
                    gate.ok_entry(where, component, value, f"{field}; under a named exception for this exact path")
                elif ok and why:
                    gate.fail(where, component, f"{field} = {value}", "a file's recorded terms must not offer a denied "
                              f"alternative; record the alternative taken ({why})")
                elif not ok:
                    label = rule.get("license", "")
                    note = (f"; {rule['class']} material keeps its upstream terms, so the label \"{label}\" does not "
                            "apply to it" if field == "upstream-license" and rule.get("class") != "first-party" else "")
                    note += "; a recorded decision does not waive the policy" if rule.get("decision") else ""
                    gate.fail(where, component, f"{field} = {value}" + (f" (labelled {label})" if field != "license" else ""),
                              why + note)
                else:
                    gate.ok_entry(where, component, value, field)
            upstream = rule.get("upstream-license")
            if upstream and rule.get("license") not in (None, "pending") and " ".join(rule["license"].split()) != " ".join(upstream.split()):
                if rule.get("class") == "adapted":
                    gate.fail(where, component, f"license = {rule['license']}, upstream-license = {upstream}",
                              "derived code is labelled with terms other than its upstream's; set license to the "
                              "upstream's terms and give ABSD's own lines as first-party-portion")
                else:
                    gate.add("distribution", "note", where, component, rule["license"],
                             f"{rule.get('class')} from {upstream} material, labelled {rule['license']}")



def licence_gate_reuse(rec, policy, exceptions, elections, gate):
    """(source tree) REUSE.toml annotations, judged from the parsed file for
    each path they annotate: a value is a licence statement however the TOML
    spells its key."""
    path = rec.root / "REUSE.toml"
    if not path.is_file():
        return
    try:
        doc = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as error:
        gate.fail("REUSE.toml", "REUSE.toml", "", f"not valid TOML: {error}")
        return
    lines = [n for n, line in enumerate(path.read_text().splitlines(), 1) if line.strip() == "[[annotations]]"]
    for index, a in enumerate(doc.get("annotations", [])):
        value = a.get("SPDX-License-Identifier")
        if value is None:
            continue
        expr = " AND ".join(" ".join(v.split()) for v in (value if isinstance(value, list) else [value]))
        where = f"REUSE.toml:{lines[index] if index < len(lines) else '?'}"
        for target in (a["path"] if isinstance(a.get("path"), list) else [a.get("path", "")]):
            extra = [e["licence"] for e in exceptions if target in e.get("paths", [])]
            ok, taken, why = judge_licence(expr, policy, extra)
            if not ok:
                gate.fail(where, f"annotation for {target}", expr, "licence annotation: " + why)
            else:
                licence_election(f"file:{target}", "", expr, taken, why, elections, gate, where, True)



def licence_gate_locks(rec, policy, elections, files, closure, gate):
    """(inventory) Every package of every lock file an artifact unit names (a
    unit's {crate}/{version} template stands for every tracked lock it
    matches) that is not in the shipped closure, read from the registry
    cache: dormant, optional, build-time, test-only and expected-fail
    dependencies. Every entry is listed, allowed ones included."""
    units = []
    for artifact in rec.config.get("artifact", []):
        for unit in artifact.get("unit", []):
            if "lock" in unit:
                pattern = re.sub(r"\{[a-z]+\}", "*", unit["lock"])
                for lock in sorted(f for f in files if fnmatch.fnmatchcase(f, pattern)) or [unit["lock"]]:
                    units.append((lock, unit))
    uses = {}
    for artifact in rec.config.get("artifact", []):
        path = rec.root / f"provenance/inventory/{artifact['name']}.tsv"
        if path.exists():
            for row in parse_tsv(path.read_text()):
                uses.setdefault((row.get("component"), row.get("version")), set()).add(f"{artifact['name']}:{row.get('use')}")
    local = set()
    for f in files:
        if f == "Cargo.toml" or f.endswith("/Cargo.toml"):
            try:
                local.add(tomllib.loads((rec.root / f).read_text()).get("package", {}).get("name"))
            except (tomllib.TOMLDecodeError, OSError):
                pass
    regs = registries(rec.config)
    owners = rec.config.get("policy", {}).get("owner_projects", [])
    toolchains, seen = {}, {}
    for lock, unit in units:
        if not (rec.root / lock).exists():
            gate.report("unknown", lock, lock, "", "lock file missing")
            continue
        sources = None
        if "sources" in unit:
            key = unit["sources"]
            if key not in toolchains:
                base = Path(os.path.realpath(expand(key)))
                found = {}
                for manifest in (base.rglob("Cargo.toml") if base.is_dir() else []):
                    try:
                        pkg = tomllib.loads(manifest.read_text()).get("package", {})
                    except (tomllib.TOMLDecodeError, OSError):
                        continue
                    if isinstance(pkg.get("name"), str):
                        found.setdefault(pkg["name"], manifest)
                toolchains[key] = found
            sources = toolchains[key]
        for p in tomllib.loads((rec.root / lock).read_text()).get("package", []):
            name, version, source = p["name"], p["version"], p.get("source", "")
            seen.setdefault((name, version), {"locks": [], "units": set(), "source": source, "sources": sources})
            seen[(name, version)]["locks"].append(lock)
            seen[(name, version)]["units"].add(unit["name"])
    reported = 0
    for (name, version), info in sorted(seen.items()):
        if (name, version) in closure:
            continue
        where = info["locks"][0] + (f" (+{len(info['locks']) - 1} lock(s))" if len(info["locks"]) > 1 else "")
        component = f"{name} {version}"
        use = ", ".join(sorted(uses.get((name, version), []))) or "unit " + ", ".join(sorted(info["units"]))
        manifest = None
        for registry in regs:
            candidate = Path(registry) / f"{name}-{version}" / "Cargo.toml"
            if candidate.exists():
                manifest = candidate
                break
        source = info["source"]
        if manifest is None and not source:
            if name in local or match(name, owners):
                gate.report("first-party", where, component, "", f"this repository's crate (its files are judged as source) or an owner project's ({use})")
                continue
            if info["sources"] is not None and name in info["sources"]:
                manifest = info["sources"][name]
            else:
                gate.report("unknown", where, component, "", f"no source line and not in the crate registry cache ({use})")
                continue
        if manifest is None:
            gate.report("unknown", where, component, "", f"not in the crate registry cache ({use})")
            continue
        try:
            m = Manifest(manifest)
        except (tomllib.TOMLDecodeError, OSError) as error:
            gate.report("unknown", where, component, "", f"manifest unreadable: {error}")
            continue
        reported += 1
        if not m.license:
            gate.report("unknown", where, component, "", f"manifest declares no licence expression ({use})")
            continue
        ok, taken, why = judge_licence(m.license, policy, cargo=True)
        if not ok:
            gate.report("pending" if "pending" in why else "denied" if "denied" in why else "not-allowed",
                        where, component, m.license, f"{why} ({use})")
        else:
            licence_election(name, version, m.license, taken, why, elections, gate, where, False)
    gate.closure["lock packages outside the closure read"] = reported



def licence_gate_pins(rec, policy, gate):
    """(inventory) Pinned upstream inputs that are not Cargo crates: the pin
    table's licence column, or a licence the policy records for that row with
    its evidence. Shipped C code is in the closure through the inventory's C
    port rows and the member tables, not through these rows."""
    for pin in policy.get("pin", []):
        path = rec.root / pin["path"]
        if not path.exists():
            gate.report("unknown", pin["path"], pin["path"], "", "pin table named by [licence_policy] is missing")
            continue
        column, recorded = pin.get("licence_column"), pin.get("licences", {})
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if not line.strip() or line.startswith("#"):
                continue
            f = line.split("\t")
            component = " ".join(f[:2])
            licence = (f[column - 1] if column and len(f) >= column else "") or recorded.get(component, "")
            if not licence:
                gate.report("unknown", f"{pin['path']}:{n}", component, "", "pin table records no licence")
                continue
            ok, _, why = judge_licence(licence, policy)
            status = ("allowed" if ok and not why else "unrecorded-election" if ok else
                      "pending" if "pending" in why else "denied" if "denied" in why else "not-allowed")
            gate.report(status, f"{pin['path']}:{n}", component, licence, why)



def licence_gate_outside(rec, policy, gate):
    """(host, inventory) Host tools, and artifacts held out of distribution."""
    for t in policy_entries(policy, gate, "host_tool", ("name", "licence", "use", "obligation")):
        gate.add("host", "host-tool", "provenance/config.toml", t["name"], t["licence"],
                 f"{t['use']}; obligation: {t['obligation']}")
    for h in policy_entries(policy, gate, "held", ("name", "licence", "reason", "decision")):
        gate.report("held", "provenance/config.toml", h["name"], h["licence"], f"{h['reason']} ({h['decision']})")



def licence_exemptions(rec, policy, gate, tables=None):
    """marker_exempt entries. A whole-file exemption is for a record the gate
    reads structurally (record = true) or a document; a source file names its
    reviewed lines and their exact text (lines = { "7" = "..." }); a verbatim
    upstream notice names its pinned upstream (verbatim_upstream_exemption).
    An entry that does not hold is dropped, so the file's wording is judged."""
    out = []
    for e in policy.get("marker_exempt", []):
        if not e.get("path") or not e.get("reason"):
            gate.unmet("O3", "provenance/config.toml", "licence_policy marker_exempt", "an exemption needs a path and a reason")
            continue
        if "upstream" in e:
            if verbatim_upstream_exemption(rec, policy, e, gate, tables):
                out.append(e)
            continue
        if not e.get("record") and not e.get("lines") and not e["path"].endswith(DOCUMENT_SUFFIXES):
            gate.unmet("O3", "provenance/config.toml", f"marker_exempt {e['path']}", "a whole-file wording exemption is "
                       "for records and documents; for a source file name the reviewed lines and their text")
            continue
        out.append(e)
    return out


def notice_references(rec, policy, path):
    """Tracked text files, other than provenance records and documents, that
    name PATH: as written from the repository root, or relative to the
    referring file's own directory. A cheap build-input check (a Makefile
    `include`, a script, a manifest); it does not see a path assembled at
    run time, a glob, or an input named only by a tool's search path."""
    records = [e["path"] for e in policy.get("marker_exempt", []) if e.get("record")]
    hits = []
    for other in tracked(rec):
        if other == path or other in ("provenance.toml", "REUSE.toml") or other.startswith("provenance/") \
                or other.endswith(DOCUMENT_SUFFIXES) or match(other, records):
            continue
        try:
            data = (rec.root / other).read_bytes()
        except OSError:
            continue
        if is_binary(data):
            continue
        text = data.decode("utf-8", "replace")
        relative = os.path.relpath(path, os.path.dirname(other) or ".")
        if path in text or ("/" in relative and relative in text):
            hits.append(other)
    return hits


def verbatim_upstream_exemption(rec, policy, e, gate, tables=None):
    """A wording exemption for one exact, reviewed notice identity (owner
    decision 2026-11-01): path, the file's sha256, the PIN row, the
    archive's sha256 and the member, with a decision. It does not tell
    notices from source: the guarantee is "this exact reviewed file", and a
    new or changed tuple is a reviewed configuration change. It holds only
    when the path (and no parent directory) is a symlink, the file is the
    recorded sha256, the pin file pins the archive, the archive is on this
    machine with the member equal to the file byte for byte, the file is
    classified imported and declared as a distributed component's notice,
    it is no pin or member table, nor a consumed input of one, and no
    tracked file other than records and documents names it
    (notice_references). Licence tags in the file are still judged. A byte
    mismatch is G3; anything else is O3 and grants nothing, so the file's
    wording is judged."""
    path, up = e["path"], e.get("upstream")
    subject = f"marker_exempt {path}"
    fields = ("pin", "pin_row", "archive_sha256", "member", "sha256")
    problems = []
    if not isinstance(up, dict) or not all(isinstance(up.get(f), str) and up.get(f) for f in fields):
        problems.append(f"a verbatim upstream notice names upstream {{ {', '.join(fields)} }}")
        up = {}
    elif not (HEX64.fullmatch(up["sha256"]) and HEX64.fullmatch(up["archive_sha256"])) \
            or len(up["pin_row"].split()) != 2:
        problems.append("sha256 and archive_sha256 must be sha256s and pin_row \"NAME VERSION\"")
    if not e.get("decision"):
        problems.append("a verbatim upstream notice exemption records the owner's decision")
    if e.get("record") or e.get("lines"):
        problems.append("a verbatim upstream notice exemption is neither a record nor a line review")
    if any(ch in path for ch in "*?[]") or path.startswith("/") or ".." in path.split("/"):
        problems.append("a verbatim upstream notice exemption names one exact repository path")
    else:
        parts = path.split("/")
        for n in range(1, len(parts) + 1):
            try:
                if stat.S_ISLNK(os.lstat(rec.root.joinpath(*parts[:n])).st_mode):
                    problems.append(f"{'/'.join(parts[:n])} is a symlink: a verbatim upstream notice is a regular "
                                    "file reached without links")
                    break
            except OSError:
                break
    rule = rec.rules.match(path) or {}
    if rule.get("class") != "imported":
        problems.append(f"a verbatim upstream notice is classified imported in provenance.toml, not "
                        f"{rule.get('class', 'unclassified')}")
    table_files = {t.get(k) for t in policy.get("member_table", []) for k in ("path", "receipt", "notice", "labels")}
    table_files |= {p.get("path") for p in policy.get("pin", [])}
    if path in table_files or path.startswith("LICENSES/"):
        problems.append("a pin or member table, a table's receipt, notice or labels, or a licence text is not a "
                        "verbatim upstream notice")
    inner = str(up.get("member", "")).split("/", 1)[-1]
    consumed = {r.get("input") for _, _, rows in (tables or {}).values() for r in rows if r.get("use") == "consumed"}
    if path in consumed or inner in consumed:
        problems.append("the file or its archive member is a consumed input of a member table: source, not a notice")
    notices = {n for a in rec.config.get("artifact", []) if a.get("distributed")
               for c in a.get("component", []) for n in c.get("notice_files", [])}
    if path not in notices:
        problems.append("the path is not a notice file of a distributed artifact's component")
    referring = notice_references(rec, policy, path)
    if referring:
        problems.append(f"named by {', '.join(referring[:5])}: a file another tracked file names may be a build "
                        "input, not only a notice")
    if problems:
        for p in problems:
            gate.unmet("O3", "provenance/config.toml", subject, p)
        return False
    file = rec.root / path
    data = file.read_bytes() if file.is_file() else None
    if data is None or hashlib.sha256(data).hexdigest() != up["sha256"]:
        gate.unmet("G3", path, subject, "the file differs from the sha256 its verbatim upstream exemption pins"
                   if data is not None else "the exempted notice file is missing")
        return False
    name, version = up["pin_row"].split()
    pin = rec.root / up["pin"]
    rows = [line.split("\t") for line in (pin.read_text().splitlines() if pin.is_file() else [])
            if line.strip() and not line.startswith("#")]
    if not any(r[:3] == [name, version, up["archive_sha256"]] for r in rows):
        gate.unmet("G3", up["pin"], subject, f"no row {name} {version} pins archive sha256 {up['archive_sha256'][:12]}")
        return False
    candidates = [os.environ.get(f"ABSD_SOURCE_ARCHIVE_{name.upper()}", "")]
    candidates += [str(expand(p, rec.root)) for p in up.get("source_archives", [])]
    archive = next((Path(c) for c in candidates if c and Path(c).is_file()
                    and hashlib.sha256(Path(c).read_bytes()).hexdigest() == up["archive_sha256"]), None)
    if archive is None:
        gate.unmet("O3", path, subject, f"the pinned archive ({name} {version}, sha256 {up['archive_sha256'][:12]}) is "
                   f"not on this machine (source_archives or $ABSD_SOURCE_ARCHIVE_{name.upper()}): the file is not "
                   f"verified as {up['member']}, so no exemption is granted and its wording is judged")
        return False
    with tarfile.open(archive) as t:
        try:
            member = t.getmember(up["member"])
            body = t.extractfile(member).read() if member.isfile() else None
        except KeyError:
            body = None
    if body != data:
        gate.unmet("G3", path, subject, f"the file is not {up['member']} of the pinned archive "
                   + ("(no such member)" if body is None else "byte for byte"))
        return False
    return True


def licence_gate_markers(rec, policy, exceptions, elections, files, gate, exempt):
    """(source tree) Licence tags and copyleft wording in tracked files. A
    licence tag is judged in every file, before any exemption: it states a
    file's licence. Wording is not judged in: records the gate reads
    structurally and documents that only discuss licences (marker_exempt,
    their wording listed in the inventory instead), reviewed lines of a
    source file, pin and member tables, licence texts under LICENSES/ for
    allowed terms, and a named exception's exact paths for the wording
    families it lists."""
    used = set()
    allowed_ids = {leaf for term in policy["allowed"] + [e["licence"] for e in exceptions]
                   for leaf in re.findall(r"[A-Za-z0-9.+-]+", term) if leaf not in ("WITH", "AND", "OR")}
    tables = [p["path"] for p in policy.get("pin", []) + policy.get("member_table", [])]
    for path in files:
        try:
            data = (rec.root / path).read_bytes()
        except OSError:
            continue
        if is_binary(data):
            continue
        hit = next((i for i, e in enumerate(exempt) if match(path, [e["path"]])), None)
        if hit is not None:
            used.add(hit)
        reviewed = {int(k): v for k, v in exempt[hit].get("lines", {}).items()} if hit is not None else {}
        wording = not (path.startswith("LICENSES/") and path.endswith(".txt") and path[9:-4] in allowed_ids) \
            and path not in tables
        covering = [e for e in exceptions if path in e.get("paths", [])]
        families = {f for e in covering for f in e.get("markers", [])}
        rule = rec.rules.match(path) or {}
        recorded = rule.get("upstream-license") or rule.get("license", "unclassified")
        lines = data.decode("utf-8", "replace").splitlines()
        for n, text in reviewed.items():
            if n > len(lines) or lines[n - 1].strip() != text.strip():
                gate.unmet("O3", f"{path}:{n}", f"marker_exempt {path}", "the reviewed line of a wording "
                           "exemption changed: review it again and record its text")
        for n, line in enumerate(lines, 1):
            tag = LICENCE_TAG.search(line) if path != "REUSE.toml" else None
            if tag:
                ok, taken, why = judge_licence(tag.group(1), policy, [e["licence"] for e in covering])
                if not ok:
                    gate.fail(f"{path}:{n}", f"file recorded as {recorded}", tag.group(1), "licence tag: " + why)
                else:
                    licence_election(f"file:{path}", "", tag.group(1), taken, why, elections, gate, f"{path}:{n}", True)
                continue
            if not wording:
                continue
            for family, rx in LICENCE_MARKERS:
                if rx.search(line):
                    if family in families:
                        gate.ok_entry(f"{path}:{n}", f"{family} wording", "", "under exception "
                                      + ", ".join(e["id"] for e in covering))
                    elif hit is not None and (n in reviewed or not exempt[hit].get("lines")):
                        if "upstream" in exempt[hit]:
                            up = exempt[hit]["upstream"]
                            gate.report("verbatim-notice", f"{path}:{n}", f"file recorded as {recorded}",
                                        f"{family} wording", f"{up['member']} of {up['pin_row']} ({up['pin']}), "
                                        f"sha256 {up['sha256'][:12]}: {exempt[hit]['reason']}")
                        elif not exempt[hit].get("record"):
                            gate.report("discussion", f"{path}:{n}", f"file recorded as {recorded}", f"{family} wording",
                                        exempt[hit]["reason"])
                    else:
                        gate.fail(f"{path}:{n}", f"file recorded as {recorded}", f"{family} wording: "
                                  f"\"{line.strip()[:110]}\"", "copyleft licence marker outside the named exceptions")
                    break
    for i, e in enumerate(exempt):
        if i not in used:
            gate.add("distribution", "note", "provenance/config.toml", f"marker_exempt {e['path']}", "",
                     "matches no tracked text file")



# ---------------------------------------------------------------- crate identity

def crate_archives(rec, policy):
    """A checker (name, version, lock checksum) -> problem or None. A
    registry crate's licence is read from its source directory; that
    directory's manifest must equal the manifest inside the crate archive, and
    the archive's sha256 must equal the lock's checksum, or for a lock root
    or staged copy (no checksum in the lock) the checksum the policy records
    from its pin ([licence_policy.crate_checksums]). Archives are found in
    Cargo's registry cache beside each source directory and in
    $ABSD_CRATE_ARCHIVES."""
    dirs = [p for p in os.environ.get("ABSD_CRATE_ARCHIVES", "").split(os.pathsep) if p]
    for src in registries(rec.config):
        dirs.append(str(Path(src).parent.parent / "cache" / Path(src).name))
    pinned = policy.get("crate_checksums", {})
    cache = {}

    def check(name, version, checksum):
        key = (name, version, checksum)
        if key in cache:
            return cache[key]
        want = checksum
        problem = None
        if not re.fullmatch(r"[0-9a-f]{64}", want or ""):
            problem = "no lock checksum and no pinned checksum ([licence_policy.crate_checksums])"
        else:
            archive = next((Path(d) / f"{name}-{version}.crate" for d in dirs
                            if (Path(d) / f"{name}-{version}.crate").is_file()), None)
            if archive is None:
                problem = "crate archive not found (Cargo's registry cache or $ABSD_CRATE_ARCHIVES)"
            else:
                data = archive.read_bytes()
                if hashlib.sha256(data).hexdigest() != want:
                    problem = f"{archive}: sha256 differs from the checksum the lock or pin records"
                else:
                    try:
                        with tarfile.open(fileobj=io.BytesIO(data)) as t:
                            inside = t.extractfile(f"{name}-{version}/Cargo.toml").read()
                    except (KeyError, tarfile.TarError, AttributeError):
                        inside = None
                    local = next((Path(r) / f"{name}-{version}" / "Cargo.toml" for r in registries(rec.config)
                                  if (Path(r) / f"{name}-{version}" / "Cargo.toml").is_file()), None)
                    if inside is None or local is None or local.read_bytes() != inside:
                        problem = "the crate source's manifest differs from the verified archive's"
        cache[key] = problem
        return problem
    return check



# ---------------------------------------------------------------- shared tools

def shared_tool_checks(rec, out, peer=None):
    """The provenance tools are one implementation shared by the kernel and
    platform repositories. Each one present here must be pinned in
    [shared_tools.sha256] and match its pin; the pin set must be exactly the
    tools present. With PEER (the other repository's checkout) the peer's
    files and pins must equal these: an update made in one repository alone
    does not pass a paired run. [shared_tools] peer_required = true makes
    `full` refuse to pass without one."""
    present = [t for t in SHARED_TOOLS if (rec.root / t).is_file()]
    pins = rec.config.get("shared_tools", {}).get("sha256", {})
    if present and sorted(pins) != sorted(present):
        out.add("COMPLIANCE_ACTION_REQUIRED", "provenance/config.toml", "[shared_tools.sha256] must pin exactly the "
                f"shared provenance tools present ({', '.join(present)}); it pins {', '.join(sorted(pins)) or 'none'}",
                "pin every shared tool, in both repositories")
    for name, want in sorted(pins.items()):
        path = rec.root / name
        got = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "missing"
        if got != want:
            out.add("COMPLIANCE_ACTION_REQUIRED", name, f"shared provenance tool differs from its pinned identity "
                    f"({got[:12]}, pinned {want[:12]})", "change the file in both repositories together and update "
                    "[shared_tools] in both provenance/config.toml files")
    if peer:
        other = Path(peer)
        try:
            theirs = tomllib.loads((other / "provenance/config.toml").read_text()).get("shared_tools", {}).get("sha256", {})
        except (OSError, tomllib.TOMLDecodeError) as error:
            out.add("COMPLIANCE_ACTION_REQUIRED", str(other), f"peer repository unreadable: {error}", "")
            return
        if theirs != pins:
            out.add("COMPLIANCE_ACTION_REQUIRED", "provenance/config.toml", f"the peer {other} pins other shared tools",
                    "update both repositories together")
        for name in SHARED_TOOLS:
            mine = rec.root / name
            yours = other / name
            if mine.is_file() != yours.is_file() or (mine.is_file() and mine.read_bytes() != yours.read_bytes()):
                out.add("COMPLIANCE_ACTION_REQUIRED", name, f"differs from the peer's {yours}", "update both together")
        out.note(f"shared tools compared with the peer {other}")
    elif rec.config.get("shared_tools", {}).get("peer_required") and getattr(out, "full", False):
        out.add("COMPLIANCE_ACTION_REQUIRED", "provenance/config.toml", "full needs the paired repository: give "
                "--peer DIR or $ABSD_PROVENANCE_PEER", "rerun with the other repository's checkout")



# ---------------------------------------------------------------- notices

def notices(rec, name, out_dir, quiet=False):
    artifact = next((a for a in rec.config.get("artifact", []) if a["name"] == name), None)
    if artifact is None:
        raise Problem(f"no artifact named {name}")
    rows, notes = inventory(rec, artifact)
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / "licenses").mkdir(parents=True)
    regs = registries(rec.config)
    index, missing, actions = [], [], []
    destinations, folded = {}, {}

    def copy_notice(src, target, metadata=False):
        src, target = Path(src), Path(target)
        identity = src.resolve()
        if target in destinations and destinations[target] != identity:
            raise Problem(f"notice destination collision at {target.relative_to(out_dir)}: "
                          f"{destinations[target]} and {identity}")
        destinations[target] = identity
        # Paths that differ only in case are one path on a case-insensitive
        # file system: refuse them as the same destination.
        rel = target.relative_to(out_dir)
        for part in [rel, *rel.parents][:-1]:
            if folded.setdefault(part.as_posix().lower(), part.as_posix()) != part.as_posix():
                raise Problem(f"notice destination collision at {part.as_posix()}: differs only in case from "
                              f"{folded[part.as_posix().lower()]}")
        return (shutil.copy2 if metadata else shutil.copyfile)(src, target)

    extras = {e["name"]: e for e in artifact.get("component", [])}
    toolchains = {u["name"]: u for u in artifact.get("unit", []) if "notice_files" in u}
    for row in rows:
        if not shipped(row):
            continue
        ident = f"{row['component']}-{row['version']}".rstrip("-")
        sources = []
        if row["component"] in extras:
            extra = extras[row["component"]]
            sources = [expand(p, rec.root) for p in extra.get("notice_files", [])]
            actions += [f"{row['component']}: {a}" for a in extra.get("actions", [])]
        elif row["origin"] == "registry":
            for registry in regs:
                d = Path(registry) / ident
                sources = [d / n for n in license_files(d)]
                if d.exists():
                    break
        elif row["origin"] == "vendored":
            d = rec.root / row["source"]
            sources = [d / n for n in license_files(d)]
        elif row["origin"] == "toolchain":
            for unit in toolchains.values():
                if row["units"] & {unit["name"]} if isinstance(row["units"], set) else unit["name"] in row["units"]:
                    sources = [expand(p) for p in unit["notice_files"]]
            ident = "rust-standard-library"
        elif row["origin"] == "upstream-tarball":
            sources = [expand(p, rec.root) for p in row["_notice_files"]]
        copied = []
        absent = [str(src) for src in sources if not src.exists()]
        if absent:
            missing.append(f"{row['component']} {row['version']}: configured notice file(s) not on this machine: "
                           + ", ".join(absent))
        for src in sources:
            if src.is_dir():
                shutil.copytree(src, out_dir / "licenses" / ident / src.name, dirs_exist_ok=True,
                                copy_function=lambda a, b: copy_notice(a, b, metadata=True))
                copied.append(src.name + "/")
            elif src.is_file():
                rel = Path(src.name)
                for base in [Path(r) / ident for r in regs] + ([rec.root / row["source"]] if row["origin"] == "vendored" else []):
                    if base in src.parents:
                        rel = src.relative_to(base)
                (out_dir / "licenses" / ident / rel).parent.mkdir(parents=True, exist_ok=True)
                copy_notice(src, out_dir / "licenses" / ident / rel)
                copied.append(rel.as_posix())
        stated = extras.get(row["component"], {}).get("texts")
        if not copied and not absent and not stated:
            missing.append(f"{row['component']} {row['version']} ({row['license'] or 'no licence declared'}): "
                           "no licence text found in its source; obtain it from upstream")
        index.append(f"| {row['component']} | {row['version']} | {row['origin']} | {row['license']} | "
                     f"{row['elected']} | " + (f"{row['use']} | " if artifact.get("_compiler_coverage") else "") +
                     f"{', '.join(copied) or stated or 'MISSING'} |")
    intree = []
    files = tracked(rec)
    for d in rec.declarations:
        present = any(rec.rules.match(f) is d["rule"] for f in files)
        if present and d["kind"] in THIRD_PARTY and d["in_artifacts"] is not None and name in d["in_artifacts"]:
            actions += [f"{d['id']} ({d['origin']}): {a}" for a in d["binary_actions"]]
            intree.append(f"| {d['id']} | {d['origin']} | {d['license']} | {d['notice'] or 'none recorded'} |")
            for f in d["license_files"]:
                if (rec.root / f).is_file():
                    target = out_dir / "licenses" / re.sub(r"[^A-Za-z0-9._-]+", "_", d["id"])
                    target.mkdir(exist_ok=True)
                    copy_notice(rec.root / f, target / Path(f).name)
    acknowledgements = []
    for table in rec.config.get("licence_policy", {}).get("member_table", []):
        if table.get("artifact") == name and table.get("notice") and (rec.root / table["notice"]).is_file():
            target = out_dir / "licenses" / re.sub(r"[^A-Za-z0-9._-]+", "_", f"{table.get('name')}-{table.get('version')}")
            target.mkdir(exist_ok=True)
            copy_notice(rec.root / table["notice"], target / Path(table["notice"]).name)
            intree.append(f"| {table.get('component', table['path'])} | {table['path']} | per linked member | "
                          f"{table['notice']} |")
            lines = (rec.root / table["notice"]).read_text().splitlines()
            if "== ACKNOWLEDGEMENTS" in lines:
                for line in lines[lines.index("== ACKNOWLEDGEMENTS") + 1:]:
                    if not line.strip():
                        break
                    acknowledgements.append(line.strip())
    head = git("rev-parse", "HEAD", root=rec.root).strip()
    dirty = bool(git("status", "--porcelain", root=rec.root).strip())
    digest = hashlib.sha256(render(rows).encode()).hexdigest()
    text = [f"# Candidate third-party notices: {name}", "",
            f"Generated from {rec.config.get('repository', '')} {head}{' (uncommitted changes present)' if dirty else ''}.",
            f"Inventory sha256 {digest}. A bundle is valid only for the inventory it names; regenerate it",
            "when the dependency graph or the image composition changes.", "",
            "This is a candidate. Bundling these texts does not by itself satisfy every licence: the",
            "actions below (source availability, modification notices) are separate, and whether the",
            "set is sufficient is a legal judgement this tool does not make.", "",
            "Licences marked \"taken as\" record a choice among alternatives the upstream offers.", "",
            "## Actions not satisfied by this bundle", ""]
    text += [f"- {a}" for a in actions] or ["- none recorded"]
    if acknowledgements:
        text += ["", "## Acknowledgements", "", "Required by the licences of code this artifact links. Naming an "
                 "organisation acknowledges its work; it does not imply that it endorses ABSD.", ""]
        text += [f"- {a}" for a in acknowledgements]
    text += ["", "## Missing texts", ""] + ([f"- {m}" for m in missing] or ["- none"])
    text += ["", "## Unresolved inputs", ""] + ([f"- {where}: {why}" for _, where, why in notes] or ["- none"])
    text += ["", "## In-tree third-party material in this artifact (provenance.toml)", "",
             "| Material | Origin | Upstream terms | Upstream notice |", "|---|---|---|---|"] + (intree or ["| none | | | |"])
    if artifact.get("_compiler_coverage"):
        text += ["", "Compiler-input rows cover exact target compiler sources, not proven final ELF code membership.",
                 "The proc_macro upstream declaration, when derived, is bound in DOCUMENT-COMPOSITION.json rather than its Cargo manifest."]
        text += ["", "## Components", "", "| Component | Version | Origin | Upstream terms (see declaration source) | Taken as | Use | Texts |",
                 "|---|---|---|---|---|---|---|"] + index
    else:
        text += ["", "## Components", "", "| Component | Version | Origin | Declared licence | Taken as | Texts |",
                 "|---|---|---|---|---|---|"] + index
    (out_dir / "NOTICES.md").write_text("\n".join(text) + "\n")
    (out_dir / "inventory.tsv").write_text(render(rows))
    if not quiet:
        print(f"PROVENANCE NOTICES {name}: {len(index)} component(s), {len(missing)} missing text(s), "
              f"{len(actions)} further action(s); written to {out_dir}")
    return len(index), missing, actions


# ---------------------------------------------------------------- readiness

def readiness(rec, rows, findings):
    base = rec.config["baseline"]
    head = git("rev-parse", "HEAD", root=rec.root).strip()
    tree = git("rev-parse", "HEAD^{tree}", root=rec.root).strip()
    files = tracked(rec)
    changed = {p for s, p in changes(rec, base["commit"])}
    lines = [f"# Release readiness: {rec.config.get('repository', rec.root.name)}", "",
             f"Commit {head}, tree {tree}. Reviewed baseline: {base['audit']} at commit {base['commit']}.",
             "A mechanical report. It is not legal advice or clearance.", "", "## Against the reviewed baseline", ""]
    levels = {}
    for f in files:
        if f in changed:
            continue
        level = next((c["level"] for c in base.get("coverage", []) if match(f, c["paths"])), "not-reviewed")
        levels[level] = levels.get(level, 0) + 1
    third = [f for f in files if any(d.get("kind") in THIRD_PARTY for d in rec.declared(f))]
    lines.append(f"- A. Files unchanged since the baseline: {sum(levels.values())} "
                 f"({', '.join(f'{n} {k}' for k, n in sorted(levels.items()))}).")
    lines.append(f"- B. Files new or changed since the baseline, not covered by that review: "
                 f"{len([f for f in changed if f in files and f not in third])}.")
    lines.append(f"- C. In-tree third-party files (provenance.toml: imported or adapted) unchanged since the "
                 f"baseline: {len([f for f in third if f not in changed])}.")
    lines.append(f"- D. In-tree third-party files added or changed since the baseline: "
                 f"{len([f for f in third if f in changed])}"
                 + (f" ({', '.join(sorted(f for f in third if f in changed)[:8])})" if any(f in changed for f in third) else "")
                 + ".")
    lines.append(f"- E. Obligations from the baseline still open: "
                 f"{len([1 for o, _, _ in rows if o.get('status', 'open') == 'open' and o.get('origin') == base['audit']])}.")
    lines.append(f"- F. Obligations added since: "
                 f"{len([1 for o, _, _ in rows if o.get('status', 'open') == 'open' and o.get('origin') != base['audit']])}; "
                 f"new findings in this run: {len(findings.items)}.")
    lines += ["", "Coverage of the baseline review (what \"unchanged\" does and does not mean):", ""]
    lines += [f"- {c['level']}: {c['note']} ({', '.join(c['paths'])})" for c in base.get("coverage", [])]
    lines += [f"- {text}" for text in base.get("limits", [])]
    titles = {"source": "SOURCE_PUBLICATION", "binary": "BINARY_DISTRIBUTION", "site": "WEBSITE_PUBLICATION"}
    verdicts = {}
    for scope, title in titles.items():
        mine = [(o, fires, why) for o, fires, why in rows if scope in o.get("applies_to", [])
                and o.get("status", "open") == "open"]
        blocking = [x for x in mine if x[0].get("blocks", x[0].get("kind", "mechanical") in ("mechanical", "owner-decision"))]
        fresh = findings.items
        if scope == "site":
            site = rec.config.get("website")
            if not site:
                continue
            verdict = "NOT_READY" if blocking else "NO_KNOWN_BLOCKER"
            lines += ["", f"## {title}: {verdict}", "", site["statement"], ""]
        else:
            verdict = "NOT_READY" if blocking or fresh else "NO_KNOWN_BLOCKER"
            lines += ["", f"## {title}: {verdict}", ""]
            if scope == "source":
                spdx = spdx_run(rec, None, release=True)
                lines.append(f"- File-level licensing (scripts/spdx-check.py --mode release): "
                             f"{'pass' if spdx['pass'] else 'fail'}; {spdx['established']} of {spdx['files']} tracked "
                             f"files have established licensing; "
                             + ", ".join(f"{n} {c}" for c, n in spdx["counts"].items() if n) + ".")
            if scope == "binary":
                for artifact in rec.config.get("artifact", []):
                    inv, _ = inventory(rec, artifact)
                    ship = [r for r in inv if shipped(r)]
                    if artifact.get("inventoried") is False:
                        lines.append(f"- Artifact {artifact['name']}: NOT inventoried crate by crate; "
                                     f"{len(ship)} declared component(s) only.")
                        continue
                    lines.append(f"- Artifact {artifact['name']}: {len(ship)} third-party component(s) "
                                 f"({len({r['component'] for r in ship})} distinct names), inventory sha256 "
                                 f"{hashlib.sha256(render(inv).encode()).hexdigest()[:16]}, "
                                 f"{sum(1 for r in ship if r['texts'] == 'MISSING')} without a licence text in source.")
            if fresh:
                lines.append(f"- {len(fresh)} finding(s) in this run must be cleared first (see the check output).")
        verdicts[scope] = verdict
        for kind, heading in (("mechanical", "To do (mechanical)"), ("owner-decision", "Owner decisions"),
                              ("counsel", "For counsel"), ("note", "Notes, not blocking")):
            group = [x for x in mine if x[0].get("kind", "mechanical") == kind]
            if group:
                lines += ["", f"### {heading}", ""]
                for o, fires, why in group:
                    state = (f" [not checked: {why}]" if fires is None and why else "" if fires is None
                             else f" [{'holds' if fires else 'clear'}: {why}]")
                    lines.append(f"- {o['id']}: {o['title']}{state}")
    lines += ["", "\"NO_KNOWN_BLOCKER\" means no recorded obligation or mechanical finding blocks that kind of",
              "release. It does not mean the release is authorized or that its licensing has been cleared."]
    return "\n".join(lines) + "\n", verdicts


def update(rec):
    (rec.root / "provenance/inventory").mkdir(parents=True, exist_ok=True)
    for artifact in rec.config.get("artifact", []):
        rows, notes = inventory(rec, artifact)
        path = rec.root / f"provenance/inventory/{artifact['name']}.tsv"
        unknown = [r for r in rows if "UNKNOWN" in (r["elected"], r["texts"])]
        if unknown:
            raise Problem(f"{artifact['name']}: {len(unknown)} component(s) could not be read on this machine "
                          f"(first: {unknown[0]['component']} {unknown[0]['version']}); inventory not written")
        path.write_text(render(rows))
        ship = [r for r in rows if shipped(r)]
        print(f"PROVENANCE INVENTORY {artifact['name']}: {len(rows)} component(s), {len(ship)} shipped "
              f"third-party ({len({r['component'] for r in ship})} distinct names), {len(notes)} unresolved input(s)")
        for _, where, why in notes:
            print(f"  UNKNOWN  {where}: {why}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=str(ROOT), help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("check")
    p.add_argument("--base")
    p.add_argument("--peer", default=os.environ.get("ABSD_PROVENANCE_PEER"),
                   help="the other repository's checkout: compare shared tools and paired audits")
    p = sub.add_parser("full")
    p.add_argument("--out", default=None)
    p.add_argument("--release", help="a release manifest: its kernel_commit must be the incorporated revision")
    p.add_argument("--peer", default=os.environ.get("ABSD_PROVENANCE_PEER"),
                   help="the other repository's checkout: compare shared tools and paired audits")
    sub.add_parser("update")
    p = sub.add_parser("notices")
    p.add_argument("artifact")
    p.add_argument("--document-release")
    p.add_argument("--document-build-receipt")
    p.add_argument("--document-deps")
    p.add_argument("--out", required=True)
    p = sub.add_parser("report")
    p.add_argument("--require", choices=["source", "binary", "site"])
    args = parser.parse_args(argv)
    try:
        rec = Records(args.root)
        if args.command == "check":
            release = None if args.base else source_release(rec)
            if release:
                # A source release: the tree is compared with its manifest,
                # and the licence gate still runs on the tree as it is.
                same, text = release
                allowed = os.environ.get("ABSD_ALLOW_MODIFIED") == "1"
                print(f"PROVENANCE CHECK: {text}" + ("" if same or not allowed else " (ABSD_ALLOW_MODIFIED=1)"))
                gate = licence_gate(rec)
                gate.print()
                return 0 if (same or allowed) and gate.ok() else 1
            out = check(rec, args.base, args.peer)
            out.print("CHECK")
            gate = licence_gate(rec, peer=args.peer)
            gate.print()
            return 0 if out.verdict() == "UNCHANGED" and gate.ok() else 1
        if args.command == "full":
            out_dir = args.out or str(rec.root / "target/provenance")
            out, (report, _) = full(rec, out_dir, args.peer)
            out.print("FULL")
            gate = licence_gate(rec, full=True, peer=args.peer, release=args.release)
            gate.print()
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            (Path(out_dir) / "licence-report.tsv").write_text(
                "".join("\t".join(str(x).replace("\t", " ").replace("\n", " ") for x in r) + "\n" for r in gate.rows()))
            print(report)
            print(f"PROVENANCE FULL wrote {out_dir}/READINESS.md, {out_dir}/licence-report.tsv and {out_dir}/notices/")
            return 0 if out.verdict() == "UNCHANGED" and gate.ok() else 1
        if args.command == "update":
            update(rec)
            return 0
        if args.command == "notices":
            selected = any((args.document_release, args.document_build_receipt, args.document_deps))
            binding = None
            if args.artifact == rec.config.get("document_application", {}).get("artifact"):
                if not all((args.document_release, args.document_build_receipt, args.document_deps)):
                    raise Problem("document artifact needs --document-release, --document-build-receipt and --document-deps")
                binding = document_artifact(rec, args.document_release, args.document_build_receipt, args.document_deps)
            elif selected:
                raise Problem("document inputs require the document-enabled artifact")
            _, missing, _ = notices(rec, args.artifact, args.out)
            if binding is not None:
                if missing:
                    raise Problem("document notices incomplete: " + "; ".join(missing))
                (Path(args.out) / "DOCUMENT-COMPOSITION.json").write_text(json.dumps(binding, indent=2) + "\n")
            return 0
        if args.command == "report":
            out = Findings()
            files = tracked(rec)
            inventory_checks(rec, out)
            declaration_checks(rec, files, out)
            report, verdicts = readiness(rec, obligation_checks(rec, files, out), out)
            print(report)
            if args.require and verdicts.get(args.require) != "NO_KNOWN_BLOCKER":
                print(f"PROVENANCE REPORT {args.require}: NOT_READY", file=sys.stderr)
                return 1
            return 0
    except Problem as error:
        print(f"PROVENANCE UNKNOWN: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
