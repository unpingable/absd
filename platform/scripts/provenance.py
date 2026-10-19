#!/usr/bin/env python3
"""Provenance, licensing and distribution-readiness checks (docs/PROVENANCE.md).

  provenance.py check [--base REF]   fast: what a change adds to the baseline
  provenance.py full [--out DIR]     whole tree, inventory, notices, readiness
  provenance.py update               regenerate provenance/inventory/*.tsv
  provenance.py notices ARTIFACT --out DIR   candidate third-party notice bundle
  provenance.py report [--require source|binary]   release readiness

This tool owns the release-readiness decision. Per-file licensing
classification is provenance.toml at the repository root, and its validation
is scripts/spdx-check.py (docs/SOURCE-LICENSING.md): this tool runs that
check and reads that file; it does not restate either. Its own records are
under provenance/: config.toml (baseline identity, coverage, dependency
licence policy, artifacts), obligations.toml (known obligations and
decisions), inventory/ (generated dependency inventory), baseline/ (inventory
frozen at the reviewed baseline). Python standard library only; no network;
nothing is built.

A passing check is a mechanical result. It is not legal clearance, and it
does not show that unchanged code is original: the baseline's coverage limits
are printed with every full report.
"""
import argparse
import ast
import fnmatch
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
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

def license_tree(expr):
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
            pos += 1
            return node
        if pos + 1 < len(tokens) and tokens[pos].upper() == "WITH":
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

    def __init__(self, root, lock, manifest_dir, cfg, registries):
        self.root, self.cfg, self.registries = Path(root), cfg, registries
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

    def manifest(self, key):
        if key in self.cache:
            return self.cache[key]
        name, version = key
        m = None
        local = self.local.get(name) if not self.packages[key].get("source") else None
        if local is not None and self.root in local.path.parents:
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
            if m is None:
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
    env = os.environ.get("ABSD_CARGO_REGISTRY")
    if env:
        return env.split(os.pathsep)
    base = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")) / "registry/src"
    return sorted(str(p) for p in base.glob("*")) if base.exists() else []


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
        if source.startswith("registry") or in_registry:
            # A lock's own root package, and a crate patched from a staged
            # copy, carry no source line but are registry crates all the same.
            origin, ident = "registry", pkg.get("checksum", "")
        elif m is not None and root in m.path.parents:
            rel = m.path.parent.relative_to(root).as_posix()
            origin, ident = ("vendored" if any(d["kind"] == "vendored" for d in rec.declared(rel + "/Cargo.toml"))
                             else "first-party"), rel
        elif m is not None and str(m.path).startswith(str(unit.get("_sources", "\0"))):
            origin, ident = "toolchain", unit.get("source_id", "")
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
        decision = rec.policy.get("decisions", {}).get(key[0])
        if use != "linked":
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
        rank = ["not-built", "build-only", "linked"]
        if rank.index(use) > rank.index(row["use"]):
            # Linked by this unit though an earlier one only named it: take this reading.
            row.update(origin=origin, source=ident, license=declared, elected=elected, use=use,
                       texts=",".join(texts) if texts else ("" if elected == "n/a" else "UNKNOWN" if m is None else "MISSING"))
        if use != "not-built":
            row["units"].add(unit["name"])

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
            texts = ",".join(Path(f).name for f in unit.get("notice_files", [])) or "MISSING"
            for name, upstream, source_file, *_ in c_port_rows(root, unit):
                if upstream not in pins:
                    notes.append(("UNKNOWN", unit["c_ports"], f"{name}: upstream {upstream} is not a row of {unit['pin']}"))
                    continue
                version, url, digest, declared = pins[upstream]
                rows[(f"{upstream.rsplit('-', 1)[0]}-{name}", version)] = {
                    "component": f"{upstream.rsplit('-', 1)[0]}-{name}", "version": version,
                    "origin": "upstream-tarball", "source": f"{url} sha256:{digest} {source_file}",
                    "license": declared,
                    "elected": " AND ".join(elect(declared, rec.policy) or ["DECISION_REQUIRED"]) if declared
                    else "UNDECLARED",
                    "use": "linked", "units": {unit["name"]}, "texts": texts,
                }
            continue
        unit = dict(unit)
        manifest_dir = unit.get("manifest_dir", ".")
        manifest_dir = [root / d for d in manifest_dir] if isinstance(manifest_dir, list) else root / manifest_dir
        if "sources" in unit:
            unit["_sources"] = expand(unit["sources"])
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
            graph = Graph(root, lock, directory or root, cfg, regs)
            keys = graph.by_name.get(package, [])
            if len(keys) != 1:
                notes.append(("UNKNOWN", lock, f"root package {package} not unique in lock"))
                continue
            m = graph.manifest(keys[0])
            only = None
            if bins and m is not None:
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
                add(unit, key, graph, use)
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
    """Part of a distributed artifact and not ABSD's own (or, for a sibling
    checkout the policy names, the owner's own)."""
    return row["use"] in ("linked", "included") and row["elected"] != "n/a" and row["origin"] != "first-party"


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
    linked = {f"{r['component']}-{r['version']}" for r in rows if r["use"] == "linked" and r["origin"] == "registry"}
    for unit in artifact.get("unit", []):
        if "evidence" not in unit:
            continue
        directory = (rec.root / unit["evidence"]).resolve()
        files = sorted(directory.glob("*.d")) if directory.is_dir() else []
        if not files:
            out.note(f"{name}/{unit['name']}: no build output at {unit['evidence']}; inventory not compared with a build")
            continue
        compiled, text = set(), ""
        for f in files:
            text += f.read_text(errors="replace")
        compiled |= set(re.findall(r"/registry/src/[^/]+/([^/ ]+)/", text))
        mine = {f"{r['component']}-{r['version']}" for r in rows if r["use"] == "linked" and r["origin"] == "registry"
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
                    if r["license"] != old[moved[c]]["license"]:
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


def check(rec, base=None):
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


def full(rec, out_dir):
    out = Findings()
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
    extras = {e["name"]: e for e in artifact.get("component", [])}
    toolchains = {u["name"]: u for u in artifact.get("unit", []) if "notice_files" in u}
    tarballs = {u["name"]: u for u in artifact.get("unit", []) if "c_ports" in u}
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
            for unit in tarballs.values():
                if unit["name"] in row["units"]:
                    sources = [expand(p, rec.root) for p in unit.get("notice_files", [])]
        copied = []
        absent = [str(src) for src in sources if not src.exists()]
        if absent:
            missing.append(f"{row['component']} {row['version']}: configured notice file(s) not on this machine: "
                           + ", ".join(absent))
        for src in sources:
            if src.is_dir():
                shutil.copytree(src, out_dir / "licenses" / ident / src.name, dirs_exist_ok=True)
                copied.append(src.name + "/")
            elif src.is_file():
                rel = Path(src.name)
                for base in [Path(r) / ident for r in regs] + ([rec.root / row["source"]] if row["origin"] == "vendored" else []):
                    if base in src.parents:
                        rel = src.relative_to(base)
                (out_dir / "licenses" / ident / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, out_dir / "licenses" / ident / rel)
                copied.append(rel.as_posix())
        stated = extras.get(row["component"], {}).get("texts")
        if not copied and not absent and not stated:
            missing.append(f"{row['component']} {row['version']} ({row['license'] or 'no licence declared'}): "
                           "no licence text found in its source; obtain it from upstream")
        index.append(f"| {row['component']} | {row['version']} | {row['origin']} | {row['license']} | "
                     f"{row['elected']} | "
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
                    shutil.copyfile(rec.root / f, target / Path(f).name)
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
    text += ["", "## Missing texts", ""] + ([f"- {m}" for m in missing] or ["- none"])
    text += ["", "## Unresolved inputs", ""] + ([f"- {where}: {why}" for _, where, why in notes] or ["- none"])
    text += ["", "## In-tree third-party material in this artifact (provenance.toml)", "",
             "| Material | Origin | Upstream terms | Upstream notice |", "|---|---|---|---|"] + (intree or ["| none | | | |"])
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
    p = sub.add_parser("full")
    p.add_argument("--out", default=None)
    sub.add_parser("update")
    p = sub.add_parser("notices")
    p.add_argument("artifact")
    p.add_argument("--out", required=True)
    p = sub.add_parser("report")
    p.add_argument("--require", choices=["source", "binary", "site"])
    args = parser.parse_args(argv)
    try:
        rec = Records(args.root)
        if args.command == "check":
            release = None if args.base else source_release(rec)
            if release:
                same, text = release
                allowed = os.environ.get("ABSD_ALLOW_MODIFIED") == "1"
                print(f"PROVENANCE CHECK: {text}" + ("" if same or not allowed else " (ABSD_ALLOW_MODIFIED=1)"))
                return 0 if same or allowed else 1
            out = check(rec, args.base)
            out.print("CHECK")
            return 0 if out.verdict() == "UNCHANGED" else 1
        if args.command == "full":
            out_dir = args.out or str(rec.root / "target/provenance")
            out, (report, _) = full(rec, out_dir)
            out.print("FULL")
            print(report)
            print(f"PROVENANCE FULL wrote {out_dir}/READINESS.md and {out_dir}/notices/")
            return 0 if out.verdict() == "UNCHANGED" else 1
        if args.command == "update":
            update(rec)
            return 0
        if args.command == "notices":
            notices(rec, args.artifact, args.out)
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
