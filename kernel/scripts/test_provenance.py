#!/usr/bin/env python3
"""Tests for scripts/provenance.py against a small synthetic repository and
registry: no cargo, no network, a few seconds. Run: python3 scripts/test_provenance.py"""
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tarfile
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenance as pv  # noqa: E402

# The fixtures below quote licence tags and notices as test data.
# REUSE-IgnoreStart

CONFIG = """
repository = "demo"
main = "main"
[baseline]
audit = "audit-test"
commit = "BASE"
tree = "TREE"
limits = ["not a legal review"]
[[baseline.coverage]]
level = "keyword-sweep"
paths = ["*"]
note = "markers only"
[target]
triple = "x86_64-unknown-demo"
names = []
[target.values]
target_os = "demo"
target_arch = "x86_64"
[policy]
prefer = ["MIT", "Apache-2.0", "BSD-3-Clause"]
[policy.decisions]
[scan]
binary_ok = ["fixtures/*"]
path_ok = []
[[artifact]]
name = "image"
  [[artifact.unit]]
  name = "app"
  lock = "Cargo.lock"
  package = "app"
  bins = ["tool"]
  [[artifact.component]]
  name = "Bootloader"
  version = "host"
  origin = "host-package"
  license = "GPL-3.0-or-later"
  use = "included"
  notice_files = []
  actions = ["corresponding source must be offered"]
"""

# The per-file classification scripts/spdx-check.py validates and this tool reads.
PROVENANCE = """
version = 1
[[files]]
path = ["*", "src/**", "scripts/**", "fixtures/**", "provenance/**", "blob/**", "third_party/**"]
class = "first-party"
license = "pending"
[[files]]
path = ["Cargo.lock", "ports.lock", "provenance/inventory/**", "provenance/baseline/**"]
class = "generated"
generator = "tools"
license = "pending"
[[files]]
path = "vendor/old/**"
class = "imported"
origin = "example.org old 1.0"
license = "MIT"
notice-files = ["vendor/old/LICENSE"]
in-artifacts = ["image"]
binary-actions = ["reproduce the notice"]
"""

REUSE = """
version = 1
[[annotations]]
path = "vendor/old/**"
SPDX-FileCopyrightText = "2020 Someone"
SPDX-License-Identifier = "MIT"
"""

OBLIGATIONS = """
[[obligation]]
id = "LIC"
title = "no licence chosen"
kind = "owner-decision"
applies_to = ["source", "binary"]
origin = "audit-test"
status = "open"
detect = { kind = "spdx", category = "unknown-licensing" }
[[obligation]]
id = "CLEAN"
title = "unsupported clean-room claim"
kind = "mechanical"
applies_to = ["source"]
origin = "audit-test"
status = "resolved"
resolved = "test: the claim was removed"
detect = { kind = "grep", files = ["README.md"], pattern = "clean-room" }
[[obligation]]
id = "PATHS"
title = "development paths in scripts"
kind = "mechanical"
applies_to = ["source"]
origin = "audit-test"
status = "open"
detect = { kind = "grep", files = ["scripts/*"], pattern = "/home/dev/", max = 1 }
[[obligation]]
id = "DRIVER"
title = "adapted driver: reproduce its notice in images"
kind = "mechanical"
applies_to = ["binary"]
origin = "audit-test"
status = "latent"
detect = { kind = "exists", path = "src/driver.rs" }
"""

MANIFEST = """
[package]
name = "app"
version = "0.1.0"
[dependencies]
liba = "1"
libunused = "1"
libopt = { version = "1", optional = true }
macros = "1"
[target.'cfg(unix)'.dependencies]
libunix = "1"
[target.'cfg(target_os = "demo")'.dependencies]
libdemo = "1"
[build-dependencies]
libbuild = "1"
[features]
default = []
extra = ["dep:libopt"]
"""


def lock(packages):
    out = ["version = 4", ""]
    for name, version, deps, registry in packages:
        out += ["[[package]]", f'name = "{name}"', f'version = "{version}"']
        if registry:
            out += ['source = "registry+https://example.invalid/index"', f'checksum = "{name}{version}"']
        if deps:
            out += ["dependencies = [", *[f' "{d}",' for d in deps], "]"]
        out.append("")
    return "\n".join(out)


BASE_LOCK = [
    ("app", "0.1.0", ["liba", "libunused", "libopt", "macros", "libunix", "libdemo", "libbuild"], False),
    ("liba", "1.0.0", ["libinner"], True), ("libinner", "1.0.0", [], True), ("libunused", "1.0.0", [], True),
    ("libopt", "1.0.0", [], True), ("macros", "1.0.0", ["libmacrodep"], True), ("libmacrodep", "1.0.0", [], True),
    ("libunix", "1.0.0", [], True), ("libdemo", "1.0.0", [], True), ("libbuild", "1.0.0", [], True),
]


class Repo:
    def __init__(self, tmp):
        self.root = Path(tmp) / "repo"
        self.registry = Path(tmp) / "registry"
        self.root.mkdir()
        self.registry.mkdir()
        for name, license_ in [("liba", "MIT OR Apache-2.0"), ("libinner", "MIT"), ("libunused", "MIT"),
                               ("libopt", "MIT"), ("libmacrodep", "MIT"), ("libunix", "MIT"),
                               ("libdemo", "BSD-3-Clause"), ("libbuild", "MIT")]:
            self.crate(name, "1.0.0", license_, deps='libinner = "1"' if name == "liba" else "")
        self.crate("macros", "1.0.0", "MIT", deps='libmacrodep = "1"', extra="[lib]\nproc-macro = true\n")
        self.write("Cargo.toml", MANIFEST)
        self.write("Cargo.lock", lock(BASE_LOCK))
        self.write("src/bin/tool.rs", "use liba::x;\nuse libdemo::y;\nuse libunix::z;\nuse libopt::o;\nuse macros::m;\nfn main() {}\n")
        self.write("src/bin/other.rs", "use libunused::q;\nfn main() {}\n")
        self.write("README.md", "# demo\n")
        self.write("scripts/build.sh", "tool=/home/dev/bin/tool\n")
        self.write("vendor/old/LICENSE", "MIT text\n")
        self.write("vendor/old/lib.rs", "// Copyright (c) 2020 Someone\npub fn f() {}\n")
        self.write("provenance.toml", PROVENANCE)
        self.write("REUSE.toml", REUSE)
        self.write("LICENSES/MIT.txt", "MIT text\n")
        (self.root / "scripts").mkdir(exist_ok=True)
        shutil.copyfile(Path(__file__).resolve().parent / "spdx-check.py", self.root / "scripts/spdx-check.py")
        self.write("provenance/obligations.toml", OBLIGATIONS)
        # The one shared provenance tool a fixture carries is pinned, as the
        # real repositories pin theirs.
        self.shared = ('\n[shared_tools.sha256]\n"scripts/spdx-check.py" = "'
                       + hashlib.sha256((self.root / "scripts/spdx-check.py").read_bytes()).hexdigest() + '"\n')
        self.write("provenance/config.toml", CONFIG + self.shared)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        os.environ["ABSD_CARGO_REGISTRY"] = str(self.registry)
        os.environ["ABSD_PRIVATE_PATTERNS"] = str(Path(tmp) / "absent")
        self.update()
        self.commit("base")
        base = self.git("rev-parse", "HEAD").strip()
        self.write("provenance/config.toml", CONFIG.replace("BASE", base) + self.shared)
        (self.root / "provenance/baseline").mkdir()
        self.write("provenance/baseline/image.tsv", (self.root / "provenance/inventory/image.tsv").read_text())
        self.commit("baseline records")
        self.base = self.git("rev-parse", "HEAD").strip()

    def crate(self, name, version, license_, deps="", extra="", text=True):
        d = self.registry / f"{name}-{version}"
        d.mkdir(exist_ok=True)
        lic = f'license = "{license_}"\n' if license_ else ""
        (d / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "{version}"\n{lic}{extra}'
                                      f"[dependencies]\n{deps}\n")
        if text:
            (d / "LICENSE-MIT").write_text(f"MIT licence of {name}\n")

    def write(self, path, text):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text) if isinstance(text, bytes) else p.write_text(text)

    def append(self, path, text):
        self.write(path, (self.root / path).read_text() + text)

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True, text=True).stdout

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def rec(self):
        return pv.Records(self.root)

    def update(self):
        rec = self.rec()
        (self.root / "provenance/inventory").mkdir(exist_ok=True)
        for artifact in rec.config["artifact"]:
            rows, _ = pv.inventory(rec, artifact)
            (self.root / f"provenance/inventory/{artifact['name']}.tsv").write_text(pv.render(rows))

    def check(self):
        return pv.check(self.rec(), self.base)

    def rows(self):
        rec = self.rec()
        return {r["component"]: r for r in pv.inventory(rec, rec.config["artifact"][0])[0]}

    def add_dependency(self, name, license_="MIT", text=True, version="1.0.0"):
        self.crate(name, version, license_, text=text)
        manifest = (self.root / "Cargo.toml").read_text().replace('liba = "1"', f'liba = "1"\n{name} = "1"')
        self.write("Cargo.toml", manifest)
        packages = [(n, v, d + [name] if n == "app" else d, r) for n, v, d, r in BASE_LOCK] + [(name, version, [], True)]
        self.write("Cargo.lock", lock(packages))
        self.append("src/bin/tool.rs", f"use {name}::n;\n")


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repo(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def reasons(self, out):
        return " | ".join(f"{s} {p}: {r}" for s, p, r, _ in out.items)

    def test_build_evidence_reads_unique_sibling_port_layout_and_legacy_relative_paths(self):
        stage = Path(str(self.repo.root)+".staged-compat")
        for tree, dependency in (("uu_basename-0.12.0", "liba-1.0.0"),("ripgrep-15.2.0", "unlisted-2.0.0")):
            deps = stage/f"target-ports/{tree}/x86_64-unknown-absd/release/deps"
            deps.mkdir(parents=True)
            (deps/"port.d").write_text(f"out: /cache/registry/src/index/{dependency}/src/lib.rs\n")
        rows = [{"component":"liba","version":"1.0.0","origin":"registry","use":"linked","units":["ports"],"source":"registry"}]
        unit = {"name":"ports","evidence":"{root}.staged-compat/target-ports/*/x86_64-unknown-absd/release/deps","evidence_exact":True}
        out = pv.Findings()
        pv.build_evidence(pv.Records(self.repo.root),{"name":"image","unit":[unit]},rows,out)
        self.assertIn("build output lists 2 registry crate(s)"," | ".join(out.info))
        self.assertIn("unlisted-2.0.0",self.reasons(out))
        self.assertNotIn("no build output"," | ".join(out.info))
        legacy = self.repo.root/"target/[legacy]/deps"; legacy.mkdir(parents=True)
        (legacy/"port.d").write_text("out: /cache/registry/src/index/liba-1.0.0/src/lib.rs\n")
        unit["evidence"]="target/[legacy]/deps"
        out=pv.Findings()
        pv.build_evidence(pv.Records(self.repo.root),{"name":"image","unit":[unit]},rows,out)
        self.assertFalse(out.items)
        self.assertIn("build output lists 1 registry crate(s)"," | ".join(out.info))

    # ---- resolution

    def test_inventory_is_what_the_installed_binary_links(self):
        rows = self.repo.rows()
        self.assertEqual(rows["liba"]["use"], "linked")
        self.assertEqual(rows["libinner"]["use"], "linked")           # transitive
        self.assertEqual(rows["libdemo"]["use"], "linked")            # cfg(target_os = "demo")
        self.assertEqual(rows["libunix"]["use"], "not-built")         # cfg(unix) is false for the target
        self.assertEqual(rows["libopt"]["use"], "not-built")          # optional, feature off
        self.assertEqual(rows["libunused"]["use"], "not-built")       # only a binary that is not installed names it
        self.assertEqual(rows["macros"]["use"], "build-only")         # procedural macro
        self.assertEqual(rows["libmacrodep"]["use"], "build-only")
        self.assertEqual(rows["libbuild"]["use"], "build-only")       # build dependency
        self.assertEqual(rows["liba"]["elected"], "MIT")              # the recorded choice among alternatives
        self.assertTrue(pv.shipped(rows["Bootloader"]))

    def test_license_choice_and_cfg(self):
        policy = {"prefer": ["MIT", "Apache-2.0", "BSD-3-Clause"]}
        self.assertEqual(pv.elect("Apache-2.0 OR GPL-2.0-only", policy), ["Apache-2.0"])
        self.assertEqual(pv.elect("(Apache-2.0 OR MIT) AND BSD-3-Clause", policy), ["BSD-3-Clause", "MIT"])
        self.assertEqual(pv.elect("Unlicense/MIT", policy), ["MIT"])
        self.assertIsNone(pv.elect("GPL-3.0-only", policy))
        self.assertIsNone(pv.elect("MIT AND GPL-3.0-only", policy))
        cfg = pv.Cfg({"triple": "t", "names": [], "values": {"target_os": "demo"}})
        self.assertTrue(cfg.holds('cfg(not(all(windows, target_env = "msvc")))'))
        self.assertTrue(cfg.holds('cfg(any(unix, target_os = "demo"))'))
        self.assertFalse(cfg.holds("cfg(unix)"))
        self.assertTrue(cfg.holds("t"))

    # ---- ordinary work is not flagged

    def test_unchanged_tree(self):
        out = self.repo.check()
        self.assertEqual(out.verdict(), "UNCHANGED", self.reasons(out))

    def test_ordinary_first_party_change(self):
        self.repo.append("src/bin/tool.rs", "fn helper() -> u32 { 7 } // derived from the request, taken from the queue\n")
        self.repo.write("src/new_module.rs", "pub fn g() {}\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "UNCHANGED", self.reasons(out))

    def test_documentation_only_change(self):
        self.repo.append("README.md", "Copyright (c) 2020 and licence questions are tracked. Adapted from nothing.\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "UNCHANGED", self.reasons(out))

    # ---- dependencies

    def test_new_dependency_needs_only_an_inventory_update(self):
        self.repo.add_dependency("libnew")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "COMPLIANCE_ACTION_REQUIRED")
        self.assertIn("committed inventory does not match", self.reasons(out))
        self.repo.update()
        out = self.repo.check()
        self.assertEqual(out.verdict(), "UNCHANGED", self.reasons(out))
        self.assertTrue(any("new shipped component libnew" in n for n in out.info))

    def test_dependency_version_change_is_reported(self):
        self.repo.crate("liba", "1.1.0", "MIT OR Apache-2.0", deps='libinner = "1"')
        self.repo.write("Cargo.lock", lock([(n, "1.1.0" if n == "liba" else v, d, r) for n, v, d, r in BASE_LOCK]))
        self.repo.update()
        out = self.repo.check()
        self.assertEqual(out.verdict(), "UNCHANGED", self.reasons(out))
        self.assertTrue(any("liba 1.0.0 -> 1.1.0" in n for n in out.info))

    def test_removed_dependency_leaves_the_inventory_and_the_notices(self):
        rec = self.repo.rec()
        before = Path(self.tmp.name) / "before"
        pv.notices(rec, "image", before, quiet=True)
        self.assertTrue((before / "licenses/libdemo-1.0.0/LICENSE-MIT").exists())
        self.repo.write("src/bin/tool.rs", "use liba::x;\nfn main() {}\n")
        self.repo.update()
        self.assertEqual(self.repo.rows()["libdemo"]["use"], "not-built")
        out = self.repo.check()
        self.assertTrue(any("shipped component removed: libdemo" in n for n in out.info))
        after = Path(self.tmp.name) / "after"
        pv.notices(self.repo.rec(), "image", after, quiet=True)
        self.assertFalse((after / "licenses/libdemo-1.0.0").exists())
        # A bundle names the inventory it was made from, so the old one is detectably stale.
        self.assertNotEqual((before / "inventory.tsv").read_text(), (after / "inventory.tsv").read_text())
        self.assertNotEqual([l for l in (before / "NOTICES.md").read_text().splitlines() if "sha256" in l],
                            [l for l in (after / "NOTICES.md").read_text().splitlines() if "sha256" in l])

    def test_missing_licence_metadata(self):
        self.repo.add_dependency("libnolicense", license_="")
        self.repo.update()
        out = self.repo.check()
        self.assertEqual(out.verdict(), "BLOCKED")
        self.assertIn("declares no licence", self.reasons(out))

    def test_missing_licence_text(self):
        self.repo.add_dependency("libnotext", text=False)
        self.repo.update()
        out = self.repo.check()
        self.assertEqual(out.verdict(), "COMPLIANCE_ACTION_REQUIRED")
        self.assertIn("carries no licence text", self.reasons(out))
        _, missing, _ = pv.notices(self.repo.rec(), "image", Path(self.tmp.name) / "n", quiet=True)
        self.assertTrue(any("libnotext" in m for m in missing))

    def test_copyleft_dependency_is_a_decision_not_a_refusal(self):
        self.repo.add_dependency("libgpl", license_="GPL-3.0-only")
        self.repo.update()
        out = self.repo.check()
        self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED")
        self.assertIn("explicit decision", self.reasons(out))
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace("[policy.decisions]", '[policy.decisions]\n"libgpl 1.0.0" = "GPL-3.0-only"'))
        self.repo.update()
        out = self.repo.check()
        self.assertEqual(out.verdict(), "UNCHANGED", self.reasons(out))

    def test_attribution_alone_is_not_a_problem(self):
        self.repo.add_dependency("libbsd", license_="BSD-3-Clause")
        self.repo.update()
        self.assertEqual(self.repo.check().verdict(), "UNCHANGED")

    # ---- new material in the tree

    def test_new_vendored_source_needs_a_declaration(self):
        self.repo.write("vendor/new/lib.rs", "// SPDX-License-Identifier: BSD-3-Clause\n// Copyright (c) 2001 Intel\npub fn f() {}\n")
        self.repo.write("vendor/new/LICENSE", "BSD text\n")
        out = self.repo.check()
        # No provenance.toml rule classifies the new directory: spdx-check says so.
        self.assertEqual(out.verdict(), "COMPLIANCE_ACTION_REQUIRED")
        self.assertIn("vendor/new/lib.rs: spdx-check missing-metadata", self.reasons(out))
        self.repo.append("provenance.toml", '\n[[files]]\npath = "vendor/new/**"\nclass = "imported"\n'
                         'origin = "example.org new 2.0"\nlicense = "BSD-3-Clause"\n'
                         'notice-files = ["vendor/new/LICENSE"]\n')
        self.repo.write("LICENSES/BSD-3-Clause.txt", "BSD text\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "UNCHANGED", self.reasons(out))
        self.assertTrue(any("imported material added" in n for n in out.info))

    def test_licence_header_in_a_first_party_file(self):
        self.repo.write("src/quirk.rs", "// SPDX-License-Identifier: GPL-2.0-only\npub fn q() {}\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "COMPLIANCE_ACTION_REQUIRED")
        self.assertIn("spdx-check conflict", self.reasons(out))

    # ---- defects found by the independent review of 2026-10-10

    def test_a_locks_own_root_crate_is_a_shipped_registry_crate(self):
        # A port: the lock's root package is itself a registry crate and has no source line.
        self.repo.crate("porttool", "2.0.0", "MIT", deps='liba = "1"')
        self.repo.write("ports.lock", lock([("porttool", "2.0.0", ["liba"], False), ("liba", "1.0.0", ["libinner"], True),
                                           ("libinner", "1.0.0", [], True)]))
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace("  [[artifact.component]]", '  [[artifact.unit]]\n'
                        '  name = "port"\n  lock = "ports.lock"\n  package = "porttool"\n  [[artifact.component]]', 1))
        row = self.repo.rows()["porttool"]
        self.assertEqual((row["origin"], row["use"], row["elected"]), ("registry", "linked", "MIT"))
        self.assertTrue(pv.shipped(row))
        _, missing, _ = pv.notices(self.repo.rec(), "image", Path(self.tmp.name) / "p", quiet=True)
        self.assertTrue((Path(self.tmp.name) / "p/licenses/porttool-2.0.0/LICENSE-MIT").exists())

    def test_pinned_registry_identity_does_not_become_first_party_in_local_stage(self):
        repo = self.repo
        repo.crate("patched", "1.0.0", "MIT")
        repo.append("Cargo.toml", '\n[dependencies.patched]\npath = ".staged/patched"\n')
        repo.append("src/bin/tool.rs", "use patched::p;\n")
        repo.write(".staged/patched/Cargo.toml", '[package]\nname = "patched"\nversion = "1.0.0"\nlicense = "GPL-3.0-only"\n')
        repo.write("Cargo.lock", lock([(n,v,d+["patched"] if n=="app" else d,r) for n,v,d,r in BASE_LOCK]
                                     + [("patched", "1.0.0", [], False)]))
        repo.append("provenance/config.toml", '\n[licence_policy.crate_checksums]\n"patched 1.0.0" = "' + "a"*64 + '"\n')
        row = repo.rows()["patched"]
        self.assertEqual((row["origin"], row["license"], row["elected"]), ("registry", "MIT", "MIT"))
        self.assertEqual(repo.rows()["app"]["origin"], "first-party")
        shutil.rmtree(repo.registry / "patched-1.0.0")
        rec = repo.rec()
        # Isolate this negative control from any identically named default cache.
        old = pv.registries
        try:
            pv.registries = lambda _: [str(repo.registry)]
            rows, notes = pv.compute_inventory(rec, rec.config["artifact"][0])
        finally:
            pv.registries = old
        row = next(row for row in rows if row["component"] == "patched")
        self.assertEqual((row["origin"], row["elected"], row["texts"]), ("registry", "UNKNOWN", "UNKNOWN"))
        self.assertTrue(any("package manifest(s) not available" in reason for _,_,reason in notes))

    def test_inventory_does_not_depend_on_what_is_staged_beside_the_checkout(self):
        # A patched registry crate staged outside the repository, and a private sibling that is not linked.
        self.repo.crate("patched", "1.0.0", "MIT")
        self.repo.append("Cargo.toml", '\n[dependencies.patched]\nversion = "1"\n[dependencies.sibling]\npath = "../sibling"\n'
                         '[patch.crates-io]\npatched = { path = "../staged/patched" }\n')
        self.repo.write("Cargo.lock", lock([(n, v, d + ["patched", "sibling"] if n == "app" else d, r) for n, v, d, r in BASE_LOCK]
                                           + [("patched", "1.0.0", [], False), ("sibling", "0.1.0", [], False)]))
        self.repo.append("src/bin/tool.rs", "use patched::p;\n")
        absent = pv.render(pv.inventory(self.repo.rec(), self.repo.rec().config["artifact"][0])[0])
        for name in ("staged/patched", "sibling"):
            d = Path(self.tmp.name) / name
            d.mkdir(parents=True)
            (d / "Cargo.toml").write_text(f'[package]\nname = "{d.name}"\nversion = "1.0.0"\nlicense = "GPL-3.0-only"\n')
        present = pv.render(pv.inventory(self.repo.rec(), self.repo.rec().config["artifact"][0])[0])
        self.assertEqual(absent, present)
        rows = self.repo.rows()
        self.assertEqual((rows["patched"]["origin"], rows["patched"]["use"], rows["patched"]["elected"]), ("registry", "linked", "MIT"))
        self.assertEqual((rows["sibling"]["origin"], rows["sibling"]["use"]), ("outside-repository", "not-built"))

    def test_crates_reached_through_links_are_the_same_crates(self):
        # As ssh/ does: a second workspace names a first-party crate and a staged, patched registry crate
        # through tree/ links that a stage script makes; its unit also crawls the root workspace, which
        # finds the first-party crate where the links are not made yet.
        repo, tmp = self.repo, Path(self.tmp.name)
        repo.write("core1/Cargo.toml", '[package]\nname = "core1"\nversion = "0.1.0"\n')
        repo.append("Cargo.toml", '\n[workspace]\nmembers = ["core1"]\n')
        repo.crate("patched", "1.0.0", "MIT")
        staged = tmp / "staged/patched"
        staged.mkdir(parents=True)
        (staged / "Cargo.toml").write_text('[package]\nname = "patched"\nversion = "1.0.0"\nlicense = "GPL-3.0-only"\n')
        repo.write("sub/Cargo.toml", '[package]\nname = "subapp"\nversion = "0.1.0"\n[dependencies]\n'
                   'core1 = { path = "tree/core1" }\npatched = "1"\n[patch.crates-io]\n'
                   'patched = { path = "tree/patched" }\n[workspace]\n')
        repo.write("sub/Cargo.lock", lock([("subapp", "0.1.0", ["core1", "patched"], False), ("core1", "0.1.0", [], False),
                                          ("patched", "1.0.0", [], False)]))
        config = (repo.root / "provenance/config.toml").read_text()
        repo.write("provenance/config.toml", config.replace("  [[artifact.component]]", '  [[artifact.unit]]\n'
                   '  name = "sub"\n  lock = "sub/Cargo.lock"\n  package = "subapp"\n  manifest_dir = ["sub", "."]\n'
                   '  [[artifact.component]]', 1))
        absent = pv.render(pv.inventory(repo.rec(), repo.rec().config["artifact"][0])[0])
        (repo.root / "sub/tree").mkdir()
        (repo.root / "sub/tree/core1").symlink_to("../../core1")
        (repo.root / "sub/tree/patched").symlink_to(os.path.relpath(staged, repo.root / "sub/tree"))
        present = pv.render(pv.inventory(repo.rec(), repo.rec().config["artifact"][0])[0])
        self.assertEqual(absent, present)
        rows = repo.rows()
        self.assertEqual((rows["core1"]["origin"], rows["core1"]["source"], rows["core1"]["use"]), ("first-party", "core1", "linked"))
        self.assertEqual((rows["patched"]["origin"], rows["patched"]["elected"]), ("registry", "MIT"))
        # The same records reached through a link to the repository classify the same way.
        link = tmp / "repo-link"
        link.symlink_to(repo.root)
        through = pv.Records(link)
        self.assertEqual(pv.render(pv.inventory(through, through.config["artifact"][0])[0]), present)

    def toolchain_fixture(self, license_="MIT"):
        source = Path(self.tmp.name) / "toolchain"
        source.mkdir()
        manifest = '[package]\nname = "compiler-source"\nversion = "0.1.0"\n'
        if license_:
            manifest += f'license = "{license_}"\n'
        (source / "Cargo.toml").write_text(manifest)
        (source / "LICENSE-MIT").write_text("Synthetic toolchain notice\n")
        alias = Path(self.tmp.name) / "toolchain-alias"
        alias.symlink_to(source)
        self.repo.write("toolchain.lock", lock([("compiler-source", "0.1.0", [], False)]))
        return source, alias

    def toolchain_inventory(self, source, manifest_dir="."):
        artifact = {"unit": [{"name": "compiler", "lock": "toolchain.lock", "package": "compiler-source",
                              "sources": str(source), "manifest_dir": manifest_dir,
                              "source_id": "fixture-source-revision"}]}
        return pv.compute_inventory(self.repo.rec(), artifact)

    def test_toolchain_source_root_alias_preserves_inventory(self):
        source, alias = self.toolchain_fixture()
        direct = self.toolchain_inventory(source)
        self.assertEqual((direct[0][0]["origin"], direct[0][0]["elected"]), ("toolchain", "MIT"))
        self.assertEqual(self.toolchain_inventory(alias), direct)

    def test_toolchain_source_alias_preserves_missing_license(self):
        source, alias = self.toolchain_fixture(license_=None)
        direct = self.toolchain_inventory(source)
        self.assertEqual(direct[0][0]["elected"], "UNDECLARED")
        self.assertEqual(self.toolchain_inventory(alias), direct)

    def test_toolchain_source_alias_does_not_resolve_missing_manifest(self):
        source, alias = self.toolchain_fixture()
        (source / "Cargo.toml").unlink()
        direct = self.toolchain_inventory(source)
        self.assertEqual((direct[0][0]["origin"], direct[0][0]["elected"]), ("unresolved", "UNKNOWN"))
        self.assertEqual(self.toolchain_inventory(alias), direct)

    def test_toolchain_source_links_outside_root_stay_unknown(self):
        source, alias = self.toolchain_fixture()
        (source / "Cargo.toml").write_text('[workspace]\nmembers = ["component"]\n')
        # One sibling shares the configured root's spelling. Neither sibling
        # belongs to the tree, even when a member link or root alias reaches it.
        for name in ("toolchain-sibling", "outside"):
            outside = Path(self.tmp.name) / name
            outside.mkdir()
            (outside / "Cargo.toml").write_text(
                '[package]\nname = "compiler-source"\nversion = "0.1.0"\nlicense = "MIT"\n')
            member = source / "component"
            member.symlink_to(outside)
            for configured in (source, alias):
                with self.subTest(outside=name, configured=configured.name):
                    rows, notes = self.toolchain_inventory(configured, "component")
                    self.assertFalse(notes)
                    self.assertEqual((rows[0]["origin"], rows[0]["elected"]), ("sibling-checkout", "UNKNOWN"))
            member.unlink()

    def test_missing_registry_is_unknown_not_a_licence_failure(self):
        os.environ["ABSD_CARGO_REGISTRY"] = str(Path(self.tmp.name) / "nowhere")
        try:
            out = self.repo.check()
            self.assertEqual(out.verdict(), "UNKNOWN", self.reasons(out))
            self.assertNotIn("declares no licence", self.reasons(out))
            self.assertNotIn("run scripts/provenance.py update", " ".join(i[3] for i in out.items))
            with self.assertRaises(pv.Problem):
                pv.update(self.repo.rec())
        finally:
            os.environ["ABSD_CARGO_REGISTRY"] = str(self.repo.registry)

    def test_bundle_reports_configured_notice_files_it_could_not_copy(self):
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace("notice_files = []", 'notice_files = ["/nonexistent/COPYING"]'))
        out_dir = Path(self.tmp.name) / "b"
        _, missing, _ = pv.notices(self.repo.rec(), "image", out_dir, quiet=True)
        self.assertTrue(any("Bootloader" in m and "/nonexistent/COPYING" in m for m in missing))
        self.assertIn("| MISSING |", [l for l in (out_dir / "NOTICES.md").read_text().splitlines() if l.startswith("| Bootloader")][0])

    def test_any_finding_blocks_readiness(self):
        self.repo.write("blob/firmware.bin", b"\0\1\2\3" * 64)
        self.repo.commit("blob")
        _, (report, verdicts) = pv.full(self.repo.rec(), Path(self.tmp.name) / "f")
        self.assertEqual(verdicts["source"], "NOT_READY")
        self.assertEqual(verdicts["binary"], "NOT_READY")

    def test_resolved_needs_a_statement(self):
        text = (self.repo.root / "provenance/obligations.toml").read_text()
        self.repo.write("provenance/obligations.toml", text.replace('status = "open"\ndetect = { kind = "spdx"',
                                                                    'status = "resolved"\ndetect = { kind = "spdx"'))
        out = self.repo.check()
        self.assertIn("LIC is marked resolved with no statement of how", self.reasons(out))

    def test_a_first_party_rule_does_not_hide_a_licence_header(self):
        self.repo.write("vendor/stub/lib.rs", "// SPDX-License-Identifier: GPL-2.0-only\npub fn s() {}\n")
        self.repo.append("provenance.toml", '\n[[files]]\npath = "vendor/stub/**"\nclass = "first-party"\nlicense = "pending"\n')
        out = self.repo.check()
        self.assertEqual(out.verdict(), "COMPLIANCE_ACTION_REQUIRED")
        self.assertIn("spdx-check conflict", self.reasons(out))
        self.assertTrue(any("licensing and provenance records changed" in n for n in out.info))

    def test_material_under_provenance_is_examined_and_record_changes_are_shown(self):
        self.repo.write("provenance/blob.bin", b"\0\1\2\3" * 64)
        self.repo.append("provenance/config.toml", "\n# loosened\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED")
        self.assertTrue(any("licensing and provenance records changed" in n for n in out.info))

    def test_submodule(self):
        other = Path(self.tmp.name) / "other"
        other.mkdir()
        for args in (["init", "-q"], ["config", "user.email", "t@example.invalid"], ["config", "user.name", "t"]):
            subprocess.run(["git", "-C", str(other), *args], check=True)
        (other / "f").write_text("x\n")
        subprocess.run(["git", "-C", str(other), "add", "f"], check=True)
        subprocess.run(["git", "-C", str(other), "commit", "-q", "-m", "x"], check=True)
        subprocess.run(["git", "-C", str(self.repo.root), "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                        str(other), "third_party/other"], check=True, capture_output=True)
        out = self.repo.check()
        self.assertIn("git submodule", self.reasons(out))

    def test_malformed_record_is_reported(self):
        self.repo.append("provenance/obligations.toml", "\n[[obligation\n")
        with self.assertRaises(pv.Problem):
            self.repo.rec()

    # ---- defects found by the review of the combined implementation

    def test_new_file_slipped_into_a_vendored_directory(self):
        self.repo.write("vendor/old/extra.rs", "pub fn e() {}\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED")
        self.assertIn("vendor/old/extra.rs", self.reasons(out))

    def test_wording_that_names_an_upstream(self):
        for line in ("// All rights reserved.", "// under the GNU General Public License",
                     "// copied from FreeBSD sys/dev/e1000", "// derived from linux/drivers/usb/host"):
            self.repo.write("src/x.rs", line + "\npub fn x() {}\n")
            out = self.repo.check()
            self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED", line)
        self.repo.write("src/x.rs", "// the offset is derived from the request and copied from the caller's buffer\npub fn x() {}\n")
        self.assertEqual(self.repo.check().verdict(), "UNCHANGED")

    def test_source_placed_among_the_records(self):
        self.repo.write("provenance/copied.rs", "// Copyright (c) 2008 Someone\npub fn c() {}\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED")
        self.assertIn("provenance/copied.rs", self.reasons(out))

    def test_unresolved_material_is_reviewed_not_hidden(self):
        self.repo.write("mystery/lib.rs", "pub fn m() {}\n")
        self.repo.append("provenance.toml", '\n[[files]]\npath = "mystery/**"\nclass = "unresolved"\nreason = "origin not known"\n')
        out = self.repo.check()
        self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED")
        self.assertIn("origin not known", self.reasons(out))

    def test_partial_crate_cache_does_not_fail_an_unchanged_tree(self):
        shutil.rmtree(self.repo.registry / "libunix-1.0.0")       # not built for the target
        shutil.rmtree(self.repo.registry / "libmacrodep-1.0.0")   # build-time only
        out = self.repo.check()
        self.assertEqual(out.verdict(), "UNCHANGED", self.reasons(out))
        shutil.rmtree(self.repo.registry / "libinner-1.0.0")      # linked: now it matters
        self.assertEqual(self.repo.check().verdict(), "UNKNOWN")

    def test_a_root_licence_file_while_the_licence_is_pending(self):
        self.repo.write("LICENSE", "MIT text\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "COMPLIANCE_ACTION_REQUIRED")
        self.assertIn("reads as the project's licence", self.reasons(out))

    def test_lock_file_no_artifact_reads(self):
        self.repo.write("tools/new/Cargo.lock", lock([("newtool", "0.1.0", [], False)]))
        self.repo.append("provenance.toml", '\n[[files]]\npath = "tools/**"\nclass = "generated"\ngenerator = "cargo"\nlicense = "pending"\n')
        out = self.repo.check()
        self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED")
        self.assertIn("no artifact in provenance/config.toml reads", self.reasons(out))

    def test_an_spdx_check_rule_this_tool_does_not_know_needs_review(self):
        rec = self.repo.rec()
        rec.__dict__["_spdx"] = {(self.repo.base, False): {"schema": "absd-spdx-check/1", "counts": {}, "notes": [],
                                 "findings": [{"category": "new-obligation", "kind": "something-new", "path": "a",
                                               "detail": "a rule added later", "class": None}]}}
        out = pv.Findings()
        pv.spdx_checks(rec, out, self.repo.base)
        self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED")

    def test_notice_files_in_the_repository_are_copied_into_the_bundle(self):
        self.repo.write("provenance/upstream-notices/x.NOTICE", "x\nCopyright 2026 Someone\n")
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace("notice_files = []",
                        'notice_files = ["provenance/upstream-notices/x.NOTICE"]'))
        out_dir = Path(self.tmp.name) / "nb"
        _, missing, _ = pv.notices(self.repo.rec(), "image", out_dir, quiet=True)
        self.assertTrue((out_dir / "licenses/Bootloader-host/x.NOTICE").exists())
        self.assertFalse(any("Bootloader" in m for m in missing))

    def test_notice_destination_collision_refuses_before_overwrite(self):
        for second in ("first notice\n", "second notice\n"):
            with self.subTest(second=second):
                self.repo.write("notices/a/LICENSE", "first notice\n")
                self.repo.write("notices/b/LICENSE", second)
                rec = self.repo.rec()
                rec.config["artifact"][0]["component"][0]["notice_files"] = [
                    "notices/a/LICENSE", "notices/b/LICENSE"]
                output = Path(self.tmp.name) / "collision"
                with self.assertRaisesRegex(pv.Problem, "notice destination collision"):
                    pv.notices(rec, "image", output, quiet=True)
                self.assertEqual((output / "licenses/Bootloader-host/LICENSE").read_text(), "first notice\n")
                self.assertFalse((output / "NOTICES.md").exists())
                self.assertFalse((output / "inventory.tsv").exists())

    def test_notice_destinations_differing_only_in_case_collide(self):
        self.repo.write("notices/LICENSE", "first notice\n")
        rec = self.repo.rec()
        extra = dict(rec.config["artifact"][0]["component"][0], name="bootloader", notice_files=["notices/LICENSE"])
        rec.config["artifact"][0]["component"].append(extra)
        rec.config["artifact"][0]["component"][0]["notice_files"] = ["notices/LICENSE"]
        with self.assertRaisesRegex(pv.Problem, "differs only in case from licenses/"):
            pv.notices(rec, "image", Path(self.tmp.name) / "case", quiet=True)

    def test_notice_directory_collision_refuses_before_overwrite(self):
        self.repo.write("notices/a/licenses/LICENSE", "first notice\n")
        self.repo.write("notices/b/licenses/LICENSE", "second notice\n")
        rec = self.repo.rec()
        rec.config["artifact"][0]["component"][0]["notice_files"] = [
            "notices/a/licenses", "notices/b/licenses"]
        output = Path(self.tmp.name) / "directory-collision"
        with self.assertRaisesRegex(pv.Problem, "notice destination collision"):
            pv.notices(rec, "image", output, quiet=True)
        self.assertEqual((output / "licenses/Bootloader-host/licenses/LICENSE").read_text(), "first notice\n")
        self.assertFalse((output / "NOTICES.md").exists())

    def test_repeated_same_notice_source_is_permitted(self):
        self.repo.write("notices/LICENSE", "same source\n")
        rec = self.repo.rec()
        rec.config["artifact"][0]["component"][0]["notice_files"] = ["notices/LICENSE", "notices/LICENSE"]
        output = Path(self.tmp.name) / "same-source"
        _, missing, _ = pv.notices(rec, "image", output, quiet=True)
        self.assertEqual((output / "licenses/Bootloader-host/LICENSE").read_text(), "same source\n")
        self.assertFalse(any("Bootloader" in m for m in missing))

    def test_symlink_notice_alias_shares_only_the_same_source(self):
        self.repo.write("notices/a/LICENSE", "first notice\n")
        self.repo.write("notices/b/LICENSE", "different notice\n")
        alias = self.repo.root / "notices/alias/LICENSE"
        alias.parent.mkdir()
        for target in ("../a/LICENSE", "../b/LICENSE"):
            with self.subTest(target=target):
                if alias.is_symlink():
                    alias.unlink()
                alias.symlink_to(target)
                rec = self.repo.rec()
                rec.config["artifact"][0]["component"][0]["notice_files"] = [
                    "notices/a/LICENSE", "notices/alias/LICENSE"]
                output = Path(self.tmp.name) / "alias-notices"
                if target == "../a/LICENSE":
                    pv.notices(rec, "image", output, quiet=True)
                else:
                    with self.assertRaisesRegex(pv.Problem, "notice destination collision"):
                        pv.notices(rec, "image", output, quiet=True)
                    self.assertFalse((output / "NOTICES.md").exists())
                self.assertEqual((output / "licenses/Bootloader-host/LICENSE").read_text(), "first notice\n")

    def test_toolchain_source_note_names_only_its_linked_package(self):
        unit = dict(source_id="toolchain", linked_source_notes={"compiler_builtins": "toolchain libm origin"})
        self.assertEqual(pv.toolchain_source_id(unit, "compiler_builtins", "linked"), "toolchain; toolchain libm origin")
        for name, use in [("core", "linked"), ("compiler_builtins", "not-built"), ("compiler_builtins", "build-only")]:
            self.assertEqual(pv.toolchain_source_id(unit, name, use), "toolchain")

    def test_declaring_copyleft_source_still_needs_a_decision(self):
        self.repo.write("src/quirk.rs", "pub fn q() {}\n")
        entry = ('\n[[files]]\npath = "src/quirk.rs"\nclass = "adapted"\norigin = "example.org driver"\n'
                 'upstream-license = "GPL-2.0-only"\nlicense = "pending"\n')
        self.repo.append("provenance.toml", entry)
        out = self.repo.check()
        self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED")
        self.assertIn("explicit decision", self.reasons(out))
        self.repo.append("provenance.toml", 'decision = "owner, 2026-10-10: this file ships under GPL-2.0-only"\n')
        self.assertEqual(self.repo.check().verdict(), "UNCHANGED")

    def test_adapted_code_in_a_first_party_file(self):
        self.repo.append("src/bin/tool.rs", "// Register sequences adapted from the FreeBSD driver.\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED")

    def test_changed_vendored_file_and_removed_licence(self):
        self.repo.append("vendor/old/lib.rs", "pub fn patched() {}\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED")
        self.assertIn("its provenance.toml rule was not touched", self.reasons(out))
        # Saying what changed, in the rule, is the record that clears it.
        text = (self.repo.root / "provenance.toml").read_text()
        self.repo.write("provenance.toml", text.replace('origin = "example.org old 1.0"',
                                                        'origin = "example.org old 1.0, plus fn patched (ABSD)"'))
        out = self.repo.check()
        self.assertEqual(out.verdict(), "UNCHANGED", self.reasons(out))
        self.assertTrue(any("rule is new or updated" in n for n in out.info))
        (self.repo.root / "vendor/old/LICENSE").unlink()
        out = self.repo.check()
        self.assertEqual(out.verdict(), "BLOCKED")
        self.assertIn("licence", self.reasons(out))

    def test_new_sensitive_fixture(self):
        self.repo.write("fixtures/secrets/id.pem", "-----BEGIN " + "PRIVATE KEY-----\nAAAA\n-----END " + "PRIVATE KEY-----\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "BLOCKED")
        self.repo.append("provenance.toml", '\n[[files]]\npath = "fixtures/secrets/**"\nclass = "first-party"\n'
                         'license = "pending"\nkind = "test-key"\nnote = "generated for the fixture; never enrolled"\n')
        out = self.repo.check()
        self.assertEqual(out.verdict(), "UNCHANGED", self.reasons(out))

    def test_der_key_is_recognised_by_content(self):
        self.repo.write("fixtures/k/issuer.pk8", bytes.fromhex("302e020100300506032b657004220420") + bytes(32))
        self.assertEqual(self.repo.check().verdict(), "BLOCKED")

    def test_new_binary_outside_fixture_directories(self):
        self.repo.write("fixtures/store.db", b"SQLite format 3\0" + bytes(64))
        self.assertEqual(self.repo.check().verdict(), "UNCHANGED")
        self.repo.write("blob/firmware.bin", b"\0\1\2\3" * 64)
        out = self.repo.check()
        self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED")
        self.assertIn("blob/firmware.bin", self.reasons(out))

    def test_absolute_path_dependency(self):
        self.repo.append("Cargo.toml", '\n[dependencies.private]\npath = "/data/git/private-project/crate"\n')
        out = self.repo.check()
        self.assertIn("absolute development-machine path in a build manifest", self.reasons(out))
        self.assertEqual(out.verdict(), "COMPLIANCE_ACTION_REQUIRED")

    # ---- obligations stay tracked

    def test_known_obligations_do_not_fail_the_check_but_block_release(self):
        rec = self.repo.rec()
        out = pv.Findings()
        rows = pv.obligation_checks(rec, pv.tracked(rec), out)
        self.assertEqual(out.verdict(), "UNCHANGED")
        report, verdicts = pv.readiness(rec, rows, out)
        self.assertEqual(verdicts, {"source": "NOT_READY", "binary": "NOT_READY"})
        self.assertIn("LIC: no licence chosen", report)
        self.assertIn("not a legal review", report)
        self.assertNotIn("DRIVER", report)   # latent: not yet applicable

    def test_resolved_obligation_that_returns(self):
        self.repo.append("README.md", "A clean-room implementation.\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "COMPLIANCE_ACTION_REQUIRED")
        self.assertIn("CLEAN is recorded resolved", self.reasons(out))

    def test_tracked_count_may_not_grow(self):
        self.repo.append("scripts/build.sh", "other=/home/dev/bin/other\n")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "COMPLIANCE_ACTION_REQUIRED")
        self.assertIn("PATHS has grown", self.reasons(out))

    def test_latent_obligation_fires_when_its_condition_appears(self):
        self.repo.write("src/driver.rs", "pub fn d() {}\n")
        self.repo.commit("merge the driver")
        out = self.repo.check()
        self.assertEqual(out.verdict(), "NEW_REVIEW_REQUIRED")
        self.assertIn("DRIVER now applies", self.reasons(out))

    def test_first_party_licence_stays_pending_and_blocks_release(self):
        rec = self.repo.rec()
        fires, why, _ = pv.detect(rec, next(o for o in rec.obligations if o["id"] == "LIC"), pv.tracked(rec))
        self.assertTrue(fires)
        self.assertIn("unknown-licensing", why)
        # A LICENSE file alone changes nothing: the classification is provenance.toml's.
        self.repo.write("LICENSE", "x\n")
        rec = self.repo.rec()
        self.assertTrue(pv.detect(rec, next(o for o in rec.obligations if o["id"] == "LIC"), pv.tracked(rec))[0])

    def test_fresh_checkout_without_a_crate_cache(self):
        os.environ["ABSD_CARGO_REGISTRY"] = ""
        os.environ["CARGO_HOME"] = str(Path(self.tmp.name) / "no-cargo-home")
        try:
            self.repo.append("src/bin/tool.rs", "fn later() {}\n")
            out = self.repo.check()
            self.assertEqual(out.verdict(), "UNCHANGED", self.reasons(out))
            self.assertTrue(any("dependency inventory not recomputed" in n for n in out.info))
            self.repo.add_dependency("libnew")
            self.assertEqual(self.repo.check().verdict(), "UNKNOWN")
        finally:
            os.environ["ABSD_CARGO_REGISTRY"] = str(self.repo.registry)
            del os.environ["CARGO_HOME"]

    # ---- notices and the full run

    def test_notice_bundle(self):
        out_dir = Path(self.tmp.name) / "bundle"
        count, missing, actions = pv.notices(self.repo.rec(), "image", out_dir, quiet=True)
        text = (out_dir / "NOTICES.md").read_text()
        self.assertTrue((out_dir / "licenses/liba-1.0.0/LICENSE-MIT").exists())
        self.assertTrue((out_dir / "licenses/vendor_old_/LICENSE").exists())
        self.assertFalse((out_dir / "licenses/libbuild-1.0.0").exists())     # build-only: not in the image
        self.assertIn("corresponding source must be offered", text)          # not satisfied by bundling
        self.assertIn("| vendor/old/** | example.org old 1.0 | MIT |", text)   # in-tree material, from provenance.toml
        self.assertIn("reproduce the notice", text)
        self.assertTrue(any("Bootloader" in m for m in missing))             # nothing fabricated for it
        self.assertIn("does not by itself satisfy", text)

    def test_c_ports_from_a_pinned_tarball(self):
        """A C port table (userland/PORTS.tsv) lists one shipped row per
        program, under the pinned upstream's licence, with the tarball digest;
        its names are not crate ports, and its notice reaches the bundle."""
        self.repo.write("userland/PIN", "# NAME VERSION URL SHA256 LICENSE\n"
                        "tools\t1.0\thttps://example.invalid/tools-1.0.tar.gz\tabc123\tMIT\n")
        self.repo.write("userland/PORTS.tsv", "# NAME UPSTREAM SOURCE BUILD GATED SHA256 BYTES\n"
                        "grep\ttools-1.0\tgrep.c\tabsd/grep\taa\tbb\t10\n")
        self.repo.write("userland/tools.LICENSE", "MIT text of tools\n")
        self.repo.write("scripts/image.py", 'PORTS = ["grep"]\n')
        self.repo.write("ports.tsv", "# crate version kind bin result\n")
        units = "\n".join([
            '  [[artifact.unit]]', '  name = "ports"', '  ports = "scripts/image.py:PORTS"', '  table = "ports.tsv"',
            '  lock = "pins/{crate}-{version}.Cargo.lock"',
            '  [[artifact.unit]]', '  name = "c-ports"', '  c_ports = "userland/PORTS.tsv"', '  pin = "userland/PIN"',
            '  notice_files = ["userland/tools.LICENSE"]', '  [[artifact.component]]', '  name = "Bootloader"'])
        config = self.repo.root / "provenance/config.toml"
        config.write_text(config.read_text().replace('  [[artifact.component]]\n  name = "Bootloader"', units, 1))
        rows = self.repo.rows()
        row = rows["tools-grep"]
        self.assertEqual((row["version"], row["origin"], row["use"], row["license"], row["elected"], row["texts"]),
                         ("1.0", "upstream-tarball", "linked", "MIT", "MIT", "tools.LICENSE"))
        self.assertIn("sha256:abc123", row["source"])
        self.assertTrue(pv.shipped(row))
        self.assertNotIn("grep", rows)                                         # not taken for a crate port
        out_dir = Path(self.tmp.name) / "bundle"
        pv.notices(self.repo.rec(), "image", out_dir, quiet=True)
        self.assertEqual((out_dir / "licenses/tools-grep-1.0/tools.LICENSE").read_text(), "MIT text of tools\n")
        self.repo.write("userland/PORTS.tsv", "grep\ttools-2.0\tgrep.c\tabsd/grep\taa\tbb\t10\n")
        rec = self.repo.rec()
        notes = pv.inventory(rec, rec.config["artifact"][0])[1]
        self.assertTrue(any("not a row of userland/PIN" in why for _, _, why in notes))

    def c_notice_record(self, notice_files):
        self.repo.write("userland/PIN", "sbase\t0.1\thttps://example.invalid/sbase.tar.gz\taa\tMIT\n"
                        "toybox\t0.8.15\thttps://example.invalid/toybox.tar.gz\tbb\t0BSD\n")
        self.repo.write("userland/PORTS.tsv", "grep\tsbase-0.1\tgrep.c\tbin/grep\taa\tbb\t10\n"
                        "hexdump\ttoybox-0.8.15\thexdump.c\tbin/hexdump\taa\tbb\t10\n")
        self.repo.write("notices/sbase/LICENSE", "sbase notice\n")
        self.repo.write("notices/toybox/LICENSE", "toybox notice\n")
        rec = self.repo.rec()
        rec.config["artifact"][0]["unit"].append(dict(name="c-ports", c_ports="userland/PORTS.tsv",
                                                   pin="userland/PIN", notice_files=notice_files))
        return rec

    def test_c_port_notices_are_selected_by_pinned_upstream(self):
        rec = self.c_notice_record({"sbase-0.1": ["notices/sbase/LICENSE"],
                                    "toybox-0.8.15": ["notices/toybox/LICENSE"]})
        output = Path(self.tmp.name) / "c-notices"
        pv.notices(rec, "image", output, quiet=True)
        for name, text in [("sbase-grep-0.1", "sbase notice\n"), ("toybox-hexdump-0.8.15", "toybox notice\n")]:
            directory = output / "licenses" / name
            self.assertEqual(sorted(p.name for p in directory.iterdir()), ["LICENSE"])
            self.assertEqual((directory / "LICENSE").read_text(), text)

    def test_c_port_notice_map_without_its_upstream_refuses(self):
        rec = self.c_notice_record({"sbase-0.1": ["notices/sbase/LICENSE"]})
        with self.assertRaisesRegex(pv.Problem, "no notices configured for toybox-0.8.15"):
            pv.notices(rec, "image", Path(self.tmp.name) / "unmapped", quiet=True)

    def test_unit_marked_unlisted_is_not_resolved(self):
        config = self.repo.root / "provenance/config.toml"
        config.write_text(config.read_text() + '''
[[artifact]]
name = "tests-only"
inventoried = false

  [[artifact.unit]]
  name = "elsewhere"
  lock = "missing/Cargo.lock"
  listed = false
  note = "its sources are not in this repository"
''')
        rec = self.repo.rec()
        artifact = next(a for a in rec.config["artifact"] if a["name"] == "tests-only")
        self.assertEqual(pv.compute_inventory(rec, artifact)[0], [])
        self.assertTrue(any(p.search("missing/Cargo.lock") for p in pv.named_locks(rec)))

    def test_source_release_is_compared_with_its_manifest(self):
        import types
        top = Path(self.tmp.name) / "release"
        (top / "part").mkdir(parents=True)
        (top / "part/file").write_text("one\n")
        git = lambda *args: subprocess.run(["git", "-C", str(top), "-c", "user.name=t", "-c", "user.email=t@t",
                                            *args], check=True, capture_output=True, text=True).stdout.strip()
        git("init", "-q")
        git("add", "-A")
        git("commit", "-qm", "release")
        rec = types.SimpleNamespace(root=top / "part")
        self.assertIsNone(pv.source_release(rec))
        tree = git("rev-parse", "HEAD:part")
        (top / "SOURCE-MANIFEST.toml").write_text(
            f'[release]\nid = "r1"\n[[component]]\npath = "part"\ntree = "{tree}"\n')
        self.assertEqual(pv.source_release(rec)[0], True)
        (top / "part/file").write_text("two\n")
        self.assertEqual(pv.source_release(rec)[0], False)
        # A development checkout beside a stray manifest is not a release.
        (top / "part/.git").write_text("gitdir: elsewhere\n")
        self.assertIsNone(pv.source_release(rec))
        (top / "part/.git").unlink()
        (top / "SOURCE-MANIFEST.toml").write_text('[release]\nid = "r1"\n[[component]]\npath = "other"\n')
        self.assertIsNone(pv.source_release(rec))

    def test_full_run_on_the_baseline(self):
        out, (report, verdicts) = pv.full(self.repo.rec(), Path(self.tmp.name) / "full")
        self.assertEqual(out.verdict(), "UNCHANGED", self.reasons(out))
        self.assertEqual(verdicts["binary"], "NOT_READY")
        self.assertIn("A. Files unchanged since the baseline", report)
        self.assertTrue((Path(self.tmp.name) / "full/READINESS.md").exists())

    def test_full_run_counts_what_the_review_did_not_cover(self):
        self.repo.append("src/bin/tool.rs", "fn later() {}\n")
        self.repo.commit("later work")
        _, (report, _) = pv.full(self.repo.rec(), Path(self.tmp.name) / "full")
        # The edited source file, and the two records committed after the baseline commit.
        self.assertIn("B. Files new or changed since the baseline, not covered by that review: 3.", report)


# ---- licence-policy gate: distribution closure, repository inventory, host tools

TAG = "SPDX" + "-License-Identifier"
import tomllib  # noqa: E402
# The fixtures validate expressions with this repository's pinned SPDX library.
SPDX_LIBRARY = tomllib.loads((Path(__file__).resolve().parent.parent / "provenance/config.toml").read_text())[
    "licence_policy"]["spdx_library"]


def spdx_library_toml(lib=SPDX_LIBRARY):
    out = "\n[licence_policy.spdx_library]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in lib.items() if k != "wheels")
    return out + "\n[licence_policy.spdx_library.wheels]\n" + "".join(f'"{k}" = "{v}"\n' for k, v in lib["wheels"].items())
FONT_SHA = "a" * 64

GATE_POLICY = """
[licence_policy]
allowed = ["MIT", "Apache-2.0", "BSD-3-Clause", "Apache-2.0 WITH LLVM-exception"]
denied = ["GPL-*", "LGPL-*", "AGPL-*", "MPL-*", "EPL-*"]
crate_registries = ["registry+https://example.invalid/index"]

[[licence_policy.pending]]
licence = "LicenseRef-test-notice"
users = "test"
obligations = "keep the notice"
decision = "awaiting owner"

[[licence_policy.exception]]
id = "GRUB"
component = "GRUB"
version = "host"
artifacts = ["image"]
source = "copied by grub-mkrescue"
licence = "GPL-3.0-or-later"
paths = ["media/notices.toml"]
markers = ["gpl"]
scope = "boot component, disclosed, source ships"
decision = "owner, test"

[[licence_policy.exception]]
id = "unifont-font"
component = "GNU Unifont"
version = "15.1.01"
artifacts = ["image"]
sha256 = "FONTSHA"
licence = "OFL-1.1"
paths = ["provenance/boot-font/unifont.NOTICE"]
markers = ["gpl"]
scope = "the boot font only, OFL-1.1 elected"
decision = "owner, test"

[[licence_policy.pin]]
path = "c/PIN"
licence_column = 3

[[licence_policy.host_tool]]
name = "QEMU"
licence = "GPL-2.0-only"
use = "boots test images"
obligation = "none while only run"

[[licence_policy.held]]
name = "board device tree"
licence = "GPL-2.0-only"
reason = "boots one board; not in the repository"
decision = "owner, test"

[[licence_policy.variant]]
name = "image with an extra program"
env = ["ABSD_TEST_VARIANT"]
reason = "its closure is not resolved here"

[[licence_policy.marker_exempt]]
path = "provenance/config.toml"
record = true
reason = "the policy table itself"

[[licence_policy.marker_exempt]]
path = "provenance.toml"
record = true
reason = "judged structurally"

[[licence_policy.marker_exempt]]
path = "provenance/inventory/*.tsv"
record = true
reason = "generated inventory"

[[licence_policy.marker_exempt]]
path = "provenance/baseline/*.tsv"
record = true
reason = "historical record"
""".replace("FONTSHA", FONT_SHA) + spdx_library_toml()

UNIFONT = f"""
  [[artifact.component]]
  name = "GNU Unifont"
  version = "15.1.01"
  origin = "host-package"
  license = "OFL-1.1"
  use = "included"
  source = "unicode.pf2 SHA256 {FONT_SHA}"
  notice_files = ["provenance/boot-font/unifont.NOTICE"]
"""

ELECTION = """
[[licence_policy.election]]
component = "libdual"
versions = ["1.0.0"]
expression = "Apache-2.0 OR GPL-2.0-only"
elected = "Apache-2.0"
decision = "owner, test"
"""

MEMBERS = "member\tlinked_by\tinput\tlabel\tlicence\tuse\tsha256\n"


class LicenceGateCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repo(self.tmp.name)
        self.archives = Path(self.tmp.name) / "archives"
        self.archives.mkdir()
        os.environ["ABSD_CRATE_ARCHIVES"] = str(self.archives)
        for name in ("ABSD_TEST_VARIANT", "ABSD_PROVENANCE_PEER"):
            os.environ.pop(name, None)
        config = (self.repo.root / "provenance/config.toml").read_text()
        config = config.replace('name = "Bootloader"\n  version = "host"\n',
                                'name = "GRUB"\n  version = "host"\n  source = "copied by grub-mkrescue"\n')
        config = config.replace('[[artifact]]\nname = "image"\n', '[[artifact]]\nname = "image"\ndistributed = true\n')
        config = config.replace("\n[shared_tools.sha256]", UNIFONT + GATE_POLICY + "\n[shared_tools.sha256]")
        self.repo.write("provenance/config.toml", config)
        self.repo.write("c/PIN", "# NAME VERSION LICENSE\nlibc\t1.0\tBSD-3-Clause\n")
        self.repo.write("media/notices.toml", 'GPL3 = "host:/usr/share/common-licenses/GPL-3"\n')
        self.repo.write("provenance/boot-font/unifont.NOTICE", "Dual licensed: GNU General Public License or OFL-1.1\n")
        self.repo.append("provenance.toml", '\n[[files]]\npath = ["c/**", "media/**", "docs/**"]\nclass = "first-party"\n'
                         'license = "pending"\n')
        self.seal()

    def tearDown(self):
        self.tmp.cleanup()
        for name in ("ABSD_CRATE_ARCHIVES", "ABSD_TEST_VARIANT", "ABSD_PROVENANCE_PEER"):
            os.environ.pop(name, None)

    def seal(self):
        """Give every fixture crate an archive and the lock its checksum, as
        crates.io and Cargo do; then refresh the inventory and commit."""
        import tarfile
        lock = (self.repo.root / "Cargo.lock").read_text()
        for crate in sorted(self.repo.registry.iterdir()):
            archive = self.archives / f"{crate.name}.crate"
            with tarfile.open(archive, "w:gz") as t:
                for f in sorted(crate.rglob("*")):
                    t.add(f, arcname=f"{crate.name}/{f.relative_to(crate)}", recursive=False)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            name, version = crate.name.rsplit("-", 1)
            lock = re.sub(rf'(name = "{re.escape(name)}"\nversion = "{re.escape(version)}"\nsource = "[^"]*"\n'
                          rf'checksum = )"[^"]*"', rf'\g<1>"{digest}"', lock)
        self.repo.write("Cargo.lock", lock)
        self.repo.update()
        if self.repo.git("status", "--porcelain").strip():
            self.repo.commit("sealed")

    def gate(self, full=False, seal=True):
        if seal:
            self.seal()
        return pv.licence_gate(self.repo.rec(), full=full)

    def fails(self, gate):
        """Failures and gating obligations, and what the report-only
        obligations detected (status DETECTED Ox): text to search."""
        detected = [i for i in gate.items if i[0] == "obligation" and i[1].startswith("DETECTED")]
        return " | ".join(" ".join(map(str, f[1:])) for f in gate.fails() + detected)

    def entries(self, gate, scope, status):
        return [i for i in gate.items if i[0] == scope and i[1] == status]

    def members(self, table_rows, **receipt):
        """A member table with its sealed receipt, bound to c/PIN."""
        rows = table_rows
        table = MEMBERS + "".join("\t".join(r) + "\n" for r in rows)
        self.repo.write("c/MEMBERS.tsv", table)
        coverage = {}
        for r in rows:
            coverage[r[0]] = coverage.get(r[0], 0) + 1
        body = {"table_sha256": hashlib.sha256(table.encode()).hexdigest(), "rows": len(rows), "source_sha256": "5" * 64,
                "member_count": len(coverage), "members": sorted(coverage), "coverage": coverage,
                "bound_files": {"c/PIN": hashlib.sha256((self.repo.root / "c/PIN").read_bytes()).hexdigest()}}
        body.update(receipt)
        raw = json.dumps(body, indent=1, sort_keys=True) + "\n"
        self.repo.write("c/MEMBERS.receipt.json", raw)
        self.repo.append("provenance/config.toml", '\n[[licence_policy.member_table]]\npath = "c/MEMBERS.tsv"\n'
                         'artifact = "image"\nname = "libc"\nversion = "1.0"\ncomponent = "libc members"\n'
                         'receipt = "c/MEMBERS.receipt.json"\n'
                         f'receipt_sha256 = "{hashlib.sha256(raw.encode()).hexdigest()}"\n')
        return table

    # ---- the policy and its exceptions

    def test_policy_passes_with_the_grub_and_unifont_exceptions(self):
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        allowed = " ".join(" ".join(map(str, i)) for i in self.entries(gate, "distribution", "allowed"))
        self.assertIn("exception GRUB", allowed)
        self.assertIn("exception unifont-font", allowed)
        self.assertIn("media/notices.toml:1 gpl wording", allowed)
        self.assertIn("provenance/boot-font/unifont.NOTICE:1 gpl wording", allowed)
        self.assertEqual(gate.closure["distributed artifacts"], "image")
        self.assertEqual([i[3] for i in gate.items if i[0] == "host"], ["QEMU"])
        self.assertEqual([i[3] for i in self.entries(gate, "inventory", "held")], ["board device tree"])

    def test_exceptions_are_bound_to_the_component_identity(self):
        config = (self.repo.root / "provenance/config.toml").read_text()
        for old, new in (('version = "15.1.01"\n  origin', 'version = "15.1.02"\n  origin'),          # another version
                         (f'source = "unicode.pf2 SHA256 {FONT_SHA}"', 'source = "unicode.pf2 SHA256 ' + "b" * 64 + '"'),
                         ('name = "GRUB"\n  version = "host"', 'name = "Bootloader"\n  version = "host"')):
            self.repo.write("provenance/config.toml", config.replace(old, new, 1))
            self.assertFalse(self.gate().ok(), old)
        self.repo.write("provenance/config.toml", config.replace('artifacts = ["image"]\nsha256', 'artifacts = ["other"]\nsha256'))
        self.assertIn("not this version, artifact and source identity", self.fails(self.gate()))

    def test_a_path_exception_covers_each_named_path_only(self):
        self.repo.write("src/font.rs", "pub fn f() {}\n")
        self.repo.append("provenance.toml", '\n[[files]]\npath = ["provenance/boot-font/unifont.NOTICE", "src/font.rs"]\n'
                         'class = "imported"\norigin = "font"\nlicense = "OFL-1.1"\n')
        reasons = self.fails(self.gate())
        self.assertIn("src/font.rs", reasons)
        self.assertNotIn("unifont.NOTICE [font] OFL-1.1", reasons)
        self.repo.append("REUSE.toml", '\n[[annotations]]\npath = ["provenance/boot-font/unifont.NOTICE", "src/other.rs"]\n'
                         'SPDX-License-Identifier = "OFL-1.1"\n')
        reasons = self.fails(self.gate())
        self.assertIn("annotation for src/other.rs", reasons)
        self.assertNotIn("annotation for provenance/boot-font/unifont.NOTICE", reasons)

    def test_adapted_from_lgpl_and_labelled_apache_fails(self):
        # The TinyCC pattern: a recorded decision and a permissive label do not waive the upstream's terms.
        self.repo.write("tcc/patches/one.patch", "--- a/tccelf.c\n+++ b/tccelf.c\n")
        self.repo.append("provenance.toml", '\n[[files]]\npath = "tcc/patches/*.patch"\nclass = "adapted"\n'
                         'origin = "TinyCC mob"\nupstream-license = "LGPL-2.1-or-later"\n'
                         'decision = "owner ruling: staging only"\nlicense = "Apache-2.0"\n')
        gate = self.gate()
        (_, status, where, component, licence, rule), = [f for f in gate.fails() if f[4].startswith("upstream-license")]
        self.assertRegex(where, r"^provenance\.toml:\d+$")
        self.assertIn("tcc/patches/*.patch", component)
        self.assertEqual(licence, "upstream-license = LGPL-2.1-or-later (labelled Apache-2.0)")
        self.assertIn("keeps its upstream terms", rule)
        self.assertIn("decision does not waive", rule)
        self.assertIn("derived code is labelled", self.fails(gate))

    def test_derived_code_keeps_its_upstream_label(self):
        self.repo.write("src/derived.rs", "pub fn d() {}\n")
        self.repo.append("provenance.toml", '\n[[files]]\npath = "src/derived.rs"\nclass = "adapted"\n'
                         'origin = "example"\nupstream-license = "MIT"\nlicense = "Apache-2.0"\n')
        self.assertIn("derived code is labelled with terms other than its upstream's", self.fails(self.gate()))
        text = (self.repo.root / "provenance.toml").read_text()
        self.repo.write("provenance.toml", text[:text.rindex('license = "Apache-2.0"')]
                        + 'license = "MIT"\nfirst-party-portion = "Apache-2.0"\n')
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))

    # ---- the closure

    def test_dormant_denied_dependency_is_reported_not_failed(self):
        self.repo.crate("libunix", "1.0.0", "MPL-2.0")            # cfg(unix) is false for the target
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        (_, _, where, component, licence, why), = self.entries(gate, "inventory", "denied")
        self.assertEqual((where, component, licence), ("Cargo.lock", "libunix 1.0.0", "MPL-2.0"))

    def test_a_dependency_no_binary_source_names_is_still_in_the_closure(self):
        # libunused is named only by a binary that is not installed: every
        # normal dependency of the package can be linked into each binary.
        self.repo.crate("libunused", "1.0.0", "MPL-2.0")
        self.assertIn("libunused 1.0.0", self.fails(self.gate()))

    def test_denied_dependency_in_the_closure_fails(self):
        self.repo.add_dependency("liblgpl", license_="LGPL-2.1-or-later")
        gate = self.gate()
        self.assertIn("liblgpl 1.0.0", self.fails(gate))
        self.assertIn("LGPL-2.1-or-later (LGPL-*)", self.fails(gate))

    def test_closure_crates_are_verified_against_their_lock_checksum(self):
        self.repo.add_dependency("libsealed")
        self.seal()
        lock = (self.repo.root / "Cargo.lock").read_text()
        digest = hashlib.sha256((self.archives / "libsealed-1.0.0.crate").read_bytes()).hexdigest()
        self.repo.write("Cargo.lock", lock.replace(digest, "0" * 64))
        self.repo.update()
        self.repo.commit("wrong checksum")
        self.assertIn("sha256 differs from the checksum", self.fails(self.gate(seal=False)))
        self.repo.write("Cargo.lock", lock)
        self.repo.update()
        self.repo.commit("right checksum")
        self.repo.crate("libsealed", "1.0.0", "MIT", deps="x = \"1\"")   # the source no longer matches its archive
        self.assertIn("manifest differs from the verified archive", self.fails(self.gate(seal=False)))

    def test_every_lock_identity_of_a_crate_is_verified(self):
        # Round 2: a zeroed checksum in one lock was hidden by another lock's
        # row for the same name and version.
        self.repo.add_dependency("libsealed")
        self.seal()
        rec = self.repo.rec()
        policy = rec.config["licence_policy"]
        good = hashlib.sha256((self.archives / "libsealed-1.0.0.crate").read_bytes()).hexdigest()
        row = {"component": "libsealed", "version": "1.0.0", "use": "linked", "origin": "registry",
               "_ids": {("a/Cargo.lock", "registry+https://example.invalid/index", good),
                        ("b/Cargo.lock", "registry+https://example.invalid/index", "0" * 64)}}
        gate = pv.LicenceGate(False)
        pv.pre_crates(rec, policy, [({"name": "image"}, [row])], gate)
        self.assertIn("conflicting checksums across locks", self.fails(gate))
        row["_ids"] = {("b/Cargo.lock", "registry+https://example.invalid/index", "0" * 64)}
        gate = pv.LicenceGate(False)
        pv.pre_crates(rec, policy, [({"name": "image"}, [row])], gate)
        self.assertIn("sha256 differs from the checksum", self.fails(gate))
        # Every identity is checked, not the first: here the second names another registry.
        row["_ids"] = {("a/Cargo.lock", "registry+https://example.invalid/index", good),
                       ("b/Cargo.lock", "registry+https://elsewhere.invalid/index", good)}
        gate = pv.LicenceGate(False)
        pv.pre_crates(rec, policy, [({"name": "image"}, [row])], gate)
        self.assertIn("unsupported source registry+https://elsewhere.invalid/index", self.fails(gate))

    def test_crate_verification_is_cached_by_full_identity(self):
        # Round 2: a correct checksum, then a wrong one, both passed.
        self.repo.add_dependency("libsealed")
        self.seal()
        check = pv.crate_archives(self.repo.rec(), {})
        good = hashlib.sha256((self.archives / "libsealed-1.0.0.crate").read_bytes()).hexdigest()
        self.assertIsNone(check("libsealed", "1.0.0", good))
        self.assertIn("sha256 differs", check("libsealed", "1.0.0", "0" * 64))

    def test_the_spdx_library_is_a_pinned_policy_input(self):
        config = (self.repo.root / "provenance/config.toml").read_text()
        base = self.repo.git("rev-parse", "HEAD").strip()
        name, wheel = next((k, v) for k, v in SPDX_LIBRARY["wheels"].items() if k.startswith("license_expression-"))
        for old, new in ((f'"{name}" = "{wheel}"', f'"{name}" = "{"9" * 64}"'),
                         (f'spdx_license_list_version = "{SPDX_LIBRARY["spdx_license_list_version"]}"',
                          'spdx_license_list_version = "9.99"')):
            with self.subTest(changed=new):
                pv._SPDX.clear()
                self.repo.write("provenance/config.toml", config.replace(old, new))
                gate = self.gate()
                if "9.99" in new:   # database consistency is reported, not gated (review round 3)
                    self.assertIn("DETECTED S", self.fails(gate))
                    self.assert_reported(gate, "S")
                else:               # the wheel's own sha256 gates
                    self.assertIn("UNMET O1", self.fails(gate))
                    self.assertTrue(gate.verdict().startswith("NO CLAIM"))
                out = pv.check(self.repo.rec(), base)
                self.assertIn("SPDX library policy input changed", " ".join(i[2] for i in out.items))
        pv._SPDX.clear()

    REPORTED = {"O2": "O2 evidence completeness", "O3": "O3 identities", "O4": "O4 notices", "O5": "O5 composition",
                "C": "collector completeness", "S": "SPDX database consistency"}

    def assert_reported(self, gate, *oids):
        """Each report-only obligation is listed UNVERIFIED in the verdict and
        in the report rows, whatever was detected; none is part of a PASS."""
        verdict = gate.verdict()
        rows = [r for r in gate.rows() if r[0] == "obligation" and r[1].startswith("UNVERIFIED")]
        for oid in oids or self.REPORTED:
            self.assertIn(self.REPORTED[oid], verdict)
            self.assertIn(f"UNVERIFIED {oid}", [r[1] for r in rows])

    def test_report_only_obligations_are_listed_unverified_on_passing_inputs(self):
        # Round 3: every mode set to report on passing inputs printed a plain PASS.
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertTrue(gate.verdict().startswith("PASS (scope: expression validity and declared-licence policy; "
                                                  "UNVERIFIED: "))
        self.assert_reported(gate)
        self.assertNotIn("DETECTED", " ".join(i[1] for i in gate.items))
        self.assertNotEqual(gate.verdict(), "PASS")

    def test_r3_intra_lock_source_overwrite_is_reported_unverified(self):
        # Round 3, KNOWN-UNVERIFIED: a second stanza of one name and version
        # with another source inside one lock is overwritten before checking.
        lock = (self.repo.root / "Cargo.lock").read_text()
        self.repo.write("Cargo.lock", lock.replace('[[package]]\nname = "libinner"',
                        '[[package]]\nname = "libinner"\nversion = "1.0.0"\nsource = "registry+https://other.invalid/index"\n'
                        'checksum = "' + "0" * 64 + '"\n\n[[package]]\nname = "libinner"', 1))
        self.repo.update()
        self.repo.commit("second source")
        self.assert_reported(self.gate(seal=False), "O2")

    def test_r3_collector_omission_is_reported_unverified(self):
        # Round 3, KNOWN-UNVERIFIED: a consumed input left out of the
        # dependency list, the table resealed, passes the byte checks.
        self.members([("a.o", "tool", "src/a.c", "B", "BSD-3-Clause", "consumed", "0")])
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assert_reported(gate, "C", "O2")

    def test_r3_exception_hash_elsewhere_in_the_source_is_reported_unverified(self):
        # Round 3, KNOWN-UNVERIFIED: the accepted font hash kept elsewhere in a
        # changed source description still matches the Unifont exception.
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace(f'source = "unicode.pf2 SHA256 {FONT_SHA}"',
                        f'source = "unicode.pf2 SHA256 {"b" * 64} (was {FONT_SHA})"'))
        gate = self.gate()
        self.assert_reported(gate, "O3")

    def test_r3_acknowledgement_removal_is_reported_unverified(self):
        # Round 3, KNOWN-UNVERIFIED: acknowledgement fields and their notice
        # lines removed together, resealed, while the decision remains.
        self.notice_table(self.NOTICE.replace("This product includes work of Example Labs.\n", ""), acknowledgement=None)
        gate = self.gate()
        self.assert_reported(gate, "O4")

    def test_r3_nested_peer_composition_is_reported_unverified(self):
        # Round 3, KNOWN-UNVERIFIED: a nested peer run skips composition and
        # can pass a cross-repository component without a paired record.
        self.kernel_component("1" * 40)
        gate = pv.licence_gate(self.repo.rec(), nested=True)
        self.assert_reported(gate, "O5")

    def test_open_owner_conditions_are_printed(self):
        self.notice_table(self.NOTICE)
        gate = self.gate()
        self.assertIn("OPEN: release-document acknowledgements", gate.verdict())
        self.assertIn(("condition", "OPEN"), [r[:2] for r in gate.rows()])

    def test_the_counterexample_corpus_is_covered(self):
        corpus = tomllib.loads((Path(__file__).resolve().parent / "provenance-counterexamples.toml").read_text())
        here = Path(__file__).resolve().parent
        for case in corpus["case"]:
            with self.subTest(case=case["id"]):
                self.assertTrue(case["description"] and case["round"] in (1, 2, 3))
                if case["round"] == 3:
                    self.assertEqual(case["status"], "KNOWN-UNVERIFIED")
                    self.assertTrue(case["obligation"] and case["test"])
                if case.get("test"):
                    path = here / case["file"]
                    if path.is_file():
                        self.assertIn(f"def {case['test']}(", path.read_text())

    def test_registry_variable_adds_to_the_default_search_list(self):
        home = Path(self.tmp.name) / "cargo"
        (home / "registry/src/index.example").mkdir(parents=True)
        old = os.environ.get("CARGO_HOME")
        os.environ["CARGO_HOME"] = str(home)
        try:
            found = pv.registries({})
        finally:
            os.environ.pop("CARGO_HOME") if old is None else os.environ.__setitem__("CARGO_HOME", old)
        self.assertEqual(found, [str(self.repo.registry), str(home / "registry/src/index.example")])

    def test_an_election_must_be_recorded_for_exactly_this_version(self):
        self.repo.add_dependency("libdual", license_="Apache-2.0 OR GPL-2.0-only")
        self.assertIn("election not recorded", self.fails(self.gate()))
        self.repo.append("provenance/config.toml", ELECTION.replace('versions = ["1.0.0"]', 'versions = ["0.9.0"]'))
        self.assertIn("election not recorded", self.fails(self.gate()))
        config = (self.repo.root / "provenance/config.toml").read_text().replace('versions = ["0.9.0"]', 'versions = ["1.0.0"]')
        self.repo.write("provenance/config.toml", config.replace('elected = "Apache-2.0"\ndecision = "owner, test"\n',
                                                                 'elected = "GPL-2.0-only"\ndecision = "owner, test"\n'))
        self.assertIn("election not recorded", self.fails(self.gate()))
        self.repo.write("provenance/config.toml", config)
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertTrue(any("libdual 1.0.0" in i[3] and "elected Apache-2.0; owner, test" in i[5]
                            for i in self.entries(gate, "distribution", "allowed")))

    def test_a_dormant_election_is_reported(self):
        self.repo.crate("libunix", "1.0.0", "MIT OR LGPL-2.1-or-later")
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertEqual([i[3] for i in self.entries(gate, "inventory", "unrecorded-election")], ["libunix 1.0.0"])

    def test_unknown_in_the_closure_fails_and_outside_it_is_reported(self):
        shutil.rmtree(self.repo.registry / "libunix-1.0.0")       # not built for the image
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertIn("libunix 1.0.0", [i[3] for i in self.entries(gate, "inventory", "unknown")])
        self.repo.add_dependency("libmissing")
        self.seal()
        shutil.rmtree(self.repo.registry / "libmissing-1.0.0")
        gate = self.gate(seal=False)
        self.assertIn("FAIL", [f[1] for f in gate.fails()])               # an unknown licence fails the judgement
        self.assertIn("libmissing 1.0.0", self.fails(gate))
        self.assertTrue(gate.verdict().startswith("FAIL"))

    def test_unlisted_units_cannot_be_distributed(self):
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace('  bins = ["tool"]\n',
                        '  bins = ["tool"]\n  [[artifact.unit]]\n  name = "hidden"\n  lock = "Cargo.lock"\n  listed = false\n'))
        self.assertIn("listed = false units are never resolved", self.fails(self.gate()))

    def test_an_uncovered_variant_is_refused_while_selected(self):
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertEqual([i[3] for i in self.entries(gate, "inventory", "variant-not-covered")], ["image with an extra program"])
        os.environ["ABSD_TEST_VARIANT"] = "1"
        self.assertIn("selects a build variant whose closure the gate does not resolve", self.fails(self.gate()))

    def kernel_component(self, commit):
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace(UNIFONT, UNIFONT + f"""
  [[artifact.component]]
  name = "kernel"
  version = "pinned"
  origin = "first-party"
  license = ""
  use = "included"
  cross_repository = "absd-kernel"
  paired_artifact = "kernel-image"
  incorporated_commit = "{commit}"
  paired_audit = "provenance/paired/kernel.toml"
"""))

    def paired_record(self, revision, **changes):
        pins = pv.Records(self.repo.root).config["shared_tools"]["sha256"]
        fields = {"repository": "absd-kernel", "commit": revision, "artifact": "kernel-image", "gate": "PASS",
                  "inventory_sha256": "2" * 64, "recorded": "test"}
        fields.update(changes)
        self.repo.write("provenance/paired/kernel.toml", "".join(f'{k} = "{v}"\n' for k, v in fields.items())
                        + "[shared_tools]\n" + "".join(f'"{k}" = "{v}"\n' for k, v in pins.items()))

    def test_a_cross_repository_component_needs_a_matching_paired_audit(self):
        commit = "1" * 40
        self.kernel_component(commit)
        self.assertIn("without a paired-audit record", self.fails(self.gate()))
        for changes, expect in (({"gate": "FAIL 2"}, "gate recorded FAIL 2"),
                                ({"repository": "absd-other"}, "the record is for absd-other"),
                                ({"artifact": "other-image"}, "the record audits other-image"),
                                ({"commit": "f" * 40}, "not the component's incorporated_commit")):   # round 2: fabricated
            with self.subTest(expect=expect):
                self.paired_record(commit, **changes)
                reasons = self.fails(self.gate())
                self.assertIn("DETECTED O3", reasons)
                self.assertIn(expect, reasons)
        self.paired_record(commit)
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertIn("no peer given", gate.verdict())                    # not compared without a peer
        self.assert_reported(gate, "O5")
        # Another kernel identity (the qualification default) is listed as distinct, never as covered.
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace('  paired_audit = "provenance/paired/kernel.toml"\n',
                        '  paired_audit = "provenance/paired/kernel.toml"\n  distinct_identities = [{ commit = "'
                        + "a" * 40 + '", role = "check-all default" }]\n'))
        gate = self.gate()
        self.assertIn(f"{'a' * 40} (check-all default) is a different identity from the paired audit's {commit}",
                      self.fails(gate))
        self.assert_reported(gate, "O3")

    def test_a_peer_must_be_another_repository_at_the_recorded_revision(self):
        self.kernel_component("1" * 40)
        self.paired_record("1" * 40)
        self.seal()
        # Round 2: this repository given as its own peer.
        self.assertIn("the peer is this repository", self.fails(pv.licence_gate(self.repo.rec(), peer=self.repo.root)))
        clone = Path(self.tmp.name) / "clone"                            # another checkout of this repository
        subprocess.run(["git", "clone", "-q", str(self.repo.root), str(clone)], check=True)
        self.assertIn("the peer is this repository", self.fails(pv.licence_gate(self.repo.rec(), peer=clone)))
        (Path(self.tmp.name) / "peer").mkdir()
        registry = os.environ["ABSD_CARGO_REGISTRY"]
        peer = Repo(Path(self.tmp.name) / "peer")
        os.environ["ABSD_CARGO_REGISTRY"] = registry
        peer.write("provenance/config.toml", (peer.root / "provenance/config.toml").read_text()
                   .replace('repository = "demo"', 'repository = "absd-kernel"'))
        peer.commit("kernel")
        reasons = self.fails(pv.licence_gate(self.repo.rec(), peer=peer.root))
        self.assertIn("the peer is at", reasons)                         # not the recorded revision
        head = peer.git("rev-parse", "HEAD").strip()
        self.kernel_component(head)
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace(f'incorporated_commit = "{"1" * 40}"\n', ""))
        self.paired_record(head)
        self.seal()
        reasons = self.fails(pv.licence_gate(self.repo.rec(), peer=peer.root))
        self.assertIn("the peer's distribution gate does not pass now", reasons)

    def test_inventory_reporting_lists_allowed_entries_and_full_writes_them(self):
        gate = self.gate()
        self.assertIn("libunix 1.0.0", [i[3] for i in self.entries(gate, "inventory", "allowed")])
        self.assertIn(("c/PIN:2", "libc 1.0"), [(i[2], i[3]) for i in self.entries(gate, "inventory", "allowed")])
        self.assertIn("liba 1.0.0", [i[3] for i in self.entries(gate, "distribution", "allowed")])
        import contextlib
        import io
        out = Path(self.tmp.name) / "fullout"
        with contextlib.redirect_stdout(io.StringIO()):
            pv.main(["--root", str(self.repo.root), "full", "--out", str(out)])
        report = (out / "licence-report.tsv").read_text()
        self.assertIn("inventory\tallowed\tCargo.lock\tlibunix 1.0.0\tMIT", report)
        self.assertIn("distribution\tallowed", report)

    # ---- member tables

    def test_member_table_rows_are_judged(self):
        self.members([("a.o", "tool", "src/a.c", "B", "BSD-3-Clause", "consumed", "0"),
                      ("a.o", "tool", "src/b.h", "L", "LGPL-2.1-or-later", "consumed", "0")])
        (_, _, where, component, licence, rule), = self.gate().fails()
        self.assertEqual((where, licence), ("c/MEMBERS.tsv", "LGPL-2.1-or-later"))
        self.assertIn("1 linked member(s), 1 input(s): a.o<-src/b.h", component)

    def test_a_probe_is_recorded_not_judged_as_source(self):
        self.members([("a.o", "tool", "src/a.c", "B", "BSD-3-Clause", "consumed", "0"),
                      ("a.o", "tool", "host:/usr/include/limits.h", "host", "LGPL-2.1-or-later", "probe", "0")])
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertEqual([i[3] for i in self.entries(gate, "distribution", "probe")], ["a.o<-host:/usr/include/limits.h"])

    def test_member_table_elections_and_pending_terms(self):
        self.members([("a.o", "tool", "src/a.c", "X", "MIT OR GPL-3.0-only", "consumed", "0"),
                      ("b.o", "tool", "src/b.c", "Y", "LicenseRef-test-notice", "consumed", "0")])
        reasons = self.fails(self.gate())
        self.assertIn("election not recorded", reasons)
        self.assertIn("pending owner acceptance: LicenseRef-test-notice", reasons)

    def test_a_member_table_must_match_its_sealed_receipt(self):
        rows = [("a.o", "tool", "src/a.c", "B", "BSD-3-Clause", "consumed", "0"),
                ("b.o", "tool", "src/b.c", "B", "BSD-3-Clause", "consumed", "0")]
        table = self.members(rows)
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        for altered, expect in ((MEMBERS, "differs from the sha256"),                         # header only
                                (table.rsplit("b.o", 1)[0], "differs from the sha256")):       # truncated
            self.repo.write("c/MEMBERS.tsv", altered)
            self.assertIn(expect, self.fails(self.gate()))
        self.repo.write("c/MEMBERS.tsv", table)
        self.repo.append("c/PIN", "other\t2.0\tMIT\n")                                         # stale inputs
        self.assertIn("c/PIN changed since the table was generated", self.fails(self.gate()))

    def test_a_receipt_must_agree_with_its_table(self):
        rows = [("a.o", "tool", "src/a.c", "B", "BSD-3-Clause", "consumed", "0"),
                ("b.o", "tool", "src/b.c", "B", "BSD-3-Clause", "consumed", "0")]
        self.members(rows, rows=3)
        self.assertIn("2 row(s) and 2 member(s); the receipt states 3 and 2", self.fails(self.gate()))
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config[:config.rindex("\n[[licence_policy.member_table]]")] + "\n")
        self.members(rows, member_count=1)
        self.assertIn("the receipt states 2 and 1", self.fails(self.gate()))
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config[:config.rindex("\n[[licence_policy.member_table]]")] + "\n")
        self.members(rows, coverage={"a.o": 2})
        self.assertIn("per-member input counts differ", self.fails(self.gate()))

    COPYING = ("Files: src/a.c\nCopyright: Example Labs\nLicense: Ack\n\nFiles: src/b.c\nCopyright: B\nLicense: B\n\n"
               "License: Ack\n Use freely;\n acknowledge Example Labs.\n\nLicense: B\n Three clauses.\n")
    SOURCES = {"src/a.c": "/* (c) Example Labs */\nint a;\n", "src/b.c": "/* (c) B */\nint b;\n"}
    ACK = "This product includes work of Example Labs."
    NOTICE = ("== ACKNOWLEDGEMENTS\nThis product includes work of Example Labs.\n\n"
              "== LABEL Ack\nUse freely;\nacknowledge Example Labs.\n\n-- FILE src/a.c\n/* (c) Example Labs */\n\n"
              "== LABEL B\nThree clauses.\n\n-- FILE src/b.c\n/* (c) B */\n")

    def notice_table(self, notice, archive=True, table_notice=True, **policy):
        """A member table whose linked members need a distribution notice,
        verified against a pinned source archive."""
        import tarfile
        src = Path(self.tmp.name) / "src.tar.gz"
        with tarfile.open(src, "w:gz") as t:
            for name, text in {"COPYING.picolibc": self.COPYING, **self.SOURCES}.items():
                data = text.encode()
                info = tarfile.TarInfo(f"pkg/{name}")
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        digest = hashlib.sha256(src.read_bytes()).hexdigest()
        if not archive:
            src.unlink()
        rows = [("a.o", "tool", "src/a.c", "Ack", "LicenseRef-test-ack", "consumed",
                 hashlib.sha256(self.SOURCES["src/a.c"].encode()).hexdigest()),
                ("b.o", "tool", "src/b.c", "B", "BSD-3-Clause", "consumed", "0")]
        texts = {"Ack": "Use freely; acknowledge Example Labs.", "B": "Three clauses."}
        self.repo.write("c/LABELS.tsv", "".join(f"{k}\t{hashlib.sha256(v.encode()).hexdigest()}\tx\ty\n"
                                                for k, v in texts.items()))
        self.repo.write("c/NOTICES.txt", notice)
        self.members(rows, source_sha256=digest, notice="c/NOTICES.txt",
                     notice_sha256=hashlib.sha256(notice.encode()).hexdigest())
        if table_notice:
            self.repo.append("provenance/config.toml", f'notice = "c/NOTICES.txt"\nlabels = "c/LABELS.tsv"\n'
                             f'source_archives = ["{src}"]\n')
        accepted = {"licence": "LicenseRef-test-ack", "member_table": "c/MEMBERS.tsv", "name": "libc", "version": "1.0",
                    "source_sha256": digest, "conditions": "notice and acknowledgement", "decision": "owner, test",
                    "acknowledgement": self.ACK}
        accepted.update(policy)
        toml = lambda v: ("{ " + ", ".join(f"{json.dumps(k)} = {json.dumps(x)}" for k, x in v.items()) + " }"
                          if isinstance(v, dict) else json.dumps(v))
        self.repo.append("provenance/config.toml", "\n[[licence_policy.accepted]]\n" + "".join(
            f'{k} = {toml(v)}\n' for k, v in accepted.items() if v is not None))

    def test_accepted_terms_with_their_notice_pass(self):
        self.notice_table(self.NOTICE)
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertEqual([i[3] for i in self.entries(gate, "distribution", "accepted")], ["a.o<-src/a.c"])

    def test_accepted_terms_are_bound_to_their_table_version_and_source(self):
        for field, value in (("version", "2.0"), ("source_sha256", "6" * 64), ("member_table", "c/OTHER.tsv")):
            with self.subTest(field=field):
                self.tearDown()
                self.setUp()
                self.notice_table(self.NOTICE, **{field: value})
                self.assertIn("not on the allowed list: LicenseRef-test-ack", self.fails(self.gate()))
        self.tearDown()
        self.setUp()
        self.notice_table(self.NOTICE, conditions="")
        self.assertIn("DETECTED O3", self.fails(self.gate()))

    def test_a_linked_member_without_its_verified_notice_fails(self):
        cases = (
            (self.NOTICE.replace("-- FILE src/a.c\n/* (c) Example Labs */\n\n", ""), "ships src/a.c (Ack) without its notice entry"),
            (self.NOTICE.replace("This product includes work of Example Labs.\n", ""), "acknowledgement missing"),
            (self.NOTICE.replace("Use freely;", "Use as you like;"), "not the reviewed text for that label"),
            # Round 2: an emptied body under its marker, with a matching receipt digest.
            (self.NOTICE.replace("/* (c) Example Labs */\n", ""), "src/a.c: its notice body is not the file's header"),
            (self.NOTICE.replace("/* (c) Example Labs */", "/* (c) Someone Else */"), "src/a.c: its notice body is not"),
        )
        for notice, expect in cases:
            with self.subTest(expect=expect):
                self.tearDown()
                self.setUp()
                self.notice_table(notice)
                reasons = self.fails(self.gate())
                self.assertIn("DETECTED O4", reasons)
                self.assertIn(expect, reasons)

    def test_conditional_acceptance_requires_its_notice_inputs(self):
        # Round 2: a table with no `notice` disabled every notice check.
        self.notice_table(self.NOTICE, table_notice=False)
        self.assertIn("its accepted terms require a notice and a label map", self.fails(self.gate()))
        self.tearDown()
        self.setUp()
        self.notice_table(self.NOTICE, archive=False)
        self.assertIn("the pinned source archive is not available", self.fails(self.gate()))

    def test_an_interpretation_carries_its_terms_for_its_one_input(self):
        terms = (self.repo.root / "LICENSES/MIT.txt").read_text().strip("\n")
        with_terms = self.NOTICE.replace("acknowledge Example Labs.\n\n-- FILE src/a.c",
                                         f"acknowledge Example Labs.\n\n-- TERMS MIT (owner interpretation)\n{terms}\n\n-- FILE src/a.c")
        sha = hashlib.sha256(self.SOURCES["src/a.c"].encode()).hexdigest()
        self.notice_table(with_terms, inputs=["src/a.c"], input_sha256={"src/a.c": sha}, interpretation="MIT")
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertIn("interpreted as MIT", " ".join(i[5] for i in self.entries(gate, "distribution", "accepted")))
        for notice, kwargs, expect in (
                (self.NOTICE, {}, "terms of its interpretation are not in the notice"),
                (with_terms, {"input_sha256": {"src/a.c": "7" * 64}}, "not on the allowed list")):
            with self.subTest(expect=expect):
                self.tearDown()
                self.setUp()
                self.notice_table(notice, **{"inputs": ["src/a.c"], "input_sha256": {"src/a.c": sha},
                                             "interpretation": "MIT", **kwargs})
                self.assertIn(expect, self.fails(self.gate()))

    def test_the_notice_bundle_carries_the_member_notice_and_acknowledgements(self):
        self.notice_table(self.NOTICE)
        out = Path(self.tmp.name) / "bundle"
        pv.notices(self.repo.rec(), "image", out, quiet=True)
        self.assertEqual((out / "licenses/libc-1.0/NOTICES.txt").read_text(), self.NOTICE)
        self.assertIn("## Acknowledgements", (out / "NOTICES.md").read_text())
        self.assertIn("- This product includes work of Example Labs.", (out / "NOTICES.md").read_text())

    def test_a_reduced_table_with_a_reissued_receipt_fails_the_pin(self):
        self.members([("a.o", "tool", "src/a.c", "B", "BSD-3-Clause", "consumed", "0")])
        config = (self.repo.root / "provenance/config.toml").read_text()
        receipt = json.loads((self.repo.root / "c/MEMBERS.receipt.json").read_text())
        receipt.update(rows=0, member_count=0, members=[], coverage={},
                       table_sha256=hashlib.sha256(MEMBERS.encode()).hexdigest())
        self.repo.write("c/MEMBERS.tsv", MEMBERS)
        self.repo.write("c/MEMBERS.receipt.json", json.dumps(receipt))
        self.assertIn("receipt differs from the sha256 the policy pins", self.fails(self.gate()))
        self.repo.write("provenance/config.toml", config.replace('receipt_sha256 = "', 'receipt_ = "'))
        self.assertIn("without its sealed receipt", self.fails(self.gate()))

    # ---- tags, annotations, wording

    def test_expressions(self):
        policy = {"allowed": ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "LicenseRef-public-domain"],
                  "denied": ["GPL-*", "LGPL-*", "MPL-*"], "pending": [{"licence": "LicenseRef-x"}],
                  "spdx_library": SPDX_LIBRARY}
        self.assertEqual(pv.judge_licence("MIT OR LGPL-2.1-or-later", policy)[:2], (True, ["MIT"]))
        self.assertFalse(pv.judge_licence("MIT/Apache-2.0", policy)[0])                                  # not SPDX outside Cargo
        self.assertEqual(pv.judge_licence("Apache-2.0 WITH LLVM-exception", policy)[:2],
                         (True, ["Apache-2.0 WITH LLVM-exception"]))
        self.assertEqual(pv.judge_licence("LicenseRef-public-domain", policy)[:2], (True, ["LicenseRef-public-domain"]))
        self.assertEqual(pv.judge_licence("MIT/Apache-2.0", policy, cargo=True)[:2], (True, ["MIT"]))   # Cargo's legacy OR
        self.assertIn("GPL-*", pv.judge_licence("GPL-2.0-only WITH Classpath-exception-2.0", policy)[2])
        self.assertIn("LGPL-*", pv.judge_licence("MIT AND LGPL-2.1-only", policy)[2])
        self.assertIn("MPL-*", pv.judge_licence("GPL-2.0-only OR MPL-2.0", policy)[2])
        self.assertEqual(pv.judge_licence("Artistic-2.0", policy)[2], "not on the allowed list: Artistic-2.0")
        self.assertEqual(pv.judge_licence("LicenseRef-x", policy)[2], "pending owner acceptance: LicenseRef-x")
        for bad in ("MIT!", "MIT; GPL-2.0-only", "free for any use", "MIT, Apache-2.0", "(MIT GPL-3.0-only",
                    "(MIT OR Apache-2.0", "MIT)", "MIT AND", "Apache-2.0 WITH MIT", "NotALicence-1.0", "public domain"):
            with self.subTest(expression=bad):
                ok, taken, why = pv.judge_licence(bad, policy)
                self.assertEqual((ok, taken), (False, None))
                self.assertTrue(why.startswith("O1: "), why)
        self.assertEqual(pv.judge_licence("", policy)[2], "no licence recorded")
        # The local grammar the inventory falls back to never skips a token either.
        for bad in ("(MIT GPL-3.0-only", "(MIT OR Apache-2.0", "MIT)", "( )", "MIT AND", "MIT WITH OR"):
            with self.subTest(local=bad), self.assertRaises(ValueError):
                pv.local_license_tree(bad)

    def test_licence_tags_in_every_comment_form_and_file(self):
        self.repo.write("src/server.rs", f"// {TAG}: AGPL-3.0-only\npub fn s() {{}}\n")
        self.repo.write("src/doc.rs", f"//! {TAG}: Artistic-2.0\n")
        self.repo.write("src/lib.c", f"/* {TAG}: MIT */\n")
        self.repo.write("src/quote.py", f'TEXT = "// {TAG}: Artistic-2.0\\n"\n')       # a mention, not a tag
        self.repo.write("src/dual.rs", f"// {TAG}: MIT OR GPL-3.0-only\n")
        self.repo.write("LICENSES/MIT.txt", f"MIT text\n{TAG}: GPL-2.0-only\n")          # a licence text is no hiding place
        self.repo.append("c/PIN", f"# {TAG}: GPL-2.0-only\n")                            # nor a pin table
        where = [f[2] for f in self.gate().fails()]
        for path in ("src/server.rs:1", "src/doc.rs:1", "src/dual.rs:1", "LICENSES/MIT.txt:2", "c/PIN:3"):
            self.assertIn(path, where)
        self.assertNotIn("src/lib.c:1", where)
        self.assertNotIn("src/quote.py:1", where)

    def test_reuse_annotations_are_judged_from_the_parsed_file(self):
        self.repo.append("REUSE.toml", '\n[[annotations]]\npath = "src/quoted.rs"\n"SPDX-License-Identifier" = "GPL-2.0-only"\n')
        self.assertIn("annotation for src/quoted.rs", self.fails(self.gate()))

    def test_copyleft_wording_in_tracked_files(self):
        self.repo.write("src/notes.rs", "// line one\n// Licensed under the GNU Affero General Public License.\n")
        self.assertIn("src/notes.rs:2", [f[2] for f in self.gate().fails()])

    def test_discussion_documents_are_inventoried_not_failed(self):
        self.repo.write("docs/POLICY.md", "We never ship LGPL code.\n")
        self.assertIn("docs/POLICY.md:1", [f[2] for f in self.gate().fails()])
        self.repo.append("provenance/config.toml", '\n[[licence_policy.marker_exempt]]\npath = "docs/POLICY.md"\n')
        self.assertIn("an exemption needs a path and a reason", self.fails(self.gate()))
        self.repo.append("provenance/config.toml", 'reason = "describes the policy"\n')
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertEqual([i[2] for i in self.entries(gate, "inventory", "discussion")], ["docs/POLICY.md:1"])
        self.repo.append("docs/POLICY.md", f"<!-- {TAG}: GPL-3.0-only -->\n")            # never hides a licence tag
        self.assertIn("docs/POLICY.md:2", [f[2] for f in self.gate().fails()])

    def test_a_source_file_exemption_names_its_reviewed_lines(self):
        self.repo.write("src/fdt.rs", "//! the trees' inputs are GPL-2.0-only\nfn f() {}\n")
        self.repo.append("provenance/config.toml", '\n[[licence_policy.marker_exempt]]\npath = "src/fdt.rs"\n'
                         'reason = "a comment"\n')
        self.assertIn("for a source file name the reviewed lines", self.fails(self.gate()))
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace('path = "src/fdt.rs"\n',
                        'path = "src/fdt.rs"\nlines = { "1" = "//! the trees\' inputs are GPL-2.0-only" }\n'))
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.repo.append("src/fdt.rs", "// Licensed under the GNU Lesser General Public License\n")
        self.assertIn("src/fdt.rs:3", [f[2] for f in self.gate().fails()])
        self.repo.write("src/fdt.rs", "//! the trees' inputs are LGPL-2.1-only\nfn f() {}\n")
        self.assertIn("the reviewed line of a wording exemption changed", self.fails(self.gate()))

    # A verbatim upstream notice (owner decision 2026-11-01): one exact path
    # with pinned provenance; nothing else is exempted.
    UPSTREAM_COPYING = ("Files: scripts/cross.sh\nLicense: AGPL3\n\nLicense: AGPL3\n it under the terms of the GNU "
                        "Affero General Public License as\n published by the Free Software Foundation.\n")
    NOTICE_PATH = "provenance/linked-notices/libc-1.0/COPYING"

    def verbatim_notice(self, archive=True, member=None, declare=True, text=None, notice_path=None,
                        archive_member="libc-1.0/COPYING", classify="imported", extra=None, **fields):
        """The libc component's notice: COPYING carried verbatim from a pinned
        archive, classified imported, and its marker_exempt entry (the one
        reviewed tuple). EXTRA {path: text}: more files, each also an archive
        member, classified imported and declared as a notice, but no tuple."""
        extra = extra or {}
        import tarfile
        text = text or self.UPSTREAM_COPYING
        notice_path = notice_path or self.NOTICE_PATH
        data = text.encode()
        src = Path(self.tmp.name) / "libc-1.0.tar.gz"
        with tarfile.open(src, "w:gz") as t:
            body = (member if member is not None else text).encode()
            info = tarfile.TarInfo(archive_member)
            info.size = len(body)
            t.addfile(info, io.BytesIO(body))
            for other, content in extra.items():
                info = tarfile.TarInfo("libc-1.0/" + other)
                info.size = len(content.encode())
                t.addfile(info, io.BytesIO(content.encode()))
        digest = hashlib.sha256(src.read_bytes()).hexdigest()
        if not archive:
            src.unlink()
        self.repo.write(notice_path, text)
        for other, content in extra.items():
            self.repo.write(other, content)
        self.repo.write("c/SOURCES", f"# NAME VERSION SHA256\nlibc\t1.0\t{digest}\n")
        if classify:
            for one in [notice_path, *extra]:
                self.repo.append("provenance.toml", f'\n[[files]]\npath = "{one}"\nclass = "{classify}"\n'
                                 'origin = "libc 1.0 archive"\nlicense = "MIT"\n')
        if declare:
            self.repo.append("provenance/config.toml", '\n[[artifact.component]]\nname = "libc"\nversion = "1.0"\n'
                             'origin = "upstream-tarball"\nlicense = "BSD-3-Clause"\nuse = "linked"\n'
                             f'notice_files = {json.dumps([notice_path, *extra])}\n')
        up = {"pin": "c/SOURCES", "pin_row": "libc 1.0", "archive_sha256": digest, "member": archive_member,
              "sha256": hashlib.sha256(data).hexdigest(), "source_archives": [str(src)]}
        entry = {"path": notice_path, "reason": "upstream aggregate COPYING", "decision": "owner, test"}
        for k, v in fields.items():
            (up if k in up else entry)[k] = v
        up = {k: v for k, v in up.items() if v is not None}
        self.repo.append("provenance/config.toml", "\n[[licence_policy.marker_exempt]]\n" + "".join(
            f"{k} = {json.dumps(v)}\n" for k, v in entry.items() if v is not None)
            + "upstream = { " + ", ".join(f"{k} = {json.dumps(v)}" for k, v in up.items()) + " }\n")

    def test_a_verbatim_upstream_notice_is_listed_not_failed(self):
        self.verbatim_notice()
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertNotIn("DETECTED", self.fails(gate))
        listed = self.entries(gate, "inventory", "verbatim-notice")
        self.assertIn(f"{self.NOTICE_PATH}:5", [i[2] for i in listed])
        self.assertIn("libc-1.0/COPYING of libc 1.0 (c/SOURCES)", listed[0][5])

    def test_prohibited_code_still_fails_beside_a_verbatim_notice(self):
        self.verbatim_notice()
        self.repo.write("src/cross.rs", "// it under the terms of the GNU Affero General Public License as\n")
        self.repo.write("provenance/linked-notices/other/COPYING", self.UPSTREAM_COPYING.replace("libc", "other"))
        self.members([("a.o", "tool", "src/a.c", "L", "LGPL-2.1-or-later", "consumed", "0")])
        failed = [f[2] for f in self.gate().fails()]
        self.assertIn("src/cross.rs:1", failed)
        self.assertIn("provenance/linked-notices/other/COPYING:5", failed)
        self.assertIn("c/MEMBERS.tsv", failed)
        self.assertNotIn(f"{self.NOTICE_PATH}:5", failed)

    def test_a_verbatim_notice_whose_bytes_changed_fails(self):
        self.verbatim_notice()
        self.repo.append(self.NOTICE_PATH, "GNU Affero General Public License, added here\n")
        reasons = self.fails(self.gate())
        self.assertIn("UNMET G3", reasons)
        self.assertIn("differs from the sha256 its verbatim upstream exemption pins", reasons)
        # The pin follows the file, but the pinned archive's member does not.
        self.tearDown()
        self.setUp()
        changed = self.UPSTREAM_COPYING + "added\n"
        self.verbatim_notice(sha256=hashlib.sha256(changed.encode()).hexdigest())
        self.repo.write(self.NOTICE_PATH, changed)
        self.assertIn("is not libc-1.0/COPYING of the pinned archive byte for byte", self.fails(self.gate()))
        # A pin row that names another archive.
        self.tearDown()
        self.setUp()
        self.verbatim_notice(archive_sha256="6" * 64)
        self.assertIn("no row libc 1.0 pins archive sha256", self.fails(self.gate()))

    def test_a_verbatim_notice_exempts_only_its_own_path(self):
        self.verbatim_notice()
        self.repo.write("docs/COPYING", self.UPSTREAM_COPYING)                       # identical bytes elsewhere
        self.repo.write("provenance/linked-notices/libc-1.0/COPYING.orig", self.UPSTREAM_COPYING)
        failed = [f[2] for f in self.gate().fails()]
        self.assertIn("docs/COPYING:5", failed)
        self.assertIn("provenance/linked-notices/libc-1.0/COPYING.orig:5", failed)
        self.assertNotIn(f"{self.NOTICE_PATH}:5", failed)
        for kwargs, expect in (({"path": "provenance/linked-notices/*/COPYING"}, "names one exact repository path"),
                               ({"declare": False}, "not a notice file of a distributed artifact's component"),
                               ({"decision": None}, "records the owner's decision"),
                               ({"pin_row": None}, "names upstream")):
            with self.subTest(expect=expect):
                self.tearDown()
                self.setUp()
                self.verbatim_notice(**kwargs)
                gate = self.gate()
                self.assertIn(expect, self.fails(gate))
                self.assertIn(f"{self.NOTICE_PATH}:5", [f[2] for f in gate.fails()])

    def test_a_verbatim_notice_without_its_archive_is_not_exempted(self):
        # Review r1: a missing archive must not establish the relationship.
        self.verbatim_notice(archive=False)
        gate = self.gate()
        self.assertIn("DETECTED O3", self.fails(gate))
        self.assertIn("no exemption is granted", self.fails(gate))
        self.assertIn(f"{self.NOTICE_PATH}:5", [f[2] for f in gate.fails()])
        # A changed file with its pin following it, and no archive: still no exemption.
        self.tearDown()
        self.setUp()
        changed = self.UPSTREAM_COPYING + "changed\n"
        self.verbatim_notice(archive=False, text=changed)
        self.assertIn(f"{self.NOTICE_PATH}:5", [f[2] for f in self.gate().fails()])

    AGPL = "it under the terms of the GNU Affero General Public License as"
    # Review r1 and r2: source declared imported, listed as a notice and
    # matching an archive member, but not the reviewed tuple.
    CANDIDATES = {
        "src/code.rs": f"// {AGPL}\npub fn f() -> u32 {{ 1 }}\n",
        "provenance/linked-notices/libc-1.0/Makefile": f"# {AGPL}\nall:\n\tcc -o tool tool.c\n",
        "provenance/linked-notices/libc-1.0/source.txt": f"// {AGPL}\npub fn g() -> u32 {{ 2 }}\n",
        "provenance/linked-notices/libc-1.0/code.C": f"/* {AGPL} */\nint c(void) {{ return 3; }}\n",
        "provenance/linked-notices/libc-1.0/code.RS": f"// {AGPL}\npub fn h() {{}}\n",
        "provenance/linked-notices/libc-1.0/run": f"#!/bin/sh\n# {AGPL}\nexec true\n",
    }

    def test_only_the_reviewed_tuple_is_exempted(self):
        self.verbatim_notice(extra=self.CANDIDATES)
        gate = self.gate()
        failed = {f[2].rsplit(":", 1)[0] for f in gate.fails()}
        self.assertEqual(failed, set(self.CANDIDATES), self.fails(gate))
        self.assertEqual({i[2].rsplit(":", 1)[0] for i in self.entries(gate, "inventory", "verbatim-notice")},
                         {self.NOTICE_PATH})

    def test_the_tuple_path_with_other_bytes_fails(self):
        reviewed = hashlib.sha256(self.UPSTREAM_COPYING.encode()).hexdigest()
        source = f"/* {self.AGPL} */\nint copying(void) {{ return 0; }}\n"     # COPYING holding source
        one_byte = self.UPSTREAM_COPYING.replace("Affero", "Afferp")           # one byte changed
        for text in (source, one_byte):
            with self.subTest(text=text[:20]):
                self.tearDown()
                self.setUp()
                self.verbatim_notice(text=text, sha256=reviewed)                # the archive member matches the file
                gate = self.gate()
                self.assertIn("UNMET G3", self.fails(gate))
                self.assertIn("differs from the sha256 its verbatim upstream exemption pins", self.fails(gate))

    def test_a_reviewed_file_another_file_names_is_not_exempted(self):
        makefile = f"# {self.AGPL}\nall:\n\tcc -o tool tool.c\n"
        self.verbatim_notice(text=makefile, notice_path="provenance/linked-notices/libc-1.0/Makefile",
                             archive_member="libc-1.0/Makefile")
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))                          # the reviewed tuple, named by nothing
        self.repo.write("Makefile", "include provenance/linked-notices/libc-1.0/Makefile\n")
        gate = self.gate()
        self.assertIn("named by Makefile", self.fails(gate))
        self.assertIn("provenance/linked-notices/libc-1.0/Makefile:1", [f[2] for f in gate.fails()])

    def test_a_symlinked_notice_or_parent_is_not_exempted(self):
        for link in (self.NOTICE_PATH, "provenance/linked-notices/libc-1.0"):
            with self.subTest(link=link):
                self.tearDown()
                self.setUp()
                self.verbatim_notice()
                target = self.repo.root / "provenance/real" / Path(link).name
                target.parent.mkdir(parents=True)
                (self.repo.root / link).rename(target)
                os.symlink(os.path.relpath(target, (self.repo.root / link).parent), self.repo.root / link)
                gate = self.gate()
                self.assertIn(f"{link} is a symlink", self.fails(gate))
                self.assertEqual(self.entries(gate, "inventory", "verbatim-notice"), [])

    def test_record_checks_still_apply_to_the_tuple(self):
        for kwargs, expect in (
                ({"classify": "first-party"}, "classified imported in provenance.toml, not first-party"),
                ({"classify": None}, "classified imported in provenance.toml, not first-party")):
            with self.subTest(expect=expect):
                self.tearDown()
                self.setUp()
                self.verbatim_notice(**kwargs)
                gate = self.gate()
                self.assertIn(expect, self.fails(gate))
                self.assertIn(f"{self.NOTICE_PATH}:5", [f[2] for f in gate.fails()])

    def test_a_consumed_input_is_never_a_verbatim_notice(self):
        self.members([("a.o", "tool", "COPYING", "B", "BSD-3-Clause", "consumed", "0")])
        self.verbatim_notice()
        gate = self.gate()
        self.assertIn("consumed input of a member table", self.fails(gate))
        self.assertIn(f"{self.NOTICE_PATH}:5", [f[2] for f in gate.fails()])

    def test_a_verbatim_notice_still_has_its_licence_tags_judged(self):
        self.verbatim_notice(text=self.UPSTREAM_COPYING + f"{TAG}: GPL-2.0-only\n")
        gate = self.gate()
        self.assertNotIn("UNMET", self.fails(gate))
        self.assertEqual([f[2] for f in gate.fails()], [f"{self.NOTICE_PATH}:7"])

    def test_a_component_backed_by_a_member_table_takes_its_licence(self):
        self.members([("a.o", "tool", "src/a.c", "B", "BSD-3-Clause", "consumed", "0"),
                      ("b.o", "tool", "src/b.c", "M", "MIT OR Apache-2.0", "consumed", "0"),
                      ("b.o", "tool", "host:/usr/include/x.h", "host", "LGPL-2.1-or-later", "probe", "0")])
        component = ('\n[[artifact.component]]\nname = "libc"\nversion = "1.0"\norigin = "upstream-tarball"\n'
                     'member_table = "c/MEMBERS.tsv"\nlicense = "LICENCE"\nuse = "linked"\nnotice_files = []\n')
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.append("provenance/config.toml", component.replace("LICENCE", "BSD-3-Clause AND (MIT OR Apache-2.0)"))
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertIn("libc 1.0", [i[3] for i in self.entries(gate, "distribution", "allowed")])
        for changed, expect in ((component.replace("LICENCE", "BSD-3-Clause"), "the component and its member table disagree"),
                                (component.replace("LICENCE", "BSD-3-Clause AND (MIT OR Apache-2.0)")
                                 .replace('version = "1.0"', 'version = "2.0"'), "the table is libc 1.0, not libc 2.0"),
                                (component.replace("LICENCE", "BSD-3-Clause AND (MIT OR Apache-2.0)")
                                 .replace("c/MEMBERS.tsv", "c/OTHER.tsv"), "is not a [[licence_policy.member_table]]")):
            with self.subTest(expect=expect):
                self.repo.write("provenance/config.toml", config + changed)
                self.assertIn(expect, self.fails(self.gate()))

    def test_pin_tables_are_inventory(self):
        self.repo.append("c/PIN", "libgpl\t2.0\tGPL-2.0-or-later\n")
        self.repo.append("provenance/config.toml", '\n[[licence_policy.pin]]\npath = "c/OTHER"\n'
                         'licences = { "tool 1.0" = "MIT" }\n')
        self.repo.write("c/OTHER", "tool\t1.0\tsha\nother\t2.0\tsha\n")
        gate = self.gate()
        self.assertTrue(gate.ok(), self.fails(gate))
        self.assertEqual([(i[2], i[3]) for i in self.entries(gate, "inventory", "denied")], [("c/PIN:3", "libgpl 2.0")])
        self.assertIn(("c/OTHER:2", "other 2.0"), [(i[2], i[3]) for i in self.entries(gate, "inventory", "unknown")])

    # ---- configuration

    def test_every_artifact_says_whether_it_is_distributed_and_ships_no_host_tool(self):
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace("distributed = true\n", ""))
        self.assertIn("every artifact states distributed", self.fails(self.gate()))
        self.repo.write("provenance/config.toml", config.replace(UNIFONT, UNIFONT + UNIFONT.replace("GNU Unifont", "QEMU")))
        self.assertIn("a host tool or held artifact is declared part of a distributed artifact", self.fails(self.gate()))

    def test_a_missing_policy_fails(self):
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config[:config.index("[licence_policy]")]
                        + config[config.index("\n[shared_tools.sha256]"):])
        self.assertIn("no [licence_policy]", self.fails(self.gate()))

    def test_unversioned_decisions_fail(self):
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace("[policy.decisions]", '[policy.decisions]\nliba = "MIT"'))
        self.assertIn("a decision names one exact version", self.fails(self.gate()))

    def test_shared_tools_need_their_full_pin_set_and_a_matching_peer(self):
        base = self.repo.git("rev-parse", "HEAD").strip()
        out = pv.check(self.repo.rec(), base)
        self.assertEqual(out.verdict(), "UNCHANGED", " | ".join(f"{s} {p}: {r}" for s, p, r, _ in out.items))
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace(self.repo.shared, ""))
        self.assertIn("must pin exactly the shared provenance tools", " ".join(i[2] for i in pv.check(self.repo.rec(), base).items))
        self.repo.write("provenance/config.toml", config + '"scripts/provenance.py" = "' + "0" * 64 + '"\n')
        self.assertIn("must pin exactly the shared provenance tools", " ".join(i[2] for i in pv.check(self.repo.rec(), base).items))
        self.repo.write("provenance/config.toml", config)
        self.repo.append("scripts/spdx-check.py", "# drift\n")
        self.assertIn("differs from its pinned identity", " ".join(i[2] for i in pv.check(self.repo.rec(), base).items))
        # The same drift with its pin updated passes alone but not beside the peer.
        digest = hashlib.sha256((self.repo.root / "scripts/spdx-check.py").read_bytes()).hexdigest()
        self.repo.write("provenance/config.toml", config.replace(self.repo.shared.split('"')[3], digest))
        self.assertEqual(pv.check(self.repo.rec(), base).verdict(), "UNCHANGED")
        peer = Path(self.tmp.name) / "peer"
        (peer / "scripts").mkdir(parents=True)
        (peer / "provenance").mkdir()
        shutil.copyfile(Path(__file__).resolve().parent / "spdx-check.py", peer / "scripts/spdx-check.py")
        (peer / "provenance/config.toml").write_text(self.repo.shared)
        reasons = " ".join(i[2] for i in pv.check(self.repo.rec(), base, peer).items)
        self.assertIn("pins other shared tools", reasons)
        self.assertIn("differs from the peer's", reasons)
        out = pv.Findings()
        out.full = True
        rec = self.repo.rec()
        rec.config.setdefault("shared_tools", {})["peer_required"] = True
        pv.shared_tool_checks(rec, out)
        self.assertIn("full needs the paired repository", " ".join(i[2] for i in out.items))

    def test_a_licence_change_needs_review_unless_an_identity_bound_decision_covers_it(self):
        config = (self.repo.root / "provenance/config.toml").read_text()
        unelected = config.replace('version = "15.1.01"\n  origin = "host-package"\n  license = "OFL-1.1"',
                                   'version = "15.1.00"\n  origin = "host-package"\n  license = "GPL-2.0-or-later"', 1)
        self.repo.write("provenance/config.toml", unelected)
        self.repo.update()
        self.repo.commit("unelected font")
        old = self.repo.git("rev-parse", "HEAD").strip()
        self.repo.write("provenance/config.toml", config)
        self.repo.update()
        out = pv.check(self.repo.rec(), old)
        self.assertEqual(out.verdict(), "UNCHANGED", " | ".join(f"{s} {p}: {r}" for s, p, r, _ in out.items))
        self.assertIn("accepted by owner, test", " ".join(out.info))
        # The exception names 15.1.01: a later font declared OFL-1.1 still needs review.
        self.repo.write("provenance/config.toml", config.replace('version = "15.1.01"\n  origin', 'version = "15.1.02"\n  origin', 1))
        self.repo.update()
        out = pv.check(self.repo.rec(), old)
        self.assertIn("licence declaration changed", " ".join(i[2] for i in out.items))
        # Nor do terms no decision names.
        self.repo.write("provenance/config.toml", config.replace('license = "OFL-1.1"\n  use', 'license = "MIT"\n  use', 1))
        self.repo.update()
        out = pv.check(self.repo.rec(), old)
        self.assertIn("licence declaration changed", " ".join(i[2] for i in out.items))

    def test_source_release_check_runs_the_gate(self):
        import contextlib
        import io
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace('component = "GRUB"', 'component = "GRUB 2"'))
        saved = pv.source_release
        pv.source_release = lambda rec: (True, "SOURCE RELEASE r1: matches the manifest")
        try:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                status = pv.main(["--root", str(self.repo.root), "check"])
        finally:
            pv.source_release = saved
        self.assertEqual(status, 1)
        self.assertIn("LICENCE POLICY DISTRIBUTION: FAIL", buffer.getvalue())

    def test_check_prints_the_gate_and_fails_on_it(self):
        import contextlib
        import io
        base = self.repo.git("rev-parse", "HEAD").strip()

        def run():
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                status = pv.main(["--root", str(self.repo.root), "check", "--base", base])
            return status, buffer.getvalue()

        status, text = run()
        self.assertEqual(status, 0, text)
        self.assertIn("LICENCE POLICY DISTRIBUTION: PASS (scope: expression validity and declared-licence policy; "
                      "UNVERIFIED: O2 evidence completeness, O3 identities, O4 notices, O5 composition, collector "
                      "completeness, SPDX database consistency; no peer given)", text)
        self.assertIn("LICENCE INVENTORY:", text)
        self.assertIn("LICENCE HOST TOOLS: 1 recorded", text)
        config = (self.repo.root / "provenance/config.toml").read_text()
        self.repo.write("provenance/config.toml", config.replace('component = "GRUB"', 'component = "GRUB 2"'))
        status, text = run()
        self.assertEqual(status, 1)
        self.assertIn("PROVENANCE CHECK: UNCHANGED", text)
        self.assertIn("LICENCE POLICY DISTRIBUTION: FAIL 1", text)
        self.assertIn("component: GRUB host", text)


class RealStagingCase(unittest.TestCase):
    def test_real_compat_stage_isolates_cargo_ancestor_configuration_and_worktrees(self):
        source = Path(__file__).resolve().parent.parent
        if not (source / "scripts/stage-compat.sh").is_file():
            self.skipTest("platform-only compatibility stage is absent")
        archives = Path(os.environ.get("CARGO_HOME", Path.home()/".cargo")) / "registry/cache/index.crates.io-1949cf8c6b5b557f"
        row = next(line for line in (source/"compat/programs.tsv").read_text().splitlines() if line and not line.startswith("#"))
        name, version, checksum = row.split("\t")[:3]
        archive = archives/f"{name}-{version}.crate"
        if not archive.is_file(): self.skipTest(f"verified stage input unavailable: {archive}")
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), checksum)
        with tempfile.TemporaryDirectory(prefix="absd-compat-cargo-isolation-") as temporary:
            parent = Path(temporary)
            foreign = parent/"absd-std-staged-compat"; foreign.mkdir()
            sentinel = foreign/"foreign-owner-evidence"; sentinel.write_bytes(b"foreign evidence\n")
            cargo_home = parent/"cargo-home"; (cargo_home/"registry").mkdir(parents=True)
            for kind in ("cache", "index"):
                (cargo_home/"registry"/kind).symlink_to(archives.parents[1]/kind)
            env = {k:v for k,v in os.environ.items() if not k.startswith("CARGO_") and k not in ("RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER")}
            env["CARGO_HOME"] = str(cargo_home)
            stages = []
            for spelling in ("checkout-a", "checkout-b"):
                root = parent/spelling
                for directory in ("scripts", "compat", "pins/compat", ".cargo"):
                    (root/directory).mkdir(parents=True, exist_ok=True)
                shutil.copy2(source/"scripts/stage-compat.sh", root/"scripts/stage-compat.sh")
                (root/"compat/programs.tsv").write_text(row+"\n")
                shutil.copy2(source/f"pins/compat/{name}-{version}.Cargo.lock", root/f"pins/compat/{name}-{version}.Cargo.lock")
                for crate in ("runtime", "broker", "fs", "fsd", "release"):
                    shutil.copytree(source/crate, root/crate, ignore=shutil.ignore_patterns("target", "tree"))
                bad_config = root/".cargo/config.toml"
                bad_config.write_text("[invalid ancestor configuration\n")
                subprocess.run(["sh",str(root/"scripts/stage-compat.sh")], env=env, check=True, stdout=subprocess.PIPE)
                outside = Path(str(root)+".staged-compat")
                inside = root/".staged-compat"
                actual = outside if outside.is_dir() else inside
                result = subprocess.run(["cargo","metadata","--offline","--no-deps","--format-version","1"], cwd=actual/f"absd/{name}-{version}", env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual(actual,outside,"compatibility staging must be outside the checkout")
                self.assertEqual(bad_config.read_text(),"[invalid ancestor configuration\n")
                self.assertFalse(inside.exists())
                stages.append(outside)
                if len(stages)==1: (outside/"linux/first-worktree-owner").write_text("retained first stage")
            self.assertNotEqual(stages[0],stages[1])
            self.assertEqual((stages[0]/"linux/first-worktree-owner").read_text(),"retained first stage")
            self.assertEqual(sentinel.read_bytes(),b"foreign evidence\n")

    def test_real_worktree_local_ssh_and_compat_stages_keep_registry_identity(self):
        source = Path(__file__).resolve().parent.parent
        if not (source / "scripts/stage-ssh.sh").is_file():
            self.skipTest("platform-only real stage consumers are absent from this repository")
        config = tomllib.loads((source / "provenance/config.toml").read_text())
        pins = config["licence_policy"]["crate_checksums"]
        archives = Path(os.environ.get("CARGO_HOME", Path.home()/".cargo")) / "registry/cache/index.crates.io-1949cf8c6b5b557f"
        installed = pv.literal(source, "scripts/operator_image.py:PORTS")
        table = {row.split("\t")[3]: row.split("\t")[:2] for row in (source/"compat/programs.tsv").read_text().splitlines() if row and not row.startswith("#")}
        c_names = {row[0] for artifact in config["artifact"] for unit in artifact.get("unit",[])
                   if "c_ports" in unit for row in pv.c_port_rows(source,unit)}
        packages = [("sunset", "0.6.0")] + [tuple(table[name]) for name in installed if name not in c_names]
        all_stage = [tuple(row.split("\t")[:2]) for row in (source/"compat/programs.tsv").read_text().splitlines() if row and not row.startswith("#")]
        for name, version in set(packages + all_stage):
            if not (archives/f"{name}-{version}.crate").is_file():
                self.skipTest(f"real stage input archive unavailable: {name} {version}")
        with tempfile.TemporaryDirectory(prefix="absd-provenance-real-stage-") as temporary:
            root, registry = Path(temporary)/"checkout", Path(temporary)/"registry"
            root.mkdir(); registry.mkdir()
            # A fresh source checkout with no shared stage or Cargo writes.
            for name in subprocess.check_output(["git", "-C", str(source), "ls-files", "-z"]).decode().split("\0"):
                if not name: continue
                src, dst = source/name, root/name
                dst.parent.mkdir(parents=True, exist_ok=True)
                if src.is_symlink(): dst.symlink_to(os.readlink(src))
                else: shutil.copy2(src, dst)
            for name, version in packages:
                archive = archives/f"{name}-{version}.crate"
                self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), pins[f"{name} {version}"])
                with tarfile.open(archive) as tar: tar.extractall(registry, filter="data")
            prior = os.environ.get("ABSD_CARGO_REGISTRY")
            os.environ["ABSD_CARGO_REGISTRY"] = str(registry) + (os.pathsep+prior if prior else "")
            try:
                unit = next(u for a in config["artifact"] for u in a.get("unit",[]) if u["name"] == "sshd")
                artifact = {"name":"real-stage", "_wide":True, "unit":[unit]}
                before, _ = pv.compute_inventory(pv.Records(root), artifact)
                subprocess.run([str(root/"scripts/stage-ssh.sh")], check=True, stdout=subprocess.PIPE)
                after, _ = pv.compute_inventory(pv.Records(root), artifact)
                def sunset(rows): return next(row for row in rows if row["component"] == "sunset")
                self.assertEqual((sunset(after)["origin"], sunset(after)["elected"], sunset(after)["texts"]),
                                 (sunset(before)["origin"], sunset(before)["elected"], sunset(before)["texts"]))
                self.assertEqual(sunset(after)["origin"], "registry")
                self.assertNotEqual(sunset(after)["texts"], "")
                self.assertTrue((root/"ssh/tree/sunset").is_symlink())
                subprocess.run([str(root/"scripts/stage-compat.sh")], check=True, stdout=subprocess.PIPE)
                for name, version in packages[1:]:
                    # This is the manifest a native port build actually opens,
                    # including the runtime stanza appended by real staging.
                    staged = Path(str(root)+".staged-compat")/f"absd/{name}-{version}"
                    self.assertIn("dependencies.absd-runtime", (staged/"Cargo.toml").read_text())
                    unit = {"name":name,"package":name,"lock":f"pins/compat/{name}-{version}.Cargo.lock",
                            "manifest_dir":os.path.relpath(staged,root)}
                    rows, _ = pv.compute_inventory(pv.Records(root), {"name":"real-stage-port","_wide":True,"unit":[unit]})
                    row = next(row for row in rows if row["component"] == name)
                    self.assertEqual((row["origin"],row["elected"]),("registry","MIT"), name)
                    self.assertNotIn(row["texts"], ("", "MISSING", "UNKNOWN"), name)
            finally:
                if prior is None: os.environ.pop("ABSD_CARGO_REGISTRY",None)
                else: os.environ["ABSD_CARGO_REGISTRY"] = prior


# REUSE-IgnoreEnd

if __name__ == "__main__":
    unittest.main()
