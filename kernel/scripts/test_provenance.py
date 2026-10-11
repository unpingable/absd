#!/usr/bin/env python3
"""Tests for scripts/provenance.py against a small synthetic repository and
registry: no cargo, no network, a few seconds. Run: python3 scripts/test_provenance.py"""
import os
import shutil
import subprocess
import sys
import tempfile
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
        self.write("provenance/config.toml", CONFIG)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        os.environ["ABSD_CARGO_REGISTRY"] = str(self.registry)
        os.environ["ABSD_PRIVATE_PATTERNS"] = str(Path(tmp) / "absent")
        self.update()
        self.commit("base")
        base = self.git("rev-parse", "HEAD").strip()
        self.write("provenance/config.toml", CONFIG.replace("BASE", base))
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
        self.repo.write("provenance/config.toml", config.replace("[policy.decisions]", '[policy.decisions]\nlibgpl = "GPL-3.0-only"'))
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


# REUSE-IgnoreEnd

if __name__ == "__main__":
    unittest.main()
