#!/usr/bin/env python3
"""Unit tests for scripts/release_manifest.py over a tiny fake release:
manifest determinism, verify (intact, corrupted, unrecorded), the ISO's
extracted contents, the kernel comparison (bytes, compared stripped,
differs), the toolchain comparison, and the fingerprint's agreement with
scripts/verify-inputs.sh's shell pipeline.

    python3 scripts/test_release_manifest.py
"""

import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
import unittest

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import release_manifest as rm  # noqa: E402

ELF = pathlib.Path("/bin/true")
FAKE_TOOLCHAIN = {
    "toolchain.rustc": {"commit_hash": "a" * 40, "release": "1.95.0"},
    "toolchain.kernel_rustc": {"commit_hash": "b" * 40, "rustup_toolchain": "stable"},
    "toolchain.host": {"xorriso": "xorriso 1.5.6"},
}


def git(path, *args):
    subprocess.run(["git", "-C", str(path), "-c", "user.name=t", "-c", "user.email=t@t", *args], check=True,
                   capture_output=True)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


def build_id_flipped(src, dest, text_too=False):
    """A copy of the ELF `src` whose GNU build-id differs (and, with
    text_too, one byte of .text)."""
    data = bytearray(src.read_bytes())
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    sections = [struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize) for i in range(shnum)]
    stroff = sections[shstrndx][4]
    for name, kind, _, _, offset, size in sections:
        label = bytes(data[stroff + name:data.index(b"\0", stroff + name)])
        if label == b".note.gnu.build-id":
            namesz, descsz, _ = struct.unpack_from("<III", data, offset)
            desc = offset + 12 + ((namesz + 3) & ~3)
            data[desc] ^= 0xFF
        if text_too and label == b".text":
            data[offset + size // 2] ^= 0xFF
    dest.write_bytes(bytes(data))
    dest.chmod(0o755)


def make_iso(kernel, cfg, out, work):
    tree = pathlib.Path(work) / ("iso-" + out.stem)
    write(tree / "boot" / "absd-kernel", kernel.read_bytes())
    write(tree / "boot" / "grub" / "grub.cfg", cfg)
    subprocess.run(["xorriso", "-as", "mkisofs", "-r", "-o", str(out), str(tree)], check=True, capture_output=True)


@unittest.skipUnless(shutil.which("xorriso") and shutil.which(rm.STRIP) and ELF.is_file(), "needs xorriso, "
                     f"{rm.STRIP}, and an ELF at {ELF}")
class ReleaseManifestTest(unittest.TestCase):
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="test-release-manifest-"))
        self.platform = self.work / "platform"
        self.kernel = self.work / "kernel"
        self.release = self.work / "release"
        p = self.platform
        write(p / "scripts" / "verify-inputs.sh",
              'test "$(git -C "$pulse" rev-parse HEAD)" = \\\n    ' + "1" * 40 + ' || fail\n')
        write(p / ".cargo" / "config.toml",
              '[unstable]\nbuild-std = ["core"]\n[target.x86_64-unknown-absd]\nrustflags = ["-C", "x"]\n')
        for name in ("scripts/rustc-staged.sh", "scripts/prepare-and-build.sh", "user-linker.ld",
                     "patches/rust-1.95.0-absd-std.patch", "pins/library.Cargo.lock", "targets/x.json"):
            write(p / name, name)
        write(p / "commands" / "ls", b"\x7fELF ls")
        write(p / "sshd.elf", ELF.read_bytes())
        write(p / "manpages" / "man1" / "ls.1", "LS(1)\n")
        git(p, "init", "-q")
        git(p, "add", ".")
        git(p, "commit", "-q", "-m", "platform")
        write(self.kernel / "Makefile", "durable-iso:\n")
        git(self.kernel, "init", "-q")
        git(self.kernel, "add", ".")
        git(self.kernel, "commit", "-q", "-m", "kernel")
        r = self.release
        write(r / "tree" / "bin" / "ls", (p / "commands" / "ls").read_bytes())
        write(r / "tree" / "share" / "man" / "man1" / "ls.1", "LS(1)\n")
        write(r / "sshd.elf", ELF.read_bytes())
        write(r / "release", "absd-release 1\nrelease=t1\nkernel_abi=1\nfsd_protocol=2\nfs_format=2\napp_abi=1\n"
                             "check=0\n")
        self.cfg = "set timeout=0\n"
        make_iso(ELF, self.cfg, r / rm.ISO, self.work)

    def tearDown(self):
        shutil.rmtree(self.work)

    def build(self):
        return rm.build(self.release, self.platform, self.kernel, partial=True, built="2026-10-02T00:00:00Z",
                        toolchain=FAKE_TOOLCHAIN, components=None)

    def test_manifest_is_deterministic_and_parses(self):
        first = self.build()
        second = self.build()
        self.assertEqual(first, second)
        doc = tomllib.loads(first)
        self.assertEqual(doc["release"]["id"], "t1")
        self.assertEqual(doc["identity"]["fs_format"], 2)
        self.assertEqual(doc["filesystem"]["formats_accepted"], [2])
        files = doc["artifacts"]["files"]
        self.assertEqual(list(files), sorted(files))
        self.assertEqual(files["tree/bin/ls"]["origin"], "commands/ls")
        self.assertEqual(files["tree/share/man/man1/ls.1"]["origin"], "manpages/man1/ls.1")
        self.assertEqual(files["release"]["origin"], "release tool")
        self.assertEqual(doc["source"]["kernel_tree_clean"], True)
        self.assertEqual(doc["source"]["coordination_pins"]["pulse_commit"], "1" * 40)
        self.assertEqual(doc["build"]["rustflags"], ["-C", "x"])
        self.assertEqual(doc["artifacts"]["iso"]["boot/absd-kernel"], rm.sha256_file(ELF))
        self.assertEqual(doc["artifacts"]["iso"]["boot/grub/grub.cfg"], rm.sha256_bytes(self.cfg.encode()))
        self.assertNotIn(rm.MANIFEST, files)

    def test_verify_intact_corrupt_and_unrecorded(self):
        self.build()
        self.assertEqual(rm.verify(self.release), [])
        write(self.release / "tree" / "bin" / "ls", b"\x7fELF LS")
        write(self.release / "stray", "x")
        problems = rm.verify(self.release)
        self.assertIn("digest mismatch tree/bin/ls", problems)
        self.assertIn("unrecorded file stray", problems)
        (self.release / "sshd.elf").unlink()
        self.assertIn("missing sshd.elf", rm.verify(self.release))

    def test_verify_detects_a_changed_iso_kernel(self):
        self.build()
        build_id_flipped(ELF, self.work / "k2", text_too=True)
        make_iso(self.work / "k2", self.cfg, self.release / rm.ISO, self.work)
        problems = rm.verify(self.release)
        self.assertIn(f"digest mismatch {rm.ISO}:boot/absd-kernel", problems)
        self.assertIn(f"digest mismatch {rm.ISO}:kernel_normalized", problems)

    def test_compare_kernel_bytes_stripped_and_differs(self):
        self.build()
        manifest = self.release / rm.MANIFEST
        results, ok = rm.compare(manifest, self.platform, self.release / rm.ISO)
        self.assertTrue(ok)
        self.assertEqual(results[rm.ISO]["kernel"], "identical")
        self.assertEqual(results["tree/bin/ls"]["result"], "identical")
        self.assertEqual(results["release"]["result"], "not rebuilt")

        build_id_flipped(ELF, self.work / "k-path", text_too=False)
        make_iso(self.work / "k-path", self.cfg, self.work / "rebuilt.iso", self.work)
        results, ok = rm.compare(manifest, self.platform, self.work / "rebuilt.iso")
        self.assertTrue(ok)
        self.assertEqual(results[rm.ISO]["kernel"], "identical when compared stripped")
        self.assertTrue(results[rm.ISO]["kernel_method"].startswith("compared stripped"))

        build_id_flipped(ELF, self.work / "k-text", text_too=True)
        make_iso(self.work / "k-text", self.cfg, self.work / "other.iso", self.work)
        results, ok = rm.compare(manifest, self.platform, self.work / "other.iso")
        self.assertFalse(ok)
        self.assertEqual(results[rm.ISO]["kernel"], "differs")

        write(self.platform / "commands" / "ls", b"\x7fELF other")
        results, ok = rm.compare(manifest, self.platform, self.release / rm.ISO)
        self.assertFalse(ok)
        self.assertEqual(results["tree/bin/ls"]["result"], "differs")
        rm.write_receipt(self.work / rm.RECEIPT, manifest, results, ok, [], {"note": "x"})
        receipt = tomllib.loads((self.work / rm.RECEIPT).read_text())
        self.assertEqual(receipt["reconstruction"]["result"], "not reconstructed")
        self.assertEqual(receipt["files"]["tree/bin/ls"]["result"], "differs")

    def test_toolchain_mismatches_are_named(self):
        doc = tomllib.loads(rm.toml_dump({"toolchain.kernel_rustc": {"commit_hash": "b" * 40},
                                          "toolchain.host": {"xorriso": "xorriso 1.5.6", "qemu": "8.2.2"}}))
        here = {"toolchain.kernel_rustc": {"commit_hash": "c" * 40},
                "toolchain.host": {"xorriso": "xorriso 1.5.6", "qemu": "9.0"}}
        problems = rm.toolchain_mismatches(doc, here)
        self.assertEqual(len(problems), 2)
        self.assertTrue(problems[0].startswith("toolchain.kernel_rustc.commit_hash"))
        self.assertTrue(problems[1].startswith("toolchain.host.qemu"))
        self.assertEqual(rm.toolchain_mismatches(doc, {"toolchain.kernel_rustc": {"commit_hash": "b" * 40},
                                                       "toolchain.host": {"xorriso": "xorriso 1.5.6",
                                                                          "qemu": "8.2.2"}}), [])

    def test_fingerprint_matches_the_shell_pipeline(self):
        base = self.work / "src"
        write(base / "library" / "b" / "x.rs", "x")
        write(base / "library" / "a.rs", "a")
        write(base / "library" / "B.rs", "B")
        shell = subprocess.run("find library -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | "
                               "sha256sum | awk '{print $1}'", shell=True, cwd=base, check=True,
                               capture_output=True, text=True).stdout.strip()
        self.assertEqual(rm.tree_fingerprint(base, "library"), (shell, 3, 3, 0))
        dot = subprocess.run("find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | "
                             "awk '{print $1}'", shell=True, cwd=base / "library", check=True,
                             capture_output=True, text=True).stdout.strip()
        self.assertEqual(rm.dot_tree_hash(base / "library"), dot)

    def test_toml_strings_round_trip(self):
        doc = {"t": {"plain": 'a "quoted" \\ value', "list": ["x", "y"], "inline": {"b": 1, "a": True},
                     "dotted.key": "v"}}
        self.assertEqual(tomllib.loads(rm.toml_dump(doc))["t"],
                         {"plain": 'a "quoted" \\ value', "list": ["x", "y"], "inline": {"a": True, "b": 1},
                          "dotted.key": "v"})


if __name__ == "__main__":
    unittest.main()
