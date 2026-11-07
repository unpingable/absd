#!/usr/bin/env python3
"""Exercise the real wrappers with observable compiler/Cargo boundaries."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SEP = "\x1f"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class BuildFlags(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="absd-flags-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "checkout = one"
        (self.root / "scripts").mkdir(parents=True)
        for name in ["kernel-cargo.sh", "build-user.sh", "rust-source-map.sh", "rust-build-flags.py"]:
            shutil.copyfile(ROOT / "scripts" / name, self.root / "scripts" / name)
        (self.root / "user").mkdir()
        shutil.copyfile(ROOT / "user/Cargo.toml", self.root / "user/Cargo.toml")
        self.sysroot = self.base / "compiler = root"
        (self.sysroot / "lib/rustlib").mkdir(parents=True)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        compiler = self.bin / "rustc"
        compiler.write_text("#!/usr/bin/env python3\nimport os,sys\n"
                            "if os.environ.get('FAIL_COMPILER'): sys.exit(7)\n"
                            "print(os.environ['FAKE_SYSROOT'] if sys.argv[1:] == ['--print', 'sysroot'] "
                            "else 'commit-hash: " + COMMIT + "')\n")
        compiler.chmod(0o755)
        cargo = self.bin / "cargo"
        cargo.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys,tomllib
pathlib.Path(os.environ['RECORD']).write_text(json.dumps({'argv':sys.argv[1:],'env':dict(os.environ)}))
if '--manifest-path' in sys.argv:
    manifest=pathlib.Path(sys.argv[sys.argv.index('--manifest-path')+1])
    target=pathlib.Path(sys.argv[sys.argv.index('--target-dir')+1])/'x86_64-unknown-linux-gnu/release'
    target.mkdir(parents=True,exist_ok=True)
    for item in tomllib.loads(manifest.read_text())['bin']:
        (target/item['name']).write_bytes(b'fixture')
''')
        cargo.chmod(0o755)
        self.record = self.base / "record.json"
        self.env = dict(os.environ)
        for name in ["CARGO_ENCODED_RUSTFLAGS", "RUSTFLAGS", "ABSD_KERNEL_ROOT_REMAP_TO"]:
            self.env.pop(name, None)
        self.env.update(PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        RUSTC=str(compiler), FAKE_SYSROOT=str(self.sysroot), RECORD=str(self.record))

    def kernel(self, extra=None, arguments=None, root=None):
        environment = dict(self.env, **(extra or {}))
        arguments = arguments or ["rustc", "argument with spaces", "$(literal)"]
        result = subprocess.run(["sh", str((root or self.root) / "scripts/kernel-cargo.sh"), *arguments],
                                env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(self.record.read_text())
        self.assertEqual(record["argv"], arguments)
        return record["env"], record["env"]["CARGO_ENCODED_RUSTFLAGS"].split(SEP)

    def test_plain_flags_and_default(self):
        env, flags = self.kernel({"RUSTFLAGS": "--cfg caller\t-C debuginfo=2",
                                  "ABSD_KERNEL_ROOT_REMAP_TO": "/stale/carrier"})
        self.assertEqual(flags[0], f"--remap-path-prefix={self.root}=/absd/kernel")
        self.assertEqual(flags[1:-1], ["--cfg", "caller", "-C", "debuginfo=2"])
        self.assertEqual(flags[-1], f"--remap-path-prefix={self.sysroot}/lib/rustlib/src/rust=/rustc/{COMMIT}")
        self.assertEqual(env["ABSD_KERNEL_ROOT_REMAP_TO"], "/absd/kernel")

    def test_encoded_preserves_tokens_and_priority(self):
        caller = ["--cfg", 'label="a b=$(literal)"', "--remap-path-prefix", f"{self.root}=/media/first",
                  f"--remap-path-prefix={self.root}=/absd/kernel-run"]
        env, flags = self.kernel({"RUSTFLAGS": "--cfg ignored", "CARGO_ENCODED_RUSTFLAGS": SEP.join(caller)})
        self.assertEqual(flags[1:-1], caller)
        self.assertEqual(flags[0], f"--remap-path-prefix={self.root}=/absd/kernel-run")
        self.assertEqual(env["ABSD_KERNEL_ROOT_REMAP_TO"], "/absd/kernel-run")

    def test_empty_encoded_ignores_plain(self):
        _, flags = self.kernel({"RUSTFLAGS": "--cfg ignored", "CARGO_ENCODED_RUSTFLAGS": ""})
        self.assertEqual(len(flags), 2)

    def test_source_aliases(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        # Direct helper invocation can receive a logical checkout alias.
        result = subprocess.run(["python3", str(alias / "scripts/rust-build-flags.py"), "kernel", str(alias), "check"],
                                env=dict(self.env, RUSTFLAGS=f"--remap-path-prefix={alias}=/media/kernel"),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        flags = json.loads(self.record.read_text())["env"]["CARGO_ENCODED_RUSTFLAGS"].split(SEP)
        self.assertEqual(flags[:2], [f"--remap-path-prefix={alias}=/media/kernel",
                                    f"--remap-path-prefix={self.root}=/media/kernel"])

    def test_compiler_failure_prevents_cargo(self):
        result = subprocess.run(["sh", str(self.root / "scripts/kernel-cargo.sh"), "check"],
                                env=dict(self.env, FAIL_COMPILER="1"), capture_output=True)
        self.assertEqual(result.returncode, 7)
        self.assertFalse(self.record.exists())

    def test_nested_build_isolation_and_policy(self):
        inherited = {name: "outer-setting" for name in [
            "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
            "CLIPPY_ARGS", "CARGO_MAKEFLAGS", "MAKEFLAGS", "MFLAGS", "TARGET"]}
        inherited.update(CARGO_ENCODED_RUSTFLAGS="--cfg" + SEP + "kernel_only", RUSTFLAGS="--cfg outer",
                         ABSD_KERNEL_ROOT_REMAP_TO="/absd/kernel-run", CARGO=str(self.bin / "cargo"))
        output = self.base / "target = separate"
        result = subprocess.run(["sh", str(self.root / "scripts/build-user.sh"), str(output)],
                                env=dict(self.env, **inherited), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(self.record.read_text())
        for name in inherited.keys() - {"CARGO_ENCODED_RUSTFLAGS", "ABSD_KERNEL_ROOT_REMAP_TO", "CARGO"}:
            self.assertNotIn(name, record["env"])
        flags = record["env"]["CARGO_ENCODED_RUSTFLAGS"].split(SEP)
        self.assertEqual(flags[0], f"--remap-path-prefix={self.root}=/absd/kernel-run")
        self.assertNotIn("kernel_only", flags)
        for flag in ["relocation-model=static", "code-model=large", "link-arg=-Wl,--build-id=sha1",
                     f"link-arg=-Wl,-T,{self.root}/user/linker.ld"]:
            self.assertIn(flag, flags)
        self.assertTrue((output / "init.elf").is_file())


if __name__ == "__main__":
    unittest.main()
