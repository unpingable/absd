#!/usr/bin/env python3
"""Host controls for the dedicated fsd regeneration build.

Compile the real fsd startup prologue and host_key function against a small
in-memory filesystem and deterministic test entropy. Arguments here are the
resolved std::env::args after runtime startup-record/fallback selection. The
same source runs with and without the Cargo feature. No guest, network endpoint
or credential file is created. Native guard/durability and clone readiness
still need QEMU. In particular, the fence-only case reproduces the actual
kernel argv that suppressed the old build-time regeneration argument.

--baseline REV runs these controls against that revision's old prologue and
build script; the regeneration and conflict controls must fail there.
"""
import argparse
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PARSER = argparse.ArgumentParser()
PARSER.add_argument("--baseline")
OPTIONS, REMAINING = PARSER.parse_known_args()


def source(name):
    if OPTIONS.baseline:
        return subprocess.check_output(["git", "-C", str(ROOT), "show", OPTIONS.baseline + ":" + name],
                                       text=True)
    return (ROOT / name).read_text()


def function(text, name):
    start = text.index("fn " + name + "(")
    opening = text.index("{", start)
    depth = 1
    at = opening + 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[start:at]


FAKE_FS = r'''
use std::marker::PhantomData;
#[derive(Debug)] enum Error { NotFound, NotDir, Other }
#[derive(PartialEq)] enum Kind { File, Dir }
struct Attr { kind: Kind, size: u64 }
struct OpenFlags { read: bool, write: bool, create: bool, create_new: bool, truncate: bool }
struct RegionDevice;
struct Fs<R> { seed: Vec<u8>, staged: Option<Vec<u8>>, writes: usize, marker: PhantomData<R> }
impl<R> Fs<R> {
    fn stat(&mut self, path: &[u8]) -> Result<Attr, Error> {
        if path == b"/ssh" { return Ok(Attr { kind: Kind::Dir, size: 0 }); }
        if path == SEED_PATH { return Ok(Attr { kind: Kind::File, size: self.seed.len() as u64 }); }
        Err(Error::NotFound)
    }
    fn mkdir(&mut self, _: &[u8]) -> Result<(), Error> { self.writes += 1; Ok(()) }
    fn unlink(&mut self, path: &[u8]) -> Result<(), Error> {
        assert_eq!(path, SEED_STAGING);
        if self.staged.take().is_none() { return Err(Error::NotFound); }
        self.writes += 1; Ok(())
    }
    fn open(&mut self, path: &[u8], flags: OpenFlags) -> Result<u64, Error> {
        assert_eq!(path, SEED_STAGING);
        assert!(!flags.read && flags.write && !flags.create && flags.create_new && !flags.truncate);
        assert!(self.staged.is_none()); self.staged = Some(Vec::new()); self.writes += 1; Ok(1)
    }
    fn write_at(&mut self, handle: u64, offset: u64, bytes: &[u8]) -> Result<usize, Error> {
        assert_eq!((handle, offset), (1, 0)); self.staged = Some(bytes.to_vec());
        self.writes += 1; Ok(bytes.len())
    }
    fn sync(&mut self) -> Result<(), Error> { self.writes += 1; Ok(()) }
    fn close(&mut self, handle: u64) -> Result<(), Error> { assert_eq!(handle, 1); Ok(()) }
    fn rename(&mut self, from: &[u8], to: &[u8], no_replace: bool) -> Result<(), Error> {
        assert_eq!(from, SEED_STAGING); assert_eq!(to, SEED_PATH); assert!(!no_replace);
        self.seed = self.staged.take().unwrap(); self.writes += 1; Ok(())
    }
}
mod getrandom {
    pub fn fill(bytes: &mut [u8]) -> Result<(), &'static str> { bytes.fill(0xa5); Ok(()) }
}
fn fatal(reason: &str) -> ! { println!("FSD FAILED {reason}"); std::process::exit(3) }
fn finalize(bounded: bool) -> ! { println!("FINALIZE bounded={bounded}"); std::process::exit(0) }
const SEED_PATH: &[u8] = b"/ssh/host_ed25519_seed";
const SEED_STAGING: &[u8] = b"/ssh/host_ed25519_seed.new";
'''


class Regeneration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="test-fsd-regeneration-")
        cls.work = pathlib.Path(cls.scratch.name)
        text = source("ssh/src/fsd_server.rs")
        start = text.index("{", text.index("fn main()")) + 1
        end = text.index("    let qualification =", start)
        prologue = text[start:end]
        helper = (ROOT / "ssh/src/fsd_regenerate_mode.rs").read_text()
        # The guest dependency is a tiny local module in this host probe.
        helper = "\n".join(line for line in helper.splitlines() if not line.startswith("//!"))
        # Consume the real wrapper and constants. Only the host syscall
        # boundary is a fixture; it validates the actual startup probe.
        constants = [line for line in (ROOT / "runtime/src/lib.rs").read_text().splitlines()
                     if line.startswith("const SYS_WAIT_READABLE:")]
        if len(constants) != 1:
            raise AssertionError("expected one runtime wait_readable syscall definition")
        runtime = '''\nmod absd_runtime {
    pub fn link_anchor() {}
    __SYSCALL_CONSTANT__
    #[path = __READABLE_PATH__] mod readable;
    pub use readable::{wait_readable, WAIT_READABLE_POLL};
    unsafe fn syscall3(number: u64, pointer: u64, count: u64, ticks: u64) -> i64 {
        assert_eq!(number, SYS_WAIT_READABLE);
        assert_ne!(pointer, 0);
        assert_eq!(count, 0);
        assert_eq!(ticks, WAIT_READABLE_POLL);
        -22
    }
}
'''.replace("__SYSCALL_CONSTANT__", constants[0]).replace(
            "__READABLE_PATH__", json.dumps(str(ROOT / "runtime/src/readable.rs")))
        probe = FAKE_FS + runtime + '\nmod fsd_regenerate_mode { use crate::absd_runtime;\n' + helper + '\n}\n'
        probe += '''
#[cfg(feature = "regenerate-host-key")] use fsd_regenerate_mode::link_anchor;
#[cfg(not(feature = "regenerate-host-key"))] use absd_runtime::link_anchor;
'''
        probe += function(text, "ensure_dir") + "\n" + function(text, "host_key")
        probe += "\nfn main() {\n" + prologue + r'''
    let mut fs = Fs::<RegionDevice> { seed: vec![0x37; 32], staged: None, writes: 0, marker: PhantomData };
    let before = fs.seed.clone();
    let result = host_key(&mut fs, regenerate).unwrap();
    println!("KEY result={} unchanged={} writes={}", result, before == fs.seed, fs.writes);
}
'''
        file = cls.work / "probe.rs"
        file.write_text(probe)
        cls.binaries = {}
        for feature in (False, True):
            binary = cls.work / ("regenerate" if feature else "normal")
            argv = ["rustc", "--edition=2024", "-A", "warnings", str(file), "-o", str(binary)]
            if feature:
                argv += ["--cfg", 'feature="regenerate-host-key"']
            subprocess.run(argv, check=True, capture_output=True)
            cls.binaries[feature] = binary

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def run_mode(self, feature, *args):
        return subprocess.run([str(self.binaries[feature]), *args], capture_output=True, text=True)

    def generated(self, feature, *args):
        run = self.run_mode(feature, *args)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("KEY result=GENERATED unchanged=false", run.stdout)
        self.assertNotIn("writes=0", run.stdout)

    def test_dedicated_build_regenerates_with_empty_argv(self):
        self.generated(True)

    def test_dedicated_build_regenerates_with_actual_served_fence_argv(self):
        self.generated(True, "--storage-fence=none")

    def test_normal_build_keeps_existing_key_with_empty_or_fence_argv(self):
        for args in ((), ("--storage-fence=none",)):
            with self.subTest(args=args):
                run = self.run_mode(False, *args)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertIn("KEY result=PRESENT unchanged=true writes=0", run.stdout)

    def test_normal_build_keeps_explicit_regeneration(self):
        self.generated(False, "--regenerate-host-key", "--storage-fence=none")

    def test_dedicated_build_still_performs_kernel_finalization(self):
        for flag, bounded in (("--finalize", "false"), ("--finalize-bounded", "true")):
            with self.subTest(flag=flag):
                run = self.run_mode(True, flag)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertEqual(run.stdout.strip(), "FINALIZE bounded=" + bounded)

    def test_dedicated_build_refuses_conflicting_modes_before_key_writes(self):
        for args in (("--finalize", "--finalize-bounded"),
                     ("--finalize", "--regenerate-host-key"),
                     ("--finalize-bounded", "--qualification-hang-on-notice"),
                     ("--qualification-exit-on-notice",),
                     ("--qualification-hang-on-notice",)):
            with self.subTest(args=args):
                run = self.run_mode(True, *args)
                self.assertEqual(run.returncode, 3, run.stdout + run.stderr)
                self.assertIn("FSD FAILED", run.stdout)
                self.assertNotIn("KEY result=", run.stdout)
                self.assertNotIn("FINALIZE bounded=", run.stdout)

    def test_build_script_keeps_feature_out_of_normal_artifacts(self):
        # Run the actual shell script with a disposable compiler fixture.
        # The Rust controls above independently check what the feature does.
        with tempfile.TemporaryDirectory(dir=self.work) as temporary:
            root = pathlib.Path(temporary)
            scripts = root / "scripts"
            scripts.mkdir()
            (root / "ssh").mkdir()
            (root / ".staged-sysroot/lib/rustlib/src/rust/library").mkdir(parents=True)
            (scripts / "build-ssh.sh").write_text(source("scripts/build-ssh.sh"))
            (scripts / "check-abi-elf.py").write_text(source("scripts/check-abi-elf.py"))
            (scripts / "inputs.sh").write_text('absd_rust_remap() { ABSD_RUST_REMAP="build.rustflags=[]"; export ABSD_RUST_REMAP; }\n')
            (scripts / "stage-ssh.sh").write_text("#!/bin/sh\nexit 0\n")
            (scripts / "stage-ssh.sh").chmod(0o755)
            tools = root / "tools"
            tools.mkdir()
            # The real build script validates the packaged SFTP worker.
            # Link a small host fixture with the actual user image layout;
            # do not replace its ABI checker with a successful mock.
            assembly = root / "worker.S"
            assembly.write_text(".global _start\n.text\n_start: ret\n.data\n.byte 0\n")
            worker = root / "worker.elf"
            subprocess.run(["cc", "-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none",
                            "-Wl,-T," + str(ROOT / "user-linker.ld"),
                            str(assembly), "-o", str(worker)], check=True, capture_output=True)
            cargo = tools / "cargo"
            cargo.write_text('''#!/usr/bin/env python3
import json,pathlib,sys
r=pathlib.Path.cwd();args=sys.argv[1:]
features=args[args.index('--features')+1] if '--features' in args else ''
with (r/'build-calls.jsonl').open('a') as f:f.write(json.dumps({'features':features,'args':args})+'\\n')
out=r/'target/x86_64-unknown-absd/release';out.mkdir(parents=True,exist_ok=True)
names=[args[i+1] for i,arg in enumerate(args[:-1]) if arg=='--bin']
assert names, 'build script did not request any binaries'
for name in names:
    if name=='absd-sftp': (out/name).write_bytes((r.parent/'worker.elf').read_bytes())
    else: (out/name).write_text(features+':'+name)
''')
            cargo.chmod(0o755)
            strip = tools / "llvm-strip-18"
            strip.write_text("#!/bin/sh\ncp \"$3\" \"$2\"\n")
            strip.chmod(0o755)
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"],
                       ABSD_RUST_TOOLCHAIN=str(root / "unused-toolchain"))
            run = subprocess.run(["sh", str(scripts / "build-ssh.sh")], env=env,
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            calls = [json.loads(line) for line in (root / "ssh/build-calls.jsonl").read_text().splitlines()]
            self.assertEqual([x["features"] for x in calls], ["", "regenerate-host-key"])
            for name in ("sshd", "sshtest", "absd-fsd", "absd-enroll"):
                self.assertEqual((root / (name + ".elf")).read_text(), ":" + name)
            self.assertEqual((root / "absd-fsd-regenerate.elf").read_text(), "regenerate-host-key:absd-fsd")
            self.assertEqual((root / "absd-sftp.elf").read_bytes(), worker.read_bytes())
            self.assertEqual((root / "commands/absd-sftp").read_bytes(), worker.read_bytes())
            # The actual packaging gate must reject a malformed worker.
            worker.write_bytes(b"BAD!" + worker.read_bytes()[4:])
            refused = subprocess.run(["sh", str(scripts / "build-ssh.sh")], env=env,
                                     capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("bad ELF magic", refused.stdout + refused.stderr)


if __name__ == "__main__":
    unittest.main(argv=[__file__, *REMAINING])
