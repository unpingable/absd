#!/usr/bin/env python3
"""Compiler fact integration controls; set ABSD_KERNEL_RUN to a real kernel checkout."""
import importlib.util
import os
import sys

sys.dont_write_bytecode = True
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "check-abi-elf.py"
spec = importlib.util.spec_from_file_location("gate", path)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
kernel = os.environ["ABSD_KERNEL_RUN"]
for features, heap in (("", 8192), ("builder-profile", 98304), ("builder-large-envelope", 524288)):
    facts = gate.kernel_facts(kernel, features=features)
    assert facts["USER_HEAP_PAGES"][0] == heap, facts
    assert facts["MAX_MAP_PAGES"][0] == 64, facts
    assert facts["USER_IMAGE_MIN"][0] == 0x8000400000, facts
    print(f"PASS actual compiler features={features or 'default'} heap={heap}")
missing = gate.kernel_facts(kernel, features="no-such-abi-facts-feature")
assert missing["USER_HEAP_PAGES"][0] is None, missing
print("PASS unknown kernel feature refuses facts")
lines = []
assert gate.check_kernel(kernel, str(path.parent.parent), out=lines.append) == 0, lines
assert gate.check_kernel(kernel, str(path.parent.parent), out=lambda _: None, features="builder-profile") == 1
print("PASS default comparison; selected builder mismatch remains visible")

assert gate.kernel_facts(kernel, profile="release")["USER_HEAP_PAGES"][0] == 8192
assert gate.kernel_facts(kernel, profile="unsupported")["USER_HEAP_PAGES"][0] is None
assert gate.kernel_facts(kernel, target="no-such-target")["USER_HEAP_PAGES"][0] is None
print("PASS selected release and unsupported profile/target refusal")
# Use the existing real-workspace scratch consumer for compiler cfg controls.
spec = importlib.util.spec_from_file_location("fixtures", path.parent / "tests/test_check_abi_elf.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
with fixtures.tempfile.TemporaryDirectory(prefix="abi-compiler-control-") as directory:
    kdir, pdir = fixtures.scratch(directory)
    fixtures.mutate(kdir, "abi/src/layout.rs", "pub const USER_HEAP_PAGES: u64 = 8192;",
                    'pub const USER_HEAP_PAGES: u64 = if cfg!(target_os = "linux") { 8193 } else { 8192 };')
    result = gate.kernel_facts(kdir, target="x86_64-unknown-linux-gnu")
    assert result["USER_HEAP_PAGES"][0] == 8193, result
    assert gate.check_kernel(kdir, pdir, out=lambda _: None) == 1
    fixtures.mutate(kdir, "user/Cargo.toml", 'absd-abi = { path = "../abi" }',
                    'absd-abi = { path = "../abi", features = ["builder-profile"] }')
    assert gate.kernel_facts(kdir)["USER_HEAP_PAGES"][0] is None
print("PASS actual target cfg expression and foreign workspace feature refusal")

with fixtures.tempfile.TemporaryDirectory(prefix="abi-forwarding-control-") as directory:
    kdir, _ = fixtures.scratch(directory)
    fixtures.mutate(kdir, "user/Cargo.toml", "[features]", '[features]\ndefault = ["forward-abi"]\nforward-abi = ["absd-abi/builder-profile"]')
    result = gate.kernel_facts(kdir)
    assert result["USER_HEAP_PAGES"][0] is None, result
print("PASS another member default-feature forwarding refuses facts")
previous = os.environ.get("RUSTC_WRAPPER")
try:
    # A passthrough wrapper still changes producer identity and must refuse.
    os.environ["RUSTC_WRAPPER"] = "/usr/bin/env"
    assert gate.kernel_facts(kernel)["USER_HEAP_PAGES"][0] is None
finally:
    if previous is None: os.environ.pop("RUSTC_WRAPPER", None)
    else: os.environ["RUSTC_WRAPPER"] = previous
print("PASS unsupported Cargo compiler wrapper refuses facts")

for relative, new_file in (("user/Cargo.toml", False), ("abi/src/new_unconsumed.rs", True)):
    with fixtures.tempfile.TemporaryDirectory(prefix="abi-changing-input-") as directory:
        kdir, _ = fixtures.scratch(directory)
        original = gate.subprocess.run
        def concurrent_edit(command, *args, **kwargs):
            result = original(command, *args, **kwargs)
            if command[:2] == ["cargo", "metadata"]:
                path = Path(kdir) / relative
                if new_file: path.write_text("// new compiler input inventory member\n")
                else: path.write_text(path.read_text() + "\n# concurrent manifest edit\n")
            return result
        gate.subprocess.run = concurrent_edit
        try:
            result = gate.kernel_facts(kdir)
            assert result["USER_HEAP_PAGES"][0] is None, result
            assert "inputs changed" in result["USER_HEAP_PAGES"][1], result
        finally:
            gate.subprocess.run = original
print("PASS member-manifest and source-set changes during actual acquisition refuse facts")

for kind in ("dev-dependencies", "build-dependencies"):
    with fixtures.tempfile.TemporaryDirectory(prefix="abi-dependency-kind-") as directory:
        kdir, _ = fixtures.scratch(directory)
        manifest = Path(kdir) / "Cargo.toml"
        manifest.write_text(manifest.read_text() + '\n[' + kind + ']\nabsd-abi = {path="abi", features=["builder-profile"]}\n')
        result = gate.kernel_facts(kdir)
        assert result["USER_HEAP_PAGES"][0] is None, result
        assert "non-normal" in result["USER_HEAP_PAGES"][1], result
print("PASS root dev/build ABI dependencies refuse selected facts")

report = []
assert gate.check_kernel(kernel, str(path.parent.parent), out=report.append) == 0
assert sum(line.startswith("ABI COMPILER ") for line in report) == 1, report
assert sum("compiler=" in line for line in report) == 1, report
print("PASS one compiler/hash citation per selected comparison report")
