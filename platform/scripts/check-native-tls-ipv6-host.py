#!/usr/bin/env python3
"""Type-check all four TLS binaries without linking target binaries or booting.

Usage: check-native-tls-ipv6-host.py --stage RING --cargo-home CARGO --work FRESH
Uses the existing native ring/std recipe and Rust 1.95.0. The target is ABSD:
Linux-target checking omits native-only dependencies, NicLink and KernelPipe.
FRESH must be an admitted private scratch path outside the source worktree.
It retains the command log, dummy inputs and result for the caller's custody;
the caller owns retirement after readback. No private keys or real PKI needed.
The dummy DER is intentionally invalid and the ELF is only an include buffer.
Neither is a runnable fixture. A pass is type-check evidence, not native proof.
Cargo may compile, link and execute host build scripts while checking target
dependencies. This helper never executes the TLS binaries.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parent.parent
BINS = {"https_get", "tls_service_probe", "https_get_ipv6", "tls_ipv6_service_probe"}


def identity(path):
    value = path.read_bytes()
    return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--toolchain", type=Path, default=Path.home() / ".rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu")
    args = parser.parse_args()
    work, stage, cargo = args.work.resolve(), args.stage.resolve(), args.cargo_home.resolve()
    if work == ROOT or ROOT in work.parents or work.exists() or not cargo.is_dir():
        parser.error("use a fresh private work path outside source and an existing Cargo home")
    manifest = tomllib.loads((ROOT / "tls/Cargo.toml").read_text())
    if {entry["name"] for entry in manifest["bin"]} != BINS:
        parser.error("TLS binary inventory changed; review this helper")
    library = ROOT / ".staged-sysroot/lib/rustlib/src/rust/library"
    if not library.is_dir():
        parser.error("stage the established ABSD standard-library source first")
    # Match the established builder's patched std identity, not an ambient SDK.
    files = sorted((p for p in library.rglob("*") if p.is_file()),
                   key=lambda p: p.relative_to(library).as_posix().encode())
    if any(p.is_symlink() for p in library.rglob("*")):
        parser.error("staged std contains a symlink")
    lines = "".join(f"{identity(p)['sha256']}  library/{p.relative_to(library).as_posix()}\n" for p in files)
    std_sha = hashlib.sha256(lines.encode()).hexdigest()
    if std_sha != "c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c" or len(files) != 2251 or sum(p.stat().st_size for p in files) != 45920288:
        parser.error("staged std differs from the existing native TLS recipe")
    toolchain = args.toolchain.resolve()
    cc, ar = shutil.which("clang-18"), shutil.which("llvm-ar-18")
    if not cc or not ar or not (toolchain / "bin/rustc").is_file():
        parser.error("Rust 1.95.0, clang-18 and llvm-ar-18 are required")
    include = Path(subprocess.check_output([cc, "-print-resource-dir"], text=True).strip()) / "include"
    if not include.is_absolute() or not include.is_dir():
        parser.error("Clang builtin headers unavailable")
    work.mkdir(parents=True)
    dummy_der, dummy_elf = work / "dummy-root.der", work / "dummy-child.elf"
    dummy_der.write_bytes(bytes([0x30, 0]))
    dummy_elf.write_bytes(b"\x7fELF" + bytes(60))
    # Use the builder's override isolation; no inherited target/CPU/profile flags.
    removed = sorted(key for key in os.environ if key in {
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTDOC", "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER", "CC", "CXX", "AR", "ARFLAGS", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
        "CRATE_CC_NO_DEFAULTS", "ABSD_RESTRICTED_STD_ALL", "ABSD_RUST_REMAP",
        "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    } or key.startswith(("CARGO_PROFILE_", "CARGO_TARGET_", "RUSTC_BOOTSTRAP", "CC_", "AR_", "ARFLAGS_", "CFLAGS_", "CPPFLAGS_", "CXX_", "CXXFLAGS_")))
    env = {key: value for key, value in os.environ.items() if key not in removed}
    cflags = ["--target=x86_64-unknown-none-elf", "-ffreestanding", "-nostdinc", "-isystem", str(include),
              "-I" + str(ROOT / "sqlite/include"), "-mcmodel=large", "-fno-pic", "-O2", "-ffunction-sections", "-fdata-sections"]
    env.update(CARGO_HOME=str(cargo), CARGO_BUILD_JOBS="1", ABSD_PROFILE="core",
               ABSD_REAL_RUSTC=str(toolchain / "bin/rustc"),
               ABSD_STAGED_SYSROOT=str(ROOT / ".staged-sysroot"),
               RUSTC=str(ROOT / "scripts/rustc-staged.sh"), RUSTC_BOOTSTRAP="1",
               RUST_TARGET_PATH=str(ROOT / "targets"), CARGO_TARGET_DIR=str(work / "target"),
               ABSD_TLS_ROOT_DER=str(dummy_der), ABSD_TLS_CLIENT_ELF=str(dummy_elf),
               ABSD_TLS_IPV6_CLIENT_ELF=str(dummy_elf), ABSD_TLS_CASE="P01", ABSD_TLS_IPV6_CASE="P01",
               ABSD_TLS_UNIX_SECONDS="1792209064", CC_x86_64_unknown_absd=cc,
               AR_x86_64_unknown_absd=ar, CRATE_CC_NO_DEFAULTS="1", CFLAGS_x86_64_unknown_absd=shlex.join(cflags))
    remaps = [f"--remap-path-prefix={ROOT}=/absd", f"--remap-path-prefix={cargo}/registry/src=/cargo/registry/src",
              f"--remap-path-prefix={stage}=/tls-fixture-stage"]
    command = [str(toolchain / "bin/cargo"), "--config", "target.x86_64-unknown-absd.rustflags=" + json.dumps(remaps),
               "check", "--manifest-path", str(ROOT / "tls/Cargo.toml"), "--bins", "--release",
               "-Z", "build-std=core,alloc,std,panic_abort", "--locked", "--offline",
               "--target", "x86_64-unknown-absd", "--message-format=json"]
    lock = identity(ROOT / "tls/Cargo.lock")
    log = work / "check.log"
    with log.open("xb") as output:
        stage_command = ["python3", str(ROOT / "scripts/stage-native-tls-fixture.py"),
                         "--stage", str(stage), "--cargo-home", str(cargo)]
        stage_result = subprocess.run(stage_command, cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT)
        checked = subprocess.run(command, cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT) if stage_result.returncode == 0 else None
    records = []
    for line in log.read_text().splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    artifacts = [x for x in records if x.get("reason") == "compiler-artifact" and "bin" in x.get("target", {}).get("kind", [])]
    checked_names = {x["target"]["name"] for x in artifacts}
    code = checked.returncode if checked is not None else stage_result.returncode
    passed = code == 0 and checked_names == BINS and any(x.get("reason") == "build-finished" and x.get("success") is True for x in records)
    result = {"schema_version": 1, "disposition": "PASS" if passed else "FAIL", "scope": "ABSD-target cargo check only; no target-binary link, guest, kernel build or runtime evidence; host build scripts may compile, link and execute",
              "stage_command": stage_command, "command": command, "exit": code, "removed_environment": removed,
              "explicit_environment": {k: env[k] for k in ["CARGO_HOME", "CARGO_TARGET_DIR", "RUSTC", "ABSD_REAL_RUSTC", "ABSD_STAGED_SYSROOT", "RUSTC_BOOTSTRAP", "RUST_TARGET_PATH", "ABSD_TLS_ROOT_DER", "ABSD_TLS_CLIENT_ELF", "ABSD_TLS_IPV6_CLIENT_ELF", "ABSD_TLS_CASE", "ABSD_TLS_IPV6_CASE", "ABSD_TLS_UNIX_SECONDS", "CC_x86_64_unknown_absd", "AR_x86_64_unknown_absd", "CRATE_CC_NO_DEFAULTS", "CFLAGS_x86_64_unknown_absd"]},
              "expected_bins": sorted(BINS), "checked_bins": sorted(checked_names), "compiler_artifacts": artifacts,
              "log": identity(log), "dummy_der": identity(dummy_der), "dummy_elf": identity(dummy_elf),
              "tls_lock_before": lock, "tls_lock_after": identity(ROOT / "tls/Cargo.lock"), "staged_std_sha256": std_sha,
              "ring_stage": json.loads((stage / "STAGE.json").read_text()) if (stage / "STAGE.json").is_file() else None,
              "retirement": "Caller retains exact source/result/log through readback, then retires owned work/target/dummy buffers and unused private stage under campaign rules."}
    if result["tls_lock_after"] != lock:
        result["disposition"] = "FAIL"
    with (work / "RESULT.json").open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    print(json.dumps({"disposition": result["disposition"], "result": str(work / "RESULT.json")}))
    return 0 if result["disposition"] == "PASS" else code or 1


if __name__ == "__main__":
    raise SystemExit(main())
