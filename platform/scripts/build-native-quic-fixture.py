#!/usr/bin/env python3
"""Build only the admitted private QUIC fixture in its isolated workspace.

Run on the admitted cloud builder, never on the shared development host.
The public fixture root is a separately sealed build input, not tracked source.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def verify_ipv6_client(receipt, client_sha256, root_sha256, revision, tree):
    """Bind reused child bytes to the same source, family and trust input."""
    if (receipt.get("source_revision") != revision or receipt.get("source_tree") != tree
            or receipt.get("transport_family") != "ipv6"
            or receipt.get("root_der", {}).get("sha256") != root_sha256
            or receipt.get("outputs", {}).get("quic_echo", {}).get("sha256") != client_sha256
            or receipt.get("tracked_dirty") is not False
            or receipt.get("untracked_source") is not False):
        raise ValueError("IPv6 service child source/family/root receipt differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--client-only", action="store_true")
    mode.add_argument("--service-only", action="store_true")
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--cargo-home", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--family", choices=("ipv4", "ipv6"), default="ipv4")
    parser.add_argument("--client-receipt", type=Path)
    args = parser.parse_args()
    if args.receipt.exists():
        raise SystemExit("build receipt already exists; preserve it and choose a new receipt")
    root_der = Path(os.environ["ABSD_QUIC_ROOT_DER"])
    if not root_der.is_absolute() or root_der.is_symlink():
        raise SystemExit("public root must be an absolute regular file")
    root_der = root_der.resolve()
    if root_der.parent != ROOT / "fixtures/native-quic/pki" or root_der.suffix != ".der":
        raise SystemExit("public root must use the declared generated certificate directory")
    if not root_der.is_file() or not 0 < root_der.stat().st_size <= 4096:
        raise SystemExit("public root size is invalid")
    expected_root = os.environ["ABSD_QUIC_ROOT_SHA256"]
    if sha(root_der) != expected_root:
        raise SystemExit("public root differs from the separately sealed PKI input")
    target = json.loads((ROOT / "targets/x86_64-unknown-absd.json").read_text())
    if target["cpu"] != "x86-64" or target["features"] != "+sse,+sse2":
        raise SystemExit("fixture requires the literal generic x86-64 compile target")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise SystemExit("source is dirty or contains untracked inputs; build inputs must be sealed first")
    # Check declared registry and path-patched inputs before staging or compiling.
    pin_check = json.loads(subprocess.check_output(
        [sys.executable, str(ROOT / "scripts/check-native-quic-pins.py")], cwd=ROOT, text=True))
    cargo_home = args.cargo_home.resolve()
    stage = args.stage.resolve()
    if not cargo_home.is_dir():
        raise SystemExit("private Cargo home is missing")
    # Refuse inherited compiler/CPU/optimization overrides by removing them.
    removed = sorted(key for key in os.environ if key in {
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTDOC", "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER", "CC", "CXX", "AR", "ARFLAGS", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
        "CRATE_CC_NO_DEFAULTS",
        "ABSD_RESTRICTED_STD_ALL", "ABSD_RUST_REMAP", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_TARGET",
        "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    } or key.startswith(("CARGO_PROFILE_", "CARGO_TARGET_", "RUSTC_BOOTSTRAP", "CC_", "AR_", "ARFLAGS_", "CFLAGS_", "CPPFLAGS_", "CXX_", "CXXFLAGS_")))
    env = {key: value for key, value in os.environ.items() if key not in removed}
    toolchain = Path(env.get("ABSD_RUST_TOOLCHAIN", str(Path.home() / ".rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu")))
    env.update(CARGO_HOME=str(cargo_home), CARGO_BUILD_JOBS="1", ABSD_PROFILE="core",
               ABSD_REAL_RUSTC=str(toolchain / "bin/rustc"),
               ABSD_STAGED_SYSROOT=str(ROOT / ".staged-sysroot"),
               RUSTC=str(ROOT / "scripts/rustc-staged.sh"), RUSTC_BOOTSTRAP="1",
               RUST_TARGET_PATH=str(ROOT / "targets"), CARGO_TARGET_DIR=str(ROOT / "quic/target"),
               ABSD_QUIC_ROOT_DER=str(root_der), ABSD_QUIC_ROOT_SHA256=expected_root,
               ABSD_QUIC_FAMILY=args.family,
               CARGO_ENCODED_RUSTFLAGS="\x1f".join(["-Zunstable-options", "-C", "link-arg=-Tuser-linker.ld", "-C", "link-arg=--gc-sections", "--cfg", 'getrandom_backend="custom"']))
    # Match the established native C profile used by build-ag-loopctl.sh.
    # A host C compiler otherwise imports hosted ABI assumptions into ring.
    cc = shutil.which("clang-18", path=env.get("PATH"))
    ar = shutil.which("llvm-ar-18", path=env.get("PATH"))
    if cc is None or ar is None:
        raise SystemExit("native QUIC requires clang-18 and llvm-ar-18")
    clang_include = Path(subprocess.check_output([cc, "-print-resource-dir"], text=True).strip()) / "include"
    if not clang_include.is_absolute() or not clang_include.is_dir():
        raise SystemExit("Clang builtin headers are unavailable")
    cflags = ["--target=x86_64-unknown-none-elf", "-ffreestanding", "-nostdinc",
              "-isystem", str(clang_include), "-I" + str(ROOT / "sqlite/include"),
              "-mcmodel=large", "-fno-pic", "-O2", "-ffunction-sections", "-fdata-sections"]
    env.update(CC_x86_64_unknown_absd=cc, AR_x86_64_unknown_absd=ar,
               CRATE_CC_NO_DEFAULTS="1", CFLAGS_x86_64_unknown_absd=shlex.join(cflags))
    c_toolchain = {"compiler": {"path": cc, "sha256": sha(Path(cc)),
                               "version": subprocess.check_output([cc, "--version"], text=True)},
                   "archiver": {"path": ar, "sha256": sha(Path(ar)),
                                "version": subprocess.check_output([ar, "--version"], text=True)},
                   "builtin_include": str(clang_include), "flags": cflags,
                   "platform_headers": {path.name: sha(path) for path in sorted((ROOT / "sqlite/include").iterdir()) if path.is_file()}}
    subprocess.run(["python3", str(ROOT / "scripts/check-native-quic-source.py")], cwd=ROOT, env=env, check=True)
    subprocess.run(["python3", str(ROOT / "scripts/stage-native-tls-fixture.py"), "--stage", str(stage),
                    "--cargo-home", str(cargo_home)], cwd=ROOT, env=env, check=True)
    staged_ring = stage / "ring"
    link = ROOT / "quic/tree/ring"
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink():
        if link.resolve() != staged_ring.resolve():
            raise SystemExit("QUIC ring link points outside the admitted exact stage")
    elif link.exists():
        raise SystemExit("QUIC ring link is not a symlink")
    else:
        link.symlink_to(staged_ring)
    library = ROOT / ".staged-sysroot/lib/rustlib/src/rust/library"
    if not library.exists():
        subprocess.run([str(ROOT / "scripts/stage-library.sh")], cwd=ROOT, env=env, check=True)
    # Reuse only the established pinned std source identity. Replacing it on every
    # service selector would cause needless std rebuilds and obscure correspondence.
    library_files = sorted((path for path in library.rglob("*") if path.is_file()),
                           key=lambda path: path.relative_to(library).as_posix().encode())
    if any(path.is_symlink() for path in library.rglob("*")):
        raise SystemExit("staged std source contains a symlink")
    library_lines = "".join(f"{sha(path)}  library/{path.relative_to(library).as_posix()}\n" for path in library_files)
    std_hash = hashlib.sha256(library_lines.encode()).hexdigest()
    if std_hash != "c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c" or len(library_files) != 2251 or sum(path.stat().st_size for path in library_files) != 45920288:
        raise SystemExit("staged std source differs from the established patch identity")
    remaps = [f"--remap-path-prefix={ROOT}=/absd", f"--remap-path-prefix={cargo_home}/registry/src=/cargo/registry/src",
              f"--remap-path-prefix={stage}=/quic-fixture-stage"]
    # Encoded flags apply to the actual getrandom compilation as well as the
    # first-party crate. Cargo config alone would lose to this environment.
    env["CARGO_ENCODED_RUSTFLAGS"] += "\x1f" + "\x1f".join(remaps)
    remap_config = "target.x86_64-unknown-absd.rustflags=" + json.dumps(remaps)
    outputs = {}
    if not args.client_only:
        case = os.environ["ABSD_QUIC_CASE"]
        seconds = os.environ["ABSD_QUIC_UNIX_SECONDS"]
        cases = json.loads((ROOT / "quic/CASES.json").read_text())
        if case not in {entry["id"] for entry in cases["native_occurrences"]} | {"Q31"}:
            raise SystemExit("unknown fixture selector")
        if args.family == "ipv6" and case not in {"Q01", "Q08", "Q17"}:
            raise SystemExit("unreviewed private IPv6 consumer case")
        if not seconds.isascii() or not seconds.isdecimal() or seconds.startswith("0") or len(seconds) > 20:
            raise SystemExit("fixture time must be a canonical positive Unix seconds value")
        if int(seconds) > 2**64 - 16:
            raise SystemExit("fixture time would overflow the bounded provider")
        env["ABSD_QUIC_CASE"] = case
        env["ABSD_QUIC_UNIX_SECONDS"] = seconds


    def build(name, output):
        subprocess.run(["cargo", "+1.95.0", "--config", remap_config, "build", "--manifest-path", str(ROOT / "quic/Cargo.toml"),
                        "-Z", "build-std=core,alloc,std,panic_abort", "--release", "--locked", "--offline",
                        "--target", "x86_64-unknown-absd", "--bin", name], cwd=ROOT, env=env, check=True)
        subprocess.run(["llvm-strip-18", "-o", str(output), str(ROOT / "quic/target/x86_64-unknown-absd/release" / name)],
                       cwd=ROOT, env=env, check=True)
        outputs[name] = {"path": str(output), "sha256": sha(output), "bytes": output.stat().st_size}

    if args.service_only:
        client = Path(os.environ["ABSD_QUIC_CLIENT_ELF"])
        if not client.is_absolute() or not client.is_file() or sha(client) != os.environ["ABSD_QUIC_CLIENT_SHA256"]:
            raise SystemExit("service-only child differs from the sealed root-pinned executable")
        if args.family == "ipv6":
            if args.client_receipt is None or args.client_receipt.is_symlink():
                raise SystemExit("IPv6 service-only requires its exact child build receipt")
            verify_ipv6_client(json.loads(args.client_receipt.read_text()), sha(client), expected_root,
                               git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}"))
        outputs["quic_echo"] = {"path": str(client), "sha256": sha(client), "bytes": client.stat().st_size, "reused": True}
    else:
        client = ROOT / "quic-client.elf"
        build("quic_echo", client)
    env["ABSD_QUIC_CLIENT_ELF"] = str(client)
    if not args.client_only:
        build("quic_service_probe", ROOT / "quic-service-probe.elf")
    receipt = {"schema_version": 1, "source_revision": git("rev-parse", "HEAD"),
               "transport_family": args.family,
               "reused_client_receipt": ({"path": str(args.client_receipt), "sha256": sha(args.client_receipt)}
                                          if args.service_only and args.family == "ipv6" else None),
               "source_tree": git("rev-parse", "HEAD^{tree}"), "tracked_dirty": False, "untracked_source": False,
               "service_selectors": {key: env.get(key) for key in ["ABSD_QUIC_CASE", "ABSD_QUIC_UNIX_SECONDS"]} if not args.client_only else None,
               "reused_client_sha256": outputs["quic_echo"]["sha256"] if args.service_only else None,
               "root_der": {"path": str(root_der), "sha256": expected_root, "bytes": root_der.stat().st_size, "generated_ignored_input": True},
               "cargo_lock_sha256": sha(ROOT / "quic/Cargo.lock"), "staged_std_source_sha256": std_hash, "target_sha256": sha(ROOT / "targets/x86_64-unknown-absd.json"),
               "ring_stage": json.loads((stage / "STAGE.json").read_text()), "removed_environment_names": removed,
               "declared_pin_lock_check": pin_check,
               "explicit_environment": {key: env[key] for key in ["CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "ABSD_REAL_RUSTC", "ABSD_STAGED_SYSROOT", "RUSTC_BOOTSTRAP", "RUST_TARGET_PATH", "ABSD_PROFILE", "ABSD_QUIC_ROOT_DER", "ABSD_QUIC_ROOT_SHA256", "ABSD_QUIC_CLIENT_ELF", "CC_x86_64_unknown_absd", "AR_x86_64_unknown_absd", "CRATE_CC_NO_DEFAULTS", "CFLAGS_x86_64_unknown_absd"]},
               "native_c_toolchain": c_toolchain,
               "remap_config": remap_config, "outputs": outputs}
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    with args.receipt.open("x") as output:
        output.write(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"result": "QUIC fixture build completed", "receipt": str(args.receipt), "outputs": outputs}))


if __name__ == "__main__":
    main()
