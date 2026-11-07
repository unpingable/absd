#!/usr/bin/env python3
"""Build and qualify the current operator media's exact artifact chain.

Uses operator_image's canonical producer and filesystem reader. This is a
bounded qualification entry point, not a replacement release format. Admission
pins are supplied by the caller; build and boot receipts are separate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import boot_artifacts as ba
import operator_boot_binding as ob
import operator_build_receipt as br
import operator_image as op
import release_record
from e1000_rx import wait_rx_setup
from served_ram import served_qemu

ROOT = Path(__file__).resolve().parent.parent


def write(path, data):
    with path.open("x") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def read_pinned(path, pin):
    ba.need(ba.sha(path) == pin, "receipt identity changed: " + str(path))
    return json.loads(path.read_text())


def platform_build(args):
    receipt = read_pinned(args.build_receipt, args.build_receipt_sha256)
    ba.need(receipt["status"] == "success" and receipt["source"] == br.source(ROOT),
            "platform source differs from successful build")
    required = br.required_outputs(receipt.get("environment", {}))
    ba.need(required == br.required_outputs(), "platform App A selection differs from build")
    ba.need(set(required) <= set(receipt["outputs"]), "incomplete platform build outputs")
    for name, entry in receipt["outputs"].items():
        ba.need(ba.sha(ROOT / name) == entry["sha256"], "platform executable changed: " + name)
    return receipt


def inspect_media(out, kernel, build):
    binary = kernel / "build/external/target/debug/absd-kernel"
    config = kernel / "build/durable/iso-0/boot/grub/grub.cfg"
    # Exact canonical step-zero loader command, not a release/version label.
    grub = config.read_bytes()
    ob.validate_operator_grub(grub)
    iso = ob.verify_iso((out / op.ISO).read_bytes(), binary.read_bytes(), grub)
    catalog = ob.verify_kernel_catalog(binary.read_bytes(), {
        "external-workload": (ROOT / "sshd.elf").read_bytes(),
        "file-server": (ROOT / "absd-fsd.elf").read_bytes(),
        "logd": (ROOT / "absd-logd.elf").read_bytes()})
    files = op.tree(out / op.IMAGE)
    selected = release_record.parse_selected(files["/absd/selected"])
    executed = {}
    for name in ("uname", "sha256sum", "absd-sh", "shutdown", "release"):
        source = "commands/" + name
        # shutdown is a shell builtin; it has no separately loaded ELF.
        if name == "shutdown":
            continue
        physical = release_record.physical("/bin/" + name, selected)
        expected = build["outputs"][source]["sha256"]
        ba.need(hashlib.sha256(files[physical]).hexdigest() == expected,
                "disk executable differs from produced output: " + physical)
        executed[physical] = expected
    installed_apps = {}
    if "commands/https-document" in build["outputs"]:
        physical = release_record.physical("/bin/https-document", selected)
        expected = build["outputs"]["commands/https-document"]["sha256"]
        ba.need(physical in files and hashlib.sha256(files[physical]).hexdigest() == expected,
                "disk App A differs from produced output")
        installed_apps[physical] = expected
    manifest = (out / "MANIFEST").read_text().splitlines()
    named = {}
    for line in manifest:
        if line.startswith("file "):
            _, digest, name = line.split(" ", 2)
            ba.need(name not in named, "duplicate manifest member")
            named[name] = digest
    actual = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    ba.need(named == actual, "operator manifest differs from actual disk files")
    ba.need([line for line in manifest if line.startswith("iso ")] == ["iso " + ba.sha(out / op.ISO)],
            "operator manifest names another ISO")
    return {"iso_structure": iso, "catalog": catalog, "selected_release": selected,
            "executed_files": executed, "installed_apps": installed_apps, "disk_files": actual,
            "iso_sha256": ba.sha(out / op.ISO), "disk_sha256": ba.sha(out / op.IMAGE),
            "manifest_sha256": ba.sha(out / "MANIFEST")}


def build(args):
    produced = platform_build(args)
    kernel_source = br.source(args.kernel)
    ba.need(kernel_source["revision"] == args.kernel_commit, "wrong kernel source")
    ba.need(not (args.kernel / "build").exists(), "kernel build directory must be fresh")
    ba.need(not args.out.exists(), "fresh media output required")
    args.out.mkdir()
    command = [sys.executable, "-I", str(ROOT / "scripts/operator_image.py"), "build",
               "--kernel", str(args.kernel), "--authorized-keys", str(args.authorized_keys),
               "--qemu", str(args.qemu) + " -accel tcg -cpu max,vendor=GenuineIntel,+rdrand", str(args.out)]
    with (args.out / "producer.log").open("xb") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    ba.need(result.returncode == 0, "canonical operator producer failed; see producer.log")
    ba.need(br.source(args.kernel) == kernel_source, "kernel source changed during build")
    ba.need(platform_build(args) == produced, "platform build changed during media construction")
    media = inspect_media(args.out, args.kernel, produced)
    write(args.out / "BOOT-BINDING.json", {
        "schema": 1, "source": produced["source"], "kernel_source": kernel_source,
        "build_receipt_sha256": args.build_receipt_sha256, "media": media,
        "producer": {"command": command, "rc": result.returncode,
                     "log_sha256": ba.sha(args.out / "producer.log"), "fresh_kernel_build": True},
        "qemu_sha256": ba.sha(args.qemu),
        "scope": "Canonical operator_image build; no media-profile portability or reproducibility claim."})
    print("OPERATOR BINDING BUILT " + ba.sha(args.out / "BOOT-BINDING.json"))


def boot(args):
    binding = read_pinned(args.out / "BOOT-BINDING.json", args.binding_sha256)
    produced = platform_build(args)
    ba.need(binding["build_receipt_sha256"] == args.build_receipt_sha256,
            "media binds another platform build")
    ba.need(binding["kernel_source"] == br.source(args.kernel), "kernel source changed")
    ba.need(binding["source"] == produced["source"], "media binds another source")
    media = inspect_media(args.out, args.kernel, produced)
    ba.need(media == binding["media"], "media/ELF binding changed")
    args.results.mkdir()
    disk = args.results / op.IMAGE
    shutil.copyfile(args.out / op.IMAGE, disk)
    os.chmod(disk, 0o600)
    console = args.results / "console.log"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    guest, guest_port = op.endpoint(disk)
    network = guest.rsplit(".", 1)[0] + ".0/24"
    command = [*served_qemu([str(args.qemu)]), "-accel", "tcg", "-cpu", "max,vendor=GenuineIntel,+rdrand",
               "-rtc", "base=utc", "-cdrom", str(args.out / op.ISO),
               "-drive", f"file={disk},format=raw,if=ide,index=0",
               "-netdev", f"user,id=n0,net={network},hostfwd=tcp:127.0.0.1:{port}-{guest}:{guest_port}",
               "-device", "e1000,netdev=n0", "-display", "none", "-serial", f"file:{console}",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    result = {"passed": False, "binding_sha256": args.binding_sha256, "sessions": {}}
    process = None
    try:
        with (args.results / "qemu.log").open("xb") as log:
            process = ba.launch(command, iso_sha256=media["iso_sha256"], disk_sha256=media["disk_sha256"],
                                qemu_sha256=binding["qemu_sha256"], record_path=args.results / "LAUNCH.json",
                                stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 420
            while True:
                raw = console.read_bytes() if console.exists() else b""
                text = raw.decode(errors="replace") + "\n" + op.ssh_absd.captured(raw)
                import re
                keys = re.findall(r"(?m)^sshd: host key (ssh-ed25519 [A-Za-z0-9+/=]+)$", text)
                ba.need(not any(x in text for x in ("ABSD PANIC", "KERNEL FAULT", "MACHINE STOP")), "guest fault")
                if "SSH LISTENING" in text and keys:
                    break
                ba.need(process.poll() is None and time.monotonic() < deadline, "guest did not become ready")
                time.sleep(.2)
            wait_rx_setup(lambda: console.read_bytes(), lambda: process.poll() is None, deadline)
            known = args.results / "known_hosts"
            known.write_text(f"[127.0.0.1]:{port} {keys[0]}\n")
            ssh = ["ssh", "-F", "/dev/null", "-i", str(args.login_key), "-p", str(port), "-o", "IdentityAgent=none",
                   "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                   "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"UserKnownHostsFile={known}",
                   "-o", "ConnectTimeout=30", "operator@127.0.0.1"]
            for word in ("sha256sum /bin/uname /bin/sha256sum /bin/absd-sh /bin/release", "uname", "release", "shutdown"):
                done = subprocess.run([*ssh, word], capture_output=True, timeout=180)
                result["sessions"][word] = {"rc": done.returncode, "stdout": done.stdout.decode(errors="replace"),
                                           "stderr": done.stderr.decode(errors="replace")}
                if word != "shutdown":
                    ba.need(done.returncode == 0, "guest command failed: " + word)
            status = process.wait(timeout=180)
            result["qemu_status"] = status
            ba.need(status == 3, "guest did not halt cleanly")
            observed = result["sessions"]["sha256sum /bin/uname /bin/sha256sum /bin/absd-sh /bin/release"]["stdout"]
            for name, expected in media["executed_files"].items():
                logical = "/bin/" + name.rsplit("/", 1)[1]
                ba.need(any(line.split() == [expected, logical] for line in observed.splitlines()),
                        "guest executable hash mismatch: " + logical)
            after = op.tree(disk)
            for name, expected in media["executed_files"].items():
                ba.need(hashlib.sha256(after[name]).hexdigest() == expected, "executed file changed: " + name)
            ba.need(after["/absd/selected"] == release_record.selected_bytes(media["selected_release"]),
                    "release selection changed")
            result["passed"] = True
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        result["console_sha256"] = ba.sha(console) if console.exists() else None
        result["launch_sha256"] = ba.sha(args.results / "LAUNCH.json") if (args.results / "LAUNCH.json").exists() else None
        result["disk_after_sha256"] = ba.sha(disk)
        disk.unlink()  # contains the occurrence's disposable guest host key
        result["disk_retired"] = True
        write(args.results / "RESULT.json", result)
    print("OPERATOR BINDING EXECUTED")



def execution_status(out, results, binding_pin):
    """Consume the existing terminal boot/launch receipts, not a PASS label."""
    binding = read_pinned(out / "BOOT-BINDING.json", binding_pin)
    result = json.loads((results / "RESULT.json").read_text())
    ba.need(result.get("passed") is True and result.get("binding_sha256") == binding_pin
            and result.get("qemu_status") == 3 and result.get("disk_retired") is True,
            "operator media has no successful terminal execution")
    ba.need(result.get("console_sha256") and ba.sha(results / "console.log") == result["console_sha256"],
            "operator console identity differs")
    launch = read_pinned(results / "LAUNCH.json", result["launch_sha256"])
    ba.need(launch.get("admitted") is True and launch.get("iso_sha256") == binding["media"]["iso_sha256"]
            and launch.get("disk_before_sha256") == binding["media"]["disk_sha256"]
            and launch.get("qemu_sha256") == binding["qemu_sha256"], "operator launch/media binding differs")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "boot", "status"))
    for flag in ("kernel", "out", "qemu", "build-receipt"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--build-receipt-sha256", required=True)
    parser.add_argument("--kernel-commit")
    parser.add_argument("--authorized-keys", type=Path)
    parser.add_argument("--binding-sha256")
    parser.add_argument("--login-key", type=Path)
    parser.add_argument("--results", type=Path)
    args = parser.parse_args()
    for name in ("kernel", "out", "qemu", "build_receipt", "authorized_keys", "login_key", "results"):
        if getattr(args, name) is not None:
            setattr(args, name, getattr(args, name).absolute())
    if args.mode == "build":
        ba.need(args.kernel_commit and args.authorized_keys, "build needs kernel commit and authorized keys")
        build(args)
    elif args.mode == "boot":
        ba.need(args.binding_sha256 and args.login_key and args.results, "boot needs binding pin, login key and fresh results")
        boot(args)
    else:
        ba.need(args.binding_sha256 and args.results, "status needs binding pin and terminal results")
        execution_status(args.out, args.results, args.binding_sha256)
        print("PASS")


if __name__ == "__main__":
    main()
