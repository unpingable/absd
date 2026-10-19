#!/usr/bin/env python3
"""Filesystem execution on ABSD (kernel docs/PROCESS-STARTUP.md).

Importer boots carry the commands (and the probe itself) into the ABSD
filesystem under /bin, plus a text file and a truncated image to refuse;
the host reads the filesystem back and requires every file byte for byte.
Then init runs exec-probe as the durable worker: it holds the read-write
block handle and the spawn right, and starts the /bin programs through
std::process::Command, each read from the filesystem and started with the
kernel's spawn_image. The whole captured stream must equal
exec-expected.txt, every started image must appear in the kernel's own
spawn log, the kernel's accounting line must show nothing left behind, and
the device afterwards must hold what the parent wrote and nothing a child
tried to write.
"""

import argparse
import hashlib
import importlib.util
import pathlib
import re
import struct
import subprocess
import sys

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
from served_ram import served_qemu
from served_kernel import kernel_make
import absd_fs
import release_record  # noqa: E402
import absd_inputs  # noqa: E402

spec = importlib.util.spec_from_file_location("durable_matrix", here / "durable-matrix.py")
dm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dm)

IMAGE_BYTES = 16 * 1024 * 1024
DEVICE_SECTORS = IMAGE_BYTES // 512
# Bytes one importer boot streams through init's pipe: well inside init's
# worker deadline under TCG.
IMPORT_BUDGET = 1024 * 1024
COMMANDS = ["echo", "pwd", "ls", "cat", "printenv", "uname"]
MOTD = b"Welcome to ABSD.\n"
# Every image the probe and its children start, in the kernel's spawn log:
# FS EXEC 3, ARGV ENV 3, CWD 6, FS SPAWN 1 + 6 nested, the others 6, and
# the two views of the parent's file. Refused images never appear.
EXPECTED_IMAGE_SPAWNS = 27


def fail(message):
    print(f"EXEC MATRIX FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def require(condition, message):
    if not condition:
        fail(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def stream(entries):
    """The importer's input: (path, bytes) pairs."""
    out = bytearray(b"ABSDFIX1")
    for path, data in entries:
        name = path.encode()
        out += struct.pack("<H", len(name)) + name + struct.pack("<Q", len(data))
        out += hashlib.sha256(data).digest() + data
    out += struct.pack("<H", 0)
    return bytes(out)


def import_plan(files):
    """Boots of (step, entries): creating boots (step 1, then 2) of at most
    IMPORT_BUDGET bytes, and append boots (step 3) for a file larger than
    that, whose first part a creating boot made."""
    boots, current, used, appends = [], [], 0, []
    for path, data in files:
        head, rest = data[:IMPORT_BUDGET], data[IMPORT_BUDGET:]
        if current and used + len(head) > IMPORT_BUDGET:
            boots.append(current)
            current, used = [], 0
        current.append((path, head))
        used += len(head)
        while rest:
            appends.append((path, rest[:IMPORT_BUDGET]))
            rest = rest[IMPORT_BUDGET:]
    if current:
        boots.append(current)
    plan = [(1 if index == 0 else 2, entries) for index, entries in enumerate(boots)]
    plan += [(3, [entry]) for entry in appends]
    return plan


class Matrix:
    def __init__(self, args):
        self.kernel = pathlib.Path(args.kernel).resolve()
        require(not absd_inputs.is_kernel_source(self.kernel), "refusing the canonical kernel checkout")
        self.importer = pathlib.Path(args.importer).resolve()
        self.probe = pathlib.Path(args.probe).resolve()
        self.commands = pathlib.Path(args.commands).resolve()
        self.expected = pathlib.Path(args.expected).read_text()
        self.work = pathlib.Path(args.work).resolve()
        self.qemu = args.qemu
        self.work.mkdir(parents=True, exist_ok=True)
        self.boots = 0

    def boot(self, name, step, image, input_bytes, worker):
        input_path = self.work / f"input-{sha256(input_bytes)}.bin"
        input_path.write_bytes(input_bytes)
        subprocess.run([*kernel_make(), "--no-print-directory", "-C", str(self.kernel), "durable-iso",
                        f"DURABLE_STEP={step}", f"EXTERNAL_USER_ELF={worker}",
                        f"EXTERNAL_INPUT={input_path}", "EXTERNAL_READER_ELF=", "EXTERNAL_READER_INPUT=",
                        "BROKER_POLICY="],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        iso = self.kernel / "build" / "durable" / f"absd-durable-{step}.iso"
        self.boots += 1
        log = self.work / f"{name}.{self.boots:03d}.serial.log"
        result = subprocess.run(
            [str(self.kernel / "scripts" / "durable-boot.sh"), str(iso), str(image), str(log), "600",
             *served_qemu(self.qemu)], check=True, capture_output=True, text=True)
        serial = log.read_bytes()
        require(b"PANIC" not in serial and b"KERNEL FAULT" not in serial, f"{name}: kernel fault")
        return int(result.stdout.strip()), serial, dm.Harness.captured(serial)

    def files(self):
        echo = (self.commands / "echo").read_bytes()
        files = [(f"/bin/{name}", (self.commands / name).read_bytes()) for name in COMMANDS]
        files.append(("/bin/exec-probe", self.probe.read_bytes()))
        # Refused by spawn_image: an ELF cut short, and a text file.
        files.append(("/bin/truncated", echo[:4096]))
        files.append(("/etc/motd", MOTD))
        return files

    def install(self, image, files):
        for step, entries in import_plan(files):
            status, serial, captured = self.boot(f"import-{step}", step, image, stream(entries),
                                                 self.importer)
            require(status == 3 and f"FIXTURE IMPORT OK files={len(entries)}" in captured,
                    f"import step {step}: status {status}\n{captured}")
        region = absd_fs.fs_region(image, DEVICE_SECTORS)
        selected = absd_fs.select(region)
        tree = absd_fs.tree(region, selected)
        for path, data in files:
            require(path in tree and absd_fs.content(region, selected, tree[path]) == data,
                    f"host reader sees different bytes at {path}")
        print(f"EXEC FILES INSTALLED files={len(files)} bytes={sum(len(data) for _, data in files)}")

    def run(self):
        image = self.work / "exec.img"
        with open(image, "wb") as handle:
            handle.truncate(IMAGE_BYTES)
        files = self.files()
        self.install(image, files)

        status, serial, captured = self.boot("exec", 4, image, b"", self.probe)
        text = serial.decode(errors="replace")
        (self.work / "exec.captured.txt").write_text(captured)
        require(status == 3 and "DURABLE WORKLOAD OK" in text, f"exec boot: status {status}\n{captured}")
        # uname -a names the release id the commands were built with
        # (ABSD_RELEASE_ID); the expected stream names it as `dev`, so the
        # built id is checked here and then normalised before the comparison.
        release_id = release_record.release_id_from_env()
        require(f"uname=ABSD {release_id} " in captured,
                f"uname does not name the built release id {release_id}:\n{captured}")
        captured = captured.replace(f"uname=ABSD {release_id} ", "uname=ABSD dev ")
        require(captured == self.expected,
                f"captured output differs from the expected stream:\n{captured}")
        require(re.search(r"^DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ", text, re.M),
                "the kernel's accounting line shows something left behind")
        images = re.findall(r"^SPAWN OK pid=\d+ parent=\d+ program=image$", text, re.M)
        require(len(images) == EXPECTED_IMAGE_SPAWNS,
                f"{len(images)} image spawns in the kernel log, expected {EXPECTED_IMAGE_SPAWNS}")
        killed = re.findall(r"^USER KILLED pid=\d+ by=\d+$", text, re.M)
        require(len(killed) == 1, f"expected exactly one kill, saw {len(killed)}")

        region = absd_fs.fs_region(image, DEVICE_SECTORS)
        selected = absd_fs.select(region)
        tree = absd_fs.tree(region, selected)
        require(absd_fs.content(region, selected, tree["/etc/written-by-parent"])
                == b"committed before the child started\n", "the parent's file is not on the device")
        require("/etc/child-was-here" not in tree and "/child" not in tree,
                "a child's write reached the device")
        for path, data in files:
            require(absd_fs.content(region, selected, tree[path]) == data, f"{path} changed")

        # Kernel refusals: the text file and the truncated image (via
        # Command), seven raw requests, and the child without the spawn right.
        print(f"FS EXEC OK images={len(images)} kernel-refusals=10 frames=0 processes=0 cells=0 pipes=0")
        print("ARGV ENV OK")
        print("CWD OK")
        print("FS SPAWN OK depth=2 status=7")
        print("EXEC VIEW READ ONLY OK file=refused mkdir=refused raw-block=-1")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--importer", required=True)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--commands", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--qemu", required=True)
    Matrix(parser.parse_args()).run()


if __name__ == "__main__":
    main()
