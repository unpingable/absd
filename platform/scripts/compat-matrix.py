#!/usr/bin/env python3
"""The source-portability probe on ABSD (docs/COMPATIBILITY-LEDGER.md).

Importer boots install the probe's unmodified upstream programs under /bin
and its inputs under /data; the host reads every file back. Then init runs
compat-launch as the durable worker: it runs each case of compat/cases.tsv
through std::process::Command (each program read from the filesystem and
started with the kernel's spawn_image) and prints stdout, stderr, and exit
status in a fixed framing. The same cases run here against the Linux
reference build of the same sources, with the same argv[0], working
directory contents, empty environment, and stdin.

Requires: the capture equals compat-expected.txt; every case agrees with
Linux (stdout, stderr, status) except those compat/divergences.txt names,
and each named case really differs; every started image is in the kernel's
spawn log; the kernel's accounting line shows nothing left behind.
"""

import argparse
import hashlib
import importlib.util
import pathlib
import re
import subprocess
import sys
import tempfile

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("exec_matrix", here / "exec-matrix.py")
em = importlib.util.module_from_spec(spec)
spec.loader.exec_module(em)
require = em.require

# 32 MiB: the filesystem region (the second half, 16 MiB) holds about 13 MB
# of programs. A larger region is not formatted within init's worker
# deadline under TCG.
em.IMAGE_BYTES = 32 * 1024 * 1024
em.DEVICE_SECTORS = em.IMAGE_BYTES // 512


def blob():
    """200,000 deterministic bytes (a SHA-256 chain), large enough that
    b3sum would map the file and hash it on several threads on Linux."""
    out, state = bytearray(), b"absd-compat"
    while len(out) < 200_000:
        state = hashlib.sha256(state).digest()
        out += state
    return bytes(out[:200_000])


def captured_bytes(serial):
    data = bytearray()
    for match in em.dm.CHUNK.finditer(serial):
        require(int(match.group(1), 16) == len(data), "non-contiguous captured output")
        data.extend(bytes.fromhex(match.group(2).decode("ascii")))
    return bytes(data)


def cases(text):
    return [line.split("\t") for line in text.splitlines() if line and not line.startswith("#")]


def split_cases(stream):
    """Case records of a launcher-framed stream, keyed by their header."""
    records = {}
    for chunk in re.split(rb"(?m)^(?=== )", stream):
        if chunk.startswith(b"== "):
            header, _, body = chunk.partition(b"\n")
            records[header[3:].decode()] = body
    return records


class Matrix(em.Matrix):
    def __init__(self, args):
        root = pathlib.Path(args.compat).resolve()
        self.data = root / "data"
        self.cases_text = (root / "cases.tsv").read_text()
        self.divergences = {}
        for line in (root / "divergences.txt").read_text().splitlines():
            if line and not line.startswith("#"):
                case, _, reason = line.partition("\t")
                self.divergences[case] = reason
        self.linux = pathlib.Path(args.linux).resolve()
        super().__init__(args)
        self.expected_bytes = pathlib.Path(args.expected).read_bytes()

    def data_files(self):
        files = [(f"/data/{path.relative_to(self.data)}", path.read_bytes())
                 for path in sorted(self.data.rglob("*")) if path.is_file()]
        files.append(("/data/blob.bin", blob()))
        return files

    def files(self):
        programs = sorted(path for path in self.commands.iterdir())
        return [(f"/bin/{path.name}", path.read_bytes()) for path in programs] + self.data_files()

    def linux_stream(self):
        out = bytearray()
        with tempfile.TemporaryDirectory() as scratch:
            data = pathlib.Path(scratch) / "data"
            for path, content in self.data_files():
                target = data / path.removeprefix("/data/")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            for fields in cases(self.cases_text):
                stdin, program, args = fields[0], fields[1], fields[2:]
                out += f"== {' '.join(fields[1:])}\n".encode()
                result = subprocess.run(
                    [program, *args], executable=self.linux / pathlib.Path(program).name,
                    cwd=data, env={}, capture_output=True,
                    input=None if stdin == "-" else (data / stdin).read_bytes(),
                    stdin=subprocess.DEVNULL if stdin == "-" else None)
                out += result.stdout + b"-- stderr\n" + result.stderr
                out += f"-- status {result.returncode}\n".encode()
        out += f"COMPAT LAUNCH DONE cases={len(cases(self.cases_text))}\n".encode()
        return bytes(out)

    def run(self):
        linux = self.linux_stream()
        (self.work / "compat.linux.txt").write_bytes(linux)

        image = self.work / "compat.img"
        with open(image, "wb") as handle:
            handle.truncate(em.IMAGE_BYTES)
        self.install(image, self.files())

        status, serial, _ = self.boot("compat", 4, image, self.cases_text.encode(), self.probe)
        text = serial.decode(errors="replace")
        absd = captured_bytes(serial)
        (self.work / "compat.captured.txt").write_bytes(absd)
        require(status == 3 and "DURABLE WORKLOAD OK" in text, f"compat boot: status {status}\n{absd!r}")
        require(re.search(r"^DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ", text, re.M),
                "the kernel's accounting line shows something left behind")
        count = len(cases(self.cases_text))
        images = re.findall(r"^SPAWN OK pid=\d+ parent=\d+ program=image$", text, re.M)
        require(len(images) == count, f"{len(images)} image spawns in the kernel log, expected {count}")
        require(absd == self.expected_bytes,
                "captured output differs from compat-expected.txt (see compat.captured.txt)")

        ours, theirs = split_cases(absd), split_cases(linux)
        require(list(ours) == list(theirs) and len(ours) == count, "case lists differ")
        agree, agreeing = 0, set()
        for case in ours:
            same = ours[case] == theirs[case]
            if case in self.divergences:
                require(not same, f"listed as divergent but agrees with Linux: {case}")
                print(f"COMPAT DIVERGES {case} :: {self.divergences[case]}")
            else:
                require(same, f"differs from Linux: {case}\nABSD:\n{ours[case].decode(errors='replace')}"
                              f"\nLinux:\n{theirs[case].decode(errors='replace')}")
                agree += 1
                agreeing.add(pathlib.Path(case.split(" ")[0]).name)
        # A program counts as ran when at least one of its cases agrees
        # with Linux byte for byte.
        print(f"COMPAT MATRIX OK programs={len(agreeing)} cases={count} agree={agree} "
              f"diverge={len(self.divergences)} images={len(images)} frames=0 processes=0 cells=0 pipes=0")


def main():
    parser = argparse.ArgumentParser()
    for name in ["kernel", "importer", "launcher", "commands", "linux", "compat", "expected", "work",
                 "qemu"]:
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    args.probe = args.launcher
    Matrix(args).run()


if __name__ == "__main__":
    main()
