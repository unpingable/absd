#!/usr/bin/env python3
"""absd-sh on ABSD: the shell is itself a filesystem executable.

Importer boots install the /bin commands, /bin/absd-sh, /bin/sh-probe,
/etc/motd, and a multi-kilobyte /etc/big; the host reads every file back.
Then init runs sh-launch as the durable worker: it starts /bin/absd-sh
through std::process::Command on its own standard input (sh-input.txt, a
scripted session with pipelines, input redirection, and output redirection
refused on the session's read-only view) and then as `absd-sh -c "ls /"`;
checks the pipe discipline with negative controls (a consumed end, a
retained writer suppressing end-of-file, a retained reader suppressing the
broken pipe, the kernel's -32 and std's BrokenPipe, one right per end); and
runs the shell's executor with its own write authority for `>`/`>>`. The
whole captured stream must equal sh-expected.txt, every started image must
appear in the kernel's spawn log, the kernel's accounting line must show
nothing left behind, and the device must hold what the shell redirected and
nothing a child tried to write.
"""

import argparse
import importlib.util
import pathlib
import re
import sys

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("exec_matrix", here / "exec-matrix.py")
em = importlib.util.module_from_spec(spec)
spec.loader.exec_module(em)
require = em.require

# Images started: the session's 17 (ls, cat, /bin/echo, cat /nosuch, cat
# after `echo hello |`, three cats, flood+count, cat+count, count,
# flood+head, the cat after `nosuch |`, cat motd), ls under the second
# shell, the two shells, the pipe checks' 7, and the writer-hosted
# executor's 5. Nothing refused (a missing program, a redirection that
# cannot open, a syntax error, a spawn the kernel refuses) appears.
EXPECTED_IMAGE_SPAWNS = 32
# /etc/big: 400 numbered lines, about 18 KiB, through `<` and `|`.
BIG = b"".join(b"%05d the quick brown fox jumps over the lazy dog\n" % i for i in range(400))


class Matrix(em.Matrix):
    def __init__(self, args):
        self.shell = pathlib.Path(args.shell).resolve()
        self.input = pathlib.Path(args.input).read_bytes()
        super().__init__(args)

    def files(self):
        files = [(f"/bin/{name}", (self.commands / name).read_bytes()) for name in em.COMMANDS]
        files.append(("/bin/absd-sh", self.shell.read_bytes()))
        files.append(("/bin/sh-probe", (self.commands / "sh-probe").read_bytes()))
        files.append(("/etc/motd", em.MOTD))
        files.append(("/etc/big", BIG))
        return files

    def run(self):
        image = self.work / "sh.img"
        with open(image, "wb") as handle:
            handle.truncate(em.IMAGE_BYTES)
        self.install(image, self.files())

        status, serial, captured = self.boot("sh", 4, image, self.input, self.probe)
        text = serial.decode(errors="replace")
        (self.work / "sh.captured.txt").write_text(captured)
        require(status == 3 and "DURABLE WORKLOAD OK" in text, f"shell boot: status {status}\n{captured}")
        require(captured == self.expected,
                f"captured output differs from the expected stream:\n{captured}")
        require(re.search(r"^DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ", text, re.M),
                "the kernel's accounting line shows something left behind")
        images = re.findall(r"^SPAWN OK pid=\d+ parent=\d+ program=image$", text, re.M)
        require(len(images) == EXPECTED_IMAGE_SPAWNS,
                f"{len(images)} image spawns in the kernel log, expected {EXPECTED_IMAGE_SPAWNS}")
        print(f"FS SHELL OK images={len(images)} session-status=3 command-status=0 "
              "frames=0 processes=0 cells=0 pipes=0")

        # The device: what the writer-hosted executor redirected, and
        # nothing any child tried to write, nor the session's refused `>`.
        region = em.absd_fs.fs_region(image, em.DEVICE_SECTORS)
        selected = em.absd_fs.select(region)
        tree = em.absd_fs.tree(region, selected)
        content = lambda path: em.absd_fs.content(region, selected, tree[path])
        require(content("/etc/redirected") == b"ESCAPE create=ReadOnlyFilesystem "
                b"target=ReadOnlyFilesystem raw-block=-1\nappended by the shell\n",
                "the redirected file on the device")
        flood_sum = sum(i % 251 for i in range(20000))
        require(content("/etc/counted") == b"COUNT bytes=20000 sum=%d\n" % flood_sum,
                "the pipeline's redirected output on the device")
        require(content("/etc/count-errors") == b"", "stderr redirection")
        for path in ["/etc/escaped", "/etc/out", "/etc/err"]:
            require(path not in tree, f"{path} reached the device")
        for path, data in self.files():
            require(content(path) == data, f"{path} changed")

        # Every line below is also in the exact expected stream; these name
        # what each acceptance line rests on.
        big_sum = sum(BIG)
        for line in [
            "absd$ COUNT bytes=65536 sum=%d" % sum(i % 251 for i in range(65536)),
            f"absd$ COUNT bytes={len(BIG)} sum={big_sum}",
            "absd$ hello",
            "SH PIPE retained-writer while-held=-110 running=true "
            "after-close=COUNT bytes=3000 sum=21000 status=0",
            "SH PIPE consumed parent-copy-after-spawn=-9 respawn=InvalidInput",
        ]:
            require(any(l.startswith(line) for l in captured.splitlines()), f"missing: {line}")
        print(f"SHELL PIPE OK echo-cat=1 three-stage=1 flood-count=65536 file-count={len(BIG)} "
              "retained-writer=no-eof-until-closed shell-copy-closed-at-spawn=1")
        for line in [
            "sh-probe flood: write failed: BrokenPipe; still running, exiting 3",
            "SH BROKEN PIPE reader-exited=0 raw=-32 std=BrokenPipe writer-still-running=yes",
        ]:
            require(line in captured.splitlines(), f"missing: {line}")
        print("SHELL BROKEN PIPE OK kernel=-32 std=BrokenPipe signal=none "
              "retained-reader=blocked-until-closed")
        print("SHELL REDIRECT OK executor=writer-hosted in=pipe-copy out=pipe-copy append=1 "
              "stderr=1 session-view=read-only-refused")
        print("SHELL AUTHORITY NARROWING OK child-stdout=pipe-end create=ReadOnlyFilesystem "
              "own-target=ReadOnlyFilesystem raw-block=-1 device=untouched")


def main():
    parser = argparse.ArgumentParser()
    for name in ["kernel", "importer", "launcher", "shell", "commands", "input", "expected", "work",
                 "qemu"]:
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    args.probe = args.launcher
    Matrix(args).run()


if __name__ == "__main__":
    main()
