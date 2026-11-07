"""Bind the operator qualification boot to its admitted ISO and disk bytes.

Linux/QEMU only. The ISO is a sealed memfd; the writable disk is an open,
inode-pinned occurrence copy. QEMU starts paused. Before cont, QMP and /proc
must agree on the actual executable, command, and opened block inputs.
This does not attest firmware or a compiler, or protect a writable disk from
an unrelated concurrent writer. The caller owns the isolated disk and process.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import time


class Refused(ValueError):
    pass


def sha(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def need(ok, message):
    if not ok:
        raise Refused(message)


def operator_inputs(command):
    """Accept the existing operator-boot shape, with no second boot source."""
    values = {"-m", "-accel", "-cpu", "-rtc", "-cdrom", "-drive", "-netdev",
              "-device", "-display", "-serial"}
    flags = {"-no-reboot", "-no-shutdown"}
    seen = {}
    index = 1
    while index < len(command):
        key = command[index]
        if key in flags:
            need(key not in seen, "duplicate QEMU option: " + key)
            seen[key] = True
            index += 1
            continue
        need(key in values and index + 1 < len(command), "unsupported QEMU option: " + key)
        need(key == "-device" or key not in seen, "duplicate QEMU option: " + key)
        value = command[index + 1]
        if key == "-device":
            need(value in ("e1000,netdev=n0", "isa-debug-exit,iobase=0xf4,iosize=0x04"),
                 "unsupported QEMU device")
        seen[key] = value
        index += 2
    need("-cdrom" in seen and "-drive" in seen, "exactly one ISO and disk required")
    need("-no-shutdown" not in seen or "-no-reboot" in seen,
         "durable no-shutdown requires no-reboot")
    suffix = ",format=raw,if=ide,index=0"
    drive = seen["-drive"]
    need(drive.startswith("file=") and drive.endswith(suffix), "noncanonical operator disk")
    disk = drive[5:-len(suffix)]
    need(disk and "," not in disk, "ambiguous operator disk path")
    need(seen.get("-display") == "none", "headless operator boot required")
    return Path(seen["-cdrom"]), Path(disk)


class QMP:
    def __init__(self, path, process, deadline):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        while True:
            try:
                self.sock.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                need(process.poll() is None, "QEMU exited before QMP admission")
                need(time.monotonic() < deadline, "QMP admission timeout")
                time.sleep(.02)
        self.stream = self.sock.makefile("rwb")
        need("QMP" in self.read(), "not a QMP greeting")
        self.execute("qmp_capabilities")

    def read(self):
        line = self.stream.readline()
        need(line, "QMP closed during admission")
        return json.loads(line)

    def execute(self, name):
        self.stream.write((json.dumps({"execute": name, "id": name}) + "\n").encode())
        self.stream.flush()
        while True:
            result = self.read()
            if result.get("id") == name:
                need("return" in result, "QMP refused " + name + ": " + str(result))
                return result["return"]

    def close(self):
        self.stream.close()
        self.sock.close()


def launch(command, *, iso_sha256, disk_sha256, qemu_sha256, record_path, **popen_args):
    """Return the real QEMU Popen only after bound paused admission succeeds.

    The caller must retain the terminal status and workload evidence. A launch
    receipt alone is never a passed execution. No caller-supplied QMP/boot
    overrides, wrappers or alternative disks are admitted.
    """
    command = [str(x) for x in command]
    iso, disk = operator_inputs(command)
    executable = Path(command[0])
    need(executable.is_absolute(), "absolute QEMU executable required")
    need(sha(executable) == qemu_sha256, "QEMU executable changed")
    need(not set(popen_args) & {"pass_fds", "preexec_fn", "executable", "shell"},
         "unsupported Popen override")
    record_path = Path(record_path)
    # Reserve before any process exists; never overwrite an earlier occurrence.
    record_file = record_path.open("x")
    record = {"schema": 1, "admitted": False, "requested_command": command,
              "iso_sha256": iso_sha256, "disk_before_sha256": disk_sha256,
              "qemu_sha256": qemu_sha256}
    descriptors = []
    process = None
    qmp = None
    try:
        for path in (iso, disk):
            fd = os.open(path, (os.O_RDONLY if path == iso else os.O_RDWR) | os.O_NOFOLLOW)
            descriptors.append(fd)
            need(stat.S_ISREG(os.fstat(fd).st_mode), "boot input is not a regular file")
        source_fd, disk_fd = descriptors
        need((os.fstat(source_fd).st_dev, os.fstat(source_fd).st_ino) !=
             (os.fstat(disk_fd).st_dev, os.fstat(disk_fd).st_ino), "ISO and writable disk must differ")
        need(sha(f"/proc/self/fd/{disk_fd}") == disk_sha256, "disk differs from admitted bytes")
        sealed = os.memfd_create("absd-operator-iso", os.MFD_ALLOW_SEALING)
        descriptors.append(sealed)
        with os.fdopen(os.dup(source_fd), "rb") as source:
            while chunk := source.read(1024 * 1024):
                view = memoryview(chunk)
                while view:
                    view = view[os.write(sealed, view):]
        os.lseek(sealed, 0, os.SEEK_SET)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(sealed, fcntl.F_ADD_SEALS, seals)
        need(sha(f"/proc/self/fd/{sealed}") == iso_sha256, "ISO differs from admitted bytes")
        iso_path, disk_path = f"/proc/self/fd/{sealed}", f"/proc/self/fd/{disk_fd}"
        actual = list(command)
        actual[actual.index("-cdrom") + 1] = iso_path
        actual[actual.index("-drive") + 1] = f"file={disk_path},format=raw,if=ide,index=0"
        # Explicit ISO-first boot, no fallback to another device.
        with tempfile.TemporaryDirectory(prefix="absd-qmp-") as scratch:
            socket_path = Path(scratch) / "qmp"
            actual += ["-S", "-boot", "order=d,strict=on", "-qmp", f"unix:{socket_path},server=on,wait=off"]
            process = subprocess.Popen(actual, pass_fds=(sealed, disk_fd), **popen_args)
            record.update(pid=process.pid, command=actual)
            qmp = QMP(socket_path, process, time.monotonic() + 15)
            status = qmp.execute("query-status")
            need(status.get("running") is False and status.get("status") in ("prelaunch", "paused"),
                 "QEMU was not paused before admission")
            proc = Path(f"/proc/{process.pid}")
            need(sha(proc / "exe") == qemu_sha256, "actual QEMU executable mismatch")
            cmdline = (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
            need(cmdline == [os.fsencode(x) for x in actual], "actual QEMU argv mismatch")
            blocks = qmp.execute("query-block")
            inserted = [b["inserted"] for b in blocks if "inserted" in b]
            need(len(inserted) == 2 and {b["file"] for b in inserted} == {iso_path, disk_path},
                 "QEMU opened different block inputs")
            identities = {}
            for name, fd, expected in (("iso", sealed, iso_sha256), ("disk", disk_fd, disk_sha256)):
                opened = proc / "fd" / str(fd)
                ours, theirs = os.fstat(fd), opened.stat()
                need((ours.st_dev, ours.st_ino) == (theirs.st_dev, theirs.st_ino),
                     "QEMU opened another " + name)
                need(sha(opened) == expected, "opened " + name + " bytes changed before execution")
                identities[name] = {"device": theirs.st_dev, "inode": theirs.st_ino,
                                    "bytes": theirs.st_size, "sha256": expected}
            need(fcntl.fcntl(sealed, fcntl.F_GET_SEALS) & seals == seals, "ISO not sealed")
            record.update(start_ticks=(proc / "stat").read_text().rsplit(")", 1)[1].split()[19],
                          paused_status=status, qmp_blocks=blocks, opened_inputs=identities,
                          iso_seals=seals, admitted=True)
            # Write admission durably before releasing the vCPU.
            record_file.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
            record_file.flush()
            os.fsync(record_file.fileno())
            qmp.execute("cont")
            qmp.close()
            qmp = None
        return process
    except BaseException as error:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
        record.update(admitted=False, error=str(error))
        record_file.seek(0)
        record_file.truncate()
        record_file.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
        raise
    finally:
        if qmp is not None:
            qmp.close()
        for fd in descriptors:
            os.close(fd)
        record_file.close()
