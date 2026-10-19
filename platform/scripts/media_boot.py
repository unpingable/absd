"""One bounded, foreground UEFI boot of a media image under QEMU/OVMF in TCG
(scripts/media.py boot; ported from S4's validate-uefi.py). No host devices,
no network, no keys; the image is attached read-only as USB mass storage.
"""

import hashlib
import json
import pathlib
import shutil
import socket
import subprocess
import sys
import time
from served_ram import served_qemu


def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


class Qmp:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(10)
        self.sock.connect(str(path))
        self.file = self.sock.makefile("rwb", buffering=0)
        require("QMP" in json.loads(self.file.readline()), "check failed: 'QMP' in json.loads(self.file.readline())")
        self.call("qmp_capabilities")

    def call(self, name, args=None):
        message = {"execute": name}
        if args is not None:
            message["arguments"] = args
        self.file.write((json.dumps(message) + "\n").encode())
        while True:
            obj = json.loads(self.file.readline())
            if "error" in obj:
                raise RuntimeError(obj)
            if "return" in obj:
                return obj["return"]

    def close(self):
        self.file.close()
        self.sock.close()


class BootFailed(Exception):
    pass


def require(condition, reason):
    """An explicit check: unlike assert, it survives `python3 -O`."""
    if not condition:
        raise BootFailed(reason)


def qemu_path(path):
    """QEMU splits -drive values on commas; a path containing one is refused
    rather than escaped, so the attached file is always the named one."""
    text = str(path)
    if "," in text:
        raise BootFailed(f"path_refused {text!r} contains a comma")
    return text


def boot(image, mode, out, sentinel, code, vars_template, checker, expected, timeout=150,
         qemu="qemu-system-x86_64", env=None):
    out = pathlib.Path(out)
    out.mkdir(exist_ok=False)
    variables = out / "OVMF_VARS.fd"
    shutil.copyfile(vars_template, variables)
    qmp_path = out / "qmp.sock"
    serial = out / "serial.log"
    command = [*served_qemu([qemu]), "-machine", "q35,accel=tcg",
               "-cpu", "max,vendor=GenuineIntel,+rdrand", "-smp", "1",
               "-drive", f"if=pflash,format=raw,readonly=on,file={qemu_path(code)}",
               "-drive", f"if=pflash,format=raw,file={qemu_path(variables)}",
               "-device", "qemu-xhci,id=usb",
               "-drive", f"if=none,id=stick,format=raw,readonly=on,file={qemu_path(image)}",
               "-device", "usb-storage,drive=stick,bus=usb.0,bootindex=1",
               "-nic", "none", "-display", "none", "-vga", "std",
               "-serial", f"file:{qemu_path(serial)}", "-qmp", f"unix:{qemu_path(qmp_path)},server=on,wait=off",
               "-no-reboot", "-no-shutdown"]
    if sentinel is not None:
        command += ["-drive", f"if=none,id=sentinel,format=raw,file={qemu_path(sentinel)}",
                    "-device", "nvme,serial=absd,drive=sentinel"]
    (out / "COMMAND.json").write_text(json.dumps(command, indent=2) + "\n")
    qmp = None
    passed = False
    with open(out / "qemu.log", "wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env)
        try:
            start = time.monotonic()
            while not qmp_path.exists():
                require(process.poll() is None, "QEMU exited before QMP")
                require(time.monotonic() - start < 10, "QMP startup timeout")
                time.sleep(0.1)
            qmp = Qmp(qmp_path)
            if mode == "runtime":
                # The second menu entry; selection is proven by the decoded
                # output below, never inferred from key timing.
                time.sleep(5)
                qmp.call("screendump", {"filename": str(out / "before-selection.ppm")})
                qmp.call("human-monitor-command", {"command-line": "sendkey down"})
                time.sleep(0.3)
                qmp.call("human-monitor-command", {"command-line": "sendkey ret"})
            wanted = b"PHYSICAL SURVEY COMPLETE" if mode == "survey" else b"EXTERNAL WORKLOAD OK"
            while True:
                data = serial.read_bytes() if serial.exists() else b""
                require(process.poll() is None, "QEMU exited before the terminal marker")
                require(time.monotonic() - start < timeout, "guest terminal timeout")
                require(b"ABSD PANIC" not in data and b"KERNEL FAULT" not in data, "guest fault")
                if wanted in data and b"ABSD BOOT OK" in data:
                    break
                time.sleep(0.25)
            time.sleep(0.5)
            qmp.call("screendump", {"filename": str(out / "terminal.ppm")})
            status = qmp.call("query-status")
            if mode == "runtime":
                subprocess.run([sys.executable, str(checker), str(serial), str(expected)], check=True, env=env)
                require(b"BLOCK WRITES DISABLED: read-only build" in data, "check failed: b'BLOCK WRITES DISABLED: read-only build' in data")
                require(b"EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0" in data, "check failed: b'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0' in data")
                require(b"SERVED" not in data and b"NIC INITIALIZED" not in data, "check failed: b'SERVED' not in data and b'NIC INITIALIZED' not in data")
                if sentinel is not None:
                    require(b"NVME READ OK lba=0" in data and b"access=read-only" in data, "check failed: b'NVME READ OK lba=0' in data and b'access=read-only' in data")
            else:
                require(b"PERSISTENT WRITES: DISABLED" in data, "check failed: b'PERSISTENT WRITES: DISABLED' in data")
                require(b"STORAGE CONTROLLER INITIALIZATION: NOT PERFORMED" in data, "check failed: b'STORAGE CONTROLLER INITIALIZATION: NOT PERFORMED' in data")
                require(b"NETWORK INITIALIZATION: DISABLED" in data, "check failed: b'NETWORK INITIALIZATION: DISABLED' in data")
            (out / "RESULT.json").write_text(json.dumps({
                "mode": mode, "passed": True, "command": command, "serial_sha256": sha(serial),
                "firmware_code_sha256": sha(code), "firmware_vars_template_sha256": sha(vars_template),
                "qmp_status_at_terminal": status, "terminal_screen": str(out / "terminal.ppm"),
                "scope": "OVMF/TCG/q35, USB mass storage firmware boot, BSP, no NIC. No physical qualification.",
            }, indent=2) + "\n")
            passed = True
        finally:
            if process.poll() is None:
                if qmp is not None:
                    try:
                        qmp.call("quit")
                    except (OSError, ValueError, RuntimeError):
                        pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=5)
            if qmp is not None:
                qmp.close()
            (out / "PROCESS-TERMINAL.json").write_text(json.dumps({
                "pid": process.pid, "returncode": process.returncode, "guest_assertion_passed": passed,
            }, indent=2) + "\n")
            if qmp_path.exists():
                qmp_path.unlink()
