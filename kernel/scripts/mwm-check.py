#!/usr/bin/env python3
"""Independent copied-frame pixel oracle and admitted-socket phase driver.

This module has no QEMU launch path. An execution envelope owns process
creation and admission; socket_session only connects to its existing sockets.
"""
import argparse
import importlib.util
import pathlib
import socket
import sys
import time

sys.dont_write_bytecode = True

_spec = importlib.util.spec_from_file_location(
    "mwm_framebuffer_ppm", pathlib.Path(__file__).with_name("framebuffer-check.py")
)
_ppm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ppm)

WIDTH = 1024
HEIGHT = 768
GEOMETRY = (WIDTH, HEIGHT, 4096, 32)
BACKGROUND = 0x102040
FAULT_FOREGROUND = bytes((255, 255, 255))
FAULT_BACKGROUND = bytes((160, 0, 0))
INFO_1 = (
    b"MWM DISPLAY INFO generation=1 high_water=0 width=1024 height=768 "
    b"pitch=4096 bpp=32 rgb=16:8,8:8,0:8\n"
)
INFO_2 = INFO_1.replace(b"generation=1", b"generation=2")
PHASES = (
    ("01-rectangle.ppm", [(16, 16, 0x20C080)]),
    ("02-animation.ppm", [(32, 16, 0x20C080)]),
    ("03-mask.ppm", []),
    ("04-successor.ppm", [(32, 32, 0xC04040)]),
)
MARKERS = (
    INFO_1,
    b"MWM RECTANGLE READY\n",
    b"MWM READ ONLY REFUSED error=-1\n",
    b"MWM MALFORMED REFUSED error=-22\n",
    b"MWM ANIMATION READY\n",
    b"MWM SECOND OPEN REFUSED error=-11\n",
    b"MWM LAST CLOSE MASK\n",
    b"MWM SUCCESSOR OPEN generation=2 high_water=0\n",
    INFO_2,
    b"MWM SUCCESSOR READY\n",
    b"MWM FAULT ACTIVE\n",
    b"KERNEL FAULT vector=14 ",
)
NORMAL_MARKERS = MARKERS[:-2] + (
    b"MWM FAULT ACTIVE\n",
    b"MWM FAULT NOT ARMED REFUSED error=-22\n",
    b"MWM DEMO OK processes=1\n",
    b"USERSPACE BOOTSTRAP OK\n",
    b"EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0\n",
    b"EXTERNAL WORKLOAD OK\n",
    b"ABSD BOOT OK\n",
)


class OracleError(Exception):
    pass


def read_ppm(path):
    try:
        return _ppm.read_ppm(path)
    except (ValueError, IndexError, OSError, OverflowError) as error:
        raise OracleError(f"malformed PPM {path}: {error}") from error


def rgb(value):
    if not 0 <= value <= 0xFFFFFF:
        raise OracleError(f"invalid RGB value {value}")
    return bytes(((value >> 16) & 255, (value >> 8) & 255, value & 255))


def rectangle(x, y, color, size=64, background=BACKGROUND):
    if size < 0 or x < 0 or y < 0 or x + size > WIDTH or y + size > HEIGHT:
        raise OracleError("rectangle outside the pinned display")
    image = bytearray(rgb(background) * (WIDTH * HEIGHT))
    if size:
        for row in range(y, y + size):
            start = (row * WIDTH + x) * 3
            image[start:start + size * 3] = rgb(color) * size
    return bytes(image)


def write_ppm(path, image):
    path = pathlib.Path(path)
    if len(image) != WIDTH * HEIGHT * 3:
        raise OracleError("wrong fixture byte count")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(f"P6\n{WIDTH} {HEIGHT}\n255\n".encode() + image)


def write_phase(root, name, image):
    write_ppm(pathlib.Path(root) / name, image)


def _image(path):
    width, height, pixels = read_ppm(path)
    if (width, height, 4096, 32) != GEOMETRY or len(pixels) != WIDTH * HEIGHT * 3:
        raise OracleError(f"wrong geometry in {path}")
    return pixels


def check_phase(path, phase, expected_geometry, expected_rectangles, background):
    if expected_geometry != GEOMETRY:
        raise OracleError(f"unsupported expected geometry for {phase}")
    actual = _image(path)
    expected = bytearray(rgb(background) * (WIDTH * HEIGHT))
    for x, y, color in expected_rectangles:
        painted = rectangle(x, y, color, background=background)
        for row in range(64):
            start = ((y + row) * WIDTH + x) * 3
            expected[start:start + 64 * 3] = painted[start:start + 64 * 3]
    if actual != expected:
        mismatch = next(
            (index for index, pair in enumerate(zip(actual, expected)) if pair[0] != pair[1]),
            None,
        )
        raise OracleError(f"wrong or reused pixels for {phase} at byte {mismatch}")


def _ordered_log(root, markers=MARKERS, normal=False):
    path = pathlib.Path(root) / "serial.log"
    try:
        data = path.read_bytes()
    except OSError as error:
        raise OracleError(f"missing serial log: {error}") from error
    if b"MWM FAILED" in data or b"ABSD PANIC:" in data or (normal and b"KERNEL FAULT" in data):
        raise OracleError("failure marker in serial evidence")
    position = 0
    for marker in markers:
        found = data.find(marker, position)
        if found < 0:
            raise OracleError(f"missing or out-of-order marker {marker!r}")
        position = found + len(marker)
    return data


def _completed_halt_visible(pixels):
    glyphs = _ppm.font.glyphs()
    for column, byte in enumerate(b"ABSD HALT code=2"):
        bits = glyphs[byte]
        for y in range(13):
            base = ((13 + y) * WIDTH + column * 8) * 3
            expected = b"".join(
                FAULT_FOREGROUND if bits[y] & (0x80 >> x) else FAULT_BACKGROUND
                for x in range(8)
            )
            if pixels[base:base + 24] != expected:
                return False
    return True


def _check_fault(root):
    first = _image(pathlib.Path(root) / "05-fault.ppm")
    held = _image(pathlib.Path(root) / "05-fault-held.ppm")
    if first != held:
        raise OracleError("fault image was not held")
    if FAULT_FOREGROUND not in first or FAULT_BACKGROUND not in first:
        raise OracleError("failure colors missing from held fault image")
    if not _completed_halt_visible(first):
        raise OracleError("completed fault halt notice missing")


def check_sequence(root):
    root = pathlib.Path(root)
    expected_files = {name for name, _ in PHASES} | {"05-fault.ppm", "05-fault-held.ppm", "serial.log"}
    try:
        files = {path.name for path in root.iterdir() if path.is_file() and path.suffix in (".ppm", ".log")}
    except OSError as error:
        raise OracleError(f"unreadable evidence root: {error}") from error
    if files != expected_files:
        raise OracleError(f"missing or unexpected phase evidence: {sorted(files ^ expected_files)}")
    _ordered_log(root)
    seen = set()
    for name, rectangles in PHASES:
        path = root / name
        check_phase(path, name, GEOMETRY, rectangles, BACKGROUND)
        digest = path.read_bytes()
        if digest in seen:
            raise OracleError(f"reused phase dump {name}")
        seen.add(digest)
    _check_fault(root)


def check_normal_sequence(root):
    root = pathlib.Path(root)
    expected_files = {name for name, _ in PHASES} | {"serial.log"}
    files = {path.name for path in root.iterdir() if path.is_file() and path.suffix in (".ppm", ".log")}
    if files != expected_files:
        raise OracleError(f"missing or unexpected normal-phase evidence: {sorted(files ^ expected_files)}")
    _ordered_log(root, NORMAL_MARKERS, normal=True)
    for name, rectangles in PHASES:
        check_phase(root / name, name, GEOMETRY, rectangles, BACKGROUND)


class ObservationSession:
    def __init__(self, root, receive, send, capture):
        self.root = pathlib.Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.receive = receive
        self.send = send
        self.capture = capture
        self.log = bytearray()
        self.fault_timeout = 10.0
        self.fault_poll_interval = 0.2

    def _wait(self, marker):
        while marker not in self.log:
            try:
                chunk = self.receive(256)
            except (OSError, TimeoutError) as error:
                raise OracleError(f"serial receive failed: {error}") from error
            if not chunk:
                raise OracleError(f"serial ended before {marker!r}")
            self.log.extend(chunk)

    def _save(self, name, rectangles, fault=False):
        (self.root / "serial.log").write_bytes(self.log)
        path = self.root / name
        try:
            self.capture(path)
        except OracleError:
            raise
        except (OSError, TimeoutError) as error:
            raise OracleError(f"capture failed for {name}: {error}") from error
        if fault:
            _image(path)
        else:
            check_phase(path, name, GEOMETRY, rectangles, BACKGROUND)

    def _acknowledge(self):
        try:
            self.send(b"GO\n")
        except (OSError, TimeoutError) as error:
            raise OracleError(f"acknowledgement failed: {error}") from error

    def _phase(self, marker, name, rectangles):
        self._wait(marker)
        self._save(name, rectangles)
        self._acknowledge()

    def _observe_frames(self):
        self._wait(INFO_1)
        self._phase(b"MWM RECTANGLE READY\n", "01-rectangle.ppm", [(16, 16, 0x20C080)])
        self._wait(b"MWM READ ONLY REFUSED error=-1\n")
        self._wait(b"MWM MALFORMED REFUSED error=-22\n")
        self._phase(b"MWM ANIMATION READY\n", "02-animation.ppm", [(32, 16, 0x20C080)])
        self._wait(b"MWM SECOND OPEN REFUSED error=-11\n")
        self._phase(b"MWM LAST CLOSE MASK\n", "03-mask.ppm", [])
        self._wait(b"MWM SUCCESSOR OPEN generation=2 high_water=0\n")
        self._wait(INFO_2)
        self._phase(b"MWM SUCCESSOR READY\n", "04-successor.ppm", [(32, 32, 0xC04040)])

    def observe_normal(self):
        self._observe_frames()
        self._wait(b"MWM FAULT ACTIVE\n")
        self._wait(b"MWM FAULT NOT ARMED REFUSED error=-22\n")
        self._wait(b"MWM DEMO OK processes=1\n")
        self._wait(b"USERSPACE BOOTSTRAP OK\n")
        self._wait(b"EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0\n")
        self._wait(b"EXTERNAL WORKLOAD OK\n")
        self._wait(b"ABSD BOOT OK\n")
        (self.root / "serial.log").write_bytes(self.log)
        check_normal_sequence(self.root)

    def observe_fault(self):
        self._observe_frames()
        self._wait(b"MWM FAULT ACTIVE\n")
        self._wait(b"KERNEL FAULT vector=14 ")
        deadline = time.monotonic() + self.fault_timeout
        while True:
            self._save("05-fault.ppm", [], fault=True)
            self._save("05-fault-held.ppm", [], fault=True)
            try:
                _check_fault(self.root)
            except OracleError:
                if time.monotonic() >= deadline:
                    raise
            else:
                check_sequence(self.root)
                return
            time.sleep(self.fault_poll_interval)


def _unix_connection(path):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(10)
    try:
        connection.connect(str(path))
    except Exception:
        connection.close()
        raise
    return connection


def _monitor_response(commands):
    response = bytearray()
    while not response.endswith(b"(qemu) "):
        chunk = commands.read(1)
        if not chunk:
            raise OracleError("monitor ended before its prompt")
        response.extend(chunk)
        if len(response) > 65536:
            raise OracleError("unbounded monitor response")
    return bytes(response)


class SocketObservationSession(ObservationSession):
    def __init__(self, root, serial_path, monitor_path):
        self.serial = _unix_connection(serial_path)
        self.monitor = _unix_connection(monitor_path)
        self.commands = self.monitor.makefile("rwb", buffering=0)
        _monitor_response(self.commands)

        def capture(path):
            path = pathlib.Path(path)
            temporary = path.with_name(path.name + ".capture")
            temporary.unlink(missing_ok=True)
            try:
                self.commands.write(f"screendump {temporary}\n".encode())
                response = _monitor_response(self.commands)
                if any(line.startswith(b"Error:") for line in response.splitlines()):
                    raise OracleError(f"screendump failed: {response!r}")
                if not temporary.is_file():
                    raise OracleError("screendump did not create a file")
                temporary.replace(path)
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise

        super().__init__(root, self.serial.recv, self.serial.sendall, capture)

    def close(self):
        self.commands.close()
        self.monitor.close()
        self.serial.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def socket_session(root, serial_path, monitor_path):
    return SocketObservationSession(root, pathlib.Path(serial_path), pathlib.Path(monitor_path))


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", type=pathlib.Path, help="check a fault evidence root")
    modes.add_argument("--check-normal", type=pathlib.Path, help="check a normal-demo evidence root")
    args = parser.parse_args()
    try:
        if args.check_normal is not None:
            check_normal_sequence(args.check_normal)
        else:
            check_sequence(args.check)
    except OracleError as error:
        parser.exit(1, f"MWM CHECK FAILED: {error}\n")
    print("MWM CHECK OK: independent pixels, phase order, and terminal evidence")


if __name__ == "__main__":
    main()
