import importlib.util
import pathlib
import socket
import tempfile
import threading
import unittest

SPEC = importlib.util.spec_from_file_location(
    "mwm_check", pathlib.Path(__file__).with_name("mwm-check.py")
)
oracle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oracle)

INFO = (
    b"MWM DISPLAY INFO generation=1 high_water=0 width=1024 height=768 "
    b"pitch=4096 bpp=32 rgb=16:8,8:8,0:8\n"
)
LOG = b"".join(
    [
        INFO,
        b"MWM RECTANGLE READY\n",
        b"MWM READ ONLY REFUSED error=-1\n",
        b"MWM MALFORMED REFUSED error=-22\n",
        b"MWM ANIMATION READY\n",
        b"MWM SECOND OPEN REFUSED error=-11\n",
        b"MWM LAST CLOSE MASK\n",
        b"MWM SUCCESSOR OPEN generation=2 high_water=0\n",
        INFO.replace(b"generation=1", b"generation=2"),
        b"MWM SUCCESSOR READY\n",
        b"MWM FAULT ACTIVE\n",
        b"KERNEL FAULT vector=14 error=0x0 rip=0x1 cr2=0x2\n",
    ]
)


def partial_fault_image():
    image = bytearray(oracle.rectangle(32, 32, 0xC04040))
    image[0:3] = bytes((255, 255, 255))
    image[3:6] = bytes((160, 0, 0))
    return bytes(image)


def fault_image():
    image = bytearray(partial_fault_image())
    glyphs = oracle._ppm.font.glyphs()
    for column, byte in enumerate(b"ABSD HALT code=2"):
        bits = glyphs[byte]
        for y in range(13):
            for x in range(8):
                color = bytes((255, 255, 255)) if bits[y] & (0x80 >> x) else bytes((160, 0, 0))
                offset = ((13 + y) * oracle.WIDTH + column * 8 + x) * 3
                image[offset:offset + 3] = color
    return bytes(image)


class OracleTests(unittest.TestCase):
    def populate(self, root):
        oracle.write_phase(root, "01-rectangle.ppm", oracle.rectangle(16, 16, 0x20C080))
        oracle.write_phase(root, "02-animation.ppm", oracle.rectangle(32, 16, 0x20C080))
        oracle.write_phase(root, "03-mask.ppm", oracle.rectangle(0, 0, 0x102040, size=0))
        oracle.write_phase(root, "04-successor.ppm", oracle.rectangle(32, 32, 0xC04040))
        fault = fault_image()
        oracle.write_phase(root, "05-fault.ppm", fault)
        oracle.write_phase(root, "05-fault-held.ppm", fault)
        (pathlib.Path(root) / "serial.log").write_bytes(LOG)

    def test_positive_sequence(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            self.assertIsNone(oracle.check_sequence(root))

    def test_rejects_missing_mask(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            (pathlib.Path(root) / "03-mask.ppm").unlink()
            with self.assertRaises(oracle.OracleError):
                oracle.check_sequence(root)

    def test_rejects_reused_phase_dump(self):
        with tempfile.TemporaryDirectory() as root:
            image = oracle.rectangle(16, 16, 0x20C080)
            for name in ("01-rectangle.ppm", "02-animation.ppm", "03-mask.ppm", "04-successor.ppm"):
                oracle.write_phase(root, name, image)
            with self.assertRaises(oracle.OracleError):
                oracle.check_sequence(root)

    def test_rejects_blank_and_wrong_color(self):
        for color in (0, 0x20C081):
            with self.subTest(color=color), tempfile.TemporaryDirectory() as root:
                self.populate(root)
                oracle.write_phase(root, "01-rectangle.ppm", oracle.rectangle(16, 16, color))
                with self.assertRaises(oracle.OracleError):
                    oracle.check_sequence(root)

    def test_rejects_out_of_order_log(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            path = pathlib.Path(root) / "serial.log"
            expected = b"MWM LAST CLOSE MASK\nMWM SUCCESSOR OPEN generation=2 high_water=0\n"
            reversed_order = b"MWM SUCCESSOR OPEN generation=2 high_water=0\nMWM LAST CLOSE MASK\n"
            path.write_bytes(LOG.replace(expected, reversed_order))
            with self.assertRaises(oracle.OracleError):
                oracle.check_sequence(root)

    def test_rejects_missing_successor_authority_and_refusal_evidence(self):
        for marker in (b"MWM SUCCESSOR OPEN generation=2 high_water=0\n", b"MWM READ ONLY REFUSED error=-1\n"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as root:
                self.populate(root)
                (pathlib.Path(root) / "serial.log").write_bytes(LOG.replace(marker, b""))
                with self.assertRaises(oracle.OracleError):
                    oracle.check_sequence(root)

    def test_rejects_truncated_and_malformed_ppm(self):
        for data in (b"P6\n2 2\n255\n\x00", b"P6\n", b"not a ppm"):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as root:
                path = pathlib.Path(root) / "bad.ppm"
                path.write_bytes(data)
                with self.assertRaises(oracle.OracleError):
                    oracle.read_ppm(path)

    def test_rejects_wrong_geometry(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "image.ppm"
            oracle.write_ppm(path, oracle.rectangle(16, 16, 0x20C080))
            with self.assertRaises(oracle.OracleError):
                oracle.check_phase(path, "rectangle", (800, 600, 3200, 32), [(16, 16, 0x20C080)], 0x102040)
            path.write_bytes(b"P6\n2 2\n255\n" + bytes(12))
            with self.assertRaises(oracle.OracleError):
                oracle.check_phase(path, "rectangle", oracle.GEOMETRY, [(16, 16, 0x20C080)], 0x102040)

    def test_fault_requires_colors_marker_and_identical_held_capture(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            oracle.write_phase(root, "05-fault-held.ppm", oracle.rectangle(0, 0, 0xA00000, size=0))
            with self.assertRaises(oracle.OracleError):
                oracle.check_sequence(root)
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            oracle.write_phase(root, "05-fault.ppm", oracle.rectangle(0, 0, 0xA00000, size=0))
            oracle.write_phase(root, "05-fault-held.ppm", oracle.rectangle(0, 0, 0xA00000, size=0))
            with self.assertRaises(oracle.OracleError):
                oracle.check_sequence(root)

    def test_fault_rejects_identical_incomplete_images(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            partial = partial_fault_image()
            oracle.write_phase(root, "05-fault.ppm", partial)
            oracle.write_phase(root, "05-fault-held.ppm", partial)
            with self.assertRaises(oracle.OracleError):
                oracle.check_sequence(root)

    def test_fault_observation_retries_early_incomplete_captures(self):
        with tempfile.TemporaryDirectory() as root:
            chunks = iter(LOG.splitlines(keepends=True))
            phases = {
                "01-rectangle.ppm": oracle.rectangle(16, 16, 0x20C080),
                "02-animation.ppm": oracle.rectangle(32, 16, 0x20C080),
                "03-mask.ppm": oracle.rectangle(0, 0, 0x102040, size=0),
                "04-successor.ppm": oracle.rectangle(32, 32, 0xC04040),
            }
            partial = partial_fault_image()
            complete = fault_image()
            fault_images = iter((partial, partial, complete, complete))
            fault_captures = []

            def capture(path):
                if path.name in phases:
                    oracle.write_ppm(path, phases[path.name])
                    return
                fault_captures.append(path.name)
                oracle.write_ppm(path, next(fault_images))

            session = oracle.ObservationSession(
                root,
                lambda size: next(chunks, b""),
                lambda data: None,
                capture,
            )
            session.fault_poll_interval = 0
            try:
                session.observe_fault()
            except oracle.OracleError as error:
                self.fail(f"observation rejected recoverable early captures: {error}")
            self.assertEqual(
                fault_captures,
                ["05-fault.ppm", "05-fault-held.ppm", "05-fault.ppm", "05-fault-held.ppm"],
            )
            oracle.check_sequence(root)

    def test_fault_observation_bounds_incomplete_captures(self):
        with tempfile.TemporaryDirectory() as root:
            chunks = iter(LOG.splitlines(keepends=True))
            captures = []

            def capture(path):
                phases = {
                    "01-rectangle.ppm": oracle.rectangle(16, 16, 0x20C080),
                    "02-animation.ppm": oracle.rectangle(32, 16, 0x20C080),
                    "03-mask.ppm": oracle.rectangle(0, 0, 0x102040, size=0),
                    "04-successor.ppm": oracle.rectangle(32, 32, 0xC04040),
                }
                captures.append(path.name)
                oracle.write_ppm(path, phases.get(path.name, partial_fault_image()))

            session = oracle.ObservationSession(
                root,
                lambda size: next(chunks, b""),
                lambda data: None,
                capture,
            )
            session.fault_timeout = 0
            with self.assertRaises(oracle.OracleError):
                session.observe_fault()
            self.assertEqual(captures.count("05-fault.ppm"), 1)

    def test_observation_acknowledges_only_after_each_capture(self):
        with tempfile.TemporaryDirectory() as root:
            chunks = iter(LOG.splitlines(keepends=True))
            sent = []
            captures = []
            images = {
                "01-rectangle.ppm": oracle.rectangle(16, 16, 0x20C080),
                "02-animation.ppm": oracle.rectangle(32, 16, 0x20C080),
                "03-mask.ppm": oracle.rectangle(0, 0, 0x102040, size=0),
                "04-successor.ppm": oracle.rectangle(32, 32, 0xC04040),
                "05-fault.ppm": fault_image(),
                "05-fault-held.ppm": fault_image(),
            }

            def capture(path):
                captures.append(path.name)
                oracle.write_ppm(path, images[path.name])

            session = oracle.ObservationSession(
                root,
                lambda size: next(chunks, b""),
                sent.append,
                capture,
            )
            session.observe_fault()
            self.assertEqual(sent, [b"GO\n"] * 4)
            self.assertEqual(captures, list(images))
            oracle.check_sequence(root)

    def test_normal_observation_requires_console_restore_and_process_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            normal_log = LOG.replace(
                b"KERNEL FAULT vector=14 error=0x0 rip=0x1 cr2=0x2\n",
                b"MWM FAULT NOT ARMED REFUSED error=-22\nMWM DEMO OK processes=1\nUSERSPACE BOOTSTRAP OK\nEXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0\nEXTERNAL WORKLOAD OK\nABSD BOOT OK\n",
            )
            chunks = iter(normal_log.splitlines(keepends=True))
            sent = []
            images = {
                "01-rectangle.ppm": oracle.rectangle(16, 16, 0x20C080),
                "02-animation.ppm": oracle.rectangle(32, 16, 0x20C080),
                "03-mask.ppm": oracle.rectangle(0, 0, 0x102040, size=0),
                "04-successor.ppm": oracle.rectangle(32, 32, 0xC04040),
            }
            session = oracle.ObservationSession(
                root,
                lambda size: next(chunks, b""),
                sent.append,
                lambda path: oracle.write_ppm(path, images[path.name]),
            )
            session.observe_normal()
            self.assertEqual(sent, [b"GO\n"] * 4)
            oracle.check_normal_sequence(root)

    def test_normal_validation_requires_kernel_terminal_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            for name, rectangles in oracle.PHASES:
                image = (
                    oracle.rectangle(*rectangles[0])
                    if rectangles
                    else oracle.rectangle(0, 0, 0x102040, size=0)
                )
                oracle.write_phase(root, name, image)
            (pathlib.Path(root) / "serial.log").write_bytes(LOG.replace(
                b"KERNEL FAULT vector=14 error=0x0 rip=0x1 cr2=0x2\n",
                b"MWM FAULT NOT ARMED REFUSED error=-22\nMWM DEMO OK processes=1\n",
            ))
            with self.assertRaises(oracle.OracleError):
                oracle.check_normal_sequence(root)

    def test_normal_validation_rejects_later_kernel_fault(self):
        with tempfile.TemporaryDirectory() as root:
            for name, rectangles in oracle.PHASES:
                image = (
                    oracle.rectangle(*rectangles[0])
                    if rectangles
                    else oracle.rectangle(0, 0, 0x102040, size=0)
                )
                oracle.write_phase(root, name, image)
            log = LOG.replace(
                b"KERNEL FAULT vector=14 error=0x0 rip=0x1 cr2=0x2\n",
                b"MWM FAULT NOT ARMED REFUSED error=-22\nMWM DEMO OK processes=1\nUSERSPACE BOOTSTRAP OK\nEXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0\nEXTERNAL WORKLOAD OK\nABSD BOOT OK\n",
            )
            (pathlib.Path(root) / "serial.log").write_bytes(log + b"KERNEL FAULT vector=14 error=0x0\n")
            with self.assertRaises(oracle.OracleError):
                oracle.check_normal_sequence(root)

    def test_real_unix_socket_and_hmp_adapter(self):
        with tempfile.TemporaryDirectory() as root_name:
            root = pathlib.Path(root_name)
            normal_log = LOG.replace(
                b"KERNEL FAULT vector=14 error=0x0 rip=0x1 cr2=0x2\n",
                b"MWM FAULT NOT ARMED REFUSED error=-22\nMWM DEMO OK processes=1\nUSERSPACE BOOTSTRAP OK\nEXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0\nEXTERNAL WORKLOAD OK\nABSD BOOT OK\n",
            )
            images = {
                "01-rectangle.ppm": oracle.rectangle(16, 16, 0x20C080),
                "02-animation.ppm": oracle.rectangle(32, 16, 0x20C080),
                "03-mask.ppm": oracle.rectangle(0, 0, 0x102040, size=0),
                "04-successor.ppm": oracle.rectangle(32, 32, 0xC04040),
            }

            def listener(name):
                server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                server.settimeout(5)
                server.bind(str(root / name))
                server.listen(1)
                return server

            serial_server = listener("serial.sock")
            monitor_server = listener("monitor.sock")
            acknowledgements = []
            errors = []

            def serial_endpoint():
                try:
                    connection, _ = serial_server.accept()
                    with connection:
                        connection.sendall(normal_log)
                        for _ in range(4):
                            data = bytearray()
                            while len(data) < 3:
                                chunk = connection.recv(3 - len(data))
                                if not chunk:
                                    raise AssertionError("early serial EOF")
                                data.extend(chunk)
                            acknowledgements.append(bytes(data))
                except BaseException as error:
                    errors.append(error)

            def monitor_endpoint():
                try:
                    connection, _ = monitor_server.accept()
                    with connection:
                        commands = connection.makefile("rwb", buffering=0)
                        commands.write(b"QEMU 8.2.2 monitor - type 'help' for more information\n(qemu) ")
                        for name, image in images.items():
                            capture = root / (name + ".capture")
                            expected = f"screendump {capture}\n".encode()
                            self.assertEqual(commands.readline(), expected)
                            oracle.write_ppm(capture, image)
                            commands.write(b"(qemu) ")
                except BaseException as error:
                    errors.append(error)

            threads = [
                threading.Thread(target=serial_endpoint, daemon=True),
                threading.Thread(target=monitor_endpoint, daemon=True),
            ]
            for thread in threads:
                thread.start()
            try:
                with oracle.socket_session(root, root / "serial.sock", root / "monitor.sock") as session:
                    session.observe_normal()
            finally:
                for thread in threads:
                    thread.join(5)
                serial_server.close()
                monitor_server.close()
            self.assertFalse(errors, errors)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(acknowledgements, [b"GO\n"] * 4)
            oracle.check_normal_sequence(root)

    def test_hmp_error_cannot_reuse_existing_capture(self):
        with tempfile.TemporaryDirectory() as root_name:
            root = pathlib.Path(root_name)
            target = root / "05-fault.ppm"
            target.write_bytes(b"previous capture")

            def listener(name):
                server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                server.settimeout(5)
                server.bind(str(root / name))
                server.listen(1)
                return server

            serial_server = listener("serial.sock")
            monitor_server = listener("monitor.sock")
            errors = []
            received = []

            def serial_endpoint():
                try:
                    connection, _ = serial_server.accept()
                    connection.close()
                except BaseException as error:
                    errors.append(error)

            def monitor_endpoint():
                try:
                    connection, _ = monitor_server.accept()
                    with connection:
                        commands = connection.makefile("rwb", buffering=0)
                        commands.write(b"QEMU 8.2.2 monitor - type 'help' for more information\n(qemu) ")
                        received.append(commands.readline())
                        commands.write(b"Error: injected screendump failure\n(qemu) ")
                except BaseException as error:
                    errors.append(error)

            threads = [
                threading.Thread(target=serial_endpoint, daemon=True),
                threading.Thread(target=monitor_endpoint, daemon=True),
            ]
            for thread in threads:
                thread.start()
            try:
                with oracle.socket_session(root, root / "serial.sock", root / "monitor.sock") as session:
                    with self.assertRaises(oracle.OracleError):
                        session.capture(target)
            finally:
                for thread in threads:
                    thread.join(5)
                serial_server.close()
                monitor_server.close()
            self.assertFalse(errors, errors)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(target.read_bytes(), b"previous capture")
            self.assertFalse((root / "05-fault.ppm.capture").exists())
            self.assertEqual(
                received,
                [f"screendump {root / '05-fault.ppm.capture'}\n".encode()],
            )

    def test_observation_does_not_acknowledge_bad_capture(self):
        with tempfile.TemporaryDirectory() as root:
            sent = []
            chunks = iter(LOG.splitlines(keepends=True))
            session = oracle.ObservationSession(
                root,
                lambda size: next(chunks, b""),
                sent.append,
                lambda path: oracle.write_ppm(path, bytes(1024 * 768 * 3)),
            )
            with self.assertRaises(oracle.OracleError):
                session.observe_fault()
            self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()
