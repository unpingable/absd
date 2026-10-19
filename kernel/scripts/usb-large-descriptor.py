"""Local USB2 descriptor fixture for QEMU usb-redir, never a physical device.

Implements only the documented usbredir 0.7 packets needed for EP0 descriptor
reads. Only xHCI-required capabilities, no network listener or USB forwarding.
Wire definitions: https://github.com/SPICEorg/usbredir/blob/master/usb-redirection-protocol.txt
This is an independent implementation of that protocol, not imported source.
"""
import json
from pathlib import Path
import socket
import struct
import threading


class LargeDescriptor:
    def __init__(self, path, receipt, keyboard=False, descriptor_fault=None):
        self.receipt = Path(receipt)
        self.records = []
        self.error = None
        self.stopping = False
        self.connected = threading.Event()
        self.peer = None
        self.wide = False
        self.keyboard = keyboard
        self.descriptor_fault = descriptor_fault
        self.receiving = threading.Event()
        self.send_lock = threading.Lock()
        self.sequence = 0
        self.configuration = 0
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(path))
        self.listener.listen(1)
        self.listener.settimeout(.2)
        self.config = bytes([9, 2, 10, 4, 1, 1, 0, 0x80, 0,
                             9, 4, 0, 0, 0, 0xff, 0, 0, 0])
        self.config += bytes([254, 0xff] + [0] * 252) * 4
        assert len(self.config) == 1034
        if keyboard:
            self.config = bytes([9, 2, 34, 0, 1, 1, 0, 0x80, 0,
                                 9, 4, 0, 0, 1, 3, 1, 1, 0,
                                 9, 0x21, 0x11, 1, 0, 1, 0x22, 63, 0,
                                 7, 5, 0x81, 3, 8, 0, 10])
        self.device = bytes([18, 1, 0, 2, 0, 0, 0, 64,
                             0xfe, 0xca, 1, 0, 0, 1, 0, 0, 0, 1])
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def packet(self, kind, body=b"", identity=0):
        with self.send_lock:
            self.peer.sendall(struct.pack("<IIQ" if self.wide else "<III", kind, len(body), identity) + body)

    def announce(self):
        types = bytearray([255] * 32)
        types[0] = types[16] = 0
        intervals = bytearray(32)
        packets = [0] * 32
        packets[0] = packets[16] = 64
        if self.keyboard:
            types[17] = 3
            intervals[17] = 10
            packets[17] = 8
        self.packet(5, types + intervals + bytes(32) + struct.pack("<32H", *packets))
        self.packet(4, struct.pack("<I", 1) + bytes(32)
                    + bytes([3 if self.keyboard else 255]) + bytes(31)
                    + bytes([1 if self.keyboard else 0]) + bytes(31)
                    + bytes([1 if self.keyboard else 0]) + bytes(31))

    def input(self, data, status=0):
        if not self.keyboard or not self.receiving.wait(timeout=5):
            raise RuntimeError("keyboard fixture is not receiving")
        self.packet(103, struct.pack("<BBH", 0x81, status, len(data)) + data, self.sequence)
        self.sequence += 1
        self.records.append({"interrupt_bytes": len(data), "status": status})

    def read(self, length):
        data = bytearray()
        while len(data) < length:
            part = self.peer.recv(length - len(data))
            if not part:
                raise EOFError("QEMU closed descriptor fixture")
            data.extend(part)
        return bytes(data)

    def serve(self):
        try:
            while not self.stopping:
                try:
                    self.peer, _ = self.listener.accept()
                    break
                except TimeoutError:
                    continue
            if self.peer is None:
                return
            self.packet(0, b"ABSD local large configuration".ljust(64, b"\0") + struct.pack("<I", 0x70))
            hello = True
            while not self.stopping:
                kind, length, identity = struct.unpack("<IIQ" if self.wide else "<III", self.read(16 if self.wide else 12))
                if length > 4096:
                    raise RuntimeError("fixture packet exceeds bound")
                body = self.read(length)
                if hello:
                    if kind != 0 or len(body) < 68 or struct.unpack_from("<I", body, 64)[0] & 0x70 != 0x70:
                        raise RuntimeError("missing usbredir hello")
                    hello = False
                    self.wide = True
                    # EP0 OUT/IN, all other endpoints absent. xHCI requires
                    # packet sizes, 64-bit IDs and 32-bit bulk lengths.
                    self.announce()
                    self.packet(1, struct.pack("<BBBBHH", 1, 0, 0, 0, 0xcafe, 1))
                    self.connected.set()
                elif kind == 3:  # USB device reset, no response packet.
                    self.records.append({"reset": True})
                    self.configuration = 0
                elif self.keyboard and kind in {6, 7}:
                    if kind == 6:
                        self.configuration = body[0]
                        self.announce()
                    self.packet(8, bytes([0, self.configuration]), identity)
                elif self.keyboard and kind in {15, 16}:
                    self.packet(17, bytes([0, body[0]]), identity)
                    if kind == 15:
                        self.receiving.set()
                    else:
                        self.receiving.clear()
                elif kind == 100:
                    if len(body) != 10:
                        raise RuntimeError("unexpected control packet length")
                    ep, request, requesttype, _, value, index, requested = struct.unpack("<BBBBHHH", body)
                    if request == 6 and requesttype == 0x80 and index == 0 and value in {0x100, 0x200}:
                        data = (self.device if value == 0x100 else self.config)[:requested]
                        if value == 0x100 and self.descriptor_fault == 'prefix':
                            data = data[:7] + b'\0' + data[8:]
                        if value == 0x100 and self.descriptor_fault == 'device' and requested == 18:
                            data = b'\x11' + data[1:]
                    elif self.keyboard and requesttype == 0x21 and request in {0x0a, 0x0b} and value == index == requested == 0:
                        data = b""
                    elif self.keyboard and requesttype == 0xa1 and request == 3 and value == index == 0 and requested == 1:
                        data = b"\0"
                    else:
                        raise RuntimeError("unexpected fixture control request")
                    self.records.append({"descriptor": value >> 8, "requested": requested,
                                         "returned": len(data), "config_total": len(self.config)})
                    self.packet(100, struct.pack("<BBBBHHH", ep, request, requesttype, 0,
                                                value, index, len(data)) + data, identity)
                else:
                    raise RuntimeError(f"unexpected fixture packet {kind}")
        except EOFError:
            pass  # QEMU may exit normally before the fixture is closed.
        except OSError as error:
            if not self.stopping:
                self.error = str(error)
        except Exception as error:
            self.error = repr(error)
        finally:
            self.receipt.write_text(json.dumps({"configuration_bytes": len(self.config),
                                               "records": self.records, "error": self.error}, indent=2) + "\n")

    def close(self):
        self.stopping = True
        if self.peer:
            try:
                self.peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.peer.close()
        self.listener.close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("descriptor fixture did not end")
