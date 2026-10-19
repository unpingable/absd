#!/usr/bin/env python3
"""Exercise real Unix socket binding with a campaign-length work path."""
import importlib.util
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / "net-matrix.py"
spec = importlib.util.spec_from_file_location("net_matrix", source)
net = importlib.util.module_from_spec(spec)
spec.loader.exec_module(net)


class SocketPaths(unittest.TestCase):
    def test_deep_work_directory_and_launch_failure_cleanup(self):
        for link_down in (False, True):
            with self.subTest(link_down=link_down), tempfile.TemporaryDirectory() as root:
                work = Path(root) / ("campaign-" + "x" * 140)
                work.mkdir()
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as control:
                    with self.assertRaisesRegex(OSError, "AF_UNIX path too long"):
                        control.bind(str(work / "host.sock"))
                seen = []
                sockets = []
                real_socket = socket.socket

                def opened(*args, **kwargs):
                    sock = real_socket(*args, **kwargs)
                    sockets.append(sock)
                    return sock

                def launch(iso, image, log, args, stopped_with_qmp=None):
                    self.assertEqual(Path(log).parent, work)
                    self.assertIn(str(work / ("linkdown.pcap" if link_down else "frames.pcap")), args[-1])
                    paths = dict(piece.split("=", 1) for piece in args[1].split(",") if "=" in piece)
                    host = paths["remote.path"]
                    guest = paths["local.path"]
                    self.assertTrue(os.path.exists(host))
                    self.assertLessEqual(len(os.fsencode(host)), 107)
                    self.assertEqual(Path(host).parent, Path(guest).parent)
                    if link_down:
                        self.assertEqual(Path(stopped_with_qmp).parent, Path(host).parent)
                    else:
                        self.assertIsNone(stopped_with_qmp)
                    seen.append(Path(host).parent)
                    raise RuntimeError("injected launch failure")

                with patch.object(net, "build_iso", return_value=("iso", "image")), \
                     patch.object(net.socket, "socket", side_effect=opened), \
                     patch.object(net, "start_qemu", side_effect=launch):
                    with self.assertRaisesRegex(RuntimeError, "injected launch failure"):
                        net.run_frames("kernel", "elf", str(work), link_down)
                self.assertEqual(len(seen), 1)
                self.assertFalse(seen[0].exists())
                self.assertTrue(all(sock.fileno() == -1 for sock in sockets))


if __name__ == "__main__":
    unittest.main()
