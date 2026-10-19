"""Exercise actual userland census and PTY admission without a guest."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here))
spec = importlib.util.spec_from_file_location("userland_matrix", here / "userland-matrix.py")
um = importlib.util.module_from_spec(spec)
spec.loader.exec_module(um)


class Tests(unittest.TestCase):
    def fixture(self, counts):
        matrix = um.UserlandMatrix.__new__(um.UserlandMatrix)
        matrix.connections = 7
        events = []

        def output():
            count = next(counts)
            events.append(("reclaimed", count))
            return (f'SERVED CAPACITY boot={"a" * 32} accepted_reclaimed={count} '
                    'slots=0 pool=0 processes=3 handles=57 pipes=24 cells=1 '
                    'frames=619 heap_pages_peak=222\n')

        matrix.t = types.SimpleNamespace(output=output, all_images=lambda: 0,
                                         system_objects=lambda: [], census_detail=lambda: "fixture")

        def sysinfo():
            events.append(("sysinfo",))
            return "memory: fixture", "kernel: 4 process slots, 66 handles, 27 pipes, 1 cells"

        matrix.sysinfo = sysinfo
        matrix.fsd_capacity = lambda: (1, 0, 20)
        matrix.fsd_peak = lambda: 20
        return matrix, events

    def test_census_waits_for_all_prior_connections(self):
        matrix, events = self.fixture(iter([6, 7]))
        with patch.object(um.cm.ck.time, "sleep"):
            census = matrix.census()
        self.assertEqual(events, [("reclaimed", 6), ("reclaimed", 7), ("sysinfo",)])
        self.assertEqual(census["quiescent"]["accepted_reclaimed"], 7)
        self.assertEqual(census["fsd"], 20)

    def test_missing_reclamation_refuses_before_sysinfo(self):
        matrix, events = self.fixture(iter([6, 6]))
        with patch.object(um.cm.ck.time, "monotonic", side_effect=[0, 0, 61]), \
                patch.object(um.cm.ck.time, "sleep"):
            with self.assertRaisesRegex(um.cm.ck.sm.Failed, "no quiescent"):
                matrix.census()
        self.assertNotIn(("sysinfo",), events)

    def test_old_disabled_gate_fails_ordering_control(self):
        matrix, events = self.fixture(iter([6, 7]))
        with patch.object(um.UserlandMatrix, "QUIESCENT_READINGS", False):
            census = matrix.census()
        self.assertEqual(events, [("sysinfo",)])
        self.assertNotIn("quiescent", census)

    def test_interrupt_counts_pty_before_open(self):
        matrix = um.UserlandMatrix.__new__(um.UserlandMatrix)
        matrix.connections = 7
        matrix.stable = lambda *args: {}
        matrix.fresh_dir = lambda case: None
        events = []

        class StopFixture(Exception):
            pass

        def open_shell(actual):
            events.append(actual.connections)
            raise StopFixture()

        matrix.t = types.SimpleNamespace(all_images=lambda: 0, open_shell=open_shell)
        with self.assertRaises(StopFixture):
            matrix.interrupts()
        self.assertEqual(events, [8])
        self.assertEqual(matrix.connections, 8)


if __name__ == "__main__":
    unittest.main()
