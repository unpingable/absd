"""Exercise Cports census admission and restart accounting without a guest."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here))
spec = importlib.util.spec_from_file_location("cports_matrix", here / "cports-matrix.py")
cm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cm)


class Tests(unittest.TestCase):
    def fixture(self, counts, images=0):
        matrix = cm.CportsMatrix.__new__(cm.CportsMatrix)
        matrix.connections = 7
        events = []

        def output():
            count = next(counts)
            events.append(("reclaimed", count))
            return (f'SERVED CAPACITY boot={"a" * 32} accepted_reclaimed={count} '
                    'slots=0 pool=0 processes=3 handles=57 pipes=24 cells=1 '
                    'frames=619 heap_pages_peak=222\n')

        matrix.t = types.SimpleNamespace(output=output, all_images=lambda: images,
                                         system_objects=lambda: [], census_detail=lambda: "fixture")
        def sysinfo():
            events.append(("sysinfo",))
            return "memory: fixture", "kernel: 4 process slots, 66 handles, 27 pipes, 1 cells"
        matrix.sysinfo = sysinfo
        matrix.fsd_capacity = lambda: (1, 0, 20)
        matrix.fsd_peak = lambda: 20
        return matrix, events

    def test_exact_reclamation_precedes_measurement(self):
        matrix, events = self.fixture(iter([6, 7, 7]))
        with patch.object(cm.ck.time, "sleep"):
            census = matrix.census()
            matrix.census()
        self.assertEqual(events, [("reclaimed", 6), ("reclaimed", 7), ("sysinfo",),
                                  ("reclaimed", 7), ("sysinfo",)])
        self.assertEqual(census["quiescent"]["accepted_reclaimed"], 7)
        self.assertEqual(matrix.connections, 7)  # Same-boot debt is never rebased.

    def test_missing_excess_or_live_session_refuses_before_measurement(self):
        for count, images in [(6, 0), (8, 0), (7, 1)]:
            with self.subTest(count=count, images=images):
                matrix, events = self.fixture(iter([count, count]), images)
                with patch.object(cm.ck.time, "monotonic", side_effect=[0, 0, 61]), \
                        patch.object(cm.ck.time, "sleep"):
                    with self.assertRaisesRegex(cm.ck.sm.Failed, "no quiescent"):
                        matrix.census()
                self.assertNotIn(("sysinfo",), events)

    def test_disabled_gate_exposes_ordering_failure(self):
        matrix, events = self.fixture(iter([6, 7]))
        with patch.object(cm.CportsMatrix, "QUIESCENT_READINGS", False):
            census = matrix.census()
        self.assertEqual(events, [("sysinfo",)])
        self.assertNotIn("quiescent", census)

    def test_restart_resets_debt_before_first_new_boot_census(self):
        matrix = cm.CportsMatrix.__new__(cm.CportsMatrix)
        matrix.connections = 73
        matrix.restart_round = 1
        matrix.work = Path("/tmp/not-created-cports-quiescence")
        matrix.host_key = "fixture-key"
        events = []
        def start(**kwargs):
            events.append(("start", matrix.connections))
            return {"generated": False, "public": matrix.host_key}
        matrix.t = types.SimpleNamespace(stop=lambda: events.append(("stop",)),
                                         start=start, image="fixture-image", log=Path("old.log"))
        process = types.SimpleNamespace(kill=lambda: None, wait=lambda: None)
        matrix.close_pipes = lambda p: None
        matrix.check = lambda label, okay, *args: self.assertTrue(okay, label)
        class AtCensus(Exception):
            pass
        def rest(label):
            events.append(("census", matrix.connections))
            raise AtCensus()
        matrix.take_rest = rest
        with patch.object(cm.shutil, "copy"), patch.object(Path, "stat", return_value=types.SimpleNamespace(st_size=512)):
            with self.assertRaises(AtCensus):
                matrix.cut(types.SimpleNamespace(name="sqlite.excl-crash"), process, "fixture")
        self.assertEqual(events, [("stop",), ("start", 73), ("census", 0)])


if __name__ == "__main__":
    unittest.main()
