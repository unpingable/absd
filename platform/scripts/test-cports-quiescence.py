"""Exercise Cports census admission and restart accounting without a guest."""
import importlib.util
from pathlib import Path
import sys
import tempfile
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

    def test_fenced_cut_never_restarts(self):
        # Under the owner's storage fence (coordination record #63 (b)) the cut's
        # image is refused, never reopened writable: no start, no census.
        with tempfile.TemporaryDirectory() as directory:
            matrix = cm.CportsMatrix.__new__(cm.CportsMatrix)
            matrix.connections = 73
            matrix.restart_round = 1
            matrix.work = Path(directory)
            image = Path(directory) / "ssh.img"
            image.write_bytes(b"fixture image")
            events = []
            def start(**kwargs):
                raise AssertionError("cut() reopened the fenced image writable")
            matrix.t = types.SimpleNamespace(stop=lambda: events.append(("stop",)), start=start, image=image,
                                             log=Path("old.log"), tree=lambda: {"/x": b"1"})
            process = types.SimpleNamespace(kill=lambda: None, wait=lambda: None)
            matrix.close_pipes = lambda p: None
            matrix.check = lambda label, okay, *args: self.assertTrue(okay, label)
            matrix.take_rest = lambda label: self.fail("census on a fenced image")
            refusal = {"status": "7", "refusal": "RECOVERY WRITABLE REFUSED", "log": "refused.serial.log"}
            with patch.object(cm.fence_guest, "refused_cold_boot", return_value=refusal) as refused:
                matrix.cut(types.SimpleNamespace(name="sqlite.excl-crash"), process, "fixture")
            refused.assert_called_once_with(matrix.t, "ata", "fixture-refused", served=False)
        self.assertEqual(events, [("stop",)])
        self.assertEqual((matrix.fenced, matrix.connections), ("sqlite.excl-crash", 73))

    def test_fresh_image_resets_debt_before_first_new_boot_census(self):
        with tempfile.TemporaryDirectory() as directory:
            matrix = cm.CportsMatrix.__new__(cm.CportsMatrix)
            matrix.connections = 73
            matrix.work = Path(directory)
            matrix.fenced = "sqlite.excl-crash"
            events = []
            def start(**kwargs):
                events.append(("start", matrix.connections, kwargs))
                return {"generated": True, "public": "fresh-key"}
            matrix.t = types.SimpleNamespace(setup=lambda work, authorized: events.append(("setup", work.name)),
                                             start=start, port=1, boots=2, image="fresh-image")
            class AtCensus(Exception):
                pass
            def rest(label):
                events.append(("census", matrix.connections))
                raise AtCensus()
            matrix.take_rest = rest
            with patch.object(cm.sm, "Client"), self.assertRaises(AtCensus):
                matrix.fresh_image("authorized", types.SimpleNamespace(name="sqlite.power-cut"))
        self.assertEqual(events, [("setup", "fresh-sqlite.power-cut"), ("start", 73, {"fresh": True}), ("census", 0)])
        self.assertEqual((matrix.fenced, matrix.host_key), (None, "fresh-key"))

if __name__ == "__main__":
    unittest.main()
