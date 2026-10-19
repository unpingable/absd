"""Actual comparison controls for the documented downward rest-floor rule."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import sys
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
spec = importlib.util.spec_from_file_location("cports_matrix", Path(__file__).with_name("cports-matrix.py"))
cm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cm)


def reading(handles, frames=720):
    return {"images": 0, "memory": f"memory: 100000 KiB free, {frames * 4} KiB allocated (25000 + {frames} frames of 4096 bytes)",
            "kernel": f"kernel: 4 process slots, {handles} handles, 27 pipes, 1 cells", "objects": [],
            "fsd": 20, "fsd_opens": 1, "fsd_draining": 0,
            "rest_at_judgment": {"boot": 8, "handles": handles, "opens": 1}}


class Tests(unittest.TestCase):
    def matrix(self):
        matrix = cm.CportsMatrix.__new__(cm.CportsMatrix)
        matrix.t = types.SimpleNamespace(boots=8)
        matrix.rest = {"boot": 8, "handles": 66, "opens": 1}
        matrix.steps = 0
        matrix.highwater = []
        matrix.limited = set()
        matrix.allowed = lambda case: set()

        def check(text, ok, detail=""):
            if not ok:
                raise cm.sm.Failed(text + ": " + detail)

        matrix.check = check
        return matrix

    def compare(self, before, after, allowed=None, **kwargs):
        matrix = self.matrix()
        if allowed is not None:
            matrix.allowed = lambda case: allowed
        case = types.SimpleNamespace(name="interrupt", removed=[], cwd="fixture")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            matrix.compare_census(case, before, after, **kwargs)
        return matrix, output.getvalue()

    def test_permitted_lowering_retains_raw_counts(self):
        before, after = reading(67), reading(66)
        originals = copy.deepcopy((before, after))
        _, text = self.compare(before, after)
        self.assertEqual((before, after), originals)
        self.assertIn("same-boot rest handle floor 67 -> 66", text)

    def test_stamp_is_independent_of_later_mutation(self):
        matrix = self.matrix()
        raw = reading(66)
        raw.pop("rest_at_judgment")
        stamped = matrix.stamp_rest(raw)
        matrix.rest["handles"] = 65
        self.assertEqual(stamped["rest_at_judgment"]["handles"], 66)
        self.assertNotIn("rest_at_judgment", raw)

    def test_negative_boundaries_remain_failures(self):
        cases = []
        before, after = reading(67), reading(66)
        for field, value in [("boot", 9), ("handles", 65), ("opens", 2)]:
            altered = copy.deepcopy(after)
            altered["rest_at_judgment"][field] = value
            cases.append((field, before, altered))
        for field, value in [("rest_at_judgment", None), ("images", 1), ("fsd_opens", 2),
                             ("fsd_draining", 1), ("fsd", 24), ("objects", [("/other", False, 1)]),
                             ("kernel", "kernel: 4 process slots, 66 handles, 28 pipes, 1 cells")]:
            cases.append((field, before, dict(after, **{field: value})))
        legacy = copy.deepcopy(before)
        legacy.pop("rest_at_judgment")
        cases += [("legacy", legacy, after), ("raised floor", reading(66), reading(67)),
                  ("persistent extra handle", before, dict(after, kernel=before["kernel"])),
                  ("frames exceed existing bound", before, reading(66, frames=720 + cm.STEP_BOUND + 1))]
        for label, first, last in cases:
            with self.subTest(label=label), self.assertRaises(cm.sm.Failed):
                self.compare(first, last)

    def test_explicit_strict_comparisons_stay_exact(self):
        for kwargs in [{"allow_rest_lowering": False},
                       {"restart": True, "allow_rest_lowering": False}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(cm.sm.Failed):
                self.compare(reading(67), reading(66), **kwargs)


    def test_restarted_boot_rebase_uses_its_own_recorded_floor(self):
        before, after = reading(67, 673), reading(66, 729)
        journal = "/fixture/x.db-journal"
        before["objects"] = [(journal, False, 4096)]
        originals = copy.deepcopy((before, after))
        matrix, text = self.compare(before, after, allowed={journal}, restart=True)
        self.assertEqual((before, after), originals)
        self.assertIn("after the restart; informational", text)
        self.assertIn("same-boot rest handle floor 67 -> 66", text)
        self.assertEqual(matrix.steps, 0)
        self.assertEqual(matrix.highwater, [])
        for label, changed in [
            ("different boot", dict(after, rest_at_judgment={"boot": 9, "handles": 66, "opens": 1})),
            ("missing stamp", dict(after, rest_at_judgment=None)),
            ("draining", dict(after, fsd_draining=1)),
            ("extra pipe", dict(after, kernel="kernel: 4 process slots, 66 handles, 28 pipes, 1 cells")),
            ("undeclared file", dict(after, objects=[("/other", False, 1)])),
        ]:
            with self.subTest(label=label), self.assertRaises(cm.sm.Failed):
                self.compare(before, changed, allowed={journal}, restart=True)


if __name__ == "__main__":
    unittest.main()
