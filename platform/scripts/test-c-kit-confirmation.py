"""Host replay of C-kit census confirmation; no guest or SSH identities."""
import contextlib
import copy
import importlib.util
import io
import itertools
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
spec = importlib.util.spec_from_file_location("kit_confirmation", Path(__file__).with_name("c-kit-matrix.py"))
ck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ck)


def reading(handles=66, frames=743):
    return {"images": 0,
            "memory": f"memory: {frames * 4} KiB allocated (63181 + {frames} frames of 4096 bytes)",
            "kernel": f"kernel: 4 process slots, {handles} handles, 27 pipes, 1 cells",
            "objects": [("/etc/input", False, False, 1, "digest")],
            "quiescent": {"handles": 57, "accepted_reclaimed": 146}}


class Clock:
    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Tests(unittest.TestCase):
    def setUp(self):
        self.real_time = ck.time
        ck.time = Clock()
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()

    def tearDown(self):
        self.output.__exit__(None, None, None)
        ck.time = self.real_time

    def matrix(self, samples, anchor=True):
        matrix = ck.KitMatrix.__new__(ck.KitMatrix)
        if anchor:
            matrix._settled_census = reading()
        sequence = iter(samples)
        last = None
        matrix.samples = []

        def census():
            nonlocal last
            last = next(sequence, last)
            matrix.samples.append(copy.deepcopy(last))
            return copy.deepcopy(last)

        def check(text, ok, detail=""):
            if not ok:
                raise ck.sm.Failed(text + ": " + detail)

        matrix.census, matrix.check = census, check
        return matrix

    def test_n5_pair_does_not_confirm_before(self):
        # Actual candidate11 pattern: 66, then two transient 67 readings;
        # reclamation returns to 66 while confirmation is still polling.
        matrix = self.matrix([reading(n) for n in (66, 67, 67, 66, 66)])
        before = matrix.stable("exit return", "before", confirm=True)
        self.assertEqual(before["kernel"], reading()["kernel"])
        self.assertEqual(len(matrix.samples), 5)
        matrix.compare_census("exit return", before, reading())
        self.assertEqual(matrix.samples[1]["kernel"], reading(67)["kernel"])

    def test_real_case_loop_keeps_the_preceding_judged_anchor(self):
        # Three initial readings plus two after readings establish the first
        # case. The next case's transient lasts three readings, so merely
        # increasing the agreement count cannot make this replay pass.
        samples = [reading(n) for n in [66] * 5 + [67] * 3 + [66] * 4]
        matrix = self.matrix(samples)
        ran = []
        with tempfile.TemporaryDirectory(prefix="c-kit-n5-loop-") as work:
            matrix.work = Path(work)
            matrix.op = Path(work) / "fixture"
            matrix.op.with_suffix(".pub").write_text("fixture text, not an SSH identity")
            matrix.t = types.SimpleNamespace(setup=mock.Mock(), start=lambda **kw: {"public": "fixture"},
                                             stop=mock.Mock(), port=0)
            matrix.pin = ["fixture"]
            matrix.cases = [("shell", name, "-") for name in ("first", "second")]
            matrix.probe_shell = lambda: {}

            def run_case(route, program, *args):
                ran.append(program)
                return program, None, None, []

            matrix.run_case = run_case
            matrix.judge = lambda *args: "agree"
            matrix.live_frames = lambda *args, **kwargs: (0, 743)
            matrix.run_vectors = lambda *args: None
            matrix.alive = lambda *args: None
            with mock.patch.object(ck.sm, "Client", return_value=types.SimpleNamespace(trust=lambda key: None)):
                matrix.run()
        self.assertEqual(ran, ["first", "second"])
        self.assertEqual(len(matrix.samples), 12)
        self.assertEqual(matrix._settled_census, reading())

    def test_initial_confirmation_also_rejects_a_pair(self):
        matrix = self.matrix([reading(n) for n in (66, 67, 67, 66, 66, 66)], anchor=False)
        before = matrix.stable("first case", "before", confirm=True)
        self.assertEqual(before["kernel"], reading()["kernel"])
        self.assertEqual(len(matrix.samples), 6)

    def test_persistent_extra_handle_after_still_fails(self):
        matrix = self.matrix([reading(), reading()])
        before = matrix.stable("leaky", "before", confirm=True)
        matrix.census = lambda: reading(67)
        after = matrix.stable("leaky", "after")
        self.assertEqual(after["kernel"], reading(67)["kernel"])
        with self.assertRaisesRegex(ck.sm.Failed, "resources after leaky"):
            matrix.compare_census("leaky", before, after)

    def after(self, samples):
        """The after-reading of a case whose before census is 66 handles."""
        matrix = self.matrix(samples)
        return matrix, matrix.stable("exit abort", "after", settle_to=reading())

    def test_after_transient_that_settles_back_passes(self):
        # 66 -> (case) -> 66, 67, 66 (the mock repeats the last sample).
        matrix, after = self.after([reading(n) for n in (66, 67, 66)])
        self.assertEqual(after["kernel"], reading()["kernel"])
        matrix.compare_census("exit abort", reading(), after)

    def test_candidate12_after_pair_no_longer_ends_the_reading(self):
        # Candidate 12 (f8921a65): 66, then a transient pair 67, 67, which the
        # old rule returned; reclamation then brings the census back to 66.
        matrix, after = self.after([reading(n) for n in (66, 67, 67, 66)])
        self.assertEqual(after["kernel"], reading()["kernel"])
        matrix.compare_census("exit abort", reading(), after)
        self.assertLessEqual(ck.time.now, 20)

    def test_persistent_extra_handle_after_with_its_before_still_fails(self):
        matrix, after = self.after([reading(67)])
        self.assertEqual(after["kernel"], reading(67)["kernel"])
        self.assertGreaterEqual(ck.time.now, 20)
        with self.assertRaisesRegex(ck.sm.Failed, "resources after exit abort"):
            matrix.compare_census("exit abort", reading(), after)

    def test_after_transient_longer_than_the_bound_still_fails(self):
        # 67 for the whole 20 s, back to 66 only later: the last sample read
        # within the bound is 67, as before this change.
        samples = [reading(67)] * 25 + [reading(66)]
        matrix, after = self.after(samples)
        self.assertEqual(after["kernel"], reading(67)["kernel"])
        with self.assertRaisesRegex(ck.sm.Failed, "resources after exit abort"):
            matrix.compare_census("exit abort", reading(), after)

    def test_bounded_after_histories_pass_only_on_a_settled_pair(self):
        # Every history of up to 8 readings (the last repeats, well within the
        # bound) is judged equal to before exactly when two consecutive
        # readings are 66: a 67 pair never ends the reading, a lone 66 never
        # hides a persistent 67, and a history ending at 66 always passes.
        traces = 0
        for length in range(1, 9):
            for sequence in itertools.product((66, 67), repeat=length):
                traces += 1
                matrix, after = self.after([reading(n) for n in sequence])
                stream = list(sequence) + [sequence[-1]]
                settled = any(a == b == 66 for a, b in zip(stream, stream[1:]))
                self.assertEqual(matrix.unchanged("exit abort", reading(), after), settled, sequence)
        self.assertEqual(traces, 510)

    def test_retained_file_after_reading_settles_like_compare_census(self):
        kept = reading()
        kept["objects"].append((ck.STDIO_FILE, False, False, 3, "new digest"))
        matrix = self.matrix([kept])
        after = matrix.stable("stdio write", "after", settle_to=reading())
        self.assertEqual(after, kept)
        self.assertLess(ck.time.now, 20)
        matrix.compare_census("stdio write", reading(), after)

    def test_persistent_extra_handle_before_is_unsettled(self):
        matrix = self.matrix([reading(67)])
        with self.assertRaisesRegex(ck.sm.Failed, "C KIT RESOURCES UNSETTLED"):
            matrix.stable("leaky", "before", confirm=True)
        self.assertGreaterEqual(ck.time.now, ck.CONFIRM_SECONDS)

    def test_anchor_preserves_every_compared_resource(self):
        variants = [dict(reading(), images=1), reading(frames=744),
                    dict(reading(), objects=[])]
        for kernel in ["kernel: 5 process slots, 66 handles, 27 pipes, 1 cells",
                       "kernel: 4 process slots, 66 handles, 28 pipes, 1 cells",
                       "kernel: 4 process slots, 66 handles, 27 pipes, 2 cells"]:
            variants.append(dict(reading(), kernel=kernel))
        for sample in variants:
            with self.subTest(sample=sample):
                matrix = self.matrix([sample])
                with self.assertRaisesRegex(ck.sm.Failed, "C KIT RESOURCES UNSETTLED"):
                    matrix.stable("changed", "before", confirm=True)
                with self.assertRaisesRegex(ck.sm.Failed, "resources after changed"):
                    matrix.compare_census("changed", reading(), sample)

    def test_expected_stdio_file_is_part_of_next_anchor(self):
        after = reading()
        after["objects"].append((ck.STDIO_FILE, False, False, 3, "new digest"))
        matrix = self.matrix([after, after])
        matrix.compare_census("stdio write", reading(), after)
        matrix._settled_census = copy.deepcopy(after)
        before = matrix.stable("cat c-stdio.dat", "before", confirm=True)
        self.assertEqual(before["objects"], after["objects"])

    def test_quiescence_sequence_is_not_an_exact_resource_field(self):
        first, second = reading(), reading()
        second["quiescent"]["accepted_reclaimed"] += 1
        matrix = self.matrix([first, second])
        self.assertEqual(matrix.stable("same", "before", confirm=True), second)

    def test_bounded_sample_histories_never_confirm_an_anchor_change(self):
        traces = 0
        for length in range(1, 9):
            for sequence in itertools.product((66, 67), repeat=length):
                traces += 1
                matrix = self.matrix([reading(n) for n in sequence])
                try:
                    before = matrix.stable("bounded replay", "before", confirm=True)
                except ck.sm.Failed as error:
                    self.assertIn("C KIT RESOURCES UNSETTLED", str(error))
                else:
                    self.assertEqual(before["kernel"], reading()["kernel"])
        self.assertEqual(traces, 510)


if __name__ == "__main__":
    unittest.main()
