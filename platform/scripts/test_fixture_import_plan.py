"""Pure host controls for the unchanged stream and append-plan diagnostics."""
import hashlib
import json
import importlib.util
import pathlib
import struct
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("exec_matrix", HERE / "exec-matrix.py")
em = importlib.util.module_from_spec(spec)
spec.loader.exec_module(em)


class ImportPlan(unittest.TestCase):
    def test_cross_boot_prefix_and_result_identities_match_exact_bytes(self):
        data = b"a" * em.IMPORT_BUDGET + b"b" * em.IMPORT_BUDGET + b"tail"
        files = [("/directory/", b""), ("/large", data), ("/small", b"small")]
        plan = em.import_plan(files)
        records = em.import_plan_records(plan)
        self.assertEqual([step for step, _ in plan], [1, 2, 3, 3])
        state = {}
        for (step, entries), record in zip(plan, records):
            self.assertLessEqual(record["pipe_bytes"], em.IMPORT_BUDGET)
            for (path, chunk), detail in zip(entries, record["files"]):
                prefix = state.get(path, b"") if step == 3 else b""
                result = prefix + chunk
                self.assertEqual(detail["prefix_bytes"], len(prefix))
                self.assertEqual(detail["prefix_sha256"], hashlib.sha256(prefix).hexdigest())
                self.assertEqual(detail["chunk_sha256"], hashlib.sha256(chunk).hexdigest())
                self.assertEqual(detail["result_sha256"], hashlib.sha256(result).hexdigest())
                self.assertEqual(detail["temporary_bytes"], len(result))
                self.assertEqual(detail["temporary_blocks"], (len(result) + 4095) // 4096)
                self.assertEqual(detail["estimated_file_io_bytes"], 3 * len(prefix) + 2 * len(chunk))
                state[path] = result
        self.assertEqual(state, dict(files))

    def test_append_without_a_known_plan_prefix_is_not_a_replay_record(self):
        with self.assertRaisesRegex(ValueError, "no known prefix"):
            em.import_plan_records([(3, [("/file", b"suffix")])])

    def test_step_four_replaces_the_expected_result_instead_of_appending(self):
        records = em.import_plan_records([(1, [("/file", b"old")]), (4, [("/file", b"new")])])
        self.assertEqual(records[-1]["files"][0]["prefix_bytes"], 0)
        self.assertEqual(records[-1]["files"][0]["result_sha256"], hashlib.sha256(b"new").hexdigest())

    def test_peak_counts_the_old_prefix_and_full_successor_at_the_same_time(self):
        size = em.IMPORT_BUDGET
        files = [("/large", b"a" * (2 * size)), ("/small", b"x" * 4096)]
        self.assertEqual(em.import_peak_bytes(files), 3 * size + 4096)
        records = em.import_plan_records(em.import_plan(files))
        self.assertEqual(records[-1]["resident_extra_blocks"] * 4096, 2 * size + 4096)
        self.assertEqual(records[-1]["peak_extra_blocks"] * 4096, 3 * size + 4096)

    def test_temporary_components_are_reserved_in_host_plans(self):
        for path in ["/.absd-import-0000", "/x/.absd-import-abCD/file", "/.absd-import-0000/"]:
            with self.assertRaisesRegex(ValueError, "reserved"):
                em.import_plan_records([(1, [(path, b"")])])

    def test_upfront_capacity_refuses_an_append_peak_that_old_payload_check_would_fit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "blank.img"
            with path.open("wb") as handle:
                handle.truncate(64 * 1024 * 1024)
            files = [("/large", b"x" * (18 * 1024 * 1024))]
            plan = em.import_plan(files)
            self.assertLess(len(files[0][1]), 31 * 1024 * 1024)
            with self.assertRaisesRegex(ValueError, "import_capacity.*temporary successor does not fit"):
                em.check_import_capacity(path, plan)
            self.assertEqual(path.read_bytes()[:512], bytes(512))
            self.assertGreater(em.check_import_capacity(path, em.import_plan([("/small", b"ok")]))["free_blocks"], 0)

    def test_fitted_image_holds_the_peak_that_a_floor_image_refuses(self):
        # The plan the 32 MiB command-matrix image could not hold: its fitted
        # image passes check_import_capacity, and one MiB less would not hold
        # the peak plus headroom.
        mib = 1024 * 1024
        plan = em.import_plan([(f"/bin/p{i}", bytes([i]) * (600 * 1024)) for i in range(30)])
        with tempfile.TemporaryDirectory() as directory:
            floor = pathlib.Path(directory) / "floor.img"
            with floor.open("wb") as handle:
                handle.truncate(16 * mib)
            with self.assertRaisesRegex(ValueError, "temporary successor does not fit"):
                em.check_import_capacity(floor, plan)
            size = em.fitted_image_bytes(plan, 16 * mib)
            self.assertEqual(size % mib, 0)
            fitted = pathlib.Path(directory) / "fitted.img"
            with fitted.open("wb") as handle:
                handle.truncate(size)
            capacity = em.check_import_capacity(fitted, plan)
            peak = capacity["peak_extra_blocks"]
            self.assertGreaterEqual(capacity["free_blocks"], peak + -(-peak // 4))
            smaller = (size - mib) // 512
            self.assertLess(em.absd_fs.geometry(smaller - smaller // 2)["data_blocks"], peak + -(-peak // 4))
        self.assertEqual(em.fitted_image_bytes(em.import_plan([("/small", b"ok")]), 16 * mib), 16 * mib)

    def test_shared_reserved_path_vectors_match_the_rust_constructor(self):
        rows = json.loads((HERE.parent / "tests/fixture-import-paths.json").read_text())
        for row in rows:
            self.assertEqual(em.reserved_import_path(row["path"]), row["reserved"], row["path"])

    def test_replacement_peak_credits_old_blocks_only_after_each_commit(self):
        initial = [("/a", b"a" * 4096), ("/b", b"b" * 4096)]
        records = em.import_plan_records([(4, [("/a", b"new-a"), ("/b", b"new-b")])], initial_files=initial)
        self.assertEqual(records[-1]["peak_extra_blocks"], 1)
        self.assertEqual(records[-1]["resident_extra_blocks"], 0)
        self.assertEqual([f["committed_before_blocks"] for f in records[0]["files"]], [0, 0])
        # A zero-byte replacement can release old blocks for the next entry.
        records = em.import_plan_records([(4, [("/a", b""), ("/b", b"x" * 4096)])], initial_files=initial)
        self.assertEqual(records[-1]["peak_extra_blocks"], 0)
        self.assertEqual(records[-1]["resident_extra_blocks"], -1)

    def test_stream_remains_the_existing_absdfix1_layout(self):
        path, data = b"/file", b"bytes"
        expected = (b"ABSDFIX1" + struct.pack("<H", len(path)) + path + struct.pack("<Q", len(data))
                    + hashlib.sha256(data).digest() + data + b"\0\0")
        self.assertEqual(em.stream([(path.decode(), data)]), expected)


if __name__ == "__main__":
    unittest.main()
