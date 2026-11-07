"""Pinned host-wheel preparation; network responses are finite fixtures."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("preview2_fetch", Path(__file__).with_name("fetch-preview2-inputs.py"))
fetcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetcher)


class ProvenanceWheelFetch(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.top = Path(self.temp.name) / "source"
        self.work = Path(self.temp.name) / "work"
        self.name = "boolean_py-5.0-py3-none-any.whl"
        self.data = b"finite wheel-download fixture"
        self.digest = hashlib.sha256(self.data).hexdigest()
        for component in ("kernel", "platform"):
            self.config(component, self.digest)

    def config(self, component, digest):
        file = self.top / component / "provenance/config.toml"
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text('[licence_policy.spdx_library.wheels]\n'
                        f'"{self.name}" = "{digest}"\n')

    def responses(self, filename=None, data=None):
        def open_url(url):
            if url == "https://pypi.org/pypi/boolean_py/5.0/json":
                return io.BytesIO(json.dumps({"urls": [{
                    "filename": filename or self.name,
                    "url": "https://files.pythonhosted.org/finite-fixture.whl",
                    "digests": {"sha256": self.digest}
                }]}).encode())
            if url == "https://files.pythonhosted.org/finite-fixture.whl":
                return io.BytesIO(self.data if data is None else data)
            self.fail(f"unexpected network input: {url}")
        return mock.patch.object(fetcher.urllib.request, "urlopen", side_effect=open_url)

    def test_shared_component_pin_materializes_verified_wheel_in_work(self):
        with self.responses():
            fetcher.fetch_provenance_wheels(self.top, self.work)
        file = self.work / "provenance-wheels" / self.name
        self.assertEqual(file.read_bytes(), self.data)
        self.assertEqual(hashlib.sha256(file.read_bytes()).hexdigest(), self.digest)
        self.assertFalse((self.top / ".cache").exists())

    def test_component_pin_disagreement_refuses_before_network(self):
        self.config("platform", "0" * 64)
        with mock.patch.object(fetcher.urllib.request, "urlopen", side_effect=AssertionError("must refuse before download")):
            with self.assertRaisesRegex(SystemExit, "conflicting.*wheel"):
                fetcher.fetch_provenance_wheels(self.top, self.work)
        self.assertFalse((self.work / "provenance-wheels" / self.name).exists())

    def test_same_digest_under_wrong_filename_refuses(self):
        with self.responses(filename="different-5.0-py3-none-any.whl"):
            with self.assertRaisesRegex(SystemExit, "exactly one pinned"):
                fetcher.fetch_provenance_wheels(self.top, self.work)
        self.assertFalse((self.work / "provenance-wheels" / self.name).exists())

    def test_changed_download_retains_unaccepted_part_and_no_final_wheel(self):
        with self.responses(data=b"changed bytes"):
            with self.assertRaisesRegex(SystemExit, "checksum differs"):
                fetcher.fetch_provenance_wheels(self.top, self.work)
        file = self.work / "provenance-wheels" / self.name
        self.assertFalse(file.exists())
        self.assertEqual(file.with_name(file.name + ".part").read_bytes(), b"changed bytes")

    def test_existing_corrupt_wheel_is_not_accepted(self):
        file = self.work / "provenance-wheels" / self.name
        file.parent.mkdir(parents=True)
        file.write_bytes(b"stale bytes")
        with self.responses():
            with self.assertRaisesRegex(SystemExit, "checksum differs"):
                fetcher.fetch_provenance_wheels(self.top, self.work)
        self.assertEqual(file.read_bytes(), b"stale bytes")


if __name__ == "__main__":
    unittest.main()
