from pathlib import Path
import importlib.util
import os
import shlex
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


post = load("post_kit", "check-post-kit.py")
fixtures = load("kit_context_fixtures", "test_c_kit_source.py")


class PostKit(unittest.TestCase):
    def setUp(self):
        # Reuse the original guard's real Git/source/kit/POSIX receipt fixture.
        # Its products are dummy bytes; no compiler or guest is started.
        self.f = fixtures.CKitSourceTests("runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        binary = self.f.base / "bin"
        binary.mkdir()
        strip = binary / "llvm-strip-18"
        strip.write_text("#!/bin/sh\n[ \"$1\" = -o ] || exit 1\nprintf '%s' 'stripped printf fixture' >\"$2\"\n")
        strip.chmod(0o755)
        self.env = self.f.env | {"PATH": str(binary) + ":" + os.environ["PATH"]}

    def refresh_context(self):
        self.f.head = self.f.commit("updated fixture")
        self.f.write_kit()
        self.f.run_helper("capture", check=True)
        self.f.run_helper("stamp", check=True)

    def change_field(self, index, value):
        table = self.f.root / "userland/PORTS.tsv"
        row = table.read_text().strip().split("\t")
        row[index] = value
        table.write_text("\t".join(row) + "\n")
        self.refresh_context()

    def check(self):
        with mock.patch.dict(os.environ, self.env, clear=True):
            return post.check(self.f.root)

    def test_original_installer_output_matches_catalog(self):
        self.assertEqual(self.check(), 1)
        self.assertFalse(self.f.ports.exists())  # --print did not install.

    def test_stale_gated_digest_refuses(self):
        self.change_field(4, "0" * 64)
        with self.assertRaisesRegex(post.source.Refused, "printf GATED_SHA256"):
            self.check()

    def test_stale_stripped_digest_refuses(self):
        self.change_field(5, "1" * 64)
        with self.assertRaisesRegex(post.source.Refused, "printf SHA256"):
            self.check()

    def test_stale_installed_length_refuses(self):
        self.change_field(6, "9999")
        with self.assertRaisesRegex(post.source.Refused, "printf BYTES"):
            self.check()

    def test_original_source_context_guard_still_refuses(self):
        self.f.commit("different source")
        with self.assertRaisesRegex(post.source.Refused, "C kit was built from"):
            self.check()

    def builder_marker(self):
        marker = self.f.base / "unexpected-build"
        (self.f.root / "scripts/build-userland.sh").write_text(
            "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nexit 1\n")
        self.refresh_context()
        return marker

    def test_missing_product_refuses_without_building(self):
        marker = self.builder_marker()
        self.f.binary.unlink()
        with self.assertRaisesRegex(post.source.Refused, "post-kit product missing"):
            self.check()
        self.assertFalse(marker.exists())

    def test_disappearing_product_cannot_trigger_installers_implicit_build(self):
        marker = self.builder_marker()
        verify = post.source.verify

        def remove_after_verify(*args, **kwargs):
            result = verify(*args, **kwargs)
            self.f.binary.unlink()
            return result

        with mock.patch.object(post.source, "verify", side_effect=remove_after_verify), \
                self.assertRaisesRegex(post.source.Refused, "no build requested"):
            self.check()
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
