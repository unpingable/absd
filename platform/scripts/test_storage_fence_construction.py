#!/usr/bin/env python3
"""Real constructor boundaries with failed imports, without guest substitution."""
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import operator_image as operator
import storage_fence_state as guard


class InterruptedConstruction(unittest.TestCase):
    def test_failed_seed_or_verification_never_publishes_boot_recipe(self):
        for stop in ("system", "seed", "verify"):
            with self.subTest(stop=stop), tempfile.TemporaryDirectory() as directory:
                # Enrollment sidecars live beside OUT, so own its parent too.
                out = pathlib.Path(directory) / "artifacts"
                calls = []

                def importing(kernel, image, plan, *args, **kwargs):
                    self.assertTrue(kwargs["fresh"])
                    calls.append(plan)
                    if len(calls) == 1 and stop == "system":
                        raise operator.Failed("interrupted before seed")
                    if len(calls) == 2:
                        self.assertIn((guard.PATH, guard.encode("fresh")), plan[0][1])
                        # Interrupted seed can leave any incomplete disk. It
                        # remains unpublished, rather than being resumed.
                        with open(image, "r+b") as handle:
                            handle.write(guard.encode("fresh")[:17])
                        if stop == "seed":
                            raise operator.Failed("interrupted seed import")

                with patch.object(operator, "IMAGE_BYTES", 4096), \
                     patch.object(operator, "check_platform_release"), \
                     patch.object(operator, "system_files", return_value=[]), \
                     patch.object(operator, "etc_files", return_value=[]), \
                     patch.object(operator, "authorized", return_value=""), \
                     patch.object(operator, "import_boots", side_effect=importing), \
                     patch.object(operator, "verify", side_effect=operator.Failed("incomplete import")), \
                     patch.object(operator, "kernel_iso") as boot_iso, \
                     patch.object(operator, "manifest") as manifest:
                    with self.assertRaises(operator.Failed):
                        operator.build(out, out, [], root=out, release_id="dev")
                    boot_iso.assert_not_called()
                    manifest.assert_not_called()
                self.assertTrue((out / operator.IMAGE).is_file())
                self.assertFalse((out / operator.ISO).exists())
                self.assertFalse((out / "MANIFEST").exists())

    def test_existing_output_is_never_overwritten_or_reseeded(self):
        for name in (operator.IMAGE, operator.ISO, "MANIFEST"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                out = pathlib.Path(directory)
                prior = out / name
                prior.write_bytes(b"existing state")
                with patch.object(operator, "check_platform_release"), \
                     patch.object(operator, "import_boots") as importing:
                    with self.assertRaises(operator.Failed):
                        operator.build(out, out, [], root=out, release_id="dev")
                    importing.assert_not_called()
                self.assertEqual(prior.read_bytes(), b"existing state")


if __name__ == "__main__":
    unittest.main()
