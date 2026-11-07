import hashlib
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(*args, env=None):
    completed = subprocess.run(
        ["nice", "-n", "10", "taskset", "-c", "0,1,6,7", *args],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise AssertionError(f"command failed ({completed.returncode}): {' '.join(args)}\n{completed.stdout}")
    return completed.stdout


class MwmBuildTests(unittest.TestCase):
    def test_protocol_and_experiment_elf_iso_identities(self):
        run("make", "mwm-protocol-test", "mwm-demo-iso", "mwm-fault-iso")
        receipts = {}
        for phase in ("demo", "fault"):
            lines = (ROOT / f"build/mwm/{phase}.sha256").read_text().splitlines()
            self.assertEqual(len(lines), 4)
            records = []
            for line in lines:
                digest, name = line.split(maxsplit=1)
                path = pathlib.Path(name.lstrip("*"))
                if not path.is_absolute():
                    path = ROOT / path
                self.assertTrue(path.is_file(), path)
                self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
                records.append((digest, path))
            self.assertEqual(records[0][1].name, "mwm.elf")
            self.assertEqual(records[1][1].name, "init.elf")
            self.assertNotEqual(records[0][0], records[1][0])
            self.assertEqual(records[0][1].read_bytes()[:5], b"\x7fELF\x02")
            self.assertEqual(records[1][1].read_bytes()[:5], b"\x7fELF\x02")
            self.assertEqual(records[3][1], ROOT / f"build/mwm/{phase}.iso")
            receipts[phase] = records
        self.assertEqual(receipts["demo"][2][0], receipts["fault"][2][0])
        self.assertNotEqual(receipts["demo"][3][0], receipts["fault"][3][0])

    def test_ordinary_userspace_build_has_no_mwm_elf_or_route(self):
        run("sh", "scripts/build-user.sh", "build/mwm-default/user")
        self.assertFalse((ROOT / "build/mwm-default/user/mwm.elf").exists())
        init = (ROOT / "build/mwm-default/user/init.elf").read_bytes()
        self.assertNotIn(b"MWM LAST CLOSE MASK", init)
        self.assertNotIn(b"MWM SUCCESSOR OPEN", init)


if __name__ == "__main__":
    unittest.main()
