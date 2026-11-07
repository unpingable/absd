#!/usr/bin/env python3
"""ABSD-target C compilations read no host system header.

A cross build for ABSD may read its own sources, the kit's and Picolibc's
headers and clang's resource headers, never the host's /usr/include or
/usr/local/include. Each compiler configuration that builds shipped ABSD
code is run here with -M on a probe that includes the headers whose clang
versions probe the host (limits.h, stdint.h, both through __has_include_next
as Picolibc's limits.h does with #include_next); the dependency list must
name nothing outside the fixture and clang's resource headers:

  * Picolibc: the c_args of c/picolibc/cross-absd.txt (scripts/build-picolibc.sh
    also checks the real build's Ninja dependency log);
  * absd-cc, the driver the cports, the POSIX adapter and the userland ports
    compile with (the real script, over a fixture kit);
  * the kit's own C objects (kitflags of scripts/build-c-kit.sh);
  * the cc-crate CFLAGS_x86_64_unknown_absd of the shell build scripts, and
    -nostdinc in the Python fixture builders' flag lists.

Negative controls show the check sees the host header when the flags allow
it (the Picolibc c_args without -nostdlibinc; absd-cc without -nostdinc).
Needs clang-18; builds nothing.
"""
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLANG = os.environ.get("ABSD_CLANG", "clang-18")
RESOURCE = subprocess.run([CLANG, "-print-resource-dir"], capture_output=True, text=True,
                          check=True).stdout.strip() + "/include/"
SHELL_CFLAGS = ["build-integration.sh", "build-ag-loopctl.sh", "prepare-and-build.sh",
                "build-nq.sh", "build-nightshift.sh"]
PYTHON_CFLAGS = ["build-native-tls-fixture.py", "build-native-quic-fixture.py",
                 "check-native-tls-ipv6-host.py", "clang-guest-matrix.py"]


def deps(text):
    """Paths of a make-style dependency list (first target dropped)."""
    body = text.replace("\\\n", " ").split(":", 1)[1]
    return body.split()


class TargetHostHeaders(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="absd-host-headers."))
        self.addCleanup(shutil.rmtree, self.tmp)
        inc = self.tmp / "kit/include"
        inc.mkdir(parents=True)
        # Picolibc's limits.h ends in #include_next <limits.h> (to reach clang's).
        (inc / "limits.h").write_text("#include_next <limits.h>\n")
        self.probe = self.tmp / "probe.c"
        self.probe.write_text("#include <limits.h>\n#include <stdint.h>\n#include <stddef.h>\n"
                              "int x = INT_MAX; intptr_t y; size_t z;\n")

    def host_reads(self, paths):
        return sorted(p for p in paths if os.path.isabs(p) and not p.startswith(str(self.tmp) + "/")
                      and not p.startswith(RESOURCE))

    def clang_m(self, flags):
        r = subprocess.run([CLANG, *flags, "-M", str(self.probe)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return self.host_reads(deps(r.stdout))

    def picolibc_args(self):
        cross = (ROOT / "c/picolibc/cross-absd.txt").read_text()
        c = re.search(r"^c = \[(.*?)\]", cross, re.M | re.S).group(1)
        args = re.search(r"^c_args = \[(.*?)\]", cross, re.M | re.S).group(1)
        quoted = lambda s: re.findall(r"'([^']*)'", s)
        # The '-fdebug-prefix-map=' + absd_tmpdir + '=/tmp' element is a
        # concatenation; its pieces are not flags of their own.
        flags = [a for a in quoted(args) if a.startswith("-") and a != "=/tmp" and not a.endswith("=")]
        return quoted(c)[1:], flags

    def test_picolibc_cross_args(self):
        target, flags = self.picolibc_args()
        self.assertIn("-nostdlibinc", flags)
        self.assertEqual(self.clang_m(target + flags + ["-I", str(self.tmp / "kit/include")]), [])

    def test_picolibc_negative_control(self):
        target, flags = self.picolibc_args()
        flags = [f for f in flags if f != "-nostdlibinc"]
        self.assertIn("/usr/include/limits.h", self.clang_m(target + flags + ["-I", str(self.tmp / "kit/include")]))

    def absd_cc(self, script):
        kit = self.tmp / "kit"
        (kit / "bin").mkdir(exist_ok=True)
        (kit / "bin/absd-cc").write_text(script)
        (kit / "bin/absd-cc").chmod(0o755)
        dep = self.tmp / "probe.d"
        r = subprocess.run([str(kit / "bin/absd-cc"), "-c", f"-Wp,-MD,{dep}", "-o", str(self.tmp / "probe.o"),
                            str(self.probe)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return self.host_reads(deps(dep.read_text()))

    def test_absd_cc(self):
        self.assertEqual(self.absd_cc((ROOT / "c/bin/absd-cc").read_text()), [])

    def test_absd_cc_negative_control(self):
        script = (ROOT / "c/bin/absd-cc").read_text()
        self.assertEqual(script.count(" -nostdinc "), 1)
        self.assertIn("/usr/include/limits.h", self.absd_cc(script.replace(" -nostdinc ", " ")))

    def test_kit_objects(self):
        text = (ROOT / "scripts/build-c-kit.sh").read_text()
        flags = re.search(r'^kitflags="([^"]*)"', text, re.M).group(1)
        flags = (flags.replace("$root/c/include", str(ROOT / "c/include"))
                 .replace("$pico/include", str(self.tmp / "kit/include"))
                 .replace("$clang_include", RESOURCE.rstrip("/")))
        self.assertNotIn("$", flags)
        self.assertEqual(self.clang_m(shlex.split(flags)), [])

    def test_cc_crate_cflags(self):
        for name in SHELL_CFLAGS:
            with self.subTest(script=name):
                text = (ROOT / "scripts" / name).read_text()
                found = re.findall(r'^CFLAGS_x86_64_unknown_absd="([^"]*)"', text, re.M)
                self.assertEqual(len(found), 1)
                flags = (found[0].replace("$clang_include", RESOURCE.rstrip("/"))
                         .replace("$root", str(ROOT)))
                self.assertNotIn("$", flags)
                self.assertEqual(self.clang_m(shlex.split(flags)), [])
        for name in PYTHON_CFLAGS:
            with self.subTest(script=name):
                text = (ROOT / "scripts" / name).read_text()
                lists = re.findall(r'\["--target=x86_64-unknown-none-elf",[^\]]*', text)
                self.assertTrue(lists)
                for flags in lists:
                    self.assertIn('"-nostdinc"', flags)


if __name__ == "__main__":
    unittest.main()
