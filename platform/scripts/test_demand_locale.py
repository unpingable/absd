#!/usr/bin/env python3
"""Host-only audit: every script that writes a symbol-demand report
(`... > X.demand`) exports LC_ALL=C before it, and never sets another
locale. sort and comm order names by the locale's collation, so a report
written under en_US.UTF-8 differs from one written under C with the same
symbols (the cross-host finding behind scripts/check-cports-locale.py).
A new writer must be classified here. A bounded source-pattern audit."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
WRITERS = {"build-cports.sh": 1, "build-tcc.sh": 1, "run-c-kit.sh": 1}
WRITE = re.compile(r'>\s*"?[^\s"<>|]*\.demand"?(\s|$)')
PIN = re.compile(r"^\s*export LC_ALL=C\s*(#.*)?$")
OTHER = re.compile(r"\bLC_ALL=(?!C\b)|\bLANG=|\bLC_COLLATE=")


def audit(name, source):
    pinned, count = False, 0
    for line in source.replace("\\\n", " ").splitlines():
        if line.lstrip().startswith("#"):
            continue
        if PIN.match(line):
            pinned = True
        elif OTHER.search(line):
            raise ValueError(f"{name}: sets a locale other than C: {line.strip()}")
        if WRITE.search(line):
            count += 1
            if not pinned:
                raise ValueError(f"{name}: writes a .demand report before exporting LC_ALL=C")
    return count


def audit_tree(root=ROOT):
    found = {}
    for path in sorted(root.rglob("*.sh")):
        count = audit(path.name, path.read_text())
        if count:
            found[path.relative_to(root).as_posix()] = count
    return found


class DemandLocaleTests(unittest.TestCase):
    def test_every_demand_writer_pins_the_c_locale(self):
        self.assertEqual(audit_tree(), WRITERS)

    def test_bypasses_are_refused(self):
        writer = 'llvm-nm-18 -u "$o" | awk \'{print $NF}\' | sort > "$dir/$p.demand"\n'
        for source in (writer,
                       writer + "export LC_ALL=C\n",
                       "export LC_ALL=C\nLC_ALL=en_US.UTF-8 sort x > y.demand\n",
                       "export LC_ALL=C\nexport LANG=en_US.UTF-8\n" + writer,
                       'comm -23 "$u" "$d" > "$elf.demand"\n'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                audit("new.sh", source)
        self.assertEqual(audit("new.sh", "export LC_ALL=C\n" + writer), 1)
        self.assertEqual(audit("new.sh", 'cp "$out/absd/"*.demand "$receipts/demand/"\n'), 0)

    def test_the_current_writers_fail_without_their_pin(self):
        for name in WRITERS:
            source = (ROOT / name).read_text()
            with self.subTest(writer=name), self.assertRaises(ValueError):
                audit(name, source.replace("export LC_ALL=C\n", ""))


if __name__ == "__main__":
    unittest.main()
