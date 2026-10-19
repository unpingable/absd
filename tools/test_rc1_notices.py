import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("rc1_notices", Path(__file__).with_name("rc1_notices.py"))
notices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notices)


class NoticeChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "docs/rc1/notices"
        self.directory.mkdir(parents=True)
        self.driver = self.root / "platform/c/bin/absd-cc"
        self.driver.parent.mkdir(parents=True)
        self.driver.write_text('link "$kit/lib/libc.a"\n')
        self.makefile = self.root / "platform/userland/Makefile"
        self.makefile.parent.mkdir(parents=True)
        self.makefile.write_text("link libutil.a\n")
        self.sun = self.directory / "libm-0.2.16-UPSTREAM-NOTICES.txt"
        self.sun.write_text("Sun Microsystems Permission to use, copy, modify provided that this notice\n")
        self.if_em = self.directory / "FreeBSD-if_em-BSD-2-Clause.txt"
        self.if_em.write_text("BSD-2-Clause Nicole Graziano Kevin Bowling Intel Corporation\n")
        for name in notices.REQUIRED_SOURCES | notices.REQUIRED_SUPPLEMENTS:
            file = self.root / name
            if not file.exists():
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("local fixture\n")
        self.base = self.root / "base.tar.gz"
        with tarfile.open(self.base, "w:gz") as archive:
            member = tarfile.TarInfo("base/notice.txt")
            member.size = 8
            archive.addfile(member, io.BytesIO(b"original"))
        self.inventory = dict(schema="absd-linked-notices/1", release_id="fixture", scope="local fixture",
            source_sha256={f: notices.sha((self.root / f).read_bytes()) for f in notices.REQUIRED_SOURCES},
            supplement_sha256={f: notices.sha((self.root / f).read_bytes()) for f in notices.REQUIRED_SUPPLEMENTS},
            c_link_inputs={"libc.a": "fixture classified library"}, c_userland_archives={"libutil.a": "fixture"},
            base_archive=dict(name=self.base.name, sha256=notices.sha(self.base.read_bytes()),
                              regular_members_sha256={"base/notice.txt": notices.sha(b"original")}))
        self.write_inventory()

    def write_inventory(self):
        (self.directory / "NOTICE-INPUTS.json").write_text(json.dumps(self.inventory))

    def test_complete_fixture_passes(self):
        self.assertEqual(notices.check(self.root, self.base)[1]["result"], "PASS")

    def test_changed_source_or_missing_notice_refuses(self):
        self.driver.write_text("changed source\n")
        with self.assertRaisesRegex(ValueError, "input missing or changed"):
            notices.check(self.root, self.base)
        self.driver.write_text('link "$kit/lib/libc.a"\n')
        self.sun.unlink()
        with self.assertRaisesRegex(ValueError, "input missing or changed"):
            notices.check(self.root, self.base)

    def test_rehashed_new_link_input_still_requires_classification(self):
        self.driver.write_text('link "$kit/lib/libc.a" "$kit/lib/libnew.a"\n')
        self.inventory["source_sha256"][str(self.driver.relative_to(self.root))] = notices.sha(self.driver.read_bytes())
        self.write_inventory()
        with self.assertRaisesRegex(ValueError, "linker inputs differ"):
            notices.check(self.root, self.base)

    def test_changed_base_or_member_inventory_refuses(self):
        self.inventory["base_archive"]["regular_members_sha256"]["base/notice.txt"] = "0" * 64
        self.write_inventory()
        with self.assertRaisesRegex(ValueError, "member inventory differs"):
            notices.check(self.root, self.base)
        self.base.write_bytes(b"a different archive")
        with self.assertRaisesRegex(ValueError, "base notices archive differs"):
            notices.check(self.root, self.base)

    def test_notice_symlink_refuses(self):
        original = self.if_em.read_bytes()
        self.if_em.unlink()
        other = self.root / "notice.txt"
        other.write_bytes(original)
        self.if_em.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "input missing or changed"):
            notices.check(self.root, self.base)

    def test_omitting_required_entry_and_file_cannot_pass(self):
        for field, name in (("supplement_sha256", "docs/rc1/notices/Picolibc-1.8.12-COPYING.txt"),
                            ("source_sha256", "platform/c/picolibc/PIN")):
            with self.subTest(field=field):
                before = self.inventory[field].pop(name)
                self.write_inventory()
                with self.assertRaisesRegex(ValueError, "required RC1 .* coverage differs"):
                    notices.check(self.root, self.base)
                self.inventory[field][name] = before
                self.write_inventory()

    def test_package_is_repeatable_omits_unlisted_file_and_preserves_base(self):
        (self.directory / "unlisted-fixture.txt").write_text("not approved for packaging")
        before = self.base.read_bytes()
        a, b = self.root / "a.tar.gz", self.root / "b.tar.gz"
        notices.package(self.root, self.base, a)
        notices.package(self.root, self.base, b)
        self.assertEqual(a.read_bytes(), b.read_bytes())
        self.assertEqual(self.base.read_bytes(), before)
        with tarfile.open(a) as archive:
            self.assertFalse(any("unlisted-fixture" in x for x in archive.getnames()))
        with self.assertRaises(FileExistsError):
            notices.package(self.root, self.base, a)


if __name__ == "__main__":
    unittest.main()
