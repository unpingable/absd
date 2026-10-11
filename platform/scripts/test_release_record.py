#!/usr/bin/env python3
"""Host tests of scripts/release_record.py: the record round trip, each way
a record or selection is malformed, and the release layout. Plain python3:
`python3 scripts/test_release_record.py`."""

import hashlib
import pathlib
import sys
import unittest

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import release_record as rr  # noqa: E402


def reseal(lines):
    """Six body lines with a correct check line after them."""
    body = b"".join(line + b"\n" for line in lines)
    return body + b"check=" + hashlib.sha256(body).hexdigest().encode() + b"\n"


GOOD_BODY = [b"absd-release 1", b"release=dev", b"kernel_abi=1", b"fsd_protocol=2", b"fs_format=2", b"app_abi=1"]


class Record(unittest.TestCase):
    def test_round_trip(self):
        for release_id in ("dev", "0.4.0", "a", "x" * 64, "rc-1.2"):
            text = rr.record_text(release_id)
            lines = text.split("\n")
            self.assertEqual(lines[-1], "")
            self.assertEqual(len(lines[:-1]), 7)
            body = "".join(line + "\n" for line in lines[:6])
            self.assertEqual(lines[6], "check=" + hashlib.sha256(body.encode()).hexdigest())
            fields = rr.parse_record(text.encode())
            self.assertEqual(fields, dict({"release": release_id}, **rr.IDENTITY))

    def test_matches_the_crate_layout(self):
        self.assertEqual(rr.record_text("dev").encode(), reseal(GOOD_BODY))

    def test_bad_ids_are_refused_when_writing(self):
        for bad in ("", "Dev", "a b", "../etc", "x" * 65, "a\n", "a/b", "é"):
            with self.assertRaises(rr.Malformed, msg=repr(bad)) as caught:
                rr.record_text(bad)
            self.assertEqual(caught.exception.reason, "malformed_id")
            self.assertIsInstance(caught.exception, ValueError)

    def assert_reason(self, data, reason):
        with self.assertRaises(rr.Malformed, msg=repr(data)) as caught:
            rr.parse_record(data)
        self.assertEqual(caught.exception.reason, reason, repr(data))
        self.assertEqual(str(caught.exception), reason)

    def test_each_malformation(self):
        good = rr.record_text("dev").encode()
        malformed = [
            good.decode(),                                  # not bytes
            good[:-1],                                      # no final newline
            good.replace(b"\n", b"\r\n"),                   # carriage returns
            good + b"\n",                                   # an eighth (empty) line
            b"".join(line + b"\n" for line in good.split(b"\n")[:6]),  # six lines
            reseal([b"absd-release 2"] + GOOD_BODY[1:]),    # header
            reseal([GOOD_BODY[0], b"releases=dev"] + GOOD_BODY[2:]),  # key
            reseal([GOOD_BODY[0], b"release="] + GOOD_BODY[2:]),       # empty id
            reseal([GOOD_BODY[0], b"release=Dev"] + GOOD_BODY[2:]),    # id grammar
            reseal(GOOD_BODY[:2] + [b"fsd_protocol=2", b"kernel_abi=1"] + GOOD_BODY[4:]),  # order
            reseal(GOOD_BODY[:2] + [b"kernel_abi=01"] + GOOD_BODY[3:]),  # leading zero
            reseal(GOOD_BODY[:2] + [b"kernel_abi=-1"] + GOOD_BODY[3:]),  # sign
            reseal(GOOD_BODY[:2] + [b"kernel_abi=4294967296"] + GOOD_BODY[3:]),  # beyond u32
            reseal(GOOD_BODY[:2] + [b"kernel_abi=\xd9\xa1"] + GOOD_BODY[3:]),  # non-ASCII digit
            good.replace(b"check=", b"chek="),              # check key
            good[:-2] + b"\n",                              # short check
            good[:-65] + good[-65:-1].upper() + b"\n",      # uppercase hex
        ]
        for data in malformed:
            self.assert_reason(data, "malformed_record")
        # A well-formed check line that does not seal the body.
        damaged = bytearray(good)
        at = damaged.index(b"=") + 1
        damaged[at] = ord("x")
        self.assert_reason(bytes(damaged), "check_mismatch")
        self.assert_reason(good.replace(b"fs_format=2", b"fs_format=3"), "check_mismatch")
        # Fields that parse but differ from this build's are the file
        # server's business (release_mismatch, ...), not the parser's.
        other = reseal(GOOD_BODY[:4] + [b"fs_format=1"] + GOOD_BODY[5:])
        self.assertEqual(rr.parse_record(other)["fs_format"], 1)
        self.assertEqual(rr.parse_record(reseal(GOOD_BODY[:2] + [b"kernel_abi=0"] + GOOD_BODY[3:]))["kernel_abi"], 0)

    def test_selection(self):
        self.assertEqual(rr.selected_bytes("dev"), b"dev\n")
        self.assertEqual(rr.parse_selected(b"dev\n"), "dev")
        self.assertEqual(rr.parse_selected(b"dev"), "dev")
        for bad in (b"", b"\n", b"Dev\n", b"a\n\n", b"../etc\n", b"a b\n", b"x" * 65 + b"\n"):
            with self.assertRaises(rr.Malformed) as caught:
                rr.parse_selected(bad)
            self.assertEqual(caught.exception.reason, "malformed_selected")

    def test_release_id_from_env(self):
        self.assertEqual(rr.release_id_from_env({}), "dev")
        self.assertEqual(rr.release_id_from_env({"ABSD_RELEASE_ID": ""}), "dev")
        self.assertEqual(rr.release_id_from_env({"ABSD_RELEASE_ID": "0.4.0"}), "0.4.0")
        with self.assertRaises(rr.Malformed):
            rr.release_id_from_env({"ABSD_RELEASE_ID": "Bad"})


class Layout(unittest.TestCase):
    FILES = [
        ("/bin/ls", b"ELF ls"),
        ("/bin/", b""),
        ("/share/man/man1/ls.1", b".Dd ls"),
        ("/etc/motd", b"hello\n"),
        ("/ssh/authorized_keys", b"ssh-ed25519 AAAA\n"),
        ("/binary/x", b"not bound"),
        ("/home/operator/.profile", b""),
    ]

    def test_layout(self):
        out = rr.release_layout(self.FILES, "dev")
        self.assertEqual(out, [
            ("/releases/dev/bin/ls", b"ELF ls"),
            ("/releases/dev/bin/", b""),
            ("/releases/dev/share/man/man1/ls.1", b".Dd ls"),
            ("/etc/motd", b"hello\n"),
            ("/ssh/authorized_keys", b"ssh-ed25519 AAAA\n"),
            ("/binary/x", b"not bound"),
            ("/home/operator/.profile", b""),
            ("/releases/dev/release", rr.record_text("dev").encode()),
            ("/absd/selected", b"dev\n"),
        ])
        self.assertEqual(len(out), len(self.FILES) + 2)
        # Nothing is left at a logical bound path.
        self.assertFalse([p for p, _ in out if p.startswith("/bin/") or p.startswith("/share/")])

    def test_idempotent(self):
        once = rr.release_layout(self.FILES, "0.4.0")
        self.assertEqual(rr.release_layout(once, "0.4.0"), once)
        self.assertEqual(rr.release_layout(rr.release_layout(once, "0.4.0"), "0.4.0"), once)
        # Exactly one record and one selection.
        paths = [p for p, _ in rr.release_layout(once, "0.4.0")]
        self.assertEqual(paths.count("/releases/0.4.0/release"), 1)
        self.assertEqual(paths.count("/absd/selected"), 1)
        unselected = rr.release_layout(self.FILES, "0.4.0", select=False)
        self.assertNotIn("/absd/selected", [p for p, _ in unselected])
        self.assertEqual(rr.release_layout(unselected, "0.4.0"), once)

    def test_conflicts_are_refused(self):
        with self.assertRaises(ValueError):
            rr.release_layout([("/bin/ls", b"a"), ("/releases/dev/bin/ls", b"b")], "dev")
        with self.assertRaises(rr.Malformed):
            rr.release_layout([("/absd/selected", b"other\n")], "dev")
        with self.assertRaises(rr.Malformed):
            rr.release_layout([("/releases/dev/release", rr.record_text("other").encode())], "dev")
        with self.assertRaises(rr.Malformed):
            rr.release_layout(self.FILES, "Bad")

    def test_physical(self):
        self.assertEqual(rr.physical("/bin", "dev"), "/releases/dev/bin")
        self.assertEqual(rr.physical("/share/man/x", "dev"), "/releases/dev/share/man/x")
        self.assertEqual(rr.physical("/bins", "dev"), "/bins")
        self.assertEqual(rr.physical("/etc/motd", "dev"), "/etc/motd")


if __name__ == "__main__":
    unittest.main(verbosity=1)
