#!/usr/bin/env python3
"""Exercise the real frozen checker on reviewed files and structural mutants.

Uses one temporary Git repository and immutable historical base-file fixtures.
No component Git history, build, guest, network, or source-checkout edits are
needed. Run with python3 -B -I.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
CHECKER = "scripts/check-storage-fence-frozen.py"
# Independently reviewed fixtures (#94/#119 and steward2052 authority check).
# PTY oracle review: steward Claude git-0a, 2026-11-06 01:34Z.
# outbox/20261106T0133Z-steward-paste-oracle-accept-01a1aa59.md
# Patch SHA256 01bb61f97a9eb59aad45fc9511bb3db790e5e5e8d89c392a629e4ea56afd02f3.
# Only live PTY mode bytes changed; historical frozen fixtures stay pinned.
# Combined LOGD + PTY blobs accepted by steward git-0a, 2026-11-06 01:41Z:
# outbox/20261106T0141Z-steward-combined-blobs-accept-01a1aa64.md
# COMBINED-LIVE-BLOBS.patch SHA256 081bc4003474b2bf2c08af2a62a2a73be67991cb5165b0a7260495529872a9da.
# Capacity/profile oracle review: Claude git-0a, 2026-11-06.
# CAPACITY-INDEPENDENT-REVIEW-claude-git0a.md SHA256
# a48e6380453e30ea0974c303a0f7d67be42c9ef2bd0d7e2ba9c91c88c8fdf400.
# Only the two exact reviewed live blobs advance; historical fixtures stay pinned.
# Journal inventory oracle: Claude git-0a ACCEPT, 2026-11-06.
# journal-oracle01/INDEPENDENT-REVIEW-claude-git0a.md SHA256
# 7ee5ba1f3bfa6f41e28e2465e9a6f250c68973125a9fd393c663f93c9eadaa66.
# Exact ssh_absd live blob only; historical fixtures remain unchanged.
REVIEWED = {
    "scripts/run-storage-fence-matrix.sh": "c99193d372c8206cafc8661bd87db685e05bf73d",
    "scripts/storage-fence-ghost.py": "068e9d3e34a6bcb252c4f741596ce8ecdf1b9575",
    # Served-only prompt-context repair: steward Claude git-0a, 2026-11-06 01:53Z.
    # outbox/20261106T0153Z-steward-oracle02-accept-01a1aa59.md
    # Patch SHA256 e38fba546a61f64969dc765f75a3b1b90851840d923febad7617dc0843c16aff.
    # Combined LOGD + oracle02 blob accepted by steward git-0a, 2026-11-06 01:57Z.
    # outbox/20261106T0157Z-steward-combined-blob02-accept-01a1aa64.md
    # Combined patch SHA256 a13acea45de63e8a1b2d682ec9e22e8f57ba9ea9ceb0ae4152d20c46fe99c90c.
    "scripts/served-matrix.py": "103107ec8f9ad713803c0dd1795a831fa3ba19e8",
    # Exact eight-mount oracle accepted by steward Claude git-0a, 2026-11-06 03:06Z.
    # outbox/20261106T0306Z-steward-mount-oracle-accept-01a1aa64.md
    # Acceptance record SHA256 eb847dee6010c10f19c874753ee701e5d7a2877ebe87150c860107478d5497ba.
    "scripts/ssh_absd.py": "56bf45d31994c8836326eac28f04e8fc6a1b3e49",
}
RUN, GHOST, SERVED, SSH = REVIEWED
BASE_FIXTURES = {
    RUN: "06d40ee48a3f72d91f0fac9bef46dad2d57b6bfe",
    GHOST: "7c8ee0bba0172e585d724bece5e526d6f45eed73",
    SERVED: "3c694f36280bdac0ebfc102c1ff2048cbf26ea31",
    SSH: "8d970eb1283b6c6e2c642a88b9b1d5d24e5c0c37",
}


class FrozenSources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="absd-frozen-controls-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.tree = Path(cls.temporary.name) / "source"
        # Other historical rules compare equal sources. Only the reviewed
        # exceptions differ from this fixture base, which is not 0414342f.
        shutil.copytree(ROOT / "scripts", cls.tree / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        subprocess.run(["git", "init", "--quiet", str(cls.tree)], check=True)
        cls.reviewed, cls.base_sources = {}, {}
        for path, blob in REVIEWED.items():
            body = (ROOT / path).read_bytes()
            old = (ROOT / "scripts/fixtures/storage-fence-frozen" / Path(path).name).read_bytes()
            for data, pinned in ((body, blob), (old, BASE_FIXTURES[path])):
                actual = subprocess.check_output(["git", "-C", str(cls.tree), "hash-object", "--stdin"],
                                                 input=data).decode().strip()
                if actual != pinned:
                    raise AssertionError(f"{path}: test fixture blob {actual} is not {pinned}")
            cls.reviewed[path] = body
            cls.base_sources[path] = old
            (cls.tree / path).write_bytes(old)
        subprocess.run(["git", "-C", str(cls.tree), "add", "scripts"], check=True)
        subprocess.run(["git", "-C", str(cls.tree), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                        "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "Frozen checker fixture base"],
                       check=True)
        cls.base = subprocess.check_output(["git", "-C", str(cls.tree), "rev-parse", "HEAD"], text=True).strip()
        for path, body in cls.reviewed.items():
            (cls.tree / path).write_bytes(body)

    def checker(self):
        return subprocess.run([sys.executable, "-B", "-I", str(self.tree / CHECKER), "--base", self.base],
                              cwd=self.tree, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
                              capture_output=True, text=True, timeout=30)

    def replaced(self, path, before, after):
        body = self.reviewed[path]
        self.assertEqual(body.count(before), 1, "mutation must replace exactly one reviewed location")
        return body.replace(before, after, 1)

    def refuses(self, path, body):
        target = self.tree / path
        try:
            if body is None:
                target.unlink()
            else:
                target.write_bytes(body)
            result = self.checker()
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("STORAGE FENCE FROZEN FAILED", result.stderr)
            self.assertIn(path, result.stderr)
            self.assertNotIn("STORAGE FENCE FROZEN OK", result.stdout)
        finally:
            target.write_bytes(self.reviewed[path])

    def test_exact_reviewed_sources_pass(self):
        result = self.checker()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"STORAGE FENCE FROZEN OK files=20 base={self.base}", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_omitted_work_guard_refuses(self):
        self.refuses(RUN, self.replaced(RUN, b'absd_work_dir "$work" "$root/.fence-work/run"\n', b""))

    def test_omitted_work_marker_trap_refuses(self):
        self.refuses(RUN, self.replaced(RUN, b'trap \'absd_mark_work "$work"\' EXIT\n', b""))

    def test_guard_after_deletion_refuses(self):
        guard = b'absd_work_dir "$work" "$root/.fence-work/run"\n'
        body = self.replaced(RUN, guard, b"")
        deletion = b'rm -rf "${work:?}"\n'
        self.assertEqual(body.count(deletion), 1)
        self.refuses(RUN, body.replace(deletion, deletion + guard, 1))

    def test_original_return_without_session_authority_fixture_refuses(self):
        self.refuses(SERVED, self.replaced(
            SERVED,
            b'        return super().files(authorized) + [("/ssh/matrix-echo", (self.root / "commands" / "echo").read_bytes())]\n',
            b'        return super().files(authorized)\n'))

    def test_omitted_loader_assertion_refuses(self):
        assertion = (
            b'        self.check("a file that is no program is refused by the loader, read with the session\'s authority",\n'
            b'                   rc == 126 and out == b"" and err.startswith(b"absd-sh: /home/operator/not-a-program: cannot run: "),\n'
            b'                   f"rc={rc} {out!r} {err!r}")\n')
        self.refuses(SERVED, self.replaced(SERVED, assertion, b""))

    def test_duplicate_socket_creation_refuses(self):
        line = b"    sockets.mkdir(mode=0o700)\n"
        self.refuses(GHOST, self.replaced(GHOST, line, line + line))

    def test_socket_creation_before_path_bound_check_refuses(self):
        line = b"    sockets.mkdir(mode=0o700)\n"
        body = self.replaced(GHOST, line, b"")
        loop = b"    for path in (export, ctl):\n"
        self.assertEqual(body.count(loop), 1)
        self.refuses(GHOST, body.replace(loop, line + loop, 1))

    def test_early_success_marker_refuses(self):
        marker = b'        self.mark("DIRECT PATH OK")\n'
        body = self.replaced(SERVED, marker, b"")
        first = b'        rc, out, err = self.ssh("/ssh/matrix-echo read with sshd authority")\n'
        self.assertEqual(body.count(first), 1)
        self.refuses(SERVED, body.replace(first, marker + first, 1))

    def test_one_character_mutations_refuse(self):
        for path, before, after in (
                (RUN, b'absd_work_dir "$work"', b'absd_work_dir "$worl"'),
                (GHOST, b"sockets.mkdir(mode=0o700)", b"sockets.mkdir(mode=0o701)"),
                (SERVED, b'self.mark("DIRECT PATH OK")', b'self.mark("DIRECT PATH NO")'),
                (SSH, b'if storage_fence_state.parse(state) != "clean":',
                 b'if storage_fence_state.parse(state) == "clean":')):
            with self.subTest(path=path):
                self.refuses(path, self.replaced(path, before, after))

    def test_unlisted_additions_refuse(self):
        for path in REVIEWED:
            with self.subTest(path=path):
                self.refuses(path, self.reviewed[path] + b"\n# unlisted addition\n")

    def test_missing_sources_refuse(self):
        for path in REVIEWED:
            with self.subTest(path=path):
                self.refuses(path, None)

    def test_old_base_sources_are_not_current_positive_controls(self):
        for path in REVIEWED:
            with self.subTest(path=path):
                self.refuses(path, self.base_sources[path])


if __name__ == "__main__":
    unittest.main()
