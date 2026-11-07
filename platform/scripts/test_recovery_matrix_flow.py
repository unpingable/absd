"""Stubbed native-matrix flow and deliberate omission controls.

Boots, release commands, SSH transport and cold boots are local substitutions;
the Matrix methods, snapshots, real file hashes, case order and terminal
report run unchanged. This is oracle qualification, not native OS evidence.
"""

import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import inspect
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("recovery_flow_oracle", HERE / "recovery-point-matrix.py")
n = importlib.util.module_from_spec(spec); spec.loader.exec_module(n)
A = "03479a3e090e847ccdfa647dce44e7b16d035988"
B = "b" * 40
KERNEL = "101c61d82534b8c25b7295eb5a2fcd0e72cc5b3a"
SEED = bytes(range(32))
FP = n.rel.host_key_fingerprint(SEED)


def image_write(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, sort_keys=True))


def image_read(path):
    return json.loads(path.read_text())


class Target:
    def __init__(self, out):
        self.out = Path(out).resolve(); self.image = self.out / n.rel.IMAGE; self.iso = self.out / n.rel.ISO

    def tree(self):
        return {path: bytes.fromhex(data) for path, data in image_read(self.image)["files"].items()}

    def release_iso(self, release):
        return self.out / "releases" / release / n.rel.ISO


def inventory(image):
    state = image_read(image)
    found = {path: {"kind": "directory"} for path in state["dirs"]
             if any(path == root or path.startswith(root + "/") for root in n.rp.STATE_ROOTS)}
    found.update({path: {"kind": "file", "bytes": len(bytes.fromhex(data)), "sha256": n.sha(bytes.fromhex(data))}
                  for path, data in state["files"].items()
                  if any(path == root or path.startswith(root + "/") for root in n.rp.STATE_ROOTS)})
    return found


class Scenario:
    def __init__(self, root, injection=None):
        self.root, self.injection, self.current = root, injection, None
        self.pub = root / "evidence"; self.private = root / "private"
        self.point_image, self.point_iso = None, b"release-A-iso"
        self.release_dirs = {}
        for rid, revision in (("rel-a", A), ("rel-b", B)):
            path = root / rid; path.mkdir(); self.release_dirs[rid] = path
            (path / "manifest").write_text("stub manifest for " + revision)
        (root / "key").write_text("local substitution fixture, not an SSH private key")
        (root / "key.pub").write_text("local substitution public identity")
        ancestry = root / "ancestry.json"
        ancestry.write_text(json.dumps({"schema": "p2-source-ancestry/1", "A": A, "B": B,
                                        "command": "git merge-base --is-ancestor", "exit_code": 0}))
        self.args = types.SimpleNamespace(private_work=str(self.private), evidence=str(self.pub), key=str(root / "key"),
            release_a=str(root / "rel-a"), release_b=str(root / "rel-b"), kernel=str(root / "kernel"),
            source_a=A, source_b=B, ancestry=str(ancestry), ancestry_sha256=n.sha(ancestry.read_bytes()), port=2237)
        if injection == "ancestry-pin":self.args.ancestry_sha256 = "0" * 64

    def release(self, path):
        rid = Path(path).name
        source = A if rid == "rel-a" else B
        return types.SimpleNamespace(id=rid, path=Path(path), manifest=Path(path) / "manifest",
            artifact_digests=lambda: {"tree/bin/release": n.sha(rid.encode())},
            kernel_commit=lambda: ("0f770fe5469861e5d6a55652a2153c75ba834ffe" if self.injection == "old-kernel" else "4bc8009701bfd0ddfde1b27851593aaad9aa906f" if self.injection == "previous-kernel" else "e" * 40 if self.injection == "wrong-kernel" else KERNEL), _manifest_doc=lambda: {
                "source": {"platform_commit": source, "kernel_commit": KERNEL,
                           "platform_tree_clean": True, "kernel_tree_clean": True},
                "artifacts": {"files": {"tree/bin/release": {"sha256": n.sha(rid.encode())}}}})

    def boot(self, target, iso, name, port):
        scenario = self
        class Proc:
            returncode = None
            def poll(self):return self.returncode
            def wait(self, timeout=None):return self.returncode
            def kill(self):
                state = image_read(target.image)
                state["files"][n.guard.PATH] = n.guard.encode(
                    "clean" if scenario.injection == "dirty-guard" else "dirty").hex()
                image_write(target.image, state); self.returncode = -9
                if scenario.injection == "post-stop-marker":
                    del state["files"][n.LATER]; image_write(target.image, state)
                if scenario.injection == "post-stop-unreadable":target.image.write_bytes(bytes(512))
        class Boot:
            def wait_ready(self, rid):
                if scenario.injection == "ended-boot":
                    self.proc.returncode = 7
                    raise RuntimeError("substitution boot ended before readiness")
                return {"fingerprint": FP}
            def stop(self):
                if self.proc.poll() is None:self.proc.kill()
            def wait_end(self):return self.proc.wait()
        boot = Boot(); boot.target = target; boot.name = name; boot.proc = Proc()
        boot.console = target.out / ("console-" + name + ".log")
        boot.stderr_path = target.out / ("qemu-" + name + ".err")
        worker = b"SSH LISTENING\n"
        boot.console.write_bytes(b"ABSD KERNEL BOOT\nRELEASE OK release=" + image_read(target.image)["selected"].encode()
            + b"\nEXTERNAL OUTPUT CHUNK offset=00000000 data=" + worker.hex().encode() + b"\n")
        boot.stderr_path.write_bytes(b"")
        boot.client = n.rel.smx.Client(target.out, port)
        self.current = boot
        return boot

    def ssh_run(self, argv, input, **kwargs):
        assert "SSH_AUTH_SOCK" not in kwargs["env"]
        assert "IdentityAgent=none" in argv and "ForwardAgent=no" in argv
        boot = self.current; command = argv[-1]; state = image_read(boot.target.image)
        rc, out, err = 0, b"", b""
        if command == "/bin/release":out = ("ABSD release=" + state["selected"] + "\n").encode()
        elif command.startswith("/bin/mkdir "):state["dirs"].append(command[len("/bin/mkdir "):])
        elif command.startswith("/bin/cat > "):state["files"][command[len("/bin/cat > "):]] = input.hex()
        elif command.startswith("/bin/cat "):
            path = command[len("/bin/cat "):]
            if path in state["files"]:out = bytes.fromhex(state["files"][path])
            else:rc, err = 1, ("cat: " + path + ": ABSD path not found\n").encode()
            if path == n.LATER and boot.target.out.name == "replacement-A":
                if self.injection == "RPO-marker":rc, out, err = 0, n.POST_POINT, b""
                if self.injection == "RPO-transport":rc, out, err = 255, b"", b"SSH transport refused\n"
            if path == n.NEW and "restart" in boot.name and self.injection == "new-write":out = b"wrong readback"
        elif command == "shutdown":
            state["files"][n.guard.PATH] = n.guard.encode("clean").hex(); boot.proc.returncode = 3
            out = b"going down for halt\n"
            if boot.name == "rollback-A-restart":
                if self.injection == "rollback-state":state["files"][n.DATA] = b"changed after readback".hex()
                for injection, name in (("original-final", "original-A"), ("failed-B-final", "refused-B")):
                    if self.injection == injection:
                        path = self.private / name / n.rel.IMAGE; changed = image_read(path)
                        changed["files"]["/var/substitution"] = b"changed".hex(); image_write(path, changed)
        image_write(boot.target.image, state)
        return subprocess.CompletedProcess(argv, rc, out, err)

    def cmd_install(self, args, log):
        target = Target(args.target)
        image_write(target.image, {"files": {n.guard.PATH: n.guard.encode("clean").hex(),
            "/ssh/host_ed25519_seed": SEED.hex(), "/etc/motd": b"fixture banner\n".hex()},
            "dirs": ["/home", "/home/operator", "/etc", "/ssh"], "selected": "rel-a"})
        target.release_iso("rel-a").parent.mkdir(parents=True)
        target.release_iso("rel-a").write_bytes(self.point_iso); target.iso.write_bytes(self.point_iso)

    def cmd_backup(self, args, log):
        point = Path(args.backup); point.mkdir(); self.point_image = Target(args.target).image.read_bytes()
        (point / n.rel.IMAGE).write_bytes(self.point_image); (point / "backup.toml").write_bytes(b"stub pinned metadata\n")
        boot = point / "releases/rel-a" / n.rel.ISO; boot.parent.mkdir(parents=True); boot.write_bytes(self.point_iso)

    def snapshot(self, args):
        point = Path(args.backup)
        return n.rp.Snapshot({"identity": {"host_key_fingerprint": FP}}, Target(point).tree(), "rel-a",
                             self.point_image, self.point_iso, args.recovery_point_sha256)

    def cmd_restore(self, args, log):
        point = Path(args.backup); target = Path(args.target)
        reason = None
        if args.recovery_point_sha256 is None:
            if self.injection == "legacy-accepted":return
            reason = "other_refusal" if self.injection == "legacy-reason" else "recovery_point_strict_required"
        elif (point / "backup.toml").read_bytes() != b"stub pinned metadata\n":reason = "recovery_point_pin_mismatch"
        elif (point / n.rel.IMAGE).stat().st_size != len(self.point_image):reason = "recovery_point_member_size"
        elif (point / n.rel.IMAGE).read_bytes() != self.point_image:reason = "recovery_point_image_digest"
        elif (point / "releases/rel-a" / n.rel.ISO).read_bytes() != self.point_iso:reason = "recovery_point_iso_digest"
        elif args.expected_release != "rel-a":reason = "recovery_point_release_mismatch"
        elif n.rel.image_holders(point / n.rel.IMAGE):reason = "image_in_use"
        elif target.exists() or target.is_symlink():
            reason = "other_refusal" if self.injection == "existing-target-reason" else "recovery_point_target_exists"
        if reason:
            if self.injection == "refusal-reason" and reason == "recovery_point_pin_mismatch":reason += "_suffix"
            raise n.rel.Failed(reason + ": local substitution refusal")
        target.mkdir(); (target / n.rel.IMAGE).write_bytes(self.point_image)
        boot = target / "releases/rel-a" / n.rel.ISO; boot.parent.mkdir(parents=True); boot.write_bytes(self.point_iso)
        (target / n.rel.ISO).write_bytes(self.point_iso)

    def cmd_stage(self, args, log):
        target = Target(args.target); boot = target.release_iso("rel-b"); boot.parent.mkdir(parents=True)
        boot.write_bytes(b"release-B-iso")

    def cmd_select(self, args, log):
        target = Target(args.target); state = image_read(target.image); state["selected"] = "rel-b"
        image_write(target.image, state); target.iso.write_bytes(b"release-B-iso")

    def cold(self, target, iso, name):
        if name == "B-selection-A-image-refused":
            state = image_read(target.image); state["files"][n.guard.PATH] = n.guard.encode("dirty").hex()
            image_write(target.image, state)
            reason = "wrong_reason" if self.injection == "P06-reason" else "release_mismatch"
            return b"ABSD KERNEL BOOT\nRELEASE REFUSED reason=" + reason.encode() + b"\n", "7"
        if self.injection == "fence-image":
            state = image_read(target.image); state["files"]["/var/substitution"] = b"changed".hex()
            image_write(target.image, state)
        previous = "not_ready" if target.out.name == "refused-B" else "failed"
        return (b"ABSD KERNEL BOOT\nSTORAGE FENCE fence=none reason=not_declared\n"
                + f"RECOVERY WRITABLE REFUSED reason=storage_fence previous={previous} fence=none\n".encode()
                + b"DURABLE status=1 block_writes=0 block_flushes=0 block_errors=0 ticks=1\n"), "7"

    def git_output(self, argv, **kwargs):
        if argv[0] == "ssh-keygen":return FP + " local fixture\n"
        if argv[-1] == "HEAD":return ("c" * 40 if self.injection == "source-binding" else B) + "\n"
        if argv[-1] == "--porcelain":return ""
        raise RuntimeError("unexpected subprocess in local flow fixture")

    def execute(self, focused=False):
        with ExitStack() as stack:
            for name, value in (("Target", Target), ("Release", self.release), ("Boot", self.boot),
                ("check_kernel", lambda *args: self.root / "kernel"), ("cmd_install", self.cmd_install),
                ("cmd_backup", self.cmd_backup), ("cmd_restore", self.cmd_restore), ("cmd_stage", self.cmd_stage),
                ("cmd_select", self.cmd_select), ("recovery_snapshot", self.snapshot)):
                stack.enter_context(mock.patch.object(n.rel, name, value))
            stack.enter_context(mock.patch.object(n, "inventory", inventory))
            stack.enter_context(mock.patch.object(n.subprocess, "run", self.ssh_run))
            stack.enter_context(mock.patch.object(n.subprocess, "check_output", self.git_output))
            stack.enter_context(mock.patch.object(n.Matrix, "cold", lambda matrix, *args: self.cold(*args)))
            matrix = n.Matrix(self.args)
            error = None
            try:
                if focused:
                    target = Target(matrix.work / "original-A"); self.cmd_install(n.Args(target=str(target.out)), print)
                    matrix.fenced(target, target.iso, "focused-cold", "failed")
                else:matrix.run()
            except Exception as problem:error = str(problem)
            if focused:return error is None, matrix, error
            passed = matrix.finish(error)
            return passed, matrix, error


class FlowControls(unittest.TestCase):
    def scenario(self, injection=None, focused=False):
        self.temp = tempfile.TemporaryDirectory(prefix="recovery-flow-"); self.addCleanup(self.temp.cleanup)
        return Scenario(Path(self.temp.name), injection).execute(focused)

    def rejected(self, injection, focused=False):
        passed, _, error = self.scenario(injection, focused)
        self.assertFalse(passed, "weakened Matrix accepted " + injection)
        self.assertIsNotNone(error)

    def test_fenced_method_detects_changed_image(self):self.rejected("fence-image", focused=True)
    def test_RPO_marker_observation(self):self.rejected("RPO-marker")
    def test_RPO_requires_cat_not_transport_failure(self):self.rejected("RPO-transport")
    def test_new_write_readback(self):self.rejected("new-write")
    def test_corrupt_controls_reason_token(self):self.rejected("refusal-reason")
    def test_P03_dirty_guard(self):self.rejected("dirty-guard")
    def test_P06_release_refusal(self):self.rejected("P06-reason")
    def test_P07_rollback_state(self):self.rejected("rollback-state")
    def test_P08_original_hash(self):self.rejected("original-final")
    def test_P08_failed_B_hash(self):self.rejected("failed-B-final")
    def test_exact_oracle_source_binding(self):self.rejected("source-binding")
    def test_old_kernel_refused(self):
        passed, _, error = self.scenario("old-kernel")
        self.assertFalse(passed)
        self.assertEqual(error, "kernel differs from the dispatched base")

    def test_previous_kernel_refused(self):
        passed, _, error = self.scenario("previous-kernel")
        self.assertFalse(passed)
        self.assertEqual(error, "kernel differs from the dispatched base")

    def test_other_kernel_refused(self):
        passed, _, error = self.scenario("wrong-kernel")
        self.assertFalse(passed)
        self.assertEqual(error, "kernel differs from the dispatched base")

    def test_ancestry_pin_binding(self):self.rejected("ancestry-pin")
    def test_legacy_refusal_reason(self):self.rejected("legacy-reason")
    def test_legacy_unexpected_acceptance(self):self.rejected("legacy-accepted")
    def test_existing_target_refusal_reason(self):self.rejected("existing-target-reason")
    def test_post_stop_marker_check(self):self.rejected("post-stop-marker")

    def test_post_stop_unreadable_is_recorded(self):
        passed, matrix, _ = self.scenario("post-stop-unreadable")
        self.assertFalse(passed)
        receipt = matrix.evidence / "original-post-stop-inventory.json"
        self.assertTrue(receipt.exists())
        self.assertEqual(json.loads(receipt.read_text())["disposition"], "UNREADABLE")

    def test_ended_failed_boot_is_captured(self):
        passed, matrix, _ = self.scenario("ended-boot")
        self.assertFalse(passed)
        self.assertTrue((matrix.evidence / "console-source-point.log").exists())
        self.assertTrue((matrix.evidence / "qemu-source-point.err").exists())

    def test_public_inventory_omits_private_content_digests(self):
        private = {"/ssh/host_ed25519_seed": {"kind": "file", "bytes": 32, "sha256": "private"},
                   "/home/state": {"kind": "file", "bytes": 1, "sha256": "public-fixture"}}
        public = n.public_inventory(private)
        self.assertNotIn("sha256", public["/ssh/host_ed25519_seed"])
        self.assertEqual(public["/home/state"]["sha256"], "public-fixture")

    def test_full_stubbed_sequence_and_guest_difference(self):
        passed, matrix, error = self.scenario()
        self.assertTrue(passed, error)
        result = json.loads((matrix.evidence / "RESULT.json").read_text())
        self.assertEqual([row["case"] for row in result["rows"]], list(n.REQUIRED))
        self.assertTrue(result["rows"][0]["detail"].get("guest_difference", {}).get("changed_tree_files"))


MUTATIONS = {
    "test_fenced_method_detects_changed_image": ("fenced", 'n/a'),
    "test_RPO_marker_observation": ("durable_service", 'RPO'),
    "test_RPO_requires_cat_not_transport_failure": ("durable_service", 'RPO'),
    "test_new_write_readback": ("durable_service", 'new-write'),
    "test_corrupt_controls_reason_token": ("corrupt_controls", 'reason'),
    "test_P03_dirty_guard": ("run", 'dirty'),
    "test_P06_release_refusal": ("run", 'P06'),
    "test_P07_rollback_state": ("durable_service", 'state'),
    "test_P08_original_hash": ("run", 'original'),
    "test_P08_failed_B_hash": ("run", 'failed-B'),
    "test_exact_oracle_source_binding": ("run", 'source'),
    "test_ancestry_pin_binding": ("run", 'ancestry'),
    "test_legacy_refusal_reason": ("run", 'legacy-reason'),
    "test_legacy_unexpected_acceptance": ("run", 'legacy-accepted'),
    "test_existing_target_refusal_reason": ("run", 'existing-reason'),
    "test_post_stop_marker_check": ("run", 'post-marker'),
    "test_post_stop_unreadable_is_recorded": ("run", 'unreadable-receipt'),
    "test_ended_failed_boot_is_captured": ("finish", 'capture'),
    "test_public_inventory_omits_private_content_digests": (None, 'private'),
    "test_full_stubbed_sequence_and_guest_difference": (None, 'difference'),
}


def mutant(method, change):
    if method is None:
        name = "public_inventory" if change == "private" else "guest_difference"
        return mock.patch.object(n, name, (lambda state: state) if change == "private" else lambda *args: {})
    before, after = {
        "n/a": ('n.rel.sha256_file(target.image) == before', 'True'),
        "RPO": ('missing_status == 1 and missing_out == b"" and missing_line in missing_err.splitlines()', 'True'),
        "new-write": ('actual == value', 'True'),
        "reason": ('require_reason(error, reason)', 'None'),
        "dirty": ('guard.parse(original.tree().get(guard.PATH)) == "dirty"', 'True'),
        "P06": ('re.search(r"(?m)^RELEASE REFUSED reason=release_mismatch$", serial)', 'True'),
        "state": ('require_state(inventory(target.image), expected)', 'None'),
        "original": ('rel.sha256_file(original.image) == self.original_hash', 'True'),
        "failed-B": ('rel.sha256_file(failed.image) == self.failed_hash', 'True'),
        "source": ('own == self.args.source_b', 'True'),
        "ancestry": ('sha(ancestry_bytes) == self.args.ancestry_sha256', 'True'),
        "legacy-reason": ('require_reason(error, "recovery_point_strict_required")', 'None'),
        "legacy-accepted": ('raise RuntimeError("legacy restore accepted a pinned point over the fenced original")', 'pass'),
        "existing-reason": ('require_reason(error, "recovery_point_target_exists")', 'None'),
        "post-marker": ('marker == {"kind": "file", "bytes": len(POST_POINT), "sha256": sha(POST_POINT)}', 'True'),
        "unreadable-receipt": ('self.json("original-post-stop-inventory.json", {"disposition": "UNREADABLE", "error": str(error)})', 'None'),
        "capture": ('self.capture_boot(boot)', 'None'),
    }[change]
    if change == 'n/a':before = before.replace('n.rel.', 'rel.')
    source = textwrap.dedent(inspect.getsource(getattr(n.Matrix, method)))
    if before not in source:raise RuntimeError("mutant source no longer matches " + change)
    scope = {}; exec(compile(source.replace(before, after), '<disabled Matrix check>', 'exec'), n.__dict__, scope)
    return mock.patch.object(n.Matrix, method, scope[method])


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--output'); args = ap.parse_args()
    log = io.StringIO()
    with mock.patch('sys.stdout', log):
        normal = unittest.TextTestRunner(stream=log).run(unittest.defaultTestLoader.loadTestsFromTestCase(FlowControls))
    rows = []
    for name, (method, change) in MUTATIONS.items():
        stream = io.StringIO()
        try:
            with mutant(method, change), mock.patch('sys.stdout', stream):
                result = unittest.TextTestRunner(stream=stream).run(unittest.TestSuite([FlowControls(name)]))
            row = dict(test=name, mutant=change, killed=bool(result.failures) and not result.errors,
                       failures=len(result.failures), errors=len(result.errors), diagnostic=stream.getvalue()[-2000:])
        except Exception as error:row = dict(test=name, mutant=change, killed=False, harness_error=str(error))
        rows.append(row)
    passed = normal.wasSuccessful() and all(row['killed'] for row in rows)
    result = dict(schema_version=1, disposition='PASS' if passed else 'FAIL', controls=normal.testsRun,
                  normal_log=log.getvalue(), mutants=rows, scope='Stubbed Matrix control flow; no native execution or acceptance.')
    if args.output:
        with Path(args.output).open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(disposition=result['disposition'],controls=normal.testsRun,mutants_killed=sum(r['killed'] for r in rows))))
    if not passed:
        print(log.getvalue())
        for row in rows:
            if not row['killed']:print(json.dumps(row))
    return 0 if passed else 1


if __name__ == '__main__':raise SystemExit(main())
