#!/usr/bin/env python3
"""Native replacement-and-restore qualification on disposable VM storage.

Both release directories must be complete, independently pinned inputs. A is
the earlier source; B is a distinct later platform revision with the same
kernel ABI. This runner never generates credentials, resets a guard, exports
an image, reuses a destination, or accepts an incomplete case set as success.
The caller owns durable execution, the collector and bounded VM retirement.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import absd_fs
import recovery_point as rp
import storage_fence_guest as fence
import storage_fence_state as guard
from served_ram import served_qemu

spec = importlib.util.spec_from_file_location("release_recovery_native", HERE / "release.py")
rel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rel)

REQUIRED = ("P00-inputs", "P01-clean-point", "P02-corrupt-refusals",
            "P03-original-fenced", "P04-A-recovered-durable", "P05-B-updated-durable",
            "P06-B-refused-fenced", "P07-fresh-A-rollback-durable", "P08-fences-retained")
DATA = "/home/operator/p2/state.bin"
EMPTY = "/home/operator/p2/empty"
LATER = "/home/operator/p2/post-point.bin"
NEW = "/home/operator/p2/new-write.bin"
STATE = bytes(range(256)) * 17 + b"\0point-A\xff\n"
POST_POINT = b"committed after the last recovery point; explicitly outside RPO\n"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_identity(path):
    path = Path(path)
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": rel.sha256_file(path)}


def require_ready(raw, ready, release_id, fingerprint):
    serial = raw.decode(errors="replace")
    worker = fence.captured_complete(raw)
    require(raw.count(b"ABSD KERNEL BOOT\n") == 1, "readiness needs exactly one boot")
    require(len(re.findall(rf"(?m)^RELEASE OK release={re.escape(release_id)}(?: |$)", serial)) == 1,
            "readiness lacks the exact expected release")
    require("SSH LISTENING" in worker, "readiness lacks the SSH listener")
    require(ready.get("fingerprint") == fingerprint, "replacement host fingerprint differs from the point")
    require("MACHINE RECOVER RESET" not in serial, "readiness crossed a machine reset")


def require_halt(raw, status, ssh_status, stdout):
    serial = raw.decode(errors="replace")
    fence.captured_complete(raw)
    require(status == 3 and ssh_status == 0 and b"going down for halt" in stdout,
            "shutdown did not complete an orderly halt")
    require(raw.count(b"ABSD KERNEL BOOT\n") == 1, "halt crossed a machine reset")
    require("SERVED SHUTDOWN ESCALATED" not in serial and "SERVED RECOVERY" not in serial,
            "halt used escalation or recovery")


def require_state(found, expected):
    differences = sorted(p for p in set(found) | set(expected) if found.get(p) != expected.get(p))
    require(not differences, "declared state differs at " + ", ".join(differences[:16]))


def require_reason(error, code):
    require(re.match(rf"^{re.escape(code)}(?=:|\s|$)", str(error)) is not None,
            f"wrong named refusal: expected {code}: {error}")


def public_inventory(state):
    # /ssh content digests stay private. Exact internal comparison still
    # covers them; the independently pinned public host fingerprint is public.
    return {path: {k: v for k, v in record.items()
                   if k != "sha256" or not (path == "/ssh" or path.startswith("/ssh/"))}
            for path, record in state.items()}


def binary_change(A, B, name):
    require(re.fullmatch(r"tree/bin/[a-z0-9][a-z0-9._-]*", name) is not None,
            "required binary must name one release tree/bin executable")
    identities = []
    for release in (A, B):
        declared = release.artifact_digests().get(name)
        path = release.path / name
        if declared is None:
            require(not path.exists(), "unrecorded required binary exists")
            identities.append(None)
            continue
        data = path.read_bytes()
        require(data.startswith(b"\x7fELF"), "required binary is not ELF")
        require(sha(data) == declared, "required binary differs from its manifest")
        identities.append({"sha256": sha(data), "bytes": len(data)})
    require(identities[1] is not None, "required B binary is absent")
    require(identities[0] != identities[1], "required binary did not change")
    return {"path": name, "A": identities[0], "B": identities[1],
            "scope": "Manifest-verified ELF bytes supplied to the existing verified install/stage path; execution is qualified separately."}


def installed_binary(target, release, name):
    tree = target.tree()
    require(target.selected(tree) == release.id, "required binary release is not selected")
    physical = f"/releases/{release.id}/{name[len('tree/'):]}"
    data = tree.get(physical)
    require(isinstance(data, bytes) and data.startswith(b"\x7fELF"), "selected binary is absent or not ELF")
    require(sha(data) == release.artifact_digests().get(name), "selected binary differs from B manifest")
    return {"selected_release": release.id, "logical_path": name[len('tree'):],
            "physical_path": physical, "sha256": sha(data), "bytes": len(data)}


def guest_difference(A, B, required_binary=None):
    trees = [{name: value for name, value in release.artifact_digests().items()
              if name.startswith("tree/")} for release in (A, B)]
    require(all(trees), "manifest guest trees are missing")
    result = {"A_tree_sha256": sha(json.dumps(trees[0], sort_keys=True).encode()),
            "B_tree_sha256": sha(json.dumps(trees[1], sort_keys=True).encode()),
            "changed_tree_files": sorted(name for name in set(trees[0]) | set(trees[1])
                                         if trees[0].get(name) != trees[1].get(name)),
            "scope": "Release ID rebuild only in the guest; this exercises stage/select/rollback, not a guest content update."}
    if required_binary is not None:
        result["binary_change"] = binary_change(A, B, required_binary)
        result["scope"] = "Different manifest-verified guest ELF content; internal A baseline, not a published RC1 upgrade."
    return result


def terminal_result(rows, error=None):
    complete = (tuple(row["case"] for row in rows) == REQUIRED
                and all(row.get("verdict") == "PASS" for row in rows))
    return {"schema_version": 1, "disposition": "PASS" if complete and error is None else "FAIL_OR_INCOMPLETE",
            "required_cases": list(REQUIRED), "rows": rows, "error": error}


def destination_snapshot(path):
    if not path.exists():
        return None
    result = {}
    for entry in [path, *sorted(path.rglob("*"))]:
        st = entry.lstat()
        result[str(entry.relative_to(path))] = [st.st_mode, st.st_ino, st.st_mtime_ns,
            st.st_ctime_ns, rel.sha256_file(entry) if entry.is_file() else None]
    return result


def inventory(image):
    region = absd_fs.fs_region(image, rel.oi.DEVICE_SECTORS)
    require(region is not None, "declared state has no filesystem region")
    fs = absd_fs.select(region)
    require(fs is not None, "declared state has no committed filesystem")
    result = {}
    for path, record in absd_fs.tree(region, fs).items():
        if any(path == root or path.startswith(root + "/") for root in rp.STATE_ROOTS):
            result[path] = ({"kind": "directory"} if record["dir"] else
                            {"kind": "file", "bytes": record["size"],
                             "sha256": sha(absd_fs.content(region, fs, record))})
    return result


class Args:
    def __init__(self, **values):
        self.__dict__.update(values)

    def __getattr__(self, name):
        return None


class Matrix:
    def __init__(self, args):
        self.args = args
        self.work = Path(args.private_work).resolve()
        self.evidence = Path(args.evidence).resolve()
        require(self.work != self.evidence and self.work not in self.evidence.parents
                and self.evidence not in self.work.parents, "private work and public evidence must be separate")
        self.work.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.rows, self.boots, self.events = [], [], 0
        self.key = Path(args.key).resolve()
        self.A, self.B = rel.Release(args.release_a), rel.Release(args.release_b)
        self.kernel = rel.check_kernel(args.kernel, self.A)
        rel.check_kernel(args.kernel, self.B)
        self.point = self.work / "point-A"
        self.pin, self.fingerprint, self.public_key = None, None, None
        self.base_state, self.original_hash, self.failed_hash = None, None, None
        self.original_run_boot = rel.run_boot

    def save(self, name, data):
        path = self.evidence / name
        with path.open("xb") as stream:
            stream.write(data)
        return file_identity(path)

    def json(self, name, data):
        return self.save(name, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode())

    def event(self, kind, detail):
        self.events += 1
        return self.json(f"event-{self.events:04d}-{kind}.json", detail)

    def mark(self, case, detail):
        require(case == REQUIRED[len(self.rows)], "native cases completed out of order")
        self.rows.append({"case": case, "verdict": "PASS", "detail": detail})
        self.event("case", self.rows[-1])
        print(f"RECOVERY NATIVE PASS {case}", flush=True)

    def tool(self, func, **values):
        lines = []
        try:
            func(Args(**values), log=lines.append)
        except BaseException as error:
            self.event("tool", {"command": func.__name__, "arguments": values,
                                "lines": lines, "outcome": "REFUSED_OR_INCOMPLETE", "error": str(error)})
            raise
        self.event("tool", {"command": func.__name__, "arguments": values, "lines": lines, "outcome": "COMPLETED"})
        return lines

    def traced_importer_boot(self, script, iso, image, serial):
        """Copy the existing boot's raw output before its temporary dir ends.

        The original launcher and every original acceptance predicate stay
        in place. A failed or interrupted call is never turned into success.
        """
        status = None
        try:
            status = self.original_run_boot(script, iso, image, serial)
            return status
        finally:
            self.events += 1
            name = f"importer-{self.events:04d}"
            raw = self.save(name + ".serial.log", Path(serial).read_bytes()) if Path(serial).is_file() else None
            self.json(name + ".json", {"script": str(script), "iso": file_identity(iso),
                                       "image": str(image), "status": status, "raw": raw})

    def ssh(self, boot, command, data=b"", allow_failure=False):
        # Pin one exact campaign identity; never use an inherited agent.
        env = dict(os.environ)
        env.pop("SSH_AUTH_SOCK", None)
        argv = boot.client.base(self.key, ("-o", "IdentityAgent=none", "-o", "ForwardAgent=no",
                                          "-o", "User=operator", "-T")) + [command]
        p = subprocess.run(argv, input=data, capture_output=True, timeout=120, env=env)
        self.events += 1
        prefix = f"ssh-{self.events:04d}"
        out = self.save(prefix + ".stdout", p.stdout)
        err = self.save(prefix + ".stderr", p.stderr)
        self.json(prefix + ".json", {"command": command, "stdin_bytes": len(data), "stdin_sha256": sha(data),
                                      "exit_code": p.returncode, "stdout": out, "stderr": err})
        require(allow_failure or p.returncode == 0, f"SSH command failed: {command}: status={p.returncode}")
        return p.returncode, p.stdout, p.stderr

    def start(self, target, name, release_id, initial=False):
        require(not any(b.proc.poll() is None for b in self.boots), "previous execution has not retired")
        boot = rel.Boot(target, target.iso, name, self.args.port)
        self.boots.append(boot)
        ready = boot.wait_ready(release_id)
        if initial:
            # The source's initial identity is subsequently independently
            # checked from its clean halted point, before any restore.
            self.fingerprint = ready["fingerprint"]
        require_ready(boot.console.read_bytes(), ready, release_id, self.fingerprint)
        if self.public_key:
            boot.client.trust(self.public_key)
        _, output, _ = self.ssh(boot, "/bin/release")
        require(re.search(rf"(?:^|\s)release={re.escape(release_id)}(?:\s|$)", output.decode(errors="replace")),
                "served /bin/release does not name the selected release")
        self.event("ready", {"name": name, "release": release_id, "fingerprint": ready["fingerprint"]})
        return boot

    def capture_boot(self, boot):
        require(boot.proc.poll() is not None, "cannot seal a live boot capture")
        for path in (boot.console, boot.stderr_path):
            data = path.read_bytes() if path.exists() else b""
            captured = self.evidence / path.name
            if captured.exists():
                require(captured.read_bytes() == data, "sealed boot capture changed")
            else:
                self.save(path.name, data)

    def halt(self, boot):
        status, output, _ = self.ssh(boot, "shutdown", allow_failure=True)
        ended = boot.wait_end()
        self.capture_boot(boot)
        require_halt(boot.console.read_bytes(), ended, status, output)
        require(guard.parse(boot.target.tree().get(guard.PATH)) == "clean", "orderly halt did not leave a clean guard")

    def cold(self, target, iso, name):
        require(not any(b.proc.poll() is None for b in self.boots), "cold boot overlaps an earlier execution")
        log = self.evidence / (name + ".serial.log")
        require(not log.exists(), "cold boot capture already exists")
        env = dict(os.environ, ABSD_BLOCK_ATTACH="ata")
        env.pop("ABSD_QEMU_REBOOT", None)
        guest, port = rel.oi.endpoint(target.image)
        net = ".".join(guest.split(".")[:3]) + ".0/24"
        argv = [str(self.kernel / "scripts/durable-boot.sh"), str(iso), str(target.image), str(log), "300",
                *served_qemu(rel.QEMU), "-netdev", f"user,id=n0,net={net}", "-device", "e1000,netdev=n0"]
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, start_new_session=True)
        try:
            out, err = proc.communicate(timeout=360)
        except BaseException:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
            out, err = proc.communicate()
            self.save(name + ".stdout", out)
            self.save(name + ".stderr", err)
            self.event("cold-interrupted", {"name": name, "wrapper_status": proc.returncode})
            raise
        self.save(name + ".stdout", out)
        self.save(name + ".stderr", err)
        self.event("cold", {"name": name, "wrapper_status": proc.returncode, "status": out.decode(errors="replace").strip()})
        require(proc.returncode == 0, "cold wrapper did not complete normally")
        return log.read_bytes(), out.decode().strip()

    def fenced(self, target, iso, name, previous):
        before = rel.sha256_file(target.image)
        raw, status = self.cold(target, iso, name)
        line = fence.require_refusal(raw, status, previous=previous)
        require(rel.sha256_file(target.image) == before, "fenced boot changed the original image")
        return {"refusal": line, "image_sha256": before, "writes": 0, "flushes": 0}

    def restore(self, name):
        target = rel.Target(self.work / name)
        self.tool(rel.cmd_restore, target=str(target.out), backup=str(self.point),
                  recovery_point_sha256=self.pin, expected_release=self.A.id)
        require(rel.sha256_file(target.image) == rel.sha256_file(self.point / rel.IMAGE), "restore differs from the point")
        require_state(inventory(target.image), self.base_state)
        return target

    def durable_service(self, target, name, release_id):
        value = (name + ": a new write after replacement\n").encode() + bytes(range(256)) + b"\0\xff"
        boot = self.start(target, name + "-first", release_id)
        _, actual, _ = self.ssh(boot, "/bin/cat " + DATA)
        require(actual == STATE, "served declared state differs from the recovery point")
        self.ssh(boot, "/bin/ls " + EMPTY)
        missing_status, missing_out, missing_err = self.ssh(boot, "/bin/cat " + LATER, allow_failure=True)
        missing_line = ("cat: " + LATER + ": ABSD path not found").encode()
        require(missing_status == 1 and missing_out == b"" and missing_line in missing_err.splitlines(),
                "RPO absence lacks cat's own not-found result")
        self.ssh(boot, "/bin/cat > " + NEW, value)
        self.ssh(boot, "/bin/sync")
        self.halt(boot)
        expected = dict(self.base_state)
        expected[NEW] = {"kind": "file", "bytes": len(value), "sha256": sha(value)}
        require_state(inventory(target.image), expected)
        boot = self.start(target, name + "-restart", release_id)
        _, actual, _ = self.ssh(boot, "/bin/cat " + NEW)
        require(actual == value, "new write did not survive clean restart")
        _, state, _ = self.ssh(boot, "/bin/cat " + DATA)
        require(state == STATE, "declared state changed across restart")
        self.halt(boot)
        require_state(inventory(target.image), expected)
        receipt = self.json(name + "-inventory.json", public_inventory(expected))
        return {"release": release_id, "state_inventory": receipt, "new_write_sha256": sha(value),
                "new_write_restart": True, "post_point_marker_absent": True, "fingerprint": self.fingerprint}

    def corrupt_controls(self):
        rows = []
        for name, reason in (("metadata", "recovery_point_pin_mismatch"),
                             ("disk", "recovery_point_image_digest"),
                             ("truncated", "recovery_point_member_size"),
                             ("iso", "recovery_point_iso_digest"),
                             ("wrong-release", "recovery_point_release_mismatch"),
                             ("holder", "image_in_use")):
            with tempfile.TemporaryDirectory(prefix="negative-", dir=self.work) as tmp:
                tmp = Path(tmp)
                point = tmp / "point"
                shutil.copytree(self.point, point)
                if name == "metadata":
                    with (point / "backup.toml").open("a") as f:
                        f.write("\n# deterministic metadata substitution\n")
                if name == "disk":
                    with (point / rel.IMAGE).open("r+b") as f:
                        f.seek(512); b = f.read(1); f.seek(512); f.write(bytes([b[0] ^ 1]))
                if name == "truncated":
                    with (point / rel.IMAGE).open("r+b") as f:
                        f.truncate(512)
                if name == "iso":
                    with (point / "releases" / self.A.id / rel.ISO).open("r+b") as f:
                        b = f.read(1); f.seek(0); f.write(bytes([b[0] ^ 1]))
                held = (point / rel.IMAGE).open("rb") if name == "holder" else None
                try:
                    for sentinel in (False, True):
                        target = tmp / ("existing" if sentinel else "absent")
                        if sentinel:
                            target.mkdir(); (target / "sentinel").write_bytes(b"unchanged destination\n")
                        before = destination_snapshot(target)
                        try:
                            self.tool(rel.cmd_restore, target=str(target), backup=str(point),
                                      recovery_point_sha256=self.pin,
                                      expected_release=self.B.id if name == "wrong-release" else self.A.id)
                        except rel.Failed as error:
                            require_reason(error, reason)
                        else:
                            raise RuntimeError(f"{name}: invalid point was admitted")
                        require(destination_snapshot(target) == before, f"{name}: refusal changed the destination")
                    rows.append({"name": name, "reason": reason, "absent_and_existing_unchanged": True})
                finally:
                    if held:
                        held.close()
        return rows

    def run(self):
        require(self.key.is_file() and self.key.with_suffix(".pub").is_file(), "exact campaign key pair is required")
        require(self.A.id != self.B.id, "A and B must have distinct release identities")
        own = subprocess.check_output(["git", "-C", str(HERE.parent), "rev-parse", "HEAD"], text=True).strip()
        require(own == self.args.source_b and not subprocess.check_output(
            ["git", "-C", str(HERE.parent), "status", "--porcelain"], text=True),
            "oracle must execute from the exact clean B source revision")
        ancestry_bytes = Path(self.args.ancestry).read_bytes()
        require(sha(ancestry_bytes) == self.args.ancestry_sha256, "source ancestry input differs from its independent pin")
        ancestry = json.loads(ancestry_bytes)
        require(ancestry.get("schema") == "p2-source-ancestry/1" and ancestry.get("A") == self.args.source_a
                and ancestry.get("B") == self.args.source_b and ancestry.get("command") == "git merge-base --is-ancestor"
                and type(ancestry.get("exit_code")) is int and ancestry["exit_code"] == 0,
                "missing recorded A-to-B ancestry evidence")
        self.save("source-ancestry.json", ancestry_bytes)
        sources = []
        for release, expected in ((self.A, self.args.source_a), (self.B, self.args.source_b)):
            manifest = release._manifest_doc()
            require(manifest["source"].get("platform_commit") == expected,
                    "release manifest differs from independently supplied platform revision")
            require(manifest["source"].get("platform_tree_clean") is True
                    and manifest["source"].get("kernel_tree_clean") is True,
                    "release inputs were not built from clean source trees")
            sources.append({"release": release.id, "platform_revision": expected,
                            "kernel_revision": release.kernel_commit(), "manifest": file_identity(release.manifest)})
            self.save("release-" + release.id + "-manifest.toml", release.manifest.read_bytes())
        require(self.args.source_a != self.args.source_b, "the update must name a later distinct source revision")
        require(self.args.source_a == "03479a3e090e847ccdfa647dce44e7b16d035988", "A differs from the dispatched base")
        require(self.A.kernel_commit() == "101c61d82534b8c25b7295eb5a2fcd0e72cc5b3a", "kernel differs from the dispatched base")
        self.mark("P00-inputs", {"sources": sources, "oracle": file_identity(__file__),
                                "guest_difference": guest_difference(self.A, self.B, getattr(self.args, "require_binary_change", None)),
                                "ancestry_sha256": self.args.ancestry_sha256,
                                "credential_fingerprint": subprocess.check_output(
                                    ["ssh-keygen", "-lf", str(self.key.with_suffix(".pub"))], text=True).strip()})
        original = rel.Target(self.work / "original-A")
        self.tool(rel.cmd_install, release=str(self.A.path), kernel=str(self.kernel), target=str(original.out),
                  target_identity="p2-replacement-machine")
        boot = self.start(original, "source-point", self.A.id, initial=True)
        self.ssh(boot, "/bin/mkdir /home/operator/p2")
        self.ssh(boot, "/bin/mkdir " + EMPTY)
        self.ssh(boot, "/bin/cat > " + DATA, STATE)
        self.ssh(boot, "/bin/sync")
        self.halt(boot)
        self.base_state = inventory(original.image)
        require(DATA in self.base_state and self.base_state.get(EMPTY) == {"kind": "directory"},
                "source point lacks the declared fixture state or empty directory")
        self.tool(rel.cmd_backup, target=str(original.out), backup=str(self.point), recovery_point=True)
        self.pin = rel.sha256_file(self.point / "backup.toml")
        point = rel.recovery_snapshot(Args(backup=str(self.point), recovery_point_sha256=self.pin,
                                            expected_release=self.A.id))
        require(point.metadata["identity"]["host_key_fingerprint"] == self.fingerprint,
                "independent point fingerprint differs from initial served identity")
        seed = point.tree["/ssh/host_ed25519_seed"]
        self.public_key = "ssh-ed25519 " + base64.b64encode(rel.host_key_blob(seed)).decode()
        self.json("point-A-pin.json", {"metadata_sha256": self.pin, "source_release": self.A.id,
                                      "host_fingerprint": self.fingerprint,
                                      "RPO": "last clean halted point; every subsequent write may be lost"})
        inv = self.json("point-A-inventory.json", public_inventory(self.base_state))
        self.mark("P01-clean-point", {"pin": self.pin, "inventory": inv})
        self.mark("P02-corrupt-refusals", self.corrupt_controls())

        boot = self.start(original, "original-after-point", self.A.id)
        self.ssh(boot, "/bin/cat > " + LATER, POST_POINT)
        self.ssh(boot, "/bin/sync")
        _, actual, _ = self.ssh(boot, "/bin/cat " + LATER)
        require(actual == POST_POINT, "post-point write was not committed and read before the unclean stop")
        if getattr(self.args, "bound_qemu", None):
            import p2_boot_binding
            p2_boot_binding.kill_served(boot.proc.pid, boot.console, self.evidence / "boot-bindings")
        else:
            boot.proc.kill()
        require(boot.proc.wait(timeout=30) == -signal.SIGKILL, "original did not stop uncleanly")
        self.capture_boot(boot)
        try:
            post_stop = inventory(original.image)
        except (absd_fs.Refused, ValueError, OSError, RuntimeError, AttributeError) as error:
            self.json("original-post-stop-inventory.json", {"disposition": "UNREADABLE", "error": str(error)})
        else:
            marker = post_stop.get(LATER)
            self.json("original-post-stop-inventory.json", {"disposition": "READABLE",
                      "inventory": public_inventory(post_stop), "post_point_marker": marker})
            require(marker == {"kind": "file", "bytes": len(POST_POINT), "sha256": sha(POST_POINT)},
                    "committed post-point marker is absent or changed after SIGKILL")
        require(guard.parse(original.tree().get(guard.PATH)) == "dirty", "unclean original is not fenced dirty")
        self.original_hash = rel.sha256_file(original.image)
        self.mark("P03-original-fenced", self.fenced(original, original.iso, "original-cold-refused", "failed"))
        before = destination_snapshot(original.out)
        try:
            self.tool(rel.cmd_restore, target=str(original.out), backup=str(self.point), replace=True)
        except rel.Failed as error:
            require_reason(error, "recovery_point_strict_required")
        else:
            raise RuntimeError("legacy restore accepted a pinned point over the fenced original")
        require(destination_snapshot(original.out) == before, "legacy refusal changed the fenced original")
        for name, symlink in (("existing-target", False), ("symlink-target", True)):
            target = self.work / name
            if symlink:
                target.symlink_to(original.out, target_is_directory=True)
            else:
                target.mkdir(); (target / "sentinel").write_bytes(b"keep\n")
            before = destination_snapshot(target)
            try:
                self.tool(rel.cmd_restore, target=str(target), backup=str(self.point),
                          recovery_point_sha256=self.pin, expected_release=self.A.id)
            except rel.Failed as error:
                require_reason(error, "recovery_point_target_exists")
            else:
                raise RuntimeError("strict restore reused an existing or symlinked target")
            require(destination_snapshot(target) == before, "existing-target refusal changed its destination")

        recovered = self.restore("replacement-A")
        self.mark("P04-A-recovered-durable", self.durable_service(recovered, "recovered-A", self.A.id))
        # Each previous clean execution has ended before the next copy serves.
        updated = self.restore("replacement-B")
        self.tool(rel.cmd_stage, release=str(self.B.path), kernel=str(self.kernel), target=str(updated.out))
        self.tool(rel.cmd_select, release=str(self.B.path), kernel=str(self.kernel), target=str(updated.out))
        require_state(inventory(updated.image), self.base_state)
        required_binary = getattr(self.args, "require_binary_change", None)
        if required_binary:
            self.json("updated-B-installed-binary.json", installed_binary(updated, self.B, required_binary))
        self.mark("P05-B-updated-durable", self.durable_service(updated, "updated-B", self.B.id))

        failed = self.restore("refused-B")
        self.tool(rel.cmd_stage, release=str(self.B.path), kernel=str(self.kernel), target=str(failed.out))
        self.tool(rel.cmd_select, release=str(self.B.path), kernel=str(self.kernel), target=str(failed.out))
        raw, status = self.cold(failed, failed.release_iso(self.A.id), "B-selection-A-image-refused")
        serial = raw.decode(errors="replace")
        require(status == "7" and raw.count(b"ABSD KERNEL BOOT\n") == 1
                and re.search(r"(?m)^RELEASE REFUSED reason=release_mismatch$", serial),
                "deterministic B startup mismatch was not refused once")
        require("SSH LISTENING" not in fence.captured_complete(raw) and "MACHINE RECOVER RESET" not in serial,
                "mismatched B generation served or reset")
        self.failed_hash = rel.sha256_file(failed.image)
        self.mark("P06-B-refused-fenced", self.fenced(failed, failed.iso, "failed-B-cold-refused", "not_ready"))
        rollback = self.restore("fresh-rollback-A")
        self.mark("P07-fresh-A-rollback-durable", self.durable_service(rollback, "rollback-A", self.A.id))
        require(rel.sha256_file(original.image) == self.original_hash, "original changed during replacements")
        require(rel.sha256_file(failed.image) == self.failed_hash, "failed B changed during fresh rollback")
        final_fence = self.fenced(original, original.iso, "original-final-refused", "failed")
        require(rel.sha256_file(original.image) == self.original_hash, "final fence changed original")
        self.mark("P08-fences-retained", {"original": final_fence, "failed_B_image_sha256": self.failed_hash,
                                         "rollback_destination_distinct": True})

    def finish(self, error=None):
        for boot in self.boots:
            if boot.proc.poll() is None:
                boot.stop()
                self.event("aborted-owned-boot", {"console": str(boot.console), "status": boot.proc.returncode})
            self.capture_boot(boot)
        result = terminal_result(self.rows, error)
        result.update({"RPO": "the independently pinned last clean halted A point",
                       "limits": ["Operator retires old executions; no global duplicate-copy detection.",
                                  "No in-place writable recovery, guard reset, format conversion or kernel ABI change.",
                                  "No physical host power-loss or live kernel replacement claim.",
                                  "Refused B uses the existing deterministic selection/image mismatch fixture.",
                                  ("B contains the explicitly required different ELF; application-state lifecycle is qualified separately."
                                   if getattr(self.args, "require_binary_change", None) else
                                   "B changes the guest release ID only; no guest content update is qualified."),
                                  "Private images and runtime credentials are VM-local; collector retains public raw results."]})
        if getattr(self.args, "bound_qemu", None):
            import p2_boot_binding
            try:
                result["bound_launch_count"] = p2_boot_binding.terminal_bindings(self.evidence / "boot-bindings",
                    self.args.bound_qemu_sha256, {self.args.release_a_manifest_sha256, self.args.release_b_manifest_sha256})
            except (ValueError, OSError, KeyError) as failure:
                result["disposition"] = "FAIL"
                result["binding_error"] = str(failure)
        self.json("RESULT.json", result)
        self.json("PUBLIC-ARTIFACTS.json", {"schema_version": 1, "artifacts": [
            file_identity(path) for path in sorted(self.evidence.rglob("*")) if path.is_file()]})
        return result["disposition"] == "PASS"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("release-a", "release-b", "source-a", "source-b", "ancestry", "ancestry-sha256",
                 "kernel", "key", "private-work", "evidence"):
        ap.add_argument("--" + name, required=True)
    ap.add_argument("--require-binary-change", help="require a changed manifest-verified tree/bin ELF in B")
    ap.add_argument("--bound-qemu", type=Path, help="exact canonical IDE qualification QEMU executable")
    ap.add_argument("--bound-qemu-sha256")
    ap.add_argument("--release-a-manifest-sha256")
    ap.add_argument("--release-b-manifest-sha256")
    ap.add_argument("--port", type=int, default=2237)
    args = ap.parse_args()
    require(not sys.flags.optimize, "qualification predicates require Python optimization disabled")
    for revision in (args.source_a, args.source_b):
        require(re.fullmatch(r"[0-9a-f]{40}", revision), "full source revisions are required")
    pins = (args.bound_qemu, args.bound_qemu_sha256, args.release_a_manifest_sha256, args.release_b_manifest_sha256)
    require(not any(pins) or all(pins), "bound P2 needs QEMU and both independent manifest pins")
    matrix = Matrix(args)
    original_qemu = rel.QEMU
    previous_binding = os.environ.get("ABSD_P2_BOUND_INPUTS")
    if args.bound_qemu:
        import p2_boot_binding
        proxy_command = p2_boot_binding.proxy_command(rel.QEMU)
        inputs = matrix.evidence / "P2-BOOT-INPUTS.json"
        p2_boot_binding.prepare(inputs, args.bound_qemu, args.bound_qemu_sha256, [
            {"path": str(matrix.A.path), "manifest_sha256": args.release_a_manifest_sha256},
            {"path": str(matrix.B.path), "manifest_sha256": args.release_b_manifest_sha256}],
            matrix.evidence / "boot-bindings")
        os.environ["ABSD_P2_BOUND_INPUTS"] = str(inputs)
        rel.QEMU = proxy_command
    error = None
    rel.run_boot = matrix.traced_importer_boot
    try:
        matrix.run()
    except BaseException as failure:
        error = f"{type(failure).__name__}: {failure}"
        print("RECOVERY NATIVE FAILED " + error, file=sys.stderr, flush=True)
    finally:
        rel.run_boot = matrix.original_run_boot
        rel.QEMU = original_qemu
        if previous_binding is None:
            os.environ.pop("ABSD_P2_BOUND_INPUTS", None)
        else:
            os.environ["ABSD_P2_BOUND_INPUTS"] = previous_binding
    return 0 if matrix.finish(error) else 1


if __name__ == "__main__":
    raise SystemExit(main())
