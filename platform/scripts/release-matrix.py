#!/usr/bin/env python3
"""Failure injection for the INSTALL_UPDATE_RECOVERY gate (docs/RELEASE.md
section 12): every case is one host operation or one QEMU boot with a
named expected refusal or a named expected success, recorded as an E3 line.

Inputs: two release directories A and B (release.py build, different ids),
their kernel checkouts (one checkout at the shared commit is fine), an
operator key, a work directory, and optionally a format-1 operator image
(from the pre-gate platform) for the migration cases.

Cases (the numbers are the gate's):
  1  mismatched boot image and release tree: A's image, B selected
  2  unsupported filesystem format: B's image on a format-1 disk
  3  update artifact missing: stage from a release directory lacking its importer
  4  staged release corrupted: B's record altered on the disk, then selected
  5  failure before the selection switch: a partial stage, then select
  6  failure after selection before readiness: B selected, A's image booted
  7  failed served boot, manual rollback: B refused, rollback to A
  8  the previous release selected again: A boots and is accepted
  9  restore from a known-good backup: boot, readiness, content
  10 restore from corrupt backups: truncated, wrong format, corrupted superblock,
     altered record, mismatched backup.toml, future format
  11 migration from format 1 (needs --format1-image)
  12 rollback across the migration boundary is refused; the retained image restores
"""

import argparse
import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_").replace(".py", ""), here / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rel = load("release.py")
oi = load("operator_image.py")
em = load("exec-matrix.py")

RESULTS = []


def record(case, name, ok, detail):
    RESULTS.append({"case": case, "name": name, "verdict": "PASS" if ok else "FAIL", "detail": detail})
    print(f"E3 {'PASS' if ok else 'FAIL'} {case:>2} {name:<28} {detail[:300]}", flush=True)


class Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def __getattr__(self, name):
        return None


def run_tool(func, **kw):
    """One release.py command; (ok, text) where text is the refusal or the
    log lines."""
    lines = []
    try:
        func(Args(**kw), log=lines.append)
        return True, "\n".join(lines)
    except (rel.Failed, absd_fs.Refused, oi.Failed) as error:
        return False, str(error)


def boot_expect(target, iso, name, port, release_id=None, want_refusal=None, timeout=240):
    """Boots `iso` against the target; returns (ended_status, serial). With
    `want_refusal`, the boot must end pre-ready with QEMU status 7 and the
    refusal line, and must not reset."""
    boot = rel.Boot(target, iso, name, port)
    try:
        if want_refusal:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and boot.proc.poll() is None:
                time.sleep(0.5)
            status = boot.proc.poll()
            serial = boot.serial()
            ok = (status == 7 and want_refusal in serial and "MACHINE RECOVER RESET" not in serial
                  and serial.count("ABSD KERNEL BOOT") == 1 and "SSH LISTENING" not in boot.worker())
            return ok, status, serial
        ready = boot.wait_ready(release_id)
        return True, ready, boot
    finally:
        if want_refusal:
            boot.stop()


def fresh_target(work, name):
    out = work / name
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    return rel.Target(out)


def install(target, release, kernel, identity="matrix-disk"):
    return run_tool(rel.cmd_install, release=str(release.path), kernel=str(kernel), target=str(target.out),
                    target_identity=identity, replace=True)


def accept(target, key, port):
    return run_tool(rel.cmd_accept, target=str(target.out), key=str(key), port=port)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--release-a", required=True)
    ap.add_argument("--release-b", required=True)
    ap.add_argument("--kernel", help="default checkout for both releases (same-kernel matrix)")
    ap.add_argument("--kernel-a", help="checkout matching release A's manifest")
    ap.add_argument("--kernel-b", help="checkout matching release B's manifest")
    ap.add_argument("--key", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--port", type=int, default=2231)
    ap.add_argument("--format1-image", help="a format-1 operator image (pre-gate build) for cases 11 and 12")
    ap.add_argument("--format1-key", help="the operator key that image authorizes (its site state survives the migration)")
    ap.add_argument("--only", default="", help="comma-separated case numbers")
    ap.add_argument("--results")
    args = ap.parse_args()
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    A, B = rel.Release(args.release_a), rel.Release(args.release_b)
    if not (args.kernel_a or args.kernel) or not (args.kernel_b or args.kernel):
        ap.error("give --kernel or both --kernel-a and --kernel-b")
    kernel_a = pathlib.Path(args.kernel_a or args.kernel).resolve()
    kernel = pathlib.Path(args.kernel_b or args.kernel).resolve()
    key = pathlib.Path(args.key).resolve()
    wanted = {int(n) for n in args.only.split(",") if n} or set(range(1, 13))
    port = args.port

    def want(n):
        return n in wanted

    # A base disk with A installed and accepted, reused by copying.
    base = fresh_target(work, "base")
    ok, text = install(base, A, kernel_a)
    if not ok:
        print(f"E3 ABORT base install: {text}")
        sys.exit(2)
    ok, text = accept(base, key, port)
    if not ok:
        print(f"E3 ABORT base accept: {text}")
        sys.exit(2)

    def from_base(name):
        t = fresh_target(work, name)
        shutil.rmtree(t.out)
        shutil.copytree(base.out, t.out)
        return rel.Target(t.out)

    if want(1):
        t = from_base("case1")
        ok, text = run_tool(rel.cmd_stage, release=str(B.path), kernel=str(kernel), target=str(t.out))
        ok2, text2 = run_tool(rel.cmd_select, release=str(B.path), kernel=str(kernel), target=str(t.out))
        # B selected; boot A's image: the file server's release mismatch.
        okb, status, serial = boot_expect(t, t.release_iso(A.id), "case1", port,
                                          want_refusal="RELEASE REFUSED reason=release_mismatch")
        record(1, "image-tree-mismatch", ok and ok2 and okb, f"stage={ok} select={ok2} status={status}")

    if want(2):
        t = from_base("case2")
        if args.format1_image:
            shutil.copyfile(args.format1_image, t.image)
            okb, status, serial = boot_expect(t, t.release_iso(A.id), "case2", port,
                                              want_refusal="FSD FAILED mount")
            unsupported = "UnsupportedFormat" in serial or "unsupported" in serial.lower()
            record(2, "unsupported-fs-format", okb and unsupported, f"status={status} named={unsupported}")
        else:
            record(2, "unsupported-fs-format", False, "skipped: no --format1-image")

    if want(3):
        t = from_base("case3")
        with tempfile.TemporaryDirectory(dir=work) as tmp:
            broken = pathlib.Path(tmp) / "B-missing-importer"
            shutil.copytree(B.path, broken)
            (broken / "fixture-import.elf").unlink()
            try:
                rel.Release(broken)
                ok, text = False, "the release directory loaded without its importer"
            except rel.Failed as error:
                ok, text = "missing fixture-import.elf" in str(error), str(error)
        record(3, "update-artifact-missing", ok, text)

    if want(4):
        t = from_base("case4")
        ok, text = run_tool(rel.cmd_stage, release=str(B.path), kernel=str(kernel), target=str(t.out))
        # Corrupt the staged record on the disk the only way the disk is
        # written: an importer step replacing the file whole.
        good = (B.path / "release").read_bytes()
        bad = good[:-9] + b"deadbeef\n"
        rel.import_files(kernel, B, t.image, [(f"/releases/{B.id}/release", bad)], lambda s: None, step_override=4)
        ok2, text2 = run_tool(rel.cmd_select, release=str(B.path), kernel=str(kernel), target=str(t.out))
        # The host refuses the selection (check_mismatch) and A still boots.
        okb, ready, boot = boot_expect(t, t.release_iso(A.id), "case4", port, release_id=A.id)
        boot.ssh(key, "shutdown"); boot.wait_end(); boot.stop()
        record(4, "staged-release-corrupted", ok and not ok2 and "check_mismatch" in text2 and okb,
               f"stage={ok} select_refused={not ok2} ({text2[:60]}) A_boots={okb}")

    if want(5):
        t = from_base("case5")
        # A partial stage: B's tree without its record (the staging cut short).
        partial = [f for f in B.tree_files() if not f[0].endswith("/release")][:3]
        rel.import_files(kernel, B, t.image, partial, lambda s: None)
        ok2, text2 = run_tool(rel.cmd_select, release=str(B.path), kernel=str(kernel), target=str(t.out))
        okb, ready, boot = boot_expect(t, t.release_iso(A.id), "case5", port, release_id=A.id)
        boot.ssh(key, "shutdown"); boot.wait_end(); boot.stop()
        record(5, "failure-before-switch", not ok2 and "no_release_tree" in text2 and okb,
               f"select_refused={not ok2} ({text2[:60]}) A_boots={okb}")

    if want(6) or want(7) or want(8):
        t = from_base("case6")
        ok, text = run_tool(rel.cmd_stage, release=str(B.path), kernel=str(kernel), target=str(t.out))
        ok2, text2 = run_tool(rel.cmd_select, release=str(B.path), kernel=str(kernel), target=str(t.out))
        if want(6):
            # B selected but A's image booted: refused pre-ready, no reset.
            okb, status, serial = boot_expect(t, t.release_iso(A.id), "case6", port,
                                              want_refusal="RELEASE REFUSED reason=release_mismatch")
            record(6, "failure-after-switch", ok and ok2 and okb, f"status={status}")
        if want(7):
            # B's own image reaches readiness but fails acceptance (the
            # acceptance check is the gate): simulate with a B whose
            # acceptance is refused because the ledger never accepted it,
            # then roll back by hand to A.
            okb, ready, boot = boot_expect(t, t.release_iso(B.id), "case7", port, release_id=B.id)
            rc, out, err = boot.ssh(key, "/bin/release")
            boot.ssh(key, "shutdown"); boot.wait_end(); boot.stop()
            b_ready = okb and f"release={B.id}" in out.decode(errors="replace")
            okr, textr = run_tool(rel.cmd_rollback, release=str(A.path), kernel=str(kernel_a), target=str(t.out))
            record(7, "served-then-rollback", b_ready and okr, f"B_ready={b_ready} rollback={okr} {textr[:80]}")
        if want(8):
            okb, ready, boot = boot_expect(t, t.iso, "case8", port, release_id=A.id)
            rc, out, err = boot.ssh(key, "/bin/release")
            boot.ssh(key, "shutdown"); boot.wait_end(); boot.stop()
            oka, texta = accept(t, key, port)
            record(8, "previous-selected-again", okb and f"release={A.id}" in out.decode(errors="replace") and oka,
                   f"A_boots={okb} accepted={oka}")

    if want(9) or want(10):
        t = from_base("case9")
        backup = work / "backup-good"
        shutil.rmtree(backup, ignore_errors=True)
        okb, textb = run_tool(rel.cmd_backup, target=str(t.out), backup=str(backup))
        if want(9):
            # Destroy the disk, restore, boot, read the acceptance marker.
            t.image.write_bytes(b"\0" * 4096)
            okr, textr = run_tool(rel.cmd_restore, target=str(t.out), backup=str(backup), replace=True,
                                  clone=False, release=None, kernel=None, key=None, port=port, target_identity=None)
            okboot, ready, boot = boot_expect(t, t.iso, "case9", port, release_id=A.id)
            rc, out, err = boot.ssh(key, "/bin/cat /home/operator/.accept")
            boot.ssh(key, "shutdown"); boot.wait_end(); boot.stop()
            record(9, "restore-known-good", okb and okr and okboot and rc == 0 and b"accept " in out,
                   f"backup={okb} restore={okr} boot={okboot} marker={out[:40]!r}")
        if want(10):
            results = []
            good_image = (backup / rel.IMAGE).read_bytes()
            good_meta = (backup / "backup.toml").read_text()

            def corrupt(name, mutate_image=None, mutate_meta=None):
                d = work / f"backup-{name}"
                shutil.rmtree(d, ignore_errors=True)
                shutil.copytree(backup, d)
                if mutate_image:
                    (d / rel.IMAGE).write_bytes(mutate_image(bytearray(good_image)))
                if mutate_meta:
                    (d / "backup.toml").write_text(mutate_meta(good_meta))
                okx, textx = run_tool(rel.cmd_restore, target=str(t.out), backup=str(d), replace=True, clone=False,
                                      release=None, kernel=None, key=None, port=port, target_identity=None)
                results.append((name, not okx, textx[:70]))

            region = absd_fs.fs_region(backup / rel.IMAGE, oi.DEVICE_SECTORS)
            fs_first = region.first * 512
            corrupt("truncated", mutate_image=lambda b: bytes(b[: len(b) // 2]))
            corrupt("superblock", mutate_image=lambda b: bytes(b[:fs_first + 100]) + b"\xff" + bytes(b[fs_first + 101:]))
            corrupt("future-format", mutate_image=lambda b: bytes(b[:fs_first + 7]) + b"9" + bytes(b[fs_first + 8:]))
            corrupt("mismatched-meta", mutate_meta=lambda m: m.replace("commit_sequence = ", "commit_sequence = 9"))

            def altered_record(b):
                # A byte inside the metadata half: the image digest fails.
                half = region.first * 512 + 8 * 512 + 200
                b[half] ^= 0x55
                return bytes(b)
            corrupt("altered-metadata", mutate_image=altered_record)
            if args.format1_image:
                d = work / "backup-wrong-format"
                shutil.rmtree(d, ignore_errors=True)
                shutil.copytree(backup, d)
                shutil.copyfile(args.format1_image, d / rel.IMAGE)
                okx, textx = run_tool(rel.cmd_restore, target=str(t.out), backup=str(d), replace=True, clone=False,
                                      release=None, kernel=None, key=None, port=port, target_identity=None)
                results.append(("wrong-format", not okx, textx[:70]))
            allok = all(r[1] for r in results)
            record(10, "restore-corrupt-refused", allok, "; ".join(f"{n}:{'refused' if r else 'ACCEPTED'} {t}" for n, r, t in results))

    if want(11) or want(12):
        if not args.format1_image:
            record(11, "migration-from-format-1", False, "skipped: no --format1-image")
            record(12, "rollback-across-migration", False, "skipped: no --format1-image")
        else:
            t = fresh_target(work, "case11")
            shutil.copyfile(args.format1_image, t.image)
            t.image.chmod(0o600)
            (t.out / rel.TARGET).write_text("matrix-disk\n")
            old_tree = oi.tree(t.image)
            okm, textm = run_tool(rel.cmd_migrate, release=str(B.path), kernel=str(kernel), target=str(t.out))
            if want(11) and not okm:
                record(11, "migration-from-format-1", False, f"migrate refused: {textm[-300:]}")
            elif want(11):
                # The migrated disk keeps the old site state, so the old
                # image's operator key is the one that gets in; the matrix
                # key (which only the releases' site defaults authorize)
                # must not.
                old_key = pathlib.Path(args.format1_key or key)
                okboot, ready, boot = boot_expect(t, t.iso, "case11", port, release_id=B.id)
                rcn, _, _ = boot.ssh(key, "echo in") if args.format1_key else (255, b"", b"")
                rc, out, err = boot.ssh(old_key, "/bin/cat /etc/sshd.conf")
                rc2, out2, err2 = boot.ssh(old_key, "/bin/stat /etc/sshd.conf")
                boot.ssh(old_key, "shutdown"); boot.wait_end(); boot.stop()
                same = rc == 0 and out == old_tree.get("/etc/sshd.conf")
                # A migrated object's mtime is 0 (docs/FILESYSTEM.md "Format
                # 2"): read from the record on the disk by the host reader,
                # the format's own witness (stat(1) does not show mtime yet).
                region = absd_fs.fs_region(t.image, oi.DEVICE_SECTORS)
                selected = absd_fs.select(region)
                mtime = absd_fs.tree(region, selected)["/etc/sshd.conf"].get("mtime")
                record(11, "migration-from-format-1", okm and okboot and same and mtime == 0 and rcn == 255,
                       f"migrate={okm} boot={okboot} old_key_in={rc == 0} new_key_refused={rcn == 255} etc_same={same} "
                       f"mtime={mtime} stat_rc={rc2} {textm[:60]}")
            if want(12):
                okr, textr = run_tool(rel.cmd_rollback, release=str(A.path), kernel=str(kernel_a), target=str(t.out))
                retained = sorted(t.out.glob(f"{rel.IMAGE}.pre-migration-*"))
                record(12, "rollback-across-migration", not okr and retained and
                       ("migration" in textr or "accepted" in textr), f"refused={not okr} ({textr[:80]}) retained={len(retained)}")

    passed = sum(r["verdict"] == "PASS" for r in RESULTS)
    print(f"E3 SUMMARY pass={passed} fail={len(RESULTS) - passed}")
    if args.results:
        pathlib.Path(args.results).write_text(json.dumps(RESULTS, indent=1))
    sys.exit(0 if passed == len(RESULTS) else 1)


if __name__ == "__main__":
    main()
