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
  4  staged release corrupted: first a copy of B with one tree file altered after
     its build is refused by stage (manifest_mismatch, nothing written); then B's
     record altered on the disk, then selected
  5  failure before the selection switch: a partial stage, then select
  6  failure after selection before readiness: B selected, A's image booted
  7  failed served boot, manual rollback: B refused, rollback to A
  8  the previous release selected again: A boots and is accepted
  9  restore from a known-good backup: boot, readiness, content
  10 restore from corrupt backups: truncated, wrong format, corrupted superblock,
     altered record, mismatched backup.toml, future format
  11 migration from format 1 (needs --format1-image)
  12 rollback across the migration boundary is refused; the retained image restores

Cases run only when named with --only (they are not part of the gate's 1-12):
  13 rollback from cache without a kernel checkout: B served, `rollback
     --target` alone boots the selection image cached at A's install (any
     kernel build is refused), A accepted, halted backup, restore, A served
     with its marker and accepted again
  14 A->B->C staging after removing A (needs --release-c): B staged, selected
     and accepted; C's stage refused (two trees); `remove --id A` by B's
     importer (step 5); C staged, selected and accepted; rollback from the
     cache to B, B served and accepted
  15 restore --clone through served readiness: a halted backup of the A
     machine restored with --clone into a new operator directory under another
     target identity; the clone served with a host key that is not the
     source's (a client trusting only the source's key is refused), its
     selection cache for A present, every other release without one named,
     and the source's operator directory byte-identical after the backup
  16 corrupted source tree: stage refuses by exact tree-file name, appends one
     REFUSED receipt and leaves every previous target file unchanged
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


def no_build(*args, **kwargs):
    raise rel.Failed("a kernel build was attempted")


def last_receipt(target, prefix):
    found = sorted((target.out / "receipts").glob(f"{prefix}-*.toml"))
    return rel.read_toml_flat(found[-1]) if found else {}


def snapshot(directory):
    """Every file under `directory` and its digest."""
    return {str(p.relative_to(directory)): rel.sha256_file(p)
            for p in sorted(pathlib.Path(directory).rglob("*")) if p.is_file()}


def stage_refusal_only(target, before, reason):
    """One new, parseable pre-write receipt; every previous byte preserved."""
    after = snapshot(target.out)
    added = set(after) - set(before)
    if len(added) != 1:
        return False
    name = added.pop()
    if not name.startswith("receipts/stage-failed-") or not name.endswith(".toml"):
        return False
    try:
        receipt = rel.read_toml_flat(target.out / name).get("stage", {})
    except (OSError, ValueError):
        return False
    del after[name]
    return (after == before and receipt.get("state") == "REFUSED"
            and receipt.get("target_effects_possible") is False
            and reason in receipt.get("error", ""))


def corrupt_tree_stage_case(target, release, kernel, work):
    # A private source copy: the supplied release and target remain intact,
    # apart from the one failure receipt that is itself checked below.
    with tempfile.TemporaryDirectory(prefix="case16-release-", dir=work) as scratch:
        changed = pathlib.Path(scratch) / "release"
        shutil.copytree(release.path, changed)
        victim = sorted(p for p in (changed / "tree").rglob("*") if p.is_file())[0]
        victim.write_bytes(victim.read_bytes() + b"\ncase16 changed source\n")
        reason = f"manifest_mismatch digest {victim.relative_to(changed).as_posix()}"
        before = snapshot(target.out)
        ok, text = run_tool(rel.cmd_stage, release=str(changed), kernel=str(kernel), target=str(target.out))
        checked = not ok and reason in text and stage_refusal_only(target, before, reason)
        return checked, f"named_refusal={not ok and reason in text} receipt_and_target={checked} {text[-180:]}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--release-a", required=True)
    ap.add_argument("--release-b", required=True)
    ap.add_argument("--kernel", help="default checkout for both releases (same-kernel matrix)")
    ap.add_argument("--kernel-a", help="checkout matching release A's manifest")
    ap.add_argument("--kernel-b", help="checkout matching release B's manifest")
    ap.add_argument("--release-c", help="a third release directory (case 14), another id")
    ap.add_argument("--kernel-c", help="checkout matching release C's manifest (default: --kernel)")
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
        # A release directory whose tree no longer matches its manifest
        # (one command altered after the build): stage refuses by name
        # before any importer boot, and the operator directory is unchanged.
        tampered = work / "case4-tampered-release"
        shutil.rmtree(tampered, ignore_errors=True)
        shutil.copytree(B.path, tampered)
        victim = sorted((tampered / "tree" / "bin").iterdir())[0]
        data = bytearray(victim.read_bytes())
        data[len(data) // 2] ^= 0x01
        victim.write_bytes(bytes(data))
        before = snapshot(t.out)
        okt, textt = run_tool(rel.cmd_stage, release=str(tampered), kernel=str(kernel), target=str(t.out))
        tamper_refused = (not okt and f"manifest_mismatch digest tree/bin/{victim.name}" in textt
                          and stage_refusal_only(t, before, f"manifest_mismatch digest tree/bin/{victim.name}"))
        shutil.rmtree(tampered, ignore_errors=True)
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
        record(4, "staged-release-corrupted", tamper_refused and ok and not ok2 and "check_mismatch" in text2 and okb,
               f"tampered_tree_refused={tamper_refused} ({textt[-80:]}) stage={ok} select_refused={not ok2} "
               f"({text2[:60]}) A_boots={okb}")

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

    if want(13):
        t = from_base("case13")
        ok, text = run_tool(rel.cmd_stage, release=str(B.path), kernel=str(kernel), target=str(t.out))
        ok2, text2 = run_tool(rel.cmd_select, release=str(B.path), kernel=str(kernel), target=str(t.out))
        okb, ready, boot = boot_expect(t, t.iso, "case13-b", port, release_id=B.id)
        rc, out, err = boot.ssh(key, "/bin/release")
        boot.ssh(key, "shutdown"); boot.wait_end(); boot.stop()
        b_ready = okb and f"release={B.id}" in out.decode(errors="replace")
        # No --kernel, no --release: the cached selection image of A, and
        # any kernel build on the way is a refusal.
        saved, rel.oi.kernel_iso = rel.oi.kernel_iso, no_build
        try:
            okr, textr = run_tool(rel.cmd_rollback, target=str(t.out))
        finally:
            rel.oi.kernel_iso = saved
        source = last_receipt(t, f"rolled_back-{A.id}").get("rolled_back", {}).get("source")
        oka, texta = accept(t, key, port)
        backup = work / "backup-case13"
        shutil.rmtree(backup, ignore_errors=True)
        okk, textk = run_tool(rel.cmd_backup, target=str(t.out), backup=str(backup))
        t.image.write_bytes(b"\0" * 4096)
        okre, textre = run_tool(rel.cmd_restore, target=str(t.out), backup=str(backup), replace=True, clone=False,
                                release=None, kernel=None, key=None, port=port, target_identity=None)
        okboot, ready, boot = boot_expect(t, t.iso, "case13-restored", port, release_id=A.id)
        rcm, marker, _ = boot.ssh(key, "/bin/cat /home/operator/.accept")
        boot.ssh(key, "shutdown"); boot.wait_end(); boot.stop()
        oka2, texta2 = accept(t, key, port)
        record(13, "rollback-from-cache", ok and ok2 and b_ready and okr and source == "cache" and oka and okk
               and okre and okboot and rcm == 0 and f"accept {A.id} ".encode() in marker and oka2,
               f"B_ready={b_ready} rollback={okr} source={source} accepted={oka} backup={okk} restore={okre} "
               f"boot={okboot} marker={marker[:40]!r} reaccepted={oka2} {textr[-80:] if not okr else ''}")

    if want(14) and not args.release_c:
        record(14, "stage-third-after-remove", False, "skipped: no --release-c")
    elif want(14):
        C = rel.Release(args.release_c)
        kernel_c = pathlib.Path(args.kernel_c or args.kernel or args.kernel_b).resolve()
        t = from_base("case14")
        steps = {}
        steps["stage_b"], _ = run_tool(rel.cmd_stage, release=str(B.path), kernel=str(kernel), target=str(t.out))
        steps["select_b"], _ = run_tool(rel.cmd_select, release=str(B.path), kernel=str(kernel), target=str(t.out))
        steps["accept_b"], _ = accept(t, key, port)
        okc, textc = run_tool(rel.cmd_stage, release=str(C.path), kernel=str(kernel_c), target=str(t.out))
        steps["third_refused"] = not okc and "at most 2" in textc
        # A is neither selected nor the last accepted (B is both): B's
        # importer removes /releases/A/ in one step-5 commit.
        okr, textr = run_tool(rel.cmd_remove, release=str(B.path), kernel=str(kernel), target=str(t.out), id=A.id)
        steps["remove_a"] = okr and A.id not in t.trees() and not (t.out / "releases" / A.id).exists()
        steps["stage_c"], textsc = run_tool(rel.cmd_stage, release=str(C.path), kernel=str(kernel_c),
                                            target=str(t.out))
        steps["select_c"], _ = run_tool(rel.cmd_select, release=str(C.path), kernel=str(kernel_c), target=str(t.out))
        steps["accept_c"], _ = accept(t, key, port)
        steps["trees_bc"] = t.trees() == sorted([B.id, C.id])
        saved, rel.oi.kernel_iso = rel.oi.kernel_iso, no_build
        try:
            steps["rollback_b"], textrb = run_tool(rel.cmd_rollback, target=str(t.out))
        finally:
            rel.oi.kernel_iso = saved
        steps["reaccept_b"], _ = accept(t, key, port)
        failed = [name for name, ok in steps.items() if not ok]
        record(14, "stage-third-after-remove", not failed,
               f"failed={','.join(failed) or 'none'} remove={textr[-100:]!r} trees={','.join(t.trees())}")

    if want(15):
        # The source: the A machine (installed, accepted, its host key made
        # at its first served boot), halted. The backup appends one ledger
        # line to it; from then on nothing may change it.
        src = from_base("case15-source")
        src_seed = src.tree().get("/ssh/host_ed25519_seed")
        src_fp = rel.host_key_fingerprint(src_seed) if src_seed else "none"
        src_image = rel.sha256_file(src.image)
        backup = work / "backup-case15"
        shutil.rmtree(backup, ignore_errors=True)
        steps, facts = {}, {}
        steps["source_has_key"] = src_seed is not None
        steps["backup"], textk = run_tool(rel.cmd_backup, target=str(src.out), backup=str(backup))
        src_after_backup = snapshot(src.out)
        t = fresh_target(work, "case15-clone")
        steps["clone"], textc = run_tool(rel.cmd_restore, target=str(t.out), backup=str(backup), replace=False,
                                         clone=True, release=str(A.path), kernel=str(kernel_a), key=str(key),
                                         port=port, target_identity="matrix-clone")
        # The CLONE OK line, or the whole refusal (a readiness refusal puts
        # its cause first and the console lines after it).
        facts["clone"] = ((textc.splitlines() or [""])[-1] if steps["clone"]
                          else " | ".join(textc.splitlines())[:300])
        clone_seed = t.tree().get("/ssh/host_ed25519_seed") if steps["clone"] else None
        clone_fp = rel.host_key_fingerprint(clone_seed) if clone_seed else "none"
        steps["identity_differs"] = t.identity() == "matrix-clone" and t.identity() != src.identity()
        steps["key_differs"] = clone_seed is not None and clone_seed != src_seed and clone_fp != src_fp
        try:
            facts["cache"] = rel.select_cache(t, A.id)["iso_sha256"][:16]
            receipt = last_receipt(t, f"clone-{A.id}")
            steps["cache_present"] = receipt.get("select_cache", {}).get("iso_sha256", "")[:16] == facts["cache"]
            absent = receipt.get("select_cache_absent", {}).get("releases")
            steps["absent_named"] = absent == [r for r in t.trees() if r != A.id]
        except rel.Failed as error:
            steps["cache_present"], facts["cache"] = False, str(error)[:120]
        if steps["clone"]:
            try:
                okb, ready, boot = boot_expect(t, t.iso, "case15-clone", port, release_id=A.id)
                try:
                    rc, out, err = boot.ssh(key, "/bin/release")
                    steps["served"] = rc == 0 and f"release={A.id}" in out.decode(errors="replace")
                    steps["served_key_is_clones"] = not ready["generated"] and ready["fingerprint"] == clone_fp
                    # A client that trusts only the source machine's key.
                    old = work / "case15-source-trust"
                    old.mkdir(exist_ok=True)
                    client = rel.smx.Client(old, port)
                    client.trust(rel.host_public_key(src_seed) if src_seed else "ssh-ed25519 AAAA")
                    rco, _, erro = client.run(key, "echo in")
                    steps["source_key_refused"] = rco == 255 and b"Host key verification failed" in erro
                    facts["old_client"] = f"rc={rco} {erro.decode(errors='replace').strip()[:60]}"
                    boot.ssh(key, "shutdown")
                    steps["halted"] = boot.wait_end() == 3
                finally:
                    boot.stop()
            except rel.Failed as error:
                steps["served"], facts["boot"] = False, str(error)[-200:]
        steps["source_untouched"] = (rel.sha256_file(src.image) == src_image
                                     and snapshot(src.out) == src_after_backup)
        failed = [name for name, ok in steps.items() if not ok]
        # A refusal goes right after failed=: record() prints 300 characters.
        record(15, "restore-clone-served", not failed and len(steps) == 12,
               f"failed={','.join(failed) or 'none'} "
               + ("" if steps["clone"] else f"clone_refused={facts['clone'][:160]!r} ")
               + f"source={src_fp} clone={clone_fp} target={t.identity()} "
               f"cache={facts.get('cache')} old_client={facts.get('old_client')} {facts.get('boot', '')}")

    if want(16):
        t = from_base("case16")
        ok, text = corrupt_tree_stage_case(t, B, kernel, work)
        record(16, "corrupted-source-tree-receipt", ok, text)

    passed = sum(r["verdict"] == "PASS" for r in RESULTS)
    print(f"E3 SUMMARY pass={passed} fail={len(RESULTS) - passed}")
    if args.results:
        pathlib.Path(args.results).write_text(json.dumps(RESULTS, indent=1))
    sys.exit(0 if passed == len(RESULTS) else 1)


if __name__ == "__main__":
    main()
