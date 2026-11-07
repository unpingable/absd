#!/usr/bin/env python3
"""F3's ghost write against the storage fence rule (kernel
docs/STORAGE-STALE-WRITE-FENCE.md; owner decision (b), 2026-10-17).

F3's NBD stall device (platform lane/f3-blkstall-20261017, qual/blkstall,
used unchanged) holds one write of a commit body past the kernel's bound,
then answers it EIO without performing it and keeps its bytes: a backend
that reports a write failed and can still apply it. The served boot's file
server fails on the poisoned mount and init resets the machine; QEMU's reset
drain waits for that EIO, then the same image boots again.

With no storage fence declared, the successor must be refused writable
recovery before anything reaches the device:
  - the successor prints the kernel's `STORAGE FENCE fence=none
    reason=not_declared` and the file server's `RECOVERY WRITABLE REFUSED
    reason=storage_fence previous=failed fence=none`, never `FSD READY` or
    a listener, and init stops the machine (status 7) instead of resetting;
  - its accounting line counts block_writes=0 block_flushes=0, and the
    device log has no WRITE or FLUSH arriving after the held request's
    reply (reads only);
then the retained ghost is applied, as in F3, and the host reader's view is
recorded. Finally a cold boot with `storage-fence=external` must still refuse
before any write/flush. A corrupted image may refuse at its read-only mount.
The declaration is never treated as an independently established fence.

    storage-fence-ghost.py --platform P --kernel K --f3 F3/qual/blkstall \\
        --backend ata|nvme --receipt DIR [--seed N]
"""

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import random
import re
import shutil
import subprocess
import sys
import threading
import time

HOME = "/home/operator"
OPS_BEFORE = 4


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def first_boot_case(args, target, receipt, ctl, device_log, wrapper, blk, say):
    """Hold initial ledger metadata after the dirty guard is durable."""
    guest = load(target.root / "scripts/storage_fence_guest.py", "storage_fence_guest")
    state = load(target.root / "scripts/storage_fence_state.py", "storage_fence_state")
    fs = blk.load(target.root / "scripts/absd_fs.py", "absd_fs_first_boot")
    region = fs.fs_region(target.image, target.image.stat().st_size // fs.SECTOR)
    selected = fs.select(region)
    records = fs.tree(region, selected)
    record = records[state.PATH]
    if fs.content(region, selected, record) != state.FRESH or len(record["blocks"]) != 1:
        raise RuntimeError("first-boot control did not start from the seeded guard")
    guard_offset = (region.first + selected["geometry"]["data_first"]
                    + record["blocks"][0] * fs.SECTORS_PER_BLOCK) * fs.SECTOR
    metadata_end = (region.first + selected["geometry"]["data_first"]) * fs.SECTOR
    rule = {"arm": "write", "hold": blk.blk_classify.HOLD_BOUND[args.backend] + 5.0,
            "min_run": 4, "ghost": True}
    say(f"first-boot arm {blk.control(ctl, rule)}")
    raw, status, log = guest.cold_boot(target, args.backend, "first-boot-failure", qemu=wrapper)
    serial = raw.decode(errors="replace")
    if (status != "7" or serial.count("ABSD KERNEL BOOT\n") != 1
            or "FSD FAILED recovery charge:" not in serial):
        raise RuntimeError(f"first-boot failure did not occur at ledger charge: {status} {log}")
    if any(word in serial for word in ("FSD HOST KEY", "FSD READY ", "MACHINE RECOVER RESET")):
        raise RuntimeError("first-boot failure happened after the required boundary")

    def events():
        text = device_log.read_text()
        complete = text[:text.rfind("\n") + 1]
        return [json.loads(line) for line in complete.splitlines() if line]

    end = time.monotonic() + rule["hold"] + 30
    while True:
        observed = events()
        held = [event for event in observed if event.get("ghost")]
        if held:
            break
        if time.monotonic() > end:
            raise RuntimeError("first-boot retained metadata command not established")
        time.sleep(0.2)
    writes = [event for event in observed if event.get("event") == "arrive"
              and event.get("type") == "write"]
    if not writes or (writes[0]["offset"], writes[0]["length"]) != (guard_offset, 512):
        raise RuntimeError("the guard was not the first device write")
    if len(held) != 1 or not (region.first * fs.SECTOR <= held[0]["offset"] < metadata_end):
        raise RuntimeError("retained write is not initial filesystem metadata")
    marker_reply = next((event for event in observed if event.get("event") == "reply"
                         and event.get("seq") == writes[0]["seq"]), None)
    if not marker_reply or marker_reply.get("error") != 0 or not marker_reply.get("performed"):
        raise RuntimeError("dirty marker write was not acknowledged")
    between = [event for event in observed if event.get("event") == "reply"
               and event.get("type") == "flush" and event.get("performed")
               and writes[0]["seq"] < event["seq"] < held[0]["seq"]]
    if not between:
        raise RuntimeError("no completed dirty-marker flush before ledger metadata")
    region = fs.fs_region(target.image, target.image.stat().st_size // fs.SECTOR)
    selected = fs.select(region)
    records = fs.tree(region, selected)
    if "/var/state" in records or "/var/state/recovery" in records:
        raise RuntimeError("ledger state already exists: missing-ledger control is not established")
    if "/ssh/host_ed25519_seed" in records:
        raise RuntimeError("host key was written before the ledger")
    if fs.content(region, selected, records[state.PATH]) != state.encode("dirty"):
        raise RuntimeError("failed initial charge did not leave dirty state")

    cursor = len(observed)
    retries = [guest.refused_cold_boot(target, args.backend, "missing-ledger-served",
                                      previous="none", qemu=wrapper),
               guest.refused_cold_boot(target, args.backend, "missing-ledger-plain",
                                      previous="none", served=False, qemu=wrapper)]
    later = [event for event in events()[cursor:] if event.get("event") == "arrive"]
    if any(event.get("type") != "read" for event in later):
        raise RuntimeError("a missing-ledger retry issued a mutating request")
    before = hashlib.sha256(target.image.read_bytes()).hexdigest()
    answer = blk.control(ctl, {"apply_ghost": True})
    applied = answer.get("applied", [])
    if len(applied) != 1 or applied[0]["seq"] != held[0]["seq"]:
        raise RuntimeError("the original metadata command was not retained until after refusal")
    after = hashlib.sha256(target.image.read_bytes()).hexdigest()
    result = {"verdict": "FIRST_BOOT_UNKNOWN_REFUSED", "first_failure_status": status,
              "ledger_absent": True, "host_key_absent": True, "guard": "dirty",
              "guard_offset": guard_offset, "retained_metadata": applied[0],
              "read_only_retry_requests": len(later), "retries": retries,
              "image_changed_at_late_effect": before != after}
    say(f"STORAGE FENCE FIRST BOOT OK backend={args.backend} ledger_absent=true "
        f"served_and_plain_refused=true successor_mutating_requests=0")
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", required=True)
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--f3", required=True, help="F3's qual/blkstall directory (nbd-stall.py, f3-qemu, run-blkstall.py)")
    ap.add_argument("--backend", required=True, choices=["ata", "nvme"])
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--qemu", default="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand")
    ap.add_argument("--first-boot", action="store_true",
                    help="retain initial ledger metadata, then retry with no ledger on served and plain fsd")
    args = ap.parse_args()
    platform = pathlib.Path(args.platform).resolve()
    f3 = pathlib.Path(args.f3).resolve()
    receipt = pathlib.Path(args.receipt).resolve()
    # The NBD sockets live in this run's own receipt, not a shared /tmp name.
    # AF_UNIX paths hold at most 107 bytes before the terminating NUL; refuse
    # before creating anything.
    sockets = receipt / "sock"
    export, ctl = sockets / "export.sock", sockets / "control.sock"
    for path in (export, ctl):
        if len(os.fsencode(path)) > 107:
            raise SystemExit(f"storage-fence-ghost: socket path {path} is {len(os.fsencode(path))} bytes, "
                             "over the 107-byte AF_UNIX limit; use a shorter --receipt")
    receipt.mkdir(parents=True, exist_ok=False)
    work = receipt / "work"
    work.mkdir(mode=0o700)
    seed = args.seed if args.seed is not None else random.SystemRandom().randrange(1 << 32)
    log = open(receipt / "run.log", "w", buffering=1)

    def say(text):
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {text}"
        log.write(line + "\n")
        print(line, flush=True)

    sys.path.insert(0, str(platform / "scripts"))
    blk = load(f3 / "run-blkstall.py", "run_blkstall")
    classify = blk.blk_classify
    ssh_absd = load(platform / "scripts" / "ssh_absd.py", "ssh_absd")
    matrix = load(platform / "scripts" / "ssh-matrix.py", "ssh_matrix")
    os.environ["ABSD_HARNESS_STORAGE_FENCE"] = "none"
    served = load(platform / "scripts" / "served-matrix.py", "served_matrix")
    if served.ServedTarget.storage_fence is not None:
        raise RuntimeError("the served target still declares a storage fence")
    os.environ["ABSD_BLOCK_ATTACH"] = args.backend
    target = served.ServedTarget(argparse.Namespace(kernel=args.kernel, platform=str(platform),
                                                    shell=str(platform / "commands/absd-sh"),
                                                    qemu=args.qemu, boot_seconds=3000))
    key = work / "client_key"
    matrix.keygen(key)
    target.setup(work, (work / "client_key.pub").read_text())
    say(f"backend={args.backend} seed={seed} image imported")

    sockets.mkdir(mode=0o700)
    device_log = receipt / "device.jsonl"
    nbd = subprocess.Popen([sys.executable, str(f3 / "nbd-stall.py"), str(target.image), str(export), str(ctl),
                            str(device_log)], stdout=subprocess.PIPE, text=True)
    result = {"backend": args.backend, "seed": seed}
    try:
        if nbd.stdout.readline().strip() != "NBD STALL READY":
            raise RuntimeError("the stall device did not start")
        os.environ.update(ABSD_QEMU_REBOOT="allow", F3_DRIVE=f"nbd:{export}", F3_REAL_QEMU=args.qemu.split()[0])
        os.environ.pop("F3_QMP", None)
        wrapper = f"{f3 / 'f3-qemu'} {' '.join(args.qemu.split()[1:])}"
        if args.first_boot:
            result.update(first_boot_case(args, target, receipt, ctl, device_log, wrapper, blk, say))
            return
        boot = target.start(qemu_extra=wrapper)
        watcher = blk.Serial(target.log)
        watcher.start()
        client = matrix.Client(work, target.port)
        client.trust(boot["public"])
        rng = random.Random(seed)
        counter = iter(range(1 << 20))

        def op(name, minimum=1, timeout=600):
            index = next(counter)
            data = classify.payload(seed, index, 0, rng.randint(minimum, 65536))
            try:
                rc, out, _ = client.run(key, f"cd {HOME}; cat > {name}", stdin=data, timeout=timeout)
            except subprocess.TimeoutExpired:
                rc, out = None, b""
            say(f"op {index} {name} {len(data)} bytes rc={rc}")
            return rc == 0 and not out

        names = [f"f3-{n:03d}" for n in range(OPS_BEFORE)]
        if not all(op(name) for name in names):
            raise RuntimeError("an operation before arming failed")
        time.sleep(3)
        hold = classify.HOLD_BOUND[args.backend] + 5.0
        rule = {"arm": "write", "hold": hold, "min_run": 4, "ghost": True}
        armed_at = time.time()
        say(f"arm {blk.control(ctl, rule)}")
        thread = threading.Thread(target=op, args=(names[1],), kwargs={"minimum": 32768}, daemon=True)
        thread.start()
        deadline = armed_at + hold + classify.slack(args.backend) + classify.RETURN_BOUND + 60
        while time.time() < deadline and target.proc.poll() is None:
            time.sleep(0.5)
        if target.proc.poll() is None:
            raise RuntimeError("the machine neither stopped nor ended within the bound")
        watcher.stop = True
        watcher.join(timeout=5)
        status = target.proc.stdout.read().decode(errors="replace").strip()
        raw = target.log.read_bytes()
        boots = raw.decode(errors="replace").split("ABSD KERNEL BOOT\n")[1:]
        captured = served.captured_all(raw)
        result.update(status=status, boots=len(boots))
        if status != "7" or len(boots) != 2:
            raise RuntimeError(f"expected two boots and init's stop (7): status={status!r} boots={len(boots)}")
        first, second = boots
        for needed in ("FSD FAILED", "MACHINE RECOVER RESET pid=1"):
            if needed not in first:
                raise RuntimeError(f"the failing generation lacks {needed!r}")
        kernel_line = re.search(r"(?m)^STORAGE FENCE fence=none reason=not_declared$", second)
        refusal = re.search(r"(?m)^RECOVERY WRITABLE REFUSED reason=storage_fence previous=failed fence=none$", second)
        if not kernel_line or not refusal:
            raise RuntimeError(f"the successor lacks the fence lines: {second[-2500:]}")
        for absent in ("FSD READY ", "FSD RECOVERY seq=", "MACHINE RECOVER RESET"):
            if absent in second:
                raise RuntimeError(f"the refused successor printed {absent!r}")
        if "SSH LISTENING" in captured[1]:
            raise RuntimeError("the refused successor listened")
        counted = re.search(r"(?m)^DURABLE status=.* block_writes=(\d+) block_flushes=(\d+) block_errors=(\d+) ",
                            second)
        if not counted or counted.groups() != ("0", "0", "0"):
            raise RuntimeError(f"the successor's accounting: {counted.group(0) if counted else None!r}")
        events = [json.loads(line) for line in device_log.read_text().splitlines()]
        held = [e for e in events if e.get("ghost")]
        if len(held) != 1:
            raise RuntimeError(f"expected one ghost-held request, found {len(held)}")
        replied = held[0]["reply"]
        later = [e for e in events if e.get("event") == "arrive" and e["arrive"] > replied]
        mutating = [e for e in later if e.get("type") in ("write", "flush", "trim", "write_zeroes")]
        kinds = sorted({e.get("type") for e in later})
        result.update(successor_device_requests=len(later), successor_request_kinds=kinds,
                      successor_mutating_requests=len(mutating), ghost_offset=held[0]["offset"],
                      ghost_bytes=held[0].get("length"))
        if mutating:
            raise RuntimeError(f"a write or flush reached the device after the ghost's EIO: {mutating[:3]}")
        say(f"REFUSED BEFORE ANY WRITE: status={status} successor requests={len(later)} kinds={kinds} "
            f"{kernel_line.group(0)!r} {refusal.group(0)!r}")
        # The same NBD service still owns the retained command. Exercise
        # both declarations against that actual live backing service,
        # before applying its late effect or changing the image at all.
        guest = load(platform / "scripts/storage_fence_guest.py", "storage_fence_guest")
        result["unverified_declarations"] = []
        for declaration, reason in (("external", "external_unverified"),
                ("controller", "backend_unverified" if args.backend == "nvme" else "no_controller_reset")):
            result["unverified_declarations"].append(guest.refused_cold_boot(target, args.backend,
                "retained-command-" + declaration, declaration=declaration, reason=reason, qemu=wrapper))
        complete = device_log.read_text()
        complete = complete[:complete.rfind("\n") + 1]
        after_declarations = [json.loads(line) for line in complete.splitlines()]
        new_requests = [event for event in after_declarations[len(events):]
                        if event.get("event") == "arrive"]
        if any(event.get("type") != "read" for event in new_requests):
            raise RuntimeError("a declaration retry sent a non-read request to the retained-command backend")
        result["declaration_request_kinds"] = sorted({event.get("type") for event in new_requests})
        before = hashlib.sha256(target.image.read_bytes()).hexdigest()
        answer = blk.control(ctl, {"apply_ghost": True})
        after = hashlib.sha256(target.image.read_bytes()).hexdigest()
        snap = work / "at-ghost.img"
        shutil.copyfile(target.image, snap)
        snap.chmod(0o600)
        # Read the actual fitted image geometry, not a newly loaded
        # module's default image-size constant.
        fs = ssh_absd.absd_fs
        try:
            view = {"seq": fs.select(fs.fs_region(snap, snap.stat().st_size // fs.SECTOR))["seq"]}
        except fs.Refused as error:
            view = {"error": str(error)}
        result["ghost"] = {"applied": answer.get("applied"), "image_changed": before != after,
                           "host_reader": {"seq": view.get("seq"), "error": view.get("error")}}
        say(f"ghost applied {answer}; image changed={before != after}; host reader {result['ghost']['host_reader']}")
        (receipt / "serial-1.log").write_bytes(raw)
        # Finishing this fixture's held request does not make an unchecked
        # boot declaration a supported recovery mechanism. The same image
        # must still refuse; a corrupted metadata image may refuse at the
        # read-only mount before its guard can be read.
        result["declared"] = guest.refused_cold_boot(target, args.backend,
            "declared-after-ghost", declaration="external", reason="external_unverified",
            allow_corrupt=True, qemu=wrapper)
        result["declared"]["outcome"] = "refused"
        result["verdict"] = "REFUSED_BEFORE_WRITE"
        print(f"STORAGE FENCE GHOST OK backend={args.backend} successor_mutating_requests=0 "
              f"ghost_image_changed={result['ghost']['image_changed']} declared={result['declared']['outcome']}",
              flush=True)
    except Exception as error:
        result["verdict"] = f"FAILED: {type(error).__name__}: {error}"[:2000]
        raise
    finally:
        (receipt / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        if target.proc and target.proc.poll() is None:
            target.stop()
        nbd.terminate()
        try:
            nbd.wait(timeout=10)
        except subprocess.TimeoutExpired:
            nbd.kill()
        shutil.rmtree(sockets, ignore_errors=True)


if __name__ == "__main__":
    main()
