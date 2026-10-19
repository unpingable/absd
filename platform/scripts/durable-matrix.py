#!/usr/bin/env python3
"""Crash matrix for the real Pulse journal over ABSD's native append region.

Every scenario is a sequence of QEMU boots against one persistent raw image.
The guest stops itself abruptly at a named journal write stage through the
kernel's `stop` syscall (QEMU exits at once; nothing later runs), the host
keeps the image, and a fresh boot scans, classifies, and recovers. Some
scenarios also mutate the image between boots: those are content-mutation
fixtures for damage the tested failure model cannot produce by itself.

Failure model actually exercised: abrupt loss of all guest state with every
device-acknowledged sector retained. Host power loss is not modelled.
"""


import argparse
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from served_ram import served_qemu
from served_kernel import kernel_make
import absd_image  # noqa: E402
import absd_inputs  # noqa: E402

IMAGE_BYTES = 4 * 1024 * 1024
DEVICE_SECTORS = IMAGE_BYTES // 512
STOP_BASE = 16
GENERATION_STOP_BASE = 32
POINTS = {
    1: "BeforeBuild", 2: "BodyPartial", 3: "BodyComplete", 4: "HeaderWritten",
    5: "ActivationBegin", 6: "ActivationWritten", 7: "ActivationFlushed",
    8: "ReclaimPartial", 9: "CandidateInReusedRegion",
}
HEADER_BYTES = 8 + 2 + 1 + 1 + 8 + 4 + 71
TRAILER_BYTES = 8 + 71
COMMIT_BYTES = 8 + 8 + 71 + 71
STAGES = {
    1: ("HeaderPartiallyWritten", "TruncatedHeader"),
    2: ("PayloadPartiallyWritten", "TruncatedPayload"),
    3: ("TrailerPartiallyWritten", "TruncatedTrailer"),
    4: ("FrameWrittenBeforeSync", "UncommittedSuffix"),
    5: ("DataFrameSynced", "UncommittedSuffix"),
    6: ("CommitMarkerPartiallyWritten", "TruncatedCommitMarker"),
    7: ("CommitMarkerSyncedBeforeAcknowledgement", None),
}
CHUNK = re.compile(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)")


def fail(message):
    print(f"DURABLE MATRIX FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def step_word(kind, count=0, record=0, stage=0, abort_record=0, abort_stage=0):
    return (kind * 10_000_000_000 + abort_record * 10_000_000 + abort_stage * 1_000_000
            + count * 10_000 + record * 10 + stage)


WORKER_ABORT_STATUS = 97
ABORT_AFTER_ACK = 8


class Harness:
    def __init__(self, args):
        self.kernel = pathlib.Path(args.kernel).resolve()
        self.elf = pathlib.Path(args.elf).resolve()
        self.work = pathlib.Path(args.work).resolve()
        self.qemu = args.qemu
        self.work.mkdir(parents=True, exist_ok=True)
        self.empty_input = self.work / "empty-input.bin"
        self.empty_input.write_bytes(b"")
        self.isos = {}
        self.boots = 0
        if absd_inputs.is_kernel_source(self.kernel):
            fail("refusing to build in the canonical kernel checkout")

    def iso(self, step):
        if step not in self.isos:
            subprocess.run(
                [
                    *kernel_make(), "--no-print-directory", "-C", str(self.kernel), "durable-iso",
                    f"DURABLE_STEP={step}", f"EXTERNAL_USER_ELF={self.elf}",
                    f"EXTERNAL_INPUT={self.empty_input}",
                ],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            )
            self.isos[step] = self.kernel / "build" / "durable" / f"absd-durable-{step}.iso"
        return self.isos[step]

    def boot(self, name, step, image):
        self.boots += 1
        log = self.work / f"{name}.{self.boots:03d}.serial.log"
        result = subprocess.run(
            [str(self.kernel / "scripts" / "durable-boot.sh"), str(self.iso(step)), str(image),
             str(log), "300", *served_qemu(self.qemu)],
            check=True, capture_output=True, text=True,
        )
        status = int(result.stdout.strip())
        serial = log.read_bytes()
        if b"PANIC" in serial or b"KERNEL FAULT" in serial:
            fail(f"{name}: kernel panic or fault in {log}")
        return status, serial, self.captured(serial), log

    @staticmethod
    def captured(serial):
        data = bytearray()
        for match in CHUNK.finditer(serial):
            offset = int(match.group(1), 16)
            if offset != len(data):
                fail(f"non-contiguous captured output at {offset}")
            data.extend(bytes.fromhex(match.group(2).decode("ascii")))
        return data.decode("utf-8", errors="replace")


def new_image(path):
    with open(path, "wb") as handle:
        handle.truncate(IMAGE_BYTES)
    return path


def require(condition, message):
    if not condition:
        fail(message)


def expect_orderly(name, status, serial, captured, kind):
    require(status == 3, f"{name}: QEMU status {status}, expected orderly 3")
    require(b"DURABLE WORKLOAD OK\n" in serial, f"{name}: DURABLE WORKLOAD OK missing")
    require(f"PULSE JOURNAL STEP OK kind={kind}\n" in captured, f"{name}: step not OK:\n{captured}")


def expect_stop(name, status, serial, stage):
    code = STOP_BASE + stage
    require(status == 4 * code + 3, f"{name}: QEMU status {status}, expected stop {4 * code + 3}")
    require(f"MACHINE STOP code={code}\n".encode() in serial, f"{name}: MACHINE STOP missing")
    require(b"DURABLE WORKLOAD" not in serial, f"{name}: workload finished despite stop")


def scan_fields(captured):
    match = re.search(
        r"JOURNAL SCAN outcome=(\w+) damage=(\w+|Some\(\w+\)) records=(\d+) "
        r"first_damaged_offset=(\w+|Some\(\d+\)) valid_prefix=(\d+) observed=(\d+)",
        captured,
    )
    require(match is not None, f"JOURNAL SCAN line missing:\n{captured}")
    damage = match.group(2)
    damage = None if damage == "None" else damage[len("Some("):-1]
    return {
        "outcome": match.group(1),
        "damage": damage,
        "records": int(match.group(3)),
        "valid_prefix": int(match.group(5)),
        "observed": int(match.group(6)),
    }


def verdicts(captured):
    found = {}
    for match in re.finditer(
        r"DURABLE VERDICT seq=(\d+) (COMMITTED|VALIDATED_UNREPLAYABLE|ABSENT|INDETERMINATE)", captured
    ):
        found[int(match.group(1))] = match.group(2)
    return found


def block_counters(serial):
    match = re.search(rb"^DURABLE status=\S+ .* block_writes=(\d+) block_flushes=(\d+) ", serial, re.M)
    require(match is not None, "DURABLE accounting line missing")
    return int(match.group(1)), int(match.group(2))


def acknowledged(captured):
    """(sequence, identity, file_bytes_after_append) for every acknowledgement
    the host saw before the boot ended. Lines relayed after an abrupt stop may
    be missing, so this is a lower bound on what was acknowledged."""
    return [(int(m.group(1)), m.group(2), int(m.group(3)))
            for m in re.finditer(r"PULSE APPEND seq=(\d+) id=(\S+) digest=\S+ bytes=(\d+) ", captured)]


def require_acks_survive(name, acks, recovery_captured, scan):
    """Every acknowledged record is in the recovered prefix with its identity,
    and ends at or before the valid prefix."""
    committed = {int(m.group(1)): m.group(2) for m in re.finditer(
        r"DURABLE VERDICT seq=(\d+) COMMITTED kind=\w+ id=(\S+)", recovery_captured)}
    for sequence, identity, end in acks:
        require(committed.get(sequence) == identity,
                f"{name}: acknowledged seq {sequence} ({identity}) not recovered as COMMITTED")
        require(end <= scan["valid_prefix"],
                f"{name}: acknowledged seq {sequence} ends at {end} beyond valid prefix {scan['valid_prefix']}")


def require_repair_boundary(image, offset):
    """The operator repair zeroes from `valid_prefix`, which Pulse derives by
    re-serializing records; check it is a real record boundary."""
    with open(image, "rb") as handle:
        handle.seek(ledger_base(image) + offset - 71)
        before = handle.read(71)
        after = handle.read(8)
    require(re.fullmatch(rb"sha256:[0-9a-f]{64}", before) is not None,
            f"repair boundary {offset} does not follow a commit checksum")
    require(b"PCJDATA1".startswith(after.rstrip(b"\x00")) and after[:1] == b"P",
            f"repair boundary {offset} does not start a data frame")


def check_recovery(name, harness, image, committed, outcome, damage, next_verdict="ABSENT"):
    status, serial, captured, log = harness.boot(name + ".recover", step_word(2), image)
    expect_orderly(name, status, serial, captured, 2)
    writes, flushes = block_counters(serial)
    require(writes == 0 and flushes == 0, f"{name}: recovery wrote {writes} sectors, flushed {flushes}")
    scan = scan_fields(captured)
    require(scan["outcome"] == outcome, f"{name}: outcome {scan['outcome']}, expected {outcome}")
    require(scan["damage"] == damage, f"{name}: damage {scan['damage']}, expected {damage}")
    require(scan["records"] == committed, f"{name}: {scan['records']} records, expected {committed}")
    seen = verdicts(captured)
    prefix_verdict = "VALIDATED_UNREPLAYABLE" if outcome == "Refused" else "COMMITTED"
    for sequence in range(1, committed + 1):
        require(seen.get(sequence) == prefix_verdict, f"{name}: seq {sequence} verdict {seen.get(sequence)}")
    require(seen.get(committed + 1) == next_verdict,
            f"{name}: seq {committed + 1} verdict {seen.get(committed + 1)}, expected {next_verdict}")
    require(len(seen) == committed + 1, f"{name}: unexpected verdicts {seen}")
    if outcome == "Refused":
        require("DURABLE UNKNOWN OK\n" in captured, f"{name}: DURABLE UNKNOWN OK missing")
        require("PULSE DURABLE JOURNAL OK" not in captured, f"{name}: recovery claimed on refused scan")
    else:
        marker = "DURABLE COMMIT OK" if outcome == "Clean" else "DURABLE TORN TAIL OK"
        require(marker in captured, f"{name}: {marker} missing")
        require("PULSE RESTART standing=Unknown evidence=0 deadlines=0\n" in captured,
                f"{name}: restart law line missing")
        require("DURABLE RECOVERY OK\n" in captured and "PULSE DURABLE JOURNAL OK\n" in captured,
                f"{name}: recovery markers missing")
    print(f"  {name}: outcome={scan['outcome']} damage={scan['damage']} records={scan['records']} "
          f"observed={scan['observed']} next={next_verdict} log={log.name}")
    scan["captured"] = captured
    return scan


def scenario_fresh_crash(harness, count, record, stage):
    name = f"fresh{count}-rec{record}-stage{stage}"
    image = new_image(harness.work / f"{name}.img")
    status, serial, captured, _ = harness.boot(name, step_word(1, count, record, stage), image)
    expect_stop(name, status, serial, stage)
    committed = record if stage == 7 else record - 1
    outcome = "Clean" if stage == 7 else "RecoveredThroughValidPrefix"
    if stage != 7 and committed == 0:
        outcome = "Refused"
    damage = STAGES[stage][1]
    next_verdict = "INDETERMINATE" if outcome == "Refused" else "ABSENT"
    scan = check_recovery(name, harness, image, committed, outcome, damage, next_verdict)
    require_acks_survive(name, acknowledged(captured), scan["captured"], scan)
    return name, image, scan


def scenario_fresh_clean(harness, count):
    name = f"fresh{count}-clean"
    image = new_image(harness.work / f"{name}.img")
    status, serial, captured, _ = harness.boot(name, step_word(1, count), image)
    expect_orderly(name, status, serial, captured, 1)
    require(f"PULSE APPEND seq={count} " in captured, f"{name}: final append missing")
    require("PULSE RUNTIME standing=Unknown binding=Unbound events=" in captured,
            f"{name}: real runtime history line missing")
    _, flushes = block_counters(serial)
    # One flush formats the layout, one syncs the empty journal, one its
    # directory, then two per record.
    require(flushes == 3 + 2 * count, f"{name}: {flushes} device flushes, expected {3 + 2 * count}")
    scan = check_recovery(name, harness, image, count, "Clean", None)
    require_acks_survive(name, acknowledged(captured), scan["captured"], scan)
    require(scan["observed"] == acknowledged(captured)[-1][2], f"{name}: clean extent != last ack")
    return name, image, scan


def mutate(image, offset, data):
    with open(image, "r+b") as handle:
        handle.seek(offset)
        handle.write(data)


def damage(image, offset):
    """Inverts one byte: unlike writing a constant, this always changes the
    image, so a digest byte that already held that constant cannot leave a
    record intact (a 1-in-256 no-op per record, seen once as an activation
    record surviving "both-damaged")."""
    with open(image, "r+b") as handle:
        handle.seek(offset)
        byte = handle.read(1)
        handle.seek(offset)
        handle.write(bytes([byte[0] ^ 0xff]))


def layout(image):
    regions = absd_image.parse_layout(image, DEVICE_SECTORS)
    require(regions is not None, f"{image}: unformatted")
    return regions


def ledger_base(image):
    return absd_image.region_of_kind(layout(image), absd_image.KIND_LEDGER).offset


def mutate_ledger(image, offset, data):
    """Offsets from the workload are ledger-relative; the ledger is one
    bounded region of the layout, so translate through the parsed descriptor."""
    mutate(image, ledger_base(image) + offset, data)


def scenario_mutations(harness):
    """Damage the tested model cannot produce: interior corruption, garbage,
    and an operator-style truncation."""
    name = "mutate-base"
    image = new_image(harness.work / "mutate.img")
    status, serial, captured, _ = harness.boot(name, step_word(1, 3), image)
    expect_orderly(name, status, serial, captured, 1)
    scan = check_recovery(name, harness, image, 3, "Clean", None)
    end = scan["observed"]

    mutate_ledger(image, end, b"\xab" * 8)
    check_recovery("garbage-short", harness, image, 3, "RecoveredThroughValidPrefix", "UnexpectedTrailingBytes")
    mutate_ledger(image, end, b"\x00" * 8)
    check_recovery("garbage-repaired", harness, image, 3, "Clean", None)

    mutate_ledger(image, end, b"\xab" * 200)
    check_recovery("garbage-long", harness, image, 3, "Refused", "InteriorCorruption", "INDETERMINATE")
    mutate_ledger(image, end, b"\x00" * 200)

    # Zero the last record's commit marker: the frame stays complete.
    mutate_ledger(image, end - COMMIT_BYTES, b"\x00" * COMMIT_BYTES)
    check_recovery("commit-lost", harness, image, 2, "RecoveredThroughValidPrefix", "UncommittedSuffix")

    # Operator repair: drop the uncommitted suffix, then the journal is clean
    # and appendable again.
    status, serial, captured, _ = harness.boot("commit-lost.continue", step_word(3, 1), image)
    require(status == 7 and "PULSE JOURNAL NOT APPENDABLE" in captured,
            f"commit-lost.continue: torn journal was appendable (status {status})")
    scan = scan_fields(harness.boot("commit-lost.rescan", step_word(2), image)[2])
    require_repair_boundary(image, scan["valid_prefix"])
    mutate_ledger(image, scan["valid_prefix"], b"\x00" * (end - scan["valid_prefix"]))
    check_recovery("commit-lost.repaired", harness, image, 2, "Clean", None)
    status, serial, captured, _ = harness.boot("commit-lost.append", step_word(3, 2), image)
    expect_orderly("commit-lost.append", status, serial, captured, 3)
    check_recovery("commit-lost.appended", harness, image, 4, "Clean", None)

    # Flip one payload byte of the first record: interior corruption refuses
    # everything, including the records that follow.
    flip = HEADER_BYTES + 10
    with open(image, "rb") as handle:
        handle.seek(ledger_base(image) + flip)
        original = handle.read(1)
    mutate_ledger(image, flip, bytes([original[0] ^ 0x20]))
    check_recovery("payload-flip", harness, image, 0, "Refused", "InteriorCorruption", "INDETERMINATE")
    mutate_ledger(image, flip, original)
    check_recovery("payload-restored", harness, image, 4, "Clean", None)


def generations(serial):
    """(generation, pid, status) for every worker init started in one boot."""
    found = []
    for match in re.finditer(rb"DURABLE WORKER OUTCOME generation=(\d+) pid=(\d+) status=(-?\d+)", serial):
        found.append((int(match.group(1)), int(match.group(2)), int(match.group(3))))
    return found


def expect_generations(name, serial, statuses):
    seen = generations(serial)
    # One worker at a time: every generation's outcome precedes the next
    # generation's start. That sequencing is init's exclusive-writer rule
    # for the device.
    # An abrupt machine stop can leave only the last generation without an
    # outcome line; every earlier one must have ended before its successor.
    starts = [m.start() for m in re.finditer(rb"DURABLE WORKER GENERATION generation=", serial)]
    ends = [m.start() for m in re.finditer(rb"DURABLE WORKER OUTCOME generation=", serial)]
    require(len(starts) - len(ends) in (0, 1) and all(e < s for e, s in zip(ends, starts[1:])),
            f"{name}: worker generations overlapped")
    require([status for _, _, status in seen] == statuses,
            f"{name}: worker outcomes {seen}, expected statuses {statuses}")
    pids = [pid for _, pid, _ in seen]
    require(len(set(pids)) == len(pids), f"{name}: worker PIDs repeat: {pids}")
    require([g for g, _, _ in seen] == list(range(1, len(seen) + 1)), f"{name}: generations {seen}")
    return seen


def scenario_process_then_machine(harness):
    """Worker 1 dies after record 2 is acknowledged; init's replacement
    resumes from the journal alone, appends record 3, and the machine is
    lost during record 4. A fresh boot recovers 1..3, then a fresh worker
    continues after the documented operator repair."""
    name = "process-machine"
    image = new_image(harness.work / f"{name}.img")
    step = step_word(4, count=4, record=4, stage=5, abort_record=2, abort_stage=ABORT_AFTER_ACK)
    status, serial, captured, _ = harness.boot(name, step, image)
    expect_stop(name, status, serial, 5)
    expect_generations(name, serial, [WORKER_ABORT_STATUS])
    require("PULSE WORKER ABORT seq=2 at=Acknowledged\n" in captured, f"{name}: abort line missing")
    require("PULSE WORKER RESUMED prefix=2\n" in captured, f"{name}: replacement did not resume")
    # The replacement's own acknowledgement lines may not be relayed before
    # the abrupt stop; the recovery boot below is the evidence for record 3.
    check_recovery(name, harness, image, 3, "RecoveredThroughValidPrefix", "UncommittedSuffix")
    scan = scan_fields(harness.boot(name + ".rescan", step_word(2), image)[2])
    require_repair_boundary(image, scan["valid_prefix"])
    mutate_ledger(image, scan["valid_prefix"], b"\x00" * (scan["observed"] - scan["valid_prefix"]))
    status, serial, captured, _ = harness.boot(name + ".continue", step_word(3, count=2), image)
    expect_orderly(name + ".continue", status, serial, captured, 3)
    check_recovery(name + ".continued", harness, image, 5, "Clean", None)

    # A worker that dies with its commit marker synced but unacknowledged
    # leaves a committed record; the replacement must resume after it.
    name = "process-unacked"
    image = new_image(harness.work / f"{name}.img")
    step = step_word(4, count=3, abort_record=2, abort_stage=7)
    status, serial, captured, _ = harness.boot(name, step, image)
    expect_orderly(name, status, serial, captured, 4)
    expect_generations(name, serial, [WORKER_ABORT_STATUS, 0])
    require("PULSE WORKER RESUMED prefix=2\n" in captured, f"{name}: unacknowledged commit not resumed")
    check_recovery(name, harness, image, 3, "Clean", None)

    # A worker that dies mid-frame leaves a torn tail the replacement must
    # refuse rather than silently truncate.
    name = "process-torn"
    image = new_image(harness.work / f"{name}.img")
    step = step_word(4, count=3, abort_record=2, abort_stage=2)
    status, serial, captured, _ = harness.boot(name, step, image)
    require(status == 7, f"{name}: status {status}, expected failed workload 7")
    expect_generations(name, serial, [WORKER_ABORT_STATUS, 96])
    require("PULSE JOURNAL NOT APPENDABLE" in captured, f"{name}: torn tail was appendable")
    check_recovery(name, harness, image, 1, "RecoveredThroughValidPrefix", "TruncatedPayload")


def scenario_stress(harness, rounds):
    """Bounded append / stop / recover / replace cycle on one image. Every
    recovery must show contiguous sequences and unique identities, and the
    region must stay within the journal's own file bound."""
    name = "stress"
    image = new_image(harness.work / f"{name}.img")
    status, serial, captured, _ = harness.boot(name, step_word(1, count=2), image)
    expect_orderly(name, status, serial, captured, 1)
    committed = 2
    ids = {}

    def recover(label, outcome, damage):
        nonlocal committed
        _, _, captured, _ = harness.boot(label, step_word(2), image)
        scan = scan_fields(captured)
        require(scan["outcome"] == outcome and scan["damage"] == damage,
                f"{label}: {scan}, expected {outcome}/{damage}")
        require(scan["records"] == committed, f"{label}: {scan['records']} records, expected {committed}")
        for match in re.finditer(r"DURABLE VERDICT seq=(\d+) COMMITTED kind=\w+ id=(\S+)", captured):
            sequence, identity = int(match.group(1)), match.group(2)
            require(ids.setdefault(sequence, identity) == identity,
                    f"{label}: seq {sequence} identity changed")
        require(sorted(ids) == list(range(1, committed + 1)), f"{label}: sequences {sorted(ids)}")
        require(len(set(ids.values())) == committed, f"{label}: duplicate identities")
        require(scan["observed"] <= 2 * 1024 * 1024, f"{label}: region exceeds bound")
        return scan

    recover(f"{name}.r0", "Clean", None)
    for round_index in range(rounds):
        stage = 1 + round_index % 7
        label = f"{name}.round{round_index}"
        # append two clean records
        status, serial, captured, _ = harness.boot(label + ".append", step_word(3, count=2), image)
        expect_orderly(label + ".append", status, serial, captured, 3)
        committed += 2
        recover(label + ".r1", "Clean", None)
        # worker replacement on the live journal: dies after one acked record
        step = step_word(6, count=committed + 2, abort_record=committed + 1, abort_stage=ABORT_AFTER_ACK)
        status, serial, captured, _ = harness.boot(label + ".replace", step, image)
        expect_orderly(label + ".replace", status, serial, captured, 6)
        expect_generations(label + ".replace", serial, [WORKER_ABORT_STATUS, 0])
        committed += 2
        recover(label + ".r2", "Clean", None)
        # machine stop during the next record
        status, serial, _, _ = harness.boot(label + ".stop", step_word(3, count=1, record=committed + 1, stage=stage), image)
        expect_stop(label + ".stop", status, serial, stage)
        if stage == 7:
            committed += 1
            recover(label + ".r3", "Clean", None)
        else:
            scan = recover(label + ".r3", "RecoveredThroughValidPrefix", STAGES[stage][1])
            status, _, captured, _ = harness.boot(label + ".refuse", step_word(3, count=1), image)
            require(status == 7 and "PULSE JOURNAL NOT APPENDABLE" in captured,
                    f"{label}: torn journal accepted appends (status {status})")
            require_repair_boundary(image, scan["valid_prefix"])
            mutate_ledger(image, scan["valid_prefix"], b"\x00" * (scan["observed"] - scan["valid_prefix"]))
            recover(label + ".r4", "Clean", None)
    print(f"  stress: rounds={rounds} committed={committed} identities={len(set(ids.values()))}")


def scenario_continue_after_crash(harness):
    """Clean crash after commit sync, then append across the restart."""
    name, image, _ = scenario_fresh_crash(harness, 3, 2, 7)
    status, serial, captured, _ = harness.boot(name + ".continue", step_word(3, 2, 4, 5), image)
    expect_stop(name + ".continue", status, serial, 5)
    check_recovery(name + ".continued", harness, image, 3, "RecoveredThroughValidPrefix", "UncommittedSuffix")


# ---------------------------------------------------------------------------
# Generation replacement (AG authority image) scenarios
# ---------------------------------------------------------------------------

KIND_ACT, KIND_LEDGER, KIND_GEN = absd_image.KIND_ACTIVATION, absd_image.KIND_LEDGER, absd_image.KIND_GENERATION


def gen_step(kind, count=0, index=0, point=0, mode=0):
    """kind 8/10: `count` generations, stop at `index` at protocol `point`;
    `mode` 1 reclaims the superseded region, 2 also pre-builds there,
    3 first attempts a hostile build into the active region."""
    return step_word(kind, count=count, record=index, stage=point, abort_stage=mode)


def guest_selection(captured):
    match = re.search(r"AG GENERATION SELECTED gen=(\d+) region=(\d+) seq=(\d+) slot=(\d+) rolled_back=(true|false) newest=(\S+)", captured)
    if match is None:
        if "AG GENERATION REFUSED" in captured:
            return "refused"
        if "AG GENERATION NONE" in captured:
            return None
        fail(f"no selection line:\n{captured}")
    newest = match.group(6)
    newest = None if newest == "None" else int(newest[len("Some("):-1])
    return {"generation": int(match.group(1)), "region": int(match.group(2)),
            "sequence": int(match.group(3)), "slot": int(match.group(4)),
            "rolled_back": match.group(5) == "true", "newest": newest}


def expect_host_and_guest_agree(name, image, captured):
    """The host applies the recovery rule to the raw bytes; the guest must
    report the same generation, region, sequence, rollback, and newest."""
    host = absd_image.select(image, layout(image))
    guest = guest_selection(captured)
    if host["refused"]:
        require(guest == "refused", f"{name}: host refuses, guest said {guest}")
        return None
    if host["selected"] is None:
        require(guest is None, f"{name}: host has no generation, guest said {guest}")
        return None
    generation, region, sequence, slot = host["selected"]
    require(isinstance(guest, dict), f"{name}: guest {guest}, host {host['selected']}")
    require((guest["generation"], guest["region"], guest["sequence"], guest["slot"]) == (generation, region, sequence, slot),
            f"{name}: guest {guest} != host {host['selected']}")
    require(guest["rolled_back"] == host["rolled_back"], f"{name}: rollback flag differs")
    require(guest["newest"] == host["newest"], f"{name}: newest differs {guest['newest']} vs {host['newest']}")
    return host


def gen_recover(harness, name, image, expect_generation, expect_rolled_back=False, expect_newest=None):
    status, serial, captured, log = harness.boot(name, step_word(9), image)
    writes, flushes = block_counters(serial)
    require(writes == 0 and flushes == 0, f"{name}: generation recovery wrote {writes} sectors")
    host = expect_host_and_guest_agree(name, image, captured)
    if expect_generation == "refused":
        require(status == 7 and host is None and "AG GENERATION REFUSED" in captured,
                f"{name}: expected refusal, status {status}")
        require("GENERATION RECOVERY OK" not in captured, f"{name}: recovery claimed after refusal")
        print(f"  {name}: refused (indeterminate) log={log.name}")
        return None
    expect_orderly(name, status, serial, captured, 9)
    require(host is not None and host["selected"][0] == expect_generation,
            f"{name}: selected {host and host['selected']}, expected generation {expect_generation}")
    require(host["rolled_back"] == expect_rolled_back, f"{name}: rolled_back {host['rolled_back']}")
    if expect_newest is not None:
        require(host["newest"] == expect_newest, f"{name}: newest {host['newest']} != {expect_newest}")
    require(f"GENERATION RECOVERY OK gen={expect_generation}\n" in captured, f"{name}: recovery marker")
    require(re.search(rf"AG AUTHORITY GENERATION OK gen={expect_generation} admitted={expect_generation} witness=sha256:", captured),
            f"{name}: real AG admission proof missing")
    print(f"  {name}: selected gen={expect_generation} region={host['selected'][1]} seq={host['selected'][2]} "
          f"rolled_back={host['rolled_back']} newest={host['newest']} log={log.name}")
    return host


def gen_init(harness, name, image):
    status, serial, captured, _ = harness.boot(name, step_word(7), image)
    expect_orderly(name, status, serial, captured, 7)
    require("MULTI REGION LAYOUT OK\n" in captured and "GENERATION ACTIVATE OK gen=1\n" in captured,
            f"{name}: init markers missing:\n{captured}")
    regions = layout(image)
    kinds = sorted(r.kind for r in regions)
    require(kinds == [KIND_ACT, KIND_LEDGER, KIND_GEN, KIND_GEN] + [absd_image.KIND_LOG] * 4 + [absd_image.KIND_FS], f"{name}: layout kinds {kinds}")
    host = absd_image.select(image, regions)
    require(host["selected"] and host["selected"][0] == 1, f"{name}: host selection {host}")
    return regions


def gen_regions(image):
    regions = layout(image)
    return absd_image.region_of_kind(regions, KIND_ACT), [r for r in regions if r.kind == KIND_GEN]


def expect_gen_stop(name, status, serial, point):
    code = GENERATION_STOP_BASE + point
    require(status == 4 * code + 3, f"{name}: status {status}, expected stop {4 * code + 3}")
    require(f"MACHINE STOP code={code}\n".encode() in serial, f"{name}: MACHINE STOP missing")


def scenario_layout(harness):
    name = "layout"
    image = new_image(harness.work / f"{name}.img")
    regions = gen_init(harness, name, image)
    # Independent bounds: sector 0 is no region, regions are disjoint and
    # inside the device (parse_layout checks), and the descriptor identity
    # is bound to the device size: the same bytes on another size refuse.
    try:
        absd_image.parse_layout(image, DEVICE_SECTORS * 2)
        fail("layout accepted for a different device size")
    except ValueError:
        pass
    gen_recover(harness, name + ".recover", image, 1)
    # Corrupt the descriptor: one byte in the region table. Every consumer
    # must refuse; nothing may guess a layout.
    original = absd_image.read_sector(image, 0)
    mutate(image, 30, bytes([original[30] ^ 0x01]))
    status, serial, captured, _ = harness.boot(name + ".descriptor-corrupt", step_word(9), image)
    require(status == 7 and "Device(-22)" in captured, f"{name}: corrupt descriptor accepted: {captured}")
    # The journal scan sees no ledger at all: an I/O failure is a refused,
    # indeterminate scan, read-only, never a guessed layout.
    status, serial, captured, _ = harness.boot(name + ".descriptor-corrupt-journal", step_word(2), image)
    writes, flushes = block_counters(serial)
    require(status == 3 and "damage=Some(IoFailure)" in captured and "DURABLE UNKNOWN OK\n" in captured
            and "PULSE DURABLE JOURNAL OK" not in captured and writes == 0 and flushes == 0,
            f"{name}: journal ignored corrupt descriptor: {captured}")
    mutate(image, 0, original)
    # Overlapping regions with a valid checksum: refuse.
    sector = bytearray(original)
    import struct
    struct.pack_into("<Q", sector, 24 + 2 * 32 + 8, 20)  # region 3 first := 20, overlaps the ledger
    struct.pack_into("<Q", sector, 512 - 8, absd_image.fnv1a(bytes(sector[:504])))
    mutate(image, 0, bytes(sector))
    try:
        absd_image.parse_layout(image, DEVICE_SECTORS)
        fail("host parser accepted overlapping regions")
    except ValueError:
        pass
    status, serial, captured, _ = harness.boot(name + ".overlap", step_word(9), image)
    require(status == 7 and "Device(-22)" in captured, f"{name}: overlapping layout accepted")
    # Refusals the guest must make on its own, each with a valid checksum:
    # a descriptor written for another device size, and a table that is
    # not the v1 table (generation regions renumbered, so every activation
    # record would name the other slot).
    for label, edit in (("other-size", lambda s: struct.pack_into("<Q", s, 16, DEVICE_SECTORS * 2)),
                        ("renumbered", lambda s: (struct.pack_into("<I", s, 24 + 2 * 32, 4),
                                                  struct.pack_into("<I", s, 24 + 3 * 32, 3)))):
        sector = bytearray(original)
        edit(sector)
        struct.pack_into("<Q", sector, 512 - 8, absd_image.fnv1a(bytes(sector[:504])))
        mutate(image, 0, bytes(sector))
        try:
            absd_image.parse_layout(image, DEVICE_SECTORS)
            fail(f"host parser accepted the {label} descriptor")
        except ValueError:
            pass
        status, serial, captured, _ = harness.boot(f"{name}.{label}", step_word(9), image)
        require(status == 7 and "Device(-22)" in captured, f"{name}: {label} descriptor accepted: {captured}")
    # A lost descriptor over surviving state: formatting must refuse and
    # leave sector 0 zero, never turn stale activation records, generations,
    # or ledger bytes into believed state.
    mutate(image, 0, bytes(512))
    for label, step in (("stale-format", step_word(7)), ("stale-format-journal", step_word(1, count=1))):
        status, serial, captured, _ = harness.boot(f"{name}.{label}", step, image)
        require("PULSE JOURNAL STEP OK" not in captured and "MULTI REGION LAYOUT FORMATTED" not in captured,
                f"{name}: {label} formatted over stale state: {captured}")
        require(absd_image.read_sector(image, 0) == bytes(512), f"{name}: {label} wrote a descriptor over stale state")
    mutate(image, 0, original)
    gen_recover(harness, name + ".restored", image, 1)
    print("  MULTI REGION LAYOUT OK")
    print("  REGION BOUNDS OK")


def scenario_activation_matrix(harness):
    """Stop at every protocol point while replacing generation 1 by 2."""
    for point, label in POINTS.items():
        name = f"activate-{point}-{label}"
        image = new_image(harness.work / f"{name}.img")
        gen_init(harness, name, image)
        mode = {8: 1, 9: 2}.get(point, 0)
        status, serial, captured, _ = harness.boot(name, gen_step(8, count=1, index=1, point=point, mode=mode), image)
        expect_gen_stop(name, status, serial, point)
        # Expected selection from the protocol, checked against the bytes.
        expected = 1 if point <= 5 else 2
        newest = {1: 1, 2: 1, 3: 1, 4: 2, 5: 2, 6: 2, 7: 2, 8: 2, 9: 3}[point]
        host = absd_image.select(image, layout(image))
        require(host["selected"] and host["selected"][0] == expected, f"{name}: host {host}")
        gen_recover(harness, name + ".recover", image, expected, expect_newest=newest)
        # The survivor must remain a base for the next replacement.
        status, serial, captured, _ = harness.boot(name + ".advance", gen_step(8, count=1), image)
        expect_orderly(name + ".advance", status, serial, captured, 8)
        gen_recover(harness, name + ".advanced", image, expected + 1)
    print("  GENERATION CRASH MATRIX OK")
    print("  LAST GOOD GENERATION OK")


def scenario_corruption(harness):
    name = "corrupt"
    image = new_image(harness.work / f"{name}.img")
    gen_init(harness, name, image)
    status, serial, captured, _ = harness.boot(name + ".advance", gen_step(8, count=1), image)
    expect_orderly(name + ".advance", status, serial, captured, 8)
    activation, gens = gen_regions(image)
    host = absd_image.select(image, layout(image))
    gen2_region = absd_image.region_by_id(layout(image), host["selected"][1])
    gen1_region = next(r for r in gens if r.id != gen2_region.id)
    newest_slot = host["selected"][3]
    older_slot = 1 - newest_slot
    require(host["selected"][0] == 2, f"{name}: base is not generation 2")
    snapshot = absd_image.read_bytes(image, 0, IMAGE_BYTES)

    def restore():
        mutate(image, 0, snapshot)

    # corrupt newest generation body: roll back to 1
    mutate(image, gen2_region.offset + 512 + 5, b"\xff")
    gen_recover(harness, name + ".body", image, 1, expect_rolled_back=True, expect_newest=2)
    # advance from the rollback: activation must not overwrite the record
    # of the selected generation, so the next corruption still falls back
    status, serial, captured, _ = harness.boot(name + ".body-advance", gen_step(8, count=1), image)
    expect_orderly(name + ".body-advance", status, serial, captured, 8)
    after = gen_recover(harness, name + ".body-advanced", image, 2, expect_newest=2)
    fallback = [s[1] for s in after["slots"] if s[0] == "record" and s[2] is None and s[1]["region"] == gen1_region.id]
    require(len(fallback) == 1 and fallback[0]["generation"] == 1,
            f"{name}: advance after rollback discarded the fallback record: {after['slots']}")
    mutate(image, gen2_region.offset + 512 + 5, b"\xff")
    gen_recover(harness, name + ".body-again", image, 1, expect_rolled_back=True, expect_newest=2)
    restore()
    # corrupt newest generation header
    mutate(image, gen2_region.offset + 40, b"\x00\x00")
    gen_recover(harness, name + ".header", image, 1, expect_rolled_back=True, expect_newest=2)
    restore()
    # corrupt the newest activation record: older record still validates
    damage(image, activation.offset + newest_slot * 512 + 70)
    gen_recover(harness, name + ".activation", image, 1, expect_newest=2)
    print("  TORN ACTIVATION FALLBACK OK")
    restore()
    # stale activation: older record copied over the newer slot
    older = absd_image.read_sector(image, activation.first + older_slot)
    mutate(image, activation.offset + newest_slot * 512, older)
    gen_recover(harness, name + ".stale", image, 1, expect_newest=2)
    restore()
    # explicit rollback activation to the older generation, with a higher
    # sequence: selected 1, newest observed 2, not a rollback by evidence
    gen1, _ = absd_image.parse_generation(image, gen1_region)
    record = absd_image.encode_activation(host["selected"][2] + 1, gen1_region.id, 1, gen1["digest"])
    mutate(image, activation.offset + older_slot * 512, record)
    gen_recover(harness, name + ".rollback-record", image, 1, expect_newest=2)
    restore()
    # garbage in the inactive region: irrelevant to selection
    mutate(image, gen1_region.offset + 512 * 3, b"\xa5" * 512)
    gen_recover(harness, name + ".inactive-garbage", image, 2)
    restore()
    # activation naming a non-generation region (the ledger): unusable
    record = absd_image.encode_activation(host["selected"][2] + 1, absd_image.region_of_kind(layout(image), KIND_LEDGER).id, 2, absd_image.parse_generation(image, gen2_region)[0]["digest"])
    mutate(image, activation.offset + older_slot * 512, record)
    # the newer record is skipped, so this is a rollback past unusable evidence
    gen_recover(harness, name + ".alias-ledger", image, 2, expect_rolled_back=True, expect_newest=2)
    restore()
    # both activation records damaged: refuse, never guess from headers
    damage(image, activation.offset + 70)
    damage(image, activation.offset + 512 + 70)
    gen_recover(harness, name + ".both-damaged", image, "refused")
    restore()
    # both generations intact, both activations empty: no generation, and
    # the workload must not resurrect one from headers alone
    mutate(image, activation.offset, bytes(1024))
    status, serial, captured, _ = harness.boot(name + ".no-activation", step_word(9), image)
    expect_orderly(name + ".no-activation", status, serial, captured, 9)
    require("AG GENERATION ABSENT\n" in captured and "GENERATION RECOVERY OK" not in captured,
            f"{name}: generation resurrected without activation")
    restore()
    gen_recover(harness, name + ".restored", image, 2)


def scenario_reuse(harness, rounds):
    """Alternating reuse with stops at body-complete, activation-written and
    reclaim-partial points; the selected generation never regresses below
    the last activated one, and regions alternate."""
    name = "reuse"
    image = new_image(harness.work / f"{name}.img")
    gen_init(harness, name, image)
    # Hostile: a build into the selected region must be refused.
    status, serial, captured, _ = harness.boot(name + ".hostile", gen_step(8, count=1, mode=3), image)
    expect_orderly(name + ".hostile", status, serial, captured, 8)
    require("GENERATION RECLAIM REFUSED region=" in captured, f"{name}: active region reuse not refused")
    current = 2
    last_region = absd_image.select(image, layout(image))["selected"][1]
    points = [3, 6, 8, 4, 7, 2]
    for round_index in range(rounds):
        point = points[round_index % len(points)]
        label = f"{name}.r{round_index}"
        status, serial, _, _ = harness.boot(label + ".stop", gen_step(8, count=1, index=1, point=point, mode=1), image)
        expect_gen_stop(label + ".stop", status, serial, point)
        if point >= 6:
            current += 1
        host = gen_recover(harness, label + ".recover", image, current)
        region = host["selected"][1]
        if point >= 6:
            require(region != last_region, f"{label}: region did not alternate")
            last_region = region
        else:
            require(region == last_region, f"{label}: survivor moved regions")
        # finish the round cleanly (with reclamation) and verify again
        status, serial, captured, _ = harness.boot(label + ".finish", gen_step(8, count=1, mode=1), image)
        expect_orderly(label + ".finish", status, serial, captured, 8)
        current += 1
        host = gen_recover(harness, label + ".verify", image, current)
        require(host["selected"][1] != last_region, f"{label}: finish did not alternate")
        last_region = host["selected"][1]
        # the superseded region was reclaimed: header zero
        activation, gens = gen_regions(image)
        other = next(r for r in gens if r.id != last_region)
        require(absd_image.read_sector(image, other.first) == bytes(512), f"{label}: superseded header not reclaimed")
    print(f"  reuse: rounds={rounds} final_generation={current}")
    print("  GENERATION REUSE OK")
    print("  GENERATION RECLAIM BOUNDARY OK")


def scenario_isolation(harness):
    """Pulse ledger and AG image on one device: neither boot touches the
    other's bytes, and damage to one is invisible to the other."""
    name = "isolation"
    image = new_image(harness.work / f"{name}.img")
    status, serial, captured, _ = harness.boot(name + ".journal", step_word(1, count=2), image)
    expect_orderly(name + ".journal", status, serial, captured, 1)
    regions = layout(image)
    ledger = absd_image.region_of_kind(regions, KIND_LEDGER)
    gens = [r for r in regions if r.kind == KIND_GEN]
    activation = absd_image.region_of_kind(regions, KIND_ACT)
    before = absd_image.region_hash(image, ledger)
    gen_init(harness, name + ".ag", image)
    # no reclamation here: generation 2 must survive as the rollback target
    status, serial, captured, _ = harness.boot(name + ".ag-advance", gen_step(8, count=2), image)
    expect_orderly(name + ".ag-advance", status, serial, captured, 8)
    require(absd_image.region_hash(image, ledger) == before, f"{name}: AG boots changed the ledger region")
    ag_hashes = [absd_image.region_hash(image, r) for r in gens] + [absd_image.region_hash(image, activation)]
    status, serial, captured, _ = harness.boot(name + ".journal-append", step_word(3, count=2), image)
    expect_orderly(name + ".journal-append", status, serial, captured, 3)
    check_recovery(name + ".journal-recover", harness, image, 4, "Clean", None)
    require([absd_image.region_hash(image, r) for r in gens] + [absd_image.region_hash(image, activation)] == ag_hashes,
            f"{name}: journal boots changed AG regions")
    # damage the AG image: the journal is unaffected and vice versa
    snapshot = absd_image.read_bytes(image, 0, IMAGE_BYTES)
    host = absd_image.select(image, regions)
    active = absd_image.region_by_id(regions, host["selected"][1])
    mutate(image, active.offset + 512 + 3, b"\x00" * 16)
    check_recovery(name + ".journal-after-ag-damage", harness, image, 4, "Clean", None)
    gen_recover(harness, name + ".ag-after-damage", image, 2, expect_rolled_back=True, expect_newest=3)
    mutate(image, 0, snapshot)
    scan = check_recovery(name + ".base", harness, image, 4, "Clean", None)
    mutate_ledger(image, scan["observed"] - 20, b"\xee" * 20)
    check_recovery(name + ".journal-damaged", harness, image, 3, "Refused", "InteriorCorruption", "INDETERMINATE")
    gen_recover(harness, name + ".ag-after-journal-damage", image, 3)
    mutate(image, 0, snapshot)
    print("  SECOND DURABLE CONSUMER OK consumer=ag-authority")
    print("  CROSS REGION ISOLATION OK")


def scenario_composition(harness):
    """Worker replacement, journal recovery, and generation activation on one
    image, with every identity checked to be distinct."""
    name = "compose"
    image = new_image(harness.work / f"{name}.img")
    gen_init(harness, name + ".gen1", image)
    step = step_word(4, count=3, abort_record=2, abort_stage=ABORT_AFTER_ACK)
    status, serial, captured, _ = harness.boot(name + ".workers", step, image)
    expect_orderly(name + ".workers", status, serial, captured, 4)
    gens = expect_generations(name + ".workers", serial, [WORKER_ABORT_STATUS, 0])
    status, serial, captured, _ = harness.boot(name + ".candidate-lost", gen_step(8, count=1, index=1, point=4), image)
    expect_gen_stop(name + ".candidate-lost", status, serial, 4)
    gen_recover(harness, name + ".chooses-1", image, 1, expect_newest=2)
    check_recovery(name + ".journal-clean", harness, image, 3, "Clean", None)
    status, serial, captured, _ = harness.boot(name + ".rebuild", gen_step(10, count=2, index=1, point=7), image)
    expect_gen_stop(name + ".rebuild", status, serial, 7)
    gen_recover(harness, name + ".chooses-2", image, 2)
    scan = check_recovery(name + ".journal-after", harness, image, 5, "Clean", None)
    acts = absd_image.select(image, layout(image))
    seqs = {int(m.group(1)) for m in re.finditer(r"DURABLE VERDICT seq=(\d+) COMMITTED", scan["captured"])}
    pids = {pid for _, pid, _ in gens}
    identities = {"worker_pids": pids, "worker_generations": {g for g, _, _ in gens},
                  "journal_sequences": seqs, "persistent_generation": {acts["selected"][0]},
                  "activation_sequence": {acts["selected"][2]}}
    print(f"  compose: {identities}")
    require(len(pids) == 2 and seqs == {1, 2, 3, 4, 5} and acts["selected"][0] == 2 and acts["selected"][2] == 2,
            f"{name}: identities {identities}")
    print("  PROCESS JOURNAL GENERATION RECOVERY OK")


def scenario_multi_stress(harness, rounds):
    name = "mstress"
    image = new_image(harness.work / f"{name}.img")
    status, serial, captured, _ = harness.boot(name + ".journal", step_word(1, count=2), image)
    expect_orderly(name + ".journal", status, serial, captured, 1)
    gen_init(harness, name + ".gen", image)
    committed, generation = 2, 1
    regions = layout(image)
    ledger = absd_image.region_of_kind(regions, KIND_LEDGER)
    for round_index in range(rounds):
        label = f"{name}.r{round_index}"
        point = [6, 3, 8, 7][round_index % 4]
        # journal append + generation advance with a stop
        status, serial, _, _ = harness.boot(label + ".mixed", gen_step(10, count=1, index=1, point=point, mode=1), image)
        expect_gen_stop(label + ".mixed", status, serial, point)
        committed += 1
        if point >= 6:
            generation += 1
        gen_recover(harness, label + ".gen", image, generation)
        check_recovery(label + ".journal", harness, image, committed, "Clean", None)
        ledger_hash = absd_image.region_hash(image, ledger)
        # worker replacement on the journal; AG regions must not move
        ag_before = [absd_image.region_hash(image, r) for r in regions if r.kind != KIND_LEDGER]
        step = step_word(6, count=committed + 2, abort_record=committed + 1, abort_stage=ABORT_AFTER_ACK)
        status, serial, captured, _ = harness.boot(label + ".replace", step, image)
        expect_orderly(label + ".replace", status, serial, captured, 6)
        committed += 2
        require([absd_image.region_hash(image, r) for r in regions if r.kind != KIND_LEDGER] == ag_before,
                f"{label}: journal workers touched AG regions")
        require(absd_image.region_hash(image, ledger) != ledger_hash, f"{label}: ledger unchanged after appends")
        check_recovery(label + ".journal2", harness, image, committed, "Clean", None)
        gen_recover(harness, label + ".gen2", image, generation)
        require(absd_image.read_bytes(image, ledger.offset + ledger.bytes - 512, 512) == bytes(512),
                f"{label}: ledger reached its bound")
    print(f"  multi stress: rounds={rounds} committed={committed} generation={generation}")
    print("  MULTI REGION RECOVERY STRESS OK")


# ---------------------------------------------------------------------------
# Log + checkpoint (Route B) scenarios
# ---------------------------------------------------------------------------

LOG_STOP_BASE = 48
LOG_POINTS = {1: "AppendPartial", 2: "AppendWritten", 3: "ReclaimPartial", 4: "SegmentReused"}


def log_step(kind, count=0, index=0, point=0, mode=0, abort_record=0, abort_stage=0):
    return step_word(kind, count=count, record=index, stage=point, abort_stage=mode or abort_stage,
                     abort_record=abort_record)


def expect_log_stop(name, status, serial, point):
    code = LOG_STOP_BASE + point
    require(status == 4 * code + 3, f"{name}: QEMU status {status}, expected log stop {4 * code + 3}")
    require(f"MACHINE STOP code={code}\n".encode() in serial, f"{name}: MACHINE STOP missing")


def host_recovery(image):
    return absd_image.checkpoint_recovery(image, layout(image))


def log_recover(harness, name, image, admitted, checkpoint, replayed):
    """Read-only recovery must match the host's composed rule exactly."""
    status, serial, captured, log = harness.boot(name, step_word(14), image)
    writes, flushes = block_counters(serial)
    require(writes == 0 and flushes == 0, f"{name}: recovery wrote {writes} sectors, flushed {flushes}")
    host = host_recovery(image)
    require(host["refused"] is None, f"{name}: host refuses ({host['refused']}) but a recovery was expected")
    expect_orderly(name, status, serial, captured, 14)
    match = re.search(r"AG RECOVERED admitted=(\d+) checkpoint=(\d+) replayed=(\d+) witness=sha256:", captured)
    require(match is not None, f"{name}: no recovery line:\n{captured}")
    got = tuple(int(match.group(i)) for i in (1, 2, 3))
    require(got == (admitted, checkpoint, replayed), f"{name}: guest {got}, expected {(admitted, checkpoint, replayed)}")
    require((host["checkpoint"], len(host["events"])) == (checkpoint, replayed) and
            host["checkpoint"] + len(host["events"]) == admitted,
            f"{name}: host {host} disagrees with guest {got}")
    require(f"LOG CHECKPOINT RECOVERY OK checkpoint={checkpoint} events={replayed}\n" in captured, f"{name}: marker")
    print(f"  {name}: admitted={admitted} checkpoint={checkpoint} replayed={replayed} log={log.name}")


def log_refuse(harness, name, image, reason_fragment):
    status, serial, captured, log = harness.boot(name, step_word(14), image)
    writes, flushes = block_counters(serial)
    require(writes == 0 and flushes == 0, f"{name}: refusal wrote to the device")
    host = host_recovery(image)
    require(host["refused"] is not None, f"{name}: host recovered {host} but a refusal was expected")
    require(status == 7 and "AG LOG REFUSED" in captured and reason_fragment in captured
            and "LOG CHECKPOINT RECOVERY OK" not in captured,
            f"{name}: expected refusal mentioning {reason_fragment!r}, status {status}:\n{captured}")
    print(f"  {name}: refused ({host['refused']}) log={log.name}")


def log_orderly(harness, name, image, step, kind, marker):
    status, serial, captured, _ = harness.boot(name, step, image)
    expect_orderly(name, status, serial, captured, kind)
    require(marker in captured, f"{name}: {marker!r} missing:\n{captured}")
    return captured


def log_init(harness, name, image, count):
    captured = log_orderly(harness, name, image, log_step(11, count=count), 11, f"AG LOG INIT OK admitted={count}\n")
    require("MULTI REGION LAYOUT OK\n" in captured, f"{name}: layout marker")
    regions = layout(image)
    require(len([r for r in regions if r.kind == absd_image.KIND_LOG]) == 4, f"{name}: log segments")
    return regions


def live_segments(image):
    return absd_image.live_log_segments(image, layout(image))


def scenario_logstore(harness):
    name = "logstore"
    image = new_image(harness.work / f"{name}.img")
    log_init(harness, name, image, 5)
    log_recover(harness, name + ".r0", image, 5, 0, 5)
    log_orderly(harness, name + ".ckpt1", image, log_step(13), 13, "CHECKPOINT ACTIVATION OK covered=5\n")
    log_recover(harness, name + ".r1", image, 5, 5, 0)
    log_orderly(harness, name + ".append", image, log_step(12, count=3), 12, "AG LOG APPEND OK admitted=8\n")
    log_recover(harness, name + ".r2", image, 8, 5, 3)
    # checkpoint with retirement: the segment holding 1..8 is current, so it
    # is rotated out rather than reclaimed; nothing is lost.
    captured = log_orderly(harness, name + ".ckpt2", image, log_step(13, mode=1), 13, "CHECKPOINT ACTIVATION OK covered=8\n")
    require("LOG SEGMENT ROTATED next=9\n" in captured and "LOG PREFIX RECLAIMED" not in captured, f"{name}: rotation")
    log_recover(harness, name + ".r3", image, 8, 8, 0)
    require(len(live_segments(image)) == 2, f"{name}: expected two live segments")
    log_orderly(harness, name + ".append2", image, log_step(12, count=2), 12, "AG LOG APPEND OK admitted=10\n")
    log_recover(harness, name + ".r4", image, 10, 8, 2)
    captured = log_orderly(harness, name + ".ckpt3", image, log_step(13, mode=1), 13, "CHECKPOINT ACTIVATION OK covered=10\n")
    require("LOG PREFIX RECLAIMED region=" in captured, f"{name}: prefix 1..8 was not reclaimed")
    log_recover(harness, name + ".r5", image, 10, 10, 0)
    # the reclaimed segment is zero on the device
    regions = layout(image)
    zeroed = [r for r in regions if r.kind == absd_image.KIND_LOG
              and absd_image.read_bytes(image, r.offset, r.bytes) == bytes(r.bytes)]
    require(len(zeroed) >= 1, f"{name}: no zeroed segment after reclaim")
    print("  LOG COMPACTION OK")


def checkpoint_base(harness, name):
    """init 4 -> checkpoint+rotate (segment A: 1..4, current B) -> append 3 (B: 5..7)."""
    image = new_image(harness.work / f"{name}.img")
    log_init(harness, name + ".init", image, 4)
    log_orderly(harness, name + ".ckpt", image, log_step(13, mode=1), 13, "CHECKPOINT ACTIVATION OK covered=4\n")
    log_orderly(harness, name + ".append", image, log_step(12, count=3), 12, "AG LOG APPEND OK admitted=7\n")
    log_recover(harness, name + ".base", image, 7, 4, 3)
    return image


def scenario_checkpoint_matrix(harness):
    for point in range(1, 10):
        label = POINTS[point]
        name = f"ckpt-{point}-{label}"
        image = checkpoint_base(harness, name)
        status, serial, captured, _ = harness.boot(name, log_step(13, point=point, mode=1), image)
        if point <= 7:
            expect_gen_stop(name, status, serial, point)
        else:
            expect_log_stop(name, status, serial, {8: 3, 9: 4}[point])
        # before activation is durable on the device: old checkpoint + full suffix
        if point <= 5:
            log_recover(harness, name + ".recover", image, 7, 4, 3)
        else:
            log_recover(harness, name + ".recover", image, 7, 7, 0)
        # the survivor must keep working: append and checkpoint again
        log_orderly(harness, name + ".append", image, log_step(12, count=1), 12, "AG LOG APPEND OK admitted=8\n")
        log_orderly(harness, name + ".ckpt", image, log_step(13, mode=1), 13, "CHECKPOINT ACTIVATION OK covered=8\n")
        log_recover(harness, name + ".final", image, 8, 8, 0)
    # point 10: torn append after a checkpoint
    name = "ckpt-10-AppendPartial"
    image = checkpoint_base(harness, name)
    log_orderly(harness, name + ".ckpt", image, log_step(13, mode=1), 13, "CHECKPOINT ACTIVATION OK covered=7\n")
    status, serial, _, _ = harness.boot(name, log_step(12, count=2, index=2, point=1), image)
    expect_log_stop(name, status, serial, 1)
    log_recover(harness, name + ".recover", image, 8, 7, 1)
    status, serial, _, _ = harness.boot(name + ".written", log_step(12, count=1, index=1, point=2), image)
    expect_log_stop(name + ".written", status, serial, 2)
    log_recover(harness, name + ".recover2", image, 9, 7, 2)
    # point 11: a torn append, then a checkpoint with retirement before any
    # further append. Rotation supersedes the torn segment, so it must erase
    # the torn record first or every later recovery refuses.
    name = "ckpt-11-TornRotate"
    image = checkpoint_base(harness, name)
    status, serial, _, _ = harness.boot(name, log_step(12, count=1, index=1, point=1), image)
    expect_log_stop(name, status, serial, 1)
    log_recover(harness, name + ".recover", image, 7, 4, 3)
    captured = log_orderly(harness, name + ".ckpt", image, log_step(13, mode=1), 13, "CHECKPOINT ACTIVATION OK covered=7\n")
    require("LOG SEGMENT ROTATED next=8\n" in captured, f"{name}: rotation")
    log_recover(harness, name + ".rotated", image, 7, 7, 0)
    log_orderly(harness, name + ".append", image, log_step(12, count=1), 12, "AG LOG APPEND OK admitted=8\n")
    log_orderly(harness, name + ".ckpt2", image, log_step(13, mode=1), 13, "LOG PREFIX RECLAIMED region=")
    log_recover(harness, name + ".final", image, 8, 8, 0)
    require(len(live_segments(image)) <= 2, f"{name}: live segments not bounded")
    print("  CHECKPOINT CRASH MATRIX OK")
    print("  LOG PREFIX RETAINED OK")


def scenario_checkpoint_validity(harness):
    name = "ckvalid"
    image = new_image(harness.work / f"{name}.img")
    log_init(harness, name + ".init", image, 4)
    log_orderly(harness, name + ".ckpt1", image, log_step(13), 13, "CHECKPOINT ACTIVATION OK covered=4\n")
    log_orderly(harness, name + ".append", image, log_step(12, count=2), 12, "AG LOG APPEND OK admitted=6\n")
    log_orderly(harness, name + ".ckpt2", image, log_step(13), 13, "CHECKPOINT ACTIVATION OK covered=6\n")
    log_orderly(harness, name + ".append2", image, log_step(12, count=1), 12, "AG LOG APPEND OK admitted=7\n")
    log_recover(harness, name + ".base", image, 7, 6, 1)
    regions = layout(image)
    activation = absd_image.region_of_kind(regions, absd_image.KIND_ACTIVATION)
    sel = absd_image.select(image, regions)
    newest_region = absd_image.region_by_id(regions, sel["selected"][1])
    older_region = next(r for r in regions if r.kind == absd_image.KIND_GENERATION and r.id != newest_region.id)
    newest_slot = sel["selected"][3]
    snapshot = absd_image.read_bytes(image, 0, IMAGE_BYTES)
    restore = lambda: mutate(image, 0, snapshot)
    # corrupt newest checkpoint body -> older checkpoint + full suffix
    mutate(image, newest_region.offset + 512 + 7, b"\xff")
    log_recover(harness, name + ".body", image, 7, 4, 3)
    restore()
    # corrupt newest checkpoint header -> same
    mutate(image, newest_region.offset + 30, b"\x00\x00")
    log_recover(harness, name + ".header", image, 7, 4, 3)
    restore()
    # checkpoint valid but its activation record corrupt -> older
    damage(image, activation.offset + newest_slot * 512 + 70)
    log_recover(harness, name + ".activation", image, 7, 4, 3)
    restore()
    # checkpoint claims more than it contains: a re-signed body with admitted=9
    header, _ = absd_image.parse_generation(image, newest_region)
    import json
    body = json.loads(header["body"].decode())
    body["admitted"] = 9
    forged = json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()
    mutate(image, newest_region.offset + 512, forged + bytes((-len(forged)) % 512))
    mutate(image, newest_region.offset, absd_image.encode_generation_header(header["generation"], forged))
    mutate(image, activation.offset + newest_slot * 512,
           absd_image.encode_activation(sel["selected"][2], newest_region.id, header["generation"], absd_image.sha256(forged)))
    status, serial, captured, _ = harness.boot(name + ".overclaim", step_word(14), image)
    require(status == 7 and "authority image shape" in captured and "LOG CHECKPOINT RECOVERY OK" not in captured,
            f"{name}: over-claiming checkpoint accepted:\n{captured}")
    print(f"  {name}.overclaim: refused (image shape)")
    restore()
    # damaged retained suffix: interior event -> refused; last event -> torn
    log = absd_image.parse_log(image, regions)
    seg = next(r for e, rid in log["live"] for r in regions if r.id == rid)
    parsed = absd_image.parse_segment(image, seg)
    # event 5 is the first record after the checkpoint in this segment layout
    index = 1
    for sequence, body in parsed["events"]:
        if sequence == 5:
            mutate(image, seg.offset + (index + 1) * 512 + 3, b"\xee")
            break
        index += 1 + (len(body) + 511) // 512
    log_refuse(harness, name + ".interior", image, "damaged record followed by more records")
    restore()
    # the last record damaged with its final sector written is not a torn
    # append (sectors land in order): refuse, never erase an acknowledged
    # record
    last_sector = None
    index = 1
    for sequence, body in parsed["events"]:
        if sequence == 7:
            mutate(image, seg.offset + (index + 1) * 512 + 3, b"\xee")
            last_sector = index + (len(body) + 511) // 512
        index += 1 + (len(body) + 511) // 512
    require(last_sector is not None, f"{name}: event 7 not found")
    log_refuse(harness, name + ".tail", image, "final sector was written")
    restore()
    # a lost final sector (all zero) is exactly a torn append under this
    # model: the one damage shape still recovered as uncommitted
    mutate(image, seg.offset + last_sector * 512, bytes(512))
    log_recover(harness, name + ".tail-lost", image, 6, 6, 0)
    restore()
    # the same loss after a checkpoint covered event 7: the log would resume
    # at sequence 7 below the checkpoint and bury the next admission; refuse
    log_orderly(harness, name + ".cover", image, log_step(13), 13, "CHECKPOINT ACTIVATION OK covered=7\n")
    mutate(image, seg.offset + last_sector * 512, bytes(512))
    log_refuse(harness, name + ".behind", image, "does not follow the checkpoint")
    restore()
    # reclaimed prefix with the checkpoints gone: refuse, never restart at 5
    log_orderly(harness, name + ".ckpt3", image, log_step(13, mode=1), 13, "CHECKPOINT ACTIVATION OK covered=7\n")
    log_orderly(harness, name + ".append3", image, log_step(12, count=1), 12, "AG LOG APPEND OK admitted=8\n")
    log_orderly(harness, name + ".ckpt4", image, log_step(13, mode=1), 13, "LOG PREFIX RECLAIMED region=")
    log_recover(harness, name + ".compacted", image, 8, 8, 0)
    mutate(image, activation.offset, bytes(1024))
    log_refuse(harness, name + ".no-checkpoint", image, "prefix")
    print("  CHECKPOINT VALIDITY OK")


def scenario_compaction(harness, rounds):
    name = "compact"
    image = new_image(harness.work / f"{name}.img")
    log_init(harness, name + ".init", image, 3)
    admitted, checkpoint = 3, 0
    points = [3, 6, 8, 9, 0, 2]
    for r in range(rounds):
        label = f"{name}.r{r}"
        point = points[r % len(points)]
        if point:
            status, serial, _, _ = harness.boot(label + ".stop", log_step(13, point=point, mode=1), image)
            if point <= 7:
                expect_gen_stop(label + ".stop", status, serial, point)
            else:
                expect_log_stop(label + ".stop", status, serial, {8: 3, 9: 4}[point])
            if point >= 6:
                checkpoint = admitted
            log_recover(harness, label + ".recover", image, admitted, checkpoint, admitted - checkpoint)
        log_orderly(harness, label + ".ckpt", image, log_step(13, mode=1), 13, f"CHECKPOINT ACTIVATION OK covered={admitted}\n")
        checkpoint = admitted
        log_orderly(harness, label + ".append", image, log_step(12, count=2), 12, f"AG LOG APPEND OK admitted={admitted + 2}\n")
        admitted += 2
        log_recover(harness, label + ".verify", image, admitted, checkpoint, 2)
        live = live_segments(image)
        require(len(live) <= 2, f"{label}: {len(live)} live segments, storage not bounded")
    print(f"  compaction: rounds={rounds} admitted={admitted} checkpoint={checkpoint} live_segments={len(live_segments(image))}")
    print("  CHECKPOINT REUSE OK")
    print("  BOUNDED DURABLE STATE OK")


def scenario_ag_process(harness):
    name = "agproc"
    image = new_image(harness.work / f"{name}.img")
    log_init(harness, name + ".init", image, 2)
    # worker dies after event 4 is acknowledged; the replacement resumes from
    # the device and completes the total of 6
    status, serial, captured, _ = harness.boot(name + ".acked", log_step(15, count=6, abort_record=2, abort_stage=8), image)
    expect_orderly(name + ".acked", status, serial, captured, 15)
    expect_generations(name + ".acked", serial, [WORKER_ABORT_STATUS, 0])
    require("AG WORKER RESUMED admitted=4 replacement=1\n" in captured, f"{name}: resume line:\n{captured}")
    log_recover(harness, name + ".r1", image, 6, 0, 6)
    # worker dies mid-append (header written, body not): uncommitted
    status, serial, captured, _ = harness.boot(name + ".torn", log_step(15, count=8, abort_record=1, abort_stage=1), image)
    expect_orderly(name + ".torn", status, serial, captured, 15)
    expect_generations(name + ".torn", serial, [WORKER_ABORT_STATUS, 0])
    require("AG WORKER RESUMED admitted=6 replacement=1\n" in captured, f"{name}: torn resume:\n{captured}")
    log_recover(harness, name + ".r2", image, 8, 0, 8)
    # checkpoint lost before activation, then machine loss after activation
    status, serial, _, _ = harness.boot(name + ".ckpt-lost", log_step(13, point=4, mode=1), image)
    expect_gen_stop(name + ".ckpt-lost", status, serial, 4)
    log_recover(harness, name + ".r3", image, 8, 0, 8)
    status, serial, _, _ = harness.boot(name + ".ckpt-durable", log_step(13, point=7, mode=1), image)
    expect_gen_stop(name + ".ckpt-durable", status, serial, 7)
    log_recover(harness, name + ".r4", image, 8, 8, 0)
    status, serial, captured, _ = harness.boot(name + ".more", log_step(15, count=10, abort_record=1, abort_stage=8), image)
    expect_orderly(name + ".more", status, serial, captured, 15)
    gens = expect_generations(name + ".more", serial, [WORKER_ABORT_STATUS, 0])
    log_recover(harness, name + ".r5", image, 10, 8, 2)
    host = host_recovery(image)
    require(host["events"] == [9, 10] and len({pid for _, pid, _ in gens}) == 2, f"{name}: identities {host} {gens}")
    print("  AG PROCESS MACHINE RECOVERY OK")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, help="disposable ABSD kernel checkout")
    parser.add_argument("--elf", required=True, help="pulse-journal-std.elf")
    parser.add_argument("--work", required=True, help="scratch directory for images and logs")
    parser.add_argument("--qemu", default="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand")
    parser.add_argument("--quick", action="store_true", help="one crash stage only")
    parser.add_argument("--rounds", type=int, default=4, help="stress rounds")
    parser.add_argument("--only", default="", help="comma-separated scenario names to run alone")
    args = parser.parse_args()
    harness = Harness(args)
    table = [
        ("fresh", "fresh journal, no crash", lambda: scenario_fresh_clean(harness, 3)),
    ]
    stages = [5] if args.quick else list(STAGES)
    for stage in stages:
        table.append((f"stage{stage}", f"stop at record 2 stage {stage} ({STAGES[stage][0]})",
                      lambda stage=stage: scenario_fresh_crash(harness, 3, 2, stage)))
    if not args.quick:
        table += [
            ("first-record", "stop during the first record (no valid prefix)", lambda: scenario_fresh_crash(harness, 3, 1, 2)),
            ("third-record", "stop during the third record after two commits", lambda: scenario_fresh_crash(harness, 3, 3, 3)),
            ("continue", "continue after a clean stop, then stop again", lambda: scenario_continue_after_crash(harness)),
            ("mutations", "content-mutation fixtures", lambda: scenario_mutations(harness)),
            ("process", "worker replacement composed with machine loss", lambda: scenario_process_then_machine(harness)),
            ("stress", "bounded append / stop / recover / replace stress", lambda: scenario_stress(harness, rounds=args.rounds)),
            ("layout", "multi-region layout", lambda: scenario_layout(harness)),
            ("activation", "generation activation crash points", lambda: scenario_activation_matrix(harness)),
            ("corruption", "generation corruption and rollback", lambda: scenario_corruption(harness)),
            ("reuse", "generation reuse and reclamation boundary", lambda: scenario_reuse(harness, rounds=args.rounds)),
            ("isolation", "second consumer isolation", lambda: scenario_isolation(harness)),
            ("compose", "process + journal + generation composition", lambda: scenario_composition(harness)),
            ("mstress", "multi-region stress", lambda: scenario_multi_stress(harness, rounds=args.rounds)),
            ("logstore", "event log with checkpoints and retirement", lambda: scenario_logstore(harness)),
            ("ckpt-matrix", "checkpoint crash points", lambda: scenario_checkpoint_matrix(harness)),
            ("ckpt-validity", "checkpoint and suffix validity", lambda: scenario_checkpoint_validity(harness)),
            ("compaction", "append / checkpoint / reclaim cycles", lambda: scenario_compaction(harness, rounds=args.rounds)),
            ("agproc", "AG worker replacement with checkpoints and machine loss", lambda: scenario_ag_process(harness)),
        ]
    only = {name for name in args.only.split(",") if name}
    scenarios = 0
    for key, title, run in table:
        if only and key not in only:
            continue
        print(f"durable matrix: {title}")
        run()
        scenarios += 1
    print(f"DURABLE MATRIX OK scenarios={scenarios} boots={harness.boots}")


if __name__ == "__main__":
    main()
