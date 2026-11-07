#!/usr/bin/env python3
"""Producer smoke of the amdvi-oracle boot's plumbing (INTERFACE v2 + v3 draft).

Boots `amdvi-oracle=1`, waits for READY, and drives the mailbox over qtest:
SYNC, REVOKE_PAGE of the first granted page, the same REVOKE_PAGE again
(must be REFUSED), RESTART before any device revoke (refused not-revoked),
REVOKE_DEVICE (BME clear), RESTART (set 2, disjoint, BME set), REVOKE_DEVICE,
RESTART (refused CONTAINED_BUT_UNUSABLE, BME clear), SYNC, FINISH. It checks that each command gets
its response line and ack in order, that a non-target DTE and the revoked
target's DTE read back as V=1 TV=0 IR=IW=0, and that after BYE QEMU is
still running and the mailbox readable (the smoke stops QEMU). With
SMOKE_DECOY=<slot> (a second edu at 00:<slot>.0, never armed) it is also the
producer's passthrough test: after READY it forces that function's Bus
Master Enable on from outside and has it copy a pattern into a canary; the
canary must not change. A requester left on passthrough fails it.
SMOKE_CODE=3..7 picks the injected unit-error code (default 5).
SMOKE_MODE=fail|fail-revoke|fail-restart|timeout|overflow instead drives one
failure sequence (fail-revoke/fail-restart: a pending code 5 seen by the next
REVOKE_PAGE or RESTART without SYNC): a code
5 event injected while the target is armed, a runtime completion timeout
(command buffer disabled from outside), or EventOverflow before a device
revoke (contained must stay UNESTABLISHED, the restart still proceeds). It makes no DMA and judges no
containment: that is the independent oracle's (separate lane).
SMOKE_MODE=two-device (#116) adds a QEMU NVMe at 00:07.0 backed by a fixture
image this smoke writes (read-only to QEMU) and checks the second domain:
lines, tables (own root, own deny-all interrupt table), NVMe reads of known
LBAs checked byte for byte in guest RAM, NVMe reads aimed at the edu's
grant, a canary, the device table and unrelated RAM (nothing lands), edu
writes into the NVMe's grant (nothing lands), revoke of either device while
the other keeps working, and the revoked NVMe set unreachable after its
restart. SMOKE_MODE=two-device-ahci (#123; the ISO from
`make amdvi-oracle-ahci-iso`, boot line `amdvi-oracle=1 ahci-disk=absd`)
instead adds an ich9-ahci controller at 00:07.0 with one ide-hd (serial
absd) on the same fixture (snapshot=on: QEMU's ide-hd refuses a read-only
drive, so guest writes, of which there are none, would go to a discarded
overlay; the fixture's hash is checked after the run) and checks the AHCI
domain: GRANT roles and per-page permissions (in the GRANT lines and in the
page tables), DTE, AHCI_READ (opcode 7) of known LBAs checked byte for byte,
reads aimed at foreign memory (nothing lands), edu writes into the AHCI's
pages (nothing lands), revoke of the AHCI while the edu keeps working, and
restart onto set 2 with set 1 unreachable. Every read aimed outside the
grant is one sector, must complete with status=done, must leave memory
unchanged, and must be followed by a SYNC (overflow=0 record=complete
unit=ok) reporting at least one IO page fault from 0x0038. Page revocation
of the command list and FIS area is refused (engine-cached-page); the bounce
page's is acknowledged and a read into it lands nothing.
SMOKE_MODE=two-device-ahci-fail: a unit error with the edu and the AHCI both
armed (both BMEs clear, AHCI_READ and both restarts refused unit-failed).
QEMU_PROBE=<binary> records `<binary> --version` in qemu-version.txt (for a
QEMU argument that is a wrapper whose stdout does not reach the smoke).
Usage:
  amdvi-oracle-smoke.py <iso> <out-dir> <qemu> [extra qemu args...]
  amdvi-oracle-smoke.py --self-test   (host only: parsers and page walk)
"""
import os
import re
import socket
import shlex
import subprocess
import sys
import time
import hashlib

FIXTURE_SECTORS = 2048
AHCI_ROLES = [("cl", "rw"), ("fis", "rw"), ("ctba", "r"), ("bounce", "rw")]
AHCI_LINE = r"^AMDVI-ORACLE AHCI devid=0x0038 port=(\d+) sectors=(\d+) lba-bytes=512$"
AHCI_READ_LINE = r"^AMDVI-ORACLE AHCIREAD seq={seq} devid=0x0038 lba=(0x[0-9a-f]+) blocks=(\d+) dba=(0x[0-9a-f]+) status=(done|device-error|short-transfer|timeout)$"
AHCI_FAULT = r"^AMDVI-ORACLE FAULT seq={seq} code=0x2 devid=0x0038 "
ADDRESS = 0x000F_FFFF_FFFF_F000


def ahci_faults(text, seq):
    """IO page faults (code 2) from 0x0038 a SYNC with `seq` reported."""
    return len(re.findall(AHCI_FAULT.format(seq=seq), text, re.M))


def fixture_sector(lba):
    return (hashlib.sha256(b"absd116-lba-%d" % lba).digest() * 16)[:512]


def grant_lines_of(text, devid, extra=""):
    """(iova, perm, role) per GRANT line of `devid`, in order."""
    found = re.findall(
        rf"^AMDVI-ORACLE GRANT {extra}devid={devid:#06x} iova=(0x[0-9a-f]+) pa=\1 perm=(r|w|rw)(?: role=([a-z]+))?$", text, re.M)
    return [(int(i, 16), p, r) for i, p, r in found]


def ahci_grant_ok(lines):
    """The AHCI grant: four pages, roles and permissions as declared."""
    return [(p, r) for _, p, r in lines] == [(p, r) for r, p in AHCI_ROLES]


def leaf_perm(readq, root, iova, mode=3):
    """The effective permission a level-`mode` AMD-Vi table under `root`
    gives `iova` ("r", "w", "rw"), or None when not present: the walk the
    unit does (IR/IW ANDed down the levels)."""
    table, read, write = root, True, True
    for level in range(mode, 0, -1):
        entry = readq(table + 8 * ((iova >> (12 + 9 * (level - 1))) & 0x1FF))
        if entry & 1 == 0:
            return None
        read &= bool(entry >> 61 & 1)
        write &= bool(entry >> 62 & 1)
        table = entry & ADDRESS
    return {(True, True): "rw", (True, False): "r", (False, True): "w"}.get((read, write), "none")


def self_test():
    sample = "\n".join([
        "AMDVI-ORACLE GRANT devid=0x0038 iova=0x200000 pa=0x200000 perm=rw role=cl",
        "AMDVI-ORACLE GRANT devid=0x0038 iova=0x201000 pa=0x201000 perm=rw role=fis",
        "AMDVI-ORACLE GRANT devid=0x0038 iova=0x202000 pa=0x202000 perm=r role=ctba",
        "AMDVI-ORACLE GRANT devid=0x0038 iova=0x203000 pa=0x203000 perm=rw role=bounce",
        "AMDVI-ORACLE GRANT devid=0x0028 iova=0x300000 pa=0x300000 perm=r",
        "AMDVI-ORACLE AHCI devid=0x0038 port=0 sectors=2048 lba-bytes=512",
        "AMDVI-ORACLE AHCIREAD seq=3 devid=0x0038 lba=0x25 blocks=8 dba=0x203000 status=done",
    ]) + "\n"
    ahci = grant_lines_of(sample, 0x38)
    assert ahci_grant_ok(ahci), ahci
    assert [i for i, _, _ in ahci] == [0x200000, 0x201000, 0x202000, 0x203000]
    # Negative controls: ctba writable, a role missing, roles reordered.
    assert not ahci_grant_ok([(a, "rw", r) for a, _, r in ahci])
    assert not ahci_grant_ok(ahci[:3])
    assert not ahci_grant_ok([ahci[1], ahci[0]] + ahci[2:])
    assert len(grant_lines_of(sample, 0x28)) == 1
    m = re.search(AHCI_LINE, sample, re.M)
    assert m and int(m.group(2)) == FIXTURE_SECTORS
    m = re.search(AHCI_READ_LINE.format(seq=3), sample, re.M)
    assert m and int(m.group(3), 16) == 0x203000 and m.group(4) == "done"
    assert not re.search(AHCI_READ_LINE.format(seq=4), sample, re.M)
    assert not re.search(AHCI_LINE, sample.replace("lba-bytes=512", "lba-bytes=4096"), re.M)
    # The page walk over a fake three-level table: rw, r, and absent.
    memory = {}
    root, l2, l1 = 0x1000, 0x2000, 0x3000
    def entry(address, level_next, read, write):
        return address | (level_next << 9) | (read << 61) | (write << 62) | 1
    memory[root + 8 * 0] = entry(l2, 2, 1, 1)
    memory[l2 + 8 * 1] = entry(l1, 1, 1, 1)
    memory[l1 + 8 * 0] = entry(0x200000, 0, 1, 1)
    memory[l1 + 8 * 2] = entry(0x202000, 0, 1, 0)
    readq = lambda a: memory.get(a, 0)
    assert leaf_perm(readq, root, 0x200000) == "rw"
    assert leaf_perm(readq, root, 0x202000) == "r"
    assert leaf_perm(readq, root, 0x201000) is None
    assert leaf_perm(readq, root, 0x400000) is None
    # A read-only directory entry caps the leaf (negative control).
    memory[l2 + 8 * 1] = entry(l1, 1, 1, 0)
    assert leaf_perm(readq, root, 0x200000) == "r"
    assert len(fixture_sector(0)) == 512 and fixture_sector(0) != fixture_sector(1)
    faults = "\n".join([
        "AMDVI-ORACLE FAULT seq=7 code=0x2 devid=0x0038 domain=0x0002 addr=0x0 flags=0x20",
        "AMDVI-ORACLE FAULT seq=7 code=0x2 devid=0x0028 domain=0x0001 addr=0x0 flags=0x20",
        "AMDVI-ORACLE FAULT seq=6 code=0x2 devid=0x0038 domain=0x0002 addr=0x0 flags=0x20",
        "AMDVI-ORACLE FAULT seq=7 code=0x5 devid=0x0038 domain=0x0000 addr=0x0 flags=0x0",
        "AMDVI-ORACLE FAULT seq=17 code=0x2 devid=0x0038 domain=0x0002 addr=0x0 flags=0x20",
    ])
    # Only this SYNC's IO page faults from the AHCI count: not another
    # device's, another SYNC's (7 vs 6 and 17), or another event code.
    assert ahci_faults(faults, 7) == 1 and ahci_faults(faults, 6) == 1 and ahci_faults(faults, 8) == 0
    print("amdvi-oracle-smoke: self-test ok")


if sys.argv[1:] == ["--self-test"]:
    self_test()
    sys.exit(0)

iso, out, qemu, *extra = sys.argv[1:]
os.makedirs(out, exist_ok=True)

# QEMU may be a wrapper whose stdout does not reach us (execution_host's
# vm-admit): QEMU_PROBE names the binary asked for its version. Without it
# the QEMU argument itself is asked, which must then be a bare executable.
# The version is recorded in qemu-version.txt; a failed or unrecognised
# answer fails the smoke.
probe_words = shlex.split(os.environ.get("QEMU_PROBE") or qemu)
if not os.environ.get("QEMU_PROBE") and len(probe_words) != 1:
    raise SystemExit("smoke: QEMU is a wrapper; set QEMU_PROBE to the QEMU binary")
probe = subprocess.run([*probe_words, "--version"], capture_output=True, text=True)
version = (probe.stdout.splitlines() or [""])[0].strip()
if probe.returncode != 0 or not version.startswith("QEMU emulator version "):
    raise SystemExit(f"smoke: no QEMU version from {probe_words!r} (exit {probe.returncode})")
open(os.path.join(out, "qemu-version.txt"), "w").write(version + "\n")
print("qemu:", version, flush=True)

AHCI_MODES = ("two-device-ahci", "two-device-ahci-fail")
if os.environ.get("SMOKE_MODE") in AHCI_MODES:
    fixture = os.path.join(out, "fixture.img")
    with open(fixture, "wb") as image:
        for lba in range(FIXTURE_SECTORS):
            image.write(fixture_sector(lba))
    fixture_sha = hashlib.sha256(open(fixture, "rb").read()).hexdigest()
    extra += ["-boot", "d",
              "-drive", f"file={fixture},if=none,id=sd0,format=raw,snapshot=on",
              "-device", "ich9-ahci,id=ahci7,addr=0x7",
              "-device", "ide-hd,bus=ahci7.0,serial=absd,drive=sd0"]
if os.environ.get("SMOKE_MODE") in ("two-device", "two-device-fail"):
    fixture = os.path.join(out, "fixture.img")
    with open(fixture, "wb") as image:
        for lba in range(FIXTURE_SECTORS):
            image.write(fixture_sector(lba))
    extra += ["-drive", f"file={fixture},if=none,id=nv0,format=raw,readonly=on",
              "-device", "nvme,serial=absd116,drive=nv0,addr=0x7"]
log = os.path.join(out, "serial.log")
sock = os.path.join(out, "qtest.sock")
for path in (log, sock):
    if os.path.exists(path):
        os.remove(path)
# The QEMU argument may carry a wrapper (e.g. execution_host's
# `vm-admit run ... -- /usr/bin/qemu-system-x86_64`).
cmd = [*shlex.split(qemu), "-M", "q35", "-accel", "tcg", "-smp", "1", "-m", "1024M", "-nic", "none",
       "-display", "none", "-monitor", "none", "-no-reboot", "-serial", f"file:{log}",
       *extra,
       "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-cdrom", iso,
       "-chardev", f"socket,id=qt,path={sock},server=on,wait=off", "-qtest", "chardev:qt"]
print("cmd:", " ".join(cmd), flush=True)
proc = subprocess.Popen(cmd, stdout=open(os.path.join(out, "qemu.out"), "w"),
                        stderr=open(os.path.join(out, "qemu.err"), "w"))


def serial():
    try:
        return open(log, "rb").read().decode(errors="replace").replace("\r\n", "\n")
    except FileNotFoundError:
        return ""


def wait_for(pattern, seconds=240):
    deadline = time.time() + seconds
    while time.time() < deadline:
        match = re.search(pattern, serial(), re.M)
        if match:
            return match
        if proc.poll() is not None:
            break
        time.sleep(0.2)
    raise SystemExit(f"smoke: timed out waiting for {pattern!r}")


try:
    wait_for(r"^AMDVI-ORACLE READY$")
    for _ in range(50):
        if os.path.exists(sock):
            break
        time.sleep(0.1)
    qt = socket.socket(socket.AF_UNIX)
    qt.connect(sock)
    qt_file = qt.makefile("rw")

    def qtest(line):
        qt_file.write(line + "\n")
        qt_file.flush()
        while True:
            reply = qt_file.readline().strip()
            if not reply.startswith("IRQ"):
                return reply

    mailbox = int(wait_for(r"^AMDVI-ORACLE MAILBOX pa=(0x[0-9a-f]+)$").group(1), 16)
    grants = [int(m, 16) for m in re.findall(r"^AMDVI-ORACLE GRANT (?:devid=0x[0-9a-f]+ )?iova=(0x[0-9a-f]+) ", serial(), re.M)]
    magic = qtest(f"readq {mailbox:#x}")
    assert magic == "OK 0x31454c4341524f41", magic

    def command(seq, opcode, arg0, expect, seconds=60, slots=()):
        for offset, value in slots:
            assert qtest(f"writeq {mailbox + offset:#x} {value:#x}") == "OK"
        assert qtest(f"writeq {mailbox + 0x10:#x} {opcode:#x}") == "OK"
        assert qtest(f"writeq {mailbox + 0x18:#x} {arg0:#x}") == "OK"
        assert qtest(f"writeq {mailbox + 0x20:#x} 0x5eed{seq:04x}") == "OK"
        assert qtest(f"writeq {mailbox + 0x08:#x} {seq:#x}") == "OK"
        match = wait_for(expect.format(seq=seq), seconds)
        line = match.group(0)
        deadline = time.time() + 60
        while qtest(f"readq {mailbox + 0x40:#x}") != f"OK {seq:#018x}":
            if time.time() > deadline:
                raise SystemExit(f"smoke: no ack for seq {seq}")
            time.sleep(0.05)
        print("smoke:", line, flush=True)
        return match

    devtab_match = re.search(r"^AMDVI DOMAIN .* devtab=(0x[0-9a-f]+) ", serial(), re.M)

    def dte_qword0(devid):
        reply = qtest(f"readq {int(devtab_match.group(1), 16) + devid * 32:#x}")
        assert reply.startswith("OK "), reply
        return int(reply[3:], 16)

    def blocked(devid):
        q0 = dte_qword0(devid)
        # V=1, TV=0, IR=IW=0 (Mode and root ignored).
        assert q0 & 1 == 1 and q0 & 2 == 0 and (q0 >> 61) & 3 == 0, f"{devid:#x}: {q0:#x}"

    def cfg_address(slot, offset):
        return 0x8000_0000 | (slot << 11) | (offset & 0xfc)

    def cfg_read32(slot, offset):
        assert qtest(f"outl 0xcf8 {cfg_address(slot, offset):#x}") == "OK"
        reply = qtest("inl 0xcfc")
        assert reply.startswith("OK "), reply
        return int(reply[3:], 16)

    def cfg_write32(slot, offset, value):
        assert qtest(f"outl 0xcf8 {cfg_address(slot, offset):#x}") == "OK"
        assert qtest(f"outl 0xcfc {value:#x}") == "OK"

    def readq(address):
        reply = qtest(f"readq {address:#x}")
        assert reply.startswith("OK "), reply
        return int(reply[3:], 16)

    def readl(address):
        reply = qtest(f"readl {address:#x}")
        assert reply.startswith("OK "), reply
        return int(reply[3:], 16)

    def edu_dma(bar, src, dst, to_ram):
        # One edu DMA with liveness: the registers must read back as written,
        # RUN must be seen set after the command (edu runs its DMA from a
        # timer), and must then clear.
        for offset, value in ((0x80, src), (0x88, dst), (0x90, 0x40)):
            assert qtest(f"writeq {bar + offset:#x} {value:#x}") == "OK"
            assert readq(bar + offset) == value, f"edu register {offset:#x} not accepted"
        assert qtest(f"writeq {bar + 0x98:#x} {1 | (2 if to_ram else 0):#x}") == "OK"
        command = readq(bar + 0x98)
        assert command & 1, f"edu command not accepted (RUN clear at once: {command:#x})"
        assert command & 2 == (2 if to_ram else 0), f"edu direction {command:#x}"
        deadline = time.time() + 10
        while readq(bar + 0x98) & 1:
            if time.time() > deadline:
                raise SystemExit("smoke: decoy DMA never completed (liveness)")
            time.sleep(0.01)

    def decoy_check(slot):
        assert cfg_read32(slot, 0) == 0x11e8_1234, "decoy is not an edu"
        bar = cfg_read32(slot, 0x10) & ~0xF
        command = cfg_read32(slot, 4) & 0xFFFF
        assert command & 0x2, "decoy memory decode off"
        # MMIO liveness: identification, and the register that reads back
        # the inverse of what was written.
        assert readl(bar) == 0x010000ED, "decoy edu identification"
        assert qtest(f"writel {bar + 4:#x} 0x5a5a1234") == "OK"
        assert readl(bar + 4) == (~0x5A5A1234 & 0xFFFFFFFF), "decoy edu liveness"
        assert command & 0x4 == 0, "decoy already mastering"
        canary = int(re.search(r"^AMDVI-ORACLE CANARY pa=(0x[0-9a-f]+)$", serial(), re.M).group(1), 16)
        source = mailbox + 0x800
        for i in range(8):
            assert qtest(f"writeq {source + 8 * i:#x} {0xd0d0_0000_0000_0000 | i:#x}") == "OK"
        before = [qtest(f"readq {canary + 8 * i:#x}") for i in range(8)]
        assert all(word != f"OK {0xd0d0_0000_0000_0000 | i:#018x}" for i, word in enumerate(before))
        # Bus Master Enable (and memory decode) forced on from outside.
        cfg_write32(slot, 4, command | 0x6)
        edu_dma(bar, source, 0x40000, False)
        edu_dma(bar, 0x40000, canary, True)
        cfg_write32(slot, 4, command)
        after = [qtest(f"readq {canary + 8 * i:#x}") for i in range(8)]
        assert after == before, f"smoke: decoy 00:{slot:02x}.0 write landed: requester on passthrough"
        print(f"smoke: decoy 00:{slot:02x}.0 bme=forced dma=completed canary=unchanged", flush=True)

    def read_bytes(address, size):
        reply = qtest(f"read {address:#x} {size:#x}")
        assert reply.startswith("OK 0x"), reply[:80]
        return bytes.fromhex(reply[5:])

    def write_bytes(address, data):
        assert qtest(f"write {address:#x} {len(data):#x} 0x{data.hex()}") == "OK"

    def two_device():
        text = serial()
        nvme_id, edu_slot, nvme_slot = 0x0038, 5, 7
        # Wire v4 draft §3: INHERITED lines (if any) before the first TARGET.
        first_target = text.index("AMDVI-ORACLE TARGET ")
        assert "AMDVI-ORACLE INHERITED " not in text[first_target:], "INHERITED after TARGET in two-device mode"
        assert re.search(r"^AMDVI-ORACLE TARGET devid=0x0028 domain=0x0001$", text, re.M), "edu TARGET"
        assert re.search(r"^AMDVI-ORACLE TARGET devid=0x0038 domain=0x0002$", text, re.M), "NVMe TARGET"
        roles = ["asq", "acq", "iosq", "iocq", "identify", "bounce"]
        def grant_lines(devid, extra=""):
            found = re.findall(
                rf"^AMDVI-ORACLE GRANT {extra}devid={devid:#06x} iova=(0x[0-9a-f]+) pa=\1 perm=(r|w|rw)(?: role=([a-z]+))?$", serial(), re.M)
            if devid == nvme_id:
                assert [r for _, _, r in found] == roles, f"NVMe roles {found}"
            else:
                assert all(r == "" for _, _, r in found), f"edu line with a role {found}"
            return [(int(i, 16), p) for i, p, _ in found]
        edu1, nvme1 = grant_lines(0x28), grant_lines(nvme_id)
        assert len(edu1) == 3 and len(nvme1) == 6 and all(p == "rw" for _, p in nvme1), (edu1, nvme1)
        assert not {a for a, _ in edu1} & {a for a, _ in nvme1}, "grants overlap"
        assert not re.search(r"^AMDVI-ORACLE GRANT iova=", text, re.M), "unlabelled GRANT in two-device mode"
        assert not re.search(r"^AMDVI-ORACLE IRGRANT devid=0x0038", text, re.M), "NVMe has an interrupt grant"
        facts = re.search(r"^AMDVI-ORACLE NVME devid=0x0038 namespace=(\d+) sectors=(\d+) lba-bytes=512 ioqid=1 qsize=(\d+) msix=masked iocq-vector=(\d+)$", text, re.M)
        assert facts and int(facts.group(2)) == FIXTURE_SECTORS, "NVME line"
        # MSI-X enabled with the function mask set (ADD-7).
        at = cfg_read32(nvme_slot, 0x34) & 0xFC
        while at and (cfg_read32(nvme_slot, at) & 0xFF) != 0x11:
            at = (cfg_read32(nvme_slot, at) >> 8) & 0xFC
        assert at and cfg_read32(nvme_slot, at) >> 30 == 0b11, "NVMe MSI-X not enabled with the function mask"
        edu_root = int(re.search(r"^AMDVI DOMAIN id=1 devid=00:05.0 .* root=(0x[0-9a-f]+) ", text, re.M).group(1), 16)
        nvme_dom = re.search(r"^AMDVI DOMAIN id=2 devid=00:07.0 mode=3 root=(0x[0-9a-f]+) ir-table=(0x[0-9a-f]+) interrupts=deny-all$", text, re.M)
        nvme_root, nvme_table = (int(x, 16) for x in nvme_dom.groups())
        edu_table = int(re.search(r"^AMDVI IRGRANT .* table=(0x[0-9a-f]+) ", text, re.M).group(1), 16)
        devtab = int(devtab_match.group(1), 16)
        def dte(devid):
            return [readq(devtab + devid * 32 + 8 * i) for i in range(4)]
        def tables_ok(after):
            q = dte(nvme_id)
            assert q[0] & 0x3 == 0x3 and (q[0] >> 9) & 7 == 3, f"NVMe DTE not translated {after}: {q[0]:#x}"
            assert q[0] & 0x000F_FFFF_FFFF_F000 == nvme_root != edu_root, f"NVMe root {after}: {q[0]:#x}"
            assert q[1] & 0xFFFF == 2, f"NVMe DomainID {after}: {q[1]:#x}"
            assert q[2] & 1 and (q[2] >> 60) & 3 == 2, f"NVMe interrupts not remapped {after}: {q[2]:#x}"
            assert q[2] & ((1 << 56) | (1 << 57) | (1 << 58) | (1 << 62) | (1 << 63)) == 0, "NVMe pass bits"
            root = q[2] & 0x000F_FFFF_FFFF_FFC0
            assert root == nvme_table != edu_table, f"NVMe interrupt table {root:#x} shared or moved {after}"
            assert read_bytes(nvme_table, 2048) == bytes(2048), f"NVMe interrupt table not deny-all {after}"
            e = dte(0x28)
            assert e[1] & 0xFFFF == 1, f"edu DomainID {e[1]:#x}"
        skip_tables = os.environ.get("SMOKE_SKIP_TABLES") == "1"
        if skip_tables:
            # Negative-control runs only: let the memory and trace witnesses
            # judge a broken layout the table checks would stop first.
            tables_ok = lambda after: None
        tables_ok("at READY")
        print("smoke: two-device tables SKIPPED (negative-control run)" if skip_tables else
              "smoke: two-device tables: separate roots, domains 1/2, NVMe interrupt table deny-all and its own", flush=True)
        seq = [0]
        def next_seq():
            seq[0] += 1
            return seq[0]
        read_line = r"^AMDVI-ORACLE NVMEREAD seq={seq} devid=0x0038 lba=(0x[0-9a-f]+) blocks=(\d+) prp1=(0x[0-9a-f]+) status=(0x[0-9a-f]+)$"
        def nvme_read(lba, blocks=8, prp1=0):
            m = command(next_seq(), 6, lba, read_line, slots=((0x28, blocks), (0x30, prp1)))
            return int(m.group(3), 16), int(m.group(4), 16)
        def nvme_positive(lba, bounce):
            used, status = nvme_read(lba)
            assert status == 0 and used == bounce, f"NVMe read lba {lba}: status {status:#x} prp1 {used:#x}"
            want = b"".join(fixture_sector(lba + i) for i in range(8))
            assert read_bytes(bounce, 4096) == want, f"NVMe bounce page does not hold LBA {lba}"
        bounce1 = nvme1[5][0]
        for lba in (0, 37, FIXTURE_SECTORS - 8):
            nvme_positive(lba, bounce1)
        print("smoke: NVMe reads of LBAs 0, 37 and the last 8 checked byte for byte in guest RAM", flush=True)
        trace_path = os.environ.get("SMOKE_TRACE")
        vector = int(facts.group(4))
        def nvme_msix_denied(stage, bounce):
            # Play a device that ignores masks (oracle v4 ADD-7): write a
            # message into the I/O CQ vector's table entry, mask every other
            # entry, clear the function mask, complete one NVMe read; the
            # message must reach the IOMMU from 0x38 and deliver nothing.
            if not trace_path:
                return
            def trace():
                try: return open(trace_path, errors="replace").read()
                except FileNotFoundError: return ""
            bar0 = (cfg_read32(nvme_slot, 0x10) & ~0xF) | (cfg_read32(nvme_slot, 0x14) << 32)
            control = cfg_read32(nvme_slot, at)
            table_info = cfg_read32(nvme_slot, at + 4)
            assert table_info & 7 == 0, "MSI-X table not in BAR0"
            table = bar0 + (table_info & ~7)
            size = ((control >> 16) & 0x7FF) + 1
            saved = [read_bytes(table + 16 * i, 16) for i in range(size)]
            for i in range(size):
                assert qtest(f"writel {table + 16 * i + 12:#x} 0x1") == "OK"
            for data in (0x10, 0x000, 0x1FF):
                entry = table + 16 * vector
                for offset, value in ((0, 0xFEE00000), (4, 0), (8, data), (12, 0)):
                    assert qtest(f"writel {entry + offset:#x} {value:#x}") == "OK"
                cfg_write32(nvme_slot, at, control & ~(1 << 30))
                before = trace()
                nvme_positive(500, bounce)
                time.sleep(0.3)
                cfg_write32(nvme_slot, at, control)
                assert qtest(f"writel {entry + 12:#x} 0x1") == "OK"
                chunk = trace()[len(before):]
                assert re.search(rf"amdvi_ir_remap_msi_req addr 0xfee00000 data {data:#x} devid 0x38", chunk), f"no NVMe MSI-X from 0x38 traced ({stage}, data {data:#x}): {chunk[-300:]}"
                assert "apic_deliver_irq" not in chunk.split(f"devid 0x38", 1)[1], f"NVMe MSI-X delivered ({stage}, data {data:#x}): {chunk[-400:]}"
            for i in range(size):
                write_bytes(table + 16 * i, saved[i])
            assert cfg_read32(nvme_slot, at) >> 30 == 0b11, "function mask not restored"
            print(f"smoke: NVMe MSI-X (data 0x10 = edu's granted index, 0x0, 0x1ff) reached the IOMMU from 0x38 and was not delivered ({stage})", flush=True)
        nvme_msix_denied("contained", bounce1)
        bar = cfg_read32(edu_slot, 0x10) & ~0xF
        def edu_positive(grant, tag):
            source, target = grant[0][0], grant[1][0]
            payload = bytes((tag + i) & 0xFF for i in range(64))
            write_bytes(source, payload)
            write_bytes(target, bytes(64))
            edu_dma(bar, source, 0x40000, False)
            edu_dma(bar, 0x40000, target, True)
            assert read_bytes(target, 64) == payload, f"edu granted transfer failed ({tag:#x})"
        edu_positive(edu1, 0x10)
        print("smoke: edu granted transfer (read page -> device -> write page) ok", flush=True)
        canary = int(re.search(r"^AMDVI-ORACLE CANARY pa=(0x[0-9a-f]+)$", text, re.M).group(1), 16)
        # NVMe aimed outside its grant: the edu's write page, a canary, the
        # device table, unrelated RAM. Nothing lands, a nonzero status, and
        # a permitted read afterwards (liveness).
        for name, address in (("edu-grant", edu1[1][0]), ("canary", canary),
                              ("device-table", devtab + 0x1000), ("unrelated-ram", 0x3000000)):
            write_bytes(address, bytes([0xA7]) * 4096) if name != "device-table" else None
            before = read_bytes(address, 4096)
            used, status = nvme_read(64, 8, address)
            # QEMU 10.2.1 reports a refused PRP data write as success (oracle
            # v4 §1.3): the status is recorded, memory is the witness.
            assert used == address, f"NVMe read into {name}: PRP1 {used:#x}"
            assert read_bytes(address, 4096) == before, f"NVMe DMA landed in {name}"
            nvme_positive(40, bounce1)
            print(f"smoke: NVMe read aimed at {name} {address:#x}: status {status:#x}, nothing landed, liveness ok", flush=True)
        # The edu aimed at the NVMe's grant: its bounce and I/O submission
        # pages. Nothing lands.
        write_bytes(edu1[0][0], bytes([0x5C]) * 64)
        edu_dma(bar, edu1[0][0], 0x40000, False)
        for name, address in (("nvme-bounce", bounce1), ("nvme-io-sq", nvme1[2][0])):
            before = read_bytes(address, 64)
            edu_dma(bar, 0x40000, address, True)
            assert read_bytes(address, 64) == before, f"edu DMA landed in {name}"
        nvme_positive(48, bounce1)
        print("smoke: edu writes into the NVMe's bounce and I/O SQ pages blocked; NVMe still reads", flush=True)
        # Revoke the NVMe only; the edu keeps working.
        command(next_seq(), 2, nvme_id, r"^AMDVI-ORACLE REVOKED seq={seq} scope=device devid=0x0038 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        assert cfg_read32(nvme_slot, 4) & 0x4 == 0, "NVMe BME set after its revoke"
        blocked(nvme_id)
        assert cfg_read32(edu_slot, 4) & 0x4, "edu BME lost on the NVMe's revoke"
        edu_positive(edu1, 0x20)
        command(next_seq(), 6, 0, r"^AMDVI-ORACLE REFUSED seq={seq} reason=revoked$", slots=((0x28, 8), (0x30, 0)))
        print("smoke: NVMe revoked (BME clear, DTE blocked, reads refused); edu transfer still ok", flush=True)
        # Restart the NVMe onto set 2; set 1 stays unreachable.
        s = next_seq()
        command(s, 5, nvme_id, r"^AMDVI-ORACLE RESTARTED seq={seq} set=2 devid=0x0038 domain=0x0002 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        nvme2 = grant_lines(nvme_id, f"seq={s} set=2 ")
        assert len(nvme2) == 6 and not {a for a, _ in nvme2} & {a for a, _ in nvme1 + edu1}, nvme2
        tables_ok("after the NVMe restart")
        bounce2 = nvme2[5][0]
        nvme_positive(100, bounce2)
        for name, address in (("old-bounce", bounce1), ("old-io-cq", nvme1[3][0])):
            write_bytes(address, bytes([0x3E]) * 4096)
            used, status = nvme_read(64, 8, address)
            assert used == address and read_bytes(address, 4096) == bytes([0x3E]) * 4096, f"NVMe reached its retained set 1 ({name}, status {status:#x})"
        nvme_positive(101, bounce2)
        print("smoke: NVMe restarted on set 2: reads ok, retained set 1 unreachable", flush=True)
        nvme_msix_denied("after the NVMe restart", bounce2)
        # Revoke the edu only; the NVMe keeps working.
        command(next_seq(), 2, 0, r"^AMDVI-ORACLE REVOKED seq={seq} scope=device devid=0x0028 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        blocked(0x28)
        command_reg = cfg_read32(edu_slot, 4) & 0xFFFF
        assert command_reg & 0x4 == 0, "edu BME set after its revoke"
        nvme_positive(200, bounce2)
        write_bytes(edu1[1][0], bytes([0x99]) * 64)
        cfg_write32(edu_slot, 4, command_reg | 0x6)
        edu_dma(bar, 0x40000, edu1[1][0], True)
        cfg_write32(edu_slot, 4, command_reg)
        assert read_bytes(edu1[1][0], 64) == bytes([0x99]) * 64, "revoked edu reached its old grant"
        print("smoke: edu revoked (forced BME, write blocked); NVMe still reads", flush=True)
        s = next_seq()
        command(s, 5, 0, r"^AMDVI-ORACLE RESTARTED seq={seq} set=2 devid=0x0028 domain=0x0001 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        edu2 = grant_lines(0x28, f"seq={s} set=2 ")
        assert len(edu2) == 3, edu2
        edu_positive(edu2, 0x30)
        nvme_positive(300, bounce2)
        command(next_seq(), 2, 0x30, r"^AMDVI-ORACLE REFUSED seq={seq} reason=not-a-target$")
        command(next_seq(), 3, 0, r"^AMDVI-ORACLE SYNCED seq={seq} faults=\d+ overflow=[01] record=(complete|incomplete) unit=ok$")
        command(next_seq(), 4, 0, r"^AMDVI-ORACLE BYE seq={seq}$")
        print("smoke: two-device ok", flush=True)

    def two_device_ahci():
        # #123: the AHCI controller at 00:07.0 as the second target.
        text = serial()
        ahci_id, edu_slot, ahci_slot = 0x0038, 5, 7
        first_target = text.index("AMDVI-ORACLE TARGET ")
        assert "AMDVI-ORACLE INHERITED " not in text[first_target:], "INHERITED after TARGET in two-device mode"
        assert re.search(r"^AMDVI-ORACLE TARGET devid=0x0028 domain=0x0001$", text, re.M), "edu TARGET"
        assert re.search(r"^AMDVI-ORACLE TARGET devid=0x0038 domain=0x0002$", text, re.M), "AHCI TARGET"
        assert re.search(r"^AMDVI ADMIT device=00:07.0 closure=own-only driver=ahci$", text, re.M), "AHCI ADMIT"
        assert re.search(r"^AMDVI CONTAINED devid=00:07.0 domain=2 bme=on profile=enforced driver=ahci$", text, re.M), "AHCI CONTAINED"
        edu1 = [(a, p) for a, p, r in grant_lines_of(text, 0x28)]
        ahci1_lines = grant_lines_of(text, ahci_id)
        assert ahci_grant_ok(ahci1_lines), f"AHCI roles/perms {ahci1_lines}"
        ahci1 = [(a, p) for a, p, _ in ahci1_lines]
        assert len(edu1) == 3 and not {a for a, _ in edu1} & {a for a, _ in ahci1}, "grants overlap"
        assert not re.search(r"^AMDVI-ORACLE GRANT iova=", text, re.M), "unlabelled GRANT in two-device mode"
        assert not re.search(r"^AMDVI-ORACLE IRGRANT devid=0x0038", text, re.M), "AHCI has an interrupt grant"
        assert not re.search(r"^AMDVI-ORACLE NVME ", text, re.M), "NVME line in AHCI mode"
        facts = re.search(AHCI_LINE, text, re.M)
        assert facts and int(facts.group(2)) == FIXTURE_SECTORS, "AHCI line"
        # The kernel's own GRANT lines carry the roles too.
        for (address, perm), (role, _) in zip(ahci1, AHCI_ROLES):
            assert re.search(rf"^AMDVI GRANT devid=00:07.0 iova={address:#x} page={address:#x} bytes=4096 perm={perm} role={role}$", text, re.M), f"AMDVI GRANT {role}"
        edu_root = int(re.search(r"^AMDVI DOMAIN id=1 devid=00:05.0 .* root=(0x[0-9a-f]+) ", text, re.M).group(1), 16)
        dom = re.search(r"^AMDVI DOMAIN id=2 devid=00:07.0 mode=3 root=(0x[0-9a-f]+) ir-table=(0x[0-9a-f]+) interrupts=deny-all$", text, re.M)
        assert dom, "AHCI DOMAIN line"
        ahci_root, ahci_table = (int(x, 16) for x in dom.groups())
        edu_table = int(re.search(r"^AMDVI IRGRANT .* table=(0x[0-9a-f]+) ", text, re.M).group(1), 16)
        devtab = int(devtab_match.group(1), 16)
        def dte(devid):
            return [readq(devtab + devid * 32 + 8 * i) for i in range(4)]
        def tables_ok(after, grant):
            q = dte(ahci_id)
            assert q[0] & 0x3 == 0x3 and (q[0] >> 9) & 7 == 3, f"AHCI DTE not translated {after}: {q[0]:#x}"
            assert q[0] & 0x000F_FFFF_FFFF_F000 == ahci_root != edu_root, f"AHCI root {after}: {q[0]:#x}"
            assert q[1] & 0xFFFF == 2, f"AHCI DomainID {after}: {q[1]:#x}"
            assert q[2] & 1 and (q[2] >> 60) & 3 == 2, f"AHCI interrupts not remapped {after}: {q[2]:#x}"
            assert q[2] & ((1 << 56) | (1 << 57) | (1 << 58) | (1 << 62) | (1 << 63)) == 0, "AHCI pass bits"
            assert q[2] & 0x000F_FFFF_FFFF_FFC0 == ahci_table != edu_table, f"AHCI interrupt table shared or moved {after}"
            assert read_bytes(ahci_table, 2048) == bytes(2048), f"AHCI interrupt table not deny-all {after}"
            # Per-page permissions as walked in the domain's tables.
            for (address, perm), (role, _) in zip(grant, AHCI_ROLES):
                got = leaf_perm(readq, ahci_root, address)
                assert got == perm, f"AHCI {role} page {address:#x} maps {got}, granted {perm} ({after})"
            for address, _ in edu1:
                assert leaf_perm(readq, ahci_root, address) is None, f"edu page {address:#x} in the AHCI domain"
            assert dte(0x28)[1] & 0xFFFF == 1, "edu DomainID"
        tables_ok("at READY", ahci1)
        print("smoke: two-device-ahci tables: own root and deny-all interrupt table, roles cl/fis rw, ctba r, bounce rw", flush=True)
        seq = [0]
        def next_seq():
            seq[0] += 1
            return seq[0]
        def ahci_read(lba, blocks=8, dba=0):
            m = command(next_seq(), 7, lba, AHCI_READ_LINE, slots=((0x28, blocks), (0x30, dba)))
            return int(m.group(3), 16), m.group(4)
        def ahci_positive(lba, bounce):
            used, status = ahci_read(lba)
            assert status == "done" and used == bounce, f"AHCI read lba {lba}: status {status} dba {used:#x}"
            want = b"".join(fixture_sector(lba + i) for i in range(8))
            assert read_bytes(bounce, 4096) == want, f"AHCI bounce page does not hold LBA {lba}"
        def sync_strict():
            # Drains the event log; overflow, an incomplete record or a
            # failed unit fail the smoke.
            s = next_seq()
            command(s, 3, 0, r"^AMDVI-ORACLE SYNCED seq={seq} faults=\d+ overflow=0 record=complete unit=ok$")
            return s
        def ahci_hostile(name, address, fill=0xA7, dba=None):
            # One sector aimed outside the grant (a denied PRDT write is
            # ~129 IO page faults on QEMU 10.2.1, so one sector per SYNC
            # keeps the 256-entry log from overflowing): status done,
            # memory unchanged, and the next SYNC reports at least one IO
            # page fault (code 0x2) from 0x0038.
            if fill is not None:
                write_bytes(address, bytes([fill]) * 4096)
            before = read_bytes(address, 4096)
            used, status = ahci_read(64, 1, address if dba is None else dba)
            assert used == address, f"AHCI read into {name}: dba {used:#x}"
            assert status == "done", f"AHCI read into {name}: status {status}, not done"
            assert read_bytes(address, 4096) == before, f"AHCI DMA landed in {name}"
            s = sync_strict()
            faults = ahci_faults(serial(), s)
            assert faults >= 1, f"no IO page fault from 0x0038 reported for {name}"
            return faults
        bounce1 = ahci1[3][0]
        for lba in (0, 37, FIXTURE_SECTORS - 8):
            ahci_positive(lba, bounce1)
        print("smoke: AHCI reads of LBAs 0, 37 and the last 8 checked byte for byte in guest RAM", flush=True)
        bar = cfg_read32(edu_slot, 0x10) & ~0xF
        def edu_positive(grant, tag):
            source, target = grant[0][0], grant[1][0]
            payload = bytes((tag + i) & 0xFF for i in range(64))
            write_bytes(source, payload)
            write_bytes(target, bytes(64))
            edu_dma(bar, source, 0x40000, False)
            edu_dma(bar, 0x40000, target, True)
            assert read_bytes(target, 64) == payload, f"edu granted transfer failed ({tag:#x})"
        edu_positive(edu1, 0x10)
        canary = int(re.search(r"^AMDVI-ORACLE CANARY pa=(0x[0-9a-f]+)$", text, re.M).group(1), 16)
        sync_strict()
        for name, address in (("edu-grant", edu1[1][0]), ("canary", canary),
                              ("device-table", devtab + 0x1000), ("unrelated-ram", 0x3000000)):
            faults = ahci_hostile(name, address, None if name == "device-table" else 0xA7)
            ahci_positive(40, bounce1)
            print(f"smoke: AHCI read aimed at {name} {address:#x}: status done, nothing landed, {faults} IO page faults from 0x0038, liveness ok", flush=True)
        # The edu aimed at the AHCI's pages: bounce, command table, command
        # list. Nothing lands.
        write_bytes(edu1[0][0], bytes([0x5C]) * 64)
        edu_dma(bar, edu1[0][0], 0x40000, False)
        for name, address in (("ahci-bounce", bounce1), ("ahci-ctba", ahci1[2][0]), ("ahci-cl", ahci1[0][0])):
            before = read_bytes(address, 64)
            edu_dma(bar, 0x40000, address, True)
            assert read_bytes(address, 64) == before, f"edu DMA landed in {name}"
        ahci_positive(48, bounce1)
        sync_strict()
        print("smoke: edu writes into the AHCI's bounce, command table and command list blocked; AHCI still reads", flush=True)
        # Page revocation: the command list and FIS area are used from a
        # mapping the engine took at ST/FRE, so revoking either alone is
        # refused and the grant stays; the bounce page is fetched per
        # command, so its revocation is acknowledged and enforced.
        cl1, fis1 = ahci1[0][0], ahci1[1][0]
        for name, address in (("cl", cl1), ("fis", fis1)):
            command(next_seq(), 1, address, r"^AMDVI-ORACLE REFUSED seq={seq} reason=engine-cached-page$")
            assert leaf_perm(readq, ahci_root, address) == "rw", f"refused {name} revocation changed the grant"
        ahci_positive(52, bounce1)
        command(next_seq(), 1, bounce1, r"^AMDVI-ORACLE REVOKED seq={seq} scope=page iova=0x[0-9a-f]+ cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        assert leaf_perm(readq, ahci_root, bounce1) is None, "revoked bounce page still mapped"
        faults = ahci_hostile("revoked-bounce", bounce1, 0x6B, dba=0)
        print(f"smoke: AHCI page revoke: cl and fis refused engine-cached-page (grant intact), bounce revoked and a read into it landed nothing ({faults} IO page faults)", flush=True)
        # Revoke the AHCI only; the edu keeps working.
        command(next_seq(), 2, ahci_id, r"^AMDVI-ORACLE REVOKED seq={seq} scope=device devid=0x0038 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        assert cfg_read32(ahci_slot, 4) & 0x4 == 0, "AHCI BME set after its revoke"
        blocked(ahci_id)
        assert re.search(r"^AHCI PORT WITHDRAWN reason=revoke$", serial(), re.M), "no R1 withdrawal"
        assert re.search(r"^AHCI PORT CLEANUP stop=confirmed dma=off$", serial(), re.M), "no confirmed R4 stop"
        assert re.search(r"^AMDVI REVOKE devid=00:07.0 R1=closed R2=bme-clear R3=completed R4=reset-requested-stop-confirmed R5=no-mechanism$", serial(), re.M), "AHCI revocation steps"
        assert cfg_read32(edu_slot, 4) & 0x4, "edu BME lost on the AHCI's revoke"
        edu_positive(edu1, 0x20)
        command(next_seq(), 7, 0, r"^AMDVI-ORACLE REFUSED seq={seq} reason=revoked$", slots=((0x28, 8), (0x30, 0)))
        print("smoke: AHCI revoked (BME clear, DTE blocked, port stopped, reads refused); edu transfer still ok", flush=True)
        # Restart onto set 2; set 1 stays unreachable.
        s = next_seq()
        command(s, 5, ahci_id, r"^AMDVI-ORACLE RESTARTED seq={seq} set=2 devid=0x0038 domain=0x0002 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        ahci2_lines = grant_lines_of(serial(), ahci_id, f"seq={s} set=2 ")
        assert ahci_grant_ok(ahci2_lines), f"AHCI set 2 roles/perms {ahci2_lines}"
        ahci2 = [(a, p) for a, p, _ in ahci2_lines]
        assert not {a for a, _ in ahci2} & {a for a, _ in ahci1 + edu1}, ahci2
        tables_ok("after the AHCI restart", ahci2)
        for address, _ in ahci1:
            assert leaf_perm(readq, ahci_root, address) is None, f"retained set 1 page {address:#x} still mapped"
        bounce2 = ahci2[3][0]
        ahci_positive(100, bounce2)
        for name, address in (("old-bounce", bounce1), ("old-ctba", ahci1[2][0])):
            ahci_hostile(f"retained set 1 {name}", address, 0x3E)
            ahci_positive(101, bounce2)
        edu_positive(edu1, 0x30)
        print("smoke: AHCI restarted on set 2: reads ok, retained set 1 unreachable; edu still ok", flush=True)
        sync_strict()
        command(next_seq(), 4, 0, r"^AMDVI-ORACLE BYE seq={seq}$")
        print("smoke: two-device-ahci ok", flush=True)

    MMIO = 0xFED80000
    mode = os.environ.get("SMOKE_MODE", "")
    synced = r"^AMDVI-ORACLE SYNCED seq={seq} faults=\d+ overflow=%s record=%s unit=%s$"

    code = int(os.environ.get("SMOKE_CODE", "5"))
    reason = {3: "dev-tab-hw-error", 4: "page-tab-hw-error", 5: "illegal-command",
              6: "command-hw-error", 7: "iotlb-inv-timeout"}[code]

    def inject_unit_error():
        base = readq(MMIO + 0x10) & 0x000F_FFFF_FFFF_F000
        tail = readq(MMIO + 0x2018) & 0x7FFF0
        assert qtest(f"writeq {base + tail:#x} {(code << 28) << 32:#x}") == "OK"
        assert qtest(f"writeq {base + tail + 8:#x} 0x0") == "OK"
        assert qtest(f"writeq {MMIO + 0x2018:#x} {(tail + 16) % 4096:#x}") == "OK"

    if grants:
        # Enforced path (increment 6 split): inherited masters not cleared.
        assert not re.search(r"^AMDVI INHERITED-BME closed=", serial(), re.M), "enforced path closed inherited masters"
    if grants and mode == "setup-unit-error":
        raise SystemExit("smoke: SMOKE_MODE=setup-unit-error expects setup refused, but ABSD granted")
    if grants and mode == "fail-revoke":
        # A unit error pending, no SYNC: the next map change must act on it
        # (BME clear before the ack), and RESTART refuses.
        assert cfg_read32(5, 4) & 0x4, "target not armed at READY"
        inject_unit_error()
        command(1, 1, grants[1], r"^AMDVI-ORACLE REVOKED seq={seq} scope=page iova=0x[0-9a-f]+ cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        assert cfg_read32(5, 4) & 0x4 == 0, "target BME still set after a pending unit error"
        assert re.search(rf"^AMDVI UNIT FAILED reason={reason} ", serial(), re.M)
        command(2, 5, 0, r"^AMDVI-ORACLE REFUSED seq={seq} reason=unit-failed$")
        command(3, 3, 0, synced % ("0", "complete", "failed"))
        assert re.search(rf"^AMDVI-ORACLE FAULT seq=3 code={code:#x} ", serial(), re.M)
        command(4, 4, 0, r"^AMDVI-ORACLE BYE seq={seq}$")
    elif grants and mode == "fail-restart":
        # A unit error arriving after a device revoke, before RESTART.
        command(1, 2, 0, r"^AMDVI-ORACLE REVOKED seq={seq} scope=device devid=0x0028 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        inject_unit_error()
        command(2, 5, 0, r"^AMDVI-ORACLE REFUSED seq={seq} reason=unit-failed$")
        assert cfg_read32(5, 4) & 0x4 == 0, "target BME set after refused restart"
        assert not re.search(r"^AMDVI-ORACLE GRANT seq=2 ", serial(), re.M)
        command(3, 3, 0, synced % ("0", "complete", "failed"))
        command(4, 4, 0, r"^AMDVI-ORACLE BYE seq={seq}$")
    elif grants and mode == "irq":
        # Interrupt remapping (increment 7, interface v3.3 `irq`): QEMU trace
        # (-trace amdvi_ir*,apic_deliver_irq,amdvi_intr_inval -D <trace>,
        # path in SMOKE_TRACE) shows each MSI's outcome.
        trace_path = os.environ["SMOKE_TRACE"]
        def trace():
            try: return open(trace_path, errors="replace").read()
            except FileNotFoundError: return ""
        grant = re.search(r"^AMDVI-ORACLE IRGRANT devid=0x0028 index=(0x[0-9a-f]+) vector=(0x[0-9a-f]+) dest=(0x[0-9a-f]+)$", serial(), re.M)
        assert grant, "no IRGRANT line"
        index, vector, dest = (int(x, 16) for x in grant.groups())
        table = int(re.search(r"^AMDVI IRGRANT .* table=(0x[0-9a-f]+) entries=512 intctl=remap$", serial(), re.M).group(1), 16)
        def irtes_outside(expect_granted):
            # Every IRTE but the granted one stays zero; the granted one is
            # the grant (or zero after revoke).
            for i in range(512):
                value = readl(table + 4 * i)
                if i == index:
                    want = (1 | (dest << 8) | (vector << 16)) if expect_granted else 0
                    assert value == want, f"IRTE {i:#x} = {value:#x}, expected {want:#x}"
                else:
                    assert value == 0, f"IRTE {i:#x} outside the grant = {value:#x}"
        irtes_outside(True)
        bar = cfg_read32(5, 0x10) & ~0xF
        # Find the target's MSI capability and check ABSD programmed it.
        at = cfg_read32(5, 0x34) & 0xFC
        while at and (cfg_read32(5, at) & 0xFF) != 0x05:
            at = (cfg_read32(5, at) >> 8) & 0xFC
        header = cfg_read32(5, at)
        data_at = at + (0x0C if header & (1 << 23) else 0x08)
        assert header & (1 << 16), "MSI not enabled by ABSD"
        assert cfg_read32(5, at + 4) & 0xFFF00000 == 0xFEE00000, "MSI address"
        assert cfg_read32(5, data_at) & 0xFFFF == index, "MSI data is not the granted index"
        def fire():
            before = trace()
            assert qtest(f"writel {bar + 0x60:#x} 0x1") == "OK"
            time.sleep(0.3)
            return trace()[len(before):]
        def delivered(chunk, vec):
            return re.search(rf"apic_deliver_irq .*vector {vec}\b", chunk) is not None
        cmd = cfg_read32(5, 4) & 0xFFFF
        assert cmd & 0x4, "target BME not set at READY"
        chunk = fire()
        assert delivered(chunk, vector), f"granted MSI not delivered at vector {vector:#x}: {chunk[-400:]}"
        print(f"smoke: irq granted index={index:#x} delivered vector={vector:#x}", flush=True)
        # Ungranted indices: a sample, each must deliver nothing.
        for other in (0x000, 0x001, index + 1, 0x0FF, 0x100, 0x1FF):
            cfg_write32(5, data_at, other)
            chunk = fire()
            assert "apic_deliver_irq" not in chunk, f"index {other:#x} delivered: {chunk[-400:]}"
        cfg_write32(5, data_at, index)
        print("smoke: irq ungranted indices blocked (0x0,0x1,next,0xff,0x100,0x1ff)", flush=True)
        # The decoy-free DTE checks: no pass bits anywhere sampled.
        # The revoke's own interrupt-table invalidation: processed between
        # the command's issue and its acknowledgement (setup's earlier one
        # does not count).
        before = trace()
        command(1, 2, 0, r"^AMDVI-ORACLE REVOKED seq={seq} scope=device devid=0x0028 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        assert "amdvi_intr_inval" in trace()[len(before):], "no interrupt-table invalidation processed by the revoke"
        # After the revoke, with BME forced on as a hostile device would.
        cfg_write32(5, 4, cmd | 0x6)
        chunk = fire()
        assert "apic_deliver_irq" not in chunk, f"revoked MSI delivered: {chunk[-400:]}"
        irtes_outside(False)
        print("smoke: irq revoked: granted index blocked, interrupt table invalidated, IRTEs outside the grant zero", flush=True)
        # RESTART after the revoke must not resurrect the interrupt grant.
        command(2, 5, 0, r"^AMDVI-ORACLE RESTARTED seq={seq} set=2 domain=0x0001 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        cfg_write32(5, 4, cfg_read32(5, 4) | 0x6)
        for other in (index, 0x000, 0x1FF):
            cfg_write32(5, data_at, other)
            chunk = fire()
            assert "apic_deliver_irq" not in chunk, f"index {other:#x} delivered after RESTART: {chunk[-400:]}"
        cfg_write32(5, data_at, index)
        irtes_outside(False)
        print("smoke: irq restart: no interrupt re-granted, IRTEs all zero", flush=True)
        command(3, 4, 0, r"^AMDVI-ORACLE BYE seq={seq}$")
    elif grants and mode == "two-device":
        two_device()
    elif grants and mode == "two-device-ahci":
        two_device_ahci()
    elif grants and mode == "two-device-ahci-fail":
        # #123: a unit error with the edu and the AHCI both armed: both BMEs
        # clear at the SYNC's ack and through a 2 s hold, AHCI reads and both
        # restarts refused unit-failed, no grant grows.
        assert cfg_read32(5, 4) & 0x4 and cfg_read32(7, 4) & 0x4, "both devices armed at READY"
        assert re.search(AHCI_LINE, serial(), re.M), "AHCI line"
        inject_unit_error()
        command(1, 3, 0, synced % ("0", "complete", "failed"))
        for hold in (0, 2):
            time.sleep(hold)
            assert cfg_read32(5, 4) & 0x4 == 0 and cfg_read32(7, 4) & 0x4 == 0, f"a BME still set {hold}s after unit failure"
        for devid in ("00:05.0", "00:07.0"):
            assert re.search(rf"^AMDVI UNIT FAILED reason={reason} devid={devid} bme=clear step=R2 claims=none$", serial(), re.M), devid
        command(2, 7, 0, r"^AMDVI-ORACLE REFUSED seq={seq} reason=unit-failed$", slots=((0x28, 1), (0x30, 0)))
        command(3, 5, 0, r"^AMDVI-ORACLE REFUSED seq={seq} reason=unit-failed$")
        command(4, 5, 0x38, r"^AMDVI-ORACLE REFUSED seq={seq} reason=unit-failed$")
        assert not re.search(r"^AMDVI-ORACLE GRANT seq=", serial(), re.M), "a grant grew after unit failure"
        assert not re.search(r"^AMDVI-ORACLE AHCIREAD ", serial(), re.M), "an AHCI read was served"
        assert cfg_read32(5, 4) & 0x4 == 0 and cfg_read32(7, 4) & 0x4 == 0, "a BME set by a refused restart"
        command(5, 3, 0, synced % ("0", "complete", "failed"))
        command(6, 4, 0, r"^AMDVI-ORACLE BYE seq={seq}$")
        print("smoke: two-device-ahci unit failure: both BMEs clear (ack and 2 s), AHCI read and both restarts refused unit-failed, no grant grew", flush=True)
    elif grants and mode == "two-device-fail":
        # A unit error with both devices armed (oracle v4 draft §5.10):
        # both BMEs clear at the SYNC's ack and through a 2 s hold, NVMe
        # reads refused, both restarts refused, no grant grows.
        assert cfg_read32(5, 4) & 0x4 and cfg_read32(7, 4) & 0x4, "both devices armed at READY"
        inject_unit_error()
        command(1, 3, 0, synced % ("0", "complete", "failed"))
        for hold in (0, 2):
            time.sleep(hold)
            assert cfg_read32(5, 4) & 0x4 == 0 and cfg_read32(7, 4) & 0x4 == 0, f"a BME still set {hold}s after unit failure"
        for devid in ("00:05.0", "00:07.0"):
            assert re.search(rf"^AMDVI UNIT FAILED reason={reason} devid={devid} bme=clear step=R2 claims=none$", serial(), re.M), devid
        command(2, 6, 0, r"^AMDVI-ORACLE REFUSED seq={seq} reason=unit-failed$", slots=((0x28, 8), (0x30, 0)))
        command(3, 5, 0, r"^AMDVI-ORACLE REFUSED seq={seq} reason=unit-failed$")
        command(4, 5, 0x38, r"^AMDVI-ORACLE REFUSED seq={seq} reason=unit-failed$")
        assert not re.search(r"^AMDVI-ORACLE GRANT seq=", serial(), re.M), "a grant grew after unit failure"
        assert cfg_read32(5, 4) & 0x4 == 0 and cfg_read32(7, 4) & 0x4 == 0, "a BME set by a refused restart"
        command(5, 3, 0, synced % ("0", "complete", "failed"))
        command(6, 4, 0, r"^AMDVI-ORACLE BYE seq={seq}$")
        print("smoke: two-device unit failure: both BMEs clear (ack and 2 s), NVMe read and both restarts refused unit-failed, no grant grew", flush=True)
    elif grants and mode == "fail":
        # A unit error while the target is armed: a code 5 record written
        # into the event log and the tail advanced (emulated injection).
        assert cfg_read32(5, 4) & 0x4, "target not armed at READY"
        inject_unit_error()
        command(1, 3, 0, synced % ("0", "complete", "failed"))
        assert re.search(rf"^AMDVI-ORACLE FAULT seq=1 code={code:#x} ", serial(), re.M)
        assert cfg_read32(5, 4) & 0x4 == 0, "target BME still set after unit failure"
        command(2, 5, 0, r"^AMDVI-ORACLE REFUSED seq={seq} reason=unit-failed$")
        command(3, 3, 0, synced % ("0", "complete", "failed"))
        command(4, 4, 0, r"^AMDVI-ORACLE BYE seq={seq}$")
    elif grants and mode == "timeout":
        # A runtime completion timeout while the target is armed: the
        # command buffer disabled from outside, then a map change.
        assert cfg_read32(5, 4) & 0x4, "target not armed at READY"
        control = readq(MMIO + 0x18)
        assert qtest(f"writeq {MMIO + 0x18:#x} {control & ~(1 << 12):#x}") == "OK"
        command(1, 1, grants[1], r"^AMDVI-ORACLE REFUSED seq={seq} reason=no-completion$", 600)
        assert cfg_read32(5, 4) & 0x4 == 0, "target BME still set after timeout"
        assert re.search(r"^AMDVI UNIT FAILED reason=invalidation-timeout ", serial(), re.M)
        command(2, 3, 0, synced % ("0", "complete", "failed"))
        command(3, 5, 0, r"^AMDVI-ORACLE REFUSED seq={seq} reason=unit-failed$")
        command(4, 4, 0, r"^AMDVI-ORACLE BYE seq={seq}$")
    elif grants and mode == "overflow":
        # Overflow before R3: event interrupts on (QEMU 10.2.1 reports
        # EventOverflow only then), the target's denied writes fill the log.
        control = readq(MMIO + 0x18)
        assert qtest(f"writeq {MMIO + 0x18:#x} {control | (1 << 3):#x}") == "OK"
        bar = cfg_read32(5, 0x10) & ~0xF
        canary = int(re.search(r"^AMDVI-ORACLE CANARY pa=(0x[0-9a-f]+)$", serial(), re.M).group(1), 16)
        for _ in range(300):
            edu_dma(bar, 0x40000, canary, True)
            if readq(MMIO + 0x2020) & 1:
                break
        assert readq(MMIO + 0x2020) & 1, "no EventOverflow"
        command(1, 2, 0, r"^AMDVI-ORACLE REVOKED seq={seq} scope=device devid=0x0028 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        assert re.search(r"^AMDVI CLAIM devid=00:05.0 contained=UNESTABLISHED$", serial(), re.M), "contained claimed after overflow"
        command(2, 5, 0, r"^AMDVI-ORACLE RESTARTED seq={seq} set=2 domain=0x0001 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        command(3, 3, 0, synced % ("1", "incomplete", "ok"), 120)
        command(4, 3, 0, synced % ("[01]", "incomplete", "ok"))
        command(5, 4, 0, r"^AMDVI-ORACLE BYE seq={seq}$")
    elif grants:
        if os.environ.get("SMOKE_DECOY"):
            decoy_check(int(os.environ["SMOKE_DECOY"], 16))
        blocked(0x0030)
        blocked(0xffff)
        command(1, 3, 0, r"^AMDVI-ORACLE SYNCED seq={seq} faults=\d+ overflow=0 record=complete unit=ok$")
        command(2, 1, grants[0], r"^AMDVI-ORACLE REVOKED seq={seq} scope=page iova=0x[0-9a-f]+ cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        command(3, 1, grants[0], r"^AMDVI-ORACLE REFUSED seq={seq} reason=already-revoked$")
        command(4, 5, 0, r"^AMDVI-ORACLE REFUSED seq={seq} reason=not-revoked$")
        command(5, 2, 0, r"^AMDVI-ORACLE REVOKED seq={seq} scope=device devid=0x0028 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        blocked(0x0028)
        assert cfg_read32(5, 4) & 0x4 == 0, "target BME set after REVOKE_DEVICE"
        command(6, 5, 0, r"^AMDVI-ORACLE RESTARTED seq={seq} set=2 domain=0x0001 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        set2 = re.findall(r"^AMDVI-ORACLE GRANT seq=6 set=2 iova=(0x[0-9a-f]+) pa=\1 perm=(r|w|rw)$", serial(), re.M)
        assert len(set2) == 3 and not set(int(i, 16) for i, _ in set2) & set(grants), set2
        assert cfg_read32(5, 4) & 0x4, "target BME clear after RESTART"
        command(7, 2, 0, r"^AMDVI-ORACLE REVOKED seq={seq} scope=device devid=0x0028 cw-store=0x[0-9a-f]+ cw-data=0x[0-9a-f]+$")
        command(8, 5, 0, r"^AMDVI-ORACLE REFUSED seq={seq} reason=CONTAINED_BUT_UNUSABLE$")
        assert cfg_read32(5, 4) & 0x4 == 0, "target BME set after exhaustion"
        command(9, 3, 0, r"^AMDVI-ORACLE SYNCED seq={seq} faults=\d+ overflow=0 record=complete unit=ok$")
        command(10, 4, 0, r"^AMDVI-ORACLE BYE seq={seq}$")
    else:
        # An explicit enforced mode must not pass through the refusal
        # checks when setup was refused (no grants).
        if mode in ("fail", "fail-revoke", "fail-restart", "irq", "timeout", "overflow", "two-device", "two-device-fail", "two-device-ahci", "two-device-ahci-fail"):
            raise SystemExit(f"smoke: SMOKE_MODE={mode} needs an enforced setup; ABSD refused (no grants)")
        # Refusal path (increment 6 split): inherited masters reported, then
        # closed, R2 only.
        assert re.search(r"^AMDVI INHERITED-BME closed=\d+ path=refusal step=R2 claims=none$", serial(), re.M), "refusal path did not close inherited masters"
        if mode == "setup-unit-error":
            assert re.search(r"^AMDVI-ORACLE UNAVAILABLE reason=unit-failed$", serial(), re.M), "setup did not refuse"
            assert cfg_read32(5, 4) & 0x4 == 0, "target armed on a failed unit"
        command(1, 1, 0x1000, r"^AMDVI-ORACLE REFUSED seq={seq} reason=unavailable$")
        command(2, 4, 0, r"^AMDVI-ORACLE BYE seq={seq}$")
    # After BYE: QEMU not exited; the mailbox still answers (the halt itself,
    # interrupts off, is by source).
    time.sleep(2)
    assert proc.poll() is None, f"smoke: qemu exited after BYE ({proc.returncode})"
    assert qtest(f"readq {mailbox:#x}") == "OK 0x31454c4341524f41"
    assert qtest(f"readq {mailbox + 0x48:#x}") == "OK 0x0000000000000000"
    print("smoke: after BYE qemu running, mailbox readable", flush=True)
finally:
    if proc.poll() is None:
        # TERM first, so a wrapper can stop its guest and release its lease.
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
lines = [l for l in serial().splitlines() if l.startswith("AMDVI-ORACLE ")]
open(os.path.join(out, "oracle-lines.txt"), "w").write("\n".join(lines) + "\n")
if os.environ.get("SMOKE_MODE") in AHCI_MODES:
    # snapshot=on: the fixture itself is never written.
    assert hashlib.sha256(open(fixture, "rb").read()).hexdigest() == fixture_sha, "fixture image changed"
print("smoke: protocol plumbing ok")
