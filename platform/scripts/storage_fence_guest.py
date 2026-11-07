"""Cold file-server boots and strict read-only refusal checks for the fence cases."""

import hashlib
import os
import re
import subprocess

import ssh_absd
from served_ram import served_qemu


def captured_complete(raw):
    """The worker's output stream, refusing an incomplete capture. Unlike
    ssh_absd.captured, which stops silently at the first offset
    discontinuity, a gap or overlap here is an error, so no later chunk
    (for example a readiness line) can hide behind it."""
    data = bytearray()
    for m in re.finditer(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]+) data=([0-9a-f]*)\n", raw):
        if int(m.group(1), 16) != len(data):
            raise RuntimeError(f"worker output capture is incomplete: chunk offset {m.group(1).decode()} "
                               f"after {len(data)} bytes")
        data.extend(bytes.fromhex(m.group(2).decode()))
    return data.decode(errors="replace")


def accounting(serial):
    lines = re.findall(r"(?m)^DURABLE status=.* block_writes=(\d+) block_flushes=(\d+) block_errors=(\d+)\b", serial)
    if len(lines) != 1:
        raise RuntimeError("expected exactly one terminal block-accounting record")
    return tuple(map(int, lines[0]))


def require_refusal(raw, status, previous="failed", reason="not_declared", allow_corrupt=False):
    serial = raw.decode(errors="replace")
    if status != "7" or serial.count("ABSD KERNEL BOOT\n") != 1:
        raise RuntimeError(f"cold refusal needs one failed boot: status={status}")
    if not re.search(rf"(?m)^STORAGE FENCE fence=none reason={re.escape(reason)}$", serial):
        raise RuntimeError("missing exact kernel not-established reason")
    refusal = f"RECOVERY WRITABLE REFUSED reason=storage_fence previous={previous} fence=none"
    named = re.search(rf"(?m)^{re.escape(refusal)}$", serial)
    if allow_corrupt:
        named = named or re.search(r"(?m)^FSD FAILED read-only mount: Corrupt\(.+\)$", serial)
    if not named:
        raise RuntimeError("missing named read-only refusal: " + serial[-1800:])
    combined = serial + "\n" + captured_complete(raw)
    if any(word in combined for word in ("FSD READY ", "SSH LISTENING", "MACHINE RECOVER RESET")):
        raise RuntimeError("refused cold boot reached readiness or reset")
    if accounting(serial) != (0, 0, 0):
        raise RuntimeError("refused cold boot issued write/flush/error")
    return named.group(0)


WRITABLE_REFUSED = "RECOVERY WRITABLE REFUSED reason=storage_fence previous=failed fence=none"
NO_SERVER = "FSD PROTOCOL REFUSED reason=no_server status=-5"
# init.rs prints this whole line before the served worker would start.
INIT_REFUSED = "SERVED RECOVERY REFUSED generation_not_ready"


def require_served_successor_refusal(raw, status, reason="not_declared", forbid=()):
    """A served boot after an unclean end (owner fence (b)): require_refusal
    with previous=failed, then init's named pre-ready refusal (the exact
    whole line) and sshd's refusal for want of a server, a complete worker
    capture, no sshd readiness output, no reset or
    stop, and no `forbid` text in the serial. Returns the refusal line."""
    line = require_refusal(raw, status, "failed", reason)
    if line != WRITABLE_REFUSED:
        raise RuntimeError(f"unexpected refusal line: {line!r}")
    serial, worker = raw.decode(errors="replace"), captured_complete(raw)
    if not re.search(rf"(?m)^{re.escape(INIT_REFUSED)}$", serial):
        raise RuntimeError("init did not refuse the not-ready generation by name: " + serial[-800:])
    if not re.search(rf"(?m)^{re.escape(NO_SERVER)}$", worker):
        raise RuntimeError("sshd did not refuse for want of a server: " + worker[-800:])
    for absent in ("SSH HOST KEY", "SSH RECOVERY ", "SSH NET "):
        if absent in worker:
            raise RuntimeError(f"the refused successor's sshd printed {absent!r}: {worker[-800:]}")
    for absent in ("FSD RECOVERY seq=", "SERVED RECOVERY RESET ", "MACHINE STOP", *forbid):
        if absent in serial:
            raise RuntimeError(f"the refused successor printed {absent!r}: {serial[-800:]}")
    return line


UNSUPPORTED = "WRITABLE RECOVERY UNSUPPORTED (owner 2026-10-19; #63)"


def require_successor_in_log(raw_log, status, index, reason="not_declared", forbid=()):
    """The same-QEMU successor of an unclean end, from the whole serial log
    of one QEMU: the run ended with status 7 after exactly `index + 1` boots
    (no further reset), and boot `index + 1` is the strict served refusal
    (require_served_successor_refusal). Returns the refusal line."""
    parts = raw_log.split(b"ABSD KERNEL BOOT\n")[1:]
    if status != "7" or len(parts) != index + 1:
        raise RuntimeError(f"refused successor: status={status} boots={len(parts)}, "
                           f"expected status 7 after exactly {index + 1} boots")
    return require_served_successor_refusal(b"ABSD KERNEL BOOT\n" + parts[index], status, reason, forbid)


def cold_boot(target, backend, name, *, served=True, declaration=None, worker=None, qemu=None):
    if target.proc is not None and target.proc.poll() is None:
        raise RuntimeError("prior producer still running; cold boot refused")
    options = "net fsd" + (" served" if served else "")
    if declaration:
        options += " storage-fence=" + declaration
    # Explicit options: no inherited served-only declaration injection.
    worker = worker or getattr(target, "sshd_elf", target.root / "sshd.elf")
    server = getattr(target, "fsd_elf", target.root / "absd-fsd.elf")
    iso = ssh_absd.AbsdTarget.iso(target, 0, worker, options=options, server=server)
    log = target.work / (name + ".serial.log")
    env = dict(os.environ, ABSD_BLOCK_ATTACH=backend)
    env.pop("ABSD_QEMU_REBOOT", None)
    qemu = qemu or target.qemu
    net = ["-netdev", "user,id=n0,net=10.0.2.0/24", "-device", "e1000,netdev=n0"]
    result = subprocess.run([str(target.kernel / "scripts/durable-boot.sh"), str(iso),
                             str(target.image), str(log), "300", *served_qemu(qemu), *net],
                            capture_output=True, text=True, env=env, timeout=360, check=True)
    return log.read_bytes(), result.stdout.strip(), log


def refused_cold_boot(target, backend, name, *, served=True, declaration=None,
                      previous="failed", reason="not_declared", allow_corrupt=False, qemu=None):
    with open(target.image, "rb") as image:
        before = hashlib.file_digest(image, "sha256").hexdigest()
    raw, status, log = cold_boot(target, backend, name, served=served,
                               declaration=declaration, qemu=qemu)
    line = require_refusal(raw, status, previous, reason, allow_corrupt)
    with open(target.image, "rb") as image:
        after = hashlib.file_digest(image, "sha256").hexdigest()
    if before != after:
        raise RuntimeError("cold refusal changed the owned image")
    print(f"STORAGE FENCE COLD REFUSAL OK name={name} served={served} declaration={declaration} "
          f"status={status} block_writes=0 block_flushes=0 image_unchanged=true", flush=True)
    return {"name": name, "served": served, "declaration": declaration, "status": status,
            "refusal": line, "image_sha256": after, "log": str(log)}
