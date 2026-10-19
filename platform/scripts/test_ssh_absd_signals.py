"""Host test: a signalled ssh driver ends its boot (ssh_absd.end_boots_on_signal).

A fake kernel's scripts/durable-boot.sh stands in for the boot: like the
real one it runs `timeout <boot-seconds>s <emulator>`, here `sleep`, and it
never prints SSH LISTENING, so the driver waits in AbsdTarget.start(). The
test SIGTERMs the driver (and, separately, SIGINTs and SIGHUPs it) and
asserts that it died of that signal (KeyboardInterrupt for SIGINT) and that
no descendant of it is left. SIGKILL is not tested: it cannot be caught,
and the boot then lives until its own timeout (disclosed in ssh_absd.py).
No QEMU, no ISO, no image is used.
"""

import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import ssh_absd  # noqa: E402

FAKE_BOOT = """#!/bin/sh
# iso image output seconds [emulator arguments...]
status=0
timeout "${4}s" sleep 600 || status=$?
printf '%s\\n' "$status"
"""

DRIVER = """
import pathlib, sys
sys.path.insert(0, sys.argv[1])
import ssh_absd
work = pathlib.Path(sys.argv[2])
t = ssh_absd.target(["--kernel", str(work / "kernel"), "--shell", str(work / "shell"),
                     "--boot-seconds", "600", "--qemu", "fake"])
t.work, t.image, t.port = work, work / "image", 1
t.sshd_iso = lambda regenerate=False: work / "fake.iso"
t.system_objects = lambda: []
t.start()
"""


def alive(pid):
    try:
        state = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except OSError:
        return False
    return state != "Z"


def run(signum, work):
    driver = subprocess.Popen([sys.executable, "-I", "-c", DRIVER, str(here), str(work)],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 30
    boot = []
    while time.monotonic() < deadline:
        boot = ssh_absd.descendants(driver.pid)
        # sh, timeout and sleep: the whole fake boot has started.
        if len(boot) >= 3:
            break
        time.sleep(0.1)
    else:
        driver.kill()
        raise SystemExit(f"fake boot did not start: {driver.communicate()[0]!r}")
    os.kill(driver.pid, signum)
    try:
        output = driver.communicate(timeout=60)[0]
    except subprocess.TimeoutExpired:
        driver.kill()
        raise SystemExit(f"driver ignored {signal.Signals(signum).name}")
    if signum == signal.SIGINT:
        assert driver.returncode in (1, -signum) and b"KeyboardInterrupt" in output, (driver.returncode, output)
    else:
        assert driver.returncode == -signum, (driver.returncode, output)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and any(alive(pid) for pid in boot):
        time.sleep(0.1)
    left = [pid for pid in boot if alive(pid)]
    for pid in left:
        os.kill(pid, signal.SIGKILL)
    assert not left, f"{signal.Signals(signum).name}: descendants left {left}"
    return len(boot)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        (work / "kernel" / "scripts").mkdir(parents=True)
        boot = work / "kernel" / "scripts" / "durable-boot.sh"
        boot.write_text(FAKE_BOOT)
        boot.chmod(0o755)
        counts = [run(signum, work) for signum in ssh_absd.END_SIGNALS]
    print(f"ABSD SSH DRIVER SIGNAL TEST OK signals=TERM,INT,HUP descendants={counts[0]} left=0")


if __name__ == "__main__":
    main()
