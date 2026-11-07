#!/usr/bin/env python3
"""Own the operator launch from spawn through recovery classification.

boot-operator.sh execs this process with the recovery lock on descriptor 9.
Signal handlers only latch intent. The synchronous owner always reaps its
exact child before classification; optional diagnostics cannot abort cleanup.
"""
import os
from pathlib import Path
import signal
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import storage_fence_resume as recovery


def diagnostic(text, fd=1):
    """A closed terminal or pipe must not change a durable classification."""
    try:
        os.write(fd, (text+'\n').encode())
    except OSError:
        pass


def retire(child):
    # Popen retains the observed return code, and its signal methods poll
    # before sending. Never target a PID after observing its terminal status.
    if child is None or child.returncode is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        child.kill()
        # SIGKILL ends a runnable substitute/QEMU; wait still owns reaping.
        # A host task stuck in uninterruptible I/O may delay reap. Keep the
        # recovery lock in that case rather than classify a running machine.
        child.wait()


def supervise(out, console, ident, console_stdio, command):
    interrupted = False

    def latch(signum, frame):
        nonlocal interrupted
        interrupted = True

    # This attended launcher owns HUP even when inherited as SIG_IGN.
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, latch)
    # Python normally ignores SIGPIPE. Set it explicitly so even a caller
    # with a different disposition cannot kill this owner on a diagnostic.
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    child = None
    status = 1
    bookkeeping_failed = False
    launch_error = None
    try:
        if interrupted:
            status = 130
        else:
            # close_fds excludes the lock descriptor and every other extra
            # descriptor. Popen returns the owned object even if a latched
            # signal arrives while its internal spawn is still in progress.
            child = subprocess.Popen(command, close_fds=True,
                                     stdin=None if console_stdio else subprocess.DEVNULL)
            if ident and recovery.launched(out, ident=ident, pid=child.pid,
                                           console=console, log=diagnostic) != 0:
                raise RuntimeError('launched publication refused')
            while True:
                if interrupted:
                    status = 130
                    break
                try:
                    returncode = child.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    continue
                # A normal exit returned as guest halt (status 3) wins over a late signal.
                # Otherwise a latched stop selects 130 even when QEMU returns 0
                # from its own signal handler. Cleanup never changes this choice.
                status = 130 if interrupted and returncode != 3 else (
                    returncode if returncode >= 0 else 128-returncode)
                break
    except Exception as error:
        bookkeeping_failed = True
        launch_error = error
    finally:
        # No optional output is allowed before exact-child retirement here.
        retire(child)

    if launch_error is not None:
        diagnostic(f'boot-operator: launched record could not be published or launch failed: {launch_error}', 2)
    try:
        classified = recovery.exit_path(out, status_word=str(status), console=console, log=diagnostic)
        if classified not in (0, recovery.LAUNCH_FAILED):
            bookkeeping_failed = True
    except Exception as error:
        classified = 1
        bookkeeping_failed = True
        diagnostic(f'boot-operator: exit classification error: {error}', 2)
    if bookkeeping_failed:
        diagnostic(f'boot-operator: the exit classification failed or launch bookkeeping failed (status {status}); run release.py recover --status', 2)
        return 1
    if status == 130:
        return 130
    if classified == recovery.LAUNCH_FAILED:
        diagnostic(f'boot-operator: launch failed: QEMU exited with status {status} before ABSD KERNEL BOOT (see {console}); the authorization is intact: fix the cause and boot again', 2)
        return 6
    if status == 3:
        diagnostic('boot-operator: the machine halted')
        return 0
    diagnostic(f'boot-operator: QEMU exited with status {status} (see {console})', 2)
    return status


if __name__ == '__main__':
    out, console, ident, stdio = sys.argv[1:5]
    sys.exit(supervise(out, console, ident, stdio == '1', sys.argv[5:]))
