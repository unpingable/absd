#!/usr/bin/env python3
"""Prepare a QEMU e1000 receive exchange without changing its test deadline.

QEMU's e1000 arms a one-second virtual-clock receive gate on RCTL writes.
The kernel prints the link/probe record after the final probe write. Wait
one second plus a 100 ms host scheduling margin after observing that record.
This is setup for the default, continuously running, non-icount QEMU guests;
it is not a virtual-clock, hardware or receive-latency guarantee. Call only
after QMP cont, and do not pause the VM during this setup interval. First
TX alone does not establish receive readiness (ARP TX can precede the gate).
"""
import re
import time

BOOT = b'ABSD KERNEL BOOT\n'
NIC_READY = re.compile(rb'(?m)^(?:NETWORK LINK OK|NIC LINK DOWN AT PROBE) '
                       rb'rx_descriptors=\d+ tx_descriptors=\d+ buffer_bytes=\d+\n')
RX_SETUP_SECONDS = 1.1
POLL_SECONDS = 0.05


class RxSetupFailed(RuntimeError):
    pass


def wait_rx_setup(read_console, running, deadline, *, clock=None, sleep=None):
    """Wait for the latest boot's NIC record and settle within `deadline`.

    `deadline` is the caller's original absolute readiness deadline. This
    function never renews it, sends a warm-up frame, retries an exchange or
    changes a pass criterion. A reset after the observed NIC record refuses
    stale readiness. Return the host setup duration for optional receipts.
    """
    clock = time.monotonic if clock is None else clock
    sleep = time.sleep if sleep is None else sleep
    started = clock()
    ready_at = generation = None
    while True:
        now = clock()
        if not running():
            raise RxSetupFailed('QEMU ended during e1000 receive setup')
        if now >= deadline:
            raise RxSetupFailed('original readiness deadline expired during e1000 receive setup')
        try:
            raw = read_console()
        except FileNotFoundError:
            raw = b''
        if isinstance(raw, str):
            raw = raw.encode()
        boot = raw.count(BOOT)
        latest = raw.rsplit(BOOT, 1)[-1]
        marker = NIC_READY.search(latest)
        # Console reads/parsing and the process check may take time. Anchor
        # observation after they finish, and refuse late/ended results.
        alive = running()
        now = clock()
        if not alive:
            raise RxSetupFailed('QEMU ended during e1000 receive setup')
        if now >= deadline:
            raise RxSetupFailed('original readiness deadline expired during e1000 receive setup')
        if ready_at is None:
            if marker:
                ready_at, generation = now + RX_SETUP_SECONDS, boot
        elif boot != generation:
            raise RxSetupFailed('guest reset during e1000 receive setup; old readiness refused')
        if ready_at is not None and now >= ready_at:
            return now - started
        remaining = deadline - now
        if ready_at is not None:
            remaining = min(remaining, ready_at - now)
        sleep(min(POLL_SECONDS, remaining))
