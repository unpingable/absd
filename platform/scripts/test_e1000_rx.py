#!/usr/bin/env python3
"""Receive-setup ordering and deadline controls. No QEMU or network sockets."""
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import e1000_rx as rx
import ssh_absd

NIC = b'NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n'
DOWN = b'NIC LINK DOWN AT PROBE rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n'
BOOT = b'ABSD KERNEL BOOT\n'


def load(name):
    spec = importlib.util.spec_from_file_location('rx_' + name.replace('-', '_'), HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class Process:
    pid = 12345
    returncode = None

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9

    def wait(self):
        return self.returncode


class Socket:
    def bind(self, path):
        pass

    def settimeout(self, value):
        pass

    def close(self):
        pass


class ReachedFirstExchange(Exception):
    pass


class GateTests(unittest.TestCase):
    def run_gate(self, read, clock, deadline=4, running=lambda: True):
        return rx.wait_rx_setup(read, running, deadline, clock=clock, sleep=clock.sleep)

    def test_late_observed_marker_anchors_a_full_setup_interval(self):
        clock = Clock()
        elapsed = self.run_gate(lambda: BOOT + (NIC if clock.now >= 0.5 else b''), clock)
        self.assertGreaterEqual(elapsed, 0.5 + rx.RX_SETUP_SECONDS)
        self.assertLess(elapsed, 1.7)
        self.assertTrue(all(0 < wait <= rx.POLL_SECONDS for wait in clock.sleeps))

    def test_link_down_probe_still_allows_receive_gate_to_expire(self):
        clock = Clock()
        self.assertEqual(self.run_gate(lambda: BOOT + DOWN, clock), rx.RX_SETUP_SECONDS)

    def test_first_transmit_is_not_a_receive_gate_witness(self):
        clock = Clock()
        with self.assertRaisesRegex(rx.RxSetupFailed, 'original readiness deadline'):
            self.run_gate(lambda: BOOT + b'GUEST ARP TX\n', clock, deadline=0.3)
        self.assertLessEqual(clock.now, 0.3)

    def test_setup_does_not_renew_the_original_deadline(self):
        clock = Clock()
        with self.assertRaisesRegex(rx.RxSetupFailed, 'original readiness deadline'):
            self.run_gate(lambda: BOOT + NIC, clock, deadline=0.7)
        self.assertEqual(clock.now, 0.7)

    def test_partial_record_is_not_ready(self):
        clock = Clock()
        with self.assertRaises(rx.RxSetupFailed):
            self.run_gate(lambda: BOOT + NIC[:-1], clock, deadline=0.2)

    def test_old_boot_record_is_not_reused_after_reset(self):
        clock = Clock()
        old = BOOT + NIC
        with self.assertRaisesRegex(rx.RxSetupFailed, 'reset'):
            self.run_gate(lambda: old + (BOOT if clock.now >= 0.2 else b''), clock)

    def test_latest_boot_must_have_its_own_complete_record(self):
        clock = Clock()
        with self.assertRaisesRegex(rx.RxSetupFailed, 'deadline'):
            self.run_gate(lambda: BOOT + NIC + BOOT, clock, deadline=0.2)

    def test_process_exit_refuses_without_waiting_out_setup(self):
        clock = Clock()
        with self.assertRaisesRegex(rx.RxSetupFailed, 'QEMU ended'):
            self.run_gate(lambda: BOOT + NIC, clock, running=lambda: clock.now < 0.2)
        self.assertLess(clock.now, rx.RX_SETUP_SECONDS)

    def test_slow_first_read_does_not_backdate_marker_observation(self):
        clock = Clock()
        reads = []
        def read():
            if not reads:
                clock.now += 1.2
            reads.append(clock.now)
            return BOOT + NIC
        elapsed = self.run_gate(read, clock)
        self.assertGreaterEqual(elapsed, 1.2 + rx.RX_SETUP_SECONDS)

    def test_slow_final_read_cannot_return_after_original_deadline(self):
        clock = Clock()
        def read():
            if clock.now >= rx.RX_SETUP_SECONDS:
                clock.now += 0.4
            return BOOT + NIC
        with self.assertRaisesRegex(rx.RxSetupFailed, 'deadline'):
            self.run_gate(read, clock, deadline=1.3)

    def test_process_ending_during_read_is_refused_before_another_sleep(self):
        clock = Clock()
        def read():
            clock.now = 0.2
            return BOOT + NIC
        with self.assertRaisesRegex(rx.RxSetupFailed, 'QEMU ended'):
            self.run_gate(read, clock, running=lambda: clock.now < 0.1)
        self.assertEqual(clock.sleeps, [])


class CallSiteTests(unittest.TestCase):
    def test_network_ready_retains_one_absolute_deadline(self):
        net = load('net-matrix.py')
        clock = Clock()
        match = object()
        def output(*args, **kw):
            self.assertEqual(kw['timeout'], 5)
            clock.now = 2
            return match
        def setup(read, running, deadline):
            self.assertEqual(deadline, 5)  # not two seconds plus a new five
            self.assertTrue(running())
        with patch.object(net.time, 'monotonic', clock), patch.object(net, 'wait_output', output), \
                patch.object(net, 'wait_rx_setup', setup):
            self.assertIs(net.wait_network_ready('unused', b'ready', Process(), timeout=5), match)

    def test_raw_frame_sender_is_reached_only_after_setup(self):
        net = load('net-matrix.py')
        prepared = []
        ready = SimpleNamespace(group=lambda n: {1: b'52:54:00:12:34:56', 2: b'up'}[n])
        def prepare(*args, **kw):
            prepared.append(True)
            return ready
        def wire(*args):
            self.assertEqual(prepared, [True])
            raise ReachedFirstExchange()
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(net, 'build_iso', return_value=('iso', 'image')), \
                patch.object(net, 'start_qemu', return_value=Process()), \
                patch.object(net.socket, 'socket', return_value=Socket()), \
                patch.object(net, 'wait_network_ready', prepare), \
                patch.object(net, 'wait_output', return_value=ready), patch.object(net, 'Wire', wire):
            with self.assertRaises(ReachedFirstExchange):
                net.run_frames_with_sockets('kernel', 'elf', tmp, tmp)

    def test_tcp_measurement_and_connect_start_after_setup(self):
        net = load('net-matrix.py')
        prepared = []
        ready = SimpleNamespace(group=lambda n: b'2')
        def prepare(*args, **kw):
            prepared.append(True)
            return ready
        def clock():
            self.assertEqual(prepared, [True], 'measurement started before RX preparation')
            return 10
        def connect(*args):
            self.assertEqual(prepared, [True])
            raise ReachedFirstExchange()
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(net, 'build_iso', return_value=('iso', 'image')), \
                patch.object(net, 'start_qemu', return_value=Process()), \
                patch.object(net, 'free_ports', return_value=[1, 2, 3]), \
                patch.object(net, 'wait_network_ready', prepare), \
                patch.object(net, 'wait_output', return_value=ready), \
                patch.object(net.time, 'monotonic', clock), patch.object(net, 'connect', connect):
            with self.assertRaises(ReachedFirstExchange):
                net.run_tcp('kernel', 'elf', tmp)

    def test_shared_ssh_start_does_not_return_before_setup(self):
        target = ssh_absd.AbsdTarget.__new__(ssh_absd.AbsdTarget)
        target.work = Path('/unused'); target.kernel = Path('/unused')
        target.image = Path('/unused/image'); target.port = 2222
        target.boots = 0; target.boot_seconds = 600; target.qemu = 'qemu'
        target.sshd_iso = lambda regenerate=False: '/unused/iso'
        target.system_objects = lambda: []
        target.host_public_from_image = lambda: 'ssh-ed25519 AAAA'
        target.serial = lambda: (BOOT + NIC + b'FSD HOST KEY PRESENT \nFSD READY\n').decode()
        target.output = lambda: ('SSH LISTENING\nSSH HOST KEY LOADED ssh-ed25519 AAAA SHA256:abc\n'
                                'SSH STORAGE VIA FILE SERVER OK block=none '
                                'control=/ssh:ro,/bin:ro,/etc:ro,/var/log:rw,/var/state:ro,/var/state/facts:rw slots=8\n')
        prepared = []
        def setup(read, running, deadline):
            self.assertEqual(deadline, 304)
            self.assertTrue(running())
            self.assertIn('NETWORK LINK OK', read())
            prepared.append(True)
        try:
            with patch.object(ssh_absd.subprocess, 'Popen', return_value=Process()), \
                    patch.object(ssh_absd, 'end_boots_on_signal'), \
                    patch.object(ssh_absd.time, 'monotonic', return_value=4), \
                    patch.object(ssh_absd, 'wait_rx_setup', setup):
                result = target.start()
            self.assertEqual(prepared, [True])
            self.assertEqual(result['public'], 'ssh-ed25519 AAAA')
        finally:
            ssh_absd.LIVE_BOOTS.discard(target)


    def test_ring_fault_start_observes_identity_without_claiming_receive_preparation(self):
        for injected, explicit, expected in [(True,True,'identity'),(False,True,'marker'),(True,False,'ended')]:
            with self.subTest(injected=injected,explicit=explicit):
                target=ssh_absd.AbsdTarget.__new__(ssh_absd.AbsdTarget)
                target.work=Path('/unused');target.kernel=Path('/unused');target.image=Path('/unused/image')
                target.port=2222;target.boots=0;target.boot_seconds=600;target.qemu='qemu'
                target.sshd_iso=lambda regenerate=False:'/unused/iso';target.system_objects=lambda:[]
                target.host_public_from_image=lambda:'ssh-ed25519 AAAA'
                raw=(BOOT+NIC+b'FSD HOST KEY PRESENT \nFSD READY\n').decode()
                if injected:raw+='NIC RING FAULT INJECTED rdh=35\n'
                target.serial=lambda:raw
                target.output=lambda:('SSH LISTENING\nSSH HOST KEY LOADED ssh-ed25519 AAAA SHA256:abc\n'
                    'SSH STORAGE VIA FILE SERVER OK block=none control=/ssh:ro,/bin:ro,/etc:ro,'
                    '/var/log:rw,/var/state:ro,/var/state/facts:rw slots=8\n')
                ended=Process();ended.returncode=0
                try:
                    with patch.object(ssh_absd.subprocess,'Popen',return_value=ended), \
                            patch.object(ssh_absd,'end_boots_on_signal'), \
                            patch.object(ssh_absd.time,'monotonic',return_value=4):
                        if expected=='identity':
                            with patch.object(ssh_absd,'wait_rx_setup',side_effect=AssertionError('fault observation must not claim RX setup')):
                                result=target.start(expect_nic_fault=explicit)
                            self.assertEqual(result['public'],'ssh-ed25519 AAAA')
                            self.assertFalse(result['receive_prepared'])
                        else:
                            with self.assertRaisesRegex(ssh_absd.Failed,'injection marker' if expected=='marker' else 'QEMU ended'):
                                target.start(expect_nic_fault=explicit)
                finally:ssh_absd.LIVE_BOOTS.discard(target)


class IndependentBootPaths(unittest.TestCase):
    def test_operator_does_not_advertise_prepared_state_after_setup_failure(self):
        operator = load('operator-matrix.py')
        boot = operator.Boot.__new__(operator.Boot)
        boot.proc = Process()
        boot.worker = lambda: 'SSH LISTENING'
        boot.text = lambda: (BOOT + NIC).decode()
        output = io.StringIO()
        with patch.object(operator, 'wait_rx_setup', side_effect=rx.RxSetupFailed('deadline')) as setup, \
                patch.object(operator.sys, 'stderr', output):
            self.assertFalse(boot.await_listening(timeout=7))
        self.assertEqual(setup.call_count, 1)
        self.assertIn('OPERATOR RECEIVE SETUP FAILED reason=deadline', output.getvalue())

    def test_release_retains_readiness_deadline_and_host_identity(self):
        release = load('release.py')
        boot = release.Boot.__new__(release.Boot)
        boot.proc = Process()
        boot.serial = lambda: (BOOT + NIC).decode() + 'RELEASE OK release=fixture\n'
        boot.worker = lambda: 'SSH LISTENING\nSSH HOST KEY LOADED ssh-ed25519 AAAA SHA256:abc\n'
        prepared = []
        def setup(read, running, deadline):
            self.assertEqual(deadline, 17)
            prepared.append(True)
        def trust(public):
            self.assertEqual(prepared, [True])
            self.assertEqual(public, 'ssh-ed25519 AAAA')
        boot.client = SimpleNamespace(trust=trust)
        with patch.object(release.time, 'monotonic', return_value=10), \
                patch.object(release, 'wait_rx_setup', setup):
            self.assertEqual(boot.wait_ready('fixture', timeout=7)['host_key'], 'ssh-ed25519 AAAA')

    def test_recovery_does_not_return_a_generation_lost_during_setup(self):
        recovery = load('survival-recovery.py')
        identity = 'a' * 32
        serial = (BOOT + NIC).decode() + f'FSD READY \nFSD CAPACITY boot={identity} \n'
        worker = f'SSH LISTENING port=22 authorized_keys=1 preauth_per_source=2\nSERVED CAPACITY boot={identity} \n'
        parts = [(serial, worker)]
        target = SimpleNamespace(proc=Process(), serial=lambda: serial)
        def setup(*args):
            parts.append((serial, worker))
        with patch.object(recovery, 'boot_parts', side_effect=lambda t: list(parts)), \
                patch.object(recovery, 'wait_rx_setup', setup):
            with self.assertRaisesRegex(RuntimeError, 'changed generation'):
                recovery.ready(target, 0, target.proc.pid, timeout=7)


if __name__ == '__main__':
    unittest.main()
