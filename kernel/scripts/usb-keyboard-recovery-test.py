#!/usr/bin/env python3
"""Actual QMP removal/rebind -> native Console, one bounded guest per case."""
import json
import os
from pathlib import Path
import re
import runpy
import shlex
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
base = runpy.run_path(str(ROOT / 'scripts/usb-keyboard-test.py'))
require, Guest, console_bytes = (base[x] for x in ['require', 'Guest', 'console_bytes'])
CASES = ['cycles', 'empty', 'unsupported', 'during-recovery', 'stall', 'babble', 'short',
         'large-header', 'bad-prefix', 'bad-device', 'swap', 'late-entry', 'reset-timeout', 'budget', 'swap-enumerating']


def check(data, minimum, fault=False, quarantine=False, expected_fault=None, quarantine_after_reset=False):
    serial = console_bytes(data)
    require(b'SHELL SESSION OK\n' in serial and b'ABSD BOOT OK\n' in serial, 'native session did not finish')
    require(not re.search(rb'PANIC|KERNEL FAULT', serial), 'driver failed')
    require((b'USB KEYBOARD QUARANTINED ' in serial) == quarantine, 'unexpected quarantine disposition')
    if quarantine:
        terminal = serial.rfind(b'USB KEYBOARD QUARANTINED ')
        require(not re.search(rb'USB KEYBOARD (?:SUCCESSOR|RECLAIM|REBOUND|ENQUEUED|STATE (?:Running|Fenced|Halting|Draining|Clean|Recovering|Watching))\b', serial[terminal:]), 'quarantined generation progressed')
    failures = re.findall(rb'USB KEYBOARD FAILED ([^\n]+)', serial)
    require(len(failures) == (int(fault) if expected_fault is None else expected_fault[0]), 'unexpected runtime fault count')
    if failures:
        require(all(f.startswith(b'Keyboard(Completion' if expected_fault is None else expected_fault[1]) for f in failures), 'wrong fixture fault')
    fenced = False
    for line in serial.splitlines():
        if b'USB KEYBOARD FENCED ' in line or b'USB KEYBOARD STATE Fenced' in line:
            fenced = True
        if b'USB KEYBOARD REBOUND ' in line:
            fenced = False
        require(not (fenced and b'USB KEYBOARD ENQUEUED ' in line), 'input between fence and successor commit')
    successors = [(int(a), int(b)) for a, b in re.findall(rb'USB KEYBOARD SUCCESSOR retired=(\d+) generation=(\d+)', serial)]
    require(len(successors) >= minimum, 'missing successor construction')
    require(all(b == a + 1 for a, b in successors), 'generation revived or skipped')
    require(all(a[1] == b[0] for a, b in zip(successors, successors[1:])), 'generation history diverged')
    for generation in [b for _, b in successors]:
        start = serial.index(f'USB KEYBOARD SUCCESSOR retired={generation-1} generation={generation}'.encode())
        reclaim = serial.find(f'USB KEYBOARD RECLAIM generation={generation} reset=1 halted=1 dma_off=1'.encode(), start)
        rebound = serial.find(f'USB KEYBOARD REBOUND generation={generation} '.encode(), start)
        if rebound != -1:
            require(start < reclaim < rebound, 'rebind before reset/reclamation')
        prior = serial[:start]
        require(prior.rfind(b'USB KEYBOARD QUIET ') > prior.rfind(b'USB KEYBOARD HALTED DMA_OFF '), 'successor before quiet')
    progress = re.findall(rb'USB KEYBOARD (?:RECOVERY )?PROGRESS tick=(\d+) events=(\d+) acknowledged=(\d+)', serial)
    require(all(0 < int(n) <= 8 for _, n, _ in progress), 'event bound exceeded')
    require(len({t for t, _, _ in progress}) == len(progress), 'multiple event pumps in one tick')
    require(all(int(a[2]) < int(b[2]) for a, b in zip(progress, progress[1:])), 'event acknowledgement regressed')
    require(len(base['VECTOR'].findall(data)) == len(base['DELIVERY'].findall(data)), 'wrong interrupt route')
    enqueues = serial.count(b'USB KEYBOARD ENQUEUED ')
    require(base['normal_reports'](data) >= enqueues, 'missing actual normal-IN completions')
    require(not enqueues or base['DELIVERY'].search(data), 'no actual BSP USB delivery')
    quiet = serial.rfind(b'USB KEYBOARD QUIET ')
    require(quiet >= 0, 'no final clean stop or clean predecessor to quarantine')
    if quarantine_after_reset:
        require(quarantine, 'reset quarantine boundary requires quarantine')
        quiet = serial.rfind(b'USB KEYBOARD QUARANTINED ')
        require(quiet >= 0, 'missing terminal quarantine boundary')
    after = data[base['raw_position'](data, quiet):]
    require(not base['VECTOR'].search(after), 'interrupt after final quiet')
    require(not re.search(rb'usb_xhci_(oper_write|runtime_write|port_write|doorbell_write)\b|msix_write_config ', after), 'device write after final quiet')
    require(b'USB KEYBOARD ENQUEUED ' not in serial[quiet:], 'input after final stop')


def run_case(name, qemu, work):
    fault = name in {'stall', 'babble', 'short'}
    empty = name in {'empty', 'large-header', 'bad-prefix', 'bad-device', 'swap', 'late-entry', 'reset-timeout', 'budget', 'swap-enumerating'} or fault
    variant = 'recover-late-entry' if name == 'late-entry' else 'recover-reset-timeout' if name in {'reset-timeout', 'during-recovery'} else 'recover-enumeration-hold' if name == 'swap-enumerating' else 'recover'
    g = Guest('recover-' + name, qemu, work, serial=True, variant=variant, keyboard=not empty)
    minimum = 1
    try:
        g.wait(rb'^> ')
        if name == 'late-entry':
            g.wait(rb'USB KEYBOARD QUARANTINED statics=reserved$')
            require(b'USB KEYBOARD RECOVERY FIXTURE late-entry source=software-entry' in g.console(), 'missing explicit late-entry fixture')
            g.write_serial('hello-b\n')
            g.wait(rb'shell: hello-b exited 0', shell=True)
            g.write_serial('quit\n')
            check(g.finish(), 1, quarantine=True, expected_fault=(1, b'Keyboard(RetirementUncertain)'))
            return
        if name == 'reset-timeout':
            g.wait(rb'USB KEYBOARD FAILED Keyboard\(ResetTimeout\)')
            g.wait(rb'USB KEYBOARD QUARANTINED statics=reserved$')
            require(g.console().count(b'USB KEYBOARD SUCCESSOR ') == 1, 'reset timeout retried')
            g.write_serial('hello-b\n')
            g.wait(rb'shell: hello-b exited 0', shell=True)
            g.write_serial('quit\n')
            check(g.finish(), 1, quarantine=True, expected_fault=(1, b'Keyboard(ResetTimeout)'), quarantine_after_reset=True)
            return
        if name == 'swap-enumerating':
            g.wait(rb'USB KEYBOARD STATE Watching$')
            before = len(g.data())
            g.qmp.execute('stop')
            for port in [1, 2]:
                g.qmp.execute('device_add', driver='usb-mouse', id=f'mouse{port}', bus='xhci.0', port=str(port))
            g.qmp.execute('cont')
            g.wait(rb'USB KEYBOARD RECOVERY FIXTURE enumeration-held port=5 source=completion-defer$', before)
            before = len(g.data())
            g.qmp.execute('stop')
            g.qmp.execute('device_del', id='mouse1')
            g.qmp.execute('device_add', driver='usb-kbd', id='kbd', bus='xhci.0', port='1')
            g.qmp.execute('cont')
            g.wait(rb'USB KEYBOARD ENUMERATION CHANGE port=5 scanned_through=[56]$', before)
            g.wait(rb'USB KEYBOARD REBOUND generation=\d+ port=5 slot=1$', before)
            g.type('hello-b\n')
            g.wait(rb'shell: hello-b exited 0', shell=True)
            g.type('quit\n', final=True)
            check(g.finish(), 3)
            return
        if name in {'large-header', 'bad-prefix', 'bad-device'}:
            g.wait(rb'USB KEYBOARD STATE Watching$')
            module = runpy.run_path(str(ROOT / 'scripts/usb-large-descriptor.py'))
            path = Path(g.scratch.name) / 'lower'
            g.fixture = module['LargeDescriptor'](path, work / (name + '-device.json'),
                descriptor_fault='prefix' if name == 'bad-prefix' else 'device' if name == 'bad-device' else None)
            g.qmp.execute('chardev-add', id='fixture', backend={'type': 'socket', 'data': {'server': False, 'addr': {'type': 'unix', 'data': {'path': str(path)}}}})
            before = len(g.data())
            g.qmp.execute('device_add', driver='usb-redir', id='fixture', chardev='fixture', bus='xhci.0', port='1')
            g.wait(rb'USB KEYBOARD UNSUPPORTED port=5$', before)
            g.wait(rb'USB KEYBOARD STATE Watching$', before)
            before = len(g.data())
            g.qmp.execute('device_add', driver='usb-kbd', id='kbd', bus='xhci.0', port='2')
            g.wait(rb'USB KEYBOARD REBOUND generation=\d+ port=6 slot=1$', before)
            if name == 'large-header':
                configs = [r for r in g.fixture.records if r.get('descriptor') == 2]
                require(configs and all(r['requested'] == 9 for r in configs), 'runtime fetched oversized configuration')
            require(g.fixture.error is None, f'descriptor fixture failed: {g.fixture.error}')
            g.type('quit\n', final=True)
            check(g.finish(), 3)
            return
        if name == 'swap':
            g.wait(rb'USB KEYBOARD STATE Watching$')
            before = len(g.data())
            g.qmp.execute('device_add', driver='usb-mouse', id='mouse', bus='xhci.0', port='1')
            g.wait(rb'USB KEYBOARD UNSUPPORTED port=5$', before)
            g.wait(rb'USB KEYBOARD STATE Watching$', before)
            before = len(g.data())
            g.qmp.execute('stop')
            g.qmp.execute('device_del', id='mouse')
            g.qmp.execute('device_add', driver='usb-kbd', id='kbd', bus='xhci.0', port='1')
            g.qmp.execute('cont')
            g.wait(rb'USB KEYBOARD REBOUND generation=\d+ port=5 slot=1$', before)
            g.type('quit\n', final=True)
            check(g.finish(), 3)
            return
        if fault or name == 'budget':
            g.wait(rb'USB KEYBOARD STATE Watching$')
            module = runpy.run_path(str(ROOT / 'scripts/usb-large-descriptor.py'))
            path = Path(g.scratch.name) / 'keyboard'
            g.fixture = module['LargeDescriptor'](path, work / (name + '-device.json'), keyboard=True)
            g.qmp.execute('chardev-add', id='fixture', backend={'type': 'socket', 'data': {'server': False, 'addr': {'type': 'unix', 'data': {'path': str(path)}}}})
            before = len(g.data())
            g.qmp.execute('device_add', driver='usb-redir', id='fixture', chardev='fixture', bus='xhci.0', port='1')
            require(g.fixture.connected.wait(timeout=5), 'keyboard fixture did not connect')
            g.wait(rb'USB KEYBOARD REBOUND generation=\d+ port=\d+ slot=1$', before)
            if name == 'budget':
                g.deadline += 180
                faults = 0
                for _ in range(33):
                    before = len(g.data())
                    g.fixture.input(bytes(8), status=4)
                    g.wait(rb'USB KEYBOARD FAILED Keyboard\(CompletionCode\(6\)\)', before)
                    faults += 1
                    result = g.wait(rb'USB KEYBOARD (REBOUND generation=\d+ port=\d+ slot=1|RECOVERY REFUSED budget=32 statics=reserved)$', before)
                    if result[1].startswith(b'RECOVERY REFUSED'):
                        break
                else:
                    require(False, 'successor budget did not terminate recovery')
                require(len(re.findall(rb'USB KEYBOARD SUCCESSOR ', g.console())) == 32, 'wrong exhaustion boundary')
                g.write_serial('hello-b\n')
                g.wait(rb'shell: hello-b exited 0', shell=True)
                g.write_serial('quit\n')
                check(g.finish(), 32, expected_fault=(faults, b'Keyboard(CompletionCode(6))'))
                return
            before = len(g.data())
            status = {'stall': 4, 'babble': 6, 'short': 0}[name]
            g.fixture.input(bytes(7 if name == 'short' else 8), status=status)
            expected = {'stall': 6, 'babble': 3, 'short': 13}[name]
            g.wait(rb'USB KEYBOARD FAILED Keyboard\(CompletionCode\(' + str(expected).encode() + rb'\)\)', before)
            g.wait(rb'USB KEYBOARD REBOUND generation=\d+ port=\d+ slot=1$', before)
            for letter in 'hello-b\n':
                usage = 0x28 if letter == '\n' else 0x2d if letter == '-' else ord(letter) - ord('a') + 4
                before = len(g.data())
                g.fixture.input(bytes([0, 0, usage, 0, 0, 0, 0, 0]))
                g.wait(rb'USB KEYBOARD ENQUEUED bytes=1 ', before)
                before = len(g.data())
                g.fixture.input(bytes(8))
                g.wait(rb'USB KEYBOARD PROGRESS ', before)
            g.wait(rb'shell: hello-b exited 0', shell=True)
            require(g.fixture.error is None, f'keyboard fixture failed: {g.fixture.error}')
            g.write_serial('quit\n')
            check(g.finish(), 3, expected_fault=(1, f'Keyboard(CompletionCode({expected}))'.encode()))
            return
        elif name == 'empty':
            g.wait(rb'USB KEYBOARD STATE Watching$')
            before = len(g.data())
            g.write_serial('hello-b\n')
            g.wait(rb'shell: hello-b exited 0', before, shell=True)
            before = len(g.data())
            g.qmp.execute('device_add', driver='usb-kbd', id='kbd', bus='xhci.0', port='1')
            g.wait(rb'USB KEYBOARD REBOUND generation=\d+ port=\d+ slot=1$', before)
            minimum = 2
            g.type('quit\n', final=True)
        else:
            g.type('hello-b\n')
            g.wait(rb'shell: hello-b exited 0', shell=True)
            for cycle in range(3 if name == 'cycles' else 1):
                before = len(g.data())
                g.qmp.execute('device_del', id='kbd')
                g.wait(rb'USB KEYBOARD SUCCESSOR ', before)
                if name == 'during-recovery':
                    g.wait(rb'USB KEYBOARD RECOVERY FIXTURE reset-pending source=observation-substitution', before)
                    # Actual process exit during an explicitly held reset
                    # observation; no claim QEMU's synchronous HCRST is slow.
                    g.write_serial('quit\n')
                    data = g.finish()
                    serial = console_bytes(data)
                    require(b'interrupted=ResetWait' in serial, 'wrong interrupted phase')
                    require(b'USB KEYBOARD RECOVERY STOP RESET WAIT source=observation-substitution' in serial, 'stop did not exercise reset-pending wait')
                    # The retiring successor need not have reached reconstruction.
                    check(data, 1)
                    return
                g.wait(rb'USB KEYBOARD STATE Watching$', before)
                start = len(g.data())
                g.write_serial('hello-b\n')
                g.wait(rb'shell: hello-b exited 0', start, shell=True)
                if name == 'unsupported':
                    start = len(g.data())
                    g.qmp.execute('device_add', driver='usb-mouse', id='mouse', bus='xhci.0', port='1')
                    g.wait(rb'USB KEYBOARD UNSUPPORTED port=5$', start)
                    g.wait(rb'USB KEYBOARD STATE Watching$', start)
                    start = len(g.data())
                    g.qmp.execute('device_add', driver='usb-kbd', id='kbd', bus='xhci.0', port='2')
                else:
                    start = len(g.data())
                    g.qmp.execute('device_add', driver='usb-kbd', id='kbd', bus='xhci.0', port='1')
                g.wait(rb'USB KEYBOARD REBOUND generation=\d+ port=\d+ slot=1$', start)
                start = len(g.data())
                g.type('hello-b\n')
                g.wait(rb'shell: hello-b exited 0', start, shell=True)
            minimum = 6 if name == 'cycles' else 3 if name == 'unsupported' else 2
            g.type('quit\n', final=True)
        check(g.finish(), minimum)
    finally:
        g.close()


def self_test():
    good = (b'USB KEYBOARD READY\n'
            b'usb_xhci_xfer_start 0x123: slotid 1, epid 3, streamid 0\n'
            b'usb_xhci_xfer_success 0x123: len 8\n'
            b'apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0\n'
            b'USB KEYBOARD ENQUEUED bytes=1 total=1 dropped=0\n'
            b'USB KEYBOARD FENCED reason=disconnected\n'
            b'USB KEYBOARD HALTED DMA_OFF bus_master=0\nUSB KEYBOARD QUIET late=0\n'
            b'USB KEYBOARD SUCCESSOR retired=1 generation=2 attempt=1\n'
            b'USB KEYBOARD RECLAIM generation=2 reset=1 halted=1 dma_off=1\n'
            b'USB KEYBOARD REBOUND generation=2 port=5 slot=1\n'
            b'USB KEYBOARD PROGRESS tick=20 events=1 acknowledged=10\n'
            b'USB KEYBOARD FENCED reason=processes finished\n'
            b'USB KEYBOARD HALTED DMA_OFF bus_master=0\nUSB KEYBOARD QUIET late=0\n'
            b'SHELL SESSION OK\nABSD BOOT OK\n')
    check(good, 1)
    reset_quarantine = (good[:good.index(b'USB KEYBOARD RECLAIM generation=2')]
        + b'usb_xhci_oper_write off 0x00, val 0x00000002\n'
        + b'USB KEYBOARD FAILED Keyboard(ResetTimeout)\nUSB KEYBOARD STATE Quarantined\n'
        + b'USB KEYBOARD QUARANTINED statics=reserved\nSHELL SESSION OK\nABSD BOOT OK\n')
    check(reset_quarantine, 1, quarantine=True, expected_fault=(1, b'Keyboard(ResetTimeout)'), quarantine_after_reset=True)
    for suffix in [b'usb_xhci_oper_write off 0x00, val 0x00000001\n',
                   b'USB KEYBOARD SUCCESSOR retired=2 generation=3 attempt=2\n']:
        try:
            check(reset_quarantine + suffix, 1, quarantine=True,
                  expected_fault=(1, b'Keyboard(ResetTimeout)'), quarantine_after_reset=True)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('reset quarantine accepted terminal progress')
    fence = b'USB KEYBOARD FENCED reason=disconnected\n'
    quiet = good.rfind(b'USB KEYBOARD QUIET ')
    negatives = [good.replace(fence, fence + b'USB KEYBOARD ENQUEUED bytes=1\n'),
        good.replace(b'RECLAIM generation=2 reset=1', b'RECLAIM generation=2 reset=0'),
        good.replace(b'retired=1 generation=2', b'retired=1 generation=1'),
        good + b'USB KEYBOARD ENQUEUED bytes=1\n',
        good[:quiet] + b'USB KEYBOARD QUARANTINED statics=reserved\n' + good[quiet:],
        good + b'usb_xhci_oper_write off 0x00, val 0x00000001\n',
        good + b'apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0\n',
        good.replace(b'events=1 acknowledged=10', b'events=9 acknowledged=10'),
        good.replace(b'USB KEYBOARD PROGRESS tick=20 events=1 acknowledged=10\n',
            b'USB KEYBOARD PROGRESS tick=20 events=1 acknowledged=10\nUSB KEYBOARD PROGRESS tick=20 events=1 acknowledged=11\n'),
        good.replace(b'usb_xhci_xfer_success 0x123: len 8\n', b''),
        good.replace(b'ABSD BOOT OK\n', b''),
        good.replace(b'vector 208 trigger_mode 0', b'vector 208 trigger_mode 1')]
    for data in negatives:
        try:
            check(data, 1)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('recovery oracle accepted a negative control')
    print(f'usb-keyboard-recovery: oracle passed 2 positive and {len(negatives) + 2} negative controls')


def main():
    if sys.argv[1:] == ['--self-test']:
        self_test()
        return
    selected = os.environ.get('USB_RECOVERY_CASES', '').split() or CASES
    require(not set(selected) - set(CASES), 'unknown recovery case')
    work = ROOT / 'build/usb-keyboard-recovery'
    work.mkdir(parents=True, exist_ok=True)
    qemu = shlex.split(sys.argv[1] if len(sys.argv) > 1 else 'qemu-system-x86_64')
    results = []
    for name in selected:
        run_case(name, qemu, work)
        print(f'usb-keyboard-recovery: {name} PASS', flush=True)
        results.append({'case': name, 'disposition': 'PASS'})
    (work / 'RESULT.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
