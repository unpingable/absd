#!/usr/bin/env python3
"""Fail-closed serial oracles for the admitted v0 terminal/refusal cases.
These validate captured guest output; synthetic self-tests are not guest evidence.
"""
import argparse
from pathlib import Path
import re
import unittest

CLEAN = 'SERVED FRAME ACCOUNTING records=0 total=0 used=0 idle=0 status=ok'


def check(text, case, service='init', frames=16427, error=-12, usable_bytes=None, minimum_bytes=None):
    lines = text.splitlines()
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    require(not re.search(r'(?i)panicked|kernel panic', text), 'panic is not a refusal')
    accounting = [line for line in lines if line.startswith('SERVED FRAME ACCOUNTING ')]
    if case == 'clean':
        require(accounting == [CLEAN], 'missing, repeated or dirty terminal accounting')
        require(any('WORKLOAD OK' in line for line in lines), 'missing workload success')
        require(not any('FRAME ADMISSION REFUSED' in line for line in lines), 'admission refused')
    elif case == 'accounting-failure':
        require(len(accounting) == 1 and re.fullmatch(
            r'SERVED FRAME ACCOUNTING records=\d+ total=\d+ used=\d+ idle=\d+ status=failed',
            accounting[0]), 'missing accounting failure')
        require('MACHINE RESTART' not in text and 'WORKLOAD OK' not in text,
                'accounting failure allowed success or reset')
    elif case == 'ram-refusal':
        refusals = [re.fullmatch(
            r'SERVED FRAME BOOT REFUSED reason=ram_below_minimum usable_bytes=(\d+) minimum_bytes=(\d+)', line)
            for line in lines if line.startswith('SERVED FRAME BOOT REFUSED')]
        require(len(refusals) == 1 and refusals[0] is not None, 'missing exact RAM refusal')
        usable, minimum = map(int, refusals[0].groups())
        require(usable < minimum, 'refusal despite sufficient backing')
        require(usable_bytes is None or usable == usable_bytes, 'wrong usable bytes')
        require(minimum_bytes is None or minimum == minimum_bytes, 'wrong minimum bytes')
        require('SSH LISTENING' not in text and 'MACHINE RESTART' not in text and 'WORKLOAD OK' not in text,
                'boot refused but became ready or successful')
    elif case == 'admission-refusal':
        require(f'SERVED FRAME ADMISSION REFUSED service={service} frames={frames} error={error}' in lines,
                'missing exact admission refusal')
        step = {'init': 'frame self admission', 'fsd': 'file server spawn', 'sshd': 'external workload spawn'}[service]
        require(f'init: FAILED at {step}' in lines, 'missing existing init failure')
        require('SSH LISTENING' not in text and 'WORKLOAD OK' not in text, 'refusal downgraded to ready/success')
    elif case == 'finalizer-refusal':
        require('SERVED SHUTDOWN FINALIZE FAILED step=finalize spawn' in lines, 'missing ordinary finalizer refusal')
        require(not any(line.startswith('SERVED SHUTDOWN FINALIZED') for line in lines), 'false finalization')
    elif case == 'private':
        for actor in ('init', 'child'):
            for number in range(0x7ff0, 0x7ff5):
                require(f'FRAME V0 PRIVATE actor={actor} number={number} result=-38' in lines,
                        f'missing private-call witness {actor}/{number}')
    else:
        raise ValueError('unknown case')


class Oracles(unittest.TestCase):
    def test_accounting_cannot_pass_on_idle_alone_or_restart(self):
        check(CLEAN + '\nWORKLOAD OK\n', 'clean')
        with self.assertRaises(ValueError):
            check(CLEAN.replace('records=0', 'records=1') + '\nWORKLOAD OK\n', 'clean')
        failure = 'SERVED FRAME ACCOUNTING records=1 total=1 used=1 idle=0 status=failed\n'
        check(failure, 'accounting-failure')
        for suffix in ('MACHINE RESTART', 'WORKLOAD OK', 'kernel panicked'):
            with self.assertRaises(ValueError):
                check(failure + suffix, 'accounting-failure')

    def test_refusal_is_exact_and_never_ready(self):
        refusal = 'SERVED FRAME BOOT REFUSED reason=ram_below_minimum usable_bytes=134086656 minimum_bytes=152543232\n'
        check(refusal, 'ram-refusal')
        for minimum in (134086656, 134086655):
            with self.assertRaises(ValueError):
                check(refusal.replace('152543232', str(minimum)), 'ram-refusal')
        with self.assertRaises(ValueError):
            check(refusal + refusal, 'ram-refusal')
        with self.assertRaises(ValueError):
            check(refusal, 'ram-refusal', usable_bytes=1)
        with self.assertRaises(ValueError):
            check(refusal + 'SSH LISTENING', 'ram-refusal')
        for service, total, step in [('init',16427,'frame self admission'), ('fsd',9333,'file server spawn'), ('sshd',9434,'external workload spawn')]:
            text = f'SERVED FRAME ADMISSION REFUSED service={service} frames={total} error=-38\ninit: FAILED at {step}\n'
            check(text, 'admission-refusal', service, total, -38)
            with self.assertRaises(ValueError):
                check(text.replace('error=-38', 'error=-12'), 'admission-refusal', service, total, -38)

    def test_every_private_call_for_both_actors_is_required(self):
        lines = [f'FRAME V0 PRIVATE actor={actor} number={n} result=-38' for actor in ('init','child') for n in range(0x7ff0,0x7ff5)]
        check('\n'.join(lines), 'private')
        with self.assertRaises(ValueError):
            check('\n'.join(lines[:-1]), 'private')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path, nargs='?')
    parser.add_argument('--case', choices=['clean','accounting-failure','ram-refusal','admission-refusal','finalizer-refusal','private'])
    parser.add_argument('--service', choices=['init','fsd','sshd'], default='init')
    parser.add_argument('--frames', type=int, default=16427)
    parser.add_argument('--error', type=int, default=-12)
    parser.add_argument('--usable-bytes', type=int)
    parser.add_argument('--minimum-bytes', type=int)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[__file__])
    if args.log is None or args.case is None:
        parser.error('log and --case are required')
    try:
        check(args.log.read_text(), args.case, args.service, args.frames, args.error, args.usable_bytes, args.minimum_bytes)
        print(f'FRAME V0 LOG OK case={args.case}')
    except (ValueError, OSError) as error:
        parser.exit(1, f'{error}\n')
