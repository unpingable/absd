#!/usr/bin/env python3
"""The opt-in CPU profile for the served operator image and launcher."""
import os
import shlex
import sys


def profile(env=None):
    env = os.environ if env is None else env
    value = env.get('ABSD_OPERATOR_CPUS', '1')
    if value not in ('1', '2', '4', '6'):
        raise ValueError('ABSD_OPERATOR_CPUS must be 1, 2, 4 or 6')
    return int(value)


def qemu(argv, env=None):
    words = shlex.split(argv) if isinstance(argv, str) else list(argv)
    cpus = profile(env)
    if cpus > 1:
        if any(word.startswith(('-smp', '--smp')) for word in words):
            raise ValueError('SMP operator profile owns QEMU CPU count; remove -smp')
        words += ['-smp', f'{cpus},sockets=1,cores={cpus},threads=1']
    return words


def main(args):
    if args[0] == 'check':
        qemu(args[2:])
        cpus = profile()
        if cpus > 1:
            from operator_boot_binding import iso_payload, validate_operator_grub
            _, grub = iso_payload(open(args[1], 'rb').read())
            validate_operator_grub(grub, cpus)
    elif args[0] == 'launch':
        command = qemu(args[1:])
        os.execvp(command[0], command)
    else:
        raise ValueError('expected check or launch')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (ValueError, OSError) as error:
        sys.exit(str(error))
