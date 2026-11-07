#!/usr/bin/env python3
"""Real bounded boots around successful and interrupted host product updates.

The shared release importer is the stage/selection/cached-rollback/removal
boundary. This control starts from Clean+Ended, checks a successful update,
then commits one ordinary file before a second invalid entry fails. Dirty
must remain, and served/plain/regeneration boots must all refuse with zero
WRITE/FLUSH and an unchanged image. No simulated log is guest evidence.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import storage_fence_guest as guest
import storage_fence_host as host
import storage_fence_state as guard


def load(name):
    path = Path(__file__).with_name(name)
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('platform', 'kernel', 'key', 'work'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--qemu', default='qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand')
    args = parser.parse_args()
    args.sshd_controls = str(Path(args.platform)/'sshd.elf')
    work = Path(args.work).resolve();work.mkdir(parents=True, exist_ok=False, mode=0o700)
    matrix = load('storage-fence-matrix.py')
    release = load('release.py')
    release.QEMU = args.qemu
    target = matrix.new_target(args, work, Path(args.key), None)
    result = {'source': 'real canonical importer/file-server boots', 'backend': 'ata', 'refusals': []}
    try:
        for index, previous in enumerate(('none', 'ended')):
            raw, status, log = guest.cold_boot(target, 'ata', 'bounded-'+str(index),
                                             served=False, worker=target.root/'commands/echo')
            serial = raw.decode(errors='replace')
            if status != '3' or serial.count('ABSD KERNEL BOOT\n') != 1:
                raise RuntimeError('bounded boot failed: '+str(log))
            matrix.fsd_fence(serial, 'none', previous)
            if 'FSD SHUTDOWN FINALIZED status=0' not in serial or target.tree()[guard.PATH] != guard.encode('clean'):
                raise RuntimeError('bounded boot did not finalize cleanly')
            if index == 0:
                identity, marker = host.marker(target.image)
                entries = [('/etc/motd', b'guarded successful update\n')]
                iso = target.iso(4, target.root/'fixture-import.elf', release.em.stream(entries))
                release.importer_boot(target.kernel/'scripts/durable-boot.sh', iso, target.image,
                    work, 40, 1, 4, entries, print)
                if host.marker(target.image) != (identity, marker) or target.tree()['/etc/motd'] != entries[0][1]:
                    raise RuntimeError('successful host update changed guard identity/state or lost data')
                result['successful_update'] = True

        entries = [('/etc/motd', b'committed before the interrupted import\n'),
                   ('/ssh/authorized_keys/child', b'invalid parent')]
        iso = target.iso(4, target.root/'fixture-import.elf', release.em.stream(entries))
        try:
            release.importer_boot(target.kernel/'scripts/durable-boot.sh', iso, target.image,
                work, 41, 1, 4, entries, print)
        except release.ImportFailed as error:
            result['failed_import'] = str(error)
        else:
            raise RuntimeError('negative importer entry unexpectedly succeeded')
        tree = target.tree()
        if tree['/etc/motd'] != entries[0][1] or tree[guard.PATH] != guard.encode('dirty'):
            raise RuntimeError('partial real import or dirty guard was not established')
        for name, served in (('update-served', True), ('update-plain', False)):
            result['refusals'].append(guest.refused_cold_boot(target, 'ata', name,
                                                            previous='ended', served=served))
        ordinary = target.fsd_elf
        try:
            target.fsd_elf = target.root/'absd-fsd-regenerate.elf'
            result['refusals'].append(guest.refused_cold_boot(target, 'ata', 'update-clone-regenerate',
                                                            previous='ended'))
        finally:
            target.fsd_elf = ordinary
        result['verdict'] = 'PASS'
        print('STORAGE FENCE UPDATES OK successful_update=true failed_partial_import=true refusals=3', flush=True)
    except BaseException as error:
        result.update(verdict='FAIL_OR_INCOMPLETE', error=repr(error))
        raise
    finally:
        target.stop()
        (work/'result.json').write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    main()
