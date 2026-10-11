#!/usr/bin/env python3
"""Validate the fpu-test boot's isolation evidence, not just its final line."""
import re
import sys
from pathlib import Path

ORDER = [
    'fpu-mxcsr: task A preserved rounds=400 mxcsr=0x0000ff80',
    'FPU MXCSR ISOLATION OK',
    'FPU XM FAULT OK',
    'FPU POST-FAULT WITNESS OK',
    'FPU EXIT WITNESS OK',
    'FPU KILL WITNESS OK',
    'FPU OK',
    'ABSD BOOT OK',
]


def check(path):
    lines = Path(path).read_text().splitlines()
    assert not any(re.search(r'PANIC|KERNEL FAULT|CORRUPTED|CONTAMINATED|NOT DELIVERED|ESCAPED|FAILED', s)
                   for s in lines)
    position = 0
    for marker in ORDER:
        position = lines.index(marker, position) + 1
    assert 'fpu-mxcsr: task B preserved rounds=400 mxcsr=0x00003fc0' in lines
    assert sum(s.startswith('fpu-mxcsr: witness default state mxcsr=0x00001f80 fcw=0x037f')
               for s in lines) == 3
    faults = [s for s in lines if s.startswith('USER FAULT ')]
    assert len(faults) == 1 and re.match(r'USER FAULT pid=4 vector=19 address=0x[0-9a-f]+ error=0x0+$',
                                         faults[0])
    counters = [s for s in lines if s.startswith('FPU status=')]
    assert len(counters) == 1
    fields = dict(re.findall(r'(\w+)=(\d+)', counters[0]))
    assert fields['status'] == '0'
    assert fields['faults'] == '1' and fields['kills'] == '1'
    # The isolation tasks never block, so a timer preemption from one directly
    # to the other proves their state crossed an involuntary switch.
    assert int(fields['peer_preempts']) >= 2
    return int(fields['peer_preempts'])


if __name__ == '__main__':
    try:
        preempts = check(sys.argv[1])
    except (AssertionError, ValueError, KeyError) as error:
        print(f'check-fpu: {sys.argv[1]} rejected ({error!r})', file=sys.stderr)
        sys.exit(1)
    print(f'check-fpu: FPU/MXCSR isolation evidence accepted peer_preempts={preempts}')
