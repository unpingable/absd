#!/usr/bin/env python3
"""Two-generation reconstruction model. Hardware fences are assumptions.

One TD per generation, two quiet steps, possible queued completion. The old
runtime is retired before a new private generation is constructed. Reset
clears the modeled controller's queued events before storage reuse. The wire
event carries no generation tag: after pointer reuse an old identical event
cannot be recognized by identity matching alone. Clearing and fencing are
therefore essential assumptions, not a claim of tag checking in hardware.
"""
from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    generation: int = 1
    phase: str = 'Running'
    retired: int = 0
    dma_off: bool = False
    route_off: bool = False
    pending: bool = False
    quiet: int = 0
    reset: bool = False
    reused: bool = False
    posted: bool = False
    submitted: bool = False
    completion: int = 0
    bad: bool = False


def steps(s, mutation):
    if s.phase == 'Quarantined':
        return
    if s.phase == 'Running':
        if not s.submitted:
            yield 'post', replace(s, posted=True, submitted=True)
        if s.completion:
            yield 'publish', replace(s, completion=0, bad=s.bad or s.completion != s.generation)
        yield 'fence', replace(s, phase='Fenced', retired=s.retired | (1 << s.generation))
    if s.posted and not s.dma_off and s.phase in {'Running', 'Fenced'}:
        yield 'complete', replace(s, posted=False, completion=s.generation, pending=True)
    if s.pending:
        yield 'drain-irq', replace(s, pending=False, quiet=0)
    if s.phase == 'Fenced':
        yield 'halt-dma-route-fences', replace(s, phase='Draining', dma_off=True, route_off=True)
    if s.phase == 'Draining' and not s.pending and s.quiet < 2:
        yield 'quiet', replace(s, quiet=s.quiet + 1)
    if s.phase == 'Draining' and s.quiet == 2:
        yield 'retire', replace(s, phase='Clean')
    if s.phase == 'Clean' and s.generation == 1:
        yield 'construct-successor', replace(s, phase='Resetting')
    if mutation == 'terminal' and s.phase == 'Clean':
        yield 'revive-old', replace(s, phase='Running', bad=True)
    if s.phase == 'Resetting':
        yield 'confirm-reset', replace(s, phase='Reconstructing', reset=True,
            completion=s.completion if mutation == 'reset' else 0, posted=False)
    if s.phase == 'Reconstructing' or mutation == 'reuse' and s.phase == 'Fenced':
        yield 'reuse-storage', replace(s, phase='Validating', reused=True,
            bad=s.bad or not (s.dma_off and s.route_off and not s.pending and s.quiet == 2 and s.reset))
    if s.phase == 'Validating':
        yield 'fresh-generation-route', replace(s, generation=2, phase='Running', dma_off=False,
            route_off=False, quiet=0, posted=False, submitted=False, reused=False, reset=False)
    if s.phase not in {'Clean'}:
        yield 'uncertainty', replace(s, phase='Quarantined')


def explore(mutation=None):
    queue = deque([(State(), ())]); seen = {State()}
    while queue:
        s, path = queue.popleft()
        if s.bad or s.phase == 'Running' and s.retired & (1 << s.generation):
            return len(seen), path
        for action, nxt in steps(s, mutation):
            if nxt not in seen:
                seen.add(nxt); queue.append((nxt, path + (action,)))
    return len(seen), None


def main():
    count, failure = explore()
    assert failure is None, failure
    print(f'usb-recovery model: {count} states; generation, reuse and completion properties hold')
    for mutation in ['terminal', 'reuse', 'reset']:
        _, failure = explore(mutation)
        assert failure is not None, mutation
        print(f'usb-recovery model: omitted-{mutation}: ' + ' -> '.join(failure))


if __name__ == '__main__':
    main()
