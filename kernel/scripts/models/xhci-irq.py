#!/usr/bin/env python3
"""Bounded IRQ-generation model for NATIVE-USB-STAGE1.md.

Two generations, at most two posted messages per generation, one LAPIC
pending bit (coalescing), a synchronous BSP handler. The fence is assumed
to stop new posting and to flush already posted messages into LAPIC state.
This assumption needs hardware qualification; this model cannot prove it.
"""
from collections import deque
from dataclasses import dataclass, replace
import sys


@dataclass(frozen=True)
class State:
    generation: int = 0
    armed: bool = False
    fenced: bool = True
    pending: int = 0  # oracle source generation; absent from the real MSI
    sent: int = 0
    credited: tuple = ()
    retired: int = 0


def steps(s, skip_drain):
    if not s.armed and s.fenced and s.generation < 2 and (skip_drain or not s.pending):
        yield "arm", replace(s, generation=s.generation + 1, armed=True, fenced=False, sent=0)
    if s.armed and not s.fenced and s.sent < 2:
        yield "post", replace(s, pending=s.pending or s.generation, sent=s.sent + 1)
    if s.armed and not s.fenced:
        yield "fence-retire", replace(s, armed=False, fenced=True)
    if s.pending:
        yield "handle", replace(s, pending=0,
            credited=s.credited + ((s.pending, s.generation),) if s.armed else s.credited,
            retired=s.retired + int(not s.armed))


def explore(skip_drain=False):
    initial = State()
    queue = deque([(initial, ())])
    seen = {initial}
    while queue:
        state, path = queue.popleft()
        if any(source != receiver for source, receiver in state.credited):
            return len(seen), path
        for name, next_state in steps(state, skip_drain):
            if next_state not in seen:
                seen.add(next_state)
                queue.append((next_state, path + (name,)))
    return len(seen), None


def main():
    if sys.argv[1:] not in ([], ["--self-test"]):
        raise SystemExit("usage: xhci-irq.py [--self-test]")
    states, counterexample = explore()
    if counterexample is not None:
        raise SystemExit(f"xhci-irq model FAIL: {counterexample}")
    _, negative = explore(skip_drain=True)
    if negative is None:
        raise SystemExit("xhci-irq model negative control failed to distinguish omitted drain")
    print(f"xhci-irq model: {states} bounded states; no cross-generation credit")
    print("xhci-irq model: omitted-drain control: " + " -> ".join(negative))


if __name__ == "__main__":
    main()
