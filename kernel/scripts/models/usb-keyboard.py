#!/usr/bin/env python3
"""Bounded keyboard fence/stop model; see NATIVE-USB-STAGE2.md.

One controller generation, at most two submitted TDs. Completion can race
input fencing; interrupts coalesce into one pending bit. Route disable and
the DMA fence are assumptions, not hardware proofs. Two quiet steps stand
for the runtime's twenty ticks. No Rust layout or transfer format is modeled.
"""
from collections import deque
from dataclasses import dataclass, replace
import sys


@dataclass(frozen=True)
class State:
    phase: str = "Running"
    fenced: bool = False
    route: bool = True
    dma_fenced: bool = False
    posted: bool = False
    completed: bool = False
    pending_irq: bool = False
    submitted: int = 0
    delivered: int = 0
    quiet: int = 0
    bad: bool = False
    reclaimed: bool = False
    terminal: bool = False


def steps(s, mutation):
    if s.phase in {"Clean", "Quarantined"}:
        if mutation == "terminal":
            yield "revive-terminal-generation", replace(s, phase="Running")
        # Permission for a subsequent owner; stage 2 reserves its pages even
        # after Clean. This does not revive this generation or its authority.
        if s.phase == "Clean" and not s.reclaimed:
            yield "reclaim-after-fence", replace(s, reclaimed=True)
        return
    if mutation == "reuse" and s.fenced and not s.dma_fenced:
        yield "reuse-before-dma-fence", replace(s, reclaimed=True)
    if s.submitted < 2 and not s.posted and not s.completed:
        if s.phase == "Running" or mutation == "rearm" and s.phase == "Fenced":
            yield "post", replace(s, posted=True, submitted=s.submitted + 1,
                                  bad=s.bad or s.fenced)
    if s.posted and not s.dma_fenced:
        yield "complete", replace(s, posted=False, completed=True,
                                  pending_irq=s.pending_irq or s.route)
    if s.completed and (s.phase == "Running" or mutation == "publish" and s.phase == "Fenced"):
        yield "publish", replace(s, completed=False, delivered=s.delivered + 1,
                                 bad=s.bad or s.fenced)
    if s.pending_irq:
        yield "handle-irq", replace(s, pending_irq=False)
    if s.phase == "Running":
        yield "observe-disconnect-or-stop", replace(s, phase="Fenced", fenced=True)
    if s.phase == "Fenced":
        yield "disable-route-request-halt", replace(s, phase="Halting", route=False)
    if s.phase == "Halting":
        yield "confirm-halt-and-dma-fence", replace(s, phase="Draining", dma_fenced=True)
    if s.phase == "Draining" and not s.pending_irq and s.quiet < 2:
        yield "quiet-step", replace(s, quiet=s.quiet + 1)
    if s.phase == "Draining" and (s.quiet == 2 or mutation == "quiet"):
        yield "clean", replace(s, phase="Clean", terminal=True)
    # Observation of authority loss or uncertainty is terminal; no later
    # transition may touch the device, publish input or rearm a TD.
    yield "ownership-loss-or-uncertainty", replace(s, phase="Quarantined", fenced=True, terminal=True)


def explore(mutation=None):
    queue = deque([(State(), ())])
    seen = {State()}
    while queue:
        state, path = queue.popleft()
        if state.bad or state.terminal and state.phase == "Running" or state.reclaimed and not state.dma_fenced or state.phase == "Clean" and (
                not state.dma_fenced or state.pending_irq or state.quiet != 2):
            return len(seen), path
        for name, next_state in steps(state, mutation):
            if next_state not in seen:
                seen.add(next_state)
                queue.append((next_state, path + (name,)))
    return len(seen), None


def main():
    if sys.argv[1:] not in ([], ["--self-test"]):
        raise SystemExit("usage: usb-keyboard.py [--self-test]")
    count, failure = explore()
    if failure is not None:
        raise SystemExit(f"usb-keyboard model FAIL: {failure}")
    print(f"usb-keyboard model: {count} bounded states; fence/stop properties hold")
    for mutation in ["publish", "rearm", "quiet", "terminal", "reuse"]:
        _, negative = explore(mutation)
        if negative is None:
            raise SystemExit(f"usb-keyboard model negative control missing: {mutation}")
        print(f"usb-keyboard model: omitted-{mutation}-guard control: " + " -> ".join(negative))


if __name__ == "__main__":
    main()
