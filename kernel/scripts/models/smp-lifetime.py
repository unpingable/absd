#!/usr/bin/env python3
"""Small explicit-state scheduler/lifetime abstraction; not a kernel proof."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
import argparse


@dataclass(frozen=True)
class S:
    gen: int = 0                 # one reusable slot, generations 0..2
    life: str = "Empty"          # Empty/Runnable/Running/Waiting/Terminal
    home: int = 0                # queued placement or last running CPU
    owner: int = -1
    active_mask: int = 0
    loaded_mask: int = 0
    saved: bool = True
    fenced_gens: int = 0
    reclaimed_gens: int = 0
    delivered: bool = False
    epoch: int = 0
    qmask: int = 0               # one bit per CPU; queue identity is this generation
    ctx: bool = False
    cr3: bool = False
    resources: bool = False
    stop: str = "Active"         # Active/Requested/Observed/Departed
    pending: int = -1            # deferred migration destination
    steal_armed: bool = False
    wait_record: bool = False
    intent: str = ""             # exit/fault/stop while still executing
    acked: bool = False
    parent_waiting: bool = False # abstract parent continuation, not a modeled task
    parent_ready: bool = False


def check(s: S, ncpu: int) -> None:
    allmask = (1 << ncpu) - 1
    assert 0 <= s.home < ncpu
    assert s.qmask & ~allmask == 0
    assert s.qmask.bit_count() <= 1, "duplicate queue membership"
    assert s.active_mask.bit_count() <= 1, "duplicate execution"
    assert s.loaded_mask.bit_count() <= 1, "duplicate address-space activity"
    assert s.active_mask == s.loaded_mask
    assert s.active_mask == (0 if s.owner < 0 else 1 << s.owner)
    if s.active_mask: assert not (s.fenced_gens | s.reclaimed_gens) & (1 << s.gen), "execution after fence"
    if s.delivered:
        assert s.reclaimed_gens & (1 << s.gen), "wait returned before total fence"
        assert s.owner == -1 and not s.active_mask and not s.loaded_mask and not s.resources

    if s.life == "Empty":
        assert s.owner == -1 and s.qmask == 0
        assert not s.ctx and not s.cr3 and not s.resources
        assert s.pending == -1 and not s.wait_record
    elif s.life == "Reclaimed":
        assert not s.resources and not s.cr3 and not s.ctx
        assert s.owner == -1 and s.qmask == 0 and s.pending == -1 and not s.wait_record
        assert s.reclaimed_gens & (1 << s.gen)
    else:
        assert s.gen in (1, 2) and s.ctx and s.cr3 and s.resources
    if s.owner >= 0:
        assert s.owner < ncpu
        assert s.life in ("Running", "Waiting")
        assert s.stop != "Departed"
        assert s.qmask == 0
        assert s.home == s.owner
    assert bool(s.qmask) == (s.life == "Runnable")
    if s.life == "Running" and s.owner == -1:
        assert s.stop == "Departed" and s.intent == "stop", "orphan running state"
    if s.life == "Runnable":
        assert s.owner == -1 and s.stop == "Active"
        assert s.qmask == 1 << s.home and s.saved
    if s.life == "Waiting":
        assert s.qmask == 0 and s.wait_record
        if s.owner == -1:
            assert s.stop == "Active"
    if s.pending >= 0:
        # A block can set Waiting before the common switch departs the CPU;
        # the pending destination remains fenced until that departure cancels it.
        assert s.pending < ncpu and s.owner >= 0 and s.life in ("Running", "Waiting")
    if s.stop == "Departed":
        assert s.owner == -1 and s.qmask == 0 and s.intent == "stop"
    if s.acked:
        assert s.stop == "Departed" and s.life in ("Terminal", "Reclaimed")
    if s.intent == "stop" and s.life in ("Terminal", "Reclaimed"):
        assert s.acked and s.fenced_gens & (1 << s.gen), "stop reclaimed without ack fence"
    if s.life == "Terminal":
        assert s.owner == -1 and s.qmask == 0 and s.pending == -1
        assert s.intent in ("exit", "fault", "stop", "kill")
    if s.parent_ready:
        assert s.life in ("Reclaimed", "Empty")


def acknowledge(s:S, token:tuple[int,int,int])->S:
    assert token==(s.gen,s.epoch,s.home), "stale stop token"
    assert s.stop=="Departed" and s.owner==-1 and not s.active_mask and not s.loaded_mask, "ack before departure"
    return replace(s,life="Terminal",acked=True,fenced_gens=s.fenced_gens|(1<<s.gen))

def step(s: S, ncpu: int):
    # Spawn/reuse. The toy model starts each generation on CPU0.
    if s.life == "Empty" and s.gen < 2:
        g = s.gen + 1
        yield "spawn", replace(s, gen=g, life="Runnable", home=0, qmask=1,
                               ctx=True, cr3=True, resources=True, stop="Active",
                               pending=-1, steal_armed=False, wait_record=False,
                               intent="", acked=False, parent_ready=False,
                               parent_waiting=False, delivered=False)
    # Claim only the task's unique runnable membership.
    # Absolute claim epochs are capped at four total over both generations;
    # the epoch remains monotonic across slot reuse.
    if s.life == "Runnable" and s.stop == "Active" and s.epoch < 4:
        for cpu in range(ncpu):
            if s.qmask == 1 << cpu:
                yield "dispatch", replace(s, life="Running", owner=cpu,
                                           home=cpu, epoch=s.epoch + 1, qmask=0, active_mask=1<<cpu, loaded_mask=1<<cpu, saved=False)
        if s.steal_armed:
            for cpu in range(ncpu):
                if cpu != s.home:
                    # Transfer and claim are combined as one scheduler selection
                    # boundary; source membership disappears before destination claim.
                    yield "steal+dispatch", replace(s, life="Running", owner=cpu,
                                                      home=cpu, epoch=s.epoch + 1,
                                                      qmask=0, steal_armed=False, active_mask=1<<cpu, loaded_mask=1<<cpu, saved=False)
        if s.steal_armed:
            yield "steal-disarm", replace(s, steal_armed=False)
        for dest in range(ncpu):
            if dest != s.home:
                yield "migration-request-transfer", replace(s, home=dest,
                                                               qmask=1 << dest)
        if s.epoch > 0 and not s.steal_armed:
            yield "arm-steal", replace(s, steal_armed=True)
    if s.life == "Running" and s.owner >= 0 and s.stop == "Active" and s.intent == "":
        # Ordinary yield/preemption departs the saved context then republishes it.
        dest = s.pending if s.pending >= 0 else s.owner
        yield "yield/preempt-depart+publish", replace(s, life="Runnable", owner=-1,
                                                        home=dest, qmask=1 << dest,
                                                        pending=-1, active_mask=0, loaded_mask=0, saved=True)
        # The syscall stores wait metadata before scheduler departure. Owner
        # remains until commit_cpu_switch leaves the task stack/CR3/TSS.
        yield "block", replace(s, life="Waiting", wait_record=True, qmask=0)
        for dest in range(ncpu):
            if dest != s.owner and s.pending < 0:
                yield "migration-request-deferred", replace(s, pending=dest)
        if s.epoch > 0 and not s.steal_armed:
            yield "arm-steal", replace(s, steal_armed=True)
        yield "exit-intent", replace(s, intent="exit")
        yield "fault-intent", replace(s, intent="fault")
        yield "stop-request", replace(s, stop="Requested", intent="stop")
    if s.life == "Running" and s.owner >= 0 and s.intent in ("exit", "fault"):
        yield "terminal-depart", replace(s, life="Terminal", owner=-1,
                                            qmask=0, home=s.home, pending=-1,
                                            wait_record=False, active_mask=0, loaded_mask=0)
    if s.life == "Waiting" and s.owner >= 0:
        # A block's departure cancels any deferred destination: sleeping work
        # is absent from every run queue until its ordinary wake.
        if not s.saved:
            yield "save-block-frame", replace(s, saved=True)
        else:
            yield "block-depart", replace(s, owner=-1, pending=-1, active_mask=0, loaded_mask=0)
    if s.life == "Waiting" and s.owner == -1 and s.stop == "Active":
        yield "wake+publish", replace(s, life="Runnable", qmask=1 << s.home,
                                       wait_record=False)
    if s.life in ("Runnable", "Waiting") and s.owner == -1 and s.stop == "Active":
        # Ordinary kill of an unowned runnable/blocked process needs no remote
        # stop ACK, but still removes queue/wait authority before reclamation.
        yield "kill-unowned", replace(s, life="Terminal", qmask=0, pending=-1,
                                       wait_record=False, intent="kill")
    if s.life in ("Running", "Waiting") and s.owner >= 0 and s.stop == "Requested":
        yield "stop-observed", replace(s, stop="Observed")
    if s.life in ("Running", "Waiting") and s.owner >= 0 and s.stop == "Observed":
        yield "stop-depart", replace(s, owner=-1, qmask=0, pending=-1,
                                      stop="Departed", life="Running",
                                      wait_record=False, active_mask=0, loaded_mask=0)
    if s.stop == "Departed" and s.life == "Running" and s.owner == -1:
        # The AP ACK/drain boundary is after hardware departure; terminal stop
        # disposition and parent completion occur after that boundary.
        yield "ack+terminalize", acknowledge(s, (s.gen, s.epoch, s.home))
    if s.life == "Terminal" and s.resources:
        if s.intent == "stop": assert s.acked
        yield "release-resources", replace(s, life="Reclaimed", ctx=False,cr3=False,resources=False,
                                             reclaimed_gens=s.reclaimed_gens|(1<<s.gen))
    if s.life == "Reclaimed" and not s.delivered:
        yield "wait-result", replace(s,parent_waiting=False,parent_ready=True,delivered=True)
    if s.life == "Reclaimed" and s.delivered:
        yield "release-slot", replace(s,life="Empty",home=0,stop="Active",intent="",acked=False,
                                         steal_armed=False,wait_record=False,saved=True)

    if s.life in ("Runnable", "Running", "Waiting") and not s.parent_waiting and not s.parent_ready:
        # Abstract parent wait registration/outcome handoff; does not model its
        # CPU claim or queue.
        yield "parent-wait", replace(s, parent_waiting=True)


def explore(ncpu: int, max_states: int = 250_000):
    initial = S()
    todo = deque([(initial, ())])
    seen = {initial}
    terminal_paths = 0
    max_depth = 0
    while todo:
        state, path = todo.popleft()
        check(state, ncpu)
        max_depth = max(max_depth, len(path))
        if state.gen == 2 and state.life == "Empty":
            terminal_paths += 1
        if len(seen) > max_states:
            raise RuntimeError(f"state bound exceeded at {ncpu} CPUs")
        for action, nxt in step(state, ncpu):
            check(nxt, ncpu)
            if nxt not in seen:
                seen.add(nxt)
                todo.append((nxt, path + (action,)))
    return {"cpus": ncpu, "states": len(seen), "depth": max_depth,
            "second_generation_empty_states": terminal_paths}


def mutant_checks():
    # Seed states are reachable-shaped boundaries; each mutated proposition is
    # checked by the same invariant function used on explored successors.
    base = S(gen=1, life="Running", home=0, owner=0, epoch=1, qmask=0,
             ctx=True, cr3=True, resources=True, active_mask=1, loaded_mask=1, saved=False)
    wait = replace(base, life="Waiting", wait_record=True)
    runq = replace(base, life="Runnable", owner=-1, qmask=1,active_mask=0,loaded_mask=0,saved=True)
    stop_req = replace(wait, stop="Requested", intent="stop")
    departed = replace(base, owner=-1, stop="Departed", intent="stop",active_mask=0,loaded_mask=0)
    terminal = acknowledge(departed,(departed.gen,departed.epoch,departed.home))
    mutants = {
        "early-transfer-while-owned": replace(base, qmask=2),
        "ack-before-departure": replace(base, acked=True),
        "free-resources-while-running": replace(base, resources=False),
        "lost-wake-publication": replace(runq, qmask=0),
        "duplicate-queue-membership": replace(runq, qmask=3),
        "duplicate-execution": replace(base,active_mask=3,loaded_mask=3),
        "wait-before-cleanup": replace(terminal,delivered=True),
        "wake-before-context-save": replace(runq,saved=False),
        "execution-after-ack": replace(base,fenced_gens=2),
        "wake-after-stop-request": replace(stop_req, life="Runnable", qmask=1,owner=-1,active_mask=0,loaded_mask=0,saved=True,
                                            wait_record=False),
    }
    for seed in [base, wait, runq, stop_req, departed, terminal]: check(seed,2)
    for name, bad in mutants.items():
        try:
            check(bad, 2)
        except AssertionError:
            continue
        raise AssertionError(f"mutant escaped: {name}")
    # A stop acknowledgment is bound to (generation, epoch, owner). A token
    # from generation one must not match a reused generation-two slot.
    stale = (1, 1, 0)
    reused = replace(terminal, gen=2, life="Running", epoch=2, owner=1,
                     home=1, stop="Active", intent="", acked=False,
                     parent_ready=False, resources=True, ctx=True, cr3=True)
    try: acknowledge(replace(reused,owner=-1,active_mask=0,loaded_mask=0,stop="Departed",intent="stop"), stale)
    except AssertionError: pass
    else: raise AssertionError("stale stop token accepted")
    return list(mutants) + ["stale-generation-ack"]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true", help="check deterministic mutants")
    args = ap.parse_args()
    results = [explore(2), explore(3)]
    mutants = mutant_checks() if args.self_test else []
    for r in results:
        print(f"MODEL OK cpus={r['cpus']} states={r['states']} max-depth={r['depth']} "
              f"gen2-empty={r['second_generation_empty_states']}")
    if args.self_test:
        print(f"MODEL MUTANTS REJECTED count={len(mutants)} cases={','.join(mutants)}")


if __name__ == "__main__":
    main()
