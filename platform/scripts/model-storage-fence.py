#!/usr/bin/env python3
"""Bounded writable-entry model: two boots, one retained effect per failure.

Correspondence: write_guard::{assess,begin,finish,finish_update}, the host
offline mutation transaction, recovery::charge and init's same-boot
finalizer. Sector effects are atomic and occur at most
once; a successful flush orders preceding successful writes. A failed
write may apply later, independently of boot/reset. The fixed marker's
allocation never moves and only the authorized current writer changes it.
This model proves no physical-device or repeated-effect guarantee.

Operator-authorized resume (coordination record #63, fsd/src/resume.rs,
scripts/storage_fence_resume.py): the host act writes a record naming the
exact committed state it saw (here: the marker and ledger), only on an
unclean charged history and only when no retained filesystem command is
outstanding (the act's attestation, not a mechanism). A serving successor
admits a dirty marker exactly when the record names its current state,
consumes the record as its first device write, and charges. A failed
consumption write retains an effect that can only write `none`. The two
added negative controls: `record-any-state` (a record admits whatever
state the disk is in) and `consume-effect-record` (a delayed consumption
effect re-establishes the record); a third boot runs only after a resume.
"""

from collections import deque
from dataclasses import dataclass, replace
import json


@dataclass(frozen=True)
class State:
    boot: int = 0
    phase: str = "assess"
    marker: str = "fresh"
    ledger: str = "absent"
    expected: str = "fresh"
    pending: tuple = ()
    # The resume slot: "none", or ("record", marker, ledger, origin) with
    # origin "act" (the operator wrote it) or "effect" (a device effect did).
    slot: tuple = ("none",)
    # Operator acts so far, and whether this boot was admitted by a record.
    acts: int = 0
    resumed: bool = False


RESUME_PROPERTIES = (
    "a resume admission is of exactly the authorized state: dirty marker, charged unclean history, "
    "and a record the operator act wrote naming that state",
    "a delayed consumption effect can only write none; no record a device effect wrote admits anything",
)


def explore(mutation=None):
    seen = set()
    phases = set()
    # An NVMe presentation may have an NBD backend: the declaration does
    # not remove its retained commands from the transition system.
    for backend in ("ata", "nvme-nbd"):
        for declaration in ("none", "controller", "external"):
            for writers in ((a,b) for a in ('plain','served','update') for b in ('plain','served','update')):
                for seed, history in (("absent","absent"), ("invalid","absent"),
                                      ("fresh","absent"), ("clean","ended")):
                    initial = State(marker=seed, ledger=history)
                    queue = deque([(initial, ())])
                    local = set()
                    while queue:
                        state, trace = queue.popleft()
                        if state in local:
                            continue
                        local.add(state)
                        writer = writers[min(state.boot, 1)]
                        served = writer == 'served'
                        seen.add((backend, declaration, writers, state))
                        phases.add(state.phase)
                        retained_fs = any(kind.startswith("fs-") and generation < state.boot
                                          for kind, generation in state.pending)
                        if state.phase in ("charge", "data", "complete") and retained_fs:
                            return {"states": len(seen), "counterexample": {
                                "backend": backend, "declaration": declaration,
                                "writers": writers, "seed": seed,
                                "trace": trace + ("filesystem mutation permitted with prior command outstanding",),
                            }}
                        if state.phase == "consume" and state.slot[0] == "record":
                            # The resume properties, checked at every resume admission
                            # (the state the admission step was taken in).
                            record = state.slot
                            exact = (state.marker == "dirty" and state.ledger == "active"
                                     and record[1:3] == (state.marker, state.ledger))
                            if not exact:
                                return {"states": len(seen), "counterexample": {
                                    "backend": backend, "declaration": declaration, "writers": writers,
                                    "seed": seed, "trace": trace + ("resume admission of a state the act did not name",)}}
                            if record[3] != "act":
                                return {"states": len(seen), "counterexample": {
                                    "backend": backend, "declaration": declaration, "writers": writers,
                                    "seed": seed, "trace": trace + ("resume admission by a record a device effect wrote",)}}

                        def step(label, **fields):
                            queue.append((replace(state, **fields), trace + (label,)))

                        def failed(kind):
                            step("failed " + kind + ": retain effect, stop",
                                 phase="stopped", pending=state.pending + ((kind, state.boot),))

                        # The device may finish any old failed command at
                        # any phase, including after a successor started.
                        for index, (kind, generation) in enumerate(state.pending):
                            pending = state.pending[:index] + state.pending[index + 1:]
                            fields = {"pending": pending}
                            if kind in ("dirty", "clean", "fresh"):
                                fields["marker"] = kind
                            elif kind == "fs-ledger":
                                fields["ledger"] = "active"
                            elif kind == "fs-complete":
                                fields["ledger"] = "ended"
                            elif kind == "slot-none":
                                # Negative control: the delayed effect re-establishes a record.
                                fields["slot"] = (("record", "dirty", "active", "effect")
                                                  if mutation == "consume-effect-record" else ("none",))
                            step(f"late {kind} effect from boot {generation}", **fields)

                        if state.phase == "assess":
                            # Negative controls reproduce the three rejected
                            # admission paths; none is an allowed policy.
                            declared = declaration == "external" or (
                                declaration == "controller" and backend == "nvme-nbd")
                            bypass = ((mutation == "declaration" and declared)
                                      or (mutation == "served-only" and not served)
                                      or (mutation == "update-unguarded" and writer == 'update'))
                            record = state.slot[0] == "record"
                            checks = (record and state.marker == "dirty" and state.ledger == "active"
                                      and state.slot[1:3] == ("dirty", "active"))
                            if bypass:
                                step("unchecked admission bypass", phase="data" if writer == 'update' else "charge")
                            elif ((state.marker, state.ledger) in
                                  (("fresh", "absent"), ("clean", "ended"))
                                  or (mutation == "absent-ledger" and state.ledger == "absent")):
                                step("read-only admission", phase="arm", expected=state.marker)
                            elif (writer != 'update' and state.marker == "dirty"
                                  and (checks or (mutation == "record-any-state" and record))):
                                # Path (e): the record names this exact state; the
                                # guard stays dirty and the record is consumed first.
                                step("resume admission by the operator's record", phase="consume",
                                     expected="dirty", resumed=True)
                            else:
                                step("refuse before write/flush", phase="refused")
                        elif state.phase == "consume":
                            # begin rechecks the assessment: a record that is no
                            # longer there (a delayed consumption effect landed)
                            # or a changed marker refuses before any write.
                            if state.marker != state.expected or state.slot[0] != "record":
                                step("assessment changed: refuse", phase="refused")
                            else:
                                step("write none at the fixed slot", slot=("none",), phase="consume-flush")
                                failed("slot-none")
                                step("interrupt before the consumption write", phase="stopped")
                        elif state.phase == "consume-flush":
                            step("consumption flush acknowledged", phase="charge")
                            step("consumption flush failed/interrupted: poisoned, no FS write", phase="stopped")
                        elif state.phase == "arm":
                            if state.marker != state.expected:
                                step("assessment changed: refuse", phase="refused")
                            else:
                                step("write fixed dirty sector", marker="dirty", phase="arm-flush")
                                failed("dirty")
                                step("interrupt before dirty write", phase="stopped")
                        elif state.phase == "arm-flush":
                            step("dirty flush acknowledged", phase="data" if writer == 'update' else "charge")
                            step("dirty flush failed/interrupted: no FS write", phase="stopped")
                        elif state.phase == "charge":
                            step("ledger creation/charge acknowledged", ledger="active", phase="data")
                            failed("fs-ledger")
                            step("interrupt before ledger creation", phase="stopped")
                        elif state.phase == "data":
                            step("ordinary filesystem writes acknowledged",
                                 phase="update-sync" if writer == 'update' else "complete")
                            failed("fs-data")
                            step("interrupt during service", phase="stopped")
                        elif state.phase == "complete":
                            # Source conditions also require same boot id,
                            # matching shutdown facts, successful reaping
                            # and no descendant. Those have focused tests.
                            step("same-boot completion and FS sync acknowledged",
                                 ledger="ended", phase="clean-write")
                            failed("fs-complete")
                            step("completion flush failed: keep dirty", phase="stopped")
                        elif state.phase == "update-sync":
                            step("bounded update verified; unchanged history; FS sync acknowledged", phase="clean-write")
                            step("update sync failed: keep dirty", phase="stopped")
                        elif state.phase == "clean-write":
                            marker = state.expected if writer == 'update' else 'clean'
                            step("write final marker last", marker=marker, phase="clean-flush")
                            failed(marker)
                            step("interrupt before clean write", phase="stopped")
                        elif state.phase == "clean-flush":
                            step("clean flush acknowledged or interrupted", phase="stopped")
                        elif state.phase in ("stopped", "refused"):
                            # The operator act (release.py recover): one record for
                            # the exact unclean charged state, attested free of
                            # outstanding filesystem commands, at most once per boot.
                            unclean = state.marker == "dirty" and state.ledger == "active"
                            attested = not any(kind.startswith("fs-") for kind, _ in state.pending)
                            if (state.slot == ("none",) and state.acts == state.boot
                                    and (unclean or (mutation == "record-any-state" and state.marker == "dirty"))
                                    and attested):
                                step("operator act writes the record for the state it saw",
                                     slot=("record", state.marker, state.ledger, "act"), acts=state.acts + 1)
                            if state.boot == 0:
                                step("boot successor without retiring retained effects", boot=1, phase="assess",
                                     resumed=False)
                            elif state.boot == 1 and state.resumed:
                                # A third boot only after a resume: the consumed record's
                                # delayed effects and the recovered generation's end.
                                step("boot the recovered generation's successor", boot=2, phase="assess",
                                     resumed=False)
    return {"states": len(seen), "phases": sorted(phases), "counterexample": None}


def main():
    baseline = explore()
    if baseline["counterexample"]:
        raise AssertionError(baseline)
    controls = {name: explore(name) for name in
                ("declaration", "served-only", "absent-ledger", "update-unguarded",
                 "record-any-state", "consume-effect-record")}
    if not all(result["counterexample"] for result in controls.values()):
        raise AssertionError("negative control did not discriminate: " + json.dumps(controls, indent=2))
    print(json.dumps({"scope": "two boots (three after a resume); each retained sector effect once; ordered "
                               "successful flushes; fixed marker and slot mapping; the act attested free of "
                               "outstanding filesystem commands",
                      "resume_properties": RESUME_PROPERTIES,
                      "baseline": baseline, "negative_controls": controls}, indent=2))
    print(f"STORAGE FENCE MODEL OK controls={len(controls)}")


if __name__ == "__main__":
    main()
