"""Bounded protocol model of pinned-point replacement, not a kernel proof.

Three destination generations, two source values, one later successor value,
and at most 16 transitions. Pin validity and orderly-halt/served/write results
are abstract inputs. Native qualification must establish their correspondence.
The single-live-identity rule is an OPERATOR assumption, not global detection
implemented by release.py. Retirement and preservation of the original are
operator assumptions except for the explicitly modelled tool calls. The
legacy replacement refusal abstracts its source-table/target admission checks;
host controls, not this model, establish correspondence. Hardware fencing and
host power loss are excluded.
"""

import argparse
from collections import deque
import json
from pathlib import Path
from typing import NamedTuple

DEPTH = 16
STATE_LIMIT = 100000
ABSENT = ("absent", "A", -1)


class State(NamedTuple):
    original: str
    source_value: int
    point: int
    point_clean: bool
    pin_valid: bool
    original_fenced: bool
    fenced_value: int
    targets: tuple
    retired: int


def set_target(s, i, value, **extra):
    targets = list(s.targets); targets[i] = value
    return s._replace(targets=tuple(targets), **extra)


def transitions(s, mutant=None):
    if s.original == "serving":
        yield "halt-original", s._replace(original="halted")
        if s.point >= 0 and s.source_value == 0:
            yield "commit-after-point", s._replace(source_value=1)
        yield "unclean-stop-original", s._replace(original="fenced", original_fenced=True,
                                                   fenced_value=s.source_value)
    if s.original == "halted":
        yield "resume-original", s._replace(original="serving")
        if s.point >= 0:
            yield "retire-original", s._replace(original="retired")
    if s.point < 0 and (s.original == "halted" or
                       (mutant == "dirty_point" and s.original == "serving")):
        yield "capture-point", s._replace(point=s.source_value, point_clean=s.original == "halted")
    if mutant == "reset_original" and s.original == "fenced":
        yield "clear-original-fence", s._replace(original="halted")
    if s.original == "fenced" and s.point >= 0:
        # A legacy restore is an explicit refused operation, not an implicit
        # promise that the tool can prevent all external original mutation.
        yield "legacy-replace-refused", s
        if mutant == "legacy_replace":
            yield "legacy-replace-fenced-original", s._replace(original="halted", source_value=s.point)
    for i, (phase, release, value) in enumerate(s.targets):
        fresh = phase == "absent" or (mutant == "reuse_fenced" and phase == "fenced")
        admitted = s.point >= 0 and s.point_clean and (s.pin_valid or mutant == "untrusted_point")
        if fresh and admitted and s.original in ("fenced", "retired"):
            yield f"restore-A:{i}", set_target(s, i, ("constructed", "A", s.point))
            if phase == "absent":
                yield f"interrupt-construction:{i}", set_target(s, i, ("partial", "A", -1))
        if phase == "constructed" and release == "A":
            yield f"stage-select-B:{i}", set_target(s, i, ("constructed", "B", value))
        if phase == "constructed" and release == "B":
            yield f"B-refused-before-ready:{i}", set_target(s, i, ("fenced", "B", value),
                                                          retired=s.retired | (1 << i))
        if mutant == "rollback_dirty" and phase == "fenced":
            yield f"select-A-on-dirty-B:{i}", set_target(s, i, ("constructed", "A", s.point))
        # A previous serving/halted generation must be retired before a
        # different one serves the same identity. This is a stated assumption.
        previous = any(j != i and item[0] in ("serving", "halted")
                       for j, item in enumerate(s.targets))
        if phase in ("constructed", "halted") and (not previous or mutant == "concurrent_serve"):
            action = "serve" if phase == "constructed" else "restart"
            yield f"{action}-{release}:{i}", set_target(s, i, ("serving", release, value))
        if phase == "serving":
            if value != 2:
                yield f"new-write-{release}:{i}", set_target(s, i, (phase, release, 2))
            yield f"clean-halt-{release}:{i}", set_target(s, i, ("halted", release, value))
        if phase == "halted":
            yield f"retire-{release}:{i}", set_target(s, i, ("retired", release, value),
                                                   retired=s.retired | (1 << i))


def invariant(s):
    if s.point >= 0 and not s.point_clean:
        return "recovery point was not captured after a clean halt"
    if s.original_fenced and (s.original != "fenced" or s.source_value != s.fenced_value):
        return "original preservation assumption or modelled tool refusal was violated"
    if any(t[0] != "absent" for t in s.targets) and not s.pin_valid:
        return "untrusted point admitted destination effects"
    if sum(t[0] == "serving" for t in s.targets) > 1:
        return "concurrent serving copies of one logical identity"
    for i, (phase, _, value) in enumerate(s.targets):
        if s.retired & (1 << i) and phase not in ("retired", "fenced"):
            return "fenced or retired target generation was reused"
        if phase == "constructed" and value != s.point:
            return "construction did not reproduce the point"
    return None


def explore(mutant=None):
    initial = [State("serving", 0, -1, False, pin, False, -1, (ABSENT,) * 3, 0)
               for pin in (False, True)]
    queue = deque((s, ()) for s in initial); seen = set(initial)
    edges, witnesses = 0, {}
    while queue:
        state, trace = queue.popleft()
        if len(trace) == DEPTH:
            continue
        for action, successor in transitions(state, mutant):
            edges += 1; steps = trace + (action,)
            failure = invariant(successor)
            if failure:
                return {"states": len(seen), "transitions": edges, "counterexample": {
                    "reason": failure, "trace": steps, "state": successor._asdict()}}
            if action.startswith("restart-A:") and successor.targets[int(action.split(":")[1])][2] == 2:
                if successor.original_fenced and successor.point < successor.fenced_value:
                    witnesses.setdefault("recovery_RPO_and_new_write_restart", steps)
            if action.startswith("restart-B:") and successor.targets[int(action.split(":")[1])][2] == 2:
                witnesses.setdefault("updated_B_new_write_restart", steps)
            if action.startswith("serve-A:") and any(t[:2] == ("fenced", "B") for t in state.targets):
                witnesses.setdefault("fresh_A_rollback_after_B_refusal", steps)
            if successor not in seen:
                if len(seen) >= STATE_LIMIT:
                    raise RuntimeError("bounded state limit reached; no successful model claim")
                seen.add(successor); queue.append((successor, steps))
    return {"states": len(seen), "transitions": edges, "counterexample": None, "witnesses": witnesses}


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument("--output"); args = ap.parse_args()
    normal = explore()
    required = {"recovery_RPO_and_new_write_restart", "updated_B_new_write_restart",
                "fresh_A_rollback_after_B_refusal"}
    mutants = {name: explore(name) for name in ("dirty_point", "untrusted_point", "reset_original", "legacy_replace",
                                               "reuse_fenced", "rollback_dirty", "concurrent_serve")}
    passed = (normal["counterexample"] is None and set(normal["witnesses"]) == required
              and all(value["counterexample"] for value in mutants.values()))
    result = {"schema_version": 1, "disposition": "PASS" if passed else "FAIL",
              "bounds": {"destinations": 3, "maximum_transitions_per_trace": DEPTH,
                         "source_values": [0, 1], "new_successor_value": 2},
              "normal": normal, "mutants": mutants,
              "limits": ["Abstract point/pin and clean/served results are inputs, not cryptographic or kernel proofs.",
                         "Operator retirement/single-identity discipline is assumed; the tool does not detect all copies.",
                         "Original preservation is an operator assumption except for explicit modelled tool calls; legacy replacement is modelled as refusal.",
                         "Data write and clean restart are abstract transitions; actual durability needs native evidence.",
                         "No hardware fencing, host power-loss durability, ABI conversion or live kernel replacement."]}
    if args.output:
        with Path(args.output).open("x") as f:json.dump(result, f, indent=2); f.write("\n")
    print(json.dumps({"disposition": result["disposition"], "states": normal["states"],
                      "transitions": normal["transitions"], "witnesses": sorted(normal["witnesses"]),
                      "mutant_counterexamples": sum(bool(v["counterexample"]) for v in mutants.values())}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
