#!/usr/bin/env python3
"""Bounded CPU-cookie admission model; deliberately not an x86 emulator."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import argparse

COOKIE_TAG = 0xAB5D_0100
NONE = -1


def cookie(cpu: int) -> int:
    return COOKIE_TAG | cpu


def decode(value: int, ncpu: int) -> int | None:
    if value & 0xFFFF_FF00 != COOKIE_TAG:
        return None
    cpu = value & 0xFF
    return cpu if cpu < ncpu else None


@dataclass(frozen=True)
class State:
    # Per-CPU stages: 0 uninitialized, 1 raw identity/support checked,
    # 2 local WRMSR/RDTSCP readback matched, 3 ready ledger Release-published.
    stages: tuple[int, ...]
    aux: tuple[int, ...]
    ready_cookie: tuple[int, ...]
    supports_rdtscp: tuple[bool, ...]
    raw_identity_valid: tuple[bool, ...]
    enabled: bool = False


def expected(ncpu: int):
    # In this controlled topology the existing admission check requires
    # contiguous xAPIC IDs, so logical CPU index equals registered APIC ID.
    return tuple(cookie(i) for i in range(ncpu))


def check(s: State, ncpu: int) -> None:
    assert len(s.stages) == len(s.aux) == len(s.ready_cookie) == ncpu
    assert len(s.supports_rdtscp) == len(s.raw_identity_valid) == ncpu
    assert all(stage in (0, 1, 2, 3) for stage in s.stages)
    exp = expected(ncpu)
    for cpu, stage in enumerate(s.stages):
        if stage > 0:
            assert s.supports_rdtscp[cpu], "RDTSCP unsupported on initialized CPU"
            assert s.raw_identity_valid[cpu], "raw identity/registration gate failed"
        if stage < 2:
            assert s.aux[cpu] == NONE
        if stage >= 2:
            assert s.aux[cpu] == exp[cpu], "local cookie/readback mismatch"
        if stage < 3:
            assert s.ready_cookie[cpu] == NONE
        else:
            assert s.ready_cookie[cpu] == exp[cpu]
    published = [s.ready_cookie[i] for i in range(ncpu) if s.stages[i] == 3]
    assert len(set(published)) == len(published), "duplicate ready cookie"
    if s.enabled:
        assert all(stage == 3 for stage in s.stages), "enabled before all CPUs ready"
        assert tuple(s.ready_cookie) == exp, "enabled with wrong CPU/cookie map"
        assert len(set(s.ready_cookie)) == ncpu


def successors(s: State):
    for cpu, stage in enumerate(s.stages):
        stages = list(s.stages)
        aux = list(s.aux)
        records = list(s.ready_cookie)
        if stage == 0:
            # Raw APIC identity == registered lock ID == logical CPU index;
            # BSP role iff CPU0; RDTSCP feature exists on this CPU.
            if not s.supports_rdtscp[cpu] or not s.raw_identity_valid[cpu]:
                continue
            stages[cpu] = 1
            yield f"cpu{cpu}-raw-validate", State(tuple(stages), tuple(aux), tuple(records),
                                                   s.supports_rdtscp,
                                                   s.raw_identity_valid, s.enabled)
        elif stage == 1:
            aux[cpu] = expected(len(stages))[cpu]  # local WRMSR then RDTSCP readback
            stages[cpu] = 2
            yield f"cpu{cpu}-write-readback", State(tuple(stages), tuple(aux), tuple(records),
                                                    s.supports_rdtscp,
                                                    s.raw_identity_valid, s.enabled)
        elif stage == 2:
            records[cpu] = aux[cpu]               # Release-publish ready ledger
            stages[cpu] = 3
            yield f"cpu{cpu}-ready-release", State(tuple(stages), tuple(aux), tuple(records),
                                                   s.supports_rdtscp,
                                                   s.raw_identity_valid, s.enabled)
    if not s.enabled and all(stage == 3 for stage in s.stages):
        enabled = State(s.stages, s.aux, s.ready_cookie, s.supports_rdtscp,
                        s.raw_identity_valid, True)
        check(enabled, len(s.stages))         # BSP Acquire/whole-set validation
        yield "bsp-enable-release", enabled


def explore(ncpu: int):
    start = State((0,) * ncpu, (NONE,) * ncpu, (NONE,) * ncpu,
                  (True,) * ncpu, (True,) * ncpu)
    todo = deque([start])
    seen = {start}
    while todo:
        s = todo.popleft()
        check(s, ncpu)
        for _, nxt in successors(s):
            check(nxt, ncpu)
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    enabled_states = [s for s in seen if s.enabled]
    assert len(enabled_states) == 1
    final = enabled_states[0]
    assert all(decode(final.aux[cpu], ncpu) == cpu for cpu in range(ncpu))
    return len(seen)


def mutant_checks():
    n = 4
    good = State((3,) * n, expected(n), expected(n), (True,) * n, (True,) * n, True)
    bads = {
        "missing-ready": State((3, 3, 3, 2), expected(n),
                               (cookie(0), cookie(1), cookie(2), NONE), (True,) * n,
                               (True,) * n, True),
        "unsupported-feature-used": State((3,) * n, expected(n), expected(n),
                               (True, True, False, True), (True,) * n, True),
        "zero-cookie": State((3,) * n, (cookie(0), cookie(1), 0, cookie(3)),
                             (cookie(0), cookie(1), 0, cookie(3)), (True,) * n,
                             (True,) * n, True),
        "crosswired-valid-cookie": State((3,) * n,
                             (cookie(0), cookie(2), cookie(2), cookie(3)),
                             (cookie(0), cookie(2), cookie(2), cookie(3)),
                             (True,) * n, (True,) * n, True),
        "early-enable": State((3, 3, 2, 3), expected(n),
                              (cookie(0), cookie(1), NONE, cookie(3)), (True,) * n,
                              (True,) * n, True),
        "duplicate-id": State((3,) * n,
                               (cookie(0), cookie(1), cookie(1), cookie(3)),
                               (cookie(0), cookie(1), cookie(1), cookie(3)),
                               (True,) * n, (True,) * n, True),
        "wrong-bsp-role": State((3,) * n, expected(n), expected(n), (True,) * n,
                                (False, True, True, True), True),
        "wrong-lock-registration": State((3,) * n, expected(n), expected(n),
                                (True,) * n, (True, False, True, True), True),
    }
    for name, bad in bads.items():
        try:
            check(bad, n)
        except AssertionError:
            continue
        raise AssertionError(f"mutant escaped: {name}")

    assert decode(cookie(n), n) is None, "out-of-configured-range cookie accepted"
    assert decode(0, n) is None, "uninitialized cookie accepted"
    bads["valid-tag-out-of-range"] = None

    # The fast path only decodes a supported, in-range full cookie. If a
    # privileged writer changes CPU0's MSR to CPU1's already-valid cookie
    # after enable, lookup aliases CPU0 to CPU1; no cookie-range check reveals
    # the physical writer. This is an explicit counterexample to any claim
    # that software can detect arbitrary post-enable WRMSR using RDTSCP alone.
    runtime_aux = list(good.aux)
    runtime_aux[0] = cookie(1)
    wrong_runtime = decode(runtime_aux[0], n)
    assert wrong_runtime == 1 and wrong_runtime != 0
    assert good.enabled
    return list(bads), wrong_runtime


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    for ncpu in (1, 2, 4, 6):
        print(f"BINDING MODEL OK cpus={ncpu} states={explore(ncpu)}")
    if args.self_test:
        rejected, counterexample = mutant_checks()
        print(f"BINDING MUTANTS REJECTED count={len(rejected)} "
              f"cases={','.join(rejected)}")
        print(f"IMMUTABILITY COUNTEREXAMPLE cpu=0 runtime-cookie-selects={counterexample} "
              "assumption=post-enable IA32_TSC_AUX write impossible")


if __name__ == "__main__":
    main()
