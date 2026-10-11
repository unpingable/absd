#!/usr/bin/env python3
"""Finite borrower obligation and token/reference comparisons, stdlib only.

This models stated contracts, not production Rust execution. Run without -O.
No build, VM, syscall, filesystem mutation or third-party dependency.
"""
from collections import deque
from dataclasses import asdict, dataclass, replace
import json


@dataclass(frozen=True)
class Borrow:
    holder: str = 'Vacant'
    child_live: bool = False
    other_holder: bool = False
    obligation: bool = False
    parent_alive: bool = True
    parent_open: bool = True
    teardown_verified: bool = False
    successor_authorized: bool = False
    retired: bool = False
    generation: int = 0
    borrower_generation: int = -1
    spawns: int = 0


BORROW_ACTIONS = ('spawn', 'track_ok', 'track_full', 'parent_request',
                  'child_exit', 'poll', 'close_parent', 'parent_exit',
                  'forward_after_parent_exit', 'other_holder_exit',
                  'verify_teardown', 'retire', 'authorize_successor', 'reissue')


def borrow_step(s, action, variant):
    if action == 'spawn':
        if (not s.parent_alive or not s.parent_open or s.retired
                or s.holder != 'Vacant' or s.spawns == 2):
            return None
        return replace(s, holder='Pending', child_live=True, obligation=True,
                       borrower_generation=s.generation, spawns=s.spawns + 1), 'spawned'
    if action in ('track_ok', 'track_full'):
        if s.holder != 'Pending' or not s.parent_alive:
            return None
        if action == 'track_ok':
            return replace(s, holder='Tracked'), 'tracked'
        holder = 'Vacant' if variant == 'zero-on-error' else 'Untracked'
        return replace(s, holder=holder), 'Full'
    if action == 'parent_request':
        if not s.parent_alive or not s.parent_open or s.retired or s.holder == 'Pending':
            return None
        allowed = s.holder == 'Vacant' or variant == 'ignoreborrow'
        return s, 'parent-transport' if allowed else 'AGAIN'
    if action == 'child_exit':
        if not s.child_live:
            return None
        return replace(s, child_live=False), 'child-terminal-endpoints-released'
    if action == 'poll':
        if not s.parent_alive:
            return None
        if s.holder == 'Tracked' and (not s.child_live or variant == 'prematureclear'):
            return replace(s, holder='Vacant', obligation=False), 'tracking-released'
        if s.holder in ('Tracked', 'Untracked'):
            return s, 'AGAIN'
        return None
    if action == 'close_parent':
        if not s.parent_open or s.holder == 'Pending':
            return None
        return replace(s, parent_open=False), 'parent-endpoint-closed'
    if action == 'parent_exit':
        if not s.parent_alive:
            return None
        # Local bookkeeping disappears. Adopted child/forwarded endpoints
        # and the external obligation do not disappear with that memory.
        return replace(s, parent_alive=False, parent_open=False, holder='Lost',
                       obligation=False if variant == 'parentdeath-clears-obligation'
                       else s.obligation), 'parent-exited'
    if action == 'forward_after_parent_exit':
        # Limit descendant exploration to retirement after parent loss.
        # Normal live-parent tracking of arbitrary descendants is unproved.
        if s.parent_alive or not s.child_live or s.other_holder:
            return None
        return replace(s, other_holder=True), 'delegated-endpoint-survives'
    if action == 'other_holder_exit':
        if not s.other_holder:
            return None
        return replace(s, other_holder=False), 'other-holder-endpoints-released'
    if action == 'verify_teardown':
        # Trusted outside evidence: every old endpoint holder is departed,
        # and old work is drained/fenced. No production primitive is supplied.
        if s.parent_open or s.child_live or s.other_holder or s.teardown_verified:
            return None
        return replace(s, teardown_verified=True), 'old-holders-and-work-fenced'
    if action == 'retire':
        if (s.parent_alive or s.parent_open or s.child_live or s.other_holder or s.retired
                or not s.teardown_verified):
            return None
        return replace(s, retired=True, obligation=False, holder='Vacant'), 'retired'
    if action == 'authorize_successor':
        if not s.retired or s.successor_authorized:
            return None
        return replace(s, successor_authorized=True), 'new-currentness-authorized'
    if action == 'reissue':
        if s.generation != 0:
            return None
        if variant == 'slotreissue-live' and s.child_live and not s.parent_open:
            return replace(s, generation=1, parent_open=True, holder='Vacant'), 'reissued'
        if not s.retired or not s.successor_authorized:
            return None
        return replace(s, generation=1, parent_alive=True, parent_open=True,
                       retired=False, holder='Vacant', teardown_verified=False,
                       successor_authorized=False, borrower_generation=-1), 'reissued'
    raise AssertionError(action)


def borrow_error(before, action, after, result):
    old_holders = before.child_live or before.other_holder
    if result == 'parent-transport' and (old_holders or before.obligation):
        return 'parent exclusive operation while borrower obligation remains'
    if result == 'spawned' and before.obligation:
        return 'second lend while previous borrower obligation remains'
    if before.obligation and not after.obligation and old_holders:
        return 'old-holder obligation discharged while endpoint holders survive'
    if result == 'Full' and before.obligation and after.holder == 'Vacant':
        return 'tracking refusal erased the guard for an unfulfilled obligation'
    if result in ('Full', 'AGAIN') and before.obligation and not after.obligation:
        return 'refusal discharged an unfulfilled obligation'
    if (after.child_live or after.other_holder) and after.borrower_generation != after.generation:
        return 'slot reissued while old generation endpoint holder is live'
    if before.holder == 'Untracked' and action == 'poll' and after != before:
        return 'untracked polling invented retirement evidence'
    if result == 'retired' and (old_holders or not before.teardown_verified):
        return 'retirement without complete old-holder teardown'
    if result == 'reissued' and not (before.retired and before.successor_authorized):
        return 'reissue without retired predecessor and new authorized currentness'
    return None


def explore(initial, actions, step, invariant, variant, depth):
    queue = deque([(initial, ())])
    seen = {initial}
    transitions = 0
    while queue:
        state, trace = queue.popleft()
        if len(trace) == depth:
            continue
        for action in actions:
            transition = step(state, action, variant)
            if transition is None:
                continue
            after, result = transition
            transitions += 1
            event = {'action': action, 'result': result, 'after': asdict(after)}
            path = trace + (event,)
            error = invariant(state, action, after, result)
            if error:
                return {'violation': error, 'trace': list(path),
                        'states_seen': len(seen), 'transitions': transitions}
            if after not in seen:
                seen.add(after)
                queue.append((after, path))
    return {'violation': None, 'states_seen': len(seen), 'transitions': transitions}


def replay(initial, trace, step, invariant):
    state = initial
    results = []
    for entry in trace:
        transition = step(state, entry['action'], 'candidate')
        if transition is None:
            results.append({'action': entry['action'], 'result': 'guard-refused'})
            break
        after, result = transition
        assert invariant(state, entry['action'], after, result) is None
        results.append({'action': entry['action'], 'result': result})
        state = after
    return results


def availability_and_replacement():
    rows = []
    repeated_refusals = 0
    # Fixed, pre-authorized independent channels; no allocation on refusal.
    for count in range(1, 5):
        for failed_mask in range(1 << count):
            channels = [Borrow() for _ in range(count)]
            for index in range(count):
                if failed_mask & (1 << index):
                    state, _ = borrow_step(channels[index], 'spawn', 'candidate')
                    state, result = borrow_step(state, 'track_full', 'candidate')
                    assert result == 'Full'
                    channels[index] = state
            admitted = blocked = 0
            for state in channels:
                if state.holder == 'Untracked':
                    blocked += 1
                    snapshot = state
                    for _ in range(8):
                        for action in ('poll', 'parent_request'):
                            state, result = borrow_step(state, action, 'candidate')
                            assert result == 'AGAIN' and state == snapshot
                            repeated_refusals += 1
                        # No second borrower/WAIT allocation is admitted.
                        assert borrow_step(state, 'spawn', 'candidate') is None
                        assert borrow_step(state, 'track_full', 'candidate') is None
                else:
                    after, result = borrow_step(state, 'parent_request', 'candidate')
                    assert result == 'parent-transport' and after == state
                    admitted += 1
            assert admitted == count - blocked
            rows.append({'channels': count, 'failed_mask': failed_mask,
                         'unavailable': blocked, 'independent_available': admitted})

    state = Borrow()
    counterexample = []
    for action in ('spawn', 'track_full', 'parent_exit'):
        after, result = borrow_step(state, action, 'candidate')
        assert borrow_error(state, action, after, result) is None
        state = after
        counterexample.append({'action': action, 'result': result, 'after': asdict(state)})
    assert not state.parent_alive and state.child_live and state.obligation
    assert borrow_step(state, 'retire', 'candidate') is None
    assert borrow_step(state, 'reissue', 'candidate') is None
    # A separately authorized new channel, within the fixed two-channel
    # envelope, can make progress without rebinding the occupied old one.
    independent = Borrow()
    independent_after, result = borrow_step(independent, 'parent_request', 'candidate')
    assert result == 'parent-transport' and independent_after == independent
    assert state.child_live and state.obligation
    for action in ('forward_after_parent_exit', 'child_exit'):
        state, _ = borrow_step(state, action, 'candidate')
    assert state.other_holder and state.obligation
    assert borrow_step(state, 'verify_teardown', 'candidate') is None
    assert borrow_step(state, 'retire', 'candidate') is None
    # Only complete endpoint release plus external quiescence/fencing and
    # explicit successor authorization admits a reissue of the old slot.
    for action in ('other_holder_exit', 'verify_teardown', 'retire'):
        after, result = borrow_step(state, action, 'candidate')
        assert borrow_error(state, action, after, result) is None
        state = after
    assert borrow_step(state, 'reissue', 'candidate') is None
    for action in ('authorize_successor', 'reissue'):
        state, _ = borrow_step(state, action, 'candidate')
    assert state.generation == 1 and state.parent_alive and not state.obligation
    return {'fixed_channel_cases': rows, 'repeated_again_events': repeated_refusals,
            'allocations_during_repeated_refusal': 0,
            'always_replacement_clears': False,
            'parent_exit_counterexample': counterexample,
            'independent_new_channel_can_progress_with_old_channel_blocked': True,
            'same_slot_reissue_requires_all_holders_released_and_new_currentness': True}


def main():
    if not __debug__:
        raise SystemExit('Run without -O: model assertions must remain enabled')
    broken = explore(Borrow(), BORROW_ACTIONS, borrow_step, borrow_error, 'zero-on-error', 12)
    assert broken['violation'] is not None
    candidate = explore(Borrow(), BORROW_ACTIONS, borrow_step, borrow_error, 'candidate', 12)
    assert candidate['violation'] is None
    controls = {}
    for name in ('prematureclear', 'ignoreborrow', 'slotreissue-live', 'parentdeath-clears-obligation'):
        result = explore(Borrow(), BORROW_ACTIONS, borrow_step, borrow_error, name, 12)
        assert result['violation'] is not None, name
        result['candidate_same_actions'] = replay(Borrow(), result['trace'], borrow_step, borrow_error)
        controls[name] = result
    state = Borrow()
    known = []
    for action in ('spawn', 'track_full', 'parent_request'):
        state, result = borrow_step(state, action, 'zero-on-error')
        known.append({'action': action, 'result': result, 'after': asdict(state)})
    assert result == 'parent-transport' and state.obligation
    assert replay(Borrow(), known, borrow_step, borrow_error)[-1]['result'] == 'AGAIN'
    state = Borrow()
    for action in ('spawn', 'track_ok', 'child_exit', 'poll', 'parent_request'):
        after, result = borrow_step(state, action, 'candidate')
        assert borrow_error(state, action, after, result) is None
        state = after
    assert result == 'parent-transport' and not state.obligation
    state = Borrow()
    for action in ('spawn', 'track_full', 'child_exit', 'poll', 'parent_request'):
        state, result = borrow_step(state, action, 'candidate')
    assert state.holder == 'Untracked' and state.obligation and result == 'AGAIN'
    print(json.dumps({'schema_version': 1, 'result': 'BOUNDED_BORROWER_MODEL_PASS',
        'known_zero_on_error': {'verdict': 'REJECTED', 'host_correspondence_trace': known},
        'candidate': candidate, 'availability': availability_and_replacement(),
        'mutants': controls,
        'bounds': {'borrower_depth': 12, 'max_borrowers_created_per_lifecycle': 2},
        'limits': ['Abstract serialized contract only; not production Rust execution or recovery mechanism',
                   'No runtime borrower tokens or generation protocol are introduced',
                   'All-holder teardown/fencing and authorized rebinding are external assumptions',
                   'Untracked has no in-process discharge; raw/trusted paths remain excluded']},
        indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
