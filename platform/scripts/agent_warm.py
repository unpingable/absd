"""R23 adapter for the exact fixed agent-exec cases; never arbitrary jobs."""
import json
import time
from pathlib import Path
import warm_baseline as wb

ROOT = '/home/operator/agent'


def shape(c):
    return (c.id, c.case, c.declared, c.timeout_s, c.stdin, c.expect, c.text, c.requires)


class Rehearsal:
    def __init__(self, module, runner):
        self.ae, self.runner, self.t = module, runner, runner.t
        canonical = module.load_cases(module.DEFAULT_CASES)
        wb.require([shape(c) for c in runner.calls] == [shape(c) for c in canonical],
                   'R23 requires the complete canonical fixed case sequence')
        self.calls = [c for c in runner.calls if not c.requires or c.requires == runner.candidate]
        self.shapes = ('reset-input-state',) + tuple(c.id for c in self.calls)
        self.prefix = self.t.target.physical(ROOT)
        self.initial = self.state()
        wb.require(not any(p == self.prefix or p.startswith(self.prefix + '/') for p in self.initial),
                   'fixed-case generated directory already exists')
        self.final = None
        self.evidence = runner.receipts.with_name(runner.receipts.name + '.warm.jsonl')
        wb.require(not self.evidence.exists(), 'warm evidence already exists; choose a new occurrence')
        self.expected_reclaimed = None
        cold = self.sample()
        self.expected_reclaimed = cold[0]["accepted_reclaimed"]
        self.warm = wb.WarmBaseline(cold, self.shapes, self.emit)

    def emit(self, data):
        with self.evidence.open('a') as f:
            f.write(json.dumps(data, sort_keys=True) + '\n')
        self.runner.out('AGENT WARM ' + json.dumps(data, sort_keys=True))

    def state(self):
        # Same established object-tree exclusions as the other live consumers.
        # Serial numbers are implementation generations, not logical identity.
        return {p: (directory, readonly, digest)
                for p, directory, readonly, serial, digest in self.t.target.system_objects()}

    def sample(self):
        deadline = time.monotonic() + 60
        reason = 'capacity unavailable'
        while time.monotonic() < deadline:
            pair = (wb.latest_capacity(self.t.worker(), 'SERVED CAPACITY'),
                    wb.latest_capacity(self.t.serial(), 'FSD CAPACITY'))
            try:
                wb.validate(pair)
                if hasattr(self, 'warm'):
                    self.warm.same_boot(pair)
                if (self.expected_reclaimed is None or
                        pair[0]['accepted_reclaimed'] == self.expected_reclaimed) and self.t.target.all_images() == 0:
                    return pair
                reason = 'capacity does not cover exactly the accepted sessions'
            except wb.BaselineError as error:
                reason = str(error)
            time.sleep(0.2)
        raise wb.BaselineError('agent warm sample: ' + reason)

    def verify_end(self, state):
        expected = {self.prefix: True, self.prefix + '/in.txt': False}
        if any(c.id == 'C12a' for c in self.calls):
            expected.update({self.prefix + '/t.c': False, self.prefix + '/t': False})
        extra = {p: v for p, v in state.items() if p not in self.initial}
        wb.require(set(extra) == set(expected), 'fixed-case effect inventory differs')
        wb.require({p: v for p, v in state.items() if p in self.initial} == self.initial,
                   'fixed-case changed an initial logical object')
        for p, directory in expected.items():
            wb.require(extra[p][0] == directory and not extra[p][1], 'generated object kind/authority differs')
        for cid, name in (('C3b', 'in.txt'), ('C12a', 't.c')):
            c = next((c for c in self.calls if c.id == cid), None)
            if c:
                wb.require(extra[self.prefix + '/' + name][2] == self.ae.sha256(c.stdin),
                           'generated input content differs')
        return state

    def reset(self):
        self.warm.same_boot(self.sample())
        before = self.state()
        if self.final is None:
            wb.require(before == self.initial, 'cold input state changed')
        else:
            wb.require(before == self.final, 'logical effects changed since the previous group')
            self.verify_end(before)
            # Recursive deletion is confined to the fully enumerated known tree.
            # Unknown effects, mount/type substitutions, or changed bytes refuse first.
            c = self.ae.Call('R23', 'session', 60, '-', [('rc', '0')],
                             'rm -r ' + ROOT, None, 0)
            r = self.runner.call(c)
            r.setdefault('checks_failed', [])
            r['checks_failed'] += self.runner.check(c, r)
            self.expected_reclaimed += r.get('sessions', 0)
            self.emit({'phase': 'reset', 'receipt': r})
            wb.require(not r['checks_failed'], 'reset session failed its original checks')
            wb.require(self.state() == self.initial, 'reset did not restore exact logical input state')
        self.emit({'phase': 'reset-input-state', 'verified': True})

    def group(self, attempt):
        self.reset()
        path = self.runner.receipts.with_name(self.runner.receipts.name + f'.rehearsal-{attempt}')
        wb.require(not path.exists(), 'rehearsal receipt already exists')
        r = self.ae.Runner(self.t, self.runner.calls, path, self.runner.candidate,
                           self.runner.baseline_mode, self.runner.out, self.runner.settle_timeout)
        summary, good = r.run()
        self.expected_reclaimed += sum(x.get('sessions', 0) for x in r.by_id.values())
        wb.require(good, 'rehearsal failed original case checks: ' + summary)
        end = self.verify_end(self.state())
        if self.final is not None:
            wb.require(end == self.final, 'rehearsal logical end state changed')
        self.final = end
        return self.shapes

    def run(self):
        try:
            self.warm.establish(self.group, self.sample)
            # Same declared prerequisite as every rehearsal, separate from case timing.
            self.reset()
            result = self.runner.run()
            self.expected_reclaimed += sum(x.get('sessions', 0) for x in self.runner.by_id.values())
            wb.require(result[1], 'measured fixed cases failed original checks')
            current = self.verify_end(self.state())
            wb.require(current == self.final, 'measured end state differs from final rehearsal')
            self.warm.measured_group(self.sample())
            self.emit({'phase': 'coverage', 'status': 'ESTABLISHED', 'scope': 'canonical-fixed-cases',
                       'jobs': 'NOT_ESTABLISHED',
                       'skipped': [c.id for c in self.runner.calls if c not in self.calls]})
            return result
        except (wb.BaselineError, self.ae.Failed) as e:
            self.emit({'phase': 'coverage', 'status': 'NOT_ESTABLISHED', 'reason': str(e)})
            raise self.ae.Failed('R23 fixed-case warm qualification: ' + str(e)) from e
