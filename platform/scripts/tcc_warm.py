"""TCC's declared reset-BEGIN workload; no guest effects outside caller methods."""
import contextlib
import io
import json
import time
import warm_baseline as wb


class Rehearsal:
    def __init__(self, matrix, out_dir):
        self.m = matrix
        self.outputs = [out_dir + '/' + c.name + '.elf' for c in matrix.cases if c.kind == 'compile-run']
        self.state_files = {c.cwd + '/' + f for c in matrix.cases if c.cwd for f in c.keeps + c.drops}
        self.shapes = ['reset-begin'] + [json.dumps([c.name, c.kind, c.args, c.stdin, c.pipe, c.cwd,
                         c.keeps, c.drops, getattr(c, 'gate', None)], sort_keys=True) for c in matrix.cases]
        wb.require(not matrix.pin, 'pin authoring cannot establish TCC warm qualification')
        # Only the current ordered write/verify state chain is established.
        cwd_cases = [(c.name, c.cwd, c.keeps, c.drops) for c in matrix.cases if c.cwd]
        wb.require(not cwd_cases or cwd_cases == [
            ('stdio.write', '/home/operator/tcc-work', ['c-stdio.dat'], []),
            ('stdio.verify', '/home/operator/tcc-work', [], ['c-stdio.dat'])],
            'unknown or incomplete TCC state/reset chain')
        wb.require(len(set(self.outputs)) == len(self.outputs), 'duplicate TCC output paths')
        self.final = None

    def emit(self, record):
        print('TCC WARM ' + json.dumps(record, sort_keys=True), flush=True)

    def capacity(self):
        m = self.m
        deadline = time.monotonic() + 60
        reason = 'capacity unavailable'
        while time.monotonic() < deadline:
            pair = (wb.latest_capacity(m.t.output(), 'SERVED CAPACITY'),
                    wb.latest_capacity(m.t.serial(), 'FSD CAPACITY'))
            try:
                wb.validate(pair)
                if hasattr(self, 'baseline'):
                    self.baseline.same_boot(pair)
                if pair[0]['accepted_reclaimed'] == m.connections and m.t.all_images() == 0:
                    return pair
                reason = 'capacity does not account for all opened sessions'
            except wb.BaselineError as e:
                reason = str(e)
            time.sleep(.2)
        raise wb.BaselineError('TCC warm capacity unsettled: ' + reason)

    def host_state_clean(self):
        for c in self.m.cases:
            if c.cwd:
                for name in c.keeps + c.drops:
                    wb.require(not (self.m.linux_dir(c.cwd) / name).exists(),
                               'TCC Linux reference state chain did not restore initial files')

    def reset(self):
        m = self.m
        before = m.t.tree()
        wb.require(not self.state_files.intersection(before), 'TCC state chain did not restore initial files')
        self.host_state_clean()
        present = [p for p in self.outputs if p in before]
        # The same declared reset is invoked even for the cold empty output set.
        # rm -f is not presumed: only known-present paths are passed to native rm.
        command = '\"/bin/rm\" ' + ' '.join(m.warm_quote(p) for p in present) if present else '"exit" "0"'
        started = time.monotonic()
        rc, out, err, _, _ = m.shell_ssh(command)
        wb.require((rc, out, err) == (0, b'', b''), 'TCC reset command failed')
        after = m.t.tree()
        wb.require(not set(self.outputs).intersection(after) and not self.state_files.intersection(after),
                   'TCC reset left a declared file')
        # Match existing CportsMatrix.compare_census /var/log/ exclusion.
        # Log byte stability is not established; the full capacity predicate
        # retains its separate bounded rotated-log count normalization.
        data = lambda tree: {k: v for k, v in tree.items() if not k.startswith('/var/log/')}
        want = data(before)
        for name in present:
            del want[name]
        wb.require(data(after) == want, 'TCC reset changed undeclared filesystem content')
        self.emit({'phase': 'reset-begin', 'removed': present, 'seconds': time.monotonic() - started})

    def end_files(self):
        self.host_state_clean()
        tree = self.m.t.tree()
        wb.require(not self.state_files.intersection(tree), 'TCC final state chain files remain')
        wb.require(all(p in tree for p in self.outputs), 'TCC final output missing')
        return {p: data for p, data in tree.items() if not p.startswith('/var/log/')}

    def rehearsal_census(self, case, before, after):
        # Capacity growth during establishment is recorded, not charged to
        # the measured boot allowance. All non-capacity guards still apply.
        m = self.m
        allowed = m.allowed(case)
        kept = lambda c: [o for o in c['objects'] if o[0] not in allowed and not o[0].startswith('/var/log/')]
        lowered = m.permitted_rest_lowering(before, after)
        bk, ak = m.comparison_kernels(before, after, lowered)
        m.check('TCC rehearsal preserves images, kernel objects and unrelated files',
                (before['images'], bk) == (after['images'], ak)
                and kept(before) == kept(after) and (m.rest_handles(before) or lowered) and m.rest_handles(after),
                str((before, after)))
        m.check('TCC rehearsal FSD drained', before['fsd_draining'] == after['fsd_draining'] == 0,
                str((before['fsd_draining'], after['fsd_draining'])))
        m.rest_opens('TCC rehearsal before', before)
        m.rest_opens('TCC rehearsal after', after)
        if lowered:
            self.emit({'phase': 'rehearsal-rest-lowered',
                       'before': before['rest_at_judgment'], 'after': after['rest_at_judgment']})
        self.emit({'phase': 'rehearsal-capacity', 'case': case.name,
                   'before_memory': before['memory'], 'after_memory': after['memory'],
                   'before_fsd': before['fsd'], 'after_fsd': after['fsd']})

    def group(self, attempt):
        m = self.m
        self.reset()
        for case in m.cases:
            output = io.StringIO()
            try:
                with contextlib.redirect_stdout(output):
                    before = m.stable(case.name, 'warm-before')
                    verdict, _ = m.run_negative(case) if case.kind == 'spawn-refused' else m.run_compile_case(case)
                    wb.require(verdict != 'failed', 'TCC rehearsal semantic failure: ' + case.name)
                    self.rehearsal_census(case, before, m.stable(case.name, 'warm-after'))
            finally:
                for line in output.getvalue().splitlines():
                    print(f'TCC REHEARSAL {attempt} {line}', flush=True)
        current = self.end_files()
        wb.require(self.final is None or current == self.final, 'TCC rehearsal output bytes changed')
        self.final = current
        self.emit({'phase': 'complete-group', 'attempt': attempt, 'shapes': self.shapes})
        return self.shapes

    def establish(self):
        self.baseline = wb.WarmBaseline(self.capacity(), self.shapes, self.emit)
        self.baseline.establish(self.group, self.capacity)

    def measured(self):
        wb.require(self.end_files() == self.final, 'TCC measured final files differ from rehearsal')
        self.baseline.measured_group(self.capacity())
