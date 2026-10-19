"""Bounded R23 capacity plateau; first live consumer is the C-kit harness.

Mapped-page observations only, not retained-byte or allocator correctness proof.
Callers own workload semantics, complete shapes and same-boot quiescent sampling.
"""
import copy
import re

SSH_FIELDS = ('slots', 'pool', 'net_sockets', 'net_closing', 'processes',
              'handles', 'pipes', 'cells', 'frames', 'heap_pages_peak')
FSD_FIELDS = ('bound', 'opens', 'draining', 'heap_pages_peak')


class BaselineError(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise BaselineError(message)


def latest_capacity(text, prefix):
    """Only the newest named line is eligible; never reuse an older good line."""
    lines = [line for line in text.splitlines() if line.startswith(prefix + ' ')]
    if not lines:
        return None
    fields = {}
    for token in lines[-1][len(prefix) + 1:].split():
        parts = token.split('=', 1)
        if len(parts) != 2 or parts[0] in fields:
            return None
        key, value = parts
        fields[key] = int(value) if value.isascii() and value.isdigit() and key != 'boot' else value
    return fields


def validate(sample):
    require(isinstance(sample, (tuple, list)) and len(sample) == 2, 'paired SSH/FSD capacity required')
    ssh, fsd = sample
    for data, names in ((ssh, SSH_FIELDS + ('accepted_reclaimed',)),
                        (fsd, FSD_FIELDS + ('settled_releases', 'fs_objects', 'rotated_logs'))):
        require(isinstance(data, dict), 'capacity record unavailable')
        require(isinstance(data.get('boot'), str) and re.fullmatch('[0-9a-f]{32}', data['boot']),
                'capacity boot identity missing or malformed')
        for name in names:
            require(type(data.get(name)) is int and data[name] >= 0, 'capacity field missing or invalid: ' + name)
    require(ssh['boot'] == fsd['boot'], 'SSH/FSD boot identities differ')
    require(all(ssh[x] == 0 for x in ('slots', 'pool', 'net_closing')), 'SSH capacity not quiescent')
    require(all(fsd[x] == 0 for x in ('bound', 'draining')), 'FSD capacity not settled')
    require(fsd['rotated_logs'] <= 2 and fsd['fs_objects'] >= fsd['rotated_logs'], 'invalid rotated log count')
    require(ssh['frames'] >= ssh['heap_pages_peak'] + fsd['heap_pages_peak'], 'negative residual frames')
    return sample


def fingerprint(sample):
    ssh, fsd = validate(sample)
    return tuple(ssh[x] for x in SSH_FIELDS) + tuple(fsd[x] for x in FSD_FIELDS) + (
        fsd['fs_objects'] - fsd['rotated_logs'],)


def split(sample):
    ssh, fsd = validate(sample)
    return {'ssh_heap': ssh['heap_pages_peak'], 'fsd_heap': fsd['heap_pages_peak'],
            'rest': ssh['frames'] - ssh['heap_pages_peak'] - fsd['heap_pages_peak']}


class WarmBaseline:
    """Single establishment attempt per instance/boot; no fallback after failure."""
    def __init__(self, cold, shapes, emit):
        self.cold = copy.deepcopy(validate(cold))
        self.boot = cold[0]['boot']
        self.shapes = tuple(shapes)
        require(bool(self.shapes) and len(set(self.shapes)) == len(self.shapes), 'explicit unique shape inventory required')
        self.emit = emit
        self.attempted = False
        self.baseline = None
        self.last = self.cold

    def same_boot(self, sample):
        validate(sample)
        require(sample[0]['boot'] == self.boot, 'baseline cannot cross boot identity')

    def progressed(self, before, after):
        self.same_boot(after)
        require(after[0]['accepted_reclaimed'] > before[0]['accepted_reclaimed'], 'stale SSH group evidence')
        require(after[1]['settled_releases'] > before[1]['settled_releases'], 'stale FSD group evidence')

    def establish(self, group, sample):
        require(not self.attempted, 'baseline already attempted for this boot')
        self.attempted = True
        previous = self.cold
        for attempt in range(1, 4):
            executed = tuple(group(attempt))
            require(executed == self.shapes, 'rehearsal omitted, reordered or added a workload shape')
            current = copy.deepcopy(sample())
            self.progressed(previous, current)
            self.emit({'phase': 'rehearsal', 'attempt': attempt, 'boot': self.boot,
                       'shapes': executed, 'sample': current})
            if attempt >= 2 and fingerprint(current) == fingerprint(previous):
                self.baseline = self.last = current
                a, b = split(self.cold), split(current)
                delta = {k: b[k] - a[k] for k in a}
                self.emit({'phase': 'baseline', 'boot': self.boot, 'groups': attempt,
                           'cold': self.cold, 'baseline': current, 'cold_to_warm': delta,
                           'owner_report_required': delta['rest'] > 6})
                return current
            previous = current
        raise BaselineError('reusable capacity did not plateau within three complete groups')

    def measured_group(self, current):
        """C-kit has no 64-open shape: no separate FSD allowance is applicable.

        Its existing per-case/exact-repeat checks remain stricter and untouched.
        This adds a boot-cumulative boundary after the complete measured group.
        """
        require(self.baseline is not None, 'no established baseline')
        self.progressed(self.last, current)
        ssh, fsd = current
        base_ssh, base_fsd = self.baseline
        for key in SSH_FIELDS:
            if key not in ('frames', 'heap_pages_peak'):
                require(ssh[key] == base_ssh[key], 'post-warm SSH drift: ' + key)
        for key in FSD_FIELDS:
            require(fsd[key] == base_fsd[key], 'post-warm FSD drift: ' + key)
        require(fsd['fs_objects'] - fsd['rotated_logs'] == base_fsd['fs_objects'] - base_fsd['rotated_logs'],
                'post-warm filesystem object drift')
        require(split(current)['rest'] == split(self.baseline)['rest'], 'post-warm residual drift')
        require(0 <= ssh['frames'] - base_ssh['frames'] <= 5, 'post-warm cumulative frame bound exceeded')
        if self.last is not self.baseline:
            require(fingerprint(current) == fingerprint(self.last), 'repeat measured group did not read flat')
        self.last = copy.deepcopy(current)
        self.emit({'phase': 'measured', 'boot': self.boot, 'sample': current,
                   'frames_from_baseline': ssh['frames'] - base_ssh['frames']})
