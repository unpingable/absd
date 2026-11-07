"""Copy-only conversion of a clean, guard-less format-2 disk.

The old disk is read-only input. A successful legacy shutdown is evidence
about its logical history, not proof that an old device has retired I/O.
Only a new independent backing file receives the seed. No boot image or
selection cache is copied or published by this conversion.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil

import absd_fs
import storage_fence_state as guard


def fnv(data):
    value = 0xcbf29ce484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001b3) & ((1 << 64) - 1)
    return value


def ledger(data):
    if len(data) != 128:
        raise ValueError('clean evidence: ledger size')
    line, separator, padding = data.partition(b'\n')
    match = re.fullmatch(rb'absd-recovery v1 seq=([1-9][0-9]*) boot=([0-9a-f]{32}) '
                         rb'streak=(0|[1-9][0-9]*) fnv=([0-9a-f]{16})', line)
    if not separator or padding.strip(b'\0') or not match:
        raise ValueError('clean evidence: malformed ledger')
    seq, boot, streak, check = match.groups()
    if (max(int(seq), int(streak)) >= 1 << 64
            or int(check, 16) != fnv(line.rsplit(b' fnv=', 1)[0])):
        raise ValueError('clean evidence: invalid ledger check or range')
    return {'seq': int(seq), 'boot': boot.decode(), 'streak': int(streak)}


def fact(boot, action=None):
    suffix = '' if action is None else ' action=' + action
    return ('boot=' + boot + suffix + '\n').encode().ljust(64, b'\0')


def clean_history(tree, console):
    if guard.PATH in tree or guard.RESUME_PATH in tree:
        raise ValueError('clean evidence: guard or resume slot already exists; conversion never resets it')
    if any(p == '/var/state.new' or p.startswith('/var/state.new/') for p in tree):
        raise ValueError('clean evidence: incomplete recovery staging')
    if tree.get('/var/state/recovery.init') != b'':
        raise ValueError('clean evidence: missing recovery initialization')
    record = ledger(tree.get('/var/state/recovery', b''))
    boot = record['boot']
    for name, action in [('ready', None), ('end', 'halt'), ('stopped', None), ('completed', None)]:
        if tree.get('/var/state/facts/served-' + name) != fact(boot, action):
            raise ValueError('clean evidence: missing or mismatched ' + name)
    # A reboot log can contain earlier generations. Only its final boot
    # can establish the halted source generation being converted.
    if 'ABSD KERNEL BOOT\n' not in console:
        raise ValueError('clean evidence: no boot console')
    last = 'ABSD KERNEL BOOT\n' + console.rsplit('ABSD KERNEL BOOT\n', 1)[1]
    recovery = re.findall(r'(?m)^FSD RECOVERY seq=(\d+) streak=(\d+) previous=\w+$', last)
    shutdown = re.findall(r'(?m)^SERVED SHUTDOWN action=halt worker_status=0 '
                          r'file_server_status=0 orphans_reaped=\d+ drained=true$', last)
    required = ['FSD READY ', 'FSD STOPPED ', 'FSD FINALIZED boot=' + boot + '\n',
                'SERVED SHUTDOWN FINALIZED status=0\n', 'ABSD BOOT OK\n']
    if (recovery != [(str(record['seq']), str(record['streak']))] or len(shutdown) != 1
            or any(last.count(word) != 1 for word in required)
            or re.search(r'(?m)^(?:.*REFUSED.*|FSD .*FAILED.*|MACHINE RESTART.*)$', last)):
        raise ValueError('clean evidence: console does not establish this successful halt')
    positions = [last.index(word) for word in required]
    if positions != sorted(positions) or not positions[1] < last.index(shutdown[0]) < positions[2]:
        raise ValueError('clean evidence: shutdown records out of order')
    return record


def digest(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def inspect(path):
    region = absd_fs.fs_region(path, Path(path).stat().st_size // 512)
    if region is None:
        raise ValueError('conversion needs an existing filesystem')
    selected = absd_fs.select(region)
    if selected is None or selected['format'] != 2:
        raise ValueError('conversion supports only the current filesystem format 2')
    namespace = {path: dict(record, fs_id=selected['fs_id'])
                 for path, record in absd_fs.tree(region, selected).items()}
    namespace['/'] = dict(selected['records'][0], fs_id=selected['fs_id'])
    files = {path: absd_fs.content(region, selected, record)
             for path, record in namespace.items() if not record['dir']}
    return files, namespace


def convert(source, output, console, work, kernel, *, oi, release, log=print,
            attest_no_writes_since_halt=False, halt_image_sha256=None):
    if not attest_no_writes_since_halt:
        raise ValueError('conversion requires explicit attestation: no writer ran after the clean halt')
    if not isinstance(halt_image_sha256, str) or not re.fullmatch('[0-9a-f]{64}', halt_image_sha256):
        raise ValueError('conversion needs the whole-image SHA-256 recorded at that clean halt')
    source, output, work, kernel = map(Path, (source, output, work, kernel))
    if source.is_symlink() or not source.is_file() or source.stat().st_nlink != 1:
        raise ValueError('conversion needs a regular, exclusively owned raw input file')
    if output.exists() or output.is_symlink() or source.resolve() == output.resolve():
        raise ValueError('conversion output must be a new independent pathname')
    release.refuse_in_use(source, 'guard conversion')
    source_hash = digest(source)
    source_stat = source.stat()
    if source_hash != halt_image_sha256:
        raise ValueError('clean evidence: image changed since the recorded clean halt')
    tree, old_namespace = inspect(source)
    if (guard.PATH in old_namespace or guard.RESUME_PATH in old_namespace
            or any(p == '/var/state.new' or p.startswith('/var/state.new/') for p in old_namespace)):
        raise ValueError('clean evidence: existing guard, resume slot or incomplete recovery staging')
    identity = clean_history(tree, console)
    work.mkdir(mode=0o700, parents=False, exist_ok=False)
    candidate = work / 'candidate.incomplete.img'
    # Exclusive creation, a full byte copy, and no reflink/backing chain.
    with source.open('rb') as src, candidate.open('xb') as dst:
        os.chmod(candidate, 0o600)
        shutil.copyfileobj(src, dst)
        dst.flush(); os.fsync(dst.fileno())
    if digest(candidate) != source_hash:
        raise ValueError('conversion copy differs from its source')
    entries = [(guard.PATH, guard.encode('clean')), (guard.RESUME_PATH, guard.encode_resume('none'))]
    # This is new-device construction, never admission of the old disk.
    # The canonical importer alone adds the file and its namespace entry.
    oi.import_boots(kernel, candidate, [(2, entries)], work, root=oi.ROOT, log=log, fresh=True)
    found_tree, found_namespace = inspect(candidate)
    if found_tree != dict(tree, **{guard.PATH: guard.encode('clean'), guard.RESUME_PATH: guard.encode_resume('none')}):
        raise ValueError('conversion changed existing file content or recovery history')
    identity_after, state = release.storage_fence_host.marker(candidate)
    if state != guard.encode('clean'):
        raise ValueError('conversion did not construct a fixed clean marker')
    if set(found_namespace) != set(old_namespace) | {guard.PATH, guard.RESUME_PATH}:
        raise ValueError('conversion changed the existing namespace')
    for path, old in old_namespace.items():
        actual = dict(found_namespace[path]); expected = dict(old)
        # Adding the new child legitimately changes /var's directory mtime.
        if path.rstrip('/') == '/var':
            actual.pop('mtime', None); expected.pop('mtime', None)
        if actual != expected:
            raise ValueError('conversion changed existing object identity or mapping: ' + path)
    release.refuse_in_use(source, 'conversion publication')
    current_stat = source.stat()
    if ((source_stat.st_dev, source_stat.st_ino, source_stat.st_size) !=
            (current_stat.st_dev, current_stat.st_ino, current_stat.st_size)
            or digest(source) != source_hash):
        raise ValueError('conversion source changed; candidate remains unactivated')
    result = {'source_sha256': source_hash, 'output_sha256': digest(candidate),
              'operator_attestation': 'No writer ran after the clean halt; hash recorded at that halt',
              'halt_image_sha256': halt_image_sha256,
              'platform_source': oi.identity(oi.ROOT), 'kernel_source': oi.identity(kernel),
              'importer_sha256': digest(oi.ROOT / 'fixture-import.elf'),
              'clean_console_sha256': hashlib.sha256(console.encode()).hexdigest(),
              'preserved_recovery': identity, 'guard_identity': identity_after,
              'disposition': 'PREPARED_UNACTIVATED',
              'activation': 'Use the current guard-aware release boot image; old boot images and '
                            'selection caches are not conversion outputs. Keep source for rollback; '
                            'post-activation effects are not reversed by restoring it.'}
    with candidate.open('r+b') as handle:
        os.fsync(handle.fileno())
    # link is exclusive: an output created during verification is not replaced.
    # Work and output must share a filesystem; no implicit destination fallback.
    os.link(candidate, output, follow_symlinks=False)
    candidate.unlink()
    directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return result
