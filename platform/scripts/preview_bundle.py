#!/usr/bin/env python3
"""Compose preview assets through the existing media builders and readers."""
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import absd_try
import boot_corresponding_source as boot_source
import c_kit_source
import media_operator
import operator_boot_binding as binding
import operator_image as oi
from served_ram import DEFAULT_GUEST_RAM, ram_bytes

NATIVE_INPUTS = ('sshd.elf', 'absd-fsd.elf', 'absd-logd.elf', 'fixture-import.elf', 'absd-enroll.elf')
HELPERS = {'absd-try.py': 'absd_try.py', 'absd_fs.py': 'absd_fs.py',
           'absd_image.py': 'absd_image.py', 'served_ram.py': 'served_ram.py'}


def run_tool(command, log):
    with Path(log).open('xb') as stream:
        subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True)


def sha(path):
    return absd_try.sha256_file(path)


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def fresh(path):
    if path.exists() or path.is_symlink():
        raise ValueError(f'fresh preview path required: {path}')


def replace_text(path, text):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile('w', dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def seal(out, doc):
    """The one manifest/checksum writer for initial composition and finalize."""
    paths = sorted(p for p in out.iterdir() if p.name not in {'MANIFEST.toml', 'SHA256SUMS'})
    names = {entry['name']: role for role, entry in doc['assets'].items()}
    used = set(names.values())
    entries = {}
    for index, path in enumerate(paths):
        role = names.get(path.name)
        if role is None:
            number = index
            while f'extra_{number}' in used:
                number += 1
            role = f'extra_{number}'
            used.add(role)
        entry = dict(doc['assets'].get(role, {}))
        entry.update(name=path.name, sha256=sha(path), bytes=path.stat().st_size)
        entries[role] = entry
    doc['assets'] = entries
    lines = [name + ' = ' + json.dumps(doc[name]) for name in
             ('schema', 'signature', 'qualification', 'limitations')]
    for section in ('release', 'qemu'):
        if section in doc:
            lines.append('[' + section + ']')
            lines += [name + ' = ' + json.dumps(value) for name, value in doc[section].items()]
    for role, entry in entries.items():
        lines.append('[assets.' + role + ']')
        lines += [name + ' = ' + json.dumps(value) for name, value in entry.items()]
    text = '\n'.join(lines) + '\n'
    # Per-file replacement prevents a truncated metadata file. A reader that
    # sees the interval between the two replacements refuses mismatched sums.
    replace_text(out / 'MANIFEST.toml', text)
    paths = sorted([*paths, out / 'MANIFEST.toml'])
    replace_text(out / 'SHA256SUMS', ''.join(f'{sha(path)}  {path.name}\n' for path in paths))


def finalize(directory, quickstart):
    out = Path(directory).resolve()
    doc = absd_try.verify_assets(out)
    guide = out / 'QUICKSTART.md'
    if guide.exists() or guide.is_symlink():
        raise ValueError('preview guide already exists; nothing was overwritten')
    actual = {p.name for p in out.iterdir()} - {'MANIFEST.toml', 'SHA256SUMS'}
    if actual != {entry['name'] for entry in doc['assets'].values()}:
        raise ValueError('preview directory contains unlisted assets; nothing was changed')
    before = {entry['name']: entry['sha256'] for role, entry in doc['assets'].items()
              if role in {'operator_iso', 'enroll_iso', 'disk'}}
    data = Path(quickstart).read_bytes()
    with guide.open('xb') as stream:
        stream.write(data)
    seal(out, doc)
    if any(sha(out / name) != digest for name, digest in before.items()):
        raise ValueError('preview media changed during finalization')
    absd_try.verify_assets(out)
    return out


def compose(args):
    for value in (args.work, args.out):
        fresh(Path(value))  # Refuse a dangling leaf link before resolving it.
    platform, kernel, work, out = map(lambda x: Path(x).resolve(),
        (args.platform, args.kernel, args.work, args.out))
    for value in (args.id, args.tag):
        if not re.fullmatch(r'[a-z0-9.-]{1,64}', value):
            raise ValueError('preview id and tag must contain 1-64 lowercase letters, digits, dots or hyphens')
    if not args.repository.startswith('https://'):
        raise ValueError('preview repository must be an explicit HTTPS URL')
    for target in (work, out):
        fresh(target)
        for source in (platform, kernel):
            if target.is_relative_to(source):
                raise ValueError('preview work/output must be outside source trees')
    if work.is_relative_to(out) or out.is_relative_to(work):
        raise ValueError('preview work and output must be separate directories')
    media_operator.checkout_at(platform, args.platform_commit, 'platform')
    media_operator.checkout_at(kernel, args.kernel_commit, 'kernel')
    # This is the actual source-bound reader, not existence of a receipt alone.
    c_kit_source.read_installed(platform, platform / 'ports')
    inputs = {name: {'sha256': sha(platform / name), 'bytes': (platform / name).stat().st_size}
              for name in (*NATIVE_INPUTS, 'ports/.c-ports.built-from.json', 'userland/PORTS.tsv')}
    notices = Path(args.notices).read_bytes()
    if not notices.strip():
        raise ValueError('preview notices must be supplied and nonempty')
    quickstart = Path(args.quickstart).read_bytes() if args.quickstart else None
    Path(args.authorized_keys).stat()
    boot_source.verify_sources(args.boot_sources)
    work.mkdir(mode=0o700)
    python = sys.executable
    run_tool([python, '-B', str(platform / 'scripts/provenance.py'), 'check', '--peer', str(kernel)],
             work / 'provenance.log')
    media = work / 'operator'
    common = ['--profile', args.profile, '--platform-tree', str(platform), '--kernel-run', str(kernel)]
    run_tool([python, '-B', str(platform / 'scripts/media.py'), 'operator-image', *common,
              '--platform-commit', args.platform_commit, '--kernel-commit', args.kernel_commit,
              '--authorized-keys', str(Path(args.authorized_keys).resolve()), '--release-id', args.id,
              '--no-local-login', '--out', str(media)], work / 'operator-build.log')
    run_tool([python, '-B', str(platform / 'scripts/media.py'), 'operator-validate', *common,
              '--out', str(media)], work / 'operator-validate.log')
    # Bind all served services, including the logger omitted by the RC1 inventory.
    tree = kernel / 'build/durable/iso-0/boot'
    binary = (tree / 'absd-kernel').read_bytes()
    boot = (tree / 'grub/grub.cfg').read_bytes()
    binding.verify_iso((media / oi.ISO).read_bytes(), binary, boot)
    catalog = binding.verify_kernel_catalog(binary, {
        'external-workload': (platform / 'sshd.elf').read_bytes(),
        'file-server': (platform / 'absd-fsd.elf').read_bytes(),
        'logd': (platform / 'absd-logd.elf').read_bytes()})
    source_asset = work / boot_source.ASSET
    source_receipt = boot_source.build(args.boot_sources, media / oi.ISO, source_asset, args.profile)
    replay = work / 'operator-replay'
    replay.mkdir()
    (replay / 'absd-kernel').write_bytes(binary)
    (replay / 'grub.cfg').write_bytes(boot)
    enroll = work / 'enroll'
    run_tool([python, '-B', str(platform / 'scripts/enroll-matrix.py'), '--kernel', str(kernel),
              '--importer', str(platform / 'fixture-import.elf'), '--enroll', str(platform / 'absd-enroll.elf'),
              '--work', str(enroll)], work / 'enroll.log')
    result = json.loads((enroll / 'result.json').read_text())
    if (result['isos']['enroll'] != sha(enroll / 'enroll.iso') or
        any(result['elfs'][name] != inputs[file]['sha256'] for name, file in
            [('enroll', 'absd-enroll.elf'), ('importer', 'fixture-import.elf')])):
        raise ValueError('enrollment matrix artifacts differ from the current inputs')
    blank = work / 'blank'
    blank.mkdir()
    image = blank / oi.IMAGE
    shutil.copyfile(media / oi.IMAGE, image)
    shutil.copyfile(media / 'MANIFEST', blank / 'MANIFEST')
    oi.import_boots(kernel, image, [(4, [(absd_try.KEYS_PATH, b'')])], blank,
                    qemu=oi.QEMU, root=platform)
    # First original consumer boundary: the actual disk to be compressed.
    absd_try.check_blank(absd_try.read_tree(image), args.id)
    compressed = work / 'disk.img.xz'
    with image.open('rb') as src, lzma.open(compressed, 'wb') as dst:
        shutil.copyfileobj(src, dst)
    checked = work / 'decompressed.img'
    with lzma.open(compressed, 'rb') as src, checked.open('xb') as dst:
        shutil.copyfileobj(src, dst)
    if checked.stat().st_size != image.stat().st_size or sha(checked) != sha(image):
        raise ValueError('compressed preview disk differs after decompression')
    # Second original boundary: the bytes the downloaded helper will read.
    absd_try.check_blank(absd_try.read_tree(checked), args.id)
    c_kit_source.read_installed(platform, platform / 'ports')
    if any(sha(platform / name) != data['sha256'] for name, data in inputs.items()):
        raise ValueError('preview inputs changed during composition')
    out.mkdir(mode=0o700)
    copies = {'operator.iso': media / oi.ISO, 'enroll.iso': enroll / 'enroll.iso',
              'disk.img.xz': compressed, boot_source.ASSET: source_asset}
    copies.update({name: platform / 'scripts' / source for name, source in HELPERS.items()})
    for name, source in copies.items():
        shutil.copyfile(source, out / name)
    (out / 'NOTICES.md').write_bytes(notices)
    if quickstart is not None:
        (out / 'QUICKSTART.md').write_bytes(quickstart)
    write_json(out / 'BUILD-INPUTS.json', dict(platform_commit=args.platform_commit,
        kernel_commit=args.kernel_commit, inputs=inputs, operator_catalog=catalog,
        boot_corresponding_source=source_receipt,
        raw_disk_bytes=image.stat().st_size, provenance_environment={name: os.environ.get(name, '')
            for name in ('ABSD_CARGO_REGISTRY', 'ABSD_CRATE_ARCHIVES')}))
    # The site generates this guide from the proposed final download list.
    # Include its planned name before it exists, so adding it cannot change
    # the very inputs from which it was generated.
    names = sorted({p.name for p in out.iterdir()} |
                   {'QUICKSTART-INPUT.json', 'MANIFEST.toml', 'QUICKSTART.md'})
    repository = args.repository.rstrip('/')
    record = dict(repository=repository, release_id=args.tag, platform_commit=args.platform_commit,
        kernel_commit=args.kernel_commit, binary_preview={'assets': [dict(name=n,
            url=f'{repository}/releases/download/{args.tag}/{n}') for n in names]})
    write_json(out / 'QUICKSTART-INPUT.json', {'record': record, 'manifest': 'MANIFEST.toml'})
    doc = dict(schema='absd-preview-manifest/1', signature='unsigned', qualification='built',
        limitations=args.limitation, release=dict(id=args.id, tag=args.tag,
            kernel_commit=args.kernel_commit, platform_commit=args.platform_commit),
        assets=dict(operator_iso={'name': 'operator.iso'}, enroll_iso={'name': 'enroll.iso'},
            boot_source={'name': boot_source.ASSET},
            disk=dict(name='disk.img.xz', raw_sha256=sha(image), raw_bytes=image.stat().st_size)),
        qemu=dict(cpu_tcg=absd_try.CPU_TCG, memory_mib=ram_bytes(DEFAULT_GUEST_RAM) // (1024 * 1024),
                  smp=1, nic='e1000', disk='ide', firmware='SeaBIOS'))
    seal(out, doc)
    absd_try.verify_assets(out)
    write_json(work / 'COMPOSITION.json', dict(status='BUILT_NOT_ACCEPTED', platform_commit=args.platform_commit,
        kernel_commit=args.kernel_commit, assets={p.name: sha(p) for p in sorted(out.iterdir())},
        raw_disk_bytes=image.stat().st_size, work_retirement='Caller retains owned intermediates only through review/replay dependencies.'))
    return out
