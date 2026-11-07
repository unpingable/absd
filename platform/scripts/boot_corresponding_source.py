#!/usr/bin/env python3
"""Bind pinned local GRUB/Unifont sources to an operator ISO.

Archive validation is migrated from the RC1 attachment procedure; the existing
media_operator checker remains the one implementation of ISO GRUB validation.
No downloads or package installation. See docs/RELEASE.md for pin provenance
and the generated GRUB image limitation.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

import media_operator

PINS = json.loads((Path(__file__).resolve().parent.parent / 'media/boot-source-pins.json').read_text())
SOURCE_HASHES = PINS['sources']
ASSET = 'boot-corresponding-source.tar'
GRUB_PACKAGES = ('grub-common', 'grub-pc-bin', 'grub-efi-amd64-bin')


def sha_stream(stream):
    return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_sources(directory):
    directory = Path(directory)
    for name, digest in SOURCE_HASHES.items():
        with (directory / name).open('rb') as stream:
            if sha_stream(stream) != digest:
                raise ValueError(f'source hash mismatch: {name}')


def checksums():
    return ''.join(f'{digest}  {name}\n' for name, digest in sorted(SOURCE_HASHES.items())).encode()


def verify_archive(path):
    """RC1's exact regular-member and checksum checks, with pinned digests."""
    expected = {'grub-source/' + name for name in SOURCE_HASHES} | {'grub-source/SHA256SUMS'}
    with tarfile.open(path, 'r:') as archive:
        members = archive.getmembers()
        if len(members) != len(expected) or {m.name for m in members} != expected:
            raise ValueError('source archive member inventory mismatch')
        if not all(m.isfile() for m in members):
            raise ValueError('source archive requires regular files')
        if archive.extractfile('grub-source/SHA256SUMS').read() != checksums():
            raise ValueError('source archive checksum inventory mismatch')
        for name, digest in SOURCE_HASHES.items():
            with archive.extractfile('grub-source/' + name) as stream:
                if sha_stream(stream) != digest:
                    raise ValueError(f'source archive hash mismatch: {name}')


def verify_iso(iso, profile_name='vm-operator'):
    profile = media_operator.load_operator_profile(profile_name)
    for name in GRUB_PACKAGES:
        if profile['pins']['packages'].get(name) != PINS['grub_version']:
            raise ValueError(f'GRUB package version mismatch in profile: {name}')
        version = subprocess.check_output(
            ['dpkg-query', '-W', '-f=${Version}', name], text=True).strip()
        if version != PINS['grub_version']:
            raise ValueError(f'GRUB package version mismatch: {name} = {version}')
    inventory, modules = media_operator.grub_inventory()
    if inventory['sha256'] != PINS['module_inventory_sha256']:
        raise ValueError('GRUB package module inventory differs from pinned version')
    copied, _ = media_operator.expected_grub(profile, modules)
    digest = hashlib.sha256(json.dumps(copied, sort_keys=True).encode()).hexdigest()
    if digest != PINS['iso_inventory_sha256']:
        raise ValueError('ISO GRUB profile inventory differs from pinned version')
    with tempfile.TemporaryDirectory(prefix='boot-source-iso-') as tmp:
        grub = Path(tmp) / 'grub'
        subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(Path(iso).resolve()),
                        '-extract', '/boot/grub', str(grub)], check=True, capture_output=True)
        return media_operator.check_iso_grub(grub, profile, modules, PINS['font_sha256'])


def build(sources, iso, output, profile_name='vm-operator'):
    sources, iso, output = map(Path, (sources, iso, output))
    if output.exists() or output.is_symlink():
        raise ValueError(f'source asset already exists: {output}')
    verify_sources(sources)
    grub = verify_iso(iso, profile_name)
    # Keep the final name absent until the archive has passed its real reader.
    # Hard-link creation refuses a concurrently created destination as well.
    with tempfile.TemporaryDirectory(prefix='.boot-source-', dir=output.parent) as tmp:
        staged = Path(tmp) / ASSET
        with tarfile.open(staged, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted([*SOURCE_HASHES, 'SHA256SUMS']):
                entry = tarfile.TarInfo('grub-source/' + name)
                entry.mode = 0o644
                if name == 'SHA256SUMS':
                    data = checksums()
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
                else:
                    with (sources / name).open('rb') as stream:
                        entry.size = os.fstat(stream.fileno()).st_size
                        archive.addfile(entry, stream)
        verify_archive(staged)
        os.link(staged, output)
    return {'source_files': len(SOURCE_HASHES), 'grub': grub,
            'grub_version': PINS['grub_version'], 'unifont_version': PINS['unifont_version']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources', required=True, help='local pinned source directory (including unifont/)')
    parser.add_argument('--operator-iso', required=True)
    parser.add_argument('--out', required=True, help='new archive path; parent must exist')
    parser.add_argument('--profile', default='vm-operator')
    args = parser.parse_args()
    try:
        result = build(args.sources, args.operator_iso, args.out, args.profile)
    except (OSError, ValueError, subprocess.CalledProcessError, media_operator._media().Refused) as error:
        parser.exit(2, f'boot-source: REFUSED: {error}\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
