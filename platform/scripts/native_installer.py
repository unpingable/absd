#!/usr/bin/env python3
"""Build the #143 blank-disk QEMU software pilot with the existing #28 ESP tools.

Build from a kernel with the actual installed filesystem workload embedded. The builder
writes private regular files only. The native kernel performs target disk I/O.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import uuid
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import install_disk as layout
import media
import media_operator

HEADER = 128
MODEL = 'QEMU HARDDISK'
EPOCH = 1793836800  # 2026-11-05 UTC, fixed for this software pilot


def pack(image, serial, model):
    if not layout.SERIAL.fullmatch(serial) or model != MODEL:
        raise layout.Refused('unsupported native target identity')
    size = layout.lstat_target(image).st_size
    header = bytearray(HEADER)
    header[:8] = b'ABSDINS1'
    struct.pack_into('<Q', header, 8, size//512)
    header[20:20+len(serial)] = serial.encode('ascii')
    header[40:40+len(model)] = model.encode('ascii')
    count = 0
    body = bytearray()
    # Never put a record across the primary commit boundary (LBA 34).
    with open(image, 'rb') as handle:
        for start, end in [(0, 34*512), (34*512, layout.ABSD_FIRST*512), (size-33*512, size)]:
            handle.seek(start)
            for at in range(start, end, 4096):
                data = handle.read(min(4096, end-at))
                if any(data):
                    body.extend(struct.pack('<QII', at//512, len(data), 0))
                    body.extend(data)
                    count += 1
    struct.pack_into('<I', header, 16, count)
    return bytes(header + body)


def records(payload):
    at = HEADER
    count, = struct.unpack_from('<I', payload, 16)
    for _ in range(count):
        lba, length, reserved = struct.unpack_from('<QII', payload, at)
        if reserved or not 0 < length <= 4096 or length % 512 or at+16+length > len(payload):
            raise layout.Refused('invalid sparse record')
        yield lba, payload[at+16:at+16+length]
        at += 16+length
    if at != len(payload):
        raise layout.Refused('trailing payload bytes')


def iso(kernel, output, config, work, plan=None):
    tree = work/'iso'
    (tree/'boot/grub').mkdir(parents=True)
    shutil.copyfile(kernel, tree/'boot/installer.elf')
    (tree/'boot/grub/grub.cfg').write_text(config)
    if plan is not None:
        (tree/'PLAN.json').write_text(json.dumps(plan, indent=2, sort_keys=True)+'\n')
    # Reuse #28's frozen-clock/EFI-free-space normalization, including its
    # deterministic FAT serial. Ordinary grub-mkrescue is not reproducible.
    media_operator.build_iso(tree, output, EPOCH,
        {"iso": {"locales": "", "efi_serial_prefix": "1430"}},
        media.sha(kernel)[:40], media.git(media.ROOT, 'rev-parse', 'HEAD').decode().strip(),
        work/'normalize')


def config(serial, crc, commit=False, plan=None):
    consent = f' install-consent={crc:08x}' if commit else ''
    select = 'ahci-write' if commit else 'ahci-disk'
    identity = '' if plan is None else '\n'.join(
        'echo '+key+'='+plan[key] for key in ('kernel_source','platform_source','payload_sha256'))
    return f'''serial --unit=0 --speed=115200
terminal_input serial console
terminal_output serial console
set timeout=0
{identity}
menuentry 'ABSD native installer: {"ERASE blank exact disk" if commit else "INSPECT ONLY"}' {{
    multiboot2 /boot/installer.elf native-install {select}={serial}{consent}
    boot
}}
'''


def require_clean(repo):
    if media.git(repo, 'status', '--porcelain', '--untracked-files=all'):
        raise layout.Refused('dirty source tree: '+str(repo))


def build(args):
    repo = pathlib.Path(args.kernel_repo).resolve()
    require_clean(media.ROOT)
    require_clean(repo)
    out = pathlib.Path(args.out).resolve()
    out.mkdir()  # new directory, never overwrite evidence
    kernel = pathlib.Path(args.kernel).resolve()
    env = media.clean_env(EPOCH)
    profile = layout.load_profile()
    pins = media.check_pins(profile, env=env)
    checked = layout.check_kernel(kernel, args.kernel_sha256, env)
    if not layout.SERIAL.fullmatch(args.serial) or args.sectors < layout.MIN_SECTORS:
        raise layout.Refused('invalid exact-disk plan')
    identity = f'{checked["sha256"]}:{args.serial}:{args.sectors}:{EPOCH}'
    ids = {name: str(uuid.uuid5(uuid.NAMESPACE_URL, identity+':'+name)).upper() for name in ('disk','esp','absd')}
    volume = hashlib.sha256(identity.encode()).hexdigest()[:8].upper()
    stage = out/'stage'; stage.mkdir()
    line = layout.kernel_line(['durable=0'], ids['absd'], args.serial)
    grub = layout.grub_config(profile, line)
    install = json.dumps({'schema':'absd-native-install/1', 'guids':ids, 'kernel':checked,
                          'serial':args.serial, 'sectors':args.sectors}, sort_keys=True)+'\n'
    esp, files, _ = layout.build_esp(stage, profile, kernel, grub, volume[:4]+'-'+volume[4:],
                                    volume, install, EPOCH, env)
    raw = stage/'disk.img'
    with raw.open('xb') as handle: handle.truncate(args.sectors*512)
    target = layout.Target(raw, writable=True)
    try:
        layout.write_gpt(target, ids['disk'], ids['esp'], ids['absd'], env)
        layout.copy_esp(esp, target)
        os.fsync(target.fd)
        layout.read_back(target.fd, target.size, ids)
    finally: target.close()
    payload = pack(raw, args.serial, MODEL)
    (out/'payload.bin').write_bytes(payload)
    crc = zlib.crc32(payload)
    plan = {'schema':'absd-native-install-plan/1', 'serial':args.serial, 'model':MODEL, 'sectors':args.sectors,
            'logical_sector_bytes':512, 'policy':'whole-disk-blank-only', 'guids':ids,
            'layout':{'esp_first':layout.ESP_FIRST, 'esp_sectors':layout.ESP_SECTORS,
                      'absd_first':layout.ABSD_FIRST, 'absd_sectors':layout.ABSD_SECTORS},
            'kernel':checked, 'payload_sha256':hashlib.sha256(payload).hexdigest(), 'payload_crc32':f'{crc:08x}',
            'esp_files':files, 'pins':pins,
            'kernel_source':media.git(repo, 'rev-parse', 'HEAD').decode().strip(),
            'platform_source':media.git(media.ROOT, 'rev-parse', 'HEAD').decode().strip(),
            'limits':['QEMU emulated AHCI only; no physical admission', 'No SSH/network enrollment in this pilot',
                      'CRC32 is corruption detection; trusted media required; Secure Boot deferred',
                      'Interrupted/nonempty disks refuse retry; no data migration or resume']}
    shutil.copyfile(kernel, out/'installed.elf')
    # Build a dedicated kernel with immutable payload in reserved kernel RAM.
    build_env = dict(os.environ, ABSD_INSTALLER_PAYLOAD=str(out/'payload.bin'), CARGO_BUILD_JOBS='2')
    subprocess.run(['make', 'build'], cwd=repo, env=build_env, check=True)
    shutil.copyfile(repo/'target/debug/absd-kernel', out/'installer.elf')
    iso(out/'installer.elf', out/'installer.iso', config(args.serial, crc, plan=plan), stage/'media', plan)
    plan['artifacts'] = {name:media.sha(out/name) for name in ('payload.bin','installed.elf','installer.elf','installer.iso')}
    (out/'PLAN.json').write_text(json.dumps(plan, indent=2, sort_keys=True)+'\n')
    (out/'SHA256SUMS').write_text(''.join(f'{media.sha(out/name)}  {name}\n' for name in (*plan['artifacts'], 'PLAN.json')))
    shutil.rmtree(stage)  # private staging, no retained consumer
    print('INSTALLER ARTIFACT '+str(out))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel', required=True)
    p.add_argument('--kernel-sha256', required=True)
    p.add_argument('--kernel-repo', required=True)
    p.add_argument('--serial', required=True)
    p.add_argument('--sectors', type=int, default=(3 << 30)//512)
    p.add_argument('--out', required=True)
    args = p.parse_args()
    try: build(args)
    except layout.Refused as error: p.exit(2, f'INSTALLER REFUSED {error}\n')

if __name__ == '__main__': main()
