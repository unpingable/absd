#!/usr/bin/env python3
"""Inspect the operator kernel's actual loadable program catalog and ISO files.

This checks binary structure, not compiler correctness or runtime execution.
The catalog layout is the observed x86_64 Rust EmbeddedProgram layout of the
supported kernel: two (pointer, length) pairs, name then image. Fail closed if
that layout changes. The caller separately binds clean source, builds and launch.
"""
import hashlib
import struct

NAMES = ('init', 'hello-a', 'hello-b', 'exit7', 'fault', 'fpu', 'trap', 'privileged', 'heap', 'unmapped', 'overflow', 'cell', 'shared', 'readonly', 'watcher', 'piper', 'sleeper', 'shell', 'fuzz', 'multi-handle', 'stack-grow', 'stack-jump', 'orphaner', 'supervised-worker', 'recovery-worker', 'service-client', 'client-service-worker', 'alloc-probe', 'isolation', 'input-stream', 'external-workload', 'block-probe', 'external-reader', 'owner-1', 'owner-2', 'owner-3', 'owner-4', 'nic-probe', 'file-server', 'machine-probe', 'hostile-probe', 'rt-probe', 'fpu-mxcsr', 'smp-user', 'logd')


class BindingError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise BindingError(message)


def digest(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def load_segments(data):
    require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01', 'ELF64 little endian required')
    require(struct.unpack_from('<HH', data, 16) == (2, 62), 'x86_64 ET_EXEC required')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    require(size == 56 and 0 < count <= 128 and offset + size * count <= len(data), 'ELF program headers')
    loads = []
    for i in range(count):
        kind, flags, start, address, _, length, memory, _ = struct.unpack_from('<IIQQQQQQ', data, offset + i * size)
        if kind == 1:
            require(start + length <= len(data) and length <= memory and address + memory < 2**64, 'ELF LOAD bounds')
            loads.append((start, address, length, flags))
    require(loads, 'ELF LOAD missing')
    return loads


def mapped_slice(data, loads, address, length):
    require(length > 0 and address + length < 2**64, 'empty or overflowing catalog slice')
    matches = [(off + address - va, flags) for off, va, size, flags in loads
               if va <= address and address + length <= va + size]
    require(len(matches) == 1, 'catalog slice must have one file-backed LOAD mapping')
    off, flags = matches[0]
    return data[off:off + length], off, flags


def verify_kernel_catalog(kernel, expected):
    """Bind named catalog slots to exact ELF bytes; require the full unique catalog.

    expected maps catalog names (init, external-workload, file-server) to bytes.
    Every catalog row is checked, including rows not selected by this boot.
    """
    require(expected and set(expected) <= set(NAMES), 'unknown or empty expected catalog slots')
    loads = load_segments(kernel)
    candidates = set()
    for off, va, size, _ in loads:
        at = kernel.find(b'init', off, off + size)
        while at >= 0:
            pointer = struct.pack('<QQ', va + at - off, 4)
            for table_off, table_va, table_size, _ in loads:
                pos = kernel.find(pointer, table_off, table_off + table_size)
                while pos >= 0:
                    if pos % 8 == 0 and pos + 32 * len(NAMES) <= table_off + table_size:
                        candidates.add((pos, table_va + pos - table_off))
                    pos = kernel.find(pointer, pos + 1, table_off + table_size)
            at = kernel.find(b'init', at + 1, off + size)
    found = []
    for pos, address in candidates:
        rows = []
        try:
            for index, name in enumerate(NAMES):
                np, nl, ip, il = struct.unpack_from('<QQQQ', kernel, pos + index * 32)
                actual_name, _, _ = mapped_slice(kernel, loads, np, nl)
                require(actual_name == name.encode(), 'catalog name/order')
                image, image_off, _ = mapped_slice(kernel, loads, ip, il)
                load_segments(image)
                rows.append((name, image, {'index': index, 'name': name, 'address': ip,
                                           'file_offset': image_off, **digest(image)}))
            found.append((pos, address, rows))
        except (BindingError, struct.error):
            continue
    require(len(found) == 1, 'unique complete loadable program catalog required')
    pos, address, rows = found[0]
    selected = []
    for name, image, receipt in rows:
        if name in expected:
            require(image == expected[name], 'catalog image differs: ' + name)
            selected.append(receipt)
    return {'kernel': digest(kernel), 'catalog_file_offset': pos, 'catalog_address': address,
            'catalog_entries': len(NAMES), 'selected': selected,
            'limit': 'Exact loadable catalog slices; assumes trusted source/compiler/loader and separately bound launch.'}


def iso_payload(data):
    """Read the actual ISO9660/Rock Ridge critical file extents, without mounting."""
    pvd = data[16 * 2048:17 * 2048]
    require(len(pvd) == 2048 and pvd[:7] == b'\x01CD001\x01', 'ISO critical member binding failed')
    require(struct.unpack_from('<H', pvd, 128)[0] == struct.unpack_from('>H', pvd, 130)[0] == 2048, 'ISO critical member binding failed')

    def contents(record):
        require(len(record) >= 34, 'ISO critical member binding failed')
        at, length = (struct.unpack_from('<I', record, 2)[0], struct.unpack_from('<I', record, 10)[0])
        require(at == struct.unpack_from('>I', record, 6)[0] and length == struct.unpack_from('>I', record, 14)[0], 'ISO critical member binding failed')
        require(at * 2048 + length <= len(data), 'ISO critical member binding failed')
        return data[at * 2048:at * 2048 + length]

    def child(directory, wanted):
        require(len(directory) >= 34, 'ISO directory record bounds')
        require(directory[25] & 2, 'ISO critical member binding failed')
        raw, at, found = (contents(directory), 0, [])
        while at < len(raw):
            size = raw[at]
            if not size:
                at = (at // 2048 + 1) * 2048
                continue
            record = raw[at:at + size]
            require(len(record) == size and size >= 34, 'ISO critical member binding failed')
            at += size
            n = record[32]
            require(33 + n <= len(record), 'ISO name bounds')
            name = record[33:33 + n].split(b';', 1)[0].lower()
            extra = 33 + n + (n % 2 == 0)
            while extra + 4 <= len(record):
                kind, length = (record[extra:extra + 2], record[extra + 2])
                require(length >= 4 and extra + length <= len(record), 'ISO critical member binding failed')
                if kind == b'NM':
                    require(length >= 5, 'ISO Rock Ridge name bounds')
                if kind == b'NM' and record[extra + 4] == 0:
                    name = record[extra + 5:extra + length]
                extra += length
            if name == wanted:
                found.append(record)
        require(len(found) == 1, 'ISO critical directory/file missing or duplicated')
        return found[0]
    root = pvd[156:156 + pvd[156]]
    directory = child(root, b'boot')
    image = child(directory, b'absd-kernel')
    config = child(child(directory, b'grub'), b'grub.cfg')
    require(not image[25] & 2 and (not config[25] & 2), 'ISO critical member binding failed')
    kernel, boot = contents(image), contents(config)
    require(kernel and data.count(kernel) == 1, 'ISO critical member binding failed')
    return kernel, boot


def _iso_binding(data, kernel, boot):
    actual_kernel, actual_boot = iso_payload(data)
    require(actual_kernel == kernel and actual_boot == boot, 'ISO critical member binding failed')
    return {'kernel': digest(actual_kernel), 'grub_config': digest(actual_boot)}


def verify_iso(iso, kernel, grub):
    """Compare critical ISO9660/Rock Ridge file bytes, without mounting."""
    try:
        return _iso_binding(iso, kernel, grub)
    except (IndexError, struct.error) as error:
        raise BindingError('ISO critical member binding failed: ' + str(error)) from error


def validate_operator_grub(config, cpus=1):
    """Accept only the canonical operator boot command sequence.

    Standalone comments and blank lines are harmless; every other line must
    match the supported Makefile durable=0 served configuration exactly after
    surrounding whitespace is removed. No GRUB substitutions or extra commands.
    """
    require(isinstance(config, bytes), 'GRUB config must be bytes')
    try:
        text = config.decode('ascii')
    except UnicodeDecodeError as error:
        raise BindingError('GRUB config must be ASCII') from error
    require(all(ord(c) >= 32 or c in '\t\n\r' for c in text) and '\x7f' not in text,
            'GRUB config contains control characters')
    require('\r' not in text.replace('\r\n', ''), 'GRUB config contains bare carriage return')
    meaningful = [line.strip() for line in text.splitlines()
                  if line.strip() and not line.lstrip().startswith('#')]
    require(type(cpus) is int and cpus in (1, 2, 4, 6), 'unsupported operator CPU count')
    option = f' smp-operator={cpus}' if cpus > 1 else ''
    expected = ['insmod all_video', 'set timeout=0',
                'menuentry "ABSD durable step" {',
                'multiboot2 /boot/absd-kernel durable=0 net fsd served' + option + ' nvme-write=absd',
                'boot', '}']
    require(meaningful == expected, 'GRUB config differs from canonical operator boot commands')
    return {'config': digest(config), 'commands': meaningful}
