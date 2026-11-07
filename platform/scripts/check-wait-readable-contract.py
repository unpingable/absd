#!/usr/bin/env python3
"""Check paired readable-wait constants and compile the real Rust/C bindings."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def constant(path, name, expected):
    text = path.read_text()
    values = re.findall(r'^(?:pub )?const ' + name + r': (?:u64|u32|usize) = ([^;]+);$', text, re.M)
    if values != [expected]:
        raise SystemExit(f'{path}: {name} expected {expected}, found {values}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--kit', type=Path, help='also verify and compile the installed kit header')
    args = parser.parse_args()
    root, kernel = args.root.resolve(), args.kernel.resolve()
    for path, name, value in [
        (kernel / 'abi/src/lib.rs', 'KERNEL_ABI', '1'),
        (root / 'release/src/lib.rs', 'KERNEL_ABI', '1'),
        (kernel / 'abi/src/syscall.rs', 'SYS_WAIT_READABLE', '0x7fa8'),
        (root / 'runtime/src/lib.rs', 'SYS_WAIT_READABLE', '0x7fa8'),
        (kernel / 'abi/src/syscall.rs', 'WAIT_READABLE_MAX', '11'),
        (root / 'runtime/src/readable.rs', 'WAIT_READABLE_MAX', '11'),
        (root / 'fsd/src/readiness.rs', 'MAX_HANDLES', '11'),
        (kernel / 'abi/src/syscall.rs', 'WAIT_READABLE_POLL', 'u64::MAX'),
        (root / 'runtime/src/readable.rs', 'WAIT_READABLE_POLL', 'u64::MAX'),
        (kernel / 'src/kernel_log.rs', 'SYS_LOG_READ', '0x7fc0'),
    ]:
        constant(path, name, value)
    header = root / 'c/include/absd/syscall.h'
    if args.kit:
        installed = args.kit.resolve() / 'include/absd/syscall.h'
        if installed.read_bytes() != header.read_bytes():
            raise SystemExit('installed syscall header differs from reviewed source')
        header = installed
    with tempfile.TemporaryDirectory(prefix='absd-readable-contract-') as directory:
        work = Path(directory)
        subprocess.run(['rustc', '+1.95.0', '--edition=2024', '--test',
                        str(root / 'tests/fixtures/wait_readable_binding.rs'),
                        '-o', str(work / 'binding')], check=True)
        subprocess.run([str(work / 'binding')], check=True)
        consumer = work / 'consumer.c'
        consumer.write_text('''#include <absd/syscall.h>
_Static_assert(ABSD_SYS_WAIT_READABLE == 0x7fa8, "number");
_Static_assert(ABSD_WAIT_READABLE_MAX == 11, "bound");
_Static_assert(ABSD_WAIT_READABLE_POLL == UINT64_MAX, "poll");
int64_t probe(const uint64_t *handles, uint64_t count, uint64_t ticks) {
    return absd_wait_readable(handles, count, ticks);
}
''')
        resource = subprocess.check_output(['clang', '-print-resource-dir'], text=True).strip()
        subprocess.run(['clang', '--target=x86_64-unknown-none-elf', '-ffreestanding',
                        '-nostdinc', '-isystem', str(header.parent.parent),
                        '-isystem', resource + '/include', '-Wall', '-Wextra', '-Werror',
                        '-O2', '-c', str(consumer), '-o', str(work / 'consumer.o')], check=True)
        code = subprocess.check_output(['objdump', '-d', str(work / 'consumer.o')], text=True)
        if not re.search(r'\bint\s+\$0x80', code) or '$0x7fa8,%eax' not in code:
            raise SystemExit('compiled C wrapper lacks the expected int80 syscall number')
    print('WAIT READABLE CONTRACT OK ABI=1 number=0x7fa8 max=11 log=0x7fc0'
          + (' installed_header=checked' if args.kit else ' installed_header=not_checked'))


if __name__ == '__main__':
    main()
