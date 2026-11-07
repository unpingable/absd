#!/usr/bin/env python3
"""Prepare a separate guarded copy of a cleanly halted legacy raw disk."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import storage_fence_upgrade as upgrade


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output', 'clean-console', 'work', 'kernel'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--attest-no-writes-since-halt', action='store_true',
                        help='attest that no writer ran after the recorded clean halt (off by default)')
    parser.add_argument('--halt-image-sha256',
                        help='whole-image hash recorded immediately after the awaited clean halt')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('release_for_guard_upgrade',
                                                Path(__file__).with_name('release.py'))
    release = importlib.util.module_from_spec(spec); spec.loader.exec_module(release)
    try:
        result = upgrade.convert(Path(args.source), Path(args.output),
            Path(args.clean_console).read_text(), Path(args.work), Path(args.kernel),
            oi=release.oi, release=release,
            attest_no_writes_since_halt=args.attest_no_writes_since_halt,
            halt_image_sha256=args.halt_image_sha256)
    except (ValueError, OSError, release.Failed, release.oi.Failed, release.absd_fs.Refused) as error:
        parser.exit(1, 'guard conversion refused: ' + str(error) + '\n')
    (Path(args.work) / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print('GUARD CONVERSION PREPARED_UNACTIVATED ' + str(args.output))


if __name__ == '__main__':
    main()
