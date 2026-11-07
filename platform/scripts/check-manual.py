#!/usr/bin/env python3
"""Check command manual coverage without building any programs."""
import argparse
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import manual_coverage
import operator_image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--source-only', action='store_true')
    mode.add_argument('--rendered', type=pathlib.Path)
    parser.add_argument('--https-document', action='store_true')
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    names = operator_image.command_names(args.https_document)
    files = None
    if args.rendered is not None:
        files = [(f'/share/man/{p.relative_to(args.rendered)}', p.read_bytes())
                 for p in sorted(args.rendered.rglob('*')) if p.is_file()]
    try:
        count = manual_coverage.check(root, names, files)
    except manual_coverage.Refused as error:
        parser.exit(1, f'manual coverage refused: {error}\n')
    print(f'ABSD MAN COVERAGE commands={count} mode={"source" if files is None else "rendered"}')


if __name__ == '__main__':
    main()
