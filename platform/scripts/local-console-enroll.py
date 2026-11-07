#!/usr/bin/env python3
"""Create a per-image operator verifier and owner-only random token.
Install verifier as /ssh/local-login; retain token outside the image.
"""
import argparse
import hashlib
import os
import secrets
from pathlib import Path

def enroll(verifier: Path, token_file: Path):
    token = secrets.token_hex(16).encode('ascii')
    # Exclusive creation prevents accidental overwrite of an enrolled identity.
    with os.fdopen(os.open(token_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(token + b'\n')
    descriptor = b'ABSD-LOCAL-1 operator ' + hashlib.sha256(token).hexdigest().encode() + b'\n'
    with os.fdopen(os.open(verifier, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(descriptor)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--verifier', required=True, type=Path)
    p.add_argument('--token-file', required=True, type=Path)
    args = p.parse_args()
    enroll(args.verifier, args.token_file)
    print('Local operator enrollment created; token was not printed. Install only the verifier in /ssh/local-login.')
if __name__ == '__main__':
    main()
