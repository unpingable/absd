#!/usr/bin/env python3
"""Execute the real observation syscall body against controlled boundaries."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='absd-observation-syscall-') as temporary:
    out = Path(temporary)
    subprocess.run(['rustc', '--edition=2024', '--crate-name', 'absd_abi', '--crate-type=rlib',
                    str(ROOT / 'abi/src/lib.rs'), '-o', str(out / 'libabsd_abi.rlib')], check=True)
    subprocess.run(['rustc', '--edition=2024', str(ROOT / 'scripts/fixtures/observation-syscall.rs'),
                    '--extern', 'absd_abi=' + str(out / 'libabsd_abi.rlib'), '-o', str(out / 'check')], check=True)
    subprocess.run([str(out / 'check')], check=True, timeout=15)
