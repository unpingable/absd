#!/usr/bin/env python3
"""Execute the actual civil-time runtime codec against kernel-shared vectors."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='absd-civil-clock-') as temporary:
    binary = Path(temporary) / 'wire-test'
    subprocess.run(['rustc', '--edition=2024', '--test',
                    str(ROOT / 'tests/civil-clock-wire.rs'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=15)
