#!/usr/bin/env python3
"""Exercise actual startup encoder/parser with the shared terminal role vector."""
from pathlib import Path
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="absd-terminal-startup-") as temporary:
    binary = Path(temporary) / "test"
    subprocess.run(["rustc", "--edition=2024", "--test", "-Adead_code", str(ROOT / "scripts/fixtures/terminal-startup.rs"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
