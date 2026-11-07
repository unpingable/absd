#!/usr/bin/env python3
"""Concrete P2 QEMU adapter; inputs are prepared by recovery-point-matrix."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from p2_boot_binding import proxy
sys.exit(proxy(sys.argv[1:]))
