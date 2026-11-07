#!/usr/bin/env python3
"""Exercise the real CLI with a deterministic terminal observation provider.
The ABSD-linked builds separately check the actual syscall/runtime integration.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
STUB = r'''
mod absd_runtime {
    pub fn link_anchor() {}
    pub fn sleep_ticks(_: u64) {}
    pub mod terminal {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static READ: AtomicUsize = AtomicUsize::new(0);
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct Size { pub columns: u32, pub rows: u32 }
        pub fn size() -> Option<Size> {
            let next = READ.fetch_add(1, Ordering::SeqCst);
            match std::env::var("TEST_TERMINAL").unwrap().as_str() {
                "known" => Some(Size { rows: 51, columns: 173 }),
                "unknown" => None,
                "resize" if next < 2 => Some(Size { rows: 51, columns: 173 }),
                "resize" if next == 2 => Some(Size { rows: 52, columns: 174 }),
                _ => None,
            }
        }
    }
}
'''

with tempfile.TemporaryDirectory(prefix="absd-terminal-cli-") as directory:
    source = Path(directory) / "terminal.rs"
    program = Path(directory) / "terminal-size"
    actual = (ROOT / "src/bin/terminal_size.rs").read_text()
    # Remove only the ABSD target feature and module documentation. Every
    # executable statement is the production CLI source, with native calls
    # supplied by this bounded provider instead of issuing kernel syscalls.
    actual = "\n".join(line for line in actual.splitlines() if not line.startswith(("#!", "//!")))
    source.write_text(STUB + actual)
    subprocess.run(["rustc", "--edition=2024", str(source), "-o", str(program)], check=True)
    def run(mode, args=()):
        return subprocess.run([str(program), *args], env={**os.environ, "TEST_TERMINAL": mode}, capture_output=True)
    result = run("known")
    assert (result.returncode, result.stdout, result.stderr) == (0, b"51 173\n", b"")
    result = run("unknown")
    assert result.returncode == 1 and not result.stdout and b"dimensions unknown" in result.stderr
    result = run("known", ("--invalid",))
    assert result.returncode == 2 and b"usage: terminal-size [--watch]" in result.stderr
    result = run("resize", ("--watch",))
    assert result.returncode == 1 and result.stdout == b"51 173\n52 174\n" and b"dimensions unknown" in result.stderr
print("TERMINAL SIZE CLI 4/4 PASS")
