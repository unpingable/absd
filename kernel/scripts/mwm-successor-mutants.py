#!/usr/bin/env python3
"""Bounded fault controls against the actual successor host tests."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'user/src/mwm_successor.rs').read_text()
TESTS = (ROOT / 'user/src/mwm_successor_tests.rs').read_bytes()
MUTANTS = [
    ('shared-placement', 'sink.select(i);', 'sink.select(0);', 'isolated_faults_recompose_survivor'),
    ('fault-aborts-b', 'self.revoke(i, clients, sink)?;', 'return Err(Fault::Display);', 'isolated_faults_recompose_survivor'),
    ('omit-survivor-redraw', 'c.redraw(sink)?;', 'let _ = c;', 'revoke_redraw_never_resurrects_a'),
    ('unconditional-cached-redraw', 'c.redraw(sink)?;', 'draw(&c.last_pixels, c.last_sequence.unwrap_or(1), sink).map_err(|_| Fault::Display)?;', 'revoke_redraw_never_resurrects_a'),
    ('starve-second-client', 'let i = (self.next + offset) % 2;', 'let i = self.next; let _ = offset;', 'fast_sender_cannot_starve_b'),
    ('poll-fast-client-repeatedly', 'self.visits[i] += 1;', 'self.visits[i] += 1; if i == 0 { for _ in 0..8 { let _ = streams[i].poll(&mut clients[i]); } }', 'fast_sender_cannot_starve_b'),
    ('read-idle-writer', 'if available == 0 && writers != 0 {', 'if false && available == 0 && writers != 0 {', 'readiness_does_not_read_an_idle_writer'),
    ('mask-failure-is-success', 'sink.mask().map_err(|_| Fault::Mask)?;', 'let _ = sink.mask();', 'pump_mask_failure_stays_failed'),
    ('orderly-revoke-redraw',
     ('self.revoked = true;\n            self.last_sequence = None;',
      '&& !self.revoked\n            && !self.mask_required'),
     ('self.revoked = true;', '&& !self.mask_required'),
     'orderly_then_revoked_never_redrawn'),
]


def run():
    with tempfile.TemporaryDirectory(prefix='mwm-successor-mutants-') as tmp:
        directory = Path(tmp)
        (directory / 'mwm_successor_tests.rs').write_bytes(TESTS)
        for name, old, new, case in [('baseline', '', '', '')] + MUTANTS:
            source = SOURCE
            if name != 'baseline':
                changes = [(old, new)] if isinstance(old, str) else zip(old, new, strict=True)
                for before, after in changes:
                    assert before in source, name
                    source = source.replace(before, after)
            (directory / 'mwm_successor.rs').write_text(source)
            subprocess.run(['rustc', '--edition', '2024', '--test', '-O', str(directory / 'mwm_successor_tests.rs'), '-o', str(directory / 'test')], check=True)
            command = [str(directory / 'test'), '--test-threads=1']
            if case:
                command.extend([case, '--exact'])
            result = subprocess.run(command, capture_output=True, text=True)
            print(name, 'PASS' if name == 'baseline' and result.returncode == 0 else 'DIED' if result.returncode else 'SURVIVED', flush=True)
            print(result.stdout, end='')
            print(result.stderr, end='')
            assert (result.returncode == 0) == (name == 'baseline'), name


if __name__ == '__main__':
    run()
