#!/usr/bin/env python3
"""Exercise the carried NQ age predicates and civil gate, not a rebuilt NQ CLI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '80574417f0188afd37992db7ac764a6f0f72ff62'
FILES = ['crates/nq-app/src/cli.rs', 'crates/nq-core/src/engine.rs']


def balanced(text, start, ending):
    depth = 0
    for pos in range(start, len(text)):
        char = text[pos]
        if char in '({[':
            depth += 1
        elif char in ')}]':
            depth -= 1
        if char == ending and depth == 0:
            return text[start:pos + 1]
    raise ValueError('unterminated source region')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    parser.add_argument('--age-only', action='store_true')
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        path = work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(subprocess.check_output(['git', '-C', str(args.source), 'show', PIN + ':' + name]))
    patch = ROOT / 'patches/nq-absd.patch'
    subprocess.run(['git', 'apply', '--unsafe-paths', *['--include=' + f for f in FILES], str(patch)], cwd=work, check=True)
    engine = (work / FILES[1]).read_text()
    regions = []
    for marker in ['fn visibility_for(', 'let evaluated_at = parse_timestamp(&row.evaluated_at).ok();']:
        pos = engine.index('let stale =', engine.index(marker))
        regions.append(balanced(engine, pos, ';'))
    rust = '''use chrono::{DateTime, Utc, Duration};
struct Freshness { reliance_seconds: i64 }
struct Descriptor { freshness: Freshness }
struct Profile { descriptor: Descriptor }
impl Profile { fn descriptor(&self) -> &Descriptor { &self.descriptor } }
fn profile() -> Profile { Profile { descriptor: Descriptor { freshness: Freshness { reliance_seconds: 60 } } } }
fn live(evaluated_at: DateTime<Utc>, observed: Option<DateTime<Utc>>) -> bool {
let profile = profile();
''' + regions[0] + ''' stale }
fn historical(evaluated: DateTime<Utc>, observed_at: Option<DateTime<Utc>>) -> bool {
let compiled = profile(); let evaluated_at = Some(evaluated);
''' + regions[1] + ''' stale }
fn check_age(predicate: fn(DateTime<Utc>, Option<DateTime<Utc>>) -> bool) {
let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
assert!(predicate(now, Some(now + Duration::seconds(1))), "future evidence cannot be fresh");
assert!(predicate(now, Some(now - Duration::seconds(61))));
assert!(predicate(now, None));
assert!(!predicate(now, Some(now)));
assert!(!predicate(now, Some(now - Duration::seconds(60))));
}
#[test] fn actual_live_age_rejects_future_and_old_evidence() { check_age(live); }
#[test] fn actual_historical_age_rejects_future_and_old_evidence() { check_age(historical); }
'''
    cli = (work / FILES[0]).read_text()
    if not args.age_only:
        start = cli.index('fn absd_require_civil_time()')
        body = cli.index('{', start)
        gate = cli[start:body] + balanced(cli, body, '}')
        rust += '''extern crate self as absd_runtime;
use anyhow::{Result, bail};
mod civil_clock {
use std::sync::Mutex;
#[derive(Clone, Copy)] pub struct Info { pub unix_ns: Option<u64>, pub expired: bool }
impl Info { pub fn stale(&self) -> bool { self.expired } }
pub static VALUE: Mutex<Result<Info, i64>> = Mutex::new(Err(-5));
pub fn info() -> Result<Info, i64> { *VALUE.lock().unwrap() }
}
''' + gate + '''
#[test] fn actual_gate_refuses_unknown_stale_and_status_errors() {
use civil_clock::{Info, VALUE};
for value in [Err(-5), Ok(Info {unix_ns: None, expired: false}), Ok(Info {unix_ns: Some(1), expired: true})] {
*VALUE.lock().unwrap() = value; assert!(absd_require_civil_time().is_err());
}
*VALUE.lock().unwrap() = Ok(Info {unix_ns: Some(1_800_000_000_000_000_000), expired: false});
assert!(absd_require_civil_time().is_ok());
}
'''
        # This is source admission, not an execution claim for CLI dispatch.
        entry = cli[cli.index('pub async fn run(options: Nq)'):]
        prefix = entry[:entry.index('match options.command')]
        assert 'absd_require_civil_time()?' in prefix
        for command in ['DiagnosticsCommand::Qualify', 'DiagnosticsCommand::Inspect', 'DiagnosticsCommand::Export', 'Command::Profiles', 'Command::Protocol']:
            assert command in prefix
    (work / 'src').mkdir(exist_ok=True)
    (work / 'src/lib.rs').write_text(rust)
    (work / 'Cargo.toml').write_text('[package]\nname="nq-clock-proof"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\nchrono="0.4.45"\nanyhow="1"\n[profile.test]\ndebug=0\n')
    (work / 'SOURCE.json').write_text(json.dumps({'pin': PIN, 'patch_sha256': hashlib.sha256(patch.read_bytes()).hexdigest(), 'files': {f: hashlib.sha256((work / f).read_bytes()).hexdigest() for f in FILES}, 'scope': 'Actual carried age predicates and gate; profile/status boundary substitutions. CLI exemption source admission only; no store, whole CLI or guest execution.'}, indent=2) + '\n')
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()), CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0')
    subprocess.run(['cargo', '+1.95.0', 'test', '--manifest-path', str(work / 'Cargo.toml'), '--target', 'x86_64-unknown-linux-gnu', '--offline', '--lib', '--', '--test-threads=1'], env=env, check=True)


if __name__ == '__main__':
    main()
