#!/usr/bin/env python3
"""Exercise the real pinned-and-patched AG clock function with clock status only substituted.

No AG staging script or upstream checkout is mutated. ABSD_AG_CLOCK_WORK may
name a fresh persistent directory for red/green evidence; otherwise temporary
scratch is retired after this foreground test. ABSD_AG_SOURCE names the existing
AG Git input; the machine-local source map is the fallback.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
PIN = '21c8da079f2465a2466c54431cc315699fc57cbe'
SUBJECT = 'crates/ag-app/src/bin/ag-loopctl.rs'


def ag_source():
    source = os.environ.get('ABSD_AG_SOURCE')
    config = ROOT.parent / 'absd-inputs.local.sh'
    if source is None and config.is_file():
        source = next((line.split('=', 1)[1] for line in config.read_text().splitlines()
                       if line.startswith('ABSD_AG_SOURCE=')), None)
    if not source:
        raise RuntimeError('set ABSD_AG_SOURCE to the existing pinned AG Git input')
    return Path(source).resolve()


class ActualAgClock(unittest.TestCase):
    def test_patched_clock_refuses_unusable_civil_time_and_uses_same_known_sample(self):
        # Wrongly retaining SystemTime::now, accepting stale/unknown status,
        # resampling after validation, or multiplying ns instead of dividing
        # makes these actual consumer controls fail.
        repo = ag_source()
        patch = ROOT / 'patches/ag-loopctl-absd.patch'
        requested = os.environ.get('ABSD_AG_CLOCK_WORK')
        if requested:
            work = Path(requested).resolve()
            work.mkdir(parents=True, exist_ok=False)
        else:
            temp = tempfile.TemporaryDirectory(prefix='ag-clock-')
            self.addCleanup(temp.cleanup)
            work = Path(temp.name)
        upstream = work / 'ag'
        upstream.mkdir()
        paths = subprocess.check_output(['git', 'apply', '--numstat', str(patch)], text=True)
        for row in paths.splitlines():
            path = row.split('\t', 2)[2]
            source = subprocess.run(['git', '-C', str(repo), 'show', PIN + ':' + path],
                                    capture_output=True)
            if source.returncode == 0:
                destination = upstream / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(source.stdout)
            elif not row.startswith(('0\t', '-\t')):
                # New carried-patch files legitimately do not exist at the pin.
                exists = subprocess.run(['git', '-C', str(repo), 'cat-file', '-e', PIN],
                                        capture_output=True)
                self.assertEqual(exists.returncode, 0, 'the exact AG pin is unavailable')
        subprocess.run(['git', 'apply', '--check', str(patch)], cwd=upstream, check=True)
        subprocess.run(['git', 'apply', str(patch)], cwd=upstream, check=True)
        subprocess.run(['git', 'apply', '--reverse', '--check', str(patch)], cwd=upstream, check=True)
        patched = (upstream / SUBJECT).read_text()
        # The pinned file ends with this function. Include its actual complete
        # source, preserving cfg branches; do not reimplement its behavior.
        function = patched[patched.index('fn now_unix_ms() -> anyhow::Result<u64> {'):]
        (work / 'actual-clock.rs').write_text(function)
        identity = {'source_repository': str(repo), 'source_pin': PIN,
                    'source_path': SUBJECT, 'patch_sha256': hashlib.sha256(patch.read_bytes()).hexdigest(),
                    'patched_source_sha256': hashlib.sha256(patched.encode()).hexdigest(),
                    'tested_function_sha256': hashlib.sha256(function.encode()).hexdigest(),
                    'civil_module_sha256': hashlib.sha256((ROOT/'runtime/src/civil_clock.rs').read_bytes()).hexdigest(),
                    'scope': 'actual patched AG function and real civil info decoder; kernel status transport substituted; no guest'}
        (work / 'SOURCE.json').write_text(json.dumps(identity, indent=2)+'\n')
        (work / 'Cargo.toml').write_text('''[package]
name="actual-ag-clock-proof"
version="0.1.0"
edition="2024"
[workspace]
[lib]
path="fixture.rs"
[dependencies]
anyhow="=1.0.103"
[profile.test]
debug=0
''')
        fixture = '''extern crate self as absd_runtime;
use anyhow::Context;
#[allow(unused_imports)]
use std::time::{SystemTime, UNIX_EPOCH};
#[allow(dead_code)]
#[path=CIVIL_PATH]
pub mod civil_clock;
#[allow(dead_code)]
fn clock_owner_handle() -> u64 { panic!("clock mutation is outside this test") }
thread_local! {
    static STATUS: std::cell::RefCell<(i64,[u8;96])> = const { std::cell::RefCell::new((0,[0;96])) };
}
unsafe fn syscall3(op:u64, out:u64, b:u64, c:u64) -> i64 {
    assert_eq!((op,b,c),(0x7fb0,0,0));
    STATUS.with(|status| {
        let (rc, bytes) = *status.borrow();
        if rc >= 0 { unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(),out as *mut u8,96); } }
        rc
    })
}
include!("actual-clock.rs");
#[cfg(target_os = "absd")]
fn status(ns: Option<u64>, stale:bool) {
    let mut bytes=[0u8;96];
    bytes[..4].copy_from_slice(&1u32.to_le_bytes());
    if ns.is_some() {
        bytes[4..8].copy_from_slice(&(if stale {3u32} else {1u32}).to_le_bytes());
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&100u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&101u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&1u64.to_le_bytes());
        bytes[48..56].copy_from_slice(&1u64.to_le_bytes());
    }
    bytes[16..24].copy_from_slice(&ns.unwrap_or(u64::MAX).to_le_bytes());
    STATUS.with(|s| *s.borrow_mut()=(0,bytes));
}
#[cfg(target_os = "absd")]
#[test] fn unknown_cannot_become_a_persistable_timestamp() {
    status(None,false); assert!(now_unix_ms().is_err());
}
#[cfg(target_os = "absd")]
#[test] fn stale_known_sample_cannot_become_a_persistable_timestamp() {
    status(Some(1_700_000_000_123_456_789),true); assert!(now_unix_ms().is_err());
}
#[cfg(target_os = "absd")]
#[test] fn kernel_refusal_cannot_become_a_persistable_timestamp() {
    STATUS.with(|s| s.borrow_mut().0=-38); assert!(now_unix_ms().is_err());
}
#[cfg(target_os = "absd")]
#[test] fn exact_known_sample_is_used_instead_of_system_time_resampling() {
    status(Some(1_700_000_000_123_456_789),false);
    assert_eq!(now_unix_ms().unwrap(),1_700_000_000_123);
}
#[cfg(target_os = "absd")]
#[test] fn nanosecond_conversion_handles_epoch_submilliseconds_and_upper_bound() {
    status(Some(0),false); assert_eq!(now_unix_ms().unwrap(),0);
    status(Some(999_999),false); assert_eq!(now_unix_ms().unwrap(),0);
    status(Some(18_446_744_073_709_551_614),false);
    assert_eq!(now_unix_ms().unwrap(),18_446_744_073_709);
}
#[cfg(target_os = "absd")]
#[test] fn reserved_unknown_sentinel_is_refused_even_with_known_flag() {
    status(Some(u64::MAX),false); assert!(now_unix_ms().is_err());
}
#[cfg(not(target_os = "absd"))]
#[test] fn unix_branch_keeps_standard_system_time_behavior() {
    let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    let value = now_unix_ms().unwrap() as u128;
    let after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    assert!(before <= value && value <= after);
}
'''.replace('CIVIL_PATH', json.dumps(str(ROOT/'runtime/src/civil_clock.rs')))
        (work / 'fixture.rs').write_text(fixture)
        env = dict(os.environ, CARGO_TARGET_DIR=str(work/'target'), CARGO_INCREMENTAL='0',
                   CARGO_BUILD_JOBS='2', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
                   CARGO_ENCODED_RUSTFLAGS='\x1f'.join(['--check-cfg','cfg(target_os,values("absd"))',
                                                       '--cfg','target_os="absd"','-Aexplicit_builtin_cfgs_in_flags']))
        for key in ['RUSTFLAGS','RUSTC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER']:
            env.pop(key,None)
        for configuration in ['absd', 'unix']:
            compile_env = dict(env)
            if configuration == 'unix':
                compile_env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(
                    ['--check-cfg', 'cfg(target_os,values("absd"))'])
            result = subprocess.run(['cargo','+1.95.0','test','--offline','--manifest-path',str(work/'Cargo.toml'),
                                     '--target','x86_64-unknown-linux-gnu','--lib','--','--nocapture'],
                                    cwd=work,env=compile_env,text=True,capture_output=True)
            (work/(configuration+'-cargo.log')).write_text(result.stdout+result.stderr)
            print(configuration + ':\n' + result.stdout+result.stderr)
            self.assertEqual(result.returncode,0,'actual patched AG clock failed: '+configuration)


if __name__ == '__main__':
    unittest.main()
