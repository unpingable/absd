#!/usr/bin/env python3
"""Recording-only full-profile flag contracts; never invokes real Cargo/clang."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parent
FAMILIES = ('integration', 'nightshift', 'pulse', 'pulse-observe', 'nq', 'ag-loopctl')
INVENTORY = set('pulse-std pulse-journal-std ag-authority ag-sqlite nightshift-resolver nightshift-ag-resolver nightshift-ag-resolver-short-ttl nightshift-writer nightshift-pipeline-writer pulse-support-resolver pulse-support-resolver-test pulse-frame-pressure-cycle pulse-frame-pressure-resolver pulse-frame-pressure-resolver-test nq nq-unknown ag-loopctl-init ag-loopctl-record-proposal'.split())
RECORDER = r'''#!/usr/bin/python3
import json, os, pathlib, sys
p = pathlib.Path.cwd()
env = dict(os.environ)
with open(env['RECORD'], 'a') as f:
    f.write(json.dumps({'cwd': str(p), 'argv': sys.argv[1:], 'env': env}) + '\n')
if env.get('FAIL_CARGO'):
    sys.exit(23)
args = sys.argv[1:]
names = [args[args.index('--bin')+1]] if '--bin' in args else ['pulse_std', 'pulse_journal_std', 'ag_authority', 'ag_sqlite']
out = pathlib.Path(env.get('CARGO_TARGET_DIR', str(p/'target'))) / 'x86_64-unknown-absd/release'
out.mkdir(parents=True, exist_ok=True)
for name in names:
    (out/name).write_bytes(('RECORDED '+name).encode())
if names == ['nq']:
    digest = out/'build/nq-profiles-fixture/output'
    digest.parent.mkdir(parents=True, exist_ok=True)
    digest.write_text('cargo:rustc-env=NQ_PROFILES_SOURCE_DIGEST=sha256:'+'a'*64+'\n')
'''

class Flags(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='absd-flags-')
        self.addCleanup(self.temp.cleanup)
        self.top = Path(self.temp.name)
        self.root = self.top/'platform'
        scripts = self.root/'scripts'
        scripts.mkdir(parents=True)
        for name in ['inputs.sh'] + ['build-'+f+'.sh' for f in FAMILIES]:
            shutil.copy2(SOURCE/name, scripts/name)
        (self.root/'integration').mkdir()
        (self.root/'.staged-sysroot/lib/rustlib/src/rust/library').mkdir(parents=True)
        for stage in ('ag', 'pulse-source', 'nightshift', 'pulse', 'pulse-observe', 'nq', 'ag-loopctl'):
            stub = scripts/('stage-'+stage+'.sh')
            stub.write_text('#!/bin/sh\nset -eu\n[ "${FAIL_STAGE:-}" != '+stage+' ] || exit 17\nmkdir -p "$(dirname "$0")/../../absd-std-staged-'+stage+'/absd-nq" "$(dirname "$0")/../../absd-std-staged-'+stage+'/absd-ag"\n')
            stub.chmod(0o755)
        bindir = self.top/'bin'
        bindir.mkdir()
        (bindir/'cargo').write_text(RECORDER)
        (bindir/'cargo').chmod(0o755)
        (bindir/'clang').write_text('#!/bin/sh\n[ "$#" = 1 ] && [ "$1" = -print-resource-dir ] || exit 99\nprintf "%s\\n" /recorded/clang/resource\n')
        (bindir/'clang').chmod(0o755)
        self.record = self.top/'calls.jsonl'
        self.env = {'PATH': str(bindir)+':/usr/bin:/bin', 'HOME': str(self.top), 'CARGO_HOME': str(self.top/'cargo'), 'ABSD_RUST_TOOLCHAIN': '/recorded/toolchain', 'RECORD': str(self.record), 'LC_ALL': 'C', 'ABSD_INCREMENTAL': '0'}
        for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_TARGET_X86_64_UNKNOWN_ABSD_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS'):
            self.env[name] = 'AMBIENT_SENTINEL'

    def run_family(self, family):
        return subprocess.run([str(self.root/'scripts'/('build-'+family+'.sh'))], env=self.env, text=True, capture_output=True)

    def calls(self):
        return [json.loads(line) for line in self.record.read_text().splitlines()]

    def helper(self, family='integration', cfg=None, root=None, cargo=None):
        env = dict(self.env, ROOT=str(root or self.root))
        if cargo is not None:
            env['CARGO_HOME'] = str(cargo)
        args = [family] + ([] if cfg is None else [cfg])
        return subprocess.run(['/bin/sh', '-c', 'set -eu; root=$ROOT; . "$root/scripts/inputs.sh"; absd_full_rustflags "$@"; printf "%s" "$ABSD_FULL_RUSTFLAGS"', 'fixture', *args], env=env, text=True, capture_output=True)

    def verify(self, call):
        env, args = call['env'], call['argv']
        family = 'integration' if Path(call['cwd']).name == 'integration' else Path(call['cwd']).name.removeprefix('absd-std-staged-')
        family = {'absd-nq':'nq', 'absd-ag':'ag-loopctl'}.get(family, family)
        flags = env['CARGO_ENCODED_RUSTFLAGS'].split('\x1f')
        linker = 'user-linker.ld' if family == 'integration' else str(self.root/'user-linker.ld')
        expected = ['-C', 'link-arg=-T'+linker, '-C', 'link-arg=--gc-sections']
        if family in ('pulse', 'pulse-observe'):
            expected += ['--check-cfg', 'cfg(pulse_absd_test_config)']
            if env['CARGO_TARGET_DIR'].endswith('/target-test'):
                expected += ['--cfg', 'pulse_absd_test_config']
        else:
            expected += ['--cfg', 'getrandom_backend="rdrand"']
        self.assertEqual(flags[:len(expected)], expected)
        remaps = flags[len(expected):]
        self.assertEqual(len(remaps), 9)
        mapping = dict(x.removeprefix('--remap-path-prefix=').split('=', 1) for x in remaps)
        self.assertEqual(mapping[str(self.root)], '/absd')
        self.assertEqual(mapping[str(self.top/'cargo/registry/src')], '/cargo/registry/src')
        for stage in ('ag','pulse-source','nightshift','pulse','pulse-observe','nq','ag-loopctl'):
            self.assertEqual(mapping[str(self.top/('absd-std-staged-'+stage))], '/absd-inputs/'+stage)
        self.assertEqual([len(x) for x in mapping], sorted(len(x) for x in mapping))
        for name in ('RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_TARGET_X86_64_UNKNOWN_ABSD_RUSTFLAGS','CARGO_BUILD_RUSTFLAGS'):
            self.assertNotIn(name, env)
        self.assertNotIn('AMBIENT_SENTINEL', env['CARGO_ENCODED_RUSTFLAGS'])
        self.assertNotIn('--config', args)
        for arg in ('+1.95.0','build','-Z','build-std=core,alloc,std,panic_abort','--release','--offline','--locked'):
            self.assertIn(arg, args)
        self.assertEqual(env['ABSD_REAL_RUSTC'], '/recorded/toolchain/bin/rustc')
        self.assertEqual(env['RUSTC'], str(self.root/'scripts/rustc-staged.sh'))
        if family != 'integration':
            self.assertEqual(args[args.index('--target')+1], 'x86_64-unknown-absd')
        if family in ('integration','nightshift','nq','ag-loopctl'):
            self.assertEqual(env['CC_x86_64_unknown_absd'], 'clang')
            self.assertEqual(env['AR_x86_64_unknown_absd'], 'llvm-ar-18')
            self.assertEqual(env['CRATE_CC_NO_DEFAULTS'], '1')
            self.assertEqual(env['CFLAGS_x86_64_unknown_absd'], '--target=x86_64-unknown-none-elf -ffreestanding -nostdinc -isystem /recorded/clang/resource/include -I'+str(self.root)+'/sqlite/include -mcmodel=large -fno-pic -O2 -ffunction-sections -fdata-sections')
            self.assertEqual(env['LIBSQLITE3_FLAGS'], '-DSQLITE_OS_OTHER=1 -DSQLITE_OMIT_LOCALTIME -USQLITE_ENABLE_LOAD_EXTENSION -DSQLITE_OMIT_LOAD_EXTENSION')
        if family in ('nightshift','pulse','pulse-observe'):
            self.assertEqual(env['CARGO_PROFILE_RELEASE_PANIC'], 'abort')
        return family

    def test_full_inventory_and_program_contracts(self):
        result = self.run_family('integration')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.stem for p in self.root.glob('*.elf')}, INVENTORY)
        calls = self.calls()
        self.assertEqual(len(calls), 15) # integration invocation produces four
        groups = {}
        for call in calls:
            groups.setdefault(self.verify(call), []).append(call['env'])
        night = groups['nightshift']
        self.assertEqual([x.get('CARGO_PROFILE_RELEASE_STRIP') for x in night], [None,'symbols','symbols',None,None])
        base = '--store /nightshift/nightshift.sqlite --resolver-id nightshift-observation-resolver/v1 --default-ttl-ms '
        self.assertEqual([x['ABSD_PROGRAM_ARGS'] for x in night[:3]], [base+'600000',base+'86400000',base+'600000'])
        self.assertEqual(night[3]['ABSD_PROGRAM_ARGS'], '--store /nightshift/nightshift.sqlite cycle run --request /nightshift/posture-request.json --present-evidence-resolver /owners/pulse-support-resolver --nq-program /owners/nq --nq-config /owners/nq.toml --nq-source-id nq-node:fixture')
        self.assertEqual(night[4]['ABSD_PROGRAM_ARGS'], '--store /nightshift/nightshift.sqlite cycle run --request /nightshift/cycle-request.json --present-evidence-resolver /owners/pulse-support-resolver --nq-program /owners/nq --nq-config /owners/nq.toml --nq-source-id nq-store-genesis:26373050-17aa-4ed9-8a41-cc27f3bcfb1f --ag-loopctl /owners/ag-loopctl --ag-database /ag/ag.sqlite --ag-observation-resolver /owners/observation-resolver --ag-observation-resolver-id nightshift-observation-resolver/v1 --ag-runtime-profile /ag/runtime-profile.json')
        self.assertEqual([x['ABSD_PROGRAM_NAME'] for x in groups['pulse']], ['pulse-support-resolver']*2)
        self.assertEqual([x['PULSE_ABSD_TEST_CONFIG'] for x in groups['pulse']], ['/pulse/support-config.json']*2)
        self.assertEqual([x['ABSD_PROGRAM_NAME'] for x in groups['pulse-observe']], ['absd-frame-pressure-cycle','pulse-support-resolver','pulse-support-resolver'])
        self.assertEqual([x['PULSE_ABSD_TEST_CONFIG'] for x in groups['pulse-observe']], ['/observe/support-config.json']*3)
        prefix = '--config /nq/nq.toml --json diagnostics qualify sha256:'
        self.assertEqual([x['ABSD_PROGRAM_ARGS'] for x in groups['nq']], [prefix+'bddd0a9e1e29fad5c066ab0fb3cfd6c32408e6f1ad8d3f38ec79235a5a83bbd3',prefix+'0'*64])
        self.assertEqual([x['ABSD_PROGRAM_ARGS'] for x in groups['ag-loopctl']], ['init --database /ag/state/ag.sqlite --genesis /ag/genesis.json --runtime-profile /ag/config/runtime-profile.json', 'record-proposal --database /ag/state/ag.sqlite --input /ag/proposal.json --observation-resolver /ag/config/observation-resolver --expected-observation-resolver-id nightshift-observation-resolver/v1'])

    def test_standalone_families(self):
        for family in FAMILIES[1:]:
            with self.subTest(family=family):
                self.record.unlink(missing_ok=True)
                result = self.run_family(family)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(self.calls())
                for call in self.calls():
                    self.assertEqual(self.verify(call), family)

    def test_refusals(self):
        for family,cfg in [('unknown',None),('integration','--cfg pulse_absd_test_config'),('pulse','--cfg surprise')]:
            with self.subTest(family=family,cfg=cfg):
                result = self.helper(family,cfg)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(result.stdout,'')
        for value in ('relative','/tmp/a=b','/tmp/a\nb','/tmp/a\x1fb','/tmp/a\x7fb'):
            with self.subTest(path=value):
                result = self.helper(cargo=value)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(result.stdout,'')

    def test_tokens_aliases_and_specificity(self):
        cargo = self.root/"cache ' quoted space"
        result = self.helper(cargo=cargo)
        self.assertEqual(result.returncode,0,result.stderr)
        flags = result.stdout.split('\x1f')
        self.assertIn('--remap-path-prefix='+str(cargo)+'/registry/src=/cargo/registry/src',flags)
        rootflag = '--remap-path-prefix='+str(self.root)+'=/absd'
        self.assertLess(flags.index(rootflag), flags.index('--remap-path-prefix='+str(cargo)+'/registry/src=/cargo/registry/src'))
        alias = self.top/"alias ' space"
        alias.symlink_to(self.root, target_is_directory=True)
        result = self.helper(root=alias)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(rootflag,result.stdout.split('\x1f'))
        self.assertIn('--remap-path-prefix='+str(alias)+'=/absd',result.stdout.split('\x1f'))
        badroot = self.top/'root=ambiguous'
        badroot.symlink_to(self.root,target_is_directory=True)
        result = self.helper(root=badroot)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout,'')
        conflict = self.top/'absd-std-staged-ag'
        conflict.symlink_to(self.root,target_is_directory=True)
        result = self.helper()
        self.assertNotEqual(result.returncode,0)
        self.assertIn('conflicting identities',result.stderr)

    def test_symlink_parent_traversal_refused(self):
        # normpath(link/..) is not the filesystem meaning of link/.. .
        (self.top/'a').mkdir()
        (self.top/'target/d').mkdir(parents=True)
        (self.top/'a/link').symlink_to(self.top/'target/d', target_is_directory=True)
        cargo = self.top/'a/link/../cache'
        self.assertEqual(cargo.resolve(), self.top/'target/cache')
        result = self.helper(cargo=cargo)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('unsupported or ambiguous path', result.stderr)

    def test_failure_propagation(self):
        self.env['FAIL_STAGE'] = 'ag'
        result = self.run_family('integration')
        self.assertEqual(result.returncode,17)
        self.assertFalse(self.record.exists())
        self.env.pop('FAIL_STAGE')
        self.env['FAIL_CARGO'] = '1'
        for family in FAMILIES:
            with self.subTest(family=family):
                result = self.run_family(family)
                self.assertEqual(result.returncode,23,result.stderr)
                self.assertNotIn(' BUILT ',result.stdout)
                self.assertFalse(list(self.root.glob('*.elf')))

    def test_legacy_helper(self):
        result = subprocess.run(['/bin/sh','-c','set -eu; root=$1; . "$root/scripts/inputs.sh"; absd_rust_remap; printf "%s" "$ABSD_RUST_REMAP"','fixture',str(self.root)],env=self.env,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        pair = "'--remap-path-prefix="+str(self.root)+"=/absd'"
        self.assertEqual(result.stdout, "target.x86_64-unknown-absd.rustflags=["+pair+", "+pair+", '--remap-path-prefix="+str(self.top)+"/cargo/registry/src=/cargo/registry/src']")

if __name__ == '__main__':
    unittest.main(verbosity=2)
