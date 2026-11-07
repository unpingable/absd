"""Document notice selection on local release/build/dep-info fixtures; no build."""
import hashlib
import copy
import importlib.util
import json
import os
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import provenance as pv
import release_manifest as rm
from test_provenance import Repo, lock

spec=importlib.util.spec_from_file_location('document_builder',Path(__file__).with_name('build-native-tls-fixture.py'))
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class DocumentNotices(unittest.TestCase):
    def setUp(self):
        self.env = dict(os.environ)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.restore_env)
        self.repo = Repo(self.temp.name)
        r = self.repo
        r.write('tls/Cargo.toml', '[package]\nname="doc"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nliba="1"\n[[bin]]\nname="https_document"\npath="src/bin/https_document.rs"\n')
        r.write('tls/src/lib.rs', '// local library fixture\n')
        r.write('tls/src/bin/https_document.rs', 'fn main() {}\n')
        r.write('tls/Cargo.lock', lock([('doc', '0.1.0', ['liba'], False),
            ('liba', '1.0.0', ['libinner'], True), ('libinner', '1.0.0', [], True)]))
        r.write('targets/x86_64-unknown-absd.json', '{"arch":"x86_64"}')
        r.write('tls/PIN.json', json.dumps({'packages':[{'name':'ring','checksum':'1'*64}]}))
        for name in ('ring-absd.patch', 'ring-absd-tls-fixture-rng.patch'):
            r.write('patches/'+name, 'local patch fixture '+name)
        self.stage = Path(self.temp.name)/'stage'
        (self.stage/'ring').mkdir(parents=True)
        (self.stage/'ring/LICENSE').write_text('local ring fixture')
        files = {'LICENSE': digest((self.stage/'ring/LICENSE').read_bytes())}
        (self.stage/'STAGED-FILES.json').write_text(json.dumps(files))
        stage = {'ring_archive_sha256':'1'*64,
            'patches': {n:digest((r.root/'patches'/n).read_bytes()) for n in ('ring-absd.patch','ring-absd-tls-fixture-rng.patch')},
            'source_manifest_sha256':digest((self.stage/'STAGED-FILES.json').read_bytes())}
        (self.stage/'STAGE.json').write_text(json.dumps(stage))
        (r.root/'tls/tree').mkdir(); (r.root/'tls/tree/ring').symlink_to(self.stage/'ring')
        r.write('.gitignore', '.staged-sysroot/\n')
        r.write('.staged-sysroot/lib/rustlib/src/rust/library/std/src/lib.rs', '// standard library fixture\n')
        r.write('commands/https-document', b'\x7fELFlocal document fixture')
        r.commit('document fixture inputs')
        self.release = Path(self.temp.name)/'release'
        (self.release/'tree/bin').mkdir(parents=True)
        self.binary = self.release/'tree/bin/https-document'
        self.binary.write_bytes(b'\x7fELFlocal document fixture')
        self.manifest = self.release/'release-manifest.toml'
        self.receipt = Path(self.temp.name)/'build.json'
        self.build = {'outputs':{'https_document':{'path':'unused-label','sha256':digest(self.binary.read_bytes()),'bytes':self.binary.stat().st_size}},
            'source_revision':r.git('rev-parse','HEAD').strip(),'source_tree':r.git('rev-parse','HEAD^{tree}').strip(),
            'tracked_dirty':False,'untracked_source':False,'application':{'schema':'absd-https-document-build/1','fixture_selectors':False},
            'cargo_lock_sha256':digest((r.root/'tls/Cargo.lock').read_bytes()),'target_sha256':digest((r.root/'targets/x86_64-unknown-absd.json').read_bytes()),'ring_stage':stage,
            'staged_std_source_sha256':digest((digest(b'// standard library fixture\n')+'  library/std/src/lib.rs\n').encode())}
        self.deps = Path(self.temp.name)/'target/x86_64-unknown-absd/release/deps';self.deps.mkdir(parents=True)
        (self.deps/'https_document-0123456789abcdef.d').write_text('/absd/tls/src/bin/https_document.rs /cargo/registry/src/registry/liba-1.0.0/src/lib.rs /cargo/registry/src/registry/libinner-1.0.0/src/lib.rs')
        (self.deps/'doc-0123456789abcdef.d').write_text('/absd/tls/src/lib.rs')
        for crate in ('liba','libinner'):
            (self.deps/(crate+'-0123456789abcdef.d')).write_text('/cargo/registry/src/registry/'+crate+'-1.0.0/src/lib.rs')
        tool=Path(self.temp.name)/'selected-toolchain'
        compiler=tool/'bin/rustc';compiler.parent.mkdir(parents=True);compiler.write_bytes(b'local compiler fixture')
        docs=tool/'share/doc/rust';(docs/'licenses').mkdir(parents=True)
        (docs/'COPYRIGHT-library.html').write_text('local copyright fixture')
        (docs/'licenses/MIT.txt').write_text('local MIT fixture')
        (docs/'licenses/Apache-2.0.txt').write_text('local Apache fixture')
        self.std_notice=docs/'licenses/MIT.txt'
        self.build['explicit_environment']={'ABSD_REAL_RUSTC':str(compiler)}
        self.bind_dependencies()

    def bind_dependencies(self):
        self.build['application']['target_dep_info']=builder.document_dep_info(self.deps)
        self.bind_manifest()

    def bind_manifest(self):
        self.receipt.write_text(json.dumps(self.build))
        os.environ.update(ABSD_HTTPS_DOCUMENT='1', ABSD_HTTPS_DOCUMENT_RECEIPT=str(self.receipt), ABSD_TLS_STAGE=str(self.stage))
        # Use the actual producer, so consumer tests cannot invent its schema.
        document=rm.document_configuration(self.repo.root,self.release)
        self.manifest.write_text(rm.toml_dump({'release':{'id':'fixture-b'}, 'build':{'https_document':document},
            'source':{'platform_commit':self.repo.git('rev-parse','HEAD').strip()},
            'artifacts':{'files':{'tree/bin/https-document':{'sha256':digest(self.binary.read_bytes())}}}}))

    def restore_env(self):
        os.environ.clear();os.environ.update(self.env)

    def records(self):
        rec=pv.Records(self.repo.root)
        rec.config['document_application']={'artifact':'document-image','base':'image','binary':'tree/bin/https-document',
            'unit':{'name':'https-document','lock':'tls/Cargo.lock','manifest_dir':'tls','package':'doc','features':[]}}
        if hasattr(self, 'std_unit'):
            rec.config['artifact'][0]['unit'].append(copy.deepcopy(self.std_unit))
        return rec

    def select(self, rec=None):
        return pv.document_artifact(rec or self.records(),self.release,self.receipt,self.deps)

    def add_ring_target(self):
        r = self.repo
        r.crate('ring', '0.17.14', 'MIT')
        text = (r.root/'tls/Cargo.toml').read_text().replace('liba="1"', 'liba="1"\nring="=0.17.14"')
        r.write('tls/Cargo.toml', text + '\n[patch.crates-io]\nring={path="tree/ring"}\n')
        r.write('tls/Cargo.lock', lock([('doc','0.1.0',['liba','ring'],False),
            ('liba','1.0.0',['libinner'],True),('libinner','1.0.0',[],True),('ring','0.17.14',[],False)]))
        shutil.copyfile(r.registry/'ring-0.17.14/Cargo.toml', self.stage/'ring/Cargo.toml')
        files = {p.relative_to(self.stage/'ring').as_posix(): digest(p.read_bytes())
                 for p in (self.stage/'ring').rglob('*') if p.is_file()}
        (self.stage/'STAGED-FILES.json').write_text(json.dumps(files))
        stage = json.loads((self.stage/'STAGE.json').read_text())
        stage['source_manifest_sha256'] = digest((self.stage/'STAGED-FILES.json').read_bytes())
        (self.stage/'STAGE.json').write_text(json.dumps(stage))
        self.build['ring_stage'] = stage
        r.commit('actual Cargo patch spelling fixture')
        self.build['source_revision'] = r.git('rev-parse','HEAD').strip()
        self.build['source_tree'] = r.git('rev-parse','HEAD^{tree}').strip()
        self.build['cargo_lock_sha256'] = digest((r.root/'tls/Cargo.lock').read_bytes())
        self.ring_dep = self.deps/'ring-2051cdd587ff3b0f.d'

    def test_ring_relative_patch_dep_info_and_existing_remaps(self):
        self.add_ring_target()
        for spelling in ('tree/ring/', str(self.stage/'ring')+'/', '/tls-fixture-stage/ring/'):
            with self.subTest(spelling=spelling):
                self.ring_dep.write_text(str(self.ring_dep)+': '+spelling+'src/lib.rs\n')
                self.bind_dependencies()
                binding = self.select()
                ring = next(row for row in binding['target_compiled_crates'] if row['component']=='ring')
                self.assertEqual(ring['source'], str(self.stage/'ring'))
                self.assertEqual(ring['dep_info'], [self.ring_dep.name])

    def test_ring_suffixes_and_unbound_relative_alias_refuse(self):
        self.add_ring_target()
        for spelling in ('/unrelated/tree/ring/', 'prefix/tree/ring/', '../tree/ring/', 'tree/ring-other/'):
            with self.subTest(spelling=spelling):
                self.ring_dep.write_text(spelling+'src/lib.rs')
                self.bind_dependencies()
                with self.assertRaisesRegex(pv.Problem, 'compiler closure differs'):
                    self.select()
        self.ring_dep.write_text('tree/ring/src/lib.rs')
        alias = self.repo.root/'tls/tree/ring'
        alias.unlink()
        other = Path(self.temp.name)/'different-ring'; other.mkdir()
        alias.symlink_to(other)
        row = {'component':'ring','version':'0.17.14','origin':'registry','use':'linked'}
        with self.assertRaisesRegex(pv.Problem, 'source path differs'):
            pv.document_path_closure([row],[self.ring_dep],self.repo.root,Path('/absent'),ring=self.stage/'ring')

    def test_tls_relative_entries_match_sources_not_output_target(self):
        lib = self.deps/'doc-0123456789abcdef.d'
        binary = self.deps/'https_document-0123456789abcdef.d'
        output = str(self.repo.root/'tls/target/x86_64-unknown-absd/release/deps/output')
        lib.write_text(output+': src/lib.rs\n')
        binary.write_text(output+': src/bin/https_document.rs /cargo/registry/src/registry/liba-1.0.0/src/lib.rs /cargo/registry/src/registry/libinner-1.0.0/src/lib.rs\n')
        self.bind_dependencies()
        self.select()
        for wrong in ('/unbound/src/lib.rs', 'src/lib.rs-extra', 'src/bin/https_document.rs'):
            with self.subTest(wrong=wrong):
                lib.write_text(output+': '+wrong+'\n')
                self.bind_dependencies()
                with self.assertRaisesRegex(pv.Problem, 'source path differs'):
                    self.select()

    def test_selected_inventory_and_actual_notice_texts_preserve_default(self):
        rec=self.records();base=rec.config['artifact'][0]
        before=pv.render(pv.inventory(rec,base)[0]);binding=self.select(rec)
        self.assertEqual(binding['sha256'],digest(self.binary.read_bytes()))
        self.assertEqual(binding['target_compiled_registry_packages'],['liba-1.0.0','libinner-1.0.0'])
        self.assertEqual(pv.render(pv.inventory(rec,base)[0]),before)
        out=Path(self.temp.name)/'notices';pv.notices(rec,'document-image',out,quiet=True)
        self.assertIn('https-document\tfixture-b\tfirst-party', (out/'inventory.tsv').read_text())
        self.assertEqual((out/'licenses/liba-1.0.0/LICENSE-MIT').read_text(), (self.repo.registry/'liba-1.0.0/LICENSE-MIT').read_text())

    def test_mismatched_binary_refuses_before_output(self):
        self.binary.write_bytes(b'\x7fELFchanged')
        with self.assertRaises(pv.Problem):self.select()

    def test_wrong_receipt_lock_target_or_source_refuses(self):
        for key in ('cargo_lock_sha256','target_sha256','source_revision','source_tree'):
            with self.subTest(key=key):
                changed={**self.build,key:'0'*64};self.receipt.write_text(json.dumps(changed))
                with self.assertRaises(pv.Problem):self.select()
        self.receipt.write_text(json.dumps(self.build))

    def test_fixture_actor_receipt_refuses(self):
        changed={**self.build,'application':{'schema':'absd-https-document-build/1','fixture_selectors':True}}
        self.receipt.write_text(json.dumps(changed))
        with self.assertRaises(pv.Problem):self.select()

    def test_changed_ring_source_refuses(self):
        (self.stage/'ring/LICENSE').write_text('changed')
        with self.assertRaisesRegex(pv.Problem,'ring stage'):self.select()

    def test_missing_compiler_dep_info_refuses(self):
        (self.deps/'https_document-0123456789abcdef.d').unlink()
        with self.assertRaisesRegex(pv.Problem,'no https_document binary'):self.select()

    def test_extra_or_missing_compiled_component_refuses(self):
        path=self.deps/'https_document-0123456789abcdef.d';original=path.read_text()
        path.write_text(original+' /cargo/registry/src/registry/extra-1.0/src/lib.rs')
        self.bind_dependencies()
        with self.assertRaisesRegex(pv.Problem,'compiler closure differs'):self.select()
        path.write_text(original.replace('/cargo/registry/src/registry/liba-1.0.0/src/lib.rs',''))
        (self.deps/'liba-0123456789abcdef.d').unlink()
        self.bind_dependencies()
        with self.assertRaisesRegex(pv.Problem,'compiler closure differs'):self.select()

    def test_substituted_receipt_refuses_even_with_same_output(self):
        self.receipt.write_text(self.receipt.read_text()+'\n')
        with self.assertRaisesRegex(pv.Problem,'identity differs'):self.select()

    def test_substituted_dependency_record_refuses(self):
        with (self.deps/'doc-0123456789abcdef.d').open('a') as out:out.write(' extra')
        with self.assertRaisesRegex(pv.Problem,'dep-info differs'):self.select()

    def test_missing_linked_path_crate_refuses(self):
        (self.deps/'doc-0123456789abcdef.d').unlink();self.bind_dependencies()
        with self.assertRaisesRegex(pv.Problem,'missing path crate'):self.select()

    def test_producer_record_with_altered_dep_identity_refuses(self):
        self.build['application']['target_dep_info']['doc-0123456789abcdef.d']['sha256']='0'*64
        self.bind_manifest()
        with self.assertRaisesRegex(pv.Problem,'dep-info differs'):self.select()

    def add_standard_library(self):
        r=self.repo;library=r.root/'.staged-sysroot/lib/rustlib/src/rust/library'
        for name in ('std','core'):
            root=library/name;root.mkdir(parents=True,exist_ok=True)
            (root/'src').mkdir(exist_ok=True);(root/'src/lib.rs').write_text('// local '+name+' fixture')
            (root/'Cargo.toml').write_text('[package]\nname="'+name+'"\nversion="0.0.0"\nlicense="MIT"\n'+
                ('[dependencies]\ncore={path="../core"}\n' if name=='std' else ''))
            (self.deps/(name+'-1111111111111111.d')).write_text('/absd/.staged-sysroot/lib/rustlib/src/rust/library/'+name+'/src/lib.rs')
        duplicate=library/'unconsumed/core';duplicate.mkdir(parents=True)
        (duplicate/'Cargo.toml').write_text('[package]\nname="core"\nversion="0.0.0"\n')
        r.write('pins/library.Cargo.lock',lock([('std','0.0.0',['core'],False),('core','0.0.0',[],False)]))
        r.commit('standard library selection fixture')
        files=sorted((p for p in library.rglob('*') if p.is_file()),key=lambda p:p.relative_to(library).as_posix().encode())
        self.build['staged_std_source_sha256']=digest(''.join(digest(p.read_bytes())+'  library/'+p.relative_to(library).as_posix()+'\n' for p in files).encode())
        self.build['source_revision']=r.git('rev-parse','HEAD').strip();self.build['source_tree']=r.git('rev-parse','HEAD^{tree}').strip()
        self.std_notice.unlink()
        self.std_unit={'name':'std','lock':'pins/library.Cargo.lock','package':'std','sources':str(library),
            'manifest_dir':'std','features':[],'source_id':'exact local toolchain fixture','notice_files':[str(self.std_notice)]}
        self.bind_dependencies()

    def test_selected_staged_std_keeps_toolchain_classification_and_all_crates(self):
        self.add_standard_library();rec=self.records();self.std_notice.write_text('local std fixture notice')
        boot_notice=Path(self.temp.name)/'boot-notice.txt';boot_notice.write_text('local boot fixture')
        rec.config['artifact'][0]['component'][0]['notice_files']=[str(boot_notice)]
        binding=self.select(rec)
        artifact=next(a for a in rec.config['artifact'] if a['name']=='document-image')
        rows,_=pv.inventory(rec,artifact)
        std=[row for row in rows if row['component'] in ('std','core')]
        self.assertEqual(len(std),2);self.assertTrue(all(row['origin']=='toolchain' for row in std))
        selected_core=next(row for row in binding['target_compiled_crates'] if row['component']=='core')
        self.assertTrue(selected_core['source'].endswith('/library/core'))
        self.assertEqual({row['component'] for row in binding['target_compiled_crates']},{'doc','liba','libinner','std','core'})
        out=Path(self.temp.name)/'complete-std-notices'
        _,missing,_=pv.notices(rec,'document-image',out,quiet=True)
        self.assertEqual(missing,[])
        self.assertEqual((out/'licenses/rust-standard-library/licenses/MIT.txt').read_bytes(),self.std_notice.read_bytes())
        (self.deps/'core-1111111111111111.d').unlink();self.bind_dependencies()
        with self.assertRaisesRegex(pv.Problem,'missing path crate'):self.select()

    def test_cli_missing_std_notice_and_default_base_notice_refuse(self):
        self.add_standard_library()
        boot_notice=Path(self.temp.name)/'boot-notice.txt';boot_notice.write_text('local boot fixture')
        for missing in ('std','base'):
            with self.subTest(missing=missing):
                if missing=='base':self.std_notice.write_text('local std fixture notice')
                rec=self.records()
                if missing=='std':rec.config['artifact'][0]['component'][0]['notice_files']=[str(boot_notice)]
                out=Path(self.temp.name)/('missing-'+missing)
                with patch.object(pv,'Records',return_value=rec):
                    code=pv.main(['--root',str(self.repo.root),'notices','document-image',
                        '--document-release',str(self.release),'--document-build-receipt',str(self.receipt),
                        '--document-deps',str(self.deps),'--out',str(out)])
                self.assertEqual(code,2);self.assertFalse((out/'DOCUMENT-COMPOSITION.json').exists())
                if missing=='base':self.assertIn('Bootloader',(out/'NOTICES.md').read_text())

    def test_missing_receipt_compiler_cannot_use_configured_notice_paths(self):
        self.build.pop('explicit_environment');self.bind_manifest()
        with self.assertRaisesRegex(pv.Problem,'requires actual compiler'):self.select()

    def test_changed_staged_std_refuses(self):
        (self.repo.root/'.staged-sysroot/lib/rustlib/src/rust/library/std/src/lib.rs').write_text('changed')
        with self.assertRaisesRegex(pv.Problem,'standard library differs'):self.select()

    def test_nested_toolchain_manifest_and_alias_are_resolved(self):
        library=Path(self.temp.name)/'known-library'
        for name,relative,alias in (('std_detect','stdarch/crates/std_detect','std_detect'),
                                    ('compiler_builtins','compiler-builtins/compiler-builtins','compiler_builtins')):
            crate=library/relative;crate.mkdir(parents=True)
            (crate/'Cargo.toml').write_text('[package]\nname="'+name+'"\nversion="1.0.0"\n[lib]\nname="'+alias+'"\n')
        rows=[{'component':name,'version':'1.0.0','use':'linked','origin':'toolchain'}
              for name in ('std_detect','compiler_builtins')]
        files=[]
        for name,relative in (('std_detect','stdarch/crates/std_detect'),('compiler_builtins','compiler-builtins/compiler-builtins')):
            p=self.deps/(name+'-1111111111111111.d')
            p.write_text('/absd/.staged-sysroot/lib/rustlib/src/rust/library/'+relative+'/src/lib.rs');files.append(p)
        found=pv.document_path_closure(rows,files,self.repo.root,library)
        self.assertEqual({row['component'] for row in found},{'std_detect','compiler_builtins'})
        with self.assertRaisesRegex(pv.Problem,'missing path crate'):
            pv.document_path_closure(rows,files[:1],self.repo.root,library)
        files[0].write_text('/unbound/library/stdarch/crates/std_detect/src/lib.rs')
        with self.assertRaisesRegex(pv.Problem,'source path differs'):
            pv.document_path_closure(rows,files,self.repo.root,library)
        files[0].write_text('/wrong/absd/.staged-sysroot/lib/rustlib/src/rust/library/stdarch/crates/std_detect/src/lib.rs')
        with self.assertRaisesRegex(pv.Problem,'source path differs'):
            pv.document_path_closure(rows,files,self.repo.root,library)

    def test_registry_lib_alias_is_not_derived_from_package_name(self):
        crate=self.repo.registry/'rustls-webpki-1.0.0';crate.mkdir()
        (crate/'Cargo.toml').write_text('[package]\nname="rustls-webpki"\nversion="1.0.0"\n[lib]\nname="webpki"\n')
        row={'component':'rustls-webpki','version':'1.0.0','origin':'registry','use':'linked'}
        p=self.deps/'webpki-1111111111111111.d';p.write_text('/cargo/registry/src/registry/rustls-webpki-1.0.0/src/lib.rs')
        pv.document_path_closure([row],[p],self.repo.root,Path('/absent'),[self.repo.registry])
        wrong=self.deps/'rustls_webpki-1111111111111111.d';wrong.write_bytes(p.read_bytes())
        with self.assertRaisesRegex(pv.Problem,'unexpected target'):
            pv.document_path_closure([row],[wrong],self.repo.root,Path('/absent'),[self.repo.registry])

    def test_unexpected_target_and_arbitrary_filename_suffix_refuse(self):
        for name in ('extra-1111111111111111.d','doc-label.d'):
            p=self.deps/name;p.write_text('/absd/tls/src/lib.rs');self.bind_dependencies()
            with self.assertRaisesRegex(pv.Problem,'unexpected target|Cargo target identity'):self.select()
            p.unlink()

    def test_builder_refuses_missing_or_substituted_dep_info(self):
        app=self.deps/'https_document-0123456789abcdef.d';data=app.read_bytes();app.unlink()
        with self.assertRaisesRegex(SystemExit,'lacks target'):builder.document_dep_info(self.deps)
        substitute=Path(self.temp.name)/'alternate.d';substitute.write_bytes(data);app.symlink_to(substitute)
        with self.assertRaisesRegex(SystemExit,'regular file'):builder.document_dep_info(self.deps)

    def test_document_cli_requires_all_final_notice_texts(self):
        for available in (False,True):
            with self.subTest(available=available):
                rec=self.records()
                if available:
                    notice=Path(self.temp.name)/'boot-license.txt';notice.write_text('Local boot licence fixture')
                    rec.config['artifact'][0]['component'][0]['notice_files']=[str(notice)]
                out=Path(self.temp.name)/('notice-output-'+str(available))
                with patch.object(pv,'Records',return_value=rec):
                    rc=pv.main(['--root',str(self.repo.root),'notices','document-image',
                        '--document-release',str(self.release),'--document-build-receipt',str(self.receipt),
                        '--document-deps',str(self.deps),'--out',str(out)])
                self.assertEqual(rc,0 if available else 2)
                self.assertEqual((out/'DOCUMENT-COMPOSITION.json').exists(),available)

    def test_missing_dependency_license_refuses(self):
        (self.repo.registry/'liba-1.0.0/LICENSE-MIT').unlink()
        with self.assertRaisesRegex(pv.Problem,'notice texts'):self.select()

    def test_default_selection_never_adds_document_unit(self):
        rec=self.records()
        self.assertEqual([a['name'] for a in rec.config['artifact']],['image'])
        self.assertNotIn('https-document',pv.render(pv.inventory(rec,rec.config['artifact'][0])[0]))

    def test_default_cli_rejects_document_inputs_without_output(self):
        out=Path(self.temp.name)/'must-not-exist'
        code=pv.main(['--root',str(self.repo.root),'notices','image',
            '--document-release',str(self.release),'--out',str(out)])
        self.assertEqual(code,2)
        self.assertFalse(out.exists())

    def test_compiler_input_scope_does_not_change_default_inventory(self):
        self.add_standard_library();self.std_notice.write_text('local MIT fixture');rec=self.records()
        before=pv.render(pv.inventory(rec,rec.config['artifact'][0])[0])
        binding=self.select(rec)
        self.assertEqual(before,pv.render(pv.inventory(rec,rec.config['artifact'][0])[0]))
        rows=pv.inventory(rec,rec.config['artifact'][-1])[0]
        std=[r for r in rows if r['component'] in ('std','core')]
        self.assertTrue(std);self.assertTrue(all(r['use']=='compiler-input' for r in std))
        self.assertIn('not final ELF',binding['coverage'])
        self.assertTrue(all('membership not established' in r['coverage'] for r in binding['target_compiled_crates']))

    def test_compiler_fingerprint_observation_is_hash_bound_not_link_proof(self):
        fp=self.deps.parent/'.fingerprint/doc-0123456789abcdef/lib-doc.json';fp.parent.mkdir(parents=True)
        fp.write_text(json.dumps({'deps':[[1,'std',True,2]],'compile_kind':123}))
        binding=self.select();observed=binding['compiler_fingerprint_observations']['doc-0123456789abcdef.d']
        self.assertEqual(observed['sha256'],digest(fp.read_bytes()));self.assertEqual(observed['unit_dependencies'],[[1,'std',True,2]])
        self.assertIn('not final ELF',binding['coverage'])
        fp.write_text('{malformed')
        with self.assertRaisesRegex(pv.Problem,'fingerprint malformed'):self.select()

    def test_changed_source_is_not_the_receipt_source(self):
        self.repo.write('tls/Cargo.toml',(self.repo.root/'tls/Cargo.toml').read_text()+'\n# change\n')
        with self.assertRaisesRegex(pv.Problem,'identity differs'):self.select()


class ToolchainDeclaration(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.library=self.root/'library'
        self.manifest=self.library/'proc_macro/Cargo.toml';self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text('[package]\nname="proc_macro"\nversion="0.0.0"\n')
        self.tool=self.root/'1.95.0-x86_64-unknown-linux-gnu'
        self.compiler=self.tool/'bin/rustc';self.compiler.parent.mkdir(parents=True);self.compiler.write_bytes(b'local compiler identity fixture')
        self.doc=self.tool/'share/doc/rust/COPYRIGHT-library.html';self.doc.parent.mkdir(parents=True)
        self.doc.write_text('<b>File/Directory:</b> <code>.</code>\n<p><b>License:</b> Apache-2.0 OR MIT</p>')
        licenses=self.doc.parent/'licenses';licenses.mkdir();(licenses/'MIT.txt').write_text('local MIT fixture');(licenses/'Apache-2.0.txt').write_text('local Apache fixture')
        self.pins={'manifest_sha256':digest(self.manifest.read_bytes()),'std_sha256':'selected-staged-source',
                   'rustc_sha256':digest(self.compiler.read_bytes()),'copyright_sha256':digest(self.doc.read_bytes())}
        self.receipt={'explicit_environment':{'ABSD_REAL_RUSTC':str(self.compiler)},'staged_std_source_sha256':'selected-staged-source'}

    def bind(self):
        with patch.object(pv,'DOCUMENT_PROC_MACRO_DECLARATION',self.pins):return pv.document_toolchain_notices(self.library,self.receipt)

    def test_exact_upstream_source_declaration_and_notice_paths(self):
        paths,proof=self.bind();self.assertEqual(paths,[str(self.doc),str(self.doc.parent/'licenses')])
        self.assertEqual(proof['proc_macro']['license'],'Apache-2.0 OR MIT')
        self.assertIn('not Cargo-declared',proof['proc_macro']['basis'])
        self.assertEqual(proof['proc_macro']['sha256'],digest(self.doc.read_bytes()))

    def test_wrong_selected_compiler_refuses(self):
        self.compiler.write_bytes(b'changed compiler')
        with self.assertRaises(pv.Problem):self.bind()

    def test_wrong_copyright_refuses(self):
        self.doc.write_text(self.doc.read_text()+'changed')
        with self.assertRaises(pv.Problem):self.bind()

    def test_wrong_manifest_refuses(self):
        self.manifest.write_text(self.manifest.read_text()+'description="changed"\n')
        with self.assertRaises(pv.Problem):self.bind()

    def test_wrong_staged_source_refuses(self):
        self.receipt['staged_std_source_sha256']='different'
        with self.assertRaises(pv.Problem):self.bind()

    def test_wrong_compiler_path_refuses(self):
        self.receipt['explicit_environment']['ABSD_REAL_RUSTC']=str(self.root/'other/rustc')
        with self.assertRaises(pv.Problem):self.bind()

    def test_applicable_upstream_exception_refuses_even_with_pinned_document(self):
        self.doc.write_text(self.doc.read_text()+'<b>File/Directory:</b> <code>library/proc_macro</code>')
        self.pins['copyright_sha256']=digest(self.doc.read_bytes())
        with self.assertRaisesRegex(pv.Problem,'scope differs'):self.bind()

    def test_missing_root_scope_refuses_even_with_pinned_document(self):
        self.doc.write_text(self.doc.read_text().replace('<code>.</code>','<code>other</code>'))
        self.pins['copyright_sha256']=digest(self.doc.read_bytes())
        with self.assertRaises(pv.Problem):self.bind()

    def test_manifest_symlink_refuses(self):
        actual=self.root/'copied-manifest';actual.write_bytes(self.manifest.read_bytes());self.manifest.unlink();self.manifest.symlink_to(actual)
        with self.assertRaises(pv.Problem):self.bind()

    def test_license_directory_root_symlink_refuses(self):
        original=self.doc.parent/'licenses';moved=self.root/'outside-licenses';original.rename(moved);original.symlink_to(moved)
        with self.assertRaisesRegex(pv.Problem,'aliased'):self.bind()

    def test_ancestor_notice_directory_symlink_refuses(self):
        original=self.tool/'share';moved=self.root/'outside-share';original.rename(moved);original.symlink_to(moved)
        with self.assertRaisesRegex(pv.Problem,'aliased'):self.bind()

    def test_missing_notice_texts_refuses(self):
        shutil.rmtree(self.doc.parent/'licenses')
        with self.assertRaises(pv.Problem):self.bind()


if __name__=='__main__':unittest.main()
