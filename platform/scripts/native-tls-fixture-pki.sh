#!/bin/sh
# First-party disposable fixture recipe. No private material belongs in the tree.
set -eu
umask 077
exec python3 - "$0" "$@" <<'PY'
import argparse, datetime, hashlib, json, os, pathlib, re, socket, stat, subprocess, sys

def require(ok, why):
    if not ok: raise RuntimeError(why)
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(path): return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
def seal(path, value):
    with pathlib.Path(path).open('x') as f:
        json.dump(value, f, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
def identity(path):
    p=pathlib.Path(path); return {'path':str(p.resolve()),'bytes':p.stat().st_size,'sha256':sha(p)}
def date_at(t): return datetime.datetime.fromtimestamp(t,datetime.timezone.utc).strftime('%Y%m%d%H%M%SZ')

script=pathlib.Path(sys.argv[1]).resolve()
p=argparse.ArgumentParser(description='Generate admitted fixture-only PKI; never writes private keys into source/evidence.')
p.add_argument('--admission',required=True);p.add_argument('--run',required=True)
p.add_argument('--public-dir',type=pathlib.Path,required=True)
p.add_argument('--der-dir',type=pathlib.Path,required=True)
p.add_argument('--private-dir',type=pathlib.Path,required=True)
p.add_argument('--unix-time',type=int,required=True)
a=p.parse_args(sys.argv[2:]);admission=json.loads(pathlib.Path(a.admission).read_text())
require(admission.get('pki_generation_go') is True and admission.get('run')==a.run,
        'PKI generation remains held')
require(admission.get('pki_script_sha256')==sha(script),'reviewed PKI script differs')
require(os.geteuid()==0 and socket.gethostname()==admission.get('host_name') and
        re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',a.run) is not None and
        socket.gethostname()=='absd-s2-tls-'+a.run[:8],
        'PKI is restricted to the exact isolated fixture VM/run')
require(2020<=datetime.datetime.fromtimestamp(a.unix_time,datetime.timezone.utc).year<=2090,
        'validation anchor outside fixture range')
public=a.public_dir.resolve();private=a.private_dir.resolve();der=a.der_dir.resolve()
source=pathlib.Path(admission['source_root']).resolve()
require(source.is_dir() and (source/'.git').exists(),'exact implementation source root required')
require(der==source/'fixtures/native-tls/pki','public DER must use the declared generated source input directory')
require(private!=source and source not in private.parents and public!=source and source not in public.parents,
        'public/private PKI custody must stay outside the implementation worktree')
for key,value in [('public_dir',public),('private_dir',private),('der_dir',der)]:
    require(str(value)==admission.get(key),'PKI destination differs: '+key)
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+',str(value)),'unsupported PKI path characters')
require(private!=public and private not in public.parents and public not in private.parents and
        private!=der and private not in der.parents and der not in private.parents,'private/public custody overlaps')
require('private' in private.name and not private.exists(),'fresh explicit private directory required')
require(not public.exists(),'fresh public occurrence required')
private.mkdir(parents=False,mode=0o700);public.mkdir(parents=False,mode=0o700)
der.mkdir(parents=True,exist_ok=True)
require(not list(der.iterdir()),'generated DER directory is not empty; do not overwrite a prior fixture')
seal(public/'PRIVATE-PKI-LIFECYCLE.json',{'run':a.run,'time':now(),'owner':admission['owner'],
    'purpose':'TLS Linux fixture server and finite certificate controls only','private_directory':str(private),
    'account':'root on exact isolated VM','destinations':['10.0.2.2:4443 only'],
    'private_material_in_evidence':False,'intended_lifetime':'Until fixture consumers end, bounded by original VM lease',
    'retirement':'Delete exact private files after live consumers end; provider DELETE retires remaining VM volume. '
                 'Retain public chain/CSR/recipe hashes. Matching-key retirement may prevent exact root-pinned ELF replay.',
    'generated_objects':['root-A.key','root-B.key','root-C.key','leaf.key'],
    'protected_replay_custody':admission.get('protected_private_replay_custody','NONE; retire by default')})
commands=[]
def run(args,expected=0):
    result=subprocess.run(['/usr/bin/openssl',*args],capture_output=True,timeout=30)
    row={'time':now(),'argv':['/usr/bin/openssl',*args],'exit':result.returncode}
    for flag in ['-config','-extfile']:
        if flag in args:row[flag+'_input']=identity(args[args.index(flag)+1])
    commands.append(row)
    require(result.returncode==expected,'OpenSSL fixture command failed: '+str(args[:2])+' exit='+str(result.returncode))
    return result.stdout.decode(errors='replace'),result.stderr.decode(errors='replace')
def key(name):
    dest=private/(name+'.key')
    run(['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(dest)])
    os.chmod(dest,0o600)
def ski(cert,extension='subjectKeyIdentifier'):
    text,_=run(['x509','-in',str(cert),'-noout','-ext',extension])
    match=re.search(r'(?:[0-9A-Fa-f]{2}:){19}[0-9A-Fa-f]{2}',text)
    require(match is not None,'missing key identifier: '+extension)
    return match.group(0).upper()
roots={};configs={}
try:
    version,_=run(['version','-a'])
    for tag in ['A','B','C']:
        key('root-'+tag);subject='/CN=ABSD TLS Fixture Root '+('A' if tag=='C' else tag)
        csr=public/('root-'+tag+'.csr.pem');bootstrap=private/('bootstrap-'+tag+'.pem')
        run(['req','-new','-sha256','-key',str(private/('root-'+tag+'.key')),'-subj',subject,'-out',str(csr)])
        identifier=ski(roots['A']) if tag=='C' else 'hash'
        run(['req','-new','-x509','-sha256','-days','14','-key',str(private/('root-'+tag+'.key')),
             '-subj',subject,'-addext','basicConstraints=critical,CA:TRUE,pathlen:0',
             '-addext','keyUsage=critical,keyCertSign,cRLSign','-addext','subjectKeyIdentifier='+identifier,
             '-out',str(bootstrap)])
        db=private/('ca-'+tag);db.mkdir(mode=0o700);(db/'newcerts').mkdir(mode=0o700)
        (db/'index').write_text('');(db/'serial').write_text({'A':'1000','B':'2000','C':'3000'}[tag]+'\n')
        config=private/('ca-'+tag+'.cnf')
        def config_text(certificate):
            return ('[ca]\ndefault_ca=fixture\n[fixture]\ndatabase='+str(db/'index')+
                '\nnew_certs_dir='+str(db/'newcerts')+'\nserial='+str(db/'serial')+
                '\nprivate_key='+str(private/('root-'+tag+'.key'))+'\ncertificate='+str(certificate)+
                '\ndefault_md=sha256\ndefault_days=2\npolicy=policy\nunique_subject=no\ncopy_extensions=none\n'
                '[policy]\ncommonName=supplied\n[ca_ext]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n'
                'keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier='+identifier+
                '\nauthorityKeyIdentifier=keyid:always\n')
        config.write_text(config_text(bootstrap));root=public/('root-'+tag+'.pem')
        run(['ca','-batch','-selfsign','-notext','-config',str(config),'-extensions','ca_ext',
             '-in',str(csr),'-out',str(root),'-startdate',date_at(a.unix_time-7*86400),
             '-enddate',date_at(a.unix_time+7*86400)])
        config.write_text(config_text(root));roots[tag]=root;configs[tag]=config
    require(ski(roots['A'])==ski(roots['C']),'P02b CA key identifiers differ')
    subjects=[run(['x509','-in',str(roots[t]),'-noout','-subject','-nameopt','RFC2253'])[0] for t in ['A','C']]
    require(subjects[0]==subjects[1],'P02b issuer names differ')
    public_keys=[run(['x509','-in',str(roots[t]),'-noout','-pubkey'])[0] for t in ['A','C']]
    require(public_keys[0]!=public_keys[1],'P02b CA public keys are equal')
    key('leaf');leaves={}
    for mode,ca,name,start,end in [
        ('valid','A','absd-fixture.test',-86400,86400),
        ('untrusted','B','absd-fixture.test',-86400,86400),
        ('signature-failure','C','absd-fixture.test',-86400,86400),
        ('wrong-name','A','other.absd-fixture.test',-86400,86400),
        ('expired','A','absd-fixture.test',-2*86400,-86400),
        ('future','A','absd-fixture.test',86400,2*86400)]:
        csr=public/(mode+'.csr.pem');cert=public/(mode+'.pem');ext=public/(mode+'.ext.cnf')
        run(['req','-new','-sha256','-key',str(private/'leaf.key'),'-subj','/CN='+name,'-out',str(csr)])
        ext.write_text('[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
            'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:'+name+
            '\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
        run(['ca','-batch','-notext','-config',str(configs[ca]),'-extfile',str(ext),'-extensions','leaf',
             '-in',str(csr),'-out',str(cert),'-startdate',date_at(a.unix_time+start),'-enddate',date_at(a.unix_time+end)])
        leaves[mode]=cert
    require(ski(leaves['signature-failure'],'authorityKeyIdentifier')==ski(roots['A']),
            'P02b leaf AKI does not match trusted A')
    for name,cert in {**{'root-'+k:v for k,v in roots.items()},**leaves}.items():
        run(['x509','-in',str(cert),'-outform','DER','-out',str(der/(name+'.der'))])
        os.chmod(der/(name+'.der'),0o644)
    controls=[]
    expected_codes={'valid':0,'untrusted':20,'signature-failure':7,'wrong-name':62,'expired':10,'future':9}
    for mode,cert in leaves.items():
        args=['/usr/bin/openssl','verify','-CAfile',str(roots['A']),'-no-CApath','-no-CAstore',
              '-attime',str(a.unix_time),'-purpose','sslserver','-verify_hostname','absd-fixture.test',str(cert)]
        result=subprocess.run(args,capture_output=True,text=True,timeout=30)
        output=result.stdout+result.stderr;code=expected_codes[mode]
        require((result.returncode==0) if code==0 else
                (result.returncode!=0 and re.search(r'error '+str(code)+r' at 0 depth lookup:',output)),
                'independent certificate control has wrong reason: '+mode)
        controls.append({'mode':mode,'argv':args,'exit':result.returncode,'expected_verify_code':code,
                         'stdout':result.stdout,'stderr':result.stderr})
    rows=[]
    for cert in sorted(der.glob('*.der')):
        source=public/(cert.stem+'.pem')
        metadata,_=run(['x509','-in',str(source),'-noout','-serial','-subject','-issuer','-dates',
                        '-ext','subjectAltName,extendedKeyUsage,basicConstraints,subjectKeyIdentifier,authorityKeyIdentifier'])
        rows.append({**identity(cert),'metadata':metadata,'generated':True,'git_ignored':True})
    invalid=[]
    for name,data in [('empty-root.der',b''),('truncated-root.der',(der/'root-A.der').read_bytes()[:-1]),
                      ('truncated-leaf.der',(der/'valid.der').read_bytes()[:12]),
                      ('malformed-leaf.der',b'\x30\x82\xff\xffinvalid')]:
        target=der/name;target.write_bytes(data);os.chmod(target,0o644);invalid.append(identity(target))
    manifest={'schema_version':1,'run':a.run,'time':now(),'validation_unix_time':a.unix_time,
        'reference_name':'absd-fixture.test','root_der':identity(der/'root-A.der'),
        'public_certificates':rows,'invalid_public_inputs':invalid,
        'leaf_certificates':{k:identity(v) for k,v in leaves.items()},
        'leaf_private_key_path':str(private/'leaf.key'),'private_keys_in_evidence':False,
        'case_groups':32,'positive_client_close_notify_required':True,
        'openssl_version':version,'openssl_binary':identity('/usr/bin/openssl'),
        'generation_script':identity(script),'commands':commands,'independent_verifier_controls':controls,
        'public_recipe_files':[identity(x) for x in sorted(public.iterdir()) if x.is_file()],
        'private_fixture_key_retirement':'Delete exact private directory after consumers end; retain public recipe/chain/CSR metadata. '
            'No exact root-pinned live replay promised after private leaf-key retirement.',
        'build_inputs':{'ABSD_TLS_ROOT_DER':str(der/'root-A.der'),'ABSD_TLS_ROOT_SHA256':sha(der/'root-A.der')},
        'source_correspondence_limit':'Generated ignored DER is separately enumerated/hash-sealed; clean tracked Git state does not mean no generated inputs.'}
    seal(public/'PUBLIC-PKI.json',manifest)
except BaseException as error:
    seal(public/'PKI-FAIL.json',{'time':now(),'run':a.run,'error_type':type(error).__name__,
        'message':str(error),'commands':commands,'disposition':'FAIL','private_retirement_owner':admission['owner'],
        'next_action':'Known-ended setup failure: preserve public evidence; retire exact private objects after consumers end; do not overwrite/reclassify this occurrence.'})
    raise
print(json.dumps({'public_manifest':str(public/'PUBLIC-PKI.json'),
                  'root_der_sha256':sha(der/'root-A.der'),'private_material_logged':False}))
PY
