import pathlib,tempfile,subprocess,os,json,shutil
HERE=pathlib.Path(__file__).parent
rows=[]
with tempfile.TemporaryDirectory(prefix="composition-shell-controls-") as td:
 base=pathlib.Path(td)
 def fixture(name):
  r=base/name.replace(" ","_");w=r/"platform";g=r/"run";bin=r/"bin"
  for d in [w/"scripts",g/"logs",g/"tools",g/"work/KA",bin,w/".fence-work/resume-releases/dev"]:d.mkdir(parents=True,exist_ok=True)
  (w/".fence-work/resume-releases/dev/item").write_text("original")
  def sh(p,s):p.write_text("#!/bin/sh\n"+s+"\n");p.chmod(0o755)
  sh(bin/"python3",'case " $* " in *c7.py*) [ "${MOCK_C7_FAIL:-0}" = 0 ] || exit 8;; esac; echo local-stub; exit "${MOCK_DIRECT_FAIL:-0}"')
  sh(bin/"taskset",'shift 2; exec "$@"');sh(bin/"nice",'shift 2; exec "$@"');sh(bin/"git",'[ "${MOCK_ARCHIVE_FAIL:-0}" = 0 ] || exit 1; echo local-source')
  sh(bin/"cp",'/bin/cp "$@" || exit $?; if [ "${MOCK_COPY_MISMATCH:-0}" = 1 ]; then echo changed >> "$ABSD_COMPOSITION_RUN_ROOT/work/A/item"; fi')
  sh(g/"tools/gate.sh",'echo called >> "$ABSD_COMPOSITION_RUN_ROOT/logs/census-calls"; if [ "$1" = --list ]; then [ "${MOCK_LIST_FAIL:-0}" = 0 ] || exit 3; [ "${MOCK_LEFTOVER:-0}" = 0 ] || echo "other local-fixture"; exit 0; fi; exit "${MOCK_GATE_FAIL:-0}"')
  for n in ['cases.sh','regress.sh','f2.sh']:sh(g/"tools"/n,'exit "${MOCK_PREREQ_FAIL:-0}"')
  (r/"media-status").write_text("PASS")
  e=dict(os.environ,PATH=str(bin)+":"+os.environ['PATH'],ABSD_COMPOSITION_PLATFORM=str(w),ABSD_COMPOSITION_RUN_ROOT=str(g),ABSD_COMPOSITION_RUN='fixture',ABSD_COMPOSITION_KEY=str(r/"unused-key"),ABSD_COMPOSITION_MEDIA_STATUS=str(r/"media-status"))
  return r,w,g,e
 def run(name,script,args=(),flags=None,existing=False,expect=1,media="PASS",missing_media=False):
  r,w,g,e=fixture(name);e.update(flags or {})
  (r/"media-status").write_text(media)
  if missing_media: (r/"media-status").unlink()
  if existing:(w/".fence-work/resume-runs-fixture/m1").mkdir(parents=True)
  z=subprocess.run(['sh',str(HERE/script),*args],env=e,capture_output=True,text=True)
  assert (z.returncode!=0)==bool(expect),(name,z.returncode,z.stderr)
  if flags and ('MOCK_C7_FAIL' in flags or 'MOCK_DIRECT_FAIL' in flags) and script in ('cases.sh','regress.sh'):
   assert (g/'logs/census-calls').read_text().count('called') >= 2, name
  if script == 'cases.sh' and flags and 'MOCK_DIRECT_FAIL' in flags:
   assert 'rc=9' in (g/'logs/cases.log').read_text()
  rows.append(dict(case=name,wrapper=script,rc=z.returncode,expected='nonzero' if expect else 'zero',stderr=z.stderr))
 for flags,label in [({'MOCK_GATE_FAIL':'1'},'gate refusal'),({'MOCK_DIRECT_FAIL':'9'},'direct failure'),({'MOCK_LEFTOVER':'1'},'leftover'),({'MOCK_LIST_FAIL':'3'},'census failure')]:
  run('cases '+label,'cases.sh',['m1'],flags)
 run('cases existing work','cases.sh',['m1'],existing=True)
 run('cases success','cases.sh',['m1'],expect=0)
 for flags,label in [({'MOCK_GATE_FAIL':'1'},'gate refusal'),({'MOCK_DIRECT_FAIL':'9'},'direct failure'),({'MOCK_LEFTOVER':'1'},'leftover'),({'MOCK_LIST_FAIL':'3'},'census failure')]:
  run('regress '+label,'regress.sh',['updates'],flags)
 run('regress success','regress.sh',['updates'],expect=0)
 for flags,label in [({'MOCK_GATE_FAIL':'1'},'C7 gate refusal'),({'MOCK_COPY_MISMATCH':'1'},'copy mismatch'),({'MOCK_C7_FAIL':'8'},'C7 direct failure'),({'MOCK_DIRECT_FAIL':'9'},'direct failure'),({'MOCK_LEFTOVER':'1'},'C7 leftover'),({'MOCK_LIST_FAIL':'3'},'C7 census failure')]:
  run('must '+label,'must.sh',flags=flags)
 run('must success','must.sh',expect=0)
 run('must prerequisite failure','must.sh',flags={'MOCK_PREREQ_FAIL':'9'})
 run('should success','should.sh',expect=0)
 run('cases unknown','cases.sh',['m1x'])
 run('regress archive failure','regress.sh',['ghost-ata'],flags={'ABSD_COMPOSITION_F3_REF':'fixture','MOCK_ARCHIVE_FAIL':'1'})
 run('regress extraction failure','regress.sh',['ghost-ata'],flags={'ABSD_COMPOSITION_F3_REF':'fixture'})
 run('cases empty','cases.sh')
 run('regress empty','regress.sh')
 run('regress unknown','regress.sh',['unknown'])
 run('must media missing','must.sh',missing_media=True)
 run('must media fail','must.sh',media='FAIL')
 run('must media prefix','must.sh',media='PASS extra')
 run('should direct failure','should.sh',flags={'MOCK_PREREQ_FAIL':'9'})
 # Exercise the real F2 wrapper with local commands and records, including negative controls.
 for label,flags,expected in [('success',{},0),('command failure',{'MOCK_F2_FAIL':'1'},1),('gate refusal',{'MOCK_GATE_FAIL':'1'},1),('leftover',{'MOCK_LEFTOVER':'1'},1),('census failure',{'MOCK_LIST_FAIL':'1'},1),('negative unexpectedly succeeds',{'MOCK_NEG_SUCCESS':'1'},1)]:
  r,w,g,e=fixture('f2 '+label);e.update(flags)
  sh= lambda p,t: (p.write_text('#!/bin/sh\n'+t+'\n'),p.chmod(0o755))
  for d in [g/'work/A',g/'work/OUT/releases/dev',g/'work/OUT/recovery']: d.mkdir(parents=True,exist_ok=True)
  for p in [g/'work/A/absd-operator.iso',g/'work/OUT/absd-operator.iso',g/'work/OUT/releases/dev/absd-operator.iso']:p.write_text('iso')
  for name in ('TARGET','RELEASES','MANIFEST'): (g/'work/OUT'/name).write_text(name)
  (g/'logs/load-gate.log').write_text("local gate\n")
  (g/'work/OUT/console-accept-dev.log').write_text('RELEASE OK\n')
  sh(r/'bin/python3', '''case " $* " in
   *NC-*) echo "guard=clean selected='dev'"; exit 0;;
   *NC1-none*|*NC2-target*|*NC3-releases*|*NC1-rel*) [ "${MOCK_NEG_SUCCESS:-0}" = 0 ] && exit 1; exit 0;;
   *snapshot.py*) echo "guard=clean selected='dev'";;
  esac
  exit "${MOCK_F2_FAIL:-0}"''')
  (w/'scripts/build-operator-image.sh').write_text('#!/bin/sh\nexit "${MOCK_NEG_SUCCESS:-1}"\n')
  (w/'scripts/build-operator-image.sh').chmod(0o755)
  z=subprocess.run(['sh',str(HERE/'f2.sh')],env=e,capture_output=True,text=True)
  assert (z.returncode!=0)==bool(expected),(label,z.returncode,z.stderr,(g/'logs/f2-steps.log').read_text())
  rows.append(dict(case='f2 '+label,wrapper='f2.sh',rc=z.returncode,expected='nonzero' if expected else 'zero'))
 print(json.dumps(dict(controls=rows,count=len(rows),all_expected=True,no_guest=True),indent=2))
