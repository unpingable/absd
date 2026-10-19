"""R23's explicit, non-stopping Cports replay contract; not a generic resetter."""
import contextlib
import io
import json
import time
import warm_baseline as wb

# Only these generated files may be removed. Input files and unknown effects
# are checked, never restored or silently deleted.
RESET = {'posix': ['l'], 'zlib-example': ['foo.gz'],
         'sqlite': ['t.db', 't.db-journal'],
         'sqlite-nomem': ['n.db', 'n.db-journal'],
         'speedtest': ['s5.db', 's5.db-journal', 'st.db', 'st.db-journal'],
         'excl': ['x.db', 'x.db-journal']}
EXCL = ['sqlite.excl-setup', 'sqlite.readonly', 'sqlite.excl-busy',
        'sqlite.excl-release', 'sqlite.excl-concurrency-loss']


def selected(m, module):
    canonical = {c.name: c for c in module.load_cases(m.repo / 'cports/cases.tsv')}
    chosen = []
    stopped = False
    for c in m.cases:
        if c.name in module.RESTART_ROUNDS:
            stopped = True
            continue
        wb.require(not stopped, 'non-stopping case after stopping case has no same-boot replay contract: '+c.name)
        original = canonical.get(c.name)
        wb.require(original is not None and vars(original) == vars(c),
                   'case has no exact Cports replay contract: '+c.name)
        chosen.append(c)
    names = [c.name for c in chosen]
    for chain in module.CHAINS:
        have = [n for n in chain['cases'] if n in names]
        if have:
            # Partial prefixes are meaningful; an index/rollback/vacuum alone is not.
            last = max(chain['cases'].index(n) for n in have)
            wb.require(have == chain['cases'][:last+1], 'missing ordered SQLite predecessor: '+str(have))
    for n in names:
        if n in module.REPEATABLE:
            other = module.REPEATABLE[n]
            wb.require(other in names, 'gzip/gunzip pair required for repeatable input: '+n)
            if 'gunzip' in n:
                wb.require(names.index(other) < names.index(n), 'gzip must precede gunzip: '+n)
        if n in EXCL:
            # readonly needs setup; deny needs two rows; later cases require deny's third row.
            need = EXCL[:EXCL.index(n)+1]
            wb.require([x for x in names if x in need] == need, 'missing ordered exclusive-lock predecessor: '+n)
    return chosen


def target_state(m, module):
    # Use the existing whole-system object inventory, which already excludes
    # only the four declared log files and boot recovery state. No CWD prefix
    # filter: unrelated file effects must never become an accepted initial state.
    # Serial numbers are implementation generations, not logical reset identity.
    return {o[0]: (o[1], o[2], o[4]) for o in m.t.system_objects()}


def linux_state(m):
    import hashlib
    root = m.work / 'linux'
    state = {}
    for p in root.rglob('*'):
        wb.require(not p.is_symlink(), 'unexpected reference symlink: '+str(p))
        state[str(p.relative_to(root))] = ('dir' if p.is_dir() else hashlib.sha256(p.read_bytes()).hexdigest(),
                                          p.stat().st_mode & 0o777)
    return state


class Rehearsal:
    def __init__(self, m, module):
        self.m, self.mod = m, module
        self.cases = selected(m, module)
        self.boot = m.t.boots
        self.target = target_state(m, module)
        self.linux = linux_state(m)
        self.generated = [(cwd, n) for cwd in {c.cwd for c in self.cases}
                          for n in RESET.get(cwd, [])]
        for cwd,name in self.generated:
            wb.require(f'{module.CPORTS}/{cwd}/{name}' not in self.target and
                       f'{cwd}/{name}' not in self.linux,
                       'declared generated file already exists in initial fixture: '+cwd+'/'+name)
        self.expected_shapes = ['reset-input-state', 'session-probes']
        warmed=False
        for c in self.cases:
            if c.route=='scenario' and not warmed:
                self.expected_shapes.append('frames-warmup');warmed=True
            self.expected_shapes.append(c.name)
        self.expected_shapes.append('alive')
        self.events = []
        self.baseline = wb.WarmBaseline(m.warm_capacity(), self.expected_shapes, self.emit)

    def emit(self, record):
        self.events.append(record)
        print('CPORTS WARM '+json.dumps(record, sort_keys=True), flush=True)

    def reset(self):
        m, mod = self.m, self.mod
        wb.require(m.t.boots == self.boot, 'reset cannot cross boot')
        for cwd, name in self.generated:
            guest = f'{mod.CPORTS}/{cwd}/{name}'
            obj = m.objects().get(guest)
            if obj is not None:
                wb.require(not obj[1], 'reset refuses generated directory: '+guest)
                rc,out,err,_,_ = m.shell_ssh(' '.join(mod.ck.quote(w) for w in ['/bin/rm', guest]))
                wb.require((rc,out,err)==(0,b'',b'') and guest not in m.objects(), 'target reset failed: '+guest)
            local = m.linux_dir(cwd)/name
            if local.exists() or local.is_symlink():
                wb.require(local.is_file() and not local.is_symlink(), 'reference reset refuses non-file: '+str(local))
                local.unlink()
        wb.require(target_state(m,mod)==self.target, 'target reset not equivalent: undeclared object/content/mode change')
        wb.require(linux_state(m)==self.linux, 'reference reset not equivalent: undeclared object/content/mode change')

    def group(self, attempt):
        m,mod=self.m,self.mod
        self.reset()
        original_work=m.work
        work=original_work/f'warm-rehearsal-{attempt}'
        work.mkdir(exist_ok=False)
        (work/'linux').symlink_to(original_work/'linux', target_is_directory=True)
        saved={k:getattr(m,k) for k in ['first','a17','a17_printed','steps']}
        old_warmed=getattr(m,'warmed',False);m.warmed=False
        m.first={};m.a17=dict.fromkeys(m.a17);m.a17_printed=False
        out=io.StringIO();shapes=['reset-input-state'];outcomes={}
        try:
            m.work=work
            with contextlib.redirect_stdout(out):
                m.session_probes();shapes.append('session-probes')
                for c in self.cases:
                    if c.name=='sqlite.speedtest1-20' and m.speedtest_limit:
                        # The workload remains in the explicit inventory; no execution claimed.
                        outcomes[c.name]='NOT_RUN_IMAGE_CAPACITY';shapes.append(c.name);continue
                    if c.route=='probe':
                        rc,data,err,_,pids=m.shell_ssh(m.text(c),timeout=c.timeout)
                        m.check(c.name+' rehearsal probe',rc==0 and err==b'' and len(pids)==1)
                        if c.name=='probe.env':m.check('empty session environment',not any('=' in x for x in data.decode().splitlines()))
                    elif c.route=='scenario':
                        if not m.warmed:
                            m.frames_warmup(rehearsal=True);shapes.append('frames-warmup')
                        method=getattr(m,'scenario_'+c.program.replace('-','_'),None)
                        wb.require(method is not None,'no scenario replay method: '+c.name)
                        method(c)
                    else:
                        try:got,ref=m.run_shell_case(c)
                        except mod.SessionTimeout as e:
                            m.keep_timeout(c,e)
                            wb.require(c.name in mod.LIMIT_ON_TIMEOUT,'timeout has no repeatable LIMIT contract: '+c.name)
                            deadline=time.monotonic()+120
                            while m.t.all_images()!=0 and time.monotonic()<deadline:time.sleep(.5)
                            wb.require(m.t.all_images()==0,'LIMIT session not reclaimed: '+c.name)
                            outcomes[c.name]='LIMIT_TIMEOUT';shapes.append(c.name);continue
                        if c.name in mod.INTEGRITY:m.integrity(c)
                        verdict=m.judge(c,got,ref)
                        if c.outputs:m.check_outputs(c)
                        if c.program=='/bin/speedtest1' and verdict=='agree':m.verify_line(c,got)
                        if c.program=='/bin/lua' and 'all.lua' in c.args:m.check_lua(c,m.normalized(c,got),m.normalized(c,ref))
                    outcomes[c.name]='EXECUTED';shapes.append(c.name)
                m.alive('Cports rehearsal');shapes.append('alive')
        finally:
            m.work=original_work
            for k,v in saved.items():setattr(m,k,v)
            m.warmed=old_warmed
            (work/'transcript.log').write_text(out.getvalue())
            (work/'outcomes.json').write_text(json.dumps(outcomes,indent=2))
            for line in out.getvalue().splitlines():print(f'CPORTS REHEARSAL {attempt} {line}',flush=True)
        # Preserve end state. The next group begins with the SAME reset action.
        # A LIMIT counts only after its exact reset was independently demonstrated
        # at the next boundary; final establishment performs that measured reset.
        self.final_target = target_state(m, mod)
        self.final_linux = linux_state(m)
        return shapes

    def establish(self):
        try:
            self.baseline.establish(self.group,self.m.warm_capacity)
            # Actual measured-group prerequisite, identical declared action.
            self.reset()
        except (wb.BaselineError, self.mod.sm.Failed, self.mod.ck.sm.Failed) as e:
            self.emit({'phase':'coverage','state':'NOT_ESTABLISHED','reason':str(e),
                       'correctness':'No measured result inferred; unsafe state is not reused'})
            raise
        # The next action is the actual measured group's explicit reset. If it
        # fails, no measured case runs on an unestablished prerequisite state.
        self.emit({'phase':'measured-prerequisite','shape':'reset-input-state','state':'VERIFIED'})
        self.emit({'phase':'coverage','state':'ESTABLISHED_NONSTOPPING',
                   'stopping_cases':'NOT_ESTABLISHED','R23':'PARTIAL',
                   'image_capacity_exclusions':['sqlite.speedtest1-20'] if self.m.speedtest_limit else []})

    def finish(self):
        # No final reset: the stopping scenarios need the measured x.db state.
        if self.m.t.boots != self.boot:
            self.emit({'phase':'post-warm','state':'NOT_ESTABLISHED','reason':'boot changed'})
            return
        if (target_state(self.m,self.mod) != self.final_target or
                linux_state(self.m) != self.final_linux):
            self.emit({'phase':'post-warm','state':'NOT_ESTABLISHED',
                       'reason':'logical end files differ from rehearsal; no generated-file exemption',
                       'correctness':'Existing measured checks retain their independent result'})
            return
        self.baseline.measured_group(self.m.warm_capacity())
        self.emit({'phase':'post-warm','state':'ESTABLISHED','file_correspondence':'exact names/kinds/modes/content; serial generations excluded'})
