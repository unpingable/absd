use super::*;
use std::collections::BTreeMap;

#[test]
fn resolves_lexically() {
    assert_eq!(resolve("/", "bin"), "/bin");
    assert_eq!(resolve("/bin", ".."), "/");
    assert_eq!(resolve("/", "../.."), "/");
    assert_eq!(resolve("/a/b", "./c//d/../e"), "/a/b/c/e");
    assert_eq!(resolve("/a", "/x/./y/"), "/x/y");
    assert_eq!(program_path("/a", "ls"), "/bin/ls");
    assert_eq!(program_path("/a", "./tool"), "/a/tool");
    assert_eq!(program_path("/a", "/bin/cat"), "/bin/cat");
}

#[test]
fn all_processes_uses_shipped_program_with_pipe_and_redirect_support() {
    let (_, _, shell) = run(Mode::Interactive, "ps -A\nps -A | cat\nps -A <<EOF\nignored\nEOF\n");
    assert_eq!(shell.host.runs.iter().filter(|(name, _, _)| name == "/bin/ps").count(), 3);
    assert!(shell.host.asked.is_empty(), "machine census must not reuse SSH session-only listing");

    let mut shell = Shell::new(fake(), "/".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    session(&mut shell, Mode::Interactive, &mut b"ps <<EOF\nignored\nEOF\n".as_slice(), &mut out, &mut err);
    assert_eq!(err, b"absd-sh: heredocs require a native consuming command\n");
    assert!(shell.host.runs.is_empty(), "argument-free ps remains a builtin");
    assert!(shell.host.asked.is_empty(), "refused heredoc must not reach session control");
}

#[test]
fn parses_shell_arguments() {
    let s = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(parse_args(&[]), Ok(Mode::Interactive));
    assert_eq!(parse_args(&s(&["-c", "ls /"])), Ok(Mode::Command("ls /".into())));
    assert!(parse_args(&s(&["-c"])).is_err());
    assert!(parse_args(&s(&["-x", "y"])).is_err());
}

/// A fake platform: programs by path with a fixed result; directories;
/// files the shell may read, and whether it may write.
struct Fake {
    programs: BTreeMap<String, io::Result<Exit>>,
    dirs: Vec<String>,
    files: BTreeMap<String, Vec<u8>>,
    writable: bool,
    /// Program, arguments, working directory of every started stage.
    runs: Vec<(String, Vec<String>, String)>,
    /// Each pipeline's plan: one line per stage.
    plans: Vec<Vec<String>>,
    /// Files the shell opened, in order (`r path` / `w path` / `a path`).
    opened: Vec<String>,
    /// The filesystem authority each started stage was given.
    authorities: Vec<Authority>,
    /// What a started stage writes to a file its stdout was redirected to.
    written: std::rc::Rc<std::cell::RefCell<BTreeMap<String, Vec<u8>>>>,
    /// The session's answers, in order; `None`: no control channel.
    answers: Option<Vec<(i32, String)>>,
    /// What the shell asked the session.
    asked: Vec<String>,
    /// Whole lines the interactive loop reported read.
    lines: u64,
    prompt_modes: Vec<u8>,
    prompt_mode: bool,
    terminal_shape: Option<(u32,u32)>,
    cancel_on_line: Option<u64>,
    cancel_on_next_program_ack: bool,
    ack_cancel_pending: bool,
    /// The session ended while a pipeline ran (`/bin/ended`).
    ended: bool,
}

/// A file the fake opened for writing.
struct FakeSink {
    path: String,
    written: std::rc::Rc<std::cell::RefCell<BTreeMap<String, Vec<u8>>>>,
}

impl Write for FakeSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.borrow_mut().entry(self.path.clone()).or_default().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Host for Fake {
    type Source = io::Cursor<Vec<u8>>;
    type Sink = FakeSink;

    fn open_read(&mut self, path: &str) -> io::Result<Self::Source> {
        self.opened.push(format!("r {path}"));
        if self.dirs.iter().any(|d| d == path) {
            return Err(io::ErrorKind::IsADirectory.into());
        }
        match self.files.get(path) {
            Some(bytes) => Ok(io::Cursor::new(bytes.clone())),
            None => Err(io::ErrorKind::NotFound.into()),
        }
    }

    fn open_write(&mut self, path: &str, append: bool) -> io::Result<Self::Sink> {
        self.opened.push(format!("{} {path}", if append { "a" } else { "w" }));
        if !self.writable {
            return Err(io::ErrorKind::ReadOnlyFilesystem.into());
        }
        let mut written = self.written.borrow_mut();
        let file = written.entry(path.to_string()).or_insert_with(|| {
            self.files.get(path).cloned().unwrap_or_default()
        });
        if !append {
            file.clear();
        }
        Ok(FakeSink { path: path.into(), written: self.written.clone() })
    }

    fn run(&mut self, stages: Vec<Stage<Self::Source, Self::Sink>>) -> Vec<Ran> {
        assert!(!self.prompt_mode, "native programs must not run in prompt/history mode");
        assert_eq!(self.prompt_modes.last().copied().unwrap_or(0), 0,
            "a disarmed read fence is not program mode");
        let mut plan = Vec::new();
        let mut results = Vec::new();
        for stage in stages {
            self.runs.push((stage.program.clone(), stage.args.clone(), stage.cwd.clone()));
            self.authorities.push(stage.authority);
            let stdin = match &stage.stdin {
                Input::Inherit => "inherit".to_string(),
                Input::Previous => "previous".to_string(),
                Input::Bytes(bytes) => format!("bytes:{}", String::from_utf8_lossy(bytes).escape_debug()),
                Input::File(source) => {
                    format!("file:{}", String::from_utf8_lossy(source.get_ref()).escape_debug())
                }
            };
            if let Input::Inherit = stage.stdin && stage.program.starts_with("/bin/head") { dv::child_reads(&stage.program); }
            if stage.program == "/bin/ended" {
                self.ended = true;
            }
            let exit = match self.programs.get(&stage.program) {
                Some(Ok(exit)) => Ok(*exit),
                Some(Err(e)) => Err(io::Error::new(e.kind(), e.to_string())),
                None => Err(io::ErrorKind::NotFound.into()),
            };
            let mut outputs = Vec::new();
            for (stream, output) in [("stdout", stage.stdout), ("stderr", stage.stderr)] {
                outputs.push(match output {
                    Output::Inherit => "inherit".to_string(),
                    Output::Next => "next".to_string(),
                    Output::ParentStdout => "parent-stdout".to_string(),
                    Output::ParentStderr => "parent-stderr".to_string(),
                    Output::SameAsStdout => "same-as-stdout".to_string(),
                    Output::Discard => "discard".to_string(),
                    Output::Shared(mut sink) => {
                        let path = sink.0.borrow().path.clone();
                        if exit.is_ok() { let _ = writeln!(sink, "{stream} of {}", stage.program); }
                        format!("file:{path}")
                    },
                    Output::Capture(_) => "capture".to_string(),

                });
            }
            plan.push(format!(
                "{} in={stdin} out={} err={}",
                stage.program, outputs[0], outputs[1]
            ));
            results.push(Ran { exit, redirect: None });
        }
        self.plans.push(plan);
        results
    }

    fn is_dir(&mut self, path: &str) -> io::Result<bool> {
        if self.dirs.iter().any(|d| d == path) {
            Ok(true)
        } else if self.programs.contains_key(path) || self.files.contains_key(path) {
            Ok(false)
        } else {
            Err(io::ErrorKind::NotFound.into())
        }
    }

    fn session_request(&mut self, request: SessionRequest) -> io::Result<(i32, String)> {
        self.asked.push(format!("{request:?}"));
        match self.answers.as_mut() {
            None => Err(io::ErrorKind::Unsupported.into()),
            Some(answers) if answers.is_empty() => Err(io::Error::other("the session ended")),
            Some(answers) => Ok(answers.remove(0)),
        }
    }

    fn prompt_input(&mut self, mode: u8) { if dv::active() { dv::on_mode(mode); } else { rv::on_mode(mode); }
        self.prompt_mode = matches!(mode, 1 | 2);
        self.prompt_modes.push(mode);
        if mode == 0 && std::mem::take(&mut self.cancel_on_next_program_ack) {
            self.ack_cancel_pending = true;
        }
    }
    fn discard_pending_input(&mut self) { if dv::active() { dv::discard(); } else { rv::discard(); } }
    fn refuse_interactive_input(&mut self) -> bool { if dv::active() { dv::on_mode(4); true } else { false } }
    fn read_interactive(&mut self, input: &mut dyn io::BufRead, text: &mut String) -> io::Result<usize> { if dv::active() { super::read_interactive_record(input, text) } else { rv::read(input, text) } }
    fn terminal_size(&self) -> Option<(u32,u32)> { self.terminal_shape }
    fn prompt_cancelled(&mut self) -> bool { if dv::active() { return dv::take_latch(); }
        if rv::on_cancel() { return true; }
        std::mem::take(&mut self.ack_cancel_pending)
            || self.cancel_on_line.take_if(|line| *line == self.lines).is_some()
    }

    fn line_read(&mut self) { if dv::active() { dv::drain_events(); } rv::on_line();
        self.lines += 1;
    }

    fn ended(&self) -> bool {
        self.ended
    }
}

fn fake() -> Fake {
    let mut programs = BTreeMap::new();
    programs.insert("/bin/ls".to_string(), Ok(Exit::Code(0)));
    programs.insert("/bin/cat".to_string(), Ok(Exit::Code(0)));
    programs.insert("/bin/fail".to_string(), Ok(Exit::Code(1)));
    programs.insert("/bin/false".to_string(), Ok(Exit::Code(1)));
    programs.insert("/bin/crash".to_string(), Ok(Exit::Other));
    programs.insert("/bin/hang".to_string(), Ok(Exit::Interrupted));
    // Its run ends the session (the server's End while it runs).
    programs.insert("/bin/ended".to_string(), Ok(Exit::Interrupted));
    programs.insert(
        "/bin/nospawn".to_string(),
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "ABSD I/O syscall failed")),
    );
    programs.insert(
        "/bin/junk".to_string(),
        Err(io::Error::new(io::ErrorKind::InvalidData, "not executable")),
    );
    let mut files = BTreeMap::new();
    files.insert("/etc/motd".to_string(), b"Welcome\n".to_vec());
    Fake {
        programs,
        dirs: vec!["/".into(), "/bin".into(), "/tmp".into(), "/etc".into()],
        files,
        writable: false,
        runs: Vec::new(),
        plans: Vec::new(),
        opened: Vec::new(),
        authorities: Vec::new(),
        written: Default::default(),
        answers: None,
        asked: Vec::new(),
        lines: 0,
        prompt_modes: Vec::new(),
        prompt_mode: false,
        terminal_shape: None,
        cancel_on_line: None,
        cancel_on_next_program_ack: false,
        ack_cancel_pending: false,
        ended: false,
    }
}

fn run(mode: Mode, input: &str) -> (i32, String, Shell<Fake>) {
    let mut shell = Shell::new(fake(), "/".into());
    let mut out = Vec::new();
    let mut err = Vec::new();
    // Interleave both streams as one console would, via a shared buffer.
    let status = {
        let mut console = Console(&mut out);
        let mut console_err = Console(&mut err);
        session(&mut shell, mode, &mut input.as_bytes(), &mut console, &mut console_err)
    };
    let _ = err;
    (status, String::from_utf8(out).unwrap(), shell)
}

struct Console<'a>(&'a mut Vec<u8>);
impl Write for Console<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Both streams into one buffer, in write order.
fn console(mode: Mode, input: &str) -> (i32, String, Shell<Fake>) {
    let mut shell = Shell::new(fake(), "/".into());
    let shared = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    struct Shared(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let status = session(
        &mut shell,
        mode,
        &mut input.as_bytes(),
        &mut Shared(shared.clone()),
        &mut Shared(shared.clone()),
    );
    let text = String::from_utf8(shared.borrow().clone()).unwrap();
    (status, text, shell)
}

#[test]
fn scripted_session() {
    let input = "pwd\ncd /bin\npwd\nls\nls -l \"a b\"\necho hi  there\nnosuch\nfalse\nstatus\n\
                 junk\ncrash\ncd nowhere\ncd ls\ncd ..\npwd\n\nexit 3\necho unreachable\n";
    let (status, text, shell) = console(Mode::Interactive, input);
    assert_eq!(status, 3);
    assert_eq!(
        text,
        "absd$ /\n\
         absd$ absd$ /bin\n\
         absd$ absd$ absd$ hi there\n\
         absd$ absd-sh: nosuch: not found\n\
         absd$ \
         absd$ 1\n\
         absd$ absd-sh: junk: cannot run: not executable\n\
         absd$ absd-sh: crash: ended abnormally\n\
         absd$ absd-sh: cd: nowhere: not found\n\
         absd$ absd-sh: cd: ls: not a directory\n\
         absd$ absd$ /\n\
         absd$ absd$ "
    );
    assert_eq!(
        shell.host.runs,
        [
            ("/bin/ls".into(), vec![], "/bin".into()),
            ("/bin/ls".into(), vec!["-l".to_string(), "a b".to_string()], "/bin".into()),
            ("/bin/nosuch".into(), vec![], "/bin".into()),
            ("/bin/junk".into(), vec![], "/bin".into()),
            ("/bin/crash".into(), vec![], "/bin".into()),
        ]
    );
}

#[test]
fn statuses_and_eof() {
    assert_eq!(console(Mode::Interactive, "").0, 0);
    assert_eq!(console(Mode::Interactive, "false\n").0, 1);
    assert_eq!(console(Mode::Interactive, "false").0, 1, "last line without newline runs");
    assert_eq!(console(Mode::Interactive, "nosuch\n").0, STATUS_NOT_FOUND);
    assert_eq!(console(Mode::Interactive, "junk\n").0, STATUS_REFUSED);
    assert_eq!(console(Mode::Interactive, "false\nexit\n").0, 1);
    let (status, text, _) = console(Mode::Interactive, "exit x\nexit 1 2\nstatus\n");
    assert_eq!(status, 0, "status itself succeeds");
    assert_eq!(
        text,
        "absd$ absd-sh: exit: x: not a number\nabsd$ absd-sh: exit: too many arguments\n\
         absd$ 2\nabsd$ "
    );
    let (status, text, _) = console(Mode::Interactive, "echo \"open\nstatus\n");
    assert_eq!((status, text.as_str()), (2, "absd$ > > absd-sh: unmatched `\"` starting on line 1:6\n"));
}

#[test]
fn command_mode() {
    let (status, text, shell) = console(Mode::Command("ls /".into()), "ignored\n");
    assert_eq!((status, text.as_str()), (0, ""));
    assert_eq!(shell.host.runs, [("/bin/ls".into(), vec!["/".to_string()], "/".into())]);
    assert_eq!(console(Mode::Command("false".into()), "").0, 1);
    assert_eq!(console(Mode::Command("exit 7".into()), "").0, 7);
    assert_eq!(console(Mode::Command("echo a \"b  c\"".into()), "").1, "a b  c\n");
    assert_eq!(console(Mode::Command("cd /tmp".into()), "").2.cwd, "/tmp");
}

#[test]
fn cd_defaults_to_root_and_rejects_extra_arguments() {
    let (_, text, shell) = console(Mode::Interactive, "cd bin\ncd\npwd\ncd a b\n");
    assert_eq!(text, "absd$ absd$ absd$ /\nabsd$ absd-sh: cd: too many arguments\nabsd$ ");
    assert_eq!(shell.cwd, "/");
}

#[test]
fn separate_streams_keep_diagnostics_off_stdout() {
    let (_, out, _) = run(Mode::Interactive, "nosuch\necho ok\n");
    assert_eq!(out, "absd$ absd$ ok\nabsd$ ");
}

#[test]
fn lists_run_in_order_as_their_joins_allow() {
    let (status, text, shell) = console(
        Mode::Interactive,
        "ls && echo yes || echo no\nfalse && echo yes || echo no\nfalse ; echo after ; status\n\
         ls || echo skipped && echo chained\ncd /etc && pwd\nfalse && cd /\npwd\n",
    );
    assert_eq!(status, 0);
    assert_eq!(
        text,
        "absd$ yes\nabsd$ no\nabsd$ after\n0\n\
         absd$ chained\nabsd$ /etc\nabsd$ absd$ /etc\nabsd$ "
    );
    assert_eq!(shell.cwd, "/etc");
    let (status, text, _) = console(Mode::Interactive, "exit 4 ; echo unreachable\n");
    assert_eq!((status, text.as_str()), (4, "absd$ "));
    let (status, text, _) = console(Mode::Interactive, "nosuch ; status\nls ;; ls\nls &\nstatus\n");
    assert_eq!(status, 0);
    assert_eq!(
        text,
        "absd$ absd-sh: nosuch: not found\n127\nabsd$ absd-sh: found unexpected token on line 1:4: ;;\n\
         absd$ absd-sh: background jobs are not supported\nabsd$ 2\nabsd$ "
    );
    // An interrupted pipeline ends the list, whichever stage ^C ended;
    // so does the session's end.
    let (status, text, _) = console(Mode::Interactive, "hang ; echo not-run\nstatus\n");
    assert_eq!((status, text.as_str()), (0, "absd$ absd$ 130\nabsd$ "));
    let (_, text, _) = console(Mode::Interactive, "hang | ls ; echo not-run\nstatus\n");
    assert_eq!(text, "absd$ absd$ 0\nabsd$ ");
    let (status, text, shell) = console(Mode::Interactive, "ended && echo not-run\necho not-read\n");
    assert_eq!((status, text.as_str(), shell.host.ended), (STATUS_INTERRUPTED, "absd$ ", true));
}

#[test]
fn echo_n_and_help() {
    let (_, text, _) = console(Mode::Interactive, "echo -n a b\necho -n\necho x -n\nhelp | cat\n");
    assert_eq!(text, "absd$ a babsd$ absd$ x -n\nabsd$ absd$ ");
    let (status, text, _) = console(Mode::Command("help".into()), "");
    assert_eq!((status, text.as_str()), (0, HELP));
    assert!(HELP.lines().all(|l| l.len() <= 80) && HELP.ends_with('\n') && HELP.contains("builtins:"));
}

#[test]
fn pipeline_plans_connect_neighbours_and_report_the_last_status() {
    let (status, text, shell) = console(Mode::Interactive, "ls -l | cat | fail\nstatus\n");
    assert_eq!(status, 0);
    assert_eq!(text, "absd$ absd-sh: fail: exit status 1\nabsd$ 1\nabsd$ ");
    assert_eq!(
        shell.host.plans,
        [vec![
            "/bin/ls in=inherit out=next err=inherit".to_string(),
            "/bin/cat in=previous out=next err=inherit".to_string(),
            "/bin/fail in=previous out=inherit err=inherit".to_string(),
        ]]
    );
    // Only the last command's status counts; earlier failures are named
    // only when they could not start.
    let (_, text, _) = console(Mode::Interactive, "fail | cat\nstatus\nnosuch | cat\nstatus\ncat | nosuch\nstatus\n");
    assert_eq!(
        text,
        "absd$ absd$ 0\n\
         absd$ absd-sh: nosuch: not found\nabsd$ 0\n\
         absd$ absd-sh: nosuch: not found\nabsd$ 127\nabsd$ "
    );
}

#[test]
fn a_builtin_heads_a_pipeline_with_its_output() {
    let (_, text, shell) = console(Mode::Interactive, "echo hello | cat\ncd /etc\npwd | cat\n");
    assert_eq!(text, "absd$ absd$ absd$ absd$ ");
    assert_eq!(
        shell.host.plans,
        [
            vec!["/bin/cat in=bytes:hello\\n out=inherit err=inherit".to_string()],
            vec!["/bin/cat in=bytes:/etc\\n out=inherit err=inherit".to_string()],
        ]
    );
    let (_, text, shell) = console(
        Mode::Interactive,
        "ls | echo x\ncd / | cat\nls | exit\necho a < /etc/motd | cat\nstatus\n",
    );
    assert_eq!(
        text,
        "absd$ absd-sh: echo: a builtin can only start a pipeline\n\
         absd$ absd-sh: cd: cannot run in a pipeline\n\
         absd$ absd-sh: exit: cannot run in a pipeline\n\
         absd$ absd-sh: echo: a builtin in a pipeline takes no redirection\n\
         absd$ 2\nabsd$ "
    );
    assert!(shell.host.runs.is_empty(), "nothing starts for a refused line");
}

#[test]
fn input_redirection_is_opened_by_the_shell_and_fed_through_a_pipe() {
    let (_, text, shell) = console(Mode::Interactive, "cd /etc\ncat < motd | cat\ncat < /nosuch\nstatus\ncat < /tmp\n");
    assert_eq!(
        text,
        "absd$ absd$ absd$ absd-sh: /nosuch: not found\nabsd$ 1\nabsd$ absd-sh: /tmp: is a directory\nabsd$ "
    );
    assert_eq!(shell.host.opened, ["r /etc/motd", "r /nosuch", "r /tmp"]);
    // The child is planned with the file's bytes arriving through a pipe
    // the shell writes, never the file itself.
    assert_eq!(
        shell.host.plans,
        [vec![
            "/bin/cat in=file:Welcome\\n out=next err=inherit".to_string(),
            "/bin/cat in=previous out=inherit err=inherit".to_string(),
        ]]
    );
}

#[test]
fn output_redirection_is_refused_honestly_on_a_read_only_view() {
    let (_, text, shell) = console(
        Mode::Interactive,
        "echo x > /tmp/out\nstatus\nls >> /tmp/out\nls 2> /tmp/err\nls | cat > out\n",
    );
    let refusal = |p: &str| format!("absd-sh: {p}: cannot write: read-only here\n");
    assert_eq!(
        text,
        format!(
            "absd$ {}absd$ 1\nabsd$ {}absd$ {}absd$ {}absd$ ",
            refusal("/tmp/out"),
            refusal("/tmp/out"),
            refusal("/tmp/err"),
            refusal("/out")
        )
    );
    assert!(shell.host.runs.is_empty(), "nothing starts when a redirection cannot open");
    assert_eq!(shell.host.opened, ["w /tmp/out", "a /tmp/out", "w /tmp/err", "w /out"]);
}

#[test]
fn output_redirection_with_write_authority_goes_through_the_shell() {
    let mut host = fake();
    host.writable = true;
    let mut shell = Shell::new(host, "/tmp".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    for line in ["ls > a", "echo one > b", "echo two >> b", "ls | cat >> b 2> e", "pwd 2> c"] {
        shell.run_line(line, &mut out, &mut err);
    }
    // A lone builtin's stdout stays the terminal when only stderr moves.
    assert_eq!(String::from_utf8(out).unwrap(), "/tmp\n");
    assert_eq!(String::from_utf8(err).unwrap(), "");
    let written = shell.host.written.borrow();
    assert_eq!(written["/tmp/a"], b"stdout of /bin/ls\n");
    assert_eq!(written["/tmp/b"], b"one\ntwo\nstdout of /bin/cat\n");
    assert_eq!(written["/tmp/e"], b"stderr of /bin/cat\n");
    assert_eq!(written["/tmp/c"], b"");
    assert_eq!(
        shell.host.plans,
        [
            vec!["/bin/ls in=inherit out=file:/tmp/a err=inherit".to_string()],
            vec![
                "/bin/ls in=inherit out=next err=inherit".to_string(),
                "/bin/cat in=previous out=file:/tmp/b err=file:/tmp/e".to_string(),
            ],
        ]
    );
}

#[test]
fn builtins_other_than_output_ones_take_no_redirection() {
    let (_, text, _) = console(Mode::Interactive, "cd /tmp > x\nexit 3 > x\nstatus\n");
    assert_eq!(
        text,
        "absd$ absd-sh: cd: takes no redirection\nabsd$ absd-sh: exit: takes no redirection\nabsd$ 2\nabsd$ "
    );
}

#[test]
fn ro_and_nofs_narrow_what_a_command_gets() {
    let mut host = fake();
    host.writable = true;
    let mut shell = Shell::new(host, "/tmp".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    for line in ["ls > a", "ro ls > b", "nofs cat < /etc/motd", "ls | ro cat | nofs cat"] {
        shell.run_line(line, &mut out, &mut err);
    }
    assert_eq!(String::from_utf8(err.clone()).unwrap(), "");
    assert_eq!(
        shell.host.authorities,
        [
            Authority::Shell,
            Authority::ReadOnly,
            Authority::None,
            Authority::Shell,
            Authority::ReadOnly,
            Authority::None,
        ]
    );
    // The prefix is not part of the program: `ro ls` runs /bin/ls.
    assert_eq!(shell.host.runs[1].0, "/bin/ls");
    // Only programs take it, and it needs one.
    for (line, message) in [
        ("ro cd /bin", "absd-sh: ro: applies to programs, not the builtin cd\n"),
        ("nofs echo hi > x", "absd-sh: nofs: applies to programs, not the builtin echo\n"),
        ("ro", "absd-sh: ro: needs a program\n"),
    ] {
        let mut err = Vec::new();
        assert_eq!(shell.run_line(line, &mut out, &mut err), Flow::Continue);
        assert_eq!(String::from_utf8(err).unwrap(), message, "{line}");
        assert_eq!(shell.status, STATUS_USAGE);
    }
    assert_eq!(shell.host.authorities.len(), 6);
}

/// Runs `input` interactively with the session answering `answers`.
fn with_session(answers: Option<Vec<(i32, &str)>>, input: &str) -> (i32, String, Shell<Fake>) {
    let mut host = fake();
    host.answers = answers.map(|a| a.into_iter().map(|(s, t)| (s, t.to_string())).collect());
    let mut shell = Shell::new(host, "/".into());
    let mut both = Vec::new();
    let status = {
        let shared = std::cell::RefCell::new(&mut both);
        struct To<'a, 'b>(&'a std::cell::RefCell<&'b mut Vec<u8>>);
        impl Write for To<'_, '_> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        session(&mut shell, Mode::Interactive, &mut input.as_bytes(), &mut To(&shared), &mut To(&shared))
    };
    (status, String::from_utf8(both).unwrap(), shell)
}

#[test]
fn session_builtins_ask_the_server() {
    let answers = vec![
        (0, "session 1 (this session)\n"),
        (0, "ABSD is going down for halt\n"),
        (2, "usage: shutdown\n"),
        (1, "reboot: a halt is already under way\n"),
    ];
    let input = "ps\nshutdown\nshutdown +5\nreboot\nstatus\n";
    let (status, text, shell) = with_session(Some(answers), input);
    assert_eq!(status, 0);
    assert_eq!(
        text,
        "absd$ session 1 (this session)\n\
         absd$ ABSD is going down for halt\n\
         absd$ usage: shutdown\n\
         absd$ reboot: a halt is already under way\n\
         absd$ 1\n\
         absd$ "
    );
    assert_eq!(shell.host.asked, ["List", "Machine(\"shutdown\")", "Machine(\"shutdown +5\")", "Machine(\"reboot\")"]);
    assert_eq!(shell.host.lines, 5);
    assert!(shell.host.runs.is_empty(), "no program named ps, shutdown or reboot ran");
}

#[test]
fn session_builtins_without_a_channel_or_in_the_wrong_place() {
    let input = "ps\nshutdown\nps extra\nshutdown | cat\nreboot > /tmp/x\nro ps\nps | cat\n";
    let (_, text, shell) = with_session(None, input);
    assert_eq!(
        text,
        "absd$ absd-sh: ps: no session control channel (only a session's shell has one)\n\
         absd$ absd-sh: shutdown: no session control channel (only a session's shell has one)\n\
         absd$ absd-sh: ps: not found\n\
         absd$ absd-sh: shutdown: cannot run in a pipeline\n\
         absd$ absd-sh: reboot: takes no redirection\n\
         absd$ absd-sh: ro: applies to programs, not the builtin ps\n\
         absd$ absd-sh: ps: no session control channel (only a session's shell has one)\n\
         absd$ "
    );
    // `ps | cat`: the builtin's (empty) output still feeds the pipeline.
    assert_eq!(shell.host.runs.len(), 2);
    // A session that ended while the shell asked.
    let (_, text, _) = with_session(Some(vec![]), "ps\n");
    assert_eq!(text, "absd$ absd-sh: ps: the session ended\nabsd$ ");
}

#[test]
fn an_interrupted_pipeline_is_quiet_with_status_130() {
    let (status, text, _) = with_session(None, "hang\nstatus\ncat | hang\nstatus\nhang\n");
    assert_eq!(status, STATUS_INTERRUPTED);
    assert_eq!(text, "absd$ absd$ 130\nabsd$ absd$ 130\nabsd$ absd$ ");
}

#[test]
fn an_ended_session_exits_without_reading_on() {
    let (status, text, shell) = with_session(None, "cat | ended\necho never\nls\n");
    assert_eq!(status, STATUS_INTERRUPTED);
    assert_eq!(text, "absd$ ");
    assert_eq!(shell.host.runs.len(), 2, "nothing after the ended line ran");
    let mut shell = Shell::new(fake(), "/".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = session(&mut shell, Mode::Command("ended".into()), &mut "".as_bytes(), &mut out, &mut err);
    assert_eq!((status, out.is_empty(), err.is_empty()), (STATUS_INTERRUPTED, true, true));
}

#[test]
fn a_refused_start_says_permission_denied() {
    let (status, text, _) = with_session(None, "nospawn\nstatus\n");
    assert_eq!(status, 0);
    assert_eq!(text, "absd$ absd-sh: nospawn: cannot run: permission denied\nabsd$ 126\nabsd$ ");
}

#[test]
fn document_fetch_is_refused_after_shell_resolution_before_redirections_or_spawn() {
    for (cwd, name) in [
        ("/", "https-document"),
        ("/", "/bin//https-document"),
        ("/", "/bin/./https-document"),
        ("/tmp", "../bin/https-document"),
        ("/bin", "./https-document"),
        ("/", "\"/bin/https-document\""),
    ] {
        let mut host = fake();
        host.writable = true;
        host.programs
            .insert("/bin/https-document".into(), Ok(Exit::Code(0)));
        let mut shell = Shell::new(host, cwd.into());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        shell.run_line(
            &format!("{name} --boot x --grant-expiry 15100 > /tmp/output"),
            &mut out,
            &mut err,
        );
        assert_eq!(shell.status, STATUS_REFUSED, "{cwd} {name}");
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "absd-sh: https-document: requires direct SSH exec\n"
        );
        assert!(shell.host.runs.is_empty() && shell.host.opened.is_empty());
    }
}
#[test]
fn shell_fetch_refusal_covers_pipeline_authority_wrappers_and_session_modes() {
    for prefix in ["", "ro ", "nofs "] {
        let line = format!(
            "cat < /etc/motd | {prefix}/bin/https-document --grant-expiry 15100 > /tmp/output"
        );
        for mode in [Mode::Command(line.clone()), Mode::Interactive] {
            let input = format!("{line}\nexit\n");
            let (status, text, shell) = console(mode, &input);
            assert_eq!(status, STATUS_REFUSED);
            assert!(text.contains("https-document: requires direct SSH exec"));
            assert!(shell.host.runs.is_empty() && shell.host.opened.is_empty());
        }
    }
}
#[test]
fn shell_document_sample_and_unrelated_programs_keep_ordinary_behavior() {
    let mut host = fake();
    host.programs
        .insert("/bin/https-document".into(), Ok(Exit::Code(0)));
    let mut shell = Shell::new(host, "/bin".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    for name in ["https-document", "/bin//https-document", "./https-document"] {
        shell.run_line(&format!("{name} --sample"), &mut out, &mut err);
        assert_eq!(shell.status, 0);
        let last = shell.host.runs.last().unwrap();
        assert_eq!(last.0, "/bin/https-document");
        assert_eq!(last.1, ["--sample"]);
    }
    shell.run_line("ls", &mut out, &mut err);
    assert_eq!(shell.status, 0);
    assert_eq!(shell.host.runs.last().unwrap().0, "/bin/ls");
    shell.run_line("https-document --sample extra", &mut out, &mut err);
    assert_eq!(shell.status, STATUS_REFUSED);
    assert_eq!(shell.host.runs.len(), 4);
}

#[test]
fn ordinary_script_syntax_and_expansion() {
    let mut shell = Shell::new(fake(), "/".into());
    let mut out = Vec::new();
    let mut err = Vec::new();
    shell.run_line("name='two words'; echo \"$name\"; echo 'literal $name'; echo escaped\\ space", &mut out, &mut err);
    assert_eq!(String::from_utf8(out).unwrap(), "two words\nliteral $name\nescaped space\n");
    assert!(err.is_empty(), "{}", String::from_utf8_lossy(&err));
}

#[test]
fn ordinary_conditionals_loops_and_status() {
    let mut shell = Shell::new(fake(), "/".into());
    let mut out = Vec::new();
    let mut err = Vec::new();
    shell.run_line("if false; then echo wrong; else for x in one 'two words'; do echo \"$x\"; done; fi; echo $?", &mut out, &mut err);
    assert_eq!(String::from_utf8(out).unwrap(), "one\ntwo words\n0\n");
}

#[test]
fn ordinary_command_substitution_and_parameter_defaults() {
    let mut shell = Shell::new(fake(), "/".into());
    let mut out = Vec::new();
    let mut err = Vec::new();
    shell.run_line("name=$(echo hello); echo \"${name:-wrong} ${missing:-default}\"", &mut out, &mut err);
    assert_eq!(String::from_utf8(out).unwrap(), "hello default\n");
}

#[test]
fn interpreted_file_output_never_lends_the_active_shell_channel() {
    let mut stage: Stage<io::Cursor<Vec<u8>>, Vec<u8>> = Stage {
        program: "/bin/cat".into(), args: vec![], cwd: "/".into(), env: vec![],
        authority: Authority::Shell, stdin: Input::Inherit,
        stdout: Output::Shared(SharedSink(Rc::new(RefCell::new(Vec::new())))), stderr: Output::Inherit,
    };
    assert!(stage.copies_files(), "shared script sink is an active filesystem consumer");
    stage.stdout = Output::Capture(Capture::new());
    assert!(!stage.copies_files(), "memory capture alone does not need a filesystem channel");
    stage.stderr = Output::Shared(SharedSink(Rc::new(RefCell::new(Vec::new()))));
    assert!(stage.copies_files());
}

#[test]
fn continuation_only_waits_when_parser_stopped_at_end_of_input() {
    for text in ["for f in *; echo $f; done\n", "for f in a; nonsense\n", "echo ${name?bad}\n)"] {
        assert!(!language::incomplete(text), "invalid middle input trapped continuation: {text}");
    }
    for text in ["if true; then\n", "for f in a; do\n", "echo 'open\n", "echo \"open\n", "echo $(echo open\n"] {
        assert!(language::incomplete(text), "genuine EOF should continue: {text}");
    }
}

#[test]
fn interactive_prompt_history_mode_ends_before_native_programs_and_scripts_never_enable_it() {
    let (_, _, shell) = console(Mode::Interactive, "cat\nexit\n");
    assert_eq!(shell.host.prompt_modes, [1, 3, 0, 1, 3, 0]);
    let (_, _, shell) = console(Mode::Command("cat".into()), "");
    assert!(shell.host.prompt_modes.is_empty());
    let (_, _, shell) = console(Mode::Stdin(vec![]), "cat\n");
    assert!(shell.host.prompt_modes.is_empty());
}

#[test]
fn standard_application_paste_marker_is_not_a_private_source_record() {
    let bytes=b"\x1b[200~1048576\nhello\n\x1b[201~";
    let mut input=std::io::Cursor::new(bytes);let mut text=String::new();
    let count=read_interactive_record(&mut input,&mut text).expect("ordinary app marker must not request a 1 MiB private read");
    assert_eq!(text,"\x1b[200~1048576\n");assert_eq!(count,text.len());
    assert_eq!(&bytes[input.position() as usize..],b"hello\n\x1b[201~");
}

#[test]
fn unconfigured_frontend_keeps_whole_source_limit_refusal() {
    let source=format!("echo '{}' > /refused\necho suffix > /victim\n", "x".repeat(MAX_SCRIPT_BYTES));
    let (status, text, shell)=console(Mode::Interactive,&source);
    assert_eq!(status,STATUS_USAGE);assert!(text.contains("input exceeds 1 MiB"));
    assert!(!shell.host.written.borrow().contains_key("/refused"));assert!(!shell.host.written.borrow().contains_key("/victim"));
}

#[test]
fn ordinary_syntax_error_then_completed_quote_and_fresh_command_recover() {
    let (_, text, _) = console(Mode::Interactive,"echo ; ;\necho 'first\nsecond'\necho fresh\n");
    assert!(text.contains("first\nsecond\n")); assert!(text.contains("fresh\n"));
}

#[test]
fn continuation_read_fence_is_distinct_from_program_mode() {
    let (_, _, shell) = console(Mode::Interactive, "echo 'one\ntwo'\n");
    assert_eq!(shell.host.prompt_modes, [1, 3, 2, 3, 0, 1, 3, 0]);
}

#[test]
fn cancellation_during_program_ack_opens_no_output() {
    let mut shell = Shell::new(fake(), "/".into());
    shell.host.writable = true;
    shell.host.cancel_on_next_program_ack = true;
    let mut out = Vec::new();
    let mut err = Vec::new();
    session(&mut shell, Mode::Interactive,
        &mut "echo must-not-run > skipped\nexit\n".as_bytes(), &mut out, &mut err);
    assert!(!shell.host.opened.iter().any(|v| v.contains("skipped")));
    assert!(!shell.host.written.borrow().contains_key("/skipped"));
    assert!(err.is_empty());
}

#[test]
fn cancellation_during_eof_program_ack_skips_pending_input() {
    let mut shell = Shell::new(fake(), "/".into());
    shell.host.cancel_on_next_program_ack = true;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = session(&mut shell, Mode::Interactive,
        &mut "echo 'unfinished".as_bytes(), &mut out, &mut err);
    assert_eq!(status, STATUS_INTERRUPTED);
    assert!(err.is_empty());
}

#[test]
fn prompt_uses_observed_size_and_removes_unknown_dimensions() {
    let mut shell = Shell::new(fake(), "/".into());
    shell.set_environment([("LINES".into(), "999".into())]);
    shell.host.terminal_shape = Some((173,0));
    let mut out = Vec::new();
    let mut err = Vec::new();
    session(&mut shell, Mode::Interactive, &mut "echo ${COLUMNS} ${LINES:-unknown}\nexit\n".as_bytes(), &mut out, &mut err);
    assert!(String::from_utf8(out).unwrap().contains("173 unknown"));
}

#[test]
fn prompt_interrupt_cancels_accumulated_continuation_and_restores_prompt() {
    let mut shell = Shell::new(fake(), "/".into());
    shell.host.cancel_on_line = Some(2);
    let mut out = Vec::new();
    let mut err = Vec::new();
    session(&mut shell, Mode::Interactive, &mut "echo 'unfinished\n\necho restored\nexit\n".as_bytes(), &mut out, &mut err);
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("absd$ > absd$ restored\nabsd$ "), "{out:?}");
    assert!(!out.contains("unfinished"));
    assert!(err.is_empty());
}

#[test]
fn standard_stream_aliases_route_builtin_output_in_source_order() {
    let mut host = fake();
    host.writable = true;
    let mut shell = Shell::new(host, "/tmp".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line("echo first 1>&2; echo second 1>&2 2> after; echo third", &mut out, &mut err);
    assert_eq!(shell.status, 0, "{}", String::from_utf8_lossy(&err));
    assert_eq!(out, b"third\n");
    assert_eq!(err, b"first\nsecond\n");
    assert_eq!(shell.host.opened, ["w /tmp/after"]);
    assert_eq!(shell.host.written.borrow()["/tmp/after"], b"");
}

#[test]
fn repeated_output_opens_have_effects_before_the_final_destination() {
    let mut host = fake();
    host.writable = true;
    let mut shell = Shell::new(host, "/tmp".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line("echo kept > first > second; echo appended >> second", &mut out, &mut err);
    assert_eq!(shell.status, 0, "{}", String::from_utf8_lossy(&err));
    assert!(out.is_empty() && err.is_empty());
    assert_eq!(shell.host.opened, ["w /tmp/first", "w /tmp/second", "a /tmp/second"]);
    let written = shell.host.written.borrow();
    assert_eq!(written["/tmp/first"], b"");
    assert_eq!(written["/tmp/second"], b"kept\nappended\n");
}

#[test]
fn aliases_in_compounds_share_the_opened_file_and_restore_outer_streams() {
    let mut host = fake();
    host.writable = true;
    let mut shell = Shell::new(host, "/tmp".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line("{ echo one; echo two 1>&2; } > both 2>&1; echo outer; echo error 1>&2", &mut out, &mut err);
    assert_eq!(shell.status, 0, "{}", String::from_utf8_lossy(&err));
    assert_eq!(out, b"outer\n");
    assert_eq!(err, b"error\n");
    assert_eq!(shell.host.opened, ["w /tmp/both"]);
    assert_eq!(shell.host.written.borrow()["/tmp/both"], b"one\ntwo\n");
}

#[test]
fn unsupported_descriptor_forms_refuse_before_earlier_program_effects() {
    for form in ["2>&3", "2>&-", "0>&1", "1<&2", "3> other"] {
        let mut host = fake(); host.writable = true;
        let mut shell = Shell::new(host, "/tmp".into());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        shell.run_line(&format!("echo before > untouched; echo bad {form}"), &mut out, &mut err);
        assert_eq!(shell.status, STATUS_USAGE, "{form}");
        assert!(out.is_empty() && !err.is_empty(), "{form}");
        assert!(shell.host.opened.is_empty() && shell.host.runs.is_empty(), "{form}");
    }
}

#[test]
fn nested_alias_uses_the_saved_parent_not_the_later_redirected_descriptor() {
    let mut host = fake(); host.writable = true;
    let mut shell = Shell::new(host, "/tmp".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line("{ echo original-error; echo file 1>&2; } 1>&2 2> nested; echo outer", &mut out, &mut err);
    assert_eq!(shell.status, 0);
    assert_eq!(out, b"outer\n");
    assert_eq!(err, b"original-error\n");
    assert_eq!(shell.host.written.borrow()["/tmp/nested"], b"file\n");
}

#[test]
fn output_endpoint_resolution_matches_a_bounded_independent_identity_table() {
    for piped in [false, true] {
        for length in 0..=4_u32 {
            for sequence in 0..4_usize.pow(length) {
                let mut host = fake(); host.writable = true;
                let mut shell = Shell::new(host, "/tmp".into());
                let base = if piped { 3 } else { 2 };
                let mut expected = [if piped { 2 } else { 0 }, 1];
                let mut encoded = sequence;
                let mut command = Command::default();
                let mut opens = Vec::new();
                for position in 0..length as usize {
                    let operation = encoded % 4; encoded /= 4;
                    if operation < 2 {
                        expected[operation] = base + position;
                        command.redirects.push(Redirect::File { fd: operation as u8 + 1,
                            path: format!("generation-{position}"), append: false });
                        opens.push(format!("w /tmp/generation-{position}"));
                    } else {
                        let target = operation - 2;
                        expected[target] = expected[1 - target];
                        command.redirects.push(Redirect::Dup { fd: target as u8 + 1, from: (1 - target) as u8 + 1 });
                    }
                }
                let resolved = shell.resolve_outputs(&command, piped).unwrap();
                let actual = resolved.each_ref().map(|endpoint| match endpoint.as_ref() {
                    Destination::Parent(slot) => *slot,
                    Destination::Next => 2,
                    Destination::File(sink) => base + sink.0.borrow().path.rsplit('-').next().unwrap().parse::<usize>().unwrap(),
                    Destination::Capture(_) => unreachable!(),
                    Destination::Discard => unreachable!(),
                });
                assert_eq!(actual, expected, "piped={piped}, length={length}, sequence={sequence}");
                assert_eq!(Rc::ptr_eq(&resolved[0], &resolved[1]), expected[0] == expected[1]);
                assert_eq!(shell.host.opened, opens);
            }
        }
    }
}

#[test]
fn compound_output_open_failure_preserves_redirect_status_and_skips_body() {
    let mut shell = Shell::new(fake(), "/tmp".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line("{ echo never; ls; } > unavailable", &mut out, &mut err);
    assert_eq!(shell.status, STATUS_REDIRECT);
    assert!(out.is_empty() && !err.is_empty());
    assert!(shell.host.runs.is_empty());
}

#[test]
fn exact_null_redirections_require_no_filesystem_open_even_on_a_read_only_view() {
    let mut shell = Shell::new(fake(), "/tmp".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line("echo ignored > /dev/null 2>&1", &mut out, &mut err);
    assert_eq!(shell.status, 0, "{}", String::from_utf8_lossy(&err));
    assert!(out.is_empty() && err.is_empty());
    assert!(shell.host.opened.is_empty());
    shell.run_line("cat < /dev/null", &mut out, &mut err);
    assert_eq!(shell.status, 0, "{}", String::from_utf8_lossy(&err));
    assert!(shell.host.opened.is_empty());
    assert_eq!(shell.host.plans.last().unwrap(), &["/bin/cat in=bytes: out=inherit err=inherit"]);
}

#[test]
fn null_ordering_keeps_the_earlier_stdout_alias_for_diagnostics() {
    let mut shell = Shell::new(fake(), "/tmp".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line("ps > /dev/null 2>&1", &mut out, &mut err);
    assert_eq!(shell.status, 1);
    assert!(out.is_empty() && err.is_empty());
    shell.run_line("ps 2>&1 > /dev/null", &mut out, &mut err);
    assert_eq!(shell.status, 1);
    assert!(!out.is_empty() && err.is_empty());
    assert!(shell.host.opened.is_empty());
}

#[test]
fn null_mapping_is_only_the_exact_expanded_redirection_word() {
    for path in ["/dev/nullish", "/dev/./null", "dev/null"] {
        let mut shell = Shell::new(fake(), "/tmp".into());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        shell.run_line(&format!("echo ignored > {path}"), &mut out, &mut err);
        assert_eq!(shell.status, STATUS_REDIRECT, "{path}");
        assert_eq!(shell.host.opened.len(), 1, "{path}");
    }
    let mut shell = Shell::new(fake(), "/tmp".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line("cat /dev/null", &mut out, &mut err);
    assert_eq!(shell.host.runs[0].1, ["/dev/null"]);
    assert!(shell.host.opened.is_empty());
}

#[test]
fn redirected_stderr_suppresses_only_the_extra_native_exit_status_line() {
    for (line, diagnostic) in [
        ("ls", true),
        ("ls > /dev/null", true),
        ("ls 2> /dev/null", false),
        ("ls > /dev/null 2>&1", false),
        ("ls 2>&1 > /dev/null", false),
        ("ls 2>&2", false),
    ] {
        let mut host = fake(); host.programs.insert("/bin/ls".into(), Ok(Exit::Code(7)));
        let mut shell = Shell::new(host, "/tmp".into());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        shell.run_line(line, &mut out, &mut err);
        assert_eq!(shell.status, 7, "{line}");
        assert_eq!(err, if diagnostic { b"absd-sh: ls: exit status 7\n".as_slice() } else { b"" }, "{line}");
    }
    let mut host = fake(); host.writable = true;
    host.programs.insert("/bin/ls".into(), Ok(Exit::Code(7)));
    let mut shell = Shell::new(host, "/tmp".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line("{ ls; } 2> error", &mut out, &mut err);
    assert_eq!(shell.status, 7);
    assert!(err.is_empty());
    assert_eq!(shell.host.written.borrow()["/tmp/error"], b"stderr of /bin/ls\n");
}

#[test]fn clock_uses_operator_channel_and_never_spawns_a_clockwriter(){
    let(_,text,shell)=with_session(Some(vec![(0,"clock source=rtc-unverified\n"),(0,"clock corrected\n"),(1,"sync disabled\n")]),"clock status\nclock set 100\nclock sync\n");
    assert!(text.contains("rtc-unverified"));assert!(text.contains("sync disabled"));assert_eq!(shell.host.asked,["Clock(\"status\")","Clock(\"set 100\")","Clock(\"sync\")"]);assert!(shell.host.runs.is_empty());
    let(_,text,_)=with_session(None,"clock set 100\nclock sync | cat\n");assert!(text.contains("no session control channel"));assert!(text.contains("cannot run in a pipeline"));
}

// ---- independent reviewer harness: real shell::session + real ssh tty.rs ----
#[path = "../../ssh/src/tty.rs"]
#[allow(dead_code)]
mod real_tty;
mod rv {
    use super::real_tty::{LineDiscipline, MAX_LINE};
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io::{BufReader, Read};

    pub struct Wire { pub ld: LineDiscipline, pub pipe: VecDeque<u8>, pub src: Vec<u8>, pub at: usize, pub rng: u64,
        pub sizes: Vec<usize>, pub pending: bool, pub flag: bool, pub echo: Vec<u8>, pub race: u64, pub armed: bool }
    thread_local! { pub static W: RefCell<Option<Wire>> = const { RefCell::new(None) }; }
    impl Wire {
        pub fn r(&mut self) -> u64 { let mut x = self.rng; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.rng = x; x }
        pub fn pump(&mut self) {
            if self.at >= self.src.len() { return; }
            let i = (self.r() as usize) % self.sizes.len();
            let mut n = self.sizes[i];
            if n == 0 { n = 1 + (self.r() as usize) % 4096; }
            let end = (self.at + n).min(self.src.len());
            let (mut c, mut e) = (Vec::new(), Vec::new());
            let batch = self.src[self.at..end].to_vec();
            let ev = self.ld.input(&batch, &mut c, &mut e);
            self.at = end;
            self.pipe.extend(c);
            self.echo.extend(e);
            if ev.interrupt { self.pending = true; }
        }
    }
    pub fn on_mode(mode: u8) {
        W.with(|w| if let Some(w) = w.borrow_mut().as_mut() {
            // A batch may land before sshd services the request, or after.
            if w.race > 0 && w.armed && w.r() % w.race == 0 { w.pump(); }
            w.armed = true;
            w.ld.set_prompt_mode(mode);
            // ask(): listen drains events up to the reply; cancellation stays latched.
            if w.pending { w.flag = true; w.pending = false; }
            // Cancellation is retained until the interactive loop purges it.
            if w.race > 0 && w.r() % w.race == 0 { w.pump(); }
        });
    }
    thread_local! { static DRAIN_ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(true) }; }
    pub fn discard() {
        on_mode(0);
        if DRAIN_ENABLED.with(|enabled| enabled.get()) {
            W.with(|w| if let Some(w) = w.borrow_mut().as_mut() { w.pipe.clear(); });
        }
    }
    pub fn on_line() { W.with(|w| if let Some(w) = w.borrow_mut().as_mut() && w.pending { w.flag = true; w.pending = false; }); }
    pub fn on_cancel() -> bool { W.with(|w| w.borrow_mut().as_mut().is_some_and(|w| std::mem::take(&mut w.flag))) }
    struct Reader;
    impl Read for Reader {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            W.with(|w| { let mut g = w.borrow_mut(); let w = g.as_mut().unwrap();
                while w.pipe.is_empty() && w.at < w.src.len() { w.pump(); }
                match w.pipe.pop_front() { Some(x) => { b[0] = x; Ok(1) } None => Ok(0) } })
        }
    }
    pub fn read(input: &mut dyn io::BufRead, text: &mut String) -> io::Result<usize> {
        if W.with(|w| w.borrow().is_none()) { input.read_line(text) }
        else { super::super::read_interactive_record(input, text) }
    }
    pub struct R { pub files: BTreeMap<String, Vec<u8>>, pub err: String }
    pub fn drive(src: &[u8], sizes: &[usize], seed: u64, race: u64) -> R {
        W.with(|w| *w.borrow_mut() = Some(Wire { ld: LineDiscipline::new(), pipe: VecDeque::new(), src: src.to_vec(), at: 0,
            rng: seed.wrapping_mul(0x9E3779B97F4A7C15) | 1, sizes: sizes.to_vec(), pending: false, flag: false, echo: Vec::new(), race, armed: false }));
        let mut shell = Shell::new(fake(), "/".into());
        shell.host.writable = true;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut input = BufReader::with_capacity(1, Reader);
        session(&mut shell, Mode::Interactive, &mut input, &mut out, &mut err);
        W.with(|w| *w.borrow_mut() = None);
        let files = shell.host.written.borrow().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        R { files, err: String::from_utf8_lossy(&err).into_owned() }
    }
    const SIZES: &[usize] = &[1,2,3,5,7,40,41,42,63,64,255,256,1023,1024,1025,2047,2048,4095,4096,0];
    fn cr(s: &str) -> Vec<u8> { s.bytes().map(|b| if b == b'\n' { b'\r' } else { b }).collect() }

    fn tally(name: &str, src: &[u8], path: &str, want: &[u8], runs: u64) {
        let (mut pass, mut fail, mut lost, mut first) = (0, 0, 0usize, None);
        for set in 0..3 { for seed in 1..=runs {
            let sizes: Vec<usize> = match set { 0 => SIZES.to_vec(), 1 => vec![SIZES[(seed as usize) % SIZES.len()]], _ => vec![1024] };
            let race = [0u64, 2, 4][(seed % 3) as usize];
            let r = drive(src, &sizes, seed + 1000 * set as u64, race);
            let got = r.files.get(path).cloned().unwrap_or_default();
            if got == want { pass += 1 } else { fail += 1; lost += want.len().saturating_sub(got.len());
                if first.is_none() { first = Some((seed, set, got.len(), r.err.lines().next().map(str::to_string))); } }
        }}
        println!("[{name}] pass={pass} fail={fail} avg_lost={} first_fail={first:?}", lost.checked_div(fail).unwrap_or(0));
        assert_eq!(fail, 0, "{name}: lost or changed input under the tested schedules");
    }


    #[test] fn a_continuation_ascii() {
        let b = "0123456789012345678901234567890123456789\n".repeat(200);
        let src = cr(&format!("echo '\n{b}' > /f\n"));
        tally("A continuation 200 lines", &src, "/f", format!("\n{b}\n").as_bytes(), 300);
    }
    #[test] fn a2_continuation_full_size() {
        let b = "0123456789012345678901234567890123456789\n".repeat(1600);
        let src = cr(&format!("echo '\n{b}' > /f\n"));
        tally("A2 continuation 1600 lines", &src, "/f", format!("\n{b}\n").as_bytes(), 6);
    }
    #[test] fn b_continuation_utf8_mixed_widths() {
        let mut b = String::new(); let mut x = 77u64;
        for _ in 0..300 { x = x.wrapping_mul(6364136223846793005).wrapping_add(1); let n = (x >> 40) as usize % 300;
            for j in 0..n { b.push(['a','é','🙂','世','z',' '][(x as usize >> (j % 30)) % 6]); } b.push('\n'); }
        let src = cr(&format!("echo '\n{b}' > /f\n"));
        tally("B continuation utf8", &src, "/f", format!("\n{b}\n").as_bytes(), 200);
    }
    #[test] fn c_exact_fit_lines() {
        // Whole terminal line exactly MAX_LINE, inside a quote; ASCII and straddling multibyte.
        let a = "a".repeat(MAX_LINE);
        let u = format!("{}é", "b".repeat(MAX_LINE - 2));
        let b = format!("{a}\n{u}\n{a}\n");
        let src = cr(&format!("echo '\n{b}' > /f\n"));
        tally("C exact-fit MAX_LINE", &src, "/f", format!("\n{b}\n").as_bytes(), 200);
    }
    #[test] fn d_primary_many_commands() {
        let mut s = String::new(); let mut want = String::new();
        for i in 0..400 { s.push_str(&format!("echo line-{i:05}-0123456789012345678901234567 >> /f\n")); want.push_str(&format!("line-{i:05}-0123456789012345678901234567\n")); }
        tally("D primary-prompt 400 commands", &cr(&s), "/f", want.as_bytes(), 300);
    }
    #[test] fn e_two_quoted_commands() {
        let b = "0123456789012345678901234567890123456789\n".repeat(50);
        let src = cr(&format!("echo '\n{b}' >> /f\necho '\n{b}' >> /f\n"));
        let w = format!("\n{b}\n\n{b}\n");
        tally("E two quoted commands", &src, "/f", w.as_bytes(), 300);
    }
    #[test] fn f_diagnostic_shape() {
        let b = "0123456789012345678901234567890123456789\n".repeat(1600);
        let src = cr(&format!("PASTE_BODY='\n{b}'\necho \"$PASTE_BODY\" > /f\necho DONE\n"));
        tally("F diagnostic shape", &src, "/f", format!("\n{b}\n").as_bytes(), 15);
    }
    #[test] fn g_torn_primary_line_runs_suffix() {
        // Exact deterministic witness: boundary inside the second command.
        let src = b"echo first > /a\recho pasted > /etc-config; echo second > /b\r".to_vec();
        let cut = b"echo first > /a\recho pasted > /etc-config;".len();
        let r = drive(&src, &[cut, 4096], 3, 0);
        println!("[G torn primary] files={:?} err={:?}", r.files.keys().collect::<Vec<_>>(), r.err);
    }
    #[test] fn h_interrupt_mid_quoted_paste_runs_body_as_command() {
        let src = b"echo 'body\recho EXECUTED > /victim\r\x03more'\r".to_vec();
        let r = drive(&src, &[4096], 3, 0);
        println!("[H ctrl-c] files={:?} err={:?}", r.files.keys().collect::<Vec<_>>(), r.err);
        assert!(!r.files.contains_key("/victim"), "cancelled quoted text executed");
    }
    #[test] fn h2_already_forwarded_quoted_body_requires_the_pipe_drain() {
        // Two eleven-byte reads deliver the body line to the inherited pipe
        // before the following batch supplies Ctrl-C. The shell has already
        // accumulated the opening quote. This fixture is a modelled pipe.
        let src = b"echo 'body\recho x > /victim     \r\x03";
        DRAIN_ENABLED.with(|enabled| enabled.set(false));
        let broken = drive(src, &[11], 3, 1);
        DRAIN_ENABLED.with(|enabled| enabled.set(true));
        assert!(broken.files.contains_key("/victim"), "negative control did not expose forwarded bytes");
        let fixed = drive(src, &[11], 3, 1);
        assert!(!fixed.files.contains_key("/victim"), "forwarded quoted input escaped cancellation");
    }

    #[test] fn bracketed_paste_must_not_execute_before_enter() {
        let src = b"\x1b[200~echo staged > /paste-marker\r\x1b[201~";
        let result = drive(src, &[1, 7, 1024], 3, 2);
        assert!(!result.files.contains_key("/paste-marker"), "paste executed before review/Enter");
    }
    #[test] fn bracketed_multicommand_and_original_assignment_have_exact_bytes_after_enter() {
        let body="0123456789012345678901234567890123456789\n".repeat(1600);
        let script=format!("PASTE_BODY='\n{body}'\necho \"$PASTE_BODY\" > /large\necho done > /done\n");
        let wire=[b"\x1b[200~".as_slice(),&cr(&script),b"\x1b[201~\r"].concat();
        for sizes in [&[1,7,1024][..],&[4096][..]] {
            let result=drive(&wire,sizes,14,2);
            assert_eq!(result.files.get("/large"),Some(&format!("\n{body}\n").into_bytes()));
            assert_eq!(result.files.get("/done"),Some(&b"done\n".to_vec()));
        }
    }
    #[test] fn forged_end_marker_is_a_documented_inband_boundary_limit() {
        let normal = b"\x1b[200~echo reviewed\r\x1b[201~\recho suffix > /campaign-owned-marker\r";
        let mut forged = normal.to_vec();
        forged.extend_from_slice(b"not-the-real-end-yet\x1b[201~");
        assert_eq!(&forged[..normal.len()], normal);
        let ordinary_prefix = drive(normal, &[1, 7, 1024], 3, 2);
        let embedded_prefix = drive(&forged[..normal.len()], &[1, 7, 1024], 3, 2);
        assert_eq!(ordinary_prefix.files, embedded_prefix.files,
            "the byte-only consumer cannot distinguish two origins of the same prefix");
        // Steward1748Z explicitly accepts standard delimiter semantics.
        // This pins a known limit, not a protection against a forged marker.
        assert!(ordinary_prefix.files.contains_key("/campaign-owned-marker"));
        assert!(embedded_prefix.files.contains_key("/campaign-owned-marker"));
    }

    #[test] fn exact_new_physical_line_limit_has_exact_output() {
        let prefix = "echo '"; let suffix = "' > /long";
        let body = "x".repeat(MAX_LINE - prefix.len() - suffix.len());
        let command = format!("{prefix}{body}{suffix}");
        assert_eq!(command.len(), MAX_LINE);
        let result = drive(&cr(&(command + "\n")), &[7, 1024, 4096], 3, 2);
        assert_eq!(result.files.get("/long"), Some(&format!("{body}\n").into_bytes()));
    }

    #[test] fn i_overlong_line() {
        let long = "x".repeat(MAX_LINE + 905);
        let src = cr(&format!("echo '{long}' > /f\necho after > /g\n"));
        let r = drive(&src, &[4096], 3, 0);
        println!("[I overlong] f_len={:?} g={:?} err={:?}", r.files.get("/f").map(Vec::len), r.files.contains_key("/g"), r.err.lines().next());
        assert!(!r.files.contains_key("/f"), "a shortened overlong command executed");
        let mut ld = LineDiscipline::new(); let (mut c, mut e) = (Vec::new(), Vec::new());
        let ev = ld.input(long.as_bytes(), &mut c, &mut e);
        println!("[I overlong tty] accepted_echo={} of {} events={ev:?} bel={}", e.len(), long.len(), e.contains(&7));
        assert!(ev.interrupt, "overlong line was silently truncated");
        assert!(String::from_utf8_lossy(&e).contains("exceeds"), "refusal must explain its bound");
    }
    #[test] fn j_invalid_utf8_dropped() {
        let mut ld = LineDiscipline::new(); let (mut c, mut e) = (Vec::new(), Vec::new());
        let ev = ld.input(b"caf\xe9 \xff\xfeok\r", &mut c, &mut e);
        println!("[J invalid utf8] child={:?} events={ev:?}", String::from_utf8_lossy(&c));
        assert!(c.is_empty(), "invalid UTF8 was silently edited into executable input");
        assert!(ev.interrupt, "whole command must be cancelled");
    }
    #[test] fn n_before_first_prompt() {
        let mut ld = LineDiscipline::new(); let (mut c, mut e) = (Vec::new(), Vec::new());
        ld.input(b"echo pasted-before-first-prompt", &mut c, &mut e);
        ld.set_prompt_mode(1);
        ld.input(b" tail\r", &mut c, &mut e);
        println!("[N before first prompt] child={:?}", String::from_utf8_lossy(&c));
        assert_eq!(c, b"echo pasted-before-first-prompt tail\n");
    }
    #[test] fn zg_guard_torn() {
        let src = b"echo first > /a\rcd /nonexistent && echo tail > /oops\r".to_vec();
        let cut = b"echo first > /a\rcd /nonexistent &&".len();
        let whole = drive(&src, &[4096], 3, 0);
        let torn = drive(&src, &[cut], 3, 0);
        println!("[G guard] whole={:?} torn={:?} torn_err={:?}", whole.files.keys().collect::<Vec<_>>(), torn.files.keys().collect::<Vec<_>>(), torn.err);
        assert!(!whole.files.contains_key("/oops"));
        assert!(!torn.files.contains_key("/oops"), "a dropped guard executed the suffix");
    }
    #[test] fn k_tty_edit_fuzz_vs_unsplit() {
        // Random editing bytes: any fence/re-arm schedule must equal the unsplit reference.
        let toks: &[&[u8]] = &[b"a", b"bc", b" ", "é".as_bytes(), "🙂".as_bytes(), b"\r", b"\n", b"\x08", b"\x7f", b"\x15", b"\x17",
            b"\x1b[D", b"\x1b[C", b"\x1b[3~", b"\x1b[H", b"\x1b[F", b"\x1b", b"\x1bO", b"\x1b[[", b"\t", b"\x01"];
        let (mut pass, mut fail, mut first) = (0, 0, None);
        let mut x = 88172645463325252u64;
        let mut r = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
        for seed in 0..20000u64 {
            let mut src = Vec::new();
            for _ in 0..(1 + r() % 60) { src.extend_from_slice(toks[(r() as usize) % toks.len()]); }
            let (mut rf, mut e) = (Vec::new(), Vec::new());
            let mut ld = LineDiscipline::new(); ld.set_prompt_mode(2);
            for b in src.chunks(1) { ld.input(b, &mut rf, &mut e); }
            let reference = rf;
            let (mut got, mut e2) = (Vec::new(), Vec::new());
            let mut ld = LineDiscipline::new(); ld.set_prompt_mode(2);
            let mut at = 0;
            while at < src.len() {
                let n = 1 + (r() as usize) % 6; let end = (at + n).min(src.len());
                ld.input(&src[at..end], &mut got, &mut e2); at = end;
                match r() % 3 { 0 => { ld.set_prompt_mode(3); ld.set_prompt_mode(2); } 1 => { ld.set_prompt_mode(3); } _ => {} }
                if r() % 3 == 0 { ld.set_prompt_mode(3); ld.set_prompt_mode(2); }
            }
            if got == reference { pass += 1 } else { fail += 1; if first.is_none() { first = Some((seed, src.clone(), reference.clone(), got.clone())); } }
        }
        println!("[K edit fuzz] pass={pass} fail={fail} first={first:?}");
    }
    #[test] fn l_post_interrupt_residue_at_primary() {
        let mut ld = LineDiscipline::new(); let (mut c, mut e) = (Vec::new(), Vec::new());
        ld.set_prompt_mode(1);
        ld.input(b"cmd\rjunk\x03tail", &mut c, &mut e);
        ld.set_prompt_mode(3); ld.set_prompt_mode(1);
        ld.input(b"\r", &mut c, &mut e);
        println!("[L post-^C tail, fence then primary] child={:?}", String::from_utf8_lossy(&c));
        assert_eq!(c, b"\n", "cancelled tail must not survive a premature prompt rearm");
    }
    #[test] fn m_prompt_display_with_retained_partial() {
        let mut ld = LineDiscipline::new(); let (mut c, mut e) = (Vec::new(), Vec::new());
        ld.set_prompt_mode(1);
        ld.input(b"echo '\rpart", &mut c, &mut e);
        ld.set_prompt_mode(3); ld.set_prompt_mode(2);
        e.extend_from_slice(b"> "); // what sh writes after the ack
        ld.input(b"ial\x08\r", &mut c, &mut e);
        println!("[M display] echo={:?}", String::from_utf8_lossy(&e));
    }
}

// ---- delta-review harness (claude git0a): real session() + real tty.rs/paste.rs
// with sshd's InputMode dispatch, stdin queue, record padding and pause modelled
// from ssh/src/conn.rs at 5a2794a7 (terminal_input, InputMode arm, stdin write).
mod dv {
    use super::real_tty::{paste, LineDiscipline, MAX_LINE};
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io::{BufReader, Read};
    pub const CODE: &[u8] = b"\x00CODE\x00";
    pub const WAIT: &[u8] = b"\x00WAIT\x00";
    pub struct W { pub ld: LineDiscipline, q: Vec<u8>, pipe: VecDeque<u8>, cap: usize, rw: paste::RecordWrite, paused: bool,
        events: usize, latch: bool, src: Vec<u8>, at: usize, rng: u64, sizes: Vec<usize>, race: u64, pub echo: Vec<u8>,
        pub child: Vec<u8>, finished: bool, last_mode: u8, pub wedge: bool, pub max_q: usize, pub max_pipe: usize, pub drain_over: bool, pub shell_in: Vec<u8> }
    thread_local! { static S: RefCell<Option<W>> = const { RefCell::new(None) }; }
    pub fn active() -> bool { S.with(|s| s.borrow().is_some()) }
    fn with<T>(f: impl FnOnce(&mut W) -> T) -> T { S.with(|s| f(s.borrow_mut().as_mut().unwrap())) }
    impl W {
        fn r(&mut self) -> u64 { let mut x = self.rng; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.rng = x; x }
        fn flush(&mut self) {
            if self.paused { return; }
            let room = self.cap.saturating_sub(self.pipe.len());
            let n = room.min(self.q.len()); if n == 0 { return; }
            let n = if self.r().is_multiple_of(2) { n } else { 1 + (self.r() as usize) % n };
            let moved: Vec<u8> = self.q.drain(..n).collect();
            self.rw.written(&moved); self.pipe.extend(moved);
            self.max_pipe = self.max_pipe.max(self.pipe.len());
        }
        fn terminal_input(&mut self, bytes: Option<&[u8]>) {
            self.ld.pending_source_bytes(self.q.len());
            let padding = self.rw.cancel_padding(&self.q);
            let ev = match bytes { Some(b) => self.ld.input(b, &mut self.q, &mut self.echo), None => self.ld.finish_input(&mut self.q, &mut self.echo) };
            if ev.interrupt {
                let wake = !self.q.is_empty(); self.q.clear();
                if let Some((h, c)) = padding { self.q.extend_from_slice(&h); self.q.resize(h.len() + c, b'\n'); }
                if wake { self.q.push(b'\n'); }
            }
            if self.ld.needs_recovery_code() { let r = self.r().to_le_bytes(); self.ld.recovery_code(r, &mut self.echo); }
            if ev.interrupt { self.events += 1; }
            self.max_q = self.max_q.max(self.q.len());
        }
        // Keep the UTF-8 boundary check: malformed recovery prompts must still fail here.
        #[allow(clippy::sliced_string_as_bytes)]
        fn code(&self) -> Vec<u8> {
            let e = String::from_utf8_lossy(&self.echo);
            e.rsplit("terminal: type ").next().unwrap()[..16].as_bytes().to_vec()
        }
        /// One client batch, or false when nothing can be delivered.
        fn pump(&mut self) -> bool {
            self.flush();
            if self.at >= self.src.len() || self.q.len() >= 4096 { return false; }
            if self.src[self.at..].starts_with(WAIT) {
                if TRACE.with(|t| t.get()) { println!("  WAIT cancelled={} refused={} last_mode={}", self.ld.input_cancelled(), self.ld.input_refused(), self.last_mode); }
                // The human waits for a fresh, armed primary prompt.
                if self.ld.input_cancelled() || self.ld.input_refused() || !matches!(self.last_mode, 1 | 2) { return false; }
                self.at += WAIT.len(); return true;
            }
            if self.src[self.at..].starts_with(CODE) {
                if !self.ld.input_refused() || !String::from_utf8_lossy(&self.echo).contains("terminal: type ") { return false; }
                let c = self.code(); self.at += CODE.len(); if TRACE.with(|t| t.get()) { println!("  CODE typed"); } self.terminal_input(Some(&c)); self.flush(); return true;
            }
            let i = (self.r() as usize) % self.sizes.len();
            let mut n = self.sizes[i]; if n == 0 { n = 1 + (self.r() as usize) % 4096; }
            let mut end = (self.at + n).min(self.src.len());
            if let Some(k) = self.src[self.at..end].iter().position(|&b| b == 0) { end = self.at + k; }
            let batch = self.src[self.at..end].to_vec(); self.at = end;
            let (q0, p0) = (self.q.len(), self.pipe.len());
            self.terminal_input(Some(&batch));
            if TRACE.with(|t| t.get()) { println!("  pump {:?} q {}->{} pipe {} ev={} cancelled={} refused={}", String::from_utf8_lossy(&batch[..batch.len().min(40)]), q0, self.q.len(), p0, self.events, self.ld.input_cancelled(), self.ld.input_refused()); }
            self.flush(); true
        }
        fn control(&mut self, mode: u8) {
            self.last_mode = mode;
            if mode == 4 {
                self.ld.refuse_input("shell source exceeds 1 MiB", &mut self.q, &mut self.echo);
                let r = self.r().to_le_bytes(); self.ld.recovery_code(r, &mut self.echo);
                self.rw = paste::RecordWrite::default(); self.events += 1;
            }
            if matches!(mode, 0 | 4) && self.ld.input_cancelled() { self.q.clear(); self.rw = paste::RecordWrite::default(); self.paused = true; }
            else if matches!(mode, 1 | 2) && self.paused { self.q.clear(); self.paused = false; }
            self.ld.set_prompt_mode(if mode == 4 { 0 } else { mode });
            if matches!(mode, 1 | 2) && self.ld.finish_recovery(&mut self.q, &mut self.echo) { self.events += 1; }
        }
        fn read_byte(&mut self) -> Option<u8> {
            loop {
                if let Some(b) = self.pipe.pop_front() { return Some(b); }
                if !self.pump() {
                    self.flush(); if !self.pipe.is_empty() { continue; }
                    if self.at < self.src.len() {
                        if TRACE.with(|t|t.get()) {println!("  reader temporarily blocked: events={} latch={} cancelled={} refused={} remaining={}",self.events,self.latch,self.ld.input_cancelled(),self.ld.input_refused(),self.src.len()-self.at);}
                        self.wedge = true; return None;
                    }
                    if !self.finished { self.finished = true; self.terminal_input(None); self.flush(); continue; }
                    return None;
                }
            }
        }
    }
    thread_local! { pub static TRACE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
    pub fn on_mode(mode: u8) { with(|w| {
        if TRACE.with(|t| t.get()) { println!(" mode {mode} ev={} latch={} q={} pipe={} paused={}", w.events, w.latch, w.q.len(), w.pipe.len(), w.paused); }
        if w.race > 0 && w.r() % w.race == 0 { w.pump(); }
        w.control(mode);
        if w.events > 0 { w.latch = true; w.events = 0; }
        if w.race > 0 && w.r() % w.race == 0 { w.pump(); }
    }) }
    pub fn drain_events() { with(|w| if w.events > 0 { w.latch = true; w.events = 0; }) }
    pub fn take_latch() -> bool { with(|w| std::mem::take(&mut w.latch)) }
    pub fn discard() {
        on_mode(0);
        // Model the actual server's new INPUT_PAUSED reply. A mode change
        // by itself does not authorize a client-side pipe drain.
        if !with(|w| w.paused) { return; }
        let over = with(|w| { let over = w.pipe.len() > 4097 * 256; w.pipe.clear(); w.drain_over |= over; over });
        if over { on_mode(4); }
    }
    pub fn child_reads(program: &str) { with(|w| {
        let mut got = Vec::new();
        let line = |w: &mut W, got: &mut Vec<u8>| { while let Some(b) = w.read_byte() { got.push(b); if b == b'\n' { break; } } };
        if program == "/bin/headline" { line(w, &mut got); }
        else if program == "/bin/headb2004" { w.ld.child_output(b"\x1b[?20"); w.ld.child_output(b"04h"); line(w, &mut got); }
        else if program == "/bin/headnone2004" { w.ld.child_output(b"\x1b[?2004h"); }
        else if program == "/bin/headnone" { }
        else if program == "/bin/headflip" { w.ld.child_output(b"\x1b[?2004h"); line(w, &mut got); w.ld.child_output(b"\x1b[?2004l"); line(w, &mut got); }
        else { for _ in 0..10 { match w.read_byte() { Some(b) => got.push(b), None => break } } }
        w.child.extend(got);
    }) }
    struct Reader;
    impl Read for Reader {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            if b.is_empty() { return Ok(0); }
            Ok(with(|w| match w.read_byte() { Some(x) => { b[0] = x; w.wedge = false; w.shell_in.push(x); 1 } None => 0 }))
        }
    }
    pub struct R { pub files: BTreeMap<String, Vec<u8>>, pub err: String, pub out: String, pub echo: String, pub wedge: bool,
        pub plans: Vec<Vec<String>>, pub child: Vec<u8>, pub max_q: usize, pub max_pipe: usize, pub refused: bool, pub left: usize, pub shell_in: Vec<u8> }
    pub fn drive(src: &[u8], sizes: &[usize], seed: u64, race: u64, cap: usize) -> R {
        let src = [WAIT, src].concat();
        S.with(|s| *s.borrow_mut() = Some(W { ld: LineDiscipline::new(), q: Vec::new(), pipe: VecDeque::new(), cap,
            rw: paste::RecordWrite::default(), paused: false, events: 0, latch: false, src: src.to_vec(), at: 0,
            rng: seed.wrapping_mul(0x9E3779B97F4A7C15) | 1, sizes: sizes.to_vec(), race, echo: Vec::new(), child: Vec::new(),
            finished: false, last_mode: 0, wedge: false, max_q: 0, max_pipe: 0, drain_over: false, shell_in: Vec::new() }));
        let mut shell = Shell::new(fake(), "/".into());
        shell.host.writable = true;
        shell.host.programs.insert("/bin/headline".into(), Ok(Exit::Code(0)));
        shell.host.programs.insert("/bin/headbytes".into(), Ok(Exit::Code(0)));
        for p in ["/bin/headb2004", "/bin/headnone2004", "/bin/headnone", "/bin/headflip"] { shell.host.programs.insert(p.into(), Ok(Exit::Code(0))); }
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut input = BufReader::with_capacity(1, Reader);
        session(&mut shell, Mode::Interactive, &mut input, &mut out, &mut err);
        let w = S.with(|s| s.borrow_mut().take().unwrap());
        let files = shell.host.written.borrow().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        R { files, err: String::from_utf8_lossy(&err).into_owned(), out: String::from_utf8_lossy(&out).into_owned(),
            plans: shell.host.plans, echo: String::from_utf8_lossy(&w.echo).into_owned(), wedge: w.wedge, child: w.child, max_q: w.max_q,
            max_pipe: w.max_pipe, refused: w.ld.input_refused(), left: w.src.len() - w.at, shell_in: w.shell_in }
    }
    const SIZES: &[usize] = &[1,2,3,5,6,7,8,13,40,63,64,255,256,1023,1024,4095,4096,0];
    const CAPS: &[usize] = &[1, 7, 512, 4096, 65536];
    pub fn cr(s: &str) -> Vec<u8> { s.bytes().map(|b| if b == b'\n' { b'\r' } else { b }).collect() }
    pub fn bp(body: &[u8]) -> Vec<u8> { [paste::BEGIN.as_slice(), body, paste::END.as_slice()].concat() }
    /// Runs every schedule; `check` returns Err(reason) on a failure.
    pub fn tally(name: &str, src: &[u8], runs: u64, check: impl Fn(&R) -> Result<(), String>) {
        let (mut pass, mut fail, mut first) = (0, 0, None);
        let (mut mq, mut mp) = (0, 0);
        for set in 0..3 { for seed in 1..=runs {
            let sizes: Vec<usize> = match set { 0 => SIZES.to_vec(), 1 => vec![SIZES[(seed as usize) % SIZES.len()]], _ => vec![1 + (seed as usize * 37) % 4096] };
            let race = [0u64, 2, 3, 5][(seed % 4) as usize];
            let cap = CAPS[(seed as usize / 4) % CAPS.len()];
            let r = drive(src, &sizes, seed + 1000 * set as u64, race, cap);
            mq = mq.max(r.max_q); mp = mp.max(r.max_pipe);
            let res = if r.wedge { Err(format!("wedge left={}", r.left)) } else { check(&r) };
            match res { Ok(()) => pass += 1, Err(e) => { fail += 1; if first.is_none() {
                first = Some(format!("seed={seed} set={set} cap={cap} race={race}: {e}; files={:?} err={:?} echo_tail={:?}",
                    r.files.keys().collect::<Vec<_>>(), r.err.lines().take(3).collect::<Vec<_>>(), &r.echo[r.echo.len().saturating_sub(200)..])); } } }
        }}
        println!("[{name}] pass={pass} fail={fail} max_queue={mq} max_pipe={mp} first={first:?}");
        assert_eq!(fail, 0, "{name}: discarded or reordered input crossed an execution boundary");
    }
    fn has(r: &R, p: &str, want: &[u8]) -> Result<(), String> {
        match r.files.get(p) { Some(v) if v == want => Ok(()), Some(v) => Err(format!("{p} len {} want {}", v.len(), want.len())), None => Err(format!("{p} missing")) }
    }
    fn not(r: &R, p: &str) -> Result<(), String> { if r.files.contains_key(p) { Err(format!("{p} written")) } else { Ok(()) } }
    fn no_read_err(r: &R) -> Result<(), String> { if r.err.contains("read:") { Err(format!("shell exited: {}", r.err)) } else { Ok(()) } }

    #[test] fn d01_two_quoted_typed_and_pasted() {
        let b = "0123456789012345678901234567890123456789\n".repeat(50);
        let w = format!("\n{b}\n\n{b}\n");
        let text = format!("echo '\n{b}' >> /f\necho '\n{b}' >> /f\n");
        tally("01a two quoted typed", &cr(&text), 200, |r| { has(r, "/f", w.as_bytes())?; no_read_err(r) });
        let src = [bp(text.as_bytes()), b"\r".to_vec()].concat();
        tally("01b two quoted bracketed", &src, 200, |r| { has(r, "/f", w.as_bytes())?; no_read_err(r) });
    }
    #[test] fn d02_400_commands() {
        let mut s = String::new(); let mut want = String::new();
        for i in 0..400 { s.push_str(&format!("echo line-{i:05}-0123456789012345678901234567 >> /f\n")); want.push_str(&format!("line-{i:05}-0123456789012345678901234567\n")); }
        tally("02a 400 typed", &cr(&s), 100, |r| has(r, "/f", want.as_bytes()));
        let src = [bp(s.as_bytes()), b"\r".to_vec()].concat();
        tally("02b 400 bracketed", &src, 100, |r| has(r, "/f", want.as_bytes()));
    }
    #[test] fn d03_guard_drop() {
        let t = "echo first > /a\ncd /nonexistent && echo tail > /oops\n";
        let chk = |r: &R| { has(r, "/a", b"first\n")?; not(r, "/oops") };
        tally("03a guard typed", &cr(t), 300, chk);
        tally("03b guard bracketed", &[bp(t.as_bytes()), b"\r".to_vec()].concat(), 300, chk);
    }
    #[test] fn d04_ctrl_c_queued_quoted() {
        let src = b"echo 'body\recho EXECUTED > /victim\r\x03more'\r".to_vec();
        tally("04a ^C queued typed", &src, 300, |r| { not(r, "/victim")?; if !r.out.ends_with("absd$ ") && !r.out.contains("absd$ absd$ ") { /* fine */ } Ok(()) });
        // Steward2054Z: a complete more' line first offered after rearm is
        // typing, and may start a new continuation. Explicitly cancel that
        // possible continuation before checking a fresh command.
        let src = [bp(b"echo 'body\necho EXECUTED > /victim\n"), b"\r\x03more'\r".to_vec(), WAIT.to_vec(), b"\x03".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        tally("04b ^C queued bracketed + operator cancel + fresh", &src, 300, |r| { not(r, "/victim")?; has(r, "/h", b"fresh\n")?; no_read_err(r) });
        // Prompt redraw: after ^C at a continuation prompt the next prompt is primary.
        let r = drive(&[b"echo 'a\r".to_vec(), WAIT.to_vec(), b"\x03".to_vec(), WAIT.to_vec()].concat(), &[4096], 1, 0, 4096);
        println!("[04c redraw] out={:?} echo={:?}", r.out, r.echo);
    }
    #[test] fn d04_complete_post_rearm_line_can_start_a_new_continuation() {
        // Exact original failed schedule, accepted known limit2054Z.
        let src=[bp(b"echo 'body\necho EXECUTED > /victim\n"),b"\r\x03more'\r".to_vec(),WAIT.to_vec(),b"echo fresh > /h\r".to_vec()].concat();
        let r=drive(&src,&[7],1023,5,1);
        not(&r,"/victim").unwrap();not(&r,"/h").unwrap();
        assert!(r.err.contains("unmatched `'`"));assert!(r.out.ends_with("> > "));
    }
    #[test] fn d05_5000_and_overlong() {
        let x = "x".repeat(5000);
        let want = format!("{x}\n");
        tally("05a 5000-byte line", &cr(&format!("echo '{x}' > /f\necho after > /g\n")), 200, |r| { has(r, "/f", want.as_bytes())?; has(r, "/g", b"after\n") });
        let x = "x".repeat(MAX_LINE + 10);
        let src = [cr(&format!("echo '{x}' > /f\necho after > /g\n")), CODE.to_vec(), b"\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        tally("05b overlong + code + fresh", &src, 100, |r| { not(r, "/f")?; not(r, "/g")?; has(r, "/h", b"fresh\n")?; no_read_err(r) });
        let src = [cr(&format!("echo '{x}' > /f\necho after > /g\n")), b"\x03\x03echo late > /late\r".to_vec()].concat();
        tally("05c overlong, ^C does not release", &src, 100, |r| { not(r, "/f")?; not(r, "/g")?; not(r, "/late") });
    }
    #[test] fn d06_invalid_utf8() {
        let src = [b"echo caf\xe9 > /f\recho next > /g\r".to_vec(), CODE.to_vec(), b"\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        tally("06 invalid utf8 + code + fresh", &src, 300, |r| { not(r, "/f")?; not(r, "/g")?; has(r, "/h", b"fresh\n")?; no_read_err(r) });
    }
    #[test] fn d07_ctrl_c_mid_record() {
        let mut body = String::new(); for i in 0..3000 { body.push_str(&format!("echo l-{i:05} >> /f\n")); }
        let mut want = String::new(); for i in 0..3000 { want.push_str(&format!("l-{i:05}\n")); }
        // Steward2052Z: this record claim requires BEGIN at a prompt.
        // The old prior-command race is retained in its named known-limit test.
        let src = [bp(body.as_bytes()), b"\r\x03".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        tally("07 prompt-owned ^C mid-record", &src, 200, |r| {
            if let Some(f) = r.files.get("/f") && f != want.as_bytes() { return Err(format!("partial record ran: {}", f.len())); }
            has(r, "/h", b"fresh\n")?; no_read_err(r) });
        // UTF-8 split by padding.
        let body = "echo é > /u\n".repeat(2000);
        let src = [bp(body.as_bytes()), b"\r\x03".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        tally("07b ^C mid-record utf8", &src, 200, |r| { has(r, "/h", b"fresh\n")?; no_read_err(r) });
    }
    #[test] fn d07_application_owned_paste_can_become_inherited_shell_input() {
        // Exact old failed schedule. BEGIN completes during mode0 for the
        // preceding command; no application reads it. It is cooked input,
        // not one atomic source record, and Ctrl-C cannot undo prior effects.
        let body=(0..3000).map(|i| format!("echo l-{i:05} >> /f\n")).collect::<String>();
        let src=[b"echo start > /s\r".to_vec(),bp(body.as_bytes()),b"\r\x03".to_vec(),WAIT.to_vec(),b"echo fresh > /h\r".to_vec()].concat();
        let r=drive(&src,&[6],1058,3,65536);
        has(&r,"/s",b"start\n").unwrap();has(&r,"/h",b"fresh\n").unwrap();
        let observed=r.files.get("/f").expect("known inherited application bytes became shell input");
        assert!(!observed.is_empty() && observed.len()<3000*8);
        no_read_err(&r).unwrap();
    }
    #[test] fn d08_overflow_boundaries_under_2028_contract() {
        let x = "x".repeat(MAX_LINE + 10);
        let body = format!("echo '{x}'\necho SUFFIX > /oops\n");
        let src = [bp(body.as_bytes()), b"\recho tail > /t\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        // Owner/steward 2028Z: a complete later line at the recovered
        // prompt is indistinguishable from fresh typing. A discarded prefix
        // must never become a shortened command or an empty redirected file.
        tally("08a END recovery: no partial tail; complete later command is a known limit", &src, 100, |r| {
            not(r, "/oops")?; no_suffix(r, "echo tail > /t")?;
            if let Some(tail)=r.files.get("/t") && tail!=b"tail\n" {
                return Err(format!("shortened tail executed: {tail:?}"));
            }
            has(r, "/h", b"fresh\n")?; no_read_err(r)
        });
        let body = format!("echo SUFFIX > /oops\necho '{x}'\n");
        let src = [bp(body.as_bytes()), b"\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        tally("08b first line fine, later overflow", &src, 100, |r| { not(r, "/oops")?; has(r, "/h", b"fresh\n") });
        // Source budget > 1 MiB across lines.
        let body = format!("{}\n", "y".repeat(60000)).repeat(20);
        let src = [bp(format!("echo '\n{body}' > /big\n").as_bytes()), b"\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        tally("08c 1.2 MiB paste refused", &src, 20, |r| { not(r, "/big")?; has(r, "/h", b"fresh\n") });
    }
    #[test] fn d08_complete_tail_after_rearm_has_no_observable_origin() {
        let x="x".repeat(MAX_LINE+10);
        let body=format!("echo '{x}'\necho SUFFIX > /oops\n");
        let prefix=bp(body.as_bytes());
        let tail=b"\recho tail > /t\r";
        let fresh=b"echo fresh > /h\r";
        let old=[prefix.clone(),tail.to_vec(),WAIT.to_vec(),fresh.to_vec()].concat();
        let human=[prefix.clone(),WAIT.to_vec(),tail.to_vec(),WAIT.to_vec(),fresh.to_vec()].concat();
        // WAIT is a fixture-only human pause, never a byte on the SSH wire.
        let wire=|input:&[u8]|input.split(|b|*b==0).filter(|p|*p!=b"WAIT").flatten().copied().collect::<Vec<_>>();
        assert_eq!(wire(&old),wire(&human));
        let old=drive(&old,&[6],4,0,7);
        let human=drive(&human,&[6],4,0,7);
        assert_eq!(old.files.get("/t"),Some(&b"tail\n".to_vec()));
        assert_eq!(human.files.get("/t"),Some(&b"tail\n".to_vec()));
        assert_eq!(old.files,human.files);
        assert!(old.files.contains_key("/h"));assert!(!old.files.contains_key("/oops"));
        println!("COMPLETE TAIL ORIGIN: prewritten and human-wait input have identical wire bytes and file outcomes at the recovered prompt; both execute /t");
    }
    #[test] fn d09_ctrl_c_then_paste_straddle() {
        let src = [b"\x03".to_vec(), bp(b"echo one > /one\necho SUFFIX > /oops\n"), b"\r".to_vec()].concat();
        tally("09 ^C then immediate paste", &src, 300, |r| { if r.files.contains_key("/oops") && !r.files.contains_key("/one") { Err("paste tail ran without its head".into()) } else { Ok(()) } });
    }
    #[test] fn d09b_ctrl_c_paste_without_enter() {
        let src = [b"\x03".to_vec(), bp(b"echo one > /one\necho SUFFIX > /oops\n")].concat();
        tally("09b ^C then paste, no Enter", &src, 300, |r| { not(r, "/oops") });
    }
    #[test] fn d10_child_reads_record() {
        let src = [b"headline\r".to_vec(), bp(b"echo pasted > /p\n"), b"\r".to_vec()].concat();
        let r = drive(&src, &[4096], 1, 0, 4096);
        println!("[10a typeahead record into child] child={:?} files={:?} err={:?}", String::from_utf8_lossy(&r.child), r.files.keys().collect::<Vec<_>>(), r.err);
        let src = [b"headbytes\r".to_vec(), bp("ééééé\n".as_bytes()), b"\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        let r = drive(&src, &[4096], 1, 0, 4096);
        println!("[10b partial record consumer] child={:?} files={:?} err={:?} left={}", r.child, r.files.keys().collect::<Vec<_>>(), r.err, r.left);
        let src = "headbytes\raéééééééé\recho fresh > /h\r".as_bytes().to_vec();
        let r = drive(&src, &[4096], 1, 0, 4096);
        println!("[10c typed partial consumer (no record)] files={:?} err={:?}", r.files.keys().collect::<Vec<_>>(), r.err);
    }
    #[test] fn z_trace() {
        let which = std::env::var("DVT").unwrap_or_default();
        TRACE.with(|t| t.set(true));
        if which == "R04" {
            let x = "x".repeat(MAX_LINE + 10);
            let body = format!("echo '{x}'\necho SUFFIX > /oops\n");
            let src = [bp(body.as_bytes()), b"\recho tail > /t\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
            let seed: u64 = std::env::var("SEED").unwrap().parse().unwrap();
            let sizes: Vec<usize> = SIZES.to_vec(); let race = [0u64, 2, 3, 5][(seed % 4) as usize]; let cap = CAPS[(seed as usize / 4) % CAPS.len()];
            let r = drive(&src, &sizes, seed, race, cap);
            println!("files={:?} shell_in={:?} echo_tail={:?}", r.files.keys().collect::<Vec<_>>(), String::from_utf8_lossy(&r.shell_in), &r.echo[r.echo.len().saturating_sub(400)..]);
        }
        if which == "x01" {
            let src=[b"echo x\r\x03".to_vec(),bp(b"echo one > /one\necho SUFFIX > /oops\n"),WAIT.to_vec(),b"echo fresh > /h\r".to_vec()].concat();
            let r=drive(&src,SIZES,8,0,512);
            println!("X01 observed files={:?} shell={:?}",r.files,String::from_utf8_lossy(&r.shell_in));
        }
        if which == "x07" {
            let src=[b"headb2004\r".to_vec(),bp(b"1048576\nhello\n"),b"\x03".to_vec(),WAIT.to_vec(),b"echo fresh > /h\r".to_vec()].concat();
            let r=drive(&src,SIZES,29,2,512);
            println!("X07 observed files={:?} child={:?} wedge={} left={} shell={:?}",r.files,r.child,r.wedge,r.left,String::from_utf8_lossy(&r.shell_in));
        }
        if which == "04" {
            let src = [bp(b"echo 'body\necho EXECUTED > /victim\n"), b"\r\x03more'\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
            let r=drive(&src,&[7],1023,5,1);
            println!("files={:?} err={:?} out={:?}",r.files,r.err,r.out);
        }
        if which == "07" {
            let mut body = String::new(); for i in 0..3000 { body.push_str(&format!("echo l-{i:05} >> /f\n")); }
            let src = [b"echo start > /s\r".to_vec(), bp(body.as_bytes()), b"\r\x03".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
            let r = drive(&src, &[6], 58 + 1000, 3, 65536);
            println!("files={:?} f={:?}", r.files.keys().collect::<Vec<_>>(), r.files.get("/f").map(Vec::len));
        }
        if which == "12" {
            let body = format!("{}\n", "y".repeat(60000)).repeat(18);
            let src = [cr(&format!("echo '\n{body}' > /big\n")), b"echo after > /g\r".to_vec(), CODE.to_vec(), b"\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
            let r = drive(&src, SIZES, 5, 2, 7);
            println!("files={:?} err={:?}", r.files.keys().collect::<Vec<_>>(), r.err);
        }
        if which == "08" {
            let x = "x".repeat(MAX_LINE + 10);
            let body = format!("echo '{x}'\necho SUFFIX > /oops\n");
            let src = [bp(body.as_bytes()), b"\recho tail > /t\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
            let r = drive(&src, SIZES, 18, 3, 65536);
            println!("files={:?} wedge={} refused={} echo_tail={:?}", r.files.keys().collect::<Vec<_>>(), r.wedge, r.refused, &r.echo[r.echo.len()-300..]);
        }
    }
    #[test] fn d12_mode4_and_exec() {
        let body = format!("{}\n", "y".repeat(60000)).repeat(18);
        let src = [cr(&format!("echo '\n{body}' > /big\n")), b"echo after > /g\r".to_vec(), CODE.to_vec(), b"\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        tally("12a typed >1 MiB shell source (mode 4)", &src, 30, |r| { not(r, "/big")?; not(r, "/g")?; has(r, "/h", b"fresh\n")?; no_read_err(r) });
        // No shell control channel (exec session): no mode changes ever arrive.
        let mut ld = LineDiscipline::new(); let (mut c, mut e) = (Vec::new(), Vec::new());
        ld.input(b"\xff", &mut c, &mut e); ld.recovery_code([3;8], &mut e);
        ld.input(b"0303030303030303\r", &mut c, &mut e);
        let ev = ld.input(b"\x03", &mut c, &mut e);
        ld.input(b"typed\r", &mut c, &mut e);
        println!("[12b exec pty: after correct code] refused={} ^C_event={} delivered={:?}", ld.input_refused(), ev.interrupt, String::from_utf8_lossy(&c));
    }
    #[test] fn d11_challenge_reuse_and_ordinary() {
        // An old code in in-flight bytes after a second refusal must not release.
        let mut ld = LineDiscipline::new(); ld.set_prompt_mode(1);
        let (mut c, mut e) = (Vec::new(), Vec::new());
        ld.input(b"\xff", &mut c, &mut e); ld.recovery_code([1;8], &mut e);
        ld.set_prompt_mode(0); ld.input(b"0101010101010101\r", &mut c, &mut e);
        assert!(!ld.input_refused());
        ld.set_prompt_mode(0); ld.set_prompt_mode(1);
        ld.input(&[b'z'; MAX_LINE + 1], &mut c, &mut e); ld.recovery_code([2;8], &mut e);
        ld.input(b"0101010101010101\r", &mut c, &mut e);
        println!("[11a stale code after second refusal] still_refused={}", ld.input_refused());
        assert!(ld.input_refused());
        // Ordinary typing with edits, history and ^C: compare with the base expectations.
        let src = b"echo a > /a\recho bb\x7f > /b\recho c\x1b[D\x1b[Cx > /c\r\x1b[A\x15echo d > /d\r".to_vec();
        tally("11b ordinary typing", &src, 200, |r| { has(r, "/a", b"a\n")?; has(r, "/b", b"b\n")?; has(r, "/c", b"cx\n")?; has(r, "/d", b"d\n") });
    }

    // ===== round-2 independent review additions (claude git-0a) =====
    pub fn t2(name: &str, src: &[u8], runs: u64, check: impl Fn(&R) -> Result<(), String>, kl: impl Fn(&R) -> bool) {
        let (mut pass, mut fail, mut known, mut first, mut firstk) = (0, 0, 0, None, None);
        let (mut mq, mut mp) = (0, 0);
        for set in 0..3 { for seed in 1..=runs {
            let sizes: Vec<usize> = match set { 0 => SIZES.to_vec(), 1 => vec![SIZES[(seed as usize) % SIZES.len()]], _ => vec![1 + (seed as usize * 37) % 4096] };
            let race = [0u64, 2, 3, 5][(seed % 4) as usize];
            let cap = CAPS[(seed as usize / 4) % CAPS.len()];
            let r = drive(src, &sizes, seed + 1000 * set as u64, race, cap);
            mq = mq.max(r.max_q); mp = mp.max(r.max_pipe);
            let res = if r.wedge { Err(format!("wedge left={}", r.left)) } else { check(&r) };
            match res { Ok(()) => pass += 1,
                Err(e) if !r.wedge && kl(&r) => { known += 1; if firstk.is_none() { firstk = Some(format!("seed={seed} set={set}: {e}")); } }
                Err(e) => { fail += 1; if first.is_none() {
                first = Some(format!("seed={seed} set={set} cap={cap} race={race}: {e}; files={:?} err={:?} shell_in_tail={:?}",
                    r.files.keys().collect::<Vec<_>>(), r.err.lines().take(3).collect::<Vec<_>>(), String::from_utf8_lossy(&r.shell_in[r.shell_in.len().saturating_sub(120)..]))); } } }
        }}
        println!("[R2 {name}] pass={pass} fail={fail} known_limit={known} max_queue={mq} max_pipe={mp} first={first:?} first_known={firstk:?}");
        assert_eq!(fail, 0, "{name}: independent review schedules failed");
    }
    fn lines(r: &R) -> Vec<String> { r.shell_in.split(|&b| b == b'\n').map(|l| String::from_utf8_lossy(l).into_owned()).collect() }
    fn no_suffix(r: &R, full: &str) -> Result<(), String> {
        for l in lines(r) { if !l.is_empty() && l.len() < full.len() && full.ends_with(l.as_str()) { return Err(format!("shell read suffix {l:?} of {full:?}")); } }
        Ok(())
    }
    fn whole_line(r: &R, full: &str) -> bool { lines(r).iter().any(|l| l == full) }
    fn never(_: &R) -> bool { false }

    #[test] fn x01_ctrl_c_paste_no_enter() {
        let src = [b"\x03".to_vec(), bp(b"echo one > /one\necho SUFFIX > /oops\n")].concat();
        t2("x01 ^C then paste, no Enter", &src, 300, |r| { not(r, "/oops")?; not(r, "/one") }, never);
        let src = [b"echo x\r\x03".to_vec(), bp(b"echo one > /one\necho SUFFIX > /oops\n"), WAIT.to_vec(), b"\x03".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        t2("x01b typed+^C then paste, explicit cancel, later fresh", &src, 300, |r| { not(r, "/oops")?; not(r, "/one")?; no_read_err(r) }, never);
    }
    #[test] fn x01b_later_enter_approves_a_valid_paste_received_after_rearm() {
        // Steward2150Z: exact original failed schedule, normal approval.
        let src=[b"echo x\r\x03".to_vec(),bp(b"echo one > /one\necho SUFFIX > /oops\n"),WAIT.to_vec(),b"echo fresh > /h\r".to_vec()].concat();
        let r=drive(&src,SIZES,8,0,512);
        has(&r,"/one",b"one\n").unwrap();has(&r,"/oops",b"SUFFIX\n").unwrap();has(&r,"/h",b"fresh\n").unwrap();
        assert!(r.shell_in.windows(INPUT_RECORD_PREFIX.len()).any(|w|w==INPUT_RECORD_PREFIX.as_bytes()));
        no_read_err(&r).unwrap();
    }
    #[test] fn x02_tail_without_head() {
        let src = [b"\x03".to_vec(), bp(b"echo one > /one\necho SUFFIX > /oops\n"), b"\r".to_vec()].concat();
        t2("x02 ^C then paste+Enter: tail never without head", &src, 300, |r| {
            if r.files.contains_key("/oops") && !r.files.contains_key("/one") { return Err("tail without head".into()); }
            no_suffix(r, "echo SUFFIX > /oops")?; no_suffix(r, "echo one > /one") }, never);
    }
    #[test] fn x03_ctrl_c_more_quote() {
        let src = b"echo 'body\recho EXECUTED > /victim\r\x03more'\r".to_vec();
        t2("x03a ^C more' typed", &src, 300, |r| { not(r, "/victim")?; no_suffix(r, "more'") }, never);
        let src = [bp(b"echo 'body\necho EXECUTED > /victim\n"), b"\r\x03more'\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        // Known limit (2054Z): the complete line more' first offered after rearm may open a continuation.
        t2("x03b ^C more' bracketed + fresh (original check)", &src, 300,
            |r| { not(r, "/victim")?; no_suffix(r, "more'")?; has(r, "/h", b"fresh\n")?; no_read_err(r) },
            |r| not(r, "/victim").is_ok() && no_suffix(r, "more'").is_ok() && whole_line(r, "more'"));
    }
    #[test] fn x04_o_tail_after_end_release() {
        let x = "x".repeat(MAX_LINE + 10);
        let body = format!("echo '{x}'\necho SUFFIX > /oops\n");
        let src = [bp(body.as_bytes()), b"\recho tail > /t\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        t2("x04 END release: no o-tail", &src, 100, |r| {
            not(r, "/oops")?; no_suffix(r, "echo tail > /t")?;
            if let Some(t) = r.files.get("/t") && t != b"tail\n" { return Err(format!("/t={t:?}")); }
            has(r, "/h", b"fresh\n")?; no_read_err(r) }, never);
    }
    #[test] fn x04b_partial_line_consumed_while_end_is_latched() {
        let x = "x".repeat(MAX_LINE + 10);
        let body = format!("echo '{x}'\necho SUFFIX > /oops\n");
        // Partial line consumed while the refusal is latched, then a human pause.
        let src = [bp(body.as_bytes()), b"echo t".to_vec(), WAIT.to_vec(), b"ail > /t\r".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        t2("x04b END latch + partial line + pause", &src, 100, |r| {
            not(r, "/oops")?; no_suffix(r, "echo tail > /t")?;
            if let Some(file)=r.files.get("/t") && file!=b"tail\n" {return Err(format!("shortened command created /t={file:?}"));}
            has(r, "/h", b"fresh\n") }, never);
    }
    #[test] fn x05_double_interrupt_fresh_typing() {
        let src = [b"echo a > /a\r\x03\x03".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        t2("x05a ^C^C then fresh", &src, 300, |r| has(r, "/h", b"fresh\n"), never);
        let src = [b"\x03".to_vec(), WAIT.to_vec(), b"\x03\x03\x03".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        t2("x05b ^C, ^C^C^C then fresh", &src, 300, |r| has(r, "/h", b"fresh\n"), never);
        let src = [b"echo caf\xe9 > /f\r".to_vec(), CODE.to_vec(), b"\r\x03".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        t2("x05c code Enter + ^C then fresh", &src, 300, |r| { not(r, "/f")?; has(r, "/h", b"fresh\n") }, never);
    }
    #[test] fn x06_end_latches() {
        let src = [bp(b"echo pre > /p\necho \xc3"), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        t2("x06a prompt paste incomplete UTF-8 at END: no code, recovers", &src, 200, |r| { not(r, "/p")?; has(r, "/h", b"fresh\n")?; no_read_err(r) }, never);
        let src = [b"echo ".to_vec(), vec![b'x'; 40000], b"\x1b[H".to_vec(), bp(&vec![b'y'; 30000]), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        t2("x06b composed overflow at END: no code, recovers", &src, 60, |r| { has(r, "/h", b"fresh\n")?; if r.files.len() != 1 { return Err(format!("{:?}", r.files.keys())); } no_read_err(r) }, never);
    }
    #[test] fn x07_witness_and_app_owned() {
        // An application that asked for 2004h gets BEGIN + "1048576" as its first line.
        let src = [b"headb2004\r".to_vec(), bp(b"1048576\nhello\n"), b"\x03".to_vec(), WAIT.to_vec(), b"echo fresh > /h\r".to_vec()].concat();
        t2("x07a 2004h app, witness first line", &src, 100, |r| { no_read_err(r)?; has(r, "/h", b"fresh\n") }, never);
        let r = drive(&src, &[4096], 3, 0, 4096);
        println!("[R2 x07a sample] child={:?} shell_in={:?} err={:?}", String::from_utf8_lossy(&r.child), String::from_utf8_lossy(&r.shell_in), r.err);
        let src = [b"headflip\r".to_vec(), bp(b"one\ntwo\n"), b"\r".to_vec()].concat();
        let r = drive(&src, &[4096], 5, 0, 4096);
        println!("[R2 x07b flip mid-paste] child={:?} shell_in={:?}", String::from_utf8_lossy(&r.child), String::from_utf8_lossy(&r.shell_in));
    }
}
#[test]
fn missing_heredoc_delimiter_is_continuation_and_named_eof_error() {
    for source in ["cat <<EOF\n", "cat <<EOF\npayload\n", "cat <<EOF\npayload", "cat <<'END'\nEND-not\n"] {
        assert!(language::incomplete(source), "{source:?}");
        let error = language::parse_program(source).unwrap_err();
        assert!(error.contains("unterminated heredoc"), "{error}");
    }
}

#[test]
fn heredoc_delimiter_at_eof_is_complete_without_trailing_newline() {
    use conch_parser::{lexer::Lexer, parse::DefaultParser};
    for source in ["cat <<EOF\npayload\nEOF", "cat <<EOF\nEOF", "cat <<-EOF\n\tpayload\n\tEOF"] {
        let parsed = DefaultParser::new(Lexer::new(source.chars())).into_iter().collect::<Result<Vec<_>, _>>();
        assert!(parsed.is_ok(), "{parsed:?}");
        assert!(!language::incomplete(source));
    }
}

#[test]
fn unterminated_heredoc_refuses_whole_script_before_prior_effects() {
    for mode in [Mode::Command("echo before > /marker; cat <<EOF\npayload\n".into()), Mode::Stdin(Vec::new())] {
        let (status, text, shell) = console(mode, "echo before > /marker; cat <<EOF\npayload\n");
        assert_eq!(status, STATUS_USAGE);
        assert!(text.contains("unterminated heredoc"), "{text}");
        assert!(shell.host.runs.is_empty());
        assert!(shell.host.opened.is_empty());
    }
}

#[test]
fn heredoc_expanded_body_exact_limit_and_overflow_precede_consumer_spawn() {
    for (size, ok) in [(MAX_SCRIPT_BYTES - 1, true), (MAX_SCRIPT_BYTES, false)] {
        let mut shell = Shell::new(fake(), "/".into());
        shell.vars.insert("BODY".into(), "x".repeat(size));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        shell.run_line("/bin/ls <<EOF\n$BODY\nEOF\n", &mut out, &mut err);
        if ok {
            assert_eq!(shell.status, 0, "{}", String::from_utf8_lossy(&err));
            assert_eq!(shell.host.runs.len(), 1);
            let body = shell.host.plans[0][0].split_once(" in=bytes:").unwrap().1.split_once(" out=").unwrap().0;
            assert_eq!(body.len(), MAX_SCRIPT_BYTES + 1); // final newline is escaped
        } else {
            assert_eq!(shell.status, STATUS_USAGE);
            assert!(String::from_utf8_lossy(&err).contains("heredoc exceeds 1 MiB"));
            assert!(shell.host.runs.is_empty());
            assert!(shell.host.opened.is_empty());
        }
    }
}

#[test]
fn heredoc_keeps_authority_and_rejects_duplicate_or_pipeline_input_before_effects() {
    let mut shell = Shell::new(fake(), "/".into());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line("nofs /bin/ls <<EOF\nbody\nEOF\n", &mut out, &mut err);
    assert_eq!(shell.status, 0, "{}", String::from_utf8_lossy(&err));
    assert_eq!(shell.host.authorities, [Authority::None]);
    assert!(shell.host.opened.is_empty());
    for source in ["echo before > /marker; /bin/ls < /input <<EOF\nbody\nEOF\n", "echo before > /marker; /bin/ls <<ONE <<TWO\na\nONE\nb\nTWO\n", "echo before > /marker; /bin/ls | /bin/ls <<EOF\nbody\nEOF\n", "echo before > /marker; sh -c true <<EOF\nbody\nEOF\n"] {
        let (_, text, refused) = console(Mode::Command(source.into()), "");
        assert!(!text.is_empty());
        assert!(refused.host.runs.is_empty(), "{source}");
        assert!(refused.host.opened.is_empty(), "{source}");
    }
}

#[test]
fn prompt_interrupt_discards_accumulated_heredoc_without_starting_consumer() {
    let mut shell = Shell::new(fake(), "/".into());
    shell.host.cancel_on_line = Some(2);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    session(&mut shell, Mode::Interactive, &mut "/bin/ls <<EOF\nbody\necho restored\nexit\n".as_bytes(), &mut out, &mut err);
    assert!(shell.host.runs.is_empty());
    assert!(String::from_utf8(out).unwrap().contains("restored\n"));
    assert!(err.is_empty());
}

#[test]
fn heredoc_source_exact_limit_and_one_byte_over_use_the_existing_source_bound() {
    let header = "/bin/ls <<'EOF'\n";
    let suffix = "\nEOF\n";
    let source = format!("{header}{}{suffix}", "x".repeat(MAX_SCRIPT_BYTES - header.len() - suffix.len()));
    assert_eq!(source.len(), MAX_SCRIPT_BYTES);
    assert!(language::parse_program(&source).is_ok());
    assert_eq!(language::parse_program(&(source + "\n")).unwrap_err(), "script exceeds 1 MiB");
}

#[test]
fn interactive_heredoc_does_not_reparse_every_body_line() {
    language::CONTINUATION_PARSE_CALLS.with(|count| count.set(0));
    let source = format!("/bin/ls <<EOF\n{}EOF\nexit\n", "body line with literal text\n".repeat(64));
    let (status, _, shell) = console(Mode::Interactive, &source);
    assert_eq!(status, 0);
    assert_eq!(shell.host.runs.len(), 1);
    let calls = language::CONTINUATION_PARSE_CALLS.with(|count| count.get());
    assert!(calls <= 4, "reparsed {calls} times for64 body lines");
}

#[test]
fn interactive_heredoc_uses_parser_quote_tab_and_compound_state() {
    for source in ["/bin/ls <<-E\"O\"F\n\tpayload\n\tEOF\t\n\tEOF\nexit\n", "if true; then\n/bin/ls <<EOF\npayload\nEOF\nfi\nexit\n"] {
        let (status, _, shell) = console(Mode::Interactive, source);
        assert_eq!(status, 0);
        assert_eq!(shell.host.runs.len(), 1);
        assert!(shell.host.plans[0][0].contains("bytes:payload\\n"));
    }
}

#[test]
fn interactive_heredoc_large_pastes_reparse_at_delimiter_only() {
    let line = "0123456789012345678901234567890123456789\n";
    for budget in [64 * 1024, 256 * 1024, MAX_SCRIPT_BYTES - 128] {
        language::CONTINUATION_PARSE_CALLS.with(|count| count.set(0));
        let source = format!("/bin/ls <<EOF\n{}EOF\nexit\n", line.repeat(budget / line.len()));
        assert!(source.len() <= MAX_SCRIPT_BYTES);
        let start = std::time::Instant::now();
        let (status, _, shell) = console(Mode::Interactive, &source);
        let calls = language::CONTINUATION_PARSE_CALLS.with(|count| count.get());
        assert_eq!(status, 0);
        assert_eq!(shell.host.runs.len(), 1);
        assert!(calls <= 4, "{}bytes caused {calls} reparses", source.len());
        eprintln!("HEREDOC PASTE bytes={} parser_calls={} elapsed_ms={}", source.len(), calls, start.elapsed().as_millis());
    }
}

#[test]
fn heredoc_composition_cancel_clears_delimiter_before_fresh_command() {
    let src = [b"cat <<EOF\r".as_slice(), dv::WAIT, b"\x03", dv::WAIT,
        b"echo fresh > /fresh\r", dv::WAIT].concat();
    let r = dv::drive(&src, &[4096], 1, 0, 4096);
    assert!(!r.wedge, "{}", r.err);
    assert_eq!(r.files.get("/fresh").map(Vec::as_slice), Some(b"fresh\n".as_slice()));
    assert!(r.out.ends_with("absd$ "), "stale heredoc continuation: {:?}", r.out);
}

#[test]
fn heredoc_composition_pasted_body_finishes_at_delimiter_inside_record() {
    let src = [b"cat <<EOF\r".to_vec(), dv::WAIT.to_vec(),
        dv::bp(b"body\nEOF\necho fresh > /fresh\n"), b"\r".to_vec(), dv::WAIT.to_vec()].concat();
    let r = dv::drive(&src, &[4096], 1, 0, 4096);
    assert!(!r.wedge, "{}", r.err);
    assert_eq!(r.files.get("/fresh").map(Vec::as_slice), Some(b"fresh\n".as_slice()));
    assert!(r.out.ends_with("absd$ "), "record delimiter not recognized: {:?}", r.out);
    assert!(r.err.is_empty(), "{}", r.err);
}

#[test]
fn heredoc_composition_fragmented_paste_and_continuation_schedules() {
    let body = "0123456789é🙂\n".repeat(64);
    let rest = format!("{body}EOF\necho fresh > /fresh\n");
    for source in [
        dv::cr(&format!("cat <<EOF\n{rest}")),
        [dv::bp(format!("cat <<EOF\n{rest}").as_bytes()), b"\r".to_vec()].concat(),
        [b"cat <<EOF\r".to_vec(), dv::WAIT.to_vec(), dv::bp(rest.as_bytes()), b"\r".to_vec()].concat(),
    ] {
        dv::tally("heredoc composition", &source, 20, |r| {
            if r.files.get("/fresh").map(Vec::as_slice) != Some(b"fresh\n".as_slice()) {
                return Err("following command did not execute".into());
            }
            if !r.err.is_empty() { return Err(r.err.clone()); }
            if !r.out.ends_with("absd$ ") { return Err(format!("pending continuation {:?}", r.out)); }
            Ok(())
        });
    }
}

#[test]
fn heredoc_composition_original_65600_bytes_reach_consumer_across_batches() {
    let body = "0123456789012345678901234567890123456789\n".repeat(1600);
    assert_eq!(body.len(), 65600);
    let source = format!("cat <<'PASTE'\n{body}PASTE\necho done > /done\n");
    let want = format!("/bin/cat in=bytes:{} out=inherit err=inherit", body.escape_debug());
    for (sizes, race, cap) in [(vec![1024], 2, 512), (vec![1,7,1024,4096], 3, 7), (vec![4096], 0, 4096)] {
        for bytes in [dv::cr(&source), [dv::bp(source.as_bytes()), b"\r".to_vec()].concat()] {
            let r = dv::drive(&bytes, &sizes, 77, race, cap);
            assert!(!r.wedge, "{}", r.err);
            assert_eq!(r.plans.first(), Some(&vec![want.clone()]));
            assert_eq!(r.files.get("/done").map(Vec::as_slice),Some(b"done\n".as_slice()));
            assert!(r.err.is_empty(), "{}", r.err);
        }
    }
}

#[test]
fn heredoc_composition_review_tab_delimiter() {
    let r = dv::drive(&dv::cr("cat <<-EOF\n\tbody\n\tEOF\necho fresh > /fresh\n"), &[1, 4096], 3, 0, 4096);
    assert!(!r.wedge);
    assert_eq!(r.plans.first(), Some(&vec!["/bin/cat in=bytes:body\\n out=inherit err=inherit".to_string()]));
    assert_eq!(r.files.get("/fresh").map(Vec::as_slice), Some(b"fresh\n".as_slice()));
    assert!(r.out.ends_with("absd$ "));
    assert!(r.err.is_empty(), "{}", r.err);
}

#[test]
fn heredoc_composition_review_cancel_races() {
    let src = [b"cat <<EOF > /bad\r".as_slice(), dv::WAIT, b"x\r\x03",
        dv::WAIT, b"echo fresh > /fresh\r", dv::WAIT].concat();
    dv::tally("heredoc cancellation race", &src, 40, |r| {
        if r.files.get("/fresh").map(Vec::as_slice) != Some(b"fresh\n".as_slice()) {
            return Err(format!("fresh command missing: {:?}", r.out));
        }
        if r.files.contains_key("/bad") || r.plans.iter().flatten().any(|p| p.contains("/bin/cat")) {
            return Err("cancelled heredoc executed".into());
        }
        Ok(())
    });
}

#[test]
fn delimiter172_interactive_split_delimiter_reparses_joined_line() {
    let source = "/bin/ls <<EOF\npayload\nEO\\\nF\necho done\nexit\n";
    let (status, text, shell) = console(Mode::Interactive, source);
    assert_eq!(status, 0, "{text}");
    assert_eq!(shell.host.runs.len(), 1, "{text}");
    assert!(shell.host.plans[0][0].contains("bytes:payload\\n"));
    // EOF also parses accumulated input, so execution alone cannot prove
    // that the joined delimiter restored the primary prompt in time.
    assert_eq!(text.matches(PROMPT).count(), 3, "delimiter did not finish before the next read: {text}");
}

#[test]
fn delimiter172_interactive_cr_body_stays_inert() {
    let source = "/bin/ls <<EOF\npayload\nEOF\r\necho BAD > /marker\nEOF\nexit\n";
    let (status, text, shell) = console(Mode::Interactive, source);
    assert_eq!(status, 0, "{text}");
    assert_eq!(shell.host.runs.len(), 1, "{text}");
    assert!(!shell.host.opened.iter().any(|path| path.contains("marker")));
    assert!(shell.host.plans[0][0].contains("echo BAD"));
}
