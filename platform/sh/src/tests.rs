use super::*;
use std::collections::BTreeMap;

/// The words of a line without operators.
fn split(line: &str) -> Result<Vec<String>, ParseError> {
    Ok(tokenize(line)?
        .into_iter()
        .filter_map(|token| match token {
            Token::Word(word) => Some(word),
            _ => None,
        })
        .collect())
}

fn words(line: &str) -> Vec<String> {
    split(line).unwrap()
}

#[test]
fn splits_on_whitespace_and_quotes() {
    assert_eq!(words("  ls   -l\t/bin \n"), ["ls", "-l", "/bin"]);
    assert_eq!(words("echo \"a  b\" c"), ["echo", "a  b", "c"]);
    assert_eq!(words("a\"b c\"d"), ["ab cd"]);
    assert_eq!(words("echo \"\""), ["echo", ""]);
    assert_eq!(words(r#"echo "q\"x\\y\n""#), ["echo", "q\"x\\y\\n"]);
    assert_eq!(words(r"a\b"), [r"a\b"]);
    assert!(words("   ").is_empty());
    assert_eq!(split("echo \"open"), Err(ParseError::UnterminatedQuote));
    assert_eq!(split("echo \"open\\"), Err(ParseError::UnterminatedQuote));
    assert_eq!(words("echo \"a | b\" \"<\" \">\""), ["echo", "a | b", "<", ">"]);
}

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
        let mut plan = Vec::new();
        let mut results = Vec::new();
        for stage in stages {
            self.runs.push((stage.program.clone(), stage.args.clone(), stage.cwd.clone()));
            self.authorities.push(stage.authority);
            let stdin = match stage.stdin {
                Input::Inherit => "inherit".to_string(),
                Input::Previous => "previous".to_string(),
                Input::Bytes(bytes) => format!("bytes:{}", String::from_utf8_lossy(&bytes).escape_debug()),
                Input::File(source) => {
                    format!("file:{}", String::from_utf8_lossy(source.get_ref()).escape_debug())
                }
            };
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
                    Output::File(mut sink) => {
                        if exit.is_ok() {
                            let _ = write!(sink, "{stream} of {}\n", stage.program);
                        }
                        format!("file:{}", sink.path)
                    }
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

    fn line_read(&mut self) {
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
         absd$ absd-sh: false: exit status 1\n\
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
            ("/bin/false".into(), vec![], "/bin".into()),
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
    assert_eq!((status, text.as_str()), (0, "absd$ absd-sh: unterminated quote\nabsd$ 2\nabsd$ "));
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

fn command(words: &[&str]) -> Command {
    Command { words: words.iter().map(|w| w.to_string()).collect(), ..Command::default() }
}

#[test]
fn tokenizes_operators_outside_quotes() {
    use Token::*;
    let w = |s: &str| Word(s.into());
    assert_eq!(tokenize("a|b").unwrap(), [w("a"), Pipe, w("b")]);
    assert_eq!(
        tokenize("cat<in>out 2>err").unwrap(),
        [w("cat"), In, w("in"), Out { append: false }, w("out"), Err { append: false }, w("err")]
    );
    assert_eq!(tokenize("x >>f 2>>g").unwrap(), [w("x"), Out { append: true }, w("f"), Err { append: true }, w("g")]);
    // `2>` only when the 2 starts a word.
    assert_eq!(tokenize("echo 2 >f").unwrap(), [w("echo"), w("2"), Out { append: false }, w("f")]);
    assert_eq!(tokenize("a2>f").unwrap(), [w("a2"), Out { append: false }, w("f")]);
    assert_eq!(tokenize("\"|\" \"a>b\"").unwrap(), [w("|"), w("a>b")]);
}

/// The one pipeline of a line.
fn pipeline(line: &str) -> Result<Vec<Command>, ParseError> {
    let mut list = parse(line)?;
    assert!(list.len() <= 1, "{line}: {list:?}");
    Ok(list.pop().map(|p| p.commands).unwrap_or_default())
}

#[test]
fn parses_pipelines_and_redirections() {
    assert_eq!(pipeline("").unwrap(), []);
    assert_eq!(pipeline("  ").unwrap(), []);
    assert_eq!(pipeline("a | b | c").unwrap(), [command(&["a"]), command(&["b"]), command(&["c"])]);
    let parsed = pipeline("sort < in -r > out 2>> log").unwrap();
    assert_eq!(
        parsed,
        [Command {
            words: vec!["sort".into(), "-r".into()],
            stdin: Some("in".into()),
            stdout: Some(Redirect { path: "out".into(), append: false }),
            stderr: Some(Redirect { path: "log".into(), append: true }),
        }]
    );
    assert_eq!(parse("| cat"), Err(ParseError::EmptyCommand));
    assert_eq!(parse("cat |"), Err(ParseError::EmptyCommand));
    assert_eq!(parse("a | | b"), Err(ParseError::EmptyCommand));
    assert_eq!(parse("> f"), Err(ParseError::EmptyCommand));
    assert_eq!(parse("cat <"), Err(ParseError::MissingTarget("<")));
    assert_eq!(parse("cat > | b"), Err(ParseError::MissingTarget(">")));
    assert_eq!(parse("cat 2>>"), Err(ParseError::MissingTarget("2>>")));
    assert_eq!(parse("cat > a >> b"), Err(ParseError::Duplicate(">>")));
    assert_eq!(parse("cat < a < b"), Err(ParseError::Duplicate("<")));
    assert_eq!(parse("a > f | b"), Err(ParseError::OutputConflict));
    assert_eq!(parse("a | b < f"), Err(ParseError::InputConflict));
    assert_eq!(parse("a 2>&1"), Err(ParseError::Duplication));
    assert_eq!(parse("a >&2"), Err(ParseError::Duplication));
}

#[test]
fn parses_lists() {
    let one = |words: &[&str], then| Pipeline { commands: vec![command(words)], then };
    assert_eq!(
        parse("a ; b && c || d;").unwrap(),
        [one(&["a"], Join::Always), one(&["b"], Join::IfOk), one(&["c"], Join::IfFailed), one(&["d"], Join::Always)]
    );
    assert_eq!(
        parse("a | b&&c > f").unwrap(),
        [
            Pipeline { commands: vec![command(&["a"]), command(&["b"])], then: Join::IfOk },
            Pipeline {
                commands: vec![Command {
                    words: vec!["c".into()],
                    stdout: Some(Redirect { path: "f".into(), append: false }),
                    ..Command::default()
                }],
                then: Join::Always,
            }
        ]
    );
    assert_eq!(parse("echo \";\" \"a && b\"").unwrap(), [one(&["echo", ";", "a && b"], Join::Always)]);
    assert_eq!(parse(";"), Err(ParseError::EmptyList));
    assert_eq!(parse("; a"), Err(ParseError::EmptyList));
    assert_eq!(parse("a ;; b"), Err(ParseError::EmptyList));
    assert_eq!(parse("a &&"), Err(ParseError::EmptyList));
    assert_eq!(parse("a || "), Err(ParseError::EmptyList));
    assert_eq!(parse("a && | b"), Err(ParseError::EmptyCommand));
    assert_eq!(parse("a &"), Err(ParseError::Background));
    assert_eq!(parse("a & b"), Err(ParseError::Background));
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
        "absd$ yes\nabsd$ absd-sh: false: exit status 1\nno\nabsd$ absd-sh: false: exit status 1\nafter\n0\n\
         absd$ chained\nabsd$ /etc\nabsd$ absd-sh: false: exit status 1\nabsd$ /etc\nabsd$ "
    );
    assert_eq!(shell.cwd, "/etc");
    let (status, text, _) = console(Mode::Interactive, "exit 4 ; echo unreachable\n");
    assert_eq!((status, text.as_str()), (4, "absd$ "));
    let (status, text, _) = console(Mode::Interactive, "nosuch ; status\nls ;; ls\nls &\nstatus\n");
    assert_eq!(status, 0);
    assert_eq!(
        text,
        "absd$ absd-sh: nosuch: not found\n127\nabsd$ absd-sh: syntax error: empty command in list\n\
         absd$ absd-sh: syntax error: `&` is not supported (there are no background jobs)\nabsd$ 2\nabsd$ "
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
    let (status, text, shell) = console(Mode::Interactive, "ls -l | cat | false\nstatus\n");
    assert_eq!(status, 0);
    assert_eq!(text, "absd$ absd-sh: false: exit status 1\nabsd$ 1\nabsd$ ");
    assert_eq!(
        shell.host.plans,
        [vec![
            "/bin/ls in=inherit out=next err=inherit".to_string(),
            "/bin/cat in=previous out=next err=inherit".to_string(),
            "/bin/false in=previous out=inherit err=inherit".to_string(),
        ]]
    );
    // Only the last command's status counts; earlier failures are named
    // only when they could not start.
    let (_, text, _) = console(Mode::Interactive, "false | cat\nstatus\nnosuch | cat\nstatus\ncat | nosuch\nstatus\n");
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
         absd$ absd-sh: ps: takes no arguments (it lists this session)\n\
         absd$ absd-sh: shutdown: cannot run in a pipeline\n\
         absd$ absd-sh: reboot: takes no redirection\n\
         absd$ absd-sh: ro: applies to programs, not the builtin ps\n\
         absd$ absd-sh: ps: no session control channel (only a session's shell has one)\n\
         absd$ "
    );
    // `ps | cat`: the builtin's (empty) output still feeds the pipeline.
    assert_eq!(shell.host.runs.len(), 1);
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
