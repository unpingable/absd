//! Native ABSD shell: upstream conch grammar and a capability-aware executor.
//! Scripts and control flow use `language`; pipelines retain explicit process
//! handles, filesystem authority and bounded session interruption. No fork or jobs.

use std::io::{self, Write};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::cell::RefCell;
#[path = "../../ssh/src/input_record.rs"]
#[allow(dead_code)]
// Tests compile the real SSH producer beside the shell consumer in separate module scopes.
#[cfg_attr(test, allow(clippy::duplicate_mod))]
mod input_record;
pub use input_record::PREFIX as INPUT_RECORD_PREFIX;
mod language;
mod streams;
use streams::{Destination, Endpoint, outer_streams};

/// The fixed directory searched for a bare command name.
pub const BIN_DIR: &str = "/bin";
/// The prompt written before each line read from standard input.
pub const PROMPT: &str = "absd$ ";
/// Status of a command that could not be found.
pub const STATUS_NOT_FOUND: i32 = 127;
/// Status of a command that was found but could not be started.
pub const STATUS_REFUSED: i32 = 126;
/// Status of a child that ended without an exit code.
pub const STATUS_ABNORMAL: i32 = 128;
/// Status of a pipeline ended by ^C.
pub const STATUS_INTERRUPTED: i32 = 130;
/// Status of a usage error in the shell itself or a builtin.
pub const STATUS_USAGE: i32 = 2;
/// Status of a redirection the shell could not open or complete.
pub const STATUS_REDIRECT: i32 = 1;

/// How a child ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exit {
    Code(i32),
    /// Ended without an exit code (the platform's description).
    Other,
    /// Ended by the shell on ^C.
    Interrupted,
}

/// What the shell asks the server that started its session (sshd).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRequest<'a> {
    /// A `shutdown` or `reboot` command's words, decided by the server.
    Machine(&'a str),
    Clock(&'a str),
    /// This session's processes.
    List,
}

/// Where a started command's standard input comes from.
#[derive(Debug)]
pub enum Input<S> {
    /// The shell's own standard input.
    Inherit,
    /// The previous command's standard output (a pipe between them).
    Previous,
    /// Bytes the shell writes into a pipe and then closes (a builtin's
    /// output at the head of a pipeline).
    Bytes(Vec<u8>),
    /// A file the shell opened; the shell copies it into a pipe.
    File(S),
}

/// Where a started command's standard output or error goes.
#[derive(Debug)]
pub enum Output<W> {
    /// The shell's own stream.
    Inherit,
    /// Explicit inheritance across stdout and stderr slots.
    ParentStdout,
    ParentStderr,
    /// Child stderr shares the resolved stdout endpoint.
    SameAsStdout,
    /// Shell-provided /dev/null output, consumed without a filesystem object.
    Discard,
    /// The next command's standard input (either output stream).
    Next,
    /// Bounded stdout collected by command substitution.
    Capture(Capture),
    /// Stream inherited from an interpreted script or compound redirection.
    Shared(SharedSink<W>),
}

/// The filesystem authority a started command gets, never more than the
/// shell's own: the shell's, the shell's read-only (`ro CMD`), or none
/// (`nofs CMD`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authority {
    Shell,
    ReadOnly,
    None,
}

/// Leading `ro` / `nofs` words: the authority they ask for and the command
/// after them.
pub fn authority(words: &[String]) -> (Authority, &[String]) {
    match words.first().map(String::as_str) {
        Some("ro") => (Authority::ReadOnly, &words[1..]),
        Some("nofs") => (Authority::None, &words[1..]),
        _ => (Authority::Shell, words),
    }
}

/// One command of a pipeline, ready to start.
#[derive(Debug)]
pub struct Stage<S, W> {
    /// Absolute program path.
    pub program: String,
    pub args: Vec<String>,
    pub cwd: String,
    /// Complete child environment, including command-local assignments.
    pub env: Vec<(String, String)>,
    /// What of the shell's filesystem authority the command gets.
    pub authority: Authority,
    pub stdin: Input<S>,
    pub stdout: Output<W>,
    pub stderr: Output<W>,
}

impl<S, W> Stage<S, W> {
    /// Whether stream copying uses this shell's filesystem channel concurrently
    /// with the child. Such a child must receive a spare, never borrow ours.
    pub fn copies_files(&self) -> bool {
        matches!(self.stdin, Input::File(_)) || matches!(self.stdout, Output::Shared(_)) || matches!(self.stderr, Output::Shared(_))
    }
}

/// What became of one stage.
#[derive(Debug)]
pub struct Ran {
    /// How it ended, or why it could not start.
    pub exit: io::Result<Exit>,
    /// A failure copying between its pipes and its redirection files.
    pub redirect: Option<io::Error>,
}

/// What the shell needs from the platform.
pub trait Host {
    /// A file opened for reading with the shell's own authority.
    type Source: io::Read;
    /// A file opened for writing with the shell's own authority; `flush`
    /// makes what was written durable.
    type Sink: io::Write;

    /// Opens `path` (absolute) for reading.
    fn open_read(&mut self, path: &str) -> io::Result<Self::Source>;
    /// Opens `path` (absolute) for writing: created if missing, truncated
    /// unless `append`.
    fn open_write(&mut self, path: &str, append: bool) -> io::Result<Self::Sink>;
    /// Starts every stage in order, connecting `Previous`/`Next` with a
    /// pipe whose ends go only to the two children (the shell keeps no
    /// copy once both have started), copies `Bytes`/`File` inputs and
    /// `File` outputs through pipes, and waits for all of them. One result
    /// per stage, in order.
    fn run(&mut self, stages: Vec<Stage<Self::Source, Self::Sink>>) -> Vec<Ran>;
    /// Whether `path` (absolute) names a directory.
    fn is_dir(&mut self, path: &str) -> io::Result<bool>;
    /// Asks the server that started this session; its status and text.
    /// `Unsupported` when this shell has no session control channel.
    fn session_request(&mut self, request: SessionRequest) -> io::Result<(i32, String)>;
    /// The interactive loop read a whole line; collect pending control
    /// events before deciding whether its input may execute.
    fn line_read(&mut self) {}
    /// 1/2 arm primary/continuation reads; 3 acknowledges a completed read
    /// without transferring pending input to an application; 0 enters actual
    /// program input. Script/application input never enables command history.
    fn prompt_input(&mut self, _mode: u8) {}
    /// Read one physical line or one complete approved paste source. Native
    /// controlled sessions keep source separate from inherited application stdin.
    fn read_interactive(&mut self, input: &mut dyn io::BufRead, text: &mut String) -> io::Result<usize> { read_interactive_plain(input, text) }
    fn input_limit_notice(&self) -> &'static str { "absd-sh: input exceeds 1 MiB" }
    /// A prompt interrupt wakes the input read and cancels accumulated syntax.
    fn prompt_cancelled(&mut self) -> bool { false }
    /// Pause the producer and discard pending interactive input after cancellation.
    fn discard_pending_input(&mut self) {}
    /// Enter bounded recovery only when this frontend can actually quarantine
    /// input. Other frontends retain their existing source-limit refusal.
    fn refuse_interactive_input(&mut self) -> bool { false }
    /// Current observed terminal size; zero fields stay unknown.
    fn terminal_size(&self) -> Option<(u32, u32)> { None }
    /// Poll an interrupt while executing builtins or loops without children.
    fn interrupted(&mut self) -> bool { false }
    /// The session has ended (the server said so): every command this
    /// shell started is gone, and the shell exits without reading on.
    fn ended(&self) -> bool {
        false
    }
}

/// A redirection target as written (resolved against the working
/// directory when the line runs).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Redirect {
    File { fd: u8, path: String, append: bool },
    Dup { fd: u8, from: u8 },
}

/// One command of a parsed line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandInput {
    File(String),
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Command {
    pub words: Vec<String>,
    pub stdin: Option<CommandInput>,
    pub redirects: Vec<Redirect>,
}

pub fn resolve(cwd: &str, path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let joined = if path.starts_with('/') { path.to_string() } else { format!("{cwd}/{path}") };
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    if parts.is_empty() { "/".to_string() } else { format!("/{}", parts.join("/")) }
}

/// Where a command word runs from: by path if it contains `/`, else
/// from [`BIN_DIR`].
pub fn program_path(cwd: &str, name: &str) -> String {
    if name.contains('/') { resolve(cwd, name) } else { format!("{BIN_DIR}/{name}") }
}

/// Whether the shell continues after a line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Flow {
    Continue,
    Exit(i32),
}

pub struct Shell<H: Host> {
    pub host: H,
    pub cwd: String,
    /// The last command's status (`$?`).
    pub status: i32,
    vars: BTreeMap<String, String>,
    exported: BTreeSet<String>,
    positional: Vec<String>,
    functions: BTreeMap<String, conch_parser::ast::DefaultCompoundCommand>,
    loop_control: Option<bool>,
    loop_depth: usize,
    depth: usize,
    steps: usize,
    halted: bool,
    substitution_status: Option<i32>,
    report_native_status: bool,
    output_context: [Endpoint<H::Sink>; 2],
}

/// Shared owned stream for script/compound redirections, borrowed only per write.
#[derive(Debug)]
pub struct SharedSink<W>(Rc<RefCell<W>>);
impl<W> Clone for SharedSink<W> { fn clone(&self) -> Self { Self(self.0.clone()) } }
impl<W> SharedSink<W> {
    pub(crate) fn with_mut<T>(&self, body: impl FnOnce(&mut W) -> T) -> T { body(&mut self.0.borrow_mut()) }
}
impl<W: Write> Write for SharedSink<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.with_mut(|writer| writer.write(bytes)) }
    fn flush(&mut self) -> io::Result<()> { self.with_mut(|writer| writer.flush()) }
}

/// Command substitution output stays bounded and is drained concurrently with pipes.
#[derive(Clone, Debug)]
pub struct Capture(Rc<RefCell<Vec<u8>>>, Rc<std::cell::Cell<bool>>);
pub const MAX_SCRIPT_BYTES: usize = 1024 * 1024;
impl Capture {
    pub fn new() -> Self { Self(Rc::new(RefCell::new(Vec::new())), Rc::new(std::cell::Cell::new(false))) }
    fn bytes(&self) -> Vec<u8> { self.0.borrow().clone() }
}
impl Default for Capture {
    fn default() -> Self { Self::new() }
}
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut buf = self.0.borrow_mut();
        if buf.len().saturating_add(bytes.len()) > MAX_SCRIPT_BYTES {
            self.1.set(true);
            return Err(io::Error::other("command substitution exceeds 1 MiB"));
        }
        buf.extend_from_slice(bytes); Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

/// Builtins that only write output, allowed at the head of a pipeline.
fn is_output_builtin(name: &str) -> bool {
    matches!(name, "pwd" | "echo" | "status" | "ps" | "help")
}

/// Builtins that act on the session or the shell: alone on a line only.
fn is_control_builtin(name: &str) -> bool {
    matches!(name, "cd" | "exit" | "shutdown" | "reboot" | "clock")
}

fn is_builtin(name: &str) -> bool {
    is_output_builtin(name) || is_control_builtin(name)
}

/// A diagnostic for a redirection the shell could not open.
fn open_error(path: &str, writing: bool, error: &io::Error) -> String {
    match (writing, error.kind()) {
        (true, io::ErrorKind::ReadOnlyFilesystem) => {
            format!("absd-sh: {path}: cannot write: read-only here")
        }
        (_, io::ErrorKind::NotFound) => format!("absd-sh: {path}: not found"),
        (_, io::ErrorKind::IsADirectory) => format!("absd-sh: {path}: is a directory"),
        (true, _) => format!("absd-sh: {path}: cannot open for writing: {error}"),
        (false, _) => format!("absd-sh: {path}: cannot open: {error}"),
    }
}

impl<H: Host> Shell<H> {
    pub fn new(host: H, cwd: String) -> Self {
        Self { host, cwd: cwd.clone(), status: 0,
            vars: BTreeMap::from([("PATH".into(), "/bin".into()), ("HOME".into(), "/".into()), ("PWD".into(), cwd.clone())]),
            exported: BTreeSet::from(["PATH".into(), "HOME".into(), "PWD".into()]),
            positional: vec!["sh".into()], functions: BTreeMap::new(),
            loop_control: None, loop_depth: 0, depth: 0, steps: 0, halted: false,
            substitution_status: None, report_native_status: true, output_context: outer_streams(),
        }
    }

    /// Runs one line: its pipelines in order, each after the join before it
    /// allows (`&&` needs status 0, `||` needs another), until one exits
    /// the shell, is interrupted, or the session has ended. Builtin output
    /// goes to `out`, diagnostics to `err`.
    pub fn run_line(&mut self, line: &str, out: &mut dyn Write, err: &mut dyn Write) -> Flow {
        self.steps = 0;
        self.halted = false;
        match language::parse_program(line) {
            Ok(program) => match self.eval_program(&program, out, err) {
                Ok(flow) => flow,
                Err(error) => {
                    let _ = writeln!(err, "absd-sh: {error}");
                    self.status = STATUS_USAGE;
                    Flow::Continue
                }
            },
            Err(error) => {
                let _ = writeln!(err, "absd-sh: {error}");
                self.status = STATUS_USAGE;
                Flow::Continue
            }
        }
    }

    fn execute(&mut self, commands: Vec<Command>, out: &mut dyn Write, err: &mut dyn Write) -> Flow {
        let (status, flow, interrupted) = match commands.as_slice() {
            [single] if is_builtin(&single.words[0]) && !(single.words[0] == "ps" && single.words.len() > 1) => {
                let (status, flow) = self.builtin_line(single, out, err);
                (status, flow, false)
            }
            _ => {
                let (status, interrupted) = self.pipeline(commands, out, err);
                (status, Flow::Continue, interrupted)
            }
        };
        self.status = status;
        self.halted |= interrupted || self.host.ended();
        let _ = out.flush();
        flow
    }

    /// Opens the shell's own redirections of a builtin run alone.
    fn builtin_line(&mut self, command: &Command, out: &mut dyn Write, err: &mut dyn Write) -> (i32, Flow) {
        let name = command.words[0].as_str();
        if !is_output_builtin(name)
            && (command.stdin.is_some() || !command.redirects.is_empty())
        {
            let _ = writeln!(err, "absd-sh: {name}: takes no redirection");
            return (STATUS_USAGE, Flow::Continue);
        }
        if matches!(command.stdin, Some(CommandInput::Bytes(_))) {
            let _ = writeln!(err, "absd-sh: heredocs require a native consuming command");
            return (STATUS_USAGE, Flow::Continue);
        }
        if let Some(CommandInput::File(path)) = &command.stdin
            && path != "/dev/null"
        {
            // Opened (and so checked) as any command's would be; unread.
            let path = resolve(&self.cwd, path);
            if let Err(error) = self.host.open_read(&path) {
                let _ = writeln!(err, "{}", open_error(&path, false, &error));
                return (STATUS_REDIRECT, Flow::Continue);
            }
        }
        let destinations = match self.resolve_outputs(command, false) {
            Ok(outputs) => outputs,
            Err(error) => {
                let _ = writeln!(err, "{error}");
                return (STATUS_REDIRECT, Flow::Continue);
            }
        };
        let context = self.output_context.clone();
        let (status, flow) = streams::with_writers(&destinations, &context, out, err, |out, err| {
            self.builtin(&command.words, out, err)
        });
        let status = match streams::flush(&destinations) {
            Ok(()) => status,
            Err(error) => { let _ = writeln!(err, "absd-sh: {error}"); STATUS_REDIRECT }
        };
        (status, flow)
    }

    fn builtin(&mut self, words: &[String], out: &mut dyn Write, err: &mut dyn Write) -> (i32, Flow) {
        let (name, args) = words.split_first().expect("non-empty");
        match name.as_str() {
            "exit" => match args {
                [] => (self.status, Flow::Exit(self.status)),
                [n] => match n.parse::<i32>() {
                    Ok(n) => (n, Flow::Exit(n)),
                    Err(_) => {
                        let _ = writeln!(err, "absd-sh: exit: {n}: not a number");
                        (STATUS_USAGE, Flow::Continue)
                    }
                },
                _ => {
                    let _ = writeln!(err, "absd-sh: exit: too many arguments");
                    (STATUS_USAGE, Flow::Continue)
                }
            },
            "cd" => (self.cd(args, err), Flow::Continue),
            "pwd" => (write_line(out, err, &self.cwd.clone()), Flow::Continue),
            "echo" => match args.split_first() {
                Some((flag, rest)) if flag == "-n" => (write_text(out, err, &rest.join(" ")), Flow::Continue),
                _ => (write_line(out, err, &args.join(" ")), Flow::Continue),
            },
            "status" => (write_line(out, err, &self.status.to_string()), Flow::Continue),
            "help" => (write_text(out, err, HELP), Flow::Continue),
            "ps" if !args.is_empty() => {
                let _ = writeln!(err, "absd-sh: ps: takes no arguments (it lists this session)");
                (STATUS_USAGE, Flow::Continue)
            }
            "ps" => (self.ask(name, SessionRequest::List, out, err), Flow::Continue),
            "clock" => {let request=args.join(" ");(self.ask(name,SessionRequest::Clock(&request),out,err),Flow::Continue)},
            "shutdown" | "reboot" => {
                let words = words.join(" ");
                (self.ask(name, SessionRequest::Machine(&words), out, err), Flow::Continue)
            }
            _ => unreachable!("not a builtin: {name}"),
        }
    }

    /// Opens every redirection, then hands the stages to the host. Nothing
    /// starts unless every file opened. The status, and whether any stage
    /// was interrupted (^C), which ends the line whatever the status.
    fn pipeline(&mut self, commands: Vec<Command>, out: &mut dyn Write, err: &mut dyn Write) -> (i32, bool) {
        for (index, command) in commands.iter().enumerate() {
            let (narrowed, words) = authority(&command.words);
            let Some(name) = words.first().map(String::as_str) else {
                let _ = writeln!(err, "absd-sh: {}: needs a program", command.words[0]);
                return (STATUS_USAGE, false);
            };
            if program_path(&self.cwd, name) == "/bin/https-document"
                && !(words.len() == 2 && words[1] == "--sample")
            {
                let _ = writeln!(err, "absd-sh: https-document: requires direct SSH exec");
                return (STATUS_REFUSED, false);
            }
            if narrowed != Authority::Shell && is_builtin(name) && !(name == "ps" && words.len() > 1) {
                let _ = writeln!(err, "absd-sh: {}: applies to programs, not the builtin {name}", command.words[0]);
                return (STATUS_USAGE, false);
            }
            if is_control_builtin(name) {
                let _ = writeln!(err, "absd-sh: {name}: cannot run in a pipeline");
                return (STATUS_USAGE, false);
            }
            if is_output_builtin(name) && !(name == "ps" && words.len() > 1) && index > 0 {
                let _ = writeln!(err, "absd-sh: {name}: a builtin can only start a pipeline");
                return (STATUS_USAGE, false);
            }
            if is_output_builtin(name) && !(name == "ps" && words.len() > 1) && (command.stdin.is_some() || !command.redirects.is_empty()) {
                let _ = writeln!(err, "absd-sh: {name}: a builtin in a pipeline takes no redirection");
                return (STATUS_USAGE, false);
            }
        }
        let mut stages = Vec::with_capacity(commands.len());
        let mut names = Vec::with_capacity(commands.len());
        let mut report_status = Vec::with_capacity(commands.len());
        let mut head: Option<Vec<u8>> = None;
        let last = commands.len() - 1;
        for (index, command) in commands.iter().enumerate() {
            let (narrowed, words) = authority(&command.words);
            let (name, args) = words.split_first().expect("non-empty");
            if is_output_builtin(name) && !(name == "ps" && words.len() > 1) {
                // Only first, and never last (a lone builtin runs above):
                // its output is the next command's input.
                let mut bytes = Vec::new();
                let _ = self.builtin(&command.words, &mut bytes, err);
                head = Some(bytes);
                continue;
            }
            let stdin = match (&command.stdin, index, head.take()) {
                (_, _, Some(bytes)) => Input::Bytes(bytes),
                (Some(CommandInput::Bytes(bytes)), _, None) => Input::Bytes(bytes.clone()),
                (Some(CommandInput::File(path)), _, None) if path == "/dev/null" => Input::Bytes(Vec::new()),
                (Some(CommandInput::File(path)), _, None) => {
                    let path = resolve(&self.cwd, path);
                    match self.host.open_read(&path) {
                        Ok(source) => Input::File(source),
                        Err(error) => {
                            let _ = writeln!(err, "{}", open_error(&path, false, &error));
                            return (STATUS_REDIRECT, false);
                        }
                    }
                }
                (None, 0, None) => Input::Inherit,
                (None, _, None) => Input::Previous,
            };
            let destinations = match self.resolve_outputs(command, index < last) {
                Ok(outputs) => outputs,
                Err(error) => {
                    let _ = writeln!(err, "{error}");
                    return (STATUS_REDIRECT, false);
                }
            };
            let [stdout, stderr] = streams::stage_outputs(&destinations);
            let explicit_stderr = command.redirects.iter().any(|redirect| matches!(redirect,
                Redirect::File { fd: 2, .. } | Redirect::Dup { fd: 2, .. }));
            let inherited_stderr = !matches!(self.output_context[1].as_ref(), Destination::Parent(1));
            report_status.push(!explicit_stderr && !inherited_stderr);
            names.push(name.clone());
            stages.push(Stage {
                program: program_path(&self.cwd, name),
                args: args.to_vec(),
                cwd: self.cwd.clone(),
                env: self.exported.iter().filter_map(|key| self.vars.get(key).map(|value| (key.clone(), value.clone()))).collect(),
                authority: narrowed,
                stdin,
                stdout,
                stderr,
            });
        }
        let _ = out.flush();
        let results = self.host.run(stages);
        let count = results.len();
        let mut status = 0;
        let mut interrupted = false;
        for (index, (ran, name)) in results.into_iter().zip(&names).enumerate() {
            let is_last = index + 1 == count;
            let stage_status = match ran.exit {
                Ok(Exit::Code(0)) => 0,
                Ok(Exit::Code(code)) => {
                    if is_last && report_status[index] && self.report_native_status {
                        let _ = writeln!(err, "absd-sh: {name}: exit status {code}");
                    }
                    code
                }
                Ok(Exit::Other) => {
                    if is_last {
                        let _ = writeln!(err, "absd-sh: {name}: ended abnormally");
                    }
                    STATUS_ABNORMAL
                }
                // The ^C on the screen says why; nothing more is printed.
                Ok(Exit::Interrupted) => {
                    interrupted = true;
                    STATUS_INTERRUPTED
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let _ = writeln!(err, "absd-sh: {name}: not found");
                    STATUS_NOT_FOUND
                }
                // The kernel's refusal of a start without the spawn right
                // (a shell a command started has none).
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    let _ = writeln!(err, "absd-sh: {name}: cannot run: permission denied");
                    STATUS_REFUSED
                }
                Err(e) => {
                    let _ = writeln!(err, "absd-sh: {name}: cannot run: {e}");
                    STATUS_REFUSED
                }
            };
            let stage_status = match ran.redirect {
                Some(error) => {
                    let _ = writeln!(err, "absd-sh: {name}: redirection failed: {error}");
                    if stage_status == 0 { STATUS_REDIRECT } else { stage_status }
                }
                None => stage_status,
            };
            if is_last {
                status = stage_status;
            }
        }
        (status, interrupted)
    }

    /// A request to the session's server: its text to `out` on success, to
    /// `err` otherwise.
    fn ask(&mut self, name: &str, request: SessionRequest, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
        match self.host.session_request(request) {
            Ok((0, text)) => match out.write_all(text.as_bytes()) {
                Ok(()) => 0,
                Err(e) => {
                    let _ = writeln!(err, "absd-sh: write: {e}");
                    1
                }
            },
            Ok((status, text)) => {
                let _ = err.write_all(text.as_bytes());
                status
            }
            Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                let _ = writeln!(err, "absd-sh: {name}: no session control channel (only a session's shell has one)");
                1
            }
            Err(e) => {
                let _ = writeln!(err, "absd-sh: {name}: {e}");
                1
            }
        }
    }

    fn cd(&mut self, args: &[String], err: &mut dyn Write) -> i32 {
        let target = match args {
            [] => self.vars.get("HOME").cloned().unwrap_or_else(|| "/".into()),
            [dir] => resolve(&self.cwd, dir),
            _ => {
                let _ = writeln!(err, "absd-sh: cd: too many arguments");
                return STATUS_USAGE;
            }
        };
        let requested = args.first().map(String::as_str).unwrap_or(&target).to_string();
        match self.host.is_dir(&target) {
            Ok(true) => {
                self.vars.insert("OLDPWD".into(), self.cwd.clone());
                self.vars.insert("PWD".into(), target.clone());
                self.cwd = target;
                0
            }
            Ok(false) => {
                let _ = writeln!(err, "absd-sh: cd: {}: not a directory", requested);
                1
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let _ = writeln!(err, "absd-sh: cd: {}: not found", requested);
                1
            }
            Err(e) => {
                let _ = writeln!(err, "absd-sh: cd: {}: {e}", requested);
                1
            }
        }
    }
}

fn write_line(out: &mut dyn Write, err: &mut dyn Write, text: &str) -> i32 {
    match writeln!(out, "{text}") {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(err, "absd-sh: write: {e}");
            1
        }
    }
}

fn write_text(out: &mut dyn Write, err: &mut dyn Write, text: &str) -> i32 {
    match out.write_all(text.as_bytes()) {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(err, "absd-sh: write: {e}");
            1
        }
    }
}

/// What `help` prints: the shell's whole grammar on one screen.
pub const HELP: &str = "\
sh: scripts: sh FILE [ARG...] | sh -c COMMAND [NAME [ARG...]] | sh -s
  lists: ; newline && || | ! ; if/for/while/until/case; functions and groups
  words: single/double quotes, escapes, $VAR ${VAR:-default} $1 $@ $? $(CMD)
  files: * ? [abc] ; < FILE > FILE >> FILE 2> FILE 2>> FILE
  streams: 2>&1 1>&2 (literal output descriptors 1 or 2); shell /dev/null
  native input: <<WORD <<-WORD heredocs (quoted delimiter keeps literal text)
builtins: cd pwd echo [-n] exit status help true false : export unset
  set -- [ARG...] shift [N] break continue sh . FILE
  ps (session) ; ps ARGS (/bin/ps, if installed)
  shutdown -h|-p|-r now ; reboot
  clock [status | set UNIX_SECONDS | sync] (operator owner request)
  ro CMD / nofs CMD narrow native filesystem authority; man absd-sh
limits: source and expanded heredoc 1 MiB
  no jobs/fork, descriptor closure or raw screen mode
";

/// Parsed command line of the shell itself.
#[derive(Debug, Eq, PartialEq)]
pub enum Mode {
    /// Read lines from standard input, prompting before each.
    Interactive,
    /// Run one line and exit with its status (`-c LINE`).
    Command(String),
    CommandArgs(String, Vec<String>),
    Script(Vec<String>),
    Stdin(Vec<String>),
}

pub fn parse_args(args: &[String]) -> Result<Mode, String> {
    match args {
        [] => Ok(Mode::Interactive),
        [flag, line] if flag == "-c" => Ok(Mode::Command(line.clone())),
        [flag, line, rest @ ..] if flag == "-c" => Ok(Mode::CommandArgs(line.clone(), rest.to_vec())),
        [flag, rest @ ..] if flag == "-s" => Ok(Mode::Stdin(rest.to_vec())),
        [path, ..] if !path.starts_with('-') => Ok(Mode::Script(args.to_vec())),
        _ => Err("usage: sh [-c COMMAND [NAME [ARG...]] | -s [ARG...] | FILE [ARG...]]".to_string()),
    }
}

/// A bounded plain physical line, without consuming foreground-child input.
/// Classify overflow before decoding a potentially truncated UTF-8 prefix.
pub fn read_interactive_plain(input: &mut dyn io::BufRead, text: &mut String) -> io::Result<usize> {
    use std::io::{BufRead, Read};
    let mut bytes = Vec::new();
    let n = input.take((MAX_SCRIPT_BYTES + 1) as u64).read_until(b'\n', &mut bytes)?;
    if bytes.len() > MAX_SCRIPT_BYTES {
        return Err(io::Error::new(io::ErrorKind::FileTooLarge, "interactive source exceeds 1 MiB"));
    }
    let line = String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    text.push_str(&line);
    Ok(n)
}

/// Matched native PTY protocol. ESC cannot be supplied as ordinary terminal
/// source. Read the entire approved source before a child inherits stdin.
/// A partial ordinary line may precede the record after a nonempty Ctrl-D.
pub fn read_interactive_record(input: &mut dyn io::BufRead, text: &mut String) -> io::Result<usize> {
    let mut physical = String::new();
    let n = input.read_line(&mut physical)?;
    let Some(at) = physical.find(INPUT_RECORD_PREFIX) else { text.push_str(&physical); return Ok(n); };
    let length = physical[at + INPUT_RECORD_PREFIX.len()..].strip_suffix('\n').ok_or_else(|| io::Error::other("incomplete paste record header"))?;
    if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::Error::other("invalid paste record length"));
    }
    let length: usize = length.parse().map_err(|_| io::Error::other("invalid paste record length"))?;
    if length > MAX_SCRIPT_BYTES { return Err(io::Error::other("paste record exceeds 1 MiB")); }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    let source=String::from_utf8(bytes).map_err(|_| io::Error::other("invalid paste record UTF-8"))?;
    text.push_str(&physical[..at]); text.push_str(&source);
    Ok(at + source.len())
}

/// Runs the whole session over `input`. Returns the shell's exit status.
/// In interactive mode the prompt goes to `out` before each line; end of
/// input exits with the last status.
pub fn session<H: Host>(
    shell: &mut Shell<H>,
    mode: Mode,
    input: &mut dyn io::BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    match mode {
        Mode::CommandArgs(line, args) => {
            shell.set_positional(args);
            session(shell, Mode::Command(line), input, out, err)
        }
        Mode::Script(args) => {
            match shell.invoke_script(&args, false, out, err) {
                Ok(_) => shell.status,
                Err(error) => { let _ = writeln!(err, "absd-sh: {error}"); STATUS_USAGE }
            }
        }
        Mode::Stdin(args) => {
            use std::io::Read;
            shell.set_positional(std::iter::once("sh".into()).chain(args).collect());
            let mut text = String::new();
            match input.take((MAX_SCRIPT_BYTES + 1) as u64).read_to_string(&mut text) {
                Ok(_) => session(shell, Mode::Command(text), input, out, err),
                Err(error) => { let _ = writeln!(err, "absd-sh: {error}"); STATUS_USAGE }
            }
        }
        Mode::Command(line) => match shell.run_line(&line, out, err) {
            _ if shell.host.ended() => STATUS_INTERRUPTED,
            Flow::Exit(code) => code,
            Flow::Continue => shell.status,
        },
        Mode::Interactive => {
            let mut line = String::new();
            let mut pending_heredoc: Option<language::HeredocDelimiter> = None;
            loop {
                if let Some((columns, rows)) = shell.host.terminal_size() {
                    for (key, value) in [("COLUMNS", columns), ("LINES", rows)] {
                        if value == 0 { shell.vars.remove(key); shell.exported.remove(key); }
                        else { shell.vars.insert(key.into(), value.to_string()); shell.exported.insert(key.into()); }
                    }
                }
                shell.host.prompt_input(if line.is_empty() { 1 } else { 2 });
                if shell.host.ended() { return STATUS_INTERRUPTED; }
                if shell.host.prompt_cancelled() {
                    line.clear();
                    pending_heredoc = None;
                    shell.host.discard_pending_input();
                    if shell.host.ended() { return STATUS_INTERRUPTED; }
                    shell.status = STATUS_INTERRUPTED;
                    continue;
                }
                let _ = out.write_all(if line.is_empty() { PROMPT.as_bytes() } else { b"> " });
                let _ = out.flush();
                let mut more = String::new();
                let read = shell.host.read_interactive(input, &mut more);
                shell.host.prompt_input(3);
                if shell.host.ended() { return STATUS_INTERRUPTED; }
                // Padding a cancelled record can split its last UTF-8 code
                // point. Cancellation owns that input before decode errors.
                if shell.host.prompt_cancelled() {
                    line.clear();
                    pending_heredoc = None;
                    shell.host.discard_pending_input();
                    if shell.host.ended() { return STATUS_INTERRUPTED; }
                    shell.status = STATUS_INTERRUPTED;
                    continue;
                }
                let overflow = matches!(&read, Err(error) if error.kind() == io::ErrorKind::FileTooLarge)
                    || line.len().saturating_add(more.len()) > MAX_SCRIPT_BYTES;
                if overflow {
                    let _ = writeln!(err, "{}", shell.host.input_limit_notice());
                    line.clear();
                    more.clear();
                    pending_heredoc = None;
                    if !shell.host.refuse_interactive_input() { return STATUS_USAGE; }
                    shell.host.discard_pending_input();
                    if shell.host.ended() { return STATUS_INTERRUPTED; }
                    shell.status = STATUS_USAGE;
                    continue;
                }
                match read {
                    Ok(0) => {
                        shell.host.prompt_input(0);
                        if shell.host.ended() || shell.host.prompt_cancelled() {
                            shell.host.discard_pending_input();
                            return STATUS_INTERRUPTED;
                        }
                        if !line.is_empty() { shell.run_line(&line, out, err); }
                        return shell.status;
                    },
                    Ok(_) if more.ends_with('\n') => shell.host.line_read(),
                    Ok(_) => {}
                    Err(e) => {
                        let _ = writeln!(err, "absd-sh: read: {e}");
                        return STATUS_USAGE;
                    }
                }
                if shell.host.ended() {
                    return STATUS_INTERRUPTED;
                }
                if shell.host.prompt_cancelled() {
                    line.clear();
                    pending_heredoc = None;
                    shell.host.discard_pending_input();
                    if shell.host.ended() { return STATUS_INTERRUPTED; }
                    shell.status = STATUS_INTERRUPTED;
                    continue;
                }
                line.push_str(&more);
                if pending_heredoc.as_ref().is_some_and(|delimiter| !delimiter.may_finish(&more)) {
                    continue;
                }
                pending_heredoc = None;
                match language::continuation(&line) {
                    language::Continuation::Complete => {},
                    language::Continuation::Syntax => continue,
                    language::Continuation::Heredoc(delimiter) => {
                        pending_heredoc = Some(delimiter);
                        continue;
                    }
                }
                shell.host.prompt_input(0);
                if shell.host.ended() { return STATUS_INTERRUPTED; }
                // The final acknowledgement can itself receive an interrupt.
                // Nothing in this command has executed or opened output yet.
                if shell.host.prompt_cancelled() {
                    line.clear();
                    pending_heredoc = None;
                    shell.host.discard_pending_input();
                    if shell.host.ended() { return STATUS_INTERRUPTED; }
                    shell.status = STATUS_INTERRUPTED;
                    continue;
                }
                let flow = shell.run_line(&line, out, err);
                line.clear();
                if shell.host.ended() {
                    return STATUS_INTERRUPTED;
                }
                if let Flow::Exit(code) = flow {
                    return code;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod throughput_tests;
