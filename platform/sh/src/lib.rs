//! absd-sh: a deliberately small line-based command shell.
//!
//! One line is a list of pipelines joined by `;`, `&&` (the next runs if
//! the status is 0), or `||` (if it is not), run in order; a pipeline is
//! commands joined by `|`, each with optional `< file`, `> file`,
//! `>> file`, and `2> file` / `2>> file`. Words split on whitespace, with
//! double quotes grouping (inside them `\"` and `\\` are escapes; a quoted
//! `|`, `<`, `>`, `;`, or `&` is an ordinary character). Builtins are
//! `cd`, `pwd`, `echo [-n]`, `exit [n]`, `status`, and `help`, and, in a
//! shell sshd started for a session, `ps`, `shutdown`, and `reboot`, which
//! ask sshd on the session control channel; anything else runs as a
//! filesystem executable, by path when the name contains `/`, else from the
//! fixed directory `/bin`. No globbing, variables, descriptor duplication
//! (`2>&1`), background jobs (`&`), job control, or signals.
//!
//! Interruption: in a session with a control channel, ^C typed while a
//! pipeline runs reaches the shell there (never through its input), and the
//! shell ends every command of the pipeline with the process handles it
//! holds ([`Host::run`]); the line's status is [`STATUS_INTERRUPTED`].
//!
//! Ending: when the session ends (the client disconnected, the session
//! timed out, or the system is going down), the server says so on the same
//! channel; the shell ends and reaps every command it is running, as for
//! ^C, and exits instead of reading another line ([`Host::ended`]). The
//! commands it starts cannot start programs of their own (they get no spawn
//! right), so those are every process of the session.
//!
//! Authority: the shell opens every redirection target itself, with its
//! own filesystem authority, before anything starts; a child is only ever
//! given a pipe end for a redirected stream, and the shell copies between
//! that pipe and the file ([`Host::run`]). A child therefore never holds a
//! file, only the one pipe end its stream needs. A pipeline's status is
//! its last command's.
//!
//! The shell keeps its own working directory and gives it to every child;
//! the platform (composition, files, directory test) is the [`Host`] trait
//! so the logic is tested on the host.

use std::io::{self, Write};

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
    /// The next command's standard input (stdout only).
    Next,
    /// A file the shell opened; the shell copies a pipe into it.
    File(W),
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
    /// What of the shell's filesystem authority the command gets.
    pub authority: Authority,
    pub stdin: Input<S>,
    pub stdout: Output<W>,
    pub stderr: Output<W>,
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
    /// The interactive loop read one more whole line: a ^C typed before it,
    /// at the prompt, is not meant for the command it starts.
    fn line_read(&mut self) {}
    /// The session has ended (the server said so): every command this
    /// shell started is gone, and the shell exits without reading on.
    fn ended(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Token {
    Word(String),
    /// `|`
    Pipe,
    /// `<`
    In,
    /// `>` or `>>` (append)
    Out { append: bool },
    /// `2>` or `2>>` (append)
    Err { append: bool },
    /// `;`
    Seq,
    /// `&&`
    And,
    /// `||`
    Or,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ParseError {
    UnterminatedQuote,
    /// A `|` with no command on one side.
    EmptyCommand,
    /// A redirection operator with no file name after it.
    MissingTarget(&'static str),
    /// The same stream redirected twice in one command.
    Duplicate(&'static str),
    /// Standard output both to a file and into a pipe.
    OutputConflict,
    /// Standard input both from a file and from a pipe.
    InputConflict,
    /// `2>&1` and similar: there are no descriptors to duplicate.
    Duplication,
    /// A `;`, `&&`, or `||` with no pipeline on one side (a trailing `;`
    /// is allowed).
    EmptyList,
    /// A single `&` (not `&&`), anywhere outside quotes: there are no
    /// background jobs.
    Background,
}

impl ParseError {
    fn message(&self) -> String {
        match self {
            ParseError::UnterminatedQuote => "unterminated quote".into(),
            ParseError::EmptyCommand => "syntax error: empty command in pipeline".into(),
            ParseError::MissingTarget(op) => format!("syntax error: `{op}` needs a file name"),
            ParseError::Duplicate(op) => format!("syntax error: `{op}` given twice for one command"),
            ParseError::OutputConflict => {
                "syntax error: output cannot go both to a file and into a pipe".into()
            }
            ParseError::InputConflict => {
                "syntax error: input cannot come both from a file and from a pipe".into()
            }
            ParseError::Duplication => {
                "syntax error: descriptor duplication (`>&`) is not supported".into()
            }
            ParseError::EmptyList => "syntax error: empty command in list".into(),
            ParseError::Background => "syntax error: `&` is not supported (there are no background jobs)".into(),
        }
    }
}

/// Splits a line into words and operators: whitespace separates, `"..."`
/// groups (and may join adjacent text, `a"b c"` is one word), `\"` and
/// `\\` escape inside quotes. Outside quotes a backslash is literal and
/// `|`, `||`, `<`, `>`, `>>`, `;`, `&&` are operators wherever they
/// appear; `2>` and `2>>` are operators when the `2` starts a word; any
/// other `&`, even inside a word, is an error (after a redirection it
/// starts a word, for the parser to refuse as `>&` duplication).
pub fn tokenize(line: &str) -> Result<Vec<Token>, ParseError> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = line.chars().peekable();
    let end_word = |tokens: &mut Vec<Token>, word: &mut String, in_word: &mut bool| {
        if *in_word {
            tokens.push(Token::Word(std::mem::take(word)));
            *in_word = false;
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        None => return Err(ParseError::UnterminatedQuote),
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(e @ ('"' | '\\')) => word.push(e),
                            Some(other) => {
                                word.push('\\');
                                word.push(other);
                            }
                            None => return Err(ParseError::UnterminatedQuote),
                        },
                        Some(other) => word.push(other),
                    }
                }
            }
            '2' if !in_word && chars.peek() == Some(&'>') => {
                chars.next();
                let append = chars.next_if_eq(&'>').is_some();
                tokens.push(Token::Err { append });
            }
            '|' => {
                end_word(&mut tokens, &mut word, &mut in_word);
                let or = chars.next_if_eq(&'|').is_some();
                tokens.push(if or { Token::Or } else { Token::Pipe });
            }
            ';' => {
                end_word(&mut tokens, &mut word, &mut in_word);
                tokens.push(Token::Seq);
            }
            '&' if chars.peek() == Some(&'&') => {
                end_word(&mut tokens, &mut word, &mut in_word);
                chars.next();
                tokens.push(Token::And);
            }
            // `>&`, `2>&`: a word for the parser to refuse as duplication.
            '&' if !in_word && matches!(tokens.last(), Some(Token::In | Token::Out { .. } | Token::Err { .. })) => {
                in_word = true;
                word.push('&');
            }
            '&' => return Err(ParseError::Background),
            '<' => {
                end_word(&mut tokens, &mut word, &mut in_word);
                tokens.push(Token::In);
            }
            '>' => {
                end_word(&mut tokens, &mut word, &mut in_word);
                let append = chars.next_if_eq(&'>').is_some();
                tokens.push(Token::Out { append });
            }
            c if c.is_whitespace() => end_word(&mut tokens, &mut word, &mut in_word),
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    end_word(&mut tokens, &mut word, &mut in_word);
    Ok(tokens)
}

/// A redirection target as written (resolved against the working
/// directory when the line runs).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Redirect {
    pub path: String,
    pub append: bool,
}

/// One command of a parsed line.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Command {
    pub words: Vec<String>,
    pub stdin: Option<String>,
    pub stdout: Option<Redirect>,
    pub stderr: Option<Redirect>,
}

/// What must hold for the pipeline after this one to run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Join {
    /// `;` (or the end of the line)
    Always,
    /// `&&`
    IfOk,
    /// `||`
    IfFailed,
}

/// One pipeline of a line, and how the next one is joined to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pipeline {
    pub commands: Vec<Command>,
    pub then: Join,
}

/// Parses a line into its pipelines, in order; an empty line is none.
pub fn parse(line: &str) -> Result<Vec<Pipeline>, ParseError> {
    let tokens = tokenize(line)?;
    let mut list = Vec::new();
    let mut group = Vec::new();
    for token in tokens {
        let then = match token {
            Token::Seq => Join::Always,
            Token::And => Join::IfOk,
            Token::Or => Join::IfFailed,
            other => {
                group.push(other);
                continue;
            }
        };
        if group.is_empty() {
            return Err(ParseError::EmptyList);
        }
        list.push(Pipeline { commands: pipeline_of(std::mem::take(&mut group))?, then });
    }
    if group.is_empty() {
        // Nothing, or a trailing `;`; `a &&` and `a ||` promise a pipeline.
        if list.last().is_some_and(|p| p.then != Join::Always) {
            return Err(ParseError::EmptyList);
        }
        return Ok(list);
    }
    list.push(Pipeline { commands: pipeline_of(group)?, then: Join::Always });
    Ok(list)
}

/// Parses one pipeline's tokens (no list operators among them).
fn pipeline_of(tokens: Vec<Token>) -> Result<Vec<Command>, ParseError> {
    let mut commands = vec![Command::default()];
    let mut tokens = tokens.into_iter();
    while let Some(token) = tokens.next() {
        let current = commands.last_mut().expect("never empty");
        let (op, slot_is_set) = match &token {
            Token::Word(word) => {
                current.words.push(word.clone());
                continue;
            }
            Token::Pipe => {
                commands.push(Command::default());
                continue;
            }
            Token::In => ("<", current.stdin.is_some()),
            Token::Out { append: false } => (">", current.stdout.is_some()),
            Token::Out { append: true } => (">>", current.stdout.is_some()),
            Token::Err { append: false } => ("2>", current.stderr.is_some()),
            Token::Err { append: true } => ("2>>", current.stderr.is_some()),
            Token::Seq | Token::And | Token::Or => unreachable!("list operators are split off first"),
        };
        let path = match tokens.next() {
            Some(Token::Word(path)) if path.starts_with('&') => return Err(ParseError::Duplication),
            Some(Token::Word(path)) => path,
            _ => return Err(ParseError::MissingTarget(op)),
        };
        if slot_is_set {
            return Err(ParseError::Duplicate(op));
        }
        match token {
            Token::In => current.stdin = Some(path),
            Token::Out { append } => current.stdout = Some(Redirect { path, append }),
            Token::Err { append } => current.stderr = Some(Redirect { path, append }),
            Token::Word(_) | Token::Pipe | Token::Seq | Token::And | Token::Or => unreachable!(),
        }
    }
    let last = commands.len() - 1;
    for (index, command) in commands.iter().enumerate() {
        if command.words.is_empty() {
            return Err(ParseError::EmptyCommand);
        }
        if index < last && command.stdout.is_some() {
            return Err(ParseError::OutputConflict);
        }
        if index > 0 && command.stdin.is_some() {
            return Err(ParseError::InputConflict);
        }
    }
    Ok(commands)
}

/// Resolves `path` against the absolute directory `cwd` lexically:
/// `.` and empty components drop, `..` removes one (never above `/`).
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

pub struct Shell<H> {
    pub host: H,
    pub cwd: String,
    /// The last command's status (`$?`).
    pub status: i32,
}

/// Builtins that only write output, allowed at the head of a pipeline.
fn is_output_builtin(name: &str) -> bool {
    matches!(name, "pwd" | "echo" | "status" | "ps" | "help")
}

/// Builtins that act on the session or the shell: alone on a line only.
fn is_control_builtin(name: &str) -> bool {
    matches!(name, "cd" | "exit" | "shutdown" | "reboot")
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
        Self { host, cwd, status: 0 }
    }

    /// Runs one line: its pipelines in order, each after the join before it
    /// allows (`&&` needs status 0, `||` needs another), until one exits
    /// the shell, is interrupted, or the session has ended. Builtin output
    /// goes to `out`, diagnostics to `err`.
    pub fn run_line(&mut self, line: &str, out: &mut dyn Write, err: &mut dyn Write) -> Flow {
        let list = match parse(line) {
            Ok(list) => list,
            Err(error) => {
                let _ = writeln!(err, "absd-sh: {}", error.message());
                self.status = STATUS_USAGE;
                return Flow::Continue;
            }
        };
        let mut before = Join::Always;
        for pipeline in list {
            let runs = match before {
                Join::Always => true,
                Join::IfOk => self.status == 0,
                Join::IfFailed => self.status != 0,
            };
            before = pipeline.then;
            if !runs {
                continue;
            }
            let (status, flow, interrupted) = match pipeline.commands.as_slice() {
                [single] if is_builtin(&single.words[0]) => {
                    let (status, flow) = self.builtin_line(single, out, err);
                    (status, flow, false)
                }
                _ => {
                    let (status, interrupted) = self.pipeline(pipeline.commands, out, err);
                    (status, Flow::Continue, interrupted)
                }
            };
            self.status = status;
            let _ = out.flush();
            if flow != Flow::Continue || interrupted || self.host.ended() {
                return flow;
            }
        }
        Flow::Continue
    }

    /// Opens the shell's own redirections of a builtin run alone.
    fn builtin_line(&mut self, command: &Command, out: &mut dyn Write, err: &mut dyn Write) -> (i32, Flow) {
        let name = command.words[0].as_str();
        if !is_output_builtin(name)
            && (command.stdin.is_some() || command.stdout.is_some() || command.stderr.is_some())
        {
            let _ = writeln!(err, "absd-sh: {name}: takes no redirection");
            return (STATUS_USAGE, Flow::Continue);
        }
        if let Some(path) = &command.stdin {
            // Opened (and so checked) as any command's would be; unread.
            let path = resolve(&self.cwd, path);
            if let Err(error) = self.host.open_read(&path) {
                let _ = writeln!(err, "{}", open_error(&path, false, &error));
                return (STATUS_REDIRECT, Flow::Continue);
            }
        }
        let mut sinks = Vec::new();
        for redirect in [&command.stdout, &command.stderr] {
            let Some(Redirect { path, append }) = redirect else {
                sinks.push(None);
                continue;
            };
            let path = resolve(&self.cwd, path);
            match self.host.open_write(&path, *append) {
                Ok(sink) => sinks.push(Some((path, sink))),
                Err(error) => {
                    let _ = writeln!(err, "{}", open_error(&path, true, &error));
                    return (STATUS_REDIRECT, Flow::Continue);
                }
            }
        }
        let mut stderr_sink = sinks.pop().expect("two");
        let mut stdout_sink = sinks.pop().expect("two");
        let (mut status, flow) = {
            let out: &mut dyn Write = match &mut stdout_sink {
                Some((_, sink)) => sink,
                None => out,
            };
            let err: &mut dyn Write = match &mut stderr_sink {
                Some((_, sink)) => sink,
                None => err,
            };
            self.builtin(&command.words, out, err)
        };
        for (path, mut sink) in [stdout_sink, stderr_sink].into_iter().flatten() {
            if let Err(error) = sink.flush() {
                let _ = writeln!(err, "absd-sh: {path}: {error}");
                status = STATUS_REDIRECT;
            }
        }
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
            if narrowed != Authority::Shell && is_builtin(name) {
                let _ = writeln!(err, "absd-sh: {}: applies to programs, not the builtin {name}", command.words[0]);
                return (STATUS_USAGE, false);
            }
            if is_control_builtin(name) {
                let _ = writeln!(err, "absd-sh: {name}: cannot run in a pipeline");
                return (STATUS_USAGE, false);
            }
            if is_output_builtin(name) && index > 0 {
                let _ = writeln!(err, "absd-sh: {name}: a builtin can only start a pipeline");
                return (STATUS_USAGE, false);
            }
            if is_output_builtin(name) && (command.stdin.is_some() || command.stderr.is_some()) {
                let _ = writeln!(err, "absd-sh: {name}: a builtin in a pipeline takes no redirection");
                return (STATUS_USAGE, false);
            }
        }
        let mut stages = Vec::with_capacity(commands.len());
        let mut names = Vec::with_capacity(commands.len());
        let mut head: Option<Vec<u8>> = None;
        let last = commands.len() - 1;
        for (index, command) in commands.iter().enumerate() {
            let (narrowed, words) = authority(&command.words);
            let (name, args) = words.split_first().expect("non-empty");
            if is_output_builtin(name) {
                // Only first, and never last (a lone builtin runs above):
                // its output is the next command's input.
                let mut bytes = Vec::new();
                let _ = self.builtin(&command.words, &mut bytes, err);
                head = Some(bytes);
                continue;
            }
            let stdin = match (&command.stdin, index, head.take()) {
                (_, _, Some(bytes)) => Input::Bytes(bytes),
                (Some(path), _, None) => {
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
            let mut outputs = Vec::with_capacity(2);
            for (redirect, next) in [(&command.stdout, index < last), (&command.stderr, false)] {
                outputs.push(match redirect {
                    Some(Redirect { path, append }) => {
                        let path = resolve(&self.cwd, path);
                        match self.host.open_write(&path, *append) {
                            Ok(sink) => Output::File(sink),
                            Err(error) => {
                                let _ = writeln!(err, "{}", open_error(&path, true, &error));
                                return (STATUS_REDIRECT, false);
                            }
                        }
                    }
                    None if next => Output::Next,
                    None => Output::Inherit,
                });
            }
            let stderr = outputs.pop().expect("two");
            let stdout = outputs.pop().expect("two");
            names.push(name.clone());
            stages.push(Stage {
                program: program_path(&self.cwd, name),
                args: args.to_vec(),
                cwd: self.cwd.clone(),
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
                    if is_last {
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
            [] => "/".to_string(),
            [dir] => resolve(&self.cwd, dir),
            _ => {
                let _ = writeln!(err, "absd-sh: cd: too many arguments");
                return STATUS_USAGE;
            }
        };
        match self.host.is_dir(&target) {
            Ok(true) => {
                self.cwd = target;
                0
            }
            Ok(false) => {
                let _ = writeln!(err, "absd-sh: cd: {}: not a directory", args[0]);
                1
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let _ = writeln!(err, "absd-sh: cd: {}: not found", args[0]);
                1
            }
            Err(e) => {
                let _ = writeln!(err, "absd-sh: cd: {}: {e}", args[0]);
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
absd-sh: a line is pipelines joined by `;`, `&&` (next if ok), `||` (if not)
  pipeline: CMD [ARG...] [| CMD...]; < FILE, > FILE, >> FILE, 2> FILE, 2>> FILE
  CMD: a builtin below, /bin/NAME, or a path with a `/`; `ls /bin` lists them
  prefixes: `ro CMD` (read-only filesystem), `nofs CMD` (no filesystem)
builtins: cd [DIR]  pwd  echo [-n] [WORD...]  status  exit [N]  help
  ps (this session's processes)  shutdown -h|-p|-r now  reboot  (man absd-sh)
quoting: \"a b\" is one word; no variables, globbing, scripts, or jobs (`&`)
";

/// Parsed command line of the shell itself.
#[derive(Debug, Eq, PartialEq)]
pub enum Mode {
    /// Read lines from standard input, prompting before each.
    Interactive,
    /// Run one line and exit with its status (`-c LINE`).
    Command(String),
}

pub fn parse_args(args: &[String]) -> Result<Mode, String> {
    match args {
        [] => Ok(Mode::Interactive),
        [flag, line] if flag == "-c" => Ok(Mode::Command(line.clone())),
        _ => Err("usage: absd-sh [-c COMMAND]".to_string()),
    }
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
        Mode::Command(line) => match shell.run_line(&line, out, err) {
            _ if shell.host.ended() => STATUS_INTERRUPTED,
            Flow::Exit(code) => code,
            Flow::Continue => shell.status,
        },
        Mode::Interactive => {
            let mut line = String::new();
            loop {
                let _ = out.write_all(PROMPT.as_bytes());
                let _ = out.flush();
                line.clear();
                match input.read_line(&mut line) {
                    Ok(0) => return shell.status,
                    Ok(_) if line.ends_with('\n') => shell.host.line_read(),
                    Ok(_) => {}
                    Err(e) => {
                        let _ = writeln!(err, "absd-sh: read: {e}");
                        return STATUS_USAGE;
                    }
                }
                if shell.host.ended() {
                    return STATUS_INTERRUPTED;
                }
                let flow = shell.run_line(&line, out, err);
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
