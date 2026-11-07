//! Native evaluation of the pinned upstream conch shell AST. No fork emulation.
use super::*;
use conch_parser::{ast as a, lexer::Lexer, parse::DefaultParser};
use std::io::Read;

type Program = Vec<a::TopLevelCommand<String>>;
type Word = a::TopLevelWord<String>;

#[cfg(test)]
std::thread_local! {
    pub(super) static CONTINUATION_PARSE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn parse_program(source: &str) -> Result<Program, String> {
    if source.len() > MAX_SCRIPT_BYTES {
        return Err("script exceeds 1 MiB".into());
    }
    let program = DefaultParser::new(Lexer::new(source.chars()))
        .into_iter()
        .collect::<Result<Program, _>>()
        .map_err(|e| e.to_string())?;
    validate_program(&program, &BTreeSet::new(), 0)?;
    Ok(program)
}

pub(super) enum Continuation {
    Complete,
    Syntax,
    Heredoc(HeredocDelimiter),
}

/// The normalized delimiter comes from the parser, including its tab mode.
/// A conservative reparse hint; only the parser decides delimiter recognition.
pub(super) struct HeredocDelimiter {
    word: String,
    strip_tabs: bool,
    joined_tail: bool,
}
impl HeredocDelimiter {
    pub(super) fn may_finish(&self, line: &str) -> bool {
        // A delimiter may be split across physical lines. Reparse at joins
        // and after a possible joined tail; quoted/even-slash cases may cause
        // an extra parse but cannot decide completion without the parser.
        if self.joined_tail || line.contains("\\\n") || line.ends_with('\\') {
            return true;
        }
        // A private input record may contain many physical lines, including
        // the delimiter followed by another command. The parser remains the
        // authority; this scan only decides when it must run again.
        line.split_inclusive('\n').any(|line| {
            let line = line.strip_suffix('\n').unwrap_or(line);
            let line = if self.strip_tabs { line.trim_start_matches('\t') } else { line };
            line == self.word
        })
    }
}

/// An unmatched opener reports its opener, not the stopping position. Use
/// the parser's actual cursor to distinguish EOF from a bad middle token.
pub(super) fn continuation(source: &str) -> Continuation {
    #[cfg(test)]
    CONTINUATION_PARSE_CALLS.with(|count| count.set(count.get() + 1));
    let mut parser = DefaultParser::new(Lexer::new(source.chars()));
    loop {
        match parser.complete_command() {
            Ok(Some(_)) => {}
            Ok(None) => return Continuation::Complete,
            Err(error) => {
                if parser.pos().byte < source.trim_end().len() {
                    return Continuation::Complete;
                }
                return match error {
                    conch_parser::parse::ParseError::UnterminatedHeredoc(word, _, strip_tabs) =>
                        Continuation::Heredoc(HeredocDelimiter { word, strip_tabs,
                            joined_tail: source.ends_with("\\\n") || source.ends_with('\\') }),
                    conch_parser::parse::ParseError::UnexpectedEOF
                        | conch_parser::parse::ParseError::Unmatched(..)
                        | conch_parser::parse::ParseError::IncompleteCmd(..) => Continuation::Syntax,
                    _ => Continuation::Complete,
                };
            }
        }
    }
}

#[cfg(test)]
pub(super) fn incomplete(source: &str) -> bool {
    !matches!(continuation(source), Continuation::Complete)
}

#[derive(Clone)]
struct State {
    cwd: String,
    vars: BTreeMap<String, String>,
    exported: BTreeSet<String>,
    positional: Vec<String>,
    functions: BTreeMap<String, a::DefaultCompoundCommand>,
    loop_control: Option<bool>,
    loop_depth: usize,
}

impl<H: Host> Shell<H> {
    /// Startup environment is explicit; local assignments stay private until exported.
    pub fn set_environment(&mut self, env: impl IntoIterator<Item = (String, String)>) {
        for (key, value) in env {
            self.exported.insert(key.clone());
            self.vars.insert(key, value);
        }
    }
    pub fn set_positional(&mut self, args: Vec<String>) {
        self.positional = args;
    }
    fn save(&self) -> State {
        State {
            cwd: self.cwd.clone(),
            vars: self.vars.clone(),
            exported: self.exported.clone(),
            positional: self.positional.clone(),
            functions: self.functions.clone(),
            loop_control: self.loop_control,
            loop_depth: self.loop_depth,
        }
    }
    fn restore(&mut self, state: State) {
        self.cwd = state.cwd;
        self.vars = state.vars;
        self.exported = state.exported;
        self.positional = state.positional;
        self.functions = state.functions;
        self.loop_control = state.loop_control;
        self.loop_depth = state.loop_depth;
    }
    fn with_fresh_loop_context<T>(&mut self, body: impl FnOnce(&mut Self) -> T) -> T {
        let control = self.loop_control.take();
        let depth = std::mem::replace(&mut self.loop_depth, 0);
        let result = body(self);
        self.loop_control = control;
        self.loop_depth = depth;
        result
    }
    fn stopped(&self, flow: Flow) -> bool {
        flow != Flow::Continue || self.loop_control.is_some() || self.halted || self.host.ended()
    }
    pub(super) fn eval_program(
        &mut self,
        program: &[a::TopLevelCommand<String>],
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<Flow, String> {
        validate_program(program, &self.functions.keys().cloned().collect(), 0)?;
        self.depth += 1;
        if self.depth > 64 {
            self.depth -= 1;
            return Err("shell nesting exceeds 64 levels".into());
        }
        let result = self.eval_program_inner(program, out, err);
        self.depth -= 1;
        result
    }
    fn eval_program_inner(
        &mut self,
        program: &[a::TopLevelCommand<String>],
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<Flow, String> {
        for command in program {
            self.steps += 1;
            if self.steps > 100_000 {
                return Err("execution step limit (100000) exceeded".into());
            }
            if self.host.interrupted() {
                self.status = STATUS_INTERRUPTED;
                self.halted = true;
                return Ok(Flow::Continue);
            }
            let list = match &command.0 {
                a::Command::Job(_) => return Err("background jobs are not supported".into()),
                a::Command::List(list) => list,
            };
            let mut flow = self.with_status_reporting(list.rest.is_empty(), |shell| {
                shell.eval_listable(&list.first, out, err)
            })?;
            if self.stopped(flow) {
                return Ok(flow);
            }
            for (index, item) in list.rest.iter().enumerate() {
                let next = match item {
                    a::AndOr::And(cmd) if self.status == 0 => Some(cmd),
                    a::AndOr::Or(cmd) if self.status != 0 => Some(cmd),
                    _ => None,
                };
                if let Some(cmd) = next {
                    flow = self.with_status_reporting(index + 1 == list.rest.len(), |shell| {
                        shell.eval_listable(cmd, out, err)
                    })?;
                }
                if self.stopped(flow) {
                    return Ok(flow);
                }
            }
        }
        Ok(Flow::Continue)
    }
    fn with_status_reporting<T>(&mut self, enabled: bool, body: impl FnOnce(&mut Self) -> T) -> T {
        let previous = self.report_native_status;
        self.report_native_status = previous && enabled;
        let result = body(self);
        self.report_native_status = previous;
        result
    }
    fn eval_listable(
        &mut self,
        command: &a::DefaultListableCommand,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<Flow, String> {
        let report = !matches!(command, a::ListableCommand::Pipe(true, _));
        self.with_status_reporting(report, |shell| shell.eval_listable_inner(command, out, err))
    }
    fn eval_listable_inner(
        &mut self,
        command: &a::DefaultListableCommand,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<Flow, String> {
        match command {
            a::ListableCommand::Single(command) => self.eval_pipeable(command, out, err),
            a::ListableCommand::Pipe(negate, commands) => {
                let flow = if commands.len() == 1 {
                    self.eval_pipeable(&commands[0], out, err)?
                } else {
                    let saved = self.save();
                    let result: Result<Flow, String> = (|| {
                        let mut expanded = Vec::new();
                        for command in commands {
                            let a::PipeableCommand::Simple(simple) = command else {
                                return Err(
                                    "compound commands in pipelines are not supported".into()
                                );
                            };
                            let (cmd, assignments) = self.expand_command(simple, err)?;
                            if !assignments.is_empty() {
                                return Err("command-local assignments in pipelines are not supported; export first".into());
                            }
                            if cmd.words.is_empty()
                                || language_builtin(&cmd.words[0])
                                || self.functions.contains_key(&cmd.words[0])
                            {
                                return Err(
                                    "script builtins and functions in pipelines are not supported"
                                        .into(),
                                );
                            }
                            expanded.push(cmd);
                        }
                        for (index, cmd) in expanded.iter().enumerate() {
                            if index > 0 && cmd.stdin.is_some() {
                                return Err("input cannot come from both a file and a pipe".into());
                            }
                        }
                        Ok(self.execute(expanded, out, err))
                    })();
                    self.restore(saved);
                    result?
                };
                if *negate {
                    self.status = i32::from(self.status == 0);
                }
                Ok(flow)
            }
        }
    }
    fn eval_pipeable(
        &mut self,
        command: &a::DefaultPipeableCommand,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<Flow, String> {
        match command {
            a::PipeableCommand::Simple(simple) => self.eval_simple(simple, out, err),
            a::PipeableCommand::Compound(compound) => self.eval_compound(compound, out, err),
            a::PipeableCommand::FunctionDef(name, body) => {
                self.functions.insert(name.clone(), (**body).clone());
                self.status = 0;
                Ok(Flow::Continue)
            }
        }
    }
    fn eval_compound(
        &mut self,
        command: &a::DefaultCompoundCommand,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<Flow, String> {
        if !command.io.is_empty() {
            let mut redirects = Command::default();
            for redirect in &command.io {
                self.expand_redirect(&mut redirects, redirect, err)?;
            }
            let mut plain = command.clone();
            plain.io.clear();
            return self.with_redirects(&redirects, out, err, |shell, out, err| {
                shell.eval_compound(&plain, out, err)
            });
        }
        use a::CompoundCommandKind::*;
        match &command.kind {
            Brace(body) => self.eval_program(body, out, err),
            Subshell(body) => {
                let state = self.save();
                let result = self.with_fresh_loop_context(|shell| shell.eval_program(body, out, err));
                self.restore(state);
                result.map(|_| Flow::Continue)
            }
            If {
                conditionals,
                else_branch,
            } => {
                for branch in conditionals {
                    let flow = self.with_status_reporting(false, |shell| {
                        shell.eval_program(&branch.guard, out, err)
                    })?;
                    if self.stopped(flow) {
                        return Ok(flow);
                    }
                    if self.status == 0 {
                        return self.eval_program(&branch.body, out, err);
                    }
                }
                if let Some(body) = else_branch {
                    self.eval_program(body, out, err)
                } else {
                    self.status = 0;
                    Ok(Flow::Continue)
                }
            }
            For { var, words, body } => {
                let mut values = Vec::new();
                if let Some(words) = words {
                    for word in words {
                        values.extend(self.expand_word(word, true, err)?);
                    }
                } else {
                    values.extend(self.positional.iter().skip(1).cloned());
                }
                self.status = 0;
                self.loop_depth += 1;
                let result = (|| {
                    for value in values {
                        self.vars.insert(var.clone(), value);
                        let flow = self.eval_program(body, out, err)?;
                        let control = self.loop_control.take();
                        if self.stopped(flow) || control == Some(true) {
                            return Ok(flow);
                        }
                    }
                    Ok(Flow::Continue)
                })();
                self.loop_depth -= 1;
                result
            }
            While(pair) | Until(pair) => {
                let until = matches!(&command.kind, Until(_));
                self.loop_depth += 1;
                let result = (|| {
                    let mut status = 0;
                    loop {
                        let flow = self.with_status_reporting(false, |shell| {
                            shell.eval_program(&pair.guard, out, err)
                        })?;
                        let control = self.loop_control.take();
                        if self.stopped(flow) {
                            return Ok(flow);
                        }
                        if (self.status == 0) == until {
                            self.status = status;
                            return Ok(Flow::Continue);
                        }
                        match control {
                            Some(true) => return Ok(flow),
                            Some(false) => continue,
                            None => {}
                        }
                        let flow = self.eval_program(&pair.body, out, err)?;
                        status = self.status;
                        let control = self.loop_control.take();
                        if self.stopped(flow) || control == Some(true) {
                            return Ok(flow);
                        }
                    }
                })();
                self.loop_depth -= 1;
                result
            }
            Case { word, arms } => {
                let value = self.expand_word(word, false, err)?.join("");
                for arm in arms {
                    for pattern in &arm.patterns {
                        let pattern = self
                            .expand_word_internal(pattern, false, true, true, err)?
                            .join("");
                        if glob::Pattern::new(&pattern)
                            .map_err(|e| e.to_string())?
                            .matches(&value)
                        {
                            return self.eval_program(&arm.body, out, err);
                        }
                    }
                }
                self.status = 0;
                Ok(Flow::Continue)
            }
        }
    }
    fn expand_command(
        &mut self,
        command: &a::DefaultSimpleCommand,
        err: &mut dyn Write,
    ) -> Result<(Command, Vec<(String, String)>), String> {
        let mut cmd = Command::default();
        let mut assignments = Vec::new();
        self.substitution_status = None;
        let mut previous = BTreeMap::new();
        let prefix: Result<(), String> = (|| {
            for item in &command.redirects_or_env_vars {
                match item {
                    a::RedirectOrEnvVar::EnvVar(name, value) => {
                        let value = match value {
                            Some(w) => self.expand_word(w, false, err)?.join(""),
                            None => String::new(),
                        };
                        previous
                            .entry(name.clone())
                            .or_insert_with(|| self.vars.get(name).cloned());
                        self.vars.insert(name.clone(), value.clone());
                        assignments.push((name.clone(), value));
                    }
                    a::RedirectOrEnvVar::Redirect(r) => self.expand_redirect(&mut cmd, r, err)?,
                }
            }
            Ok(())
        })();
        for (key, value) in previous {
            match value {
                Some(value) => {
                    self.vars.insert(key, value);
                }
                None => {
                    self.vars.remove(&key);
                }
            }
        }
        prefix?;
        for item in &command.redirects_or_cmd_words {
            match item {
                a::RedirectOrCmdWord::CmdWord(word) => cmd.words.extend(self.expand_word(
                    word,
                    cmd.words.first().map(String::as_str) != Some("export"),
                    err,
                )?),
                a::RedirectOrCmdWord::Redirect(r) => self.expand_redirect(&mut cmd, r, err)?,
            }
        }
        Ok((cmd, assignments))
    }
    fn expand_redirect(
        &mut self,
        cmd: &mut Command,
        redirect: &a::DefaultRedirect,
        err: &mut dyn Write,
    ) -> Result<(), String> {
        use a::Redirect::*;
        if let Heredoc(fd, word) = redirect {
            if fd.unwrap_or(0) != 0 || cmd.stdin.is_some() {
                return Err("unsupported descriptor or duplicate input redirection".into());
            }
            cmd.stdin = Some(CommandInput::Bytes(self.expand_heredoc(word, err)?));
            return Ok(());
        }
        if let DupWrite(fd, word) = redirect {
            let fd = fd.unwrap_or(1);
            let from = static_word(word).and_then(|s| match s.as_str() { "1" => Some(1), "2" => Some(2), _ => None })
                .ok_or("output duplication requires literal descriptor 1 or 2")?;
            if !matches!(fd, 1 | 2) { return Err("only output descriptors 1 and 2 are supported".into()); }
            cmd.redirects.push(super::Redirect::Dup { fd: fd as u8, from });
            return Ok(());
        }
        let (fd, word, append) = match redirect {
            Read(fd, word) => (fd.unwrap_or(0), word, false),
            Write(fd, word) | Clobber(fd, word) => (fd.unwrap_or(1), word, false),
            Append(fd, word) => (fd.unwrap_or(1), word, true),
            _ => return Err("unsupported redirection".into()),
        };
        let words = self.expand_word(word, true, err)?;
        if words.len() != 1 { return Err("ambiguous redirection".into()); }
        let path = words[0].clone();
        match (redirect, fd) {
            (Read(..), 0) if cmd.stdin.is_none() => cmd.stdin = Some(CommandInput::File(path)),
            (_, 1 | 2) if !matches!(redirect, Read(..)) => {
                cmd.redirects.push(super::Redirect::File { fd: fd as u8, path, append });
            }
            _ => return Err("unsupported descriptor or duplicate input redirection".into()),
        }
        Ok(())
    }

    /// The parser has already resolved delimiter quoting and tab stripping.
    /// Expand its body AST as text, without argument splitting, glob or tilde
    /// expansion. Check each append before growing the bounded input buffer.
    fn expand_heredoc(&mut self, word: &Word, err: &mut dyn Write) -> Result<Vec<u8>, String> {
        let parts = match &word.0 {
            a::ComplexWord::Single(part) => std::slice::from_ref(part),
            a::ComplexWord::Concat(parts) => parts.as_slice(),
        };
        let mut bytes = Vec::new();
        let mut append = |text: &str| -> Result<(), String> {
            if text.len() > MAX_SCRIPT_BYTES - bytes.len() {
                return Err("heredoc exceeds 1 MiB".into());
            }
            bytes.extend_from_slice(text.as_bytes());
            Ok(())
        };
        for part in parts {
            match part {
                a::Word::SingleQuoted(text) => append(text)?,
                a::Word::Simple(a::SimpleWord::Escaped(text)) if text == "\"" => append("\\\"")?,
                a::Word::Simple(a::SimpleWord::Escaped(text)) if text == "\n" => {},
                a::Word::Simple(part) => append(&self.simple_word(part, false, err)?)?,
                a::Word::DoubleQuoted(parts) => {
                    for part in parts { append(&self.simple_word(part, false, err)?)?; }
                }
            }
        }
        Ok(bytes)
    }

    fn eval_simple(
        &mut self,
        simple: &a::DefaultSimpleCommand,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<Flow, String> {
        let (cmd, assignments) = self.expand_command(simple, err)?;
        if self.halted || self.host.ended() {
            self.status = STATUS_INTERRUPTED;
            return Ok(Flow::Continue);
        }
        if cmd.words.is_empty() {
            self.vars.extend(assignments);
            self.status = self.substitution_status.unwrap_or(0);
            // An assignment-only redirection still opens/truncates its target.
            if cmd.stdin.is_some() || !cmd.redirects.is_empty() {
                let mut no_op = cmd;
                no_op.words.push("echo".into());
                no_op.words.push("-n".into());
                let saved = self.status;
                self.execute(vec![no_op], out, err);
                if self.status == 0 {
                    self.status = saved;
                }
            }
            return Ok(Flow::Continue);
        }
        let mut previous = BTreeMap::new();
        for (key, value) in &assignments {
            previous
                .entry(key.clone())
                .or_insert_with(|| (self.vars.get(key).cloned(), self.exported.contains(key)));
            self.vars.insert(key.clone(), value.clone());
            self.exported.insert(key.clone());
        }
        let result = self.eval_expanded(cmd, out, err);
        for (key, (value, exported)) in previous {
            match value {
                Some(value) => {
                    self.vars.insert(key.clone(), value);
                }
                None => {
                    self.vars.remove(&key);
                }
            }
            if exported {
                self.exported.insert(key);
            } else {
                self.exported.remove(&key);
            }
        }
        result
    }
    fn eval_expanded(
        &mut self,
        cmd: Command,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<Flow, String> {
        let name = cmd.words[0].as_str();
        let args = &cmd.words[1..];
        if matches!(cmd.stdin, Some(CommandInput::Bytes(_)))
            && (language_builtin(name) || self.functions.contains_key(name)
                || (is_builtin(name) && (name != "ps" || args.is_empty())))
        {
            return Err("heredocs require a native consuming command".into());
        }
        if unsupported_builtin(name) {
            return Err(format!("unsupported builtin `{name}`"));
        }
        if (language_builtin(name) || self.functions.contains_key(name))
            && (cmd.stdin.is_some() || !cmd.redirects.is_empty())
        {
            let mut plain = cmd.clone();
            plain.stdin = None;
            plain.redirects.clear();
            return self.with_redirects(&cmd, out, err, |shell, out, err| {
                shell.eval_expanded(plain, out, err)
            });
        }
        if let Some(body) = self.functions.get(name).cloned() {
            let args = std::iter::once(
                self.positional
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "sh".into()),
            )
            .chain(cmd.words[1..].iter().cloned())
            .collect();
            let positional = std::mem::replace(&mut self.positional, args);
            let result = self.with_fresh_loop_context(|shell| shell.eval_compound(&body, out, err));
            self.positional = positional;
            return result;
        }
        if matches!(name, "ro" | "nofs")
            && cmd
                .words
                .get(1)
                .is_some_and(|name| language_builtin(name) || self.functions.contains_key(name))
        {
            return Err(format!(
                "{name}: applies to native programs, not interpreted commands"
            ));
        }
        if language_builtin(name) {
            if cmd.stdin.is_some() || !cmd.redirects.is_empty() {
                return Err(format!(
                    "{name}: script builtin redirection is not supported"
                ));
            }
            self.status = 0;
            match name {
                ":" | "true" => {}
                "false" => self.status = 1,
                "export" => {
                    for arg in args {
                        let (key, value) = arg
                            .split_once('=')
                            .map_or((arg.as_str(), None), |(k, v)| (k, Some(v)));
                        if !valid_name(key) {
                            return Err(format!("export: {key}: invalid variable name"));
                        }
                        if let Some(value) = value {
                            self.vars.insert(key.into(), value.into());
                        } else {
                            self.vars.entry(key.into()).or_default();
                        }
                        self.exported.insert(key.into());
                    }
                }
                "unset" => {
                    for arg in args {
                        self.vars.remove(arg);
                        self.exported.remove(arg);
                    }
                }
                "set" => {
                    if args.first().map(String::as_str) != Some("--") {
                        return Err("set: supported form is set -- [ARG...]".into());
                    }
                    self.positional.truncate(1);
                    self.positional.extend_from_slice(&args[1..]);
                }
                "shift" => {
                    let count = match args {
                        [] => 1,
                        [n] => n.parse::<usize>().map_err(|_| "shift: invalid count")?,
                        _ => return Err("shift: too many arguments".into()),
                    };
                    if count >= self.positional.len() {
                        self.status = 1;
                    } else {
                        self.positional.drain(1..=count);
                    }
                }
                "break" | "continue" => {
                    if !args.is_empty() {
                        return Err(format!(
                            "{name}: only the innermost loop is supported (no arguments)"
                        ));
                    }
                    if self.loop_depth == 0 {
                        let _ = writeln!(err, "absd-sh: {name}: outside a loop");
                    } else {
                        self.loop_control = Some(name == "break");
                    }
                }
                "sh" | "/bin/sh" | "absd-sh" | "/bin/absd-sh" => {
                    return self.invoke_script(args, false, out, err);
                }
                "." => return self.invoke_script(args, true, out, err),
                _ => unreachable!(),
            }
            return Ok(Flow::Continue);
        }
        if program_path(&self.cwd, name) == "/bin/https-document"
            && !(cmd.words.len() == 2 && cmd.words[1] == "--sample")
        {
            return Ok(self.execute(vec![cmd], out, err));
        }
        // Direct executable scripts are interpreted by this authority-holding shell.
        // Probe only an explicit path; ELF commands remain native processes.
        if name.contains('/') {
            let path = resolve(&self.cwd, name);
            if let Ok(mut file) = self.host.open_read(&path) {
                let mut prefix = [0; 2];
                if file.read_exact(&mut prefix).is_ok() && prefix == *b"#!" {
                    return self.with_redirects(&cmd, out, err, |shell, out, err| {
                        shell.invoke_script(&cmd.words, false, out, err)
                    });
                }
            }
        }
        Ok(self.execute(vec![cmd], out, err))
    }
    pub(super) fn invoke_script(
        &mut self,
        args: &[String],
        source: bool,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<Flow, String> {
        match self.invoke_script_inner(args, source, out, err) {
            Ok(flow) => Ok(flow),
            Err(error) => {
                let _ = writeln!(err, "absd-sh: {error}");
                self.status = if self.halted || self.host.ended() {
                    STATUS_INTERRUPTED
                } else {
                    STATUS_USAGE
                };
                Ok(Flow::Continue)
            }
        }
    }
    fn invoke_script_inner(
        &mut self,
        args: &[String],
        source: bool,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<Flow, String> {
        let (text, positional) = if args.first().map(String::as_str) == Some("-c") && !source {
            let text = args.get(1).ok_or("sh -c: command required")?.clone();
            let positional = if args.len() > 2 {
                args[2..].to_vec()
            } else {
                vec!["sh".into()]
            };
            (text, positional)
        } else {
            let name = args
                .first()
                .ok_or("sh: script path required (interactive nested shell is unsupported)")?;
            let path = resolve(&self.cwd, name);
            let mut file = self
                .host
                .open_read(&path)
                .map_err(|e| format!("{name}: {e}"))?;
            let mut text = String::new();
            file.by_ref()
                .take((MAX_SCRIPT_BYTES + 1) as u64)
                .read_to_string(&mut text)
                .map_err(|e| format!("{name}: {e}"))?;
            if text.starts_with("#!") {
                let interpreter = text.lines().next().unwrap()[2..].trim();
                if !matches!(interpreter, "/bin/sh" | "/bin/absd-sh") {
                    return Err(format!("{name}: unsupported shebang {interpreter}"));
                }
            }
            (text, args.to_vec())
        };
        let program = parse_program(&text)?;
        let saved = self.save();
        self.status = 0;
        if !source || args.len() > 1 {
            self.positional = positional;
        }
        self.loop_control = None;
        self.loop_depth = 0;
        let result = self.eval_program(&program, out, err);
        if !source {
            self.restore(saved);
            result.map(|_| Flow::Continue)
        } else {
            self.positional = saved.positional;
            self.loop_depth = saved.loop_depth;
            result
        }
    }
    fn with_redirects<F>(
        &mut self,
        cmd: &Command,
        out: &mut dyn Write,
        err: &mut dyn Write,
        body: F,
    ) -> Result<Flow, String>
    where
        F: FnOnce(&mut Self, &mut dyn Write, &mut dyn Write) -> Result<Flow, String>,
    {
        if cmd.stdin.is_some() {
            return Err("input redirection on interpreted scripts/compounds is unsupported; redirect the consuming command".into());
        }
        let destinations = match self.resolve_outputs(cmd, false) {
            Ok(destinations) => destinations,
            Err(error) => {
                let _ = writeln!(err, "{error}");
                self.status = STATUS_REDIRECT;
                return Ok(Flow::Continue);
            }
        };
        let previous = std::mem::replace(&mut self.output_context, destinations.clone());
        let result = super::streams::with_writers(&destinations, &previous, out, err, |out, err| {
            body(self, out, err)
        });
        self.output_context = previous;
        if let Err(error) = super::streams::flush(&destinations) {
            let _ = writeln!(err, "absd-sh: {error}");
            self.status = STATUS_REDIRECT;
            return match result {
                Ok(Flow::Exit(_)) => Ok(Flow::Exit(STATUS_REDIRECT)),
                Ok(flow) => Ok(flow),
                Err(error) => Err(error),
            };
        }
        result
    }

    fn parameter(&self, param: &a::DefaultParameter) -> String {
        use a::Parameter::*;
        match param {
            Var(name) => self.vars.get(name).cloned().unwrap_or_default(),
            Positional(n) => self
                .positional
                .get(*n as usize)
                .cloned()
                .unwrap_or_default(),
            Question => self.status.to_string(),
            Pound => self.positional.len().saturating_sub(1).to_string(),
            At | Star => self
                .positional
                .iter()
                .skip(1)
                .cloned()
                .collect::<Vec<_>>()
                .join(" "),
            Dollar => std::process::id().to_string(),
            Dash | Bang => String::new(),
        }
    }
    fn param_set(&self, param: &a::DefaultParameter, null: bool) -> bool {
        let set = match param {
            a::Parameter::Var(name) => self.vars.contains_key(name),
            a::Parameter::Positional(n) => (*n as usize) < self.positional.len(),
            _ => true,
        };
        set && (!null || !self.parameter(param).is_empty())
    }
    fn substitution(
        &mut self,
        sub: &a::DefaultParameterSubstitution,
        tilde: bool,
        err: &mut dyn Write,
    ) -> Result<String, String> {
        use a::ParameterSubstitution::*;
        match sub {
            Command(program) => {
                let saved = self.save();
                let saved_status = self.status;
                let capture = Capture::new();
                self.loop_depth = 0;
                self.loop_control = None;
                let output_context = std::mem::replace(&mut self.output_context[0],
                    Rc::new(Destination::Capture(capture.clone())));
                let result = self.eval_program(program, &mut capture.clone(), err);
                self.output_context[0] = output_context;
                let status = self.status;
                self.restore(saved);
                self.status = saved_status;
                result?;
                if capture.1.get() {
                    return Err("command substitution exceeds 1 MiB".into());
                }
                self.substitution_status = Some(status);
                String::from_utf8(capture.bytes())
                    .map(|s| s.trim_end_matches('\n').to_string())
                    .map_err(|_| "command substitution output is not UTF-8".into())
            }
            Len(param) => Ok(self.parameter(param).chars().count().to_string()),
            Default(null, param, word)
            | Assign(null, param, word)
            | Error(null, param, word)
            | Alternative(null, param, word) => {
                let set = self.param_set(param, *null);
                if matches!(sub, Alternative(..)) && !set {
                    return Ok(String::new());
                }
                if set && !matches!(sub, Alternative(..)) {
                    return Ok(self.parameter(param));
                }
                let value = match word {
                    Some(word) => self.expand_word_internal(word, false, false, tilde, err)?.join(""),
                    None => String::new(),
                };
                if matches!(sub, Error(..)) {
                    return Err(if value.is_empty() {
                        "parameter is unset".into()
                    } else {
                        value
                    });
                }
                if matches!(sub, Assign(..)) {
                    let a::Parameter::Var(name) = param else {
                        return Err("cannot assign a positional parameter".into());
                    };
                    self.vars.insert(name.clone(), value.clone());
                }
                Ok(value)
            }
            Arith(None) => Ok("0".into()),
            Arith(Some(expr)) => self.arithmetic(expr).map(|v| v.to_string()),
            _ => Err("parameter prefix/suffix pattern removal is not supported".into()),
        }
    }
    fn arithmetic(&mut self, expr: &a::DefaultArithmetic) -> Result<isize, String> {
        use a::Arithmetic::*;
        let overflow = || "arithmetic overflow or division by zero".to_string();
        match expr {
            Literal(v) => Ok(*v),
            Var(name) => self
                .vars
                .get(name)
                .map(String::as_str)
                .unwrap_or("0")
                .parse()
                .map_err(|_| format!("{name}: not an integer")),
            Add(l, r) => self
                .arithmetic(l)?
                .checked_add(self.arithmetic(r)?)
                .ok_or_else(overflow),
            Sub(l, r) => self
                .arithmetic(l)?
                .checked_sub(self.arithmetic(r)?)
                .ok_or_else(overflow),
            Mult(l, r) => self
                .arithmetic(l)?
                .checked_mul(self.arithmetic(r)?)
                .ok_or_else(overflow),
            Div(l, r) => self
                .arithmetic(l)?
                .checked_div(self.arithmetic(r)?)
                .ok_or_else(overflow),
            Modulo(l, r) => self
                .arithmetic(l)?
                .checked_rem(self.arithmetic(r)?)
                .ok_or_else(overflow),
            UnaryPlus(e) => self.arithmetic(e),
            UnaryMinus(e) => self.arithmetic(e)?.checked_neg().ok_or_else(overflow),
            LogicalNot(e) => Ok(isize::from(self.arithmetic(e)? == 0)),
            _ => {
                Err("unsupported arithmetic operator (supported: + - * / % and unary + - !)".into())
            }
        }
    }
    fn expand_word(
        &mut self,
        word: &Word,
        split: bool,
        err: &mut dyn Write,
    ) -> Result<Vec<String>, String> {
        self.expand_word_internal(word, split, false, true, err)
    }
    fn expand_word_internal(
        &mut self,
        word: &Word,
        split: bool,
        pattern_only: bool,
        tilde: bool,
        err: &mut dyn Write,
    ) -> Result<Vec<String>, String> {
        let parts: Vec<_> = match &word.0 {
            a::ComplexWord::Single(w) => vec![w],
            a::ComplexWord::Concat(parts) => parts.iter().collect(),
        };
        let mut fields = vec![Field::default()];
        for (index, part) in parts.iter().enumerate() {
            match part {
                a::Word::SingleQuoted(text) => append(&mut fields, text, false, false, true),
                a::Word::DoubleQuoted(parts) => {
                    if parts.is_empty() {
                        fields.last_mut().unwrap().keep_empty = true;
                    }
                    for part in parts {
                        if matches!(part, a::SimpleWord::Param(a::Parameter::At)) {
                            let values: Vec<_> = self.positional.iter().skip(1).cloned().collect();
                            if let Some(first) = values.first() {
                                append(&mut fields, first, false, false, true);
                                for value in &values[1..] {
                                    fields.push(Field::default());
                                    append(&mut fields, value, false, false, true);
                                }
                            }
                        } else {
                            let value = self.simple_word(part, tilde, err)?;
                            append(&mut fields, &value, false, false, true);
                        }
                    }
                }
                a::Word::Simple(part) => {
                    let value = if tilde && index == 0
                        && matches!(part, a::SimpleWord::Tilde)
                        && (parts.len() == 1
                            || matches!(parts.get(1), Some(a::Word::Simple(a::SimpleWord::Literal(text))) if text.starts_with('/')))
                    {
                        self.vars.get("HOME").cloned().unwrap_or("~".into())
                    } else {
                        self.simple_word(part, tilde, err)?
                    };
                    let expanded =
                        matches!(part, a::SimpleWord::Param(_) | a::SimpleWord::Subst(_));
                    let escaped = matches!(part, a::SimpleWord::Escaped(_));
                    append(&mut fields, &value, !escaped, split && expanded, escaped);
                }
            }
        }
        let mut separated = Vec::new();
        for field in fields {
            if !split {
                separated.push((field.text, field.pattern));
                continue;
            }
            let mut text = String::new();
            let mut pattern = String::new();
            // Pattern escaping is reconstructed per character after field splitting.
            let mut protected_empty = field.keep_empty;
            for (index, ch) in field.text.char_indices() {
                if field.split[index] && matches!(ch, ' ' | '\t' | '\n') {
                    if !text.is_empty() {
                        separated.push((std::mem::take(&mut text), std::mem::take(&mut pattern)));
                        protected_empty = false;
                    }
                } else {
                    text.push(ch);
                    if field.glob[index] {
                        pattern.push(ch);
                    } else {
                        pattern.push_str(&glob::Pattern::escape(&ch.to_string()));
                    }
                }
            }
            if !text.is_empty() || protected_empty {
                separated.push((text, pattern));
            }
        }
        if pattern_only {
            return Ok(separated.into_iter().map(|(_, pattern)| pattern).collect());
        }
        let mut result = Vec::new();
        for (value, pattern) in separated {
            if split && pattern.contains(['*', '?', '[']) {
                let full = if pattern.starts_with('/') {
                    pattern.clone()
                } else {
                    format!("{}/{}", self.cwd.trim_end_matches('/'), pattern)
                };
                let options = glob::MatchOptions {
                    require_literal_leading_dot: true,
                    ..Default::default()
                };
                let matches: Result<Vec<_>, _> = glob::glob_with(&full, options)
                    .map_err(|e| e.to_string())?
                    .collect();
                let matches = matches.map_err(|e| format!("glob: {e}"))?;
                if !matches.is_empty() {
                    for path in matches {
                        let text = path.to_str().ok_or("glob path is not UTF-8")?;
                        result.push(if value.starts_with('/') {
                            text.to_string()
                        } else {
                            text.strip_prefix(&format!("{}/", self.cwd.trim_end_matches('/')))
                                .unwrap_or(text)
                                .to_string()
                        });
                    }
                    continue;
                }
            }
            result.push(value);
        }
        Ok(result)
    }
    fn simple_word(
        &mut self,
        word: &a::DefaultSimpleWord,
        tilde: bool,
        err: &mut dyn Write,
    ) -> Result<String, String> {
        use a::SimpleWord::*;
        Ok(match word {
            Literal(text) | Escaped(text) => text.clone(),
            Param(param) => self.parameter(param),
            Subst(sub) => self.substitution(sub, tilde, err)?,
            Star => "*".into(),
            Question => "?".into(),
            SquareOpen => "[".into(),
            SquareClose => "]".into(),
            Tilde => "~".into(),
            Colon => ":".into(),
        })
    }
}
#[derive(Default)]
struct Field {
    text: String,
    pattern: String,
    split: Vec<bool>,
    glob: Vec<bool>,
    keep_empty: bool,
}
fn append(fields: &mut [Field], text: &str, glob: bool, split: bool, keep_empty: bool) {
    let last = fields.last_mut().unwrap();
    last.text.push_str(text);
    last.pattern.push_str(&if glob {
        text.into()
    } else {
        glob::Pattern::escape(text)
    });
    last.split.extend(std::iter::repeat_n(split, text.len()));
    last.glob.extend(std::iter::repeat_n(glob, text.len()));
    last.keep_empty |= keep_empty;
}
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}
fn language_builtin(name: &str) -> bool {
    matches!(
        name,
        ":" | "true"
            | "false"
            | "export"
            | "unset"
            | "set"
            | "shift"
            | "break"
            | "continue"
            | "sh"
            | "/bin/sh"
            | "absd-sh"
            | "/bin/absd-sh"
            | "."
    )
}

fn unsupported_builtin(name: &str) -> bool {
    matches!(
        name,
        "return"
            | "read"
            | "trap"
            | "exec"
            | "eval"
            | "wait"
            | "local"
            | "getopts"
            | "ulimit"
            | "umask"
            | "jobs"
            | "fg"
            | "bg"
    )
}
fn static_word(word: &Word) -> Option<String> {
    fn simple(part: &a::DefaultSimpleWord) -> Option<String> {
        match part {
            a::SimpleWord::Literal(v) | a::SimpleWord::Escaped(v) => Some(v.clone()),
            _ => None,
        }
    }
    fn part(part: &a::DefaultWord) -> Option<String> {
        match part {
            a::Word::SingleQuoted(v) => Some(v.clone()),
            a::Word::Simple(v) => simple(v),
            a::Word::DoubleQuoted(parts) => parts
                .iter()
                .map(simple)
                .collect::<Option<Vec<_>>>()
                .map(|s| s.concat()),
        }
    }
    match &word.0 {
        a::ComplexWord::Single(v) => part(v),
        a::ComplexWord::Concat(parts) => parts
            .iter()
            .map(part)
            .collect::<Option<Vec<_>>>()
            .map(|s| s.concat()),
    }
}
/// Validate structural support before evaluation: unsupported forms in a later
/// statement, dead branch or nested substitution must not leave earlier effects.
fn validate_program(
    program: &[a::TopLevelCommand<String>],
    inherited_functions: &BTreeSet<String>,
    depth: usize,
) -> Result<(), String> {
    if depth > 64 {
        return Err("shell nesting exceeds 64 levels".into());
    }
    let mut functions = inherited_functions.clone();
    for command in program {
        if let a::Command::List(list) = &command.0 {
            for item in
                std::iter::once(&list.first).chain(list.rest.iter().map(|item| match item {
                    a::AndOr::And(v) | a::AndOr::Or(v) => v,
                }))
            {
                let parts = match item {
                    a::ListableCommand::Single(v) => std::slice::from_ref(v),
                    a::ListableCommand::Pipe(_, v) => v.as_slice(),
                };
                for part in parts {
                    if let a::PipeableCommand::FunctionDef(name, _) = part {
                        functions.insert(name.clone());
                    }
                }
            }
        }
    }
    for command in program {
        let a::Command::List(list) = &command.0 else {
            return Err("background jobs are not supported".into());
        };
        for item in std::iter::once(&list.first).chain(list.rest.iter().map(|item| match item {
            a::AndOr::And(v) | a::AndOr::Or(v) => v,
        })) {
            let parts = match item {
                a::ListableCommand::Single(v) => std::slice::from_ref(v),
                a::ListableCommand::Pipe(_, v) => v.as_slice(),
            };
            for (index, part) in parts.iter().enumerate() {
                match part {
                    a::PipeableCommand::Simple(simple) => {
                        let words: Vec<_> = simple
                            .redirects_or_cmd_words
                            .iter()
                            .filter_map(|item| match item {
                                a::RedirectOrCmdWord::CmdWord(w) => Some(w),
                                _ => None,
                            })
                            .collect();
                        let name = words.first().and_then(|w| static_word(w));
                        let heredoc = simple.redirects_or_env_vars.iter().any(|item| matches!(item,
                            a::RedirectOrEnvVar::Redirect(a::Redirect::Heredoc(..))))
                            || simple.redirects_or_cmd_words.iter().any(|item| matches!(item,
                            a::RedirectOrCmdWord::Redirect(a::Redirect::Heredoc(..))));
                        if heredoc && (words.is_empty() || name.as_ref().is_some_and(|name|
                            language_builtin(name) || functions.contains(name)
                            || (is_builtin(name) && !(name == "ps" && words.len() > 1))))
                        {
                            return Err("heredocs require a native consuming command".into());
                        }
                        if let Some(name) = &name {
                            if unsupported_builtin(name) {
                                return Err(format!("unsupported builtin `{name}`"));
                            }
                            if parts.len() > 1
                                && (language_builtin(name) || functions.contains(name))
                            {
                                return Err(
                                    "script builtins and functions in pipelines are not supported"
                                        .into(),
                                );
                            }
                            if parts.len() > 1 && is_control_builtin(name) {
                                return Err(format!("{name}: cannot run in a pipeline"));
                            }
                            if index > 0
                                && is_output_builtin(name)
                                && !(name == "ps" && words.len() > 1)
                            {
                                return Err(format!("{name}: a builtin can only start a pipeline"));
                            }
                        }
                        let mut streams = BTreeSet::new();
                        for item in &simple.redirects_or_env_vars {
                            match item {
                                a::RedirectOrEnvVar::EnvVar(_, value) => {
                                    if parts.len() > 1 {
                                        return Err("command-local assignments in pipelines are not supported; export first".into());
                                    }
                                    if let Some(w) = value {
                                        validate_word(w, &functions, depth + 1)?;
                                    }
                                }
                                a::RedirectOrEnvVar::Redirect(r) => {
                                    let fd = validate_redirect(r, &functions, depth + 1)?;
                                    if !streams.insert(fd) && fd == 0 {
                                        return Err("duplicate input redirection".into());
                                    }
                                }
                            }
                        }
                        for item in &simple.redirects_or_cmd_words {
                            match item {
                                a::RedirectOrCmdWord::CmdWord(w) => {
                                    validate_word(w, &functions, depth + 1)?
                                }
                                a::RedirectOrCmdWord::Redirect(r) => {
                                    let fd = validate_redirect(r, &functions, depth + 1)?;
                                    if !streams.insert(fd) && fd == 0 {
                                        return Err("duplicate input redirection".into());
                                    }
                                }
                            }
                        }
                        if index > 0 && streams.contains(&0) {
                            return Err("input cannot come from both a file and a pipe".into());
                        }
                        if let Some(name) = &name {
                            if is_control_builtin(name) && !streams.is_empty() {
                                return Err(format!("{name}: takes no redirection"));
                            }
                            if (language_builtin(name) || functions.contains(name))
                                && streams.contains(&0)
                            {
                                return Err("input redirection on interpreted scripts/compounds is unsupported; redirect the consuming command".into());
                            }
                        }
                    }
                    a::PipeableCommand::Compound(compound) => {
                        if parts.len() > 1 {
                            return Err("compound commands in pipelines are not supported".into());
                        }
                        validate_compound(compound, &functions, depth + 1)?;
                    }
                    a::PipeableCommand::FunctionDef(name, body) => {
                        if unsupported_builtin(name) {
                            return Err(format!("unsupported builtin `{name}`"));
                        }
                        if parts.len() > 1 {
                            return Err(
                                "function definitions in pipelines are not supported".into()
                            );
                        }
                        validate_compound(body, &functions, depth + 1)?;
                    }
                }
            }
        }
    }
    Ok(())
}
fn validate_compound(
    command: &a::DefaultCompoundCommand,
    functions: &BTreeSet<String>,
    depth: usize,
) -> Result<(), String> {
    let mut streams = BTreeSet::new();
    for redirect in &command.io {
        let fd = validate_redirect(redirect, functions, depth + 1)?;
        if fd == 0 {
            return Err("input redirection on interpreted scripts/compounds is unsupported; redirect the consuming command".into());
        }
        streams.insert(fd);
    }
    use a::CompoundCommandKind::*;
    match &command.kind {
        Brace(body) | Subshell(body) => validate_program(body, functions, depth + 1)?,
        While(pair) | Until(pair) => {
            validate_program(&pair.guard, functions, depth + 1)?;
            validate_program(&pair.body, functions, depth + 1)?;
        }
        If {
            conditionals,
            else_branch,
        } => {
            for pair in conditionals {
                validate_program(&pair.guard, functions, depth + 1)?;
                validate_program(&pair.body, functions, depth + 1)?;
            }
            if let Some(body) = else_branch {
                validate_program(body, functions, depth + 1)?;
            }
        }
        For { words, body, .. } => {
            if let Some(words) = words {
                for word in words {
                    validate_word(word, functions, depth + 1)?;
                }
            }
            validate_program(body, functions, depth + 1)?;
        }
        Case { word, arms } => {
            validate_word(word, functions, depth + 1)?;
            for arm in arms {
                for word in &arm.patterns {
                    validate_word(word, functions, depth + 1)?;
                }
                validate_program(&arm.body, functions, depth + 1)?;
            }
        }
    }
    Ok(())
}
fn validate_redirect(
    redirect: &a::DefaultRedirect,
    functions: &BTreeSet<String>,
    depth: usize,
) -> Result<u16, String> {
    let (fd, word) = match redirect {
        a::Redirect::Read(fd, word) | a::Redirect::Heredoc(fd, word)
            if fd.unwrap_or(0) == 0 => (0, word),
        a::Redirect::Write(fd, word)
        | a::Redirect::Clobber(fd, word)
        | a::Redirect::Append(fd, word)
            if matches!(fd.unwrap_or(1), 1 | 2) =>
        {
            (fd.unwrap_or(1), word)
        }
        a::Redirect::DupWrite(fd, word) if matches!(fd.unwrap_or(1), 1 | 2) => {
            if !matches!(static_word(word).as_deref(), Some("1" | "2")) {
                return Err("output duplication requires literal descriptor 1 or 2".into());
            }
            (fd.unwrap_or(1), word)
        }
        _ => return Err("unsupported redirection: only standard file streams and output duplication of 1 or 2 are supported".into()),
    };
    validate_word(word, functions, depth + 1)?;
    Ok(fd)
}
fn validate_word(word: &Word, functions: &BTreeSet<String>, depth: usize) -> Result<(), String> {
    if depth > 64 {
        return Err("shell nesting exceeds 64 levels".into());
    }
    let parts = match &word.0 {
        a::ComplexWord::Single(v) => std::slice::from_ref(v),
        a::ComplexWord::Concat(v) => v.as_slice(),
    };
    for part in parts {
        let simple = match part {
            a::Word::SingleQuoted(_) => continue,
            a::Word::Simple(v) => std::slice::from_ref(v),
            a::Word::DoubleQuoted(v) => v.as_slice(),
        };
        for word in simple {
            if let a::SimpleWord::Subst(sub) = word {
                use a::ParameterSubstitution::*;
                match &**sub {
                    Command(program) => validate_program(program, functions, depth + 1)?,
                    Len(_) | Arith(None) => {}
                    Arith(Some(expr)) => validate_arithmetic(expr, depth + 1)?,
                    Default(_, _, word)
                    | Assign(_, _, word)
                    | Error(_, _, word)
                    | Alternative(_, _, word) => {
                        if let Some(word) = word {
                            validate_word(word, functions, depth + 1)?;
                        }
                    }
                    _ => {
                        return Err(
                            "parameter prefix/suffix pattern removal is not supported".into()
                        );
                    }
                }
            }
        }
    }
    Ok(())
}
fn validate_arithmetic(expr: &a::DefaultArithmetic, depth: usize) -> Result<(), String> {
    if depth > 64 {
        return Err("arithmetic nesting exceeds 64 levels".into());
    }
    use a::Arithmetic::*;
    match expr {
        Literal(_) | Var(_) => {}
        Add(l, r) | Sub(l, r) | Mult(l, r) | Div(l, r) | Modulo(l, r) => {
            validate_arithmetic(l, depth + 1)?;
            validate_arithmetic(r, depth + 1)?;
        }
        UnaryPlus(v) | UnaryMinus(v) | LogicalNot(v) => validate_arithmetic(v, depth + 1)?,
        _ => {
            return Err(
                "unsupported arithmetic operator (supported: + - * / % and unary + - !)".into(),
            );
        }
    }
    Ok(())
}
