//! One SSH connection: sunset's sans-IO `Runner` plus at most one session
//! channel bridged to one child process. Platform-independent; the caller
//! moves bytes between the network and `push_input`/`output`, and calls
//! `pump` whenever anything may have changed.
//!
//! Session policy: one authenticated operator identity, one session channel
//! per connection, `shell` or `exec`, optionally after `pty-req` (no
//! environment, no subsystem, no forwarding). A PTY session's bytes pass
//! through the line discipline in `tty`. When the child's stdout and stderr have ended and it has
//! exited, the server sends channel EOF, `exit-status`, and close, in that
//! order. Client EOF closes the child's stdin once everything received
//! before it has been delivered.
//!
//! Machine requests: an `exec` of exactly `shutdown` (or `shutdown now`,
//! `shutdown -h now`, `shutdown -p now`) or `reboot` (or `shutdown -r
//! now`) from the authenticated operator starts no program; it is handed
//! to the backend (`Spawner::machine_request`), which decides. Other
//! arguments to those words are refused with status 2.
//!
//! Session control: a backend may give a session's shell a control
//! channel (`control.rs`). Then ^C on the terminal is told to the shell,
//! which ends its own running command, and the shell's `shutdown`,
//! `reboot`, and `ps` come to sshd there: a machine request is decided as
//! the `exec` above, a listing covers the asking session only. Ending a
//! session (`SessionChild::terminate`) goes through the same channel: the
//! backend tells the shell first and kills it only if it has not ended its
//! commands and exited within a bound.

use std::io;
use std::time::{Duration, Instant};

use crate::tty::{self, LineDiscipline};
use sunset::{ChanData, ChanFail, ChanHandle, Event, PubKey, Runner, ServEvent, SignKey};

pub type ServerRunner = Runner<'static, sunset::Server>;

/// What a session asks to run.
#[derive(Clone, Debug)]
pub enum Command {
    Shell,
    Exec(String),
}

/// How a session's child ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// Exited with a status (reported as `exit-status`).
    Code(u32),
    /// Ended without a status (a fault, or a reclaimed child): no
    /// `exit-status` is sent, so the client reports a lost status.
    Abnormal,
}

/// A running session child. Reads and writes never block: `Ok(None)` means
/// "not now". `Ok(Some(0))` from a read is end of stream.
pub trait SessionChild {
    fn read_stdout(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>>;
    fn read_stderr(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>>;
    fn write_stdin(&mut self, buf: &[u8]) -> io::Result<Option<usize>>;
    fn close_stdin(&mut self);
    fn try_wait(&mut self) -> io::Result<Option<Exit>>;
    /// Ends the child and reclaims it (client gone mid-command, idle
    /// timeout, shutdown grace over). A child holding a session control
    /// channel is told `END` and given a bounded time to end its own
    /// commands and exit before it is killed (the backend finishes that
    /// after the call returns); any other child is killed now.
    fn terminate(&mut self);
    /// ^C on this session's terminal, for a child that ends its own
    /// commands (a shell holding a session control channel, `control.rs`).
    /// `false`: it has no such channel.
    fn interrupt(&mut self) -> bool {
        false
    }
    /// Moves what waits on the control channel; whether anything moved.
    fn pump_control(&mut self) -> bool {
        false
    }
    /// A request the child made on its control channel, if one is whole.
    /// `Err` when the channel just ended (closed or malformed).
    fn control_request(&mut self, _now: Instant) -> Result<Option<ControlRequest>, String> {
        Ok(None)
    }
    /// Answers the child's request on its control channel.
    fn control_reply(&mut self, _status: u8, _text: &str) {}
    /// The processes of this session the backend can name, and what it can
    /// only count, for the session's own listing.
    fn describe(&mut self) -> String {
        String::new()
    }
}

/// What a session's shell may ask sshd on its control channel (only the
/// ABSD backend gives one).
#[cfg_attr(not(target_os = "absd"), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlRequest {
    /// The words of a `shutdown` or `reboot` command.
    Machine(String),
    /// This session's processes.
    List,
}

/// What an operator asks of the machine from a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineRequest {
    Halt,
    Restart,
}

impl MachineRequest {
    pub fn word(self) -> &'static str {
        match self {
            MachineRequest::Halt => "halt",
            MachineRequest::Restart => "restart",
        }
    }
}

/// `Some(Ok(request))` for a machine request, `Some(Err(usage))` for one
/// of its words with other arguments, `None` for any other command.
pub fn machine_request(command: &str) -> Option<Result<MachineRequest, String>> {
    let words: Vec<&str> = command.split_ascii_whitespace().collect();
    match words.as_slice() {
        ["shutdown"] | ["shutdown", "now"] | ["shutdown", "-h" | "-p", "now"] => {
            Some(Ok(MachineRequest::Halt))
        }
        ["reboot"] | ["shutdown", "-r", "now"] => Some(Ok(MachineRequest::Restart)),
        ["shutdown" | "reboot", ..] => Some(Err(
            "usage: shutdown [-h|-p|-r now] | reboot (this sshd takes no other form)\n".into(),
        )),
        _ => None,
    }
}

pub trait Spawner {
    type Child: SessionChild;
    /// An authenticated operator's machine request. `Ok` carries the text
    /// the requesting session prints before it ends with status 0; `Err`
    /// the refusal it prints before status 1.
    fn machine_request(&mut self, request: MachineRequest) -> Result<String, String>;
    /// Starts `command`. On a `terminal` (PTY) session the child's stdout
    /// and stderr are one pipe, as they are one screen: `read_stderr` then
    /// only ever reports end of stream.
    fn spawn(&mut self, command: &Command, terminal: bool) -> io::Result<Self::Child>;
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// From connection start until authentication succeeds.
    pub auth_timeout: Duration,
    /// Without any traffic in either direction or child output.
    pub idle_timeout: Duration,
    /// Rejected authentication requests before the connection is dropped.
    pub max_auth_failures: u32,
}

pub struct Identity<'k> {
    pub host_key: &'k SignKey,
    pub authorized: &'k [[u8; 32]],
}

struct Session<C> {
    chan: Option<ChanHandle>,
    child: Option<C>,
    /// Client data read from the channel, not yet taken by the child.
    stdin: Vec<u8>,
    stdin_closed: bool,
    out_eof: bool,
    err_eof: bool,
    exit: Option<Exit>,
    sent_eof: bool,
    sent_status: bool,
    sent_close: bool,
    /// An `exec` whose program could not be started, reported as a shell
    /// would: this message on stderr, then exit status 127 (not found) or
    /// 126 (not started).
    refusal: Option<Vec<u8>>,
    /// The terminal, once `pty-req` was accepted.
    tty: Option<LineDiscipline>,
    /// Echo of the client's keystrokes, not yet sent.
    echo: Vec<u8>,
    /// The child is an `exec` command (sshd's own child doing the work),
    /// not the shell.
    exec: bool,
    /// A reply sshd itself gives on stdout (a machine request's answer),
    /// sent like `refusal`.
    reply: Option<Vec<u8>>,
    /// The system-shutdown notice, not yet sent.
    notice: Vec<u8>,
    /// The system is going down: the child's stdin closes once what the
    /// client sent before is delivered.
    shutting_down: bool,
}

pub struct Connection<C: SessionChild> {
    runner: ServerRunner,
    started: Instant,
    last_activity: Instant,
    authenticated: bool,
    auth_failures: u32,
    session: Session<C>,
    netin: Vec<u8>,
    net_eof: bool,
    end: Option<String>,
    log_prefix: String,
    id: u64,
}

const CHUNK: usize = 4096;

impl<C: SessionChild> Connection<C> {
    pub fn new(id: u64, now: Instant) -> Self {
        Connection {
            runner: Runner::new_server_owned(),
            started: now,
            last_activity: now,
            authenticated: false,
            auth_failures: 0,
            session: Session {
                chan: None,
                child: None,
                stdin: Vec::new(),
                stdin_closed: false,
                out_eof: false,
                err_eof: false,
                exit: None,
                sent_eof: false,
                sent_status: false,
                sent_close: false,
                refusal: None,
                tty: None,
                echo: Vec::new(),
                exec: false,
                reply: None,
                notice: Vec::new(),
                shutting_down: false,
            },
            netin: Vec::new(),
            net_eof: false,
            end: None,
            log_prefix: format!("sshd: conn {id}:"),
            id,
        }
    }

    /// Whether network input should be read now (the previous is consumed).
    pub fn wants_input(&self) -> bool {
        self.end.is_none() && !self.net_eof && self.netin.is_empty()
    }

    pub fn push_input(&mut self, data: &[u8], now: Instant) {
        self.netin.extend_from_slice(data);
        self.last_activity = now;
    }

    /// The peer closed its sending direction (or the connection broke).
    pub fn input_closed(&mut self) {
        if !self.net_eof {
            self.net_eof = true;
            self.runner.close_input();
        }
    }

    pub fn output(&mut self) -> &[u8] {
        self.runner.output_buf()
    }

    pub fn consume_output(&mut self, n: usize, now: Instant) {
        if n > 0 {
            self.runner.consume_output(n);
            self.last_activity = now;
        }
    }

    pub fn output_pending(&self) -> bool {
        self.runner.is_output_pending()
    }

    /// Why the connection ended, once it has. The caller then flushes
    /// output it can, closes the transport, and drops the connection
    /// (which reclaims any child).
    pub fn ended(&self) -> Option<&str> {
        self.end.as_deref()
    }

    /// Authentication releases this connection's per-source pre-auth slot;
    /// the global connection limit still applies.
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn child_mut(&mut self) -> Option<&mut C> {
        self.session.child.as_mut()
    }

    /// Whether the child's output is wanted now (the channel has room).
    pub fn wants_child_output(&self) -> bool {
        self.session.child.is_some()
            && self.session.chan.is_some()
            && !(self.session.out_eof && self.session.err_eof)
    }

    /// The earliest instant at which `pump` has timer work to do.
    pub fn deadline(&self, limits: &Limits) -> Instant {
        let idle = self.last_activity + limits.idle_timeout;
        if self.authenticated {
            idle
        } else {
            idle.min(self.started + limits.auth_timeout)
        }
    }

    /// The system is going down. A session whose child runs is told so, and
    /// its child's stdin closes once what the client sent before has been
    /// delivered: a shell or a command reading its input sees end of file,
    /// finishes, and the session ends as it always does (EOF,
    /// `exit-status`, close). A connection with no session running ends
    /// now.
    pub fn begin_shutdown(&mut self, notice: &str) {
        if self.end.is_some() {
            return;
        }
        let s = &mut self.session;
        let pending = s.refusal.is_some() || s.reply.is_some() || s.exit.is_some();
        if s.chan.is_none() || (s.child.is_none() && !pending) {
            self.finish("system shutdown");
            return;
        }
        if s.child.is_some() && s.exit.is_none() {
            let text = format!("\nsshd: {notice}\n");
            if s.tty.is_some() {
                tty::output(text.as_bytes(), &mut s.notice);
            } else {
                s.notice.extend_from_slice(text.as_bytes());
            }
            s.shutting_down = true;
        }
    }

    /// The shutdown grace is over: a child still running is ended now (no
    /// `exit-status`) and the channel closes without waiting for its
    /// streams, which a descendant it left may still hold open.
    pub fn force_end(&mut self) {
        if self.end.is_some() {
            return;
        }
        let s = &mut self.session;
        if let Some(child) = s.child.as_mut() {
            if s.exit.is_none() {
                child.terminate();
                say!(
                    "{} shutdown grace over: session child ended",
                    self.log_prefix
                );
                s.exit = Some(Exit::Abnormal);
            }
        }
        s.out_eof = true;
        s.err_eof = true;
        s.refusal = None;
        s.reply = None;
        s.notice.clear();
    }

    /// Ends the connection now (the transport closes after what is queued).
    pub fn end_now(&mut self, reason: &str) {
        self.finish(reason.to_owned());
    }

    fn finish(&mut self, reason: impl Into<String>) {
        if self.end.is_none() {
            let reason = reason.into();
            say!("{} end: {reason}", self.log_prefix);
            self.end = Some(reason);
            if let Some(child) = self.session.child.as_mut() {
                if self.session.exit.is_none() {
                    child.terminate();
                    say!("{} session child reclaimed", self.log_prefix);
                }
            }
            self.session.child = None;
        }
    }

    /// Drives everything that can progress without blocking. Returns
    /// whether anything happened.
    pub fn pump<S: Spawner<Child = C>>(
        &mut self,
        spawner: &mut S,
        identity: &Identity,
        limits: &Limits,
        now: Instant,
    ) -> bool {
        let mut any = false;
        loop {
            if self.end.is_some() {
                return any;
            }
            let mut progressed = false;
            if !self.netin.is_empty() && self.runner.is_input_ready() {
                match self.runner.input(&self.netin) {
                    Ok(n) => {
                        self.netin.drain(..n);
                        progressed |= n > 0;
                    }
                    Err(error) => {
                        self.finish(format!("input refused: {error:?}"));
                        return true;
                    }
                }
            }
            match self.drive_protocol(spawner, identity, limits) {
                Ok(p) => progressed |= p,
                Err(reason) => {
                    self.finish(reason);
                    return true;
                }
            }
            match self.bridge(now) {
                Ok(p) => progressed |= p,
                Err(reason) => {
                    self.finish(reason);
                    return true;
                }
            }
            progressed |= self.control(spawner, now);
            if !progressed {
                break;
            }
            any = true;
        }
        if self.net_eof && !self.runner.is_output_pending() {
            self.finish("client closed the connection");
            return true;
        }
        if !self.authenticated && now >= self.started + limits.auth_timeout {
            self.finish("authentication timeout");
            return true;
        }
        if now >= self.last_activity + limits.idle_timeout {
            self.finish("idle timeout");
            return true;
        }
        any
    }

    fn drive_protocol<S: Spawner<Child = C>>(
        &mut self,
        spawner: &mut S,
        identity: &Identity,
        limits: &Limits,
    ) -> Result<bool, String> {
        let mut progressed = false;
        loop {
            let event = self
                .runner
                .progress()
                .map_err(|e| format!("protocol: {e:?}"))?;
            match event {
                Event::None => return Ok(progressed),
                Event::Progressed => progressed = true,
                Event::Cli(_) => return Err("client event on a server".into()),
                Event::Serv(event) => {
                    progressed = true;
                    let s = &mut self.session;
                    let prefix = &self.log_prefix;
                    let r = match event {
                        ServEvent::Hostkeys(h) => h.hostkeys(&[identity.host_key]),
                        ServEvent::FirstAuth(mut a) => {
                            say!("{prefix} user {:?}", a.username().unwrap_or("?"));
                            a.enable_password_auth(false)
                                .and_then(|()| a.enable_pubkey_auth(true))
                                .and_then(|()| a.reject())
                        }
                        ServEvent::PasswordAuth(a) => {
                            self.auth_failures += 1;
                            a.reject()
                        }
                        ServEvent::PubkeyAuth(a) => {
                            let known = matches!(
                                a.pubkey(),
                                Ok(PubKey::Ed25519(k)) if identity.authorized.contains(&k.key.0)
                            );
                            if known {
                                a.allow()
                            } else {
                                self.auth_failures += 1;
                                say!("{prefix} public key refused");
                                a.reject()
                            }
                        }
                        ServEvent::Authenticated => {
                            self.authenticated = true;
                            say!("{prefix} authenticated");
                            Ok(())
                        }
                        ServEvent::OpenSession(o) => {
                            if s.chan.is_none() {
                                o.accept().map(|chan| s.chan = Some(chan))
                            } else {
                                o.reject(ChanFail::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)
                            }
                        }
                        ServEvent::SessionPty(p) => {
                            if s.chan.is_some()
                                && s.tty.is_none()
                                && s.child.is_none()
                                && s.exit.is_none()
                            {
                                say!("{prefix} pty accepted");
                                s.tty = Some(LineDiscipline::new());
                                p.succeed()
                            } else {
                                say!("{prefix} pty refused");
                                p.fail()
                            }
                        }
                        ServEvent::SessionEnv(e) => e.fail(),
                        ServEvent::SessionSubsystem(r) => r.fail(),
                        ServEvent::SessionShell(r) => {
                            if s.child.is_some() || s.exit.is_some() {
                                r.fail()
                            } else {
                                match spawner.spawn(&Command::Shell, s.tty.is_some()) {
                                    Ok(child) => {
                                        say!("{prefix} shell started");
                                        s.child = Some(child);
                                        r.succeed()
                                    }
                                    Err(error) => {
                                        say!("{prefix} shell refused: {error}");
                                        r.fail()
                                    }
                                }
                            }
                        }
                        ServEvent::SessionExec(r) => {
                            if s.child.is_some() || s.exit.is_some() {
                                r.fail()
                            } else {
                                let command = r.command().map(str::to_owned);
                                match command {
                                    Err(e) => {
                                        say!("{prefix} exec command unreadable: {e:?}");
                                        r.fail()
                                    }
                                    Ok(command) if machine_request(&command).is_some() => {
                                        let answer = match machine_request(&command) {
                                            Some(Ok(request)) => {
                                                say!(
                                                    "{prefix} machine request {:?}",
                                                    request.word()
                                                );
                                                spawner.machine_request(request).map_err(|m| (m, 1))
                                            }
                                            Some(Err(usage)) => Err((usage, 2)),
                                            None => unreachable!("matched as a machine request"),
                                        };
                                        let tty_out = |text: &str| {
                                            let mut out = Vec::new();
                                            tty::output(text.as_bytes(), &mut out);
                                            out
                                        };
                                        match answer {
                                            Ok(text) => {
                                                s.reply = Some(if s.tty.is_some() {
                                                    tty_out(&text)
                                                } else {
                                                    text.into_bytes()
                                                });
                                                s.exit = Some(Exit::Code(0));
                                                s.err_eof = true;
                                            }
                                            Err((text, code)) => {
                                                s.refusal = Some(if s.tty.is_some() {
                                                    tty_out(&text)
                                                } else {
                                                    text.into_bytes()
                                                });
                                                s.exit = Some(Exit::Code(code));
                                                s.out_eof = true;
                                            }
                                        }
                                        r.succeed()
                                    }
                                    Ok(command) => {
                                        match spawner
                                            .spawn(&Command::Exec(command.clone()), s.tty.is_some())
                                        {
                                            Ok(child) => {
                                                say!("{prefix} exec {command:?}");
                                                s.child = Some(child);
                                                s.exec = true;
                                                r.succeed()
                                            }
                                            Err(error) => {
                                                say!("{prefix} exec {command:?} refused: {error}");
                                                let code = if error.kind()
                                                    == std::io::ErrorKind::NotFound
                                                {
                                                    127
                                                } else {
                                                    126
                                                };
                                                let word = command
                                                    .split_ascii_whitespace()
                                                    .next()
                                                    .unwrap_or("");
                                                let message =
                                                    format!("sshd: {word}: {error}\n").into_bytes();
                                                s.refusal = Some(if s.tty.is_some() {
                                                    let mut out = Vec::new();
                                                    tty::output(&message, &mut out);
                                                    out
                                                } else {
                                                    message
                                                });
                                                s.exit = Some(Exit::Code(code));
                                                s.out_eof = true;
                                                r.succeed()
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        ServEvent::Defunct => return Err("connection closed (defunct)".into()),
                        ServEvent::PollAgain => Ok(()),
                    };
                    r.map_err(|e| format!("event response: {e:?}"))?;
                    if self.auth_failures >= limits.max_auth_failures {
                        return Err(format!("{} authentication failures", self.auth_failures));
                    }
                }
            }
        }
    }

    /// The session's control channel: ^C still on its way to the shell,
    /// and the shell's requests. A machine request is decided exactly as
    /// the same `exec` would be; a listing covers this session only, since
    /// the channel it arrives on is the session.
    fn control<S: Spawner<Child = C>>(&mut self, spawner: &mut S, now: Instant) -> bool {
        let s = &mut self.session;
        let Some(child) = s.child.as_mut().filter(|_| s.exit.is_none()) else {
            return false;
        };
        let mut progressed = child.pump_control();
        let request = match child.control_request(now) {
            Ok(Some(request)) => request,
            Ok(None) => return progressed,
            Err(reason) => {
                say!(
                    "{} session control channel ended: {reason}",
                    self.log_prefix
                );
                return true;
            }
        };
        progressed = true;
        let (status, text) = match request {
            ControlRequest::Machine(words) => match machine_request(&words) {
                Some(Ok(request)) => {
                    say!(
                        "{} machine request {:?} from the session's shell",
                        self.log_prefix,
                        request.word()
                    );
                    match spawner.machine_request(request) {
                        Ok(text) => (0, text),
                        Err(text) => (1, text),
                    }
                }
                Some(Err(usage)) => (2, usage),
                None => (2, "sshd: not a machine request\n".to_string()),
            },
            ControlRequest::List => {
                let age = now.saturating_duration_since(self.started).as_secs();
                let mut text = format!(
                    "session {} (this session), {}, connected {age} s\n",
                    self.id,
                    if s.tty.is_some() {
                        "terminal"
                    } else {
                        "no terminal"
                    }
                );
                text.push_str(&child.describe());
                say!("{} session listing", self.log_prefix);
                (0, text)
            }
        };
        child.control_reply(status, &text);
        progressed
    }

    /// Moves data between the channel and the child and ends the channel.
    fn bridge(&mut self, now: Instant) -> Result<bool, String> {
        let mut progressed = false;
        let s = &mut self.session;
        let Some(chan) = s.chan.as_ref() else {
            return Ok(false);
        };
        let runner = &mut self.runner;

        // The client closed the channel: reclaim a running child.
        if runner.is_channel_closed(chan) && !s.sent_close {
            if let Some(child) = s.child.as_mut() {
                if s.exit.is_none() {
                    child.terminate();
                    say!(
                        "{} channel closed by client; session child reclaimed",
                        self.log_prefix
                    );
                    s.exit = Some(Exit::Abnormal);
                }
            }
            s.child = None;
            runner
                .close_channel(chan)
                .map_err(|e| format!("close: {e:?}"))?;
            s.sent_close = true;
            return Ok(true);
        }

        // PTY session: keystrokes -> the line discipline -> `stdin` and
        // `echo`. They are read while the child runs even if it does not
        // take them, so that ^C is seen; completed input waits in `stdin`,
        // bounded (beyond it the channel's window holds the client back).
        if let Some(ld) = s.tty.as_mut() {
            if let Some(child) = s.child.as_mut() {
                if s.stdin.len() < CHUNK && s.echo.len() < CHUNK {
                    let mut buf = [0u8; CHUNK];
                    match runner.read_channel(chan, ChanData::Normal, &mut buf) {
                        Ok(0) | Err(sunset::Error::ChannelEOF) => {}
                        Ok(n) => {
                            let events = ld.input(&buf[..n], &mut s.stdin, &mut s.echo);
                            // A shell's commands are the shell's children,
                            // which sshd cannot end (and ending the shell
                            // would end the session): sshd tells the shell
                            // on its control channel, and the shell ends its
                            // own command with the process handle it holds.
                            // That includes an `exec` the shell runs (its
                            // text has shell syntax). ^C ends any other
                            // `exec` command: it is sshd's own child. Either
                            // way the line being typed is discarded.
                            if events.interrupt && s.exit.is_none() {
                                if child.interrupt() {
                                    say!("{} interrupt: told the shell", self.log_prefix);
                                } else if s.exec {
                                    child.terminate();
                                    say!("{} interrupt: exec child ended", self.log_prefix);
                                    s.exit = Some(Exit::Abnormal);
                                }
                            }
                            progressed = true;
                        }
                        Err(e) => return Err(format!("channel read: {e:?}")),
                    }
                }
            } else if runner.read_channel_ready().is_some() {
                runner
                    .discard_read_channel(chan)
                    .map_err(|e| format!("discard: {e:?}"))?;
                progressed = true;
            }
            if s.stdin_closed {
                s.stdin.clear();
            }
        }

        // Client -> child stdin.
        let typed_eof = s.tty.as_ref().is_some_and(LineDiscipline::at_eof);
        if let Some(child) = s.child.as_mut().filter(|_| !s.stdin_closed) {
            if s.tty.is_none() && s.stdin.is_empty() {
                let mut buf = [0u8; CHUNK];
                match runner.read_channel(chan, ChanData::Normal, &mut buf) {
                    Ok(0) => {}
                    Ok(n) => {
                        s.stdin.extend_from_slice(&buf[..n]);
                        progressed = true;
                    }
                    Err(sunset::Error::ChannelEOF) => {}
                    Err(e) => return Err(format!("channel read: {e:?}")),
                }
            }
            if !s.stdin.is_empty() {
                match child.write_stdin(&s.stdin) {
                    Ok(Some(n)) if n > 0 => {
                        s.stdin.drain(..n);
                        progressed = true;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        // The child stopped reading; drop what it will not take.
                        s.stdin.clear();
                        child.close_stdin();
                        s.stdin_closed = true;
                        progressed = true;
                    }
                }
            }
            if s.stdin.is_empty()
                && (runner.is_channel_eof(chan) || typed_eof || s.shutting_down)
                && !s.stdin_closed
            {
                child.close_stdin();
                s.stdin_closed = true;
                progressed = true;
            }
        } else if s.tty.is_none() && runner.read_channel_ready().is_some() {
            // No consumer: discard, so the connection keeps moving.
            runner
                .discard_read_channel(chan)
                .map_err(|e| format!("discard: {e:?}"))?;
            progressed = true;
        }

        // A refused exec's message -> client stderr.
        if let Some(message) = s.refusal.as_mut() {
            match runner.write_channel_ready(chan, ChanData::Stderr) {
                Ok(Some(room)) if room > 0 => {
                    let n = runner
                        .write_channel(chan, ChanData::Stderr, &message[..room.min(message.len())])
                        .map_err(|e| format!("channel write: {e:?}"))?;
                    message.drain(..n);
                    progressed = true;
                }
                Ok(Some(_)) => {}
                Ok(None) => message.clear(),
                Err(e) => return Err(format!("channel ready: {e:?}")),
            }
            if message.is_empty() {
                s.refusal = None;
                s.err_eof = true;
                progressed = true;
            }
        }

        // sshd's own reply -> client stdout (on a PTY, the one screen).
        if let Some(message) = s.reply.as_mut() {
            match runner.write_channel_ready(chan, ChanData::Normal) {
                Ok(Some(room)) if room > 0 => {
                    let n = runner
                        .write_channel(chan, ChanData::Normal, &message[..room.min(message.len())])
                        .map_err(|e| format!("channel write: {e:?}"))?;
                    message.drain(..n);
                    progressed = true;
                }
                Ok(Some(_)) => {}
                Ok(None) => message.clear(),
                Err(e) => return Err(format!("channel ready: {e:?}")),
            }
            if message.is_empty() {
                s.reply = None;
                s.out_eof = true;
                progressed = true;
            }
        }

        // The shutdown notice -> client (stderr, or the screen on a PTY).
        if !s.notice.is_empty() {
            let dt = if s.tty.is_some() {
                ChanData::Normal
            } else {
                ChanData::Stderr
            };
            match runner.write_channel_ready(chan, dt) {
                Ok(Some(room)) if room > 0 => {
                    let n = runner
                        .write_channel(chan, dt, &s.notice[..room.min(s.notice.len())])
                        .map_err(|e| format!("channel write: {e:?}"))?;
                    s.notice.drain(..n);
                    progressed = true;
                }
                Ok(Some(_)) => {}
                Ok(None) => s.notice.clear(),
                Err(e) => return Err(format!("channel ready: {e:?}")),
            }
        }

        // Echo of keystrokes -> client.
        if !s.echo.is_empty() {
            match runner.write_channel_ready(chan, ChanData::Normal) {
                Ok(Some(room)) if room > 0 => {
                    let n = runner
                        .write_channel(chan, ChanData::Normal, &s.echo[..room.min(s.echo.len())])
                        .map_err(|e| format!("channel write: {e:?}"))?;
                    s.echo.drain(..n);
                    progressed = true;
                }
                Ok(Some(_)) => {}
                Ok(None) => s.echo.clear(),
                Err(e) => return Err(format!("channel ready: {e:?}")),
            }
        }

        // Child stdout/stderr -> client, only as far as the channel has room.
        // On a PTY the child's stdout and stderr are one pipe (one screen,
        // in order) sent as ordinary data, and LF becomes CR LF (so at most
        // half the room is read).
        if let Some(child) = s.child.as_mut() {
            for dt in [ChanData::Normal, ChanData::Stderr] {
                let eof = if dt == ChanData::Normal {
                    &mut s.out_eof
                } else {
                    &mut s.err_eof
                };
                if *eof {
                    continue;
                }
                let send = if s.tty.is_some() {
                    ChanData::Normal
                } else {
                    dt
                };
                let room = match runner.write_channel_ready(chan, send) {
                    Ok(Some(room)) => room,
                    Ok(None) => {
                        *eof = true;
                        continue;
                    }
                    Err(e) => return Err(format!("channel ready: {e:?}")),
                };
                if room == 0 {
                    continue;
                }
                let mut buf = [0u8; CHUNK];
                let want = if s.tty.is_some() { room / 2 } else { room }.min(CHUNK);
                if want == 0 {
                    continue;
                }
                let r = if dt == ChanData::Normal {
                    child.read_stdout(&mut buf[..want])
                } else {
                    child.read_stderr(&mut buf[..want])
                };
                match r {
                    Ok(None) => {}
                    Ok(Some(0)) | Err(_) => {
                        *eof = true;
                        progressed = true;
                    }
                    Ok(Some(n)) => {
                        let mut translated = Vec::new();
                        let data = if s.tty.is_some() {
                            tty::output(&buf[..n], &mut translated);
                            &translated[..]
                        } else {
                            &buf[..n]
                        };
                        let written = runner
                            .write_channel(chan, send, data)
                            .map_err(|e| format!("channel write: {e:?}"))?;
                        if written != data.len() {
                            return Err(format!(
                                "channel took {written} of {} ready bytes",
                                data.len()
                            ));
                        }
                        self.last_activity = now;
                        progressed = true;
                    }
                }
            }
            if s.exit.is_none() {
                match child.try_wait() {
                    Ok(Some(exit)) => {
                        say!("{} session child exited: {exit:?}", self.log_prefix);
                        s.exit = Some(exit);
                        progressed = true;
                    }
                    Ok(None) => {}
                    Err(error) => return Err(format!("wait: {error}")),
                }
            }
        }

        // End of session: EOF, exit-status, close, each once, in order.
        if let Some(exit) = s
            .exit
            .filter(|_| s.out_eof && s.err_eof && s.notice.is_empty())
        {
            if !s.sent_eof {
                runner.send_eof(chan).map_err(|e| format!("eof: {e:?}"))?;
                s.sent_eof = true;
                progressed = true;
            }
            if !s.sent_status {
                match exit {
                    Exit::Code(code) => match runner.send_exit_status(chan, code) {
                        Ok(()) => {
                            s.sent_status = true;
                            progressed = true;
                        }
                        // Output is congested: try again after it drains.
                        Err(sunset::Error::BusySend { .. }) => return Ok(progressed),
                        Err(e) => return Err(format!("exit-status: {e:?}")),
                    },
                    Exit::Abnormal => s.sent_status = true,
                }
            }
            if s.sent_status && !s.sent_close {
                runner
                    .close_channel(chan)
                    .map_err(|e| format!("close: {e:?}"))?;
                s.sent_close = true;
                s.child = None;
                progressed = true;
            }
        }
        Ok(progressed)
    }
}

/// Fixed admission rule for accepted connections. The caller supplies only
/// live slots; recomputing from them avoids a separate counter that could
/// survive close or timeout. `source` is the peer IP, never its TCP port.
pub(crate) fn preauth_source_has_room<'a, S: Eq + 'a>(
    source: &S,
    live: impl IntoIterator<Item = (&'a S, bool)>,
    limit: usize,
) -> bool {
    live.into_iter()
        .filter(|(peer, authenticated)| *peer == source && !*authenticated)
        .take(limit)
        .count()
        < limit
}

impl<C: SessionChild> Drop for Connection<C> {
    fn drop(&mut self) {
        if let Some(child) = self.session.child.as_mut() {
            if self.session.exit.is_none() {
                child.terminate();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MachineRequest, machine_request, preauth_source_has_room};

    #[test]
    fn per_source_pre_auth_admission_recomputes_live_slots() {
        let a = 1u8;
        let b = 2u8;
        let limit = 2;
        assert!(preauth_source_has_room(&a, [], limit));
        let one = [(&a, false)];
        assert!(preauth_source_has_room(&a, one, limit));
        let full = [(&a, false), (&a, false), (&b, false)];
        assert!(!preauth_source_has_room(&a, full, limit));
        assert!(preauth_source_has_room(&b, full, limit));
        // Authentication stops consuming a pre-auth source slot, even
        // though that connection still occupies a global session slot.
        let authenticated = [(&a, true), (&a, false), (&b, false)];
        assert!(preauth_source_has_room(&a, authenticated, limit));
        // Close and timeout remove slots before this pure check. Neither
        // can leave a stale per-source count behind.
        let after_close = [(&a, false), (&b, false)];
        assert!(preauth_source_has_room(&a, after_close, limit));
        let after_timeout = [(&b, false)];
        assert!(preauth_source_has_room(&a, after_timeout, limit));
    }

    #[test]
    fn machine_requests_are_exact_words() {
        for halt in [
            "shutdown",
            " shutdown now ",
            "shutdown -h now",
            "shutdown -p now",
        ] {
            assert_eq!(
                machine_request(halt),
                Some(Ok(MachineRequest::Halt)),
                "{halt}"
            );
        }
        for restart in ["reboot", "shutdown -r now"] {
            assert_eq!(
                machine_request(restart),
                Some(Ok(MachineRequest::Restart)),
                "{restart}"
            );
        }
        for usage in [
            "shutdown -r",
            "shutdown +5",
            "reboot now",
            "shutdown -h now please",
        ] {
            assert!(matches!(machine_request(usage), Some(Err(_))), "{usage}");
        }
        for other in ["/bin/shutdown", "ls", "", "echo shutdown", "shutdownx"] {
            assert_eq!(machine_request(other), None, "{other}");
        }
    }
}
