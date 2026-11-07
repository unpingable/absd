//! One SSH connection: sunset's sans-IO `Runner` plus at most one session
//! channel bridged to one child process. Platform-independent; the caller
//! moves bytes between the network and `push_input`/`output`, and calls
//! `pump` whenever anything may have changed.
//!
//! Session policy: one authenticated operator identity, one session channel
//! per connection, `shell` or `exec`, optionally after `pty-req`, or the
//! non-PTY `sftp` subsystem (no environment or forwarding). A PTY session's bytes pass
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

use crate::tty::{self, LineDiscipline, Terminal};
use sunset::{ChanData, ChanFail, ChanHandle, Event, PubKey, Runner, ServEvent, SignKey};

pub type ServerRunner = Runner<'static, sunset::Server>;

/// What a session asks to run.
#[derive(Clone, Debug)]
pub enum Command {
    Shell,
    Exec(String),
    Sftp,
}

fn subsystem_admitted(name: &str, terminal: bool, started: bool) -> bool {
    name == "sftp" && !terminal && !started
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

/// Diagnostic cause only; both cases keep the existing transport cleanup.
#[derive(Clone, Copy)]
pub enum InputClose {
    Eof,
    Failure,
}

enum ProtocolProgress {
    Running(bool),
    Closed,
}

/// A running session child. Reads and writes never block: `Ok(None)` means
/// "not now". `Ok(Some(0))` from a read is end of stream.
pub trait SessionChild {
    fn read_stdout(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>>;
    fn read_stderr(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>>;
    fn write_stdin(&mut self, buf: &[u8]) -> io::Result<Option<usize>>;
    fn close_stdin(&mut self);
    fn try_wait(&mut self) -> io::Result<Option<Exit>>;
    /// The last status query before the child is ended by force: no
    /// polling cadence may defer it, so an exit that already happened is
    /// reported rather than lost.
    fn final_wait(&mut self) -> io::Result<Option<Exit>> {
        self.try_wait()
    }
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
    /// Publish a client-reported resize for this session's commands.
    fn terminal_changed(&mut self, _terminal: &Terminal) -> io::Result<()> { Ok(()) }
    /// The processes of this session the backend can name, and what it can
    /// only count, for the session's own listing.
    fn describe(&mut self) -> String {
        String::new()
    }
    /// The boot-local process incarnation already owned by this backend.
    fn audit_pid(&self) -> Option<u64> { None }
}

/// What a session's shell may ask sshd on its control channel (only the
/// ABSD backend gives one).
#[cfg_attr(not(target_os = "absd"), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlRequest {
    /// The words of a `shutdown` or `reboot` command.
    Machine(String),
    Clock(String),
    /// This session's processes.
    List,
    InputMode(u8),
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
    /// The installed ABSD identity, already checked against the file
    /// server before listening. The Linux reference backend has none.
    fn release_id(&self) -> Option<&str> {
        None
    }
    /// An authenticated operator's machine request. `Ok` carries the text
    /// the requesting session prints before it ends with status 0; `Err`
    /// the refusal it prints before status 1.
    fn machine_request(&mut self, request: MachineRequest) -> Result<String, String>;
    fn clock_request(&mut self,_words:&str)->Result<String,String>{Err("clock: no clock owner in this backend\n".into())}
    /// Starts `command`. On a `terminal` (PTY) session the child's stdout
    /// and stderr are one pipe, as they are one screen: `read_stderr` then
    /// only ever reports end of stream.
    fn spawn(&mut self, command: &Command, terminal: Option<&Terminal>) -> io::Result<Self::Child>;
    /// A managed physical login uses the local partition, never a remote slot.
    fn spawn_local(&mut self, command: &Command, terminal: Option<&Terminal>) -> io::Result<Self::Child> {
        self.spawn(command, terminal)
    }
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
    input_paused: bool,
    record_write: tty::paste::RecordWrite,
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
    terminal: Option<Terminal>,
    /// Echo of the client's keystrokes, not yet sent.
    echo: Vec<u8>,
    /// Login banner, sent before terminal echo or child output.
    banner: Vec<u8>,
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

impl<C: SessionChild> Session<C> {
    /// Actual PTY event handling, shared by channel bytes and channel EOF.
    fn terminal_input(&mut self, bytes: Option<&[u8]>, prefix: &str) -> tty::Events {
        let Some(tty) = self.tty.as_mut() else { return tty::Events::default(); };
        tty.pending_source_bytes(self.stdin.len());
        let was_refused = tty.input_refused();
        let padding = self.record_write.cancel_padding(&self.stdin);
        let event = match bytes {
            Some(bytes) => tty.input(bytes, &mut self.stdin, &mut self.echo),
            None => tty.finish_input(&mut self.stdin, &mut self.echo),
        };
        if event.interrupt {
            let wake = !self.stdin.is_empty();
            self.stdin.clear();
            if let Some((header, count)) = padding {
                self.stdin.extend_from_slice(&header);
                self.stdin.resize(header.len() + count, b'\n');
            }
            if wake { self.stdin.push(b'\n'); }
        }
        if event.interrupt && self.exit.is_none() {
            if let Some(child) = self.child.as_mut() {
                if child.interrupt() {
                    info!("{} interrupt: told the shell", prefix);
                } else if self.exec && event.application_interrupt {
                    child.terminate();
                    self.exit = Some(Exit::Abnormal);
                    info!("{} interrupt: exec application ended", prefix);
                } else if self.exec && tty.input_refused() {
                    // No controlled shell can acknowledge this pause. This
                    // single-threaded producer owns it and can confirm it
                    // directly; already consumed application data is not undone.
                    self.input_paused = true;
                    tty.set_prompt_mode(0);
                    // END may have arrived in the same channel packet as the
                    // refusal, before this producer could acknowledge its pause.
                    if tty.finish_recovery(&mut self.stdin, &mut self.echo) {
                        self.stdin.clear();
                        self.record_write = tty::paste::RecordWrite::default();
                        tty.resume_application_input();
                        self.input_paused = false;
                    }
                } else if self.exec && was_refused && self.input_paused {
                    self.stdin.clear();
                    self.record_write = tty::paste::RecordWrite::default();
                    tty.resume_application_input();
                    self.input_paused = false;
                } else if self.exec {
                    child.terminate();
                    self.exit = Some(Exit::Abnormal);
                    info!("{} interrupt: exec child ended", prefix);
                }
            }
        }
        if self.exit.is_none() && tty.needs_recovery_code() {
            let mut random = [0; 8];
            match getrandom::fill(&mut random) {
                Ok(()) => tty.recovery_code(random, &mut self.echo),
                Err(_) => tty.recovery_unavailable(&mut self.echo),
            }
        }
        event
    }
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
    input_failed: bool, // Diagnostic classification only, never transport policy.
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
                input_paused: false,
                record_write: tty::paste::RecordWrite::default(),
                stdin_closed: false,
                out_eof: false,
                err_eof: false,
                exit: None,
                sent_eof: false,
                sent_status: false,
                sent_close: false,
                refusal: None,
                tty: None,
                terminal: None,
                echo: Vec::new(),
                banner: Vec::new(),
                exec: false,
                reply: None,
                notice: Vec::new(),
                shutting_down: false,
            },
            netin: Vec::new(),
            net_eof: false,
            input_failed: false,
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

    /// The peer closed its sending direction or an I/O failure was observed.
    /// Keep the cause only for diagnostics; close/drain behavior is unchanged.
    pub fn input_closed(&mut self, cause: InputClose) {
        let late_failure = matches!(cause, InputClose::Failure)
            && !self.input_failed && self.end.is_some();
        self.input_failed |= matches!(cause, InputClose::Failure);
        if late_failure {
            crate::oplog::line(format!("{} I/O failure after connection end", self.log_prefix));
        }
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
            self.finish_normal("system shutdown");
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
                let (exit, ended) = end_by_force(child);
                if ended {
                    say!(
                        "{} shutdown grace over: session child ended",
                        self.log_prefix
                    );
                }
                s.exit = Some(exit);
            }
        }
        s.out_eof = true;
        s.err_eof = true;
        s.refusal = None;
        s.reply = None;
        s.notice.clear();
    }

    /// Ends the connection now (the transport closes after what is queued).
    pub fn end_shutdown(&mut self) {
        self.finish_normal("system shutdown");
    }

    fn finish(&mut self, reason: impl Into<String>) {
        self.finish_classified(reason, false);
    }

    fn finish_normal(&mut self, reason: impl Into<String>) {
        self.finish_classified(reason, true);
    }

    fn finish_input_close(&mut self, reason: impl Into<String>) {
        if self.input_failed {
            self.finish(reason)
        } else {
            self.finish_normal(reason)
        }
    }

    fn finish_classified(&mut self, reason: impl Into<String>, normal: bool) {
        if self.end.is_none() {
            let reason = reason.into();
            let text = format!("{} end: {reason}", self.log_prefix);
            if normal { crate::oplog::info(text) } else { crate::oplog::line(text) }
            self.end = Some(reason);
            if let Some(child) = self.session.child.as_mut() {
                if self.session.exit.is_none() {
                    child.terminate();
                    let text = format!("{} session child reclaimed", self.log_prefix);
                    if normal { crate::oplog::info(text) } else { crate::oplog::line(text) }
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
                Ok(ProtocolProgress::Running(p)) => progressed |= p,
                Ok(ProtocolProgress::Closed) => {
                    self.finish_input_close("connection closed (defunct)");
                    return true;
                }
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
            self.finish_input_close("client closed the connection");
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
    ) -> Result<ProtocolProgress, String> {
        let mut progressed = false;
        loop {
            let event = self
                .runner
                .progress()
                .map_err(|e| format!("protocol: {e:?}"))?;
            match event {
                Event::None => return Ok(ProtocolProgress::Running(progressed)),
                Event::Progressed => progressed = true,
                Event::Cli(_) => return Err("client event on a server".into()),
                Event::Serv(event) => {
                    progressed = true;
                    let s = &mut self.session;
                    let prefix = &self.log_prefix;
                    let r = match event {
                        ServEvent::Hostkeys(h) => h.hostkeys(&[identity.host_key]),
                        ServEvent::FirstAuth(mut a) => {
                            info!("{prefix} user {:?}", a.username().unwrap_or("?"));
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
                            info!("{prefix} authenticated");
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
                                info!("{prefix} pty accepted");
                                let dimensions = p.dimensions().map_err(|e| format!("pty dimensions: {e:?}"))?;
                                let term = p.terminal().map_err(|e| format!("pty TERM: {e:?}"))?.unwrap_or("");
                                s.terminal = Some(Terminal::ssh(term, dimensions.0, dimensions.1));
                                s.tty = Some(LineDiscipline::new());
                                p.succeed()
                            } else {
                                say!("{prefix} pty refused");
                                p.fail()
                            }
                        }
                        ServEvent::SessionWindow(p) => {
                            if let Some(terminal) = s.terminal.as_mut() {
                                let dimensions = p.dimensions().map_err(|e| format!("window dimensions: {e:?}"));
                                match change_terminal_size(terminal, dimensions, s.child.as_mut()) {
                                    Ok(()) => p.succeed(),
                                    Err(error) => { say!("{prefix} window update ignored: {error}"); p.fail() }
                                }
                            } else { p.fail() }
                        }
                        ServEvent::SessionEnv(e) => e.fail(),
                        ServEvent::SessionSubsystem(r) => {
                            let admitted = r.command().is_ok_and(|name| {
                                subsystem_admitted(name, s.tty.is_some(), s.child.is_some() || s.exit.is_some())
                            });
                            if admitted {
                                match spawner.spawn(&Command::Sftp, None) {
                                    Ok(child) => {
                                        say!("{prefix} sftp subsystem started");
                                        s.child = Some(child);
                                        s.exec = true;
                                        r.succeed()
                                    }
                                    Err(error) => {
                                        say!("{prefix} sftp subsystem refused: {error}");
                                        r.fail()
                                    }
                                }
                            } else {
                                r.fail()
                            }
                        }
                        ServEvent::SessionShell(r) => {
                            if s.child.is_some() || s.exit.is_some() {
                                r.fail()
                            } else {
                                match spawner.spawn(&Command::Shell, s.terminal.as_ref()) {
                                    Ok(child) => {
                                        info!("{prefix} shell started");
                                        s.child = Some(child);
                                        let banner = crate::motd::for_session(
                                            &Command::Shell,
                                            s.tty.is_some(),
                                            spawner.release_id(),
                                        );
                                        tty::output(&banner, &mut s.banner);
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
                                            .spawn(&Command::Exec(command.clone()), s.terminal.as_ref())
                                        {
                                            Ok(child) => {
                                                info!("{prefix} exec {command:?}");
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
                        ServEvent::Defunct => return Ok(ProtocolProgress::Closed),
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
            ControlRequest::Clock(words) => {
                if matches!(words.split_ascii_whitespace().next(), Some("set" | "sync")) {
                    let pid = child.audit_pid().map(|n| n.to_string()).unwrap_or_else(|| "unknown".into());
                    say!("{} pid={pid}: clock request {words:?} from the authenticated session's shell", self.log_prefix);
                }
                match spawner.clock_request(&words) { Ok(t) => (0, t), Err(t) => (1, t) }
            },
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
            ControlRequest::InputMode(prompt) => {
                if prompt == 4 {
                    if let Some(tty) = s.tty.as_mut() {
                        tty.refuse_input("shell source exceeds 1 MiB", &mut s.stdin, &mut s.echo);
                        let mut random=[0;8];
                        if getrandom::fill(&mut random).is_ok() { tty.recovery_code(random, &mut s.echo); }
                        else { tty.recovery_unavailable(&mut s.echo); }
                    }
                    s.record_write = tty::paste::RecordWrite::default();
                    child.interrupt();
                }
                if matches!(prompt, 0 | 4) && s.tty.as_ref().is_some_and(LineDiscipline::input_cancelled) {
                    s.stdin.clear();
                    s.record_write = tty::paste::RecordWrite::default();
                    s.input_paused = true;
                } else if matches!(prompt, 1 | 2) && s.input_paused {
                    s.stdin.clear();
                    s.input_paused = false;
                }
                if matches!(prompt, 0 | 1 | 2 | 4) && s.tty.is_some() {
                    s.echo.extend_from_slice(if matches!(prompt, 1 | 2) { b"\x1b[?2004h" } else { b"\x1b[?2004l" });
                }
                let mut refused = false;
                if let Some(tty) = s.tty.as_mut() {
                    tty.set_prompt_mode(if prompt == 4 { 0 } else { prompt });
                    if matches!(prompt, 1 | 2) && tty.finish_recovery(&mut s.stdin, &mut s.echo) { child.interrupt(); }
                    refused = tty.input_refused();
                }
                (if matches!(prompt, 0 | 4) && s.input_paused { crate::control::INPUT_PAUSED }
                 else if refused { crate::control::INPUT_REFUSED } else { 0 },
                 if s.tty.is_some() { "paste-record-v2".into() } else { String::new() })
            }
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
                info!("{} session listing", self.log_prefix);
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

        // PTY input has bounded backpressure. A nonreader may fill stdin
        // and delay an in-band Ctrl-C until space becomes available.
        if s.tty.is_some() {
            if s.child.is_some() {
                if s.stdin.len() < CHUNK && s.echo.len() < CHUNK {
                    let mut buf = [0u8; CHUNK];
                    match runner.read_channel(chan, ChanData::Normal, &mut buf) {
                        Ok(0) | Err(sunset::Error::ChannelEOF) => {
                            if runner.is_channel_eof(chan) {
                                progressed |= s.terminal_input(None, &self.log_prefix).interrupt;
                            }
                        }
                        Ok(n) => {
                            s.terminal_input(Some(&buf[..n]), &self.log_prefix);
                            progressed = true;
                        }
                        Err(e) => return Err(format!("channel read: {e:?}")),
                    }
                }
            } else if runner.read_channel_ready().is_some() {
                runner.discard_read_channel(chan).map_err(|e| format!("discard: {e:?}"))?;
                progressed = true;
            }
            if s.stdin_closed { s.stdin.clear(); }
        }

        // The terminal handler mutates session input state, never the channel.
        let chan = s.chan.as_ref().expect("session channel remains owned");

        // Client -> child stdin.
        let typed_eof = s.tty.as_ref().is_some_and(LineDiscipline::at_eof);
        if let Some(child) = s.child.as_mut().filter(|_| !s.stdin_closed && !s.input_paused) {
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
                        s.record_write.written(&s.stdin[..n]);
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

        if !s.stdin_closed && s.stdin.is_empty()
            && (runner.is_channel_eof(chan) || typed_eof || s.shutting_down) {
            if let Some(child) = s.child.as_mut() {
                child.close_stdin();
                s.stdin_closed = true;
                progressed = true;
            }
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

        // The interactive login banner precedes even a prompt from a
        // child that starts immediately. Preserve it across short writes.
        if !s.banner.is_empty() {
            match runner.write_channel_ready(chan, ChanData::Normal) {
                Ok(Some(room)) if room > 0 => {
                    let n = runner
                        .write_channel(chan, ChanData::Normal, &s.banner[..room.min(s.banner.len())])
                        .map_err(|e| format!("channel write: {e:?}"))?;
                    s.banner.drain(..n);
                    progressed = true;
                }
                Ok(Some(_)) => {}
                Ok(None) => s.banner.clear(),
                Err(e) => return Err(format!("channel ready: {e:?}")),
            }
            if !s.banner.is_empty() {
                return Ok(progressed);
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
                        let data = if let Some(terminal) = s.tty.as_mut() {
                            terminal.child_output(&buf[..n]);
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
                        crate::oplog::session_exit(&self.log_prefix, exit);
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
            .filter(|_| s.out_eof && s.err_eof && s.notice.is_empty() && s.echo.is_empty())
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

/// A resize failure is local to the update and cannot end a session.
fn change_terminal_size<C: SessionChild>(terminal: &mut Terminal, dimensions: Result<(u32,u32),String>, child: Option<&mut C>) -> Result<(),String> {
    let (columns,rows)=dimensions?;
    let mut next=terminal.clone();
    next.size.columns=columns; next.size.rows=rows;
    next.size=next.size.bounded();
    if let Some(child)=child { child.terminal_changed(&next).map_err(|e| format!("terminal update: {e}"))?; }
    *terminal=next;
    Ok(())
}

/// A child still running when the shutdown grace ends: a status it already
/// has is kept; otherwise it is ended and its exit is abnormal. Whether it
/// was ended is the second value.
fn end_by_force(child: &mut impl SessionChild) -> (Exit, bool) {
    if let Ok(Some(exit)) = child.final_wait() {
        return (exit, false);
    }
    child.terminate();
    (Exit::Abnormal, true)
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
    #[test]
    fn only_exact_sftp_without_a_terminal_or_started_session_is_admitted() {
        assert!(super::subsystem_admitted("sftp", false, false));
        for name in ["", "SFTP", "sftp ", "sftp-extra", "sftp\0"] {
            assert!(!super::subsystem_admitted(name, false, false));
        }
        assert!(!super::subsystem_admitted("sftp", true, false));
        assert!(!super::subsystem_admitted("sftp", false, true));
    }

    use super::{
        Exit, MachineRequest, SessionChild, end_by_force, machine_request, preauth_source_has_room,
    };
    use std::io;

    /// A child whose ordinary status query is deferred by a cadence, as the
    /// ABSD backend's is, while its final query is not.
    struct Deferred {
        exited: Option<Exit>,
        failing: bool,
        terminated: bool,
    }
    impl SessionChild for Deferred {
        fn read_stdout(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
            Ok(Some(0))
        }
        fn read_stderr(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
            Ok(Some(0))
        }
        fn write_stdin(&mut self, _: &[u8]) -> io::Result<Option<usize>> {
            Ok(None)
        }
        fn close_stdin(&mut self) {}
        fn terminal_changed(&mut self, _: &super::Terminal) -> io::Result<()> {
            if self.failing {Err(io::Error::other("cell update failed"))} else {Ok(())}
        }
        fn try_wait(&mut self) -> io::Result<Option<Exit>> {
            Ok(None)
        }
        fn final_wait(&mut self) -> io::Result<Option<Exit>> {
            if self.failing {
                return Err(io::Error::other("wait failed"));
            }
            Ok(self.exited)
        }
        fn terminate(&mut self) {
            self.terminated = true;
        }
    }

    #[test]
    fn captured_connection_close_keeps_io_failure_warning_after_eof() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "conn::tests::emit_connection_close", "--nocapture"])
            .env("ABSD_CLOSE_TEST_CHILD", "1").output().unwrap();
        assert!(output.status.success());
        let out = String::from_utf8(output.stdout).unwrap();
        let err = String::from_utf8(output.stderr).unwrap();
        assert!(out.contains("known-eof"));
        assert!(!err.contains("known-eof"));
        assert!(err.contains("failed-after-eof"));
        assert!(!out.contains("failed-after-eof"));
        assert_eq!(out.lines().filter(|line| line.contains("known-eof")).count(), 1);
        assert!(!err.contains("sshd: conn 901:"));
        assert_eq!(err.lines().filter(|line| line.contains("sshd: conn 902:")).count(), 1);
        assert!(out.contains("normal-end-before-write-failure"));
        let late: Vec<_> = err.lines().filter(|line| line.contains("sshd: conn 903:")).collect();
        assert_eq!(late.len(), 1, "the first late I/O failure must warn exactly once");
        assert!(late[0].contains("I/O failure after connection end"));
        assert!(!out.contains("I/O failure after connection end"));
    }

    #[test]
    fn emit_connection_close() {
        if std::env::var_os("ABSD_CLOSE_TEST_CHILD").is_none() { return; }
        let mut clean = super::Connection::<Deferred>::new(901, std::time::Instant::now());
        clean.input_closed(super::InputClose::Eof);
        clean.finish_input_close("known-eof");
        clean.finish_input_close("ignored-clean-repeat");
        let mut failed = super::Connection::<Deferred>::new(902, std::time::Instant::now());
        failed.input_closed(super::InputClose::Eof);
        failed.input_closed(super::InputClose::Failure);
        failed.input_closed(super::InputClose::Failure);
        failed.input_closed(super::InputClose::Eof); // EOF cannot clear a failure.
        failed.finish_input_close("failed-after-eof");
        failed.finish_input_close("ignored-failure-repeat");
        let mut late = super::Connection::<Deferred>::new(903, std::time::Instant::now());
        late.input_closed(super::InputClose::Eof);
        late.finish_input_close("normal-end-before-write-failure");
        late.input_closed(super::InputClose::Failure);
        late.input_closed(super::InputClose::Failure);
        late.input_closed(super::InputClose::Eof);
        late.finish_input_close("ignored-late-repeat");
        assert_eq!(late.end.as_deref(), Some("normal-end-before-write-failure"));
    }

    #[test]
    fn resize_refusal_keeps_known_dimensions_and_live_child() {
        let mut terminal=super::Terminal::ssh("xterm",80,25);
        let mut child=Deferred{exited:None,failing:true,terminated:false};
        assert!(super::change_terminal_size(&mut terminal,Ok((120,40)),Some(&mut child)).is_err());
        assert_eq!((terminal.size.columns,terminal.size.rows),(80,25));
        assert!(!child.terminated);
        child.failing=false;
        assert!(super::change_terminal_size(&mut terminal,Err("bad dimensions".into()),Some(&mut child)).is_err());
        assert_eq!((terminal.size.columns,terminal.size.rows),(80,25));
        assert!(super::change_terminal_size(&mut terminal,Ok((120,40)),Some(&mut child)).is_ok());
        assert_eq!((terminal.size.columns,terminal.size.rows),(120,40));
    }

    #[test]
    fn shutdown_force_keeps_an_exit_the_cadence_had_not_yet_observed() {
        let mut child = Deferred {
            exited: Some(Exit::Code(7)),
            failing: false,
            terminated: false,
        };
        assert_eq!(end_by_force(&mut child), (Exit::Code(7), false));
        assert!(!child.terminated);
    }

    #[test]
    fn shutdown_force_ends_a_child_still_running() {
        let mut child = Deferred {
            exited: None,
            failing: false,
            terminated: false,
        };
        assert_eq!(end_by_force(&mut child), (Exit::Abnormal, true));
        assert!(child.terminated);
    }

    #[test]
    fn shutdown_force_ends_a_child_whose_final_query_fails() {
        let mut child = Deferred {
            exited: Some(Exit::Code(7)),
            failing: true,
            terminated: false,
        };
        assert_eq!(end_by_force(&mut child), (Exit::Abnormal, true));
        assert!(child.terminated);
    }

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

#[cfg(test)]
mod proposed_typeahead_control_tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    // Test boundary is the real Connection control dispatcher and its TTY/
    // stdin queue, not encrypted channel transport or a simulated discipline.
    struct Child {
        request: Option<ControlRequest>,
        replies: Vec<(u8, String)>,
        retired: Rc<Cell<bool>>,
        controlled: bool,
    }
    impl SessionChild for Child {
        fn read_stdout(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> { Ok(None) }
        fn read_stderr(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> { Ok(None) }
        fn write_stdin(&mut self, bytes: &[u8]) -> io::Result<Option<usize>> { Ok(Some(bytes.len())) }
        fn close_stdin(&mut self) {}
        fn try_wait(&mut self) -> io::Result<Option<Exit>> { Ok(None) }
        fn terminate(&mut self) { self.retired.set(true); }
        fn interrupt(&mut self) -> bool { self.controlled }
        fn control_request(&mut self, _: Instant) -> Result<Option<ControlRequest>, String> {
            Ok(self.request.take())
        }
        fn control_reply(&mut self, status: u8, text: &str) {
            self.replies.push((status, text.to_owned()));
        }
    }
    struct NoSpawn;
    impl Spawner for NoSpawn {
        type Child = Child;
        fn machine_request(&mut self, _: MachineRequest) -> Result<String, String> {
            panic!("no machine request in this control test")
        }
        fn spawn(&mut self, _: &Command, _: Option<&Terminal>) -> io::Result<Child> {
            panic!("no spawn in this control test")
        }
    }
    fn connection() -> (Connection<Child>, Rc<Cell<bool>>) {
        let retired = Rc::new(Cell::new(false));
        let mut conn = Connection::new(149, Instant::now());
        conn.session.child = Some(Child { request: None, replies: Vec::new(), retired: retired.clone(), controlled: true });
        conn.session.tty = Some(LineDiscipline::new());
        (conn, retired)
    }
    fn mode(conn: &mut Connection<Child>, mode: u8) {
        conn.session.child.as_mut().unwrap().request = Some(ControlRequest::InputMode(mode));
        assert!(conn.control(&mut NoSpawn, Instant::now()));
        let status=if matches!(mode,0|4) && conn.session.input_paused { crate::control::INPUT_PAUSED }
            else if conn.session.tty.as_ref().is_some_and(LineDiscipline::input_refused) { crate::control::INPUT_REFUSED } else {0};
        assert_eq!(conn.session.child.as_ref().unwrap().replies.last(), Some(&(status, "paste-record-v2".into())));
    }
    fn input(conn: &mut Connection<Child>, bytes: &[u8]) -> tty::Events {
        conn.session.terminal_input(Some(bytes), &conn.log_prefix)
    }
    #[test]
    fn control_dispatch_preserves_observed_typeahead_across_segmentations() {
        let command = [b"echo ".to_vec(), vec![b'C'; 4090]].concat();
        for chunk in [1, 7, 128, 256, 4096] {
            let (mut conn, _) = connection(); mode(&mut conn, 1);
            input(&mut conn, b"echo B\r");
            for part in command[..3712].chunks(chunk) { input(&mut conn, part); }
            mode(&mut conn, 0); mode(&mut conn, 1);
            for part in command[3712..].chunks(chunk) { input(&mut conn, part); }
            input(&mut conn, b"\r");
            assert_eq!(conn.session.stdin, [b"echo B\n".to_vec(), command.clone(), vec![b'\n']].concat());
            assert!(conn.session.echo.ends_with(b"\r\n"));
            conn.session.stdin.clear(); mode(&mut conn, 1);
            input(&mut conn, b"\x1b[A\r");
            assert_eq!(conn.session.stdin, b"echo B\n", "application draft was promoted into history");
        }
    }
    #[test]
    fn unread_inherited_stdin_policy_and_actual_session_retirement_are_explicit() {
        let (mut conn, retired) = connection();
        mode(&mut conn, 0); input(&mut conn, b"unread complete\rpartial");
        mode(&mut conn, 1); input(&mut conn, b" tail\r");
        // Completed input was already queued in the accepted base. The
        // proposed policy additionally preserves the unfinished draft.
        assert_eq!(conn.session.stdin, b"unread complete\npartial tail\n");
        conn.session.stdin.clear(); mode(&mut conn, 1); input(&mut conn, b"\x1b[A\r");
        assert_eq!(conn.session.stdin, b"\n", "unread application text entered history");
        input(&mut conn, b"retired unfinished");
        conn.end_shutdown(); assert!(retired.get());
        drop(conn);
        let (mut fresh, _) = connection(); mode(&mut fresh, 1);
        input(&mut fresh, b"\x1b[A\r"); assert_eq!(fresh.session.stdin, b"\n");
    }
    #[test]
    fn cancel_discards_server_queue_and_batch_tail_then_pauses_before_rearm() {
        let (mut conn, _) = connection();
        mode(&mut conn, 1);
        let event = input(&mut conn, b"echo first\r\x03echo must-not-run\r");
        assert!(event.interrupt);
        // Submission disarmed collection, but the shell still owns the read.
        assert_eq!(conn.session.stdin, b"\n", "wake once, never deliver cancelled queued lines");
        input(&mut conn, b"more cancelled input\r");
        assert_eq!(conn.session.stdin, b"\n");
        mode(&mut conn, 0);
        assert!(conn.session.stdin.is_empty(), "pause ACK must clear the server queue");
        input(&mut conn, b"late cancelled input\r");
        assert!(conn.session.stdin.is_empty());
        mode(&mut conn, 1);
        input(&mut conn, b"fresh\r");
        assert_eq!(conn.session.stdin, b"fresh\n");
    }

    #[test]
    fn initial_prompt_cannot_release_cancelled_input_before_pause() {
        let (mut conn, _) = connection();
        input(&mut conn, b"echo 'body\recho must-not-run\r\x03tail\r");
        assert!(conn.session.stdin.is_empty());
        mode(&mut conn, 1);
        input(&mut conn, b"still cancelled\r");
        assert!(conn.session.stdin.is_empty());
        mode(&mut conn, 0);
        mode(&mut conn, 1);
        input(&mut conn, b"fresh\r");
        assert_eq!(conn.session.stdin, b"fresh\n");
    }
    #[test]
    fn malformed_input_keeps_its_session_and_cannot_rearm_by_mode_change() {
        let (mut conn, retired) = connection();
        mode(&mut conn, 1);
        let event = input(&mut conn, &vec![b'x'; tty::MAX_LINE + 1]);
        assert!(event.interrupt && !retired.get());
        assert_eq!(conn.session.exit, None);
        assert!(!conn.session.stdin_closed);
        assert!(String::from_utf8_lossy(&conn.session.echo).contains("recovery required"));
        mode(&mut conn, 0); mode(&mut conn, 1);
        conn.session.stdin.clear();
        input(&mut conn, b"\x03echo suffix > /victim\r");
        assert!(conn.session.stdin.is_empty());
        let (mut fresh, _) = connection(); mode(&mut fresh, 1);
        input(&mut fresh, b"fresh\r"); assert_eq!(fresh.session.stdin, b"fresh\n");
    }
    #[test]
    fn actual_session_pads_only_an_inflight_record_and_resets_after_the_drain() {
        let source=b"echo one\necho two\n";
        let expected=[tty::paste::record::header(source.len()),source.to_vec()].concat();
        for cut in 0..=expected.len() {
            let(mut conn,retired)=connection();mode(&mut conn,1);
            input(&mut conn,&[b"\x1b[200~".as_slice(),source,b"\x1b[201~\r"].concat());
            assert_eq!(conn.session.stdin,expected);
            conn.session.record_write.written(&expected[..cut]);conn.session.stdin.drain(..cut);
            let padding=conn.session.record_write.cancel_padding(&conn.session.stdin);
            input(&mut conn,b"\x03echo stale\r");
            if let Some((header,left))=padding {
                let mut want=header;want.resize(want.len()+left,b'\n');want.push(b'\n');assert_eq!(conn.session.stdin,want);
            } else {assert_eq!(conn.session.stdin,b"\n");}
            mode(&mut conn,0);assert!(conn.session.stdin.is_empty());
            assert!(conn.session.record_write.cancel_padding(b"").is_none());
            mode(&mut conn,1);input(&mut conn,b"fresh\r");assert_eq!(conn.session.stdin,b"fresh\n");assert!(!retired.get());
        }
    }
    #[test]
    fn shell_source_mode_four_stays_in_the_same_session_and_early_code_is_latched() {
        let(mut conn,retired)=connection();mode(&mut conn,1);mode(&mut conn,4);
        assert!(conn.session.input_paused);assert!(conn.session.tty.as_ref().unwrap().input_refused());
        let display=String::from_utf8_lossy(&conn.session.echo);
        let code=display.split("terminal: type ").nth(1).unwrap().split_whitespace().next().unwrap().to_owned();
        input(&mut conn,format!("{code}\recho stale\r").as_bytes());
        // Mode 4 already acknowledged pause; recovery remains cancelled until
        // a second pause/drain/rearm. A fresh command then uses the same child.
        mode(&mut conn,0);mode(&mut conn,1);input(&mut conn,b"fresh\r");
        assert_eq!(conn.session.stdin,b"fresh\n");assert_eq!(conn.session.exit,None);assert!(!retired.get());
    }
    #[test]
    fn direct_exec_refusal_code_recovers_without_terminating_the_child() {
        let(mut conn,retired)=connection();conn.session.exec=true;
        conn.session.child.as_mut().unwrap().controlled=false;
        input(&mut conn,b"\xff");
        let shown=String::from_utf8_lossy(&conn.session.echo);
        let code=shown.split("terminal: type ").nth(1).unwrap().split_whitespace().next().unwrap().to_owned();
        input(&mut conn,format!("{code}\r").as_bytes());
        assert!(!conn.session.tty.as_ref().unwrap().input_refused(),"direct exec has no shell handshake to release refusal");
        input(&mut conn,b"fresh application input\r");
        assert_eq!(conn.session.stdin,b"fresh application input\n");
        assert!(!retired.get());assert_eq!(conn.session.exit,None);
    }
    #[test]
    fn direct_exec_refused_paste_recovers_at_end_in_the_same_packet() {
        let(mut conn,retired)=connection();conn.session.exec=true;
        conn.session.child.as_mut().unwrap().controlled=false;
        input(&mut conn,b"\x1b[200~\xffignored\n\x1b[201~");
        assert!(!conn.session.tty.as_ref().unwrap().input_refused());
        input(&mut conn,b"fresh\n");assert_eq!(conn.session.stdin,b"fresh\n");
        assert!(!retired.get());assert_eq!(conn.session.exit,None);
    }
    #[test]
    fn actual_random_code_recovers_the_same_session_and_drops_stale_tail() {
        let (mut conn, retired)=connection(); mode(&mut conn,1);
        input(&mut conn,b"\xffecho victim\r\x03");
        let display=String::from_utf8_lossy(&conn.session.echo);
        let code=display.split("terminal: type ").nth(1).unwrap().split_whitespace().next().unwrap().to_owned();
        assert_eq!(code.len(),16); assert!(code.bytes().all(|b| b.is_ascii_hexdigit()));
        mode(&mut conn,0); mode(&mut conn,1); conn.session.stdin.clear();
        input(&mut conn,b"wrong\r\x03echo victim\r"); assert!(conn.session.stdin.is_empty());
        let reply=format!("{code}\r\necho stale > /victim\r"); input(&mut conn,reply.as_bytes());
        assert!(!conn.session.tty.as_ref().unwrap().input_refused());
        assert!(!conn.session.stdin.windows(5).any(|b| b==b"stale"));
        mode(&mut conn,0); mode(&mut conn,1); input(&mut conn,b"echo fresh\r");
        assert_eq!(conn.session.stdin,b"echo fresh\n"); assert!(!retired.get()); assert_eq!(conn.session.exit,None);
    }
    #[test]
    fn incomplete_utf8_at_actual_session_eof_is_visible_and_refused() {
        let (mut conn, retired) = connection(); mode(&mut conn, 1);
        input(&mut conn, b"echo prefix\xc3");
        let event = conn.session.terminal_input(None, &conn.log_prefix);
        assert!(event.interrupt && !retired.get());
        assert_eq!(conn.session.exit, None);
        assert_eq!(conn.session.stdin, b"\n");
        assert!(String::from_utf8_lossy(&conn.session.echo).contains("incomplete UTF-8"));
    }
}

#[cfg(test)]
#[path = "review02_conn.rs"]
mod review02_conn;
