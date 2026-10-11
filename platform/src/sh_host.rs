//! absd-sh's platform (`shell::Host`) on ABSD: files through `std::fs` with
//! the running process's own filesystem authority, and pipelines composed
//! from `std::process::Command` over kernel pipes. Included by path by
//! `/bin/absd-sh` and by `sh-launch` (which runs the same executor in a
//! process that holds write authority).
//!
//! Composition. `a | b`: `a` starts with a piped stdout, whose read end
//! comes back to this process as `ChildStdout`; it is given to `b` as its
//! stdin with `Stdio::from`, and the successful spawn of `b` consumes it
//! (the personality closes this process's copy at once). The write end was
//! only ever `a`'s: the runtime closes the parent's copy right after `a`
//! starts. So once both are running, the pipe's only reader is `b` and its
//! only writer is `a`: `b` sees end-of-file exactly when `a` is done, and
//! `a` gets a typed broken-pipe error (`io::ErrorKind::BrokenPipe`, the
//! kernel's `-32`) exactly when `b` is gone. No handle is inherited
//! implicitly and there are no signals.
//!
//! Files. A child never gets a file: ABSD files are the `absd-fs` library's
//! objects inside the process that mounted them, not kernel handles. For
//! `< f` this process opens `f` and copies it into a pipe whose read end is
//! the child's stdin; for `> f`, `>> f`, `2> f` it opens `f` for writing
//! and copies the child's output pipe into it. The child holds one pipe end
//! per redirected stream and nothing else. The copier (`Feed`, `Drain`)
//! only uses `std::fs` files the shell opened, so it works unchanged when
//! `std::fs` goes through a filesystem server whose mount list gives the
//! shell a writable directory; if such a server later hands out a handle
//! for exactly one file, a redirection can give the child that handle
//! instead of a pipe, and the shell's own open stays the authority check.
//!
//! Interruption. A shell sshd started for a session holds a session
//! control channel (startup roles 16 and 17, `absd_runtime::session`;
//! the protocol is `ssh/src/control.rs`). While a pipeline runs, the shell
//! alternates a timed wait on each child it has not reaped (`try_wait`, one
//! tick) with a timed read of the control channel ([`CONTROL_TICKS`]); on
//! ^C there it kills every child still running with the process handle it
//! holds and reaps it. No signal, process group, or wait on several objects
//! at once is involved. A shell without the channel waits for its children
//! as before.
//!
//! Ending. When the session ends (client gone, idle timeout, or the system
//! going down), sshd sends `END` on the same channel before it does
//! anything else to the shell. The shell kills and reaps every child still
//! running exactly as for ^C, drops its copiers, and exits without reading
//! another line; at the prompt, the end of its input (sshd closes it too)
//! is enough. `absd-sh` starts its commands without the spawn right
//! (`src/bin/absd_sh.rs`), so a command has no children of its own: the
//! shell's children are the whole session, and it holds a kill right on
//! each of them.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::absd::process::AsRawHandle;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

use absd_runtime::fsd::ChildFs;

use crate::session_control::{self as control, Decoder, Frame};
use crate::shell::{Authority, Exit, Host, Input, Output, Ran, SessionRequest, Stage};

/// Longest single wait on one pipe while several are being copied.
const INTERLEAVE_TICKS: u64 = 1;
/// Wait on the only pipe left (the loop only repeats on a timeout).
const ALONE_TICKS: u64 = 1000;
const KERNEL_TIMEOUT: i64 = -110;
const KERNEL_BROKEN_PIPE: i64 = -32;
/// Longest wait on the control channel between two looks at the children
/// (the children are looked at with a one-tick wait each): bounds how late
/// the shell notices a child's end. ^C wakes the wait at once.
const CONTROL_TICKS: u64 = 4;
/// How long the shell waits for sshd to take a request and answer it.
const ANSWER_TICKS: u64 = 60_000;
/// Copying rounds that moved bytes between two looks at the children and
/// the control channel.
const COPY_STREAK: u32 = 8;

pub struct Absd {
    control: Option<Control>,
    /// sshd ended the session: every child is gone and the shell exits.
    ended: bool,
}

impl Absd {
    pub fn new() -> Self {
        let control = absd_runtime::session::channel().map(|(events, requests)| Control {
            events,
            requests,
            decoder: Decoder::new(control::EVENTS),
        });
        Absd { control, ended: false }
    }
}

/// This shell's ends of its session control channel: it reads events
/// (^C, answers) and writes requests.
struct Control {
    events: u64,
    requests: u64,
    decoder: Decoder,
}

enum Heard {
    Nothing,
    Interrupt,
    Answer(u8, String),
    /// The session ended: end every command and exit.
    End,
    /// sshd closed the channel or sent something malformed.
    Gone,
}

impl Control {
    /// Waits at most `ticks` for events.
    fn listen(&mut self, ticks: u64) -> Heard {
        let mut buffer = [0u8; 256];
        match absd_runtime::read_within(self.events, &mut buffer, ticks) {
            Ok(0) => return Heard::Gone,
            Ok(count) => self.decoder.push(&buffer[..count]),
            Err(KERNEL_TIMEOUT) => {}
            Err(_) => return Heard::Gone,
        }
        let mut heard = Heard::Nothing;
        loop {
            match self.decoder.next() {
                Ok(None) => return heard,
                Ok(Some(Frame::Interrupt)) => heard = Heard::Interrupt,
                Ok(Some(Frame::End)) => return Heard::End,
                Ok(Some(Frame::Reply { status, text })) => return Heard::Answer(status, text),
                Ok(Some(_)) | Err(_) => return Heard::Gone,
            }
        }
    }

    /// Discards what waits in the channel: a ^C typed at the prompt, which
    /// is not meant for the line just read. `Nothing`, `End`, or `Gone`.
    fn discard_stale(&mut self) -> Heard {
        loop {
            match self.listen(1) {
                Heard::Interrupt | Heard::Answer(..) => {}
                other => return other,
            }
        }
    }

    fn ask(&mut self, frame: &[u8]) -> io::Result<(u8, String)> {
        let gone = || io::Error::new(io::ErrorKind::BrokenPipe, "the session control channel is closed");
        let start = absd_runtime::ticks();
        let mut left = frame;
        while !left.is_empty() {
            match absd_runtime::write_within(self.requests, left, ANSWER_TICKS) {
                Ok(count) => left = &left[count..],
                Err(KERNEL_TIMEOUT) => return Err(io::Error::new(io::ErrorKind::TimedOut, "sshd did not take the request")),
                Err(_) => return Err(gone()),
            }
        }
        // A ^C while waiting has nothing to end: it is dropped.
        while absd_runtime::ticks() < start + ANSWER_TICKS {
            match self.listen(1000) {
                Heard::Answer(status, text) => return Ok((status, text)),
                Heard::End => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "the session ended")),
                Heard::Gone => return Err(gone()),
                Heard::Nothing | Heard::Interrupt => {}
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "sshd did not answer"))
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        let _ = absd_runtime::close(self.events);
        let _ = absd_runtime::close(self.requests);
    }
}

/// A file this process opened for writing; `flush` syncs it.
pub struct Sink(File);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.sync_all()
    }
}

fn kernel_error(code: i64) -> io::Error {
    match code {
        KERNEL_BROKEN_PIPE => io::Error::new(io::ErrorKind::BrokenPipe, "pipe has no reader"),
        code => io::Error::other(format!("kernel error {code}")),
    }
}

/// Bytes on their way from a source into a child's stdin.
struct Feed {
    stage: usize,
    to: ChildStdin,
    from: Source,
    buffer: [u8; 256],
    start: usize,
    end: usize,
}

enum Source {
    Bytes(Vec<u8>, usize),
    File(File),
}

impl Source {
    fn fill(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Source::Bytes(bytes, at) => {
                let count = buffer.len().min(bytes.len() - *at);
                buffer[..count].copy_from_slice(&bytes[*at..*at + count]);
                *at += count;
                Ok(count)
            }
            Source::File(file) => file.read(buffer),
        }
    }
}

enum Pipe {
    Out(ChildStdout),
    Err(ChildStderr),
}

impl Pipe {
    fn handle(&self) -> u64 {
        match self {
            Pipe::Out(pipe) => pipe.as_raw_handle(),
            Pipe::Err(pipe) => pipe.as_raw_handle(),
        }
    }
}

/// A child's output on its way into a file.
struct Drain {
    stage: usize,
    from: Pipe,
    to: Sink,
}

enum Step {
    /// Nothing moved within the wait.
    Pending,
    /// Bytes moved.
    Moved,
    Done,
    Failed(io::Error),
}

impl Feed {
    fn step(&mut self, ticks: u64) -> Step {
        if self.start == self.end {
            match self.from.fill(&mut self.buffer) {
                // Source exhausted: dropping `to` closes the only writer
                // this process holds, so the child reads end-of-file.
                Ok(0) => return Step::Done,
                Ok(count) => (self.start, self.end) = (0, count),
                Err(error) => return Step::Failed(error),
            }
        }
        let bytes = &self.buffer[self.start..self.end];
        match absd_runtime::write_within(self.to.as_raw_handle(), bytes, ticks) {
            Ok(count) => {
                self.start += count;
                Step::Moved
            }
            Err(KERNEL_TIMEOUT) => Step::Pending,
            // The child stopped reading its input: not an error of ours.
            Err(KERNEL_BROKEN_PIPE) => Step::Done,
            Err(code) => Step::Failed(kernel_error(code)),
        }
    }
}

impl Drain {
    fn step(&mut self, ticks: u64) -> Step {
        let mut buffer = [0u8; 256];
        match absd_runtime::read_within(self.from.handle(), &mut buffer, ticks) {
            Ok(0) => match self.to.flush() {
                Ok(()) => Step::Done,
                Err(error) => Step::Failed(error),
            },
            Ok(count) => match self.to.write_all(&buffer[..count]) {
                Ok(()) => Step::Moved,
                Err(error) => Step::Failed(error),
            },
            Err(KERNEL_TIMEOUT) => Step::Pending,
            Err(code) => Step::Failed(kernel_error(code)),
        }
    }
}

/// Copies every feed and drain to its end, interleaving bounded waits so
/// that no pipe can stall another. Dropping a feed or drain closes this
/// process's end of that pipe.
fn copy_all(mut feeds: Vec<Feed>, mut drains: Vec<Drain>, ran: &mut [Ran]) {
    while !feeds.is_empty() || !drains.is_empty() {
        let ticks = if feeds.len() + drains.len() > 1 { INTERLEAVE_TICKS } else { ALONE_TICKS };
        copy_round(&mut feeds, &mut drains, ran, ticks);
    }
}

/// One step of every feed and drain, each waiting at most `ticks`.
/// Whether any of them moved bytes or finished.
fn copy_round(feeds: &mut Vec<Feed>, drains: &mut Vec<Drain>, ran: &mut [Ran], ticks: u64) -> bool {
    let mut moved = false;
    let mut index = 0;
    while index < feeds.len() {
        match feeds[index].step(ticks) {
            Step::Pending => index += 1,
            Step::Moved => {
                moved = true;
                index += 1;
            }
            Step::Done => {
                moved = true;
                drop(feeds.swap_remove(index));
            }
            Step::Failed(error) => {
                moved = true;
                let feed = feeds.swap_remove(index);
                ran[feed.stage].redirect.get_or_insert(error);
            }
        }
    }
    let mut index = 0;
    while index < drains.len() {
        match drains[index].step(ticks) {
            Step::Pending => index += 1,
            Step::Moved => {
                moved = true;
                index += 1;
            }
            Step::Done => {
                moved = true;
                drop(drains.swap_remove(index));
            }
            Step::Failed(error) => {
                moved = true;
                let drain = drains.swap_remove(index);
                ran[drain.stage].redirect.get_or_insert(error);
            }
        }
    }
    moved
}

fn exit_of(status: io::Result<std::process::ExitStatus>) -> io::Result<Exit> {
    status.map(|status| status.code().map_or(Exit::Other, Exit::Code))
}

/// Runs a started pipeline to its end under a control channel: copies,
/// timed waits on the children, and a timed read of the channel, in turn.
/// On ^C every child still running is killed and reaped
/// (`Exit::Interrupted`); what was copied into files so far is kept. On
/// `END` the same, without waiting for the files to be made durable (the
/// file server commits the session's files when sshd releases it); `true`
/// then: the session has ended.
fn supervise(
    control: &mut Option<Control>,
    children: &mut [Option<Child>],
    mut feeds: Vec<Feed>,
    mut drains: Vec<Drain>,
    ran: &mut [Ran],
) -> bool {
    let mut streak = 0;
    loop {
        if !feeds.is_empty() || !drains.is_empty() {
            // While bytes flow, several rounds of copying between looks at
            // the children and the channel (each look costs a tick).
            if copy_round(&mut feeds, &mut drains, ran, INTERLEAVE_TICKS) && streak < COPY_STREAK {
                streak += 1;
                continue;
            }
            streak = 0;
        }
        let mut running = false;
        for (result, slot) in ran.iter_mut().zip(children.iter_mut()) {
            let Some(child) = slot.as_mut() else { continue };
            match child.try_wait() {
                Ok(None) => running = true,
                Ok(Some(status)) => {
                    result.exit = exit_of(Ok(status));
                    *slot = None;
                }
                Err(error) => {
                    result.exit = Err(error);
                    *slot = None;
                }
            }
        }
        if !running && feeds.is_empty() && drains.is_empty() {
            return false;
        }
        let Some(channel) = control.as_mut() else {
            // The channel is gone (sshd ended): finish as a shell without one.
            copy_all(feeds, drains, ran);
            for (result, slot) in ran.iter_mut().zip(children.iter_mut()) {
                if let Some(mut child) = slot.take() {
                    result.exit = exit_of(child.wait());
                }
            }
            return false;
        };
        let ticks = if feeds.is_empty() && drains.is_empty() { CONTROL_TICKS } else { 1 };
        let heard = channel.listen(ticks);
        if let Heard::Interrupt | Heard::End = heard {
            // A killed child releases everything it held at once; `wait`
            // then frees its slot. It had no spawn right, so nothing of
            // its own is left behind.
            for (result, slot) in ran.iter_mut().zip(children.iter_mut()) {
                if let Some(mut child) = slot.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                    result.exit = Ok(Exit::Interrupted);
                }
            }
            // Dropping the copiers closes this shell's pipe ends; what
            // reached a file stays (on ^C made durable first).
            drop(feeds);
            if let Heard::End = heard {
                return true;
            }
            for mut drain in drains {
                let _ = drain.to.flush();
            }
            return false;
        }
        match heard {
            Heard::Gone => *control = None,
            Heard::Nothing | Heard::Answer(..) | Heard::Interrupt | Heard::End => {}
        }
    }
}

impl Host for Absd {
    type Source = File;
    type Sink = Sink;

    fn open_read(&mut self, path: &str) -> io::Result<File> {
        let file = File::open(path)?;
        if file.metadata()?.is_dir() {
            return Err(io::ErrorKind::IsADirectory.into());
        }
        Ok(file)
    }

    fn open_write(&mut self, path: &str, append: bool) -> io::Result<Sink> {
        let mut options = OpenOptions::new();
        options.create(true);
        if append {
            options.append(true);
        } else {
            options.write(true).truncate(true);
        }
        options.open(path).map(Sink)
    }

    fn run(&mut self, stages: Vec<Stage<File, Sink>>) -> Vec<Ran> {
        let mut ran: Vec<Ran> = Vec::with_capacity(stages.len());
        let mut children: Vec<Option<Child>> = Vec::with_capacity(stages.len());
        let mut feeds = Vec::new();
        let mut drains = Vec::new();
        let mut previous: Option<ChildStdout> = None;
        // While a redirection is being copied this shell uses its own
        // channel to the file server, so no child may borrow it then.
        let copying = stages.iter().any(|stage| {
            matches!(stage.stdin, Input::File(_))
                || matches!(stage.stdout, Output::File(_))
                || matches!(stage.stderr, Output::File(_))
        });
        for (index, stage) in stages.into_iter().enumerate() {
            absd_runtime::fsd::set_next_child(match stage.authority {
                Authority::Shell if copying => ChildFs::SpareOnly,
                Authority::Shell => ChildFs::Inherit,
                Authority::ReadOnly => ChildFs::ReadOnly,
                Authority::None => ChildFs::None,
            });
            let mut command = Command::new(&stage.program);
            command.args(&stage.args).current_dir(&stage.cwd);
            let feed = match stage.stdin {
                Input::Inherit => {
                    command.stdin(Stdio::inherit());
                    None
                }
                // The previous command's read end, consumed by this spawn;
                // if the previous command never started, end-of-file.
                Input::Previous => {
                    command.stdin(previous.take().map_or_else(Stdio::null, Stdio::from));
                    None
                }
                Input::Bytes(bytes) => {
                    command.stdin(Stdio::piped());
                    Some(Source::Bytes(bytes, 0))
                }
                Input::File(file) => {
                    command.stdin(Stdio::piped());
                    Some(Source::File(file))
                }
            };
            let mut sinks = [None, None];
            for (slot, output) in [stage.stdout, stage.stderr].into_iter().enumerate() {
                let stdio = match output {
                    Output::Inherit => Stdio::inherit(),
                    Output::Next => Stdio::piped(),
                    Output::File(sink) => {
                        sinks[slot] = Some(sink);
                        Stdio::piped()
                    }
                };
                if slot == 0 { command.stdout(stdio) } else { command.stderr(stdio) };
            }
            match command.spawn() {
                Ok(mut child) => {
                    if let Some(from) = feed {
                        let to = child.stdin.take().expect("piped stdin");
                        feeds.push(Feed { stage: index, to, from, buffer: [0; 256], start: 0, end: 0 });
                    }
                    let [out_sink, err_sink] = sinks;
                    match out_sink {
                        Some(to) => {
                            let from = Pipe::Out(child.stdout.take().expect("piped stdout"));
                            drains.push(Drain { stage: index, from, to });
                        }
                        None => previous = child.stdout.take(),
                    }
                    if let Some(to) = err_sink {
                        let from = Pipe::Err(child.stderr.take().expect("piped stderr"));
                        drains.push(Drain { stage: index, from, to });
                    }
                    ran.push(Ran { exit: Ok(Exit::Other), redirect: None });
                    children.push(Some(child));
                }
                // A refused spawn consumed nothing: dropping `command` here
                // closes the previous command's read end, so that command
                // gets a broken pipe rather than blocking forever.
                Err(error) => {
                    ran.push(Ran { exit: Err(error), redirect: None });
                    children.push(None);
                }
            }
        }
        drop(previous);
        if self.control.is_some() {
            self.ended |= supervise(&mut self.control, &mut children, feeds, drains, &mut ran);
            return ran;
        }
        copy_all(feeds, drains, &mut ran);
        for (result, child) in ran.iter_mut().zip(children) {
            if let Some(mut child) = child {
                result.exit = exit_of(child.wait());
            }
        }
        ran
    }

    fn is_dir(&mut self, path: &str) -> io::Result<bool> {
        std::fs::metadata(path).map(|m| m.is_dir())
    }

    fn session_request(&mut self, request: SessionRequest) -> io::Result<(i32, String)> {
        let Some(channel) = self.control.as_mut() else { return Err(io::ErrorKind::Unsupported.into()) };
        let frame = match request {
            SessionRequest::Machine(words) => control::encode(control::MACHINE, words.as_bytes()),
            SessionRequest::List => control::encode(control::LIST, b""),
        };
        match channel.ask(&frame) {
            Ok((status, text)) => Ok((i32::from(status), text)),
            Err(error) => {
                match error.kind() {
                    io::ErrorKind::BrokenPipe => self.control = None,
                    io::ErrorKind::ConnectionAborted => self.ended = true,
                    _ => {}
                }
                Err(error)
            }
        }
    }

    fn line_read(&mut self) {
        if let Some(channel) = self.control.as_mut() {
            match channel.discard_stale() {
                Heard::End => self.ended = true,
                Heard::Gone => self.control = None,
                _ => {}
            }
        }
    }

    fn ended(&self) -> bool {
        self.ended
    }
}
