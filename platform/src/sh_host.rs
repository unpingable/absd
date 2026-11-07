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
//! tick) with a control check. Progressing copies inspect channel readiness;
//! otherwise the check uses a timed read ([`CONTROL_TICKS`]). On
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
    paste_records: bool,
    plain_recovery: bool,
    plain_refused: bool,
    pause_confirmed: bool,
}

impl Absd {
    pub fn new() -> Self {
        let control = absd_runtime::session::channel().map(|(events, requests)| Control {
            events,
            requests,
            decoder: Decoder::new(control::EVENTS),
            prompt_cancelled: false,
        });
        Absd { control, ended: false, paste_records: false, plain_recovery: false, plain_refused: false, pause_confirmed: false }
    }

    /// Wait on control, never on a stdin pipe whose producer is paused.
    fn wait_plain_cancel(&mut self) -> bool {
        let Some(channel) = self.control.as_mut() else { self.ended = true; return true; };
        channel.prompt_cancelled = false;
        loop {
            match channel.listen(1) {
                Heard::Nothing => {},
                Heard::Interrupt => {
                    channel.prompt_cancelled = false;
                    self.plain_refused = false;
                    return true;
                }
                Heard::End | Heard::Gone | Heard::Answer(..) => {
                    self.ended = true;
                    return true;
                }
            }
        }
    }
}

/// This shell's ends of its session control channel: it reads events
/// (^C, answers) and writes requests.
struct Control {
    events: u64,
    requests: u64,
    decoder: Decoder,
    prompt_cancelled: bool,
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
    /// The shell is the sole reader of this event pipe. Ready bytes cannot
    /// be consumed by a competing reader between the query and the read.
    /// An event arriving just after an empty snapshot waits until the next
    /// bounded supervision turn. Decoder-buffered frames still need service.
    fn poll(&mut self) -> Heard {
        match absd_runtime::fsd::pipe_info(self.events) {
            Ok([0, _, _, writers]) if writers > 0 => self.decode(),
            Ok(_) => self.listen(1), // ready bytes or EOF; neither needs a wait
            Err(_) => Heard::Gone,
        }
    }

    /// Uses the existing timed read with a `ticks` timeout.
    fn listen(&mut self, ticks: u64) -> Heard {
        let mut buffer = [0u8; 256];
        match absd_runtime::read_within(self.events, &mut buffer, ticks) {
            Ok(0) => return Heard::Gone,
            Ok(count) => self.decoder.push(&buffer[..count]),
            Err(KERNEL_TIMEOUT) => {}
            Err(_) => return Heard::Gone,
        }
        self.decode()
    }

    fn decode(&mut self) -> Heard {
        let mut heard = Heard::Nothing;
        loop {
            match self.decoder.next() {
                Ok(None) => return heard,
                Ok(Some(Frame::Interrupt)) => {
                    self.prompt_cancelled = true;
                    heard = Heard::Interrupt;
                },
                Ok(Some(Frame::End)) => return Heard::End,
                Ok(Some(Frame::Reply { status, text })) => return Heard::Answer(status, text),
                Ok(Some(_)) | Err(_) => return Heard::Gone,
            }
        }
    }

    /// Consume available control frames, retaining interruption for the
    /// interactive loop. Return `Nothing`, `End`, or `Gone`.
    fn drain_events(&mut self) -> Heard {
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
        // The request completes, while interrupts remain latched for the
        // interactive loop to cancel input before any command effect.
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

#[path = "sh_drain.rs"]
mod sh_drain;
use sh_drain::{BufferedFile, Step, Target};

struct FileBacking(File);
impl Write for FileBacking {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.0.write(bytes) }
    fn flush(&mut self) -> io::Result<()> { self.0.sync_all() }
}
/// One buffer per actual file endpoint, inside the shell's SharedSink.
/// Write::flush keeps its existing durability meaning.
pub struct Sink(BufferedFile<FileBacking, fn() -> u64>);
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.0.write(bytes) }
    fn flush(&mut self) -> io::Result<()> { self.0.flush() }
}
enum DrainTarget {
    File(crate::shell::SharedSink<Sink>),
    Immediate(Box<dyn Write>),
}
impl Write for DrainTarget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self { Self::File(w) => w.write(bytes), Self::Immediate(w) => w.write(bytes) }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self { Self::File(w) => w.flush(), Self::Immediate(w) => w.flush() }
    }
}
impl Target for DrainTarget {
    fn flush_pending(&mut self, force: bool) -> io::Result<bool> {
        match self { Self::File(w) => w.with_mut(|w| w.0.flush_pending(force)), Self::Immediate(_) => Ok(false) }
    }
    fn wait_limit(&self, ticks: u64) -> u64 {
        match self { Self::File(w) => w.with_mut(|w| w.0.wait_limit(ticks)), Self::Immediate(_) => ticks }
    }
    fn finish(&mut self, durable: bool) -> io::Result<()> {
        self.flush_pending(true)?;
        if durable { self.flush() } else { Ok(()) }
    }
}

fn kernel_error(code: i64) -> io::Error {
    match code {
        KERNEL_BROKEN_PIPE => io::Error::new(io::ErrorKind::BrokenPipe, "pipe has no reader"),
        code => io::Error::other(format!("kernel error {code}")),
    }
}

/// Refill file input in 4 KiB reads; each step still offers at most 256
/// bytes to the pipe so other streams and session control get their turn.
struct Feed {
    stage: usize,
    to: ChildStdin,
    from: Source,
    buffer: [u8; 4096],
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

type Drain = sh_drain::Drain<Pipe, DrainTarget>;

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
        let end = self.end.min(self.start + 256);
        let bytes = &self.buffer[self.start..end];
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
        match drains[index].step(ticks, |from, buffer, wait| {
            match absd_runtime::read_within(from.handle(), buffer, wait) {
                Ok(n) => Ok(Some(n)),
                Err(KERNEL_TIMEOUT) => Ok(None),
                Err(code) => Err(kernel_error(code)),
            }
        }) {
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
/// timed waits on the children, and a control-channel check, in turn.
/// On ^C every child still running is killed and reaped
/// (`Exit::Interrupted`); what was copied into files so far is kept. On
/// `END` the same, flushing accepted bytes without an extra explicit sync
/// (the destination's existing close semantics still apply); `true`
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
        let mut copied = false;
        if !feeds.is_empty() || !drains.is_empty() {
            // While bytes flow, several rounds of copying between looks at
            // the children and the channel. Keep the same observation cadence
            // without paying an empty control timeout after a successful copy.
            copied = copy_round(&mut feeds, &mut drains, ran, INTERLEAVE_TICKS);
            if copied && streak < COPY_STREAK {
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
            // This shell started without a session channel. Managed control loss
            // is handled below as END before another round can run.
            copy_all(feeds, drains, ran);
            for (result, slot) in ran.iter_mut().zip(children.iter_mut()) {
                if let Some(mut child) = slot.take() {
                    result.exit = exit_of(child.wait());
                }
            }
            return false;
        };
        let ticks = if feeds.is_empty() && drains.is_empty() { CONTROL_TICKS } else { 1 };
        let heard = if copied { channel.poll() } else { channel.listen(ticks) };
        if let Heard::Interrupt | Heard::End | Heard::Gone = heard {
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
            // was accepted into shared file buffers is written (on ^C synced
            // too). A terminal flush error remains a redirection failure.
            drop(feeds);
            let ending = matches!(heard, Heard::End | Heard::Gone);
            for mut drain in drains {
                if let Err(error) = drain.finish(!ending) { ran[drain.stage].redirect.get_or_insert(error); }
            }
            return ending;
        }
    }
}

impl Host for Absd {
    fn prompt_cancelled(&mut self) -> bool {
        if self.plain_refused {
            // The producer can confirm cancellation that already arrived in
            // the refusal batch. Otherwise this is still a discard, not EOF.
            self.prompt_input(0);
            if self.ended { return true; }
            if self.pause_confirmed {
                if let Some(channel) = self.control.as_mut() { channel.prompt_cancelled = false; }
                return true;
            }
            return self.wait_plain_cancel();
        }
        self.control.as_mut().is_some_and(|channel| std::mem::take(&mut channel.prompt_cancelled))
    }

    fn terminal_size(&self) -> Option<(u32, u32)> {
        absd_runtime::terminal::size().map(|s| (s.columns, s.rows))
    }

    fn prompt_input(&mut self, mode: u8) {
        self.pause_confirmed = false;
        if let Some(channel) = self.control.as_mut() {
            // Serialize this with all other shell requests. Commands never
            // receive these pipe ends, so an application cannot race replies.
            match channel.ask(&control::encode(control::INPUT_MODE, &[mode])) {
                Ok((status @ (0 | control::INPUT_REFUSED | control::INPUT_PAUSED), capability)) => {
                    self.paste_records = capability == "paste-record-v2";
                    self.plain_recovery = capability == "plain-discard-v1";
                    self.plain_refused = self.plain_recovery && status == control::INPUT_REFUSED;
                    self.pause_confirmed = matches!(mode, 0 | 4) && status == control::INPUT_PAUSED;
                },
                _ => self.ended = true,
            }
        }
    }

    fn input_limit_notice(&self) -> &'static str {
        if self.plain_recovery {
            "absd-sh: input exceeds 1 MiB; command discarded; press Ctrl-C to recover"
        } else {
            "absd-sh: input exceeds 1 MiB"
        }
    }

    fn refuse_interactive_input(&mut self) -> bool {
        if self.plain_recovery {
            self.prompt_input(4);
            if self.ended || !self.pause_confirmed { return false; }
            // Its reply follows the producer's new discard fence.
            return self.wait_plain_cancel();
        }
        if !self.paste_records { return false; }
        self.prompt_input(4);
        !self.ended
    }

    fn discard_pending_input(&mut self) {
        if self.ended || self.control.is_none() { return; }
        // A cancelled session's mode-0 reply fences the producer pause.
        // No later stdin write can race the drain until the next prompt.
        self.prompt_input(0);
        if self.ended || !self.pause_confirmed { return; }
        let (input, _) = absd_runtime::standard_stream_handles();
        if input == 0 { return; }
        let mut bytes = [0u8; 256];
        for _ in 0..=4096 {
            match absd_runtime::read_within(input, &mut bytes, 1) {
                Ok(0) | Err(KERNEL_TIMEOUT) => return,
                Ok(_) => {},
                Err(_) => { self.ended = true; return; },
            }
        }
        // Keep the producer quarantined if the acknowledged pipe contract
        // was exceeded. Do not label a partial drain successful.
        self.prompt_input(4);
    }

    fn interrupted(&mut self) -> bool {
        let Some(channel) = &mut self.control else { return false; };
        match channel.listen(1) {
            Heard::Interrupt => true,
            Heard::End | Heard::Gone => { self.ended = true; true },
            _ => channel.prompt_cancelled,
        }
    }

    fn read_interactive(&mut self, input: &mut dyn io::BufRead, text: &mut String) -> io::Result<usize> {
        if self.paste_records { crate::shell::read_interactive_record(input, text) }
        else { crate::shell::read_interactive_plain(input, text) }
    }

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
        options.open(path).map(|file| Sink(BufferedFile::new(FileBacking(file), absd_runtime::ticks as fn() -> u64)))
    }

    fn run(&mut self, stages: Vec<Stage<File, Sink>>) -> Vec<Ran> {
        let mut ran: Vec<Ran> = Vec::with_capacity(stages.len());
        let mut children: Vec<Option<Child>> = Vec::with_capacity(stages.len());
        let mut feeds = Vec::new();
        let mut drains = Vec::new();
        let mut previous: Option<Stdio> = None;
        // While a redirection is being copied this shell uses its own
        // channel to the file server, so no child may borrow it then.
        let copying = stages.iter().any(Stage::copies_files);
        for (index, stage) in stages.into_iter().enumerate() {
            absd_runtime::fsd::set_next_child(match stage.authority {
                Authority::Shell if copying => ChildFs::SpareOnly,
                Authority::Shell => ChildFs::Inherit,
                Authority::ReadOnly => ChildFs::ReadOnly,
                Authority::None => ChildFs::None,
            });
            let mut command = Command::new(&stage.program);
            command.args(&stage.args).current_dir(&stage.cwd).env_clear().envs(stage.env);
            if let Some(size) = absd_runtime::terminal::size() {
                if size.columns > 0 { command.env("COLUMNS", size.columns.to_string()); } else { command.env_remove("COLUMNS"); }
                if size.rows > 0 { command.env("LINES", size.rows.to_string()); } else { command.env_remove("LINES"); }
            }
            let feed = match stage.stdin {
                Input::Inherit => {
                    command.stdin(Stdio::inherit());
                    None
                }
                // The previous command's read end, consumed by this spawn;
                // if the previous command never started, end-of-file.
                Input::Previous => {
                    command.stdin(previous.take().unwrap_or_else(Stdio::null));
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
            let merged = matches!(stage.stderr, Output::SameAsStdout);
            let direct = match &stage.stdout {
                Output::Inherit | Output::ParentStdout => Some(0),
                Output::ParentStderr => Some(1),
                _ => None,
            };
            let merge_pipe = merged && direct.is_none();
            let mut next = [false, false];
            let mut sinks: [Option<DrainTarget>; 2] = [None, None];
            for (slot, output) in [stage.stdout, stage.stderr].into_iter().enumerate() {
                let stdio = match output {
                    Output::Inherit => Stdio::inherit(),
                    Output::ParentStdout => Stdio::from(io::stdout()),
                    Output::ParentStderr => Stdio::from(io::stderr()),
                    Output::SameAsStdout => match direct {
                        Some(0) => Stdio::from(io::stdout()),
                        Some(_) => Stdio::from(io::stderr()),
                        None => Stdio::piped(),
                    },
                    Output::Next => { next[slot] = true; Stdio::piped() },
                    Output::Discard => { sinks[slot] = Some(DrainTarget::Immediate(Box::new(io::sink()))); Stdio::piped() },
                    Output::Shared(sink) => { sinks[slot] = Some(DrainTarget::File(sink)); Stdio::piped() },
                    Output::Capture(capture) => { sinks[slot] = Some(DrainTarget::Immediate(Box::new(capture))); Stdio::piped() },
                };
                if slot == 0 { command.stdout(stdio) } else { command.stderr(stdio) };
            }
            // Existing per-process spawn policy, scoped to this single spawn.
            // Clearing before handling either result also covers refused starts.
            absd_runtime::process::merge_output_for_children(merge_pipe);
            let spawned = command.spawn();
            absd_runtime::process::merge_output_for_children(false);
            match spawned {
                Ok(mut child) => {
                    if let Some(from) = feed {
                        let to = child.stdin.take().expect("piped stdin");
                        feeds.push(Feed { stage: index, to, from, buffer: [0; 4096], start: 0, end: 0 });
                    }
                    let [out_sink, err_sink] = sinks;
                    match out_sink {
                        Some(to) => {
                            let from = Pipe::Out(child.stdout.take().expect("piped stdout"));
                            drains.push(Drain::new(index, from, to));
                        }
                        None if next[0] => previous = child.stdout.take().map(Stdio::from),
                        None => {},
                    }
                    if let Some(to) = err_sink {
                        let from = Pipe::Err(child.stderr.take().expect("piped stderr"));
                        drains.push(Drain::new(index, from, to));
                    } else if next[1] {
                        previous = child.stderr.take().map(Stdio::from);
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
            SessionRequest::Clock(words) => control::encode(control::CLOCK, words.as_bytes()),
            SessionRequest::List => control::encode(control::LIST, b""),
        };
        match channel.ask(&frame) {
            Ok((status, text)) => Ok((i32::from(status), text)),
            Err(error) => {
                match error.kind() {
                    io::ErrorKind::BrokenPipe => self.ended = true,
                    io::ErrorKind::ConnectionAborted => self.ended = true,
                    _ => {}
                }
                Err(error)
            }
        }
    }

    fn line_read(&mut self) {
        if let Some(channel) = self.control.as_mut() {
            match channel.drain_events() {
                Heard::End => self.ended = true,
                Heard::Gone => self.ended = true,
                _ => {}
            }
        }
    }

    fn ended(&self) -> bool {
        self.ended
    }
}
