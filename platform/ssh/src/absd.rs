//! ABSD backend: one process holding the NIC (its TCP/IP stack is
//! `absd-net`, smoltcp over the kernel's frame calls, linked in), the
//! file server's control channel and its pool of client slots, and the
//! spawn right, which it spends only on session children. It holds no
//! block handle: the file server (`absd-fsd`, `src/fsd_main.rs`) is the
//! only process with one (kernel `docs/PROCESS-STARTUP.md`, "File server").
//!
//! Start-up order:
//!
//! 1. Entropy: `getrandom` (RDRAND backend) must accept the CPU and two
//!    draws must differ, or sshd refuses to start.
//! 2. Host key: read once, through the control channel, which sees `/ssh`
//!    and `/bin` read-only; the file server created it if it was absent.
//!    sshd keeps it in memory. No session's binding includes `/ssh`.
//! 3. Serve: listen on TCP 22; per connection a sunset runner; per session
//!    a child started from the filesystem by `std::process` with three
//!    pipes and one client slot sshd bound to the session's mounts
//!    (`/home/operator` and the session's own `/tmp/session-N` read-write,
//!    `/bin`, `/etc`, `/share`, and `/var/log` read-only); a shell also gets up to two spare
//!    slots, each a channel of its own for a child it starts (with the
//!    shell's authority or less). Every child that keeps the spawn right
//!    (a shell: interactive, or running an `exec` text with shell syntax)
//!    also gets a session control channel (`control.rs`, startup roles 16
//!    and 17): sshd tells it of ^C there, answers its `ps`, `shutdown`, and
//!    `reboot`, and tells it when the session ends. The shell starts its
//!    commands without the spawn right, so they have no children: sshd
//!    holds a kill right on the shell, the shell on each command.
//!    Ending a session (client gone, idle timeout, shutdown grace over) is
//!    `END` on that channel first: the shell kills and reaps its commands
//!    and exits; sshd reads and drops its output meanwhile and kills it
//!    only if it has not exited `END_GRACE` after reading `END`, or has
//!    not read it within `END_UNREAD_LIMIT` (`SSH SESSION END ...
//!    forced=true`: its commands can then outlive the session). A child
//!    without the channel (an `exec` program, no spawn right) is killed at
//!    once.
//!    When the child has ended, sshd releases the slot: whatever it started loses the
//!    session's authority at once, and the file server binds the slot
//!    again only once no process but sshd holds its client ends.
//! 4. Shut down, on the operator's request (an `exec` of `shutdown` or
//!    `reboot`, `conn::machine_request`): stop listening, tell every
//!    session and close its child's stdin, wait `SHUTDOWN_GRACE` for the
//!    children to finish and their sessions to close as usual, then end
//!    what is left as above (`END`, then the same bounds); once every
//!    session's child is gone, release every slot (the file server commits each
//!    released session's files); exit 0 for a halt or
//!    `SERVED_WORKER_RESTART_STATUS` for a restart. The exit closes the
//!    control channel: the file server commits and stops, and init, which
//!    holds the machine handle, ends the boot. sshd holds no machine right.

use std::cell::RefCell;
use std::io;
use std::os::absd::process::AsRawHandle;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::rc::Rc;
use std::time::{Duration, Instant};

use absd_fsd::proto::{Frame, Mount, op, status};
use absd_runtime::fsd::{self as fsd_client, ChildFs};

use absd_net::{Connection as TcpConn, Listener, NetError, NicLink, Stack};

use crate::Config;
use crate::conn::{
    self, Connection, ControlRequest, Exit, Identity, MachineRequest, SessionChild, Spawner,
};
use crate::control::{self, Decoder, Frame as ControlFrame};
use crate::etc;
use crate::keys;

/// Set once the control channel has answered: from then on sshd's
/// refusals also reach the console (the file server's `NOTICE`) and its
/// log file.
static CONSOLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The recovery streak the file server charged for this generation
/// (absd_fsd::recovery): read through the control channel (read-only
/// there), checked, and required to name this boot.
fn recovery_streak(boot: &absd_fsd::recovery::Boot) -> Result<u64, String> {
    let path = std::str::from_utf8(absd_fsd::recovery::LEDGER).expect("ascii path");
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let ledger = absd_fsd::recovery::parse_ledger(&bytes)
        .ok_or_else(|| format!("{path}: unparsable or failed its check"))?;
    if ledger.boot != *boot {
        return Err(format!("{path}: charged for another boot"));
    }
    Ok(ledger.streak)
}

/// Overwrites one recovery fact (a fixed-size file the file server made)
/// in place and commits it before returning: nothing is advertised on a
/// fact that is not durable, and nothing is allocated.
fn write_fact(path: &[u8], boot: &absd_fsd::recovery::Boot, action: Option<&str>) -> io::Result<()> {
    use std::io::Write as _;
    let path = std::str::from_utf8(path).expect("ascii path");
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(&absd_fsd::recovery::format_fact(boot, action))?;
    file.sync_all()
}

fn fatal(message: &str) -> ! {
    if CONSOLE.load(std::sync::atomic::Ordering::Relaxed) {
        crate::oplog::notice(&format!("sshd: {message}; sshd is not running"));
        crate::oplog::flush();
    } else {
        say!("sshd: {message}");
    }
    std::process::exit(1);
}

/// Reads one configuration file: its settings, or `None` when it does not
/// exist. Any other failure, or a malformed file, refuses the start.
fn configuration<T>(path: &str, parse: fn(&[u8]) -> Result<T, String>) -> Option<T> {
    match std::fs::read(path) {
        Ok(text) => Some(parse(&text).unwrap_or_else(|e| {
            fatal(&format!(
                "{path}: {e}; fix the file (network.conf(5), sshd.conf(5), afterboot(8))"
            ))
        })),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => fatal(&format!("{path}: {error}")),
    }
}

/// The entropy sshd uses for its host key and, through sunset, for every
/// key exchange: `getrandom`'s RDRAND backend, which refuses unless CPUID
/// reports RDRAND and a self-test of the instruction passes.
fn entropy() -> io::Result<()> {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    getrandom::fill(&mut a).map_err(|e| io::Error::other(format!("{e}")))?;
    getrandom::fill(&mut b).map_err(|e| io::Error::other(format!("{e}")))?;
    if a == b || a == [0; 32] {
        return Err(io::Error::other("entropy draws repeat"));
    }
    Ok(())
}

/// One tick: the shortest bounded wait the kernel's `transfer` makes.
const PIPE_WAIT_TICKS: u64 = 1;
const ERROR_TIMEOUT: i64 = -110;

pub struct AbsdChild {
    /// `None` once handed to the session ender (`Ending`).
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    /// Reaped (its exit seen, or killed and waited), or being ended.
    ended: bool,
    /// The shell's session control channel (sshd's ends).
    control: Option<Control>,
    pid: u32,
    program: String,
    /// Held for its `Drop`, which releases the session's slots after this
    /// child is gone (fields drop after `AbsdChild::drop` runs); moved to
    /// the `Ending` when the child is ended through its shell.
    binding: Option<Binding>,
}

/// How long a shell gets, once it has read `END`, to kill and reap its
/// commands and exit, before sshd kills it (which would leave its commands
/// to init). Killing and reaping are kernel calls; what else the shell does
/// then (closing a redirection's file) is one file server request.
const END_GRACE: Duration = Duration::from_millis(1000);

/// How long a shell that has not yet read `END` is waited for. It reads the
/// channel between its own steps; the steps that do not look at it are a
/// program load or a file server request (a redirection's copy, an open),
/// which end when the file server serves them, and a busy file server can
/// take seconds. Only a shell that has not read `END` in this long is
/// killed unread: the same bound sshd gives sessions after a shutdown
/// request, so the time a session end takes is bounded, and a kill before
/// it is never the result of the file server being busy.
const END_UNREAD_LIMIT: Duration = SHUTDOWN_GRACE;

/// A session child told `END`, until it has exited (or sshd killed it:
/// `END_GRACE` after it read `END`, or `END_UNREAD_LIMIT` if it never
/// did). Then its slots are released.
struct Ending {
    child: Child,
    control: Control,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    pid: u32,
    since: Instant,
    /// The whole `END` frame is in the events pipe.
    sent: bool,
    /// When the events pipe was first seen empty after `sent`: the shell
    /// has read `END` (and whatever preceded it).
    read: Option<Instant>,
    _binding: Option<Binding>,
}

thread_local! {
    /// Sessions being ended, driven by the main loop (`drive_endings`).
    static ENDING: RefCell<Vec<Ending>> = const { RefCell::new(Vec::new()) };
}

impl Ending {
    /// One look: `END` out, output read and dropped (a shell blocked on a
    /// full output pipe could not act), exit seen. `true` once done.
    fn step(&mut self, now: Instant) -> bool {
        if !self.sent {
            match self.control.flush() {
                Ok(_) => self.sent = self.control.out.is_empty(),
                // The shell's end is gone: it has exited or is exiting.
                Err(_) => self.sent = true,
            }
        }
        let mut buf = [0u8; 1024];
        for _ in 0..8 {
            let out = read_pipe(&mut self.stdout, &mut buf);
            let err = read_pipe(&mut self.stderr, &mut buf);
            if !matches!(out, Ok(Some(n)) if n > 0) && !matches!(err, Ok(Some(n)) if n > 0) {
                break;
            }
        }
        if self.sent && self.read.is_none() && self.control.unread() == Some(0) {
            self.read = Some(now);
        }
        let took = now.saturating_duration_since(self.since).as_millis();
        // `read=` is how long the shell took to read `END` (-1: not seen,
        // as when it exited on its input's end alone).
        let read = self.read.map_or(-1, |at| {
            at.saturating_duration_since(self.since).as_millis() as i64
        });
        let expired = match self.read {
            Some(at) => now >= at + END_GRACE,
            None => now >= self.since + END_UNREAD_LIMIT,
        };
        match self.child.try_wait() {
            Ok(None) if !expired => false,
            Ok(None) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                say!(
                    "SSH SESSION END pid={} sent={} exited=false forced=true ms={took} read={read}",
                    self.pid,
                    u8::from(self.sent)
                );
                true
            }
            Ok(Some(_)) | Err(_) => {
                say!(
                    "SSH SESSION END pid={} sent={} exited=true forced=false ms={took} read={read}",
                    self.pid,
                    u8::from(self.sent)
                );
                true
            }
        }
    }
}

/// Drives every session being ended. Whether any still is.
fn drive_endings(now: Instant) -> bool {
    ENDING.with(|list| {
        let mut list = list.borrow_mut();
        list.retain_mut(|ending| !ending.step(now));
        !list.is_empty()
    })
}

/// How often an idle control channel is looked at for a request (each
/// look is a one-tick timed read).
const CONTROL_LOOK: Duration = Duration::from_millis(10);

/// sshd's ends of a session control channel (`control.rs`): it writes
/// events, reads requests. Created before the shell starts, since a handle
/// reaches a process only when it is spawned.
struct Control {
    events: u64,
    requests: u64,
    decoder: Decoder,
    /// Framed bytes not yet taken by the events pipe.
    out: Vec<u8>,
    /// A ^C not yet framed (several unsent ones are one: the shell only
    /// needs to know that one came).
    interrupt: bool,
    next_look: Instant,
}

impl Control {
    fn new((events, requests): (u64, u64)) -> Self {
        Control {
            events,
            requests,
            decoder: Decoder::new(control::REQUESTS),
            out: Vec::new(),
            interrupt: false,
            next_look: Instant::now(),
        }
    }

    /// Bytes in the events pipe the shell has not read yet.
    fn unread(&self) -> Option<u64> {
        fsd_client::pipe_info(self.events)
            .ok()
            .map(|[available, ..]| available)
    }

    /// Moves queued events into the pipe as far as it takes them. `Err`
    /// once the shell's end is gone.
    fn flush(&mut self) -> Result<bool, i64> {
        if self.out.is_empty() && std::mem::take(&mut self.interrupt) {
            self.out = control::interrupt();
        }
        let mut moved = false;
        while !self.out.is_empty() {
            match absd_runtime::write_within(self.events, &self.out, PIPE_WAIT_TICKS) {
                Ok(n) => {
                    self.out.drain(..n);
                    moved = true;
                }
                Err(ERROR_TIMEOUT) => break,
                Err(code) => return Err(code),
            }
            if self.out.is_empty() && std::mem::take(&mut self.interrupt) {
                self.out = control::interrupt();
            }
        }
        Ok(moved)
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        let _ = absd_runtime::close(self.events);
        let _ = absd_runtime::close(self.requests);
    }
}

/// The file server slots (channel numbers; 0 is the control channel) one
/// session holds. Released when the session's child has ended.
struct Binding {
    pool: Rc<RefCell<Pool>>,
    slots: Vec<usize>,
}

impl Drop for Binding {
    fn drop(&mut self) {
        let Some(&primary) = self.slots.first() else {
            return;
        };
        let frame = Frame::request(op::RELEASE).u8(primary as u8).finish();
        match fsd_client::request_on(0, frame) {
            Ok((closed, _)) if closed >= 0 => {
                say!(
                    "SSH FS RELEASE slot={primary} spares={:?} closed={closed}",
                    &self.slots[1..]
                )
            }
            other => {
                // The file server may still hold the old binding. Reusing
                // this channel would assign its authority to a new session.
                // A direct stderr marker avoids a recursive FSD log request.
                eprintln!(
                    "SERVED SERVICE FAULT component=sshd reason=fsd-release slot={primary} result={other:?}"
                );
                std::process::exit(1);
            }
        }
        let mut pool = self.pool.borrow_mut();
        for slot in &self.slots {
            pool.busy[*slot] = false;
        }
        pool.sessions -= 1;
    }
}

/// Which of the file server's client slots a session holds now.
struct Pool {
    /// Indexed by channel number; channel 0 (control) is never a slot.
    busy: Vec<bool>,
    /// Sessions holding a binding now.
    sessions: usize,
    /// Most sessions at once (sshd's connection limit).
    max_sessions: usize,
}

impl Pool {
    fn free(&self) -> Vec<usize> {
        (1..self.busy.len())
            .filter(|&slot| !self.busy[slot])
            .collect()
    }
    /// Free slots kept back from a new binding's spares: a slot and one
    /// spare for every further session sshd may still accept, so a later
    /// shell can still run a pipeline, a redirected command, or `ro`.
    fn reserve(&self) -> usize {
        2 * self.max_sessions.saturating_sub(self.sessions + 1)
    }
}

/// What a session may see and change: the ceiling every process it starts
/// derives its own authority from.
fn session_mounts(id: u64) -> Vec<Mount> {
    vec![
        Mount::new(b"/home/operator", true),
        Mount::new(format!("/tmp/session-{id}").as_bytes(), true),
        Mount::new(b"/bin", false),
        Mount::new(b"/etc", false),
        // The manual (man(1)): rendered pages, read-only like /bin.
        Mount::new(b"/share", false),
        // The file server's and sshd's logs, written only by them.
        Mount::new(absd_fsd::log::DIR, false),
    ]
}

/// Binds a free slot (and, for a shell, spares) to a session's mounts.
/// A slot some earlier session's processes still hold is refused by the
/// server (busy) and skipped.
fn bind(pool: &Rc<RefCell<Pool>>, mounts: &[Mount], spares_wanted: usize) -> io::Result<Binding> {
    let (free, reserve) = {
        let pool = pool.borrow();
        (pool.free(), pool.reserve())
    };
    for (at, &primary) in free.iter().enumerate() {
        // Spares only while the reserve stays free for later sessions.
        let after = &free[at + 1..];
        let spares: Vec<usize> = after
            .iter()
            .copied()
            .take(spares_wanted.min(after.len().saturating_sub(reserve)))
            .collect();
        for &slot in std::iter::once(&primary).chain(&spares) {
            // A reply an earlier holder never read would reach the next.
            let _ = fsd_client::drain_reply(slot);
        }
        let mut frame = Frame::request(op::BIND)
            .u8(primary as u8)
            .u8(spares.len() as u8);
        for spare in &spares {
            frame = frame.u8(*spare as u8);
        }
        match fsd_client::request_on(0, frame.mounts(mounts).finish()) {
            Ok((0, _)) => {
                let mut claimed = pool.borrow_mut();
                let mut slots = vec![primary];
                slots.extend(&spares);
                for slot in &slots {
                    claimed.busy[*slot] = true;
                }
                claimed.sessions += 1;
                return Ok(Binding {
                    pool: pool.clone(),
                    slots,
                });
            }
            Ok((status::BUSY, _)) => continue,
            Ok((code, _)) => {
                return Err(io::Error::other(format!(
                    "file server refused the binding: {code}"
                )));
            }
            Err(code) => {
                return Err(io::Error::other(format!(
                    "file server control channel: {code}"
                )));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::ResourceBusy,
        "no free file server slot",
    ))
}

fn read_pipe<P: AsRawHandle>(pipe: &mut Option<P>, buf: &mut [u8]) -> io::Result<Option<usize>> {
    let Some(p) = pipe.as_ref() else {
        return Ok(Some(0));
    };
    match absd_runtime::read_within(p.as_raw_handle(), buf, PIPE_WAIT_TICKS) {
        Ok(0) => {
            *pipe = None;
            Ok(Some(0))
        }
        Ok(n) => Ok(Some(n)),
        Err(ERROR_TIMEOUT) => Ok(None),
        Err(code) => {
            *pipe = None;
            Err(io::Error::other(format!("pipe read {code}")))
        }
    }
}

impl SessionChild for AbsdChild {
    fn read_stdout(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        read_pipe(&mut self.stdout, buf)
    }
    fn read_stderr(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        read_pipe(&mut self.stderr, buf)
    }
    fn write_stdin(&mut self, buf: &[u8]) -> io::Result<Option<usize>> {
        let Some(p) = self.stdin.as_ref() else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        match absd_runtime::write_within(p.as_raw_handle(), buf, PIPE_WAIT_TICKS) {
            Ok(n) => Ok(Some(n)),
            Err(ERROR_TIMEOUT) => Ok(None),
            Err(code) => Err(io::Error::other(format!("pipe write {code}"))),
        }
    }
    fn close_stdin(&mut self) {
        self.stdin = None;
    }
    fn try_wait(&mut self) -> io::Result<Option<Exit>> {
        let Some(child) = self.child.as_mut() else {
            return Ok(Some(Exit::Abnormal));
        };
        let status = child.try_wait()?;
        self.ended |= status.is_some();
        Ok(status.map(|status| match status.code() {
            Some(code) => Exit::Code(code as u32),
            None => Exit::Abnormal,
        }))
    }
    fn terminate(&mut self) {
        if self.ended {
            return;
        }
        self.ended = true;
        let Some(mut child) = self.child.take() else {
            return;
        };
        // Its input ends too: a shell at its prompt exits on that alone.
        self.stdin = None;
        match self.control.take() {
            Some(mut control) => {
                control.out.extend(control::end());
                let mut ending = Ending {
                    child,
                    control,
                    stdout: self.stdout.take(),
                    stderr: self.stderr.take(),
                    pid: self.pid,
                    since: Instant::now(),
                    sent: false,
                    read: None,
                    _binding: self.binding.take(),
                };
                if !ending.step(Instant::now()) {
                    ENDING.with(|list| list.borrow_mut().push(ending));
                }
            }
            // No control channel: an `exec` program without the spawn
            // right, which has no children; it ends now.
            None => {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    fn interrupt(&mut self) -> bool {
        let Some(control) = self.control.as_mut() else {
            return false;
        };
        control.interrupt = true;
        self.pump_control();
        true
    }
    fn pump_control(&mut self) -> bool {
        let Some(control) = self.control.as_mut() else {
            return false;
        };
        match control.flush() {
            Ok(moved) => moved,
            Err(code) => {
                say!("sshd: session control events pipe: {code}; channel closed");
                self.control = None;
                true
            }
        }
    }
    fn control_request(&mut self, now: Instant) -> Result<Option<ControlRequest>, String> {
        match self.read_request(now) {
            Ok(request) => Ok(request),
            Err(reason) => self.control_ended(reason),
        }
    }
    fn control_reply(&mut self, status: u8, text: &str) {
        if let Some(control) = self.control.as_mut() {
            control.out.extend(control::reply(status, text));
        }
        self.pump_control();
    }
    fn describe(&mut self) -> String {
        // Named: the one process of this session sshd holds a handle to.
        // The shell starts its commands itself, in the foreground only, so
        // while it asks it has none running.
        let mut text = format!("  PID PROGRAM\n{:>5} {}\n", self.pid, self.program);
        // Counted: whoever else holds this session's input or its file
        // server channels (an interrupted or disconnected command's own
        // children, which init adopted), from the kernel's handle counts
        // on the ends sshd holds. sshd cannot name them.
        let input = self
            .stdin
            .as_ref()
            .and_then(|pipe| fsd_client::pipe_info(pipe.as_raw_handle()).ok())
            .map_or(0, |[_, _, readers, _]| readers.saturating_sub(1));
        let channels = fsd_client::channels();
        let holders: u64 = self
            .binding
            .iter()
            .flat_map(|binding| binding.slots.iter())
            .filter_map(|&slot| channels.get(slot))
            .filter_map(|&(request, _)| fsd_client::pipe_info(request).ok())
            .map(|[_, _, _, writers]| writers.saturating_sub(2))
            .sum();
        text.push_str(&format!(
            "other holders: input {input}, file server channels {holders}\n"
        ));
        text
    }
}

impl AbsdChild {
    /// Qualification only (`--qualification-controls`): kills the shell
    /// without `END`, as every end path did before the protocol.
    fn kill_without_end(&mut self) {
        if let Some(child) = self.child.as_mut().filter(|_| !self.ended) {
            let _ = child.kill();
            say!(
                "SSH QUALIFICATION SHELL KILLED WITHOUT END pid={}",
                self.pid
            );
        }
    }

    fn control_ended(&mut self, reason: String) -> Result<Option<ControlRequest>, String> {
        self.control = None;
        Err(reason)
    }

    /// The shell's next whole request. A look at an idle channel costs a
    /// one-tick read, so it is made at most every `CONTROL_LOOK`.
    fn read_request(&mut self, now: Instant) -> Result<Option<ControlRequest>, String> {
        let Some(control) = self.control.as_mut() else {
            return Ok(None);
        };
        let frame = match control.decoder.next() {
            Ok(Some(frame)) => Some(frame),
            Ok(None) if now < control.next_look => return Ok(None),
            Ok(None) => {
                control.next_look = now + CONTROL_LOOK;
                let mut buf = [0u8; 256];
                match absd_runtime::read_within(control.requests, &mut buf, PIPE_WAIT_TICKS) {
                    Ok(0) => return Err("the shell closed it".to_string()),
                    Ok(n) => {
                        control.decoder.push(&buf[..n]);
                        control
                            .decoder
                            .next()
                            .map_err(|_| "malformed request".to_string())?
                    }
                    Err(ERROR_TIMEOUT) => None,
                    Err(code) => return Err(format!("requests pipe: {code}")),
                }
            }
            Err(_) => return Err("malformed request".to_string()),
        };
        match frame {
            None => Ok(None),
            Some(ControlFrame::Machine(words)) => Ok(Some(ControlRequest::Machine(words))),
            Some(ControlFrame::List) => Ok(Some(ControlRequest::List)),
            Some(other) => Err(format!("unexpected frame {other:?}")),
        }
    }
}

impl Drop for AbsdChild {
    fn drop(&mut self) {
        // The slot is released (by `binding`, after this) only once the
        // child is gone.
        if !self.ended {
            self.terminate();
        }
    }
}

/// How long session children get to finish after the shutdown notice
/// (their stdin closed) before sshd ends them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
/// After the grace: how long closed sessions get for the clients to take
/// the close and disconnect, before sshd drops the connections.
const SHUTDOWN_CLOSE: Duration = Duration::from_secs(5);
/// How long the stack gets to finish the TCP closes before sshd exits.
const SHUTDOWN_LINGER: Duration = Duration::from_secs(2);
/// A served boot's worker asks init for a restart with this status (kernel
/// `abi/src/program.rs`); 0 asks for a halt.
const SERVED_WORKER_RESTART_STATUS: i32 = 98;

struct AbsdSpawner<'c> {
    config: &'c Config,
    started: u64,
    /// Sessions this boot tried to bind, started or not: the scratch name
    /// is never retried, so a name that cannot be bound is not retried
    /// forever either.
    attempted: u64,
    pool: Rc<RefCell<Pool>>,
    /// The operator's machine request, once made; no session starts after.
    requested: Option<MachineRequest>,
    /// Qualification only: `qualification-kill-shells` was asked.
    kill_shells: bool,
    /// Qualification only: the server faults right after writing its
    /// requested-end fact, before its orderly exit (a crash in the window
    /// the recovery ledger's clear must not trust).
    fault_at_end: bool,
}

impl Spawner for AbsdSpawner<'_> {
    type Child = AbsdChild;
    /// The operator identity (every authenticated session) may ask for a
    /// halt or a restart; sshd acts by ending its sessions and exiting with
    /// the status that tells init which. The first request wins.
    fn machine_request(&mut self, request: MachineRequest) -> Result<String, String> {
        if let Some(earlier) = self.requested {
            return Err(format!(
                "{}: a {} is already under way\n",
                request.word(),
                earlier.word()
            ));
        }
        self.requested = Some(request);
        Ok(format!(
            "ABSD is going down for {}: sessions are told and end, the file server commits and stops, then the machine {}.\n",
            request.word(),
            match request {
                MachineRequest::Halt => "halts",
                MachineRequest::Restart => "restarts",
            }
        ))
    }
    fn spawn(&mut self, command: &conn::Command, terminal: bool) -> io::Result<AbsdChild> {
        if self.requested.is_some() {
            return Err(io::Error::other("the system is going down"));
        }
        if let (true, conn::Command::Exec(text)) = (self.config.qualification_controls, command) {
            match text.trim() {
                "qualification-sshd-exit" => {
                    say!("SSH QUALIFICATION SSHD EXITS with sessions running");
                    crate::oplog::flush();
                    std::process::exit(0);
                }
                "qualification-sshd-fault" => {
                    eprintln!("SERVED SERVICE FAULT component=sshd reason=qualification");
                    std::process::exit(7);
                }
                "qualification-fsd-exit" => {
                    // With the paired FSD qualification flag, the file
                    // server exits while this NOTICE waits for its reply.
                    // The command never reports success to the client.
                    crate::oplog::notice("FSD QUALIFICATION EXIT");
                    return Err(io::Error::other(
                        "qualification: file server exited before NOTICE reply",
                    ));
                }
                "qualification-sshd-fault-at-end" => {
                    self.fault_at_end = true;
                    return Err(io::Error::other(
                        "qualification: the server faults after recording its requested end",
                    ));
                }
                "qualification-kill-shells" => {
                    self.kill_shells = true;
                    return Err(io::Error::other(
                        "qualification: every session shell is killed without END",
                    ));
                }
                _ => {}
            }
        }
        let argv = self
            .config
            .argv(command)
            .map_err(|m| io::Error::new(io::ErrorKind::InvalidInput, m))?;
        // A shell starts the commands it is given, so it keeps the spawn
        // right; a program named directly by `exec` gets none.
        let shell = self.config.runs_shell(command);
        absd_runtime::process::deny_spawn_to_children(!shell);
        absd_runtime::process::merge_output_for_children(terminal);
        // The session's authority: a slot bound to its mounts. A shell,
        // which starts commands, also gets spares for its children.
        self.attempted += 1;
        let id = self.attempted;
        let binding = bind(&self.pool, &session_mounts(id), if shell { 2 } else { 0 })?;
        fsd_client::set_next_child(ChildFs::Slot {
            own: binding.slots[0],
            spares: binding.slots[1..].to_vec(),
        });
        // A shell also gets a session control channel (^C, the session's
        // end, and its requests to sshd), made now because a handle reaches
        // a process only when it is spawned: every child that keeps the
        // spawn right, so that sshd can tell it to end what it started.
        // Nothing else of sshd's gets one.
        let control = if shell {
            Some(Control::new(
                absd_runtime::session::give_next_child()
                    .map_err(|code| io::Error::other(format!("session control channel: {code}")))?,
            ))
        } else {
            None
        };
        let spawned = Command::new(&argv[0])
            .args(&argv[1..])
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        // Spent by the spawn; if it never got that far, never by a later one.
        absd_runtime::session::cancel_next_child();
        let mut child = spawned?;
        self.started += 1;
        say!(
            "SSH SESSION CHILD pid={} spawn_right={shell} argv0={} fs_slot={} spares={:?} control={}",
            child.id(),
            argv[0],
            binding.slots[0],
            &binding.slots[1..],
            control.is_some()
        );
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        Ok(AbsdChild {
            pid: child.id(),
            program: argv[0].clone(),
            child: Some(child),
            stdin,
            stdout,
            stderr,
            ended: false,
            control,
            binding: Some(binding),
        })
    }
}

struct Slot {
    conn: Connection<AbsdChild>,
    tcp: TcpConn,
    source: absd_net::Ipv4Address,
    net_eof: bool,
}

// Only accepted unauthenticated connections consume this per-IP allowance.
// Pre-accept SYN/listen backlog sockets are bounded separately by `listen`.
// The global max-connections bound still includes authenticated sessions.
const PREAUTH_PER_SOURCE: usize = 2;

fn report_quiescent_capacity(
    boot: &str,
    accepted_reclaimed: u64,
    slots: usize,
    pool: usize,
    stack: &Stack<NicLink>,
) {
    let census = absd_runtime::resource_census().unwrap_or_else(|code| {
        eprintln!("SERVED CAPACITY REFUSED reason=census code={code}");
        std::process::exit(1);
    });
    // Direct stderr keeps this sample from queuing another FSD log write.
    eprintln!(
        "SERVED CAPACITY boot={boot} accepted_reclaimed={accepted_reclaimed} slots={slots} pool={pool} net_sockets={} net_closing={} processes={} handles={} pipes={} cells={} frames={} heap_pages_peak={}",
        stack.socket_count(),
        stack.closing_count(),
        census.processes,
        census.handles,
        census.pipes,
        census.cells,
        census.frames,
        absd_runtime::heap_mapped_pages(),
    );
}

pub fn run(config: Config) -> ! {
    match entropy() {
        Ok(()) => say!("SSH ENTROPY OK source=rdrand"),
        Err(e) => fatal(&format!("entropy: {e}")),
    }
    // Storage is the file server's: sshd has its control channel (which
    // no child of sshd ever gets) and the client slots, no block handle.
    fsd_client::set_default_child(ChildFs::None);
    if absd_runtime::has_block_device() || !fsd_client::active() {
        fatal("sshd needs file server channels and no block handle (an `fsd` boot)");
    }
    if config.regenerate_host_key {
        fatal("the file server regenerates the host key (absd-fsd --regenerate-host-key)");
    }
    // The runtime already refused this process unless the control
    // channel's server speaks this build's protocol; sshd also requires
    // it to serve this build's release (docs/RELEASE.md section 2), before
    // anything is read through it and long before it listens. A refusal
    // exits 104 pre-ready with `FSD PROTOCOL REFUSED ...`.
    let server = fsd_client::require_server(0, true);
    say!(
        "SSH RELEASE OK release={} fsd_protocol={}",
        String::from_utf8_lossy(&server.release),
        server.fsd_protocol
    );
    let mounts = fsd_client::mounts().unwrap_or_else(|e| fatal(&format!("control mounts: {e}")));
    let slots = fsd_client::channels().len() - 1;
    let shown: Vec<String> = mounts
        .iter()
        .map(|m| {
            format!(
                "{}:{}",
                String::from_utf8_lossy(&m.path),
                if m.writable { "rw" } else { "ro" }
            )
        })
        .collect();
    say!(
        "SSH STORAGE VIA FILE SERVER OK block=none control={} slots={slots}",
        shown.join(",")
    );
    CONSOLE.store(true, std::sync::atomic::Ordering::Relaxed);
    crate::oplog::open();
    // Configuration: /etc/sshd.conf and /etc/network.conf, or the built-in
    // defaults when a file is absent; a malformed one refuses the start.
    let mut config = config;
    let sshd_file = configuration(etc::SSHD_PATH, etc::parse_sshd);
    let settings = sshd_file.unwrap_or(etc::Sshd::DEFAULT);
    config.listen = format!("0.0.0.0:{}", settings.port);
    config.max_connections = settings.max_connections;
    config.limits.auth_timeout = settings.login_grace;
    config.limits.idle_timeout = settings.idle_timeout;
    config.limits.max_auth_failures = settings.max_auth_tries;
    let network_file = configuration(etc::NETWORK_PATH, etc::parse_network);
    let network = network_file.unwrap_or(etc::Network::DEFAULT);
    let from = |read: bool, path: &str| {
        if read {
            path.to_string()
        } else {
            format!("built-in defaults, no {path}")
        }
    };
    crate::oplog::notice(&format!(
        "sshd: network {}/{} gateway {} ({})",
        etc::dotted(network.address),
        network.prefix_len,
        network.gateway.map_or("none".to_string(), etc::dotted),
        from(network_file.is_some(), etc::NETWORK_PATH)
    ));
    crate::oplog::notice(&format!(
        "sshd: port {}, at most {} connections, login grace {} s, idle timeout {} s, {} authentication tries ({})",
        settings.port,
        settings.max_connections,
        settings.login_grace.as_secs(),
        settings.idle_timeout.as_secs(),
        settings.max_auth_tries,
        from(sshd_file.is_some(), etc::SSHD_PATH)
    ));
    let host = keys::load(&config.host_key).unwrap_or_else(|e| fatal(&format!("host key: {e}")));
    say!(
        "SSH HOST KEY {} {} {}",
        if host.generated {
            "GENERATED"
        } else {
            "LOADED"
        },
        host.openssh_public(),
        host.fingerprint()
    );
    // In plain text on the console and in /var/log/sshd, in the form
    // `ssh-keygen -l` prints, so the operator can compare it with what
    // the client shows at the first connection.
    crate::oplog::notice(&format!(
        "sshd: host key 256 {} (ED25519)",
        host.fingerprint()
    ));
    crate::oplog::notice(&format!("sshd: host key {}", host.openssh_public()));
    let authorized = keys::load_authorized(&config.authorized_keys)
        .unwrap_or_else(|e| fatal(&format!("authorized keys: {e}")));

    let link = NicLink::from_startup().unwrap_or_else(|e| fatal(&format!("nic: {e:?}")));
    let net = absd_net::Config {
        address: absd_net::Ipv4Address::from(network.address),
        prefix_len: network.prefix_len,
        gateway: network.gateway.map(absd_net::Ipv4Address::from),
        ..absd_net::Config::qemu_user()
    };
    let mut stack = Stack::open(link, net).unwrap_or_else(|e| fatal(&format!("stack: {e:?}")));
    let port = settings.port;
    let listener: Listener = stack
        .listen(port, config.max_connections.clamp(1, 8))
        .unwrap_or_else(|e| fatal(&format!("listen: {e:?}")));
    let boot = absd_runtime::boot_id()
        .unwrap_or_else(|code| fatal(&format!("boot identity: {code}")))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // The recovery ledger the file server charged for this generation
    // (absd_fsd::recovery), repeated for init, and this generation's
    // readiness fact, committed before readiness is advertised. Either
    // failing is a pre-ready refusal: nothing resets a generation whose
    // count is not established.
    let boot_id: absd_fsd::recovery::Boot = boot
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| fatal("boot identity is not 32 hex digits"));
    let streak = recovery_streak(&boot_id).unwrap_or_else(|e| fatal(&format!("recovery ledger: {e}")));
    write_fact(absd_fsd::recovery::SERVED_READY, &boot_id, None)
        .unwrap_or_else(|e| fatal(&format!("recovery ready fact: {e}")));
    say!("SSH RECOVERY streak={streak}");
    say!(
        "SSH LISTENING port={port} authorized_keys={} preauth_per_source={PREAUTH_PER_SOURCE}",
        authorized.len()
    );
    crate::oplog::flush();

    let identity = Identity {
        host_key: &host.key,
        authorized: &authorized,
    };
    let pool = Rc::new(RefCell::new(Pool {
        busy: vec![false; slots + 1],
        sessions: 0,
        max_sessions: config.max_connections,
    }));
    let mut spawner = AbsdSpawner {
        config: &config,
        started: 0,
        attempted: 0,
        pool,
        requested: None,
        kill_shells: false,
        fault_at_end: false,
    };
    let mut slots: Vec<Slot> = Vec::new();
    let mut next_id = 1u64;
    let mut accepted_reclaimed = 0u64;
    let mut reported_reclaimed = None;
    let mut buf = vec![0u8; 4096];
    // (request, when, whether the grace has run out)
    let mut shutdown: Option<(MachineRequest, Instant, bool)> = None;
    let mut ended_by_shutdown = 0usize;
    loop {
        crate::oplog::flush();
        stack.poll();
        let now = Instant::now();
        while shutdown.is_none() && slots.len() < config.max_connections {
            let Some((tcp, (source, remote_port))) = stack.accept_filtered(listener, |peer| {
                let Some((source, _)) = peer else {
                    say!("SSH PREAUTH REFUSED source=unknown reason=no-peer");
                    return false;
                };
                let allowed = conn::preauth_source_has_room(
                    &source,
                    slots.iter().filter(|slot| slot.conn.ended().is_none()).map(|slot| {
                        (&slot.source, slot.conn.is_authenticated())
                    }),
                    PREAUTH_PER_SOURCE,
                );
                if !allowed {
                    say!("SSH PREAUTH REFUSED source={source:?} reason=source-limit limit={PREAUTH_PER_SOURCE}");
                }
                allowed
            }) else {
                break;
            };
            stack
                .disable_transport_timeout(tcp)
                .expect("accepted SSH timeout opt-out");
            say!("sshd: conn {next_id}: from {source:?}:{remote_port}");
            slots.push(Slot {
                conn: Connection::new(next_id, now),
                tcp,
                source,
                net_eof: false,
            });
            next_id += 1;
        }
        if shutdown.is_none() && slots.len() >= config.max_connections {
            // A completed handshake must not wait in the listener for a
            // session slot to become free. Refuse it at the transport
            // boundary without allocating a Slot or a file-server binding.
            let _ = stack.accept_filtered(listener, |peer| {
                eprintln!(
                    "SSH GLOBAL REFUSED source={peer:?} limit={} slots={} pool={}",
                    config.max_connections,
                    slots.len(),
                    spawner.pool.borrow().sessions
                );
                false
            });
        }
        let mut busy = false;
        for slot in slots.iter_mut() {
            busy |= service(
                slot,
                &mut stack,
                &mut spawner,
                &identity,
                &config,
                &mut buf,
                now,
            );
        }
        if std::mem::take(&mut spawner.kill_shells) {
            for slot in slots.iter_mut() {
                if let Some(child) = slot.conn.child_mut() {
                    child.kill_without_end();
                }
            }
        }
        let ending = drive_endings(Instant::now());
        if let (None, Some(request)) = (shutdown, spawner.requested) {
            // Nothing new is accepted; every session is told and its
            // child's input ends.
            let _ = stack.unlisten(listener);
            let notice = format!(
                "the system is going down for {}; this session ends",
                request.word()
            );
            for slot in slots.iter_mut() {
                slot.conn.begin_shutdown(&notice);
            }
            say!(
                "SSH SHUTDOWN REQUESTED action={} connections={}",
                request.word(),
                slots.len()
            );
            ended_by_shutdown = slots.len();
            shutdown = Some((request, now, false));
            busy = true;
        }
        if let Some((request, since, forced)) = shutdown.as_mut() {
            if !*forced && now >= *since + SHUTDOWN_GRACE {
                let running = slots.iter_mut().filter_map(|s| s.conn.child_mut()).count();
                say!("SSH SHUTDOWN GRACE OVER sessions_still_running={running}");
                for slot in slots.iter_mut() {
                    slot.conn.force_end();
                }
                *forced = true;
                busy = true;
            }
            if now >= *since + SHUTDOWN_GRACE + SHUTDOWN_CLOSE {
                for slot in slots.iter_mut() {
                    slot.conn.end_now("system shutdown");
                }
            }
            // Every connection is closed and every session's child is gone
            // (an `END` still under way holds its slots until then).
            if slots.is_empty() && !ending {
                let request = *request;
                finish_shutdown(&mut stack, request, ended_by_shutdown, spawner, &boot_id);
            }
        }
        slots.retain_mut(|slot| {
            if slot.conn.ended().is_none() {
                return true;
            }
            // FIN after whatever is still queued; the stack keeps
            // acknowledging (and discarding) the peer's bytes until the
            // close completes.
            let _ = stack.close(slot.tcp);
            say!("SSH SESSION RECLAIMED children_started={}", spawner.started);
            accepted_reclaimed += 1;
            false
        });
        let pool_sessions = spawner.pool.borrow().sessions;
        if reported_reclaimed != Some(accepted_reclaimed)
            && slots.is_empty()
            && !ending
            && stack.closing_count() == 0
            && pool_sessions == 0
        {
            report_quiescent_capacity(
                &boot,
                accepted_reclaimed,
                slots.len(),
                pool_sessions,
                &stack,
            );
            reported_reclaimed = Some(accepted_reclaimed);
        }
        if !busy {
            // Nothing moved: sleep in the NIC until a frame or a timer, at
            // most a few ticks (child pipes are looked at again after it).
            let children = ending || slots.iter_mut().any(|s| s.conn.child_mut().is_some());
            stack.wait(if children { 1 } else { absd_net::MAX_WAIT_MS });
        }
    }
}

/// Every connection has ended and every session's slot is released: let
/// the TCP closes finish (bounded), then exit with the status that tells
/// init what the operator asked for.
fn finish_shutdown(
    stack: &mut Stack<NicLink>,
    request: MachineRequest,
    connections: usize,
    spawner: AbsdSpawner,
    boot_id: &absd_fsd::recovery::Boot,
) -> ! {
    let started = spawner.started;
    let fault_at_end = spawner.fault_at_end;
    drop(spawner);
    let until = Instant::now() + SHUTDOWN_LINGER;
    while stack.closing_count() > 0 && Instant::now() < until {
        stack.poll();
        stack.wait(1);
    }
    say!(
        "SSH SHUTDOWN COMPLETE action={} connections={connections} children_started={started} tcp_closing={}",
        request.word(),
        stack.closing_count()
    );
    crate::oplog::flush();
    // The operator's request, committed as the last act before exit: the
    // next generation clears the recovery streak only when this fact and
    // the file server's own stopped fact both name this boot
    // (absd_fsd::recovery). A fact that cannot be written clears nothing.
    if let Err(e) = write_fact(absd_fsd::recovery::SERVED_END, boot_id, Some(request.word())) {
        say!("SSH RECOVERY END FACT FAILED {e}");
        crate::oplog::flush();
    }
    if fault_at_end {
        eprintln!("SERVED SERVICE FAULT component=sshd reason=qualification_at_end");
        std::process::exit(7);
    }
    std::process::exit(match request {
        MachineRequest::Halt => 0,
        MachineRequest::Restart => SERVED_WORKER_RESTART_STATUS,
    })
}

fn service(
    slot: &mut Slot,
    stack: &mut Stack<NicLink>,
    spawner: &mut AbsdSpawner,
    identity: &Identity,
    config: &Config,
    buf: &mut [u8],
    now: Instant,
) -> bool {
    let conn = &mut slot.conn;
    let mut busy = false;
    // A bounded number of rounds per pass, so one busy connection cannot
    // keep the loop from accepting and serving the others.
    for _ in 0..ROUNDS_PER_PASS {
        let mut moved = false;
        if conn.wants_input() && !slot.net_eof {
            match stack.recv(slot.tcp, buf) {
                Ok(0) => {}
                Ok(n) => {
                    conn.push_input(&buf[..n], now);
                    moved = true;
                }
                Err(NetError::Finished) | Err(_) => {
                    slot.net_eof = true;
                    conn.input_closed();
                    moved = true;
                }
            }
        }
        moved |= conn.pump(spawner, identity, &config.limits, now);
        while conn.output_pending() {
            match stack.send(slot.tcp, conn.output()) {
                Ok(0) => break,
                Ok(n) => {
                    conn.consume_output(n, now);
                    moved = true;
                }
                Err(_) => {
                    slot.net_eof = true;
                    conn.input_closed();
                    break;
                }
            }
        }
        if moved {
            // Let the stack move what was just queued.
            stack.poll();
        }
        busy |= moved;
        if !moved || conn.ended().is_some() {
            return busy;
        }
    }
    busy
}

const ROUNDS_PER_PASS: usize = 8;
