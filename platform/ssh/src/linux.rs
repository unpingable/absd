//! Linux backend: development and the reference matrix. `std::net` for the
//! listener and connections, `std::process` for session children, and one
//! `poll(2)` over every socket and child pipe.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use crate::Config;
use crate::conn::{self, Connection, Exit, Identity, SessionChild, Spawner};
use crate::keys;

fn nonblocking(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

fn nonblocking_result(r: io::Result<usize>) -> io::Result<Option<usize>> {
    match r {
        Ok(n) => Ok(Some(n)),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(None),
        Err(e) => Err(e),
    }
}

pub struct LinuxChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl LinuxChild {
    fn read_fds(&self) -> Vec<RawFd> {
        let mut fds = Vec::new();
        fds.extend(self.stdout.as_ref().map(|p| p.as_raw_fd()));
        fds.extend(self.stderr.as_ref().map(|p| p.as_raw_fd()));
        fds
    }
}

fn read_pipe<P: Read>(pipe: &mut Option<P>, buf: &mut [u8]) -> io::Result<Option<usize>> {
    let Some(p) = pipe.as_mut() else { return Ok(Some(0)) };
    let r = nonblocking_result(p.read(buf));
    if matches!(r, Ok(Some(0)) | Err(_)) {
        *pipe = None;
    }
    r
}

impl SessionChild for LinuxChild {
    fn read_stdout(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        read_pipe(&mut self.stdout, buf)
    }
    fn read_stderr(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        read_pipe(&mut self.stderr, buf)
    }
    fn write_stdin(&mut self, buf: &[u8]) -> io::Result<Option<usize>> {
        match self.stdin.as_mut() {
            Some(p) => nonblocking_result(p.write(buf)),
            None => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
    fn close_stdin(&mut self) {
        self.stdin = None;
    }
    fn try_wait(&mut self) -> io::Result<Option<Exit>> {
        Ok(self.child.try_wait()?.map(|status| match status.code() {
            Some(code) => Exit::Code(code as u32),
            None => Exit::Abnormal,
        }))
    }
    fn terminate(&mut self) {
        unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct LinuxSpawner<'c> {
    config: &'c Config,
}

impl Spawner for LinuxSpawner<'_> {
    type Child = LinuxChild;
    /// The Linux reference serves sessions on someone else's machine: it
    /// never acts on a machine request.
    fn machine_request(&mut self, request: conn::MachineRequest) -> Result<String, String> {
        Err(format!("sshd: {}: machine requests are served only by sshd on ABSD\n", request.word()))
    }
    fn spawn(&mut self, command: &conn::Command, terminal: bool) -> io::Result<LinuxChild> {
        let argv = self.config.argv(command).map_err(|m| io::Error::new(io::ErrorKind::InvalidInput, m))?;
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .current_dir("/")
            // Its own process group, so ending the session ends everything
            // the session started.
            .process_group(0)
            .stdin(Stdio::piped());
        // A terminal: stdout and stderr share one pipe.
        let merged = if terminal {
            let (reader, writer) = io::pipe()?;
            cmd.stdout(writer.try_clone()?).stderr(writer);
            Some(reader)
        } else {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            None
        };
        let mut child = cmd.spawn()?;
        // Drop the command: it holds the merged pipe's writers.
        drop(cmd);
        let stdin = child.stdin.take();
        let stdout = match merged {
            Some(reader) => Some(ChildStdout::from(OwnedFd::from(reader))),
            None => child.stdout.take(),
        };
        let stderr = child.stderr.take();
        for fd in [
            stdin.as_ref().map(|p| p.as_raw_fd()),
            stdout.as_ref().map(|p| p.as_raw_fd()),
            stderr.as_ref().map(|p| p.as_raw_fd()),
        ]
        .into_iter()
        .flatten()
        {
            nonblocking(fd);
        }
        Ok(LinuxChild { child, stdin, stdout, stderr })
    }
}

struct Slot {
    conn: Connection<LinuxChild>,
    sock: TcpStream,
    /// Set once the connection ended and its sending direction is shut:
    /// the peer's remaining bytes are read and discarded until it closes
    /// (closing with unread input would reset the connection and could
    /// discard our last packets on the peer's side).
    closing: Option<Instant>,
}

const LINGER: Duration = Duration::from_secs(2);

pub fn run(config: Config) -> ! {
    let host = keys::load_or_create(&config.host_key, config.regenerate_host_key, |from, to| {
        std::fs::rename(from, to)?;
        if let Some(dir) = to.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    })
    .unwrap_or_else(|e| fatal(&format!("host key: {e}")));
    eprintln!(
        "SSH HOST KEY {} {} {}",
        if host.generated { "GENERATED" } else { "LOADED" },
        host.openssh_public(),
        host.fingerprint()
    );
    let authorized =
        keys::load_authorized(&config.authorized_keys).unwrap_or_else(|e| fatal(&format!("authorized keys: {e}")));
    let listener = TcpListener::bind(&config.listen).unwrap_or_else(|e| fatal(&format!("listen: {e}")));
    listener.set_nonblocking(true).unwrap();
    eprintln!("SSH LISTENING {}", listener.local_addr().unwrap());

    let identity = Identity { host_key: &host.key, authorized: &authorized };
    let mut spawner = LinuxSpawner { config: &config };
    let mut slots: Vec<Slot> = Vec::new();
    let mut next_id = 1u64;
    let mut buf = vec![0u8; 16384];
    loop {
        let now = Instant::now();
        while slots.len() < config.max_connections {
            match listener.accept() {
                Ok((sock, peer)) => {
                    sock.set_nonblocking(true).unwrap();
                    let _ = sock.set_nodelay(true);
                    eprintln!("sshd: conn {next_id}: from {peer}");
                    slots.push(Slot { conn: Connection::new(next_id, now), sock, closing: None });
                    next_id += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    eprintln!("sshd: accept: {e}");
                    break;
                }
            }
        }
        for slot in slots.iter_mut() {
            service(slot, &mut spawner, &identity, &config, &mut buf, now);
        }
        slots.retain(|slot| {
            let done = slot.closing.is_some_and(|since| now >= since + LINGER);
            !done
        });

        // Wait for anything to become ready, or the next deadline.
        let mut fds = Vec::new();
        let mut timeout = Duration::from_secs(5);
        if slots.len() < config.max_connections {
            fds.push(pollfd(listener.as_raw_fd(), libc::POLLIN));
        }
        for slot in slots.iter_mut() {
            if let Some(since) = slot.closing {
                fds.push(pollfd(slot.sock.as_raw_fd(), libc::POLLIN));
                timeout = timeout.min((since + LINGER).saturating_duration_since(now));
                continue;
            }
            let mut events = 0;
            if slot.conn.wants_input() {
                events |= libc::POLLIN;
            }
            if slot.conn.output_pending() {
                events |= libc::POLLOUT;
            }
            fds.push(pollfd(slot.sock.as_raw_fd(), events));
            timeout = timeout.min(slot.conn.deadline(&config.limits).saturating_duration_since(now));
            let wants_output = slot.conn.wants_child_output();
            if let Some(child) = slot.conn.child_mut() {
                // A child's exit is not a descriptor event: look again soon.
                timeout = timeout.min(Duration::from_millis(20));
                if wants_output {
                    for fd in child.read_fds() {
                        fds.push(pollfd(fd, libc::POLLIN));
                    }
                }
            }
        }
        let ms = timeout.as_millis().clamp(1, 5000) as i32;
        unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
    }
}

fn service(
    slot: &mut Slot,
    spawner: &mut LinuxSpawner,
    identity: &Identity,
    config: &Config,
    buf: &mut [u8],
    now: Instant,
) {
    if slot.closing.is_some() {
        loop {
            match slot.sock.read(buf) {
                Ok(0) => {
                    slot.closing = Some(now - LINGER);
                    return;
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => {
                    slot.closing = Some(now - LINGER);
                    return;
                }
            }
        }
    }
    let conn = &mut slot.conn;
    // Bounded rounds per pass: one busy connection must not starve the rest.
    for _ in 0..8 {
        if conn.wants_input() {
            match slot.sock.read(buf) {
                Ok(0) => conn.input_closed(),
                Ok(n) => conn.push_input(&buf[..n], now),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => conn.input_closed(),
            }
        }
        let progressed = conn.pump(spawner, identity, &config.limits, now);
        let mut wrote = false;
        while conn.output_pending() {
            match slot.sock.write(conn.output()) {
                Ok(n) => {
                    conn.consume_output(n, now);
                    wrote |= n > 0;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    conn.input_closed();
                    break;
                }
            }
        }
        if conn.ended().is_some() {
            let _ = slot.sock.shutdown(std::net::Shutdown::Write);
            slot.closing = Some(now);
            return;
        }
        if !progressed && !wrote && !(conn.wants_input() && has_input(&slot.sock)) {
            return;
        }
    }
}

fn has_input(sock: &TcpStream) -> bool {
    let mut fd = [pollfd(sock.as_raw_fd(), libc::POLLIN)];
    unsafe { libc::poll(fd.as_mut_ptr(), 1, 0) > 0 }
}

fn pollfd(fd: RawFd, events: libc::c_short) -> libc::pollfd {
    libc::pollfd { fd, events, revents: 0 }
}

fn fatal(message: &str) -> ! {
    eprintln!("sshd: {message}");
    std::process::exit(1);
}
