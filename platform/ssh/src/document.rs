//! Explicit SSH admission and the single bounded document stream issuer.
use crate::{Config, ExecMode, conn};
use std::io;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid direct https-document request",
    )
}

// sshd starts session commands in /; ABSD resolves path components lexically.
fn reserved(program: &str) -> bool {
    let mut parts = Vec::new();
    for part in program.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    parts == ["bin", "https-document"]
}

pub fn admitted(
    command: &conn::Command,
    argv: &[String],
    config: &Config,
    terminal: bool,
) -> io::Result<bool> {
    let conn::Command::Exec(text) = command else {
        return Ok(false);
    };
    let words: Vec<_> = text.split_ascii_whitespace().collect();
    let first = words.first().copied().unwrap_or("");
    let raw = if first.contains('/') {
        first.to_string()
    } else {
        config.bin_dir.join(first).to_string_lossy().into_owned()
    };
    let selected = argv.first().is_some_and(|program| reserved(program));
    if !selected && !reserved(&raw) {
        return Ok(false);
    }
    if words.len() == 2 && words[1] == "--sample" {
        return Ok(false);
    }
    if !selected
        || first != "/bin/https-document"
        || terminal
        || config.exec_mode != ExecMode::Argv
        || config.runs_shell(command)
        || text.len() > 256
        || text.bytes().any(|b| b != b' ' && !b.is_ascii_graphic())
        || words.len() != 11
    {
        return Err(invalid());
    }
    for (pair, flag) in
        words[1..]
            .chunks_exact(2)
            .zip(["--boot", "--pit-ms", "--rtc", "--utc-ms", "--uncertainty"])
    {
        if pair[0] != flag
            || if flag == "--boot" {
                pair[1].len() != 32
                    || !pair[1]
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            } else {
                decimal(pair[1]).is_none()
            }
        {
            return Err(invalid());
        }
    }
    Ok(true)
}

fn decimal(text: &str) -> Option<u64> {
    (text == "0" || (!text.starts_with('0') && text.bytes().all(|b| b.is_ascii_digit())))
        .then(|| text.parse().ok())
        .flatten()
}

pub fn peer(bytes: &[u8]) -> io::Result<([u8; 4], u16)> {
    if bytes.len() > 4096 {
        return Err(invalid());
    }
    let first = std::str::from_utf8(bytes)
        .map_err(|_| invalid())?
        .split('\n')
        .next()
        .and_then(|line| line.strip_prefix("peer="))
        .ok_or_else(invalid)?;
    let (ip, port) = first.split_once(':').ok_or_else(invalid)?;
    let address: std::net::Ipv4Addr = ip.parse().map_err(|_| invalid())?;
    let port = decimal(port)
        .and_then(|n| u16::try_from(n).ok())
        .filter(|&n| n != 0)
        .ok_or_else(invalid)?;
    if address.to_string() != ip {
        return Err(invalid());
    }
    Ok((address.octets(), port))
}

pub(super) fn next_port(cursor: &mut u16) -> u16 {
    let port = 49152 + *cursor % 16384;
    *cursor = cursor.wrapping_add(1);
    port
}

/// A cancellation or clock failure cannot be undone by a later server pass.
pub(super) struct Lease {
    until: u64,
    last: u64,
    cancelled: bool,
}
impl Lease {
    pub(super) fn new(now: u64, until: u64) -> Self {
        Self {
            until,
            last: now,
            cancelled: false,
        }
    }
    pub(super) fn observe(&mut self, now: u64, allowed: bool) -> bool {
        self.cancelled |= !allowed || now < self.last || now >= self.until;
        self.last = now;
        !self.cancelled
    }
}

#[cfg(target_os = "absd")]
pub mod native {
    use super::*;
    use absd_net::datagram::channel::Pipe;
    use absd_net::{
        NicLink, Stack,
        datagram::Address,
        stream::{Grant, channel::Channel},
    };
    use std::process::{Child, ChildStdin, ChildStdout};
    use std::{cell::RefCell, io::Read, os::absd::process::AsRawHandle, rc::Rc};

    #[derive(Default)]
    struct State {
        cancel: bool,
        exit: Option<conn::Exit>,
    }
    pub struct Ticket(Rc<RefCell<State>>);
    impl Ticket {
        pub fn cancel(&self) {
            self.0.borrow_mut().cancel = true;
        }
        pub fn exit(&self) -> Option<conn::Exit> {
            self.0.borrow().exit
        }
    }
    impl Drop for Ticket {
        fn drop(&mut self) {
            self.cancel();
        }
    }
    struct Protocol {
        requests: ChildStdout,
        replies: ChildStdin,
    }
    impl Pipe for Protocol {
        fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
            match absd_runtime::read_within(self.requests.as_raw_handle(), bytes, 1) {
                Err(-110) => Ok(None),
                value => value.map(Some),
            }
        }
        fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
            match absd_runtime::write_within(self.replies.as_raw_handle(), bytes, 1) {
                Err(-110) => Ok(None),
                value => value.map(Some),
            }
        }
        fn now_ms(&self) -> u64 {
            absd_runtime::boot_millis()
        }
    }
    struct Active {
        child: Child,
        protocol: Option<Protocol>,
        channel: Option<Channel>,
        state: Rc<RefCell<State>>,
        peer: Address,
        lease: Lease,
        started: bool,
        killed: bool,
        _binding: crate::absd::Binding,
    }
    #[derive(Default)]
    pub struct Issuer {
        active: Option<Active>,
        port_cursor: u16,
    }
    impl Issuer {
        pub fn idle(&self) -> bool {
            self.active.is_none()
        }
        pub fn prepare(&self) -> io::Result<(Address, u64)> {
            if !self.idle() {
                return Err(io::Error::other("https-document is already active"));
            }
            let mut bytes = Vec::new();
            std::fs::File::open("/etc/https-document.conf")?
                .take(4097)
                .read_to_end(&mut bytes)?;
            let (ip, port) = peer(&bytes)?;
            let until = absd_runtime::boot_millis()
                .checked_add(15_000)
                .ok_or_else(invalid)?;
            Ok((Address { ip, port }, until))
        }
        pub fn attach(
            &mut self,
            mut child: Child,
            peer: Address,
            until: u64,
            binding: crate::absd::Binding,
        ) -> Ticket {
            let protocol = child
                .stdout
                .take()
                .zip(child.stdin.take())
                .map(|(requests, replies)| Protocol { requests, replies });
            let state = Rc::new(RefCell::new(State {
                cancel: protocol.is_none(),
                exit: None,
            }));
            self.active = Some(Active {
                child,
                protocol,
                channel: None,
                state: state.clone(),
                peer,
                lease: Lease::new(absd_runtime::boot_millis(), until),
                started: false,
                killed: false,
                _binding: binding,
            });
            Ticket(state)
        }
        /// One bounded pipe operation per server pass. EOF revokes networking,
        /// but leaves the child time to publish through its existing FSD scope.
        pub fn step(&mut self, stack: &mut Stack<NicLink>, allowed: bool) {
            let Some(active) = self.active.as_mut() else {
                return;
            };
            let now = absd_runtime::boot_millis();
            let mut cancel = !active
                .lease
                .observe(now, allowed && !active.state.borrow().cancel);
            if !active.started && !cancel {
                active.started = true;
                let remaining = active.lease.until - now;
                for _ in 0..=absd_net::stream::MAX_ENDPOINTS {
                    match Channel::grant(
                        stack,
                        Grant {
                            local_port: next_port(&mut self.port_cursor),
                            peer: active.peer,
                            connect_timeout_ms: remaining.min(5000),
                            lifetime_ms: remaining,
                        },
                    ) {
                        Ok(channel) => {
                            active.channel = Some(channel);
                            break;
                        }
                        Err(absd_net::stream::Error::InUse) => {}
                        Err(_) => break,
                    }
                }
                cancel |= active.channel.is_none();
            }
            cancel |= !active.lease.observe(absd_runtime::boot_millis(), true);
            if !cancel {
                if let (Some(channel), Some(protocol)) = (&mut active.channel, &mut active.protocol)
                {
                    if !channel.poll(stack, protocol) {
                        active.channel = None;
                        active.protocol = None;
                    }
                }
                let after = absd_runtime::boot_millis();
                cancel = !active.lease.observe(after, true);
            }
            if cancel {
                active.state.borrow_mut().cancel = true;
                if let Some(channel) = active.channel.as_mut() {
                    channel.revoke(stack);
                }
                active.channel = None;
                active.protocol = None;
                if !active.killed {
                    active.killed = active.child.kill().is_ok();
                }
            }
            match active.child.try_wait() {
                Ok(Some(status)) => {
                    if let Some(channel) = active.channel.as_mut() {
                        channel.revoke(stack);
                    }
                    active.protocol = None;
                    active.state.borrow_mut().exit = Some(
                        status
                            .code()
                            .map_or(conn::Exit::Abnormal, |n| conn::Exit::Code(n as u32)),
                    );
                    self.active = None;
                }
                Ok(None) => {}
                Err(_) => active.state.borrow_mut().cancel = true,
            }
        }
    }
}
