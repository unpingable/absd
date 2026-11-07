//! Two retained local terminals using the SSH session child and line discipline.
//! Physical input is owned by init, not by this service or any shell.
use crate::conn::{Command, ControlRequest, SessionChild, Spawner};
use crate::tty::LineDiscipline;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub const HISTORY: usize = 16 * 1024;
const QUEUE: usize = 8192;
const ESCAPE: u8 = 0x1d;

struct Session<C> {
    child: Option<C>,
    terminal: LineDiscipline,
    input: Vec<u8>,
    recovery: crate::plain_input::Recovery,
    wake_pending: bool,
    token: Vec<u8>,
    history: VecDeque<u8>,
    lost: u64,
    next_login: Instant,
    failures: u32,
}
impl<C> Session<C> {
    fn new(now: Instant) -> Self {
        Self {
            child: None,
            terminal: LineDiscipline::plain_lines(),
            input: Vec::new(),
            recovery: crate::plain_input::Recovery::default(),
            wake_pending: false,
            token: Vec::with_capacity(128),
            history: VecDeque::new(),
            lost: 0,
            next_login: now,
            failures: 0,
        }
    }
    fn clear_input(&mut self) {
        self.token.fill(0);
        self.token.clear();
        self.input.fill(0);
        self.input.clear();
        self.terminal = LineDiscipline::plain_lines();
        self.recovery = crate::plain_input::Recovery::default();
        self.wake_pending = false;
    }
}

pub struct Manager<C> {
    sessions: [Session<C>; 2],
    active: usize,
    escape: bool,
    logout_pending: bool,
    output: VecDeque<u8>,
    output_lost: u64,
    auth_failures: u32,
    auth_after: Instant,
    enabled: bool,
}
impl<C: SessionChild> Manager<C> {
    pub fn new(enabled: bool) -> Self {
        let now = Instant::now();
        let mut manager = Self {
            sessions: [Session::new(now), Session::new(now)],
            active: 0,
            escape: false,
            logout_pending: false,
            output: VecDeque::new(),
            output_lost: 0,
            auth_failures: 0,
            auth_after: now,
            enabled,
        };
        manager.redraw();
        manager
    }
    fn emit(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.output.len() == QUEUE {
                self.output.pop_front();
                self.output_lost = self.output_lost.saturating_add(1);
            }
            self.output.push_back(byte);
        }
    }
    fn prompt(&mut self) {
        if !self.enabled {
            self.emit(b"Local login not enrolled; kernel maintenance: Ctrl-] k\r\n");
        } else {
            self.emit(b"operator token: ");
        }
    }
    fn redraw(&mut self) {
        // A switch replaces pending presentation with this view. Bound replay
        // below the output queue and show identity last, so a long history
        // cannot evict the banner or scroll it away before the operator sees it.
        self.output.clear();
        self.output_lost = 0;
        let session = &self.sessions[self.active];
        if session.lost > 0 {
            self.emit(format!("[history truncated: {} bytes]\r\n", session.lost).as_bytes());
        }
        let history = &self.sessions[self.active].history;
        let skipped = history.len().saturating_sub(QUEUE - 512);
        let saved: Vec<u8> = history.iter().skip(skipped).copied().collect();
        if skipped > 0 {
            self.emit(format!("[history replay truncated: {skipped} bytes]\r\n").as_bytes());
        }
        self.emit(&saved);
        self.emit(
            format!(
                "\r\nABSD local console {} | Ctrl-] 1/2 switch, l then Enter logout, k kernel, r return\r\n",
                self.active + 1
            )
            .as_bytes(),
        );
        if self.sessions[self.active].child.is_none() {
            self.prompt();
        } else {
            let mut echo = Vec::new();
            self.sessions[self.active].terminal.redraw_prompt(&mut echo);
            self.emit(&echo);
        }
    }
    fn remember(&mut self, id: usize, bytes: &[u8]) {
        let s = &mut self.sessions[id];
        for &b in bytes {
            if s.history.len() == HISTORY {
                s.history.pop_front();
                s.lost = s.lost.saturating_add(1);
            }
            s.history.push_back(b);
        }
        if id == self.active {
            self.emit(bytes);
        }
    }
    pub fn output(&mut self, write: impl FnOnce(&[u8]) -> usize) {
        if self.output_lost > 0 {
            let marker = format!("\r\n[terminal output lost: {} bytes]\r\n", self.output_lost);
            // Queue the marker only once and keep bounded output.
            self.output_lost = 0;
            for &b in marker.as_bytes().iter().rev() {
                self.output.push_front(b);
            }
        }
        let bytes = self.output.make_contiguous();
        let n = write(&bytes[..bytes.len().min(256)]).min(bytes.len().min(256));
        self.output.drain(..n);
    }
    fn logout(&mut self, id: usize, now: Instant) {
        let s = &mut self.sessions[id];
        if let Some(mut child) = s.child.take() {
            child.close_stdin();
            child.terminate();
        }
        s.clear_input();
        s.history.iter_mut().for_each(|b| *b = 0);
        s.history.clear();
        s.lost = 0;
        s.next_login = now + Duration::from_secs(1);
        // Discard queued previous terminal bytes before a new identity is admitted.
        if id == self.active {
            self.escape = false;
            self.logout_pending = false;
            self.output.clear();
            self.emit(b"\r\nSession ended. Login available after one second.\r\n");
            self.prompt();
        }
    }
    pub fn end_all(&mut self, now: Instant) {
        self.enabled = false;
        self.escape = false;
        self.logout_pending = false;
        for id in 0..2 {
            self.logout(id, now);
        }
    }
    pub fn input<S: Spawner<Child = C>>(
        &mut self,
        data: &[u8],
        now: Instant,
        verify: impl Fn(&[u8]) -> bool,
        spawner: &mut S,
    ) {
        let id = self.active;
        if self.sessions[id].recovery.paused() {
            // Quarantine precedes console selectors as well as cooked input.
            // A pasted selector must not log a healthy session out.
            if self.sessions[id].recovery.input(data) {
                if let Some(child) = self.sessions[id].child.as_mut() { child.interrupt(); }
            }
            return;
        }
        let mut offset = 0;
        while offset < data.len() {
            let start = offset;
            let byte = data[offset];
            offset += 1;
            // Restore unrecognized commands literally to the ordinary input
            // path. Prefix state never eats the next command's first byte.
            let mut literal_prefix = 0;
            if self.logout_pending {
                self.logout_pending = false;
                if matches!(byte, b'\r' | b'\n') {
                    self.logout(self.active, now);
                    continue;
                }
                self.emit(b"\r\nLogout cancelled.\r\n");
                // Ctrl-C cancels the pending console command and reaches the
                // existing interrupt path without restoring abandoned text.
                if byte != 3 { literal_prefix = 2; }
            }
            if self.escape {
                self.escape = false;
                match byte {
                    b'1' | b'2' => {
                        // A partially typed token never crosses a switch.
                        self.sessions[self.active].token.fill(0);
                        self.sessions[self.active].token.clear();
                        self.active = (byte - b'1') as usize;
                        self.output.clear();
                        self.redraw();
                        continue;
                    }
                    b'l' => {
                        self.logout_pending = true;
                        self.emit(b"\r\nEnter confirms logout; any other key cancels.\r\n");
                        continue;
                    }
                    b'r' => {
                        self.output.clear();
                        self.redraw();
                        continue;
                    }
                    3 => {},
                    _ => literal_prefix = 1,
                }
            }
            if byte == ESCAPE && literal_prefix == 0 {
                self.escape = true;
                continue;
            }
            let id = self.active;
            if self.sessions[id].child.is_none() {
                if !self.enabled || now < self.auth_after || now < self.sessions[id].next_login {
                    continue;
                }
                match byte {
                    b'\r' | b'\n' => {
                        // Ignore LF paired with CR: blank token never starts another attempt.
                        if self.sessions[id].token.is_empty() {
                            continue;
                        }
                        let accepted = verify(&self.sessions[id].token);
                        self.sessions[id].token.fill(0);
                        self.sessions[id].token.clear();
                        self.emit(b"\r\n");
                        if accepted {
                            let terminal = crate::tty::Terminal {
                                size: crate::tty::terminal_wire::Size {
                                    columns: 0,
                                    rows: 0,
                                    source: crate::tty::terminal_wire::LOCAL,
                                },
                                term: Some("dumb".into()),
                            };
                            match spawner.spawn_local(&Command::Shell, Some(&terminal)) {
                                Ok(child) => {
                                    self.sessions[id].clear_input();
                                    self.sessions[id].child = Some(child);
                                    self.sessions[id].failures = 0;
                                    self.auth_failures = 0;
                                    self.emit(b"Authenticated operator. Session-bound foreground jobs only.\r\n");
                                }
                                Err(_) => {
                                    let s = &mut self.sessions[id];
                                    s.failures = s.failures.saturating_add(1);
                                    let delay = (1u64 << s.failures.min(5)).min(30);
                                    s.next_login = now + Duration::from_secs(delay);
                                    self.emit(format!("Session unavailable (resources or storage); retry in {delay}s.\r\n").as_bytes());
                                    self.prompt();
                                }
                            }
                        } else {
                            self.auth_failures = self.auth_failures.saturating_add(1);
                            let delay = (1u64 << self.auth_failures.min(5)).min(30);
                            self.auth_after = now + Duration::from_secs(delay);
                            self.emit(
                                format!("Authentication failed; retry in {delay}s.\r\n").as_bytes(),
                            );
                            self.prompt();
                        }
                    }
                    8 | 127 => {
                        let token = &mut self.sessions[id].token;
                        if !token.is_empty() {
                            let last = token.len() - 1;
                            token[last] = 0;
                            token.truncate(last);
                        }
                    }
                    3 | 21 => {
                        self.sessions[id].token.fill(0);
                        self.sessions[id].token.clear();
                    }
                    b if b.is_ascii_graphic() && self.sessions[id].token.len() < 128 => {
                        self.sessions[id].token.push(b)
                    }
                    _ => {}
                }
                continue;
            }
            // Keep authentication/session boundaries, but redraw the tail once
            // for a contiguous terminal batch, as in the accepted SSH path.
            while offset < data.len() && data[offset] != ESCAPE {
                offset += 1;
            }
            let (mut line, mut echo) = (Vec::new(), Vec::new());
            let was_refused = self.sessions[id].terminal.input_refused();
            let mut restored = Vec::new();
            let input = if literal_prefix == 0 {
                &data[start..offset]
            } else {
                restored.push(ESCAPE);
                if literal_prefix == 2 { restored.push(b'l'); }
                restored.extend_from_slice(&data[start..offset]);
                &restored
            };
            let events = self.sessions[id].terminal.input(input, &mut line, &mut echo);
            let newly_refused = !was_refused && self.sessions[id].terminal.input_refused();
            self.remember(id, &echo);
            let s = &mut self.sessions[id];
            let notify_interrupt = if newly_refused {
                s.recovery.pause();
                s.input.fill(0);
                s.input.clear();
                // This pre-acknowledgement wake contains no rejected source.
                // Every mode-0/4 pause reply clears/fences it before replying.
                assert!(line.is_empty() || line == b"\n");
                s.wake_pending = !line.is_empty();
                if id == self.active { self.escape = false; self.logout_pending = false; }
                s.recovery.input(&data[start..])
            } else {
                if events.interrupt {
                    s.input.fill(0);
                    s.input.clear();
                    s.wake_pending = false;
                }
                events.interrupt
            };
            if s.input.len() + line.len() <= QUEUE {
                s.input.extend_from_slice(&line);
            } else {
                self.emit(b"\r\n[input queue full; line dropped]\r\n");
            }
            let s = &mut self.sessions[id];
            if notify_interrupt {
                if let Some(child) = s.child.as_mut() {
                    child.interrupt();
                }
            }
            if newly_refused {
                // The remaining batch belongs to the new discard state,
                // including selectors and a cancellation after this line.
                return;
            }
            if events.eof {
                // First drain accepted pending bytes; poll closes stdin afterwards.
            }
        }
    }
    /// The live input consumer supplies its current upstream queue observation.
    /// A recovered session cannot reopen while rejected upstream bytes remain.
    pub fn poll<S: Spawner<Child = C>>(&mut self, now: Instant, spawner: &mut S, upstream_empty: bool) {
        for id in 0..2 {
            let session = &mut self.sessions[id];
            let Some(child) = session.child.as_mut() else {
                continue;
            };
            child.pump_control();
            let request = child.control_request(now);
            if request.is_err() {
                self.logout(id, now);
                continue;
            }
            if let Ok(Some(request)) = request {
                let mut reply_status = 0;
                let reply = match request {
                    ControlRequest::InputMode(mode) => {
                        if mode == 4 {
                            session.recovery.pause();
                            session.input.fill(0);
                            session.input.clear();
                            session.wake_pending = false;
                            session.terminal = LineDiscipline::plain_lines();
                            if id == self.active { self.escape = false; self.logout_pending = false; }
                        } else if mode == 0 {
                            if session.recovery.paused() {
                                session.input.fill(0);
                                session.input.clear();
                                session.wake_pending = false;
                            }
                            session.recovery.acknowledge_pause();
                        } else if matches!(mode, 1 | 2) {
                            let was_paused = session.recovery.paused();
                            if (!was_paused || (upstream_empty && session.input.is_empty())) && session.recovery.rearm() && was_paused {
                                session.terminal = LineDiscipline::plain_lines();
                            }
                        }
                        session.terminal.set_prompt_mode(if mode == 4 { 0 } else { mode });
                        reply_status = if (mode == 4 && session.recovery.paused()) || (mode == 0 && session.recovery.ready_to_rearm()) {
                            crate::control::INPUT_PAUSED
                        } else if session.recovery.paused() {
                            crate::control::INPUT_REFUSED
                        } else { 0 };
                        Ok(crate::plain_input::CAPABILITY.into())
                    }
                    ControlRequest::List => Ok(child.describe()),
                    ControlRequest::Clock(words) => {
                        if matches!(words.split_ascii_whitespace().next(), Some("set" | "sync")) {
                            let pid = child
                                .audit_pid()
                                .map(|n| n.to_string())
                                .unwrap_or_else(|| "unknown".into());
                            crate::oplog::line(format!(
                                "sshd: local console {} pid={pid}: clock request {words:?} from the enrolled session's shell",
                                id + 1
                            ));
                        }
                        spawner.clock_request(&words)
                    }
                    ControlRequest::Machine(words) => match crate::conn::machine_request(&words) {
                        Some(Ok(request)) => spawner.machine_request(request),
                        _ => Err("usage: shutdown [-h|-p|-r now] | reboot\n".into()),
                    },
                };
                match reply {
                    Ok(text) => child.control_reply(reply_status, &text),
                    Err(text) => child.control_reply(1, &text),
                }
            }
            let s = &mut self.sessions[id];
            let child = s.child.as_mut().unwrap();
            if !s.input.is_empty() && (!s.recovery.paused() || s.wake_pending) {
                match child.write_stdin(&s.input) {
                    Ok(Some(n)) if n > 0 => {
                        s.input.drain(..n);
                        if s.input.is_empty() { s.wake_pending = false; }
                    }
                    Ok(_) => {}
                    Err(_) => {
                        s.input.fill(0);
                        s.input.clear();
                        child.close_stdin();
                    }
                }
            }
            if s.terminal.at_eof() && s.input.is_empty() {
                child.close_stdin();
            }
            // Drain a bounded amount per session so a flood cannot starve input.
            for stderr in [false, true] {
                let mut bytes = [0; 256];
                let child = self.sessions[id].child.as_mut().unwrap();
                let count = if stderr {
                    child.read_stderr(&mut bytes)
                } else {
                    child.read_stdout(&mut bytes)
                };
                if let Ok(Some(n)) = count {
                    let mut text = Vec::new();
                    crate::tty::output(&bytes[..n], &mut text);
                    self.remember(id, &text);
                }
            }
            let ended = self.sessions[id].child.as_mut().unwrap().try_wait();
            if !matches!(ended, Ok(None)) {
                self.logout(id, now);
            }
        }
    }
}

#[cfg(test)]
#[path = "local_console_tests.rs"]
mod tests;
