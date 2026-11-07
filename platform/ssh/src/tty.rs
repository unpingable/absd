//! The terminal of a PTY session: a small line discipline in sshd, between
//! the channel and the child's pipes. Platform-independent and pure.
//!
//! What a client that asked for a PTY (OpenSSH: `pty-req`, then its own
//! terminal in raw mode) needs and nothing more:
//!
//! Canonical input supports cursor movement, insertion, deletion and word erase.
//! Redraw uses backspaces and tail overwrite, including on the local console.
//! Primary shell prompt mode enables bounded, session-local history. It disarms
//! at submission, before processing any following bytes in the same input batch.
//! ^C discards input and reports interruption; ^D retains pipe EOF semantics.
//! There is no termios, raw mode, process group or job control.

#[path = "paste.rs"]
pub(crate) mod paste;

/// Longest line held for editing (as a terminal's canonical buffer).
pub const MAX_LINE: usize = 64 * 1024;
/// At most 32 entries and 128 KiB of text; destroyed with the session.
pub const HISTORY_LINES: usize = 32;
pub const HISTORY_BYTES: usize = 128 * 1024;

const CTRL_C: u8 = 0x03;
const CTRL_D: u8 = 0x04;
const BS: u8 = 0x08;
const CTRL_U: u8 = 0x15;
const ESC: u8 = 0x1b;
const DEL: u8 = 0x7f;

/// Where in an escape sequence the input stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Escape {
    #[default]
    None,
    /// ESC seen: the next byte says which kind.
    Esc,
    /// `ESC [`: parameter and intermediate bytes until a final 0x40..=0x7e;
    /// `first` until one byte has followed (`ESC [ [ x`, the Linux
    /// console's F1 to F5, takes one more byte like `ESC O`).
    Csi { first: bool, param: u16 },
    /// `ESC O`: one more byte.
    Ss3,
    /// Linux console function-key prefix ESC [ [; discard its final.
    IgnoreOne,
}

/// What one batch of input asked for beyond bytes and echo.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Events {
    /// ^C was typed (the line being typed was discarded).
    pub interrupt: bool,
    /// A cooked Ctrl-C inside application paste, distinct from refusal wakeup.
    pub application_interrupt: bool,
    /// ^D on an empty line: end of input.
    pub eof: bool,
}

#[derive(Debug, Default)]
pub struct LineDiscipline {
    line: Vec<u8>,
    eof: bool,
    escape: Escape,
    cursor: usize,
    prompt: bool,
    prompt_mode: u8,
    plain_lines: bool,
    history: Vec<Vec<u8>>,
    history_at: Option<usize>,
    draft: Vec<u8>,
    utf8: Vec<u8>,
    // Sticky for this logical draft, including partial Ctrl-D delivery.
    // Prompt rearming or history recall cannot promote application input.
    history_ineligible: bool,
    cancelled: bool,
    discard_partial: bool,
    cancel_paused: bool,
    refused: bool,
    marker: paste::Marker,
    capture: bool,
    application_paste: Option<bool>,
    application_brackets: bool,
    output_marker_len: usize,
    staged_active: bool,
    staged: Vec<u8>,
    suffix: Vec<u8>,
    paste_cr: bool,
    swallow_lf: bool,
    external_pending: usize,
    discard_end: bool,
    recovery: paste::Recovery,
    recovered: bool,
    entropy_retry: bool,
    discarded: u64,

}

/// Columns a stored character occupied when echoed.
fn width(ch: &[u8]) -> usize {
    match ch {
        [c] if *c < 0x20 => 2,
        _ => 1,
    }
}

impl LineDiscipline {
    pub fn new() -> Self {
        Self::default()
    }

    /// A local producer without the matched record/pause protocol keeps
    /// cooked lines and editing, including when paste delimiters arrive.
    pub fn plain_lines() -> Self {
        Self { plain_lines: true, ..Self::default() }
    }

    /// Whether end of input has been typed.
    pub fn at_eof(&self) -> bool {
        self.eof
    }

    /// Takes client keystrokes. Completed input is appended to `to_child`,
    /// what the user should see to `echo`. After end of input only ^C is
    /// still recognised.
    pub fn input(&mut self, data: &[u8], to_child: &mut Vec<u8>, echo: &mut Vec<u8>) -> Events {
        let mut events = Events::default();
        // A contiguous insertion needs one tail redraw, including in the
        // middle of a line. Flush before edits/control keys to preserve order.
        let mut insertion: Option<(Vec<u8>, usize)> = None;
        for &raw in data {
            if self.swallow_lf { self.swallow_lf = false; if raw == b'\n' { continue; } }
            if self.refused {
                self.discarded = self.discarded.saturating_add(1);
                if !self.recovery.has_code() && matches!(raw, b'\r' | b'\n') { self.entropy_retry = true; }
                // Discard position belongs to the incoming stream, even
                // while a completed recovery is waiting for its pause ACK.
                if raw != CTRL_C { self.discard_partial = !matches!(raw, b'\r' | b'\n'); }
                let end = self.discard_end && self.marker.push(raw, paste::END).matched;
                if !self.discard_end && self.recovered && self.marker.push(raw, paste::BEGIN).matched {
                    // A new dropped BEGIN extends this visible refusal; its
                    // body cannot become ordinary lines after prompt rearm.
                    self.discard_end = true;
                    self.recovered = false;
                    self.entropy_retry = true;
                }
                if end || self.recovery.push(raw) {
                    self.latch_recovery_boundary();
                    if self.cancel_paused { self.recover(to_child, echo); events.interrupt = true; }
                }
                continue;
            }
            if (self.cancelled || self.discard_partial) && raw != CTRL_C {
                let notify = self.discard_partial && !self.cancelled && matches!(raw, b'\r' | b'\n');
                // Rearming a prompt cannot restore a discarded prefix. Keep
                // the whole physical line out, including a marker fragmented
                // across that rearm. A dropped BEGIN needs its matching END.
                if self.marker.push(raw, paste::BEGIN).matched {
                    self.capture = true;
                    self.refuse_input("paste arrived during cancellation", to_child, echo);
                    events.interrupt = true;
                } else {
                    self.discard_partial = !matches!(raw, b'\r' | b'\n');
                    if notify {
                        echo.extend_from_slice(b"\r\nterminal: input line discarded; enter it again\r\n");
                        self.redraw_prompt(echo);
                    }
                }
                continue;
            }
            let decoded = self.marker.push(raw, if self.capture || self.application_paste.is_some() { paste::END } else { paste::BEGIN });
            if decoded.matched {
                if let Some((old, cursor)) = insertion.take() { self.redraw(&old, cursor, echo); }
                if self.application_paste.is_some() {
                    if !self.utf8.is_empty() {
                        self.refuse_input("incomplete UTF-8 at application paste end", to_child, echo);
                        self.latch_recovery_boundary(); // This real END is the discard boundary.
                        events.interrupt = true;
                    } else if self.application_paste.take() == Some(true) {
                        self.application_marker(paste::END, to_child, echo, &mut events);
                        if self.refused { self.latch_recovery_boundary(); }
                    }
                } else if self.capture { self.end_paste(to_child, echo, &mut events); }
                else if self.prompt_mode != 0 && !self.plain_lines { self.begin_paste(); }
                else {
                    self.application_paste = Some(!self.plain_lines && self.application_brackets);
                    self.history_ineligible = true;
                    if !self.plain_lines && self.application_brackets { self.application_marker(paste::BEGIN, to_child, echo, &mut events); }
                }
                continue;
            }
            for &b in decoded.bytes() {
            if self.capture {
                if let Some((old, cursor)) = insertion.take() { self.redraw(&old, cursor, echo); }
                self.capture_byte(b, to_child, echo, &mut events);
                continue;
            }
            if (b < 0x20 || b == DEL)
                && let Some((old, cursor)) = insertion.take()
            {
                self.redraw(&old, cursor, echo);
            }
            if b == CTRL_C {
                // Wake a shell blocked reading a continuation prompt. An
                // application never receives this newline: prompt mode is
                // explicitly disarmed before executing any command.
                if self.application_paste.is_some() && !self.plain_lines {
                    self.refuse_input("application paste cancelled", to_child, echo);
                    events.application_interrupt = true;
                } else {
                    self.clear_input_for_pause(to_child);
                    self.discard_partial = false; // An explicit ordinary ^C.
                    self.marker.clear();
                }
                echo.extend_from_slice(b"^C\r\n");
                events.interrupt = true;
                continue;
            }
            if self.eof || self.cancelled {
                continue;
            }
            if !self.utf8.is_empty() && (b < 0x80 || b & 0xc0 != 0x80) {
                if let Some((old, cursor)) = insertion.take() { self.redraw(&old, cursor, echo); }
                self.refuse_input("invalid UTF-8", to_child, echo);
                events.interrupt = true;
                continue;
            }
            // Submission disarms the prompt immediately, even within this
            // batch. Conservatively exclude a draft that accepts any input
            // outside an armed primary prompt until completion/cancellation.
            if !self.prompt || self.prompt_mode != 1 || self.application_paste.is_some() {
                self.history_ineligible = true;
            }
            let in_sequence = match self.escape {
                Escape::None => false,
                _ if !(0x20..DEL).contains(&b) => {
                    self.escape = Escape::None;
                    false
                }
                Escape::Esc => {
                    self.escape = match b {
                        b'[' => Escape::Csi { first: true, param: 0 },
                        b'O' => Escape::Ss3,
                        _ => Escape::None,
                    };
                    true
                }
                Escape::Csi { first, param } => {
                    self.escape = if first && b == b'[' {
                        Escape::IgnoreOne
                    } else if (0x40..=0x7e).contains(&b) {
                        self.key(b, param, echo);
                        Escape::None
                    } else {
                        Escape::Csi { first: false, param: if b.is_ascii_digit() {
                            param.saturating_mul(10).saturating_add((b - b'0') as u16)
                        } else { u16::MAX } }
                    };
                    true
                }
                Escape::IgnoreOne => { self.escape = Escape::None; true }
                Escape::Ss3 => {
                    self.key(b, 0, echo);
                    self.escape = Escape::None;
                    true
                }
            };
            if in_sequence {
                continue;
            }
            if b == ESC {
                self.escape = Escape::Esc;
                continue;
            }
            if b < 0x80 { self.utf8.clear(); }
            match b {
                b'\r' | b'\n' => {
                    if self.prompt && self.prompt_mode == 1 && self.application_paste.is_none() && !self.history_ineligible && !self.line.is_empty() && self.history.last() != Some(&self.line) {
                        while self.history.len() >= HISTORY_LINES || self.history.iter().map(Vec::len).sum::<usize>() + self.line.len() > HISTORY_BYTES { self.history.remove(0); }
                        self.history.push(self.line.clone());
                    }
                    self.prompt = false;
                    self.history_ineligible = false;
                    self.history_at = None;
                    self.draft.clear();
                    self.cursor = 0;
                    if self.staged_active {
                        self.swallow_lf = b == b'\r';
                        self.staged.append(&mut self.line);
                        if !self.staged.ends_with(b"\n") { self.staged.push(b'\n'); }
                        if self.staged.len() > paste::MAX_SOURCE || self.external_pending + self.staged.len() > paste::MAX_QUEUED {
                            self.refuse_input("paste source budget exceeded", to_child, echo); events.interrupt = true;
                        } else {
                            to_child.extend_from_slice(&paste::record::header(self.staged.len()));
                            to_child.append(&mut self.staged);
                            self.staged_active = false;
                        }
                    } else {
                        to_child.append(&mut self.line);
                        to_child.push(b'\n');
                    }
                    echo.extend_from_slice(b"\r\n");
                }
                CTRL_D if self.staged_active => {
                    self.refuse_input("unapproved paste cancelled by EOF", to_child, echo);
                    events.interrupt = true;
                }
                CTRL_D if self.line.is_empty() => {
                    self.eof = true;
                    events.eof = true;
                }
                CTRL_D => {
                    to_child.append(&mut self.line);
                    self.cursor = 0;
                    // This was not a submitted line: readline still waits
                    // for newline, so a later prompt ^C must wake it.
                },
                DEL | BS => {
                    self.erase_char(echo);
                }
                CTRL_U => {
                    self.move_to(self.line.len(), echo);
                    while self.erase_char(echo) {}
                }
                0x17 => {
                    while self.cursor > 0 && self.line[self.cursor - 1].is_ascii_whitespace() { self.erase_char(echo); }
                    while self.cursor > 0 && !self.line[self.cursor - 1].is_ascii_whitespace() { self.erase_char(echo); }
                }
                _ if self.line.len() >= MAX_LINE => {
                    if let Some((old, cursor)) = insertion.take() { self.redraw(&old, cursor, echo); }
                    self.refuse_input(&format!("input line exceeds {MAX_LINE} bytes"), to_child, echo);
                    events.interrupt = true;
                }
                c => {
                    if c >= 0x80 {
                        if c & 0xc0 != 0x80 { self.utf8.clear(); }
                        self.utf8.push(c);
                        match std::str::from_utf8(&self.utf8) {
                            Ok(_) => {}
                            Err(e) if e.error_len().is_none() && self.utf8.len() < 4 => continue,
                            Err(_) => {
                                if let Some((old, cursor)) = insertion.take() { self.redraw(&old, cursor, echo); }
                                self.refuse_input("invalid UTF-8", to_child, echo);
                                events.interrupt = true;
                                continue;
                            }
                        }
                    } else { self.utf8.clear(); }
                    let bytes = if c >= 0x80 { std::mem::take(&mut self.utf8) } else { vec![c] };
                    if self.line.len() + bytes.len() > MAX_LINE
                        || self.staged.len() + self.line.len() + bytes.len() >= paste::MAX_SOURCE {
                        if let Some((old, cursor)) = insertion.take() { self.redraw(&old, cursor, echo); }
                        self.refuse_input(&format!("input line exceeds {MAX_LINE} bytes"), to_child, echo);
                        events.interrupt = true;
                        continue;
                    }
                    if insertion.is_none() { insertion = Some((self.line.clone(), self.cursor)); }
                    self.line.splice(self.cursor..self.cursor, bytes.iter().copied());
                    self.cursor += bytes.len();
                }

            }
        }
        }
        if let Some((old, cursor)) = insertion { self.redraw(&old, cursor, echo); }
        events
    }

    /// Observe only the terminal's public bracketed-paste request. This does
    /// not infer shell prompt state. The bounded prefix survives output chunks.
    pub fn child_output(&mut self, bytes: &[u8]) {
        const PREFIX: &[u8] = b"\x1b[?2004";
        for &b in bytes {
            if self.output_marker_len == PREFIX.len() {
                if b == b'h' { self.application_brackets = true; }
                else if b == b'l' { self.application_brackets = false; }
                self.output_marker_len = usize::from(b == PREFIX[0]);
            } else if b == PREFIX[self.output_marker_len] {
                self.output_marker_len += 1;
            } else { self.output_marker_len = usize::from(b == PREFIX[0]); }
        }
    }

    // Preserve the requested delimiters literally inside the existing cooked
    // editing line. They are not shell source framing or terminal edit keys.
    fn application_marker(&mut self, bytes: &[u8], to_child: &mut Vec<u8>, echo: &mut Vec<u8>, events: &mut Events) {
        if !self.utf8.is_empty() || self.line.len() + bytes.len() > MAX_LINE {
            // END has already closed the block; no further END is required.
            self.refuse_input("application paste marker exceeds input line or splits UTF-8", to_child, echo);
            events.interrupt = true;
            return;
        }
        let old = self.line.clone();
        let old_cursor = self.cursor;
        self.line.splice(self.cursor..self.cursor, bytes.iter().copied());
        self.cursor += bytes.len();
        self.redraw(&old, old_cursor, echo);
    }

    /// Prompt mode is owned by the shell, never inferred from terminal output.
    /// Proposed same-session policy: mode changes preserve the editing state;
    /// sticky draft ineligibility prevents application input entering history.
    pub fn set_prompt(&mut self, prompt: bool) { self.set_prompt_mode(u8::from(prompt)); }

    /// 0 application, 1 primary, 2 continuation, 3 acknowledged shell read.
    pub fn set_prompt_mode(&mut self, mode: u8) {
        if mode == 3 { self.prompt = false; return; }
        if self.cancelled {
            if mode == 0 { self.cancel_paused = true; }
            else if matches!(mode, 1 | 2) && self.cancel_paused && !self.refused {
                self.cancelled = false;
                self.cancel_paused = false;
            }
        }
        if mode == 0 {
            // The server disables public bracketed paste before program
            // execution. A new application must make its own request. An
            // already-open application paste retains its selected policy.
            self.application_brackets = false;
            self.output_marker_len = 0;
        }
        let prompt = matches!(mode, 1 | 2);
        self.prompt = prompt;
        self.prompt_mode = if prompt { mode } else { 0 };
    }

    /// Cancellation covers queued complete lines as well as the editing draft.
    /// The receiver pauses and drains its pipe before rearming input.
    fn clear_input_for_pause(&mut self, to_child: &mut Vec<u8>) {
        let wake = matches!(self.prompt_mode, 1 | 2) && !self.eof;
        to_child.clear();
        if wake { to_child.push(b'\n'); }
        self.line.clear();
        self.staged.clear();
        self.suffix.clear();
        self.capture = false;
        self.application_paste = None;
        self.staged_active = false;
        // Stream-owned discard_partial and marker prefix survive recovery.
        self.utf8.clear();
        self.cursor = 0;
        self.escape = Escape::None;
        self.history_at = None;
        self.draft.clear();
        self.history_ineligible = false;
        self.prompt = false;
        self.cancelled = true;
        self.cancel_paused = false;
    }

    pub fn input_cancelled(&self) -> bool { self.cancelled }
    pub fn input_refused(&self) -> bool { self.refused }

    pub fn refuse_input(&mut self, reason: &str, to_child: &mut Vec<u8>, echo: &mut Vec<u8>) {
        let capture = self.capture || self.application_paste.is_some();
        self.clear_input_for_pause(to_child);
        self.marker.clear();
        self.refused = true;
        self.discard_end = capture;
        self.recovery = paste::Recovery::default();
        self.recovered = false;
        self.entropy_retry = true;
        self.discarded = 0;
        echo.extend_from_slice(b"\r\nterminal: ");
        echo.extend_from_slice(reason.as_bytes());
        echo.extend_from_slice(if self.plain_lines {
            b"; input discarded; press Ctrl-C to recover\r\n"
        } else {
            b"; input discarded; recovery required\r\n"
        });
    }

    /// A direct exec has no shell control channel. The connection owns its
    /// paused stdin producer and releases cancellation after code recovery.
    /// Preserve any partially discarded tail until its physical line end.
    pub fn resume_application_input(&mut self) {
        if self.refused { return; }
        self.cancelled = false;
        self.cancel_paused = false;
        self.prompt = false;
        self.prompt_mode = 0;
    }

    pub fn needs_recovery_code(&self) -> bool { self.refused && !self.recovery.has_code() && !self.recovered && self.entropy_retry }

    pub fn recovery_code(&mut self, random: [u8; 8], echo: &mut Vec<u8>) {
        if !self.needs_recovery_code() { return; }
        let code = self.recovery.install(random);
        echo.extend_from_slice(b"terminal: type ");
        echo.extend_from_slice(&code);
        echo.extend_from_slice(b" then Enter to discard stale input and recover\r\n");
    }

    pub fn recovery_unavailable(&mut self, echo: &mut Vec<u8>) {
        self.entropy_retry = false;
        echo.extend_from_slice(b"terminal: recovery entropy unavailable; input remains discarded; press Enter to retry\r\n");
    }

    pub fn pending_source_bytes(&mut self, bytes: usize) { self.external_pending = bytes; }

    /// A mode-1 rearm after an acknowledged drain may complete a recovery
    /// that arrived early. The Connection sends an interrupt/wake again.
    pub fn finish_recovery(&mut self, to_child: &mut Vec<u8>, echo: &mut Vec<u8>) -> bool {
        if self.refused && self.recovered && self.cancel_paused {
            self.recover(to_child, echo); true
        } else { false }
    }

    fn latch_recovery_boundary(&mut self) {
        self.recovered = true;
        self.discard_end = false;
        self.discard_partial = false;
        self.marker.clear();
    }

    fn recover(&mut self, to_child: &mut Vec<u8>, echo: &mut Vec<u8>) {
        // Keep cancellation latched until a subsequent pause/drain/rearm.
        self.refused = false;
        self.recovered = false;
        self.discard_end = false;
        self.recovery = paste::Recovery::default();
        self.clear_input_for_pause(to_child);
        echo.extend_from_slice(format!("\r\nterminal: discarded at least {} terminal bytes; input recovered\r\n", self.discarded).as_bytes());
    }

    fn begin_paste(&mut self) {
        self.capture = true;
        self.staged_active = true;
        self.paste_cr = false;
        self.suffix = self.line.split_off(self.cursor);
        self.escape = Escape::None;
        self.history_ineligible = true;
        self.history_at = None;
        self.draft.clear();
    }

    fn capture_byte(&mut self, b: u8, to_child: &mut Vec<u8>, echo: &mut Vec<u8>, events: &mut Events) {
        if b == CTRL_C || b == CTRL_D {
            self.refuse_input("paste cancelled before approval", to_child, echo);
            events.interrupt = true; return;
        }
        if self.paste_cr && b == b'\n' { self.paste_cr = false; return; }
        self.paste_cr = b == b'\r';
        if b == b'\n' || b == b'\r' {
            if !self.utf8.is_empty() {
                self.refuse_input("invalid UTF-8 in paste", to_child, echo); events.interrupt = true; return;
            }
            if self.staged.len() + self.line.len() + self.suffix.len() + 1 >= paste::MAX_SOURCE
                || self.external_pending + self.staged.len() + self.line.len() + self.suffix.len() + 1 > paste::MAX_QUEUED {
                self.refuse_input("paste source exceeds 1 MiB", to_child, echo); events.interrupt = true; return;
            }
            self.staged.append(&mut self.line); self.staged.push(b'\n'); self.cursor = 0;
            echo.extend_from_slice(b"\r\n"); return;
        }
        self.utf8.push(b);
        match std::str::from_utf8(&self.utf8) {
            Ok(_) => {},
            Err(e) if e.error_len().is_none() && self.utf8.len() < 4 => return,
            Err(_) => { self.refuse_input("invalid UTF-8 in paste", to_child, echo); events.interrupt = true; return; }
        }
        if self.line.len() + self.utf8.len() > MAX_LINE
            || self.staged.len() + self.line.len() + self.utf8.len() + self.suffix.len() >= paste::MAX_SOURCE
            || self.external_pending + self.staged.len() + self.line.len() + self.utf8.len() + self.suffix.len() > paste::MAX_QUEUED {
            self.refuse_input("paste line/source limit exceeded", to_child, echo); events.interrupt = true; return;
        }
        Self::show(&self.utf8, echo);
        self.line.append(&mut self.utf8); self.cursor = self.line.len();
    }

    fn end_paste(&mut self, to_child: &mut Vec<u8>, echo: &mut Vec<u8>, events: &mut Events) {
        if self.line.len() + self.suffix.len() > MAX_LINE {
            self.refuse_input("composed paste line exceeds 65536 bytes", to_child, echo);
            self.latch_recovery_boundary(); events.interrupt = true; return;
        }
        if !self.utf8.is_empty() {
            self.refuse_input("incomplete UTF-8 at paste end", to_child, echo);
            self.latch_recovery_boundary(); events.interrupt = true; return;
        }
        self.capture = false;
        Self::show(&self.suffix, echo);
        echo.extend(std::iter::repeat_n(BS, Self::columns(&self.suffix)));
        self.line.append(&mut self.suffix);
    }

    /// Channel EOF must not silently drop an incomplete UTF-8 prefix.
    pub fn finish_input(&mut self, to_child: &mut Vec<u8>, echo: &mut Vec<u8>) -> Events {
        if !self.cancelled && (self.staged_active || !self.utf8.is_empty()) {
            let reason = if self.staged_active { "unapproved paste at end of input" } else { "incomplete UTF-8 at end of input" };
            self.refuse_input(reason, to_child, echo);
            Events { interrupt: true, ..Events::default() }
        } else { Events::default() }
    }

    /// Restore the actual shell prompt and unfinished input after switching
    /// local text sessions. Application/login input never fabricates a prompt.
    pub fn redraw_prompt(&self, echo: &mut Vec<u8>) {
        if !self.prompt { return; }
        echo.extend_from_slice(if self.prompt_mode == 2 { b"> " } else { b"absd$ " });
        Self::show(&self.line, echo);
        echo.extend(std::iter::repeat_n(BS, Self::columns(&self.line[self.cursor..])));
    }

    fn previous(&self, at: usize) -> usize {
        let mut pos = at.saturating_sub(1);
        while pos > 0 && self.line[pos] & 0xc0 == 0x80 { pos -= 1; }
        pos
    }

    fn next(&self, at: usize) -> usize {
        let mut pos = (at + 1).min(self.line.len());
        while pos < self.line.len() && self.line[pos] & 0xc0 == 0x80 { pos += 1; }
        pos
    }

    fn columns(bytes: &[u8]) -> usize {
        bytes.iter().filter(|&&b| b & 0xc0 != 0x80).map(|&b| width(&[b])).sum()
    }

    fn show(bytes: &[u8], echo: &mut Vec<u8>) {
        for &b in bytes {
            if b < 0x20 { echo.extend_from_slice(&[b'^', b + 0x40]); }
            else { echo.push(b); }
        }
    }

    fn move_to(&mut self, to: usize, echo: &mut Vec<u8>) {
        if to < self.cursor {
            echo.extend(std::iter::repeat_n(BS, Self::columns(&self.line[to..self.cursor])));
        } else {
            Self::show(&self.line[self.cursor..to], echo);
        }
        self.cursor = to;
    }

    fn redraw(&self, old: &[u8], old_cursor: usize, echo: &mut Vec<u8>) {
        // Leave the common prefix untouched; append-at-end stays cheap and
        // preserves the byte stream of a UTF-8 character arriving in pieces.
        let mut start = old.iter().zip(&self.line).take_while(|(a,b)| a == b).count();
        start = start.min(old_cursor).min(self.cursor);
        while start > 0 && start < self.line.len() && self.line[start] & 0xc0 == 0x80 { start -= 1; }
        echo.extend(std::iter::repeat_n(BS, Self::columns(&old[start..old_cursor])));
        Self::show(&self.line[start..], echo);
        let erased = Self::columns(&old[start..]).saturating_sub(Self::columns(&self.line[start..]));
        echo.extend(std::iter::repeat_n(b' ', erased));
        echo.extend(std::iter::repeat_n(BS, erased + Self::columns(&self.line[self.cursor..])));
    }

    fn delete(&mut self, echo: &mut Vec<u8>) -> bool {
        if self.cursor == self.line.len() { return false; }
        let old = self.line.clone();
        self.line.drain(self.cursor..self.next(self.cursor));
        self.redraw(&old, self.cursor, echo);
        true
    }

    fn erase_char(&mut self, echo: &mut Vec<u8>) -> bool {
        if self.cursor == 0 { return false; }
        let old = self.line.clone();
        let old_cursor = self.cursor;
        let start = self.previous(self.cursor);
        self.line.drain(start..self.cursor);
        self.cursor = start;
        self.redraw(&old, old_cursor, echo);
        true
    }

    fn key(&mut self, key: u8, param: u16, echo: &mut Vec<u8>) {
        match (key, param) {
            (b'D', 0 | 1) => self.move_to(self.previous(self.cursor), echo),
            (b'C', 0 | 1) => self.move_to(self.next(self.cursor), echo),
            (b'H', 0 | 1) | (b'~', 1 | 7) => self.move_to(0, echo),
            (b'F', 0 | 1) | (b'~', 4 | 8) => self.move_to(self.line.len(), echo),
            (b'~', 3) => { self.delete(echo); },
            (b'A' | b'B', 0 | 1) if self.prompt => {
                if self.history.is_empty() || (key == b'B' && self.history_at.is_none()) { return; }
                let at = match (key, self.history_at) {
                    (b'A', None) if !self.history.is_empty() => {
                        self.draft = self.line.clone();
                        Some(self.history.len() - 1)
                    }
                    (b'A', Some(at)) => Some(at.saturating_sub(1)),
                    (b'B', Some(at)) if at + 1 < self.history.len() => Some(at + 1),
                    _ => None,
                };
                let old = self.line.clone();
                let old_cursor = self.cursor;
                self.line = at.map_or_else(|| self.draft.clone(), |at| self.history[at].clone());
                self.history_at = at;
                self.cursor = self.line.len();
                self.redraw(&old, old_cursor, echo);
            }
            _ => {}
        }
    }

}

/// Output post-processing: every LF becomes CR LF. At most doubles `data`.
pub fn output(data: &[u8], out: &mut Vec<u8>) {
    for &b in data {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(ld: &mut LineDiscipline, data: &[u8]) -> (Vec<u8>, Vec<u8>, Events) {
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        let ev = ld.input(data, &mut child, &mut echo);
        (child, echo, ev)
    }

    #[test]
    fn line_editing_and_echo() {
        let mut ld = LineDiscipline::new();
        let (child, echo, ev) = feed(&mut ld, b"lx\x7fs /\r");
        assert_eq!(child, b"ls /\n");
        assert_eq!(echo, b"lx\x08 \x08s /\r\n");
        assert_eq!(ev, Events::default());
        let (child, echo, _) = feed(&mut ld, b"ab\x08c\n");
        assert_eq!((child.as_slice(), echo.as_slice()), (&b"ac\n"[..], &b"ab\x08 \x08c\r\n"[..]));
    }

    #[test]
    fn partial_lines_stay_until_the_end_of_line() {
        let mut ld = LineDiscipline::new();
        let (child, _, _) = feed(&mut ld, b"pw");
        assert!(child.is_empty());
        let (child, _, _) = feed(&mut ld, b"d\r");
        assert_eq!(child, b"pwd\n");
    }

    #[test]
    fn erase_line_utf8_and_control_characters() {
        let mut ld = LineDiscipline::new();
        let (child, echo, _) = feed(&mut ld, "é\x01x\x15ok\r".as_bytes());
        assert_eq!(child, b"ok\n");
        // é: one column; ^A two; x one.
        assert_eq!(echo, ["é^Ax".as_bytes(), b"\x08 \x08\x08\x08  \x08\x08\x08 \x08", b"ok\r\n"].concat());
        let (_, echo, _) = feed(&mut ld, b"\x7f\x15");
        assert!(echo.is_empty(), "nothing to erase");
    }

    #[test]
    fn end_of_input() {
        let mut ld = LineDiscipline::new();
        let (child, _, ev) = feed(&mut ld, b"abc\x04");
        assert_eq!((child.as_slice(), ev.eof), (&b"abc"[..], false));
        let (child, echo, ev) = feed(&mut ld, b"\x04more\r");
        assert!(ev.eof && ld.at_eof() && child.is_empty() && echo.is_empty());
        let (_, echo, ev) = feed(&mut ld, b"\x03");
        assert!(ev.interrupt && !ev.eof);
        assert_eq!(echo, b"^C\r\n");
    }

    #[test]
    fn interrupt_discards_the_line() {
        let mut ld = LineDiscipline::new();
        let (child, echo, ev) = feed(&mut ld, b"sleep\x03ok\r");
        assert!(ev.interrupt);
        assert!(child.is_empty(), "same-batch tail is cancelled until pause and rearm");
        assert_eq!(echo, b"sleep^C\r\n");
    }

    #[test]
    fn cursor_insertion_delete_home_end_and_word_erase() {
        let mut ld = LineDiscipline::new();
        let (child, _, _) = feed(&mut ld, b"ac\x1b[Db\x1b[H!\x1b[F?\x1b[D\x1b[3~\r");
        assert_eq!(child, b"!abc\n");
        let (child, _, _) = feed(&mut ld, b"keep two words\x17\x17ok\r");
        assert_eq!(child, b"keep ok\n");
        feed(&mut ld, b"ab\x1b[");
        let (child, _, _) = feed(&mut ld, b"Dx\r");
        assert_eq!(child, b"axb\n");
    }

    #[test]
    fn history_only_at_prompt_and_never_next_application_input() {
        let mut ld = LineDiscipline::new();
        feed(&mut ld, b"login-secret\r");
        ld.set_prompt(true);
        let (child, _, _) = feed(&mut ld, b"echo public\rprivate input\r");
        assert_eq!(child, b"echo public\nprivate input\n");
        assert_eq!(ld.history, [b"echo public".to_vec()]);
        ld.set_prompt(true);
        let (child, _, _) = feed(&mut ld, b"\x1b[A\r");
        assert_eq!(child, b"echo public\n");
        feed(&mut ld, b"unfinished secret");
        ld.set_prompt(true);
        let (child, _, _) = feed(&mut ld, b"draft\x1b[A\x1b[B\r");
        // Proposed narrowing: the accepted base purged this prefix.
        // It now stays executable, but recall/rearm must not retain it.
        assert_eq!(child, b"unfinished secretdraft\n");
        assert!(!ld.history.iter().any(|v| v.starts_with(b"unfinished")));
        let mut other = LineDiscipline::new();
        other.set_prompt(true);
        assert_eq!(feed(&mut other, b"draft\x1b[A\x1b[B\r").0, b"draft\n");
        ld.set_prompt(true);
        assert_eq!(feed(&mut ld, b"keep\x1b[B\r").0, b"keep\n");
        ld.set_prompt(true);
        assert_eq!(feed(&mut ld, b"ec\x1b[[Aho\r").0, b"echo\n");
    }

    #[test]
    fn bounded_history_and_interrupt_do_not_capture_input() {
        let mut ld = LineDiscipline::new();
        for n in 0..40 {
            ld.set_prompt(true);
            feed(&mut ld, format!("echo {n}\r").as_bytes());
        }
        assert_eq!(ld.history.len(), HISTORY_LINES);
        assert_eq!(ld.history[0], b"echo 8");
        ld.set_prompt(true);
        feed(&mut ld, b"cancelled\x03\r");
        assert!(!ld.history.iter().any(|v| v == b"cancelled"));
    }

    #[test]
    fn long_history_keeps_the_existing_text_budget() {
        let mut ld = LineDiscipline::new();
        for n in 0..3 {
            let mut line = format!("{n:08}").into_bytes();
            line.resize(MAX_LINE, b'x'); line.push(b'\r');
            ld.set_prompt_mode(1); feed(&mut ld, &line);
        }
        assert!(ld.history.iter().map(Vec::len).sum::<usize>() <= HISTORY_BYTES);
        assert_eq!(ld.history.len(), HISTORY_BYTES / MAX_LINE);
        assert!(ld.history.last().unwrap().starts_with(b"00000002"));
    }

    #[test]
    fn overlong_lines_refuse_the_terminal_even_after_rearm() {
        let mut ld = LineDiscipline::new();
        let (child, echo, event) = feed(&mut ld, &[b'a'; MAX_LINE + 10]);
        assert!(child.is_empty() && event.interrupt);
        assert!(String::from_utf8_lossy(&echo).contains(&format!("input line exceeds {MAX_LINE} bytes")));
        assert!(feed(&mut ld, b"\rnext command\r").0.is_empty());
        ld.set_prompt_mode(0); ld.set_prompt_mode(1);
        assert!(feed(&mut ld, b"late suffix\r").0.is_empty());
        let mut fresh = LineDiscipline::new(); fresh.set_prompt_mode(1);
        assert_eq!(feed(&mut fresh, b"fresh\r").0, b"fresh\n");
    }

    #[test]
    fn malformed_paste_cannot_resume_as_a_suffix_after_prompt_rearm() {
        let mut ld = LineDiscipline::new();
        ld.set_prompt_mode(1);
        let (_, _, event) = feed(&mut ld, &[b'x'; MAX_LINE + 1]);
        assert!(event.interrupt);
        ld.set_prompt_mode(0); ld.set_prompt_mode(1);
        let (child, _, _) = feed(&mut ld, b"echo changed-meaning > /victim\r");
        assert!(child.is_empty(), "refusal resumed before the malformed paste had ended");
    }

    #[test]
    fn invalid_utf8_refuses_whole_input_at_definitive_boundaries() {
        for suffix in [b"\n".as_slice(), b"a", b"\xc3", b"\x04"] {
            let mut ld = LineDiscipline::new();
            feed(&mut ld, b"echo prefix\xc3");
            let (child, echo, event) = feed(&mut ld, suffix);
            assert!(child.is_empty() && event.interrupt, "suffix={suffix:?}");
            assert!(String::from_utf8_lossy(&echo).contains("invalid UTF-8"));
            assert!(feed(&mut ld, b"remaining bytes\r").0.is_empty());
        }
        let mut ld = LineDiscipline::new();
        feed(&mut ld, b"echo prefix\xc3");
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        assert!(ld.finish_input(&mut child, &mut echo).interrupt);
        assert!(child.is_empty());
        assert!(String::from_utf8_lossy(&echo).contains("incomplete UTF-8 at end of input"));
    }

    #[test]
    fn exact_fit_utf8_is_accepted_but_a_whole_codepoint_overflow_is_refused() {
        let mut ld = LineDiscipline::new();
        let valid = format!("{}é\r", "a".repeat(MAX_LINE - 2));
        assert_eq!(feed(&mut ld, valid.as_bytes()).0.len(), MAX_LINE + 1);
        let mut ld = LineDiscipline::new();
        let invalid = format!("{}é\r", "a".repeat(MAX_LINE - 1));
        let (child, echo, event) = feed(&mut ld, invalid.as_bytes());
        assert!(child.is_empty() && event.interrupt);
        assert!(String::from_utf8_lossy(&echo).contains("exceeds"));
    }

    #[test]
    fn output_translation() {
        let mut out = Vec::new();
        output(b"a\nb\r\n\n", &mut out);
        assert_eq!(out, b"a\r\nb\r\r\n\r\n");
    }
}

/// Reported terminal metadata, independent of the input discipline.
#[path = "../../runtime/src/terminal_wire.rs"]
pub mod terminal_wire;
#[derive(Clone, Debug)]
pub struct Terminal {
    pub size: terminal_wire::Size,
    pub term: Option<String>,
}
impl Terminal {
    pub fn ssh(term: &str, columns: u32, rows: u32) -> Self {
        Self { size: terminal_wire::Size { columns, rows, source: terminal_wire::SSH }.bounded(), term: if !term.is_empty() && term.len() <= 64 && term.bytes().all(|c| c.is_ascii_alphanumeric() || b"_.+-".contains(&c)) { Some(term.into()) } else { None } }
    }
    pub fn local_fixed() -> Self { Self { size: terminal_wire::Size::local_fixed(), term: Some("dumb".into()) } }
}

#[cfg(test)]
mod terminal_tests {
    use super::*;
    #[test]
    fn actual_metadata_is_not_replaced_with_defaults() {
        let t = Terminal::ssh("xterm-256color", 173, 51);
        assert_eq!(t.term.as_deref(), Some("xterm-256color"));
        assert_eq!((t.size.columns, t.size.rows, t.size.source), (173, 51, terminal_wire::SSH));
        let unknown = Terminal::ssh("bad TERM\x1b", 0, 0);
        assert_eq!(unknown.term, None);
        assert_eq!((unknown.size.columns, unknown.size.rows), (0,0));
    }
    #[test]
    fn redraw_keeps_visible_text_and_cursor_consistent() {
        let mut ld = LineDiscipline::new();
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        ld.input(b"abdef\x1b[D\x1b[D\x1b[Dc\x1b[F\x7f\x1b[H\x1b[3~", &mut child, &mut echo);
        // A separate minimal screen consumer executes the emitted backspaces
        // and overwrite, rather than mirroring the editing implementation.
        let (mut screen, mut cursor) = (Vec::new(), 0usize);
        for byte in echo {
            if byte == 8 { cursor = cursor.saturating_sub(1); }
            else {
                if cursor == screen.len() { screen.push(byte); } else { screen[cursor] = byte; }
                cursor += 1;
            }
        }
        assert_eq!(screen, b"bcde  ");
        assert_eq!(cursor, 0);
        assert_eq!(ld.line, b"bcde");
    }
    #[test]
    fn utf8_character_at_middle_is_not_torn_by_redraw() {
        let mut ld = LineDiscipline::new();
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        ld.input("ac\x1b[Dé\r".as_bytes(), &mut child, &mut echo);
        assert_eq!(child, "aéc\n".as_bytes());
        assert!(std::str::from_utf8(&echo).is_ok());
    }
}

#[cfg(test)]
mod prompt_interrupt_tests {
    use super::*;
    #[test]
    fn prompt_interrupt_wakes_read_but_program_interrupt_does_not_inject_input() {
        let mut terminal = LineDiscipline::new();
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        terminal.set_prompt(true);
        let event = terminal.input(b"cancelled\x03", &mut child, &mut echo);
        assert!(event.interrupt);
        assert_eq!(child, b"\n");
        assert!(terminal.history.is_empty());
        child.clear();
        terminal.set_prompt(false);
        let event = terminal.input(b"private stdin\x03", &mut child, &mut echo);
        assert!(event.interrupt);
        assert!(child.is_empty());
    }
}

#[cfg(test)]
mod prompt_restore_tests {
    use super::*;
    #[test]
    fn restore_actual_primary_or_continuation_prompt_and_cursor_only() {
        let mut ld = LineDiscipline::new();
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        ld.input(b"private application input", &mut child, &mut echo);
        echo.clear();
        ld.redraw_prompt(&mut echo);
        assert!(echo.is_empty());
        ld.set_prompt_mode(2);
        ld.input(b"abc\x1b[D", &mut child, &mut echo);
        echo.clear();
        ld.redraw_prompt(&mut echo);
        assert_eq!(echo, b"> private application inputabc\x08");
        ld.set_prompt_mode(0);
        echo.clear();
        ld.redraw_prompt(&mut echo);
        assert!(echo.is_empty());
        ld.set_prompt_mode(1);
        ld.redraw_prompt(&mut echo);
        assert_eq!(echo, b"absd$ private application inputabc\x08");
    }
}

#[cfg(test)]
mod prompt_paste_regressions {
    use super::*;
    #[test]
    fn partial_eof_keeps_prompt_interrupt_wakeup_in_both_prompt_modes() {
        for mode in [1,2] {
            let mut ld=LineDiscipline::new(); ld.set_prompt_mode(mode);
            let (mut child,mut echo)=(Vec::new(),Vec::new());
            ld.input(b"partial\x04",&mut child,&mut echo);
            assert_eq!(child,b"partial"); assert!(!ld.at_eof());
            child.clear(); let event=ld.input(b"\x03",&mut child,&mut echo);
            assert!(event.interrupt); assert_eq!(child,b"\n");
        }
    }
    #[test]
    fn middle_paste_has_bounded_echo_and_keeps_all_accepted_bytes_and_cursor() {
        let mut ld=LineDiscipline::new();
        let (mut child,mut echo)=(Vec::new(),Vec::new());
        ld.input(&vec![b'a';2000],&mut child,&mut echo);
        ld.input(b"\x1b[H",&mut child,&mut echo); echo.clear();
        ld.input(&vec![b'b';2000],&mut child,&mut echo);
        assert!(echo.len()<=2*MAX_LINE,"middle paste generated {} echo bytes",echo.len());
        assert_eq!(ld.cursor,2000);
        assert_eq!(ld.line,[vec![b'b';2000],vec![b'a';2000]].concat());
        ld.input(b"\r",&mut child,&mut echo);
        assert_eq!(child,[vec![b'b';2000],vec![b'a';2000],vec![b'\n']].concat());
    }
}

#[cfg(test)]
mod same_session_typeahead_proposed_tests {
    use super::*;
    fn feed(ld: &mut LineDiscipline, bytes: &[u8]) -> (Vec<u8>, Vec<u8>, Events) {
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        let events = ld.input(bytes, &mut child, &mut echo);
        (child, echo, events)
    }
    #[test]
    fn observed_3707_prefix_rearm_383_suffix_preserves_command_and_not_history() {
        let command = [b"echo ".to_vec(), vec![b'C'; 4090]].concat();
        for chunk in [1, 7, 128, 256, 3712] {
            let mut ld = LineDiscipline::new();
            ld.set_prompt_mode(1);
            let previous = [b"echo ".to_vec(), vec![b'B'; 4090]].concat();
            let initial = [previous.clone(), vec![b'\r'], command[..3712].to_vec()].concat();
            let (mut submitted, mut echoed) = (Vec::new(), Vec::new());
            for part in initial.chunks(chunk) {
                let (child, echo, _) = feed(&mut ld, part);
                submitted.extend(child); echoed.extend(echo);
            }
            assert_eq!(submitted, [previous.clone(), vec![b'\n']].concat());
            ld.set_prompt_mode(0); ld.set_prompt_mode(1);
            for part in command[3712..].chunks(chunk) {
                let (child, echo, _) = feed(&mut ld, part);
                assert!(child.is_empty()); echoed.extend(echo);
            }
            let (child, echo, _) = feed(&mut ld, b"\r"); echoed.extend(echo);
            assert_eq!(child, [command.clone(), vec![b'\n']].concat(), "chunk={chunk}");
            assert_eq!(echoed, [previous.clone(), b"\r\n".to_vec(), command.clone(), b"\r\n".to_vec()].concat());
            assert_eq!(ld.history, [previous]);
        }
    }
    #[test]
    fn mode_changes_preserve_cursor_split_utf8_and_escape() {
        let mut ld = LineDiscipline::new(); ld.set_prompt_mode(1);
        feed(&mut ld, b"ac\x1b["); ld.set_prompt_mode(0);
        feed(&mut ld, b"D\xc3"); ld.set_prompt_mode(2); ld.set_prompt_mode(1);
        assert_eq!(feed(&mut ld, b"\xa9\r").0, "aéc\n".as_bytes());
        assert!(ld.history.is_empty());
    }
    #[test]
    fn rearming_and_history_recall_never_promote_application_or_continuation_draft() {
        let mut ld = LineDiscipline::new(); ld.set_prompt_mode(1);
        feed(&mut ld, b"public\r"); feed(&mut ld, b"private");
        ld.set_prompt_mode(1);
        assert_eq!(feed(&mut ld, b"\x1b[A\x1b[B tail\r").0, b"private tail\n");
        assert_eq!(ld.history, [b"public".to_vec()]);
        ld.set_prompt_mode(2); feed(&mut ld, b"continuation");
        ld.set_prompt_mode(1); feed(&mut ld, b"\r");
        assert_eq!(ld.history, [b"public".to_vec()]);
        ld.set_prompt_mode(1); feed(&mut ld, b"next public\r");
        assert_eq!(ld.history, [b"public".to_vec(), b"next public".to_vec()]);
    }
    #[test]
    fn mode_only_changes_preserve_primary_eligibility_but_editing_cannot_launder_taint() {
        let mut ld = LineDiscipline::new(); ld.set_prompt_mode(1);
        feed(&mut ld, b"public"); ld.set_prompt_mode(0); ld.set_prompt_mode(2); ld.set_prompt_mode(1);
        feed(&mut ld, b"\r"); assert_eq!(ld.history, [b"public".to_vec()]);
        feed(&mut ld, b"private"); ld.set_prompt_mode(1);
        feed(&mut ld, b"\x15replacement\r");
        assert_eq!(ld.history, [b"public".to_vec()], "erase/retype promoted an ineligible draft");
    }
    #[test]
    fn cancel_eof_and_fresh_session_keep_cleanup_and_no_history_promotion() {
        let mut ld = LineDiscipline::new(); feed(&mut ld, b"private");
        ld.set_prompt_mode(1);
        let (child, _, events) = feed(&mut ld, b"\x03");
        assert!(events.interrupt); assert_eq!(child, b"\n");
        assert!(ld.line.is_empty() && ld.utf8.is_empty());
        ld.set_prompt_mode(0); ld.set_prompt_mode(1);
        feed(&mut ld, b"public\r");
        assert_eq!(ld.history, [b"public".to_vec()]);
        feed(&mut ld, b"private\x04"); ld.set_prompt_mode(1); feed(&mut ld, b"tail\r");
        assert_eq!(ld.history, [b"public".to_vec()]);
        let (_, _, events) = feed(&mut ld, b"\x04"); assert!(events.eof);
        ld.set_prompt_mode(1); assert!(feed(&mut ld, b"ignored\r").0.is_empty());
        drop(ld);
        let mut fresh = LineDiscipline::new(); fresh.set_prompt_mode(1);
        assert_eq!(feed(&mut fresh, b"\x1b[A\r").0, b"\n");
    }
}

#[cfg(test)]
mod read_fence_regressions {
    use super::*;

    #[test]
    fn fenced_full_size_paste_keeps_every_byte() {
        let text = format!("echo '\r{}'\r",
            "0123456789012345678901234567890123456789\r".repeat(1600));
        let expected: Vec<_> = text.bytes().map(|b| if b == b'\r' { b'\n' } else { b }).collect();
        let mut ld = LineDiscipline::new();
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        ld.set_prompt_mode(1);
        for chunk in text.as_bytes().chunks(1024) {
            ld.input(chunk, &mut child, &mut echo);
            ld.set_prompt_mode(3);
            ld.set_prompt_mode(2);
        }
        assert_eq!(child.len(), expected.len(), "read fence discarded pending bytes");
        assert_eq!(child, expected);
    }

    #[test]
    fn fenced_utf8_and_text_survive_every_valid_split() {
        let text = "h\rstart é🙂 tail\r";
        let expected: Vec<_> = text.bytes().map(|b| if b == b'\r' { b'\n' } else { b }).collect();
        for split in 2..text.len() {
            let mut ld = LineDiscipline::new();
            let (mut child, mut echo) = (Vec::new(), Vec::new());
            ld.set_prompt_mode(1);
            ld.input(&text.as_bytes()[..split], &mut child, &mut echo);
            ld.set_prompt_mode(3);
            ld.set_prompt_mode(2);
            ld.input(&text.as_bytes()[split..], &mut child, &mut echo);
            assert_eq!(child, expected, "split={split}");
        }
    }

    #[test]
    fn fenced_cursor_and_partial_escape_survive() {
        let mut ld = LineDiscipline::new();
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        ld.set_prompt_mode(1);
        ld.input(b"h\rabc\x1b[", &mut child, &mut echo);
        ld.set_prompt_mode(3);
        ld.set_prompt_mode(2);
        ld.input(b"DX\r", &mut child, &mut echo);
        assert_eq!(child, b"h\nabXc\n");
    }

    #[test]
    fn program_mode_preserves_unread_draft_without_history_promotion() {
        let mut ld = LineDiscipline::new();
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        ld.set_prompt_mode(1);
        ld.input(b"h\rprivate application tail", &mut child, &mut echo);
        ld.set_prompt_mode(3);
        ld.set_prompt_mode(0);
        ld.set_prompt_mode(1);
        ld.input(b"safe\r", &mut child, &mut echo);
        assert_eq!(child, b"h\nprivate application tailsafe\n");
        assert!(!ld.history.iter().any(|v| v.starts_with(b"private")));
    }

    #[test]
    fn fence_cannot_promote_an_application_buffer() {
        let mut ld = LineDiscipline::new();
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        ld.input(b"private application tail", &mut child, &mut echo);
        ld.set_prompt_mode(3);
        ld.set_prompt_mode(2);
        ld.input(b"safe\r", &mut child, &mut echo);
        assert_eq!(child, b"private application tailsafe\n");
        assert!(ld.history.is_empty());
    }

    #[test]
    fn cancellation_after_fence_wakes_read_owner_and_requires_pause() {
        let mut ld = LineDiscipline::new();
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        ld.set_prompt_mode(1);
        ld.input(b"h\rpending", &mut child, &mut echo);
        ld.set_prompt_mode(3);
        let event = ld.input(b"\x03", &mut child, &mut echo);
        assert!(event.interrupt);
        assert_eq!(child, b"\n", "replace queued input with exactly one read-owner wake");
        ld.set_prompt_mode(2);
        ld.input(b"\x03", &mut child, &mut echo);
        assert_eq!(child, b"\n");
        ld.set_prompt_mode(0); ld.set_prompt_mode(1);
        child.clear();
        ld.input(b"fresh\r", &mut child, &mut echo);
        assert_eq!(child, b"fresh\n");
    }
}

#[cfg(test)]
mod paste_recovery_tests {
    use super::*;
    fn feed(t: &mut LineDiscipline, bytes: &[u8], pipe: &mut Vec<u8>, echo: &mut Vec<u8>, chunk: usize) {
        for p in bytes.chunks(chunk) { t.input(p, pipe, echo); }
    }
    #[test] fn approved_source_is_exact_and_never_enters_application_stdin() {
        for chunk in 1..=12 {
            let mut t=LineDiscipline::new(); t.set_prompt_mode(1); let (mut p,mut e)=(Vec::new(),Vec::new());
            feed(&mut t,b"\x1b[200~echo one\r\necho '\xc3\xa9'\n\x1b[201~",&mut p,&mut e,chunk);
            assert!(p.is_empty()); assert!(!p.windows(6).any(|w| w == paste::BEGIN));
            t.input(b"\r",&mut p,&mut e);
            let expected=b"echo one\necho '\xc3\xa9'\n";
            assert_eq!(p,[paste::record::header(expected.len()),expected.to_vec()].concat());
        }
    }
    #[test] fn paste_composes_cursor_prefix_suffix_and_preserves_raw_order_offsets() {
        let mut t=LineDiscipline::new(); t.set_prompt_mode(1); let(mut p,mut e)=(Vec::new(),Vec::new());
        t.input(b"old\recho ac\x1b[D\x1b[200~b\nlast\x1b[201~\rapp\r",&mut p,&mut e);
        let expected=b"echo ab\nlastc\n";
        assert_eq!(p,[b"old\n".to_vec(),paste::record::header(expected.len()),expected.to_vec(),b"app\n".to_vec()].concat());
    }
    #[test] fn unapproved_eof_or_cancel_never_submits_and_refused_suffix_stays_discarded() {
        for ending in [b"\x04".as_slice(),b"\x03",b"\xff"] {
            for chunk in [1,7,4096] {
                let mut t=LineDiscipline::new(); t.set_prompt_mode(1); let(mut p,mut e)=(Vec::new(),Vec::new());
                let bytes=[b"\x1b[200~echo before\r".as_slice(),ending,b"echo suffix > /victim\r\x03"].concat();
                feed(&mut t,&bytes,&mut p,&mut e,chunk);
                assert!(t.input_refused()); assert!(!p.windows(6).any(|w| w == paste::BEGIN)); assert_eq!(p,b"\n");
                t.set_prompt_mode(0); t.set_prompt_mode(1); p.clear();
                t.input(b"\x03echo late > /victim\r",&mut p,&mut e); assert!(p.is_empty());
            }
        }
    }
    #[test] fn overflow_end_recovers_only_after_pause_and_never_releases_tail() {
        for chunk in [1,7,4096] {
            let mut t=LineDiscipline::new(); t.set_prompt_mode(1); let(mut p,mut e)=(Vec::new(),Vec::new());
            let bad=[b"\x1b[200~".as_slice(),&vec![b'x';MAX_LINE+1],b"\x03echo victim\r\x1b[201~echo stale\r"].concat();
            feed(&mut t,&bad,&mut p,&mut e,chunk); assert!(t.input_refused()); assert!(!p.windows(6).any(|w| w == paste::BEGIN));
            t.set_prompt_mode(0); p.clear(); assert!(t.finish_recovery(&mut p,&mut e));
            t.input(b"trailing discarded\r",&mut p,&mut e); assert!(p.is_empty());
            t.set_prompt_mode(0); t.set_prompt_mode(1); t.input(b"echo fresh\r",&mut p,&mut e); assert_eq!(p,b"echo fresh\n");
        }
    }
    #[test] fn entropy_failure_retries_only_after_an_explicit_enter() {
        let mut t=LineDiscipline::new();t.set_prompt_mode(1);let(mut p,mut e)=(Vec::new(),Vec::new());
        t.input(b"\xff",&mut p,&mut e);assert!(t.needs_recovery_code());
        t.recovery_unavailable(&mut e);assert!(!t.needs_recovery_code());
        t.input(b"stale\x03suffix",&mut p,&mut e);assert!(!t.needs_recovery_code());
        t.input(b"\r",&mut p,&mut e);assert!(t.needs_recovery_code()); assert!(t.input_refused());
    }
    #[test] fn refusal_discovered_at_real_end_recovers_without_an_extra_marker_or_code() {
        for mode in [0,1] {
            let mut t=LineDiscipline::new();t.set_prompt_mode(mode);let(mut p,mut e)=(Vec::new(),Vec::new());
            t.input(b"\x1b[200~echo \xc3\x1b[201~",&mut p,&mut e);
            assert!(t.input_refused(),"incomplete UTF-8 at END must refuse the block");
            assert!(!t.needs_recovery_code(),"the real END was already consumed");
            t.set_prompt_mode(0);assert!(t.finish_recovery(&mut p,&mut e));
            assert!(!t.input_refused());
        }
    }
    #[test] fn composed_line_or_forwarded_end_overflow_uses_the_consumed_end_boundary() {
        for application in [false,true] {
            let mut t=LineDiscipline::new();let(mut p,mut e)=(Vec::new(),Vec::new());
            if application {
                t.child_output(b"\x1b[?2004h");
                t.input(paste::BEGIN,&mut p,&mut e);
                t.input(&vec![b'x';MAX_LINE-paste::BEGIN.len()],&mut p,&mut e);
            } else {
                t.set_prompt_mode(1);t.input(&vec![b'x';MAX_LINE],&mut p,&mut e);
                t.input(b"\x1b[H\x1b[200~y",&mut p,&mut e);
            }
            t.input(paste::END,&mut p,&mut e);
            assert!(t.input_refused());assert!(!t.needs_recovery_code());
            t.set_prompt_mode(0);assert!(t.finish_recovery(&mut p,&mut e));
            assert!(!t.input_refused());
        }
    }
    #[test] fn requested_marker_insertion_redraws_the_existing_suffix() {
        let mut t=LineDiscipline::new();t.child_output(b"\x1b[?2004h");let(mut p,mut e)=(Vec::new(),Vec::new());
        t.input(b"ac\x1b[D\x1b[200~",&mut p,&mut e);
        let(mut screen,mut cursor)=(Vec::new(),0usize);
        for byte in e {if byte==8 {cursor=cursor.saturating_sub(1);} else {if cursor==screen.len(){screen.push(byte);}else{screen[cursor]=byte;}cursor+=1;}}
        assert_eq!(screen,b"a^[[200~c");assert_eq!(cursor,8);
    }
    #[test] fn application_paste_owner_survives_prompt_changes_and_streams_newlines() {
        let mut t=LineDiscipline::new();t.set_prompt_mode(0);let(mut p,mut e)=(Vec::new(),Vec::new());
        t.input(b"\x1b[200~first\n",&mut p,&mut e);assert_eq!(p,b"first\n");
        t.set_prompt_mode(1);
        // A nested public BEGIN in data must not become a new shell capture.
        t.input(b"\x1b[200~second\n\x1b[201~",&mut p,&mut e);
        assert_eq!(p,b"first\nsecond\n","application data was held for shell approval after rearm");
    }
    #[test] fn application_requested_markers_follow_the_begin_owner_across_output_changes() {
        for split in 0..=8 {
            let mut t=LineDiscipline::new();let(mut p,mut e)=(Vec::new(),Vec::new());
            let enable=b"\x1b[?2004h";
            t.child_output(&enable[..split]);t.child_output(&enable[split..]);
            t.input(b"\x1b[200~first\n",&mut p,&mut e);
            assert_eq!(p,b"\x1b[200~first\n");
            t.child_output(b"\x1b[?2004l");t.set_prompt_mode(1);
            t.input(b"last\x1b[201~\n",&mut p,&mut e);
            assert_eq!(p,b"\x1b[200~first\nlast\x1b[201~\n");
            t.set_prompt_mode(0);p.clear();
            t.input(b"\x1b[200~plain\n\x1b[201~",&mut p,&mut e);
            assert_eq!(p,b"plain\n");
        }
    }
    #[test] fn a_new_application_does_not_inherit_the_prior_request_to_forward_markers() {
        let mut t=LineDiscipline::new();let(mut p,mut e)=(Vec::new(),Vec::new());
        t.child_output(b"\x1b[?2004h");t.set_prompt_mode(1);t.set_prompt_mode(0);
        t.input(b"\x1b[200~plain\n\x1b[201~",&mut p,&mut e);
        assert_eq!(p,b"plain\n");
    }
    #[test] fn application_paste_keeps_cooked_interrupt_and_discards_until_end() {
        let mut t=LineDiscipline::new();let(mut p,mut e)=(Vec::new(),Vec::new());
        let event=t.input(b"\x1b[200~draft\x03",&mut p,&mut e);
        assert!(event.interrupt && event.application_interrupt);assert!(t.input_refused());assert!(p.is_empty());
        t.set_prompt_mode(0);t.set_prompt_mode(1);
        t.input(b"tail\necho victim\n\x1b[201~",&mut p,&mut e);assert_eq!(p,b"\n");
        t.set_prompt_mode(0);p.clear();t.set_prompt_mode(1);
        t.input(b"echo fresh\n",&mut p,&mut e);assert_eq!(p,b"echo fresh\n");
    }
    #[test] fn application_mode_never_stages_bracketed_data_as_shell_source() {
        let mut t=LineDiscipline::new(); t.set_prompt_mode(0); let(mut p,mut e)=(Vec::new(),Vec::new());
        t.input(b"\x1b[200~echo app > /victim\r\x1b[201~\r",&mut p,&mut e);
        assert_eq!(p,b"echo app > /victim\n\n"); assert!(!t.staged_active); assert!(!t.capture);
    }
    #[test] fn fresh_code_recovers_across_every_split_without_ctrl_c_or_mode_shortcut() {
        for split in 0..=17 {
            let mut t=LineDiscipline::new(); t.set_prompt_mode(1); let(mut p,mut e)=(Vec::new(),Vec::new());
            t.input(b"\xff\x03echo victim\r",&mut p,&mut e); t.recovery_code([0x31;8],&mut e);
            t.set_prompt_mode(0); p.clear(); t.set_prompt_mode(1);
            t.input(b"stale-code\r\x03echo delayed\r",&mut p,&mut e); assert!(t.input_refused());
            let answer=b"3131313131313131\r";
            t.input(&answer[..split],&mut p,&mut e); t.input(&answer[split..],&mut p,&mut e);
            assert!(!t.input_refused()); assert!(t.input_cancelled());
            p.clear(); t.input(b"more stale\r",&mut p,&mut e); assert!(p.is_empty());
            t.set_prompt_mode(0); t.set_prompt_mode(1); t.input(b"fresh\r",&mut p,&mut e); assert_eq!(p,b"fresh\n");
        }
    }
}
