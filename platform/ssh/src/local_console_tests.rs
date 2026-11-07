use super::*;
use crate::conn::{Exit, MachineRequest};
use std::cell::RefCell;
use std::io;
use std::rc::Rc;
#[test]
fn switching_back_after_large_output_preserves_session_identity() {
    let mut m: Manager<Child> = Manager::new(true);
    m.output.clear();
    m.remember(0, &vec![b'x'; HISTORY]);
    m.output.clear();
    m.redraw();
    let mut displayed = Vec::new();
    while !m.output.is_empty() {
        m.output(|bytes| {
            displayed.extend_from_slice(bytes);
            bytes.len()
        });
    }
    let text = String::from_utf8(displayed).unwrap();
    assert!(text.contains("ABSD local console 1"));
    assert!(text.contains("history replay truncated"));
}
#[derive(Default)]
struct State {
    input: Vec<u8>,
    interrupted: usize,
    closed: bool,
    ended: bool,
    killed: bool,
    control_closed: bool,
    requests: std::collections::VecDeque<ControlRequest>,
    replies: Vec<(u8, String)>,
}
struct Child(Rc<RefCell<State>>);
impl SessionChild for Child {
    fn read_stdout(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(None)
    }
    fn read_stderr(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(None)
    }
    fn write_stdin(&mut self, b: &[u8]) -> io::Result<Option<usize>> {
        self.0.borrow_mut().input.extend_from_slice(b);
        Ok(Some(b.len()))
    }
    fn close_stdin(&mut self) {
        self.0.borrow_mut().closed = true;
    }
    fn try_wait(&mut self) -> io::Result<Option<Exit>> {
        Ok(self.0.borrow().ended.then_some(Exit::Abnormal))
    }
    fn terminate(&mut self) {
        self.0.borrow_mut().killed = true;
    }
    fn control_request(&mut self, _: Instant) -> Result<Option<ControlRequest>, String> {
        if self.0.borrow().control_closed {
            Err("closed".into())
        } else {
            Ok(self.0.borrow_mut().requests.pop_front())
        }
    }
    fn control_reply(&mut self, status: u8, text: &str) {
        self.0.borrow_mut().replies.push((status, text.into()));
    }
    fn interrupt(&mut self) -> bool {
        self.0.borrow_mut().interrupted += 1;
        true
    }
}
#[derive(Default)]
struct Spawn {
    children: Vec<Rc<RefCell<State>>>,
    exhausted: bool,
    local_requests: usize,
    clock_requests: Vec<String>,
}
impl Spawner for Spawn {
    type Child = Child;
    fn spawn(&mut self, _: &Command, _: Option<&crate::tty::Terminal>) -> io::Result<Child> {
        if self.exhausted {
            return Err(io::ErrorKind::ResourceBusy.into());
        }
        let state = Rc::new(RefCell::new(State::default()));
        self.children.push(state.clone());
        Ok(Child(state))
    }
    fn spawn_local(
        &mut self,
        command: &Command,
        terminal: Option<&crate::tty::Terminal>,
    ) -> io::Result<Child> {
        self.local_requests += 1;
        self.spawn(command, terminal)
    }
    fn clock_request(&mut self, words: &str) -> Result<String, String> {
        self.clock_requests.push(words.into());
        if words == "status" {
            Ok("clock source=rtc-unverified\n".into())
        } else {
            Err("clock: provider disabled\n".into())
        }
    }
    fn machine_request(&mut self, _: MachineRequest) -> Result<String, String> {
        Ok("requested".into())
    }
}
fn send(m: &mut Manager<Child>, s: &mut Spawn, b: &[u8], t: Instant) {
    m.input(b, t, |token| token == b"enrolled-token", s);
}
#[test]
fn exclusive_retained_sessions_and_unenrolled_refusal() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(false);
    send(&mut m, &mut s, b"enrolled-token\r", t);
    assert!(s.children.is_empty());
    let mut m = Manager::new(true);
    send(
        &mut m,
        &mut s,
        b"enrolled-token\rfirst\r\x1d2enrolled-token\rsecond\r",
        t,
    );
    m.poll(t, &mut s, true);
    assert_eq!(s.children.len(), 2);
    assert_eq!(s.children[0].borrow().input, b"first\n");
    assert_eq!(s.children[1].borrow().input, b"second\n");
    send(&mut m, &mut s, b"\x1d1back\r", t);
    m.poll(t, &mut s, true);
    assert_eq!(s.children[0].borrow().input, b"first\nback\n");
    assert!(s.children[1].borrow().input == b"second\n");
}
#[test]
fn failures_back_off_globally_and_exhaustion_does_not_loop() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(true);
    send(&mut m, &mut s, b"wrong\r\x1d2enrolled-token\r", t);
    assert!(s.children.is_empty());
    send(
        &mut m,
        &mut s,
        b"enrolled-token\r",
        t + Duration::from_secs(3),
    );
    assert_eq!(s.children.len(), 1);
    send(&mut m, &mut s, b"\x1d1", t);
    s.exhausted = true;
    send(
        &mut m,
        &mut s,
        b"enrolled-token\r",
        t + Duration::from_secs(3),
    );
    assert!(m.sessions[0].next_login > t + Duration::from_secs(3));
    assert!(m.sessions[0].child.is_none());
    send(
        &mut m,
        &mut s,
        b"enrolled-token\r",
        t + Duration::from_secs(4),
    );
    assert!(m.sessions[0].token.is_empty());
}
#[test]
fn editing_interrupt_eof_and_logout_revoke_input() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(true);
    send(
        &mut m,
        &mut s,
        b"enrolled-token\rab\x7fc\r",
        t,
    );
    m.poll(t, &mut s, true);
    assert_eq!(s.children[0].borrow().input, b"ac\n");
    // The accepted paste rule cancels producer-owned queued lines and the
    // same-batch tail. Previously delivered input is not retracted.
    send(&mut m, &mut s, b"discard\x03\x04", t);
    m.poll(t, &mut s, true);
    assert_eq!(s.children[0].borrow().interrupted, 1);
    assert_eq!(s.children[0].borrow().input, b"ac\n");
    assert!(!s.children[0].borrow().closed, "same-batch EOF must be discarded");
    for mode in [0, 1] {
        s.children[0].borrow_mut().requests.push_back(ControlRequest::InputMode(mode));
        m.poll(t, &mut s, true);
    }
    // A physical newline ends the discarded same-batch tail before a new EOF.
    send(&mut m, &mut s, b"\r\x04", t);
    m.poll(t, &mut s, true);
    assert!(s.children[0].borrow().closed);
    send(&mut m, &mut s, b"\x1dl\rstale\r", t);
    assert!(s.children[0].borrow().killed);
    assert!(m.sessions[0].input.is_empty());
    assert!(m.sessions[0].token.is_empty());
    send(
        &mut m,
        &mut s,
        b"enrolled-token\rnew\r",
        t + Duration::from_secs(2),
    );
    m.poll(t + Duration::from_secs(2), &mut s, true);
    assert_eq!(s.children[1].borrow().input, b"new\n");
}

#[test]
fn composition_local_prompt_declares_record_support_unavailable() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(true);
    send(&mut m, &mut s, b"enrolled-token\r", t);
    s.children[0].borrow_mut().requests.push_back(ControlRequest::InputMode(1));
    m.poll(t, &mut s, true);
    assert_eq!(s.children[0].borrow().replies.last(), Some(&(0, crate::plain_input::CAPABILITY.into())));
}

#[test]
fn composition_local_cancel_discards_source_still_owned_by_the_producer() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(true);
    send(&mut m, &mut s, b"enrolled-token\r", t);
    s.children[0].borrow_mut().requests.push_back(ControlRequest::InputMode(1));
    m.poll(t, &mut s, true);
    send(&mut m, &mut s, b"queued\r", t);
    assert!(s.children[0].borrow().input.is_empty());
    send(&mut m, &mut s, b"discard\x03", t);
    m.poll(t, &mut s, true);
    let state = s.children[0].borrow();
    assert_eq!(state.interrupted, 1);
    assert!(!state.input.windows(b"queued\n".len()).any(|part| part == b"queued\n"),
        "cancelled producer-owned source was delivered: {:?}", state.input);
}

#[test]
fn composition_local_cancel_never_claims_a_producer_pause() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(true);
    send(&mut m, &mut s, b"enrolled-token\r", t);
    s.children[0].borrow_mut().requests.push_back(ControlRequest::InputMode(1));
    m.poll(t, &mut s, true);
    send(&mut m, &mut s, b"discard\x03", t);
    s.children[0].borrow_mut().requests.push_back(ControlRequest::InputMode(0));
    m.poll(t, &mut s, true);
    assert_eq!(s.children[0].borrow().replies.last(),
        Some(&(0, crate::plain_input::CAPABILITY.into())));
}
#[test]
fn shell_death_requires_fresh_authentication_and_discards_history() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(true);
    send(&mut m, &mut s, b"enrolled-token\rsecret partial", t);
    s.children[0].borrow_mut().ended = true;
    m.poll(t, &mut s, true);
    assert!(m.sessions[0].child.is_none());
    assert!(m.sessions[0].history.is_empty());
    assert!(m.sessions[0].input.is_empty());
    m.poll(t + Duration::from_secs(100), &mut s, true);
    assert_eq!(s.children.len(), 1);
    send(
        &mut m,
        &mut s,
        b"enrolled-token\r",
        t + Duration::from_secs(2),
    );
    assert_eq!(s.children.len(), 2);
}
#[test]
fn retained_output_is_bounded_and_reports_loss() {
    let mut m = Manager::<Child>::new(true);
    m.remember(0, &vec![b'x'; HISTORY + 12]);
    assert_eq!(m.sessions[0].history.len(), HISTORY);
    assert_eq!(m.sessions[0].lost, 12);
    assert!(m.output.len() <= QUEUE);
    let mut output = Vec::new();
    m.output(|bytes| {
        output.extend_from_slice(bytes);
        bytes.len()
    });
    assert!(String::from_utf8_lossy(&output).contains("terminal output lost"));
}

#[test]
fn losing_shell_control_ends_the_session_instead_of_running_without_interrupts() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(true);
    send(&mut m, &mut s, b"enrolled-token\r", t);
    s.children[0].borrow_mut().control_closed = true;
    m.poll(t, &mut s, true);
    assert!(s.children[0].borrow().killed);
    assert!(m.sessions[0].child.is_none());
}

#[test]
fn middle_paste_does_not_overflow_local_echo_or_drop_accepted_input() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(true);
    send(&mut m, &mut s, b"enrolled-token\r", t);
    send(&mut m, &mut s, &vec![b'a'; 2000], t);
    send(&mut m, &mut s, b"\x1b[H", t);
    m.output.clear();
    m.output_lost = 0;
    send(&mut m, &mut s, &vec![b'b'; 2000], t);
    assert_eq!(m.output_lost, 0);
    assert!(m.output.len() <= 2 * crate::tty::MAX_LINE);
    send(&mut m, &mut s, b"\r", t);
    m.poll(t, &mut s, true);
    assert_eq!(
        s.children[0].borrow().input,
        [vec![b'b'; 2000], vec![b'a'; 2000], vec![b'\n']].concat()
    );
}

#[test]
fn local_authentication_uses_the_reserved_origin_entrypoint() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(true);
    send(&mut m, &mut s, b"enrolled-token\r", t);
    assert_eq!(s.local_requests, 1);
}

#[test]
fn enrolled_clock_requests_use_the_existing_owner_and_return_its_status() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(true);
    send(&mut m, &mut s, b"enrolled-token\r", t);
    assert_eq!(s.children.len(), 1);
    s.children[0]
        .borrow_mut()
        .requests
        .push_back(ControlRequest::Clock("status".into()));
    m.poll(t, &mut s, true);
    s.children[0]
        .borrow_mut()
        .requests
        .push_back(ControlRequest::Clock("sync".into()));
    m.poll(t, &mut s, true);
    assert_eq!(s.clock_requests, ["status", "sync"]);
    assert_eq!(
        s.children[0].borrow().replies,
        [
            (0, "clock source=rtc-unverified\n".into()),
            (1, "clock: provider disabled\n".into())
        ]
    );
    assert_eq!(s.children.len(), 1);
}

#[test]
fn composition_local_pasted_bursts_are_plain_lines_without_record_waits() {
    let t = Instant::now() + Duration::from_secs(1);
    for marked in [false, true] {
        for chunk in [1, 7, 4096] {
            let mut s = Spawn::default();
            let mut m = Manager::new(true);
            send(&mut m, &mut s, b"enrolled-token\r", t);
            s.children[0].borrow_mut().requests.push_back(ControlRequest::InputMode(1));
            m.poll(t, &mut s, true);
            let body = b"first\rsecond\r";
            let bytes = if marked {
                [b"\x1b[200~".as_slice(), body, b"\x1b[201~"].concat()
            } else { body.to_vec() };
            for part in bytes.chunks(chunk) {
                send(&mut m, &mut s, part, t);
                m.poll(t, &mut s, true);
            }
            assert_eq!(s.children[0].borrow().input, b"first\nsecond\n", "marked={marked} chunk={chunk}");
            assert!(!m.sessions[0].terminal.input_refused());
            assert!(m.sessions[0].input.is_empty());
        }
    }
}

#[test]
fn composition_local_refusal_has_a_working_logout_and_fresh_login() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(true);
    send(&mut m, &mut s, b"enrolled-token\r", t);
    send(&mut m, &mut s, b"\xff\r", t);
    assert!(m.sessions[0].terminal.input_refused());
    let text: Vec<_> = m.sessions[0].history.iter().copied().collect();
    assert!(String::from_utf8_lossy(&text).contains("press Ctrl-C to recover"));
    send(&mut m, &mut s, b"\x03", t);
    for mode in [0, 1] {
        s.children[0].borrow_mut().requests.push_back(ControlRequest::InputMode(mode));
        m.poll(t, &mut s, true);
    }
    send(&mut m, &mut s, b"\x1dl\r", t);
    assert!(s.children[0].borrow().killed);
    assert!(!m.sessions[0].terminal.input_refused());
    send(&mut m, &mut s, b"enrolled-token\rfresh\r", t + Duration::from_secs(2));
    m.poll(t + Duration::from_secs(2), &mut s, true);
    assert_eq!(s.children[1].borrow().input, b"fresh\n");
}

#[test]
fn composition_local_marked_paste_cancel_keeps_ordinary_line_recovery() {
    let t = Instant::now() + Duration::from_secs(1);
    for delivered in [false, true] {
        let mut s = Spawn::default();
        let mut m = Manager::new(true);
        send(&mut m, &mut s, b"enrolled-token\r", t);
        s.children[0].borrow_mut().requests.push_back(ControlRequest::InputMode(1));
        m.poll(t, &mut s, true);
        send(&mut m, &mut s, b"\x1b[200~first\r", t);
        if delivered { m.poll(t, &mut s, true); }
        send(&mut m, &mut s, b"discard\x03\x1b[201~\r", t);
        m.poll(t, &mut s, true);
        assert!(!m.sessions[0].terminal.input_refused(),
            "ordinary local lines entered record recovery after Ctrl-C");
        assert_eq!(s.children[0].borrow().interrupted, 1);
        for mode in [0, 1] {
            s.children[0].borrow_mut().requests.push_back(ControlRequest::InputMode(mode));
            m.poll(t, &mut s, true);
        }
        send(&mut m, &mut s, b"fresh\r", t);
        m.poll(t, &mut s, true);
        let state = s.children[0].borrow();
        assert_eq!(state.input.starts_with(b"first\n"), delivered);
        assert!(state.input.ends_with(b"fresh\n"));
        assert!(!state.input.windows(b"discard".len()).any(|p| p == b"discard"));
    }
}

// Minimal sequences from the steward's contract pilot, exercised through the
// actual Manager/LineDiscipline and existing session child substitute.
#[test]
fn pilot_abandoned_prefix_preserves_the_command_and_never_logs_out() {
    let t = Instant::now() + Duration::from_secs(1);
    for command in [b"echo hi\r".as_slice(), b"ls -l\r"] {
        for chunk in [1, 2, 4096] {
            let mut s = Spawn::default();
            let mut m = Manager::new(true);
            send(&mut m, &mut s, b"enrolled-token\r", t);
            let bytes = [b"\x1d".as_slice(), command].concat();
            for part in bytes.chunks(chunk) {
                send(&mut m, &mut s, part, t);
                m.poll(t, &mut s, true);
            }
            m.poll(t, &mut s, true);
            let state = s.children[0].borrow();
            assert!(!state.killed && !state.closed, "chunk={chunk} command={command:?}");
            let expected = [b"\x1d".as_slice(), &command[..command.len()-1], b"\n"].concat();
            assert_eq!(state.input, expected, "chunk={chunk}");
        }
    }
}

#[test]
fn pilot_logout_requires_an_explicit_enter_confirmation() {
    let t = Instant::now() + Duration::from_secs(1);
    let mut s = Spawn::default();
    let mut m = Manager::new(true);
    send(&mut m, &mut s, b"enrolled-token\r", t);
    send(&mut m, &mut s, b"\x1dl", t);
    assert!(!s.children[0].borrow().killed);
    let shown: Vec<_> = m.output.iter().copied().collect();
    assert!(String::from_utf8_lossy(&shown).contains("Enter confirms logout"));
    send(&mut m, &mut s, b"\r", t);
    assert!(s.children[0].borrow().killed);
    assert!(s.children[0].borrow().closed);
    assert!(m.sessions[0].input.is_empty());
}

#[test]
fn pilot_cancel_clears_producer_owned_complete_lines_and_the_same_batch_tail() {
    let t = Instant::now() + Duration::from_secs(1);
    for bytes in [b"echo A\recho B\r\x03".as_slice(), b"echo A\r\x03echo B\r"] {
        let mut s = Spawn::default();
        let mut m = Manager::new(true);
        send(&mut m, &mut s, b"enrolled-token\r", t);
        send(&mut m, &mut s, bytes, t);
        m.poll(t, &mut s, true);
        let state = s.children[0].borrow();
        assert!(state.input.is_empty());
        assert_eq!(state.interrupted, 1);
        assert!(!state.killed);
    }
}

#[test]
fn pilot_ctrl_c_cancels_pending_console_commands_without_logout() {
    let t = Instant::now() + Duration::from_secs(1);
    for pending in [b"\x1d".as_slice(), b"\x1dl"] {
        let mut s = Spawn::default();
        let mut m = Manager::new(true);
        send(&mut m, &mut s, b"enrolled-token\r", t);
        send(&mut m, &mut s, pending, t);
        send(&mut m, &mut s, b"\x03\r", t);
        m.poll(t, &mut s, true);
        let state = s.children[0].borrow();
        assert!(!state.killed && !state.closed);
        assert_eq!(state.interrupted, 1);
        assert!(state.input.is_empty());
        assert!(!m.escape && !m.logout_pending);
    }
}

#[test]
fn pilot_later_input_survives_ctrl_c_after_the_shell_rearms_its_prompt() {
    let t = Instant::now() + Duration::from_secs(1);
    for pending in [b"".as_slice(), b"\x1d", b"\x1dl"] {
        let mut s = Spawn::default();
        let mut m = Manager::new(true);
        send(&mut m, &mut s, b"enrolled-token\r", t);
        s.children[0].borrow_mut().requests.push_back(ControlRequest::InputMode(1));
        m.poll(t, &mut s, true);
        send(&mut m, &mut s, pending, t);
        send(&mut m, &mut s, b"\x03", t);
        m.poll(t, &mut s, true);
        // Native sh observes the interrupt, asks mode 0 while discarding,
        // then mode 1 for its new prompt (sh_host::discard_pending_input).
        for mode in [0, 1] {
            s.children[0].borrow_mut().requests.push_back(ControlRequest::InputMode(mode));
            m.poll(t, &mut s, true);
        }
        send(&mut m, &mut s, b"echo ok\r", t);
        m.poll(t, &mut s, true);
        let state = s.children[0].borrow();
        assert_eq!(state.input, b"\necho ok\n", "pending={pending:?}");
        assert_eq!(state.interrupted, 1);
        assert!(!state.killed && !state.closed);
        assert!(!m.escape && !m.logout_pending);
    }
}

// #179 contract-first controls. Exercise only Manager's public input/poll/end
// calls and the existing fake child's observable writes, replies and lifecycle.
fn plain179_login() -> (Instant, Spawn, Manager<Child>) {
    let now = Instant::now() + Duration::from_secs(1);
    let mut spawner = Spawn::default();
    let mut manager = Manager::new(true);
    send(&mut manager, &mut spawner, b"enrolled-token\r", now);
    assert_eq!(spawner.children.len(), 1);
    (now, spawner, manager)
}

fn plain179_mode(manager: &mut Manager<Child>, spawner: &mut Spawn, now: Instant, mode: u8) -> (u8, String) {
    spawner.children[0].borrow_mut().requests.push_back(ControlRequest::InputMode(mode));
    manager.poll(now, spawner, true);
    spawner.children[0].borrow().replies.last().expect("control reply").clone()
}

fn plain179_alive(state: &State) {
    assert!(!state.closed, "refusal must not close the child input");
    assert!(!state.killed, "refusal must not terminate the child");
    assert!(!state.ended, "the fake child is still running");
}

#[test]
fn plain179_mode4_acknowledges_pause_and_clears_only_undelivered_queue() {
    let (now, mut spawner, mut manager) = plain179_login();
    send(&mut manager, &mut spawner, b"already delivered\r", now);
    manager.poll(now, &mut spawner, true);
    send(&mut manager, &mut spawner, b"echo queued > /must-not-run\r", now);
    assert_eq!(plain179_mode(&mut manager, &mut spawner, now, 4),
               (crate::control::INPUT_PAUSED, "plain-discard-v1".into()));
    manager.poll(now, &mut spawner, true);
    let state = spawner.children[0].borrow();
    assert_eq!(state.input, b"already delivered\n", "producer-owned bytes were not fenced before acknowledgement");
    assert_eq!(state.interrupted, 0, "mode 4 is refusal, not the operator's cancellation");
    plain179_alive(&state);
}

#[test]
fn plain179_quarantine_discards_multiline_heredoc_suffix_and_console_logout() {
    for suffix in [
        b"quote body\r' > /refused\recho bad > /suffix\r".as_slice(),
        b"heredoc body\rEOF\recho bad > /suffix\r",
        b"\r\r\x1dl\recho bad > /suffix\r",
    ] {
        let (now, mut spawner, mut manager) = plain179_login();
        plain179_mode(&mut manager, &mut spawner, now, 4);
        send(&mut manager, &mut spawner, suffix, now);
        manager.poll(now, &mut spawner, true);
        assert_eq!(spawner.children.len(), 1);
        let state = spawner.children[0].borrow();
        assert!(state.input.is_empty(), "quarantined suffix reached the child: {suffix:?}");
        assert_eq!(state.interrupted, 0);
        plain179_alive(&state);
    }
}

#[test]
fn plain179_modes1_and2_cannot_reopen_before_explicit_cancel() {
    let (now, mut spawner, mut manager) = plain179_login();
    plain179_mode(&mut manager, &mut spawner, now, 4);
    for mode in [1, 2, 1, 2] {
        let reply = plain179_mode(&mut manager, &mut spawner, now, mode);
        assert_eq!(reply.1, "plain-discard-v1");
        send(&mut manager, &mut spawner, b"echo early > /suffix\r", now);
        manager.poll(now, &mut spawner, true);
    }
    let state = spawner.children[0].borrow();
    assert!(state.input.is_empty());
    assert_eq!(state.interrupted, 0);
    plain179_alive(&state);
}

#[test]
fn plain179_ctrl_c_discards_whole_batch_and_repetition_never_unpauses() {
    for batches in [
        vec![b"old\x03echo same-batch > /suffix\r".as_slice()],
        vec![b"old".as_slice(), b"\x03", b"echo later-but-still-paused > /suffix\r"],
    ] {
        let (now, mut spawner, mut manager) = plain179_login();
        plain179_mode(&mut manager, &mut spawner, now, 4);
        for batch in batches { send(&mut manager, &mut spawner, batch, now); }
        manager.poll(now, &mut spawner, true);
        for _ in 0..3 {
            send(&mut manager, &mut spawner, b"\x03\x1dl\recho again > /suffix\r", now);
            manager.poll(now, &mut spawner, true);
        }
        let state = spawner.children[0].borrow();
        assert!(state.input.is_empty());
        assert_eq!(state.interrupted, 1, "only the first explicit cancellation transitions the refusal");
        plain179_alive(&state);
    }
}

#[test]
fn plain179_mode0_pause_precedes_rearm_and_only_separate_fresh_line_reaches_child() {
    let (now, mut spawner, mut manager) = plain179_login();
    // Pending console selectors from the rejected source must not turn the
    // fresh line's Enter into logout after recovery.
    send(&mut manager, &mut spawner, b"\x1dl", now);
    plain179_mode(&mut manager, &mut spawner, now, 4);
    send(&mut manager, &mut spawner, b"\x03echo same-batch > /suffix\r", now);
    manager.poll(now, &mut spawner, true);
    for mode in [1, 2] {
        plain179_mode(&mut manager, &mut spawner, now, mode);
        send(&mut manager, &mut spawner, b"echo before-drain > /suffix\r", now);
        manager.poll(now, &mut spawner, true);
        assert!(spawner.children[0].borrow().input.is_empty());
    }
    assert_eq!(plain179_mode(&mut manager, &mut spawner, now, 0),
               (crate::control::INPUT_PAUSED, "plain-discard-v1".into()));
    send(&mut manager, &mut spawner, b"echo while-draining > /suffix\r", now);
    manager.poll(now, &mut spawner, true);
    assert!(spawner.children[0].borrow().input.is_empty());
    assert_eq!(plain179_mode(&mut manager, &mut spawner, now, 1), (0, "plain-discard-v1".into()));
    send(&mut manager, &mut spawner, b"echo deliberately fresh\r", now);
    manager.poll(now, &mut spawner, true);
    let state = spawner.children[0].borrow();
    assert_eq!(state.input, b"echo deliberately fresh\n");
    assert_eq!(state.interrupted, 1);
    plain179_alive(&state);
}

#[test]
fn plain179_child_end_and_control_disconnect_retire_quarantine_before_new_login() {
    for disconnect in [false, true] {
        let (now, mut spawner, mut manager) = plain179_login();
        plain179_mode(&mut manager, &mut spawner, now, 4);
        send(&mut manager, &mut spawner, b"\x1dl\rdiscarded\r", now);
        if disconnect { spawner.children[0].borrow_mut().control_closed = true; }
        else { spawner.children[0].borrow_mut().ended = true; }
        manager.poll(now, &mut spawner, true);
        assert!(spawner.children[0].borrow().closed);
        assert!(spawner.children[0].borrow().killed);
        let later = now + Duration::from_secs(2);
        send(&mut manager, &mut spawner, b"enrolled-token\recho new session\r", later);
        manager.poll(later, &mut spawner, true);
        assert_eq!(spawner.children.len(), 2);
        let fresh = spawner.children[1].borrow();
        assert_eq!(fresh.input, b"echo new session\n");
        assert_eq!(fresh.interrupted, 0);
        plain179_alive(&fresh);
    }
}

#[test]
fn plain179_end_all_retires_paused_session_and_never_reauthenticates() {
    let (now, mut spawner, mut manager) = plain179_login();
    plain179_mode(&mut manager, &mut spawner, now, 4);
    send(&mut manager, &mut spawner, b"\x1dl\rdiscarded\r", now);
    manager.end_all(now);
    send(&mut manager, &mut spawner, b"enrolled-token\recho after end\r", now + Duration::from_secs(2));
    manager.poll(now + Duration::from_secs(2), &mut spawner, true);
    assert_eq!(spawner.children.len(), 1);
    let retired = spawner.children[0].borrow();
    assert!(retired.input.is_empty());
    assert!(retired.closed && retired.killed);
}

#[test]
fn plain179_pause_ack_before_cancel_cannot_authorize_rearm_after_cancel() {
    let (now, mut spawner, mut manager) = plain179_login();
    plain179_mode(&mut manager, &mut spawner, now, 4);
    // In this new plain capability, mode 0 before cancellation reports
    // refusal; it cannot vouch that a recovery boundary already arrived.
    assert_eq!(plain179_mode(&mut manager, &mut spawner, now, 0),
               (crate::control::INPUT_REFUSED, "plain-discard-v1".into()));
    send(&mut manager, &mut spawner, b"\x03echo cancelled-batch > /suffix\r", now);
    manager.poll(now, &mut spawner, true);
    plain179_mode(&mut manager, &mut spawner, now, 1);
    send(&mut manager, &mut spawner, b"echo stale-pause-ack > /suffix\r", now);
    manager.poll(now, &mut spawner, true);
    assert!(spawner.children[0].borrow().input.is_empty());
    // Mode 0 acknowledges a writer pause. The native client must drain
    // after that acknowledgement before it deliberately asks mode 1.
    assert_eq!(plain179_mode(&mut manager, &mut spawner, now, 0),
               (crate::control::INPUT_PAUSED, "plain-discard-v1".into()));
    plain179_mode(&mut manager, &mut spawner, now, 1);
    send(&mut manager, &mut spawner, b"echo separate after fresh pause\r", now);
    manager.poll(now, &mut spawner, true);
    let state = spawner.children[0].borrow();
    assert_eq!(state.input, b"echo separate after fresh pause\n");
    assert_eq!(state.interrupted, 1);
    plain179_alive(&state);
}

#[test]
fn plain179_terminal_line_guard_enters_the_same_cancel_recovery() {
    let (now, mut spawner, mut manager) = plain179_login();
    plain179_mode(&mut manager, &mut spawner, now, 1);
    send(&mut manager, &mut spawner, &vec![b'x'; crate::tty::MAX_LINE + 1], now);
    manager.poll(now, &mut spawner, true);
    let reply = plain179_mode(&mut manager, &mut spawner, now, 3);
    assert_eq!(reply, (crate::control::INPUT_REFUSED, "plain-discard-v1".into()));
    plain179_mode(&mut manager, &mut spawner, now, 0);
    plain179_mode(&mut manager, &mut spawner, now, 1);
    send(&mut manager, &mut spawner, b"echo stale > /victim\r", now);
    manager.poll(now, &mut spawner, true);
    assert_eq!(spawner.children[0].borrow().input, b"\n");
    send(&mut manager, &mut spawner, b"\x03echo same-batch > /victim\r", now);
    plain179_mode(&mut manager, &mut spawner, now, 0);
    plain179_mode(&mut manager, &mut spawner, now, 1);
    send(&mut manager, &mut spawner, b"echo fresh\r", now);
    manager.poll(now, &mut spawner, true);
    let state = spawner.children[0].borrow();
    assert_eq!(state.input, b"\necho fresh\n");
    assert_eq!(state.interrupted, 1); // only the explicit operator cancellation
    plain179_alive(&state);
}

#[test]
fn review179_same_batch_selector_after_terminal_refusal_cannot_log_out() {
    let (now, mut spawner, mut manager) = plain179_login();
    plain179_mode(&mut manager, &mut spawner, now, 1);
    let mut batch = vec![b'x'; crate::tty::MAX_LINE + 1];
    batch.extend_from_slice(b"\x1dl\r");
    send(&mut manager, &mut spawner, &batch, now);
    manager.poll(now, &mut spawner, true);
    let state = spawner.children[0].borrow();
    plain179_alive(&state);
    assert!(!state.killed && !state.closed, "pasted selector in the refusal batch ended the session");
}

#[test]
fn review179_128_byte_chunks_selector_after_terminal_refusal_cannot_log_out() {
    let (now, mut spawner, mut manager) = plain179_login();
    plain179_mode(&mut manager, &mut spawner, now, 1);
    let mut batch = vec![b'x'; crate::tty::MAX_LINE + 1];
    batch.extend_from_slice(b"\x1dl\r");
    for chunk in batch.chunks(128) { send(&mut manager, &mut spawner, chunk, now); manager.poll(now, &mut spawner, true); }
    let state = spawner.children[0].borrow();
    assert!(!state.killed && !state.closed, "pasted selector after refusal ended the session");
}

#[test]
fn review179_refusal_tail_cancellation_preserves_a_separate_fresh_command() {
    for chunk_size in [128, crate::tty::MAX_LINE + 128] {
        let (now, mut spawner, mut manager) = plain179_login();
        plain179_mode(&mut manager, &mut spawner, now, 1);
        let mut batch = vec![b'x'; crate::tty::MAX_LINE + 1];
        batch.extend_from_slice(b"\x1dl\r\x03echo forbidden > /suffix\r");
        for chunk in batch.chunks(chunk_size) {
            send(&mut manager, &mut spawner, chunk, now);
            manager.poll(now, &mut spawner, true);
        }
        {
            let state = spawner.children[0].borrow();
            plain179_alive(&state);
            assert_eq!(state.interrupted, 1);
            assert_eq!(state.input, b"\n"); // only the existing pre-ack read wake
        }
        assert_eq!(plain179_mode(&mut manager, &mut spawner, now, 0),
                   (crate::control::INPUT_PAUSED, "plain-discard-v1".into()));
        assert_eq!(plain179_mode(&mut manager, &mut spawner, now, 1),
                   (0, "plain-discard-v1".into()));
        send(&mut manager, &mut spawner, b"echo separate fresh command\r", now);
        manager.poll(now, &mut spawner, true);
        let state = spawner.children[0].borrow();
        plain179_alive(&state);
        assert_eq!(state.input, b"\necho separate fresh command\n");
    }
}
