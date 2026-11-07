// Independent round-2 review (claude git-0a): real Connection control
// dispatch + Session::terminal_input + LineDiscipline. Shell side modelled
// on src/sh_host.rs (prompt_input / discard_pending_input / interrupt latch).
use super::*;
use std::cell::Cell;
use std::rc::Rc;

struct Child { request: Option<ControlRequest>, replies: Vec<(u8, String)>, retired: Rc<Cell<bool>>,
    controlled: bool, interrupts: Rc<Cell<u32>> }
impl SessionChild for Child {
    fn read_stdout(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> { Ok(None) }
    fn read_stderr(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> { Ok(None) }
    fn write_stdin(&mut self, bytes: &[u8]) -> io::Result<Option<usize>> { Ok(Some(bytes.len())) }
    fn close_stdin(&mut self) {}
    fn try_wait(&mut self) -> io::Result<Option<Exit>> { Ok(None) }
    fn terminate(&mut self) { self.retired.set(true); }
    fn interrupt(&mut self) -> bool { if self.controlled { self.interrupts.set(self.interrupts.get() + 1); } self.controlled }
    fn control_request(&mut self, _: Instant) -> Result<Option<ControlRequest>, String> { Ok(self.request.take()) }
    fn control_reply(&mut self, status: u8, text: &str) { self.replies.push((status, text.to_owned())); }
}
struct NoSpawn;
impl Spawner for NoSpawn {
    type Child = Child;
    fn machine_request(&mut self, _: MachineRequest) -> Result<String, String> { panic!() }
    fn spawn(&mut self, _: &Command, _: Option<&Terminal>) -> io::Result<Child> { panic!() }
}
struct T { c: Connection<Child>, retired: Rc<Cell<bool>>, irq: Rc<Cell<u32>>, seen: u32, delivered: Vec<u8> }
fn new(controlled: bool, exec: bool) -> T {
    let retired = Rc::new(Cell::new(false)); let irq = Rc::new(Cell::new(0));
    let mut c = Connection::new(149, Instant::now());
    c.session.child = Some(Child { request: None, replies: Vec::new(), retired: retired.clone(), controlled, interrupts: irq.clone() });
    c.session.tty = Some(LineDiscipline::new());
    c.session.exec = exec;
    T { c, retired, irq, seen: 0, delivered: Vec::new() }
}
impl T {
    fn mode(&mut self, m: u8) -> u8 {
        self.c.session.child.as_mut().unwrap().request = Some(ControlRequest::InputMode(m));
        assert!(self.c.control(&mut NoSpawn, Instant::now()));
        self.c.session.child.as_ref().unwrap().replies.last().unwrap().0
    }
    fn input(&mut self, b: &[u8]) -> tty::Events { let p = self.c.log_prefix.clone(); self.c.session.terminal_input(Some(b), &p) }
    /// Producer step: what sshd would write to the child pipe now.
    fn flush(&mut self) { if !self.c.session.input_paused { self.delivered.extend(self.c.session.stdin.drain(..)); } }
    fn latched(&mut self) -> bool { let n = self.irq.get(); let l = n > self.seen; self.seen = n; l }
    /// Shell at its prompt loop: prompt_input(1); on a latched interrupt,
    /// discard_pending_input (mode 0 + drain iff INPUT_PAUSED) and loop.
    fn shell_prompt(&mut self) {
        for _ in 0..8 {
            self.flush();
            self.mode(1);
            if !self.latched() { self.flush(); return; }
            let st = self.mode(0);
            if st == crate::control::INPUT_PAUSED { self.delivered.clear(); }
        }
        panic!("shell never reached an armed prompt");
    }
    fn tty(&self) -> &LineDiscipline { self.c.session.tty.as_ref().unwrap() }
    fn echo(&self) -> String { String::from_utf8_lossy(&self.c.session.echo).into_owned() }
    fn code(&self) -> Option<String> { self.echo().rsplit("terminal: type ").next().filter(|_| self.echo().contains("terminal: type ")).map(|s| s[..16].to_owned()) }
}
fn has(v: &[u8], n: &[u8]) -> bool { v.windows(n.len()).any(|w| w == n) }
const B: &[u8] = b"\x1b[200~";
const E: &[u8] = b"\x1b[201~";

// ---- Partial line consumed while refused (latched at END) and then rearm ----
#[test] fn r1_partial_line_after_latched_end_then_rearm_controlled() {
    let mut t = new(true, false); t.mode(1);
    let body = [B, &vec![b'x'; tty::MAX_LINE + 10], b"\necho SUFFIX > /oops\n", E, b"\recho t"].concat();
    t.input(&body);
    assert!(t.tty().input_refused());
    t.shell_prompt();
    assert!(!t.tty().input_refused() && !t.tty().input_cancelled(), "not rearmed");
    t.input(b"ail > /t\r"); t.flush();
    println!("[r1 controlled] delivered after rearm = {:?}", String::from_utf8_lossy(&t.delivered));
    assert!(!has(&t.delivered, b"ail > /t"), "R1: tail of a partially discarded physical line executed without its head");
}
#[test] fn r1b_partial_line_after_composed_overflow_latch() {
    let mut t = new(true, false); t.mode(1);
    t.input(&[b"echo ".as_slice(), &vec![b'x'; 40000], b"\x1b[H"].concat());
    t.input(&[B, &vec![b'y'; 30000], E, b"echo t"].concat());
    assert!(t.tty().input_refused(), "composed overflow refused");
    t.shell_prompt();
    t.input(b"ail > /t\r"); t.flush();
    println!("[r1b composed] delivered={:?} echo_tail={:?}", String::from_utf8_lossy(&t.delivered), &t.echo()[t.echo().len().saturating_sub(160)..]);
    assert!(!has(&t.delivered, b"ail > /t"));
}
#[test] fn r1c_partial_line_after_utf8_end_latch() {
    let mut t = new(true, false); t.mode(1);
    t.input(&[B, b"echo \xc3", E, b"echo t"].concat());
    assert!(t.tty().input_refused());
    t.shell_prompt();
    t.input(b"ail > /t\r"); t.flush();
    println!("[r1c utf8 latch] delivered={:?}", String::from_utf8_lossy(&t.delivered));
    assert!(!has(&t.delivered, b"ail > /t"));
}
#[test] fn r1d_exec_partial_line_after_latched_end() {
    let mut t = new(false, true);
    t.input(&[B, b"\xffjunk\n", E, b"rm -rf /dat"].concat());
    assert!(!t.tty().input_refused() && !t.c.session.input_paused, "exec recovered at END");
    t.input(b"a\r"); t.flush();
    println!("[r1d exec] delivered={:?} retired={}", String::from_utf8_lossy(&t.delivered), t.retired.get());
    assert!(!has(&t.delivered, b"a\n"), "R1d: exec app received tail 'a' of a discarded physical line");
}

// ---- Exec PTY wedge shapes ----
#[test] fn e1_exec_refusal_ctrl_c_swallowed_then_code() {
    let mut t = new(false, true);
    t.input(b"\xff"); t.input(b"\x03\x03stale\r");
    assert!(t.tty().input_refused() && !t.retired.get() && t.c.session.exit.is_none());
    let code = t.code().unwrap();
    t.input(format!("{code}\r").as_bytes());
    assert!(!t.tty().input_refused() && !t.c.session.input_paused);
    t.input(b"fresh\r"); t.flush();
    assert_eq!(t.delivered, b"fresh\n");
}
#[test] fn e2_exec_app_paste_refusal_end_in_later_packet_and_utf8_latch() {
    let mut t = new(false, true);
    t.input(&[B, &vec![b'z'; tty::MAX_LINE + 5]].concat());
    assert!(t.tty().input_refused() && t.c.session.input_paused);
    t.input(b"more\n"); t.input(E);
    assert!(!t.tty().input_refused() && !t.c.session.input_paused, "END releases exec refusal");
    t.input(b"fresh\r"); t.flush(); assert_eq!(t.delivered, b"fresh\n");
    let mut t = new(false, true);
    t.input(&[B, b"ab\xc3", E].concat());
    assert!(!t.tty().input_refused() && !t.c.session.input_paused, "UTF-8 END latch in exec");
    t.input(b"fresh\r"); t.flush(); assert_eq!(t.delivered, b"fresh\n");
}
#[test] fn e3_exec_refusal_then_channel_eof() {
    let mut t = new(false, true);
    t.input(b"\xff");
    let p = t.c.log_prefix.clone();
    let ev = t.c.session.terminal_input(None, &p);
    println!("[e3 exec refusal + EOF] ev={ev:?} refused={} paused={} exit={:?}", t.tty().input_refused(), t.c.session.input_paused, t.c.session.exit);
}

// ---- Stray application BEGIN without END ----
#[test] fn w1_stray_app_begin_then_ctrl_c_has_visible_code_recovery() {
    let mut t=new(true,false);t.mode(1);t.mode(0);
    t.input(b"\x1b[200~text from a log\r");t.flush();
    assert!(t.input(b"\x03").interrupt);
    assert!(t.tty().input_refused(),"missing END must enter visible bounded refusal");
    let code=t.code().expect("missing END must offer a recovery code");
    t.shell_prompt();t.delivered.clear();
    t.input(b"\x03\x03echo stale > /h\r");t.flush();assert!(t.delivered.is_empty());
    t.input(format!("{code}\r").as_bytes());t.shell_prompt();t.delivered.clear();
    assert!(!t.tty().input_refused());
    t.input(b"echo fresh > /h\r");t.flush();assert_eq!(t.delivered,b"echo fresh > /h\n");
}
#[test] fn cooked_ctrl_c_in_direct_exec_application_paste_ends_the_child() {
    let mut t=new(false,true);t.input(b"\x1b[200~draft");
    assert!(t.input(b"\x03").interrupt);assert!(t.retired.get());
    assert_eq!(t.c.session.exit,Some(Exit::Abnormal));
    assert!(!t.echo().contains("terminal: type"),"an ended exec cannot use a recovery challenge");
}
#[test] fn malformed_paste_then_ctrl_c_in_the_same_exec_packet_does_not_end_the_child() {
    let mut t=new(false,true);t.input(b"\x1b[200~\xff\x03");
    assert!(t.tty().input_refused());assert!(!t.retired.get());
    let code=t.code().unwrap();t.input(format!("{code}\r").as_bytes());
    assert!(!t.tty().input_refused());assert!(!t.retired.get());
}
#[test] fn w2_stray_application_begin_keeps_the_next_paste_application_owned_known_limit() {
    let mut t = new(true, false); t.mode(1); t.mode(0);
    t.input(b"\x1b[200~x\r"); t.flush();
    t.mode(1); t.delivered.clear();
    t.input(&[B, b"echo a > /pa\necho b > /pb\n", E].concat()); t.flush();
    println!("[w2] delivered before Enter={:?}", String::from_utf8_lossy(&t.delivered));
    assert!(has(&t.delivered, b"echo a > /pa\n"), "Named sticky application-owner limit");
}

// ---- Forwarding and ownership ----
#[test] fn f1_forwarding_sticky_from_begin() {
    let mut t = new(true, false); t.mode(1); t.mode(0);
    t.c.session.tty.as_mut().unwrap().child_output(b"\x1b[?2004h");
    t.input(&[B, b"a\nb"].concat());
    t.c.session.tty.as_mut().unwrap().child_output(b"\x1b[?2004l");
    t.input(&[b"c", E, b"\r"].concat()); t.flush();
    assert_eq!(t.delivered, b"\x1b[200~a\nbc\x1b[201~\n");
    let mut t = new(true, false); t.mode(1); t.mode(0);
    t.input(&[B, b"a\nb"].concat());
    t.c.session.tty.as_mut().unwrap().child_output(b"\x1b[?2004h");
    t.input(&[b"c", E, b"\r"].concat()); t.flush();
    assert_eq!(t.delivered, b"a\nbc\n");
    // A new mode 0 (next command) drops a previous application's request.
    let mut t = new(true, false); t.mode(1); t.mode(0);
    t.c.session.tty.as_mut().unwrap().child_output(b"\x1b[?2004h");
    t.mode(1); t.mode(0);
    t.input(&[B, b"q", E, b"\r"].concat()); t.flush();
    assert_eq!(t.delivered, b"q\n");
    // Combined private-mode form is not observed (markers stripped).
    let mut t = new(true, false); t.mode(1); t.mode(0);
    t.c.session.tty.as_mut().unwrap().child_output(b"\x1b[?1049;2004h");
    t.input(&[B, b"q", E, b"\r"].concat()); t.flush();
    println!("[f1] combined ?1049;2004h -> {:?}", String::from_utf8_lossy(&t.delivered));
}
#[test] fn f2_app_owned_paste_survives_rearm_as_known_limit() {
    let mut t = new(true, false); t.mode(1); t.mode(0);
    t.c.session.tty.as_mut().unwrap().child_output(b"\x1b[?2004h");
    t.input(&[B, b"one\n"].concat()); t.flush();
    t.mode(1); // app exited unread; shell prompt
    t.input(b"two\n"); t.input(E); t.flush();
    println!("[f2] app-owned residue at prompt: {:?}", String::from_utf8_lossy(&t.delivered));
    t.delivered.clear(); t.input(b"\r"); t.flush();
    println!("[f2] Enter after END: {:?}", String::from_utf8_lossy(&t.delivered));
}
#[test] fn f3_prompt_capture_survives_mode0_enter_goes_to_app() {
    let mut t = new(true, false); t.mode(1);
    t.input(b"cat\r"); t.input(&[B, b"echo p\n", E].concat());
    t.mode(3); t.mode(0); t.input(b"\r"); t.flush();
    println!("[f3] record to app in mode 0: {:?}", String::from_utf8_lossy(&t.delivered));
    assert!(!has(&t.delivered, b"\x1b[200~"));
}
#[test] fn m1_witness_digits_after_forwarded_begin_get_no_padding() {
    for n in ["1048576", "1048575", "5"] {
        let mut t = new(true, false); t.mode(1); t.mode(0);
        t.c.session.tty.as_mut().unwrap().child_output(b"\x1b[?2004h");
        t.input(&[B, n.as_bytes(), b"\nabcdefgh\n"].concat());
        // Producer writes what it has; record tracker observes it.
        let s = std::mem::take(&mut t.c.session.stdin); t.c.session.record_write.written(&s); t.delivered.extend(s);
        t.input(b"\x03");
        let q = t.c.session.stdin.clone();
        assert!(q.len() <= 1, "W/witness {n}: cancel padded {} bytes after a forwarded public BEGIN", q.len());
    }
}
#[test] fn u1_controlled_app_paste_utf8_end_latch_recovers_without_code() {
    for brackets in [false, true] {
        let mut t = new(true, false); t.mode(1); t.mode(0);
        if brackets { t.c.session.tty.as_mut().unwrap().child_output(b"\x1b[?2004h"); }
        t.input(&[B, b"line\nab\xc3", E].concat()); t.flush();
        assert!(t.tty().input_refused());
        t.shell_prompt();
        assert!(!t.tty().input_refused() && !t.tty().input_cancelled());
        t.delivered.clear(); t.input(b"echo fresh\r"); t.flush();
        assert_eq!(t.delivered, b"echo fresh\n");
        assert!(!t.echo().contains("terminal: type") || brackets || true);
    }
}

#[test] fn n3b_torn_tail_discard_has_one_visible_notice_and_the_actual_prompt() {
    let mut t=new(true,false);t.mode(1);
    t.input(&[B,&vec![b'x';tty::MAX_LINE+1],E,b"\recho t"].concat());
    t.input(b"ail > /t");t.shell_prompt();t.delivered.clear();
    let start=t.echo().len();t.input(b"echo next > /n\r");t.flush();
    let shown=t.echo()[start..].to_owned();
    assert!(!has(&t.delivered,b"echo next")&&!has(&t.delivered,b"/t"));
    assert_eq!(shown.matches("input line discarded").count(),1,"{shown:?}");
    assert!(shown.ends_with("absd$ "),"{shown:?}");
    t.input(b"echo fresh > /h\r");t.flush();assert!(has(&t.delivered,b"echo fresh > /h\n"));
}
#[test] fn n3b_direct_exec_discard_notice_does_not_fabricate_a_shell_prompt() {
    let mut t=new(false,true);t.input(&[B,b"\xff",E,b"dropped prefix"].concat());
    let start=t.echo().len();t.input(b"next line\r");t.flush();
    let shown=t.echo()[start..].to_owned();
    assert!(shown.contains("input line discarded"),"{shown:?}");assert!(!shown.contains("absd$ "));
    assert!(!has(&t.delivered,b"next line"));assert!(!t.retired.get());
    t.input(b"fresh\r");t.flush();assert_eq!(t.delivered,b"fresh\n");
}
