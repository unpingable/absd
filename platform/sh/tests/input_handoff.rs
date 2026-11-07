//! Production shell input adapter and evaluator over a real shared host pipe.
//! The raw ABSD backend is substituted by read(0); a real child inherits fd0.
use absd_sh::*;
use std::{
    cell::{Cell, RefCell},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    process::{Command, Stdio},
    rc::Rc,
};
#[path = "../../src/sh_input.rs"]
mod input;
#[path = "../../ssh/src/paste.rs"]
#[allow(dead_code)]
mod paste;

thread_local! { static NEXT_RESULT: Cell<Option<isize>> = const { Cell::new(None) }; }
unsafe extern "C" {
    fn read(fd: i32, bytes: *mut u8, length: usize) -> isize;
}
#[unsafe(no_mangle)]
unsafe extern "C" fn __absd_std_read(bytes: *mut u8, length: usize) -> isize {
    if let Some(result) = NEXT_RESULT.with(|next| next.take()) {
        return result;
    }
    let n = unsafe { read(0, bytes, length) };
    if n < 0 {
        -(io::Error::last_os_error().raw_os_error().unwrap_or(5) as isize)
    } else {
        n
    }
}
struct Inherited {
    foreground: Rc<RefCell<Vec<u8>>>,
    cancel_pending: bool,
    cancel_after_read: bool,
    records: bool,
}
impl Host for Inherited {
    type Source = File;
    type Sink = File;
    fn open_read(&mut self, path: &str) -> io::Result<File> {
        File::open(path)
    }
    fn open_write(&mut self, path: &str, append: bool) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .append(append)
            .truncate(!append)
            .open(path)
    }
    fn is_dir(&mut self, path: &str) -> io::Result<bool> {
        fs::metadata(path).map(|m| m.is_dir())
    }
    fn session_request(&mut self, _: SessionRequest) -> io::Result<(i32, String)> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn read_interactive(&mut self, input: &mut dyn io::BufRead, text: &mut String) -> io::Result<usize> {
        if self.records { read_interactive_record(input, text) } else { input.read_line(text) }
    }
    fn prompt_cancelled(&mut self) -> bool {
        std::mem::take(&mut self.cancel_pending)
    }
    fn prompt_input(&mut self, mode: u8) {
        if mode == 3 && std::mem::take(&mut self.cancel_after_read) {
            self.cancel_pending = true;
        }
    }
    fn discard_pending_input(&mut self) {
        // The parent wrote these bounded bytes and closed its pipe. This
        // actual fd drain models the target's acknowledged, paused producer;
        // it cannot consume a later fresh command from an active writer.
        let mut bytes = [0u8; 256];
        let mut discarded = 0;
        loop {
            let n = unsafe { read(0, bytes.as_mut_ptr(), bytes.len()) };
            assert!(n >= 0, "host pipe drain failed");
            if n == 0 { break; }
            discarded += n as usize;
            assert!(discarded <= 4096, "fixture input exceeded its bound");
        }
    }
    fn run(&mut self, stages: Vec<Stage<File, File>>) -> Vec<Ran> {
        use std::os::unix::process::ExitStatusExt;
        stages
            .into_iter()
            .map(|stage| {
                let mut command = Command::new(stage.program);
                command.args(stage.args).stdout(Stdio::piped()).stderr(Stdio::piped());
                let bytes = match stage.stdin {
                    Input::Inherit => { command.stdin(Stdio::inherit()); None },
                    Input::Bytes(bytes) => { command.stdin(Stdio::piped()); Some(bytes) },
                    _ => panic!("input handoff fixture accepts inherited or heredoc input"),
                };
                let exit = command.spawn().and_then(|mut child| {
                    let feed = bytes.map(|bytes| {
                        let mut writer = child.stdin.take().unwrap();
                        std::thread::spawn(move || writer.write_all(&bytes))
                    });
                    let result = child.wait_with_output();
                    if let Some(feed) = feed { feed.join().unwrap()?; }
                    result
                })
                    .map(|out| {
                        self.foreground.borrow_mut().extend(out.stdout);
                        if out.status.signal() == Some(2) {
                            Exit::Interrupted
                        } else {
                            Exit::Code(out.status.code().unwrap_or(128))
                        }
                    });
                Ran {
                    exit,
                    redirect: None,
                }
            })
            .collect()
    }
}

#[test]
fn session_child() {
    let Ok(case) = std::env::var("ABSD_INPUT_HANDOFF_CHILD") else {
        return;
    };
    let foreground = Rc::new(RefCell::new(Vec::new()));
    let mut shell = Shell::new(
        Inherited {
            foreground: foreground.clone(),
            cancel_pending: case == "prompt-cancel",
            cancel_after_read: case == "prompt-cancel-after-line" || case == "record-mid-cancel",
            records: case.starts_with("record-"),
        },
        "/".into(),
    );
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mode = if case == "script" {
        Mode::Stdin(Vec::new())
    } else {
        Mode::Interactive
    };
    let status = if mode == Mode::Interactive {
        session(
            &mut shell,
            mode,
            &mut input::interactive(),
            &mut out,
            &mut err,
        )
    } else {
        session(
            &mut shell,
            mode,
            &mut io::stdin().lock(),
            &mut out,
            &mut err,
        )
    };
    let out = String::from_utf8(out).unwrap();
    let err = String::from_utf8(err).unwrap();
    if case == "heredoc-eof" {
        assert_eq!(status, 2, "{out:?} {err:?}");
        assert!(err.contains("unterminated heredoc"), "{err:?}");
        assert!(foreground.borrow().is_empty());
        assert!(!out.contains("BEFORE"));
        return;
    }
    let expected_status = if case.starts_with("prompt-cancel") || case == "record-mid-cancel" { STATUS_INTERRUPTED } else { 0 };
    assert_eq!(status, expected_status, "{out:?} {err:?}");
    assert!(err.is_empty(), "{err:?}");
    match case.as_str() {
        "paste" => assert_eq!(
            foreground.borrow().as_slice(),
            b"operator_trial149_unique_paste_20261105\n"
        ),
        "sequential" => assert_eq!(out, "absd$ first\nabsd$ second\nabsd$ "),
        "multiline" => assert_eq!(out, "absd$ > first\nsecond\nabsd$ caf\u{e9}\nabsd$ "),
        "interrupt" => assert!(out.contains("after=130\n"), "{out:?}"),
        "prompt-cancel" | "prompt-cancel-after-line" => {
            assert!(!out.contains("discarded"), "{out:?}");
            assert!(!out.contains("restored"), "queued input escaped the drain: {out:?}");
        }
        "record-child" => {
            assert!(foreground.borrow().is_empty()); assert_eq!(out,"absd$ after-record\nabsd$ ");
        }
        "record-child-data" => {
            assert_eq!(foreground.borrow().as_slice(),b"application data\n"); assert_eq!(out,"absd$ after-record\nabsd$ ");
        }
        "record-prefix" => assert_eq!(out,"absd$ prefix\nabsd$ "),
        "record-eaten" => {
            assert_eq!(foreground.borrow().as_slice(), record(b"echo source-as-data\n"));
            assert!(!out.contains("source-as-data"));
        }
        "record-mid-cancel" => { assert!(foreground.borrow().is_empty()); assert!(!out.contains("must-not-run")); },
        "script" => assert_eq!(out, "first\nsecond\n"),
        "record-heredoc" | "record-heredoc-body" => {
            assert_eq!(foreground.borrow().as_slice(), b"payload\n");
            let expected = if case == "record-heredoc" { "absd$ after\nabsd$ " } else { "absd$ > after\nabsd$ " };
            assert_eq!(out, expected);
        }
        "heredoc" => {
            assert_eq!(foreground.borrow().as_slice(), b"payload\n");
            assert_eq!(out, "absd$ > > absd$ after\nabsd$ ");
        }
        _ => panic!("unknown case"),
    }
}

#[test]
fn pasted_heredoc_collects_body_without_consuming_following_commands() {
    child("heredoc", b"/bin/cat <<EOF\npayload\nEOF\necho after\n");
}

#[test]
fn pasted_unterminated_heredoc_refuses_before_any_command() {
    child("heredoc-eof", b"echo BEFORE; /bin/cat <<EOF\npayload\n");
}
fn child(case: &str, bytes: &[u8]) {
    let mut process = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "session_child", "--nocapture"])
        .env("ABSD_INPUT_HANDOFF_CHILD", case)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    process.stdin.take().unwrap().write_all(bytes).unwrap();
    let output = process.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "case={case} stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn pasted_foreground_input_stays_in_the_inherited_pipe() {
    child("paste", b"cat\noperator_trial149_unique_paste_20261105\n");
}
#[test]
fn sequential_pasted_commands_still_run() {
    child("sequential", b"echo first\necho second\nexit\n");
}
#[test]
fn multiline_and_utf8_use_the_existing_parser() {
    child(
        "multiline",
        "echo 'first\nsecond'\necho caf\u{e9}\nexit\n".as_bytes(),
    );
}
#[test]
fn actual_interrupted_child_preserves_following_commands() {
    child(
        "interrupt",
        b"/usr/bin/env /bin/sh -c 'kill -INT $$'\necho after=$?\nexit\n",
    );
}
#[test]
fn prompt_interrupt_discards_queued_following_commands() {
    for case in ["prompt-cancel", "prompt-cancel-after-line"] {
        child(case, b"echo discarded\necho restored\nexit\n");
    }
}
#[test]
fn stdin_script_mode_still_consumes_the_script() {
    child("script", b"echo first\necho second\n");
}

#[test]
fn raw_input_keeps_empty_eof_and_error_semantics_and_checks_counts() {
    use std::io::{ErrorKind, Read};
    let mut raw = input::RawStdin;
    NEXT_RESULT.with(|r| r.set(Some(-1)));
    assert_eq!(raw.read(&mut []).unwrap(), 0);
    // Empty reads did not call the backend or consume its next result.
    assert_eq!(
        raw.read(&mut [0; 2]).unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    for (result, kind) in [
        (-2, ErrorKind::NotFound),
        (-11, ErrorKind::WouldBlock),
        (-12, ErrorKind::OutOfMemory),
        (-14, ErrorKind::InvalidInput),
        (-22, ErrorKind::InvalidInput),
        (-24, ErrorKind::QuotaExceeded),
        (-32, ErrorKind::BrokenPipe),
        (-38, ErrorKind::Unsupported),
        (-110, ErrorKind::TimedOut),
        (-4, ErrorKind::Other),
    ] {
        NEXT_RESULT.with(|r| r.set(Some(result)));
        assert_eq!(raw.read(&mut [0; 2]).unwrap_err().kind(), kind);
    }
    NEXT_RESULT.with(|r| r.set(Some(0)));
    assert_eq!(raw.read(&mut [0; 2]).unwrap(), 0);
    NEXT_RESULT.with(|r| r.set(Some(3)));
    assert_eq!(
        raw.read(&mut [0; 2]).unwrap_err().kind(),
        ErrorKind::InvalidData
    );
}

fn record(source: &[u8]) -> Vec<u8> {
    [format!("{}{}\n",INPUT_RECORD_PREFIX,source.len()).into_bytes(),source.to_vec()].concat()
}
#[test]
fn approved_record_keeps_commands_out_of_the_first_child_stdin() {
    child("record-child", &record(b"cat\necho after-record\n"));
    child("record-child-data", &[record(b"cat\necho after-record\n"),b"application data\n".to_vec()].concat());
}
#[test]
fn record_appends_to_partial_physical_line_without_parsing_its_header() {
    child("record-prefix", &[b"echo pre".to_vec(),record(b"fix\n")].concat());
}
#[test]
fn earlier_foreground_command_consumes_a_record_as_data_including_framing() {
    // Explicit transport limit: an already queued native reader inherits the
    // FIFO. This is not claimed to give that application plain clipboard bytes.
    child("record-eaten", &[b"cat\n".to_vec(),record(b"echo source-as-data\n")].concat());
}
#[test]
fn padded_record_reaches_the_real_cancel_fence_without_executing_a_suffix() {
    let mut source=b"echo must-not-run\n".to_vec(); source.resize(65536,b'x');
    let wire=record(&source);
    for cut in [1,4,6,9,14,18,1024,wire.len()-1] {
        let mut tracker=paste::RecordWrite::default(); tracker.written(&wire[..cut]);
        let (header,left)=tracker.cancel_padding(&wire[cut..]).unwrap();
        let mut padded=wire[..cut].to_vec();padded.extend(header);padded.resize(padded.len()+left,b'\n');
        child("record-mid-cancel", &padded);
    }
    let source="é".repeat(40).into_bytes(); let wire=record(&source);
    let cut=wire.len()-source.len()+1;
    let mut tracker=paste::RecordWrite::default(); tracker.written(&wire[..cut]);
    let (header,left)=tracker.cancel_padding(&wire[cut..]).unwrap();
    let mut padded=wire[..cut].to_vec();padded.extend(header);padded.resize(padded.len()+left,b'\n');
    child("record-mid-cancel", &padded);

}

#[test]
fn heredoc_record_delivers_exact_body_to_real_child_and_runs_following_command() {
    child("record-heredoc", &record(b"/bin/cat <<EOF\npayload\nEOF\necho after\n"));
    child("record-heredoc-body", &[b"/bin/cat <<EOF\n".to_vec(),record(b"payload\nEOF\necho after\n")].concat());
}
