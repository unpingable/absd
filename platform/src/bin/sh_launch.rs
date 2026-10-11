#![feature(restricted_std)]
#![feature(absd_fs_ext)]
//! The `FS SHELL` harness's durable worker (started by init from the
//! catalog). It mounts the filesystem (writable: it is the exclusive
//! writer, and every child gets a read-only view) and then:
//!
//! 1. runs `/bin/absd-sh`, a filesystem executable, through
//!    `std::process::Command` on this process's own standard input (the
//!    scripted session, inherited), then as `absd-sh -c "ls /"`; each run's
//!    exit status is reported, and the shell and its children write
//!    straight to the console;
//! 2. checks the pipe discipline the shell's composition relies on, with
//!    negative controls: a pipe end given to a child is consumed (closed
//!    here) by the successful spawn and not by a refused one; a retained
//!    writer copy keeps the reader from seeing end-of-file and closing it
//!    delivers end-of-file; a retained reader copy keeps a writer blocked
//!    instead of broken and closing it delivers the broken pipe; a writer
//!    whose readers are all gone gets the kernel's `-32` and, through
//!    `std`, `io::ErrorKind::BrokenPipe`, and keeps running; an end is
//!    only ever given with the right its stream needs;
//! 3. runs the shell's own executor (`sh/src/lib.rs` with
//!    `src/sh_host.rs`, the code `/bin/absd-sh` runs) in this process,
//!    which holds write authority, so `>`/`>>` work: the shell opens the
//!    target, the child gets only a pipe end, and a child whose stdout is
//!    a file cannot write that file or any other itself.

// Only the executor is used here, not the session loop.
#[allow(dead_code)]
#[path = "../../sh/src/lib.rs"]
mod shell;
#[path = "../sh_host.rs"]
mod sh_host;
#[path = "../../ssh/src/control.rs"]
#[allow(dead_code)]
mod session_control;

use std::io::{Read, Write};
use std::os::absd::process::AsRawHandle;
use std::process::{Command, Stdio};

use absd_runtime::{RIGHT_READ, RIGHT_WRITE};

type Checked = Result<(), String>;

fn check(condition: bool, what: &str) -> Checked {
    if condition { Ok(()) } else { Err(what.to_owned()) }
}

fn report(what: &str, result: std::io::Result<std::process::ExitStatus>) -> Option<i32> {
    let code = match result {
        Ok(status) => status.code(),
        Err(error) => {
            println!("SH LAUNCH FAILED {what}: {error}");
            return None;
        }
    };
    println!("SH LAUNCH {what} status={}", code.map_or("none".to_string(), |c| c.to_string()));
    code
}

fn probe(args: &[&str]) -> Command {
    let mut command = Command::new("/bin/sh-probe");
    command.args(args);
    command
}

fn text(pipe: &mut impl Read) -> Result<String, String> {
    let mut text = String::new();
    pipe.read_to_string(&mut text).map_err(|error| error.to_string())?;
    Ok(text)
}

fn failed(what: &str) -> impl Fn(std::io::Error) -> String + '_ {
    move |error| format!("{what}: {error}")
}

/// Pattern sum of `sh-probe flood N`.
fn flood_sum(count: usize) -> u32 {
    (0..count).fold(0u32, |sum, i| sum.wrapping_add((i % 251) as u32))
}

/// `a | b` by hand: the read end moves into `b` and is closed here by the
/// successful spawn, while the `Command` that held it still exists.
fn consumed() -> Checked {
    let mut a = probe(&["flood", "5000"]).stdout(Stdio::piped()).spawn().map_err(failed("flood"))?;
    let reader = a.stdout.take().unwrap();
    let raw = reader.as_raw_handle();
    let mut b_command = probe(&["count"]);
    b_command.stdin(Stdio::from(reader)).stdout(Stdio::piped());
    let mut b = b_command.spawn().map_err(failed("count"))?;
    let after = absd_runtime::duplicate(raw, RIGHT_READ);
    if let Ok(copy) = after {
        let _ = absd_runtime::close(copy);
    }
    let again = b_command.spawn().map(|_| ()).map_err(|error| error.kind());
    let counted = text(b.stdout.as_mut().unwrap())?;
    let (a_status, b_status) = (a.wait().map_err(failed("wait"))?, b.wait().map_err(failed("wait"))?);
    println!(
        "SH PIPE consumed parent-copy-after-spawn={} respawn={:?} count={} statuses={},{}",
        after.map_or_else(|code| code.to_string(), |_| "open".into()),
        again.unwrap_err(),
        counted.trim_end(),
        a_status.code().unwrap_or(-1),
        b_status.code().unwrap_or(-1)
    );
    check(after.is_err(), "the parent's read end survived the spawn")?;
    check(counted == format!("COUNT bytes=5000 sum={}\n", flood_sum(5000)), "count")?;
    check(again == Err(std::io::ErrorKind::InvalidInput), "respawn")?;
    check(a_status.success() && b_status.success(), "statuses")
}

/// A writer copy kept here suppresses end-of-file; closing it delivers it.
fn retained_writer() -> Checked {
    let mut child = probe(&["count"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(failed("count"))?;
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&vec![7u8; 3000]).map_err(failed("write"))?;
    let retained = absd_runtime::duplicate(stdin.as_raw_handle(), RIGHT_WRITE).map_err(|c| format!("dup {c}"))?;
    drop(stdin);
    let stdout = child.stdout.take().unwrap();
    let mut buffer = [0u8; 64];
    let waited = absd_runtime::read_within(stdout.as_raw_handle(), &mut buffer, 300);
    let running = child.try_wait().map_err(failed("try_wait"))?.is_none();
    absd_runtime::close(retained).map_err(|c| format!("close {c}"))?;
    let mut stdout = stdout;
    let counted = text(&mut stdout)?;
    let status = child.wait().map_err(failed("wait"))?;
    println!(
        "SH PIPE retained-writer while-held={} running={running} after-close={} status={}",
        waited.map_or_else(|code| code.to_string(), |n| format!("read {n}")),
        counted.trim_end(),
        status.code().unwrap_or(-1)
    );
    check(waited == Err(-110) && running, "a retained writer did not suppress end-of-file")?;
    check(counted == format!("COUNT bytes=3000 sum={}\n", 3000 * 7) && status.success(), "eof after close")
}

/// A reader copy kept here keeps the writer blocked instead of broken;
/// closing it turns the block into a typed broken pipe.
fn retained_reader() -> Checked {
    let mut writer = probe(&["flood", "65536"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(failed("flood"))?;
    let reader = writer.stdout.take().unwrap();
    let retained = absd_runtime::duplicate(reader.as_raw_handle(), RIGHT_READ).map_err(|c| format!("dup {c}"))?;
    let mut head = probe(&["head", "4"])
        .stdin(Stdio::from(reader))
        .stdout(Stdio::piped())
        .spawn()
        .map_err(failed("head"))?;
    let headed = text(head.stdout.as_mut().unwrap())?;
    let head_status = head.wait().map_err(failed("wait head"))?;
    absd_runtime::sleep_ticks(300);
    let blocked = writer.try_wait().map_err(failed("try_wait"))?.is_none();
    absd_runtime::close(retained).map_err(|c| format!("close {c}"))?;
    let complaint = text(writer.stderr.as_mut().unwrap())?;
    let status = writer.wait().map_err(failed("wait flood"))?;
    println!(
        "SH PIPE retained-reader head={} head-status={} writer-blocked-while-held={blocked} \
         after-close-status={} stderr={}",
        headed.trim_end(),
        head_status.code().unwrap_or(-1),
        status.code().unwrap_or(-1),
        complaint.trim_end()
    );
    check(headed == "HEAD 4 bytes=[0, 1, 2, 3]\n" && head_status.success(), "head")?;
    check(blocked, "a retained reader did not keep the writer blocked")?;
    check(status.code() == Some(3) && complaint.contains("BrokenPipe"), "broken pipe after close")
}

/// Every reader gone: the kernel's -32, `std`'s BrokenPipe, no signal.
fn broken_pipe() -> Checked {
    let mut child = probe(&["head", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(failed("head"))?;
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"x").map_err(failed("write"))?;
    let headed = text(child.stdout.as_mut().unwrap())?;
    let status = child.wait().map_err(failed("wait"))?;
    let raw = absd_runtime::write_within(stdin.as_raw_handle(), b"y", 1);
    let typed = stdin.write(b"y").map_err(|error| error.kind());
    println!(
        "SH BROKEN PIPE reader-exited={} raw={} std={:?} writer-still-running=yes",
        status.code().unwrap_or(-1),
        raw.map_or_else(|code| code.to_string(), |n| format!("wrote {n}")),
        typed.unwrap_err()
    );
    check(headed == "HEAD 1 bytes=[120]\n" && status.success(), "head")?;
    check(raw == Err(-32) && typed == Err(std::io::ErrorKind::BrokenPipe), "broken pipe")
}

/// Ends are given with one right only: a write end as stdin is refused by
/// the kernel, and the refused spawn consumes nothing.
fn rights() -> Checked {
    let mut cat = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(failed("cat"))?;
    let writer = cat.stdin.take().unwrap();
    let mut wrong = probe(&["count"]);
    wrong.stdin(Stdio::from(writer));
    let refused = wrong.spawn().map(|_| ()).map_err(|error| error.kind());
    // The write end is still held (inside `wrong`): cat has no EOF yet.
    let still_running = cat.try_wait().map_err(failed("try_wait"))?.is_none();
    drop(wrong);
    let echoed = text(cat.stdout.as_mut().unwrap())?;
    let status = cat.wait().map_err(failed("wait"))?;
    println!(
        "SH PIPE rights write-end-as-stdin={:?} end-kept-by-refused-spawn={still_running} \
         eof-after-drop={} status={}",
        refused.unwrap_err(),
        echoed.is_empty(),
        status.code().unwrap_or(-1)
    );
    check(refused == Err(std::io::ErrorKind::PermissionDenied), "wrong right accepted")?;
    check(still_running && echoed.is_empty() && status.success(), "refused spawn consumed")
}

/// The shell's executor with this process's write authority.
fn redirect() -> Checked {
    let mut shell = shell::Shell::new(sh_host::Absd::new(), "/".to_string());
    let (mut out, mut err) = (std::io::stdout(), std::io::stdout());
    for line in [
        "sh-probe escape /etc/escaped /etc/redirected > /etc/redirected",
        "echo appended by the shell >> /etc/redirected",
        "sh-probe flood 20000 | sh-probe count > /etc/counted 2> /etc/count-errors",
        "cat < /etc/redirected",
        "cat /etc/counted /etc/escaped",
        "status",
    ] {
        println!("SH REDIRECT $ {line}");
        let _ = std::io::stdout().flush();
        shell.run_line(line, &mut out, &mut err);
    }
    let redirected = std::fs::read_to_string("/etc/redirected").map_err(failed("read"))?;
    let counted = std::fs::read_to_string("/etc/counted").map_err(failed("read"))?;
    let errors = std::fs::read("/etc/count-errors").map_err(failed("read"))?;
    let escaped = std::fs::metadata("/etc/escaped").map(|_| ()).map_err(|error| error.kind());
    check(
        redirected
            == "ESCAPE create=ReadOnlyFilesystem target=ReadOnlyFilesystem raw-block=-1\n\
                appended by the shell\n",
        "redirected file",
    )?;
    check(counted == format!("COUNT bytes=20000 sum={}\n", flood_sum(20000)), "counted file")?;
    check(errors.is_empty() && escaped == Err(std::io::ErrorKind::NotFound), "escape")?;
    println!("SH REDIRECT files redirected+appended counted errors-empty escaped=absent");
    Ok(())
}

fn main() {
    absd_runtime::link_anchor();
    if let Err(error) = absd_runtime::storage::mount(false, true) {
        println!("SH LAUNCH FAILED mount {error:?}");
        std::process::exit(1);
    }
    let _ = std::io::stdout().flush();
    let session = report("session", Command::new("/bin/absd-sh").status());
    let command = report(
        "command",
        Command::new("/bin/absd-sh").args(["-c", "ls /"]).stdin(Stdio::null()).status(),
    );
    let _ = std::io::stdout().flush();
    let mut ok = session == Some(3) && command == Some(0);
    for (name, step) in [
        ("consumed", consumed as fn() -> Checked),
        ("retained-writer", retained_writer),
        ("retained-reader", retained_reader),
        ("broken-pipe", broken_pipe),
        ("rights", rights),
        ("redirect", redirect),
    ] {
        if let Err(error) = step() {
            println!("SH LAUNCH FAILED {name}: {error}");
            ok = false;
            break;
        }
    }
    let _ = std::io::stdout().flush();
    std::process::exit(if ok { 0 } else { 1 });
}
