#![feature(restricted_std)]
//! Runs as an init-brokered worker and exercises `std::process` through the
//! broker under `broker-policy.txt`: four slots; only the path `broker-echo`
//! with exactly two free arguments is permitted, and that child is given
//! `BROKER_ECHO=hello=world`. Every other request must be refused. Uses all
//! four slots, in order.

use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};

const ECHO: &str = "broker-echo";
/// What `broker-echo` reports of the environment the policy gives it.
const ECHO_ENV: &[u8] = b"broker-echo env=BROKER_ECHO=hello=world\n";

struct Checks(u32);

impl Checks {
    fn check(&mut self, name: &str, ok: bool, detail: impl std::fmt::Debug) {
        if ok {
            self.0 += 1;
            println!("ABSD BROKER {name} OK");
        } else {
            println!("ABSD BROKER REQUESTER FAIL {name}: {detail:?}");
            std::process::exit(1);
        }
    }
}

fn kind<T>(result: std::io::Result<T>) -> Option<ErrorKind> {
    result.err().map(|error| error.kind())
}

fn main() {
    absd_runtime::link_anchor();
    let mut checks = Checks(0);

    // The policy gives this worker no environment; it is read-only anyway.
    let own = (std::env::vars().count(), std::env::var_os("BROKER_ECHO"));
    checks.check("own-env-empty", own == (0, None), own);

    // Refused locally: nothing is sent and no slot is spent.
    let env = kind(Command::new(ECHO).args(["0", "x"]).env("A", "B").output());
    checks.check("env-unsupported", env == Some(ErrorKind::Unsupported), env);
    let cwd = kind(Command::new(ECHO).args(["0", "x"]).current_dir("/").output());
    checks.check("cwd-unsupported", cwd == Some(ErrorKind::Unsupported), cwd);
    let inherit = kind(Command::new(ECHO).args(["0", "x"]).spawn());
    checks.check("stdin-inherit-unsupported", inherit == Some(ErrorKind::Unsupported), inherit);

    // Refused by init: spends nothing.
    let path = kind(Command::new("not-in-policy").args(["0", "x"]).output());
    checks.check("refused-path", path == Some(ErrorKind::PermissionDenied), path);
    let argc = kind(Command::new(ECHO).arg("0").output());
    checks.check("refused-argc", argc == Some(ErrorKind::PermissionDenied), argc);

    // Slot 0: stdin to stdout, argv on stderr.
    let mut child = Command::new(ECHO)
        .args(["0", "alpha"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn slot 0");
    checks.check("pid", child.id() != 0, child.id());
    child.stdin.take().unwrap().write_all(b"hello broker\n").unwrap();
    let output = child.wait_with_output().unwrap();
    checks.check("piped-stdout", output.stdout == b"hello broker\n", &output.stdout);
    checks.check("piped-stderr", output.stderr == [b"broker-echo args=0,alpha\n", ECHO_ENV].concat(), &output.stderr);
    checks.check("exit-zero", output.status.success() && output.status.code() == Some(0), output.status);

    // Slot 1 (a fault, output null) and slot 2 (inherited stdout) run at
    // once; try_wait on slot 2 while slot 1's replies may arrive and must be
    // filed for later, and the two are waited out of order.
    let mut faulting = Command::new(ECHO)
        .args(["fault", "gamma"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn slot 1");
    let mut child = Command::new(ECHO)
        .args(["7", "zeta"])
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn slot 2");
    let early = child.try_wait().unwrap();
    checks.check("try-wait-running", early.is_none(), early);
    child.stdin.take().unwrap().write_all(b"ABSD BROKER INHERITED LINE\n").unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
    };
    checks.check("exit-seven", !status.success() && status.code() == Some(7), status);
    let again = child.wait().unwrap();
    checks.check("wait-after-try-wait", again == status, again);
    let kill = kind(child.kill());
    checks.check("kill-unsupported", kill == Some(ErrorKind::Unsupported), kill);
    let status = faulting.wait().unwrap();
    checks.check(
        "fault",
        !status.success() && status.code().is_none() && status.to_string() == "fault: vector 6",
        status.to_string(),
    );

    // Slot 3: output() reads both streams to the end without deadlock.
    let output = Command::new(ECHO).args(["flood", "delta"]).output().unwrap();
    checks.check(
        "flood",
        output.status.success()
            && output.stdout.len() == 8192
            && output.stderr.len() == 8192 + "broker-echo args=flood,delta\n".len() + ECHO_ENV.len(),
        (output.stdout.len(), output.stderr.len()),
    );

    // Every slot is spent.
    let spent = kind(Command::new(ECHO).args(["0", "eta"]).output());
    checks.check("slots-exhausted", spent == Some(ErrorKind::QuotaExceeded), spent);

    println!("ABSD BROKER REQUESTER OK checks={}", checks.0);
}
