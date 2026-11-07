//! SSH diagnostics use ordinary stdout for known routine information and
//! stderr for failures and unclassified events. Init captures both streams with its
//! trusted service/PID label; FSD's collector persists it and maintains the
//! legacy /var/log/sshd projection. The producer never synchronously opens,
//! rotates or writes a log through the very service it is diagnosing.
pub fn line(text: String) {
    eprintln!("{text}");
}

/// Known routine information. Init assigns info priority from stdout;
/// producer text cannot forge the trusted service/PID metadata.
pub fn info(text: String) {
    println!("{text}");
}

pub fn session_exit(prefix: &str, exit: crate::conn::Exit) {
    let text = format!("{prefix} session child exited: {exit:?}");
    match exit {
        crate::conn::Exit::Code(0) => info(text),
        _ => line(text),
    }
}

/// Reporting only: Ending keeps ownership of wait/kill/release decisions.
#[cfg_attr(not(target_os = "absd"), allow(dead_code))]
pub fn ending_result(
    pid: u32,
    sent: bool,
    took: u128,
    read: i64,
    result: std::io::Result<std::process::ExitStatus>,
) {
    match result {
        Ok(status) => {
            let text = format!(
                "SSH SESSION END pid={pid} sent={} exited=true forced=false ms={took} read={read}",
                u8::from(sent)
            );
            if status.success() {
                info(text)
            } else {
                line(text)
            }
        }
        Err(error) => line(format!(
            "SSH SESSION END pid={pid} sent={} exited=unknown forced=false ms={took} read={read} wait_error={error}",
            u8::from(sent)
        )),
    }
}

#[cfg(target_os = "absd")]
pub fn open() {}
#[cfg(target_os = "absd")]
pub fn flush() {}

/// Existing control notices remain for the file-server test controls and
/// console announcements. They have a finite transport budget; diagnostic
/// persistence itself never depends on this round trip.
#[cfg(target_os = "absd")]
pub fn notice(text: &str) {
    use absd_fsd::proto::{Frame, MAX_NOTICE, op};
    line(text.to_string());
    let bytes = &text.as_bytes()[..text.len().min(MAX_NOTICE)];
    let _ = absd_runtime::fsd::request_on_within(
        0,
        Frame::request(op::NOTICE).bytes(bytes).finish(),
        100,
    );
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn captured_actual_reporting_distinguishes_success_failure_and_unknown_wait() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "oplog::tests::emit_actual_reporting",
                "--nocapture",
            ])
            .env("ABSD_OPLOG_TEST_CHILD", "1")
            .output()
            .unwrap();
        assert!(result.status.success());
        let out = String::from_utf8(result.stdout).unwrap();
        let err = String::from_utf8(result.stderr).unwrap();
        for expected in [
            "routine explicit info",
            "conn-zero session child exited: Code(0)",
            "pid=41 sent=1 exited=true",
        ] {
            assert!(out.contains(expected), "missing info: {expected}");
            assert!(!err.contains(expected), "info became warning: {expected}");
        }
        for expected in [
            "unclassified stays warning",
            "conn-seven session child exited: Code(7)",
            "conn-abnormal session child exited: Abnormal",
            "pid=42 sent=1 exited=true",
            "pid=43 sent=1 exited=unknown",
            "wait_error=wait refused",
        ] {
            assert!(err.contains(expected), "missing warning: {expected}");
            assert!(!out.contains(expected), "warning became info: {expected}");
        }
    }

    #[test]
    fn emit_actual_reporting() {
        if std::env::var_os("ABSD_OPLOG_TEST_CHILD").is_none() {
            return;
        }
        info("routine explicit info".into());
        line("unclassified stays warning".into());
        session_exit("conn-zero", crate::conn::Exit::Code(0));
        session_exit("conn-seven", crate::conn::Exit::Code(7));
        session_exit("conn-abnormal", crate::conn::Exit::Abnormal);
        ending_result(41, true, 2, 0, Ok(std::process::ExitStatus::from_raw(0)));
        ending_result(
            42,
            true,
            2,
            0,
            Ok(std::process::ExitStatus::from_raw(7 << 8)),
        );
        ending_result(43, true, 2, 0, Err(std::io::Error::other("wait refused")));
    }
}
