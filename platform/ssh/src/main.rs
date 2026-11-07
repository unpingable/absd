#![cfg_attr(target_os = "absd", feature(restricted_std))]
#![cfg_attr(target_os = "absd", feature(absd_fs_ext))]
//! A small SSH server on sunset's sans-IO core: one process, one thread, a
//! poll loop over the network and each session child's pipes.
//!
//! Security boundary: one operator identity (the keys of one
//! `authorized_keys` file, public key authentication only) gets bounded
//! sessions. The sftp subsystem is an ordinary restricted session worker.
//! There are no accounts, passwords, forwarding, or other subsystems,
//! and no claim of separation between several users. A PTY is a line
//! discipline in sshd (`tty`), not a kernel object.

/// A diagnostic line: stderr, and on ABSD `/var/log/sshd` (`oplog`).
macro_rules! say {
    ($($arg:tt)*) => { $crate::oplog::line(format!($($arg)*)) };
}

/// Routine service information, captured by init at info priority.
macro_rules! info {
    ($($arg:tt)*) => { $crate::oplog::info(format!($($arg)*)) };
}

mod conn;
#[cfg(any(target_os = "absd", test))]
mod pipe_read;
#[cfg(any(target_os = "absd", test))]
mod child_wait;
#[cfg_attr(not(target_os = "absd"), allow(dead_code))]
mod document;
#[cfg(test)]
mod document_tests;
#[cfg_attr(not(target_os = "absd"), allow(dead_code))]
mod etc;
mod oplog;
// The session control protocol; only the ABSD backend has the channel.
#[cfg_attr(not(target_os = "absd"), allow(dead_code))]
mod control;
mod keys;
mod motd;
mod tty;
mod plain_input;
mod local_console;
#[cfg_attr(not(target_os = "absd"), allow(dead_code))]
mod session_pool;
mod local_auth;

#[cfg(target_os = "absd")]
mod absd;
#[cfg(target_os = "absd")]
mod net_diagnostics;
#[cfg(target_os="absd")]
mod time_owner;
#[cfg(any(target_os="absd",test))]
mod time_policy;
#[cfg(unix)]
mod linux;

use std::path::PathBuf;
use std::time::Duration;

/// How an `exec` request's command string becomes a child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecMode {
    /// `<shell> -c <command>`, as OpenSSH runs it: the shell parses.
    Shell,
    /// The command split on ASCII whitespace; the first word names the
    /// program (a bare name is looked up in `bin_dir`). No quoting.
    Argv,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: String,
    pub host_key: PathBuf,
    pub authorized_keys: PathBuf,
    pub shell: PathBuf,
    pub exec_mode: ExecMode,
    pub bin_dir: PathBuf,
    pub limits: conn::Limits,
    pub max_connections: usize,
    pub regenerate_host_key: bool,
    /// Qualification only (a separately built `sshd-controls.elf`, whose
    /// arguments are fixed at build time; scripts/run-contain-matrix.sh):
    /// the `exec` words `qualification-kill-shells` (kill every session's
    /// shell without End) and `qualification-sshd-exit` (exit at once with
    /// sessions running). The installed sshd never has it.
    pub qualification_controls: bool,
}

impl Config {
    #[cfg(any(target_os = "absd", test))]
    fn initial_cwd(&self, command: &conn::Command) -> &'static str {
        match command {
            conn::Command::Shell | conn::Command::Sftp => "/home/operator",
            conn::Command::Exec(_) => "/",
        }
    }

    fn defaults() -> Self {
        Config {
            listen: "0.0.0.0:22".into(),
            host_key: "/ssh/host_ed25519_seed".into(),
            authorized_keys: "/ssh/authorized_keys".into(),
            shell: if cfg!(target_os = "absd") { "/bin/absd-sh" } else { "/bin/sh" }.into(),
            // On ABSD an exec runs the named program as sshd's own child
            // (see README "SSH"); the Linux reference runs `sh -c`.
            exec_mode: if cfg!(target_os = "absd") { ExecMode::Argv } else { ExecMode::Shell },
            bin_dir: "/bin".into(),
            limits: conn::Limits {
                auth_timeout: Duration::from_secs(30),
                idle_timeout: Duration::from_secs(1800),
                max_auth_failures: 6,
            },
            max_connections: 4,
            regenerate_host_key: false,
            qualification_controls: false,
        }
    }

    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut config = Self::defaults();
        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
            let millis = |v: String| {
                v.parse::<u64>().map(Duration::from_millis).map_err(|_| format!("{flag}: not a number"))
            };
            match flag.as_str() {
                "--listen" => config.listen = value()?,
                "--host-key" => config.host_key = value()?.into(),
                "--authorized-keys" => config.authorized_keys = value()?.into(),
                "--shell" => config.shell = value()?.into(),
                "--bin-dir" => config.bin_dir = value()?.into(),
                "--exec" => {
                    config.exec_mode = match value()?.as_str() {
                        "shell" => ExecMode::Shell,
                        "argv" => ExecMode::Argv,
                        other => return Err(format!("--exec {other}: shell or argv")),
                    }
                }
                "--auth-timeout-ms" => config.limits.auth_timeout = millis(value()?)?,
                "--idle-timeout-ms" => config.limits.idle_timeout = millis(value()?)?,
                "--max-auth-failures" => {
                    config.limits.max_auth_failures =
                        value()?.parse().map_err(|_| "--max-auth-failures: not a number")?
                }
                "--max-connections" => {
                    config.max_connections =
                        value()?.parse().map_err(|_| "--max-connections: not a number")?
                }
                "--regenerate-host-key" => config.regenerate_host_key = true,
                "--qualification-controls" => config.qualification_controls = true,
                other => return Err(format!("unknown argument {other}")),
            }
        }
        Ok(config)
    }

    /// Whether a session command runs as the shell (which keeps the spawn
    /// right, gets spare filesystem channels for its commands, and gets
    /// the session control channel): a `shell` request, any `exec` in shell
    /// mode, and in argv mode an `exec` whose text uses the shell's syntax
    /// (operators, quoting, expansion, assignments or script builtins),
    /// such as `cat > FILE`, the upload
    /// half of file transfer.
    pub fn runs_shell(&self, command: &conn::Command) -> bool {
        match command {
            conn::Command::Shell => true,
            conn::Command::Sftp => false,
            conn::Command::Exec(text) => {
                self.exec_mode == ExecMode::Shell || shell_syntax(text) || !self.direct(text)
            }
        }
    }

    /// Whether an argv-mode `exec` runs its first word as sshd's own child:
    /// a bare name (`/bin/NAME`) or exactly `/bin/NAME`. sshd reads a
    /// program image with its own filesystem authority, which holds `/bin`
    /// but not the session's mounts, so any other path (an uploaded program
    /// in `/home/operator`, say) runs under `absd-sh -c`, which reads it
    /// with the session's authority instead. Neither way can sshd's own
    /// mounts (`/ssh`) be read for a session.
    fn direct(&self, text: &str) -> bool {
        let Some(first) = text.split_ascii_whitespace().next() else { return true };
        if !first.contains('/') {
            return true;
        }
        // `--bin-dir /bin/` names the same directory as `/bin`.
        let configured = self.bin_dir.to_string_lossy();
        let bin = configured.trim_end_matches('/');
        first
            .strip_prefix(bin)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|name| !name.is_empty() && !name.contains('/') && name != "." && name != "..")
    }

    /// The program and arguments a session command runs.
    pub fn argv(&self, command: &conn::Command) -> Result<Vec<String>, String> {
        let shell = self.shell.to_string_lossy().into_owned();
        match (command, self.exec_mode) {
            (conn::Command::Shell, _) => Ok(vec![shell]),
            (conn::Command::Sftp, _) => Ok(vec![self.bin_dir.join("absd-sftp").to_string_lossy().into_owned()]),
            (conn::Command::Exec(text), ExecMode::Shell) => Ok(vec![shell, "-c".into(), text.clone()]),
            (conn::Command::Exec(text), ExecMode::Argv) if shell_syntax(text) || !self.direct(text) => {
                Ok(vec![shell, "-c".into(), text.clone()])
            }
            (conn::Command::Exec(text), ExecMode::Argv) => {
                let mut words: Vec<String> = text.split_ascii_whitespace().map(str::to_owned).collect();
                let Some(first) = words.first_mut() else { return Err("empty command".into()) };
                if !first.contains('/') {
                    *first = self.bin_dir.join(&*first).to_string_lossy().into_owned();
                }
                Ok(words)
            }
        }
    }
}

/// An `exec` text only the shell can run: a pipeline, a redirection, a
/// list, or a quoted word.
fn shell_syntax(text: &str) -> bool {
    if text.contains(['|', '<', '>', '"', '\'', ';', '&', '$', '`', '\\', '*', '?', '[', ']', '~', '(', ')', '{', '}', '\n', '#']) { return true; }
    let first = text.split_ascii_whitespace().next().unwrap_or("");
    first.contains('=') || matches!(first,
        "sh" | "/bin/sh" | "absd-sh" | "/bin/absd-sh" | "cd" | "exit" |
        "status" | "help" | "clock" | "true" | "false" | ":" | "export" | "unset" |
        "set" | "shift" | "break" | "continue" | "." | "if" | "for" |
        "while" | "until" | "case" | "!" | "ro" | "nofs" | "shutdown" | "reboot")
}

#[cfg(test)]
mod tests {
    use super::{Config, ExecMode, conn::Command};

    #[test]
    fn shell_requests_start_in_home_while_exec_keeps_root() {
        let mut config = Config::defaults();
        for mode in [ExecMode::Argv, ExecMode::Shell] {
            config.exec_mode = mode;
            assert_eq!(config.initial_cwd(&Command::Shell), "/home/operator");
            for text in ["pwd", "cat relative.txt", "echo quoted > file", "sh -s"] {
                assert_eq!(config.initial_cwd(&Command::Exec(text.into())), "/");
            }
        }
    }

    #[test]
    fn sftp_is_a_direct_worker_without_shell_authority_in_either_exec_mode() {
        let mut config = Config::defaults();
        config.bin_dir = "/trusted/bin".into();
        for mode in [ExecMode::Shell, ExecMode::Argv] {
            config.exec_mode = mode;
            assert_eq!(config.argv(&Command::Sftp).unwrap(), ["/trusted/bin/absd-sftp"]);
            assert!(!config.runs_shell(&Command::Sftp));
            assert_eq!(config.initial_cwd(&Command::Sftp), "/home/operator");
        }
    }

    #[test]
    fn exec_texts_with_shell_syntax_run_as_the_shell() {
        let mut config = Config::defaults();
        config.exec_mode = ExecMode::Argv;
        config.shell = "/bin/absd-sh".into();
        let exec = |text: &str| Command::Exec(text.into());
        assert_eq!(config.argv(&exec("cat /home/operator/f")).unwrap(), ["/bin/cat", "/home/operator/f"]);
        assert!(!config.runs_shell(&exec("cat /home/operator/f")));
        for text in ["cat > /home/operator/f", "cat >> f", "wc -l < f", "ls | wc -l", "echo \"a b\"", "mkdir d && ls d",
                     "cd /etc; pwd", "false || echo no"] {
            assert_eq!(config.argv(&exec(text)).unwrap(), ["/bin/absd-sh", "-c", text], "{text}");
            assert!(config.runs_shell(&exec(text)), "{text}");
        }
        assert!(config.runs_shell(&Command::Shell));
    }

    #[test]
    fn shell_expansions_and_script_builtins_keep_the_shell_authority() {
        let mut config = Config::defaults(); config.exec_mode = ExecMode::Argv;
        config.shell = "/bin/absd-sh".into();
        for text in ["echo 'two words'", "echo $HOME", "echo `pwd`", "echo *.txt", "echo a?", "echo [ab]", "echo a\\ b", "echo ~", "X=value", "export X", "cd /", "sh task.sh", "/bin/sh task.sh", "set -- a", "echo first\necho second", "# comment"] {
            let command = Command::Exec(text.into());
            assert!(config.runs_shell(&command), "{text}");
            assert_eq!(config.argv(&command).unwrap(), ["/bin/absd-sh", "-c", text], "{text}");
        }
    }

    #[test]
    fn operator_clock_exec_uses_the_session_shell_without_a_tty() {
        let mut config = Config::defaults();
        config.exec_mode = ExecMode::Argv;
        config.shell = "/bin/absd-sh".into();
        // Exec carries no PTY requirement. Both decisions feed the real
        // spawn path: argv chooses the shell; runs_shell gives it control.
        for text in ["clock sync", "clock", "clock status", "clock set 1793836800",
                     "  clock   sync  ", "clock 'status'", "clock set \"1793836800\""] {
            let command = Command::Exec(text.into());
            assert_eq!(config.argv(&command).unwrap(), ["/bin/absd-sh", "-c", text], "{text}");
            assert!(config.runs_shell(&command), "{text}");
        }
    }

    #[test]
    fn operator_clock_routing_preserves_direct_programs() {
        let mut config = Config::defaults();
        config.exec_mode = ExecMode::Argv;
        config.shell = "/bin/absd-sh".into();
        for (text, expected) in [
            ("date --status", vec!["/bin/date", "--status"]),
            ("/bin/https-document --sample", vec!["/bin/https-document", "--sample"]),
            ("clockwork sync", vec!["/bin/clockwork", "sync"]),
            ("/bin/clock sync", vec!["/bin/clock", "sync"]),
        ] {
            let command = Command::Exec(text.into());
            assert_eq!(config.argv(&command).unwrap(), expected, "{text}");
            assert!(!config.runs_shell(&command), "{text}");
        }
    }

    #[test]
    fn only_bin_programs_run_directly() {
        let mut config = Config::defaults();
        config.exec_mode = ExecMode::Argv;
        config.shell = "/bin/absd-sh".into();
        config.bin_dir = "/bin".into();
        let exec = |text: &str| Command::Exec(text.into());
        for (text, argv) in [("wc -l f", vec!["/bin/wc", "-l", "f"]), ("/bin/wc f", vec!["/bin/wc", "f"])] {
            assert_eq!(config.argv(&exec(text)).unwrap(), argv, "{text}");
            assert!(!config.runs_shell(&exec(text)), "{text}");
        }
        for text in ["/home/operator/prog in.txt", "/home/operator/prog", "./prog", "home/operator/prog",
                     "/bin//wc f", "/bin/./wc", "/bin/../home/operator/prog", "/bin/", "/bin", "/binx/wc",
                     "/ssh/host_ed25519_seed", "/tmp/session-1/prog a b"] {
            assert_eq!(config.argv(&exec(text)).unwrap(), ["/bin/absd-sh", "-c", text], "{text}");
            assert!(config.runs_shell(&exec(text)), "{text}");
        }
        assert!(config.argv(&exec("   ")).is_err());
        // A trailing slash in --bin-dir changes nothing: argv() and
        // runs_shell() agree, and /bin/NAME (https-document's admitted
        // form) stays direct.
        config.bin_dir = "/bin/".into();
        for (text, direct) in [("wc f", true), ("/bin/wc f", true), ("/bin/https-document --sample", true),
                               ("/bin//wc f", false), ("/home/operator/prog", false)] {
            let argv = config.argv(&exec(text)).unwrap();
            assert_eq!(argv[0] == "/bin/absd-sh", !direct, "{text}");
            assert_eq!(config.runs_shell(&exec(text)), !direct, "{text}");
        }
    }
}

fn main() {
    #[cfg(target_os = "absd")]
    absd_runtime::link_anchor();
    let config = match Config::parse(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("sshd: {message}");
            std::process::exit(2);
        }
    };
    #[cfg(unix)]
    linux::run(config);
    #[cfg(target_os = "absd")]
    absd::run(config);
}
