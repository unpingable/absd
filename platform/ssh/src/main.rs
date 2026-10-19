#![cfg_attr(target_os = "absd", feature(restricted_std))]
#![cfg_attr(target_os = "absd", feature(absd_fs_ext))]
//! A small SSH server on sunset's sans-IO core: one process, one thread, a
//! poll loop over the network and each session child's pipes.
//!
//! Security boundary: one operator identity (the keys of one
//! `authorized_keys` file, public key authentication only) gets bounded
//! sessions. There are no accounts, passwords, forwarding, or subsystems,
//! and no claim of separation between several users. A PTY is a line
//! discipline in sshd (`tty`), not a kernel object.

/// A diagnostic line: stderr, and on ABSD `/var/log/sshd` (`oplog`).
macro_rules! say {
    ($($arg:tt)*) => { $crate::oplog::line(format!($($arg)*)) };
}

mod conn;
#[cfg_attr(not(target_os = "absd"), allow(dead_code))]
mod etc;
mod oplog;
// The session control protocol; only the ABSD backend has the channel.
#[cfg_attr(not(target_os = "absd"), allow(dead_code))]
mod control;
mod keys;
mod tty;

#[cfg(target_os = "absd")]
mod absd;
#[cfg(target_os = "absd")]
mod net_diagnostics;
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
    /// (`|`, `<`, `>`, `;`, `&`, or `"`), such as `cat > FILE`, the upload
    /// half of file transfer.
    pub fn runs_shell(&self, command: &conn::Command) -> bool {
        match command {
            conn::Command::Shell => true,
            conn::Command::Exec(text) => self.exec_mode == ExecMode::Shell || shell_syntax(text),
        }
    }

    /// The program and arguments a session command runs.
    pub fn argv(&self, command: &conn::Command) -> Result<Vec<String>, String> {
        let shell = self.shell.to_string_lossy().into_owned();
        match (command, self.exec_mode) {
            (conn::Command::Shell, _) => Ok(vec![shell]),
            (conn::Command::Exec(text), ExecMode::Shell) => Ok(vec![shell, "-c".into(), text.clone()]),
            (conn::Command::Exec(text), ExecMode::Argv) if shell_syntax(text) => {
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
    text.contains(['|', '<', '>', '"', ';', '&'])
}

#[cfg(test)]
mod tests {
    use super::{Config, ExecMode, conn::Command};

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
