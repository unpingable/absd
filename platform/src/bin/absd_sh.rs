#![feature(restricted_std)]
#![feature(absd_fs_ext)]
//! absd-sh: the native script and interactive shell (logic in `sh/src/lib.rs`, host-tested;
//! the platform, pipelines and redirections, in `src/sh_host.rs`).
//! `sh FILE [ARG...]`, `sh -s` and `sh -c COMMAND` execute script input.
//! Without arguments it reads interactive commands with continuation prompts.
//! Children are filesystem executables started by `std::process::Command`
//! with the shell's working directory; a stream that is not piped or
//! redirected is the shell's own. Children get no spawn right: a command
//! cannot start programs.

#[path = "../../sh/src/lib.rs"]
mod shell;
#[path = "../sh_host.rs"]
mod sh_host;
// The session control protocol (sshd's side is ssh/src/absd.rs).
#[path = "../../ssh/src/control.rs"]
#[allow(dead_code)]
mod session_control;

#[path = "../sh_input.rs"]
mod sh_input;

use shell::Shell;
use std::io;

/// A qualification-only build (scripts/run-contain-matrix.sh, its negative
/// control) sets this at compile time to leave the spawn right with the
/// commands it starts. The installed shell never does.
const KEEP_SPAWN_RIGHT: bool = option_env!("ABSD_SH_QUALIFICATION_KEEP_SPAWN_RIGHT").is_some();

fn main() {
    absd_runtime::link_anchor();
    // Commands the shell starts get no spawn right, so they cannot start
    // programs of their own (the kernel refuses, and nothing restores the
    // right): the shell's children are every process of its session, and
    // it holds a kill right on each of them.
    absd_runtime::process::deny_spawn_to_children(!KEEP_SPAWN_RIGHT);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = match shell::parse_args(&args) {
        Ok(mode) => mode,
        Err(usage) => {
            eprintln!("absd-sh: {usage}");
            std::process::exit(shell::STATUS_USAGE);
        }
    };
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .filter(|p| p.starts_with('/'))
        .unwrap_or_else(|| "/".to_string());
    let mut shell = Shell::new(sh_host::Absd::new(), cwd);
    shell.set_environment(std::env::vars());
    let status = if mode == shell::Mode::Interactive {
        shell::session(
            &mut shell,
            mode,
            &mut sh_input::interactive(),
            &mut io::stdout(),
            &mut io::stderr(),
        )
    } else {
        shell::session(
            &mut shell,
            mode,
            &mut io::stdin().lock(),
            &mut io::stdout(),
            &mut io::stderr(),
        )
    };
    std::process::exit(status);
}
