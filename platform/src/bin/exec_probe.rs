#![feature(restricted_std)]
//! Filesystem execution through `std::process` (kernel
//! `docs/PROCESS-STARTUP.md`). Started by init as the durable worker (no
//! arguments: it holds the read-write block handle and the spawn right), it
//! mounts the filesystem the importer filled and runs the programs under
//! `/bin` with `Command`: argv, environment, working directory, streams,
//! exit status, kill, the read-only view children get, and every refusal,
//! from `std` down to the raw `spawn_image` call. Installed itself as
//! `/bin/exec-probe`, it is also the child that reports what it was given
//! (`child-report`), starts further programs (`child-spawn`), and probes
//! what it may not do (`child-denied`, `child-write`).
//!
//! Every line is deterministic (no PIDs), so the host compares the whole
//! captured stream; any failed check ends the worker with status 1.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use absd_runtime::process::{deny_spawn_to_children, spawn_image_raw};
use absd_runtime::storage;

type Checked = Result<(), String>;

fn check(condition: bool, what: &str) -> Checked {
    if condition { Ok(()) } else { Err(what.to_owned()) }
}

fn stdout_of(command: &mut Command) -> Result<(String, Option<i32>), String> {
    let output = command.output().map_err(|error| format!("{command:?}: {error}"))?;
    let text = String::from_utf8(output.stdout).map_err(|_| "stdout not UTF-8".to_owned())?;
    Ok((text, output.status.code()))
}

fn kind(result: std::io::Result<std::process::Output>) -> String {
    match result {
        Ok(output) => format!("started({:?})", output.status.code()),
        Err(error) => format!("{:?}", error.kind()),
    }
}

/// A `spawn_image` request for `image` with no handles; the raw result.
fn raw(image: &[u8], length: u64) -> i64 {
    let request = [image.as_ptr() as u64, length, 0, 0];
    spawn_image_raw(request.as_ptr() as u64, 0, 0)
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn fs_exec() -> Checked {
    let (text, status) = stdout_of(Command::new("/bin/echo").arg("hello from /bin/echo"))?;
    println!("FS EXEC echo stdout={} status={}", text.trim_end(), status.unwrap_or(-1));
    check(text == "hello from /bin/echo\n" && status == Some(0), "echo")?;

    // Inherited stdout: the child writes straight into this process's own
    // output handle, so its line lands here, between ours.
    let status = Command::new("/bin/echo")
        .arg("FS EXEC inherited stdout line")
        .status()
        .map_err(|error| format!("inherit: {error}"))?;
    check(status.success(), "inherit")?;

    let missing = kind(Command::new("/bin/nope").output());
    let directory = kind(Command::new("/bin").output());
    let bare = kind(Command::new("echo").output());
    let text = kind(Command::new("/etc/motd").output());
    let truncated = kind(Command::new("/bin/truncated").output());
    println!(
        "FS EXEC refusals missing={missing} directory={directory} bare={bare} text={text} truncated={truncated}"
    );
    check(
        missing == "NotFound"
            && directory == "IsADirectory"
            && bare == "InvalidInput"
            && text == "InvalidData"
            && truncated == "InvalidData",
        "command refusals",
    )?;

    // The kernel's own refusals of an image this process holds, each a
    // one-field mutation of the real /bin/echo.
    let image = std::fs::read("/bin/echo").map_err(|error| format!("read echo: {error}"))?;
    let length = image.len() as u64;
    let mut malformed = image.clone();
    malformed[0] = 0;
    let mut entry = image.clone();
    put64(&mut entry, 24, 0x10);
    let phoff = u64_at(&image, 32) as usize;
    let phnum = u16_at(&image, 56) as usize;
    let mut window = image.clone();
    let mut interp = image.clone();
    for index in 0..phnum {
        let header = phoff + index * 56;
        if u16_at(&image, header) == 1 {
            put64(&mut window, header + 16, u64_at(&image, header + 16) + (1 << 32));
        }
    }
    put64(&mut window, 24, u64_at(&image, 24) + (1 << 32));
    interp[phoff..phoff + 4].copy_from_slice(&3u32.to_le_bytes());
    let codes = [
        raw(&malformed, length),
        raw(&image, length / 2),
        raw(&entry, length),
        raw(&window, length),
        raw(&interp, length),
        raw(&image, (32 << 20) + 1),
        spawn_image_raw([0x1000u64, 4096, 0, 0].as_ptr() as u64, 0, 0),
    ];
    println!(
        "FS EXEC raw malformed={} truncated={} entry={} window={} interp={} oversize={} pointer={}",
        codes[0], codes[1], codes[2], codes[3], codes[4], codes[5], codes[6]
    );
    check(codes == [-8, -8, -8, -8, -8, -22, -14], "raw refusals")?;
    // The same image, unmutated, still starts: nothing above leaked.
    let (text, _) = stdout_of(Command::new("/bin/echo").arg("after refusals"))?;
    check(text == "after refusals\n", "after refusals")?;
    println!("FS EXEC after-refusals=ok");
    Ok(())
}

fn argv_env() -> Checked {
    let (text, status) = stdout_of(
        Command::new("/bin/exec-probe")
            .args(["child-report", "two words", "ünïcode", ""])
            .env("GREETING", "hello")
            .env("EMPTY", ""),
    )?;
    print!("ARGV ENV {text}");
    check(
        text == "REPORT name=/bin/exec-probe args=two words|ünïcode| cwd=/ env=EMPTY=,GREETING=hello\n"
            && status == Some(0),
        "report",
    )?;
    let (text, _) = stdout_of(Command::new("/bin/printenv").env("A", "1").env("B", "x=y"))?;
    println!("ARGV ENV printenv={}", text.trim_end().replace('\n', ","));
    check(text == "A=1\nB=x=y\n", "printenv")?;
    let bad = kind(Command::new("/bin/printenv").env("", "v").output());
    println!("ARGV ENV empty-key={bad}");
    check(bad == "InvalidInput", "empty key")?;
    let (text, _) = stdout_of(Command::new("/bin/echo").args(["-n", "no", "newline"]))?;
    println!("ARGV ENV echo-n={text:?}");
    check(text == "no newline", "echo -n")?;
    Ok(())
}

fn cwd() -> Checked {
    let here = std::env::current_dir().map_err(|error| format!("current_dir: {error}"))?;
    let (default, _) = stdout_of(&mut Command::new("/bin/pwd"))?;
    let (given, _) = stdout_of(Command::new("/bin/pwd").current_dir("/etc"))?;
    let (relative, _) = stdout_of(Command::new("/bin/pwd").current_dir("bin"))?;
    println!(
        "CWD parent={} default={} given={} relative={}",
        here.display(),
        default.trim_end(),
        given.trim_end(),
        relative.trim_end()
    );
    check(here.to_str() == Some("/") && default == "/\n" && given == "/etc\n" && relative == "/bin\n", "cwd")?;
    let missing = kind(Command::new("/bin/pwd").current_dir("/nope").output());
    let file = kind(Command::new("/bin/pwd").current_dir("/etc/motd").output());
    println!("CWD refusals missing={missing} file={file}");
    check(missing == "NotFound" && file == "NotADirectory", "cwd refusals")?;

    std::env::set_current_dir("/bin").map_err(|error| format!("chdir: {error}"))?;
    let now = std::env::current_dir().map_err(|error| format!("current_dir: {error}"))?;
    let (inherited, _) = stdout_of(&mut Command::new("./pwd"))?;
    let (motd, status) = stdout_of(Command::new("../bin/cat").arg("../etc/motd"))?;
    let own = std::fs::read_to_string("../etc/motd").map_err(|error| format!("relative read: {error}"))?;
    let (listing, _) = stdout_of(Command::new("/bin/ls").arg("../etc"))?;
    println!(
        "CWD after-chdir={} child={} relative-program-cat={} status={} own-read-equal={} ls-etc={}",
        now.display(),
        inherited.trim_end(),
        motd.trim_end(),
        status.unwrap_or(-1),
        own == motd,
        listing.trim_end().replace('\n', ",")
    );
    check(
        now.to_str() == Some("/bin") && inherited == "/bin\n" && motd == own && status == Some(0),
        "chdir",
    )?;
    let to_file = std::env::set_current_dir("/etc/motd").map_err(|error| error.kind());
    let to_missing = std::env::set_current_dir("/nope").map_err(|error| error.kind());
    println!("CWD chdir-refusals file={:?} missing={:?}", to_file.unwrap_err(), to_missing.unwrap_err());
    std::env::set_current_dir("..").map_err(|error| format!("chdir ..: {error}"))?;
    let back = std::env::current_dir().map_err(|error| format!("current_dir: {error}"))?;
    println!("CWD back={}", back.display());
    check(back.to_str() == Some("/"), "chdir ..")?;
    Ok(())
}

fn fs_spawn() -> Checked {
    let (text, status) = stdout_of(
        Command::new("/bin/exec-probe").arg("child-spawn").env("LEVEL", "1").current_dir("/etc"),
    )?;
    print!("{text}");
    println!("FS SPAWN child status={}", status.map_or(-1, i64::from));
    check(status == Some(7) && text.ends_with("SPAWN nested done\n"), "fs spawn")?;
    Ok(())
}

fn others() -> Checked {
    // `kill` ends a child blocked reading its stdin.
    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cat: {error}"))?;
    let early = child.try_wait().map_err(|error| format!("try_wait: {error}"))?;
    child.kill().map_err(|error| format!("kill: {error}"))?;
    let status = child.wait().map_err(|error| format!("wait: {error}"))?;
    println!("EXEC OTHER kill try_wait={early:?} status={status} code={:?}", status.code());
    check(early.is_none() && status.code().is_none() && !status.success(), "kill")?;

    // Piped stdin through /bin/cat.
    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cat: {error}"))?;
    child.stdin.take().unwrap().write_all(b"through a pipe\n").map_err(|error| error.to_string())?;
    let mut echoed = String::new();
    child.stdout.take().unwrap().read_to_string(&mut echoed).map_err(|error| error.to_string())?;
    let status = child.wait().map_err(|error| error.to_string())?;
    println!("EXEC OTHER cat-stdin={} status={status}", echoed.trim_end());
    check(echoed == "through a pipe\n" && status.success(), "cat stdin")?;

    let child = Command::new("/bin/uname").arg("-a").stdout(Stdio::piped()).spawn();
    let child = child.map_err(|error| format!("uname: {error}"))?;
    let pid = child.id();
    let output = child.wait_with_output().map_err(|error| error.to_string())?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let (name, reported) = text.trim_end().rsplit_once(" pid=").unwrap_or(("", ""));
    println!("EXEC OTHER uname={name} pid-match={}", reported == pid.to_string());
    check(reported == pid.to_string(), "uname pid")?;
    let (listing, _) = stdout_of(Command::new("/bin/ls").arg("/"))?;
    println!("EXEC OTHER ls-root={}", listing.trim_end().replace('\n', ","));

    // The child's filesystem view is read-only, in the library and in the
    // kernel.
    let (text, _) = stdout_of(Command::new("/bin/exec-probe").arg("child-write"))?;
    print!("EXEC OTHER {text}");
    check(text == "WRITE file=ReadOnlyFilesystem mkdir=ReadOnlyFilesystem raw-block=-1\n", "read-only view")?;

    // A child started without the spawn right cannot start anything.
    deny_spawn_to_children(true);
    let result = stdout_of(Command::new("/bin/exec-probe").arg("child-denied"));
    deny_spawn_to_children(false);
    let (text, _) = result?;
    print!("EXEC OTHER {text}");
    check(text == "DENIED kind=PermissionDenied\n", "denied")?;
    Ok(())
}

fn worker() -> i32 {
    // This process is the exclusive writer; every child gets a read-only view.
    match storage::mount(false, true) {
        Ok(mounted) => println!("EXEC PROBE mounted formatted={}", mounted.formatted),
        Err(error) => {
            println!("EXEC PROBE FAILED mount {error:?}");
            return 1;
        }
    }
    // A file this process creates: its name is committed at once, its
    // bytes and length only by a sync (docs/FILESYSTEM.md). A child's view
    // is the last commit when it mounted, checked at the end.
    let mut written = match std::fs::File::create("/etc/written-by-parent") {
        Ok(file) => file,
        Err(error) => {
            println!("EXEC PROBE FAILED create {error}");
            return 1;
        }
    };
    if written.write_all(b"committed before the child started\n").is_err() {
        println!("EXEC PROBE FAILED write");
        return 1;
    }
    for (name, step) in [
        ("FS EXEC", fs_exec as fn() -> Checked),
        ("ARGV ENV", argv_env),
        ("CWD", cwd),
        ("FS SPAWN", fs_spawn),
        ("EXEC OTHER", others),
    ] {
        match step() {
            Ok(()) => println!("{name} checks passed"),
            Err(error) => {
                println!("{name} FAILED {error}");
                return 1;
            }
        }
    }
    let view = || stdout_of(Command::new("/bin/cat").arg("/etc/written-by-parent")).map(|(text, _)| text);
    let before = view();
    let synced = written.sync_all().map_err(|error| error.to_string());
    let after = view();
    match (before, synced, after) {
        (Ok(before), Ok(()), Ok(after)) => {
            println!("EXEC PROBE child view before-sync={before:?} after-sync={after:?}");
            if !before.is_empty() || after != "committed before the child started\n" {
                println!("EXEC PROBE FAILED view");
                return 1;
            }
        }
        other => {
            println!("EXEC PROBE FAILED view {other:?}");
            return 1;
        }
    }
    println!("EXEC PROBE done");
    0
}

/// `child-report`: what this process was started with.
fn report() -> i32 {
    let mut args = std::env::args();
    let name = args.next().unwrap_or_default();
    let args: Vec<String> = args.skip(1).collect();
    let mut env: Vec<String> = std::env::vars().map(|(key, value)| format!("{key}={value}")).collect();
    env.sort();
    let cwd = std::env::current_dir().map(|path| path.display().to_string()).unwrap_or_default();
    println!("REPORT name={name} args={} cwd={cwd} env={}", args.join("|"), env.join(","));
    0
}

/// `child-spawn`: a filesystem program starting filesystem programs.
fn nested() -> i32 {
    let run = || -> Result<(), String> {
        let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
        println!("SPAWN nested cwd={} LEVEL={}", cwd.display(), std::env::var("LEVEL").unwrap_or_default());
        let (text, _) = stdout_of(Command::new("/bin/echo").args(["nested", "a b"]))?;
        println!("SPAWN nested echo={}", text.trim_end());
        let (text, _) = stdout_of(&mut Command::new("/bin/pwd"))?;
        println!("SPAWN nested pwd={}", text.trim_end());
        let (text, _) = stdout_of(Command::new("/bin/printenv").env("EXTRA", "2"))?;
        println!("SPAWN nested inherited-env={}", text.trim_end().replace('\n', ","));
        let (text, _) = stdout_of(Command::new("/bin/printenv").env_clear().env("ONLY", "1"))?;
        println!("SPAWN nested cleared-env={}", text.trim_end());
        let (text, _) = stdout_of(Command::new("/bin/cat").arg("motd"))?;
        println!("SPAWN nested cat-relative={}", text.trim_end());
        let output = Command::new("/bin/cat").arg("/missing").output().map_err(|error| error.to_string())?;
        println!(
            "SPAWN nested cat-missing status={} stderr={}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim_end()
        );
        println!("SPAWN nested done");
        Ok(())
    };
    match run() {
        Ok(()) => 7,
        Err(error) => {
            println!("SPAWN nested FAILED {error}");
            1
        }
    }
}

/// `child-denied`: started without the spawn right.
fn denied() -> i32 {
    match Command::new("/bin/echo").arg("must not run").output() {
        Ok(_) => println!("DENIED started"),
        Err(error) => println!("DENIED kind={:?}", error.kind()),
    }
    0
}

/// `child-write`: tries to change the filesystem through its view.
fn write() -> i32 {
    let file = std::fs::write("/etc/child-was-here", b"x").map_err(|error| error.kind());
    let mkdir = std::fs::create_dir("/child").map_err(|error| error.kind());
    let sector = [0u8; 512];
    let raw = match absd_runtime::layout::write_raw(absd_runtime::block_handle(), 0, &sector) {
        Ok(()) => 0,
        Err(code) => code,
    };
    println!(
        "WRITE file={} mkdir={} raw-block={raw}",
        file.err().map_or("written".to_owned(), |kind| format!("{kind:?}")),
        mkdir.err().map_or("created".to_owned(), |kind| format!("{kind:?}")),
    );
    0
}

fn main() {
    absd_runtime::link_anchor();
    let status = match std::env::args().nth(1).as_deref() {
        None => worker(),
        Some("child-report") => report(),
        Some("child-spawn") => nested(),
        Some("child-denied") => denied(),
        Some("child-write") => write(),
        Some(other) => {
            println!("EXEC PROBE unknown mode {other}");
            2
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(status);
}
