#![feature(restricted_std)]
//! `health`: how this generation came to be running, in one screen: the
//! release the file server serves, this boot and its age, how the previous
//! generation ended and how many generations in a row have failed, the
//! configuration files sshd started from, and the size of each log.
//!
//! The recovery facts come from the file server's own log, the line it
//! writes before serving (`FSD RECOVERY seq=… streak=… previous=…` after
//! `started: boot <id>`), and only for this boot's identity: never a line
//! from another boot, never a guess (absd_fsd::log::generation). A session
//! cannot read the recovery ledger, and the ledger is overwritten before
//! anything is served, so the log line is the record. Why a failed
//! generation failed (a crash, a stall, a budget stop) is on the console
//! only; this command does not claim to know it.
//!
//! `/etc` is read-only to every session and only replaced on a halted
//! machine, and sshd refuses to start on a malformed file, so the files a
//! session sees are the ones the running sshd parsed. A line whose source
//! refuses says so in place, and the exit status is then 1
//! (docs/admin-on-box-20261015/DESIGN.md, section 3.1).

use absd_fsd::log::{self, generation};
use absd_runtime::fsd;

#[path = "../health_observation.rs"]
mod observation;

fn json_health() -> i32 {
    let start = absd_runtime::ticks();
    let boot = absd_runtime::boot_id();
    let ticks = absd_runtime::ticks();
    let release = if fsd::active() {
        fsd::check_server(0, false)
            .map(|server| server.release)
            .map_err(observation::version_issue)
    } else {
        Err(observation::Issue::unavailable("fsd_absent"))
    };
    let recovery = match (&boot, &release) {
        (Err(_), _) => Err(observation::Issue::unavailable("boot_id_unavailable")),
        (_, Err(issue)) => Err(*issue),
        (Ok(id), Ok(_)) => {
            let boot = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let dir = std::str::from_utf8(log::DIR).expect("FSD log directory must be UTF-8");
            let path = format!("{dir}/fsd");
            observation::recovery(
                &boot,
                read(&path).map_err(|e| e.kind()),
                read(&(path + ".0")).map_err(|e| e.kind()),
            )
        }
    };
    let pid = Some(std::process::id());
    let sample = observation::Sample {
        start,
        end: absd_runtime::ticks(),
        ticks,
        pid,
        boot,
        release,
        recovery,
    };
    match observation::render(sample) {
        Ok((text, status)) => {
            use std::io::Write;
            match std::io::stdout().write_all(format!("{text}\n").as_bytes()) {
                Ok(()) => status,
                Err(_) => 2,
            }
        }
        Err(reason) => {
            eprintln!("health: {reason}");
            2
        }
    }
}

fn read(path: &str) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(path)
}

fn main() {
    absd_runtime::link_anchor();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--json"] {
        std::process::exit(json_health());
    }
    if !args.is_empty() {
        eprintln!("health: usage: health [--json]");
        std::process::exit(2);
    }
    let mut status = 0;

    let release = if !fsd::active() {
        status = 1;
        "unknown (no file server serves this process)".to_owned()
    } else {
        match fsd::check_server(0, false) {
            Ok(server) => String::from_utf8_lossy(&server.release).into_owned(),
            Err(refusal) => {
                status = 1;
                refusal.line()
            }
        }
    };
    println!("release: {release}");

    let seconds = absd_runtime::boot_millis() / 1000;
    let boot =
        absd_runtime::boot_id().map(|id| id.iter().map(|b| format!("{b:02x}")).collect::<String>());
    match &boot {
        Ok(boot) => println!(
            "boot: {boot}, up {} days {:02}:{:02}:{:02} ({} ticks)",
            seconds / 86_400,
            seconds % 86_400 / 3600,
            seconds % 3600 / 60,
            seconds % 60,
            absd_runtime::ticks()
        ),
        Err(code) => {
            status = 1;
            println!("boot: unknown (the kernel refused: {code})");
        }
    }

    let recovery = match &boot {
        Err(_) => "unknown (no boot identity to match the log against)".to_owned(),
        Ok(boot) => {
            let path = std::str::from_utf8(log::DIR)
                .unwrap_or("/var/log")
                .to_owned()
                + "/fsd";
            let current = read(&path);
            let rotated = read(&(path.clone() + ".0")).unwrap_or_default();
            match current {
                Err(e) => format!("unknown ({path}: {e})"),
                Ok(current) => match generation(&rotated, &current, boot) {
                    Ok(g) => format!("previous={} streak={} seq={}", g.previous, g.streak, g.seq),
                    Err(why) => format!("unknown ({})", why.reason()),
                },
            }
        }
    };
    if recovery.starts_with("unknown") {
        status = 1;
    }
    println!("recovery: {recovery}");

    for (name, path) in [("network", "/etc/network.conf"), ("sshd", "/etc/sshd.conf")] {
        match std::fs::metadata(path) {
            Ok(_) => println!("config: {name} from {path}"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!("config: {name} built-in defaults (no {path})")
            }
            Err(e) => {
                status = 1;
                println!("config: {name} unknown ({path}: {e})");
            }
        }
    }

    let mut logs = Vec::new();
    for name in ["fsd", "fsd.0", "sshd", "sshd.0"] {
        let path = format!("/var/log/{name}");
        match std::fs::metadata(&path) {
            Ok(meta) => logs.push(format!("{name} {} bytes", meta.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => logs.push(format!("{name} none")),
            Err(e) => {
                status = 1;
                logs.push(format!("{name} unknown ({e})"));
            }
        }
    }
    println!("logs: {}", logs.join(", "));
    std::process::exit(status);
}
