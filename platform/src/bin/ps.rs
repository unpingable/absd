#![feature(restricted_std)]
//! Boot-scoped kernel process snapshots, independent of FSD and SSH.
use absd_runtime::observation::{self as obs, word};

fn main() {
    absd_runtime::link_anchor();
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if !(arguments.is_empty() || arguments == ["-A"]) {
        eprintln!("usage: ps [-A]"); std::process::exit(2);
    }
    let capacity=match obs::capacity() {
        Ok(capacity)=>capacity,
        Err(code)=>{eprintln!("ps: process capacity unavailable code={code}; no partial census reported");std::process::exit(1);}
    };
    println!("  PID  PPID STATE     WAIT       HANDLES CPU IMAGE");
    let mut failed = false;
    for slot in 0..capacity.processes {
        match obs::read(slot as u64) {
            Ok(record) if word(&record,1)!=1 || word(&record,3)!=slot as u64 => {
                eprintln!("ps: malformed process snapshot slot={slot}"); failed=true; break;
            }
            Ok(record) if word(&record, 7) != 0 => {
                let cpu = match word(&record, 12) { u64::MAX => "-".to_string(), cpu => cpu.to_string() };
                let image = match word(&record, 6) { 0 => "init".to_string(), 30 => "boot-worker".to_string(), 32 => "boot-reader".to_string(), 38 => "file-server".to_string(), 44 => "logd".to_string(), 0xffff_ffff => "filesystem-image".to_string(), id => format!("embedded:{id}") };
                println!("{:5} {:5} {:9} {:10} {:7} {:3} {}", word(&record, 4), word(&record, 5), obs::state(word(&record, 7)), obs::wait(word(&record, 8)), word(&record, 9), cpu, image);
                if word(&record, 7) == 5 { println!("      exit={}", word(&record, 10) as i64); }
                if word(&record, 7) == 6 { println!("      fault-vector={}", word(&record, 11)); }
            }
            Ok(_) => {}
            Err(code) => { eprintln!("ps: unavailable slot={slot} code={code}"); failed = true; break; }
        }
    }
    println!("Snapshots are per row; PID identity is scoped to this boot. CPU%, command arguments and per-process memory: unknown.");
    std::process::exit(i32::from(failed));
}
