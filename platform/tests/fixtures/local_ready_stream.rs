#![allow(dead_code, static_mut_refs, unused_imports, unused_variables)]
use std::fmt::Write;
#[path = "abi.rs"] pub mod syscall;
#[path = "program.rs"] mod program;
#[path = "object.rs"] mod object;
#[path = "gate.rs"] mod frame_admission;
include!("emitter.rs");
static mut SERVED_READY: bool = false;
static mut SERVED_READY_PROBE: program::ServedReadyProbe = program::ServedReadyProbe::new();
static mut GATE: frame_admission::BootstrapAdmission = frame_admission::BootstrapAdmission::new();
static mut GRANTED: bool = true;
include!("observer.rs");
fn deliver(bytes: &[u8], pipe: object::PipeId) {
    if unsafe { GATE.delivered(1, pipe, bytes) } {
        unsafe { GRANTED = false; }
    }
    observe_served_ready(bytes);
}
fn attempt() -> (i64, usize) {
    let request = syscall::SpawnReservedRequest {
        program_and_flags: program::LOGD | syscall::SPAWN_NO_SPAWN,
        copies_address: 0,
        copies_count: 0,
        total_frames: 9291,
    };
    let mut copies = 0;
    let allowed = unsafe { GATE.allowed(1, GRANTED) };
    let result = frame_admission::read_request(allowed, 0, 0, |out| {
        copies += 1;
        *out = request.to_bytes();
        true
    });
    (match result { Ok(_) => 0, Err(error) => error }, copies)
}
fn main() {
    let argument = std::env::args().nth(1).unwrap_or("ssh".into());
    match argument.as_str() {
        "--emit-ssh" => { emit_ssh_ready(); return; }
        "--emit-local" => { emit_local_ready(true); return; }
        "--emit-local-unenrolled" => { emit_local_ready(false); return; }
        _ => {}
    }
    let scenario = argument;
    let bound = object::fixture(10, 1);
    let stderr = object::fixture(11, 1);
    unsafe { GATE.designate(1); GATE.bind(1, bound); }
    if scenario != "never-ready" {
        let emitter = match scenario.as_str() {
            "ssh" => "--emit-ssh",
            "local-unenrolled" | "local-unenrolled-stdout" => "--emit-local-unenrolled",
            _ => "--emit-local",
        };
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg(emitter).output().unwrap();
        assert!(output.status.success());
        let on_stdout = !output.stdout.is_empty();
        assert!(on_stdout ^ !output.stderr.is_empty());
        let mut bytes = if on_stdout { output.stdout } else { output.stderr };
        let mut target = if on_stdout { bound } else { stderr };
        if scenario == "foreign" { target = object::fixture(10, 2); }
        if scenario == "local-stdout-control" || scenario == "local-unenrolled-stdout" {
            assert_eq!(emitter, if scenario == "local-stdout-control" { "--emit-local" } else { "--emit-local-unenrolled" });
            target = bound;
        }
        if scenario == "missing-newline" { assert_eq!(bytes.pop(), Some(b'\n')); }
        if scenario == "fragmented" {
            deliver(&bytes[..11], target);
            let (raw, copies) = attempt();
            assert_eq!((raw, copies), (0, 1));
            deliver(&bytes[11..], target);
        } else {
            deliver(&bytes, target);
        }
    }
    let ready = unsafe { SERVED_READY };
    let allowed = unsafe { GATE.allowed(1, GRANTED) };
    let (raw, copies) = attempt();
    match scenario.as_str() {
        "ssh" | "local" | "local-stdout-control" | "fragmented" => {
            assert!(ready); assert!(!allowed); assert_eq!((raw, copies), (-1, 0));
        }
        "foreign" => {
            assert!(ready); assert!(allowed); assert_eq!((raw, copies), (0, 1));
        }
        "local-unenrolled" | "local-unenrolled-stdout" | "missing-newline" | "never-ready" => {
            assert!(!ready); assert!(allowed); assert_eq!((raw, copies), (0, 1));
        }
        _ => panic!("unknown scenario"),
    }
    println!("scenario={scenario} init_ready={ready} bootstrap_allowed={allowed} reserved_raw={raw} request_copies={copies}");
}
