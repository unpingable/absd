#!/usr/bin/env python3
"""Exercise the actual serial transmitter with controlled port readiness."""
from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def main():
    source = (ROOT / "src/serial.rs").read_text()
    control = os.environ.get("ABSD_SERIAL_ROUTE_CONTROL", "")
    if control == "legacy":
        gate="if !MANAGED_PRESENTATION.load(Ordering::Acquire) {"
        assert source.count(gate)==1
        source=source.replace(gate,"if true {")
    main_source=(ROOT/"src/main.rs").read_text()
    panic_source=main_source[main_source.index("#[panic_handler]"):main_source.index("// The host Rust target's")]
    panic_source=panic_source.replace("#[panic_handler]","").replace("info: &PanicInfo","info: &str")
    start=main_source.index('pub extern "C" fn kernel_exception_report(')
    fault_source=main_source[start:main_source.index("use serial::{decimal as serial_decimal",start)]
    privileged='''    let cr2: u64;
    unsafe {
        asm!("mov {}, cr2", out(reg) cr2, options(nostack, preserves_flags));
    }'''
    assert fault_source.count(privileged)==1
    fault_source=fault_source.replace(privileged,"    let cr2=0xdeadu64;")
    if control == "muted-panic": panic_source=panic_source.replace("serial::emergency_presentation();","")
    if control == "muted-fault": fault_source=fault_source.replace("serial::emergency_presentation();","")
    old_out = '''    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }'''
    old_in = '''    let value: u8;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags));
    }
    value'''
    assert source.count(old_out) == source.count(old_in) == 1
    source = source.replace(old_out, "    crate::ports::write(port, value)")
    source = source.replace(old_in, "    crate::ports::read(port)")
    with tempfile.TemporaryDirectory(prefix="absd-serial-tx-") as temporary:
        work = Path(temporary)
        (work / "serial.rs").write_text(source)
        fixture = r'''
#![allow(dead_code, unused_imports)]
extern crate self as absd_kernel;
pub use absd_abi::{program, syscall};
#[path = "CONSOLE_INPUT"] pub mod console_input;
#[path = "HANDLE"] pub mod handle;
#[path = "OBJECT"] pub mod object;
#[path = "KERNEL_LOG"] pub mod kernel_log;
#[path = "DEFER_LOG"] pub mod defer_log;
#[path = "PRESENTATION"] pub mod console_presentation;
mod process { pub const KERNEL_PARENT: u64 = 0; }
// Hardware containment is outside this host presentation fixture.
mod contain { pub fn fatal() {} }
mod sched { pub fn now() -> u64 { 42 } }
mod serial;
mod smp_user { pub fn enabled() -> bool { false } }
mod kernel_lock {
    pub const BSP: usize = 0;
    pub fn assert_current_owner() {}
    pub fn assert_bsp_device_access() {}
    pub fn assert_held(_: usize) {}
}
fn debug_assert_interrupts_disabled() {}
mod framebuffer {
    pub static BYTES: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
    pub fn put(byte: u8) { BYTES.lock().unwrap().push(byte); }
    pub fn fault_colors() {}
}
mod ports {
    use std::sync::{Mutex, atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering}};
    pub static READY: AtomicBool = AtomicBool::new(false);
    pub static READY_STATUS: AtomicU8 = AtomicU8::new(0x60);
    pub static READS: AtomicU64 = AtomicU64::new(0);
    pub static BYTES: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    pub fn read(port: u16) -> u8 {
        assert_eq!(port, 0x3fd);
        READS.fetch_add(1, Ordering::Relaxed);
        if READY.load(Ordering::Relaxed) { READY_STATUS.load(Ordering::Relaxed) } else { 0 }
    }
    pub fn write(port: u16, byte: u8) {
        assert_eq!(port, 0x3f8);
        BYTES.lock().unwrap().push(byte);
    }
}
use serial::{Serial, write as serial_write, decimal as serial_decimal, hex as serial_hex};
use std::fmt::Write;
mod smp_operator { pub fn fatal_guard() {} }
mod cpu { pub fn begin_fault_report()->bool {true} }
fn exit_qemu(code:u32)->! {
    serial::finish_output();
    let expected=match code {1=>b"ABSD PANIC: fatal detail survives".as_slice(),2=>b"KERNEL FAULT vector=14".as_slice(),_=>panic!("unexpected exit")};
    if !ports::BYTES.lock().unwrap().windows(expected.len()).any(|w|w==expected) {
        eprintln!("fatal UART detail was muted");std::process::exit(1);
    }
    if !framebuffer::BYTES.lock().unwrap().windows(expected.len()).any(|w|w==expected) {
        eprintln!("fatal framebuffer detail was muted");std::process::exit(1);
    }
    std::process::exit(0)
}
FATAL_HANDLERS
fn main() {
    use std::sync::atomic::Ordering;
    match std::env::args().nth(1).as_deref().unwrap() {
        "transient" => {
            serial::write("boot");
            assert_eq!(ports::READS.load(Ordering::Relaxed), 400_000);
            assert!(ports::BYTES.lock().unwrap().is_empty());
            assert_eq!(serial::tx_dropped(), 0, "transient unready bytes must remain pending");
            ports::READY.store(true, Ordering::Relaxed);
            serial::write("!");
            assert_eq!(*ports::BYTES.lock().unwrap(), b"boot!");
            assert_eq!(serial::tx_dropped(), 0);
        }
        "terminal-ready" => {
            serial::write("boot");
            ports::READY.store(true, Ordering::Relaxed);
            serial::finish_output();
            assert_eq!(*ports::BYTES.lock().unwrap(), b"boot");
            assert_eq!(serial::tx_dropped(), 0);
        }
        "terminal-stalled" => {
            serial::write("boot");
            serial::finish_output();
            assert_eq!(serial::tx_dropped(), 4);
            assert_eq!(ports::READS.load(Ordering::Relaxed), 500_000);
            serial::finish_output();
            assert_eq!(serial::tx_dropped(), 4, "terminal accounting is idempotent");
            assert_eq!(ports::READS.load(Ordering::Relaxed), 500_000);
            assert!(ports::BYTES.lock().unwrap().is_empty());
        }
        "overflow" => {
            for n in 0..300 { serial::byte_out((n % 251) as u8); }
            assert_eq!(serial::tx_dropped(), 44);
            assert_eq!(ports::READS.load(Ordering::Relaxed), 30_000_000);
            ports::READY.store(true, Ordering::Relaxed);
            serial::byte_out(b'!');
            let mut expected: Vec<u8> = (0..256).map(|n| (n % 251) as u8).collect();
            expected.push(b'!');
            assert_eq!(*ports::BYTES.lock().unwrap(), expected);
            serial::finish_output();
            assert_eq!(serial::tx_dropped(), 44);
            assert!(ports::READS.load(Ordering::Relaxed) <= 30_100_000);
        }
        "absent-status" => {
            ports::READY_STATUS.store(0xff, Ordering::Relaxed);
            ports::READY.store(true, Ordering::Relaxed);
            serial::write("absent");
            serial::finish_output();
            assert_eq!(*ports::BYTES.lock().unwrap(), b"absent");
            assert_eq!(serial::tx_dropped(), 0);
            assert_eq!(ports::READS.load(Ordering::Relaxed), 6);
        }
        "digest-boundary" => {
            serial::write("boot");
            let (count, _) = serial::evidence();
            assert_eq!(count, 4);
            assert_eq!(serial::tx_dropped(), 4);
        }
        "wrap" => {
            let mut expected = Vec::new();
            for round in 0..32 {
                ports::READY.store(false, Ordering::Relaxed);
                for n in 0..16 {
                    let byte = ((round * 16 + n) % 251) as u8;
                    serial::byte_out(byte);
                    expected.push(byte);
                }
                ports::READY.store(true, Ordering::Relaxed);
                serial::byte_out(b'|');
                expected.push(b'|');
            }
            serial::finish_output();
            assert_eq!(*ports::BYTES.lock().unwrap(), expected);
            assert_eq!(serial::tx_dropped(), 0);
        }
        "managed-output" => {
            use handle::{HandleTable, Object, RIGHT_WRITE};
            ports::READY.store(true, Ordering::Relaxed);
            let mut handles=HandleTable::new(1);
            let console=handles.insert(Object::Console,RIGHT_WRITE).unwrap();
            serial::presentation_request(1,0,0,&handles,console,1,0).unwrap();
            for &b in b"J1 boot-id-prefix" { serial::display_byte_out(b); }
            serial::presenter_ended(18,1,0);
            serial::write("USER EXIT pid=18 status=0\n");
            for &b in b"-suffix logs output\nabsd$ " { serial::display_byte_out(b); }
            serial::finish_output();
            let expected=b"J1 boot-id-prefix-suffix logs output\nabsd$ ";
            assert_eq!(*ports::BYTES.lock().unwrap(),expected);
            assert_eq!(*framebuffer::BYTES.lock().unwrap(),expected);
            assert_eq!(serial::evidence().0,expected.len() as u64);
            let record=kernel_log::LOG.read(0).unwrap().record.unwrap();
            assert_eq!(record.text(),b"USER EXIT pid=18 status=0");
            assert!(kernel_log::LOG.read(record.sequence+1).unwrap().record.is_none());
            serial::presentation_request(1,0,0,&handles,console,0,0).unwrap();
            serial::write("LEGACY\n");
            assert!(ports::BYTES.lock().unwrap().ends_with(b"LEGACY\n"));
        }
        "managed-authority" => {
            use handle::{HandleTable,Object,RIGHT_READ,RIGHT_WRITE};
            use console_presentation::RequestError;
            ports::READY.store(true,Ordering::Relaxed);
            let mut handles=HandleTable::new(1);
            let console=handles.insert(Object::Console,RIGHT_WRITE).unwrap();
            let readonly=handles.insert(Object::Console,RIGHT_READ).unwrap();
            let diag=handles.insert(Object::Diagnostics,RIGHT_READ).unwrap();
            let mut pipes=object::PipeTable::new();
            let pipe=handles.insert(Object::Pipe(pipes.create(RIGHT_WRITE).unwrap()),RIGHT_WRITE).unwrap();
            let stale=handles.insert(Object::Console,RIGHT_WRITE).unwrap();
            handles.close(stale).unwrap();
            serial::presentation_request(1,0,0,&handles,console,1,0).unwrap();
            for (pid,parent,program) in [(2,1,0),(1,1,0),(1,0,7)] {
                assert_eq!(serial::presentation_request(pid,parent,program,&handles,console,0,0),Err(RequestError::Rights));
            }
            assert_eq!(serial::presentation_request(1,0,0,&handles,console,2,0),Err(RequestError::Invalid));
            assert_eq!(serial::presentation_request(1,0,0,&handles,console,0,1),Err(RequestError::Invalid));
            for handle in [0,readonly,diag,pipe,stale] {
                assert!(matches!(serial::presentation_request(1,0,0,&handles,handle,0,0),Err(RequestError::Handle(_))));
            }
            serial::write("USER EXIT remains hidden after refused setters\n");
            serial::display_byte_out(b'!');
            assert_eq!(*ports::BYTES.lock().unwrap(),b"!");
        }
        "managed-emergency" | "presenter-ended" => {
            use handle::{HandleTable,Object,RIGHT_WRITE};
            use std::fmt::Write;
            ports::READY.store(true,Ordering::Relaxed);
            let mut handles=HandleTable::new(1);
            let console=handles.insert(Object::Console,RIGHT_WRITE).unwrap();
            serial::presentation_request(1,0,0,&handles,console,1,0).unwrap();
            serial::write("normal hidden\n");
            if std::env::args().nth(1).as_deref()==Some("presenter-ended") {
                serial::presenter_ended(1,0,0);
            } else {
                serial::fatal_raw(b"RAW EMERGENCY\n");
                assert_eq!(*ports::BYTES.lock().unwrap(),b"RAW EMERGENCY\n");
                serial::emergency_presentation();
            }
            write!(serial::Serial,"KERNEL FAULT vector={} detail={}\n",14,"preserved").unwrap();
            assert!(ports::BYTES.lock().unwrap().ends_with(b"KERNEL FAULT vector=14 detail=preserved\n"));
            assert!(framebuffer::BYTES.lock().unwrap().ends_with(b"KERNEL FAULT vector=14 detail=preserved\n"));
        }
        "panic-detail" | "kernel-fault-detail" => {
            use handle::{HandleTable,Object,RIGHT_WRITE};
            ports::READY.store(true,Ordering::Relaxed);
            let mut handles=HandleTable::new(1);
            let console=handles.insert(Object::Console,RIGHT_WRITE).unwrap();
            serial::presentation_request(1,0,0,&handles,console,1,0).unwrap();
            if std::env::args().nth(1).as_deref()==Some("panic-detail") {panic("fatal detail survives");}
            kernel_exception_report(14,7,0xfeed);
        }
        "managed-pending-prefix" => {
            use handle::{HandleTable,Object,RIGHT_WRITE};
            serial::write("old pending notice");
            let mut handles=HandleTable::new(1);
            let console=handles.insert(Object::Console,RIGHT_WRITE).unwrap();
            serial::presentation_request(1,0,0,&handles,console,1,0).unwrap();
            assert_eq!(serial::tx_dropped(),18);
            ports::READY.store(true,Ordering::Relaxed);
            for &b in b"new UI" { serial::display_byte_out(b); }
            assert_eq!(*ports::BYTES.lock().unwrap(),b"new UI");
        }
        other => panic!("unknown case: {other}"),
    }
}
'''.replace("CONSOLE_INPUT", str(ROOT / "src/console_input.rs"))
        fixture = fixture.replace("FATAL_HANDLERS", panic_source + fault_source)
        for marker, path in [("HANDLE", "src/handle.rs"), ("OBJECT", "src/object.rs"),
                             ("KERNEL_LOG", "src/kernel_log.rs"), ("DEFER_LOG", "src/defer_log.rs"), ("PRESENTATION", "src/console_presentation.rs")]:
            fixture = fixture.replace(marker, str(ROOT / path))
        (work / "fixture.rs").write_text(fixture)
        subprocess.run(["rustc", "--edition=2024", "--crate-name", "absd_abi", "--crate-type=rlib",
                        "-O", str(ROOT / "abi/src/lib.rs"), "-o", str(work / "libabsd_abi.rlib")], check=True)
        binary = work / "fixture"
        subprocess.run(["rustc", "--edition=2024", "-O", str(work / "fixture.rs"),
                        "--extern", f"absd_abi={work}/libabsd_abi.rlib",
                        "-o", str(binary)], cwd=ROOT, check=True)
        cases = ["transient", "terminal-ready", "terminal-stalled", "overflow",
                 "absent-status", "digest-boundary", "wrap", "managed-output", "managed-authority",
                 "managed-emergency", "presenter-ended", "managed-pending-prefix", "panic-detail", "kernel-fault-detail"]
        if chosen:=os.environ.get("ABSD_SERIAL_CASE"):
            assert chosen in cases
            cases=[chosen]
        for case in cases:
            subprocess.run([str(binary), case], check=True, timeout=15)
    print(f"SERIAL TX HOST TEST OK cases={len(cases)}")


if __name__ == "__main__":
    main()
