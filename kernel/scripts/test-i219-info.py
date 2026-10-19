#!/usr/bin/env python3
"""Host regression for production i219_device::info; no hardware or Cargo build.

Compile the actual function with scripted carrier/reap/MMIO boundaries. This
checks snapshot ordering and counters, not hardware behavior or the helpers'
implementation. The negative control restores the pre-r82 flag expression.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SIGNATURE = "pub fn info() -> Option<NicInfo> {"
FIXTURE = r'''
#![allow(private_interfaces)]
const NIC_FLAG_LINK_UP: u32 = 1;
const NIC_FLAG_DISABLED: u32 = 2;
const MPC: u32 = 0x4010;
#[derive(Clone, Copy, Default, Debug)]
struct NicInfo { flags: u32, rx_missed: u64, tx_frames: u64, tx_errors: u64 }
struct Registers { reads: usize }
impl Registers {
    fn read32(&mut self, register: u32) -> u32 {
        assert_eq!(register, MPC);
        self.reads += 1;
        7
    }
}
struct Nic {
    info: NicInfo, io: Registers, disabled: Option<()>,
    carrier: Result<bool, ()>, late_fault: bool, ensure_calls: usize, reap_calls: usize,
}
impl Nic {
    fn ensure_active(&mut self) -> Result<bool, ()> {
        self.ensure_calls += 1;
        assert_eq!(self.reap_calls, 0, "carrier/activation must precede reap");
        if self.disabled.is_some() { return Err(()); }
        if self.carrier.is_err() { self.disabled = Some(()); }
        self.carrier
    }
    fn reap_held(&mut self) {
        assert!(self.disabled.is_none(), "disabled descriptors consulted");
        assert_eq!(self.ensure_calls, 1, "reap before carrier/activation");
        self.reap_calls += 1;
        // The held done bit is counted even if its error bits retire the NIC.
        self.info.tx_frames += 1;
        if self.late_fault { self.disabled = Some(()); }
    }
}
static mut NIC: Option<Nic> = None;
fn nic() -> Option<&'static mut Nic> {
    // Single-threaded fixture; each returned borrow ends before replacement.
    unsafe { (&mut *core::ptr::addr_of_mut!(NIC)).as_mut() }
}
__PRODUCTION_INFO__
fn case(name: &str, carrier: Result<bool, ()>, initially_disabled: bool,
        late_fault: bool, expected_flags: u32, expected_reap: usize) {
    unsafe { NIC = Some(Nic {
        info: NicInfo { flags: 0xffff, rx_missed: 11, tx_frames: 13, tx_errors: 17 },
        io: Registers { reads: 0 }, disabled: initially_disabled.then_some(()),
        carrier, late_fault, ensure_calls: 0, reap_calls: 0,
    }); }
    let out = info().expect("NIC exists");
    assert_eq!(out.flags, expected_flags, "{name}: flags");
    assert_ne!(out.flags, NIC_FLAG_LINK_UP | NIC_FLAG_DISABLED, "{name}: inconsistent flags");
    let n = nic().unwrap();
    assert_eq!(n.ensure_calls, 1, "{name}: carrier call count");
    assert_eq!(n.reap_calls, expected_reap, "{name}: reap count");
    assert_eq!(n.io.reads, expected_reap, "{name}: missed-counter MMIO count");
    assert_eq!(out.rx_missed, 11 + 7 * expected_reap as u64, "{name}: missed counter");
    assert_eq!(out.tx_frames, 13 + expected_reap as u64,
               "{name}: completed counter");
    assert_eq!(out.tx_errors, 17,
               "{name}: error counter");
    println!("PASS {name}");
}
fn main() {
    assert!(info().is_none());
    println!("PASS absent");
    case("late_fault_up", Ok(true), false, true, NIC_FLAG_DISABLED, 1);
    case("ordinary_up", Ok(true), false, false, NIC_FLAG_LINK_UP, 1);
    case("ordinary_down", Ok(false), false, false, 0, 1);
    case("initially_disabled", Ok(true), true, true, NIC_FLAG_DISABLED, 0);
    case("activation_failure", Err(()), false, true, NIC_FLAG_DISABLED, 0);
    case("late_fault_down", Ok(false), false, true, NIC_FLAG_DISABLED, 1);
}
'''


def main():
    source = (ROOT / "src/i219_device.rs").read_text()
    if source.count(SIGNATURE) != 1:
        raise SystemExit("expected exactly one production info function")
    # info is currently the final item. Include its unchanged source tail;
    # unexpected future dependencies fail compilation instead of using a copy.
    info = source[source.index(SIGNATURE):]
    fixed = "if n.disabled.is_none() && link"
    if info.count(fixed) != 1:
        raise SystemExit("negative-control substitution no longer matches production")
    variants = (("production", info), ("pre_r82", info.replace(fixed, "if link", 1)))
    # Exact generated inputs are reproducible; no binary has a retention dependency.
    with tempfile.TemporaryDirectory(prefix="absd-i219-info-") as scratch:
        for name, body in variants:
            rust = Path(scratch) / f"{name}.rs"
            binary = Path(scratch) / name
            rust.write_text(FIXTURE.replace("__PRODUCTION_INFO__", body))
            subprocess.run([os.environ.get("RUSTC", "rustc"), "--edition=2021",
                            str(rust), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            if name == "production":
                print(result.stdout, end="")
                if result.returncode != 0:
                    raise SystemExit(result.stderr)
            else:
                if result.returncode == 0 or "late_fault_up: flags" not in result.stderr:
                    raise SystemExit("negative control did not reproduce the original late-fault failure\n"
                                     + result.stdout + result.stderr)
                print("PASS pre-r82 negative control: late_fault_up rejected")
    print("PASS i219 info host regression (7 cases + pre-r82 negative control)")


if __name__ == "__main__":
    main()
