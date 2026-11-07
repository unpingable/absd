#!/usr/bin/env python3
"""Run actual init logger output/outcome consumers with substituted pipe/console transport."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    source = (ROOT/'user/src/bin/init.rs').read_text()
    def function(name):
        start = source.index('fn '+name+'(')
        end = source.index('\n}', start)+2
        return source[start:end]+'\n'
    selected = ''.join(function(n) for n in ['service_outcome','logd_output','logd_retry_notice','logd_problem','logd_ended'])
    library = (ROOT/'user/src/lib.rs').read_text()
    buffer = library[library.index('pub struct LineBuffer {'):library.index('\nimpl Console {', library.index('pub struct LineBuffer {'))]
    write_bound = next(line for line in library.splitlines() if line.startswith('pub const MAX_WRITE:'))
    local = (ROOT/'user/src/local_console.rs').read_text()
    start = local.index('pub fn startup_capture_closed()')
    accessor = local[start:local.index('\n}', start)+2]
    adapter = 'mod local_console { use std::sync::atomic::{AtomicBool, Ordering}; static STARTUP_CAPTURE_CLOSED:AtomicBool=AtomicBool::new(false); pub fn set_owned(owned:bool) {STARTUP_CAPTURE_CLOSED.store(owned,Ordering::Relaxed);}' + accessor + '}\n'
    harness = '''use core::fmt::Write;
use std::sync::Mutex;
#[allow(dead_code)]
#[path=POLICY]
mod logd_policy;
#[allow(dead_code)]
#[path=LINES]
mod console_lines;
WRITE_BOUND
LOCAL_ADAPTER
BUFFER
#[derive(Clone,Copy)]struct Console;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]enum Error { Timeout }
impl Console {fn write_once(self,bytes:&[u8])->Result<usize,()> {assert!(bytes.len()<=MAX_WRITE);DISPLAY.lock().unwrap_or_else(|e|e.into_inner()).extend_from_slice(bytes);Ok(bytes.len())}}
struct Pipe;
impl Pipe {
 fn from_raw(_:u64)->Self {Self}
 fn read_timeout(self,out:&mut [u8],_:u64)->Result<usize,Error> {
   let mut input=INPUT.lock().unwrap_or_else(|e|e.into_inner());let n=out.len().min(input.len());out[..n].copy_from_slice(&input[..n]);input.drain(..n);Ok(n)
 }
}
static INPUT:Mutex<Vec<u8>>=Mutex::new(Vec::new());
static DISPLAY:Mutex<Vec<u8>>=Mutex::new(Vec::new());
static RECORDS:Mutex<Vec<Vec<u8>>>=Mutex::new(Vec::new());
static OUTCOMES:Mutex<Vec<i64>>=Mutex::new(Vec::new());
static mut LOGD_OUTPUT:u64=1;
static mut LOGD_PID:u64=9;
static mut LOGD_GENERATION:u64=1;
static mut LOGD_COLLECT_PROBE:logd_policy::Collected=logd_policy::Collected::new();
static mut LOGD_POLICY:logd_policy::Policy=logd_policy::Policy::new();
static mut LOGD_FAULT_INJECTED:bool=false;
static mut LOGD_FAULT_AT:u64=u64::MAX;
const LOGD_FAULT:bool=false;
fn time()->u64 {90000}
fn getpid()->u64 {1}
fn service_record(_:Console,_:u64,_:u64,stream:u64,bytes:&[u8]) {
 if stream==3 && bytes.starts_with(b"ended status=") {
   OUTCOMES.lock().unwrap_or_else(|e|e.into_inner()).push(std::str::from_utf8(bytes).unwrap().strip_prefix("ended status=").unwrap().parse().unwrap());
 }
 RECORDS.lock().unwrap_or_else(|e|e.into_inner()).push(bytes.to_vec());
}
SELECTED
fn setup() {
 console_lines::reset();
 local_console::set_owned(false);
 INPUT.lock().unwrap_or_else(|e|e.into_inner()).clear();DISPLAY.lock().unwrap_or_else(|e|e.into_inner()).clear();RECORDS.lock().unwrap_or_else(|e|e.into_inner()).clear();OUTCOMES.lock().unwrap_or_else(|e|e.into_inner()).clear();
 let mut p=logd_policy::Policy::new();p.unproductive=20;assert!(p.begin(0));p.spawned();assert!(!p.reporting());
 unsafe {LOGD_POLICY=p;LOGD_COLLECT_PROBE=logd_policy::Collected::new();}
}
#[test]fn genuine_nontransient_outcomes_are_recorded_even_during_retry_throttling() {
 setup();
 for status in [-1,-1006,3,104,-1] {
   logd_ended(Console,9,status);
   if unsafe {(*core::ptr::addr_of!(LOGD_POLICY)).state}!=logd_policy::State::Exhausted {
     unsafe {let p=&mut *core::ptr::addr_of_mut!(LOGD_POLICY);assert!(p.begin(p.due));p.spawned();}
   }
 }
 assert_eq!(*OUTCOMES.lock().unwrap_or_else(|e|e.into_inner()),vec![-1,-1006,3,104,-1]);
}
#[test]fn panic_and_other_output_survive_retry_notice_suppression_without_text_classification() {
 for owned in [false,true] {
   setup();local_console::set_owned(owned);let bytes=b"thread panicked: retained fault detail\\n";
   INPUT.lock().unwrap_or_else(|e|e.into_inner()).extend_from_slice(bytes);logd_output(Console);
   assert!(RECORDS.lock().unwrap_or_else(|e|e.into_inner()).iter().any(|r|r==bytes));
   assert_eq!(*DISPLAY.lock().unwrap_or_else(|e|e.into_inner()),if owned {b"".as_slice()} else {bytes});
 }
}
#[test]fn transient_outcome_still_may_be_summarized() {
 setup();logd_ended(Console,9,75);assert!(OUTCOMES.lock().unwrap_or_else(|e|e.into_inner()).is_empty());
}
'''.replace('POLICY',json.dumps(str(ROOT/'user/src/logd_policy.rs')),1).replace('LINES',json.dumps(str(ROOT/'user/src/console_lines.rs')),1).replace('WRITE_BOUND',write_bound,1).replace('BUFFER',buffer,1).replace('LOCAL_ADAPTER',adapter,1).replace('SELECTED',selected,1)
    (work/'actual-init-consumers.rs').write_text(harness)
    (work/'SOURCE.json').write_text(json.dumps({'scope':'actual init consumers and fixed LineBuffer; only pipe/console append transport substituted; no syscall claim','source_revision':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),'source_sha256':{str(ROOT/name):hashlib.sha256((ROOT/name).read_bytes()).hexdigest()for name in ['user/src/bin/init.rs','user/src/lib.rs','user/src/logd_policy.rs','user/src/local_console.rs','user/src/console_lines.rs','scripts/test-logd-output.py']},'harness_sha256':hashlib.sha256(harness.encode()).hexdigest()},indent=2)+'\n')
    subprocess.run(['rustc','+1.98.0','--edition','2024','--test',str(work/'actual-init-consumers.rs'),'-o',str(work/'proof')],check=True)
    subprocess.run([str(work/'proof'),'--test-threads=1','--nocapture'],check=True)


if __name__=='__main__':main()
