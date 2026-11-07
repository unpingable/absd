#!/usr/bin/env python3
"""Exercise real sh_host control/prompt code with deterministic queued replies."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[2]
source=(ROOT/'src/sh_host.rs').read_text()
control=source[source.index('struct Control {'):source.index('impl Drop for Control {')]
start=source.index('    fn prompt_input(&mut self, mode: u8) {')
end=start+source[start:].index('{')+1
depth=1
while depth:
    depth += (source[end]=='{') - (source[end]=='}')
    end+=1
method=source[start:end]
start=source.index('    fn discard_pending_input(&mut self) {')
end=start+source[start:].index('{')+1
depth=1
while depth:
    depth += (source[end]=='{') - (source[end]=='}')
    end+=1
discard=source[start:end]
start=source.index('    fn read_interactive(&mut self, input: &mut dyn io::BufRead, text: &mut String)')
end=start+source[start:].index('{')+1
depth=1
while depth:
    depth += (source[end]=='{') - (source[end]=='}')
    end+=1
read=source[start:end]
shell_source=(ROOT/'sh/src/lib.rs').read_text()
plain_start=shell_source.index('pub fn read_interactive_plain(')
plain_end=shell_source.index('\n}\n',plain_start)+2
plain_read=shell_source[plain_start:plain_end]
plain_limit=next(line for line in shell_source.splitlines() if line.startswith('pub const MAX_SCRIPT_BYTES:'))
harness=r'''
use std::io;
#[path="CONTROL_PATH"] mod control;
use control::{Decoder,Frame};
const KERNEL_TIMEOUT:i64=-110;
const ANSWER_TICKS:u64=10000;
mod absd_runtime {
    use std::sync::{Mutex,atomic::{AtomicU64,Ordering}};
    static INPUT:Mutex<Vec<u8>>=Mutex::new(Vec::new());
    static STDIN:Mutex<Vec<u8>>=Mutex::new(Vec::new());
    static READS:AtomicU64=AtomicU64::new(0);
    static TICK:AtomicU64=AtomicU64::new(0);
    pub fn input(bytes:Vec<u8>) {*INPUT.lock().unwrap()=bytes;}
    pub fn stdin(bytes:Vec<u8>) {*STDIN.lock().unwrap()=bytes;READS.store(0,Ordering::Relaxed);}
    pub fn reads()->u64 {READS.load(Ordering::Relaxed)}
    pub fn standard_stream_handles()->(u64,u64) {(100,101)}
    pub fn ticks()->u64 {TICK.fetch_add(1,Ordering::Relaxed)}
    pub fn read_within(handle:u64,out:&mut[u8],_:u64)->Result<usize,i64> {
        if handle==100 {READS.fetch_add(1,Ordering::Relaxed);}
        let mut bytes=if handle==100 {STDIN.lock().unwrap()} else {INPUT.lock().unwrap()};
        if bytes.is_empty(){return Err(-110);}
        let n=bytes.len().min(out.len());out[..n].copy_from_slice(&bytes[..n]);bytes.drain(..n);Ok(n)
    }
    pub fn write_within(_:u64,bytes:&[u8],_:u64)->Result<usize,i64>{Ok(bytes.len())}
    pub mod fsd {
        pub fn pipe_info(_:u64)->Result<[u64;4],i64> {
            let n=super::INPUT.lock().unwrap().len() as u64;
            Ok([n,1024-n,1,1])
        }
    }
}
CONTROL_SOURCE
mod shell {
    use std::io;
    PLAIN_LIMIT
    PLAIN_READ
    pub fn read_interactive_record(_: &mut dyn std::io::BufRead, _: &mut String) -> std::io::Result<usize> {
        panic!("an unavailable local record producer must use ordinary lines")
    }
}
struct Absd {control:Option<Control>,ended:bool,paste_records:bool,plain_recovery:bool,plain_refused:bool,pause_confirmed:bool}
impl Absd { PROMPT_METHOD DISCARD_METHOD READ_METHOD }
fn main() {
    let mut shell=Absd{control:Some(Control{events:1,requests:2,decoder:Decoder::new(control::EVENTS),prompt_cancelled:false}),ended:false,paste_records:false,plain_recovery:false,plain_refused:false,pause_confirmed:false};
    for mode in [1,2] {
        absd_runtime::input([control::interrupt(),control::reply(0,"")].concat());
        shell.prompt_input(mode);
        assert!(!shell.ended);
        assert!(std::mem::take(&mut shell.control.as_mut().unwrap().prompt_cancelled),"pre-ack cancellation was lost in prompt mode {mode}");
    }
    // An interrupt after the mode reply belongs to the new prompt and must
    // remain queued until the shell acknowledges the line it then reads.
    absd_runtime::input([control::reply(0,""),control::interrupt()].concat());
    shell.prompt_input(1);
    assert!(!shell.control.as_ref().unwrap().prompt_cancelled);
    absd_runtime::input(control::reply(0,""));
    shell.prompt_input(0);
    assert!(shell.control.as_ref().unwrap().prompt_cancelled,"post-ack prompt interrupt was lost");
    absd_runtime::input([control::interrupt(),control::reply(0,"")].concat());
    shell.prompt_input(0);
    assert!(shell.control.as_ref().unwrap().prompt_cancelled,"a real prompt cancellation was lost on mode0 ack");
    // A stale second cancellation does not imply another producer pause.
    // A normal mode-0 acknowledgement must not consume fresh input bytes.
    absd_runtime::input(control::reply(0,"paste-record-v2"));
    absd_runtime::stdin(b"fresh typing must remain intact\n".to_vec());
    shell.discard_pending_input();
    assert_eq!(absd_runtime::reads(),0,"unconfirmed pause drained fresh typing");
    absd_runtime::input(control::reply(control::INPUT_PAUSED,"paste-record-v2"));
    absd_runtime::stdin(b"cancelled pending bytes\n".to_vec());
    shell.discard_pending_input();
    assert!(absd_runtime::reads()>0,"confirmed pause did not drain cancelled input");
    assert!(!shell.ended);
    absd_runtime::input(control::reply(control::INPUT_PAUSED,"paste-record-v2"));
    absd_runtime::stdin(vec![b'x';1024*1024]);
    shell.discard_pending_input();
    assert_eq!(absd_runtime::reads(),4097,"exact bound needs an empty final probe");
    assert!(!shell.ended,"exact-bound drain must not end the session");
    absd_runtime::input(control::reply(0,"unsupported"));
    shell.prompt_input(1);
    assert!(!shell.ended && !shell.paste_records && !shell.pause_confirmed);
    let mut lines=std::io::Cursor::new(b"first\nsecond\n");
    let mut text=String::new();
    assert_eq!(shell.read_interactive(&mut lines,&mut text).unwrap(),6);
    assert_eq!(text,"first\n");
    text.clear();
    assert_eq!(shell.read_interactive(&mut lines,&mut text).unwrap(),7);
    assert_eq!(text,"second\n");
    absd_runtime::input(control::reply(0,"unsupported"));
    absd_runtime::stdin(b"already delivered local input\n".to_vec());
    shell.discard_pending_input();
    assert!(!shell.ended && !shell.pause_confirmed);
    assert_eq!(absd_runtime::reads(),0,"unsupported local pause must not drain inherited input");
    absd_runtime::input(control::reply(1,"refused"));
    shell.prompt_input(1);
    assert!(shell.ended);
    assert!(shell.control.as_ref().unwrap().prompt_cancelled,"failed ack cleared cancellation");
}
'''.replace('CONTROL_PATH',str(ROOT/'ssh/src/control.rs')).replace('CONTROL_SOURCE',control).replace('PROMPT_METHOD',method).replace('DISCARD_METHOD',discard).replace('READ_METHOD',read).replace('PLAIN_LIMIT',plain_limit).replace('PLAIN_READ',plain_read)
with tempfile.TemporaryDirectory(prefix='absd-prompt-ack-') as temp:
    src=Path(temp)/'test.rs'; binary=Path(temp)/'test';src.write_text(harness)
    subprocess.run(['rustc','--edition=2024','-Adead_code',str(src),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('PROMPT MODE ACK: primary/continuation/mode0/failure retain cancellation until interactive purge')
