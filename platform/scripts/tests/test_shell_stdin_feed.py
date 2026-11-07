#!/usr/bin/env python3
"""Compile actual Feed/Source/copy_round with deterministic primitive I/O.

The writer deliberately does not clamp its input: the production Feed must
offer at most 256 bytes itself. This exercises userspace copying, not kernel
wakeups, FSD transport, real synchronous stalls or native throughput.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / "src/sh_host.rs").read_text()
feed_source = source[source.index("struct Feed {"):source.index("enum Pipe {")]
step_source = source[source.index("impl Feed {"):source.index("fn exit_of(")]
start = source.index("feeds.push(Feed {")
constructor = source[start:source.index("});", start) + 3]
harness = r'''
use std::{cell::RefCell, collections::VecDeque, io::{self, Read, Write}, rc::Rc};
#[path="DRAIN_PATH"] mod sh_drain;
use sh_drain::{Step, Target};
const KERNEL_TIMEOUT:i64=-110;
const KERNEL_BROKEN_PIPE:i64=-32;
const INTERLEAVE_TICKS:u64=1;
const ALONE_TICKS:u64=1000;
#[derive(Default)]
struct Output {
    bytes:Vec<u8>, offers:Vec<usize>, waits:Vec<u64>,
    outcomes:VecDeque<Result<usize,i64>>, closed:bool,
}
#[derive(Default)]
struct State { outputs:Vec<Output>, events:Vec<String>, drain:VecDeque<u8> }
thread_local! { static STATE:RefCell<State>=RefCell::new(State::default()); }
fn reset() {STATE.with(|s|*s.borrow_mut()=State::default());}
struct ChildStdin(u64);
impl ChildStdin {fn as_raw_handle(&self)->u64 {self.0}}
impl Drop for ChildStdin {
    fn drop(&mut self) {STATE.with(|s|s.borrow_mut().outputs[self.0 as usize].closed=true);}
}
mod absd_runtime {
    pub fn write_within(handle:u64,bytes:&[u8],ticks:u64)->Result<usize,i64> {
        super::STATE.with(|s| {
            let mut s=s.borrow_mut();s.events.push(format!("write:{handle}"));
            let out=&mut s.outputs[handle as usize];out.offers.push(bytes.len());out.waits.push(ticks);
            let n=out.outcomes.pop_front().unwrap_or(Ok(bytes.len()))?.min(bytes.len());
            out.bytes.extend_from_slice(&bytes[..n]);Ok(n)
        })
    }
    pub fn read_within(_:u64,bytes:&mut[u8],_:u64)->Result<usize,i64> {
        super::STATE.with(|s| {
            let mut s=s.borrow_mut();s.events.push("drain".into());
            let n=bytes.len().min(s.drain.len());
            for byte in &mut bytes[..n] {*byte=s.drain.pop_front().unwrap();}
            Ok(n)
        })
    }
}
#[derive(Default)]
struct ReadState {bytes:Vec<u8>,at:usize,limits:Vec<usize>,short:Option<usize>,fail_at:Option<usize>}
struct File(Rc<RefCell<ReadState>>);
impl Read for File {
    fn read(&mut self,bytes:&mut[u8])->io::Result<usize> {
        let mut s=self.0.borrow_mut();s.limits.push(bytes.len());
        if s.fail_at.is_some_and(|at|s.at>=at) {return Err(io::Error::other("source failed"));}
        let n=bytes.len().min(s.bytes.len()-s.at).min(s.short.unwrap_or(usize::MAX));
        bytes[..n].copy_from_slice(&s.bytes[s.at..s.at+n]);s.at+=n;Ok(n)
    }
}
FEED_SOURCE
struct Pipe;
impl Pipe {fn handle(&self)->u64 {99}}
struct Sink(Rc<RefCell<Vec<u8>>>);
impl Write for Sink {
    fn write(&mut self,b:&[u8])->io::Result<usize>{self.0.borrow_mut().extend_from_slice(b);Ok(b.len())}
    fn flush(&mut self)->io::Result<()>{Ok(())}
}
impl Target for Sink {
    fn flush_pending(&mut self,_:bool)->io::Result<bool>{Ok(false)}
    fn wait_limit(&self,ticks:u64)->u64{ticks}
    fn finish(&mut self,_:bool)->io::Result<()>{Ok(())}
}
type Drain=sh_drain::Drain<Pipe,Sink>;
struct Ran {redirect:Option<io::Error>}
fn kernel_error(code:i64)->io::Error {io::Error::other(format!("kernel error {code}"))}
STEP_SOURCE
fn feed(index:usize,from:Source)->Feed {
    let to=STATE.with(|s| {let mut s=s.borrow_mut();let h=s.outputs.len();s.outputs.push(Output::default());ChildStdin(h as u64)});
    let mut feeds=Vec::new();
    CONSTRUCTOR
    feeds.pop().unwrap()
}
fn payload(n:usize)->Vec<u8>{(0..n).map(|i|((i*37+11)%251) as u8).collect()}
fn file_feed(n:usize)->(Feed,Rc<RefCell<ReadState>>,Vec<u8>) {
    let bytes=payload(n);let state=Rc::new(RefCell::new(ReadState{bytes:bytes.clone(),..ReadState::default()}));
    (feed(0,Source::File(File(state.clone()))),state,bytes)
}
fn outcomes(handle:usize,items:impl IntoIterator<Item=Result<usize,i64>>) {
    STATE.with(|s|s.borrow_mut().outputs[handle].outcomes.extend(items));
}
fn finish(mut f:Feed) {
    for _ in 0..100_000 {
        match f.step(1) {Step::Done=>return,Step::Failed(e)=>panic!("unexpected {e}"),_=>{}}
    }
    panic!("feed did not terminate");
}
fn assert_output(handle:usize,want:&[u8]) {
    STATE.with(|s| {let s=s.borrow();let o=&s.outputs[handle];assert_eq!(o.bytes,want);assert!(o.closed);assert!(o.offers.iter().all(|&n|n<=256));});
}
#[test] fn aligned_file_uses_four_refills_and_one_eof_read() {
    reset();let (f,s,want)=file_feed(16*1024);finish(f);assert_output(0,&want);
    assert_eq!(s.borrow().limits,vec![4096;5],"16KiB needs four refills, not sixty-four");
}
#[test] fn boundary_file_and_bytes_sources_preserve_every_byte() {
    for n in [0,1,255,256,257,4095,4096,4097,17*1024] {
        reset();let (f,_,want)=file_feed(n);finish(f);assert_output(0,&want);
        reset();finish(feed(0,Source::Bytes(want.clone(),0)));assert_output(0,&want);
    }
}
#[test] fn one_step_offers_at_most_256_without_transport_clamping() {
    reset();let (mut f,s,_)=file_feed(8192);assert!(matches!(f.step(7),Step::Moved));
    assert_eq!(s.borrow().limits,vec![4096]);
    STATE.with(|s| {let s=s.borrow();assert_eq!(s.outputs[0].offers,vec![256]);assert_eq!(s.outputs[0].waits,vec![7]);});
}
#[test] fn one_byte_writes_preserve_pending_tail_until_next_refill() {
    reset();let (mut f,s,want)=file_feed(4097);outcomes(0,std::iter::repeat_n(Ok(1),4096));
    for _ in 0..4096 {assert!(matches!(f.step(1),Step::Moved));assert_eq!(s.borrow().limits.len(),1);}
    assert_eq!((f.start,f.end),(4096,4096));finish(f);assert_output(0,&want);
    assert_eq!(s.borrow().limits,vec![4096;3]);
}
#[test] fn repeated_timeouts_and_short_writes_do_not_refill_or_lose_bytes() {
    reset();let (mut f,s,want)=file_feed(5000);
    outcomes(0,[Ok(3),Err(-110),Err(-110),Ok(7),Err(-110)]);
    for expected in [3,3,3,10,10] {
        let before=STATE.with(|s|s.borrow().outputs[0].offers.len());
        let step=f.step(1);assert!(matches!(step,Step::Moved|Step::Pending));
        assert_eq!(f.start,expected);assert_eq!(s.borrow().limits.len(),1);
        assert_eq!(STATE.with(|s|s.borrow().outputs[0].offers.len()),before+1);
    }
    finish(f);assert_output(0,&want);
}
#[test] fn eof_is_read_only_after_pending_suffix_drains() {
    reset();let (mut f,s,want)=file_feed(3);outcomes(0,[Ok(1),Err(-110),Ok(1),Ok(1)]);
    for _ in 0..4 {assert!(!matches!(f.step(1),Step::Done));assert_eq!(s.borrow().limits.len(),1);}
    assert!(matches!(f.step(1),Step::Done));assert_eq!(s.borrow().limits.len(),2);drop(f);assert_output(0,&want);
}
#[test] fn short_source_reads_continue_instead_of_claiming_eof() {
    reset();let (f,s,want)=file_feed(517);s.borrow_mut().short=Some(17);finish(f);assert_output(0,&want);
    assert_eq!(s.borrow().at,517);
}
#[test] fn broken_pipe_closes_feed_without_reading_remaining_source() {
    reset();let (mut f,s,_)=file_feed(8192);outcomes(0,[Ok(3),Err(-32)]);
    assert!(matches!(f.step(1),Step::Moved));assert!(matches!(f.step(1),Step::Done));
    assert_eq!(s.borrow().limits.len(),1);drop(f);assert_output(0,&payload(3));
}
#[test] fn source_error_after_drained_tail_remains_a_redirect_error() {
    reset();let (f,s,want)=file_feed(8192);s.borrow_mut().fail_at=Some(4096);
    let mut feeds=vec![f];let mut drains=vec![];let mut ran=vec![Ran{redirect:None}];
    while !feeds.is_empty() {copy_round(&mut feeds,&mut drains,&mut ran,1);}
    assert_eq!(ran[0].redirect.as_ref().unwrap().to_string(),"source failed");assert_output(0,&want[..4096]);
}
#[test] fn write_error_is_recorded_and_stops_this_feed() {
    reset();let (f,s,_)=file_feed(8192);outcomes(0,[Err(-5)]);
    let mut feeds=vec![f];let mut drains=vec![];let mut ran=vec![Ran{redirect:None}];
    assert!(copy_round(&mut feeds,&mut drains,&mut ran,1));assert!(feeds.is_empty());
    assert_eq!(ran[0].redirect.as_ref().unwrap().to_string(),"kernel error -5");assert_eq!(s.borrow().limits.len(),1);
}
#[test] fn stalled_feed_does_not_block_another_feed_or_output_drain() {
    reset();let (a,_,want)=file_feed(8192);let b=feed(1,Source::Bytes(payload(5000),0));
    outcomes(0,[Err(-110)]);STATE.with(|s|s.borrow_mut().drain.extend(b"stdout"));
    let sink=Rc::new(RefCell::new(Vec::new()));let mut drains=vec![Drain::new(0,Pipe,Sink(sink.clone()))];
    let mut feeds=vec![a,b];let mut ran=vec![Ran{redirect:None},Ran{redirect:None}];
    assert!(copy_round(&mut feeds,&mut drains,&mut ran,1));
    assert_eq!(STATE.with(|s|s.borrow().events.clone()),vec!["write:0","write:1","drain"]);
    assert_eq!(&*sink.borrow(),b"stdout");assert_eq!(feeds[0].start,0);assert_eq!(feeds[1].start,256);
    copy_all(feeds,drains,&mut ran);assert_output(0,&want);assert_output(1,&payload(5000));
    assert!(ran.iter().all(|r|r.redirect.is_none()));
}
#[test] fn each_round_attempts_one_write_per_feed_during_partial_drain() {
    reset();let a=feed(0,Source::Bytes(payload(8192),0));let b=feed(1,Source::Bytes(payload(8192),0));
    let mut feeds=vec![a,b];let mut drains=vec![];let mut ran=vec![Ran{redirect:None},Ran{redirect:None}];
    for round in 1..=16 {
        assert!(copy_round(&mut feeds,&mut drains,&mut ran,1));
        STATE.with(|s|for o in &s.borrow().outputs {assert_eq!(o.offers.len(),round);assert_eq!(o.bytes.len(),round*256);});
    }
}
'''.replace("DRAIN_PATH", str(ROOT / "src/sh_drain.rs")).replace(
    "FEED_SOURCE", feed_source).replace("STEP_SOURCE", step_source).replace("CONSTRUCTOR", constructor)
with tempfile.TemporaryDirectory(prefix="absd-stdin-feed-") as temp:
    src = Path(temp) / "test.rs"
    binary = Path(temp) / "test"
    src.write_text(harness)
    subprocess.run(["rustc", "--edition=2024", "--test", "-Adead_code", "-Cdebuginfo=0",
                    "-Cstrip=debuginfo", str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary), "--test-threads=1"], check=True)
print("SHELL STDIN FEED: actual Feed/Source/copy_round and output Drain controls passed")
