#!/usr/bin/env python3
"""Run the actual Control/supervise bodies with deterministic primitive I/O.

Like test_prompt_mode_ack, this compiles production source with the real wire
decoder. Transport, child status and copy-round results are injected; this is
not a scheduler, kernel-pipe, filesystem-durability or guest timing proof.
"""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / "src/sh_host.rs").read_text()
control = source[source.index("struct Control {"):source.index("impl Drop for Control {")]
supervision = source[source.index("fn exit_of("):source.index("impl Host for Absd {")]
constants = "\n".join(re.findall(r"^const [A-Z_]+: [^\n]+", source, re.M))
harness = r'''
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::Mutex;
#[path="CONTROL_PATH"] mod control;
use control::{Decoder, Frame};
CONSTANTS
#[derive(Default)]
struct State {
    round: usize, end_round: usize, child_end: usize, child_polls_end: usize, stall: Vec<usize>,
    input: Vec<u8>, arrivals: Vec<(usize, Vec<u8>)>, closed_at: usize,
    info_error: bool, read_error: bool, after_empty: bool,
    reads: Vec<(usize,u64)>, infos: usize, polls: Vec<usize>,
    kills: usize, reaps: usize, finishes: Vec<bool>, finish_error: bool,
}
static STATE: Mutex<State> = Mutex::new(State {
    round:0,end_round:0,child_end:0,child_polls_end:0,stall:Vec::new(),input:Vec::new(),
    arrivals:Vec::new(),closed_at:0,info_error:false,read_error:false,
    after_empty:false,reads:Vec::new(),infos:0,polls:Vec::new(),kills:0,
    reaps:0,finishes:Vec::new(),finish_error:false,
});
fn reset() {
    *STATE.lock().unwrap_or_else(|p|p.into_inner()) = State {end_round:28, child_end:28, ..State::default()};
    STATE.clear_poison();
}
mod absd_runtime {
    pub fn ticks()->u64 { super::STATE.lock().unwrap().round as u64 }
    pub fn write_within(_:u64,b:&[u8],_:u64)->Result<usize,i64>{Ok(b.len())}
    pub fn read_within(_:u64,out:&mut[u8],ticks:u64)->Result<usize,i64> {
        let mut s=super::STATE.lock().unwrap(); let round=s.round;
        s.reads.push((round,ticks));
        if s.read_error {return Err(-5)}
        let n=out.len().min(s.input.len());
        if n>0 {out[..n].copy_from_slice(&s.input[..n]);s.input.drain(..n);return Ok(n)}
        if s.closed_at>0 && round>=s.closed_at {Ok(0)} else {Err(-110)}
    }
    pub mod fsd {
        pub fn pipe_info(_:u64)->Result<[u64;4],i64> {
            let mut s=super::super::STATE.lock().unwrap();s.infos+=1;
            if s.info_error {return Err(-9)}
            let n=s.input.len() as u64;
            let writers=u64::from(s.closed_at==0 || s.round<s.closed_at);
            // An event arriving just after an empty observation must be
            // handled at the next bounded check, not lost or spun on.
            if n==0 && s.after_empty {s.after_empty=false;s.input=crate::control::interrupt();}
            Ok([n,1024-n,1,writers])
        }
    }
}
CONTROL_SOURCE
#[derive(Debug,PartialEq)] enum Exit {Code(i32),Other,Interrupted}
struct Ran {exit:io::Result<Exit>,redirect:Option<io::Error>}
struct Child;
impl Child {
    fn try_wait(&mut self)->io::Result<Option<ExitStatus>> {
        let mut s=STATE.lock().unwrap();let round=s.round;s.polls.push(round);
        if round>=s.child_end || (s.child_polls_end>0 && s.polls.len()>=s.child_polls_end) {
            s.reaps+=1;Ok(Some(ExitStatus::from_raw(7<<8)))
        } else {Ok(None)}
    }
    fn kill(&mut self)->io::Result<()> {STATE.lock().unwrap().kills+=1;Ok(())}
    fn wait(&mut self)->io::Result<ExitStatus> {STATE.lock().unwrap().reaps+=1;Ok(ExitStatus::from_raw(0))}
}
struct Feed;
struct Drain {stage:usize}
impl Drain {
    fn finish(&mut self,sync:bool)->io::Result<()> {
        let mut s=STATE.lock().unwrap();s.finishes.push(sync);
        if s.finish_error {Err(io::Error::other("flush failed"))} else {Ok(())}
    }
}
fn copy_round(feeds:&mut Vec<Feed>,drains:&mut Vec<Drain>,_:&mut[Ran],_:u64)->bool {
    let mut s=STATE.lock().unwrap();s.round+=1;let round=s.round;
    assert!(round<=100,"supervision stopped making bounded progress");
    let mut pending=Vec::new();
    for (at,bytes) in std::mem::take(&mut s.arrivals) {
        if at==round {s.input.extend(bytes)} else {pending.push((at,bytes))}
    }
    s.arrivals=pending;
    if round>=s.end_round {feeds.clear();drains.clear();}
    !s.stall.contains(&round)
}
fn copy_all(_:Vec<Feed>,_:Vec<Drain>,_:&mut[Ran]) {panic!("unexpected unmanaged path")}
SUPERVISION_SOURCE
fn channel()->Control {Control {events:1,requests:2,decoder:Decoder::new(control::EVENTS),prompt_cancelled:false}}
fn run_with(c:Control,n:usize)->(bool,Vec<Ran>,Control) {
    let mut c=Some(c);let mut children=(0..n).map(|_|Some(Child)).collect::<Vec<_>>();
    let mut results=(0..n).map(|_|Ran{exit:Ok(Exit::Other),redirect:None}).collect::<Vec<_>>();
    let ended=supervise(&mut c,&mut children,vec![],vec![Drain{stage:0}],&mut results);
    assert!(children.iter().all(Option::is_none),"child was not reaped");
    (ended,results,c.unwrap())
}
#[test] fn progressing_copy_skips_empty_control_timeout() {
    reset();let (ended,r,_)=run_with(channel(),1);assert!(!ended);
    assert_eq!(r[0].exit.as_ref().unwrap(),&Exit::Code(7));
    let s=STATE.lock().unwrap();assert_eq!(s.polls,vec![9,18,27,28]);
    assert!(s.reads.is_empty(),"progressing copy incurred empty control reads: {:?}",s.reads);
    assert_eq!(s.reaps,1);assert_eq!(s.kills,0);
}
#[test] fn stalled_round_keeps_blocking_fallback() {
    reset();{let mut s=STATE.lock().unwrap();s.stall=vec![9];s.end_round=10;s.child_end=10;}
    run_with(channel(),1);assert_eq!(STATE.lock().unwrap().reads,vec![(9,1)]);
}
#[test] fn idle_child_keeps_timed_control_wait_and_is_reaped() {
    reset();{let mut s=STATE.lock().unwrap();s.child_end=usize::MAX;s.child_polls_end=3;}
    let mut c=Some(channel());let mut children=vec![Some(Child)];
    let mut results=vec![Ran{exit:Ok(Exit::Other),redirect:None}];
    assert!(!supervise(&mut c,&mut children,vec![],vec![],&mut results));
    assert!(children[0].is_none());assert!(matches!(results[0].exit,Ok(Exit::Code(7))));
    let s=STATE.lock().unwrap();assert_eq!(s.reads,vec![(0,CONTROL_TICKS),(0,CONTROL_TICKS)]);
    assert_eq!(s.infos,0);assert_eq!(s.reaps,1);
}
#[test] fn interrupt_reaps_every_child_and_syncs_accepted_bytes() {
    reset();STATE.lock().unwrap().arrivals.push((1,control::interrupt()));
    let (ended,r,c)=run_with(channel(),2);assert!(!ended);assert!(c.prompt_cancelled);
    assert!(r.iter().all(|r|matches!(r.exit,Ok(Exit::Interrupted))));
    let s=STATE.lock().unwrap();assert_eq!(s.round,9);assert_eq!(s.kills,2);
    assert_eq!(s.reaps,2);assert_eq!(s.finishes,vec![true]);
}
#[test] fn end_and_closed_writer_use_existing_session_cleanup() {
    for eof in [false,true] {
        reset();if eof {STATE.lock().unwrap().closed_at=1;} else {STATE.lock().unwrap().arrivals.push((1,control::end()));}
        assert!(run_with(channel(),1).0);let s=STATE.lock().unwrap();
        assert_eq!(s.round,9);assert_eq!((s.kills,s.reaps),(1,1));assert_eq!(s.finishes,vec![false]);
    }
}
#[test] fn readiness_error_is_control_loss() {
    reset();STATE.lock().unwrap().info_error=true;
    assert!(run_with(channel(),1).0);let s=STATE.lock().unwrap();
    assert_eq!(s.round,9);assert!(s.reads.is_empty());assert_eq!((s.kills,s.reaps),(1,1));
}
#[test] fn ready_read_error_is_control_loss() {
    reset();{let mut s=STATE.lock().unwrap();s.read_error=true;s.input=control::interrupt();}
    assert!(run_with(channel(),1).0);assert_eq!(STATE.lock().unwrap().finishes,vec![false]);
}
#[test] fn buffered_frames_are_decoded_even_when_pipe_is_empty() {
    for end in [false,true] {
        reset();let mut c=channel();c.decoder.push(&[control::reply(0,""),if end {control::end()} else {control::interrupt()}].concat());
        assert_eq!(run_with(c,1).0,end);let s=STATE.lock().unwrap();
        assert_eq!(s.round,18);assert!(s.reads.is_empty());assert_eq!((s.kills,s.reaps),(1,1));
    }
}
#[test] fn fragmented_event_waits_for_its_complete_frame() {
    reset();let frame=control::interrupt();{let mut s=STATE.lock().unwrap();s.arrivals=vec![(1,frame[..1].to_vec()),(10,frame[1..].to_vec())];}
    assert!(!run_with(channel(),1).0);let s=STATE.lock().unwrap();
    assert_eq!(s.round,18);assert_eq!(s.reads,vec![(9,1),(18,1)]);assert_eq!(s.kills,1);
}
#[test] fn end_takes_priority_over_interrupt_in_one_read() {
    reset();STATE.lock().unwrap().input=[control::interrupt(),control::end()].concat();
    let (ended,_,c)=run_with(channel(),1);assert!(ended);assert!(c.prompt_cancelled);
    assert_eq!(STATE.lock().unwrap().finishes,vec![false]);
}
#[test] fn malformed_event_preserves_fail_closed_behavior() {
    reset();STATE.lock().unwrap().input=control::encode(control::MACHINE,b"shutdown");
    assert!(run_with(channel(),1).0);assert_eq!(STATE.lock().unwrap().kills,1);
}
#[test] fn child_exit_does_not_abandon_buffered_payload() {
    reset();STATE.lock().unwrap().child_end=9;let (ended,r,_)=run_with(channel(),1);
    assert!(!ended);assert!(matches!(r[0].exit,Ok(Exit::Code(7))));
    let s=STATE.lock().unwrap();assert_eq!(s.round,28);assert_eq!(s.polls,vec![9]);assert_eq!(s.reaps,1);
}
#[test] fn event_after_empty_snapshot_is_seen_at_next_check() {
    reset();STATE.lock().unwrap().after_empty=true;
    assert!(!run_with(channel(),1).0);let s=STATE.lock().unwrap();
    assert_eq!(s.round,18);assert_eq!(s.reads,vec![(18,1)]);assert_eq!(s.kills,1);
}
#[test] fn cancellation_flush_error_remains_a_redirection_failure() {
    reset();{let mut s=STATE.lock().unwrap();s.input=control::interrupt();s.finish_error=true;}
    let (ended,r,_)=run_with(channel(),1);assert!(!ended);assert!(r[0].redirect.is_some());
}
'''.replace("CONTROL_PATH", str(ROOT / "ssh/src/control.rs")).replace(
    "CONSTANTS", constants).replace("CONTROL_SOURCE", control).replace("SUPERVISION_SOURCE", supervision)
with tempfile.TemporaryDirectory(prefix="absd-control-poll-") as temp:
    src = Path(temp) / "test.rs"
    binary = Path(temp) / "test"
    src.write_text(harness)
    subprocess.run(["rustc", "--edition=2024", "--test", "-Adead_code", str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary), "--test-threads=1"], check=True)
print("SHELL CONTROL POLL: actual control/decoder/supervision regression checks passed")
