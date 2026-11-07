#![feature(restricted_std)]
//! Same one-shot Owner: actual malformed/off-peer inputs then Linux ping.
use absd_net::{
    FRAME_MAX, Link, LinkReading, NicLink,
    ipv6::echo_responder::{self, Owner},
};
use std::{cell::RefCell, rc::Rc};
#[path = "../ipv6_echo_boundary.rs"]
mod boundary;
struct Observed<L> {
    inner: L,
    trace: Rc<RefCell<boundary::Trace>>,
}
impl<L: Link> Link for Observed<L> {
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn pause(&self, ms: u64) {
        self.inner.pause(ms)
    }
    fn read(&self) -> Option<LinkReading> {
        self.inner.read()
    }
    fn receive(&mut self, frame: &mut [u8; FRAME_MAX], timeout: u64) -> Result<Option<usize>, i64> {
        let result = self.inner.receive(frame, timeout);
        if let Ok(Some(n)) = result {
            if n <= frame.len() {
                self.trace.borrow_mut().receive(&frame[..n]);
            }
        }
        result
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        let result = self.inner.send(frame);
        if result.is_ok() {
            self.trace.borrow_mut().send(frame);
        }
        result
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn run() -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    absd_runtime::link_anchor();
    let link = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let trace = Rc::new(RefCell::new(boundary::Trace::default()));
    let mut owner = Owner::acquire(
        Observed {
            inner: link,
            trace: trace.clone(),
        },
        start,
        getrandom_0_2::getrandom,
    )
    .map_err(|e| format!("DAD {e:?}"))?;
    let endpoint = owner
        .activate(echo_responder::fixture_peer())
        .map_err(|e| format!("activation {e:?}"))?;
    println!(
        "PING6 RESPONDER READY local=fd00:ab5d::15 peer=fd00:ab5d::2 scope=1 replies=1 max_icmp_bytes=1240 stop_ms={}",
        owner.stop_ms()
    );
    // Every frame is passed unchanged through the actual DAD/Port/Owner path.
    // A wire-only sender receipt cannot replace these actual receive records.
    loop {
        owner
            .poll(endpoint)
            .map_err(|e| format!("negative poll {e:?}"))?;
        if trace.borrow().invalid {
            return Err("negative input order/bound".into());
        }
        if owner.possible_reply_effects() != 0
            || owner.observe(endpoint) != Err(echo_responder::Error::Again)
        {
            return Err("negative input consumed responder".into());
        }
        if trace.borrow().complete() {
            break;
        }
        owner.wait().map_err(|e| format!("negative wait {e:?}"))?;
    }
    {
        let t = trace.borrow();
        let ns = t.warm_ns.as_ref().unwrap();
        let na = t.warm_na.as_ref().unwrap();
        println!(
            "PING6 RESPONDER WARM v=1 ns_rx={} na_tx={} na_after_rx={} ns={} na={}",
            ns.ordinal,
            na.ordinal,
            na.after_receive,
            hex(&ns.frame),
            hex(&na.frame)
        );
        for (name, r) in boundary::NAMES.iter().zip(&t.negative) {
            println!(
                "PING6 RESPONDER NEG v=1 case={} rx={} frame={} effects=0 observation=Again",
                name,
                r.ordinal,
                hex(&r.frame)
            );
        }
    }
    println!("PING6 RESPONDER NEG COMPLETE v=1 cases=4 effects=0 observation=Again sockets=0");
    let result = loop {
        owner.poll(endpoint).map_err(|e| {
            format!(
                "poll {e:?} possible_effects={}",
                owner.possible_reply_effects()
            )
        })?;
        match owner.observe(endpoint) {
            Ok(observation) => break observation,
            Err(echo_responder::Error::Again) => {}
            Err(e) => return Err(format!("observation {e:?}")),
        }
        owner.wait().map_err(|e| format!("wait {e:?}"))?;
    };
    if owner.observe(endpoint) != Err(echo_responder::Error::Spent)
        || owner.activate(echo_responder::fixture_peer()) != Err(echo_responder::Error::Exhausted)
    {
        return Err("one-shot method state".into());
    }
    owner.retire();
    if owner.observe(endpoint) != Err(echo_responder::Error::Stale)
        || owner.socket_count() != 0
        || owner.possible_reply_effects() != 1
    {
        return Err("terminal owner state".into());
    }
    println!("PING6 RESPONDER STATE v=1 observe=Spent activate=Exhausted retired=Stale sockets=0");
    println!(
        "PING6 RESPONDER PASS peer=fd00:ab5d::2 scope=1 identifier={} sequence={} icmp_bytes={} submitted_at_ms={} possible_effects=1 sockets=0 auth=none",
        result.identifier, result.sequence, result.icmp_bytes, result.submitted_at_ms
    );
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("PING6 RESPONDER ERROR {error}");
            std::process::ExitCode::from(1)
        }
    }
}
