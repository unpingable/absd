//! Fixture-only observation: received/sent bytes are returned unchanged.
//! This record is not a production drop counter or an admission decision.
use std::{format, vec::Vec};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub ordinal: u32,
    pub after_receive: u32,
    pub frame: Vec<u8>,
}
#[derive(Default)]
pub struct Trace {
    received: u32,
    sent: u32,
    pub warm_ns: Option<Record>,
    pub warm_na: Option<Record>,
    pub negative: Vec<Record>,
    pub invalid: bool,
}
pub const NAMES: [&str; 4] = ["bad-checksum", "short-icmp", "wrong-code", "wrong-peer"];
pub fn literal(name: &str) -> Vec<u8> {
    let text = include_str!("../fixtures/native-ipv6-echo-responder/boundary-v1.txt");
    let hex = text
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .expect("fixture name");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("fixture hex"))
        .collect()
}
impl Trace {
    pub fn receive(&mut self, frame: &[u8]) {
        self.received = self.received.saturating_add(1);
        self.invalid |= self.received > 128;
        let record = Record {
            ordinal: self.received,
            after_receive: self.received,
            frame: frame.to_vec(),
        };
        if frame == literal("warm-ns") {
            self.invalid |= self.warm_ns.is_some();
            self.warm_ns = Some(record);
        } else if let Some(index) = NAMES.iter().position(|n| frame == literal(n)) {
            self.invalid |= index != self.negative.len() || self.warm_na.is_none();
            if self.negative.len() < NAMES.len() {
                self.negative.push(record);
            } else {
                self.invalid = true;
            }
        }
    }
    pub fn send(&mut self, frame: &[u8]) {
        self.sent = self.sent.saturating_add(1);
        self.invalid |= self.sent > 128;
        if frame == literal("warm-na") {
            self.invalid |= self.warm_na.is_some() || self.warm_ns.is_none();
            self.warm_na = Some(Record {
                ordinal: self.sent,
                after_receive: self.received,
                frame: frame.to_vec(),
            });
        }
    }
    pub fn complete(&self) -> bool {
        !self.invalid
            && self.warm_ns.is_some()
            && self.warm_na.is_some()
            && self.negative.len() == NAMES.len()
    }
}
