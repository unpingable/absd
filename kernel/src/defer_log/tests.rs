extern crate std;
use super::*;
use std::vec::Vec;

fn drained<const N: usize>(log: &mut DeferLog<N>) -> Vec<u8> {
    let mut out = Vec::new();
    log.drain(|byte| out.push(byte));
    out
}

#[test]
fn bytes_come_back_in_order() {
    let mut log: DeferLog<8> = DeferLog::EMPTY;
    for byte in b"abc" {
        log.push(*byte);
    }
    assert_eq!(drained(&mut log), b"abc");
    assert_eq!(log.dropped(), 0);
}

#[test]
fn a_full_log_keeps_the_oldest_and_counts_the_rest() {
    let mut log: DeferLog<4> = DeferLog::EMPTY;
    for byte in b"abcdef" {
        log.push(*byte);
    }
    assert_eq!(log.dropped(), 2);
    assert_eq!(drained(&mut log), b"abcd");
}

#[test]
fn draining_twice_gives_nothing_new() {
    let mut log: DeferLog<4> = DeferLog::EMPTY;
    log.push(b'a');
    assert_eq!(drained(&mut log), b"a");
    assert_eq!(drained(&mut log), b"");
}
