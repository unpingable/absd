//! Exercise the serving-loop quiet decision with the actual protocol parser.
use absd_fsd::readiness::Quiet;
use absd_fsd::{Inbox, Taken, proto};

fn nested_frames() -> (Vec<u8>, Vec<u8>, usize) {
    let inner = proto::Frame::request(proto::op::COMMIT).finish_seq(9);
    let outer = proto::Frame::request(proto::op::WRITE_AT)
        .bytes(&inner)
        .bytes(&[0x55; 64])
        .finish_seq(7);
    let prefix = proto::HEADER + 1 + inner.len();
    (outer, inner, prefix)
}

#[test]
fn an_empty_poll_does_not_resynchronize_a_live_partial_frame() {
    let (outer, _, prefix) = nested_frames();
    let mut inbox = Inbox::new();
    let mut quiet = Quiet::default();
    inbox.push(&outer[..prefix]);
    assert_eq!(inbox.take(), Taken::Nothing);
    if quiet.empty(100) {
        inbox.idle();
    }
    assert_eq!(inbox.take(), Taken::Nothing);
    if quiet.empty(101) {
        inbox.idle();
    }
    assert_eq!(inbox.take(), Taken::Nothing);
    quiet.reset();
    inbox.push(&outer[prefix..]);
    assert_eq!(
        inbox.take(),
        Taken::Frame {
            seq: 7,
            body: outer[proto::HEADER..outer.len() - proto::TRAILER].to_vec()
        }
    );
}

#[test]
fn a_full_quiet_period_still_recovers_the_next_holders_frame() {
    let (outer, inner, prefix) = nested_frames();
    let mut inbox = Inbox::new();
    let mut quiet = Quiet::default();
    inbox.push(&outer[..prefix]);
    assert!(!quiet.empty(100));
    assert!(quiet.empty(102));
    inbox.idle();
    assert_eq!(
        inbox.take(),
        Taken::Frame {
            seq: 9,
            body: inner[proto::HEADER..inner.len() - proto::TRAILER].to_vec()
        }
    );
}
