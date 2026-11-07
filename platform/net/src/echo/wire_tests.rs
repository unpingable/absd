//! Actual Owner/engine controls for the private receive transcript fixture.
use super::*;
use alloc::vec;
#[path = "../../../src/echo_wire_fixture.rs"]
mod fixture;
fn opened_wire() -> (
    Owner<fixture::ReceiptLink<TestLink>>,
    Rc<RefCell<State>>,
    Rc<RefCell<fixture::Trace>>,
) {
    let (_, state) = opened();
    let trace = Rc::new(RefCell::new(fixture::Trace::default()));
    let owner = Owner::open(
        fixture::ReceiptLink {
            inner: TestLink(state.clone()),
            trace: trace.clone(),
        },
        Config {
            address: LOCAL.into(),
            prefix_len: 24,
            gateway: None,
            rx_buffer: 1024,
            tx_buffer: 1024,
        },
    )
    .unwrap();
    (owner, state, trace)
}
fn submitted() -> (
    Owner<fixture::ReceiptLink<TestLink>>,
    Rc<RefCell<State>>,
    Rc<RefCell<fixture::Trace>>,
    Endpoint,
    Vec<u8>,
) {
    let (mut owner, state, trace) = opened_wire();
    let endpoint = owner.grant(PEER, 1000, entropy).unwrap();
    owner.start(endpoint, PEER).unwrap();
    owner.poll().unwrap();
    state.borrow_mut().rx.push_back(arp_reply());
    owner.poll().unwrap();
    let request = trace.borrow().request(0).unwrap().to_vec();
    assert_eq!(trace.borrow().requests(0), 1);
    (owner, state, trace, endpoint, request)
}
#[test]
fn nine_actual_delivered_wire_cases_leave_owner_unobserved_until_explicit_close() {
    let (mut owner, state, trace, endpoint, request) = submitted();
    for index in 0..fixture::CASES.len() {
        let selected = fixture::selected_reply(&request, index).unwrap();
        let prior_rx = trace.borrow().rx;
        state.borrow_mut().rx.push_back(selected.clone());
        owner.poll().unwrap();
        assert_eq!(trace.borrow().rx, prior_rx + 1);
        assert_eq!(trace.borrow().frames.last().unwrap().bytes, selected);
        assert_eq!(owner.observe(endpoint), Err(Error::Again), "case {index}");
        assert_eq!(owner.socket_count(), 1);
        assert_eq!(trace.borrow().requests(0), 1);
        state.borrow_mut().now += 1;
    }
    owner.close(endpoint).unwrap();
    assert_eq!(owner.socket_count(), 0);
    assert_eq!(owner.start(endpoint, PEER), Err(Error::Stale));
}
#[test]
fn fresh_after_negative_can_observe_once_with_same_real_owner_engine() {
    let (mut owner, state, trace, negative, request) = submitted();
    state
        .borrow_mut()
        .rx
        .push_back(fixture::selected_reply(&request, 8).unwrap());
    owner.poll().unwrap();
    assert_eq!(owner.observe(negative), Err(Error::Again));
    owner.close(negative).unwrap();
    trace.borrow_mut().phase = 1;
    let positive = owner.grant(PEER, 1000, entropy).unwrap();
    assert_ne!(negative, positive);
    assert_eq!(owner.start(negative, PEER), Err(Error::Stale));
    owner.start(positive, PEER).unwrap();
    owner.poll().unwrap();
    let fresh = trace.borrow().request(1).unwrap().to_vec();
    assert_ne!(&fresh[58..66], &request[58..66]);
    state.borrow_mut().rx.push_back(response(&fresh));
    owner.poll().unwrap();
    let observed = owner.observe(positive).unwrap();
    assert_eq!(observed.epoch, positive.epoch);
    assert_eq!(owner.observe(positive), Err(Error::Spent));
    assert_eq!(owner.socket_count(), 0);
    assert_eq!(trace.borrow().requests(1), 1);
    owner.close(positive).unwrap();
    assert_eq!(owner.start(positive, PEER), Err(Error::Stale));
}
#[test]
fn literal_case_offsets_checksums_and_exact_frame_matching_remain_distinct() {
    let (_, _, _, _, request) = submitted();
    assert_eq!(
        fixture::CASES,
        [
            "wrong-peer",
            "wrong-type",
            "wrong-code",
            "wrong-identifier",
            "wrong-sequence",
            "wrong-body",
            "wrong-epoch",
            "wrong-nonce",
            "bad-checksum"
        ]
    );
    for index in 0..9 {
        let selected = fixture::selected_reply(&request, index).unwrap();
        assert_eq!(selected.len(), 74);
        assert_eq!(fixture::checksum(&selected[14..34]), 0);
        assert_eq!(fixture::checksum(&selected[34..]) == 0, index != 8);
        assert!(fixture::matches_case(&request, &selected, index));
        for other in 0..9 {
            if other != index {
                assert!(!fixture::matches_case(&request, &selected, other));
            }
        }
        let mut substituted = selected.clone();
        substituted[0] ^= 1;
        assert!(!fixture::matches_case(&request, &substituted, index));
        assert!(!fixture::matches_case(&request, &selected[..73], index));
    }
}
#[test]
fn matching_packet_acceptance_is_byte_correlation_not_authenticated_history() {
    let (mut owner, state, _, endpoint, request) = submitted();
    // Equal bytes on this current tuple can satisfy the observer. A source
    // generator or a historical epoch cannot be identified from those bytes.
    let exact = response(&request);
    assert!(!fixture::matches_case(&request, &exact, 6));
    state.borrow_mut().rx.push_back(exact);
    owner.poll().unwrap();
    assert!(owner.observe(endpoint).is_ok());
    assert_eq!(owner.observe(endpoint), Err(Error::Spent));
}
#[test]
fn transcript_preserves_actual_receive_bytes_ordinals_and_phase_without_rewrite() {
    let (_, state, trace) = opened_wire();
    let first = arp_reply();
    let second = vec![0x5a; 74];
    state
        .borrow_mut()
        .rx
        .extend([first.clone(), second.clone()]);
    let mut link = fixture::ReceiptLink {
        inner: TestLink(state.clone()),
        trace: trace.clone(),
    };
    let mut bytes = [0; FRAME_MAX];
    assert_eq!(link.receive(&mut bytes, 0), Ok(Some(first.len())));
    assert_eq!(&bytes[..first.len()], &first);
    trace.borrow_mut().phase = 1;
    state.borrow_mut().now = 2;
    assert_eq!(link.receive(&mut bytes, 0), Ok(Some(second.len())));
    assert_eq!(&bytes[..second.len()], &second);
    assert_eq!(link.receive(&mut bytes, 0), Ok(None));
    let t = trace.borrow();
    assert_eq!(t.rx, 2);
    assert_eq!(t.tx, 0);
    assert_eq!(
        (t.frames[0].ordinal, t.frames[0].phase, t.frames[0].at_ms),
        (1, 0, 1)
    );
    assert_eq!(
        (t.frames[1].ordinal, t.frames[1].phase, t.frames[1].at_ms),
        (2, 1, 2)
    );
}
#[test]
fn failed_send_keeps_real_effect_but_is_not_recorded_as_successful_submission() {
    let (_, state, trace) = opened_wire();
    let frame = arp_reply();
    state.borrow_mut().send_error = Some(-5);
    let mut link = fixture::ReceiptLink {
        inner: TestLink(state.clone()),
        trace: trace.clone(),
    };
    assert_eq!(link.send(&frame), Err(-5));
    assert_eq!(state.borrow().tx, [frame]);
    assert_eq!(
        trace.borrow().tx,
        0,
        "no absence-of-wire inference is permitted on Err"
    );
}
#[test]
fn receipt_bound_refuses_after_actual_read_without_inventing_rollback() {
    let (_, state, trace) = opened_wire();
    state.borrow_mut().rx.extend((0..33).map(|_| vec![0; 14]));
    let mut link = fixture::ReceiptLink {
        inner: TestLink(state.clone()),
        trace: trace.clone(),
    };
    let mut bytes = [0; FRAME_MAX];
    for _ in 0..32 {
        assert_eq!(link.receive(&mut bytes, 0), Ok(Some(14)));
    }
    assert_eq!(link.receive(&mut bytes, 0), Err(-5));
    assert_eq!(trace.borrow().rx, 32);
    assert!(
        state.borrow().rx.is_empty(),
        "the refused 33rd read already happened"
    );
}
#[test]
fn strict_original_clock_and_submitted_request_shape_refuse_substitutions() {
    let (_, _, _, _, request) = submitted();
    for at in [14, 16, 23, 26, 30, 34, 36] {
        let mut changed = request.clone();
        changed[at] ^= 1;
        assert!(fixture::selected_reply(&changed, 0).is_err());
    }
    assert!(fixture::selected_reply(&request, 9).is_err());
    let mut last = 1;
    assert_eq!(fixture::clock(&mut last, 8001, 8000), Ok(()));
    assert!(fixture::clock(&mut last, 8001, 8001).is_err());
    assert!(fixture::clock(&mut last, 8001, 7999).is_err());
    assert_eq!(last, 8000);
}
