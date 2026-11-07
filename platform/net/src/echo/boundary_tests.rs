//! Host qualification of the actual shared fixture and public Owner/Channel.
use super::*;
#[path = "../../../src/echo_boundary.rs"]
mod fixture;
fn prepared() -> (
    Owner<TestLink>,
    Rc<RefCell<State>>,
    Endpoint,
    Channel,
    fixture::ObservedPipe<TestPipe>,
) {
    let (mut owner, state) = opened();
    let endpoint = owner.grant(PEER, 1000, entropy).unwrap();
    let channel = Channel::new(&mut owner, endpoint).unwrap();
    let mut input = fixture::REQUESTS.concat();
    input.push(0);
    let transport = fixture::ObservedPipe::new(pipe(state.clone(), &input), Some(56));
    (owner, state, endpoint, channel, transport)
}
fn reach_prefix(
    owner: &mut Owner<TestLink>,
    channel: &mut Channel,
    transport: &mut fixture::ObservedPipe<TestPipe>,
) {
    for _ in 0..20 {
        assert!(channel.poll(owner, transport));
        assert_eq!(
            owner.socket_count(),
            1,
            "negative IPC must not close or spend the grant"
        );
        if transport.prefix.is_some() {
            return;
        }
    }
    panic!("actual partial input not consumed");
}
#[test]
fn seven_actual_channel_exchanges_keep_socket_until_observed_partial_eof() {
    let (mut owner, state, endpoint, mut channel, mut transport) = prepared();
    reach_prefix(&mut owner, &mut channel, &mut transport);
    assert!(fixture::ledger_matches(&transport.input, &transport.output));
    assert_eq!(transport.inner.read_effect, 57);
    assert!(transport.eof.is_none());
    assert!(state.borrow().tx.is_empty());
    transport.inner.eof = true;
    assert!(!channel.poll(&mut owner, &mut transport));
    assert_eq!(transport.eof.unwrap().bytes, 0);
    assert_eq!(owner.socket_count(), 0);
    assert_eq!(owner.start(endpoint, PEER), Err(Error::Stale));
    let fresh = owner.grant(PEER, 1000, entropy).unwrap();
    assert_ne!(fresh, endpoint);
    assert_eq!(owner.socket_count(), 1);
    assert!(state.borrow().tx.is_empty());
}
#[test]
fn literal_ledgers_refuse_each_request_reply_and_prefix_substitution() {
    let mut input = fixture::REQUESTS.concat();
    input.push(0);
    let output: Vec<u8> = (0..7).flat_map(fixture::reply).collect();
    assert!(fixture::ledger_matches(&input, &output));
    for at in 0..input.len() {
        let mut changed = input.clone();
        changed[at] ^= 1;
        assert!(!fixture::ledger_matches(&changed, &output));
    }
    for at in 0..output.len() {
        let mut changed = output.clone();
        changed[at] ^= 1;
        assert!(!fixture::ledger_matches(&input, &changed));
    }
    assert!(!fixture::ledger_matches(&input[..56], &output));
    assert!(!fixture::ledger_matches(&input, &output[..335]));
}
#[test]
fn constructor_fixture_uses_actual_refusals_without_poll_or_wire_submission() {
    let (mut owner, state) = opened();
    let (rows, old) = fixture::constructors(&mut owner, 1, 1000, entropy).unwrap();
    assert_eq!(
        rows.iter().map(|r| r.0).collect::<Vec<_>>(),
        [
            "unspecified",
            "loopback",
            "multicast",
            "local",
            "subnet",
            "broadcast",
            "off-link",
            "expired",
            "too-long",
            "entropy-error",
            "entropy-zero",
            "second-grant",
            "closed-stale"
        ]
    );
    assert_eq!(
        rows.iter().map(|r| r.1).collect::<Vec<_>>(),
        [2, 2, 2, 2, 2, 2, 2, 1, 1, 13, 13, 3, 4]
    );
    assert_eq!(
        rows.iter().map(|r| r.2).collect::<Vec<_>>(),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
    );
    assert!(state.borrow().tx.is_empty());
    let fresh = owner.grant(PEER, 1000, entropy).unwrap();
    assert_ne!(fresh, old);
    assert_eq!(owner.start(old, PEER), Err(Error::Stale));
}
#[test]
fn eof_at_249_is_observed_but_frame_expiry_is_not_reported_as_eof() {
    for delay in [249, 250] {
        let (mut owner, state, endpoint, mut channel, mut transport) = prepared();
        reach_prefix(&mut owner, &mut channel, &mut transport);
        let stamp = transport.prefix.unwrap();
        transport.inner.eof = true;
        state.borrow_mut().now = stamp.after + delay;
        assert!(!channel.poll(&mut owner, &mut transport));
        assert_eq!(transport.eof.is_some(), delay == 249);
        assert_eq!(
            fixture::before_frame(stamp.before, 1000, state.borrow().now),
            delay == 249
        );
        assert_eq!(owner.socket_count(), 0);
        assert_eq!(owner.start(endpoint, PEER), Err(Error::Stale));
    }
}
#[test]
fn real_pipe_none_partial_and_eof_are_distinct_in_shared_observer() {
    let (_, state) = opened();
    let mut observed = fixture::ObservedPipe::new(pipe(state.clone(), &[]), Some(0));
    let mut bytes = [0; 8];
    assert_eq!(observed.read(&mut bytes), Ok(None));
    assert!(observed.prefix.is_none() && observed.eof.is_none());
    observed.inner.input.push_back(0);
    observed.inner.read_advance = 3;
    assert_eq!(observed.read(&mut bytes), Ok(Some(1)));
    assert_eq!(bytes[0], 0);
    assert_eq!(
        observed.prefix,
        Some(fixture::ReadStamp {
            before: 1,
            after: 4,
            bytes: 1
        })
    );
    assert_eq!(observed.input, [0]);
    observed.inner.eof = true;
    assert_eq!(observed.read(&mut bytes), Ok(Some(0)));
    assert_eq!(
        observed.eof,
        Some(fixture::ReadStamp {
            before: 4,
            after: 4,
            bytes: 0
        })
    );
}
#[test]
fn native_child_transaction_checks_exact_typed_reply_and_no_retry() {
    struct Script {
        input: VecDeque<u8>,
        output: Vec<u8>,
    }
    impl Pipe for Script {
        fn now_ms(&self) -> u64 {
            1
        }
        fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
            let n = b.len().min(self.input.len()).min(5);
            for byte in &mut b[..n] {
                *byte = self.input.pop_front().unwrap();
            }
            Ok(Some(n))
        }
        fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
            let n = b.len().min(3);
            self.output.extend_from_slice(&b[..n]);
            Ok(Some(n))
        }
    }
    let mut p = Script {
        input: (0..7).flat_map(fixture::reply).collect(),
        output: Vec::new(),
    };
    let mut last = 1;
    for (i, request) in fixture::REQUESTS.iter().enumerate() {
        assert_eq!(
            transact(&mut p, request, 1000, &mut last),
            Ok(fixture::reply(i))
        );
    }
    assert_eq!(p.output, fixture::REQUESTS.concat());
    assert!(p.input.is_empty());
    let mut invalid = fixture::reply(0);
    invalid[4] = 1;
    let mut p = Script {
        input: invalid.into(),
        output: Vec::new(),
    };
    assert_eq!(
        transact(&mut p, &fixture::REQUESTS[0], 1000, &mut last),
        Err(-22)
    );
    assert_eq!(p.output, fixture::REQUESTS[0]);
}
#[test]
fn counted_link_delegates_actual_frame_and_counts_before_failed_send() {
    let (_, state) = opened();
    let sends = std::rc::Rc::new(std::cell::Cell::new(0));
    let mut link = fixture::CountedLink {
        inner: TestLink(state.clone()),
        sends: sends.clone(),
    };
    let frame = arp_reply();
    assert_eq!(link.send(&frame), Ok(()));
    state.borrow_mut().send_error = Some(-5);
    assert_eq!(link.send(&frame), Err(-5));
    assert_eq!(sends.get(), 2);
    assert_eq!(state.borrow().tx, [frame.clone(), frame]);
    assert_eq!(link.read(), state.borrow().reading);
}
#[test]
fn shared_post_io_and_terminal_clock_checks_refuse_expiry_rewind_overflow() {
    let mut last = 1;
    assert_eq!(fixture::clock(&mut last, 100, 99), Ok(()));
    assert!(fixture::clock(&mut last, 100, 100).is_err());
    assert!(fixture::clock(&mut last, 100, 98).is_err());
    assert_eq!(last, 99);
    assert!(fixture::before_frame(10, 1000, 259));
    assert!(!fixture::before_frame(10, 1000, 260));
    assert!(!fixture::before_frame(10, 200, 200));
    assert!(!fixture::before_frame(u64::MAX - 1, u64::MAX, u64::MAX - 1));
}
