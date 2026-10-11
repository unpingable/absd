//! Host tests: every startup-record refusal the parser names, request and
//! reply round trips, and reply demultiplexing across slots and fragments.

use std::vec::Vec;

use super::*;

fn record(roles: &[(u8, u8)], args: &[&[u8]]) -> Vec<u8> {
    let mut bytes = STARTUP_MAGIC.to_vec();
    bytes.extend_from_slice(&(roles.len() as u16).to_le_bytes());
    for &(role, index) in roles {
        bytes.push(role);
        bytes.push(index);
    }
    bytes.extend_from_slice(&(args.len() as u16).to_le_bytes());
    for arg in args {
        bytes.extend_from_slice(&(arg.len() as u16).to_le_bytes());
        bytes.extend_from_slice(arg);
    }
    bytes
}

/// The worker vector of the specification with `k` slots:
/// [startup, input, block, step, request, reply, k x (in, out, err), console].
fn worker_roles(k: u8) -> Vec<(u8, u8)> {
    let mut roles = std::vec![
        (role::STDIN, 1),
        (role::BLOCK, 2),
        (role::STEP, 3),
        (role::REQUEST, 4),
        (role::REPLY, 5),
    ];
    for slot in 0..k {
        roles.push((role::SLOT_STDIN, 6 + 3 * slot));
        roles.push((role::SLOT_STDOUT, 7 + 3 * slot));
        roles.push((role::SLOT_STDERR, 8 + 3 * slot));
    }
    roles
}

#[test]
fn worker_record_parses() {
    let bytes = record(&worker_roles(8), &[]);
    let startup = parse_startup(&bytes, 6 + 24 + 1).unwrap();
    assert_eq!(startup.stdin, Some(1));
    assert_eq!(startup.block, Some(2));
    assert_eq!(startup.step, Some(3));
    assert_eq!(startup.request, Some(4));
    assert_eq!(startup.reply, Some(5));
    assert_eq!(startup.stderr, None);
    assert_eq!(startup.slot_count, 8);
    assert_eq!(startup.slots[7], SlotIndexes { stdin: 27, stdout: 28, stderr: 29 });
    assert_eq!(startup.argc, 0);
    assert_eq!(startup.args().count(), 0);
}

#[test]
fn child_record_parses_with_argv() {
    // [startup, stdin, stderr, block, console]
    let bytes = record(
        &[(role::STDIN, 1), (role::STDERR, 2), (role::BLOCK, 3)],
        &[b"7", b"", b"two words"],
    );
    let startup = parse_startup(&bytes, 5).unwrap();
    assert_eq!(startup.stderr, Some(2));
    assert_eq!(startup.slot_count, 0);
    let args: Vec<&[u8]> = startup.args().collect();
    assert_eq!(args, [&b"7"[..], b"", b"two words"]);
}

#[test]
fn child_record_with_stdout_role() {
    // [startup, stdin, stdout, stderr, console]: the stdout role names the
    // pipe the console already is.
    let bytes = record(&[(role::STDIN, 1), (role::STDOUT, 2), (role::STDERR, 3)], &[b"x"]);
    let startup = parse_startup(&bytes, 5).unwrap();
    assert_eq!(startup.stdout, Some(2));
    assert_eq!(startup.stderr, Some(3));
    assert!(parse_startup(&record(&[(role::STDOUT, 1), (role::STDOUT, 2), (role::STDERR, 3)], &[]), 5).is_err());
}

fn with_env(mut bytes: Vec<u8>, entries: &[&[u8]]) -> Vec<u8> {
    bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for entry in entries {
        bytes.extend_from_slice(&(entry.len() as u16).to_le_bytes());
        bytes.extend_from_slice(entry);
    }
    bytes
}

#[test]
fn environment_section() {
    let roles = [(role::STDIN, 1), (role::STDOUT, 2), (role::STDERR, 3)];
    let base = record(&roles, &[b"a"]);
    assert_eq!(parse_startup(&base, 5).unwrap().env().count(), 0);
    let bytes = with_env(base.clone(), &[b"PULSE_LOAD_SUPPORT_CONFIG=/etc/p.toml", b"EMPTY=", b"EQ=a=b"]);
    let startup = parse_startup(&bytes, 5).unwrap();
    let env: Vec<(&[u8], &[u8])> = startup.env().map(split_env).collect();
    assert_eq!(env, [
        (&b"PULSE_LOAD_SUPPORT_CONFIG"[..], &b"/etc/p.toml"[..]),
        (b"EMPTY", b""),
        (b"EQ", b"a=b"),
    ]);
    assert_eq!(startup.args().collect::<Vec<_>>(), [&b"a"[..]]);
    // An empty section is fine; a truncated count is not.
    assert!(parse_startup(&with_env(base.clone(), &[]), 5).is_ok());
    let mut half = base.clone();
    half.push(0);
    assert!(parse_startup(&half, 5).is_err());
    for bad in [&b"NOEQUALS"[..], b"=value", b"K=\0", b""] {
        assert!(parse_startup(&with_env(base.clone(), &[bad]), 5).is_err(), "{bad:?}");
    }
    assert!(parse_startup(&with_env(base.clone(), &[b"K=1", b"K=2"]), 5).is_err());
    let long = [b'x'; MAX_ENV_ENTRY + 1];
    let mut entry = b"K=".to_vec();
    entry.extend_from_slice(&long[..MAX_ENV_ENTRY - 2]);
    assert!(parse_startup(&with_env(base.clone(), &[&entry]), 5).is_ok());
    entry.push(b'x');
    assert!(parse_startup(&with_env(base.clone(), &[&entry]), 5).is_err());
    let keys: Vec<Vec<u8>> = (0..33).map(|i| std::format!("K{i}=v").into_bytes()).collect();
    let refs: Vec<&[u8]> = keys.iter().map(|k| &k[..]).collect();
    assert!(parse_startup(&with_env(base.clone(), &refs[..32]), 5).is_ok());
    assert!(parse_startup(&with_env(base.clone(), &refs), 5).is_err());
    let mut trailing = with_env(base, &[b"K=v"]);
    trailing.push(0);
    assert!(parse_startup(&trailing, 5).is_err());
}

#[test]
fn slot_roles_may_interleave_but_pair_in_order() {
    let roles = [
        (role::STDIN, 1),
        (role::REQUEST, 2),
        (role::REPLY, 3),
        (role::SLOT_STDERR, 4),
        (role::SLOT_STDIN, 5),
        (role::SLOT_STDOUT, 6),
        (role::SLOT_STDIN, 7),
        (role::SLOT_STDOUT, 8),
        (role::SLOT_STDERR, 9),
    ];
    let bytes = record(&roles, &[]);
    let startup = parse_startup(&bytes, 11).unwrap();
    assert_eq!(startup.slots[0], SlotIndexes { stdin: 5, stdout: 6, stderr: 4 });
    assert_eq!(startup.slots[1], SlotIndexes { stdin: 7, stdout: 8, stderr: 9 });
}

#[test]
fn record_refusals() {
    let good = [(role::STDIN, 1), (role::STDERR, 2), (role::BLOCK, 3)];
    assert!(parse_startup(&record(&good, &[]), 5).is_ok());
    // Too few handles for the record shape.
    assert!(parse_startup(&record(&good[..2], &[]), 4).is_err());
    // Wrong magic, truncated, trailing.
    let mut bytes = record(&good, &[]);
    bytes[7] = b'2';
    assert!(parse_startup(&bytes, 5).is_err());
    let bytes = record(&good, &[b"abc"]);
    for cut in 0..bytes.len() {
        assert!(parse_startup(&bytes[..cut], 5).is_err(), "cut {cut}");
    }
    let mut bytes = record(&good, &[]);
    bytes.push(0);
    assert!(parse_startup(&bytes, 5).is_err());
    // Index 0 (startup), the console, out of range, duplicate index.
    assert!(parse_startup(&record(&[(role::STDIN, 0), (role::STDERR, 2), (role::BLOCK, 3)], &[]), 5).is_err());
    assert!(parse_startup(&record(&[(role::STDIN, 1), (role::STDERR, 2), (role::BLOCK, 4)], &[]), 5).is_err());
    assert!(parse_startup(&record(&[(role::STDIN, 1), (role::STDERR, 2), (role::BLOCK, 9)], &[]), 5).is_err());
    assert!(parse_startup(&record(&[(role::STDIN, 1), (role::STDERR, 1), (role::BLOCK, 3)], &[]), 5).is_err());
    // A position left unnamed.
    assert!(parse_startup(&record(&good[..2], &[]), 5).is_err());
    // Unknown roles.
    for unknown in [0u8, 13, 255] {
        assert!(parse_startup(&record(&[(role::STDIN, 1), (unknown, 2), (role::BLOCK, 3)], &[]), 5).is_err());
    }
    // The NIC, with or without a broker channel, at most once.
    let nic = [(role::STDIN, 1), (role::BLOCK, 2), (role::STEP, 3), (role::NIC, 4)];
    let bytes = record(&nic, &[]);
    let startup = parse_startup(&bytes, 6).unwrap();
    assert_eq!((startup.nic, startup.request, startup.slot_count), (Some(4), None, 0));
    let mut roles = worker_roles(1);
    roles.push((role::NIC, 9));
    assert_eq!(parse_startup(&record(&roles, &[]), 11).unwrap().nic, Some(9));
    assert!(parse_startup(&record(&[(role::NIC, 1), (role::NIC, 2), (role::BLOCK, 3)], &[]), 5).is_err());
    assert_eq!(parse_startup(&record(&good, &[]), 5).unwrap().nic, None);
    // The machine handle, at most once.
    let machine = [(role::STDIN, 1), (role::BLOCK, 2), (role::STEP, 3), (role::MACHINE, 4)];
    assert_eq!(parse_startup(&record(&machine, &[]), 6).unwrap().machine, Some(4));
    assert_eq!(parse_startup(&record(&good, &[]), 5).unwrap().machine, None);
    assert!(parse_startup(&record(&[(role::MACHINE, 1), (role::MACHINE, 2), (role::BLOCK, 3)], &[]), 5).is_err());
    // A single role twice.
    assert!(parse_startup(&record(&[(role::STDIN, 1), (role::STDIN, 2), (role::BLOCK, 3)], &[]), 5).is_err());
    // Request without reply, and slots without the channel.
    assert!(parse_startup(&record(&[(role::STDIN, 1), (role::REQUEST, 2), (role::BLOCK, 3)], &[]), 5).is_err());
    let slots_only = [(role::SLOT_STDIN, 1), (role::SLOT_STDOUT, 2), (role::SLOT_STDERR, 3)];
    assert!(parse_startup(&record(&slots_only, &[]), 5).is_err());
    // Incomplete triple.
    let mut roles = worker_roles(2);
    roles.pop();
    assert!(parse_startup(&record(&roles, &[]), 6 + 6).is_err());
    // More than K slots.
    assert!(parse_startup(&record(&worker_roles(9), &[]), 6 + 27 + 1).is_err());
    // argc bound, NUL inside an argument, short argument.
    let many: Vec<&[u8]> = (0..33).map(|_| &b"x"[..]).collect();
    assert!(parse_startup(&record(&good, &many[..32]), 5).is_ok());
    assert!(parse_startup(&record(&good, &many), 5).is_err());
    assert!(parse_startup(&record(&good, &[b"a\0b"]), 5).is_err());
    let mut bytes = record(&good, &[b"abc"]);
    let at = bytes.len() - 5;
    bytes[at] = 4;
    assert!(parse_startup(&bytes, 5).is_err());
    // Oversized record.
    let mut bytes = record(&good, &[]);
    bytes.resize(MAX_STARTUP + 1, 0);
    assert!(parse_startup(&bytes, 5).is_err());
}

#[test]
fn request_round_trip_and_bounds() {
    let mut out = [0u8; MAX_REQUEST];
    let args: [&[u8]; 2] = [b"--config", b"/etc/x"];
    let length = encode_request(3, b"/owners/nq", args, &mut out).unwrap();
    let request = decode_request(&out[..length]).unwrap();
    assert_eq!(request.slot, 3);
    assert_eq!(request.path, b"/owners/nq");
    assert_eq!(request.args().collect::<Vec<_>>(), args);
    assert_eq!(&out[..10], b"ABSDBR01\x01\x03");

    let empty: [&[u8]; 0] = [];
    assert_eq!(encode_request(0, b"", empty, &mut out), Err(RequestError::Invalid));
    assert_eq!(encode_request(0, b"a\0", empty, &mut out), Err(RequestError::Invalid));
    assert_eq!(encode_request(0, b"a", [&b"\0"[..]], &mut out), Err(RequestError::Invalid));
    let many: Vec<&[u8]> = (0..33).map(|_| &b"x"[..]).collect();
    assert!(encode_request(0, b"a", many[..32].iter().copied(), &mut out).is_ok());
    assert_eq!(
        encode_request(0, b"a", many.iter().copied(), &mut out),
        Err(RequestError::TooManyArguments)
    );
    let big = [b'x'; 2100];
    assert_eq!(
        encode_request(0, b"a", [&big[..], &big[..]], &mut out),
        Err(RequestError::TooLarge)
    );
    // Exactly 4096 bytes is accepted: 8 + 2 + (2 + 1) + 2 + (2 + n) = 4096.
    let n = MAX_REQUEST - 17;
    let exact = std::vec![b'y'; n];
    assert_eq!(encode_request(0, b"a", [&exact[..]], &mut out), Ok(MAX_REQUEST));
    let mut small = [0u8; 16];
    assert_eq!(encode_request(0, b"abc", empty, &mut small), Err(RequestError::TooLarge));

    let length = encode_request(1, b"p", empty, &mut out).unwrap();
    let mut trailing = out[..length].to_vec();
    trailing.push(0);
    assert!(decode_request(&trailing).is_err());
}

#[test]
fn reply_codec() {
    let reply = Reply { kind: reply::EXITED, slot: 2, code: 0, value: (-1006i64) as u64 };
    let bytes = encode_reply(reply);
    assert_eq!(decode_reply(&bytes), Ok(reply));
    let mut bad = bytes;
    bad[10] = 1;
    assert!(decode_reply(&bad).is_err());
    let mut bad = bytes;
    bad[8] = 4;
    assert!(decode_reply(&bad).is_err());
    let mut bad = bytes;
    bad[0] = b'X';
    assert!(decode_reply(&bad).is_err());
}

fn frame(kind: u8, slot: u8, code: u32, value: u64) -> [u8; REPLY_BYTES] {
    encode_reply(Reply { kind, slot, code, value })
}

#[test]
fn book_demultiplexes_interleaved_fragmented_replies() {
    let mut book = Book::new(3);
    assert_eq!(book.next_unspent(), Some(0));
    book.mark_requested(0).unwrap();
    assert_eq!(book.take_spawn(0), Ok(None));
    let mut stream = Vec::new();
    stream.extend_from_slice(&frame(reply::STARTED, 0, 0, 40));
    book.feed(&stream[..5]).unwrap();
    assert_eq!(book.take_spawn(0), Ok(None));
    book.feed(&stream[5..]).unwrap();
    assert_eq!(book.take_spawn(0), Ok(Some(Ok(40))));
    assert_eq!(book.next_unspent(), Some(1));

    book.mark_requested(1).unwrap();
    let mut stream = Vec::new();
    stream.extend_from_slice(&frame(reply::STARTED, 1, 0, 41));
    stream.extend_from_slice(&frame(reply::EXITED, 1, 0, 7));
    stream.extend_from_slice(&frame(reply::EXITED, 0, 0, (-1i64) as u64));
    for byte in &stream {
        book.feed(core::slice::from_ref(byte)).unwrap();
    }
    assert_eq!(book.exit_value(0), Ok(Some(-1)));
    assert_eq!(book.exit_value(1), Ok(Some(7)));
    assert_eq!(book.take_spawn(1), Ok(Some(Ok(41))));
}

#[test]
fn book_refusal_spends_nothing_except_unavailable() {
    let mut book = Book::new(2);
    book.mark_requested(0).unwrap();
    book.feed(&frame(reply::REFUSED, 0, refusal::NOT_PERMITTED, 0)).unwrap();
    assert_eq!(book.take_spawn(0), Ok(Some(Err(refusal::NOT_PERMITTED))));
    assert_eq!(book.next_unspent(), Some(0));
    book.mark_requested(0).unwrap();
    book.feed(&frame(reply::REFUSED, 0, refusal::SLOT_UNAVAILABLE, 0)).unwrap();
    assert_eq!(book.take_spawn(0), Ok(Some(Err(refusal::SLOT_UNAVAILABLE))));
    assert_eq!(book.next_unspent(), Some(1));
    assert_eq!(book.mark_requested(0), Err(BookError::NotPending));
}

#[test]
fn book_poisons_on_contradiction() {
    let cases: [[u8; REPLY_BYTES]; 5] = [
        frame(reply::STARTED, 1, 0, 1),                // unrequested slot
        frame(reply::EXITED, 0, 0, 0),                 // exit before start
        frame(reply::STARTED, 5, 0, 1),                // beyond the slots
        frame(reply::REFUSED, 0, 0, 0),                // refusal without a code
        *b"ABSDBP01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
    ];
    for (case, bytes) in cases.iter().enumerate() {
        let mut book = Book::new(2);
        book.mark_requested(0).unwrap();
        if case == 4 {
            // Well formed; then a second STARTED for the same slot.
            book.feed(bytes).unwrap();
            assert_eq!(book.feed(bytes), Err(BookError::Protocol), "case {case}");
        } else {
            assert_eq!(book.feed(bytes), Err(BookError::Protocol), "case {case}");
        }
        assert!(book.is_poisoned());
        assert_eq!(book.take_spawn(0), Err(BookError::Protocol));
        assert_eq!(book.next_unspent().is_some(), true);
        assert_eq!(book.mark_requested(1), Err(BookError::Protocol));
    }
}

fn with_cwd(mut bytes: Vec<u8>, cwd: &[u8]) -> Vec<u8> {
    bytes.extend_from_slice(&(cwd.len() as u16).to_le_bytes());
    bytes.extend_from_slice(cwd);
    bytes
}

#[test]
fn working_directory_section() {
    let roles = [(role::STDIN, 1), (role::STDOUT, 2), (role::STDERR, 3)];
    let base = with_env(record(&roles, &[b"a"]), &[b"K=v"]);
    assert_eq!(parse_startup(&base, 5).unwrap().cwd, b"");
    let bytes = with_cwd(base.clone(), b"/bin");
    let startup = parse_startup(&bytes, 5).unwrap();
    assert_eq!(startup.cwd, b"/bin");
    assert_eq!(startup.env().count(), 1);
    assert_eq!(parse_startup(&with_cwd(base.clone(), b"/"), 5).unwrap().cwd, b"/");
    for bad in [&b""[..], b"bin", b"/bin/", b"//", b"/a/./b", b"/a/../b", b"/a\0", b"/.."] {
        assert!(parse_startup(&with_cwd(base.clone(), bad), 5).is_err(), "{bad:?}");
    }
    let mut long = std::vec![b'/'];
    long.extend(std::iter::repeat_n(b'x', MAX_CWD - 1));
    assert!(parse_startup(&with_cwd(base.clone(), &long), 5).is_ok());
    long.push(b'x');
    assert!(parse_startup(&with_cwd(base.clone(), &long), 5).is_err());
    let mut trailing = with_cwd(base.clone(), b"/bin");
    trailing.push(0);
    assert!(parse_startup(&trailing, 5).is_err());
    // The program name follows the working directory.
    let named = with_cwd(with_cwd(base.clone(), b"/bin"), b"ls");
    assert_eq!(parse_startup(&named, 5).unwrap().name, b"ls");
    assert!(parse_startup(&with_cwd(with_cwd(base.clone(), b"/bin"), b""), 5).is_err());
    assert!(parse_startup(&with_cwd(with_cwd(base, b"/bin"), b"l\0s"), 5).is_err());
}

#[test]
fn filesystem_role() {
    // [startup, stdin, stdout, stderr, fs, console]
    let roles = [(role::STDIN, 1), (role::STDOUT, 2), (role::STDERR, 3), (role::FS, 4)];
    let bytes = record(&roles, &[]);
    let startup = parse_startup(&bytes, 6).unwrap();
    assert_eq!(startup.fs, Some(4));
    assert_eq!(startup.block, None);
    let both = [(role::STDIN, 1), (role::FS, 2), (role::BLOCK, 3)];
    assert!(parse_startup(&record(&both, &[]), 5).is_err());
    let twice = [(role::FS, 1), (role::FS, 2), (role::STDERR, 3)];
    assert!(parse_startup(&record(&twice, &[]), 5).is_err());
}

#[test]
fn encoded_startup_round_trips() {
    let roles = [(role::STDIN, 1), (role::STDOUT, 2), (role::STDERR, 3), (role::FS, 4)];
    let mut out = [0u8; MAX_STARTUP];
    let args: [&[u8]; 2] = [b"-l", b"two words"];
    let env: [&[u8]; 2] = [b"HOME=/", b"TERM=dumb"];
    let used = encode_startup(&roles, args, env, b"/bin", b"/bin/ls", 6, &mut out).unwrap();
    let startup = parse_startup(&out[..used], 6).unwrap();
    assert_eq!(startup.args().collect::<Vec<_>>(), args);
    assert_eq!(startup.env().collect::<Vec<_>>(), env);
    assert_eq!(startup.cwd, b"/bin");
    assert_eq!(startup.name, b"/bin/ls");
    assert_eq!(startup.fs, Some(4));
    assert_eq!(encode_startup(&roles, [], [], b"", b"ls", 6, &mut out), Err(RequestError::Invalid));
    // No working directory: the section is left out.
    let used = encode_startup(&roles, [], [], b"", b"", 6, &mut out).unwrap();
    assert_eq!(parse_startup(&out[..used], 6).unwrap().cwd, b"");
    // What a child would refuse is refused here.
    assert_eq!(encode_startup(&roles, [], [&b"NOEQUALS"[..]], b"", b"", 6, &mut out), Err(RequestError::Invalid));
    assert_eq!(encode_startup(&roles, [], [], b"relative", b"", 6, &mut out), Err(RequestError::Invalid));
    assert_eq!(encode_startup(&roles, [], [], b"/", b"", 5, &mut out), Err(RequestError::Invalid));
    assert_eq!(encode_startup(&roles, [&b"a\0"[..]], [], b"/", b"", 6, &mut out), Err(RequestError::Invalid));
    let many: Vec<&[u8]> = (0..33).map(|_| &b"x"[..]).collect();
    assert_eq!(encode_startup(&roles, many.iter().copied(), [], b"/", b"", 6, &mut out), Err(RequestError::TooManyArguments));
    let big = std::vec![b'x'; 3000];
    let three: [&[u8]; 3] = [&big, &big, &big];
    assert_eq!(encode_startup(&roles, three, [], b"/", b"", 6, &mut out), Err(RequestError::TooLarge));
}

#[test]
fn file_server_channels_pair_in_order() {
    // Server: [startup, block, (request, reply) x 3, console].
    let mut roles = std::vec![(role::BLOCK, 1)];
    for channel in 0..3u8 {
        roles.push((role::FS_REQUEST, 2 + 2 * channel));
        roles.push((role::FS_REPLY, 3 + 2 * channel));
    }
    let bytes = record(&roles, &[]);
    let startup = parse_startup(&bytes, 9).unwrap();
    assert_eq!(startup.channel_count, 3);
    assert_eq!(startup.channels[2], ChannelIndexes { request: 6, reply: 7 });
    assert_eq!(startup.block, Some(1));
    // Client: requests first, then replies; still paired by order.
    let roles = [
        (role::STDIN, 1),
        (role::FS_REQUEST, 2),
        (role::FS_REQUEST, 3),
        (role::FS_REPLY, 4),
        (role::FS_REPLY, 5),
    ];
    let bytes = record(&roles, &[]);
    let startup = parse_startup(&bytes, 7).unwrap();
    assert_eq!(startup.channels[0], ChannelIndexes { request: 2, reply: 4 });
    assert_eq!(startup.channels[1], ChannelIndexes { request: 3, reply: 5 });
    // An unpaired end, or a channel beside a read-only view, is refused.
    let unpaired = [(role::STDIN, 1), (role::FS_REQUEST, 2), (role::FS_REQUEST, 3), (role::FS_REPLY, 4)];
    assert!(parse_startup(&record(&unpaired, &[]), 6).is_err());
    let with_view = [(role::FS, 1), (role::FS_REQUEST, 2), (role::FS_REPLY, 3)];
    assert!(parse_startup(&record(&with_view, &[]), 5).is_err());
    // At most MAX_CHANNELS.
    let mut many = std::vec::Vec::new();
    for channel in 0..=MAX_CHANNELS as u8 {
        many.push((role::FS_REQUEST, 1 + 2 * channel));
        many.push((role::FS_REPLY, 2 + 2 * channel));
    }
    assert!(parse_startup(&record(&many, &[]), 2 * MAX_CHANNELS + 4).is_err());
}

#[test]
fn session_control_roles_come_together() {
    // A shell sshd started: [startup, stdin, stdout, stderr, events, requests, console].
    let roles = [
        (role::STDIN, 1),
        (role::STDOUT, 2),
        (role::STDERR, 3),
        (role::SESSION_EVENTS, 4),
        (role::SESSION_REQUESTS, 5),
    ];
    let bytes = record(&roles, &[]);
    let startup = parse_startup(&bytes, 7).unwrap();
    assert_eq!((startup.session_events, startup.session_requests), (Some(4), Some(5)));
    // Absent: neither.
    let plain = record(&roles[..3], &[]);
    let startup = parse_startup(&plain, 5).unwrap();
    assert_eq!((startup.session_events, startup.session_requests), (None, None));
    // One without the other, or either twice, is refused.
    assert!(parse_startup(&record(&roles[..4], &[]), 6).is_err());
    let lone = [(role::STDIN, 1), (role::SESSION_REQUESTS, 2)];
    assert!(parse_startup(&record(&lone, &[]), 4).is_err());
    let twice = [(role::SESSION_EVENTS, 1), (role::SESSION_EVENTS, 2), (role::SESSION_REQUESTS, 3)];
    assert!(parse_startup(&record(&twice, &[]), 5).is_err());
}
