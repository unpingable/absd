//! Host tests of the release record: the exact bytes, every malformation,
//! and every mismatch reason.

use alloc::string::String;
use alloc::vec::Vec;
use std::format;

use super::*;

fn record() -> Record {
    Record {
        release: b"2026.10.02-a".to_vec(),
        kernel_abi: KERNEL_ABI,
        fsd_protocol: FSD_PROTOCOL,
        fs_format: FS_FORMAT,
        app_abi: APP_ABI,
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Re-seals `body` (the six lines) with a correct check line.
fn sealed(body: &str) -> Vec<u8> {
    let digest = sha2::Sha256::digest(body.as_bytes());
    let mut hex = String::new();
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("{body}check={hex}\n").into_bytes()
}

#[test]
fn encoding_is_the_pinned_bytes_and_round_trips() {
    let bytes = encode(&record());
    let body = "absd-release 1\nrelease=2026.10.02-a\nkernel_abi=1\nfsd_protocol=2\nfs_format=2\napp_abi=1\n";
    assert_eq!(text(&bytes), text(&sealed(body)));
    assert_eq!(parse(&bytes), Ok(record()));
    assert_eq!(verify(&bytes, &record()), Ok(record()));
}

#[test]
fn compiled_identity_is_the_documented_generations() {
    assert_eq!((KERNEL_ABI, FSD_PROTOCOL, FS_FORMAT, APP_ABI), (1, 2, 2, 1));
    assert!(valid_id(RELEASE_ID.as_bytes()));
    if option_env!("ABSD_RELEASE_ID").is_none() {
        assert_eq!(RELEASE_ID, "dev");
    }
    let me = compiled();
    assert_eq!(me.release, RELEASE_ID.as_bytes());
    assert_eq!(parse(&encode(&me)), Ok(me));
}

#[test]
fn release_ids_follow_the_grammar() {
    for good in [&b"a"[..], b"dev", b"1.0-rc.2", &[b'z'; MAX_ID]] {
        assert!(valid_id(good), "{good:?}");
    }
    for bad in [
        &b""[..],
        b"A",
        b"a b",
        b"a/b",
        b"a_b",
        b"\xff",
        &[b'z'; MAX_ID + 1],
    ] {
        assert!(!valid_id(bad), "{bad:?}");
    }
}

#[test]
fn every_malformation_is_malformed_record() {
    let good = text(&encode(&record()));
    let body = "absd-release 1\nrelease=2026.10.02-a\nkernel_abi=1\nfsd_protocol=2\nfs_format=2\napp_abi=1\n";
    let mut cases: Vec<Vec<u8>> = Vec::new();
    // Framing: no final newline, a blank line after, CRLF, trailing space,
    // a second check line, an empty file, a non-UTF-8 byte.
    cases.push(good.trim_end_matches('\n').as_bytes().to_vec());
    cases.push(format!("{good}\n").into_bytes());
    cases.push(good.replace('\n', "\r\n").into_bytes());
    cases.push(sealed(
        &body.replace("release=2026.10.02-a\n", "release=2026.10.02-a \n"),
    ));
    let check_line = good.lines().last().unwrap();
    cases.push(format!("{good}{check_line}\n").into_bytes());
    cases.push(Vec::new());
    // Header, order, missing, extra, and unknown keys (each re-sealed, so
    // the check is not what refuses them).
    cases.push(sealed(&body.replace("absd-release 1", "absd-release 2")));
    cases.push(sealed(&body.replace("absd-release 1\n", "")));
    cases.push(sealed(
        "absd-release 1\nkernel_abi=1\nrelease=2026.10.02-a\nfsd_protocol=2\nfs_format=2\napp_abi=1\n",
    ));
    cases.push(sealed(&body.replace("app_abi=1\n", "")));
    cases.push(sealed(&format!("{body}extra=1\n")));
    cases.push(sealed(&body.replace("app_abi=1", "app-abi=1")));
    cases.push(sealed(
        &body.replace("\nfs_format=2\n", "\nfs_format = 2\n"),
    ));
    // Values: an id off the grammar, empty, too long; numbers signed, with
    // leading zeros, empty, out of range, not decimal.
    for (from, to) in [
        ("release=2026.10.02-a", "release=Release"),
        ("release=2026.10.02-a", "release="),
        ("kernel_abi=1", "kernel_abi=+1"),
        ("kernel_abi=1", "kernel_abi=01"),
        ("kernel_abi=1", "kernel_abi="),
        ("fsd_protocol=2", "fsd_protocol=4294967296"),
        ("fs_format=2", "fs_format=0x2"),
        ("app_abi=1", "app_abi=-1"),
    ] {
        cases.push(sealed(&body.replace(from, to)));
    }
    let long = format!("release={}", "a".repeat(MAX_ID + 1));
    cases.push(sealed(&body.replace("release=2026.10.02-a", &long)));
    // The check itself: not 64 lowercase hex digits.
    cases.push(
        good.replace(
            check_line,
            &check_line.to_uppercase().replace("CHECK=", "check="),
        )
        .into_bytes(),
    );
    cases.push(
        good.replace(check_line, &check_line[..check_line.len() - 1])
            .into_bytes(),
    );
    cases.push(good.replace(check_line, "check=").into_bytes());
    for case in cases {
        assert_eq!(
            parse(&case),
            Err(Refusal::MalformedRecord),
            "{:?}",
            text(&case)
        );
        assert_eq!(Refusal::MalformedRecord.reason(), "malformed_record");
    }
}

#[test]
fn a_changed_byte_is_a_check_mismatch() {
    let good = text(&encode(&record()));
    for (from, to) in [
        ("kernel_abi=1", "kernel_abi=7"),
        ("release=2026.10.02-a", "release=2026.10.02-b"),
        ("app_abi=1", "app_abi=2"),
    ] {
        let changed = good.replace(from, to).into_bytes();
        assert_eq!(parse(&changed), Err(Refusal::CheckMismatch), "{from}");
    }
    let last = good.len() - 2;
    let mut flipped = good.into_bytes();
    flipped[last] = if flipped[last] == b'0' { b'1' } else { b'0' };
    assert_eq!(parse(&flipped), Err(Refusal::CheckMismatch));
    assert_eq!(Refusal::CheckMismatch.reason(), "check_mismatch");
}

#[test]
fn each_field_has_its_own_mismatch_reason_in_record_order() {
    let mine = record();
    let cases: [(fn(&mut Record), Refusal, &str); 5] = [
        (
            |r| r.release = b"other".to_vec(),
            Refusal::ReleaseMismatch,
            "release_mismatch",
        ),
        (
            |r| r.kernel_abi = 9,
            Refusal::KernelAbiMismatch,
            "kernel_abi_mismatch",
        ),
        (
            |r| r.fsd_protocol = 1,
            Refusal::FsdProtocolMismatch,
            "fsd_protocol_mismatch",
        ),
        (
            |r| r.fs_format = 1,
            Refusal::FsFormatMismatch,
            "fs_format_mismatch",
        ),
        (
            |r| r.app_abi = 0,
            Refusal::AppAbiMismatch,
            "app_abi_mismatch",
        ),
    ];
    for (change, refusal, reason) in cases {
        let mut theirs = record();
        change(&mut theirs);
        assert_eq!(compare(&theirs, &mine), Err(refusal));
        assert_eq!(verify(&encode(&theirs), &mine), Err(refusal));
        assert_eq!(refusal.reason(), reason);
    }
    // Several differ: the first in record order is named.
    let mut theirs = record();
    theirs.app_abi = 5;
    theirs.kernel_abi = 5;
    assert_eq!(compare(&theirs, &mine), Err(Refusal::KernelAbiMismatch));
    assert_eq!(compare(&mine, &mine), Ok(()));
}

#[test]
fn the_selection_file_is_one_id_and_at_most_one_newline() {
    assert_eq!(parse_selected(b"2026.10.02-a\n"), Ok(&b"2026.10.02-a"[..]));
    assert_eq!(parse_selected(b"dev"), Ok(&b"dev"[..]));
    for bad in [
        &b""[..],
        b"\n",
        b"a\n\n",
        b"a\r\n",
        b"a b\n",
        b"A\n",
        b" a\n",
        b"../x\n",
    ] {
        assert_eq!(
            parse_selected(bad),
            Err(Refusal::MalformedSelected),
            "{bad:?}"
        );
    }
    assert_eq!(Refusal::MalformedSelected.reason(), "malformed_selected");
    assert_eq!(Refusal::NoSelectedRelease.reason(), "no_selected_release");
    assert_eq!(Refusal::NoReleaseTree.reason(), "no_release_tree");
}

#[test]
fn abi_refusal_line_needs_no_allocation() {
    let mut buffer = [0u8; ABI_LINE_BYTES];
    assert_eq!(
        abi_refusal_line(-38, &mut buffer),
        b"ABI REFUSED kernel=-38 required=1\n"
    );
    assert_eq!(
        abi_refusal_line(2, &mut buffer),
        b"ABI REFUSED kernel=2 required=1\n"
    );
    assert_eq!(
        abi_refusal_line(i64::MIN, &mut buffer),
        b"ABI REFUSED kernel=-9223372036854775808 required=1\n"
    );
}
