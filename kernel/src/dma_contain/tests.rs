extern crate std;
use super::*;
use std::string::{String, ToString};
use std::vec::Vec;

const AHCI: Bdf = Bdf {
    bus: 5,
    device: 0,
    function: 1,
};
const NIC: Bdf = Bdf {
    bus: 1,
    device: 0,
    function: 0,
};

#[test]
fn none_is_a_census_naming_no_driver() {
    let word = parse(b"none").unwrap();
    assert_eq!(
        word,
        Word {
            ahci: None,
            rtl8125: None
        }
    );
    assert!(word.is_census());
}

#[test]
fn named_drivers_parse_in_either_order() {
    let want = Word {
        ahci: Some(AHCI),
        rtl8125: Some(NIC),
    };
    assert_eq!(parse(b"ahci@05:00.1,rtl8125@01:00.0"), Ok(want));
    assert_eq!(parse(b"rtl8125@01:00.0,ahci@05:00.1"), Ok(want));
    assert!(!want.is_census());
}

#[test]
fn one_driver_alone_parses() {
    assert_eq!(
        parse(b"rtl8125@01:00.0"),
        Ok(Word {
            ahci: None,
            rtl8125: Some(NIC)
        })
    );
}

#[test]
fn each_malformed_word_has_its_own_refusal() {
    assert_eq!(parse(b""), Err(WordRefusal::Empty));
    assert_eq!(parse(b"ahci@05:00.1,"), Err(WordRefusal::UnknownDriver));
    assert_eq!(parse(b"nvme@05:00.0"), Err(WordRefusal::UnknownDriver));
    assert_eq!(parse(b"none,ahci@05:00.1"), Err(WordRefusal::UnknownDriver));
    assert_eq!(parse(b"ahci"), Err(WordRefusal::UnknownDriver));
    assert_eq!(parse(b"ahci@05:20.0"), Err(WordRefusal::Address));
    assert_eq!(parse(b"ahci@05:00.8"), Err(WordRefusal::Address));
    assert_eq!(parse(b"ahci@5:00.1"), Err(WordRefusal::Address));
    assert_eq!(parse(b"ahci@05:00"), Err(WordRefusal::Address));
    assert_eq!(parse(b"ahci@zz:00.1"), Err(WordRefusal::Address));
    assert_eq!(
        parse(b"ahci@05:00.1,ahci@05:00.2"),
        Err(WordRefusal::DuplicateDriver)
    );
    assert_eq!(
        parse(b"ahci@05:00.1,rtl8125@05:00.1"),
        Err(WordRefusal::SameFunction)
    );
}

fn with<'a>(present: &'a [&'a [u8]]) -> impl Fn(&[u8]) -> bool + 'a {
    move |word| present.contains(&word)
}

fn check(word: &Word, present: &[&[u8]]) -> Result<(), WordRefusal> {
    check_options(word, with(present), with(present))
}

/// A word in a position its consumer does not read has selected nothing.
#[test]
fn a_prerequisite_must_be_what_its_consumer_reads() {
    let ahci = parse(b"ahci@05:00.1").unwrap();
    assert_eq!(
        check_options(&ahci, with(&[b"ahci-disk="]), with(&[])),
        Err(WordRefusal::NeedsDisk)
    );
    let nic = parse(b"rtl8125@01:00.0").unwrap();
    assert_eq!(
        check_options(&nic, with(&[b"net-rtl8125", b"net"]), with(&[b"net"])),
        Err(WordRefusal::NeedsNetBackend)
    );
    assert_eq!(
        check_options(
            &nic,
            with(&[b"net-rtl8125", b"net"]),
            with(&[b"net-rtl8125"])
        ),
        Err(WordRefusal::NeedsNetProbe)
    );
}

#[test]
fn a_conflict_counts_wherever_it_appears() {
    let census = parse(b"none").unwrap();
    assert_eq!(
        check_options(&census, with(&[b"smp-cpus="]), with(&[])),
        Err(WordRefusal::Conflict)
    );
}

#[test]
fn modes_reaching_other_devices_conflict() {
    let census = parse(b"none").unwrap();
    for word in [
        b"smp-cpus=".as_slice(),
        b"smp-kernel-only",
        b"amdvi-enforce-test",
        b"amdvi-oracle=1",
        b"nvme-write=",
        b"whole-ram-test",
        b"ahci-census",
        b"native-install",
        b"install-consent=",
        b"i219-init",
        b"survey",
        b"rtl8125-probe",
        b"usb-keyboard",
        b"xhci-probe",
        b"net-i219",
    ] {
        assert_eq!(
            check(&census, &[word]),
            Err(WordRefusal::Conflict),
            "{}",
            String::from_utf8_lossy(word)
        );
    }
}

#[test]
fn named_drivers_need_the_options_that_start_them() {
    let ahci = parse(b"ahci@05:00.1").unwrap();
    assert_eq!(check(&ahci, &[]), Err(WordRefusal::NeedsDisk));
    assert_eq!(check(&ahci, &[b"ahci-disk="]), Ok(()));
    assert_eq!(check(&ahci, &[b"ahci-write="]), Ok(()));

    let nic = parse(b"rtl8125@01:00.0").unwrap();
    assert_eq!(check(&nic, &[]), Err(WordRefusal::NeedsNetBackend));
    assert_eq!(
        check(&nic, &[b"net-rtl8125"]),
        Err(WordRefusal::NeedsNetProbe)
    );
    assert_eq!(check(&nic, &[b"net-rtl8125", b"net"]), Ok(()));
    assert_eq!(check(&nic, &[b"net-rtl8125", b"net-probe"]), Ok(()));

    assert_eq!(check(&parse(b"none").unwrap(), &[]), Ok(()));
}

#[test]
fn a_census_refuses_disk_and_network_options() {
    let census = parse(b"none").unwrap();
    for word in [b"ahci-disk=".as_slice(), b"ahci-write=", b"net-rtl8125"] {
        assert_eq!(check(&census, &[word]), Err(WordRefusal::Conflict));
    }
}

/// A tripwire, not a proof: every boot-word-shaped byte string in main.rs must
/// be classified, so a new device-reaching word cannot slip into contain mode
/// unnoticed. Computed names would evade it.
#[test]
fn every_boot_word_in_main_is_classified() {
    let source = include_str!("../main.rs");
    let mut missing: Vec<String> = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find("b\"") {
        rest = &rest[at + 2..];
        let Some(end) = rest.find('"') else { break };
        let word = &rest[..end];
        rest = &rest[end + 1..];
        let shaped = word.len() >= 3
            && word
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'=');
        if !shaped {
            continue;
        }
        let bytes = word.as_bytes();
        if !COMPATIBLE_WORDS.contains(&bytes) && !REFUSED_WORDS.contains(&bytes) {
            missing.push(word.to_string());
        }
    }
    assert!(missing.is_empty(), "unclassified: {missing:?}");
}

#[test]
fn no_word_is_both_compatible_and_refused() {
    for word in COMPATIBLE_WORDS {
        assert!(!REFUSED_WORDS.contains(word));
    }
}

#[test]
fn the_check_needs_an_ahci_target() {
    let nic = parse(b"rtl8125@01:00.0").unwrap();
    assert_eq!(
        check(&nic, &[b"net-rtl8125", b"net", b"dma-contain-check"]),
        Err(WordRefusal::CheckNeedsDisk)
    );
    let census = parse(b"none").unwrap();
    assert_eq!(
        check(&census, &[b"dma-contain-check"]),
        Err(WordRefusal::CheckNeedsDisk)
    );
    let ahci = parse(b"ahci@05:00.1").unwrap();
    assert_eq!(check(&ahci, &[b"ahci-disk=", b"dma-contain-check"]), Ok(()));
}
