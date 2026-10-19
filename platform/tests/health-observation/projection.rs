use absd_fsd::{log::Generation, version::Refusal};
use health_observation::{Issue, Sample, recovery, render, version_issue};
use std::io::ErrorKind;

const BOOT: &str = "00112233445566778899aabbccddeeff";
fn sample() -> Sample {
    Sample {
        start: 100,
        end: 106,
        ticks: 102,
        pid: Some(17),
        boot: Ok([
            0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255,
        ]),
        release: Ok(b"absd-20261017.1".to_vec()),
        recovery: Ok(Generation {
            seq: 9,
            streak: 2,
            previous: "failed",
        }),
    }
}
fn log(seq: &str, boot: &str) -> Vec<u8> {
    format!("0 fsd: started: boot {boot}, release dev\n1 fsd: FSD RECOVERY seq={seq} streak=2 previous=failed\n").into_bytes()
}

#[test]
fn source_refusals_and_rendered_samples() {
    let mut output = Vec::new();
    let mut collect = |s: Sample, expected: i32| {
        let (text, status) = render(s).unwrap();
        assert_eq!(status, expected);
        output.push(format!("{text}\n"));
    };
    collect(sample(), 0);
    let mut s = sample();
    s.start = u64::MAX - 1;
    s.ticks = u64::MAX;
    s.end = u64::MAX;
    s.recovery.as_mut().unwrap().seq = 9007199254740993;
    collect(s, 0);
    let mut s = sample();
    s.boot = Err(-95);
    collect(s, 1);
    let mut s = sample();
    s.pid = None;
    collect(s, 0);
    for (refusal, expected) in [
        (Refusal::NoAnswer, Issue::unavailable("no_answer")),
        (
            Refusal::NoServer(-13),
            Issue {
                availability: "denied",
                reason: "fsd_refused",
            },
        ),
        (
            Refusal::Refused(-1),
            Issue {
                availability: "denied",
                reason: "fsd_refused",
            },
        ),
        (
            Refusal::Refused(-95),
            Issue {
                availability: "unsupported",
                reason: "unsupported",
            },
        ),
        (Refusal::NoServer(-32), Issue::unavailable("io_error")),
        (Refusal::Refused(-5), Issue::unavailable("fsd_refused")),
        (Refusal::Malformed, Issue::malformed("malformed")),
        (
            Refusal::Protocol { server: 99 },
            Issue::malformed("protocol_mismatch"),
        ),
        (
            Refusal::Release {
                server: b"other".to_vec(),
            },
            Issue::malformed("release_mismatch"),
        ),
    ] {
        assert_eq!(version_issue(refusal), expected);
        let mut s = sample();
        s.release = Err(expected);
        s.recovery = Err(expected);
        collect(s, 1);
    }
    for bytes in [vec![0xff], vec![b'x'; 65], b"UPPER".to_vec(), vec![]] {
        let mut s = sample();
        s.release = Ok(bytes);
        collect(s, 1);
    }
    for (current, rotated, reason) in [
        (
            Err(ErrorKind::NotFound),
            Ok(vec![]),
            "recovery_not_retained",
        ),
        (Err(ErrorKind::PermissionDenied), Ok(vec![]), "fsd_refused"),
        (
            Ok(log("9", BOOT)),
            Err(ErrorKind::PermissionDenied),
            "fsd_refused",
        ),
        (Ok(log("9", BOOT)), Err(ErrorKind::Other), "io_error"),
        (Ok(log("bad", BOOT)), Ok(vec![]), "recovery_malformed"),
        (
            Ok(log("9", "ffffffffffffffffffffffffffffffff")),
            Ok(vec![]),
            "recovery_not_retained",
        ),
        (Ok(vec![]), Ok(vec![]), "recovery_not_retained"),
    ] {
        let r = recovery(BOOT, current, rotated);
        assert_eq!(r.as_ref().unwrap_err().reason, reason);
        let mut s = sample();
        s.recovery = r;
        collect(s, 1);
    }
    for (current, rotated) in [
        (Ok(log("9", BOOT)), Err(ErrorKind::NotFound)),
        (Ok(vec![]), Ok(log("9", BOOT))),
    ] {
        let mut s = sample();
        s.recovery = recovery(BOOT, current, rotated);
        collect(s, 0);
    }
    let mut s = sample();
    s.release = Err(Issue::unavailable("fsd_absent"));
    s.recovery = Err(Issue::unavailable("fsd_absent"));
    collect(s, 1);
    // Every actual output goes through the independently written named validator.
    std::fs::write(
        std::env::var("ABSD_HEALTH_RENDERED_OUTPUT").unwrap(),
        output.concat(),
    )
    .unwrap();
}

#[test]
fn interval_refuses_instead_of_inventing_order() {
    let mut s = sample();
    s.end = 99;
    assert!(render(s).is_err());
    let mut s = sample();
    s.ticks = 99;
    assert!(render(s).is_err());
    let mut s = sample();
    s.ticks = 107;
    assert!(render(s).is_err());
}

#[test]
fn bounded_two_boot_one_rotation_model() {
    // Each writer history appends a start and a record, rotating at one
    // boundary. Collection reads current first and rotated at the same or
    // a later state, matching the actual collector's order. Old boot A and
    // live boot B have different sequences so an incorrect join is visible.
    let old_boot = "ffffffffffffffffffffffffffffffff";
    let old = log("3", old_boot);
    let start = format!("0 fsd: started: boot {BOOT}, release dev\n").into_bytes();
    let record = b"1 fsd: FSD RECOVERY seq=9 streak=2 previous=failed\n".to_vec();
    let mut combinations = 0;
    let mut successes = 0;
    for boundary in 0..=2 {
        let mut current = old.clone();
        let mut rotated = Vec::new();
        let mut states = vec![(current.clone(), rotated.clone())];
        for (step, line) in [start.clone(), record.clone(), Vec::new()]
            .into_iter()
            .enumerate()
        {
            if step == boundary {
                rotated = std::mem::take(&mut current);
                states.push((current.clone(), rotated.clone()));
            }
            current.extend(line);
            states.push((current.clone(), rotated.clone()));
        }
        let (current, rotated) = states.last().unwrap();
        let stable = recovery(BOOT, Ok(current.clone()), Ok(rotated.clone()))
            .expect("the complete retained B summary must be found at every rotation boundary");
        assert_eq!(stable.seq, 9);
        for i in 0..states.len() {
            for j in i..states.len() {
                let result = recovery(BOOT, Ok(states[i].0.clone()), Ok(states[j].1.clone()));
                match result {
                    Ok(g) => {
                        successes += 1;
                        assert_eq!(
                            g.seq, 9,
                            "rotation boundary={boundary} current={i} rotated={j}"
                        );
                        assert_eq!(g.previous, "failed");
                    }
                    Err(issue) => assert_eq!(issue, Issue::unavailable("recovery_not_retained")),
                }
                combinations += 1;
            }
        }
    }
    assert_eq!(combinations, 45);
    // Hand-enumerated complete spans: 3 before-start, 3 between-lines,
    // and 10 after-record acquisitions. Reject-all cannot satisfy this.
    assert_eq!(successes, 16);
    // Does not model arbitrary content mutation, more than one rotation,
    // process replacement within one boot, or a commit/durability property.
}
