use super::*;

fn empty() -> DiagnosticFailure<'static> {
    DiagnosticFailure {
        outcome: "CERTIFICATE",
        phase: "FENCED",
        tls_error_code: Some("UNKNOWN_ISSUER"),
        authenticated: false,
        http: [0; 3],
        output: None,
    }
}

#[test]
fn shared_golden_vectors_match_actual_formatter() {
    let vectors = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/native-https-document/failure-v1.tsv"),
    )
    .unwrap();
    for row in vectors.lines().skip(1) {
        let f: Vec<_> = row.split('\t').collect();
        assert_eq!(f.len(), 13);
        let output = if f[7] == "NONE" {
            assert!(f[7..12].iter().all(|value| *value == "NONE"));
            None
        } else {
            Some(DiagnosticOutput {
                queued: f[7] == "1",
                attempts: f[8].parse().unwrap(),
                native_bytes_accepted: f[9].parse().unwrap(),
                queue_drained: f[10] == "1",
                error: (f[11] != "NONE").then_some(f[11]),
            })
        };
        let report = DiagnosticFailure {
            outcome: f[0],
            phase: f[1],
            tls_error_code: (f[2] != "NONE").then_some(f[2]),
            authenticated: f[3] == "1",
            http: [
                f[4].parse().unwrap(),
                f[5].parse().unwrap(),
                f[6].parse().unwrap(),
            ],
            output,
        };
        assert_eq!(failure_diagnostic(&report), format!("{}\n", f[12]));
    }
}

#[test]
fn every_closed_code_and_maximum_integer_width_fit_the_bound() {
    let mut maximum = 0;
    for outcome in DIAGNOSTIC_OUTCOMES {
        for phase in DIAGNOSTIC_PHASES {
            for tls in DIAGNOSTIC_TLS_CODES {
                let report = DiagnosticFailure {
                    outcome,
                    phase,
                    tls_error_code: Some(tls),
                    authenticated: true,
                    http: [usize::MAX; 3],
                    output: Some(DiagnosticOutput {
                        queued: true,
                        attempts: usize::MAX,
                        native_bytes_accepted: u64::MAX,
                        queue_drained: true,
                        error: Some("CLOSE_INCOMPLETE"),
                    }),
                };
                let text = failure_diagnostic(&report);
                maximum = maximum.max(text.len());
                assert!(text.len() <= MAX_FAILURE_LINE_BYTES);
                assert!(text.is_ascii());
                assert_eq!(text.bytes().filter(|b| *b == b'\n').count(), 1);
            }
        }
    }
    assert_eq!(maximum, 349);
}

#[test]
fn unknown_strings_are_closed_other_without_any_input_bytes() {
    let text = "peer-supplied\nsecret=\t".repeat(1024);
    let report = DiagnosticFailure {
        outcome: &text,
        phase: &text,
        tls_error_code: Some(&text),
        output: Some(DiagnosticOutput {
            queued: false,
            attempts: 0,
            native_bytes_accepted: 0,
            queue_drained: false,
            error: Some(&text),
        }),
        ..empty()
    };
    let result = failure_diagnostic(&report);
    for field in ["outcome", "phase", "tls_error_code", "error"] {
        assert!(result.contains(&format!("{field}=OTHER")));
    }
    assert!(!result.contains("secret"));
    assert!(result.len() <= MAX_FAILURE_LINE_BYTES);
    assert_eq!(result.lines().count(), 1);
}

#[test]
fn absence_is_distinct_from_present_zero_and_missing_error() {
    let absent = failure_diagnostic(&empty());
    assert!(absent.ends_with(
        "queued=NONE attempts=NONE native_bytes_accepted=NONE queue_drained=NONE error=NONE\n"
    ));
    let present = failure_diagnostic(&DiagnosticFailure {
        output: Some(DiagnosticOutput {
            queued: false,
            attempts: 0,
            native_bytes_accepted: 0,
            queue_drained: false,
            error: None,
        }),
        ..empty()
    });
    assert!(
        present
            .ends_with("queued=0 attempts=0 native_bytes_accepted=0 queue_drained=0 error=NONE\n")
    );
}
