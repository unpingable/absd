use crate::{
    Config, ExecMode,
    conn::Command,
    document::{Lease, next_port, peer},
};

fn admitted(command: &Command, config: &Config, terminal: bool) -> std::io::Result<bool> {
    let argv = config.argv(command).map_err(std::io::Error::other)?;
    crate::document::admitted(command, &argv, config, terminal)
}

fn config() -> Config {
    let mut config = Config::defaults();
    config.exec_mode = ExecMode::Argv;
    config
}
fn command() -> String {
    "/bin/https-document --boot 0123456789abcdef0123456789abcdef --pit-ms 123 --rtc 456 --utc-ms 456000 --uncertainty 1000".into()
}
fn exec(text: impl Into<String>) -> Command {
    Command::Exec(text.into())
}

#[test]
fn exact_direct_attestation_is_admitted() {
    assert!(admitted(&exec(command()), &config(), false).unwrap());
}
#[test]
fn sample_never_requests_network_authority() {
    for terminal in [false, true] {
        for mode in [ExecMode::Argv, ExecMode::Shell] {
            let mut config = config();
            config.exec_mode = mode;
            assert!(!admitted(&exec("/bin/https-document --sample"), &config, terminal).unwrap());
        }
    }
}
#[test]
fn ordinary_commands_and_shell_remain_unselected() {
    for command in [
        Command::Shell,
        exec("echo ok"),
        exec("https-document --sample"),
    ] {
        assert!(!admitted(&command, &config(), false).unwrap());
    }
}
#[test]
fn pty_and_shell_mode_cannot_issue_document_grants() {
    assert!(admitted(&exec(command()), &config(), true).is_err());
    let mut shell = config();
    shell.exec_mode = ExecMode::Shell;
    assert!(admitted(&exec(command()), &shell, false).is_err());
}
#[test]
fn shell_syntax_and_non_space_separators_refuse() {
    for suffix in [" | cat", "; true", " > /tmp/f", " &", "\n", "\t"] {
        assert!(admitted(&exec(format!("{}{suffix}", command())), &config(), false).is_err());
    }
}
#[test]
fn unknown_duplicate_extra_and_parent_expiry_arguments_refuse() {
    for text in [
        command().replace("--rtc", "--pit-ms"),
        command().replace("--rtc", "--unknown"),
        format!("{} --grant-expiry 999", command()),
        format!("{} extra", command()),
        "/bin/https-document".into(),
        "/bin/https-document --sample extra".into(),
    ] {
        assert!(admitted(&exec(text), &config(), false).is_err());
    }
}
#[test]
fn attestation_integer_boundaries_are_canonical() {
    for value in ["0", "18446744073709551615"] {
        assert!(
            admitted(
                &exec(command().replace("--pit-ms 123", &format!("--pit-ms {value}"))),
                &config(),
                false
            )
            .unwrap()
        );
    }
    for value in ["00", "0123", "+123", "-1", "1.0", "18446744073709551616"] {
        assert!(
            admitted(
                &exec(command().replace("--pit-ms 123", &format!("--pit-ms {value}"))),
                &config(),
                false
            )
            .is_err()
        );
    }
}
#[test]
fn boot_identity_requires_exact_lowercase_hex() {
    for value in [
        "0123456789ABCDEF0123456789abcdef",
        "0123456789abcdef",
        "g123456789abcdef0123456789abcdef",
    ] {
        assert!(
            admitted(
                &exec(command().replace("0123456789abcdef0123456789abcdef", value)),
                &config(),
                false
            )
            .is_err()
        );
    }
}
#[test]
fn command_length_is_bounded_before_admission() {
    assert!(
        admitted(
            &exec(format!("{}{}", command(), " ".repeat(257))),
            &config(),
            false
        )
        .is_err()
    );
}
#[test]
fn peer_is_first_line_only_and_port_boundaries_are_exact() {
    for port in [1, 65535] {
        assert_eq!(
            peer(format!("peer=192.0.2.1:{port}\nname=example.test\n").as_bytes()).unwrap(),
            ([192, 0, 2, 1], port)
        );
    }
    assert!(peer(b"name=example.test\npeer=192.0.2.1:443\n").is_err());
}
#[test]
fn peer_rejects_noncanonical_and_unbounded_input() {
    for text in [
        "peer=192.000.2.1:443",
        "peer=192.0.2.1:0443",
        "peer=192.0.2.1:0",
        "peer=192.0.2.1:65536",
        "peer=example.test:443",
        "peer=[::1]:443",
        "peer=192.0.2.1:443\r\n",
        " peer=192.0.2.1:443",
        "peer=192.0.2.1:+443",
    ] {
        assert!(peer(text.as_bytes()).is_err(), "{text}");
    }
    assert!(peer(&[b'x'; 4097]).is_err());
    assert!(peer(b"peer=192.0.2.1:443\n\xff").is_err());
}
#[test]
fn original_expiry_is_exclusive_and_cannot_be_renewed() {
    let mut lease = Lease::new(100, 15100);
    assert!(lease.observe(15099, true));
    assert!(!lease.observe(15100, true));
    assert!(!lease.observe(101, true));
}
#[test]
fn cancellation_link_refusal_and_clock_regression_are_sticky() {
    let mut cancelled = Lease::new(100, 15100);
    assert!(!cancelled.observe(101, false));
    assert!(!cancelled.observe(102, true));
    let mut rewind = Lease::new(100, 15100);
    assert!(rewind.observe(101, true));
    assert!(!rewind.observe(100, true));
    assert!(!rewind.observe(102, true));
}

#[test]
fn resolved_document_aliases_refuse_caller_expiry_and_attestation() {
    for path in [
        "https-document",
        "/bin//https-document",
        "/bin/./https-document",
        "bin/https-document",
        "/bin/../bin/https-document",
        "///bin/https-document/",
    ] {
        for text in [
            command().replacen("/bin/https-document", path, 1),
            format!(
                "{} --grant-expiry 15100",
                command().replacen("/bin/https-document", path, 1)
            ),
        ] {
            assert!(admitted(&exec(text), &config(), false).is_err(), "{path}");
        }
        assert!(!admitted(&exec(format!("{path} --sample")), &config(), false).unwrap());
    }
}
#[test]
fn shell_resolution_cannot_send_the_reserved_program_to_ordinary_stdio() {
    for path in [
        "https-document",
        "/bin//https-document",
        "/bin/./https-document",
    ] {
        let mut shell = config();
        shell.exec_mode = ExecMode::Shell;
        assert!(
            admitted(
                &exec(command().replacen("/bin/https-document", path, 1)),
                &shell,
                false
            )
            .is_err()
        );
        assert!(
            admitted(
                &exec(format!(
                    "{} | cat",
                    command().replacen("/bin/https-document", path, 1)
                )),
                &config(),
                false
            )
            .is_err()
        );
    }
}
#[test]
fn unrelated_configured_program_name_is_not_reserved() {
    let mut config = config();
    config.bin_dir = "/tools".into();
    assert!(!admitted(&exec("https-document other arguments"), &config, false).unwrap());
}
#[test]
fn issuer_ephemeral_cursor_advances_and_wraps_within_range() {
    let mut cursor = 0;
    assert_eq!(next_port(&mut cursor), 49152);
    assert_eq!(next_port(&mut cursor), 49153);
    cursor = 16383;
    assert_eq!(next_port(&mut cursor), 65535);
    assert_eq!(next_port(&mut cursor), 49152);
    cursor = u16::MAX;
    assert_eq!(next_port(&mut cursor), 65535);
    assert_eq!(next_port(&mut cursor), 49152);
}
