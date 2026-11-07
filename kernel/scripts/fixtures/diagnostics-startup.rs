//! Compile the actual kernel user startup encoder/parser against only an
//! unused I/O type shim; the checked bytes are shared with platform broker.
#[derive(Debug)]
pub enum Error {
    Invalid,
    BrokenPipe,
}
#[derive(Clone, Copy)]
pub struct Pipe;
impl Pipe {
    pub fn from_raw(_: u64) -> Self {
        Self
    }
    pub fn read_once(self, _: &mut [u8]) -> Result<usize, Error> {
        Err(Error::Invalid)
    }
    pub fn write_all(self, _: &[u8]) -> Result<(), Error> {
        Err(Error::Invalid)
    }
}
#[path = "../../user/src/broker.rs"]
mod broker;
#[test]
fn diagnostics_role_has_identical_wire_bytes_in_kernel_and_platform() {
    let mut bytes = [0; 128];
    let n = broker::startup_record(
        &mut bytes,
        &[(1, 1), (2, 2), (3, 3), (broker::ROLE_DIAGNOSTICS, 4)],
        &[0, 0],
    )
    .unwrap();
    let hex = include_str!("../../tests/fixtures/diagnostics-startup-v1.hex").trim();
    let expected: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(&bytes[..n], expected);
    let startup = broker::Startup::parse(&bytes[..n], 6).unwrap();
    assert_eq!(startup.role(broker::ROLE_DIAGNOSTICS, 0), Some(4));
    assert_eq!(startup.role(broker::ROLE_STDOUT, 0), Some(2));
}

#[test]
fn clock_owner_role_matches_the_shared_exact_owner_vector() {
    let mut bytes = [0; 128];
    let n = broker::startup_record(
        &mut bytes,
        &[(1, 1), (2, 2), (3, 3), (broker::ROLE_CLOCK_OWNER, 4)],
        &[0, 0],
    ).unwrap();
    let hex = include_str!("../../tests/fixtures/clock-owner-startup-v1.hex").trim();
    let expected: Vec<u8> = (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
    assert_eq!(&bytes[..n], expected);
    let startup = broker::Startup::parse(&bytes[..n], 6).unwrap();
    assert_eq!(startup.role(broker::ROLE_CLOCK_OWNER, 0), Some(4));
    assert_eq!(startup.role(broker::ROLE_DIAGNOSTICS, 0), None);
}

#[test]
fn local_terminal_encoder_matches_the_platform_consumer_golden() {
    let mut bytes = [0; 128];
    let n = broker::startup_record(&mut bytes,
        &[(broker::ROLE_STDIN, 1), (broker::ROLE_LOCAL_TERMINAL, 2), (broker::ROLE_STEP, 3)],
        &[0, 0]).unwrap();
    let hex = include_str!("../../user/tests/vectors/local-terminal-startup.hex").trim();
    let expected: Vec<u8> = (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16).unwrap()).collect();
    assert_eq!(&bytes[..n], expected);
    let parsed = broker::Startup::parse(&bytes[..n], 5).unwrap();
    assert_eq!(parsed.role(broker::ROLE_LOCAL_TERMINAL, 0), Some(2));
    assert_eq!(parsed.role(broker::ROLE_STEP, 0), Some(3));
}
