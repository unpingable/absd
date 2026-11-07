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
fn terminal_role_matches_platform_startup_vector() {
    let expected = include_bytes!("../../tests/fixtures/terminal-startup.bin");
    let mut bytes = [0; 128];
    let n = broker::startup_record(
        &mut bytes,
        &[(1, 1), (2, 2), (3, 3), (broker::ROLE_TERMINAL, 4)],
        &expected[18..],
    ).unwrap();
    assert_eq!(&bytes[..n], expected);
    // The kernel's own startup consumer does not read the platform's cwd
    // and argv0 trailer. Its role table is shared; test that consumer using
    // its actual supported empty-argv grammar instead.
    let mut kernel_record = expected[..18].to_vec();
    kernel_record.extend_from_slice(&[0, 0]);
    let startup = broker::Startup::parse(&kernel_record, 6).unwrap();
    assert_eq!(startup.role(broker::ROLE_TERMINAL, 0), Some(4));
}
