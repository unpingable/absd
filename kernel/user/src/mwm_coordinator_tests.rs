use std::sync::Mutex;

extern crate self as absd_user;

mod api {
    use std::sync::Mutex;

    pub static CLOSES: Mutex<Vec<u64>> = Mutex::new(Vec::new());
    pub static EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    pub static FAILURE: Mutex<u8> = Mutex::new(0);
    static OPENS: Mutex<u64> = Mutex::new(0);
    static DUPLICATES: Mutex<u64> = Mutex::new(0);

    pub fn reset(failure: u8) {
        CLOSES.lock().unwrap().clear();
        EVENTS.lock().unwrap().clear();
        *FAILURE.lock().unwrap() = failure;
        *OPENS.lock().unwrap() = 0;
        *DUPLICATES.lock().unwrap() = 0;
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Child(pub u64);
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Console(pub u64);
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Pipe(pub u64);
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Error {
        Again,
        Invalid,
    }
    impl Error {
        pub fn from_code(code: i64) -> Self {
            if code == -11 { Self::Again } else { Self::Invalid }
        }
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Outcome {
        Exited(i32),
    }
    pub struct SpawnHandleCopy;
    impl SpawnHandleCopy {
        pub fn new(_: u64, _: u64) -> Self { Self }
        pub fn console(_: u64, _: u64) -> Self { Self }
    }
    pub const RIGHT_READ: u64 = 1;
    pub const RIGHT_WRITE: u64 = 2;
    pub const SPAWN_NO_SPAWN: u64 = 1;
    pub mod program {
        pub const EXTERNAL_WORKLOAD: u64 = 30;
    }
    pub struct ResourceCensus {
        pub processes: u64,
    }
    pub mod mwm_protocol {
        use super::{Console, Error, Pipe};
        #[derive(Clone, Copy)]
        pub struct DisplayInfo {
            pub generation: u64,
            pub high_water: u64,
        }
        pub fn wait_ack(_: Console, _: u64) -> Result<(), &'static str> { Ok(()) }
        pub fn parse_info(_: &[u8; 48]) -> Result<DisplayInfo, &'static str> {
            Ok(DisplayInfo { generation: 2, high_water: 0 })
        }
        pub fn read_timeout(_: Pipe, _: &mut [u8], _: u64) -> Result<usize, Error> { Ok(0) }
    }

    impl Console {
        pub fn raw(self) -> u64 { self.0 }
        pub fn write_str(self, text: &str) -> Result<(), Error> {
            EVENTS.lock().unwrap().push(text.to_owned());
            Ok(())
        }
    }
    impl Pipe {
        pub fn create() -> Result<Self, Error> { Ok(Self(10)) }
        pub fn from_raw(raw: u64) -> Self { Self(raw) }
        pub fn raw(self) -> u64 { self.0 }
        pub fn read_timeout(self, buffer: &mut [u8], _: u64) -> Result<usize, Error> {
            EVENTS.lock().unwrap().push("readiness".to_owned());
            let message = b"MWM READY\n";
            buffer[..message.len()].copy_from_slice(message);
            Ok(message.len())
        }
    }

    pub fn duplicate(_: u64, _: u64) -> Result<u64, Error> {
        let mut index = DUPLICATES.lock().unwrap();
        *index += 1;
        if *FAILURE.lock().unwrap() == 1 && *index == 2 {
            return Err(Error::Invalid);
        }
        Ok(10 + *index)
    }
    pub fn close(handle: u64) -> Result<(), Error> {
        CLOSES.lock().unwrap().push(handle);
        Ok(())
    }
    pub fn spawn_many_copy(_: u64, _: &[SpawnHandleCopy]) -> Result<Child, Error> {
        EVENTS.lock().unwrap().push("spawn".to_owned());
        if *FAILURE.lock().unwrap() == 2 { Err(Error::Invalid) } else { Ok(Child(42)) }
    }
    pub fn kill(_: Child) -> Result<(), Error> {
        EVENTS.lock().unwrap().push("kill".to_owned());
        Ok(())
    }
    pub fn wait(_: Option<Child>) -> Result<Outcome, Error> { Ok(Outcome::Exited(0)) }
    pub fn wait_timeout(_: Option<Child>, _: u64) -> Result<Outcome, Error> { Ok(Outcome::Exited(0)) }
    pub fn resource_census() -> Result<ResourceCensus, Error> { Ok(ResourceCensus { processes: 1 }) }
    pub fn time() -> u64 { 0 }
    pub unsafe fn syscall3(number: u64, _: u64, _: u64, _: u64) -> i64 {
        match number {
            0x7fd0 => {
                let mut opens = OPENS.lock().unwrap();
                *opens += 1;
                match *opens {
                    1 => 4,
                    2 => {
                        EVENTS.lock().unwrap().push("second-open".to_owned());
                        -11
                    }
                    _ => 20,
                }
            }
            0x7fd1 => 0,
            _ => -22,
        }
    }
}

pub use api::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[path = "mwm_coordinator.rs"]
mod coordinator;

#[test]
fn partial_spawn_failures_close_every_parent_copy() {
    let _guard = TEST_LOCK.lock().unwrap();
    for (failure, writer) in [(1, None), (2, Some(12))] {
        absd_user::reset(failure);
        assert!(coordinator::run(absd_user::Console(1)).is_err());
        let closes = absd_user::CLOSES.lock().unwrap().clone();
        for handle in [4, 10, 11] {
            assert!(closes.contains(&handle), "missing close {handle} in {closes:?} after failure {failure}");
        }
        if let Some(handle) = writer {
            assert!(closes.contains(&handle), "missing writer close in {closes:?}");
        }
    }
}

#[test]
fn second_open_follows_readiness_and_precedes_kill() {
    let _guard = TEST_LOCK.lock().unwrap();
    absd_user::reset(0);
    coordinator::run(absd_user::Console(1)).unwrap();
    let events = absd_user::EVENTS.lock().unwrap();
    let position = |name: &str| events.iter().position(|event| event == name).unwrap();
    assert!(position("readiness") < position("second-open"), "events: {events:?}");
    assert!(position("second-open") < position("kill"), "events: {events:?}");
}
