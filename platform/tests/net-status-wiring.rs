//! The actual SSH diagnostics module with a local NetWatch input fixture.
//! This covers its projection/wiring, not NIC reads or the runtime loop.
extern crate self as absd_net;

#[derive(Clone, Copy)]
pub enum Carrier {
    Unknown,
    Down,
    Up,
}
pub struct NetWatch {
    carrier: Carrier,
    disabled: Option<bool>,
}
impl NetWatch {
    pub fn carrier(&self) -> Carrier {
        self.carrier
    }
    pub fn disabled_reading(&self) -> Option<bool> {
        self.disabled
    }
    pub fn disabled(&self) -> bool {
        self.disabled == Some(true)
    }
}
mod etc {
    pub struct Network {
        pub address: [u8; 4],
        pub prefix_len: u8,
        pub gateway: Option<[u8; 4]>,
    }
}
mod oplog {
    std::thread_local! { static NOTICES: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) }; }
    pub fn notice(text: &str) {
        NOTICES.with(|v| v.borrow_mut().push(text.into()));
    }
    pub fn take() -> Vec<String> {
        NOTICES.with(|v| std::mem::take(&mut *v.borrow_mut()))
    }
}
#[path = "../ssh/src/net_diagnostics.rs"]
mod diagnostics;
use absd_fsd::net_status::{Carrier as SampleCarrier, Listener, Record};

fn owner() -> diagnostics::Diagnostics {
    oplog::take();
    diagnostics::Diagnostics::new(
        *b"0123456789abcdef0123456789abcdef",
        7,
        etc::Network {
            address: [10, 0, 2, 15],
            prefix_len: 24,
            gateway: Some([10, 0, 2, 2]),
        },
        false,
        22,
    )
}
fn directory(name: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("absd-net-wiring-{}-{}", name, std::process::id()));
    std::fs::create_dir(&path).unwrap();
    path
}
#[test]
fn draining_precedes_disabled_fault_in_actual_diagnostics_projection() {
    let dir = directory("draining");
    let path = dir.join("sample");
    let mut diagnostics = owner();
    let watch = NetWatch {
        carrier: Carrier::Down,
        disabled: Some(true),
    };
    diagnostics.fresh_to(&path, &watch, 1000, 1001, true, true);
    let record = Record::parse(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(record.listener, Listener::Draining);
    assert_eq!(record.carrier, SampleCarrier::Down);
    assert_eq!(record.disabled, Some(true));
    assert!(oplog::take().is_empty());
    drop(diagnostics);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(dir).unwrap();
}
#[test]
fn actual_diagnostics_forwards_device_changed_and_keeps_notice_across_skipped_pass() {
    let dir = directory("changed");
    let parent = dir.join("missing");
    let path = parent.join("sample");
    let watch = NetWatch {
        carrier: Carrier::Up,
        disabled: Some(false),
    };
    let mut diagnostics = owner();
    diagnostics.fresh_to(&path, &watch, 1000, 1000, false, false); // failed open: first notice
    diagnostics.fresh_to(&path, &watch, 1001, 1001, false, false); // skipped: must not clear notice
    diagnostics.fresh_to(&path, &watch, 1002, 1002, true, false); // forwarded change forces failed retry
    assert_eq!(oplog::take().len(), 1);
    std::fs::create_dir(&parent).unwrap();
    diagnostics.fresh_to(&path, &watch, 1003, 1003, true, false); // forwarded change forces success
    assert_eq!(
        Record::parse(&std::fs::read(&path).unwrap()).unwrap().end,
        1003
    );
    diagnostics.fresh_to(&path, &watch, 1004, 1004, false, false);
    assert_eq!(
        Record::parse(&std::fs::read(&path).unwrap()).unwrap().end,
        1003
    );
    assert!(oplog::take().is_empty());
    // An invalid module-boundary fixture exercises a new error after success.
    // The real NetWatch never returns this inconsistent carrier/flag pair.
    let malformed = NetWatch {
        carrier: Carrier::Up,
        disabled: None,
    };
    diagnostics.fresh_to(&path, &malformed, 1005, 1005, true, false);
    assert_eq!(oplog::take().len(), 1); // Ok(true) cleared the previous streak
    assert_eq!(
        Record::parse(&std::fs::read(&path).unwrap()).unwrap().end,
        1003
    );
    drop(diagnostics);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(parent).unwrap();
    std::fs::remove_dir(dir).unwrap();
}
