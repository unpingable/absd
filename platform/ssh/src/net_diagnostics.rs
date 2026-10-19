//! Static SSH owner's bounded projection. Existing NetWatch supplies only
//! fresh device observations; no protocol, peer, counter or config authority.
use absd_fsd::net_status::{Carrier, Listener, Origin, Record};
use absd_net::NetWatch;

#[path = "../../src/net_status_file.rs"]
mod file;

pub struct Diagnostics {
    record: Record,
    file: file::SampleFile,
    failure_reported: bool,
}

impl Diagnostics {
    pub fn new(
        boot: [u8; 32],
        recovery: u64,
        network: crate::etc::Network,
        explicit: bool,
        port: u16,
    ) -> Self {
        Self {
            record: Record {
                boot,
                recovery,
                start: 0,
                end: 0,
                address: network.address,
                prefix: network.prefix_len,
                gateway: network.gateway,
                carrier: Carrier::Unknown,
                disabled: None,
                origin: if explicit {
                    Origin::File
                } else {
                    Origin::Defaults
                },
                listener: Listener::Listening,
                port,
            },
            file: file::SampleFile::default(),
            failure_reported: false,
        }
    }

    /// Caller must have performed a fresh NetWatch read inside start..=end.
    pub fn fresh(&mut self, watch: &NetWatch, start: u64, end: u64, changed: bool, draining: bool) {
        self.fresh_to(
            std::path::Path::new(absd_fsd::net_status::PATH),
            watch,
            start,
            end,
            changed,
            draining,
        );
    }

    /// The native caller fixes the owner path; host wiring cases use an
    /// isolated local file without acquiring any device or service authority.
    pub(crate) fn fresh_to(
        &mut self,
        path: &std::path::Path,
        watch: &NetWatch,
        start: u64,
        end: u64,
        changed: bool,
        draining: bool,
    ) {
        self.record.start = start;
        self.record.end = end;
        self.record.carrier = match watch.carrier() {
            absd_net::Carrier::Unknown => Carrier::Unknown,
            absd_net::Carrier::Down => Carrier::Down,
            absd_net::Carrier::Up => Carrier::Up,
        };
        self.record.disabled = watch.disabled_reading();
        self.record.listener = if draining {
            Listener::Draining
        } else if watch.disabled() {
            Listener::Fault
        } else {
            Listener::Listening
        };
        match self.file.publish_fresh_at(path, &self.record, changed) {
            Ok(true) => self.failure_reported = false,
            Ok(false) => {}
            Err(error) if !self.failure_reported => {
                self.failure_reported = true;
                crate::oplog::notice(&format!("sshd: network diagnostics unavailable: {error}"));
            }
            Err(_) => {}
        }
    }
}
