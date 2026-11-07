// The harness imports actual kernel production logging and the production
// Collector. Only unused authorization bindings, acquisition syscalls and the
// block-device transport are substituted; there is no authorization claim.
extern crate self as absd_runtime;
use absd_fs::{Device, Error, Fs, SECTOR};
use absd_fsd::{
    Inbox, PipeState, Server, Taken,
    journal::{self, Record},
    journal_rpc::RpcStore,
    proto::{self, Reader},
};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
#[allow(dead_code)]
mod handle {
    pub const RIGHT_READ: u8 = 1;
    pub const RIGHT_WRITE: u8 = 2;
    #[derive(Clone, Copy)]
    pub enum Object {
        Diagnostics,
        Console,
        Other,
    }
    #[derive(Debug)]
    pub enum HandleError {
        Rights,
    }
    pub struct Handle {
        pub object: Object,
        pub rights: u8,
    }
    pub struct HandleTable;
    impl HandleTable {
        pub fn diagnostics_readable(&self) -> bool {
            false
        }
        pub fn console_rights(&self) -> u8 {
            0
        }
        pub fn lookup(&self, _: u64) -> Result<Handle, HandleError> {
            Err(HandleError::Rights)
        }
    }
}
mod process {
    pub const KERNEL_PARENT: u64 = u64::MAX;
}
mod program {
    pub const INIT: u8 = 1;
}
static PRODUCER: kernel_producer::Log = kernel_producer::Log::new();
pub static NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(2000);
pub fn ticks() -> u64 {
    NOW.load(std::sync::atomic::Ordering::Relaxed)
}
pub fn wall_clock_seconds() -> Result<u64, i64> {
    Err(-1)
}
pub mod kernel_log {
    pub use crate::wire::*;
    pub fn read(cursor: &mut Cursor) -> Result<Read, i64> {
        let actual = crate::PRODUCER.read(cursor.0)?.encode();
        let read = decode(&actual)?;
        cursor.0 = read.next;
        Ok(read)
    }
}
#[derive(Clone)]
struct Disk(Rc<RefCell<BTreeMap<u64, [u8; SECTOR]>>>);
impl Device for Disk {
    fn sectors(&self) -> u64 {
        16384
    }
    fn read(&mut self, n: u64, b: &mut [u8; SECTOR]) -> Result<(), Error> {
        *b = self.0.borrow().get(&n).copied().unwrap_or([0; SECTOR]);
        Ok(())
    }
    fn write(&mut self, n: u64, b: &[u8; SECTOR]) -> Result<(), Error> {
        self.0.borrow_mut().insert(n, *b);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
fn request(server: &mut Server<Disk>, frame: Vec<u8>) -> (i64, Vec<u8>) {
    let mut input = Inbox::new();
    input.push(&frame);
    let Taken::Frame { seq, body } = input.take() else {
        panic!("real request frame rejected")
    };
    let mut reply = server.dispatch(
        6,
        &body,
        &|_| {
            Some(PipeState {
                request_available: 0,
                request_writers: 1,
                reply_available: 0,
                reply_readers: 1,
            })
        },
        2000,
    );
    proto::stamp_seq(&mut reply, seq);
    let mut output = Inbox::new();
    output.push(&reply);
    let Taken::Frame {
        seq: returned,
        body,
    } = output.take()
    else {
        panic!("real reply frame rejected")
    };
    assert_eq!(returned, seq);
    let mut reader = Reader(&body);
    (reader.i64().unwrap(), reader.rest().to_vec())
}
fn service(service: u64, pid: u64, text: &[u8]) {
    service_stream(service, pid, 2, text);
}
fn service_stream(service: u64, pid: u64, stream: u64, text: &[u8]) {
    let mut request = [0; 296];
    for (at, value) in [
        (0, 1),
        (8, pid),
        (16, service),
        (24, stream),
        (32, text.len() as u64),
    ] {
        request[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    request[40..40 + text.len()].copy_from_slice(text);
    let record = kernel_producer::service_request(&request, 0).unwrap();
    assert!(PRODUCER.emit(
        record.source,
        record.severity,
        Some(1000),
        &record.message[..record.len],
        0
    ));
}
