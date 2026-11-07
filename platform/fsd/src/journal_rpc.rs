//! Journal storage over one exclusively handed-off FSD client channel.
//! The caller supplies a bounded request transport; no syscall/host mock is
//! embedded here, so tests exercise the real server dispatcher too.
use crate::{
    journal::Store,
    proto::{self, Frame, op},
};
use absd_fs::{Attr, Error, Kind, OpenFlags};
use alloc::vec::Vec;

/// Private logger/init lifecycle v1; shared golden in tests/fixtures.
pub const REATTACH_EXIT_STATUS: i32 = 75;
/// Bound a request by both its operation allowance and the caller's pass deadline.
pub fn bounded_request(
    frame: Vec<u8>,
    now: u64,
    deadline: u64,
    call: impl FnOnce(Vec<u8>, u64) -> Result<(i64, Vec<u8>), i64>,
) -> Result<(i64, Vec<u8>), i64> {
    if now >= deadline {
        return Err(-110);
    }
    // Opcode follows the entire framing header, including its sequence word.
    let allowance = match frame.get(proto::HEADER) {
        Some(&op::COMMIT) | Some(&op::LOGGER_BEGIN) => 1000,
        _ => 100,
    };
    call(frame, (deadline - now).min(allowance))
}

pub struct RpcStore<F> {
    call: F,
    reattach: bool,
}
impl<F: FnMut(Vec<u8>) -> Result<(i64, Vec<u8>), i64>> RpcStore<F> {
    pub fn new(call: F) -> Self {
        Self {
            call,
            reattach: false,
        }
    }
    fn request(&mut self, frame: Vec<u8>) -> Result<(u64, Vec<u8>), Error> {
        let opcode = frame.get(proto::HEADER).copied();
        if self.reattach && opcode != Some(op::LOGGER_BEGIN) {
            return Err(Error::Device(-110));
        }
        let (status, body) = match (self.call)(frame) {
            Ok(reply) => reply,
            Err(code) => {
                // An unknown OPEN/CLOSE may retain an unreachable server
                // handle. Only a new, exclusively owned BEGIN retires it.
                if matches!(opcode, Some(op::OPEN | op::CLOSE | op::LOGGER_BEGIN)) {
                    self.reattach = true;
                }
                return Err(error(code));
            }
        };
        if status == -24 {
            self.reattach = true;
        }
        if status < 0 {
            return Err(error(status));
        }
        Ok((status as u64, body))
    }
    pub fn needs_reattachment(&self) -> bool {
        self.reattach
    }
    pub fn begin(&mut self) -> Result<(), Error> {
        self.request(Frame::request(op::LOGGER_BEGIN).finish())?;
        self.reattach = false;
        Ok(())
    }
}
fn error(code: i64) -> Error {
    match code {
        -2 => Error::NotFound,
        -9 => Error::BadHandle,
        -13 => Error::Denied,
        -17 => Error::Exists,
        -22 => Error::Invalid,
        -28 => Error::NoSpace,
        -30 => Error::ReadOnlyFs,
        _ => Error::Device(code),
    }
}
impl<F: FnMut(Vec<u8>) -> Result<(i64, Vec<u8>), i64>> Store for RpcStore<F> {
    fn mkdir(&mut self, p: &[u8]) -> Result<(), Error> {
        self.request(Frame::request(op::MKDIR).bytes(p).finish())
            .map(|_| ())
    }
    fn open(&mut self, p: &[u8], f: OpenFlags) -> Result<u64, Error> {
        let flags = u32::from(f.read)
            | u32::from(f.write) * 2
            | u32::from(f.create) * 8
            | u32::from(f.create_new) * 16
            | u32::from(f.truncate) * 32;
        self.request(Frame::request(op::OPEN).u32(flags).bytes(p).finish())
            .map(|r| r.0)
    }
    fn close(&mut self, h: u64) -> Result<(), Error> {
        self.request(Frame::request(op::CLOSE).u64(h).finish())
            .map(|_| ())
    }
    fn fstat(&mut self, h: u64) -> Result<Attr, Error> {
        let (_, b) = self.request(Frame::request(op::FSTAT).u64(h).finish())?;
        if b.len() != proto::ATTR_BYTES {
            return Err(Error::Invalid);
        }
        let word = |i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let kind = match u32::from_le_bytes(b[..4].try_into().unwrap()) {
            1 => Kind::File,
            2 => Kind::Dir,
            _ => return Err(Error::Invalid),
        };
        let readonly = match u32::from_le_bytes(b[4..8].try_into().unwrap()) {
            0 => false,
            1 => true,
            _ => return Err(Error::Invalid),
        };
        Ok(Attr {
            kind,
            readonly,
            size: word(8),
            fs_id: word(16),
            serial: word(24),
            links: word(32).try_into().map_err(|_| Error::Invalid)?,
            mtime: word(40),
        })
    }
    fn read_at(&mut self, h: u64, o: u64, b: &mut [u8]) -> Result<usize, Error> {
        let mut filled = 0;
        while filled < b.len() {
            let n = (b.len() - filled).min(proto::MAX_IO);
            let (count, body) = self.request(
                Frame::request(op::READ_AT)
                    .u64(h)
                    .u64(o + filled as u64)
                    .u32(n as u32)
                    .finish(),
            )?;
            if count as usize != body.len() || body.len() > n {
                return Err(Error::Invalid);
            }
            b[filled..filled + body.len()].copy_from_slice(&body);
            filled += body.len();
            if body.len() < n {
                break;
            }
        }
        Ok(filled)
    }
    fn write_at(&mut self, h: u64, o: u64, b: &[u8]) -> Result<usize, Error> {
        if b.len() > proto::MAX_IO {
            return Err(Error::Invalid);
        }
        self.request(Frame::request(op::WRITE_AT).u64(h).u64(o).bytes(b).finish())
            .map(|r| r.0 as usize)
    }
    fn set_len(&mut self, h: u64, n: u64) -> Result<(), Error> {
        self.request(Frame::request(op::SET_LEN).u64(h).u64(n).finish())
            .map(|_| ())
    }
    fn rename(&mut self, a: &[u8], b: &[u8], n: bool) -> Result<(), Error> {
        self.request(
            Frame::request(op::RENAME)
                .u8(n as u8)
                .u16(a.len() as u16)
                .bytes(a)
                .bytes(b)
                .finish(),
        )
        .map(|_| ())
    }
    fn unlink(&mut self, p: &[u8]) -> Result<(), Error> {
        self.request(Frame::request(op::UNLINK).bytes(p).finish())
            .map(|_| ())
    }
    fn sync(&mut self) -> Result<(), Error> {
        self.request(Frame::request(op::COMMIT).finish())
            .map(|_| ())
    }
}
