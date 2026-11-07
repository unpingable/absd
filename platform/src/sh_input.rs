//! Interactive input must leave bytes after the command line in the inherited
//! pipe for its foreground child. StdinLock has a second read-ahead buffer, so
//! putting a small BufReader around that lock would still steal child input.
use std::io::{self, BufRead, BufReader, Read};

unsafe extern "C" {
    fn __absd_std_read(bytes: *mut u8, length: usize) -> isize;
}

pub struct RawStdin;

impl Read for RawStdin {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        // The existing runtime reads only this process's inherited input. The
        // writable slice remains valid for the entire synchronous call.
        let result = unsafe { __absd_std_read(bytes.as_mut_ptr(), bytes.len()) };
        if result < 0 {
            // Match std's existing ABSD raw-stdio error mapping.
            let kind = match result {
                -1 => io::ErrorKind::PermissionDenied,
                -2 => io::ErrorKind::NotFound,
                -11 => io::ErrorKind::WouldBlock,
                -12 => io::ErrorKind::OutOfMemory,
                -14 | -22 => io::ErrorKind::InvalidInput,
                -24 => io::ErrorKind::QuotaExceeded,
                -32 => io::ErrorKind::BrokenPipe,
                -38 => io::ErrorKind::Unsupported,
                -110 => io::ErrorKind::TimedOut,
                _ => io::ErrorKind::Other,
            };
            return Err(io::Error::new(kind, "ABSD I/O syscall failed"));
        }
        let count = result as usize;
        if count > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ABSD input count exceeds buffer",
            ));
        }
        Ok(count)
    }
}

pub fn interactive() -> impl BufRead {
    // read_line stops at its newline without fetching any following byte.
    // Script modes keep their existing standard buffered input path.
    BufReader::with_capacity(1, RawStdin)
}
