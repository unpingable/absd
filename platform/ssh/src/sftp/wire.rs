//! Bounded SFTP framing around Sunset's existing SSH wire primitives.
use std::io::{self, Read, Write};
use sunset::sshwire::{SSHDecode, SSHEncode, read_ssh, ssh_push_vec};

pub(super) const MAX_PACKET: usize = 256 * 1024;

pub(super) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid SFTP packet")
}

pub(super) fn decode<'a, T: SSHDecode<'a>>(bytes: &'a [u8]) -> io::Result<(T, usize)> {
    read_ssh(bytes, None).map_err(|_| invalid())
}

pub(super) fn encode(out: &mut Vec<u8>, value: &dyn SSHEncode) {
    // Every caller bounds borrowed strings and responses before encoding.
    // Sunset's append helper asserts against the whole destination length
    // in debug builds, so give it an empty destination for each value.
    let mut encoded = Vec::new();
    ssh_push_vec(&mut encoded, value).expect("bounded SFTP wire value");
    out.extend_from_slice(&encoded);
}

pub(super) enum Frame {
    Packet(Vec<u8>),
    Oversized { kind: u8, id: u32 },
}

pub(super) fn read_frame(input: &mut impl Read) -> io::Result<Option<Frame>> {
    let mut header = [0; 4];
    loop {
        match input.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    input.read_exact(&mut header[1..])?;
    let (size, _) = decode::<u32>(&header)?;
    let size = size as usize;
    if size == 0 {
        return Err(invalid());
    }
    if size > MAX_PACKET {
        // Only recover the fixed request type/id; never allocate or drain
        // the claimed body. The caller sends a refusal and ends the stream.
        let mut prefix = [0; 5];
        input.read_exact(&mut prefix)?;
        let (id, _) = decode::<u32>(&prefix[1..])?;
        return Ok(Some(Frame::Oversized {
            kind: prefix[0],
            id,
        }));
    }
    let mut body = vec![0; size];
    input.read_exact(&mut body)?;
    Ok(Some(Frame::Packet(body)))
}

pub(super) fn write_frame(output: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_PACKET {
        return Err(invalid());
    }
    let mut header = Vec::with_capacity(4);
    encode(&mut header, &(body.len() as u32));
    output.write_all(&header)?;
    output.write_all(body)?;
    output.flush()
}

pub(super) struct Fields<'a>(pub &'a [u8]);
impl<'a> Fields<'a> {
    fn take<T: SSHDecode<'a>>(&mut self) -> Result<T, u32> {
        let (value, used) = decode(self.0).map_err(|_| 5u32)?;
        self.0 = &self.0[used..];
        Ok(value)
    }
    pub fn u32(&mut self) -> Result<u32, u32> {
        self.take()
    }
    pub fn u64(&mut self) -> Result<u64, u32> {
        self.take()
    }
    pub fn string(&mut self, max: usize) -> Result<&'a [u8], u32> {
        let value: sunset::sshwire::BinString<'a> = self.take()?;
        if value.0.len() > max {
            return Err(5);
        }
        Ok(value.0)
    }
    pub fn finish(self) -> Result<(), u32> {
        if self.0.is_empty() { Ok(()) } else { Err(5) }
    }
}

#[derive(Default)]
pub(super) struct Attributes {
    pub size: Option<u64>,
    pub permissions: Option<u32>,
    pub unsupported: bool,
}
impl Attributes {
    pub fn parse(fields: &mut Fields<'_>) -> Result<Self, u32> {
        let flags = fields.u32()?;
        if flags & !(1 | 2 | 4 | 8 | 0x8000_0000) != 0 {
            return Err(5);
        }
        let mut attrs = Self::default();
        if flags & 1 != 0 {
            attrs.size = Some(fields.u64()?);
        }
        if flags & 2 != 0 {
            fields.u32()?;
            fields.u32()?;
            attrs.unsupported = true;
        }
        if flags & 4 != 0 {
            attrs.permissions = Some(fields.u32()?);
        }
        if flags & 8 != 0 {
            fields.u32()?;
            fields.u32()?;
            attrs.unsupported = true;
        }
        if flags & 0x8000_0000 != 0 {
            let count = fields.u32()?;
            if count > 16 {
                return Err(5);
            }
            for _ in 0..count {
                fields.string(4096)?;
                fields.string(65536)?;
            }
            attrs.unsupported = true;
        }
        Ok(attrs)
    }
    pub fn creation(&self) -> Result<(), u32> {
        // ABSD has no POSIX mode setter. Initial permissions are advisory;
        // they never change the authority already granted by FSD.
        if self.size.is_some() || self.unsupported {
            Err(8)
        } else {
            Ok(())
        }
    }
    pub fn size_only(&self) -> Result<(), u32> {
        if self.permissions.is_some() || self.unsupported {
            Err(8)
        } else {
            Ok(())
        }
    }
}

pub(super) fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    encode(out, &sunset::sshwire::BinString(bytes));
}
pub(super) fn response(kind: u8, id: u32) -> Vec<u8> {
    let mut out = vec![kind];
    encode(&mut out, &id);
    out
}
pub(super) fn status(id: u32, code: u32) -> Vec<u8> {
    let mut out = response(101, id);
    encode(&mut out, &code);
    string(
        &mut out,
        match code {
            0 => b"OK",
            1 => b"EOF",
            2 => b"No such file",
            3 => b"Permission denied",
            5 => b"Bad message",
            8 => b"Unsupported operation",
            _ => b"Operation failed",
        },
    );
    string(&mut out, b"");
    out
}
