#[cfg(not(test))]
use crate::{Console, Error, time};

pub struct AckReader {
    index: usize,
}

impl AckReader {
    pub const fn new() -> Self {
        Self { index: 0 }
    }

    pub fn reset(&mut self) {
        self.index = 0;
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<bool, &'static str> {
        if self.index == 3 && !bytes.is_empty() {
            return Err("acknowledgement already complete");
        }
        for byte in bytes {
            if self.index == 3 || *byte != b"GO\n"[self.index] {
                return Err("unexpected acknowledgement bytes");
            }
            self.index += 1;
        }
        Ok(self.index == 3)
    }

    pub fn finish(self) -> Result<(), &'static str> {
        if self.index == 3 {
            Ok(())
        } else {
            Err("incomplete acknowledgement")
        }
    }
}

impl Default for AckReader {
    fn default() -> Self {
        Self::new()
    }
}

pub fn wait_ack_with(
    mut read: impl FnMut(&mut [u8], u64) -> Result<usize, &'static str>,
    now: impl Fn() -> u64,
    ticks: u64,
) -> Result<(), &'static str> {
    let deadline = now().saturating_add(ticks);
    let mut reader = AckReader::new();
    loop {
        let remaining = deadline.saturating_sub(now());
        if remaining == 0 {
            return Err("acknowledgement timeout");
        }
        let mut bytes = [0u8; 4];
        match read(&mut bytes, remaining) {
            Ok(0) => return Err("acknowledgement closed"),
            Ok(count) => {
                if reader.push(&bytes[..count])? {
                    let mut trailing = [0u8; 4];
                    return match read(&mut trailing, 1) {
                        Ok(0) => Err("acknowledgement closed"),
                        Ok(_) => Err("trailing acknowledgement data"),
                        Err("timeout") => reader.finish(),
                        Err(error) => Err(error),
                    };
                }
            }
            Err("timeout") => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(not(test))]
pub fn wait_ack(console: Console, ticks: u64) -> Result<(), &'static str> {
    wait_ack_with(
        |bytes, timeout| match console.read_timeout(bytes, timeout) {
            Ok(count) => Ok(count),
            Err(Error::Timeout) => Err("timeout"),
            Err(_) => Err("acknowledgement read"),
        },
        time,
        ticks,
    )
}

pub fn rectangle(color: u32) -> [u8; 16_384] {
    let color = color.to_le_bytes();
    let mut pixels = [0u8; 16_384];
    let mut index = 0;
    while index < pixels.len() {
        pixels[index..index + 4].copy_from_slice(&color);
        index += 4;
    }
    pixels
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayInfo {
    pub generation: u64,
    pub high_water: u64,
}

pub fn parse_info(record: &[u8; 48]) -> Result<DisplayInfo, &'static str> {
    let matches = u32::from_le_bytes(record[0..4].try_into().unwrap()) == 1024
        && u32::from_le_bytes(record[4..8].try_into().unwrap()) == 768
        && u32::from_le_bytes(record[8..12].try_into().unwrap()) == 4096
        && record[12..22] == [32, 1, 0, 0, 16, 8, 8, 8, 0, 8]
        && record[22..24] == [0, 0]
        && u64::from_le_bytes(record[40..48].try_into().unwrap()) == 65_536;
    if !matches {
        return Err("unsupported display geometry");
    }
    Ok(DisplayInfo {
        generation: u64::from_le_bytes(record[24..32].try_into().unwrap()),
        high_water: u64::from_le_bytes(record[32..40].try_into().unwrap()),
    })
}
