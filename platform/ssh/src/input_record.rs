//! Matched sshd/shell source records. This private delimiter is distinct
//! from standard bracketed-paste markers forwarded to an application.
pub const PREFIX: &str = "\x1b]absd-source;";
pub const MAX_HEADER: usize = PREFIX.len() + 8; // seven length digits and LF

pub fn header(length: usize) -> Vec<u8> {
    let mut bytes = PREFIX.as_bytes().to_vec();
    bytes.extend_from_slice(length.to_string().as_bytes());
    bytes.push(b'\n');
    bytes
}
