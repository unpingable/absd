//! Safe rendering for kernel-maintenance records, including captured service text.
pub fn render(bytes: &[u8], out: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut count = 0;
    for &byte in bytes {
        let mut escaped = [0u8; 4];
        let text: &[u8] = match byte {
            b'\\' => b"\\\\",
            0x20..=0x7e => {
                escaped[0] = byte;
                &escaped[..1]
            }
            _ => {
                escaped = [
                    b'\\',
                    b'x',
                    HEX[usize::from(byte >> 4)],
                    HEX[usize::from(byte & 15)],
                ];
                &escaped
            }
        };
        if count + text.len() > out.len() {
            break;
        }
        out[count..count + text.len()].copy_from_slice(text);
        count += text.len();
    }
    count
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_controls_and_record_separators_are_visible_text() {
        let mut out = [0; 128];
        let n = render(b"line\n\r\x1b[2J\xff\\", &mut out);
        assert_eq!(&out[..n], b"line\\x0a\\x0d\\x1b[2J\\xff\\\\");
    }
    #[test]
    fn bounded_output_never_splits_an_escape() {
        let mut out = [0; 3];
        assert_eq!(render(b"\x1b", &mut out), 0);
    }
}
