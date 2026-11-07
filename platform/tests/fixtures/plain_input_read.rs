use std::io::Cursor;
const LIMIT: usize = 1024 * 1024;
fn adapter() -> Adapter { Adapter { paste_records: false } }
#[test]
fn overlong_physical_line_stops_before_unbounded_allocation() {
    let mut input=Cursor::new(vec![b'x'; LIMIT + 4096]);
    let mut text=String::new();
    let error=adapter().read_interactive(&mut input,&mut text).expect_err("oversized line must refuse");
    assert_eq!(error.kind(),io::ErrorKind::FileTooLarge);
    assert!(input.position() <= (LIMIT+1) as u64);
    assert!(text.is_empty(),"rejected physical input must not become source");
}
#[test]
fn overflow_is_classified_before_decoding_a_truncated_utf8_prefix() {
    let mut bytes=vec![b'x'; LIMIT];bytes.extend_from_slice("é".as_bytes());bytes.extend_from_slice(b"tail\n");
    let mut input=Cursor::new(bytes);let mut text=String::new();
    let error=adapter().read_interactive(&mut input,&mut text).expect_err("over limit");
    assert_eq!(error.kind(),io::ErrorKind::FileTooLarge);
    assert_eq!(input.position(),(LIMIT+1) as u64);assert!(text.is_empty());
}
#[test]
fn exact_limit_and_ordinary_lines_preserve_bytes() {
    for bytes in [b"echo ok\n".to_vec(),[vec![b'x';LIMIT-1],b"\n".to_vec()].concat()] {
        let mut input=Cursor::new(bytes.clone());let mut text=String::new();
        assert_eq!(adapter().read_interactive(&mut input,&mut text).unwrap(),bytes.len());
        assert_eq!(text.as_bytes(),bytes);assert_eq!(input.position(),bytes.len() as u64);
    }
}
#[test]
fn following_foreground_input_remains_unread() {
    let bytes=b"cat\nforeground bytes\n";let mut input=Cursor::new(bytes);let mut text=String::new();
    assert_eq!(adapter().read_interactive(&mut input,&mut text).unwrap(),4);
    assert_eq!(text,"cat\n");assert_eq!(&bytes[input.position() as usize..],b"foreground bytes\n");
}
#[test]
fn short_invalid_utf8_is_a_decode_error_and_not_source() {
    let mut input=Cursor::new(b"\xff\n".as_slice());let mut text=String::new();
    assert_eq!(adapter().read_interactive(&mut input,&mut text).unwrap_err().kind(),io::ErrorKind::InvalidData);
    assert!(text.is_empty());
}
