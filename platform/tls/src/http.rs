//! Strict, bounded HTTP response framing for the native HTTPS fixture.
//!
//! This parser deliberately accepts only the fixture's single HTTP/1.1 200
//! response with a known length. It does not implement a general HTTP client.

pub const MAX_HEADERS: usize = 4096;
pub const MAX_LINE: usize = 1024;
pub const MAX_FIELDS: usize = 32;
pub const MAX_BODY: usize = 16384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BodyLimit,
    HeaderLimit,
    LineLimit,
    FieldLimit,
    InvalidLineEnding,
    InvalidStatus,
    InvalidField,
    MissingLength,
    DuplicateLength,
    InvalidLength,
    LengthMismatch,
    TransferEncoding,
    ContentEncoding,
    BodyMismatch,
    ExtraBody,
    HeadersIncomplete,
    BodyIncomplete,
}

impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::BodyLimit => "body_limit",
            Self::HeaderLimit => "header_limit",
            Self::LineLimit => "line_limit",
            Self::FieldLimit => "field_limit",
            Self::InvalidLineEnding => "invalid_line_ending",
            Self::InvalidStatus => "invalid_status",
            Self::InvalidField => "invalid_field",
            Self::MissingLength => "missing_length",
            Self::DuplicateLength => "duplicate_length",
            Self::InvalidLength => "invalid_length",
            Self::LengthMismatch => "length_mismatch",
            Self::TransferEncoding => "transfer_encoding",
            Self::ContentEncoding => "content_encoding",
            Self::BodyMismatch => "body_mismatch",
            Self::ExtraBody => "extra_body",
            Self::HeadersIncomplete => "headers_incomplete",
            Self::BodyIncomplete => "body_incomplete",
        }
    }
}

pub fn expected_body_byte(offset: usize) -> u8 {
    b'a' + (offset % 26) as u8
}

pub struct ResponseParser {
    headers: [u8; MAX_HEADERS],
    used: usize,
    line_start: usize,
    header_done: bool,
    expected: usize,
    body_read: usize,
    failed: Option<Error>,
}

impl ResponseParser {
    pub fn new(expected_body_len: usize) -> Result<Self, Error> {
        if expected_body_len > MAX_BODY {
            return Err(Error::BodyLimit);
        }
        Ok(Self {
            headers: [0; MAX_HEADERS],
            used: 0,
            line_start: 0,
            header_done: false,
            expected: expected_body_len,
            body_read: 0,
            failed: None,
        })
    }

    /// Consume every available plaintext byte, including bytes after the body.
    /// A refusal is sticky: no later fragment can make this response valid.
    pub fn feed(&mut self, mut input: &[u8]) -> Result<(), Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let result = (|| {
            while !self.header_done && !input.is_empty() {
                let byte = input[0];
                input = &input[1..];
                if self.used == MAX_HEADERS {
                    return Err(Error::HeaderLimit);
                }
                let previous = self.used.checked_sub(1).map(|i| self.headers[i]);
                if (byte == b'\n' && previous != Some(b'\r'))
                    || (previous == Some(b'\r') && byte != b'\n')
                {
                    return Err(Error::InvalidLineEnding);
                }
                self.headers[self.used] = byte;
                self.used += 1;
                if self.used - self.line_start > MAX_LINE {
                    return Err(Error::LineLimit);
                }
                if byte == b'\n' {
                    let line_len = self.used - self.line_start;
                    self.line_start = self.used;
                    if line_len == 2 {
                        parse_headers(&self.headers[..self.used], self.expected)?;
                        self.header_done = true;
                    }
                }
            }
            for &byte in input {
                if self.body_read == self.expected {
                    return Err(Error::ExtraBody);
                }
                if byte != expected_body_byte(self.body_read) {
                    return Err(Error::BodyMismatch);
                }
                self.body_read += 1;
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }

    pub fn headers_complete(&self) -> bool {
        self.header_done
    }

    pub fn is_complete(&self) -> bool {
        self.failed.is_none() && self.header_done && self.body_read == self.expected
    }

    pub fn body_len(&self) -> usize {
        self.body_read
    }

    pub fn finish(&self) -> Result<usize, Error> {
        if let Some(error) = self.failed {
            Err(error)
        } else if !self.header_done {
            Err(Error::HeadersIncomplete)
        } else if self.body_read != self.expected {
            Err(Error::BodyIncomplete)
        } else {
            Ok(self.body_read)
        }
    }
}

fn parse_headers(headers: &[u8], expected: usize) -> Result<(), Error> {
    let mut lines = headers.split(|&byte| byte == b'\n');
    let status = lines.next().ok_or(Error::InvalidStatus)?;
    let status = status.strip_suffix(b"\r").ok_or(Error::InvalidLineEnding)?;
    let reason = status
        .strip_prefix(b"HTTP/1.1 200 ")
        .ok_or(Error::InvalidStatus)?;
    if !reason.iter().all(|&byte| valid_value(byte)) {
        return Err(Error::InvalidStatus);
    }
    let mut field_count = 0;
    let mut length = None;
    let mut encoding_seen = false;
    for line in lines {
        // The delimiter and final empty split element have no field content.
        if line == b"\r" || line.is_empty() {
            continue;
        }
        field_count += 1;
        if field_count > MAX_FIELDS {
            return Err(Error::FieldLimit);
        }
        let line = line.strip_suffix(b"\r").ok_or(Error::InvalidLineEnding)?;
        let colon = line
            .iter()
            .position(|&byte| byte == b':')
            .ok_or(Error::InvalidField)?;
        let name = &line[..colon];
        let value = &line[colon + 1..];
        if name.is_empty()
            || !name.iter().all(|&byte| token(byte))
            || !value.iter().all(|&byte| valid_value(byte))
        {
            return Err(Error::InvalidField);
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            if length.is_some() {
                return Err(Error::DuplicateLength);
            }
            let value = trim_ows(value);
            if value.is_empty() || (value.len() > 1 && value[0] == b'0') {
                return Err(Error::InvalidLength);
            }
            let mut number = 0usize;
            for &digit in value {
                if !digit.is_ascii_digit() {
                    return Err(Error::InvalidLength);
                }
                number = number
                    .checked_mul(10)
                    .and_then(|n| n.checked_add((digit - b'0') as usize))
                    .ok_or(Error::InvalidLength)?;
            }
            if number > MAX_BODY {
                return Err(Error::BodyLimit);
            }
            length = Some(number);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(Error::TransferEncoding);
        } else if name.eq_ignore_ascii_case(b"content-encoding") {
            if encoding_seen || !trim_ows(value).eq_ignore_ascii_case(b"identity") {
                return Err(Error::ContentEncoding);
            }
            encoding_seen = true;
        }
    }
    if length.ok_or(Error::MissingLength)? != expected {
        return Err(Error::LengthMismatch);
    }
    Ok(())
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|&byte| byte == b' ' || byte == b'\t')
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|&byte| byte == b' ' || byte == b'\t')
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn valid_value(byte: u8) -> bool {
    byte == b'\t' || (byte >= 0x20 && byte != 0x7f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(body_len: usize) -> Vec<u8> {
        let mut response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\n\r\n").into_bytes();
        response.extend((0..body_len).map(expected_body_byte));
        response
    }

    #[test]
    fn every_fragment_boundary_and_single_byte_fragments() {
        let bytes = response(67);
        for split in 0..=bytes.len() {
            let mut parser = ResponseParser::new(67).unwrap();
            parser.feed(&bytes[..split]).unwrap();
            parser.feed(&bytes[split..]).unwrap();
            assert_eq!(parser.finish(), Ok(67));
        }
        let mut parser = ResponseParser::new(67).unwrap();
        for byte in &bytes {
            parser.feed(std::slice::from_ref(byte)).unwrap();
        }
        assert_eq!(parser.finish(), Ok(67));
    }

    #[test]
    fn incomplete_framing_is_distinct_from_complete_body() {
        let bytes = response(3);
        for end in 0..bytes.len() {
            let mut parser = ResponseParser::new(3).unwrap();
            parser.feed(&bytes[..end]).unwrap();
            assert!(!parser.is_complete());
            assert!(matches!(
                parser.finish(),
                Err(Error::HeadersIncomplete | Error::BodyIncomplete)
            ));
        }
        let mut parser = ResponseParser::new(0).unwrap();
        parser.feed(&response(0)).unwrap();
        assert!(parser.is_complete());
    }

    #[test]
    fn body_bounds_contents_and_extra_bytes() {
        assert!(matches!(
            ResponseParser::new(MAX_BODY + 1),
            Err(Error::BodyLimit)
        ));
        let mut parser = ResponseParser::new(MAX_BODY).unwrap();
        for chunk in response(MAX_BODY).chunks(1024) {
            parser.feed(chunk).unwrap();
        }
        assert_eq!(parser.finish(), Ok(MAX_BODY));
        assert_eq!(parser.feed(b"a"), Err(Error::ExtraBody));
        assert_eq!(parser.finish(), Err(Error::ExtraBody));
        let mut parser = ResponseParser::new(3).unwrap();
        let mut bytes = response(3);
        *bytes.last_mut().unwrap() = b'!';
        assert_eq!(parser.feed(&bytes), Err(Error::BodyMismatch));
        assert_eq!(parser.feed(b"c"), Err(Error::BodyMismatch));
    }

    fn refusal(headers: &[u8], expected: usize, error: Error) {
        let mut parser = ResponseParser::new(expected).unwrap();
        assert_eq!(parser.feed(headers), Err(error));
        assert_eq!(parser.feed(&response(expected)), Err(error));
        assert_eq!(parser.finish(), Err(error));
    }

    #[test]
    fn strict_content_length_and_unsupported_framing() {
        for value in [
            "",
            "00",
            "01",
            "+3",
            "-1",
            "3,3",
            "3 3",
            "0x3",
            "9999999999999999999999999999999999999999",
        ] {
            refusal(
                format!("HTTP/1.1 200 OK\r\nContent-Length:{value}\r\n\r\n").as_bytes(),
                3,
                Error::InvalidLength,
            );
        }
        refusal(
            b"HTTP/1.1 200 OK\r\nContent-Length:16385\r\n\r\n",
            0,
            Error::BodyLimit,
        );
        refusal(
            b"HTTP/1.1 200 OK\r\nContent-Length:2\r\n\r\n",
            3,
            Error::LengthMismatch,
        );
        refusal(b"HTTP/1.1 200 OK\r\n\r\n", 0, Error::MissingLength);
        refusal(
            b"HTTP/1.1 200 OK\r\nContent-Length:0\r\ncOnTeNt-LeNgTh:0\r\n\r\n",
            0,
            Error::DuplicateLength,
        );
        refusal(
            b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nTransfer-Encoding:identity\r\n\r\n",
            0,
            Error::TransferEncoding,
        );
        refusal(
            b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nContent-Encoding:gzip\r\n\r\n",
            0,
            Error::ContentEncoding,
        );
        let mut parser = ResponseParser::new(3).unwrap();
        parser.feed(b"HTTP/1.1 200 OK\r\ncOnTeNt-LeNgTh:\t 3 \t\r\nContent-Encoding: Identity\r\n\r\nabc").unwrap();
        assert_eq!(parser.finish(), Ok(3));
    }

    #[test]
    fn invalid_status_line_endings_and_fields() {
        for status in [
            "HTTP/1.0 200 OK",
            "HTTP/1.1 100 Continue",
            "HTTP/1.1 301 Moved",
            "HTTP/1.1 200",
            "HTTP/1.1 2000 OK",
        ] {
            refusal(
                format!("{status}\r\nContent-Length:0\r\n\r\n").as_bytes(),
                0,
                Error::InvalidStatus,
            );
        }
        for headers in [b"HTTP/1.1 200 OK\n".as_slice(), b"HTTP/1.1 200 OK\rX"] {
            refusal(headers, 0, Error::InvalidLineEnding);
        }
        for field in [
            " folded:value",
            "bad name:value",
            "missingcolon",
            ":empty",
            "x:\u{7f}",
            "x:\u{1}",
        ] {
            refusal(
                format!("HTTP/1.1 200 OK\r\n{field}\r\nContent-Length:0\r\n\r\n").as_bytes(),
                0,
                Error::InvalidField,
            );
        }
    }

    #[test]
    fn exact_line_and_field_boundaries_include_crlf() {
        let mut exact = b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nX:".to_vec();
        exact.extend(std::iter::repeat_n(b'a', MAX_LINE - 4));
        exact.extend_from_slice(b"\r\n\r\n");
        let mut parser = ResponseParser::new(0).unwrap();
        parser.feed(&exact).unwrap();
        let mut too_long = exact.clone();
        too_long.insert(too_long.len() - 4, b'a');
        refusal(&too_long, 0, Error::LineLimit);
        let mut status = b"HTTP/1.1 200 ".to_vec();
        status.extend(std::iter::repeat_n(b'a', MAX_LINE - status.len() - 2));
        status.extend_from_slice(b"\r\nContent-Length:0\r\n\r\n");
        let mut parser = ResponseParser::new(0).unwrap();
        parser.feed(&status).unwrap();
        status.insert(MAX_LINE - 2, b'a');
        refusal(&status, 0, Error::LineLimit);
        let mut exact = b"HTTP/1.1 200 OK\r\nContent-Length:0\r\n".to_vec();
        for _ in 1..MAX_FIELDS {
            exact.extend_from_slice(b"X:a\r\n");
        }
        let mut parser = ResponseParser::new(0).unwrap();
        let mut complete = exact.clone();
        complete.extend_from_slice(b"\r\n");
        parser.feed(&complete).unwrap();
        exact.extend_from_slice(b"X:a\r\n\r\n");
        refusal(&exact, 0, Error::FieldLimit);
    }

    #[test]
    fn aggregate_header_boundary_includes_final_delimiter() {
        let mut exact = b"HTTP/1.1 200 OK\r\nContent-Length:0\r\n".to_vec();
        while MAX_HEADERS - exact.len() - 2 > MAX_LINE {
            exact.extend_from_slice(b"X:");
            exact.extend(std::iter::repeat_n(b'a', MAX_LINE - 4));
            exact.extend_from_slice(b"\r\n");
        }
        let remaining = MAX_HEADERS - exact.len() - 2;
        exact.extend_from_slice(b"X:");
        exact.extend(std::iter::repeat_n(b'a', remaining - 4));
        exact.extend_from_slice(b"\r\n\r\n");
        assert_eq!(exact.len(), MAX_HEADERS);
        let mut parser = ResponseParser::new(0).unwrap();
        parser.feed(&exact).unwrap();
        assert!(parser.is_complete());
        exact.insert(exact.len() - 4, b'a');
        refusal(&exact, 0, Error::HeaderLimit);
    }
}
