//! Read-only xHCI census and the single gate into controller mutation.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Function {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Malformed,
    Repeated,
    Absent,
    Missing(Function),
    WrongClass(Function),
}

/// One optional `xhci-pci=BB:DD.F`, hexadecimal with exact field widths.
/// Repetition is ambiguous even if the two values happen to be identical.
pub fn option<'a>(words: impl Iterator<Item = &'a [u8]>) -> Result<Option<Function>, Error> {
    let mut value = None;
    let mut seen = false;
    for word in words {
        if word != b"xhci-pci" && !word.starts_with(b"xhci-pci=") {
            continue;
        }
        if seen {
            return Err(Error::Repeated);
        }
        seen = true;
        value = Some(
            word.strip_prefix(b"xhci-pci=")
                .and_then(parse)
                .ok_or(Error::Malformed),
        );
    }
    value.transpose()
}

fn parse(bytes: &[u8]) -> Option<Function> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    if bytes.len() != 7 || bytes[2] != b':' || bytes[5] != b'.' {
        return None;
    }
    let bus = (hex(bytes[0])? << 4) | hex(bytes[1])?;
    let device = (hex(bytes[3])? << 4) | hex(bytes[4])?;
    let function = hex(bytes[6])?;
    if device >= 32 || function >= 8 {
        return None;
    }
    Some(Function {
        bus,
        device,
        function,
    })
}

/// Census all present PCI functions using configuration reads only. Report
/// every xHCI candidate, then enter the mutating callback exactly once, only
/// with the selected class-matching function. An invalid request never enters
/// that callback. The callback's own failure is returned without retry.
pub fn select<T>(
    request: Result<Option<Function>, Error>,
    enumerate: impl FnOnce(&mut dyn FnMut(Function, u32)),
    mut candidate: impl FnMut(Function),
    selected: impl FnOnce(Function) -> T,
) -> Result<T, Error> {
    let mut first = None;
    let mut requested_class = None;
    enumerate(&mut |function, code| {
        let matches = code >> 8 == 0x0c0330;
        if matches {
            candidate(function);
            first.get_or_insert(function);
        }
        if request == Ok(Some(function)) {
            requested_class = Some(matches);
        }
    });
    let function = match request? {
        None => first.ok_or(Error::Absent)?,
        Some(function) => match requested_class {
            None => return Err(Error::Missing(function)),
            Some(false) => return Err(Error::WrongClass(function)),
            Some(true) => function,
        },
    };
    Ok(selected(function))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    const FIRST: Function = Function {
        bus: 0,
        device: 4,
        function: 0,
    };
    const SECOND: Function = Function {
        bus: 0,
        device: 5,
        function: 0,
    };
    const OTHER: Function = Function {
        bus: 0,
        device: 3,
        function: 0,
    };
    const MISSING: Function = Function {
        bus: 0,
        device: 6,
        function: 0,
    };

    // Catches accepting a prefix/short form, out-of-range device/function,
    // or selecting the first of ambiguous repeated boot options.
    #[test]
    fn strict_boot_selector() {
        for (text, expected) in [
            (b"shell".as_slice(), Ok(None)),
            (b"xhci-pci=00:05.0", Ok(Some(SECOND))),
            (
                b"xhci-pci=aF:1F.7",
                Ok(Some(Function {
                    bus: 175,
                    device: 31,
                    function: 7,
                })),
            ),
            (b"xhci-pci=0:05.0", Err(Error::Malformed)),
            (b"xhci-pci=00:20.0", Err(Error::Malformed)),
            (b"xhci-pci=00:05.8", Err(Error::Malformed)),
            (b"xhci-pci=00:05.0x", Err(Error::Malformed)),
            (b"xhci-pci=00:0g.0", Err(Error::Malformed)),
            (b"xhci-pci=", Err(Error::Malformed)),
            (b"xhci-pci", Err(Error::Malformed)),
        ] {
            assert_eq!(option([text].into_iter()), expected, "{text:?}");
        }
        for words in [
            [b"xhci-pci=00:04.0".as_slice(), b"xhci-pci=00:05.0"],
            [b"xhci-pci=00:05.0".as_slice(), b"xhci-pci=00:05.0"],
            [b"xhci-pci=bad".as_slice(), b"xhci-pci=00:05.0"],
        ] {
            assert_eq!(option(words.into_iter()), Err(Error::Repeated));
        }
    }

    fn exercise(
        request: Result<Option<Function>, Error>,
    ) -> (Result<Function, Error>, Vec<Function>, Vec<Function>) {
        let mut candidates = Vec::new();
        let mut claims = Vec::new();
        let result = select(
            request,
            |visit| {
                visit(OTHER, 0x02000001);
                visit(FIRST, 0x0c033001);
                visit(SECOND, 0x0c033002);
            },
            |f| candidates.push(f),
            |f| {
                claims.push(f);
                f
            },
        );
        (result, candidates, claims)
    }

    // Catches early exit after the first match and mutating both functions.
    #[test]
    fn census_finishes_before_single_selected_claim() {
        for (request, expected) in [(None, FIRST), (Some(FIRST), FIRST), (Some(SECOND), SECOND)] {
            let (result, census, claims) = exercise(Ok(request));
            assert_eq!(result, Ok(expected));
            assert_eq!(census, [FIRST, SECOND]);
            assert_eq!(claims, [expected]);
        }
    }

    // Catches fallback to the first xHCI or any claim on invalid input.
    #[test]
    fn invalid_selection_never_enters_mutating_callback() {
        for (request, error) in [
            (Ok(Some(MISSING)), Error::Missing(MISSING)),
            (Ok(Some(OTHER)), Error::WrongClass(OTHER)),
            (Err(Error::Malformed), Error::Malformed),
            (Err(Error::Repeated), Error::Repeated),
        ] {
            let (result, census, claims) = exercise(request);
            assert_eq!(result, Err(error));
            assert_eq!(census, [FIRST, SECOND]);
            assert!(claims.is_empty());
        }
        let mut writes = 0;
        assert_eq!(
            select(Ok(None), |_| {}, |_| {}, |_| writes += 1),
            Err(Error::Absent)
        );
        assert_eq!(writes, 0);
    }

    // Catches retrying the callback on a second controller after refusal.
    #[test]
    fn selected_failure_has_no_second_attempt() {
        let mut writes = Vec::new();
        let result = select(
            Ok(Some(FIRST)),
            |visit| {
                visit(FIRST, 0x0c033000);
                visit(SECOND, 0x0c033000);
            },
            |_| {},
            |f| {
                writes.push(f);
                Err::<(), _>("selected controller refused")
            },
        );
        assert_eq!(result, Ok(Err("selected controller refused")));
        assert_eq!(writes, [FIRST]);
    }
}
