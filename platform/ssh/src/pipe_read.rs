//! One child-pipe read, with readiness supplied by the ABSD backend.
use std::io;

pub(crate) fn read<P>(
    pipe: &mut Option<P>,
    bytes: &mut [u8],
    info: impl FnOnce(&P) -> Result<[u64; 4], i64>,
    transfer: impl FnOnce(&P, &mut [u8]) -> Result<usize, i64>,
) -> io::Result<Option<usize>> {
    let Some(p) = pipe.as_ref() else {
        return Ok(Some(0));
    };
    // Querying readiness does not consume bytes. Only skip an empty pipe
    // that still has a writer; buffered data and EOF retain the timed read.
    // Query failures also use the existing read/error path.
    if matches!(info(p), Ok([0, _, _, writers]) if writers > 0) {
        return Ok(None);
    }
    match transfer(p, bytes) {
        Ok(0) => {
            *pipe = None;
            Ok(Some(0))
        }
        Ok(n) => Ok(Some(n)),
        Err(-110) => Ok(None),
        Err(code) => {
            *pipe = None;
            Err(io::Error::other(format!("pipe read {code}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::read;
    use std::{cell::Cell, rc::Rc};
    struct Pipe(Rc<Cell<usize>>);
    impl Drop for Pipe {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    fn pipe() -> (Option<Pipe>, Rc<Cell<usize>>) {
        let dropped = Rc::new(Cell::new(0));
        (Some(Pipe(dropped.clone())), dropped)
    }
    #[test]
    fn empty_live_pipe_does_not_wait_or_drop() {
        let (mut p, dropped) = pipe();
        let got = read(
            &mut p,
            &mut [0; 8],
            |_| Ok([0, 256, 1, 1]),
            |_, _| panic!("empty live pipe must not issue timed read"),
        );
        assert_eq!(got.unwrap(), None);
        assert!(p.is_some());
        assert_eq!(dropped.get(), 0);
    }
    #[test]
    fn buffered_bytes_are_delivered_even_after_last_writer_closes() {
        let (mut p, dropped) = pipe();
        let mut bytes = [0; 8];
        let got = read(
            &mut p,
            &mut bytes,
            |_| Ok([3, 253, 1, 0]),
            |_, out| {
                out[..3].copy_from_slice(b"abc");
                Ok(3)
            },
        );
        assert_eq!(got.unwrap(), Some(3));
        assert_eq!(&bytes[..3], b"abc");
        assert!(p.is_some());
        assert_eq!(
            read(&mut p, &mut bytes, |_| Ok([0, 256, 1, 0]), |_, _| Ok(0)).unwrap(),
            Some(0)
        );
        assert!(p.is_none());
        assert_eq!(dropped.get(), 1);
    }
    #[test]
    fn readiness_to_read_timeout_keeps_pipe_open() {
        let (mut p, dropped) = pipe();
        assert_eq!(
            read(
                &mut p,
                &mut [0; 8],
                |_| Ok([1, 255, 1, 1]),
                |_, _| Err(-110)
            )
            .unwrap(),
            None
        );
        assert!(p.is_some());
        assert_eq!(dropped.get(), 0);
    }
    #[test]
    fn query_failure_falls_back_to_existing_read_success() {
        let (mut p, _) = pipe();
        assert_eq!(
            read(&mut p, &mut [0; 8], |_| Err(-9), |_, _| Ok(2)).unwrap(),
            Some(2)
        );
        assert!(p.is_some());
    }
    #[test]
    fn query_failure_preserves_read_error_and_drop() {
        let (mut p, dropped) = pipe();
        let error = read(&mut p, &mut [0; 8], |_| Err(-14), |_, _| Err(-9)).unwrap_err();
        assert_eq!(error.to_string(), "pipe read -9");
        assert!(p.is_none());
        assert_eq!(dropped.get(), 1);
    }
    #[test]
    fn absent_pipe_is_eof_without_query_or_transfer() {
        let mut p: Option<Pipe> = None;
        assert_eq!(
            read(
                &mut p,
                &mut [0; 8],
                |_| panic!("absent query"),
                |_, _| panic!("absent read")
            )
            .unwrap(),
            Some(0)
        );
    }
    #[test]
    fn both_ready_streams_progress_and_empty_stderr_does_not_wait() {
        let (mut out, _) = pipe();
        let (mut err, _) = pipe();
        let mut calls = 0;
        for p in [&mut out, &mut err] {
            assert_eq!(
                read(
                    p,
                    &mut [0; 8],
                    |_| Ok([2, 254, 1, 1]),
                    |_, _| {
                        calls += 1;
                        Ok(2)
                    }
                )
                .unwrap(),
                Some(2)
            );
        }
        assert_eq!(calls, 2);
        assert_eq!(
            read(
                &mut err,
                &mut [0; 8],
                |_| Ok([0, 256, 1, 1]),
                |_, _| panic!("empty stderr wait")
            )
            .unwrap(),
            None
        );
    }
}
