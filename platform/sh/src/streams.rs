//! Ordered standard-stream destinations shared by the evaluator and executor.
use super::*;

pub(super) type Endpoint<W> = Rc<Destination<W>>;
pub(super) enum Destination<W> {
    Parent(usize),
    Next,
    Discard,
    File(SharedSink<W>),
    Capture(Capture),
}

pub(super) fn outer_streams<W>() -> [Endpoint<W>; 2] {
    [
        Rc::new(Destination::Parent(0)),
        Rc::new(Destination::Parent(1)),
    ]
}

impl<H: Host> Shell<H> {
    pub(super) fn resolve_outputs(
        &mut self,
        command: &Command,
        next: bool,
    ) -> Result<[Endpoint<H::Sink>; 2], String> {
        let mut streams = self.output_context.clone();
        if next {
            streams[0] = Rc::new(Destination::Next);
        }
        for redirect in &command.redirects {
            match redirect {
                Redirect::File { fd, path, append } => {
                    if path == "/dev/null" {
                        streams[usize::from(*fd - 1)] = Rc::new(Destination::Discard);
                        continue;
                    }
                    let path = resolve(&self.cwd, path);
                    let sink = self
                        .host
                        .open_write(&path, *append)
                        .map_err(|error| open_error(&path, true, &error))?;
                    streams[usize::from(*fd - 1)] =
                        Rc::new(Destination::File(SharedSink(Rc::new(RefCell::new(sink)))));
                }
                Redirect::Dup { fd, from } => {
                    streams[usize::from(*fd - 1)] = streams[usize::from(*from - 1)].clone();
                }
            }
        }
        Ok(streams)
    }
}

pub(super) fn stage_outputs<W>(streams: &[Endpoint<W>; 2]) -> [Output<W>; 2] {
    fn output<W>(endpoint: &Destination<W>, slot: usize) -> Output<W> {
        match endpoint {
            Destination::Parent(stream) if *stream == slot => Output::Inherit,
            Destination::Parent(0) => Output::ParentStdout,
            Destination::Parent(_) => Output::ParentStderr,
            Destination::Next => Output::Next,
            Destination::Discard => Output::Discard,
            Destination::File(sink) => Output::Shared(sink.clone()),
            Destination::Capture(capture) => Output::Capture(capture.clone()),
        }
    }
    [
        output(&streams[0], 0),
        if Rc::ptr_eq(&streams[0], &streams[1]) {
            Output::SameAsStdout
        } else {
            output(&streams[1], 1)
        },
    ]
}

struct BorrowedWriter<'a>(Rc<RefCell<&'a mut dyn Write>>);
impl Write for BorrowedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush()
    }
}

pub(super) fn with_writers<'a, W: Write, T>(
    streams: &[Endpoint<W>; 2],
    context: &[Endpoint<W>; 2],
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
    body: impl FnOnce(&mut dyn Write, &mut dyn Write) -> T,
) -> T {
    let parents = [Rc::new(RefCell::new(out)), Rc::new(RefCell::new(err))];
    let mut writers: Vec<Box<dyn Write + '_>> = streams
        .iter()
        .map(|endpoint| {
            if let Some(slot) = context
                .iter()
                .position(|previous| Rc::ptr_eq(previous, endpoint))
            {
                return Box::new(BorrowedWriter(parents[slot].clone())) as Box<dyn Write>;
            }
            match endpoint.as_ref() {
                Destination::Parent(_) => {
                    unreachable!("an inherited endpoint belongs to the current context")
                }
                Destination::File(sink) => Box::new(sink.clone()),
                Destination::Capture(capture) => Box::new(capture.clone()),
                Destination::Discard => Box::new(io::sink()),
                Destination::Next => {
                    unreachable!("interpreted commands do not run in native pipelines")
                }
            }
        })
        .collect();
    let mut stderr = writers.pop().expect("two streams");
    body(writers[0].as_mut(), stderr.as_mut())
}

pub(super) fn flush<W: Write>(streams: &[Endpoint<W>; 2]) -> io::Result<()> {
    let mut first = None;
    for (slot, endpoint) in streams.iter().enumerate() {
        if slot == 1 && Rc::ptr_eq(endpoint, &streams[0]) {
            continue;
        }
        if let Destination::File(sink) = endpoint.as_ref()
            && let Err(error) = sink.clone().flush() {
            first.get_or_insert(error);
        }
    }
    match first { Some(error) => Err(error), None => Ok(()) }
}
