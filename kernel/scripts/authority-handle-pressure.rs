//! Standalone host trace linked to the qualified production kernel library.
//! This establishes handle-allocation correspondence, not an entire spawn.
use absd_kernel::handle::{
    HandleError, HandleTable, MAX_HANDLES, Object, RIGHT_KILL, RIGHT_READ, RIGHT_WAIT, RIGHT_WRITE,
};
use absd_kernel::object::PipeTable;
fn main() {
    assert_eq!(MAX_HANDLES, 64);
    let mut handles = HandleTable::new(71);
    for _ in 0..61 {
        handles.insert(Object::Console, RIGHT_WRITE).unwrap();
    }
    let mut pipes = PipeTable::new();
    let id = pipes.create(RIGHT_READ | RIGHT_WRITE).unwrap();
    let combined = handles
        .insert(Object::Pipe(id), RIGHT_READ | RIGHT_WRITE)
        .unwrap();
    let reader = handles.duplicate(combined, RIGHT_READ).unwrap().0;
    let writer = handles.duplicate(combined, RIGHT_WRITE).unwrap().0;
    assert_eq!(handles.live_count(), 64);
    handles.close(combined).unwrap();
    assert_eq!(handles.live_count(), 63);
    assert!(handles.has_free_slot());
    let child = handles
        .insert(Object::Process(91), RIGHT_WAIT | RIGHT_KILL)
        .unwrap();
    assert_eq!(handles.live_count(), 64);
    assert_eq!(handles.duplicate(child, RIGHT_WAIT), Err(HandleError::Full));
    assert_eq!(handles.process(child, RIGHT_WAIT), Ok(91));
    assert_eq!(handles.pipe(reader, RIGHT_READ), Ok(id));
    assert_eq!(handles.pipe(writer, RIGHT_WRITE), Ok(id));
    println!(
        "HANDLE PRESSURE TRACE initial=61 startup-peak=64 pre-spawn=63 published=64 wait-copy=Full source-authority=unchanged"
    );
    // Constructor-ordering repair frees exactly its temporary.
    handles.close(reader).unwrap();
    let copied = handles.duplicate(child, RIGHT_WAIT).unwrap().0;
    assert_eq!(handles.live_count(), 64);
    assert_eq!(handles.process(copied, RIGHT_WAIT), Ok(91));
    assert_eq!(
        handles.process(copied, RIGHT_KILL),
        Err(HandleError::Rights)
    );
    println!(
        "HANDLE PRESSURE TRACE close-startup-reader=true wait-copy=granted right=WAIT limit=64"
    );
    handles.close(copied).unwrap();
    let successor = handles.insert(Object::Process(92), RIGHT_WAIT).unwrap();
    assert_eq!(copied & 0xff, successor & 0xff);
    assert_ne!(copied, successor);
    assert_eq!(
        handles.process(copied, RIGHT_WAIT),
        Err(HandleError::Invalid)
    );
    assert_eq!(handles.close(copied), Err(HandleError::Invalid));
    assert_eq!(handles.process(successor, RIGHT_WAIT), Ok(92));
    println!(
        "HANDLE PRESSURE TRACE reissued-slot=true stale-wait=Invalid stale-close=Invalid successor=unchanged"
    );
}
