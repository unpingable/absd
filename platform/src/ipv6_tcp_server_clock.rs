//! Private owner completion-clock check, shared only with focused host controls.
//! Observation must follow every potentially blocking result read/wait and
//! precede terminal success, even if EOF/zero sockets make drain loops empty.
pub fn observe(previous: &mut u64, until: u64, now: u64) -> Result<(), &'static str> {
    if now < *previous {
        return Err("owner completion clock rewind");
    }
    if now >= until {
        return Err("owner completion deadline");
    }
    *previous = now;
    Ok(())
}
