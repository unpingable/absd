//! Compile the real logs command as a host consumer of this journal schema.
//! Its own tests exercise parsing, bounded filesystem reads and volatile output.
#[allow(dead_code)]
#[path = "../../src/bin/logs.rs"]
mod logs;
