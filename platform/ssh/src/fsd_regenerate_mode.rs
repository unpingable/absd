//! Validate operations on the dedicated clone-construction program.
//!
//! The compiled role selects key regeneration while serving. It does not
//! change startup argv, and the same ELF must still perform the kernel's
//! explicit finalize operation after an orderly halt.

pub fn link_anchor() {
    absd_runtime::link_anchor();
    validate(std::env::args()).unwrap_or_else(|reason| crate::fatal(reason));
}

pub fn validate(args: impl IntoIterator<Item = String>) -> Result<(), &'static str> {
    let mut finalize = 0;
    let mut regenerate = false;
    let mut qualification = false;
    for arg in args {
        match arg.as_str() {
            "--finalize" | "--finalize-bounded" => finalize += 1,
            "--regenerate-host-key" => regenerate = true,
            "--qualification-exit-on-notice" | "--qualification-hang-on-notice" => {
                qualification = true
            }
            _ => {}
        }
    }
    if finalize > 1 || (finalize == 1 && (regenerate || qualification)) {
        return Err("conflicting file-server startup modes");
    }
    if finalize == 0 && qualification {
        return Err("host-key regeneration conflicts with qualification mode");
    }
    Ok(())
}
