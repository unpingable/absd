//! One experimental SSH session may receive the boot's playback writer.
//! Restore only before successful kernel spawn; afterward the child may act.
use core::sync::atomic::{AtomicU64, Ordering};

pub struct Lease<'a> {
    slot: &'a AtomicU64,
    handle: u64,
}

pub fn claim<'a>(slot: &'a AtomicU64, path: &[u8]) -> Option<Lease<'a>> {
    if path != b"/bin/doomgeneric" {
        return None;
    }
    let handle = slot.swap(0, Ordering::AcqRel);
    if handle == 0 {
        None
    } else {
        Some(Lease { slot, handle })
    }
}

impl Lease<'_> {
    pub fn handle(&self) -> u64 {
        self.handle
    }
    /// The caller must close this parent's writer after kernel spawn succeeds.
    pub fn commit(mut self) -> u64 {
        let handle = self.handle;
        self.handle = 0;
        handle
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if self.handle != 0 {
            // Startup initializes the slot once; only leases modify it later.
            assert!(
                self.slot
                    .compare_exchange(0, self.handle, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::claim;
    use core::sync::atomic::{AtomicU64, Ordering};
    #[test]
    fn unrelated_command_cannot_claim() {
        let slot = AtomicU64::new(17);
        assert!(claim(&slot, b"/bin/sshtest").is_none());
        assert_eq!(slot.load(Ordering::Relaxed), 17);
    }
    #[test]
    fn failed_spawn_restores_but_excludes_second_claim() {
        let slot = AtomicU64::new(17);
        {
            let lease = claim(&slot, b"/bin/doomgeneric").unwrap();
            assert_eq!(lease.handle(), 17);
            assert!(claim(&slot, b"/bin/doomgeneric").is_none());
        }
        assert_eq!(claim(&slot, b"/bin/doomgeneric").unwrap().handle(), 17);
    }
    #[test]
    fn successful_spawn_spends_even_if_startup_later_fails() {
        let slot = AtomicU64::new(17);
        let handle = claim(&slot, b"/bin/doomgeneric").unwrap().commit();
        assert_eq!(handle, 17);
        assert_eq!(slot.load(Ordering::Relaxed), 0);
        assert!(claim(&slot, b"/bin/doomgeneric").is_none());
    }
    #[test]
    fn absent_grant_stays_absent() {
        assert!(claim(&AtomicU64::new(0), b"/bin/doomgeneric").is_none());
    }
}
